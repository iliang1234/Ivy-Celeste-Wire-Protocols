import unittest
import sys
import os
import grpc
import threading
import time
from protos import chat_pb2_grpc, chat_pb2
from server.server import ChatServicer
from concurrent import futures

# cd grpc_protocol
# python -m unittest test_grpc_protocol.py

# Add parent directory to path to import grpc_protocol
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TrackedChannel:
    def __init__(self, channel):
        self.channel = channel
        self.bytes_sent = 0
        self.bytes_received = 0

    def track_rpc(self, stub_method, request):
        """Tracks and prints bytes sent/received for a gRPC request."""
        serialized_request = request.SerializeToString()
        self.bytes_sent += len(serialized_request)

        response = stub_method(request)  # Call the RPC

        serialized_response = response.SerializeToString()
        self.bytes_received += len(serialized_response)

        print(f"\n📡 RPC Call: {stub_method._method}")  # ✅ Get the method name properly
        print(f"   🔹 Bytes Sent: {len(serialized_request)}")
        print(f"   🔹 Bytes Received: {len(serialized_response)}")
        
        return response

    def close(self):
        self.channel.close()

class TestChatSystem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start server in a separate thread
        cls.server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        chat_pb2_grpc.add_ChatServiceServicer_to_server(ChatServicer(), cls.server)
        cls.server.add_insecure_port('[::]:65432')
        cls.server.start()

        # Allow some time for the server to start
        time.sleep(1)

    def setUp(self):
        # Create test users
        self.test_users = {
            'user1': 'pass1',
            'user2': 'pass2',
            'user3': 'pass3'
        }
        
        # Register test users via gRPC
        with grpc.insecure_channel('localhost:65432') as channel:
            tracked_channel = TrackedChannel(channel)
            stub = chat_pb2_grpc.ChatServiceStub(channel)

            for username, password in self.test_users.items():
                request = chat_pb2.CreateAccountRequest(username=username, password=password)
                response = tracked_channel.track_rpc(stub.CreateAccount, request)
                print(f"\n✅ Setup - Registered {username}: {response.message}")

    def tearDown(self):
        # Clean up test users via gRPC
        with grpc.insecure_channel('localhost:65432') as channel:
            tracked_channel = TrackedChannel(channel)
            stub = chat_pb2_grpc.ChatServiceStub(channel)

            for username, password in self.test_users.items():
                request = chat_pb2.DeleteAccountRequest(username=username, password=password)
                response = tracked_channel.track_rpc(stub.DeleteAccount, request)
                print(f"\n❌ Teardown - Deleted {username}: {response.message}")

    def test_user_registration(self):
        """Test user registration functionality"""
        with grpc.insecure_channel('localhost:65432') as channel:
            tracked_channel = TrackedChannel(channel)
            stub = chat_pb2_grpc.ChatServiceStub(channel)

            request = chat_pb2.CreateAccountRequest(username='newuser', password='newpass')
            response = tracked_channel.track_rpc(stub.CreateAccount, request)

            self.assertEqual(response.success, True)
            print(f"\n✅ Successful registration: {response.message}")

    def test_user_login(self):
        """Test user login functionality"""
        with grpc.insecure_channel('localhost:65432') as channel:
            tracked_channel = TrackedChannel(channel)
            stub = chat_pb2_grpc.ChatServiceStub(channel)

            request = chat_pb2.LoginRequest(username='user1', password='pass1')
            response = tracked_channel.track_rpc(stub.Login, request)

            self.assertEqual(response.success, True)
            print(f"\n🔓 Login: {response.message}")

    def test_message_sending(self):
        """Test message sending functionality"""
        with grpc.insecure_channel('localhost:65432') as channel:
            tracked_channel = TrackedChannel(channel)
            stub = chat_pb2_grpc.ChatServiceStub(channel)

            request = chat_pb2.SendMessageRequest(sender='user1', recipient='user2', content='Test message')
            response = tracked_channel.track_rpc(stub.SendMessage, request)
            self.assertEqual(response.success, True)
            print(f"📨 Send message: {response.message}")

            # Read messages to verify
            request = chat_pb2.ReadMessagesRequest(username='user2')
            response = tracked_channel.track_rpc(stub.ReadMessages, request)
            self.assertTrue(any(msg.content == 'Test message' for msg in response.messages))
            print(f"📩 Read messages: {len(response.messages)} messages received")

    def test_message_deletion(self):
        """Test message deletion functionality"""
        with grpc.insecure_channel('localhost:65432') as channel:
            tracked_channel = TrackedChannel(channel)
            stub = chat_pb2_grpc.ChatServiceStub(channel)

            request = chat_pb2.SendMessageRequest(sender='user1', recipient='user2', content='Test message to delete')
            response = tracked_channel.track_rpc(stub.SendMessage, request)
            msg_id = response.message_id

            # Delete message
            delete_request = chat_pb2.DeleteMessagesRequest(username='user1', message_ids=[msg_id])
            delete_response = tracked_channel.track_rpc(stub.DeleteMessages, delete_request)
            self.assertEqual(delete_response.success, True)
            print(f"❌ Delete message: {delete_response.message}")

            # Verify deletion
            request = chat_pb2.ReadMessagesRequest(username='user2')
            response = tracked_channel.track_rpc(stub.ReadMessages, request)
            self.assertFalse(any(msg.id == msg_id for msg in response.messages))
            print(f"✅ Verify deletion: {len(response.messages)} messages remaining")

if __name__ == '__main__':
    unittest.main()