import sys
import os
import grpc
import unittest
from concurrent import futures
import time

# Add parent directory to path to import grpc_protocol
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from grpc_protocol import chat_pb2_grpc
from grpc_protocol.server.server import ChatServicer

class TestChatServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        cls.chat_servicer = ChatServicer()  # Assuming ChatServicer is defined in your server code
        chat_pb2_grpc.add_ChatServicer_to_server(cls.chat_servicer, cls.server)
        cls.server.add_insecure_port('[::]:65432')
        cls.server.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop(0)

    def test_login(self):
        with grpc.insecure_channel('localhost:65432') as channel:
            stub = chat_pb2_grpc.ChatStub(channel)
            response = stub.Login(chat_pb2.LoginRequest(username='user1', password='pass1'))
            self.assertTrue(response.success)

    def test_send_message(self):
        with grpc.insecure_channel('localhost:65432') as channel:
            stub = chat_pb2_grpc.ChatStub(channel)
            stub.Login(chat_pb2.LoginRequest(username='user1', password='pass1'))
            response = stub.SendMessage(chat_pb2.SendMessageRequest(sender='user1', recipient='user2', content='Hello!'))
            self.assertTrue(response.success)

            # Check if user2 receives the message
            response_stream = stub.StreamMessages(chat_pb2.StreamMessagesRequest(username='user2'))
            message_response = next(response_stream)
            self.assertEqual(message_response.content, 'Hello!')

    def test_stream_messages(self):
        with grpc.insecure_channel('localhost:65432') as channel:
            stub = chat_pb2_grpc.ChatStub(channel)
            stub.Login(chat_pb2.LoginRequest(username='user1', password='pass1'))
            response_stream = stub.StreamMessages(chat_pb2.StreamMessagesRequest(username='user1'))
            stub.SendMessage(chat_pb2.SendMessageRequest(sender='user2', recipient='user1', content='Hi there!'))
            time.sleep(1)  # Wait for the message to be processed
            message_response = next(response_stream)
            self.assertEqual(message_response.content, 'Hi there!')

    def test_login_and_stream_messages(self):
        # Test user login
        with grpc.insecure_channel('localhost:65432') as channel:
            stub = chat_pb2_grpc.ChatStub(channel)
            response = stub.Login(chat_pb2.LoginRequest(username='user1', password='pass1'))
            self.assertTrue(response.success)

            # Test message streaming
            response_stream = stub.StreamMessages(chat_pb2.StreamMessagesRequest(username='user1'))
            # Send a message to user2 and check if user1 receives it
            stub.SendMessage(chat_pb2.SendMessageRequest(sender='user1', recipient='user2', content='Hello!'))
            time.sleep(1)  # Wait for the message to be processed
            message_response = next(response_stream)
            self.assertEqual(message_response.content, 'Hello!')

if __name__ == '__main__':
    unittest.main()
