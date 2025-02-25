import grpc
from concurrent import futures
import threading
import bcrypt
from datetime import datetime
import argparse
import os
import sys
import time

# Add the parent directory to the Python path so we can import the generated code
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import chat_pb2
import chat_pb2_grpc

class ChatServicer(chat_pb2_grpc.ChatServiceServicer):
    def __init__(self):
        self.messages = {}  # username -> {msg_id: message}
        self.accounts = {}  # username -> {password_hash}
        self.active_sessions = {}  # username -> list of message streams
        self.lock = threading.Lock()
        self.next_msg_id = 0

    def CreateAccount(self, request, context):
        with self.lock:
            if request.username in self.accounts:
                return chat_pb2.StatusResponse(
                    success=False,
                    message='Username already exists'
                )
            
            salt = bcrypt.gensalt()
            password_hash = bcrypt.hashpw(request.password.encode('utf-8'), salt)
            
            self.accounts[request.username] = {
                'password_hash': password_hash
            }
            self.messages[request.username] = {}
            
            return chat_pb2.StatusResponse(
                success=True,
                message='Account created successfully'
            )

    def Login(self, request, context):
        if request.username not in self.accounts:
            return chat_pb2.LoginResponse(
                success=False,
                message='Username not found'
            )
        
        if not bcrypt.checkpw(request.password.encode('utf-8'), 
                            self.accounts[request.username]['password_hash']):
            return chat_pb2.LoginResponse(
                success=False,
                message='Invalid password'
            )
        
        with self.lock:
            # Get all messages involving this user
            all_messages = []
            for user_messages in self.messages.values():
                for msg in user_messages.values():
                    if msg.sender == request.username or msg.recipient == request.username:
                        all_messages.append(msg)
            
            # Sort messages by ID
            all_messages.sort(key=lambda x: x.id)
            
            # Count unread messages
            # (Add your existing unread message counting logic here)

            # Add the user to active sessions
            if request.username not in self.active_sessions:
                self.active_sessions[request.username] = []
            
            # Add the current stream to the user's active sessions
            self.active_sessions[request.username].append(context)

        return chat_pb2.LoginResponse(
            success=True,
            message='Login successful',
            messages=all_messages
        )

    def DeleteAccount(self, request, context):
        if request.username not in self.accounts:
            return chat_pb2.StatusResponse(
                success=False,
                message='User not found'
            )
        
        if not bcrypt.checkpw(request.password.encode('utf-8'), 
                            self.accounts[request.username]['password_hash']):
            return chat_pb2.StatusResponse(
                success=False,
                message='Invalid password'
            )
        
        with self.lock:
            # Remove user's account and messages
            del self.accounts[request.username]
            del self.messages[request.username]
            
            # Remove user from active sessions
            if request.username in self.active_sessions:
                del self.active_sessions[request.username]
            
            return chat_pb2.StatusResponse(
                success=True,
                message='Account deleted successfully'
            )

    def ListAccounts(self, request, context):
        accounts = list(self.accounts.keys())
        if request.pattern:
            accounts = [acc for acc in accounts 
                       if request.pattern.lower() in acc.lower()]
        return chat_pb2.ListAccountsResponse(accounts=accounts)

    def SendMessage(self, request, context):
        if request.recipient not in self.accounts:
            return chat_pb2.SendMessageResponse(
                success=False,
                message='Recipient not found'
            )
        
        with self.lock:
            msg_id = self.next_msg_id
            self.next_msg_id += 1
            
            message = chat_pb2.ChatMessage(
                id=msg_id,
                sender=request.sender,
                recipient=request.recipient,
                content=request.content,
                timestamp=datetime.now().isoformat(),
                read=False
            )
            
            # Ensure message dictionaries exist for both users
            if request.recipient not in self.messages:
                self.messages[request.recipient] = {}
            if request.sender not in self.messages:
                self.messages[request.sender] = {}
            
            # Store message for both sender and recipient
            self.messages[request.recipient][msg_id] = message
            self.messages[request.sender][msg_id] = message
            
            # Immediately send message to active sessions
            for username in [request.sender, request.recipient]:
                if username in self.active_sessions:
                    for context in self.active_sessions[username]:
                        try:
                            # Force immediate write without buffering
                            context.write(message)
                            context._state.core._flush()
                        except:
                            pass
            
            return chat_pb2.SendMessageResponse(
                success=True,
                message='Message sent',
                message_id=msg_id
            )

    def ReadMessages(self, request, context):
        if request.username not in self.accounts:
            return chat_pb2.ReadMessagesResponse()
        
        with self.lock:
            relevant_messages = []
            # If sender is specified, filter messages for that conversation
            if request.sender:
                for msg in self.messages[request.username].values():
                    if msg.sender == request.sender or msg.recipient == request.sender:
                        if msg.recipient == request.username:
                            msg.read = True
                        relevant_messages.append(msg)
            # Otherwise, return all messages
            else:
                for msg in self.messages[request.username].values():
                    if msg.recipient == request.username:
                        msg.read = True
                    relevant_messages.append(msg)
            
            return chat_pb2.ReadMessagesResponse(messages=relevant_messages)

    def DeleteMessages(self, request, context):
        if request.username not in self.accounts:
            return chat_pb2.StatusResponse(
                success=False,
                message='User not found'
            )
        
        with self.lock:
            # Find messages to delete
            deleted = False
            for msg_id in request.message_ids:
                for username, user_messages in self.messages.items():
                    if msg_id in user_messages:
                        msg = user_messages[msg_id]
                        if msg.sender == request.username:
                            # Delete message from both sender and recipient
                            del self.messages[msg.sender][msg_id]
                            if msg.recipient in self.messages and msg_id in self.messages[msg.recipient]:
                                del self.messages[msg.recipient][msg_id]
                            deleted = True
                            
                            # Notify active sessions about deletion
                            deletion_notification = chat_pb2.ChatMessage(
                                id=msg_id,
                                sender=msg.sender,
                                recipient=msg.recipient,
                                content="<message deleted>",
                                timestamp=datetime.now().isoformat(),
                                read=True
                            )
                            
                            # Send notification to all active sessions
                            for username, contexts in self.active_sessions.items():
                                if username in [msg.sender, msg.recipient]:
                                    for context in contexts:
                                        try:
                                            context.write(deletion_notification)
                                        except:
                                            pass
            
            return chat_pb2.StatusResponse(
                success=deleted,
                message='Messages deleted' if deleted else 'No messages found to delete'
            )

    def GetUnreadCount(self, request, context):
        if request.username not in self.accounts:
            return chat_pb2.UnreadCountResponse(unread_count=0)
        
        with self.lock:
            unread_count = sum(
                1 for msg in self.messages[request.username].values()
                if msg.recipient == request.username and not msg.read
            )
            
            return chat_pb2.UnreadCountResponse(unread_count=unread_count)

    def Logout(self, request, context):
        with self.lock:
            if request.username in self.active_sessions:
                # Remove the user's stream from active sessions
                self.active_sessions[request.username].remove(context)
                if not self.active_sessions[request.username]:
                    del self.active_sessions[request.username]

    def StreamMessages(self, request, context):
        if request.username not in self.accounts:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details('User not found')
            return
        
        with self.lock:
            # Add the current stream to active sessions
            if request.username not in self.active_sessions:
                self.active_sessions[request.username] = []
            self.active_sessions[request.username].append(context)

        try:
            while True:
                # Wait for new messages to be sent to this user
                new_messages = self.messages.get(request.username, {}).values()
                for msg in new_messages:
                    yield chat_pb2.MessageResponse(
                        sender=msg.sender,
                        recipient=msg.recipient,
                        content=msg.content,
                        timestamp=msg.timestamp
                    )
                time.sleep(1)  # Adjust the sleep time as necessary for performance
        except grpc.RpcError:
            pass
        finally:
            # Remove the stream from active sessions on disconnect
            with self.lock:
                self.active_sessions[request.username].remove(context)
                if not self.active_sessions[request.username]:
                    del self.active_sessions[request.username]

def serve(host='0.0.0.0', port=65432):
    # Create server with better connection stability settings
    options = [
        ('grpc.max_send_message_length', 512 * 1024),  # 512KB
        ('grpc.max_receive_message_length', 512 * 1024),  # 512KB
        ('grpc.keepalive_time_ms', 5000),  # 5 seconds (reduced from 10)
        ('grpc.keepalive_timeout_ms', 2000),  # 2 seconds (reduced from 5)
        ('grpc.keepalive_permit_without_calls', 1),  # Allow keepalive pings when there are no calls
        ('grpc.http2.min_time_between_pings_ms', 5000),  # 5 seconds
        ('grpc.http2.max_pings_without_data', 5),  # Allow more pings without data
        ('grpc.http2.min_ping_interval_without_data_ms', 2000),  # 2 seconds
        ('grpc.max_connection_idle_ms', 60000),  # 1 minute max idle
        ('grpc.max_connection_age_ms', 300000),  # 5 minutes max age
        ('grpc.max_connection_age_grace_ms', 5000),  # 5 seconds grace period
    ]
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10),
        options=options
    )
    chat_pb2_grpc.add_ChatServiceServicer_to_server(ChatServicer(), server)
    server.add_insecure_port(f'{host}:{port}')
    server.start()
    print(f"Server started on {host}:{port}")
    server.wait_for_termination()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Start the chat server.")
    parser.add_argument("--host", default=os.getenv("CHAT_SERVER_HOST", "0.0.0.0"),
                      help="Server hostname or IP")
    parser.add_argument("--port", type=int, default=int(os.getenv("CHAT_SERVER_PORT", "65432")),
                      help="Server port")
    args = parser.parse_args()
    serve(args.host, args.port)
