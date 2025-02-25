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
            unread_count = sum(1 for msg in all_messages 
                             if not msg.read and msg.recipient == request.username)
            
            return chat_pb2.LoginResponse(
                success=True,
                message=f'Login successful. You have {unread_count} unread messages.',
                unread_count=unread_count,
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
            
            # Store message for both sender and recipient
            self.messages[request.recipient][msg_id] = message
            self.messages[request.sender][msg_id] = message
            
            # Send the actual message to all active sessions
            for username, contexts in self.active_sessions.items():
                for context in contexts:
                    try:
                        context.write(message)
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

    def StreamMessages(self, request, context):
        if request.username not in self.accounts:
            return
        
        # Add the stream context to active sessions
        with self.lock:
            if request.username not in self.active_sessions:
                self.active_sessions[request.username] = []
            self.active_sessions[request.username].append(context)
        
        try:
            # Keep the stream alive
            while context.is_active():
                # Sleep to prevent busy waiting
                time.sleep(0.1)
        finally:
            # Remove the stream when the client disconnects
            with self.lock:
                if request.username in self.active_sessions:
                    self.active_sessions[request.username].remove(context)
                    if not self.active_sessions[request.username]:
                        del self.active_sessions[request.username]

def serve(host='0.0.0.0', port=65432):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
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
