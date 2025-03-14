import grpc
from concurrent import futures
import threading
import bcrypt
from datetime import datetime
import argparse
import os
import sys
import time
import queue
import signal
import base64

# Add the parent directory to the Python path so we can import the generated code
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import chat_pb2
import chat_pb2_grpc
from persistence import DataPersistence

class ChatServicer(chat_pb2_grpc.ChatServiceServicer):
    def __init__(self, host: str = 'localhost', port: int = 65432, server_id: int = 0):
        self.host = host
        self.port = port
        self.server_id = server_id
        self.data_dir = f'server_data_{server_id}'
        self.persistence = DataPersistence(self.data_dir)
        
        # Load persisted data
        self.messages = self.persistence.load_messages()
        self.accounts = self.persistence.load_accounts()
        self.next_msg_id = self.persistence.load_msg_id()
        
        # Initialize active sessions
        self.active_sessions = {}  # username -> list of Queue instances
        self.lock = threading.Lock()
        
        # Keep track of other servers
        self.base_port = 65432
        self.other_servers = [
            f'{host}:{self.base_port + i}' 
            for i in range(3) if i != server_id
        ]

    def CreateAccount(self, request, context):
        print(f"Received registration request for user: {request.username}")
        with self.lock:
            if request.username in self.accounts:
                print(f"Username {request.username} already exists")
                return chat_pb2.StatusResponse(
                    success=False,
                    message='Username already exists'
                )
            
            print(f"Creating new account for {request.username}")
            salt = bcrypt.gensalt()
            password_hash = bcrypt.hashpw(request.password.encode('utf-8'), salt)
            
            self.accounts[request.username] = {
                'password_hash': base64.b64encode(password_hash).decode('utf-8')
            }
            self.messages[request.username] = {}
            
            # Persist changes
            print(f"Saving account data for {request.username}")
            self.persistence.save_accounts(self.accounts)
            self.persistence.save_messages(self.messages)
            
            print(f"Account created successfully for {request.username}")
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
        
        stored_hash = base64.b64decode(self.accounts[request.username]['password_hash'].encode('utf-8'))
        if not bcrypt.checkpw(request.password.encode('utf-8'), stored_hash):
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
            
            # Count unread messages (without marking them as read yet)
            unread_count = sum(1 for msg in all_messages 
                            if not msg.read and msg.recipient == request.username)
            
            # Return login response with unread message count
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
        
        stored_hash = base64.b64decode(self.accounts[request.username]['password_hash'].encode('utf-8'))
        if not bcrypt.checkpw(request.password.encode('utf-8'), stored_hash):
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
            
            # Persist changes
            self.persistence.save_messages(self.messages)
            self.persistence.save_msg_id(self.next_msg_id)
            
            # Print message dictionaries for debugging
            print(self.messages)
            # print("\n=== Current Message Dictionaries ===")
            # for username, msgs in self.messages.items():
            #     if msgs:  # Only print if user has messages
            #         print(f"\nMessages for {username}:")
            #         for msg_id, msg in msgs.items():
            #             print(f"  Message ID: {msg_id}")
            #             print(f"    From: {msg.sender}")
            #             print(f"    To: {msg.recipient}")
            #             print(f"    Content: {msg.content}")
            #             print(f"    Time: {msg.timestamp}")
            #             print(f"    Read: {msg.read}")
            # print("===================================\n")

            # Enqueue the new message to all active sessions for sender and recipient
            recipients = {request.sender, request.recipient}
            for username in recipients:
                if username in self.active_sessions:
                    for q in self.active_sessions[username]:
                        try:
                            q.put(message)
                        except Exception:
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
                        if msg.recipient == request.username and not msg.read:
                            msg.read = True  # Mark the message as read
                        relevant_messages.append(msg)
            # Otherwise, return all messages
            else:
                for msg in self.messages[request.username].values():
                    if msg.recipient == request.username and not msg.read:
                        msg.read = True  # Mark the message as read
                    relevant_messages.append(msg)
            
            return chat_pb2.ReadMessagesResponse(messages=relevant_messages)

    def DeleteMessages(self, request, context):
        if request.username not in self.accounts:
            return chat_pb2.StatusResponse(
                success=False,
                message='User not found'
            )
        
        with self.lock:
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
                            
                            # Create deletion notification
                            deletion_notification = chat_pb2.ChatMessage(
                                id=msg_id,
                                sender=msg.sender,
                                recipient=msg.recipient,
                                content="<message deleted>",
                                timestamp=datetime.now().isoformat(),
                                read=True
                            )
                            
                            # Enqueue deletion notification to active sessions for both users
                            for username in [msg.sender, msg.recipient]:
                                if username in self.active_sessions:
                                    for q in self.active_sessions[username]:
                                        try:
                                            q.put(deletion_notification)
                                        except Exception:
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
        
        # Create a dedicated queue for this stream
        local_queue = queue.Queue()
        with self.lock:
            if request.username not in self.active_sessions:
                self.active_sessions[request.username] = []
            self.active_sessions[request.username].append(local_queue)
            
            # Collect all existing messages for this user
            messages = []
            for user_messages in self.messages.values():
                for msg in user_messages.values():
                    if msg.sender == request.username or msg.recipient == request.username:
                        messages.append(msg)
            messages.sort(key=lambda x: x.id)
        
        # First, yield all existing messages
        for msg in messages:
            yield msg
        
        try:
            # Now continuously yield new messages from the local queue
            while context.is_active():
                try:
                    msg = local_queue.get(timeout=0.1)
                    yield msg
                except queue.Empty:
                    continue
        finally:
            # Cleanup: remove the local queue from active sessions when done
            with self.lock:
                if request.username in self.active_sessions and local_queue in self.active_sessions[request.username]:
                    self.active_sessions[request.username].remove(local_queue)
                    if not self.active_sessions[request.username]:
                        del self.active_sessions[request.username]

def serve(host='0.0.0.0', port=65432, server_id=0):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=50))
    servicer = ChatServicer(host=host, port=port, server_id=server_id)
    chat_pb2_grpc.add_ChatServiceServicer_to_server(servicer, server)
    server.add_insecure_port(f'{host}:{port}')
    server.start()
    print(f"Server {server_id} started on {host}:{port}")
    
    def handle_shutdown(signum, frame):
        print(f"\nServer {server_id} shutting down...")
        # Save final state
        servicer.persistence.save_messages(servicer.messages)
        servicer.persistence.save_accounts(servicer.accounts)
        servicer.persistence.save_msg_id(servicer.next_msg_id)
        server.stop(0)
        sys.exit(0)
    
    signal.signal(signal.SIGINT, handle_shutdown)
    server.wait_for_termination()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Start the chat server.")
    parser.add_argument("--host", default=os.getenv("CHAT_SERVER_HOST", "0.0.0.0"),
                        help="Server hostname or IP")
    parser.add_argument("--port", type=int, default=int(os.getenv("CHAT_SERVER_PORT", "65432")),
                        help="Port number")
    parser.add_argument("--server-id", type=int, default=0,
                        help="Server ID (0-2)")
    args = parser.parse_args()

    # Pass the parsed arguments to the serve function
    serve(host=args.host, port=args.port, server_id=args.server_id)
