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

# Add protos directory to Python path
protos_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'protos')
sys.path.append(protos_dir)

import chat_pb2
import chat_pb2_grpc
from persistence import DataPersistence

class ChatServicer(chat_pb2_grpc.ChatClientServiceServicer, chat_pb2_grpc.ChatReplicationServiceServicer):
    def __init__(self, host: str = 'localhost', port: int = 65432, server_id: int = 0):
        from config import load_server_config
        
        self.host = host
        self.port = port
        self.server_id = server_id
        
        # Load configuration
        self.config = load_server_config()
        self.data_dir = os.path.join(self.config['database']['connection'], f'server_{server_id}')
        self.persistence = DataPersistence(self.data_dir)
        
        # Initialize active sessions
        self.active_sessions = {}  # username -> list of Queue instances
        self.lock = threading.Lock()
        
        # Keep track of other servers
        self.other_servers = [
            (server['host'], server['port'])
            for server in self.config['servers']
            if server['id'] != server_id
        ]
        
        # Initialize replication state
        self.version = int(time.time() * 1000)  # Lamport timestamp
        self.replication_stubs = {}
        self.channels = {}
        
        # Load data from our own files
        self.messages = self.persistence.load_messages() or {}
        self.accounts = self.persistence.load_accounts() or {}
        self.next_msg_id = self.persistence.load_msg_id() or 0
        
        # Start background thread for server discovery
        self.discovery_thread = threading.Thread(target=self._server_discovery, daemon=True)
        self.discovery_thread.start()
        
    def _server_discovery(self):
        """Background thread to discover and connect to other servers"""
        while True:
            # First, clean up any dead connections
            for (host, port) in list(self.replication_stubs.keys()):
                try:
                    # Test if connection is still alive
                    request = chat_pb2.SyncRequest(
                        server_id=self.server_id,
                        last_version=self.version
                    )
                    self.replication_stubs[(host, port)].SyncState(request, timeout=1)
                except Exception as e:
                    print(f"Removing dead connection to {host}:{port}: {e}")
                    self.channels.pop((host, port), None)
                    self.replication_stubs.pop((host, port), None)
            
            # Then try to establish new connections
            for host, port in self.other_servers:
                if (host, port) not in self.replication_stubs:
                    try:
                        print(f"Attempting to connect to server at {host}:{port}...")
                        # Try to establish connection
                        channel = grpc.insecure_channel(
                            f"{host}:{port}",
                            options=[
                                ('grpc.enable_http_proxy', 0),
                                ('grpc.keepalive_time_ms', 10000),
                                ('grpc.keepalive_timeout_ms', 5000),
                                ('grpc.keepalive_permit_without_calls', True),
                                ('grpc.http2.min_time_between_pings_ms', 10000),
                                ('grpc.http2.max_pings_without_data', 0),
                                ('grpc.max_receive_message_length', 10 * 1024 * 1024),
                                ('grpc.max_reconnect_backoff_ms', 2000),
                            ]
                        )
                        
                        # Test connection with timeout
                        future = grpc.channel_ready_future(channel)
                        future.result(timeout=2)  # Increased timeout
                        
                        # Create stub and store it
                        stub = chat_pb2_grpc.ChatReplicationServiceStub(channel)
                        
                        # Test the connection with a sync request
                        request = chat_pb2.SyncRequest(
                            server_id=self.server_id,
                            last_version=self.version
                        )
                        stub.SyncState(request, timeout=2)
                        
                        # Store working connection
                        self.replication_stubs[(host, port)] = stub
                        self.channels[(host, port)] = channel
                        
                        # Sync with the new server
                        try:
                            print(f"Syncing with server at {host}:{port}...")
                            self._sync_with_server(stub)
                            print(f"Successfully connected to replica at {host}:{port}")
                        except Exception as e:
                            print(f"Error syncing with server at {host}:{port}: {e}")
                            # Clean up failed connection
                            self.channels.pop((host, port), None)
                            self.replication_stubs.pop((host, port), None)
                    except Exception as e:
                        print(f"Failed to connect to {host}:{port}: {e}")
                        # Clean up failed connection attempt
                        if (host, port) in self.channels:
                            try:
                                self.channels[(host, port)].close()
                            except:
                                pass
                            self.channels.pop((host, port), None)
                            self.replication_stubs.pop((host, port), None)
            time.sleep(1)  # Check more frequently
    
    def _sync_with_server(self, stub):
        """Sync state with another server"""
        try:
            # Request sync with our last known version
            request = chat_pb2.SyncRequest(
                server_id=self.server_id,
                last_version=self.version
            )
            print(f"Requesting sync with version {self.version}")
            response = stub.SyncState(request, timeout=5)
            
            # If their state is newer, update ours
            if response.state.version > self.version:
                print(f"Updating state from version {self.version} to {response.state.version}")
                self.version = response.state.version
                
                # Update accounts and messages
                for username, account in response.state.accounts.items():
                    print(f"Syncing account for {username}")
                    self.accounts[username] = {
                        'password_hash': account.password_hash
                    }
                    if username not in self.messages:
                        self.messages[username] = {}
                
                for username, user_msgs in response.state.messages.items():
                    if username not in self.messages:
                        self.messages[username] = {}
                    for msg_id_str, msg in user_msgs.messages.items():
                        msg_id = int(msg_id_str)  # Convert string key to int
                        print(f"Syncing message {msg_id} for {username}")
                        self.messages[username][msg_id] = {
                            'id': msg.id,
                            'sender': msg.sender,
                            'recipient': msg.recipient,
                            'content': msg.content,
                            'timestamp': msg.timestamp,
                            'read': msg.read
                        }
                        
                        # Create ChatMessage for active sessions
                        message = chat_pb2.ChatMessage(
                            id=msg.id,
                            sender=msg.sender,
                            recipient=msg.recipient,
                            content=msg.content,
                            timestamp=msg.timestamp,
                            read=msg.read
                        )
                        
                        # Notify active sessions
                        if username in self.active_sessions:
                            for q in self.active_sessions[username]:
                                try:
                                    q.put(message)
                                except Exception as e:
                                    print(f"Error notifying session: {e}")
                
                self.next_msg_id = max(self.next_msg_id, response.state.next_msg_id)
                
                # Save to persistence
                print(f"Saving synced state: {len(self.messages)} users with messages")
                self.persistence.save_accounts(self.accounts)
                self.persistence.save_messages(self.messages)
                self.persistence.save_msg_id(self.next_msg_id)
        except Exception as e:
            print(f"Error syncing with server: {e}")
            raise
    
    def _propagate_update(self, update_type, affected_data=None):
        """Propagate an update to all other servers"""
        # Increment our version
        self.version = max(self.version, int(time.time() * 1000)) + 1
        print(f"Propagating update type {update_type} with version {self.version}")
        
        # Create delta state based on update type
        delta_state = chat_pb2.ServerState(
            version=self.version,
            next_msg_id=self.next_msg_id
        )
        
        if update_type in [chat_pb2.UpdateRequest.ACCOUNT_CREATED, chat_pb2.UpdateRequest.ACCOUNT_DELETED]:
            # For account updates, include just the affected account
            username = affected_data
            if username in self.accounts:
                delta_state.accounts[username].password_hash = self.accounts[username]['password_hash']
                print(f"Propagating account update for {username}")
        
        elif update_type == chat_pb2.UpdateRequest.MESSAGE_SENT:
            # For message updates, include just the new message
            msg = affected_data
            sender = msg['sender']
            recipient = msg['recipient']
            msg_id = msg['id']
            
            # Add message to both sender and recipient in delta state
            for username in [sender, recipient]:
                if username not in delta_state.messages:
                    delta_state.messages[username] = chat_pb2.UserMessages()
                delta_state.messages[username].messages[str(msg_id)].CopyFrom(  # Convert msg_id to string
                    chat_pb2.ChatMessage(
                        id=msg['id'],
                        sender=msg['sender'],
                        recipient=msg['recipient'],
                        content=msg['content'],
                        timestamp=msg['timestamp'],
                        read=msg['read']
                    )
                )
            print(f"Propagating message {msg_id} from {sender} to {recipient}")
        
        # Create update request
        request = chat_pb2.UpdateRequest(
            type=update_type,
            delta_state=delta_state,
            version=self.version
        )
        
        # Send to all other servers
        for host, stub in self.replication_stubs.items():
            try:
                print(f"Sending update to server at {host}")
                stub.PropagateUpdate(request, timeout=5)
            except Exception as e:
                print(f"Error propagating update to {host}: {e}")
    
    # Replication service handlers
    def SyncState(self, request, context):
        """Handle sync request from another server"""
        with self.lock:
            print(f"Received sync request from server {request.server_id} with version {request.last_version}")
            # Convert our state to proto format
            state = chat_pb2.ServerState(
                version=self.version,
                next_msg_id=self.next_msg_id
            )
            
            # Add accounts
            for username, account in self.accounts.items():
                print(f"Including account {username} in sync response")
                state.accounts[username].password_hash = account['password_hash']
            
            # Add messages
            for username, msgs in self.messages.items():
                if msgs:  # Only add if there are messages
                    print(f"Including {len(msgs)} messages for {username} in sync response")
                    state.messages[username] = chat_pb2.UserMessages()
                    for msg_id, msg in msgs.items():
                        chat_msg = chat_pb2.ChatMessage(
                            id=msg['id'],
                            sender=msg['sender'],
                            recipient=msg['recipient'],
                            content=msg['content'],
                            timestamp=msg['timestamp'],
                            read=msg['read']
                        )
                        state.messages[username].messages[str(msg_id)].CopyFrom(chat_msg)
            
            print(f"Sending sync response with version {self.version}")
            return chat_pb2.SyncResponse(state=state)
    
    def PropagateUpdate(self, request, context):
        """Handle update from another server"""
        with self.lock:
            print(f"Received update with version {request.version} (our version: {self.version})")
            # Only apply update if it's newer than our version
            if request.version <= self.version:
                print(f"Ignoring update with older version {request.version}")
                return chat_pb2.UpdateResponse(
                    success=False,
                    message="Update version is older or equal to current version"
                )
            
            # Update our version
            print(f"Updating to version {request.version}")
            self.version = request.version
            
            # Apply the changes based on update type
            delta = request.delta_state
            if request.type in [chat_pb2.UpdateRequest.ACCOUNT_CREATED, chat_pb2.UpdateRequest.ACCOUNT_DELETED]:
                # Update accounts
                for username, account in delta.accounts.items():
                    if request.type == chat_pb2.UpdateRequest.ACCOUNT_CREATED:
                        print(f"Creating account for {username}")
                        self.accounts[username] = {
                            'password_hash': account.password_hash
                        }
                        if username not in self.messages:
                            self.messages[username] = {}
                    else:  # ACCOUNT_DELETED
                        print(f"Deleting account for {username}")
                        self.accounts.pop(username, None)
                        self.messages.pop(username, None)
            
            elif request.type == chat_pb2.UpdateRequest.MESSAGE_SENT:
                # Update messages
                for username, user_msgs in delta.messages.items():
                    if username not in self.messages:
                        self.messages[username] = {}
                    for msg_id_str, msg in user_msgs.messages.items():
                        msg_id = int(msg_id_str)  # Convert string key to int
                        print(f"Adding message {msg_id} to {username}'s messages")
                        self.messages[username][msg_id] = {
                            'id': msg.id,
                            'sender': msg.sender,
                            'recipient': msg.recipient,
                            'content': msg.content,
                            'timestamp': msg.timestamp,
                            'read': msg.read
                        }
                        self.next_msg_id = max(self.next_msg_id, msg.id + 1)
                        
                        # Create ChatMessage for active sessions
                        message = chat_pb2.ChatMessage(
                            id=msg.id,
                            sender=msg.sender,
                            recipient=msg.recipient,
                            content=msg.content,
                            timestamp=msg.timestamp,
                            read=msg.read
                        )
                        
                        # Notify active sessions
                        if username in self.active_sessions:
                            for q in self.active_sessions[username]:
                                try:
                                    q.put(message)
                                except Exception as e:
                                    print(f"Error notifying session: {e}")
            
            # Save changes to persistence
            print("Saving changes to disk")
            self.persistence.save_accounts(self.accounts)
            self.persistence.save_messages(self.messages)
            self.persistence.save_msg_id(self.next_msg_id)
            
            return chat_pb2.UpdateResponse(success=True, message="Update applied successfully")
    
    def _sync_with_server(self, stub):
        """Sync state with another server"""
        try:
            # Request sync with our last known version
            request = chat_pb2.SyncRequest(
                server_id=self.server_id,
                last_version=self.version
            )
            response = stub.SyncState(request, timeout=5)
            
            # If their state is newer, update ours
            if response.state.version > self.version:
                self.version = response.state.version
                
                # Update accounts and messages
                for username, account in response.state.accounts.items():
                    self.accounts[username] = {
                        'password_hash': account.password_hash
                    }
                
                for username, user_msgs in response.state.messages.items():
                    if username not in self.messages:
                        self.messages[username] = {}
                    for msg_id, msg in user_msgs.messages.items():
                        self.messages[username][msg_id] = {
                            'id': msg.id,
                            'sender': msg.sender,
                            'recipient': msg.recipient,
                            'content': msg.content,
                            'timestamp': msg.timestamp,
                            'read': msg.read
                        }
                
                self.next_msg_id = max(self.next_msg_id, response.state.next_msg_id)
                
                # Save to persistence
                self.persistence.save_accounts(self.accounts)
                self.persistence.save_messages(self.messages)
                self.persistence.save_msg_id(self.next_msg_id)
        except Exception as e:
            print(f"Error syncing with server: {e}")
                
    def _propagate_update(self, update_type, affected_data=None):
        """Propagate an update to all other servers"""
        # Increment our version (Lamport timestamp)
        self.version = max(self.version, int(time.time() * 1000)) + 1
        
        # Create the delta state with only changed data
        delta = chat_pb2.ServerState(
            version=self.version,
            next_msg_id=self.next_msg_id
        )
        
        if affected_data:
            if update_type in [chat_pb2.UpdateRequest.ACCOUNT_CREATED, chat_pb2.UpdateRequest.ACCOUNT_DELETED]:
                username = affected_data
                if username in self.accounts:
                    delta.accounts[username].password_hash = self.accounts[username]['password_hash']
            elif update_type == chat_pb2.UpdateRequest.MESSAGE_SENT:
                msg = affected_data
                if msg['sender'] not in delta.messages:
                    delta.messages[msg['sender']] = chat_pb2.UserMessages()
                if msg['recipient'] not in delta.messages:
                    delta.messages[msg['recipient']] = chat_pb2.UserMessages()
                
                # Add message to both sender and recipient's message lists
                for username in [msg['sender'], msg['recipient']]:
                    chat_msg = chat_pb2.ChatMessage(
                        id=msg['id'],
                        sender=msg['sender'],
                        recipient=msg['recipient'],
                        content=msg['content'],
                        timestamp=msg['timestamp'],
                        read=msg['read']
                    )
                    delta.messages[username].messages[msg['id']].CopyFrom(chat_msg)
        
        # Create update request
        request = chat_pb2.UpdateRequest(
            type=update_type,
            delta_state=delta,
            version=self.version
        )
        
        # Send to all connected servers
        for (host, port), stub in self.replication_stubs.items():
            try:
                response = stub.PropagateUpdate(request, timeout=5)
                if not response.success:
                    print(f"Failed to propagate update to {host}:{port}: {response.message}")
            except Exception as e:
                print(f"Error propagating update to {host}:{port}: {e}")
                # Remove failed stub
                self.channels.pop((host, port), None)
                self.replication_stubs.pop((host, port), None)

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
            
            # Persist changes and sync
            print(f"Saving account data for {request.username}")
            self.persistence.save_accounts(self.accounts)
            self.persistence.save_messages(self.messages)
            self.sync_with_other_servers()
            
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
                
            # Persist changes and sync
            self.persistence.save_accounts(self.accounts)
            self.persistence.save_messages(self.messages)
            self.sync_with_other_servers()
            
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
            
            # Create message with current timestamp
            timestamp = datetime.now().isoformat()
            
            # Create message object first
            message = chat_pb2.ChatMessage(
                id=msg_id,
                sender=request.sender,
                recipient=request.recipient,
                content=request.content,
                timestamp=timestamp,
                read=False
            )
            
            # Convert to dict for storage
            message_dict = {
                'id': msg_id,
                'sender': request.sender,
                'recipient': request.recipient,
                'content': request.content,
                'timestamp': timestamp,
                'read': False
            }
            
            print(f"Storing message {msg_id} from {request.sender} to {request.recipient}")
            self.messages[request.recipient][msg_id] = message_dict
            self.messages[request.sender][msg_id] = message_dict
            
            # Persist changes
            print(f"Saving message to disk")
            self.persistence.save_messages(self.messages)
            self.persistence.save_msg_id(self.next_msg_id)
            
            # Propagate the update to other servers
            print(f"Propagating message to other servers")
            self._propagate_update(chat_pb2.UpdateRequest.MESSAGE_SENT, message_dict)
            
            # Notify active sessions
            print(f"Notifying active sessions")
            for username in [request.sender, request.recipient]:
                if username in self.active_sessions:
                    for q in self.active_sessions[username]:
                        try:
                            q.put(message)
                        except Exception as e:
                            print(f"Error notifying session: {e}")
            
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
    
    # Register both services
    chat_pb2_grpc.add_ChatClientServiceServicer_to_server(servicer, server)
    chat_pb2_grpc.add_ChatReplicationServiceServicer_to_server(servicer, server)
    
    server.add_insecure_port(f'{host}:{port}')
    server.start()
    print(f"Server {server_id} started on {host}:{port}")
    
    def handle_shutdown(signum, frame):
        print(f"\nServer {server_id} shutting down...")
        # Close all replication channels
        for channel in servicer.channels.values():
            try:
                channel.close()
            except:
                pass
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
