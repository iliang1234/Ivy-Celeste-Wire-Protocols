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

class ChatServicer(chat_pb2_grpc.ChatClientServiceServicer,
                   chat_pb2_grpc.ChatReplicationServiceServicer):
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
        
        # Keep track of other servers (host, port) except myself
        self.other_servers = [
            (server['host'], server['port'])
            for server in self.config['servers']
            if server['id'] != server_id
        ]
        
        # Quorum settings for 2-fault tolerance
        self.read_quorum = self.config['quorum']['read']
        self.write_quorum = self.config['quorum']['write']
        
        # Initialize replication state
        self.version = int(time.time() * 1000)  # Lamport timestamp
        self.replication_stubs = {}  # (host,port)-> stub
        self.channels = {}           # (host,port)-> channel
        self.server_states = {}      # (host,port)-> last known state version
        
        # Load data from local persistent files
        self.messages = self.persistence.load_messages() or {}
        self.accounts = self.persistence.load_accounts() or {}
        self.next_msg_id = self.persistence.load_msg_id() or 0
        
        # Start background threads
        self.discovery_thread = threading.Thread(target=self._server_discovery, daemon=True)
        self.sync_thread = threading.Thread(target=self._periodic_sync, daemon=True)
        self.discovery_thread.start()
        self.sync_thread.start()
    
    def _server_discovery(self):
        """Background thread that repeatedly attempts to connect or re-connect to other servers
           and calls _sync_with_server() if successful."""
        while True:
            # First, check if existing stubs are alive
            for (host, port) in list(self.replication_stubs.keys()):
                try:
                    request = chat_pb2.SyncRequest(server_id=self.server_id, last_version=self.version)
                    self.replication_stubs[(host, port)].SyncState(request, timeout=1)
                except Exception as e:
                    print(f"[Discovery] Stub {host}:{port} check failed: {e}")
            
            # Then, for every server in other_servers, if we don't have a stub, try connecting
            for (host, port) in self.other_servers:
                if (host, port) not in self.replication_stubs:
                    # Use 127.0.0.1 here instead of localhost
                    print(f"[Discovery] Attempting initial connection to {host}:{port}...")
                    try:
                        channel = grpc.insecure_channel(
                            f"{host}:{port}",
                            options=[
                                ('grpc.enable_http_proxy', 0),
                                ('grpc.keepalive_time_ms', 30000),
                                ('grpc.keepalive_timeout_ms', 10000),
                                ('grpc.keepalive_permit_without_calls', True),
                                ('grpc.http2.min_time_between_pings_ms', 30000),
                                ('grpc.http2.max_pings_without_data', 2),
                                ('grpc.max_receive_message_length', 10 * 1024 * 1024),
                                ('grpc.max_reconnect_backoff_ms', 2000),
                            ]
                        )
                        # Increase channel ready timeout to 5 seconds
                        future = grpc.channel_ready_future(channel)
                        future.result(timeout=5)
                        
                        stub = chat_pb2_grpc.ChatReplicationServiceStub(channel)
                        
                        # Test a SyncState call quickly
                        test_req = chat_pb2.SyncRequest(server_id=self.server_id, last_version=self.version)
                        stub.SyncState(test_req, timeout=2)
                        
                        self.replication_stubs[(host, port)] = stub
                        self.channels[(host, port)] = channel
                        
                        print(f"[Discovery] Connected to {host}:{port}. Now attempting a full sync...")
                        self._sync_with_server(stub)
                        print(f"[Discovery] Full sync from {host}:{port} completed.")
                
                    except Exception as e:
                        print(f"[Discovery] Could not connect to {host}:{port}: {e}")
                        if (host, port) in self.channels:
                            try:
                                self.channels[(host, port)].close()
                            except:
                                pass
                            self.channels.pop((host, port), None)
                            self.replication_stubs.pop((host, port), None)
        time.sleep(2)


    def _sync_with_server(self, stub, host_port=None):
        """
        Request a full state sync from the given stub.
        Returns True if sync was successful, False otherwise.
        """
        try:
            request = chat_pb2.SyncRequest(
                server_id=self.server_id,
                last_version=self.version
            )
            response = stub.SyncState(request, timeout=5)
            remote_version = response.state.version
            
            if host_port:
                self.server_states[host_port] = remote_version
            
            print(f"[Sync] Received SyncState from remote_version={remote_version}, local_version={self.version}")
            
            # Check if we have quorum for this version
            version_counts = {}
            for version in self.server_states.values():
                version_counts[version] = version_counts.get(version, 0) + 1
            
            # Find version with highest quorum
            max_quorum = 0
            quorum_version = None
            for version, count in version_counts.items():
                if count >= self.read_quorum and count > max_quorum:
                    max_quorum = count
                    quorum_version = version
            
            # Only update if we have quorum and remote version is newer
            if quorum_version and quorum_version > self.version:
                print(f"[Sync] Quorum achieved for version {quorum_version}. Updating local state.")
                self.version = quorum_version
                
                # Overwrite local accounts
                remote_accounts = response.state.accounts
                for username, acct in remote_accounts.items():
                    self.accounts[username] = {
                        'password_hash': acct.password_hash
                    }
                    if username not in self.messages:
                        self.messages[username] = {}
                
                # Overwrite local messages
                remote_messages = response.state.messages
                for username, user_msgs in remote_messages.items():
                    if username not in self.messages:
                        self.messages[username] = {}
                    for msg_id_str, msg in user_msgs.messages.items():
                        msg_id = int(msg_id_str)
                        self.messages[username][msg_id] = {
                            'id': msg.id,
                            'sender': msg.sender,
                            'recipient': msg.recipient,
                            'content': msg.content,
                            'timestamp': msg.timestamp,
                            'read': msg.read
                        }
                
                # Update next_msg_id
                self.next_msg_id = max(self.next_msg_id, response.state.next_msg_id)
                
                # Persist updated state
                print("[Sync] Saving synced state to disk.")
                self.persistence.save_accounts(self.accounts)
                self.persistence.save_messages(self.messages)
                self.persistence.save_msg_id(self.next_msg_id)
                return True
            else:
                print(f"[Sync] No quorum or remote version={remote_version} is <= local_version={self.version}; skipping.")
                return False
        
        except Exception as e:
            print(f"[Sync] Error syncing with server: {e}")
            return False

    def _periodic_sync(self):
        """Background thread that periodically syncs state with other servers"""
        while True:
            try:
                # Get list of active stubs
                active_stubs = list(self.replication_stubs.items())
                if not active_stubs:
                    time.sleep(self.config['database']['sync_interval'])
                    continue
                
                # Try to sync with each server
                successful_syncs = 0
                for (host, port), stub in active_stubs:
                    try:
                        if self._sync_with_server(stub, (host, port)):
                            successful_syncs += 1
                    except Exception as e:
                        print(f"[Sync] Error syncing with {host}:{port}: {e}")
                
                # Check if we have write quorum
                if successful_syncs >= self.write_quorum:
                    print(f"[Sync] Write quorum achieved with {successful_syncs} servers")
                else:
                    print(f"[Sync] Warning: Only synced with {successful_syncs} servers, need {self.write_quorum} for write quorum")
            
            except Exception as e:
                print(f"[Sync] Error in periodic sync: {e}")
            
            time.sleep(self.config['database']['sync_interval'])
    
    def _propagate_update(self, update_type, affected_data=None):
        """
        Send an UpdateRequest with a minimal delta to every known server.
        Requires write quorum for success.
        """
        with self.lock:
            # Update our logical clock
            self.version = max(self.version, int(time.time() * 1000)) + 1
            
            # Build minimal delta state
            delta = chat_pb2.ServerState(
                version=self.version,
                next_msg_id=self.next_msg_id
            )
            if affected_data:
                if update_type in [chat_pb2.UpdateRequest.ACCOUNT_CREATED,
                                   chat_pb2.UpdateRequest.ACCOUNT_DELETED]:
                    username = affected_data
                    # Only include the account if it still exists locally
                    if username in self.accounts:
                        delta.accounts[username].password_hash = self.accounts[username]['password_hash']
                
                elif update_type == chat_pb2.UpdateRequest.MESSAGE_SENT:
                    msg = affected_data
                    for user in [msg['sender'], msg['recipient']]:
                        if user not in delta.messages:
                            delta.messages[user] = chat_pb2.UserMessages()
                        chat_msg = chat_pb2.ChatMessage(
                            id=msg['id'],
                            sender=msg['sender'],
                            recipient=msg['recipient'],
                            content=msg['content'],
                            timestamp=msg['timestamp'],
                            read=msg['read']
                        )
                        delta.messages[user].messages[str(msg['id'])].CopyFrom(chat_msg)
            
            request = chat_pb2.UpdateRequest(
                type=update_type,
                delta_state=delta,
                version=self.version
            )
            
            # Broadcast to all stubs
            for (host, port), stub in list(self.replication_stubs.items()):
                try:
                    response = stub.PropagateUpdate(request, timeout=5)
                    if not response.success:
                        print(f"[Propagate] {host}:{port} rejected update: {response.message}")
                except Exception as e:
                    print(f"[Propagate] Failed to update {host}:{port}: {e}")
                    # We won't remove them from replication_stubs, so the discovery thread can keep trying

    # ------------------------------------------------------------------------
    # Replication service handlers (used by other servers calling into us)
    # ------------------------------------------------------------------------
    def SyncState(self, request, context):
        """
        Another server calls us asking for a full snapshot. We'll give them everything.
        """
        with self.lock:
            print(f"[SyncState] Incoming from server {request.server_id} (they have version={request.last_version}, local={self.version})")
            
            # Build full state from our local data
            state = chat_pb2.ServerState(
                version=self.version,
                next_msg_id=self.next_msg_id
            )
            
            # Add all accounts
            for username, account in self.accounts.items():
                state.accounts[username].password_hash = account['password_hash']
            
            # Add all messages
            for username, msgs in self.messages.items():
                if msgs:
                    umsgs = chat_pb2.UserMessages()
                    for msg_id, msg_dict in msgs.items():
                        chat_msg = chat_pb2.ChatMessage(
                            id=msg_dict['id'],
                            sender=msg_dict['sender'],
                            recipient=msg_dict['recipient'],
                            content=msg_dict['content'],
                            timestamp=msg_dict['timestamp'],
                            read=msg_dict['read']
                        )
                        umsgs.messages[str(msg_id)].CopyFrom(chat_msg)
                    state.messages[username].CopyFrom(umsgs)
            
            print(f"[SyncState] Responding with version={self.version} to server {request.server_id}")
            return chat_pb2.SyncResponse(state=state)
    
    def _propagate_update(self, update_type, affected_data=None):
        """
        Send an UpdateRequest with a minimal delta to every known server.
        Instead of holding the lock during network calls (which may block),
        we copy the current stubs and then release the lock.
        """ 
        with self.lock:
            # Update our logical clock
            self.version = max(self.version, int(time.time() * 1000)) + 1

            # Build minimal delta state
            delta = chat_pb2.ServerState(
                version=self.version,
                next_msg_id=self.next_msg_id
            )
            if affected_data:
                if update_type in [chat_pb2.UpdateRequest.ACCOUNT_CREATED,
                                   chat_pb2.UpdateRequest.ACCOUNT_DELETED]:
                    username = affected_data
                    # Only include the account if it still exists locally
                    if username in self.accounts:
                        delta.accounts[username].password_hash = self.accounts[username]['password_hash']
                elif update_type == chat_pb2.UpdateRequest.MESSAGE_SENT:
                    msg = affected_data
                    for user in [msg['sender'], msg['recipient']]:
                        if user not in delta.messages:
                            delta.messages[user] = chat_pb2.UserMessages()
                        chat_msg = chat_pb2.ChatMessage(
                            id=msg['id'],
                            sender=msg['sender'],
                            recipient=msg['recipient'],
                            content=msg['content'],
                            timestamp=msg['timestamp'],
                            read=msg['read']
                        )
                        delta.messages[user].messages[str(msg['id'])].CopyFrom(chat_msg)
            request = chat_pb2.UpdateRequest(
                type=update_type,
                delta_state=delta,
                version=self.version
            )
            # Copy the stubs so we can release the lock
            stubs = list(self.replication_stubs.items())

        # Now, outside the lock, send the update to each known server.
        for (host, port), stub in stubs:
            try:
                response = stub.PropagateUpdate(request, timeout=5)
                if not response.success:
                    print(f"[Propagate] {host}:{port} rejected update: {response.message}")
            except Exception as e:
                print(f"[Propagate] Failed to update {host}:{port}: {e}")


    # ------------------------------------------------------------------------
    # Client-facing RPC methods
    # ------------------------------------------------------------------------
    def CreateAccount(self, request, context):
        print(f"[CreateAccount] Attempt for username: {request.username}")
        with self.lock:
            if request.username in self.accounts:
                return chat_pb2.StatusResponse(success=False, message='Username already exists')
            
            salt = bcrypt.gensalt()
            password_hash = bcrypt.hashpw(request.password.encode('utf-8'), salt)
            
            self.accounts[request.username] = {
                'password_hash': base64.b64encode(password_hash).decode('utf-8')
            }
            self.messages[request.username] = {}
            
            # Persist
            self.persistence.save_accounts(self.accounts)
            self.persistence.save_messages(self.messages)
            
            # Replicate
            self._propagate_update(chat_pb2.UpdateRequest.ACCOUNT_CREATED, request.username)
            return chat_pb2.StatusResponse(success=True, message='Account created successfully')

    def DeleteAccount(self, request, context):
        print(f"[DeleteAccount] Request for username: {request.username}")
        if request.username not in self.accounts:
            return chat_pb2.StatusResponse(success=False, message='User not found')
        
        stored_hash = base64.b64decode(self.accounts[request.username]['password_hash'].encode('utf-8'))
        if not bcrypt.checkpw(request.password.encode('utf-8'), stored_hash):
            return chat_pb2.StatusResponse(success=False, message='Invalid password')
        
        with self.lock:
            self.accounts.pop(request.username, None)
            self.messages.pop(request.username, None)
            
            if request.username in self.active_sessions:
                self.active_sessions.pop(request.username, None)
            
            # Persist
            self.persistence.save_accounts(self.accounts)
            self.persistence.save_messages(self.messages)
            
            # Replicate
            self._propagate_update(chat_pb2.UpdateRequest.ACCOUNT_DELETED, request.username)
            
            return chat_pb2.StatusResponse(success=True, message='Account deleted successfully')
    
    def Login(self, request, context):
        if request.username not in self.accounts:
            return chat_pb2.LoginResponse(success=False, message='Username not found')
        
        stored_hash = base64.b64decode(self.accounts[request.username]['password_hash'].encode('utf-8'))
        if not bcrypt.checkpw(request.password.encode('utf-8'), stored_hash):
            return chat_pb2.LoginResponse(success=False, message='Invalid password')
        
        with self.lock:
            all_messages = []
            for user_msgs in self.messages.values():
                for msg in user_msgs.values():
                    if msg['sender'] == request.username or msg['recipient'] == request.username:
                        all_messages.append(msg)
            
            all_messages.sort(key=lambda x: x['id'])
            unread_count = sum(1 for m in all_messages if m['recipient'] == request.username and not m['read'])
            
            # Convert to ChatMessage proto
            message_objects = []
            for m in all_messages:
                cm = chat_pb2.ChatMessage(
                    id=m['id'],
                    sender=m['sender'],
                    recipient=m['recipient'],
                    content=m['content'],
                    timestamp=m['timestamp'],
                    read=m['read']
                )
                message_objects.append(cm)
            
            return chat_pb2.LoginResponse(
                success=True,
                message=f'Login successful. You have {unread_count} unread messages.',
                unread_count=unread_count,
                messages=message_objects
            )
    
    def ListAccounts(self, request, context):
        pattern = request.pattern.lower() if request.pattern else ''
        accounts_list = list(self.accounts.keys())
        if pattern:
            accounts_list = [a for a in accounts_list if pattern in a.lower()]
        return chat_pb2.ListAccountsResponse(accounts=accounts_list)

    def SendMessage(self, request, context):
        if request.recipient not in self.accounts:
            return chat_pb2.SendMessageResponse(success=False, message='Recipient not found')
        
        with self.lock:
            # Check for duplicate message within a small time window (100ms)
            current_time = datetime.now()
            
            # Check recent messages in sender's history
            if request.sender in self.messages:
                for msg in self.messages[request.sender].values():
                    if (msg['sender'] == request.sender and
                        msg['recipient'] == request.recipient and
                        msg['content'] == request.content):
                        # Check if message was sent within last 100ms
                        msg_time = datetime.fromisoformat(msg['timestamp'])
                        if abs((current_time - msg_time).total_seconds()) < 0.1:
                            # This is likely a duplicate, return existing message ID
                            return chat_pb2.SendMessageResponse(
                                success=True,
                                message='Message sent',
                                message_id=msg['id']
                            )
            
            # No duplicate found, create new message
            msg_id = self.next_msg_id
            self.next_msg_id += 1
            
            timestamp = current_time.isoformat()
            message_dict = {
                'id': msg_id,
                'sender': request.sender,
                'recipient': request.recipient,
                'content': request.content,
                'timestamp': timestamp,
                'read': False
            }
            
            if request.sender not in self.messages:
                self.messages[request.sender] = {}
            if request.recipient not in self.messages:
                self.messages[request.recipient] = {}
            
            self.messages[request.sender][msg_id] = message_dict
            self.messages[request.recipient][msg_id] = message_dict
            
            # Persist
            self.persistence.save_messages(self.messages)
            self.persistence.save_msg_id(self.next_msg_id)
            
            # Replicate
            self._propagate_update(chat_pb2.UpdateRequest.MESSAGE_SENT, message_dict)
            
            # Notify streaming sessions
            chat_msg = chat_pb2.ChatMessage(
                id=msg_id,
                sender=request.sender,
                recipient=request.recipient,
                content=request.content,
                timestamp=timestamp,
                read=False
            )
            for username in [request.sender, request.recipient]:
                if username in self.active_sessions:
                    for q in self.active_sessions[username]:
                        q.put(chat_msg)
            
            return chat_pb2.SendMessageResponse(success=True,
                                                message='Message sent',
                                                message_id=msg_id)

    def ReadMessages(self, request, context):
        if request.username not in self.accounts:
            return chat_pb2.ReadMessagesResponse(messages=[])
        
        with self.lock:
            relevant = []
            seen_ids = set()  # Track message IDs we've seen
            
            # Check messages where user is sender
            user_msgs = self.messages.get(request.username, {})
            for m in user_msgs.values():
                if request.sender:
                    # Only messages between user and specified sender
                    if m['recipient'] == request.sender:
                        if m['id'] not in seen_ids:
                            seen_ids.add(m['id'])
                            relevant.append(m)
            
            # Check messages where user is recipient
            if request.sender:
                sender_msgs = self.messages.get(request.sender, {})
                for m in sender_msgs.values():
                    if m['recipient'] == request.username:
                        if m['id'] not in seen_ids:
                            seen_ids.add(m['id'])
                            if not m['read']:
                                m['read'] = True
                            relevant.append(m)
            
            relevant.sort(key=lambda x: x['timestamp'])
            
            proto_msgs = []
            for r in relevant:
                cm = chat_pb2.ChatMessage(
                    id=r['id'],
                    sender=r['sender'],
                    recipient=r['recipient'],
                    content=r['content'],
                    timestamp=r['timestamp'],
                    read=r['read']
                )
                proto_msgs.append(cm)
            
            return chat_pb2.ReadMessagesResponse(messages=proto_msgs)

    def DeleteMessages(self, request, context):
        if request.username not in self.accounts:
            return chat_pb2.StatusResponse(success=False, message='User not found')
        
        with self.lock:
            deleted_any = False
            for mid in request.message_ids:
                if mid in self.messages.get(request.username, {}):
                    msg = self.messages[request.username][mid]
                    if msg['sender'] == request.username:
                        # Remove from sender
                        self.messages[request.username].pop(mid, None)
                        # Remove from recipient
                        recipient = msg['recipient']
                        if recipient in self.messages:
                            self.messages[recipient].pop(mid, None)
                        deleted_any = True
                        
                        # Notify about deletion
                        deletion_note = chat_pb2.ChatMessage(
                            id=mid,
                            sender=msg['sender'],
                            recipient=recipient,
                            content="<message deleted>",
                            timestamp=datetime.now().isoformat(),
                            read=True
                        )
                        for uname in [msg['sender'], recipient]:
                            if uname in self.active_sessions:
                                for q in self.active_sessions[uname]:
                                    q.put(deletion_note)
            
            self.persistence.save_messages(self.messages)
            return chat_pb2.StatusResponse(success=deleted_any,
                                           message='Messages deleted' if deleted_any else 'No messages found to delete')

    def GetUnreadCount(self, request, context):
        if request.username not in self.accounts:
            return chat_pb2.UnreadCountResponse(unread_count=0)
        
        with self.lock:
            user_msgs = self.messages.get(request.username, {})
            count = sum(1 for m in user_msgs.values()
                        if m['recipient'] == request.username and not m['read'])
            return chat_pb2.UnreadCountResponse(unread_count=count)

    def StreamMessages(self, request, context):
        if request.username not in self.accounts:
            return
        
        local_q = queue.Queue()
        with self.lock:
            if request.username not in self.active_sessions:
                self.active_sessions[request.username] = []
            self.active_sessions[request.username].append(local_q)
            
            # Collect all existing messages for this user
            existing = []
            for user_msgs in self.messages.values():
                for m in user_msgs.values():
                    if m['sender'] == request.username or m['recipient'] == request.username:
                        existing.append(m)
            existing.sort(key=lambda x: x['id'])
        
        # Yield existing first
        for m in existing:
            yield chat_pb2.ChatMessage(
                id=m['id'],
                sender=m['sender'],
                recipient=m['recipient'],
                content=m['content'],
                timestamp=m['timestamp'],
                read=m['read']
            )
        
        try:
            # Then yield new messages from the queue
            while context.is_active():
                try:
                    msg = local_q.get(timeout=0.2)
                    yield msg
                except queue.Empty:
                    pass
        finally:
            # Cleanup
            with self.lock:
                if request.username in self.active_sessions:
                    if local_q in self.active_sessions[request.username]:
                        self.active_sessions[request.username].remove(local_q)
                    if not self.active_sessions[request.username]:
                        self.active_sessions.pop(request.username)

def serve(host='0.0.0.0', port=65432, server_id=0):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=50))
    servicer = ChatServicer(host=host, port=port, server_id=server_id)
    
    chat_pb2_grpc.add_ChatClientServiceServicer_to_server(servicer, server)
    chat_pb2_grpc.add_ChatReplicationServiceServicer_to_server(servicer, server)
    
    server.add_insecure_port(f"{host}:{port}")
    server.start()
    print(f"[Startup] Server {server_id} started on {host}:{port}")
    
    def handle_shutdown(signum, frame):
        print(f"\n[Shutdown] Server {server_id} shutting down gracefully...")
        # Close all channels
        for chan in servicer.channels.values():
            try:
                chan.close()
            except:
                pass
        # Persist final state
        servicer.persistence.save_accounts(servicer.accounts)
        servicer.persistence.save_messages(servicer.messages)
        servicer.persistence.save_msg_id(servicer.next_msg_id)
        server.stop(0)
        sys.exit(0)
    
    signal.signal(signal.SIGINT, handle_shutdown)
    server.wait_for_termination()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(...)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=65432)
    parser.add_argument("--server-id", type=int, default=0)
    args = parser.parse_args()

    serve(host=args.host, port=args.port, server_id=args.server_id)

