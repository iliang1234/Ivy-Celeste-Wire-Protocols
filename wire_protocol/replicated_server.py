import json
import os
import socket
import threading
import pickle
from typing import Dict, List, Optional
from protocol import WireProtocol, MessageType
from raft import RaftNode, LogEntry, NodeState
import bcrypt
import struct
import time

class ReplicatedChatServer:
    def __init__(self, config_path: str, node_id: int):
        self.node_id = node_id
        self.running = True
        
        # Load configuration
        with open(config_path) as f:
            self.config = json.load(f)
        self.node_config = next(r for r in self.config['replicas'] if r['id'] == node_id)
        
        # Initialize Raft node
        self.raft = RaftNode(node_id, config_path)
        
        # Get script directory for relative paths
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Initialize server state
        self.messages: Dict[str, Dict[int, dict]] = {}
        self.accounts: Dict[str, dict] = {}
        self.active_sessions: Dict[str, socket.socket] = {}
        self.lock = threading.Lock()
        self.next_message_id = 0
        
        # Ensure data directory exists
        self.data_dir = os.path.join(self.script_dir, "data", f"replica_{node_id}")
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Load persistent state
        self.load_state()
        
        # Initialize server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.node_config['host'], self.node_config['client_port']))
        
        # Start server thread
        self.server_thread = threading.Thread(target=self.start, daemon=True)
        self.server_thread.start()
        
    def load_state(self):
        """Load server state from Raft log"""
        committed_entries = self.raft.get_committed_entries()
        for entry in committed_entries:
            self.apply_command(entry)
            
    def save_state(self):
        """Save current state to persistent storage"""
        state = {
            'messages': self.messages,
            'accounts': self.accounts,
            'next_message_id': self.next_message_id
        }
        state_bytes = pickle.dumps(state)
        self.raft.append_entry(state_bytes)
        
    def apply_command(self, command_bytes: bytes):
        """Apply a command from the Raft log"""
        command = pickle.loads(command_bytes)
        cmd_type = command['type']
        
        if cmd_type == 'create_account':
            username = command['username']
            password_hash = command['password_hash']
            self.accounts[username] = {'password_hash': password_hash}
            
        elif cmd_type == 'delete_account':
            username = command['username']
            if username in self.accounts:
                del self.accounts[username]
                if username in self.messages:
                    del self.messages[username]
                    
        elif cmd_type == 'send_message':
            sender = command['sender']
            recipient = command['recipient']
            content = command['content']
            msg_id = command['msg_id']
            
            if recipient not in self.messages:
                self.messages[recipient] = {}
            self.messages[recipient][msg_id] = {
                'sender': sender,
                'content': content,
                'timestamp': command['timestamp']
            }
            
        elif cmd_type == 'delete_message':
            username = command['username']
            msg_id = command['msg_id']
            if username in self.messages and msg_id in self.messages[username]:
                del self.messages[username][msg_id]
                
        elif cmd_type == 'state_update':
            self.messages = command['messages']
            self.accounts = command['accounts']
            self.next_message_id = command['next_message_id']
            
    def start(self):
        """Start the server"""
        self.server_socket.listen(5)
        print(f"Server started on {self.node_config['host']}:{self.node_config['client_port']}")
        
        while True:
            client_socket, address = self.server_socket.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()
            
    def handle_client(self, client_socket: socket.socket):
        """Handle client connection"""
        username = None
        try:
            while True:
                try:
                    # Wait for data with a shorter timeout
                    client_socket.settimeout(0.1)
                    try:
                        client_socket.recv(1, socket.MSG_PEEK)
                    except socket.timeout:
                        continue
                    except Exception as e:
                        print(f"Error peeking data: {e}")
                        break
                    
                    # Once we have data, use a longer timeout for reading
                    client_socket.settimeout(10)
                    header_data = self.recv_exact(client_socket, 9)
                    if not header_data:
                        print("Failed to receive header")
                        break
                        
                    msg_type, payload_length, num_items = WireProtocol.unpack_header(header_data)
                    
                    # Read payload first before checking leadership
                    payload = b''
                    if payload_length > 0:
                        payload = self.recv_exact(client_socket, payload_length)
                        if not payload:
                            print("Failed to receive payload")
                            break
                    
                    print(f"Received message type: {msg_type}, payload length: {payload_length}")
                    
                    # Handle health check regardless of leader status
                    if msg_type == MessageType.HEALTH_CHECK:
                        try:
                            # Send empty success response for health check
                            header = struct.pack('!BII', MessageType.SUCCESS, 0, 0)
                            client_socket.sendall(header)
                            continue
                        except Exception as e:
                            print(f"Error sending health check response: {e}")
                            break
                    
                    # Forward request to leader if we're not the leader
                    if self.raft.state != NodeState.LEADER:
                        if self.raft.leader_id is not None:
                            leader_config = next(r for r in self.config['replicas'] if r['id'] == self.raft.leader_id)
                            response = WireProtocol.error_response(
                                f"Not leader. Please connect to {leader_config['host']}:{leader_config['client_port']}"
                            )
                            try:
                                client_socket.sendall(response)
                            except:
                                break
                            break
                        else:
                            response = WireProtocol.error_response("No leader available. Please try again later.")
                            try:
                                client_socket.sendall(response)
                            except:
                                break
                            break
                    
                    response = None
                    
                    if msg_type == MessageType.LOGIN:
                        login_username, offset = WireProtocol.unpack_string(payload)
                        password, _ = WireProtocol.unpack_string(payload, offset)
                        response = self.login(login_username, password, client_socket)
                        if response and b"Login successful" in response:
                            username = login_username
                            
                    elif msg_type == MessageType.CREATE_ACCOUNT:
                        new_username, offset = WireProtocol.unpack_string(payload)
                        password, _ = WireProtocol.unpack_string(payload, offset)
                        response = self.create_account(new_username, password)
                        
                    elif msg_type == MessageType.LIST_ACCOUNTS:
                        pattern, offset = WireProtocol.unpack_string(payload)
                        if len(payload) >= offset + 8:
                            page = struct.unpack('!I', payload[offset:offset+4])[0]
                            per_page = struct.unpack('!I', payload[offset+4:offset+8])[0]
                        else:
                            page = 1
                            per_page = 10
                        response = self.list_accounts(pattern, page, per_page)
                        
                    elif msg_type == MessageType.SEND_MESSAGE:
                        if not username:
                            response = WireProtocol.error_response("Not logged in")
                        else:
                            sender, offset = WireProtocol.unpack_string(payload)
                            recipient, offset = WireProtocol.unpack_string(payload, offset)
                            content, _ = WireProtocol.unpack_string(payload, offset)
                            if sender != username:
                                response = WireProtocol.error_response("Invalid sender")
                            else:
                                response = self.send_message(sender, recipient, content)
                                
                    elif msg_type == MessageType.DELETE_ACCOUNT:
                        del_username, offset = WireProtocol.unpack_string(payload)
                        password, _ = WireProtocol.unpack_string(payload, offset)
                        response = self.delete_account(del_username, password)
                        
                    elif msg_type == MessageType.DELETE_MESSAGE:
                        del_username, offset = WireProtocol.unpack_string(payload)
                        if len(payload) < offset + 4:
                            response = WireProtocol.error_response("Missing message id")
                        else:
                            msg_id = struct.unpack('!I', payload[offset:offset+4])[0]
                            response = self.delete_message(del_username, msg_id)
                            
                    else:
                        response = WireProtocol.error_response("Unknown message type")
                        
                    if response:
                        try:
                            client_socket.sendall(response)
                        except Exception as e:
                            print(f"Error sending response to {username}: {e}")
                            break
                            
                except socket.timeout:
                    continue
                except ConnectionError as e:
                    print(f"Connection error with {username}: {e}")
                    break
                except Exception as e:
                    print(f"Error handling client message from {username}: {e}")
                    try:
                        error_response = WireProtocol.error_response(str(e))
                        client_socket.sendall(error_response)
                    except:
                        break
                        
        finally:
            if username and username in self.active_sessions:
                del self.active_sessions[username]
            try:
                client_socket.close()
            except:
                pass
                
    def recv_exact(self, sock, n, chunk_size=4096):
        """Receive exactly n bytes"""
        data = b''
        try:
            while len(data) < n:
                remaining = n - len(data)
                chunk = sock.recv(min(remaining, chunk_size))
                if not chunk:
                    print("Connection closed by peer")
                    return None
                data += chunk
            return data
        except socket.timeout as e:
            print(f"Socket timeout: {e}")
            return None
        except Exception as e:
            print(f"Error receiving data: {e}")
            return None
            
    def create_account(self, username: str, password: str) -> bytes:
        """Create a new account"""
        if username in self.accounts:
            return WireProtocol.error_response("Username already exists")
            
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        command = {
            'type': 'create_account',
            'username': username,
            'password_hash': password_hash
        }
        
        # Try to replicate with longer timeout
        if not self.raft.append_entry(pickle.dumps(command), timeout=10.0):
            return WireProtocol.error_response("Failed to create account. Please try again.")
            
        # Verify account was created
        if username not in self.accounts:
            return WireProtocol.error_response("Failed to create account. Please try again.")
            
        return WireProtocol.success_response("Account created successfully")
        
    def login(self, username: str, password: str, client_socket: socket.socket) -> bytes:
        """Login to an existing account"""
        if username not in self.accounts:
            return WireProtocol.error_response("Account does not exist")
            
        stored_hash = self.accounts[username]['password_hash']
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            return WireProtocol.error_response("Invalid password")
            
        if username in self.active_sessions:
            return WireProtocol.error_response("Account already logged in")
            
        self.active_sessions[username] = client_socket
        return WireProtocol.success_response("Login successful")
        
    def list_accounts(self, pattern: str, page: int, per_page: int) -> bytes:
        """List accounts matching the pattern"""
        matching_accounts = []
        for username in self.accounts:
            if pattern.lower() in username.lower():
                matching_accounts.append(username)
                
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        accounts_page = matching_accounts[start_idx:end_idx]
        
        response_data = struct.pack('!I', len(matching_accounts))  # Total count
        response_data += struct.pack('!I', len(accounts_page))    # Page count
        
        for account in accounts_page:
            response_data += WireProtocol.pack_string(account)
            
        return WireProtocol.success_response("Accounts retrieved", response_data)
        
    def send_message(self, sender: str, recipient: str, content: str) -> bytes:
        """Send a message to another user"""
        if recipient not in self.accounts:
            return WireProtocol.error_response("Recipient does not exist")
            
        msg_id = self.next_message_id
        self.next_message_id += 1
        
        command = {
            'type': 'send_message',
            'sender': sender,
            'recipient': recipient,
            'content': content,
            'msg_id': msg_id,
            'timestamp': time.time()
        }
        
        if not self.raft.append_entry(pickle.dumps(command)):
            return WireProtocol.error_response("Failed to send message. Not leader.")
            
        return WireProtocol.success_response("Message sent successfully")
        
    def delete_account(self, username: str, password: str) -> bytes:
        """Delete an account"""
        if username not in self.accounts:
            return WireProtocol.error_response("Account does not exist")
            
        stored_hash = self.accounts[username]['password_hash']
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            return WireProtocol.error_response("Invalid password")
            
        command = {
            'type': 'delete_account',
            'username': username
        }
        
        if not self.raft.append_entry(pickle.dumps(command)):
            return WireProtocol.error_response("Failed to delete account. Not leader.")
            
        if username in self.active_sessions:
            try:
                self.active_sessions[username].close()
            except:
                pass
            del self.active_sessions[username]
            
        return WireProtocol.success_response("Account deleted successfully")
        
    def delete_message(self, username: str, msg_id: int) -> bytes:
        """Delete a message"""
        if username not in self.messages or msg_id not in self.messages[username]:
            return WireProtocol.error_response("Message not found")
            
        command = {
            'type': 'delete_message',
            'username': username,
            'msg_id': msg_id
        }
        
        if not self.raft.append_entry(pickle.dumps(command)):
            return WireProtocol.error_response("Failed to delete message. Not leader.")
            
        return WireProtocol.success_response("Message deleted successfully")
