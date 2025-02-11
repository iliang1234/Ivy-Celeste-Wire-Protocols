import socket
import threading
import bcrypt
import struct
from datetime import datetime
from typing import Dict, List, Optional
from protocol import WireProtocol, MessageType
import time

class ChatServer:
    def __init__(self, host: str = 'localhost', port: int = 5002):
        self.messages: Dict[str, Dict[int, dict]] = {}  # username -> {msg_id: message_data}
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.accounts: Dict[str, dict] = {}  # username -> {password_hash}
        self.active_sessions: Dict[str, socket.socket] = {}  # username -> socket
        self.lock = threading.Lock()
        self.next_message_id = 0
        self.processed_messages = set()  # Track processed message IDs

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server started on {self.host}:{self.port}")
        
        while True:
            client_socket, address = self.server_socket.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

    def recv_exact(self, sock, n, timeout=5):
        """Receive exactly n bytes with timeout"""
        data = b''
        start_time = time.time()
        sock.settimeout(timeout)
        
        try:
            while len(data) < n:
                # Check if we've exceeded total timeout
                if time.time() - start_time > timeout:
                    raise socket.timeout("Total operation timeout")
                    
                try:
                    chunk = sock.recv(n - len(data))
                    if not chunk:
                        raise ConnectionError("Socket closed before receiving expected data")
                    data += chunk
                except socket.timeout:
                    # For short timeouts, retry if we haven't exceeded total timeout
                    if time.time() - start_time <= timeout:
                        continue
                    raise
            return data
        finally:
            sock.settimeout(None)

    def handle_client(self, client_socket: socket.socket):
        """Handle client connection"""
        username = None
        try:
            while True:
                try:
                    # First peek to see if there's data
                    client_socket.settimeout(0.05)
                    try:
                        client_socket.recv(1, socket.MSG_PEEK)
                    except socket.timeout:
                        # No data available, continue waiting
                        continue
                    except Exception as e:
                        raise e
                        
                    # If we get here, there's data to read
                    header_data = self.recv_exact(client_socket, 9, timeout=1)
                    msg_type, payload_length, num_items = WireProtocol.unpack_header(header_data)
                    
                    # Receive payload if any
                    payload = b''
                    if payload_length > 0:
                        payload = self.recv_exact(client_socket, payload_length, timeout=1)
                        
                    print(f"Received message type: {msg_type}, payload length: {payload_length}")
                    
                    # Process the request
                    response = None
                    
                    if msg_type == MessageType.LOGIN:
                        login_username, offset = WireProtocol.unpack_string(payload)
                        password, _ = WireProtocol.unpack_string(payload, offset)
                        response = self.login(login_username, password, client_socket)
                        if response:
                            username = login_username
                    elif msg_type == MessageType.CREATE_ACCOUNT:
                        new_username, offset = WireProtocol.unpack_string(payload)
                        password, _ = WireProtocol.unpack_string(payload, offset)
                        response = self.create_account(new_username, password)
                    elif msg_type == MessageType.LIST_ACCOUNTS:
                        pattern, _ = WireProtocol.unpack_string(payload)
                        response = self.list_accounts(pattern)
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
                                
                    # Send response if we have one
                    if response:
                        try:
                            client_socket.sendall(response)
                        except Exception as e:
                            print(f"Error sending response to {username}: {e}")
                            break
                            
                except socket.timeout:
                    # Normal timeout, just continue
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

    def process_request(self, msg_type: MessageType, payload: bytes, client_socket: socket.socket) -> bytes:
        try:
            if msg_type == MessageType.CREATE_ACCOUNT:
                username, offset = WireProtocol.unpack_string(payload)
                password, _ = WireProtocol.unpack_string(payload, offset)
                return self.create_account(username, password)
                
            elif msg_type == MessageType.LOGIN:
                username, offset = WireProtocol.unpack_string(payload)
                password, _ = WireProtocol.unpack_string(payload, offset)
                return self.login(username, password, client_socket)
                
            elif msg_type == MessageType.LIST_ACCOUNTS:
                pattern, _ = WireProtocol.unpack_string(payload)
                return self.list_accounts(pattern if pattern else None)
                
            elif msg_type == MessageType.SEND_MESSAGE:
                sender, offset = WireProtocol.unpack_string(payload)
                recipient, offset = WireProtocol.unpack_string(payload, offset)
                content, _ = WireProtocol.unpack_string(payload, offset)
                return self.send_message(sender, recipient, content)
            
            else:
                return WireProtocol.error_response("Invalid message type")
                
        except Exception as e:
            return WireProtocol.error_response(f"Error processing request: {str(e)}")

    def create_account(self, username: str, password: str) -> bytes:
        with self.lock:
            if username in self.accounts:
                return WireProtocol.error_response("Username already exists")
            
            salt = bcrypt.gensalt()
            password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
            
            self.accounts[username] = {'password_hash': password_hash}
            self.messages[username] = {}
            return WireProtocol.success_response("Account created successfully")

    def login(self, username: str, password: str, client_socket: socket.socket) -> bytes:
        if username not in self.accounts:
            return WireProtocol.error_response("Invalid username or password")
            
        stored_hash = self.accounts[username]['password_hash']
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            return WireProtocol.error_response("Invalid username or password")
            
        with self.lock:
            # Remove any existing session for this user
            if username in self.active_sessions:
                try:
                    old_socket = self.active_sessions[username]
                    if old_socket and old_socket != client_socket:
                        old_socket.close()
                except Exception:
                    pass
                    
            self.active_sessions[username] = client_socket
            
            messages_data = b''
            num_messages = 0
            
            # Initialize messages dict if it doesn't exist
            if username not in self.messages:
                self.messages[username] = {}
            
            # Get all messages where user is sender or recipient
            relevant_messages = []
            for msg_dict in self.messages.values():
                for msg_id, msg in msg_dict.items():
                    if msg['sender'] == username or msg['recipient'] == username:
                        if msg not in relevant_messages:  # Avoid duplicates
                            relevant_messages.append(msg)
            
            # Sort messages by timestamp and pack them
            relevant_messages.sort(key=lambda x: x['timestamp'])
            for msg in relevant_messages:
                try:
                    messages_data += WireProtocol.pack_message(
                        msg['id'],
                        msg['sender'],
                        msg['recipient'],
                        msg['content'],
                        msg['timestamp'],
                        msg['read']
                    )
                    num_messages += 1
                except Exception as e:
                    print(f"Error packing message {msg['id']}: {e}")
                    continue
            
            message = f"Login successful. You have {num_messages} messages."
            message_bytes = WireProtocol.pack_string(message)
            payload = message_bytes + struct.pack('!I', num_messages) + messages_data
            header = WireProtocol.pack_header(MessageType.SUCCESS, len(payload))
            return header + payload

    def list_accounts(self, pattern: Optional[str] = None) -> bytes:
        accounts = list(self.accounts.keys())
        if pattern:
            accounts = [acc for acc in accounts if pattern.lower() in acc.lower()]
        
        accounts_data = b''
        for account in accounts:
            accounts_data += WireProtocol.pack_string(account)
        
        header = WireProtocol.pack_header(MessageType.SUCCESS, len(accounts_data), len(accounts))
        return header + accounts_data

    def send_message(self, sender: str, recipient: str, content: str) -> bytes:
        """Handle a send message request"""
        if recipient not in self.accounts:
            return WireProtocol.error_response("Recipient does not exist")
            
        with self.lock:
            msg_id = self.next_message_id
            self.next_message_id += 1
            
            timestamp = time.time()
            
            # Create message object with consistent structure
            message = {
                'id': msg_id,
                'sender': sender,
                'recipient': recipient,
                'content': content,
                'timestamp': timestamp,
                'read': False
            }
            
            # Store message for both sender and recipient
            if recipient not in self.messages:
                self.messages[recipient] = {}
            if sender not in self.messages:
                self.messages[sender] = {}
                
            # Store the same message object for both users
            self.messages[recipient][msg_id] = message
            self.messages[sender][msg_id] = message
            
            # If recipient is active, send notification with the same message object
            if recipient in self.active_sessions:
                try:
                    notification = WireProtocol.pack_message(
                        message['id'],
                        message['sender'],
                        message['recipient'],
                        message['content'],
                        message['timestamp'],
                        message['read']
                    )
                    header = WireProtocol.pack_header(MessageType.NEW_MESSAGE_NOTIFICATION, len(notification))
                    notification_data = header + notification
                    
                    recipient_socket = self.active_sessions[recipient]
                    if recipient_socket and recipient_socket.fileno() != -1:
                        recipient_socket.sendall(notification_data)
                except Exception as e:
                    print(f"Failed to send notification to {recipient}: {str(e)}")
                    if recipient in self.active_sessions:
                        del self.active_sessions[recipient]
            
            # Send success response with the message object
            response_msg = "Message sent successfully"
            response_payload = WireProtocol.pack_message(
                message['id'],
                message['sender'],
                message['recipient'],
                message['content'],
                message['timestamp'],
                message['read']
            )
            header = WireProtocol.pack_header(MessageType.SUCCESS, len(response_payload))
            return header + response_payload

if __name__ == '__main__':
    server = ChatServer()
    server.start()
