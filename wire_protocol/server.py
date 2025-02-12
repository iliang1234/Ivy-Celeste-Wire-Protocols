import socket
import threading
import bcrypt
import struct
from datetime import datetime
from typing import Dict, List, Optional
from protocol import WireProtocol, MessageType
import time

class ChatServer:
    def __init__(self, host: str = 'localhost', port: int = 5001):
        self.messages: Dict[str, Dict[int, dict]] = {}  # username -> {msg_id: message_data}
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.accounts: Dict[str, dict] = {}  # username -> {password_hash}
        self.active_sessions: Dict[str, socket.socket] = {}  # username -> socket
        self.lock = threading.Lock()
        self.next_message_id = 0
        self.running = True

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server started on {self.host}:{self.port}")
        
        while self.running:
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
                if time.time() - start_time > timeout:
                    raise socket.timeout("Total operation timeout")
                try:
                    chunk = sock.recv(n - len(data))
                    if not chunk:
                        raise ConnectionError("Socket closed before receiving expected data")
                    data += chunk
                except socket.timeout:
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
                    # Use a short timeout to check for available data.
                    client_socket.settimeout(0.05)
                    try:
                        client_socket.recv(1, socket.MSG_PEEK)
                    except socket.timeout:
                        continue
                    except Exception as e:
                        raise e
                        
                    header_data = self.recv_exact(client_socket, 9, timeout=1)
                    msg_type, payload_length, num_items = WireProtocol.unpack_header(header_data)
                    
                    payload = b''
                    if payload_length > 0:
                        payload = self.recv_exact(client_socket, payload_length, timeout=1)
                        
                    print(f"Received message type: {msg_type}, payload length: {payload_length}")
                    
                    response = None
                    
                    if msg_type == MessageType.LOGIN:
                        login_username, offset = WireProtocol.unpack_string(payload)
                        password, _ = WireProtocol.unpack_string(payload, offset)
                        response = self.login(login_username, password, client_socket)
                        # Check for a successful login message before setting the active username.
                        if response and b"Login successful" in response:
                            username = login_username
                    elif msg_type == MessageType.CREATE_ACCOUNT:
                        new_username, offset = WireProtocol.unpack_string(payload)
                        password, _ = WireProtocol.unpack_string(payload, offset)
                        response = self.create_account(new_username, password)
                    elif msg_type == MessageType.LIST_ACCOUNTS:
                        # The payload is expected to contain a search pattern (string)
                        # followed optionally by two 4-byte unsigned ints: page and per_page.
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
                        # Expect username and password in payload.
                        del_username, offset = WireProtocol.unpack_string(payload)
                        password, _ = WireProtocol.unpack_string(payload, offset)
                        response = self.delete_account(del_username, password)
                    elif msg_type == MessageType.DELETE_MESSAGE:
                        # Expect username (string) and then a 4-byte message id.
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
                pattern, offset = WireProtocol.unpack_string(payload)
                if len(payload) >= offset + 8:
                    page = struct.unpack('!I', payload[offset:offset+4])[0]
                    per_page = struct.unpack('!I', payload[offset+4:offset+8])[0]
                else:
                    page = 1
                    per_page = 10
                return self.list_accounts(pattern, page, per_page)
            elif msg_type == MessageType.SEND_MESSAGE:
                sender, offset = WireProtocol.unpack_string(payload)
                recipient, offset = WireProtocol.unpack_string(payload, offset)
                content, _ = WireProtocol.unpack_string(payload, offset)
                return self.send_message(sender, recipient, content)
            elif msg_type == MessageType.DELETE_ACCOUNT:
                username, offset = WireProtocol.unpack_string(payload)
                password, _ = WireProtocol.unpack_string(payload, offset)
                return self.delete_account(username, password)
            elif msg_type == MessageType.DELETE_MESSAGE:
                username, offset = WireProtocol.unpack_string(payload)
                if len(payload) < offset+4:
                    return WireProtocol.error_response("Missing message id")
                msg_id = struct.unpack('!I', payload[offset:offset+4])[0]
                return self.delete_message(username, msg_id)
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
            if username not in self.messages:
                self.messages[username] = {}
            relevant_messages = []
            for msg_dict in self.messages.values():
                for msg_id, msg in msg_dict.items():
                    if msg['sender'] == username or msg['recipient'] == username:
                        if msg not in relevant_messages:
                            relevant_messages.append(msg)
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

    def list_accounts(self, pattern: Optional[str] = None, page: int = 1, per_page: int = 10) -> bytes:
        accounts = list(self.accounts.keys())
        if pattern:
            accounts = [acc for acc in accounts if pattern.lower() in acc.lower()]
        start = (page - 1) * per_page
        paged_accounts = accounts[start:start + per_page]
        accounts_data = b''
        for account in paged_accounts:
            accounts_data += WireProtocol.pack_string(account)
        header = WireProtocol.pack_header(MessageType.SUCCESS, len(accounts_data), len(paged_accounts))
        return header + accounts_data

    def send_message(self, sender: str, recipient: str, content: str) -> bytes:
        if recipient not in self.accounts:
            return WireProtocol.error_response("Recipient does not exist")
        with self.lock:
            msg_id = self.next_message_id
            self.next_message_id += 1
            timestamp = time.time()
            message = {
                'id': msg_id,
                'sender': sender,
                'recipient': recipient,
                'content': content,
                'timestamp': timestamp,
                'read': False
            }
            if recipient not in self.messages:
                self.messages[recipient] = {}
            if sender not in self.messages:
                self.messages[sender] = {}
            # Save the message for both the sender and recipient.
            self.messages[recipient][msg_id] = message
            self.messages[sender][msg_id] = message

            # Send a live notification to the recipient if connected.
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

    def delete_account(self, username: str, password: str) -> bytes:
        with self.lock:
            if username not in self.accounts:
                return WireProtocol.error_response("Account does not exist")
            stored_hash = self.accounts[username]['password_hash']
            if not bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                return WireProtocol.error_response("Invalid password")
            
            # Delete the account data
            del self.accounts[username]
            if username in self.messages:
                del self.messages[username]
            if username in self.active_sessions:
                try:
                    self.active_sessions[username].close()
                except Exception:
                    pass
                del self.active_sessions[username]
            
            # Broadcast account deletion notification to all other connected clients.
            payload = WireProtocol.pack_string(username)  # pack the username of the deleted account
            header = WireProtocol.pack_header(MessageType.ACCOUNT_DELETED_NOTIFICATION, len(payload))
            notification_data = header + payload
            
            # Loop through active sessions and notify everyone except the deleted user.
            for user, sock in list(self.active_sessions.items()):
                if user != username:
                    try:
                        sock.sendall(notification_data)
                    except Exception as e:
                        print(f"Failed to notify {user} about account deletion: {e}")
            
            return WireProtocol.success_response("Account deleted successfully")


    def delete_message(self, username: str, msg_id: int) -> bytes:
        with self.lock:
            if username not in self.messages or msg_id not in self.messages[username]:
                return WireProtocol.error_response("Message not found")
            
            message = self.messages[username][msg_id]
            # Only allow deletion if the requesting user is the sender or recipient.
            if username != message['sender'] and username != message['recipient']:
                return WireProtocol.error_response("Unauthorized deletion attempt")
            
            sender = message['sender']
            recipient = message['recipient']
            # Remove the message from both sender and recipient histories.
            if sender in self.messages and msg_id in self.messages[sender]:
                del self.messages[sender][msg_id]
            if recipient in self.messages and msg_id in self.messages[recipient]:
                del self.messages[recipient][msg_id]

            # Determine the other party
            other_party = recipient if username == sender else sender
            # If the other party is online, notify them of the deletion.
            if other_party in self.active_sessions:
                try:
                    # For simplicity, let’s send just the msg_id (4 bytes) as the payload.
                    payload = struct.pack('!I', msg_id)
                    header = WireProtocol.pack_header(MessageType.DELETE_MESSAGE_NOTIFICATION, len(payload))
                    notification_data = header + payload
                    other_socket = self.active_sessions[other_party]
                    if other_socket and other_socket.fileno() != -1:
                        other_socket.sendall(notification_data)
                except Exception as e:
                    print(f"Failed to notify {other_party} of deletion: {e}")

            return WireProtocol.success_response("Message deleted successfully")


    def stop(self):
        """Stop the server and close all connections."""
        try:
            for client_socket in list(self.active_sessions.values()):
                try:
                    client_socket.close()
                except:
                    pass
            self.active_sessions.clear()
            if hasattr(self, 'server_socket'):
                self.server_socket.close()
            self.running = False
        except Exception as e:
            print(f"Error stopping server: {str(e)}")

if __name__ == '__main__':
    server = ChatServer()
    server.start()
