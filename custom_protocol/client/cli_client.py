"""Command-line interface for the chat client."""

import socket
import threading
import argparse
import logging
from typing import Optional
import struct
import sys

from shared.constants import DEFAULT_HOST, DEFAULT_PORT, MessageType, ErrorCode, SuccessCode
from shared.security import hash_password, encode_bytes, decode_bytes
from custom_protocol.protocol import Protocol

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ChatClient:
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        self.username: Optional[str] = None
        self.connected = False
        self.message_thread: Optional[threading.Thread] = None
    
    def connect_to_server(self) -> bool:
        """Connect to the chat server."""
        try:
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.connected = True
            
            if self.message_thread and self.message_thread.is_alive():
                self.connected = False
                self.message_thread.join(timeout=1)
            
            self.message_thread = threading.Thread(target=self.listen_for_messages, daemon=True)
            self.message_thread.start()
            return True
        except Exception as e:
            logger.error(f"Failed to connect to server: {e}")
            self.connected = False
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
            return False
    
    def listen_for_messages(self):
        """Listen for incoming messages from the server."""
        try:
            while self.connected:
                # First read exactly HEADER_SIZE bytes
                header = b''
                while len(header) < Protocol.HEADER_SIZE:
                    chunk = self.socket.recv(Protocol.HEADER_SIZE - len(header))
                    if not chunk:
                        return
                    header += chunk

                # Parse header
                msg_type, payload_len, checksum = Protocol.parse_header(header)
                
                # Read payload
                payload = b''
                while len(payload) < payload_len:
                    chunk = self.socket.recv(payload_len - len(payload))
                    if not chunk:
                        return
                    payload += chunk
                
                if not Protocol.verify_checksum(payload, checksum):
                    logger.error("Checksum verification failed")
                    continue
                
                self.handle_server_message(msg_type, payload)
        
        except Exception as e:
            logger.error(f"Error in message listener: {e}")
            self.connected = False
            print("\nLost connection to server")
            sys.exit(1)
    
    def handle_server_message(self, msg_type: int, payload: bytes):
        """Handle incoming server messages."""
        try:
            if msg_type == MessageType.ERROR:
                error_code = struct.unpack("!H", payload)[0]
                print(f"\nError: {error_code}")
            
            elif msg_type == MessageType.SUCCESS:
                success_code = struct.unpack("!H", payload[:2])[0]
                
                if success_code == SuccessCode.LOGIN_SUCCESS:
                    unread_count = struct.unpack("!I", payload[2:])[0]
                    print(f"\nLogin successful! You have {unread_count} unread messages.")
                
                elif success_code == SuccessCode.ACCOUNT_CREATED:
                    print("\nAccount created successfully!")
                
                elif success_code == SuccessCode.MESSAGE_SENT:
                    print("\nMessage sent successfully!")
                
                elif success_code == SuccessCode.MESSAGES_READ:
                    count = struct.unpack("!I", payload[2:6])[0]
                    if count == 0:
                        print("\nNo new messages.")
                    else:
                        print(f"\nReceived {count} messages:")
                        pos = 6
                        for _ in range(count):
                            msg_id = struct.unpack("!I", payload[pos:pos+4])[0]
                            pos += 4
                            sender_len = struct.unpack("!H", payload[pos:pos+2])[0]
                            pos += 2
                            sender = payload[pos:pos+sender_len].decode()
                            pos += sender_len
                            content_len = struct.unpack("!I", payload[pos:pos+4])[0]
                            pos += 4
                            content = payload[pos:pos+content_len].decode()
                            pos += content_len
                            timestamp = struct.unpack("!Q", payload[pos:pos+8])[0]
                            pos += 8
                            print(f"From {sender}: {content}")
        
        except Exception as e:
            logger.error(f"Error handling server message: {e}")
    
    def create_account(self, username: str, password: str):
        """Create a new account."""
        if not self.connected and not self.connect_to_server():
            print("Failed to connect to server")
            return
        
        password_hash = hash_password(password)
        payload = Protocol.create_account_payload(username, password_hash)
        packet = Protocol.create_packet(MessageType.CREATE_ACCOUNT, payload)
        
        try:
            self.socket.send(packet)
        except Exception as e:
            logger.error(f"Failed to send create account request: {e}")
            print("Failed to send create account request")
    
    def login(self, username: str, password: str):
        """Log in to an existing account."""
        if not self.connected and not self.connect_to_server():
            print("Failed to connect to server")
            return
        
        password_hash = hash_password(password)
        payload = Protocol.login_payload(username, password_hash)
        packet = Protocol.create_packet(MessageType.LOGIN, payload)
        
        try:
            self.socket.send(packet)
            self.username = username
        except Exception as e:
            logger.error(f"Failed to send login request: {e}")
            print("Failed to send login request")
    
    def list_users(self, pattern: Optional[str] = None):
        """List users matching the pattern."""
        payload = Protocol.list_accounts_payload(pattern)
        packet = Protocol.create_packet(MessageType.LIST_ACCOUNTS, payload)
        
        try:
            self.socket.send(packet)
        except Exception as e:
            logger.error(f"Failed to list users: {e}")
            print("Failed to list users")
    
    def send_packet(self, packet: bytes) -> bool:
        """Send a packet to the server."""
        if not self.connected:
            if not self.connect_to_server():
                return False
        
        try:
            total_sent = 0
            while total_sent < len(packet):
                sent = self.socket.send(packet[total_sent:])
                if sent == 0:
                    raise RuntimeError("Socket connection broken")
                total_sent += sent
            return True
        except Exception as e:
            logger.error(f"Failed to send packet: {e}")
            self.connected = False
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
            return False
    
    def send_message(self, recipient: str, message: str):
        """Send a message to a user."""
        try:
            payload = Protocol.send_message_payload(recipient, message.encode())
            packet = Protocol.create_packet(MessageType.SEND_MESSAGE, payload)
            if not self.send_packet(packet):
                print("Failed to send message")
        except Exception as e:
            logger.error(f"Failed to create message packet: {e}")
            print("Failed to send message")
    
    def read_messages(self):
        """Read unread messages."""
        payload = Protocol.read_messages_payload()
        packet = Protocol.create_packet(MessageType.READ_MESSAGES, payload)
        
        try:
            self.socket.send(packet)
        except Exception as e:
            logger.error(f"Failed to read messages: {e}")
            print("Failed to read messages")
    
    def delete_account(self):
        """Delete the current account."""
        payload = Protocol.delete_account_payload()
        packet = Protocol.create_packet(MessageType.DELETE_ACCOUNT, payload)
        
        try:
            self.socket.send(packet)
        except Exception as e:
            logger.error(f"Failed to delete account: {e}")
            print("Failed to delete account")
    
    def close(self):
        """Close the connection."""
        self.connected = False
        if self.socket:
            self.socket.close()

def main():
    parser = argparse.ArgumentParser(description="Chat Client")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Server host address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Server port number")
    args = parser.parse_args()
    
    client = ChatClient(args.host, args.port)
    
    while True:
        print("\nChat Client Menu:")
        print("1. Create Account")
        print("2. Login")
        print("3. List Users")
        print("4. Send Message")
        print("5. Read Messages")
        print("6. Delete Account")
        print("7. Exit")
        
        choice = input("\nEnter your choice (1-7): ")
        
        if choice == "1":
            username = input("Enter username: ")
            password = input("Enter password: ")
            client.create_account(username, password)
        
        elif choice == "2":
            username = input("Enter username: ")
            password = input("Enter password: ")
            client.login(username, password)
        
        elif choice == "3":
            pattern = input("Enter search pattern (or press Enter for all): ")
            client.list_users(pattern if pattern else None)
        
        elif choice == "4":
            if not client.username:
                print("Please login first")
                continue
            recipient = input("Enter recipient username: ")
            message = input("Enter message: ")
            client.send_message(recipient, message)
        
        elif choice == "5":
            if not client.username:
                print("Please login first")
                continue
            client.read_messages()
        
        elif choice == "6":
            if not client.username:
                print("Please login first")
                continue
            confirm = input("Are you sure you want to delete your account? (yes/no): ")
            if confirm.lower() == "yes":
                client.delete_account()
                break
        
        elif choice == "7":
            print("Goodbye!")
            client.close()
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nGoodbye!")
        sys.exit(0)
