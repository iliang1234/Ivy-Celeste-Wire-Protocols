"""Custom protocol server implementation."""

import socket
import threading
import sqlite3
import argparse
import struct
from typing import Dict, Set, Optional
import logging
from pathlib import Path

from shared.constants import DEFAULT_HOST, DEFAULT_PORT, MessageType, ErrorCode, SuccessCode
from shared.security import verify_password, encode_bytes, decode_bytes
from custom_protocol.protocol import Protocol

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ChatServer:
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Initialize database
        db_path = Path(__file__).parent / "chat.db"
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash BLOB
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                sender TEXT,
                recipient TEXT,
                content BLOB,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                read INTEGER DEFAULT 0,
                FOREIGN KEY (sender) REFERENCES users (username),
                FOREIGN KEY (recipient) REFERENCES users (username)
            )
        """)
        self.conn.commit()
        
        # Thread safety
        self.conn_lock = threading.Lock()
        self.online_users_lock = threading.Lock()
        self.active_connections = {}
        self.online_users = set()
    
    def recv_all(self, sock: socket.socket, length: int) -> Optional[bytes]:
        """Receive exactly length bytes from the socket."""
        data = bytearray()
        while len(data) < length:
            try:
                chunk = sock.recv(length - len(data))
                if not chunk:
                    return None
                data.extend(chunk)
            except socket.error as e:
                logger.error(f"Socket error while receiving: {e}")
                return None
        return bytes(data)
    
    def send_all(self, sock: socket.socket, data: bytes) -> bool:
        """Send all data to the socket."""
        total_sent = 0
        while total_sent < len(data):
            try:
                sent = sock.send(data[total_sent:])
                if sent == 0:
                    return False
                total_sent += sent
            except socket.error as e:
                logger.error(f"Socket error while sending: {e}")
                return False
        return True
        self.active_connections: Dict[str, socket.socket] = {}
        self.online_users: Set[str] = set()
        
        # Initialize database
        db_path = Path(__file__).parent / "chat.db"
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash BLOB
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                sender TEXT,
                recipient TEXT,
                content BLOB,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                read INTEGER DEFAULT 0,
                FOREIGN KEY (sender) REFERENCES users (username),
                FOREIGN KEY (recipient) REFERENCES users (username)
            )
        """)
        self.conn.commit()
        
        # Thread safety
        self.conn_lock = threading.Lock()
        self.online_users_lock = threading.Lock()
    
    def start(self):
        """Start the chat server."""
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        logger.info(f"Server started on {self.host}:{self.port}")
        
        while True:
            client_socket, address = self.socket.accept()
            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            logger.info(f"New connection from {address}")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()
    
    def handle_client(self, client_socket: socket.socket):
        """Handle client connection."""
        username: Optional[str] = None
        
        try:
            while True:
                try:
                    # Read exactly HEADER_SIZE bytes
                    header = self.recv_all(client_socket, Protocol.HEADER_SIZE)
                    if not header:
                        logger.info("Client disconnected")
                        break
                    
                    # Parse header
                    msg_type, payload_len, checksum = Protocol.parse_header(header)
                    logger.debug(f"Received message type {msg_type} with payload length {payload_len}")
                    
                    # Read payload
                    payload = self.recv_all(client_socket, payload_len)
                    if not payload:
                        logger.info("Client disconnected during payload read")
                        break
                    
                    if not Protocol.verify_checksum(payload, checksum):
                        logger.error("Checksum verification failed")
                        continue
                    
                    # Process the message
                    self.process_message(client_socket, msg_type, payload, username)
                    
                except ValueError as e:
                    logger.error(f"Protocol error: {e}")
                    continue
                except struct.error as e:
                    logger.error(f"Packet format error: {e}")
                    continue
                except Exception as e:
                    logger.error(f"Error handling client message: {e}")
                    continue
                
                # Process message
                if msg_type == MessageType.CREATE_ACCOUNT:
                    response = self.handle_create_account(payload)
                elif msg_type == MessageType.LOGIN:
                    username = self.handle_login(payload, client_socket)
                    response = self.create_login_response(username)
                elif msg_type == MessageType.LIST_ACCOUNTS:
                    response = self.handle_list_accounts(payload)
                elif msg_type == MessageType.SEND_MESSAGE:
                    response = self.handle_send_message(payload, username)
                elif msg_type == MessageType.READ_MESSAGES:
                    response = self.handle_read_messages(payload, username)
                elif msg_type == MessageType.DELETE_MESSAGES:
                    response = self.handle_delete_messages(payload, username)
                elif msg_type == MessageType.DELETE_ACCOUNT:
                    response = self.handle_delete_account(username)
                    if response[0] == MessageType.SUCCESS:
                        break
                else:
                    response = (MessageType.ERROR, Protocol.create_packet(
                        MessageType.ERROR,
                        struct.pack("!H", ErrorCode.INVALID_REQUEST)
                    ))
                
                # Send response
                client_socket.send(response[1])
                
        except Exception as e:
            logger.error(f"Error handling client: {e}")
        finally:
            if username:
                with self.online_users_lock:
                    self.online_users.remove(username)
                    del self.active_connections[username]
            client_socket.close()
    
    def handle_create_account(self, payload: bytes) -> tuple:
        """Handle account creation request."""
        username_len = struct.unpack("!H", payload[:2])[0]
        username = payload[2:2+username_len].decode()
        password_hash = payload[2+username_len+4:]
        
        with self.conn_lock:
            cursor = self.conn.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                return (MessageType.ERROR, Protocol.create_packet(
                    MessageType.ERROR,
                    struct.pack("!H", ErrorCode.USERNAME_EXISTS)
                ))
            
            self.conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                            (username, password_hash))
            self.conn.commit()
        
        return (MessageType.SUCCESS, Protocol.create_packet(
            MessageType.SUCCESS,
            struct.pack("!H", SuccessCode.ACCOUNT_CREATED)
        ))
    
    def handle_login(self, payload: bytes, client_socket: socket.socket) -> Optional[str]:
        """Handle login request."""
        username_len = struct.unpack("!H", payload[:2])[0]
        username = payload[2:2+username_len].decode()
        password_hash = payload[2+username_len+4:]
        
        with self.conn_lock:
            cursor = self.conn.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (username,)
            )
            result = cursor.fetchone()
            
            if not result or not verify_password(password_hash, result[0]):
                return None
            
            with self.online_users_lock:
                self.online_users.add(username)
                self.active_connections[username] = client_socket
            
            return username
    
    def create_login_response(self, username: Optional[str]) -> tuple:
        """Create response for login request."""
        if not username:
            return (MessageType.ERROR, Protocol.create_packet(
                MessageType.ERROR,
                struct.pack("!H", ErrorCode.INVALID_CREDENTIALS)
            ))
        
        # Get unread message count
        with self.conn_lock:
            cursor = self.conn.execute(
                "SELECT COUNT(*) FROM messages WHERE recipient = ? AND read = 0",
                (username,)
            )
            unread_count = cursor.fetchone()[0]
        
        return (MessageType.SUCCESS, Protocol.create_packet(
            MessageType.SUCCESS,
            struct.pack("!HI", SuccessCode.LOGIN_SUCCESS, unread_count)
        ))
    
    def handle_list_accounts(self, payload: bytes) -> tuple:
        """Handle list accounts request."""
        pattern_len = struct.unpack("!H", payload[:2])[0]
        pattern = payload[2:2+pattern_len].decode() if pattern_len > 0 else None
        
        with self.conn_lock:
            if pattern:
                cursor = self.conn.execute(
                    "SELECT username FROM users WHERE username LIKE ?",
                    (f"%{pattern}%",)
                )
            else:
                cursor = self.conn.execute("SELECT username FROM users")
            
            usernames = [row[0] for row in cursor.fetchall()]
        
        # Pack response
        response = struct.pack("!HH", SuccessCode.ACCOUNTS_LISTED, len(usernames))
        for username in usernames:
            username_bytes = username.encode()
            response += struct.pack(f"!H{len(username_bytes)}s",
                                  len(username_bytes), username_bytes)
        
        return (MessageType.SUCCESS, Protocol.create_packet(MessageType.SUCCESS, response))
    
    def handle_send_message(self, payload: bytes, sender: Optional[str]) -> tuple:
        """Handle send message request."""
        if not sender:
            return (MessageType.ERROR, Protocol.create_packet(
                MessageType.ERROR,
                struct.pack("!H", ErrorCode.NOT_LOGGED_IN)
            ))
        
        recipient_len = struct.unpack("!H", payload[:2])[0]
        recipient = payload[2:2+recipient_len].decode()
        message_len = struct.unpack("!I", payload[2+recipient_len:2+recipient_len+4])[0]
        message = payload[2+recipient_len+4:2+recipient_len+4+message_len]
        
        with self.conn_lock:
            cursor = self.conn.execute(
                "SELECT 1 FROM users WHERE username = ?",
                (recipient,)
            )
            if not cursor.fetchone():
                return (MessageType.ERROR, Protocol.create_packet(
                    MessageType.ERROR,
                    struct.pack("!H", ErrorCode.USER_NOT_FOUND)
                ))
            
            self.conn.execute(
                "INSERT INTO messages (sender, recipient, content) VALUES (?, ?, ?)",
                (sender, recipient, message)
            )
            self.conn.commit()
        
        # If recipient is online, notify them
        with self.online_users_lock:
            if recipient in self.active_connections:
                notification = Protocol.create_packet(
                    MessageType.SUCCESS,
                    struct.pack("!H", SuccessCode.MESSAGE_SENT)
                )
                try:
                    self.active_connections[recipient].send(notification)
                except:
                    pass
        
        return (MessageType.SUCCESS, Protocol.create_packet(
            MessageType.SUCCESS,
            struct.pack("!H", SuccessCode.MESSAGE_SENT)
        ))
    
    def handle_read_messages(self, payload: bytes, username: Optional[str]) -> tuple:
        """Handle read messages request."""
        if not username:
            return (MessageType.ERROR, Protocol.create_packet(
                MessageType.ERROR,
                struct.pack("!H", ErrorCode.NOT_LOGGED_IN)
            ))
        
        count = struct.unpack("!I", payload)[0]
        
        with self.conn_lock:
            if count == 0:
                cursor = self.conn.execute(
                    """SELECT id, sender, content, timestamp
                       FROM messages
                       WHERE recipient = ? AND read = 0
                       ORDER BY timestamp ASC""",
                    (username,)
                )
            else:
                cursor = self.conn.execute(
                    """SELECT id, sender, content, timestamp
                       FROM messages
                       WHERE recipient = ? AND read = 0
                       ORDER BY timestamp ASC
                       LIMIT ?""",
                    (username, count)
                )
            
            messages = cursor.fetchall()
            
            # Mark messages as read
            if messages:
                self.conn.execute(
                    "UPDATE messages SET read = 1 WHERE id IN (%s)" % 
                    ",".join("?" * len(messages)),
                    tuple(msg[0] for msg in messages)
                )
                self.conn.commit()
        
        # Pack response
        response = struct.pack("!HI", SuccessCode.MESSAGES_READ, len(messages))
        for msg_id, sender, content, timestamp in messages:
            sender_bytes = sender.encode()
            response += struct.pack(f"!IH{len(sender_bytes)}sI{len(content)}sQ",
                                  msg_id,
                                  len(sender_bytes), sender_bytes,
                                  len(content), content,
                                  int(timestamp.timestamp()))
        
        return (MessageType.SUCCESS, Protocol.create_packet(MessageType.SUCCESS, response))
    
    def handle_delete_messages(self, payload: bytes, username: Optional[str]) -> tuple:
        """Handle delete messages request."""
        if not username:
            return (MessageType.ERROR, Protocol.create_packet(
                MessageType.ERROR,
                struct.pack("!H", ErrorCode.NOT_LOGGED_IN)
            ))
        
        count = struct.unpack("!I", payload[:4])[0]
        message_ids = struct.unpack(f"!{count}I", payload[4:])
        
        with self.conn_lock:
            # Verify ownership of messages
            cursor = self.conn.execute(
                """SELECT COUNT(*)
                   FROM messages
                   WHERE id IN (%s) AND recipient = ?""" %
                ",".join("?" * count),
                (*message_ids, username)
            )
            if cursor.fetchone()[0] != count:
                return (MessageType.ERROR, Protocol.create_packet(
                    MessageType.ERROR,
                    struct.pack("!H", ErrorCode.INVALID_REQUEST)
                ))
            
            # Delete messages
            self.conn.execute(
                "DELETE FROM messages WHERE id IN (%s)" %
                ",".join("?" * count),
                message_ids
            )
            self.conn.commit()
        
        return (MessageType.SUCCESS, Protocol.create_packet(
            MessageType.SUCCESS,
            struct.pack("!H", SuccessCode.MESSAGES_DELETED)
        ))
    
    def handle_delete_account(self, username: Optional[str]) -> tuple:
        """Handle delete account request."""
        if not username:
            return (MessageType.ERROR, Protocol.create_packet(
                MessageType.ERROR,
                struct.pack("!H", ErrorCode.NOT_LOGGED_IN)
            ))
        
        with self.conn_lock:
            # Delete all messages
            self.conn.execute("DELETE FROM messages WHERE sender = ? OR recipient = ?",
                            (username, username))
            # Delete account
            self.conn.execute("DELETE FROM users WHERE username = ?", (username,))
            self.conn.commit()
        
        with self.online_users_lock:
            self.online_users.remove(username)
            del self.active_connections[username]
        
        return (MessageType.SUCCESS, Protocol.create_packet(
            MessageType.SUCCESS,
            struct.pack("!H", SuccessCode.ACCOUNT_DELETED)
        ))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chat Server")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port number")
    args = parser.parse_args()
    
    server = ChatServer(args.host, args.port)
    server.start()
