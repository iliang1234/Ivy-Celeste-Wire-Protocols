"""Custom protocol client implementation with PyQt6 GUI."""

import sys
import socket
import threading
import struct
import argparse
from datetime import datetime
from typing import Optional, List, Tuple
import logging
from pathlib import Path

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                            QHBoxLayout, QPushButton, QLineEdit, QLabel,
                            QTextEdit, QMessageBox, QInputDialog, QListWidget)
from PyQt6.QtCore import pyqtSignal, QObject, Qt

from shared.constants import DEFAULT_HOST, DEFAULT_PORT, MessageType, ErrorCode, SuccessCode
from shared.security import hash_password, encode_bytes, decode_bytes
from custom_protocol.protocol import Protocol

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SignalHandler(QObject):
    message_received = pyqtSignal(str, str, str)  # sender, content, timestamp
    error_occurred = pyqtSignal(str)
    login_successful = pyqtSignal(int)  # unread message count

class ChatClient(QMainWindow):
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        super().__init__()
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        self.username: Optional[str] = None
        self.connected = False
        self.signal_handler = SignalHandler()
        
        self.init_ui()
        self.connect_signals()
    
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Chat Client")
        self.setGeometry(100, 100, 800, 600)
        
        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Login section
        login_layout = QHBoxLayout()
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_button = QPushButton("Login")
        self.create_account_button = QPushButton("Create Account")
        
        login_layout.addWidget(self.username_input)
        login_layout.addWidget(self.password_input)
        login_layout.addWidget(self.login_button)
        login_layout.addWidget(self.create_account_button)
        layout.addLayout(login_layout)
        
        # Chat section
        chat_layout = QHBoxLayout()
        
        # Users list
        users_layout = QVBoxLayout()
        self.users_list = QListWidget()
        self.refresh_users_button = QPushButton("Refresh Users")
        self.user_filter = QLineEdit()
        self.user_filter.setPlaceholderText("Filter users...")
        users_layout.addWidget(self.user_filter)
        users_layout.addWidget(self.users_list)
        users_layout.addWidget(self.refresh_users_button)
        
        # Messages
        messages_layout = QVBoxLayout()
        self.messages_area = QTextEdit()
        self.messages_area.setReadOnly(True)
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message...")
        self.send_button = QPushButton("Send")
        
        messages_layout.addWidget(self.messages_area)
        messages_layout.addWidget(self.message_input)
        messages_layout.addWidget(self.send_button)
        
        chat_layout.addLayout(users_layout)
        chat_layout.addLayout(messages_layout)
        layout.addLayout(chat_layout)
        
        # Action buttons
        actions_layout = QHBoxLayout()
        self.read_messages_button = QPushButton("Read Messages")
        self.delete_messages_button = QPushButton("Delete Messages")
        self.delete_account_button = QPushButton("Delete Account")
        
        actions_layout.addWidget(self.read_messages_button)
        actions_layout.addWidget(self.delete_messages_button)
        actions_layout.addWidget(self.delete_account_button)
        layout.addLayout(actions_layout)
        
        # Initially disable chat functionality
        self.set_chat_enabled(False)
    
    def connect_signals(self):
        """Connect UI signals to slots."""
        self.login_button.clicked.connect(self.handle_login)
        self.create_account_button.clicked.connect(self.handle_create_account)
        self.refresh_users_button.clicked.connect(self.refresh_users_list)
        self.user_filter.textChanged.connect(self.filter_users)
        self.send_button.clicked.connect(self.send_message)
        self.message_input.returnPressed.connect(self.send_message)
        self.read_messages_button.clicked.connect(self.read_messages)
        self.delete_messages_button.clicked.connect(self.delete_messages)
        self.delete_account_button.clicked.connect(self.delete_account)
        
        # Signal handler connections
        self.signal_handler.message_received.connect(self.display_message)
        self.signal_handler.error_occurred.connect(self.show_error)
        self.signal_handler.login_successful.connect(self.handle_login_success)
    
    def set_chat_enabled(self, enabled: bool):
        """Enable or disable chat functionality."""
        self.users_list.setEnabled(enabled)
        self.refresh_users_button.setEnabled(enabled)
        self.user_filter.setEnabled(enabled)
        self.message_input.setEnabled(enabled)
        self.send_button.setEnabled(enabled)
        self.read_messages_button.setEnabled(enabled)
        self.delete_messages_button.setEnabled(enabled)
        self.delete_account_button.setEnabled(enabled)
    
    def connect_to_server(self) -> bool:
        """Connect to the chat server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            # Start listener thread
            threading.Thread(target=self.listen_for_messages, daemon=True).start()
            return True
        except Exception as e:
            logger.error(f"Failed to connect to server: {e}")
            self.show_error("Failed to connect to server")
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
            self.signal_handler.error_occurred.emit("Lost connection to server")
    
    def handle_server_message(self, msg_type: int, payload: bytes):
        """Handle incoming server messages."""
        if msg_type == MessageType.ERROR:
            error_code = struct.unpack("!H", payload)[0]
            self.signal_handler.error_occurred.emit(f"Error: {error_code}")
        
        elif msg_type == MessageType.SUCCESS:
            success_code = struct.unpack("!H", payload[:2])[0]
            
            if success_code == SuccessCode.LOGIN_SUCCESS:
                unread_count = struct.unpack("!I", payload[2:])[0]
                self.signal_handler.login_successful.emit(unread_count)
            
            elif success_code == SuccessCode.MESSAGE_SENT:
                self.refresh_messages()
    
    def handle_login(self):
        """Handle login button click."""
        if not self.connected and not self.connect_to_server():
            return
        
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        if not username or not password:
            self.show_error("Username and password are required")
            return
        
        password_hash = hash_password(password)
        payload = Protocol.login_payload(username, password_hash)
        packet = Protocol.create_packet(MessageType.LOGIN, payload)
        
        try:
            self.socket.send(packet)
            self.username = username
        except Exception as e:
            logger.error(f"Failed to send login request: {e}")
            self.show_error("Failed to send login request")
    
    def handle_create_account(self):
        """Handle create account button click."""
        if not self.connected and not self.connect_to_server():
            return
        
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        if not username or not password:
            self.show_error("Username and password are required")
            return
        
        password_hash = hash_password(password)
        payload = Protocol.create_account_payload(username, password_hash)
        packet = Protocol.create_packet(MessageType.CREATE_ACCOUNT, payload)
        
        try:
            self.socket.send(packet)
        except Exception as e:
            logger.error(f"Failed to send create account request: {e}")
            self.show_error("Failed to send create account request")
    
    def handle_login_success(self, unread_count: int):
        """Handle successful login."""
        self.set_chat_enabled(True)
        self.refresh_users_list()
        QMessageBox.information(self, "Login Successful",
                              f"Welcome {self.username}! You have {unread_count} unread messages.")
        if unread_count > 0:
            self.read_messages()
    
    def refresh_users_list(self):
        """Refresh the list of users."""
        pattern = self.user_filter.text().strip()
        payload = Protocol.list_accounts_payload(pattern if pattern else None)
        packet = Protocol.create_packet(MessageType.LIST_ACCOUNTS, payload)
        
        try:
            self.socket.send(packet)
            # Response will be handled in handle_server_message
        except Exception as e:
            logger.error(f"Failed to refresh users list: {e}")
            self.show_error("Failed to refresh users list")
    
    def filter_users(self):
        """Handle user filter text changes."""
        self.refresh_users_list()
    
    def send_message(self):
        """Send a message to the selected user."""
        recipient = self.users_list.currentItem()
        if not recipient:
            self.show_error("Please select a recipient")
            return
        
        message = self.message_input.text().strip()
        if not message:
            return
        
        recipient = recipient.text()
        payload = Protocol.send_message_payload(recipient, message.encode())
        packet = Protocol.create_packet(MessageType.SEND_MESSAGE, payload)
        
        try:
            self.socket.send(packet)
            self.message_input.clear()
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            self.show_error("Failed to send message")
    
    def read_messages(self):
        """Read unread messages."""
        payload = Protocol.read_messages_payload()
        packet = Protocol.create_packet(MessageType.READ_MESSAGES, payload)
        
        try:
            self.socket.send(packet)
        except Exception as e:
            logger.error(f"Failed to read messages: {e}")
            self.show_error("Failed to read messages")
    
    def delete_messages(self):
        """Delete selected messages."""
        # This would typically show a dialog to select messages to delete
        pass
    
    def delete_account(self):
        """Delete the current account."""
        reply = QMessageBox.question(
            self, "Delete Account",
            "Are you sure you want to delete your account? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            payload = Protocol.delete_account_payload()
            packet = Protocol.create_packet(MessageType.DELETE_ACCOUNT, payload)
            
            try:
                self.socket.send(packet)
                self.close()
            except Exception as e:
                logger.error(f"Failed to delete account: {e}")
                self.show_error("Failed to delete account")
    
    def display_message(self, sender: str, content: str, timestamp: str):
        """Display a message in the messages area."""
        self.messages_area.append(f"[{timestamp}] {sender}: {content}")
    
    def show_error(self, message: str):
        """Show an error message."""
        QMessageBox.critical(self, "Error", message)
    
    def closeEvent(self, event):
        """Handle window close event."""
        self.connected = False
        if self.socket:
            self.socket.close()
        event.accept()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chat Client")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Server host address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Server port number")
    args = parser.parse_args()
    
    app = QApplication(sys.argv)
    client = ChatClient(args.host, args.port)
    client.show()
    sys.exit(app.exec())
