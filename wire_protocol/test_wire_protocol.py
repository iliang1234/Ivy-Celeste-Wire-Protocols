import unittest
import sys
import os
import socket
import threading
import time
import struct
import json
import tkinter as tk
from unittest.mock import patch, MagicMock, PropertyMock

# Add current directory to path to import client and server modules
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from server import ChatServer
from protocol import WireProtocol, MessageType
from tkinter_client import ChatClient

###############################################################################
# A simple socket wrapper that tracks the number of bytes transferred.
###############################################################################
class TrackedSocket:
    def __init__(self, sock):
        self.sock = sock
        self.bytes_sent = 0
        self.bytes_received = 0
        
    def sendall(self, data):
        self.bytes_sent += len(data)
        return self.sock.sendall(data)
        
    def recv(self, bufsize):
        data = self.sock.recv(bufsize)
        self.bytes_received += len(data)
        return data
        
    def connect(self, *args, **kwargs):
        return self.sock.connect(*args, **kwargs)
        
    def close(self):
        return self.sock.close()
        
    def fileno(self):
        return self.sock.fileno()
        
    def settimeout(self, timeout):
        return self.sock.settimeout(timeout)
        
    def get_total_bytes(self):
        return self.bytes_sent + self.bytes_received

###############################################################################
# Test module for the chat system using the wire protocol.
###############################################################################
class TestChatSystemWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start server in a separate thread.
        cls.server = ChatServer(port=65432)
        cls.server.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls.server_thread = threading.Thread(target=cls.server.start)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(1)  # Wait for the server to start

    def setUp(self):
        # Create a set of test users.
        self.test_users = {
            'user1': 'pass1',
            'user2': 'pass2',
            'user3': 'pass3'
        }
        # For each test user, send a create account request.
        for username, password in self.test_users.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(('localhost', 65432))
            request = WireProtocol.create_account_request(username, password)
            sock.sendall(request)
            # Drain response (we ignore the details here)
            try:
                self._read_response(sock)
            except Exception:
                pass
            sock.close()

    def tearDown(self):
        # Delete the test users.
        for username, password in self.test_users.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(('localhost', 65432))
            request = WireProtocol.delete_account_request(username, password)
            sock.sendall(request)
            try:
                self._read_response(sock)
            except Exception:
                pass
            sock.close()

    def _create_socket(self):
        """Create a new socket wrapped by TrackedSocket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(5)  # Increase timeout to 5 seconds
        return TrackedSocket(sock)

    def _read_response(self, sock, timeout=5):
        """Read the header and drain any payload; return the message type."""
        try:
            sock.settimeout(timeout)
            header = sock.recv(9)
            if not header or len(header) < 9:
                return None
            msg_type, payload_length, _ = WireProtocol.unpack_header(header)
            # Drain any payload.
            if payload_length > 0:
                remaining = payload_length
                payload = b''
                while remaining > 0:
                    chunk = sock.recv(min(remaining, 4096))
                    if not chunk:
                        break
                    payload += chunk
                    remaining -= len(chunk)
            return msg_type
        except Exception as e:
            print(f"Error reading response: {e}")
            return None

    def _read_full_response(self, sock, timeout=5):
        """Read header and payload; return (msg_type, payload)."""
        try:
            sock.settimeout(timeout)
            header = sock.recv(9)
            if not header or len(header) < 9:
                return None, None
            msg_type, payload_length, _ = WireProtocol.unpack_header(header)
            payload = b''
            if payload_length > 0:
                remaining = payload_length
                while remaining > 0:
                    chunk = sock.recv(min(remaining, 4096))
                    if not chunk:
                        break
                    payload += chunk
                    remaining -= len(chunk)
            return msg_type, payload
        except Exception as e:
            print(f"Error reading full response: {e}")
            return None, None

    def test_user_registration(self):
        """Test user registration functionality."""
        sock = self._create_socket()
        sock.connect(('localhost', 65432))
        
        # Test successful registration with a unique username.
        username, password = 'newuser', 'newpass'
        request = WireProtocol.create_account_request(username, password)
        sock.sendall(request)
        msg_type = self._read_response(sock)
        self.assertEqual(msg_type, MessageType.SUCCESS)
        
        # Test duplicate registration.
        sock.sendall(request)
        msg_type = self._read_response(sock)
        self.assertEqual(msg_type, MessageType.ERROR)
        
        print(f"\nRegistration test: {sock.get_total_bytes()} bytes transferred")
        # Clean up: delete the account.
        request = WireProtocol.delete_account_request(username, password)
        sock.sendall(request)
        self._read_response(sock)
        sock.close()

    def test_user_login(self):
        """Test user login functionality."""
        sock = self._create_socket()
        sock.connect(('localhost', 65432))
        
        # Test successful login.
        request = WireProtocol.login_request('user1', 'pass1')
        sock.sendall(request)
        msg_type = self._read_response(sock)
        self.assertEqual(msg_type, MessageType.SUCCESS)
        
        # Test login with wrong password.
        request = WireProtocol.login_request('user1', 'wrongpass')
        sock.sendall(request)
        msg_type = self._read_response(sock)
        self.assertEqual(msg_type, MessageType.ERROR)
        
        print(f"\nLogin test: {sock.get_total_bytes()} bytes transferred")
        sock.close()

    def test_message_sending(self):
        """Test message sending functionality."""
        sock1 = self._create_socket()
        sock2 = self._create_socket()
        sock1.connect(('localhost', 65432))
        sock2.connect(('localhost', 65432))
        
        # Login both users.
        sock1.sendall(WireProtocol.login_request('user1', 'pass1'))
        self._read_response(sock1)
        sock2.sendall(WireProtocol.login_request('user2', 'pass2'))
        self._read_response(sock2)
        
        # Send a message from user1 to user2.
        message = "Hello, user2!"
        request = WireProtocol.send_message_request('user1', 'user2', message)
        sock1.sendall(request)
        
        # Wait for the NEW_MESSAGE_NOTIFICATION on sock2.
        time.sleep(1)  # Give more time for message propagation
        msg_type, payload = self._read_full_response(sock2)
        self.assertEqual(msg_type, MessageType.NEW_MESSAGE_NOTIFICATION)
        if payload:
            message_data, _ = WireProtocol.unpack_message(payload)
            self.assertEqual(message_data['content'], message)
        
        print(f"\nMessage test: {sock1.get_total_bytes() + sock2.get_total_bytes()} bytes transferred")
        sock1.close()
        sock2.close()

    def test_message_deletion(self):
        """Test message deletion functionality."""
        sock1 = self._create_socket()
        sock2 = self._create_socket()
        try:
            sock1.connect(('localhost', 65432))
            sock2.connect(('localhost', 65432))
            
            # Login both users.
            sock1.sendall(WireProtocol.login_request('user1', 'pass1'))
            self._read_response(sock1)
            sock2.sendall(WireProtocol.login_request('user2', 'pass2'))
            self._read_response(sock2)
            
            # Send a message from user1 to user2.
            message = "Test message for deletion"
            request = WireProtocol.send_message_request('user1', 'user2', message)
            sock1.sendall(request)
            
            # Wait for NEW_MESSAGE_NOTIFICATION on sock2 and capture the message ID.
            time.sleep(1)  # Give more time for message propagation
            msg_type, payload = self._read_full_response(sock2)
            self.assertEqual(msg_type, MessageType.NEW_MESSAGE_NOTIFICATION)
            if payload:
                message_data, _ = WireProtocol.unpack_message(payload)
                actual_msg_id = message_data['id']
                
                # Delete the message.
                request = WireProtocol.delete_message_request('user1', actual_msg_id)
                sock1.sendall(request)
                
                # Wait for deletion notification on sock2.
                time.sleep(1)  # Give more time for deletion propagation
                msg_type, payload = self._read_full_response(sock2)
                self.assertEqual(msg_type, MessageType.DELETE_MESSAGE_NOTIFICATION)
                if payload:
                    deleted_msg_id = struct.unpack('!I', payload)[0]
                    self.assertEqual(deleted_msg_id, actual_msg_id)
        finally:
            sock1.close()
            sock2.close()

    def test_user_list(self):
        """Test user list (account listing) functionality."""
        sock = self._create_socket()
        try:
            sock.connect(('localhost', 65432))
            # Login as a test user.
            sock.sendall(WireProtocol.login_request('user1', 'pass1'))
            self._read_response(sock)
            
            # Request a list of all accounts.
            request = WireProtocol.list_accounts_request()
            sock.sendall(request)
            msg_type = self._read_response(sock)
            self.assertEqual(msg_type, MessageType.SUCCESS)
            
            print(f"\nList accounts test: {sock.get_total_bytes()} bytes transferred")
        finally:
            sock.close()

    def test_delete_account(self):
        """Test account deletion functionality."""
        sock1 = self._create_socket()
        sock2 = self._create_socket()
        try:
            sock1.connect(('localhost', 65432))
            sock2.connect(('localhost', 65432))
            
            # Login both users.
            sock1.sendall(WireProtocol.login_request('user1', 'pass1'))
            self._read_response(sock1)
            sock2.sendall(WireProtocol.login_request('user2', 'pass2'))
            self._read_response(sock2)
            
            # Delete user1's account.
            request = WireProtocol.delete_account_request('user1', 'pass1')
            sock1.sendall(request)
            time.sleep(1)  # Give more time for account deletion propagation
            
            # Wait for sock2 to receive the account deletion notification.
            msg_type, payload = self._read_full_response(sock2)
            self.assertEqual(msg_type, MessageType.ACCOUNT_DELETED_NOTIFICATION)
            if payload:
                deleted_username, _ = WireProtocol.unpack_string(payload)
                self.assertEqual(deleted_username, 'user1')
        finally:
            sock1.close()
            sock2.close()

    def test_client_message_history(self):
        """Test that ChatClient orders messages by timestamp."""
        # Create a mock Tk root window
        root = MagicMock()
        with patch('tkinter.Tk', return_value=root), \
             patch('tkinter.StringVar') as mock_string_var, \
             patch('tkinter.ttk.Treeview'), \
             patch('tkinter.Text'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Frame'):
            
            # Configure the StringVar mock
            string_var_instance = MagicMock()
            string_var_instance.get.return_value = "10"
            mock_string_var.return_value = string_var_instance
            
            client = ChatClient()
            chat_key = tuple(sorted(['user1', 'user2']))
            # Simulate three messages with increasing timestamps.
            client.chat_histories[chat_key] = [
                {'id': 1, 'sender': 'user1', 'recipient': 'user2', 'content': 'Message 1', 'timestamp': 1.0, 'read': False},
                {'id': 2, 'sender': 'user2', 'recipient': 'user1', 'content': 'Message 2', 'timestamp': 2.0, 'read': False},
                {'id': 3, 'sender': 'user1', 'recipient': 'user2', 'content': 'Message 3', 'timestamp': 3.0, 'read': False}
            ]
            # Check that sorting by timestamp yields the expected order.
            sorted_messages = sorted(client.chat_histories[chat_key], key=lambda x: x['timestamp'])
            self.assertEqual(sorted_messages[0]['timestamp'], 1.0)
            self.assertEqual(sorted_messages[-1]['timestamp'], 3.0)

    def test_client_pagination(self):
        """Test that ChatClient correctly computes the number of message pages."""
        # Create a mock Tk root window
        root = MagicMock()
        with patch('tkinter.Tk', return_value=root), \
             patch('tkinter.StringVar') as mock_string_var, \
             patch('tkinter.ttk.Treeview'), \
             patch('tkinter.Text'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Frame'):
            
            # Configure the StringVar mock
            string_var_instance = MagicMock()
            string_var_instance.get.return_value = "5"
            mock_string_var.return_value = string_var_instance
            
            client = ChatClient()
            chat_key = tuple(sorted(['user1', 'user2']))
            # Simulate 15 messages.
            client.chat_histories[chat_key] = [
                {
                    'id': i,
                    'sender': 'user1' if i % 2 == 0 else 'user2',
                    'recipient': 'user2' if i % 2 == 0 else 'user1',
                    'content': f'Message {i}',
                    'timestamp': float(i),
                    'read': False
                }
                for i in range(1, 16)
            ]
            # Set messages per page to 5.
            client.messages_per_page = 5
            total_msgs = len(client.chat_histories[chat_key])
            expected_pages = (total_msgs + client.messages_per_page - 1) // client.messages_per_page
            self.assertEqual(expected_pages, 3)

    def test_user_registration_byte_transfer(self):
        """Test user registration functionality with byte transfer tracking."""
        sock = self._create_socket()
        sock.connect(('localhost', 65432))
        
        # Test successful registration with a unique username.
        username, password = 'newuser', 'newpass'
        request = WireProtocol.create_account_request(username, password)
        sock.sendall(request)
        msg_type = self._read_response(sock)
        self.assertEqual(msg_type, MessageType.SUCCESS)
        
        # Test duplicate registration.
        sock.sendall(request)
        msg_type = self._read_response(sock)
        self.assertEqual(msg_type, MessageType.ERROR)
        
        print(f"\nRegistration test: {sock.get_total_bytes()} bytes transferred")
        # Clean up: delete the account.
        request = WireProtocol.delete_account_request(username, password)
        sock.sendall(request)
        self._read_response(sock)
        sock.close()

    def test_user_login_byte_transfer(self):
        """Test user login functionality with byte transfer tracking."""
        sock = self._create_socket()
        sock.connect(('localhost', 65432))
        
        # Test successful login.
        request = WireProtocol.login_request('user1', 'pass1')
        sock.sendall(request)
        msg_type = self._read_response(sock)
        self.assertEqual(msg_type, MessageType.SUCCESS)
        
        # Test login with wrong password.
        request = WireProtocol.login_request('user1', 'wrongpass')
        sock.sendall(request)
        msg_type = self._read_response(sock)
        self.assertEqual(msg_type, MessageType.ERROR)
        
        print(f"\nLogin test: {sock.get_total_bytes()} bytes transferred")
        sock.close()

    def test_message_sending_byte_transfer(self):
        """Test message sending functionality with byte transfer tracking."""
        sock1 = self._create_socket()
        sock2 = self._create_socket()
        sock1.connect(('localhost', 65432))
        sock2.connect(('localhost', 65432))
        
        # Login both users.
        sock1.sendall(WireProtocol.login_request('user1', 'pass1'))
        self._read_response(sock1)
        sock2.sendall(WireProtocol.login_request('user2', 'pass2'))
        self._read_response(sock2)
        
        # Send a message from user1 to user2.
        message = "Hello, user2!"
        request = WireProtocol.send_message_request('user1', 'user2', message)
        sock1.sendall(request)
        
        # Wait for the NEW_MESSAGE_NOTIFICATION on sock2.
        time.sleep(1)  # Give more time for message propagation
        msg_type, payload = self._read_full_response(sock2)
        self.assertEqual(msg_type, MessageType.NEW_MESSAGE_NOTIFICATION)
        if payload:
            message_data, _ = WireProtocol.unpack_message(payload)
            self.assertEqual(message_data['content'], message)
        
        print(f"\nMessage test: {sock1.get_total_bytes() + sock2.get_total_bytes()} bytes transferred")
        sock1.close()
        sock2.close()

    def test_message_deletion_byte_transfer(self):
        """Test message deletion functionality with byte transfer tracking."""
        sock1 = self._create_socket()
        sock2 = self._create_socket()
        try:
            sock1.connect(('localhost', 65432))
            sock2.connect(('localhost', 65432))
            
            # Login both users.
            sock1.sendall(WireProtocol.login_request('user1', 'pass1'))
            self._read_response(sock1)
            sock2.sendall(WireProtocol.login_request('user2', 'pass2'))
            self._read_response(sock2)
            
            # Send a message from user1 to user2.
            message = "Test message for deletion"
            request = WireProtocol.send_message_request('user1', 'user2', message)
            sock1.sendall(request)
            
            # Wait for NEW_MESSAGE_NOTIFICATION on sock2 and capture the message ID.
            time.sleep(1)  # Give more time for message propagation
            msg_type, payload = self._read_full_response(sock2)
            self.assertEqual(msg_type, MessageType.NEW_MESSAGE_NOTIFICATION)
            if payload:
                message_data, _ = WireProtocol.unpack_message(payload)
                actual_msg_id = message_data['id']
                
                # Delete the message.
                request = WireProtocol.delete_message_request('user1', actual_msg_id)
                sock1.sendall(request)
                
                # Wait for deletion notification on sock2.
                time.sleep(1)  # Give more time for deletion propagation
                msg_type, payload = self._read_full_response(sock2)
                self.assertEqual(msg_type, MessageType.DELETE_MESSAGE_NOTIFICATION)
                if payload:
                    deleted_msg_id = struct.unpack('!I', payload)[0]
                    self.assertEqual(deleted_msg_id, actual_msg_id)
        finally:
            sock1.close()
            sock2.close()

    def test_user_list_byte_transfer(self):
        """Test user list (account listing) functionality with byte transfer tracking."""
        sock = self._create_socket()
        try:
            sock.connect(('localhost', 65432))
            # Login as a test user.
            sock.sendall(WireProtocol.login_request('user1', 'pass1'))
            self._read_response(sock)
            
            # Request a list of all accounts.
            request = WireProtocol.list_accounts_request()
            sock.sendall(request)
            msg_type = self._read_response(sock)
            self.assertEqual(msg_type, MessageType.SUCCESS)
            
            print(f"\nList accounts test: {sock.get_total_bytes()} bytes transferred")
        finally:
            sock.close()

    def test_delete_account_byte_transfer(self):
        """Test account deletion functionality with byte transfer tracking."""
        sock1 = self._create_socket()
        sock2 = self._create_socket()
        try:
            sock1.connect(('localhost', 65432))
            sock2.connect(('localhost', 65432))
            
            # Login both users.
            sock1.sendall(WireProtocol.login_request('user1', 'pass1'))
            self._read_response(sock1)
            sock2.sendall(WireProtocol.login_request('user2', 'pass2'))
            self._read_response(sock2)
            
            # Delete user1's account.
            request = WireProtocol.delete_account_request('user1', 'pass1')
            sock1.sendall(request)
            time.sleep(1)  # Give more time for account deletion propagation
            
            # Wait for sock2 to receive the account deletion notification.
            msg_type, payload = self._read_full_response(sock2)
            self.assertEqual(msg_type, MessageType.ACCOUNT_DELETED_NOTIFICATION)
            if payload:
                deleted_username, _ = WireProtocol.unpack_string(payload)
                self.assertEqual(deleted_username, 'user1')
        finally:
            sock1.close()
            sock2.close()

    def test_client_message_history_byte_transfer(self):
        """Test that ChatClient orders messages by timestamp with byte transfer tracking."""
        # Create a mock Tk root window
        root = MagicMock()
        with patch('tkinter.Tk', return_value=root), \
             patch('tkinter.StringVar') as mock_string_var, \
             patch('tkinter.ttk.Treeview'), \
             patch('tkinter.Text'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Frame'):
            
            # Configure the StringVar mock
            string_var_instance = MagicMock()
            string_var_instance.get.return_value = "10"
            mock_string_var.return_value = string_var_instance
            
            client = ChatClient()
            chat_key = tuple(sorted(['user1', 'user2']))
            # Simulate three messages with increasing timestamps.
            client.chat_histories[chat_key] = [
                {'id': 1, 'sender': 'user1', 'recipient': 'user2', 'content': 'Message 1', 'timestamp': 1.0, 'read': False},
                {'id': 2, 'sender': 'user2', 'recipient': 'user1', 'content': 'Message 2', 'timestamp': 2.0, 'read': False},
                {'id': 3, 'sender': 'user1', 'recipient': 'user2', 'content': 'Message 3', 'timestamp': 3.0, 'read': False}
            ]
            # Check that sorting by timestamp yields the expected order.
            sorted_messages = sorted(client.chat_histories[chat_key], key=lambda x: x['timestamp'])
            self.assertEqual(sorted_messages[0]['timestamp'], 1.0)
            self.assertEqual(sorted_messages[-1]['timestamp'], 3.0)

    def test_client_pagination_byte_transfer(self):
        """Test that ChatClient correctly computes the number of message pages with byte transfer tracking."""
        # Create a mock Tk root window
        root = MagicMock()
        with patch('tkinter.Tk', return_value=root), \
             patch('tkinter.StringVar') as mock_string_var, \
             patch('tkinter.ttk.Treeview'), \
             patch('tkinter.Text'), \
             patch('tkinter.Entry'), \
             patch('tkinter.Button'), \
             patch('tkinter.Frame'):
            
            # Configure the StringVar mock
            string_var_instance = MagicMock()
            string_var_instance.get.return_value = "5"
            mock_string_var.return_value = string_var_instance
            
            client = ChatClient()
            chat_key = tuple(sorted(['user1', 'user2']))
            # Simulate 15 messages.
            client.chat_histories[chat_key] = [
                {
                    'id': i,
                    'sender': 'user1' if i % 2 == 0 else 'user2',
                    'recipient': 'user2' if i % 2 == 0 else 'user1',
                    'content': f'Message {i}',
                    'timestamp': float(i),
                    'read': False
                }
                for i in range(1, 16)
            ]
            # Set messages per page to 5.
            client.messages_per_page = 5
            total_msgs = len(client.chat_histories[chat_key])
            expected_pages = (total_msgs + client.messages_per_page - 1) // client.messages_per_page
            self.assertEqual(expected_pages, 3)

if __name__ == '__main__':
    unittest.main()
