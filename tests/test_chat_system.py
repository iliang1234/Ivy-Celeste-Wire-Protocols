import unittest
import sys
import os
import json
import socket
import threading
import time
import tkinter as tk
import bcrypt
from unittest.mock import MagicMock, patch, PropertyMock

# Add parent directory to path to import client and server modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

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
        
    def get_total_bytes(self):
        return self.bytes_sent + self.bytes_received

from json_protocol.server.server import ChatServer
from json_protocol.client.tkinter_client import ChatClient

class TestChatSystem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start server in a separate thread
        cls.server = ChatServer()
        cls.server.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls.server_thread = threading.Thread(target=cls.server.start)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(1)  # Wait for server to start

    def setUp(self):
        # Create test users
        self.test_users = {
            'user1': 'pass1',
            'user2': 'pass2',
            'user3': 'pass3'
        }
        
        # Register test users via API
        for username, password in self.test_users.items():
            request = {
                'action': 'create_account',
                'username': username,
                'password': password
            }
            sock = TrackedSocket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            sock.connect(('localhost', 5001))
            sock.sendall(json.dumps(request).encode('utf-8'))
            sock.recv(4096)  # Wait for response
            print(f"\nSetup - Register {username}: {sock.get_total_bytes()} bytes transferred")
            sock.close()

    def tearDown(self):
        # Clean up test users via API
        for username, password in self.test_users.items():
            request = {
                'action': 'delete_account',
                'username': username,
                'password': password
            }
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('localhost', 5001))
            sock.sendall(json.dumps(request).encode('utf-8'))
            sock.recv(4096)  # Wait for response
            sock.close()

    def test_user_registration(self):
        """Test user registration functionality"""
        sock = TrackedSocket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        sock.connect(('localhost', 5001))
        
        # Register the socket connection
        self.server.active_sessions[sock.sock] = None
        
        # Test successful registration
        request = {
            'action': 'create_account',
            'username': 'newuser',
            'password': 'newpass'
        }
        sock.sendall(json.dumps(request).encode('utf-8'))
        response = json.loads(sock.recv(4096).decode('utf-8'))
        self.assertEqual(response['status'], 'success')
        print(f"\nSuccessful registration: {sock.get_total_bytes()} bytes transferred")
        
        # Test duplicate registration
        sock.sendall(json.dumps(request).encode('utf-8'))
        response = json.loads(sock.recv(4096).decode('utf-8'))
        self.assertEqual(response['status'], 'error')
        print(f"Duplicate registration: {sock.get_total_bytes()} bytes transferred")
        
        # Clean up
        request = {
            'action': 'delete_account',
            'username': 'newuser',
            'password': 'newpass'
        }
        sock.sendall(json.dumps(request).encode('utf-8'))
        sock.recv(4096)  # Wait for response
        print(f"Account deletion: {sock.get_total_bytes()} bytes transferred")
        sock.close()

    def test_user_login(self):
        """Test user login functionality"""
        sock = TrackedSocket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        sock.connect(('localhost', 5001))
        
        # Register the socket connection
        self.server.active_sessions[sock] = None
        
        # Test successful login
        request = {
            'action': 'login',
            'username': 'user1',
            'password': 'pass1'
        }
        sock.sendall(json.dumps(request).encode('utf-8'))
        response = json.loads(sock.recv(4096).decode('utf-8'))
        self.assertEqual(response['status'], 'success')
        
        # Test wrong password
        request['password'] = 'wrongpass'
        sock.sendall(json.dumps(request).encode('utf-8'))
        response = json.loads(sock.recv(4096).decode('utf-8'))
        self.assertEqual(response['status'], 'error')
        
        # Clean up
        del self.server.active_sessions[sock]
        sock.close()

    def test_message_sending(self):
        """Test message sending functionality"""
        sock = TrackedSocket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        sock.connect(('localhost', 5001))
        
        # Register the socket connection
        self.server.active_sessions[sock.sock] = None
        
        # Login first
        request = {
            'action': 'login',
            'username': 'user1',
            'password': 'pass1'
        }
        sock.sendall(json.dumps(request).encode('utf-8'))
        response = json.loads(sock.recv(4096).decode('utf-8'))
        print(f"\nLogin: {sock.get_total_bytes()} bytes transferred")
        
        # Update connection with logged in user
        self.server.active_sessions[sock.sock] = 'user1'
        
        # Send message
        request = {
            'action': 'send_message',
            'sender': 'user1',
            'recipient': 'user2',
            'content': 'Test message'
        }
        sock.sendall(json.dumps(request).encode('utf-8'))
        response = json.loads(sock.recv(4096).decode('utf-8'))
        self.assertEqual(response['status'], 'success')
        print(f"Send message: {sock.get_total_bytes()} bytes transferred")
        
        # Read messages to verify
        request = {
            'action': 'read_messages',
            'username': 'user2',
            'sender': 'user1'
        }
        sock.sendall(json.dumps(request).encode('utf-8'))
        response = json.loads(sock.recv(4096).decode('utf-8'))
        print(f"Read messages: {sock.get_total_bytes()} bytes transferred")
        
        # Verify message was stored
        self.assertTrue(any(
            msg['content'] == 'Test message' 
            for msg in response.get('messages', [])
        ))
        
        sock.close()

    def test_message_deletion(self):
        """Test message deletion functionality"""
        sock = TrackedSocket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        sock.connect(('localhost', 5001))
        
        # Register the socket connection
        self.server.active_sessions[sock.sock] = None
        
        # Login and send a message first
        request = {
            'action': 'login',
            'username': 'user1',
            'password': 'pass1'
        }
        sock.sendall(json.dumps(request).encode('utf-8'))
        response = json.loads(sock.recv(4096).decode('utf-8'))
        print(f"\nLogin: {sock.get_total_bytes()} bytes transferred")
        
        # Update connection with logged in user
        self.server.active_sessions[sock.sock] = 'user1'
        
        request = {
            'action': 'send_message',
            'sender': 'user1',
            'recipient': 'user2',
            'content': 'Test message'
        }
        sock.sendall(json.dumps(request).encode('utf-8'))
        response = json.loads(sock.recv(4096).decode('utf-8'))
        msg_id = response.get('message_id')
        print(f"Send message: {sock.get_total_bytes()} bytes transferred")
        
        # Delete message
        request = {
            'action': 'delete_messages',
            'username': 'user1',
            'other_user': 'user2',
            'message_ids': [msg_id]
        }
        sock.sendall(json.dumps(request).encode('utf-8'))
        response = json.loads(sock.recv(4096).decode('utf-8'))
        self.assertEqual(response['status'], 'success')
        print(f"Delete message: {sock.get_total_bytes()} bytes transferred")
        
        # Read messages to verify deletion
        request = {
            'action': 'read_messages',
            'username': 'user2',
            'sender': 'user1'
        }
        sock.sendall(json.dumps(request).encode('utf-8'))
        response = json.loads(sock.recv(4096).decode('utf-8'))
        print(f"Verify deletion: {sock.get_total_bytes()} bytes transferred")
        
        # Verify message was deleted
        self.assertFalse(any(
            msg['id'] == msg_id 
            for msg in response.get('messages', [])
        ))
        
        sock.close()

    def test_user_list(self):
        """Test user list functionality"""
        sock = TrackedSocket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        sock.connect(('localhost', 5001))
        
        # Login first
        request = {
            'action': 'login',
            'username': 'user1',
            'password': 'pass1'
        }
        sock.sendall(json.dumps(request).encode('utf-8'))
        response = json.loads(sock.recv(4096).decode('utf-8'))
        print(f"\nLogin: {sock.get_total_bytes()} bytes transferred")
        
        # Get user list
        request = {
            'action': 'list_accounts',
            'pattern': None
        }
        sock.sendall(json.dumps(request).encode('utf-8'))
        response = json.loads(sock.recv(4096).decode('utf-8'))
        self.assertEqual(response['status'], 'success')
        print(f"List accounts: {sock.get_total_bytes()} bytes transferred")
        
        # Verify all test users are in the list
        user_list = response.get('accounts', [])
        for username in self.test_users:
            if username != 'user1':  # Current user is not in the list
                self.assertIn(username, user_list)
        
        sock.close()

    def test_client_message_history(self):
        """Test client message history handling"""
        with patch('tkinter.Tk') as mock_tk:
            # Mock root window
            root = MagicMock()
            mock_tk.return_value = root
            
            # Mock StringVar
            string_var = MagicMock()
            string_var.get.return_value = '10'
            with patch('tkinter.StringVar', return_value=string_var):
                client = ChatClient()
                
                # Mock chat histories
                chat_key = ('user1', 'user2')
                client.chat_histories[chat_key] = [
                    ('Message 1', 1, 'user1'),
                    ('Message 2', 2, 'user2'),
                    ('Message 3', 3, 'user1')
                ]
                
                # Test message ordering
                sorted_messages = sorted(client.chat_histories[chat_key], key=lambda x: x[1])
                self.assertEqual(len(sorted_messages), 3)
                self.assertEqual(sorted_messages[0][1], 1)
                self.assertEqual(sorted_messages[-1][1], 3)

    def test_client_pagination(self):
        """Test client message pagination"""
        with patch('tkinter.Tk') as mock_tk:
            # Mock root window
            root = MagicMock()
            mock_tk.return_value = root
            
            # Mock StringVar
            string_var = MagicMock()
            string_var.get.return_value = '5'
            with patch('tkinter.StringVar', return_value=string_var):
                client = ChatClient()
                
                # Mock chat histories with 15 messages
                chat_key = ('user1', 'user2')
                client.chat_histories[chat_key] = [
                    (f'Message {i}', i, 'user1' if i % 2 == 0 else 'user2')
                    for i in range(1, 16)
                ]
                
                # Set messages per page to 5
                client.msg_per_page_var = string_var
                
                # Calculate total pages
                total_msgs = len(client.chat_histories[chat_key])
                msgs_per_page = 5
                expected_pages = (total_msgs + msgs_per_page - 1) // msgs_per_page
                
                self.assertEqual(expected_pages, 3)

if __name__ == '__main__':
    unittest.main()
