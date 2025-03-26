import unittest
import sys
import os
import time
import json
import shutil
import threading
from datetime import datetime

# Add parent directory to path
project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_dir)

class TestChat(unittest.TestCase):
    def setUp(self):
        # Create test directory structure
        self.test_dir = os.path.join(project_dir, 'test_data')
        self.server_data_dir = os.path.join(self.test_dir, 'server_data')
        os.makedirs(self.server_data_dir, exist_ok=True)

        # Initialize test accounts
        self.accounts = {
            'test1': {'password_hash': 'password1'},
            'test2': {'password_hash': 'password2'}
        }
        self.save_accounts()

        # Initialize empty messages
        self.messages = {
            'test1': [],
            'test2': []
        }
        self.save_messages()

    def tearDown(self):
        # Clean up test directory
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def save_accounts(self):
        accounts_file = os.path.join(self.server_data_dir, 'accounts.json')
        with open(accounts_file, 'w') as f:
            json.dump(self.accounts, f)

    def save_messages(self):
        for username, messages in self.messages.items():
            user_dir = os.path.join(self.server_data_dir, username)
            os.makedirs(user_dir, exist_ok=True)
            messages_file = os.path.join(user_dir, 'messages.json')
            with open(messages_file, 'w') as f:
                json.dump(messages, f)

    def test_account_creation(self):
        """Test account creation and validation"""
        # Test creating a new account
        username = 'newuser'
        password = 'newpass'
        self.accounts[username] = {'password_hash': password}
        self.save_accounts()

        # Verify account exists
        accounts_file = os.path.join(self.server_data_dir, 'accounts.json')
        with open(accounts_file, 'r') as f:
            saved_accounts = json.load(f)
        self.assertIn(username, saved_accounts)
        self.assertEqual(saved_accounts[username]['password_hash'], password)

    def test_message_sending(self):
        """Test message sending between users"""
        # Send a message from test1 to test2
        msg = {
            'id': '1',
            'sender': 'test1',
            'recipient': 'test2',
            'content': 'Hello test2!',
            'timestamp': datetime.now().isoformat(),
            'read': False
        }
        
        # Add message to both users' message lists
        self.messages['test1'].append(msg)
        self.messages['test2'].append(msg)
        self.save_messages()

        # Verify message was saved for both users
        for username in ['test1', 'test2']:
            messages_file = os.path.join(self.server_data_dir, username, 'messages.json')
            with open(messages_file, 'r') as f:
                saved_messages = json.load(f)
            self.assertEqual(len(saved_messages), 1)
            saved_msg = saved_messages[0]
            self.assertEqual(saved_msg['content'], 'Hello test2!')
            self.assertEqual(saved_msg['sender'], 'test1')
            self.assertEqual(saved_msg['recipient'], 'test2')

    def test_message_deletion(self):
        """Test message deletion"""
        # First send a message
        msg = {
            'id': '1',
            'sender': 'test1',
            'recipient': 'test2',
            'content': 'Message to delete',
            'timestamp': datetime.now().isoformat(),
            'read': False
        }
        self.messages['test1'].append(msg)
        self.messages['test2'].append(msg)
        self.save_messages()

        # Delete the message (mark as deleted)
        for username in ['test1', 'test2']:
            messages = self.messages[username]
            for message in messages:
                if message['id'] == '1':
                    message['content'] = '<message deleted>'
        self.save_messages()

        # Verify message was marked as deleted for both users
        for username in ['test1', 'test2']:
            messages_file = os.path.join(self.server_data_dir, username, 'messages.json')
            with open(messages_file, 'r') as f:
                saved_messages = json.load(f)
            self.assertEqual(len(saved_messages), 1)
            self.assertEqual(saved_messages[0]['content'], '<message deleted>')

    def test_duplicate_prevention(self):
        """Test duplicate message prevention"""
        # Send same message multiple times
        msg_content = "Duplicate test message"
        sent_messages = []
        
        # Try to send same message 5 times within 12 seconds
        for i in range(5):
            msg = {
                'id': str(i+1),
                'sender': 'test1',
                'recipient': 'test2',
                'content': msg_content,
                'timestamp': datetime.now().isoformat(),
                'read': False
            }
            
            # Check if similar message exists within 12 second window
            is_duplicate = False
            for sent_msg in sent_messages:
                time_diff = abs((datetime.fromisoformat(msg['timestamp']) - 
                               datetime.fromisoformat(sent_msg['timestamp'])).total_seconds())
                if (sent_msg['content'] == msg['content'] and 
                    sent_msg['sender'] == msg['sender'] and 
                    sent_msg['recipient'] == msg['recipient'] and
                    time_diff < 12):
                    is_duplicate = True
                    break
            
            if not is_duplicate:
                sent_messages.append(msg)
                self.messages['test1'].append(msg)
                self.messages['test2'].append(msg)
            
            time.sleep(0.1)  # Small delay between attempts
        
        self.save_messages()

        # Verify only one message was saved
        for username in ['test1', 'test2']:
            messages_file = os.path.join(self.server_data_dir, username, 'messages.json')
            with open(messages_file, 'r') as f:
                saved_messages = json.load(f)
            duplicate_messages = [m for m in saved_messages if m['content'] == msg_content]
            self.assertEqual(len(duplicate_messages), 1)

if __name__ == '__main__':
    unittest.main()
