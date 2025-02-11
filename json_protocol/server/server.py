import json
import socket
import threading
import bcrypt
from datetime import datetime
from typing import Dict, List, Optional

class ChatServer:
    def __init__(self, host: str = 'localhost', port: int = 5001):
        # Store messages with their read status: {username: {msg_id: {message_data}}}
        self.messages = {}
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.accounts: Dict[str, dict] = {}  # username -> {password_hash, messages}
        self.active_sessions: Dict[str, socket.socket] = {}  # username -> socket
        self.lock = threading.Lock()
        self.next_msg_id = 0  # Global message ID counter

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server started on {self.host}:{self.port}")
        
        while True:
            client_socket, address = self.server_socket.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

    def handle_client(self, client_socket: socket.socket):
        while True:
            try:
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                request = json.loads(data)
                response = self.process_request(request, client_socket)
                client_socket.send(json.dumps(response).encode('utf-8'))
            except Exception as e:
                print(f"Error handling client: {str(e)}")
                break
        
        client_socket.close()

    def process_request(self, request: dict, client_socket: socket.socket) -> dict:
        action = request.get('action')
        
        if action == 'create_account':
            return self.create_account(request['username'], request['password'])
        elif action == 'login':
            return self.login(request['username'], request['password'], client_socket)
        elif action == 'list_accounts':
            return self.list_accounts(request.get('pattern'))
        elif action == 'send_message':
            return self.send_message(request['sender'], request['recipient'], request['content'])
        elif action == 'read_messages':
            return self.read_messages(request['username'], request.get('sender'))
        elif action == 'delete_messages':
            return self.delete_messages(request['username'], request['other_user'], request['message_ids'])
        elif action == 'delete_account':
            return self.delete_account(request['username'], request['password'])
        elif action == 'get_unread_count':
            return self.get_unread_count(request['username'])
        else:
            return {'status': 'error', 'message': 'Invalid action'}

    def create_account(self, username: str, password: str) -> dict:
        with self.lock:
            if username in self.accounts:
                return {'status': 'error', 'message': 'Username already exists'}
            
            salt = bcrypt.gensalt()
            password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
            
            self.accounts[username] = {
                'password_hash': password_hash
            }
            self.messages[username] = {}
            return {'status': 'success', 'message': 'Account created successfully'}

    def login(self, username: str, password: str, client_socket: socket.socket) -> dict:
        if username not in self.accounts:
            return {'status': 'error', 'message': 'Username not found'}
        
        if not bcrypt.checkpw(password.encode('utf-8'), self.accounts[username]['password_hash']):
            return {'status': 'error', 'message': 'Invalid password'}
        
        with self.lock:
            self.active_sessions[username] = client_socket
            
            # Get all messages involving this user
            all_messages = []
            for user_messages in self.messages.values():
                for msg in user_messages.values():
                    if msg['sender'] == username or msg['recipient'] == username:
                        all_messages.append(msg)
            
            # Sort messages by ID to maintain chronological order
            all_messages.sort(key=lambda x: x['id'])
            
            # Count unread messages (only those received)
            unread_messages = [msg for msg in all_messages 
                             if not msg['read'] and msg['recipient'] == username]
            unread_count = len(unread_messages)
            
            return {
                'status': 'success',
                'message': f'Login successful. You have {unread_count} unread messages.',
                'unread_count': unread_count,
                'messages': all_messages
            }

    def get_unread_count(self, username: str) -> dict:
        if username not in self.accounts:
            return {'status': 'error', 'message': 'User not found'}
            
        with self.lock:
            # Count unread messages where user is recipient
            unread_count = sum(
                1 for msg in self.messages[username].values()
                if msg['recipient'] == username and not msg['read']
            )
            
            return {
                'status': 'success',
                'unread_count': unread_count
            }
            
    def list_accounts(self, pattern: Optional[str] = None) -> dict:
        accounts = list(self.accounts.keys())
        if pattern:
            accounts = [acc for acc in accounts if pattern.lower() in acc.lower()]
        return {'status': 'success', 'accounts': accounts}

    def send_message(self, sender: str, recipient: str, content: str) -> dict:
        if recipient not in self.accounts:
            return {'status': 'error', 'message': 'Recipient not found'}
        
        with self.lock:
            # Get next global message ID
            msg_id = self.next_msg_id
            self.next_msg_id += 1
            
            message = {
                'id': msg_id,
                'sender': sender,
                'recipient': recipient,
                'content': content,
                'timestamp': datetime.now().isoformat(),
                'read': False
            }
            
            # Store message for both sender and recipient
            recipient_msg = message.copy()
            sender_msg = message.copy()
            sender_msg['read'] = True  # Sender's copy is always read
            
            self.messages[recipient][msg_id] = recipient_msg
            self.messages[sender][msg_id] = sender_msg
            
            # If recipient is active, deliver immediately
            if recipient in self.active_sessions:
                try:
                    notification = {
                        'type': 'new_message',
                        'message': message
                    }
                    self.active_sessions[recipient].send(json.dumps(notification).encode('utf-8'))
                except:
                    # Failed delivery
                    pass  
                    
        return {'status': 'success', 'message': 'Message sent', 'message_id': msg_id}

    def read_messages(self, username: str, sender: str = None) -> dict:
        if username not in self.accounts:
            return {'status': 'error', 'message': 'User not found'}
        
        with self.lock:
            # Get relevant messages (between username and sender)
            relevant_messages = []
            if sender:
                for msg in self.messages[username].values():
                    if msg['sender'] == sender or msg['recipient'] == sender:
                        # Mark as read if user is recipient
                        if msg['recipient'] == username:
                            msg['read'] = True
                        relevant_messages.append(msg)
            
            return {
                'status': 'success',
                'messages': relevant_messages
            }

    def delete_messages(self, username: str, other_user: str, message_ids: List[int]) -> dict:
        if username not in self.accounts or other_user not in self.accounts:
            return {'status': 'error', 'message': 'User not found'}
        
        with self.lock:
            # Delete messages from both users' message stores
            for msg_id in message_ids:
                # Delete from both users' messages regardless of sender/recipient
                if msg_id in self.messages[username]:
                    msg = self.messages[username][msg_id]
                    if (msg['sender'] == username and msg['recipient'] == other_user) or \
                       (msg['sender'] == other_user and msg['recipient'] == username):
                        del self.messages[username][msg_id]
                        
                if msg_id in self.messages[other_user]:
                    msg = self.messages[other_user][msg_id]
                    if (msg['sender'] == username and msg['recipient'] == other_user) or \
                       (msg['sender'] == other_user and msg['recipient'] == username):
                        del self.messages[other_user][msg_id]
            
            # Notify other user if they're online
            if other_user in self.active_sessions:
                try:
                    notification = {
                        'type': 'messages_deleted',
                        'deleted_ids': message_ids,
                        'other_user': username  # The other user in the conversation
                    }
                    self.active_sessions[other_user].send(json.dumps(notification).encode('utf-8'))
                except:
                    # Failed notification
                    pass 
                    
            return {'status': 'success', 'message': 'Messages deleted'}

    def delete_account(self, username: str, password: str) -> dict:
        if username not in self.accounts:
            return {'status': 'error', 'message': 'User not found'}
            
        # Verify password
        if not bcrypt.checkpw(password.encode('utf-8'), self.accounts[username]['password_hash']):
            return {'status': 'error', 'message': 'Invalid password'}
        
        with self.lock:
            # Remove user's messages from other users' message stores
            for other_user in list(self.messages.keys()):
                if other_user != username:
                    # Get messages to delete (where user is sender or recipient)
                    to_delete = []
                    for msg_id, msg in self.messages[other_user].items():
                        if msg['sender'] == username or msg['recipient'] == username:
                            to_delete.append(msg_id)
                    
                    # Delete the messages
                    for msg_id in to_delete:
                        del self.messages[other_user][msg_id]
                        
                    # Notify other user if they're online
                    if other_user in self.active_sessions:
                        try:
                            notification = {
                                'type': 'account_deleted',
                                'username': username
                            }
                            self.active_sessions[other_user].send(json.dumps(notification).encode('utf-8'))
                        except:
                            pass
            
            # Delete user's message store
            if username in self.messages:
                del self.messages[username]
            
            # Delete user's account
            del self.accounts[username]
            
            # Remove from active sessions if logged in
            if username in self.active_sessions:
                del self.active_sessions[username]
            
            return {'status': 'success', 'message': 'Account deleted successfully'}
        if not bcrypt.checkpw(password.encode('utf-8'), self.accounts[username]['password_hash']):
            return {'status': 'error', 'message': 'Invalid password'}
        
        with self.lock:
            # Remove from active sessions if logged in
            if username in self.active_sessions:
                del self.active_sessions[username]
            
            # Delete account and all associated messages
            del self.accounts[username]
            return {'status': 'success', 'message': 'Account deleted successfully'}

if __name__ == '__main__':
    server = ChatServer()
    server.start()
