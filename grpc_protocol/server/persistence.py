import json
import os
import threading
from datetime import datetime
import chat_pb2

class DataPersistence:
    def __init__(self, data_dir="server_data"):
        self.data_dir = data_dir
        self.lock = threading.Lock()
        os.makedirs(data_dir, exist_ok=True)
        
    def _message_to_dict(self, message):
        return {
            'id': message.id,
            'sender': message.sender,
            'recipient': message.recipient,
            'content': message.content,
            'timestamp': message.timestamp,
            'read': message.read
        }
    
    def _dict_to_message(self, data):
        message = chat_pb2.ChatMessage()
        message.id = data['id']
        message.sender = data['sender']
        message.recipient = data['recipient']
        message.content = data['content']
        message.timestamp = data['timestamp']
        message.read = data['read']
        return message
    
    def save_messages(self, messages):
        with self.lock:
            messages_dict = {}
            for username, user_messages in messages.items():
                messages_dict[username] = {
                    str(msg_id): self._message_to_dict(msg)
                    for msg_id, msg in user_messages.items()
                }
            
            with open(os.path.join(self.data_dir, 'messages.json'), 'w') as f:
                json.dump(messages_dict, f)
    
    def load_messages(self):
        try:
            with self.lock:
                with open(os.path.join(self.data_dir, 'messages.json'), 'r') as f:
                    messages_dict = json.load(f)
                
                messages = {}
                for username, user_messages in messages_dict.items():
                    messages[username] = {
                        int(msg_id): self._dict_to_message(msg_data)
                        for msg_id, msg_data in user_messages.items()
                    }
                return messages
        except FileNotFoundError:
            return {}
    
    def save_accounts(self, accounts):
        with self.lock:
            with open(os.path.join(self.data_dir, 'accounts.json'), 'w') as f:
                json.dump(accounts, f)
    
    def load_accounts(self):
        try:
            with self.lock:
                with open(os.path.join(self.data_dir, 'accounts.json'), 'r') as f:
                    return json.load(f)
        except FileNotFoundError:
            return {}
    
    def save_msg_id(self, msg_id):
        with self.lock:
            with open(os.path.join(self.data_dir, 'msg_id.txt'), 'w') as f:
                f.write(str(msg_id))
    
    def load_msg_id(self):
        try:
            with self.lock:
                with open(os.path.join(self.data_dir, 'msg_id.txt'), 'r') as f:
                    return int(f.read().strip())
        except FileNotFoundError:
            return 0
