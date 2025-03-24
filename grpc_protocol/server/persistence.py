import json
import os
import threading
from datetime import datetime
import chat_pb2

class DataPersistence:
    def __init__(self, server_id=0, data_dir="server_data"):
        self.server_id = server_id
        self.data_dir = os.path.join(data_dir, f"server_{server_id}")
        self.lock = threading.Lock()
        os.makedirs(self.data_dir, exist_ok=True)
        
    # def _message_to_dict(self, message):
    #     # Handle both dict and ChatMessage objects
    #     if isinstance(message, dict):
    #         return message  # Already a dict, return as is
    #     else:
    #         return {
    #             'id': message.id,
    #             'sender': message.sender,
    #             'recipient': message.recipient,
    #             'content': message.content,
    #             'timestamp': message.timestamp,
    #             'read': message.read
    #         }
    
    # def _dict_to_message(self, data):
    #     message = chat_pb2.ChatMessage()
    #     message.id = data['id']
    #     message.sender = data['sender']
    #     message.recipient = data['recipient']
    #     message.content = data['content']
    #     message.timestamp = data['timestamp']
    #     message.read = data['read']
    #     return message
    

    def save_messages(self, messages):
        """Save messages with atomic file write to prevent corruption"""
        with self.lock:
            messages_dict = {}
            for username, user_msgs in messages.items():
                messages_dict[username] = {}
                for msg_id, msg in user_msgs.items():
                    messages_dict[username][str(msg_id)] = msg

            # Write to temporary file first
            temp_file = os.path.join(self.data_dir, 'messages.json.tmp')
            target_file = os.path.join(self.data_dir, 'messages.json')
            backup_file = os.path.join(self.data_dir, 'messages.json.bak')
            
            try:
                # Write to temp file
                with open(temp_file, 'w') as f:
                    json.dump(messages_dict, f)
                    f.flush()
                    os.fsync(f.fileno())
                
                # Create backup of current file if it exists
                if os.path.exists(target_file):
                    if os.path.exists(backup_file):
                        os.remove(backup_file)
                    os.rename(target_file, backup_file)
                
                # Atomically move temp file to target
                os.rename(temp_file, target_file)
                
                # Success - remove backup
                if os.path.exists(backup_file):
                    os.remove(backup_file)
                    
            except Exception as e:
                print(f"Error saving messages: {e}")
                # Try to restore from backup if save failed
                if os.path.exists(backup_file):
                    if os.path.exists(target_file):
                        os.remove(target_file)
                    os.rename(backup_file, target_file)
                os.fsync(f.fileno())

            os.rename(temp_file, os.path.join(self.data_dir, 'messages.json'))

    
    def load_messages(self):
        try:
            with self.lock:
                with open(os.path.join(self.data_dir, 'messages.json'), 'r') as f:
                    messages_dict = json.load(f)

                messages = {}
                for username, user_messages in messages_dict.items():
                    messages[username] = {}
                    for msg_id_str, msg_data in user_messages.items():
                        msg_id = int(msg_id_str)
                        # msg_data is already a dict with 'sender','recipient','content','timestamp','read'
                        messages[username][msg_id] = msg_data
                return messages
        except FileNotFoundError:
            return {}


    
    def save_accounts(self, accounts):
        with self.lock:
            # First write to temp file
            temp_file = os.path.join(self.data_dir, 'accounts.json.tmp')
            with open(temp_file, 'w') as f:
                json.dump(accounts, f)
                f.flush()
                os.fsync(f.fileno())
            
            # Then atomically rename
            os.rename(temp_file, os.path.join(self.data_dir, 'accounts.json'))
    
    def load_accounts(self):
        try:
            with self.lock:
                with open(os.path.join(self.data_dir, 'accounts.json'), 'r') as f:
                    return json.load(f)
        except FileNotFoundError:
            return {}
    
    def save_msg_id(self, msg_id):
        with self.lock:
            # First write to temp file
            temp_file = os.path.join(self.data_dir, 'msg_id.txt.tmp')
            with open(temp_file, 'w') as f:
                f.write(str(msg_id))
                f.flush()
                os.fsync(f.fileno())
            
            # Then atomically rename
            os.rename(temp_file, os.path.join(self.data_dir, 'msg_id.txt'))
    
    def load_msg_id(self):
        try:
            with self.lock:
                with open(os.path.join(self.data_dir, 'msg_id.txt'), 'r') as f:
                    return int(f.read().strip())
        except FileNotFoundError:
            return 0