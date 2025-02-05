from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import bcrypt
from datetime import datetime
import re
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from json_protocol.protocol import Protocol, MessageType
import uuid

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# In-memory storage (replace with database in production)
users = {}  # username -> {password_hash, socket_id}
messages = {}  # username -> [messages]
active_sessions = {}  # socket_id -> username

@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in active_sessions:
        username = active_sessions[request.sid]
        if username in users:
            users[username]['socket_id'] = None
        del active_sessions[request.sid]

@socketio.on('message')
def handle_message(json_message):
    message = Protocol.decode(json_message)
    message_type = message.get('type')

    if message_type == MessageType.CREATE_ACCOUNT.value:
        handle_create_account(message)
    elif message_type == MessageType.LOGIN.value:
        handle_login(message)
    elif message_type == MessageType.LIST_ACCOUNTS.value:
        handle_list_accounts(message)
    elif message_type == MessageType.SEND_MESSAGE.value:
        handle_send_message(message)
    elif message_type == MessageType.READ_MESSAGES.value:
        handle_read_messages(message)
    elif message_type == MessageType.DELETE_MESSAGES.value:
        handle_delete_messages(message)
    elif message_type == MessageType.DELETE_ACCOUNT.value:
        handle_delete_account(message)

def handle_create_account(message):
    username = message['username']
    password = message['password']

    if username in users:
        emit('message', Protocol.encode(Protocol.error_response("Username already exists")))
        return

    # Hash the password
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password.encode(), salt).decode()

    users[username] = {
        'password_hash': password_hash,
        'socket_id': request.sid
    }
    messages[username] = []
    active_sessions[request.sid] = username
    
    emit('message', Protocol.encode(Protocol.success_response({
        "message": "Account created successfully",
        "unread_count": 0
    })))

def handle_login(message):
    username = message['username']
    password = message['password']

    if username not in users:
        emit('message', Protocol.encode(Protocol.error_response("User not found")))
        return

    try:
        stored_hash = users[username]['password_hash'].encode()
        if not bcrypt.checkpw(password.encode(), stored_hash):
            emit('message', Protocol.encode(Protocol.error_response("Invalid password")))
            return
    except Exception as e:
        print(f"Error verifying password: {e}")
        emit('message', Protocol.encode(Protocol.error_response("Error verifying password")))
        return

    users[username]['socket_id'] = request.sid
    active_sessions[request.sid] = username
    unread_count = len(messages[username])

    emit('message', Protocol.encode(Protocol.success_response({
        "message": "Login successful",
        "unread_count": unread_count
    })))

def handle_list_accounts(message):
    pattern = message.get('pattern', '')
    page = message.get('page', 1)
    page_size = 10

    filtered_users = []
    if pattern:
        regex = re.compile(pattern.replace('*', '.*'))
        filtered_users = [u for u in users.keys() if regex.match(u)]
    else:
        filtered_users = list(users.keys())

    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    page_users = filtered_users[start_idx:end_idx]
    
    emit('message', Protocol.encode(Protocol.success_response({
        "users": page_users,
        "total": len(filtered_users),
        "page": page,
        "total_pages": (len(filtered_users) + page_size - 1) // page_size
    })))

def handle_send_message(message):
    sender = active_sessions.get(request.sid)
    if not sender:
        emit('message', Protocol.encode(Protocol.error_response("Not logged in")))
        return

    recipient = message['recipient']
    if recipient not in users:
        emit('message', Protocol.encode(Protocol.error_response("Recipient not found")))
        return

    content = message['content']
    timestamp = datetime.now().isoformat()
    message_id = message.get('id', str(uuid.uuid4()))
    
    new_message = {
        "id": message_id,
        "sender": sender,
        "recipient": recipient,
        "content": content,
        "timestamp": timestamp
    }
    
    # Initialize message lists if they don't exist
    if sender not in messages:
        messages[sender] = []
    if recipient not in messages:
        messages[recipient] = []
    
    # Store message in both users' message lists
    messages[sender].append({**new_message, 'is_sent': True})
    messages[recipient].append({**new_message, 'is_sent': False})
    
    # If recipient is online, deliver the message
    recipient_socket = users[recipient]['socket_id']
    if recipient_socket:
        emit('new_message', Protocol.encode({**new_message, 'is_sent': False}), room=recipient_socket)

    emit('message', Protocol.encode(Protocol.success_response({
        "message": "Message sent successfully",
        "message_id": message_id,
        "content": content
    })))

def handle_read_messages(message):
    username = active_sessions.get(request.sid)
    if not username:
        emit('message', Protocol.encode(Protocol.error_response("Not logged in")))
        return

    recipient = message.get('recipient')
    if not recipient:
        emit('message', Protocol.encode(Protocol.error_response("Recipient not specified")))
        return

    # Get messages between these two users
    chat_messages = []
    if username in messages:
        chat_messages.extend([
            msg for msg in messages[username]
            if msg['sender'] == username and msg['recipient'] == recipient
            or msg['sender'] == recipient and msg['recipient'] == username
        ])

    # Sort by timestamp
    chat_messages = sorted(chat_messages, key=lambda x: x['timestamp'])

    emit('message', Protocol.encode(Protocol.success_response({
        'messages': chat_messages
    })))

def handle_delete_messages(message):
    username = active_sessions.get(request.sid)
    if not username:
        emit('message', Protocol.encode(Protocol.error_response("Not logged in")))
        return

    message_ids = set(message['message_ids'])
    
    # Verify the user owns these messages
    for msg_id in message_ids:
        message_exists = False
        for msg in messages[username]:
            if msg['id'] == msg_id and msg['sender'] == username:
                message_exists = True
                break
        if not message_exists:
            emit('message', Protocol.encode(Protocol.error_response("Cannot delete messages you don't own")))
            return

    # Remove the messages
    messages[username] = [msg for msg in messages[username] 
                         if msg['id'] not in message_ids]

    # Send success response with the deleted message ID
    for msg_id in message_ids:
        emit('message', Protocol.encode(Protocol.success_response({
            "message": "Message deleted successfully",
            "deleted_message_id": msg_id
        })))

def handle_delete_account(message):
    username = active_sessions.get(request.sid)
    if not username:
        emit('message', Protocol.encode(Protocol.error_response("Not logged in")))
        return

    # Delete all messages sent to this user
    del messages[username]
    
    # Delete user's account
    del users[username]
    del active_sessions[request.sid]

    emit('message', Protocol.encode(Protocol.success_response({
        "message": "Account deleted successfully"
    })))

from ..config import load_config

if __name__ == '__main__':
    config = load_config('server')
    socketio.run(app, host=config['host'], port=config['port'], debug=True)
