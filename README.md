# JSON Wire Protocol Chat Application

A simple client-server chat application using JSON as the wire protocol. This application allows users to create accounts, send messages, and communicate in real-time with other users.

## Features

- Account Management
  - Create new accounts with username/password
  - Secure password storage (bcrypt hashing)
  - Login/Logout functionality
  
- Messaging
  - Real-time message delivery
  - Offline message storage
  - Message history
  
- User Interface
  - Clean Tkinter-based GUI
  - User list with refresh capability
  - Real-time updates

## Prerequisites

- Python 3.x
- pip (Python package installer)

## Installation

1. Create and activate a virtual environment (recommended):
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
.\venv\Scripts\activate
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

## Running the Application

1. Start the server:
```bash
python3 json_protocol/server/server.py --host \[host IP address\] --port \[port number\]
```

2. In a new terminal, you may start the client on the local device:
```bash
python3 json_protocol/client/tkinter_client.py
```

3. In a new terminal, you may start the client on a different device:
```bash
python3 -OO -X faulthandler tkinter_client.py --host \[host IP address\] --port \[port number\]
```

## Usage

1. Creating an Account
   - Launch the client
   - Enter a username and password
   - Click "Register"

2. Logging In
   - Enter your username and password
   - Click "Login"
   - You'll see your unread message count

3. Sending Messages
   - Select a recipient from the user list
   - Type your message in the text box
   - Press Enter or click "Send"

4. Other Features
   - Click "Refresh" to update the user list
   - Click "Logout" to sign out
   - Messages are stored when recipients are offline

## Protocol Specification

The application uses JSON for all client-server communication. Message formats:

1. Account Creation:
```json
{
    "action": "create_account",
    "username": "string",
    "password": "string"
}
```

2. Login:
```json
{
    "action": "login",
    "username": "string",
    "password": "string"
}
```

3. Messaging:
```json
{
    "action": "send_message",
    "sender": "string",
    "recipient": "string",
    "content": "string"
}
```

## Architecture

- Server (`server.py`)
  - Handles multiple client connections using threading
  - Manages user accounts and message storage
  - Implements the JSON wire protocol

- Client (`tkinter_client.py`)
  - Provides GUI using Tkinter
  - Handles real-time message updates
  - Implements the client-side protocol

## Security Features

- Passwords are hashed using bcrypt
- Messages are stored securely on the server
- No plaintext password transmission

## Troubleshooting

1. Port Already in Use
   - The server uses port 5001 by default
   - If the port is in use, modify the port number in both server.py and tkinter_client.py

2. Connection Issues
   - Ensure the server is running before starting clients
   - Check that the host and port match in both server and client

3. Tkinter Issues
   - On macOS, ensure you have python-tk installed:
     ```bash
     brew install python-tk@3.13
     ```
