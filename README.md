# gRPC Protocol Chat Application

A simple client-server chat application using gRPC as the wire protocol. This application allows users to create accounts, send messages, and communicate in real-time with other users.

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

## Testing
Run the command
```bash
cd grpc_protocol
python -m unittest test_grpc_protocol.py
```