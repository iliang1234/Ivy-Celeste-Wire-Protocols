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

### Single Machine Setup

1. Start servers (3):
```bash
python3 grpc_protocol/server/launch_servers.py
```

2. Start the client:
```bash
python3 grpc_protocol/client/tkinter_client.py
```

### Distributed Setup (Multiple Machines)

1. Find IP addresses of all machines:
```bash
# On Mac:
ifconfig | grep "inet " | grep -v 127.0.0.1

# On Windows:
ipconfig
# Look for IPv4 Address (e.g., 192.168.1.100)
```

2. Edit config.json and config.py to specify host and port numbers for each machine.

3. Start the three servers:
```bash
python3 grpc_protocol/server/launch_servers.py --server-ids 0 1 --host 10.250.4.227
python3 grpc_protocol/server/launch_servers.py --server-ids 2 --host 10.250.214.226
```

4. Start the client:
```bash
python3 grpc_protocol/client/tkinter_client.py
```

### Network Requirements
- All machines must be on the same network
- Ports 65432-65434 must be open in firewalls
- Each machine must be able to ping others using IP addresses
- Use IP addresses instead of hostnames unless DNS resolution is configured

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

### Debugging Testing Errors
TypeError: Couldn't build proto file into descriptor pool: duplicate symbol 'chat.CreateAccountRequest'
   - This error occurs when the protocol buffer files are modified and re-generated.
   - Ensure you are in the grpc_protocol/protos directory.
   - Remove existing chat_pb2.py and chat_pb2_grpc.py files:
      ```bash
      rm -f chat_pb2.py chat_pb2_grpc.py
      ```
   - Recompile the .proto file correctly:
     ```bash
     python -m grpc_tools.protoc -I . --python_out=. --grpc_python_out=. chat.proto
     ```
   - After running the above command, check if the files chat_pb2.py and chat_pb2_grpc.py exist:
     ```bash
     ls -l chat_pb2.py chat_pb2_grpc.py
     ```
   - Rerun tests (cd out of proto directory):
   ```bash
   python -m unittest test_grpc_protocol.py
   ```
     
