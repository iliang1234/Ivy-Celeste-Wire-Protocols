# Custom Wire Protocol Chat Application

A simple client-server chat application using a custom binary wire protocol. This application allows users to create accounts, send messages, and communicate in real-time with other users.

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
python3 wire_protocol/server.py --host [host IP address] --port [port number]
```

2. In a new terminal, you may start the client on the local device:
```bash
python3 wire_protocol/tkinter_client.py
```

3. In a new terminal, you may start the client on a different device:
```bash
python3 -OO -X faulthandler tkinter_client.py --host [host IP address] --port [port number]
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

The application uses a custom binary wire protocol for efficient client-server communication. The protocol is structured as follows:

### Message Format

Each message consists of a header followed by a payload:

#### Header (9 bytes total):
- Message Type (1 byte): Indicates the type of operation
- Payload Length (4 bytes): Length of the payload in bytes
- Number of Items (4 bytes): Number of items in payload (for lists/arrays)

#### Data Type Encoding:
- Strings: Prefixed with length (4 bytes) followed by UTF-8 encoded data
- Lists: Prefixed with count (4 bytes)
- Timestamps: 8-byte float (unix timestamp)
- Boolean values: 1 byte (0 or 1)

### Message Types:

1. Account Operations:
   - CREATE_ACCOUNT (1)
   - LOGIN (2)
   - DELETE_ACCOUNT (3)

2. User Operations:
   - LIST_ACCOUNTS (4)

3. Message Operations:
   - SEND_MESSAGE (5)
   - READ_MESSAGES (6)
   - DELETE_MESSAGES (7)

4. Response Types:
   - SUCCESS (8)
   - ERROR (9)

5. Real-time Notifications:
   - NEW_MESSAGE_NOTIFICATION (10)
   - MESSAGE_DELETED_NOTIFICATION (11)
   - ACCOUNT_DELETED_NOTIFICATION (12)

This binary protocol provides efficient data transfer and clear message type distinction while maintaining compatibility across different platforms.

## Running Tests and Protocol Analysis

### Running the Tests
To run the test suite and see the protocol's byte transfer metrics:

```bash
# Wire protocol implementation
cd wire_protocol
python3 -m unittest test_wire_protocol.py -v

### Byte Transfer Metrics
The test suite includes byte transfer tracking for each operation. Here are the typical byte counts for common operations:

1. Basic Account Operations:
   - Registration: 139 bytes
   - Login: 154 bytes
   - List Accounts: 131 bytes

2. Messaging Operations:
   - Send Message: 265 bytes (includes message content)

These metrics help demonstrate the efficiency of our wire protocol implementation compared to the JSON implementation.

## Architecture

- Server (`server.py`)
  - Handles multiple client connections using threading
  - Manages user accounts and message storage
  - Implements the custom binary wire protocol

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