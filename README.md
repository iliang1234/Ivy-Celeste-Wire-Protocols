# JSON-Based Chat Application

A real-time chat application built with Python, Flask, and WebSocket technology. This application demonstrates the implementation of a client-server architecture using JSON for message protocols.

## Features

- **Account Management**
  - Create new accounts with username/password
  - Secure password storage using bcrypt hashing
  - Login to existing accounts
  - View unread message count on login

- **Real-time Messaging**
  - Send and receive messages instantly
  - Messages are stored for offline users
  - Blue bubbles for sent messages, white for received
  - Timestamps on all messages
  - Delete your own messages

- **User Interface**
  - Modern, responsive design using Bootstrap
  - Real-time updates without page refresh
  - User list with search functionality
  - Pagination for large user lists
  - Clean, intuitive message bubbles

## Prerequisites

- Python 3.6+
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd Ivy-Celeste-Wire-Protocols
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

## Configuration

The application can be configured using either a config file (`config.ini`) or environment variables.

### Using config.ini

Create a `config.ini` file in the root directory:

```ini
[server]
host = 0.0.0.0
port = 5001

[client]
host = localhost
port = 8000

[websocket]
url = http://localhost:5001
```

### Using Environment Variables

Alternatively, use environment variables to override any config file settings:

```bash
export CHAT_SERVER_HOST=0.0.0.0
export CHAT_SERVER_PORT=5001
export CHAT_CLIENT_HOST=localhost
export CHAT_CLIENT_PORT=8000
export CHAT_WEBSOCKET_URL=http://localhost:5001
```

## Running the Application

1. Start the server:
```bash
python -m json_protocol.server.server
```

2. Start the client application:
```bash
python -m json_protocol.client.app
```

3. Open your web browser and navigate to the client URL (default: http://localhost:8000)

## Project Structure

```
json_protocol/
├── client/
│   ├── static/
│   │   ├── index.html    # Web interface
│   │   ├── script.js     # Client-side logic
│   │   └── style.css     # Styling
│   └── app.py           # Client server
├── server/
│   └── server.py        # Main server application
└── protocol.py          # Protocol definitions
```

## Protocol

The application uses a JSON-based protocol for all communications. Message types include:

- `create_account`: Create a new user account
- `login`: Authenticate existing users
- `list_accounts`: Get list of users
- `send_message`: Send a message to another user
- `read_messages`: Retrieve unread messages
- `delete_messages`: Remove messages
- `delete_account`: Delete user account

## Security Features

- Passwords are hashed using bcrypt before storage
- Users can only delete their own messages
- Server validates all operations
- WebSocket for secure, real-time communication

## Usage

1. **Creating an Account**
   - Enter a username and password
   - Click "Create Account"
   - If the username exists, you'll be prompted to log in instead

2. **Sending Messages**
   - Select a recipient from the user list
   - Type your message in the input box
   - Press Enter or click Send

3. **Deleting Messages**
   - Hover over any message you've sent
   - Click the × button that appears
   - Confirm deletion when prompted

## Error Handling

The application includes comprehensive error handling for:
- Duplicate usernames
- Invalid login credentials
- Network disconnections
- Invalid message operations

## Technical Details

- Configurable server and client ports
- WebSocket-based real-time communication using Flask-SocketIO
- Bootstrap 5.1.3 for responsive design
- In-memory storage for messages and user data
- Configuration via config file or environment variables

## Contributing

Feel free to submit issues and enhancement requests!

## License

[Your chosen license]
