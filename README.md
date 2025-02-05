# Chat Application with Wire Protocol Implementations

A client-server chat application implemented with both custom wire protocol and JSON implementations for CS 2620.

## Features

- Account creation and authentication
- Real-time messaging between online users
- Message storage for offline users
- Account listing with wildcard pattern support
- Message management (read, delete)
- Account deletion
- Graphical user interface

## Project Structure

```
├── custom_protocol/     # Custom wire protocol implementation
│   ├── client/
│   └── server/
├── json_protocol/       # JSON protocol implementation
│   ├── client/
│   └── server/
├── shared/             # Shared utilities and constants
├── tests/              # Test suite
└── requirements.txt    # Python dependencies
```

## Setup

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Unix/macOS
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

### Custom Protocol Version
1. Start the server:
   ```bash
   source venv/bin/activate && PYTHONPATH=/Users/iliang/Desktop/CS\ 2620/Ivy-Celeste-Wire-Protocols python3 custom_protocol/server/server.py
   ```
2. Start the client:
   ```bash
   source venv/bin/activate && PYTHONPATH=/Users/iliang/Desktop/CS\ 2620/Ivy-Celeste-Wire-Protocols python3 custom_protocol/client/cli_client.py
   ```

### JSON Protocol Version
1. Start the server:
   ```bash
   python json_protocol/server/server.py
   ```
2. Start the client:
   ```bash
   python json_protocol/client/client.py
   ```

## Configuration

Connection settings can be configured either through command-line arguments or a config file (`config.ini`).

## Testing

Run the test suite:
```bash
python -m pytest tests/
```

## Performance Comparison

See `COMPARISON.md` for a detailed analysis of the performance differences between the custom wire protocol and JSON implementations.

## License

MIT License
Design Exercise: Wire Protocols for CS 2620
