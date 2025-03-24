import json
import os

def load_server_config():
    """Load server configuration from config.json"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # Default configuration
        return {
            "servers": [
                {"id": 0, "host": "127.0.0.1", "port": 65432},
                {"id": 1, "host": "127.0.0.1", "port": 65433},
                {"id": 2, "host": "127.0.0.1", "port": 65434}
            ],
            "database": {
                "type": "file",  # Can be "file" or "mongodb"
                "connection": "server_data"  # Directory for file storage or MongoDB connection string
            }
        }

def save_server_config(config):
    """Save server configuration to config.json"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
