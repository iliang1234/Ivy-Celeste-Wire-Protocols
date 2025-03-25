import json
import os

def load_server_config():
    """Load server configuration from config.json"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # Default configuration for 3 servers
        # For 3 servers, we need write quorum of 2 to maintain consistency
        # and read quorum of 2 to ensure we get the latest data
        return {
            "servers": [
                {"id": 0, "host": "10.250.4.227", "port": 65432},
                {"id": 1, "host": "10.250.4.227", "port": 65433},
                {"id": 2, "host": "10.250.4.189", "port": 65434}
            ],
            "quorum": {
                "read": 2,   # Minimum servers needed for a successful read
                "write": 2   # Minimum servers needed for a successful write
            },
            "database": {
                "type": "file",
                "connection": "server_data",
                "sync_interval": 5  # How often to sync state in seconds
            }
        }

def save_server_config(config):
    """Save server configuration to config.json"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
