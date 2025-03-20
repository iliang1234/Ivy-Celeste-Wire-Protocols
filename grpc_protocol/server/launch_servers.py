import subprocess
import sys
import time
import signal
import os
from config import load_server_config, save_server_config

def launch_server(server_config):
    return subprocess.Popen(
        [sys.executable, "server.py", "--server-id", str(server_config['id'])],
        cwd=os.path.dirname(os.path.abspath(__file__))
    )

def configure_servers():
    """Configure servers interactively"""
    print("Chat Server Configuration")
    print("=======================")
    
    servers = []
    for i in range(3):
        print(f"\nServer {i} Configuration:")
        host = input(f"Enter hostname for server {i} (default: localhost): ").strip() or 'localhost'
        while True:
            try:
                port = int(input(f"Enter port for server {i} (default: {65432 + i}): ").strip() or (65432 + i))
                break
            except ValueError:
                print("Invalid port number. Please enter a number.")
        
        servers.append({
            "id": i,
            "host": host,
            "port": port
        })
    
    # Update config file
    config = load_server_config()
    config['servers'] = servers
    save_server_config(config)
    print("\nConfiguration saved to config.json")

def main():
    if '--configure' in sys.argv:
        configure_servers()
        return

    # Load server configuration
    config = load_server_config()
    servers = []
    
    try:
        # Launch each server from config
        for server_config in config['servers']:
            server = launch_server(server_config)
            servers.append(server)
            print(f"Started server {server_config['id']} at {server_config['host']}:{server_config['port']}")
            time.sleep(1)  # Give each server time to start
        
        # Wait for keyboard interrupt
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nShutting down servers...")
    finally:
        for server in servers:
            server.send_signal(signal.SIGINT)
            server.wait()

if __name__ == "__main__":
    main()
