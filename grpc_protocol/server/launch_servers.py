import subprocess
import sys
import time
import signal
import os
import argparse
from config import load_server_config, save_server_config

def launch_server(server_config):
    return subprocess.Popen(
        [
            sys.executable, 
            "server.py", 
            "--server-id", str(server_config['id']),
            "--host", server_config['host'],
            "--port", str(server_config['port'])
        ],
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
    parser = argparse.ArgumentParser(description="Launch chat servers.")
    parser.add_argument("--configure", action="store_true", help="Configure server settings")
    parser.add_argument("--server-ids", type=int, nargs="+", help="List of server IDs to launch (e.g., 0 1 2)")
    parser.add_argument("--host", help="Override host for all launched servers")
    args = parser.parse_args()

    if args.configure:
        configure_servers()
        return

    # Load server configuration
    config = load_server_config()
    servers = []
    
    try:
        # Filter servers based on provided server IDs
        server_configs = config['servers']
        if args.server_ids:
            server_configs = [s for s in server_configs if s['id'] in args.server_ids]
            if not server_configs:
                print(f"No servers found with IDs: {args.server_ids}")
                return
        
        # Launch specified servers from config
        for server_config in server_configs:
            # Override host if provided
            if args.host:
                server_config = dict(server_config)  # Make a copy
                server_config['host'] = args.host
            
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