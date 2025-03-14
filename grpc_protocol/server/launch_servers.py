import subprocess
import sys
import time
import signal
import os

def launch_server(port, server_id):
    return subprocess.Popen(
        [sys.executable, "server.py", "--port", str(port), "--server-id", str(server_id)],
        cwd=os.path.dirname(os.path.abspath(__file__))
    )

def main():
    # Launch 3 server instances for 2-fault tolerance
    base_port = 65432
    servers = []
    
    try:
        for i in range(3):
            port = base_port + i
            server = launch_server(port, i)
            servers.append(server)
            print(f"Started server {i} on port {port}")
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
