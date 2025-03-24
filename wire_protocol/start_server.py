import argparse
import os
from replicated_server import ReplicatedChatServer

def main():
    parser = argparse.ArgumentParser(description="Start a replicated chat server")
    parser.add_argument("--node-id", type=int, required=True, help="Node ID of this server instance")
    parser.add_argument("--config", default="replica_config.json", help="Path to replica configuration file")
    args = parser.parse_args()
    
    # Get the absolute path of the script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Resolve config path relative to script directory
    config_path = os.path.join(script_dir, args.config)
    
    # Clean up any stale socket files
    import glob
    for sock_file in glob.glob(os.path.join(script_dir, "*.sock")):
        try:
            os.remove(sock_file)
        except:
            pass
    
    # Ensure data directory exists
    data_dir = os.path.join(script_dir, "data")
    os.makedirs(data_dir, exist_ok=True)
    
    # Ensure node data directory exists
    node_data_dir = os.path.join(data_dir, f"replica_{args.node_id}")
    os.makedirs(node_data_dir, exist_ok=True)
    
    # Start server
    server = None
    try:
        server = ReplicatedChatServer(config_path, args.node_id)
        print(f"Server node {args.node_id} started successfully")
        
        # Keep main thread alive
        import signal
        def signal_handler(sig, frame):
            print("\nShutting down server...")
            if server:
                server.shutdown()
            import sys
            sys.exit(0)
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.pause()
        
    except Exception as e:
        print(f"Error starting server: {e}")
        if server:
            server.shutdown()
        raise

if __name__ == "__main__":
    main()
