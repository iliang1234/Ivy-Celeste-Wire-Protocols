import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import time
import re
from typing import Optional, Tuple
from protocol import WireProtocol, MessageType

class RobustChatClient:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.socket = None
        self.socket_lock = threading.Lock()
        self.connected = False
        self.leader_info = None
        
        # Initialize UI
        self.root = tk.Tk()
        self.root.title("Chat Client")
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Login frame
        login_frame = ttk.LabelFrame(main_frame, text="Account", padding="5")
        login_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(login_frame, text="Username:").grid(row=0, column=0, sticky=tk.W)
        self.username_var = tk.StringVar()
        ttk.Entry(login_frame, textvariable=self.username_var).grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(login_frame, text="Password:").grid(row=1, column=0, sticky=tk.W)
        self.password_var = tk.StringVar()
        ttk.Entry(login_frame, textvariable=self.password_var, show="*").grid(row=1, column=1, sticky=(tk.W, tk.E))
        
        btn_frame = ttk.Frame(login_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=5)
        
        ttk.Button(btn_frame, text="Register", command=self.register).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Login", command=self.login).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Logout", command=self.logout).pack(side=tk.LEFT, padx=5)
        
    def connect(self) -> bool:
        """Connect to the server"""
        # Clean up existing socket
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
            
        try:
            # Create new socket with timeout
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.settimeout(5)
            self.socket.connect((self.host, self.port))
            
            # Send a health check request to test connection
            health_check = WireProtocol.health_check_request()
            self.socket.sendall(health_check)
            
            # Wait for response with longer timeout for initial connection
            try:
                self.socket.settimeout(5)  # Longer timeout for initial connection
                header = self.receive_exact(9)
                if header:
                    msg_type, payload_length, _ = WireProtocol.unpack_header(header)
                    if msg_type == MessageType.ERROR:
                        if payload_length > 0:
                            payload = self.receive_exact(payload_length)
                            if payload:
                                error_msg = payload.decode('utf-8')
                                if "Not leader" in error_msg:
                                    match = re.search(r'Please connect to ([^:]+):([0-9]+)', error_msg)
                                    if match:
                                        new_host, new_port = match.groups()
                                        new_port = int(new_port)
                                        if (new_host, new_port) != (self.host, self.port):
                                            print(f"Redirecting to leader at {new_host}:{new_port}")
                                            self.host = new_host
                                            self.port = new_port
                                            time.sleep(0.5)  # Brief pause before reconnecting
                                            return self.connect()  # Recursively try new leader
                    elif msg_type == MessageType.SUCCESS:
                        if payload_length > 0:
                            self.receive_exact(payload_length)  # Read but ignore payload
                        self.connected = True
                        print(f"Connected to server at {self.host}:{self.port}")
                        return True
                    
            except Exception as e:
                print(f"Error during connection test: {e}")
                
            self.connected = False
            return False
            
        except Exception as e:
            self.connected = False
            print(f"Connection failed to {self.host}:{self.port}: {e}")
            return False
            
    def receive_exact(self, n: int, timeout: int = 5) -> Optional[bytes]:
        """Receive exactly n bytes with timeout"""
        if not self.socket:
            return None
            
        data = bytearray()
        start_time = time.time()
        
        try:
            while len(data) < n:
                # Calculate remaining time and bytes
                remaining_time = timeout - (time.time() - start_time)
                if remaining_time <= 0:
                    print(f"Timeout receiving data after {timeout}s")
                    return None
                
                # Set a shorter timeout for each recv call
                self.socket.settimeout(min(0.5, remaining_time))
                
                try:
                    # Read in smaller chunks
                    remaining_bytes = n - len(data)
                    chunk = self.socket.recv(min(remaining_bytes, 1024))
                    if not chunk:
                        print("Connection closed by server")
                        return None
                    data.extend(chunk)
                except socket.timeout:
                    # Only fail if we've exceeded total timeout
                    if time.time() - start_time > timeout:
                        print("Socket timeout")
                        return None
                    continue
            
            return bytes(data)
            
        except Exception as e:
            print(f"Error receiving data: {e}")
            return None
            
    def send_request(self, data: bytes, max_retries: int = 3) -> Tuple[int, bytes, int]:
        """Send a request to the server and receive the response"""
        retries = 0
        last_error = None
        
        while retries < max_retries:
            # Try to connect if needed
            if not self.connected or not self.socket or self.socket.fileno() == -1:
                if not self.connect():
                    print(f"Connection attempt {retries + 1} failed")
                    time.sleep(1)
                    retries += 1
                    continue
            
            try:
                with self.socket_lock:
                    # Send request with timeout
                    self.socket.settimeout(5)
                    total_sent = 0
                    while total_sent < len(data):
                        try:
                            sent = self.socket.send(data[total_sent:])
                            if sent == 0:
                                raise ConnectionError("Socket connection broken")
                            total_sent += sent
                        except socket.timeout:
                            print("Send timeout, retrying...")
                            continue
                    
                    # Wait briefly for server to process
                    time.sleep(0.1)
                    
                    # Receive header
                    self.socket.settimeout(5)  # Longer timeout for receiving
                    header = self.receive_exact(9)
                    if not header:
                        raise ConnectionError("Failed to receive header")
                    
                    msg_type, payload_length, num_items = WireProtocol.unpack_header(header)
                    
                    # Receive payload if any
                    payload = b''
                    if payload_length > 0:
                        payload = self.receive_exact(payload_length)
                        if not payload:
                            raise ConnectionError("Failed to receive payload")
                    
                    # Handle leader redirection
                    if msg_type == MessageType.ERROR:
                        error_msg = payload.decode('utf-8')
                        if "Not leader" in error_msg:
                            match = re.search(r'Please connect to ([^:]+):([0-9]+)', error_msg)
                            if match:
                                new_host, new_port = match.groups()
                                new_port = int(new_port)
                                
                                # Only redirect if it's different from current connection
                                if (new_host, new_port) != (self.host, self.port):
                                    print(f"Redirecting to leader at {new_host}:{new_port}")
                                    self.host = new_host
                                    self.port = new_port
                                    self.connected = False
                                    try:
                                        self.socket.close()
                                    except:
                                        pass
                                    self.socket = None
                                    retries += 1
                                    time.sleep(0.5)  # Wait before reconnecting
                                    continue
                                    
                    # If we get here, we have a valid response
                    return msg_type, payload, num_items
                    
            except Exception as e:
                print(f"Error in send_request: {e}")
                last_error = e
                self.connected = False
                try:
                    self.socket.close()
                except:
                    pass
                self.socket = None
                retries += 1
                time.sleep(1)  # Wait before retrying
                continue
        
        error_msg = f"Failed after {max_retries} attempts. Last error: {last_error}"
        print(error_msg)
        return MessageType.ERROR, error_msg.encode(), 0
        
    def register(self):
        """Register a new account"""
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
            
        request = WireProtocol.create_account_request(username, password)
        msg_type, payload, _ = self.send_request(request)
        
        if msg_type == MessageType.SUCCESS:
            messagebox.showinfo("Success", "Account created successfully")
        else:
            messagebox.showerror("Error", payload.decode('utf-8'))
            
    def login(self):
        """Login to an existing account"""
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
            
        request = WireProtocol.login_request(username, password)
        msg_type, payload, _ = self.send_request(request)
        
        if msg_type == MessageType.SUCCESS:
            messagebox.showinfo("Success", "Login successful")
        else:
            messagebox.showerror("Error", payload.decode('utf-8'))
            
    def logout(self):
        """Logout from the current session"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        self.connected = False
        messagebox.showinfo("Success", "Logged out successfully")
        
    def run(self):
        """Start the client"""
        self.root.mainloop()

def main():
    # Default to first replica
    client = RobustChatClient("localhost", 65432)
    client.run()

if __name__ == "__main__":
    main()
