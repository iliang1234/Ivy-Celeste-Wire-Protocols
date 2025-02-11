import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Dict, List
from protocol import WireProtocol, MessageType
import struct
from datetime import datetime
import errno
import time

class ChatClient:
    def __init__(self, host: str = 'localhost', port: int = 5002):  
        self.host = host
        self.port = port
        self.socket = None
        self.current_user = None
        self.running = True
        self.message_listener = None
        self.received_messages = set()  
        self.chat_histories = {}  
        self.socket_lock = threading.Lock()
        self.setup_gui()
        
    def setup_gui(self):
        self.root = tk.Tk()
        self.root.title("Chat Application")
        self.root.geometry("800x600")
        
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.login_frame = ttk.LabelFrame(self.main_container, text="Login/Register")
        self.login_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(self.login_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = ttk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(self.login_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = ttk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)
        
        self.login_button = ttk.Button(self.login_frame, text="Login", command=self.login)
        self.login_button.grid(row=2, column=0, padx=5, pady=5)
        
        self.register_button = ttk.Button(self.login_frame, text="Register", command=self.register)
        self.register_button.grid(row=2, column=1, padx=5, pady=5)
        
        self.chat_frame = ttk.LabelFrame(self.main_container, text="Chat")
        
        self.users_frame = ttk.Frame(self.chat_frame)
        self.users_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        ttk.Label(self.users_frame, text="Users:").pack()
        
        self.search_frame = ttk.Frame(self.users_frame)
        self.search_frame.pack(fill=tk.X, pady=(0, 5))
        self.search_entry = ttk.Entry(self.search_frame)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.search_button = ttk.Button(self.search_frame, text="Search", command=self.search_users)
        self.search_button.pack(side=tk.RIGHT)
        
        self.users_listbox = tk.Listbox(self.users_frame, width=20)
        self.users_listbox.pack(fill=tk.Y, expand=True)
        self.users_listbox.bind('<<ListboxSelect>>', self.on_user_select)
        
        self.refresh_users_button = ttk.Button(self.users_frame, text="Refresh", command=self.refresh_users)
        self.refresh_users_button.pack(pady=(0, 5))
        
        self.logout_button = ttk.Button(self.users_frame, text="Logout", command=self.logout)
        self.logout_button.pack()
        
        self.right_container = ttk.Frame(self.chat_frame)
        self.right_container.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        self.messages_frame = ttk.Frame(self.right_container)
        self.messages_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.messages_canvas = tk.Canvas(self.messages_frame)
        self.scrollbar = ttk.Scrollbar(self.messages_frame, orient="vertical", command=self.messages_canvas.yview)
        self.scrollable_frame = ttk.Frame(self.messages_canvas)
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.messages_canvas.configure(scrollregion=self.messages_canvas.bbox("all"))
        )
        self.messages_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.messages_canvas.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")
        self.messages_canvas.pack(side="left", fill="both", expand=True)
        
        self.input_frame = ttk.Frame(self.right_container)
        self.input_frame.pack(fill=tk.X, padx=5, pady=5)
        self.message_entry = ttk.Entry(self.input_frame)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.send_button = ttk.Button(self.input_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def connect(self) -> bool:
        """Connect to the server"""
        try:
            if self.socket:
                try:
                    self.socket.close()
                except Exception:
                    pass
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)  # 5 second timeout for connection
            self.socket.connect((self.host, self.port))
            self.socket.settimeout(None)
            return True
        except Exception as e:
            print(f"Failed to connect: {str(e)}")
            messagebox.showerror("Connection Error", f"Failed to connect to server: {str(e)}")
            return False
            
    def send_request(self, data: bytes) -> tuple:
        """Send a request to the server and receive the response"""
        if (not self.socket) or (self.socket.fileno() == -1):
            if not self.connect():
                return MessageType.ERROR, b"Not connected to server", 0
                
        try:
            # Send request and receive response atomically
            with self.socket_lock:
                # Send the request
                self.socket.sendall(data)
                
                # Set timeout for receiving response
                self.socket.settimeout(5)
                
                # Receive header
                header_data = b''
                remaining = 9
                while remaining > 0:
                    chunk = self.socket.recv(remaining)
                    if not chunk:
                        raise ConnectionError("Server closed connection")
                    header_data += chunk
                    remaining -= len(chunk)
                    
                # Parse header
                msg_type, payload_length, num_items = WireProtocol.unpack_header(header_data)
                
                # Receive payload if any
                payload = b''
                if payload_length > 0:
                    remaining = payload_length
                    while remaining > 0:
                        chunk = self.socket.recv(remaining)
                        if not chunk:
                            raise ConnectionError("Server closed connection")
                        payload += chunk
                        remaining -= len(chunk)
                        
                return msg_type, payload, num_items
                
        except Exception as e:
            print(f"Error in send_request: {str(e)}")
            if isinstance(e, (ConnectionError, socket.timeout)):
                self.root.after(0, self.logout)
            return MessageType.ERROR, str(e).encode(), 0
            
        finally:
            # Always reset timeout
            try:
                self.socket.settimeout(None)
            except Exception:
                pass

    def login(self):
        """Handle user login"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
            
        try:
            request = WireProtocol.login_request(username, password)
            msg_type, payload, num_items = self.send_request(request)
            
            if msg_type == MessageType.SUCCESS:
                try:
                    # Parse login response
                    message, offset = WireProtocol.unpack_string(payload)
                    num_messages = struct.unpack('!I', payload[offset:offset + 4])[0]
                    offset += 4
                    
                    # Update client state
                    self.current_user = username
                    self.chat_histories.clear()
                    self.received_messages.clear()
                    
                    # Process initial messages
                    for _ in range(num_messages):
                        try:
                            message_data, new_offset = WireProtocol.unpack_message(payload[offset:])
                            offset += new_offset
                            
                            # Store message in chat history
                            chat_key = tuple(sorted([message_data['sender'], message_data['recipient']]))
                            if chat_key not in self.chat_histories:
                                self.chat_histories[chat_key] = []
                            if message_data['id'] not in self.received_messages:
                                self.chat_histories[chat_key].append(message_data)
                                self.received_messages.add(message_data['id'])
                        except Exception as e:
                            print(f"Error processing message during login: {e}")
                            continue
                            
                    # Switch to chat interface
                    self.login_frame.pack_forget()
                    self.chat_frame.pack(fill=tk.BOTH, expand=True)
                    
                    # Start background tasks
                    self.running = True
                    self.start_message_listener()
                    self.refresh_users()
                    
                    messagebox.showinfo("Success", message)
                    
                except Exception as e:
                    print(f"Error processing login response: {e}")
                    messagebox.showerror("Error", f"Error processing login response: {str(e)}")
                    return
                    
            else:
                message, _ = WireProtocol.unpack_string(payload)
                messagebox.showerror("Error", message)
                
        except Exception as e:
            messagebox.showerror("Error", f"Login failed: {str(e)}")

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        request = WireProtocol.create_account_request(username, password)
        msg_type, payload, _ = self.send_request(request)
        message, _ = WireProtocol.unpack_string(payload)
        if msg_type == MessageType.SUCCESS:
            messagebox.showinfo("Success", "Account created successfully! You can now login.")
        else:
            messagebox.showerror("Error", message)
            
    def show_chat_interface(self):
        self.login_frame.pack_forget()
        self.chat_frame.pack(fill=tk.BOTH, expand=True)
        self.refresh_users()
        self.root.title(f"Chat Application - {self.current_user}")
        
    def refresh_users(self):
        request = WireProtocol.list_accounts_request()
        msg_type, payload, num_accounts = self.send_request(request)
        if msg_type == MessageType.SUCCESS:
            self.users_listbox.delete(0, tk.END)
            offset = 0
            for _ in range(num_accounts):
                username, new_offset = WireProtocol.unpack_string(payload, offset)
                offset = new_offset
                if username != self.current_user:
                    self.users_listbox.insert(tk.END, username)
                    
    def search_users(self):
        search_pattern = self.search_entry.get()
        request = WireProtocol.list_accounts_request(search_pattern)
        msg_type, payload, num_accounts = self.send_request(request)
        if msg_type == MessageType.SUCCESS:
            self.users_listbox.delete(0, tk.END)
            if num_accounts == 0:
                messagebox.showinfo("Search Result", "No users found matching your search.")
            else:
                offset = 0
                for _ in range(num_accounts):
                    username, new_offset = WireProtocol.unpack_string(payload, offset)
                    offset = new_offset
                    if username != self.current_user:
                        self.users_listbox.insert(tk.END, username)
                        
    def send_message(self):
        """Send a message to the selected recipient"""
        if not self.users_listbox.curselection():
            messagebox.showerror("Error", "Please select a recipient")
            return
            
        recipient = self.users_listbox.get(self.users_listbox.curselection())
        content = self.message_entry.get().strip()
        
        if not content:
            return
            
        try:
            request = WireProtocol.send_message_request(self.current_user, recipient, content)
            msg_type, payload, _ = self.send_request(request)
            
            if msg_type == MessageType.SUCCESS:
                self.message_entry.delete(0, tk.END)
                try:
                    # Server sends back the message object in the success response
                    message_data, _ = WireProtocol.unpack_message(payload)
                    self.display_message(message_data)
                    print(f"Message sent successfully to {recipient}")
                except Exception as e:
                    print(f"Error displaying sent message: {e}")
            else:
                message, _ = WireProtocol.unpack_string(payload)
                messagebox.showerror("Error", message)
                
        except Exception as e:
            print(f"Failed to send message: {str(e)}")
            messagebox.showerror("Error", f"Failed to send message: {str(e)}")

    def display_message(self, message_data: dict):
        """Display a message in the chat window"""
        if not isinstance(message_data, dict) or 'id' not in message_data:
            print(f"Invalid message data: {message_data}")
            return
            
        # Skip if we've already processed this message
        if message_data['id'] in self.received_messages:
            return
            
        self.received_messages.add(message_data['id'])
        
        # Store in chat history
        chat_key = tuple(sorted([message_data['sender'], message_data['recipient']]))
        if chat_key not in self.chat_histories:
            self.chat_histories[chat_key] = []
        self.chat_histories[chat_key].append(message_data)
        
        # Only display if this chat is currently selected
        selected_user = None
        if self.users_listbox.curselection():
            selected_user = self.users_listbox.get(self.users_listbox.curselection())
            
        other_party = message_data['recipient'] if message_data['sender'] == self.current_user else message_data['sender']
        if selected_user and selected_user == other_party:
            self._show_message(message_data)

    def _show_message(self, message_data: dict):
        """Internal method to show a message in the chat window"""
        if message_data['sender'] == self.current_user:
            message_text = f"You -> {message_data['recipient']}: {message_data['content']}"
            align = tk.RIGHT
        else:
            message_text = f"{message_data['sender']} -> You: {message_data['content']}"
            align = tk.LEFT
            
        message_frame = ttk.Frame(self.scrollable_frame)
        message_frame.pack(fill=tk.X, padx=5, pady=2)
        
        message_label = ttk.Label(message_frame, text=message_text, wraplength=400, justify=align)
        message_label.pack(side=align, padx=5)
        
        self.messages_canvas.yview_moveto(1.0)

    def on_user_select(self, event):
        """Handle user selection from the list"""
        if not self.users_listbox.curselection():
            return
            
        # Clear the messages area
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
            
        selected_user = self.users_listbox.get(self.users_listbox.curselection())
        chat_key = tuple(sorted([self.current_user, selected_user]))
        
        # Display chat history for selected user
        if chat_key in self.chat_histories:
            messages = sorted(self.chat_histories[chat_key], key=lambda x: x.get('timestamp', 0))
            for message_data in messages:
                self._show_message(message_data)

    def listen_for_messages(self):
        """Listen for incoming messages"""
        while self.running:
            try:
                with self.socket_lock:
                    # Very short timeout just to check if we should keep running
                    self.socket.settimeout(0.05)
                    try:
                        # Peek at the socket to see if there's data
                        self.socket.recv(1, socket.MSG_PEEK)
                    except socket.timeout:
                        continue
                    except Exception as e:
                        raise e
                        
                    # If we get here, there's data to read. Set a longer timeout for reading
                    self.socket.settimeout(1)
                    
                    # Read header
                    header_data = b''
                    remaining = 9
                    while remaining > 0 and self.running:
                        chunk = self.socket.recv(remaining)
                        if not chunk:
                            raise ConnectionError("Server closed connection")
                        header_data += chunk
                        remaining -= len(chunk)
                        
                    # Parse header
                    msg_type, payload_length, num_items = WireProtocol.unpack_header(header_data)
                    
                    # Read payload
                    payload = b''
                    if payload_length > 0:
                        remaining = payload_length
                        while remaining > 0 and self.running:
                            chunk = self.socket.recv(remaining)
                            if not chunk:
                                raise ConnectionError("Server closed connection")
                            payload += chunk
                            remaining -= len(chunk)
                            
                    # Process message
                    if msg_type == MessageType.NEW_MESSAGE_NOTIFICATION:
                        message_data, _ = WireProtocol.unpack_message(payload)
                        self.root.after(0, lambda: self.display_message(message_data))
                        
            except socket.timeout:
                continue
            except ConnectionError as e:
                print(f"Connection error in listener: {e}")
                self.root.after(0, self.logout)
                break
            except Exception as e:
                print(f"Error in message listener: {e}")
                time.sleep(0.1)  # Brief pause before retrying
                continue
            finally:
                try:
                    self.socket.settimeout(None)
                except:
                    pass
                    
        print("Message listener stopped")

    def start_message_listener(self):
        self.message_listener = threading.Thread(target=self.listen_for_messages)
        self.message_listener.daemon = True
        self.message_listener.start()
        
    def logout(self):
        self.running = False
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self.socket.close()
            self.socket = None
        self.current_user = None
        self.chat_frame.pack_forget()
        self.login_frame.pack(fill=tk.X, pady=5)
        self.root.title("Chat Application")
        
    def on_closing(self):
        self.running = False
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self.socket.close()
            self.socket = None
        self.root.destroy()
        
    def run(self):
        self.root.mainloop()

if __name__ == '__main__':
    client = ChatClient()
    client.run()
