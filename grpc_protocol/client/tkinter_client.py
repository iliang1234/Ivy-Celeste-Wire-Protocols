import sys
import os
import time

# Add parent directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tkinter as tk
from tkinter import ttk, messagebox
import grpc
import queue
import threading
from typing import Dict, List, Optional, Tuple
import argparse
import bcrypt
from datetime import datetime
from protos import chat_pb2
from protos import chat_pb2_grpc

class GRPCClient:
    def __init__(self, host: str = '127.0.0.1', port: int = 65432):
        self.host = host
        self.port = port
        self.channel = None
        self.stub = None
        self.message_queue = queue.Queue()
        self.running = True
        self.connect()
        
    def list_accounts(self, pattern: str = None) -> List[str]:
        try:
            request = chat_pb2.ListAccountsRequest()
            if pattern:
                request.pattern = pattern
            response = self.stub.ListAccounts(request)
            return list(response.accounts)
        except grpc.RpcError as e:
            print(f"Failed to list accounts: {e}")
            return []
            
    def delete_messages(self, username: str, message_ids: List[int]) -> bool:
        try:
            request = chat_pb2.DeleteMessagesRequest(
                username=username,
                message_ids=message_ids
            )
            response = self.stub.DeleteMessages(request)
            return response.success
        except grpc.RpcError as e:
            print(f"Failed to delete messages: {e}")
            return False
            
    def delete_account(self, username: str, password: str) -> bool:
        try:
            request = chat_pb2.DeleteAccountRequest(
                username=username,
                password=password
            )
            response = self.stub.DeleteAccount(request)
            return response.success
        except grpc.RpcError as e:
            print(f"Failed to delete account: {e}")
            return False
            
    def read_messages(self, username: str, sender: str = None) -> List[chat_pb2.ChatMessage]:
        try:
            request = chat_pb2.ReadMessagesRequest(
                username=username
            )
            if sender:
                request.sender = sender
            response = self.stub.ReadMessages(request)
            return list(response.messages)
        except grpc.RpcError as e:
            print(f"Failed to read messages: {e}")
            return []

    def connect(self):
        try:
            # Create channel with keepalive options
            self.channel = grpc.insecure_channel(
                f"{self.host}:{self.port}",
                options=[
                    ('grpc.keepalive_time_ms', 30000),  # Send keepalive ping every 30 seconds
                    ('grpc.keepalive_timeout_ms', 10000),  # Wait 10 seconds for ping ack
                    ('grpc.keepalive_permit_without_calls', False),  # Don't allow keepalive pings without active calls
                    ('grpc.http2.min_time_between_pings_ms', 30000),  # Minimum 30 seconds between pings
                    ('grpc.http2.max_pings_without_data', 2),  # Allow only 2 pings without data
                    ('grpc.max_receive_message_length', 10 * 1024 * 1024),  # 10MB max message size
                ]
            )
            self.stub = chat_pb2_grpc.ChatServiceStub(self.channel)
        except Exception as e:
            print(f"Failed to connect to server: {e}")
            raise

    def close(self):
        self.running = False
        if self.channel:
            self.channel.close()

    def register_user(self, username: str, password: str) -> bool:
        try:
            request = chat_pb2.CreateAccountRequest(
                username=username,
                password=password
            )
            response = self.stub.CreateAccount(request)
            return response.success
        except grpc.RpcError as e:
            print(f"Registration failed: {e}")
            return False

    def login(self, username: str, password: str) -> Tuple[bool, List[chat_pb2.ChatMessage]]:
        try:
            request = chat_pb2.LoginRequest(
                username=username,
                password=password
            )
            response = self.stub.Login(request)
            return response.success, list(response.messages)
        except grpc.RpcError as e:
            print(f"Login failed: {e}")
            return False, []

    def send_message(self, sender: str, receiver: str, content: str) -> bool:
        try:
            print(f"Sending message: sender={sender} (type: {type(sender)}), recipient={receiver} (type: {type(receiver)}), content={content} (type: {type(content)})")
            request = chat_pb2.SendMessageRequest(
                sender=sender,
                recipient=receiver,
                content=content
            )
            response = self.stub.SendMessage(request)
            if not response.success:
                print(f"Server failed to send message: {response.message}")
            return response.success
        except grpc.RpcError as e:
            print(f"Failed to send message: {e}")
            # Try to reconnect if the connection was lost
            self.connect()
            return False
        except Exception as e:
            print(f"Unexpected error sending message: {e}")
            return False

    def start_message_listener(self, username: str):
        def message_listener():
            while self.running:
                try:
                    request = chat_pb2.StreamMessagesRequest(username=username)
                    for message in self.stub.StreamMessages(request):
                        if not self.running:
                            break
                        # Put the message in the queue immediately
                        self.message_queue.put(message)
                except grpc.RpcError as e:
                    if self.running:
                        print(f"Message listener error: {e}")
                        if 'too_many_pings' in str(e).lower():
                            # Increase reconnection delay if we're getting ping errors
                            time.sleep(5)
                        # Reconnect if the connection was lost
                        try:
                            self.connect()
                        except:
                            pass
                        # Wait a bit before retrying
                        time.sleep(1)
                except Exception as e:
                    if self.running:
                        print(f"Unexpected error in message listener: {e}")
                        time.sleep(1)

        thread = threading.Thread(target=message_listener)
        thread.daemon = True
        thread.start()
        return thread

class ChatClient:
    def __init__(self, host: str = '127.0.0.1', port: int = 65432):
        # Initialize gRPC client
        self.grpc_client = GRPCClient(host, port)
        
        # Create the root window
        self.root = tk.Tk()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Store message IDs for deletion: {message_text: (msg_id, sender)}
        self.message_ids: Dict[str, tuple] = {}
        # Store chat histories: {(sender, receiver): [messages]}
        self.chat_histories: Dict[tuple, List] = {}
        self.current_user: Optional[str] = None
        self.message_listener: Optional[threading.Thread] = None
        self.unread_count = 0
        # Initialize message-related variables
        self.messages_per_page = 10
        self.current_msg_page = 1
        
        # Setup GUI
        self.setup_gui()
        
        # Start message checking
        self.check_messages()

    def check_messages(self):
        try:
            while not self.grpc_client.message_queue.empty():
                message = self.grpc_client.message_queue.get_nowait()
                self.process_message(message)
        except queue.Empty:
            pass
        if not self.root.winfo_exists():
            return
        self.root.after(100, self.check_messages)

    def process_message(self, message):
        # Only process messages that involve the current user
        if message.sender != self.current_user and message.recipient != self.current_user:
            return
            
        # Get the other user involved in this message
        other_user = message.sender if message.recipient == self.current_user else message.recipient
        
        # Store message in chat history
        key = tuple(sorted([message.sender, message.recipient]))
        
        # Initialize chat history if it doesn't exist
        if key not in self.chat_histories:
            self.chat_histories[key] = []
            
        # Check if this is a deletion notification
        if not message.content and message.id:
            # Remove the message with this ID from chat history
            self.chat_histories[key] = [msg for msg in self.chat_histories[key] if msg.id != message.id]
            # Force refresh if this chat is open
            current_recipient = self.receiver_entry.get() if hasattr(self, 'receiver_entry') else None
            if current_recipient == other_user:
                self.refresh_messages(force=True)
        else:
            # Check if we have a temporary message with the same content
            temp_msg_index = next((i for i, msg in enumerate(self.chat_histories[key]) 
                                if not msg.id and msg.content == message.content), -1)
            
            if temp_msg_index >= 0:
                # Replace temporary message with real message
                self.chat_histories[key][temp_msg_index] = message
                # If this chat is open and it's a new message, update display
                current_recipient = self.receiver_entry.get() if hasattr(self, 'receiver_entry') else None
                if current_recipient == other_user:
                    self.refresh_messages(force=True)
            else:
                # Add new message if not already there
                msg_exists = any(msg.id == message.id for msg in self.chat_histories[key])
                if not msg_exists:
                    self.chat_histories[key].append(message)
                    # If this chat is open, update display
                    current_recipient = self.receiver_entry.get() if hasattr(self, 'receiver_entry') else None
                    if current_recipient == other_user:
                        # Force a refresh to ensure proper ordering
                        self.refresh_messages(force=True)
                        self.messages_canvas.yview_moveto(1.0)
            
            # Update window title and play sound if we're the recipient
            if message.recipient == self.current_user:
                if message.sender == other_user:  # Only notify if message is from current chat
                    self.root.bell()
                if self.root.state() == 'iconic':
                    self.unread_count += 1
                    self.root.title(f"Chat Client ({self.unread_count} unread)")

    def setup_gui(self):
        self.root.title("Chat Application")
        self.root.geometry("800x600")
        
        # Create main container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Login Frame
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
        
        self.register_button = ttk.Button(self.login_frame, text="Register", command=self.register_user)
        self.register_button.grid(row=2, column=1, padx=5, pady=5)
        
        # Chat Frame (initially hidden)
        self.chat_frame = ttk.LabelFrame(self.main_container, text="Chat")
        
        # Users List
        self.users_frame = ttk.Frame(self.chat_frame)
        self.users_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        ttk.Label(self.users_frame, text="Users:").pack()
        
        # Add search frame
        self.search_frame = ttk.Frame(self.users_frame)
        self.search_frame.pack(fill=tk.X, pady=(0, 5))
        self.search_entry = ttk.Entry(self.search_frame)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.search_button = ttk.Button(self.search_frame, text="Search", command=self.search_users)
        self.search_button.pack(side=tk.RIGHT)
        
        # Create users listbox with fixed height for 5 users
        self.users_listbox = tk.Listbox(self.users_frame, width=20, height=5)
        self.users_listbox.pack(fill=tk.X)
        self.users_listbox.bind('<<ListboxSelect>>', self.on_user_select)
        
        # Add pagination frame
        self.page_frame = ttk.Frame(self.users_frame)
        self.page_frame.pack(fill=tk.X, pady=2)
        
        self.prev_button = ttk.Button(self.page_frame, text="←", width=3, command=self.prev_page)
        self.prev_button.pack(side=tk.LEFT)
        
        self.page_label = ttk.Label(self.page_frame, text="Page 1")
        self.page_label.pack(side=tk.LEFT, expand=True)
        
        self.next_button = ttk.Button(self.page_frame, text="→", width=3, command=self.next_page)
        self.next_button.pack(side=tk.RIGHT)
        
        self.current_page = 1
        self.users_per_page = 5
        self.all_users = []
        
        self.refresh_users_button = ttk.Button(self.users_frame, text="Refresh", command=self.refresh_users)
        self.refresh_users_button.pack(pady=(5, 0))
        
        # Create button frame for logout and delete account
        self.button_frame = ttk.Frame(self.users_frame)
        self.button_frame.pack(fill=tk.X, pady=5)
        
        self.logout_button = ttk.Button(self.button_frame, text="Logout", command=self.logout)
        self.logout_button.pack(side=tk.LEFT, padx=2)
        
        self.delete_account_button = ttk.Button(self.button_frame, text="Delete Account", command=self.delete_account)
        self.delete_account_button.pack(side=tk.RIGHT, padx=2)
        
        # Create right side container
        self.right_container = ttk.Frame(self.chat_frame)
        self.right_container.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Create recipient frame
        self.recipient_frame = ttk.Frame(self.right_container)
        self.recipient_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(self.recipient_frame, text="To:").pack(side=tk.LEFT)
        self.receiver_entry = ttk.Entry(self.recipient_frame)
        self.receiver_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Create message display frame
        self.messages_frame = ttk.Frame(self.right_container)
        self.messages_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(5,0))
        
        # Message controls frame at the top
        self.message_controls = ttk.Frame(self.right_container)
        self.message_controls.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        
        # Messages per page control
        ttk.Label(self.message_controls, text="Messages per page:").pack(side=tk.LEFT, padx=(0, 5))
        self.msg_per_page_var = tk.StringVar(value="10")
        self.msg_per_page_entry = ttk.Entry(self.message_controls, textvariable=self.msg_per_page_var, width=5)
        self.msg_per_page_entry.pack(side=tk.LEFT)
        
        # Add apply button for message count
        self.apply_count_btn = ttk.Button(self.message_controls, text="Apply", 
                                        command=self.update_message_count)
        self.apply_count_btn.pack(side=tk.LEFT, padx=5)
        
        # Navigation buttons
        self.prev_msg_btn = ttk.Button(self.message_controls, text="↑", command=self.prev_messages, width=3)
        self.prev_msg_btn.pack(side=tk.RIGHT, padx=(5, 0))
        self.next_msg_btn = ttk.Button(self.message_controls, text="↓", command=self.next_messages, width=3)
        self.next_msg_btn.pack(side=tk.RIGHT)
        
        # Message page counter
        self.msg_page_var = tk.StringVar(value="Page 1")
        self.msg_page_label = ttk.Label(self.message_controls, textvariable=self.msg_page_var)
        self.msg_page_label.pack(side=tk.RIGHT, padx=10)
        
        # Create messages container with scrollbar
        self.messages_frame = ttk.Frame(self.right_container)
        self.messages_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        
        # Add scrollbar
        self.messages_canvas = tk.Canvas(self.messages_frame)
        self.scrollbar = ttk.Scrollbar(self.messages_frame, orient="vertical", command=self.messages_canvas.yview)
        
        # Configure scrolling
        self.scrollable_frame = ttk.Frame(self.messages_canvas)
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.messages_canvas.configure(scrollregion=self.messages_canvas.bbox("all"))
        )
        
        # Create window in canvas for messages
        self.messages_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw", width=self.messages_canvas.winfo_width())
        self.messages_canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Pack scrollbar and canvas
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.messages_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Handle canvas resize
        def on_canvas_configure(e):
            self.messages_canvas.itemconfig(
                self.messages_canvas.find_withtag("all")[0],
                width=e.width
            )
        
        self.messages_canvas.bind("<Configure>", on_canvas_configure)
        
        # Initialize message pagination variables
        self.current_msg_page = 0
        self.total_msg_pages = 0
        
        # Message Input at bottom
        self.input_frame = ttk.Frame(self.right_container)
        self.input_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)
        
        self.message_entry = ttk.Entry(self.input_frame)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.send_button = ttk.Button(self.input_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)
        
        # Bind enter key to send message
        self.message_entry.bind('<Return>', lambda e: self.send_message())

    def show_chat_page(self):
        self.login_frame.pack_forget()
        self.chat_frame.pack(fill=tk.BOTH, expand=True)
        self.root.title(f"Chat - {self.current_user}")
        self.refresh_users()
        self.refresh_messages()

    def show_login_page(self):
        self.chat_frame.pack_forget()
        self.login_frame.pack(fill=tk.X, pady=5)
        self.root.title("Chat Application")
        
    def search_users(self):
        pattern = self.search_entry.get()
        if pattern:
            self.all_users = self.grpc_client.list_accounts(pattern)
        else:
            self.all_users = self.grpc_client.list_accounts()
        self.current_page = 1
        self.update_user_list()
        
    def refresh_users(self):
        # Get all users except current user
        self.all_users = [u for u in self.grpc_client.list_accounts() if u != self.current_user]
        self.current_page = 1
        self.update_user_list()
        
    def update_user_list(self):
        self.users_listbox.delete(0, tk.END)
        start_idx = (self.current_page - 1) * self.users_per_page
        end_idx = start_idx + self.users_per_page
        page_users = self.all_users[start_idx:end_idx]
        
        for user in page_users:
            self.users_listbox.insert(tk.END, user)
            
        # Update page label
        total_pages = (len(self.all_users) + self.users_per_page - 1) // self.users_per_page
        self.page_label.config(text=f"Page {self.current_page}/{total_pages}")
        
        # Update button states
        self.prev_button.config(state=tk.NORMAL if self.current_page > 1 else tk.DISABLED)
        self.next_button.config(state=tk.NORMAL if self.current_page < total_pages else tk.DISABLED)
        
    def prev_page(self):
        if self.current_page > 1:
            self.current_page -= 1
            self.update_user_list()
            
    def next_page(self):
        total_pages = (len(self.all_users) + self.users_per_page - 1) // self.users_per_page
        if self.current_page < total_pages:
            self.current_page += 1
            self.update_user_list()
            
    def on_user_select(self, event=None):
        if not hasattr(self, 'receiver_entry'):
            return
            
        selection = self.users_listbox.curselection()
        if selection:
            user = self.users_listbox.get(selection[0])
            self.receiver_entry.delete(0, tk.END)
            self.receiver_entry.insert(0, user)
            
            # Clear current messages
            for widget in self.scrollable_frame.winfo_children():
                widget.destroy()
            
            # Load messages between current user and selected user
            messages = self.grpc_client.read_messages(self.current_user, user)
            
            # Store messages in chat history
            key = tuple(sorted([self.current_user, user]))
            
            # Initialize chat history if it doesn't exist
            if key not in self.chat_histories:
                self.chat_histories[key] = []
                
            # Update messages
            self.chat_histories[key] = messages
            
            # Reset unread count when switching to this conversation
            if self.unread_count > 0:
                self.unread_count = 0
                self.root.title("Chat Application")
            
            # Display messages in order
            for msg in sorted(messages, key=lambda x: x.id):
                self.handle_message(msg)
                
            # Scroll to bottom
            self.messages_canvas.yview_moveto(1.0)

    def register_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return
        
        try:
            if self.grpc_client.register_user(username, password):
                messagebox.showinfo("Success", "Registration successful!")
                self.username_entry.delete(0, tk.END)
                self.password_entry.delete(0, tk.END)
            else:
                messagebox.showerror("Error", "Username already exists")
        except Exception as e:
            messagebox.showerror("Error", f"Registration failed: {str(e)}")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return
        
        success, messages = self.grpc_client.login(username, password)
        if success:
            self.current_user = username
            
            # Store initial messages
            for message in messages:
                key = (message.sender, message.recipient)
                reverse_key = (message.recipient, message.sender)
                
                # Initialize chat histories if they don't exist
                if key not in self.chat_histories:
                    self.chat_histories[key] = []
                if reverse_key not in self.chat_histories:
                    self.chat_histories[reverse_key] = []
                    
                # Add message to both perspectives
                if message not in self.chat_histories[key]:
                    self.chat_histories[key].append(message)
                if message not in self.chat_histories[reverse_key]:
                    self.chat_histories[reverse_key].append(message)
            
            # Start message listener
            self.message_listener = self.grpc_client.start_message_listener(username)
            
            # Start polling for new messages
            self.root.after(100, self.check_messages)
            
            self.show_chat_page()
        else:
            messagebox.showerror("Error", "Invalid username or password")
            
    def check_messages(self):
        try:
            while True:
                message = self.grpc_client.message_queue.get_nowait()
                self.process_message(message)
        except queue.Empty:
            pass
        
        # Schedule next check if still logged in
        if self.current_user and self.root.winfo_exists():
            self.root.after(100, self.check_messages)

    def send_message(self, event=None):
        if not self.current_user:
            messagebox.showerror("Error", "Not logged in")
            return
            
        if not hasattr(self, 'receiver_entry') or not hasattr(self, 'message_entry'):
            return
        
        receiver = self.receiver_entry.get()
        content = self.message_entry.get().strip()
        
        if not receiver or not content:
            return
        
        try:
            print(f"Sending message: sender={self.current_user} (type: {type(self.current_user)}), recipient={receiver} (type: {type(receiver)}), content={content} (type: {type(content)})")
            success = self.grpc_client.send_message(self.current_user, receiver, content)
            if success:
                # Clear input field
                self.message_entry.delete(0, tk.END)
                
                # Create a temporary message for immediate display
                temp_msg = chat_pb2.ChatMessage(
                    sender=self.current_user,
                    recipient=receiver,
                    content=content,
                    timestamp=datetime.now().isoformat(),
                    read=False
                )
                
                # Add to chat history and display immediately
                chat_key = tuple(sorted([self.current_user, receiver]))
                if chat_key not in self.chat_histories:
                    self.chat_histories[chat_key] = []
                self.chat_histories[chat_key].append(temp_msg)
                
                # Update display
                self.handle_message(temp_msg)
                self.messages_canvas.yview_moveto(1.0)
            else:
                messagebox.showerror("Error", "Failed to send message")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {str(e)}")

    def update_chat_history(self, sender: str, receiver: str, content: str):
        chat_key = tuple(sorted([sender, receiver]))
        if chat_key not in self.chat_histories:
            self.chat_histories[chat_key] = []
        
        message = f"{sender} -> {receiver}: {content}"
        self.chat_histories[chat_key].append(message)
        
        # Create a new message label in the scrollable frame
        message_frame = ttk.Frame(self.scrollable_frame)
        message_frame.pack(fill=tk.X, padx=5, pady=2)
        
        # Message text
        message_label = ttk.Label(message_frame, text=message, wraplength=400)
        message_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Store message ID for potential deletion
        self.message_ids[message] = (len(self.chat_histories[chat_key]) - 1, sender)
        
        # If message is from current user, add delete button
        if sender == self.current_user:
            delete_btn = ttk.Button(message_frame, text="X", width=2,
                                  command=lambda msg_id=self.message_ids[message][0]: 
                                  self.delete_message(msg_id))
            delete_btn.pack(side=tk.RIGHT)
        
        # Scroll to bottom
        self.messages_canvas.yview_moveto(1.0)

    def update_message_count(self):
        try:
            new_count = int(self.msg_per_page_var.get())
            if new_count > 0:
                self.messages_per_page = new_count
                self.current_msg_page = 1
                self.refresh_messages()
            else:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid positive number")
            self.msg_per_page_var.set(str(self.messages_per_page))
            
    def prev_messages(self):
        if self.current_msg_page > 1:
            self.current_msg_page -= 1
            self.refresh_messages()
            
    def next_messages(self):
        total_pages = self.total_msg_pages
        if self.current_msg_page < total_pages:
            self.current_msg_page += 1
            self.refresh_messages()
            
    def delete_message(self, message):
        try:
            # Send delete request to server
            if not self.grpc_client.delete_messages(self.current_user, [message.id]):
                messagebox.showerror("Error", "Failed to delete message")
                return
                
            # Remove message from chat history
            key = tuple(sorted([message.sender, message.recipient]))
            if key in self.chat_histories:
                self.chat_histories[key] = [msg for msg in self.chat_histories[key] if msg.id != message.id]
                
            # Clear and rebuild the message display
            for widget in self.scrollable_frame.winfo_children():
                widget.destroy()
                
            # Re-display messages for current chat
            current_recipient = self.receiver_entry.get()
            if current_recipient:
                chat_key = tuple(sorted([self.current_user, current_recipient]))
                if chat_key in self.chat_histories:
                    # Display messages in order
                    for msg in sorted(self.chat_histories[chat_key], key=lambda x: x.id):
                        self.handle_message(msg)
                        
            # Force a refresh to ensure both sides update
            self.refresh_messages()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete message: {str(e)}")

    def handle_message(self, message):
        # Create message frame
        message_frame = ttk.Frame(self.scrollable_frame)
        message_frame.pack(fill=tk.X, padx=5, pady=2)
        
        # Message text
        if message.sender == self.current_user:
            message_text = f"You -> {message.recipient}: {message.content}"
            align = tk.RIGHT
        else:
            message_text = f"{message.sender}: {message.content}"
            align = tk.LEFT
            
        message_label = ttk.Label(message_frame, text=message_text, wraplength=400, justify=align)
        message_label.pack(side=align, fill=tk.X, expand=True, padx=5)
        
        # If message is from current user, add delete button
        if message.sender == self.current_user:
            delete_btn = ttk.Button(message_frame, text="×", width=3,
                                command=lambda msg=message: 
                                self.delete_message(msg))
            delete_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Store message ID for potential deletion
        self.message_ids[message_text] = (message.id, message.sender)
        
        # Scroll to bottom
        self.messages_canvas.yview_moveto(1.0)

    def list_users(self):
        users = self.grpc_client.list_accounts()
        if users:
            messagebox.showinfo("Users", "\n".join(users))
        else:
            messagebox.showerror("Error", "Failed to retrieve user list")
    
    def delete_account(self):
        if not self.current_user:
            messagebox.showerror("Error", "Not logged in")
            return
            
        if messagebox.askokcancel("Confirm", "Are you sure you want to delete your account? This cannot be undone."):
            password = self.password_entry.get()
            if self.grpc_client.delete_account(self.current_user, password):
                messagebox.showinfo("Success", "Account deleted successfully")
                self.logout()
            else:
                messagebox.showerror("Error", "Failed to delete account")
    
    def refresh_messages(self, force=False):
        if not self.current_user:
            return
            
        current_recipient = self.receiver_entry.get() if hasattr(self, 'receiver_entry') else None
        if not current_recipient:
            return
            
        # Clear message IDs and scrollable frame
        self.message_ids.clear()
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        
        # Get messages between current user and selected recipient
        if not force:
            # For manual refresh, get from server
            messages = self.grpc_client.read_messages(self.current_user, current_recipient)
            # Update cache
            chat_key = tuple(sorted([self.current_user, current_recipient]))
            self.chat_histories[chat_key] = messages
        
        # Get messages from cache
        chat_key = tuple(sorted([self.current_user, current_recipient]))
        messages = self.chat_histories.get(chat_key, [])
        
        # Sort messages by ID
        messages = sorted(messages, key=lambda x: x.id)
        
        try:
            messages_per_page = int(self.msg_per_page_var.get())
        except ValueError:
            messages_per_page = 10
            self.msg_per_page_var.set(str(messages_per_page))
        
        # Calculate pagination
        total_messages = len(messages)
        self.total_msg_pages = max(1, (total_messages + messages_per_page - 1) // messages_per_page)
        
        if self.current_msg_page > self.total_msg_pages:
            self.current_msg_page = self.total_msg_pages
        if self.current_msg_page < 1:
            self.current_msg_page = 1
        
        # Update page counter
        self.msg_page_var.set(f"Page {self.current_msg_page}/{self.total_msg_pages}")
        
        # Enable/disable navigation buttons
        self.prev_msg_btn.config(state=tk.NORMAL if self.current_msg_page > 1 else tk.DISABLED)
        self.next_msg_btn.config(state=tk.NORMAL if self.current_msg_page < self.total_msg_pages else tk.DISABLED)
        
        # Calculate slice indices
        start_idx = (self.current_msg_page - 1) * messages_per_page
        end_idx = min(start_idx + messages_per_page, total_messages)
        
        # Display messages for current page
        for msg in messages[start_idx:end_idx]:
            self.handle_message(msg)
            
        # Always scroll to bottom after refresh
        self.messages_canvas.yview_moveto(1.0)
    
    def logout(self):
        if messagebox.askokcancel("Confirm", "Are you sure you want to logout?"):
            # Store the current user before clearing it
            username = self.current_user
            self.current_user = None
            
            # Close and recreate gRPC client
            self.grpc_client.close()
            self.grpc_client = GRPCClient()
            
            # Clear messages in scrollable frame if it exists
            if hasattr(self, 'scrollable_frame'):
                for widget in self.scrollable_frame.winfo_children():
                    widget.destroy()
            
            # Clear input fields if they exist
            for field in ['message_entry', 'receiver_entry', 'password_entry', 'username_entry']:
                if hasattr(self, field):
                    widget = getattr(self, field)
                    widget.delete(0, tk.END)
            
            # Reset message pagination
            self.current_msg_page = 1
            self.total_msg_pages = 0
            if hasattr(self, 'msg_page_var'):
                self.msg_page_var.set("Page 1")
            
            # Show login page
            self.show_login_page()

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.grpc_client.close()
            self.root.destroy()

    def run(self):
        try:
            self.root.mainloop()
        finally:
            self.grpc_client.close()
            if self.message_listener:
                self.message_listener.join(timeout=1)

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Start the chat client.")
    parser.add_argument("--host", default=os.getenv("CHAT_SERVER_HOST", "127.0.0.1"),
                      help="Server hostname or IP")
    parser.add_argument("--port", type=int, default=int(os.getenv("CHAT_SERVER_PORT", "65432")),
                      help="Server port")
    args = parser.parse_args()
    
    # Create and run the client
    client = ChatClient(args.host, args.port)
    client.run()
