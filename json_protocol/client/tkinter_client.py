import json
import socket
import threading
import tkinter as tk
import argparse
from tkinter import ttk, messagebox, simpledialog
from typing import Optional, Callable

class ChatClient:
    def __init__(self, host: str = 'localhost', port: int = 5001):
        # Dictionary to store message IDs for deletion: {message_text: (msg_id, sender)}
        self.message_ids = {}
        # Dictionary to store chat histories: {(sender, receiver): [messages]}
        self.chat_histories = {}
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        self.current_user: Optional[str] = None
        self.message_listener: Optional[threading.Thread] = None
        self.running = True
        self.unread_count = 0
        
        self.setup_gui()
        
    def setup_gui(self):
        self.root = tk.Tk()
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
        
        self.register_button = ttk.Button(self.login_frame, text="Register", command=self.register)
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
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def connect(self) -> bool:
        try:
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            # Set initial timeout for notification listener
            self.socket.settimeout(1.0)
            return True
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect to server: {str(e)}")
            return False
            
    def send_request(self, request: dict) -> dict:
        if not self.socket:
            if not self.connect():
                return {'status': 'error', 'message': 'Not connected to server'}
                
        try:
            # Set timeout for operations
            self.socket.settimeout(5.0)  # 5 second timeout
            
            # Send request
            data = json.dumps(request).encode('utf-8')
            self.socket.sendall(data)
            
            # Get response
            response_data = b''
            
            while True:
                chunk = self.socket.recv(4096)
                if not chunk:
                    raise ConnectionError("Server closed connection")
                response_data += chunk
                
                try:
                    # Try to decode and parse the accumulated data
                    data = json.loads(response_data.decode('utf-8'))
                    
                    # Handle notifications by passing to notification handler
                    if isinstance(data, dict):
                        if 'type' in data:
                            # This is a notification, process it and continue reading
                            self.root.after(0, lambda: self.handle_notification(data))
                            response_data = b''
                            continue
                        elif 'status' in data:
                            # This is the response we're waiting for
                            return data
                        
                except json.JSONDecodeError:
                    # Incomplete JSON, keep reading
                    continue
                except socket.timeout:
                    # If we've received some data but timed out, try to parse what we have
                    if response_data:
                        try:
                            data = json.loads(response_data.decode('utf-8'))
                            if isinstance(data, dict) and 'type' in data:
                                notification = data
                            else:
                                response = data
                            break
                        except json.JSONDecodeError:
                            pass
                    return {'status': 'error', 'message': 'Server response timed out'}
            
            # If we got a notification, handle it
            if notification:
                self.root.after(0, lambda: self.handle_notification(notification))
            
            if response is None:
                return {'status': 'error', 'message': 'No response received'}
                
            return response
        except ConnectionError:
            return {'status': 'error', 'message': 'Connection lost'}
        except Exception as e:
            return {'status': 'error', 'message': f'Communication error: {str(e)}'}
        finally:
            # Reset timeout for notification listener
            if self.socket:
                self.socket.settimeout(1.0)
            
    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
            
        # Clear any existing connection
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
            
        # Clear any existing message listener
        if self.message_listener:
            self.running = False
            self.message_listener.join()
            self.message_listener = None
            
        # Ensure we have a fresh connection
        if not self.connect():
            return
            
        response = self.send_request({
            'action': 'login',
            'username': username,
            'password': password
        })
        
        if response['status'] == 'success':
            self.current_user = username
            self.chat_histories.clear()  # Clear any old chat histories
            self.unread_count = response.get('unread_count', 0)
            self.show_chat_interface()
            self.start_message_listener()
            # Update title immediately with unread count
            self.update_title()
        else:
            messagebox.showerror("Error", response['message'])
            
    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
            
        response = self.send_request({
            'action': 'create_account',
            'username': username,
            'password': password
        })
        
        if response['status'] == 'success':
            messagebox.showinfo("Success", "Account created successfully! You can now login.")
        else:
            messagebox.showerror("Error", response['message'])
            
    def show_chat_interface(self):
        # Clear any existing chat data
        self.chat_histories.clear()
        self.all_users.clear()
        self.current_msg_page = 0
        
        # Clear message display
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
            
        # Clear user list
        self.users_listbox.delete(0, tk.END)
        
        self.login_frame.pack_forget()
        self.chat_frame.pack(fill=tk.BOTH, expand=True)
        
        # Get all messages for this user
        response = self.send_request({
            'action': 'get_messages',
            'username': self.current_user
        })
        
        if response.get('status') == 'success' and response.get('messages'):
            # Sort messages by timestamp
            messages = sorted(response['messages'], key=lambda x: x.get('timestamp', ''))
            
            for msg in messages:
                # Skip messages without required fields
                if not all(key in msg for key in ['id', 'sender', 'recipient', 'content']):
                    print(f"Message missing required fields: {msg}")
                    continue
                    
                chat_key = tuple(sorted([msg['sender'], msg['recipient']]))
                if chat_key not in self.chat_histories:
                    self.chat_histories[chat_key] = []
                    
                # Format message text
                sender = msg['sender']
                content = msg['content']
                if sender == self.current_user:
                    msg_text = f"You -> {msg['recipient']}: {content}"
                else:
                    msg_text = f"{sender}: {content}"
                    
                # Only add message if we don't already have it
                if not any(mid == msg['id'] for _, mid, _ in self.chat_histories[chat_key]):
                    self.chat_histories[chat_key].append((msg_text, msg['id'], sender))
        
        self.refresh_users()
        self.update_title()
        
    def refresh_users(self):
        try:
            response = self.send_request({
                'action': 'list_accounts',
                'pattern': None
            })
            
            if not isinstance(response, dict):
                print(f"Invalid response format: {response}")
                return
                
            if response.get('status') == 'success':
                accounts = response.get('accounts', [])
                if not isinstance(accounts, list):
                    print(f"Invalid accounts format: {accounts}")
                    return
                    
                self.all_users = [user for user in accounts if user != self.current_user]
                self.current_page = 1
                self.update_user_list()
            else:
                print(f"Failed to refresh users: {response.get('message', 'Unknown error')}")
        except Exception as e:
            print(f"Error refreshing users: {str(e)}")
                    
    def search_users(self):
        search_pattern = self.search_entry.get()
        response = self.send_request({
            'action': 'list_accounts',
            'pattern': search_pattern
        })
        
        if response['status'] == 'success':
            self.all_users = [user for user in response['accounts'] if user != self.current_user]
            
            if not self.all_users:
                messagebox.showinfo("Search Result", "No users found matching your search.")
            
            self.current_page = 1
            self.update_user_list()
                    
    def update_message_count(self):
        if self.users_listbox.curselection():
            selected_user = self.users_listbox.get(self.users_listbox.curselection())
            chat_key = tuple(sorted([self.current_user, selected_user]))
            self.current_msg_page = 0  # Reset to first page
            self.update_message_display(chat_key)
    
    def send_message(self):
        if not self.users_listbox.curselection():
            messagebox.showerror("Error", "Please select a recipient")
            return
            
        recipient = self.users_listbox.get(self.users_listbox.curselection())
        content = self.message_entry.get().strip()
        
        if not content:
            return
            
        try:
            # Save content and clear input field
            msg_content = content
            self.message_entry.delete(0, tk.END)
            
            # Send the message
            response = self.send_request({
                'action': 'send_message',
                'sender': self.current_user,
                'recipient': recipient,
                'content': msg_content
            })
            
            if response['status'] == 'success':
                msg_text = f"You -> {recipient}: {msg_content}"
                self.display_message(msg_text, self.current_user, recipient, response.get('message_id'))
            else:
                # If failed, restore the message
                self.message_entry.insert(0, msg_content)
                messagebox.showerror("Error", response['message'])
        except ConnectionError as e:
            # If failed, restore the message
            self.message_entry.insert(0, msg_content)
            messagebox.showerror("Connection Error", str(e))
        except Exception as e:
            # If failed, restore the message
            self.message_entry.insert(0, msg_content)
            messagebox.showerror("Error", f"Failed to send message: {str(e)}")
            
    def display_message(self, message: str, sender: str, receiver: str, msg_id: int = None):
        try:
            # Store message in chat history
            chat_key = tuple(sorted([sender, receiver]))
            if chat_key not in self.chat_histories:
                self.chat_histories[chat_key] = []
            self.chat_histories[chat_key].append((message, msg_id, sender))
            
            # Only display if this conversation is currently selected
            if self.users_listbox.curselection():
                selected_user = self.users_listbox.get(self.users_listbox.curselection())
                current_chat_key = tuple(sorted([self.current_user, selected_user]))
                if chat_key == current_chat_key:
                    try:
                        msgs_per_page = max(1, int(self.msg_per_page_var.get()))
                    except ValueError:
                        msgs_per_page = 10
                        self.msg_per_page_var.set(str(msgs_per_page))
                    
                    total_msgs = len(self.chat_histories[chat_key])
                    last_page = (total_msgs - 1) // msgs_per_page
                    
                    # For new messages, always show the last page
                    if sender == self.current_user:
                        self.current_msg_page = last_page
                        self.update_message_display(chat_key)
                        # Force scroll to bottom after a short delay to ensure message is rendered
                        self.root.after(50, lambda: self.messages_canvas.yview_moveto(1.0))
                    # For received messages, only update if we're on the last page
                    elif self.current_msg_page == last_page:
                        self.update_message_display(chat_key)
                        self.root.after(50, lambda: self.messages_canvas.yview_moveto(1.0))
        except Exception as e:
            print(f"Error displaying message: {str(e)}")
                
    def on_user_select(self, event=None):
        if not self.users_listbox.curselection():
            return
            
        selected_user = self.users_listbox.get(self.users_listbox.curselection())
        chat_key = tuple(sorted([self.current_user, selected_user]))
        
        try:
            # Mark messages from this user as read and get chat history
            response = self.send_request({
                'action': 'read_messages',
                'username': self.current_user,
                'sender': selected_user
            })
            
            if response and response.get('status') == 'success':
                # Update chat history with messages
                if chat_key not in self.chat_histories:
                    self.chat_histories[chat_key] = []
                
                # Process new messages
                for msg in response.get('messages', []):
                    message_text = f"{msg['sender']}: {msg['content']}"
                    if msg['sender'] == self.current_user:
                        message_text = f"You -> {msg['recipient']}: {msg['content']}"
                    
                    # Add message if not already in history
                    msg_exists = any(mid == msg['id'] for _, mid, _ in self.chat_histories[chat_key])
                    if not msg_exists:
                        self.chat_histories[chat_key].append((message_text, msg['id'], msg['sender']))
                
                # Update unread count
                self.get_unread_count()
                
                # Reset to first page and update display
                self.current_msg_page = 0
                self.update_message_display(chat_key)
            
        except Exception as e:
            print(f"Error in on_user_select: {str(e)}")
            # Clear display on error
            for widget in self.scrollable_frame.winfo_children():
                widget.destroy()
        
    def update_message_display(self, chat_key):
        # Clear current display
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        
        if chat_key in self.chat_histories:
            # Get all messages and sort by ID and timestamp
            sorted_messages = sorted(self.chat_histories[chat_key], key=lambda x: (x[1] if x[1] is not None else float('inf')))
            
            try:
                msgs_per_page = max(1, int(self.msg_per_page_var.get()))
            except ValueError:
                msgs_per_page = 10
                self.msg_per_page_var.set(str(msgs_per_page))
            
            # Calculate total pages
            self.total_msg_pages = (len(sorted_messages) + msgs_per_page - 1) // msgs_per_page
            
            # Ensure current page is valid
            self.current_msg_page = min(max(0, self.current_msg_page), max(0, self.total_msg_pages - 1))
            
            # Calculate slice indices
            start_idx = self.current_msg_page * msgs_per_page
            end_idx = start_idx + msgs_per_page
            
            # Display messages for current page
            for message, msg_id, sender in sorted_messages[start_idx:end_idx]:
                self.add_message_to_display(message, msg_id, sender)
            
            # Update page counter
            if self.total_msg_pages > 0:
                self.msg_page_var.set(f"Page {self.current_msg_page + 1} of {self.total_msg_pages}")
            else:
                self.msg_page_var.set("No messages")
            
            # Update navigation buttons
            self.prev_msg_btn["state"] = "normal" if self.current_msg_page > 0 else "disabled"
            self.next_msg_btn["state"] = "normal" if self.current_msg_page < self.total_msg_pages - 1 else "disabled"
            
            # If this is the last page, scroll to bottom
            if self.current_msg_page == self.total_msg_pages - 1:
                self.scrollable_frame.update_idletasks()
                self.messages_canvas.yview_moveto(1.0)
    
    def prev_messages(self):
        if self.current_msg_page > 0:
            self.current_msg_page -= 1
            if self.users_listbox.curselection():
                selected_user = self.users_listbox.get(self.users_listbox.curselection())
                chat_key = tuple(sorted([self.current_user, selected_user]))
                self.update_message_display(chat_key)
    
    def next_messages(self):
        if self.current_msg_page < self.total_msg_pages - 1:
            self.current_msg_page += 1
            if self.users_listbox.curselection():
                selected_user = self.users_listbox.get(self.users_listbox.curselection())
                chat_key = tuple(sorted([self.current_user, selected_user]))
                self.update_message_display(chat_key)
    
    def add_message_to_display(self, message: str, msg_id: int, sender: str):
        # Create a frame for the message
        msg_frame = ttk.Frame(self.scrollable_frame)
        msg_frame.pack(fill=tk.X, padx=5, pady=2)
        
        # Create message content frame
        content_frame = ttk.Frame(msg_frame)
        if sender == self.current_user:
            content_frame.pack(side=tk.RIGHT)
        else:
            content_frame.pack(side=tk.LEFT)
        
        # Add message text
        msg_label = ttk.Label(content_frame, text=message, wraplength=350)
        msg_label.pack(side=tk.LEFT)
        
        # Store message ID with unique key (message ID + content)
        msg_key = f"{msg_id}_{message}" if msg_id is not None else message
        self.message_ids[msg_key] = (msg_id, sender)
        
        # Add delete button if message is from current user
        if sender == self.current_user and msg_id is not None:
            delete_button = ttk.Button(
                content_frame,
                text="Delete",
                command=lambda mid=msg_id: self.delete_message(mid)
            )
            delete_button.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Update scrollable frame to show latest messages
        self.scrollable_frame.update_idletasks()
            
    def delete_message(self, msg_id: int):
        if not self.users_listbox.curselection():
            return
            
        selected_user = self.users_listbox.get(self.users_listbox.curselection())
        
        # Send delete request to server
        response = self.send_request({
            'action': 'delete_messages',
            'username': self.current_user,
            'other_user': selected_user,
            'message_ids': [msg_id]
        })
        
        if response['status'] == 'success':
            # Remove message from chat history
            chat_key = tuple(sorted([self.current_user, selected_user]))
            if chat_key in self.chat_histories:
                # Only remove the specific message with this ID
                self.chat_histories[chat_key] = [
                    (msg, mid, sndr) for msg, mid, sndr in self.chat_histories[chat_key]
                    if mid != msg_id
                ]
                
                # Clean up message_ids dictionary
                keys_to_remove = [k for k, v in self.message_ids.items() 
                                if v[0] == msg_id]
                for k in keys_to_remove:
                    del self.message_ids[k]
                
                # Update the display while maintaining scroll position
                self.update_message_display(chat_key)
        else:
            messagebox.showerror("Error", response['message'])
    
    def start_message_listener(self):
        # Stop any existing listener
        if self.message_listener:
            self.running = False
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
            self.message_listener.join()
            self.message_listener = None
            self.socket = None
        
        # Reset state
        self.running = True
        
        def listen_for_messages():
            while self.running and self.socket:
                try:
                    # Set a timeout to allow checking running state
                    self.socket.settimeout(1.0)
                    try:
                        data = self.socket.recv(4096).decode('utf-8')
                        if not data:
                            if self.running:
                                # Connection closed by server
                                print("Server closed connection")
                            break
                            
                        try:
                            notification = json.loads(data)
                            if not isinstance(notification, dict):
                                print(f"Invalid notification format: {data}")
                                continue
                                
                            # Use root.after to handle GUI updates in main thread
                            self.root.after(0, lambda n=notification: self.handle_notification(n))
                        except json.JSONDecodeError:
                            print(f"Invalid JSON received: {data}")
                    except socket.timeout:
                        # This is normal, just continue the loop
                        continue
                    except ConnectionError:
                        if self.running:
                            print("Connection lost")
                        break
                except Exception as e:
                    if self.running:
                        print(f"Error in message listener: {str(e)}")
                    break
            
            if self.running:
                # Only try to reconnect if we didn't intentionally stop
                print("Message listener stopped, attempting to reconnect...")
                self.root.after(5000, self.reconnect)
                    
        self.message_listener = threading.Thread(target=listen_for_messages)
        self.message_listener.daemon = True
        self.message_listener.start()
        print("Message listener started")
        
    def reconnect(self):
        """Attempt to reconnect to the server"""
        if not self.running:
            return
            
        try:
            if self.socket:
                self.socket.close()
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            
            # Re-login with stored credentials
            if self.current_user:
                response = self.send_request({
                    'action': 'login',
                    'username': self.current_user,
                    'password': self.password_entry.get()
                })
                
                if response['status'] == 'success':
                    print("Reconnected and logged back in")
                    self.start_message_listener()
                else:
                    print("Failed to log back in after reconnect")
                    self.logout()
        except Exception as e:
            print(f"Reconnection failed: {str(e)}")
            # Try again in 5 seconds
            self.root.after(5000, self.reconnect)
        
    def handle_notification(self, notification):
        """Handle incoming notifications in the main thread"""
        try:
            if not isinstance(notification, dict):
                print(f"Invalid notification format: {notification}")
                return
                
            # If this is a response with messages, process them
            if 'status' in notification and notification.get('status') == 'success':
                if 'messages' in notification:
                    for msg in notification['messages']:
                        self.process_message(msg)
                return
                
            notification_type = notification.get('type')
            if not notification_type:
                # Try to infer type from content
                if any(key in notification for key in ['sender', 'recipient', 'content']):
                    self.process_message(notification)
                    return
                else:
                    print(f"Notification missing type: {notification}")
                    return
                    
            if notification_type == 'new_message':
                message = notification.get('message')
                if message:
                    self.process_message(message)
            elif notification_type == 'messages_deleted':
                deleted_ids = notification.get('deleted_ids', [])
                other_user = notification.get('other_user')
                if deleted_ids and other_user:
                    chat_key = tuple(sorted([self.current_user, other_user]))
                    if chat_key in self.chat_histories:
                        # Remove deleted messages from chat history
                        self.chat_histories[chat_key] = [
                            (msg, mid, sndr) for msg, mid, sndr in self.chat_histories[chat_key]
                            if mid not in deleted_ids
                        ]
                        # Update display if this chat is selected
                        if self.users_listbox.curselection():
                            selected_user = self.users_listbox.get(self.users_listbox.curselection())
                            if selected_user == other_user:
                                self.update_message_display(chat_key)
        except Exception as e:
            print(f"Error handling notification: {e}")
                    
    def process_message(self, message):
        try:
            """Process a single message and add it to chat history"""
            # Handle message deletion notifications
            if isinstance(message, dict) and message.get('type') in ['message_deleted', 'messages_deleted']:
                # Handle both singular and plural forms
                msg_ids = []
                
                # Try all possible field names for message IDs
                if 'message_ids' in message:
                    msg_ids = message['message_ids']
                elif 'deleted_ids' in message:
                    msg_ids = message['deleted_ids']
                elif 'message_id' in message:
                    msg_ids = [message['message_id']]
                
                # Convert all IDs to integers
                msg_ids = [int(mid) for mid in msg_ids if mid is not None]
                
                other_user = message.get('other_user')
                if not other_user:
                    other_user = message.get('from_user')  # Try alternate key
                
                if msg_ids and other_user:
                    # Remove from chat history
                    chat_key = tuple(sorted([self.current_user, other_user]))
                    if chat_key in self.chat_histories:
                        before_count = len(self.chat_histories[chat_key])
                        self.chat_histories[chat_key] = [
                            msg for msg in self.chat_histories[chat_key]
                            if msg[1] not in msg_ids
                        ]
                        after_count = len(self.chat_histories[chat_key])
                        
                        if before_count != after_count:
                            # Update display if this chat is currently open
                            if self.users_listbox.curselection():
                                selected_user = self.users_listbox.get(self.users_listbox.curselection())
                                if selected_user == other_user:
                                    self.update_message_display(chat_key)
                return
            
            # Handle regular messages
            if not all(key in message for key in ['id', 'sender', 'recipient', 'content']):
                print(f"Message missing required fields: {message}")
                return
                
            chat_key = tuple(sorted([message['sender'], message['recipient']]))
            if chat_key not in self.chat_histories:
                self.chat_histories[chat_key] = []
                
            # Format message text
            sender = message['sender']
            content = message['content']
            if sender == self.current_user:
                msg_text = f"You -> {message['recipient']}: {content}"
            else:
                msg_text = f"{sender}: {content}"
                
            # Add to chat history if not already there
            msg_exists = any(mid == message['id'] for _, mid, _ in self.chat_histories[chat_key])
            if not msg_exists:
                self.chat_histories[chat_key].append((msg_text, message['id'], sender))
                
                # Only update display if this chat is currently selected
                if self.users_listbox.curselection():
                    selected_user = self.users_listbox.get(self.users_listbox.curselection())
                    if selected_user in chat_key:
                        self.update_message_display(chat_key)
                
                # Increment unread count if we're the recipient and message is unread
                if message.get('recipient') == self.current_user and not message.get('read', True):
                    self.unread_count += 1
                    self.update_title()

                    
                elif notification_type == 'account_deleted':
                    deleted_user = notification.get('username')
                    if not deleted_user:
                        print(f"Account deletion notification missing username: {notification}")
                        return
                        
                    # Remove from users list
                    for i in range(self.users_listbox.size()):
                        if self.users_listbox.get(i) == deleted_user:
                            self.users_listbox.delete(i)
                            break
                    # Clear chat if viewing deleted user
                    if self.users_listbox.curselection():
                        selected_user = self.users_listbox.get(self.users_listbox.curselection())
                        if selected_user == deleted_user:
                            for widget in self.scrollable_frame.winfo_children():
                                widget.destroy()
                    # Remove from all_users list
                    if deleted_user in self.all_users:
                        self.all_users.remove(deleted_user)
                        self.update_user_list()
                else:
                    print(f"Unknown notification type: {notification_type}")
        except Exception as e:
            print(f"Error handling notification: {str(e)}")
            import traceback
            traceback.print_exc()
        
    def logout(self):
        self.current_user = None
        self.running = False
        if self.socket:
            self.socket.close()
            self.socket = None
        # Clear all widgets in scrollable frame
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        self.chat_histories = {}
        self.message_ids = {}
        self.users_listbox.delete(0, tk.END)
        self.chat_frame.pack_forget()
        self.login_frame.pack(fill=tk.X, pady=5)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.root.title("Chat Application")

    def on_closing(self):
        self.running = False
        if self.socket:
            self.socket.close()
        self.root.destroy()
        
    def delete_account(self):
        if not self.current_user:
            return
            
        # Ask for confirmation
        if not messagebox.askyesno("Confirm Delete", 
            "Are you sure you want to delete your account? This will permanently delete all your messages and cannot be undone."):
            return
            
        # Get password for verification
        password = simpledialog.askstring("Password Required", 
            "Please enter your password to confirm account deletion:", show='*')
        if not password:
            return
        
        try:
            # Set a shorter timeout for delete_account
            if self.socket:
                self.socket.settimeout(3.0)  # 3 second timeout
            
            # Send delete request to server
            response = self.send_request({
                'action': 'delete_account',
                'username': self.current_user,
                'password': password
            })
            
            if response['status'] == 'success':
                messagebox.showinfo("Success", response['message'])
                self.logout()
            else:
                messagebox.showerror("Error", response['message'])
                
        except socket.timeout:
            messagebox.showerror("Error", "Server took too long to respond. Logging out for safety.")
            self.logout()
        except ConnectionError as e:
            messagebox.showerror("Connection Error", str(e))
            self.logout()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete account: {str(e)}")
            self.logout()
        finally:
            # Reset timeout to default
            if self.socket:
                self.socket.settimeout(5.0)
    
    def update_user_list(self):
        self.users_listbox.delete(0, tk.END)
        
        start_idx = (self.current_page - 1) * self.users_per_page
        end_idx = start_idx + self.users_per_page
        page_users = self.all_users[start_idx:end_idx]
        
        for user in page_users:
            self.users_listbox.insert(tk.END, user)
        
        total_pages = (len(self.all_users) + self.users_per_page - 1) // self.users_per_page
        self.page_label.config(text=f"Page {self.current_page}/{max(1, total_pages)}")
        
        # Update button states
        self.prev_button.config(state='normal' if self.current_page > 1 else 'disabled')
        self.next_button.config(state='normal' if self.current_page < total_pages else 'disabled')
    
    def prev_page(self):
        if self.current_page > 1:
            self.current_page -= 1
            self.update_user_list()
    
    def next_page(self):
        total_pages = (len(self.all_users) + self.users_per_page - 1) // self.users_per_page
        if self.current_page < total_pages:
            self.current_page += 1
            self.update_user_list()
    
    def update_title(self):
        title = f"Chat Application - {self.current_user}"
        if self.unread_count > 0:
            title += f" ({self.unread_count} unread)"
        self.root.title(title)
        
    def get_unread_count(self):
        response = self.send_request({
            'action': 'get_unread_count',
            'username': self.current_user
        })
        if response['status'] == 'success':
            self.unread_count = response['unread_count']
            self.update_title()
            
    def run(self):
        self.root.mainloop()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Start the chat client')
    parser.add_argument('--host', default='localhost',
                        help='Server host address to connect to (default: localhost)')
    parser.add_argument('--port', type=int, default=5001,
                        help='Server port to connect to (default: 5001)')
    args = parser.parse_args()
    
    client = ChatClient(host=args.host, port=args.port)
    print(f"Connecting to server at {args.host}:{args.port}")
    client.run()