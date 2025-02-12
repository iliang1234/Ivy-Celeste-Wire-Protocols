import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from typing import Optional, Dict, List
from protocol import WireProtocol, MessageType
import struct
from datetime import datetime
import time
import os
import argparse

class ChatClient:
    def __init__(self, host: str = '127.0.0.1', port: int = 65432):  
        self.host = host
        self.port = port
        self.socket = None
        self.current_user = None
        self.running = True
        self.message_listener = None
        self.received_messages = set()  
        self.chat_histories = {}  
        self.socket_lock = threading.Lock()
        self.all_users = []
        self.current_page = 1
        self.users_per_page = 5
        self.current_chat_user = None
        self.unread_messages = {}  # {username: count}
        self.current_msg_page = 1
        self.messages_per_page = 10
        self.setup_gui()
        
    def setup_gui(self):
        """Setup the GUI components"""
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
        
        button_frame = ttk.Frame(self.login_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=5)
        
        self.login_button = ttk.Button(button_frame, text="Login", command=self.login)
        self.login_button.pack(side=tk.LEFT, padx=5)
        
        self.register_button = ttk.Button(button_frame, text="Register", command=self.register)
        self.register_button.pack(side=tk.LEFT, padx=5)
        
        # Chat Frame (initially hidden)
        self.chat_frame = ttk.Frame(self.main_container)
        
        # Left side - Users List
        self.users_frame = ttk.LabelFrame(self.chat_frame, text="Users")
        self.users_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        # Search frame
        self.search_frame = ttk.Frame(self.users_frame)
        self.search_frame.pack(fill=tk.X, pady=5)
        self.search_entry = ttk.Entry(self.search_frame)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.search_button = ttk.Button(self.search_frame, text="Search", command=self.search_users)
        self.search_button.pack(side=tk.RIGHT)
        
        # Users listbox with pagination
        self.users_listbox = tk.Listbox(self.users_frame, width=20, height=5)
        self.users_listbox.pack(fill=tk.X)
        self.users_listbox.bind('<<ListboxSelect>>', self.on_user_select)
        
        # Pagination frame
        self.page_frame = ttk.Frame(self.users_frame)
        self.page_frame.pack(fill=tk.X, pady=2)
        
        self.prev_button = ttk.Button(self.page_frame, text="←", width=3, command=self.prev_page)
        self.prev_button.pack(side=tk.LEFT)
        
        self.page_label = ttk.Label(self.page_frame, text="Page 1")
        self.page_label.pack(side=tk.LEFT, expand=True)
        
        self.next_button = ttk.Button(self.page_frame, text="→", width=3, command=self.next_page)
        self.next_button.pack(side=tk.RIGHT)
        
        # Buttons frame
        self.buttons_frame = ttk.Frame(self.users_frame)
        self.buttons_frame.pack(fill=tk.X, pady=5)
        
        self.refresh_button = ttk.Button(self.buttons_frame, text="Refresh", command=self.refresh_users)
        self.refresh_button.pack(side=tk.LEFT, padx=2)
        
        self.logout_button = ttk.Button(self.buttons_frame, text="Logout", command=self.logout)
        self.logout_button.pack(side=tk.LEFT, padx=2)
        
        self.delete_account_button = ttk.Button(self.buttons_frame, text="Delete Account", command=self.delete_account)
        self.delete_account_button.pack(side=tk.RIGHT, padx=2)
        
        # Right side - Chat Area
        self.chat_area_frame = ttk.LabelFrame(self.chat_frame, text="Chat")
        self.chat_area_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Message controls
        self.message_controls = ttk.Frame(self.chat_area_frame)
        self.message_controls.pack(fill=tk.X, pady=5)
        
        ttk.Label(self.message_controls, text="Messages per page:").pack(side=tk.LEFT, padx=(0, 5))
        self.msg_per_page_var = tk.StringVar(value="10")
        self.msg_per_page_entry = ttk.Entry(self.message_controls, textvariable=self.msg_per_page_var, width=5)
        self.msg_per_page_entry.pack(side=tk.LEFT)
        
        self.apply_count_btn = ttk.Button(self.message_controls, text="Apply", command=self.update_message_count)
        self.apply_count_btn.pack(side=tk.LEFT, padx=5)
        
        # Message navigation
        self.prev_msg_btn = ttk.Button(self.message_controls, text="↑", command=self.prev_messages, width=3)
        self.prev_msg_btn.pack(side=tk.RIGHT, padx=(5, 0))
        self.next_msg_btn = ttk.Button(self.message_controls, text="↓", command=self.next_messages, width=3)
        self.next_msg_btn.pack(side=tk.RIGHT)
        
        self.msg_page_var = tk.StringVar(value="Page 1")
        self.msg_page_label = ttk.Label(self.message_controls, textvariable=self.msg_page_var)
        self.msg_page_label.pack(side=tk.RIGHT, padx=10)
        
        # Messages area with scrollbar
        self.messages_frame = ttk.Frame(self.chat_area_frame)
        self.messages_frame.pack(fill=tk.BOTH, expand=True)
        
        self.messages_canvas = tk.Canvas(self.messages_frame)
        self.scrollbar = ttk.Scrollbar(self.messages_frame, orient="vertical", command=self.messages_canvas.yview)
        
        self.scrollable_frame = ttk.Frame(self.messages_canvas)
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.messages_canvas.configure(scrollregion=self.messages_canvas.bbox("all"))
        )
        
        self.messages_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.messages_canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.messages_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Message input
        self.input_frame = ttk.Frame(self.chat_area_frame)
        self.input_frame.pack(fill=tk.X, pady=5)
        
        self.message_entry = ttk.Entry(self.input_frame)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        self.send_button = ttk.Button(self.input_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)
        
        # Set protocol for window close
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
            with self.socket_lock:
                self.socket.sendall(data)
                self.socket.settimeout(5)
                header_data = b''
                remaining = 9
                while remaining > 0:
                    chunk = self.socket.recv(remaining)
                    if not chunk:
                        raise ConnectionError("Server closed connection")
                    header_data += chunk
                    remaining -= len(chunk)
                    
                msg_type, payload_length, num_items = WireProtocol.unpack_header(header_data)
                
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
                    message_text, offset = WireProtocol.unpack_string(payload)
                    num_messages = struct.unpack('!I', payload[offset:offset + 4])[0]
                    offset += 4
                    
                    self.current_user = username
                    self.chat_histories.clear()
                    self.received_messages.clear()
                    
                    for _ in range(num_messages):
                        try:
                            message_data, new_offset = WireProtocol.unpack_message(payload[offset:])
                            offset += new_offset
                            chat_key = tuple(sorted([message_data['sender'], message_data['recipient']]))
                            if chat_key not in self.chat_histories:
                                self.chat_histories[chat_key] = []
                            if message_data['id'] not in self.received_messages:
                                self.chat_histories[chat_key].append(message_data)
                                self.received_messages.add(message_data['id'])
                        except Exception as e:
                            print(f"Error processing message during login: {e}")
                            continue
                            
                    self.login_frame.pack_forget()
                    self.chat_frame.pack(fill=tk.BOTH, expand=True)
                    self.running = True
                    self.start_message_listener()
                    self.refresh_users()
                    
                    messagebox.showinfo("Success", message_text)
                    
                except Exception as e:
                    print(f"Error processing login response: {e}")
                    messagebox.showerror("Error", f"Error processing login response: {str(e)}")
                    return
                    
            else:
                error_msg, _ = WireProtocol.unpack_string(payload)
                messagebox.showerror("Error", error_msg)
                
        except Exception as e:
            messagebox.showerror("Error", f"Login failed: {str(e)}")

    def register(self):
        """Handle user registration"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
            
        request = WireProtocol.create_account_request(username, password)
        msg_type, payload, _ = self.send_request(request)
        
        if msg_type == MessageType.SUCCESS:
            message_text, _ = WireProtocol.unpack_string(payload)
            messagebox.showinfo("Success", message_text)
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
        else:
            error_msg, _ = WireProtocol.unpack_string(payload)
            messagebox.showerror("Error", error_msg)

    def refresh_users(self):
        """Refresh the list of users and update pagination"""
        request = WireProtocol.list_accounts_request()
        msg_type, payload, num_accounts = self.send_request(request)
        if msg_type == MessageType.SUCCESS:
            self.all_users = []
            offset = 0
            for _ in range(num_accounts):
                username, new_offset = WireProtocol.unpack_string(payload, offset)
                offset = new_offset
                if username != self.current_user:
                    self.all_users.append(username)
            self.current_page = 1
            self.update_users_display()

    def search_users(self):
        """Search for users based on pattern"""
        pattern = self.search_entry.get()
        request = WireProtocol.list_accounts_request(pattern)
        msg_type, payload, num_items = self.send_request(request)
        
        if msg_type == MessageType.SUCCESS:
            self.all_users = []
            offset = 0
            for _ in range(num_items):
                username, new_offset = WireProtocol.unpack_string(payload, offset)
                offset = new_offset
                if username != self.current_user:
                    self.all_users.append(username)
            self.current_page = 1
            self.update_users_display()

    def update_users_display(self):
        """Update the users listbox with current page"""
        self.users_listbox.delete(0, tk.END)
        start_idx = (self.current_page - 1) * self.users_per_page
        end_idx = start_idx + self.users_per_page
        for username in self.all_users[start_idx:end_idx]:
            unread = self.unread_messages.get(username, 0)
            display = f"{username} ({unread})" if unread > 0 else username
            self.users_listbox.insert(tk.END, display)
        total_pages = (len(self.all_users) + self.users_per_page - 1) // self.users_per_page
        self.page_label.config(text=f"Page {self.current_page}/{max(total_pages, 1)}")

    def prev_page(self):
        """Go to previous page of users"""
        if self.current_page > 1:
            self.current_page -= 1
            self.update_users_display()
            
    def next_page(self):
        """Go to next page of users"""
        max_pages = (len(self.all_users) + self.users_per_page - 1) // self.users_per_page
        if self.current_page < max_pages:
            self.current_page += 1
            self.update_users_display()

    def on_user_select(self, event):
        """Handle user selection from listbox"""
        selection = self.users_listbox.curselection()
        if not selection:
            return
            
        display_text = self.users_listbox.get(selection[0])
        username = display_text.split(" (")[0]
        
        if username != self.current_chat_user:
            self.current_chat_user = username
            self.current_msg_page = 1
            self.display_chat_history(username)
            if username in self.unread_messages:
                del self.unread_messages[username]
                self.update_users_display()

    def display_chat_history(self, other_user):
        """Display chat history with pagination"""
        chat_key = tuple(sorted([self.current_user, other_user]))
        
        # Clear any existing messages
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
            
        if chat_key in self.chat_histories:
            messages = self.chat_histories[chat_key]
            total_messages = len(messages)
            start_idx = (self.current_msg_page - 1) * self.messages_per_page
            end_idx = min(start_idx + self.messages_per_page, total_messages)
            
            for msg in messages[start_idx:end_idx]:
                message_frame = ttk.Frame(self.scrollable_frame)
                message_frame.pack(fill=tk.X, padx=5, pady=2)
                
                # Add delete button if this message was sent by the current user
                if msg.get('sender') == self.current_user:
                    delete_btn = ttk.Button(
                        message_frame, 
                        text="×", 
                        width=3,
                        command=lambda mid=msg.get('id'): self.delete_message(mid)
                    )
                    delete_btn.pack(side=tk.RIGHT, padx=(5, 0))
                    
                message_text = f"{msg['sender']}: {msg['content']}"
                align = tk.RIGHT if msg['sender'] == self.current_user else tk.LEFT
                
                message_label = ttk.Label(
                    message_frame,
                    text=message_text,
                    wraplength=400,
                    justify=align
                )
                message_label.pack(side=align, padx=5)
                
            max_pages = (total_messages + self.messages_per_page - 1) // self.messages_per_page
            self.msg_page_var.set(f"Page {self.current_msg_page}/{max_pages}")
            
        self.messages_canvas.yview_moveto(1.0)

    def display_message(self, message_data: dict):
        """Display an incoming message"""
        if not isinstance(message_data, dict) or 'id' not in message_data:
            print(f"Invalid message data: {message_data}")
            return
            
        if message_data['id'] in self.received_messages:
            return
            
        self.received_messages.add(message_data['id'])
        
        chat_key = tuple(sorted([message_data['sender'], message_data['recipient']]))
        if chat_key not in self.chat_histories:
            self.chat_histories[chat_key] = []
        self.chat_histories[chat_key].append(message_data)
        
        other_party = message_data['recipient'] if message_data['sender'] == self.current_user else message_data['sender']
        if self.current_chat_user == other_party:
            self.display_chat_history(self.current_chat_user)

    def send_message(self):
        """Send a message to the selected user"""
        if not self.current_chat_user:
            messagebox.showwarning("Warning", "Please select a user to chat with")
            return
            
        content = self.message_entry.get().strip()
        if not content:
            return
            
        request = WireProtocol.send_message_request(self.current_user, self.current_chat_user, content)
        msg_type, payload, _ = self.send_request(request)
        
        if msg_type == MessageType.SUCCESS:
            self.message_entry.delete(0, tk.END)
            # Unpack the message from the server response so that you get the server-generated ID.
            message_data, _ = WireProtocol.unpack_message(payload)
            chat_key = tuple(sorted([self.current_user, self.current_chat_user]))
            
            if chat_key not in self.chat_histories:
                self.chat_histories[chat_key] = []
            self.chat_histories[chat_key].append(message_data)
            
            self.display_chat_history(self.current_chat_user)

        else:
            error_msg, _ = WireProtocol.unpack_string(payload)
            messagebox.showerror("Error", error_msg)

    def listen_for_messages(self):
        """Continuously listen for incoming messages/notifications"""
        while self.running:
            try:
                with self.socket_lock:
                    self.socket.settimeout(0.05)
                    try:
                        self.socket.recv(1, socket.MSG_PEEK)
                    except socket.timeout:
                        continue
                    except Exception as e:
                        raise e
                        
                    self.socket.settimeout(1)
                    header_data = b''
                    remaining = 9
                    while remaining > 0 and self.running:
                        chunk = self.socket.recv(remaining)
                        if not chunk:
                            raise ConnectionError("Server closed connection")
                        header_data += chunk
                        remaining -= len(chunk)
                        
                    msg_type, payload_length, num_items = WireProtocol.unpack_header(header_data)
                    
                    payload = b''
                    if payload_length > 0:
                        remaining = payload_length
                        while remaining > 0 and self.running:
                            chunk = self.socket.recv(remaining)
                            if not chunk:
                                raise ConnectionError("Server closed connection")
                            payload += chunk
                            remaining -= len(chunk)
                            
                    if msg_type == MessageType.NEW_MESSAGE_NOTIFICATION:
                        message_data, _ = WireProtocol.unpack_message(payload)
                        self.root.after(0, lambda: self.display_message(message_data))
                    elif msg_type == MessageType.DELETE_MESSAGE_NOTIFICATION:
                        # The payload is just the 4-byte message id.
                        if len(payload) >= 4:
                            msg_id = struct.unpack('!I', payload[:4])[0]
                            self.root.after(0, lambda: self.remove_deleted_message(msg_id))
                    elif msg_type == MessageType.ACCOUNT_DELETED_NOTIFICATION:
                        # Unpack the username of the deleted account.
                        deleted_username, _ = WireProtocol.unpack_string(payload)
                        self.root.after(0, lambda: self.handle_account_deletion(deleted_username))
                # … handle other message types if needed …
                        
            except socket.timeout:
                continue
            except ConnectionError as e:
                print(f"Connection error in listener: {e}")
                self.root.after(0, self.logout)
                break
            except Exception as e:
                print(f"Error in message listener: {e}")
                time.sleep(0.1)
                continue
            finally:
                try:
                    self.socket.settimeout(None)
                except:
                    pass
                    
        print("Message listener stopped")

    def remove_deleted_message(self, msg_id):
        # Go through all chat histories to remove the message
        for chat_key, messages in self.chat_histories.items():
            new_messages = [msg for msg in messages if msg.get('id') != msg_id]
            self.chat_histories[chat_key] = new_messages
        # If the current chat is open, refresh its display
        if self.current_chat_user:
            self.display_chat_history(self.current_chat_user)

    def handle_account_deletion(self, deleted_username: str):
        # Remove the deleted username from the list of all users.
        if deleted_username in self.all_users:
            self.all_users.remove(deleted_username)
        # Optionally, remove any associated chat history.
        chat_keys_to_remove = [chat_key for chat_key in self.chat_histories
                            if deleted_username in chat_key]
        for key in chat_keys_to_remove:
            del self.chat_histories[key]
        # Refresh the users display so the change is immediately visible.
        self.display_chat_history(self.current_chat_user)
        self.update_users_display()
    
    def start_message_listener(self):
        """Start the background thread that listens for new messages"""
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

    def update_message_count(self):
        """Update number of messages shown per page"""
        try:
            new_count = int(self.msg_per_page_var.get())
            if new_count > 0:
                self.messages_per_page = new_count
                if self.current_chat_user:
                    self.display_chat_history(self.current_chat_user)
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number")
            
    def prev_messages(self):
        """Show previous page of messages"""
        if self.current_msg_page > 1:
            self.current_msg_page -= 1
            self.display_chat_history(self.current_chat_user)
            
    def next_messages(self):
        """Show next page of messages"""
        chat_key = tuple(sorted([self.current_user, self.current_chat_user]))
        total_messages = len(self.chat_histories.get(chat_key, []))
        max_pages = (total_messages + self.messages_per_page - 1) // self.messages_per_page
        
        if self.current_msg_page < max_pages:
            self.current_msg_page += 1
            self.display_chat_history(self.current_chat_user)
            
    def delete_account(self):
        """Delete current user's account"""
        if not self.current_user:
            return
            
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete your account? This cannot be undone."):
            password = simpledialog.askstring("Password Required", "Enter your password to confirm:", show="*")
            if password:
                request = WireProtocol.delete_account_request(self.current_user, password)
                msg_type, payload, _ = self.send_request(request)
                
                messagebox.showinfo("Success", "Account deleted successfully")
                self.logout()
                    
    def delete_message(self, message_id):
        """Delete a specific message"""
        if not self.current_chat_user:
            return
                
        # Pass only the current_user and message_id.
        # request = WireProtocol.delete_message_request(self.current_user, message_id)
        request = WireProtocol.delete_message_request(self.current_user, message_id)

        msg_type, payload, _ = self.send_request(request)
        
        if msg_type == MessageType.SUCCESS:
            chat_key = tuple(sorted([self.current_user, self.current_chat_user]))
            if chat_key in self.chat_histories:
                self.chat_histories[chat_key] = [
                    msg for msg in self.chat_histories[chat_key]
                    if msg.get('id') != message_id
                ]
            self.display_chat_history(self.current_chat_user)
        else:
            error_msg, _ = WireProtocol.unpack_string(payload)
            messagebox.showerror("Error", error_msg)


if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Start the chat client.")
    parser.add_argument("--host", default=os.getenv("CHAT_SERVER_HOST", "127.0.0.1"), help="Server hostname or IP")
    parser.add_argument("--port", type=int, default=int(os.getenv("CHAT_SERVER_PORT", 65432)), help="Port number")
    args = parser.parse_args()

    # Create and start the client
    client = ChatClient(host=args.host, port=args.port)
    client.run()
