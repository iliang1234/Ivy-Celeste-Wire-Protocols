import json
import socket
import threading
import tkinter as tk
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
        
        # Create messages container with scrollbar
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
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            return True
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect to server: {str(e)}")
            return False
            
    def send_request(self, request: dict) -> dict:
        if not self.socket:
            if not self.connect():
                return {'status': 'error', 'message': 'Not connected to server'}
                
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            response = self.socket.recv(4096).decode('utf-8')
            return json.loads(response)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to communicate with server: {str(e)}")
            return {'status': 'error', 'message': str(e)}
            
    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
            
        response = self.send_request({
            'action': 'login',
            'username': username,
            'password': password
        })
        
        if response['status'] == 'success':
            self.current_user = username
            self.chat_histories = {}  # Clear any old chat histories
            self.unread_count = response.get('unread_count', 0)
            
            # Process all messages
            if 'messages' in response and response['messages']:
                for msg in response['messages']:
                    chat_key = tuple(sorted([msg['sender'], msg['recipient']]))
                    
                    # Initialize chat history if needed
                    if chat_key not in self.chat_histories:
                        self.chat_histories[chat_key] = []
                    
                    # Format message text
                    if msg['sender'] == username:
                        message_text = f"You -> {msg['recipient']}: {msg['content']}"
                    else:
                        message_text = f"{msg['sender']}: {msg['content']}"
                    
                    # Add to chat history if not already there
                    msg_exists = any(mid == msg['id'] for _, mid, _ in self.chat_histories[chat_key])
                    if not msg_exists:
                        self.chat_histories[chat_key].append((message_text, msg['id'], msg['sender']))
            
            # Show chat interface and start listener
            self.show_chat_interface()
            messagebox.showinfo("Success", response['message'])
            self.start_message_listener()
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
        self.login_frame.pack_forget()
        self.chat_frame.pack(fill=tk.BOTH, expand=True)
        self.refresh_users()
        self.update_title()
        
    def refresh_users(self):
        response = self.send_request({
            'action': 'list_accounts',
            'pattern': None
        })
        
        if response['status'] == 'success':
            self.all_users = [user for user in response['accounts'] if user != self.current_user]
            self.current_page = 1
            self.update_user_list()
                    
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
                    
    def send_message(self):
        if not self.users_listbox.curselection():
            messagebox.showerror("Error", "Please select a recipient")
            return
            
        recipient = self.users_listbox.get(self.users_listbox.curselection())
        content = self.message_entry.get()
        
        if not content:
            return
            
        response = self.send_request({
            'action': 'send_message',
            'sender': self.current_user,
            'recipient': recipient,
            'content': content
        })
        
        if response['status'] == 'success':
            self.message_entry.delete(0, tk.END)
            msg_text = f"You -> {recipient}: {content}"
            self.display_message(msg_text, self.current_user, recipient, response.get('message_id'))
        else:
            messagebox.showerror("Error", response['message'])
            
    def display_message(self, message: str, sender: str, receiver: str, msg_id: int = None):
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
                self.add_message_to_display(message, msg_id, sender)
                
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
            
            # Clear display
            for widget in self.scrollable_frame.winfo_children():
                widget.destroy()
            
            # Show messages in order
            if chat_key in self.chat_histories:
                sorted_messages = sorted(self.chat_histories[chat_key], key=lambda x: x[1])
                for message, msg_id, sender in sorted_messages:
                    self.add_message_to_display(message, msg_id, sender)
            
            # Scroll to bottom
            self.messages_canvas.yview_moveto(1.0)
            
        except Exception as e:
            print(f"Error in on_user_select: {str(e)}")
            # Clear display on error
            for widget in self.scrollable_frame.winfo_children():
                widget.destroy()
        
    def add_message_to_display(self, message: str, msg_id: int, sender: str):
        # Create a frame for the message
        msg_frame = ttk.Frame(self.scrollable_frame)
        msg_frame.pack(fill=tk.X, padx=5, pady=2)
        
        # Add message text
        msg_label = ttk.Label(msg_frame, text=message, wraplength=350)
        msg_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Add delete button if message is from current user
        if sender == self.current_user and msg_id is not None:
            delete_btn = ttk.Button(
                msg_frame,
                text="Delete",
                command=lambda: self.delete_message(msg_id)
            )
            delete_btn.pack(side=tk.RIGHT)
        
        # Scroll to bottom
        self.messages_canvas.yview_moveto(1.0)
            
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
                self.chat_histories[chat_key] = [
                    (msg, mid, sndr) for msg, mid, sndr in self.chat_histories[chat_key]
                    if mid != msg_id
                ]
            
            # Refresh the display
            self.on_user_select(None)
        else:
            messagebox.showerror("Error", response['message'])
    
    def start_message_listener(self):
        def listen_for_messages():
            while self.running and self.socket:
                try:
                    data = self.socket.recv(4096).decode('utf-8')
                    if data:
                        notification = json.loads(data)
                        if notification['type'] == 'new_message':
                            message = notification['message']
                            # Increment unread count if we're the recipient and message is unread
                            if message['recipient'] == self.current_user and not message['read']:
                                self.unread_count += 1
                                self.update_title()
                            
                            # Format message text
                            if message['sender'] == self.current_user:
                                msg_text = f"You -> {message['recipient']}: {message['content']}"
                            else:
                                msg_text = f"{message['sender']}: {message['content']}"
                            
                            self.display_message(msg_text, message['sender'], message['recipient'], message['id'])
                            
                        elif notification['type'] == 'messages_deleted':
                            # Refresh the display if we're viewing the chat with the user who deleted messages
                            if self.users_listbox.curselection():
                                selected_user = self.users_listbox.get(self.users_listbox.curselection())
                                if selected_user == notification['from_user']:
                                    self.on_user_select(None)
                                    
                        elif notification['type'] == 'account_deleted':
                            # Remove the deleted user from the listbox
                            deleted_user = notification['username']
                            for i in range(self.users_listbox.size()):
                                if self.users_listbox.get(i) == deleted_user:
                                    self.users_listbox.delete(i)
                                    break
                            # Clear chat if we were viewing the deleted user's messages
                            if self.users_listbox.curselection():
                                selected_user = self.users_listbox.get(self.users_listbox.curselection())
                                if selected_user == deleted_user:
                                    for widget in self.scrollable_frame.winfo_children():
                                        widget.destroy()
                except:
                    break
                    
        self.message_listener = threading.Thread(target=listen_for_messages)
        self.message_listener.daemon = True
        self.message_listener.start()
        
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
    client = ChatClient()
    client.run()