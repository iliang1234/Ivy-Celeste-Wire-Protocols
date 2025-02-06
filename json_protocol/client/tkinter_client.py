import json
import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox
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
        self.users_listbox = tk.Listbox(self.users_frame, width=20)
        self.users_listbox.pack(fill=tk.Y, expand=True)
        self.users_listbox.bind('<<ListboxSelect>>', self.on_user_select)
        self.refresh_users_button = ttk.Button(self.users_frame, text="Refresh", command=self.refresh_users)
        self.refresh_users_button.pack(pady=(0, 5))
        
        self.logout_button = ttk.Button(self.users_frame, text="Logout", command=self.logout)
        self.logout_button.pack()
        
        # Messages Area
        self.messages_frame = ttk.Frame(self.chat_frame)
        self.messages_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.messages_text = tk.Text(self.messages_frame, height=20, width=50, state=tk.DISABLED)
        self.messages_text.pack(fill=tk.BOTH, expand=True)
        
        # Create right-click menu
        self.context_menu = tk.Menu(self.messages_text, tearoff=0)
        self.context_menu.add_command(label="Delete Message", command=self.delete_selected_message)
        self.messages_text.bind("<Button-3>", self.show_context_menu)
        
        # Message Input
        self.input_frame = ttk.Frame(self.messages_frame)
        self.input_frame.pack(fill=tk.X, pady=5)
        
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
            self.show_chat_interface()
            
            # Display all messages
            if 'messages' in response and response['messages']:
                for msg in response['messages']:
                    if msg['sender'] == username:
                        # This is a message we sent
                        message_text = f"You -> {msg['recipient']}: {msg['content']}"
                    else:
                        # This is a message we received
                        message_text = f"{msg['sender']}: {msg['content']}"
                    self.display_message(message_text, msg['sender'], msg['recipient'], msg['id'])
            
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
        self.root.title(f"Chat Application - {self.current_user}")
        
    def refresh_users(self):
        response = self.send_request({
            'action': 'list_accounts',
            'pattern': None
        })
        
        if response['status'] == 'success':
            self.users_listbox.delete(0, tk.END)
            for user in response['accounts']:
                if user != self.current_user:
                    self.users_listbox.insert(tk.END, user)
                    
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
        self.chat_histories[chat_key].append(message)
        
        # Store message ID for deletion
        if msg_id is not None:
            self.message_ids[message] = (msg_id, sender)
        
        # Only display if this conversation is currently selected
        if self.users_listbox.curselection():
            selected_user = self.users_listbox.get(self.users_listbox.curselection())
            current_chat_key = tuple(sorted([self.current_user, selected_user]))
            if chat_key == current_chat_key:
                self.messages_text.configure(state=tk.NORMAL)
                self.messages_text.insert(tk.END, message + "\n")
                self.messages_text.see(tk.END)
                self.messages_text.configure(state=tk.DISABLED)
                
    def on_user_select(self, event):
        if not self.users_listbox.curselection():
            return
            
        selected_user = self.users_listbox.get(self.users_listbox.curselection())
        chat_key = tuple(sorted([self.current_user, selected_user]))
        
        # Mark messages from this user as read
        response = self.send_request({
            'action': 'read_messages',
            'username': self.current_user,
            'sender': selected_user
        })
        
        # Clear and update message display
        self.messages_text.configure(state=tk.NORMAL)
        self.messages_text.delete(1.0, tk.END)
        
        # Display chat history for selected user
        if chat_key in self.chat_histories:
            for message in self.chat_histories[chat_key]:
                self.messages_text.insert(tk.END, message + "\n")
        
        self.messages_text.see(tk.END)
        self.messages_text.configure(state=tk.DISABLED)
        
    def show_context_menu(self, event):
        try:
            # Get the index of the clicked position
            index = self.messages_text.index(f"@{event.x},{event.y}")
            # Get the line of text at that index
            line_start = self.messages_text.index(f"{index} linestart")
            line_end = self.messages_text.index(f"{index} lineend")
            clicked_message = self.messages_text.get(line_start, line_end).strip()
            
            # Only show menu if message exists and belongs to current user
            if clicked_message in self.message_ids:
                msg_id, sender = self.message_ids[clicked_message]
                if sender == self.current_user:
                    self.selected_message = clicked_message
                    self.context_menu.post(event.x_root, event.y_root)
        except:
            pass
            
    def delete_selected_message(self):
        if hasattr(self, 'selected_message') and self.selected_message in self.message_ids:
            msg_id, sender = self.message_ids[self.selected_message]
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
                    self.chat_histories[chat_key].remove(self.selected_message)
                del self.message_ids[self.selected_message]
                
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
                            self.display_message(
                                f"{message['sender']}: {message['content']}",
                                message['sender'],
                                self.current_user,
                                message['id']
                            )
                        elif notification['type'] == 'messages_deleted':
                            # Refresh the display if we're viewing the chat with the user who deleted messages
                            if self.users_listbox.curselection():
                                selected_user = self.users_listbox.get(self.users_listbox.curselection())
                                if selected_user == notification['from_user']:
                                    self.on_user_select(None)
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
        self.messages_text.configure(state=tk.NORMAL)
        self.messages_text.delete(1.0, tk.END)
        self.messages_text.configure(state=tk.DISABLED)
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
        
    def run(self):
        self.root.mainloop()

if __name__ == '__main__':
    client = ChatClient()
    client.run()
