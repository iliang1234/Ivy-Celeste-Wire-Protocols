class ChatClient {
    constructor() {
        this.messageIdCounter = 0;
        this.currentUser = null;
        this.selectedRecipient = null;
        this.userPage = 1;
        this.initializeSocket();
    }

    async initializeSocket() {
        try {
            const response = await fetch('/config');
            const config = await response.json();
            this.socket = io(config.websocket_url);
            this.setupSocketHandlers();
            this.setupEventListeners();
        } catch (error) {
            console.error('Failed to initialize socket:', error);
            alert('Failed to connect to chat server. Please try again later.');
        }
    }

    setupSocketHandlers() {
        this.socket.on('connect', () => {
            console.log('Connected to server');
        });

        this.socket.on('message', (data) => {
            const message = JSON.parse(data);
            this.handleServerMessage(message);
        });

        this.socket.on('new_message', (data) => {
            const message = JSON.parse(data);
            // Only display the message if it's from the currently selected chat
            if (message.sender === this.selectedRecipient || message.recipient === this.selectedRecipient) {
                // Don't display messages we sent (they're already displayed)
                if (message.sender !== this.currentUser) {
                    this.displayMessage(message);
                }
            }
        });
    }

    setupEventListeners() {
        // Auth form handlers
        document.getElementById('login-form').addEventListener('submit', (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            this.login(username, password);
        });

        document.getElementById('register-btn').addEventListener('click', () => {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            this.register(username, password);
        });

        // Chat interface handlers
        document.getElementById('message-form').addEventListener('submit', (e) => {
            e.preventDefault();
            const input = document.getElementById('message-input');
            this.sendMessage(input.value);
            input.value = '';
        });

        document.getElementById('user-search').addEventListener('input', (e) => {
            this.searchUsers(e.target.value);
        });

        document.getElementById('prev-users').addEventListener('click', () => {
            if (this.userPage > 1) {
                this.userPage--;
                this.listUsers();
            }
        });

        document.getElementById('next-users').addEventListener('click', () => {
            this.userPage++;
            this.listUsers();
        });

        document.getElementById('logout-btn').addEventListener('click', () => {
            this.logout();
        });
    }

    sendToServer(message) {
        this.socket.emit('message', JSON.stringify(message));
    }

    register(username, password) {
        this.sendToServer({
            type: 'create_account',
            username: username,
            password: password,
            is_registration: true
        });
    }

    login(username, password) {
        this.sendToServer({
            type: 'login',
            username: username,
            password: password
        });
        this.currentUser = username; // Store the logged-in user
    }
    

    logout() {
        this.currentUser = null;  // Reset user on logout
        this.selectedRecipient = null;
        
        // Reset UI
        document.getElementById('auth-form').classList.remove('d-none');
        document.getElementById('chat-interface').classList.add('d-none');
        document.getElementById('username').value = '';
        document.getElementById('password').value = '';
        document.getElementById('chat-header').textContent = 'Select a user to start chatting';
        document.getElementById('no-chat-selected').classList.remove('d-none');
        document.getElementById('chat-area').classList.add('d-none');
        document.getElementById('message-list').innerHTML = '';
    }
    

    listUsers(pattern = '') {
        this.sendToServer({
            type: 'list_accounts',
            pattern: pattern,
            page: this.userPage
        });
    }

    searchUsers(pattern) {
        this.userPage = 1;
        this.listUsers(pattern);
    }

    sendMessage(content) {
        if (!this.selectedRecipient) {
            alert('Please select a recipient first');
            return;
        }

        const messageId = this.messageIdCounter++;
        this.sendToServer({
            type: 'send_message',
            recipient: this.selectedRecipient,
            content: content,
            id: messageId
        });
    }

    handleServerMessage(message) {
        if (message.type === 'error') {
            alert(message.message);
            if (message.message === 'Username already exists') {
                document.getElementById('username').value = '';
                document.getElementById('password').value = '';
            }
            return;
        }
        
        // Hide chat area when first logging in
        if (message.type === 'success' && message.unread_count !== undefined) {
            document.getElementById('no-chat-selected').classList.remove('d-none');
            document.getElementById('chat-area').classList.add('d-none');
            document.getElementById('chat-header').textContent = 'Select a user to start chatting';
        }

        if (message.type === 'success') {
            if (message.unread_count !== undefined) {
                // Login/registration successful
                this.currentUser = document.getElementById('username').value; // Set currentUser
                document.getElementById('auth-form').classList.add('d-none');
                document.getElementById('chat-interface').classList.remove('d-none');
                this.listUsers();
            } else if (message.users !== undefined) {
                // User list received
                this.updateUserList(message.users, message.total_pages);
            } else if (message.messages !== undefined) {
                // Messages received
                message.messages.forEach(msg => this.displayMessage(msg));
            } else if (message.deleted_message_id !== undefined) {
                // Message deleted
                const msgElement = document.querySelector(`[data-message-id="${message.deleted_message_id}"]`);
                if (msgElement) {
                    msgElement.remove();
                }
            } else if (message.message === "Message sent successfully") {
                // When a message is sent successfully, display it immediately as a sent message
                const sentMessage = {
                    id: message.message_id,
                    content: message.content,
                    sender: this.currentUser,
                    recipient: this.selectedRecipient,
                    timestamp: new Date().toISOString(),
                    is_sent: true
                };
                this.displayMessage(sentMessage);
            }
        }
    }

    updateUserList(users, totalPages) {
        const userList = document.getElementById('user-list');
        userList.innerHTML = '';
        
        users.forEach(username => {
            if (username === this.currentUser) return;
            
            const userElement = document.createElement('a');
            userElement.classList.add('list-group-item', 'list-group-item-action', 'user-item');
            if (username === this.selectedRecipient) {
                userElement.classList.add('active');
            }
            userElement.textContent = username;
            userElement.addEventListener('click', () => {
                this.selectedRecipient = username;
                document.querySelectorAll('.user-item').forEach(el => {
                    el.classList.remove('active');
                });
                userElement.classList.add('active');
                
                // After selecting a new user, re-fetch and display their messages
                this.fetchMessagesForRecipient(username);
            });
            userList.appendChild(userElement);
        });
    
        document.getElementById('prev-users').disabled = this.userPage <= 1;
        document.getElementById('next-users').disabled = this.userPage >= totalPages;
    }
    
    fetchMessagesForRecipient(recipient) {
        if (!recipient) return;
        
        this.selectedRecipient = recipient;
        
        // Update UI
        document.getElementById('chat-header').textContent = `Chat with ${recipient}`;
        document.getElementById('no-chat-selected').classList.add('d-none');
        document.getElementById('chat-area').classList.remove('d-none');
        
        // Clear existing messages
        document.getElementById('message-list').innerHTML = '';
        
        // Fetch messages for this recipient
        this.sendToServer({
            type: 'read_messages',
            recipient: recipient
        });
    }    

    displayMessage(message) {
        const messageList = document.getElementById('message-list');
        const messageElement = document.createElement('div');
        messageElement.classList.add('message');
        
        // Use is_sent flag if available, otherwise determine based on sender
        const isSent = message.hasOwnProperty('is_sent') ? message.is_sent : message.sender === this.currentUser;
        
        // Add the appropriate class based on whether the message was sent or received
        if (isSent) {
            messageElement.classList.add('sent');
        } else {
            messageElement.classList.add('received');
        }
        
        // Assign a message ID if not present
        if (!message.id) {
            message.id = this.messageIdCounter++;
        }
        messageElement.setAttribute('data-message-id', message.id);
        
        const contentWrapper = document.createElement('div');
        contentWrapper.classList.add('message-content');
        
        const content = document.createElement('div');
        content.classList.add('message-text');
        content.textContent = message.content;
        contentWrapper.appendChild(content);
        
        const timestamp = document.createElement('div');
        timestamp.classList.add('timestamp');
        timestamp.textContent = new Date(message.timestamp).toLocaleString();
        contentWrapper.appendChild(timestamp);
        
        messageElement.appendChild(contentWrapper);
        
        // Add delete button for sent messages
        if (isSent) {
            const deleteBtn = document.createElement('button');
            deleteBtn.classList.add('delete-msg-btn');
            deleteBtn.innerHTML = '&times;';
            deleteBtn.onclick = (e) => {
                e.stopPropagation();
                this.deleteMessage(message.id);
            };
            messageElement.appendChild(deleteBtn);
        }
        
        messageList.appendChild(messageElement);
        messageList.scrollTop = messageList.scrollHeight;
    }    
}

// Initialize the chat client when the page loads
window.addEventListener('load', () => {
    new ChatClient();
});

// Handle connection errors
window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    if (event.reason.message.includes('Failed to fetch')) {
        alert('Unable to connect to the chat server. Please check your connection and try again.');
    }
});
