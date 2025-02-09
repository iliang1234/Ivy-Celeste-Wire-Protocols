# Chat System Test Suite

This test suite verifies the functionality of both the chat client and server components.

## Test Coverage

1. **User Management**
   - User registration
   - User login
   - User list retrieval

2. **Messaging**
   - Message sending
   - Message deletion
   - Message history

3. **Client Features**
   - Message pagination
   - Message ordering
   - Chat history handling

## Running Tests

To run all tests:
```bash
python3 -m unittest tests/test_chat_system.py
```

To run a specific test:
```bash
python3 -m unittest tests.test_chat_system.TestChatSystem.test_name
```

## Test Cases

### User Registration (`test_user_registration`)
- Tests successful user registration
- Tests duplicate registration handling

### User Login (`test_user_login`)
- Tests successful login
- Tests login with wrong password

### Message Sending (`test_message_sending`)
- Tests message delivery
- Verifies message storage

### Message Deletion (`test_message_deletion`)
- Tests message deletion
- Verifies message removal

### User List (`test_user_list`)
- Tests user list retrieval
- Verifies user list contents

### Client Message History (`test_client_message_history`)
- Tests message ordering
- Verifies history management

### Client Pagination (`test_client_pagination`)
- Tests page calculation
- Verifies message grouping

## Adding New Tests

To add new tests:
1. Create a new test method in `TestChatSystem` class
2. Follow the naming convention: `test_feature_name`
3. Add appropriate assertions
4. Update this README with new test details
