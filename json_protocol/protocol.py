from enum import Enum
import json
import bcrypt

class MessageType(Enum):
    CREATE_ACCOUNT = "create_account"
    LOGIN = "login"
    LIST_ACCOUNTS = "list_accounts"
    SEND_MESSAGE = "send_message"
    READ_MESSAGES = "read_messages"
    DELETE_MESSAGES = "delete_messages"
    DELETE_ACCOUNT = "delete_account"
    ERROR = "error"
    SUCCESS = "success"

class Protocol:
    @staticmethod
    def create_account_request(username: str, password: str) -> dict:
        """Create an account creation request"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt)
        return {
            "type": MessageType.CREATE_ACCOUNT.value,
            "username": username,
            "password_hash": hashed.decode(),
        }

    @staticmethod
    def login_request(username: str, password: str) -> dict:
        """Create a login request"""
        return {
            "type": MessageType.LOGIN.value,
            "username": username,
            "password": password,
        }

    @staticmethod
    def list_accounts_request(pattern: str = None, page: int = 1) -> dict:
        """Create a request to list accounts"""
        return {
            "type": MessageType.LIST_ACCOUNTS.value,
            "pattern": pattern,
            "page": page,
        }

    @staticmethod
    def send_message_request(recipient: str, content: str) -> dict:
        """Create a message send request"""
        return {
            "type": MessageType.SEND_MESSAGE.value,
            "recipient": recipient,
            "content": content,
            "timestamp": None,  # Will be set by server
        }

    @staticmethod
    def read_messages_request(count: int = 10) -> dict:
        """Create a request to read messages"""
        return {
            "type": MessageType.READ_MESSAGES.value,
            "count": count,
        }

    @staticmethod
    def delete_messages_request(message_ids: list) -> dict:
        """Create a request to delete messages"""
        return {
            "type": MessageType.DELETE_MESSAGES.value,
            "message_ids": message_ids,
        }

    @staticmethod
    def delete_account_request() -> dict:
        """Create a request to delete the current account"""
        return {
            "type": MessageType.DELETE_ACCOUNT.value,
        }

    @staticmethod
    def error_response(message: str) -> dict:
        """Create an error response"""
        return {
            "type": MessageType.ERROR.value,
            "message": message,
        }

    @staticmethod
    def success_response(data: dict = None) -> dict:
        """Create a success response"""
        response = {
            "type": MessageType.SUCCESS.value,
        }
        if data:
            response.update(data)
        return response

    @staticmethod
    def encode(message: dict) -> str:
        """Encode a message to JSON string"""
        return json.dumps(message)

    @staticmethod
    def decode(message: str) -> dict:
        """Decode a JSON string to a message"""
        return json.loads(message)
