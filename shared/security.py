"""Security utilities for password hashing and verification."""

import bcrypt
from cryptography.fernet import Fernet
import base64

def hash_password(password: str) -> bytes:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_password(password: str, hashed: bytes) -> bool:
    """Verify a password against its hash."""
    return bcrypt.checkpw(password.encode(), hashed)

def generate_key() -> bytes:
    """Generate a new encryption key."""
    return Fernet.generate_key()

class MessageEncryption:
    def __init__(self, key: bytes):
        self.fernet = Fernet(key)
    
    def encrypt_message(self, message: str) -> bytes:
        """Encrypt a message."""
        return self.fernet.encrypt(message.encode())
    
    def decrypt_message(self, encrypted: bytes) -> str:
        """Decrypt a message."""
        return self.fernet.decrypt(encrypted).decode()

def encode_bytes(data: bytes) -> str:
    """Encode bytes to base64 string for transmission."""
    return base64.b64encode(data).decode()

def decode_bytes(data: str) -> bytes:
    """Decode base64 string back to bytes."""
    return base64.b64decode(data.encode())
