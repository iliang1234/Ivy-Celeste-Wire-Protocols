from enum import IntEnum
import struct
from typing import Optional, Tuple, List, Dict
from dataclasses import dataclass
from datetime import datetime

class MessageType(IntEnum):
    # Account operations
    CREATE_ACCOUNT = 1
    LOGIN = 2
    DELETE_ACCOUNT = 3
    
    # User operations
    LIST_ACCOUNTS = 4
    
    # Message operations
    SEND_MESSAGE = 5
    READ_MESSAGES = 6
    DELETE_MESSAGES = 7
    
    # Responses
    SUCCESS = 8
    ERROR = 9
    
    # Real-time notifications
    NEW_MESSAGE_NOTIFICATION = 10
    MESSAGE_DELETED_NOTIFICATION = 11

    @classmethod
    def _missing_(cls, value):
        """Handle invalid message types"""
        raise ValueError(f"{value} is not a valid MessageType")

class WireProtocol:
    """
    Wire Protocol Format:
    
    Header (9 bytes total):
    - Message Type (1 byte): Indicates the type of message
    - Payload Length (4 bytes): Length of the payload in bytes
    - Number of Items (4 bytes): Number of items in payload (for lists/arrays)
    
    Payload Format varies by message type but follows these conventions:
    - Strings are prefixed with their length (4 bytes)
    - Lists are prefixed with their count (4 bytes)
    - Timestamps are stored as 8-byte float (unix timestamp)
    - Boolean values are stored as 1 byte (0 or 1)
    """
    
    @staticmethod
    def pack_string(s: str) -> bytes:
        """Pack a string with its length prefix"""
        encoded = s.encode('utf-8') if s else b''
        return struct.pack('!I', len(encoded)) + encoded
    
    @staticmethod
    def unpack_string(data: bytes, offset: int = 0) -> Tuple[str, int]:
        """Unpack a string and return it with the new offset"""
        length = struct.unpack('!I', data[offset:offset + 4])[0]
        offset += 4
        string = data[offset:offset + length].decode('utf-8') if length > 0 else ''
        return string, offset + length
    
    @staticmethod
    def pack_header(msg_type: MessageType, payload_length: int, num_items: int = 0) -> bytes:
        """Pack a message header into bytes"""
        try:
            if not isinstance(msg_type, MessageType):
                msg_type = MessageType(msg_type)
                
            header = struct.pack('!BII', msg_type.value, payload_length, num_items)
            return header
            
        except Exception as e:
            raise ValueError(f"Failed to pack header: {str(e)}")
            
    @staticmethod
    def unpack_header(data: bytes) -> Tuple[MessageType, int, int]:
        """Unpack a message header from bytes"""
        try:
            if len(data) < 9:
                raise ValueError(f"Insufficient header length: {len(data)} bytes received")
                
            header_data = data[:9]  # Only take the first 9 bytes for the header
            msg_type_val, payload_length, num_items = struct.unpack('!BII', header_data)
            if msg_type_val == 0:
                raise ValueError("Message type cannot be 0")
                
            try:
                msg_type = MessageType(msg_type_val)
            except ValueError:
                raise ValueError(f"{msg_type_val} is not a valid MessageType")
                
            return msg_type, payload_length, num_items
            
        except struct.error as e:
            raise ValueError(f"Failed to unpack header: {e}")
        except Exception as e:
            raise ValueError(f"Invalid header data: {str(e)}")

            
    @staticmethod
    def create_account_request(username: str, password: str) -> bytes:
        """Create an account creation request"""
        username_bytes = WireProtocol.pack_string(username)
        password_bytes = WireProtocol.pack_string(password)
        payload = username_bytes + password_bytes
        header = WireProtocol.pack_header(MessageType.CREATE_ACCOUNT, len(payload))
        return header + payload
    
    @staticmethod
    def login_request(username: str, password: str) -> bytes:
        """Create a login request"""
        username_bytes = WireProtocol.pack_string(username)
        password_bytes = WireProtocol.pack_string(password)
        payload = username_bytes + password_bytes
        header = WireProtocol.pack_header(MessageType.LOGIN, len(payload))
        return header + payload
    
    @staticmethod
    def list_accounts_request(pattern: Optional[str] = None) -> bytes:
        """Create a list accounts request"""
        pattern_bytes = WireProtocol.pack_string(pattern if pattern else '')
        header = WireProtocol.pack_header(MessageType.LIST_ACCOUNTS, len(pattern_bytes))
        return header + pattern_bytes
    
    @staticmethod
    def send_message_request(sender: str, recipient: str, content: str) -> bytes:
        """Create a send message request"""
        try:
            sender_bytes = WireProtocol.pack_string(sender)
            recipient_bytes = WireProtocol.pack_string(recipient)
            content_bytes = WireProtocol.pack_string(content)
            payload = sender_bytes + recipient_bytes + content_bytes
            header = WireProtocol.pack_header(MessageType.SEND_MESSAGE, len(payload))
            return header + payload
        except Exception as e:
            raise ValueError(f"Failed to create send message request: {str(e)}")
    
    @staticmethod
    def success_response(message: str, data: Optional[bytes] = None) -> bytes:
        """Create a success response"""
        message_bytes = WireProtocol.pack_string(message)
        payload = message_bytes + (data if data else b'')
        header = WireProtocol.pack_header(MessageType.SUCCESS, len(payload))
        return header + payload
    
    @staticmethod
    def error_response(message: str) -> bytes:
        """Create an error response"""
        try:
            message_bytes = WireProtocol.pack_string(message)
            header = WireProtocol.pack_header(MessageType.ERROR, len(message_bytes))
            return header + message_bytes
        except Exception as e:
            # Fallback error response if something goes wrong
            fallback_msg = "Internal error occurred"
            fallback_bytes = WireProtocol.pack_string(fallback_msg)
            header = WireProtocol.pack_header(MessageType.ERROR, len(fallback_bytes))
            return header + fallback_bytes
    
    @staticmethod
    def pack_message(msg_id: int, sender: str, recipient: str, content: str, 
                    timestamp: float, read: bool) -> bytes:
        """Pack a message into bytes"""
        try:
            result = bytearray()
            result.extend(struct.pack('!I', msg_id))
            result.extend(WireProtocol.pack_string(sender))
            result.extend(WireProtocol.pack_string(recipient))
            result.extend(WireProtocol.pack_string(content))
            result.extend(struct.pack('!d', timestamp))
            result.extend(struct.pack('!?', read))
            return bytes(result)
        except Exception as e:
            raise ValueError(f"Failed to pack message: {str(e)}")
    
    @staticmethod
    def unpack_message(data: bytes, offset: int = 0) -> Tuple[Dict, int]:
        """Unpack a message from bytes"""
        try:
            msg_id = struct.unpack('!I', data[offset:offset + 4])[0]
            offset += 4
            
            sender, offset = WireProtocol.unpack_string(data, offset)
            recipient, offset = WireProtocol.unpack_string(data, offset)
            content, offset = WireProtocol.unpack_string(data, offset)
            
            timestamp = struct.unpack('!d', data[offset:offset + 8])[0]
            offset += 8
            
            read = struct.unpack('!?', data[offset:offset + 1])[0]
            offset += 1
            
            return {
                'id': msg_id,
                'sender': sender,
                'recipient': recipient,
                'content': content,
                'timestamp': timestamp,
                'read': read
            }, offset
        except struct.error as e:
            raise ValueError(f"Failed to unpack message: {e}")
