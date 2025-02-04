"""JSON protocol implementation for the chat application."""

import json
import struct
from typing import Dict, Any, Optional
from ..shared.constants import MessageType

class Protocol:
    """
    JSON protocol format:
    
    Header (8 bytes):
    - Message length (4 bytes): Length of the JSON payload
    - Message type (4 bytes): Type of message
    
    Payload (variable length):
    - JSON encoded message
    """
    
    HEADER_FORMAT = "!II"  # network byte order, 2 unsigned ints
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
    
    @staticmethod
    def create_account_payload(username: str, password_hash: bytes) -> Dict[str, Any]:
        """Create account request payload."""
        return {
            "username": username,
            "password_hash": encode_bytes(password_hash)
        }
    
    @staticmethod
    def login_payload(username: str, password_hash: bytes) -> Dict[str, Any]:
        """Login request payload."""
        return Protocol.create_account_payload(username, password_hash)
    
    @staticmethod
    def list_accounts_payload(pattern: Optional[str] = None) -> Dict[str, Any]:
        """List accounts request payload."""
        return {"pattern": pattern} if pattern else {}
    
    @staticmethod
    def send_message_payload(recipient: str, message: str) -> Dict[str, Any]:
        """Send message request payload."""
        return {
            "recipient": recipient,
            "message": message
        }
    
    @staticmethod
    def read_messages_payload(count: Optional[int] = None) -> Dict[str, Any]:
        """Read messages request payload."""
        return {"count": count} if count is not None else {}
    
    @staticmethod
    def delete_messages_payload(message_ids: list[int]) -> Dict[str, Any]:
        """Delete messages request payload."""
        return {"message_ids": message_ids}
    
    @staticmethod
    def delete_account_payload() -> Dict[str, Any]:
        """Delete account request payload."""
        return {}
    
    @staticmethod
    def error_payload(error_code: int, message: str) -> Dict[str, Any]:
        """Error response payload."""
        return {
            "error_code": error_code,
            "message": message
        }
    
    @staticmethod
    def success_payload(success_code: int, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Success response payload."""
        payload = {"success_code": success_code}
        if data:
            payload.update(data)
        return payload
    
    @staticmethod
    def create_packet(msg_type: int, payload: Dict[str, Any]) -> bytes:
        """Create a complete packet with header and JSON payload."""
        json_payload = json.dumps(payload).encode()
        header = struct.pack(Protocol.HEADER_FORMAT, len(json_payload), msg_type)
        return header + json_payload
    
    @staticmethod
    def parse_header(header: bytes) -> tuple[int, int]:
        """Parse packet header, return (payload_length, message_type)."""
        return struct.unpack(Protocol.HEADER_FORMAT, header)
