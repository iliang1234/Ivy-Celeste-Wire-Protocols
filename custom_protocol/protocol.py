"""Custom wire protocol implementation for the chat application."""

import struct
from typing import Tuple, List, Optional
from shared.constants import MessageType

class Protocol:
    """
    Custom wire protocol format:
    
    Header (9 bytes total):
    - Magic number (2 bytes): 0xC4A7
    - Message type (1 byte)
    - Payload length (4 bytes)
    - Checksum (2 bytes): CRC16 of payload
    
    Payload (variable length):
    - Format depends on message type
    """
    
    MAGIC_NUMBER = 0xC4A7
    HEADER_FORMAT = "!HBIH"  # network byte order, unsigned short, unsigned char, unsigned int, unsigned short
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
    
    @staticmethod
    def create_account_payload(username: str, password_hash: bytes) -> bytes:
        """Create account request payload."""
        username_len = len(username)
        fmt = f"!H{username_len}sI{len(password_hash)}s"
        return struct.pack(fmt, username_len, username.encode(), len(password_hash), password_hash)
    
    @staticmethod
    def login_payload(username: str, password_hash: bytes) -> bytes:
        """Login request payload."""
        return Protocol.create_account_payload(username, password_hash)
    
    @staticmethod
    def list_accounts_payload(pattern: Optional[str] = None) -> bytes:
        """List accounts request payload."""
        if pattern is None:
            return struct.pack("!H", 0)
        pattern_len = len(pattern)
        return struct.pack(f"!H{pattern_len}s", pattern_len, pattern.encode())
    
    @staticmethod
    def send_message_payload(recipient: str, message: bytes) -> bytes:
        """Send message request payload."""
        recipient_len = len(recipient)
        fmt = f"!H{recipient_len}sI{len(message)}s"
        return struct.pack(fmt, recipient_len, recipient.encode(), len(message), message)
    
    @staticmethod
    def read_messages_payload(count: Optional[int] = None) -> bytes:
        """Read messages request payload."""
        return struct.pack("!I", count if count is not None else 0)
    
    @staticmethod
    def delete_messages_payload(message_ids: List[int]) -> bytes:
        """Delete messages request payload."""
        count = len(message_ids)
        fmt = f"!I{count}I"
        return struct.pack(fmt, count, *message_ids)
    
    @staticmethod
    def delete_account_payload() -> bytes:
        """Delete account request payload (empty)."""
        return b""
    
    @staticmethod
    def calculate_checksum(payload: bytes) -> int:
        """Calculate CRC16 checksum of payload."""
        crc = 0xFFFF
        for b in payload:
            crc ^= b
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc >>= 1
        return crc
    
    @staticmethod
    def create_packet(msg_type: int, payload: bytes) -> bytes:
        """Create a complete packet with header and payload."""
        if not isinstance(payload, bytes):
            raise ValueError("Payload must be bytes")
        
        checksum = Protocol.calculate_checksum(payload)
        header = struct.pack(Protocol.HEADER_FORMAT,
                           Protocol.MAGIC_NUMBER,
                           msg_type,
                           len(payload),
                           checksum)
        return header + payload
    
    @staticmethod
    def parse_header(header: bytes) -> Tuple[int, int, int]:
        """Parse packet header, return (message_type, payload_length, checksum)."""
        magic, msg_type, payload_len, checksum = struct.unpack(Protocol.HEADER_FORMAT, header)
        if magic != Protocol.MAGIC_NUMBER:
            raise ValueError("Invalid magic number")
        return msg_type, payload_len, checksum
    
    @staticmethod
    def verify_checksum(payload: bytes, expected_checksum: int) -> bool:
        """Verify payload checksum."""
        return Protocol.calculate_checksum(payload) == expected_checksum
