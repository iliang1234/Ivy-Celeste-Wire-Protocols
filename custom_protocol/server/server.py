import socket
import threading
import sqlite3
import argparse
import struct
from typing import Dict, Set, Optional
import logging
from pathlib import Path

from shared.constants import DEFAULT_HOST, DEFAULT_PORT, MessageType, ErrorCode, SuccessCode
from shared.security import verify_password, encode_bytes, decode_bytes
from custom_protocol.protocol import Protocol

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ChatServer:
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients = {}  # Dictionary to track connected clients
        self.accounts = {}  # Dictionary to store user accounts

    def start(self):
        """Start the chat server."""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        logger.info(f"Server listening on {self.host}:{self.port}")

        while True:
            client_socket, addr = self.server_socket.accept()
            logger.info(f"New connection from {addr}")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket: socket.socket):
        """Handle communication with a connected client."""
        username = None
        client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        try:
            while True:
                header = self.recv_all(client_socket, Protocol.HEADER_SIZE)
                if not header:
                    logger.info("Client disconnected (no header received).")
                    break  # Exit the loop if the client disconnected

                msg_type, payload_len, checksum = Protocol.parse_header(header)
                payload = self.recv_all(client_socket, payload_len)
                if not payload:
                    logger.info("Client disconnected during payload read.")
                    break  # Exit if payload could not be read

                if not Protocol.verify_checksum(payload, checksum):
                    logger.error("Checksum verification failed")
                    continue

                response = self.process_message(client_socket, msg_type, payload, username)
                if response:
                    packet = Protocol.create_packet(response[0], response[1])
                    try:
                        client_socket.sendall(packet)  # Ensure full packet is sent
                    except socket.error as e:
                        logger.error(f"Failed to send response: {e}")
                        break  # Stop processing if sending fails

                if msg_type == MessageType.DELETE_ACCOUNT and response[0] == MessageType.SUCCESS:
                    break  # Stop processing if account is deleted

        except Exception as e:
            logger.error(f"Error handling client: {e}")

        logger.info("Closing client connection.")
        client_socket.close()


    def process_message(self, client_socket: socket.socket, msg_type: int, payload: bytes, username: Optional[str]) -> tuple:
        """Process incoming messages and return a response tuple (MessageType, payload)."""
        if msg_type == MessageType.CREATE_ACCOUNT:
            return self.handle_create_account(payload)
        elif msg_type == MessageType.LOGIN:
            username = self.handle_login(payload, client_socket)
            return self.create_login_response(username)
        elif msg_type == MessageType.LIST_ACCOUNTS:
            return self.handle_list_accounts(payload)
        elif msg_type == MessageType.SEND_MESSAGE:
            return self.handle_send_message(payload, username)
        elif msg_type == MessageType.READ_MESSAGES:
            return self.handle_read_messages(payload, username)
        elif msg_type == MessageType.DELETE_MESSAGES:
            return self.handle_delete_messages(payload, username)
        elif msg_type == MessageType.DELETE_ACCOUNT:
            response = self.handle_delete_account(username)
            if response[0] == MessageType.SUCCESS:
                return response  # Account deleted, stop processing
        else:
            return (MessageType.ERROR, Protocol.create_packet(
                MessageType.ERROR,
                struct.pack("!H", ErrorCode.INVALID_REQUEST)
            ))

        return (MessageType.ERROR, struct.pack("!H", ErrorCode.INVALID_REQUEST))

    def recv_all(self, sock: socket.socket, length: int) -> bytes:
        """Receive a specific amount of bytes from a socket."""
        data = b""
        while len(data) < length:
            try:
                more = sock.recv(length - len(data))
                if not more:
                    logger.warning("⚠️ Client disconnected while receiving data.")
                    return b""  # Returning empty bytes signals a disconnect
                data += more
            except socket.error as e:
                logger.error(f"🚨 Socket error while receiving data: {e}")
                return b""
        return data


    def handle_create_account(self, payload: bytes) -> tuple:
        """Handles account creation."""
        username = payload.decode().strip()
        if username in self.accounts:
            return (MessageType.ERROR, Protocol.create_packet(
                MessageType.ERROR, struct.pack("!H", ErrorCode.ACCOUNT_EXISTS)
            ))

        self.accounts[username] = []
        return (MessageType.SUCCESS, Protocol.create_packet(MessageType.SUCCESS, b""))

    def handle_login(self, payload: bytes, client_socket: socket.socket) -> Optional[str]:
        """Handles user login."""
        username = payload.decode().strip()
        if username not in self.accounts:
            client_socket.send(Protocol.create_packet(
                MessageType.ERROR, struct.pack("!H", ErrorCode.INVALID_CREDENTIALS)
            ))
            return None

        self.clients[username] = client_socket
        return username

    def create_login_response(self, username: Optional[str]) -> tuple:
        """Returns the appropriate response after a login attempt."""
        if username:
            return (MessageType.SUCCESS, Protocol.create_packet(MessageType.SUCCESS, b""))
        return (MessageType.ERROR, Protocol.create_packet(
            MessageType.ERROR, struct.pack("!H", ErrorCode.INVALID_CREDENTIALS)
        ))

    def handle_list_accounts(self, payload: bytes) -> tuple:
        """Handles listing all accounts."""
        account_list = "\n".join(self.accounts.keys()).encode()
        return (MessageType.LIST_ACCOUNTS, Protocol.create_packet(MessageType.LIST_ACCOUNTS, account_list))

    def handle_send_message(self, payload: bytes, sender: Optional[str]) -> tuple:
        """Handles sending a message."""
        if not sender:
            return (MessageType.ERROR, Protocol.create_packet(
                MessageType.ERROR, struct.pack("!H", ErrorCode.NOT_LOGGED_IN)
            ))

        try:
            target_user, message = payload.decode().split("\n", 1)
            if target_user not in self.accounts:
                return (MessageType.ERROR, Protocol.create_packet(
                    MessageType.ERROR, struct.pack("!H", ErrorCode.USER_NOT_FOUND)
                ))

            self.accounts[target_user].append((sender, message))
            return (MessageType.SUCCESS, Protocol.create_packet(MessageType.SUCCESS, b""))
        except ValueError:
            return (MessageType.ERROR, Protocol.create_packet(
                MessageType.ERROR, struct.pack("!H", ErrorCode.INVALID_REQUEST)
            ))

    def handle_read_messages(self, payload: bytes, username: Optional[str]) -> tuple:
        """Handles reading messages."""
        if not username:
            return (MessageType.ERROR, Protocol.create_packet(
                MessageType.ERROR, struct.pack("!H", ErrorCode.NOT_LOGGED_IN)
            ))

        messages = self.accounts.get(username, [])
        message_data = "\n".join([f"{sender}: {msg}" for sender, msg in messages]).encode()
        self.accounts[username] = []  # Clear messages after reading
        return (MessageType.READ_MESSAGES, Protocol.create_packet(MessageType.READ_MESSAGES, message_data))

    def handle_delete_messages(self, payload: bytes, username: Optional[str]) -> tuple:
        """Handles deleting all messages."""
        if not username:
            return (MessageType.ERROR, Protocol.create_packet(
                MessageType.ERROR, struct.pack("!H", ErrorCode.NOT_LOGGED_IN)
            ))

        self.accounts[username] = []
        return (MessageType.SUCCESS, Protocol.create_packet(MessageType.SUCCESS, b""))

    def handle_delete_account(self, username: Optional[str]) -> tuple:
        """Handles account deletion."""
        if not username:
            return (MessageType.ERROR, Protocol.create_packet(
                MessageType.ERROR, struct.pack("!H", ErrorCode.NOT_LOGGED_IN)
            ))

        if username in self.accounts:
            del self.accounts[username]
        if username in self.clients:
            del self.clients[username]

        return (MessageType.SUCCESS, Protocol.create_packet(MessageType.SUCCESS, b""))


if __name__ == "__main__":
    server = ChatServer()
    server.start()
