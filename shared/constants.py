"""Constants shared between custom and JSON protocol implementations."""

# Network constants
DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 8000
BUFFER_SIZE = 4096

# Protocol message types
class MessageType:
    CREATE_ACCOUNT = 1
    LOGIN = 2
    LIST_ACCOUNTS = 3
    SEND_MESSAGE = 4
    READ_MESSAGES = 5
    DELETE_MESSAGES = 6
    DELETE_ACCOUNT = 7
    ERROR = 8
    SUCCESS = 9

# Error codes
class ErrorCode:
    USERNAME_EXISTS = 101
    INVALID_CREDENTIALS = 102
    USER_NOT_FOUND = 103
    NOT_LOGGED_IN = 104
    INVALID_REQUEST = 105
    SERVER_ERROR = 106

# Success codes
class SuccessCode:
    ACCOUNT_CREATED = 201
    LOGIN_SUCCESS = 202
    MESSAGE_SENT = 203
    MESSAGES_READ = 204
    MESSAGES_DELETED = 205
    ACCOUNT_DELETED = 206
    ACCOUNTS_LISTED = 207
