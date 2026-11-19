"""IPC package for ITShield."""

from itshield.ipc.protocol import (
    Request,
    Response,
    encode_message,
    decode_header,
    parse_request,
    parse_response,
    dict_to_struct,
    struct_to_dict,
    HEADER_SIZE,
)
from itshield.ipc.handlers import HandlerRegistry, handle_request
from itshield.ipc.server import IPCServer
from itshield.ipc.client import IPCClient, IPCError

__all__ = [
    "Request",
    "Response",
    "encode_message",
    "decode_header",
    "parse_request",
    "parse_response",
    "dict_to_struct",
    "struct_to_dict",
    "HEADER_SIZE",
    "HandlerRegistry",
    "handle_request",
    "IPCServer",
    "IPCClient",
    "IPCError",
]
