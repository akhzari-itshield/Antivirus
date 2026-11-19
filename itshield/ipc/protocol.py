"""Protocol module for ITShield IPC.

Contains:
    * the generated Protobuf Python bindings (``protocol_pb2``)
    * frame helpers for the 4-byte length-prefixed wire format

The generated module is produced at build time from ``protocol.proto``::

    python -m grpc_tools.protoc \\
        --proto_path=itshield/ipc \\
        --python_out=itshield/ipc \\
        itshield/ipc/protocol.proto

For developer convenience, if the generated module is missing we try to
generate it on the fly from the .proto file.
"""

from __future__ import annotations

import importlib
import os
import struct
import sys
from pathlib import Path
from typing import Tuple

from google.protobuf.struct_pb2 import Struct  # always available
from google.protobuf.json_format import MessageToDict, ParseDict

from itshield.logging.logger import get_logger

logger = get_logger(__name__)

_pb2 = None
try:
    _pb2 = importlib.import_module("itshield.ipc.protocol_pb2")
except ImportError:
    _proto_path = Path(__file__).resolve().parent / "protocol.proto"
    _out_dir = Path(__file__).resolve().parent
    try:
        from grpc_tools import protoc as _protoc  # type: ignore[import-not-found]
        rc = _protoc.main([
            "protoc",
            f"--proto_path={_out_dir}",
            f"--python_out={_out_dir}",
            str(_proto_path),
        ])
        if rc == 0:
            importlib.invalidate_caches()
            _pb2 = importlib.import_module("itshield.ipc.protocol_pb2")
            logger.info("Generated protocol_pb2.py on the fly from %s", _proto_path)
        else:
            logger.error("protoc returned %d while generating protocol_pb2.py", rc)
    except Exception:
        logger.exception("Failed to generate protocol_pb2.py on the fly")

if _pb2 is None:
    raise RuntimeError(
        "itshield.ipc.protocol_pb2 not available and could not be generated. "
        "Run: python -m grpc_tools.protoc --proto_path=itshield/ipc "
        "--python_out=itshield/ipc itshield/ipc/protocol.proto"
    )

Request = _pb2.Request
Response = _pb2.Response

_HEADER_FORMAT = "!I"  # 4-byte big-endian unsigned int
_HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)


def max_message_size() -> int:
    """Return the configured maximum message size (default 1 MiB)."""
    from itshield.config.settings import get_settings
    return get_settings().ipc_max_message_size


def encode_message(message) -> bytes:
    """Serialize a Protobuf message and prepend the 4-byte length header."""
    body = message.SerializeToString()
    if len(body) > max_message_size():
        raise ValueError(
            f"Message too large: {len(body)} > {max_message_size()} bytes"
        )
    return struct.pack(_HEADER_FORMAT, len(body)) + body


def decode_header(data: bytes) -> Tuple[int, int]:
    """Given at least 4 bytes, return (body_length, header_size)."""
    if len(data) < _HEADER_SIZE:
        raise ValueError(f"Need at least {_HEADER_SIZE} bytes for header; got {len(data)}")
    (body_length,) = struct.unpack(_HEADER_FORMAT, data[:_HEADER_SIZE])
    if body_length > max_message_size():
        raise ValueError(
            f"Declared body length {body_length} exceeds max {max_message_size()}"
        )
    return body_length, _HEADER_SIZE


def parse_request(data: bytes) -> Request:
    """Deserialize a Request from its raw body bytes (no header)."""
    req = Request()
    req.ParseFromString(data)
    return req


def parse_response(data: bytes) -> Response:
    """Deserialize a Response from its raw body bytes (no header)."""
    resp = Response()
    resp.ParseFromString(data)
    return resp


def dict_to_struct(value: dict) -> Struct:
    """Convert a Python dict into a ``google.protobuf.Struct``."""
    s = Struct()
    ParseDict(value, s)
    return s


def struct_to_dict(s: Struct) -> dict:
    """Convert a ``google.protobuf.Struct`` into a Python dict."""
    return MessageToDict(s, preserving_proto_field_name=True)


HEADER_SIZE = _HEADER_SIZE
