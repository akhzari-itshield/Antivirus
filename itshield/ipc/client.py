"""IPC Client - connects to the ITShield core service.

The client is intentionally synchronous: every operation is a single
request/response round-trip. A future async client can be layered on top
once the GUI needs streamed progress updates for live scans.
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from itshield.config.settings import get_settings
from itshield.ipc.protocol import (
    HEADER_SIZE,
    Request,
    Response,
    decode_header,
    dict_to_struct,
    encode_message,
    parse_response,
    struct_to_dict,
)
from itshield.logging.logger import get_logger

logger = get_logger(__name__)


class IPCError(Exception):
    """Raised when the server returns a non-success Response."""

    def __init__(self, error_code: str, error_message: str, data: Optional[dict] = None) -> None:
        super().__init__(f"[{error_code}] {error_message}")
        self.error_code = error_code
        self.error_message = error_message
        self.data = data or {}


class IPCClient:
    """Synchronous request/response client for the ITShield core service."""

    def __init__(
        self,
        socket_path: Optional[str | Path] = None,
        connect_timeout: float = 2.0,
        read_timeout: float = 5.0,
    ) -> None:
        settings = get_settings()
        self.socket_path = Path(socket_path) if socket_path else settings.ipc_socket_resolved
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self._sock: Optional[socket.socket] = None

    def connect(self) -> None:
        if self._sock is not None:
            return
        if not self.socket_path.exists():
            raise ConnectionError(f"IPC socket not found: {self.socket_path}")

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.connect_timeout)
        sock.connect(str(self.socket_path))
        sock.settimeout(self.read_timeout)
        self._sock = sock
        logger.debug("Connected to IPC socket %s", self.socket_path)

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def __enter__(self) -> "IPCClient":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def call(self, operation: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send one request and return the ``data`` payload of the response.

        Raises :class:`IPCError` if the server returns ``success=False``.
        """
        if self._sock is None:
            self.connect()
        assert self._sock is not None

        req = Request()
        req.operation = operation
        if params:
            req.params.CopyFrom(dict_to_struct(params))

        try:
            self._sock.sendall(encode_message(req))
            resp = self._read_response()
        except (socket.timeout, ConnectionError, OSError) as exc:
            self.close()
            raise IPCError("TRANSPORT_ERROR", str(exc)) from exc

        data = struct_to_dict(resp.data) if resp.success else {}
        if not resp.success:
            raise IPCError(resp.error_code, resp.error_message, data)
        return data

    def _read_response(self) -> Response:
        header = self._recv_exactly(HEADER_SIZE)
        if header is None:
            raise ConnectionError("server closed before sending header")
        body_len, _ = decode_header(header)
        body = self._recv_exactly(body_len)
        if body is None:
            raise ConnectionError("server closed mid-response")
        return parse_response(body)

    def _recv_exactly(self, n: int) -> Optional[bytes]:
        assert self._sock is not None
        chunks = []
        remaining = n
        while remaining > 0:
            chunk = self._sock.recv(remaining)
            if not chunk:
                return None if not chunks else b"".join(chunks)
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def core_status(self) -> Dict[str, Any]:
        return self.call("core.status")

    def core_health(self) -> Dict[str, Any]:
        return self.call("core.health")

    def scan_request(self, target_path: str, recursive: bool = True) -> Dict[str, Any]:
        return self.call(
            "scan.request",
            params={"target_path": target_path, "recursive": str(recursive).lower()},
        )
