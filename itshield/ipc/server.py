"""IPC Server - listens on a Unix Domain Socket (Linux) and serves requests.

Section 13.2 of the architecture document.

The server:
    * binds to ``$XDG_RUNTIME_DIR/itshield.sock`` (or /tmp fallback)
    * accepts connections in a background thread
    * per connection: reads a 4-byte length-prefixed Request, dispatches it
      through a :class:`HandlerRegistry`, writes back a length-prefixed Response
    * authenticates the peer via SO_PEERCRED on Linux (uid check)
    * enforces the 1 MiB max message size

A Windows Named Pipe transport is described in section 13.3 but not
implemented here. ``pywin32`` would be required and we are on Linux.
"""

from __future__ import annotations

import os
import socket
import struct
import threading
from pathlib import Path
from typing import Optional

from itshield.config.settings import get_settings
from itshield.ipc.handlers import HandlerRegistry, make_default_registry
from itshield.ipc.protocol import (
    HEADER_SIZE,
    decode_header,
    encode_message,
    max_message_size,
    parse_request,
)
from itshield.logging.logger import get_logger

logger = get_logger(__name__)


class IPCServer:
    """Length-prefixed Protobuf IPC over Unix Domain Socket."""

    def __init__(
        self,
        core_manager,
        socket_path: Optional[str | Path] = None,
        registry: Optional[HandlerRegistry] = None,
        allow_uids: Optional[list[int]] = None,
    ) -> None:
        self.core_manager = core_manager
        settings = get_settings()
        self.socket_path = Path(socket_path) if socket_path else settings.ipc_socket_resolved
        self.registry = registry or make_default_registry(core_manager)
        self.allow_uids = allow_uids

        self._sock: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._connections: list[threading.Thread] = []

    def start(self) -> None:
        """Bind the socket and start accepting connections in background."""
        if self._sock is not None:
            logger.warning("IPCServer.start() called while already running")
            return

        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except OSError:
                logger.warning("Could not remove stale socket %s", self.socket_path)

        self.socket_path.parent.mkdir(parents=True, exist_ok=True)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        sock.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o660)
        sock.listen(16)
        self._sock = sock
        self._stop_event.clear()

        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="ipc-accept", daemon=True
        )
        self._accept_thread.start()
        logger.info("IPC server listening on %s", self.socket_path)

    def stop(self) -> None:
        """Stop accepting, close the socket and join worker threads."""
        if self._sock is None:
            return
        self._stop_event.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._sock = None

        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2.0)
            self._accept_thread = None

        for t in list(self._connections):
            if t.is_alive():
                t.join(timeout=1.0)
        self._connections.clear()

        try:
            if self.socket_path.exists():
                self.socket_path.unlink()
        except OSError:
            pass
        logger.info("IPC server stopped")

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop_event.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop_event.is_set():
                    break
                logger.exception("accept() failed; retrying")
                continue

            t = threading.Thread(
                target=self._handle_connection,
                args=(conn,),
                name="ipc-conn",
                daemon=True,
            )
            self._connections.append(t)
            t.start()

        self._connections = [t for t in self._connections if t.is_alive()]

    def _handle_connection(self, conn: socket.socket) -> None:
        try:
            self._authenticate(conn)
            while not self._stop_event.is_set():
                req = self._read_request(conn)
                if req is None:
                    break
                response = self.registry.handle(req)
                conn.sendall(encode_message(response))
        except (ConnectionError, OSError) as exc:
            logger.debug("Connection closed: %s", exc)
        except Exception:
            logger.exception("Error handling IPC connection")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _authenticate(self, conn: socket.socket) -> None:
        """Verify the peer uid via SO_PEERCRED on Linux."""
        if self.allow_uids is None:
            return  # open policy (used by tests and single-user dev)

        try:
            cred = conn.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("iII")
            )
            _, uid, _ = struct.unpack("iII", cred)
        except (AttributeError, OSError) as exc:
            logger.warning("SO_PEERCRED unavailable (%s); rejecting connection", exc)
            raise ConnectionError("peer credential check unavailable")

        if uid not in self.allow_uids:
            logger.warning("IPC connection rejected: uid %d not in allow_uids", uid)
            raise ConnectionError(f"peer uid {uid} not allowed")

    def _read_request(self, conn: socket.socket):
        """Read one length-prefixed Request; return None on clean EOF."""
        header = self._recv_exactly(conn, HEADER_SIZE)
        if header is None:
            return None
        body_len, _ = decode_header(header)
        body = self._recv_exactly(conn, body_len)
        if body is None:
            logger.warning("Connection closed mid-message")
            return None
        return parse_request(body)

    @staticmethod
    def _recv_exactly(conn: socket.socket, n: int) -> Optional[bytes]:
        """Read exactly ``n`` bytes; return None on EOF before any byte."""
        chunks = []
        remaining = n
        while remaining > 0:
            try:
                chunk = conn.recv(remaining)
            except socket.timeout:
                continue
            if not chunk:
                return None if not chunks else b"".join(chunks)
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def __enter__(self) -> "IPCServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
