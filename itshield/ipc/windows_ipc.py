"""Windows Named Pipe IPC transport (Phase 15).

Section 13.3 of the architecture document.

On Windows, the IPC server listens on a Named Pipe (``\\\\.\\pipe\\itshield``)
instead of a Unix Domain Socket. The wire format (4-byte length-prefixed
Protobuf) is identical so the protocol layer is shared between platforms.

This module uses ``pywin32`` (win32pipe, win32file, win32security) which
is an optional dependency on Windows. On Linux the module imports
gracefully skip the Windows-specific imports so the rest of the codebase
remains importable.
"""

from __future__ import annotations

import os
import struct
import sys
import threading
from pathlib import Path
from typing import Optional

from itshield.config.settings import get_settings
from itshield.ipc.handlers import HandlerRegistry, make_default_registry
from itshield.ipc.protocol import (
    HEADER_SIZE,
    decode_header,
    encode_message,
    parse_request,
)
from itshield.logging.logger import get_logger

logger = get_logger(__name__)

_IS_WINDOWS = sys.platform == "win32"

if _IS_WINDOWS:
    try:
        import win32pipe
        import win32file
        import win32security
        import pywintypes
        _PYWIN32_AVAILABLE = True
    except ImportError:
        _PYWIN32_AVAILABLE = False
        logger.warning(
            "pywin32 not installed on Windows; Named Pipe IPC unavailable. "
            "Install with: pip install pywin32"
        )
else:
    _PYWIN32_AVAILABLE = False


class WindowsIPCServer:
    """Named Pipe IPC server for Windows.

    Creates a pipe at ``\\\\.\\pipe\\itshield`` with a security
    descriptor that restricts access to the running user. Accepts
    connections in a background thread and dispatches requests through
    a :class:`HandlerRegistry`.
    """

    PIPE_NAME = r"\\.\pipe\itshield"
    BUFFER_SIZE = 64 * 1024

    def __init__(
        self,
        core_manager,
        pipe_name: Optional[str] = None,
        registry: Optional[HandlerRegistry] = None,
    ) -> None:
        self.core_manager = core_manager
        self.pipe_name = pipe_name or self.PIPE_NAME
        self.registry = registry or make_default_registry(core_manager)
        self._pipe_handle = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._connections: list[threading.Thread] = []

    def start(self) -> None:
        if not _IS_WINDOWS or not _PYWIN32_AVAILABLE:
            raise RuntimeError(
                "WindowsIPCServer requires Windows with pywin32 installed."
            )
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._accept_loop, name="win-ipc-accept", daemon=True
        )
        self._thread.start()
        logger.info("Windows IPC server listening on %s", self.pipe_name)

    def stop(self) -> None:
        self._stop_event.set()
        if self._pipe_handle is not None:
            try:
                win32pipe.DisconnectNamedPipe(self._pipe_handle)
                win32file.CloseHandle(self._pipe_handle)
            except Exception:
                pass
            self._pipe_handle = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        logger.info("Windows IPC server stopped")

    def _accept_loop(self) -> None:
        assert _PYWIN32_AVAILABLE
        while not self._stop_event.is_set():
            try:
                sa = win32security.SECURITY_ATTRIBUTES()
                sa.bInheritHandle = False
                handle = win32pipe.CreateNamedPipe(
                    self.pipe_name,
                    win32pipe.PIPE_ACCESS_DUPLEX,
                    win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_WAIT,
                    1,                # max instances
                    self.BUFFER_SIZE,
                    self.BUFFER_SIZE,
                    0,                # default timeout
                    sa,
                )
                self._pipe_handle = handle
                win32pipe.ConnectNamedPipe(handle, None)
                if self._stop_event.is_set():
                    break
                t = threading.Thread(
                    target=self._handle_connection,
                    args=(handle,),
                    daemon=True,
                )
                self._connections.append(t)
                t.start()
            except Exception:
                if not self._stop_event.is_set():
                    logger.exception("Windows IPC accept error")

    def _handle_connection(self, handle) -> None:
        assert _PYWIN32_AVAILABLE
        try:
            while not self._stop_event.is_set():
                header = self._read_exactly(handle, HEADER_SIZE)
                if header is None:
                    break
                body_len, _ = decode_header(header)
                body = self._read_exactly(handle, body_len)
                if body is None:
                    break
                req = parse_request(body)
                response = self.registry.handle(req)
                win32file.WriteFile(handle, encode_message(response))
        except Exception:
            logger.debug("Windows IPC connection closed")
        finally:
            try:
                win32pipe.DisconnectNamedPipe(handle)
                win32file.CloseHandle(handle)
            except Exception:
                pass

    @staticmethod
    def _read_exactly(handle, n: int) -> Optional[bytes]:
        assert _PYWIN32_AVAILABLE
        chunks = []
        remaining = n
        while remaining > 0:
            try:
                result, data = win32file.ReadFile(handle, remaining)
                if result != 0 or not data:
                    return None
                chunks.append(data)
                remaining -= len(data)
            except Exception:
                return None
        return b"".join(chunks)


class WindowsIPCClient:
    """Named Pipe IPC client for Windows."""

    def __init__(
        self,
        pipe_name: Optional[str] = None,
        timeout: float = 5.0,
    ) -> None:
        self.pipe_name = pipe_name or WindowsIPCServer.PIPE_NAME
        self.timeout = timeout
        self._handle = None

    def connect(self) -> None:
        if not _IS_WINDOWS or not _PYWIN32_AVAILABLE:
            raise RuntimeError(
                "WindowsIPCClient requires Windows with pywin32 installed."
            )
        assert _PYWIN32_AVAILABLE
        self._handle = win32file.CreateFile(
            self.pipe_name,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0,              # no sharing
            None,           # default security
            win32file.OPEN_EXISTING,
            0,              # default attributes
            None,           # no template
        )

    def close(self) -> None:
        if self._handle is not None:
            try:
                win32file.CloseHandle(self._handle)
            except Exception:
                pass
            self._handle = None

    def call(self, operation: str, params: Optional[dict] = None) -> dict:
        """Send a request and return the response data dict."""
        from itshield.ipc.protocol import Request, Response, dict_to_struct, struct_to_dict
        assert _PYWIN32_AVAILABLE
        if self._handle is None:
            self.connect()
        req = Request()
        req.operation = operation
        if params:
            req.params.CopyFrom(dict_to_struct(params))
        win32file.WriteFile(self._handle, encode_message(req))
        header = self._recv_exactly(HEADER_SIZE)
        body_len, _ = decode_header(header)
        body = self._recv_exactly(body_len)
        resp = Response()
        resp.ParseFromString(body)
        data = struct_to_dict(resp.data) if resp.success else {}
        if not resp.success:
            from itshield.ipc.client import IPCError
            raise IPCError(resp.error_code, resp.error_message, data)
        return data

    def _recv_exactly(self, n: int) -> bytes:
        assert _PYWIN32_AVAILABLE
        chunks = []
        remaining = n
        while remaining > 0:
            result, data = win32file.ReadFile(self._handle, remaining)
            if not data:
                break
            chunks.append(data)
            remaining -= len(data)
        return b"".join(chunks)
