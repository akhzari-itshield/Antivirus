"""Request handlers for the ITShield IPC protocol.

Section 13.4 of the architecture document defines the operations supported
by version 1 of the protocol:

    core.status    -> full status dict (every module, every state)
    core.health    -> compact health summary
    scan.request   -> NOT IMPLEMENTED in this version; returns
                      SCANNER_NOT_IMPLEMENTED so the GUI can show a clean
                      error instead of a silent failure.

Handlers are registered in a :class:`HandlerRegistry` so adding a new
operation is a one-line registration. Each handler takes the parsed
:class:`Request` and returns a :class:`Response`.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from itshield.ipc.protocol import Request, Response, dict_to_struct, struct_to_dict
from itshield.logging.logger import get_logger

logger = get_logger(__name__)

Handler = Callable[[Request], Response]


class HandlerRegistry:
    """Maps operation names to handler callables."""

    def __init__(self) -> None:
        self._handlers: Dict[str, Handler] = {}

    def register(self, operation: str, handler: Handler) -> None:
        if operation in self._handlers:
            raise ValueError(f"Operation already registered: {operation}")
        self._handlers[operation] = handler
        logger.debug("Registered IPC handler for %s", operation)

    def __contains__(self, operation: str) -> bool:
        return operation in self._handlers

    def handle(self, req: Request) -> Response:
        """Dispatch ``req`` to its handler; return an error Response if unknown."""
        op = req.operation
        if not op or len(op) > 64 or not op.replace(".", "").replace("_", "").isalnum():
            logger.warning("Invalid IPC operation name: %r", op[:32] if op else "None")
            return _error_response(
                req,
                error_code="INVALID_OPERATION",
                error_message="Operation name is missing or malformed",
            )
        handler = self._handlers.get(op)
        if handler is None:
            logger.warning("Unknown IPC operation: %s", op)
            return _error_response(
                req,
                error_code="UNKNOWN_OPERATION",
                error_message=f"Unknown operation: {op}",
            )
        try:
            return handler(req)
        except Exception as exc:
            logger.exception("Handler for %s raised", op)
            return _error_response(
                req,
                error_code="HANDLER_EXCEPTION",
                error_message="Internal handler error (see server logs for details)",
            )


def _ok_response(req: Request, data: Dict[str, Any]) -> Response:
    """Build a successful Response with ``data`` as its Struct payload."""
    resp = Response()
    resp.success = True
    resp.error_code = "OK"
    resp.error_message = ""
    resp.data.CopyFrom(dict_to_struct(data))
    return resp


def _error_response(
    req: Request,
    error_code: str,
    error_message: str,
    data: Optional[Dict[str, Any]] = None,
) -> Response:
    """Build a failure Response."""
    resp = Response()
    resp.success = False
    resp.error_code = error_code
    resp.error_message = error_message
    if data:
        resp.data.CopyFrom(dict_to_struct(data))
    return resp


def make_default_registry(core_manager) -> HandlerRegistry:
    """Build a registry wired to the given :class:`CoreManager`."""
    registry = HandlerRegistry()
    registry.register("core.status", _make_status_handler(core_manager))
    registry.register("core.health", _make_health_handler(core_manager))
    registry.register("scan.request", _make_scan_request_handler())
    return registry


def _make_status_handler(core_manager):
    def _handler(req: Request) -> Response:
        return _ok_response(req, core_manager.status())

    return _handler


def _make_health_handler(core_manager):
    def _handler(req: Request) -> Response:
        return _ok_response(req, core_manager.health())

    return _handler


def _make_scan_request_handler():
    """Returns SCANNER_NOT_IMPLEMENTED, matching the document section 13.4."""

    def _handler(req: Request) -> Response:
        params = struct_to_dict(req.params) if req.params.fields else {}
        logger.info(
            "scan.request received (params=%s); returning SCANNER_NOT_IMPLEMENTED",
            params,
        )
        return _error_response(
            req,
            error_code="SCANNER_NOT_IMPLEMENTED",
            error_message=(
                "Scanner is not wired to the IPC layer yet. "
                "Use the CLI (test_scanner.py) for now."
            ),
            data={"requested_params": params} if params else None,
        )

    return _handler


def handle_request(registry: HandlerRegistry, req: Request) -> Response:
    return registry.handle(req)
