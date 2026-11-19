"""Hash Engine - SHA-256 computation for scanned files.

Section 9.2 of the architecture document.

Files are read in fixed-size chunks so that scanning a multi-gigabyte file
does not load it entirely into memory. The chunk size is configurable via
:class:`Settings`.

The pure-Python ``hashlib`` implementation is used here. A Rust-backed
implementation is provided under ``native/rust`` and can be swapped in via
``HashEngine(backend="rust")`` once :mod:`itshield_native` is built with
maturin. If the Rust extension is not importable, the engine transparently
falls back to the Python implementation.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional

from itshield.config.settings import get_settings
from itshield.logging.logger import get_logger

logger = get_logger(__name__)


class HashEngine:
    """Compute SHA-256 (and optionally MD5) digests of arbitrary files."""

    SUPPORTED_ALGORITHMS = ("sha256", "sha1", "md5")

    def __init__(
        self,
        algorithm: str = "sha256",
        chunk_size: Optional[int] = None,
        backend: str = "auto",
    ) -> None:
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Unsupported hash algorithm: {algorithm}. "
                f"Supported: {self.SUPPORTED_ALGORITHMS}"
            )
        self.algorithm = algorithm
        settings = get_settings()
        self.chunk_size = chunk_size or settings.scanner_chunk_size
        self._backend_name = backend
        self._rust_backend = None

        if backend in ("auto", "rust"):
            self._rust_backend = self._try_load_rust_backend()
            if self._rust_backend is not None:
                logger.info("HashEngine using Rust backend (itshield_native)")
            elif backend == "rust":
                logger.warning(
                    "Rust backend requested but itshield_native not available; "
                    "falling back to Python hashlib"
                )

    @staticmethod
    def _try_load_rust_backend():
        """Attempt to import the Rust extension built with PyO3/Maturin."""
        try:
            import itshield_native  # type: ignore[import-not-found]

            if hasattr(itshield_native, "sha256_file"):
                return itshield_native
        except ImportError:
            return None
        return None

    @property
    def backend(self) -> str:
        return "rust" if self._rust_backend else "python"

    def hash_file(self, path: str | Path, max_file_size: Optional[int] = None) -> str:
        """Return the hex digest of ``path`` using the configured algorithm.

        Args:
            path: File to hash.
            max_file_size: If set, raises ValueError when the file exceeds
                this many bytes. Protects against DoS via huge files.

        Raises:
            FileNotFoundError: file doesn't exist.
            IsADirectoryError: path is a directory.
            ValueError: file exceeds max_file_size (if provided).
            OSError: permission denied or other I/O error.
        """
        path = Path(path)
        if max_file_size is not None:
            try:
                actual_size = path.stat().st_size
            except OSError as exc:
                raise FileNotFoundError(f"Cannot stat file: {path}: {exc}")
            if actual_size > max_file_size:
                raise ValueError(
                    f"File too large: {actual_size} > {max_file_size} bytes: {path}"
                )

        if self.algorithm != "sha256":
            return self._hash_python(path)

        if self._rust_backend is not None:
            try:
                return self._rust_backend.sha256_file(str(path))
            except Exception:
                logger.exception(
                    "Rust sha256_file failed; falling back to Python for %s", path
                )
        return self._hash_python(path)

    def _hash_python(self, path: Path) -> str:
        """Pure-Python chunked hashing implementation."""
        hasher = hashlib.new(self.algorithm)
        try:
            with path.open("rb") as fh:
                while True:
                    chunk = fh.read(self.chunk_size)
                    if not chunk:
                        break
                    hasher.update(chunk)
        except FileNotFoundError:
            raise
        except IsADirectoryError:
            raise
        except PermissionError as exc:
            raise OSError(f"Permission denied reading {path}: {exc}")
        except OSError as exc:
            raise OSError(f"Error reading {path}: {exc}")
        return hasher.hexdigest()

    def hash_bytes(self, data: bytes) -> str:
        """Convenience helper for hashing in-memory bytes (used by tests)."""
        return hashlib.new(self.algorithm, data).hexdigest()
