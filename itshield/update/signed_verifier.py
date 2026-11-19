"""Ed25519 signed update verification (Phase 11).

Section 19 of the architecture document - "Signed Updates".

Phase 8 added SHA-256 *integrity* verification. Phase 11 adds Ed25519
*authenticity* verification so the user can be sure a signature bank or
YARA rule pack was produced by the ITShield team (or whoever holds the
private key) and not tampered with in transit.

Components:
    * :class:`KeyPair`       - Ed25519 private/public key pair (generate/load)
    * :class:`UpdateSigner`  - sign a bank file with a private key
    * :class:`SignedVerifier`- verify a bank file against a public key

Key format: PEM-encoded (PKCS8 for private, SubjectPublicKeyInfo for
public). Keys live on disk so the signing key never ships with the
product; only the public key is bundled for verification.

Signature storage: a ``.sig`` sidecar file next to the bank, containing
the base64-encoded Ed25519 signature of the bank file's SHA-256 hash.
Signing the hash (not the file) keeps signatures small and lets us
reuse the same signature when the bank is re-hashed.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from itshield.logging.logger import get_logger

logger = get_logger(__name__)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    _CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    _CRYPTOGRAPHY_AVAILABLE = False
    logger.warning(
        "cryptography package not available; Ed25519 signing/verification disabled. "
        "Install with: pip install cryptography"
    )


@dataclass
class KeyPair:
    """An Ed25519 key pair."""

    private_pem: bytes        # PEM-encoded private key (PKCS8, no encryption)
    public_pem: bytes         # PEM-encoded public key (SubjectPublicKeyInfo)


@dataclass
class VerifyResult:
    """Outcome of a signature verification."""

    ok: bool
    status: str               # OK / NO_SIGNATURE / INVALID_SIGNATURE / KEY_ERROR / NO_CRYPTO
    detail: str = ""
    bank_sha256: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "status": self.status,
            "detail": self.detail,
            "bank_sha256": self.bank_sha256,
        }


def generate_keypair() -> KeyPair:
    """Generate a fresh Ed25519 key pair. Returns PEM-encoded keys."""
    if not _CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError(
            "cryptography package not installed. Run: pip install cryptography"
        )
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return KeyPair(private_pem=priv_pem, public_pem=pub_pem)


def save_keypair(pair: KeyPair, private_path: Path, public_path: Path) -> None:
    """Write the key pair to disk. Sets private key file mode 0600."""
    private_path = Path(private_path)
    public_path = Path(public_path)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(pair.private_pem)
    public_path.write_bytes(pair.public_pem)
    try:
        import os
        os.chmod(private_path, 0o600)
    except OSError:
        pass
    logger.info("Saved Ed25519 keypair: private=%s, public=%s", private_path, public_path)


def load_private_key(path: str | Path) -> "Ed25519PrivateKey":
    """Load a PEM-encoded Ed25519 private key."""
    if not _CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError("cryptography package not installed")
    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def load_public_key(path: str | Path) -> "Ed25519PublicKey":
    """Load a PEM-encoded Ed25519 public key."""
    if not _CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError("cryptography package not installed")
    data = Path(path).read_bytes()
    return serialization.load_pem_public_key(data)


class UpdateSigner:
    """Sign a signature bank file with an Ed25519 private key.

    Produces a ``<bank_path>.sig`` sidecar file containing the base64
    signature of the bank's SHA-256 hash.
    """

    def __init__(self, private_key_path: str | Path) -> None:
        self._priv = load_private_key(private_key_path)

    def sign_file(self, file_path: str | Path) -> Tuple[str, str]:
        """Sign ``file_path``. Returns (sha256_hex, signature_b64)."""
        file_path = Path(file_path)
        sha = _hash_file(file_path)
        sig = self._priv.sign(sha.encode("ascii"))
        sig_b64 = base64.b64encode(sig).decode("ascii")
        return sha, sig_b64

    def sign_and_write(self, file_path: str | Path) -> Path:
        """Sign the file and write the ``.sig`` sidecar. Returns the sidecar path."""
        sha, sig_b64 = self.sign_file(file_path)
        sig_path = Path(str(file_path) + ".sig")
        sig_path.write_text(sig_b64, encoding="ascii")
        logger.info("Wrote signature sidecar %s (sha256=%s..)", sig_path, sha[:12])
        return sig_path


class SignedVerifier:
    """Verify a signature bank file against a public key.

    The ``.sig`` sidecar must exist next to the bank file. Its content is
    the base64-encoded Ed25519 signature of the bank's SHA-256 hash.
    """

    def __init__(self, public_key_path: str | Path) -> None:
        self._pub = load_public_key(public_key_path)

    def verify_file(self, file_path: str | Path) -> VerifyResult:
        """Verify ``file_path`` against its ``.sig`` sidecar."""
        if not _CRYPTOGRAPHY_AVAILABLE:
            return VerifyResult(ok=False, status="NO_CRYPTO",
                                detail="cryptography package not installed")
        file_path = Path(file_path)
        if not file_path.exists():
            return VerifyResult(ok=False, status="KEY_ERROR",
                                detail=f"file not found: {file_path}")
        sig_path = Path(str(file_path) + ".sig")
        if not sig_path.exists():
            return VerifyResult(ok=False, status="NO_SIGNATURE",
                                detail=f"signature sidecar missing: {sig_path}")

        sha = _hash_file(file_path)
        try:
            sig_b64 = sig_path.read_text(encoding="ascii").strip()
            sig = base64.b64decode(sig_b64)
        except Exception as exc:
            return VerifyResult(ok=False, status="INVALID_SIGNATURE",
                                detail=f"could not decode signature: {exc}",
                                bank_sha256=sha)

        try:
            self._pub.verify(sig, sha.encode("ascii"))
            return VerifyResult(ok=True, status="OK",
                                detail="signature valid",
                                bank_sha256=sha)
        except Exception as exc:
            return VerifyResult(ok=False, status="INVALID_SIGNATURE",
                                detail=f"signature verification failed: {exc}",
                                bank_sha256=sha)


def _hash_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()
