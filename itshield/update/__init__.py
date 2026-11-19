"""Update system package for ITShield (Phase 8-9).

Section 18 of the architecture document.

The update system is responsible for:
    * downloading (or reading from a local source) a new signature bank
    * verifying its integrity (SHA-256) and authenticity (signature)
    * backing up the current bank before swapping
    * recording the operation in ``update_history``
    * rolling back to the previous version if something goes wrong

Phase 8 (v0.4.x): local-file updates, SHA-256 verification, rollback.
Phase 9 (v0.5.0): HTTP downloads from GitHub + YARA rule downloader for
neo23x0/signature-base integration.

Components:
    * :class:`SignatureVerifier`     - SHA-256 + (future) Ed25519 verification
    * :class:`UpdateManager`         - orchestrates signature bank check + apply + rollback
    * :class:`UpdateInfo`            - dataclass describing a candidate update
    * :class:`UpdateResult`          - dataclass describing the apply outcome
    * :class:`LocalUpdateSource`     - reads candidate banks from a local dir
    * :class:`HTTPUpdateSource`      - downloads a file from an HTTPS URL (Phase 9)
    * :class:`GitHubArchiveSource`   - downloads a GitHub repo as a ZIP (Phase 9)
    * :class:`YaraRuleDownloader`    - downloads + merges YARA rules from GitHub (Phase 9)
"""

from itshield.update.verifier import (
    SignatureVerifier,
    VerificationResult,
    VerificationStatus,
)
from itshield.update.update_manager import (
    UpdateManager,
    UpdateInfo,
    UpdateResult,
    UpdateSource,
    LocalUpdateSource,
)
from itshield.update.http_source import (
    HTTPUpdateSource,
    GitHubArchiveSource,
    DownloadResult,
    DEFAULT_USER_AGENT,
)
from itshield.update.yara_downloader import (
    YaraRuleDownloader,
    YaraDownloadResult,
    DEFAULT_REPO,
    DEFAULT_REF,
)
from itshield.update.hash_downloader import (
    HashBankDownloader,
    HashDownloadResult,
    HashSource,
    MalwareBazaarSource,
)
from itshield.update.signed_verifier import (
    KeyPair,
    UpdateSigner,
    SignedVerifier,
    VerifyResult as SignedVerifyResult,
    generate_keypair,
    save_keypair,
    load_private_key,
    load_public_key,
)
from itshield.update.yara_sources import (
    YaraSource,
    YARA_SOURCES,
    get_source as get_yara_source,
    list_sources as list_yara_sources,
    sources_summary as yara_sources_summary,
)
from itshield.update.ioc_downloader import (
    IOCSource,
    IOCDownloader,
    IOCDownloadResult,
    ThreatFoxSource,
    URLHausSource,
    FeodoTrackerSource,
    IOC_SOURCES,
    get_ioc_source,
)

__all__ = [
    "SignatureVerifier",
    "VerificationResult",
    "VerificationStatus",
    "UpdateManager",
    "UpdateInfo",
    "UpdateResult",
    "UpdateSource",
    "LocalUpdateSource",
    "HTTPUpdateSource",
    "GitHubArchiveSource",
    "DownloadResult",
    "DEFAULT_USER_AGENT",
    "YaraRuleDownloader",
    "YaraDownloadResult",
    "DEFAULT_REPO",
    "DEFAULT_REF",
    "HashBankDownloader",
    "HashDownloadResult",
    "HashSource",
    "MalwareBazaarSource",
    "KeyPair",
    "UpdateSigner",
    "SignedVerifier",
    "SignedVerifyResult",
    "generate_keypair",
    "save_keypair",
    "load_private_key",
    "load_public_key",
    "YaraSource",
    "YARA_SOURCES",
    "get_yara_source",
    "list_yara_sources",
    "yara_sources_summary",
    "IOCSource",
    "IOCDownloader",
    "IOCDownloadResult",
    "ThreatFoxSource",
    "URLHausSource",
    "FeodoTrackerSource",
    "IOC_SOURCES",
    "get_ioc_source",
]
