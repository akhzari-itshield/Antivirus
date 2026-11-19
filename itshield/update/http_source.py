"""HTTP update sources for ITShield (Phase 9).

Section 18 of the architecture document - remote update channel.

Provides:
    * :class:`HTTPUpdateSource` - downloads a single file from an HTTPS URL,
      verifies its SHA-256, and returns the local path.
    * :class:`GitHubArchiveSource` - downloads a GitHub repo as a ZIP archive
      (used by :class:`~itshield.update.yara_downloader.YaraRuleDownloader`
      to pull the neo23x0/signature-base rule collection).

Both sources use :mod:`urllib.request` so no extra dependencies are
required. A User-Agent header is sent because GitHub requires one.
"""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import tempfile
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from itshield.logging.logger import get_logger

logger = get_logger(__name__)


DEFAULT_USER_AGENT = "ITShield-Antivirus/0.5.0 (Linux; endpoint protection)"


@dataclass
class DownloadResult:
    """Outcome of an HTTP download."""

    success: bool
    url: str
    local_path: str = ""
    bytes_downloaded: int = 0
    sha256: str = ""
    expected_sha256: str = ""
    status: str = ""        # OK / HTTP_ERROR / HASH_MISMATCH / NETWORK_ERROR
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "url": self.url,
            "local_path": self.local_path,
            "bytes_downloaded": self.bytes_downloaded,
            "sha256": self.sha256,
            "expected_sha256": self.expected_sha256,
            "status": self.status,
            "detail": self.detail,
        }


class HTTPUpdateSource:
    """Downloads a single file from an HTTP/HTTPS URL."""

    def __init__(
        self,
        user_agent: str = DEFAULT_USER_AGENT,
        timeout: float = 30.0,
        chunk_size: int = 64 * 1024,
    ) -> None:
        self.user_agent = user_agent
        self.timeout = timeout
        self.chunk_size = chunk_size

    def download(
        self,
        url: str,
        dest_path: str | Path,
        expected_sha256: Optional[str] = None,
    ) -> DownloadResult:
        """Download ``url`` to ``dest_path``.

        If ``expected_sha256`` is provided, the downloaded content is
        verified after the write; on mismatch the partial file is removed
        and ``status=HASH_MISMATCH`` is returned.
        """
        dest = Path(dest_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        req = urllib.request.Request(
            url,
            headers={"User-Agent": self.user_agent, "Accept": "*/*"},
        )
        result = DownloadResult(success=False, url=url, expected_sha256=expected_sha256 or "")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                status_code = getattr(response, "status", 200)
                if status_code >= 400:
                    result.status = "HTTP_ERROR"
                    result.detail = f"HTTP {status_code}"
                    return result

                hasher = hashlib.sha256()
                total = 0
                with dest.open("wb") as fh:
                    while True:
                        chunk = response.read(self.chunk_size)
                        if not chunk:
                            break
                        fh.write(chunk)
                        hasher.update(chunk)
                        total += len(chunk)

                result.bytes_downloaded = total
                result.sha256 = hasher.hexdigest()
                result.local_path = str(dest)

                if expected_sha256 and result.sha256.lower() != expected_sha256.lower():
                    dest.unlink(missing_ok=True)
                    result.status = "HASH_MISMATCH"
                    result.detail = (
                        f"expected {expected_sha256[:12]}.. got {result.sha256[:12]}.."
                    )
                    result.local_path = ""
                    logger.warning("Download hash mismatch for %s: %s", url, result.detail)
                    return result

                result.success = True
                result.status = "OK"
                logger.info(
                    "Downloaded %s -> %s (%d bytes, sha256=%s..)",
                    url, dest, total, result.sha256[:12],
                )
                return result

        except urllib.error.HTTPError as exc:
            result.status = "HTTP_ERROR"
            result.detail = f"HTTP {exc.code}: {exc.reason}"
            logger.warning("HTTP error downloading %s: %s", url, result.detail)
            return result
        except urllib.error.URLError as exc:
            result.status = "NETWORK_ERROR"
            result.detail = str(exc.reason)
            logger.warning("Network error downloading %s: %s", url, result.detail)
            return result
        except Exception as exc:
            result.status = "NETWORK_ERROR"
            result.detail = str(exc)
            logger.exception("Unexpected error downloading %s", url)
            return result


class GitHubArchiveSource:
    """Downloads a GitHub repository as a ZIP archive.

    Uses GitHub's ``/archive/refs/heads/<branch>.zip`` endpoint which is
    publicly available without authentication for public repos.

    Example:
        src = GitHubArchiveSource(repo="neo23x0/signature-base", ref="master")
        result = src.download(dest_path="/tmp/sig-base.zip")
    """

    GITHUB_ARCHIVE_URL = "https://github.com/{repo}/archive/refs/heads/{ref}.zip"

    def __init__(
        self,
        repo: str,
        ref: str = "master",
        user_agent: str = DEFAULT_USER_AGENT,
        timeout: float = 60.0,
    ) -> None:
        self.repo = repo
        self.ref = ref
        self._http = HTTPUpdateSource(user_agent=user_agent, timeout=timeout)

    @property
    def archive_url(self) -> str:
        return self.GITHUB_ARCHIVE_URL.format(repo=self.repo, ref=self.ref)

    def download(self, dest_path: str | Path) -> DownloadResult:
        """Download the repo archive to ``dest_path``.

        No SHA-256 is checked here because GitHub does not publish one
        ahead of time; the caller can record the computed hash for
        future verification.
        """
        return self._http.download(self.archive_url, dest_path)
