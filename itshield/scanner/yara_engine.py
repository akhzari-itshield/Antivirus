"""YARA Engine - rule-based malware detection.

Section 9.4 of the architecture document.

Important design decision (mirrors the document): a YARA match is treated
conservatively as ``SUSPICIOUS`` rather than ``MALICIOUS``. Only a positive
signature match (SHA-256 in the bank) can flag a file as ``MALICIOUS`` in
this version. A future Risk Engine will combine multiple signals into a
stronger verdict.

Uses ``yara-python`` (real YARA 4.x). If the module is not importable, the
engine raises at construction time so the Core can degrade gracefully.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import yara

from itshield.config.settings import get_settings
from itshield.logging.logger import get_logger

logger = get_logger(__name__)


class YaraMatch:
    """One matched rule against a scanned file."""

    __slots__ = ("rule", "namespace", "tags", "meta", "strings")

    def __init__(self, rule: str, namespace: str, tags: List[str],
                 meta: dict, strings: List) -> None:
        self.rule = rule
        self.namespace = namespace
        self.tags = tags
        self.meta = meta
        self.strings = strings

    def __repr__(self) -> str:  # pragma: no cover
        return f"YaraMatch(rule={self.rule!r}, namespace={self.namespace!r})"


class YaraEngine:
    """Compile and apply YARA rules against files."""

    def __init__(
        self,
        rules_path: Optional[str | Path] = None,
        timeout_seconds: Optional[int] = None,
    ) -> None:
        settings = get_settings()
        self.rules_path = Path(rules_path) if rules_path else settings.yara_rules_path
        self.timeout_seconds = (
            timeout_seconds or settings.scanner_yara_timeout_seconds
        )
        self._compiled = None
        self._rule_count = 0
        self._load_rules()

    def _load_rules(self) -> None:
        if not self.rules_path.exists():
            logger.warning(
                "YARA rules path not found at %s; engine will match nothing",
                self.rules_path,
            )
            return

        try:
            if self.rules_path.is_dir():
                self._load_from_directory(self.rules_path)
            else:
                self._load_from_file(self.rules_path)
            if self._compiled is None:
                logger.warning(
                    "No YARA rules compiled from %s; engine will match nothing",
                    self.rules_path,
                )
                return
            if isinstance(self._compiled, list):
                self._rule_count = sum(sum(1 for _ in iter(r)) for r in self._compiled)
            else:
                self._rule_count = sum(1 for _ in iter(self._compiled))
            logger.info(
                "Loaded %d YARA rules from %s",
                self._rule_count,
                self.rules_path,
            )
        except yara.Error as exc:
            logger.error("Failed to compile YARA rules %s: %s", self.rules_path, exc)
            self._compiled = None

    def _load_from_file(self, path: Path) -> None:
        """Load a single .yar file as the 'default' namespace."""
        self._compiled = yara.compile(filepaths={"default": str(path)})

    def _load_from_directory(self, directory: Path) -> None:
        """Load every .yar file in ``directory`` as a separate namespace.

        CRITICAL: If one file has a syntax error, we must NOT let it
        abort the entire compilation. We try to compile ALL files together
        first; if that fails, we fall back to compiling each file
        individually and skip the ones that error out.
        """
        yar_files = sorted(directory.glob("*.yar"))
        if not yar_files:
            logger.warning(
                "No .yar files found in directory %s; engine will match nothing",
                directory,
            )
            self._compiled = None
            return

        filepaths = {}
        for yf in yar_files:
            ns = yf.stem
            if ns in filepaths:
                ns = f"{yf.stem}_{hash(str(yf)) & 0xFFFF:x}"
            filepaths[ns] = str(yf)

        logger.info(
            "Compiling %d YARA files from %s as separate namespaces",
            len(filepaths), directory,
        )

        try:
            self._compiled = yara.compile(filepaths=filepaths)
            return
        except yara.Error as exc:
            logger.warning(
                "Batch YARA compilation failed (%s); falling back to "
                "per-file compilation (bad files will be skipped)",
                exc,
            )

        good_filepaths = {}
        skipped = 0
        for ns, fp in filepaths.items():
            try:
                yara.compile(filepaths={ns: fp})
                good_filepaths[ns] = fp
            except yara.Error as exc:
                logger.warning(
                    "Skipping YARA file %s (compile error: %s)",
                    fp, str(exc)[:100],
                )
                skipped += 1

        if skipped > 0:
            logger.warning(
                "Skipped %d YARA file(s) with compilation errors out of %d total",
                skipped, len(filepaths),
            )

        if not good_filepaths:
            logger.error(
                "All %d YARA files failed to compile; engine will match nothing",
                len(filepaths),
            )
            self._compiled = None
            return

        logger.info(
            "Compiling %d valid YARA files (skipped %d)",
            len(good_filepaths), skipped,
        )
        try:
            self._compiled = yara.compile(filepaths=good_filepaths)
        except yara.Error as exc:
            logger.error(
                "Combined compilation of individually-valid files failed: %s. "
                "Compiling each as a separate Rules object.",
                exc,
            )
            compiled_list = []
            for ns, fp in good_filepaths.items():
                try:
                    compiled_list.append(yara.compile(filepaths={ns: fp}))
                except yara.Error:
                    pass
            if compiled_list:
                self._compiled = compiled_list
            else:
                self._compiled = None

    def reload(self) -> int:
        """Re-read the rules path and recompile. Returns the new rule count.

        Useful after :class:`YaraRuleDownloader` writes new .yar files
        into the rules directory: call ``reload()`` and the engine picks
        them up without restarting the process.
        """
        self._compiled = None
        self._rule_count = 0
        self._load_rules()
        return self._rule_count

    @property
    def rule_count(self) -> int:
        return self._rule_count

    @property
    def ready(self) -> bool:
        """True if at least one rule is compiled and ready to match."""
        return self._compiled is not None and self._rule_count > 0

    def scan_file(self, path: str | Path) -> List[YaraMatch]:
        """Apply every compiled rule to ``path`` and return the matches.

        Returns an empty list if no rules are loaded or no rule matches.
        Honors ``timeout_seconds`` to avoid infinite evaluation on
        pathologically packed files.
        """
        if self._compiled is None:
            return []

        path = Path(path)
        if not path.exists() or not path.is_file():
            return []

        if isinstance(self._compiled, list):
            all_matches = []
            for rules_obj in self._compiled:
                try:
                    matches = rules_obj.match(
                        str(path), timeout=self.timeout_seconds,
                    )
                    all_matches.extend(matches)
                except yara.TimeoutError:
                    logger.warning("YARA timed out on %s", path)
                except yara.Error as exc:
                    logger.debug("YARA scan error on %s: %s", path, exc)
            matches = all_matches
        else:
            try:
                matches = self._compiled.match(
                    str(path),
                    timeout=self.timeout_seconds,
                )
            except yara.TimeoutError:
                logger.warning(
                    "YARA timed out on %s after %ds; treating as no match",
                    path,
                    self.timeout_seconds,
                )
                return []
            except yara.Error as exc:
                logger.error("YARA scan failed on %s: %s", path, exc)
                return []

        result: List[YaraMatch] = []
        for m in matches:
            result.append(
                YaraMatch(
                    rule=m.rule,
                    namespace=m.namespace,
                    tags=list(m.tags),
                    meta=dict(m.meta) if m.meta else {},
                    strings=list(m.strings) if m.strings else [],
                )
            )
        return result
