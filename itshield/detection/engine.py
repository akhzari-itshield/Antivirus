"""Detection Engine - combines multiple signals into a final verdict.

Section 10 of the architecture document.

The current logic is intentionally simple and matches the document exactly:

    * A positive signature match (SHA-256 in the bank)  -> MALICIOUS
    * Any YARA rule match                                -> SUSPICIOUS
    * Neither                                            -> CLEAN
    * Insufficient data (e.g. hash unavailable)          -> UNKNOWN

A future Risk Engine will score each signal separately (signature severity,
YARA rule weight, entropy, import anomalies, ...) and combine them into a
risk score that can flip ``SUSPICIOUS`` to ``MALICIOUS`` with enough
evidence. The interface here (:class:`DetectionInput`) is already shaped
to carry that richer evidence without breaking callers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from itshield.scanner.models import DetectionVerdict


@dataclass
class DetectionInput:
    """Inputs the detection engine reasons about."""

    sha256: Optional[str] = None
    signature_name: Optional[str] = None
    yara_rules: List[str] = field(default_factory=list)
    file_type: Optional[str] = None
    file_size: int = 0
    entropy: Optional[float] = None
    is_executable: bool = False
    is_archive: bool = False
    is_script: bool = False
    extra: dict = field(default_factory=dict)


@dataclass
class DetectionOutput:
    """Result of a detection decision."""

    verdict: DetectionVerdict
    reason: str
    confidence: float = 0.0   # 0..1, future use

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "reason": self.reason,
            "confidence": self.confidence,
        }


class DetectionEngine:
    """Stateless decision maker used by the scanner."""

    def decide(self, evidence: DetectionInput) -> DetectionOutput:
        """Apply the documented decision tree to ``evidence``."""
        if evidence.sha256 is None:
            return DetectionOutput(
                verdict=DetectionVerdict.UNKNOWN,
                reason="hash unavailable; insufficient evidence",
                confidence=0.1,
            )

        if evidence.signature_name:
            return DetectionOutput(
                verdict=DetectionVerdict.MALICIOUS,
                reason=(
                    f"signature match: {evidence.signature_name}"
                ),
                confidence=1.0,
            )

        if evidence.yara_rules:
            rules_str = ", ".join(evidence.yara_rules)
            return DetectionOutput(
                verdict=DetectionVerdict.SUSPICIOUS,
                reason=f"YARA matched: {rules_str}",
                confidence=0.6,
            )

        return DetectionOutput(
            verdict=DetectionVerdict.CLEAN,
            reason="no detection signals matched",
            confidence=0.5,
        )
