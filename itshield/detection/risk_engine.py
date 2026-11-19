"""Risk Engine - combines multiple detection signals into a risk score.

Section 10 (future work) of the architecture document.

In Phase 5 the Detection Engine applied a strict priority:
    signature match -> MALICIOUS
    YARA match      -> SUSPICIOUS
    nothing         -> CLEAN

The Risk Engine is the Phase 6 upgrade: it scores every signal
independently and combines them into a 0-100 risk score. The resulting
:class:`RiskAssessment` carries both the score and the contributing
factors so the GUI / reports can explain *why* a file was flagged.

The verdict mapping is:
    score <  20  -> CLEAN
    20 <= score < 50 -> UNKNOWN (insufficient evidence; review recommended)
    50 <= score < 75 -> SUSPICIOUS
    score >= 75    -> MALICIOUS

A single strong signal (e.g. signature match worth 80 points) flips the
verdict to MALICIOUS on its own, but weaker signals from multiple
sources (YARA + high entropy + suspicious imports) can also combine to
push a file over the threshold.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List

from itshield.scanner.models import DetectionVerdict


class RiskLevel(str, Enum):
    """Human-readable risk bucket derived from the numeric score."""

    LOW = "LOW"           # 0-19
    MEDIUM = "MEDIUM"     # 20-49
    HIGH = "HIGH"         # 50-74
    CRITICAL = "CRITICAL" # 75-100


@dataclass
class RiskFactor:
    """One contributing factor to the final risk score."""

    name: str
    weight: int           # raw points this factor contributed
    detail: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "weight": self.weight, "detail": self.detail}


@dataclass
class RiskAssessment:
    """The Risk Engine's verdict on a single file."""

    score: int                    # 0-100, capped
    level: RiskLevel
    verdict: DetectionVerdict
    factors: List[RiskFactor] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "level": self.level.value,
            "verdict": self.verdict.value,
            "factors": [f.to_dict() for f in self.factors],
        }



WEIGHT_SIGNATURE_MATCH = 80
WEIGHT_YARA_MATCH_PER_RULE = 25
WEIGHT_YARA_MATCH_CAP = 50
WEIGHT_HIGH_ENTROPY = 15
WEIGHT_PACKED_SECTION = 20
WEIGHT_SUSPICIOUS_IMPORTS = 15
WEIGHT_NETWORK_C2 = 30
WEIGHT_PROCESS_ANOMALY = 30
WEIGHT_UNKNOWN_FILE_TYPE = 5


class RiskEngine:
    """Stateless risk scorer driven by a :class:`RiskInput`."""

    def assess(self, evidence) -> RiskAssessment:
        """Compute the risk assessment for the given evidence.

        ``evidence`` is expected to be a :class:`RiskInput` (defined below
        for convenience) or any object exposing the same attributes.
        """
        factors: List[RiskFactor] = []
        score = 0

        if evidence.signature_name:
            factors.append(RiskFactor(
                name="signature_match",
                weight=WEIGHT_SIGNATURE_MATCH,
                detail=f"matched: {evidence.signature_name}",
            ))
            score += WEIGHT_SIGNATURE_MATCH

        if evidence.yara_rules:
            yara_pts = min(
                len(evidence.yara_rules) * WEIGHT_YARA_MATCH_PER_RULE,
                WEIGHT_YARA_MATCH_CAP,
            )
            factors.append(RiskFactor(
                name="yara_matches",
                weight=yara_pts,
                detail=f"rules: {', '.join(evidence.yara_rules)}",
            ))
            score += yara_pts

        if evidence.entropy is not None and evidence.entropy >= 7.0:
            factors.append(RiskFactor(
                name="high_entropy",
                weight=WEIGHT_HIGH_ENTROPY,
                detail=f"entropy={evidence.entropy:.3f}",
            ))
            score += WEIGHT_HIGH_ENTROPY

        if evidence.packed_section:
            factors.append(RiskFactor(
                name="packed_section",
                weight=WEIGHT_PACKED_SECTION,
                detail=evidence.packed_section,
            ))
            score += WEIGHT_PACKED_SECTION

        if evidence.suspicious_imports:
            factors.append(RiskFactor(
                name="suspicious_imports",
                weight=WEIGHT_SUSPICIOUS_IMPORTS,
                detail=f"imports: {', '.join(evidence.suspicious_imports)}",
            ))
            score += WEIGHT_SUSPICIOUS_IMPORTS

        if evidence.c2_indicator:
            factors.append(RiskFactor(
                name="network_c2",
                weight=WEIGHT_NETWORK_C2,
                detail=evidence.c2_indicator,
            ))
            score += WEIGHT_NETWORK_C2

        if evidence.process_anomaly:
            factors.append(RiskFactor(
                name="process_anomaly",
                weight=WEIGHT_PROCESS_ANOMALY,
                detail=evidence.process_anomaly,
            ))
            score += WEIGHT_PROCESS_ANOMALY

        if evidence.file_type in (None, "UNKNOWN") and not evidence.signature_name:
            factors.append(RiskFactor(
                name="unknown_file_type",
                weight=WEIGHT_UNKNOWN_FILE_TYPE,
                detail="file type could not be identified",
            ))
            score += WEIGHT_UNKNOWN_FILE_TYPE

        score = max(0, min(score, 100))
        if score < 20:
            level = RiskLevel.LOW
            verdict = DetectionVerdict.CLEAN
        elif score < 50:
            level = RiskLevel.MEDIUM
            verdict = DetectionVerdict.UNKNOWN
        elif score < 75:
            level = RiskLevel.HIGH
            verdict = DetectionVerdict.SUSPICIOUS
        else:
            level = RiskLevel.CRITICAL
            verdict = DetectionVerdict.MALICIOUS

        return RiskAssessment(
            score=score,
            level=level,
            verdict=verdict,
            factors=factors,
        )


@dataclass
class RiskInput:
    """Evidence gathered by every detector, ready for risk scoring."""

    sha256: str | None = None
    signature_name: str | None = None
    yara_rules: List[str] = field(default_factory=list)
    file_type: str | None = None
    file_size: int = 0
    entropy: float | None = None
    packed_section: str | None = None         # detail string if detected
    suspicious_imports: List[str] = field(default_factory=list)
    c2_indicator: str | None = None           # e.g. "connected to 1.2.3.4:443"
    process_anomaly: str | None = None        # e.g. "spawned 50 children in 2s"
