"""Detection package for ITShield."""

from itshield.detection.engine import DetectionEngine, DetectionInput
from itshield.detection.risk_engine import (
    RiskEngine,
    RiskInput,
    RiskAssessment,
    RiskFactor,
    RiskLevel,
)
from itshield.detection.correlation_engine import CorrelationEngine
from itshield.detection.behavior_analyzer import BehaviorAnalyzer
from itshield.detection.ioc_matcher import IOCMatcher

__all__ = [
    "DetectionEngine",
    "DetectionInput",
    "RiskEngine",
    "RiskInput",
    "RiskAssessment",
    "RiskFactor",
    "RiskLevel",
    "CorrelationEngine",
    "BehaviorAnalyzer",
    "IOCMatcher",
]
