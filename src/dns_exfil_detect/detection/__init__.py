"""Detection: explainable rules plus optional tree-ensemble classifier."""

from dns_exfil_detect.detection.engine import DetectionEngine, risk_level
from dns_exfil_detect.detection.ml import MLClassifier, build_estimator
from dns_exfil_detect.detection.rules import RuleScorer

__all__ = ["DetectionEngine", "MLClassifier", "RuleScorer", "build_estimator", "risk_level"]
