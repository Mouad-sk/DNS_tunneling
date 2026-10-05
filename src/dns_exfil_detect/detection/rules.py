"""Explainable weighted rule scorer over window features."""

from __future__ import annotations

from dns_exfil_detect.config import RulesConfig
from dns_exfil_detect.models import WindowFeatures

DEFAULT_WEIGHTS: dict[str, float] = {
    "entropy": 0.14,
    "longest_label": 0.12,
    "fqdn_length": 0.08,
    "encoding_likeness": 0.12,
    "ngram_anomaly": 0.10,
    "unique_subdomains": 0.14,
    "nxdomain_ratio": 0.08,
    "txt_null_ratio": 0.08,
    "query_rate": 0.07,
    "unpopular": 0.07,
}

DEFAULT_THRESHOLDS: dict[str, float] = {
    "entropy_high": 3.5,
    "longest_label_high": 25,
    "fqdn_length_high": 80,
    "encoding_likeness_high": 0.45,
    "ngram_anomaly_high": 0.55,
    "unique_subdomain_ratio_high": 0.6,
    "nxdomain_ratio_high": 0.35,
    "txt_null_ratio_high": 0.25,
    "queries_per_minute_high": 40,
    "unpopular_ratio_high": 0.7,
}


def _clamp01(value: float) -> float:
    return min(1.0, max(0.0, value))


def _ramp(value: float, low: float, high: float) -> float:
    """Piecewise linear 0-1 score: 0 at ``low``, 1 at ``high``."""
    if high <= low:
        return 1.0 if value >= high else 0.0
    return _clamp01((value - low) / (high - low))


class RuleScorer:
    """Weighted, threshold-driven scorer. Contributions are retained for explainability."""

    def __init__(self, config: RulesConfig | None = None) -> None:
        cfg = config or RulesConfig()
        self.weights = {**DEFAULT_WEIGHTS, **(cfg.weights or {})}
        self.thresholds = {**DEFAULT_THRESHOLDS, **(cfg.thresholds or {})}
        self.alert_threshold = cfg.alert_threshold
        total = sum(self.weights.values()) or 1.0
        self.weights = {k: v / total for k, v in self.weights.items()}

    def score(self, window: WindowFeatures) -> tuple[float, dict[str, float], str]:
        """Return (score in 0-1, per-signal contributions, human-readable reason)."""
        t = self.thresholds
        ngram_anomaly = _clamp01((-window.mean_ngram_score - 1.4) / 1.6)

        parts: dict[str, float] = {
            "entropy": _ramp(window.mean_entropy, t["entropy_high"] * 0.7, t["entropy_high"] * 1.15),
            "longest_label": _ramp(
                window.max_longest_label,
                t["longest_label_high"] * 0.6,
                t["longest_label_high"] * 1.4,
            ),
            "fqdn_length": _ramp(
                window.mean_fqdn_length,
                t["fqdn_length_high"] * 0.6,
                t["fqdn_length_high"] * 1.3,
            ),
            "encoding_likeness": _ramp(
                window.mean_encoding_likeness,
                t["encoding_likeness_high"] * 0.5,
                t["encoding_likeness_high"] * 1.2,
            ),
            "ngram_anomaly": _ramp(ngram_anomaly, t["ngram_anomaly_high"] * 0.4, t["ngram_anomaly_high"]),
            "unique_subdomains": _ramp(
                window.unique_subdomain_ratio,
                t["unique_subdomain_ratio_high"] * 0.4,
                t["unique_subdomain_ratio_high"] * 1.1,
            ),
            "nxdomain_ratio": _ramp(
                window.nxdomain_ratio,
                t["nxdomain_ratio_high"] * 0.4,
                t["nxdomain_ratio_high"] * 1.2,
            ),
            "txt_null_ratio": _ramp(
                window.txt_null_ratio,
                t["txt_null_ratio_high"] * 0.3,
                min(1.0, t["txt_null_ratio_high"] * 1.5),
            ),
            "query_rate": _ramp(
                window.queries_per_minute,
                t["queries_per_minute_high"] * 0.5,
                t["queries_per_minute_high"] * 1.5,
            ),
            "unpopular": _ramp(
                window.unpopular_ratio,
                t["unpopular_ratio_high"] * 0.5,
                t["unpopular_ratio_high"],
            ),
        }

        contributions = {name: parts[name] * self.weights.get(name, 0.0) for name in parts}
        total = _clamp01(sum(contributions.values()))
        ranked = sorted(contributions.items(), key=lambda kv: kv[1], reverse=True)
        top = [f"{name}={parts[name]:.2f} (w={self.weights.get(name, 0):.2f})" for name, _ in ranked[:4]]
        reason = "; ".join(top)
        return total, contributions, reason
