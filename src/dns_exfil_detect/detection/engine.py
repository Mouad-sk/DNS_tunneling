"""Combined rule + ML detection engine over a stream of DNS events."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from datetime import datetime, timezone

from dns_exfil_detect.config import AppConfig, load_config
from dns_exfil_detect.detection.ml import MLClassifier
from dns_exfil_detect.detection.rules import RuleScorer
from dns_exfil_detect.features.query import NgramModel, extract_query_features, load_domain_list
from dns_exfil_detect.features.reputation import ReputationList
from dns_exfil_detect.features.window import SlidingWindowAggregator
from dns_exfil_detect.models import DetectionResult, DnsQueryEvent, QueryFeatures, WindowFeatures


def risk_level(rule_score: float, ml_score: float | None, rule_t: float, ml_t: float) -> str:
    combined = rule_score
    if ml_score is not None and ml_score == ml_score:  # not NaN
        combined = max(rule_score, ml_score)
    if combined >= 0.85 or (ml_score is not None and ml_score >= 0.9):
        return "critical"
    if combined >= max(rule_t, ml_t) + 0.1:
        return "high"
    if combined >= min(rule_t, ml_t):
        return "medium"
    if combined >= 0.3:
        return "low"
    return "info"


class DetectionEngine:
    """Feature extraction + dual scoring. Designed for batch and streaming use."""

    def __init__(self, config: AppConfig | None = None, classifier: MLClassifier | None = None) -> None:
        self.config = config or load_config()
        self.rules = RuleScorer(self.config.rules)
        self.classifier = classifier
        if self.classifier is None and self.config.ml.enabled and self.config.ml.model_path.is_file():
            self.classifier = MLClassifier.load(self.config.ml.model_path)

        self.ngram = NgramModel(n=self.config.ngram_n)
        corpus = load_domain_list(str(self.config.ngram_corpus_path))
        if not corpus:
            corpus = _fallback_corpus()
        self.ngram.fit(corpus)
        self.reputation = ReputationList.from_file(self.config.tranco_path)
        if len(self.reputation) == 0:
            self.reputation = ReputationList(corpus)
        self.aggregator = SlidingWindowAggregator(
            size_seconds=self.config.window.size_seconds,
            slide_seconds=self.config.window.slide_seconds,
        )

    def extract(self, event: DnsQueryEvent) -> QueryFeatures:
        return extract_query_features(event, self.ngram, self.reputation.domains)

    def score_window(self, window: WindowFeatures) -> DetectionResult:
        rule_score, contrib, reason = self.rules.score(window)
        ml_score: float | None = None
        if self.config.ml.enabled and self.classifier is not None and self.classifier.ready:
            ml_score = self.classifier.predict_proba(window)
            reason = f"{reason} | ml_p={ml_score:.3f}"
        domain = window.sample_domains[0] if window.sample_domains else window.src_ip
        if window.parent_unique_subdomains:
            domain = max(window.parent_unique_subdomains.items(), key=lambda kv: kv[1])[0]
        level = risk_level(
            rule_score,
            ml_score,
            self.config.rules.alert_threshold,
            self.config.ml.alert_threshold,
        )
        return DetectionResult(
            timestamp=datetime.now(timezone.utc),
            src_ip=window.src_ip,
            domain=domain,
            rule_score=rule_score,
            ml_score=ml_score,
            reason=reason,
            raw_query_count=window.query_count,
            window_start=window.window_start,
            window_end=window.window_end,
            risk_level=level,
            contributions=contrib,
        )

    def is_alert(self, result: DetectionResult) -> bool:
        rule_hit = result.rule_score >= self.config.rules.alert_threshold
        ml_hit = (
            result.ml_score is not None
            and result.ml_score == result.ml_score
            and result.ml_score >= self.config.ml.alert_threshold
        )
        if self.config.rules.enabled and self.config.ml.enabled and self.classifier and self.classifier.ready:
            return rule_hit or ml_hit
        if self.config.ml.enabled and self.classifier and self.classifier.ready:
            return ml_hit
        return rule_hit

    def process_events(
        self,
        events: Iterable[DnsQueryEvent],
        *,
        min_queries: int | None = None,
        alerts_only: bool = False,
    ) -> Iterator[tuple[QueryFeatures, DetectionResult | None]]:
        """Yield (query_features, optional detection) as windows close.

        Query features are yielded for every event (for raw_queries storage).
        Detections are attached on the last query of a closed window (None otherwise).
        Flush remaining windows after the iterator is exhausted by calling ``flush``.
        """
        threshold = self.config.window.min_queries if min_queries is None else min_queries
        for event in events:
            feat = self.extract(event)
            detections = self.aggregator.push(feat)
            emitted: DetectionResult | None = None
            for window in detections:
                if window.query_count < threshold:
                    continue
                emitted = self.score_window(window)
                if alerts_only and not self.is_alert(emitted):
                    emitted = None
            yield feat, emitted

    def flush(self, *, min_queries: int | None = None, alerts_only: bool = False) -> list[DetectionResult]:
        threshold = self.config.window.min_queries if min_queries is None else min_queries
        results: list[DetectionResult] = []
        for window in self.aggregator.flush():
            if window.query_count < threshold:
                continue
            det = self.score_window(window)
            if alerts_only and not self.is_alert(det):
                continue
            results.append(det)
        return results


def _fallback_corpus() -> list[str]:
    return [
        "google.com",
        "googleapis.com",
        "microsoft.com",
        "office.com",
        "apple.com",
        "icloud.com",
        "amazon.com",
        "cloudflare.com",
        "github.com",
        "wikipedia.org",
        "linkedin.com",
        "netflix.com",
        "adobe.com",
        "salesforce.com",
        "zoom.us",
    ]
