"""Shared dataclasses for DNS events, features, and detections."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class DnsQueryEvent:
    """Normalized DNS transaction (query + optional response metadata)."""

    timestamp: datetime
    src_ip: str
    fqdn: str
    record_type: str
    response_code: str
    dst_ip: str = ""
    response_size: int = 0
    query_id: int | None = None


@dataclass
class QueryFeatures:
    """Per-query lexical / statistical features."""

    timestamp: datetime
    src_ip: str
    fqdn: str
    parent_domain: str
    record_type: str
    response_code: str
    response_size: int
    fqdn_length: int
    longest_label_length: int
    label_count: int
    shannon_entropy: float
    letter_ratio: float
    digit_ratio: float
    hyphen_ratio: float
    other_ratio: float
    encoding_likeness: float
    ngram_score: float
    is_nxdomain: bool
    in_top_list: bool


@dataclass
class WindowFeatures:
    """Aggregated behavioral features for one source IP in a time window."""

    src_ip: str
    window_start: datetime
    window_end: datetime
    query_count: int
    queries_per_minute: float
    unique_fqdn_count: int
    unique_parent_count: int
    unique_subdomain_ratio: float
    nxdomain_ratio: float
    txt_null_ratio: float
    mean_response_size: float
    max_response_size: float
    mean_entropy: float
    max_entropy: float
    mean_longest_label: float
    max_longest_label: float
    mean_fqdn_length: float
    mean_encoding_likeness: float
    mean_ngram_score: float
    unpopular_ratio: float
    record_type_counts: dict[str, int] = field(default_factory=dict)
    sample_domains: list[str] = field(default_factory=list)
    parent_unique_subdomains: dict[str, int] = field(default_factory=dict)

    def to_vector(self) -> list[float]:
        """Numeric feature vector used by the ML classifier."""
        return [
            float(self.query_count),
            self.queries_per_minute,
            float(self.unique_fqdn_count),
            float(self.unique_parent_count),
            self.unique_subdomain_ratio,
            self.nxdomain_ratio,
            self.txt_null_ratio,
            self.mean_response_size,
            self.max_response_size,
            self.mean_entropy,
            self.max_entropy,
            self.mean_longest_label,
            self.max_longest_label,
            self.mean_fqdn_length,
            self.mean_encoding_likeness,
            self.mean_ngram_score,
            self.unpopular_ratio,
        ]


FEATURE_NAMES: tuple[str, ...] = (
    "query_count",
    "queries_per_minute",
    "unique_fqdn_count",
    "unique_parent_count",
    "unique_subdomain_ratio",
    "nxdomain_ratio",
    "txt_null_ratio",
    "mean_response_size",
    "max_response_size",
    "mean_entropy",
    "max_entropy",
    "mean_longest_label",
    "max_longest_label",
    "mean_fqdn_length",
    "mean_encoding_likeness",
    "mean_ngram_score",
    "unpopular_ratio",
)


@dataclass
class DetectionResult:
    """Combined rule + ML assessment for a window."""

    timestamp: datetime
    src_ip: str
    domain: str
    rule_score: float
    ml_score: float | None
    reason: str
    raw_query_count: int
    window_start: datetime
    window_end: datetime
    risk_level: str
    contributions: dict[str, float] = field(default_factory=dict)
    extras: dict[str, Any] = field(default_factory=dict)
