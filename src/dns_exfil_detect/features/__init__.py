"""Feature extraction: per-query lexical stats and windowed behaviors."""

from dns_exfil_detect.features.query import (
    NgramModel,
    encoding_likeness,
    extract_query_features,
    load_domain_list,
    longest_label_length,
    parent_domain,
    shannon_entropy,
    subdomain_labels,
)
from dns_exfil_detect.features.reputation import ReputationList
from dns_exfil_detect.features.window import SlidingWindowAggregator, summarize_window, windows_from_features

__all__ = [
    "NgramModel",
    "ReputationList",
    "SlidingWindowAggregator",
    "encoding_likeness",
    "extract_query_features",
    "load_domain_list",
    "longest_label_length",
    "parent_domain",
    "shannon_entropy",
    "subdomain_labels",
    "summarize_window",
    "windows_from_features",
]
