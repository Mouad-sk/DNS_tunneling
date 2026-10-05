"""Unit tests for per-query feature extractors."""

from __future__ import annotations

from datetime import datetime, timezone

from dns_exfil_detect.features.query import (
    NgramModel,
    encoding_likeness,
    extract_query_features,
    longest_label_length,
    parent_domain,
    shannon_entropy,
    subdomain_labels,
)
from dns_exfil_detect.models import DnsQueryEvent

NOW = datetime(2024, 6, 1, tzinfo=timezone.utc)


def test_shannon_entropy_known_values() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    # two symbols equally likely → 1 bit
    assert abs(shannon_entropy("abab") - 1.0) < 1e-9
    high = shannon_entropy("a1b2c3d4e5f6g7h8")
    low = shannon_entropy("www")
    assert high > low


def test_longest_label_and_parent() -> None:
    fqdn = "very-long-label-used-for-chunking.api.example.com"
    assert longest_label_length(fqdn) == len("very-long-label-used-for-chunking")
    assert parent_domain(fqdn) == "example.com"
    assert parent_domain("www.bbc.co.uk") == "bbc.co.uk"
    assert subdomain_labels("a.b.example.com") == ["a", "b"]


def test_encoding_likeness_separates_benign_and_payloadish() -> None:
    benign = encoding_likeness("www")
    payload = encoding_likeness("k5swy3dpeb2gq2ltebuw4zdpn5q")
    hexish = encoding_likeness("deadbeefcafebabe0123456789abcdef")
    assert benign < 0.3
    assert payload > 0.5
    assert hexish > 0.5


def test_ngram_prefers_legitimate_looking_names() -> None:
    model = NgramModel(n=3)
    model.fit(["google.com", "www.google.com", "microsoft.com", "office.com", "apple.com", "github.com"])
    good = model.score("mail.google.com")
    bad = model.score("q7x9m2k4p8n3w1z5.tunnel-test.net")
    assert good > bad


def test_extract_query_features_nxdomain_and_txt() -> None:
    model = NgramModel(n=3)
    model.fit(["google.com", "www.google.com"])
    event = DnsQueryEvent(
        timestamp=NOW,
        src_ip="10.0.0.8",
        fqdn="k5swy3dpeb2gq2ltebuw4zdpn5q.abc.evil-test.net",
        record_type="TXT",
        response_code="NXDOMAIN",
        response_size=120,
    )
    feat = extract_query_features(event, model, {"google.com"})
    assert feat.is_nxdomain is True
    assert feat.record_type == "TXT"
    assert feat.in_top_list is False
    assert feat.fqdn_length == len(event.fqdn)
    assert feat.shannon_entropy > 3.0
    assert feat.longest_label_length >= 20
