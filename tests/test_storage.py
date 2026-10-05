"""SQLite + SIEM export tests."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from dns_exfil_detect.models import DetectionResult, QueryFeatures
from dns_exfil_detect.storage.siem import to_cef, to_syslog
from dns_exfil_detect.storage.sqlite import SqliteStorage

NOW = datetime(2024, 6, 1, tzinfo=timezone.utc)


def test_sqlite_roundtrip(tmp_path: Path) -> None:
    db = SqliteStorage(tmp_path / "t.db")
    q = QueryFeatures(
        timestamp=NOW,
        src_ip="10.0.0.1",
        fqdn="www.google.com",
        parent_domain="google.com",
        record_type="A",
        response_code="NOERROR",
        response_size=64,
        fqdn_length=14,
        longest_label_length=3,
        label_count=3,
        shannon_entropy=1.5,
        letter_ratio=1.0,
        digit_ratio=0.0,
        hyphen_ratio=0.0,
        other_ratio=0.0,
        encoding_likeness=0.0,
        ngram_score=-1.2,
        is_nxdomain=False,
        in_top_list=True,
    )
    d = DetectionResult(
        timestamp=NOW,
        src_ip="10.0.0.1",
        domain="evil-test.net",
        rule_score=0.77,
        ml_score=0.81,
        reason="entropy=0.9",
        raw_query_count=20,
        window_start=NOW,
        window_end=NOW,
        risk_level="high",
    )
    db.insert_queries([q])
    db.insert_detections([d])
    dets = db.fetch_detections()
    queries = db.fetch_queries(src_ip="10.0.0.1")
    db.close()
    assert dets[0]["domain"] == "evil-test.net"
    assert dets[0]["rule_score"] == 0.77
    assert queries[0]["fqdn"] == "www.google.com"


def test_cef_and_syslog_contain_fields() -> None:
    d = DetectionResult(
        timestamp=NOW,
        src_ip="10.0.0.1",
        domain="evil-test.net",
        rule_score=0.77,
        ml_score=0.81,
        reason="entropy=0.9",
        raw_query_count=20,
        window_start=NOW,
        window_end=NOW,
        risk_level="high",
    )
    cef = to_cef(d)
    syslog = to_syslog(d)
    assert cef.startswith("CEF:0|")
    assert "src=10.0.0.1" in cef
    assert "rule=0.7700" in syslog
    assert "evil-test.net" in syslog
