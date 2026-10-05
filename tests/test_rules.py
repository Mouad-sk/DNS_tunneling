"""Rule scorer and window aggregation tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from dns_exfil_detect.config import load_config
from dns_exfil_detect.detection.engine import DetectionEngine
from dns_exfil_detect.detection.rules import RuleScorer
from dns_exfil_detect.features.window import summarize_window
from dns_exfil_detect.models import QueryFeatures
from dns_exfil_detect.synth import generate_benign_session, generate_tunnel_session

NOW = datetime(2024, 6, 1, tzinfo=timezone.utc)


def _qf(**kwargs: object) -> QueryFeatures:
    defaults: dict[str, object] = dict(
        timestamp=NOW,
        src_ip="10.1.1.8",
        fqdn="www.google.com",
        parent_domain="google.com",
        record_type="A",
        response_code="NOERROR",
        response_size=80,
        fqdn_length=14,
        longest_label_length=6,
        label_count=3,
        shannon_entropy=2.0,
        letter_ratio=0.9,
        digit_ratio=0.0,
        hyphen_ratio=0.0,
        other_ratio=0.0,
        encoding_likeness=0.05,
        ngram_score=-1.4,
        is_nxdomain=False,
        in_top_list=True,
    )
    defaults.update(kwargs)
    return QueryFeatures(**defaults)  # type: ignore[arg-type]


def test_summarize_window_rates() -> None:
    items = [_qf(timestamp=NOW + timedelta(seconds=i * 2)) for i in range(10)]
    window = summarize_window("10.1.1.8", items)
    assert window is not None
    assert window.query_count == 10
    assert window.nxdomain_ratio == 0.0
    assert window.queries_per_minute > 0


def test_unique_subdomain_signal() -> None:
    items = [
        _qf(
            fqdn=f"chunk{i}.evil-test.net",
            parent_domain="evil-test.net",
            in_top_list=False,
            shannon_entropy=4.1,
            encoding_likeness=0.8,
            longest_label_length=40,
            ngram_score=-3.2,
            record_type="TXT",
            is_nxdomain=True,
            response_code="NXDOMAIN",
        )
        for i in range(20)
    ]
    window = summarize_window("10.1.1.9", items)
    assert window is not None
    assert window.unique_subdomain_ratio == 1.0
    assert window.txt_null_ratio == 1.0
    score, contrib, reason = RuleScorer().score(window)
    assert score >= 0.55
    assert contrib
    assert "unique_subdomains" in reason or "entropy" in reason


def test_benign_window_below_threshold() -> None:
    items = [_qf() for _ in range(12)]
    window = summarize_window("10.1.1.8", items)
    assert window is not None
    score, _, _ = RuleScorer().score(window)
    assert score < 0.55


def test_engine_separates_synthetic_sessions(tmp_config) -> None:
    cfg = load_config(tmp_config)
    benign_engine = DetectionEngine(cfg)
    tunnel_engine = DetectionEngine(cfg)
    benign = generate_benign_session(0, 80, src_ip="10.0.0.4", seed=3)
    tunnel = generate_tunnel_session(1, 80, src_ip="10.0.0.9", seed=3)
    b_dets = [d for _, d in benign_engine.process_events(benign) if d] + benign_engine.flush()
    t_dets = [d for _, d in tunnel_engine.process_events(tunnel) if d] + tunnel_engine.flush()
    assert t_dets
    max_b = max(d.rule_score for d in b_dets) if b_dets else 0.0
    max_t = max(d.rule_score for d in t_dets)
    assert max_t > max_b
    assert max_t >= cfg.rules.alert_threshold
    assert max_b < cfg.rules.alert_threshold
