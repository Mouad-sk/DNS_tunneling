"""Benchmark + session-split ML tests (rule engine first)."""

from __future__ import annotations

from pathlib import Path

from dns_exfil_detect.benchmark import evaluate_pair, threshold_sweep
from dns_exfil_detect.config import load_config
from dns_exfil_detect.detection.engine import DetectionEngine
from dns_exfil_detect.synth import generate_benign_session, generate_tunnel_session, write_demo_pcaps
from dns_exfil_detect.train import train_model


def _score_session(cfg, events):
    eng = DetectionEngine(cfg)
    dets = [d for _, d in eng.process_events(events) if d]
    dets.extend(eng.flush())
    return dets


def test_rule_benchmark_on_demo_pcaps(tmp_config, tmp_path: Path) -> None:
    cfg = load_config(tmp_config)
    benign, tunnel = write_demo_pcaps(str(tmp_path / "demo"))
    engine = DetectionEngine(cfg)
    metrics = evaluate_pair(benign, tunnel, engine=engine, mode="rule")
    assert metrics["tp"] == 1
    assert metrics["fn"] == 0
    assert metrics["fp"] == 0
    assert metrics["tn"] == 1
    assert metrics["f1"] == 1.0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0


def test_threshold_sweep_reports_f1(tmp_config) -> None:
    cfg = load_config(tmp_config)
    pairs = []
    for events, label in (
        (generate_benign_session(2, 120, seed=5), 0),
        (generate_tunnel_session(3, 120, seed=5), 1),
    ):
        dets = _score_session(cfg, events)
        pairs.extend((d, label) for d in dets)
    rows = threshold_sweep(DetectionEngine(cfg), pairs)
    assert rows
    assert all("f1" in r and "threshold" in r for r in rows)
    best = max(r["f1"] for r in rows)
    assert best >= 0.9


def test_ml_session_split_not_random_rows(tmp_config, tmp_path: Path) -> None:
    cfg = load_config(tmp_config)
    cfg.ml.enabled = True
    out = tmp_path / "model.joblib"
    result = train_model(config=cfg, out_path=out, seed=11)
    assert out.is_file()
    assert result["train_windows"] > 0
    assert result["test_windows"] > 0
    assert result["f1"] >= 0.9
    cm = result["confusion_matrix"]
    assert cm[0][1] <= 1  # few false positives on held-out session
    assert "disjoint capture sessions" in str(result["methodology"])
    importance = result["feature_importance"]
    assert isinstance(importance, dict) and importance
