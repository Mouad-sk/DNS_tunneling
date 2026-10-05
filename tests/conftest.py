"""Shared fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def repo_root() -> Path:
    return ROOT


@pytest.fixture
def tmp_config(tmp_path: Path) -> Path:
    cfg = {
        "window": {"size_seconds": 60, "slide_seconds": 15, "min_queries": 5},
        "rules": {
            "enabled": True,
            "alert_threshold": 0.55,
            "weights": {},
            "thresholds": {},
        },
        "ml": {
            "enabled": False,
            "backend": "random_forest",
            "model_path": str(tmp_path / "model.joblib"),
            "alert_threshold": 0.5,
        },
        "reputation": {"tranco_path": str(ROOT / "data" / "tranco_sample.txt")},
        "ngram": {"corpus_path": str(ROOT / "data" / "legitimate_domains.txt"), "n": 3},
        "storage": {"sqlite_path": str(tmp_path / "det.db")},
        "capture": {"bpf_filter": "udp port 53", "batch_size": 200},
        "siem": {"format": "cef", "product": "dns-exfil-detect"},
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return path
