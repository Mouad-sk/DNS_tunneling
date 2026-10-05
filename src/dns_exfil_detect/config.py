"""YAML configuration loading with pathlib (cross-platform)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


def _as_path(value: str | Path, base: Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = (base / path).resolve()
    return path


@dataclass
class WindowConfig:
    size_seconds: int = 60
    slide_seconds: int = 30
    min_queries: int = 5


@dataclass
class RulesConfig:
    enabled: bool = True
    alert_threshold: float = 0.55
    weights: dict[str, float] = field(default_factory=dict)
    thresholds: dict[str, float] = field(default_factory=dict)


@dataclass
class MLConfig:
    enabled: bool = True
    backend: str = "random_forest"
    model_path: Path = Path("data/models/dns_exfil_rf.joblib")
    alert_threshold: float = 0.5


@dataclass
class AppConfig:
    window: WindowConfig
    rules: RulesConfig
    ml: MLConfig
    tranco_path: Path
    ngram_corpus_path: Path
    ngram_n: int
    sqlite_path: Path
    bpf_filter: str
    batch_size: int
    siem_format: str
    product: str
    source_path: Path


def load_config(path: str | Path | None = None) -> AppConfig:
    """Load YAML config, resolving relative paths against the config file or CWD."""
    if path is None:
        candidates = [
            Path.cwd() / "config" / "default.yaml",
            Path(__file__).resolve().parents[2] / "config" / "default.yaml",
        ]
        cfg_path = next((p for p in candidates if p.is_file()), candidates[0])
    else:
        cfg_path = Path(path).resolve()

    raw: dict[str, Any] = {}
    if cfg_path.is_file():
        raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        base = cfg_path.parent.parent
    else:
        base = Path.cwd()

    window_raw = raw.get("window") or {}
    rules_raw = raw.get("rules") or {}
    ml_raw = raw.get("ml") or {}
    rep_raw = raw.get("reputation") or {}
    ngram_raw = raw.get("ngram") or {}
    storage_raw = raw.get("storage") or {}
    capture_raw = raw.get("capture") or {}
    siem_raw = raw.get("siem") or {}

    ml_path = _as_path(ml_raw.get("model_path", "data/models/dns_exfil_rf.joblib"), base)

    return AppConfig(
        window=WindowConfig(
            size_seconds=int(window_raw.get("size_seconds", 60)),
            slide_seconds=int(window_raw.get("slide_seconds", 30)),
            min_queries=int(window_raw.get("min_queries", 5)),
        ),
        rules=RulesConfig(
            enabled=bool(rules_raw.get("enabled", True)),
            alert_threshold=float(rules_raw.get("alert_threshold", 0.55)),
            weights=dict(rules_raw.get("weights") or {}),
            thresholds=dict(rules_raw.get("thresholds") or {}),
        ),
        ml=MLConfig(
            enabled=bool(ml_raw.get("enabled", True)),
            backend=str(ml_raw.get("backend", "random_forest")),
            model_path=ml_path,
            alert_threshold=float(ml_raw.get("alert_threshold", 0.5)),
        ),
        tranco_path=_as_path(rep_raw.get("tranco_path", "data/tranco_sample.txt"), base),
        ngram_corpus_path=_as_path(
            ngram_raw.get("corpus_path", "data/legitimate_domains.txt"), base
        ),
        ngram_n=int(ngram_raw.get("n", 3)),
        sqlite_path=_as_path(storage_raw.get("sqlite_path", "data/detections.db"), base),
        bpf_filter=str(capture_raw.get("bpf_filter", "udp port 53 or tcp port 53")),
        batch_size=int(capture_raw.get("batch_size", 500)),
        siem_format=str(siem_raw.get("format", "cef")),
        product=str(siem_raw.get("product", "dns-exfil-detect")),
        source_path=cfg_path,
    )
