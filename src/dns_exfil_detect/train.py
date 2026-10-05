"""Train a window-level classifier on disjoint capture sessions."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, f1_score

from dns_exfil_detect.config import AppConfig, load_config
from dns_exfil_detect.detection.engine import DetectionEngine
from dns_exfil_detect.detection.ml import MLClassifier, build_estimator
from dns_exfil_detect.features.window import SlidingWindowAggregator
from dns_exfil_detect.models import DnsQueryEvent, FEATURE_NAMES
from dns_exfil_detect.synth import labeled_sessions


def windows_with_labels(
    engine: DetectionEngine,
    labeled_events: list[tuple[DnsQueryEvent, int]],
    min_queries: int = 5,
) -> tuple[np.ndarray, np.ndarray]:
    """Aggregate events into windows; label a window malicious if any event is.

    Events from different source IPs stay separated. Sessions must not be mixed
    via a random shuffle of rows — callers should pass one session collection.
    """
    by_ip: dict[str, list[tuple[DnsQueryEvent, int]]] = defaultdict(list)
    for event, label in labeled_events:
        by_ip[event.src_ip].append((event, label))

    x_rows: list[list[float]] = []
    y_rows: list[int] = []
    for _ip, group in by_ip.items():
        group.sort(key=lambda pair: pair[0].timestamp)
        agg = SlidingWindowAggregator(
            size_seconds=engine.config.window.size_seconds,
            slide_seconds=engine.config.window.slide_seconds,
        )
        pending_label = 0
        for event, label in group:
            pending_label = max(pending_label, label)
            feat = engine.extract(event)
            for window in agg.push(feat):
                if window.query_count >= min_queries:
                    x_rows.append(window.to_vector())
                    y_rows.append(pending_label)
                pending_label = label
        for window in agg.flush():
            if window.query_count >= min_queries:
                x_rows.append(window.to_vector())
                y_rows.append(pending_label)
    if not x_rows:
        return np.zeros((0, len(FEATURE_NAMES))), np.zeros((0,), dtype=int)
    return np.asarray(x_rows, dtype=float), np.asarray(y_rows, dtype=int)


def train_model(
    config: AppConfig | None = None,
    backend: str | None = None,
    out_path: Path | None = None,
    seed: int = 7,
) -> dict[str, object]:
    """Fit on session 0/1, evaluate on session 2/3, persist the model."""
    config = config or load_config()
    backend = backend or config.ml.backend
    engine = DetectionEngine(config)
    train, test = labeled_sessions(seed=seed)
    x_train, y_train = windows_with_labels(engine, train, min_queries=config.window.min_queries)
    x_test, y_test = windows_with_labels(engine, test, min_queries=config.window.min_queries)

    estimator = build_estimator(backend=backend, random_state=seed)
    estimator.fit(x_train, y_train)
    clf = MLClassifier(estimator=estimator, backend=backend)
    dest = out_path or config.ml.model_path
    clf.save(dest)

    y_pred = estimator.predict(x_test)
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1]).tolist()
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    importance = clf.feature_importance()
    return {
        "model_path": str(dest),
        "backend": backend,
        "train_windows": int(len(y_train)),
        "test_windows": int(len(y_test)),
        "f1": f1,
        "report": report,
        "confusion_matrix": cm,
        "feature_importance": importance,
        "methodology": (
            "Labels: 0=benign recursive DNS (popular names, A/AAAA), "
            "1=tunnel-shaped (unique high-entropy labels, TXT/NULL, NXDOMAIN). "
            "Split: disjoint capture sessions (different IPs, time bases, parent domains), "
            "not a random row split inside one pcap."
        ),
    }


def importance_table(importance: dict[str, float]) -> list[tuple[str, float]]:
    return sorted(importance.items(), key=lambda kv: kv[1], reverse=True)
