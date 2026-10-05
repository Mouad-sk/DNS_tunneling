"""Benchmark rule and ML detectors against labeled benign vs tunnel pcaps."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from dns_exfil_detect.capture.factory import open_source
from dns_exfil_detect.config import AppConfig, load_config
from dns_exfil_detect.detection.engine import DetectionEngine
from dns_exfil_detect.models import DetectionResult, DnsQueryEvent


def load_events(path: str | Path) -> list[DnsQueryEvent]:
    return list(open_source(path).events())


def score_pcap(
    path: str | Path,
    engine: DetectionEngine,
    *,
    alerts_only: bool = False,
) -> list[DetectionResult]:
    events = load_events(path)
    detections: list[DetectionResult] = []
    for _feat, det in engine.process_events(events, alerts_only=False):
        if det is not None:
            detections.append(det)
    detections.extend(engine.flush(alerts_only=False))
    if alerts_only:
        return [d for d in detections if engine.is_alert(d)]
    return detections


def _predicted_positive(results: list[DetectionResult], engine: DetectionEngine, mode: str) -> bool:
    """Host/session-level decision: any window fires."""
    if not results:
        return False
    if mode == "rule":
        return any(r.rule_score >= engine.config.rules.alert_threshold for r in results)
    if mode == "ml":
        return any(
            r.ml_score is not None and r.ml_score == r.ml_score and r.ml_score >= engine.config.ml.alert_threshold
            for r in results
        )
    return any(engine.is_alert(r) for r in results)


def confusion(tp: int, fp: int, tn: int, fn: int) -> dict[str, float | int | list[list[int]]]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    tpr = recall
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tpr": tpr,
        "fpr": fpr,
        "matrix": [[tn, fp], [fn, tp]],
    }


def evaluate_pair(
    benign_pcap: str | Path,
    tunnel_pcap: str | Path,
    engine: DetectionEngine | None = None,
    config: AppConfig | None = None,
    mode: str = "combined",
) -> dict[str, object]:
    """Treat each pcap as one labeled session (0=benign, 1=tunnel)."""
    engine = engine or DetectionEngine(config or load_config())
    # Fresh aggregators per file
    benign_engine = DetectionEngine(engine.config, classifier=engine.classifier)
    tunnel_engine = DetectionEngine(engine.config, classifier=engine.classifier)
    benign_dets = score_pcap(benign_pcap, benign_engine)
    tunnel_dets = score_pcap(tunnel_pcap, tunnel_engine)
    pred_benign = _predicted_positive(benign_dets, engine, mode)
    pred_tunnel = _predicted_positive(tunnel_dets, engine, mode)
    tp = int(pred_tunnel)
    fn = int(not pred_tunnel)
    fp = int(pred_benign)
    tn = int(not pred_benign)
    metrics = confusion(tp, fp, tn, fn)
    metrics["mode"] = mode
    metrics["benign_windows"] = len(benign_dets)
    metrics["tunnel_windows"] = len(tunnel_dets)
    metrics["benign_max_rule"] = max((d.rule_score for d in benign_dets), default=0.0)
    metrics["tunnel_max_rule"] = max((d.rule_score for d in tunnel_dets), default=0.0)
    return metrics


def window_level_metrics(
    results_and_labels: Iterable[tuple[DetectionResult, int]],
    engine: DetectionEngine,
    mode: str = "rule",
) -> dict[str, float | int | list[list[int]]]:
    tp = fp = tn = fn = 0
    for det, label in results_and_labels:
        if mode == "ml":
            pred = int(
                det.ml_score is not None
                and det.ml_score == det.ml_score
                and det.ml_score >= engine.config.ml.alert_threshold
            )
        elif mode == "combined":
            pred = int(engine.is_alert(det))
        else:
            pred = int(det.rule_score >= engine.config.rules.alert_threshold)
        if label == 1 and pred == 1:
            tp += 1
        elif label == 0 and pred == 1:
            fp += 1
        elif label == 0 and pred == 0:
            tn += 1
        else:
            fn += 1
    return confusion(tp, fp, tn, fn)


def threshold_sweep(
    engine_factory,
    labeled_dets: list[tuple[DetectionResult, int]],
    thresholds: Iterable[float] | None = None,
) -> list[dict[str, float]]:
    """F1 vs rule threshold (ML ignored). ``engine_factory`` rebuilds with new threshold."""
    from dns_exfil_detect.config import load_config

    rows: list[dict[str, float]] = []
    for thr in thresholds or [i / 20 for i in range(2, 19)]:
        cfg = load_config() if not hasattr(engine_factory, "config") else engine_factory.config
        cfg.rules.alert_threshold = float(thr)
        engine = DetectionEngine(cfg)
        m = window_level_metrics(labeled_dets, engine, mode="rule")
        rows.append({"threshold": float(thr), "f1": float(m["f1"]), "precision": float(m["precision"]), "recall": float(m["recall"])})
    return rows
