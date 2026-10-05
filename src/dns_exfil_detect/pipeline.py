"""End-to-end analysis: capture → features → dual score → SQLite / SIEM."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from dns_exfil_detect.capture.base import batched
from dns_exfil_detect.capture.factory import open_source
from dns_exfil_detect.config import AppConfig, load_config
from dns_exfil_detect.detection.engine import DetectionEngine
from dns_exfil_detect.models import DetectionResult, QueryFeatures
from dns_exfil_detect.storage.siem import format_event
from dns_exfil_detect.storage.sqlite import SqliteStorage


def analyze(
    *,
    path: str | Path | None = None,
    interface: str | None = None,
    config: AppConfig | None = None,
    store: bool = True,
    live_count: int = 0,
    live_timeout: float | None = None,
) -> tuple[list[QueryFeatures], list[DetectionResult]]:
    cfg = config or load_config()
    backend = open_source(
        path,
        interface=interface,
        bpf_filter=cfg.bpf_filter,
        live_count=live_count,
        live_timeout=live_timeout,
    )
    engine = DetectionEngine(cfg)
    storage = SqliteStorage(cfg.sqlite_path) if store else None
    queries: list[QueryFeatures] = []
    detections: list[DetectionResult] = []

    for batch in batched(backend.events(), cfg.batch_size):
        q_batch: list[QueryFeatures] = []
        d_batch: list[DetectionResult] = []
        for feat, det in engine.process_events(batch, alerts_only=False):
            q_batch.append(feat)
            if det is not None:
                d_batch.append(det)
        queries.extend(q_batch)
        detections.extend(d_batch)
        if storage:
            storage.insert_queries(q_batch)
            storage.insert_detections(d_batch)

    flushed = engine.flush(alerts_only=False)
    detections.extend(flushed)
    if storage:
        storage.insert_detections(flushed)
        storage.close()
    return queries, detections


def iter_siem_lines(detections: list[DetectionResult], cfg: AppConfig | None = None) -> Iterator[str]:
    cfg = cfg or load_config()
    for det in detections:
        yield format_event(det, fmt=cfg.siem_format, product=cfg.product)
