"""Sliding-window behavioral features per source IP."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta

from dns_exfil_detect.models import QueryFeatures, WindowFeatures


class SlidingWindowAggregator:
    """Maintain per-IP deques and emit window summaries on a sliding cadence."""

    def __init__(self, size_seconds: int = 60, slide_seconds: int = 30) -> None:
        self.size = timedelta(seconds=size_seconds)
        self.slide = timedelta(seconds=slide_seconds)
        self._buffers: dict[str, deque[QueryFeatures]] = defaultdict(deque)
        self._last_emit: dict[str, datetime] = {}

    def push(self, feat: QueryFeatures) -> list[WindowFeatures]:
        """Add one query; return any windows that closed for that source IP."""
        buf = self._buffers[feat.src_ip]
        buf.append(feat)
        cutoff = feat.timestamp - self.size
        while buf and buf[0].timestamp < cutoff:
            buf.popleft()
        last = self._last_emit.get(feat.src_ip)
        if last is None:
            self._last_emit[feat.src_ip] = feat.timestamp
            return []
        if feat.timestamp - last < self.slide:
            return []
        self._last_emit[feat.src_ip] = feat.timestamp
        window = summarize_window(feat.src_ip, list(buf))
        return [window] if window else []

    def flush(self) -> list[WindowFeatures]:
        """Emit remaining buffers (end of file / batch)."""
        out: list[WindowFeatures] = []
        for src_ip, buf in self._buffers.items():
            if not buf:
                continue
            window = summarize_window(src_ip, list(buf))
            if window:
                out.append(window)
        self._buffers.clear()
        self._last_emit.clear()
        return out


def windows_from_features(
    features: Iterable[QueryFeatures],
    size_seconds: int = 60,
    slide_seconds: int = 30,
) -> Iterator[WindowFeatures]:
    """Streaming-friendly conversion of a feature sequence into windows."""
    agg = SlidingWindowAggregator(size_seconds=size_seconds, slide_seconds=slide_seconds)
    for feat in features:
        yield from agg.push(feat)
    yield from agg.flush()


def summarize_window(src_ip: str, items: list[QueryFeatures]) -> WindowFeatures | None:
    """Aggregate query features for one source IP over the buffered span."""
    if not items:
        return None
    start = items[0].timestamp
    end = items[-1].timestamp
    span_seconds = max((end - start).total_seconds(), 1.0)
    qpm = len(items) * 60.0 / span_seconds

    parents: dict[str, set[str]] = defaultdict(set)
    record_counts: dict[str, int] = defaultdict(int)
    fqdns: set[str] = set()
    nx = 0
    txt_null = 0
    unpopular = 0
    sizes: list[int] = []
    entropies: list[float] = []
    labels: list[int] = []
    lengths: list[int] = []
    encodings: list[float] = []
    ngrams: list[float] = []
    samples: list[str] = []

    for item in items:
        fqdns.add(item.fqdn)
        parents[item.parent_domain].add(item.fqdn)
        record_counts[item.record_type] += 1
        if item.is_nxdomain:
            nx += 1
        if item.record_type in {"TXT", "NULL"}:
            txt_null += 1
        if not item.in_top_list:
            unpopular += 1
        sizes.append(item.response_size)
        entropies.append(item.shannon_entropy)
        labels.append(item.longest_label_length)
        lengths.append(item.fqdn_length)
        encodings.append(item.encoding_likeness)
        ngrams.append(item.ngram_score)
        if len(samples) < 8:
            samples.append(item.fqdn)

    parent_unique = {p: len(s) for p, s in parents.items()}
    # Unique-subdomain signal: many distinct left-hand labels under one parent.
    max_unique = max(parent_unique.values()) if parent_unique else 0
    unique_ratio = max_unique / len(items)

    n = float(len(items))
    return WindowFeatures(
        src_ip=src_ip,
        window_start=start,
        window_end=end,
        query_count=len(items),
        queries_per_minute=qpm,
        unique_fqdn_count=len(fqdns),
        unique_parent_count=len(parents),
        unique_subdomain_ratio=unique_ratio,
        nxdomain_ratio=nx / n,
        txt_null_ratio=txt_null / n,
        mean_response_size=sum(sizes) / n,
        max_response_size=float(max(sizes) if sizes else 0),
        mean_entropy=sum(entropies) / n,
        max_entropy=max(entropies) if entropies else 0.0,
        mean_longest_label=sum(labels) / n,
        max_longest_label=float(max(labels) if labels else 0),
        mean_fqdn_length=sum(lengths) / n,
        mean_encoding_likeness=sum(encodings) / n,
        mean_ngram_score=sum(ngrams) / n,
        unpopular_ratio=unpopular / n,
        record_type_counts=dict(record_counts),
        sample_domains=samples,
        parent_unique_subdomains=parent_unique,
    )
