"""SQLite persistence with a SIEM-friendly schema."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from dns_exfil_detect.models import DetectionResult, QueryFeatures
from dns_exfil_detect.storage.base import StorageBackend

SCHEMA = """
CREATE TABLE IF NOT EXISTS raw_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    fqdn TEXT NOT NULL,
    parent_domain TEXT,
    record_type TEXT NOT NULL,
    response_code TEXT NOT NULL,
    response_size INTEGER,
    fqdn_length INTEGER,
    longest_label_length INTEGER,
    shannon_entropy REAL,
    encoding_likeness REAL,
    ngram_score REAL,
    is_nxdomain INTEGER
);

CREATE INDEX IF NOT EXISTS idx_raw_queries_ts ON raw_queries(timestamp);
CREATE INDEX IF NOT EXISTS idx_raw_queries_src ON raw_queries(src_ip);

CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    domain TEXT NOT NULL,
    rule_score REAL NOT NULL,
    ml_score REAL,
    reason TEXT,
    raw_query_count INTEGER,
    risk_level TEXT,
    window_start TEXT,
    window_end TEXT
);

CREATE INDEX IF NOT EXISTS idx_detections_ts ON detections(timestamp);
CREATE INDEX IF NOT EXISTS idx_detections_src ON detections(src_ip);
CREATE INDEX IF NOT EXISTS idx_detections_level ON detections(risk_level);
"""


def _ts(value: datetime) -> str:
    return value.isoformat()


class SqliteStorage(StorageBackend):
    """File-backed SQLite store. Safe to copy into a SIEM pipeline later."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self.init_schema()

    def init_schema(self) -> None:
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def insert_queries(self, rows: Sequence[QueryFeatures]) -> None:
        if not rows:
            return
        self._conn.executemany(
            """
            INSERT INTO raw_queries (
                timestamp, src_ip, fqdn, parent_domain, record_type, response_code,
                response_size, fqdn_length, longest_label_length, shannon_entropy,
                encoding_likeness, ngram_score, is_nxdomain
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    _ts(r.timestamp),
                    r.src_ip,
                    r.fqdn,
                    r.parent_domain,
                    r.record_type,
                    r.response_code,
                    r.response_size,
                    r.fqdn_length,
                    r.longest_label_length,
                    r.shannon_entropy,
                    r.encoding_likeness,
                    r.ngram_score,
                    int(r.is_nxdomain),
                )
                for r in rows
            ],
        )
        self._conn.commit()

    def insert_detections(self, rows: Sequence[DetectionResult]) -> None:
        if not rows:
            return
        self._conn.executemany(
            """
            INSERT INTO detections (
                timestamp, src_ip, domain, rule_score, ml_score, reason,
                raw_query_count, risk_level, window_start, window_end
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    _ts(r.timestamp),
                    r.src_ip,
                    r.domain,
                    r.rule_score,
                    r.ml_score,
                    r.reason,
                    r.raw_query_count,
                    r.risk_level,
                    _ts(r.window_start),
                    _ts(r.window_end),
                )
                for r in rows
            ],
        )
        self._conn.commit()

    def fetch_detections(self, limit: int = 500) -> list[dict[str, object]]:
        cur = self._conn.execute(
            "SELECT * FROM detections ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        return [dict(row) for row in cur.fetchall()]

    def fetch_queries(self, limit: int = 500, src_ip: str | None = None) -> list[dict[str, object]]:
        if src_ip:
            cur = self._conn.execute(
                "SELECT * FROM raw_queries WHERE src_ip = ? ORDER BY timestamp DESC LIMIT ?",
                (src_ip, limit),
            )
        else:
            cur = self._conn.execute(
                "SELECT * FROM raw_queries ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
        return [dict(row) for row in cur.fetchall()]

    def close(self) -> None:
        self._conn.close()
