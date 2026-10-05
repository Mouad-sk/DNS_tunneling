"""Storage backend interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence

from dns_exfil_detect.models import DetectionResult, QueryFeatures


class StorageBackend(ABC):
    """Persisted queries and detections (SQLite today; SIEM later)."""

    @abstractmethod
    def init_schema(self) -> None:
        """Create tables if they do not exist."""

    @abstractmethod
    def insert_queries(self, rows: Sequence[QueryFeatures]) -> None:
        """Bulk-insert raw query features."""

    @abstractmethod
    def insert_detections(self, rows: Sequence[DetectionResult]) -> None:
        """Bulk-insert detection records."""

    @abstractmethod
    def fetch_detections(self, limit: int = 500) -> list[dict[str, object]]:
        """Recent detections for the dashboard / API."""

    @abstractmethod
    def fetch_queries(self, limit: int = 500, src_ip: str | None = None) -> list[dict[str, object]]:
        """Recent raw queries, optionally filtered by client IP."""

    def insert_query(self, row: QueryFeatures) -> None:
        self.insert_queries([row])

    def insert_detection(self, row: DetectionResult) -> None:
        self.insert_detections([row])

    def close(self) -> None:
        return None


def store_stream(
    storage: StorageBackend,
    queries: Iterable[QueryFeatures],
    detections: Iterable[DetectionResult],
) -> None:
    storage.insert_queries(list(queries))
    storage.insert_detections(list(detections))
