"""Capture backend interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator

from dns_exfil_detect.models import DnsQueryEvent


class CaptureBackend(ABC):
    """Source of normalized DNS query events.

    Implementations may read pcaps, vendor logs, or live interfaces.
    Events should be yielded in timestamp order when the source allows it.
    """

    @abstractmethod
    def events(self) -> Iterator[DnsQueryEvent]:
        """Yield DNS transactions from the backing source."""


def batched(iterator: Iterator[DnsQueryEvent], size: int) -> Iterator[list[DnsQueryEvent]]:
    """Group an event stream into batches for windowed / streaming processing."""
    batch: list[DnsQueryEvent] = []
    for item in iterator:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch
