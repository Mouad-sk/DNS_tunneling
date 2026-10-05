"""Local domain-popularity lookup (Tranco / Alexa-style ranked list)."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path


class ReputationList:
    """In-memory set of popular parent domains (e.g. Tranco top-1M)."""

    def __init__(self, domains: Iterable[str] | None = None) -> None:
        self.domains: set[str] = {d.lower().strip(".") for d in domains or []}

    @classmethod
    def from_file(cls, path: str | Path) -> ReputationList:
        file_path = Path(path)
        if not file_path.is_file():
            return cls([])
        found: list[str] = []
        for line in file_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "," in line:
                line = line.split(",")[-1].strip()
            if "\t" in line:
                line = line.split("\t")[-1].strip()
            found.append(line.lower().strip("."))
        return cls(found)

    def contains(self, domain: str) -> bool:
        return domain.lower().strip(".") in self.domains

    def __len__(self) -> int:
        return len(self.domains)
