"""Zeek ``dns.log`` (tab-separated, #fields header) ingest."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from dns_exfil_detect.capture._parse import parse_ts, qtype_name, rcode_name
from dns_exfil_detect.capture.base import CaptureBackend
from dns_exfil_detect.models import DnsQueryEvent


class ZeekDnsLogCapture(CaptureBackend):
    """Parse Zeek-style ``dns.log`` (TSV with ``#fields``)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.is_file():
            raise FileNotFoundError(f"Zeek dns.log not found: {self.path}")

    def events(self) -> Iterator[DnsQueryEvent]:
        fields: list[str] = []
        with self.path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.rstrip("\n")
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    continue
                if not line or line.startswith("#"):
                    continue
                cols = line.split("\t")
                row = {fields[i]: cols[i] if i < len(cols) else "" for i in range(len(fields))}
                if not fields:
                    row = _positional(cols)
                query = (row.get("query") or "").strip().rstrip(".").lower()
                if not query or query == "-":
                    continue
                yield DnsQueryEvent(
                    timestamp=parse_ts(row.get("ts") or "0"),
                    src_ip=row.get("id.orig_h") or row.get("id_orig_h") or "",
                    dst_ip=row.get("id.resp_h") or row.get("id_resp_h") or "",
                    fqdn=query,
                    record_type=qtype_name(row.get("qtype_name") or row.get("qtype")),
                    response_code=rcode_name(row.get("rcode_name") or row.get("rcode")),
                    response_size=_answer_size(row.get("answers")),
                    query_id=_safe_int(row.get("trans_id")),
                )


def _positional(cols: list[str]) -> dict[str, str]:
    names = [
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "trans_id",
        "query",
        "qclass",
        "qtype",
        "rcode",
    ]
    return {names[i]: cols[i] for i in range(min(len(names), len(cols)))}


def _answer_size(answers: str | None) -> int:
    if not answers or answers in {"-", "(empty)"}:
        return 0
    return len(answers)


def _safe_int(value: str | None) -> int | None:
    if value is None or value in {"", "-"}:
        return None
    try:
        return int(value)
    except ValueError:
        return None
