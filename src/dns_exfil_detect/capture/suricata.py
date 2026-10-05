"""Suricata ``eve.json`` DNS event ingest."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from dns_exfil_detect.capture._parse import parse_ts, qtype_name, rcode_name
from dns_exfil_detect.capture.base import CaptureBackend
from dns_exfil_detect.models import DnsQueryEvent


class SuricataEveCapture(CaptureBackend):
    """Parse Suricata EVE JSONL DNS records."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.is_file():
            raise FileNotFoundError(f"Suricata eve.json not found: {self.path}")

    def events(self) -> Iterator[DnsQueryEvent]:
        with self.path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("event_type") != "dns":
                    continue
                dns = rec.get("dns") or {}
                qname = (
                    dns.get("rrname")
                    or dns.get("query")
                    or _first_query_name(dns)
                    or ""
                )
                qname = str(qname).rstrip(".").lower()
                if not qname:
                    continue
                rcode = dns.get("rcode") or dns.get("rcode_name") or "NOERROR"
                qtype = dns.get("rrtype") or dns.get("type") or _first_query_type(dns)
                answers = dns.get("answers") or []
                size = 0
                if isinstance(answers, list):
                    size = sum(len(json.dumps(a)) for a in answers)
                yield DnsQueryEvent(
                    timestamp=parse_ts(rec.get("timestamp") or rec.get("ts") or 0),
                    src_ip=str(rec.get("src_ip") or ""),
                    dst_ip=str(rec.get("dest_ip") or rec.get("dst_ip") or ""),
                    fqdn=qname,
                    record_type=qtype_name(qtype),
                    response_code=rcode_name(rcode),
                    response_size=int(size),
                    query_id=_as_int(dns.get("id")),
                )


def _first_query_name(dns: dict[str, object]) -> str:
    queries = dns.get("queries")
    if isinstance(queries, list) and queries:
        first = queries[0]
        if isinstance(first, dict):
            return str(first.get("rrname") or first.get("rrname") or "")
    return ""


def _first_query_type(dns: dict[str, object]) -> str:
    queries = dns.get("queries")
    if isinstance(queries, list) and queries:
        first = queries[0]
        if isinstance(first, dict):
            return str(first.get("rrtype") or first.get("type") or "A")
    return "A"


def _as_int(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
