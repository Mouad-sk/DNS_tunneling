"""Offline pcap reader via scapy."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from dns_exfil_detect.capture._parse import qtype_name, rcode_name
from dns_exfil_detect.capture.base import CaptureBackend
from dns_exfil_detect.models import DnsQueryEvent


class PcapCapture(CaptureBackend):
    """Parse DNS from a ``.pcap`` / ``.pcapng`` file using scapy.

    Queries are paired with responses by (client IP, DNS ID) when both are
    present so ``response_code`` and ``response_size`` are populated.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.is_file():
            raise FileNotFoundError(f"pcap not found: {self.path}")

    def events(self) -> Iterator[DnsQueryEvent]:
        try:
            from scapy.all import DNS, IP, IPv6, PcapReader  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError("scapy is required to read pcap files") from exc

        pending: dict[tuple[str, int], DnsQueryEvent] = {}

        with PcapReader(str(self.path)) as reader:
            for pkt in reader:
                if DNS not in pkt:
                    continue
                dns = pkt[DNS]
                ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc)
                src = _ip_of(pkt, src=True)
                dst = _ip_of(pkt, src=False)
                qname, qtype = _question(dns)
                if not qname:
                    continue
                ident = int(dns.id)
                qr = int(dns.qr)

                if qr == 0:
                    pending[(src, ident)] = DnsQueryEvent(
                        timestamp=ts,
                        src_ip=src,
                        dst_ip=dst,
                        fqdn=qname,
                        record_type=qtype,
                        response_code="NOERROR",
                        response_size=0,
                        query_id=ident,
                    )
                    continue

                rcode = rcode_name(int(dns.rcode))
                size = len(bytes(dns))
                key = (dst, ident)
                prior = pending.pop(key, None)
                if prior is not None:
                    yield DnsQueryEvent(
                        timestamp=prior.timestamp,
                        src_ip=prior.src_ip,
                        dst_ip=prior.dst_ip,
                        fqdn=prior.fqdn,
                        record_type=prior.record_type,
                        response_code=rcode,
                        response_size=size,
                        query_id=ident,
                    )
                else:
                    yield DnsQueryEvent(
                        timestamp=ts,
                        src_ip=dst or src,
                        dst_ip=src,
                        fqdn=qname,
                        record_type=qtype,
                        response_code=rcode,
                        response_size=size,
                        query_id=ident,
                    )

        yield from pending.values()


def _question(dns: object) -> tuple[str, str]:
    qd = getattr(dns, "qd", None)
    if qd is None:
        return "", "UNKNOWN"
    qname = str(getattr(qd, "qname", b"") or b"")
    if isinstance(qname, bytes):
        qname = qname.decode("utf-8", errors="replace")
    qname = qname.rstrip(".")
    qtype = qtype_name(getattr(qd, "qtype", None))
    return qname.lower(), qtype


def _ip_of(pkt: object, *, src: bool) -> str:
    try:
        from scapy.all import IP, IPv6  # type: ignore[import-untyped]
    except ImportError:
        return ""
    if IP in pkt:
        return str(pkt[IP].src if src else pkt[IP].dst)
    if IPv6 in pkt:
        return str(pkt[IPv6].src if src else pkt[IPv6].dst)
    return ""
