"""Live DNS capture via scapy (BPF filter, cross-platform)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone

from dns_exfil_detect.capture._parse import qtype_name, rcode_name
from dns_exfil_detect.capture.base import CaptureBackend
from dns_exfil_detect.models import DnsQueryEvent


class LiveCapture(CaptureBackend):
    """Sniff DNS on a network interface.

    Requires libpcap/Npcap on the host. Works on Linux, Windows, and macOS
    with the same scapy API — no OS-specific syscalls in this module.
    """

    def __init__(
        self,
        interface: str,
        bpf_filter: str = "udp port 53 or tcp port 53",
        count: int = 0,
        timeout: float | None = None,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.count = count
        self.timeout = timeout

    def events(self) -> Iterator[DnsQueryEvent]:
        try:
            from scapy.all import DNS, IP, IPv6, sniff  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError("scapy is required for live capture") from exc

        kwargs: dict[str, object] = {
            "iface": self.interface,
            "filter": self.bpf_filter,
            "store": True,
        }
        if self.count:
            kwargs["count"] = self.count
        if self.timeout is not None:
            kwargs["timeout"] = self.timeout

        packets = sniff(**kwargs)
        for pkt in packets:
            if DNS not in pkt:
                continue
            dns = pkt[DNS]
            if int(dns.qr) != 0 and dns.qd is None:
                continue
            ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc)
            src = str(pkt[IP].src) if IP in pkt else (str(pkt[IPv6].src) if IPv6 in pkt else "")
            dst = str(pkt[IP].dst) if IP in pkt else (str(pkt[IPv6].dst) if IPv6 in pkt else "")
            qd = dns.qd
            qname = str(getattr(qd, "qname", b"") or b"")
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="replace")
            qname = qname.rstrip(".").lower()
            if not qname:
                continue
            qtype = qtype_name(getattr(qd, "qtype", None))
            rcode = rcode_name(int(dns.rcode)) if int(dns.qr) == 1 else "NOERROR"
            yield DnsQueryEvent(
                timestamp=ts,
                src_ip=src,
                dst_ip=dst,
                fqdn=qname,
                record_type=qtype,
                response_code=rcode,
                response_size=len(bytes(dns)) if int(dns.qr) == 1 else 0,
                query_id=int(dns.id),
            )
