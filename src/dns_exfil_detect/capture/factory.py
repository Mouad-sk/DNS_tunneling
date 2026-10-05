"""Select a capture backend from a path or live interface."""

from __future__ import annotations

from pathlib import Path

from dns_exfil_detect.capture.base import CaptureBackend
from dns_exfil_detect.capture.live import LiveCapture
from dns_exfil_detect.capture.pcap import PcapCapture
from dns_exfil_detect.capture.suricata import SuricataEveCapture
from dns_exfil_detect.capture.zeek import ZeekDnsLogCapture


def open_source(
    path: str | Path | None = None,
    *,
    interface: str | None = None,
    bpf_filter: str = "udp port 53 or tcp port 53",
    live_count: int = 0,
    live_timeout: float | None = None,
) -> CaptureBackend:
    """Factory: pcap, Zeek dns.log, Suricata eve.json, or live sniff."""
    if interface:
        return LiveCapture(
            interface=interface,
            bpf_filter=bpf_filter,
            count=live_count,
            timeout=live_timeout,
        )
    if path is None:
        raise ValueError("Provide a pcap/log path or a live interface")
    source = Path(path)
    suffix = source.suffix.lower()
    name = source.name.lower()
    if suffix in {".pcap", ".pcapng", ".cap"}:
        return PcapCapture(source)
    if "eve" in name and suffix == ".json":
        return SuricataEveCapture(source)
    if suffix == ".json" or name.endswith("eve.json"):
        return SuricataEveCapture(source)
    if "dns.log" in name or suffix == ".log":
        return ZeekDnsLogCapture(source)
    if suffix in {".pcap", ".pcapng"}:
        return PcapCapture(source)
    # Default: try Zeek if the file starts with a Zeek header, else pcap.
    try:
        head = source.read_text(encoding="utf-8", errors="replace")[:64]
    except OSError:
        head = ""
    if head.startswith("#") or "\t" in head:
        return ZeekDnsLogCapture(source)
    return PcapCapture(source)
