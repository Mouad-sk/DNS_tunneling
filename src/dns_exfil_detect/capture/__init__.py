"""Capture backends: pcap, live sniff, Zeek dns.log, Suricata EVE."""

from dns_exfil_detect.capture.base import CaptureBackend, batched
from dns_exfil_detect.capture.factory import open_source
from dns_exfil_detect.capture.live import LiveCapture
from dns_exfil_detect.capture.pcap import PcapCapture
from dns_exfil_detect.capture.suricata import SuricataEveCapture
from dns_exfil_detect.capture.zeek import ZeekDnsLogCapture

__all__ = [
    "CaptureBackend",
    "LiveCapture",
    "PcapCapture",
    "SuricataEveCapture",
    "ZeekDnsLogCapture",
    "batched",
    "open_source",
]
