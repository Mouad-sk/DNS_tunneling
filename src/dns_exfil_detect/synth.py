"""Labeled synthetic DNS sessions for training and unit tests.

Events mimic *observed query names and rates*, not a working tunnel client.
Two disjoint sessions (different IPs, time bases, and parent domains) support
a capture-session train/test split instead of a random row split.
"""

from __future__ import annotations

import random
import string
from datetime import datetime, timedelta, timezone

from dns_exfil_detect.models import DnsQueryEvent

BENIGN_HOSTS = [
    "www.google.com",
    "accounts.google.com",
    "mail.google.com",
    "outlook.office.com",
    "login.microsoftonline.com",
    "api.github.com",
    "github.com",
    "itunes.apple.com",
    "configuration.apple.com",
    "www.amazon.com",
    "s3.amazonaws.com",
    "cdn.jsdelivr.net",
    "fonts.googleapis.com",
    "www.linkedin.com",
    "zoom.us",
    "edge.microsoft.com",
    "windowsupdate.microsoft.com",
    "ocsp.digicert.com",
    "www.wikipedia.org",
    "cloudflare-dns.com",
]

BENIGN_TYPES = ["A", "AAAA", "CNAME", "A", "A"]


def _ts(session: int, offset_s: float) -> datetime:
    base = datetime(2024, 1, 1, tzinfo=timezone.utc) + timedelta(days=session * 7)
    return base + timedelta(seconds=offset_s)


def _rand_alnum(rng: random.Random, n: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(n))


def generate_benign_session(
    session_id: int,
    n_queries: int = 400,
    src_ip: str | None = None,
    seed: int = 1,
) -> list[DnsQueryEvent]:
    """Office-like recursive DNS: popular names, A/AAAA, mostly NOERROR."""
    rng = random.Random(seed + session_id * 17)
    ip = src_ip or f"10.{session_id}.1.{rng.randint(10, 200)}"
    events: list[DnsQueryEvent] = []
    t = 0.0
    for _ in range(n_queries):
        t += rng.uniform(0.3, 4.0)
        fqdn = rng.choice(BENIGN_HOSTS)
        if rng.random() < 0.12:
            fqdn = f"img{rng.randint(1, 9)}.{rng.choice(['akamaihd.net', 'cloudfront.net', 'office.net'])}"
        rcode = "NXDOMAIN" if rng.random() < 0.04 else "NOERROR"
        events.append(
            DnsQueryEvent(
                timestamp=_ts(session_id, t),
                src_ip=ip,
                dst_ip="10.0.0.53",
                fqdn=fqdn,
                record_type=rng.choice(BENIGN_TYPES),
                response_code=rcode,
                response_size=rng.randint(64, 220),
            )
        )
    return events


def generate_tunnel_session(
    session_id: int,
    n_queries: int = 400,
    src_ip: str | None = None,
    seed: int = 1,
    parent: str | None = None,
) -> list[DnsQueryEvent]:
    """High-entropy unique labels under an unpopular parent — tunnel-shaped traffic."""
    rng = random.Random(seed + 99 + session_id * 13)
    ip = src_ip or f"10.{session_id}.8.{rng.randint(10, 200)}"
    parent = parent or f"s{session_id}{rng.choice(['cdn-upd', 'mailer-int', 'ntp-sync'])}.internal-test.net"
    events: list[DnsQueryEvent] = []
    t = 0.0
    types = ["TXT", "NULL", "A", "CNAME", "TXT"]
    for i in range(n_queries):
        t += rng.uniform(0.05, 0.6)
        label_len = rng.randint(28, 52)
        label = _rand_alnum(rng, label_len)
        # Chunk index style unique subdomain per query
        fqdn = f"{label}.{i:04x}.{parent}"
        rcode = "NXDOMAIN" if rng.random() < 0.42 else "NOERROR"
        qtype = rng.choice(types)
        events.append(
            DnsQueryEvent(
                timestamp=_ts(session_id, t),
                src_ip=ip,
                dst_ip="10.0.0.53",
                fqdn=fqdn,
                record_type=qtype,
                response_code=rcode,
                response_size=rng.randint(80, 900) if qtype == "TXT" else rng.randint(40, 180),
            )
        )
    return events


def labeled_sessions(
    *,
    benign_n: int = 400,
    tunnel_n: int = 400,
    seed: int = 7,
) -> tuple[list[tuple[DnsQueryEvent, int]], list[tuple[DnsQueryEvent, int]]]:
    """Return (train, test) as lists of (event, label) from disjoint sessions.

    Session 0 = train benign, session 1 = train tunnel,
    session 2 = test benign, session 3 = test tunnel.
    """
    train = [(e, 0) for e in generate_benign_session(0, benign_n, seed=seed)] + [
        (e, 1) for e in generate_tunnel_session(1, tunnel_n, seed=seed)
    ]
    test = [(e, 0) for e in generate_benign_session(2, benign_n, seed=seed + 1)] + [
        (e, 1) for e in generate_tunnel_session(3, tunnel_n, seed=seed + 1)
    ]
    return train, test


def write_demo_pcaps(out_dir: str, seed: int = 7) -> tuple[str, str]:
    """Write two labeled pcaps (benign / tunnel-shaped) for ``benchmark.py``."""
    from pathlib import Path

    from scapy.all import DNS, DNSQR, IP, UDP, wrpcap  # type: ignore[import-untyped]

    dest = Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    benign_path = dest / "benign_session.pcap"
    tunnel_path = dest / "tunnel_session.pcap"

    def to_pkts(events: list[DnsQueryEvent]) -> list[object]:
        pkts = []
        for i, ev in enumerate(events):
            q = (
                IP(src=ev.src_ip, dst=ev.dst_ip or "10.0.0.53")
                / UDP(sport=40000 + (i % 20000), dport=53)
                / DNS(id=i % 65535, rd=1, qd=DNSQR(qname=ev.fqdn, qtype=ev.record_type))
            )
            rcode = 3 if ev.response_code == "NXDOMAIN" else 0
            r = (
                IP(src=ev.dst_ip or "10.0.0.53", dst=ev.src_ip)
                / UDP(sport=53, dport=40000 + (i % 20000))
                / DNS(id=i % 65535, qr=1, aa=1, rcode=rcode, qd=DNSQR(qname=ev.fqdn, qtype=ev.record_type))
            )
            q.time = ev.timestamp.timestamp()
            r.time = ev.timestamp.timestamp() + 0.01
            pkts.extend([q, r])
        return pkts

    wrpcap(str(benign_path), to_pkts(generate_benign_session(2, 250, seed=seed)))
    wrpcap(str(tunnel_path), to_pkts(generate_tunnel_session(3, 250, seed=seed)))
    return str(benign_path), str(tunnel_path)
