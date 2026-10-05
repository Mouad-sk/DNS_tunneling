"""Log ingest and pcap pairing tests."""

from __future__ import annotations

from pathlib import Path

from dns_exfil_detect.capture.factory import open_source
from dns_exfil_detect.capture.suricata import SuricataEveCapture
from dns_exfil_detect.capture.zeek import ZeekDnsLogCapture
from dns_exfil_detect.synth import write_demo_pcaps


def test_zeek_dns_log(tmp_path: Path) -> None:
    log = tmp_path / "dns.log"
    log.write_text(
        "\n".join(
            [
                "#separator \\x09",
                "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\tquery\tqclass\tqtype\tqtype_name\trcode\trcode_name",
                "1710000000.1\tC1\t10.0.0.8\t12345\t10.0.0.53\t53\tudp\t1\twww.google.com\t1\t1\tA\t0\tNOERROR",
                "1710000001.1\tC2\t10.0.0.8\t12346\t10.0.0.53\t53\tudp\t2\taaaa.payload.evil-test.net\t1\t16\tTXT\t3\tNXDOMAIN",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    events = list(ZeekDnsLogCapture(log).events())
    assert len(events) == 2
    assert events[0].fqdn == "www.google.com"
    assert events[0].record_type == "A"
    assert events[1].response_code == "NXDOMAIN"
    assert events[1].record_type == "TXT"


def test_suricata_eve(tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text(
        '{"timestamp":"2024-01-01T00:00:00.000000+0000","event_type":"dns","src_ip":"10.1.1.2","dest_ip":"10.0.0.53","dns":{"rrname":"Mail.Google.COM","rrtype":"A","rcode":"NOERROR","id":9}}\n'
        '{"timestamp":"2024-01-01T00:00:01.000000+0000","event_type":"alert","src_ip":"10.1.1.2"}\n',
        encoding="utf-8",
    )
    events = list(SuricataEveCapture(eve).events())
    assert len(events) == 1
    assert events[0].fqdn == "mail.google.com"
    assert events[0].record_type == "A"


def test_open_source_routes_logs(tmp_path: Path) -> None:
    log = tmp_path / "dns.log"
    log.write_text("#fields\tts\tquery\n1\twww.example.com\n", encoding="utf-8")
    backend = open_source(log)
    assert isinstance(backend, ZeekDnsLogCapture)


def test_pcap_roundtrip(tmp_path: Path) -> None:
    benign, tunnel = write_demo_pcaps(str(tmp_path / "pcaps"))
    b = list(open_source(benign).events())
    t = list(open_source(tunnel).events())
    assert len(b) >= 50
    assert len(t) >= 50
    assert any(e.response_code == "NXDOMAIN" for e in t)
    assert any("google.com" in e.fqdn or "microsoft" in e.fqdn or "apple.com" in e.fqdn for e in b)
