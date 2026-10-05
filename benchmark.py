#!/usr/bin/env python3
"""CLI wrapper: benchmark labeled benign vs malicious pcaps.

Example:
  python benchmark.py --benign data/demo/benign_session.pcap --malicious data/demo/tunnel_session.pcap
  python benchmark.py --generate-demo
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from dns_exfil_detect.benchmark import evaluate_pair  # noqa: E402
from dns_exfil_detect.config import load_config  # noqa: E402
from dns_exfil_detect.detection.engine import DetectionEngine  # noqa: E402
from dns_exfil_detect.synth import write_demo_pcaps  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark DNS tunnel detector")
    parser.add_argument("--benign", type=Path, help="Labeled benign pcap")
    parser.add_argument("--malicious", type=Path, help="Labeled tunneling pcap")
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--generate-demo", action="store_true")
    parser.add_argument("--mode", default="all", choices=["rule", "ml", "combined", "all"])
    args = parser.parse_args()

    cfg = load_config(args.config)
    benign, malicious = args.benign, args.malicious
    if args.generate_demo or benign is None or malicious is None:
        demo = ROOT / "data" / "demo"
        b, m = write_demo_pcaps(str(demo))
        benign, malicious = Path(b), Path(m)
        print(f"Wrote demo pcaps: {benign} {malicious}")

    engine = DetectionEngine(cfg)
    modes = ["rule", "ml", "combined"] if args.mode == "all" else [args.mode]
    out = {mode: evaluate_pair(benign, malicious, engine=engine, mode=mode) for mode in modes}
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
