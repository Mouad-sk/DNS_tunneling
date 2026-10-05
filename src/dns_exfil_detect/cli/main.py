"""Rich + Typer CLI."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from dns_exfil_detect import __version__
from dns_exfil_detect.benchmark import evaluate_pair, threshold_sweep
from dns_exfil_detect.config import load_config
from dns_exfil_detect.detection.engine import DetectionEngine
from dns_exfil_detect.models import DetectionResult
from dns_exfil_detect.pipeline import analyze, iter_siem_lines
from dns_exfil_detect.synth import generate_benign_session, generate_tunnel_session, write_demo_pcaps
from dns_exfil_detect.train import train_model

app = typer.Typer(no_args_is_help=True, add_completion=False, help="DNS tunneling / exfiltration detection")
console = Console()

LEVEL_STYLE = {
    "info": "cyan",
    "low": "blue",
    "medium": "yellow",
    "high": "dark_orange",
    "critical": "bold red",
}


def _print_detections(dets: list[DetectionResult]) -> None:
    table = Table(title="DNS exfiltration / C2 detections")
    table.add_column("Risk")
    table.add_column("Src IP")
    table.add_column("Domain")
    table.add_column("Rule")
    table.add_column("ML")
    table.add_column("Queries")
    table.add_column("Reason", overflow="fold")
    for det in dets:
        style = LEVEL_STYLE.get(det.risk_level, "white")
        ml = "—" if det.ml_score is None or det.ml_score != det.ml_score else f"{det.ml_score:.3f}"
        table.add_row(
            Text(det.risk_level.upper(), style=style),
            det.src_ip,
            det.domain,
            f"{det.rule_score:.3f}",
            ml,
            str(det.raw_query_count),
            det.reason,
        )
    console.print(table)


@app.command()
def version() -> None:
    """Print package version."""
    console.print(__version__)


@app.command("analyze")
def analyze_cmd(
    path: Optional[Path] = typer.Option(None, "--pcap", "--path", help="pcap, dns.log, or eve.json"),
    interface: Optional[str] = typer.Option(None, "--iface", help="Live capture interface"),
    config: Optional[Path] = typer.Option(None, "--config", help="YAML config"),
    no_store: bool = typer.Option(False, "--no-store"),
    siem: bool = typer.Option(False, "--siem", help="Print CEF/syslog lines"),
    live_count: int = typer.Option(0, "--count", help="Live packet count (0 = sniff until timeout/interrupt)"),
    live_timeout: Optional[float] = typer.Option(None, "--timeout", help="Live sniff timeout seconds"),
) -> None:
    """Analyze a pcap/log or sniff DNS on an interface."""
    if path is None and not interface:
        raise typer.BadParameter("Provide --pcap/--path or --iface")
    cfg = load_config(config)
    queries, dets = analyze(
        path=path,
        interface=interface,
        config=cfg,
        store=not no_store,
        live_count=live_count,
        live_timeout=live_timeout,
    )
    console.print(f"Parsed [bold]{len(queries)}[/] DNS queries, [bold]{len(dets)}[/] windows scored")
    _print_detections(dets)
    if siem:
        for line in iter_siem_lines(dets, cfg):
            console.print(line)


@app.command()
def train(
    config: Optional[Path] = typer.Option(None, "--config"),
    backend: str = typer.Option("random_forest", "--backend"),
    out: Optional[Path] = typer.Option(None, "--out"),
) -> None:
    """Train ML on disjoint synthetic sessions and write feature importance."""
    cfg = load_config(config)
    result = train_model(config=cfg, backend=backend, out_path=out)
    payload = {k: v for k, v in result.items() if k != "report"}
    console.print_json(data=payload)
    table = Table(title="Feature importance")
    table.add_column("Feature")
    table.add_column("Importance")
    importance = result["feature_importance"]
    assert isinstance(importance, dict)
    for name, value in sorted(importance.items(), key=lambda kv: kv[1], reverse=True):
        table.add_row(name, f"{value:.4f}")
    console.print(table)


@app.command()
def benchmark(
    benign: Optional[Path] = typer.Option(None, "--benign", help="Labeled benign pcap"),
    malicious: Optional[Path] = typer.Option(None, "--malicious", help="Labeled tunnel pcap"),
    config: Optional[Path] = typer.Option(None, "--config"),
    generate: bool = typer.Option(False, "--generate-demo", help="Write demo pcaps under data/demo"),
) -> None:
    """Compute TPR/FPR/precision/recall/F1 and a confusion matrix."""
    cfg = load_config(config)
    if generate or benign is None or malicious is None:
        demo_dir = Path.cwd() / "data" / "demo"
        benign_s, mal_s = write_demo_pcaps(str(demo_dir))
        benign = Path(benign_s)
        malicious = Path(mal_s)
        console.print(f"Wrote demo pcaps to {demo_dir}")
    engine = DetectionEngine(cfg)
    for mode in ("rule", "ml", "combined"):
        metrics = evaluate_pair(benign, malicious, engine=engine, mode=mode)
        console.print(f"\n[bold]{mode}[/] session-level metrics")
        console.print_json(data=metrics)


@app.command()
def sweep(
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """F1 across rule thresholds on synthetic labeled windows."""
    cfg = load_config(config)
    engine = DetectionEngine(cfg)
    pairs: list[tuple[DetectionResult, int]] = []
    for events, label in (
        (generate_benign_session(2, 200), 0),
        (generate_tunnel_session(3, 200), 1),
    ):
        eng = DetectionEngine(cfg, classifier=engine.classifier)
        dets: list[DetectionResult] = []
        for _feat, det in eng.process_events(events):
            if det:
                dets.append(det)
        dets.extend(eng.flush())
        pairs.extend((d, label) for d in dets)
    rows = threshold_sweep(engine, pairs)
    table = Table(title="Rule threshold sweep (window-level F1)")
    table.add_column("threshold")
    table.add_column("precision")
    table.add_column("recall")
    table.add_column("F1")
    best = max(rows, key=lambda r: r["f1"])
    for row in rows:
        marker = " *" if row["threshold"] == best["threshold"] else ""
        table.add_row(
            f"{row['threshold']:.2f}{marker}",
            f"{row['precision']:.3f}",
            f"{row['recall']:.3f}",
            f"{row['f1']:.3f}",
        )
    console.print(table)
    console.print(f"Best F1={best['f1']:.3f} at threshold={best['threshold']:.2f}")


@app.command()
def dashboard(
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Launch the Streamlit dashboard."""
    import os
    import subprocess
    import sys

    app_path = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"
    env = os.environ.copy()
    if config:
        env["DNS_EXFIL_CONFIG"] = str(Path(config).resolve())
    raise SystemExit(subprocess.call([sys.executable, "-m", "streamlit", "run", str(app_path)], env=env))


@app.command("serve-api")
def serve_api(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8080, "--port"),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Serve a small JSON API over detections (SIEM-friendly)."""
    from dns_exfil_detect.api import run_api

    cfg = load_config(config)
    console.print(f"API listening on http://{host}:{port}  (GET /detections, GET /health)")
    run_api(cfg, host=host, port=port)


@app.command()
def export_siem(
    db: Optional[Path] = typer.Option(None, "--db"),
    config: Optional[Path] = typer.Option(None, "--config"),
    fmt: str = typer.Option("cef", "--format"),
) -> None:
    """Dump detections from SQLite as CEF or syslog."""
    from dns_exfil_detect.storage.siem import format_event
    from dns_exfil_detect.storage.sqlite import SqliteStorage

    cfg = load_config(config)
    store = SqliteStorage(db or cfg.sqlite_path)
    for row in store.fetch_detections(limit=10_000):
        det = DetectionResult(
            timestamp=datetime.fromisoformat(str(row["timestamp"])),
            src_ip=str(row["src_ip"]),
            domain=str(row["domain"]),
            rule_score=float(row["rule_score"]),
            ml_score=None if row["ml_score"] is None else float(row["ml_score"]),
            reason=str(row["reason"] or ""),
            raw_query_count=int(row["raw_query_count"] or 0),
            window_start=datetime.fromisoformat(str(row["window_start"])),
            window_end=datetime.fromisoformat(str(row["window_end"])),
            risk_level=str(row["risk_level"] or "info"),
        )
        console.print(format_event(det, fmt=fmt, product=cfg.product))
    store.close()


def main() -> None:
    app()


if __name__ == "__main__":
    app()
