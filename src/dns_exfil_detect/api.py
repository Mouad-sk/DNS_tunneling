"""Minimal JSON HTTP API over SQLite detections (stdlib only)."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from dns_exfil_detect.config import AppConfig
from dns_exfil_detect.storage.sqlite import SqliteStorage


def run_api(config: AppConfig, host: str = "127.0.0.1", port: int = 8080) -> None:
    storage = SqliteStorage(config.sqlite_path)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def _json(self, payload: object, status: int = 200) -> None:
            raw = json.dumps(payload, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            if parsed.path in {"/health", "/"}:
                self._json({"status": "ok", "product": config.product})
                return
            if parsed.path == "/detections":
                limit = int(qs.get("limit", ["200"])[0])
                self._json({"detections": storage.fetch_detections(limit=limit)})
                return
            if parsed.path == "/queries":
                limit = int(qs.get("limit", ["200"])[0])
                src = qs.get("src_ip", [None])[0]
                self._json({"queries": storage.fetch_queries(limit=limit, src_ip=src)})
                return
            self._json({"error": "not found"}, status=404)

    try:
        server = ThreadingHTTPServer((host, port), Handler)
        server.serve_forever()
    finally:
        storage.close()
