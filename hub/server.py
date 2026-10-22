#!/usr/bin/env python3
"""Mamori hub — tiny FastAPI-free HTTP service (stdlib only).

Endpoints:
  GET  /                 -> landing page (what is Mamori / how to join)
  GET  /api/latest       -> latest intel bundle (public, redacted)
  POST /api/observations -> partners submit attack observations (shared key)
  GET  /api/observations -> list shared observations (shared key via ?key= or header)
  GET  /healthz          -> ok

Storage: JSONL file at DATA_DIR/observations.jsonl
"""
from __future__ import annotations

import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

DATA_DIR = Path(os.environ.get("MAMORI_DATA", "./data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
OBS_FILE = DATA_DIR / "observations.jsonl"
LATEST_FILE = DATA_DIR / "latest_bundle.json"
SHARE_KEY = os.environ.get("MAMORI_SHARE_KEY", "")

LANDING = """<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>守 Mamori — セキュリティの民主化</title>
<style>body{font-family:system-ui,sans-serif;max-width:720px;margin:3rem auto;padding:0 1rem;line-height:1.7;color:#1a1a1a}
h1{font-size:2rem}code{background:#f2f2f2;padding:.1em .4em;border-radius:4px}
.card{border:1px solid #e5e5e5;border-radius:12px;padding:1.2rem;margin:1rem 0}
a{color:#0b5fff}</style></head><body>
<h1>🛡 守（まもり）Mamori</h1>
<p><strong>みんなでレポートして、みんなで守る。</strong><br>
Mamoriは、最新の攻撃情報・脆弱性情報を自動で集め、自分の環境に関係あるか照合し、
対策まで下書きするセキュリティエージェントです。ある1社が受けた攻撃の知見が、
全員の防御になります。</p>
<div class="card"><h2>いま検知している脅威</h2>
<p><a href="/api/latest">/api/latest</a> — 最新の脅威インテルバンドル（JSON・誰でも読めます）</p></div>
<div class="card"><h2>参加するには</h2>
<ol><li>攻撃の観測（怪しいIP・ペイロード・手法）を <code>POST /api/observations</code> に共有キーで投稿</li>
<li>全員の観測が <code>GET /api/observations</code> で共有されます</li>
<li>テスト参加・共有キーの発行は運営までご連絡ください</li></ol></div>
<p style="color:#888;font-size:.85rem">Mamori v0.1 — an Enabler project</p>
</body></html>"""


def _read_obs() -> list[dict]:
    if not OBS_FILE.exists():
        return []
    out = []
    for line in OBS_FILE.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str = "application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode())

    def _authorized(self) -> bool:
        if not SHARE_KEY:
            return False
        q = parse_qs(urlparse(self.path).query)
        return (self.headers.get("X-Mamori-Key") == SHARE_KEY
                or q.get("key", [None])[0] == SHARE_KEY)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._send(200, LANDING.encode(), "text/html; charset=utf-8")
        elif path == "/healthz":
            self._json(200, {"ok": True, "ts": time.time()})
        elif path == "/api/latest":
            if LATEST_FILE.exists():
                self._send(200, LATEST_FILE.read_bytes())
            else:
                self._json(404, {"error": "no bundle yet"})
        elif path == "/api/observations":
            if not self._authorized():
                return self._json(403, {"error": "share key required"})
            self._json(200, {"count": len(_read_obs()), "observations": _read_obs()[-200:]})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/api/observations":
            return self._json(404, {"error": "not found"})
        if not self._authorized():
            return self._json(403, {"error": "share key required"})
        try:
            length = min(int(self.headers.get("Content-Length", 0)), 64_000)
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._json(400, {"error": "invalid json"})
        if not isinstance(body, dict) or not body.get("type"):
            return self._json(400, {"error": "observation must be an object with 'type'"})
        body["received_at"] = time.time()
        body["remote"] = self.client_address[0]
        with OBS_FILE.open("a") as f:
            f.write(json.dumps(body, ensure_ascii=False) + "\n")
        self._json(201, {"ok": True})

    def log_message(self, *a):  # quiet
        pass


def main():
    port = int(os.environ.get("PORT", "8080"))
    print(f"mamori hub listening on :{port}")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
