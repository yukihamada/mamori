#!/usr/bin/env python3
"""Mamori hub v0.2 — mutual-defense sharing hub (stdlib only).

Changes from v0.1:
  - Per-participant keys (MAMORI_KEYS_JSON: {"<key>": {"org": "...", "tlp_max": "AMBER"}})
    Falls back to single MAMORI_SHARE_KEY for backward compatibility.
  - Submitter-side + hub-side anonymization: hub masks IPv4 last octet,
    strips email-like strings, rounds timestamps to the hour.
  - TLP labels on observations (CLEAR/GREEN/AMBER). GET returns only
    observations at or below the caller's tlp_max.
  - Rate limiting: 30 POST/hour per key, 120 GET/hour per IP.
  - Public stats endpoint (/api/stats) — counts only, no content.
  - Retention: observations older than 90 days are dropped on read.

Endpoints:
  GET  /                  -> landing (what/why/how + live stats)
  GET  /api/latest        -> latest public intel bundle (TLP:CLEAR)
  GET  /api/stats         -> public counters (participants, observations)
  POST /api/observations  -> submit observation (participant key)
  GET  /api/observations  -> read shared observations (participant key)
  GET  /healthz           -> ok
"""
from __future__ import annotations

import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

DATA_DIR = Path(os.environ.get("MAMORI_DATA", "./data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
OBS_FILE = DATA_DIR / "observations.jsonl"
LATEST_FILE = DATA_DIR / "latest_bundle.json"
RETENTION_SEC = 90 * 86400
POST_LIMIT = 30   # per key per hour
GET_LIMIT = 120   # per IP per hour

# --- participant keys -------------------------------------------------------
def _load_keys() -> dict:
    raw = os.environ.get("MAMORI_KEYS_JSON", "")
    if raw:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass
    single = os.environ.get("MAMORI_SHARE_KEY", "")
    return {single: {"org": "default", "tlp_max": "AMBER"}} if single else {}

KEYS = _load_keys()
TLP_ORDER = {"CLEAR": 0, "GREEN": 1, "AMBER": 2, "RED": 3}

_rate: dict[str, list[float]] = {}

def _rate_ok(bucket: str, limit: int) -> bool:
    now = time.time()
    hits = [t for t in _rate.get(bucket, []) if now - t < 3600]
    _rate[bucket] = hits
    if len(hits) >= limit:
        return False
    hits.append(now)
    return True

# --- anonymization ----------------------------------------------------------
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b")

def anonymize(value):
    """Recursively mask emails and IPv4 last octets in strings."""
    if isinstance(value, str):
        value = EMAIL_RE.sub("[email-masked]", value)
        return IPV4_RE.sub(r"\1.0/24", value)
    if isinstance(value, list):
        return [anonymize(v) for v in value]
    if isinstance(value, dict):
        return {k: anonymize(v) for k, v in value.items()}
    return value

def _stats() -> dict:
    obs = _read_obs()
    intel, last = 0, None
    if LATEST_FILE.exists():
        try:
            b = json.loads(LATEST_FILE.read_text())
            intel = len(b.get("objects", []))
            last = b.get("created", "")[:16].replace("T", " ") + " UTC"
        except Exception:
            pass
    return {"participants": len(KEYS), "observations_shared": len(obs),
            "intel_objects": intel, "last_update": last}


def _read_obs() -> list[dict]:
    if not OBS_FILE.exists():
        return []
    cutoff = time.time() - RETENTION_SEC
    out = []
    for line in OBS_FILE.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        if o.get("received_at", 0) >= cutoff:
            out.append(o)
    # dedupe by (type, pattern) keeping the latest
    seen, dedup = {}, []
    for o in out:
        k = (o.get("type"), o.get("pattern"))
        seen[k] = o
    dedup = list(seen.values())
    return dedup

LANDING = """<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>守 Mamori — セキュリティの民主化</title>
<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:3rem auto;padding:0 1rem;line-height:1.75;color:#1a1a1a}
h1{font-size:2rem}h2{font-size:1.2rem;margin-top:2rem}code{background:#f2f2f2;padding:.1em .4em;border-radius:4px}
.card{border:1px solid #e5e5e5;border-radius:12px;padding:1.2rem;margin:1rem 0}
.stat{display:inline-block;background:#f6f9f7;border:1px solid #dcebe2;border-radius:10px;padding:.6rem 1rem;margin:.2rem .4rem .2rem 0;font-size:.95rem}
.stat b{font-size:1.2rem;color:#0b7a4b}
a{color:#0b5fff}small{color:#888}</style></head><body>
<h1>🛡 守（まもり）Mamori</h1>
<p><strong>みんなでレポートして、みんなで守る。</strong><br>
Mamoriは、最新の攻撃情報・脆弱性情報を自動で集め、自分の環境に関係あるか照合し、
対策まで下書きするセキュリティエージェントです。ある1社が受けた攻撃の知見が、全員の防御になります。</p>

<div class="card"><h2>いまの共有状況</h2>
<div id="stats">__STATS_HTML__</div>
<p style="margin-top:.6rem"><a href="/api/latest">/api/latest</a> — 最新の脅威インテル（TLP:CLEAR・誰でも読めます）<br>
<a href="/api/stix">/api/stix</a> — STIX 2.1 バンドル（MISP/OpenCTIにインポート可）<br>
<a href="/api/sample-report">/api/sample-report</a> — 対策下書きレポートの実物</p></div>

<div class="card"><h2>参加すると何が起きる？</h2>
<ol>
<li>発行された<strong>参加者専用キー</strong>で、攻撃の観測（怪しいIP・ペイロード・手法）を <code>POST /api/observations</code> に投稿</li>
<li>ハブ側でも自動匿名化（IP最終オクテット掩蔽・メールアドレス除去・時刻丸め）</li>
<li>TLPラベル（CLEAR/GREEN/AMBER）で共有範囲を自分で制御</li>
<li>観測は90日で自動削除。削除依頼は随時受付</li>
</ol></div>

<div class="card"><h2>投稿者の保護</h2>
<ul>
<li>組織名は公開されません（統計は件数のみ）</li>
<li>IPアドレスは /24 に丸めて保存</li>
<li>メールアドレスらしき文字列は自動で除去</li>
<li>AMBER指定の観測は参加者のみが閲覧</li>
</ul>
<p><small>それでも識別可能な情報（自社ドメイン等）は投稿前に除いてください。</small></p></div>

<p>テスト参加・専用キーの発行: <a href="https://teai.io/mamori">teai.io/mamori</a></p>
<p><small>Mamori v0.4 — an Enabler project / 観測データは90日で自動削除されます / <a href="/terms">利用規約・データ取り扱い</a> / <a href="https://github.com/yukihamada/mamori/blob/main/docs/key-management.md">キー管理運用手順</a></small></p>
<script>
fetch('/api/stats').then(r=>r.json()).then(s=>{
  document.getElementById('stats').innerHTML =
    '<span class="stat"><b>'+s.participants+'</b> 参加組織</span>'+
    '<span class="stat"><b>'+s.observations_shared+'</b> 共有された観測</span>'+
    '<span class="stat"><b>'+s.intel_objects+'</b> 公開インテル件数</span>'+
    '<span class="stat">最終更新 '+ (s.last_update||'—') +'</span>';
}).catch(()=>{document.getElementById('stats').textContent='統計を取得できませんでした';});
</script>
</body></html>"""


TERMS = """<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mamori 利用規約・データ取り扱い</title>
<style>body{font-family:system-ui,sans-serif;max-width:720px;margin:3rem auto;padding:0 1rem;line-height:1.8;color:#1a1a1a}
h1{font-size:1.6rem}h2{font-size:1.15rem;margin-top:2rem}a{color:#0b5fff}</style></head><body>
<h1>Mamori 利用規約・データ取り扱い方針</h1>
<p>最終更新: 2026-10-22 / 運営: Enabler（<a href="https://teai.io">teai.io</a>）</p>

<h2>1. サービスの性質</h2>
<p>Mamoriはベータ版の脅威情報共有サービスです。提供される情報（インテル・観測・対策下書き）は
<strong>現状のまま（as is）</strong>提供され、正確性・完全性・網羅性を保証しません。
対策の実施判断とその結果は利用者の責任において行ってください。</p>

<h2>2. 共有データの取り扱い</h2>
<ul>
<li>投稿された観測データは、TLPラベルに従って共有されます（CLEAR=公開 / GREEN=参加者 / AMBER=制限付き）</li>
<li>ハブ側で自動匿名化（IP /24丸め・メール除去・時刻1時間丸め）を行いますが、
識別可能な情報（自社ドメイン・内部ホスト名等）は投稿者が事前に除去してください</li>
<li>観測データは90日後に自動削除されます。削除依頼は随時受け付けます</li>
<li>投稿データの著作権は投稿者に帰属します。投稿者は運営に対し、サービス提供・改善のための
非独占的利用許諾を与えるものとします</li>
</ul>

<h2>3. 禁止事項</h2>
<ul>
<li>虚偽・悪意のある観測の投稿（ポイズニング行為）</li>
<li>他の参加者のキーの不正使用</li>
<li>個人情報・秘密情報を含むデータの投稿</li>
<li>本サービスを用いた攻撃行為</li>
</ul>
<p>違反が確認された場合、キーの失効・投稿の削除を行うことがあります。</p>

<h2>4. 免責</h2>
<p>本サービスの利用または利用不能から生じるいかなる損害についても、運営は責任を負いません。
共有された情報に基づく防御措置の効果を保証しません。</p>

<h2>5. 個人情報</h2>
<p>観測データのIPアドレスは /24 に丸めて保存されますが、それでも個人情報に該当しうる場合、
投稿者は自国の法令（日本の個人情報保護法、GDPR等）に従って投稿の可否を判断してください。</p>

<h2>6. キーの管理</h2>
<ul>
<li>参加者キーは組織ごとに発行されます。第三者への貸与・共有は禁止です</li>
<li>漏洩の疑いがある場合は直ちに連絡してください。24時間以内に失効・再発行します</li>
<li>キーのローテーションは随時リクエスト可能です</li>
</ul>

<h2>7. 変更</h2>
<p>本規約は予告なく変更されることがあります。重要な変更はこのページで告知します。</p>

<p><a href="/">← ハブに戻る</a></p>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode())

    def _caller(self) -> dict | None:
        q = parse_qs(urlparse(self.path).query)
        key = self.headers.get("X-Mamori-Key") or q.get("key", [None])[0]
        return KEYS.get(key) if key else None

    def do_GET(self):
        path = urlparse(self.path).path
        if not _rate_ok(f"get:{self.client_address[0]}", GET_LIMIT):
            return self._json(429, {"error": "rate limit exceeded"})
        if path == "/":
            stats = _stats()
            html = LANDING.replace("__STATS_HTML__",
                f'<span class="stat"><b>{stats["participants"]}</b> 参加組織</span>'
                f'<span class="stat"><b>{stats["observations_shared"]}</b> 共有された観測</span>'
                f'<span class="stat"><b>{stats["intel_objects"]}</b> 公開インテル件数</span>'
                f'<span class="stat">最終更新 {stats["last_update"] or "—"}</span>')
            self._send(200, html.encode(), "text/html; charset=utf-8")
        elif path == "/healthz":
            self._json(200, {"ok": True, "ts": time.time()})
        elif path == "/api/latest":
            if LATEST_FILE.exists():
                self._send(200, LATEST_FILE.read_bytes())
            else:
                self._json(404, {"error": "no bundle yet"})
        elif path == "/api/stats":
            self._json(200, _stats())
        elif path == "/api/observations":
            caller = self._caller()
            if not caller:
                # No key: TLP:CLEAR observations are public (read-only).
                visible = [o for o in _read_obs() if o.get("tlp") == "CLEAR"]
                return self._json(200, {"count": len(visible), "tlp": "CLEAR",
                                        "observations": visible[-200:]})
            max_tlp = TLP_ORDER.get(caller.get("tlp_max", "AMBER"), 2)
            visible = [o for o in _read_obs()
                       if TLP_ORDER.get(o.get("tlp", "GREEN"), 1) <= max_tlp]
            self._json(200, {"count": len(visible), "observations": visible[-200:]})
        elif path == "/api/stix":
            stix_file = DATA_DIR / "stix_bundle.json"
            if stix_file.exists():
                self._send(200, stix_file.read_bytes())
            else:
                self._json(404, {"error": "no STIX bundle yet"})
        elif path == "/terms":
            self._send(200, TERMS.encode(), "text/html; charset=utf-8")
        elif path == "/api/sample-report":
            reports = sorted(DATA_DIR.glob("reports/report-*.md"))
            if reports:
                self._send(200, reports[-1].read_bytes(), "text/markdown; charset=utf-8")
            else:
                self._json(404, {"error": "no report yet"})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/api/observations":
            return self._json(404, {"error": "not found"})
        caller = self._caller()
        if not caller:
            return self._json(403, {"error": "participant key required"})
        if not _rate_ok(f"post:{id(caller)}", POST_LIMIT):
            return self._json(429, {"error": "rate limit exceeded (30/hour)"})
        try:
            length = min(int(self.headers.get("Content-Length", 0)), 64_000)
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._json(400, {"error": "invalid json"})
        if not isinstance(body, dict) or not body.get("type"):
            return self._json(400, {"error": "observation must be an object with 'type'"})
        tlp = str(body.get("tlp", "GREEN")).upper()
        if tlp not in TLP_ORDER or tlp == "RED":
            tlp = "GREEN"  # RED (do not share) is rejected into GREEN-less: refuse instead
            if str(body.get("tlp", "")).upper() == "RED":
                return self._json(400, {"error": "TLP:RED must not be shared; do not submit"})
        body = anonymize(body)
        body["tlp"] = tlp
        body["org_hash"] = format(abs(hash(caller.get("org", "default"))) % 10**8, "08d")
        body["received_at"] = round(time.time() / 3600) * 3600  # hour-rounding
        with OBS_FILE.open("a") as f:
            f.write(json.dumps(body, ensure_ascii=False) + "\n")
        self._json(201, {"ok": True, "tlp": tlp})

    def log_message(self, *a):
        pass


def main():
    port = int(os.environ.get("PORT", "8080"))
    print(f"mamori hub v0.2 listening on :{port} (participants: {len(KEYS)})")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
