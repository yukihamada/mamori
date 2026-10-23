#!/usr/bin/env python3
"""Mamori hub v0.5 — mutual-defense sharing hub (stdlib only).

Changes in v0.5:
  - The hub refreshes intel itself (on boot + every MAMORI_REFRESH_HOURS).
  - JPCERT/CC 注意喚起 added as a source.
  - Stable org_hash (sha256) instead of per-process hash().
  - /start onboarding guide, /kit.tar.gz starter kit, /docs/keys, /api/whoami,
    /media/* with HTTP Range (video playback on iOS).

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

import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

DATA_DIR = Path(os.environ.get("MAMORI_DATA", "./data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
OBS_FILE = DATA_DIR / "observations.jsonl"
LATEST_FILE = DATA_DIR / "latest_bundle.json"
APP_DIR = Path(os.environ.get("MAMORI_APP", Path(__file__).resolve().parent.parent))
MEDIA_DIR = APP_DIR / "media"
REFRESH_HOURS = float(os.environ.get("MAMORI_REFRESH_HOURS", "6"))
VERSION = "0.5"
_refresh_state = {"last_run": None, "last_ok": None, "last_error": None}
_file_lock = threading.Lock()
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


def _tlp_max(caller: dict) -> str:
    # 指定のないキーは GREEN まで（AMBER は運営が確認した組織に明示で付与）
    return str(caller.get("tlp_max") or "GREEN").upper()

KEYS = _load_keys()
TLP_ORDER = {"CLEAR": 0, "GREEN": 1, "AMBER": 2, "RED": 3}

_rate: dict[str, list[float]] = {}

_rate_lock = threading.Lock()


def _rate_ok(bucket: str, limit: int) -> bool:
    with _rate_lock:
        return _rate_ok_locked(bucket, limit)


def _rate_ok_locked(bucket: str, limit: int) -> bool:
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

def org_hash(org: str) -> str:
    """プロセス再起動で変わらない組織ハッシュ（v0.4までは hash() で毎回変わっていた）。"""
    return hashlib.sha256(("mamori-org:" + org).encode()).hexdigest()[:10]


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
    return {"participants": len({v.get("org") for v in KEYS.values()}),
            "observations_shared": len(obs),
            "intel_objects": intel, "last_update": last,
            "last_refresh_check": _refresh_state["last_ok"],
            "refresh_every_hours": REFRESH_HOURS,
            "sources": ["CISA KEV", "JPCERT/CC 注意喚起", "JPCERT/CC Weekly Report"],
            "version": VERSION}


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

# --- daily refresh (v0.5) ---------------------------------------------------
# v0.4 までは手元で run.sh を回してファイルを置く運用で、ページの「毎日更新」が
# 守られていなかった。ハブ自身が起動時と REFRESH_HOURS ごとに取り込む。
def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def _py(script: str, *args: str) -> bytes:
    r = subprocess.run([sys.executable, str(APP_DIR / "agent" / script), *args],
                       capture_output=True, timeout=180)
    if r.returncode != 0:
        raise RuntimeError(f"{script} exit {r.returncode}: {r.stderr.decode()[-300:]}")
    return r.stdout


def refresh_once() -> dict:
    work = DATA_DIR / "work"
    work.mkdir(exist_ok=True)
    raw = _py("fetch_feeds.py")
    raw_obj = json.loads(raw)
    if not raw_obj.get("items"):
        raise RuntimeError(f"no items fetched: {raw_obj.get('errors')}")
    (work / "raw.json").write_bytes(raw)
    matched = _py("match_inventory.py", str(work / "raw.json"))
    (work / "matched.json").write_bytes(matched)
    out = json.loads(_py("draft_actions.py", str(work / "matched.json")))
    (work / "bundle.json").write_text(json.dumps(out["share_bundle"], ensure_ascii=False, indent=2))
    stix = _py("export_stix.py", str(work / "bundle.json"), str(OBS_FILE))
    with _file_lock:
        _atomic_write(LATEST_FILE, (work / "bundle.json").read_bytes())
        _atomic_write(DATA_DIR / "stix_bundle.json", stix)
        rep = DATA_DIR / "reports"
        rep.mkdir(exist_ok=True)
        stamp = time.strftime("%Y%m%dT%H%M", time.gmtime(time.time() + 9 * 3600))
        _atomic_write(rep / f"report-{stamp}.md", out["report_md"].encode())
        for old in sorted(rep.glob("report-*.md"))[:-60]:
            old.unlink(missing_ok=True)
    return {"items": len(raw_obj["items"]), "errors": raw_obj.get("errors", [])}


def _bundle_age_hours() -> float:
    if not LATEST_FILE.exists():
        return 1e9
    return (time.time() - LATEST_FILE.stat().st_mtime) / 3600


def refresh_loop() -> None:
    while True:
        if _bundle_age_hours() >= REFRESH_HOURS * 0.9:
            _refresh_state["last_run"] = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
            try:
                res = refresh_once()
                _refresh_state["last_ok"] = _refresh_state["last_run"]
                _refresh_state["last_error"] = res["errors"] or None
                print(f"refresh ok: {res}", flush=True)
            except Exception as e:  # noqa: BLE001 — 失敗は記録し、前回のバンドルを配信し続ける
                _refresh_state["last_error"] = str(e)[:300]
                print(f"refresh failed: {e}", flush=True)
        else:
            _refresh_state["last_ok"] = _refresh_state["last_ok"] or "fresh-on-boot"
        time.sleep(600)





# --- starter kit / media ----------------------------------------------------
KIT_FILES = ["run.sh", "README.md", "agent", "examples", "docs", "tools"]


def build_kit() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name in KIT_FILES:
            src = APP_DIR / name
            if src.exists():
                tar.add(src, arcname=f"mamori/{name}",
                        filter=lambda ti: None if "__pycache__" in ti.name else ti)
    return buf.getvalue()


_kit_cache: dict[str, bytes] = {}
PAGES_DIR = Path(__file__).resolve().parent / "pages"


def _page(name: str) -> bytes:
    return (PAGES_DIR / name).read_bytes()


def _esc(t) -> str:
    return (str(t or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


SRC_LABEL = {"cisa_kev": ("悪用確認済み", "CISA KEV", "red"),
             "jpcert_alert": ("注意喚起", "JPCERT/CC", "amber"),
             "jpcert": ("週報", "JPCERT/CC", "gray"),
             "jpcert_ics": ("制御システム", "JPCERT/CC", "gray")}


def render_intel() -> bytes:
    """/api/latest を人が読める一覧にする（運営の照合結果は出さない）。"""
    try:
        b = json.loads(LATEST_FILE.read_text())
    except Exception:  # noqa: BLE001
        b = {"objects": [], "created": ""}
    objs = [o for o in b.get("objects", []) if o.get("title")]
    objs.sort(key=lambda o: o.get("published") or "", reverse=True)
    newest = max((o.get("published") or "" for o in objs), default="")
    import datetime as _dt
    try:
        cut = (_dt.date.fromisoformat(newest) - _dt.timedelta(days=7)).isoformat() if newest else ""
    except ValueError:
        cut = ""
    rows = []
    for o in objs:
        kind, src, color = SRC_LABEL.get(o.get("source"), ("情報", o.get("source", ""), "gray"))
        due = f'<span class="due">米国政府の対応期限 {_esc(o.get("due_date"))}</span>' if o.get("due_date") else ""
        fresh = ' class="fresh"' if cut and (o.get("published") or "") >= cut else ""
        rows.append(f'<li{fresh}><span class="d">{_esc(o.get("published") or "—")}</span>'
                    f'<span class="tag {color}">{kind}</span><span class="src">{_esc(src)}</span>'
                    f'<a href="{_esc(o.get("url"))}" rel="noopener" target="_blank">{_esc(o.get("title"))}</a>{due}</li>')
    created = (b.get("created") or "")[:16].replace("T", " ")
    html = _page("intel.html").decode()
    html = html.replace("__UPDATED__", _esc(created + " UTC" if created else "—"))
    html = html.replace("__COUNT__", str(len(objs))).replace("__ROWS__", "\n".join(rows))
    return html.encode()


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
<p style="margin-top:.6rem"><a href="/intel"><strong>最新の脅威を見る</strong></a>（登録不要）<br>
<a href="/api/latest">/api/latest</a> — 最新の脅威インテル（TLP:CLEAR・誰でも読めます）<br>
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

<p><strong>はじめての方へ:</strong> <a href="/start">参加ガイド（5分）</a> ／ <a href="/kit.tar.gz">照合キットをダウンロード</a> ／ 製品ページ <a href="https://teai.io/mamori">teai.io/mamori</a></p>
<p><small>Mamori v0.5 — an Enabler project / 脅威情報は6時間ごとに自動取得 / 観測データは90日で自動削除されます / <a href="/terms">利用規約・データ取り扱い</a> / <a href="/docs/keys">キー管理運用手順</a></small></p>
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
<p>最終更新: 2026-10-23 / 運営: Enabler（<a href="https://teai.io">teai.io</a>）</p>

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

    def _media(self, name: str):
        if not re.fullmatch(r"[a-z0-9-]+\.(mp4|jpg|vtt)", name):
            return self._json(404, {"error": "not found"})
        f = MEDIA_DIR / name
        if not f.exists():
            return self._json(404, {"error": "not found"})
        ctype = {"mp4": "video/mp4", "jpg": "image/jpeg", "vtt": "text/vtt; charset=utf-8"}[name.rsplit(".", 1)[1]]
        size = f.stat().st_size
        start, end = 0, size - 1
        rng = self.headers.get("Range", "")
        m = re.fullmatch(r"bytes=(\d*)-(\d*)", rng.strip())
        partial = bool(m and (m.group(1) or m.group(2)))
        if partial:
            if m.group(1):
                start = int(m.group(1))
                end = min(int(m.group(2)), size - 1) if m.group(2) else size - 1
            else:
                start = max(0, size - int(m.group(2)))
            if start > end or start >= size:
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{size}")
                self.end_headers()
                return
        self.send_response(206 if partial else 200)
        self.send_header("Content-Type", ctype)
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Cache-Control", "public, max-age=86400")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(end - start + 1))
        if partial:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.end_headers()
        if self.command == "HEAD":
            return
        with f.open("rb") as fh:
            fh.seek(start)
            remaining = end - start + 1
            while remaining > 0:
                chunk = fh.read(min(65536, remaining))
                if not chunk:
                    break
                self.wfile.write(chunk)
                remaining -= len(chunk)

    def do_HEAD(self):
        path = urlparse(self.path).path
        if path.startswith("/media/"):
            return self._media(path[len("/media/"):])
        self.send_response(200 if path in ("/", "/healthz", "/start", "/intel") else 404)
        self.end_headers()

    def _caller(self) -> dict | None:
        q = parse_qs(urlparse(self.path).query)
        key = self.headers.get("X-Mamori-Key") or q.get("key", [None])[0]
        return KEYS.get(key) if key else None

    def do_GET(self):
        path = urlparse(self.path).path
        # 動画は1回の再生で多数の Range リクエストが来るため読取制限の対象外
        if not path.startswith("/media/") and path != "/healthz" and \
                not _rate_ok(f"get:{self.client_address[0]}", GET_LIMIT):
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
            max_tlp = TLP_ORDER.get(_tlp_max(caller), 1)
            visible = [o for o in _read_obs()
                       if TLP_ORDER.get(o.get("tlp", "GREEN"), 1) <= max_tlp]
            self._json(200, {"count": len(visible), "observations": visible[-200:]})
        elif path == "/api/stix":
            stix_file = DATA_DIR / "stix_bundle.json"
            if stix_file.exists():
                self._send(200, stix_file.read_bytes())
            else:
                self._json(404, {"error": "no STIX bundle yet"})
        elif path.startswith("/media/"):
            return self._media(path[len("/media/"):])
        elif path == "/start":
            self._send(200, _page("start.html"), "text/html; charset=utf-8")
        elif path == "/intel":
            self._send(200, render_intel(), "text/html; charset=utf-8")
        elif path == "/kit.tar.gz":
            if "kit" not in _kit_cache:
                _kit_cache["kit"] = build_kit()
            self.send_response(200)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Disposition", 'attachment; filename="mamori-kit.tar.gz"')
            self.send_header("Content-Length", str(len(_kit_cache["kit"])))
            self.end_headers()
            self.wfile.write(_kit_cache["kit"])
        elif path == "/docs/keys":
            doc = APP_DIR / "docs" / "key-management.md"
            if doc.exists():
                self._send(200, doc.read_bytes(), "text/markdown; charset=utf-8")
            else:
                self._json(404, {"error": "not found"})
        elif path == "/api/whoami":
            caller = self._caller()
            if not caller:
                return self._json(401, {"ok": False, "error": "participant key required (X-Mamori-Key)"})
            self._json(200, {"ok": True, "org_hash": org_hash(caller.get("org", "default")),
                             "tlp_max": _tlp_max(caller)})
        elif path == "/api/refresh-status":
            self._json(200, {**_refresh_state, "bundle_age_hours": round(_bundle_age_hours(), 2),
                             "refresh_every_hours": REFRESH_HOURS})
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
        if not _rate_ok(f"post:{org_hash(caller.get('org', 'default'))}", POST_LIMIT):
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
        body["org_hash"] = org_hash(caller.get("org", "default"))
        body["received_at"] = round(time.time() / 3600) * 3600  # hour-rounding
        with _file_lock, OBS_FILE.open("a") as f:
            f.write(json.dumps(body, ensure_ascii=False) + "\n")
        self._json(201, {"ok": True, "tlp": tlp})

    def log_message(self, *a):
        pass


def main():
    port = int(os.environ.get("PORT", "8080"))
    print(f"mamori hub v{VERSION} listening on :{port} (keys: {len(KEYS)})", flush=True)
    if os.environ.get("MAMORI_NO_REFRESH") != "1" and (APP_DIR / "agent").exists():
        threading.Thread(target=refresh_loop, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
