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

ORG_SALT = os.environ.get("MAMORI_ORG_SALT", "")


def org_hash(org: str) -> str:
    """組織の記号。ハブだけが知る秘密の値（MAMORI_ORG_SALT）で HMAC を取るので、
    組織名の候補から外部が同じ記号を計算することはできない。再起動しても変わらない。"""
    import hmac
    return hmac.new(ORG_SALT.encode(), ("mamori-org:" + org).encode(), hashlib.sha256).hexdigest()[:10]


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
    with _file_lock:
        _atomic_write(LATEST_FILE, (work / "bundle.json").read_bytes())
        rep = DATA_DIR / "reports"
        rep.mkdir(exist_ok=True)
        stamp = time.strftime("%Y%m%dT%H%M", time.gmtime(time.time() + 9 * 3600))
        _atomic_write(rep / f"report-{stamp}.md", out["report_md"].encode())
        for old in sorted(rep.glob("report-*.md"))[:-60]:
            old.unlink(missing_ok=True)
    prune_observations()
    rebuild_stix()
    return {"items": len(raw_obj["items"]), "errors": raw_obj.get("errors", [])}


def prune_observations() -> int:
    """90日を過ぎた観測をファイルから実際に消す（読み出し時の除外だけにしない）。"""
    if not OBS_FILE.exists():
        return 0
    cutoff = time.time() - RETENTION_SEC
    with _file_lock:
        keep, dropped = [], 0
        for line in OBS_FILE.read_text().splitlines():
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                dropped += 1
                continue
            if o.get("received_at", 0) >= cutoff:
                keep.append(line)
            else:
                dropped += 1
        if dropped:
            _atomic_write(OBS_FILE, ("\n".join(keep) + ("\n" if keep else "")).encode())
    return dropped


def rebuild_stix() -> None:
    """公開の /api/stix には TLP:CLEAR かつ保持期間内の観測だけを入れる。"""
    if not LATEST_FILE.exists():
        return
    work = DATA_DIR / "work"
    work.mkdir(exist_ok=True)
    public = work / "obs_public.jsonl"
    public.write_text("".join(json.dumps(o, ensure_ascii=False) + "\n"
                              for o in _read_obs() if o.get("tlp") == "CLEAR"))
    stix = _py("export_stix.py", str(LATEST_FILE), str(public))
    with _file_lock:
        _atomic_write(DATA_DIR / "stix_bundle.json", stix)


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
<title>守 Mamori — みんなでレポートして、みんなで守る</title>
<meta name="description" content="Mamoriは最新の攻撃・脆弱性情報を自動収集し、自社環境への影響を照合、対策まで下書きするセキュリティエージェント。CISA KEV/JPCERT連携、TLP管理、90日自動削除。">
<meta property="og:title" content="守 Mamori — セキュリティの民主化">
<meta property="og:description" content="1社が受けた攻撃の知見が、全員の防御になる。脅威インテル共有ハブ。">
<meta property="og:type" content="website">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡</text></svg>">
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--fg:#e6edf3;--muted:#8b949e;--accent:#3fb950;--accent2:#58a6ff;--warn:#d29922}
@media (prefers-color-scheme:light){:root{--bg:#ffffff;--card:#f6f8fa;--border:#d0d7de;--fg:#1f2328;--muted:#57606a;--accent:#1a7f37;--accent2:#0969da}}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--fg);margin:0;line-height:1.7}
.skip{position:absolute;left:-9999px;top:0;background:var(--accent);color:#000;padding:.5rem 1rem;z-index:9}
.skip:focus{left:0}
header{border-bottom:1px solid var(--border);padding:1rem 1.5rem;display:flex;justify-content:space-between;align-items:center;max-width:1100px;margin:0 auto}
.brand{font-weight:700;font-size:1.15rem;text-decoration:none;color:var(--fg)}
.brand span{color:var(--accent)}
header small{color:var(--muted)}
main{max-width:1100px;margin:0 auto;padding:0 1.5rem}
.hero{padding:4rem 0 3rem;text-align:center}
.hero .shield-svg{display:block;margin:0 auto;filter:drop-shadow(0 0 18px rgba(63,185,80,.35))}
.hero h1{font-size:2.4rem;margin:.6rem 0 .4rem;letter-spacing:-.02em}
.hero .tag{color:var(--accent);font-weight:600;font-size:1.15rem;margin-bottom:1rem}
.hero p.lead{max-width:640px;margin:0 auto 1.8rem;color:var(--muted);font-size:1.05rem}
.cta{display:flex;gap:.8rem;justify-content:center;flex-wrap:wrap}
.btn{display:inline-block;padding:.75rem 1.6rem;border-radius:8px;text-decoration:none;font-weight:600;font-size:1rem}
.btn.primary{background:var(--accent);color:#04160a}
.btn.primary:hover{background:#4ac95c}
.btn.ghost{border:1px solid var(--border);color:var(--fg)}
.btn.ghost:hover{border-color:var(--accent)}
.stats{display:flex;gap:1rem;justify-content:center;flex-wrap:wrap;margin:2.5rem 0 0}
.stat{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1rem 1.5rem;min-width:140px;text-align:center}
.stat b{display:block;font-size:1.8rem;color:var(--accent)}
.stat span{color:var(--muted);font-size:.85rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1.2rem;margin:2.5rem 0}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.5rem}
.card h2{font-size:1.15rem;margin:0 0 .8rem;color:var(--fg)}
.card ol,.card ul{margin:0;padding-left:1.3rem}
.card li{margin:.4rem 0;color:var(--muted)}
.card li strong{color:var(--fg)}
code{background:#1f2630;padding:.15em .45em;border-radius:4px;font-size:.9em;color:var(--accent2)}
a{color:var(--accent2)}
a:focus-visible,.btn:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
.api-list{list-style:none;padding:0}
.api-list li{margin:.5rem 0}
.api-list a{font-family:ui-monospace,monospace;font-size:.92rem}
.badge{display:inline-block;background:#1f2630;border:1px solid var(--border);border-radius:6px;padding:.1rem .5rem;font-size:.75rem;color:var(--muted);margin-left:.4rem}
.trust{text-align:center;color:var(--muted);font-size:.9rem;margin:2.5rem 0 1rem}
.trust b{color:var(--fg)}
footer{border-top:1px solid var(--border);margin-top:3rem;padding:1.5rem;text-align:center;color:var(--muted);font-size:.85rem}
footer a{margin:0 .5rem}
.en-note{background:#1f2630;border-left:3px solid var(--accent2);padding:.8rem 1rem;border-radius:0 8px 8px 0;font-size:.85rem;color:var(--muted);margin-top:1.5rem}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
@media(max-width:600px){.hero h1{font-size:1.8rem}.stat b{font-size:1.4rem}}
</style></head><body>
<a class="skip" href="#main">本文へスキップ</a>
<header>
<a class="brand" href="/">🛡 守 <span>Mamori</span></a>
<small>an <a href="https://teai.io" style="color:var(--muted)">Enabler</a> project · v0.5</small>
</header>
<main id="main">
<section class="hero">
<svg class="shield-svg" viewBox="0 0 64 64" width="72" height="72" role="img" aria-label="Mamoriの盾ロゴ"><path d="M32 3 6 13v16c0 16 11 27 26 32 15-5 26-16 26-32V13L32 3z" fill="none" stroke="var(--accent)" stroke-width="3.5" stroke-linejoin="round"/><path d="M20 32l8 8 16-16" fill="none" stroke="var(--accent)" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
<h1>みんなでレポートして、<br>みんなで守る。</h1>
<p class="tag">ある1社が受けた攻撃の知見が、全員の防御になる。</p>
<p class="lead">Mamoriは、最新の攻撃情報・脆弱性情報（CISA KEV／JPCERT/CC）を6時間ごとに自動収集し、あなたの環境に関係あるか照合、対策の下書きまで出すセキュリティエージェントです。仕組み・API・データ取り扱いはすべて公開。まずは認証不要の公開インテルから試せます。</p>
<div class="cta">
<a class="btn primary" href="/start">参加ガイド（5分）</a>
<a class="btn ghost" href="/intel">最新の脅威を見る（登録不要）</a>
<a class="btn ghost" href="/api/sample-report">対策レポートの実物</a>
</div>
<p style="margin-top:1rem;font-size:.85rem;color:var(--muted)"><a href="/kit.tar.gz">照合キット</a> = 自社スタックと脆弱性情報を突き合わせるローカル実行スクリプト一式（tar.gz・認証不要）</p>
<div class="stats" id="stats">__STATS_HTML__</div>
</section>

<div class="grid">
<div class="card"><h2>📡 公開API（登録不要）</h2>
<ul class="api-list">
<li><a href="/api/latest">/api/latest</a> — 最新の脅威インテル<span class="badge">TLP:CLEAR</span></li>
<li><a href="/api/stix">/api/stix</a> — STIX 2.1 バンドル（MISP/OpenCTIにインポート可）</li>
<li><a href="/api/sample-report">/api/sample-report</a> — 対策下書きレポートの実物</li>
</ul></div>

<div class="card"><h2>🤝 参加すると何が起きる？</h2>
<ol>
<li>発行された<strong>参加者専用キー</strong>で、攻撃の観測（怪しいIP・ペイロード・手法）を <code>POST /api/observations</code> に投稿</li>
<li>ハブ側で<strong>自動匿名化</strong>（IP最終オクテット掩蔽・メールアドレス除去・時刻丸め）</li>
<li><strong>TLPラベル</strong>（CLEAR/GREEN/AMBER）で共有範囲を自分で制御</li>
<li>観測は<strong>90日で自動削除</strong>。削除依頼は随時受付</li>
</ol></div>

<div class="card"><h2>🔒 投稿者の保護</h2>
<ul>
<li>組織名は公開されません（統計は件数のみ）</li>
<li>IPアドレスは /24 に丸めて保存</li>
<li>メールアドレスらしき文字列は自動で除去</li>
<li>AMBER指定の観測は参加者のみが閲覧</li>
</ul>
<p style="margin:.8rem 0 0"><small>それでも識別可能な情報（自社ドメイン等）は投稿前に除いてください。詳しくは<a href="/terms">データ取り扱い方針</a>へ。</small></p></div>
</div>

<p class="trust">情報源: <b>CISA KEV</b>（悪用確認済み脆弱性） · <b>JPCERT/CC 注意喚起</b> · <b>JPCERT/CC 週報</b> — 6時間ごとに自動取得 / 観測データは90日で自動削除</p>

<div class="en-note" lang="en"><strong>English:</strong> Mamori is a mutual-defense threat-intel hub. It auto-collects CISA KEV &amp; JPCERT advisories every 6 hours, matches them against your stack, and drafts countermeasures. Public TLP:CLEAR intel is free at <a href="/api/latest">/api/latest</a> (STIX 2.1 available). Observations are anonymized (IP /24, email stripped) and auto-deleted after 90 days.</div>
</main>
<footer>
Mamori v0.5 — an Enabler project<br>
<a href="https://teai.io/mamori">製品ページ</a> · <a href="/terms">利用規約・データ取り扱い</a> · <a href="/docs/keys">キー管理運用手順</a> · <a href="/start">参加ガイド</a>
</footer>
<script>
fetch('/api/stats').then(r=>r.json()).then(s=>{
  document.getElementById('stats').innerHTML =
    '<div class="stat"><b>'+s.participants+'</b><span>参加組織</span></div>'+
    '<div class="stat"><b>'+s.observations_shared+'</b><span>共有された観測</span></div>'+
    '<div class="stat"><b>'+s.intel_objects+'</b><span>公開インテル件数</span></div>'+
    '<div class="stat"><b style="font-size:1rem">'+ (s.last_update||'—') +'</b><span>最終更新</span></div>';
}).catch(()=>{});
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
                f'<div class="stat"><b>{stats["participants"]}</b><span>参加組織</span></div>'
                f'<div class="stat"><b>{stats["observations_shared"]}</b><span>共有された観測</span></div>'
                f'<div class="stat"><b>{stats["intel_objects"]}</b><span>公開インテル件数</span></div>'
                f'<div class="stat"><b style="font-size:1rem">{stats["last_update"] or "—"}</b><span>最終更新</span></div>')
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
    if not ORG_SALT:
        print("warning: MAMORI_ORG_SALT is not set; org_hash is guessable", flush=True)
    if (APP_DIR / "agent").exists():
        try:  # 起動時に公開STIXを必ず作り直す（古い版が書いた内容を残さない）
            prune_observations()
            rebuild_stix()
        except Exception as e:  # noqa: BLE001
            print(f"stix rebuild failed: {e}", flush=True)
    if os.environ.get("MAMORI_NO_REFRESH") != "1" and (APP_DIR / "agent").exists():
        threading.Thread(target=refresh_loop, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
