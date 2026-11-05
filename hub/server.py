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
# IPv6（簡易）: コロンを2つ以上含む16進表現を伏せる
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
# 内部・プライベートを示唆するドメイン尾（.local/.internal/.lan/.corp 等）
INTERNAL_TLD_RE = re.compile(
    r"\b[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
    r"\.(?:local|internal|lan|corp|intra|private)\b", re.IGNORECASE)

def anonymize(value):
    """Recursively mask emails, IPv4 last octets, IPv6, and internal-looking domains."""
    if isinstance(value, str):
        value = EMAIL_RE.sub("[email-masked]", value)
        value = IPV4_RE.sub(r"\1.0/24", value)
        value = IPV6_RE.sub("[ipv6-masked]", value)
        value = INTERNAL_TLD_RE.sub("[internal-domain-masked]", value)
        return value
    if isinstance(value, list):
        return [anonymize(v) for v in value]
    if isinstance(value, dict):
        return {k: anonymize(v) for k, v in value.items()}
    return value

ORG_SALT = os.environ.get("MAMORI_ORG_SALT", "")
sys.path.insert(0, str(Path(__file__).resolve().parent))
import accounts  # noqa: E402  セルフサービスの鍵発行・管理
STORE = accounts.Store(DATA_DIR / "accounts.json", ORG_SALT)
PUBLIC_URL = os.environ.get("MAMORI_PUBLIC_URL", "https://mamori.teai.io").rstrip("/")
COOKIE_FLAGS = "HttpOnly; SameSite=Lax" + ("; Secure" if PUBLIC_URL.startswith("https://") else "")

# --- 期間限定の新規登録 -------------------------------------------------------
# MAMORI_SIGNUP_UNTIL（epoch秒）までの間だけ、/account/login（メールリンク送信＝新規登録）を
# 受け付ける。期限切れ後も、既存セッションの鍵管理・発行・停止はそのまま使える。
SIGNUP_UNTIL = float(os.environ.get("MAMORI_SIGNUP_UNTIL", "0") or 0)


def signup_open() -> bool:
    return SIGNUP_UNTIL <= 0 or time.time() < SIGNUP_UNTIL


def signup_deadline_jst() -> str:
    return time.strftime("%Y-%m-%d %H:%M JST", time.gmtime(SIGNUP_UNTIL + 9 * 3600)) if SIGNUP_UNTIL > 0 else ""


def lookup_key(key: str | None) -> dict | None:
    """運営発行のキー（MAMORI_KEYS_JSON）→ セルフサービスのキーの順に探す。"""
    if not key:
        return None
    return KEYS.get(key) or STORE.lookup(key)


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
    return {"participants": len({v.get("org") for v in KEYS.values()} | STORE.active_orgs()),
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
KIT_FILES = ["run.sh", "README.md", "agent", "examples", "docs", "tools", "mcp"]


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


SRC_LABEL = {"cisa_kev": ("悪用確認済み", "Actively exploited", "CISA KEV", "red"),
             "jpcert_alert": ("注意喚起", "Advisory", "JPCERT/CC", "amber"),
             "jpcert": ("週報", "Weekly report", "JPCERT/CC", "gray"),
             "jpcert_ics": ("制御システム", "ICS/OT", "JPCERT/CC", "gray")}


def render_intel(products: list[str] | None = None, lang: str = "ja") -> bytes:
    """/api/latest を人が読める一覧にする（運営の照合結果は出さない）。
    products が指定された場合、タイトルに製品名を含む項目だけを強調表示する。
    lang は "ja"/"en"。サーバー側で初期言語を確定し、JSは切替のみ担当する。"""
    if lang not in ("ja", "en"):
        lang = "ja"
    try:
        b = json.loads(LATEST_FILE.read_text())
    except Exception:  # noqa: BLE001
        b = {"objects": [], "created": ""}
    raw = b.get("objects") or b.get("items") or []
    objs = [o for o in raw if isinstance(o, dict) and o.get("title")]
    objs.sort(key=lambda o: o.get("published") or "", reverse=True)
    matched_set: set[int] = set()
    if products:
        kws = [p.lower() for p in products if p]
        for i, o in enumerate(objs):
            t = (o.get("title") or "").lower()
            if any(k in t for k in kws):
                matched_set.add(i)
    if matched_set:
        order = sorted(range(len(objs)), key=lambda i: (0 if i in matched_set else 1, i))
        objs = [objs[i] for i in order]
        matched_set = set(range(len(matched_set)))
    newest = max((o.get("published") or "" for o in objs), default="")
    import datetime as _dt
    try:
        cut = (_dt.date.fromisoformat(newest) - _dt.timedelta(days=7)).isoformat() if newest else ""
    except ValueError:
        cut = ""

    def _clean_title(title: str) -> str:
        t = (title or "").strip()
        for _ in range(4):
            m = re.match(r"^(.+?):\s+\1\b", t)
            if m:
                t = t[m.end(1) + 2:]
                continue
            m = re.match(r"^(\S+)\s+\1\b", t)
            if m:
                t = t[m.end(1) + 1:]
                continue
            break
        return t
    rows = []
    for i, o in enumerate(objs):
        kind_ja, kind_en, src, color = SRC_LABEL.get(
            o.get("source"), ("情報", "Info", o.get("source", ""), "gray"))
        due = (f'<span class="due"><span class="ja">米国政府の対応期限 {_esc(o.get("due_date"))}</span>'
               f'<span class="en">US federal due date {_esc(o.get("due_date"))}</span></span>'
               ) if o.get("due_date") else ""
        cls = ' class="fresh"' if cut and (o.get("published") or "") >= cut else ""
        if i in matched_set:
            cls = ' class="match"'
        title = _clean_title(o.get("title"))
        if lang == "en":
            title = re.sub(r"号\s*$", "", title).strip()
        orig = ""
        if lang == "en" and re.search(r"[\u3040-\u30ff\u4e00-\u9fff]", title):
            orig = '<span class="orig" title="Original title is in Japanese">JA original</span> '
        rows.append(f'<li{cls}><span class="d">{_esc(o.get("published") or "—")}</span>'
                    f'<span class="tag {color}"><span class="ja">{kind_ja}</span><span class="en">{kind_en}</span></span>'
                    f'<span class="src">{_esc(src)}</span>'
                    f'<a href="{_esc(o.get("url"))}" rel="noopener" target="_blank">{orig}{_esc(title)}</a>{due}</li>')
    created = (b.get("created") or "")[:16].replace("T", " ")
    html = _page("intel.html").decode()
    html = html.replace("__LANG__", lang)
    if lang == "en":
        html = html.replace("__TITLE__", "Latest threats — Mamori")
        html = html.replace("__DESC__", "CISA KEV (actively exploited) and JPCERT/CC advisories, refreshed every 6 hours. Free, no sign-up.")
    else:
        html = html.replace("__TITLE__", "最新の脅威 — 守 Mamori")
        html = html.replace("__DESC__", "CISA KEV（悪用確認済み）とJPCERT/CC注意喚起を6時間ごとに自動取得。登録不要で読めます。")
    html = html.replace("__UPDATED__", _esc(created + " UTC" if created else "—"))
    html = html.replace("__COUNT__", str(len(objs))).replace("__ROWS__", "\n".join(rows))
    if not objs:
        html = html.replace("__EMPTY__",
            '<p class="empty"><span class="ja">いま取得できた項目がありません。時間をおいて再読み込みしてください。</span>'
            '<span class="en">No items could be fetched right now. Please reload in a little while.</span></p>')
    else:
        html = html.replace("__EMPTY__", "")
    if products:
        if matched_set:
            ja_msg = (f'該当する {len(matched_set)} 件を先頭に並べ、緑の枠で示しています。')
            en_msg = (f'{len(matched_set)} matching item(s) are shown first, highlighted in green.')
        else:
            ja_msg = '一致する項目は見つかりませんでした。製品名の表記を変えて試してください。'
            en_msg = 'No matching items were found. Try a different product spelling.'
        note = (f'<p class="filter-note" role="status"><span class="ja">🔍 選択中の製品: <b>{_esc(", ".join(products))}</b> — '
                f'{ja_msg}</span>'
                f'<span class="en">🔍 Selected products: <b>{_esc(", ".join(products))}</b> — '
                f'{en_msg}</span> '
                f'<a href="/intel?lang={lang}"><span class="ja">すべて表示に戻す</span><span class="en">Show all</span></a></p>')
        html = html.replace("__FILTER_NOTE__", note)
    else:
        html = html.replace("__FILTER_NOTE__", "")
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
.check-card{background:var(--card);border:1px solid var(--accent);border-radius:12px;padding:1.4rem 1.5rem;max-width:760px;margin:0 auto 1.8rem;text-align:left}
.check-title{margin:0 0 .3rem;font-weight:700;font-size:1.05rem}
.check-sub{margin:0 0 .9rem;color:var(--muted);font-size:.88rem}
.check-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:.45rem .9rem;margin-bottom:1rem}
.check-grid label{display:flex;align-items:center;gap:.45rem;font-size:.92rem;cursor:pointer;padding:.25rem .4rem;border-radius:6px}
.check-grid label:hover{background:rgba(63,185,80,.08)}
.check-grid input{accent-color:var(--accent);width:1rem;height:1rem}
.check-actions{display:flex;gap:.7rem;flex-wrap:wrap;align-items:center;margin:0}
.check-note{margin:.7rem 0 0;font-size:.8rem;color:var(--muted)}
.mac-card{max-width:760px;margin:1.6rem auto 0;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1rem 1.2rem}
.mac-card-body{display:flex;align-items:center;gap:1rem;flex-wrap:wrap}
.mac-card-icon{font-size:1.8rem;line-height:1}
.mac-card-text{flex:1;min-width:200px}
.mac-card-title{margin:0;font-weight:700;font-size:1rem}
.mac-card-sub{margin:.2rem 0 0;color:var(--muted);font-size:.85rem}
.mac-card-note{margin:.7rem 0 0;font-size:.78rem;color:var(--muted)}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
@media(max-width:600px){.hero h1{font-size:1.8rem}.stat b{font-size:1.4rem}}
</style></head><body>
<a class="skip" href="#main">本文へスキップ</a>
<header>
<a class="brand" href="/">🛡 守 <span>Mamori</span></a>
<nav style="font-size:.9rem"><a href="/intel" style="color:var(--muted);text-decoration:none;margin-left:1rem">脅威一覧</a><a href="/newsletter" style="color:var(--muted);text-decoration:none;margin-left:1rem">メルマガ</a><a href="/my" style="color:var(--muted);text-decoration:none;margin-left:1rem">マイページ</a><a href="/post" style="color:var(--muted);text-decoration:none;margin-left:1rem">共有する</a><a href="/api" style="color:var(--muted);text-decoration:none;margin-left:1rem">API</a><a href="/status" style="color:var(--muted);text-decoration:none;margin-left:1rem">ステータス</a><a href="/about" style="color:var(--muted);text-decoration:none;margin-left:1rem">仕組み</a><a href="/agent" style="color:var(--muted);text-decoration:none;margin-left:1rem">エージェント</a></nav>
</header>
<main id="main">
<section class="hero">
<svg class="shield-svg" viewBox="0 0 64 64" width="72" height="72" role="img" aria-label="Mamoriの盾ロゴ"><path d="M32 3 6 13v16c0 16 11 27 26 32 15-5 26-16 26-32V13L32 3z" fill="none" stroke="var(--accent)" stroke-width="3.5" stroke-linejoin="round"/><path d="M20 32l8 8 16-16" fill="none" stroke="var(--accent)" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
<h1>うちの製品、<br>今狙われてる？</h1>
<p class="tag">登録不要・30秒で確認。CISA KEV／JPCERT/CC の最新情報から、自社に関係ある脅威だけを絞り込めます。</p>
<p class="lead">Mamoriは、最新の攻撃情報・脆弱性情報を6時間ごとに自動収集し、自社環境への影響を照合、対策の下書きまで出すセキュリティエージェントです。まずは下のチェックボックスで、使っている製品を選ぶだけ。キー・登録は不要です。</p>

<div class="check-card" id="threat-check">
<p class="check-title">🔍 自社に関係ある脅威チェック（キー不要・ブラウザ完結）</p>
<p class="check-sub">使っている製品を選んでください。選択だけで下の「最新の脅威」が絞り込まれます。</p>
<div class="check-grid" id="product-checks">
<label><input type="checkbox" value="wordpress"> WordPress</label>
<label><input type="checkbox" value="fortinet"> Fortinet (FortiOS/FortiGate)</label>
<label><input type="checkbox" value="cisco"> Cisco (IOS/ASA/その他)</label>
<label><input type="checkbox" value="microsoft"> Microsoft (Windows/Exchange)</label>
<label><input type="checkbox" value="apache"> Apache (HTTP Server/Struts)</label>
<label><input type="checkbox" value="nginx"> nginx</label>
<label><input type="checkbox" value="vmware"> VMware</label>
<label><input type="checkbox" value="citrix"> Citrix</label>
<label><input type="checkbox" value="ivanti"> Ivanti</label>
<label><input type="checkbox" value="openssl"> OpenSSL</label>
</div>
<p class="check-actions"><a class="btn primary" id="check-go" href="/intel">この条件で最新の脅威を見る →</a>
<button class="btn ghost" id="check-clear" type="button">選択をクリア</button></p>
<p class="check-note">※ 絞り込みはブラウザ内で完結し、選択内容はサーバーに送信されません。</p>
</div>

<div class="cta">
<a class="btn primary" href="/start">参加ガイド（5分）</a>
<a class="btn ghost" href="/intel">すべての脅威を見る（登録不要）</a>
<a class="btn ghost" href="/newsletter">📬 メルマガで受け取る</a>
<a class="btn ghost" href="/about">仕組みと他との違い</a>
</div>
<p style="margin-top:1rem;font-size:.85rem;color:var(--muted)"><a href="/kit.tar.gz">照合キット</a> = 自社スタックと脆弱性情報を突き合わせるローカル実行スクリプト一式（tar.gz・認証不要）</p>
<div class="mac-card">
<div class="mac-card-body">
<div class="mac-card-icon">🖥️</div>
<div class="mac-card-text">
<p class="mac-card-title">Mac アプリ「守」— この Mac の守りを毎日採点</p>
<p class="mac-card-sub">メニューバーに常駐し、設定の穴を点検・安全な項目は自動で修正。ダウンロードして開くだけ（登録不要）。</p>
</div>
<a class="btn primary" href="/MamoriBar.zip" download>⬇ Mac アプリをダウンロード</a>
</div>
<p class="mac-card-note">初回だけ「システム設定 → プライバシーとセキュリティ → このまま開く」が必要です（公証なしのため）。<a href="/start#mac">手順を見る</a></p>
</div>
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
<li>発行された<strong>参加者専用キー</strong>で、攻撃の観測（怪しいIP・ペイロード・手法）を共有。<a href="/post">ブラウザの投稿フォーム</a>または <code>POST /api/observations</code></li>
<li>ハブ側で<strong>自動匿名化</strong>（IP最終オクテット掩蔽・メールアドレス除去・時刻丸め）</li>
<li><strong>TLPラベル</strong>（CLEAR/GREEN/AMBER）で共有範囲を自分で制御</li>
<li><a href="/my">マイページ</a>で自分の共有履歴・みんなの共有をブラウザで確認</li>
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
(function(){
  var boxes=document.querySelectorAll('#product-checks input[type=checkbox]');
  var go=document.getElementById('check-go');
  var clear=document.getElementById('check-clear');
  function update(){
    var sel=[];boxes.forEach(function(b){if(b.checked)sel.push(b.value)});
    go.href = sel.length ? '/intel?products='+encodeURIComponent(sel.join(',')) : '/intel';
  }
  boxes.forEach(function(b){b.addEventListener('change',update)});
  if(clear){clear.addEventListener('click',function(){boxes.forEach(function(b){b.checked=false});update();});}
  update();
})();
fetch('/api/stats').then(r=>r.json()).then(s=>{
  document.getElementById('stats').innerHTML =
    '<div class="stat"><b>'+s.participants+'</b><span>参加組織</span></div>'+
    '<div class="stat"><b>'+s.observations_shared+'</b><span>共有された観測</span></div>'+
    '<div class="stat"><b>'+s.intel_objects+'</b><span>公開インテル件数</span></div>'+
    '<div class="stat"><b style="font-size:1rem">'+ (s.last_update||'—') +'</b><span>最終更新</span></div>';
}).catch(()=>{});
</script>
</body></html>"""


PAGE_CSS = """
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--fg:#e6edf3;--muted:#8b949e;--accent:#3fb950;--accent2:#58a6ff;--warn:#d29922;--danger:#f85149}
@media (prefers-color-scheme:light){:root{--bg:#ffffff;--card:#f6f8fa;--border:#d0d7de;--fg:#1f2328;--muted:#57606a;--accent:#1a7f37;--accent2:#0969da}}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--fg);margin:0;line-height:1.7}
.wrap{max-width:860px;margin:0 auto;padding:2rem 1.25rem 4rem}
a{color:var(--accent2)}
a:focus-visible,button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
header.top{border-bottom:1px solid var(--border);padding:.9rem 1.25rem;display:flex;justify-content:space-between;align-items:center}
.brand{font-weight:700;text-decoration:none;color:var(--fg)}
.brand span{color:var(--accent)}
nav.top a{margin-left:1rem;font-size:.9rem;text-decoration:none;color:var(--muted)}
nav.top a:hover{color:var(--fg)}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.4rem;margin:1rem 0}
h1{font-size:1.7rem;margin:.4rem 0 1rem}
h2{font-size:1.15rem;margin:0 0 .8rem}
.muted{color:var(--muted)}
code,kbd{background:#1f2630;padding:.15em .45em;border-radius:4px;font-size:.9em;color:var(--accent2)}
input[type=text],input[type=password],select,textarea{width:100%;padding:.65rem .8rem;border:1px solid var(--border);border-radius:8px;background:var(--bg);color:var(--fg);font-size:1rem;font-family:inherit}
textarea{min-height:110px;font-family:ui-monospace,monospace;font-size:.9rem}
label{display:block;font-weight:600;margin:1rem 0 .3rem}
.btn{display:inline-block;padding:.7rem 1.5rem;border-radius:8px;border:0;font-weight:600;font-size:1rem;cursor:pointer;text-decoration:none}
.btn.primary{background:var(--accent);color:#04160a}
.btn.ghost{border:1px solid var(--border);color:var(--fg);background:transparent}
table{width:100%;border-collapse:collapse;font-size:.9rem}
td,th{border-bottom:1px solid var(--border);padding:.55rem .4rem;text-align:left;vertical-align:top}
.tag{display:inline-block;border-radius:6px;padding:.05rem .5rem;font-size:.75rem;font-weight:700}
.tag.CLEAR{background:#30363d;color:#e6edf3}
.tag.GREEN{background:rgba(63,185,80,.18);color:var(--accent)}
.tag.AMBER{background:rgba(210,153,34,.2);color:var(--warn)}
.pill{display:inline-block;border:1px solid var(--border);border-radius:999px;padding:.15rem .7rem;font-size:.8rem;color:var(--muted)}
.ok{color:var(--accent);font-weight:700}
.err{color:var(--danger);font-weight:700}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
"""

NAV = """<header class="top"><a class="brand" href="/">🛡 守 <span>Mamori</span></a>
<nav class="top"><a href="/intel">脅威一覧</a><a href="/newsletter">メルマガ</a><a href="/my">マイページ</a><a href="/post">共有する</a><a href="/api">API</a><a href="/status">ステータス</a><a href="/about">仕組み</a><a href="/agent">エージェント</a><a href="/start">参加ガイド</a><a href="/account">鍵の発行</a></nav></header>"""


def render_my(caller, key: str) -> bytes:
    if not caller:
        body = """<div class="card"><h2>参加者キーを入力</h2>
<p class="muted">発行された専用キー（mk_...）を入力すると、あなたの組織の状態・共有履歴・他社の共有が見られます。キーはURLには載りません。</p>
<form method="post" action="/my"><label for="k">参加者キー</label>
<input id="k" name="key" type="password" autocomplete="off" placeholder="mk_..." required>
<p style="margin-top:1rem"><button class="btn primary" type="submit">表示する</button></p></form>
<p class="muted" style="font-size:.85rem">キーをお持ちでない方は <a href="/start">参加ガイド</a> へ。公開インテルはキー不要で <a href="/intel">/intel</a> から読めます。</p></div>"""
        return _shell("マイページ — 守 Mamori", body)
    oh = org_hash(caller.get("org", "default"))
    tlp_max = _tlp_max(caller)
    max_tlp = TLP_ORDER.get(tlp_max, 1)
    mine = [o for o in _read_obs() if o.get("org_hash") == oh]
    visible = [o for o in _read_obs() if TLP_ORDER.get(o.get("tlp", "GREEN"), 1) <= max_tlp]
    others = [o for o in visible if o.get("org_hash") != oh]
    def rows(obs, show_org):
        out = []
        for o in sorted(obs, key=lambda x: x.get("received_at", 0), reverse=True)[:50]:
            ts = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(o.get("received_at", 0)))
            tlp = _esc(o.get("tlp", "GREEN"))
            typ = _esc(o.get("type", "—"))
            pat = _esc(str(o.get("pattern", ""))[:120])
            org = f'<td class="muted">{_esc(o.get("org_hash", "—")[:10])}</td>' if show_org else ""
            out.append(f'<tr><td class="muted">{ts}</td><td><span class="tag {tlp}">{tlp}</span></td>'
                       f'<td>{typ}</td><td>{pat}</td>{org}</tr>')
        return "\n".join(out) or '<tr><td colspan="5" class="muted">まだありません</td></tr>'
    body = f"""<div class="card"><h2>あなたのキー</h2>
<p>組織の記号: <code>{_esc(oh)}</code> ／ 閲覧範囲: <span class="tag {_esc(tlp_max)}">{_esc(tlp_max)}</span> まで</p>
<p class="muted" style="font-size:.85rem">組織名は記号（ハッシュ）でのみ表示されます。キーの漏洩が疑われる場合は <a href="https://teai.io/contact">お問い合わせ</a> から失効を依頼してください（24時間以内に対応）。</p></div>
<div class="card"><h2>あなたの共有（直近50件・90日で自動削除）</h2>
<table><tr><th>時刻</th><th>TLP</th><th>種別</th><th>内容</th></tr>{rows(mine, False)}</table></div>
<div class="card"><h2>みんなの共有（あなたが見られる範囲・直近50件）</h2>
<table><tr><th>時刻</th><th>TLP</th><th>種別</th><th>内容</th><th>共有元</th></tr>{rows(others, True)}</table>
<form method="post" action="/post" style="margin-top:1rem"><input type="hidden" name="key" value="{_esc(key)}"><button class="btn ghost" type="submit">観測を共有する →</button></form></div>"""
    return _shell("マイページ — 守 Mamori", body)


def render_post(caller, key: str, msg: str = "", ok: bool | None = None) -> bytes:
    if not caller:
        body = """<div class="card"><h2>観測の共有には参加者キーが必要です</h2>
<form method="post" action="/post"><label for="k">参加者キー</label>
<input id="k" name="key" type="password" autocomplete="off" placeholder="mk_..." required>
<p style="margin-top:1rem"><button class="btn primary" type="submit">次へ</button></p></form>
<p class="muted" style="font-size:.85rem">キーは <a href="/start">参加ガイド</a> の手順で発行されます（ベータ期間中は無料）。</p></div>

<div class="card"><h2>📝 記入例（キーなしで今すぐ読めます）</h2>
<p class="muted">「何を書けばいいか分からない」方へ。実際の共有はこんな一文で十分です。IPアドレスの末尾とメールアドレスはハブ側で自動的に伏せられます。</p>
<table>
<tr><th>種別</th><th>記入例（このまま書いてOK）</th><th>TLP目安</th></tr>
<tr><td>http_probe</td><td><code>/wp-login.php への総当たりを412回観測。同一 /24 から30分間に集中</code></td><td><span class="tag GREEN">GREEN</span></td></tr>
<tr><td>payload</td><td><code>/etc/passwd を含むGETリクエストを検知。User-Agentは sqlmap/1.7</code></td><td><span class="tag GREEN">GREEN</span></td></tr>
<tr><td>scanner</td><td><code>22番ポートへのSSHスキャン。NmapのSYNスキャン特徴あり</code></td><td><span class="tag CLEAR">CLEAR</span></td></tr>
</table>
<p class="muted" style="font-size:.85rem;margin-top:.8rem">種別の選び方：怪しいパスへのアクセス=http_probe／ログイン試行の繰り返し=brute_force／コマンドやSQL文らしき文字列=payload／網羅的な探索=scanner。迷ったら other で構いません。</p></div>

<div class="card"><h2>🚫 書いてはいけない情報（投稿前チェック）</h2>
<ul>
<li><strong>自社ドメイン・社内ホスト名</strong>（例: <code>mail.example.co.jp</code>、<code>srv01.internal</code>）— ハブ側でも一部自動マスクしますが、投稿前にご自身で消してください</li>
<li><strong>人の名前・メールアドレス</strong>（担当者名・顧客名など）</li>
<li><strong>顧客・取引先を特定できる情報</strong></li>
<li><strong>TLP:RED（共有不可）に指定された情報</strong> — 絶対に投稿しないでください</li>
</ul>
<p class="muted" style="font-size:.85rem">詳しくは <a href="/terms">データ取り扱い方針</a> をご確認ください。</p></div>"""
        return _shell("観測を共有 — 守 Mamori", body)
    flash = ""
    if msg:
        cls = "ok" if ok else "err"
        flash = f'<p class="{cls}">{_esc(msg)}</p>'
    body = f"""<div class="card"><h2>攻撃の観測を共有する</h2>
<p class="muted">見つけた攻撃の特徴（怪しいパス・ペイロード・手法など）を共有すると、他の参加者の防御に使われます。IPアドレスの末尾・メールアドレスは自動で伏せられますが、<strong>自社ドメイン・社内サーバー名・人の名前は投稿前にご自身で消してください</strong>。</p>
{flash}
<form method="post" action="/post">
<input type="hidden" name="key" value="{_esc(key)}">
<label for="type">種別（何を見たか）</label>
<select id="type" name="type">
<option value="http_probe">HTTP プローブ（怪しいパスへのアクセス）</option>
<option value="brute_force">総当たり（ログイン試行）</option>
<option value="payload">ペイロード（コマンド・SQL注入など）</option>
<option value="scanner">スキャナー（脆弱性スキャン）</option>
<option value="malware">マルウェア通信</option>
<option value="other">その他</option>
</select>
<label for="pattern">内容（何を・どこで）。例: wp-login.php へのPOST、/etc/passwd を含むリクエスト</label>
<textarea id="pattern" name="pattern" required maxlength="2000" placeholder="例: /wp-login.php への総当たりを412回観測。送信元は /24 で伏せられます"></textarea>
<label for="tlp">共有範囲（TLP）— 迷ったら GREEN</label>
<select id="tlp" name="tlp">
<option value="CLEAR">CLEAR（白）— 誰でも見られる</option>
<option value="GREEN" selected>GREEN（緑）— 参加している会社だけ</option>
<option value="AMBER">AMBER（黄）— 運営が確認した会社だけ</option>
</select>
<p style="margin-top:1.2rem"><button class="btn primary" type="submit">共有する</button>
<button class="btn ghost" type="submit" formaction="/my" formnovalidate>マイページへ</button></p></form>
<p class="muted" style="font-size:.85rem">投稿は1時間に30件まで。90日後に自動削除されます。TLP:RED（共有不可）の情報は絶対に投稿しないでください。</p></div>"""
    return _shell("観測を共有 — 守 Mamori", body)


def render_api_doc() -> bytes:
    body = """<div class="card"><h2>認証</h2>
<p>参加者向けエンドポイントは、HTTPヘッダー <code>X-Mamori-Key: mk_...</code>（またはクエリ <code>?key=</code>）で認証します。公開エンドポイントは認証不要です。レート制限: 投稿 30回/時・キー、読取 120回/時・IP。超過時は <code>429</code>。</p></div>
<div class="card"><h2>公開（認証不要）</h2>
<table><tr><th>エンドポイント</th><th>内容</th></tr>
<tr><td><code>GET /api/latest</code></td><td>最新の脅威インテル（TLP:CLEAR・JSON）</td></tr>
<tr><td><code>GET /api/stix</code></td><td>STIX 2.1 バンドル（MISP/OpenCTIにインポート可）</td></tr>
<tr><td><code>GET /api/stats</code></td><td>公開カウンタ（参加組織数・観測数・インテル件数）</td></tr>
<tr><td><code>GET /api/sample-report</code></td><td>対策下書きレポートの実物（Markdown）</td></tr>
<tr><td><code>GET /api/observations</code></td><td>キーなし: TLP:CLEAR の観測のみ</td></tr>
<tr><td><code>GET /healthz</code> / <code>/api/refresh-status</code></td><td>稼働確認・最終リフレッシュ状況</td></tr></table></div>
<div class="card"><h2>参加者（キー必須）</h2>
<table><tr><th>エンドポイント</th><th>内容</th></tr>
<tr><td><code>GET /api/whoami</code></td><td>キーの有効性確認。org_hash と tlp_max を返す</td></tr>
<tr><td><code>GET /api/observations</code></td><td>自分の tlp_max 以下の観測（直近200件・90日保持）</td></tr>
<tr><td><code>POST /api/observations</code></td><td>観測を投稿。JSON: <code>{"type": "...", "pattern": "...", "tlp": "CLEAR|GREEN|AMBER"}</code>。TLP:RED は拒否（400）。成功時 201</td></tr></table></div>
<div class="card"><h2>エラー形式</h2>
<p>すべて <code>{"error": "..."}</code> 形式のJSON。400=形式不正、401/403=キー不正、404=なし、429=レート制限。</p>
<p class="muted">ブラウザからの投稿は <a href="/post">/post</a>、状態確認は <a href="/my">/my</a> でも行えます。</p></div>"""
    return _shell("APIリファレンス — 守 Mamori", body)


def render_about() -> bytes:
    body = """<div class="card"><h2>30秒でわかるMamori</h2>
<p><strong>Mamoriは「攻撃の観測を、会社どうしで匿名で共有する場」です。</strong></p>
<p>ある会社が「うちにこんな攻撃が来た」と共有すると、ほかの会社が「同じ攻撃が来たら止めよう」と先回りできます。1社の被害が、みんなのワクチンになる仕組みです。</p>
<div style="background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:1.2rem;font-family:ui-monospace,monospace;font-size:.85rem;line-height:2;overflow-x:auto">
🏢 A社「/wp-login.php に総当たりが来た」<br>
&nbsp;&nbsp;→ 🛡 Mamori（自動で匿名化：IP末尾を伏せ・社名は記号に）<br>
&nbsp;&nbsp;&nbsp;&nbsp;→ 🏢 B社・C社「同じパターンを自社ログで探してブロック」<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;→ 🏢 B社「うちにも来た。今度はこっちの手口も共有」<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;→ 🔁 共有するほど、全員の防御が強くなる
</div></div>

<div class="card"><h2>3つの仕組み</h2>
<h3 style="margin:.6rem 0 .3rem">1. 脅威を自動で集める（キー不要）</h3>
<p class="muted">CISA KEV（米政府の「悪用確認済み」脆弱性リスト）とJPCERT/CCの注意喚起・週報を6時間ごとに自動取得。<a href="/intel">/intel</a> で誰でも読めます。</p>
<h3 style="margin:1rem 0 .3rem">2. 自社に関係あるか照合する</h3>
<p class="muted">照合キット（無料）が、自社の使っている製品一覧と脆弱性情報を突き合わせ、「要対応／要確認／関係なし」に分類し、対策の下書きまで出します。</p>
<h3 style="margin:1rem 0 .3rem">3. 観測を匿名で共有する</h3>
<p class="muted">攻撃を見つけたら、<a href="/post">ブラウザのフォーム</a>から共有。IPアドレスの末尾・メールアドレスは自動で伏せ、会社名は記号（ハッシュ）に置き換えて保存します。共有範囲はTLP（白=公開／緑=参加者のみ／黄=限定）で投稿ごとに選べます。90日後に自動削除。</p></div>

<div class="card"><h2>なぜこれがいいのか</h2>
<ul>
<li><strong>中小企業こそ狙われる</strong> — 大企業は高い対策を持つため、攻撃者は対策の薄い中小を踏み台・直接の標的にします。でも中小には専任のセキュリティ担当がいない。</li>
<li><strong>「受信専用」の情報はあるが「共有する場」がなかった</strong> — JPCERTの注意喚起は読めるが、自社の観測を匿名で出し合う日本語の場は実質ゼロでした。</li>
<li><strong>共有の最大の障壁は「バレる」こと</strong> — 攻撃を受けたことを公表したくない。Mamoriは自動匿名化でこの心理的障壁を技術的に取り除きます。</li>
<li><strong>1社の被害が全員の防御になる</strong> — 同じ攻撃は複数社に同時に来ます。最初の1社が共有すれば、残り全員が被害を回避できます。</li>
</ul></div>

<div class="card"><h2>ほかにないの？（既存の仕組みとの違い）</h2>
<table>
<tr><th>仕組み</th><th>向いている人</th><th>コスト・障壁</th><th>Mamoriとの違い</th></tr>
<tr><td><a href="https://www.misp-project.org/" rel="noopener" target="_blank">MISP</a>（OSS）</td><td>大きなSOC</td><td>無料だが構築・運用に専門要員</td><td>Mamoriはサーバ不要・ブラウザ完結</td></tr>
<tr><td><a href="https://filigran.io/solutions/open-cti/" rel="noopener" target="_blank">OpenCTI</a></td><td>CTIチーム</td><td>インフラが重い（ES/K8s）</td><td>同上</td></tr>
<tr><td><a href="https://www.jpcert.or.jp/cista/" rel="noopener" target="_blank">CISTA</a>（JPCERT/CC）</td><td>重要インフラ等・審査制</td><td>中小は事実上対象外</td><td>Mamoriは審査なし・誰でも</td></tr>
<tr><td>業界ISAC</td><td>業種限定</td><td>年会費数十万〜</td><td>無料・業種不問</td></tr>
<tr><td>Recorded Future等</td><td>大企業</td><td>年数百万〜（見積制）</td><td>無料</td></tr>
<tr><td>JPCERT注意喚起・<a href="https://www.jpcert.or.jp/tsubame/" rel="noopener" target="_blank">TSUBAME</a></td><td>全員</td><td>無料</td><td>あちらは<strong>受信専用</strong>。Mamoriは<strong>双方向</strong></td></tr>
<tr><td><a href="https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/automated-indicator-sharing-ais" rel="noopener" target="_blank">CISA AIS</a>（米）</td><td>米国中心</td><td>PKI証明書・TAXII運用</td><td>日本の中小には非現実的</td></tr>
</table>
<p class="muted" style="font-size:.85rem;margin-top:.8rem">Mamoriの独自性: ①ゼロインフラ・ブラウザ完結 ②自動匿名化 ③無料 ④TLPの軽量実装 ⑤日本の中小の「観測共有の空白」を埋める双方向ハブ</p></div>

<div class="card"><h2>使い方（人とAIエージェント）</h2>
<p><strong>人が使う:</strong> <a href="/my">マイページ</a>でキーを入力 → 共有を読む・<a href="/post">投稿する</a>。詳しい手順は <a href="/start">参加ガイド</a>。</p>
<p><strong>AIエージェントが使う:</strong> Claude・Senteなどのエージェントから「最新の脅威を調べて」「この観測を共有して」と頼めます。HTTP API（<a href="/api">/api</a>）のほか、<strong>MCPサーバー</strong>も用意しています → <a href="/agent">エージェント向けガイド</a></p></div>"""
    return _shell("Mamoriの仕組み — 守 Mamori", body)


def render_agent() -> bytes:
    body = """<div class="card"><h2>AIエージェントから使う</h2>
<p>MamoriはHTTP APIなので、どんなAIエージェント・スクリプトからでも使えます。さらに、Claude等のエージェントが標準で話せる <strong>MCP（Model Context Protocol）サーバー</strong> も同梱しています。</p></div>

<div class="card"><h2>方法1: HTTP API（どのエージェントでも）</h2>
<p class="muted">エージェントにこう頼むだけです:</p>
<div style="background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:1rem;font-size:.9rem;line-height:1.9">
「https://mamori.teai.io/api/latest を読んで、今週の重要な脆弱性を3つ教えて」<br>
「Mamoriに『/wp-login.phpへの総当たり』をTLP:GREENで共有して。キーは環境変数 MAMORI_KEY」
</div>
<pre style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:.9rem;font-size:.85rem;overflow-x:auto"># 最新の脅威を読む（キー不要）
curl -s https://mamori.teai.io/api/latest

# 観測を共有する（参加者キー）
curl -X POST https://mamori.teai.io/api/observations \\
  -H "X-Mamori-Key: $MAMORI_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"type":"http_probe","pattern":"/wp-login.php への総当たり","tlp":"GREEN"}'

# みんなの共有を読む
curl -s https://mamori.teai.io/api/observations -H "X-Mamori-Key: $MAMORI_KEY"</pre>
<p class="muted">エンドポイント一覧は <a href="/api">APIリファレンス</a>。</p></div>

<div class="card"><h2>方法2: MCPサーバー（Claude Desktop / Claude Code / Sente）</h2>
<p><b>かんたん導入：</b><code>curl -fsSL https://mamori.teai.io/install.sh | bash</code> で Claude Code・Codex・Sente に自動登録。Windows は PowerShell で <code>irm https://mamori.teai.io/install.ps1 | iex</code>（<a href="/start#ai">手順</a>）。</p>
<p>照合キット（<a href="/kit.tar.gz">kit.tar.gz</a>）に <code>mcp/mamori_mcp.py</code> として同梱。エージェントに「mamori_latest」「mamori_share」などのツールとして見えます。</p>
<h3 style="margin:.8rem 0 .3rem">Claude Desktop / Claude Code の設定例</h3>
<pre style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:.9rem;font-size:.85rem;overflow-x:auto">{
  "mcpServers": {
    "mamori": {
      "command": "python3",
      "args": ["/path/to/mamori/mcp/mamori_mcp.py"],
      "env": { "MAMORI_KEY": "mk_..." }
    }
  }
}</pre>
<h3 style="margin:1rem 0 .3rem">使えるツール</h3>
<table>
<tr><th>ツール</th><th>やること</th><th>キー</th></tr>
<tr><td><code>mamori_latest</code></td><td>最新の脅威インテルを取得</td><td>不要</td></tr>
<tr><td><code>mamori_intel_summary</code></td><td>直近の脅威を日本語で要約</td><td>不要</td></tr>
<tr><td><code>mamori_observations</code></td><td>みんなの共有を読む</td><td>必要</td></tr>
<tr><td><code>mamori_share</code></td><td>観測を共有（type/pattern/tlp）</td><td>必要</td></tr>
<tr><td><code>mamori_whoami</code></td><td>キーの有効性を確認</td><td>必要</td></tr>
</table>
<p class="muted" style="margin-top:.8rem">MCPサーバーは標準入出力で話す小さなPythonスクリプト（依存なし・stdlibのみ）。キーは環境変数で渡し、コードに書きません。</p></div>

<div class="card"><h2>エージェント運用の例</h2>
<ul>
<li><strong>朝の巡回:</strong> エージェントが mamori_latest を読み、自社スタックに関係ある新着をSlack/LINEに要約</li>
<li><strong>インシデント時:</strong> ログに怪しいパターンを見つけたエージェントが mamori_share で共有（TLP:GREEN）</li>
<li><strong>相互防御:</strong> mamori_observations を定期取得し、自社のWAF/ファイアウォールのブロック候補を提案</li>
</ul>
<p class="muted">エージェントによる共有も人間と同じく自動匿名化・90日削除の対象です。TLP:RED（共有不可）の情報は絶対に投稿しないでください。</p></div>"""
    return _shell("エージェント向けガイド — 守 Mamori", body)


def render_status() -> bytes:
    s = _stats()
    rs = {**_refresh_state, "bundle_age_hours": round(_bundle_age_hours(), 2)}
    age = rs["bundle_age_hours"]
    fresh = age < REFRESH_HOURS * 1.5
    state = '<span class="ok">正常</span>' if fresh and not _refresh_state.get("last_error") else \
            ('<span class="err">要確認</span>' if _refresh_state.get("last_error") else '<span class="muted">更新待ち</span>')
    body = f"""<div class="card"><h2>稼働状況</h2>
<p>状態: {state} ／ バージョン: v{VERSION}</p>
<table>
<tr><th>項目</th><th>値</th></tr>
<tr><td>最終インテル生成</td><td>{_esc(s["last_update"] or "—")}</td></tr>
<tr><td>最終リフレッシュ成功</td><td>{_esc(_refresh_state.get("last_ok") or "—")}</td></tr>
<tr><td>バンドルの経過時間</td><td>{age} 時間（{REFRESH_HOURS}時間ごとに自動更新）</td></tr>
<tr><td>最後のエラー</td><td>{_esc(_refresh_state.get("last_error") or "なし")}</td></tr>
<tr><td>参加組織 / 観測 / インテル</td><td>{s["participants"]} / {s["observations_shared"]} / {s["intel_objects"]}</td></tr></table></div>
<div class="card"><h2>情報源</h2>
<ul><li>CISA KEV（悪用確認済み脆弱性カタログ）</li><li>JPCERT/CC 注意喚起</li><li>JPCERT/CC Weekly Report</li></ul>
<p class="muted">機械向け: <code>GET /healthz</code> ・ <code>GET /api/refresh-status</code>（JSON）</p></div>"""
    return _shell("ステータス — 守 Mamori", body)


def _shell(title: str, body: str) -> bytes:
    html = f"""<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)}</title>
<meta name="description" content="守 Mamori — セキュリティ相互防御ハブ">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡</text></svg>">
<style>{PAGE_CSS}</style></head><body>
{NAV}
<main class="wrap">{body}</main>
</body></html>"""
    return html.encode()


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



def hmac_eq(a: str, b: str) -> bool:
    import hmac as _hm
    return bool(a) and _hm.compare_digest(a, b)


def _fmt_day(ts) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ts or 0))


TLP_EXPLAIN = {
    "GREEN": "緑（GREEN）まで — 参加している会社の共有も見られます",
    "CLEAR": "白（CLEAR）まで — 公開分のみ。フリーメールで登録した場合の初期値です。会社のメールで登録し直すか、運営の確認後に緑まで広がります",
    "AMBER": "黄（AMBER）まで — 運営が確認した会社向けの共有も見られます",
}


def render_account_login(msg: str = "") -> bytes:
    flash = f'<p class="err">{_esc(msg)}</p>' if msg else ""
    body = f"""<div class="card"><h2>🔑 鍵の発行・管理</h2>
<p class="muted">メールアドレスを入れると、ログイン用のリンクが届きます。リンクを開くと、その場で鍵（参加者キー）を発行・確認・停止できます。ベータ期間中は無料です。</p>
{flash}
<form method="post" action="/account/login"><label for="email">メールアドレス</label>
<input id="email" name="email" type="email" autocomplete="email" placeholder="you@example.co.jp" required>
<p style="margin-top:1rem"><button class="btn primary" type="submit">ログイン用のリンクを送る</button></p></form>
<p class="muted" style="font-size:.85rem">会社のドメインのメールで登録すると、参加している会社の共有（緑）まで見られます。フリーメールの場合は、まず公開分（白）からです。パスワードはありません。</p></div>"""
    return _shell("鍵の発行・管理 — 守 Mamori", body)


def render_account_sent(email: str) -> bytes:
    body = f"""<div class="card"><h2>📮 メールを送りました</h2>
<p><strong>{_esc(email)}</strong> にログイン用のリンクを送りました。30分以内に開いてください。</p>
<p class="muted">数分たっても届かないときは、迷惑メールのフォルダを確認するか、<a href="/account">もう一度送ってください</a>。</p></div>"""
    return _shell("メールを送りました — 守 Mamori", body)


def render_account_verify(token: str, email: str | None) -> bytes:
    if not email:
        body = """<div class="card"><h2>リンクが使えません</h2>
<p>期限（30分）が切れたか、すでに使われています。<a href="/account">もう一度メールアドレスを入れてください</a>。</p></div>"""
        return _shell("ログイン — 守 Mamori", body)
    body = f"""<div class="card"><h2>ログインしますか？</h2>
<p><strong>{_esc(email)}</strong> として、鍵の管理画面に入ります。</p>
<form method="post" action="/account/verify"><input type="hidden" name="t" value="{_esc(token)}">
<p style="margin-top:1rem"><button class="btn primary" type="submit">ログインする</button></p></form></div>"""
    return _shell("ログイン — 守 Mamori", body)


# --- メルマガ（守 Mamori セキュリティ便り） -----------------------------------
NL_TAGLINE = "CISA KEV・JPCERT/CC の更新と、いま実際に使われている突破の手口を、やさしい日本語で週1回まとめてお届けします。登録はメールアドレスだけ。1クリックでいつでも解除できます。"


def render_newsletter(msg: str = "", ok: bool | None = None, email: str = "") -> bytes:
    flash = ""
    if msg:
        cls = "ok" if ok else "err"
        flash = f'<p class="{cls}">{_esc(msg)}</p>'
    body = f"""<div class="card"><h2>📬 守 Mamori セキュリティ便り（無料メルマガ）</h2>
<p class="muted">{_esc(NL_TAGLINE)}</p>
{flash}
<form method="post" action="/newsletter/subscribe"><label for="nl-email">メールアドレス</label>
<input id="nl-email" name="email" type="email" autocomplete="email" placeholder="you@example.co.jp" value="{_esc(email)}" required>
<p style="margin-top:1rem"><button class="btn primary" type="submit">確認メールを送る</button></p></form>
<p class="muted" style="font-size:.85rem">なりすまし登録を防ぐため、確認メールのリンクを開いた時点で購読開始です。メールアドレスはメルマガ配信だけに使い、第三者には渡しません。解除は毎回のメールのリンクから1クリックでできます。</p></div>
<div class="card"><h2>どんな内容が届くの？</h2>
<ul>
<li><strong>今週の3点</strong> — 悪用が確認された脆弱性と国内の注意喚起から、急ぐものだけを厳選</li>
<li><strong>突破の手口をやさしく</strong> — 最近実際に使われた攻撃（アプリ解析→API攻撃、AIスキャン等）を図解レベルで解説</li>
<li><strong>今日できる一手</strong> — 専門家でなくてもその日にできる対策を1つ</li>
</ul>
<p class="muted" style="font-size:.85rem">配信は週1回程度。派手な宣伝は送りません。最新の脅威は <a href="/intel">脅威一覧</a> でいつでも無料・登録不要で見られます。</p></div>"""
    return _shell("セキュリティ便り（メルマガ） — 守 Mamori", body)


def render_newsletter_confirm(email: str, token: str, valid: bool) -> bytes:
    if not valid:
        body = """<div class="card"><h2>確認リンクが使えません</h2>
<p>リンクが古いか、書き換えられています。<a href="/newsletter">もう一度メールアドレスを登録してください</a>。</p></div>"""
        return _shell("購読の確認 — 守 Mamori", body)
    body = f"""<div class="card"><h2>購読を開始しますか？</h2>
<p><strong>{_esc(email)}</strong> に「守 Mamori セキュリティ便り」をお届けします。</p>
<form method="post" action="/newsletter/confirm">
<input type="hidden" name="email" value="{_esc(email)}"><input type="hidden" name="t" value="{_esc(token)}">
<p style="margin-top:1rem"><button class="btn primary" type="submit">購読を開始する</button></p></form>
<p class="muted" style="font-size:.85rem">心当たりがない場合は、このページを閉じてください（何も起きません）。</p></div>"""
    return _shell("購読の確認 — 守 Mamori", body)


def render_newsletter_done(email: str) -> bytes:
    body = f"""<div class="card"><h2>✅ 購読を開始しました</h2>
<p><strong>{_esc(email)}</strong> 宛に、次号から「守 Mamori セキュリティ便り」をお届けします。</p>
<p class="muted">届かないときは迷惑メールのフォルダを確認してください。解除はメールの末尾のリンクからいつでも1クリックでできます。</p>
<p><a href="/intel">→ さっそく最新の脅威一覧を見る</a></p></div>"""
    return _shell("購読開始 — 守 Mamori", body)


def render_newsletter_unsub(email: str, ok: bool) -> bytes:
    if ok:
        body = f"""<div class="card"><h2>配信を停止しました</h2>
<p><strong>{_esc(email)}</strong> への「守 Mamori セキュリティ便り」の配信を止めました。いつでも <a href="/newsletter">こちら</a> から再開できます。</p>
<p class="muted">脅威一覧は登録不要でいつでも見られます: <a href="/intel">/intel</a></p></div>"""
    else:
        body = """<div class="card"><h2>解除リンクが使えません</h2>
<p>リンクが古いか、すでに解除済みです。メール本文の最新の解除リンクをお試しください。</p></div>"""
    return _shell("配信停止 — 守 Mamori", body)


def _nl_link(purpose: str, email: str) -> str:
    return f"{PUBLIC_URL}/newsletter/{purpose}?email={email}&t={STORE.nl_token(purpose, email)}"


def _newsletter_subscribe_post(self):
    ip = self.client_address[0]
    form = self._form()
    email = accounts.normalize_email(form.get("email", ""))
    if not email:
        return self._html(400, render_newsletter("メールアドレスの形を確認してください", False))
    if not (_rate_ok(f"nl-ip:{ip}", 10) and _rate_ok(f"nl-mail:{email}", 3)):
        return self._html(429, render_newsletter("送信が続いています。1時間ほどおいてからお試しください", False, email))
    STORE.nl_subscribe_pending(email)
    link = _nl_link("confirm", email)
    sent = accounts.send_mail(email, "【守 Mamori】セキュリティ便りの購読確認",
        "守 Mamori セキュリティ便り（週1回・無料）の購読申込を受け付けました。\n"
        "下のリンクを開いて「購読を開始する」を押すと、登録が完了します。\n\n"
        f"{link}\n\n"
        "心当たりがない場合は、このメールを破棄してください（登録されません）。\n\n"
        "守 Mamori — https://mamori.teai.io")
    if not sent:
        return self._html(503, render_newsletter("メールを送れませんでした。時間をおいてもう一度お試しください", False, email))
    body = f"""<div class="card"><h2>📮 確認メールを送りました</h2>
<p><strong>{_esc(email)}</strong> に購読確認のメールを送りました。メールのリンクを開いて「購読を開始する」を押すと、登録が完了します。</p>
<p class="muted">数分たっても届かないときは、迷惑メールのフォルダを確認するか、<a href="/newsletter">もう一度送ってください</a>。</p></div>"""
    return self._html(200, _shell("確認メール送信 — 守 Mamori", body))


def _newsletter_confirm_post(self):
    form = self._form()
    email = accounts.normalize_email(form.get("email", ""))
    token = form.get("t", "")
    if not email or not hmac_eq(token, STORE.nl_token("confirm", email)):
        return self._html(400, render_newsletter_confirm("", "", False))
    STORE.nl_confirm(email)
    return self._html(200, render_newsletter_done(email))


def _newsletter_unsub_get(self):
    q = parse_qs(urlparse(self.path).query)
    email = accounts.normalize_email(q.get("email", [""])[0])
    token = q.get("t", [""])[0]
    if not email or not hmac_eq(token, STORE.nl_token("unsub", email)):
        return self._html(400, render_newsletter_unsub("", False))
    ok = STORE.nl_unsubscribe(email)
    return self._html(200, render_newsletter_unsub(email, ok))


def render_account(email: str, csrf: str, msg: str = "", new_key: str | None = None,
                   new_rec: dict | None = None) -> bytes:
    acct = STORE.account(email) or {"tlp_max": accounts.tlp_for_email(email)}
    keys = STORE.keys_for(email)
    active = [k for k in keys if not k.get("revoked_at")]
    flash = f'<p class="ok">{_esc(msg)}</p>' if msg else ""
    newbox = ""
    if new_key:
        newbox = f"""<div class="card" style="border-color:var(--accent)"><h2>✅ 鍵を発行しました</h2>
<p><strong>この画面を閉じると、二度と表示されません。</strong>いまパスワード管理ソフトなどに保存してください。</p>
<div style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:center">
<code id="newkey" style="font-size:1rem;padding:.6rem .8rem;word-break:break-all">{_esc(new_key)}</code>
<button class="btn ghost" type="button" onclick="navigator.clipboard&&navigator.clipboard.writeText(document.getElementById('newkey').textContent).then(()=>this.textContent='コピーしました')">コピー</button></div>
<p class="muted" style="margin-top:.8rem">使い方: ターミナルで <code>export MAMORI_KEY='上のキー'</code> → <code>bash tools/check-key.sh</code> で <code>"ok": true</code> が出れば準備完了。詳しくは <a href="/start">参加ガイド（動画つき）</a>。</p></div>"""
    rows = []
    for k in keys:
        status = (f'<span class="muted">停止（{_fmt_day(k["revoked_at"])}）</span>' if k.get("revoked_at")
                  else '<span class="tag GREEN">有効</span>')
        action = "" if k.get("revoked_at") else f"""<form method="post" action="/account/revoke" style="margin:0"
onsubmit="return confirm('このキーを止めますか？止めると元に戻せません')"><input type="hidden" name="csrf" value="{_esc(csrf)}">
<input type="hidden" name="id" value="{_esc(k['id'])}"><button class="btn ghost" type="submit" style="white-space:nowrap">止める</button></form>"""
        rows.append(f'<tr><td>{_esc(k["label"])}</td><td><code>mk_…{_esc(k["last4"])}</code></td>'
                    f'<td class="muted">{_fmt_day(k["created"])}</td><td>{status}</td><td>{action}</td></tr>')
    table = "\n".join(rows) or '<tr><td colspan="5" class="muted">まだ鍵はありません。下のボタンで発行できます</td></tr>'
    can_issue = len(active) < accounts.MAX_ACTIVE_KEYS
    issue = f"""<form method="post" action="/account/keys"><input type="hidden" name="csrf" value="{_esc(csrf)}">
<label for="label">鍵の名前（どこで使うか。例: 本社サーバー）</label>
<input id="label" name="label" type="text" maxlength="40" placeholder="既定のキー" style="width:100%">
<p style="margin-top:1rem"><button class="btn primary" type="submit">新しい鍵を発行する</button></p></form>""" if can_issue else \
        f'<p class="muted">有効な鍵は{accounts.MAX_ACTIVE_KEYS}本までです。使っていない鍵を止めると発行できます。</p>'
    body = f"""{newbox}<div class="card"><h2>🔑 あなたの鍵</h2>
<p>ログイン中: <strong>{_esc(email)}</strong></p>
<p class="muted">閲覧範囲: {_esc(TLP_EXPLAIN.get(acct.get("tlp_max", "CLEAR"), acct.get("tlp_max", "")))}</p>
{flash}
<div style="overflow-x:auto"><table style="white-space:nowrap"><tr><th>名前</th><th>キー</th><th>発行日</th><th>状態</th><th></th></tr>{table}</table></div>
<p class="muted" style="font-size:.85rem">キーは発行した瞬間に1回だけ表示し、ハブには元に戻せない形（ハッシュ）でしか保存していません。なくしたら、止めて新しく発行してください。漏れたかもしれないときも、すぐに「止める」を押してください。</p></div>
<div class="card"><h2>新しい鍵</h2>{issue}</div>
<div class="card"><p>次にやること: <a href="/start">参加ガイド（動画つき）</a> ／ <a href="/my">マイページ</a> ／ <a href="/post">観測を共有する</a></p>
<form method="post" action="/account/logout" style="margin-top:.6rem"><input type="hidden" name="csrf" value="{_esc(csrf)}">
<button class="btn ghost" type="submit">ログアウト</button></form></div>"""
    return _shell("鍵の発行・管理 — 守 Mamori", body)

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

    def _kit_head(self):
        if "kit" not in _kit_cache:
            _kit_cache["kit"] = build_kit()
        self.send_response(200)
        self.send_header("Content-Type", "application/gzip")
        self.send_header("Content-Disposition", 'attachment; filename="mamori-kit.tar.gz"')
        self.send_header("Content-Length", str(len(_kit_cache["kit"])))
        self.end_headers()

    def do_HEAD(self):
        path = urlparse(self.path).path
        if path.startswith("/media/"):
            return self._media(path[len("/media/"):])
        if path == "/kit.tar.gz":
            return self._kit_head()
        if path in ("/MamoriCheck.zip", "/MamoriBar.zip"):
            f = APP_DIR / ("MamoriCheck.zip" if path == "/MamoriCheck.zip" else "dist/MamoriBar.zip")
            if not f.exists():
                self.send_response(404)
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition", f'attachment; filename="{f.name}"')
                self.send_header("Content-Length", str(f.stat().st_size))
            self.end_headers()
            return
        self.send_response(200 if path in ("/", "/healthz", "/install.sh", "/install.ps1", "/start", "/intel", "/my", "/post", "/api", "/status", "/about", "/agent", "/newsletter") else 404)
        self.end_headers()

    def _caller(self) -> dict | None:
        q = parse_qs(urlparse(self.path).query)
        key = self.headers.get("X-Mamori-Key") or q.get("key", [None])[0]
        return lookup_key(key)

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
            qs = parse_qs(urlparse(self.path).query)
            products = [p.strip() for p in (qs.get("products", [""])[0].split(",")) if p.strip()]
            lang = (qs.get("lang", [""])[0] or "").lower()
            if lang not in ("ja", "en"):
                accept = (self.headers.get("Accept-Language") or "").strip().lower()
                first = accept.split(",")[0].split(";")[0].strip() if accept else ""
                lang = "ja" if first.startswith("ja") else ("en" if first else "ja")
            self._send(200, render_intel(products or None, lang), "text/html; charset=utf-8")
        elif path == "/install.ps1":
            f = APP_DIR / "tools" / "install.ps1"
            if f.exists():
                self._send(200, f.read_bytes(), "text/plain; charset=utf-8")
            else:
                self._json(404, {"error": "not found"})
        elif path == "/install.sh":
            f = APP_DIR / "tools" / "install.sh"
            if f.exists():
                self._send(200, f.read_bytes(), "text/x-shellscript; charset=utf-8")
            else:
                self._json(404, {"error": "not found"})
        elif path == "/kit.tar.gz":
            if "kit" not in _kit_cache:
                _kit_cache["kit"] = build_kit()
            self._kit_head()  # ヘッダーはHEADと共通
            self.wfile.write(_kit_cache["kit"])
        elif path in ("/MamoriCheck.zip", "/MamoriBar.zip"):
            f = APP_DIR / ("MamoriCheck.zip" if path == "/MamoriCheck.zip" else "dist/MamoriBar.zip")
            if not f.exists():
                return self._json(404, {"error": "not found"})
            data = f.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", f'attachment; filename="{f.name}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
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
        elif path == "/my":
            self._send(200, render_my(None, ""), "text/html; charset=utf-8")
        elif path == "/account":
            sid = self._sid()
            email = STORE.session_email(sid)
            self._html(200, render_account(email, STORE.csrf(sid)) if email else render_account_login())
        elif path == "/account/verify":
            # メールのリンク先は確認ボタンだけ（メールソフトの自動プレビューでリンクが消費されないように）
            t = parse_qs(urlparse(self.path).query).get("t", [""])[0]
            self._html(200, render_account_verify(t, STORE.peek_login(t)))
        elif path == "/newsletter":
            self._html(200, render_newsletter())
        elif path == "/newsletter/confirm":
            # 確認リンクの着地はボタンだけ（自動プレビューで購読が確定しないように）
            q = parse_qs(urlparse(self.path).query)
            e = accounts.normalize_email(q.get("email", [""])[0]) or ""
            t = q.get("t", [""])[0]
            self._html(200, render_newsletter_confirm(e, t, bool(e) and hmac_eq(t, STORE.nl_token("confirm", e))))
        elif path == "/newsletter/unsub":
            return _newsletter_unsub_get(self)
        elif path == "/post":
            self._send(200, render_post(None, ""), "text/html; charset=utf-8")
        elif path == "/api":
            self._send(200, render_api_doc(), "text/html; charset=utf-8")
        elif path == "/status":
            self._send(200, render_status(), "text/html; charset=utf-8")
        elif path == "/about":
            self._send(200, render_about(), "text/html; charset=utf-8")
        elif path == "/agent":
            self._send(200, render_agent(), "text/html; charset=utf-8")
        else:
            self._json(404, {"error": "not found"})

    def _form(self) -> dict:
        try:
            length = min(int(self.headers.get("Content-Length", 0)), 16_000)
            return {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
        except Exception:  # noqa: BLE001
            return {}

    def _sid(self) -> str:
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "mamori_session":
                return v
        return ""

    def _redirect(self, to: str, cookie: str | None = None):
        self.send_response(303)
        self.send_header("Location", to)
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _html(self, code: int, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _account_post(self, path: str):
        ip = self.client_address[0]
        form = self._form()
        if path == "/account/login":
            email = accounts.normalize_email(form.get("email", ""))
            if not email:
                return self._html(400, render_account_login("メールアドレスの形を確認してください"))
            if not (_rate_ok(f"login-ip:{ip}", 10) and _rate_ok(f"login-mail:{email}", 3)):
                return self._html(429, render_account_login("送信が続いています。1時間ほどおいてからお試しください"))
            token = STORE.create_login(email)
            link = f"{PUBLIC_URL}/account/verify?t={token}"
            sent = accounts.send_mail(email, "【守 Mamori】ログイン用のリンク",
                f"守（Mamori）の鍵の管理画面へのログイン用リンクです。30分以内に開いてください。\n\n{link}\n\n"
                "心当たりがない場合は、このメールを破棄してください（何も起きません）。\n\n"
                "守 Mamori — https://mamori.teai.io")
            if not sent:
                return self._html(503, render_account_login("メールを送れませんでした。時間をおいてもう一度お試しください"))
            return self._html(200, render_account_sent(email))
        if path == "/account/verify":
            email = STORE.consume_login(form.get("t", ""))
            if not email:
                return self._html(400, render_account_login("リンクの期限が切れたか、すでに使われています。もう一度メールアドレスを入れてください"))
            sid = STORE.create_session(email)
            return self._redirect("/account", f"mamori_session={sid}; Path=/; Max-Age={accounts.SESSION_TTL}; {COOKIE_FLAGS}")
        sid = self._sid()
        email = STORE.session_email(sid)
        if not email:
            return self._redirect("/account")
        if not hmac_eq(form.get("csrf", ""), STORE.csrf(sid)):
            return self._html(403, render_account_login("画面を開き直してからもう一度お試しください"))
        if path == "/account/logout":
            STORE.end_session(sid)
            return self._redirect("/account", f"mamori_session=; Path=/; Max-Age=0; {COOKIE_FLAGS}")
        if path == "/account/keys":
            try:
                key, rec = STORE.issue(email, form.get("label", ""))
            except ValueError as e:
                return self._html(400, render_account(email, STORE.csrf(sid), msg=str(e)))
            return self._html(200, render_account(email, STORE.csrf(sid), new_key=key, new_rec=rec))
        if path == "/account/revoke":
            ok = STORE.revoke(email, form.get("id", ""))
            return self._html(200, render_account(email, STORE.csrf(sid),
                                                  msg="キーを止めました。このキーはもう使えません" if ok else "そのキーは見つかりませんでした"))
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        if path.startswith("/newsletter/"):
            if not _rate_ok(f"nl:{self.client_address[0]}", 60):
                return self._json(429, {"error": "rate limit exceeded"})
            if path == "/newsletter/subscribe":
                return _newsletter_subscribe_post(self)
            if path == "/newsletter/confirm":
                return _newsletter_confirm_post(self)
            return self._json(404, {"error": "not found"})
        if path.startswith("/account/"):
            if not _rate_ok(f"acct:{self.client_address[0]}", 60):
                return self._json(429, {"error": "rate limit exceeded"})
            return self._account_post(path)
        if path == "/my":
            form = self._form()
            key = form.get("key", "")
            return self._html(200, render_my(lookup_key(key), key) if lookup_key(key)
                              else render_my(None, ""))
        if path == "/post":
            return self._post_form()
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
        err, saved = self._save_observation(caller, body)
        if err:
            return self._json(400, {"error": err})
        self._json(201, {"ok": True, "tlp": saved["tlp"]})

    def _save_observation(self, caller: dict, body: dict):
        """共通の投稿処理。(エラーメッセージ or None, 保存したbody) を返す。"""
        tlp = str(body.get("tlp", "GREEN")).upper()
        if str(body.get("tlp", "")).upper() == "RED":
            return "TLP:RED must not be shared; do not submit", None
        if tlp not in TLP_ORDER:
            tlp = "GREEN"
        body = anonymize(body)
        body["tlp"] = tlp
        body["org_hash"] = org_hash(caller.get("org", "default"))
        body["received_at"] = round(time.time() / 3600) * 3600  # hour-rounding
        with _file_lock, OBS_FILE.open("a") as f:
            f.write(json.dumps(body, ensure_ascii=False) + "\n")
        return None, body

    def _post_form(self):
        """ブラウザの投稿フォーム（/post）からの送信。"""
        try:
            length = min(int(self.headers.get("Content-Length", 0)), 64_000)
            raw = self.rfile.read(length).decode()
            multi = parse_qs(raw)
            form = {k: v[0] for k, v in multi.items()}
            if "edit" in multi.get("confirm", []):
                form["confirm"] = "edit"
        except Exception:
            self._send(400, render_post(None, "", "送信内容を読めませんでした", False),
                       "text/html; charset=utf-8")
            return
        key = form.get("key", "")
        caller = lookup_key(key)
        if not caller:
            return self._send(403, render_post(None, "", "キーが正しくありません", False),
                              "text/html; charset=utf-8")
        if not _rate_ok(f"post:{org_hash(caller.get('org', 'default'))}", POST_LIMIT):
            return self._send(429, render_post(caller, key, "投稿は1時間に30件までです。しばらく待ってからお試しください", False),
                              "text/html; charset=utf-8")
        if "pattern" not in form or form.get("confirm") == "edit":
            return self._send(200, render_post(caller, key), "text/html; charset=utf-8")
        pattern = (form.get("pattern") or "").strip()
        if not pattern:
            self._send(400, render_post(caller, key, "「内容」を入力してください", False),
                       "text/html; charset=utf-8")
            return
        # 確認ステップ: 匿名化後の姿を見せてから投稿（confirm=1 で確定）
        if form.get("confirm") != "1":
            preview = anonymize({"type": form.get("type", "other"), "pattern": pattern,
                                 "tlp": form.get("tlp", "GREEN")})
            body = f"""<div class="card"><h2>投稿前の確認</h2>
<p class="muted">この内容で共有します。自動匿名化（IP末尾・メール・IPv6・内部ドメインを伏字）を適用したあとの姿です。<strong>自社ドメイン・社内サーバー名・人の名前が残っていないか確認してください。</strong></p>
<div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:1rem;font-family:ui-monospace,monospace;font-size:.9rem;white-space:pre-wrap">{_esc(preview['pattern'])}</div>
<p style="margin:.6rem 0">種別: <code>{_esc(preview['type'])}</code> ／ 共有範囲: <span class="tag {_esc(preview['tlp'])}">{_esc(preview['tlp'])}</span></p>
<form method="post" action="/post">
<input type="hidden" name="key" value="{_esc(key)}">
<input type="hidden" name="type" value="{_esc(form.get('type','other'))}">
<input type="hidden" name="pattern" value="{_esc(pattern)}">
<input type="hidden" name="tlp" value="{_esc(form.get('tlp','GREEN'))}">
<input type="hidden" name="confirm" value="1">
<p style="margin-top:1rem"><button class="btn primary" type="submit">この内容で共有する</button>
<button class="btn ghost" type="submit" name="confirm" value="edit">書き直す</button></p></form></div>"""
            self._send(200, _shell("投稿前の確認 — 守 Mamori", body), "text/html; charset=utf-8")
            return
        body = {"type": form.get("type", "other"), "pattern": pattern,
                "tlp": form.get("tlp", "GREEN"), "via": "web-form"}
        err, saved = self._save_observation(caller, body)
        if err:
            self._send(400, render_post(caller, key, err, False), "text/html; charset=utf-8")
            return
        self._send(200, render_post(caller, key, f"共有しました（TLP:{saved['tlp']}）。ありがとうございます — みんなの防御に使われます。", True),
                   "text/html; charset=utf-8")

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
