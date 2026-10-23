#!/usr/bin/env python3
"""Mamori v0.5 tests (stdlib only, no network). Run: python3 tests/test_v05.py"""
from __future__ import annotations

import io
import json
import os
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAILS: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("ok   " if cond else "FAIL ") + name + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILS.append(name)


def req(url, key=None, data=None, headers=None):
    h = dict(headers or {})
    if key:
        h["X-Mamori-Key"] = key
    if data is not None:
        h["Content-Type"] = "application/json"
        data = json.dumps(data).encode()
    r = urllib.request.Request(url, data=data, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_matcher() -> None:
    sys.path.insert(0, str(ROOT / "agent"))
    import match_inventory as mi
    watch = [{"name": "openssh", "keywords": ["ssh"]}, {"name": "php", "keywords": ["php"]}]
    a = mi.classify({"title": "Cisco SSH Server flaw", "severity": "exploited-in-the-wild"}, watch)
    check("matcher: short keyword hits on word", a["match"]["hits"] == ["openssh"] and a["match"]["status"] == "relevant")
    b = mi.classify({"title": "phpMyAdmin sshd-config parser", "severity": "info"}, watch)
    check("matcher: short keyword ignores substrings", b["match"]["hits"] == [], str(b["match"]))
    d = mi.classify({"title": "Fortinet FortiOS path traversal", "severity": "exploited-in-the-wild"},
                    [{"name": "Fortinet"}])
    check("matcher: name-only entry works", d["match"]["hits"] == ["Fortinet"], str(d["match"]))
    c = mi.classify({"title": "PHPにおける複数の脆弱性に関する注意喚起", "severity": "alert"}, watch)
    check("matcher: JPCERT alert with hit is relevant", c["match"]["status"] == "relevant", str(c["match"]))


def test_inventory_messages() -> None:
    tmp = Path(tempfile.mkdtemp())
    raw = tmp / "raw.json"
    raw.write_text(json.dumps({"fetched_at": "2026-10-23T00:00:00+00:00", "items": [
        {"id": "x", "title": "WordPress plugin flaw", "severity": "info"}]}))
    bad = tmp / "bad.json"
    bad.write_text('{"watch": [\n {"name": "WordPress"}\n {"name": "PHP"}\n]}')
    r = subprocess.run([sys.executable, str(ROOT / "agent" / "match_inventory.py"), str(raw), str(bad)],
                       capture_output=True, text=True)
    check("inventory: JSON error in Japanese with line", r.returncode == 2 and "3 行目" in r.stderr and "Traceback" not in r.stderr, r.stderr)
    kana = tmp / "kana.json"
    kana.write_text(json.dumps({"watch": [{"name": "ワードプレス"}, {"name": "WordPress 6.4"}]}, ensure_ascii=False))
    r = subprocess.run([sys.executable, str(ROOT / "agent" / "match_inventory.py"), str(raw), str(kana)],
                       capture_output=True, text=True)
    curly = tmp / "curly.json"
    curly.write_text('{\u201cwatch\u201d: [{\u201cname\u201d: \u201cWordPress\u201d}]}')
    r2 = subprocess.run([sys.executable, str(ROOT / "agent" / "match_inventory.py"), str(raw), str(curly)],
                        capture_output=True, text=True)
    check("inventory: curly quotes accepted", r2.returncode == 0 and json.loads(r2.stdout)["summary"]["maybe"] == 1, r2.stderr)
    check("inventory: warns katakana and versioned names", r.returncode == 0 and r.stderr.count("一致しにくい") == 2, r.stderr)


def test_drafter() -> None:
    sys.path.insert(0, str(ROOT / "agent"))
    import draft_actions as da
    item = {"id": "jpcert-at260033", "title": "PHP 注意喚起", "severity": "alert", "published": "2026-10-22",
            "cves": ["CVE-2026-109618"], "url": "https://www.jpcert.or.jp/at/2026/at260033.html",
            "source": "jpcert_alert", "match": {"status": "relevant", "hits": ["php"]}}
    acts = da.draft_actions(item)
    check("drafter: alert line", any("[注意喚起]" in a and "CVE-2026-109618" in a for a in acts))
    md = da.render_report({"fetched_at": "2026-10-23T00:00:00+00:00", "items": [item],
                           "summary": {"total": 1, "relevant": 1, "maybe": 0}})
    md0 = da.render_report({"fetched_at": "2026-10-23T00:00:00+00:00", "items": [],
                            "summary": {"total": 0, "relevant": 0, "maybe": 0}})
    check("drafter: zero-hit caution", "0件は「安全」という意味ではありません" in md0)
    check("drafter: JST header + fresh section", "09:00 JST" in md and "直近7日の新着" in md, md[:200])


def test_hub() -> None:
    tmp = Path(tempfile.mkdtemp())
    media = ROOT / "media"
    media.mkdir(exist_ok=True)
    probe = media / "zz-test.mp4"
    probe.write_bytes(bytes(range(256)) * 40)
    (tmp / "latest_bundle.json").write_text(json.dumps({"created": "2026-10-23T00:00:00+00:00", "objects": [{"id": "x"}]}))
    now = time.time()
    (tmp / "observations.jsonl").write_text("".join(json.dumps(o) + "\n" for o in [
        {"type": "attack-observation", "pattern": "public-clear-obs", "tlp": "CLEAR", "received_at": now},
        {"type": "attack-observation", "pattern": "secret-green-obs", "tlp": "GREEN", "received_at": now},
        {"type": "attack-observation", "pattern": "secret-amber-obs", "tlp": "AMBER", "received_at": now},
        {"type": "attack-observation", "pattern": "old-clear-obs", "tlp": "CLEAR", "received_at": now - 91 * 86400},
    ]))
    port = free_port()
    env = dict(os.environ, MAMORI_DATA=str(tmp), MAMORI_APP=str(ROOT), PORT=str(port), MAMORI_NO_REFRESH="1",
               MAMORI_KEYS_JSON=json.dumps({"k-green": {"org": "acme", "tlp_max": "GREEN"},
                                            "k-amber": {"org": "vetted", "tlp_max": "AMBER"}}))
    proc = subprocess.Popen([sys.executable, str(ROOT / "hub" / "server.py")], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(base + "/healthz", timeout=1)
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.1)
        st, _, body = req(base + "/api/stats")
        s = json.loads(body)
        check("stats: version 0.5 and org count", st == 200 and s["version"] == "0.5" and s["participants"] == 2, str(s))
        st, _, body = req(base + "/api/stix")
        txt = body.decode()
        check("stix: only CLEAR and in-retention observations", st == 200 and "public-clear-obs" in txt
              and "secret-green-obs" not in txt and "secret-amber-obs" not in txt and "old-clear-obs" not in txt, txt[:300])
        check("retention: old lines physically removed", "old-clear-obs" not in (tmp / "observations.jsonl").read_text())
        st, _, _ = req(base + "/api/whoami")
        check("whoami: no key -> 401", st == 401)
        st, _, body = req(base + "/api/whoami", key="k-green")
        w = json.loads(body)
        check("whoami: valid key", st == 200 and w["ok"] and w["tlp_max"] == "GREEN" and "k-green" not in body.decode())
        st, _, body = req(base + "/api/observations", key="k-green",
                          data={"type": "attack-observation", "pattern": "brute force 203.0.113.55 a@b.co", "tlp": "AMBER", "count": 3})
        check("post: amber accepted", st == 201, body.decode())
        st, _, body = req(base + "/api/observations", key="k-green",
                          data={"type": "attack-observation", "pattern": "x", "tlp": "RED"})
        check("post: RED rejected", st == 400)
        st, _, body = req(base + "/api/observations", key="k-green")
        seen = [o["pattern"] for o in json.loads(body)["observations"]]
        check("read: GREEN key cannot see AMBER", not any("amber" in x or "brute force" in x for x in seen), str(seen))
        st, _, body = req(base + "/api/observations", key="k-amber")
        o = [x for x in json.loads(body)["observations"] if "brute force" in x["pattern"]][0]
        check("anonymize: ip /24 + email masked", "203.0.113.0/24" in o["pattern"] and "a@b.co" not in o["pattern"], o["pattern"])
        import hashlib
        check("org_hash stable sha256", o["org_hash"] == hashlib.sha256(b"mamori-org:acme").hexdigest()[:10])
        r = subprocess.run(["bash", str(ROOT / "tools" / "feed.sh")], capture_output=True, text=True,
                           env=dict(os.environ, MAMORI_HUB=base, MAMORI_KEY="k-amber"))
        check("feed.sh lists observations in Japanese", r.returncode == 0 and "共有された観測" in r.stdout and "[黄]" in r.stdout, r.stdout + r.stderr)
        st, h, body = req(base + "/media/zz-test.mp4", headers={"Range": "bytes=10-19"})
        check("media: range 206", st == 206 and body == (bytes(range(256)) * 40)[10:20] and h.get("Content-Range") == "bytes 10-19/10240", str((st, h.get("Content-Range"))))
        st, _, _ = req(base + "/media/../server.py")
        check("media: no traversal", st == 404)
        st, _, body = req(base + "/kit.tar.gz")
        names = tarfile.open(fileobj=io.BytesIO(body)).getnames()
        check("kit: contains run.sh, tools, example", all(n in names for n in ["mamori/run.sh", "mamori/tools/share.sh", "mamori/tools/feed.sh", "mamori/examples/inventory.example.json"]), str(names[:10]))
        check("kit: excludes admin tool", not any("admin" in n for n in names))
        for path in ("/", "/start", "/terms", "/docs/keys"):
            st, _, body = req(base + path)
            check(f"page {path} 200", st == 200)
        st, _, body = req(base + "/")
        check("landing: no github link", b"github.com" not in body)
    finally:
        proc.terminate()
        probe.unlink(missing_ok=True)


if __name__ == "__main__":
    test_matcher()
    test_inventory_messages()
    test_drafter()
    test_hub()
    print(f"\n{len(FAILS)} failed" if FAILS else "\nall passed")
    sys.exit(1 if FAILS else 0)
