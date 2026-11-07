#!/usr/bin/env python3
"""Mamori v0.5 tests (stdlib only, no network). Run: python3 tests/test_v05.py"""
from __future__ import annotations

import io
import json
import os
import re
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
    (tmp / "latest_bundle.json").write_text(json.dumps({"created": "2026-10-23T00:00:00+00:00", "objects": [
        {"id": "x", "title": "Unrelated router flaw", "published": "2026-10-22", "url": "https://example.com/a"},
        {"id": "y", "title": "PHP remote code execution", "published": "2026-10-21", "url": "https://example.com/b"},
        {"id": "z", "title": "WordPress plugin flaw", "published": "2026-10-20", "url": "https://example.com/c"},
        {"id": "w", "title": "WordPress WordPress Core race condition", "published": "2026-10-19", "url": "https://example.com/d"},
    ]}))
    now = time.time()
    (tmp / "observations.jsonl").write_text("".join(json.dumps(o) + "\n" for o in [
        {"type": "attack-observation", "pattern": "public-clear-obs", "tlp": "CLEAR", "received_at": now},
        {"type": "attack-observation", "pattern": "secret-green-obs", "tlp": "GREEN", "received_at": now},
        {"type": "attack-observation", "pattern": "secret-amber-obs", "tlp": "AMBER", "received_at": now},
        {"type": "attack-observation", "pattern": "old-clear-obs", "tlp": "CLEAR", "received_at": now - 91 * 86400},
    ]))
    port = free_port()
    env = dict(os.environ, MAMORI_ORG_SALT="test-salt", MAMORI_DATA=str(tmp), MAMORI_APP=str(ROOT), PORT=str(port), MAMORI_NO_REFRESH="1",
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
        import hmac
        check("org_hash is salted HMAC (not guessable from name)",
              o["org_hash"] == hmac.new(b"test-salt", b"mamori-org:acme", hashlib.sha256).hexdigest()[:10]
              and o["org_hash"] != hashlib.sha256(b"mamori-org:acme").hexdigest()[:10])
        r = subprocess.run(["bash", str(ROOT / "tools" / "feed.sh")], capture_output=True, text=True,
                           env=dict(os.environ, MAMORI_HUB=base, MAMORI_KEY="k-amber"))
        check("feed.sh lists observations in Japanese", r.returncode == 0 and "共有された観測" in r.stdout and "[黄]" in r.stdout, r.stdout + r.stderr)
        req(base + "/api/observations", key="k-green", data={"type": "attack-observation", "pattern": "own-green", "tlp": "GREEN", "count": 1})
        r = subprocess.run(["bash", str(ROOT / "tools" / "feed.sh")], capture_output=True, text=True,
                           env=dict(os.environ, MAMORI_HUB=base, MAMORI_KEY="k-green"))
        check("feed.sh marks own rows", "（自社）" in r.stdout, r.stdout)
        r = subprocess.run(["bash", str(ROOT / "tools" / "feed.sh")], capture_output=True, text=True,
                           env=dict(os.environ, MAMORI_HUB=base, MAMORI_KEY="wrong-key"))
        check("feed.sh stops on invalid key", r.returncode != 0 and "キーが確認できません" in (r.stdout + r.stderr), r.stdout + r.stderr)
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
        st, _, body = req(base + "/intel")
        txt = body.decode()
        check("intel: bilingual toggle + explanation", st == 200 and 'id="lang-en"' in txt
              and "このページの読み方" in txt and "How to read this page" in txt, txt[:300])
        check("intel: tags carry ja and en", "悪用確認済み" in txt and "Actively exploited" in txt)
        check("intel: server renders lang=ja by default", 'data-lang="ja"' in txt and '<html lang="ja"' in txt)
        st, _, body = req(base + "/intel?lang=en")
        txt_en = body.decode()
        check("intel: ?lang=en sets html lang/data-lang server-side",
              '<html lang="en"' in txt_en and 'data-lang="en"' in txt_en, txt_en[:200])
        check("intel: ?lang=en localizes title and description",
              "<title>Latest threats" in txt_en and "CISA KEV (actively exploited)" in txt_en, txt_en[:400])
        check("intel: product filter form present", 'action="/intel"' in txt and 'name="products"' in txt)
        check("intel: no unreplaced placeholders", "__LANG__" not in txt_en and "__ROWS__" not in txt_en
              and "__EMPTY__" not in txt_en and "__FILTER_NOTE__" not in txt_en
              and "__TITLE__" not in txt_en and "__DESC__" not in txt_en)
        st, _, body = req(base + "/intel?products=php")
        check("intel: filter note bilingual", "選択中の製品" in body.decode() and "Selected products" in body.decode())
        st, _, body = req(base + "/intel", headers={"Accept-Language": "en-US,en;q=0.9"})
        check("intel: Accept-Language en picks en server-side", '<html lang="en"' in body.decode(), body.decode()[:200])
        st, _, body = req(base + "/intel", headers={"Accept-Language": "ja-JP,ja;q=0.9"})
        check("intel: Accept-Language ja keeps ja", '<html lang="ja"' in body.decode())
        st, _, body = req(base + "/intel?products=php")
        t = body.decode()
        first_li = t.find("<li class=") if "<li class=" in t else t.find("<li>")
        check("intel: matched item sorted first",
              first_li != -1 and 'class="match"' in t[first_li:first_li + 60], t[first_li:first_li + 80])
        st, _, body = req(base + "/intel?lang=en")
        check("intel: duplicate product name in title is normalized",
              "WordPress WordPress Core" not in body.decode(), body.decode()[:200])
        st, _, body = req(base + "/intel?lang=en")
        t_en = body.decode()
        legend = t_en[t_en.find('class="legend"'):t_en.find('</div>', t_en.find('class="legend"'))]
        body_tags = set(re.findall(r'<span class="tag (?:red|amber|gray)"><span class="ja">([^<]+)</span>', t_en))
        legend_tags = set(re.findall(r'<span class="tag (?:red|amber|gray)"><span class="ja">([^<]+)</span>', legend))
        check("intel: legend covers every tag used in the list", body_tags <= legend_tags,
              f"missing={body_tags - legend_tags}")
        check("intel: en titles drop trailing 号", "号<" not in t_en and "号</a>" not in t_en)
        st, _, body = req(base + "/")
        check("landing: links to open-source repo", b"github.com/yukihamada/mamori" in body)
    finally:
        proc.terminate()
        probe.unlink(missing_ok=True)


def test_accounts() -> None:
    import http.cookiejar
    tmp = Path(tempfile.mkdtemp())
    outbox = tmp / "outbox.jsonl"
    (tmp / "latest_bundle.json").write_text(json.dumps({"created": "2026-10-23T00:00:00+00:00", "objects": []}))
    port = free_port()
    env = dict(os.environ, MAMORI_ORG_SALT="test-salt", MAMORI_DATA=str(tmp), MAMORI_APP=str(ROOT), PORT=str(port),
               MAMORI_NO_REFRESH="1", MAMORI_MAIL_OUTBOX=str(outbox), MAMORI_PUBLIC_URL=f"http://127.0.0.1:{port}",
               MAMORI_KEYS_JSON="{}")
    proc = subprocess.Popen([sys.executable, str(ROOT / "hub" / "server.py")], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    def session():
        jar = http.cookiejar.CookieJar()
        return jar, urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect)

    def post(op, path, data):
        import urllib.parse
        r = urllib.request.Request(base + path, data=urllib.parse.urlencode(data).encode(), method="POST")
        try:
            resp = op.open(r, timeout=10)
            return resp.status, dict(resp.headers), resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode()

    def login(email):
        jar, op = session()
        st, _, body = post(op, "/account/login", {"email": email})
        assert st == 200, body
        link = json.loads(outbox.read_text().splitlines()[-1])["text"]
        import re as _re
        token = _re.search(r"verify\?t=([A-Za-z0-9_\-]+)", link).group(1)
        st, _, page = req(base + "/account/verify?t=" + token)       # 自動プレビューでは消費されない
        assert "ログインする" in page.decode()
        st, h, _ = post(op, "/account/verify", {"t": token})
        return jar, op, token, st, h

    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(base + "/healthz", timeout=1); break
            except Exception:  # noqa: BLE001
                time.sleep(0.1)
        st, _, body = req(base + "/account")
        check("account: login form", st == 200 and "ログイン用のリンクを送る" in body.decode())
        jar, op, token, st, h = login("Taro@Example.co.jp")
        check("account: verify sets HttpOnly session cookie", st == 303 and "HttpOnly" in h.get("Set-Cookie", ""), str(h))
        check("account: link is single-use", post(session()[1], "/account/verify", {"t": token})[0] == 400)
        page = op.open(base + "/account", timeout=10).read().decode()
        check("account: dashboard shows email", "taro@example.co.jp" in page)
        import re as _re
        csrf = _re.search(r'name="csrf" value="([0-9a-f]+)"', page).group(1)
        st, _, body = post(op, "/account/keys", {"csrf": "bad", "label": "x"})
        check("account: CSRF required", st == 403)
        st, _, body = post(op, "/account/keys", {"csrf": csrf, "label": "本社"})
        m = _re.search(r'id="newkey"[^>]*>(mk_[0-9a-f]{48})<', body)
        check("account: key issued and shown once", st == 200 and m is not None, body[:300])
        key = m.group(1)
        stored = (tmp / "accounts.json").read_text()
        check("account: plaintext key not stored", key not in stored and oct((tmp / "accounts.json").stat().st_mode)[-3:] == "600")
        st, _, w = req(base + "/api/whoami", key=key)
        check("account: company domain key works with GREEN", st == 200 and json.loads(w)["tlp_max"] == "GREEN", w.decode())
        page2 = op.open(base + "/account", timeout=10).read().decode()
        check("account: key not re-shown, last4 listed", key not in page2 and key[-4:] in page2)
        kid = _re.search(r'name="id" value="([0-9a-f]+)"', page2).group(1)
        st, _, _ = post(op, "/account/revoke", {"csrf": csrf, "id": kid})
        st2, _, _ = req(base + "/api/whoami", key=key)
        check("account: revoked key stops working", st == 200 and st2 == 401)
        _, op2, _, _, _ = login("someone@gmail.com")
        page = op2.open(base + "/account", timeout=10).read().decode()
        csrf2 = _re.search(r'name="csrf" value="([0-9a-f]+)"', page).group(1)
        body = post(op2, "/account/keys", {"csrf": csrf2})[2]
        key2 = _re.search(r'id="newkey"[^>]*>(mk_[0-9a-f]{48})<', body).group(1)
        check("account: free-mail key is CLEAR", json.loads(req(base + "/api/whoami", key=key2)[2])["tlp_max"] == "CLEAR")
        st, _, body = req(base + "/my?key=" + key2)
        check("my: key in URL is ignored", "参加者キーを入力" in body.decode())
        st, _, body = post(session()[1], "/my", {"key": key2})
        check("my: POST with key renders", st == 200 and "あなたのキー" in body)
        st, _, body = post(session()[1], "/account/login", {"email": "not-an-email"})
        check("account: invalid email rejected", st == 400)
    finally:
        proc.terminate()


if __name__ == "__main__":
    test_matcher()
    test_inventory_messages()
    test_drafter()
    test_hub()
    test_accounts()
    print(f"\n{len(FAILS)} failed" if FAILS else "\nall passed")
    sys.exit(1 if FAILS else 0)
