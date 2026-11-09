#!/usr/bin/env python3
"""招待制（2026-11-10〜）の門の試験。標準ライブラリだけ・ネットワーク不要。

  キーなし → 401（"/" だけは200）で招待制の案内・中身（キット・動画・脅威情報）は出さない
  有効なキー（ヘッダー / ?k= / 短期クッキー）→ 200
  失効したキー（運営発行から外した・セルフサービスで停止した）→ 401

Run: python3 tests/test_invite.py
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "hub"))
import accounts  # noqa: E402

FAILS: list[str] = []
GOOD, LATER_REVOKED = "mk_" + "a" * 48, "mk_" + "b" * 48

# 中身を出す（＝守り方・道具・観測が分かる）ルート
GATED = ["/kit.tar.gz", "/install.sh", "/install.ps1", "/start", "/intel", "/docs/keys",
         "/media/zz-invite-test.mp4", "/api/latest", "/api/stix", "/api/stats", "/api/observations",
         "/api/refresh-status", "/api/sample-report", "/api", "/about", "/agent", "/status", "/my",
         "/post", "/newsletter", "/MamoriBar.zip"]
PUBLIC = ["/healthz", "/terms", "/robots.txt", "/account"]


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  ({detail[:300]})"))
    if not cond:
        FAILS.append(name)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def req(url, key=None, method="GET", data=None, headers=None, opener=None):
    h = dict(headers or {})
    if key:
        h["X-Mamori-Key"] = key
    r = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with (opener or urllib.request.build_opener(NoRedirect)).open(r, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start(tmp: Path, keys: dict) -> tuple[subprocess.Popen, str]:
    port = free_port()
    env = dict(os.environ, MAMORI_ORG_SALT="test-salt", MAMORI_DATA=str(tmp), MAMORI_APP=str(ROOT),
               PORT=str(port), MAMORI_NO_REFRESH="1", MAMORI_KEYS_JSON=json.dumps(keys),
               MAMORI_MAIL_OUTBOX=str(tmp / "outbox.jsonl"), MAMORI_PUBLIC_URL=f"http://127.0.0.1:{port}")
    env.pop("MAMORI_INVITE_ONLY", None)  # 既定（招待制オン）で試す
    proc = subprocess.Popen([sys.executable, str(ROOT / "hub" / "server.py")], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    for _ in range(80):
        try:
            urllib.request.urlopen(base + "/healthz", timeout=1)
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
    return proc, base


def main() -> int:
    tmp = Path(tempfile.mkdtemp())
    (tmp / "latest_bundle.json").write_text(json.dumps({"created": "2026-11-09T00:00:00+00:00", "objects": [
        {"id": "x", "type": "advisory", "title": "SECRET-INTEL-MARKER", "published": "2026-11-08"}]}))
    (tmp / "stix_bundle.json").write_text('{"type":"bundle","objects":[]}')
    (tmp / "observations.jsonl").write_text(json.dumps(
        {"type": "attack-observation", "pattern": "CLEAR-OBS-MARKER", "tlp": "CLEAR", "received_at": time.time()}) + "\n")
    media = ROOT / "media"
    media.mkdir(exist_ok=True)
    probe = media / "zz-invite-test.mp4"
    probe.write_bytes(b"\0" * 1024)
    # セルフサービスの鍵（あとで停止する）
    store = accounts.Store(tmp / "accounts.json", "test-salt")
    self_key, self_rec = store.issue("member@example.co.jp", "試験")

    keys = {GOOD: {"org": "member", "tlp_max": "GREEN"}, LATER_REVOKED: {"org": "gone", "tlp_max": "GREEN"}}
    proc, base = start(tmp, keys)
    try:
        # --- キーなし ---------------------------------------------------------
        st, h, body = req(base + "/")
        check("/: キーなしは招待制の案内（200）", st == 200 and "招待制になりました" in body.decode()
              and "teai.io/contact" in body.decode() and "kit.tar.gz" not in body.decode(), body[:300].decode("utf-8", "replace"))
        for p in GATED:
            st, h, body = req(base + p)
            text = body.decode("utf-8", "replace")
            leaked = any(m in text for m in ("SECRET-INTEL-MARKER", "CLEAR-OBS-MARKER", "#!/", "mamori_mcp"))
            check(f"{p}: キーなしは401", st == 401, f"HTTP {st}")
            check(f"{p}: 中身を出さず案内だけ", not leaked and "招待制" in text and h.get("Content-Type", "") not in
                  ("application/gzip", "application/zip", "video/mp4"), text[:160])
        st, _, _ = req(base + "/kit.tar.gz", method="HEAD")
        check("HEAD /kit.tar.gz: キーなしは401", st == 401, f"HTTP {st}")
        st, h, body = req(base + "/api/latest")
        check("/api/*: キーなしは JSON で invite_only", st == 401 and json.loads(body).get("error") == "invite_only", body[:200])
        for p in PUBLIC:
            st, _, _ = req(base + p)
            check(f"{p}: 公開のまま（200）", st == 200, f"HTTP {st}")
        st, _, body = req(base + "/healthz")
        check("/healthz: 版を返す（デプロイ確認用）", json.loads(body).get("version") == "0.5", body[:100])
        st, _, _ = req(base + "/kit.tar.gz", key="mk_wrong")
        check("間違ったキーは401", st == 401, f"HTTP {st}")
        st, _, _ = req(base + "/kit.tar.gz", headers={"Cookie": "mamori_m=9999999999.abc.def"})
        check("偽のクッキーは401", st == 401, f"HTTP {st}")

        # --- 有効なキー --------------------------------------------------------
        for p in ["/kit.tar.gz", "/start", "/intel", "/docs/keys", "/media/zz-invite-test.mp4", "/api/latest",
                  "/api/stix", "/api/refresh-status", "/install.sh", "/"]:
            st, h, body = req(base + p, key=GOOD)
            check(f"{p}: 有効なキー（ヘッダー）で200", st == 200, f"HTTP {st} {body[:120]!r}")
        st, h, body = req(base + "/kit.tar.gz", key=GOOD)
        check("キット: 有効なキーで tar.gz が届く", h.get("Content-Type") == "application/gzip" and body[:2] == b"\x1f\x8b")
        st, _, _ = req(base + "/kit.tar.gz", key=self_key)
        check("セルフサービスの鍵でも200", st == 200, f"HTTP {st}")

        # ブラウザ: ?k= → クッキーに置き換えてキーをURLから消す
        st, h, _ = req(base + f"/intel?lang=en&k={GOOD}")
        loc, cookie = h.get("Location", ""), h.get("Set-Cookie", "")
        check("?k=: 303でキーを消したURLへ", st == 303 and loc == "/intel?lang=en", f"{st} {loc}")
        check("?k=: 短期クッキー（HttpOnly・12時間・キー本体を含まない）",
              cookie.startswith("mamori_m=") and "HttpOnly" in cookie and "Max-Age=43200" in cookie and GOOD not in cookie, cookie)
        tok = cookie.split(";")[0]
        st, _, body = req(base + "/intel", headers={"Cookie": tok})
        check("クッキーで /intel が見られる", st == 200 and "SECRET-INTEL-MARKER" in body.decode(), f"HTTP {st}")
        st, _, _ = req(base + "/media/zz-invite-test.mp4", headers={"Cookie": tok, "Range": "bytes=0-9"})
        check("クッキーで動画（Range）が見られる", st == 206, f"HTTP {st}")
        st, _, _ = req(base + f"/intel?k=mk_wrong")
        check("?k= の間違ったキーは401", st == 401, f"HTTP {st}")
        # フォーム /enter
        st, h, _ = req(base + "/enter", method="POST", data=f"key={GOOD}&next=/start".encode(),
                       headers={"Content-Type": "application/x-www-form-urlencoded"})
        check("/enter: 正しいキーでクッキー＋元のページへ", st == 303 and h.get("Location") == "/start"
              and "mamori_m=" in h.get("Set-Cookie", ""), f"{st} {h.get('Location')}")
        st, h, _ = req(base + "/enter", method="POST", data=f"key={GOOD}&next=//evil.example".encode(),
                       headers={"Content-Type": "application/x-www-form-urlencoded"})
        check("/enter: 外部へのリダイレクトはしない", st == 303 and h.get("Location") == "/", h.get("Location", ""))
        st, h, _ = req(base + "/enter", method="POST", data=b"key=mk_wrong",
                       headers={"Content-Type": "application/x-www-form-urlencoded"})
        check("/enter: 間違ったキーは401・クッキーなし", st == 401 and "Set-Cookie" not in h, f"HTTP {st}")
        # API のクッキー認証は投稿に使わない（CSRF対策）
        st, _, _ = req(base + "/api/observations", method="POST", data=b'{"type":"x","pattern":"p"}',
                       headers={"Cookie": tok, "Content-Type": "application/json"})
        check("観測の投稿はクッキーでは不可（ヘッダーのキー必須）", st == 403, f"HTTP {st}")

        # 新規登録・メルマガ新規は受け付けない
        outbox = tmp / "outbox.jsonl"
        st, _, _ = req(base + "/account/login", method="POST", data=b"email=stranger@example.com",
                       headers={"Content-Type": "application/x-www-form-urlencoded"})
        check("新規メールにはログインリンクを送らない", st == 200 and not (outbox.exists() and "stranger" in outbox.read_text()))
        st, _, _ = req(base + "/account/login", method="POST", data=b"email=member@example.co.jp",
                       headers={"Content-Type": "application/x-www-form-urlencoded"})
        check("招待済みのメールにはログインリンクを送る", st == 200 and outbox.exists() and "member@example.co.jp" in outbox.read_text())
        st, _, _ = req(base + "/newsletter/subscribe", method="POST", data=b"email=x@example.com",
                       headers={"Content-Type": "application/x-www-form-urlencoded"})
        check("メルマガの新規購読は止める", st == 403, f"HTTP {st}")

        # --- 失効 ---------------------------------------------------------------
        store.revoke("member@example.co.jp", self_rec["id"])
        st, _, _ = req(base + "/kit.tar.gz", key=self_key)
        check("停止したセルフサービスの鍵は401", st == 401, f"HTTP {st}")
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    # 運営発行の鍵を外して再起動（admin/issue_key.py revoke と同じ）→ 鍵もクッキーも401
    proc, base = start(tmp, {GOOD: keys[GOOD]})
    try:
        st, _, _ = req(base + "/kit.tar.gz", key=LATER_REVOKED)
        check("失効した運営発行キーは401", st == 401, f"HTTP {st}")
        st, _, _ = req(base + "/kit.tar.gz", key=GOOD)
        check("残っているキーは200のまま", st == 200, f"HTTP {st}")
        os.environ.setdefault("MAMORI_ORG_SALT", "test-salt")
        st, h, _ = req(base + f"/start?k={LATER_REVOKED}")
        check("失効したキーの ?k= ではクッキーを出さない", st == 401 and "Set-Cookie" not in h, f"HTTP {st}")
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        probe.unlink(missing_ok=True)

    # 失効したキーで作られていたクッキーも通らない
    sys.path.insert(0, str(ROOT / "hub"))
    proc, base = start(tmp, {LATER_REVOKED: {"org": "gone", "tlp_max": "GREEN"}})
    try:
        st, h, _ = req(base + f"/start?k={LATER_REVOKED}")
        old_cookie = h.get("Set-Cookie", "").split(";")[0]
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    proc, base = start(tmp, {GOOD: keys[GOOD]})
    try:
        probe.write_bytes(b"\0" * 1024)
        st, _, _ = req(base + "/media/zz-invite-test.mp4", headers={"Cookie": old_cookie})
        check("失効したキーのクッキーは401", bool(old_cookie) and st == 401, f"HTTP {st} cookie={bool(old_cookie)}")
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        probe.unlink(missing_ok=True)

    print(f"\n{'NG' if FAILS else 'OK'}: {len(FAILS)} failures")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
