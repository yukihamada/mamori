"""Mamori セルフサービスの鍵発行・管理（標準ライブラリのみ）。

- メールアドレスに届くリンクでログイン（パスワードなし）
- 鍵・ログイン用リンク・セッションは、元に戻せないハッシュ（SHA-256）だけを保存する
- 鍵は発行時に1回だけ表示する
- 会社のドメインのメールなら閲覧範囲 GREEN、フリーメールなら CLEAR（運営の確認後に引き上げ）
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import urllib.request
from pathlib import Path

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$")
FREE_MAIL = {
    "gmail.com", "googlemail.com", "yahoo.co.jp", "ymail.ne.jp", "yahoo.com", "icloud.com", "me.com", "mac.com",
    "outlook.com", "outlook.jp", "hotmail.com", "hotmail.co.jp", "live.com", "live.jp", "msn.com", "aol.com",
    "proton.me", "protonmail.com", "gmx.com", "gmx.net", "mail.com", "zoho.com", "yandex.com",
    "docomo.ne.jp", "ezweb.ne.jp", "au.com", "softbank.ne.jp", "i.softbank.jp", "nifty.com", "biglobe.ne.jp",
    "excite.co.jp", "livedoor.com", "infoseek.jp", "goo.jp",
}
LOGIN_TTL = 30 * 60
SESSION_TTL = 30 * 86400
MAX_ACTIVE_KEYS = 5


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def normalize_email(email: str) -> str | None:
    e = (email or "").strip().lower()
    return e if EMAIL_RE.match(e) and ".." not in e else None


def tlp_for_email(email: str) -> str:
    return "CLEAR" if email.rsplit("@", 1)[-1] in FREE_MAIL else "GREEN"


class Store:
    """data/accounts.json を1つのファイルとして扱う。書き込みはファイルロック＋置き換え。"""

    def __init__(self, path: Path, salt: str):
        self.path = path
        self.salt = salt or "mamori-dev-salt"
        self._lock = threading.Lock()
        self._cache: dict | None = None
        self._mtime = -1.0

    # --- 読み書き ---------------------------------------------------------
    def _empty(self) -> dict:
        return {"accounts": {}, "keys": {}, "logins": {}, "sessions": {}}

    def _read(self) -> dict:
        try:
            m = self.path.stat().st_mtime
        except FileNotFoundError:
            return self._empty()
        if self._cache is None or m != self._mtime:
            try:
                self._cache = json.loads(self.path.read_text())
            except Exception:  # noqa: BLE001 — 壊れていても起動は止めない
                self._cache = self._empty()
            self._mtime = m
        return self._cache

    def _update(self, fn):
        """ロックを取って最新を読み、fn(data) で変更して書き戻す。fn の戻り値を返す。"""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lockf = self.path.with_suffix(".lock")
        with self._lock, open(lockf, "a") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                data = json.loads(self.path.read_text()) if self.path.exists() else self._empty()
            except Exception:  # noqa: BLE001
                data = self._empty()
            for k in ("accounts", "keys", "logins", "sessions"):
                data.setdefault(k, {})
            out = fn(data)
            now = time.time()
            data["logins"] = {k: v for k, v in data["logins"].items() if v.get("exp", 0) > now}
            data["sessions"] = {k: v for k, v in data["sessions"].items() if v.get("exp", 0) > now}
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1))
            os.chmod(tmp, 0o600)
            tmp.replace(self.path)
            self._cache, self._mtime = data, self.path.stat().st_mtime
            return out

    # --- 鍵 ---------------------------------------------------------------
    def org_for(self, email: str) -> str:
        return "acct-" + hmac.new(self.salt.encode(), email.encode(), hashlib.sha256).hexdigest()[:12]

    def lookup(self, key: str) -> dict | None:
        if not key or not key.startswith("mk_"):
            return None
        rec = self._read()["keys"].get(_h(key))
        if not rec or rec.get("revoked_at"):
            return None
        return {"org": rec["org"], "tlp_max": rec.get("tlp_max", "CLEAR"), "via": "account"}

    def issue(self, email: str, label: str = "") -> tuple[str, dict]:
        key = "mk_" + secrets.token_hex(24)
        label = re.sub(r"[\x00-\x1f<>]", "", (label or "").strip())[:40] or "既定のキー"

        def fn(d):
            acct = d["accounts"].setdefault(email, {"created": time.time(), "org": self.org_for(email),
                                                    "tlp_max": tlp_for_email(email)})
            active = [k for k in d["keys"].values() if k["email"] == email and not k.get("revoked_at")]
            if len(active) >= MAX_ACTIVE_KEYS:
                raise ValueError(f"有効なキーは{MAX_ACTIVE_KEYS}本までです。使っていないキーを止めてから発行してください")
            rec = {"id": secrets.token_hex(6), "email": email, "org": acct["org"], "tlp_max": acct["tlp_max"],
                   "label": label, "last4": key[-4:], "created": time.time()}
            d["keys"][_h(key)] = rec
            return rec
        return key, self._update(fn)

    def keys_for(self, email: str) -> list[dict]:
        return sorted([k for k in self._read()["keys"].values() if k["email"] == email],
                      key=lambda k: k["created"], reverse=True)

    def account(self, email: str) -> dict | None:
        return self._read()["accounts"].get(email)

    def revoke(self, email: str, key_id: str) -> bool:
        def fn(d):
            for rec in d["keys"].values():
                if rec["email"] == email and rec["id"] == key_id and not rec.get("revoked_at"):
                    rec["revoked_at"] = time.time()
                    return True
            return False
        return self._update(fn)

    def active_orgs(self) -> set[str]:
        return {k["org"] for k in self._read()["keys"].values() if not k.get("revoked_at")}

    # --- ログイン用リンク・セッション ----------------------------------------
    def create_login(self, email: str) -> str:
        token = secrets.token_urlsafe(32)
        self._update(lambda d: d["logins"].__setitem__(_h(token), {"email": email, "exp": time.time() + LOGIN_TTL}))
        return token

    def peek_login(self, token: str) -> str | None:
        rec = self._read()["logins"].get(_h(token or ""))
        return rec["email"] if rec and rec["exp"] > time.time() else None

    def consume_login(self, token: str) -> str | None:
        def fn(d):
            rec = d["logins"].pop(_h(token or ""), None)
            if not rec or rec["exp"] <= time.time():
                return None
            d["accounts"].setdefault(rec["email"], {"created": time.time(), "org": self.org_for(rec["email"]),
                                                    "tlp_max": tlp_for_email(rec["email"])})
            return rec["email"]
        return self._update(fn)

    def create_session(self, email: str) -> str:
        sid = secrets.token_urlsafe(32)
        self._update(lambda d: d["sessions"].__setitem__(_h(sid), {"email": email, "exp": time.time() + SESSION_TTL}))
        return sid

    def session_email(self, sid: str) -> str | None:
        rec = self._read()["sessions"].get(_h(sid or ""))
        return rec["email"] if rec and rec["exp"] > time.time() else None

    def end_session(self, sid: str) -> None:
        self._update(lambda d: d["sessions"].pop(_h(sid or ""), None))

    def csrf(self, sid: str) -> str:
        return hmac.new(self.salt.encode(), ("csrf:" + (sid or "")).encode(), hashlib.sha256).hexdigest()[:32]


# --- メール ----------------------------------------------------------------
def send_mail(to: str, subject: str, text: str) -> bool:
    """Resend で送る。MAMORI_MAIL_OUTBOX があれば送らずにファイルへ書く（テスト用）。"""
    outbox = os.environ.get("MAMORI_MAIL_OUTBOX")
    if outbox:
        with open(outbox, "a") as f:
            f.write(json.dumps({"to": to, "subject": subject, "text": text}, ensure_ascii=False) + "\n")
        return True
    api_key = os.environ.get("RESEND_API_KEY", "")
    if not api_key:
        print("mail: RESEND_API_KEY is not set", flush=True)
        return False
    html = "".join(f"<p>{p}</p>" for p in
                   (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    .replace("\n", "<br>")).split("<br><br>"))
    body = json.dumps({"from": os.environ.get("MAMORI_MAIL_FROM", "守 Mamori <noreply@teai.io>"),
                       "to": [to], "subject": subject, "text": text, "html": html}).encode()
    req = urllib.request.Request("https://api.resend.com/emails", data=body, method="POST",
                                 headers={"Authorization": "Bearer " + api_key, "Content-Type": "application/json",
                                          "User-Agent": "mamori-hub/0.6"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return 200 <= r.status < 300
    except Exception as e:  # noqa: BLE001 — 送信失敗は利用者に「届かなければ再送」と案内する
        print(f"mail: send failed: {type(e).__name__}", flush=True)
        return False
