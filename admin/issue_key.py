#!/usr/bin/env python3
"""Mamori 参加者キーの発行・失効（運営用。キットには含めない）。

  python3 admin/issue_key.py issue <org> [--tlp-max GREEN|AMBER]
  python3 admin/issue_key.py revoke <org>
  python3 admin/issue_key.py list

- 現在のキー表は稼働中マシンの環境変数 MAMORI_KEYS_JSON から読み、
  更新は `fly secrets import`（標準入力渡し）で行う。キーはコマンド引数・ログに出さない。
- 発行したキーは ~/.config/mamori/keys/<org>.key（権限600）にだけ保存する。
- 新規の既定は tlp_max=GREEN。AMBER の閲覧は運営が確認した組織だけに付ける。
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

APP = os.environ.get("MAMORI_FLY_APP", "mamori-hub")
KEY_DIR = Path.home() / ".config" / "mamori" / "keys"


def current_keys() -> dict:
    r = subprocess.run(["fly", "ssh", "console", "-a", APP, "-C", "printenv MAMORI_KEYS_JSON"],
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        sys.exit(f"キー表を読めませんでした: {r.stderr.strip()[-300:]}")
    raw = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "{}"
    return json.loads(raw)


def save_keys(keys: dict) -> None:
    payload = "MAMORI_KEYS_JSON=" + json.dumps(keys, ensure_ascii=False, separators=(",", ":")) + "\n"
    r = subprocess.run(["fly", "secrets", "import", "-a", APP], input=payload, text=True,
                       capture_output=True, timeout=600)
    if r.returncode != 0:
        sys.exit(f"保存に失敗しました: {r.stderr.strip()[-300:]}")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    cmd = sys.argv[1]
    keys = current_keys()
    if cmd == "list":
        for k, v in keys.items():
            print(f"{v.get('org')}\ttlp_max={v.get('tlp_max')}\tkey=…{k[-4:]}")
        return 0
    org = sys.argv[2] if len(sys.argv) > 2 else ""
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,40}", org):
        sys.exit("org は英小文字・数字・ハイフン（2〜41文字）で指定してください")
    if cmd == "issue":
        tlp = "GREEN"
        if "--tlp-max" in sys.argv:
            tlp = sys.argv[sys.argv.index("--tlp-max") + 1].upper()
        if tlp not in ("CLEAR", "GREEN", "AMBER"):
            sys.exit("tlp-max は CLEAR / GREEN / AMBER")
        if any(v.get("org") == org for v in keys.values()):
            sys.exit(f"{org} には既にキーがあります（ローテーションは revoke→issue、または手順書参照）")
        key = "mk_" + secrets.token_hex(24)
        keys[key] = {"org": org, "tlp_max": tlp}
        KEY_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(KEY_DIR, 0o700)
        f = KEY_DIR / f"{org}.key"
        f.write_text(key + "\n")
        os.chmod(f, 0o600)
        save_keys(keys)
        print(f"発行しました: org={org} tlp_max={tlp} 保存先={f}（キー本体は表示しません）")
        return 0
    if cmd == "revoke":
        before = len(keys)
        keys = {k: v for k, v in keys.items() if v.get("org") != org}
        if len(keys) == before:
            sys.exit(f"{org} のキーは見つかりません")
        save_keys(keys)
        print(f"失効しました: org={org}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
