#!/usr/bin/env python3
"""運営用: メールアドレスのアカウントに鍵を発行する（本人はそのメールでログインして管理できる）。

  python3 admin/account_issue.py <email> [鍵の名前]

稼働中のハブ（fly mamori-hub）の中で accounts.Store を使って発行し、
キー本体は ~/.config/mamori/keys/<email>.key（権限600）にだけ保存する。画面には出さない。
"""
import os
import subprocess
import sys
from pathlib import Path

APP = os.environ.get("MAMORI_FLY_APP", "mamori-hub")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    email, label = sys.argv[1].strip().lower(), (sys.argv[2] if len(sys.argv) > 2 else "運営が発行")
    py = ("import sys,os;sys.path.insert(0,'/app');import accounts;"
          "s=accounts.Store(__import__('pathlib').Path('/app/data/accounts.json'),os.environ.get('MAMORI_ORG_SALT',''));"
          f"e=accounts.normalize_email({email!r});assert e,'bad email';"
          f"k,r=s.issue(e,{label!r});print('KEY='+k);print('TLP='+r['tlp_max'])")
    r = subprocess.run(["fly", "ssh", "console", "-a", APP, "-C", f"python3 -c \"{py}\""],
                       capture_output=True, text=True, timeout=180)
    lines = dict(l.split("=", 1) for l in r.stdout.splitlines() if l.startswith(("KEY=", "TLP=")))
    if "KEY" not in lines:
        sys.exit(f"発行できませんでした: {(r.stderr or r.stdout).strip()[-300:]}")
    d = Path.home() / ".config" / "mamori" / "keys"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    f = d / f"{email}.key"
    f.write_text(lines["KEY"].strip() + "\n")
    os.chmod(f, 0o600)
    print(f"発行しました: {email} 閲覧範囲={lines.get('TLP','?').strip()} 保存先={f}（キー本体は表示しません）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
