#!/usr/bin/env python3
"""tools/install.sh の通し試験（偽の HOME と偽の claude / codex / sente で実行・本物の設定には触れない）。

  python3 tests/test_install.py
"""
from __future__ import annotations

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
FAILS: list[str] = []


def check(cond: bool, msg: str) -> None:
    print(("ok   " if cond else "FAIL ") + msg)
    if not cond:
        FAILS.append(msg)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def shim(bindir: Path, name: str, log: Path) -> None:
    """引数を記録するだけの偽コマンド。`mcp remove` は「登録なし」で失敗を返す。"""
    f = bindir / name
    f.write_text(f'#!/bin/sh\necho "{name} $*" >> "{log}"\n'
                 'case "$*" in *"mcp remove"*) exit 1;; esac\nexit 0\n')
    f.chmod(0o755)


def run_install(env: dict, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(ROOT / "tools" / "install.sh"), *args],
                          env=env, capture_output=True, text=True, timeout=120)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="mamori-install-"))
    data = tmp / "hubdata"
    data.mkdir()
    (data / "latest_bundle.json").write_text(json.dumps({
        "created": "2026-10-24T00:00:00Z",
        "objects": [{"title": "試験用の脅威", "published": "2026-10-24", "url": "https://example.invalid/x"}],
    }), encoding="utf-8")
    port = free_port()
    hub = subprocess.Popen([sys.executable, str(ROOT / "hub" / "server.py")],
                           env={**os.environ, "MAMORI_APP": str(ROOT), "MAMORI_DATA": str(data),
                                "PORT": str(port), "MAMORI_KEYS_JSON": json.dumps({"mk_test_ok": {"org": "t", "tlp_max": "GREEN"}})},
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(base + "/healthz", timeout=1)
                break
            except Exception:
                time.sleep(0.2)
        with urllib.request.urlopen(urllib.request.Request(base + "/install.sh", headers={"X-Mamori-Key": "mk_test_ok"}), timeout=5) as r:
            check(r.status == 200 and b"mamori_mcp.py" in r.read(), "/install.sh を参加者に配信している")
        try:
            urllib.request.urlopen(base + "/install.sh", timeout=5)
            check(False, "/install.sh はキーなしでは配らない")
        except urllib.error.HTTPError as e:
            check(e.code == 401, "/install.sh はキーなしでは配らない（401）")

        home = tmp / "home"
        bindir = tmp / "bin"
        home.mkdir()
        bindir.mkdir()
        log = tmp / "calls.log"
        for n in ("claude", "codex", "sente"):
            shim(bindir, n, log)
        # 既存の Sente 設定（他の MCP・許可）を壊さないことも確かめる
        sdir = home / ".config" / "sente"
        sdir.mkdir(parents=True)
        (sdir / "sente.json").write_text(json.dumps({
            "mcp": {"other": {"type": "local", "command": ["x"]}},
            "permission": {"bash": {"*": "allow"}}}), encoding="utf-8")
        env = {"HOME": str(home), "PATH": f"{bindir}:/usr/bin:/bin:/usr/sbin:/sbin:{os.path.dirname(sys.executable)}",
               "MAMORI_HUB": base, "MAMORI_KEY": "mk_test_ok"}

        r = run_install(env)
        print(r.stdout[-1500:], r.stderr[-800:])
        check(r.returncode == 0, "導入が成功で終わる")
        mcp = home / ".mamori" / "kit" / "mamori" / "mcp" / "mamori_mcp.py"
        check(mcp.exists(), "キットを ~/.mamori/kit に置く")
        calls = log.read_text()
        check(f"claude mcp add -s user mamori --" in calls and str(mcp) in calls, "Claude Code に user スコープで登録")
        check(f"codex mcp add mamori --" in calls, "Codex に登録")
        cfg = json.loads((sdir / "sente.json").read_text())
        check(cfg["mcp"]["mamori"]["command"][-1] == str(mcp), "Sente に登録")
        check("other" in cfg["mcp"] and cfg["permission"]["bash"] == {"*": "allow"}, "Sente の既存設定を残す")
        check(cfg["permission"].get("mamori_mamori_intel_summary") == "allow", "Sente: 読むだけのツールは許可")
        check("mamori_mamori_share" not in cfg["permission"], "Sente: 共有ツールは毎回確認のまま")
        check(list(sdir.glob("sente.json.bak-mamori-*")), "Sente 設定の控えを残す")
        key = home / ".config" / "mamori" / "key"
        check(key.exists() and key.read_text().strip() == "mk_test_ok", "有効なキーを保存")
        check(key.exists() and (key.stat().st_mode & 0o777) == 0o600, "キーの権限は600")
        check("mk_test_ok" not in calls and "mk_test_ok" not in (sdir / "sente.json").read_text(),
              "キーを AI ツールの設定に書かない")
        check("キーは有効" in r.stdout, "自己テストでキーの有効性を確認")
        check((home / ".claude" / "skills" / "mamori" / "SKILL.md").exists(), "Claude Code にスキルを置く")

        bad = run_install({**env, "MAMORI_KEY": "mk_wrong"}, "--only", "codex")
        check(bad.returncode != 0 and "招待制" in bad.stderr and "mk_wrong" not in bad.stdout + bad.stderr,
              "招待制: 無効なキーではキットを取れず止まる（キーを表示しない）")
        nohome = tmp / "nokey-home"
        nohome.mkdir()
        nk = {k: v for k, v in env.items() if k != "MAMORI_KEY"}
        nok = run_install({**nk, "HOME": str(nohome)}, "--only", "codex")
        check(nok.returncode != 0 and "teai.io/contact" in nok.stderr and not (nohome / ".mamori" / "kit").exists(),
              "招待制: キーが無ければ案内を出して何も入れない")
        saved = run_install(nk, "--only", "codex")
        check(saved.returncode == 0, "招待制: 保存済みのキーでキットを更新できる")
        check(key.read_text().strip() == "mk_test_ok", "無効なキーで既存キーを上書きしない")

        # --guard: 偽の sudo（成功）→ 管理者として1回の昇格で fix --auto と install を実行
        glog = tmp / "guard.log"
        gstub = tmp / "guard_stub.py"
        gstub.write_text("import os,sys\nopen(%r,'a').write(('root ' if os.environ.get('FAKE_ROOT') else 'user ')+' '.join(sys.argv[1:])+'\\n')\nprint('stub', ' '.join(sys.argv[1:]))\n" % str(glog))
        (bindir / "sudo").write_text('#!/bin/sh\necho "sudo $*" >> "%s"\n[ -n "$FAKE_SUDO_FAIL" ] && exit 1\nwhile [ "${1#-}" != "$1" ]; do shift; done\nFAKE_ROOT=1 exec "$@"\n' % log)
        (bindir / "sudo").chmod(0o755)
        for n in ("launchctl", "crontab"):
            shim(bindir, n, log)
        la = home / "Library" / "LaunchAgents"
        la.mkdir(parents=True)
        (la / "io.teai.mamori.guard.plist").write_text("old")
        genv = {**env, "MAMORI_GUARD_PY": str(gstub)}
        g = run_install(genv, "--guard", "--only", "codex")
        print(g.stdout[-1200:], g.stderr[-400:])
        gl = glog.read_text()
        check(g.returncode == 0 and "管理者として毎日 9:17" in g.stdout, "--guard: 管理者として登録")
        check("root fix --auto" in gl and "root install --hour 9" in gl, "--guard: 管理者で fix --auto と install を実行")
        check(log.read_text().count("sudo /bin/sh") == 1, "--guard: 昇格は1回だけ")
        check(not (la / "io.teai.mamori.guard.plist").exists(), "--guard: 古いユーザー単位の常駐を外す")
        glog.write_text("")
        g2 = run_install({**genv, "FAKE_SUDO_FAIL": "1"}, "--guard", "--hour", "7", "--only", "codex")
        gl = glog.read_text()
        check(g2.returncode == 0 and "ユーザー単位で登録" in g2.stdout and "user install --hour 7" in gl,
              "--guard: 管理者になれなければユーザー権限で登録")

        un = run_install(env, "--uninstall")
        cfg = json.loads((sdir / "sente.json").read_text())
        check(un.returncode == 0 and "mamori" not in cfg["mcp"] and "other" in cfg["mcp"], "外すと Sente から mamori だけ消える")
        check("mamori_mamori_intel_summary" not in cfg.get("permission", {}), "外すと許可も消える")
        check("claude mcp remove -s user mamori" in log.read_text(), "外すと Claude Code からも外す")
    finally:
        hub.terminate()
    print(f"\n{'NG' if FAILS else 'OK'}: {len(FAILS)} failures")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
