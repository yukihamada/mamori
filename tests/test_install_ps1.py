#!/usr/bin/env python3
"""tools/install.ps1 の通し試験（Windows 専用・CI の windows-latest で実行）。

偽の HOME と偽の claude / codex / sente（.cmd）を使い、本物の設定には触れない。
利用者と同じ「irm <url>/install.ps1 | iex」で、PowerShell 5.1 と 7 の両方を試す。

  python tests/test_install_ps1.py
"""
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GOOD_KEY = "mk_test_ok"
FAILS: list[str] = []


def check(cond: bool, msg: str) -> None:
    print(("ok   " if cond else "FAIL ") + msg, flush=True)
    if not cond:
        FAILS.append(msg)


def build_kit() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name in ["agent", "tools", "mcp", "examples"]:
            tar.add(ROOT / name, arcname=f"mamori/{name}",
                    filter=lambda ti: None if "__pycache__" in ti.name else ti)
    return buf.getvalue()


KIT = build_kit()
LATEST = json.dumps({"created": "2026-10-24T00:00:00Z", "objects": [
    {"title": "試験用の脅威", "published": "2026-10-24", "url": "https://example.invalid/x"}]}).encode()


class Hub(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/install.ps1":
            self._send(200, (ROOT / "tools" / "install.ps1").read_bytes(), "text/plain; charset=utf-8")
        elif self.path == "/kit.tar.gz":
            self._send(200, KIT, "application/gzip")
        elif self.path == "/api/latest":
            self._send(200, LATEST, "application/json")
        elif self.path == "/api/whoami":
            if self.headers.get("X-Mamori-Key") == GOOD_KEY:
                self._send(200, b'{"ok": true, "org_hash": "test", "tlp_max": "GREEN"}', "application/json")
            else:
                self._send(401, b'{"error": "invalid key"}', "application/json")
        else:
            self._send(404, b"{}", "application/json")


def shim(bindir: Path, name: str, log: Path) -> None:
    (bindir / f"{name}.cmd").write_text(
        "@echo off\r\n"
        f'echo {name} %*>>"{log}"\r\n'
        'echo %* | findstr /C:"mcp remove" >nul && exit /b 1\r\n'
        "exit /b 0\r\n", encoding="ascii")


def run_ps(shell: str, base: str, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                           f"irm {base}/install.ps1 | iex"],
                          env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)


def one_shell(shell: str, base: str) -> None:
    print(f"\n=== {shell} ===", flush=True)
    tmp = Path(tempfile.mkdtemp(prefix="mamori-ps-"))
    home, bindir, log = tmp / "home", tmp / "bin", tmp / "calls.log"
    home.mkdir()
    bindir.mkdir()
    for n in ("claude", "codex", "sente"):
        shim(bindir, n, log)
    sdir = home / ".config" / "sente"
    sdir.mkdir(parents=True)
    (sdir / "sente.json").write_text(json.dumps({"mcp": {"other": {"type": "local", "command": ["x"]}},
                                                 "permission": {"bash": {"*": "allow"}}}), encoding="utf-8")
    env = {**os.environ, "MAMORI_HUB": base, "MAMORI_HOME_DIR": str(home), "USERPROFILE": str(home),
           "PATH": f"{bindir};{os.environ['PATH']}", "MAMORI_KEY": GOOD_KEY}

    r = run_ps(shell, base, env)
    print(r.stdout[-2000:], r.stderr[-1500:], flush=True)
    check(r.returncode == 0 and "準備できました" in r.stdout, f"[{shell}] 導入が最後まで進む")
    mcp = home / ".mamori" / "kit" / "mamori" / "mcp" / "mamori_mcp.py"
    check(mcp.exists(), f"[{shell}] キットを置く")
    calls = log.read_text(errors="replace") if log.exists() else ""
    check("claude mcp add -s user mamori --" in calls and "mamori_mcp.py" in calls, f"[{shell}] Claude Code に登録")
    check("codex mcp add mamori --" in calls, f"[{shell}] Codex に登録")
    cfg = json.loads((sdir / "sente.json").read_text(encoding="utf-8"))
    check(cfg.get("mcp", {}).get("mamori", {}).get("command", [""])[-1] == str(mcp), f"[{shell}] Sente に登録")
    check("other" in cfg["mcp"] and cfg["permission"]["bash"] == {"*": "allow"}, f"[{shell}] Sente の既存設定を残す")
    check(cfg["permission"].get("mamori_mamori_intel_summary") == "allow"
          and "mamori_mamori_share" not in cfg["permission"], f"[{shell}] 読むだけ許可・共有は確認")
    key = home / ".config" / "mamori" / "key"
    check(key.exists() and key.read_text().strip() == GOOD_KEY, f"[{shell}] キーを保存")
    check(GOOD_KEY not in calls and GOOD_KEY not in (sdir / "sente.json").read_text(encoding="utf-8"),
          f"[{shell}] キーを AI 設定に書かない")
    check("脅威情報を取得できました" in r.stdout and "キーは有効" in r.stdout, f"[{shell}] 自己テスト（キー確認含む）")
    # 実際に登録されたコマンドで MCP が動くか（initialize → tools/list）
    cmd = cfg["mcp"]["mamori"]["command"]
    p = subprocess.run(cmd, input='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
                                  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n',
                       capture_output=True, text=True, encoding="utf-8", env={**env, "PYTHONIOENCODING": "utf-8"}, timeout=60)
    check('"mamori_intel_summary"' in p.stdout, f"[{shell}] 登録したコマンドで MCP が応答する")

    bad = run_ps(shell, base, {**env, "MAMORI_KEY": "mk_wrong", "MAMORI_ONLY": "codex"})
    check(bad.returncode == 0 and "保存せずに続けます" in bad.stdout and "準備できました" in bad.stdout,
          f"[{shell}] 無効なキーは保存せず続ける")
    check(key.read_text().strip() == GOOD_KEY, f"[{shell}] 無効なキーで上書きしない")

    un = run_ps(shell, base, {**env, "MAMORI_UNINSTALL": "1"})
    cfg = json.loads((sdir / "sente.json").read_text(encoding="utf-8"))
    check(un.returncode == 0 and "mamori" not in cfg["mcp"] and "other" in cfg["mcp"]
          and "mamori_mamori_intel_summary" not in cfg.get("permission", {}), f"[{shell}] 外すと mamori だけ消える")
    check("claude mcp remove -s user mamori" in log.read_text(errors="replace"), f"[{shell}] 外すと Claude Code からも外す")


def main() -> int:
    for st in (sys.stdout, sys.stderr):
        try:
            st.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if os.name != "nt":
        print("skip: Windows 専用の試験です")
        return 0
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Hub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    shells = [s for s in ("powershell", "pwsh") if shutil.which(s)]
    check(bool(shells), "PowerShell が見つかる")
    for s in shells:
        one_shell(s, base)
    srv.shutdown()
    print(f"\n{'NG' if FAILS else 'OK'}: {len(FAILS)} failures")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
