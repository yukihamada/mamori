#!/usr/bin/env python3
"""Mamori MCP server — stdlib only, speaks MCP over stdio (JSON-RPC 2.0).

Claude Desktop / Claude Code / Sente などのAIエージェントから
Mamori（https://mamori.teai.io）を使うための小さなMCPサーバー。

設定例（claude_desktop_config.json / .mcp.json）:
  {
    "mcpServers": {
      "mamori": {
        "command": "python3",
        "args": ["/path/to/mamori/mcp/mamori_mcp.py"],
        "env": {"MAMORI_KEY": "mk_..."}
      }
    }
  }

かんたん導入（Claude Code / Codex / Sente に自動登録）:
  curl -fsSL https://mamori.teai.io/install.sh | bash

キーは環境変数 MAMORI_KEY か ~/.config/mamori/key（権限600）から読む。
設定ファイル・引数にキーを書かない。公開ツール（mamori_latest / mamori_intel_summary）はキー不要。
動作確認: python3 mamori_mcp.py --selftest
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.error

HUB = os.environ.get("MAMORI_HUB", "https://mamori.teai.io").rstrip("/")
KEY_FILE = os.path.expanduser(os.environ.get("MAMORI_KEY_FILE", "~/.config/mamori/key"))


def _load_key() -> str:
    k = os.environ.get("MAMORI_KEY", "").strip()
    if k:
        return k
    try:
        with open(KEY_FILE, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


KEY = _load_key()
PROTOCOL_VERSION = "2024-11-05"
SUPPORTED_VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18"}
SERVER_INFO = {"name": "mamori", "version": "0.2.0"}

RO = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}

TOOLS = [
    {
        "name": "mamori_latest",
        "annotations": dict(RO, title="mamori_latest"),
        "description": "最新の脅威インテル（CISA KEV・JPCERT/CC。TLP:CLEAR・公開）を取得する。キー不要。",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "mamori_intel_summary",
        "annotations": dict(RO, title="mamori_intel_summary"),
        "description": "直近の脅威インテルの件数・最新公開日・タイトル上位を日本語で要約して返す。キー不要。",
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "description": "列挙する件数（既定5）", "default": 5}},
            "additionalProperties": False,
        },
    },
    {
        "name": "mamori_observations",
        "annotations": dict(RO, title="mamori_observations"),
        "description": "参加者が共有した攻撃の観測を読む（自分のキーのTLP範囲まで）。要 MAMORI_KEY。",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "mamori_share",
        "annotations": {"title": "mamori_share", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True},
        "description": "攻撃の観測をMamoriに共有する。自動匿名化（IP /24・メール除去・時刻丸め）のうえ90日で自動削除。TLP:REDは投稿禁止。要 MAMORI_KEY。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "type": {"type": "string", "description": "種別（例: http_probe, brute_force, payload, scanner, malware, other）"},
                "pattern": {"type": "string", "description": "観測内容（例: /wp-login.php への総当たり）。自社ドメイン・社内名・人名は含めない"},
                "tlp": {"type": "string", "enum": ["CLEAR", "GREEN", "AMBER"], "description": "共有範囲。迷ったら GREEN", "default": "GREEN"},
            },
            "required": ["type", "pattern"],
            "additionalProperties": False,
        },
    },
    {
        "name": "mamori_whoami",
        "annotations": dict(RO, title="mamori_whoami"),
        "description": "MAMORI_KEY の有効性を確認し、組織の記号（org_hash）とTLP範囲を返す。",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]


def _http(method: str, path: str, body: dict | None = None, use_key: bool = False) -> tuple[int, dict]:
    url = HUB + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", "mamori-mcp/0.2.0")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if use_key:
        if not KEY:
            return 0, {"error": "キーが未設定です。https://mamori.teai.io/account で発行し、~/.config/mamori/key に保存するか環境変数 MAMORI_KEY で渡してください（公開の脅威情報はキー不要）"}
        req.add_header("X-Mamori-Key", KEY)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {"error": f"HTTP {e.code}"}
    except Exception as e:
        return 0, {"error": f"{type(e).__name__}: {e}"}


def _text(s: str) -> dict:
    return {"content": [{"type": "text", "text": s}]}


def call_tool(name: str, args: dict) -> dict:
    if name == "mamori_latest":
        code, d = _http("GET", "/api/latest")
        if code != 200:
            return _text(f"取得できませんでした: {d.get('error', code)}")
        return _text(json.dumps(d, ensure_ascii=False, indent=2)[:20000])

    if name == "mamori_intel_summary":
        code, d = _http("GET", "/api/latest")
        if code != 200:
            return _text(f"取得できませんでした: {d.get('error', code)}")
        objs = [o for o in d.get("objects", []) if o.get("title")]
        objs.sort(key=lambda o: o.get("published") or "", reverse=True)
        limit = int(args.get("limit", 5))
        created = (d.get("created") or "")[:16].replace("T", " ")
        lines = [f"脅威インテル: {len(objs)}件（生成 {created} UTC）", ""]
        for o in objs[:limit]:
            due = f" ・対応期限 {o['due_date']}" if o.get("due_date") else ""
            lines.append(f"- [{o.get('published', '—')}] {o.get('title', '')}{due}")
            if o.get("url"):
                lines.append(f"  {o['url']}")
        return _text("\n".join(lines))

    if name == "mamori_observations":
        code, d = _http("GET", "/api/observations", use_key=True)
        if code != 200:
            return _text(f"読めませんでした: {d.get('error', code)}")
        obs = d.get("observations", [])
        if not obs:
            return _text("共有された観測はまだありません。")
        lines = [f"{d.get('count', len(obs))}件の観測（直近）:", ""]
        for o in obs[-20:]:
            import time as _t
            ts = _t.strftime("%Y-%m-%d %H:%M UTC", _t.gmtime(o.get("received_at", 0)))
            lines.append(f"- [{ts}] TLP:{o.get('tlp', '?')} {o.get('type', '—')}: {str(o.get('pattern', ''))[:150]}")
        return _text("\n".join(lines))

    if name == "mamori_share":
        body = {"type": args.get("type", "other"),
                "pattern": args.get("pattern", ""),
                "tlp": args.get("tlp", "GREEN"),
                "via": "mcp"}
        if not body["pattern"]:
            return _text("pattern（観測内容）が必要です。")
        code, d = _http("POST", "/api/observations", body, use_key=True)
        if code not in (200, 201):
            return _text(f"共有できませんでした: {d.get('error', code)}")
        return _text(f"共有しました（TLP:{d.get('tlp', body['tlp'])}）。自動匿名化のうえ90日で自動削除されます。")

    if name == "mamori_whoami":
        code, d = _http("GET", "/api/whoami", use_key=True)
        if code != 200:
            return _text(f"キーを確認できませんでした: {d.get('error', code)}")
        return _text(f"キーは有効です。組織の記号: {d.get('org_hash')} ／ 閲覧範囲: TLP:{d.get('tlp_max')} まで")

    return _text(f"unknown tool: {name}")


def send(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def result(req_id, value):
    send({"jsonrpc": "2.0", "id": req_id, "result": value})


def error(req_id, code: int, message: str):
    send({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})


def selftest() -> int:
    """導入確認: ツール一覧と、キー不要の要約ツールを1回実行する。"""
    print(f"Mamori MCP {SERVER_INFO['version']} / hub {HUB}")
    print("ツール:", ", ".join(t["name"] for t in TOOLS))
    out = call_tool("mamori_intel_summary", {"limit": 3})["content"][0]["text"]
    print(out)
    ok = out.startswith("脅威インテル:")
    if KEY:
        w = call_tool("mamori_whoami", {})["content"][0]["text"]
        print(w)
        ok = ok and w.startswith("キーは有効")
    else:
        print("キー: 未設定（読むだけなら不要。共有するときは https://mamori.teai.io/account で発行）")
    print("OK" if ok else "NG")
    return 0 if ok else 1


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = req.get("method")
        req_id = req.get("id")
        if method == "initialize":
            asked = (req.get("params") or {}).get("protocolVersion")
            result(req_id, {"protocolVersion": asked if asked in SUPPORTED_VERSIONS else PROTOCOL_VERSION,
                            "capabilities": {"tools": {}},
                            "serverInfo": SERVER_INFO})
        elif method == "notifications/initialized":
            pass
        elif method == "tools/list":
            result(req_id, {"tools": TOOLS})
        elif method == "tools/call":
            params = req.get("params", {})
            try:
                result(req_id, call_tool(params.get("name", ""), params.get("arguments", {}) or {}))
            except Exception as e:  # noqa: BLE001
                error(req_id, -32603, f"{type(e).__name__}: {e}")
        elif method == "ping":
            result(req_id, {})
        elif req_id is not None:
            error(req_id, -32601, f"method not found: {method}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
