#!/usr/bin/env python3
"""Mamori — asset inventory builder.

自社の実資産を自動収集して Mamori の監視リスト（watch）を生成する。
収集源:
  1. このMac: /Applications, brew leaves, 稼働中の主要プロセス
  2. Fly.io: `fly apps list` の deployed アプリ（本番公開面）
  3. 既知の自社スタック（手動 curated リスト）

出力: inventory JSON（match_inventory.py の --inventory 形式）
"""
from __future__ import annotations

import json
import plistlib
import subprocess
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "inventory.json"

# 既知の自社スタック（リポジトリ・デプロイ構成から curated。変わったら手で更新）
CURATED_STACK = [
    {"name": "cloudflare", "keywords": ["cloudflare"]},
    {"name": "fly.io", "keywords": ["fly.io", "flyio"]},
    {"name": "node.js", "keywords": ["node.js", "nodejs", "npm"]},
    {"name": "python", "keywords": ["python", "cpython", "pip "]},
    {"name": "rust", "keywords": ["rustlang", "rust-lang", "cargo crate", "tokio", "axum"]},
    {"name": "swift/ios", "keywords": ["swift", "ios", "macos", "apple"]},
    {"name": "stripe", "keywords": ["stripe"]},
    {"name": "sqlite/turso", "keywords": ["sqlite", "turso", "libsql"]},
    {"name": "docker", "keywords": ["docker", "container"]},
    {"name": "github actions", "keywords": ["github actions", "github"]},
    {"name": "openssh", "keywords": ["openssh", "ssh"]},
    {"name": "openssl", "keywords": ["openssl"]},
    {"name": "chrome", "keywords": ["chrome", "chromium"]},
    {"name": "debian", "keywords": ["debian", "bookworm", "trixie"]},
    {"name": "postgresql", "keywords": ["postgresql", "postgres"]},
    {"name": "redis", "keywords": ["redis"]},
    {"name": "wordpress", "keywords": ["wordpress", "wp-"]},
    # PlexはこのMacでは未インストール（2026-10-23確認）だが、他マシンでの
    # 使用有無が未確認のため監視は継続する。未使用確定なら外す。
    {"name": "plex", "keywords": ["plex media server", "plex"]},
]

# アプリ名 → 監視キーワードの対応表（見つかったアプリだけ追加される）
APP_WATCH = {
    "Google Chrome.app": {"name": "chrome", "keywords": ["chrome", "chromium"]},
    "Docker.app": {"name": "docker", "keywords": ["docker", "container"]},
    "Ollama.app": {"name": "ollama", "keywords": ["ollama", "llama.cpp"]},
    "NordVPN.app": {"name": "nordvpn", "keywords": ["nordvpn"]},
    "Xcode.app": {"name": "xcode", "keywords": ["xcode"]},
    "Blender.app": {"name": "blender", "keywords": ["blender"]},
    "LINE.app": {"name": "line", "keywords": ["line messenger"]},
}

BREW_WATCH = {
    "openssl": {"name": "openssl", "keywords": ["openssl"]},
    "openssl@4": {"name": "openssl", "keywords": ["openssl"]},
    "postgresql@16": {"name": "postgresql", "keywords": ["postgresql", "postgres"]},
    "python@3.11": {"name": "python", "keywords": ["python", "cpython", "pip "]},
    "python@3.12": {"name": "python", "keywords": ["python", "cpython", "pip "]},
    "node": {"name": "node.js", "keywords": ["node.js", "nodejs", "npm"]},
    "ollama": {"name": "ollama", "keywords": ["ollama", "llama.cpp"]},
    "llama.cpp": {"name": "llama.cpp", "keywords": ["llama.cpp"]},
    "ffmpeg": {"name": "ffmpeg", "keywords": ["ffmpeg"]},
    "homebrew-ffmpeg/ffmpeg/ffmpeg": {"name": "ffmpeg", "keywords": ["ffmpeg"]},
    "cloudflared": {"name": "cloudflare", "keywords": ["cloudflare"]},
    "awscli": {"name": "aws", "keywords": ["amazon web services", "aws "]},
    "deno": {"name": "deno", "keywords": ["deno"]},
    "openjdk@17": {"name": "openjdk", "keywords": ["openjdk", "java "]},
    "syncthing": {"name": "syncthing", "keywords": ["syncthing"]},
}


def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


def collect_apps() -> list[dict]:
    found = []
    for d in ("/Applications", str(Path.home() / "Applications")):
        p = Path(d)
        if not p.exists():
            continue
        for app in p.iterdir():
            w = APP_WATCH.get(app.name)
            if w:
                found.append(w)
    return found


def collect_brew() -> list[dict]:
    out = _run(["brew", "leaves"], timeout=60)
    found = []
    for line in out.splitlines():
        w = BREW_WATCH.get(line.strip())
        if w:
            found.append(w)
    return found


def collect_fly_apps() -> list[str]:
    out = _run(["fly", "apps", "list"], timeout=60)
    apps = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == "deployed":
            apps.append(parts[0])
    return apps


def main() -> int:
    watch = list(CURATED_STACK)
    watch += collect_apps()
    watch += collect_brew()

    # 名前で重複除去
    seen = set()
    uniq = []
    for w in watch:
        if w["name"] in seen:
            continue
        seen.add(w["name"])
        uniq.append(w)

    fly_apps = collect_fly_apps()
    inv = {
        "_generated_by": "agent/asset_inventory.py",
        "_note": "CURATED_STACK は手動管理。アプリ/brew は自動収集。fly_apps は参考情報。",
        "watch": uniq,
        "fly_deployed_apps": fly_apps,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    json.dump(inv, open(OUT, "w"), ensure_ascii=False, indent=2)
    print(f"watch {len(uniq)}件 / fly deployed {len(fly_apps)}件 -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
