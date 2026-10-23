#!/usr/bin/env python3
"""Fly.io のログを巡回し、攻撃パターンを検出して Mamori に共有する。

  使い方:
    MAMORI_KEY=<組織専用キー> python3 tools/fly-watch.py [--apps app1,app2] [--since 24h] [--dry-run]

  - fly logs --no-tail を対象アプリごとに取得し、既知の攻撃パターンに一致する行を抽出
  - パターンごとに集約し、TLP:CLEAR で Mamori に共有（--dry-run で投稿せず表示のみ）
  - 既投稿と重複しないよう、直近の共有内容を /api/observations から読んでスキップ
  - 自社アプリ名・ドメインは共有しない（パターンの一般形だけを送る）

  定期実行の例（cron）:
    0 */6 * * * MAMORI_KEY=mk_... /usr/bin/python3 ~/workspace/mamori/tools/fly-watch.py >> ~/.config/mamori/fly-watch.log 2>&1
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request

HUB = os.environ.get("MAMORI_HUB", "https://mamori.teai.io")

# 検出ルール: (種別, 一般化したパターン説明, 行に対する正規表現)
RULES: list[tuple[str, str, str]] = [
    ("http_probe", "phpinfo探索: /info.php, /phpinfo 等へのGET", r'/(?:info\.php|phpinfo)'),
    ("payload", "React Server Components脆弱性の悪用試行(rsc_exploit_attempt)", r"rsc_exploit_attempt"),
    ("http_probe", "難読化PHPバックアップファイル探索（.bak/.bakup/.old付き.php）", r'\.php(?:%2e|\.)?(?:bak|bakup|old|swp|save)'),
    ("http_probe", "WordPress探索: /wp-login.php, /wp-admin, xmlrpc.php へのGET", r"/(?:wp-login\.php|wp-admin|xmlrpc\.php)"),
    ("http_probe", "設定・秘密ファイル探索: /.env, /.git, /.aws へのGET", r"/\.(?:env|git|aws|ssh)"),
    ("http_probe", "管理画面探索: /phpmyadmin, /admin/config, /actuator, /solr へのGET", r"/(?:phpmyadmin|admin/config|actuator|solr|hudson|cgi-bin)"),
    ("payload", "パストラバーサル試行（../を含むリクエスト）", r"\.\./"),
    ("payload", "コマンドインジェクション試行（/etc/passwd等）", r"/etc/passwd|union%20select|union\+select"),
    ("http_probe", "広告詐欺の偵察: /ads.txt への不審アクセス（invalid authority）", r"/ads\.txt"),
]

# ノイズ（攻撃ではない）を除外するパターン
IGNORE = re.compile(r"instance refused|listening on|Umounting|Mounting|clean,|Traceback|KeyboardInterrupt")


def fly_logs(app: str) -> str:
    r = subprocess.run(["fly", "logs", "-a", app, "--no-tail"],
                       capture_output=True, text=True, timeout=180)
    return r.stdout


def list_apps() -> list[str]:
    r = subprocess.run(["fly", "apps", "list", "--json"], capture_output=True, text=True, timeout=60)
    try:
        apps = json.loads(r.stdout)
        return [a["Name"] for a in apps if a.get("Status") == "deployed"]
    except Exception:
        return []


def detect(log: str) -> dict[str, dict]:
    """ログから攻撃パターンを抽出。key=一般化パターン説明。"""
    found: dict[str, dict] = {}
    for line in log.splitlines():
        if IGNORE.search(line):
            continue
        for typ, desc, rx in RULES:
            if re.search(rx, line, re.IGNORECASE):
                e = found.setdefault(desc, {"type": typ, "count": 0})
                e["count"] += 1
                break
    return found


def already_shared(hub: str, key: str) -> set[str]:
    req = urllib.request.Request(hub + "/api/observations", headers={"X-Mamori-Key": key})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return {o.get("pattern", "") for o in json.load(r).get("observations", [])}
    except Exception:
        return set()


def share(hub: str, key: str, typ: str, pattern: str, count: int) -> bool:
    body = json.dumps({"type": typ, "pattern": pattern, "count": count, "tlp": "CLEAR",
                       "via": "fly-watch"}, ensure_ascii=False).encode()
    req = urllib.request.Request(hub + "/api/observations", data=body, method="POST",
                                 headers={"X-Mamori-Key": key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return 200 <= r.status < 300
    except Exception as e:
        print(f"  共有失敗: {e}", file=sys.stderr)
        return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apps", default="", help="対象アプリ（カンマ区切り。省略時はdeployed全アプリ）")
    ap.add_argument("--dry-run", action="store_true", help="投稿せず検出結果だけ表示")
    args = ap.parse_args()

    key = os.environ.get("MAMORI_KEY", "")
    if not key and not args.dry_run:
        sys.exit("MAMORI_KEY を設定してください（--dry-run なら不要）")

    apps = args.apps.split(",") if args.apps else list_apps()
    if not apps:
        sys.exit("対象アプリがありません")

    existing = already_shared(HUB, key) if key and not args.dry_run else set()
    total_new = 0
    for app in apps:
        try:
            log = fly_logs(app)
        except Exception as e:
            print(f"[{app}] ログ取得失敗: {e}", file=sys.stderr)
            continue
        found = detect(log)
        for desc, e in found.items():
            prefix = f"[{app}] {e['type']} x{e['count']}: {desc}"
            if desc in existing:
                print(f"{prefix} — 共有済み、スキップ")
                continue
            if args.dry_run:
                print(f"{prefix} — (dry-run)")
            else:
                ok = share(HUB, key, e["type"], desc, e["count"])
                print(f"{prefix} — {'共有しました' if ok else '失敗'}")
                total_new += ok
    print(f"\n新規共有: {total_new}件" + ("（dry-run）" if args.dry_run else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
