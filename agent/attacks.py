#!/usr/bin/env python3
"""守 Mamori — 実際に観測された攻撃を集めて、守りに反映する。

集めるもの（すべて実データ・捏造しない）:
  1. Mamori ハブの共有観測（自組織＋参加組織。MAMORI_KEY があれば自分の範囲）
  2. この端末が直接受けた痕跡（SSH失敗・不審な待受ポートなど。読むだけ）

結果は `~/.mamori/attacks.json` に保存し、guard の点検に「同じ手口への備え」を足す。
アプリとブログはこのファイルを読む。

使い方:
    python3 agent/attacks.py            # 収集して保存
    python3 agent/attacks.py --json     # 中身を標準出力にも出す
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

HUB = os.environ.get("MAMORI_HUB", "https://mamori.teai.io").rstrip("/")
STATE = Path(os.environ.get("MAMORI_STATE_DIR") or (Path.home() / ".mamori"))
KEY_FILES = [Path.home() / ".config/mamori/key", Path.home() / ".config/mamori/keys/mail@yukihamada.jp.key"]

# 観測の type → 日本語の分類と、それに効く守り（guard の finding id と対応）
TYPE_JA = {
    "http_probe": "探索（設定・秘密ファイルを探す）",
    "payload": "攻撃の試行（脆弱性を突く）",
    "scanner": "自動スキャン",
    "brute_force": "総当たり（パスワード推測）",
    "malware": "マルウェア",
    "exposure": "露出（攻撃の入口になりうる）",
    "other": "その他",
}

# 手口のキーワード → 効く守り（guard の項目に橋渡し）
DEFENSE_MAP = [
    (re.compile(r"\.env|\.git|\.aws|secret|credential|設定|秘密|serviceAccount|Dockerfile"),
     "ai.plaintext_keys", "秘密情報を公開ディレクトリに置かない・平文の鍵を減らす"),
    (re.compile(r"phpinfo|info\.php|php"),
     "mac.os_updates", "テスト用ページ・旧ファイルを残さない・ソフトを最新に"),
    (re.compile(r"React|Next\.js|RSC|rsc"),
     "mac.os_updates", "React/Next.js を最新版へ"),
    (re.compile(r"総当たり|brute|ログイン|wp-login"),
     "ssh.hardening", "パスワード入室を止め、試行回数を制限する"),
    (re.compile(r"Webシェル|WAR|JSP|シェル"),
     "mac.os_updates", "サーバ側ソフトを最新に・不要なミドルウェアを止める"),
    (re.compile(r"A2B|App-to-Backend|APK|IPA|モバイル"),
     "ai.plaintext_keys", "アプリに鍵を埋め込まない・APIの権限を見直す"),
    (re.compile(r"/proc/.*/environ|environ|環境変数|コード実行|code_exec|ホスト実行|sandbox escape|サンドボックス"),
     "proc.env_exposure", "ホスト実行ツールを既定で無効化し、秘密をプロセス環境に置かない"),
]


def load_key() -> str:
    for f in KEY_FILES:
        try:
            t = f.read_text().strip()
            if t:
                return t
        except Exception:
            continue
    return os.environ.get("MAMORI_KEY", "")


def fetch_hub(key: str) -> list[dict]:
    """共有観測を取る。キーが無ければ公開（CLEAR）ぶんだけ。"""
    req = urllib.request.Request(HUB + "/api/observations",
                                 headers={"User-Agent": "mamori-attacks/0.1"})
    if key:
        req.add_header("X-Mamori-Key", key)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read().decode("utf-8"))
        return data.get("observations", [])
    except Exception as e:
        print(f"[attacks] 共有観測を取得できません: {type(e).__name__} {e}", file=sys.stderr)
        return []


def local_traces() -> list[dict]:
    """この端末が直接受けた痕跡（読むだけ・短時間で打ち切る）。"""
    out: list[dict] = []

    # SSH 失敗ログ（動いていなければ空）
    try:
        cp = subprocess.run(
            ["log", "show", "--last", "7d", "--predicate", 'process == "sshd"', "--style", "compact"],
            capture_output=True, text=True, timeout=25)
        fails = [ln for ln in cp.stdout.splitlines()
                 if re.search(r"fail|invalid|refus|break-in", ln, re.I)]
        if fails:
            out.append({"type": "brute_force", "source": "local-sshd",
                        "pattern": f"この端末のSSHに不審な試行 {len(fails)}件（直近7日）",
                        "count": len(fails), "received_at": None})
    except Exception:
        pass

    # 外部に開いた待受ポート（* / 0.0.0.0）。攻撃そのものではなく「入口になりうる露出」。
    try:
        cp = subprocess.run(["netstat", "-an", "-p", "tcp"], capture_output=True, text=True, timeout=10)
        exposed = []
        for ln in cp.stdout.splitlines():
            if "LISTEN" not in ln:
                continue
            parts = ln.split()
            if len(parts) < 4:
                continue
            addr = parts[3]
            if addr.startswith("*.") or addr.startswith("0.0.0.0"):
                exposed.append(addr)
        if exposed:
            out.append({"type": "exposure", "source": "local-ports",
                        "pattern": f"外部に開いた待受ポート {len(set(exposed))}件（攻撃の入口になりうる）: "
                                   + ", ".join(sorted(set(exposed))[:6]),
                        "count": len(set(exposed)), "received_at": None})
    except Exception:
        pass
    return out


def classify(obs: dict) -> dict:
    t = obs.get("type", "other")
    pat = obs.get("pattern", "")
    defenses = []
    for rx, fid, label in DEFENSE_MAP:
        if rx.search(pat):
            defenses.append({"finding": fid, "label": label})
    return {
        "type": t,
        "type_ja": TYPE_JA.get(t, TYPE_JA["other"]),
        "pattern": pat,
        "count": obs.get("count", 1),
        "tlp": obs.get("tlp", "CLEAR"),
        "source": obs.get("source", "hub"),
        "received_at": obs.get("received_at"),
        "defenses": defenses,
    }


def summarize(items: list[dict]) -> dict:
    by_type: dict[str, int] = {}
    for it in items:
        by_type[it["type_ja"]] = by_type.get(it["type_ja"], 0) + 1
    total_count = sum(it.get("count", 1) or 1 for it in items)
    return {
        "updated": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "date": dt.datetime.now().strftime("%Y-%m-%d"),
        "total_observations": len(items),
        "total_attempts": total_count,
        "by_type": by_type,
        "items": items,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="観測された攻撃を集めて守りに反映")
    ap.add_argument("--json", action="store_true", help="中身を標準出力にも出す")
    a = ap.parse_args()

    key = load_key()
    hub = [classify(o) for o in fetch_hub(key)]
    local = [classify(o) for o in local_traces()]
    items = hub + local
    # 同じ手口はまとめる（回数を足す）
    merged: dict[str, dict] = {}
    for it in items:
        k = it["pattern"][:120]
        if k in merged:
            merged[k]["count"] = (merged[k].get("count") or 1) + (it.get("count") or 1)
        else:
            merged[k] = it
    items = sorted(merged.values(), key=lambda x: -(x.get("count") or 1))

    data = summarize(items)
    STATE.mkdir(parents=True, exist_ok=True)
    (STATE / "attacks.json").write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"🛡 観測された攻撃: {data['total_observations']} 種 / 延べ {data['total_attempts']} 件")
    for label, n in sorted(data["by_type"].items(), key=lambda x: -x[1]):
        print(f"   - {label}: {n} 種")
    if a.json:
        print(json.dumps(data, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
