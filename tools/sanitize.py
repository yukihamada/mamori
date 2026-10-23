#!/usr/bin/env python3
"""投稿前のサニタイズ（投稿者側で識別情報を消す）。

ハブ側は IP末尾・メールを自動で伏せるが、自社ドメイン・社内ホスト名・
サービス名・人名はハブが知らないので、投稿者側で消す必要がある。

使い方:
  echo "本文" | python3 tools/sanitize.py [sanitize.json]
  python3 tools/sanitize.py sanitize.json < input.txt > output.txt

設定ファイル（既定: ./sanitize.json。なければ examples/sanitize.example.json を参照）:
  {"blocklist": ["自社ドメイン", "社内ホスト名", ...]}
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def load_blocklist(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
        return [str(s) for s in data.get("blocklist", []) if str(s).strip()]
    except Exception:
        return []


def sanitize(text: str, blocklist: list[str]) -> tuple[str, int]:
    """blocklist の文字列を [removed] に置き換える。(置換後テキスト, 置換回数)"""
    count = 0
    for word in blocklist:
        if not word:
            continue
        # 大文字小文字を区別しない置換（ドメイン等は表記ゆれがあるため）
        pattern = re.compile(re.escape(word), re.IGNORECASE)
        text, n = pattern.subn("[removed]", text)
        count += n
    return text, count


def main() -> int:
    cfg = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("sanitize.json")
    blocklist = load_blocklist(cfg)
    text = sys.stdin.read()
    out, n = sanitize(text, blocklist)
    sys.stdout.write(out)
    if n:
        print(f"\n[sanitize] {n}箇所を [removed] に置き換えました（{cfg}）", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
