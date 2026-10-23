#!/usr/bin/env python3
"""Mamori — applicability matcher.

Takes fetched advisories (stdin or file) and an inventory file describing
what we actually run (products, vendors, keywords), and classifies each
advisory as: relevant / maybe / not-relevant.

Inventory format (JSON):
  {"watch": [{"name": "cloudflare", "keywords": ["cloudflare"]},
              {"name": "next.js",    "keywords": ["next.js", "nextjs", "vercel"]},
              ...]}

Output: same advisory objects with added "match": {"status": ..., "hits": [...]}
"""
from __future__ import annotations

import json
import re
import sys

DEFAULT_INVENTORY = {
    "watch": [
        {"name": "cloudflare", "keywords": ["cloudflare"]},
        {"name": "fly.io", "keywords": ["fly.io", "flyio"]},
        {"name": "next.js", "keywords": ["next.js", "nextjs"]},
        {"name": "react", "keywords": ["react"]},
        {"name": "node.js", "keywords": ["node.js", "nodejs", "npm"]},
        {"name": "python", "keywords": ["python", "cpython", "pip "]},
        {"name": "rust", "keywords": ["rustlang", "rust-lang", "cargo crate", "tokio", "axum"]},
        {"name": "swift/ios", "keywords": ["swift", "ios", "macos", "apple"]},
        {"name": "wordpress", "keywords": ["wordpress", "wp-"]},
        {"name": "stripe", "keywords": ["stripe"]},
        {"name": "sqlite/turso", "keywords": ["sqlite", "turso", "libsql"]},
        {"name": "nginx", "keywords": ["nginx"]},
        {"name": "docker", "keywords": ["docker", "container"]},
        {"name": "github actions", "keywords": ["github actions", "github"]},
        {"name": "openssh", "keywords": ["openssh", "ssh"]},
        {"name": "openssl", "keywords": ["openssl"]},
        {"name": "chrome", "keywords": ["chrome", "chromium"]},
        {"name": "plex", "keywords": ["plex media server", "plex"]},
        {"name": "strapi", "keywords": ["strapi"]},
        {"name": "atlassian", "keywords": ["atlassian", "jira", "confluence"]},
        {"name": "apache", "keywords": ["apache struts", "apache http"]},
        {"name": "onlyoffice", "keywords": ["onlyoffice"]},
        # ネットワーク機器・Windowsは現状未使用のため監視対象外。使い始めたら戻す。
    ]
}


def classify(item: dict, watch: list[dict]) -> dict:
    text = " ".join([
        item.get("title", ""),
        " ".join(item.get("products", []) or []),
    ]).lower()
    # "ssh" や "ios" のような短い語の部分一致は誤検知が多いので、
    # 3文字以下のキーワードは単語境界で判定する
    def _hit(k: str) -> bool:
        if len(k) <= 3:
            return re.search(r"(?<![a-z0-9])" + re.escape(k) + r"(?![a-z0-9])", text) is not None
        return k in text
    # keywords を書かなかった項目は name（小文字）で照合する
    hits = [w["name"] for w in watch
            if any(_hit(str(k).lower()) for k in (w.get("keywords") or [w.get("name", "")]) if k)]
    if hits:
        status = "relevant" if item.get("severity") in ("exploited-in-the-wild", "alert") else "maybe"
    else:
        status = "not-relevant"
    item["match"] = {"status": status, "hits": hits}
    return item


def load_inventory(path: str) -> dict:
    """製品リストを読む。書式の誤りと、照合で一致しにくい名前を日本語で知らせる。"""
    text = open(path, encoding="utf-8").read()
    # テキストエディット等が自動で変える斜めの引用符を直してから読む
    text = text.replace("\u201c", '"').replace("\u201d", '"').replace("\u2018", "'").replace("\u2019", "'")
    try:
        inv = json.loads(text)
    except json.JSONDecodeError as e:
        line = text.splitlines()[e.lineno - 1] if e.lineno - 1 < len(text.splitlines()) else ""
        sys.stderr.write(
            f"✖ {path} の {e.lineno} 行目の書き方が違います（{e.colno} 文字目あたり）。\n"
            f"    {line.strip()}\n"
            "  見本（examples/inventory.example.json）とかっこ・カンマ・\"\" を見比べてください。\n"
            "  よくある原因: 行の終わりのカンマ忘れ／最後の行の余計なカンマ／全角の「：」「，」。\n")
        sys.exit(2)
    for w in inv.get("watch", []):
        name = str(w.get("name", ""))
        if not w.get("keywords") and (re.search(r"[^\x00-\x7f]", name) or re.search(r"\s\d+(\.\d+)*$", name)):
            sys.stderr.write(f"⚠ 「{name}」は一致しにくい名前です。脅威情報の題名は英語なので、"
                             "WordPress のように英語で、版の数字を付けずに書いてください。\n")
    return inv


def main() -> int:
    src = sys.argv[1] if len(sys.argv) > 1 else None
    inv_path = sys.argv[2] if len(sys.argv) > 2 else None
    data = json.load(open(src)) if src else json.load(sys.stdin)
    inventory = load_inventory(inv_path) if inv_path else DEFAULT_INVENTORY
    watch = inventory.get("watch", DEFAULT_INVENTORY["watch"])
    for item in data.get("items", []):
        classify(item, watch)
    rel = [i for i in data["items"] if i["match"]["status"] == "relevant"]
    maybe = [i for i in data["items"] if i["match"]["status"] == "maybe"]
    data["summary"] = {
        "total": len(data["items"]),
        "relevant": len(rel),
        "maybe": len(maybe),
    }
    json.dump(data, sys.stdout, ensure_ascii=False, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
