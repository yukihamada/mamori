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
import sys

DEFAULT_INVENTORY = {
    "watch": [
        {"name": "cloudflare", "keywords": ["cloudflare"]},
        {"name": "fly.io", "keywords": ["fly.io", "flyio"]},
        {"name": "next.js", "keywords": ["next.js", "nextjs"]},
        {"name": "react", "keywords": ["react"]},
        {"name": "node.js", "keywords": ["node.js", "nodejs", "npm"]},
        {"name": "python", "keywords": ["python", "cpython", "pip"]},
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
    hits = [w["name"] for w in watch if any(k in text for k in w["keywords"])]
    if hits:
        status = "relevant" if item.get("severity") == "exploited-in-the-wild" else "maybe"
    else:
        status = "not-relevant"
    item["match"] = {"status": status, "hits": hits}
    return item


def main() -> int:
    src = sys.argv[1] if len(sys.argv) > 1 else None
    inv_path = sys.argv[2] if len(sys.argv) > 2 else None
    data = json.load(open(src)) if src else json.load(sys.stdin)
    inventory = json.load(open(inv_path)) if inv_path else DEFAULT_INVENTORY
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
