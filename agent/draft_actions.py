#!/usr/bin/env python3
"""Mamori — action drafter & share formatter.

1) For each relevant/maybe advisory, draft a concrete action checklist.
2) Format observed-attack / intel sharing as a lightweight JSON record
   (STIX-inspired, minimal) that partner companies can consume.

Output: report markdown + share JSON.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone


def draft_actions(item: dict) -> list[str]:
    actions = []
    if item.get("severity") == "exploited-in-the-wild":
        actions.append(f"[緊急] {item['id']} は悪用確認済み。該当製品のバージョン確認を今週中に実施")
        if item.get("required_action"):
            actions.append(f"CISA指定の対応: {item['required_action']}")
        if item.get("due_date"):
            actions.append(f"CISA対応期限: {item['due_date']}")
    for hit in item.get("match", {}).get("hits", []):
        actions.append(f"自社スタック「{hit}」との関連を確認: 依存バージョンと公開面を棚卸し")
    actions.append(f"一次情報: {item.get('url')}")
    return actions


def make_share_record(observations: list[dict], org: str = "enabler") -> dict:
    """Lightweight intel-sharing record (STIX-inspired)."""
    now = datetime.now(timezone.utc).isoformat()
    return {
        "type": "mamori-intel-bundle",
        "spec_version": "0.1",
        "id": "bundle--" + hashlib.sha256(now.encode()).hexdigest()[:32],
        "created": now,
        "org": org,
        "objects": observations,
    }


def render_report(data: dict) -> str:
    s = data.get("summary", {})
    lines = [
        f"# 守（Mamori）脅威レポート — {data.get('fetched_at','')[:10]}",
        "",
        f"- 取得: {s.get('total',0)}件 / 要対応: **{s.get('relevant',0)}件** / 要確認: {s.get('maybe',0)}件",
        "",
    ]
    for status, label in (("relevant", "🔴 要対応"), ("maybe", "🟡 要確認")):
        group = [i for i in data.get("items", []) if i.get("match", {}).get("status") == status]
        if not group:
            continue
        lines.append(f"## {label} ({len(group)}件)")
        for i in group:
            lines.append(f"### {i['id']} — {i['title']}")
            for a in draft_actions(i):
                lines.append(f"- {a}")
            lines.append("")
    if data.get("errors"):
        lines.append("## 取得エラー")
        for e in data["errors"]:
            lines.append(f"- {e['source']}: {e['error']}")
    return "\n".join(lines)


def main() -> int:
    data = json.load(sys.stdin) if len(sys.argv) < 2 else json.load(open(sys.argv[1]))
    report = render_report(data)
    observations = [
        {
            "type": "advisory",
            "id": i["id"],
            "source": i["source"],
            "severity": i.get("severity"),
            "match": i.get("match"),
            "url": i.get("url"),
        }
        for i in data.get("items", [])
        if i.get("match", {}).get("status") in ("relevant", "maybe")
    ]
    bundle = make_share_record(observations)
    out = {"report_md": report, "share_bundle": bundle}
    json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
