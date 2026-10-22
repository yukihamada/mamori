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


# 製品別の具体的対策ガイド（v0.3）。ベンダー公式情報へのリンクと確認手順を優先する。
PRODUCT_GUIDANCE = {
    "plex": [
        "Plex Media Server のバージョン確認: 設定 → サーバー → 一般 で現在バージョンを確認",
        "最新版へ更新: https://www.plex.tv/media-server-downloads/ から最新を適用",
        "外部公開の確認: リモートアクセス（32400番ポート）が不要なら無効化",
        "参考: Plex セキュリティ情報 https://www.plex.tv/blog/category/security/",
    ],
    "atlassian": [
        "対象製品（Jira/Confluence等）のバージョンを管理画面で確認",
        "Atlassian セキュリティアドバイザリで影響バージョンと修正版を特定: https://confluence.atlassian.com/security",
        "修正版が適用できない場合は WAF/リバースプロキシで対象エンドポイントを制限",
    ],
    "strapi": [
        "Strapi のバージョン確認: package.json または管理パネル",
        "Strapi セキュリティリリースを確認: https://github.com/strapi/strapi/security/advisories",
        "管理パネル（/admin）をIP制限またはVPN内に限定",
    ],
    "apache": [
        "Struts のバージョン確認: 依存ツリー（pom.xml / build.gradle）で org.apache.struts を検索",
        "影響バージョンなら直ちに修正版へ更新。暫定緩和は WAF でのOGNLインジェクション検知",
        "参考: Apache Struts セキュリティ https://struts.apache.org/security.html",
    ],
    "onlyoffice": [
        "ONLYOFFICE Docs のバージョンを管理画面で確認",
        "最新のセキュリティ修正を適用: https://github.com/ONLYOFFICE/DocumentServer/releases",
        "ドキュメントサーバーをインターネット直接公開していないか確認",
    ],
    "cloudflare": ["Cloudflare ダッシュボードのセキュリティイベントを確認し、関連マネージドルールが有効か確認"],
    "next.js": ["Next.js のバージョンを package.json で確認し、該当CVEの修正版（patched release）へ更新"],
    "node.js": ["Node.js のバージョンを確認（node -v）し、セキュリティリリース https://nodejs.org/en/blog/vulnerability を適用"],
    "python": ["Python のバージョンと依存パッケージを pip-audit / safety でスキャン"],
    "rust": ["cargo audit で依存クレートの既知脆弱性をスキャン"],
    "sqlite/turso": ["SQLite のバージョンを確認し、修正版へ更新"],
    "docker": ["ベースイメージを最新のパッチ適用版へ再ビルド（docker scout / trivy でスキャン）"],
    "github actions": ["ワークフローのサードパーティActionをコミットSHA固定しているか確認"],
    "openssh": ["OpenSSH のバージョン確認（ssh -V）し、OSパッケージの最新セキュリティ更新を適用"],
    "openssl": ["OpenSSL のバージョン確認（openssl version）し、OSパッケージの最新セキュリティ更新を適用"],
    "chrome": ["Chrome を最新版へ更新（chrome://settings/help）"],
    "wordpress": ["WordPress コア・プラグインを最新版へ更新。xmlrpc.php と wp-login.php へのアクセスを制限"],
    "stripe": ["Stripe ライブラリを最新版へ更新し、Webhook署名検証が有効か確認"],
    "nginx": ["nginx のバージョン確認（nginx -v）し、OSパッケージの最新セキュリティ更新を適用"],
    "swift/ios": ["iOS/macOS を最新版へ更新。Xcode の依存パッケージを Swift Package Index の脆弱性情報で確認"],
    "fly.io": ["fly.toml のイメージを最新へ更新し、fly platform の告知を確認"],
}


def draft_actions(item: dict) -> list[str]:
    actions = []
    if item.get("severity") == "exploited-in-the-wild":
        actions.append(f"[緊急] {item['id']} は悪用確認済み。CISA対応期限: {item.get('due_date','—')}")
    for hit in item.get("match", {}).get("hits", []):
        guidance = PRODUCT_GUIDANCE.get(hit)
        if guidance:
            actions.append(f"【{hit}】具体的対策:")
            actions.extend(f"  - {g}" for g in guidance)
        else:
            actions.append(f"自社スタック「{hit}」との関連を確認: 依存バージョンと公開面を棚卸し")
    if item.get("required_action") and item["severity"] == "exploited-in-the-wild":
        actions.append(f"CISA指定の対応（一般）: {item['required_action']}")
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
