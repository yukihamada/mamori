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
from datetime import datetime, timedelta, timezone

JST = timezone(timedelta(hours=9))


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
    "php": [
        "PHP のバージョン確認: php -v（レンタルサーバーは管理画面のPHP設定）",
        "JPCERT/CC 注意喚起の「対象」と「対策」の節で影響バージョンと修正版を確認し、修正版へ更新",
        "参考: PHP 公式のリリース情報 https://www.php.net/ChangeLog-8.php",
    ],
    "fortinet": [
        "FortiGate / FortiOS 等のバージョンを管理画面（ダッシュボード → システム情報）で確認",
        "Fortinet PSIRT で影響バージョンと修正版を確認し更新: https://www.fortiguard.com/psirt",
        "管理画面（HTTPS/SSH）をインターネットに公開していないか確認",
    ],
    "ivanti": [
        "Ivanti Connect Secure 等のバージョンを管理画面で確認",
        "Ivanti セキュリティアドバイザリで修正版と緩和策を確認: https://forums.ivanti.com/s/security-advisory",
        "整合性チェックツール（ICT）で侵害の痕跡を確認",
    ],
    "cisco": [
        "対象機器のソフトウェアバージョンを確認（show version）",
        "Cisco Security Advisories で影響と修正版を確認: https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
    ],
    "microsoft windows": [
        "Windows Update で今月のセキュリティ更新プログラムが適用済みか確認（設定 → Windows Update → 更新の履歴）",
        "参考: マイクロソフト セキュリティ更新プログラム ガイド https://msrc.microsoft.com/update-guide",
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
    elif item.get("severity") == "alert":
        cves = "、".join(item.get("cves") or []) or "本文参照"
        actions.append(f"[注意喚起] JPCERT/CC が {item.get('published','')} に公開（対象CVE: {cves}）。本文の対象バージョンと回避策を確認")
    for hit in item.get("match", {}).get("hits", []):
        guidance = PRODUCT_GUIDANCE.get(hit)
        if guidance:
            actions.append(f"【{hit}】具体的対策:")
            actions.extend(f"  - {g}" for g in guidance)
        else:
            actions.append(f"自社スタック「{hit}」との関連を確認: 依存バージョンと公開面を棚卸し")
    if item.get("required_action") and item["severity"] == "exploited-in-the-wild":
        actions.append("CISA指定の対応（要約）: ベンダーの指示どおりに修正・緩和策を適用。できない場合は製品の使用を止める。"
                       "期限は米国政府機関向けの目安")
        actions.append(f"  原文: {item['required_action'][:300]}")
    actions.append(f"一次情報: {item.get('url')}")
    return actions


def make_share_record(observations: list[dict]) -> dict:
    """Lightweight intel-sharing record (STIX-inspired).
    公開バンドルに運営の組織名は入れない（orgフィールド自体を廃止）。"""
    now = datetime.now(timezone.utc).isoformat()
    return {
        "type": "mamori-intel-bundle",
        "spec_version": "0.1",
        "id": "bundle--" + hashlib.sha256(now.encode()).hexdigest()[:32],
        "created": now,
        "objects": observations,
    }


def render_report(data: dict) -> str:
    s = data.get("summary", {})
    try:
        fetched = datetime.fromisoformat(data["fetched_at"]).astimezone(JST)
    except Exception:  # noqa: BLE001
        fetched = datetime.now(JST)
    lines = [
        f"# 守（Mamori）脅威レポート — {fetched:%Y-%m-%d %H:%M} JST",
        "",
        f"- 取得: {s.get('total',0)}件 / 要対応: **{s.get('relevant',0)}件** / 要確認: {s.get('maybe',0)}件",
        "",
    ]
    if not s.get("relevant") and not s.get("maybe"):
        lines += ["> 自社の製品に一致するものは0件でした。0件は「安全」という意味ではありません。",
                  "> 製品の名前が英語で（版の数字なしで）書けているか確かめ、下の新着にも目を通してください。", ""]
    # 直近7日の新着（自社に関係なくても、何が起きているかを一覧で）
    since = (fetched - timedelta(days=7)).strftime("%Y-%m-%d")
    fresh = sorted([i for i in data.get("items", []) if (i.get("published") or "") >= since
                    and i.get("source") != "jpcert"],
                   key=lambda i: i.get("published", ""), reverse=True)
    if fresh:
        mark = {"relevant": "🔴", "maybe": "🟡"}
        lines.append(f"## 🆕 直近7日の新着 ({len(fresh)}件・{since}以降)")
        for i in fresh:
            m = mark.get(i.get("match", {}).get("status"), "・")
            src = {"cisa_kev": "CISA KEV", "jpcert_alert": "JPCERT注意喚起"}.get(i.get("source"), i.get("source"))
            lines.append(f"- {m} {i.get('published')} [{src}] {i.get('title','')[:90]} — {i.get('url')}")
        lines.append("")
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
            "title": i.get("title"),
            "published": i.get("published"),
            "due_date": i.get("due_date"),
            "required_action": i.get("required_action"),
            "url": i.get("url"),
        }
        # 公開フィードは全件（各社の照合は手元の run.sh で行う）。
        # match（運営の構成での照合結果）は公開バンドルに入れない。
        # 入っていると「運営がどの製品を使っているか」が外部に漏れるため。
        for i in data.get("items", [])
    ]
    bundle = make_share_record(observations)
    out = {"report_md": report, "share_bundle": bundle}
    json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
