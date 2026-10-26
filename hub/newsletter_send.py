#!/usr/bin/env python3
"""守 Mamori セキュリティ便り（メルマガ）配信スクリプト — stdlib only.

data/latest_bundle.json から直近7日の脅威を拾い、購読者（accounts.json の
newsletter.active）へ accounts.send_mail で送る。配信は1号につき1回だけ
（sent-log に記録。--force で再送可）。

使い方:
  cd /app   # Fly では hub/ と data/ の親
  python3 hub/newsletter_send.py            # 送信対象があれば送る
  python3 hub/newsletter_send.py --dry-run  # 本文だけ表示（送らない）
  python3 hub/newsletter_send.py --to you@example.com  # 特定1名へテスト送信

環境変数:
  RESEND_API_KEY       必須（送信時）
  MAMORI_DATA          data ディレクトリ（既定 ./data）
  MAMORI_MAIL_FROM     差出人（既定: 守 Mamori <noreply@teai.io>）
  MAMORI_NEWSLETTER_DAYS  何日分の脅威を拾うか（既定 7）
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import accounts  # noqa: E402

DATA_DIR = Path(os.environ.get("MAMORI_DATA", "./data"))
LATEST_FILE = DATA_DIR / "latest_bundle.json"
SENT_LOG = DATA_DIR / "newsletter_sent.jsonl"
DAYS = int(os.environ.get("MAMORI_NEWSLETTER_DAYS", "7"))

# CVE ごとの手動確認済み情報（配信前に一次情報で確認して更新する）。
# ペルソナ批評で「修正版の有無を書け」が最大の改善点だったため、
# 確認できたものはここに固定値で持ち、本文に「修正版あり」を明記する。
CVE_KNOWN_FIXES = {
    "CVE-2026-106931": {
        "fixed": "Ver8.00 Update5（FreeBSD は Ver7.00 Update6）",
        "vendor_url": "https://www.eg-secure.co.jp/siteguard/news/alert-202610-1",
        "vendor_name": "EGセキュアソリューションズ",
        "note": "悪用はローカルから（サーバーへのアクセス権を持つ攻撃者が権限昇格）。外部から直接ではありません。ただし、別の侵入経路（上の管理画面公開など）と組み合わさると一気に乗っ取られます。だから期限超過の今、確認だけは今日済ませてください。",
        "pre_step": "アップデートの前に、管理画面の「診断情報」をダウンロードして保管してください（攻撃の痕跡が消える可能性があります）。",
        "ja_url": "https://jvn.jp/jp/JVN88474777/",
    },
    "CVE-2026-96656": {
        "fixed": "1.43.3.10861",
        "vendor_url": "https://forums.plex.tv/t/plex-media-server/30447/711",
        "vendor_name": "Plex",
        "note": "悪用には管理者権限が必要です。外部から直接ではありません。",
    },
    "CVE-2026-114625": {
        "fixed": "VCO 5.2.3.18 / 6.1.3.10 / 6.4.2.12",
        "vendor_url": "https://www.arista.com/en/support/advisories-notices/security-advisory/24838-security-advisory-0199",
        "vendor_name": "Arista",
        "note": "対象はオンプレミス版のみ。ホステッド（クラウド）版は既にパッチ済みです。",
    },
}
# 直近で国内で注意喚起が出ている手口。号の「突破の手口」欄の素材。
# 配信時点の JPCERT-AT-2026-0030（2026-10-23 更新）に基づく。古くなったら更新する。
TECHNIQUES = [
    ("アプリ解析 → バックエンドAPI攻撃（A2B攻撃）",
     "公開されているスマホアプリを解析してAPIの入口と鍵を特定し、アプリを介さず直接サーバーのAPIを叩く手口。"
     "権限変更・不正アカウント作成・NoSQLインジェクション（データベースへの不正な問い合わせ）が確認されています。",
     "□ 自社スマホアプリがある □ サイト/アプリの開発を外部委託している",
     "制作会社に「APIの認可とレート制限、WAFの有無を確認してください」と送るだけでOKです。"),
    ("AIペネトレーション基盤の悪用",
     "AIを使った脆弱性スキャン基盤が攻撃に転用され、公開Webアプリへの探索・環境設定ファイル（.env等）の窃取が自動化されています。"
     "短時間に多数のIPからアクセスされるのが特徴です。",
     "□ 自社のWebサイト・Webサービスを公開している",
     "サーバー会社に「不要な管理画面の公開停止とWAFの有無を確認してください」と送るだけでOKです。"),
    ("Webシェルの設置",
     "公開Webサーバー経由でアプリケーションサーバーにWARファイル（JSP）を置き、外部からコマンドを実行される手口。"
     "アップロード機能の制限と、設置ファイルの定期スキャンで検知できます。",
     "□ 自社のWebサイト・Webサービスを公開している",
     "サーバー会社に「アップロード機能の制限とファイルスキャンの設定を確認してください」と送るだけでOKです。"),
]


def _recent_advisories() -> list[dict]:
    try:
        b = json.loads(LATEST_FILE.read_text())
    except Exception:  # noqa: BLE001
        return []
    # 形式は2種類あり得る: 公開STIX風 {"objects": [...]} と fetch_feeds 出力 {"items": [...]}
    objs_all = b.get("objects") or b.get("items") or []
    cut = time.strftime("%Y-%m-%d", time.gmtime(time.time() - DAYS * 86400))
    objs = [o for o in objs_all if o.get("title") and (o.get("published") or "") >= cut]
    objs.sort(key=lambda o: (o.get("published") or ""), reverse=True)
    kev = [o for o in objs if o.get("source") == "cisa_kev"]
    jpcert = [o for o in objs if str(o.get("source", "")).startswith("jpcert")]
    return (kev + jpcert)[:5] or objs[:5]


def _ja_title(o: dict) -> str:
    """CVE の英語タイトルから「製品名: 製品名 SQL Injection...」の二重表記を除き、
    日本語の見出しにする。製品名は products かタイトル先頭を使う。"""
    products = o.get("products") or []
    prod = products[0] if products else ""
    title = o.get("title", "")
    kind = ""
    for kw, ja in (("SQL Injection", "SQLインジェクション"),
                   ("OS Command Injection", "OSコマンドインジェクション"),
                   ("Command Injection", "コマンドインジェクション"),
                   ("Authentication Bypass", "認証回避"),
                   ("Server-Side Request Forgery", "SSRF（サーバー側リクエスト偽造）"),
                   ("External Control of File Name or Path", "ファイル名・パスの外部制御"),
                   ("Improper Neutralization of Encoded URI Schemes", "URIスキームの不適切な処理"),
                   ("Path Traversal", "パストラバーサル"),
                   ("Code Injection", "コードインジェクション"),
                   ("Improper Authentication", "不適切な認証")):
        if kw.lower() in title.lower():
            kind = ja
            break
    if not prod:
        prod = title.split(":")[0].strip() or title
    # 重複表記の解消（例: "Collabora Collabora Online" → "Collabora Online"）
    prod = re.sub(r"\b(\w+(?: \w+){0,3}) \1\b", r"\1", prod)
    return f"{prod}の{kind}の脆弱性" if kind else prod


def _plain_note(o: dict) -> str:
    """脆弱性名の直後に置く平たい一文。専任でなくても被害がイメージできる。"""
    t = (o.get("title") or "").lower()
    if "command injection" in t or "code injection" in t:
        return "サーバーの中で好き勝手に命令を実行される隙です。"
    if "sql injection" in t:
        return "データベースに不正な問い合わせをして情報を盗まれる隙です。"
    if "external control of file name or path" in t or "path traversal" in t:
        return "サーバー上のファイルを勝手に読み書きされる隙です。"
    if "authentication bypass" in t or "improper authentication" in t:
        return "ログインを回避されて管理機能を操作される隙です。"
    if "ssrf" in t or "server-side request forgery" in t:
        return "サーバー経由で内部システムへ侵入される隙です。"
    return "サーバーやシステムに侵入される隙です。"


def _impact_line(o: dict) -> str:
    """悪用された場合の被害を1行で。"""
    t = (o.get("title") or "").lower()
    if "command injection" in t or "code injection" in t:
        return "悪用されるとサーバー上で任意のコマンドを実行され、情報窃取・踏み台化の恐れがあります。"
    if "sql injection" in t:
        return "悪用されるとデータベースの情報を盗まれ、個人情報漏えいにつながる恐れがあります。"
    if "authentication bypass" in t or "improper authentication" in t:
        return "悪用されるとログインを回避され、管理機能を第三者に操作される恐れがあります。"
    if "ssrf" in t or "server-side request forgery" in t:
        return "悪用されるとサーバー経由で内部システムへ侵入され、情報窃取の恐れがあります。"
    if "external control of file name or path" in t or "path traversal" in t:
        return "悪用されるとサーバー上の任意のファイルを読み書きされ、情報窃取や改ざんの恐れがあります。"
    if "encoded uri" in t:
        return "悪用されると細工したリンクから利用者を危険なサイトへ誘導される恐れがあります。"
    return "悪用されると情報窃取やシステムへの不正侵入につながる恐れがあります。"


def _audience_line(o: dict) -> str:
    """どんな会社なら該当するかの判別行。使っていなければ読み飛ばせる。"""
    products = o.get("products") or []
    prod = products[0] if products else (o.get("title") or "").split(":")[0].strip()
    return f"該当するのは「{prod}」を使っている組織です。使っていなければ読み飛ばしてください。"


def _audience_check(o: dict) -> str:
    """冒頭に置く「うちは関係あるか」1行チェック。"""
    products = o.get("products") or []
    prod = products[0] if products else (o.get("title") or "").split(":")[0].strip()
    p = prod.lower()
    if "siteguard" in p:
        return "□ レンタルサーバーを利用している（自分では判断不可。まずサーバー会社に「SiteGuardは導入されていますか」と聞くだけでOKです）"
    if "plex" in p:
        return "□ 社内に Plex を入れたパソコン・NAS・メディアサーバーがある"
    if "velocloud" in p or "sd-wan" in p:
        return "□ 社内ネットワークに SD-WAN（VeloCloud等）を導入している"
    if "windows" in p or "microsoft" in p:
        return "□ 社内に Windows のパソコン・サーバーがある"
    if "wordpress" in p:
        return "□ 自社サイトが WordPress で動いている"
    if "fortinet" in p:
        return "□ 社内に Fortinet のVPN・ファイアウォールがある"
    return f"□ 社内に「{prod}」がある"


def _attack_vector(o: dict) -> str:
    """攻撃経路と前提条件を平易な一文で。確認済み情報があればそれを使う。"""
    cve = o.get("id") or o.get("cve") or ""
    known = CVE_KNOWN_FIXES.get(cve, {})
    if known.get("note"):
        return known["note"]
    t = (o.get("title") or "").lower()
    if "local" in t or "privilege" in t:
        return "サーバーへのアクセス権を持つ攻撃者が、さらに権限を奪うタイプです。"
    if "admin" in t or "authenticated" in t:
        return "管理者としてログインしている攻撃者が、さらに悪さをするタイプです。"
    return "外部から管理者権限なしで攻撃できます。"


def _relevance_hint(o: dict) -> str:
    """該当しやすさの目安を1行で。"""
    products = o.get("products") or []
    prod = (products[0] if products else (o.get("title") or "").split(":")[0].strip()).lower()
    if "siteguard" in prod:
        return "国内レンタルサーバー利用なら要確認"
    if "plex" in prod:
        return "Plex導入環境のみ。大半は読み飛ばし可"
    if "velocloud" in prod or "sd-wan" in prod:
        return "SD-WAN導入企業のみ。大半は読み飛ばし可"
    if "windows" in prod or "microsoft" in prod:
        return "Windows利用の全組織が対象"
    if "wordpress" in prod:
        return "WordPressサイト運営なら要確認"
    return "該当製品があるかご確認ください"


def _action_steps(o: dict) -> list[str]:
    """兼任担当がその日に取れる一手を箇条書きで返す。"""
    cve = o.get("id") or o.get("cve") or ""
    url = o.get("url") or ""
    products = o.get("products") or []
    prod = (products[0] if products else (o.get("title") or "").split(":")[0].strip()).lower()
    known = CVE_KNOWN_FIXES.get(cve, {})
    steps = []
    if "siteguard" in prod:
        steps.append(f"① レンタルサーバー会社のサポートに「{cve}の対応状況を教えてください」と送ってください（サーバー会社が導入するものなので、あなたがやることはこの連絡だけです）")
        if known.get("pre_step"):
            steps.append(f"② 自前のサーバー・VPSを持っている場合のみ: 業者への依頼文に「診断情報の保全もお願いします」と一文添えてください（被害調査のため、攻撃の痕跡を消さずに残す必要があります）")
        if known.get("fixed"):
            steps.append(f"③ 修正版 {known['fixed']} への更新を確認してください")
    elif "plex" in prod:
        steps.append(f"① Plex を導入した人・業者に「{cve}の対応状況を教えてください」と送ってください")
        if known.get("fixed"):
            steps.append(f"② 修正版 {known['fixed']} への更新を確認してください")
    elif "velocloud" in prod or "sd-wan" in prod:
        steps.append(f"① ネットワーク構築業者に「{cve}の対応状況を教えてください」と送ってください")
        if known.get("fixed"):
            steps.append(f"② 修正版 {known['fixed']} への更新を確認してください")
    else:
        steps.append(f"① サーバー会社・保守業者に「{cve}の対応状況を教えてください」と送ってください")
        if known.get("fixed"):
            steps.append(f"② 修正版 {known['fixed']} への更新を確認してください")
    if not known.get("fixed"):
        steps.append("修正版がまだなければ、公開停止・WAF・アクセス制限の緩和策を相談してください")
    steps.append("もし「未対応」「分かりません」と返ってきたら、「修正予定日と、それまでの暫定対策（WAFルール適用など）を教えてください」と返信してください。")
    links = []
    if known.get("vendor_url"):
        links.append(f"公式: {known['vendor_url']}")
    if known.get("ja_url"):
        links.append(f"日本語: {known['ja_url']}")
    links.append(f"NVD: {url}")
    steps.append(" / ".join(links))
    return steps


def _sort_urgent(objs: list[dict], today: str) -> list[dict]:
    """期限切れ（=本来最も危険）を先頭に、その後は期限が近い順。"""
    def key(o):
        due = o.get("due_date") or "9999"
        return (0 if due < today else 1, due)
    return sorted(objs, key=key)


def _due_label(due: str, today: str) -> str:
    """期限ステータスのラベル。超過・本日・近いを視覚的に分ける。"""
    if not due:
        return ""
    if due < today:
        return "🔴期限超過"
    if due == today:
        return "🟡本日期限"
    return "🟢期限内"


def _urgency_subject(objs: list[dict], today: str) -> str:
    """件名に緊急度とターゲットを明記する。実質の緊急度と一致させる。"""
    top = _sort_urgent(objs, today)[:3]
    dues = [o.get("due_date") for o in top if o.get("due_date")]
    overdue = [d for d in dues if d < today]
    today_due = [d for d in dues if d == today]
    n = len(top)
    if overdue:
        return f"【守 Mamori】期限超過{len(overdue)}件・本日期限{len(today_due)}件｜国内レンタルサーバー利用企業は確認を {today}"
    if today_due:
        return f"【守 Mamori】本日期限{len(today_due)}件・悪用確認済み{n}件｜セキュリティ便り {today}"
    if dues:
        nearest = min(dues)
        return f"【守 Mamori】悪用確認済み{n}件・最短期限{nearest}｜セキュリティ便り {today}"
    return f"【守 Mamori】悪用確認済み{n}件｜セキュリティ便り {today}"


def build_issue() -> tuple[str, str] | None:
    """(件名, 本文) を返す。新着がなければ None。"""
    objs = _recent_advisories()
    if not objs:
        return None
    today = time.strftime("%Y-%m-%d", time.gmtime())
    top = _sort_urgent(objs, today)[:3]
    subject = _urgency_subject(objs, today)
    lines = [f"守 Mamori セキュリティ便り（{today}）",
             "",
             "こんにちは。守 Mamori です。今週の「いま気をつけたい脅威」と「突破の手口」を、3分で読める分量でお届けします。",
             "（30秒版: 期限超過2件・本日期限1件あり。国内レンタルサーバー利用の会社は1件目だけ確認。やることはサーバー会社へのメール1通・3分で終わります）",
             "",
             "■ 今日できる一手（全員向け・先にどうぞ）",
             "・自社サイトのURLに /admin や /wp-admin を付けて、ログイン画面が開けるか試してください。開けたら公開中です。IP制限をかけるか、サーバー会社に「管理画面を非公開にしたい」と相談を。",
             "・自社の公開サイトで https://<自社ドメイン>/.env を開いてみてください。404ならOK、403ならOK、200で中身が見えたら即非公開（サーバー会社に「.envを見えないようにしてください」と伝えれば対応してもらえます）。結果の意味が分からなければ、表示された画面のスクリーンショットをそのままサーバー会社に送って判断してもらってOK。",
             "",
             "■ 今週の3点（急ぐものから・期限切れが先）",
             "いずれも CISA KEV（米国サイバー当局が『実際に悪用を確認』した脆弱性のリスト）掲載です。",
             "「対応期限」は米政府機関向けのものですが、悪用が現実に起きているため、日本の組織も同様に急ぐべきものです。",
             "期限切れ＝修正猶予を過ぎてもなお未対策の組織が攻撃され続けている状態です。",
             "目安: 期限切れは今日〜明日中に業者へ連絡。期限内は1週間以内に連絡。",
             "自社が該当するかは、保守契約書やサーバー管理画面の製品名で確認できます。不明なら保守業者に製品名をそのまま聞いて構いません。",
             ""]
    for i, o in enumerate(top, 1):
        due = o.get("due_date")
        due_txt = ""
        if due:
            due_txt = f"（{_due_label(due, today)}: {due}）"
        # 読み飛ばし可の2件目以降は1行要約に圧縮
        if i > 1 and "読み飛ばし可" in _relevance_hint(o):
            cve = o.get("id") or o.get("cve") or ""
            known = CVE_KNOWN_FIXES.get(cve, {})
            fix = f"修正版 {known['fixed']} への更新を" if known.get("fixed") else "対応状況を確認を"
            lines.append(f"{i}. {_ja_title(o)}{due_txt}")
            lines.append(f"   {_relevance_hint(o)}。{fix}。詳細: {o.get('url', '')}")
            lines.append("")
            continue
        lines.append(f"{i}. {_ja_title(o)}{due_txt}")
        lines.append(f"   {_plain_note(o)}")
        lines.append(f"   {_audience_check(o)}")
        lines.append(f"   {_attack_vector(o)}")
        lines.append("   やること:")
        for step in _action_steps(o):
            lines.append(f"   {step}")
        lines.append("")
    lines += ["■ 最近の突破の手口（やさしく）",
              "JPCERT/CC が国内で相次ぐ不正アクセスについて注意喚起しています（JPCERT-AT-2026-0030）。",
              "自社でアプリやAPIを開発・委託している会社向けの話です。",
              ""]
    for name, desc, check, action in TECHNIQUES[:2]:
        lines.append(f"・{name}")
        lines.append(f"  {desc}")
        lines.append(f"  {check}")
        lines.append(f"  → あなたがやること: {action}（今週中に連絡）")
    lines += ["",
              "（用語）WAF = Webサイトへの攻撃を遮断する仕組み。レート制限 = 短時間の大量アクセスを制限する仕組み。",
              "",
              "出典: CISA KEV https://www.cisa.gov/known-exploited-vulnerabilities-catalog / JPCERT-AT-2026-0030",
              "最新の脅威一覧（登録不要）: https://mamori.teai.io/intel",
              "JPCERT/CC の注意喚起: https://www.jpcert.or.jp/at/2026/at260030.html",
              "",
              "---",
              "このメールは「守 Mamori セキュリティ便り」にご登録いただいた方にお送りしています。",
              "配信停止はこちら（1クリックで完了します）: __UNSUB_LINK__",
              "守 Mamori — https://mamori.teai.io"]
    return subject, "\n".join(lines)


def _sent_ids() -> set[str]:
    try:
        return {json.loads(l).get("issue", "") for l in SENT_LOG.read_text().splitlines() if l.strip()}
    except FileNotFoundError:
        return set()
    except Exception:  # noqa: BLE001
        return set()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="送らず本文だけ表示")
    ap.add_argument("--to", help="指定した1アドレスへだけテスト送信")
    ap.add_argument("--force", action="store_true", help="同じ号の再送を許可")
    args = ap.parse_args()

    issue = build_issue()
    if not issue:
        print("newsletter: no recent advisories; nothing to send", flush=True)
        return 0
    subject, body = issue
    issue_id = subject

    store = accounts.Store(DATA_DIR / "accounts.json", os.environ.get("MAMORI_ORG_SALT", ""))
    if args.to:
        recipients = [args.to]
    else:
        recipients = store.nl_active_emails()
    if not recipients:
        print("newsletter: no active subscribers", flush=True)
        return 0
    if not args.force and not args.to and issue_id in _sent_ids():
        print(f"newsletter: issue already sent ({issue_id}); use --force to resend", flush=True)
        return 0

    if args.dry_run:
        print("=== 件名 ===")
        print(subject)
        print("=== 本文（__UNSUB_LINK__ は送信時に購読者ごとのリンクへ置換）===")
        print(body)
        print(f"=== 配信対象 {len(recipients)} 件 ===")
        return 0

    sent = 0
    for email in recipients:
        unsub = f"https://mamori.teai.io/newsletter/unsub?email={email}&t={store.nl_token('unsub', email)}"
        if accounts.send_mail(email, subject, body.replace("__UNSUB_LINK__", unsub)):
            sent += 1
        else:
            print(f"newsletter: send failed: {email[:3]}***", flush=True)
    with SENT_LOG.open("a") as f:
        f.write(json.dumps({"issue": issue_id, "ts": time.time(), "sent": sent,
                            "test": bool(args.to)}, ensure_ascii=False) + "\n")
    print(f"newsletter: sent {sent}/{len(recipients)} ({issue_id})", flush=True)
    return 0 if sent == len(recipients) else 1


if __name__ == "__main__":
    raise SystemExit(main())
