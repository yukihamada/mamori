# CLAUDE.md — 守 Mamori (mamori.teai.io)

セキュリティ相互防御ハブ。CISA KEV・JPCERT/CC の脅威情報を6時間ごとに自動収集し、
自社スタックとの照合・対策下書き・参加者同士の攻撃観測共有（TLP付き・自動匿名化）を行う。

## 構成
- `hub/server.py` — Fly.io `mamori-hub` 本番（stdlib only の ThreadingHTTPServer）。ルート・HTML・API全部入り
- `hub/accounts.py` — メールリンクログイン・参加者キー発行。Resend で送信（`RESEND_API_KEY`、from: `守 Mamori <noreply@teai.io>`）
- `hub/pages/` — start.html / intel.html テンプレ（`__XXX__` 置換方式）
- `agent/mamori_guard.py` — 端末守りスキャン/fix キット
- `data/` — observations.jsonl / accounts.json 等（Fly volume `mamori_data` → /app/data）
- `tests/` — pytest（test_mamori.py / test_v05.py 等）

## ルール
- デプロイは **git push → GitHub Actions のみ**。`fly deploy` 直叩き禁止（個人共通指示）
- サーバーは標準ライブラリのみ（依存追加しない）
- メール送信は `accounts.send_mail()`（`MAMORI_MAIL_OUTBOX` 設定時はファイル書き出し=テスト用）
- 観測・メール等の個人情報はハッシュ/匿名化して保存。TLP:RED は共有禁止
- 検証: `python3 -m pytest tests/` が通ること。ローカル起動は `MAMORI_NO_REFRESH=1 PORT=8080 python3 hub/server.py`

## デプロイ後の確認
`curl -s https://mamori.teai.io/healthz` が ok であること。変更したルートを1回実アクセスで確認する。
