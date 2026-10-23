#!/usr/bin/env bash
# Mamori — 資産収集→脅威フィード取得→照合→レポート生成を一括で回す。
# cron / launchd から定期実行する想定。失敗しても既存データを壊さないよう
# 各段で新ファイルに書いてから差し替える。
set -euo pipefail
cd "$(dirname "$0")/.."

STAMP=$(date +%Y%m%dT%H%M)
echo "[refresh] $STAMP 資産収集..."
python3 agent/asset_inventory.py

echo "[refresh] フィード取得..."
python3 agent/fetch_feeds.py > data/raw.new.json
mv data/raw.new.json data/raw.json
cp data/raw.json data/latest_bundle.json

echo "[refresh] 照合（自動生成インベントリ使用）..."
python3 agent/match_inventory.py data/raw.json data/inventory.json > data/matched.new.json
mv data/matched.new.json data/matched.json

echo "[refresh] レポート生成..."
python3 agent/draft_actions.py data/matched.json > data/out.new.json
mv data/out.new.json data/out.json
python3 - <<'PY'
import json
out = json.load(open('data/out.json'))
open('data/reports/report-latest.md', 'w').write(out['report_md'])
json.dump(out['share_bundle'], open('data/stix_bundle.json', 'w'), ensure_ascii=False, indent=2)
m = json.load(open('data/matched.json'))
s = m.get('summary', {})
print(f"[refresh] 完了: 取得{s.get('total')}件 / 要対応{s.get('relevant')}件 / 要確認{s.get('maybe')}件")
for it in m.get('items', []):
    if it.get('match', {}).get('status') == 'relevant':
        print(f"  🔴 {it['id']} {it.get('title','')[:70]} hits={it['match']['hits']}")
PY
