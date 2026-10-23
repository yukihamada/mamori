#!/usr/bin/env bash
# Mamori pipeline: fetch -> match -> draft -> update hub's latest bundle
set -euo pipefail
cd "$(dirname "$0")"
DATA_DIR="${MAMORI_DATA:-./data}"
mkdir -p "$DATA_DIR/reports"

python3 agent/fetch_feeds.py > "$DATA_DIR/raw.json"
# 自社の製品リスト: MAMORI_INVENTORY > ./inventory.json > 見本（運営の構成）の順
INV="${MAMORI_INVENTORY:-}"
if [ -z "$INV" ] && [ -f inventory.json ]; then INV=inventory.json; fi
if [ -z "$INV" ]; then
  echo "⚠ inventory.json がありません。見本（運営の構成）で照合します。" >&2
  echo "  cp examples/inventory.example.json inventory.json で自社の製品を書いてください。" >&2
fi
python3 agent/match_inventory.py "$DATA_DIR/raw.json" $INV > "$DATA_DIR/matched.json"
python3 agent/draft_actions.py "$DATA_DIR/matched.json" > "$DATA_DIR/out.json"

python3 - "$DATA_DIR" <<'EOF'
import json, sys, pathlib
d = pathlib.Path(sys.argv[1])
out = json.loads((d/"out.json").read_text())
(d/"latest_bundle.json").write_text(json.dumps(out["share_bundle"], ensure_ascii=False, indent=2))
from datetime import datetime, timedelta, timezone
fa = json.loads((d/"matched.json").read_text())["fetched_at"]
stamp = datetime.fromisoformat(fa).astimezone(timezone(timedelta(hours=9))).strftime("%Y%m%dT%H%M")
(d/"reports"/f"report-{stamp}.md").write_text(out["report_md"])
print(out["report_md"][:800])
print(f"\n→ 全文: {d}/reports/report-{stamp}.md")
EOF
