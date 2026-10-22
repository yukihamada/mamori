#!/usr/bin/env bash
# Mamori pipeline: fetch -> match -> draft -> update hub's latest bundle
set -euo pipefail
cd "$(dirname "$0")"
DATA_DIR="${MAMORI_DATA:-./data}"
mkdir -p "$DATA_DIR/reports"

python3 agent/fetch_feeds.py > "$DATA_DIR/raw.json"
python3 agent/match_inventory.py "$DATA_DIR/raw.json" ${MAMORI_INVENTORY:-} > "$DATA_DIR/matched.json"
python3 agent/draft_actions.py "$DATA_DIR/matched.json" > "$DATA_DIR/out.json"

python3 - "$DATA_DIR" <<'EOF'
import json, sys, pathlib
d = pathlib.Path(sys.argv[1])
out = json.loads((d/"out.json").read_text())
(d/"latest_bundle.json").write_text(json.dumps(out["share_bundle"], ensure_ascii=False, indent=2))
stamp = json.loads((d/"matched.json").read_text())["fetched_at"][:16].replace(":","").replace("-","")
(d/"reports"/f"report-{stamp}.md").write_text(out["report_md"])
print(out["report_md"][:800])
EOF
