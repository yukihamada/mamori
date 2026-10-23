#!/usr/bin/env bash
# ほかの参加者が共有した攻撃の観測を一覧で見る（自分のキーで見られる範囲・直近90日）。
#   使い方: MAMORI_KEY=<組織専用キー> bash tools/feed.sh
set -euo pipefail
HUB="${MAMORI_HUB:-https://mamori.teai.io}"
: "${MAMORI_KEY:?MAMORI_KEY に組織専用キーを入れてください}"
curl -sS "$HUB/api/observations" -H "X-Mamori-Key: $MAMORI_KEY" | python3 -c '
import json, sys, time
d = json.load(sys.stdin)
if "observations" not in d:
    sys.exit("取得できませんでした: " + json.dumps(d, ensure_ascii=False))
color = {"CLEAR": "白", "GREEN": "緑", "AMBER": "黄"}
obs = sorted(d["observations"], key=lambda o: o.get("received_at", 0), reverse=True)
print(f"共有された観測 {len(obs)}件（新しい順）")
for o in obs:
    t = time.strftime("%m-%d %H時", time.localtime(o.get("received_at", 0)))
    print(f"- {t}  [{color.get(o.get(\"tlp\"), o.get(\"tlp\"))}]  {o.get(\"pattern\", o.get(\"type\"))}  {o.get(\"count\", \"\")}回  (組織 {o.get(\"org_hash\", \"-\")})")
'
