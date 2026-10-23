#!/usr/bin/env bash
# 参加者が共有した攻撃の観測を一覧で見る（自分のキーで見られる範囲・直近90日）。自社の行には（自社）と付く。
#   使い方: MAMORI_KEY=<組織専用キー> bash tools/feed.sh
set -euo pipefail
HUB="${MAMORI_HUB:-https://mamori.teai.io}"
: "${MAMORI_KEY:?MAMORI_KEY に組織専用キーを入れてください}"
ME=$(curl -sS "$HUB/api/whoami" -H "X-Mamori-Key: $MAMORI_KEY" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("org_hash","") if d.get("ok") else "")')
if [ -z "$ME" ]; then
  echo "✖ キーが確認できません。MAMORI_KEY の写し間違いがないか確かめてください（bash tools/check-key.sh）。" >&2
  exit 1
fi
PY=$(cat <<'PYEOF'
import json, os, sys, time
d = json.load(sys.stdin)
if "observations" not in d:
    sys.exit("取得できませんでした: " + json.dumps(d, ensure_ascii=False))
me = os.environ.get("ME", "")
color = {"CLEAR": "白", "GREEN": "緑", "AMBER": "黄"}
obs = sorted(d["observations"], key=lambda o: o.get("received_at", 0), reverse=True)
print(f"共有された観測 {len(obs)}件（新しい順）")
for o in obs:
    t = time.strftime("%m-%d %H時", time.localtime(o.get("received_at", 0)))
    tlp = color.get(o.get("tlp"), o.get("tlp"))
    what = o.get("pattern", o.get("type"))
    who = "（自社）" if o.get("org_hash") == me else f"(組織 {o.get('org_hash', '-')})"
    print(f"- {t}  [{tlp}]  {what}  {o.get('count', '')}回  {who}")
PYEOF
)
curl -sS "$HUB/api/observations" -H "X-Mamori-Key: $MAMORI_KEY" | ME="$ME" python3 -c "$PY"
