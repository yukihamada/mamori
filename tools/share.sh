#!/usr/bin/env bash
# 観測した攻撃をMamoriハブに共有する。
#   使い方: MAMORI_KEY=<組織専用キー> bash tools/share.sh "wp-login.php への総当たり" 412 GREEN
#   TLP: CLEAR=誰でも / GREEN=参加者 / AMBER=限定参加者（既定 GREEN。RED は送れません）
# 送る前に、自社ドメイン・社内ホスト名・個人名などは取り除いてください。
set -euo pipefail
HUB="${MAMORI_HUB:-https://mamori.teai.io}"
: "${MAMORI_KEY:?MAMORI_KEY に組織専用キーを入れてください}"
PATTERN="${1:?何を観測したか（例: wp-login.php への総当たり）}"
COUNT="${2:-1}"
TLP="${3:-GREEN}"
BODY=$(python3 -c 'import json,sys; print(json.dumps({"type":"attack-observation","pattern":sys.argv[1],"count":int(sys.argv[2]),"tlp":sys.argv[3]}, ensure_ascii=False))' "$PATTERN" "$COUNT" "$TLP")
curl -sS -X POST "$HUB/api/observations" \
  -H "X-Mamori-Key: $MAMORI_KEY" -H "Content-Type: application/json" \
  --data "$BODY"
echo
