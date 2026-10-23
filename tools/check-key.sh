#!/usr/bin/env bash
# 組織専用キーが有効か確かめる（キー本体は表示しません）。
#   使い方: MAMORI_KEY=<組織専用キー> bash tools/check-key.sh
set -euo pipefail
HUB="${MAMORI_HUB:-https://mamori.teai.io}"
: "${MAMORI_KEY:?MAMORI_KEY に組織専用キーを入れてください}"
curl -sS "$HUB/api/whoami" -H "X-Mamori-Key: $MAMORI_KEY"
echo
