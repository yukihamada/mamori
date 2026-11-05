#!/usr/bin/env bash
# 守 Mamori — 毎日の定量化とメニューバーアプリをこのMacに常駐させる。
#
#   1. daily.py を ~/.mamori/daily.py に置く（安定パス）
#   2. launchd に毎日 9:17 の点検＋自動修正を登録（tier=auto のみ）
#   3. メニューバーアプリ「守」をビルドして ~/Applications に配置し、ログイン時に起動
#
# 使い方:  bash agent/install_daily.sh          # 導入
#          bash agent/install_daily.sh --hour 8 # 時刻を変える
#          bash agent/install_daily.sh --uninstall
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
STATE="$HOME/.mamori"
LABEL="io.teai.mamori.daily"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
PY="/usr/bin/python3"
[ -x "$PY" ] || PY="$(command -v python3)"
HOUR=9
MODE="install"

while [ $# -gt 0 ]; do
  case "$1" in
    --hour) HOUR="$2"; shift 2 ;;
    --uninstall) MODE="uninstall"; shift ;;
    *) echo "不明な引数: $1"; exit 2 ;;
  esac
done

if [ "$MODE" = "uninstall" ]; then
  launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
  echo "[uninstall] launchd から外しました（アプリは ~/Applications/守.app に残ります）"
  exit 0
fi

mkdir -p "$STATE" "$HOME/Library/LaunchAgents"
cp "$HERE/daily.py" "$STATE/daily.py"
echo "[install] $STATE/daily.py を配置"

cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array>
    <string>$PY</string>
    <string>$STATE/daily.py</string>
    <string>--fix</string>
    <string>--quiet</string>
  </array>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>$HOUR</integer><key>Minute</key><integer>17</integer></dict>
  <key>RunAtLoad</key><false/>
  <key>StandardOutPath</key><string>$STATE/daily.log</string>
  <key>StandardErrorPath</key><string>$STATE/daily.log</string>
</dict></plist>
PLIST
launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "[install] launchd $LABEL 毎日 $HOUR:17（点検＋自動修正）"

# アプリ
if [ -x "$ROOT/app/build.sh" ]; then
  bash "$ROOT/app/build.sh"
  APP="$HOME/Applications/守.app"
  # ログイン時に起動（LSUIElement なので Dock には出ない）
  osascript -e "tell application \"System Events\" to make login item at end with properties {path:\"$APP\", hidden:false}" >/dev/null 2>&1 \
    && echo "[install] ログイン時に「守」を起動するよう登録" || echo "[warn] ログイン項目の登録に失敗（手動で追加してください）"
  open "$APP" 2>/dev/null || true
  echo "[install] アプリ: $APP"
fi

echo
echo "導入できました。初回だけ点検を走らせます…"
"$PY" "$STATE/daily.py" --fix --quiet || true
echo "メニューバー右上の「守」の数字をクリックすると内訳が見られます。"
