#!/usr/bin/env bash
# 守 Mamori Guard — macOS / Linux の守りを点検し、安全な項目を自動で直して、毎日の自動点検を登録する。
#   curl -fsSL -H "X-Mamori-Key: $(cat ~/.config/mamori/key)" https://mamori.teai.io/kit.tar.gz | tar xz && sudo bash mamori/tools/guard.sh
#   点検だけ: bash mamori/tools/guard.sh --scan-only
#   止める:   sudo python3 "<保存先>/mamori_guard.py" uninstall   戻す: ... rollback
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
G="$HERE/agent/mamori_guard.py"
command -v python3 >/dev/null || { echo "✖ python3 が必要です（Linux: apt-get install -y python3 / macOS: xcode-select --install）" >&2; exit 1; }
if [ "${1:-}" = "--scan-only" ]; then exec python3 "$G" scan; fi
if [ "$(id -u)" != "0" ]; then
  echo "ℹ 管理者権限なしで実行します（直せるのはユーザー権限の項目だけ）。全部直すには: sudo bash $0"
fi
python3 "$G" fix --auto "$@"
python3 "$G" install --hour "${MAMORI_HOUR:-9}"
# 先手（Sente）を使っていれば、Mamori スキルを入れて「守りを固めて」で呼べるようにする
U="${SUDO_USER:-$(id -un)}"; UH=$(eval echo "~$U")
if [ -d "$UH/.config/sente" ]; then
  mkdir -p "$UH/.config/sente/skill/mamori" && cp "$HERE/tools/sente-skill/mamori/SKILL.md" "$UH/.config/sente/skill/mamori/SKILL.md"
  chown -R "$U" "$UH/.config/sente/skill/mamori" 2>/dev/null || true
  echo "✅ 先手（Sente）に Mamori スキルを入れました"
fi
echo "✅ 毎日の自動点検を登録しました。承認が要る項目は上の「承認して直す」の行をそのまま実行してください。"
