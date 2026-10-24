#!/usr/bin/env bash
# 守 Mamori — AIエージェントへのかんたん導入（Claude Code / Codex / Sente）
#
#   curl -fsSL https://mamori.teai.io/install.sh | bash
#   curl -fsSL https://mamori.teai.io/install.sh | MAMORI_KEY=mk_... bash     # 共有もするとき
#   curl -fsSL https://mamori.teai.io/install.sh | bash -s -- --uninstall       # 外す
#
# やること:
#   1. キット一式を ~/.mamori/kit に置く（標準ライブラリだけ・追加ソフト不要）
#   2. キーがあれば ~/.config/mamori/key（権限600）に保存（設定ファイルには書かない）
#   3. 入っている AI ツールに MCP サーバー「mamori」を登録
#        Claude Code: claude mcp add -s user / Codex: codex mcp add / Sente: ~/.config/sente/sente.json
#   4. 自己テスト（脅威情報を1回取得・キーがあれば有効性確認）
# オプション: --only claude,codex,sente  --no-skill  --uninstall
set -euo pipefail

HUB="${MAMORI_HUB:-https://mamori.teai.io}"
KIT_DIR="${MAMORI_HOME:-$HOME/.mamori}/kit"
KEY_FILE="$HOME/.config/mamori/key"
MCP="$KIT_DIR/mamori/mcp/mamori_mcp.py"
ONLY="claude,codex,sente"
SKILL=1
UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --only) ONLY="$2"; shift 2 ;;
    --only=*) ONLY="${1#*=}"; shift ;;
    --no-skill) SKILL=0; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '2,16p' "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "不明なオプション: $1" >&2; exit 2 ;;
  esac
done

want() { case ",$ONLY," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }
ok()   { printf '  ✅ %s\n' "$*"; }
skip() { printf '  ・ %s\n' "$*"; }
ng()   { printf '  ⚠️  %s\n' "$*"; }

PY="$(command -v python3 || true)"
if [ -z "$PY" ]; then
  echo "python3 が見つかりません。Mac は「xcode-select --install」、Linux は「apt install python3」等で入れてから再実行してください。" >&2
  exit 1
fi
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || { echo "Python 3.8 以上が必要です" >&2; exit 1; }

# Sente の設定（JSON）に mamori を足す／外す。既存の内容は保ち、変更前の控えを残す。
sente_config() {  # $1 = add|remove
  "$PY" - "$1" "$PY" "$MCP" <<'PYEOF'
import json, os, shutil, sys, time
action, py, mcp = sys.argv[1:4]
d = os.path.expanduser("~/.config/sente")
p = os.path.join(d, "sente.json")
data = {}
if os.path.exists(p):
    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    shutil.copy2(p, p + ".bak-mamori-" + time.strftime("%Y%m%d%H%M%S"))
elif action == "remove":
    sys.exit(0)
else:
    os.makedirs(d, exist_ok=True)
    data = {"$schema": "https://teai.io/sente/config.json"}
servers = data.setdefault("mcp", {})
perm = data.get("permission")
if not isinstance(perm, dict):
    perm = {} if perm is None else {"*": perm}
    data["permission"] = perm
# 読むだけのツールは確認なしで通す。共有（mamori_share）は送信なので毎回確認する。
READ_ONLY = ["mamori_mamori_latest", "mamori_mamori_intel_summary",
             "mamori_mamori_observations", "mamori_mamori_whoami"]
if action == "add":
    servers["mamori"] = {"type": "local", "command": [py, mcp], "enabled": True}
    for t in READ_ONLY:
        perm[t] = "allow"
else:
    servers.pop("mamori", None)
    for t in READ_ONLY:
        perm.pop(t, None)
    if not perm:
        data.pop("permission", None)
tmp = p + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=2)
    f.write("\n")
os.replace(tmp, p)
PYEOF
}

if [ "$UNINSTALL" = 1 ]; then
  echo "守 Mamori を外します"
  if want claude && command -v claude >/dev/null 2>&1; then claude mcp remove -s user mamori >/dev/null 2>&1 && ok "Claude Code から外しました" || skip "Claude Code: 登録なし"; fi
  if want codex && command -v codex >/dev/null 2>&1; then codex mcp remove mamori >/dev/null 2>&1 && ok "Codex から外しました" || skip "Codex: 登録なし"; fi
  if want sente && [ -f "$HOME/.config/sente/sente.json" ]; then sente_config remove && ok "Sente から外しました"; fi
  rm -rf "$HOME/.claude/skills/mamori"
  echo "キット（$KIT_DIR）とキー（$KEY_FILE）は残しています。不要なら手で削除してください。"
  exit 0
fi

echo "守 Mamori を AI エージェントに入れます"

# 1. キット
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL "$HUB/kit.tar.gz" -o "$TMP/kit.tgz"
mkdir -p "$TMP/x" && tar xzf "$TMP/kit.tgz" -C "$TMP/x"
[ -f "$TMP/x/mamori/mcp/mamori_mcp.py" ] || { echo "キットの中身が想定と違います" >&2; exit 1; }
mkdir -p "$(dirname "$KIT_DIR")"
rm -rf "$KIT_DIR.old"; [ -d "$KIT_DIR" ] && mv "$KIT_DIR" "$KIT_DIR.old"
mv "$TMP/x" "$KIT_DIR"; rm -rf "$KIT_DIR.old"
ok "キット: $KIT_DIR/mamori"

# 2. キー（任意）
if [ -n "${MAMORI_KEY:-}" ]; then
  code="$(curl -s -o /dev/null -w '%{http_code}' -H "X-Mamori-Key: $MAMORI_KEY" "$HUB/api/whoami" || true)"
  if [ "$code" = 200 ]; then
    mkdir -p "$(dirname "$KEY_FILE")"; chmod 700 "$(dirname "$KEY_FILE")"
    (umask 077; printf '%s\n' "$MAMORI_KEY" > "$KEY_FILE")
    ok "キー: 有効・$KEY_FILE に保存（権限600）"
  else
    ng "キーを確認できませんでした（HTTP $code）。保存せずに続けます"
    unset MAMORI_KEY
  fi
elif [ -f "$KEY_FILE" ]; then
  ok "キー: 保存済みのものを使います"
else
  skip "キー: なし（脅威情報を読むだけなら不要。共有するときは $HUB/account で発行）"
fi

# 3. AI ツールへ登録
FOUND=0
if want claude; then
  if command -v claude >/dev/null 2>&1; then
    claude mcp remove -s user mamori >/dev/null 2>&1 || true
    if claude mcp add -s user mamori -- "$PY" "$MCP" >/dev/null 2>&1; then
      ok "Claude Code に登録"; FOUND=1
      if [ "$SKILL" = 1 ]; then
        mkdir -p "$HOME/.claude/skills/mamori"
        cp "$KIT_DIR/mamori/tools/sente-skill/mamori/SKILL.md" "$HOME/.claude/skills/mamori/SKILL.md"
      fi
    else ng "Claude Code への登録に失敗"; fi
  else skip "Claude Code: 見つかりません"; fi
fi
if want codex; then
  if command -v codex >/dev/null 2>&1; then
    codex mcp remove mamori >/dev/null 2>&1 || true
    if codex mcp add mamori -- "$PY" "$MCP" >/dev/null 2>&1; then ok "Codex に登録"; FOUND=1
    else ng "Codex への登録に失敗"; fi
  else skip "Codex: 見つかりません"; fi
fi
if want sente; then
  if command -v sente >/dev/null 2>&1 || [ -d "$HOME/.config/sente" ]; then
    if sente_config add; then
      ok "Sente に登録"; FOUND=1
      if [ "$SKILL" = 1 ]; then
        mkdir -p "$HOME/.config/sente/skill/mamori"
        cp "$KIT_DIR/mamori/tools/sente-skill/mamori/SKILL.md" "$HOME/.config/sente/skill/mamori/SKILL.md"
      fi
    else ng "Sente への登録に失敗"; fi
  else skip "Sente: 見つかりません"; fi
fi

# 4. 自己テスト
echo "動作確認"
if "$PY" "$MCP" --selftest > "$TMP/selftest.txt" 2>&1; then
  ok "脅威情報を取得できました（$(sed -n 3p "$TMP/selftest.txt")）"
  grep -q '^キーは有効' "$TMP/selftest.txt" && ok "$(grep '^キーは有効' "$TMP/selftest.txt")"
else
  ng "自己テストに失敗しました:"; sed 's/^/     /' "$TMP/selftest.txt"; exit 1
fi

echo
if [ "$FOUND" = 1 ]; then
  cat <<'MSG'
準備できました。AI ツールを開き直して、こう話しかけてください:
  「Mamori で最新の攻撃情報を教えて」
  「Mamori で共有されている攻撃の手口を見せて」（キーが必要）
  「この攻撃を Mamori に共有して: /wp-login.php への総当たり」（キーが必要）
外すとき: curl -fsSL https://mamori.teai.io/install.sh | bash -s -- --uninstall
MSG
else
  echo "Claude Code / Codex / Sente が見つかりませんでした。入れてから再実行するか、MCP 設定に次を登録してください:"
  echo "  command: $PY  args: $MCP"
fi
