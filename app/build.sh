#!/usr/bin/env bash
# 守 Mamori メニューバーアプリをビルドして ~/Applications に配置する。
# 点検エンジン（agent/*.py）を .app に同梱するので、ダウンロードしただけで動く。
# 署名は Developer ID があればそれを使い、なければ ad-hoc で通す。
#
#   ./build.sh            # ビルドして ~/Applications/守.app と dist/MamoriBar.zip を作る
#   ./build.sh --no-install  # ビルドと zip だけ（配置しない）
set -euo pipefail
cd "$(dirname "$0")"
APP_DIR="$(cd .. && pwd)"

APP_NAME="MamoriBar"
BUNDLE_ID="io.teai.mamori.bar"
VERSION="0.4.0"
INSTALL=1
[ "${1:-}" = "--no-install" ] && INSTALL=0
DEST="${MAMORI_APP_DIR:-$HOME/Applications}/守.app"

echo "[build] swift build -c release"
swift build -c release
BIN=".build/release/$APP_NAME"

BUNDLE=".build/$APP_NAME.app"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/Contents/MacOS" "$BUNDLE/Contents/Resources/agent"
cp "$BIN" "$BUNDLE/Contents/MacOS/$APP_NAME"

# 点検エンジンを同梱（stdlib のみ・オフラインでも動く）
for f in daily.py mamori_guard.py attacks.py; do
  cp "$APP_DIR/agent/$f" "$BUNDLE/Contents/Resources/agent/$f"
done
echo "[bundle] agent/ を同梱（daily.py, mamori_guard.py, attacks.py）"

cat > "$BUNDLE/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>守</string>
  <key>CFBundleDisplayName</key><string>守 Mamori</string>
  <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleExecutable</key><string>$APP_NAME</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSHumanReadableCopyright</key><string>Enabler / teai.io</string>
</dict></plist>
PLIST

# 署名: Developer ID があれば使い、無ければ ad-hoc
IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null | sed -n 's/.*"\(Developer ID Application: [^"]*\)".*/\1/p' | head -1)"
# 拡張属性（.app 内の ._ ファイル）は署名を壊すので先に落とす
xattr -cr "$BUNDLE" 2>/dev/null || true
if [ -n "$IDENTITY" ]; then
  echo "[sign] $IDENTITY"
  codesign --force --deep --options runtime --sign "$IDENTITY" "$BUNDLE"
else
  echo "[sign] ad-hoc（Developer ID が見つかりません）"
  codesign --force --deep --sign - "$BUNDLE"
fi

# 配布用 zip（拡張属性を持ち込まない。持ち込むと展開後に署名が壊れる）
mkdir -p "$APP_DIR/dist"
ZIP="$APP_DIR/dist/MamoriBar.zip"
rm -f "$ZIP"
ditto -c -k --keepParent --norsrc --noextattr "$BUNDLE" "$ZIP"
echo "[zip] $ZIP ($(du -h "$ZIP" | cut -f1))"

# 公証 + staple（Developer ID 署名済みのときだけ）。notarytool の
# キーチェーンプロファイルは MAMORI_NOTARY_PROFILE（既定 "notary"）。
# 失敗しても署名済み zip は残すが、Gatekeeper-clean 配布には公証が要る。
if [ -n "$IDENTITY" ]; then
  NOTARY_PROFILE="${MAMORI_NOTARY_PROFILE:-notary}"
  echo "[notarize] submit $ZIP (profile: $NOTARY_PROFILE)"
  if xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait; then
    xcrun stapler staple "$BUNDLE"
    xcrun stapler validate "$BUNDLE"
    # staple 後の .app で zip を作り直す（staple チケットを同梱するため）
    rm -f "$ZIP"
    ditto -c -k --keepParent --norsrc --noextattr "$BUNDLE" "$ZIP"
    echo "[notarize] stapled & re-zipped: $ZIP"
  else
    echo "[notarize] WARN: notarization failed; zip is signed but NOT notarized" >&2
  fi
fi

if [ "$INSTALL" = 1 ]; then
  mkdir -p "$(dirname "$DEST")"
  rm -rf "$DEST"
  cp -R "$BUNDLE" "$DEST"
  codesign --verify --verbose=2 "$DEST" 2>&1 | tail -1 || true
  echo "[done] $DEST"
fi
