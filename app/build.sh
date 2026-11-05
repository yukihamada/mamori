#!/usr/bin/env bash
# 守 Mamori メニューバーアプリをビルドして ~/Applications に配置する。
# 署名は Developer ID（5BV85JW8US）があればそれを使い、なければ ad-hoc で通す。
set -euo pipefail
cd "$(dirname "$0")"

APP_NAME="MamoriBar"
BUNDLE_ID="io.teai.mamori.bar"
VERSION="0.1.0"
DEST="${MAMORI_APP_DIR:-$HOME/Applications}/守.app"

echo "[build] swift build -c release"
swift build -c release
BIN=".build/release/$APP_NAME"

BUNDLE=".build/$APP_NAME.app"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/Contents/MacOS" "$BUNDLE/Contents/Resources"
cp "$BIN" "$BUNDLE/Contents/MacOS/$APP_NAME"

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
</dict></plist>
PLIST

# 署名: Developer ID があれば使い、無ければ ad-hoc
IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null | sed -n 's/.*"\(Developer ID Application: Yuki Hamada ([A-Z0-9]*)\)".*/\1/p' | head -1)"
if [ -n "$IDENTITY" ]; then
  echo "[sign] $IDENTITY"
  codesign --force --deep --options runtime --sign "$IDENTITY" "$BUNDLE"
else
  echo "[sign] ad-hoc（Developer ID が見つかりません）"
  codesign --force --deep --sign - "$BUNDLE"
fi

mkdir -p "$(dirname "$DEST")"
rm -rf "$DEST"
cp -R "$BUNDLE" "$DEST"
codesign --verify --verbose=2 "$DEST" 2>&1 | tail -1 || true
echo "[done] $DEST"
