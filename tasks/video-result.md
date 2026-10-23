# Mamori 説明動画（mamori-first-share）— 結果・状態

## 状態: 🔴 承認待ち（teai 声クレジットのチャージ承認が必要）

## 完了済み
- 台本（6セグメント、4構成: 問いかけ→実際の攻撃3例→共有・照合→正直な約束→6時間ごと・無料）
  - `tools/build_first_share.py` 内 `SEGMENTS`（表示文・字幕・合成文を分離、phpinfo→ぴーえいちぴーインフォ等の読み指定済み）
- スライド6枚（1920x1080、字幕焼き込み、Mamoriブランド）: `tools/work-first-share/seg0..5.png` — 実表示で目視確認済み
- 合成パイプライン完成: `tools/build_first_share.py`（teai `/api/v1/voice/*`、voice=yukihamada、speed=1、lang=ja → ffmpeg concat → `media/mamori-first-share.mp4` / `.jpg`）
- quote照合済み: 8cr/回（standard verbatim、600字上限）× 6回 = **48cr 見込み**（500cr継続承認の範囲内）

## ブロッカー
- teai の**声クレジット残高が0**（`/api/v1/voice/generate` → 402 insufficient_credits。standard/fast 両モードで確認）
- LLM用アカウント残高（1000cr, plan=free）は別プールで声合成には使えない
- チャージは `te topup [yen]`（¥1=6cr、既定¥10000）= **現金課金のため本人承認が必要**。48cr必要 → 最小チャージで十分

## 残件（承認後の手順）
1. `te topup` でチャージ（本人操作）
2. `cd ~/workspace/mamori && python3 tools/build_first_share.py` を再実行（スライドはキャッシュ済み、音声合成から再開）
3. 基本確認（全編デコード・実尺60〜90秒・音量）→ 試聴版を本人へ
4. 本人確認後に公開（公開は別途承認）

## 検証結果
- スライド: 6枚生成・1枚目視確認 ✅
- 音声: 未生成（402のため）— 発音確認も未実施 / unverified
- 動画: 未合成
