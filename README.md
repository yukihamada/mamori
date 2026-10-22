# 守（Mamori）— セキュリティの民主化エージェント

**みんなでレポートして、みんなで守る。**

Mamoriは、最新の攻撃情報・脆弱性情報を自動で集め、自分の環境への適用範囲を照合し、対策の下書きまで出すセキュリティエージェントです。ある1社・1人が受けた攻撃の知見（IoC）をTLP管理つきで共有し、全員の防御に変える「集団免疫」を目指します。

- 製品ページ: https://teai.io/mamori
- ハブ: https://mamori.teai.io/
- Live Intel（認証不要・TLP:CLEAR）: https://mamori.teai.io/api/latest
- 公開カウンタ: https://mamori.teai.io/api/stats

## できること

1. **受信・照合（守りの更新ループ）**
   - CISA KEV（悪用確認済み脆弱性カタログ）、JPCERT/CC週報を定期取得
   - 自分のスタック（`agent/match_inventory.py` の watch リスト）と照合し、「要対応 / 要確認 / 関係なし」に分類
   - 関係あるものは対策チェックリスト（バージョン確認・CISA指定対応・期限）を下書き
2. **共有（相互防御・TLP管理）**
   - 観測した攻撃をTLPラベル（CLEAR/GREEN/AMBER）付きで共有ハブへ投稿
   - ハブ側で自動匿名化（IP /24丸め・メール除去・時刻を1時間単位に丸め）
   - TLP:RED（共有不可）は投稿自体を拒否
3. **証跡**
   - レポートは `data/reports/` に日次保存。観測データは90日で自動削除

## 使い方

### 脅威レポートを受け取るだけ（キー不要）
```bash
curl -s https://mamori.teai.io/api/latest
```

### 自分のスタックと照合する（ローカル）
```bash
cd mamori
# agent/match_inventory.py の DEFAULT_INVENTORY を自社構成に合わせて編集
bash run.sh   # data/reports/report-*.md に日次レポート
```

cron例（毎朝9時）:
```
0 9 * * * cd /path/to/mamori && bash run.sh >> data/cron.log 2>&1
```

### ハブ起動（自前運用する場合）
```bash
# 参加者ごとのキーをJSONで定義
MAMORI_KEYS_JSON='{"key-alpha-001":{"org":"your-org","tlp_max":"AMBER"}}' \
  python3 hub/server.py
```

## API（ハブ）

| エンドポイント | 認証 | 説明 |
|---|---|---|
| `GET /` | 不要 | ランディングページ（ライブ統計つき） |
| `GET /api/latest` | 不要 | 最新の脅威インテル（TLP:CLEAR） |
| `GET /api/stats` | 不要 | 参加組織数・観測件数・最終更新のカウンタ |
| `POST /api/observations` | 参加者キー | 攻撃観測の投稿（TLP付・64KB上限・30回/時） |
| `GET /api/observations` | 参加者キー | 自分のTLP権限までの観測一覧（直近200件） |

観測の投稿例：

```bash
curl -X POST https://mamori.teai.io/api/observations \
  -H "X-Mamori-Key: <組織専用キー>" -H "Content-Type: application/json" \
  -d '{"type":"attack-observation","tlp":"GREEN",
       "pattern":"wp-login.php brute force","count":412}'
```

## 投稿者の保護（設計で担保）

- **参加者専用キー**：組織ごとに発行・失効可能（`MAMORI_KEYS_JSON`）
- **自動匿名化**：IPは /24 丸め、メールアドレス除去、時刻は1時間単位に丸め
- **TLPラベル**：CLEAR/GREEN/AMBERで共有範囲を投稿者が制御。REDは拒否
- **組織名非公開**：観測には組織名ではなくハッシュを付記。公開統計は件数のみ
- **保持期間**：観測は90日で自動削除。削除依頼は随時受付
- **レート制限**：投稿30回/時・読取120回/時

それでも識別可能な情報（自社ドメイン・内部ホスト名等）は投稿前に除いてください。

## 設計メモ

- 依存は Python 標準ライブラリのみ（ハブもエージェントも）。壊れにくさ優先。
- マッチングはキーワード照合の v0.2。CPE/SBOMベースの照合、STIX 2.1/TAXIIエクスポートはロードマップ。
- 対策の**実行**（パッチ適用・WAF追加）は本エージェントは行わず、下書き＋承認フローに委ねる。
- 運営: Enabler（teai.io）。問い合わせは https://teai.io/contact
