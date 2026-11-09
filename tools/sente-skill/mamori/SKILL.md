---
name: mamori
description: 守Mamori。セキュリティの点検・強化・脆弱性対応を自動で行う。「セキュリティを上げて」「守りを固めて」「脆弱性を確認して」「Mamori回して」「このサーバー/PC/Mac/Windowsは安全？」「最新の攻撃情報」「攻撃を共有して」で使う。macOS・Windows・Linux、端末・サーバーの両方に対応。安全で元に戻せる項目は自動で直し、締め出し・停止のおそれがある項目は承認を得てから直す。
---

# 守 Mamori — 守りを自動で固める

Mamori Guard（`mamori_guard.py`・標準ライブラリのみ）で、OSの守り設定とインストール済みソフトを
Mamori の最新脅威情報（CISA KEV・JPCERT/CC、https://mamori.teai.io/api/latest）と照合し、直す。

## 入手（未取得なら）
```bash
D=~/.mamori/kit; mkdir -p $D && curl -fsSL -H "X-Mamori-Key: $(cat ~/.config/mamori/key)" https://mamori.teai.io/kit.tar.gz | tar xz -C $D
G=$D/mamori/agent/mamori_guard.py
```
Windows（PowerShell）: `iwr -Headers @{'X-Mamori-Key'=$env:MAMORI_KEY} https://mamori.teai.io/kit.tar.gz -OutFile $env:TEMP\m.tgz; tar xzf $env:TEMP\m.tgz -C $env:TEMP; $G="$env:TEMP\mamori\agent\mamori_guard.py"`（python は `py`）

## 手順（この順で）
1. **点検**: `python3 $G scan`（機械可読は `--json`）。点数・⚠️項目・tier を報告する。
2. **自動対応（承認不要）**: `sudo python3 $G fix --auto`
   - tier=auto だけを直す: ファイアウォール（端末）・自動アップデート・Defender・SMBv1停止・Gatekeeper・ゲスト無効・
     セキュリティ更新・**悪用が確認された脆弱性に該当するソフトの更新**（brew/apt/dnf/winget）。
   - 管理者権限がない場合は `needs-admin` になる。sudo のパスワードは本人に入力してもらう（迂回しない）。
     Windows は「管理者として実行」した PowerShell で `py $G fix --auto`。
3. **承認が要る項目（tier=confirm）**: 一覧（項目ID・何が変わるか・影響）を見せて本人の承認を得てから
   `sudo python3 $G fix --approve <ID,ID>`。例: SSHのパスワード入室禁止（鍵登録がない場合は手作業扱いで自動では出ない）、
   サーバーのファイアウォール有効化（今開いている番号は許可して有効化）、再起動を伴うOS更新、UAC・RDPのNLA、fail2ban。
   `--approve all` は本人が「全部」と明示した時だけ。
4. **手作業（tier=manual）**: FileVault / BitLocker / SIP など。出力の「→」の手順を本人に案内する。
5. **毎日の自動化**: 本人が常駐を望んだら `sudo python3 $G install --hour 9`（launchd / systemd timer・cron / タスク スケジューラ）。
   以後は毎日 `fix --auto` だけが走る（confirm は自動では走らない）。止める: `uninstall`。
6. **戻す**: `sudo python3 $G rollback`（直前の実行分）/ `--run <ID>` / `--id <項目ID>`。記録は state_dir の `journal.jsonl`。
   ソフトの更新は取り消せない（no-undo と表示）。
7. 直した後は必ず `scan` を再実行し、点数の前後と残件を報告する（直したと言うのは再点検で ✅ になったものだけ）。

## サーバー（リモート）
本人が対象ホストを示した時だけ、そのホストに対して上と同じ手順を ssh 経由で行う:
```bash
ssh HOST 'mkdir -p ~/.mamori/kit && curl -fsSL -H "X-Mamori-Key: $(cat ~/.config/mamori/key)" https://mamori.teai.io/kit.tar.gz | tar xz -C ~/.mamori/kit && python3 ~/.mamori/kit/mamori/agent/mamori_guard.py scan'
```
SSH設定の変更は**今の接続を切らない**が、変更後に**別ターミナルで新規接続できること**を確認してから終える。
入れなければ `rollback`。fly.io 等のコンテナ（使い捨て）は Dockerfile 側で直すのが正しいので、点検結果を下書きとして返す。

## 脅威情報・共有
- 最新の攻撃情報: `curl -s -H "X-Mamori-Key: $(cat ~/.config/mamori/key)" https://mamori.teai.io/api/latest`（人向け一覧: https://mamori.teai.io/intel）
- 観測の共有は組織キー（`MAMORI_KEY`）が必要: `bash <kit>/mamori/tools/share.sh "手口" 件数 GREEN`。
  キーをチャット・メモリ・コミットに平文で残さない。IP・社内ホスト名など識別情報は共有前に除く。

## 境界
- 自動で直すのは tier=auto のみ。confirm は毎回本人承認。本番サーバーの再起動・ファイアウォール変更は特に影響を説明する。
- 点数・結果は実際の `scan` 出力から報告し、推測で「安全です」と言わない。
