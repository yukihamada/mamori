# 守 Mamori — AIエージェントへのかんたん導入（Windows / PowerShell）
#
#   招待制（2026-11-10〜）。参加者キーが必要です:
#   $env:MAMORI_KEY='mk_...'; irm -Headers @{'X-Mamori-Key'=$env:MAMORI_KEY} https://mamori.teai.io/install.ps1 | iex
#   $env:MAMORI_UNINSTALL='1'; irm https://mamori.teai.io/install.ps1 | iex     # 外す
#   $env:MAMORI_GUARD='1'; irm https://mamori.teai.io/install.ps1 | iex         # 毎日の自動保護も入れる
#   $env:MAMORI_ONLY='claude,codex'                                              # 入れる先を絞る
#
# やること（Mac/Linux 版 install.sh と同じ）:
#   1. キット一式を %USERPROFILE%\.mamori\kit に置く
#   2. キーがあれば %USERPROFILE%\.config\mamori\key に保存（本人だけ読める権限・AI設定には書かない）
#   3. Claude Code / Codex / Sente に MCP サーバー「mamori」を登録
#   4. 自己テスト
# 管理者権限は不要です。

function Install-Mamori {
  $ErrorActionPreference = "Stop"
  $ProgressPreference = "SilentlyContinue"
  try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
  $env:PYTHONIOENCODING = "utf-8"
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

  $hub = if ($env:MAMORI_HUB) { $env:MAMORI_HUB.TrimEnd("/") } else { "https://mamori.teai.io" }
  $userHome = if ($env:MAMORI_HOME_DIR) { $env:MAMORI_HOME_DIR } else { $env:USERPROFILE }
  $kitDir = Join-Path $userHome ".mamori\kit"
  $keyFile = Join-Path $userHome ".config\mamori\key"
  $mcp = Join-Path $kitDir "mamori\mcp\mamori_mcp.py"
  $only = if ($env:MAMORI_ONLY) { $env:MAMORI_ONLY } else { "claude,codex,sente" }
  $want = { param($n) (",$only,") -like "*,$n,*" }
  $ok = { param($m) Write-Host "  ✅ $m" }
  $skip = { param($m) Write-Host "  ・ $m" }
  $ng = { param($m) Write-Host "  ⚠️  $m" }

  # Python（Microsoft Store の空の入口は除外）
  $py = $null
  foreach ($c in @("py", "python", "python3")) {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -notlike "*WindowsApps*") {
      $exe = (& $cmd.Source -c "import sys; print(sys.executable if sys.version_info >= (3, 8) else '')" 2>$null | Select-Object -First 1)
      if ($exe) { $py = $exe.Trim(); break }
    }
  }
  if (-not $py) {
    Write-Host "Python 3.8 以上が見つかりません。次のどちらかで入れてから、もう一度実行してください:"
    Write-Host "  winget install -e --id Python.Python.3.12"
    Write-Host "  https://www.python.org/downloads/"
    return
  }

  # Sente の設定（JSON）に足す／外す。中身は Mac/Linux 版と同じ処理。
  $senteCfg = @'
import json, os, shutil, sys, time
action, py, mcp, home = sys.argv[1:5]
d = os.path.join(home, ".config", "sente")
p = os.path.join(d, "sente.json")
data = {}
if os.path.exists(p):
    with open(p, encoding="utf-8-sig") as f:
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
'@
  $senteTool = { param($action)
    $f = Join-Path ([IO.Path]::GetTempPath()) ("mamori-sente-" + [guid]::NewGuid().ToString("N") + ".py")
    [IO.File]::WriteAllText($f, $senteCfg, (New-Object Text.UTF8Encoding $false))
    try { & $py $f $action $py $mcp $userHome; $LASTEXITCODE -eq 0 } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
  }
  $has = { param($n) [bool](Get-Command $n -ErrorAction SilentlyContinue) }
  # ネイティブコマンドの失敗で止めない（結果は $LASTEXITCODE で見る）
  $run = { param($exe, [string[]]$argv) $prev = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    try { & $exe @argv *> $null } catch {} finally { $ErrorActionPreference = $prev }; $LASTEXITCODE -eq 0 }

  if ($env:MAMORI_UNINSTALL -eq "1") {
    Write-Host "守 Mamori を外します"
    if ((& $want "claude") -and (& $has "claude")) { if (& $run "claude" @("mcp", "remove", "-s", "user", "mamori")) { & $ok "Claude Code から外しました" } else { & $skip "Claude Code: 登録なし" } }
    if ((& $want "codex") -and (& $has "codex")) { if (& $run "codex" @("mcp", "remove", "mamori")) { & $ok "Codex から外しました" } else { & $skip "Codex: 登録なし" } }
    if ((& $want "sente") -and (Test-Path (Join-Path $userHome ".config\sente\sente.json"))) { if (& $senteTool "remove") { & $ok "Sente から外しました" } }
    Remove-Item (Join-Path $userHome ".claude\skills\mamori") -Recurse -Force -ErrorAction SilentlyContinue
    if ($env:MAMORI_GUARD -eq "1") { & $run "schtasks" @("/Delete", "/F", "/TN", "Mamori Guard") | Out-Null; & $ok "毎日の自動保護を止めました（タスク スケジューラ）" }
    Write-Host "キット（$kitDir）とキー（$keyFile）は残しています。不要なら手で削除してください。"
    return
  }

  Write-Host "守 Mamori を AI エージェントに入れます"

  # 1. キット
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("mamori-" + [guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Path (Join-Path $tmp "x") -Force | Out-Null
  try {
    # 招待制（2026-11-10〜）: キットは参加者キーがある人だけ
    $kitHeaders = @{}
    $kitKey = if ($env:MAMORI_KEY) { $env:MAMORI_KEY } elseif (Test-Path $keyFile) { ([string](Get-Content $keyFile -TotalCount 1)).Trim() } else { "" }
    if ($kitKey) { $kitHeaders["X-Mamori-Key"] = $kitKey }
    try { Invoke-WebRequest -UseBasicParsing -Uri "$hub/kit.tar.gz" -Headers $kitHeaders -OutFile (Join-Path $tmp "kit.tgz") }
    catch { throw "キットを取得できませんでした。守（Mamori）は招待制です（2026-11-10〜）: 参加者は `$env:MAMORI_KEY にキーを入れて実行、利用希望は https://teai.io/contact へ" }
    & tar -xzf (Join-Path $tmp "kit.tgz") -C (Join-Path $tmp "x")
    if (-not (Test-Path (Join-Path $tmp "x\mamori\mcp\mamori_mcp.py"))) { throw "キットの中身が想定と違います" }
    New-Item -ItemType Directory -Path (Split-Path $kitDir -Parent) -Force | Out-Null
    if (Test-Path $kitDir) { Remove-Item $kitDir -Recurse -Force }
    Move-Item (Join-Path $tmp "x") $kitDir
  } finally { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
  & $ok "キット: $kitDir\mamori"

  # 2. キー（任意）
  if ($env:MAMORI_KEY) {
    $code = 0
    try { $code = (Invoke-WebRequest -UseBasicParsing -Uri "$hub/api/whoami" -Headers @{ "X-Mamori-Key" = $env:MAMORI_KEY }).StatusCode }
    catch { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } }
    if ($code -eq 200) {
      New-Item -ItemType Directory -Path (Split-Path $keyFile -Parent) -Force | Out-Null
      [IO.File]::WriteAllText($keyFile, $env:MAMORI_KEY + "`n", (New-Object Text.UTF8Encoding $false))
      # 本人だけが読めるようにする（継承を切って本人にだけ権限）
      & icacls $keyFile /inheritance:r /grant:r "$($env:USERNAME):(R,W)" *> $null
      & $ok "キー: 有効・$keyFile に保存（本人だけ読める権限）"
    } else {
      & $ng "キーを確認できませんでした（HTTP $code）。保存せずに続けます"
      Remove-Item Env:\MAMORI_KEY -ErrorAction SilentlyContinue
    }
  } elseif (Test-Path $keyFile) {
    & $ok "キー: 保存済みのものを使います"
  } else {
    & $skip "キー: なし"
  }

  # 3. AI ツールへ登録
  $found = $false
  if (& $want "claude") {
    if (& $has "claude") {
      & $run "claude" @("mcp", "remove", "-s", "user", "mamori") | Out-Null
      if (& $run "claude" @("mcp", "add", "-s", "user", "mamori", "--", $py, $mcp)) {
        & $ok "Claude Code に登録"; $found = $true
        if (-not $env:MAMORI_NO_SKILL) {
          $sd = Join-Path $userHome ".claude\skills\mamori"
          New-Item -ItemType Directory -Path $sd -Force | Out-Null
          Copy-Item (Join-Path $kitDir "mamori\tools\sente-skill\mamori\SKILL.md") (Join-Path $sd "SKILL.md") -Force
        }
      } else { & $ng "Claude Code への登録に失敗" }
    } else { & $skip "Claude Code: 見つかりません" }
  }
  if (& $want "codex") {
    if (& $has "codex") {
      & $run "codex" @("mcp", "remove", "mamori") | Out-Null
      if (& $run "codex" @("mcp", "add", "mamori", "--", $py, $mcp)) { & $ok "Codex に登録"; $found = $true }
      else { & $ng "Codex への登録に失敗" }
    } else { & $skip "Codex: 見つかりません" }
  }
  if (& $want "sente") {
    if ((& $has "sente") -or (Test-Path (Join-Path $userHome ".config\sente"))) {
      if (& $senteTool "add") {
        & $ok "Sente に登録"; $found = $true
        if (-not $env:MAMORI_NO_SKILL) {
          $sd = Join-Path $userHome ".config\sente\skill\mamori"
          New-Item -ItemType Directory -Path $sd -Force | Out-Null
          Copy-Item (Join-Path $kitDir "mamori\tools\sente-skill\mamori\SKILL.md") (Join-Path $sd "SKILL.md") -Force
        }
      } else { & $ng "Sente への登録に失敗" }
    } else { & $skip "Sente: 見つかりません" }
  }

  # 4. 自己テスト
  Write-Host "動作確認"
  $prevEap = $ErrorActionPreference; $ErrorActionPreference = "Continue"
  $out = & $py $mcp --selftest 2>&1 | ForEach-Object { "$_" }
  $rc = $LASTEXITCODE; $ErrorActionPreference = $prevEap
  if ($rc -eq 0) {
    & $ok ("脅威情報を取得できました（" + (($out | Where-Object { $_ -like "脅威インテル:*" }) | Select-Object -First 1) + "）")
    $w = $out | Where-Object { $_ -like "キーは有効*" } | Select-Object -First 1
    if ($w) { & $ok $w }
  } else {
    & $ng "自己テストに失敗しました:"; $out | ForEach-Object { Write-Host "     $_" }
    return
  }

  # 5. 毎日の自動保護（MAMORI_GUARD=1）
  if ($env:MAMORI_GUARD -eq "1") {
    Write-Host "毎日の自動保護（この端末の守りを点検し、安全で元に戻せる項目だけ直します）"
    $guardPy = if ($env:MAMORI_GUARD_PY) { $env:MAMORI_GUARD_PY } else { Join-Path $kitDir "mamori\agent\mamori_guard.py" }
    $hour = if ($env:MAMORI_HOUR) { [int]$env:MAMORI_HOUR } else { 9 }
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $glog = Join-Path ([IO.Path]::GetTempPath()) ("mamori-guard-" + [guid]::NewGuid().ToString("N") + ".log")
    $q = { param($x) "'" + ($x -replace "'", "''") + "'" }
    $L = & $q $glog
    $inner = "`$env:PYTHONIOENCODING='utf-8'; try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}; " +
      "`$o = & $(& $q $py) $(& $q $guardPy) fix --auto 2>&1 | ForEach-Object { `"`$_`" }; `$rc = `$LASTEXITCODE; if (`$o) { Add-Content -Encoding UTF8 -Path $L -Value `$o }; if (`$rc -ne 0) { Add-Content -Encoding UTF8 -Path $L -Value '__MAMORI_FIXFAIL__' }; " +
      "`$o = & $(& $q $py) $(& $q $guardPy) install --hour $hour 2>&1 | ForEach-Object { `"`$_`" }; `$rc = `$LASTEXITCODE; if (`$o) { Add-Content -Encoding UTF8 -Path $L -Value `$o }; if (`$rc -eq 0) { Add-Content -Encoding UTF8 -Path $L -Value '__MAMORI_INSTALLED__' }"
    $elevated = $false
    if ($isAdmin) {
      $prevEap = $ErrorActionPreference; $ErrorActionPreference = "Continue"
      & ([scriptblock]::Create($inner)); $elevated = $true
      $ErrorActionPreference = $prevEap
    } else {
      try {
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
        $shell = (Get-Process -Id $PID).Path
        Start-Process -FilePath $shell -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $enc -Verb RunAs -Wait -WindowStyle Hidden
        $elevated = $true
      } catch { $elevated = $false }
    }
    if ($elevated -and (Test-Path $glog)) {
      $lines = Get-Content $glog -Encoding UTF8
      $lines | Where-Object { $_ -notlike "__MAMORI_*" } | ForEach-Object { Write-Host "     $_" }
      if ($lines -contains "__MAMORI_FIXFAIL__") { & $ng "直す処理の一部が失敗しました（上の表示を確認してください）" }
      if ($lines -contains "__MAMORI_INSTALLED__") { & $ok "管理者として毎日 ${hour}:17 に自動保護を登録しました" }
      else { & $ng "自動保護の登録に失敗しました" }
    } else {
      & $ng "管理者になれなかったため、ユーザー権限で直せる範囲だけにします（あとでもう一度実行すれば管理者で入ります）"
      $prevEap = $ErrorActionPreference; $ErrorActionPreference = "Continue"
      & $py $guardPy fix --auto 2>&1 | ForEach-Object { Write-Host "     $_" }
      $o = & $py $guardPy install --hour $hour 2>&1 | ForEach-Object { "$_" }
      if ($LASTEXITCODE -eq 0) { & $ok "ユーザー単位で登録: $($o -join ' ')" } else { & $ng "登録に失敗: $($o -join ' ')" }
      $ErrorActionPreference = $prevEap
    }
    Remove-Item $glog -Force -ErrorAction SilentlyContinue
    Write-Host "     承認が要る項目は、AI に「Mamori で守りを固めて」と頼むと、説明して承認をもらってから直します。"
  }

  Write-Host ""
  if ($found) {
    Write-Host "準備できました。AI ツールを開き直して、こう話しかけてください:"
    Write-Host "  「Mamori で最新の攻撃情報を教えて」"
    Write-Host "  「Mamori で共有されている攻撃の手口を見せて」（キーが必要）"
    Write-Host "  「この攻撃を Mamori に共有して: /wp-login.php への総当たり」（キーが必要）"
    Write-Host "  「Mamori で守りを固めて」（点検して、承認をもらってから直します）"
    Write-Host "外すとき: `$env:MAMORI_UNINSTALL='1'; irm https://mamori.teai.io/install.ps1 | iex"
  } else {
    Write-Host "Claude Code / Codex / Sente が見つかりませんでした。入れてから再実行するか、MCP 設定に次を登録してください:"
    Write-Host "  command: $py  args: $mcp"
  }
}

Install-Mamori
