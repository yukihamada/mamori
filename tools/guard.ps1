# 守 Mamori Guard — Windows の守りを点検し、安全な項目を自動で直して、毎日の自動点検を登録する。
# 管理者として PowerShell を開き:
#   iwr -Headers @{'X-Mamori-Key'=$env:MAMORI_KEY} https://mamori.teai.io/kit.tar.gz -OutFile $env:TEMP\mamori.tgz; tar xzf $env:TEMP\mamori.tgz -C $env:TEMP; & $env:TEMP\mamori\tools\guard.ps1
# 点検だけ: & ...\guard.ps1 -ScanOnly
param([switch]$ScanOnly, [int]$Hour = 9)
$ErrorActionPreference = "Stop"
$G = Join-Path (Split-Path $PSScriptRoot -Parent) "agent\mamori_guard.py"
function Find-Python {
  foreach ($c in @("py", "python", "python3")) {
    $p = Get-Command $c -ErrorAction SilentlyContinue
    if ($p -and $p.Source -notlike "*WindowsApps*") { return $p.Source }
  }
  return $null
}
$py = Find-Python
if (-not $py) {
  Write-Host "Python が見つからないため winget で入れます（Python 3.12・全ユーザー）..."
  winget install --id Python.Python.3.12 -e --scope machine --silent --accept-source-agreements --accept-package-agreements
  $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
  $py = Find-Python
  if (-not $py) { throw "Python を入れられませんでした。https://www.python.org/downloads/ から入れて再実行してください" }
}
$env:PYTHONIOENCODING = "utf-8"
[Console]::OutputEncoding = [Text.Encoding]::UTF8
if ($ScanOnly) { & $py $G scan; exit $LASTEXITCODE }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Host "ℹ 管理者として実行していないため、直せる項目が限られます（右クリック →「管理者として実行」）" }
& $py $G fix --auto
& $py $G install --hour $Hour
$sk = Join-Path $env:USERPROFILE ".config\sente"
if (Test-Path $sk) {
  New-Item -ItemType Directory -Force -Path "$sk\skill\mamori" | Out-Null
  Copy-Item (Join-Path (Split-Path $PSScriptRoot -Parent) "tools\sente-skill\mamori\SKILL.md") "$sk\skill\mamori\SKILL.md" -Force
  Write-Host "✅ 先手（Sente）に Mamori スキルを入れました"
}
Write-Host "✅ 毎日の自動点検を登録しました。承認が要る項目は上の「承認して直す」の行を実行してください。"
