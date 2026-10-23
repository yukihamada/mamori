#!/usr/bin/env python3
"""守 Mamori Guard — 端末・サーバーの守りを自動で固める（macOS / Windows / Linux）。

1. 点検 (scan)   : OSの守り設定（ファイアウォール・自動更新・暗号化・SSH 等）と、
                   入っているソフトを Mamori の最新脅威情報（CISA KEV / JPCERT）と照合
2. 自動対応 (fix): 安全で元に戻せる項目だけを自動で直す（tier=auto）。
                   締め出し・停止のおそれがある項目（tier=confirm）は --approve で明示した時だけ。
                   人の操作が要る項目（tier=manual、例: FileVault/BitLocker）は手順を示すだけ。
3. 記録と巻き戻し: 直した内容と「元に戻す手順」を journal に残し、rollback で戻せる
4. 常駐 (install): 毎日 fix --auto を自動実行（launchd / systemd・cron / タスク スケジューラ）

依存は Python 3.8+ 標準ライブラリのみ。例:
  python3 mamori_guard.py scan
  sudo python3 mamori_guard.py fix --auto
  sudo python3 mamori_guard.py fix --approve ssh.password_auth,linux.firewall
  sudo python3 mamori_guard.py rollback
  sudo python3 mamori_guard.py install --hour 9
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import urllib.request
import uuid
from pathlib import Path

VERSION = "0.1.0"
HUB = os.environ.get("MAMORI_HUB", "https://mamori.teai.io").rstrip("/")
TASK_NAME = "io.teai.mamori.guard"

# tier: auto=自動で直してよい / confirm=承認が要る / manual=人の操作が要る
AUTO, CONFIRM, MANUAL = "auto", "confirm", "manual"


# --------------------------------------------------------------------------
# システム操作の窓口（テストではここを差し替える）
# --------------------------------------------------------------------------
class System:
    def __init__(self) -> None:
        p = sys.platform
        self.os = "darwin" if p == "darwin" else "windows" if p.startswith("win") else "linux"
        self.env = dict(os.environ)
        if self.os != "windows":
            extra = "/opt/homebrew/bin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin"
            self.env["PATH"] = self.env.get("PATH", "") + ":" + extra

    def is_admin(self) -> bool:
        if self.os == "windows":
            try:
                import ctypes
                return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
            except Exception:
                return False
        return os.geteuid() == 0

    def which(self, name: str) -> str | None:
        return shutil.which(name, path=self.env.get("PATH"))

    def run(self, cmd: list[str], timeout: int = 60) -> tuple[int, str]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                               env=self.env, encoding="utf-8", errors="replace")
            return r.returncode, (r.stdout or "") + (r.stderr or "")
        except FileNotFoundError:
            return 127, f"not found: {cmd[0]}"
        except subprocess.TimeoutExpired:
            return 124, f"timeout: {' '.join(cmd)[:80]}"
        except Exception as e:  # noqa: BLE001 - 点検は止めずに unknown として扱う
            return 1, f"error: {e}"

    def ps(self, script: str, timeout: int = 120) -> tuple[int, str]:
        return self.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                         "Bypass", "-Command", script], timeout)

    def read(self, path: str) -> str | None:
        try:
            return Path(path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None

    def exists(self, path: str) -> bool:
        return Path(path).exists()

    def write(self, path: str, content: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(content, encoding="utf-8")

    def remove(self, path: str) -> None:
        try:
            Path(path).unlink()
        except FileNotFoundError:
            pass

    def fetch_json(self, url: str, timeout: int = 20):
        req = urllib.request.Request(url, headers={"User-Agent": f"mamori-guard/{VERSION}"})
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - 固定のhttpsハブ
            return json.loads(r.read().decode("utf-8"))


def state_dir(s: System) -> Path:
    if os.environ.get("MAMORI_STATE_DIR"):
        return Path(os.environ["MAMORI_STATE_DIR"])
    admin = s.is_admin()
    if s.os == "windows":
        base = os.environ.get("ProgramData" if admin else "LOCALAPPDATA") or str(Path.home())
        return Path(base) / "Mamori"
    if s.os == "darwin":
        return Path("/Library/Application Support/Mamori") if admin else Path.home() / ".mamori"
    return Path("/var/lib/mamori") if admin else Path.home() / ".mamori"


# --------------------------------------------------------------------------
# 点検結果
# --------------------------------------------------------------------------
def finding(id_: str, title: str, status: str, detail: str = "", tier: str = AUTO,
            fix: list | None = None, undo: list | None = None, admin: bool = True,
            weight: int = 2, how: str = "", refs: list | None = None) -> dict:
    """status: ok / weak / unknown / info。weak だけが対応対象。"""
    return {"id": id_, "title": title, "status": status, "detail": detail.strip()[:300],
            "tier": tier, "fix": fix or [], "undo": undo or [], "admin": admin,
            "weight": weight, "how": how, "refs": refs or []}


def C(*cmd: str) -> dict:
    return {"cmd": list(cmd)}


def PS(script: str) -> dict:
    return {"ps": script}


# --------------------------------------------------------------------------
# 共通: SSH（macOS / Linux）
# --------------------------------------------------------------------------
# sshd は「最初に読んだ値が勝つ」ので、50-cloud-init.conf 等より先に読まれる名前にする
SSH_DROPIN = "/etc/ssh/sshd_config.d/00-mamori.conf"


def _authorized_keys_exist(s: System) -> bool:
    homes = ["/root"]
    for base in ("/home", "/Users"):
        try:
            homes += [str(p) for p in Path(base).iterdir()]
        except Exception:
            pass
    for h in homes:
        t = s.read(f"{h}/.ssh/authorized_keys")
        if t and re.search(r"^(ssh-|ecdsa-|sk-)", t, re.M):
            return True
    return False


def check_ssh(s: System) -> list[dict]:
    if not s.which("sshd") and not s.exists("/usr/sbin/sshd"):
        return []
    sshd = s.which("sshd") or "/usr/sbin/sshd"
    running = _ssh_running(s)
    if not running:
        return [finding("ssh.running", "SSHサーバー", "ok", "動いていません（外から入る口なし）", weight=1)]
    rc, out = s.run([sshd, "-T"], 30)
    if rc != 0:
        return [finding("ssh.config", "SSHサーバーの設定", "unknown",
                        "設定を読めませんでした（管理者権限で再実行してください）", weight=0)]
    conf = dict((ln.split(" ", 1) + [""])[:2] for ln in out.lower().splitlines() if ln.strip())
    main = s.read("/etc/ssh/sshd_config") or ""
    dropin_ok = bool(re.search(r"^\s*include\s+/etc/ssh/sshd_config\.d/", main, re.I | re.M))
    reload_cmd = (C("launchctl", "kickstart", "-k", "system/com.openssh.sshd") if s.os == "darwin"
                  else C("sh", "-c", "systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null"
                         " || kill -HUP $(cat /run/sshd.pid 2>/dev/null || cat /var/run/sshd.pid)"))
    keys = _authorized_keys_exist(s)
    out_f = []
    wants = {}
    pw = conf.get("passwordauthentication", "yes")
    if pw == "yes":
        wants["PasswordAuthentication"] = "no"
        wants["KbdInteractiveAuthentication"] = "no"
    root = conf.get("permitrootlogin", "")
    if root == "yes":
        wants["PermitRootLogin"] = "prohibit-password"
    if conf.get("maxauthtries", "6").isdigit() and int(conf.get("maxauthtries", "6")) > 4:
        wants["MaxAuthTries"] = "4"
    if not wants:
        return [finding("ssh.hardening", "SSHサーバーの守り", "ok", "パスワード入室なし・root直接入室なし")]
    body = "# Mamori Guard が追加（rollback で削除されます）\n" + "".join(
        f"{k} {v}\n" for k, v in wants.items())
    expect = [f"{k.lower()} {v.replace('prohibit-password', 'without-password')}" for k, v in wants.items()
              if k != "KbdInteractiveAuthentication"]
    fix = [{"write": SSH_DROPIN, "content": body},
           {"cmd": [sshd, "-t"]},
           {"cmd": [sshd, "-T"], "expect": expect},  # 実際に効いているか（他の設定に負けていないか）
           reload_cmd]
    undo = [{"rm": SSH_DROPIN}, reload_cmd]
    detail = "・".join(f"{k}→{v}" for k, v in wants.items())
    if not dropin_ok:
        return [finding("ssh.hardening", "SSHサーバーの守り", "weak", detail, tier=MANUAL,
                        how="/etc/ssh/sshd_config に上の値を設定し、sshd -t で確認してから再読込", weight=3)]
    if "PasswordAuthentication" in wants and not keys:
        return [finding("ssh.hardening", "SSHサーバーの守り", "weak",
                        detail + "（鍵の登録が見つからないため、先に ~/.ssh/authorized_keys へ公開鍵を登録）",
                        tier=MANUAL, weight=3)]
    out_f.append(finding("ssh.hardening", "SSHサーバーの守り", "weak", detail, tier=CONFIRM,
                         fix=fix, undo=undo, weight=3,
                         how="今の接続は切れませんが、新しい接続は鍵が必要になります"))
    return out_f


def _ssh_running(s: System) -> bool:
    if s.os == "darwin":
        rc, _ = s.run(["launchctl", "print", "system/com.openssh.sshd"], 10)
        if rc == 0:
            return True
        rc, out = s.run(["netstat", "-an", "-p", "tcp"], 10)
        return bool(re.search(r"\.22\s.*LISTEN", out))
    rc, out = s.run(["sh", "-c", "pgrep -x sshd >/dev/null && echo yes"], 10)
    return "yes" in out


# --------------------------------------------------------------------------
# macOS
# --------------------------------------------------------------------------
FW = "/usr/libexec/ApplicationFirewall/socketfilterfw"
SU_PLIST = "/Library/Preferences/com.apple.SoftwareUpdate"
SU_KEYS = ["AutomaticCheckEnabled", "AutomaticDownload", "CriticalUpdateInstall", "ConfigDataInstall"]


def check_macos(s: System, profile: str, level: str) -> list[dict]:
    f = []
    rc, out = s.run([FW, "--getglobalstate"], 10)
    if rc == 0 and ("enabled" in out.lower() or "state = 1" in out or "state = 2" in out):
        f.append(finding("mac.firewall", "ファイアウォール", "ok", out, weight=3))
    elif rc == 0:
        f.append(finding("mac.firewall", "ファイアウォール", "weak", "オフです", weight=3,
                         tier=AUTO if profile == "client" else CONFIRM,
                         fix=[C(FW, "--setglobalstate", "on")], undo=[C(FW, "--setglobalstate", "off")]))
    if level == "strict":
        rc, out = s.run([FW, "--getstealthmode"], 10)
        if rc == 0 and "enabled" not in out.lower() and "on" not in out.lower():
            f.append(finding("mac.stealth", "ステルスモード（pingに応答しない）", "weak", out, weight=1,
                             fix=[C(FW, "--setstealthmode", "on")], undo=[C(FW, "--setstealthmode", "off")]))
    rc, out = s.run(["spctl", "--status"], 10)
    if "enabled" in out:
        f.append(finding("mac.gatekeeper", "Gatekeeper（未署名アプリの制限）", "ok", out, weight=2))
    elif rc in (0, 1) and "disabled" in out:
        f.append(finding("mac.gatekeeper", "Gatekeeper（未署名アプリの制限）", "weak", out, weight=2,
                         fix=[C("spctl", "--master-enable")], undo=[C("spctl", "--master-disable")]))
    rc, out = s.run(["csrutil", "status"], 10)
    if "enabled" in out.lower():
        f.append(finding("mac.sip", "システム整合性保護（SIP）", "ok", out, weight=2))
    elif "disabled" in out.lower():
        f.append(finding("mac.sip", "システム整合性保護（SIP）", "weak", out, tier=MANUAL, weight=2,
                         how="復旧モードで起動 → ターミナルで csrutil enable → 再起動"))
    rc, out = s.run(["fdesetup", "status"], 10)
    if "FileVault is On" in out:
        f.append(finding("mac.filevault", "ディスク暗号化（FileVault）", "ok", out, weight=3))
    elif "FileVault is Off" in out:
        f.append(finding("mac.filevault", "ディスク暗号化（FileVault）", "weak", out, tier=MANUAL, weight=3,
                         how="システム設定 → プライバシーとセキュリティ → FileVault をオン（復旧キーは安全な場所へ）"))
    # 自動アップデート
    off, undo = [], []
    for k in SU_KEYS:
        rc, out = s.run(["defaults", "read", SU_PLIST, k], 10)
        v = out.strip()
        if rc == 0 and v == "0":  # 未設定（キーなし）は macOS 既定でオン
            off.append(k)
            undo.append(C("defaults", "write", SU_PLIST, k, "-bool", "false"))
    if off:
        f.append(finding("mac.autoupdate", "自動アップデート（セキュリティ対応の自動適用）", "weak",
                         "未設定: " + ", ".join(off), weight=3,
                         fix=[C("defaults", "write", SU_PLIST, k, "-bool", "true") for k in off], undo=undo))
    else:
        f.append(finding("mac.autoupdate", "自動アップデート（セキュリティ対応の自動適用）", "ok", "", weight=3))
    rc, out = s.run(["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"], 10)
    if out.strip() == "1":
        f.append(finding("mac.guest", "ゲストユーザー", "weak", "有効です", weight=1,
                         fix=[C("defaults", "write", "/Library/Preferences/com.apple.loginwindow",
                                "GuestEnabled", "-bool", "false")],
                         undo=[C("defaults", "write", "/Library/Preferences/com.apple.loginwindow",
                                 "GuestEnabled", "-bool", "true")]))
    if os.environ.get("MAMORI_SKIP_OSUPDATE") != "1":
        rc, out = s.run(["softwareupdate", "-l"], 180)
        labels = re.findall(r"^\s*\* Label: (.+)$", out, re.M)
        if rc == 0 and labels:
            restart = "restart" in out.lower()
            f.append(finding("mac.os_updates", "未適用のOSアップデート", "weak",
                             f"{len(labels)}件: " + ", ".join(labels[:4]), weight=4,
                             tier=CONFIRM if restart else AUTO,
                             fix=[C("softwareupdate", "-i", "-a")],
                             how=("再起動が必要なものを含みます。作業の区切りで適用してください" if restart else "")))
        elif rc == 0:
            f.append(finding("mac.os_updates", "未適用のOSアップデート", "ok", "なし", weight=4))
    f += check_ssh(s)
    return f


# --------------------------------------------------------------------------
# Linux
# --------------------------------------------------------------------------
AUTO_UPGRADES = "/etc/apt/apt.conf.d/20auto-upgrades"
AUTO_UPGRADES_BODY = 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'


def _listening_ports(s: System) -> list[str]:
    rc, out = s.run(["ss", "-ltnH"], 10)
    ports = set()
    for ln in out.splitlines():
        parts = ln.split()
        if len(parts) < 4:
            continue
        addr = parts[3]
        host, _, port = addr.rpartition(":")
        if host.strip("[]") in ("127.0.0.1", "::1") or host.startswith("127.") or "%lo" in host:
            continue
        if port.isdigit():
            ports.add(port)
    return sorted(ports, key=int)


def check_linux(s: System, profile: str, level: str) -> list[dict]:
    f = []
    apt = bool(s.which("apt-get"))
    dnf = s.which("dnf") or s.which("yum")
    if apt:
        rc, _ = s.run(["dpkg", "-s", "unattended-upgrades"], 20)
        conf = s.read(AUTO_UPGRADES) or ""
        enabled = rc == 0 and re.search(r'Unattended-Upgrade\s+"1"', conf)
        if enabled:
            f.append(finding("linux.autoupdate", "セキュリティ更新の自動適用", "ok", "unattended-upgrades", weight=4))
        else:
            fx = []
            if rc != 0:
                fx.append({"cmd": ["apt-get", "install", "-y", "unattended-upgrades"],
                           "env": {"DEBIAN_FRONTEND": "noninteractive"}})
            fx.append({"write": AUTO_UPGRADES, "content": AUTO_UPGRADES_BODY})
            un = [{"restore": AUTO_UPGRADES, "content": conf if conf else None}]
            f.append(finding("linux.autoupdate", "セキュリティ更新の自動適用", "weak",
                             "unattended-upgrades が無効", weight=4, fix=fx, undo=un))
        rc, out = s.run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], 120)
        sec = [ln.split()[1] for ln in out.splitlines() if ln.startswith("Inst ") and "-security" in ln]
        if sec:
            fx = [{"cmd": ["apt-get", "update"]},
                  {"cmd": ["apt-get", "install", "-y", "--only-upgrade"] + sec,
                   "env": {"DEBIAN_FRONTEND": "noninteractive"}}]
            f.append(finding("linux.security_updates", "未適用のセキュリティ更新", "weak",
                             f"{len(sec)}件: " + ", ".join(sec[:6]), weight=5, fix=fx,
                             how="更新後に必要ならサービスを再起動します（needrestart がある場合は自動）"))
        elif rc == 0:
            f.append(finding("linux.security_updates", "未適用のセキュリティ更新", "ok", "なし", weight=5))
    elif dnf:
        rc, out = s.run(["systemctl", "is-enabled", "dnf-automatic-install.timer"], 10)
        if out.strip() == "enabled":
            f.append(finding("linux.autoupdate", "セキュリティ更新の自動適用", "ok", "dnf-automatic", weight=4))
        else:
            f.append(finding("linux.autoupdate", "セキュリティ更新の自動適用", "weak", "dnf-automatic が無効", weight=4,
                             fix=[C(dnf, "install", "-y", "dnf-automatic"),
                                  C("systemctl", "enable", "--now", "dnf-automatic-install.timer")],
                             undo=[C("systemctl", "disable", "--now", "dnf-automatic-install.timer")]))
        rc, out = s.run([dnf, "-q", "updateinfo", "list", "--security"], 120)
        lines = [ln for ln in out.splitlines() if ln.strip() and not ln.lower().startswith(("last metadata", "updating"))]
        if rc == 0 and lines:
            f.append(finding("linux.security_updates", "未適用のセキュリティ更新", "weak",
                             f"{len(lines)}件", weight=5, fix=[C(dnf, "-y", "upgrade", "--security")]))
        elif rc == 0:
            f.append(finding("linux.security_updates", "未適用のセキュリティ更新", "ok", "なし", weight=5))
    if s.exists("/var/run/reboot-required"):
        f.append(finding("linux.reboot", "再起動待ちの更新（カーネル等）", "weak",
                         (s.read("/var/run/reboot-required.pkgs") or "").replace("\n", " ")[:200],
                         tier=CONFIRM, weight=2, fix=[C("shutdown", "-r", "+5", "Mamori: security update reboot")],
                         undo=[C("shutdown", "-c")], how="5分後に再起動します（shutdown -c で中止）"))
    # ファイアウォール
    active = None
    if s.which("ufw"):
        rc, out = s.run(["ufw", "status"], 10)
        active = "ufw" if "Status: active" in out else None
    if not active and s.which("firewall-cmd"):
        rc, out = s.run(["firewall-cmd", "--state"], 10)
        active = "firewalld" if out.strip() == "running" else None
    if not active and s.which("nft"):
        rc, out = s.run(["nft", "list", "ruleset"], 10)
        active = "nftables" if re.search(r"\bhook input\b", out) else None
    if not active and s.which("iptables"):
        rc, out = s.run(["iptables", "-S", "INPUT"], 10)
        active = "iptables" if ("-P INPUT DROP" in out or len(out.splitlines()) > 3) else None
    if active:
        f.append(finding("linux.firewall", "ファイアウォール", "ok", active, weight=3))
    elif s.which("ufw"):
        ports = _listening_ports(s)
        fx = [C("ufw", "allow", p + "/tcp") for p in ports] + [C("ufw", "--force", "enable")]
        f.append(finding("linux.firewall", "ファイアウォール", "weak",
                         "無効。今開いている " + (", ".join(ports) or "なし") + " 番だけ許可して有効化します",
                         tier=CONFIRM if profile == "server" else AUTO, weight=3, fix=fx,
                         undo=[C("ufw", "disable")]))
    else:
        f.append(finding("linux.firewall", "ファイアウォール", "weak", "見つかりません", tier=MANUAL, weight=3,
                         how="ufw か firewalld を入れて、必要な番号だけ許可してください"))
    # 総当たり対策
    if _ssh_running(s) and not s.which("fail2ban-client") and apt:
        f.append(finding("linux.fail2ban", "SSHの総当たり対策（fail2ban）", "weak", "未導入", tier=CONFIRM,
                         weight=1, fix=[{"cmd": ["apt-get", "install", "-y", "fail2ban"],
                                          "env": {"DEBIAN_FRONTEND": "noninteractive"}}],
                         undo=[C("apt-get", "remove", "-y", "fail2ban")]))
    f += check_ssh(s)
    return f


# --------------------------------------------------------------------------
# Windows
# --------------------------------------------------------------------------
def _psj(s: System, script: str):
    rc, out = s.ps(script + " | ConvertTo-Json -Compress -Depth 3")
    if rc != 0 or not out.strip():
        return None
    try:
        return json.loads(out.strip().splitlines()[-1])
    except Exception:
        return None


def _reg(path: str, name: str) -> str:
    return f"(Get-ItemProperty -Path '{path}' -Name '{name}' -ErrorAction SilentlyContinue).'{name}'"


def check_windows(s: System, profile: str, level: str) -> list[dict]:
    f = []
    prof = _psj(s, "Get-NetFirewallProfile | Select-Object Name,Enabled")
    if prof is not None:
        prof = prof if isinstance(prof, list) else [prof]
        off = [p["Name"] for p in prof if not p.get("Enabled") or p.get("Enabled") in (0, "False")]
        if off:
            f.append(finding("win.firewall", "Windows ファイアウォール", "weak", "オフ: " + ", ".join(off),
                             tier=AUTO if profile == "client" else CONFIRM, weight=3,
                             fix=[PS(f"Set-NetFirewallProfile -Profile {','.join(off)} -Enabled True")],
                             undo=[PS(f"Set-NetFirewallProfile -Profile {','.join(off)} -Enabled False")]))
        else:
            f.append(finding("win.firewall", "Windows ファイアウォール", "ok", "全プロファイル有効", weight=3))
    mp = _psj(s, "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusSignatureAge,AMServiceEnabled")
    if mp:
        if not mp.get("RealTimeProtectionEnabled"):
            f.append(finding("win.defender", "Microsoft Defender リアルタイム保護", "weak", "オフ", weight=4,
                             fix=[PS("Set-MpPreference -DisableRealtimeMonitoring $false")],
                             undo=[PS("Set-MpPreference -DisableRealtimeMonitoring $true")]))
        else:
            f.append(finding("win.defender", "Microsoft Defender リアルタイム保護", "ok", "", weight=4))
        age = mp.get("AntivirusSignatureAge") or 0
        if isinstance(age, int) and age > 1:
            f.append(finding("win.defender_sig", "ウイルス定義の更新", "weak", f"{age}日前", weight=2,
                             fix=[PS("Update-MpSignature")]))
        else:
            f.append(finding("win.defender_sig", "ウイルス定義の更新", "ok", f"{age}日前", weight=2))
    else:
        f.append(finding("win.defender", "ウイルス対策", "unknown",
                         "Defender の状態を読めません（他社製品の可能性）", weight=0))
    smb1 = _psj(s, "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol")
    if smb1 and smb1.get("EnableSMB1Protocol"):
        f.append(finding("win.smb1", "古いファイル共有方式（SMBv1）", "weak", "有効（WannaCry等で悪用）", weight=3,
                         fix=[PS("Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force")],
                         undo=[PS("Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force")]))
    elif smb1 is not None:
        f.append(finding("win.smb1", "古いファイル共有方式（SMBv1）", "ok", "無効", weight=3))
    bl = _psj(s, "Get-BitLockerVolume -MountPoint $env:SystemDrive | Select-Object ProtectionStatus")
    if bl is not None:
        on = bl.get("ProtectionStatus") in (1, "On")
        f.append(finding("win.bitlocker", "ディスク暗号化（BitLocker）", "ok" if on else "weak",
                         "" if on else "オフ", tier=MANUAL, weight=3,
                         how="設定 → プライバシーとセキュリティ → デバイスの暗号化（回復キーを安全に保管）"))
    pol = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    rc, out = s.ps(_reg(pol, "EnableLUA"))
    if out.strip() == "0":
        f.append(finding("win.uac", "ユーザーアカウント制御（UAC）", "weak", "オフ", tier=CONFIRM, weight=3,
                         fix=[PS(f"Set-ItemProperty -Path '{pol}' -Name EnableLUA -Value 1")],
                         undo=[PS(f"Set-ItemProperty -Path '{pol}' -Name EnableLUA -Value 0")],
                         how="反映には再起動が必要です"))
    ts = "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server"
    rc, deny = s.ps(_reg(ts, "fDenyTSConnections"))
    rc, nla = s.ps(_reg(ts + "\\WinStations\\RDP-Tcp", "UserAuthentication"))
    if deny.strip() == "0" and nla.strip() == "0":
        k = ts + "\\WinStations\\RDP-Tcp"
        f.append(finding("win.rdp_nla", "リモートデスクトップの事前認証（NLA）", "weak", "RDP有効・NLAなし",
                         tier=CONFIRM, weight=3,
                         fix=[PS(f"Set-ItemProperty -Path '{k}' -Name UserAuthentication -Value 1")],
                         undo=[PS(f"Set-ItemProperty -Path '{k}' -Name UserAuthentication -Value 0")]))
    au = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
    rc, out = s.ps(_reg(au, "NoAutoUpdate"))
    if out.strip() == "1":
        f.append(finding("win.autoupdate", "Windows Update の自動更新", "weak", "ポリシーで停止中", weight=4,
                         fix=[PS(f"Set-ItemProperty -Path '{au}' -Name NoAutoUpdate -Value 0")],
                         undo=[PS(f"Set-ItemProperty -Path '{au}' -Name NoAutoUpdate -Value 1")]))
    else:
        f.append(finding("win.autoupdate", "Windows Update の自動更新", "ok", "", weight=4))
    if os.environ.get("MAMORI_SKIP_OSUPDATE") != "1":
        rc, out = s.ps("(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()"
                       ".Search(\"IsInstalled=0 and Type='Software' and IsHidden=0\").Updates.Count", 300)
        n = out.strip().splitlines()[-1] if out.strip() else ""
        if rc == 0 and n.isdigit() and int(n) > 0:
            f.append(finding("win.os_updates", "未適用の Windows Update", "weak", f"{n}件", weight=4,
                             tier=CONFIRM, fix=[C("UsoClient", "StartInteractiveScan")],
                             how="更新の取得・適用を開始します。再起動が要る場合は通知されます"))
        elif rc == 0 and n == "0":
            f.append(finding("win.os_updates", "未適用の Windows Update", "ok", "なし", weight=4))
    g = _psj(s, "Get-LocalUser -Name Guest -ErrorAction SilentlyContinue | Select-Object Enabled")
    if g and g.get("Enabled"):
        f.append(finding("win.guest", "Guest アカウント", "weak", "有効", weight=1,
                         fix=[PS("Disable-LocalUser -Name Guest")], undo=[PS("Enable-LocalUser -Name Guest")]))
    return f


# --------------------------------------------------------------------------
# インストール済みソフト × Mamori 脅威情報（KEV / JPCERT）
# --------------------------------------------------------------------------
STOP = {"server", "client", "common", "core", "data", "tools", "media", "linux", "windows", "apple",
        "google", "microsoft", "mozilla", "multiple", "products", "system", "service", "update",
        "python", "base", "utils", "files", "runtime", "app", "helper", "agent", "plugin", "edge",
        "office", "security", "manager", "web", "network", "kernel", "library", "framework", "desktop"}
ALIAS = {"google chrome": "chromium", "chrome": "chromium", "microsoft edge": "chromium",
         "brave browser": "chromium", "firefox": "firefox", "openssh": "openssh"}
OS_VENDORS = {"darwin": ("apple",), "windows": ("microsoft windows", "microsoft win32k"),
              "linux": ("linux kernel",)}


def installed_software(s: System) -> list[dict]:
    """[{name, version, manager, id}]（manager: brew/cask/app/apt/rpm/win）"""
    items: list[dict] = []
    if s.os == "darwin":
        try:
            for p in Path("/Applications").glob("*.app"):
                items.append({"name": p.stem, "version": "", "manager": "app", "id": p.stem})
        except Exception:
            pass
        if s.which("brew"):
            rc, out = _brew(s, ["list", "--versions", "--formula"])
            for ln in out.splitlines():
                parts = ln.split()
                if len(parts) >= 2 and rc == 0:
                    items.append({"name": parts[0], "version": parts[-1], "manager": "brew", "id": parts[0]})
            rc, out = _brew(s, ["list", "--versions", "--cask"])
            for ln in out.splitlines():
                parts = ln.split()
                if len(parts) >= 2 and rc == 0:
                    items.append({"name": parts[0], "version": parts[-1], "manager": "cask", "id": parts[0]})
    elif s.os == "linux":
        if s.which("dpkg-query"):
            rc, out = s.run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], 60)
            for ln in out.splitlines():
                if "\t" in ln:
                    n, v = ln.split("\t", 1)
                    items.append({"name": n, "version": v, "manager": "apt", "id": n})
        elif s.which("rpm"):
            rc, out = s.run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n"], 60)
            for ln in out.splitlines():
                if "\t" in ln:
                    n, v = ln.split("\t", 1)
                    items.append({"name": n, "version": v, "manager": "rpm", "id": n})
    else:
        data = _psj(s, "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
                       "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
                       "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
                       "-ErrorAction SilentlyContinue | Where-Object DisplayName | "
                       "Select-Object DisplayName,DisplayVersion")
        for d in (data if isinstance(data, list) else [data] if data else []):
            items.append({"name": d.get("DisplayName", ""), "version": d.get("DisplayVersion") or "",
                          "manager": "win", "id": d.get("DisplayName", "")})
    return items


def _brew_owner(s: System) -> str | None:
    b = s.which("brew")
    if not b:
        return None
    try:
        import pwd
        return pwd.getpwuid(Path(b).resolve().stat().st_uid).pw_name
    except Exception:
        return None


def _brew_cmd(s: System, args: list[str]) -> list[str]:
    b = s.which("brew") or "brew"
    if s.is_admin():  # Homebrew は root で動かせないので持ち主として実行
        owner = _brew_owner(s)
        if owner and owner != "root":
            return ["sudo", "-u", owner, "-H", b] + args
    return [b] + args


def _brew(s: System, args: list[str]) -> tuple[int, str]:
    env_backup = s.env.get("HOMEBREW_NO_AUTO_UPDATE")
    s.env["HOMEBREW_NO_AUTO_UPDATE"] = "1"
    try:
        return s.run(_brew_cmd(s, args), 120)
    finally:
        if env_backup is None:
            s.env.pop("HOMEBREW_NO_AUTO_UPDATE", None)


def _norm(t: str) -> str:
    t = t.lower().replace(".app", "")
    t = re.sub(r"@[\d.]+$", "", t)
    t = re.sub(r"[-_](server|client|common|bin|core|libs?|daemon)$", "", t)
    t = re.sub(r"[^a-z0-9]+", " ", t)
    return " ".join(t.split())


def match_intel(s: System, intel: list[dict], software: list[dict]) -> tuple[list[dict], list[dict]]:
    """(該当ソフトの一覧, OS自体に関わる情報) を返す。"""
    sw_hits: dict[str, dict] = {}
    os_hits = []
    names = []
    for sw in software:
        n = _norm(sw["name"])
        n = ALIAS.get(n, n)
        if len(n) < 4 or n in STOP:
            continue
        names.append((n, sw))
    for adv in intel:
        title = adv.get("title", "")
        prefix = _norm(title.split(":", 1)[0] if ":" in title else title)
        if any(prefix.startswith(v) or (" " + v) in (" " + prefix) for v in OS_VENDORS.get(s.os, ())):
            if s.os != "darwin" or re.search(r"\b(macos|multiple products)\b", prefix):
                os_hits.append(adv)
            continue
        for n, sw in names:
            if re.search(r"(?<![a-z0-9])" + re.escape(n) + r"(?![a-z0-9])", prefix):
                key = sw["manager"] + ":" + sw["id"]
                hit = sw_hits.setdefault(key, {**sw, "advisories": []})
                if adv["id"] not in [a["id"] for a in hit["advisories"]]:
                    hit["advisories"].append({"id": adv["id"], "title": title[:120],
                                              "due": adv.get("due_date", ""), "url": adv.get("url", "")})
    return list(sw_hits.values()), os_hits


def intel_findings(s: System, sw_hits: list[dict], os_hits: list[dict]) -> list[dict]:
    f = []
    for h in sw_hits:
        ids = ", ".join(a["id"] for a in h["advisories"][:3])
        mgr = h["manager"]
        fix: list = []
        if mgr in ("brew", "cask"):
            fix = [{"cmd": _brew_cmd(s, ["upgrade"] + (["--cask"] if mgr == "cask" else []) + [h["id"]]),
                    "env": {"HOMEBREW_NO_AUTO_UPDATE": "1"}, "admin": False}]
        elif mgr == "apt":
            fix = [C("apt-get", "update"),
                   {"cmd": ["apt-get", "install", "-y", "--only-upgrade", h["id"]],
                    "env": {"DEBIAN_FRONTEND": "noninteractive"}}]
        elif mgr == "rpm":
            dnf = s.which("dnf") or "yum"
            fix = [C(dnf, "-y", "upgrade", h["id"])]
        elif mgr == "win" and s.which("winget"):
            fix = [C("winget", "upgrade", "--name", h["id"], "--exact", "--silent",
                     "--accept-source-agreements", "--accept-package-agreements")]
        f.append(finding(f"intel.{mgr}.{_norm(h['id']).replace(' ', '-')}",
                         f"悪用が確認された脆弱性の可能性: {h['name']} {h['version']}".strip(), "weak",
                         ids + " — 最新版で修正済みか確認・更新", tier=AUTO if fix else MANUAL,
                         fix=fix, weight=5, admin=mgr not in ("brew", "cask"),
                         how="" if fix else "開発元の案内に従って最新版へ更新してください",
                         refs=h["advisories"]))
    if os_hits:
        f.append(finding("intel.os", "OS本体に関わる注意情報", "info",
                         ", ".join(a["id"] for a in os_hits[:5]) + " — 上の「OSアップデート」で対応",
                         weight=0, refs=[{"id": a["id"], "title": a.get("title", "")[:120],
                                          "url": a.get("url", "")} for a in os_hits[:10]]))
    return f


def load_intel(s: System, sd: Path) -> tuple[list[dict], str]:
    cache = sd / "intel-cache.json"
    try:
        data = s.fetch_json(HUB + "/api/latest")
        objs = [o for o in data.get("objects", []) if o.get("type") == "advisory"]
        try:
            sd.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(objs, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass
        return objs, "live"
    except Exception:
        try:
            return json.loads(cache.read_text(encoding="utf-8")), "cache"
        except Exception:
            return [], "none"


# --------------------------------------------------------------------------
# 点検 → 採点
# --------------------------------------------------------------------------
def detect_profile(s: System) -> str:
    if s.os == "windows":
        rc, out = s.ps("(Get-CimInstance Win32_OperatingSystem).ProductType")
        return "client" if out.strip() == "1" else "server"
    if s.os == "darwin":
        return "client"
    return "client" if (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) else "server"


def scan(s: System, profile: str, level: str, sd: Path, with_intel: bool = True) -> dict:
    checks = {"darwin": check_macos, "linux": check_linux, "windows": check_windows}[s.os]
    f = checks(s, profile, level)
    intel_src = "skipped"
    if with_intel:
        intel, intel_src = load_intel(s, sd)
        sw_hits, os_hits = match_intel(s, intel, installed_software(s))
        f += intel_findings(s, sw_hits, os_hits)
        for x in f:  # OS の注意情報があれば OS 更新の重みを上げる
            if os_hits and x["id"] in ("mac.os_updates", "win.os_updates", "linux.security_updates") \
                    and x["status"] == "weak":
                x["weight"] += 3
                x["refs"] = [{"id": a["id"], "url": a.get("url", "")} for a in os_hits[:5]]
    total = sum(x["weight"] for x in f if x["status"] in ("ok", "weak"))
    good = sum(x["weight"] for x in f if x["status"] == "ok")
    score = round(100 * good / total) if total else None
    return {"tool": "mamori-guard", "version": VERSION, "time": _now(), "os": s.os,
            "os_version": platform.platform(), "profile": profile, "level": level,
            "admin": s.is_admin(), "intel": intel_src, "score": score, "findings": f}


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


# --------------------------------------------------------------------------
# 適用・巻き戻し
# --------------------------------------------------------------------------
def run_step(s: System, step: dict) -> tuple[bool, str]:
    if "write" in step:
        s.write(step["write"], step["content"])
        return True, f"wrote {step['write']}"
    if "rm" in step:
        s.remove(step["rm"])
        return True, f"removed {step['rm']}"
    if "restore" in step:
        if step.get("content") is None:
            s.remove(step["restore"])
        else:
            s.write(step["restore"], step["content"])
        return True, f"restored {step['restore']}"
    saved = {}
    for k, v in (step.get("env") or {}).items():
        saved[k] = s.env.get(k)
        s.env[k] = v
    try:
        if "ps" in step:
            rc, out = s.ps(step["ps"], 600)
        else:
            rc, out = s.run(step["cmd"], 1800)
    finally:
        for k, v in saved.items():
            if v is None:
                s.env.pop(k, None)
            else:
                s.env[k] = v
    if rc == 0 and step.get("expect"):
        low = out.lower()
        miss = [e for e in step["expect"] if not any(
            ln.strip() == e or ln.strip().replace("prohibit-password", "without-password") == e
            for ln in low.splitlines())]
        if miss:
            return False, "反映されていません: " + ", ".join(miss)
    return rc == 0, out.strip()[-400:]


def apply(s: System, report: dict, sd: Path, auto: bool, approve: set[str], dry: bool) -> list[dict]:
    run_id = _dt.datetime.now().strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:4]
    admin = s.is_admin()
    results = []
    for x in report["findings"]:
        if x["status"] != "weak" or not x["fix"]:
            continue
        chosen = (auto and x["tier"] == AUTO) or x["id"] in approve or \
            ("all" in approve and x["tier"] in (AUTO, CONFIRM))
        if not chosen:
            continue
        needs_admin = x["admin"] and not all(st.get("admin") is False for st in x["fix"])
        if needs_admin and not admin:
            results.append({"id": x["id"], "result": "needs-admin"})
            continue
        if dry:
            results.append({"id": x["id"], "result": "dry-run", "steps": x["fix"]})
            continue
        ok, log = True, []
        for st in x["fix"]:
            good, out = run_step(s, st)
            log.append(out)
            if not good:
                ok = False
                break
        if not ok and x["undo"]:  # 途中で失敗したら元に戻す
            for st in x["undo"]:
                log.append("undo: " + run_step(s, st)[1][:120])
        rec = {"run": run_id, "time": _now(), "id": x["id"], "title": x["title"],
               "result": "fixed" if ok else "failed", "undo": x["undo"], "log": log[-3:]}
        results.append(rec)
        try:
            sd.mkdir(parents=True, exist_ok=True)
            with open(sd / "journal.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:
            pass
    return results


def rollback(s: System, sd: Path, run_id: str | None, only: str | None) -> list[dict]:
    path = sd / "journal.jsonl"
    if not path.exists():
        return []
    recs = [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    fixed = [r for r in recs if r.get("result") == "fixed" and not r.get("rolled_back")]
    if not fixed:
        return []
    target = run_id or fixed[-1]["run"]
    todo = [r for r in fixed if r["run"] == target and (not only or r["id"] == only)]
    out = []
    for r in reversed(todo):
        if not r.get("undo"):
            out.append({"id": r["id"], "result": "no-undo（更新の取り消しはできません）"})
            continue
        ok = all(run_step(s, st)[0] for st in r["undo"])
        out.append({"id": r["id"], "result": "rolled-back" if ok else "failed"})
        if ok:
            r["rolled_back"] = _now()
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in recs), encoding="utf-8")
    return out


# --------------------------------------------------------------------------
# 常駐（毎日 fix --auto）
# --------------------------------------------------------------------------
def install(s: System, sd: Path, hour: int, level: str) -> str:
    sd.mkdir(parents=True, exist_ok=True)
    me = sd / "mamori_guard.py"
    shutil.copyfile(__file__, me)
    py = sys.executable or "python3"
    # Homebrew の版つきパスは更新で消えるので、macOS では OS 付属の python3 を優先
    if s.os == "darwin" and Path("/usr/bin/python3").exists() and s.run(["xcode-select", "-p"], 10)[0] == 0:
        py = "/usr/bin/python3"
    args = [py, str(me), "fix", "--auto", "--level", level, "--quiet"]
    log = str(sd / "guard.out")
    if s.os == "darwin":
        label = TASK_NAME
        plist_dir = Path("/Library/LaunchDaemons") if s.is_admin() else Path.home() / "Library/LaunchAgents"
        plist = plist_dir / f"{label}.plist"
        import plistlib
        plist.write_bytes(plistlib.dumps({
            "Label": label, "ProgramArguments": args, "RunAtLoad": False,
            "StartCalendarInterval": {"Hour": hour, "Minute": 17},
            "StandardOutPath": log, "StandardErrorPath": log}))
        domain = "system" if s.is_admin() else f"gui/{os.getuid()}"
        s.run(["launchctl", "bootout", domain, str(plist)], 20)
        rc, out = s.run(["launchctl", "bootstrap", domain, str(plist)], 20)
        return f"launchd {domain}/{label} 毎日 {hour}:17 ({'ok' if rc == 0 else out.strip()})"
    if s.os == "linux":
        if s.is_admin() and s.which("systemctl") and s.exists("/run/systemd/system"):
            s.write("/etc/systemd/system/mamori-guard.service",
                    "[Unit]\nDescription=Mamori Guard\nAfter=network-online.target\n\n[Service]\n"
                    f"Type=oneshot\nExecStart={' '.join(args)}\n")
            s.write("/etc/systemd/system/mamori-guard.timer",
                    f"[Unit]\nDescription=Mamori Guard daily\n\n[Timer]\nOnCalendar=*-*-* {hour:02d}:17:00\n"
                    "RandomizedDelaySec=900\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n")
            s.run(["systemctl", "daemon-reload"])
            rc, out = s.run(["systemctl", "enable", "--now", "mamori-guard.timer"])
            return f"systemd mamori-guard.timer 毎日 {hour}:17 ({'ok' if rc == 0 else out.strip()})"
        rc, cur = s.run(["crontab", "-l"])
        lines = [ln for ln in (cur if rc == 0 else "").splitlines() if "mamori_guard.py" not in ln]
        lines.append(f"17 {hour} * * * {' '.join(args)} >> {log} 2>&1")
        p = subprocess.run(["crontab", "-"], input="\n".join(lines) + "\n", text=True)
        return f"crontab 毎日 {hour}:17 ({'ok' if p.returncode == 0 else 'failed'})"
    tr = " ".join(f'"{a}"' if " " in a else a for a in args)
    cmd = ["schtasks", "/Create", "/F", "/TN", "Mamori Guard", "/SC", "DAILY",
           "/ST", f"{hour:02d}:17", "/TR", tr]
    if s.is_admin():
        cmd += ["/RU", "SYSTEM", "/RL", "HIGHEST"]
    rc, out = s.run(cmd)
    return f"タスク スケジューラ 'Mamori Guard' 毎日 {hour}:17 ({'ok' if rc == 0 else out.strip()})"


def uninstall(s: System) -> str:
    if s.os == "darwin":
        for plist, domain in ((Path("/Library/LaunchDaemons") / f"{TASK_NAME}.plist", "system"),
                              (Path.home() / f"Library/LaunchAgents/{TASK_NAME}.plist", f"gui/{os.getuid()}")):
            if plist.exists():
                s.run(["launchctl", "bootout", domain, str(plist)])
                plist.unlink()
        return "launchd から外しました"
    if s.os == "linux":
        if s.exists("/etc/systemd/system/mamori-guard.timer"):
            s.run(["systemctl", "disable", "--now", "mamori-guard.timer"])
            s.remove("/etc/systemd/system/mamori-guard.timer")
            s.remove("/etc/systemd/system/mamori-guard.service")
            s.run(["systemctl", "daemon-reload"])
        rc, cur = s.run(["crontab", "-l"])
        if rc == 0 and "mamori_guard.py" in cur:
            keep = "\n".join(ln for ln in cur.splitlines() if "mamori_guard.py" not in ln) + "\n"
            subprocess.run(["crontab", "-"], input=keep, text=True)
        return "定期実行を外しました"
    s.run(["schtasks", "/Delete", "/F", "/TN", "Mamori Guard"])
    return "タスク スケジューラから外しました"


# --------------------------------------------------------------------------
# 表示
# --------------------------------------------------------------------------
ICON = {"ok": "✅", "weak": "⚠️", "unknown": "❔", "info": "ℹ️"}
TIER_JA = {AUTO: "自動で直せます", CONFIRM: "承認すれば直せます", MANUAL: "手作業が必要"}


def render(report: dict, results: list[dict] | None = None) -> str:
    osname = {"darwin": "macOS", "windows": "Windows", "linux": "Linux"}[report["os"]]
    sc = report["score"]
    lines = [f"🛡 守 Mamori Guard {report['version']} — {osname} / "
             f"{'サーバー' if report['profile'] == 'server' else '端末'} / 守りの点数 {sc if sc is not None else '-'} 点",
             f"   脅威情報: {report['intel']}  管理者権限: {'あり' if report['admin'] else 'なし'}", ""]
    order = {"weak": 0, "unknown": 1, "info": 2, "ok": 3}
    for x in sorted(report["findings"], key=lambda x: (order.get(x["status"], 9), -x["weight"])):
        ln = f"{ICON.get(x['status'], '・')} {x['title']}"
        if x["detail"]:
            ln += f" — {x['detail']}"
        if x["status"] == "weak":
            ln += f"  [{x['id']} / {TIER_JA[x['tier']]}]"
        lines.append(ln)
        if x["status"] == "weak" and x["how"]:
            lines.append(f"     → {x['how']}")
    if results is not None:
        lines.append("")
        lines.append("— 今回の対応 —" if results else "— 自動で直す項目はありませんでした —")
        for r in results:
            lines.append(f"  {r['id']}: {r['result']}")
        if any(r["result"] == "needs-admin" for r in results):
            lines.append("  ※ needs-admin は管理者権限（sudo / 管理者として実行）で再実行すると直せます")
    weak_confirm = [x["id"] for x in report["findings"] if x["status"] == "weak" and x["tier"] == CONFIRM]
    if weak_confirm:
        lines.append("")
        lines.append("承認して直す: fix --approve " + ",".join(weak_confirm))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mamori_guard", description="守 Mamori Guard")
    sub = ap.add_subparsers(dest="cmd")
    for name in ("scan", "fix"):
        p = sub.add_parser(name)
        p.add_argument("--profile", choices=["auto", "client", "server"], default="auto")
        p.add_argument("--level", choices=["standard", "strict"], default="standard")
        p.add_argument("--json", action="store_true")
        p.add_argument("--no-intel", action="store_true")
        p.add_argument("--quiet", action="store_true")
        if name == "fix":
            p.add_argument("--auto", action="store_true", help="tier=auto を自動で直す")
            p.add_argument("--approve", default="", help="承認する項目ID（カンマ区切り・all）")
            p.add_argument("--dry-run", action="store_true")
    rb = sub.add_parser("rollback")
    rb.add_argument("--run")
    rb.add_argument("--id")
    ins = sub.add_parser("install")
    ins.add_argument("--hour", type=int, default=9)
    ins.add_argument("--level", choices=["standard", "strict"], default="standard")
    sub.add_parser("uninstall")
    sub.add_parser("status")
    a = ap.parse_args(argv)
    try:  # Windows の既定コードページでも絵文字・日本語で落ちないように
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass
    s = System()
    sd = state_dir(s)
    cmd = a.cmd or "scan"
    if cmd in ("scan", "fix"):
        profile = getattr(a, "profile", "auto")
        profile = detect_profile(s) if profile == "auto" else profile
        rep = scan(s, profile, getattr(a, "level", "standard"), sd, not getattr(a, "no_intel", False))
        results = None
        if cmd == "fix":
            approve = {x.strip() for x in a.approve.split(",") if x.strip()}
            results = apply(s, rep, sd, a.auto, approve, a.dry_run)
            if results and not a.dry_run and any(r.get("result") == "fixed" for r in results):
                rep = scan(s, profile, a.level, sd, not a.no_intel)  # 直した後の点数
                rep["applied"] = results
        try:
            sd.mkdir(parents=True, exist_ok=True)
            (sd / "last.json").write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding="utf-8")
        except Exception:
            pass
        if getattr(a, "json", False):
            out = dict(rep)
            if results is not None:
                out["applied"] = results
            print(json.dumps(out, ensure_ascii=False, indent=1))
        else:
            text = render(rep, results)
            if a.quiet:
                text = f"[{_now()}] score={rep['score']} " + " ".join(
                    f"{r['id']}={r['result']}" for r in (results or []))
                try:
                    with open(sd / "guard.log", "a", encoding="utf-8") as fh:
                        fh.write(text + "\n")
                except Exception:
                    pass
            print(text)
        return 0
    if cmd == "rollback":
        res = rollback(s, sd, a.run, a.id)
        print("\n".join(f"{r['id']}: {r['result']}" for r in res) or "戻す対象はありません")
        return 0
    if cmd == "install":
        msg = install(s, sd, a.hour, a.level)
        print(msg)
        return 0 if "(ok)" in msg else 1
    if cmd == "uninstall":
        print(uninstall(s))
        return 0
    if cmd == "status":
        last = sd / "last.json"
        if last.exists():
            r = json.loads(last.read_text(encoding="utf-8"))
            print(render(r))
        else:
            print("まだ点検していません。 scan を実行してください")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
