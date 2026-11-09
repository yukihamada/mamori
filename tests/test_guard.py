#!/usr/bin/env python3
"""mamori_guard の判定・修正・巻き戻しを、OSの応答を模した偽システムで確かめる。"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent"))
import mamori_guard as g  # noqa: E402


class Fake(g.System):
    def __init__(self, osname, answers, admin=True, tools=()):
        self.os = osname
        self.env = {}
        self.answers = answers  # [(部分文字列, rc, 出力)] 先に一致したもの
        self.admin = admin
        self.tools = set(tools)
        self.calls = []
        self.files = {}

    def is_admin(self):
        return self.admin

    def which(self, name):
        return f"/usr/bin/{name}" if name in self.tools else None

    def run(self, cmd, timeout=60):
        line = " ".join(cmd)
        self.calls.append(line)
        for key, rc, out in self.answers:
            if key in line:
                return rc, out
        return 1, ""

    def ps(self, script, timeout=120):
        return self.run(["powershell", script])

    def read(self, path):
        return self.files.get(path)

    def exists(self, path):
        return path in self.files

    def write(self, path, content):
        self.files[path] = content

    def remove(self, path):
        self.files.pop(path, None)

    def fetch_json(self, url, timeout=20):
        raise OSError("offline")


def by_id(rep):
    return {x["id"]: x for x in rep["findings"]}


WIN_WEAK = [
    ("Get-NetFirewallProfile", 0, json.dumps([{"Name": "Domain", "Enabled": True},
                                              {"Name": "Public", "Enabled": False}])),
    ("Get-MpComputerStatus", 0, json.dumps({"RealTimeProtectionEnabled": False, "AntivirusSignatureAge": 5})),
    ("Get-SmbServerConfiguration", 0, json.dumps({"EnableSMB1Protocol": True})),
    ("Get-BitLockerVolume", 0, json.dumps({"ProtectionStatus": 0})),
    ("'EnableLUA'", 0, "0"),
    ("'fDenyTSConnections'", 0, "0"),
    ("'UserAuthentication'", 0, "0"),
    ("'NoAutoUpdate'", 0, "1"),
    ("Microsoft.Update.Session", 0, "3"),
    ("Get-LocalUser", 0, json.dumps({"Enabled": True})),
    ("Uninstall", 0, json.dumps([{"DisplayName": "Plex Media Server", "DisplayVersion": "1.40"},
                                 {"DisplayName": "Google Chrome", "DisplayVersion": "120"}])),
]
INTEL = [
    {"type": "advisory", "id": "CVE-1", "title": "Plex Media Server: Plex Media Server Path Vulnerability",
     "severity": "exploited-in-the-wild"},
    {"type": "advisory", "id": "CVE-2", "title": "Google Chromium V8: Type Confusion"},
    {"type": "advisory", "id": "CVE-3", "title": "Microsoft Windows: Win32k Privilege Escalation"},
    {"type": "advisory", "id": "CVE-4", "title": "EG Secure Solutions SiteGuard: OS Command Injection"},
]


def test_windows_client():
    s = Fake("windows", WIN_WEAK, tools={"winget"})
    rep = g.scan(s, "client", "standard", Path(tempfile.mkdtemp()), with_intel=False)
    f = by_id(rep)
    assert f["win.firewall"]["status"] == "weak" and f["win.firewall"]["tier"] == g.AUTO
    assert "Public" in f["win.firewall"]["fix"][0]["ps"] and "Domain" not in f["win.firewall"]["fix"][0]["ps"]
    assert f["win.defender"]["tier"] == g.AUTO and f["win.defender_sig"]["status"] == "weak"
    assert f["win.smb1"]["undo"], "SMBv1 は戻せること"
    assert f["win.bitlocker"]["tier"] == g.MANUAL
    assert f["win.uac"]["tier"] == g.CONFIRM and f["win.rdp_nla"]["tier"] == g.CONFIRM
    assert f["win.autoupdate"]["status"] == "weak" and f["win.os_updates"]["tier"] == g.CONFIRM
    assert f["win.guest"]["status"] == "weak"
    sd = Path(tempfile.mkdtemp())
    res = {r["id"]: r["result"] for r in g.apply(s, rep, sd, auto=True, approve=set(), dry=False)}
    # 承認が要るもの・手作業のものは自動では触らない
    assert "win.uac" not in res and "win.rdp_nla" not in res and "win.bitlocker" not in res
    # 偽システムは書き込み系に rc=1 を返すので failed → 失敗時の巻き戻しが走る
    assert res["win.firewall"] == "failed"
    assert any("Set-NetFirewallProfile -Profile Public -Enabled False" in c for c in s.calls)


def test_windows_server_firewall_needs_approval():
    s = Fake("windows", WIN_WEAK)
    rep = g.scan(s, "server", "standard", Path(tempfile.mkdtemp()), with_intel=False)
    assert by_id(rep)["win.firewall"]["tier"] == g.CONFIRM


def test_windows_needs_admin():
    s = Fake("windows", WIN_WEAK, admin=False)
    rep = g.scan(s, "client", "standard", Path(tempfile.mkdtemp()), with_intel=False)
    res = g.apply(s, rep, Path(tempfile.mkdtemp()), auto=True, approve=set(), dry=False)
    assert all(r["result"] == "needs-admin" for r in res)


def test_intel_matching_windows():
    s = Fake("windows", WIN_WEAK, tools={"winget"})
    sw, os_hits = g.match_intel(s, INTEL, g.installed_software(s))
    names = {h["name"]: [a["id"] for a in h["advisories"]] for h in sw}
    assert names == {"Plex Media Server": ["CVE-1"], "Google Chrome": ["CVE-2"]}, names
    assert [a["id"] for a in os_hits] == ["CVE-3"]
    fx = g.intel_findings(s, sw, os_hits)
    plex = [x for x in fx if "Plex" in x["title"]][0]
    assert plex["tier"] == g.AUTO and plex["fix"][0]["cmd"][:2] == ["winget", "upgrade"]


def test_intel_no_false_positive_short_names():
    s = Fake("linux", [("dpkg-query", 0, "ssh\t1\nlibc6\t2\nopenssh-server\t9.6\ncore\t1\n")], tools={"dpkg-query"})
    sw, _ = g.match_intel(s, INTEL + [{"id": "CVE-9", "title": "OpenSSH: Race"}], g.installed_software(s))
    assert [h["name"] for h in sw] == ["openssh-server"]


MAC_WEAK = [
    ("--getglobalstate", 0, "Firewall is disabled. (State = 0)"),
    ("spctl --status", 0, "assessments enabled"),
    ("csrutil status", 0, "System Integrity Protection status: enabled."),
    ("fdesetup status", 0, "FileVault is Off."),
    ("AutomaticDownload", 0, "0"),
    ("SoftwareUpdate", 1, "does not exist"),
    ("GuestEnabled", 0, "1"),
    ("softwareupdate -l", 0, "* Label: macOS 27.0.1-27.0.1\n\tTitle: macOS, Action: restart"),
    ("launchctl print", 113, ""),
    ("netstat", 0, ""),
]


def test_macos():
    s = Fake("darwin", MAC_WEAK)
    rep = g.scan(s, "client", "standard", Path(tempfile.mkdtemp()), with_intel=False)
    f = by_id(rep)
    assert f["mac.firewall"]["tier"] == g.AUTO
    assert f["mac.filevault"]["tier"] == g.MANUAL
    assert f["mac.autoupdate"]["detail"] == "未設定: AutomaticDownload"  # キーなしは既定オンとして扱う
    assert f["mac.os_updates"]["tier"] == g.CONFIRM  # 再起動が要るので承認制
    assert f["mac.guest"]["status"] == "weak"
    assert 0 <= rep["score"] < 50


SU_REAL = ("* Label: Safari27.0TahoeAuto-27.0\n\tTitle: Safari, Version: 27.0, Size: 249465KiB, Recommended: YES, \n"
           "* Label: macOS Tahoe 26.7.1-25G241\n\tTitle: macOS Tahoe 26.7.1, Version: 26.7.1, Size: 4145338KiB, Recommended: YES, Action: restart, \n"
           "* Label: macOS 27.0.1-26A434\n\tTitle: macOS 27.0.1, Version: 27.0.1, Size: 11867036KiB, Recommended: YES, Action: restart, \n")


def test_macos_skips_major_upgrade():
    base = [a for a in MAC_WEAK if a[0] != "softwareupdate -l"]
    s = Fake("darwin", base + [("softwareupdate -l", 0, SU_REAL), ("sw_vers", 0, "26.6\n")])
    f = by_id(g.scan(s, "client", "standard", Path(tempfile.mkdtemp()), with_intel=False))
    o = f["mac.os_updates"]
    cmd = " ".join(o["fix"][0]["cmd"]) if isinstance(o["fix"][0], dict) else " ".join(o["fix"][0])
    assert "macOS 27.0.1-26A434" not in cmd and "-a" not in cmd.split()  # メジャー版は入れない・全部入れない
    assert "macOS Tahoe 26.7.1-25G241" in cmd and "Safari27.0TahoeAuto-27.0" in cmd
    assert o["tier"] == g.CONFIRM and "メジャー版" in o["how"]
    # メジャー版だけ残っているときは「なし」扱い（承認待ちにしない）
    only = "* Label: macOS 27.0.1-26A434\n\tTitle: macOS 27.0.1, Version: 27.0.1, Action: restart, \n"
    s = Fake("darwin", base + [("softwareupdate -l", 0, only), ("sw_vers", 0, "26.6\n")])
    o = by_id(g.scan(s, "client", "standard", Path(tempfile.mkdtemp()), with_intel=False))["mac.os_updates"]
    assert o["status"] == "ok" and "メジャー版" in o["detail"]


def test_rollback_journal():
    ans = [("--setglobalstate", 0, "ok")] + MAC_WEAK
    s = Fake("darwin", ans)
    sd = Path(tempfile.mkdtemp())
    rep = g.scan(s, "client", "standard", sd, with_intel=False)
    rep["findings"] = [x for x in rep["findings"] if x["id"] == "mac.firewall"]
    res = g.apply(s, rep, sd, auto=True, approve=set(), dry=False)
    assert res[0]["result"] == "fixed"
    s.calls.clear()
    out = g.rollback(s, sd, None, None)
    assert out == [{"id": "mac.firewall", "result": "rolled-back"}]
    assert any("--setglobalstate off" in c for c in s.calls)
    assert g.rollback(s, sd, None, None) == []  # 二重に戻さない


def test_ssh_dropin_and_lockout_guard():
    sshd_t = "passwordauthentication yes\npermitrootlogin yes\nmaxauthtries 6\n"
    ans = [("launchctl print", 113, ""), ("pgrep", 0, "yes"), ("sshd -T", 0, sshd_t)]
    s = Fake("linux", ans, tools={"sshd"})
    s.files["/etc/ssh/sshd_config"] = "Include /etc/ssh/sshd_config.d/*.conf\n"
    # 鍵が登録されていない → パスワード禁止は締め出しになるので手作業扱い
    f = {x["id"]: x for x in g.check_ssh(s)}
    assert f["ssh.hardening"]["tier"] == g.MANUAL
    s.files["/root/.ssh/authorized_keys"] = "ssh-ed25519 AAAA test\n"
    f = {x["id"]: x for x in g.check_ssh(s)}
    x = f["ssh.hardening"]
    assert x["tier"] == g.CONFIRM and x["fix"][0]["write"].endswith("00-mamori.conf")
    assert {"rm": g.SSH_DROPIN} in x["undo"]
    # 他の設定に負けて反映されない場合は失敗扱いで巻き戻す
    rep = {"findings": [x]}
    s.answers = [("sshd -t", 0, ""), ("sshd -T", 0, sshd_t)] + ans
    res = g.apply(s, rep, Path(tempfile.mkdtemp()), auto=False, approve={"ssh.hardening"}, dry=False)
    assert res[0]["result"] == "failed" and g.SSH_DROPIN not in s.files


def test_auto_never_touches_confirm():
    s = Fake("linux", [("ufw status", 0, "Status: inactive"), ("ss -ltnH", 0,
                       "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 5 127.0.0.1:5432 0.0.0.0:*\n")],
             tools={"ufw"})
    rep = g.scan(s, "server", "standard", Path(tempfile.mkdtemp()), with_intel=False)
    fw = by_id(rep)["linux.firewall"]
    assert fw["tier"] == g.CONFIRM and fw["fix"][0]["cmd"] == ["ufw", "allow", "22/tcp"]
    assert len(fw["fix"]) == 2, "localhost の 5432 は許可しない"
    res = g.apply(s, rep, Path(tempfile.mkdtemp()), auto=True, approve=set(), dry=True)
    assert "linux.firewall" not in [r["id"] for r in res]


def test_ai_plaintext_keys_found_without_leaking_values():
    s = Fake("darwin", MAC_WEAK, admin=False)
    s.env["HOME"] = "/Users/u"
    ant = "sk-ant-api03-" + "a" * 40
    s.files["/Users/u/.zshrc"] = f"export ANTHROPIC_API_KEY={ant}\n"
    s.files["/Users/u/.env"] = "GOOGLE_API_KEY=AIza" + "b" * 35 + "\n"
    rep = g.scan(s, "client", "standard", Path(tempfile.mkdtemp()), with_intel=False)
    f = by_id(rep)["ai.plaintext_keys"]
    assert f["status"] == "weak" and f["tier"] == g.MANUAL
    assert "Anthropic" in f["detail"] and "Google" in f["detail"]
    assert "OpenAI" not in f["detail"]  # sk-ant- を OpenAI と二重に数えない
    assert ant not in json.dumps(rep) and "bbbb" not in json.dumps(rep)
    assert not f["fix"]  # 自動では触らない


def test_ai_plaintext_keys_ok_when_absent():
    s = Fake("linux", [], admin=False)
    s.env["HOME"] = "/home/u"
    s.files["/home/u/.bashrc"] = "export ANTHROPIC_API_KEY=$(security find-generic-password -w)\n"
    f = by_id(g.scan(s, "server", "standard", Path(tempfile.mkdtemp()), with_intel=False))
    assert f["ai.plaintext_keys"]["status"] == "ok"


def test_process_env_flags_secrets_without_leaking_values():
    ant = "sk-ant-api03-" + "a" * 40
    s = Fake("darwin", [("ps eww", 0, f"  123 node server.js ANTHROPIC_API_KEY={ant}\n")], admin=False)
    s.env["HOME"] = "/Users/u"
    rep = g.scan(s, "client", "standard", Path(tempfile.mkdtemp()), with_intel=False)
    f = by_id(rep)["proc.env_exposure"]
    assert f["status"] == "weak" and f["tier"] == g.MANUAL
    assert "AI の API キー" in f["detail"]
    assert ant not in json.dumps(rep) and "aaaa" not in json.dumps(rep)
    assert not f["fix"]  # 自動では触らない


def test_process_env_ok_when_no_secret():
    s = Fake("darwin", [("ps eww", 0, "  123 node server.js PATH=/usr/bin\n")], admin=False)
    s.env["HOME"] = "/Users/u"
    f = by_id(g.scan(s, "client", "standard", Path(tempfile.mkdtemp()), with_intel=False))
    assert f["proc.env_exposure"]["status"] == "ok"


def test_env_secret_kinds_detects_db_url_and_private_key():
    kinds = g._env_secret_kinds("DATABASE_URL=postgres://u:p@db:5432/x\n-----BEGIN RSA PRIVATE KEY-----")
    assert "DB 接続文字列" in kinds and "秘密鍵" in kinds
    assert g._env_secret_kinds("PATH=/usr/bin\nHOME=/root") == set()


ATTACKS = {
    "total_observations": 3, "total_attempts": 7,
    "by_type": {"http_probe": 2, "payload": 1},
    "items": [
        {"type": "http_probe", "type_ja": "探索（設定・秘密ファイルを探す）",
         "pattern": "設定・秘密ファイル探索: /.env, /.git",
         "count": 5, "defenses": [{"finding": "ai.plaintext_keys",
                                   "label": "秘密情報を公開ディレクトリに置かない"}]},
        {"type": "payload", "type_ja": "攻撃の試行（脆弱性を突く）",
         "pattern": "React Server Components脆弱性の悪用試行",
         "count": 2, "defenses": [{"finding": "mac.os_updates", "label": "ソフトを最新に"}]},
    ],
}


def test_observed_attacks_raise_priority_without_double_counting():
    sd = Path(tempfile.mkdtemp())
    (sd / "attacks.json").write_text(json.dumps(ATTACKS), encoding="utf-8")
    s = Fake("darwin", MAC_WEAK)
    rep = g.scan(s, "client", "standard", sd, with_intel=False)
    f = by_id(rep)
    # 観測された攻撃に効く守りは優先度が上がる（重み +2）
    assert f["mac.os_updates"].get("observed_attack") is True
    # 観測情報そのものは info で、点数には数えない
    assert f["attack.observed"]["status"] == "info" and f["attack.observed"]["weight"] == 0
    # 二重計上しない: info を除いた合計で採点される
    counted = [x for x in rep["findings"] if x["status"] in ("ok", "weak")]
    assert all(x["id"] != "attack.observed" for x in counted)


def test_observed_attacks_ok_when_defenses_applied():
    sd = Path(tempfile.mkdtemp())
    (sd / "attacks.json").write_text(json.dumps(ATTACKS), encoding="utf-8")
    # 効く守りがすべて ok のシステム（鍵の平文なし・OS更新なし）
    good = [("--getglobalstate", 0, "Firewall is enabled. (State = 1)"),
            ("fdesetup status", 0, "FileVault is On."),
            ("AutomaticDownload", 0, "1"),
            ("SoftwareUpdate", 0, "1"),
            ("spctl --status", 0, "assessments enabled"),
            ("csrutil status", 0, "System Integrity Protection status: enabled."),
            ("softwareupdate -l", 0, "No new software available."),
            ("launchctl print", 113, ""),
            ("netstat", 0, "")]
    s = Fake("darwin", good, admin=False)
    s.env["HOME"] = "/Users/u"
    s.files["/Users/u/.zshrc"] = "export ANTHROPIC_API_KEY=$(security find-generic-password -w)\n"
    rep = g.scan(s, "client", "standard", sd, with_intel=False)
    f = by_id(rep)
    assert f["attack.covered"]["status"] == "ok"
    assert "attack.observed" not in f


def test_observed_attacks_missing_file_is_safe():
    s = Fake("darwin", MAC_WEAK)
    rep = g.scan(s, "client", "standard", Path(tempfile.mkdtemp()), with_intel=False)
    assert "attack.observed" not in by_id(rep) and "attack.covered" not in by_id(rep)



if __name__ == "__main__":
    n = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            n += 1
            print("ok", name)
    print(f"{n} passed")
