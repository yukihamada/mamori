#!/usr/bin/env python3
"""守 Mamori — 端末の守りを毎日定量化する。

`mamori_guard.py scan --json` を実行し、その日の点と内訳を履歴に残す。
結果はアプリ（メニューバー）とハブが読める形で `~/.mamori/status.json` に書き出す。

- 履歴: `~/.mamori/history.jsonl`（1日1行・同日は最新で上書き）
- 最新: `~/.mamori/status.json`（アプリが読む）
- 標準ライブラリのみ。オフラインでも guard のキャッシュで動く。

使い方:
    python3 agent/daily.py              # 点検して記録（既定）
    python3 agent/daily.py --fix        # 先に自動で直せるものだけ直す（tier=auto）
    python3 agent/daily.py --json       # status.json の中身を標準出力にも出す
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

HOME = Path.home()
DEFAULT_STATE = HOME / ".mamori"
GUARD_CANDIDATES = [
    os.environ.get("MAMORI_GUARD", ""),
    str(Path(__file__).resolve().parent / "mamori_guard.py"),
    str(HOME / ".mamori" / "kit" / "mamori" / "agent" / "mamori_guard.py"),
]

# スコアの重み（guard の findings の weight をそのまま使う）。
# 100点 = 重み付きで全項目が ok。weak は減点、info は採点対象外。
STATUS_JA = {"ok": "できている", "weak": "要改善", "ack": "対応済み（確認待ち）",
             "unknown": "未確認", "info": "参考"}
TIER_JA = {"auto": "自動で直せる", "confirm": "承認すれば直せる", "manual": "手作業が必要"}


def find_guard() -> Path:
    for c in GUARD_CANDIDATES:
        if c and Path(c).exists():
            return Path(c)
    raise SystemExit("mamori_guard.py が見つかりません（MAMORI_GUARD で指定できます）")


def state_dir() -> Path:
    return Path(os.environ.get("MAMORI_STATE_DIR") or DEFAULT_STATE)


def run_guard(guard: Path, args: list[str], timeout: int = 240) -> dict:
    """guard を実行し、JSON 出力を辞書で返す。"""
    cp = subprocess.run([sys.executable, str(guard), *args, "--json"],
                        capture_output=True, text=True, timeout=timeout)
    out = cp.stdout.strip()
    # guard は JSON の前にログ行を出さないが、念のため最初の { から読む
    start = out.find("{")
    if start < 0:
        raise SystemExit(f"guard の出力を読めませんでした: {out[:200]} {cp.stderr[:200]}")
    return json.loads(out[start:])


def today_str() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d")


def load_history(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    return rows


def save_history(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")
    tmp.replace(path)


def upsert_today(rows: list[dict], entry: dict) -> list[dict]:
    """同じ日付の行は最新で置き換える（1日1行）。"""
    day = entry["date"]
    out = [r for r in rows if r.get("date") != day]
    out.append(entry)
    out.sort(key=lambda r: r.get("date", ""))
    return out


def load_ack(sd: Path) -> dict[str, str]:
    """アプリで「対応した」と記録された項目ID→記録日。"""
    p = sd / "acknowledged.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if isinstance(data, dict):
        return {k: str(v) for k, v in data.items() if isinstance(k, str)}
    if isinstance(data, list):  # 旧形式（日付なし）は今日として扱う
        return {x: today_str() for x in data if isinstance(x, str)}
    return {}


def summarize(report: dict, prev: dict | None, history: list[dict], acked: dict[str, str] | None = None) -> dict:
    acked = acked or {}
    today = today_str()
    findings = report.get("findings", [])
    # 「対応した」は当日ぶんだけ表示を静める。翌日以降もまだ weak なら再登場させ、
    # 実際に直ったかを次の点検で確かめる（点数は水増ししない）。
    def effective(f: dict) -> str:
        if f.get("status") == "weak" and acked.get(f.get("id", "")) == today:
            return "ack"
        return f.get("status", "")
    weak = [f for f in findings if effective(f) == "weak"]
    ack_weak = [f for f in findings if effective(f) == "ack"]
    all_weak = [f for f in findings if f.get("status") == "weak"]
    # 点数は guard の実スコア。ack では加点しない（未修正を「直った」扱いにしない）。
    score = report.get("score")
    prev_score = (prev or {}).get("score")
    delta = (score - prev_score) if (score is not None and prev_score is not None) else None

    # 7日ぶんの推移（古い→新しい）。今日を含める。
    trend = [{"date": r["date"], "score": r.get("score")} for r in history[-7:]]

    # いま直すべき上位（重い weak から）。ack 済みは出さない。
    actions = sorted(weak, key=lambda f: -int(f.get("weight", 0)))
    top = [{"id": f["id"], "title": f.get("title", ""), "detail": f.get("detail", ""),
            "weight": f.get("weight", 0), "tier": f.get("tier", ""),
            "tier_ja": TIER_JA.get(f.get("tier", ""), ""),
            "how": f.get("how", "")} for f in actions[:5]]

    return {
        "updated": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "date": today_str(),
        "host": os.environ.get("MAMORI_HOST") or os.uname().nodename.split(".")[0][:40],
        "os": report.get("os", ""),
        "os_version": report.get("os_version", ""),
        "admin": report.get("admin", False),
        "intel": report.get("intel", ""),
        "score": score,
        "prev_score": prev_score,
        "delta": delta,
        "grade": grade(score),
        "counts": {"ok": sum(1 for f in findings if f.get("status") == "ok"),
                   "weak": len(all_weak),
                   "ack": len(ack_weak),
                   "total": sum(1 for f in findings if f.get("status") in ("ok", "weak"))},
        "trend": trend,
        "findings": [{"id": f["id"], "title": f.get("title", ""), "status": effective(f),
                      "status_ja": STATUS_JA.get(effective(f), ""),
                      "detail": f.get("detail", ""), "weight": f.get("weight", 0),
                      "tier": f.get("tier", ""), "tier_ja": TIER_JA.get(f.get("tier", ""), ""),
                      "how": f.get("how", "")}
                     for f in findings],
        "top_actions": top,
        "history_days": len(history),
    }


def grade(score) -> str:
    if score is None:
        return "不明"
    if score >= 90:
        return "とても良い"
    if score >= 75:
        return "良い"
    if score >= 60:
        return "ふつう"
    if score >= 40:
        return "注意"
    return "要対応"


def main() -> int:
    ap = argparse.ArgumentParser(description="守 Mamori の毎日の定量記録")
    ap.add_argument("--fix", action="store_true", help="先に自動で直せるもの（tier=auto）だけ直す")
    ap.add_argument("--json", action="store_true", help="status.json の中身も標準出力に出す")
    ap.add_argument("--quiet", action="store_true", help="1行だけ出す")
    a = ap.parse_args()

    guard = find_guard()
    sd = state_dir()
    sd.mkdir(parents=True, exist_ok=True)

    # 観測された攻撃を取り込む（守りの点検より先。guard が attacks.json を読む）
    attacks = None
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import attacks as attacks_mod  # noqa: PLC0415
        key = attacks_mod.load_key()
        items = [attacks_mod.classify(o) for o in attacks_mod.fetch_hub(key)]
        items += [attacks_mod.classify(o) for o in attacks_mod.local_traces()]
        merged: dict[str, dict] = {}
        for it in items:
            k = it["pattern"][:120]
            if k in merged:
                merged[k]["count"] = (merged[k].get("count") or 1) + (it.get("count") or 1)
            else:
                merged[k] = it
        items = sorted(merged.values(), key=lambda x: -(x.get("count") or 1))
        attacks = attacks_mod.summarize(items)
        (sd / "attacks.json").write_text(json.dumps(attacks, ensure_ascii=False, indent=1), encoding="utf-8")
    except Exception as e:  # 攻撃情報が取れなくても点検は続ける
        print(f"[daily] 攻撃観測をスキップ: {type(e).__name__} {e}", file=sys.stderr)

    fixed = 0
    if a.fix:
        try:
            res = run_guard(guard, ["fix", "--auto"])
            fixed = sum(1 for r in res.get("applied", []) if r.get("result") == "fixed")
        except Exception as e:  # 直せなくても点検は続ける
            print(f"[daily] 自動修正をスキップ: {type(e).__name__} {e}", file=sys.stderr)

    report = run_guard(guard, ["scan"])

    acked = load_ack(sd)
    hist_path = sd / "history.jsonl"
    rows = load_history(hist_path)
    prev = rows[-1] if rows else None
    if prev and prev.get("date") == today_str():
        prev = rows[-2] if len(rows) > 1 else None

    # 履歴にも status と同じ実スコアを記録し、食い違わせない。
    # 「対応した」は当日ぶん表示を静めるだけで、点数は実スコアのまま据え置く。
    findings = report.get("findings", [])
    today = today_str()
    # status.counts と同じ基準（weak は ack を含む実数、ack は別枠）で記録し、
    # status と history で件数が食い違わないようにする。
    entry = {"date": today,
             "score": report.get("score"),
             "counts": {"ok": sum(1 for f in findings if f.get("status") == "ok"),
                        "weak": sum(1 for f in findings if f.get("status") == "weak"),
                        "ack": sum(1 for f in findings if f.get("status") == "weak"
                                   and acked.get(f.get("id", "")) == today)},
             "fixed": fixed}
    rows = upsert_today(rows, entry)
    save_history(hist_path, rows)

    status = summarize(report, prev, rows, acked)
    status["fixed_today"] = fixed
    if attacks:
        status["attacks"] = {"total_observations": attacks["total_observations"],
                             "total_attempts": attacks["total_attempts"],
                             "by_type": attacks["by_type"],
                             "top": [{"type_ja": it["type_ja"], "pattern": it["pattern"],
                                      "count": it.get("count", 1)}
                                     for it in attacks["items"][:5]]}
    status_path = sd / "status.json"
    tmp = status_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(status, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(status_path)

    if a.quiet:
        d = status["delta"]
        arrow = "" if d is None else (f" (+{d})" if d > 0 else (f" ({d})" if d < 0 else " (±0)"))
        print(f"[daily] {status['date']} score={status['score']}{arrow} weak={status['counts']['weak']} fixed={fixed}")
    else:
        print(f"🛡 守 Mamori — {status['date']} の守りの点数: {status['score']} 点（{status['grade']}）")
        if status["delta"] is not None:
            print(f"   前回との差: {status['delta']:+d} ／ できている {status['counts']['ok']} / 要改善 {status['counts']['weak']}")
        if status["top_actions"]:
            print("   次に直すと効くもの:")
            for t in status["top_actions"][:3]:
                print(f"    - [{t['tier_ja']}] {t['title']}（重み {t['weight']}）")
    if a.json:
        print(json.dumps(status, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
