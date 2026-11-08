"""daily.py の「対応した」(ack) 採点ロジックの回帰テスト。

ネットワークには出ない。summarize の純粋な部分だけ検証する。
方針: ack は当日ぶん表示を静めるだけで、点数は水増ししない。
"""
import importlib.util
from pathlib import Path

_p = Path(__file__).resolve().parent.parent / "agent" / "daily.py"
_spec = importlib.util.spec_from_file_location("daily", _p)
d = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(d)


def _report():
    return {"score": 42, "findings": [
        {"id": "a", "title": "A", "status": "ok", "weight": 5},
        {"id": "b", "title": "B", "status": "weak", "weight": 5},
        {"id": "c", "title": "C", "status": "weak", "weight": 5},
        {"id": "e", "title": "E", "status": "weak", "weight": 5},
    ]}


def test_ack_does_not_inflate_score():
    today = d.today_str()
    s = d.summarize(_report(), None, [], {"b": today, "c": today, "e": today})
    assert s["score"] == 42, "ack で点数を水増ししてはいけない"


def test_ack_keeps_real_weak_count_and_ack_subset():
    today = d.today_str()
    s = d.summarize(_report(), None, [], {"b": today, "c": today, "e": today})
    assert s["counts"]["weak"] == 3, "weak は実数（ack 除外前）"
    assert s["counts"]["ack"] == 3, "ack は確認待ち件数"


def test_ack_hides_from_top_actions_today():
    today = d.today_str()
    s = d.summarize(_report(), None, [], {"b": today, "c": today, "e": today})
    assert s["top_actions"] == []


def test_ack_expires_next_day():
    s = d.summarize(_report(), None, [], {"b": "2000-01-01"})
    assert s["counts"]["ack"] == 0
    assert s["counts"]["weak"] == 3
    assert any(f["id"] == "b" and f["status"] == "weak" for f in s["findings"])


def test_ack_legacy_list_format():
    # 旧形式（[String]）は今日として扱う
    today = d.today_str()
    s = d.summarize(_report(), None, [], {"b": today})
    assert s["counts"]["ack"] == 1
    assert s["score"] == 42
