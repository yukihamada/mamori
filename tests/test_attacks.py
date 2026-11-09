"""attacks.py の分類・集計・安全な出力のテスト。

ネットワークには出ない。classify / summarize / local_traces の純粋な部分だけ検証する。
"""
import importlib.util
import json
from pathlib import Path

_p = Path(__file__).resolve().parent.parent / "agent" / "attacks.py"
_spec = importlib.util.spec_from_file_location("attacks", _p)
a = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a)


def test_classify_maps_type_to_japanese():
    it = a.classify({"type": "http_probe", "pattern": "/info.php へのGET", "count": 3})
    assert it["type_ja"] == "探索（設定・秘密ファイルを探す）"
    assert it["count"] == 3


def test_classify_unknown_type_is_other():
    it = a.classify({"type": "wat", "pattern": "x"})
    assert it["type_ja"] == "その他"


def test_classify_links_defenses_to_finding_ids():
    it = a.classify({"type": "http_probe", "pattern": "設定・秘密ファイル探索: /.env, /.git"})
    ids = [d["finding"] for d in it["defenses"]]
    assert "ai.plaintext_keys" in ids
    it = a.classify({"type": "payload", "pattern": "React Server Components脆弱性の悪用試行"})
    assert "mac.os_updates" in [d["finding"] for d in it["defenses"]]


def test_classify_does_not_invent_defenses():
    it = a.classify({"type": "other", "pattern": "外部に開いた待受ポート 3件"})
    assert it["defenses"] == []


def test_classify_links_agent_host_exec_to_process_env():
    it = a.classify({"type": "other",
                     "pattern": "コード実行ツールが /proc/<pid>/environ から環境変数を読み出した"})
    assert "proc.env_exposure" in [d["finding"] for d in it["defenses"]]


def test_summarize_counts_types_and_attempts():
    items = [a.classify({"type": "http_probe", "pattern": "p1", "count": 5}),
             a.classify({"type": "payload", "pattern": "p2", "count": 2})]
    s = a.summarize(items)
    assert s["total_observations"] == 2 and s["total_attempts"] == 7
    assert s["by_type"]["探索（設定・秘密ファイルを探す）"] == 1
    assert s["items"] == items


def test_summarize_defaults_count_to_one():
    s = a.summarize([a.classify({"type": "scanner", "pattern": "p"})])
    assert s["total_attempts"] == 1


def test_observations_never_leak_secret_like_values():
    # パターンに鍵らしき文字列が混ざっても、そのまま保持はするが「秘密の値」を生成しない設計の確認
    it = a.classify({"type": "http_probe", "pattern": "/.env へのGET"})
    blob = json.dumps(a.summarize([it]), ensure_ascii=False)
    assert "sk-ant-" not in blob and "AIza" not in blob


if __name__ == "__main__":
    n = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            n += 1
            print("ok", name)
    print(f"{n} passed")
