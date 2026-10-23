#!/usr/bin/env python3
"""Mamori — local test suite (stdlib only, no pytest required).

Covers the four v0.4 features:
  1. CPE/SBOM matching (agent/match_cpe.py) — with mocked NVD responses
  2. STIX 2.1 export (agent/export_stix.py) — structural validation
  3. Hub server (hub/server.py) — auth, TLP, anonymization, rate limits
  4. Pipeline (fetch -> match -> draft) — with fixture data

Run: python3 tests/test_mamori.py
Exit 0 = all passed.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PASS, FAIL = 0, 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} {detail}")


def run(script: str, *args: str, stdin: bytes | None = None,
        preload: str | None = None) -> tuple[int, str]:
    """Run an agent script. `preload` is python code executed in the script's
    process before main() (used to stub network caches deterministically)."""
    if preload:
        wrapper = tempfile.NamedTemporaryFile(
            "w", suffix=".py", delete=False, dir=ROOT / "tests")
        wrapper.write(
            "import sys\n"
            f"sys.path.insert(0, {str(ROOT / 'agent')!r})\n"
            f"import {Path(script).stem} as _m\n"
            f"{preload}\n"
            f"sys.argv = [{script!r}, *{list(args)!r}]\n"
            "sys.exit(_m.main())\n")
        wrapper.close()
        p = subprocess.run([sys.executable, wrapper.name],
                           input=stdin, capture_output=True, timeout=120)
        os.unlink(wrapper.name)
    else:
        p = subprocess.run(
            [sys.executable, str(ROOT / script), *args],
            input=stdin, capture_output=True, timeout=120,
        )
    return p.returncode, p.stdout.decode()


# --- 1. CPE/SBOM matching ---------------------------------------------------
def test_cpe() -> None:
    print("== CPE/SBOM matching ==")
    sys.path.insert(0, str(ROOT / "agent"))
    import match_cpe  # noqa: E402

    # cpe_parts parsing
    check("cpe_parts parses vendor/product",
          match_cpe.cpe_parts("cpe:2.3:a:plex:plex_media_server:*:*:*:*:*:*:*:*")
          == ("plex", "plex_media_server"))
    check("cpe_parts handles short strings", match_cpe.cpe_parts("cpe:2.3:a") == ("", ""))

    # sbom token extraction (CycloneDX + plain list)
    sbom = [
        {"name": "plex-media-server", "cpe": "cpe:2.3:a:plex:plex_media_server:*:*:*:*:*:*:*:*"},
        {"name": "My Tool"},  # no cpe -> name token
    ]
    tokens = match_cpe.sbom_tokens(sbom)
    check("sbom tokens include vendor+product", {"plex", "plex_media_server"} <= tokens)
    check("sbom tokens include normalized name", "my_tool" in tokens)

    # end-to-end with mocked NVD (no network; cache preloaded in subprocess)
    with tempfile.TemporaryDirectory() as td:
        matched = Path(td) / "matched.json"
        sbomf = Path(td) / "sbom.json"
        matched.write_text(json.dumps({"items": [
            {"id": "CVE-2099-0001", "match": {"status": "not-relevant", "hits": []}},
            {"id": "CVE-2099-0002", "match": {"status": "not-relevant", "hits": []}},
            {"id": "jpcert-weekly-2026-10-21", "match": {"status": "not-relevant", "hits": []}},
        ]}))
        sbomf.write_text(json.dumps({"components": sbom}))
        rc, out = run("agent/match_cpe.py", str(matched), str(sbomf),
                      preload='_m._cache.update({'
                              '"CVE-2099-0001": ["cpe:2.3:a:plex:plex_media_server:*:*:*:*:*:*:*:*"],'
                              '"CVE-2099-0002": ["cpe:2.3:a:unrelated:thing:*:*:*:*:*:*:*:*"]'
                              '})')
        check("match_cpe exit 0", rc == 0)
        d = json.loads(out)
        items = {i["id"]: i for i in d["items"]}
        check("CVE with SBOM hit -> relevant",
              items["CVE-2099-0001"]["cpe_match"]["status"] == "relevant")
        check("SBOM hit upgrades overall match",
              items["CVE-2099-0001"]["match"]["status"] == "relevant"
              and items["CVE-2099-0001"]["match"].get("via") == "cpe")
        check("CVE without SBOM hit -> not-relevant",
              items["CVE-2099-0002"]["cpe_match"]["status"] == "not-relevant")
        check("non-CVE item skipped",
              items["jpcert-weekly-2026-10-21"]["cpe_match"]["status"] == "skipped")
        check("cpe_summary present",
              d.get("cpe_summary", {}).get("cpe_relevant") == 1)


# --- 2. STIX 2.1 export ------------------------------------------------------
def test_stix() -> None:
    print("== STIX 2.1 export ==")
    with tempfile.TemporaryDirectory() as td:
        bundle = Path(td) / "bundle.json"
        obs = Path(td) / "obs.jsonl"
        bundle.write_text(json.dumps({"objects": [
            {"id": "CVE-2099-0001", "title": "Test vuln", "url": "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
             "source": "cisa_kev", "severity": "exploited-in-the-wild"},
            {"id": "jpcert-weekly-2026-10-21", "title": "not a cve"},  # must be skipped
        ]}))
        obs.write_text(
            '{"type":"attack-observation","tlp":"CLEAR","pattern":"wp-login brute","count":5}\n'
            '{"type":"attack-observation","tlp":"AMBER","pattern":"rsc probe","count":8}\n'
        )
        rc, out = run("agent/export_stix.py", str(bundle), str(obs))
        check("export_stix exit 0", rc == 0)
        d = json.loads(out)
        check("root is bundle", d.get("type") == "bundle")
        check("bundle id format", bool(re.match(r"^bundle--[0-9a-f-]{36}$", d.get("id", ""))))
        types = [o["type"] for o in d["objects"]]
        check("1 identity + 1 vulnerability + 2 observed-data",
              types.count("identity") == 1 and types.count("vulnerability") == 1
              and types.count("observed-data") == 2,
              f"got {types}")
        ids = [o["id"] for o in d["objects"]]
        check("all ids unique", len(ids) == len(set(ids)))
        check("id/type prefix consistent",
              all(o["id"].startswith(o["type"] + "--") for o in d["objects"]))
        ts_re = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
        check("timestamps are STIX format",
              all(ts_re.match(o.get("created", "")) for o in d["objects"]))
        vuln = next(o for o in d["objects"] if o["type"] == "vulnerability")
        check("vulnerability has CVE external ref",
              any(r.get("external_id") == "CVE-2099-0001" for r in vuln["external_references"]))
        check("vulnerability marked TLP:CLEAR",
              "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
              in vuln["object_marking_refs"])
        amber = next(o for o in d["objects"]
                     if o["type"] == "observed-data" and o["description"] == "rsc probe")
        check("observation keeps TLP:AMBER marking",
              "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
              in amber["object_marking_refs"])
        check("observed-data count preserved", amber["number_observed"] == 8)


# --- 3. Hub server ------------------------------------------------------------
def _wait_port(url: str, tries: int = 30) -> bool:
    for _ in range(tries):
        try:
            urllib.request.urlopen(url, timeout=1)
            return True
        except Exception:
            time.sleep(0.2)
    return False


def test_hub() -> None:
    print("== Hub server ==")
    with tempfile.TemporaryDirectory() as td:
        env = dict(os.environ, MAMORI_ORG_SALT="test-salt",
                   MAMORI_DATA=td,
                   MAMORI_KEYS_JSON='{"k-amber":{"org":"org-a","tlp_max":"AMBER"},'
                                    '"k-clear":{"org":"org-b","tlp_max":"CLEAR"}}',
                   MAMORI_NO_REFRESH="1",  # ネットワーク取得を無効化して決定的に
                   PORT="18099")
        proc = subprocess.Popen([sys.executable, str(ROOT / "hub" / "server.py")],
                                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            base = "http://localhost:18099"
            check("hub starts", _wait_port(base + "/healthz"))

            def get(path: str, key: str | None = None) -> tuple[int, dict]:
                req = urllib.request.Request(base + path)
                if key:
                    req.add_header("X-Mamori-Key", key)
                try:
                    with urllib.request.urlopen(req, timeout=5) as r:
                        return r.status, json.loads(r.read() or b"{}")
                except urllib.error.HTTPError as e:
                    return e.code, json.loads(e.read() or b"{}")

            def post(body: dict, key: str | None = None) -> tuple[int, dict]:
                req = urllib.request.Request(base + "/api/observations",
                                             data=json.dumps(body).encode(),
                                             headers={"Content-Type": "application/json"})
                if key:
                    req.add_header("X-Mamori-Key", key)
                try:
                    with urllib.request.urlopen(req, timeout=5) as r:
                        return r.status, json.loads(r.read() or b"{}")
                except urllib.error.HTTPError as e:
                    return e.code, json.loads(e.read() or b"{}")

            code, _ = get("/healthz")
            check("healthz 200", code == 200)
            code, stats = get("/api/stats")
            check("stats 200 + 2 participants", code == 200 and stats["participants"] == 2)

            code, body = post({"type": "attack-observation", "pattern": "x"})
            check("POST without key -> 403", code == 403)

            code, body = post({"type": "attack-observation", "tlp": "RED", "pattern": "x"}, "k-amber")
            check("POST TLP:RED -> 400 refused", code == 400)

            code, body = post({"type": "attack-observation", "tlp": "CLEAR",
                               "pattern": "scan from 10.1.2.99 by admin@corp.example"}, "k-amber")
            check("POST CLEAR accepted", code == 201)
            code, body = post({"type": "attack-observation", "tlp": "AMBER",
                               "pattern": "internal only"}, "k-amber")
            check("POST AMBER accepted", code == 201)

            # anonymization check
            code, body = get("/api/observations", "k-amber")
            obs = body["observations"]
            clear_obs = next(o for o in obs if o["tlp"] == "CLEAR")
            check("IP anonymized to /24", "10.1.2.0/24" in clear_obs["pattern"])
            check("email masked", "[email-masked]" in clear_obs["pattern"])
            check("org_hash attached (not org name)",
                  "org_hash" in clear_obs and "org-a" not in json.dumps(clear_obs))
            check("timestamp rounded to hour",
                  clear_obs["received_at"] % 3600 == 0)

            # TLP visibility
            code, body = get("/api/observations")  # no key -> CLEAR only
            check("public sees only CLEAR",
                  code == 200 and all(o["tlp"] == "CLEAR" for o in body["observations"])
                  and len(body["observations"]) == 1)
            code, body = get("/api/observations", "k-clear")
            check("CLEAR-key cannot read AMBER",
                  all(o["tlp"] == "CLEAR" for o in body["observations"]))
            code, body = get("/api/observations", "k-amber")
            check("AMBER-key reads CLEAR+AMBER", len(body["observations"]) == 2)

            # terms page
            req = urllib.request.Request(base + "/terms")
            with urllib.request.urlopen(req, timeout=5) as r:
                html = r.read().decode()
            check("/terms 200 with disclaimer",
                  "免責" in html and "利用規約" in html)

            # v0.5 additions: onboarding, whoami, stable org_hash, docs, kit
            req = urllib.request.Request(base + "/start")
            with urllib.request.urlopen(req, timeout=5) as r:
                html = r.read().decode()
            check("/start 200 onboarding guide", "参加ガイド" in html)

            code, body = get("/api/whoami")
            check("whoami without key -> 401", code == 401)
            code, body = get("/api/whoami", "k-amber")
            import hashlib as _h, hmac as _hm
            check("whoami returns salted HMAC org_hash",
                  code == 200 and body["org_hash"] ==
                  _hm.new(b"test-salt", b"mamori-org:org-a", _h.sha256).hexdigest()[:10])

            req = urllib.request.Request(base + "/docs/keys")
            with urllib.request.urlopen(req, timeout=5) as r:
                doc = r.read().decode()
            check("/docs/keys serves key-management doc", "ローテーション" in doc)

            req = urllib.request.Request(base + "/kit.tar.gz")
            with urllib.request.urlopen(req, timeout=5) as r:
                kit = r.read()
            import tarfile, io as _io
            names = tarfile.open(fileobj=_io.BytesIO(kit)).getnames()
            check("kit.tar.gz contains agent + run.sh",
                  "mamori/run.sh" in names
                  and any(n.startswith("mamori/agent/") for n in names))

            # media: only whitelisted names, no traversal
            code, _ = get("/media/../server.py")
            check("media traversal blocked", code == 404)
            code, _ = get("/media/evil.py")
            check("media bad extension blocked", code == 404)

            # POST rate limit (30/hour per key). 2 posts already used above.
            codes = []
            for _ in range(29):
                c, _ = post({"type": "attack-observation", "pattern": "rl"}, "k-amber")
                codes.append(c)
            first_429 = next((i for i, c in enumerate(codes) if c == 429), None)
            check("POST rate limit kicks in around 30/h",
                  first_429 is not None and 26 <= first_429 <= 28
                  and all(c == 429 for c in codes[first_429:]),
                  f"first 429 at post#{first_429 + 3 if first_429 is not None else 'never'}")
        finally:
            proc.terminate()
            proc.wait(timeout=5)


# --- 4. Pipeline (match + draft, offline fixtures) -----------------------------
def test_pipeline() -> None:
    print("== Pipeline (match_inventory + draft_actions) ==")
    fixture = {"fetched_at": "2026-10-22T00:00:00+00:00", "count": 2, "errors": [], "items": [
        {"id": "CVE-2099-0001", "title": "Plex Media Server: Path Vulnerability",
         "url": "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
         "published": "2026-10-20", "source": "cisa_kev",
         "severity": "exploited-in-the-wild",
         "products": ["Plex Media Server"], "due_date": "2026-10-23",
         "required_action": "Apply updates"},
        {"id": "CVE-2099-0002", "title": "Unrelated product issue",
         "url": "", "published": "2026-10-20", "source": "cisa_kev",
         "severity": "info", "products": ["Unrelated"]},
    ]}
    with tempfile.TemporaryDirectory() as td:
        raw = Path(td) / "raw.json"
        raw.write_text(json.dumps(fixture))
        rc, out = run("agent/match_inventory.py", str(raw))
        check("match_inventory exit 0", rc == 0)
        d = json.loads(out)
        check("plex item relevant", d["items"][0]["match"]["status"] == "relevant")
        check("unrelated item not-relevant", d["items"][1]["match"]["status"] == "not-relevant")
        check("summary counts", d["summary"]["relevant"] == 1)

        matched = Path(td) / "matched.json"
        matched.write_text(out)
        rc, out2 = run("agent/draft_actions.py", str(matched))
        check("draft_actions exit 0", rc == 0)
        o = json.loads(out2)
        check("report mentions 要対応", "要対応" in o["report_md"])
        check("report includes Plex guidance", "Plex" in o["report_md"])
        # v0.5: share_bundle carries the full public feed (matching is done
        # locally by each participant); report only covers relevant/maybe.
        check("share_bundle carries full feed", len(o["share_bundle"]["objects"]) == 2,
              f"got {len(o['share_bundle']['objects'])}")


def main() -> int:
    test_cpe()
    test_stix()
    test_pipeline()
    test_hub()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
