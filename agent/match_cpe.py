#!/usr/bin/env python3
"""Mamori — CPE/SBOM-based matcher (v0.4).

Two matching modes:
  1. Keyword watch list (legacy, fast)
  2. CPE/SBOM matching: give an SBOM (CycloneDX JSON or simple
     [{"name": "...", "version": "...", "cpe": "cpe:2.3:..."}])
     and advisories are matched by CPE vendor/product names.
     When the advisory is a CVE, CPE data is fetched from NVD API
     (no key required, rate-limited politely).

Usage:
  python3 match_cpe.py matched.json sbom.json
Output: matched.json enriched with "cpe_match" fields.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
UA = {"User-Agent": "mamori-agent/0.4"}
_cache: dict[str, list[str]] = {}


def fetch_cpes_for_cve(cve_id: str) -> list[str]:
    """Return CPE match strings (cpe:2.3:...) for a CVE from NVD."""
    if cve_id in _cache:
        return _cache[cve_id]
    try:
        req = urllib.request.Request(NVD_CVE_URL.format(cve_id), headers=UA)
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
        cpes = []
        for v in data.get("vulnerabilities", []):
            for c in v.get("cve", {}).get("configurations", []):
                for n in c.get("nodes", []):
                    for m in n.get("cpeMatch", []):
                        cpes.append(m.get("criteria", ""))
        _cache[cve_id] = cpes
        time.sleep(0.7)  # NVD polite rate limit (~50 req/30s without key)
        return cpes
    except Exception:
        _cache[cve_id] = []
        return []


def cpe_parts(cpe: str) -> tuple[str, str]:
    """cpe:2.3:a:vendor:product:... -> (vendor, product)"""
    p = cpe.split(":")
    if len(p) >= 5:
        return p[3].lower(), p[4].lower()
    return "", ""


def sbom_tokens(sbom: list[dict]) -> set[str]:
    """Tokens to match against CPE vendor/product."""
    tokens = set()
    for comp in sbom:
        if comp.get("cpe"):
            v, pr = cpe_parts(comp["cpe"])
            tokens.update(t for t in (v, pr) if t)
        name = (comp.get("name") or "").lower().replace(" ", "_").replace("-", "_")
        if name:
            tokens.add(name)
    return tokens


def main() -> int:
    matched_path, sbom_path = sys.argv[1], sys.argv[2]
    data = json.load(open(matched_path))
    sbom_raw = json.load(open(sbom_path))
    # CycloneDX: {"components": [...]} or plain list
    sbom = sbom_raw.get("components", sbom_raw) if isinstance(sbom_raw, dict) else sbom_raw
    tokens = sbom_tokens(sbom)

    hits = 0
    for item in data.get("items", []):
        cve = item.get("id", "")
        if not cve.startswith("CVE-"):
            item["cpe_match"] = {"status": "skipped", "hits": []}
            continue
        cpes = fetch_cpes_for_cve(cve)
        matched_tokens = set()
        for cpe in cpes:
            v, pr = cpe_parts(cpe)
            if v in tokens or pr in tokens:
                matched_tokens.add(f"{v}:{pr}")
        status = "relevant" if matched_tokens else "not-relevant"
        item["cpe_match"] = {"status": status, "hits": sorted(matched_tokens)}
        if matched_tokens:
            hits += 1
            # upgrade overall match
            if item.get("match", {}).get("status") == "not-relevant":
                item["match"] = {"status": "relevant", "hits": sorted(matched_tokens), "via": "cpe"}
    data["cpe_summary"] = {"sbom_components": len(sbom), "cpe_relevant": hits}
    json.dump(data, sys.stdout, ensure_ascii=False, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
