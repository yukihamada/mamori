#!/usr/bin/env python3
"""Mamori — threat-intel fetcher.

Fetches latest security advisories from public sources and normalizes
them into a common JSON shape:

  {"id": "...", "title": "...", "url": "...", "published": "ISO8601",
   "source": "cisa_kev|jpcert|ghsa", "severity": "...", "products": [...]}

Sources (no auth required):
  - CISA KEV (Known Exploited Vulnerabilities catalog, JSON)
  - JPCERT/CC weekly report (HTML, lightweight parse)
"""
from __future__ import annotations

import json
import re
import sys
import urllib.request
from datetime import datetime, timezone

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
JPCERT_URL = "https://www.jpcert.or.jp/wr/"
UA = {"User-Agent": "mamori-agent/0.1 (+https://mamori.fly.dev)"}


def _get(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def fetch_kev(limit: int = 20) -> list[dict]:
    data = json.loads(_get(KEV_URL))
    vulns = data.get("vulnerabilities", [])
    # newest first by dateAdded
    vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    out = []
    for v in vulns[:limit]:
        out.append({
            "id": v.get("cveID"),
            "title": f"{v.get('vendorProject','')} {v.get('product','')}: {v.get('vulnerabilityName','')}",
            "url": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}",
            "published": v.get("dateAdded"),
            "source": "cisa_kev",
            "severity": "exploited-in-the-wild",
            "products": [f"{v.get('vendorProject','')} {v.get('product','')}".strip()],
            "due_date": v.get("dueDate"),
            "required_action": v.get("requiredAction"),
        })
    return out


def fetch_jpcert(limit: int = 10) -> list[dict]:
    html = _get(JPCERT_URL).decode("utf-8", "replace")
    items = []
    # weekly report entries: <a href="/wr/2026/wr261021.html">...</a>
    for m in re.finditer(r'href="(/wr/\d{4}/(wr\d{6})\.html)"[^>]*>(.*?)</a>', html):
        path, wrid, title = m.groups()
        date = f"20{wrid[2:4]}-{wrid[4:6]}-{wrid[6:8]}"
        title = re.sub(r"<[^>]+>", "", title).strip() or f"JPCERT/CC Weekly Report {date}"
        items.append({
            "id": f"jpcert-weekly-{date}",
            "title": title,
            "url": f"https://www.jpcert.or.jp{path}",
            "published": date,
            "source": "jpcert",
            "severity": "info",
            "products": [],
        })
        if len(items) >= limit:
            break
    return items


def main() -> int:
    items = []
    errors = []
    for name, fn in (("cisa_kev", fetch_kev), ("jpcert", fetch_jpcert)):
        try:
            items.extend(fn())
        except Exception as e:  # noqa: BLE001
            errors.append({"source": name, "error": str(e)})
    result = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "count": len(items),
        "items": items,
        "errors": errors,
    }
    json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
    print()
    return 0 if items else 1


if __name__ == "__main__":
    sys.exit(main())
