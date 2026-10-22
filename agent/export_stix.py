#!/usr/bin/env python3
"""Mamori — STIX 2.1 exporter.

Converts the Mamori intel bundle + shared observations into a STIX 2.1
bundle that existing TIP/SIEM tools (MISP, OpenCTI, etc.) can import.

Usage: python3 export_stix.py latest_bundle.json observations.jsonl
"""
from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone

NS = "identity--mamori"
MAMORI_IDENTITY = {
    "type": "identity",
    "spec_version": "2.1",
    "id": "identity--" + str(uuid.uuid5(uuid.NAMESPACE_DNS, "mamori.teai.io")),
    "created": "2026-10-22T00:00:00.000Z",
    "modified": "2026-10-22T00:00:00.000Z",
    "name": "Mamori (teai.io)",
    "identity_class": "organization",
}

TLP_MARKINGS = {
    "CLEAR": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def advisory_to_sdo(item: dict) -> dict:
    vid = str(uuid.uuid5(uuid.NAMESPACE_URL, item.get("url", item["id"])))
    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": f"vulnerability--{vid}",
        "created": _now(),
        "modified": _now(),
        "name": item["id"],
        "description": item.get("title", ""),
        "external_references": [
            {"source_name": "cve", "external_id": item["id"], "url": item.get("url", "")},
            {"source_name": "mamori_source", "external_id": item.get("source", "")},
        ],
        "labels": [item.get("severity", "unknown")],
        "object_marking_refs": [TLP_MARKINGS["CLEAR"]],
        "created_by_ref": MAMORI_IDENTITY["id"],
    }


def observation_to_sdo(obs: dict) -> dict:
    oid = str(uuid.uuid5(uuid.NAMESPACE_DNS, json.dumps(obs, sort_keys=True)))
    tlp = obs.get("tlp", "GREEN")
    return {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": f"observed-data--{oid}",
        "created": _now(),
        "modified": _now(),
        "first_observed": obs.get("first_seen", _now()),
        "last_observed": obs.get("last_seen", _now()),
        "number_observed": int(obs.get("count", 1)),
        "description": obs.get("pattern", obs.get("type", "attack-observation")),
        "object_marking_refs": [TLP_MARKINGS.get(tlp, TLP_MARKINGS["GREEN"])],
        "created_by_ref": MAMORI_IDENTITY["id"],
        "x_mamori_severity": obs.get("severity", "unknown"),
        "x_mamori_note": obs.get("note", ""),
    }


def main() -> int:
    bundle = json.load(open(sys.argv[1]))
    objects = [MAMORI_IDENTITY]
    for item in bundle.get("objects", []):
        if item.get("id", "").startswith("CVE-"):
            objects.append(advisory_to_sdo(item))
    if len(sys.argv) > 2:
        try:
            for line in open(sys.argv[2]):
                line = line.strip()
                if line:
                    objects.append(observation_to_sdo(json.loads(line)))
        except FileNotFoundError:
            pass
    stix = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    json.dump(stix, sys.stdout, ensure_ascii=False, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
