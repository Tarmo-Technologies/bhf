#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare a release review; never treat scanner silence as human approval.

Critical/High, unknown severity, fixable Medium, and stale/invalid databases
block signing. Remaining findings are retained for the protected release
reviewer to accept or reject; none are automatically marked not_affected.
"""
import argparse
import datetime as dt
import hashlib
import json
import pathlib


def review(scan, now):
    db = scan.get("descriptor", {}).get("db", {}).get("status", {})
    built = dt.datetime.fromisoformat(db.get("built", "").replace("Z", "+00:00"))
    if not db.get("valid") or built.tzinfo is None or not dt.timedelta(0) <= now - built <= dt.timedelta(days=7):
        raise ValueError("invalid, future, or older-than-seven-days vulnerability database")
    if "matches" not in scan or not isinstance(scan["matches"], list):
        raise ValueError("missing vulnerability matches")
    blockers, residual = [], []
    for match in scan["matches"]:
        v, a = match["vulnerability"], match["artifact"]
        severity, fix = v["severity"], v.get("fix", {})
        finding = {"vulnerability": v["id"], "package": a["name"], "version": a["version"],
                   "purl": a.get("purl"), "severity": severity, "fix": fix,
                   "source": v.get("dataSource"), "status": "under_investigation"}
        if severity not in ("Medium", "Low", "Negligible") or (severity == "Medium" and fix.get("state") == "fixed"):
            blockers.append(finding)
        else:
            residual.append(finding)
    return {"schema_version": 1, "database": db,
            "decision": "BLOCK" if blockers else "REQUIRES_PROTECTED_REVIEW",
            "blockers": blockers, "residual_findings": residual,
            "review_requirement": "Production environment reviewer must review the exact archive and residual findings before signing."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=pathlib.Path)
    args = parser.parse_args()
    scan_bytes = (args.evidence / "grype.json").read_bytes()
    result = review(json.loads(scan_bytes), dt.datetime.now(dt.timezone.utc))
    result["scan_sha256"] = hashlib.sha256(scan_bytes).hexdigest()
    result["image_id"] = json.loads((args.evidence / "image-inspect.json").read_text())[0]["Id"]
    (args.evidence / "release-review.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f'{result["decision"]}: {len(result["blockers"])} blockers, {len(result["residual_findings"])} residual matches')
    raise SystemExit(1 if result["blockers"] else 0)


if __name__ == "__main__":
    main()
