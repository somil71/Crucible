#!/usr/bin/env python3
"""
Validates the integrity of the Crucible Claims Registry (CLAIMS.json).
Asserts that every claim has status: 'verified', contains evidence, and references a valid test target.
"""

import json
import os
import sys

def verify_claims():
    claims_file = "CLAIMS.json"
    if not os.path.exists(claims_file):
        print(f"ERROR: {claims_file} not found.")
        sys.exit(1)

    with open(claims_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    claims = data.get("claims", [])
    if not claims:
        print("ERROR: No claims found in CLAIMS.json.")
        sys.exit(1)

    errors = []
    for c in claims:
        cid = c.get("id", "UNKNOWN")
        status = c.get("status")
        target = c.get("test_target")
        evidence = c.get("verification_evidence")

        if status != "verified":
            errors.append(f"Claim {cid} status is '{status}' (expected 'verified').")
        if not evidence:
            errors.append(f"Claim {cid} missing verification_evidence.")
        if not target or not os.path.exists(target):
            errors.append(f"Claim {cid} target '{target}' does not exist on disk.")

    if errors:
        print(f"FAILED: {len(errors)} claim verification errors:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)

    print(f"SUCCESS: All {len(claims)} claims in {claims_file} verified with evidence and valid targets.")

if __name__ == "__main__":
    verify_claims()
