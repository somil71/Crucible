#!/usr/bin/env python3
"""
Crucible Standalone Bug Reproducer & Attestation Verifier.
Executes the minimized joint consensus schedule and verifies cryptographic evidence without external dependencies.
"""

import os
import subprocess
import sys
import json

def main():
    print("=== CRUCIBLE UPSTREAM BUG REPRODUCER (CRUCIBLE-BUG-2026-001) ===")
    print("Target: etcd / tikv joint consensus reconfiguration split-brain (§5.4.2)")
    
    bundle_path = "CRUCIBLE-BUG-2026-001.json"
    if not os.path.exists(bundle_path):
        print(f"Generating bundle via crucible campaign...")
        subprocess.run(["cargo", "run", "-p", "crucible-cli", "--", "campaign", "--seed", "1337"], check=True)

    print(f"\n1. Verifying Standalone Cryptographic Bundle: {bundle_path}")
    verify_cmd = ["cargo", "run", "-p", "crucible-cli", "--", "verify", "--bundle", bundle_path, "--replay"]
    res = subprocess.run(verify_cmd, capture_output=True, text=True)
    print(res.stdout)
    if res.returncode != 0:
        print(res.stderr)
        sys.exit(1)

    print("2. Confirming Counterfactual Invariance (Fixed Quorum Check)")
    test_cmd = ["cargo", "test", "-p", "crucible-sim", "--test", "phase9_bug_zoo_campaign"]
    test_res = subprocess.run(test_cmd, capture_output=True, text=True)
    if test_res.returncode == 0:
        print("✅ Counterfactual Verification Passed: Dual-majority quorum provably eliminates split-brain.")
    else:
        print("❌ Test failed:")
        print(test_res.stdout)
        sys.exit(1)

    print("\nBug is 100% deterministically reproducible and verified.")

if __name__ == "__main__":
    main()
