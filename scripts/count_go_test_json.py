#!/usr/bin/env python3
"""Summarize go test -json stream: pass/fail/skip counts per package."""
from __future__ import annotations

import json
import sys
from collections import defaultdict

packages: dict[str, dict[str, int]] = defaultdict(lambda: {"pass": 0, "fail": 0, "skip": 0})
failed_tests: list[str] = []
skipped_tests: list[str] = []

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        print(line, file=sys.stderr)
        continue
    action = ev.get("Action")
    pkg = ev.get("Package", "")
    test = ev.get("Test", "")
    if action == "pass" and test:
        packages[pkg]["pass"] += 1
    elif action == "fail" and test:
        packages[pkg]["fail"] += 1
        failed_tests.append(f"{pkg} {test}")
    elif action == "skip":
        if test:
            packages[pkg]["skip"] += 1
            skipped_tests.append(f"{pkg} {test}")
        else:
            packages[pkg]["skip"] += 1
            skipped_tests.append(f"{pkg} <package>")

total_pass = sum(v["pass"] for v in packages.values())
total_fail = sum(v["fail"] for v in packages.values())
total_skip = sum(v["skip"] for v in packages.values())
pkg_fail = sum(1 for v in packages.values() if v["fail"] > 0)

print(f"SUMMARY pass={total_pass} fail={total_fail} skip={total_skip} packages_with_fail={pkg_fail}")
if failed_tests:
    print("FAILED_TESTS:", *failed_tests[:50], sep="\n  ")
if skipped_tests:
    print(f"SKIPPED count={len(skipped_tests)}")
    for s in skipped_tests[:30]:
        print("  ", s)
    if len(skipped_tests) > 30:
        print(f"  ... and {len(skipped_tests) - 30} more")

sys.exit(1 if total_fail or pkg_fail else 0)
