#!/usr/bin/env python3
"""Fail a focused Go CI gate unless every named test actually ran and passed."""

import json
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path


def check_results(lines: Iterable[str], package: str, expected: Sequence[str]) -> None:
    if not expected or len(set(expected)) != len(expected):
        raise ValueError("expected test names must be nonempty and unique")
    ran: set[str] = set()
    passed: set[str] = set()
    package_passed = False
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid go test JSON on line {number}") from exc
        if not isinstance(event, dict):
            raise ValueError(f"invalid go test event on line {number}")
        action = event.get("Action")
        if action == "fail":
            raise ValueError("go test reported a failure")
        if event.get("Package") != package:
            continue
        name = event.get("Test")
        if name in expected:
            if action == "skip":
                raise ValueError(f"required test skipped: {name}")
            if action == "run":
                ran.add(name)
            elif action == "pass":
                passed.add(name)
        elif not name and action == "pass":
            package_passed = True
    missing = set(expected) - (ran & passed)
    if missing:
        raise ValueError("required tests did not run and pass: " + ", ".join(sorted(missing)))
    if not package_passed:
        raise ValueError("required package did not pass: " + package)


def main(argv: Sequence[str]) -> int:
    if len(argv) < 3:
        print("usage: assert_go_test_results.py JSONL PACKAGE TEST [TEST ...]", file=sys.stderr)
        return 2
    try:
        with Path(argv[0]).open(encoding="utf-8") as log:
            check_results(log, argv[1], argv[2:])
    except (OSError, UnicodeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"Verified {len(argv) - 2} required tests ran and passed in {argv[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
