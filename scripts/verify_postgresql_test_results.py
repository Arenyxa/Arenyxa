"""Require the live PostgreSQL correctness cases to execute without skips."""
from __future__ import annotations

import argparse
from pathlib import Path
from xml.etree import ElementTree

REQUIRED_TESTS = frozenset({
    "test_postgres_clock_authority_covers_fast_and_portable_paths",
    "test_postgres_completion_validates_expiry_after_worker_lock_wait",
    "test_postgres_completion_wins_before_revocation",
    "test_postgres_concurrent_same_key_returns_one_job",
    "test_postgresql_stale_recovery_rechecks_heartbeat_after_candidate_selection",
    "test_postgresql_fast_lease_sql_parameter_contract",
    "test_postgresql_worker_revoke_race_does_not_escape_deadlock",
})


def validate(path: Path) -> list[str]:
    try:
        root = ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError) as error:
        return [f"PostgreSQL test evidence is unavailable: {error}"]
    cases = list(root.iter("testcase"))
    names = {case.get("name", "") for case in cases}
    findings = [f"Required live PostgreSQL case missing: {name}" for name in sorted(REQUIRED_TESTS - names)]
    for case in cases:
        if any(case.find(state) is not None for state in ("skipped", "failure", "error")):
            findings.append(f"PostgreSQL case did not pass: {case.get('name', '<unnamed>')}")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    findings = validate(args.report)
    if findings:
        print("PostgreSQL live correctness gate: FAIL")
        for item in findings:
            print("- " + item)
        return 1
    print(f"PostgreSQL live correctness gate: PASS ({len(REQUIRED_TESTS)} required cases, zero skips)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
