#!/usr/bin/env python3
"""Check the JSON report from CI's live test.

Usage: check-live-report.py REPORT.json EXIT_CODE

Prints every result first, so a failed run shows which check went wrong,
then checks that example.com passes SPF and DMARC, that expired.badssl.com
fails, and that the script exited 1.

Exit codes:
  0   all checks as expected
  1   a real failure: wrong result, wrong exit code or invalid JSON
  75  only expired.badssl.com was unreachable (a network problem, not a
      script bug). The workflow retries on this code and nothing else, so
      retries can never hide a real failure. 75 is EX_TEMPFAIL from sysexits.
"""
import json
import sys
from pathlib import Path

TEMPFAIL = 75


def main(report_path: Path, exit_code: int) -> int:
    print(f"exit code: {exit_code}")
    text = report_path.read_text()
    try:
        report = json.loads(text)
    except ValueError:
        print(f"::error::{report_path} is not valid JSON:")
        print(text)
        return 1

    checks = {(c["domain"], c["id"]): c for c in report["checks"]}
    for (domain, check_id), c in sorted(checks.items()):
        print(f"{c['status']:<5} {domain:<14} {check_id:<26} {c['detail']}")

    errors = []
    unreachable = False
    expired = checks.get(("(extra hosts)", "https:expired.badssl.com"))
    if expired is None:
        errors.append("no result for expired.badssl.com")
    elif expired["status"] != "FAIL":
        # The script reports an unreachable host as WARN, not FAIL.
        if "resolve" in expired["detail"] or "reachable" in expired["detail"]:
            unreachable = True
        else:
            errors.append("expired certificate not detected: " + expired["status"])

    for check_id in ("spf", "dmarc"):
        status = checks.get(("example.com", check_id), {}).get("status")
        if status != "PASS":
            errors.append(f"example.com {check_id}: expected PASS, got {status}")

    # When badssl.com is unreachable there is no FAIL, so exit 0 is expected
    # and says nothing about the script.
    if not unreachable and exit_code != 1:
        errors.append(f"exit code {exit_code}, expected 1 (one FAIL)")

    for e in errors:
        print(f"::error::{e}")
    if errors:
        return 1
    if unreachable:
        print("expired.badssl.com was unreachable from this runner "
              "(network problem, not a script bug)")
        return TEMPFAIL
    print("live checks OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), int(sys.argv[2])))
