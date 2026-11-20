#!/usr/bin/env bash
# Regression tests for SPF lookup counting (RFC 7208 10-lookup limit).
#
# Runs domain-security-check.sh against planted SPF records in
# tests/spf-records.txt, served by the fake dig in tests/fake-bin, so the SPF
# tree never touches real DNS. Each case checks the reported status and
# detail, and how many SPF queries the script actually made: before the fix,
# a record that includes itself made hundreds of queries or never finished.
#
# Usage:   bash tests/spf-limit.sh
# Shell:   set BASH_UNDER_TEST=/bin/bash to run the script with macOS's bash 3.2
# Needs:   bash, perl (for the timeout), python3
# Network: the HTTPS checks still try to resolve the reserved .test names,
#          which fail immediately; nothing else leaves the machine.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
script="$here/../domain-security-check.sh"
shell_under_test=${BASH_UNDER_TEST:-bash}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export FAKE_RECORDS="$here/spf-records.txt"
failures=0

# check DOMAIN STATUS DETAIL-SUBSTRING MAX-SPF-QUERIES
check() {
  local domain=$1 want_status=$2 want_text=$3 max_queries=$4 rc=0 result status detail queries
  export DIG_LOG="$work/$domain.log"
  : > "$DIG_LOG"
  # perl's alarm is a portable timeout (macOS has no `timeout` command).
  PATH="$here/fake-bin:$PATH" perl -e 'alarm 30; exec @ARGV' \
    "$shell_under_test" "$script" --json "$domain" > "$work/$domain.json" 2>/dev/null || rc=$?
  if [ "$rc" -ge 128 ]; then
    echo "FAIL $domain: timed out after 30s (exit $rc)"; failures=$((failures + 1)); return
  fi
  result=$(python3 -I -c '
import json, sys
for c in json.load(open(sys.argv[1]))["checks"]:
    if c["id"] == "spf_lookups":
        print(c["status"] + "\t" + c["detail"])
' "$work/$domain.json")
  status=${result%%$'\t'*}
  detail=${result#*$'\t'}
  queries=$(wc -l < "$DIG_LOG" | tr -d ' ')

  if [ "$status" != "$want_status" ]; then
    echo "FAIL $domain: status $status, expected $want_status ($detail)"; failures=$((failures + 1))
  elif [[ $detail != *"$want_text"* ]]; then
    echo "FAIL $domain: detail '$detail' lacks '$want_text'"; failures=$((failures + 1))
  elif [ "$queries" -gt "$max_queries" ]; then
    echo "FAIL $domain: $queries SPF queries, expected at most $max_queries"; failures=$((failures + 1))
  else
    echo "ok   $domain: $status, $queries SPF queries, $detail"
  fi
}

# Correct counting for normal records
check ok.test     PASS "3 DNS lookups"  2   # a + mx + include
check shared.test PASS "4 DNS lookups"  5   # same include from two branches is not a loop
# Loops are named and stop at once
check self.test   FAIL "Include loop (self.test -> self.test)" 1
check loopa.test  FAIL "Include loop (loopa.test -> loopb.test -> loopa.test)" 2
check wide.test   FAIL "Include loop (wide.test -> wide.test)" 1
# A large tree with no loop stops just past the limit (20 lookups in full)
check big.test    FAIL "More than 10 DNS lookups" 12

if [ "$failures" -gt 0 ]; then
  echo "$failures SPF test(s) failed"; exit 1
fi
echo "All SPF tests passed"
