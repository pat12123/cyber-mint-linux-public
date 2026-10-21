#!/usr/bin/env bash
# Runs the whole automated suite and records exactly what environment it ran in.
# Usage: tests/run_all.sh [detection audit reporting scoring]
# Needs no root and changes nothing outside a private temp directory: every
# test runs the toolkit against fixture roots with mocked system commands.
# (It does NOT replace testing on a real Linux Mint VM - see docs/testing.md.)

T_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
suites=("$@"); [[ ${#suites[@]} -eq 0 ]] && suites=(reporting detection audit scoring)
results="$T_DIR/last-results.txt"

{
  echo "Test run: $(date '+%Y-%m-%d %H:%M:%S %z')"
  echo "Host: $(uname -srm) | bash $BASH_VERSION"
  [[ -r /etc/os-release ]] && echo "OS: $(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '"')"
  echo "Mode: fixtures + mocked commands (not a live Linux Mint system unless stated)"
} | tee "$results"

fail=0
for s in "${suites[@]}"; do
  f="$T_DIR/test_$s.sh"
  if [[ ! -r "$f" ]]; then echo "missing suite: $f" | tee -a "$results"; fail=1; continue; fi
  echo "=== suite: $s ===" | tee -a "$results"
  out=$(bash "$f" 2>&1); rc=$?
  printf '%s\n' "$out" | grep -E '^(  FAIL|  SKIP|-- )' | tee -a "$results"
  [[ $rc -ne 0 ]] && fail=1
done
if [[ $fail -eq 0 ]]; then echo "ALL SUITES PASSED" | tee -a "$results"; else echo "SOME TESTS FAILED" | tee -a "$results"; fi
exit $fail
