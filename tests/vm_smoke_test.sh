#!/usr/bin/env bash
# vm_smoke_test.sh - run INSIDE a disposable Linux Mint VM to record real-world results.
#
#   bash tests/vm_smoke_test.sh              # safe: detect + audit (twice); nothing is changed
#   sudo bash tests/vm_smoke_test.sh         # same as root (fewer 'Unperformed' checks)
#
# Take a VM snapshot first. The output (smoke-test-report.txt) is what you paste into
# docs/testing.md so the "tested environments" table reflects real runs, not guesses.

set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TK="$HERE/mint-toolkit.sh"
OUT="${PWD}/smoke-test-report.txt"
pass=0; fail=0
chk() { if eval "$2"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }

{
echo "== environment =="
date; uname -a
grep -E '^(PRETTY_NAME|VERSION_ID|VERSION_CODENAME|UBUNTU_CODENAME)=' /etc/os-release
cat /etc/linuxmint/info 2>/dev/null | grep -E '^(RELEASE|EDITION)='
echo "XDG_CURRENT_DESKTOP=${XDG_CURRENT_DESKTOP:-<unset>}  bash $BASH_VERSION  user=$(id -un) uid=$(id -u)"
echo
echo "== detect =="
bash "$TK" detect --no-color; rc=$?
chk "detect exits 0 on Mint 21.x/22.x (rc=$rc)" "[[ $rc -eq 0 ]]"
tmp=$(mktemp -d)
echo; echo "== fingerprint before audit (files the audit must not change) =="
fp() { { sha256sum /etc/passwd /etc/group /etc/login.defs /etc/ssh/sshd_config /etc/pam.d/common-* 2>/dev/null; ls -l /etc/shadow /etc/sudoers 2>/dev/null; ufw status 2>/dev/null; sysctl -n net.ipv4.tcp_syncookies kernel.randomize_va_space 2>/dev/null; } | sha256sum; }
before=$(fp); echo "$before"
echo; echo "== audit (run 1) =="
bash "$TK" audit --no-color --output-dir "$tmp/a1"; rc1=$?
chk "audit run 1 exits 0 (rc=$rc1)" "[[ $rc1 -eq 0 ]]"
echo; echo "== audit (run 2, repeatability) =="
bash "$TK" audit --no-color --output-dir "$tmp/a2" >/dev/null; rc2=$?
chk "audit run 2 exits 0 (rc=$rc2)" "[[ $rc2 -eq 0 ]]"
ids() { awk -F$'\x1f' '{print $4}' "$1"/audit-*/findings.dat | sort; }
chk "both audits report identical finding ids" "[[ \"\$(ids $tmp/a1)\" == \"\$(ids $tmp/a2)\" ]]"
chk "audit did not modify watched system files" "[[ \"\$(fp)\" == \"$before\" ]]"
chk "report contains no password hash" "! grep -rEq '\\\$(1|5|6|y)\\\$[A-Za-z0-9./]{8,}' $tmp/a1"
chk "report file exists" "ls $tmp/a1/audit-*/report.md >/dev/null"
echo; echo "== finding counts (run 1) =="
for c in CONFIRMED POTENTIAL INFO UNPERFORMED; do printf '%-12s %s\n' "$c" "$(awk -F$'\x1f' -v c=$c '$1==c{n++} END{print n+0}' $tmp/a1/audit-*/findings.dat)"; done
echo; echo "== UNPERFORMED checks (non-root runs list privilege gaps here) =="
awk -F$'\x1f' '$1=="UNPERFORMED"{print "  " $4 ": " $5}' $tmp/a1/audit-*/findings.dat
echo; echo "== RESULT: $pass passed, $fail failed =="
echo "Reports kept in: $tmp   (contain account names; do not publish them)"
} 2>&1 | tee "$OUT"
echo "Saved to $OUT"
