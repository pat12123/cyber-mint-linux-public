#!/usr/bin/env bash
# Tests for lib/reporting.sh: the findings store, redaction, classification and rendering.
T_NAME="reporting"
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"
export TK_NO_COLOR=1 NO_COLOR=1
source "$PROJECT/lib/common.sh"
source "$PROJECT/lib/reporting.sh"

DET_PRETTY="Linux Mint 21.3"; DET_HOSTNAME="unit"; DET_SUPPORT=targeted; DET_SUPPORT_REASON="fixture"
rp_init "$TEST_TMP/f.dat"

t_section "Adding findings"
f_confirmed high "Cat A" "T-ONE" "First issue" "evidence one" "because" "do this" "side effect" - no
f_potential medium "Cat B" "T-TWO" "Second issue" "evidence two" "maybe" "check" "" - yes
f_info "Cat C" "T-THREE" "Third" "just info"
f_unperformed "Cat D" "T-FOUR" "Could not check" "needs root"
assert_eq "four records stored" 4 "$(wc -l <"$TK_FINDINGS" | tr -d ' ')"
assert_eq "CONFIRMED count" 1 "$(rp_count CONFIRMED)"
assert_eq "POTENTIAL count" 1 "$(rp_count POTENTIAL)"
assert_eq "INFO count" 1 "$(rp_count INFO)"
assert_eq "UNPERFORMED count" 1 "$(rp_count UNPERFORMED)"
assert_eq "high-severity confirmed count" 1 "$(rp_count CONFIRMED high)"

t_section "Unique identifiers"
f_info "Cat C" "T-THREE" "Third again" "dup"
f_info "Cat C" "T-THREE" "Third and again" "dup"
ids=$(awk -F"$TK_US" '{print $4}' "$TK_FINDINGS" | sort | uniq -d)
assert_eq "no identifier is used twice" "" "$ids"
assert_contains "duplicate ids get a numeric suffix" "$(awk -F"$TK_US" '{print $4}' "$TK_FINDINGS")" "T-THREE-3"

t_section "Input validation"
rp_add BOGUS high c i t e w a s - no 2>/dev/null; rc=$?
assert_ne "invalid class is rejected" 0 "$rc"
rp_add CONFIRMED critical c i2 t e w a s - no 2>/dev/null; rc=$?
assert_ne "invalid severity is rejected" 0 "$rc"
assert_eq "rejected records are not stored" 0 "$(grep -c 'i2' "$TK_FINDINGS")"

t_section "Secret redaction"
f_info "Secrets" "T-SECRET" "secrets" 'shadow line root:$6$saltsalt$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG:19000:0:99999
md5 $1$abc$xyzXYZ0123456789
yescrypt $y$j9T$abcdefghij$ABCDEFGHIJKLMNOPQRSTUV
-----BEGIN OPENSSH PRIVATE KEY-----
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIABCDEFGHIJKLMNOPQRSTUVWXYZ012345 user@host
password=hunter2secret
API_KEY: sk_live_abcdef123456
token = abcdefg123'
rec=$(grep 'T-SECRET' "$TK_FINDINGS")
for s in 'abcdefghijklmnopqrstuvwxyz0123456789' 'xyzXYZ0123456789' 'ABCDEFGHIJKLMNOPQRSTUV' 'AAAAC3NzaC1lZDI1NTE5' 'hunter2secret' 'sk_live_abcdef123456' 'abcdefg123'; do
  assert_not_contains "secret '${s:0:14}...' is redacted" "$rec" "$s"
done
assert_contains "redaction leaves a visible marker" "$rec" "REDACTED"
assert_contains "non-secret text survives redaction" "$rec" "shadow line root"

t_section "Encoding round-trip (backslashes, newlines, quotes)"
raw=$'line1\nline2 with \\n literal and C:\\path \\\\ and "quotes" and \'single\''
f_info "Enc" "T-ENC" "enc" "$raw"
enc=$(awk -F"$TK_US" '$4=="T-ENC"{print $6}' "$TK_FINDINGS")
assert_eq "evidence survives encode/decode unchanged" "$raw" "$(rp_dec "$enc")"
assert_eq "an encoded finding is still exactly one line" 1 "$(grep -c 'T-ENC' "$TK_FINDINGS")"

t_section "Ordering"
sorted_ids=$(rp_sorted | awk -F"$TK_US" '{print $4}' | head -4 | tr '\n' ' ')
assert_eq "CONFIRMED first, then POTENTIAL, then UNPERFORMED, then INFO" "T-ONE T-TWO T-FOUR T-THREE " "$sorted_ids"
f_confirmed low "Cat A" "T-LOWC" "low confirmed" "e" "w" "a" "" - no
f_confirmed high "Cat A" "T-HIGHC" "high confirmed" "e" "w" "a" "" - no
sorted_ids=$(rp_sorted | awk -F"$TK_US" '$1=="CONFIRMED"{print $4}' | tr '\n' ' ')
assert_eq "inside a class higher severity comes first" "T-ONE T-HIGHC T-LOWC " "$sorted_ids"

t_section "Terminal summary"
out=$(rp_terminal_summary)
assert_contains "summary shows confirmed count" "$out" "Confirmed security issues : 3"
assert_contains "summary shows potential count" "$out" "Potential issues to review: 1"
assert_contains "summary lists a confirmed finding" "$out" "T-ONE"
assert_contains "summary lists a potential finding" "$out" "T-TWO"
assert_not_contains "informational findings are not listed as issues" "$out" "[INFO"
assert_contains "summary reminds that potential items are not errors" "$out" "NOT errors"
assert_contains "unperformed checks are called out as not passed" "$out" 'NOT "passed"'
assert_contains "unperformed checks are listed" "$out" "T-FOUR"
assert_not_contains "summary never promises competition points" "$out" "points"

t_section "Detailed report"
rp_write_report "$TEST_TMP/report.md"
rep=$(<"$TEST_TMP/report.md")
for h in "Confirmed security issues" "Potential issues requiring review" "Informational findings" "Unsupported or unperformed checks"; do
  assert_contains "report has section '$h'" "$rep" "$h"
done
assert_contains "finding has an identifier heading" "$rep" "### T-ONE - First issue"
assert_contains "finding shows evidence" "$rep" "evidence one"
assert_contains "finding shows why it matters" "$rep" "**Why it matters:** because"
assert_contains "finding shows recommended action" "$rep" "**Recommended action:** do this"
assert_contains "finding shows side effects" "$rep" "**Possible side effects:** side effect"
assert_contains "every finding says the toolkit makes no change itself" "$rep" "this toolkit never changes the system"
assert_contains "…and points at the manual commands" "$rep" "docs/manual-fixes.md"
assert_contains "finding states whether manual investigation is needed" "$rep" "**Manual investigation needed?** yes"
assert_contains "report explains the classes" "$rep" "*Unperformed* = the check"
assert_contains "report states the redaction policy" "$rep" "redacted"
assert_not_contains "report never contains redacted secrets" "$rep" "hunter2secret"
assert_not_contains "report never claims to know scoring" "$rep" "you will lose points"
assert_contains "report header names the OS" "$rep" "Linux Mint 21.3"
assert_contains "report records the privilege level" "$rep" "Privileges"

t_section "Uninitialised store"
unset TK_FINDINGS
rp_add INFO info c x t e >/dev/null 2>&1; rc=$?
assert_ne "adding without rp_init fails loudly instead of writing somewhere" 0 "$rc"

t_summary
