#!/usr/bin/env bash
# Tests for the competition-workflow features: Scoring Report notes, report sections, change-risk classes,
# the checklist, the expected-image row and the connectivity module.
T_NAME="scoring"
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

BASE="$FIX/mint21-cinnamon"; VULN="$FIX/vuln-overlay"

# =====================================================================
t_section "Report sections without any Scoring Report notes"
mk_env nonotes "$BASE"; T_EUID=0
run_tk audit
R=$(latest_report)
assert_eq "audit exits 0" 0 "$T_RC"
assert_file_has "remaining-scored-issues section exists" "$R" "## Remaining scored issues"
assert_file_has "…and admits it cannot know what is scored" "$R" "cannot say which findings are scored"
assert_file_has "recommended-order section exists" "$R" "## Recommended order of work"
assert_file_has "unscored-weaknesses section exists" "$R" "## Possible unscored weaknesses"
assert_file_has "unresolved-questions section exists" "$R" "## Unresolved questions"
assert_file_has "potential-penalties section exists" "$R" "## Potential penalties"
assert_file_has "checklist section exists" "$R" "## Competition checklist"
assert_file_has "checklist reminds about the Scoring Report" "$R" "Open the Scoring Report"
assert_file_has "checklist reminds about forensics questions" "$R" "Find the forensics questions"
assert_file_has "checklist says the toolkit never answers them" "$R" "The toolkit never answers them"
assert_file_has "…and that old answers do not carry over" "$R" "do not apply to this one"
assert_file_has "the report says no point values are shown" "$R" "No point values are shown"
assert_file_lacks "the report never claims a number of points" "$R" " points)"
assert_contains "terminal summary says no notes were supplied" "$T_OUT" "none supplied"
assert_contains "terminal prints the short checklist" "$T_OUT" "Forensics questions found and answered by you BEFORE changing anything"
assert_file_has "expected-image row says Mint 21 matches" "$R" "Linux Mint 21.x expected (project notes: CyberPatriot 19 Round 1) - matches"
assert_not_contains "no expectation warning when the image matches" "$T_ERR" "DIFFERS"

T_EXTRA_ENV="TK_EXPECT_MINT=22"; run_tk audit
assert_file_has "a different expected version is flagged in the report" "$(latest_report)" "DIFFERS"
assert_contains "…and warned about on stderr" "$T_ERR" "DIFFERS"
T_EXTRA_ENV="TK_EXPECT_MINT="; run_tk audit
assert_file_lacks "an empty expectation removes the row" "$(latest_report)" "Expected image"

# =====================================================================
t_section "Scoring Report notes: ordering, labels, validation"
mk_env notes "$BASE" "$VULN"; T_EUID=0
cat >"$E/notes.txt" <<'EOF'
# copied by hand from the Scoring Report
Anonymous FTP login disabled => APP-VSFTPD-ANON
Firewall protection has been enabled => FW-UFW-INACTIVE
Some item the toolkit has no check for
Removed prohibited file => NOPE-NOT-A-FINDING
EOF
before=$(snapshot_tree)
run_tk audit --scoring-notes "$E/notes.txt"
R=$(latest_report)
assert_eq "audit with notes exits 0" 0 "$T_RC"
assert_file_has "note text appears in the scored table" "$R" "Anonymous FTP login disabled"
assert_file_has "matched finding is listed next to the note" "$R" "APP-VSFTPD-ANON"
assert_file_has "a note mapped to a finding id matches it" "$R" "FW-UFW-INACTIVE"
assert_file_has "unmapped note says to investigate manually" "$R" "no mapping given - investigate manually"
assert_file_has "unmatched mapping says to refresh the Scoring Report" "$R" "refresh the Scoring Report"
assert_file_has "unmatched note appears under unresolved questions" "$R" 'Scoring Report item with no matching finding: "Removed prohibited file"'
assert_file_has "the scored finding is row 1 of the recommended order" "$R" '| 1 | `APP-VSFTPD-ANON`'
assert_file_has "…and is marked as in the notes" "$R" "**yes**"
first=$(awk '/^## Confirmed security issues/{f=1} f&&/^### /{print; exit}' "$R")
assert_contains "scored finding is the first detailed Confirmed finding" "$first" "APP-VSFTPD-ANON"
assert_contains "terminal summary counts matched findings" "$T_OUT" "2 toolkit finding(s) matched"
assert_contains "…and unmatched notes" "$T_OUT" "2 item(s) without a matching finding"
assert_eq "using notes changed nothing on the system" "$before" "$(snapshot_tree)"
assert_eq "…and issued no state-changing command" "" "$(mock_mutations)"

# change-risk column
assert_eq "firewall finding is High risk" 1 "$(grep -c 'FW-UFW-INACTIVE.*| High |' "$R")"
assert_eq "file-permission finding is Moderate risk" 1 "$(grep -c 'PERM-etc-shadow.*| Moderate |' "$R")"
assert_file_has "the legend defines the risk classes" "$R" "**Moderate** = narrow change"

# without notes the order is the plain class/severity order (a CONFIRMED high item first)
run_tk audit
first_row=$(grep -E '^\| 1 \|' "$(latest_report)")
assert_not_contains "no notes: nothing is marked as scored" "$first_row" "**yes**"
assert_contains "no notes: scoring relevance is 'unknown'" "$first_row" "unknown"

# invalid input is rejected or neutralised, never executed
run_tk audit --scoring-notes "$E/missing.txt"
assert_eq "missing notes file is rejected" 1 "$T_RC"
printf 'Weird => A;touch %s/PWNED,GOOD-ID\nControl\001chars here => $(touch %s/PWNED2)\n' "$E" "$E" >"$E/evil.txt"
run_tk audit --scoring-notes "$E/evil.txt" --modules users
assert_eq "hostile notes do not fail the audit" 0 "$T_RC"
assert_contains "invalid id prefixes are reported and ignored" "$T_ERR" "ignoring invalid id prefix"
assert_no_file "…and nothing was executed" "$E/PWNED"
assert_no_file "…not even command substitutions" "$E/PWNED2"
for i in $(seq 1 205); do printf 'item %s\n' "$i"; done >"$E/many.txt"
run_tk audit --scoring-notes "$E/many.txt" --modules users
assert_contains "very long notes files are capped" "$T_ERR" "only the first 200 items"
T_EXTRA_ENV="TK_SCORING_NOTES=$E/notes.txt"; run_tk audit --modules firewall
assert_file_has "notes may also come from the environment" "$(latest_report)" "Anonymous FTP login disabled"

# =====================================================================
t_section "Connectivity module"
mk_env conn_ok "$BASE"; T_EUID=0
run_tk audit --modules connectivity
assert_eq "default route is reported" INFO "$(finding_class CONN-ROUTE)"
assert_eq "resolvers are reported" INFO "$(finding_class CONN-DNS)"
assert_eq "internet reachable is INFO" INFO "$(finding_class CONN-INTERNET)"
assert_eq "the scoring-software statement is present" INFO "$(finding_class CONN-SCORING-NOTE)"
assert_file_has "…and says the toolkit does not touch the scoring software" "$(latest_report)" "does not locate, read, modify, stop or contact the competition scoring software"
assert_eq "a healthy connection raises no Potential finding" 0 "$(class_count POTENTIAL)"
assert_file_has "one DNS lookup and one ping were issued" "$E/mock.log" "ping -c 1 -W 3 1.1.1.1"

mk_env conn_down "$BASE"; T_EUID=0
printf '1\n' >"$E/cmds/ping.rc"; : >"$E/cmds/ping.out"; rm -f "$E/cmds/getent.hosts.out"; printf '2\n' >"$E/cmds/getent.hosts.rc"
run_tk audit --modules connectivity
assert_eq "no connectivity at all is Potential medium" POTENTIAL "$(finding_class CONN-INTERNET-DOWN)"
assert_eq "…severity medium" medium "$(finding_sev CONN-INTERNET-DOWN)"
assert_file_has "…and is framed as depending on the scenario" "$(latest_report)" "deliberately offline practice VM is fine"

mk_env conn_partial "$BASE"; T_EUID=0
printf '1\n' >"$E/cmds/ping.rc"; : >"$E/cmds/ping.out"
run_tk audit --modules connectivity
assert_eq "DNS ok but ping failing is only Potential low" low "$(finding_sev CONN-INTERNET-PARTIAL)"

mk_env conn_noroute "$BASE"; T_EUID=0
: >"$E/cmds/ip.route.show.default.out"
run_tk audit --modules connectivity
assert_eq "an empty routing table is reported" POTENTIAL "$(finding_class CONN-NOROUTE)"
assert_file_has "…without the toolkit changing network settings" "$(latest_report)" "never changes network settings"

mk_env conn_noprobe "$BASE"; T_EUID=0
run_tk audit --modules connectivity --no-network-probe
assert_eq "--no-network-probe issues no ping" 0 "$(grep -c '^ping ' "$E/mock.log")"
assert_eq "…and no DNS lookup" 0 "$(grep -c '^getent ' "$E/mock.log")"
assert_eq "…the result is 'not tested', not 'ok'" INFO "$(finding_class CONN-INTERNET)"
assert_file_has "…and says so" "$(latest_report)" "Internet reachability not tested"

mk_env conn_host "$BASE"; T_EUID=0
run_tk audit --modules connectivity --scoring-host scoring.example.org
assert_eq "named host answering over HTTPS is INFO" INFO "$(finding_class CONN-SCOREHOST)"
assert_file_has "exactly one HTTPS HEAD request is issued" "$E/mock.log" "curl --head --silent --show-error --output /dev/null --max-time 5 https://scoring.example.org/"
assert_eq "…and it is the only curl call" 1 "$(grep -c '^curl ' "$E/mock.log")"
printf '6\n' >"$E/cmds/curl.rc"; printf 'curl: (6) Could not resolve host\n' >"$E/cmds/curl.err"
run_tk audit --modules connectivity --scoring-host scoring.example.org:8443
assert_eq "named host not reachable is Potential" POTENTIAL "$(finding_class CONN-SCOREHOST-DOWN)"
assert_file_has "…and says it is reachability, not scoring status" "$(latest_report)" "This is reachability only, not the scoring status"
run_tk audit --modules connectivity --scoring-host 'bad host;rm -rf /'
assert_eq "invalid scoring host is rejected" 1 "$T_RC"
run_tk audit --modules connectivity --scoring-host '-oProxyCommand=x'
assert_eq "option-like scoring host is rejected" 1 "$T_RC"
run_tk audit --modules connectivity --scoring-host scoring.example.org --no-network-probe
assert_eq "scoring host + no probes: reported as not performed" UNPERFORMED "$(finding_class CONN-SCOREHOST)"

mk_env conn_fw "$BASE"; T_EUID=0
echo active >"$E/cmds/ufw.state"
printf 'deny (incoming), deny (outgoing), disabled (routed)\n' >"$E/cmds/ufw.default"
run_tk audit --modules connectivity
assert_eq "ufw denying outgoing traffic is reported" POTENTIAL "$(finding_class CONN-UFW-OUTBOUND)"
mk_env conn_fw_ok "$BASE"; T_EUID=0
echo active >"$E/cmds/ufw.state"
run_tk audit --modules connectivity
assert_eq "ufw allowing outgoing traffic is not reported" "" "$(finding_class CONN-UFW-OUTBOUND)"

mk_env conn_proxy "$BASE"; T_EUID=0
mkdir -p "$E/root/etc/apt/apt.conf.d"
printf 'Acquire::http::Proxy "http://alice:s3cret@proxy.local:3128";\n' >"$E/root/etc/apt/apt.conf.d/95proxy"
run_tk audit --modules connectivity
assert_eq "a configured proxy is reported" INFO "$(finding_class CONN-PROXY)"
assert_file_has "…with the credentials redacted" "$(latest_report)" "http://[REDACTED]@proxy.local:3128"
assert_file_lacks "…the password never reaches the report" "$(latest_report)" "s3cret"

# =====================================================================
t_section "Audit guard: probes are limited to one ping / one HEAD request"
mk_env guard "$BASE"
in_env 'TK_MODE=audit
chk() { tk_cmd_allowed "$@" && echo "allowed: $*" || echo "blocked: $*"; }
chk ping -c 1 -W 3 1.1.1.1
chk ping -c 1 -W 9 1.1.1.1
chk ping -c 100 -W 3 1.1.1.1
chk ping -f 1.1.1.1
chk ping -c 1 -W 3 "bad;host"
chk curl --head --silent --show-error --output /dev/null --max-time 5 https://scoring.example.org/
chk curl --head --silent --show-error --output /dev/null --max-time 5 http://scoring.example.org/
chk curl -X POST https://scoring.example.org/
chk curl --output /etc/passwd https://scoring.example.org/' >"$E/g.txt"
assert_eq "one echo request is allowed" 1 "$(grep -c '^allowed: ping -c 1 -W 3 1.1.1.1' "$E/g.txt")"
assert_eq "other ping forms are blocked" 4 "$(grep -c '^blocked: ping' "$E/g.txt")"
assert_eq "the exact HEAD request is allowed" 1 "$(grep -c '^allowed: curl --head' "$E/g.txt")"
assert_eq "other curl forms (http, POST, file output) are blocked" 3 "$(grep -c '^blocked: curl' "$E/g.txt")"

t_summary
