#!/usr/bin/env bash
# reporting.sh - findings store, secret redaction, terminal summary, detailed report.
#
# A finding has: class, severity, category, id, title, evidence, why, action,
# side effects, automation (always "-": the toolkit never changes the system), manual-review flag.
#
# Classes (kept deliberately distinct):
#   CONFIRMED    objectively insecure configuration, independent of the README
#   POTENTIAL    depends on what the competition README / system role requires
#   INFO         context only
#   UNPERFORMED  a check that could not be done (missing privilege/tool)

RP_CLASSES="CONFIRMED POTENTIAL INFO UNPERFORMED"
RP_SEVERITIES="high medium low info"

rp_init() { # file
  TK_FINDINGS=$1
  : >"$TK_FINDINGS"
}

# Encode so one finding == one line.  Backslash first, then newline.
rp_enc() {
  local s=$1
  s=${s//\\/"\\\\"}
  s=${s//$'\n'/"\\n"}
  s=${s//"$TK_US"/" "}
  printf '%s' "$s"
}
rp_dec() { printf '%b' "$1"; }

# Remove anything that looks like a secret.  Applied to ALL evidence.
rp_redact() {
  sed -E \
    -e 's/\$(1|2a|2b|2y|5|6|7|y|gy|md5|sha1)\$[A-Za-z0-9.\/$,=_-]{4,}/[REDACTED-HASH]/g' \
    -e 's/-----BEGIN [A-Z ]*PRIVATE KEY-----.*/[REDACTED-PRIVATE-KEY]/' \
    -e 's/(ssh-(rsa|ed25519|dss)|ecdsa-sha2-[a-z0-9]+) [A-Za-z0-9+\/=]{20,}/\1 [REDACTED-KEY]/g' \
    -e 's/((pass(word|wd)?|secret|token|api[_-]?key)[[:space:]]*[=:][[:space:]]*)[^[:space:]]+/\1[REDACTED]/Ig'
}

# rp_add CLASS SEVERITY CATEGORY ID TITLE EVIDENCE WHY ACTION SIDE AUTOMATION MANUAL
rp_add() {
  local class=$1 sev=$2 cat=$3 id=$4 title=$5 ev=$6 why=${7:-} act=${8:-} side=${9:-} auto=${10:--} manual=${11:-no}
  case " $RP_CLASSES " in *" $class "*) ;; *) tk_err "rp_add: bad class '$class' for $id"; return 1;; esac
  case " $RP_SEVERITIES " in *" $sev "*) ;; *) tk_err "rp_add: bad severity '$sev' for $id"; return 1;; esac
  [[ -n "${TK_FINDINGS:-}" ]] || { tk_err "rp_add: findings store not initialised"; return 1; }
  # unique id: append -2, -3 ... if taken
  local base=$id n=1
  while awk -F"$TK_US" -v id="$id" '$4==id{f=1} END{exit !f}' "$TK_FINDINGS"; do
    n=$((n+1)); id="$base-$n"
  done
  ev=$(printf '%s' "$ev" | rp_redact)
  printf '%s\n' "$class$TK_US$sev$TK_US$cat$TK_US$id$TK_US$(rp_enc "$title")$TK_US$(rp_enc "$ev")$TK_US$(rp_enc "$why")$TK_US$(rp_enc "$act")$TK_US$(rp_enc "$side")$TK_US$auto$TK_US$manual" >>"$TK_FINDINGS"
}

f_confirmed()  { rp_add CONFIRMED "$@"; }          # sev cat id title evidence why action side auto manual
f_potential()  { rp_add POTENTIAL "$@"; }          # sev cat id title evidence why action side auto manual
f_info()       { rp_add INFO info "$1" "$2" "$3" "$4" "" "" "" "-" "no"; }   # cat id title evidence
f_unperformed(){ rp_add UNPERFORMED info "$1" "$2" "$3" "$4" "This check could not be completed, so no conclusion is drawn about it." "Re-run with the missing privilege/tool, or check this area manually." "" "-" "yes"; }  # cat id title reason

rp_count() { # class [severity]
  [[ -s "${TK_FINDINGS:-/dev/null}" ]] || { echo 0; return; }
  awk -F"$TK_US" -v c="$1" -v s="${2:-}" '$1==c && (s=="" || $2==s){n++} END{print n+0}' "$TK_FINDINGS"
}

# Findings sorted: CONFIRMED, POTENTIAL, UNPERFORMED, INFO; high->low inside a class.
rp_sorted() {
  # findings named in the user's Scoring Report notes come first, then class, then severity
  awk -F"$TK_US" -v scored="${SC_SCORED_IDS:-,}" 'BEGIN{c["CONFIRMED"]=0;c["POTENTIAL"]=1;c["UNPERFORMED"]=2;c["INFO"]=3;
                        s["high"]=0;s["medium"]=1;s["low"]=2;s["info"]=3}
                  {k=(index(scored, "," $4 ",")>0)?0:1; printf "%d%d%d%s\n", k, c[$1], s[$2], $0}' "$TK_FINDINGS" | sort -s -n | cut -c4-
}

rp_sev_label() {
  case "$1" in
    high) printf '%sHIGH%s' "$C_RED" "$C_OFF";;
    medium) printf '%sMEDIUM%s' "$C_YEL" "$C_OFF";;
    low) printf '%sLOW%s' "$C_BLU" "$C_OFF";;
    *) printf 'INFO';;
  esac
}

rp_automation_text() {
  printf 'No - this toolkit never changes the system. Make the change yourself if you decide it is needed (commands: docs/manual-fixes.md)'
}

# Terminal summary: counts + one line per actionable finding.
rp_terminal_summary() { # report_path
  local total; total=$(wc -l <"$TK_FINDINGS" | tr -d ' ')
  printf '\n%s== Audit summary ==%s\n' "$C_BLD" "$C_OFF"
  printf '  Confirmed security issues : %s%s%s  (high %s / medium %s / low %s)\n' "$C_RED" "$(rp_count CONFIRMED)" "$C_OFF" \
    "$(rp_count CONFIRMED high)" "$(rp_count CONFIRMED medium)" "$(rp_count CONFIRMED low)"
  printf '  Potential issues to review: %s%s%s  (depend on the README / system role)\n' "$C_YEL" "$(rp_count POTENTIAL)" "$C_OFF"
  printf '  Informational findings    : %s\n' "$(rp_count INFO)"
  printf '  Unperformed checks        : %s  (missing privileges/tools - NOT "passed")\n' "$(rp_count UNPERFORMED)"
  printf '  Total records             : %s\n' "$total"
  local class sev cat id title rest shown=0
  printf '\n%sConfirmed / potential findings%s\n' "$C_BLD" "$C_OFF"
  while IFS="$TK_US" read -r class sev cat id title rest; do
    [[ "$class" == CONFIRMED || "$class" == POTENTIAL ]] || continue
    shown=$((shown+1))
    printf '  [%-8s] %-9s %-34s %s\n' "$(rp_sev_label "$sev")" "$class" "$id" "$(rp_dec "$title")"
  done < <(rp_sorted)
  [[ $shown -eq 0 ]] && printf '  (none)\n'
  if [[ $(rp_count UNPERFORMED) -gt 0 ]]; then
    printf '\n%sChecks that could not be performed%s\n' "$C_BLD" "$C_OFF"
    while IFS="$TK_US" read -r class sev cat id title rest; do
      [[ "$class" == UNPERFORMED ]] && printf '  - %-34s %s\n' "$id" "$(rp_dec "$title")"
    done < <(rp_sorted)
  fi
  declare -F sc_terminal_lines >/dev/null && { printf '\n'; sc_terminal_lines; }
  printf '\n%sNote:%s "Potential" items are NOT errors by themselves. Compare them with the competition README\n' "$C_BLD" "$C_OFF"
  printf '      before changing anything. This tool cannot know what the scoring engine rewards.\n'
}

# Detailed Markdown report.
rp_write_report() { # outfile
  local out=$1 class sev cat id title ev why act side auto manual cur=""
  {
    printf '# CyberPatriot Mint Toolkit - audit report\n\n'
    printf '| Item | Value |\n|---|---|\n'
    printf '| Toolkit version | %s |\n' "$TK_VERSION"
    printf '| Generated | %s |\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
    printf '| Host | %s |\n' "${DET_HOSTNAME:-unknown}"
    printf '| OS | %s |\n' "${DET_PRETTY:-unknown}"
    printf '| Mint edition / desktop | %s / %s |\n' "${DET_MINT_EDITION:-n/a}" "${DET_DESKTOP:-unknown}"
    printf '| Base | %s %s (%s) |\n' "${DET_BASE_NAME:-?}" "${DET_BASE_VERSION:-?}" "${DET_BASE_CODENAME:-?}"
    printf '| Kernel / arch | %s / %s |\n' "${DET_KERNEL:-?}" "${DET_ARCH:-?}"
    printf '| Support status | %s - %s |\n' "${DET_SUPPORT:-?}" "${DET_SUPPORT_REASON:-}"
    printf '| Privileges | %s |\n' "$(tk_is_root && echo 'root (full checks)' || echo 'NON-ROOT (some checks limited - see Unperformed)')"
    if declare -F sc_expect_text >/dev/null; then local exp; exp=$(sc_expect_text); [[ -n "$exp" ]] && printf '| Expected image | %s |\n' "$exp"; fi
    printf '\n> **How to read this report.** *Confirmed* = insecure regardless of context. *Potential* = depends on what the\n'
    printf '> competition README requires; it is **not** a claim that anything is wrong or worth points. *Unperformed* = the check\n'
    printf '> could not run, which is **not** the same as passing. Secrets (password hashes, keys, tokens) are redacted.\n\n'
    printf '## Summary\n\n| Class | Count |\n|---|---|\n'
    for class in $RP_CLASSES; do printf '| %s | %s |\n' "$class" "$(rp_count "$class")"; done
    printf '\n'
    declare -F sc_report_sections >/dev/null && sc_report_sections
    printf '# Detailed findings\n\n'
    while IFS="$TK_US" read -r class sev cat id title ev why act side auto manual; do
      if [[ "$class" != "$cur" ]]; then
        cur=$class
        case "$class" in
          CONFIRMED) printf '## Confirmed security issues\n\n';;
          POTENTIAL) printf '## Potential issues requiring review\n\n';;
          UNPERFORMED) printf '## Unsupported or unperformed checks\n\n';;
          INFO) printf '## Informational findings\n\n';;
        esac
      fi
      printf '### %s - %s\n\n' "$id" "$(rp_dec "$title")"
      printf -- '- **Severity:** %s  \n- **Category:** %s  \n- **Class:** %s\n' "$sev" "$cat" "$class"
      printf '\n**Evidence**\n\n```\n%s\n```\n\n' "$(rp_dec "$ev")"
      if [[ "$class" != INFO ]]; then
        printf '**Why it matters:** %s\n\n' "$(rp_dec "$why")"
        printf '**Recommended action:** %s\n\n' "$(rp_dec "$act")"
        [[ -n "$side" ]] && printf '**Possible side effects:** %s\n\n' "$(rp_dec "$side")"
        printf '**Automation appropriate?** %s\n\n' "$(rp_automation_text "$auto")"
        printf '**Manual investigation needed?** %s\n\n' "$manual"
      fi
    done < <(rp_sorted)
  } >"$out"
}
