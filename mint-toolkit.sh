#!/usr/bin/env bash
# CyberPatriot Linux Mint Security Toolkit
#
#   ./mint-toolkit.sh detect               identify OS/desktop/support level (read-only)
#   ./mint-toolkit.sh audit                read-only security audit + reports
#   ./mint-toolkit.sh forensics-help       list generic read-only commands (runs nothing)
#   ./mint-toolkit.sh self-test            run the bundled automated tests
#
# The toolkit never modifies the system (it only writes its own report folder). Fixes are made by you, by hand: docs/manual-fixes.md.
# See docs/usage.md and docs/security.md.

set -u
set -o pipefail

TK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
for _m in common reporting scoring detection users authentication ssh network firewall services applications permissions updates scheduled_tasks desktop_security connectivity forensics; do
  if [[ ! -r "$TK_DIR/lib/$_m.sh" ]]; then
    printf 'ERROR: missing library %s/lib/%s.sh (incomplete download?)\n' "$TK_DIR" "$_m" >&2
    exit 2
  fi
  # shellcheck disable=SC1090
  source "$TK_DIR/lib/$_m.sh"
done
unset _m

if [[ "${BASH_VERSINFO[0]}" -lt 4 || ( "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -lt 4 ) ]]; then
  tk_err "bash 4.4 or newer is required (found $BASH_VERSION)"; exit 2
fi

TK_AUDIT_MODULES=(users authentication ssh network firewall services applications permissions updates scheduled_tasks desktop_security connectivity)
declare -A TK_MODULE_FN=(
  [users]=audit_users [authentication]=audit_authentication [ssh]=audit_ssh [network]=audit_network
  [firewall]=audit_firewall [services]=audit_services [applications]=audit_applications [permissions]=audit_permissions [updates]=audit_updates
  [scheduled_tasks]=audit_scheduled_tasks [desktop_security]=audit_desktop_security [connectivity]=audit_connectivity
)

usage() {
  cat <<EOF
CyberPatriot Mint Toolkit $TK_VERSION

Usage: $0 <command> [options]

Commands:
  detect                 Show detected OS, edition, desktop, tools and support status
  audit                  Read-only security audit; writes a report folder
  forensics-help         Print generic read-only commands (runs nothing; do this BEFORE changing anything)
  self-test              Run the bundled tests (no root, no system changes)
  version | help

Options:
  --output-dir DIR       Where audit reports go (default: ./toolkit-output)
  --modules a,b,c        Audit only these modules. Available:
                         ${TK_AUDIT_MODULES[*]}
  --no-color             Disable colours
  --force-unsupported    Let 'audit' run on an unsupported OS
  --profile FILE         README-derived lists (authorized_users, authorized_admins, required_services, allow_ports)
  --authorized-users A,B       users the README lists; others are reported as 'not in your list'
  --authorized-admins A,B      users who may be administrators (sudo/admin group)
  --required-services S,T      services the README says must keep running (never reported as issues)
  --allow-ports 80,443/tcp     ports treated as intended (not reported as exposed)
  --scoring-notes FILE         unresolved items you copied from the official Scoring Report (one per line, optional '=> FINDING-ID');
                               matching findings are sorted first. The toolkit cannot read the Scoring Report itself.
  --scoring-host HOST[:PORT]   a host you got from the official documentation; one DNS lookup + one HTTPS HEAD request
  --no-network-probe           skip all active connectivity probes (DNS lookup, ping, HTTPS HEAD)

The toolkit is read-only: it reports problems and never changes the system. See docs/manual-fixes.md for the commands to fix them yourself.
EOF
}

TK_OUTPUT_DIR="${TK_OUTPUT_DIR:-$PWD/toolkit-output}"
OPT_MODULES=""; OPT_FORCE=0

parse_opts() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --output-dir) [[ $# -ge 2 ]] || { tk_err "--output-dir needs a value"; return 1; }; TK_OUTPUT_DIR=$2; shift;;
      --modules)    [[ $# -ge 2 ]] || { tk_err "--modules needs a value"; return 1; }; OPT_MODULES=$2; shift;;
      --no-color)   TK_NO_COLOR=1; tk_color_init;;
      --force-unsupported) OPT_FORCE=1;;
      --profile)    [[ $# -ge 2 ]] || { tk_err "--profile needs a value"; return 1; }; tk_load_profile "$2" || return 1; shift;;
      --authorized-users)  [[ $# -ge 2 ]] || { tk_err "--authorized-users needs a value"; return 1; }; tk_set_list TK_AUTH_USERS "$2" names || return 1; shift;;
      --authorized-admins) [[ $# -ge 2 ]] || { tk_err "--authorized-admins needs a value"; return 1; }; tk_set_list TK_AUTH_ADMINS "$2" names || return 1; shift;;
      --required-services) [[ $# -ge 2 ]] || { tk_err "--required-services needs a value"; return 1; }; tk_set_list TK_REQ_SERVICES "$2" names || return 1; shift;;
      --allow-ports)       [[ $# -ge 2 ]] || { tk_err "--allow-ports needs a value"; return 1; }; tk_set_list TK_ALLOW_PORTS "$2" ports || return 1; shift;;
      --scoring-notes) [[ $# -ge 2 ]] || { tk_err "--scoring-notes needs a value"; return 1; }; sc_load_notes "$2" || return 1; shift;;
      --scoring-host)  [[ $# -ge 2 ]] || { tk_err "--scoring-host needs a value"; return 1; }
                       conn_valid_host "$2" || { tk_err "invalid --scoring-host '$2' (use a host name or IPv4 address, optional :port)"; return 1; }
                       TK_SCORING_HOST=$2; shift;;
      --no-network-probe) TK_NETWORK_PROBE=0;;
      -h|--help)    usage; exit 0;;
      *) tk_err "unknown option: $1"; return 1;;
    esac
    shift
  done
}

cmd_detect() {
  det_run
  det_print
  case "$DET_SUPPORT" in targeted) return 0;; limited) return 0;; *) return 3;; esac
}

cmd_audit() {
  tk_notice
  det_run
  det_print
  if [[ "$DET_SUPPORT" == unsupported && $OPT_FORCE -ne 1 ]]; then
    tk_err "Unsupported system. Re-run with --force-unsupported to attempt a best-effort read-only audit."
    return 3
  fi
  [[ "$DET_SUPPORT" != targeted ]] && tk_warn "This is not a targeted Linux Mint 21.x/22.x system - results may be incomplete or inapplicable."
  sc_expect_warn
  tk_is_root || tk_warn "Not running as root: checks that need root (shadow, sudoers, ufw rules, sshd -T, per-user crontabs) will be listed as UNPERFORMED. Re-run with sudo for full coverage."

  local stamp run
  stamp=$(date '+%Y%m%d-%H%M%S')
  run="$TK_OUTPUT_DIR/audit-$stamp"
  # Only touch directories THIS run creates: --output-dir may point at an existing folder (e.g. $HOME or /tmp)
  # whose permissions/ownership must not be changed.
  local out_existed=1; [[ -d "$TK_OUTPUT_DIR" ]] || out_existed=0
  if ! mkdir -p "$run"; then tk_err "cannot create output directory $run"; return 1; fi
  chmod 700 "$run" || tk_warn "could not restrict permissions on $run"
  if [[ $out_existed -eq 0 ]]; then chmod 700 "$TK_OUTPUT_DIR" || tk_warn "could not restrict permissions on $TK_OUTPUT_DIR"; fi
  TK_RUN_DIR=$run; TK_WORK="$run"; TK_LOG_FILE="$run/audit.log"
  : >"$TK_LOG_FILE"
  rp_init "$run/findings.dat"

  TK_MODE=audit
  local m fn want="${OPT_MODULES:-$(tk_join , "${TK_AUDIT_MODULES[@]}")}" ran=()
  IFS=, read -ra sel <<<"$want"
  for m in "${sel[@]}"; do
    if [[ -z "${TK_MODULE_FN[$m]:-}" ]]; then tk_err "unknown module '$m'"; TK_MODE=none; return 1; fi
  done
  [[ -n "$TK_AUTH_USERS$TK_AUTH_ADMINS$TK_REQ_SERVICES$TK_ALLOW_PORTS" ]] && printf 'Profile in use: authorized_users=[%s] authorized_admins=[%s] required_services=[%s] allow_ports=[%s]\n' "$TK_AUTH_USERS" "$TK_AUTH_ADMINS" "$TK_REQ_SERVICES" "$TK_ALLOW_PORTS"
  printf '\n%sRunning read-only audit (%s)...%s\n' "$C_BLD" "$(tk_join ' ' "${sel[@]}")" "$C_OFF"
  for m in "${sel[@]}"; do
    fn=${TK_MODULE_FN[$m]}
    tk_log INFO "module $m start"
    if ! "$fn"; then
      f_unperformed "Toolkit" "TOOLKIT-MODULE-$m" "Module '$m' failed" "The $m module returned an error; its results are incomplete."
    fi
    ran+=("$m")
    printf '  - %-18s done\n' "$m"
  done
  TK_MODE=none

  sc_compute_scored
  rp_write_report "$run/report.md"
  chmod 600 "$run/report.md" "$run/audit.log" "$run/findings.dat" || tk_warn "could not restrict permissions on report files"
  if tk_is_root && [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
    # hand back only what this run created (never recurse into a pre-existing output directory)
    chown -R "$SUDO_UID:$SUDO_GID" "$run" || tk_warn "could not hand report folder back to $SUDO_USER"
    if [[ $out_existed -eq 0 ]]; then chown "$SUDO_UID:$SUDO_GID" "$TK_OUTPUT_DIR" || tk_warn "could not hand $TK_OUTPUT_DIR back to $SUDO_USER"; fi
  fi
  rp_terminal_summary
  sc_terminal_checklist
  printf '\n%sDetailed report:%s %s\n' "$C_BLD" "$C_OFF" "$run/report.md"
  printf '%sRun log:%s         %s\n' "$C_BLD" "$C_OFF" "$run/audit.log"
  printf 'This audit made no changes to the system. Next: read the report, compare with the README, then make any fixes yourself (docs/manual-fixes.md).\n'
  return 0
}

cmd_forensics_help() { tk_forensics_help; }

cmd_selftest() {
  if [[ ! -x "$TK_DIR/tests/run_all.sh" && ! -r "$TK_DIR/tests/run_all.sh" ]]; then tk_err "tests/ directory not found"; return 1; fi
  bash "$TK_DIR/tests/run_all.sh"
}

main() {
  TK_ERRF=$(mktemp "${TMPDIR:-/tmp}/tk.err.XXXXXX") || { tk_err "cannot create a temporary file in ${TMPDIR:-/tmp}"; return 1; }
  trap 'rm -f "$TK_ERRF"' EXIT
  # lists may also arrive via environment variables: validate them exactly like command-line values
  tk_set_list TK_AUTH_USERS "$TK_AUTH_USERS" names && tk_set_list TK_AUTH_ADMINS "$TK_AUTH_ADMINS" names \
    && tk_set_list TK_REQ_SERVICES "$TK_REQ_SERVICES" names && tk_set_list TK_ALLOW_PORTS "$TK_ALLOW_PORTS" ports || return 1
  local cmd=${1:-help}
  [[ $# -gt 0 ]] && shift
  parse_opts "$@" || { usage >&2; return 1; }
  # a notes file / scoring host given through the environment is validated the same way as the option
  if [[ -n "$TK_SCORING_NOTES" && ${#SC_NOTE_TEXT[@]} -eq 0 ]]; then sc_load_notes "$TK_SCORING_NOTES" || return 1; fi
  if [[ -n "$TK_SCORING_HOST" ]] && ! conn_valid_host "$TK_SCORING_HOST"; then tk_err "invalid TK_SCORING_HOST '$TK_SCORING_HOST'"; return 1; fi
  case "$cmd" in
    detect) cmd_detect;;
    audit) cmd_audit;;
    forensics-help) cmd_forensics_help;;
    self-test|selftest) cmd_selftest;;
    version|--version) echo "mint-toolkit $TK_VERSION";;
    help|-h|--help) usage;;
    *) tk_err "unknown command: $cmd"; usage >&2; return 1;;
  esac
}

# Allow tests to source this file without running main.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
  exit $?
fi
