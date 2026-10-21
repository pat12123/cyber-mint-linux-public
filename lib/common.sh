#!/usr/bin/env bash
# common.sh - shared helpers for the CyberPatriot Mint toolkit.
# Sourced by mint-toolkit.sh and by the tests; never executed directly.
#
# Test hooks (documented in docs/security.md):
#   TK_ROOT       prefix for every file read (default: empty = real "/")
#   TK_FAKE_EUID  pretend to be this UID when deciding "am I root"
# Everything else reaches the system through tk_cmd so tests can mock it.

# shellcheck disable=SC2034  # many variables are consumed by other modules
TK_VERSION="0.1.0"
TK_ROOT="${TK_ROOT:-}"
TK_ROOT="${TK_ROOT%/}"
TK_MODE="${TK_MODE:-none}"          # none | audit  (the toolkit has no mode that changes the system)
TK_CMD_TIMEOUT="${TK_CMD_TIMEOUT:-30}"
TK_US=$'\x1f'                        # field separator for the findings store

# Bash 5.2 "patsub_replacement" makes '&' special in ${var//x/y}; we want literal.
shopt -u patsub_replacement 2>/dev/null || true

# ---------------------------------------------------------------- paths
tkp() { printf '%s%s' "$TK_ROOT" "$1"; }

# Strip the test root prefix so evidence shows real-looking paths.
tk_unroot() { local p=$1; [[ -n "$TK_ROOT" ]] && p=${p#"$TK_ROOT"}; printf '%s' "$p"; }

# ---------------------------------------------------------------- output
tk_color_init() {
  if [[ -t 1 && -z "${NO_COLOR:-}" && "${TK_NO_COLOR:-0}" != 1 ]]; then
    C_RED=$'\e[31m'; C_YEL=$'\e[33m'; C_GRN=$'\e[32m'; C_BLU=$'\e[34m'
    C_BLD=$'\e[1m'; C_DIM=$'\e[2m'; C_OFF=$'\e[0m'
  else
    C_RED=""; C_YEL=""; C_GRN=""; C_BLU=""; C_BLD=""; C_DIM=""; C_OFF=""
  fi
}
tk_color_init

tk_log() { # level message  -> run log (if one is open)
  [[ -n "${TK_LOG_FILE:-}" ]] || return 0
  printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" >>"$TK_LOG_FILE" 2>/dev/null || true
}
tk_info() { printf '%s\n' "$*"; tk_log INFO "$*"; }
tk_ok()   { printf '%s%s%s\n' "$C_GRN" "$*" "$C_OFF"; tk_log OK "$*"; }
tk_warn() { printf '%sWARNING:%s %s\n' "$C_YEL" "$C_OFF" "$*" >&2; tk_log WARN "$*"; }
tk_err()  { printf '%sERROR:%s %s\n' "$C_RED" "$C_OFF" "$*" >&2; tk_log ERROR "$*"; }

# ---------------------------------------------------------------- privilege
tk_is_root() { [[ "${TK_FAKE_EUID:-$EUID}" -eq 0 ]]; }

# ---------------------------------------------------------------- commands
tk_have() { command -v "$1" >/dev/null 2>&1; }

# In audit mode only read-only invocations of known commands are permitted.
# This is defence in depth: even a coding mistake cannot mutate the system
# through tk_cmd while TK_MODE=audit.
tk_cmd_allowed() {
  [[ "$TK_MODE" == "audit" ]] || return 0
  local c=${1##*/} a
  shift
  case "$c" in
    uname|hostname|id|who|getent|ps|aa-status|apparmor_status|netstat|ss|stat|timeout|dpkg-query|sshd|ufw|systemctl|dpkg|apt-get|gsettings|xfconf-query|ip|sysctl|iptables|find|ls|visudo|lightdm|ping|curl) ;;
    *) return 1 ;;
  esac
  case "$c" in
    ss) for a in "$@"; do [[ "$a" == -K* || "$a" == --kill ]] && return 1; done ;;
    find) for a in "$@"; do case "$a" in -delete|-exec|-execdir|-ok|-okdir|-fprint*|-fls) return 1;; esac; done ;;
    systemctl)
      local verb=""
      for a in "$@"; do [[ "$a" != -* ]] && { verb=$a; break; }; done
      case "$verb" in
        is-active|is-enabled|is-failed|list-units|list-unit-files|list-timers|show|status|cat) ;;
        *) return 1 ;;
      esac ;;
    ufw) [[ "${1:-}" == "status" ]] || return 1 ;;
    visudo) [[ "${1:-}" == "-c" && $# -eq 1 ]] || return 1 ;;          # syntax check of the real sudoers only
    lightdm) [[ "${1:-}" == "--show-config" && $# -eq 1 ]] || return 1 ;;
    # connectivity probes: exactly one echo request / one HEAD request, nothing else
    ping) [[ $# -eq 5 && "$1" == -c && "$2" == 1 && "$3" == -W && "$4" =~ ^[1-5]$ && "$5" =~ ^[A-Za-z0-9][A-Za-z0-9.:-]*$ ]] || return 1 ;;
    curl) [[ $# -eq 8 && "$1" == --head && "$2" == --silent && "$3" == --show-error && "$4" == --output && "$5" == /dev/null \
             && "$6" == --max-time && "$7" =~ ^[1-9]$ && "$8" =~ ^https://[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]{1,5})?/$ ]] || return 1 ;;
    sshd) for a in "$@"; do [[ "$a" == -T || "$a" == -t ]] && return 0; done; return 1 ;;
    dpkg)
      case "${1:-}" in -s|-l|-L|-S|-V|-C|--audit|--status|--list|--listfiles|--search|--print-architecture|--version|--get-selections) ;; *) return 1;; esac ;;
    apt-get) local sim=0; for a in "$@"; do [[ "$a" == -s || "$a" == --simulate || "$a" == --dry-run || "$a" == --just-print ]] && sim=1; done; [[ $sim -eq 1 ]] || return 1 ;;
    gsettings) case "${1:-}" in get|list-keys|list-schemas|list-recursively|range) ;; *) return 1;; esac ;;
    xfconf-query) for a in "$@"; do case "$a" in -s|--set|-r|--reset|-n|--create|-t|--type) return 1;; esac; done ;;
    ip) for a in "$@"; do case "$a" in add|del|delete|set|flush|change|replace|append) return 1;; esac; done ;;
    sysctl) for a in "$@"; do [[ "$a" == *=* || "$a" == -w || "$a" == --write || "$a" == -p || "$a" == --load || "$a" == --system ]] && return 1; done ;;
    iptables) case "${1:-}" in -S|-L|-n|-v|--list|-t) ;; *) return 1;; esac ;;
  esac
  return 0
}

# tk_cmd CMD [ARGS...]
#   Runs an external command with a timeout.  Sets TK_OUT (stdout), TK_ERR
#   (stderr) and TK_RC.  rc 127 = missing, 126 = blocked by audit guard.
tk_cmd() {
  TK_OUT=""; TK_ERR=""; TK_RC=0
  if ! tk_cmd_allowed "$@"; then
    TK_RC=126; TK_ERR="blocked: '$*' is not a permitted read-only command in audit mode"
    tk_log BLOCKED "$*"
    return 126
  fi
  if ! tk_have "$1"; then
    TK_RC=127; TK_ERR="command not found: $1"
    return 127
  fi
  # one scratch file for stderr per process (TK_ERRF, created by main); fall back to one per call
  local errf=${TK_ERRF:-} own=0
  if [[ -z "$errf" ]]; then
    errf=$(mktemp "${TMPDIR:-/tmp}/tk.err.XXXXXX") || { TK_RC=1; TK_ERR="mktemp failed"; return 1; }
    own=1
  fi
  if tk_have timeout; then
    TK_OUT=$(timeout "$TK_CMD_TIMEOUT" "$@" 2>"$errf"); TK_RC=$?
  else
    TK_OUT=$("$@" 2>"$errf"); TK_RC=$?
  fi
  TK_ERR=$(<"$errf")
  [[ $own -eq 1 ]] && rm -f "$errf"
  tk_log CMD "$* (rc=$TK_RC)"
  return "$TK_RC"
}

# ---------------------------------------------------------------- files
tk_readable() { [[ -f "$1" && -r "$1" ]]; }

# Non-comment, non-blank lines of a file.
tk_active_lines() { grep -Ev '^[[:space:]]*(#|$)' "$1"; }

# Value of the LAST "KEY value" or "KEY=value" line (login.defs style).
tk_last_value() { # file key
  [[ -r "$1" ]] || return 1
  awk -v k="$2" '
    /^[[:space:]]*#/ {next}
    { line=$0; sub(/^[[:space:]]+/,"",line)
      n=index(line,"="); s=index(line," "); t=index(line,"\t")
      key=line; val=""
      # split at first space/tab/equals
      m=0
      for(i=1;i<=length(line);i++){c=substr(line,i,1); if(c==" "||c=="\t"||c=="="){m=i;break}}
      if(m>0){key=substr(line,1,m-1); val=substr(line,m+1); sub(/^[[:space:]=]+/,"",val); sub(/[[:space:]]+$/,"",val); gsub(/^"|"$/,"",val)}
      if(key==k) last=val; found=found||(key==k)
    }
    END{ if(found) print last; else exit 1 }' "$1"
}

# "mode owner group" for a path.  Returns non-zero with TK_ERR set on failure.
tk_meta() {
  tk_cmd stat -c '%a %U %G' -- "$1" || return 1
  printf '%s\n' "$TK_OUT"
}

# Octal helpers
tk_mode_has_other_write() { (( (8#$1 & 8#002) != 0 )); }
tk_mode_exceeds()          { (( (8#$1 & ~8#$2 & 8#7777) != 0 )); }  # mode has bits not allowed by max

# Join array elements: tk_join SEP a b c
tk_join() { local s=$1 out="" f; shift; for f in "$@"; do out+="${out:+$s}$f"; done; printf '%s' "$out"; }

# Truncate a multi-line string to N lines and note the remainder.
tk_cap_lines() { # n  (reads stdin)
  awk -v n="$1" 'NR<=n{print} NR>n{extra++} END{if(extra>0) printf "... and %d more (truncated)\n", extra}'
}

# tk_cmd_as_user USER CMD [ARGS...]
#   Read-only helper for per-user desktop settings (gsettings/xfconf).  When the
#   toolkit runs as root via sudo, queries the invoking user's session bus.
#   The inner command must itself pass the audit allow-list.
tk_cmd_as_user() {
  local user=$1; shift
  TK_OUT=""; TK_ERR=""; TK_RC=0
  if ! tk_cmd_allowed "$@"; then TK_RC=126; TK_ERR="blocked: '$*'"; return 126; fi
  tk_have runuser || { TK_RC=127; TK_ERR="runuser not found"; return 127; }
  tk_cmd id -u "$user" || { TK_ERR="cannot resolve uid of $user: $TK_ERR"; return 1; }
  local uid=$TK_OUT bus="/run/user/$TK_OUT/bus"
  [[ -S "$bus" || -n "${TK_ASSUME_BUS:-}" ]] || { TK_RC=1; TK_ERR="no session bus for $user ($bus missing - is the desktop session running?)"; return 1; }
  local errf; errf=$(mktemp "${TK_WORK:-${TMPDIR:-/tmp}}/tk.err.XXXXXX") || { TK_RC=1; TK_ERR="mktemp failed"; return 1; }
  TK_OUT=$(timeout "$TK_CMD_TIMEOUT" runuser -u "$user" -- env "DBUS_SESSION_BUS_ADDRESS=unix:path=$bus" "XDG_RUNTIME_DIR=/run/user/$uid" "$@" 2>"$errf"); TK_RC=$?
  TK_ERR=$(<"$errf"); rm -f "$errf"
  tk_log CMD "as $user: $* (rc=$TK_RC)"
  return "$TK_RC"
}

# ---------------------------------------------------------------- README-derived lists ("profile")
# The competition README decides who is authorised and what is required. The user passes that
# knowledge in via options or a profile file; the toolkit only ever USES it to be more careful
# (report unknown accounts, downgrade required services, keep required ports open).
TK_AUTH_USERS="${TK_AUTH_USERS:-}"; TK_AUTH_ADMINS="${TK_AUTH_ADMINS:-}"
TK_REQ_SERVICES="${TK_REQ_SERVICES:-}"; TK_ALLOW_PORTS="${TK_ALLOW_PORTS:-}"

# tk_in_list ITEM "a,b,c"
tk_in_list() { local list=",${2//[[:space:]]/},"; [[ -n "$2" && "$list" == *",$1,"* ]]; }

# tk_clean_list VALUE KIND -> prints normalised comma list, or returns 1 if it contains junk
tk_clean_list() {
  local v=${1//[[:space:]]/} kind=$2 item out=""
  [[ -z "$v" ]] && return 0
  local IFS=,
  for item in $v; do
    [[ -z "$item" ]] && continue
    case "$kind" in
      names) [[ "$item" =~ ^[A-Za-z0-9._@-]+$ ]] || return 1;;
      ports) [[ "$item" =~ ^[0-9]{1,5}(/(tcp|udp))?$ ]] || return 1; [[ "$item" == */* ]] || item="$item/tcp";;
    esac
    out+="${out:+,}$item"
  done
  printf '%s' "$out"
}

tk_set_list() { # VARNAME VALUE KIND
  local clean
  clean=$(tk_clean_list "$2" "$3") || { tk_err "invalid value for ${1#TK_}: '$2' (allowed: letters, digits . _ @ - ${3/ports/and port[/tcp|udp]})"; return 1; }
  printf -v "$1" '%s' "$clean"
}

# tk_load_profile FILE : "key = value" lines, '#' comments. Never sourced or evaluated.
tk_load_profile() {
  local f=$1 line k v
  [[ -r "$f" ]] || { tk_err "profile file not readable: $f"; return 1; }
  while IFS= read -r line || [[ -n "$line" ]]; do
    line=${line%%#*}
    [[ "$line" =~ ^[[:space:]]*$ ]] && continue
    [[ "$line" == *=* ]] || { tk_warn "profile: ignoring line without '=': $line"; continue; }
    k=${line%%=*}; v=${line#*=}; k=${k//[[:space:]]/}
    case "$k" in
      authorized_users)  tk_set_list TK_AUTH_USERS "$v" names || return 1;;
      authorized_admins) tk_set_list TK_AUTH_ADMINS "$v" names || return 1;;
      required_services) tk_set_list TK_REQ_SERVICES "$v" names || return 1;;
      allow_ports)       tk_set_list TK_ALLOW_PORTS "$v" ports || return 1;;
      *) tk_warn "profile: unknown key '$k' ignored";;
    esac
  done <"$f"
}

# One-line reminder printed by the audit (stderr).
tk_notice() {
  [[ "${TK_NO_NOTICE:-0}" == 1 ]] && return 0
  printf '%sNOTICE:%s this toolkit was written with AI assistance. CyberPatriot rules (CP19 Rules Book, as summarised in docs/competition-rules.md - verify with your coach) may prohibit AI-written scripts, and scripts not written by your own team, in competition rounds. Use it for practice and study unless your coach confirms otherwise.\n' "$C_YEL" "$C_OFF" >&2
}
