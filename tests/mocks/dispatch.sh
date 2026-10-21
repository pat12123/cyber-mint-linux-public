#!/usr/bin/env bash
# Generic command mock used by the test-suite.  Invoked as:  dispatch.sh CMD ARGS...
#
# Environment (set by tests/helpers.sh):
#   MOCK_CMD_DIR   directory of canned responses (writable copy of a fixture's cmds/)
#   MOCK_LOG       file that receives one line per invocation  ("cmd args")
#   MOCK_STAT_DB   "path mode owner group" table used by stat/chmod/chown
#   MOCK_FIND_DIR  ww_files / ww_dirs / suid / nouser lists for `find`
#   MOCK_REAL_PATH PATH without the mock directory (to reach real find, cp, ...)
#   TK_ROOT        fixture root; used to translate paths
#
# Canned response lookup: strip leading dashes from each argument, turn '=' and ':' into '-',
# join with '.', then try the full key and progressively shorter prefixes:
#   systemctl is-active ssh  ->  systemctl.is-active.ssh.{out,rc,err}, systemctl.is-active.{...}, systemctl.{...}
# If nothing matches the mock exits 127 ("not configured") so un-modelled calls fail loudly.

cmd=$1; shift
printf '%s %s\n' "$cmd" "$*" >>"${MOCK_LOG:-/dev/null}"

rel() { local p=$1; printf '%s' "${p#"${TK_ROOT:-}"}"; }

stat_get() { awk -v p="$1" '$1==p{print $2, $3, $4; f=1; exit} END{exit !f}' "$MOCK_STAT_DB" 2>/dev/null; }
stat_set() { # path mode owner group
  local tmp; tmp=$(mktemp "${MOCK_STAT_DB}.XXXXXX")
  awk -v p="$1" '$1!=p' "$MOCK_STAT_DB" >"$tmp" 2>/dev/null
  # "644 root root" is the default for unlisted paths, so do not persist it (keeps before/after comparisons exact)
  [[ "$2 $3 $4" == "644 root root" ]] || printf '%s %s %s %s\n' "$1" "$2" "$3" "$4" >>"$tmp"
  mv -f "$tmp" "$MOCK_STAT_DB"
}

canned() { # tries progressively shorter keys; prints stdout, stderr, returns rc
  local -a parts=(); local a k
  for a in "$@"; do
    a=${a#-}; a=${a#-}
    [[ -z "$a" ]] && continue
    a=${a//=/-}; a=${a//:/-}; a=${a//\//_}
    parts+=("$a")
  done
  local n=${#parts[@]} i base f
  for ((i=n; i>=0; i--)); do
    base="$MOCK_CMD_DIR/$cmd"
    for ((k=0; k<i; k++)); do base+=".${parts[$k]}"; done
    if [[ -e "$base.out" || -e "$base.rc" || -e "$base.err" ]]; then
      [[ -f "$base.err" ]] && cat "$base.err" >&2
      [[ -f "$base.out" ]] && cat "$base.out"
      if [[ -f "$base.rc" ]]; then return "$(tr -d '[:space:]' <"$base.rc")"; fi
      return 0
    fi
  done
  echo "mock: no canned response for: $cmd $*" >&2
  return 127
}

case "$cmd" in
  stat)
    path=${*: -1}; r=$(rel "$path")
    if entry=$(stat_get "$r"); then printf '%s\n' "$entry"; exit 0; fi
    if [[ -e "$path" ]]; then printf '644 root root\n'; exit 0; fi
    echo "stat: cannot statx '$path': No such file or directory" >&2; exit 1;;
  chmod)
    args=("$@"); path=${args[-1]}; mode=${args[0]}
    if [[ -n "${TK_ROOT:-}" && "$path" == "$TK_ROOT"* ]]; then
      r=$(rel "$path"); if entry=$(stat_get "$r"); then read -r _ o g <<<"$entry"; else o=root; g=root; fi
      stat_set "$r" "$mode" "$o" "$g"; exit 0
    fi
    PATH=$MOCK_REAL_PATH exec chmod "$@";;
  chown)
    args=("$@"); path=${args[-1]}; spec=${args[0]}
    if [[ -n "${TK_ROOT:-}" && "$path" == "$TK_ROOT"* ]]; then
      r=$(rel "$path"); if entry=$(stat_get "$r"); then read -r m _ _ <<<"$entry"; else m=644; fi
      stat_set "$r" "$m" "${spec%%:*}" "${spec#*:}"; exit 0
    fi
    exit 0;;
  find)
    # classify the scans the toolkit issues; everything else falls through to the real find
    all=" $* "
    emit() { [[ -s "$1" ]] && while IFS= read -r l; do printf '%s%s\n' "${TK_ROOT:-}" "$l"; done <"$1"; return 0; }
    if   [[ "$all" == *" -nouser "* ]];                 then emit "$MOCK_FIND_DIR/nouser"; exit 0
    elif [[ "$all" == *" -perm -4000 "* ]];             then emit "$MOCK_FIND_DIR/suid"; exit 0
    elif [[ "$all" == *" -perm -0002 "* && "$all" == *" -type f "* ]]; then emit "$MOCK_FIND_DIR/ww_files"; exit 0
    elif [[ "$all" == *" -perm -0002 "* && "$all" == *" -type d "* ]]; then emit "$MOCK_FIND_DIR/ww_dirs"; exit 0
    fi
    PATH=$MOCK_REAL_PATH exec find "$@";;
  sysctl)
    if [[ "$1" == -w ]]; then
      kv=$2; key=${kv%%=*}; val=${kv#*=}
      f="${TK_ROOT:-}/proc/sys/${key//.//}"
      [[ -f "$f" ]] || { echo "sysctl: cannot stat /proc/sys/${key//.//}" >&2; exit 255; }
      [[ -n "${MOCK_FAIL_SYSCTL:-}" && "$key" == "$MOCK_FAIL_SYSCTL" ]] && { echo "sysctl: setting key \"$key\": Operation not permitted" >&2; exit 255; }
      printf '%s\n' "$val" >"$f"; echo "$key = $val"; exit 0
    fi
    canned "$@"; exit $?;;
  ufw)
    state_file="$MOCK_CMD_DIR/ufw.state"
    case "$1" in
      status)
        st=$(cat "$state_file" 2>/dev/null || echo inactive)
        if [[ "$(id -u 2>/dev/null)" != 0 && -z "${TK_FAKE_EUID:-}" ]]; then echo "ERROR: You need to be root to run this script" >&2; exit 1; fi
        echo "Status: $st"
        if [[ "$st" == active ]]; then printf 'Logging: on (low)\nDefault: %s\nNew profiles: skip\n' "$(cat "$MOCK_CMD_DIR/ufw.default" 2>/dev/null || echo "deny (incoming), allow (outgoing), disabled (routed)")"; fi
        exit 0;;
      --force) [[ "$2" == enable ]] && { [[ -n "${MOCK_FAIL_UFW_ENABLE:-}" ]] && { echo "ERROR: enable failed" >&2; exit 1; }; echo active >"$state_file"; }; exit 0;;
      enable)  echo active >"$state_file"; exit 0;;
      disable) echo inactive >"$state_file"; exit 0;;
      default|allow|deny|reload) exit 0;;
    esac
    exit 0;;
  getent)
    # same switch as for ping: name resolution disappears together with connectivity
    if [[ -n "${MOCK_PING_FAIL_AFTER_UFW:-}" && "$(cat "$MOCK_CMD_DIR/ufw.state" 2>/dev/null)" == active ]]; then exit 2; fi
    canned "$@"; exit $?;;
  ping)
    # MOCK_PING_FAIL_AFTER_UFW=1 : connectivity disappears once the (mock) firewall is active
    if [[ -n "${MOCK_PING_FAIL_AFTER_UFW:-}" && "$(cat "$MOCK_CMD_DIR/ufw.state" 2>/dev/null)" == active ]]; then echo "ping: connect: Network is unreachable" >&2; exit 2; fi
    canned "$@"; exit $?;;
  systemctl)
    if [[ "$1" == reload ]]; then
      [[ -n "${MOCK_FAIL_RELOAD:-}" ]] && { echo "Failed to reload $2.service: mock failure" >&2; exit 1; }
      exit 0
    fi
    canned "$@"; exit $?;;
  sshd)
    case "$1" in
      -T) if [[ -f "$MOCK_CMD_DIR/sshd.effective.out" ]]; then cat "$MOCK_CMD_DIR/sshd.effective.out"; exit 0; fi
          echo "sshd: no configuration test available (mock)" >&2; exit 127;;
      -t) [[ -f "$MOCK_CMD_DIR/sshd.test.err" ]] && cat "$MOCK_CMD_DIR/sshd.test.err" >&2
          if [[ -f "$MOCK_CMD_DIR/sshd.test.rc" ]]; then exit "$(tr -d '[:space:]' <"$MOCK_CMD_DIR/sshd.test.rc")"; fi
          exit 0;;
    esac
    exit 0;;
  runuser)
    # runuser -u USER -- env VAR=... CMD ARGS  ->  run CMD ARGS through the mock
    shift 3   # -u USER --
    shift     # env
    while [[ "${1:-}" == *=* ]]; do shift; done
    exec bash "$0" "$@";;
  *)
    canned "$@"; exit $?;;
esac
