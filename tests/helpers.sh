#!/usr/bin/env bash
# helpers.sh - tiny test framework + fixture/mocking environment.  Sourced by tests/test_*.sh.
#
# A test environment ($E) is a throw-away copy of one or more fixture directories:
#   $E/root    -> becomes TK_ROOT (the fake "/")
#   $E/cmds    -> canned command output for the generic mock (tests/mocks/dispatch.sh)
#   $E/find    -> lists returned by the mocked `find` scans
#   $E/stat.db -> "path mode owner group" table behind the mocked stat/chmod/chown
#   $E/bin     -> directory of mock executables placed first on PATH
# The toolkit runs in a child bash process with that environment, so the real
# system (and the real /etc) is never touched.

T_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$(dirname "$T_DIR")"
FIX="$T_DIR/fixtures"
MOCKS="$T_DIR/mocks"
US=$'\x1f'

T_PASS=0; T_FAIL=0; T_SKIP=0; T_FAILED=()
TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/tkt.XXXXXX")
trap 'rm -rf "$TEST_TMP"' EXIT

t_section() { printf '\n== %s ==\n' "$1"; }
t_ok()   { T_PASS=$((T_PASS+1)); printf '  ok   - %s\n' "$1"; }
t_fail() { T_FAIL=$((T_FAIL+1)); T_FAILED+=("$1"); printf '  FAIL - %s\n' "$1"; [[ -n "${2:-}" ]] && printf '         %s\n' "$2"; }
t_skip() { T_SKIP=$((T_SKIP+1)); printf '  SKIP - %s (%s)\n' "$1" "${2:-}"; }

assert_eq()           { if [[ "$2" == "$3" ]]; then t_ok "$1"; else t_fail "$1" "expected [$2] got [$3]"; fi; }
assert_ne()           { if [[ "$2" != "$3" ]]; then t_ok "$1"; else t_fail "$1" "values unexpectedly equal [$2]"; fi; }
assert_contains()     { if [[ "$2" == *"$3"* ]]; then t_ok "$1"; else t_fail "$1" "missing [$3] in: ${2:0:300}"; fi; }
assert_not_contains() { if [[ "$2" != *"$3"* ]]; then t_ok "$1"; else t_fail "$1" "unexpected [$3] present"; fi; }
assert_file()         { if [[ -e "$2" ]]; then t_ok "$1"; else t_fail "$1" "missing file $2"; fi; }
assert_no_file()      { if [[ ! -e "$2" ]]; then t_ok "$1"; else t_fail "$1" "file should not exist: $2"; fi; }
assert_file_has()     { if grep -Fq -- "$3" "$2" 2>/dev/null; then t_ok "$1"; else t_fail "$1" "[$3] not in $2"; fi; }
assert_file_lacks()   { if ! grep -Fq -- "$3" "$2" 2>/dev/null; then t_ok "$1"; else t_fail "$1" "[$3] unexpectedly in $2"; fi; }

t_summary() {
  printf '\n-- %s: %d passed, %d failed, %d skipped\n' "${T_NAME:-tests}" "$T_PASS" "$T_FAIL" "$T_SKIP"
  if [[ $T_FAIL -gt 0 ]]; then printf 'Failed:\n'; printf '  - %s\n' "${T_FAILED[@]}"; return 1; fi
  return 0
}

# ---------------------------------------------------------------- environments
MOCK_CMDS_ALL=(uname hostname id ss systemctl ufw sshd dpkg dpkg-query apt-get gsettings xfconf-query ip sysctl aa-status stat find chmod chown runuser iptables visudo lightdm ping curl getent)

mk_mockbin() { # dir cmd...
  local dir=$1 c; shift
  mkdir -p "$dir"
  for c in "$@"; do
    printf '#!/usr/bin/env bash\nexec bash "%s" %s "$@"\n' "$MOCKS/dispatch.sh" "$c" >"$dir/$c"
    chmod +x "$dir/$c"
  done
}

# mk_env NAME [fixture-dir ...]   later fixtures overlay earlier ones
mk_env() {
  local name=$1 fx; shift
  E="$TEST_TMP/$name"
  rm -rf "$E"; mkdir -p "$E/root" "$E/cmds" "$E/find" "$E/bin" "$E/out" "$E/state"
  : >"$E/stat.db"
  for fx in "$@"; do
    [[ -d "$fx/root" ]] && cp -R "$fx/root/." "$E/root/"
    [[ -d "$fx/cmds" ]] && cp -R "$fx/cmds/." "$E/cmds/"
    [[ -d "$fx/find" ]] && cp -R "$fx/find/." "$E/find/"
    [[ -f "$fx/stat.db" ]] && cp "$fx/stat.db" "$E/stat.db"
  done
  # git does not store empty directories; the fixtures expect these to exist
  mkdir -p "$E/root/tmp" "$E/root/usr/bin" "$E/root/var/lib/apt/lists"
  : >"$E/mock.log"
  mk_mockbin "$E/bin" "${MOCK_CMDS_ALL[@]}"
  T_EUID=""; T_STDIN=""; T_EXTRA_ENV=""
}

# drop_mocks CMD... : simulate missing utilities
drop_mocks() { local c; for c in "$@"; do rm -f "$E/bin/$c"; done; }

# run_tk ARGS...  -> T_RC, T_OUT, T_ERR   (T_EUID=0 pretends to be root; T_STDIN=file for answers)
run_tk() {
  local -a envv=(
    "TK_ROOT=$E/root" "PATH=$E/bin:$PATH" "MOCK_CMD_DIR=$E/cmds" "MOCK_LOG=$E/mock.log"
    "MOCK_STAT_DB=$E/stat.db" "MOCK_FIND_DIR=$E/find" "MOCK_REAL_PATH=$PATH"
    "TK_OUTPUT_DIR=$E/out" "TK_STATE_DIR=$E/state" "TK_NO_COLOR=1" "NO_COLOR=1"
    "TK_CMD_TIMEOUT=60" "TK_ASSUME_BUS=1" "TK_NO_NOTICE=1"
  )
  [[ -n "${T_EUID:-}" ]] && envv+=("TK_FAKE_EUID=$T_EUID")
  local x; for x in ${T_EXTRA_ENV:-}; do envv+=("$x"); done
  env "${envv[@]}" bash "$PROJECT/mint-toolkit.sh" "$@" <"${T_STDIN:-/dev/null}" >"$E/stdout.txt" 2>"$E/stderr.txt"
  T_RC=$?
  T_OUT=$(<"$E/stdout.txt"); T_ERR=$(<"$E/stderr.txt")
}

# in_env 'bash snippet' : run a snippet with the libs sourced and the same environment
in_env() {
  local snippet=$1
  env "TK_ROOT=$E/root" "PATH=$E/bin:$PATH" "MOCK_CMD_DIR=$E/cmds" "MOCK_LOG=$E/mock.log" \
      "MOCK_STAT_DB=$E/stat.db" "MOCK_FIND_DIR=$E/find" "MOCK_REAL_PATH=$PATH" "TK_NO_COLOR=1" "NO_COLOR=1" \
      ${T_EUID:+TK_FAKE_EUID=$T_EUID} ${T_ENV2:-} \
      bash -c "set -u; source '$PROJECT/lib/common.sh'; for m in reporting scoring detection users authentication ssh network firewall services applications permissions updates scheduled_tasks desktop_security connectivity forensics; do source '$PROJECT/lib/'\"\$m\".sh; done; $snippet" 2>"$E/in_env.err"
}

latest_run() { local d; d=$(ls -d "$E"/out/audit-* 2>/dev/null | sort | tail -n1); printf '%s' "$d"; }
latest_report() { printf '%s/report.md' "$(latest_run)"; }
latest_findings() { printf '%s/findings.dat' "$(latest_run)"; }

# finding_class ID -> CONFIRMED|POTENTIAL|INFO|UNPERFORMED|"" (from the latest run)
finding_class() { awk -F"$US" -v id="$1" '$4==id{print $1; exit}' "$(latest_findings)"; }
finding_sev()   { awk -F"$US" -v id="$1" '$4==id{print $2; exit}' "$(latest_findings)"; }
finding_ids()   { awk -F"$US" '{print $4}' "$(latest_findings)" | sort; }
class_count()   { awk -F"$US" -v c="$1" '$1==c{n++} END{print n+0}' "$(latest_findings)"; }
has_id_prefix() { awk -F"$US" -v p="$1" 'index($4,p)==1{f=1} END{exit !f}' "$(latest_findings)"; }

# snapshot_tree : stable fingerprint of everything an audit must not change
snapshot_tree() {
  ( cd "$E" && { find root -type f -print0 | sort -z | xargs -0 sha256sum; grep -v '\.tk' stat.db | grep -v ' 644 root root$' | sort | sha256sum; cat cmds/ufw.state 2>/dev/null; } | sha256sum | cut -d' ' -f1 )
}

# true if the mock log contains a state-changing command
mock_mutations() {
  grep -E '^(ufw (enable|--force|disable|default|allow|deny|reload)|sysctl -w|systemctl (start|stop|restart|reload|enable|disable|mask|unmask)|apt-get (install|remove|purge|dist-upgrade|update)|apt-get -y|dpkg (-i|-r|-P|--install|--remove|--purge)|useradd|userdel|usermod|passwd|chpasswd|gpasswd|kill|rm )' "$E/mock.log" || true
}

# plant_webshell : creates a tiny PHP web-shell lookalike at test time (split strings keep the repo free of scanner-triggering samples)
plant_webshell() { mkdir -p "$E/root/var/www/html"; printf '<?php %s%s($_GET["c"]); ?>\n' "sys" "tem" >"$E/root/var/www/html/x.php"; }

mk_answers() { # n lines of answer text  -> file path in T_STDIN
  local f="$E/answers.txt" a; : >"$f"
  for a in "$@"; do printf '%s\n' "$a" >>"$f"; done
  T_STDIN=$f
}
