#!/usr/bin/env bash
# scheduled_tasks.sh - cron, at, systemd timers/units, startup and shell-profile persistence.  Read-only.
# Pattern matches mean "this looks like something worth reading", never
# "this is malware": legitimate admins use many of these constructs.

# Prints a label if the text matches a pattern commonly seen in backdoors.
sched_suspicious() {
  local t=$1
  local -a pats=(
    '/dev/(tcp|udp)/|reverse shell via /dev/tcp'
    '(^|[[:space:];|&(])(nc|ncat|netcat)[[:space:]]+[^|;]*(-e|-c|-l)|netcat listener or exec'
    'bash[[:space:]]+-i|interactive bash invocation'
    '(curl|wget)[^|;]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|da)?sh|download piped to a shell'
    'base64[[:space:]]+(-d|--decode)|base64-decoded payload'
    'python[0-9.]*[[:space:]]+-c[^|;]*(socket|pty|subprocess)|python one-liner using sockets/pty'
    'perl[[:space:]]+-e[^|;]*socket|perl one-liner using sockets'
    '(^|[[:space:]=;|&(])(/tmp|/var/tmp|/dev/shm)/[^[:space:]]+|runs something from a world-writable temp directory'
    'chmod[[:space:]]+([ugoa]*\+s|[0-7]?[4-7][0-7]{3})|sets the SUID/SGID bit'
    'LD_PRELOAD=|LD_PRELOAD environment override'
  )
  local entry re label
  for entry in "${pats[@]}"; do
    # '|' also appears inside the regex, so split on the LAST one
    label=${entry##*|}; re=${entry%|*}
    if printf '%s' "$t" | grep -Eq -- "$re"; then printf '%s' "$label"; return 0; fi
  done
  return 1
}

sched_sanitize_id() { printf '%s' "$1" | sed -E 's|^/||; s|[^A-Za-z0-9]+|-|g; s|-+$||' | cut -c1-48; }

# Scan active lines of a file for suspicious patterns; echo "ok" lines count via global.
sched_scan_file() { # file category idprefix
  local f=$1 cat=$2 prefix=$3 line label n=0
  tk_readable "$f" || return 1
  while IFS= read -r line; do
    n=$((n+1))
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    if label=$(sched_suspicious "$line"); then
      f_potential high "$cat" "$prefix-$(sched_sanitize_id "$(tk_unroot "$f")")-L$n" "Suspicious-looking entry in $(tk_unroot "$f"): $label" "$(tk_unroot "$f"):$n: $line" \
        "This pattern is common in persistence mechanisms and reverse shells. It can also be a legitimate admin script, so read it before acting." \
        "Read the line and the file/script it calls; decide with the README whether it belongs. Remove manually only if unauthorised." \
        "Removing a legitimate job stops that job." - yes
    fi
  done <"$f"
  return 0
}

audit_scheduled_tasks() {
  local cat="Scheduled tasks and persistence"
  sched_audit_cron "$cat"
  sched_audit_timers "$cat"
  sched_audit_startup "$cat"
  return 0
}

sched_audit_cron() {
  local cat=$1 f ev="" unreadable="" nfiles=0
  local -a files=()
  [[ -e "$(tkp /etc/crontab)" ]] && files+=("$(tkp /etc/crontab)")
  for f in "$(tkp /etc/cron.d)"/*; do [[ -f "$f" ]] && files+=("$f"); done
  for f in "$(tkp /var/spool/cron/crontabs)"/*; do [[ -f "$f" ]] && files+=("$f"); done
  for f in "${files[@]}"; do
    nfiles=$((nfiles+1))
    if ! tk_readable "$f"; then unreadable+="$(tk_unroot "$f") "; continue; fi
    local lines; lines=$(tk_active_lines "$f" | grep -Ev '^[[:space:]]*(SHELL|PATH|MAILTO|HOME|LOGNAME)=' || true)
    [[ -n "$lines" ]] && ev+="--- $(tk_unroot "$f")"$'\n'"$lines"$'\n'
    sched_scan_file "$f" "$cat" SCHED-CRON
  done
  if [[ ! -d "$(tkp /var/spool/cron/crontabs)" ]] || ! [[ -r "$(tkp /var/spool/cron/crontabs)" ]]; then
    tk_is_root || f_unperformed "$cat" "SCHED-USERCRON" "Per-user crontabs (/var/spool/cron/crontabs)" "Directory is root-only; re-run with sudo to inspect user crontabs."
  fi
  [[ -n "$unreadable" ]] && f_unperformed "$cat" "SCHED-CRON-READ" "Some cron files were unreadable" "$unreadable"
  f_info "$cat" "SCHED-CRON" "Active cron entries" "${ev:-No active entries in /etc/crontab, /etc/cron.d or user crontabs.}"

  # cron.hourly/daily/weekly/monthly: list names and scan contents
  local d s list=""
  for d in hourly daily weekly monthly; do
    for s in "$(tkp "/etc/cron.$d")"/*; do
      [[ -f "$s" ]] || continue
      list+="cron.$d/${s##*/} "
      sched_scan_file "$s" "$cat" SCHED-CRONDIR
    done
  done
  [[ -n "$list" ]] && f_info "$cat" "SCHED-CRONDIRS" "Scripts in /etc/cron.{hourly,daily,weekly,monthly}" "$list"
  for f in cron.allow cron.deny at.allow at.deny; do
    [[ -e "$(tkp "/etc/$f")" ]] && f_info "$cat" "SCHED-$f" "/etc/$f exists" "$(tk_active_lines "$(tkp "/etc/$f")" | tr '\n' ' ')"
  done
  # at jobs
  local aj=""; for f in "$(tkp /var/spool/cron/atjobs)"/*; do [[ -f "$f" && "${f##*/}" != .SEQ ]] && aj+="${f##*/} "; done
  [[ -n "$aj" ]] && f_potential low "$cat" "SCHED-AT" "Pending 'at' jobs exist" "Jobs: $aj" "One-shot jobs can be used for delayed persistence." "Inspect with 'sudo atq' / 'sudo at -c JOBID'." "" - yes
  return 0
}

sched_audit_timers() {
  local cat=$1
  if tk_cmd systemctl list-timers --all --no-legend --plain --no-pager; then
    local names; names=$(printf '%s\n' "$TK_OUT" | awk '{for(i=1;i<=NF;i++) if($i ~ /\.timer$/){print $i; break}}' | tr '\n' ' ')
    f_info "$cat" "SCHED-TIMERS" "Systemd timers" "${names:-none}"
  elif [[ $TK_RC -eq 127 ]]; then
    f_unperformed "$cat" "SCHED-TIMERS" "Systemd timers" "systemctl not available"
  else
    f_unperformed "$cat" "SCHED-TIMERS" "Systemd timers" "systemctl list-timers failed (rc=$TK_RC): $TK_ERR"
  fi

  # locally created units (regular files, not symlinks, in /etc/systemd/system)
  local f local_units="" n
  for f in "$(tkp /etc/systemd/system)"/*.service "$(tkp /etc/systemd/system)"/*.timer; do
    [[ -f "$f" && ! -L "$f" ]] || continue
    local_units+="${f##*/} "
    local ex; ex=$(grep -E '^[[:space:]]*Exec(Start|StartPre|StartPost|Stop)[[:space:]]*=' "$f" || true)
    local label
    if label=$(sched_suspicious "$ex"); then
      f_potential high "$cat" "SCHED-UNIT-${f##*/}" "Suspicious-looking ExecStart in ${f##*/}: $label" "${f##*/}:
$ex" "Locally created units are a persistence mechanism; this one matches a backdoor-style pattern." "Read the unit and its target; remove only if unauthorised." "" - yes
    fi
  done
  [[ -n "$local_units" ]] && f_potential low "$cat" "SCHED-LOCALUNITS" "Locally created systemd units in /etc/systemd/system" "$local_units" \
    "Admin-created units run with the privileges they declare and start at boot." "Review each ('systemctl cat UNIT'); it is not necessarily wrong." "" - yes
  # per-user units
  [[ -n "${U_ORDER[*]:-}" ]] || users_load || return 0
  for n in "${U_ORDER[@]}"; do
    local home=${U_HOME[$n]:-}; [[ -z "$home" ]] && continue
    for f in "$(tkp "$home/.config/systemd/user")"/*.service "$(tkp "$home/.config/systemd/user")"/*.timer; do
      [[ -f "$f" ]] || continue
      f_potential low "$cat" "SCHED-USERUNIT-$n-${f##*/}" "User-level systemd unit for $n: ${f##*/}" "$(tk_unroot "$f")" "Per-user units start at login without root." "Review the unit." "" - yes
      sched_scan_file "$f" "$cat" SCHED-USERUNIT
    done
  done
  return 0
}

sched_audit_startup() {
  local cat=$1 f n
  # rc.local
  f=$(tkp /etc/rc.local)
  if [[ -f "$f" ]]; then
    local body; body=$(tk_active_lines "$f" | grep -Ev '^[[:space:]]*(#!|exit[[:space:]]+0)' || true)
    if [[ -n "$body" ]]; then
      f_potential medium "$cat" "SCHED-RCLOCAL" "/etc/rc.local contains commands" "$body" "rc.local runs as root at boot." "Review each command." "" - yes
      sched_scan_file "$f" "$cat" SCHED-RCLOCAL-PAT
    fi
  fi
  # ld.so.preload
  f=$(tkp /etc/ld.so.preload)
  if [[ -s "$f" ]]; then
    f_potential high "$cat" "SCHED-LDPRELOAD" "/etc/ld.so.preload is non-empty" "$(cat "$f")" "Libraries listed here load into every process - a classic rootkit mechanism and rarely used legitimately." "Investigate each library path." "Removing a legitimately preloaded library may break the software that needs it." - yes
  fi
  # shell profiles
  local -a profiles=("$(tkp /etc/profile)" "$(tkp /etc/bash.bashrc)" "$(tkp /etc/environment)")
  for f in "$(tkp /etc/profile.d)"/*.sh; do [[ -f "$f" ]] && profiles+=("$f"); done
  [[ -n "${U_ORDER[*]:-}" ]] || users_load || true
  for n in "${U_ORDER[@]:-}"; do
    [[ -z "$n" ]] && continue
    local home=${U_HOME[$n]:-}; [[ -z "$home" ]] && continue
    for f in .bashrc .profile .bash_profile .bash_login .bash_logout .xprofile .xsessionrc; do
      [[ -f "$(tkp "$home/$f")" ]] && profiles+=("$(tkp "$home/$f")")
    done
  done
  for f in "${profiles[@]}"; do
    [[ -f "$f" ]] || continue
    if ! tk_readable "$f"; then f_unperformed "$cat" "SCHED-PROFILE-$(sched_sanitize_id "$(tk_unroot "$f")")" "Profile $(tk_unroot "$f")" "unreadable"; continue; fi
    sched_scan_file "$f" "$cat" SCHED-PROFILE
    local al; al=$(grep -nE '^[[:space:]]*alias[[:space:]]+(sudo|su|passwd|ssh|ls|cat|ps|netstat|ss)=' "$f" || true)
    [[ -n "$al" ]] && f_potential medium "$cat" "SCHED-ALIAS-$(sched_sanitize_id "$(tk_unroot "$f")")" "Shell profile redefines a security-relevant command: $(tk_unroot "$f")" "$al" \
      "Aliases can hide activity or capture passwords." "Read the alias; remove if unauthorised." "" - yes
  done
  # autostart
  local -a ad=("$(tkp /etc/xdg/autostart)")
  for n in "${U_ORDER[@]:-}"; do
    [[ -z "$n" ]] && continue
    [[ -n "${U_HOME[$n]:-}" ]] && ad+=("$(tkp "${U_HOME[$n]}/.config/autostart")")
  done
  local dir
  for dir in "${ad[@]}"; do
    [[ -d "$dir" ]] || continue
    for f in "$dir"/*.desktop; do
      [[ -f "$f" ]] || continue
      local ex; ex=$(grep -E '^Exec=' "$f" | head -n1 || true)
      local user_owned=0; [[ "$dir" != "$(tkp /etc/xdg/autostart)" ]] && user_owned=1
      local label
      if label=$(sched_suspicious "$ex"); then
        f_potential high "$cat" "SCHED-AUTOSTART-$(sched_sanitize_id "$(tk_unroot "$f")")" "Suspicious-looking autostart entry $(tk_unroot "$f"): $label" "$(tk_unroot "$f"): $ex" "Autostart entries run at every login." "Read the target; remove if unauthorised." "" - yes
      elif [[ $user_owned -eq 1 ]]; then
        f_info "$cat" "SCHED-AUTOSTART-$(sched_sanitize_id "$(tk_unroot "$f")")" "User autostart entry $(tk_unroot "$f")" "$ex"
      fi
    done
  done
  return 0
}
