#!/usr/bin/env bash
# users.sh - accounts, groups, sudo.  Read-only.  Never prints password hashes:
# only the *state* of a hash (empty / locked / set) and its algorithm id.

declare -A U_UID U_GID U_HOME U_SHELL U_PWF S_STATE S_ALGO S_MAX S_EXPIRE
U_ORDER=()
USERS_SHADOW_OK=0

users_is_nologin() { case "${1##*/}" in nologin|false|"") return 0;; esac; return 1; }
users_is_human()   { local uid=${U_UID[$1]:-0}; (( uid >= 1000 && uid < 65534 )) && [[ "$1" != nobody ]]; }
users_can_login()  { ! users_is_nologin "${U_SHELL[$1]:-}"; }

users_load() {
  U_ORDER=(); U_UID=(); U_GID=(); U_HOME=(); U_SHELL=(); U_PWF=(); S_STATE=(); S_ALGO=(); S_MAX=(); S_EXPIRE=()
  USERS_SHADOW_OK=0
  local pf; pf=$(tkp /etc/passwd)
  tk_readable "$pf" || return 1
  local name pw uid gid gecos home shell rest
  while IFS=: read -r name pw uid gid gecos home shell rest; do
    [[ -z "$name" || "$name" == \#* ]] && continue
    U_ORDER+=("$name"); U_UID[$name]=$uid; U_GID[$name]=$gid; U_HOME[$name]=$home; U_SHELL[$name]=$shell; U_PWF[$name]=$pw
  done <"$pf"
  local sf; sf=$(tkp /etc/shadow)
  if tk_readable "$sf"; then
    USERS_SHADOW_OK=1
    local hash last min max warn inact exp
    while IFS=: read -r name hash last min max warn inact exp rest; do
      [[ -z "$name" ]] && continue
      local state algo=""
      if [[ -z "$hash" ]]; then state=empty
      elif [[ "$hash" == '!'* || "$hash" == '*'* ]]; then
        state=locked; [[ "$hash" == '*'* ]] && state=disabled
        hash=${hash#!}
      else state=set; fi
      if [[ "$hash" == \$* ]]; then algo=${hash#\$}; algo=${algo%%\$*}
      elif [[ -n "$hash" && "$hash" != '*' && "$hash" != '!' ]]; then algo=des; fi
      S_STATE[$name]=$state; S_ALGO[$name]=$algo; S_MAX[$name]=$max; S_EXPIRE[$name]=$exp
    done <"$sf"
  fi
  return 0
}

# groups a user belongs to (supplementary via /etc/group + primary)
users_groups_of() {
  local u=$1 gf; gf=$(tkp /etc/group)
  [[ -r "$gf" ]] || return 0
  awk -F: -v u="$u" -v pg="${U_GID[$u]:-x}" '{ n=split($4,m,","); hit=($3==pg); for(i=1;i<=n;i++) if(m[i]==u) hit=1; if(hit) printf "%s ", $1 }' "$gf"
}

audit_users() {
  local cat="Users and privileges"
  if ! users_load; then
    f_unperformed "$cat" "USERS-PASSWD" "Could not read /etc/passwd" "File missing or unreadable at $(tkp /etc/passwd)"
    return 0
  fi

  # --- account inventory (information only; the README decides who is authorised)
  local ev="" n g
  ev+=$'NAME            UID    LOGIN-SHELL  PASSWORD   GROUPS(sudo-relevant marked *)\n'
  for n in "${U_ORDER[@]}"; do
    users_is_human "$n" || [[ "${U_UID[$n]}" == 0 ]] || continue
    local grp="" mark=""
    for g in $(users_groups_of "$n"); do
      case "$g" in sudo|admin|wheel|adm|lpadmin|docker|lxd|disk|shadow|root) mark="*";; *) mark="";; esac
      grp+="$g$mark "
    done
    ev+=$(printf '%-15s %-6s %-12s %-10s %s' "$n" "${U_UID[$n]}" "$(users_can_login "$n" && echo yes || echo no)" "${S_STATE[$n]:-unknown}" "$grp")$'\n'
  done
  f_info "$cat" "USERS-INVENTORY" "Local accounts with UID >= 1000 and root" "$ev
Compare this list with the authorized users/administrators in the competition README.
Password state 'unknown' means /etc/shadow was not readable (run as root)."

  # --- UID 0
  for n in "${U_ORDER[@]}"; do
    if [[ "${U_UID[$n]}" == 0 && "$n" != root ]]; then
      f_confirmed high "$cat" "USERS-UID0-$n" "Non-root account '$n' has UID 0" "$(grep "^$n:" "$(tkp /etc/passwd)" | cut -d: -f1,3,4,6,7)" \
        "UID 0 grants full root privileges regardless of the account name." \
        "Verify the account is not authorised, then remove it or change its UID after investigation (do not delete blindly)." \
        "Removing a UID 0 account that a service relies on could break that service." - yes
    fi
  done

  # --- duplicate UIDs
  local dups; dups=$(for n in "${U_ORDER[@]}"; do printf '%s %s\n' "${U_UID[$n]}" "$n"; done | sort -n | awk '{c[$1]++; names[$1]=names[$1] " " $2} END{for(u in c) if(c[u]>1) print u ":" names[u]}')
  if [[ -n "$dups" ]]; then
    while IFS= read -r g; do
      f_confirmed medium "$cat" "USERS-DUPUID-${g%%:*}" "Multiple accounts share UID ${g%%:*}" "$g" \
        "Accounts with the same UID are indistinguishable to the kernel and share file access." \
        "Review each account; give distinct UIDs or remove the unauthorised one." "Changing a UID requires re-owning that user's files." - yes
    done <<<"$dups"
  fi

  # --- password field in /etc/passwd
  for n in "${U_ORDER[@]}"; do
    case "${U_PWF[$n]}" in
      x|'*'|'!'|'!!') ;;
      '') f_confirmed high "$cat" "USERS-PASSWD-EMPTY-$n" "Account '$n' has an empty password field in /etc/passwd" "$n:(empty)" \
            "An empty field in the world-readable passwd file means no password is required." \
            "Lock or set a password for the account after confirming whether it is authorised." "Locking an account in use will log that user out." - yes ;;
      *)  f_confirmed high "$cat" "USERS-PASSWD-HASH-$n" "Account '$n' stores a password hash in world-readable /etc/passwd" "$n: (hash present in passwd field; value withheld)" \
            "Hashes belong in /etc/shadow, which is not world-readable." "Run 'pwconv' as root after review." "pwconv rewrites passwd/shadow; keep a backup first." - yes ;;
    esac
  done

  # --- shadow-based checks
  if [[ $USERS_SHADOW_OK -eq 0 ]]; then
    f_unperformed "$cat" "USERS-SHADOW" "Password-state checks (empty passwords, hash algorithm, aging)" "/etc/shadow is not readable by this user. Re-run with sudo."
  else
    for n in "${U_ORDER[@]}"; do
      local st=${S_STATE[$n]:-}
      [[ -z "$st" ]] && continue
      if [[ "$st" == empty ]]; then
        local sev=low; users_can_login "$n" && sev=high
        f_confirmed "$sev" "$cat" "USERS-EMPTYPW-$n" "Account '$n' has an empty password" "$n: shadow password field empty; login shell: ${U_SHELL[$n]}" \
          "An account with no password can be used without authentication (subject to PAM 'nullok' and the access method)." \
          "Decide whether the account is authorised; set a strong password (passwd $n) or lock it (passwd -l $n). Do not guess - check the README first." \
          "Locking/changing the password of an account that is required will block that user." - yes
      fi
      case "${S_ALGO[$n]:-}" in
        1|des|md5) f_potential medium "$cat" "USERS-WEAKHASH-$n" "Account '$n' password uses a weak hashing algorithm ($( [[ ${S_ALGO[$n]} == 1 ]] && echo md5 || echo "${S_ALGO[$n]}" ))" "$n: hash id '${S_ALGO[$n]}'" \
              "Legacy hashes are much faster to crack than sha512/yescrypt." "Re-set the password after verifying /etc/pam.d/common-password uses sha512 or yescrypt." "Requires changing the user's password." - yes;;
      esac
    done
    # password aging / expiry for human accounts
    local never=""
    for n in "${U_ORDER[@]}"; do
      users_is_human "$n" || continue
      users_can_login "$n" || continue
      [[ "${S_STATE[$n]:-}" == set ]] || continue
      local mx=${S_MAX[$n]:-}
      if [[ -z "$mx" || "$mx" -ge 99999 ]]; then never+="$n "; fi
      if [[ -n "${S_EXPIRE[$n]:-}" ]]; then
        f_info "$cat" "USERS-EXPIRY-$n" "Account '$n' has an expiry date set" "$n: account expires on day ${S_EXPIRE[$n]} since 1970-01-01"
      fi
    done
    if [[ -n "$never" ]]; then
      f_potential low "$cat" "USERS-PWNEVEREXPIRES" "Passwords never expire for: ${never% }" "Max password age is unset or 99999 days for: ${never% }" \
        "Without ageing, a leaked password stays valid indefinitely. Whether the competition expects ageing depends on the README." \
        "If the README requires it: 'sudo chage -M 90 USER' for each user. Existing-account ageing is NOT changed by login.defs." \
        "Users are forced to change passwords at next expiry; do not apply to service accounts." - yes
    fi
    # root
    case "${S_STATE[root]:-}" in
      set) f_potential low "$cat" "USERS-ROOTPW" "root has a usable password" "root password state: set" \
             "Linux Mint normally leaves root locked and uses sudo; a root password enables 'su -' and console root logins." \
             "Check the README. If direct root login is not required: 'sudo passwd -l root'." "Breaks workflows that log in as root directly." - yes;;
      empty) f_confirmed high "$cat" "USERS-ROOTPW-EMPTY" "root has an EMPTY password" "root password state: empty" "Anyone with local access may become root." "Set a strong password or lock the account: sudo passwd -l root" "None expected on a default Mint install." - no;;
      locked|disabled) f_info "$cat" "USERS-ROOTPW" "root password is locked (normal for Mint)" "root password state: ${S_STATE[root]}";;
    esac
  fi

  # --- system accounts with interactive shells
  for n in "${U_ORDER[@]}"; do
    [[ "$n" == root ]] && continue
    local uid=${U_UID[$n]}
    (( uid < 1000 && uid != 0 )) || continue     # UID 0 impostors are reported by USERS-UID0
    users_can_login "$n" || continue
    case "${U_SHELL[$n]}" in /bin/sync|/sbin/halt|/sbin/shutdown) continue;; esac
    f_potential medium "$cat" "USERS-SYSSHELL-$n" "System account '$n' (UID $uid) has an interactive shell" "$n:$uid shell=${U_SHELL[$n]} home=${U_HOME[$n]}" \
      "System accounts normally use /usr/sbin/nologin or /bin/false. An interactive shell lets the account log in if it has a usable credential." \
      "Confirm the account's purpose. If it is a stock service account, set shell to /usr/sbin/nologin ('sudo usermod -s /usr/sbin/nologin $n')." \
      "Some applications (e.g. a database admin account) deliberately keep a shell." - yes
  done

  # --- home directories
  for n in "${U_ORDER[@]}"; do
    users_is_human "$n" || continue
    if [[ ! -d "$(tkp "${U_HOME[$n]}")" ]]; then
      f_potential low "$cat" "USERS-NOHOME-$n" "Home directory of '$n' does not exist" "$n: ${U_HOME[$n]} missing" \
        "A missing home may indicate a stale or hand-edited account." "Verify the account against the README." "" - yes
    fi
  done
  local d b orphans=""
  for d in "$(tkp /home)"/*; do
    [[ -d "$d" ]] || continue
    b=${d##*/}
    [[ -n "${U_UID[$b]:-}" ]] || orphans+="$b "
  done
  [[ -n "$orphans" ]] && f_info "$cat" "USERS-ORPHANHOME" "Home directories without a matching account" "/home: ${orphans% }"

  # --- privileged groups
  users_audit_groups "$cat"
  users_audit_sudoers "$cat"
  users_audit_authorized "$cat"
  return 0
}

users_audit_groups() {
  local cat=$1 gf; gf=$(tkp /etc/group)
  if ! tk_readable "$gf"; then f_unperformed "$cat" "USERS-GROUPS" "Group membership" "/etc/group unreadable"; return 0; fi
  local g members ev=""
  for g in sudo admin wheel adm; do
    members=$(awk -F: -v g="$g" '$1==g{print $4}' "$gf")
    [[ -n "$members" ]] && ev+="$g: $members"$'\n'
  done
  [[ -n "$ev" ]] && f_info "$cat" "USERS-ADMINGROUPS" "Members of administrative groups (sudo/admin/wheel/adm)" "${ev}Compare against the README's list of authorized administrators."
  for g in docker lxd disk shadow; do
    members=$(awk -F: -v g="$g" '$1==g{print $4}' "$gf")
    [[ -n "$members" ]] && f_potential medium "$cat" "USERS-ROOTEQUIV-$g" "Users in root-equivalent group '$g'" "$g: $members" \
      "Membership of '$g' effectively grants root-level access." "Remove members that should not have it: sudo gpasswd -d USER $g" "May break that user's container/disk tooling." - yes
  done
  local rootgid; rootgid=$(awk -F: '$3==0 && $1!="root"{print $1}' "$gf" | tr '\n' ' ')
  [[ -n "$rootgid" ]] && f_potential medium "$cat" "USERS-GID0" "Group(s) other than root with GID 0: ${rootgid% }" "GID 0 groups: ${rootgid% }" "GID 0 grants root-group file access." "Investigate." "" - yes
  return 0
}

# Lines of sudoers that are not the stock Debian/Mint ones.
users_sudoers_files() {
  local f
  f=$(tkp /etc/sudoers); [[ -e "$f" ]] && printf '%s\n' "$f"
  for f in "$(tkp /etc/sudoers.d)"/*; do
    [[ -f "$f" ]] || continue
    case "${f##*/}" in *~|*.*) continue;; esac     # sudo ignores these names
    printf '%s\n' "$f"
  done
}

users_audit_sudoers() {
  local cat=$1 f unread=0 nonstd="" nopw="" files=0
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    files=$((files+1))
    if ! tk_readable "$f"; then unread=1; continue; fi
    local line
    while IFS= read -r line; do
      line=${line%%#*}                                  # strip trailing comment (sudoers uses # for comments)
      [[ "$line" =~ ^[[:space:]]*$ ]] && continue
      case "$line" in
        *'@includedir'*|*'@include '*|*'#include'*) continue;;
        Defaults*|Cmnd_Alias*|Host_Alias*|User_Alias*|Runas_Alias*)
           [[ "$line" == *'!authenticate'* ]] && nopw+="$(tk_unroot "$f"): $line"$'\n'
           continue;;
      esac
      local norm; norm=$(printf '%s' "$line" | tr -s ' \t' ' ')
      case "$norm" in
        'root ALL=(ALL:ALL) ALL'|'root ALL=(ALL) ALL'|'%admin ALL=(ALL) ALL'|'%sudo ALL=(ALL:ALL) ALL'|'%sudo ALL=(ALL) ALL') continue;;
      esac
      [[ "$norm" == *NOPASSWD* ]] && nopw+="$(tk_unroot "$f"): $norm"$'\n'
      nonstd+="$(tk_unroot "$f"): $norm"$'\n'
    done <"$f"
  done < <(users_sudoers_files)
  if tk_is_root && tk_have visudo; then
    if tk_cmd visudo -c; then :
    else
      f_confirmed high "$cat" "USERS-SUDOERS-SYNTAX" "sudoers has syntax errors" "visudo -c (rc=$TK_RC): ${TK_OUT:-}${TK_ERR:+ $TK_ERR}" \
        "A broken sudoers file can disable sudo for everyone." "Fix with 'sudo visudo' (never edit sudoers with a plain editor)." "None." - yes
    fi
  fi
  if [[ $files -eq 0 ]]; then
    f_unperformed "$cat" "USERS-SUDOERS" "sudoers inspection" "No sudoers files found at $(tkp /etc/sudoers)"
    return 0
  fi
  if [[ $unread -eq 1 ]]; then
    f_unperformed "$cat" "USERS-SUDOERS-READ" "Some sudoers files could not be read" "sudoers files are root-readable only; re-run with sudo for a complete result."
  fi
  if [[ -n "$nopw" ]]; then
    f_potential medium "$cat" "USERS-SUDO-NOPASSWD" "sudoers contains passwordless (NOPASSWD / !authenticate) rules" "$nopw" \
      "Passwordless sudo lets any process running as that user gain root." \
      "Check whether the rule is required. Edit ONLY with 'sudo visudo -f FILE'." "A bad sudoers edit can lock all admins out of sudo; always use visudo." - yes
  fi
  if [[ -n "$nonstd" ]]; then
    f_potential low "$cat" "USERS-SUDO-CUSTOM" "Non-default sudoers rules present" "$nonstd" \
      "Custom rules can grant privileges beyond the group-based defaults." "Review each rule against the README." "" - yes
  elif [[ $unread -eq 0 ]]; then
    f_info "$cat" "USERS-SUDO-DEFAULT" "sudoers contains only stock rules" "No non-default rules found."
  fi
  return 0
}

# Compare accounts with the lists the user took from the README (only when provided).
# "Not in your list" is a prompt to check the README - never a verdict.
users_audit_authorized() {
  local cat=$1 n g members
  if [[ -n "$TK_AUTH_USERS$TK_AUTH_ADMINS" ]]; then
    local known="$TK_AUTH_USERS,$TK_AUTH_ADMINS"
    for n in "${U_ORDER[@]}"; do
      users_is_human "$n" || continue
      tk_in_list "$n" "$known" && continue
      f_potential medium "$cat" "USERS-NOTLISTED-$n" "Account '$n' is not in your authorized lists" "$n (uid ${U_UID[$n]}) is a regular account but is absent from --authorized-users/--authorized-admins" \
        "If the README does not list this user, it may be unauthorized. If it is an unlisted but legitimate account (or your list is incomplete), ignore this." \
        "Compare with the README. Remove an unauthorized user only after checking its files and processes (sudo deluser --remove-home NAME is destructive - not automated)." \
        "Deleting a legitimate user destroys their data and is penalised in many scoring models." - yes
    done
    local a
    local IFS=,
    for a in $TK_AUTH_USERS; do
      [[ -n "$a" && -z "${U_UID[$a]:-}" ]] && f_info "$cat" "USERS-MISSING-$a" "Listed user '$a' does not exist on this system" "$a is in your authorized-users list but has no /etc/passwd entry (the README may expect it to exist)."
    done
    unset IFS
  fi
  if [[ -n "$TK_AUTH_ADMINS" ]]; then
    local gf; gf=$(tkp /etc/group)
    tk_readable "$gf" || return 0
    for g in sudo admin wheel; do
      members=$(awk -F: -v g="$g" '$1==g{print $4}' "$gf" | tr ',' ' ')
      for n in $members; do
        tk_in_list "$n" "$TK_AUTH_ADMINS" && continue
        f_potential high "$cat" "USERS-NOTADMIN-$n" "'$n' is in the '$g' group but not in your authorized-admins list" "group $g includes $n" \
          "Administrators have full control. If the README says '$n' is a standard user, this is an excess-privilege issue." \
          "Verify against the README, then: sudo gpasswd -d $n $g  (manual, so you can check the user keeps a way to log in)." "Removing a real administrator can lock you out of sudo." - yes
      done
    done
    local IFS=,
    for n in $TK_AUTH_ADMINS; do
      [[ -z "$n" || -z "${U_UID[$n]:-}" ]] && continue
      members=$(awk -F: '($1=="sudo"||$1=="admin"||$1=="wheel"){print $4}' "$gf" | tr ',' ' ')
      [[ " $members " == *" $n "* ]] || f_info "$cat" "USERS-ADMINMISSING-$n" "Listed administrator '$n' is not in the sudo/admin group" "The README may expect $n to be an administrator."
    done
    unset IFS
  fi
  return 0
}
