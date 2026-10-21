#!/usr/bin/env bash
# ssh.sh - OpenSSH server audit.  Read-only.
# Effective configuration comes from `sshd -T` when available (needs root);
# otherwise the config files are parsed with sshd's "first value wins" rule,
# honouring Include, and stopping at the first Match block.

declare -A SSH_CFG
SSH_CFG_SRC=""

ssh_parse_file() { # file
  local f=$1 line key val inc p
  [[ -r "$f" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line=${line#"${line%%[![:space:]]*}"}
    [[ -z "$line" || "$line" == \#* ]] && continue
    key=${line%%[[:space:]=]*}
    val=${line#"$key"}
    val=${val#"${val%%[![:space:]=]*}"}
    val=${val%"${val##*[![:space:]]}"}
    key=${key,,}
    case "$key" in
      match) return 0 ;;                              # everything after is conditional
      include)
        local -a pats=(); local g
        read -ra pats <<<"$val"                      # split WITHOUT globbing; globbing happens after the root prefix
        for p in "${pats[@]}"; do
          if [[ "$p" == /* ]]; then p=$(tkp "$p"); else p="$(tkp /etc/ssh)/$p"; fi
          # shellcheck disable=SC2231  # intentional glob expansion
          for g in $p; do [[ -f "$g" ]] && ssh_parse_file "$g"; done
        done ;;
      *) [[ -z "${SSH_CFG[$key]+x}" ]] && SSH_CFG[$key]=$val ;;
    esac
  done <"$f"
}

ssh_load_config() {
  SSH_CFG=(); SSH_CFG_SRC=""
  if tk_cmd sshd -T && [[ -n "$TK_OUT" ]]; then
    local k v
    while read -r k v; do [[ -n "$k" ]] && SSH_CFG[${k,,}]=$v; done <<<"$TK_OUT"
    SSH_CFG_SRC="sshd -T (effective configuration)"
    return 0
  fi
  local why="$TK_ERR"
  local main; main=$(tkp /etc/ssh/sshd_config)
  if [[ -r "$main" ]]; then
    shopt -s nullglob
    ssh_parse_file "$main"
    shopt -u nullglob
    SSH_CFG_SRC="parsed from /etc/ssh/sshd_config and includes (sshd -T unavailable: ${why:-no output}); compiled-in defaults assumed for unset keys"
    return 0
  fi
  return 1
}

ssh_val() { # key default
  local v=${SSH_CFG[$1]-}
  printf '%s' "${v:-$2}"
}

audit_ssh() {
  local cat="SSH and remote access"
  local installed=0 active=0 enabled="" dpkg_rc
  tk_cmd dpkg -s openssh-server; dpkg_rc=$TK_RC
  if [[ $dpkg_rc -eq 0 && "$TK_OUT" == *"Status: install ok installed"* ]]; then installed=1
  elif [[ -x "$(tkp /usr/sbin/sshd)" ]] || tk_have sshd; then installed=1
  elif [[ $dpkg_rc -eq 127 && -r "$(tkp /etc/ssh/sshd_config)" ]]; then
    # no package manager to ask: a config file is the best remaining evidence
    installed=1
    f_unperformed "$cat" "SSH-PKGCHECK" "OpenSSH package check" "dpkg unavailable; SSH assumed installed because /etc/ssh/sshd_config exists (it may be a leftover from a removed package)."
  fi

  if tk_cmd systemctl is-active ssh && [[ "$TK_OUT" == active ]]; then active=1
  elif tk_cmd systemctl is-active sshd && [[ "$TK_OUT" == active ]]; then active=1
  elif [[ $TK_RC -eq 127 ]]; then
    f_unperformed "$cat" "SSH-SERVICE-STATE" "SSH service state" "systemctl not available"
  fi
  tk_cmd systemctl is-enabled ssh && enabled=$TK_OUT
  local socket=0
  if tk_cmd systemctl is-active ssh.socket && [[ "$TK_OUT" == active ]]; then
    socket=1
    # Ubuntu 22.10+/24.04 start sshd on demand: an inactive ssh.service with an active ssh.socket is NORMAL and means SSH is on.
    [[ $active -eq 0 ]] && { active=1; enabled="${enabled:-unknown} (socket-activated via ssh.socket)"; }
  fi

  if [[ $installed -eq 0 ]]; then
    f_info "$cat" "SSH-INSTALLED" "OpenSSH server is not installed" "No openssh-server package or sshd binary found."
    if [[ $active -eq 1 ]]; then
      f_potential medium "$cat" "SSH-ACTIVE-NOPKG" "An ssh service reports active although no package was found" "systemctl is-active ssh -> active" "Unexpected state." "Investigate." "" - yes
    fi
    return 0
  fi

  if [[ $active -eq 1 ]]; then
    f_potential low "$cat" "SSH-ACTIVE" "SSH server is installed and running" "openssh-server installed; service active; enabled=${enabled:-unknown}" \
      "A running SSH server is remote access. It is expected if the README says SSH is required, and a risk surface if not." \
      "Check the README. If SSH is NOT required: 'sudo systemctl disable --now ssh'. If it IS required, keep it and harden its configuration instead." \
      "Disabling SSH removes remote access; required services may depend on it." - yes
  else
    f_info "$cat" "SSH-INSTALLED" "OpenSSH server is installed but not running" "service active=no enabled=${enabled:-unknown}"
  fi

  if ! ssh_load_config; then
    f_unperformed "$cat" "SSH-CONFIG" "SSH effective configuration" "sshd -T failed (${TK_ERR:-needs root}) and $(tkp /etc/ssh/sshd_config) is unreadable"
    return 0
  fi
  local src="Source: $SSH_CFG_SRC"
  local v

  v=$(ssh_val permitrootlogin prohibit-password)
  case "${v,,}" in
    yes) f_confirmed high "$cat" "SSH-ROOTLOGIN" "SSH permits direct root login with a password (PermitRootLogin yes)" "PermitRootLogin $v
$src" \
           "Direct root login over the network exposes the most privileged account to password guessing." \
           "Set 'PermitRootLogin no' (use a drop-in file in /etc/ssh/sshd_config.d/ and validate with 'sshd -t'; see docs/manual-fixes.md)." \
           "Anything that logs in as root over SSH will stop working; use a normal user plus sudo." - no;;
    no) f_info "$cat" "SSH-ROOTLOGIN" "Root login over SSH is disabled" "PermitRootLogin $v
$src";;
    *) f_info "$cat" "SSH-ROOTLOGIN" "Root login over SSH restricted to keys ($v)" "PermitRootLogin $v
$src";;
  esac

  v=$(ssh_val permitemptypasswords no)
  [[ "${v,,}" == yes ]] && f_confirmed high "$cat" "SSH-EMPTYPW" "SSH allows empty passwords (PermitEmptyPasswords yes)" "PermitEmptyPasswords $v
$src" \
    "Accounts with empty passwords could log in remotely." "Set 'PermitEmptyPasswords no' (see docs/manual-fixes.md)." "None for legitimate accounts." - no

  v=$(ssh_val passwordauthentication yes)
  [[ "${v,,}" == yes ]] && f_potential low "$cat" "SSH-PASSWORDAUTH" "SSH accepts password authentication" "PasswordAuthentication $v
$src" \
    "Password logins can be guessed; key-only login is stronger. It is also the default, and many images require it." \
    "Do NOT disable unless the README asks for it AND key-based login is verified working, otherwise you lock yourself out." \
    "Disabling without a working key locks everyone out of SSH." - yes

  v=$(ssh_val permituserenvironment no)
  [[ "${v,,}" == yes ]] && f_confirmed medium "$cat" "SSH-USERENV" "SSH permits user environment (PermitUserEnvironment yes)" "PermitUserEnvironment $v
$src" "Lets users inject environment variables (e.g. LD_PRELOAD) into sessions." "Set to 'no'." "" - no
  v=$(ssh_val hostbasedauthentication no)
  [[ "${v,,}" == yes ]] && f_confirmed medium "$cat" "SSH-HOSTBASED" "SSH host-based authentication enabled" "HostbasedAuthentication $v
$src" "Trusts remote hosts rather than users." "Set to 'no'." "" - no
  v=$(ssh_val ignorerhosts yes)
  [[ "${v,,}" == no ]] && f_confirmed medium "$cat" "SSH-RHOSTS" "SSH honours .rhosts files (IgnoreRhosts no)" "IgnoreRhosts $v
$src" "Legacy trust files can bypass authentication." "Set to 'yes'." "" - no
  v=$(ssh_val x11forwarding no)
  [[ "${v,,}" == yes ]] && f_potential low "$cat" "SSH-X11" "SSH X11 forwarding is enabled" "X11Forwarding $v
$src" "Forwarded X11 sessions can expose the client's display." "Set 'X11Forwarding no' unless the README or users need it." "Breaks remote GUI apps over SSH." - yes
  v=$(ssh_val maxauthtries 6)
  if [[ "$v" =~ ^[0-9]+$ ]] && (( v > 4 )); then
    f_potential low "$cat" "SSH-MAXAUTH" "SSH allows $v authentication attempts per connection" "MaxAuthTries $v
$src" "More attempts per connection help password guessing." "Optionally set MaxAuthTries 4 or lower." "" - yes
  fi
  v=$(ssh_val logingracetime 120)
  f_info "$cat" "SSH-SUMMARY" "SSH effective settings (selected)" "PermitRootLogin=$(ssh_val permitrootlogin prohibit-password) PasswordAuthentication=$(ssh_val passwordauthentication yes) PermitEmptyPasswords=$(ssh_val permitemptypasswords no) X11Forwarding=$(ssh_val x11forwarding no) MaxAuthTries=$(ssh_val maxauthtries 6) LoginGraceTime=$v UsePAM=$(ssh_val usepam yes)
$src"

  ssh_audit_authkeys "$cat" "$active"
  return 0
}

# Counts authorized_keys entries per user.  Key material is never printed.
ssh_audit_authkeys() {
  local cat=$1 active=$2 n ev="" total=0
  [[ -n "${U_ORDER[*]:-}" ]] || users_load || return 0
  for n in "${U_ORDER[@]}"; do
    local home=${U_HOME[$n]:-}
    [[ -z "$home" ]] && continue
    local ak; ak=$(tkp "$home/.ssh/authorized_keys")
    if [[ -e "$ak" ]]; then
      if [[ -r "$ak" ]]; then
        local c; c=$(grep -Evc '^[[:space:]]*(#|$)' "$ak" || true)
        ev+="$n: $c key(s) in $home/.ssh/authorized_keys"$'\n'; total=$((total+c))
      else
        ev+="$n: authorized_keys exists but is unreadable"$'\n'
      fi
    fi
  done
  [[ -z "$ev" ]] && return 0
  if [[ "$active" == 1 ]]; then
    f_potential low "$cat" "SSH-AUTHKEYS" "authorized_keys files grant key-based SSH access" "${ev}(Key contents are intentionally not shown.)" \
      "Planted keys are a classic persistence mechanism." "Verify each key belongs to an authorised user; remove unknown keys manually." "Removing a legitimate key blocks that user." - yes
  else
    f_info "$cat" "SSH-AUTHKEYS" "authorized_keys files exist (SSH server not running)" "$ev"
  fi
}
