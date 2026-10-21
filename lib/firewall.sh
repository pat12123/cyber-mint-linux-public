#!/usr/bin/env bash
# firewall.sh - UFW / iptables state.  Read-only.

audit_firewall() {
  local cat="Firewall"
  local have_ufw=0
  if tk_have ufw || [[ -x "$(tkp /usr/sbin/ufw)" ]]; then have_ufw=1; fi

  if [[ $have_ufw -eq 0 ]]; then
    f_potential medium "$cat" "FW-UFW-MISSING" "UFW (Uncomplicated Firewall) is not installed" "ufw command not found." \
      "Linux Mint ships ufw/gufw by default; its absence may mean it was removed. No host firewall manager is present." \
      "Install with 'sudo apt install ufw' (needs network/repositories) and decide on rules. Package installation is not automated by this toolkit." \
      "Installing packages changes the system; verify repositories first." - yes
    return 0
  fi

  local state="" detail=""
  if tk_cmd ufw status verbose && [[ -n "$TK_OUT" ]]; then
    detail=$TK_OUT
    case "$TK_OUT" in
      *"Status: active"*) state=active;;
      *"Status: inactive"*) state=inactive;;
    esac
  else
    local why="${TK_ERR:-no output}"
    local conf; conf=$(tkp /etc/ufw/ufw.conf)
    if [[ -r "$conf" ]]; then
      local en; en=$(tk_last_value "$conf" ENABLED || true)
      case "${en,,}" in
        yes) state=active;; no) state=inactive;;
      esac
      detail="ufw status unavailable ($why); read ENABLED=$en from /etc/ufw/ufw.conf. Rules could not be listed - re-run as root."
      f_unperformed "$cat" "FW-UFW-RULES" "UFW rule listing" "'ufw status' requires root ($why)"
    else
      f_unperformed "$cat" "FW-UFW-STATE" "UFW state" "ufw status failed ($why) and /etc/ufw/ufw.conf is unreadable"
      return 0
    fi
  fi

  case "$state" in
    inactive)
      local sshnote=""
      if tk_cmd systemctl is-active ssh && [[ "$TK_OUT" == active ]]; then
        sshnote=" SSH is running: allow it BEFORE enabling or you can lock yourself out of remote access."
      fi
      f_potential medium "$cat" "FW-UFW-INACTIVE" "UFW firewall is installed but not enabled" "$detail" \
        "With no host firewall every listening service is reachable. Whether the README expects a firewall is unknown.$sshnote" \
        "Enable with 'sudo ufw enable' (default deny incoming). Do this by hand after checking the README (see docs/manual-fixes.md)." \
        "Blocks inbound connections to services without an allow rule (SSH, web, file sharing...). Remote sessions could be cut." - yes;;
    active)
      f_info "$cat" "FW-UFW-ACTIVE" "UFW is active" "$detail"
      if [[ "$detail" == *"Default:"* ]]; then
        local def; def=$(printf '%s\n' "$detail" | grep -E '^Default:' | head -n1)
        if [[ "$def" != *"deny (incoming)"* && "$def" != *"reject (incoming)"* ]]; then
          f_potential medium "$cat" "FW-UFW-DEFAULT-IN" "UFW default policy for incoming traffic is not deny" "$def" \
            "An allow-by-default incoming policy defeats the firewall." "Set 'sudo ufw default deny incoming' after checking required services have allow rules." \
            "Services without an allow rule become unreachable." - yes
        fi
        local log; log=$(printf '%s\n' "$detail" | grep -E '^Logging:' | head -n1)
        [[ "$log" == *off* ]] && f_info "$cat" "FW-UFW-LOGGING" "UFW logging is off" "$log"
      fi;;
    *)
      f_unperformed "$cat" "FW-UFW-STATE" "UFW state" "Could not determine whether UFW is active: ${detail:-no output}";;
  esac

  return 0
}
