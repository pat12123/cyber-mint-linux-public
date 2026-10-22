#!/usr/bin/env bash
# desktop_security.sh - LightDM login manager and per-desktop screen-lock settings.  Read-only.
#
# Login-manager settings are system-wide files and are checked directly.
# Screen-lock settings live in each user's dconf/xfconf database, so they can
# only be read from that user's running session; the toolkit checks the
# invoking user (SUDO_USER when run with sudo) and says so.

# ---------------------------------------------------------------- LightDM
# Echo "value|source-file" of the LAST definition of key in the Seat sections,
# following LightDM's override order.
ds_lightdm_get() { # key
  local key=$1 f val="" src="" v
  local -a files=()
  shopt -s nullglob
  files+=("$(tkp /usr/share/lightdm/lightdm.conf.d)"/*.conf)
  files+=("$(tkp /etc/xdg/lightdm/lightdm.conf.d)"/*.conf)
  files+=("$(tkp /etc/lightdm/lightdm.conf.d)"/*.conf)
  files+=("$(tkp /etc/lightdm/lightdm.conf)")
  shopt -u nullglob
  for f in "${files[@]}"; do
    [[ -r "$f" ]] || continue
    v=$(awk -v k="$key" '
      /^[[:space:]]*\[/ { sec=($0 ~ /^[[:space:]]*\[(Seat:\*|SeatDefaults)\]/); next }
      sec && $0 !~ /^[[:space:]]*[#;]/ {
        line=$0; sub(/^[[:space:]]+/,"",line)
        i=index(line,"="); if(i>0){ kk=substr(line,1,i-1); gsub(/[[:space:]]+$/,"",kk)
          if(kk==k){ vv=substr(line,i+1); gsub(/^[[:space:]]+|[[:space:]]+$/,"",vv); val=vv; found=1 } } }
      END{ if(found) print val; else exit 1 }' "$f") && { val=$v; src=$f; }
  done
  [[ -n "$src" ]] || return 1
  printf '%s|%s' "$val" "$(tk_unroot "$src")"
}

ds_display_manager() {
  local f; f=$(tkp /etc/X11/default-display-manager)
  [[ -r "$f" ]] || return 1
  basename "$(head -n1 "$f")"
}

audit_desktop_security() {
  local cat="Desktop security"
  local dm
  if dm=$(ds_display_manager); then
    f_info "$cat" "DESK-DM" "Display manager: $dm" "/etc/X11/default-display-manager -> $dm"
  else
    dm=""
    f_unperformed "$cat" "DESK-DM" "Display manager detection" "/etc/X11/default-display-manager unreadable or missing"
  fi

  if [[ "$dm" == lightdm || ( -z "$dm" && -d "$(tkp /etc/lightdm)" ) ]]; then
    ds_audit_lightdm "$cat"
  elif [[ -n "$dm" ]]; then
    f_unperformed "$cat" "DESK-LOGIN-MANAGER" "Login-manager security checks" "Display manager '$dm' is not LightDM; Mint uses LightDM by default and this toolkit has no checks for $dm."
  fi
  ds_audit_screenlock "$cat"
  ds_audit_firefox "$cat"
  return 0
}

# Firefox preferences that weaken the browser (pref name|value that is bad).  Only plain pref files are read; JSON enterprise policies are not parsed.
DS_FF_BAD='dom.disable_open_during_load|false
browser.safebrowsing.malware.enabled|false
browser.safebrowsing.phishing.enabled|false
browser.safebrowsing.downloads.enabled|false
xpinstall.signatures.required|false
extensions.blocklist.enabled|false
security.tls.version.min|0
security.tls.version.min|1
security.ssl.require_safe_negotiation|false'

ds_ff_value() { # file pref-name -> last value in the file (quotes/space stripped), or nothing
  grep -E "^[[:space:]]*(user_)?pref\([[:space:]]*\"${2//./\\.}\"[[:space:]]*," "$1" 2>/dev/null | tail -n1 \
    | sed -E 's/^[^,]*,[[:space:]]*//; s/\)[[:space:]]*;?[[:space:]]*$//' | tr -d '"[:space:]'
}

ds_audit_firefox() {
  local cat=$1 f name bad v hits="" n=0 ng
  local -a files=()
  ng=$(shopt -p nullglob); shopt -s nullglob
  files+=("$(tkp /etc/firefox)"/syspref.js "$(tkp /usr/lib/firefox/defaults/pref)"/*.js)
  files+=("$(tkp /home)"/*/.mozilla/firefox/*/{prefs,user}.js "$(tkp /home)"/*/snap/firefox/common/.mozilla/firefox/*/{prefs,user}.js)
  files+=("$(tkp /root)"/.mozilla/firefox/*/{prefs,user}.js)
  eval "$ng"
  for f in "${files[@]}"; do
    [[ -f "$f" && -r "$f" ]] || continue
    n=$((n+1))
    while IFS='|' read -r name bad; do
      [[ -z "$name" ]] && continue
      v=$(ds_ff_value "$f" "$name")
      [[ "$v" == "$bad" ]] && hits+="$(tk_unroot "$f"): $name = $v"$'\n'
    done <<<"$DS_FF_BAD"
  done
  if [[ -n "$hits" ]]; then
    f_potential low "$cat" "DESK-FIREFOX-INSECURE" "Firefox has security features switched off" "$hits" \
      "Popup blocking, Safe Browsing, extension signature checks, the add-on blocklist or modern TLS are turned off in a Firefox preference file." \
      "In Firefox open about:config, find each preference above and reset it (right-click > Reset), or delete the line from the file while Firefox is closed (see docs/manual-fixes.md)." \
      "None expected for normal browsing." - yes
  elif [[ $n -gt 0 ]]; then
    f_info "$cat" "DESK-FIREFOX" "Firefox preference files checked" "$n file(s) read; none of the checked settings is weakened. Enterprise policies (policies.json) and built-in defaults are not evaluated."
  else
    f_info "$cat" "DESK-FIREFOX" "No Firefox preference files found" "Firefox is not installed or no profile has been created yet."
  fi
}

ds_audit_lightdm() {
  local cat=$1 r v src
  if ! [[ -d "$(tkp /etc/lightdm)" || -d "$(tkp /usr/share/lightdm)" ]]; then
    f_unperformed "$cat" "DESK-LIGHTDM" "LightDM configuration" "LightDM configuration directories not found"
    return 0
  fi
  local summary=""

  if r=$(ds_lightdm_get autologin-user); then
    v=${r%%|*}; src=${r#*|}
    summary+="autologin-user=${v:-<empty>} ($src)"$'\n'
    if [[ -n "$v" ]]; then
      f_confirmed medium "$cat" "DESK-AUTOLOGIN" "Automatic login is enabled for user '$v'" "autologin-user=$v  (set in $src)" \
        "Anyone with physical access to the machine is logged in as '$v' without a password." \
        "Disable unless the README requires it: see docs/manual-fixes.md, or use the Login Window settings in the Mint menu." \
        "The login screen will appear at boot and a password will be needed." - no
    fi
  else
    summary+="autologin-user: not set"$'\n'
  fi

  if r=$(ds_lightdm_get autologin-guest); then
    v=${r%%|*}; src=${r#*|}
    summary+="autologin-guest=$v ($src)"$'\n'
    [[ "${v,,}" == true ]] && f_confirmed high "$cat" "DESK-AUTOLOGIN-GUEST" "Automatic login as guest is enabled" "autologin-guest=$v ($src)" \
      "The machine logs into a guest session without any credentials." "Set autologin-guest=false." "None for normal use." - no
  fi

  if r=$(ds_lightdm_get allow-guest); then
    v=${r%%|*}; src=${r#*|}
    summary+="allow-guest=$v ($src)"$'\n'
    if [[ "${v,,}" == true ]]; then
      f_confirmed medium "$cat" "DESK-GUEST" "Guest sessions are enabled at the login screen" "allow-guest=$v  (set in $src)" \
        "Guest sessions allow login without an account; most hardening checklists disable them." \
        "Set allow-guest=false (see docs/manual-fixes.md for the exact file and lines)." \
        "Guest users can no longer log in." - no
    fi
  else
    summary+="allow-guest: not explicitly set"$'\n'
    f_potential medium "$cat" "DESK-GUEST" "Guest sessions are not explicitly disabled" "allow-guest is not set in any LightDM configuration file read." \
      "LightDM's upstream default allows guest sessions and this build's default could not be proven from configuration files alone. Verify at the login screen." \
      "Setting allow-guest=false explicitly is harmless (see docs/manual-fixes.md)." "Guest users can no longer log in." - yes
  fi

  for v in greeter-hide-users greeter-show-manual-login; do
    if r=$(ds_lightdm_get "$v"); then summary+="$v=${r%%|*} (${r#*|})"$'\n'; fi
  done
  ds_lightdm_crosscheck "$cat"
  f_info "$cat" "DESK-LIGHTDM" "Effective LightDM seat settings" "${summary}Files read in order: /usr/share/lightdm/lightdm.conf.d, /etc/xdg/lightdm/lightdm.conf.d, /etc/lightdm/lightdm.conf.d, /etc/lightdm/lightdm.conf (later wins)."
  return 0
}

# ---------------------------------------------------------------- screen lock
DS_USER=""
ds_pick_user() {
  if tk_is_root; then
    [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]] && { DS_USER=$SUDO_USER; return 0; }
    return 1
  fi
  tk_cmd id -un && DS_USER=$TK_OUT
  [[ -n "$DS_USER" ]]
}

ds_get() { # schema key -> DS_VAL
  DS_VAL=""
  if tk_is_root; then
    tk_cmd_as_user "$DS_USER" gsettings get "$1" "$2" || return 1
  else
    [[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" || -n "${TK_ASSUME_BUS:-}" ]] || { TK_ERR="no DBUS_SESSION_BUS_ADDRESS (not in a desktop session)"; return 1; }
    tk_cmd gsettings get "$1" "$2" || return 1
  fi
  DS_VAL=${TK_OUT#uint32 }
  return 0
}

ds_audit_screenlock() {
  local cat=$1
  local desk=${DET_DESKTOP:-unknown}
  if [[ "$desk" != cinnamon && "$desk" != mate && "$desk" != xfce ]]; then
    f_unperformed "$cat" "DESK-SCREENLOCK" "Screen-lock settings" "Desktop environment is '$desk'; screen-lock checks exist only for Cinnamon, MATE and Xfce."
    return 0
  fi
  if ! ds_pick_user; then
    f_unperformed "$cat" "DESK-SCREENLOCK" "Screen-lock settings ($desk)" "Per-user desktop settings can only be read from the user's own session. Run the audit as that user (without sudo) for this check, or use sudo from that user's session."
    return 0
  fi
  local manual
  case "$desk" in
    cinnamon) manual="gsettings get org.cinnamon.desktop.screensaver lock-enabled ; gsettings get org.cinnamon.desktop.session idle-delay";;
    mate)     manual="gsettings get org.mate.screensaver lock-enabled ; gsettings get org.mate.session idle-delay";;
    xfce)     manual="xfconf-query -c xfce4-screensaver -lv";;
  esac

  case "$desk" in
    cinnamon) ds_check_gsettings "$cat" cinnamon org.cinnamon.desktop.screensaver lock-enabled org.cinnamon.desktop.session idle-delay seconds "$manual";;
    mate)     ds_check_gsettings "$cat" mate org.mate.screensaver lock-enabled org.mate.session idle-delay minutes "$manual";;
    xfce)     ds_check_xfce "$cat" "$manual";;
  esac
  return 0
}

ds_check_gsettings() { # cat desk lock-schema lock-key idle-schema idle-key idle-unit manual
  local cat=$1 desk=$2 ls=$3 lk=$4 is=$5 ik=$6 unit=$7 manual=$8
  local lock="" idle="" why=""
  if ds_get "$ls" "$lk"; then lock=$DS_VAL; else why="$TK_ERR"; fi
  if ds_get "$is" "$ik"; then idle=$DS_VAL; else why="${why:+$why; }$TK_ERR"; fi
  if [[ -z "$lock" && -z "$idle" ]]; then
    f_unperformed "$cat" "DESK-SCREENLOCK" "Screen-lock settings ($desk, user $DS_USER)" "gsettings query failed: ${why:-unknown}. Check manually: $manual"
    return 0
  fi
  f_info "$cat" "DESK-SCREENLOCK-VALUES" "Screen-lock values for user $DS_USER ($desk)" "$ls $lk = ${lock:-unreadable}
$is $ik = ${idle:-unreadable} ($unit)
(These are per-user settings; other users may differ.)"
  if [[ "$lock" == false ]]; then
    f_potential medium "$cat" "DESK-LOCK-DISABLED" "Screen lock is disabled for user $DS_USER" "$ls $lk = false" \
      "An unattended, unlocked session is accessible to anyone with physical access. Whether the README requires locking is unknown." \
      "Enable it in the desktop's Screensaver/Lock settings, or: gsettings set $ls $lk true (run as that user)." "Users must re-enter their password after idle." - yes
  fi
  if [[ "$idle" =~ ^[0-9]+$ ]] && (( idle == 0 )); then
    f_potential low "$cat" "DESK-IDLE-NEVER" "Screensaver/idle activation delay is 0 (never) for user $DS_USER" "$is $ik = 0" \
      "With no idle activation the lock never triggers automatically." "Set a finite idle delay if the README asks for one." "" - yes
  fi
}

ds_check_xfce() {
  local cat=$1 manual=$2 out
  local rc=1
  if tk_is_root; then tk_cmd_as_user "$DS_USER" xfconf-query -c xfce4-screensaver -lv; rc=$?
  else tk_cmd xfconf-query -c xfce4-screensaver -lv; rc=$?; fi
  if [[ $rc -ne 0 ]]; then
    f_unperformed "$cat" "DESK-SCREENLOCK" "Screen-lock settings (xfce, user $DS_USER)" "xfconf-query failed: ${TK_ERR:-rc=$rc}. Xfce stores nothing until settings are changed from defaults. Check manually in Settings > Screensaver (or: $manual)"
    return 0
  fi
  out=$TK_OUT
  f_info "$cat" "DESK-SCREENLOCK-VALUES" "xfce4-screensaver properties for user $DS_USER" "$out
(Xfce screen-lock key names were not validated on a real Mint Xfce system; read the values above by eye.)"
  if printf '%s\n' "$out" | grep -Eq '^/saver/idle-activation/enabled[[:space:]]+false'; then
    f_potential low "$cat" "DESK-IDLE-DISABLED" "Screensaver idle activation is disabled for user $DS_USER (xfce4-screensaver)" "/saver/idle-activation/enabled = false" \
      "Without idle activation the screen never locks automatically." "Enable it in Settings > Screensaver." "" - yes
  fi
  f_info "$cat" "DESK-XFCE-DEFAULTS" "Note on Xfce defaults" "Properties missing from the list above use xfce4-screensaver's compiled defaults (lock enabled, idle activation enabled, 5 minute idle delay - from upstream source, not yet confirmed on a Mint image). Whether the image uses xfce4-screensaver, light-locker or xscreensaver should be checked with: dpkg -l xfce4-screensaver light-locker xscreensaver"
  if printf '%s\n' "$out" | grep -Eq '^/lock/enabled[[:space:]]+false'; then
    f_potential medium "$cat" "DESK-LOCK-DISABLED" "Screen lock is disabled for user $DS_USER (xfce4-screensaver)" "/lock/enabled = false" \
      "An unattended, unlocked session is accessible to anyone with physical access." "Enable locking in Settings > Screensaver > Lock Screen." "" - yes
  fi
}

# `lightdm --show-config` prints the merged configuration as LightDM itself reads it.
# Compare it with our own file parsing; a mismatch means a file we did not model is in play.
ds_lightdm_crosscheck() {
  local cat=$1
  tk_have lightdm || return 0
  tk_cmd lightdm --show-config || return 0
  [[ -n "$TK_OUT" ]] || return 0
  local key mine theirs diffs=""
  for key in autologin-user allow-guest; do
    theirs=$(printf '%s\n' "$TK_OUT" | awk -v k="$key" '/^\[/{sec=($0=="[Seat:*]"||$0=="[SeatDefaults]")} sec && $0 !~ /^[#;]/ && index($0,k"=")==1{v=substr($0,length(k)+2)} END{print v}')
    mine=""; local r; r=$(ds_lightdm_get "$key") && mine=${r%%|*}
    [[ "$mine" != "$theirs" ]] && diffs+="$key: toolkit read '${mine:-<unset>}', lightdm --show-config says '${theirs:-<unset>}'"$'\n'
  done
  if [[ -n "$diffs" ]]; then
    f_potential low "$cat" "DESK-LIGHTDM-MISMATCH" "LightDM's merged configuration differs from what the toolkit parsed" "$diffs" \
      "Another configuration source (not modelled by the toolkit) may be overriding these settings. Trust 'lightdm --show-config'." \
      "Run 'lightdm --show-config' and follow the '# from file' comments to the file that wins." "" - yes
  fi
}
