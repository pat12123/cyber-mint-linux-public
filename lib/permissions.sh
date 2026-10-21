#!/usr/bin/env bash
# permissions.sh - ownership/permissions of sensitive files and risky file types.  Read-only.
# File contents of secrets are never read: only metadata (mode/owner/group).

# path|max-mode|allowed-owner|allowed-groups(comma)|(unused, always -)
PERM_TABLE='
/etc/passwd|644|root|root|-
/etc/group|644|root|root|-
/etc/shadow|640|root|root,shadow|-
/etc/gshadow|640|root|root,shadow|-
/etc/sudoers|440|root|root|-
/etc/ssh/sshd_config|644|root|root|-
/etc/crontab|644|root|root|-
/etc/fstab|644|root|root|-
/etc/hosts|644|root|root|-
/etc/login.defs|644|root|root|-
'

perm_severity() { # path mode -> severity
  case "$1" in
    /etc/shadow|/etc/gshadow|/etc/sudoers) echo high;;
    *) echo medium;;
  esac
}

audit_permissions() {
  local cat="File permissions"
  local path max owner groups auto bad_any=0 unreadable=0
  while IFS='|' read -r path max owner groups auto; do
    [[ -z "$path" ]] && continue
    local real; real=$(tkp "$path")
    [[ -e "$real" ]] || continue
    local meta
    if ! meta=$(tk_meta "$real"); then
      unreadable=1
      f_unperformed "$cat" "PERM-STAT-$(basename "$path")" "Permissions of $path" "stat failed: ${TK_ERR:-unknown}"
      continue
    fi
    local mode own grp; read -r mode own grp <<<"$meta"
    local problems=""
    tk_mode_exceeds "$mode" "$max" && problems+="mode $mode is more permissive than $max; "
    [[ "$own" == "$owner" ]] || problems+="owner is $own, expected $owner; "
    [[ ",$groups," == *",$grp,"* ]] || problems+="group is $grp, expected one of $groups; "
    if [[ -n "$problems" ]]; then
      bad_any=1
      f_confirmed "$(perm_severity "$path")" "$cat" "PERM-$(printf '%s' "${path#/}" | tr '/' '-')" "Unsafe permissions/ownership on $path" \
        "$path  mode=$mode owner=$own group=$grp
${problems% }" \
        "Sensitive system files must be owned by root and not writable (or for shadow-type files, readable) by ordinary users." \
        "Restore stock values: chmod $max $path; chown $owner:${groups%%,*} $path  (check the current values first; see docs/manual-fixes.md)." \
        "Very low; these are the stock values. Looser modes are rarely needed." "-" no
    fi
  done <<<"$PERM_TABLE"
  [[ $bad_any -eq 0 && $unreadable -eq 0 ]] && f_info "$cat" "PERM-SENSITIVE-OK" "Sensitive file permissions match stock values" "Checked: /etc/passwd group shadow gshadow sudoers sshd_config crontab fstab hosts login.defs (those that exist)."

  perm_audit_special "$cat"
  perm_audit_homes "$cat"
  perm_audit_trees "$cat"
  perm_audit_legacy_trust "$cat"
  return 0
}

# sudoers.d, ssh host keys, grub config
perm_audit_special() {
  local cat=$1 f meta mode own grp
  for f in "$(tkp /etc/sudoers.d)"/*; do
    [[ -f "$f" ]] || continue
    meta=$(tk_meta "$f") || { f_unperformed "$cat" "PERM-SUDOERSD-${f##*/}" "Permissions of sudoers.d/${f##*/}" "stat failed: $TK_ERR"; continue; }
    read -r mode own grp <<<"$meta"
    if tk_mode_exceeds "$mode" 440 || [[ "$own" != root ]]; then
      f_confirmed high "$cat" "PERM-SUDOERSD-${f##*/}" "Unsafe permissions on /etc/sudoers.d/${f##*/}" "mode=$mode owner=$own group=$grp" \
        "sudo ignores or distrusts includes with unsafe modes, and a writable sudoers file is a privilege-escalation path." "chmod 440 and chown root:root the file." "" "-" no
    fi
  done
  for f in "$(tkp /etc/ssh)"/ssh_host_*_key; do
    [[ -f "$f" ]] || continue
    meta=$(tk_meta "$f") || continue
    read -r mode own grp <<<"$meta"
    if tk_mode_exceeds "$mode" 600 || [[ "$own" != root ]]; then
      f_confirmed high "$cat" "PERM-HOSTKEY-${f##*/}" "SSH host private key has unsafe permissions: /etc/ssh/${f##*/}" "mode=$mode owner=$own group=$grp (file contents not read)" \
        "A readable host private key allows impersonating the server." "chmod 600 and chown root:root the key." "sshd refuses keys with loose modes." "-" no
    fi
  done
  return 0
}

# World-writable files/dirs, SUID/SGID outside the stock baseline, unowned files.
PERM_SUID_BASELINE=' passwd chsh chfn gpasswd newgrp su sudo sudoedit mount umount fusermount fusermount3 pkexec ping ping6 ssh-keysign polkit-agent-helper-1 dbus-daemon-launch-helper Xorg.wrap chage expiry wall write ssh-agent unix_chkpwd pam_timestamp_check mlocate plocate locate bsd-write crontab at traceroute6.iputils mtr-packet snap-confine vmware-user-suid-wrapper ntfs-3g sudo_logsrvd pppd nvidia-modprobe cinnamon-screensaver-pam-helper mate-screensaver-pam-helper xfce4-screensaver-pam-helper lightdm-session slick-greeter-check-hidpi lightdm-gtk-greeter ubuntu-core-launcher mount.nfs mount.cifs Xorg dmcrypt-get-device bwrap fusermount-glusterfs arping '
PERM_SUID_DANGEROUS=' bash sh dash zsh find vim vi nano emacs nmap python python3 perl ruby awk gawk mawk less more env cp mv tar zip unzip tee dd cat head tail sed strings xxd base64 node php lua gdb docker '

# perm_scan find-args...  -> PERM_SCAN_OUT (paths relative to the real root, one per line)
#                            PERM_SCAN_ERR (first error line, e.g. permission denied)
perm_scan() {
  PERM_SCAN_ERR=""; PERM_SCAN_OUT=""
  tk_cmd find "$@"
  local rc=$TK_RC p
  if [[ $rc -ne 0 ]]; then PERM_SCAN_ERR="find rc=$rc: ${TK_ERR%%$'
'*}"; fi
  while IFS= read -r p; do
    [[ -n "$p" ]] && PERM_SCAN_OUT+="$(tk_unroot "$p")"$'
'
  done <<<"$TK_OUT"
  return 0
}

perm_count() { printf '%s' "$1" | grep -c . || true; }

perm_audit_trees() {
  local cat=$1 r dirs=() names=() base
  for r in /etc /usr /bin /sbin /lib /lib64 /opt /var /home /root /srv; do
    [[ -d "$(tkp "$r")" ]] && { dirs+=("$(tkp "$r")"); names+=("$r"); }
  done
  if [[ ${#dirs[@]} -eq 0 ]]; then
    f_unperformed "$cat" "PERM-TREES" "Filesystem permission scans" "none of the scan roots exist"
    return 0
  fi
  if ! tk_have find; then f_unperformed "$cat" "PERM-TREES" "Filesystem permission scans" "find not available"; return 0; fi
  local partial_hint="Directories this user cannot read were skipped; re-run with sudo for full coverage."
  local out

  # world-writable regular files
  perm_scan "${dirs[@]}" -xdev -type f -perm -0002 ! -path '*/proc/*' ! -path '*/sys/*'
  out=$PERM_SCAN_OUT
  if [[ -n "$out" ]]; then
    f_potential medium "$cat" "PERM-WW-FILES" "World-writable files found ($(perm_count "$out"))" "$(printf '%s' "$out" | tk_cap_lines 40)${PERM_SCAN_ERR:+
(scan incomplete: $PERM_SCAN_ERR)}"       "Any user can modify these files; in /etc, /usr or /home that can lead to privilege escalation or tampering."       "Inspect each file (ls -l). Fix only files that are clearly wrong (chmod o-w FILE). Do NOT run a recursive chmod."       "Some applications deliberately use world-writable files (sockets, caches)." - yes
  elif [[ -n "$PERM_SCAN_ERR" ]]; then
    f_unperformed "$cat" "PERM-WW-FILES" "World-writable file scan" "scan incomplete or failed, so 'none found' cannot be concluded: $PERM_SCAN_ERR. $partial_hint"
  else
    f_info "$cat" "PERM-WW-FILES" "No world-writable regular files in scanned trees" "Scanned: ${names[*]}"
  fi

  # world-writable directories without sticky bit
  perm_scan "${dirs[@]}" -xdev -type d -perm -0002 ! -perm -1000 ! -path '*/proc/*' ! -path '*/sys/*'
  out=$PERM_SCAN_OUT
  if [[ -n "$out" ]]; then
    f_potential medium "$cat" "PERM-WW-DIRS" "World-writable directories without the sticky bit ($(perm_count "$out"))" "$(printf '%s' "$out" | tk_cap_lines 40)${PERM_SCAN_ERR:+
(scan incomplete: $PERM_SCAN_ERR)}"       "Without the sticky bit any user can delete or rename other users' files in the directory." "Inspect; 'chmod +t DIR' or 'chmod o-w DIR' where appropriate." "May break shared-directory applications." - yes
  elif [[ -n "$PERM_SCAN_ERR" ]]; then
    f_unperformed "$cat" "PERM-WW-DIRS" "World-writable directory scan" "scan incomplete or failed: $PERM_SCAN_ERR. $partial_hint"
  fi

  # SUID / SGID
  perm_scan "${dirs[@]}" -xdev -type f '(' -perm -4000 -o -perm -2000 ')'
  out=$PERM_SCAN_OUT
  if [[ -n "$out" ]]; then
    local p dang="" unk="" total=0
    while IFS= read -r p; do
      [[ -z "$p" ]] && continue
      total=$((total+1)); base=${p##*/}
      if [[ "$PERM_SUID_DANGEROUS" == *" $base "* ]]; then dang+="$p"$'
'
      elif [[ "$PERM_SUID_BASELINE" != *" $base "* ]]; then unk+="$p"$'
'; fi
    done <<<"$out"
    if [[ -n "$dang" ]]; then
      f_confirmed high "$cat" "PERM-SUID-DANGEROUS" "SUID/SGID bit set on an interpreter, editor or general utility" "$dang"         "SUID shells/editors/utilities give any user a root shell or arbitrary root file access (see GTFOBins)."         "Verify with 'ls -l FILE' and remove the bit: sudo chmod u-s,g-s FILE. Not automated because the correct set depends on the system." "None for stock systems; these binaries are never SUID by default." - yes
    fi
    if [[ -n "$unk" ]]; then
      f_potential low "$cat" "PERM-SUID-UNKNOWN" "SUID/SGID files outside the toolkit's stock-Mint baseline" "$(printf '%s' "$unk" | tk_cap_lines 40)
(The baseline list is partial; presence here is not proof of a problem.)"         "Unexpected SUID binaries are a common privilege-escalation/persistence vector." "Check each with 'dpkg -S PATH' - files owned by a package are normally legitimate." "Removing a needed SUID bit breaks that tool." - yes
    fi
    f_info "$cat" "PERM-SUID-COUNT" "SUID/SGID file count" "$total SUID/SGID files found in scanned trees.${PERM_SCAN_ERR:+
(scan incomplete: $PERM_SCAN_ERR)}"
  elif [[ -n "$PERM_SCAN_ERR" ]]; then
    f_unperformed "$cat" "PERM-SUID" "SUID/SGID scan" "scan incomplete or failed: $PERM_SCAN_ERR. $partial_hint"
  fi

  # unowned
  perm_scan "${dirs[@]}" -xdev '(' -nouser -o -nogroup ')'
  out=$PERM_SCAN_OUT
  [[ -n "$out" ]] && f_potential low "$cat" "PERM-UNOWNED" "Files with no valid owner or group" "$(printf '%s' "$out" | tk_cap_lines 40)"     "Files owned by a deleted account can be inherited by a future account with the same UID." "Review; reassign or remove after checking." "" - yes

  # media files in homes (informational: policy depends on README)
  if [[ -d "$(tkp /home)" ]]; then
    perm_scan "$(tkp /home)" -xdev -type f '(' -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.avi' -o -iname '*.mkv' -o -iname '*.mov' -o -iname '*.flac' -o -iname '*.ogg' -o -iname '*.wav' ')'
    out=$PERM_SCAN_OUT
    [[ -n "$out" ]] && f_info "$cat" "PERM-MEDIA" "Media files under /home" "$(printf '%s' "$out" | tk_cap_lines 30)
(Whether these are allowed depends on the competition README; the toolkit takes no position.)"
  fi
  return 0
}

perm_audit_legacy_trust() {
  local cat=$1 f
  if [[ -e "$(tkp /etc/hosts.equiv)" ]]; then
    f_potential medium "$cat" "PERM-HOSTSEQUIV" "/etc/hosts.equiv exists" "/etc/hosts.equiv present" "Legacy r-command trust file; rarely legitimate today." "Review and remove if unused." "" - yes
  fi
  local n
  [[ -n "${U_ORDER[*]:-}" ]] || users_load || return 0
  for n in "${U_ORDER[@]}"; do
    local home=${U_HOME[$n]:-}
    [[ -z "$home" ]] && continue
    for f in .rhosts .shosts; do
      [[ -e "$(tkp "$home/$f")" ]] && f_potential medium "$cat" "PERM-RHOSTS-$n" "$home/$f exists" "$home/$f present (contents not shown)" "Legacy trust file allowing password-less remote login." "Review and remove if unused." "" - yes
    done
    [[ -e "$(tkp "$home/.netrc")" ]] && f_potential low "$cat" "PERM-NETRC-$n" "$home/.netrc exists" "$home/.netrc present (contents not shown; may hold plaintext credentials)" "Plaintext credential store." "Review; remove if not needed." "" - yes
  done
  return 0
}

# Home directories readable by other users (0750 or stricter is the usual recommendation).
perm_audit_homes() {
  local cat=$1 n
  [[ -n "${U_ORDER[*]:-}" ]] || users_load || return 0
  for n in "${U_ORDER[@]}"; do
    users_is_human "$n" || continue
    local home=${U_HOME[$n]:-} real meta mode own grp
    [[ -z "$home" ]] && continue
    real=$(tkp "$home"); [[ -d "$real" ]] || continue
    meta=$(tk_meta "$real") || { f_unperformed "$cat" "PERM-HOME-$n" "Permissions of $home" "stat failed: $TK_ERR"; continue; }
    read -r mode own grp <<<"$meta"
    if (( (8#$mode & 8#007) != 0 )); then
      f_potential low "$cat" "PERM-HOME-$n" "Home directory of '$n' is accessible to other users (mode $mode)" "$home mode=$mode owner=$own" \
        "Other users can read (or enter) this home directory. Common guidance is 0750 or 0700; Mint's default may be more open." \
        "chmod 750 $home (only this directory, not recursive) once you are sure no service needs access." "Web servers or shared setups that read home files may break." - yes
    fi
  done
  return 0
}
