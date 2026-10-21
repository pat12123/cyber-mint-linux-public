#!/usr/bin/env bash
# updates.sh - packages, pending updates, apt configuration.  Read-only.
# The toolkit NEVER runs 'apt update' or installs/removes anything itself:
# pending updates are computed from a simulation ('apt-get -s upgrade') against
# the package lists already on disk, which may be stale.

UPD_TOOL_PACKAGES=' john john-data hydra hydra-gtk nmap zenmap ncat netcat-traditional wireshark wireshark-qt tshark aircrack-ng hashcat nikto ophcrack medusa sqlmap kismet ettercap-text-only ettercap-graphical dsniff hping3 masscan metasploit-framework crunch wifite reaver fcrackzip netdiscover sslstrip '

audit_updates() {
  local cat="Software and updates"
  if ! tk_have dpkg && ! tk_have dpkg-query; then
    f_unperformed "$cat" "UPD-PKGMGR" "Package checks" "dpkg is not available; this does not look like a Debian-family system."
    return 0
  fi

  # --- installed packages
  local pkgs=""
  if tk_cmd dpkg-query -W -f='${Package}\n'; then
    pkgs=$TK_OUT
    f_info "$cat" "UPD-PKGCOUNT" "Installed package count" "$(printf '%s\n' "$pkgs" | grep -c . || true) packages installed (dpkg-query)."
  else
    f_unperformed "$cat" "UPD-PKGLIST" "Installed package list" "dpkg-query failed (rc=$TK_RC): ${TK_ERR:-not available}"
  fi

  # --- broken packages
  if tk_cmd dpkg --audit; then
    [[ -n "$TK_OUT" ]] && f_potential medium "$cat" "UPD-DPKG-BROKEN" "dpkg reports partially installed or broken packages" "$TK_OUT" \
      "Half-configured packages may leave services in an undefined state." "Run 'sudo dpkg --configure -a' then 'sudo apt -f install' (changes the system; manual)." "Package configuration scripts run." - yes
  else
    f_unperformed "$cat" "UPD-DPKG-AUDIT" "dpkg --audit" "failed (rc=$TK_RC): $TK_ERR"
  fi

  # --- pending updates (simulation only)
  if tk_cmd apt-get -s -o Debug::NoLocking=true upgrade; then
    local inst sec nsec ntot
    inst=$(printf '%s\n' "$TK_OUT" | grep -E '^Inst ' || true)
    ntot=$(printf '%s' "$inst" | grep -c . || true)
    sec=$(printf '%s\n' "$inst" | grep -iE 'security' || true)
    nsec=$(printf '%s' "$sec" | grep -c . || true)
    if [[ "$nsec" -gt 0 ]]; then
      f_potential medium "$cat" "UPD-SECURITY" "$nsec security update(s) pending" "$(printf '%s\n' "$sec" | cut -c1-110 | tk_cap_lines 25)" \
        "Unpatched packages carry publicly known vulnerabilities. Whether updating is expected/allowed during the competition depends on the README." \
        "Apply with the Update Manager or 'sudo apt update && sudo apt upgrade' if the README permits. Not automated by this toolkit." \
        "Upgrades can restart services and change configuration defaults; may need a reboot." - yes
    fi
    if [[ "$ntot" -gt 0 ]]; then
      f_info "$cat" "UPD-PENDING" "$ntot upgradable package(s) according to the local package lists" "($nsec of them from security pockets)
$(printf '%s\n' "$inst" | cut -c1-110 | tk_cap_lines 15)
Note: package lists on disk may be out of date; the toolkit does not run 'apt update'."
    else
      f_info "$cat" "UPD-PENDING" "No upgradable packages according to the local package lists" "Package lists may be stale; run 'sudo apt update' (modifies apt lists) to refresh before trusting this."
    fi
  elif [[ $TK_RC -eq 127 ]]; then
    f_unperformed "$cat" "UPD-PENDING" "Pending updates" "apt-get not available"
  else
    f_unperformed "$cat" "UPD-PENDING" "Pending updates" "apt-get simulation failed (rc=$TK_RC): ${TK_ERR%%$'\n'*}"
  fi

  upd_audit_apt_config "$cat"

  # --- reboot required
  [[ -e "$(tkp /var/run/reboot-required)" || -e "$(tkp /run/reboot-required)" ]] && \
    f_info "$cat" "UPD-REBOOT" "A reboot is required to finish applying updates" "reboot-required flag present."

  # --- hacking / network-attack tooling installed
  if [[ -n "$pkgs" ]]; then
    local p hits=""
    while IFS= read -r p; do
      [[ "$UPD_TOOL_PACKAGES" == *" $p "* ]] && hits+="$p "
    done <<<"$pkgs"
    if [[ -n "$hits" ]]; then
      f_potential low "$cat" "UPD-TOOLS" "Network-attack / password-cracking tools installed: ${hits% }" "Packages: ${hits% }" \
        "Such tools are dual-use. Many competition READMEs prohibit them; some images legitimately include them for a task." \
        "Check the README before removal. Removal is NOT done by this toolkit; if confirmed unauthorised use 'sudo apt remove PKG'." \
        "Removing a package other software depends on can cascade; review apt's removal list first." - yes
    fi
  fi
  return 0
}

upd_audit_apt_config() {
  local cat=$1 f hits="" files=()
  local d; d=$(tkp /etc/apt/apt.conf.d)
  [[ -f "$(tkp /etc/apt/apt.conf)" ]] && files+=("$(tkp /etc/apt/apt.conf)")
  for f in "$d"/*; do [[ -f "$f" ]] && files+=("$f"); done
  for f in "${files[@]}"; do
    [[ -r "$f" ]] || continue
    local m; m=$(grep -nEi '^[[:space:]]*[^#/[:space:]].*(AllowUnauthenticated|AllowInsecureRepositories|AllowDowngradeToInsecureRepositories)[^;]*"?(true|1|yes)"?' "$f" || true)
    [[ -n "$m" ]] && hits+="$(tk_unroot "$f"): $m"$'\n'
  done
  if [[ -n "$hits" ]]; then
    f_confirmed high "$cat" "UPD-APT-INSECURE" "apt is configured to accept unauthenticated/insecure repositories" "$hits" \
      "This disables signature checks on packages, allowing tampered packages to install silently." \
      "Remove or set the option to false (comment the lines out with '//' after backing the file up; see docs/manual-fixes.md)." \
      "Repositories that really are unsigned will stop working." - no
  fi

  # sources: trusted=yes and an inventory
  local src=() s
  [[ -f "$(tkp /etc/apt/sources.list)" ]] && src+=("$(tkp /etc/apt/sources.list)")
  for s in "$(tkp /etc/apt/sources.list.d)"/*.list "$(tkp /etc/apt/sources.list.d)"/*.sources; do [[ -f "$s" ]] && src+=("$s"); done
  if [[ ${#src[@]} -eq 0 ]]; then
    f_unperformed "$cat" "UPD-SOURCES" "APT repository inspection" "no sources files found under $(tkp /etc/apt)"
  else
    local trusted="" inv="" l
    for s in "${src[@]}"; do
      [[ -r "$s" ]] || continue
      l=$(grep -nE 'trusted=yes|Trusted:[[:space:]]*yes' "$s" || true)
      [[ -n "$l" ]] && trusted+="$(tk_unroot "$s"): $l"$'\n'
      inv+="$(tk_unroot "$s"): $(grep -Ec '^(deb |URIs:)' "$s" || true) active entr(ies)"$'\n'
    done
    [[ -n "$trusted" ]] && f_confirmed high "$cat" "UPD-SOURCES-TRUSTED" "An apt repository is marked trusted=yes (signature checks bypassed)" "$trusted" \
      "Packages from this repository are not verified." "Remove 'trusted=yes' after confirming the repository has a valid signing key." "The repository may stop working until a key is installed." - yes
    f_info "$cat" "UPD-SOURCES" "APT source files" "$inv"
  fi

  # auto updates
  local au; au=$(tkp /etc/apt/apt.conf.d/20auto-upgrades)
  if tk_readable "$au"; then
    f_info "$cat" "UPD-AUTO" "Automatic update configuration (20auto-upgrades)" "$(tk_active_lines "$au")"
  else
    f_info "$cat" "UPD-AUTO" "No unattended-upgrades configuration found" "/etc/apt/apt.conf.d/20auto-upgrades missing. Linux Mint uses the Update Manager rather than unattended-upgrades by default, so this is normal."
  fi
  return 0
}
