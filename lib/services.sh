#!/usr/bin/env bash
# services.sh - running/enabled systemd services.  Read-only.
# Only services in the table below are flagged, and only as "potential": a
# service is never recommended for removal just because it is unfamiliar.

# unit|severity|why-it-may-matter|usually-required-for
SVC_TABLE='
telnet|high|Clear-text remote login.|nothing modern
telnetd|high|Clear-text remote login.|nothing modern
inetd|medium|Super-server that launches legacy network services.|legacy services
xinetd|medium|Super-server that launches legacy network services.|legacy services
openbsd-inetd|medium|Super-server that launches legacy network services.|legacy services
rsh|high|Obsolete trust-based remote shell.|nothing modern
rexec|high|Obsolete remote execution.|nothing modern
vsftpd|high|FTP server (clear text by default).|file transfer role
proftpd|high|FTP server (clear text by default).|file transfer role
pure-ftpd|high|FTP server (clear text by default).|file transfer role
tftpd-hpa|high|TFTP has no authentication.|network boot role
ypserv|high|NIS server, legacy and weakly authenticated.|NIS domains
nfs-server|medium|NFS file server.|file sharing role
nfs-kernel-server|medium|NFS file server.|file sharing role
rpcbind|medium|RPC portmapper, needed only for NFS/NIS.|NFS/NIS
smbd|medium|Samba file server.|Windows file sharing role
nmbd|medium|Samba NetBIOS name service.|Windows file sharing role
snmpd|medium|SNMP agent, often with default community strings.|monitoring
apache2|medium|Web server.|web hosting role
nginx|medium|Web server.|web hosting role
lighttpd|medium|Web server.|web hosting role
mysql|medium|Database server.|an application that needs it
mariadb|medium|Database server.|an application that needs it
postgresql|medium|Database server.|an application that needs it
bind9|medium|DNS server.|DNS role
named|medium|DNS server.|DNS role
dovecot|medium|IMAP/POP3 server.|mail role
postfix|medium|Mail server.|mail role (local delivery only is common)
exim4|medium|Mail server.|mail role
sendmail|medium|Mail server.|mail role
xrdp|medium|Remote Desktop server.|remote desktop role
x11vnc|medium|VNC remote desktop server.|remote desktop role
vncserver|medium|VNC remote desktop server.|remote desktop role
vino-server|medium|GNOME screen sharing.|remote desktop role
isc-dhcp-server|medium|DHCP server.|network infrastructure role
slapd|medium|LDAP directory server.|directory role
squid|medium|Proxy server.|proxy role
openvpn|low|VPN service.|VPN role
docker|medium|Container runtime (docker group is root-equivalent).|container workloads
cockpit|medium|Web management console.|server administration
webmin|medium|Web management console.|server administration
minidlna|low|Media sharing server.|media sharing
transmission-daemon|medium|BitTorrent daemon (unusual on a workstation).|torrents
avahi-daemon|low|mDNS/service discovery; stock on Mint.|printer/device discovery
cups|low|Print service; stock on Mint.|printing
cups-browsed|low|Printer auto-discovery; stock on Mint.|printing
bluetooth|low|Bluetooth stack; stock on Mint.|Bluetooth devices
anydesk|medium|Remote-control software.|remote support
teamviewerd|medium|Remote-control software.|remote support
'

declare -A SVC_SEV SVC_WHY SVC_REQ
svc_load_table() {
  local u sev why req
  while IFS='|' read -r u sev why req; do
    [[ -z "$u" ]] && continue
    SVC_SEV[$u]=$sev; SVC_WHY[$u]=$why; SVC_REQ[$u]=$req
  done <<<"$SVC_TABLE"
}

audit_services() {
  local cat="Services"
  svc_load_table
  if ! tk_have systemctl; then
    f_unperformed "$cat" "SVC-LIST" "Service inventory" "systemctl not available (not a systemd system, or PATH problem)"
    return 0
  fi

  local running="" enabled=""
  if tk_cmd systemctl list-units --type=service --state=running --no-legend --plain --no-pager; then
    running=$(printf '%s\n' "$TK_OUT" | awk 'NF{print $1}')
  else
    f_unperformed "$cat" "SVC-RUNNING" "Running services" "systemctl list-units failed (rc=$TK_RC): $TK_ERR"
  fi
  if tk_cmd systemctl list-unit-files --type=service --state=enabled --no-legend --plain --no-pager; then
    enabled=$(printf '%s\n' "$TK_OUT" | awk 'NF{print $1}')
  else
    f_unperformed "$cat" "SVC-ENABLED" "Enabled services" "systemctl list-unit-files failed (rc=$TK_RC): $TK_ERR"
  fi

  local nrun nen
  nrun=$(printf '%s\n' "$running" | grep -c . || true); nen=$(printf '%s\n' "$enabled" | grep -c . || true)
  f_info "$cat" "SVC-INVENTORY" "Service inventory" "$nrun running, $nen enabled service units.
Running:
$(printf '%s\n' "$running" | sed 's/\.service$//' | tr '\n' ' ' | fold -s -w 100)"

  # flagged services: union of running and enabled
  local u base state seen=" "
  while IFS= read -r u; do
    [[ -z "$u" ]] && continue
    base=${u%.service}
    [[ -n "${SVC_SEV[$base]:-}" ]] || continue
    [[ "$seen" == *" $base "* ]] && continue
    seen+="$base "
    state=""
    printf '%s\n' "$running" | grep -qx "$u" && state+="running"
    if printf '%s\n' "$enabled" | grep -qx "$u"; then state+="${state:+ and }enabled"; fi
    if tk_in_list "$base" "$TK_REQ_SERVICES"; then
      f_info "$cat" "SVC-$base" "Service '$base' is $state (required per your profile - not an issue)" "$u: $state. Listed in --required-services; keep it and harden its configuration instead (see the Applications checks)."
      continue
    fi
    f_potential "${SVC_SEV[$base]}" "$cat" "SVC-$base" "Service '$base' is $state" "$u: $state" \
      "${SVC_WHY[$base]} It is usually required for: ${SVC_REQ[$base]}." \
      "Check whether the README requires it. If not: 'sudo systemctl disable --now $base' (and consider removing the package). If unsure, investigate first - do not disable blindly." \
      "Stopping it disables ${SVC_REQ[$base]}." - yes
  done < <(printf '%s\n%s\n' "$running" "$enabled")

  # failed units (informational)
  if tk_cmd systemctl list-units --state=failed --no-legend --plain --no-pager; then
    [[ -n "$TK_OUT" ]] && f_info "$cat" "SVC-FAILED" "Failed service units" "$TK_OUT"
  fi

  svc_audit_apparmor "$cat"
  return 0
}

svc_audit_apparmor() {
  local cat=$1
  if tk_cmd systemctl is-active apparmor; then
    f_info "$cat" "SVC-APPARMOR" "AppArmor service is active" "systemctl is-active apparmor -> $TK_OUT"
  elif [[ $TK_RC -ne 127 ]]; then
    f_potential medium "$cat" "SVC-APPARMOR" "AppArmor does not report active" "systemctl is-active apparmor -> ${TK_OUT:-$TK_ERR}" \
      "AppArmor confines services; it is on by default on Mint." "Investigate: 'sudo systemctl enable --now apparmor' only if the package is installed and the kernel supports it." \
      "Enforcing profiles can block misconfigured services." - yes
  fi
  return 0
}
