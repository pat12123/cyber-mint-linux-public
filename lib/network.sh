#!/usr/bin/env bash
# network.sh - listening sockets, kernel network parameters, interface flags.  Read-only.

# Normalised listener table: "proto|address|port|process"
NET_LISTENERS=""

net_collect_listeners() {
  NET_LISTENERS=""
  if tk_cmd ss -H -tulnp; then
    NET_LISTENERS=$(printf '%s\n' "$TK_OUT" | awk '
      NF>=5 {
        proto=$1; local=$5; proc="";
        if (match($0, /users:\(\("[^"]+"/)) { proc=substr($0, RSTART+9, RLENGTH-10) }
        port=local; sub(/.*:/,"",port); addr=local; sub(/:[^:]*$/,"",addr); sub(/%[A-Za-z0-9_.-]+$/,"",addr)
        gsub(/^\[|\]$/,"",addr)
        printf "%s|%s|%s|%s\n", proto, addr, port, proc
      }')
    return 0
  elif [[ $TK_RC -ne 127 ]]; then
    NET_ERR="ss failed (rc=$TK_RC): $TK_ERR"; return 1
  fi
  if tk_cmd netstat -tulnp; then
    NET_LISTENERS=$(printf '%s\n' "$TK_OUT" | awk '
      $1 ~ /^(tcp|udp)/ {
        local=$4; port=local; sub(/.*:/,"",port); addr=local; sub(/:[^:]*$/,"",addr)
        proc=$NF; if (proc ~ /^[0-9]+\//) { sub(/^[0-9]+\//,"",proc) } else proc=""
        printf "%s|%s|%s|%s\n", $1, addr, port, proc
      }')
    return 0
  fi
  NET_ERR="neither ss nor netstat is available"
  return 1
}

net_is_loopback() { case "$1" in 127.*|::1|localhost) return 0;; esac; return 1; }
net_is_wildcard() { case "$1" in 0.0.0.0|'*'|::|'') return 0;; esac; return 1; }

# port -> "label|severity|note"   (only for externally reachable listeners)
net_port_info() { # proto port
  local p=$2
  case "$p" in
    23)   echo "telnet|high|Telnet sends passwords in clear text.";;
    21)   echo "ftp|high|FTP sends credentials in clear text.";;
    69)   echo "tftp|high|TFTP has no authentication.";;
    512|513|514) echo "r-services|high|rsh/rlogin/rexec are obsolete and trust-based.";;
    111)  echo "rpcbind|medium|RPC portmapper, only needed with NFS/NIS.";;
    2049) echo "nfs|medium|NFS file sharing.";;
    139|445) echo "samba|medium|Windows file sharing (SMB).";;
    3389) echo "rdp|medium|Remote Desktop (xrdp).";;
    5900|5901|5902|5903) echo "vnc|medium|VNC remote desktop.";;
    6000|6001) echo "x11-tcp|medium|X11 over TCP is rarely intended.";;
    25|465|587) echo "smtp|medium|Mail server.";;
    110|143|993|995) echo "mail-retrieval|medium|POP3/IMAP server.";;
    3306) echo "mysql|medium|Database exposed beyond loopback.";;
    5432) echo "postgresql|medium|Database exposed beyond loopback.";;
    80|443|8080|8000|8443) echo "web|medium|Web server.";;
    53)   echo "dns|medium|DNS server listening on a non-loopback address.";;
    161)  echo "snmp|medium|SNMP service.";;
    631)  echo "cups|low|CUPS print service; needed only for printing/sharing.";;
    5353) echo "mdns|low|Avahi/mDNS service discovery.";;
    *) return 1;;
  esac
}

net_read_proc() { # relative path under /proc/sys
  local f; f=$(tkp "/proc/sys/$1")
  [[ -r "$f" ]] || return 1
  tr -d '[:space:]' <"$f"
}

audit_network() {
  local cat="Network exposure"
  if ! net_collect_listeners; then
    f_unperformed "$cat" "NET-LISTEN" "Listening ports" "${NET_ERR:-could not list sockets}"
  else
    local ev="PROTO  ADDRESS                PORT   PROCESS"$'\n' line proto addr port proc exposed=0
    local remote_ev="" ; local -A seen_port=()
    while IFS='|' read -r proto addr port proc; do
      [[ -z "$proto" ]] && continue
      local pkg=""
      if ! net_is_loopback "$addr" && [[ -n "$proc" ]]; then pkg=$(net_pkg_of "$proc"); fi
      ev+=$(printf '%-6s %-22s %-6s %s%s' "$proto" "$addr" "$port" "${proc:-<unknown>}" "${pkg:+  [package: $pkg]}")$'\n'
      net_is_loopback "$addr" && continue
      exposed=$((exposed+1))
      [[ -n "${seen_port[$proto-$port]:-}" ]] && continue      # same port on IPv4 and IPv6: one finding is enough (both lines stay in the listing)
      seen_port[$proto-$port]=1
      local info; info=$(net_port_info "$proto" "$port") || info=""
      if [[ -n "$info" ]] && { tk_in_list "$port/$proto" "$TK_ALLOW_PORTS" || tk_in_list "$port/${proto:0:3}" "$TK_ALLOW_PORTS"; }; then
        f_info "$cat" "NET-PORT-$proto-$port" "Port $port/$proto is reachable beyond loopback (allowed by your profile)" "$proto $addr:$port process=${proc:-<unknown>}${pkg:+ package=$pkg}"
        info=""
      fi
      if [[ -n "$info" ]]; then
        local label sev note
        IFS='|' read -r label sev note <<<"$info"
        f_potential "$sev" "$cat" "NET-PORT-$proto-$port" "Port $port/$proto ($label) is reachable beyond loopback" \
          "$proto $addr:$port process=${proc:-<unknown>}${pkg:+ package=$pkg}" \
          "$note A reachable listener is an attack surface; it is only a problem if the service is not required." \
          "Identify the service (${proc:-use 'sudo ss -tulnp'}), check the README, then stop/disable the service that owns it. Do not just block the port if the service is required." \
          "Stopping the owning service stops that functionality." - yes
      fi
      case "$port" in 22|2222) remote_ev+="$proto $addr:$port process=${proc:-<unknown>}"$'\n';; esac
    done <<<"$NET_LISTENERS"
    f_info "$cat" "NET-LISTEN" "Listening TCP/UDP sockets" "$ev
${exposed} socket(s) are bound to non-loopback addresses.$(tk_is_root || echo $'\nNon-root run: process names may be missing; use sudo for full detail.')"
    [[ -n "$remote_ev" ]] && f_info "$cat" "NET-REMOTE-PORTS" "Remote-access ports listening" "$remote_ev"
  fi

  net_audit_sysctl "$cat"
  net_audit_interfaces "$cat"
  net_audit_hosts "$cat"
  return 0
}

net_audit_sysctl() {
  local cat=$1 v
  v=$(net_read_proc kernel/randomize_va_space) || v=""
  if [[ -z "$v" ]]; then f_unperformed "$cat" "NET-ASLR" "ASLR setting" "/proc/sys/kernel/randomize_va_space not readable"
  elif [[ "$v" != 2 ]]; then
    f_confirmed medium "$cat" "NET-ASLR" "Address-space layout randomisation is not fully enabled" "kernel.randomize_va_space=$v (expected 2)" \
      "ASLR makes memory-corruption exploits harder." "Set kernel.randomize_va_space=2." "None expected." - no
  fi
  local k
  v=$(net_read_proc net/ipv4/tcp_syncookies) || v=""
  [[ "$v" == 0 ]] && f_potential low "$cat" "NET-SYNCOOKIES" "TCP SYN cookies are disabled" "net.ipv4.tcp_syncookies=0" "SYN cookies mitigate SYN-flood denial of service." "Set net.ipv4.tcp_syncookies=1 (see docs/manual-fixes.md)." "None expected." - no
  v=$(net_read_proc net/ipv4/ip_forward) || v=""
  [[ "$v" == 1 ]] && f_potential low "$cat" "NET-IPFORWARD" "IPv4 forwarding is enabled" "net.ipv4.ip_forward=1" "A host that forwards packets acts as a router; unexpected on a workstation." \
    "Disable only if this machine is not meant to route (VPN/containers/VMs may need it); not automated." "Breaks routing, Docker/libvirt NAT networking." - yes
  for k in accept_redirects send_redirects accept_source_route; do
    v=$(net_read_proc "net/ipv4/conf/all/$k") || continue
    if [[ "$v" == 1 ]]; then
      f_potential low "$cat" "NET-$k" "net.ipv4.conf.all.$k is enabled" "net.ipv4.conf.all.$k=1" \
        "A hardening recommendation: redirects/source routes can be abused to alter routing. Stock defaults vary by release." \
        "Set to 0 (see docs/manual-fixes.md)." "None expected on a workstation." - no
    fi
  done
  return 0
}

net_audit_interfaces() {
  local cat=$1
  if tk_cmd ip -o link show; then
    local promisc; promisc=$(printf '%s\n' "$TK_OUT" | grep -E '<[^>]*PROMISC' || true)
    if [[ -n "$promisc" ]]; then
      f_potential medium "$cat" "NET-PROMISC" "A network interface is in promiscuous mode" "$promisc" \
        "Promiscuous mode lets a host capture all traffic on its segment (sniffing). It is also used by bridges, VMs and capture tools." \
        "Find the process responsible (e.g. a sniffer such as tcpdump/wireshark) and decide whether it is authorised." "" - yes
    fi
  elif [[ $TK_RC -eq 127 ]]; then
    f_unperformed "$cat" "NET-PROMISC" "Interface promiscuous-mode check" "'ip' command not available"
  else
    f_unperformed "$cat" "NET-PROMISC" "Interface promiscuous-mode check" "ip failed: $TK_ERR"
  fi
  return 0
}

# Which package owns the program behind a listening socket?  (process name -> path -> dpkg -S)
declare -A NET_PKG_CACHE
net_pkg_of() { # process-name
  local p=$1 d path
  [[ -n "${NET_PKG_CACHE[$p]+x}" ]] && { printf '%s' "${NET_PKG_CACHE[$p]}"; return 0; }
  NET_PKG_CACHE[$p]=""
  tk_have dpkg || return 0
  for d in /usr/sbin /usr/bin /sbin /bin /usr/lib/openssh /usr/libexec; do
    [[ -e "$(tkp "$d/$p")" ]] || continue
    if tk_cmd dpkg -S "$d/$p" && [[ -n "$TK_OUT" ]]; then
      NET_PKG_CACHE[$p]=$(printf '%s\n' "$TK_OUT" | head -n1 | cut -d: -f1 | cut -d, -f1)
      break
    fi
  done
  printf '%s' "${NET_PKG_CACHE[$p]}"
}

# /etc/hosts: stock content is localhost + this machine's name. Anything else is worth a look,
# and entries that redirect update/security/vendor sites are a classic planted weakness.
net_audit_hosts() {
  local cat=$1 hf; hf=$(tkp /etc/hosts)
  tk_readable "$hf" || return 0
  local host; host=$(head -n1 "$(tkp /etc/hostname)" 2>/dev/null || true); host=${host:-${DET_HOSTNAME:-}}
  local line ip names n custom="" redirect=""
  while IFS= read -r line; do
    line=${line%%#*}; [[ "$line" =~ ^[[:space:]]*$ ]] && continue
    read -r ip names <<<"$line"
    local keep=0
    for n in $names; do
      case "$n" in localhost|localhost.localdomain|ip6-localhost|ip6-loopback|ip6-localnet|ip6-mcastprefix|ip6-allnodes|ip6-allrouters|ip6-allhosts) ;; *)
        [[ -n "$host" && "$n" == "$host" ]] && continue
        keep=1
        if [[ "$n" =~ (ubuntu|linuxmint|mint|debian|google|microsoft|windows|update|security|download|mirror|github|kernel\.org) ]]; then redirect+="$ip $n"$'\n'; fi;;
      esac
    done
    [[ $keep -eq 1 ]] && custom+="$ip $names"$'\n'
  done <"$hf"
  if [[ -n "$redirect" ]]; then
    f_potential medium "$cat" "NET-HOSTS-REDIRECT" "/etc/hosts maps update/security/vendor-looking names" "$redirect" \
      "Pointing update or security hostnames at another address can block updates or redirect downloads." "Remove entries that are not intended." "Removing a deliberate local override changes name resolution." - yes
  elif [[ -n "$custom" ]]; then
    f_potential low "$cat" "NET-HOSTS-CUSTOM" "/etc/hosts has entries beyond localhost and this host" "$custom" "Custom host entries override DNS." "Check each is intentional (README)." "" - yes
  fi
  return 0
}
