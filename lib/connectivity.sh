#!/usr/bin/env bash
# connectivity.sh - internet / DNS / proxy / outbound-firewall state.  Read-only.
#
# Scoring software is never located, read, stopped or contacted.  The scoring engine reports its own
# connection status in the Scoring Report; what is measured here is only a proxy for it.
# Active probes (one DNS lookup, one ping) can be switched off with --no-network-probe.  The optional
# --scoring-host HOST[:PORT] is a host the USER got from the official documentation: it gets one DNS
# lookup and one HTTPS HEAD request, nothing else.

TK_NETWORK_PROBE="${TK_NETWORK_PROBE:-1}"
TK_SCORING_HOST="${TK_SCORING_HOST:-}"
TK_PROBE_IP="${TK_PROBE_IP:-1.1.1.1}"
TK_PROBE_NAME="${TK_PROBE_NAME:-example.com}"
CONN_STATE=unknown; CONN_DETAIL=""

conn_valid_host() { [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$ ]]; }

# conn_probe_internet : sets CONN_STATE = up | partial | down | unknown and CONN_DETAIL
#   up = ping to a public IP worked; partial = DNS works but ping does not (ICMP may be filtered);
#   down = nothing works; unknown = could not be tested
conn_probe_internet() {
  CONN_STATE=unknown; CONN_DETAIL=""
  if [[ "$TK_NETWORK_PROBE" == 0 ]]; then CONN_DETAIL="active probes disabled (--no-network-probe)"; return 0; fi
  local dns=na ip=na
  if tk_cmd getent hosts "$TK_PROBE_NAME"; then [[ -n "$TK_OUT" ]] && dns=ok || dns=fail
  elif [[ $TK_RC -eq 126 || $TK_RC -eq 127 ]]; then dns=na; else dns=fail; fi
  if tk_cmd ping -c 1 -W 3 "$TK_PROBE_IP"; then ip=ok
  elif [[ $TK_RC -eq 126 || $TK_RC -eq 127 ]]; then ip=na; else ip=fail; fi
  CONN_DETAIL="DNS lookup of $TK_PROBE_NAME: $dns; ping $TK_PROBE_IP: $ip"
  if   [[ $ip == ok ]]; then CONN_STATE=up
  elif [[ $dns == ok ]]; then CONN_STATE=partial
  elif [[ $dns == fail || $ip == fail ]]; then CONN_STATE=down
  fi
  return 0
}

conn_redact_urls() { sed -E 's#(://)[^/@[:space:]]+@#\1[REDACTED]@#g'; }

audit_connectivity() {
  local cat="Connectivity"

  # --- default route
  if tk_cmd ip route show default; then
    if [[ -n "$TK_OUT" ]]; then
      f_info "$cat" "CONN-ROUTE" "Default route present" "$TK_OUT"
    else
      f_potential medium "$cat" "CONN-NOROUTE" "No default route: this machine has no path to the internet" "'ip route show default' printed nothing." \
        "Without a default route nothing outside the local network is reachable, which also stops score reporting and updates if the image is meant to be online. A practice VM that is deliberately offline is fine." \
        "Check the network connection in the Mint network settings or the hypervisor. This toolkit never changes network settings." \
        "" - yes
    fi
  else
    f_unperformed "$cat" "CONN-ROUTE" "Default route" "${TK_ERR:-'ip route' failed}"
  fi

  # --- resolver
  local rc; rc=$(tkp /etc/resolv.conf)
  if [[ -r "$rc" ]]; then
    local ns; ns=$(awk '$1=="nameserver"{print $2}' "$rc" | tr '\n' ' ')
    if [[ -n "${ns// /}" ]]; then
      f_info "$cat" "CONN-DNS" "DNS resolvers configured" "nameserver(s): $ns"
    else
      f_potential medium "$cat" "CONN-NODNS" "No DNS resolver is configured" "/etc/resolv.conf has no nameserver line." \
        "Without name resolution, host names (update servers, the scoring server) cannot be reached even if the network is up." \
        "Check the network settings; on Mint /etc/resolv.conf normally points at the local stub resolver (127.0.0.53)." "" - yes
    fi
  else
    f_unperformed "$cat" "CONN-DNS" "DNS resolver configuration" "/etc/resolv.conf is not readable"
  fi

  # --- proxy settings (only reported: a proxy changes what is reachable)
  local px="" f v
  for v in http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY; do
    [[ -n "${!v:-}" ]] && px+="environment $v=${!v}"$'\n'
  done
  for f in "$(tkp /etc/environment)" "$(tkp /etc/apt/apt.conf)" "$(tkp /etc/apt/apt.conf.d)"/*; do
    [[ -f "$f" && -r "$f" ]] || continue
    local hit; hit=$(grep -Ei '^[[:space:]]*[^#/[:space:]].*proxy' "$f" | head -n3) || true
    [[ -n "$hit" ]] && px+="$(tk_unroot "$f"): $hit"$'\n'
  done
  [[ -n "$px" ]] && f_info "$cat" "CONN-PROXY" "A proxy is configured (it affects what is reachable)" "$(printf '%s' "$px" | conn_redact_urls)"

  # --- outbound firewall policy (a firewall that blocks outgoing traffic also blocks updates and score reporting)
  if tk_cmd ufw status verbose && [[ "$TK_OUT" == *"Status: active"* ]]; then
    local def; def=$(printf '%s\n' "$TK_OUT" | grep -E '^Default:' | head -n1) || true
    if [[ "$def" =~ (deny|reject)\ \(outgoing\) ]]; then
      f_potential medium "$cat" "CONN-UFW-OUTBOUND" "UFW blocks outgoing traffic by default" "$def" \
        "Outgoing connections without an allow rule are blocked: package updates, DNS and score reporting to a remote server can fail." \
        "Unless the README demands it, run 'sudo ufw default allow outgoing'." "Outgoing connections without an allow rule keep working again; restrictive-outbound scenarios would lose that restriction." - yes
    fi
  fi
  if tk_is_root && tk_cmd iptables -S && [[ "$TK_OUT" =~ -P\ OUTPUT\ (DROP|REJECT) ]]; then
    f_potential medium "$cat" "CONN-IPT-OUTBOUND" "iptables default policy for OUTPUT is DROP/REJECT" "$(printf '%s\n' "$TK_OUT" | grep -E '^-P OUTPUT')" \
      "All outgoing traffic without an explicit ACCEPT rule is blocked, including updates and score reporting." \
      "Review the OUTPUT chain ('sudo iptables -S') against the README before changing it." "Changing a deliberate outbound restriction." - yes
  fi

  # --- active probes
  conn_probe_internet
  case "$CONN_STATE" in
    up)      f_info "$cat" "CONN-INTERNET" "Internet reachable" "$CONN_DETAIL";;
    partial) f_potential low "$cat" "CONN-INTERNET-PARTIAL" "DNS works but ping to a public address failed" "$CONN_DETAIL" \
               "ICMP is often filtered, so this may be fine. If other things (updates, the Scoring Report's connection status) also fail, the machine may be offline." \
               "Check the connection status shown by the Scoring Report itself; try opening a web page." "" - yes;;
    down)    f_potential medium "$cat" "CONN-INTERNET-DOWN" "No internet connectivity detected" "$CONN_DETAIL" \
               "If the image is meant to be online, scores may not be reported and updates cannot be fetched. A deliberately offline practice VM is fine." \
               "Check the network adapter, the route, DNS and any firewall. The toolkit never changes network settings." "" - yes;;
    *)       f_info "$cat" "CONN-INTERNET" "Internet reachability not tested" "${CONN_DETAIL:-the probe commands (getent/ping) are unavailable or were blocked}";;
  esac

  # --- host the user named (e.g. from the official competition documentation)
  if [[ -n "$TK_SCORING_HOST" ]]; then
    if ! conn_valid_host "$TK_SCORING_HOST"; then
      f_unperformed "$cat" "CONN-SCOREHOST" "Reachability of $TK_SCORING_HOST" "the host name is not valid"
    elif [[ "$TK_NETWORK_PROBE" == 0 ]]; then
      f_unperformed "$cat" "CONN-SCOREHOST" "Reachability of $TK_SCORING_HOST" "active probes are disabled (--no-network-probe)"
    else
      local h=${TK_SCORING_HOST%%:*} dnsok=0 httpsok=0
      tk_cmd getent hosts "$h" && [[ -n "$TK_OUT" ]] && dnsok=1
      tk_cmd curl --head --silent --show-error --output /dev/null --max-time 5 "https://$TK_SCORING_HOST/" && httpsok=1
      if [[ $httpsok -eq 1 ]]; then
        f_info "$cat" "CONN-SCOREHOST" "$TK_SCORING_HOST answers over HTTPS" "DNS: $([[ $dnsok -eq 1 ]] && echo ok || echo fail); HTTPS HEAD: ok"
      else
        f_potential medium "$cat" "CONN-SCOREHOST-DOWN" "$TK_SCORING_HOST is not reachable over HTTPS from this machine" \
          "DNS: $([[ $dnsok -eq 1 ]] && echo ok || echo fail); HTTPS HEAD: failed (${TK_ERR:-no detail})" \
          "This is reachability only, not the scoring status. If the Scoring Report also reports a connection problem, check DNS, the route, proxy settings and outbound firewall rules." \
          "Check the connection status shown by the Scoring Report itself." "" - yes
      fi
    fi
  fi

  f_info "$cat" "CONN-SCORING-NOTE" "Scoring-engine connection status must be read from the scoring software itself" \
    "The toolkit does not locate, read, modify, stop or contact the competition scoring software. Use the connection status shown in the Scoring Report; the checks above only show whether this machine can reach the internet."
  return 0
}
