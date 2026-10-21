#!/usr/bin/env bash
# applications.sh - configuration of common server applications.  Read-only.
# A check runs only when the application's configuration file exists; nothing is
# flagged merely because an application is installed (the README decides whether
# it is required - see --required-services).

# Value of "key = value" / "key=value" / "key value" (last active definition wins) in several files.
app_last() { # key file...
  local key=$1 f v last="" found=0; shift
  for f in "$@"; do
    [[ -r "$f" ]] || continue
    if v=$(tk_last_value "$f" "$key"); then last=$v; found=1; fi
  done
  [[ $found -eq 1 ]] || return 1
  printf '%s' "$last"
}

app_files() { # glob-prefix patterns (already rooted) -> existing regular files
  local g f
  shopt -s nullglob
  for g in "$@"; do for f in $g; do [[ -f "$f" ]] && printf '%s\n' "$f"; done; done
  shopt -u nullglob
}

audit_applications() {
  local cat="Applications"
  app_audit_vsftpd "$cat"
  app_audit_apache "$cat"
  app_audit_mysql "$cat"
  app_audit_php "$cat"
  app_audit_samba "$cat"
  app_audit_webshells "$cat"
  return 0
}

app_audit_vsftpd() {
  local cat=$1 f; f=$(tkp /etc/vsftpd.conf)
  [[ -r "$f" ]] || return 0
  local anon; anon=$(app_last anonymous_enable "$f" || true)
  if [[ "${anon^^}" == YES || "${anon^^}" == TRUE || "$anon" == 1 ]]; then
    local sev=medium; tk_in_list vsftpd "$TK_REQ_SERVICES" && sev=low
    f_confirmed "$sev" "$cat" "APP-VSFTPD-ANON" "vsftpd allows anonymous FTP login (anonymous_enable=$anon)" "/etc/vsftpd.conf: anonymous_enable=$anon" \
      "Anonymous FTP lets anyone read (and possibly write) files without an account. Even when FTP itself is required, anonymous access rarely is." \
      "Set anonymous_enable=NO and restart vsftpd - unless the README explicitly requires anonymous FTP." "Anonymous users lose access." - yes
  fi
  local w; w=$(app_last anon_upload_enable "$f" || true)
  [[ "${w^^}" == YES ]] && f_confirmed high "$cat" "APP-VSFTPD-ANONUPLOAD" "vsftpd allows anonymous uploads" "/etc/vsftpd.conf: anon_upload_enable=$w" "Anyone can place files on the server." "Set anon_upload_enable=NO." "" - yes
  local ssl; ssl=$(app_last ssl_enable "$f" || true)
  f_info "$cat" "APP-VSFTPD" "vsftpd configuration (selected)" "anonymous_enable=${anon:-<default NO>} local_enable=$(app_last local_enable "$f" || echo '<unset>') write_enable=$(app_last write_enable "$f" || echo '<unset>') ssl_enable=${ssl:-<unset>}"
}

app_audit_apache() {
  local cat=$1 f
  local -a files=()
  mapfile -t files < <(app_files "$(tkp /etc/apache2)/apache2.conf" "$(tkp /etc/apache2/conf-enabled)/*.conf" "$(tkp /etc/apache2/sites-enabled)/*.conf")
  [[ ${#files[@]} -gt 0 ]] || return 0
  local tokens sig trace
  tokens=$(app_last ServerTokens "${files[@]}" || true); sig=$(app_last ServerSignature "${files[@]}" || true); trace=$(app_last TraceEnable "${files[@]}" || true)
  if [[ -n "$tokens" && "${tokens,,}" != prod && "${tokens,,}" != productonly ]]; then
    f_potential low "$cat" "APP-APACHE-TOKENS" "Apache reveals version details (ServerTokens $tokens)" "ServerTokens $tokens" "Version banners help attackers pick exploits." "Set 'ServerTokens Prod' in conf-enabled/security.conf, then reload apache2." "None." - yes
  fi
  if [[ "${sig,,}" == on ]]; then
    f_potential low "$cat" "APP-APACHE-SIGNATURE" "Apache adds a version signature to error pages (ServerSignature On)" "ServerSignature $sig" "Information disclosure." "Set 'ServerSignature Off'." "None." - yes
  fi
  if [[ "${trace,,}" == on ]]; then
    f_potential low "$cat" "APP-APACHE-TRACE" "HTTP TRACE is enabled (TraceEnable On)" "TraceEnable $trace" "TRACE can aid cross-site tracing attacks." "Set 'TraceEnable Off'." "None." - yes
  fi
  local idx; idx=$(grep -nE '^[[:space:]]*Options[[:space:]].*\bIndexes\b' "${files[@]}" 2>/dev/null | head -n3 || true)
  [[ -n "$idx" ]] && f_potential low "$cat" "APP-APACHE-INDEXES" "Apache directory listing enabled (Options Indexes)" "$(printf '%s\n' "$idx" | sed "s|$TK_ROOT||")" "Directory listings can expose files." "Remove 'Indexes' unless the site relies on it." "Some sites use listings deliberately." - yes
}

app_audit_mysql() {
  local cat=$1
  local -a files=()
  mapfile -t files < <(app_files "$(tkp /etc/mysql)/my.cnf" "$(tkp /etc/mysql/mysql.conf.d)/*.cnf" "$(tkp /etc/mysql/conf.d)/*.cnf" "$(tkp /etc/mysql/mariadb.conf.d)/*.cnf")
  [[ ${#files[@]} -gt 0 ]] || return 0
  local bind; bind=$(app_last bind-address "${files[@]}" || true)
  case "$bind" in
    0.0.0.0|'*'|::) f_potential medium "$cat" "APP-MYSQL-BIND" "MySQL/MariaDB listens on all interfaces (bind-address=$bind)" "bind-address = $bind" \
        "A database reachable from the network is a common attack target. Required only if remote clients must connect." \
        "Set bind-address = 127.0.0.1 unless the README requires remote access, then restart the database." "Remote clients will be refused." - yes;;
  esac
  if grep -qEi '^[[:space:]]*skip-grant-tables' "${files[@]}" 2>/dev/null; then
    f_confirmed high "$cat" "APP-MYSQL-NOGRANT" "MySQL runs with skip-grant-tables (no authentication)" "skip-grant-tables present" "Anyone who can connect has full database access." "Remove the option and restart." "" - yes
  fi
  local li; li=$(app_last local-infile "${files[@]}" || true)
  [[ "$li" == 1 || "${li,,}" == on ]] && f_potential low "$cat" "APP-MYSQL-INFILE" "MySQL local-infile is enabled" "local-infile=$li" "LOCAL INFILE can be abused to read client files." "Set local-infile=0." "" - yes
  return 0
}

app_audit_php() {
  local cat=$1 f
  local -a files=()
  mapfile -t files < <(app_files "$(tkp /etc/php)"/*/apache2/php.ini "$(tkp /etc/php)"/*/fpm/php.ini "$(tkp /etc/php)"/*/cli/php.ini)
  [[ ${#files[@]} -gt 0 ]] || return 0
  for f in "${files[@]}"; do
    local rel; rel=$(tk_unroot "$f")
    local inc expose
    inc=$(grep -E '^[[:space:]]*allow_url_include[[:space:]]*=' "$f" | tail -n1 | sed -E 's/.*=[[:space:]]*//; s/[[:space:]]*;.*//' || true)
    expose=$(grep -E '^[[:space:]]*expose_php[[:space:]]*=' "$f" | tail -n1 | sed -E 's/.*=[[:space:]]*//; s/[[:space:]]*;.*//' || true)
    [[ "${inc,,}" == on || "$inc" == 1 ]] && f_confirmed medium "$cat" "APP-PHP-URLINCLUDE-$(sched_sanitize_id "$rel")" "PHP allows remote file inclusion (allow_url_include=On) in $rel" "$rel: allow_url_include = $inc" \
      "Enables remote code inclusion if any script includes user-controlled paths." "Set allow_url_include = Off and reload the web server." "Applications that include remote URLs break (rare)." - yes
    [[ "${expose,,}" == on || "$expose" == 1 ]] && f_potential low "$cat" "APP-PHP-EXPOSE-$(sched_sanitize_id "$rel")" "PHP exposes its version (expose_php=On) in $rel" "$rel: expose_php = $expose" "Information disclosure." "Set expose_php = Off." "None." - yes
  done
  return 0
}

app_audit_samba() {
  local cat=$1 f; f=$(tkp /etc/samba/smb.conf)
  [[ -r "$f" ]] || return 0
  local hits
  hits=$(grep -nEi '^[[:space:]]*(guest ok|public|usershare allow guests)[[:space:]]*=[[:space:]]*(yes|true|1)|^[[:space:]]*security[[:space:]]*=[[:space:]]*share|^[[:space:]]*map to guest[[:space:]]*=[[:space:]]*bad user' "$f" || true)
  if [[ -n "$hits" ]]; then
    f_potential medium "$cat" "APP-SAMBA-GUEST" "Samba allows guest/anonymous access" "$hits" \
      "Guest shares expose files to anyone on the network. Whether guest access is intended depends on the README." \
      "Set 'guest ok = no' / remove 'map to guest' for shares that should be private, then restart smbd." "Clients relying on guest access lose it." - yes
  fi
  local shares; shares=$(grep -E '^\[[^]]+\]' "$f" | grep -vEi '^\[(global|printers|print\$)\]' | tr '\n' ' ' || true)
  [[ -n "$shares" ]] && f_info "$cat" "APP-SAMBA-SHARES" "Samba shares defined" "$shares"
  return 0
}

# PHP web shells: file contents are only pattern-matched, never executed.
app_audit_webshells() {
  local cat=$1 r
  local -a roots=()
  for r in /var/www /srv; do [[ -d "$(tkp "$r")" ]] && roots+=("$(tkp "$r")"); done
  [[ ${#roots[@]} -gt 0 ]] || return 0
  local hits
  hits=$(grep -rIlE --include='*.php' --include='*.phtml' --include='*.php5' \
    '(eval|assert|system|passthru|shell_exec|exec|popen|proc_open)[[:space:]]*\([^;]*\$_(GET|POST|REQUEST|COOKIE)|base64_decode[[:space:]]*\([^;]*\)[^;]*eval|eval[[:space:]]*\([[:space:]]*(gzinflate|str_rot13|base64_decode)' \
    "${roots[@]}" 2>/dev/null | sed "s|^$TK_ROOT||" | head -n 20 || true)
  if [[ -n "$hits" ]]; then
    f_potential high "$cat" "APP-WEBSHELL" "PHP files that execute request data (possible web shell)" "$hits" \
      "Code that passes GET/POST data to eval/system/exec is the signature of a web shell, though some legitimate admin tools do the same." \
      "Read each file. If it is not part of an application the README requires, remove it manually (and investigate how it got there)." "Removing a legitimate admin tool breaks it." - yes
  fi
  return 0
}
