#!/usr/bin/env bash
# Tests for the read-only audit: correctness against fixtures, false-positive guard,
# read-only guarantee, secret handling, degraded environments, repeatability.
T_NAME="audit"
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

BASE="$FIX/mint21-cinnamon"; VULN="$FIX/vuln-overlay"

# expect_class ID CLASS [SEVERITY]
expect_class() {
  local id=$1 want=$2 sev=${3:-} got
  got=$(finding_class "$id")
  assert_eq "$id is $want" "$want" "$got"
  [[ -n "$sev" ]] && assert_eq "$id severity is $sev" "$sev" "$(finding_sev "$id")"
}

# =====================================================================
t_section "Healthy, mostly-default Mint 21.3 (non-root) - false-positive guard"
mk_env healthy "$BASE"
before=$(snapshot_tree)
run_tk audit
assert_eq "audit exits 0" 0 "$T_RC"
assert_file "detailed report was written" "$(latest_report)"
assert_file "findings store was written" "$(latest_findings)"
assert_file "run log was written" "$(latest_run)/audit.log"
assert_eq "NO confirmed issues are reported on a default system" 0 "$(class_count CONFIRMED)"
assert_contains "non-root run warns about limited coverage" "$T_ERR" "Not running as root"
assert_contains "terminal summary is shown" "$T_OUT" "== Audit summary =="
assert_contains "terminal summary says nothing was changed" "$T_OUT" "made no changes to the system"
expect_class FW-UFW-RULES UNPERFORMED
expect_class FW-UFW-INACTIVE POTENTIAL medium
expect_class AUTH-PAM-NULLOK POTENTIAL
expect_class AUTH-NO-LOCKOUT POTENTIAL
expect_class DESK-GUEST POTENTIAL
expect_class SSH-INSTALLED INFO
expect_class USERS-INVENTORY INFO
assert_eq "unperformed checks are never counted as passes (SCHED-USERCRON present)" UNPERFORMED "$(finding_class SCHED-USERCRON)"
after=$(snapshot_tree)
assert_eq "audit left the fixture system byte-for-byte unchanged" "$before" "$after"
assert_eq "no state-changing command reached the command mocks" "" "$(mock_mutations)"

t_section "Repeated runs are safe and consistent"
ids1=$(finding_ids)
run_tk audit
assert_eq "second audit also exits 0" 0 "$T_RC"
assert_eq "second audit produced a separate report directory" 2 "$(ls -d "$E"/out/audit-* | wc -l | tr -d ' ')"
assert_eq "second audit finds exactly the same identifiers" "$ids1" "$(finding_ids)"
assert_eq "system still unchanged after two audits" "$before" "$(snapshot_tree)"

# =====================================================================
t_section "Weak system (root) - every planted weakness is found, correctly classified"
mk_env vuln "$BASE" "$VULN"
T_EUID=0
plant_webshell
before=$(snapshot_tree)
run_tk audit
assert_eq "audit exits 0" 0 "$T_RC"
assert_eq "audit as root does not warn about missing privileges" "" "$(grep -c 'Not running as root' <<<"$T_ERR" | sed 's/^0$//')"
# users
expect_class USERS-UID0-hax CONFIRMED high
expect_class USERS-EMPTYPW-mallory CONFIRMED high
expect_class USERS-DUPUID-1001 CONFIRMED medium
expect_class USERS-WEAKHASH-bob POTENTIAL
expect_class USERS-SYSSHELL-backdoor POTENTIAL
expect_class USERS-ROOTEQUIV-docker POTENTIAL
expect_class USERS-SUDO-NOPASSWD POTENTIAL medium
expect_class USERS-ROOTPW POTENTIAL
assert_eq "the stock 'alice' admin is NOT reported as a UID-0 problem" "" "$(finding_class USERS-UID0-alice)"
assert_eq "UID-0 impostor is not double-reported as a system-shell problem" "" "$(finding_class USERS-SYSSHELL-hax)"
# auth / ssh
expect_class AUTH-PAM-NOQUALITY POTENTIAL
expect_class SSH-ACTIVE POTENTIAL
expect_class SSH-ROOTLOGIN CONFIRMED high
expect_class SSH-EMPTYPW CONFIRMED high
expect_class SSH-PASSWORDAUTH POTENTIAL
expect_class SSH-AUTHKEYS POTENTIAL
# network / firewall
expect_class NET-PORT-tcp-23 POTENTIAL high
expect_class NET-PORT-tcp-21 POTENTIAL high
expect_class NET-PORT-tcp-445 POTENTIAL medium
expect_class NET-PORT-tcp-80 POTENTIAL medium
assert_eq "SSH port 22 is not flagged as a risky port (SSH has its own checks)" "" "$(finding_class NET-PORT-tcp-22)"
assert_eq "loopback-only DNS resolver is not flagged" "" "$(finding_class NET-PORT-tcp-53)"
expect_class NET-REMOTE-PORTS INFO
expect_class NET-ASLR CONFIRMED medium
expect_class NET-SYNCOOKIES POTENTIAL
expect_class NET-IPFORWARD POTENTIAL
expect_class NET-PROMISC POTENTIAL
expect_class FW-UFW-INACTIVE POTENTIAL
# services
expect_class SVC-vsftpd POTENTIAL high
expect_class SVC-smbd POTENTIAL medium
expect_class SVC-apache2 POTENTIAL medium
assert_eq "essential services (cron, dbus, lightdm) are never flagged" "" "$(finding_class SVC-cron)$(finding_class SVC-dbus)$(finding_class SVC-lightdm)"
# permissions
expect_class PERM-etc-shadow CONFIRMED high
expect_class PERM-etc-sudoers CONFIRMED high
expect_class PERM-etc-passwd CONFIRMED medium
expect_class PERM-etc-ssh-sshd_config CONFIRMED medium
expect_class PERM-SUDOERSD-90-custom CONFIRMED high
expect_class PERM-SUID-DANGEROUS CONFIRMED high
expect_class PERM-SUID-UNKNOWN POTENTIAL
expect_class PERM-WW-FILES POTENTIAL
expect_class PERM-WW-DIRS POTENTIAL
expect_class PERM-UNOWNED POTENTIAL
expect_class PERM-MEDIA INFO
assert_file_has "dangerous SUID evidence names /usr/bin/find" "$(latest_report)" "/usr/bin/find"
assert_file_has "unknown SUID evidence names the odd binary" "$(latest_report)" "/usr/local/bin/rootme"
# applications / hosts / homes / PAM / listener packages (added from the research)
expect_class APP-VSFTPD-ANON CONFIRMED medium
expect_class APP-VSFTPD-ANONUPLOAD CONFIRMED high
expect_class APP-APACHE-TOKENS POTENTIAL low
expect_class APP-APACHE-SIGNATURE POTENTIAL low
expect_class APP-APACHE-INDEXES POTENTIAL low
expect_class APP-MYSQL-BIND POTENTIAL medium
expect_class APP-SAMBA-GUEST POTENTIAL medium
expect_class APP-WEBSHELL POTENTIAL high
expect_class APP-PHP-URLINCLUDE-etc-php-8-1-apache2-php-ini CONFIRMED medium
assert_file_has "web-shell evidence names the planted file but never its contents" "$(latest_report)" "/var/www/html/x.php"
assert_eq "benign PHP page is not flagged" 0 "$(grep -c 'index.php' "$(latest_report)")"
expect_class AUTH-PAM-MISSINGMODULE CONFIRMED high
expect_class NET-HOSTS-REDIRECT POTENTIAL medium
expect_class PERM-HOME-bob POTENTIAL low
assert_eq "home directory with mode 750 is not flagged" "" "$(finding_class PERM-HOME-alice)"
assert_file_has "listening sockets are mapped to their package" "$(latest_report)" "[package: openssh-server]"
assert_file_has "…including a legacy super-server" "$(latest_report)" "[package: openbsd-inetd]"
# updates
expect_class UPD-SECURITY POTENTIAL medium
expect_class UPD-TOOLS POTENTIAL low
expect_class UPD-APT-INSECURE CONFIRMED high
# persistence
assert_eq "cron /dev/tcp reverse shell is flagged" POTENTIAL "$(finding_class SCHED-CRON-etc-cron-d-backdoor-L1)"
assert_eq "cron job running from /tmp is flagged" POTENTIAL "$(finding_class SCHED-CRON-etc-crontab-L4)"
expect_class SCHED-RCLOCAL POTENTIAL
assert_eq "autostart 'curl | sh' is flagged" POTENTIAL "$(finding_class SCHED-AUTOSTART-home-alice-config-autostart-updater-desktop)"
assert_eq "alias overriding sudo is flagged" POTENTIAL "$(finding_class SCHED-ALIAS-home-alice-bashrc)"
assert_eq "benign stock cron job (e2scrub) is NOT flagged" "" "$(finding_class SCHED-CRON-etc-cron-d-e2scrub_all-L1)"
# desktop
expect_class DESK-AUTOLOGIN CONFIRMED medium
expect_class DESK-GUEST CONFIRMED medium
expect_class DESK-SCREENLOCK UNPERFORMED
assert_eq "autologin is traced to /etc/lightdm/lightdm.conf" 1 "$(grep -c 'etc/lightdm/lightdm.conf' <<<"$(awk -F"$US" '$4=="DESK-AUTOLOGIN"{print $6}' "$(latest_findings)")" | sed 's/^[1-9].*/1/')"

t_section "Report content and accuracy (weak system)"
rep=$(<"$(latest_report)")
assert_contains "every finding has 'Recommended action'" "$rep" "**Recommended action:**"
assert_contains "findings point at the manual-fix guide" "$rep" "docs/manual-fixes.md"
assert_contains "…and say the toolkit changes nothing" "$rep" "this toolkit never changes the system"
assert_not_contains "no finding mentions a hardening action id" "$rep" "hardening action H-"
assert_contains "side effects are given" "$rep" "**Possible side effects:**"
assert_contains "evidence for UID 0 shows the account line (no hash)" "$rep" "hax:0:0:/root:/bin/bash"
assert_not_contains "no leftover automation hint for permissions" "$rep" "H-PERMS-SENSITIVE"
assert_not_contains "report never promises lost competition points" "$rep" "lose points"
assert_not_contains "report never promises gained competition points" "$rep" "gain points"
assert_eq "no INFO finding carries a recommended-action section" 0 "$(awk '/^### /{h=$0} /Recommended action/{print h}' "$(latest_report)" | grep -c 'USERS-INVENTORY')"

t_section "Secrets never leak (reports, logs, terminal output, findings store)"
for needle in "FAKEHASHFORTESTSONLY" "FAKEROOTHASHFORTESTSONLY" "FAKEMD5HASHTESTONLY" "AAAAC3NzaC1lZDI1NTE5AAAAIFAKEKEY" "testsalt"; do
  leaked=$(grep -rlF -- "$needle" "$(latest_run)" 2>/dev/null | wc -l | tr -d ' ')
  assert_eq "'$needle' absent from every file in the run directory" 0 "$leaked"
  assert_not_contains "'$needle' absent from terminal output" "$T_OUT$T_ERR" "$needle"
done
assert_contains "authorized_keys are counted, not shown" "$rep" "1 key(s) in /home/bob/.ssh/authorized_keys"

t_section "Audit mode really is read-only (weak system)"
after=$(snapshot_tree)
assert_eq "no file, permission or firewall state changed" "$before" "$after"
assert_eq "no state-changing command reached the mocks" "" "$(mock_mutations)"
assert_eq "output is confined to the run directory (no stray files in the fixture root)" 0 "$(find "$E/root" -newer "$E/answers.txt" 2>/dev/null | wc -l | tr -d ' ')" || true

# =====================================================================
t_section "Audit guard blocks mutating commands even if code asked for them"
mk_env guard "$BASE"
in_env 'TK_MODE=audit
for c in "systemctl restart ssh" "systemctl disable cups" "ufw enable" "ufw default deny incoming" "apt-get install nmap" "apt-get -y upgrade" "sysctl -w net.ipv4.ip_forward=0" "dpkg -r nmap" "dpkg -i x.deb" "find /etc -delete" "find /etc -exec rm {} ;" "gsettings set a b c" "xfconf-query -c x -p /y -s z" "chmod 777 /etc/shadow" "rm -rf /" "useradd evil" "passwd -l root" "ip link set eth0 down" "iptables -F" "sshd -d"; do
  tk_cmd $c; printf "%s => rc=%s\n" "$c" "$TK_RC"
done' >"$E/guard.txt"
while IFS= read -r line; do
  assert_contains "blocked: ${line%% =>*}" "$line" "rc=126"
done <"$E/guard.txt"
in_env 'TK_MODE=audit
for c in "systemctl is-active ssh" "systemctl list-units" "ufw status verbose" "dpkg -s bash" "apt-get -s upgrade" "gsettings get a b" "sysctl -n kernel.randomize_va_space" "ip -o link show" "sshd -T" "sshd -t"; do
  tk_cmd $c; printf "%s => rc=%s\n" "$c" "$TK_RC"
done' >"$E/guard2.txt"
assert_eq "no read-only command is blocked by the guard" 0 "$(grep -c 'rc=126' "$E/guard2.txt")"
assert_eq "the library no longer contains any write/apply helper" 0 "$(grep -cE '^(hz_|hz\w*\(\))' "$PROJECT"/lib/*.sh | awk -F: '{s+=$2} END{print s+0}')"
assert_no_file "…the hardening library is gone" "$PROJECT/lib/hardening.sh"

# =====================================================================
t_section "Insufficient permissions"
mk_env perm "$BASE"
# 1) mocked 'ufw status' demands root (as the real one does); non-root run must not claim a result
run_tk audit
assert_eq "UFW rules: unperformed, not 'ok', when not root" UNPERFORMED "$(finding_class FW-UFW-RULES)"
assert_eq "per-user crontabs: unperformed when not root" UNPERFORMED "$(finding_class SCHED-USERCRON)"
# 2) a real unreadable file
chmod 000 "$E/root/etc/shadow" 2>/dev/null
if [[ ! -r "$E/root/etc/shadow" ]]; then
  run_tk audit
  assert_eq "unreadable /etc/shadow -> password checks unperformed" UNPERFORMED "$(finding_class USERS-SHADOW)"
  assert_eq "…and no password finding is invented" "" "$(finding_class USERS-EMPTYPW-alice)"
  chmod 644 "$E/root/etc/shadow"
else
  t_skip "unreadable /etc/shadow" "this host (Git Bash on Windows) does not enforce chmod 000; covered by the Linux VM run"
  chmod 644 "$E/root/etc/shadow" 2>/dev/null
fi
# 3) per-user desktop settings without a session
run_tk audit
assert_eq "screen lock readable for the invoking user without sudo" INFO "$(finding_class DESK-SCREENLOCK-VALUES)"

# =====================================================================
t_section "Missing utilities degrade gracefully"
mk_env nocmds "$BASE" "$VULN"
T_EUID=0
drop_mocks ss systemctl ufw sshd dpkg dpkg-query apt-get ip gsettings
run_tk audit
assert_eq "audit still completes (exit 0)" 0 "$T_RC"
assert_eq "no listening-port data -> unperformed, not 'no ports'" UNPERFORMED "$(finding_class NET-LISTEN)"
assert_eq "no systemctl -> service inventory unperformed" UNPERFORMED "$(finding_class SVC-LIST)"
assert_eq "no dpkg -> package checks unperformed" UNPERFORMED "$(finding_class UPD-PKGMGR)"
assert_eq "no ip -> promiscuous check unperformed" UNPERFORMED "$(finding_class NET-PROMISC)"
assert_eq "file-based findings still work (UID 0 impostor)" CONFIRMED "$(finding_class USERS-UID0-hax)"
assert_eq "SSH config falls back to parsing files when sshd is missing" CONFIRMED "$(finding_class SSH-ROOTLOGIN)"
assert_file_has "evidence says the SSH value was parsed from files" "$(latest_report)" "parsed from /etc/ssh/sshd_config"

# =====================================================================
t_section "Desktop editions"
mk_env mate "$BASE"
printf 'RELEASE=21.3\nEDITION="MATE"\n' >"$E/root/etc/linuxmint/info"
printf 'false\n' >"$E/cmds/gsettings.get.org.mate.screensaver.lock-enabled.out"
printf 'uint32 10\n' >"$E/cmds/gsettings.get.org.mate.session.idle-delay.out"
run_tk audit
expect_class DESK-LOCK-DISABLED POTENTIAL medium
assert_file_has "MATE uses the org.mate.screensaver schema" "$E/mock.log" "gsettings get org.mate.screensaver lock-enabled"
assert_file_lacks "MATE run does not query Cinnamon schemas" "$E/mock.log" "org.cinnamon"

mk_env xfce "$BASE"
printf 'RELEASE=21.3\nEDITION="Xfce"\n' >"$E/root/etc/linuxmint/info"
printf '/lock/enabled                     false\n/saver/enabled                    true\n' >"$E/cmds/xfconf-query.c.xfce4-screensaver.lv.out"
run_tk audit
expect_class DESK-LOCK-DISABLED POTENTIAL
assert_file_has "Xfce uses xfconf-query" "$E/mock.log" "xfconf-query -c xfce4-screensaver -lv"
assert_file_lacks "Xfce run does not call gsettings" "$E/mock.log" "gsettings"

mk_env cinn_sudo "$BASE" "$VULN"
T_EUID=0; T_EXTRA_ENV="SUDO_USER=alice"
run_tk audit
expect_class DESK-LOCK-DISABLED POTENTIAL medium
expect_class DESK-IDLE-NEVER POTENTIAL low
assert_eq "no UNPERFORMED screen-lock result when SUDO_USER has a session" "" "$(finding_class DESK-SCREENLOCK)"

mk_env nodesk "$BASE"; rm -rf "$E/root/etc/linuxmint"
run_tk audit
expect_class DESK-SCREENLOCK UNPERFORMED

# =====================================================================
t_section "README-derived lists (--authorized-users / --required-services / --allow-ports)"
mk_env prof "$BASE" "$VULN"; T_EUID=0
before=$(snapshot_tree)
run_tk audit --authorized-users alice,bob --authorized-admins alice --required-services vsftpd --allow-ports 80
assert_eq "audit with a profile exits 0" 0 "$T_RC"
assert_contains "the profile in use is echoed" "$T_OUT" "Profile in use: authorized_users=[alice,bob]"
expect_class USERS-NOTLISTED-mallory POTENTIAL medium
assert_eq "listed user 'alice' is not reported" "" "$(finding_class USERS-NOTLISTED-alice)"
assert_eq "listed user 'bob' is not reported" "" "$(finding_class USERS-NOTLISTED-bob)"
expect_class USERS-NOTADMIN-bob POTENTIAL high
expect_class USERS-NOTADMIN-mallory POTENTIAL high
assert_eq "authorized admin 'alice' is not reported as excess" "" "$(finding_class USERS-NOTADMIN-alice)"
expect_class SVC-vsftpd INFO
assert_file_has "required service is explained as 'not an issue'" "$(latest_report)" "required per your profile"
assert_eq "service NOT in the profile is still flagged" POTENTIAL "$(finding_class SVC-smbd)"
expect_class NET-PORT-tcp-80 INFO
assert_eq "port NOT in the profile is still flagged" POTENTIAL "$(finding_class NET-PORT-tcp-21)"
assert_eq "…config problems in a required service are still reported (anonymous FTP, now low)" "low" "$(finding_sev APP-VSFTPD-ANON)"
assert_eq "profiles change nothing on the system" "$before" "$(snapshot_tree)"
run_tk audit
assert_eq "without a profile no account is reported as 'not listed'" 0 "$(has_id_prefix USERS-NOTLISTED && echo 1 || echo 0)"

printf '# comment\nauthorized_users = alice , bob\nrequired_services=vsftpd\nbogus_key=1\nallow_ports=80, 443/tcp\n' >"$E/p.conf"
run_tk audit --profile "$E/p.conf" --modules users
assert_eq "profile file is accepted" 0 "$T_RC"
assert_contains "unknown profile keys are warned about, not fatal" "$T_ERR" "unknown key 'bogus_key'"
assert_contains "profile values are normalised" "$T_OUT" "authorized_users=[alice,bob]"
assert_contains "ports default to tcp" "$T_OUT" "allow_ports=[80/tcp,443/tcp]"
run_tk audit --authorized-users 'alice;rm -rf /'
assert_eq "shell metacharacters in a list are rejected" 1 "$T_RC"
assert_contains "…with a clear message" "$T_ERR" "invalid value"
run_tk audit --allow-ports 80,abc
assert_eq "non-numeric port rejected" 1 "$T_RC"
run_tk audit --allow-ports 99999999
assert_eq "absurd port rejected" 1 "$T_RC"
run_tk audit --profile "$E/does-not-exist"
assert_eq "missing profile file rejected" 1 "$T_RC"
printf 'authorized_users=$(touch %s/PWNED)\n' "$E" >"$E/evil.conf"
run_tk audit --profile "$E/evil.conf" --modules users
assert_eq "profile with command substitution is rejected" 1 "$T_RC"
assert_no_file "…and was never executed" "$E/PWNED"

# =====================================================================
t_section "sudoers syntax, ssh.socket, LightDM cross-check, notice, forensics helper"
mk_env visudo "$BASE" "$VULN"; T_EUID=0
printf '1\n' >"$E/cmds/visudo.c.rc"; echo "visudo: >>> /etc/sudoers.d/90-custom: syntax error near line 1 <<<" >"$E/cmds/visudo.c.err"
run_tk audit --modules users
expect_class USERS-SUDOERS-SYNTAX CONFIRMED high
assert_file_has "syntax-error evidence is shown" "$(latest_report)" "syntax error near line 1"
mk_env visudo2 "$BASE"; T_EUID=""
run_tk audit --modules users
assert_eq "visudo is not run by non-root audits" 0 "$(grep -c '^visudo' "$E/mock.log")"
mk_env visudo3 "$BASE"; T_EUID=0
run_tk audit --modules users
assert_eq "valid sudoers: no syntax finding" "" "$(finding_class USERS-SUDOERS-SYNTAX)"
assert_file_has "root audit does run 'visudo -c'" "$E/mock.log" "visudo -c"

mk_env sock "$BASE"; T_EUID=0
printf 'Package: openssh-server\nStatus: install ok installed\n' >"$E/cmds/dpkg.s.openssh-server.out"; printf '0\n' >"$E/cmds/dpkg.s.openssh-server.rc"
echo active >"$E/cmds/systemctl.is-active.ssh.socket.out"; printf '0\n' >"$E/cmds/systemctl.is-active.ssh.socket.rc"
run_tk audit --modules ssh
expect_class SSH-ACTIVE POTENTIAL low
assert_file_has "inactive ssh.service + active ssh.socket is reported as SSH running (socket-activated)" "$(latest_report)" "socket-activated via ssh.socket"

mk_env ldm "$BASE" "$VULN"; T_EUID=0
printf '[LightDM]\n[Seat:*]\n# /etc/lightdm/lightdm.conf.d/99-x.conf\nautologin-user=\nallow-guest=false\n' >"$E/cmds/lightdm.show-config.out"
run_tk audit --modules desktop_security
expect_class DESK-LIGHTDM-MISMATCH POTENTIAL low
assert_file_has "mismatch evidence names both views" "$(latest_report)" "lightdm --show-config says"
mk_env ldm2 "$BASE" "$VULN"; T_EUID=0
printf '[Seat:*]\nautologin-user=alice\nallow-guest=true\n' >"$E/cmds/lightdm.show-config.out"
run_tk audit --modules desktop_security
assert_eq "no mismatch when LightDM and the toolkit agree" "" "$(finding_class DESK-LIGHTDM-MISMATCH)"

mk_env notice "$BASE"; T_EXTRA_ENV="TK_NO_NOTICE=0"
run_tk audit --modules users
assert_contains "audit prints the AI/competition-rules notice" "$T_ERR" "written with AI assistance"
assert_contains "…pointing at the rules document" "$T_ERR" "docs/competition-rules.md"
run_tk version
assert_not_contains "version does not print the notice" "$T_ERR" "written with AI"
: >"$E/mock.log"
T_EXTRA_ENV="TK_NO_NOTICE=0"; run_tk forensics-help
assert_eq "forensics-help exits 0" 0 "$T_RC"
assert_contains "forensics-help lists read-only commands" "$T_OUT" "base64 -d"
assert_contains "forensics-help says to do it before changing anything" "$T_OUT" "BEFORE changing anything"
assert_eq "forensics-help ran no system command at all" 0 "$(wc -l <"$E/mock.log" | tr -d ' ')"

in_env 'TK_MODE=audit
for c in "visudo -c" "lightdm --show-config"; do tk_cmd $c; printf "%s => rc=%s\n" "$c" "$TK_RC"; done
for c in "visudo -f /etc/sudoers.d/x" "visudo" "lightdm --test-mode" "lightdm"; do tk_cmd $c; printf "%s => rc=%s\n" "$c" "$TK_RC"; done' >"$E/g.txt"
assert_eq "visudo -c and lightdm --show-config pass the audit guard" 0 "$(head -2 "$E/g.txt" | grep -c 'rc=126')"
assert_eq "other visudo/lightdm invocations are blocked" 4 "$(tail -4 "$E/g.txt" | grep -c 'rc=126')"

# =====================================================================
t_section "Extra checks: password ageing, automatic updates, games, Firefox"
mk_env extra "$BASE"; T_EUID=0
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   3/' "$E/root/etc/login.defs"
printf 'aisleriot\ngnome-mines\n' >>"$E/cmds/dpkg-query.W.out"
mkdir -p "$E/root/home/alice/.mozilla/firefox/abc.default" "$E/root/home/bob/.mozilla/firefox/xyz.default"
printf 'user_pref("dom.disable_open_during_load", false);\nuser_pref("browser.safebrowsing.malware.enabled", true);\nuser_pref("browser.startup.homepage", "https://example.org");\n' >"$E/root/home/alice/.mozilla/firefox/abc.default/prefs.js"
printf 'user_pref("security.tls.version.min", 1);\nuser_pref("browser.safebrowsing.phishing.enabled", false);\nuser_pref("browser.safebrowsing.phishing.enabled", true);\n' >"$E/root/home/bob/.mozilla/firefox/xyz.default/user.js"
run_tk audit --modules authentication,updates,desktop_security
assert_eq "extra-check audit exits 0" 0 "$T_RC"
expect_class AUTH-LOGINDEFS-MINDAYS POTENTIAL low
expect_class AUTH-LOGINDEFS-WARN POTENTIAL low
expect_class UPD-AUTO POTENTIAL low
assert_file_has "the missing automatic-update file is named" "$(latest_report)" "20auto-upgrades is missing"
expect_class UPD-GAMES POTENTIAL low
assert_file_has "installed games are named" "$(latest_report)" "aisleriot gnome-mines"
expect_class DESK-FIREFOX-INSECURE POTENTIAL low
assert_file_has "popup blocker off is reported with its file" "$(latest_report)" "/home/alice/.mozilla/firefox/abc.default/prefs.js: dom.disable_open_during_load = false"
assert_file_has "old TLS minimum is reported" "$(latest_report)" "security.tls.version.min = 1"
assert_file_lacks "a setting that is still on is not reported" "$(latest_report)" "browser.safebrowsing.malware.enabled = "
assert_file_lacks "only the LAST value of a preference counts" "$(latest_report)" "browser.safebrowsing.phishing.enabled = "

mk_env extra_ok "$BASE"; T_EUID=0
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' >"$E/root/etc/apt/apt.conf.d/20auto-upgrades"
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' "$E/root/etc/login.defs"
mkdir -p "$E/root/home/alice/.mozilla/firefox/abc.default"
printf 'user_pref("dom.disable_open_during_load", true);\n' >"$E/root/home/alice/.mozilla/firefox/abc.default/prefs.js"
run_tk audit --modules authentication,updates,desktop_security
assert_eq "automatic security updates enabled: INFO" INFO "$(finding_class UPD-AUTO)"
assert_eq "no games on a clean system" "" "$(finding_class UPD-GAMES)"
assert_eq "minimum password age of 1 is fine" "" "$(finding_class AUTH-LOGINDEFS-MINDAYS)"
assert_eq "warning age of 7 is fine" "" "$(finding_class AUTH-LOGINDEFS-WARN)"
assert_eq "healthy Firefox prefs: INFO, not a finding" INFO "$(finding_class DESK-FIREFOX)"
assert_eq "…and no insecure-Firefox finding" "" "$(finding_class DESK-FIREFOX-INSECURE)"
mk_env extra_nofx "$BASE"; T_EUID=0
run_tk audit --modules desktop_security
assert_file_has "no Firefox profile: said so" "$(latest_report)" "No Firefox preference files found"

# =====================================================================
t_section "False positives found on a real Mint 22.3 VM"
mk_env realmint "$BASE"; T_EUID=0
printf "alias ls='ls --color=auto'\nalias grep='grep --color=auto'\nalias ll='ls -alF'\n" >"$E/root/home/alice/.bashrc"
run_tk audit --modules scheduled_tasks
assert_eq "stock .bashrc aliases (ls --color=auto, grep, ll) are not reported" "" "$(finding_ids | grep '^SCHED-ALIAS' | tr '\n' ' ')"
printf "alias ls='ls --color=auto'\nalias sudo='/tmp/evil-sudo'\n" >"$E/root/home/alice/.bashrc"
run_tk audit --modules scheduled_tasks
assert_eq "a real redefinition of sudo is still reported" POTENTIAL "$(finding_class SCHED-ALIAS-home-alice-bashrc)"
assert_file_has "…showing the sudo line" "$(latest_report)" "alias sudo='/tmp/evil-sudo'"
assert_file_lacks "…but not the harmless ls line" "$(latest_report)" "alias ls='ls --color=auto'"

mk_env realsamba "$BASE"; T_EUID=0
mkdir -p "$E/root/etc/samba"
printf '[global]\n   map to guest = bad user\n   usershare allow guests = yes\n[printers]\n   guest ok = no\n' >"$E/root/etc/samba/smb.conf"
run_tk audit --modules applications
assert_eq "stock Samba guest settings: INFO only" INFO "$(finding_class APP-SAMBA-STOCK-GUEST)"
assert_eq "…no guest finding" "" "$(finding_class APP-SAMBA-GUEST)"
printf '[global]\n   map to guest = bad user\n[pub]\n   path = /srv/pub\n   guest ok = yes\n' >"$E/root/etc/samba/smb.conf"
run_tk audit --modules applications
expect_class APP-SAMBA-GUEST POTENTIAL medium
assert_eq "a share with 'guest ok = yes' is still found" "" "$(finding_class APP-SAMBA-STOCK-GUEST)"

mk_env realports "$BASE"; T_EUID=0
printf 'udp   UNCONN 0      0             0.0.0.0:5353       0.0.0.0:*\nudp   UNCONN 0      0                [::]:5353          [::]:*\n' >>"$E/cmds/ss.H.tulnp.out"
run_tk audit --modules network
assert_eq "mDNS on IPv4 and IPv6 gives ONE port finding" POTENTIAL "$(finding_class NET-PORT-udp-5353)"
assert_eq "…and no duplicate '-2' finding" "" "$(finding_class NET-PORT-udp-5353-2)"
assert_eq "…while both sockets stay in the listing" 2 "$(grep -cE '^udp +(0\.0\.0\.0|::) +5353' "$(latest_report)")"

# =====================================================================
t_section "Repository hygiene (things that only break on real Linux)"
# NB: counting bytes with tr is reliable; grep patterns containing a CR are not, on Git Bash for Windows
all_scripts=("$PROJECT"/mint-toolkit.sh "$PROJECT"/lib/*.sh "$PROJECT"/tests/*.sh "$PROJECT"/tests/mocks/*.sh "$PROJECT"/practice/*.sh)
crlf=$(for f in "${all_scripts[@]}"; do [[ $(tr -cd '\r' <"$f" | wc -c) -gt 0 ]] && basename "$f"; done | tr '\n' ' ')
assert_eq "no shell script has Windows (CRLF) line endings" "" "$crlf"
shebang_bad=$(for f in "$PROJECT"/mint-toolkit.sh "$PROJECT"/tests/*.sh "$PROJECT"/tests/mocks/*.sh "$PROJECT"/practice/*.sh; do [[ "$(head -n1 "$f")" == '#!/usr/bin/env bash' ]] || basename "$f"; done | tr '\n' ' ')
assert_eq "every runnable script starts with '#!/usr/bin/env bash'" "" "$shebang_bad"
nonascii=$(for f in "$PROJECT"/mint-toolkit.sh "$PROJECT"/lib/*.sh; do [[ $(tr -d '\000-\177' <"$f" | wc -c) -gt 0 ]] && basename "$f"; done | tr '\n' ' ')
assert_eq "toolkit code is plain ASCII (no smart quotes that bash would reject)" "" "$nonascii"

# =====================================================================
t_section "CLI behaviour"
mk_env cli "$BASE"
run_tk audit --modules users
assert_eq "--modules users runs" 0 "$T_RC"
assert_eq "only the selected module's findings exist" 0 "$(has_id_prefix SSH- && echo 1 || echo 0)"
assert_eq "selected module's findings exist" 1 "$(has_id_prefix USERS- && echo 1 || echo 0)"
run_tk audit --modules nonsense
assert_eq "unknown module is rejected" 1 "$T_RC"
assert_contains "…with a clear message" "$T_ERR" "unknown module"
run_tk audit --bogus-option
assert_eq "unknown option is rejected" 1 "$T_RC"
run_tk frobnicate
assert_eq "unknown command is rejected" 1 "$T_RC"
run_tk version
assert_contains "version command" "$T_OUT" "mint-toolkit 0.1.0"
run_tk help
assert_contains "help documents the audit" "$T_OUT" "Read-only security audit"
assert_not_contains "help no longer lists harden" "$T_OUT" "harden "
assert_not_contains "help no longer lists rollback" "$T_OUT" "rollback"
assert_contains "help points at the manual-fix guide" "$T_OUT" "docs/manual-fixes.md"
mkdir -p "$E/preexisting"
run_tk audit --modules users --output-dir "$E/preexisting"
assert_file_lacks "a pre-existing --output-dir is NOT chmod'ed" "$E/mock.log" "chmod 700 $E/preexisting "
assert_file_has "...but the run folder it creates is restricted" "$E/mock.log" "chmod 700 $E/preexisting/audit-"
run_tk audit --output-dir "$E/custom-out"
assert_eq "--output-dir is honoured" 1 "$(ls -d "$E"/custom-out/audit-* 2>/dev/null | wc -l | tr -d ' ')"

t_summary
