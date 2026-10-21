#!/usr/bin/env bash
# Tests for lib/detection.sh and the support gating in mint-toolkit.sh.
# Everything runs against fixture roots and mocked commands - see tests/helpers.sh.
T_NAME="detection"
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

BASE="$FIX/mint21-cinnamon"

# detect_vars : run det_run in the current env and print selected variables
detect_vars() {
  in_env 'det_run; printf "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n" "$DET_SUPPORT" "$DET_ID" "$DET_MINT_RELEASE" "$DET_MINT_EDITION" "$DET_BASE_NAME" "$DET_BASE_VERSION" "$DET_BASE_CODENAME" "$DET_DESKTOP" "$DET_CODENAME" "$DET_PKGMGR"'
}

# set_os OSRELEASE_TEXT [INFO_TEXT]  (INFO_TEXT empty -> remove /etc/linuxmint/info)
set_os() {
  printf '%s\n' "$1" >"$E/root/etc/os-release"
  if [[ -n "${2:-}" ]]; then mkdir -p "$E/root/etc/linuxmint"; printf '%s\n' "$2" >"$E/root/etc/linuxmint/info"; else rm -rf "$E/root/etc/linuxmint"; fi
}

t_section "Linux Mint 21.3 Cinnamon (fixture)"
mk_env d1 "$BASE"
r=$(detect_vars)
assert_eq "Mint 21.3 Cinnamon is 'targeted' with Ubuntu 22.04/jammy base" \
  "targeted|linuxmint|21.3|Cinnamon|Ubuntu|22.04|jammy|cinnamon|virginia|apt/dpkg" "$r"
in_env 'det_run; echo "$DET_KERNEL $DET_ARCH $DET_HOSTNAME"' >"$E/o.txt"; r=$(<"$E/o.txt")
assert_eq "kernel, architecture and hostname come from uname/hostname" "5.15.0-91-generic x86_64 mint-test" "$r"
run_tk detect
assert_eq "'detect' exits 0 on a targeted system" 0 "$T_RC"
assert_contains "'detect' prints support status" "$T_OUT" "Support status  : targeted"
assert_contains "'detect' prints the Mint edition" "$T_OUT" "edition: Cinnamon"

t_section "Linux Mint 22 (noble) - MATE and Xfce editions"
mk_env d2 "$BASE"
set_os 'NAME="Linux Mint"
ID=linuxmint
ID_LIKE="ubuntu debian"
PRETTY_NAME="Linux Mint 22"
VERSION_ID="22"
VERSION_CODENAME=wilma
UBUNTU_CODENAME=noble' 'RELEASE=22
CODENAME=wilma
EDITION="Xfce"'
assert_eq "Mint 22 Xfce is targeted, Ubuntu 24.04/noble, desktop xfce" "targeted|linuxmint|22|Xfce|Ubuntu|24.04|noble|xfce|wilma|apt/dpkg" "$(detect_vars)"
printf 'RELEASE=22.1\nCODENAME=xia\nEDITION="MATE"\n' >"$E/root/etc/linuxmint/info"
sed -i 's/VERSION_ID="22"/VERSION_ID="22.1"/' "$E/root/etc/os-release"
assert_eq "Mint 22.1 MATE is targeted, desktop mate" "targeted|linuxmint|22.1|MATE|Ubuntu|24.04|noble|mate|wilma|apt/dpkg" "$(detect_vars)"
printf 'RELEASE=22.1\nCODENAME=xia\nEDITION="Cinnamon 64-bit"\n' >"$E/root/etc/linuxmint/info"
assert_contains "edition string with a suffix ('Cinnamon 64-bit') is reduced to its first word" "$(detect_vars)" "|Cinnamon|"

t_section "Mismatched or out-of-range Mint versions are NOT treated as targeted"
mk_env d3 "$BASE"
set_os 'ID=linuxmint
ID_LIKE="ubuntu debian"
PRETTY_NAME="Linux Mint 20.3"
VERSION_ID="20.3"
UBUNTU_CODENAME=focal' 'RELEASE=20.3
EDITION="Cinnamon"'
assert_contains "Mint 20.3 -> limited" "$(detect_vars)" "limited|linuxmint|20.3"
set_os 'ID=linuxmint
PRETTY_NAME="Linux Mint 23"
VERSION_ID="23"
UBUNTU_CODENAME=resolute' 'RELEASE=23
EDITION="Cinnamon"'
assert_contains "Mint 23 (future release) -> limited" "$(detect_vars)" "limited|linuxmint|23"
set_os 'ID=linuxmint
PRETTY_NAME="Linux Mint 21.3"
VERSION_ID="21.3"
UBUNTU_CODENAME=noble' 'RELEASE=21.3
EDITION="Cinnamon"'
assert_contains "Mint 21 claiming a noble base is inconsistent -> limited" "$(detect_vars)" "limited|linuxmint|21.3"
set_os 'ID=linuxmint
ID_LIKE=debian
PRETTY_NAME="LMDE 6"
VERSION_ID="6"
DEBIAN_CODENAME=bookworm' 'RELEASE=6
EDITION="Cinnamon"'
assert_eq "LMDE 6 -> limited with Debian 12 base" "limited|linuxmint|6|Cinnamon|Debian|12|bookworm|cinnamon||apt/dpkg" "$(detect_vars)"

t_section "Non-Mint and non-Linux systems"
mk_env d4 "$BASE"
set_os 'ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.4 LTS"
VERSION_ID="22.04"
VERSION_CODENAME=jammy
UBUNTU_CODENAME=jammy'
r=$(detect_vars)
assert_contains "Ubuntu 22.04 -> limited (Mint-specific checks do not apply)" "$r" "limited|ubuntu"
run_tk detect; assert_eq "'detect' still exits 0 for limited" 0 "$T_RC"
mk_env d5 "$BASE"
set_os 'ID=fedora
PRETTY_NAME="Fedora Linux 40"
VERSION_ID="40"'
assert_contains "Fedora -> unsupported" "$(detect_vars)" "unsupported|fedora"
run_tk detect; assert_eq "'detect' exits 3 for unsupported" 3 "$T_RC"
run_tk audit
assert_eq "'audit' refuses an unsupported OS without --force-unsupported" 3 "$T_RC"
assert_contains "refusal explains how to override" "$T_ERR" "--force-unsupported"
assert_eq "no report directory was created for the refused audit" "" "$(ls "$E/out" 2>/dev/null)"
mk_env d6 "$BASE"; echo Darwin >"$E/cmds/uname.s.out"
assert_contains "kernel name Darwin -> unsupported" "$(detect_vars)" "unsupported|linuxmint"
mk_env d7 "$BASE"; rm -f "$E/root/etc/os-release"
assert_contains "missing /etc/os-release -> unsupported (cannot identify)" "$(detect_vars)" "unsupported||"
run_tk audit --force-unsupported
assert_eq "--force-unsupported allows a best-effort read-only audit" 0 "$T_RC"

t_section "The toolkit has no command that changes the system"
mk_env d8 "$BASE"; T_EUID=0
run_tk harden
assert_eq "'harden' no longer exists" 1 "$T_RC"
assert_contains "…and is reported as an unknown command" "$T_ERR" "unknown command"
run_tk rollback
assert_eq "'rollback' no longer exists" 1 "$T_RC"
run_tk audit --dry-run
assert_eq "'--dry-run' no longer exists" 1 "$T_RC"
assert_contains "…and is reported as an unknown option" "$T_ERR" "unknown option"
assert_eq "none of these touched the system" "" "$(mock_mutations)"
assert_eq "…and no backup/session directory was created" "" "$(ls "$E/state" 2>/dev/null)"

t_section "Missing utilities"
mk_env d10 "$BASE"
drop_mocks dpkg apt-get dpkg-query
r=$(detect_vars)
assert_contains "Mint 21.3 without dpkg/apt is limited, not targeted" "$r" "limited|linuxmint|21.3|Cinnamon|Ubuntu|22.04|jammy|cinnamon|virginia|none"
mk_env d11 "$BASE"
drop_mocks ss systemctl ufw sshd gsettings
in_env 'det_run; echo "${DET_MISSING_OPTIONAL[*]}"' >"$E/o.txt"; r=$(<"$E/o.txt")
assert_contains "missing optional commands are listed (ss)" "$r" "ss"
assert_contains "missing optional commands are listed (systemctl)" "$r" "systemctl"
assert_contains "missing optional commands are listed (ufw)" "$r" "ufw"
mk_env d12 "$BASE"; drop_mocks ss systemctl
run_tk detect
assert_contains "'detect' output names missing optional commands" "$T_OUT" "Optional cmds missing:"

t_section "Desktop detection fallbacks"
mk_env d13 "$BASE"; rm -rf "$E/root/etc/linuxmint"
set_os 'ID=linuxmint
PRETTY_NAME="Linux Mint 21.3"
VERSION_ID="21.3"
UBUNTU_CODENAME=jammy'
r=$(XDG_CURRENT_DESKTOP="X-Cinnamon" detect_vars); assert_contains "no info file: XDG_CURRENT_DESKTOP=X-Cinnamon -> cinnamon" "$r" "|cinnamon|"
r=$(XDG_CURRENT_DESKTOP="XFCE" detect_vars);       assert_contains "no info file: XDG_CURRENT_DESKTOP=XFCE -> xfce" "$r" "|xfce|"
r=$(XDG_CURRENT_DESKTOP="MATE" detect_vars);       assert_contains "no info file: XDG_CURRENT_DESKTOP=MATE -> mate" "$r" "|mate|"
r=$(XDG_CURRENT_DESKTOP="" detect_vars);           assert_contains "no info file and no env: desktop 'unknown'" "$r" "|unknown|"
touch "$E/root/usr/bin/xfce4-session"
r=$(XDG_CURRENT_DESKTOP="" detect_vars);           assert_contains "installed session binary identifies xfce" "$r" "|xfce|"
touch "$E/root/usr/bin/mate-session"
in_env 'XDG_CURRENT_DESKTOP="" det_run; echo "$DET_DESKTOP / $DET_DESKTOP_SRC"' >"$E/o.txt"; r=$(<"$E/o.txt")
assert_contains "two installed desktops -> unknown, with explanation" "$r" "unknown / multiple installed"

t_section "Robustness: os-release is parsed, never executed"
mk_env d14 "$BASE"
set_os "ID=linuxmint
PRETTY_NAME=\"Linux Mint \$(touch $E/PWNED)\"
VERSION_ID=\"21.3\"
UBUNTU_CODENAME=jammy
NAME=\`touch $E/PWNED2\`" 'RELEASE=21.3
EDITION="Cinnamon"'
detect_vars >/dev/null
assert_no_file "command substitution inside os-release was not executed" "$E/PWNED"
assert_no_file "backtick substitution inside os-release was not executed" "$E/PWNED2"

t_summary
