#!/usr/bin/env bash
# detection.sh - identify the operating system, edition, desktop and tooling.
# Parses /etc/os-release with sed (never `source`s it) so a hostile or broken
# file cannot execute code.
#
# Support model (see docs/compatibility.md):
#   targeted     Linux Mint 21.x / 22.x on its Ubuntu base, dpkg present.
#                "Targeted" is NOT "verified" - see docs/compatibility.md
#                for what has really been tested.
#   limited      Linux, but not a targeted Mint (other Mint, LMDE, Ubuntu,
#                Debian ...).  Read-only audit runs best-effort.
#   unsupported  Not Linux / cannot identify.  Audit only with --force-unsupported.

DET_REQUIRED_CMDS=(awk sed grep find stat sort cut tr uname mktemp date)
DET_OPTIONAL_CMDS=(systemctl ss ip dpkg dpkg-query apt-get ufw sshd sysctl timeout gsettings xfconf-query aa-status iptables)

det_os_get() { # KEY -> value from os-release (quotes stripped)
  local f; f=$(tkp /etc/os-release)
  [[ -r "$f" ]] || f=$(tkp /usr/lib/os-release)
  [[ -r "$f" ]] || return 1
  sed -n -E "s/^${1}=//p" "$f" | tail -n1 | sed -E "s/^\"(.*)\"\$/\\1/; s/^'(.*)'\$/\\1/"
}

det_ubuntu_version() { # codename -> version
  case "$1" in
    bionic) echo 18.04;; focal) echo 20.04;; jammy) echo 22.04;; noble) echo 24.04;;
    oracular) echo 24.10;; plucky) echo 25.04;; questing) echo 25.10;; *) echo unknown;;
  esac
}
det_debian_version() {
  case "$1" in
    buster) echo 10;; bullseye) echo 11;; bookworm) echo 12;; trixie) echo 13;; *) echo unknown;;
  esac
}

det_map_desktop() { # free text -> cinnamon|mate|xfce|other:<x>|""
  local t=${1,,}
  case "$t" in
    *cinnamon*) echo cinnamon;; *mate*) echo mate;; *xfce*) echo xfce;;
    "") echo "";; *) echo "other:$1";;
  esac
}

det_run() {
  DET_HOSTNAME=""; DET_KERNEL_NAME=""; DET_ID=""; DET_NAME=""; DET_PRETTY=""; DET_VERSION_ID=""
  DET_CODENAME=""; DET_ID_LIKE=""; DET_BASE_NAME=""; DET_BASE_VERSION=""; DET_BASE_CODENAME=""
  DET_MINT_RELEASE=""; DET_MINT_EDITION=""; DET_DESKTOP=""; DET_DESKTOP_SRC=""
  DET_KERNEL=""; DET_ARCH=""; DET_PKGMGR="none"; DET_SUPPORT="unsupported"; DET_SUPPORT_REASON=""
  DET_MISSING_REQUIRED=(); DET_MISSING_OPTIONAL=(); DET_NOTES=()

  tk_cmd uname -s;  DET_KERNEL_NAME=${TK_OUT:-unknown}
  tk_cmd uname -r;  DET_KERNEL=${TK_OUT:-unknown}
  tk_cmd uname -m;  DET_ARCH=${TK_OUT:-unknown}
  tk_cmd hostname;  DET_HOSTNAME=${TK_OUT:-unknown}

  DET_ID=$(det_os_get ID); DET_NAME=$(det_os_get NAME); DET_PRETTY=$(det_os_get PRETTY_NAME)
  DET_VERSION_ID=$(det_os_get VERSION_ID); DET_CODENAME=$(det_os_get VERSION_CODENAME)
  DET_ID_LIKE=$(det_os_get ID_LIKE)
  local ubu_code deb_code
  ubu_code=$(det_os_get UBUNTU_CODENAME); deb_code=$(det_os_get DEBIAN_CODENAME)
  [[ -z "$DET_PRETTY" ]] && DET_PRETTY="${DET_NAME:-unknown} ${DET_VERSION_ID}"

  # Linux Mint extras
  local info; info=$(tkp /etc/linuxmint/info)
  if [[ -r "$info" ]]; then
    DET_MINT_RELEASE=$(sed -n -E 's/^RELEASE=//p' "$info" | head -n1 | tr -d '"')
    local ed; ed=$(sed -n -E 's/^EDITION=//p' "$info" | head -n1 | tr -d '"')
    DET_MINT_EDITION=${ed%% *}          # "Cinnamon 64-bit" -> "Cinnamon"
  fi
  [[ -z "$DET_MINT_RELEASE" && "$DET_ID" == linuxmint ]] && DET_MINT_RELEASE=$DET_VERSION_ID

  # Ubuntu / Debian base
  if [[ -n "$ubu_code" ]]; then
    DET_BASE_NAME=Ubuntu; DET_BASE_CODENAME=$ubu_code; DET_BASE_VERSION=$(det_ubuntu_version "$ubu_code")
  elif [[ -n "$deb_code" ]]; then
    DET_BASE_NAME=Debian; DET_BASE_CODENAME=$deb_code; DET_BASE_VERSION=$(det_debian_version "$deb_code")
  elif [[ "$DET_ID" == ubuntu ]]; then
    DET_BASE_NAME=Ubuntu; DET_BASE_CODENAME=$DET_CODENAME; DET_BASE_VERSION=$DET_VERSION_ID
  elif [[ "$DET_ID" == debian ]]; then
    DET_BASE_NAME=Debian; DET_BASE_CODENAME=$DET_CODENAME; DET_BASE_VERSION=$DET_VERSION_ID
  fi

  # Desktop: edition file is the most reliable (XDG_CURRENT_DESKTOP is dropped by sudo)
  local d
  d=$(det_map_desktop "$DET_MINT_EDITION")
  if [[ -n "$d" ]]; then DET_DESKTOP=$d; DET_DESKTOP_SRC="/etc/linuxmint/info"
  else
    d=$(det_map_desktop "${XDG_CURRENT_DESKTOP:-}")
    if [[ -n "$d" ]]; then DET_DESKTOP=$d; DET_DESKTOP_SRC="XDG_CURRENT_DESKTOP"
    else
      local found=() b
      for b in cinnamon-session:cinnamon mate-session:mate xfce4-session:xfce; do
        { tk_have "${b%%:*}" || [[ -e "$(tkp "/usr/bin/${b%%:*}")" ]]; } && found+=("${b##*:}")
      done
      if [[ ${#found[@]} -eq 1 ]]; then DET_DESKTOP=${found[0]}; DET_DESKTOP_SRC="installed session binary"
      elif [[ ${#found[@]} -gt 1 ]]; then DET_DESKTOP="unknown"; DET_DESKTOP_SRC="multiple installed: ${found[*]}"
      else DET_DESKTOP="unknown"; DET_DESKTOP_SRC="not detected"; fi
    fi
  fi

  # Package manager
  if tk_have apt-get && tk_have dpkg; then DET_PKGMGR="apt/dpkg"
  elif tk_have dpkg; then DET_PKGMGR="dpkg (no apt-get)"
  elif tk_have apt-get; then DET_PKGMGR="apt-get (no dpkg)"; fi

  # Commands
  local c
  for c in "${DET_REQUIRED_CMDS[@]}"; do tk_have "$c" || DET_MISSING_REQUIRED+=("$c"); done
  for c in "${DET_OPTIONAL_CMDS[@]}"; do tk_have "$c" || DET_MISSING_OPTIONAL+=("$c"); done

  # Support classification
  local major=${DET_MINT_RELEASE%%.*}
  if [[ "$DET_KERNEL_NAME" != Linux ]]; then
    DET_SUPPORT=unsupported; DET_SUPPORT_REASON="kernel is '$DET_KERNEL_NAME', not Linux"
  elif [[ -z "$DET_ID" ]]; then
    DET_SUPPORT=unsupported; DET_SUPPORT_REASON="/etc/os-release missing or unreadable; cannot identify the distribution"
  elif [[ "$DET_ID" == linuxmint ]]; then
    if [[ -z "$ubu_code" ]]; then
      DET_SUPPORT=limited; DET_SUPPORT_REASON="Linux Mint without an Ubuntu base (probably LMDE, Debian ${DET_BASE_CODENAME:-?}); outside the 21.x/22.x target"
    elif [[ "$major" == 21 || "$major" == 22 ]]; then
      if [[ ( "$major" == 21 && "$ubu_code" == jammy ) || ( "$major" == 22 && "$ubu_code" == noble ) ]]; then
        if [[ "$DET_PKGMGR" == "apt/dpkg" ]]; then
          DET_SUPPORT=targeted; DET_SUPPORT_REASON="Linux Mint $DET_MINT_RELEASE on Ubuntu $DET_BASE_VERSION ($ubu_code)"
        else
          DET_SUPPORT=limited; DET_SUPPORT_REASON="Mint $DET_MINT_RELEASE detected but apt/dpkg are not both available"
        fi
      else
        DET_SUPPORT=limited; DET_SUPPORT_REASON="Mint $DET_MINT_RELEASE reports Ubuntu base '$ubu_code', which is not the expected base for that release"
      fi
    else
      DET_SUPPORT=limited; DET_SUPPORT_REASON="Linux Mint ${DET_MINT_RELEASE:-?} is outside the targeted 21.x/22.x range"
    fi
  elif [[ "$DET_ID" == ubuntu || "$DET_ID" == debian || "$DET_ID_LIKE" == *debian* || "$DET_ID_LIKE" == *ubuntu* ]]; then
    DET_SUPPORT=limited; DET_SUPPORT_REASON="$DET_PRETTY is Debian/Ubuntu-like but not Linux Mint; Mint-specific checks do not apply"
  else
    DET_SUPPORT=unsupported; DET_SUPPORT_REASON="'$DET_PRETTY' is not a Debian/Ubuntu/Mint system"
  fi

  [[ "$DET_ARCH" != x86_64 && "$DET_ARCH" != amd64 ]] && DET_NOTES+=("architecture '$DET_ARCH' - toolkit expects x86_64 and was not exercised on it")
  [[ "$DET_DESKTOP" == unknown ]] && DET_NOTES+=("desktop environment not detected; desktop checks will be limited")
  [[ ${#DET_MISSING_REQUIRED[@]} -gt 0 ]] && DET_NOTES+=("required commands missing: ${DET_MISSING_REQUIRED[*]} - results may be incomplete")
  return 0
}

det_print() {
  printf '%s== System detection ==%s\n' "$C_BLD" "$C_OFF"
  printf '  Hostname        : %s\n' "$DET_HOSTNAME"
  printf '  Distribution    : %s (ID=%s)\n' "$DET_PRETTY" "${DET_ID:-?}"
  printf '  Version/codename: %s / %s\n' "${DET_VERSION_ID:-?}" "${DET_CODENAME:-?}"
  [[ -n "$DET_MINT_RELEASE" ]] && printf '  Mint release    : %s   edition: %s\n' "$DET_MINT_RELEASE" "${DET_MINT_EDITION:-undetected}"
  printf '  Base system     : %s %s (%s)\n' "${DET_BASE_NAME:-unknown}" "${DET_BASE_VERSION:-?}" "${DET_BASE_CODENAME:-?}"
  printf '  Desktop         : %s (source: %s)\n' "$DET_DESKTOP" "$DET_DESKTOP_SRC"
  printf '  Kernel / arch   : %s / %s\n' "$DET_KERNEL" "$DET_ARCH"
  printf '  Package manager : %s\n' "$DET_PKGMGR"
  printf '  Privileges      : %s\n' "$(tk_is_root && echo root || echo 'non-root (some checks will be reported as unperformed)')"
  [[ ${#DET_MISSING_OPTIONAL[@]} -gt 0 ]] && printf '  Optional cmds missing: %s\n' "${DET_MISSING_OPTIONAL[*]}"
  local col=$C_GRN; [[ "$DET_SUPPORT" == limited ]] && col=$C_YEL; [[ "$DET_SUPPORT" == unsupported ]] && col=$C_RED
  printf '  Support status  : %s%s%s - %s\n' "$col" "$DET_SUPPORT" "$C_OFF" "$DET_SUPPORT_REASON"
  local n; for n in "${DET_NOTES[@]}"; do printf '  note: %s\n' "$n"; done
  case "$DET_SUPPORT" in
    limited) printf '  %sRead-only audit will run best-effort.%s\n' "$C_YEL" "$C_OFF";;
    unsupported) printf '  %sThis system is not supported. Audit needs --force-unsupported.%s\n' "$C_RED" "$C_OFF";;
  esac
  return 0
}
