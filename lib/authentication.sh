#!/usr/bin/env bash
# authentication.sh - login.defs, PAM password policy, lockout.  Read-only.
# PAM is never modified by this toolkit: a bad PAM edit can lock everyone out.
# Recommended lines are printed for MANUAL application only.

# Active, non-comment PAM lines for a given module name across the common files.
auth_pam_lines() { # module-substring
  local f
  for f in common-auth common-password common-account common-session; do
    local p; p=$(tkp "/etc/pam.d/$f")
    [[ -r "$p" ]] || continue
    grep -E "^[[:space:]]*[^#[:space:]].*$1" "$p" | sed "s|^|$f: |"
  done
}

audit_authentication() {
  local cat="Authentication"
  local ld; ld=$(tkp /etc/login.defs)

  # ---- login.defs (affects NEWLY created accounts only)
  if tk_readable "$ld"; then
    local max min warn enc
    max=$(tk_last_value "$ld" PASS_MAX_DAYS || true); min=$(tk_last_value "$ld" PASS_MIN_DAYS || true)
    warn=$(tk_last_value "$ld" PASS_WARN_AGE || true); enc=$(tk_last_value "$ld" ENCRYPT_METHOD || true)
    local ev="PASS_MAX_DAYS=${max:-<unset>}  PASS_MIN_DAYS=${min:-<unset>}  PASS_WARN_AGE=${warn:-<unset>}  ENCRYPT_METHOD=${enc:-<unset>}"
    if [[ ! "$max" =~ ^[0-9]+$ ]] || (( max >= 99999 )); then
      f_potential low "$cat" "AUTH-LOGINDEFS-MAXDAYS" "login.defs does not limit password age (PASS_MAX_DAYS=${max:-unset})" "$ev" \
        "Sets the default for NEW accounts only; existing accounts keep their own /etc/shadow values." \
        "If the README asks for password ageing, set PASS_MAX_DAYS (e.g. 90) in /etc/login.defs (see docs/manual-fixes.md) and use 'chage' for existing users." \
        "Affects only accounts created afterwards." - yes
    else
      f_info "$cat" "AUTH-LOGINDEFS" "login.defs password ageing defaults" "$ev"
    fi
    case "${enc^^}" in
      SHA512|YESCRYPT|SHA256|BLOWFISH|'') ;;
      *) f_confirmed medium "$cat" "AUTH-LOGINDEFS-ENCRYPT" "login.defs ENCRYPT_METHOD is weak ($enc)" "$ev" \
           "Weak hashing makes stolen hashes quick to crack." "Set ENCRYPT_METHOD to SHA512 or YESCRYPT." "Existing hashes stay weak until each password is changed." - yes;;
    esac
    if [[ ! "$min" =~ ^[0-9]+$ ]] || (( min < 1 )); then
      f_potential low "$cat" "AUTH-LOGINDEFS-MINDAYS" "login.defs has no minimum password age (PASS_MIN_DAYS=${min:-unset})" "$ev" \
        "With no minimum age a user can change a password several times in a row to get back to an old one." \
        "If the README asks for password ageing, set PASS_MIN_DAYS to 1 in /etc/login.defs (new accounts only; 'chage -m 1 USER' for existing ones; see docs/manual-fixes.md)." \
        "Affects only accounts created afterwards." - yes
    fi
    if [[ "$warn" =~ ^[0-9]+$ ]] && (( warn < 7 )); then
      f_potential low "$cat" "AUTH-LOGINDEFS-WARN" "login.defs warns about expiring passwords late (PASS_WARN_AGE=$warn)" "$ev" \
        "Users get fewer than 7 days of warning before a password expires." \
        "Set PASS_WARN_AGE to 7 in /etc/login.defs (see docs/manual-fixes.md)." "Affects only accounts created afterwards." - yes
    fi
    local um; um=$(tk_last_value "$ld" UMASK || true)
    [[ -n "$um" && "$um" != 022 && "$um" != 027 && "$um" != 077 && "$um" != 0022 && "$um" != 0027 && "$um" != 0077 ]] && \
      f_potential low "$cat" "AUTH-LOGINDEFS-UMASK" "login.defs UMASK is permissive ($um)" "UMASK=$um" "New files may be created group/world writable." "Consider 022 or 027." "May affect shared-directory workflows." - yes
  else
    f_unperformed "$cat" "AUTH-LOGINDEFS" "login.defs policy" "$(tkp /etc/login.defs) unreadable"
  fi

  # ---- PAM password quality
  local cp; cp=$(tkp /etc/pam.d/common-password)
  if ! tk_readable "$cp"; then
    f_unperformed "$cat" "AUTH-PAM-PASSWORD" "PAM password policy" "$(tkp /etc/pam.d/common-password) unreadable"
  else
    local pq; pq=$(auth_pam_lines 'pam_pwquality.so|pam_cracklib.so' | grep -E 'common-password' || true)
    local pwq_conf; pwq_conf=$(tkp /etc/security/pwquality.conf)
    local minlen=""
    if [[ -n "$pq" ]]; then
      minlen=$(printf '%s' "$pq" | grep -oE 'minlen=[0-9]+' | head -n1 | cut -d= -f2 || true)
    fi
    if [[ -z "$minlen" ]]; then
      minlen=$(tk_last_value "$pwq_conf" minlen || true)
    fi
    if [[ -z "$pq" ]]; then
      f_potential medium "$cat" "AUTH-PAM-NOQUALITY" "No password-quality PAM module (pam_pwquality / pam_cracklib) is active" "common-password has no pam_pwquality/pam_cracklib line." \
        "Without it the system accepts weak passwords. Whether the README requires complexity is unknown." \
        "Install libpam-pwquality if missing and add: password requisite pam_pwquality.so retry=3 minlen=10 (edit with care, keep a root shell open)." \
        "A wrong PAM edit can prevent logins; test in a second terminal." - yes
    else
      f_info "$cat" "AUTH-PAM-QUALITY" "Password-quality module is active" "$pq"
    fi
    if [[ "$minlen" =~ ^[0-9]+$ ]] && (( minlen < 8 )); then
      f_potential medium "$cat" "AUTH-PAM-MINLEN" "Minimum password length is short ($minlen)" "minlen=$minlen" "Short passwords are easy to brute-force." "Raise minlen (10+ is common) if the README asks for it." "" - yes
    elif [[ -z "$minlen" && -n "$pq" ]]; then
      f_info "$cat" "AUTH-PAM-MINLEN" "No explicit minlen found (module default applies)" "pam_pwquality default minlen is 8 on most releases; verify with 'grep -r minlen /etc/pam.d /etc/security/pwquality.conf'."
    fi
    local pu; pu=$(grep -E '^[[:space:]]*password.*pam_unix\.so' "$cp" || true)
    if [[ -n "$pu" ]]; then
      if [[ "$pu" == *md5* ]]; then
        f_confirmed medium "$cat" "AUTH-PAM-MD5" "pam_unix is configured with the md5 hash option" "$pu" "MD5 hashes are weak." "Replace 'md5' with 'sha512' or 'yescrypt'." "Existing hashes stay weak until passwords change." - yes
      fi
      if [[ "$pu" != *remember=* ]]; then
        f_info "$cat" "AUTH-PAM-REMEMBER" "No password-history ('remember=') option on pam_unix" "$pu"
      fi
    fi
  fi

  # ---- nullok (empty passwords accepted)
  local ca; ca=$(tkp /etc/pam.d/common-auth)
  if tk_readable "$ca"; then
    local nl; nl=$(grep -E '^[[:space:]]*auth.*pam_unix\.so.*nullok' "$ca" || true)
    if [[ -n "$nl" ]]; then
      f_potential medium "$cat" "AUTH-PAM-NULLOK" "PAM allows empty passwords ('nullok')" "common-auth: $nl" \
        "'nullok' lets accounts with an empty password log in. It is the stock Ubuntu/Mint default, so this is a hardening recommendation, not a fault." \
        "Remove 'nullok' from the pam_unix auth line ONLY after making sure no account relies on an empty password." \
        "If any account has an empty password it will be unable to log in." - yes
    fi
    # ---- lockout
    local lk; lk=$(grep -E '^[[:space:]]*auth.*(pam_faillock\.so|pam_tally2\.so|pam_tally\.so)' "$ca" "$(tkp /etc/pam.d/common-account)" 2>/dev/null || true)
    local fl; fl=$(tkp /etc/security/faillock.conf)
    if [[ -n "$lk" ]]; then
      local deny; deny=$(printf '%s' "$lk" | grep -oE 'deny=[0-9]+' | head -n1 || true)
      if [[ -z "$deny" ]]; then
        local dv; dv=$(tk_last_value "$fl" deny || true)
        [[ -n "$dv" ]] && deny="deny=$dv (from faillock.conf)"
      fi
      f_info "$cat" "AUTH-LOCKOUT" "Account lockout module is configured" "${lk}${deny:+
$deny}"
    else
      f_potential medium "$cat" "AUTH-NO-LOCKOUT" "No account lockout (pam_faillock / pam_tally2) configured" "No lockout module found in common-auth/common-account." \
        "Without lockout, online password guessing is not throttled. Not configured on stock Mint." \
        "If the README requires it, add pam_faillock to common-auth/common-account (see docs/security.md). Do this manually and test in a second terminal." \
        "Misconfiguration can lock out legitimate users, including admins." - yes
    fi
  else
    f_unperformed "$cat" "AUTH-PAM-COMMONAUTH" "PAM authentication stack" "$(tkp /etc/pam.d/common-auth) unreadable"
  fi

  auth_audit_pam_modules "$cat"

  # ---- libpam-pwquality installed?
  if tk_cmd dpkg -s libpam-pwquality; then
    f_info "$cat" "AUTH-PKG-PWQUALITY" "libpam-pwquality is installed" "dpkg reports the package is present."
  elif [[ $TK_RC -eq 127 ]]; then
    f_unperformed "$cat" "AUTH-PKG-PWQUALITY" "libpam-pwquality package check" "dpkg not available"
  else
    f_info "$cat" "AUTH-PKG-PWQUALITY" "libpam-pwquality is NOT installed" "dpkg -s libpam-pwquality returned rc=$TK_RC"
  fi

  # ---- root login settings: securetty / console
  if [[ -r "$(tkp /etc/securetty)" ]]; then
    f_info "$cat" "AUTH-SECURETTY" "/etc/securetty exists" "$(wc -l <"$(tkp /etc/securetty)" | tr -d ' ') tty entries (informational; modern PAM ignores it)."
  fi
  return 0
}

# Does a PAM module file exist on this system?
auth_pam_module_exists() { # name.so
  local d g
  shopt -s nullglob
  for d in "$(tkp /lib)"/*/security "$(tkp /usr/lib)"/*/security "$(tkp /lib/security)" "$(tkp /usr/lib/security)" "$(tkp /lib64/security)"; do
    for g in "$d/$1"; do [[ -e "$g" ]] && { shopt -u nullglob; return 0; }; done
  done
  shopt -u nullglob
  return 1
}

# Old checklists still tell people to add pam_tally2/pam_cracklib; they are gone on Ubuntu 22.04+/Mint 21+.
# A required module that does not exist makes PAM fail -> nobody can log in.
auth_audit_pam_modules() {
  local cat=$1 f line mod
  [[ -d "$(tkp /etc/pam.d)" ]] || return 0
  local missing=""
  for f in "$(tkp /etc/pam.d)"/*; do
    [[ -f "$f" && -r "$f" ]] || continue
    while IFS= read -r line; do
      [[ "$line" =~ ^[[:space:]]*# || -z "${line//[[:space:]]/}" ]] && continue
      [[ "$line" =~ ^[[:space:]]*- ]] && continue             # a leading '-' means "ignore if missing"
      for mod in pam_tally2.so pam_tally.so pam_cracklib.so; do
        if [[ "$line" == *"$mod"* ]] && ! auth_pam_module_exists "$mod"; then
          missing+="$(tk_unroot "$f"): $line"$'\n'
        fi
      done
    done <"$f"
  done
  if [[ -n "$missing" ]]; then
    f_confirmed high "$cat" "AUTH-PAM-MISSINGMODULE" "PAM references a module that is not installed (pam_tally2 / pam_cracklib)" "$missing" \
      "pam_tally2 and pam_cracklib were removed from Ubuntu 22.04+/Mint 21+. A non-optional PAM line for a missing module can make authentication fail for everyone." \
      "Replace with pam_faillock (lockout) and pam_pwquality (quality). Make the change from a root shell you keep open, and test a login in a second terminal before closing it." \
      "Editing PAM wrongly can lock you out; see docs/security.md." - yes
  fi
  local ca; ca=$(tkp /etc/pam.d/common-auth)
  if tk_readable "$ca"; then
    local fl; fl=$(grep -E '^[[:space:]]*auth.*pam_faillock\.so' "$ca" || true)
    if [[ -n "$fl" && "$fl" == *authfail* && "$fl" != *authsucc* ]]; then
      f_potential medium "$cat" "AUTH-FAILLOCK-INCOMPLETE" "pam_faillock is only partly configured (authfail without authsucc)" "$fl" \
        "faillock needs both the failure and the success hook to count and reset attempts correctly. (Reviewed from published STIG/CIS patterns; not verified on a live image.)" \
        "Compare with the STIG/CIS layouts in docs/security.md; test in a VM snapshot before using on an image." "A wrong layout locks users out or never locks anyone." - yes
    fi
  fi
  return 0
}
