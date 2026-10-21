# Security design, safety guarantees and manual guidance

## Design rules

1. **The toolkit is read-only by construction.** It has no command that changes the system (an earlier version had `harden` and `rollback`;
   both were removed because every automated fix could cost points when the README contradicts it - see [manual-fixes.md](manual-fixes.md)).
   While the audit runs (`TK_MODE=audit`), every external command goes through `tk_cmd`, which checks an allow-list
   (`lib/common.sh: tk_cmd_allowed`): e.g. `systemctl` only `is-active|is-enabled|list-*|show|status|cat`, `apt-get` only with `-s`, `ufw` only `status`,
   `find` never with `-delete/-exec`, `sysctl` never with `-w`, `gsettings` only `get`. A blocked call returns rc 126 and is logged.
   What an audit *does* write: its own report folder (`./toolkit-output/audit-*`, or `--output-dir`), and one
   scratch file in `$TMPDIR` (`/tmp/tk.err.*`) that is deleted on exit. A pre-existing `--output-dir` is never
   chmod'ed or chown'ed; only the run folder the audit creates is.
2. **No secrets in output.** Evidence is filtered for password hashes (`$1$ $5$ $6$ $y$ …`), private-key
   blocks, SSH public-key blobs and `password=/token=/secret=/api_key=` values. Shadow data is reduced to
   the *state* (empty/locked/set) and algorithm id. `authorized_keys` are counted, never printed.
3. **Unknown ≠ fine.** A check that cannot run produces an *Unperformed* finding.
4. **No claims about scoring.** Findings say what the system is configured to do and why that matters. The Scoring Report is the only authority.
5. **Unfamiliar ≠ malicious.** Services, accounts and tools are listed with "check the README" guidance.
   Pattern matches in persistence checks are labelled "worth reading", not "malware".

### What you must do by hand (never automated)
Deleting/locking users · changing passwords · removing packages · disabling/stopping services · SSH configuration · sudoers · PAM ·
firewall rules · cron/timers/startup items · network configuration · permission changes · `apt update/upgrade`.
[manual-fixes.md](manual-fixes.md) has the commands, with their risks, for nine common changes.

## Manual guidance for items the toolkit will not change

**What the research found about PAM (Ubuntu 22.04 / 24.04)** – `pam_tally2` and `pam_cracklib` no longer exist on Ubuntu 22.04+/Mint 21+; a non-optional PAM line for a missing module breaks logins, so the audit flags it (`AUTH-PAM-MISSINGMODULE`). The supported module is `pam_faillock`, configured in `/etc/security/faillock.conf`. Published STIG wiring (22.04 V2R8 / 24.04): `auth [default=die] pam_faillock.so authfail` and `auth sufficient pam_faillock.so authsucc` after `pam_unix.so` in `common-auth`, with `audit`, `silent`, `deny = 3`, `fail_interval = 900`, `unlock_time = 0` in `faillock.conf`. CIS instead uses a `preauth` line first plus `authfail` and an `account` line, via two `pam-auth-update` profiles. Launchpad bug 1966416 shows that dropping the `pam_deny` line after `authsucc` makes lockout silently not work. Pick one scheme; do not mix them. Password quality: CIS sets `minlen = 14` in `/etc/security/pwquality.conf`; the PAM line is `password requisite pam_pwquality.so retry=3`.

**Account lockout (PAM)** – *these snippets are untested on a real image; rehearse them in a VM snapshot first.* Edit with care and keep a root shell open in another terminal while testing. The `[success=1 default=ignore]` skip counts in `common-auth` change when lines are added, so do not just paste lines blindly.
On Mint 21/22 (`pam_faillock` is available), add to `/etc/pam.d/common-auth` *before* `pam_unix.so`:
```
auth    required      pam_faillock.so preauth silent deny=5 unlock_time=900
```
and after it:
```
auth    [default=die] pam_faillock.so authfail deny=5 unlock_time=900
auth    sufficient    pam_faillock.so authsucc deny=5 unlock_time=900
```
and add `account required pam_faillock.so` to `common-account`. Verify with `faillock --user NAME`.
(Syntax differs between PAM versions – check `man pam_faillock` on the image before editing.)

**Password quality** – `sudo apt install libpam-pwquality` (needs repositories) then in `common-password`:
`password requisite pam_pwquality.so retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1`.

**Locking a user / expiring passwords** – `sudo passwd -l USER`, `sudo chage -M 90 -W 14 USER`.
**Sudoers** – only with `sudo visudo` / `sudo visudo -f /etc/sudoers.d/FILE`.
**Services** – `sudo systemctl disable --now NAME` only after confirming the README does not need it.

## Test hooks (not for normal use)

`TK_ROOT` (prefix every file read), `TK_FAKE_EUID`, `TK_ASSUME_BUS`. These exist so the test-suite can run on a developer PC.
Because the toolkit never writes outside its report folder, a stray `TK_ROOT` can only change what the audit reads.

## SSH on Ubuntu 24.04 / Mint 22 (socket activation)

From Ubuntu 22.10, sshd is started on demand by `ssh.socket`, so an **inactive `ssh.service` with an active `ssh.socket` still means SSH is on**. The audit checks both. (Not verified for Mint 21, which is expected to use the classic service.) Always read the effective configuration with `sudo sshd -T`: drop-ins in `/etc/ssh/sshd_config.d/` are read first and the first value wins, so a file such as `50-cloud-init.conf` can override edits to `sshd_config`.

## Network traffic made by the audit

Audit mode never changes the system, but the `connectivity` module sends a few packets: one DNS lookup, one ICMP echo request, and (only with
`--scoring-host`) one DNS lookup and one HTTPS HEAD request to the host you named. The audit guard allows exactly those forms (`ping -c 1 -W N host`,
`curl --head --silent --show-error --output /dev/null --max-time N https://host/`) and blocks every other `ping`/`curl` invocation. `--no-network-probe`
disables them. The toolkit does not search for, read, stop, restart or contact the competition scoring software.

## Reporting a problem
Open an issue with the output of `./mint-toolkit.sh detect`, the finding ID, and the relevant (redacted) evidence.
