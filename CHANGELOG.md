# Changelog

## 0.2.0 - unreleased (research-driven improvements)

### Added (later)
* New read-only checks: `AUTH-LOGINDEFS-MINDAYS`, `AUTH-LOGINDEFS-WARN` (password ageing), `UPD-AUTO` (automatic security updates, now Potential instead of Info),
  `UPD-GAMES` (installed games), `DESK-FIREFOX-INSECURE` (Firefox preferences that weaken the browser). Commands in `docs/manual-fixes.md` step 10.
* `practice/make-vm-vulnerable.sh` + `practice/README.md`: a VM-only script that deliberately weakens a Mint VM for practice (refuses to run elsewhere).

### Removed
* **Hardening and rollback.** The `harden` and `rollback` commands, `--dry-run/--list/--session/--action`, the forensics gate that belonged to `harden`,
  `lib/hardening.sh` and its test suite are gone: every one of the nine automated fixes could cost points when the README contradicts it.
  The toolkit now only reports. `docs/manual-fixes.md` explains each former action and gives the commands to check, apply, verify and undo it by hand.
  Findings no longer name automated fixes. (A copy of the previous version with hardening is in `cyberpatriot-mint-toolkit-with-harden-backup`.)

### Added
* `docs/competition-rules.md`: what the CP19 Rules Book is reported to say about scripts, AI, USB, GitHub and public posting; a visible notice on `audit`/`harden`.
* README-derived lists: `--profile`, `--authorized-users`, `--authorized-admins`, `--required-services`, `--allow-ports` (validated, never executed).
* Forensics-first gate in `harden` and a read-only `forensics-help` command.
* New `applications` audit module (vsftpd, Apache, MySQL/MariaDB, PHP, Samba, PHP web-shell patterns).
* New checks: leftover `pam_tally2`/`pam_cracklib` (lock-out risk), partial `pam_faillock`, `visudo -c`, ssh.socket activation, `/etc/hosts` redirects, home-directory modes, listener-to-package mapping, `lightdm --show-config` cross-check, Xfce idle activation.
* UFW action: opens `--allow-ports` before enabling and warns which listening services it would block.

* Scoring-aware workflow: `--scoring-notes`, report sections (remaining scored issues, recommended order with change-risk class, possible unscored weaknesses, unresolved questions, potential penalties, checklist), expected-image row (Mint 21.x per project notes).
* `connectivity` audit module (route, DNS, proxy, outbound firewall, internet probe, optional `--scoring-host`), `--no-network-probe`; UFW action re-checks connectivity and restores on failure.
* Hardening records a result per action (`results.tsv`: confirmed / unresolved / needs investigation) and shows each action's risk class.

### Changed
* `H-LOGIN-DEFS` defaults are now 90/1/7 (values used in CyberPatriot training material) instead of 90/7/14.
* Documentation: competition-rules warning, private-repository advice, PAM/SSH findings from the research.

### Fixed (found by the first real run on a Mint 22.3 VM)
* The UFW proposal no longer lists Avahi's random high UDP ports as "would become unreachable" (they only receive replies to Avahi's own queries).
* The "Risk:" line of each hardening proposal now describes effects only; the rating is shown once, as "Risk class", so the two can no longer disagree (e.g. "Low" next to "HIGH" for the sysctl action).

## 0.1.0 - 2026-10-18 (initial release)

### Added
* `detect`, `audit`, `harden`, `rollback`, `self-test` commands.
* Detection of distribution, Mint release/edition, Ubuntu/Debian base, desktop, kernel, architecture, package
  manager and tool availability; `targeted` / `limited` / `unsupported` classification.
* Read-only audit modules: users/sudo, authentication/PAM, SSH, network/sysctl, UFW, services, permissions
  (sensitive files, world-writable, SUID/SGID, unowned), updates/apt, scheduled tasks & persistence,
  LightDM + screen-lock for Cinnamon / MATE / Xfce.
* Findings model (Confirmed / Potential / Informational / Unperformed), secret redaction, terminal summary and
  Markdown report.
* Audit-mode command allow-list that blocks any state-changing command.
* Nine confirmation-based hardening actions with backups, manifest, change log, verification, automatic revert and rollback.
* Automated test-suite (reporting, detection, audit, hardening) using fixtures and command mocks; VM smoke test script.

### Bugs found and fixed by the test-suite during development
* SSH `Include` globs were expanded against the real filesystem before the root prefix was applied.
* Report writer failed on a format string beginning with `-`.
* SSH module wrongly concluded "not installed" when `dpkg` was unavailable but `sshd_config` existed.
* UID-0 impostors were double-reported as "system account with a shell".
* Rollback left behind a directory the toolkit had created (now tracked and removed if empty).
* The ssh reload during an automatic revert ran before the drop-in was removed (ordering fixed).
* `audit --output-dir` on an existing folder changed its permissions (and ownership under sudo); now only the run folder is touched.
* Rollback now refuses manifest entries with relative or `..` paths.

### Known gaps
See README and `docs/compatibility.md`. Not yet verified on a real Linux Mint system.
