# CyberPatriot Mint Toolkit

> **Competition-rules warning.** This toolkit was written with AI assistance. The CyberPatriot 19 Rules Book is reported to prohibit
> AI-created scripts and scripts not written by your own team in competition rounds, and to restrict public posting of
> CyberPatriot scripts. Treat it as a **practice and study tool** unless your coach confirms otherwise, and keep the repository
> private until you have asked. Details and the questions to ask your coach: [docs/competition-rules.md](docs/competition-rules.md).

A **read-only** Bash security **auditing** toolkit for **Linux Mint 21.x / 22.x** (Cinnamon, MATE, Xfce), for practising
CyberPatriot-style image-hardening rounds, where the competition README – not this tool – decides what is required.
**It never changes the system:** it reports problems, and [docs/manual-fixes.md](docs/manual-fixes.md) lists the commands to fix them yourself.

> **Honest status (v0.1.0).** The automated test-suite passes against fixture file-trees and *mocked*
> system commands, run on Windows (Git Bash). **It has not yet been run on a real Linux Mint system.**
> Before relying on it in a competition, run `tests/vm_smoke_test.sh` in a Mint VM and record the result
> in [docs/testing.md](docs/testing.md). Compatibility is stated as *targeted*, not *verified*
> ([docs/compatibility.md](docs/compatibility.md)).

## What it does

| Mode | Command | Changes the system? |
|---|---|---|
| Detect | `./mint-toolkit.sh detect` | No |
| **Audit** | `sudo ./mint-toolkit.sh audit` | **No** – read-only (writes only its own report folder) |
| Forensics helper | `./mint-toolkit.sh forensics-help` | No (prints read-only commands) |
| Self-test | `./mint-toolkit.sh self-test` | No (fixtures + mocks) |

### Audit coverage
Users & sudo · password policy/PAM/lockout · SSH (effective config via `sshd -T`) · listening ports ·
UFW · services · permissions of sensitive files, world-writable files, SUID/SGID · pending/security updates,
insecure apt settings, attack tooling · cron/at/systemd timers/startup/profile persistence ·
LightDM autologin/guest + screen lock for Cinnamon/MATE/Xfce · kernel network settings, promiscuous interfaces ·
application configs (vsftpd, Apache, MySQL/MariaDB, PHP, Samba) and PHP web-shell patterns · `/etc/hosts` redirects ·
leftover `pam_tally2`/`pam_cracklib` that would break logins · sudoers syntax · listening ports mapped to their package.

### Scoring-aware workflow

The audit report ends each run with: remaining scored issues (from notes you copy out of the official Scoring Report), a recommended order of work with
a change-risk class per finding, possible unscored weaknesses, unresolved questions, potential penalties, and a checklist (README, Scoring Report,
forensics questions - answered by **you**, never by the toolkit). It also reports internet/DNS/proxy/outbound-firewall state. It never touches the scoring
software and never states point values. See [docs/usage.md](docs/usage.md#using-the-scoring-report-the-authority-on-what-is-scored).

### Use the README safely (`--profile`, `--authorized-users`, …)

The competition README decides who is authorised and what is required. Tell the toolkit, and it becomes more careful
(it still never deletes users or disables services):
```bash
sudo ./mint-toolkit.sh audit --authorized-users alice,bob --authorized-admins alice \
     --required-services apache2,ssh --allow-ports 80,443
```
Unlisted accounts and surplus administrators are reported as *Potential*; required services are shown as *not an issue*;
`--allow-ports` marks ports as intended so they are not reported as exposed.

### Findings are classified, never exaggerated

* **Confirmed** – insecure regardless of context (e.g. an extra UID 0 account, `PermitRootLogin yes`).
* **Potential** – depends on what the README requires (an FTP server, an extra sudoer, `avahi-daemon`…).
  *Not an error by itself.*
* **Informational** – context.
* **Unperformed** – a check that could not run (not root, tool missing). **Never treated as "passed".**

Every finding carries: unique ID · severity · category · evidence · why it matters · recommended action ·
possible side effects · whether automation is appropriate · whether manual investigation is needed.
Password hashes, private keys and tokens are redacted from all output. The tool never claims anything
about competition points – only your README knows the scoring.

### Fixing things: by hand

An earlier version could apply nine fixes itself after a typed confirmation; every one of them could cost points when the README contradicts it, so
they were **removed**. [docs/manual-fixes.md](docs/manual-fixes.md) explains each one (what it does, how it can cost points, the commands to check,
apply, verify and undo it): file permissions, password ageing, SSH root login / empty passwords, LightDM guest and auto-login, enabling UFW,
kernel network settings and apt signature checking.

Other fixes (accounts, services, packages, PAM/sudo, SUID bits, scheduled tasks) were never automated; the audit gives the evidence and a suggested command.

## Quick start (on Linux Mint)

```bash
git clone https://github.com/<you>/cyberpatriot-mint-toolkit.git   # or unzip the download
cd cyberpatriot-mint-toolkit
chmod +x mint-toolkit.sh tests/*.sh
./mint-toolkit.sh detect                 # what system is this?
sudo ./mint-toolkit.sh audit             # read-only audit  -> toolkit-output/audit-*/report.md
# then fix things yourself, one at a time: docs/manual-fixes.md
```

**Read the competition README first**, and check that the competition rules allow using external scripts.
Screen-lock settings are per-user; to include them run `sudo` from the desktop user's own session
(see [docs/usage.md](docs/usage.md)).

## Requirements
`bash ≥ 4.4`, GNU `coreutils`, `awk`, `sed`, `grep`, `find` (all present on Mint). Optional and
detected at run time: `systemctl`, `ss`/`netstat`, `ip`, `dpkg`, `apt-get`, `ufw`, `sshd`, `sysctl`,
`gsettings`, `xfconf-query`. Missing tools produce *Unperformed* findings, not crashes.

## Documentation
[**Competition rules**](docs/competition-rules.md) · [Installation](docs/installation.md) · [Usage](docs/usage.md) · [Manual fixes](docs/manual-fixes.md) · [Security](docs/security.md) ·
[Compatibility](docs/compatibility.md) · [Testing & VM setup](docs/testing.md) · [Changelog](CHANGELOG.md)

## Project layout
```
mint-toolkit.sh      entry point (detect | audit | forensics-help | self-test)
lib/common.sh        paths, command runner with read-only allow-list
lib/detection.sh     OS / edition / desktop / tool detection + support gating
lib/users.sh authentication.sh ssh.sh network.sh firewall.sh services.sh
lib/applications.sh permissions.sh updates.sh scheduled_tasks.sh desktop_security.sh connectivity.sh   read-only audit modules
lib/scoring.sh       Scoring Report notes, change-risk classes, report sections, checklist
lib/reporting.sh     findings store, redaction, terminal summary, Markdown report
lib/forensics.sh     prints generic read-only commands (runs nothing)
tests/               automated suites, fixtures, command mocks, VM smoke test
docs/                installation, usage, manual fixes, security, compatibility, testing
```

## Troubleshooting
* **`bad interpreter` / `\r` errors** – files were checked out with Windows line endings. Run
  `sed -i 's/\r$//' mint-toolkit.sh lib/*.sh tests/*.sh tests/mocks/*.sh`, or re-clone (`.gitattributes` forces LF).
* **`Permission denied`** – `chmod +x mint-toolkit.sh`, or run `bash mint-toolkit.sh …`.
* **Lots of "Unperformed"** – you are not root; re-run with `sudo`.
* **Results look odd** – the OS is not detected as Mint 21.x/22.x; the audit still runs best-effort (see `detect`).
* **Pending-update counts look stale** – the toolkit never runs `apt update`; refresh lists yourself if allowed.

## Known limitations
See [docs/compatibility.md](docs/compatibility.md#known-limitations). Highlights: never run on real Mint
by the author of this build; Xfce screen-lock property names unverified; heuristics (SUID baseline,
suspicious-pattern matching) can produce false positives *and* miss things; it is no substitute for
reading the README and your own judgement.

License: MIT (edit the copyright line in `LICENSE`).
