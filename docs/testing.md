# Testing

> **Read this first.** The automated suite exercises the toolkit against *fixture file trees* and *mocked system
> commands*. It proves the logic (parsing, classification, redaction, confirmation, backup, verification, rollback).
> It does **not** prove that real `ufw`, `sshd`, LightDM, `gsettings` or `apt` behave as the mocks assume.
> That is what the VM procedure below is for. **Do not claim a Mint version/edition is "tested" until its row in
> the VM table is filled in with a real run.**

## Automated suite

```bash
bash tests/run_all.sh                    # everything (about 25 minutes under Git Bash on Windows, a few minutes on Linux)
bash tests/run_all.sh reporting detection   # fast suites only
./mint-toolkit.sh self-test              # same thing from the entry point
```
Results are also written to `tests/last-results.txt` (git-ignored) together with the host and bash version.

| Suite | What it proves |
|---|---|
| `test_reporting.sh` | finding store, unique IDs, input validation, **secret redaction**, encode/decode round-trip, ordering, terminal summary wording, report content (evidence/why/action/side effects/automation/manual) |
| `test_detection.sh` | Mint 21.x/22.x (Cinnamon/MATE/Xfce) → *targeted*; Mint 20/23, LMDE, Ubuntu → *limited*; Fedora, Darwin, missing os-release → *unsupported*; missing `dpkg`; desktop fallbacks; `os-release` is parsed not executed; hardening refused when not targeted |
| `test_audit.sh` | healthy system → **0 confirmed findings** (false-positive guard); every planted weakness found and correctly classed; no secrets in any output file; **audit leaves the system byte-identical** and issues no state-changing command; audit guard blocks 20 mutating commands; unprivileged runs report *Unperformed*; missing utilities; MATE/Xfce/Cinnamon screen-lock paths; CLI behaviour; repeated runs give identical IDs |
| `test_hardening.sh` | root required; dry-run changes nothing; only exact `yes` consents (`y`, `YES`, empty, EOF refused); all nine actions applied + verified; backups byte-identical; manifest/log content; **idempotent re-run**; audit after hardening shows the fixes; full and per-action rollback restores a byte-identical tree; invalid session ids/path traversal rejected; damaged backup reported honestly; injected failures (`sshd -t` fails, reload fails, `sysctl` fails, `ufw enable` fails) **auto-revert**; one failing action does not block others; service-disruption warnings shown; unwritable backup location aborts before any change |

### Latest results (this build)

<!-- RESULTS:BEGIN -->
**Environment actually used:** Windows 11 Home, Git Bash (MSYS2), GNU bash 5.3.15, 2026-10-18.
Fixtures + mocked commands only. **No Linux Mint system, VM or WSL was used for these results.**

| Suite | Passed | Failed | Skipped | Run |
|---|---|---|---|---|
| reporting | 52 | 0 | 0 | 2026-10-20, after the scoring/connectivity changes |
| detection | 39 | 0 | 0 | 2026-10-20, same |
| audit | 271 | 0 | 1 (`chmod 000` unreadable-file case; Windows cannot enforce it) | 2026-10-21, final |
| scoring (new) | 81 | 0 | 0 | 2026-10-20, final |
| hardening | 195 | 0 | 1 (700 mode of the backup directory; Windows cannot report POSIX modes) | 2026-10-21, final (after the Avahi-port and risk-wording fixes) |

Honesty notes:
* The suites were run in parallel rather than through `tests/run_all.sh`, so `tests/last-results.txt` was not regenerated. Run
  `bash tests/run_all.sh` once on your machine for a single consistent run.
* The `scoring` suite covers the Scoring Report notes, the report sections and risk classes, the checklist, the expected-image row, the
  connectivity module and the audit guard for `ping`/`curl`. Hardening tests cover the risk class, notes-first ordering, `results.tsv`
  and the UFW connectivity check (including automatic revert).
* Bugs the suite caught while the toolkit was being built are listed in `CHANGELOG.md`.
* Total automated checks: 638 passed, 0 failed, 2 skipped. **None of them ran on real Linux Mint.**
* Manual run on a real VM (2026-10-20, VirtualBox 7.2.20, **Linux Mint 22.3 Cinnamon** on Ubuntu 24.04, not Mint 21): `detect`, a full
  `sudo audit` (12 modules, no module failed; 1 Confirmed, 23 Potential, 27 Info, 0 Unperformed on a fresh install) and `sudo harden --dry-run`
  all ran correctly, including real `ping`, `getent` and `ip route` output in the new connectivity module. That run found two display flaws
  (Avahi's random UDP ports listed as "unreachable"; the sysctl action's risk text said Low next to class HIGH), both fixed and covered by tests.
  **Not yet done on a real system:** an applied `harden` followed by `rollback`, `--scoring-notes` against real findings, and anything on Mint 21.
<!-- RESULTS:END -->

### Known gaps in the automated suite
* `chmod 000`/unreadable-file behaviour and POSIX mode bits (e.g. the 700 state directory) cannot be exercised on
  Windows; those tests **skip** here and are covered by `tests/vm_smoke_test.sh` on Linux.
* Mocks encode my understanding of tool output formats (`ss`, `ufw status`, `systemctl list-units`, `apt-get -s`,
  `gsettings`). If a real tool prints something different, the VM run is where it will show up.
* ShellCheck has not been run (not installed on the development PC). Run `shellcheck -x mint-toolkit.sh lib/*.sh` and fix findings.

## Setting up a Linux Mint test VM

### Which virtualisation software?
Your PC runs **Windows 11 Home** with a hypervisor already active (Hyper-V/virtualisation-based security is on).
Hyper-V Manager is *not* available on Home. **Use VirtualBox 7.x** (free; works on Windows 11 Home; 7.x can run
alongside the Windows hypervisor, a little slower than on bare metal). Alternatives that also work: VMware Workstation
Pro (free for personal use) – choose one, do not install both.
With 16 GB RAM you can run one VM at a time comfortably.

### Create the VM (repeat per Mint version/edition you want to test)
1. Download the ISO from https://linuxmint.com/download.php (21.3 Cinnamon, 22.x Cinnamon, and MATE/Xfce editions)
   and verify the SHA256 against the value on the download mirror page (`certutil -hashfile file.iso SHA256`).
2. VirtualBox → **New**: Type *Linux*, Version *Ubuntu (64-bit)*; **4096 MB** RAM; **2 CPUs**; **30 GB** dynamically allocated disk;
   enable *EFI* only if you want to; Display: 128 MB video memory, *VMSVGA*.
3. Network: *NAT* (default). That keeps the VM off your LAN. **Do not enable shared folders or clipboard sharing for test VMs.**
4. Boot the ISO, **Install Linux Mint** (erase the virtual disk). Create a user such as `alice` (that is the VM's own account).
5. After install: `sudo apt update && sudo apt full-upgrade -y`, reboot, install Guest Additions only if you need screen resize.
6. **Take a snapshot named `clean-install`** (Machine → Take Snapshot). Always test from a snapshot and revert afterwards:
   *never* run `harden` on your Windows PC or on a non-disposable machine.
7. Copy the toolkit in: `git clone …` inside the VM (NAT gives internet), or a zip over a temporary shared folder you remove afterwards.

### What to run in each VM
```bash
cd cyberpatriot-mint-toolkit && chmod +x mint-toolkit.sh tests/*.sh tests/mocks/*.sh
bash tests/vm_smoke_test.sh               # detect + 2 audits + dry-run; as a normal user
sudo bash tests/vm_smoke_test.sh          # same as root (no more 'Unperformed' for privilege)
bash tests/run_all.sh reporting detection # logic suites on real GNU/Linux tools (mawk, bash 5.1/5.2)
```
Then, **only after taking a snapshot**, make the VM deliberately weak and watch the audit catch it:
```bash
sudo useradd -m -s /bin/bash testuser                    # extra account
sudo passwd -d testuser                                  # empty password
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config   # if openssh-server installed
sudo apt install -y openssh-server vsftpd                # extra services
sudo chmod 666 /etc/passwd /etc/shadow                   # DESTRUCTIVE to the VM's security only
echo '* * * * * root /tmp/x.sh' | sudo tee /etc/cron.d/t # suspicious cron
sudo ./mint-toolkit.sh audit
sudo ./mint-toolkit.sh harden --dry-run
sudo ./mint-toolkit.sh harden          # answer yes/no; try declining, then repeat applying
sudo ./mint-toolkit.sh audit           # confirm the fixes
sudo ./mint-toolkit.sh rollback --list
sudo ./mint-toolkit.sh rollback --session <id>
```
Also run `sudo bash tests/vm_smoke_test.sh --harden`, which automates the apply → audit → rollback → fingerprint comparison.
Test a **required-service** scenario: with SSH running and a remote session open (from the host via a NAT port-forward),
confirm `H-UFW-ENABLE` keeps the session alive, and that `H-SSH-ROOTLOGIN` does not break a normal-user login.

### Record the result
Fill one row per VM. A row counts only if `vm_smoke_test.sh` reported `0 failed`.

| Date | Mint release / edition | Base | How tested | Result | Notes |
|---|---|---|---|---|---|
| *(not yet run)* | 21.3 Cinnamon | jammy | vm_smoke_test + weak-VM scenario | – | |
| *(not yet run)* | 22.x Cinnamon | noble | vm_smoke_test + weak-VM scenario | – | |
| *(not yet run)* | 21.x or 22.x MATE | | vm_smoke_test | – | |
| *(not yet run)* | 21.x or 22.x Xfce | | vm_smoke_test | – | |

## Quick real-Linux sanity check without a full VM (optional)
`wsl --install -d Ubuntu-22.04` (admin PowerShell, then reboot), then inside Ubuntu:
`bash tests/run_all.sh reporting detection audit`. This runs the fixture suites with real GNU tools on a real Linux
kernel; it still does not replace a Mint VM (no LightDM, no Cinnamon/MATE/Xfce).
