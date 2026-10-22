# Testing

> **Read this first.** The automated suite exercises the toolkit against *fixture file trees* and *mocked system
> commands*. It proves the logic (parsing, classification, redaction, report content, the read-only guarantee).
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
| `test_detection.sh` | Mint 21.x/22.x (Cinnamon/MATE/Xfce) → *targeted*; Mint 20/23, LMDE, Ubuntu → *limited*; Fedora, Darwin, missing os-release → *unsupported*; missing `dpkg`; desktop fallbacks; `os-release` is parsed not executed; `harden`, `rollback` and `--dry-run` no longer exist and are rejected as unknown |
| `test_audit.sh` | healthy system → **0 confirmed findings** (false-positive guard); every planted weakness found and correctly classed; no secrets in any output file; **audit leaves the system byte-identical** and issues no state-changing command; audit guard blocks 20 mutating commands; unprivileged runs report *Unperformed*; missing utilities; MATE/Xfce/Cinnamon screen-lock paths; CLI behaviour; repeated runs give identical IDs |
| `test_scoring.sh` | Scoring Report notes (ordering, matching, hostile input rejected, 200-item cap), report sections (remaining scored issues, recommended order, unscored weaknesses, unresolved questions, potential penalties, checklist), change-risk classes, expected-image row, the `connectivity` module (route, DNS, proxy redaction, outbound firewall, internet probe, `--scoring-host`, `--no-network-probe`) and the audit guard that allows exactly one `ping` / one `curl` form |

### Latest results (this build)

<!-- RESULTS:BEGIN -->
**Environment actually used:** Windows 11 Home, Git Bash (MSYS2), GNU bash 5.3.15, 2026-10-18.
Fixtures + mocked commands only. **No Linux Mint system, VM or WSL was used for these results.**

| Suite | Passed | Failed | Skipped | Run |
|---|---|---|---|---|
| reporting | 52 | 0 | 0 | 2026-10-21, after hardening was removed |
| detection | 42 | 0 | 0 | 2026-10-21, same |
| audit | 314 | 0 | 1 (`chmod 000` unreadable-file case; Windows cannot enforce it) | 2026-10-21, same |
| scoring | 81 | 0 | 0 | 2026-10-21, same |

Honesty notes:
* The suites were started individually (two at a time at most: four in parallel exhausted Git Bash's process limit and crashed two of them, which
  were then re-run alone), so `tests/last-results.txt` was not regenerated. Run `bash tests/run_all.sh` once for a single consistent run.
* `test_hardening.sh` (195 tests at its last run) was deleted together with `harden`/`rollback`; those numbers no longer count.
* The `scoring` suite covers the Scoring Report notes, the report sections and risk classes, the checklist, the expected-image row, the
  connectivity module and the audit guard for `ping`/`curl`.
* Bugs the suite caught while the toolkit was being built are listed in `CHANGELOG.md`.
* Total automated checks: 489 passed, 0 failed, 1 skipped. **None of them ran on real Linux Mint.**
* Real-VM run 2026-10-21 (VirtualBox, **Linux Mint 22.3 Cinnamon**, non-root): `tests/vm_smoke_test.sh` passed 7 of 7 (detect, two audits with identical finding ids, the audit changed no watched file, no password hash in the report). It exposed three false positives that are now fixed and covered by tests: the stock `alias ls='ls --color=auto'` in `.bashrc`, the stock Samba `map to guest = bad user` / `usershare allow guests = yes` lines, and one port finding reported twice (IPv4 + IPv6). Not yet run on a real system: the root run (`sudo`), `--scoring-notes` against real findings, and anything on Mint 21.
* Manual run on a real VM (2026-10-20, VirtualBox 7.2.20, **Linux Mint 22.3 Cinnamon** on Ubuntu 24.04, not Mint 21): `detect`, a full
  `sudo audit` (12 modules, no module failed; 1 Confirmed, 23 Potential, 27 Info, 0 Unperformed on a fresh install) and `sudo harden --dry-run`
  (a command that has since been removed) all ran correctly, including real `ping`, `getent` and `ip route` output in the new connectivity module. That run found two display flaws
  (Avahi's random UDP ports listed as "unreachable"; the sysctl action's risk text said Low next to class HIGH), both fixed and covered by tests.
  **Not yet done on a real system:** `--scoring-notes` against real findings, the practice script `practice/make-vm-vulnerable.sh`, and anything on Mint 21.
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
   *never* run `practice/make-vm-vulnerable.sh` on your Windows PC or on a non-disposable machine.
7. Copy the toolkit in: `git clone …` inside the VM (NAT gives internet), or a zip over a temporary shared folder you remove afterwards.

### What to run in each VM
```bash
cd cyberpatriot-mint-toolkit && chmod +x mint-toolkit.sh tests/*.sh tests/mocks/*.sh
bash tests/vm_smoke_test.sh               # detect + 2 audits; as a normal user
sudo bash tests/vm_smoke_test.sh          # same as root (no more 'Unperformed' for privilege)
bash tests/run_all.sh reporting detection # logic suites on real GNU/Linux tools (mawk, bash 5.1/5.2)
```
Then, **only after taking a snapshot**, make the VM deliberately weak and watch the audit catch it with the practice script, which refuses to
run anywhere but a Mint VM (see [../practice/README.md](../practice/README.md)):
```bash
sudo bash practice/make-vm-vulnerable.sh     # type the confirmation phrase it asks for, then reboot and snapshot "weak-baseline"
sudo ./mint-toolkit.sh audit --authorized-users YOU,alice,bob --authorized-admins YOU,bob --required-services ssh,apache2 --allow-ports 22,80
# fix things by hand (docs/manual-fixes.md), then audit again to confirm
```
There is no longer a `harden`/`rollback` to test: the fixes are manual, and the audit is how you confirm them.

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
