# Compatibility

## Support levels

| Level | Meaning | Audit |
|---|---|---|
| **targeted** | Linux Mint 21.x on Ubuntu 22.04 *jammy*, or 22.x on Ubuntu 24.04 *noble*, with `apt` and `dpkg` | yes |
| **limited** | Linux, but another Mint (20.x, 23.x…), LMDE, Ubuntu, Debian, or Mint 21/22 without apt/dpkg, or a mismatched Ubuntu base | best effort, with a warning |
| **unsupported** | not Linux, or `/etc/os-release` missing/unrecognised | only with `--force-unsupported` |

"Targeted" means *the code was written for these releases*. It does **not** mean they were verified – see the
table below for what has actually been run.

## What has actually been tested (read this before trusting a claim)

| Environment | Method | Status |
|---|---|---|
| Fixture of **Mint 21.3 Cinnamon** (jammy) – default-like and deliberately weak variants | automated suite, mocked commands, Git Bash on Windows 11 | ✅ passes ([testing.md](testing.md)) |
| Parsing of **Mint 22 / 22.1** (noble) `os-release` + MATE/Xfce edition files | automated detection tests with synthetic files | ✅ detection logic only |
| Detection of Mint 20.3, Mint 23 (hypothetical), LMDE 6, Ubuntu 22.04, Fedora, Darwin, missing os-release | automated | ✅ classified limited/unsupported |
| **Real Linux Mint 21.x VM** | not yet run | ❌ **untested** |
| **Real Linux Mint 22.x VM** | not yet run | ❌ **untested** |
| **Real MATE / Xfce edition** | not yet run | ❌ **untested** |
| The audit against a live system (real `ufw`, `sshd`, LightDM, `sysctl`, `ping`, `getent`, `ip route`) | not yet run – mocks only | ❌ **untested** |

Run `tests/vm_smoke_test.sh` in each VM and add the outcome to [testing.md](testing.md); until then, treat
Mint 21/22 support as **unverified**.

## Desktop editions

| | Cinnamon | MATE | Xfce |
|---|---|---|---|
| Edition detection | `/etc/linuxmint/info` (`EDITION=`), then `XDG_CURRENT_DESKTOP`, then installed session binary | same | same |
| Login manager | LightDM (+ slick-greeter) on all three Mint editions; other managers → "unperformed" | | |
| Screen lock (read) | `gsettings`: `org.cinnamon.desktop.screensaver lock-enabled`, `org.cinnamon.desktop.session idle-delay` (seconds; **unit not verified**) | `org.mate.screensaver lock-enabled`, `org.mate.session idle-delay` (minutes; **unit not verified**) | `xfconf-query -c xfce4-screensaver -lv`; judged: `/lock/enabled=false`, `/saver/idle-activation/enabled=false`. Property names are confirmed from the upstream source (`gs-prefs.h`); a missing property means the compiled default (lock on, idle activation on, 5 min). **Which locker a Mint Xfce image ships (xfce4-screensaver, light-locker, xscreensaver) is unverified** |
| Needs | the user's graphical session (DBus) | same | same |

Autologin/guest checks use LightDM's documented override order
(`/usr/share/lightdm/lightdm.conf.d` → `/etc/xdg/lightdm/lightdm.conf.d` → `/etc/lightdm/lightdm.conf.d` →
`/etc/lightdm/lightdm.conf`, last definition wins; `[Seat:*]`/`[SeatDefaults]` sections).
When fixing by hand, edit the file that currently defines the key (see [manual-fixes.md](manual-fixes.md)); a later definition wins.

## Version-specific notes

* **Mint 21 / Ubuntu 22.04** – `sshd_config` begins with `Include /etc/ssh/sshd_config.d/*.conf`; the SSH drop-in
  in [manual-fixes.md](manual-fixes.md) relies on it (edit `sshd_config` directly if the line is missing). `pam_faillock` is available but not configured by default.
* **Mint 22 / Ubuntu 24.04** – same SSH layout, but sshd is socket-activated (`ssh.socket`); the toolkit treats an active `ssh.socket` as SSH running. *(From Ubuntu documentation; unverified on Mint 22 – check on the VM.)*
* **`pam_tally2` / `pam_cracklib`** are absent on Ubuntu 22.04+/Mint 21+; leftover lines referencing them are reported as a lock-out risk.
* **`lightdm --show-config`** is used as a cross-check of the merged LightDM configuration; its exact output format was not verified on Mint, so a mismatch is reported only as *Potential, low*.
* **Default `nullok`** in `common-auth` is the stock Ubuntu/Mint setting, so it is reported as *Potential*, not *Confirmed*.
* **Mint's `allow-guest` default** is not asserted: if it is not set in any file the toolkit reports "not explicitly disabled" (*Potential*).
* **`ufw status`** needs root; without it only `/etc/ufw/ufw.conf` can be read, so rules are reported *Unperformed*.

## Known limitations

* Never executed on real Linux Mint by this build (see table above).
* Heuristics can be wrong: the SUID baseline is partial (expect some false *Potential* hits), the
  suspicious-pattern list is short (a determined attacker is not detected), the service/port tables cover common cases only.
* File scans (`find`) cover `/etc /usr /bin /sbin /lib /lib64 /opt /var /home /root /srv` on a single filesystem (`-xdev`);
  other mounts are not scanned. Non-root runs skip unreadable directories and say so.
* Pending-update counts depend on locally cached package lists (the toolkit never runs `apt update`).
* Per-user desktop settings are read for one user (the invoking user), not every account.
* No checks yet for: auditd/logging configuration, GRUB passwords, disk encryption, browser settings,
  kernel module blacklists, file integrity (`debsums`), malware scanning.
* `login.defs` password-ageing values only affect *new* accounts; existing accounts need `chage` (see [manual-fixes.md](manual-fixes.md)).
* Output uses ANSI colours only when stdout is a terminal.
