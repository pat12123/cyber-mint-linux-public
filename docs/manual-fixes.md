# Manual fixes: what the old hardening actions did, and the commands to do it yourself

The toolkit no longer changes anything. It reports (`audit`) and you decide. These are the nine changes the removed `harden` command used to
make, each with: what it does, how it can cost points, how to check first, the commands, how to verify, and how to undo.

> **Before any change:** read the competition README (it decides what is required), answer the forensics questions (changes can destroy
> the evidence), and write down the old value so you can undo it. Change one thing at a time and refresh the Scoring Report afterwards.
> The commands below are generic Linux; they have **not** been run on a real Mint image by the toolkit's author - try them in a VM snapshot first.
> A change is only "worth it" if the README does not contradict it: the Scoring Report is the only authority on what is scored.

Every command that needs administrator rights starts with `sudo`. `FILE.bak` copies are your undo.

---

## 1. Restore stock permissions on sensitive files (`H-PERMS-SENSITIVE`)

**What it did:** for six files, only if the mode was *looser* than stock or the owner/group was wrong, set the stock mode and owner.

| File | Stock mode | Owner : group |
|---|---|---|
| `/etc/passwd`, `/etc/group` | `644` | `root:root` |
| `/etc/shadow`, `/etc/gshadow` | `640` | `root:shadow` (the audit also accepts `root:root`) |
| `/etc/sudoers` | `440` | `root:root` |
| `/etc/ssh/sshd_config` | `644` | `root:root` |

**Can cost points when:** you loosen something by mistake (for example running `chmod 640` on a file that is already `600`) or break a service
that reads the file as a different group.

**Check first (look, do not change):**
```bash
stat -c '%a %U:%G %n' /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/sudoers /etc/ssh/sshd_config
```
Only fix a file whose mode has *more* permission bits than the table (e.g. `666`, `644` on shadow) or whose owner is wrong. A stricter mode (`600`) is fine; leave it.

**Commands (only for the files that need it):**
```bash
sudo chmod 644 /etc/passwd /etc/group            && sudo chown root:root /etc/passwd /etc/group
sudo chmod 640 /etc/shadow /etc/gshadow          && sudo chown root:shadow /etc/shadow /etc/gshadow
sudo chmod 440 /etc/sudoers                      && sudo chown root:root /etc/sudoers
sudo chmod 644 /etc/ssh/sshd_config              && sudo chown root:root /etc/ssh/sshd_config
```
**Verify:** run the `stat` line again. **Undo:** `sudo chmod OLDMODE FILE; sudo chown OLDOWNER:OLDGROUP FILE` using the values you wrote down.

---

## 2. Password ageing defaults (`H-LOGIN-DEFS`)

**What it did:** in `/etc/login.defs` set `PASS_MAX_DAYS 90`, `PASS_MIN_DAYS 1`, `PASS_WARN_AGE 7`, but only where the current value was weaker
(max above 90 or unset, min below 1, warn below 7). **It affects accounts created afterwards only.**

**Can cost points when:** the README sets different ageing rules, or you also change existing users (see below) in a way the README does not ask for.

**Check:**
```bash
grep -E '^\s*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)' /etc/login.defs
```
**Commands:**
```bash
sudo cp -p /etc/login.defs /etc/login.defs.bak
sudoedit /etc/login.defs        # set:  PASS_MAX_DAYS   90   |   PASS_MIN_DAYS   1   |   PASS_WARN_AGE   7   (one line per key)
```
**Existing users** keep their own values; change them only if the README asks (`chage -l USER` shows them):
```bash
sudo chage -M 90 -m 1 -W 7 USER
```
**Verify:** repeat the `grep`. **Undo:** `sudo cp -p /etc/login.defs.bak /etc/login.defs` (existing users: `chage` back to the values `chage -l` showed before).

---

## 3. and 4. SSH: no root login, no empty passwords (`H-SSH-ROOTLOGIN`, `H-SSH-EMPTYPW`)

**What they did:** wrote `PermitRootLogin no` and `PermitEmptyPasswords no` into a drop-in file, checked `sshd -t`, reloaded ssh.
Only done where the effective value was `PermitRootLogin yes` / `PermitEmptyPasswords yes`.

**Can cost points when:** the README requires SSH root login (rare), or the file has a typo and SSH stops working. Skip entirely if SSH is not installed.

**Check the effective values (root needed):**
```bash
sudo sshd -T | grep -iE '^(permitrootlogin|permitemptypasswords)'
grep -n '^Include' /etc/ssh/sshd_config          # must show: Include /etc/ssh/sshd_config.d/*.conf
```
Drop-ins are read first and the **first value wins**, so name the file so it sorts before others such as `50-cloud-init.conf`.

**Commands:**
```bash
printf 'PermitRootLogin no\nPermitEmptyPasswords no\n' | sudo tee /etc/ssh/sshd_config.d/00-local.conf
sudo sshd -t && sudo systemctl reload ssh          # reload only if sshd -t printed nothing
```
If there is no `Include` line, edit `/etc/ssh/sshd_config` directly instead (back it up first with `sudo cp -p`).
**Verify:** repeat `sudo sshd -T | grep ...`. **Undo:** `sudo rm /etc/ssh/sshd_config.d/00-local.conf && sudo sshd -t && sudo systemctl reload ssh`.
Keep a second terminal open while you test.

---

## 5. LightDM: no guest sessions (`H-LIGHTDM-GUEST`)

**What it did:** set `allow-guest=false` in the `[Seat:*]` section (editing the active line if `/etc/lightdm/lightdm.conf` already set it, otherwise a drop-in).

**Can cost points when:** the README says guest login must stay. Takes effect after the login screen restarts (log out / reboot).

**Check:**
```bash
grep -rn 'allow-guest' /etc/lightdm/ /usr/share/lightdm/lightdm.conf.d/ 2>/dev/null
lightdm --show-config | grep -i allow-guest
```
**Commands** (if `/etc/lightdm/lightdm.conf` has its own `allow-guest=true` line, change that line instead):
```bash
sudo mkdir -p /etc/lightdm/lightdm.conf.d
printf '[Seat:*]\nallow-guest=false\n' | sudo tee /etc/lightdm/lightdm.conf.d/99-local.conf
```
The Mint **Login Window** tool (menu) may offer the same setting; its exact tab names are not verified here.
**Verify:** `lightdm --show-config | grep -i allow-guest` (the toolkit's own check read the files, not this output). **Undo:** delete the drop-in (or restore the edited line).

---

## 6. LightDM: no automatic login (`H-LIGHTDM-AUTOLOGIN`)

**What it did:** emptied `autologin-user` and set `autologin-guest=false` where they were set.

**Can cost points when:** the README says a user must log in automatically.

**Check:**
```bash
grep -rnE 'autologin-(user|guest)' /etc/lightdm/ /usr/share/lightdm/lightdm.conf.d/ 2>/dev/null
```
**Commands:** edit the file that contains the active line (it wins over drop-ins sorted before it), or add to the drop-in from step 5:
```bash
printf '[Seat:*]\nautologin-user=\nautologin-guest=false\n' | sudo tee /etc/lightdm/lightdm.conf.d/98-local-autologin.conf
```
**Verify and undo:** as in step 5.

---

## 7. Firewall: enable UFW (`H-UFW-ENABLE`) - the one most likely to cost points

**What it did:** `default deny incoming`, `default allow outgoing`, allow SSH if it was running, allow your `--allow-ports`, then enable UFW.
**Can cost points when:** a service the README requires (web, FTP, Samba, SSH...) listens on a port you did not allow, or UFW blocks outgoing traffic
that updates or score reporting need.

**Check what must stay reachable first:**
```bash
sudo ufw status verbose
sudo ss -tulnp                       # listening services and their ports
```
**Commands - allow rules BEFORE enabling:**
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp                # only if SSH is running and required
sudo ufw allow 80/tcp                # one line per required service/port from the README
sudo ufw enable
```
**Verify:** `sudo ufw status verbose`, then test the required services and an internet connection, and check the connection status in the Scoring Report.
**Undo:** `sudo ufw disable` (rules stay stored); to remove one rule `sudo ufw delete allow 80/tcp`.

---

## 8. Kernel network settings (`H-SYSCTL-NET`)

**What it did:** set four values (only where different): `net.ipv4.tcp_syncookies=1`, `net.ipv4.conf.all.accept_redirects=0`,
`net.ipv4.conf.all.send_redirects=0`, `net.ipv4.conf.all.accept_source_route=0`.

**Can cost points when:** the machine is a router/VPN gateway that needs redirects (unusual on a workstation image).

**Check (write down the old values):**
```bash
sysctl net.ipv4.tcp_syncookies net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_source_route
```
**Commands:**
```bash
sudo tee /etc/sysctl.d/99-local-net.conf >/dev/null <<'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
EOF
sudo sysctl -p /etc/sysctl.d/99-local-net.conf
```
**Verify:** repeat the `sysctl` check. **Undo:** `sudo rm /etc/sysctl.d/99-local-net.conf`, then `sudo sysctl -w KEY=OLDVALUE` for each key you changed.

---

## 9. apt: signature checking (`H-APT-INSECURE`)

**What it did:** commented out apt options that switch off package signature checks (`AllowUnauthenticated`, `AllowInsecureRepositories`,
`AllowDowngradeToInsecureRepositories` set to true), with a backup.

**Can cost points when:** a repository that the README requires is deliberately unsigned (it stops working until signed).

**Check:**
```bash
grep -RnE 'AllowUnauthenticated|AllowInsecureRepositories|AllowDowngradeToInsecureRepositories' /etc/apt/apt.conf /etc/apt/apt.conf.d/ 2>/dev/null
```
**Commands (for each file the grep shows):**
```bash
sudo cp -p /etc/apt/apt.conf.d/FILE /etc/apt/apt.conf.d/FILE.bak     # keep the backup OUTSIDE apt.conf.d if you prefer
sudoedit /etc/apt/apt.conf.d/FILE                                    # put // in front of the offending line(s)
```
(apt ignores `*.bak` files in `apt.conf.d`, but moving the copy to your home folder is cleaner.)
**Verify:** repeat the `grep` (commented lines starting with `//` are fine), then `sudo apt-get update` still works. **Undo:** restore the backup.

---

## What the audit also recommends (never automated)

These were always manual because the right answer depends on the README: removing or changing users and groups, stopping or disabling services,
PAM and sudo edits, removing packages, removing SUID bits, scheduled tasks and prohibited files. The audit report gives the evidence and a suggested
command for each finding. Read the README first; a user or service the README lists is not a problem, and removing it can cost points.
