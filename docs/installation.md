# Installation

## On the Linux Mint machine

### Option A – git (needs network)
```bash
sudo apt install git          # usually already installed on Mint
git clone https://github.com/<your-user>/cyberpatriot-mint-toolkit.git
cd cyberpatriot-mint-toolkit
chmod +x mint-toolkit.sh tests/*.sh tests/mocks/*.sh
```

### Option B – download a ZIP / copy from USB
```bash
unzip cyberpatriot-mint-toolkit-main.zip && cd cyberpatriot-mint-toolkit-main
chmod +x mint-toolkit.sh tests/*.sh tests/mocks/*.sh
```
(Or skip `chmod` and run everything as `bash mint-toolkit.sh …`.)

### Verify the download
```bash
head -1 mint-toolkit.sh | od -c | head -2        # must end in \n, not \r \n
./mint-toolkit.sh version
./mint-toolkit.sh self-test                       # ~10 minutes on slow machines; optional
```
If you see `\r`, the files have Windows line endings: `sed -i 's/\r$//' mint-toolkit.sh lib/*.sh tests/*.sh tests/mocks/*.sh`.

### Dependencies
Everything required ships with Linux Mint: `bash` ≥ 4.4 (Mint 21: 5.1, Mint 22: 5.2), `coreutils`,
`gawk`/`mawk`, `sed`, `grep`, `findutils`. Optional tools are detected at run time (`./mint-toolkit.sh detect`
lists any that are missing). **The toolkit installs nothing.**

### Competition rules
Check the CyberPatriot rules and your round's README for what you may download or run. Fetching a script from
GitHub at competition time may be restricted; decide beforehand (and ask your coach), e.g. carry it on a USB
stick if permitted. Never rely on network access being available.

## On your Windows development PC

The toolkit only *runs* on Linux, but you can develop and run the automated tests on Windows:

| Need | Why | Get it |
|---|---|---|
| **Git for Windows** (includes Git Bash) | run the fixture/mock test-suite (`bash tests/run_all.sh`) and use git | https://git-scm.com/download/win (already on this PC) |
| **VirtualBox 7.x** (+ Extension Pack optional) | disposable Linux Mint VMs for real testing | https://www.virtualbox.org/wiki/Downloads |
| **Linux Mint ISOs** | 21.3 Cinnamon, 22.x Cinnamon, and MATE/Xfce editions | https://linuxmint.com/download.php (verify the SHA256 listed on the mirror page) |
| **ShellCheck** (optional) | static analysis of the Bash | `winget install koalaman.shellcheck` or https://github.com/koalaman/shellcheck/releases |
| **WSL2 + Ubuntu 22.04** (optional) | quick real-Linux bash/coreutils run of the unit tests | `wsl --install -d Ubuntu-22.04` in an admin PowerShell, reboot |

See [testing.md](testing.md#setting-up-a-linux-mint-test-vm) for the VM walkthrough.

## Publishing to GitHub (your own repository) - read the rules first

> **Do not make this repository public until your coach confirms it is allowed** (see [competition-rules.md](competition-rules.md): the
> rulebook is reported to restrict public posting of CyberPatriot scripts, to prohibit AI-created scripts in rounds, and to bar
> downloading your own staged scripts during a round). Create a **private** repository and use it only as a backup/transfer for
> practice. Do not rely on `git clone` during a competition.
```powershell
cd cyberpatriot-mint-toolkit
git init -b main
git config user.name "Your Name"                  # once per repository (or use --global)
git config user.email "you@example.com"           # or your GitHub noreply address
git add .                         # NOT "git add --renormalize ." - that only re-adds files git already tracks
git status                        # REVIEW the file list: no reports, logs, backups, keys
git diff --cached --stat
# make the scripts executable inside git even though Windows has no exec bit (run each command on its own line):
git update-index --chmod=+x mint-toolkit.sh tests/run_all.sh tests/vm_smoke_test.sh tests/mocks/dispatch.sh
git commit -m "Initial import of CyberPatriot Mint Toolkit"
git branch -M main
git remote add origin https://github.com/<you>/cyberpatriot-mint-toolkit.git
git push -u origin main
```
Create the (preferably **private** until the season ends) repository on github.com first. Before pushing, search
for secrets: `git grep -nEi "password|secret|token|BEGIN .*PRIVATE"` – the only matches should be documentation and
the fake test strings in `tests/fixtures/` (marked `FAKE…FORTESTSONLY`).
