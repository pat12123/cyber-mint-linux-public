# Usage

The toolkit is **read-only**: it detects, audits and reports. It has no command that changes the system. Fixes are made by you, by hand;
[manual-fixes.md](manual-fixes.md) has the commands for the nine common ones.

## Commands

```
./mint-toolkit.sh detect                       identify OS, edition, desktop, tools, support level
./mint-toolkit.sh audit    [options]           read-only audit
./mint-toolkit.sh forensics-help               print generic read-only commands (runs nothing; use BEFORE changing anything)
./mint-toolkit.sh self-test                    automated tests (fixtures + mocks)
./mint-toolkit.sh help | version
```

| Option | Applies to | Meaning |
|---|---|---|
| `--output-dir DIR` | audit | where reports go (default `./toolkit-output`) |
| `--modules a,b` | audit | run only these modules: `users authentication ssh network firewall services applications permissions updates scheduled_tasks desktop_security connectivity` |
| `--no-color` | all | plain text |
| `--force-unsupported` | audit | best-effort audit on a non-Mint/unsupported system |
| `--profile FILE` | audit | README-derived lists from a file (`key = value` lines: `authorized_users`, `authorized_admins`, `required_services`, `allow_ports`; `#` comments; never executed) |
| `--authorized-users A,B` | audit | accounts the README lists; other regular accounts are reported as *not in your list* (Potential) |
| `--authorized-admins A,B` | audit | who may be an administrator; extra `sudo`/`admin` members are reported (Potential, high) |
| `--required-services S,T` | audit | services the README says must run; shown as *not an issue*, their configuration is still audited |
| `--allow-ports 80,443/tcp` | audit | ports treated as intended; they are not reported as exposed |
| `--scoring-notes FILE` | audit | unresolved items you copied from the official Scoring Report (see below); matching findings are sorted first |
| `--scoring-host HOST[:PORT]` | audit | a host from the official documentation: one DNS lookup + one HTTPS HEAD request, reported as reachable / not reachable |
| `--no-network-probe` | audit | no active connectivity probes at all (no DNS lookup, ping or HTTPS request) |

Exit codes: `0` ok · `1` usage error or failed run · `2` incomplete install · `3` unsupported system (audit without `--force-unsupported`).
The commands `harden` and `rollback` and the option `--dry-run` no longer exist and are rejected as unknown.

## Using the Scoring Report (the authority on what is scored)

The official Scoring Report inside the competition image is the only source of truth about which vulnerabilities are scored.
**The toolkit cannot read it, never touches the scoring software, and never claims a finding earns points or how many.**
You bring the information across by hand:

1. Open the Scoring Report. Copy every item it still lists as unresolved into a text file, one per line. Optionally add `=> FINDING-ID`
   (a finding id from the audit report such as `APP-VSFTPD-ANON`, or a prefix such as `USERS-NOTLISTED`):
   ```text
   # scoring-notes.txt  (comments start with #)
   Anonymous FTP login disabled => APP-VSFTPD-ANON
   Firewall protection has been enabled => FW-UFW-INACTIVE
   Some item I have not mapped yet
   ```
2. `sudo ./mint-toolkit.sh audit --scoring-notes scoring-notes.txt ...`. The report then has:
   * **Remaining scored issues** - each of your notes, the toolkit findings it matches, and whether the toolkit still sees it as open;
   * **Recommended order of work** - your matched findings first, then Confirmed before Potential, then severity, each with a change-risk class
     (Low = read-only, Moderate = narrow change with a rollback path, High = account/authentication/service/firewall/network/system-wide);
   * **Possible unscored weaknesses**, **Unresolved questions**, **Potential penalties** and a **Competition checklist**
     (README read, Scoring Report opened, forensics questions found and answered by you before changing anything, connection status,
     recheck after each change).
3. After each change you make by hand: refresh the Scoring Report, note the item as resolved / still unresolved / needs investigation, then
   re-run the audit with the same notes file to see what is still open.

The file is parsed, never executed; ids may only contain letters, digits, `_` and `-`; at most 200 items are read.

## Connectivity checks

The `connectivity` module reports the default route, DNS resolvers, proxy settings (credentials redacted), outbound firewall policy (UFW/iptables) and
whether the internet is reachable (one DNS lookup of `example.com` and one ping to `1.1.1.1`). Results are *Info* or *Potential* - an offline practice VM is
not an error. With `--scoring-host` one more DNS lookup and one HTTPS HEAD request go to that host only. `--no-network-probe` turns all of this off.
The toolkit does **not** locate, read, stop or contact the scoring software: the connection status shown by the Scoring Report itself is authoritative.

## Recommended workflow for practice

(See [competition-rules.md](competition-rules.md) before using any script in a real round.)

1. Read the competition README completely. Note authorised users/admins, required services, forbidden items.
2. **Forensics questions first** – answer them yourself before anything is changed (`./mint-toolkit.sh forensics-help` prints generic read-only commands).
3. `./mint-toolkit.sh detect` – confirm the system is identified correctly.
4. Open the Scoring Report and note the unresolved items (see above). Then `sudo ./mint-toolkit.sh audit --scoring-notes … --authorized-users … --authorized-admins … --required-services … --allow-ports …` using the lists from the README – open `toolkit-output/audit-*/report.md`.
5. Work through **Confirmed** items, then **Potential** items *against the README*. Items marked *Unperformed* mean "unknown", not "fine".
6. Make fixes by hand, one at a time, using the report's recommendations and [manual-fixes.md](manual-fixes.md). Write down every old value so you can undo it.
7. Re-run the audit to confirm and to see what remains.

## Running as root vs. normal user

The audit works as a normal user but several checks need root and are then reported as **Unperformed**:
`/etc/shadow` (empty passwords, hash algorithms, ageing), `/etc/sudoers*`, `ufw status` rules,
`sshd -T`, per-user crontabs, `at` jobs, process names in `ss -p`, root-only directories in file scans.

**Screen lock is a per-user desktop setting.** It can only be read from that user's session:
* run the audit as the desktop user *without* sudo (limited elsewhere), **or**
* run `sudo ./mint-toolkit.sh audit` from the desktop user's terminal – the toolkit uses `SUDO_USER`'s
  session bus to read only the `gsettings get` / `xfconf-query` values (read-only).

## Reading the output

* Terminal summary – counts, plus one line per Confirmed/Potential finding and a list of unperformed checks.
* `report.md` – every finding with evidence, why it matters, recommended action, side effects,
  and a manual-investigation flag. Redacted.
* `audit.log` – every external command run (with exit code). Useful to see exactly what the audit did.
* `findings.dat` – machine-readable store (fields separated by `0x1f`).

Folders are `chmod 700` and files `600` because reports list account names and system details.
Do not publish them (they are git-ignored).
