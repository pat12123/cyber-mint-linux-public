#!/usr/bin/env bash
# forensics.sh - prints a list of generic read-only commands.  Runs nothing.

tk_forensics_help() {
  cat <<'EOT'
Forensics-question helper (prints suggestions only; runs nothing). Answer the forensics questions BEFORE changing anything.
These are generic Linux commands, not scoring knowledge. Replace PATH/USER/PATTERN as needed.

Find files
  find / -xdev -type f \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.avi' -o -iname '*.mkv' \) 2>/dev/null
  find /home -xdev -type f -newermt '2026-01-01' -printf '%TY-%Tm-%Td %p\n' | sort | tail -50
  find / -xdev -name '.*' -type f -user USER 2>/dev/null          # hidden files owned by a user
  grep -rIl 'PATTERN' /home /etc 2>/dev/null                       # text search
Accounts
  getent passwd | awk -F: '$3==0 || $3>=1000'                       # root-level and human accounts
  getent group sudo; id USER; last -n 20; sudo lastlog | head
  sudo grep -h 'sudo:' /var/log/auth.log | tail -30
Data inspection
  echo 'BASE64TEXT' | base64 -d                                     # decode a Base64 message
  sha256sum FILE; md5sum FILE; file FILE; head -c 64 FILE | xxd     # hashes, type, first bytes (BOM etc.)
  strings FILE | head -50
Processes, network, schedules
  ss -tulnp; ps aux --sort=-%cpu | head; crontab -l; sudo ls -la /etc/cron.* /var/spool/cron/crontabs
Logs
  sudo journalctl -u ssh --since '2 days ago' | tail -50
  sudo grep -E 'Failed|Accepted' /var/log/auth.log | tail -50

Copy each answer into the forensics-question file exactly as the question asks, then re-check it before you change anything.
EOT
}
