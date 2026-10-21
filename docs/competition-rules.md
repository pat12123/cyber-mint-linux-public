# Competition rules and how they affect this toolkit

> **Read this before using the toolkit in any CyberPatriot round, and before publishing it anywhere.**
> This page summarises what automated research found in the official **CyberPatriot 19 (2026-27) Rules Book
> (dated 2 Sep 2026)**. The author of this toolkit (an AI assistant) did **not** read the PDF directly; paragraph numbers
> come from the research notes. Rules change every season. **Your coach / the CyberPatriot Program Office is the
> authority – confirm everything below with them, in writing if possible.**

## The short version

| Question | What the research found | Confidence |
|---|---|---|
| May I use a script **written by AI** (including this toolkit) in a competition round? | **No.** Any script "created in whole or in part" with an AI system is reported as prohibited in any round, even if written beforehand (para 3010.4). Paid AI products may not be used in connection with the competition at all. Free AI tools are allowed only for practice on non-competition images. | Reported from the rulebook; confirm with coach |
| May I use my **own team's** script? | Yes in online rounds, if written by the team's own competitors, used only by that team, and at their own risk (no score correction if it fails) – para 3011.4.5. | Reported; confirm |
| Scripts from **other teams, coaches, mentors**, or shared between teams of the same school? | Not allowed. | Reported; confirm |
| **National Finals** | Pre-written scripts prohibited, whether stored online, on a device or on paper. A separate Finals rules document is published after Semifinals. | Reported; Finals doc not yet seen |
| May I carry a script on a **USB stick**? | In online rounds, media prepared by the team's own competitors is allowed (para 3011.3.A). | Reported; confirm |
| May I download my script from **my own GitHub** during a round? | The research reads this as **not allowed** (para 3011.3.C "staged online"). A generic public tool that is not made for CyberPatriot may be allowed under para 3011.1. | The book does not mention GitHub explicitly – ask |
| May I **publicly post** a CyberPatriot script? | Reported as prohibited, but two paragraphs word the scope differently ("created for CyberPatriot" vs "sole purpose of CyberPatriot"). | Unclear – ask whether a general Mint auditor counts |
| May I paste the README or forensics questions into an AI tool? | **Never** (para 3010.4). | Reported |
| May I touch the CyberPatriot folder or Scoring Service? | No. Do not modify, disable or tamper with them. | Reported |

## What this means for this project

* **This toolkit was written with AI assistance.** On the rulebook text as reported, it is a **practice and study tool**:
  fine for learning, for rehearsing on non-competition images and for understanding what to check by hand – not something to run in a
  scored round unless your coach/Program Office says otherwise.
* **Do not use it to cut corners on learning.** The most useful outcome is that *you* understand each check and can do it by hand
  (`docs/usage.md` and the audit report explain why each item matters and how to fix it manually).
* **Keep the repository private** (or do not upload it) until you have confirmed the posting rule. The GitHub steps in
  `docs/installation.md` are for *your own* private backup/transfer, not for public sharing.
* If your team wants a round-legal script, the safe route is: write it yourselves, by hand, understanding every line, check every
  value against man pages / benchmarks, and ask your coach whether use of AI-assisted *research* during preparation is acceptable.
* The audit feature that *does not change anything* is still only useful during a round if scripts are permitted – again, ask.

## Questions to ask your coach (copy/paste)

1. Does the "no AI-created scripts" rule (CP19 para 3010.4) apply to a script that an AI helped write for practice but that I will not
   use in a round? Does using it for study taint my own later hand-written script?
2. Is a general-purpose Linux Mint security auditor considered "created for CyberPatriot" for the purposes of the public-posting
   rule (3009.3 / 3011.5)? May I keep it in a *private* GitHub repository?
3. For online rounds: may I bring a script I wrote myself on a USB stick I prepared? (para 3011.3.A)
4. Is there any difference for State Round / Semifinals / Open vs All Service vs Middle School?
5. Can you confirm the current rules book version and share any addenda?

## Scoring facts that shaped the toolkit (official and community)

* The results report groups findings into 13 generic categories (access control, insecure services, policy violations, antivirus,
  file sharing/permissions, login policy, malware, password policy, firewall, updates, user policy, forensics questions, miscellaneous).
  Penalties apply when an action makes the system less secure or conflicts with the scenario; **not all vulnerabilities are scored**,
  and undoing a penalised change removes the penalty.
* **The README is authoritative** about authorised users/administrators, required services and prohibited files. This is why the
  toolkit never deletes users or disables services, supports `--authorized-users/--authorized-admins/--required-services/--allow-ports`
  (`docs/usage.md`), and treats most findings as *Potential*.
* Forensics questions are usually answered from evidence that hardening can destroy → answer them before changing anything; `forensics-help` prints generic read-only commands.
* Community checklists commonly recommend `login.defs` ageing of 90/1/7, `ufw default deny incoming`, `tcp_syncookies=1`, home directories
  at 0750, automatic login off and guest login off; some are Ubuntu 14–18-era and out of date (e.g. `pam_tally2`, which no longer
  exists on Ubuntu 22.04+/Mint 21+). The toolkit flags leftover `pam_tally2/pam_cracklib` lines because they can lock everyone out.

Sources: the research notes and report in `research_notes/` and `reports/` (outside this repository) cite the primary URLs.
