#!/usr/bin/env bash
# scoring.sh - connects findings to the competition workflow.  Read-only.
#
# What this file does NOT do: it never locates, reads, modifies, stops or probes the competition's
# scoring software, and it never claims that a finding earns points or how many.  The official
# Scoring Report inside the image is the only authority on what is scored.  The user copies the
# unresolved items from it into a plain notes file (--scoring-notes); the toolkit only uses those
# notes to order and label its own findings.
#
# Notes file: one item per line, '#' starts a comment line.
#     <free text from the Scoring Report>  [=> FINDING-ID-PREFIX[,PREFIX...]]
# A prefix matches a finding id exactly or as "PREFIX-..." (USERS-NOTLISTED matches USERS-NOTLISTED-mallory),
#  The file is parsed, never executed.

TK_SCORING_NOTES="${TK_SCORING_NOTES:-}"
TK_EXPECT_MINT="${TK_EXPECT_MINT-21}"      # expected Mint major version (project notes: CyberPatriot 19 Round 1); empty = no expectation
SC_NOTE_TEXT=(); SC_NOTE_PFX=(); SC_NOTE_MATCH=()
SC_SCORED_IDS=","

# Risk class of acting on a finding: Low = read-only (everything the audit does), Moderate = narrow change with a
# rollback path, High = account / authentication / service / firewall / network / system-wide changes.
SC_HIGH_CATEGORIES="Users and privileges|Authentication|SSH and remote access|Network exposure|Firewall|Services|Connectivity"

sc_finding_risk() { # category automation-id(unused) -> risk class of acting on the finding
  case "|$SC_HIGH_CATEGORIES|" in *"|$1|"*) printf 'High';; *) printf 'Moderate';; esac
}

# ---------------------------------------------------------------- notes file
sc_trim() { local s=$1; s=${s#"${s%%[![:space:]]*}"}; s=${s%"${s##*[![:space:]]}"}; printf '%s' "$s"; }

sc_load_notes() { # file
  local f=$1 line text pfx p n=0 clean arr
  if [[ ! -f "$f" || ! -r "$f" ]]; then tk_err "scoring notes file not readable: $f"; return 1; fi
  SC_NOTE_TEXT=(); SC_NOTE_PFX=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    line=$(printf '%s' "$line" | LC_ALL=C tr -cd '[:print:]\t')
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    n=$((n+1))
    if [[ $n -gt 200 ]]; then tk_warn "scoring notes: only the first 200 items are used"; break; fi
    text=$line; pfx=""
    if [[ "$line" == *"=>"* ]]; then text=${line%%=>*}; pfx=${line#*=>}; fi
    text=$(sc_trim "$text"); text=${text:0:300}
    [[ -z "$text" ]] && text="(no description)"
    clean=""
    IFS=, read -ra arr <<<"$pfx"
    for p in "${arr[@]}"; do
      p=$(sc_trim "$p"); [[ -z "$p" ]] && continue
      if [[ "$p" =~ ^[A-Za-z0-9_-]+$ ]]; then clean+="${clean:+,}$p"; else tk_warn "scoring notes: ignoring invalid id prefix '$p'"; fi
    done
    SC_NOTE_TEXT+=("$text"); SC_NOTE_PFX+=("$clean")
  done <"$f"
  return 0
}

# After the audit: which findings do the notes point at?  Sets SC_SCORED_IDS (",a,b,") and SC_NOTE_MATCH[i].
sc_compute_scored() {
  SC_SCORED_IDS=","; SC_NOTE_MATCH=()
  [[ -s "${TK_FINDINGS:-/dev/null}" ]] || return 0
  local i p ids arr
  for ((i=0; i<${#SC_NOTE_TEXT[@]}; i++)); do
    ids=""
    IFS=, read -ra arr <<<"${SC_NOTE_PFX[$i]}"
    for p in "${arr[@]}"; do
      [[ -z "$p" ]] && continue
      ids+=$(awk -F"$TK_US" -v p="$p" '($1=="CONFIRMED"||$1=="POTENTIAL"||$1=="UNPERFORMED") && ($4==p || index($4,p "-")==1){printf "%s,", $4}' "$TK_FINDINGS")
    done
    ids=${ids%,}
    SC_NOTE_MATCH[i]=$ids
    [[ -n "$ids" ]] && SC_SCORED_IDS+="$ids,"
  done
  return 0
}

sc_is_scored() { [[ "$SC_SCORED_IDS" == *",$1,"* ]]; }
sc_scored_count() { local t=${SC_SCORED_IDS#,}; t=${t%,}; [[ -z "$t" ]] && { echo 0; return; }; awk -v s="$t" 'BEGIN{n=split(s,a,","); for(i=1;i<=n;i++) u[a[i]]=1; c=0; for(k in u) c++; print c}'; }

# ---------------------------------------------------------------- expected image
sc_expect_text() {
  local exp=$TK_EXPECT_MINT
  [[ -z "$exp" ]] && return 0
  if [[ -z "${DET_MINT_RELEASE:-}" ]]; then
    printf 'Linux Mint %s.x expected (project notes: CyberPatriot 19 Round 1) - but this system is not detected as Linux Mint' "$exp"
  elif [[ "${DET_MINT_RELEASE%%.*}" == "$exp" ]]; then
    printf 'Linux Mint %s.x expected (project notes: CyberPatriot 19 Round 1) - matches (%s)' "$exp" "$DET_MINT_RELEASE"
  else
    printf 'Linux Mint %s.x expected (project notes: CyberPatriot 19 Round 1) - DIFFERS: detected %s. Version-specific checks (PAM modules, SSH socket activation, LightDM paths) may not match this image; the detected version is what the toolkit acts on' "$exp" "$DET_MINT_RELEASE"
  fi
}
sc_expect_warn() { # stderr warning only when the expectation is not met
  local t; t=$(sc_expect_text)
  [[ "$t" == *DIFFERS* || "$t" == *"not detected as"* ]] && tk_warn "$t."
  return 0
}

# ---------------------------------------------------------------- checklist
sc_checklist_items() {
  cat <<'EOT'
Read the competition README completely: authorised users and administrators, required services and software, prohibited files, any passwords or rules it gives.
Open the Scoring Report inside the image. Note every vulnerability it still lists as unresolved and any penalties; this toolkit cannot read it and cannot tell what is scored.
Find the forensics questions (and any other scored questions the README points to) and answer them yourself, before changing anything. The toolkit never answers them, and answers from a previous image do not apply to this one.
Save any evidence the questions need (users, files, logs, scheduled tasks) before changing anything: changes can destroy it. `forensics-help` lists read-only commands.
Check the internet/scoring connection status shown by the Scoring Report or scoring client itself. The toolkit's connectivity checks are only a proxy and it never touches the scoring software.
After each change: refresh the Scoring Report, then record the item as resolved, still unresolved, or needs investigation. Watch for new penalties.
Re-run the audit with `--scoring-notes` to compare, and undo by hand any change that caused a penalty (note the old value before every edit).
EOT
}

sc_terminal_lines() {
  sc_compute_scored
  if [[ ${#SC_NOTE_TEXT[@]} -gt 0 ]]; then
    local nomatch=0 i
    for ((i=0; i<${#SC_NOTE_TEXT[@]}; i++)); do [[ -z "${SC_NOTE_MATCH[$i]:-}" ]] && nomatch=$((nomatch+1)); done
    printf '  Scoring Report notes      : %s item(s); %s toolkit finding(s) matched and listed first; %s item(s) without a matching finding\n' \
      "${#SC_NOTE_TEXT[@]}" "$(sc_scored_count)" "$nomatch"
  else
    printf '  Scoring Report notes      : none supplied (the toolkit cannot know what is scored; see --scoring-notes)\n'
  fi
}

sc_terminal_checklist() {
  printf '\n%sChecklist (also in the report):%s\n' "$C_BLD" "$C_OFF"
  printf '  [ ] README read      [ ] Scoring Report opened and unresolved items noted\n'
  printf '  [ ] Forensics questions found and answered by you BEFORE changing anything (the toolkit never answers them)\n'
}

# ---------------------------------------------------------------- report sections (markdown on stdout)
sc_md() { local s=$1; s=${s//|/\\|}; s=${s//$'\n'/ }; printf '%s' "$s"; }

sc_report_sections() {
  sc_compute_scored
  local class sev cat id title ev why act side auto manual i m st mm n shown
  local legend='Change risk: **Low** = read-only (everything this audit did); **Moderate** = narrow change with understood effects and a rollback path; **High** = account, authentication, service, firewall, network or system-wide changes that need careful review.'

  printf '## Remaining scored issues (from your Scoring Report notes)\n\n'
  if [[ ${#SC_NOTE_TEXT[@]} -eq 0 ]]; then
    printf 'No Scoring Report notes were supplied, so **this report cannot say which findings are scored**. The official Scoring Report inside the image is the only authority. Copy each vulnerability it still lists as unresolved into a text file (one per line, optionally followed by `=> FINDING-ID`) and re-run with `--scoring-notes FILE`. Until then every finding below has *unknown* scoring relevance, and no point values are shown because the toolkit does not know them.\n\n'
  else
    printf '| Scoring Report item (your words) | Matching toolkit findings | Status |\n|---|---|---|\n'
    for ((i=0; i<${#SC_NOTE_TEXT[@]}; i++)); do
      m=${SC_NOTE_MATCH[$i]:-}
      if [[ -z "${SC_NOTE_PFX[$i]}" ]]; then st="no mapping given - investigate manually"; mm="-"
      elif [[ -n "$m" ]]; then st="the toolkit also sees this as open"; mm=${m//,/, }
      else st="no matching finding now: fixed, or the toolkit has no check for it - refresh the Scoring Report"; mm="-"; fi
      printf '| %s | %s | %s |\n' "$(sc_md "${SC_NOTE_TEXT[$i]}")" "$(sc_md "$mm")" "$st"
    done
    printf '\nThese are the items to work on first. Matching findings are sorted to the top everywhere in this report.\n\n'
  fi

  printf '## Recommended order of work\n\n%s\n\n' "$legend"
  printf 'Order: findings named in your Scoring Report notes, then Confirmed before Potential, then by severity. Potential items depend on the README. No point values are shown.\n\n'
  printf '| # | Finding | Class / severity | In your Scoring Report notes | Change risk |\n|---|---|---|---|---|\n'
  n=0
  while IFS="$TK_US" read -r class sev cat id title ev why act side auto manual; do
    [[ "$class" == CONFIRMED || "$class" == POTENTIAL ]] || continue
    n=$((n+1)); [[ $n -gt 40 ]] && break
    st="no"; sc_is_scored "$id" && st="**yes**"
    [[ ${#SC_NOTE_TEXT[@]} -eq 0 ]] && st="unknown"
    printf '| %s | `%s` %s | %s / %s | %s | %s |\n' "$n" "$id" "$(sc_md "$(rp_dec "$title")")" "$class" "$sev" "$st" "$(sc_finding_risk "$cat" "$auto")"
  done < <(rp_sorted)
  [[ $n -eq 0 ]] && printf '| - | (no Confirmed or Potential findings) | | | |\n'
  [[ $n -gt 40 ]] && printf '\n(first 40 shown; the full list follows below)\n'
  printf '\n'

  printf '## Possible unscored weaknesses\n\n'
  if [[ ${#SC_NOTE_TEXT[@]} -eq 0 ]]; then
    printf 'Scoring relevance is unknown (no notes). Findings that are objectively insecure are listed under *Confirmed security issues* below; the rest depend on the README.\n\n'
  else
    printf 'Findings that are **not** named in your notes. They may be real weaknesses (fixing them is good practice) but there is no evidence they are scored, and changing them can trigger penalties if the README requires the current state.\n\n'
    shown=0
    while IFS="$TK_US" read -r class sev cat id title ev why act side auto manual; do
      [[ "$class" == CONFIRMED || "$class" == POTENTIAL ]] || continue
      sc_is_scored "$id" && continue
      shown=$((shown+1)); [[ $shown -gt 40 ]] && { printf -- '- ... more in the detailed sections\n'; break; }
      printf -- '- `%s` (%s, %s): %s\n' "$id" "$class" "$sev" "$(sc_md "$(rp_dec "$title")")"
    done < <(rp_sorted)
    [[ $shown -eq 0 ]] && printf '(none)\n'
    printf '\n'
  fi

  printf '## Unresolved questions\n\n'
  printf -- '- Forensics questions and other scored questions: the toolkit cannot know whether you have found and answered them.\n'
  printf -- '- Is each *Potential* finding required by the README? Compare before changing anything.\n'
  for ((i=0; i<${#SC_NOTE_TEXT[@]}; i++)); do
    if [[ -z "${SC_NOTE_MATCH[$i]:-}" ]]; then printf -- '- Scoring Report item with no matching finding: "%s"\n' "$(sc_md "${SC_NOTE_TEXT[$i]}")"; fi
  done
  while IFS="$TK_US" read -r class sev cat id title ev why act side auto manual; do
    [[ "$class" == UNPERFORMED ]] && printf -- '- Check not performed (%s): %s\n' "$id" "$(sc_md "$(rp_dec "$title")")"
  done < <(rp_sorted)
  printf '\n'

  printf '## Potential penalties\n\n'
  printf 'Changes that can cost points or break the scenario. The toolkit never makes the first group on its own:\n\n'
  printf -- '- deleting or modifying accounts, passwords or group membership the README lists as required or authorised\n'
  printf -- '- stopping or disabling a service the README says must run, or blocking its port in the firewall\n'
  printf -- '- editing PAM or sudo configuration (a mistake can lock everyone out)\n'
  printf -- '- removing packages or files the README or a service needs; stripping SUID/SGID or permissions broadly; deleting scheduled tasks you do not recognise\n'
  printf -- '- upgrading the whole operating system\n'
  printf -- '- touching the scoring software or its configuration (never do this)\n\n'
  printf 'Findings whose fix has known side effects (check the README first):\n\n'
  shown=0
  while IFS="$TK_US" read -r class sev cat id title ev why act side auto manual; do
    [[ "$class" == POTENTIAL || "$class" == CONFIRMED ]] || continue
    [[ -n "$side" ]] || continue
    shown=$((shown+1)); [[ $shown -gt 25 ]] && { printf -- '- ... more in the detailed sections\n'; break; }
    printf -- '- `%s`: %s\n' "$id" "$(sc_md "$(rp_dec "$side")")"
  done < <(rp_sorted)
  [[ $shown -eq 0 ]] && printf '(none)\n'
  printf '\n'

  printf '## Competition checklist\n\n'
  sc_checklist_items | while IFS= read -r line; do printf -- '- [ ] %s\n' "$line"; done
  printf '\n'
}
