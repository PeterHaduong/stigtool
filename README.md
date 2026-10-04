# STIG Group Assessment Tool

Builds group STIG checklists for network devices from SolarWinds show-command output.
It works with STIG Viewer 2.x checklists (`.ckl`) or STIG Viewer 3 checklists (`.cklb`). The team picks one output format.

**Start it:** double-click `main.py`, or run `python main.py`. Needs Python 3.8 or newer. Nothing else to install.

## Moving the tool to another computer (copy and paste only)

You do not need git, email or a zip. The whole program fits in one self-installing Python file.

**On this computer:**
1. Run `python make_bundle.py`. It writes `transfer/STIGTOOL_install.py` (about 250 KB of plain text).
   If your clipboard or remote session cannot paste that much at once, run `python make_bundle.py 40` instead.
   That gives several parts of about 40 KB each (`STIGTOOL_install_part1_of_7.py`, ...).
2. Open the file (or each part) in Notepad, press Ctrl+A, then Ctrl+C.

**On the work computer:**
1. Check Python works: open a Command Prompt and run `python --version` (3.8 or newer) and
   `python -c "import tkinter"` (no error means the GUI library is there).
2. Make a folder, e.g. `C:\Tools`. Open Notepad, paste, and save as `C:\Tools\STIGTOOL_install.py`.
   In the Save dialog choose *Save as type: All files* and *Encoding: UTF-8*, so Notepad does not add `.txt`.
3. Run it: `python C:\Tools\STIGTOOL_install.py`. With parts, save and run every part, in any order.
4. It creates `C:\Tools\STIGTOOL\` with every file and folder, checks each file against a fingerprint, and ends with
   **"All 10 files installed and verified"**. If a file shows **BROKEN**, the paste changed it. Paste that part again
   and re-run it; nothing else is affected.
5. Start the tool: `python C:\Tools\STIGTOOL\main.py`. It creates `data/`, `input/`, `output/` and `logs/` itself.
6. Optional: to run the full tests (`python -m unittest discover tests`), save a blank IOS-XE Switch RTR checklist
   from STIG Viewer 2.x and a blank IOS-XE Switch NDM checklist from STIG Viewer 3 into `tests/fixtures/`, as
   `ios-xe-switch-rtr.ckl` and `ios-xe-switch-ndm.cklb`. Without them, the checklist tests are skipped.

**Your rules travel with the program.** `rules/stigtool_rules.json` is the rule library: every rule and the
manual-only list, with author names and edit history removed. It is included in the bundle and the repo.
- On a **new install with no rules**, the tool loads it automatically on first start.
- Import your checklists on tab 1 and the rules attach to them by STIG and Vuln ID.
- Later, use **Export rules...** / **Import rules...** on tab 2 to move rules between sites or teams. Import only
  adds rules that do not exist yet; it never overwrites.
- Refresh the shipped file before making a new bundle: **Export rules...** to `rules/stigtool_rules.json`.

**Updating later:** make a new bundle, put it *inside* the existing `STIGTOOL` folder and run it. Program files are
replaced; `data/` (rules, groups, imported checklists, runs) is never touched.

**By hand instead (if you cannot run the installer):** recreate this layout and paste each file into place:

```
STIGTOOL\
  main.py
  make_bundle.py
  README.md
  src\
    assess.py  checklist.py  collect.py  gui.py  rules.py  store.py
  tests\
    test_core.py
    fixtures\        (optional sample files)
```

## Team setup (do this once)

1. Put the shared data somewhere the whole team can reach, e.g. `\\server\share\stigtool`.
2. In each person's copy of the tool, create `shared_data_path.txt` next to `main.py` with that path on the first line.
   `data/`, `input/` and `output/` then live on the share. Logs stay on each PC.
3. On tab 1, choose the **team checklist output format**, either STIG Viewer 2.x (.ckl) or STIG Viewer 3 (.cklb).
   Only that format is written.

Working at the same time is safe:
- Each rule and each group is its own file, so people editing different rules never collide.
- Opening a rule locks it. Anyone else who opens it is told who has it, and can open it read-only.
- If two people do save the same rule or group, the second person is asked whether to overwrite, or (for rules)
  to keep both as separate versions. Nothing is lost silently.
- Press **F5** (or switch tabs) to see teammates' changes. The bottom bar shows where the shared data is and who
  you are signed in as.

## The workflow (the tabs, left to right)

1. **Checklists:** import the blank checklist for each STIG. There is one row per STIG. Expand it to see every file
   imported for it, labelled *STIG Viewer 2.x (.ckl)* or *STIG Viewer 3 (.cklb)*, with release, date and who
   imported it. The row turns yellow if the STIG has no file in the team's output format, or if rules need review.
2. **Rule Work Queue:** every control is listed with a state. For each one either:
   - click **New rule**: type the show command, then add conditions such as *"every section that starts with
     `line vty` has a line that contains `transport input ssh`"*. Paste real device output on the right and the tool
     colours what it matched (green), what is wrong (red), and which sections it checked (blue). Save at least one
     sample that should pass and one that should fail as **tests**. Only then can the rule be set **active**.
   - or click **Manual only** if the control cannot be checked from show output.
3. **Device Groups:** click **New group** and answer three questions: the group's name, which STIGs it gets, and
   which devices belong (hostname patterns like `*-ACCESS`, with a live preview). Fix individual devices in the list
   underneath with **Move to group**. **Rule versions** only matters when a control has more than one rule version.
4. **Collection Script:** tick groups, click **Generate**, and paste the script into SolarWinds *Execute Command
   Script*. It also shows, per STIG, how many controls are automated, manual, or not built yet. Save the SolarWinds
   output as a text file in `input/`. Do not remove the `! CMD:` lines.
5. **Import & Review:** import that file, check each device is in the right group, and review each control. The tool
   *recommends* a result, and you can change any of them (a comment is required). Then click **Write checklist
   package**. The package lands in `output/<GROUP>_<date>/`, and its `group_assessment_summary.txt` states per STIG how
   many controls were automated, manual, or not built, and the results.

## Port roles: rules for uplinks, downlinks and access ports

Uplinks are not on the same port on every switch, so rules find ports by **what they are**, not by number. The
interface description says what the port is:

```
interface TenGigabitEthernet1/1/3
 description UPLINK - DIST-SW-01 Te2/0/14        <- uplink toward distribution / core
interface GigabitEthernet1/0/24
 description DOWNLINK - ACC-SW-07 Te1/1/1        <- downlink toward an access switch
interface GigabitEthernet1/0/5
 description ACCESS - Room 112 jack 4            <- client port (ACCESS or UNTRUSTED)
```

**Labelling rules:**
- The keyword goes **first**. Anything after it is free text.
- Upper / lower case does not matter.
- The keywords are a team setting: tab 3, **Port roles...** (defaults: `UPLINK`, `DOWNLINK`, `ACCESS, UNTRUSTED`).
- Changing a keyword there changes every rule that uses it.

**Using roles in a rule** (rule editor, Add condition):

| You want | Look in | Only / skip | It |
|---|---|---|---|
| every uplink has DHCP-snooping trust | EVERY section that starts with `interface` | only: `role:uplink`; if none found: FAIL | has a line (whole line) `ip dhcp snooping trust` |
| nothing else has trust | EVERY section that starts with `interface` | skip: `role:uplink` | has NO line (whole line) `ip dhcp snooping trust` |
| every client port has 802.1x, BPDU Guard, storm control, a parking / user VLAN... | EVERY section that starts with `interface` | only: `role:access`; skip `shutdown` | has a line ... |
| every downlink has Root Guard | EVERY section that starts with `interface` | only: `role:downlink` | has a line `spanning-tree guard root` |
| every live port is labelled | EVERY section that starts with `interface` | skip `shutdown` | has a line `role:any` |

**Tips:**
- **"If no sections found"** decides what happens on a switch with no port in that role.
  - Use **FAIL** when every switch must have one (every access switch has an uplink). Then an unlabelled
    switch is flagged instead of quietly passing.
  - Use **PASS** when the role is optional (most access switches have no downlinks).
- **Pair "must have" with "must not have"** for trust settings. Trust on a client port is the real danger.
- **Add a drift check:** every `role:uplink` port has `switchport mode trunk`. A mislabelled port then shows up.
- **Groups without client ports** (core / distribution) still fail the access checks, which is the point for
  access switches. For those groups, choose a different rule version or mark the control N/A.
- **Fix commands per condition:** `{each failing section of condition N}` applies fixes only to the ports that
  failed condition N. For example, add `ip dhcp snooping trust` under failing uplinks (condition 3) and
  `no ip dhcp snooping trust` under failing client ports (condition 4). The starter drafts do exactly this.

**Starter drafts that use roles:**
- DHCP snooping trust and DAI trust on uplinks only.
- Root Guard on downlinks.
- 802.1x, BPDU Guard, unknown-unicast blocking, IP Source Guard and storm control on access ports.
- User-facing ports must be access ports.
- Every live port must be labelled.

## Starter drafts (a head start on the rules)

On tab 2, **Create starter drafts...** writes a DRAFT rule for every control that has no rule yet, for the Cisco
IOS-XE Switch / Router and NX-OS STIGs. Pick one STIG in the STIG filter first to limit it to that STIG.

- They are written from each control's check text for **Catalyst 9300** (IOS-XE 17.x), **Catalyst 8300**
  (IOS-XE 17.x) and **Nexus 9336C-FX2 / 93180YC-FX3** (NX-OS 9.3/10.x). Where those platforms behave differently,
  the draft does too, e.g. CDP is on by default on the 9300 and off on the 8300.
- Many include a **Not Applicable** check for features that are not configured (BGP, PIM, MSDP, MPLS, IPv6, SNMP).
- Each draft's *Reviewer guidance* tab explains what to adjust, e.g. your parking VLAN, approved software versions,
  or narrowing "external interface" checks to the real external interfaces.
- About a quarter of controls get **no draft**: perimeter / OOBM design, design-plan comparisons, interviews. The
  report (saved in `output/`) lists them with the reason, and offers to mark them **Manual only**.
- Existing rules are never touched, so it is safe to run again after importing new STIGs.
- Drafts cannot be activated until someone reviews them and saves a passing and a failing test sample from a real
  device. That is the point: they are a starting point, not an answer.

## Hardening scripts (tab 6)

Each rule has a **Fix commands** tab with two boxes:
- **Low impact:** banners, logging, archive / log config, timestamps, legacy services.
- **Impactful:** AAA, SSH algorithms, vty access, port / STP / 802.1x settings, SNMP, routing.

The starter drafts come with fix commands for the Catalyst 9300 / 8300 and Nexus 9000.

Tab 6 always writes **two separate scripts**, `..._LOW_IMPACT.txt` and `..._IMPACTFUL.txt`, so the safe changes can go
out on their own. There are two ways to build them:
- **From the current assessment run:** one script pair per device, containing only that device's Open controls.
  Interface-level fixes are written under the exact interfaces that failed (e.g. `interface GigabitEthernet1/0/14` /
  `storm-control broadcast level ...`).
- **Baseline:** one script pair for the whole group with every control's fix (interfaces left as `<INTERFACE>`).

In fix commands:
- `<SOMETHING>` is a site value. Every one is listed at the top of the script under **EDIT BEFORE USE**.
- `{each failing section}` on its own line, followed by indented commands, repeats those commands under every failing
  interface / section.
- Lines starting with `!` are comments.

Scripts start with `configure terminal` and end with `end`. They never save the config; do that after verifying the
device. The impactful script carries a maintenance-window warning. Intentional (risk-accepted) findings are skipped.

## Quarterly DISA updates

1. Import the new release's checklist file on tab 1. The import report says, per STIG, how many controls were added,
   removed, or changed, and lists every active rule affected. Re-importing an identical file is skipped. Importing
   an *older* release only keeps it for history.
2. Select the STIG and click **Compare releases**. Each changed control shows a word-by-word diff (red struck-out =
   removed by DISA, green = added) and whether its rule needs review.
3. For each flagged rule, either open it and adjust it (saving marks it reviewed), or click **Rule still valid - mark
   reviewed**. Either way, who reviewed it and for which release is recorded.

Only changes to the *check text* flag a rule. Changes to the fix text, title or severity are shown in the comparison
for information.

## Rules the tool always follows

- Missing output, failed connections and `% Invalid input` responses are **never** a pass. They give Not Reviewed.
  Empty output from a command that ran *is* evidence (e.g. `show run | include ip http server` printing nothing).
- Group result = the worst device: any Not Reviewed -> Not Reviewed, else any Open -> Open, else all N/A -> N/A,
  else Not a Finding. `finding_details` lists which devices failed and why.
- Where the reason goes follows team guidance (tab 1, **Where reasons go**). By default:
  - **Not a Finding / Not Applicable / Not Reviewed:** the reason (rule text, evidence, sign-off) goes in **Comments**.
  - **Open:** the reason goes in **Finding Details**.
  - The rule's extra comment and the reviewer's comment always go in Comments.
- Only **status**, **finding details** and **comments** are changed in the checklist. Every output is checked
  against its template (`preservation_validation_report.txt`). A failing file is renamed `*.FAILED_VALIDATION`.
- Controls with no rule keep whatever the template says, unless the reviewer sets a result.
- If anything is still Not Reviewed, the package folder ends in `_REVIEW_REQUIRED`.

## Folders

| Folder | What is in it |
|---|---|
| `src/` | the program (`checklist` CKL/CKLB files, `rules` matching engine, `collect` SolarWinds, `assess` groups/results/reports, `store` shared data files, `gui` screens) |
| `data/rules/`, `data/groups/` | one file per rule / group |
| `data/settings.json` | team settings: output format, manual-only controls, device moves, known devices |
| `data/templates/` | imported checklist files (read-only) and their catalogs, every release kept |
| `data/runs/`, `data/evidence/` | assessment runs with reviewer decisions; untouched copies of SolarWinds files |
| `input/`, `output/` | SolarWinds files in; scripts and checklist packages out |
| `logs/` | `stigtool.log` for troubleshooting (local to each PC) |
| `tests/` | automated tests: `python -m unittest discover tests` |

Back up `data/` to keep your rules and groups.
