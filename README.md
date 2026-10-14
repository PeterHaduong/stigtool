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
   **"All 15 files installed and verified"** (the number can change between versions). If a file shows **BROKEN**,
   the paste changed it. Paste that part again and re-run it; nothing else is affected.
5. Start the tool: `python C:\Tools\STIGTOOL\main.py`. It creates `data/`, `input/`, `output/` and `logs/` itself.
6. Optional: to run the full tests (`python -m unittest discover tests`), save a blank IOS-XE Switch RTR checklist
   from STIG Viewer 2.x and a blank IOS-XE Switch NDM checklist from STIG Viewer 3 into `tests/fixtures/`, as
   `ios-xe-switch-rtr.ckl` and `ios-xe-switch-ndm.cklb`. Without them, the checklist tests are skipped.

**Your rules travel with the program.** `rules/stigtool_rules.json` is the rule library: every rule and the
manual-only list, with author names and edit history removed. It is included in the bundle and the repo.
- On a **new install with no rules**, the tool loads it automatically on first start.
- Import your checklists (*Set up and rules > Checklists*) and the rules attach to them by STIG and Vuln ID.
- Later, use the **Rules** menu, **Export rules...** / **Import rules...**, to move rules between sites or teams. Import only
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
  rules\
    stigtool_rules.json      (the shipped rule library)
  src\
    assess.py  checklist.py  collect.py  drafts.py  gui.py  harden.py  rules.py  store.py
  tests\
    test_core.py  test_drafts.py  platform_samples.py
    fixtures\                (optional sample files)
```

## Team setup (do this once)

1. Put the shared data somewhere the whole team can reach, e.g. `\\server\share\stigtool`.
2. In each person's copy of the tool, create `shared_data_path.txt` next to `main.py` with that path on the first line.
   `data/`, `input/` and `output/` then live on the share. Logs stay on each PC.
3. In the **Team settings** menu, choose the **checklist output format**, either STIG Viewer 2.x (.ckl) or STIG
   Viewer 3 (.cklb).
   Only that format is written.

Working at the same time is safe:
- Each rule and each group is its own file, so people editing different rules never collide.
- Opening a rule locks it. Anyone else who opens it is told who has it, and can open it read-only.
- If two people do save the same rule or group, the second person is asked whether to overwrite, or (for rules)
  to keep both as separate versions. Nothing is lost silently.
- Press **F5** (or switch tabs) to see teammates' changes. The bottom bar shows where the shared data is and who
  you are signed in as.

## The two modes

The switch at the top picks what you see. Each person's choice is remembered on their own PC.

- **Run an assessment** is for collecting, reviewing and writing checklists. Most people only need this mode.
- **Set up and rules** is for importing STIGs, building rules, defining device groups and reviewing fix commands.

Less common actions are in the menu bar (**File, Assessment, Rules, Team settings**). In lists, the **More...**
button and right-click hold the less common actions for the selected row.

## Running an assessment

The **Assessment** tab is one page with four steps, top to bottom:

1. **Collect:** choose the groups in the **groups** dropdown (it has *All groups* and *None*) and click **Copy
   collection script**. Paste it into SolarWinds *Execute Command
   Script*, and save the output as a text file in `input/`. Do not remove the `! CMD:` lines.
   *Assessment > Show the last collection script* shows it again, with how many controls each STIG has automated.
2. **Import:** click **Import SolarWinds output...** and check each device landed in the right group. With many
   devices, use **Find** and **Show** (*Not in a group yet*, *Collection failed or invalid*, or one group), click
   **Select all shown**, then **Change group of the N selected devices...**. The move is remembered for future runs.
   While devices still need a group, the device list takes half the page.
3. **Review:** the tool *recommends* a result for each check. The list opens on **Needs your decision** (unexpected
   Open and Not Reviewed results); choose *Show: Everything* to see all. Change any result; a reviewer comment is
   required. A change you made but did not **Apply** is kept if you click another result, and the tool warns you
   before writing if anything is still not applied. *Not automated (left as is)* means there is no rule for that
   check, so the checklist keeps its current value unless you set one.
4. **Write:** type your full name in **Reviewer (full name)** (it is written into the checklist and remembered on
   this PC) and click **Write checklist package for <GROUP>**. A window says where the package was written and
   lists the checklist files, and offers to open the folder; the line under the button keeps showing the last
   package written, with an **Open folder** button. The package lands in `output/<GROUP>_<date>/`, and its
   `group_assessment_summary.txt` states per STIG how many controls were automated, manual, or not built, and the
   results. *Assessment > Write checklist packages for ALL groups* does every group at once.

To open an older run, use *File > Open previous assessment run*. If a rule or group changes after the results were
made, a yellow **Out of date** bar appears with a **Re-run now** button; re-running keeps your review decisions.
Importing a file that is not SolarWinds output is refused and leaves the current results alone.

## Setting up (Set up and rules)

1. **Checklists:** import the blank checklist for each STIG. There is one row per STIG. Expand it to see every file
   imported for it, with release, date and who imported it. The row turns yellow if the STIG has no file in the
   team's output format, or if rules need review. Right-click a file to remove it.
2. **Rules:** STIGs are grouped under their product (e.g. *Cisco IOS XE Switch* > NDM / RTR / L2S), each with
   how many of its checks are decided. Click a STIG's arrow to list its checks. Search and the State / Severity
   filters open the STIGs that have matches (Severity: *high (CAT I)* to do the most important checks first).
   Click any column heading to sort; this works on every table in the tool. Every check needs a decision. For each
   one, either:
   - click **New rule**. The rule editor has three panes: the **STIG requirement** on the left (commands in grey,
     the "this is a finding" sentences highlighted, a **Find** box, and right-click a `show` command to add it to
     the rule), the **rule** in the middle, and the **test** on the right. You can hide the STIG pane with the tick box
     at the top right. Type the show command, then add conditions such as *"every section that starts with
     `line vty` has a line that contains `transport input ssh`"*. Each condition shows as its own card (*Command /
     Look in / Passes if it*), joined by **AND** (the ALL setting) or **OR** (ANY). Click a card to select it,
     double-click to edit it. For rules with many conditions, tick **Compact** for one line per condition. In the
     condition window, **Start from an example** fills in common patterns (a line must / must not be there, every
     `line vty` section, every access port, a number at most N, at least N lines). Paste real device output on the
     right and the tool colours what it matched (green), what is wrong (red), and which sections it checked (blue).
     Save at least one sample that should pass and one that should fail as **tests**. The line next to **Save rule**
     says what is still missing; when everything passes it shows **Activate and save**. Shortcuts: Ctrl+S saves,
     Enter / Delete on a condition card edits / removes it.
   - or click **Manual only** if the check cannot be answered from show output.

   **Try drafts on real output** (Rules menu; the button on the Rules tab only shows while there are drafts)
   turns the starter drafts into tested, active rules, all in one window:
   1. **Copy collection script for the drafts**, run it in SolarWinds on a few devices of one type (ideally one
      well configured and one not) and save the output.
   2. **Import SolarWinds output...** in that window. This trial import never replaces the assessment, and the
      window remembers the file next time. (*Use the assessment import instead* tries the current assessment.)
   3. **Try the drafts as device group**: each device's own group, or one group you pick (picked for you when
      none of the devices is in a group). Only drafts for that group's STIGs are tried.

   Each draft shows what it would say (e.g. *1 Not a Finding, 1 Open*). *Show: Ready to save tests* lists the ones
   that passed on one device and failed on another. Select a draft to see why, double-click to open it with that
   device's output loaded, **Save samples as tests** (one per different result - only for results you checked
   are right), and **Activate selected**. A draft with the same result everywhere needs a contrasting sample added
   in the editor; *not collected* means the import has no output for its show command.

   **Different logic for some devices (rule versions):** every rule starts as the version **all device groups**
   use (the default). When some devices need different logic - border routers, core switches - select the rule,
   *More... > Add a version for some device groups...*, tick those groups, and edit the copy. Those groups then
   use it automatically; every other group keeps the default. The editor's **Used by** line shows which groups
   use a version and **Change...** edits it. *Device groups > More... > Rule versions* is only for exceptions: a
   group can pick a version for one check by hand, which wins over *Used by* (the tool offers to remove such a
   pick when you give that group its own version).
3. **Device groups:** click **New group** and answer three questions: the group's name, which STIGs it gets, and
   which devices belong (hostname patterns like `*-ACCESS`, with a live preview). For devices whose names follow no
   pattern, click **Add devices...**: search and select many at once, or paste a list of hostnames (from Excel or
   SolarWinds; IP addresses are ignored). On the tab itself, **Find** filters the device list, and **Move to group**
   works on every selected device.
4. **Fix commands:** review the fix commands that hardening scripts use (see *Hardening scripts* below). STIGs are
   grouped by product. **Only STIGs a device group uses** (on by default) keeps the count to fixes that can
   actually reach a device. Ctrl+S saves without marking reviewed.

*Help > Quick start* shows both workflows on one page; it opens by itself the first time on each PC.

**Network share:** the tool reads only files that changed since it last looked, so switching tabs stays fast when
the shared data is on a server.

## Shared rules: one rule for the same check in several STIGs

Many checks appear in more than one STIG. For example, CISC-ND-000010 is in the Switch NDM, the Router NDM and the
NX-OS NDM STIG. Write the rule once and share it:

1. Open the rule and click **Use for other checks...** at the top of the editor.
2. Likely matches are listed first, by the same or similar check text, the same STIG ID or the same title. The
   **Check text same** column shows how alike each check's text is to this one, from 0 to 100%.
3. **Click a row to compare.** The pane underneath shows that check's text word by word against this rule's check:
   red struck-out words are only in this rule's check, green words only in the other one. Case, punctuation and
   switch / router wording are ignored unless you untick that option. Switch to **Fix text** to compare the fixes.
   **Always read the diff, not just the percentage.** Some checks are 96% the same but check different things,
   e.g. auditing account *enabling* vs *disabling*.
4. Mark the ones that really are the same check: click **Share with V-...** (or the row's **Shared** box, or
   double-click the row). To mark several at once, highlight them (Ctrl-click / Shift-click) first.
5. Click **Save: share with the checks marked Yes**, then **Save rule**.

What sharing does:
- A shared rule answers every ticked check. Its tests, fix commands and changes apply to all of them.
- When DISA changes one of those checks, only that check is flagged for review. Marking it reviewed does not touch
  the others.
- A check that already has its own active rule keeps using it. Retire that rule if the shared one should replace it.
- Matches marked **other OS** (IOS-XE vs NX-OS) usually need different show commands. Share only if the tests pass
  there; otherwise make a copy.
- **Make separate copies instead...** creates independent DRAFT rules. Use copies only when a check needs different
  logic, because each copy then has to be fixed on its own.

The **Shared with** column on the Rules tab shows which rules are shared.

## Checking the checklists open in STIG Viewer

To check the checklists before using real output, use a made-up SolarWinds output file whose hostnames match one
of your device groups (`input/` is a good place; it is never committed). Import it on the Assessment page, set a
couple of results by hand, and write the package; then open the checklists in STIG Viewer and, if you use it, load
the `.ckl` files into Vulnerator. Use documentation IP addresses (192.0.2.x) in made-up files. Vulnerator reads
STIG Viewer 2.x `.ckl` files, not STIG Viewer 3 `.cklb`.

## Port roles: rules for uplinks, downlinks, access and trusted ports

Uplinks are not on the same port on every switch, so rules find ports by **what they are**, not by number. The
interface description says what the port is:

```
interface TenGigabitEthernet1/1/3
 description UPLINK - DIST-SW-01 Te2/0/14        <- uplink toward distribution / core
interface GigabitEthernet1/0/24
 description DOWNLINK - ACC-SW-07 Te1/1/1        <- downlink toward an access switch
interface GigabitEthernet1/0/5
 description ACCESS - Room 112 jack 4            <- client port (ACCESS or UNTRUSTED)
interface GigabitEthernet1/0/6
 description TRUSTED - analog gateway rm 112     <- trusted device in a secure room (no 802.1x)
```

**Labelling rules:**
- The keyword goes **first**. Anything after it is free text.
- Upper / lower case does not matter.
- The keywords are a team setting: *Team settings > Port roles* (defaults: `UPLINK`, `DOWNLINK`,
  `ACCESS, UNTRUSTED`, `TRUSTED`).
- **Add your own roles** there too (e.g. `camera` = `CAMERA, CCTV`). Built-in roles can be re-worded but not
  removed, because the starter rules use them. Each keyword can mark only one role.
- Changing a keyword there changes every rule that uses it.
- A port with no label is in **no** role.

**Using roles in a rule** (rule editor, Add condition). Set *Look in* to EVERY section, click **Pick** next to
the section box for "Every interface" or "Front-panel switch ports", then choose **Which ports (by role)**:

| You want | Which ports | Skip shut-down ports | It |
|---|---|---|---|
| every uplink has DHCP-snooping trust | Only: uplink (if none found: FAIL) | yes | has a line (whole line) `ip dhcp snooping trust` |
| nothing else has trust | Every port EXCEPT: uplink | no | has NO line (whole line) `ip dhcp snooping trust` |
| every client port has BPDU Guard, storm control... | Only: access | yes | has a line ... |
| every port that is not infrastructure or trusted has 802.1x (labelled ACCESS or not labelled) | Every port EXCEPT: uplink, downlink, trusted | yes | has a line (whole line) `dot1x pae authenticator` |
| every downlink has Root Guard | Only: downlink | yes | has a line `spanning-tree guard root` |
| every live port is labelled | Any port | yes | has a line `role:any` |

The *also only / also skip* boxes take any other filters, **one per line**: a section must match every
"only" line and is skipped if it matches any "skip" line (e.g. skip `dot1x pae authenticator` *and* trunks).
In the stored rule, roles are written as `role:uplink, downlink, trusted` lines in those same filters.

**Tips:**
- **"If no sections found"** decides what happens on a switch with no port in that role.
  - Use **FAIL** when every switch must have one (every access switch has an uplink). Then an unlabelled
    switch is flagged instead of quietly passing.
  - Use **PASS** when the role is optional (most access switches have no downlinks).
- **Pair "must have" with "must not have"** for trust settings. Trust on a client port is the real danger.
- **"Either / or" per port** (802.1x OR parked): split it into conditions that each skip the ports the other
  covers. Live ports must have 802.1x (skip shut ports); shut ports must be in the parking VLAN (skip ports
  that have 802.1x). The CISC-L2-000020 starter draft is built this way.
- **Catch the obvious violations too:** every port EXCEPT trusted has NO `authentication open` /
  `port-control force-authorized` line.
- **Add a drift check:** every `role:uplink` port has `switchport mode trunk`. A mislabelled port then shows up.
- **Groups without client ports** (core / distribution) still fail the access checks, which is the point for
  access switches. For those groups, choose a different rule version or mark the control N/A.
- **Fix commands per condition:** `{each failing section of condition N}` applies fixes only to the ports that
  failed condition N. For example, add `ip dhcp snooping trust` under failing uplinks (condition 3) and
  `no ip dhcp snooping trust` under failing client ports (condition 4). The starter drafts do exactly this.

**Starter drafts that use roles:**
- DHCP snooping trust and DAI trust on uplinks only.
- Root Guard on downlinks.
- 802.1x (CISC-L2-000020): every front-panel host port that is not an uplink, downlink or trusted port runs
  802.1x or is shut down in VLAN 2 (edit to your parking VLAN); no non-trusted port uses open authentication.
- BPDU Guard, unknown-unicast blocking, IP Source Guard and storm control on access ports.
- User-facing ports must be access ports.
- Every live port must be labelled.

## Asking an AI to write a rule's conditions

In the rule editor, **Ask an AI to write the conditions...** builds a prompt you paste into an AI your
organisation approves. Nothing is sent from the tool.

1. Say in plain words what the rule should check. Optionally paste an example that should **pass** (e.g. a
   good interface) and one that should **fail**. Paste enough config for the whole rule, including any global
   lines it needs (e.g. `dot1x system-auth-control`).
2. **Copy prompt.** It contains:
   - every condition option, generated from the rule engine so it is always current
   - your team's port roles
   - three worked example rules
   - the STIG check and fix text
   - the rule as it is today
   - your goal and examples
   - the test-box sample output, if ticked
   Passwords, secrets, keys and SNMP communities are masked. Hostnames, IP addresses and descriptions are
   **not**, so use **Preview prompt** before sending it anywhere.
3. Paste the AI's whole answer into box 2 and click **Check answer**. The answer is JSON; extra chat around it
   is ignored. The tool then:
   - lists each condition in plain words
   - flags anything the engine cannot run (bad regex, unknown role, unknown field)
   - runs your pass / fail examples and the AI's own samples as tests
4. **Replace** or **Add to** the rule's conditions. Your examples become tests, and so do the AI's samples
   (named `AI: ...`). The AI's explanation goes into Reviewer guidance. Nothing is saved until you click Save.
   The rule is still a draft and still needs passing tests to be activated.

## Starter drafts (a head start on the rules)

*Rules > Create starter drafts* writes a DRAFT rule for every control that has no rule yet, for the Cisco
IOS-XE Switch / Router and NX-OS STIGs. To limit it to one STIG, pick that STIG in the Rules tab's STIG filter first.

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

## Hardening scripts

Each rule can carry fix commands in two boxes:
- **Low impact:** banners, logging, archive / log config, timestamps, legacy services.
- **Impactful:** AAA, SSH algorithms, vty access, port / STP / 802.1x settings, SNMP, routing.

**Fix commands are reviewed separately from the rule.** A rule's tests prove its *check* works, not that its fix is
right, so fix commands are not in the rule editor. They are edited and reviewed on *Set up and rules > Fix commands*:
- Each rule's fix shows as **Not reviewed**, **Reviewed**, or **Rule changed - re-check**.
- **Only reviewed fixes go into hardening scripts.** Unreviewed ones are left out and listed at the top of the script.
- The review covers the fix *and* the rule logic it depends on. If someone changes the rule's show commands or
  conditions, the fix goes back to **Rule changed - re-check**, because `{each failing section of condition 2}` may
  now point at a different condition. Changing only the rule's wording or tests does not.
- The starter drafts come with fix commands for the Catalyst 9300 / 8300 and Nexus 9000. They start as **Not
  reviewed**.

The **Hardening scripts** tab (*Run an assessment* mode) always writes **two separate scripts**, `..._LOW_IMPACT.txt`
and `..._IMPACTFUL.txt`, so the safe changes can go out on their own. There are two ways to build them:
- **From the current assessment run:** one script pair per device, containing only that device's Open controls.
  Interface-level fixes are written under the exact interfaces that failed (e.g. `interface GigabitEthernet1/0/14` /
  `storm-control broadcast level ...`).
- **Baseline:** one script pair for the whole group with every reviewed fix (interfaces left as `<INTERFACE>`).

Boxes that hold device config (fix commands, show commands, sample output, scripts) wrap long lines, but the
wrapped part is indented under its line and every other line is shaded, so one command always reads as one
line. Scripts written to files are never wrapped.

**Site values** (*Team settings > Site values*): long or site-specific text is written once and used by name in
fix commands, e.g. `<DOD_BANNER>`, `<NTP_SERVER_1>`, `<AAA_GROUP>`. The banner fix is just `banner login ^C` /
`<DOD_BANNER>` / `^C`. Hardening scripts fill the values in. The window lists every name the fix commands use and
which ones are not set yet. The DoD banner has a built-in default. In the Fix commands tab, names that are set show
green and names that are not set show yellow. Do not store passwords, keys or community strings as site values:
anyone with the shared data can read them. Fix commands that held the full banner text are shortened to
`<DOD_BANNER>` automatically; a reviewed fix stays reviewed.

In fix commands:
- `<SOMETHING>` is a site value. Values the team has set are filled in; every other one is listed at the top of the
  script under **EDIT BEFORE USE**.
- `{each failing section}` on its own line, followed by indented commands, repeats those commands under every failing
  interface / section.
- Lines starting with `!` are comments.

Scripts start with `configure terminal` and end with `end`. They never save the config; do that after verifying the
device. The impactful script carries a maintenance-window warning. Intentional (risk-accepted) findings are skipped.

## Quarterly DISA updates

1. Import the new release's checklist file on the Checklists tab. The import report says, per STIG, how many controls were added,
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
- Where the reason goes follows team guidance (*Team settings > Where reasons go*). By default:
  - **Not a Finding / Not Applicable / Not Reviewed:** the reason (rule text, evidence, sign-off) goes in **Comments**.
  - **Open:** the reason goes in **Finding Details**.
  - The reviewer's comment always goes in Comments.
  - What a rule says for a result is written in the rule's **Reason text** for that result (Not a Finding, Open,
    Not Applicable), so a sentence like "logging is enabled" never appears on an Open result. Rules used to have
    an "Extra comment" that was added for every result; it was removed. The tool converts old rules once, on
    start and after *Import rules*: a comment that names one result moves to that result's Reason text, any other
    comment is copied to every result's Reason text, so the checklists say what they said before.
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
