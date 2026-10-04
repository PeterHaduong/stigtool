"""STIGTOOL installer - part 1 of 1 (bundle 434d3eee).

HOW TO USE: save this text as a .py file and run it:   python <this file>
  - Run every part of the bundle (1 in total), in any order.
  - The program is created in a STIGTOOL folder next to this file, or updated in place if this file
    is inside an existing STIGTOOL folder. Your data/ folder is never touched.
  - Every file is checked against a fingerprint, so a bad copy/paste is caught.
Do not edit the lines below that start with #
"""
import hashlib
import sys
from pathlib import Path


def norm(text):
    return "\n".join(line.rstrip() for line in text.split("\n")).rstrip("\n") + "\n"


def main():
    me = Path(__file__).resolve()
    if len(sys.argv) > 1:
        target = Path(sys.argv[1]).resolve()
    elif (me.parent / "main.py").exists():
        target = me.parent
    else:
        target = me.parent / "STIGTOOL"
    stash = target / "_install_parts"
    stash.mkdir(parents=True, exist_ok=True)
    files, manifest, current, buf = {}, {}, None, []
    for line in me.read_text(encoding="utf-8").splitlines():
        if line.startswith("#@ HAS "):
            manifest[line.split()[2]] = line.split()[3]
        elif line.startswith("#@ FILE "):
            # #@ FILE <path> SHA <hash> CHUNK <i> OF <n>
            f = line.split()
            current, buf = (f[2], f[4], int(f[6]), int(f[8])), []
        elif line.startswith("#@ END") and current:
            path, sha, i, n = current
            (stash / f"434d3eee_{path.replace('/', '__')}.{i}").write_text("\n".join(buf) + "\n", encoding="utf-8")
            files[path] = (sha, n)
            current = None
        elif current is not None and line.startswith("#|"):
            buf.append(line[2:])
    if not files:
        sys.exit("Nothing found to install - was the whole file pasted?")
    waiting, bad = 0, 0
    for path, (sha, n) in sorted(files.items()):
        pieces = [stash / f"434d3eee_{path.replace('/', '__')}.{i}" for i in range(1, n + 1)]
        if not all(p.exists() for p in pieces):
            have = sum(p.exists() for p in pieces)
            print(f"  waiting  {path}  ({have} of {n} pieces - run the other part(s))")
            waiting += 1
            continue
        text = norm("".join(p.read_text(encoding="utf-8") for p in pieces))
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != sha:
            print(f"  BROKEN   {path}  - the copy/paste changed it. Paste the part(s) holding it again.")
            bad += 1
            continue
        dest = target / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8", newline="\n")
        for p in pieces:
            p.unlink()
        print(f"  OK       {path}")
    (target / "tests" / "fixtures").mkdir(parents=True, exist_ok=True)
    try:
        stash.rmdir()  # only succeeds once no pieces are left
    except OSError:
        pass

    def installed(path, sha):
        dest = target / path
        return dest.exists() and hashlib.sha256(norm(dest.read_text(encoding="utf-8")).encode()).hexdigest() == sha
    missing = [p for p, sha in sorted(manifest.items()) if not installed(p, sha)]
    print()
    if bad:
        print(f"{bad} file(s) failed the fingerprint check. Nothing is broken - paste those parts again and re-run.")
    elif missing:
        print("Not finished yet - still to come from the other part(s): " + ", ".join(missing))
    else:
        print(f"All {len(manifest)} files installed and verified in {target}")
        print(f"Start it with:   python \"{target / 'main.py'}\"")


main()

# ---------------------------------------------------------------- payload (do not edit below)

#@ HAS main.py 8ab08b56d237926575fea933200ff6a3512516dcdb3480265899e9d3a9cd0f94
#@ HAS make_bundle.py 96afd027344b6418198835a8087f8961c4e1ae5d2821959b6ca5e4dbb45027f7
#@ HAS README.md 32cf8aae07c1921ced823a18b053960593f63785148908c800cdccc0609df3d2
#@ HAS src/assess.py aa8a3b694f465727b9657355dde187864d84f00c2e0b04e6e47c2e4a3a39ed77
#@ HAS src/checklist.py 205b37b3d87a31835d67152c9f5d995c86fb36f4c06c5f5f1f61d106baa53e13
#@ HAS src/collect.py 60df480238255a693ab3481021c573e05be7cb1c45d734f66c542f9bcdaa8b6f
#@ HAS src/drafts.py 012f72bf07afaeea55ec277b778d340f03da6d1cedf0028707a67c1d91e4d261
#@ HAS src/gui.py 8bff799407cb90a8c02294265365e045ef0a5424f6794ad15e953a449422670c
#@ HAS src/harden.py f20c86d706178bc610dbf0790b05e3ba1b881180c9b693d6910b96e43684284f
#@ HAS src/rules.py a9679ac673b07b57241ef375bf0786497485006aa2a915b5f34c56c98517c246
#@ HAS src/store.py eaea8d81254834e1465d9588faab49bfb769799f36080975144c590122d046f3
#@ HAS tests/test_core.py 55d0281fbbf79e4961b0dc2fb6461066de91b70486ad95a6dd95418b9ef7f827
#@ HAS tests/test_drafts.py f4183f61ab7095f8aae70b9479b4fd906ecc4d202fe527e462201c542e8e6479
#@ HAS tests/platform_samples.py 2cf4431390d9477b1cedf08cb8583909181889b1ca2aeb51ef5dc8dd5bc4ad0e
#@ HAS rules/stigtool_rules.json 5a309ccf4a5781d11ba69a023f9825c882d29e77124d4dbb2cb99562ff3a55e5
#@ FILE main.py SHA 8ab08b56d237926575fea933200ff6a3512516dcdb3480265899e9d3a9cd0f94 CHUNK 1 OF 1
#|"""STIG Group Assessment Tool - start here.
#|
#|    python main.py
#|
#|Launches the GUI. All logic lives in src/. Needs only the Python standard library (3.8+).
#|"""
#|import logging
#|import sys
#|import traceback
#|from pathlib import Path
#|
#|ROOT = Path(__file__).resolve().parent
#|sys.path.insert(0, str(ROOT / "src"))
#|
#|
#|def show_error(title, message):
#|    try:
#|        import tkinter
#|        from tkinter import messagebox
#|        root = tkinter.Tk()
#|        root.withdraw()
#|        messagebox.showerror(title, message)
#|        root.destroy()
#|    except Exception:
#|        print(f"{title}: {message}", file=sys.stderr)
#|
#|
#|def main():
#|    try:
#|        import store
#|        store.ensure_folders()
#|        logging.basicConfig(filename=store.paths.logs / "stigtool.log", level=logging.INFO,
#|                            format="%(asctime)s %(levelname)s %(message)s")
#|    except Exception as e:
#|        show_error("Startup failed", f"Could not create the project folders next to main.py:\n{e}")
#|        return 1
#|    try:
#|        import gui
#|        app = gui.App()
#|
#|        def on_error(exc, value, tb):
#|            logging.error("Unhandled error:\n%s", "".join(traceback.format_exception(exc, value, tb)))
#|            from tkinter import messagebox
#|            messagebox.showerror("Error", f"{value}\n\nDetails were written to logs/stigtool.log")
#|
#|        app.report_callback_exception = on_error
#|        logging.info("Started by %s", store.current_user())
#|        app.mainloop()
#|    except Exception as e:
#|        logging.exception("Startup failed")
#|        show_error("Startup failed", f"{e}\n\nDetails were written to logs/stigtool.log")
#|        return 1
#|    return 0
#|
#|
#|if __name__ == "__main__":
#|    sys.exit(main())
#@ END
#@ FILE make_bundle.py SHA 96afd027344b6418198835a8087f8961c4e1ae5d2821959b6ca5e4dbb45027f7 CHUNK 1 OF 1
#|"""Pack the whole program into self-installing .py file(s) that can be moved by copy and paste.
#|
#|    python make_bundle.py              -> transfer/STIGTOOL_install.py (one file)
#|    python make_bundle.py 60           -> several parts of at most ~60 KB each, for small clipboards
#|
#|On the other computer: paste each part into a new .py file (e.g. in Notepad, save as
#|STIGTOOL_install_part1.py), then run each one with Python, in any order. When the last part has been
#|run, every program file is rebuilt and checked against its fingerprint. Rules, groups and imported
#|checklists (data/) are never included and never touched.
#|"""
#|import hashlib
#|import sys
#|from pathlib import Path
#|
#|ROOT = Path(__file__).resolve().parent
#|FILES = ["main.py", "make_bundle.py", "README.md", "src/assess.py", "src/checklist.py", "src/collect.py",
#|         "src/drafts.py", "src/gui.py", "src/harden.py", "src/rules.py", "src/store.py", "tests/test_core.py", "tests/test_drafts.py",
#|         "tests/platform_samples.py"]
#|# Optional files: shipped when present (the exported rule library).
#|OPTIONAL = ["rules/stigtool_rules.json"]
#|
#|INSTALLER = r'''"""STIGTOOL installer - part {part} of {parts} (bundle {bundle}).
#|
#|HOW TO USE: save this text as a .py file and run it:   python <this file>
#|  - Run every part of the bundle ({parts} in total), in any order.
#|  - The program is created in a STIGTOOL folder next to this file, or updated in place if this file
#|    is inside an existing STIGTOOL folder. Your data/ folder is never touched.
#|  - Every file is checked against a fingerprint, so a bad copy/paste is caught.
#|Do not edit the lines below that start with #
#|"""
#|import hashlib
#|import sys
#|from pathlib import Path
#|
#|
#|def norm(text):
#|    return "\n".join(line.rstrip() for line in text.split("\n")).rstrip("\n") + "\n"
#|
#|
#|def main():
#|    me = Path(__file__).resolve()
#|    if len(sys.argv) > 1:
#|        target = Path(sys.argv[1]).resolve()
#|    elif (me.parent / "main.py").exists():
#|        target = me.parent
#|    else:
#|        target = me.parent / "STIGTOOL"
#|    stash = target / "_install_parts"
#|    stash.mkdir(parents=True, exist_ok=True)
#|    files, manifest, current, buf = {{}}, {{}}, None, []
#|    for line in me.read_text(encoding="utf-8").splitlines():
#|        if line.startswith("#@ HAS "):
#|            manifest[line.split()[2]] = line.split()[3]
#|        elif line.startswith("#@ FILE "):
#|            # #@ FILE <path> SHA <hash> CHUNK <i> OF <n>
#|            f = line.split()
#|            current, buf = (f[2], f[4], int(f[6]), int(f[8])), []
#|        elif line.startswith("#@ END") and current:
#|            path, sha, i, n = current
#|            (stash / f"{bundle}_{{path.replace('/', '__')}}.{{i}}").write_text("\n".join(buf) + "\n", encoding="utf-8")
#|            files[path] = (sha, n)
#|            current = None
#|        elif current is not None and line.startswith("#|"):
#|            buf.append(line[2:])
#|    if not files:
#|        sys.exit("Nothing found to install - was the whole file pasted?")
#|    waiting, bad = 0, 0
#|    for path, (sha, n) in sorted(files.items()):
#|        pieces = [stash / f"{bundle}_{{path.replace('/', '__')}}.{{i}}" for i in range(1, n + 1)]
#|        if not all(p.exists() for p in pieces):
#|            have = sum(p.exists() for p in pieces)
#|            print(f"  waiting  {{path}}  ({{have}} of {{n}} pieces - run the other part(s))")
#|            waiting += 1
#|            continue
#|        text = norm("".join(p.read_text(encoding="utf-8") for p in pieces))
#|        if hashlib.sha256(text.encode("utf-8")).hexdigest() != sha:
#|            print(f"  BROKEN   {{path}}  - the copy/paste changed it. Paste the part(s) holding it again.")
#|            bad += 1
#|            continue
#|        dest = target / path
#|        dest.parent.mkdir(parents=True, exist_ok=True)
#|        dest.write_text(text, encoding="utf-8", newline="\n")
#|        for p in pieces:
#|            p.unlink()
#|        print(f"  OK       {{path}}")
#|    (target / "tests" / "fixtures").mkdir(parents=True, exist_ok=True)
#|    try:
#|        stash.rmdir()  # only succeeds once no pieces are left
#|    except OSError:
#|        pass
#|
#|    def installed(path, sha):
#|        dest = target / path
#|        return dest.exists() and hashlib.sha256(norm(dest.read_text(encoding="utf-8")).encode()).hexdigest() == sha
#|    missing = [p for p, sha in sorted(manifest.items()) if not installed(p, sha)]
#|    print()
#|    if bad:
#|        print(f"{{bad}} file(s) failed the fingerprint check. Nothing is broken - paste those parts again and re-run.")
#|    elif missing:
#|        print("Not finished yet - still to come from the other part(s): " + ", ".join(missing))
#|    else:
#|        print(f"All {{len(manifest)}} files installed and verified in {{target}}")
#|        print(f"Start it with:   python \"{{target / 'main.py'}}\"")
#|
#|
#|main()
#|
#|# ---------------------------------------------------------------- payload (do not edit below)
#|'''
#|
#|
#|def norm(text):
#|    return "\n".join(line.rstrip() for line in text.split("\n")).rstrip("\n") + "\n"
#|
#|
#|def build(max_kb=None):
#|    entries = []
#|    for rel in FILES + [o for o in OPTIONAL if (ROOT / o).exists()]:
#|        text = norm((ROOT / rel).read_text(encoding="utf-8"))
#|        if not text.isascii():
#|            sys.exit(f"{rel} contains non-ASCII characters - replace them so copy/paste is safe.")
#|        entries.append((rel, hashlib.sha256(text.encode("utf-8")).hexdigest(), text.rstrip("\n").split("\n")))
#|    bundle = hashlib.sha256("".join(e[1] for e in entries).encode()).hexdigest()[:8]
#|    budget = max_kb * 1024 if max_kb else float("inf")
#|
#|    # Assign each file's lines to parts without exceeding the budget (files may span parts).
#|    parts, size = [[]], 0
#|    for rel, sha, lines in entries:
#|        start = 0
#|        while start < len(lines):
#|            end, chunk = start, 0
#|            while end < len(lines) and (size + chunk + len(lines[end]) + 3 <= budget or (size == 0 and end == start)):
#|                chunk += len(lines[end]) + 3
#|                end += 1
#|            if end == start:  # part full: start a new one
#|                parts.append([])
#|                size = 0
#|                continue
#|            parts[-1].append((rel, sha, lines[start:end]))
#|            size += chunk
#|            start = end
#|    counts = {}
#|    for part in parts:
#|        for rel, _, _ in part:
#|            counts[rel] = counts.get(rel, 0) + 1
#|
#|    out_dir = ROOT / "transfer"
#|    out_dir.mkdir(exist_ok=True)
#|    for old in out_dir.glob("STIGTOOL_install*.py"):
#|        old.unlink()
#|    seen, written = {}, []
#|    for n, part in enumerate(parts, 1):
#|        body = [INSTALLER.format(part=n, parts=len(parts), bundle=bundle)]
#|        body += [f"#@ HAS {rel} {sha}" for rel, sha, _ in entries]
#|        for rel, sha, lines in part:
#|            seen[rel] = seen.get(rel, 0) + 1
#|            body.append(f"#@ FILE {rel} SHA {sha} CHUNK {seen[rel]} OF {counts[rel]}")
#|            body += [f"#|{line}" for line in lines]
#|            body.append("#@ END")
#|        name = "STIGTOOL_install.py" if len(parts) == 1 else f"STIGTOOL_install_part{n}_of_{len(parts)}.py"
#|        path = out_dir / name
#|        path.write_text("\n".join(body) + "\n", encoding="utf-8", newline="\n")
#|        written.append(path)
#|    print(f"Bundle {bundle}: {len(entries)} files in {len(written)} part(s):")
#|    for p in written:
#|        print(f"  {p}  ({p.stat().st_size // 1024} KB)")
#|
#|
#|if __name__ == "__main__":
#|    build(int(sys.argv[1]) if len(sys.argv) > 1 else None)
#@ END
#@ FILE README.md SHA 32cf8aae07c1921ced823a18b053960593f63785148908c800cdccc0609df3d2 CHUNK 1 OF 1
#|# STIG Group Assessment Tool
#|
#|Builds group STIG checklists for network devices from SolarWinds show-command output.
#|It works with STIG Viewer 2.x checklists (`.ckl`) or STIG Viewer 3 checklists (`.cklb`). The team picks one output format.
#|
#|**Start it:** double-click `main.py`, or run `python main.py`. Needs Python 3.8 or newer. Nothing else to install.
#|
#|## Moving the tool to another computer (copy and paste only)
#|
#|You do not need git, email or a zip. The whole program fits in one self-installing Python file.
#|
#|**On this computer:**
#|1. Run `python make_bundle.py`. It writes `transfer/STIGTOOL_install.py` (about 250 KB of plain text).
#|   If your clipboard or remote session cannot paste that much at once, run `python make_bundle.py 40` instead.
#|   That gives several parts of about 40 KB each (`STIGTOOL_install_part1_of_7.py`, ...).
#|2. Open the file (or each part) in Notepad, press Ctrl+A, then Ctrl+C.
#|
#|**On the work computer:**
#|1. Check Python works: open a Command Prompt and run `python --version` (3.8 or newer) and
#|   `python -c "import tkinter"` (no error means the GUI library is there).
#|2. Make a folder, e.g. `C:\Tools`. Open Notepad, paste, and save as `C:\Tools\STIGTOOL_install.py`.
#|   In the Save dialog choose *Save as type: All files* and *Encoding: UTF-8*, so Notepad does not add `.txt`.
#|3. Run it: `python C:\Tools\STIGTOOL_install.py`. With parts, save and run every part, in any order.
#|4. It creates `C:\Tools\STIGTOOL\` with every file and folder, checks each file against a fingerprint, and ends with
#|   **"All 10 files installed and verified"**. If a file shows **BROKEN**, the paste changed it. Paste that part again
#|   and re-run it; nothing else is affected.
#|5. Start the tool: `python C:\Tools\STIGTOOL\main.py`. It creates `data/`, `input/`, `output/` and `logs/` itself.
#|6. Optional: to run the full tests (`python -m unittest discover tests`), save a blank IOS-XE Switch RTR checklist
#|   from STIG Viewer 2.x and a blank IOS-XE Switch NDM checklist from STIG Viewer 3 into `tests/fixtures/`, as
#|   `ios-xe-switch-rtr.ckl` and `ios-xe-switch-ndm.cklb`. Without them, the checklist tests are skipped.
#|
#|**Your rules travel with the program.** `rules/stigtool_rules.json` is the rule library: every rule and the
#|manual-only list, with author names and edit history removed. It is included in the bundle and the repo.
#|- On a **new install with no rules**, the tool loads it automatically on first start.
#|- Import your checklists on tab 1 and the rules attach to them by STIG and Vuln ID.
#|- Later, use **Export rules...** / **Import rules...** on tab 2 to move rules between sites or teams. Import only
#|  adds rules that do not exist yet; it never overwrites.
#|- Refresh the shipped file before making a new bundle: **Export rules...** to `rules/stigtool_rules.json`.
#|
#|**Updating later:** make a new bundle, put it *inside* the existing `STIGTOOL` folder and run it. Program files are
#|replaced; `data/` (rules, groups, imported checklists, runs) is never touched.
#|
#|**By hand instead (if you cannot run the installer):** recreate this layout and paste each file into place:
#|
#|```
#|STIGTOOL\
#|  main.py
#|  make_bundle.py
#|  README.md
#|  src\
#|    assess.py  checklist.py  collect.py  gui.py  rules.py  store.py
#|  tests\
#|    test_core.py
#|    fixtures\        (optional sample files)
#|```
#|
#|## Team setup (do this once)
#|
#|1. Put the shared data somewhere the whole team can reach, e.g. `\\server\share\stigtool`.
#|2. In each person's copy of the tool, create `shared_data_path.txt` next to `main.py` with that path on the first line.
#|   `data/`, `input/` and `output/` then live on the share. Logs stay on each PC.
#|3. On tab 1, choose the **team checklist output format**, either STIG Viewer 2.x (.ckl) or STIG Viewer 3 (.cklb).
#|   Only that format is written.
#|
#|Working at the same time is safe:
#|- Each rule and each group is its own file, so people editing different rules never collide.
#|- Opening a rule locks it. Anyone else who opens it is told who has it, and can open it read-only.
#|- If two people do save the same rule or group, the second person is asked whether to overwrite, or (for rules)
#|  to keep both as separate versions. Nothing is lost silently.
#|- Press **F5** (or switch tabs) to see teammates' changes. The bottom bar shows where the shared data is and who
#|  you are signed in as.
#|
#|## The workflow (the tabs, left to right)
#|
#|1. **Checklists:** import the blank checklist for each STIG. There is one row per STIG. Expand it to see every file
#|   imported for it, labelled *STIG Viewer 2.x (.ckl)* or *STIG Viewer 3 (.cklb)*, with release, date and who
#|   imported it. The row turns yellow if the STIG has no file in the team's output format, or if rules need review.
#|2. **Rule Work Queue:** every control is listed with a state. For each one either:
#|   - click **New rule**: type the show command, then add conditions such as *"every section that starts with
#|     `line vty` has a line that contains `transport input ssh`"*. Paste real device output on the right and the tool
#|     colours what it matched (green), what is wrong (red), and which sections it checked (blue). Save at least one
#|     sample that should pass and one that should fail as **tests**. Only then can the rule be set **active**.
#|   - or click **Manual only** if the control cannot be checked from show output.
#|3. **Device Groups:** click **New group** and answer three questions: the group's name, which STIGs it gets, and
#|   which devices belong (hostname patterns like `*-ACCESS`, with a live preview). Fix individual devices in the list
#|   underneath with **Move to group**. **Rule versions** only matters when a control has more than one rule version.
#|4. **Collection Script:** tick groups, click **Generate**, and paste the script into SolarWinds *Execute Command
#|   Script*. It also shows, per STIG, how many controls are automated, manual, or not built yet. Save the SolarWinds
#|   output as a text file in `input/`. Do not remove the `! CMD:` lines.
#|5. **Import & Review:** import that file, check each device is in the right group, and review each control. The tool
#|   *recommends* a result, and you can change any of them (a comment is required). Then click **Write checklist
#|   package**. The package lands in `output/<GROUP>_<date>/`, and its `group_assessment_summary.txt` states per STIG how
#|   many controls were automated, manual, or not built, and the results.
#|
#|## Port roles: rules for uplinks, downlinks and access ports
#|
#|Uplinks are not on the same port on every switch, so rules find ports by **what they are**, not by number. The
#|interface description says what the port is:
#|
#|```
#|interface TenGigabitEthernet1/1/3
#| description UPLINK - DIST-SW-01 Te2/0/14        <- uplink toward distribution / core
#|interface GigabitEthernet1/0/24
#| description DOWNLINK - ACC-SW-07 Te1/1/1        <- downlink toward an access switch
#|interface GigabitEthernet1/0/5
#| description ACCESS - Room 112 jack 4            <- client port (ACCESS or UNTRUSTED)
#|```
#|
#|**Labelling rules:**
#|- The keyword goes **first**. Anything after it is free text.
#|- Upper / lower case does not matter.
#|- The keywords are a team setting: tab 3, **Port roles...** (defaults: `UPLINK`, `DOWNLINK`, `ACCESS, UNTRUSTED`).
#|- Changing a keyword there changes every rule that uses it.
#|
#|**Using roles in a rule** (rule editor, Add condition):
#|
#|| You want | Look in | Only / skip | It |
#||---|---|---|---|
#|| every uplink has DHCP-snooping trust | EVERY section that starts with `interface` | only: `role:uplink`; if none found: FAIL | has a line (whole line) `ip dhcp snooping trust` |
#|| nothing else has trust | EVERY section that starts with `interface` | skip: `role:uplink` | has NO line (whole line) `ip dhcp snooping trust` |
#|| every client port has 802.1x, BPDU Guard, storm control, a parking / user VLAN... | EVERY section that starts with `interface` | only: `role:access`; skip `shutdown` | has a line ... |
#|| every downlink has Root Guard | EVERY section that starts with `interface` | only: `role:downlink` | has a line `spanning-tree guard root` |
#|| every live port is labelled | EVERY section that starts with `interface` | skip `shutdown` | has a line `role:any` |
#|
#|**Tips:**
#|- **"If no sections found"** decides what happens on a switch with no port in that role.
#|  - Use **FAIL** when every switch must have one (every access switch has an uplink). Then an unlabelled
#|    switch is flagged instead of quietly passing.
#|  - Use **PASS** when the role is optional (most access switches have no downlinks).
#|- **Pair "must have" with "must not have"** for trust settings. Trust on a client port is the real danger.
#|- **Add a drift check:** every `role:uplink` port has `switchport mode trunk`. A mislabelled port then shows up.
#|- **Groups without client ports** (core / distribution) still fail the access checks, which is the point for
#|  access switches. For those groups, choose a different rule version or mark the control N/A.
#|- **Fix commands per condition:** `{each failing section of condition N}` applies fixes only to the ports that
#|  failed condition N. For example, add `ip dhcp snooping trust` under failing uplinks (condition 3) and
#|  `no ip dhcp snooping trust` under failing client ports (condition 4). The starter drafts do exactly this.
#|
#|**Starter drafts that use roles:**
#|- DHCP snooping trust and DAI trust on uplinks only.
#|- Root Guard on downlinks.
#|- 802.1x, BPDU Guard, unknown-unicast blocking, IP Source Guard and storm control on access ports.
#|- User-facing ports must be access ports.
#|- Every live port must be labelled.
#|
#|## Starter drafts (a head start on the rules)
#|
#|On tab 2, **Create starter drafts...** writes a DRAFT rule for every control that has no rule yet, for the Cisco
#|IOS-XE Switch / Router and NX-OS STIGs. Pick one STIG in the STIG filter first to limit it to that STIG.
#|
#|- They are written from each control's check text for **Catalyst 9300** (IOS-XE 17.x), **Catalyst 8300**
#|  (IOS-XE 17.x) and **Nexus 9336C-FX2 / 93180YC-FX3** (NX-OS 9.3/10.x). Where those platforms behave differently,
#|  the draft does too, e.g. CDP is on by default on the 9300 and off on the 8300.
#|- Many include a **Not Applicable** check for features that are not configured (BGP, PIM, MSDP, MPLS, IPv6, SNMP).
#|- Each draft's *Reviewer guidance* tab explains what to adjust, e.g. your parking VLAN, approved software versions,
#|  or narrowing "external interface" checks to the real external interfaces.
#|- About a quarter of controls get **no draft**: perimeter / OOBM design, design-plan comparisons, interviews. The
#|  report (saved in `output/`) lists them with the reason, and offers to mark them **Manual only**.
#|- Existing rules are never touched, so it is safe to run again after importing new STIGs.
#|- Drafts cannot be activated until someone reviews them and saves a passing and a failing test sample from a real
#|  device. That is the point: they are a starting point, not an answer.
#|
#|## Hardening scripts (tab 6)
#|
#|Each rule has a **Fix commands** tab with two boxes:
#|- **Low impact:** banners, logging, archive / log config, timestamps, legacy services.
#|- **Impactful:** AAA, SSH algorithms, vty access, port / STP / 802.1x settings, SNMP, routing.
#|
#|The starter drafts come with fix commands for the Catalyst 9300 / 8300 and Nexus 9000.
#|
#|Tab 6 always writes **two separate scripts**, `..._LOW_IMPACT.txt` and `..._IMPACTFUL.txt`, so the safe changes can go
#|out on their own. There are two ways to build them:
#|- **From the current assessment run:** one script pair per device, containing only that device's Open controls.
#|  Interface-level fixes are written under the exact interfaces that failed (e.g. `interface GigabitEthernet1/0/14` /
#|  `storm-control broadcast level ...`).
#|- **Baseline:** one script pair for the whole group with every control's fix (interfaces left as `<INTERFACE>`).
#|
#|In fix commands:
#|- `<SOMETHING>` is a site value. Every one is listed at the top of the script under **EDIT BEFORE USE**.
#|- `{each failing section}` on its own line, followed by indented commands, repeats those commands under every failing
#|  interface / section.
#|- Lines starting with `!` are comments.
#|
#|Scripts start with `configure terminal` and end with `end`. They never save the config; do that after verifying the
#|device. The impactful script carries a maintenance-window warning. Intentional (risk-accepted) findings are skipped.
#|
#|## Quarterly DISA updates
#|
#|1. Import the new release's checklist file on tab 1. The import report says, per STIG, how many controls were added,
#|   removed, or changed, and lists every active rule affected. Re-importing an identical file is skipped. Importing
#|   an *older* release only keeps it for history.
#|2. Select the STIG and click **Compare releases**. Each changed control shows a word-by-word diff (red struck-out =
#|   removed by DISA, green = added) and whether its rule needs review.
#|3. For each flagged rule, either open it and adjust it (saving marks it reviewed), or click **Rule still valid - mark
#|   reviewed**. Either way, who reviewed it and for which release is recorded.
#|
#|Only changes to the *check text* flag a rule. Changes to the fix text, title or severity are shown in the comparison
#|for information.
#|
#|## Rules the tool always follows
#|
#|- Missing output, failed connections and `% Invalid input` responses are **never** a pass. They give Not Reviewed.
#|  Empty output from a command that ran *is* evidence (e.g. `show run | include ip http server` printing nothing).
#|- Group result = the worst device: any Not Reviewed -> Not Reviewed, else any Open -> Open, else all N/A -> N/A,
#|  else Not a Finding. `finding_details` lists which devices failed and why.
#|- Where the reason goes follows team guidance (tab 1, **Where reasons go**). By default:
#|  - **Not a Finding / Not Applicable / Not Reviewed:** the reason (rule text, evidence, sign-off) goes in **Comments**.
#|  - **Open:** the reason goes in **Finding Details**.
#|  - The rule's extra comment and the reviewer's comment always go in Comments.
#|- Only **status**, **finding details** and **comments** are changed in the checklist. Every output is checked
#|  against its template (`preservation_validation_report.txt`). A failing file is renamed `*.FAILED_VALIDATION`.
#|- Controls with no rule keep whatever the template says, unless the reviewer sets a result.
#|- If anything is still Not Reviewed, the package folder ends in `_REVIEW_REQUIRED`.
#|
#|## Folders
#|
#|| Folder | What is in it |
#||---|---|
#|| `src/` | the program (`checklist` CKL/CKLB files, `rules` matching engine, `collect` SolarWinds, `assess` groups/results/reports, `store` shared data files, `gui` screens) |
#|| `data/rules/`, `data/groups/` | one file per rule / group |
#|| `data/settings.json` | team settings: output format, manual-only controls, device moves, known devices |
#|| `data/templates/` | imported checklist files (read-only) and their catalogs, every release kept |
#|| `data/runs/`, `data/evidence/` | assessment runs with reviewer decisions; untouched copies of SolarWinds files |
#|| `input/`, `output/` | SolarWinds files in; scripts and checklist packages out |
#|| `logs/` | `stigtool.log` for troubleshooting (local to each PC) |
#|| `tests/` | automated tests: `python -m unittest discover tests` |
#|
#|Back up `data/` to keep your rules and groups.
#@ END
#@ FILE src/assess.py SHA aa8a3b694f465727b9657355dde187864d84f00c2e0b04e6e47c2e4a3a39ed77 CHUNK 1 OF 1
#|"""Groups, rule selection, assessment runs, and output packages.
#|
#|Group record (data/groups.json):
#|  {"id": "CAMPUS-ACCESS", "description": "...", "patterns": ["*-ACCESS"],
#|   "stigs": ["Cisco_IOS_XE_Switch_NDM_STIG", ...],
#|   "rule_choices": {"<stig_id>|<vuln_id>": "<rule id>" | "manual"}}
#|
#|Group result for a control (worst device wins):
#|  any device Not Reviewed (missing / bad evidence) -> Not Reviewed
#|  else any device Open                             -> Open
#|  else every device Not Applicable                 -> Not Applicable
#|  else                                             -> Not a Finding
#|Controls with no rule are "manual": the template's values are left untouched unless a
#|reviewer sets a status.
#|"""
#|import fnmatch
#|import re
#|import shutil
#|from collections import Counter, defaultdict
#|from pathlib import Path
#|
#|import checklist
#|import collect
#|import rules as engine
#|import store
#|from checklist import STATUS_LABELS
#|
#|TOOL = "STIGTOOL"
#|
#|
#|def key_of(stig_id, vuln_id):
#|    return f"{stig_id}|{vuln_id}"
#|
#|
#|def label(status):
#|    return STATUS_LABELS.get(status, "Manual (unchanged)" if status is None else str(status))
#|
#|
#|def is_expected_open(c, which="final"):
#|    """Open on purpose: the rule says this finding is intentional (e.g. risk acceptance recommended)."""
#|    return c.get(which) == "open" and bool(c.get("expected_open"))
#|
#|
#|def result_label(c, which="final"):
#|    """Like label(), but shows intentional findings as 'Open (expected)'."""
#|    return "Open (expected)" if is_expected_open(c, which) else label(c.get(which))
#|
#|
#|def outcome_prefix(c):
#|    """The rule author's Finding Details text for this control's final result, placeholders filled in."""
#|    status = c.get("final")
#|    devices = [h for h, r in c.get("per_device", {}).items() if r["status"] == status]
#|    return engine.outcome_text({"outcome_text": c.get("outcome_text")}, status, devices)
#|
#|
#|# ---------------------------------------------------------------- rules and groups
#|
#|def rules_for_control(rules_db, stig_id, vuln_id, include_retired=False):
#|    return [r for r in rules_db["rules"]
#|            if r["stig_id"] == stig_id and r["vuln_id"] == vuln_id
#|            and (include_retired or r.get("state") != "retired")]
#|
#|
#|def resolve_rule(group, rules_db, stig_id, vuln_id):
#|    """The active rule this group uses for a control, or None (manual)."""
#|    choice = (group.get("rule_choices") or {}).get(key_of(stig_id, vuln_id))
#|    if choice == "manual":
#|        return None
#|    active = [r for r in rules_for_control(rules_db, stig_id, vuln_id) if r.get("state") == "active"]
#|    for r in active:
#|        if r["id"] == choice:
#|            return r
#|    for r in active:
#|        if r.get("is_default"):
#|            return r
#|    return active[0] if active else None
#|
#|
#|def control_state(rules_db, stig_id, control):
#|    """Work queue state for a control."""
#|    key = key_of(stig_id, control["vuln_id"])
#|    if key in rules_db.get("manual_controls", []):
#|        return "Manual only"
#|    rs = rules_for_control(rules_db, stig_id, control["vuln_id"])
#|    if not rs:
#|        return "Needs rule"
#|    active = [r for r in rs if r.get("state") == "active"]
#|    if any(r.get("check_hash") != control["check_hash"] for r in active):
#|        return "STIG changed - review"
#|    return "Active" if active else "Draft"
#|
#|
#|def group_plan(group, rules_db, index):
#|    """[(stig_id, control, rule_or_None)] for every control in the group's STIGs."""
#|    plan = []
#|    for stig_id in group.get("stigs", []):
#|        stig = index.get(stig_id)
#|        if not stig:
#|            continue
#|        for vuln_id in stig["order"]:
#|            control = stig["controls"][vuln_id]
#|            plan.append((stig_id, control, resolve_rule(group, rules_db, stig_id, vuln_id)))
#|    return plan
#|
#|
#|def coverage(group, rules_db, index):
#|    """Per STIG in the group: how many controls are automated, manual-only, or not built yet."""
#|    manual = set(rules_db.get("manual_controls", []))
#|    choices = group.get("rule_choices") or {}
#|    rows = []
#|    for stig_id in group.get("stigs", []):
#|        stig = index.get(stig_id)
#|        if not stig:
#|            continue
#|        row = {"stig_id": stig_id, "short": stig["short"], "release": stig["release"], "total": 0,
#|               "automated": 0, "manual": 0, "no_rule": 0, "draft": 0, "changed": 0}
#|        for vuln_id in stig["order"]:
#|            control = stig["controls"][vuln_id]
#|            key = key_of(stig_id, vuln_id)
#|            rule = resolve_rule(group, rules_db, stig_id, vuln_id)
#|            row["total"] += 1
#|            if rule:
#|                row["automated"] += 1
#|                if rule.get("check_hash") != control["check_hash"]:
#|                    row["changed"] += 1
#|            elif key in manual or choices.get(key) == "manual":
#|                row["manual"] += 1
#|            elif rules_for_control(rules_db, stig_id, vuln_id):
#|                row["draft"] += 1
#|            else:
#|                row["no_rule"] += 1
#|        rows.append(row)
#|    return rows
#|
#|
#|def commands_for_groups(groups, rules_db, index):
#|    """{command: set('NDM V-220524', ...)} for every active rule the groups use."""
#|    sources = defaultdict(set)
#|    for g in groups:
#|        for stig_id, control, rule in group_plan(g, rules_db, index):
#|            if rule:
#|                for cmd in rule["commands"]:
#|                    if cmd.strip():
#|                        sources[cmd.strip()].add(f"{index[stig_id]['short']} {control['vuln_id']}")
#|    return dict(sources)
#|
#|
#|def assign_group(host, groups_db):
#|    """(group_id or "", how) - explicit override first, then hostname pattern."""
#|    override = groups_db.get("device_overrides", {}).get(host.upper())
#|    if override:
#|        return override, "override"
#|    for g in groups_db.get("groups", []):
#|        for pat in g.get("patterns", []):
#|            if pat.strip() and fnmatch.fnmatch(host.upper(), pat.strip().upper()):
#|                return g["id"], f"pattern {pat.strip()}"
#|    return "", "unassigned"
#|
#|
#|def find_group(groups_db, group_id):
#|    return next((g for g in groups_db.get("groups", []) if g["id"] == group_id), None)
#|
#|
#|# ---------------------------------------------------------------- runs
#|
#|def new_run(parsed, source_file, groups_db):
#|    run_id = store.stamp()
#|    membership = {}
#|    for d in parsed["devices"]:
#|        gid, how = assign_group(d["host"], groups_db)
#|        membership[d["host"]] = {"group": gid, "how": how}
#|    return {
#|        "id": run_id,
#|        "created": store.now(),
#|        "created_by": store.current_user(),
#|        "source_file": str(source_file),
#|        "source_name": Path(source_file).name,
#|        "warnings": parsed["warnings"],
#|        "devices": parsed["devices"],
#|        "membership": membership,
#|        "results": {},
#|    }
#|
#|
#|def evaluate_run(run, groups_db, rules_db, index):
#|    """(Re)compute recommendations for every group in the run. Keeps reviewer decisions."""
#|    by_group = defaultdict(list)
#|    for d in run["devices"]:
#|        gid = run["membership"].get(d["host"], {}).get("group")
#|        if gid:
#|            by_group[gid].append(d)
#|    old = run.get("results", {})
#|    results = {}
#|    for gid, devices in sorted(by_group.items()):
#|        group = find_group(groups_db, gid)
#|        if not group:
#|            continue
#|        controls = {}
#|        for stig_id, control, rule in group_plan(group, rules_db, index):
#|            k = key_of(stig_id, control["vuln_id"])
#|            rec = {
#|                "stig_id": stig_id, "family": index[stig_id]["short"],
#|                "vuln_id": control["vuln_id"], "rule_ver": control["rule_ver"],
#|                "title": control["title"], "severity": control["severity"],
#|                "template_status": control.get("template_status", "not_reviewed"),
#|                "rule_id": rule["id"] if rule else None,
#|                "rule_name": rule.get("name", "") if rule else "",
#|                "rule_version": rule.get("version", 1) if rule else None,
#|                "rule_comment": rule.get("comment", "") if rule else "",
#|                "outcome_text": dict(rule.get("outcome_text") or {}) if rule else {},
#|                "expected_open": bool(rule.get("expected_open")) if rule else False,
#|                "per_device": {}, "recommended": None, "details": "",
#|            }
#|            if rule:
#|                for d in devices:
#|                    if d["status"] != "ok":
#|                        res = {"status": "not_reviewed", "reasons": [f"Collection failed: {d['error']}"],
#|                               "evidence": []}
#|                    else:
#|                        res = engine.evaluate(rule, d["outputs"])
#|                    rec["per_device"][d["host"]] = {"status": res["status"], "reasons": res["reasons"],
#|                                                    "evidence": res["evidence"],
#|                                                    "failed_sections": res.get("failed_sections", []),
#|                                                    "failed_by_condition": res.get("failed_by_condition", {})}
#|                rec["recommended"] = rollup([v["status"] for v in rec["per_device"].values()])
#|                rec["details"] = finding_details(rec, run)
#|            prev = old.get(gid, {}).get("controls", {}).get(k, {})
#|            rec["reviewer_comment"] = prev.get("reviewer_comment", "")
#|            if prev.get("reviewer_changed"):
#|                rec.update(final=prev["final"], reviewer_changed=prev["final"] != rec["recommended"])
#|            else:
#|                rec.update(final=rec["recommended"], reviewer_changed=False)
#|            controls[k] = rec
#|        results[gid] = {"devices": [d["host"] for d in devices], "controls": controls}
#|        run.setdefault("coverage", {})[gid] = coverage(group, rules_db, index)
#|    run["results"] = results
#|    run["stig_names"] = {sid: s["short"] for sid, s in index.items()}
#|    run["stig_releases"] = {sid: s["release"] for sid, s in index.items()}
#|    run["evaluated"] = store.now()
#|    return run
#|
#|
#|def rollup(statuses):
#|    if not statuses:
#|        return "not_reviewed"
#|    if "not_reviewed" in statuses:
#|        return "not_reviewed"
#|    if "open" in statuses:
#|        return "open"
#|    if all(s == "not_applicable" for s in statuses):
#|        return "not_applicable"
#|    return "not_a_finding"
#|
#|
#|def finding_details(rec, run):
#|    by_status = defaultdict(list)
#|    for host, r in rec["per_device"].items():
#|        by_status[r["status"]].append(host)
#|    counts = ", ".join(f"{len(h)} {label(s)}" for s, h in sorted(by_status.items()))
#|    out = [
#|        f"{TOOL} automated assessment (run {run['id']}, evidence file {run['source_name']})",
#|        f"Rule {rec['rule_id']} v{rec['rule_version']} \"{rec['rule_name']}\"",
#|        f"Devices assessed: {len(rec['per_device'])} - {counts}",
#|        f"Group result: {label(rec['recommended'])}",
#|    ]
#|    for status in ("open", "not_reviewed", "not_applicable", "not_a_finding"):
#|        hosts = by_status.get(status)
#|        if not hosts:
#|            continue
#|        out.append("")
#|        out.append(f"{label(status)} ({len(hosts)}): {', '.join(hosts)}")
#|        sample = rec["per_device"][hosts[0]]
#|        if status in ("open", "not_reviewed"):
#|            for h in hosts:
#|                bad = [r for r in rec["per_device"][h]["reasons"]
#|                       if r.strip().startswith(("FAIL", "ERROR", "No usable", "Collection", "Rule", "Could"))]
#|                for r in bad or rec["per_device"][h]["reasons"][:3]:
#|                    out.append(f"  {h}: {r.strip()}")
#|        if sample["evidence"]:
#|            out.append(f"  Evidence from {hosts[0]}:")
#|            out += [f"    {line}" for line in sample["evidence"]]
#|    return "\n".join(out)
#|
#|
#|# ---------------------------------------------------------------- output package
#|
#|def unresolved_controls(results):
#|    """Controls that will still read Not Reviewed in the output checklist."""
#|    return [c for c in results["controls"].values()
#|            if c["final"] == "not_reviewed"
#|            or (c["final"] is None and c.get("template_status", "not_reviewed") == "not_reviewed")]
#|
#|
#|FIELD_LABELS = {"comments": "Comments", "finding_details": "Finding Details"}
#|
#|
#|def reason_text(c, stamp_line=""):
#|    """Why the control got its result: rule author's text, automated evidence, reviewer change, sign-off."""
#|    parts = [p for p in (outcome_prefix(c), c.get("details")) if p]
#|    if c.get("reviewer_changed"):
#|        parts.append(f"Reviewer changed result from {label(c['recommended'])} to {label(c['final'])}.")
#|    text = "\n\n".join(parts)
#|    return (text + "\n" if text else "") + stamp_line if stamp_line else text
#|
#|
#|def checklist_text(c, placement, stamp_line):
#|    """The status / finding details / comments to write for one control.
#|
#|    The reason goes in the field the team's guidance names for that result (default: Not a Finding and
#|    Not Applicable -> Comments, Open -> Finding Details). The rule's extra comment and the reviewer's
#|    comment always go in Comments. A field with nothing to say is left as the template has it.
#|    """
#|    reason = reason_text(c, stamp_line)
#|    where = (placement or store.DEFAULT_PLACEMENT).get(c["final"], "comments")
#|    comments = [p for p in (reason if where == "comments" else "",
#|                            f"Reviewer: {c['reviewer_comment']}" if c.get("reviewer_comment") else "",
#|                            c.get("rule_comment")) if p]
#|    return {
#|        "status": c["final"],
#|        "finding_details": reason if where == "finding_details" else None,
#|        "comments": "\n\n".join(comments) if comments else None,
#|    }
#|
#|
#|def write_package(run, group_id, reviewer, groups_db, rules_db, fmt, placement=None):
#|    """Write one checklist per STIG (in the team's output format) plus reports for one group.
#|
#|    placement: {result: "comments" | "finding_details"} - where the reason text goes (team setting).
#|    Returns (folder, ok, messages).
#|    """
#|    placement = placement or store.load_settings()["text_placement"]
#|    results = run["results"][group_id]
#|    group = find_group(groups_db, group_id) or {"stigs": []}
#|    unresolved = unresolved_controls(results)
#|    folder_name = f"{group_id}_{store.stamp()}" + ("_REVIEW_REQUIRED" if unresolved else "")
#|    folder, n = store.paths.output / folder_name, 1
#|    while folder.exists():  # two packages in the same second (e.g. two reviewers)
#|        n += 1
#|        folder = store.paths.output / f"{folder_name}_{n}"
#|    folder.mkdir(parents=True)
#|    messages, all_ok, written, validation, notes = [], True, [], [], []
#|    fmt_label = checklist.FORMAT_LABELS[fmt]
#|
#|    # Group controls by the template file they live in (normally one file per STIG).
#|    targets = {}
#|    for stig_id in group.get("stigs", []):
#|        cat = store.templates_for(stig_id).get(fmt)
#|        short = (run.get("stig_names") or {}).get(stig_id, stig_id)
#|        if not cat:
#|            all_ok = False
#|            notes.append(f"NO {fmt_label} TEMPLATE imported for {short} - its checklist was not written. "
#|                         f"Import the {fmt_label} file on the Checklists tab.")
#|            continue
#|        targets.setdefault(cat["id"], (cat, []))[1].append(stig_id)
#|
#|    stamp_line = f"Final determination by {reviewer} on {store.now()}"
#|    for cat, stig_ids in targets.values():
#|        in_template = {(s["stig_id"], c["vuln_id"]) for s in cat["stigs"] for c in s["controls"]}
#|        updates, skipped = {}, []
#|        for c in results["controls"].values():
#|            if c["stig_id"] not in stig_ids or c["final"] is None:
#|                continue
#|            if (c["stig_id"], c["vuln_id"]) not in in_template:
#|                skipped.append(c["vuln_id"])
#|                continue
#|            updates[(c["stig_id"], c["vuln_id"])] = checklist_text(c, placement, stamp_line)
#|        for s in cat["stigs"]:
#|            if s["stig_id"] in stig_ids:
#|                rel = checklist.release_label(s.get("version"), s.get("release_info"))
#|                newest = (run.get("stig_releases") or {}).get(s["stig_id"])
#|                if newest and newest != rel:
#|                    notes.append(f"{s['short']}: the {fmt_label} template is {rel} but rules were assessed "
#|                                 f"against {newest}. Import the {newest} {fmt_label} file.")
#|        if skipped:
#|            notes.append(f"{len(skipped)} control(s) are not in the {fmt_label} template and were left out: "
#|                         + ", ".join(skipped))
#|        names = "-".join(_safe(s["short"]) for s in cat["stigs"] if s["stig_id"] in stig_ids)
#|        dst = folder / f"{group_id}_{names}.{fmt}"
#|        src = store.template_path(cat)
#|        try:
#|            checklist.write_patched(src, dst, updates, title=dst.stem)
#|            ok, lines = checklist.validate(src, dst)
#|        except checklist.ChecklistError as e:
#|            ok, lines = False, [f"Output: {dst.name}", f"RESULT: FAILED - {e}"]
#|        validation += lines + [""]
#|        if not ok:
#|            all_ok = False
#|            if dst.exists():
#|                dst.replace(dst.with_name(dst.name + ".FAILED_VALIDATION"))
#|            messages.append(f"{dst.name} FAILED validation - see preservation_validation_report.txt")
#|        else:
#|            written.append(dst.name)
#|
#|    evidence_dir = folder / "source_evidence"
#|    evidence_dir.mkdir()
#|    if Path(run["source_file"]).exists():
#|        shutil.copy2(run["source_file"], evidence_dir / run["source_name"])
#|
#|    _write(folder / "preservation_validation_report.txt", validation or ["No checklists written."])
#|    _write(folder / "applicable_devices.txt", _devices_report(run, group_id))
#|    _write(folder / "group_assessment_summary.txt",
#|           _summary_report(run, group_id, reviewer, written, all_ok, unresolved, fmt_label, notes))
#|    _write(folder / "exceptions_and_review_required.txt", _exceptions_report(run, group_id))
#|    _write(folder / "device_drift_report.txt", _drift_report(run, group_id))
#|    _write(folder / "unused_command_report.txt", _command_report(run, group_id, group, rules_db))
#|    _write(folder / "assessment_register.txt", _register(run, group_id, reviewer))
#|    messages.insert(0, f"Package written to {folder}")
#|    messages += notes
#|    if unresolved:
#|        messages.append(f"{len(unresolved)} control(s) still Not Reviewed - package marked REVIEW_REQUIRED.")
#|    return folder, all_ok, messages
#|
#|
#|def _safe(name):
#|    return re.sub(r"[^A-Za-z0-9.-]+", "_", name).strip("_")
#|
#|
#|def _write(path, lines):
#|    with open(path, "w", encoding="utf-8", newline="\n") as f:
#|        f.write("\n".join(lines).rstrip() + "\n")
#|
#|
#|def _header(run, group_id, title):
#|    return [f"{TOOL} - {title}", f"Group: {group_id}", f"Run: {run['id']}  Evidence: {run['source_name']}",
#|            "=" * 78, ""]
#|
#|
#|def _devices_report(run, group_id):
#|    out = _header(run, group_id, "Applicable devices")
#|    devices = {d["host"]: d for d in run["devices"]}
#|    for host in run["results"][group_id]["devices"]:
#|        d, m = devices[host], run["membership"][host]
#|        state = "collected" if d["status"] == "ok" else f"COLLECTION FAILED: {d['error']}"
#|        out.append(f"{host:<30} {d['ip']:<28} {m['how']:<22} {state}")
#|    return out
#|
#|
#|def coverage_table(rows):
#|    """Text table of how many controls each STIG has automated / manual / not built."""
#|    out = [f"{'STIG':<40}{'Release':<22}{'Controls':>9}{'Automated':>11}{'Manual':>8}{'No rule':>9}"
#|           f"{'Draft':>7}{'Review':>8}"]
#|    for r in rows:
#|        out.append(f"{r['short'][:39]:<40}{r['release'][:21]:<22}{r['total']:>9}{r['automated']:>11}"
#|                   f"{r['manual']:>8}{r['no_rule']:>9}{r['draft']:>7}{r['changed']:>8}")
#|    out.append("  Automated = an active rule is used for this group.  Manual = marked manual-only.")
#|    out.append("  No rule / Draft = still to be built.  Review = automated, but the STIG text changed since the "
#|               "rule was written.")
#|    return out
#|
#|
#|def _summary_report(run, group_id, reviewer, written, all_ok, unresolved, fmt_label, notes):
#|    res = run["results"][group_id]
#|    out = _header(run, group_id, "Group assessment summary")
#|    out.append(f"Reviewer: {reviewer}")
#|    out.append(f"Devices: {len(res['devices'])}")
#|    out.append(f"Checklist format: {fmt_label}")
#|    out.append(f"Checklists written: {', '.join(written) or 'none'}")
#|    out.append(f"Preservation validation: {'PASSED' if all_ok else 'FAILED / INCOMPLETE'}")
#|    if unresolved:
#|        out.append("")
#|        out.append(f"*** REVIEW PACKAGE - {len(unresolved)} control(s) are Not Reviewed. "
#|                   "Not a validated final turnover. ***")
#|    if notes:
#|        out.append("")
#|        out.append("Notes:")
#|        out += [f"  - {n}" for n in notes]
#|    out.append("")
#|    out.append("Rule coverage per STIG (at the time of assessment):")
#|    out += ["  " + line for line in coverage_table(run.get("coverage", {}).get(group_id, []))]
#|    out.append("")
#|    out.append("Final results per STIG:")
#|    by_stig = defaultdict(Counter)
#|    for c in res["controls"].values():
#|        by_stig[c["family"]][result_label(c)] += 1
#|    names = ["Not a Finding", "Open", "Open (expected)", "Not Applicable", "Not Reviewed", "Manual (unchanged)"]
#|    out.append(f"  {'STIG':<40}" + "".join(f"{n:>20}" for n in names))
#|    for stig, counts in sorted(by_stig.items()):
#|        out.append(f"  {stig[:39]:<40}" + "".join(f"{counts.get(n, 0):>20}" for n in names))
#|    return out
#|
#|
#|def _exceptions_report(run, group_id):
#|    out = _header(run, group_id, "Exceptions and review-required items")
#|    controls = list(run["results"][group_id]["controls"].values())
#|    expected = [c for c in controls if is_expected_open(c)]
#|    for c in controls:
#|        if c["final"] == "not_a_finding" and not c["reviewer_changed"]:
#|            continue
#|        if c["final"] is None or is_expected_open(c):
#|            continue
#|        out.append(f"{c['family']} {c['vuln_id']} ({c['rule_ver']}) - final {result_label(c)}, "
#|                   f"recommended {result_label(c, 'recommended')}")
#|        out.append(f"  {c['title']}")
#|        if c["reviewer_changed"]:
#|            out.append(f"  Reviewer comment: {c.get('reviewer_comment', '')}")
#|        for host, r in c["per_device"].items():
#|            if r["status"] != "not_a_finding":
#|                out.append(f"  {host}: {label(r['status'])}")
#|                for reason in r["reasons"]:
#|                    if reason.strip().startswith(("FAIL", "ERROR", "No usable", "Collection", "Rule", "Could",
#|                                                  "TRUE")):
#|                        out.append(f"      {reason.strip()}")
#|        out.append("")
#|    if expected:
#|        out.append(f"Expected (intentional) findings - Open on purpose, e.g. risk acceptance recommended: "
#|                   f"{len(expected)}")
#|        for c in expected:
#|            out.append(f"  {c['family']} {c['vuln_id']} ({c['rule_ver']}) {c['title'][:80]}")
#|            out.append(f"      {outcome_prefix(c).replace(chr(10), ' ')}")
#|        out.append("")
#|    manual = [c for c in run["results"][group_id]["controls"].values() if c["final"] is None]
#|    if manual:
#|        out.append(f"Manual controls (no rule; template values left unchanged): {len(manual)}")
#|        out += [f"  {c['family']} {c['vuln_id']} {c['title'][:90]}" for c in manual]
#|    return out
#|
#|
#|def _drift_report(run, group_id):
#|    out = _header(run, group_id, "Device drift (devices whose result differs from the group majority)")
#|    found = False
#|    for c in run["results"][group_id]["controls"].values():
#|        statuses = Counter(r["status"] for r in c["per_device"].values())
#|        if len(statuses) < 2:
#|            continue
#|        found = True
#|        majority = statuses.most_common(1)[0][0]
#|        odd = [f"{h} ({label(r['status'])})" for h, r in c["per_device"].items() if r["status"] != majority]
#|        out.append(f"{c['family']} {c['vuln_id']}: majority {label(majority)}; differs: {', '.join(odd)}")
#|    if not found:
#|        out.append("No drift: every device returned the same result for every automated control.")
#|    return out
#|
#|
#|def _command_report(run, group_id, group, rules_db):
#|    out = _header(run, group_id, "Command usage")
#|    used = set()
#|    for c in run["results"][group_id]["controls"].values():
#|        rule = next((r for r in rules_db["rules"] if r["id"] == c["rule_id"]), None)
#|        if rule:
#|            used |= {x.strip() for x in rule["commands"] if x.strip()}
#|    devices = {d["host"]: d for d in run["devices"]}
#|    collected = set()
#|    for host in run["results"][group_id]["devices"]:
#|        collected |= set(devices[host]["outputs"])
#|    out.append("Collected but not used by this group's rules:")
#|    out += [f"  {c}" for c in sorted(collected - used)] or ["  (none)"]
#|    out.append("")
#|    out.append("Needed by rules but missing, invalid or failed, per device:")
#|    any_missing = False
#|    for host in run["results"][group_id]["devices"]:
#|        d = devices[host]
#|        for cmd in sorted(used):
#|            ev = d["outputs"].get(cmd)
#|            if not ev or ev["status"] != "ok":
#|                any_missing = True
#|                out.append(f"  {host}: {cmd} ({ev['status'] if ev else d['status'] if d['status'] != 'ok' else 'missing'})")
#|    if not any_missing:
#|        out.append("  (none)")
#|    return out
#|
#|
#|def _register(run, group_id, reviewer):
#|    out = _header(run, group_id, "Assessment register")
#|    out.append(f"Reviewer: {reviewer}   Written: {store.now()}")
#|    out.append("")
#|    out.append(f"{'STIG':<34}{'Vuln':<11}{'Rule_Ver':<17}{'Rule':<14}{'Recommended':<17}{'Final':<17}Changed")
#|    for c in run["results"][group_id]["controls"].values():
#|        rule = f"{c['rule_id']} v{c['rule_version']}" if c["rule_id"] else "manual"
#|        out.append(f"{c['family'][:33]:<34}{c['vuln_id']:<11}{c['rule_ver']:<17}{rule:<14}"
#|                   f"{result_label(c, 'recommended'):<17}{result_label(c):<17}{'yes' if c['reviewer_changed'] else ''}")
#|        if c["reviewer_changed"] and c.get("reviewer_comment"):
#|            out.append(f"{'':<34}rationale: {c['reviewer_comment']}")
#|    return out
#|
#|
#|def import_solarwinds(path, groups_db, rules_db):
#|    """Parse a SolarWinds output file into a new run (not yet evaluated)."""
#|    text = store.read_text(path)
#|    probe = collect.parse_output(text)
#|    script_ids = {d["script_id"] for d in probe["devices"] if d["script_id"]}
#|    expected = set()
#|    for sid in script_ids:
#|        rec = store.load_script_record(sid)
#|        if rec:
#|            expected |= set(rec["commands"])
#|    if not expected:
#|        expected = {c.strip() for r in rules_db["rules"] for c in r["commands"] if c.strip()}
#|    parsed = collect.parse_output(text, expected)
#|    archived = store.archive_evidence(path)
#|    run = new_run(parsed, archived, groups_db)
#|    run["script_ids"] = sorted(script_ids)
#|    return run
#@ END
#@ FILE src/checklist.py SHA 205b37b3d87a31835d67152c9f5d995c86fb36f4c06c5f5f1f61d106baa53e13 CHUNK 1 OF 1
#|"""Read, patch and validate STIG Viewer checklists.
#|
#|  .ckl  - STIG Viewer 2.x (XML)
#|  .cklb - STIG Viewer 3.x (JSON; usually saved on one line, which is normal for JSON)
#|
#|Output is always a copy of the source template with only these per-rule fields changed:
#|status, finding details, comments. For .cklb the checklist-level "id" and "title" are also
#|replaced so several group checklists made from one template do not collide in STIG Viewer 3.
#|validate() proves nothing else changed.
#|"""
#|import datetime
#|import hashlib
#|import json
#|import re
#|import uuid
#|import xml.etree.ElementTree as ET
#|from pathlib import Path
#|from xml.sax.saxutils import escape, unescape
#|
#|STATUSES = ["not_a_finding", "open", "not_applicable", "not_reviewed"]
#|STATUS_LABELS = {
#|    "not_a_finding": "Not a Finding",
#|    "open": "Open",
#|    "not_applicable": "Not Applicable",
#|    "not_reviewed": "Not Reviewed",
#|}
#|LABEL_TO_STATUS = {v: k for k, v in STATUS_LABELS.items()}
#|CKL_STATUS = {
#|    "not_a_finding": "NotAFinding",
#|    "open": "Open",
#|    "not_applicable": "Not_Applicable",
#|    "not_reviewed": "Not_Reviewed",
#|}
#|CKL_TO_STATUS = {v: k for k, v in CKL_STATUS.items()}
#|
#|FORMAT_LABELS = {"ckl": "STIG Viewer 2.x (.ckl)", "cklb": "STIG Viewer 3 (.cklb)"}
#|COMPARE_FIELDS = {"title": "title", "severity": "severity", "check": "check text", "fix": "fix text",
#|                  "rule_id": "rule ID", "rule_ver": "rule version"}
#|
#|CKLB_RULE_FIELDS = ("status", "finding_details", "comments")
#|CKLB_TOP_FIELDS = ("id", "title")
#|CKL_VULN_FIELDS = ("STATUS", "FINDING_DETAILS", "COMMENTS")
#|
#|
#|class ChecklistError(Exception):
#|    pass
#|
#|
#|def family_of(stig_id):
#|    """Cisco_IOS_XE_Switch_NDM_STIG -> NDM"""
#|    m = re.search(r"_([A-Za-z0-9]+)_STIG$", stig_id or "")
#|    return m.group(1).upper() if m else (stig_id or "UNKNOWN")
#|
#|
#|def short_name(title, stig_id=""):
#|    """'Cisco IOS XE Switch NDM Security Technical Implementation Guide' -> 'Cisco IOS XE Switch NDM'"""
#|    name = re.sub(r"\s*(Security Technical Implementation Guide|STIG)\s*$", "", title or "", flags=re.I).strip()
#|    return name or stig_id or "Unknown STIG"
#|
#|
#|def release_key(version, release_info):
#|    """Sortable (version, release, benchmark date) so newer DISA releases sort last."""
#|    def num(pattern):
#|        m = re.search(pattern, release_info or "", re.I)
#|        return int(m.group(1)) if m else 0
#|    try:
#|        ver = int(str(version).strip() or 0)
#|    except ValueError:
#|        ver = 0
#|    date = re.search(r"Benchmark Date:\s*(\d{1,2}\s+\w+\s+\d{4})", release_info or "")
#|    stamp = ""
#|    if date:
#|        try:
#|            stamp = datetime.datetime.strptime(date.group(1), "%d %b %Y").strftime("%Y%m%d")
#|        except ValueError:
#|            stamp = ""
#|    return (ver, num(r"Release:\s*(\d+)"), stamp)
#|
#|
#|def release_label(version, release_info):
#|    """'V3R6 (01 Apr 2026)'"""
#|    rel = re.search(r"Release:\s*(\d+)", release_info or "")
#|    date = re.search(r"Benchmark Date:\s*(.+)$", release_info or "")
#|    label = f"V{version}R{rel.group(1)}" if rel else (release_info or "?")
#|    return f"{label} ({date.group(1).strip()})" if date else label
#|
#|
#|def compare_controls(old, new):
#|    """Differences between two releases' control lists.
#|
#|    Returns [{"vuln_id", "kind": added|removed|changed, "fields": [...], "old", "new"}]
#|    """
#|    a = {c["vuln_id"]: c for c in old}
#|    b = {c["vuln_id"]: c for c in new}
#|    out = []
#|    for vid in [c["vuln_id"] for c in new] + [v for v in a if v not in b]:
#|        x, y = a.get(vid), b.get(vid)
#|        if x and y:
#|            fields = [f for f in COMPARE_FIELDS
#|                      if (f in ("check", "fix") and text_hash(x.get(f)) != text_hash(y.get(f)))
#|                      or (f not in ("check", "fix") and (x.get(f) or "") != (y.get(f) or ""))]
#|            if fields:
#|                out.append({"vuln_id": vid, "kind": "changed", "fields": fields, "old": x, "new": y})
#|        elif y:
#|            out.append({"vuln_id": vid, "kind": "added", "fields": [], "old": None, "new": y})
#|        else:
#|            out.append({"vuln_id": vid, "kind": "removed", "fields": [], "old": x, "new": None})
#|    return out
#|
#|
#|def viewer_of(path, fmt, data=None):
#|    """Which STIG Viewer wrote the file, e.g. 'STIG Viewer 2.10' or 'STIG Viewer 3 (CKLB 1.0)'."""
#|    if fmt == "cklb":
#|        return f"STIG Viewer 3 (CKLB {(data or {}).get('cklb_version') or '1.0'})"
#|    head = Path(path).read_bytes()[:400].decode("utf-8", errors="replace")
#|    m = re.search(r"STIG Viewer\s*::\s*([\d.]+)", head)
#|    return f"STIG Viewer {m.group(1)}" if m else "STIG Viewer 2.x"
#|
#|
#|def text_hash(text):
#|    """Fingerprint of check text, whitespace-insensitive. Used to flag rules after a STIG update."""
#|    return hashlib.sha256(" ".join((text or "").split()).encode("utf-8")).hexdigest()[:16]
#|
#|
#|def detect_format(path):
#|    path = Path(path)
#|    if path.suffix.lower() == ".cklb":
#|        return "cklb"
#|    if path.suffix.lower() == ".ckl":
#|        return "ckl"
#|    head = path.read_bytes()[:200].lstrip(b"\xef\xbb\xbf \r\n\t")
#|    if head.startswith(b"{"):
#|        return "cklb"
#|    if head.startswith(b"<"):
#|        return "ckl"
#|    raise ChecklistError(f"{path.name} is not a .ckl or .cklb checklist")
#|
#|
#|def _control(vuln_id, rule_ver, rule_id, severity, title, check, fix, status):
#|    return {
#|        "vuln_id": vuln_id,
#|        "rule_ver": rule_ver or "",
#|        "rule_id": rule_id or "",
#|        "severity": severity or "",
#|        "title": title or "",
#|        "check": check or "",
#|        "fix": fix or "",
#|        "template_status": status,
#|        "check_hash": text_hash(check),
#|    }
#|
#|
#|def read_checklist(path):
#|    """Return {"format", "stigs": [{"stig_id", "family", "title", "release_info", "version", "controls"}]}"""
#|    fmt = detect_format(path)
#|    stigs = []
#|    if fmt == "cklb":
#|        data = _load_cklb(path)
#|        for s in data.get("stigs") or []:
#|            controls = [_control(r.get("group_id"), r.get("rule_version"), r.get("rule_id"),
#|                                 r.get("severity"), r.get("rule_title"), r.get("check_content"),
#|                                 r.get("fix_text"), r.get("status", "not_reviewed"))
#|                        for r in s.get("rules") or []]
#|            stigs.append({"stig_id": s.get("stig_id", ""), "title": s.get("stig_name", ""),
#|                          "short": s.get("display_name") or short_name(s.get("stig_name"), s.get("stig_id")),
#|                          "release_info": s.get("release_info", ""), "version": str(s.get("version", "")),
#|                          "controls": controls})
#|    else:
#|        root = _load_ckl(path).getroot()
#|        for istig in root.iter("iSTIG"):
#|            info = {}
#|            for si in istig.iter("SI_DATA"):
#|                info[si.findtext("SID_NAME", "")] = si.findtext("SID_DATA", "")
#|            controls = []
#|            for vuln in istig.iter("VULN"):
#|                d = {}
#|                for sd in vuln.findall("STIG_DATA"):
#|                    d.setdefault(sd.findtext("VULN_ATTRIBUTE", ""), sd.findtext("ATTRIBUTE_DATA", ""))
#|                status = CKL_TO_STATUS.get(vuln.findtext("STATUS", ""), "not_reviewed")
#|                controls.append(_control(d.get("Vuln_Num"), d.get("Rule_Ver"), d.get("Rule_ID"),
#|                                         d.get("Severity"), d.get("Rule_Title"), d.get("Check_Content"),
#|                                         d.get("Fix_Text"), status))
#|            stigs.append({"stig_id": info.get("stigid", ""), "title": info.get("title", ""),
#|                          "short": short_name(info.get("title"), info.get("stigid")),
#|                          "release_info": info.get("releaseinfo", ""), "version": info.get("version", ""),
#|                          "controls": controls})
#|    if not stigs:
#|        raise ChecklistError(f"{Path(path).name} contains no STIGs")
#|    for s in stigs:
#|        s["family"] = family_of(s["stig_id"])
#|        missing = [c for c in s["controls"] if not c["vuln_id"]]
#|        if missing:
#|            raise ChecklistError(f"{s['stig_id']}: {len(missing)} rule(s) have no Vuln ID")
#|    return {"format": fmt, "viewer": viewer_of(path, fmt, data if fmt == "cklb" else None), "stigs": stigs}
#|
#|
#|def _load_cklb(path):
#|    try:
#|        with open(path, encoding="utf-8-sig") as f:
#|            return json.load(f)
#|    except ValueError as e:
#|        raise ChecklistError(f"{Path(path).name} is not valid CKLB JSON: {e}")
#|
#|
#|def _load_ckl(path):
#|    try:
#|        return ET.parse(path)
#|    except ET.ParseError as e:
#|        raise ChecklistError(f"{Path(path).name} is not valid CKL XML: {e}")
#|
#|
#|# ---------------------------------------------------------------- patching
#|
#|def write_patched(src, dst, updates, title=None):
#|    """Copy src to dst, changing only the given fields.
#|
#|    updates: {(stig_id, vuln_id): {"status": <STATUSES value>, "finding_details": str, "comments": str}}
#|             A field that is missing or None is left exactly as the template has it.
#|    Returns the number of controls changed.
#|    """
#|    for key, upd in updates.items():
#|        if upd.get("status") is not None and upd["status"] not in STATUSES:
#|            raise ChecklistError(f"{key}: invalid status {upd['status']!r}")
#|    if detect_format(src) == "cklb":
#|        return _patch_cklb(src, dst, updates, title)
#|    return _patch_ckl(src, dst, updates)
#|
#|
#|def _clean(text):
#|    return (text or "").replace("\r\n", "\n").replace("\r", "\n")
#|
#|
#|def _patch_cklb(src, dst, updates, title):
#|    data = _load_cklb(src)
#|    pending = dict(updates)
#|    for s in data.get("stigs") or []:
#|        for r in s.get("rules") or []:
#|            upd = pending.pop((s.get("stig_id"), r.get("group_id")), None)
#|            if not upd:
#|                continue
#|            for field in CKLB_RULE_FIELDS:
#|                if upd.get(field) is not None:
#|                    r[field] = _clean(upd[field]) if field != "status" else upd[field]
#|    if pending:
#|        raise ChecklistError(f"Controls not found in template: {', '.join(v for _, v in pending)}")
#|    data["id"] = str(uuid.uuid4())
#|    if title:
#|        data["title"] = title
#|    with open(dst, "w", encoding="utf-8", newline="") as f:
#|        f.write(json.dumps(data, ensure_ascii=False, separators=(",", ":")))
#|    return len(updates)
#|
#|
#|ISTIG_RE = re.compile(r"<iSTIG>.*?</iSTIG>", re.S)
#|VULN_RE = re.compile(r"<VULN>.*?</VULN>", re.S)
#|STIGID_RE = re.compile(r"<SID_NAME>stigid</SID_NAME>\s*<SID_DATA>(.*?)</SID_DATA>", re.S)
#|VULNNUM_RE = re.compile(r"<VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>(.*?)</ATTRIBUTE_DATA>", re.S)
#|
#|
#|def _set_element(block, tag, value):
#|    pattern = re.compile(rf"<{tag}>.*?</{tag}>|<{tag}\s*/>", re.S)
#|    if not pattern.search(block):
#|        raise ChecklistError(f"<{tag}> not found in VULN block")
#|    new = f"<{tag}>{escape(value)}</{tag}>"
#|    return pattern.sub(lambda m: new, block, count=1)
#|
#|
#|def _patch_ckl(src, dst, updates):
#|    # Edit the XML text in place (rather than re-serialising the whole tree) so every byte
#|    # outside the three edited elements stays exactly as STIG Viewer wrote it.
#|    with open(src, encoding="utf-8", newline="") as f:
#|        text = f.read()
#|    pending = dict(updates)
#|
#|    def patch_vuln(stig_id, m):
#|        block = m.group(0)
#|        num = VULNNUM_RE.search(block)
#|        upd = pending.pop((stig_id, unescape(num.group(1)).strip()), None) if num else None
#|        if not upd:
#|            return block
#|        if upd.get("status") is not None:
#|            block = _set_element(block, "STATUS", CKL_STATUS[upd["status"]])
#|        if upd.get("finding_details") is not None:
#|            block = _set_element(block, "FINDING_DETAILS", _clean(upd["finding_details"]))
#|        if upd.get("comments") is not None:
#|            block = _set_element(block, "COMMENTS", _clean(upd["comments"]))
#|        return block
#|
#|    def patch_istig(m):
#|        block = m.group(0)
#|        sid = STIGID_RE.search(block)
#|        stig_id = unescape(sid.group(1)).strip() if sid else ""
#|        return VULN_RE.sub(lambda vm: patch_vuln(stig_id, vm), block)
#|
#|    text = ISTIG_RE.sub(patch_istig, text)
#|    if pending:
#|        raise ChecklistError(f"Controls not found in template: {', '.join(v for _, v in pending)}")
#|    with open(dst, "w", encoding="utf-8", newline="") as f:
#|        f.write(text)
#|    return len(updates)
#|
#|
#|# ---------------------------------------------------------------- validation
#|
#|def validate(src, dst):
#|    """Compare output to its source template. Returns (ok, lines)."""
#|    try:
#|        if detect_format(src) == "cklb":
#|            problems, changed = _validate_cklb(src, dst)
#|        else:
#|            problems, changed = _validate_ckl(src, dst)
#|    except Exception as e:  # unreadable output is a validation failure, not a crash
#|        problems, changed = [f"Could not read output: {e}"], 0
#|    lines = [f"Source: {Path(src).name}", f"Output: {Path(dst).name}",
#|             f"Controls with edited fields: {changed}"]
#|    if problems:
#|        lines.append(f"RESULT: FAILED ({len(problems)} problem(s))")
#|        lines += [f"  - {p}" for p in problems[:200]]
#|    else:
#|        lines.append("RESULT: PASSED - only status, finding details and comments differ"
#|                     + (" (plus checklist id/title)" if detect_format(src) == "cklb" else ""))
#|    return not problems, lines
#|
#|
#|def _validate_cklb(src, dst):
#|    a, b = _load_cklb(src), _load_cklb(dst)
#|    problems, changed = [], 0
#|    for key in set(a) | set(b):
#|        if key not in CKLB_TOP_FIELDS + ("stigs",) and a.get(key) != b.get(key):
#|            problems.append(f"Checklist field '{key}' changed")
#|    sa, sb = a.get("stigs") or [], b.get("stigs") or []
#|    if len(sa) != len(sb):
#|        return problems + ["Number of STIGs changed"], 0
#|    for x, y in zip(sa, sb):
#|        if {k: v for k, v in x.items() if k != "rules"} != {k: v for k, v in y.items() if k != "rules"}:
#|            problems.append(f"STIG header changed: {x.get('stig_id')}")
#|        rx, ry = x.get("rules") or [], y.get("rules") or []
#|        if len(rx) != len(ry):
#|            problems.append(f"{x.get('stig_id')}: number of rules changed")
#|            continue
#|        for r1, r2 in zip(rx, ry):
#|            strip1 = {k: v for k, v in r1.items() if k not in CKLB_RULE_FIELDS}
#|            strip2 = {k: v for k, v in r2.items() if k not in CKLB_RULE_FIELDS}
#|            if strip1 != strip2:
#|                diff = sorted(k for k in set(strip1) | set(strip2) if strip1.get(k) != strip2.get(k))
#|                problems.append(f"{r1.get('group_id')}: protected field(s) changed: {', '.join(diff)}")
#|            if r2.get("status") not in STATUSES:
#|                problems.append(f"{r2.get('group_id')}: invalid status {r2.get('status')!r}")
#|            if any(r1.get(k) != r2.get(k) for k in CKLB_RULE_FIELDS):
#|                changed += 1
#|    return problems, changed
#|
#|
#|def _canon(el, skip=()):
#|    return (el.tag, (el.text or "").strip() and el.text, tuple(sorted(el.attrib.items())),
#|            tuple(_canon(c) for c in el if c.tag not in skip))
#|
#|
#|def _validate_ckl(src, dst):
#|    problems, changed = [], 0
#|    with open(src, encoding="utf-8") as f:
#|        pre_a = f.read().split("<CHECKLIST", 1)[0]
#|    with open(dst, encoding="utf-8") as f:
#|        pre_b = f.read().split("<CHECKLIST", 1)[0]
#|    if pre_a != pre_b:
#|        problems.append("XML declaration / STIG Viewer header comment changed")
#|    ra, rb = _load_ckl(src).getroot(), _load_ckl(dst).getroot()
#|    if _canon(ra.find("ASSET")) != _canon(rb.find("ASSET")):
#|        problems.append("ASSET (target data) changed")
#|    ia, ib = ra.findall(".//iSTIG"), rb.findall(".//iSTIG")
#|    if len(ia) != len(ib):
#|        return problems + ["Number of STIGs changed"], 0
#|    for x, y in zip(ia, ib):
#|        if _canon(x.find("STIG_INFO")) != _canon(y.find("STIG_INFO")):
#|            problems.append("STIG_INFO changed")
#|        vx, vy = x.findall("VULN"), y.findall("VULN")
#|        if len(vx) != len(vy):
#|            problems.append("Number of VULNs changed")
#|            continue
#|        for v1, v2 in zip(vx, vy):
#|            num = next((sd.findtext("ATTRIBUTE_DATA") for sd in v1.findall("STIG_DATA")
#|                        if sd.findtext("VULN_ATTRIBUTE") == "Vuln_Num"), "?")
#|            if _canon(v1, CKL_VULN_FIELDS) != _canon(v2, CKL_VULN_FIELDS):
#|                problems.append(f"{num}: protected content changed")
#|            if v2.findtext("STATUS") not in CKL_TO_STATUS:
#|                problems.append(f"{num}: invalid status {v2.findtext('STATUS')!r}")
#|            if any((v1.findtext(t) or "") != (v2.findtext(t) or "") for t in CKL_VULN_FIELDS):
#|                changed += 1
#|    return problems, changed
#@ END
#@ FILE src/collect.py SHA 60df480238255a693ab3481021c573e05be7cb1c45d734f66c542f9bcdaa8b6f CHUNK 1 OF 1
#|"""SolarWinds side: build the show-command script, and split SolarWinds output back into
#|per-device, per-command evidence.
#|
#|Expected SolarWinds "Execute Command Script" output (see _resources/test_output1.txt):
#|
#|    ____________________________________________________________
#|    HOSTNAME (IP):
#|    <device output, or "ERROR: ..." if the connection failed>
#|    ____________________________________________________________
#|
#|The generated script puts "! sources:" and "! CMD:" marker lines before every command, and
#|these come back in the output, so each block of output can be tied to its command safely.
#|If the markers are ever stripped, the echoed command line itself is used instead.
#|"""
#|import datetime
#|import hashlib
#|import re
#|
#|from rules import classify_output
#|
#|SEPARATOR_RE = re.compile(r"^\s*_{10,}\s*$")
#|HEADER_RE = re.compile(r"^(?P<host>[^\s()]+)\s*\((?P<ip>[^()]*)\)\s*:\s*$")
#|PROMPT_RE = re.compile(r"^[\w.\-]+(\([\w\-]+\))?[#>]\s?")
#|
#|
#|def build_script(command_sources, groups):
#|    """command_sources: {command: set of source labels like 'NDM V-220524'}.
#|
#|    Returns (script_text, script_id). The id is a fingerprint of the command list, so the
#|    same set of commands always gets the same id.
#|    """
#|    commands = sorted(command_sources)
#|    script_id = hashlib.sha256("\n".join(commands).encode("utf-8")).hexdigest()[:12]
#|    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
#|    out = [
#|        "! STIGTOOL collection script",
#|        f"! script_id: {script_id}",
#|        f"! generated_at_utc: {now}",
#|        f"! groups: {', '.join(groups)}",
#|        "! reviewer_notice: Evidence collection only; no automated compliance determination.",
#|        "",
#|    ]
#|    for cmd in commands:
#|        out.append(f"! sources: {','.join(sorted(command_sources[cmd]))}")
#|        out.append(f"! CMD: {cmd}")
#|        out.append(cmd)
#|        out.append("")
#|    return "\n".join(out), script_id
#|
#|
#|def _strip_prompt(line):
#|    return PROMPT_RE.sub("", line, count=1).strip()
#|
#|
#|def _trim(lines):
#|    while lines and not lines[0].strip():
#|        lines.pop(0)
#|    while lines and not lines[-1].strip():
#|        lines.pop()
#|    return lines
#|
#|
#|def _parse_device(host, body, expected):
#|    device = {"host": host["host"], "ip": host["ip"], "status": "ok", "error": "",
#|              "script_id": "", "outputs": {}, "warnings": []}
#|    has_markers = any(l.startswith("! CMD:") for l in body)
#|    errors = [l.strip() for l in body if l.strip().upper().startswith("ERROR")]
#|    if errors and not has_markers:
#|        device["status"] = "error"
#|        device["error"] = errors[0]
#|        return device
#|
#|    prompt_only = re.compile(rf"^{re.escape(host['host'])}(\([\w\-]+\))?[#>]\s*$", re.I)
#|    blocks, current, buf = [], None, []
#|
#|    def flush():
#|        if current is not None:
#|            blocks.append((current, list(buf)))
#|
#|    known = set(expected or [])
#|    for raw in body:
#|        line = raw.rstrip("\r")
#|        if line.startswith("! script_id:"):
#|            device["script_id"] = line.split(":", 1)[1].strip()
#|            continue
#|        if has_markers:
#|            if line.startswith("! CMD:"):
#|                flush()
#|                current, buf = line[6:].strip(), []
#|                continue
#|            if line.startswith("! sources:"):
#|                flush()
#|                current, buf = None, []
#|                continue
#|        elif _strip_prompt(line) in known and line.strip():
#|            flush()
#|            current, buf = _strip_prompt(line), []
#|            continue
#|        if current is None:
#|            continue
#|        if prompt_only.match(line.strip()):
#|            continue
#|        buf.append(line)
#|    flush()
#|
#|    for cmd, lines in blocks:
#|        lines = _trim(lines)
#|        if lines and _strip_prompt(lines[0]) == cmd:  # device echo of the command
#|            lines = _trim(lines[1:])
#|        text = "\n".join(lines)
#|        if cmd in device["outputs"]:
#|            device["warnings"].append(f"'{cmd}' appears more than once; last copy used")
#|        device["outputs"][cmd] = {"status": classify_output(text), "text": text}
#|    if not device["outputs"]:
#|        device["status"] = "error"
#|        device["error"] = "No command output could be identified"
#|    return device
#|
#|
#|def parse_output(text, expected_commands=None):
#|    """Split a SolarWinds output file into devices.
#|
#|    Returns {"devices": [device], "warnings": [str], "job_lines": [str]}
#|    device = {"host", "ip", "status": "ok"|"error", "error", "script_id",
#|              "outputs": {command: {"status": "ok"|"invalid", "text"}}, "warnings"}
#|    """
#|    chunks, chunk = [], []
#|    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
#|        if SEPARATOR_RE.match(line):
#|            chunks.append(chunk)
#|            chunk = []
#|        else:
#|            chunk.append(line)
#|    chunks.append(chunk)
#|
#|    devices, warnings, job_lines, seen = [], [], [], {}
#|    for chunk in chunks:
#|        lines = list(chunk)
#|        while lines and not lines[0].strip():
#|            lines.pop(0)
#|        if not lines:
#|            continue
#|        m = HEADER_RE.match(lines[0].strip())
#|        if not m:
#|            job_lines += [l for l in lines if l.strip()]
#|            continue
#|        device = _parse_device(m.groupdict(), lines[1:], expected_commands)
#|        key = device["host"].lower()
#|        if key in seen:
#|            warnings.append(f"{device['host']} appears more than once; last copy used")
#|            devices[seen[key]] = device
#|        else:
#|            seen[key] = len(devices)
#|            devices.append(device)
#|    if not devices:
#|        warnings.append("No device sections found. Is this a SolarWinds 'Execute Command Script' output file?")
#|    return {"devices": devices, "warnings": warnings, "job_lines": job_lines}
#@ END
#@ FILE src/drafts.py SHA 012f72bf07afaeea55ec277b778d340f03da6d1cedf0028707a67c1d91e4d261 CHUNK 1 OF 1
#|"""Starter DRAFT rules for the Cisco IOS-XE (Switch / Router) and NX-OS STIGs.
#|
#|These are a starting point written from each control's check text and from how the target platforms
#|print their configuration:
#|  IOS-XE Switch STIGs -> Catalyst 9300 (IOS-XE 17.x)
#|  IOS-XE Router STIGs -> Catalyst 8300 (IOS-XE 17.x)
#|  NX-OS Switch STIGs  -> Nexus 9336C-FX2 / 93180YC-FX3 (NX-OS 9.3 / 10.x)
#|
#|Every rule is created as a DRAFT. Before it can be made Active, an admin must review it against the
#|check text, save a passing and a failing test sample, and adjust anything site-specific (parking VLAN,
#|approved software releases, which interfaces are external...). Controls that need documents, design
#|plans or interviews get no rule; they are listed in the report with the reason.
#|
#|Entries are keyed "<platform>:<rule version>" (platform = IOSXE_SW, IOSXE_RTR, NXOS) with a fallback to
#|"IOSXE:<rule version>" for IOS-XE checks that are the same on switches and routers.
#|"""
#|import re
#|
#|import assess
#|import harden
#|import rules as engine
#|import store
#|
#|RUN = "show running-config"
#|STARTER_NOTE = ("STARTER DRAFT generated from the STIG check text for {platform}. Review it against the check "
#|                "text, save at least one passing and one failing test sample from a real device, then activate.")
#|PLATFORM_LABEL = {"IOSXE_SW": "Catalyst 9300 (IOS-XE 17.x)", "IOSXE_RTR": "Catalyst 8300 (IOS-XE 17.x)",
#|                  "NXOS": "Nexus 9300-series (NX-OS 9.3/10.x)"}
#|
#|
#|# ---------------------------------------------------------------- condition helpers
#|
#|def c(check, text, how="starts with", cmd=RUN, scope="all", section="", section_how="starts with", only="",
#|      exclude="", if_none="fail", op=">=", value="", ignore_case=False):
#|    return {"command": cmd, "scope": scope, "section": section, "section_how": section_how, "only": only,
#|            "exclude": exclude, "if_none": if_none, "check": check, "text": text, "how": how,
#|            "ignore_case": ignore_case, "op": op, "value": str(value)}
#|
#|
#|def has(text, how="starts with", **kw):
#|    return c("has", text, how, **kw)
#|
#|
#|def lacks(text, how="starts with", **kw):
#|    return c("lacks", text, how, **kw)
#|
#|
#|def rx_has(pattern, **kw):
#|    return c("has", pattern, "regex", **kw)
#|
#|
#|def rx_lacks(pattern, **kw):
#|    return c("lacks", pattern, "regex", **kw)
#|
#|
#|def num(text, op, value, how="starts with", **kw):
#|    return c("number", text, how, op=op, value=value, **kw)
#|
#|
#|def count(text, op, value, how="starts with", **kw):
#|    return c("count", text, how, op=op, value=value, **kw)
#|
#|
#|def every(section, cond, only="", exclude="", if_none="pass", section_how="starts with"):
#|    """Apply cond to EVERY matching section (no matching sections = pass unless told otherwise)."""
#|    return {**cond, "scope": "every", "section": section, "section_how": section_how, "only": only,
#|            "exclude": exclude, "if_none": if_none}
#|
#|
#|def anysec(section, cond, only="", exclude="", if_none="fail", section_how="starts with"):
#|    return {**cond, "scope": "any", "section": section, "section_how": section_how, "only": only,
#|            "exclude": exclude, "if_none": if_none}
#|
#|
#|def R(*conds, mode="ALL", na=None, note="", cmds=None):
#|    return {"conds": list(conds), "mode": mode, "na": list(na or []), "note": note, "cmds": cmds}
#|
#|
#|def MANUAL(reason):
#|    return {"manual": reason}
#|
#|
#|# Section shortcuts
#|VTY = "line vty"
#|ACTIVE_VTY = dict(exclude="transport input none")
#|ACCESS = dict(only="switchport mode access", exclude="shutdown")            # IOS-XE access ports
#|TRUNK = dict(only="switchport mode trunk", exclude="shutdown")
#|L3IF = dict(only="ip address", exclude="shutdown")                          # IOS-XE / NX-OS routed ports
#|NX_ACCESS = dict(only="switchport access vlan", exclude="re:^\\s*(shutdown|switchport mode trunk)\\s*$")
#|DENY_NO_LOG = r"^\s*(\d+\s+)?deny\b(?!.*\blog(-input)?\b)"
#|DENY_NO_LOGINPUT = r"^\s*(\d+\s+)?deny\b(?!.*\blog-input\b)"
#|ARCHIVE_LOG = anysec("archive", has("logging enable"))
#|VLAN1_IN_LIST = r"switchport trunk allowed vlan (add )?(.*,)?1(-\d+)?(,.*)?\s*$"
#|# Front-panel switch ports only (skips Vlan, Loopback, Port-channel and the Catalyst 9300 AppGigabitEthernet
#|# app-hosting port, which is a trunk by default).
#|IOS_PORT = r"^interface (?!AppGig)\S*(Ethernet|GigE)\d"
#|# Host-facing ports: front-panel ports that are not trunks, routed, management, port-channel members or shut down.
#|# (Unconfigured Catalyst ports default to 'dynamic auto' and are host ports too.)
#|IOS_HOST = dict(section_how="regex",
#|                exclude="re:^\\s*(shutdown|switchport mode trunk|no switchport|vrf forwarding|channel-group)\\b")
#|# Nexus: unconfigured Ethernet ports are shut down by default, so host ports are the ones with 'no shutdown'.
#|NX_PORT = r"^interface Ethernet\d"
#|NX_HOST = dict(section_how="regex", only="re:^\\s*no shutdown\\s*$",
#|               exclude="re:^\\s*(switchport mode (trunk|fex-fabric)|no switchport|channel-group)\\b")
#|NX_L3IF = dict(only="ip address", exclude="re:^\\s*(shutdown|vrf member management)\\s*$")
#|# Port roles come from interface descriptions (team setting, tab 3): "description UPLINK - ...",
#|# "description DOWNLINK - ...", "description ACCESS - ..." / "UNTRUSTED - ...". Access checks FAIL when no
#|# access-role ports are found, so unlabelled ports cannot slip past; for core / distribution groups without
#|# access ports, pick a different rule version or mark the control N/A for that group.
#|ROLE_ACCESS = dict(only="role:access", exclude="re:^\\s*shutdown\\s*$", if_none="fail")
#|ROLE_UPLINK = dict(only="role:uplink", exclude="re:^\\s*shutdown\\s*$", if_none="fail")
#|ROLE_DOWNLINK = dict(only="role:downlink", exclude="re:^\\s*shutdown\\s*$", if_none="pass")
#|NOT_UPLINK = dict(exclude="role:uplink", if_none="pass")
#|ROLE_NOTE = ("Uses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks "
#|             "'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports "
#|             "'description ACCESS - ...' or 'UNTRUSTED - ...'. ")
#|LIVE_IOS_PORT = "re:^\\s*(shutdown|no switchport|vrf forwarding|channel-group)\\b"
#|
#|# Not-applicable shortcuts (the feature is not configured on the device)
#|NA_BGP = [lacks("router bgp")]
#|NA_ROUTING = [rx_lacks(r"^router (ospf|ospfv3|bgp|eigrp|isis|rip)\b")]
#|NA_IOS_MPLS = [rx_lacks(r"^\s*mpls (ip|label protocol|ldp)\b")]
#|NA_IOS_TE = [lacks("mpls traffic-eng tunnels")]
#|NA_IOS_VPLS = [rx_lacks(r"^(l2 vfi|l2vpn vfi|bridge-domain)\b")]
#|NA_IOS_PIM = [lacks("ip multicast-routing")]
#|NA_MSDP = [lacks("ip msdp peer")]
#|NA_IPV6 = [rx_lacks(r"^\s*ipv6 address\b")]
#|NA_PERSIST = [lacks("logging persistent")]
#|NA_IOS_PKI = [lacks("crypto pki trustpoint")]
#|NA_AUX = [lacks("line aux")]
#|NA_SNMP = [rx_lacks(r"^snmp-server (group|user|host|community)\b")]
#|NA_NX_BGP = [lacks("feature bgp")]
#|NA_NX_ROUTING = [rx_lacks(r"^feature (ospf|ospfv3|bgp|eigrp|isis|rip)\b")]
#|NA_NX_MPLS = [rx_lacks(r"^(feature mpls|install feature-set mpls|feature-set mpls)\b")]
#|NA_NX_PIM = [lacks("feature pim")]
#|NA_NX_MSDP = [lacks("feature msdp")]
#|NA_NX_OSPF = [lacks("feature ospf")]
#|
#|PERIMETER = ("Perimeter / alternate-gateway / OOBM requirement: first identify which interfaces are external, "
#|             "internal or OOBM and what the approved ACLs are; then build a group-specific rule (e.g. for "
#|             "border routers only).")
#|DESIGN = "Must be compared with the network design / implementation plan (VRF, RT/RD, VC ID, VPN ID); no fixed config pattern."
#|INTERVIEW = "Requires interviewing the ISSM / administrator (e.g. unique keys per AS); keys are not visible in configuration."
#|
#|
#|# ---------------------------------------------------------------- IOS-XE (Catalyst 9300 / 8300)
#|
#|IOSXE = {
#|    "CISC-ND-000010": R(
#|        every(VTY, has("session-limit"), **ACTIVE_VTY),
#|        note="Platforms without session-limit pass by limiting active vty lines instead (vty 0 1 transport ssh, "
#|             "others 'transport input none') - adjust if so. If 'ip http secure-server' is on, also require "
#|             "'ip http max-connections'."),
#|    "CISC-ND-000090": R(ARCHIVE_LOG),
#|    "CISC-ND-000100": R(ARCHIVE_LOG),
#|    "CISC-ND-000110": R(ARCHIVE_LOG),
#|    "CISC-ND-000120": R(ARCHIVE_LOG),
#|    "CISC-ND-000140": R(every(VTY, rx_has(r"^\s*access-class \S+ in"), **ACTIVE_VTY),
#|                        note="Also confirm the ACL only permits the management network."),
#|    "CISC-ND-000150": R(num("login block-for", ">=", 900), num("attempts", "<=", 3, how="contains")),
#|    "CISC-ND-000160": R(has("banner login"),
#|                        has("You are accessing a U.S. Government (USG) Information System", how="contains")),
#|    "CISC-ND-000210": R(has("logging userinfo", how="whole line"), ARCHIVE_LOG),
#|    "CISC-ND-000280": R(has("service timestamps log datetime")),
#|    "CISC-ND-000290": R(every("ip access-list extended", rx_lacks(DENY_NO_LOGINPUT)),
#|                        note="Only interface-bound ACLs matter; CoPP / route-filter ACLs may need excluding."),
#|    "CISC-ND-000330": R(ARCHIVE_LOG),
#|    "CISC-ND-000380": R(lacks("file privilege"), na=NA_PERSIST),
#|    "CISC-ND-000390": R(lacks("file privilege"), na=NA_PERSIST),
#|    "CISC-ND-000460": R(lacks("file privilege"), na=NA_PERSIST),
#|    "CISC-ND-000470": R(*[lacks(t, how="whole line") for t in (
#|        "ip boot server", "ip bootp server", "ip dns server", "ip identd", "ip finger", "ip http server",
#|        "ip rcmd rcp-enable", "ip rcmd rsh-enable", "service config", "service finger", "service tcp-small-servers",
#|        "service udp-small-servers", "service pad", "service call-home")], lacks("boot network"),
#|        note="Catalyst 9300/8300 17.x often ship with 'service call-home' and 'ip http server' on. Call-home is "
#|             "allowed only on legacy devices that need it for Smart Licensing - otherwise a finding."),
#|    "CISC-ND-000490": R(count("username ", "==", 1),
#|                        rx_has(r"^aaa authentication login \S+ group \S+ .*\blocal\b"),
#|                        note="Exactly one local account; local must come after the AAA server group."),
#|    "CISC-ND-000550": R(anysec("aaa common-criteria policy", num("min-length", ">=", 15))),
#|    "CISC-ND-000570": R(anysec("aaa common-criteria policy", num("upper-case", ">=", 1))),
#|    "CISC-ND-000580": R(anysec("aaa common-criteria policy", num("lower-case", ">=", 1))),
#|    "CISC-ND-000590": R(anysec("aaa common-criteria policy", num("numeric-count", ">=", 1))),
#|    "CISC-ND-000600": R(anysec("aaa common-criteria policy", num("special-case", ">=", 1))),
#|    "CISC-ND-000610": R(anysec("aaa common-criteria policy", num("char-changes", ">=", 8))),
#|    "CISC-ND-000620": R(has("service password-encryption", how="whole line"), has("enable secret"),
#|                        lacks("enable password")),
#|    "CISC-ND-000720": R(every(VTY, num("exec-timeout", "<=", 5), **ACTIVE_VTY),
#|                        every("line con", num("exec-timeout", "<=", 5), if_none="fail"),
#|                        rx_lacks(r"^\s*exec-timeout 0 0\s*$"),
#|                        note="exec-timeout absent = default 10 minutes (finding). If 'ip http secure-server' is on, "
#|                             "also check 'ip http timeout-policy idle 300' or less."),
#|    "CISC-ND-000880": R(ARCHIVE_LOG),
#|    "CISC-ND-000980": R(rx_has(r"^logging buffered \d+")),
#|    "CISC-ND-001000": R(rx_lacks(r"^logging trap (emergencies|alerts|0|1)\s*$"),
#|                        note="No 'logging trap' line means informational (compliant)."),
#|    "CISC-ND-001030": R(count("ntp server", ">=", 2)),
#|    "CISC-ND-001130": R(rx_has(r"^snmp-server group \S+ v3 (auth|priv)\b"), rx_lacks(r"^snmp-server group \S+ v3 noauth\b"),
#|                        lacks("snmp-server community"),
#|                        rx_lacks(r"Authentication Protocol:\s*(MD5|None)", cmd="show snmp user"),
#|                        na=NA_SNMP, cmds=[RUN, "show snmp user"],
#|                        note="IOS-XE does not print SNMPv3 users in the running-config, so the HMAC is read from "
#|                             "'show snmp user' (SHA / SHA-2 required)."),
#|    "CISC-ND-001140": R(rx_has(r"^snmp-server group \S+ v3 priv\b"), rx_lacks(r"^snmp-server group \S+ v3 (auth|noauth)\b"),
#|                        rx_lacks(r"Privacy Protocol:\s*(None|DES|3DES)\b", cmd="show snmp user"),
#|                        na=NA_SNMP, cmds=[RUN, "show snmp user"]),
#|    "CISC-ND-001150": R(has("ntp authenticate", how="whole line"), rx_has(r"^ntp authentication-key \d+ hmac-sha2"),
#|                        has("ntp trusted-key"), rx_lacks(r"^ntp server (?!.*\bkey\b)"),
#|                        note="hmac-sha2-256 NTP keys need a recent IOS-XE 17.x release; older releases only offer MD5."),
#|    "CISC-ND-001200": R(has("ip ssh version 2", how="whole line"), has("ip ssh server algorithm mac"),
#|                        rx_lacks(r"^ip ssh server algorithm mac .*hmac-sha1")),
#|    "CISC-ND-001210": R(has("ip ssh server algorithm encryption"),
#|                        rx_lacks(r"^ip ssh server algorithm encryption .*(cbc|3des)")),
#|    "CISC-ND-001250": R(ARCHIVE_LOG),
#|    "CISC-ND-001260": R(has("login on-failure log"), has("login on-success log")),
#|    "CISC-ND-001270": R(ARCHIVE_LOG),
#|    "CISC-ND-001370": R(count(r"^(radius server|tacacs server|radius-server host|tacacs-server host) ", ">=", 2, how="regex"),
#|                        rx_has(r"^aaa authentication login \S+ group ")),
#|    "CISC-ND-001410": R(anysec("event manager applet", has("CONFIG_I", how="contains")),
#|                        anysec("event manager applet", rx_has(r"copy running-config (scp|sftp|https)://")),
#|                        has("file prompt quiet", how="whole line"),
#|                        note="Also confirm no cleartext password is embedded in the copy URL."),
#|    "CISC-ND-001440": R(anysec("crypto pki trustpoint", rx_has(r"^\s*enrollment (url|terminal|profile)\b")),
#|                        rx_lacks(r"^\s*enrollment selfsigned\b"), na=NA_IOS_PKI,
#|                        note="Reviewer must confirm the CA is DoD / DoD-approved. IOS-XE creates a self-signed "
#|                             "trustpoint for HTTPS - remove it or replace it with a CA-issued certificate. Cisco's "
#|                             "SLA-TrustPoint (licensing, 'enrollment pkcs12') is ignored."),
#|    "CISC-ND-001450": R(count(r"^logging (host \S+|\d+\.\d+\.\d+\.\d+)", ">=", 2, how="regex")),
#|    "CISC-ND-001470": R(rx_has(r"Cisco IOS XE Software, Version 17\.(0?9|12|15)\.", cmd="show version"),
#|                        cmds=["show version"],
#|                        note="EDIT the version list to the Cisco-supported / site-approved releases before use."),
#|    # ---- RTR (shared by switch and router unless overridden below)
#|    "CISC-RT-000010": MANUAL("Organization-defined information-flow policy: review the ACL design for each group."),
#|    "CISC-RT-000050": R(has("key chain"), anysec("key chain", has("cryptographic-algorithm hmac-sha", how="contains")),
#|                        na=NA_ROUTING,
#|                        note="Check every routing protocol: OSPF interfaces 'ip ospf authentication key-chain', BGP "
#|                             "neighbors 'ao <keychain>', key lifetimes 180 days or less. EIGRP/RIP/IS-IS (MD5 only) "
#|                             "are a permanent finding."),
#|    "CISC-RT-000060": R(rx_lacks(r"^\S+\s+\d+\.\d+\.\d+\.\d+\s+\S+\s+\S+\s+down\s+down\s*$",
#|                                 cmd="show ip interface brief"),
#|                        cmds=["show ip interface brief"],
#|                        note="Flags interfaces that have an IP address, are not shut down, and are down/down. "
#|                             "Unaddressed switchports are ignored."),
#|    "CISC-RT-000090": R(lacks("service config", how="whole line"), lacks("boot network"), lacks("cns ")),
#|    "CISC-RT-000120": R(has("policy-map system-cpp-policy", how="whole line"),
#|                        anysec("control-plane", rx_has(r"^\s*service-policy input \S+")), mode="ANY",
#|                        note="Catalyst 9300 uses the built-in system-cpp-policy; Catalyst 8300 uses a 'control-plane' "
#|                             "service-policy. Also review policer rates with 'show policy-map control-plane'."),
#|    "CISC-RT-000150": R(lacks("ip gratuitous-arps", how="whole line")),
#|    "CISC-RT-000160": R(every("interface", lacks("ip directed-broadcast", how="whole line"))),
#|    "CISC-RT-000170": R(every("interface", has("no ip unreachables", how="whole line"), **L3IF),
#|                        note="Applies to EXTERNAL interfaces only - narrow 'only' / 'skip' to your external "
#|                             "interfaces (or use 'ip icmp rate-limit unreachable' on the DODIN backbone)."),
#|    "CISC-RT-000180": R(every("interface", lacks("ip mask-reply", how="whole line"))),
#|    "CISC-RT-000190": R(every("interface", has("no ip redirects", how="whole line"), **L3IF),
#|                        note="Applies to EXTERNAL interfaces only - narrow to your external interfaces."),
#|    "CISC-RT-000200": R(every("ip access-list extended", rx_lacks(DENY_NO_LOG))),
#|    "CISC-RT-000210": R(every("ip access-list extended", rx_lacks(DENY_NO_LOGINPUT))),
#|    "CISC-RT-000220": R(every("ip access-list extended", rx_lacks(DENY_NO_LOGINPUT))),
#|    "CISC-RT-000230": R(anysec("line aux", has("no exec", how="whole line")), na=NA_AUX),
#|    "CISC-RT-000235": R(lacks("no ip cef", how="whole line"), lacks("no ipv6 cef", how="whole line"),
#|                        note="CEF is on by default and only shows when disabled."),
#|    "CISC-RT-000236": R(rx_lacks(r"^\s*ipv6 (nd )?hop-limit ([0-9]|[12][0-9]|3[01])\s*$"), na=NA_IPV6),
#|    "CISC-RT-000237": R(lacks("ipv6 address fec", how="contains", ignore_case=True), na=NA_IPV6),
#|    "CISC-RT-000360": R(lacks("lldp run", how="whole line"),
#|                        note="If LLDP is needed internally, change to: every EXTERNAL interface has 'no lldp transmit'."),
#|    "CISC-RT-000370": R(lacks("cdp run", how="whole line"), has("no cdp run", how="whole line"), mode="ANY",
#|                        note="If CDP is needed internally, change to: every EXTERNAL interface has 'no cdp enable'."),
#|    "CISC-RT-000380": R(every("interface", has("no ip proxy-arp", how="whole line"), **L3IF),
#|                        note="Proxy ARP is on by default. Applies to EXTERNAL interfaces - narrow as needed."),
#|    "CISC-RT-000470": R(anysec("router bgp", has("ttl-security hops", how="contains")), na=NA_BGP,
#|                        note="Every eBGP neighbor needs ttl-security; refine per neighbor."),
#|    "CISC-RT-000480": MANUAL(INTERVIEW),
#|    "CISC-RT-000490": R(rx_has(r"^ip prefix-list \S+ seq \d+ deny 10\.0\.0\.0/8"),
#|                        anysec("router bgp", rx_has(r"neighbor \S+ (prefix-list|route-map) \S+ in\s*$")), na=NA_BGP,
#|                        note="Confirm the full current Bogon list and that it is applied to ALL external peers."),
#|    "CISC-RT-000500": R(anysec("router bgp", rx_has(r"neighbor \S+ (prefix-list|route-map) \S+ in\s*$")), na=NA_BGP,
#|                        note="Reviewer must confirm the inbound filter denies the local AS prefixes."),
#|    "CISC-RT-000510": R(anysec("router bgp", rx_has(r"neighbor \S+ prefix-list \S+ in\s*$")), na=NA_BGP,
#|                        note="Only for CE peers; confirm each customer's list holds only its prefixes."),
#|    "CISC-RT-000520": R(anysec("router bgp", rx_has(r"neighbor \S+ prefix-list \S+ out\s*$")), na=NA_BGP),
#|    "CISC-RT-000530": R(anysec("router bgp", rx_has(r"neighbor \S+ prefix-list \S+ out\s*$")), na=NA_BGP),
#|    "CISC-RT-000540": R(lacks("no bgp enforce-first-as", how="contains"), na=NA_BGP),
#|    "CISC-RT-000550": R(has("ip as-path access-list"), anysec("router bgp", rx_has(r"neighbor \S+ filter-list \S+ in")),
#|                        na=NA_BGP),
#|    "CISC-RT-000560": R(anysec("router bgp", has("maximum-prefix", how="contains")), na=NA_BGP),
#|    "CISC-RT-000570": R(rx_has(r"^ip prefix-list \S+ .*le 24\b"),
#|                        anysec("router bgp", rx_has(r"neighbor \S+ prefix-list \S+ in\s*$")), na=NA_BGP),
#|    "CISC-RT-000580": R(anysec("router bgp", rx_has(r"neighbor \S+ update-source [Ll]oopback")), na=NA_BGP),
#|    "CISC-RT-000590": R(lacks("mpls ldp router-id"), rx_has(r"^mpls ldp router-id [Ll]oopback"), mode="ANY",
#|                        na=NA_IOS_MPLS),
#|    "CISC-RT-000600": R(anysec(r"^router (ospf|isis)\b", has("mpls ldp sync"), section_how="regex"), na=NA_IOS_MPLS),
#|    "CISC-RT-000610": R(has("ip rsvp signalling rate-limit"), na=NA_IOS_TE),
#|    "CISC-RT-000620": R(has("no mpls ip propagate-ttl"), na=NA_IOS_MPLS),
#|    "CISC-RT-000630": MANUAL(DESIGN),
#|    "CISC-RT-000640": MANUAL(DESIGN),
#|    "CISC-RT-000650": MANUAL(DESIGN),
#|    "CISC-RT-000660": MANUAL("Permanent finding per the STIG (no FIPS MAC for targeted LDP); CAT III if MD5 "
#|                             "'mpls ldp neighbor ... password' is configured - review and document."),
#|    "CISC-RT-000670": MANUAL(DESIGN),
#|    "CISC-RT-000680": MANUAL(DESIGN),
#|    "CISC-RT-000690": R(lacks("no-split-horizon", how="contains"), na=NA_IOS_VPLS),
#|    "CISC-RT-000700": R(every("interface", has("storm-control broadcast", how="contains"), only="re:^\\s*bridge-domain"),
#|                        na=NA_IOS_VPLS),
#|    "CISC-RT-000710": R(lacks("no ip igmp snooping", how="contains"), na=NA_IOS_VPLS),
#|    "CISC-RT-000720": R(every("bridge-domain", has("mac limit maximum addresses", how="contains")), na=NA_IOS_VPLS),
#|    "CISC-RT-000730": MANUAL("Needs the IP core address space to verify the CE-facing ACL blocks it."),
#|    "CISC-RT-000740": MANUAL("Needs the list of CE-facing interfaces ('ip verify unicast source reachable-via any')."),
#|    "CISC-RT-000750": R(rx_has(r"^ip options (drop|ignore)\b"), na=NA_IOS_MPLS),
#|    "CISC-RT-000760": R(has("policy-map"), rx_has(r"^\s*service-policy output \S+"), na=NA_IOS_MPLS,
#|                        note="Confirm the classes / bandwidth match the GIG QoS technical profile."),
#|    "CISC-RT-000770": R(has("policy-map"), rx_has(r"^\s*service-policy output \S+"), na=NA_IOS_MPLS,
#|                        note="Confirm the classes / bandwidth match the GIG QoS technical profile."),
#|    "CISC-RT-000780": R(rx_has(r"match (ip )?dscp (cs1|8)\b"), rx_has(r"^\s*service-policy (output|input) \S+"),
#|                        note="Scavenger (CS1) class with low priority in the QoS policy."),
#|    "CISC-RT-000790": MANUAL("Compare PIM-enabled interfaces with the multicast topology diagram."),
#|    "CISC-RT-000800": R(every("interface", has("ip pim neighbor-filter"), only="re:^\\s*ip pim (sparse|dense)"),
#|                        na=NA_IOS_PIM),
#|    "CISC-RT-000810": R(anysec("interface", has("ip multicast boundary")), na=NA_IOS_PIM,
#|                        note="Edge multicast routers only."),
#|    "CISC-RT-000820": R(has("ip pim accept-register"), has("ip pim register-rate-limit"), na=NA_IOS_PIM,
#|                        note="Rendezvous Point routers only; also verify MSDP peer filtering."),
#|    "CISC-RT-000830": R(has("ip pim accept-register"), na=NA_IOS_PIM, note="Rendezvous Point routers only."),
#|    "CISC-RT-000840": R(has("ip pim accept-rp"), na=NA_IOS_PIM, note="Rendezvous Point routers only."),
#|    "CISC-RT-000850": R(has("ip pim register-rate-limit"), na=NA_IOS_PIM, note="Rendezvous Point routers only."),
#|    "CISC-RT-000860": R(every("interface", has("ip igmp access-group"), only="re:^\\s*ip pim (sparse|dense)"),
#|                        na=NA_IOS_PIM, note="Source Specific Multicast only; N/A for Any Source Multicast."),
#|    "CISC-RT-000870": R(every("interface", has("ip igmp access-group"), only="re:^\\s*ip pim (sparse|dense)"),
#|                        na=NA_IOS_PIM, note="Source Specific Multicast only."),
#|    "CISC-RT-000880": R(has("ip igmp limit"), anysec("interface", has("ip igmp limit")), mode="ANY", na=NA_IOS_PIM),
#|    "CISC-RT-000890": R(has("ip pim spt-threshold infinity"), na=NA_IOS_PIM),
#|    "CISC-RT-000900": MANUAL("Review the MSDP-peering interface ACLs (TCP 639) for known peers only."),
#|    "CISC-RT-000910": R(has("ip msdp password peer"), na=NA_MSDP),
#|    "CISC-RT-000920": R(rx_has(r"^ip msdp sa-filter in "), na=NA_MSDP),
#|    "CISC-RT-000930": R(rx_has(r"^ip msdp sa-filter out "), na=NA_MSDP),
#|    "CISC-RT-000940": R(has("ip msdp sa-limit"), na=NA_MSDP),
#|    "CISC-RT-000950": R(rx_has(r"^ip msdp peer \S+ connect-source [Ll]oopback"), na=NA_MSDP),
#|    **{f"CISC-RT-000{n}": MANUAL(PERIMETER) for n in (
#|        "240", "250", "260", "270", "280", "290", "300", "310", "320", "330", "340", "350", "390", "391", "392",
#|        "393", "394", "395", "396", "397", "398", "400", "410", "420", "430", "440", "450", "460")},
#|    # ---- L2S (Catalyst 9300)
#|    "CISC-L2-000020": R(every("interface", rx_has(r"^\s*(authentication port-control auto|access-session port-control "
#|                                                    r"auto|dot1x pae authenticator|mab)\b"), **ROLE_ACCESS),
#|                        has("dot1x system-auth-control", how="whole line"),
#|                        note=ROLE_NOTE + "Every access port needs 802.1x / MAB (legacy 'authentication port-control' "
#|                             "or IBNS 2.0 'access-session'). Ports in telecom rooms / wiring closets are exempt - "
#|                             "label them differently."),
#|    "CISC-L2-000030": R(rx_has(r"VTP Operating Mode\s*:\s*Off", cmd="show vtp status"),
#|                        rx_has(r"VTP Password:\s*\S+", cmd="show vtp password"), mode="ANY",
#|                        cmds=["show vtp status", "show vtp password"],
#|                        note="Catalyst 9300 defaults to VTP Server mode, so a password is required unless VTP is off."),
#|    "CISC-L2-000040": R(has("policy-map"), rx_has(r"^\s*service-policy (output|input) \S+"),
#|                        note="Confirm the classes / bandwidth match the QoS policy."),
#|    "CISC-L2-000090": R(every("interface", has("spanning-tree guard root"), **ROLE_DOWNLINK),
#|                        note=ROLE_NOTE + "Root Guard on every DOWNLINK (ports facing access-layer switches). "
#|                             "Access switches with no downlinks pass."),
#|    "CISC-L2-000100": R(rx_has(r"^spanning-tree portfast (edge )?bpduguard default"),
#|                        every("interface", has("spanning-tree bpduguard enable"), **ROLE_ACCESS), mode="ANY",
#|                        note=ROLE_NOTE + "Global portfast bpduguard default, or BPDU Guard on every access port."),
#|    "CISC-L2-000110": R(has("spanning-tree loopguard default")),
#|    "CISC-L2-000120": R(every("interface", has("switchport block unicast"), **ROLE_ACCESS), note=ROLE_NOTE),
#|    "CISC-L2-000130": R(has("ip dhcp snooping", how="whole line"), rx_has(r"^ip dhcp snooping vlan \S+"),
#|                        every("interface", has("ip dhcp snooping trust", how="whole line"), **ROLE_UPLINK),
#|                        every("interface", lacks("ip dhcp snooping trust", how="whole line"), **NOT_UPLINK),
#|                        note=ROLE_NOTE + "Snooping on all user VLANs; 'ip dhcp snooping trust' on every UPLINK and on "
#|                             "nothing else (trust on a client port lets a rogue DHCP server through)."),
#|    "CISC-L2-000140": R(every("interface", has("ip verify source"), **ROLE_ACCESS),
#|                        note=ROLE_NOTE + "802.1x / MAB ports may be exempt - adjust if so."),
#|    "CISC-L2-000150": R(rx_has(r"^ip arp inspection vlan \S+"),
#|                        every("interface", has("ip arp inspection trust", how="whole line"), **ROLE_UPLINK),
#|                        every("interface", lacks("ip arp inspection trust", how="whole line"), **NOT_UPLINK),
#|                        note=ROLE_NOTE + "DAI on all user VLANs; 'ip arp inspection trust' on every UPLINK and on "
#|                             "nothing else."),
#|    "CISC-L2-000160": R(every("interface", has("storm-control broadcast"), **ROLE_ACCESS), note=ROLE_NOTE),
#|    "CISC-L2-000170": R(lacks("no ip igmp snooping", how="contains")),
#|    "CISC-L2-000180": R(rx_has(r"^spanning-tree mode (rapid-pvst|mst)\b")),
#|    "CISC-L2-000190": R(rx_has(r"^udld (enable|aggressive)\b"), anysec("interface", has("udld port")), mode="ANY",
#|                        note="Only required where there are fiber links to neighbors."),
#|    "CISC-L2-000200": R(rx_lacks(r"Negotiation of Trunking:\s*On", cmd="show interfaces switchport"),
#|                        cmds=["show interfaces switchport"],
#|                        note="Catalyst 9300 ports default to 'dynamic auto' (not shown in the config), so this reads "
#|                             "'show interfaces switchport'. AppGigabitEthernet ports may need excluding."),
#|    "CISC-L2-000210": R(every(IOS_PORT, rx_has(r"^\s*switchport access vlan \d+"),
#|                              only="re:^\\s*shutdown\\s*$", exclude="re:^\\s*(no switchport|vrf forwarding)\\b",
#|                              section_how="regex"),
#|                        note="EDIT to your parking VLAN, e.g. text 'switchport access vlan 999' (whole line). Also "
#|                             "confirm that VLAN is pruned from every trunk."),
#|    "CISC-L2-000220": R(rx_lacks(r"^1\s+default\s+active\s+\S+", cmd="show vlan brief"), cmds=["show vlan brief"],
#|                        note="Fails if any port is listed under VLAN 1."),
#|    "CISC-L2-000230": R(every(IOS_PORT, has("switchport trunk allowed vlan"), section_how="regex", **TRUNK),
#|                        every(IOS_PORT, rx_lacks(VLAN1_IN_LIST), section_how="regex", **TRUNK)),
#|    "CISC-L2-000240": R(every("interface Vlan1", rx_lacks(r"^\s*ip address \d"), section_how="whole line")),
#|    "CISC-L2-000250": R(every("interface", has("switchport mode access", how="whole line"), **ROLE_ACCESS),
#|                        every(IOS_PORT, has("role:any"), section_how="regex", exclude=LIVE_IOS_PORT),
#|                        note=ROLE_NOTE + "Condition 1: every access-role port is a static access port. Condition 2: "
#|                             "every live front-panel port carries a role label, so no port escapes the role-based "
#|                             "checks."),
#|    "CISC-L2-000260": R(every(IOS_PORT, rx_has(r"^\s*switchport trunk native vlan ([2-9]|\d{2,})\s*$"),
#|                              section_how="regex", **TRUNK),
#|                        note="Alternative: 'vlan dot1q tag native' globally - add as an ANY option if used."),
#|    "CISC-L2-000270": MANUAL("Needs the native VLAN ID per trunk to compare with access-port VLANs."),
#|}
#|
#|# Router (Catalyst 8300) differences
#|IOSXE_RTR = {
#|    "CISC-RT-000370": R(lacks("cdp run", how="whole line"), has("no cdp run", how="whole line"), mode="ANY",
#|                        note="CDP is off by default on IOS-XE routers ('cdp run' appears only when enabled)."),
#|}
#|# Switch (Catalyst 9300) differences
#|IOSXE_SW = {
#|    "CISC-RT-000370": R(has("no cdp run", how="whole line"),
#|                        note="CDP is ON by default on Catalyst 9300 and only 'no cdp run' shows when disabled. If CDP "
#|                             "is needed internally, change to: every EXTERNAL interface has 'no cdp enable'."),
#|}
#|
#|
#|# ---------------------------------------------------------------- NX-OS (Nexus 9336C-FX2 / 93180YC-FX3)
#|
#|NX_ACCT = R(rx_has(r"^aaa accounting default group \S+"),
#|            note="Also confirm the referenced group has reachable AAA servers.")
#|
#|NXOS = {
#|    "CISC-ND-000010": R(anysec(VTY, has("session-limit"))),
#|    "CISC-ND-000090": NX_ACCT, "CISC-ND-000100": NX_ACCT, "CISC-ND-000110": NX_ACCT, "CISC-ND-000120": NX_ACCT,
#|    "CISC-ND-000210": NX_ACCT, "CISC-ND-000330": NX_ACCT, "CISC-ND-000880": NX_ACCT, "CISC-ND-000940": NX_ACCT,
#|    "CISC-ND-001240": NX_ACCT, "CISC-ND-001250": NX_ACCT, "CISC-ND-001270": NX_ACCT,
#|    "CISC-ND-000140": R(anysec(VTY, rx_has(r"^\s*access-class \S+ in")),
#|                        anysec("interface mgmt0", rx_has(r"^\s*ip access-group \S+ in")), mode="ANY",
#|                        note="Also confirm the ACL only permits the management network."),
#|    "CISC-ND-000150": R(rx_lacks(r"^ssh login-attempts ([4-9]|\d{2,})\b"),
#|                        note="Default is 3 attempts (not shown in the config)."),
#|    "CISC-ND-000160": R(has("banner motd"),
#|                        has("You are accessing a U.S. Government (USG) Information System", how="contains")),
#|    "CISC-ND-000290": R(every("ip access-list", rx_lacks(DENY_NO_LOG)), has("logging ip access-list cache entries")),
#|    "CISC-ND-000470": R(lacks("feature telnet", how="whole line"),
#|                        note="Also review: feature wccp, nxapi, imp, dhcp - allowed only when operationally required "
#|                             "(feature dhcp is needed for DHCP snooping)."),
#|    "CISC-ND-000490": R(count("username ", "==", 1), lacks("no aaa authentication login default fallback error local")),
#|    "CISC-ND-000530": R(rx_has(r"^ssh macs .*hmac-sha2"), rx_lacks(r"^ssh macs .*hmac-sha1\b"),
#|                        note="'ssh macs' is available on NX-OS 10.x; on 9.3 confirm with 'show ssh server'."),
#|    "CISC-ND-000570": R(lacks("no password strength-check", how="whole line")),
#|    "CISC-ND-000580": R(lacks("no password strength-check", how="whole line")),
#|    "CISC-ND-000590": R(lacks("no password strength-check", how="whole line")),
#|    "CISC-ND-000600": R(lacks("no password strength-check", how="whole line")),
#|    "CISC-ND-000720": R(anysec("line console", num("exec-timeout", "<=", 5)), anysec(VTY, num("exec-timeout", "<=", 5)),
#|                        rx_lacks(r"^\s*exec-timeout 0\s*$")),
#|    "CISC-ND-000980": R(rx_has(r"^logging logfile \S+ \d+ size \d+")),
#|    "CISC-ND-001000": R(has("logging server"), rx_lacks(r"^logging server \S+ [01](\s|$)")),
#|    "CISC-ND-001030": R(count("ntp server", ">=", 2)),
#|    "CISC-ND-001050": MANUAL("UTC is the default and is not shown in the configuration; confirm with 'show clock'."),
#|    "CISC-ND-001130": R(rx_has(r"^snmp-server user \S+ .*\bauth (sha|sha-\d+)\b"),
#|                        rx_lacks(r"^snmp-server user \S+ .*\bauth md5\b"), lacks("snmp-server community"), na=NA_SNMP,
#|                        note="Nexus ships with an 'admin' SNMP user using auth md5 - remove or change it."),
#|    "CISC-ND-001140": R(rx_has(r"^snmp-server user \S+ .*\bpriv (aes-128|aes)\b"),
#|                        rx_lacks(r"^snmp-server user \S+ (?!.*\bpriv\b)"), na=NA_SNMP),
#|    "CISC-ND-001150": MANUAL("Permanent finding per the STIG: NX-OS only supports MD5 for NTP authentication. "
#|                             "Confirm MD5 authentication is configured as the mitigation and document it."),
#|    "CISC-ND-001200": R(rx_has(r"^ssh macs .*hmac-sha2"), rx_lacks(r"^ssh macs .*hmac-sha1\b"),
#|                        note="'ssh macs' is available on NX-OS 10.x; on 9.3 confirm with 'show ssh server'."),
#|    "CISC-ND-001210": R(rx_has(r"^ssh ciphers "), rx_lacks(r"^ssh ciphers .*(cbc|3des)"),
#|                        note="'ssh ciphers' is available on NX-OS 10.x; on 9.3 confirm with 'show ssh server'."),
#|    "CISC-ND-001220": R(rx_has(r"^policy-map type control-plane "),
#|                        anysec("control-plane", rx_has(r"^\s*service-policy input \S+")),
#|                        note="Nexus 9000 applies a default CoPP profile (copp-system-p-policy-*); review the rates."),
#|    "CISC-ND-001260": R(num("logging level authpri", ">=", 6), has("logging logfile")),
#|    "CISC-ND-001280": R(num("logging level authpri", ">=", 6)),
#|    "CISC-ND-001310": R(has("logging server")),
#|    "CISC-ND-001370": R(count(r"^(radius|tacacs)-server host ", ">=", 2, how="regex"),
#|                        rx_has(r"^aaa authentication login (default|console) group ")),
#|    "CISC-ND-001410": R(anysec("event manager applet", has("CONFIG_I", how="contains")),
#|                        anysec("event manager applet", rx_has(r"copy (running|startup)-config (scp|sftp)://"))),
#|    "CISC-ND-001440": R(anysec("crypto ca trustpoint", has("enrollment")), na=[lacks("crypto ca trustpoint")],
#|                        note="Reviewer must confirm the CA is DoD / DoD-approved ('show crypto ca certificates')."),
#|    "CISC-ND-001450": R(count("logging server", ">=", 2)),
#|    "CISC-ND-001470": R(rx_has(r"NXOS: version (9\.3\(1[0-9]\)|10\.[2-5]\()", cmd="show version"), cmds=["show version"],
#|                        note="EDIT the version list to the Cisco-supported / site-approved releases before use."),
#|    # ---- L2S
#|    "CISC-L2-000020": R(every(NX_PORT, rx_has(r"^\s*dot1x (port-control auto|mac-auth-bypass)"), section_how="regex",
#|                              **ROLE_ACCESS),
#|                        has("feature dot1x", how="whole line"),
#|                        note=ROLE_NOTE + "Data-center leaf ports rarely face users; mark N/A per group if no LAN "
#|                             "outlets connect."),
#|    "CISC-L2-000080": R(every(NX_PORT, rx_has(r"^\s*dot1x (port-control auto|mac-auth-bypass)"), section_how="regex",
#|                              **ROLE_ACCESS),
#|                        has("feature dot1x", how="whole line"),
#|                        note=ROLE_NOTE + "Data-center leaf ports rarely face users; mark N/A per group if no LAN "
#|                             "outlets connect."),
#|    "CISC-L2-000030": R(lacks("feature vtp", how="whole line"), rx_has(r"^vtp mode (transparent|off)\b"),
#|                        has("vtp password"), mode="ANY"),
#|    "CISC-L2-000060": R(rx_has(r"^monitor session \d+"),
#|                        note="The STIG asks for the CAPABILITY to capture a session; a reviewer may accept NaF "
#|                             "without a configured session."),
#|    "CISC-L2-000070": R(rx_has(r"^monitor session \d+"),
#|                        note="The STIG asks for the CAPABILITY to capture a session; a reviewer may accept NaF "
#|                             "without a configured session."),
#|    "CISC-L2-000090": R(every("interface", has("spanning-tree guard root"), **ROLE_DOWNLINK),
#|                        note=ROLE_NOTE + "Root Guard on every DOWNLINK (ports facing access-layer switches / hosts)."),
#|    "CISC-L2-000100": R(has("spanning-tree port type edge bpduguard default"),
#|                        every(NX_PORT, has("spanning-tree bpduguard enable"), section_how="regex", **ROLE_ACCESS),
#|                        mode="ANY", note=ROLE_NOTE),
#|    "CISC-L2-000110": R(has("spanning-tree loopguard default")),
#|    "CISC-L2-000120": R(every(NX_PORT, has("switchport block unicast"), section_how="regex", **ROLE_ACCESS),
#|                        note=ROLE_NOTE),
#|    "CISC-L2-000130": R(has("ip dhcp snooping", how="whole line"), rx_has(r"^ip dhcp snooping vlan \S+"),
#|                        every("interface", has("ip dhcp snooping trust", how="whole line"), **ROLE_UPLINK),
#|                        every("interface", lacks("ip dhcp snooping trust", how="whole line"), **NOT_UPLINK),
#|                        note=ROLE_NOTE + "'ip dhcp snooping trust' on every UPLINK and on nothing else."),
#|    "CISC-L2-000140": R(every(NX_PORT, has("ip verify source dhcp-snooping-vlan"), section_how="regex",
#|                              **ROLE_ACCESS),
#|                        note=ROLE_NOTE + "802.1x / MAB ports are exempt."),
#|    "CISC-L2-000150": R(rx_has(r"^ip arp inspection vlan \S+"),
#|                        every("interface", has("ip arp inspection trust", how="whole line"), **ROLE_UPLINK),
#|                        every("interface", lacks("ip arp inspection trust", how="whole line"), **NOT_UPLINK),
#|                        note=ROLE_NOTE + "'ip arp inspection trust' on every UPLINK and on nothing else."),
#|    "CISC-L2-000160": R(every(NX_PORT, has("storm-control broadcast"), section_how="regex", **ROLE_ACCESS),
#|                        note=ROLE_NOTE),
#|    "CISC-L2-000170": R(lacks("no ip igmp snooping", how="contains")),
#|    "CISC-L2-000190": R(has("feature udld", how="whole line"), every("interface", rx_lacks(r"^\s*udld disable"))),
#|    "CISC-L2-000210": R(every("interface", rx_has(r"^\s*switchport access vlan \d+"),
#|                              only="re:^\\s*shutdown\\s*$", exclude="no switchport"),
#|                        note="EDIT to your parking VLAN, e.g. 'switchport access vlan 999' (whole line)."),
#|    "CISC-L2-000220": R(every(NX_PORT, rx_has(r"^\s*switchport access vlan ([2-9]|\d{2,})\s*$"), section_how="regex",
#|                              **ROLE_ACCESS),
#|                        note=ROLE_NOTE + "Every access port names a VLAN other than 1 (NX-OS 'show vlan' also lists "
#|                             "trunks, so the config is read instead)."),
#|    "CISC-L2-000230": R(every("interface", has("switchport trunk allowed vlan"), **TRUNK),
#|                        every("interface", rx_lacks(VLAN1_IN_LIST), **TRUNK)),
#|    "CISC-L2-000240": R(every("interface Vlan1", rx_lacks(r"^\s*ip address \d"), section_how="whole line")),
#|    "CISC-L2-000250": R(every(NX_PORT, lacks("switchport mode trunk", how="whole line"), section_how="regex",
#|                              **ROLE_ACCESS),
#|                        every(NX_PORT, has("role:any"), section_how="regex", only="re:^\\s*no shutdown\\s*$",
#|                              exclude="re:^\\s*(no switchport|channel-group)\\b"),
#|                        note=ROLE_NOTE + "Condition 1: no access-role port is a trunk. Condition 2: every live Ethernet "
#|                             "port carries a role label."),
#|    "CISC-L2-000260": R(every("interface", rx_has(r"^\s*switchport trunk native vlan ([2-9]|\d{2,})\s*$"), **TRUNK)),
#|    "CISC-L2-000270": MANUAL("Needs the native VLAN ID per trunk to compare with access-port VLANs."),
#|    # ---- RTR
#|    "CISC-RT-000010": MANUAL("Organization-defined information-flow policy: review the ACL design for each group."),
#|    "CISC-RT-000020": R(every("interface", rx_has(r"^\s*ip ospf authentication"), only="ip router ospf"),
#|                        every("interface", rx_has(r"^\s*ip authentication (mode|key-chain) eigrp"), only="ip router eigrp"),
#|                        every("interface", rx_has(r"^\s*isis authentication"), only="ip router isis"),
#|                        every(r"^\s+neighbor \S+", rx_has(r"^\s*password \d"), section_how="regex",
#|                              exclude="re:^\\s*inherit peer"),
#|                        na=NA_NX_ROUTING,
#|                        note="BGP: every neighbor needs 'password'; templates ('inherit peer') need checking by hand."),
#|    "CISC-RT-000030": R(every(r"^\s+key \d+", has("accept-lifetime"), section_how="regex"),
#|                        every(r"^\s+key \d+", has("send-lifetime"), section_how="regex"), na=NA_NX_ROUTING,
#|                        note="Reviewer must confirm each key's lifetime is 180 days or less."),
#|    "CISC-RT-000040": R(every("interface", rx_has(r"^\s*ip ospf (message-digest-key|authentication key-chain|"
#|                                                  r"authentication message-digest)"), only="ip router ospf"),
#|                        na=NA_NX_ROUTING, note="Check BGP / EIGRP / IS-IS authentication types as well."),
#|    "CISC-RT-000050": R(anysec("key chain", has("cryptographic-algorithm hmac-sha", how="contains")), na=NA_NX_OSPF,
#|                        note="Only OSPF supports FIPS 198-1 HMAC on NX-OS; BGP/RIP/EIGRP/IS-IS are a finding."),
#|    "CISC-RT-000060": R(rx_lacks(r"link-down/admin-up", cmd="show ip interface brief vrf all"),
#|                        cmds=["show ip interface brief vrf all"],
#|                        note="Flags routed interfaces that are admin-up but link-down."),
#|    "CISC-RT-000080": R(every("callhome", lacks("enable", how="whole line"))),
#|    "CISC-RT-000120": R(rx_has(r"^policy-map type control-plane "),
#|                        anysec("control-plane", rx_has(r"^\s*service-policy input \S+")),
#|                        note="Nexus 9000 applies a default CoPP profile (copp-system-p-policy-*); review the rates."),
#|    "CISC-RT-000140": R(anysec("ip access-list", rx_has(r"deny icmp .*\bfragments\b")),
#|                        note="Must be on external and internal ACLs, before any ICMP permit."),
#|    "CISC-RT-000150": R(every("interface", has("no ip arp gratuitous", how="contains"), **NX_L3IF),
#|                        note="Applies to EXTERNAL interfaces only - narrow as needed."),
#|    "CISC-RT-000160": R(every("interface", lacks("ip directed-broadcast", how="whole line"))),
#|    "CISC-RT-000170": R(every("interface", lacks("ip unreachables", how="whole line"))),
#|    "CISC-RT-000190": R(every("interface", has("no ip redirects", how="whole line"), **NX_L3IF),
#|                        note="Applies to EXTERNAL interfaces only - narrow as needed."),
#|    "CISC-RT-000200": R(every("ip access-list", rx_lacks(DENY_NO_LOG))),
#|    "CISC-RT-000236": R(rx_lacks(r"^\s*ipv6 nd hop-limit ([0-9]|[12][0-9]|3[01])\s*$"), na=NA_IPV6),
#|    "CISC-RT-000237": R(lacks("ipv6 address fec", how="contains", ignore_case=True), na=NA_IPV6),
#|    "CISC-RT-000350": R(has("no ip source-route", how="whole line")),
#|    "CISC-RT-000360": R(lacks("feature lldp", how="whole line"),
#|                        note="If LLDP is needed internally, change to: every EXTERNAL interface has 'no lldp transmit'."),
#|    "CISC-RT-000370": R(rx_has(r"^no cdp enable\s*$"),
#|                        note="CDP is on by default. If needed internally, change to: every EXTERNAL interface has "
#|                             "'no cdp enable'."),
#|    "CISC-RT-000380": R(every("interface", lacks("ip proxy-arp", how="whole line"))),
#|    "CISC-RT-000470": R(lacks("disable-connected-check", how="contains"), na=NA_NX_BGP),
#|    "CISC-RT-000480": MANUAL(INTERVIEW),
#|    "CISC-RT-000490": R(rx_has(r"^ip prefix-list \S+ seq \d+ deny 10\.0\.0\.0/8"),
#|                        rx_has(r"^\s+(prefix-list|route-map) \S+ in\s*$"), na=NA_NX_BGP,
#|                        note="Confirm the full Bogon list and that it is applied to ALL external peers."),
#|    "CISC-RT-000500": R(rx_has(r"^\s+(prefix-list|route-map) \S+ in\s*$"), na=NA_NX_BGP,
#|                        note="Reviewer must confirm the inbound filter denies the local AS prefixes."),
#|    "CISC-RT-000510": R(rx_has(r"^\s+prefix-list \S+ in\s*$"), na=NA_NX_BGP),
#|    "CISC-RT-000520": R(rx_has(r"^\s+prefix-list \S+ out\s*$"), na=NA_NX_BGP),
#|    "CISC-RT-000530": R(rx_has(r"^\s+prefix-list \S+ out\s*$"), na=NA_NX_BGP),
#|    "CISC-RT-000540": R(lacks("no enforce-first-as", how="contains"), na=NA_NX_BGP),
#|    "CISC-RT-000550": R(has("ip as-path access-list"), rx_has(r"^\s+filter-list \S+ in\s*$"), na=NA_NX_BGP),
#|    "CISC-RT-000560": R(rx_has(r"^\s+maximum-prefix \d+"), na=NA_NX_BGP),
#|    "CISC-RT-000570": R(rx_has(r"^ip prefix-list \S+ .*le 24\b"), rx_has(r"^\s+prefix-list \S+ in\s*$"), na=NA_NX_BGP),
#|    "CISC-RT-000580": R(rx_has(r"^\s+update-source [Ll]oopback"), na=NA_NX_BGP),
#|    "CISC-RT-000590": R(every("mpls ldp configuration", rx_lacks(r"^\s+router-id ")),
#|                        every("mpls ldp configuration", rx_has(r"^\s+router-id [Ll]oopback")), mode="ANY", na=NA_NX_MPLS),
#|    "CISC-RT-000600": R(anysec(r"^router (ospf|isis)\b", has("mpls ldp sync"), section_how="regex"), na=NA_NX_MPLS),
#|    "CISC-RT-000610": MANUAL("Check RSVP message pacing on TE-enabled Nexus devices (N/A without 'mpls traffic-eng')."),
#|    "CISC-RT-000620": R(has("no mpls ip propagate-ttl"), na=NA_NX_MPLS),
#|    "CISC-RT-000710": R(lacks("no ip igmp snooping", how="contains"), na=NA_NX_MPLS),
#|    "CISC-RT-000750": R(has("no ip source-route", how="whole line"), na=NA_NX_MPLS),
#|    "CISC-RT-000760": R(rx_has(r"^\s*service-policy type qos (output|input) \S+"), na=NA_NX_MPLS,
#|                        note="Confirm the classes / bandwidth match the GIG QoS technical profile."),
#|    "CISC-RT-000770": R(rx_has(r"^\s*service-policy type qos (output|input) \S+"), na=NA_NX_MPLS,
#|                        note="Confirm the classes / bandwidth match the GIG QoS technical profile."),
#|    "CISC-RT-000780": R(rx_has(r"match (ip )?dscp (cs1|8)\b"), rx_has(r"^\s*service-policy type qos (output|input) \S+"),
#|                        note="Scavenger (CS1) class with low priority in the QoS policy."),
#|    "CISC-RT-000790": MANUAL("Compare PIM-enabled interfaces with the multicast topology diagram."),
#|    "CISC-RT-000800": R(every("interface", has("ip pim neighbor-policy"), only="ip pim sparse-mode"), na=NA_NX_PIM),
#|    "CISC-RT-000810": R(anysec("interface", has("ip pim border")), na=NA_NX_PIM, note="Edge multicast switches only."),
#|    "CISC-RT-000820": R(has("ip pim register-policy"), na=NA_NX_PIM,
#|                        note="Rendezvous Point only; also verify MSDP peer filtering."),
#|    "CISC-RT-000830": R(has("ip pim register-policy"), na=NA_NX_PIM, note="Rendezvous Point only."),
#|    "CISC-RT-000840": R(every("interface", has("ip pim jp-policy"), only="ip pim sparse-mode"), na=NA_NX_PIM,
#|                        note="Rendezvous Point only."),
#|    "CISC-RT-000860": R(every("interface", has("ip igmp report-policy"), only="ip pim sparse-mode"), na=NA_NX_PIM,
#|                        note="Source Specific Multicast only."),
#|    "CISC-RT-000870": R(every("interface", has("ip igmp report-policy"), only="ip pim sparse-mode"), na=NA_NX_PIM,
#|                        note="Source Specific Multicast only."),
#|    "CISC-RT-000880": R(every("interface", has("ip igmp state-limit"), only="ip pim sparse-mode"), na=NA_NX_PIM),
#|    "CISC-RT-000890": R(has("ip pim spt-threshold infinity"), na=NA_NX_PIM),
#|    "CISC-RT-000900": MANUAL("Review the MSDP-peering interface ACLs (TCP 639) for known peers only."),
#|    "CISC-RT-000910": R(rx_has(r"^ip msdp password "), na=NA_NX_MSDP),
#|    "CISC-RT-000920": R(rx_has(r"^ip msdp sa-policy \S+ .*\bin\s*$"), na=NA_NX_MSDP),
#|    "CISC-RT-000930": R(rx_has(r"^ip msdp sa-policy \S+ .*\bout\s*$"), na=NA_NX_MSDP),
#|    "CISC-RT-000940": R(has("ip msdp sa-limit"), na=NA_NX_MSDP),
#|    "CISC-RT-000950": R(rx_has(r"^ip msdp peer \S+ connect-source [Ll]oopback"), na=NA_NX_MSDP),
#|    **{f"CISC-RT-000{n}": MANUAL(DESIGN) for n in ("630", "640", "650", "660", "670", "680", "700", "720")},
#|    "CISC-RT-000730": MANUAL("Needs the IP core address space to verify the CE-facing ACL blocks it."),
#|    "CISC-RT-000740": MANUAL("Needs the list of CE-facing interfaces ('ip verify unicast source reachable-via any')."),
#|    **{f"CISC-RT-000{n}": MANUAL(PERIMETER) for n in (
#|        "240", "250", "260", "270", "310", "320", "330", "340", "390", "391", "450")},
#|}
#|
#|LIBRARY = {"IOSXE_SW": {**IOSXE, **IOSXE_SW}, "IOSXE_RTR": {**IOSXE, **IOSXE_RTR}, "NXOS": NXOS}
#|
#|
#|# ---------------------------------------------------------------- building rules
#|
#|def platform_of(stig_id):
#|    s = stig_id.upper().replace("-", "_")
#|    if "NX_OS" in s or "NXOS" in s:
#|        return "NXOS"
#|    if "IOS_XE" in s:
#|        return "IOSXE_RTR" if "ROUTER" in s else "IOSXE_SW"
#|    return None
#|
#|
#|def spec_for(stig_id, rule_ver):
#|    platform = platform_of(stig_id)
#|    return platform, (LIBRARY.get(platform) or {}).get(rule_ver)
#|
#|
#|def build_rule(spec, platform, stig_id, control):
#|    conds, na = spec["conds"], spec["na"]
#|    commands = spec["cmds"] or list(dict.fromkeys(cd["command"] for cd in conds + na))
#|    for cd in na:
#|        if cd["command"] not in commands:
#|            commands.append(cd["command"])
#|    note = STARTER_NOTE.format(platform=PLATFORM_LABEL[platform]) + (f"\n\n{spec['note']}" if spec["note"] else "")
#|    return {
#|        "id": store.new_rule_id(), "stig_id": stig_id, "vuln_id": control["vuln_id"], "name": "Starter draft",
#|        "state": "draft", "is_default": True, "version": 1, "commands": commands,
#|        "pass_logic": {"mode": spec["mode"], "conditions": [dict(cd) for cd in conds]},
#|        "na_enabled": bool(na), "na_logic": {"mode": "ALL", "conditions": [dict(cd) for cd in na]},
#|        "comment": "", "notes": note, "tests": [], "outcome_text": {}, "expected_open": False,
#|        "check_hash": control["check_hash"], "created_at": store.now(), "created_by": store.current_user(),
#|        "origin": "starter-drafts", "history": [], "fix": harden.starter_fix(platform, control["rule_ver"]),
#|    }
#|
#|
#|def problems_in_library():
#|    """Every condition in the library that would not run (bad regex etc.) - used by the tests."""
#|    out = []
#|    for platform, lib in LIBRARY.items():
#|        for ver, spec in lib.items():
#|            if "manual" in spec:
#|                continue
#|            commands = spec["cmds"] or [cd["command"] for cd in spec["conds"] + spec["na"]]
#|            for cd in spec["conds"] + spec["na"]:
#|                for err in engine.condition_problems(cd, commands):
#|                    out.append(f"{platform}:{ver}: {err}")
#|    return out
#|
#|
#|REFRESH_KEYS = ("commands", "pass_logic", "na_enabled", "na_logic", "notes", "fix")
#|
#|
#|def untouched(rule):
#|    """A starter draft nobody has edited or tested yet - safe to replace with a newer starter version."""
#|    return (rule.get("origin") == "starter-drafts" and rule.get("state") == "draft" and rule.get("version", 1) == 1
#|            and not rule.get("history") and not rule.get("tests"))
#|
#|
#|def create_drafts(index, rules_db, stig_ids=None):
#|    """Create starter drafts for every control that has no rule yet. Returns a report dict."""
#|    report = {"created": [], "manual": [], "no_entry": [], "skipped": 0, "fixes_added": 0, "refreshed": 0}
#|    for stig_id, stig in index.items():
#|        if stig_ids and stig_id not in stig_ids:
#|            continue
#|        for vuln_id in stig["order"]:
#|            control = stig["controls"][vuln_id]
#|            existing = assess.rules_for_control(rules_db, stig_id, vuln_id, include_retired=True)
#|            if existing:
#|                report["skipped"] += 1
#|                # starter drafts made before fix commands existed get them now (never overwrites edits)
#|                platform, spec = spec_for(stig_id, control["rule_ver"])
#|                fix = harden.starter_fix(platform, control["rule_ver"])
#|                for r in existing:
#|                    if r.get("origin") != "starter-drafts":
#|                        continue
#|                    if untouched(r) and spec and "manual" not in spec:
#|                        fresh = build_rule(spec, platform, stig_id, control)
#|                        if any(fresh[k] != r.get(k) for k in REFRESH_KEYS):
#|                            store.modify_rule(r["id"], lambda x, f=fresh: x.update({k: f[k] for k in REFRESH_KEYS}))
#|                            report["refreshed"] += 1
#|                    elif not harden.has_fix(r) and harden.has_fix({"fix": fix}):
#|                        store.modify_rule(r["id"], lambda x, f=fix: x.__setitem__("fix", f))
#|                        report["fixes_added"] += 1
#|                continue
#|            platform, spec = spec_for(stig_id, control["rule_ver"])
#|            row = (stig["short"], vuln_id, control["rule_ver"], control["title"])
#|            if spec is None:
#|                report["no_entry"].append(row + ("No starter entry for this platform / rule version.",))
#|            elif "manual" in spec:
#|                report["manual"].append(row + (spec["manual"],))
#|            else:
#|                store.save_rule(build_rule(spec, platform, stig_id, control), check=False)
#|                report["created"].append(row)
#|    return report
#|
#|
#|def report_text(report):
#|    lines = [f"Starter drafts created: {len(report['created'])}",
#|             f"Controls that already had a rule (left alone): {report['skipped']}",
#|             f"Existing starter drafts given fix commands: {report.get('fixes_added', 0)}",
#|             f"Unedited starter drafts updated to the latest starter version: {report.get('refreshed', 0)}",
#|             f"Controls needing a human / design decision (no draft): {len(report['manual'])}",
#|             f"Controls with no starter entry: {len(report['no_entry'])}", ""]
#|    if report["manual"]:
#|        lines.append("NEEDS A HUMAN DECISION (consider 'Manual only' or a group-specific rule):")
#|        for stig, vid, ver, title, why in report["manual"]:
#|            lines.append(f"  {stig} {vid} ({ver}) {title[:80]}")
#|            lines.append(f"      -> {why}")
#|        lines.append("")
#|    if report["no_entry"]:
#|        lines.append("NO STARTER ENTRY:")
#|        lines += [f"  {stig} {vid} ({ver}) {title[:80]}" for stig, vid, ver, title, _ in report["no_entry"]]
#|    return "\n".join(lines)
#@ END
#@ FILE src/gui.py SHA 8bff799407cb90a8c02294265365e045ef0a5424f6794ad15e953a449422670c CHUNK 1 OF 1
#|"""Tkinter user interface. Tabs follow the workflow left to right:
#|
#|  1 Checklists  - import blank CKL / CKLB templates
#|  2 Work Queue  - build and test a rule for each control (or mark it manual)
#|  3 Groups      - device groups, which STIGs they get, which rule version per control
#|  4 Collect     - generate the SolarWinds show-command script
#|  5 Assess      - import SolarWinds output, review results, write checklist packages
#|"""
#|import copy
#|import difflib
#|import fnmatch
#|import json
#|import os
#|import re
#|import tkinter as tk
#|from tkinter import filedialog, messagebox, simpledialog, ttk
#|from tkinter.scrolledtext import ScrolledText
#|
#|import assess
#|import checklist
#|import collect
#|import drafts
#|import harden
#|import rules as engine
#|import store
#|from checklist import LABEL_TO_STATUS, STATUS_LABELS, STATUSES
#|
#|MONO = ("Consolas", 10)
#|HIGHLIGHT = {"match": "#b9f0b4", "problem": "#ffb3b3", "section": "#cfe2ff", "skipped": "#e4e4e4"}
#|STATUS_ROW = {"open": "#ffd6d6", "not_a_finding": "#d9f7d6", "not_applicable": "#e8e8e8",
#|              "not_reviewed": "#fff0c2", "manual": "#f4f4f4", "changed": "#e5d9ff", "expected": "#ffe5c7"}
#|STATE_ROW = {"Needs rule": "#fff0c2", "Draft": "#dde9ff", "Active": "#d9f7d6",
#|             "STIG changed - review": "#ffd6d6", "Manual only": "#ececec"}
#|RESULT_COLOR = {"not_a_finding": "#1b7a1b", "open": "#b00020", "not_applicable": "#555555",
#|                "not_reviewed": "#9a6a00"}
#|RULE_STATES = ["draft", "active", "retired"]
#|SHORT = {"not_a_finding": "NaF", "open": "Open", "not_applicable": "N/A", "not_reviewed": "NR"}
#|FORMAT_SHORT = {"ckl": ".ckl (Viewer 2.x)", "cklb": ".cklb (Viewer 3)"}
#|OUTCOMES = {"Open": "open", "Not Applicable": "not_applicable", "Not a Finding": "not_a_finding"}
#|
#|
#|# ---------------------------------------------------------------- small helpers
#|
#|def text_get(widget):
#|    return widget.get("1.0", "end-1c")
#|
#|
#|def text_set(widget, value, readonly=False):
#|    widget.configure(state="normal")
#|    widget.delete("1.0", "end")
#|    widget.insert("1.0", value or "")
#|    if readonly:
#|        widget.configure(state="disabled")
#|
#|
#|def help_label(parent, text):
#|    lbl = tk.Label(parent, text=text, justify="left", anchor="w", wraplength=1150,
#|                   bg="#fffbe6", fg="#333333", padx=8, pady=6, relief="groove")
#|    lbl.pack(fill="x", padx=6, pady=(6, 4))
#|    return lbl
#|
#|
#|def make_tree(parent, columns, height=10, selectmode="browse"):
#|    """columns: [(id, heading, width)]. Returns (frame, tree)."""
#|    frame = ttk.Frame(parent)
#|    tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings",
#|                        height=height, selectmode=selectmode)
#|    for cid, heading, width in columns:
#|        tree.heading(cid, text=heading)
#|        tree.column(cid, width=width, stretch=width >= 200, anchor="w")
#|    sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
#|    tree.configure(yscrollcommand=sb.set)
#|    tree.pack(side="left", fill="both", expand=True)
#|    sb.pack(side="right", fill="y")
#|    return frame, tree
#|
#|
#|def color_tags(tree, mapping):
#|    for tag, color in mapping.items():
#|        tree.tag_configure(tag, background=color)
#|
#|
#|def ask_choice(parent, title, prompt, choices, initial=None):
#|    """Small modal dropdown dialog. Returns the chosen string or None."""
#|    dlg = tk.Toplevel(parent)
#|    dlg.title(title)
#|    dlg.transient(parent)
#|    dlg.resizable(False, False)
#|    ttk.Label(dlg, text=prompt, wraplength=460, justify="left").pack(padx=12, pady=(12, 6), anchor="w")
#|    var = tk.StringVar(value=initial if initial in choices else (choices[0] if choices else ""))
#|    box = ttk.Combobox(dlg, textvariable=var, values=choices, state="readonly", width=70)
#|    box.pack(padx=12, fill="x")
#|    result = {}
#|
#|    def ok(_=None):
#|        result["value"] = var.get()
#|        dlg.destroy()
#|
#|    row = ttk.Frame(dlg)
#|    row.pack(pady=10)
#|    ttk.Button(row, text="OK", command=ok).pack(side="left", padx=4)
#|    ttk.Button(row, text="Cancel", command=dlg.destroy).pack(side="left", padx=4)
#|    dlg.bind("<Return>", ok)
#|    dlg.bind("<Escape>", lambda e: dlg.destroy())
#|    dlg.grab_set()
#|    box.focus_set()
#|    parent.wait_window(dlg)
#|    return result.get("value")
#|
#|
#|def maximize(window, fallback):
#|    """Start maximised so the layout survives Windows display scaling."""
#|    window.geometry(fallback)
#|    try:
#|        window.state("zoomed")
#|    except tk.TclError:
#|        pass
#|
#|
#|def open_folder(path):
#|    try:
#|        os.startfile(path)  # Windows
#|    except Exception:
#|        pass
#|
#|
#|# ---------------------------------------------------------------- application
#|
#|class App(tk.Tk):
#|    def __init__(self):
#|        super().__init__()
#|        self.title("STIG Group Assessment Tool")
#|        maximize(self, "1320x840")
#|        self.minsize(1000, 650)
#|        style = ttk.Style(self)
#|        if "vista" in style.theme_names():
#|            style.theme_use("vista")
#|        style.configure("Treeview", rowheight=22)
#|        style.configure("Big.TLabel", font=("Segoe UI", 12, "bold"))
#|
#|        self.run, self.run_mtime = None, None
#|        self.open_editors = set()
#|        self.status = tk.Label(self, anchor="w", bg="#eef2f7", fg="#333", padx=8)
#|        self.status.pack(side="bottom", fill="x")
#|        self.load_data()
#|
#|        self.nb = ttk.Notebook(self)
#|        self.nb.pack(fill="both", expand=True)
#|        self.tabs = [ChecklistsTab(self.nb, self), QueueTab(self.nb, self), GroupsTab(self.nb, self),
#|                     ScriptTab(self.nb, self), AssessTab(self.nb, self), HardenTab(self.nb, self)]
#|        for tab, name in zip(self.tabs, ["1. Checklists", "2. Rule Work Queue", "3. Device Groups",
#|                                         "4. Collection Script", "5. Import & Review", "6. Hardening Script"]):
#|            self.nb.add(tab, text=f"  {name}  ")
#|        # Teammates may have changed things: re-read the shared data whenever a tab is opened.
#|        self.nb.bind("<<NotebookTabChanged>>", lambda e: self.reload())
#|        self.bind("<F5>", lambda e: self.reload())
#|        self.protocol("WM_DELETE_WINDOW", self.quit_app)
#|        runs = store.list_runs()
#|        if runs:
#|            self.set_run(store.load_run(runs[0]), runs[0].stat().st_mtime)
#|        self.refresh_all()
#|        self.after(300, self.first_start_rules)
#|
#|    def first_start_rules(self):
#|        """A fresh install with no rules picks up the rules file shipped with the program."""
#|        bundled = store.bundled_rules_path()
#|        if self.rules_db["rules"] or not bundled.exists():
#|            return
#|        try:
#|            rep = store.import_rules(bundled)
#|        except (ValueError, OSError) as e:
#|            return messagebox.showwarning("Rules", f"Could not load the shipped rules file: {e}")
#|        self.reload()
#|        messagebox.showinfo("Rules loaded", f"This looks like a new install, so the {rep['added']} rules shipped in "
#|                                            f"{bundled.name} were loaded.\n\nImport your checklists on tab 1 - the "
#|                                            "rules attach to them automatically by STIG and Vuln ID.")
#|
#|    # -- shared data
#|    def load_data(self):
#|        self.settings = store.load_settings()
#|        engine.set_port_roles(self.settings["port_roles"])
#|        self.rules_db = store.load_rules()
#|        self.groups_db = store.load_groups()
#|        self.index = store.control_index()
#|        fmt = checklist.FORMAT_LABELS[self.settings["output_format"]]
#|        self.status.configure(text=f"Shared data: {store.paths.data}     Signed in as {store.current_user()} on "
#|                                   f"{store.current_host()}     Checklist output: {fmt}     F5 = refresh")
#|
#|    def reload(self):
#|        """Re-read rules, groups, settings and templates (picks up teammates' changes)."""
#|        self.load_data()
#|        tab = self.tabs[self.nb.index("current")] if hasattr(self, "nb") else None
#|        if tab:
#|            tab.refresh()
#|
#|    def refresh_all(self):
#|        for tab in self.tabs:
#|            tab.refresh()
#|
#|    @property
#|    def output_format(self):
#|        return self.settings["output_format"]
#|
#|    def formats_text(self, stig_id):
#|        """'.ckl (Viewer 2.x) + .cklb (Viewer 3)' - which checklist files exist for this STIG."""
#|        s = self.index.get(stig_id)
#|        if not s:
#|            return "not imported"
#|        return " + ".join(FORMAT_SHORT[f] for f in sorted(s["formats"]))
#|
#|    def stig_label(self, stig_id):
#|        s = self.index.get(stig_id)
#|        return f"{s['short']}  {s['release']}  [{self.formats_text(stig_id)}]" if s else f"{stig_id} (not imported)"
#|
#|    def short(self, stig_id):
#|        s = self.index.get(stig_id)
#|        return s["short"] if s else stig_id
#|
#|    def rule_by_id(self, rule_id):
#|        return next((r for r in self.rules_db["rules"] if r["id"] == rule_id), None)
#|
#|    # -- assessment run (one file per run, shared)
#|    def set_run(self, run, mtime=None):
#|        self.run, self.run_mtime = run, mtime
#|
#|    def save_run(self):
#|        """Save the current run, unless a teammate saved it in the meantime and we should take theirs."""
#|        if not self.run:
#|            return
#|        path = store.run_path(self.run["id"])
#|        if self.run_mtime and path.exists() and abs(path.stat().st_mtime - self.run_mtime) > 0.01:
#|            other = store.load_run(path) or {}
#|            pick = ask_choice(self, "Someone else changed this run",
#|                              f"{other.get('saved_by', 'Someone')} saved this assessment run at "
#|                              f"{other.get('saved_at', '?')} while you had it open.",
#|                              ["Keep my version (overwrite theirs)", "Load their version (lose my last change)"])
#|            if pick and pick.startswith("Load"):
#|                self.set_run(other, path.stat().st_mtime)
#|                self.refresh_all()
#|                return
#|        self.run_mtime = store.save_run(self.run)
#|
#|    def quit_app(self):
#|        for editor in list(self.open_editors):
#|            editor.release()
#|        self.destroy()
#|
#|
#|# ---------------------------------------------------------------- 1. checklists
#|
#|def word_diff(widget, old, new):
#|    """Write old -> new into a Text widget: removed words red + struck out, added words green."""
#|    a, b = re.split(r"(\s+)", old or ""), re.split(r"(\s+)", new or "")
#|    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
#|        if op == "equal":
#|            widget.insert("end", "".join(a[i1:i2]))
#|            continue
#|        if i2 > i1:
#|            widget.insert("end", "".join(a[i1:i2]), "del")
#|        if j2 > j1:
#|            widget.insert("end", "".join(b[j1:j2]), "ins")
#|
#|
#|def diff_text_widget(parent, height=20):
#|    t = ScrolledText(parent, wrap="word", font=("Segoe UI", 9), height=height)
#|    t.tag_configure("del", background="#ffc9c9", overstrike=True)
#|    t.tag_configure("ins", background="#b9f0b4")
#|    t.tag_configure("head", font=("Segoe UI", 10, "bold"), spacing1=8)
#|    return t
#|
#|
#|def show_control_diff(widget, old, new):
#|    """Fill a diff widget with every compared field of two versions of one control."""
#|    widget.configure(state="normal")
#|    widget.delete("1.0", "end")
#|    if old is None or new is None:
#|        c = new or old
#|        widget.insert("end", ("ADDED in the newer release" if old is None else "REMOVED in the newer release")
#|                      + "\n", "head")
#|        widget.insert("end", f"{c['title']}\n\nCHECK:\n{c['check']}\n\nFIX:\n{c['fix']}")
#|    else:
#|        for field, name in checklist.COMPARE_FIELDS.items():
#|            same = (checklist.text_hash(old.get(field)) == checklist.text_hash(new.get(field))
#|                    if field in ("check", "fix") else (old.get(field) or "") == (new.get(field) or ""))
#|            widget.insert("end", f"{name.upper()}{'  (unchanged)' if same else '  (CHANGED)'}\n", "head")
#|            if same and field in ("check", "fix"):
#|                widget.insert("end", "(same as before)\n")
#|            else:
#|                word_diff(widget, old.get(field) or "", new.get(field) or "")
#|                widget.insert("end", "\n")
#|    widget.configure(state="disabled")
#|
#|
#|class ChecklistsTab(ttk.Frame):
#|    COLUMNS = [("release", "Current release", 170), ("formats", "Imported as", 330), ("controls", "Controls", 70),
#|               ("auto", "Automated", 80), ("manual", "Manual", 65), ("todo", "Not built", 75),
#|               ("review", "Need review", 85), ("note", "Notes", 420)]
#|
#|    def __init__(self, nb, app):
#|        super().__init__(nb)
#|        self.app = app
#|        help_label(self, "Step 1 - Import the blank checklist for each STIG. Each STIG is one row; click the arrow "
#|                         "to see every file imported for it (older releases, and STIG Viewer 2.x .ckl vs STIG "
#|                         "Viewer 3 .cklb). When DISA publishes a new quarterly release, import it here, then use "
#|                         "'Compare releases' to see exactly what changed and which rules need a look.")
#|        row = ttk.Frame(self)
#|        row.pack(fill="x", padx=6)
#|        ttk.Button(row, text="Import checklist file(s)...", command=self.do_import).pack(side="left")
#|        ttk.Button(row, text="Compare releases...", command=self.compare).pack(side="left", padx=6)
#|        ttk.Button(row, text="Remove selected file", command=self.do_remove).pack(side="left")
#|        ttk.Label(row, text="Team checklist output format:").pack(side="left", padx=(30, 4))
#|        self.fmt_var = tk.StringVar()
#|        box = ttk.Combobox(row, textvariable=self.fmt_var, state="readonly", width=26,
#|                           values=list(checklist.FORMAT_LABELS.values()))
#|        box.pack(side="left")
#|        box.bind("<<ComboboxSelected>>", lambda e: self.set_format())
#|        ttk.Button(row, text="Where reasons go...", command=lambda: PlacementDialog(self.app)).pack(side="left",
#|                                                                                                   padx=8)
#|
#|        frame = ttk.Frame(self)
#|        frame.pack(fill="both", expand=True, padx=6, pady=6)
#|        self.tree = ttk.Treeview(frame, columns=[c[0] for c in self.COLUMNS], show="tree headings")
#|        self.tree.heading("#0", text="STIG")
#|        self.tree.column("#0", width=330, stretch=False)
#|        for cid, heading, width in self.COLUMNS:
#|            self.tree.heading(cid, text=heading)
#|            self.tree.column(cid, width=width, stretch=cid == "note", anchor="w")
#|        sb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
#|        self.tree.configure(yscrollcommand=sb.set)
#|        self.tree.pack(side="left", fill="both", expand=True)
#|        sb.pack(side="right", fill="y")
#|        self.tree.tag_configure("warn", background="#fff0c2")
#|        self.tree.tag_configure("file", foreground="#444")
#|        self.tree.bind("<Double-1>", lambda e: self.compare())
#|
#|    def refresh(self):
#|        fmt = self.app.output_format
#|        self.fmt_var.set(checklist.FORMAT_LABELS[fmt])
#|        opened = {i for i in self.tree.get_children() if self.tree.item(i, "open")}
#|        keep = self.tree.selection()
#|        self.tree.delete(*self.tree.get_children())
#|        for stig_id, stig in self.app.index.items():
#|            counts = {}
#|            for vuln_id in stig["order"]:
#|                state = assess.control_state(self.app.rules_db, stig_id, stig["controls"][vuln_id])
#|                counts[state] = counts.get(state, 0) + 1
#|            formats = " | ".join(f"{checklist.FORMAT_LABELS[f]} {rel.split(' ')[0]}"
#|                                 for f, rel in sorted(stig["formats"].items()))
#|            notes = []
#|            if fmt not in stig["formats"]:
#|                notes.append(f"No {checklist.FORMAT_LABELS[fmt]} file - cannot write this checklist")
#|            elif stig["formats"][fmt] != stig["release"]:
#|                notes.append(f"Newest release only imported as the other format - import the "
#|                             f"{checklist.FORMAT_LABELS[fmt]} file")
#|            if counts.get("STIG changed - review"):
#|                notes.append(f"{counts['STIG changed - review']} rule(s) need review after a STIG update")
#|            pid = f"S|{stig_id}"
#|            self.tree.insert("", "end", iid=pid, text=stig["short"], open=pid in opened,
#|                             tags=("warn",) if notes else (),
#|                             values=(stig["release"], formats, len(stig["order"]), counts.get("Active", 0)
#|                                     + counts.get("STIG changed - review", 0), counts.get("Manual only", 0),
#|                                     counts.get("Needs rule", 0) + counts.get("Draft", 0),
#|                                     counts.get("STIG changed - review", 0), "; ".join(notes) or "OK"))
#|            current = {f: cat["id"] for f, cat in store.templates_for(stig_id).items()}
#|            for cat, s in reversed(store.releases_for(stig_id)):
#|                rel = checklist.release_label(s.get("version"), s.get("release_info"))
#|                mark = "CURRENT  " if current.get(cat["format"]) == cat["id"] else ""
#|                self.tree.insert(pid, "end", iid=f"C|{cat['id']}|{stig_id}", tags=("file",),
#|                                 text=checklist.FORMAT_LABELS[cat["format"]],
#|                                 values=(rel, cat.get("viewer", ""), len(s["controls"]), "", "", "", "",
#|                                         f"{mark}imported {cat['imported_at'][:16].replace('T', ' ')} by "
#|                                         f"{cat.get('imported_by', '?')} from {cat['source_name']}"))
#|        if not self.app.index:
#|            self.tree.insert("", "end", text="No checklists imported yet - click 'Import checklist file(s)'.")
#|        keep = [k for k in keep if self.tree.exists(k)]
#|        if keep:
#|            self.tree.selection_set(keep)
#|
#|    def selected_stig(self):
#|        sel = self.tree.selection()
#|        if not sel or "|" not in sel[0]:
#|            return None
#|        return sel[0].split("|")[-1]
#|
#|    def set_format(self):
#|        fmt = next(k for k, v in checklist.FORMAT_LABELS.items() if v == self.fmt_var.get())
#|        if fmt != self.app.output_format:
#|            store.set_setting("output_format", fmt)
#|            self.app.reload()
#|
#|    def do_import(self):
#|        files = filedialog.askopenfilenames(title="Choose STIG checklist file(s)",
#|                                            filetypes=[("STIG checklists", "*.ckl *.cklb"), ("All files", "*.*")])
#|        report = []
#|        for f in files:
#|            try:
#|                _, lines = store.import_template(f, self.app.rules_db)
#|                report += lines
#|            except Exception as e:
#|                report.append(f"{os.path.basename(f)}: NOT imported - {e}")
#|        if report:
#|            self.app.reload()
#|            ImportReport(self, "\n\n".join(report))
#|
#|    def do_remove(self):
#|        sel = self.tree.selection()
#|        if not sel or not sel[0].startswith("C|"):
#|            return messagebox.showinfo("Remove", "Expand a STIG and select the specific file to remove.")
#|        tid = sel[0].split("|")[1]
#|        cat = next((c for c in store.list_catalogs() if c["id"] == tid), None)
#|        if cat and messagebox.askyesno("Remove file", f"Remove {cat['source_name']} "
#|                                                      f"({checklist.FORMAT_LABELS[cat['format']]}) from the tool for "
#|                                                      "everyone? Rules are kept."):
#|            store.remove_template(cat)
#|            self.app.reload()
#|
#|    def compare(self):
#|        stig_id = self.selected_stig()
#|        if not stig_id:
#|            return messagebox.showinfo("Compare releases", "Select a STIG first.")
#|        ReleaseCompareWindow(self.app, stig_id)
#|
#|
#|class PlacementDialog(tk.Toplevel):
#|    """Team setting: which checklist field holds the reason for each result."""
#|
#|    def __init__(self, app):
#|        super().__init__(app)
#|        self.app = app
#|        self.title("Where reasons go in the checklist")
#|        self.transient(app)
#|        self.resizable(False, False)
#|        f = ttk.Frame(self, padding=12)
#|        f.pack()
#|        ttk.Label(f, text="For each result, which checklist field gets the reason (the rule's text, the evidence\n"
#|                          "found on the devices and the reviewer sign-off). Team setting - applies to everyone.",
#|                  justify="left").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
#|        self.vars = {}
#|        current = app.settings["text_placement"]
#|        for r, status in enumerate(["not_a_finding", "not_applicable", "open", "not_reviewed"], 1):
#|            ttk.Label(f, text=STATUS_LABELS[status]).grid(row=r, column=0, sticky="w", pady=2)
#|            var = tk.StringVar(value=assess.FIELD_LABELS[current[status]])
#|            ttk.Combobox(f, textvariable=var, values=list(assess.FIELD_LABELS.values()), state="readonly",
#|                         width=18).grid(row=r, column=1, sticky="w", padx=8)
#|            self.vars[status] = var
#|        ttk.Label(f, text="The rule's extra comment and the reviewer's comment always go in Comments.",
#|                  foreground="#555").grid(row=6, column=0, columnspan=2, sticky="w", pady=(8, 0))
#|        b = ttk.Frame(f)
#|        b.grid(row=7, column=0, columnspan=2, pady=(10, 0))
#|        ttk.Button(b, text="Save", command=self.save).pack(side="left", padx=4)
#|        ttk.Button(b, text="Cancel", command=self.destroy).pack(side="left", padx=4)
#|        self.grab_set()
#|        app.wait_window(self)
#|
#|    def save(self):
#|        to_key = {v: k for k, v in assess.FIELD_LABELS.items()}
#|        store.set_setting("text_placement", {s: to_key[v.get()] for s, v in self.vars.items()})
#|        self.app.reload()
#|        self.destroy()
#|
#|
#|class ImportReport(tk.Toplevel):
#|    def __init__(self, parent, text):
#|        super().__init__(parent)
#|        self.title("Import results")
#|        self.geometry("900x500")
#|        self.transient(parent)
#|        t = ScrolledText(self, wrap="word", font=("Segoe UI", 10))
#|        t.pack(fill="both", expand=True, padx=8, pady=8)
#|        text_set(t, text, readonly=True)
#|        ttk.Button(self, text="Close", command=self.destroy).pack(pady=(0, 8))
#|
#|
#|class ReleaseCompareWindow(tk.Toplevel):
#|    """Side-by-side view of what DISA changed between two releases of one STIG, and its effect on rules."""
#|
#|    def __init__(self, app, stig_id):
#|        super().__init__(app)
#|        self.app, self.stig_id = app, stig_id
#|        self.title(f"Compare releases - {app.short(stig_id)}")
#|        maximize(self, "1300x800")
#|        releases = {}
#|        for cat, s in store.releases_for(stig_id):
#|            releases[checklist.release_label(s.get("version"), s.get("release_info"))] = s
#|        self.releases = releases
#|        labels = list(releases)
#|
#|        top = ttk.Frame(self)
#|        top.pack(fill="x", padx=8, pady=8)
#|        ttk.Label(top, text=app.short(stig_id), style="Big.TLabel").pack(side="left")
#|        ttk.Label(top, text="   Compare").pack(side="left")
#|        self.old_var = tk.StringVar(value=labels[-2] if len(labels) > 1 else (labels[0] if labels else ""))
#|        self.new_var = tk.StringVar(value=labels[-1] if labels else "")
#|        for var, text in ((self.old_var, "with"), (self.new_var, "")):
#|            box = ttk.Combobox(top, textvariable=var, values=labels, state="readonly", width=24)
#|            box.pack(side="left", padx=4)
#|            box.bind("<<ComboboxSelected>>", lambda e: self.refresh())
#|            if text:
#|                ttk.Label(top, text=text).pack(side="left")
#|        self.only_rules = tk.BooleanVar(value=False)
#|        ttk.Checkbutton(top, text="Only changes that affect rules", variable=self.only_rules,
#|                        command=self.refresh).pack(side="left", padx=20)
#|        self.summary = ttk.Label(self, text="", foreground="#333")
#|        self.summary.pack(fill="x", padx=8)
#|
#|        paned = ttk.PanedWindow(self, orient="horizontal")
#|        paned.pack(fill="both", expand=True, padx=8, pady=8)
#|        left = ttk.Frame(paned)
#|        paned.add(left, weight=2)
#|        lf, self.tree = make_tree(left, [("vuln", "Vuln ID", 85), ("kind", "Change", 75),
#|                                         ("fields", "What changed", 170), ("rules", "Rules", 160),
#|                                         ("todo", "Rule status", 150)], height=25)
#|        lf.pack(fill="both", expand=True)
#|        color_tags(self.tree, {"review": "#ffd6d6", "ok": "#d9f7d6", "info": "#ffffff"})
#|        self.tree.bind("<<TreeviewSelect>>", lambda e: self.show())
#|        btns = ttk.Frame(left)
#|        btns.pack(fill="x", pady=4)
#|        ttk.Button(btns, text="Open rule...", command=self.open_rule).pack(side="left")
#|        ttk.Button(btns, text="Rule still valid - mark reviewed", command=self.mark_reviewed).pack(side="left",
#|                                                                                                  padx=4)
#|        right = ttk.Frame(paned)
#|        paned.add(right, weight=3)
#|        ttk.Label(right, text="Red struck-out = removed by DISA, green = added.").pack(anchor="w")
#|        self.diff = diff_text_widget(right)
#|        self.diff.pack(fill="both", expand=True)
#|        self.diffs = {}
#|        if len(labels) < 2:
#|            self.summary.configure(text="Only one release of this STIG has been imported - import the newer "
#|                                        "release on the Checklists tab, then compare.")
#|        self.refresh()
#|
#|    def refresh(self):
#|        self.tree.delete(*self.tree.get_children())
#|        old, new = self.releases.get(self.old_var.get()), self.releases.get(self.new_var.get())
#|        if not old or not new:
#|            return
#|        current = self.app.index[self.stig_id]
#|        is_current = self.new_var.get() == current["release"]
#|        diffs = checklist.compare_controls(old["controls"], new["controls"])
#|        self.diffs = {d["vuln_id"]: d for d in diffs}
#|        need = 0
#|        for d in diffs:
#|            rs = assess.rules_for_control(self.app.rules_db, self.stig_id, d["vuln_id"])
#|            new_hash = d["new"]["check_hash"] if d["new"] else None
#|            if not rs:
#|                todo, tag = "-", "info"
#|            elif d["kind"] == "removed":
#|                todo, tag = "Retire rule (control removed)", "review"
#|            elif not is_current:
#|                todo, tag = "(compare with current release)", "info"
#|            elif any(r.get("check_hash") != new_hash for r in rs if r.get("state") == "active"):
#|                todo, tag = "NEEDS REVIEW", "review"
#|            else:
#|                todo, tag = "Reviewed / unaffected", "ok"
#|            if tag == "review":
#|                need += 1
#|            if self.only_rules.get() and not rs:
#|                continue
#|            self.tree.insert("", "end", iid=d["vuln_id"], tags=(tag,),
#|                             values=(d["vuln_id"], d["kind"],
#|                                     ", ".join(checklist.COMPARE_FIELDS[f] for f in d["fields"]) or "-",
#|                                     ", ".join(f"{r['id']} ({r.get('state')})" for r in rs) or "-", todo))
#|        counts = {k: sum(1 for d in diffs if d["kind"] == k) for k in ("added", "removed", "changed")}
#|        self.summary.configure(text=f"{self.old_var.get()} -> {self.new_var.get()}:  {counts['added']} added, "
#|                                    f"{counts['removed']} removed, {counts['changed']} changed.   "
#|                                    f"Rules needing review: {need}.")
#|        self.show()
#|
#|    def selected(self):
#|        sel = self.tree.selection()
#|        return self.diffs.get(sel[0]) if sel else None
#|
#|    def show(self):
#|        d = self.selected()
#|        if d:
#|            show_control_diff(self.diff, d["old"], d["new"])
#|        else:
#|            text_set(self.diff, "Select a control on the left to see what changed.", readonly=True)
#|
#|    def open_rule(self):
#|        d = self.selected()
#|        if not d or not d["new"]:
#|            return
#|        rs = assess.rules_for_control(self.app.rules_db, self.stig_id, d["vuln_id"])
#|        if not rs:
#|            return messagebox.showinfo("No rule", "This control has no rule.", parent=self)
#|        control = self.app.index[self.stig_id]["controls"].get(d["vuln_id"])
#|        if control:
#|            RuleEditor.open(self.app, self.stig_id, control, rs[0], self.after_change)
#|
#|    def mark_reviewed(self):
#|        d = self.selected()
#|        current = self.app.index[self.stig_id]
#|        if not d or not d["new"] or self.new_var.get() != current["release"]:
#|            return messagebox.showinfo("Mark reviewed", "Select a changed control, comparing against the current "
#|                                                        f"release ({current['release']}).", parent=self)
#|        rs = [r for r in assess.rules_for_control(self.app.rules_db, self.stig_id, d["vuln_id"])
#|              if r.get("check_hash") != d["new"]["check_hash"]]
#|        if not rs:
#|            return messagebox.showinfo("Mark reviewed", "No rules need review for this control.", parent=self)
#|        if messagebox.askyesno("Mark reviewed", f"Confirm {', '.join(r['id'] for r in rs)} still check the right "
#|                                                f"thing after the {current['release']} change?", parent=self):
#|            for r in rs:
#|                store.mark_rule_reviewed(r["id"], d["new"]["check_hash"], current["release"])
#|            self.after_change()
#|
#|    def after_change(self):
#|        self.app.reload()
#|        self.refresh()
#|
#|
#|# ---------------------------------------------------------------- 2. work queue
#|
#|class QueueTab(ttk.Frame):
#|    STATES = ["All", "Needs rule", "Draft", "Active", "STIG changed - review", "Manual only"]
#|
#|    def __init__(self, nb, app):
#|        super().__init__(nb)
#|        self.app = app
#|        help_label(self, "Step 2 - Every control needs a decision. Select a control, read its check text, then click "
#|                         "'New rule' to describe which show command to run and what text proves compliance. "
#|                         "Controls that cannot be checked from show output can be marked 'Manual only'. A control "
#|                         "can have several rule versions (for example one for access switches and one for cores); "
#|                         "each group picks which version it uses on the Device Groups tab. A rule someone else "
#|                         "has open is locked so two people do not overwrite each other.")
#|        filt = ttk.Frame(self)
#|        filt.pack(fill="x", padx=6)
#|        ttk.Label(filt, text="STIG:").pack(side="left")
#|        self.stig_var = tk.StringVar(value="All")
#|        self.stig_box = ttk.Combobox(filt, textvariable=self.stig_var, state="readonly", width=50)
#|        self.stig_box.pack(side="left", padx=4)
#|        ttk.Label(filt, text="State:").pack(side="left", padx=(10, 0))
#|        self.state_var = tk.StringVar(value="All")
#|        ttk.Combobox(filt, textvariable=self.state_var, values=self.STATES, state="readonly",
#|                     width=22).pack(side="left", padx=4)
#|        ttk.Label(filt, text="Search:").pack(side="left", padx=(10, 0))
#|        self.search_var = tk.StringVar()
#|        ttk.Entry(filt, textvariable=self.search_var, width=28).pack(side="left", padx=4)
#|        for var in (self.stig_var, self.state_var, self.search_var):
#|            var.trace_add("write", lambda *a: self.refresh())
#|        ttk.Button(filt, text="Create starter drafts...", command=self.starter_drafts).pack(side="right")
#|        ttk.Button(filt, text="Import rules...", command=self.import_rules).pack(side="right", padx=4)
#|        ttk.Button(filt, text="Export rules...", command=self.export_rules).pack(side="right")
#|        self.progress = ttk.Label(self, text="", foreground="#333", wraplength=1500, justify="left")
#|        self.progress.pack(fill="x", padx=8, pady=(4, 0))
#|
#|        paned = ttk.PanedWindow(self, orient="horizontal")
#|        paned.pack(fill="both", expand=True, padx=6, pady=6)
#|        left, self.tree = make_tree(paned, [("stig", "STIG", 190), ("fmt", "Imported as", 150),
#|                                            ("vuln", "Vuln ID", 80), ("ver", "Rule Ver", 120),
#|                                            ("sev", "Severity", 65), ("state", "State", 150),
#|                                            ("rules", "Rules", 45), ("title", "Title", 400)], height=24)
#|        color_tags(self.tree, {k.replace(" ", "_"): v for k, v in STATE_ROW.items()})
#|        paned.add(left, weight=3)
#|        self.tree.bind("<<TreeviewSelect>>", lambda e: self.show_control())
#|        self.tree.bind("<Double-1>", lambda e: self.edit_rule(default=True))
#|
#|        right = ttk.Frame(paned)
#|        paned.add(right, weight=2)
#|        ttk.Label(right, text="STIG check and fix text", font=("Segoe UI", 9, "bold")).pack(anchor="w")
#|        self.details = ScrolledText(right, height=16, width=50, wrap="word", font=("Segoe UI", 9))
#|        self.details.pack(fill="both", expand=True)
#|        ttk.Label(right, text="Rules for this control", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(8, 0))
#|        rf, self.rule_tree = make_tree(right, [("id", "Rule", 75), ("name", "Version name", 150),
#|                                               ("state", "State", 60), ("ver", "Rev", 40),
#|                                               ("default", "Default", 55), ("tests", "Tests", 45),
#|                                               ("by", "Last saved by", 150)], height=5)
#|        rf.pack(fill="x")
#|        self.rule_tree.bind("<Double-1>", lambda e: self.edit_rule())
#|        for row in ((("New rule", self.new_rule), ("Edit", self.edit_rule), ("Copy as new version", self.copy_rule),
#|                     ("Manual only on/off", self.toggle_manual)),
#|                    (("Make default", self.make_default), ("Retire", self.retire_rule),
#|                     ("Delete draft", self.delete_rule))):
#|            btns = ttk.Frame(right)
#|            btns.pack(fill="x", pady=(4, 0))
#|            for text, cmd in row:
#|                ttk.Button(btns, text=text, command=cmd).pack(side="left", padx=2)
#|        self.stig_map = {}
#|
#|    # -- data
#|    def refresh(self):
#|        self.stig_map = {self.app.stig_label(s): s for s in self.app.index}
#|        self.stig_box["values"] = ["All"] + list(self.stig_map)
#|        if self.stig_var.get() not in self.stig_box["values"]:
#|            self.stig_var.set("All")
#|        want_stig = self.stig_map.get(self.stig_var.get())
#|        want_state, needle = self.state_var.get(), self.search_var.get().lower().strip()
#|        keep = self.tree.selection()
#|        self.tree.delete(*self.tree.get_children())
#|        summary = []
#|        for stig_id, stig in self.app.index.items():
#|            counts = {}
#|            for vuln_id in stig["order"]:
#|                c = stig["controls"][vuln_id]
#|                state = assess.control_state(self.app.rules_db, stig_id, c)
#|                counts[state] = counts.get(state, 0) + 1
#|                if want_stig and stig_id != want_stig:
#|                    continue
#|                if want_state != "All" and state != want_state:
#|                    continue
#|                if needle and needle not in f"{vuln_id} {c['rule_ver']} {c['title']}".lower():
#|                    continue
#|                n = len(assess.rules_for_control(self.app.rules_db, stig_id, vuln_id))
#|                self.tree.insert("", "end", iid=assess.key_of(stig_id, vuln_id), tags=(state.replace(" ", "_"),),
#|                                 values=(stig["short"], self.app.formats_text(stig_id), vuln_id, c["rule_ver"],
#|                                         c["severity"], state, n, c["title"]))
#|            if want_stig and stig_id != want_stig:
#|                continue
#|            done = counts.get("Active", 0) + counts.get("Manual only", 0)
#|            summary.append(f"{stig['short']}: {done}/{len(stig['order'])} decided"
#|                           + (f", {counts['STIG changed - review']} need review"
#|                              if counts.get("STIG changed - review") else ""))
#|        self.progress.configure(text="     ".join(summary) or "No checklists imported yet - start on tab 1.")
#|        keep = [k for k in keep if self.tree.exists(k)]
#|        if keep:
#|            self.tree.selection_set(keep)
#|            self.tree.see(keep[0])
#|        self.show_control()
#|
#|    def current(self):
#|        sel = self.tree.selection()
#|        if not sel:
#|            return None, None
#|        stig_id, vuln_id = sel[0].split("|", 1)
#|        return stig_id, self.app.index[stig_id]["controls"][vuln_id]
#|
#|    def show_control(self):
#|        stig_id, c = self.current()
#|        self.rule_tree.delete(*self.rule_tree.get_children())
#|        if not c:
#|            text_set(self.details, "", readonly=True)
#|            return
#|        text_set(self.details, f"{self.app.stig_label(stig_id)}\n"
#|                               f"{c['vuln_id']}  {c['rule_ver']}  [{c['severity']}]\n{c['title']}\n\n"
#|                               f"CHECK:\n{c['check']}\n\nFIX:\n{c['fix']}", readonly=True)
#|        for r in assess.rules_for_control(self.app.rules_db, stig_id, c["vuln_id"], include_retired=True):
#|            lock = store.lock_holder("rule", r["id"])
#|            self.rule_tree.insert("", "end", iid=r["id"],
#|                                  values=(r["id"], r.get("name", ""), r.get("state", "draft"), r.get("version", 1),
#|                                          "yes" if r.get("is_default") else "", len(r.get("tests", [])),
#|                                          f"EDITING NOW: {lock['user']}" if lock else
#|                                          f"{r.get('saved_by', r.get('updated_by', ''))} "
#|                                          f"{(r.get('saved_at') or r.get('updated_at') or '')[:10]}"))
#|
#|    def selected_rule(self):
#|        sel = self.rule_tree.selection()
#|        return self.app.rule_by_id(sel[0]) if sel else None
#|
#|    # -- actions
#|    def new_rule(self):
#|        stig_id, c = self.current()
#|        if c:
#|            RuleEditor.open(self.app, stig_id, c, None, self.after_save)
#|
#|    def edit_rule(self, default=False):
#|        stig_id, c = self.current()
#|        if not c:
#|            return
#|        r = self.selected_rule()
#|        if r is None and default:
#|            rs = assess.rules_for_control(self.app.rules_db, stig_id, c["vuln_id"])
#|            r = next((x for x in rs if x.get("is_default")), rs[0] if rs else None)
#|        if r is None and default:
#|            return self.new_rule()
#|        if r:
#|            RuleEditor.open(self.app, stig_id, c, r, self.after_save)
#|
#|    def copy_rule(self):
#|        stig_id, c = self.current()
#|        r = self.selected_rule()
#|        if not r:
#|            return messagebox.showinfo("Copy", "Select a rule to copy first.")
#|        dup = copy.deepcopy(r)
#|        for k in ("id", "history", "review_log", "is_default", "created_at", "created_by", "_rev", "saved_by",
#|                  "saved_at"):
#|            dup.pop(k, None)
#|        dup.update(name=r.get("name", "") + " (copy)", state="draft", version=0)
#|        RuleEditor.open(self.app, stig_id, c, dup, self.after_save, is_copy=True)
#|
#|    def make_default(self):
#|        stig_id, c = self.current()
#|        r = self.selected_rule()
#|        if not r:
#|            return
#|        for x in assess.rules_for_control(self.app.rules_db, stig_id, c["vuln_id"], include_retired=True):
#|            if bool(x.get("is_default")) != (x["id"] == r["id"]):
#|                store.modify_rule(x["id"], lambda d, on=x["id"] == r["id"]: d.__setitem__("is_default", on))
#|        self.after_save()
#|
#|    def retire_rule(self):
#|        r = self.selected_rule()
#|        if r and messagebox.askyesno("Retire rule", f"Retire {r['id']} '{r.get('name')}'? "
#|                                                    "Groups using it will fall back to the default version."):
#|            store.modify_rule(r["id"], lambda d: d.update(state="retired", is_default=False))
#|            self.after_save()
#|
#|    def delete_rule(self):
#|        r = self.selected_rule()
#|        if not r:
#|            return
#|        if r.get("state") != "draft" or r.get("history"):
#|            return messagebox.showinfo("Delete", "Only drafts that were never saved as Active can be deleted. "
#|                                                 "Use Retire instead so the history is kept.")
#|        if store.lock_holder("rule", r["id"]):
#|            return messagebox.showinfo("Delete", "Someone has this rule open. Try again when they are done.")
#|        if messagebox.askyesno("Delete draft", f"Delete draft {r['id']}?"):
#|            store.delete_rule(r["id"])
#|            self.after_save()
#|
#|    def export_rules(self):
#|        path = filedialog.asksaveasfilename(
#|            title="Export rules", defaultextension=".json", initialdir=str(store.paths.output),
#|            initialfile=f"stigtool_rules_{store.stamp()}.json", filetypes=[("STIGTOOL rules", "*.json")])
#|        if path:
#|            n = store.export_rules(path)
#|            messagebox.showinfo("Export rules", f"{n} rules (and the manual-only list) written to\n{path}\n\n"
#|                                                "Author names and edit history are left out.")
#|
#|    def import_rules(self):
#|        path = filedialog.askopenfilename(title="Import rules", filetypes=[("STIGTOOL rules", "*.json")],
#|                                          initialdir=str(store.bundled_rules_path().parent))
#|        if not path:
#|            return
#|        try:
#|            rep = store.import_rules(path)
#|        except ValueError as e:
#|            return messagebox.showerror("Import rules", str(e))
#|        self.after_save()
#|        messagebox.showinfo("Import rules", f"Added {rep['added']} rule(s). Skipped {rep['skipped']} that already "
#|                                            f"exist here (not overwritten). {rep['manual_added']} control(s) newly "
#|                                            "marked Manual only.")
#|
#|    def starter_drafts(self):
#|        stig_id = self.stig_map.get(self.stig_var.get())
#|        scope = self.app.short(stig_id) if stig_id else "ALL imported STIGs"
#|        if not messagebox.askyesno(
#|                "Create starter drafts",
#|                f"Create starter DRAFT rules for {scope}?\n\n"
#|                "Drafts are written from the STIG check text for Catalyst 9300 / 8300 (IOS-XE 17.x) and Nexus 9000 "
#|                "(NX-OS 9.3/10.x). Only controls with no rule yet get one - existing rules are never touched. "
#|                "Every draft must be reviewed and tested before it can be made Active."):
#|            return
#|        report = drafts.create_drafts(self.app.index, self.app.rules_db, [stig_id] if stig_id else None)
#|        text = drafts.report_text(report)
#|        path = store.paths.output / f"starter_drafts_report_{store.stamp()}.txt"
#|        path.write_text(text + "\n", encoding="utf-8")
#|        self.after_save()
#|        ImportReport(self, f"Saved to {path}\n\n{text}")
#|        if report["manual"] and messagebox.askyesno(
#|                "Manual only?", f"{len(report['manual'])} control(s) need a human or design decision (listed in the "
#|                                "report). Mark them 'Manual only' now? You can switch any back later."):
#|            for stig, vuln_id, *_ in report["manual"]:
#|                sid = next(s for s, v in self.app.index.items() if v["short"] == stig)
#|                store.set_manual(assess.key_of(sid, vuln_id), True)
#|            self.after_save()
#|
#|    def toggle_manual(self):
#|        stig_id, c = self.current()
#|        if not c:
#|            return
#|        key = assess.key_of(stig_id, c["vuln_id"])
#|        store.set_manual(key, key not in self.app.rules_db.get("manual_controls", []))
#|        self.after_save()
#|
#|    def after_save(self):
#|        self.app.load_data()
#|        self.refresh()
#|
#|
#|# ---------------------------------------------------------------- rule editor
#|
#|class RuleEditor(tk.Toplevel):
#|    @classmethod
#|    def open(cls, app, stig_id, control, rule, on_saved, is_copy=False):
#|        """Open the editor, respecting a teammate's edit lock on the rule."""
#|        readonly = False
#|        if rule and rule.get("id") and not is_copy:
#|            holder = store.acquire_lock("rule", rule["id"])
#|            if holder:
#|                pick = ask_choice(app, "Rule is being edited",
#|                                  f"{holder['user']} (on {holder['host']}) has opened {rule['id']} for editing "
#|                                  f"since {holder['since'][11:16]}. If you both edit it, one of you will lose "
#|                                  "changes.", ["Open read-only", "Edit anyway (they have finished)", "Cancel"])
#|                if not pick or pick == "Cancel":
#|                    return None
#|                if pick.startswith("Edit"):
#|                    store.acquire_lock("rule", rule["id"], force=True)
#|                else:
#|                    readonly = True
#|            # always edit the latest saved copy, not what the list showed a minute ago
#|            rule = store.load_json(store.rule_path(rule["id"]), rule)
#|        return cls(app, stig_id, control, rule, on_saved, is_copy, readonly)
#|
#|    def __init__(self, app, stig_id, control, rule, on_saved, is_copy=False, readonly=False):
#|        super().__init__(app)
#|        self.app, self.stig_id, self.control, self.on_saved = app, stig_id, control, on_saved
#|        self.readonly = readonly
#|        self.original = rule if (rule and not is_copy) else None
#|        self.r = copy.deepcopy(rule) if rule else {
#|            "name": "Default", "state": "draft", "version": 0, "commands": [],
#|            "pass_logic": {"mode": "ALL", "conditions": []}, "na_enabled": False,
#|            "na_logic": {"mode": "ALL", "conditions": []}, "comment": "", "notes": "", "tests": []}
#|        self.r.setdefault("na_logic", {"mode": "ALL", "conditions": []})
#|        self.r.setdefault("tests", [])
#|        name = app.short(stig_id)
#|        self.title(f"Rule - {name} {control['vuln_id']} {control['rule_ver']}"
#|                   + (f" - {self.r['id']}" if self.r.get("id") else " - new") + ("  (READ-ONLY)" if readonly else ""))
#|        maximize(self, "1420x900")
#|        self.sample, self.cur_cmd, self._job, self._loading = {}, None, None, False
#|        app.open_editors.add(self)
#|
#|        top = ttk.Frame(self)
#|        top.pack(fill="x", padx=8, pady=(8, 0))
#|        ttk.Label(top, text=f"{name} {control['vuln_id']} ({control['rule_ver']}, {control['severity']}): "
#|                            f"{control['title']}", wraplength=1380, font=("Segoe UI", 10, "bold")).pack(anchor="w")
#|        ttk.Label(top, text=f"STIG release {app.index[stig_id]['release']}, imported as {app.formats_text(stig_id)}. "
#|                            "Rules apply to the STIG whichever checklist format is written.",
#|                  foreground="#555").pack(anchor="w")
#|        if readonly:
#|            tk.Label(top, text="READ-ONLY: someone else is editing this rule. You can test it but not save.",
#|                     bg="#fff0c2", anchor="w", padx=6).pack(fill="x", pady=(4, 0))
#|        if self.original and self.original.get("check_hash") != control["check_hash"]:
#|            self._changed_banner(top)
#|        paned = ttk.PanedWindow(self, orient="horizontal")
#|        paned.pack(fill="both", expand=True, padx=8, pady=8)
#|        left, right = ttk.Frame(paned), ttk.Frame(paned)
#|        paned.add(left, weight=1)
#|        paned.add(right, weight=1)
#|        self._build_left(left)
#|        self._build_right(right)
#|        self.after(100, lambda: paned.sashpos(0, max(500, self.winfo_width() // 2)))
#|        self._load_form()
#|        if self.r["tests"]:
#|            self.load_test(self.r["tests"][0])
#|        self.run_all_tests(quiet=True)
#|        self.schedule()
#|        self.protocol("WM_DELETE_WINDOW", self.cancel)
#|
#|    def _changed_banner(self, parent):
#|        old_rel, old = store.find_control_version(self.stig_id, self.control["vuln_id"], self.original["check_hash"])
#|        self.banner = tk.Frame(parent, bg="#ffd6d6")
#|        self.banner.pack(fill="x", pady=(4, 0))
#|        tk.Label(self.banner, bg="#ffd6d6", anchor="w", padx=6,
#|                 text=f"DISA changed this control's check text in {self.app.index[self.stig_id]['release']}"
#|                      + (f" (this rule was written against {old_rel})" if old_rel else "")
#|                      + ". Check the rule still fits. Saving the rule marks it reviewed.").pack(side="left")
#|        if old:
#|            ttk.Button(self.banner, text="What changed?",
#|                       command=lambda: self._show_change(old_rel, old)).pack(side="left", padx=4)
#|        ttk.Button(self.banner, text="Still valid - mark reviewed", command=self._mark_reviewed).pack(side="left")
#|
#|    def _show_change(self, old_rel, old):
#|        win = tk.Toplevel(self)
#|        win.title(f"{self.control['vuln_id']}: {old_rel} -> {self.app.index[self.stig_id]['release']}")
#|        win.geometry("1000x700")
#|        ttk.Label(win, text="Red struck-out = removed by DISA, green = added.").pack(anchor="w", padx=8, pady=4)
#|        t = diff_text_widget(win)
#|        t.pack(fill="both", expand=True, padx=8, pady=(0, 8))
#|        show_control_diff(t, old, self.control)
#|
#|    def _mark_reviewed(self):
#|        if self.readonly:
#|            return
#|        saved = store.mark_rule_reviewed(self.original["id"], self.control["check_hash"],
#|                                         self.app.index[self.stig_id]["release"])
#|        for d in (self.original, self.r):
#|            d.update(check_hash=saved["check_hash"], _rev=saved["_rev"], review_log=saved.get("review_log", []))
#|        self.banner.destroy()
#|        self.on_saved()
#|
#|    # -- layout
#|    def _build_left(self, f):
#|        btns = ttk.Frame(f)  # packed first at the bottom so it stays visible on small screens
#|        btns.pack(side="bottom", fill="x", pady=8)
#|        ttk.Button(btns, text="Save rule", command=self.save).pack(side="left")
#|        ttk.Button(btns, text="Cancel", command=self.cancel).pack(side="left", padx=6)
#|        ttk.Label(btns, text="To set State = active the rule needs 2+ saved tests with different expected "
#|                             "results, all passing.", foreground="#666", wraplength=420).pack(side="left", padx=10)
#|
#|        ttk.Label(f, text="STIG check text (for reference)").pack(anchor="w")
#|        chk = ScrolledText(f, height=5, width=50, wrap="word", font=("Segoe UI", 9))
#|        chk.pack(fill="x")
#|        text_set(chk, f"{self.control['check']}\n\nFIX:\n{self.control['fix']}", readonly=True)
#|
#|        row = ttk.Frame(f)
#|        row.pack(fill="x", pady=(8, 0))
#|        ttk.Label(row, text="Version name:").pack(side="left")
#|        self.name_var = tk.StringVar()
#|        ttk.Entry(row, textvariable=self.name_var, width=28).pack(side="left", padx=4)
#|        ttk.Label(row, text="State:").pack(side="left", padx=(10, 0))
#|        self.state_var = tk.StringVar()
#|        ttk.Combobox(row, textvariable=self.state_var, values=RULE_STATES, state="readonly",
#|                     width=10).pack(side="left", padx=4)
#|        self.rev_label = ttk.Label(row, text="")
#|        self.rev_label.pack(side="left", padx=10)
#|
#|        ttk.Label(f, text="Show commands to collect (one per line, exactly as typed on the device):").pack(
#|            anchor="w", pady=(8, 0))
#|        self.cmd_text = tk.Text(f, height=3, width=50, font=MONO)
#|        self.cmd_text.pack(fill="x")
#|        self.cmd_text.bind("<KeyRelease>", lambda e: self.commands_changed())
#|
#|        self.pass_box, self.pass_mode = self._condition_block(
#|            f, "NOT A FINDING when", "of these are true.  Anything else = OPEN.", "pass_logic", height=4)
#|        na_head = ttk.Frame(f)
#|        na_head.pack(fill="x", pady=(10, 0))
#|        self.na_var = tk.BooleanVar()
#|        ttk.Checkbutton(na_head, text="Use a Not Applicable check (checked before the Not a Finding check)",
#|                        variable=self.na_var, command=self.schedule).pack(side="left")
#|        self.na_box, self.na_mode = self._condition_block(
#|            f, "NOT APPLICABLE when", "of these are true.", "na_logic", height=2)
#|
#|        extra = ttk.Notebook(f)
#|        extra.pack(fill="x", pady=(8, 0))
#|        fd = ttk.Frame(extra, padding=4)
#|        extra.add(fd, text=" Reason text ")
#|        row = ttk.Frame(fd)
#|        row.pack(fill="x")
#|        ttk.Label(row, text="When the result is").pack(side="left")
#|        self.outcome_pick = tk.StringVar(value="Open")
#|        box = ttk.Combobox(row, textvariable=self.outcome_pick, values=list(OUTCOMES), state="readonly", width=15)
#|        box.pack(side="left", padx=4)
#|        box.bind("<<ComboboxSelected>>", lambda e: self.switch_outcome())
#|        self.outcome_where = ttk.Label(row, text="", foreground="#555")
#|        self.outcome_where.pack(side="left")
#|        self.outcome_box = tk.Text(fd, height=3, width=50, wrap="word", font=("Segoe UI", 9))
#|        self.outcome_box.pack(fill="x", pady=2)
#|        self.outcome_box.bind("<KeyRelease>", lambda e: (self.store_outcome(), self.schedule()))
#|        self.expected_var = tk.BooleanVar()
#|        ttk.Checkbutton(fd, variable=self.expected_var, command=self.schedule,
#|                        text="Open is INTENTIONAL for this rule (known finding, e.g. recommend risk acceptance). "
#|                             "Reviewers see 'Open (expected)'.").pack(anchor="w")
#|        cm = ttk.Frame(extra, padding=4)
#|        extra.add(cm, text=" Extra comment ")
#|        ttk.Label(cm, text="Always added to the checklist's Comments field, whatever the result:",
#|                  foreground="#555").pack(anchor="w")
#|        self.comment_text = tk.Text(cm, height=4, width=50, wrap="word", font=("Segoe UI", 9))
#|        self.comment_text.pack(fill="x")
#|        fx = ttk.Frame(extra, padding=4)
#|        extra.add(fx, text=" Fix commands ")
#|        fx.columnconfigure(0, weight=1)
#|        fx.columnconfigure(1, weight=1)
#|        ttk.Label(fx, text="LOW-IMPACT fix (banners, logging, archive...):").grid(row=0, column=0, sticky="w")
#|        ttk.Label(fx, text="IMPACTFUL fix (AAA, SSH, vty, ports, STP, SNMP...):").grid(row=0, column=1, sticky="w")
#|        self.fix_low = tk.Text(fx, height=4, width=25, wrap="none", font=MONO)
#|        self.fix_low.grid(row=1, column=0, sticky="we", padx=(0, 4))
#|        self.fix_high = tk.Text(fx, height=4, width=25, wrap="none", font=MONO)
#|        self.fix_high.grid(row=1, column=1, sticky="we")
#|        ttk.Label(fx, foreground="#555", wraplength=700, justify="left",
#|                  text="Config commands for the Hardening Script tab. <VALUE> = fill in per site. A line "
#|                       "'{each failing section}' followed by indented commands repeats them under every interface / "
#|                       "section that failed on the device; '{each failing section of condition 2}' only under the "
#|                       "ones that failed condition 2 (so one rule can add a command on uplinks and remove it on "
#|                       "access ports).").grid(row=2, column=0, columnspan=2, sticky="w")
#|        nt = ttk.Frame(extra, padding=4)
#|        extra.add(nt, text=" Reviewer guidance ")
#|        ttk.Label(nt, text="Notes for reviewers and rule authors (not written to the checklist):",
#|                  foreground="#555").pack(anchor="w")
#|        self.notes_text = tk.Text(nt, height=4, width=50, wrap="word", font=("Segoe UI", 9))
#|        self.notes_text.pack(fill="x")
#|
#|    def _condition_block(self, parent, head, tail, logic_key, height):
#|        frame = ttk.LabelFrame(parent, text="")
#|        frame.pack(fill="x", pady=(8, 0))
#|        hdr = ttk.Frame(frame)
#|        hdr.pack(fill="x", padx=4, pady=2)
#|        ttk.Label(hdr, text=head, font=("Segoe UI", 9, "bold")).pack(side="left")
#|        mode = tk.StringVar(value="ALL")
#|        box = ttk.Combobox(hdr, textvariable=mode, values=["ALL", "ANY"], state="readonly", width=5)
#|        box.pack(side="left", padx=4)
#|        box.bind("<<ComboboxSelected>>", lambda e: self.schedule())
#|        ttk.Label(hdr, text=tail).pack(side="left")
#|        lb = tk.Listbox(frame, height=height, width=50, font=("Segoe UI", 9), activestyle="none")
#|        lb.pack(fill="x", padx=4)
#|        lb.bind("<Double-1>", lambda e: self.edit_condition(logic_key, lb))
#|        b = ttk.Frame(frame)
#|        b.pack(fill="x", padx=4, pady=2)
#|        ttk.Button(b, text="Add condition...", command=lambda: self.edit_condition(logic_key, lb, new=True)).pack(
#|            side="left")
#|        ttk.Button(b, text="Edit...", command=lambda: self.edit_condition(logic_key, lb)).pack(side="left", padx=2)
#|        ttk.Button(b, text="Remove", command=lambda: self.remove_condition(logic_key, lb)).pack(side="left", padx=2)
#|        return lb, mode
#|
#|    def _build_right(self, f):
#|        ttk.Label(f, text="Test against sample output", style="Big.TLabel").pack(anchor="w")
#|        row = ttk.Frame(f)
#|        row.pack(fill="x", pady=4)
#|        ttk.Label(row, text="Output of command:").pack(side="left")
#|        self.cmd_pick = tk.StringVar()
#|        self.cmd_box = ttk.Combobox(row, textvariable=self.cmd_pick, state="readonly")
#|        self.cmd_box.pack(side="left", padx=4, fill="x", expand=True)
#|        self.cmd_box.bind("<<ComboboxSelected>>", lambda e: self.switch_command())
#|        row2 = ttk.Frame(f)
#|        row2.pack(fill="x")
#|        ttk.Button(row2, text="Load from imported device...", command=self.load_from_device).pack(side="left")
#|        ttk.Button(row2, text="Empty output", command=self.set_empty).pack(side="left", padx=4)
#|        ttk.Button(row2, text="No output (missing)", command=self.set_missing).pack(side="left")
#|        self.sample_state = ttk.Label(f, text="", foreground="#555")
#|        self.sample_state.pack(anchor="w")
#|
#|        tf = ttk.Frame(f)  # packed last so the widgets below it always get their space
#|        self.sample_text = tk.Text(tf, height=12, width=50, font=MONO, wrap="none", undo=True)
#|        ys = ttk.Scrollbar(tf, orient="vertical", command=self.sample_text.yview)
#|        xs = ttk.Scrollbar(tf, orient="horizontal", command=self.sample_text.xview)
#|        self.sample_text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
#|        self.sample_text.grid(row=0, column=0, sticky="nsew")
#|        ys.grid(row=0, column=1, sticky="ns")
#|        xs.grid(row=1, column=0, sticky="ew")
#|        tf.rowconfigure(0, weight=1)
#|        tf.columnconfigure(0, weight=1)
#|        for tag, color in HIGHLIGHT.items():
#|            self.sample_text.tag_configure(tag, background=color)
#|        self.sample_text.bind("<<Modified>>", self.sample_modified)
#|
#|        legend = ttk.Frame(f)
#|
#|        for tag, text in (("match", "matched"), ("problem", "problem"),
#|                          ("section", "section OK"), ("skipped", "skipped")):
#|            tk.Label(legend, text=f"  {text}  ", bg=HIGHLIGHT[tag]).pack(side="left", padx=2)
#|
#|        self.result_label = tk.Label(f, text="", font=("Segoe UI", 14, "bold"), anchor="w")
#|
#|        self.explain = ScrolledText(f, height=8, width=50, wrap="none", font=MONO)
#|
#|
#|        tests = ttk.LabelFrame(f, text="Saved tests (re-run every time the rule changes)")
#|
#|        tfr, self.test_tree = make_tree(tests, [("name", "Test name", 240), ("exp", "Expected", 120),
#|                                                ("got", "Rule gives", 120), ("res", "Result", 70)], height=4)
#|        tfr.pack(fill="x", padx=4)
#|        color_tags(self.test_tree, {"pass": "#d9f7d6", "fail": "#ffd6d6"})
#|        self.test_tree.bind("<Double-1>", lambda e: self.load_selected_test())
#|        b = ttk.Frame(tests)
#|        b.pack(fill="x", padx=4, pady=4)
#|        ttk.Button(b, text="Save current sample as a test...", command=self.save_test).pack(side="left")
#|        ttk.Button(b, text="Load test into sample", command=self.load_selected_test).pack(side="left", padx=4)
#|        ttk.Button(b, text="Delete test", command=self.delete_test).pack(side="left", padx=4)
#|        tests.pack(side="bottom", fill="x", pady=(6, 0))
#|        self.explain.pack(side="bottom", fill="x")
#|        self.result_label.pack(side="bottom", fill="x", pady=(6, 0))
#|        legend.pack(side="bottom", fill="x", pady=2)
#|        tf.pack(fill="both", expand=True)
#|
#|    # -- form <-> rule
#|    def _load_form(self):
#|        self.name_var.set(self.r.get("name", ""))
#|        self.state_var.set(self.r.get("state", "draft"))
#|        self.rev_label.configure(text=f"Revision {self.r.get('version', 0)}" if self.r.get("version") else "New rule")
#|        text_set(self.cmd_text, "\n".join(self.r.get("commands", [])))
#|        self.pass_mode.set(self.r["pass_logic"].get("mode", "ALL"))
#|        self.na_mode.set(self.r["na_logic"].get("mode", "ALL"))
#|        self.na_var.set(bool(self.r.get("na_enabled")))
#|        text_set(self.comment_text, self.r.get("comment", ""))
#|        text_set(self.notes_text, self.r.get("notes", ""))
#|        text_set(self.fix_low, (self.r.get("fix") or {}).get("low", ""))
#|        text_set(self.fix_high, (self.r.get("fix") or {}).get("high", ""))
#|        self.outcomes = dict(self.r.get("outcome_text") or {})
#|        self.cur_outcome = "open"
#|        self.outcome_pick.set("Open")
#|        text_set(self.outcome_box, self.outcomes.get("open", ""))
#|        self.show_outcome_where()
#|        self.expected_var.set(bool(self.r.get("expected_open")))
#|        self.commands_changed()
#|
#|    def commands(self):
#|        seen = []
#|        for line in text_get(self.cmd_text).splitlines():
#|            if line.strip() and line.strip() not in seen:
#|                seen.append(line.strip())
#|        return seen
#|
#|    def collect(self):
#|        self.r["name"] = self.name_var.get().strip()
#|        self.r["state"] = self.state_var.get()
#|        self.r["commands"] = self.commands()
#|        self.r["pass_logic"]["mode"] = self.pass_mode.get()
#|        self.r["na_logic"]["mode"] = self.na_mode.get()
#|        self.r["na_enabled"] = self.na_var.get()
#|        self.r["comment"] = text_get(self.comment_text).strip()
#|        self.r["fix"] = {"low": text_get(self.fix_low).rstrip(), "high": text_get(self.fix_high).rstrip()}
#|        self.store_outcome()
#|        self.r["outcome_text"] = {k: v.strip() for k, v in self.outcomes.items() if v.strip()}
#|        self.r["expected_open"] = self.expected_var.get()
#|        self.r["notes"] = text_get(self.notes_text).strip()
#|        return self.r
#|
#|    def store_outcome(self):
#|        if hasattr(self, "outcomes"):
#|            self.outcomes[self.cur_outcome] = text_get(self.outcome_box)
#|
#|    def switch_outcome(self):
#|        self.store_outcome()
#|        self.cur_outcome = OUTCOMES[self.outcome_pick.get()]
#|        text_set(self.outcome_box, self.outcomes.get(self.cur_outcome, ""))
#|        self.show_outcome_where()
#|
#|    def show_outcome_where(self):
#|        field = assess.FIELD_LABELS[self.app.settings["text_placement"][self.cur_outcome]]
#|        self.outcome_where.configure(text=f"this text goes in {field.upper()} (team setting).  "
#|                                          "{devices} = the device names.")
#|
#|    def render_conditions(self):
#|        for lb, key in ((self.pass_box, "pass_logic"), (self.na_box, "na_logic")):
#|            lb.delete(0, "end")
#|            for i, c in enumerate(self.r[key]["conditions"], 1):
#|                errs = engine.condition_problems(c, self.commands())
#|                lb.insert("end", f"{i}. {engine.describe(c)}" + (f"   <-- {errs[0]}" if errs else ""))
#|                if errs:
#|                    lb.itemconfigure("end", foreground="#b00020")
#|
#|    def commands_changed(self):
#|        cmds = self.commands()
#|        self.cmd_box["values"] = cmds
#|        if self.cur_cmd not in cmds:
#|            self.cur_cmd = None
#|            self.cmd_pick.set(cmds[0] if cmds else "")
#|            self.switch_command(store_current=False)
#|        self.render_conditions()
#|        self.schedule()
#|
#|    # -- conditions
#|    def edit_condition(self, key, lb, new=False):
#|        if not self.commands():
#|            return messagebox.showinfo("Commands first", "Type at least one show command first.", parent=self)
#|        idx = None
#|        if not new:
#|            sel = lb.curselection()
#|            if not sel:
#|                return
#|            idx = sel[0]
#|        start = None if new else self.r[key]["conditions"][idx]
#|        dlg = ConditionDialog(self, self.commands(), start, default_cmd=self.cur_cmd)
#|        if dlg.result is None:
#|            return
#|        if new:
#|            self.r[key]["conditions"].append(dlg.result)
#|        else:
#|            self.r[key]["conditions"][idx] = dlg.result
#|        if key == "na_logic":
#|            self.na_var.set(True)
#|        self.render_conditions()
#|        self.schedule()
#|
#|    def remove_condition(self, key, lb):
#|        sel = lb.curselection()
#|        if sel:
#|            del self.r[key]["conditions"][sel[0]]
#|            self.render_conditions()
#|            self.schedule()
#|
#|    # -- sample handling
#|    def switch_command(self, store_current=True):
#|        if store_current:
#|            self.store_sample()
#|        self.cur_cmd = self.cmd_pick.get() or None
#|        self._loading = True
#|        text_set(self.sample_text, self.sample.get(self.cur_cmd, ""))
#|        self.sample_text.edit_modified(False)
#|        self._loading = False
#|        self.schedule()
#|
#|    def store_sample(self):
#|        # Typing anything (or pressing Empty output) makes the sample count as collected evidence.
#|        if self.cur_cmd and (self.cur_cmd in self.sample or text_get(self.sample_text)):
#|            self.sample[self.cur_cmd] = text_get(self.sample_text)
#|
#|    def sample_modified(self, _=None):
#|        if self.sample_text.edit_modified():
#|            self.sample_text.edit_modified(False)
#|            if not self._loading and self.cur_cmd:
#|                self.sample[self.cur_cmd] = text_get(self.sample_text)
#|                self.schedule()
#|
#|    def set_empty(self):
#|        if self.cur_cmd:
#|            self.sample[self.cur_cmd] = ""
#|            self.switch_command(store_current=False)
#|
#|    def set_missing(self):
#|        if self.cur_cmd:
#|            self.sample.pop(self.cur_cmd, None)
#|            self.switch_command(store_current=False)
#|
#|    def load_from_device(self):
#|        run = self.app.run
#|        devices = [d for d in (run or {}).get("devices", []) if d["status"] == "ok"]
#|        if not devices:
#|            return messagebox.showinfo("No devices", "Import a SolarWinds output file on tab 5 first, "
#|                                                     "or paste sample output into the box.", parent=self)
#|        cmds = self.commands()
#|        choices = [f"{d['host']}  ({sum(1 for c in cmds if c in d['outputs'])}/{len(cmds)} commands)"
#|                   for d in devices]
#|        pick = ask_choice(self, "Load sample", "Load this rule's command output from which device "
#|                                               f"(run {run['id']})?", choices)
#|        if not pick:
#|            return
#|        device = devices[choices.index(pick)]
#|        for c in cmds:
#|            if c in device["outputs"]:
#|                self.sample[c] = device["outputs"][c]["text"]
#|            else:
#|                self.sample.pop(c, None)
#|        self.switch_command(store_current=False)
#|
#|    def sample_outputs(self):
#|        return {c: {"status": engine.classify_output(self.sample[c]), "text": self.sample[c]}
#|                for c in self.commands() if c in self.sample}
#|
#|    # -- testing
#|    def schedule(self, *_):
#|        if self._job:
#|            self.after_cancel(self._job)
#|        self._job = self.after(300, self.run_test)
#|
#|    def run_test(self):
#|        self._job = None
#|        rule = self.collect()
#|        outputs = self.sample_outputs()
#|        res = engine.evaluate(rule, outputs)
#|        for tag in HIGHLIGHT:
#|            self.sample_text.tag_remove(tag, "1.0", "end")
#|        for idx, tag in res["marks"].get(self.cur_cmd, {}).items():
#|            self.sample_text.tag_add(tag, f"{idx + 1}.0", f"{idx + 1}.end+1c")
#|        status = res["status"]
#|        expected = status == "open" and rule.get("expected_open")
#|        self.result_label.configure(text=f"Result: {STATUS_LABELS[status].upper()}"
#|                                         + ("  (EXPECTED - intentional finding)" if expected else ""),
#|                                    fg="#b35c00" if expected else RESULT_COLOR[status])
#|        added = engine.outcome_text(rule, status, ["<device>"])
#|        field = assess.FIELD_LABELS[self.app.settings["text_placement"][status]]
#|        text_set(self.explain, f"The reason for {STATUS_LABELS[status]} goes in the checklist's {field}"
#|                 + (f", starting with:\n{added}\n\n" if added else ".\n\n") +
#|                 "\n".join(res["reasons"]) +
#|                 (f"\n\nEvidence lines that would go into {field}:\n" + "\n".join(res["evidence"])
#|                  if res["evidence"] else ""), readonly=True)
#|        if self.cur_cmd is None:
#|            state = "Add a show command on the left first."
#|        elif self.cur_cmd not in self.sample:
#|            state = "No sample for this command - the rule treats it as MISSING evidence (Not Reviewed)."
#|        elif outputs[self.cur_cmd]["status"] == "invalid":
#|            state = "The device rejected this command (% Invalid ...) - counts as INVALID evidence (Not Reviewed)."
#|        elif not self.sample[self.cur_cmd].strip():
#|            state = "Sample is EMPTY output (the command ran and printed nothing)."
#|        else:
#|            state = f"Sample: {len(engine.split_lines(self.sample[self.cur_cmd]))} lines. Paste or type to change it."
#|        self.sample_state.configure(text=state)
#|        self.run_all_tests(quiet=True)
#|        return status
#|
#|    def run_all_tests(self, quiet=False):
#|        self.test_tree.delete(*self.test_tree.get_children())
#|        for i, (t, actual, ok) in enumerate(engine.run_tests(self.collect())):
#|            self.test_tree.insert("", "end", iid=str(i), tags=("pass" if ok else "fail",),
#|                                  values=(t["name"], STATUS_LABELS.get(t["expected"], t["expected"]),
#|                                          STATUS_LABELS.get(actual, actual), "PASS" if ok else "FAIL"))
#|
#|    def save_test(self):
#|        self.store_sample()
#|        if not self.sample_outputs():
#|            return messagebox.showinfo("Nothing to save", "Load or paste sample output first.", parent=self)
#|        name = simpledialog.askstring("Save test", "Name this test (e.g. 'good config', 'telnet enabled'):",
#|                                      parent=self)
#|        if not name:
#|            return
#|        current = STATUS_LABELS[self.run_test()]
#|        labels = [STATUS_LABELS[s] for s in STATUSES]
#|        exp = ask_choice(self, "Expected result", "What SHOULD the result be for this sample? "
#|                                                  f"(the rule currently says {current})", labels, initial=current)
#|        if not exp:
#|            return
#|        self.r["tests"].append({"name": name.strip(), "expected": LABEL_TO_STATUS[exp],
#|                                "outputs": {c: self.sample[c] for c in self.commands() if c in self.sample},
#|                                "saved_at": store.now(), "saved_by": store.current_user()})
#|        self.run_all_tests()
#|
#|    def selected_test(self):
#|        sel = self.test_tree.selection()
#|        return self.r["tests"][int(sel[0])] if sel else None
#|
#|    def load_test(self, t):
#|        self.sample = dict(t.get("outputs", {}))
#|        self.switch_command(store_current=False)
#|
#|    def load_selected_test(self):
#|        t = self.selected_test()
#|        if t:
#|            self.load_test(t)
#|
#|    def delete_test(self):
#|        t = self.selected_test()
#|        if t and messagebox.askyesno("Delete test", f"Delete test '{t['name']}'?", parent=self):
#|            self.r["tests"].remove(t)
#|            self.run_all_tests()
#|
#|    # -- save
#|    def save(self):
#|        if self.readonly:
#|            return messagebox.showinfo("Read-only", "Someone else is editing this rule, so it cannot be saved here.",
#|                                       parent=self)
#|        rule = self.collect()
#|        if not rule["name"]:
#|            return messagebox.showerror("Name needed", "Give this rule version a name (e.g. 'Default').", parent=self)
#|        if rule["state"] == "active":
#|            problems = engine.activation_problems(rule)
#|            if problems:
#|                if not messagebox.askyesno("Cannot activate yet",
#|                                           "This rule cannot be Active yet:\n\n- " + "\n- ".join(problems) +
#|                                           "\n\nSave it as a Draft instead?", parent=self):
#|                    return
#|                rule["state"] = "draft"
#|        content_keys = ("name", "state", "commands", "pass_logic", "na_enabled", "na_logic", "comment", "notes",
#|                        "outcome_text", "expected_open", "fix",
#|                        "tests")
#|        if self.original is not None:
#|            before = {k: self.original.get(k) for k in content_keys}
#|            after = {k: rule.get(k) for k in content_keys}
#|            if json.dumps(before, sort_keys=True) != json.dumps(after, sort_keys=True):
#|                snapshot = {k: v for k, v in self.original.items() if k not in ("history", "review_log")}
#|                rule.setdefault("history", []).append(snapshot)
#|                rule["version"] = self.original.get("version", 1) + 1
#|            rule["check_hash"] = self.control["check_hash"]
#|            try:
#|                store.save_rule(rule)
#|            except store.ConflictError as e:
#|                pick = ask_choice(self, "Changed by someone else",
#|                                  f"{e.current.get('saved_by')} saved {rule['id']} at {e.current.get('saved_at')} "
#|                                  "while you were editing.",
#|                                  ["Save mine as a separate new version (keeps both)",
#|                                   "Overwrite theirs with mine", "Cancel - keep editing"])
#|                if not pick or pick.startswith("Cancel"):
#|                    return
#|                if pick.startswith("Overwrite"):
#|                    rule["_rev"] = e.current.get("_rev", 0)
#|                    store.save_rule(rule)
#|                else:
#|                    self._save_new({**rule, "name": f"{rule['name']} ({store.current_user()})", "state": "draft",
#|                                    "history": [], "is_default": False})
#|        else:
#|            self._save_new(rule)
#|        self.on_saved()
#|        self.close()
#|
#|    def _save_new(self, rule):
#|        rule = {k: v for k, v in rule.items() if k not in ("_rev", "review_log")}
#|        siblings = assess.rules_for_control(store.load_rules(), self.stig_id, self.control["vuln_id"])
#|        rule.update(id=store.new_rule_id(), stig_id=self.stig_id, vuln_id=self.control["vuln_id"], version=1,
#|                    check_hash=self.control["check_hash"], created_at=store.now(), created_by=store.current_user())
#|        rule.setdefault("is_default", not any(s.get("is_default") for s in siblings))
#|        rule.setdefault("history", [])
#|        store.save_rule(rule, check=False)
#|
#|    def release(self):
#|        if self.original and not self.readonly:
#|            store.release_lock("rule", self.original["id"])
#|        self.app.open_editors.discard(self)
#|
#|    def close(self):
#|        self.release()
#|        self.destroy()
#|
#|    def cancel(self):
#|        if self.readonly or messagebox.askyesno("Close", "Close without saving changes?", parent=self):
#|            self.close()
#|
#|
#|# ---------------------------------------------------------------- condition dialog
#|
#|CHECK_HELP = {
#|    "has": "Passes when at least one line matches. Example: has a line that starts with 'login block-for'.",
#|    "lacks": "Passes when NO line matches. Example: has NO line that contains 'transport input telnet'.",
#|    "number": "Finds matching line(s) and reads the first number after your text. "
#|              "Example: a line containing 'exec-timeout' with a number at most 10.",
#|    "count": "Counts matching lines. Example: at least 2 lines that start with 'ntp server'.",
#|    "pattern": "Advanced: a regular expression searched across the whole text. Use \\n to span lines.",
#|    "no_pattern": "Advanced: passes when the regular expression is NOT found anywhere.",
#|}
#|SCOPE_HELP = ("A section is a line plus the indented lines under it, e.g. 'line vty 0 4' and its settings, "
#|              "or 'interface GigabitEthernet1/0/1' and its settings. 'Only' / 'skip' look for a line STARTING "
#|              "with the text, so skip 'shutdown' does not skip 'no shutdown'. Start with re: for a regex. "
#|              "Port roles: type role:uplink, role:downlink, role:access or role:any to pick interfaces by their "
#|              "description keyword (set on the Device Groups tab).")
#|
#|
#|class ConditionDialog(tk.Toplevel):
#|    def __init__(self, parent, commands, cond, default_cmd=None):
#|        super().__init__(parent)
#|        self.title("Condition")
#|        self.transient(parent)
#|        self.resizable(False, False)
#|        self.result = None
#|        c = {**engine.NEW_CONDITION, **(cond or {})}
#|        if not c["command"]:
#|            c["command"] = default_cmd if default_cmd in commands else commands[0]
#|        self.v = {k: tk.StringVar(value=str(c[k])) for k in
#|                  ("command", "section", "section_how", "only", "exclude", "text", "how", "op", "value")}
#|        self.scope_labels = {v: k for k, v in engine.SCOPES.items()}
#|        self.check_labels = {v: k for k, v in engine.CHECKS.items()}
#|        self.v["scope"] = tk.StringVar(value=engine.SCOPES[c["scope"]])
#|        self.v["check"] = tk.StringVar(value=engine.CHECKS[c["check"]])
#|        self.v["if_none"] = tk.StringVar(value="counts as FAIL" if c["if_none"] == "fail" else "counts as PASS")
#|        self.ignore = tk.BooleanVar(value=bool(c["ignore_case"]))
#|
#|        f = ttk.Frame(self, padding=12)
#|        f.pack(fill="both")
#|        r = 0
#|
#|        def row(label, widget, colspan=3):
#|            nonlocal r
#|            ttk.Label(f, text=label).grid(row=r, column=0, sticky="w", pady=3)
#|            widget.grid(row=r, column=1, columnspan=colspan, sticky="we", pady=3)
#|            r += 1
#|            return widget
#|
#|        row("In the output of:", ttk.Combobox(f, textvariable=self.v["command"], values=commands,
#|                                              state="readonly", width=60))
#|        row("Look in:", ttk.Combobox(f, textvariable=self.v["scope"], values=list(engine.SCOPES.values()),
#|                                     state="readonly", width=60))
#|        sec = ttk.Frame(f)
#|        self.w_section_how = ttk.Combobox(sec, textvariable=self.v["section_how"], values=engine.HOWS,
#|                                          state="readonly", width=11)
#|        self.w_section_how.pack(side="left")
#|        self.w_section = ttk.Entry(sec, textvariable=self.v["section"], width=46)
#|        self.w_section.pack(side="left", padx=4)
#|        row("   ...section first line:", sec)
#|        self.w_only = row("   ...only sections with a line starting:", ttk.Entry(f, textvariable=self.v["only"]))
#|        self.w_exclude = row("   ...skip sections with a line starting:", ttk.Entry(f, textvariable=self.v["exclude"]))
#|        self.w_if_none = row("   ...if no sections found:",
#|                             ttk.Combobox(f, textvariable=self.v["if_none"], state="readonly",
#|                                          values=["counts as FAIL", "counts as PASS"]))
#|        ttk.Label(f, text=SCOPE_HELP, foreground="#666", wraplength=560).grid(row=r, column=1, columnspan=3,
#|                                                                             sticky="w")
#|        r += 1
#|        ttk.Separator(f).grid(row=r, column=0, columnspan=4, sticky="we", pady=8)
#|        r += 1
#|        row("It:", ttk.Combobox(f, textvariable=self.v["check"], values=list(engine.CHECKS.values()),
#|                                state="readonly", width=60))
#|        txt = ttk.Frame(f)
#|        self.w_how = ttk.Combobox(txt, textvariable=self.v["how"], values=engine.HOWS, state="readonly", width=11)
#|        self.w_how.pack(side="left")
#|        ttk.Entry(txt, textvariable=self.v["text"], width=46).pack(side="left", padx=4)
#|        row("   ...text:", txt)
#|        num = ttk.Frame(f)
#|        self.w_op = ttk.Combobox(num, textvariable=self.v["op"], values=list(engine.OPS), state="readonly", width=4)
#|        self.w_op.pack(side="left")
#|        self.w_value = ttk.Entry(num, textvariable=self.v["value"], width=12)
#|        self.w_value.pack(side="left", padx=4)
#|        row("   ...number is:", num)
#|        row("", ttk.Checkbutton(f, text="Ignore upper/lower case", variable=self.ignore))
#|        self.help = ttk.Label(f, text="", foreground="#666", wraplength=560)
#|        self.help.grid(row=r, column=1, columnspan=3, sticky="w")
#|        r += 1
#|        ttk.Separator(f).grid(row=r, column=0, columnspan=4, sticky="we", pady=8)
#|        r += 1
#|        ttk.Label(f, text="Reads as:", font=("Segoe UI", 9, "bold")).grid(row=r, column=0, sticky="nw")
#|        self.preview = ttk.Label(f, text="", wraplength=560)
#|        self.preview.grid(row=r, column=1, columnspan=3, sticky="w")
#|        r += 1
#|        self.errors = ttk.Label(f, text="", foreground="#b00020", wraplength=560)
#|        self.errors.grid(row=r, column=1, columnspan=3, sticky="w")
#|        r += 1
#|        b = ttk.Frame(f)
#|        b.grid(row=r, column=0, columnspan=4, pady=(10, 0))
#|        ttk.Button(b, text="OK", command=self.ok).pack(side="left", padx=4)
#|        ttk.Button(b, text="Cancel", command=self.destroy).pack(side="left", padx=4)
#|
#|        for var in list(self.v.values()) + [self.ignore]:
#|            var.trace_add("write", lambda *a: self.update_view())
#|        self.commands = commands
#|        self.update_view()
#|        self.bind("<Escape>", lambda e: self.destroy())
#|        self.grab_set()
#|        parent.wait_window(self)
#|
#|    def current(self):
#|        return {
#|            "command": self.v["command"].get(), "scope": self.scope_labels[self.v["scope"].get()],
#|            "section": self.v["section"].get(), "section_how": self.v["section_how"].get(),
#|            "only": self.v["only"].get(), "exclude": self.v["exclude"].get(),
#|            "if_none": "fail" if "FAIL" in self.v["if_none"].get() else "pass",
#|            "check": self.check_labels[self.v["check"].get()], "text": self.v["text"].get(),
#|            "how": self.v["how"].get(), "ignore_case": self.ignore.get(),
#|            "op": self.v["op"].get(), "value": self.v["value"].get().strip(),
#|        }
#|
#|    def update_view(self):
#|        c = self.current()
#|        sectioned = c["scope"] != "all"
#|        for w in (self.w_section, self.w_only, self.w_exclude):
#|            w.configure(state="normal" if sectioned else "disabled")
#|        for w in (self.w_section_how, self.w_if_none):
#|            w.configure(state="readonly" if sectioned else "disabled")
#|        numeric = c["check"] in ("number", "count")
#|        self.w_op.configure(state="readonly" if numeric else "disabled")
#|        self.w_value.configure(state="normal" if numeric else "disabled")
#|        self.w_how.configure(state="disabled" if c["check"] in ("pattern", "no_pattern") else "readonly")
#|        self.help.configure(text=CHECK_HELP[c["check"]])
#|        self.preview.configure(text=engine.describe(c))
#|        errs = engine.condition_problems(c, self.commands)
#|        self.errors.configure(text="\n".join(f"- {e}" for e in errs))
#|
#|    def ok(self):
#|        c = self.current()
#|        errs = engine.condition_problems(c, self.commands)
#|        if errs:
#|            return messagebox.showerror("Fix the condition", "\n".join(errs), parent=self)
#|        self.result = c
#|        self.destroy()
#|
#|
#|# ---------------------------------------------------------------- 3. groups
#|
#|class GroupsTab(ttk.Frame):
#|    def __init__(self, nb, app):
#|        super().__init__(nb)
#|        self.app = app
#|        help_label(self, "Step 3 - A device group is a set of devices configured alike, e.g. CAMPUS-ACCESS (NDM + "
#|                         "RTR + L2S) or CAMPUS-HANGOFF (NDM + L2S). Click 'New group' and answer the questions: "
#|                         "name, which STIGs apply, which devices belong. Devices are matched by hostname pattern; "
#|                         "anything the pattern gets wrong can be moved by hand in the device list below.")
#|        b = ttk.Frame(self)
#|        b.pack(fill="x", padx=6)
#|        for text, cmd in (("New group...", self.new_group), ("Edit group...", self.edit_group),
#|                          ("Copy group...", self.copy_group), ("Delete group", self.delete_group),
#|                          ("Rule versions...", self.choose_rules), ("Port roles...", lambda: PortRolesDialog(self.app))):
#|            ttk.Button(b, text=text, command=cmd).pack(side="left", padx=(0, 6))
#|        gf, self.tree = make_tree(self, [("id", "Group", 170), ("desc", "Description", 250),
#|                                         ("stigs", "STIG checklists", 420), ("patterns", "Hostname patterns", 160),
#|                                         ("devices", "Devices", 65), ("auto", "Controls automated", 140)], height=8)
#|        gf.pack(fill="both", expand=True, padx=6, pady=6)
#|        self.tree.bind("<Double-1>", lambda e: self.edit_group())
#|        self.tree.tag_configure("warn", background="#fff0c2")
#|
#|        ttk.Label(self, text="Devices (from SolarWinds imports, or added by hand)",
#|                  font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=6)
#|        db = ttk.Frame(self)
#|        db.pack(fill="x", padx=6, pady=2)
#|        for text, cmd in (("Move to group...", self.set_override), ("Undo move (use pattern)", self.clear_override),
#|                          ("Add device...", self.add_device), ("Forget device", self.forget_device)):
#|            ttk.Button(db, text=text, command=cmd).pack(side="left", padx=(0, 6))
#|        df, self.dev_tree = make_tree(self, [("host", "Hostname", 220), ("ip", "IP", 180), ("group", "Group", 200),
#|                                             ("how", "How it got there", 260)], height=10, selectmode="extended")
#|        df.pack(fill="both", expand=True, padx=6, pady=(0, 6))
#|        self.dev_tree.tag_configure("none", background="#fff0c2")
#|
#|    def groups(self):
#|        return self.app.groups_db["groups"]
#|
#|    def refresh(self):
#|        keep = self.tree.selection()
#|        self.tree.delete(*self.tree.get_children())
#|        members = {}
#|        for host in self.app.groups_db["known_devices"]:
#|            gid, _ = assess.assign_group(host, self.app.groups_db)
#|            members[gid] = members.get(gid, 0) + 1
#|        for g in self.groups():
#|            cov = assess.coverage(g, self.app.rules_db, self.app.index)
#|            auto, total = sum(r["automated"] for r in cov), sum(r["total"] for r in cov)
#|            missing = [s for s in g.get("stigs", []) if s not in self.app.index]
#|            self.tree.insert("", "end", iid=g["id"], tags=("warn",) if missing or not g.get("stigs") else (),
#|                             values=(g["id"], g.get("description", ""),
#|                                     ", ".join(f"{self.app.short(s)} [{self.app.formats_text(s)}]"
#|                                               for s in g.get("stigs", [])) or "(none chosen)",
#|                                     ", ".join(g.get("patterns", [])), members.get(g["id"], 0),
#|                                     f"{auto} of {total}"))
#|        keep = [k for k in keep if self.tree.exists(k)]
#|        if keep:
#|            self.tree.selection_set(keep)
#|        self.dev_tree.delete(*self.dev_tree.get_children())
#|        for host, ip in sorted(self.app.groups_db["known_devices"].items()):
#|            gid, how = assess.assign_group(host, self.app.groups_db)
#|            how = {"override": "moved by hand", "unassigned": "no pattern matches"}.get(how, how)
#|            self.dev_tree.insert("", "end", iid=host, tags=("none",) if not gid else (),
#|                                 values=(host, ip, gid or "(not in a group - will not be assessed)", how))
#|
#|    def selected(self):
#|        sel = self.tree.selection()
#|        return assess.find_group(self.app.groups_db, sel[0]) if sel else None
#|
#|    def new_group(self):
#|        if not self.app.index:
#|            return messagebox.showinfo("Groups", "Import checklists on tab 1 first.")
#|        GroupDialog(self.app, None)
#|        self.after_change()
#|
#|    def edit_group(self):
#|        g = self.selected()
#|        if g:
#|            GroupDialog(self.app, g)
#|            self.after_change()
#|
#|    def copy_group(self):
#|        g = self.selected()
#|        if g:
#|            GroupDialog(self.app, g, copy_of=True)
#|            self.after_change()
#|
#|    def delete_group(self):
#|        g = self.selected()
#|        if g and messagebox.askyesno("Delete group", f"Delete group {g['id']} for everyone? Devices moved into it "
#|                                                     "by hand go back to pattern matching."):
#|            store.delete_group(g["id"])
#|            self.after_change()
#|
#|    def choose_rules(self):
#|        g = self.selected()
#|        if not g:
#|            return messagebox.showinfo("Rule versions", "Select a group first.")
#|        RuleChoicesDialog(self.app, g)
#|        self.after_change()
#|
#|    def set_override(self):
#|        hosts = self.dev_tree.selection()
#|        ids = [g["id"] for g in self.groups()]
#|        if not hosts or not ids:
#|            return
#|        gid = ask_choice(self, "Move devices", f"Put {len(hosts)} device(s) in which group?", ids)
#|        if gid:
#|            for h in hosts:
#|                store.set_override(h, gid)
#|            self.after_change()
#|
#|    def clear_override(self):
#|        for h in self.dev_tree.selection():
#|            store.set_override(h, None)
#|        self.after_change()
#|
#|    def add_device(self):
#|        host = simpledialog.askstring("Add device", "Hostname exactly as SolarWinds shows it:", parent=self)
#|        if not host or not host.strip():
#|            return
#|        ip = simpledialog.askstring("Add device", "IP address (optional):", parent=self) or ""
#|        store.add_known_devices({host.strip(): ip.strip()})
#|        self.after_change()
#|
#|    def forget_device(self):
#|        hosts = self.dev_tree.selection()
#|        if hosts and messagebox.askyesno("Forget devices", f"Remove {len(hosts)} device(s) from the list? They come "
#|                                                           "back automatically the next time they appear in an "
#|                                                           "import."):
#|            for h in hosts:
#|                store.forget_device(h)
#|            self.after_change()
#|
#|    def after_change(self):
#|        self.app.load_data()
#|        self.refresh()
#|
#|
#|class GroupDialog(tk.Toplevel):
#|    """Create or edit a group in three plain steps."""
#|
#|    def __init__(self, app, group, copy_of=False):
#|        super().__init__(app)
#|        self.app = app
#|        self.is_new = group is None or copy_of
#|        self.group = copy.deepcopy(group) if group else {"id": "", "description": "", "patterns": [], "stigs": [],
#|                                                         "rule_choices": {}}
#|        if copy_of:
#|            self.group.update(id=group["id"] + "-COPY", _rev=0)
#|        self.title("New device group" if self.is_new else f"Edit group {group['id']}")
#|        self.transient(app)
#|        self.geometry("1050x760")
#|        self.added = set()      # hostnames to move into this group by hand on save
#|        self.removed = set()    # hostnames moved in by hand earlier, to release on save
#|
#|        f = ttk.Frame(self, padding=10)
#|        f.pack(fill="both", expand=True)
#|        step = lambda n, text: ttk.Label(f, text=f"Step {n}.  {text}", font=("Segoe UI", 10, "bold")).pack(
#|            anchor="w", pady=(10, 2))
#|
#|        step(1, "Name the group")
#|        row = ttk.Frame(f)
#|        row.pack(fill="x")
#|        ttk.Label(row, text="Group ID:").pack(side="left")
#|        self.id_var = tk.StringVar(value=self.group["id"])
#|        ttk.Entry(row, textvariable=self.id_var, width=24, state="normal" if self.is_new else "disabled").pack(
#|            side="left", padx=4)
#|        ttk.Label(row, text="e.g. CAMPUS-ACCESS (letters, numbers, - and _)", foreground="#666").pack(side="left")
#|        row2 = ttk.Frame(f)
#|        row2.pack(fill="x", pady=2)
#|        ttk.Label(row2, text="Description:").pack(side="left")
#|        self.desc_var = tk.StringVar(value=self.group.get("description", ""))
#|        ttk.Entry(row2, textvariable=self.desc_var, width=80).pack(side="left", padx=4)
#|
#|        step(2, "Tick every STIG these devices must be assessed against (click a row to tick / untick)")
#|        team = app.output_format
#|        ttk.Label(f, text=f"The team writes {checklist.FORMAT_LABELS[team]} files (tab 1). A STIG with no file in that "
#|                          "format is highlighted - import that file on tab 1.", foreground="#555").pack(anchor="w")
#|        sf, self.stig_tree = make_tree(f, [("use", "Use", 45), ("stig", "STIG", 330), ("rel", "Release", 160),
#|                                           ("fmt", "Imported as", 230), ("auto", "Automated", 110)], height=6)
#|        sf.pack(fill="x")
#|        self.stig_tree.tag_configure("on", background="#d9f7d6")
#|        self.stig_tree.tag_configure("missing", foreground="#b00020")
#|        self.stig_tree.bind("<ButtonRelease-1>", lambda e: self.toggle_stig(self.stig_tree.identify_row(e.y)))
#|        self.stig_tree.bind("<space>", lambda e: self.toggle_stig(self.stig_tree.focus()))
#|        self.chosen = set(self.group["stigs"])
#|        self.render_stigs()
#|
#|        step(3, "Say which devices belong")
#|        dev = ttk.Frame(f)
#|        dev.pack(fill="both", expand=True)
#|        dev.columnconfigure(0, weight=1)
#|        dev.columnconfigure(1, weight=2)
#|        dev.rowconfigure(1, weight=1)
#|        ttk.Label(dev, text="Hostname patterns, one per line.\n* means 'anything'. Examples:\n  *-ACCESS\n  SITE-1?-AS*",
#|                  justify="left").grid(row=0, column=0, sticky="w")
#|        self.patterns = tk.Text(dev, height=6, width=30, font=MONO)
#|        self.patterns.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
#|        self.patterns.insert("1.0", "\n".join(self.group.get("patterns", [])))
#|        self.patterns.bind("<KeyRelease>", lambda e: self.update_preview())
#|        ttk.Label(dev, text="Devices that will be in this group (live preview):").grid(row=0, column=1, sticky="sw")
#|        pf, self.preview = make_tree(dev, [("host", "Hostname", 200), ("why", "Why", 300)], height=8)
#|        pf.grid(row=1, column=1, sticky="nsew")
#|        self.preview.tag_configure("hand", background="#dde9ff")
#|        self.preview.tag_configure("lost", background="#fff0c2")
#|        pb = ttk.Frame(dev)
#|        pb.grid(row=2, column=1, sticky="w", pady=4)
#|        ttk.Button(pb, text="Add a device by hand...", command=self.add_by_hand).pack(side="left")
#|        ttk.Button(pb, text="Remove hand-added device", command=self.remove_by_hand).pack(side="left", padx=6)
#|
#|        self.summary = ttk.Label(f, text="", font=("Segoe UI", 10), foreground="#1b4f8a")
#|        self.summary.pack(anchor="w", pady=(10, 0))
#|        b = ttk.Frame(f)
#|        b.pack(fill="x", pady=(8, 0))
#|        ttk.Button(b, text="Save group", command=self.save).pack(side="left")
#|        ttk.Button(b, text="Cancel", command=self.destroy).pack(side="left", padx=6)
#|        self.update_preview()
#|        self.grab_set()
#|        app.wait_window(self)
#|
#|    def current(self):
#|        g = dict(self.group)
#|        g["id"] = self.id_var.get().strip().upper().replace(" ", "-")
#|        g["description"] = self.desc_var.get().strip()
#|        g["patterns"] = [p.strip() for p in text_get(self.patterns).splitlines() if p.strip()]
#|        g["stigs"] = [s for s in list(self.app.index) + sorted(self.chosen - set(self.app.index))
#|                      if s in self.chosen]
#|        return g
#|
#|    def render_stigs(self):
#|        team = self.app.output_format
#|        self.stig_tree.delete(*self.stig_tree.get_children())
#|        for s in list(self.app.index) + sorted(self.chosen - set(self.app.index)):
#|            stig = self.app.index.get(s)
#|            on = s in self.chosen
#|            if stig:
#|                active = sum(1 for v in stig["order"] if assess.resolve_rule(self.group, self.app.rules_db, s, v))
#|                fmt = self.app.formats_text(s)
#|                if team not in stig["formats"]:
#|                    fmt += f"  - no {FORMAT_SHORT[team].split()[0]} file!"
#|                values = ("[X]" if on else "[  ]", stig["short"], stig["release"], fmt,
#|                          f"{active} of {len(stig['order'])}")
#|                tags = (("on",) if on else ()) + (("missing",) if team not in stig["formats"] else ())
#|            else:
#|                values, tags = ("[X]" if on else "[  ]", s, "-", "not imported any more", "-"), ("missing",)
#|            self.stig_tree.insert("", "end", iid=s, values=values, tags=tags)
#|
#|    def toggle_stig(self, row):
#|        if not row:
#|            return
#|        self.chosen.symmetric_difference_update({row})
#|        self.render_stigs()
#|        self.stig_tree.focus(row)
#|        self.stig_tree.selection_set(row)
#|        self.update_preview()
#|
#|    def simulated(self):
#|        """groups_db as it would be after saving, to preview membership."""
#|        g = self.current()
#|        db = copy.deepcopy(self.app.groups_db)
#|        db["groups"] = [x for x in db["groups"] if x["id"] != (self.group["id"] or g["id"])]
#|        db["groups"].append(g)
#|        db["groups"].sort(key=lambda x: x["id"])
#|        for h in self.removed:
#|            db["device_overrides"].pop(h, None)
#|        for h in self.added:
#|            db["device_overrides"][h] = g["id"]
#|        return g, db
#|
#|    def update_preview(self):
#|        g, db = self.simulated()
#|        self.preview.delete(*self.preview.get_children())
#|        n = 0
#|        for host in sorted(db["known_devices"]):
#|            gid, how = assess.assign_group(host, db)
#|            mine = any(fnmatch.fnmatch(host, p.upper()) for p in g["patterns"])
#|            if gid == g["id"]:
#|                n += 1
#|                self.preview.insert("", "end", iid=host, tags=("hand",) if how == "override" else (),
#|                                    values=(host, "added by hand" if how == "override" else f"matches {how[8:]}"))
#|            elif mine:
#|                why = f"moved by hand to {gid}" if how == "override" else f"already taken by group {gid}"
#|                self.preview.insert("", "end", iid=host, tags=("lost",), values=(host, f"NOT included: {why}"))
#|        cov = assess.coverage(g, self.app.rules_db, self.app.index)
#|        auto, total = sum(r["automated"] for r in cov), sum(r["total"] for r in cov)
#|        self.summary.configure(text=f"This group will have {len(g['stigs'])} STIG checklist(s), {n} known "
#|                                    f"device(s), and {auto} of {total} controls automated.")
#|
#|    def add_by_hand(self):
#|        g, db = self.simulated()
#|        others = sorted(h for h in db["known_devices"] if assess.assign_group(h, db)[0] != g["id"])
#|        typed = "(type a hostname that has not been imported yet)"
#|        pick = ask_choice(self, "Add device", "Which device should always be in this group?", [typed] + others)
#|        if pick == typed:
#|            pick = simpledialog.askstring("Add device", "Hostname exactly as SolarWinds shows it:", parent=self)
#|            if pick and pick.strip():
#|                store.add_known_devices({pick.strip(): ""})
#|                self.app.groups_db["known_devices"][pick.strip().upper()] = ""
#|        if pick and pick.strip():
#|            self.added.add(pick.strip().upper())
#|            self.removed.discard(pick.strip().upper())
#|            self.update_preview()
#|
#|    def remove_by_hand(self):
#|        sel = self.preview.selection()
#|        if not sel:
#|            return
#|        host = sel[0]
#|        if host in self.added:
#|            self.added.discard(host)
#|        elif self.app.groups_db["device_overrides"].get(host) == self.group["id"]:
#|            self.removed.add(host)
#|        else:
#|            return messagebox.showinfo("Remove", "That device is here because it matches a pattern. Change the "
#|                                                 "patterns, or move it to another group in the device list.",
#|                                       parent=self)
#|        self.update_preview()
#|
#|    def save(self):
#|        g = self.current()
#|        if not g["id"] or any(not (ch.isalnum() or ch in "-_") for ch in g["id"]):
#|            return messagebox.showerror("Group ID", "Use letters, numbers, - and _ only.", parent=self)
#|        if self.is_new and store.group_path(g["id"]).exists():
#|            return messagebox.showerror("Group ID", f"A group called {g['id']} already exists.", parent=self)
#|        if not g["stigs"] and not messagebox.askyesno("No STIGs", "No STIG checklists are ticked, so nothing will "
#|                                                                  "be assessed for this group. Save anyway?",
#|                                                      parent=self):
#|            return
#|        try:
#|            store.save_group(g, check=not self.is_new)
#|        except store.ConflictError as e:
#|            if not messagebox.askyesno("Changed by someone else",
#|                                       f"{e.current.get('saved_by')} saved this group at {e.current.get('saved_at')} "
#|                                       "while you were editing. Overwrite their changes with yours?", parent=self):
#|                return
#|            g["_rev"] = e.current.get("_rev", 0)
#|            store.save_group(g)
#|        for h in self.removed:
#|            store.set_override(h, None)
#|        for h in self.added:
#|            store.set_override(h, g["id"])
#|        self.destroy()
#|
#|
#|class PortRolesDialog(tk.Toplevel):
#|    """Team setting: the interface-description keywords that mark uplink / downlink / access ports."""
#|
#|    def __init__(self, app):
#|        super().__init__(app)
#|        self.app = app
#|        self.title("Port roles")
#|        self.transient(app)
#|        self.resizable(False, False)
#|        f = ttk.Frame(self, padding=12)
#|        f.pack()
#|        ttk.Label(f, justify="left", wraplength=620, text=(
#|            "Rules find uplinks, downlinks and client ports by the START of the interface description, so the "
#|            "port number does not matter. Label ports like 'description UPLINK - DIST-SW-01 Te2/0/14' or "
#|            "'description ACCESS - Room 112 jack 4'. Separate several keywords with commas. Upper / lower case "
#|            "does not matter. In a rule, use role:uplink, role:downlink, role:access or role:any.")).grid(
#|            row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
#|        self.vars = {}
#|        labels = {"uplink": "Uplinks (toward distribution / core):",
#|                  "downlink": "Downlinks (toward access switches):",
#|                  "access": "Access / client ports (untrusted):"}
#|        for r, role in enumerate(("uplink", "downlink", "access"), 1):
#|            ttk.Label(f, text=labels[role]).grid(row=r, column=0, sticky="w", pady=3)
#|            var = tk.StringVar(value=app.settings["port_roles"][role])
#|            ttk.Entry(f, textvariable=var, width=36).grid(row=r, column=1, sticky="w", padx=6)
#|            self.vars[role] = var
#|        b = ttk.Frame(f)
#|        b.grid(row=5, column=0, columnspan=2, pady=(10, 0))
#|        ttk.Button(b, text="Save", command=self.save).pack(side="left", padx=4)
#|        ttk.Button(b, text="Cancel", command=self.destroy).pack(side="left", padx=4)
#|        self.grab_set()
#|        app.wait_window(self)
#|
#|    def save(self):
#|        roles = {k: ", ".join(w.strip() for w in v.get().split(",") if w.strip()) for k, v in self.vars.items()}
#|        if not all(roles.values()):
#|            return messagebox.showerror("Port roles", "Every role needs at least one keyword.", parent=self)
#|        store.set_setting("port_roles", roles)
#|        self.app.reload()
#|        self.destroy()
#|
#|
#|class RuleChoicesDialog(tk.Toplevel):
#|    def __init__(self, app, group):
#|        super().__init__(app)
#|        self.app, self.group_id = app, group["id"]
#|        self.title(f"Rule versions for {group['id']}")
#|        self.geometry("1100x650")
#|        self.transient(app)
#|        help_label(self, "Only needed when a control has more than one rule version (e.g. 'Access' and 'Core'). "
#|                         "Double-click a control to choose the version this group uses. 'Default' follows whichever "
#|                         "version is marked default in the work queue. 'Manual' means no automated check for this "
#|                         "group.")
#|        self.only_multi = tk.BooleanVar(value=True)
#|        ttk.Checkbutton(self, text="Only show controls with more than one active version", variable=self.only_multi,
#|                        command=self.refresh).pack(anchor="w", padx=6)
#|        frame, self.tree = make_tree(self, [("stig", "STIG", 200), ("vuln", "Vuln ID", 80), ("title", "Title", 420),
#|                                            ("choice", "Group uses", 260)], height=20)
#|        frame.pack(fill="both", expand=True, padx=6, pady=6)
#|        self.tree.bind("<Double-1>", lambda e: self.choose())
#|        self.empty = ttk.Label(self, text="", foreground="#666")
#|        self.empty.pack()
#|        ttk.Button(self, text="Close", command=self.destroy).pack(pady=6)
#|        self.refresh()
#|        self.grab_set()
#|        app.wait_window(self)
#|
#|    def group(self):
#|        return store.load_json(store.group_path(self.group_id), None) or {"stigs": [], "rule_choices": {}}
#|
#|    def refresh(self):
#|        self.tree.delete(*self.tree.get_children())
#|        group = self.group()
#|        choices = group.get("rule_choices") or {}
#|        shown = 0
#|        for stig_id, control, rule in assess.group_plan(group, self.app.rules_db, self.app.index):
#|            active = [r for r in assess.rules_for_control(self.app.rules_db, stig_id, control["vuln_id"])
#|                      if r.get("state") == "active"]
#|            if self.only_multi.get() and len(active) < 2:
#|                continue
#|            key = assess.key_of(stig_id, control["vuln_id"])
#|            raw = choices.get(key)
#|            if raw == "manual":
#|                label_ = "Manual (no automated check)"
#|            elif rule:
#|                label_ = f"{rule['id']} {rule.get('name', '')}" + ("" if raw else "  (default)")
#|            else:
#|                label_ = "- no active rule -"
#|            self.tree.insert("", "end", iid=key, values=(self.app.short(stig_id), control["vuln_id"],
#|                                                         control["title"], label_))
#|            shown += 1
#|        self.empty.configure(text="" if shown else "Nothing to choose: no control in this group has more than one "
#|                                                   "active rule version.")
#|
#|    def choose(self):
#|        sel = self.tree.selection()
#|        if not sel:
#|            return
#|        stig_id, vuln_id = sel[0].split("|", 1)
#|        active = [r for r in assess.rules_for_control(self.app.rules_db, stig_id, vuln_id)
#|                  if r.get("state") == "active"]
#|        options = ["Default"] + [f"{r['id']} {r.get('name', '')}" for r in active] + ["Manual (no automated check)"]
#|        pick = ask_choice(self, "Rule version", f"Which version should {self.group_id} use for {vuln_id}?", options)
#|        if not pick:
#|            return
#|
#|        def change(g):
#|            choices = g.setdefault("rule_choices", {})
#|            if pick == "Default":
#|                choices.pop(sel[0], None)
#|            elif pick.startswith("Manual"):
#|                choices[sel[0]] = "manual"
#|            else:
#|                choices[sel[0]] = pick.split()[0]
#|        store.modify_group(self.group_id, change)
#|        self.refresh()
#|
#|
#|# ---------------------------------------------------------------- 4. collection script
#|
#|class ScriptTab(ttk.Frame):
#|    def __init__(self, nb, app):
#|        super().__init__(nb)
#|        self.app = app
#|        help_label(self, "Step 4 - Tick the groups you are collecting from and click Generate. One script covers "
#|                         "every ticked group. Paste it into SolarWinds 'Execute Command Script', run it against the "
#|                         "devices, and save the output as a text file (the input folder is a good place). Do not "
#|                         "remove the '! CMD:' lines - they tie each output block to its command.")
#|        top = ttk.Frame(self)
#|        top.pack(fill="x", padx=6)
#|        self.group_frame = ttk.LabelFrame(top, text="Groups")
#|        self.group_frame.pack(side="left", fill="y")
#|        btns = ttk.Frame(top)
#|        btns.pack(side="left", padx=10, anchor="n")
#|        ttk.Button(btns, text="Generate script", command=self.generate).pack(fill="x")
#|        ttk.Button(btns, text="Copy to clipboard", command=self.copy).pack(fill="x", pady=4)
#|        ttk.Button(btns, text="Open scripts folder", command=lambda: open_folder(store.paths.output / "scripts")).pack(
#|            fill="x")
#|        self.info = ttk.Label(top, text="", justify="left", wraplength=700)
#|        self.info.pack(side="left", padx=10, anchor="n")
#|        self.text = ScrolledText(self, font=MONO, wrap="none")
#|        self.text.pack(fill="both", expand=True, padx=6, pady=6)
#|        self.vars = {}
#|
#|    def refresh(self):
#|        old = {k: v.get() for k, v in self.vars.items()}
#|        for w in self.group_frame.winfo_children():
#|            w.destroy()
#|        self.vars = {}
#|        for g in self.app.groups_db.get("groups", []):
#|            var = tk.BooleanVar(value=old.get(g["id"], False))
#|            names = ", ".join(self.app.short(s) for s in g.get("stigs", []))
#|            ttk.Checkbutton(self.group_frame, text=f"{g['id']}  ({names})", variable=var).pack(anchor="w", padx=6)
#|            self.vars[g["id"]] = var
#|        if not self.vars:
#|            ttk.Label(self.group_frame, text="Create groups on tab 3 first.").pack(padx=6, pady=6)
#|
#|    def generate(self):
#|        groups = [g for g in self.app.groups_db.get("groups", []) if self.vars.get(g["id"], tk.BooleanVar()).get()]
#|        if not groups:
#|            return messagebox.showinfo("Script", "Tick at least one group.")
#|        sources = assess.commands_for_groups(groups, self.app.rules_db, self.app.index)
#|        if not sources:
#|            return messagebox.showinfo("Script", "These groups have no active rules yet, so there is nothing to "
#|                                                 "collect. Activate rules on the Work Queue tab.")
#|        script, sid = collect.build_script(sources, [g["id"] for g in groups])
#|        store.save_script_record({"script_id": sid, "created": store.now(), "created_by": store.current_user(),
#|                                  "groups": [g["id"] for g in groups], "commands": sorted(sources)})
#|        path = store.paths.output / "scripts" / f"collect_{'_'.join(g['id'] for g in groups)[:80]}_{sid}.txt"
#|        path.write_text(script, encoding="utf-8")
#|        text_set(self.text, script)
#|        lines = [f"{len(sources)} unique command(s). Saved to {path}"]
#|        for g in groups:
#|            lines.append(f"{g['id']}:")
#|            for r in assess.coverage(g, self.app.rules_db, self.app.index):
#|                line = (f"   {r['short']}: {r['automated']} of {r['total']} automated, {r['manual']} manual, "
#|                        f"{r['no_rule'] + r['draft']} not built yet")
#|                if r["changed"]:
#|                    line += f"  - WARNING: {r['changed']} rule(s) need review after a STIG update"
#|                lines.append(line)
#|        self.info.configure(text="\n".join(lines))
#|
#|    def copy(self):
#|        self.clipboard_clear()
#|        self.clipboard_append(text_get(self.text))
#|
#|
#|# ---------------------------------------------------------------- 5. import and review
#|
#|class AssessTab(ttk.Frame):
#|    FILTERS = ["Everything", "Needs attention (unexpected Open / Not Reviewed)", "Open", "Open (expected)",
#|               "Not Reviewed",
#|               "Not Applicable", "Not a Finding", "Manual (no rule)", "Changed by reviewer"]
#|
#|    def __init__(self, nb, app):
#|        super().__init__(nb)
#|        self.app = app
#|        help_label(self, "Step 5 - Import the SolarWinds output file. Check every device landed in the right group, "
#|                         "then review the results group by group. The tool only RECOMMENDS a result: you can change "
#|                         "any of them (a reason is required). When done, write the checklist package for the group. "
#|                         "Missing, failed or invalid evidence is never treated as a pass.")
#|        top = ttk.Frame(self)
#|        top.pack(fill="x", padx=6)
#|        ttk.Button(top, text="Import SolarWinds output...", command=self.do_import).pack(side="left")
#|        ttk.Button(top, text="Open previous run...", command=self.open_run).pack(side="left", padx=4)
#|        ttk.Button(top, text="Re-run assessment", command=self.reevaluate).pack(side="left", padx=4)
#|        self.run_label = ttk.Label(top, text="", foreground="#333")
#|        self.run_label.pack(side="left", padx=10)
#|
#|        paned = ttk.PanedWindow(self, orient="vertical")
#|        paned.pack(fill="both", expand=True, padx=6, pady=6)
#|        dev = ttk.Frame(paned)
#|        paned.add(dev, weight=1)
#|        df, self.dev_tree = make_tree(dev, [("host", "Device", 160), ("ip", "IP", 140), ("group", "Group", 150),
#|                                            ("how", "Assigned by", 130), ("state", "Collection", 260),
#|                                            ("cmds", "Commands", 100)], height=5, selectmode="extended")
#|        df.pack(fill="both", expand=True)
#|        color_tags(self.dev_tree, {"bad": "#ffd6d6", "nogroup": "#fff0c2"})
#|        db = ttk.Frame(dev)
#|        db.pack(fill="x", pady=2)
#|        ttk.Button(db, text="Change group of selected devices...", command=self.change_group).pack(side="left")
#|        self.warn_label = ttk.Label(db, text="", foreground="#9a6a00")
#|        self.warn_label.pack(side="left", padx=10)
#|
#|        rev = ttk.Frame(paned)
#|        paned.add(rev, weight=3)
#|        bar = ttk.Frame(rev)
#|        bar.pack(fill="x")
#|        ttk.Label(bar, text="Group:").pack(side="left")
#|        self.group_var = tk.StringVar()
#|        self.group_box = ttk.Combobox(bar, textvariable=self.group_var, state="readonly", width=24)
#|        self.group_box.pack(side="left", padx=4)
#|        self.group_box.bind("<<ComboboxSelected>>", lambda e: self.show_results())
#|        ttk.Label(bar, text="Show:").pack(side="left", padx=(10, 0))
#|        self.filter_var = tk.StringVar(value=self.FILTERS[0])
#|        fb = ttk.Combobox(bar, textvariable=self.filter_var, values=self.FILTERS, state="readonly", width=34)
#|        fb.pack(side="left", padx=4)
#|        fb.bind("<<ComboboxSelected>>", lambda e: self.show_results())
#|        self.count_label = ttk.Label(bar, text="")
#|        self.count_label.pack(side="left", padx=10)
#|
#|        inner = ttk.PanedWindow(rev, orient="horizontal")
#|        inner.pack(fill="both", expand=True, pady=4)
#|        rf, self.res_tree = make_tree(inner, [("fam", "STIG", 170), ("vuln", "Vuln ID", 75), ("ver", "Rule Ver", 110),
#|                                              ("rec", "Recommended", 120), ("final", "Final", 120),
#|                                              ("devs", "Devices", 110), ("title", "Title", 200)],
#|                                      height=14, selectmode="extended")
#|        color_tags(self.res_tree, STATUS_ROW)
#|        inner.add(rf, weight=3)
#|        self.res_tree.bind("<<TreeviewSelect>>", lambda e: self.show_detail())
#|        side = ttk.Frame(inner)
#|        inner.add(side, weight=2)
#|        self.detail = ScrolledText(side, height=14, wrap="none", font=("Consolas", 9))
#|        self.detail.pack(fill="both", expand=True)
#|        act = ttk.Frame(side)
#|        act.pack(fill="x", pady=4)
#|        ttk.Label(act, text="Final result:").grid(row=0, column=0, sticky="w")
#|        self.final_var = tk.StringVar()
#|        ttk.Combobox(act, textvariable=self.final_var, state="readonly", width=18,
#|                     values=[STATUS_LABELS[s] for s in STATUSES] + ["Manual (unchanged)"]).grid(row=0, column=1,
#|                                                                                            sticky="w")
#|        ttk.Label(act, text="Reviewer comment:").grid(row=1, column=0, sticky="nw")
#|        self.comment = tk.Text(act, height=3, width=48, wrap="word", font=("Segoe UI", 9))
#|        self.comment.grid(row=1, column=1, sticky="we")
#|        ab = ttk.Frame(act)
#|        ab.grid(row=2, column=1, sticky="w", pady=4)
#|        ttk.Button(ab, text="Apply to selected", command=self.apply).pack(side="left")
#|        ttk.Button(ab, text="Reset to recommendation", command=self.reset).pack(side="left", padx=4)
#|
#|        bottom = ttk.Frame(self)
#|        bottom.pack(fill="x", padx=6, pady=(0, 6))
#|        ttk.Label(bottom, text="Reviewer name:").pack(side="left")
#|        self.reviewer = tk.StringVar(value=store.current_user())
#|        ttk.Entry(bottom, textvariable=self.reviewer, width=24).pack(side="left", padx=4)
#|        ttk.Button(bottom, text="Write checklist package for this group",
#|                   command=lambda: self.write(all_groups=False)).pack(side="left", padx=8)
#|        ttk.Button(bottom, text="Write packages for all groups",
#|                   command=lambda: self.write(all_groups=True)).pack(side="left")
#|        ttk.Button(bottom, text="Open output folder", command=lambda: open_folder(store.paths.output)).pack(
#|            side="left", padx=8)
#|        self.fmt_label = ttk.Label(bottom, text="", foreground="#1b4f8a")
#|        self.fmt_label.pack(side="left", padx=10)
#|
#|    # -- data
#|    def refresh(self):
#|        run = self.app.run
#|        self.fmt_label.configure(text=f"Writes {checklist.FORMAT_LABELS[self.app.output_format]} files "
#|                                      "(team setting on tab 1)")
#|        self.dev_tree.delete(*self.dev_tree.get_children())
#|        if not run:
#|            self.run_label.configure(text="No run loaded. Import a SolarWinds output file to start.")
#|            self.group_box["values"] = []
#|            self.show_results()
#|            return
#|        self.run_label.configure(text=f"Run {run['id']} - {run['source_name']} - {len(run['devices'])} devices"
#|                                      + (f" - assessed {run['evaluated']}" if run.get("evaluated") else ""))
#|        for d in run["devices"]:
#|            m = run["membership"].get(d["host"], {"group": "", "how": "unassigned"})
#|            if d["status"] != "ok":
#|                state, tag = f"FAILED: {d['error']}", "bad"
#|            else:
#|                bad = [c for c, o in d["outputs"].items() if o["status"] != "ok"]
#|                state = "OK" + (f", {len(bad)} invalid command(s)" if bad else "")
#|                tag = "bad" if bad else ("nogroup" if not m["group"] else "")
#|            self.dev_tree.insert("", "end", iid=d["host"], tags=(tag,),
#|                                 values=(d["host"], d["ip"], m["group"] or "(none - not assessed)", m["how"], state,
#|                                         f"{len(d['outputs'])} collected"))
#|        self.warn_label.configure(text="; ".join(run.get("warnings", []))[:200])
#|        groups = sorted(run.get("results", {}))
#|        self.group_box["values"] = groups
#|        if self.group_var.get() not in groups:
#|            self.group_var.set(groups[0] if groups else "")
#|        self.show_results()
#|
#|    def results(self):
#|        if not self.app.run:
#|            return None
#|        return self.app.run.get("results", {}).get(self.group_var.get())
#|
#|    def show_results(self):
#|        keep = self.res_tree.selection()
#|        self.res_tree.delete(*self.res_tree.get_children())
#|        res = self.results()
#|        if not res:
#|            self.count_label.configure(text="")
#|            self.show_detail()
#|            return
#|        f = self.filter_var.get()
#|        counts = {}
#|        for key, c in res["controls"].items():
#|            final = c["final"]
#|            shown_as = assess.result_label(c)
#|            counts[shown_as] = counts.get(shown_as, 0) + 1
#|            if f.startswith("Needs") and (final not in ("open", "not_reviewed") or assess.is_expected_open(c)):
#|                continue
#|            if (f in STATUS_LABELS.values() or f == "Open (expected)") and shown_as != f:
#|                continue
#|            if f.startswith("Manual") and c["rule_id"]:
#|                continue
#|            if f.startswith("Changed") and not c["reviewer_changed"]:
#|                continue
#|            per = {}
#|            for r in c["per_device"].values():
#|                per[r["status"]] = per.get(r["status"], 0) + 1
#|            devs = ", ".join(f"{n} {SHORT[s]}" for s, n in sorted(per.items())) or "-"
#|            tag = "changed" if c["reviewer_changed"] else (
#|                "expected" if assess.is_expected_open(c) else (final or "manual"))
#|            self.res_tree.insert("", "end", iid=key, tags=(tag,),
#|                                 values=(c["family"], c["vuln_id"], c["rule_ver"],
#|                                         assess.result_label(c, "recommended"), shown_as, devs, c["title"]))
#|        self.count_label.configure(text="   ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
#|        keep = [k for k in keep if self.res_tree.exists(k)]
#|        if keep:
#|            self.res_tree.selection_set(keep)
#|        self.show_detail()
#|
#|    def selected(self):
#|        res = self.results()
#|        return [res["controls"][k] for k in self.res_tree.selection()] if res else []
#|
#|    def show_detail(self):
#|        sel = self.selected()
#|        if not sel:
#|            text_set(self.detail, "", readonly=True)
#|            return
#|        c = sel[0]
#|        lines = [f"{c['family']} {c['vuln_id']} {c['rule_ver']} [{c['severity']}]", c["title"], ""]
#|        if c["rule_id"]:
#|            prefix = assess.outcome_prefix(c)
#|            if assess.is_expected_open(c):
#|                lines += ["EXPECTED FINDING: the rule marks Open as intentional for this control.", ""]
#|            field = assess.FIELD_LABELS[self.app.settings["text_placement"].get(c["final"] or "", "comments")]
#|            lines += [f"For {assess.label(c['final'])} this reason is written to the checklist's {field.upper()}:",
#|                      ""]
#|            if prefix:
#|                lines += [prefix, ""]
#|            lines.append(c["details"])
#|        else:
#|            lines.append("No rule for this control in this group (manual). The checklist keeps the template's "
#|                         f"current value ({STATUS_LABELS.get(c.get('template_status'), '?')}) unless you set a "
#|                         "final result here.")
#|        if c["reviewer_changed"] or c.get("reviewer_comment"):
#|            lines += ["", f"Reviewer: final {assess.label(c['final'])} - {c.get('reviewer_comment', '')}"]
#|        text_set(self.detail, "\n".join(lines), readonly=True)
#|        self.final_var.set(assess.label(c["final"]))
#|        text_set(self.comment, c.get("reviewer_comment", ""))
#|
#|    # -- actions
#|    def do_import(self):
#|        path = filedialog.askopenfilename(title="Choose SolarWinds output file", initialdir=str(store.paths.input),
#|                                          filetypes=[("Text files", "*.txt *.log"), ("All files", "*.*")])
#|        if not path:
#|            return
#|        run = assess.import_solarwinds(path, self.app.groups_db, self.app.rules_db)
#|        store.add_known_devices({d["host"]: d["ip"] for d in run["devices"]})
#|        assess.evaluate_run(run, self.app.groups_db, self.app.rules_db, self.app.index)
#|        self.app.set_run(run)
#|        self.app.save_run()
#|        self.refresh()
#|        bad = [d["host"] for d in run["devices"] if d["status"] != "ok"]
#|        nogroup = [h for h, m in run["membership"].items() if not m["group"]]
#|        msg = [f"{len(run['devices'])} device(s) imported."]
#|        if bad:
#|            msg.append(f"Collection failed for: {', '.join(bad)}")
#|        if nogroup:
#|            msg.append(f"Not in any group (not assessed): {', '.join(nogroup)}")
#|        msg += run.get("warnings", [])
#|        messagebox.showinfo("Import", "\n".join(msg))
#|
#|    def open_run(self):
#|        runs = store.list_runs()
#|        if not runs:
#|            return messagebox.showinfo("Runs", "No previous runs.")
#|        loaded = [(p, store.load_run(p)) for p in runs[:50]]
#|        labels = [f"{r['id']}  {r['source_name']}  ({len(r['devices'])} devices, by {r.get('created_by', '?')}"
#|                  f"{', last saved by ' + r['saved_by'] if r.get('saved_by') else ''})" for _, r in loaded]
#|        pick = ask_choice(self, "Open run", "Open which assessment run?", labels)
#|        if pick:
#|            path, run = loaded[labels.index(pick)]
#|            self.app.set_run(run, path.stat().st_mtime)
#|            self.refresh()
#|
#|    def reevaluate(self):
#|        run = self.app.run
#|        if not run:
#|            return
#|        for host, m in run["membership"].items():
#|            gid, how = assess.assign_group(host, self.app.groups_db)
#|            m.update(group=gid, how=how)
#|        assess.evaluate_run(run, self.app.groups_db, self.app.rules_db, self.app.index)
#|        self.app.save_run()
#|        self.refresh()
#|
#|    def change_group(self):
#|        run = self.app.run
#|        hosts = self.dev_tree.selection()
#|        ids = [g["id"] for g in self.app.groups_db.get("groups", [])]
#|        if not run or not hosts or not ids:
#|            return
#|        gid = ask_choice(self, "Change group", f"Put {len(hosts)} device(s) in which group? "
#|                                               "(saved as an override for future runs too)", ids)
#|        if not gid:
#|            return
#|        for h in hosts:
#|            store.set_override(h, gid)
#|        self.app.load_data()
#|        self.reevaluate()
#|
#|    def apply(self):
#|        sel = self.selected()
#|        if not sel:
#|            return
#|        label = self.final_var.get()
#|        final = None if label.startswith("Manual") else LABEL_TO_STATUS[label]
#|        comment = text_get(self.comment).strip()
#|        for c in sel:
#|            if final is None and c["rule_id"]:
#|                return messagebox.showerror("Not allowed", f"{c['vuln_id']} has a rule; choose a result.")
#|        if any(final != c["recommended"] for c in sel) and not comment:
#|            return messagebox.showerror("Reason needed", "You are changing the recommended result. "
#|                                                         "Type a reviewer comment explaining why.")
#|        for c in sel:
#|            c["final"] = final
#|            c["reviewer_comment"] = comment
#|            c["reviewer_changed"] = final != c["recommended"]
#|        self.app.save_run()
#|        self.show_results()
#|
#|    def reset(self):
#|        for c in self.selected():
#|            c.update(final=c["recommended"], reviewer_comment="", reviewer_changed=False)
#|        self.app.save_run()
#|        self.show_results()
#|
#|    def write(self, all_groups):
#|        run = self.app.run
#|        if not run or not run.get("results"):
#|            return messagebox.showinfo("Write", "Nothing to write - import and assess a SolarWinds output first.")
#|        reviewer = self.reviewer.get().strip()
#|        if not reviewer:
#|            return messagebox.showerror("Reviewer", "Enter the reviewer name.")
#|        groups = sorted(run["results"]) if all_groups else [self.group_var.get()]
#|        fmt = self.app.output_format
#|        summary = [f"Format: {checklist.FORMAT_LABELS[fmt]}", ""]
#|        for gid in groups:
#|            summary.append(f"{gid}:")
#|            per = {}
#|            for c in run["results"][gid]["controls"].values():
#|                per.setdefault(c["family"], {}).setdefault(assess.label(c["final"]), 0)
#|                per[c["family"]][assess.label(c["final"])] += 1
#|            cov = {r["short"]: r for r in run.get("coverage", {}).get(gid, [])}
#|            group = assess.find_group(self.app.groups_db, gid) or {"stigs": []}
#|            for stig_id in group["stigs"]:
#|                name = self.app.short(stig_id)
#|                r = cov.get(name)
#|                head = f"   {name}: {r['automated']}/{r['total']} automated" if r else f"   {name}:"
#|                if fmt not in store.templates_for(stig_id):
#|                    head += f"  - NO {checklist.FORMAT_LABELS[fmt]} FILE, will be skipped"
#|                summary.append(head)
#|                summary.append("      " + ", ".join(f"{v} {k}" for k, v in sorted(per.get(name, {}).items())))
#|        if not messagebox.askyesno("Confirm", "Write checklist package(s)?\n\n" + "\n".join(summary) +
#|                                   f"\n\nBy continuing, {reviewer} confirms these results were reviewed."):
#|            return
#|        report, last = [], None
#|        for gid in groups:
#|            folder, ok, msgs = assess.write_package(run, gid, reviewer, self.app.groups_db, self.app.rules_db, fmt,
#|                                                    self.app.settings["text_placement"])
#|            report += msgs + [""]
#|            last = folder
#|        self.app.save_run()
#|        if messagebox.askyesno("Done", "\n".join(report) + "\nOpen the output folder?"):
#|            open_folder(last if len(groups) == 1 else store.paths.output)
#|
#|
#|# ---------------------------------------------------------------- 6. hardening script
#|
#|class HardenTab(ttk.Frame):
#|    def __init__(self, nb, app):
#|        super().__init__(nb)
#|        self.app = app
#|        help_label(self, "Step 6 (optional) - Build configuration scripts that FIX findings, from each rule's Fix "
#|                         "commands. Two scripts are always written separately: LOW IMPACT (banners, logging, "
#|                         "archive, timestamps, legacy services) and IMPACTFUL (AAA, SSH, vty access, ports, STP, "
#|                         "SNMP, routing). Review every line, fill in the <VALUES> listed at the top of each script, "
#|                         "and test on one device before pushing with SolarWinds.")
#|        top = ttk.Frame(self)
#|        top.pack(fill="x", padx=6)
#|        ttk.Label(top, text="Group:").grid(row=0, column=0, sticky="w")
#|        self.group_var = tk.StringVar()
#|        self.group_box = ttk.Combobox(top, textvariable=self.group_var, state="readonly", width=28)
#|        self.group_box.grid(row=0, column=1, sticky="w", padx=4)
#|        self.mode = tk.StringVar(value="run")
#|        ttk.Radiobutton(top, text="From the current assessment run: one script pair per device, only the controls "
#|                                  "that are Open on that device (interfaces filled in automatically)",
#|                        variable=self.mode, value="run").grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 0))
#|        ttk.Radiobutton(top, text="Baseline for the whole group: every control that has fix commands "
#|                                  "(interfaces left as <INTERFACE> to fill in)",
#|                        variable=self.mode, value="baseline").grid(row=2, column=0, columnspan=3, sticky="w")
#|        self.drafts_var = tk.BooleanVar(value=True)
#|        ttk.Checkbutton(top, text="Baseline: also use DRAFT rules that are not active yet",
#|                        variable=self.drafts_var).grid(row=3, column=0, columnspan=3, sticky="w", padx=(20, 0))
#|        b = ttk.Frame(top)
#|        b.grid(row=4, column=0, columnspan=3, sticky="w", pady=6)
#|        ttk.Button(b, text="Generate scripts", command=self.generate).pack(side="left")
#|        ttk.Button(b, text="Open hardening folder",
#|                   command=lambda: open_folder(store.paths.output / "hardening")).pack(side="left", padx=6)
#|        self.info = ttk.Label(self, text="", justify="left", foreground="#1b4f8a")
#|        self.info.pack(fill="x", padx=8)
#|        pane = ttk.PanedWindow(self, orient="horizontal")
#|        pane.pack(fill="both", expand=True, padx=6, pady=6)
#|        lf, self.files = make_tree(pane, [("file", "Script", 320), ("n", "Controls", 70)], height=12)
#|        pane.add(lf, weight=1)
#|        self.files.bind("<<TreeviewSelect>>", lambda e: self.preview_selected())
#|        self.preview = ScrolledText(pane, font=MONO, wrap="none")
#|        pane.add(self.preview, weight=3)
#|        self.paths = {}
#|
#|    def refresh(self):
#|        ids = [g["id"] for g in self.app.groups_db.get("groups", [])]
#|        self.group_box["values"] = ids
#|        if self.group_var.get() not in ids:
#|            self.group_var.set(ids[0] if ids else "")
#|
#|    def generate(self):
#|        gid = self.group_var.get()
#|        group = assess.find_group(self.app.groups_db, gid)
#|        if not group:
#|            return messagebox.showinfo("Hardening", "Create a device group on tab 3 first.")
#|        if self.mode.get() == "run":
#|            run = self.app.run
#|            if not run or gid not in run.get("results", {}):
#|                return messagebox.showinfo("Hardening", f"The current assessment run has no results for {gid}. "
#|                                                        "Import and assess on tab 5, or choose Baseline.")
#|            folder, written = harden.generate_from_run(run, gid, self.app.rules_db)
#|        else:
#|            folder, written = harden.generate_baseline(group, self.app.rules_db, self.app.index,
#|                                                       include_drafts=self.drafts_var.get())
#|        self.files.delete(*self.files.get_children())
#|        self.paths = {}
#|        for path, n in written:
#|            iid = str(path)
#|            self.paths[iid] = path
#|            self.files.insert("", "end", iid=iid, values=(path.name, n))
#|        if not written:
#|            self.info.configure(text=f"Nothing to fix: no Open controls with fix commands ({folder}).")
#|            text_set(self.preview, "", readonly=True)
#|            return
#|        self.info.configure(text=f"{len(written)} script(s) written to {folder}")
#|        self.files.selection_set(self.files.get_children()[0])
#|
#|    def preview_selected(self):
#|        sel = self.files.selection()
#|        if sel:
#|            text_set(self.preview, self.paths[sel[0]].read_text(encoding="utf-8"), readonly=True)
#@ END
#@ FILE src/harden.py SHA f20c86d706178bc610dbf0790b05e3ba1b881180c9b693d6910b96e43684284f CHUNK 1 OF 1
#|"""Hardening scripts: fix commands per rule, and the scripts generated from them.
#|
#|Every rule can carry two blocks of fix commands (rule["fix"] = {"low": text, "high": text}):
#|  low   - low impact: banners, logging, archive, timestamps, disabling legacy services...
#|  high  - impactful: AAA, SSH algorithms, vty access, port / STP / 802.1x settings, SNMP, routing...
#|Scripts are always written as two separate files so the low-impact one can be pushed on its own.
#|
#|Inside fix commands:
#|  <SOMETHING>              a site value to fill in; the script lists every one at the top as EDIT BEFORE USE
#|  {each failing section}   on its own line, followed by indented commands: repeat those commands under every
#|                           section (usually an interface) that failed on the device. Without assessment results
#|                           a placeholder header is written instead.
#|  {each failing section of condition 2}
#|                           the same, but only for sections that failed condition 2 of the rule (numbered as in the
#|                           rule editor). Lets one rule add a command where it is missing (e.g. trust on uplinks)
#|                           and remove it where it must not be (e.g. trust on access ports).
#|  ! text                   a comment, copied into the script
#|"""
#|import re
#|
#|import assess
#|import store
#|
#|EACH = "{each failing section}"
#|EACH_RE = re.compile(r"^\{each failing section(?: of condition (\d+))?\}$", re.I)
#|PLACEHOLDER_RE = re.compile(r"<[A-Z0-9_ /.-]+>")
#|IMPACT = {"low": "LOW IMPACT", "high": "IMPACTFUL"}
#|HEADER_WARNING = {
#|    "low": ["! Low-impact changes (banners, logging, archive, timestamps, legacy services).",
#|            "! Still review before use and test on one device first."],
#|    "high": ["! *** IMPACTFUL CHANGES - these can disconnect management sessions, lock out accounts or change how",
#|             "! *** traffic is forwarded. Apply in a maintenance window, on ONE device first, with console or",
#|             "! *** out-of-band access available. Review every line."],
#|}
#|
#|DOD_BANNER = """You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
#|By using this IS (which includes any device attached to this IS), you consent to the following conditions:
#|-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
#|-At any time, the USG may inspect and seize data stored on this IS.
#|-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
#|-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
#|-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."""
#|
#|
#|def F(low=(), high=()):
#|    return {"low": "\n".join(low), "high": "\n".join(high)}
#|
#|
#|def each(*cmds):
#|    return [EACH] + [f" {c}" for c in cmds]
#|
#|
#|# ---------------------------------------------------------------- IOS-XE fix commands (Catalyst 9300 / 8300)
#|
#|ARCHIVE = ["archive", " log config", "  logging enable", "  logging size 1000"]
#|IOS_LEGACY = ["no service pad", "no service finger", "no service tcp-small-servers", "no service udp-small-servers",
#|              "no ip finger", "no ip identd", "no ip bootp server", "no ip dns server", "no ip rcmd rcp-enable",
#|              "no ip rcmd rsh-enable", "no service config", "no ip boot server"]
#|ACL_LOG = each("! add 'log-input' to every deny statement in this ACL, e.g. <SEQ> deny ip any any log-input")
#|
#|FIX_IOSXE = {
#|    "CISC-ND-000010": F(low=["ip http max-connections 2"], high=["line vty 0 4", " session-limit 2"]),
#|    **{k: F(low=ARCHIVE) for k in ("CISC-ND-000090", "CISC-ND-000100", "CISC-ND-000110", "CISC-ND-000120",
#|                                   "CISC-ND-000330", "CISC-ND-000880", "CISC-ND-001250", "CISC-ND-001270")},
#|    "CISC-ND-000140": F(high=["ip access-list extended MGMT_NET", " permit ip <MGMT_SUBNET> <MGMT_WILDCARD> any",
#|                              " deny ip any any log-input", "line vty 0 4", " access-class MGMT_NET in"]),
#|    "CISC-ND-000150": F(high=["login block-for 900 attempts 3 within 120"]),
#|    "CISC-ND-000160": F(low=["banner login ^C"] + DOD_BANNER.splitlines() + ["^C"]),
#|    "CISC-ND-000210": F(low=["logging userinfo"] + ARCHIVE),
#|    "CISC-ND-000280": F(low=["service timestamps log datetime msec localtime show-timezone"]),
#|    "CISC-ND-000290": F(high=ACL_LOG),
#|    **{k: F(low=["file privilege 15"]) for k in ("CISC-ND-000380", "CISC-ND-000390", "CISC-ND-000460")},
#|    "CISC-ND-000470": F(low=IOS_LEGACY, high=["no ip http server", "no service call-home"]),
#|    "CISC-ND-000490": F(high=["! remove every local account except the account of last resort:",
#|                              "! no username <EXTRA_ACCOUNT>",
#|                              "aaa authentication login default group <AAA_GROUP> local"]),
#|    "CISC-ND-000550": F(low=["aaa common-criteria policy PASSWORD_POLICY", " min-length 15"]),
#|    "CISC-ND-000570": F(low=["aaa common-criteria policy PASSWORD_POLICY", " upper-case 1"]),
#|    "CISC-ND-000580": F(low=["aaa common-criteria policy PASSWORD_POLICY", " lower-case 1"]),
#|    "CISC-ND-000590": F(low=["aaa common-criteria policy PASSWORD_POLICY", " numeric-count 1"]),
#|    "CISC-ND-000600": F(low=["aaa common-criteria policy PASSWORD_POLICY", " special-case 1"]),
#|    "CISC-ND-000610": F(low=["aaa common-criteria policy PASSWORD_POLICY", " char-changes 8"]),
#|    "CISC-ND-000620": F(low=["service password-encryption"],
#|                        high=["no enable password", "enable algorithm-type scrypt secret <ENABLE_SECRET>"]),
#|    "CISC-ND-000720": F(low=["line con 0", " exec-timeout 5 0", "line vty 0 4", " exec-timeout 5 0",
#|                             "ip http timeout-policy idle 300 life 86400 requests 10000"]),
#|    "CISC-ND-000980": F(low=["logging buffered 64000 informational"]),
#|    "CISC-ND-001000": F(low=["logging trap critical"]),
#|    "CISC-ND-001030": F(low=["ntp server <NTP_SERVER_1>", "ntp server <NTP_SERVER_2>"]),
#|    "CISC-ND-001130": F(high=["snmp-server group <SNMP_GROUP> v3 priv read <SNMP_VIEW>",
#|                              "snmp-server user <SNMP_USER> <SNMP_GROUP> v3 auth sha <AUTH_PASSWORD> priv aes 256 "
#|                              "<PRIV_PASSWORD>", "no snmp-server community <OLD_COMMUNITY>"]),
#|    "CISC-ND-001140": F(high=["snmp-server group <SNMP_GROUP> v3 priv read <SNMP_VIEW>",
#|                              "snmp-server user <SNMP_USER> <SNMP_GROUP> v3 auth sha <AUTH_PASSWORD> priv aes 256 "
#|                              "<PRIV_PASSWORD>"]),
#|    "CISC-ND-001150": F(high=["ntp authentication-key 1 hmac-sha2-256 <NTP_KEY>", "ntp authenticate",
#|                              "ntp trusted-key 1", "ntp server <NTP_SERVER_1> key 1", "ntp server <NTP_SERVER_2> key 1"]),
#|    "CISC-ND-001200": F(high=["ip ssh version 2", "ip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256"]),
#|    "CISC-ND-001210": F(high=["ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr"]),
#|    "CISC-ND-001260": F(low=["login on-failure log", "login on-success log"]),
#|    "CISC-ND-001370": F(high=["tacacs server <AAA_SERVER_1>", " address ipv4 <AAA_IP_1>", " key <AAA_KEY>",
#|                              "tacacs server <AAA_SERVER_2>", " address ipv4 <AAA_IP_2>", " key <AAA_KEY>",
#|                              "aaa group server tacacs+ <AAA_GROUP>", " server name <AAA_SERVER_1>",
#|                              " server name <AAA_SERVER_2>", "aaa authentication login default group <AAA_GROUP> local"]),
#|    "CISC-ND-001410": F(low=["file prompt quiet", "event manager applet BACKUP_CONFIG authorization bypass",
#|                             " event syslog pattern \"%SYS-5-CONFIG_I\"", " action 1 cli command \"enable\"",
#|                             " action 2 info type routername",
#|                             " action 3 cli command \"copy running-config scp://<SCP_USER>@<SCP_SERVER>/<SCP_PATH>/"
#|                             "$_info_routername-running-config\""]),
#|    "CISC-ND-001440": F(high=["! enroll with a DoD / DoD-approved CA and remove self-signed trustpoints:",
#|                              "crypto pki trustpoint <DOD_CA_TRUSTPOINT>", " enrollment url <CA_ENROLLMENT_URL>",
#|                              " revocation-check crl", "! no crypto pki trustpoint <SELF_SIGNED_TRUSTPOINT>"]),
#|    "CISC-ND-001450": F(low=["logging host <SYSLOG_SERVER_1>", "logging host <SYSLOG_SERVER_2>"]),
#|    "CISC-ND-001470": F(high=["! upgrade the device to a Cisco-supported IOS-XE release (not a config change)"]),
#|    "CISC-RT-000050": F(high=["key chain <KEY_CHAIN>", " key 1", "  key-string <ROUTING_KEY>",
#|                              "  cryptographic-algorithm hmac-sha-256",
#|                              "  send-lifetime 00:00:00 <START_DATE> duration 180",
#|                              "  accept-lifetime 00:00:00 <START_DATE> duration 180",
#|                              "interface <ROUTING_INTERFACE>", " ip ospf authentication key-chain <KEY_CHAIN>"]),
#|    "CISC-RT-000060": F(high=["! shut down routed interfaces that are not in use:",
#|                              "interface <UNUSED_INTERFACE>", " shutdown"]),
#|    "CISC-RT-000090": F(low=["no service config", "! also remove any 'boot network' and 'cns' lines"]),
#|    "CISC-RT-000120": F(high=["! Catalyst 9300: keep the built-in 'policy-map system-cpp-policy' and tune rates;",
#|                              "! Catalyst 8300: build a CoPP policy-map and apply it:",
#|                              "control-plane", " service-policy input <COPP_POLICY>"]),
#|    "CISC-RT-000150": F(high=["no ip gratuitous-arps"]),
#|    "CISC-RT-000160": F(low=each("no ip directed-broadcast")),
#|    "CISC-RT-000170": F(low=each("no ip unreachables")),
#|    "CISC-RT-000180": F(low=each("no ip mask-reply")),
#|    "CISC-RT-000190": F(low=each("no ip redirects")),
#|    "CISC-RT-000200": F(high=each("! add 'log' or 'log-input' to every deny statement in this ACL")),
#|    "CISC-RT-000210": F(high=ACL_LOG),
#|    "CISC-RT-000220": F(high=ACL_LOG),
#|    "CISC-RT-000230": F(low=["line aux 0", " no exec", " transport input none"]),
#|    "CISC-RT-000235": F(low=["ip cef", "ipv6 cef"]),
#|    "CISC-RT-000236": F(low=["ipv6 hop-limit 64"]),
#|    "CISC-RT-000237": F(high=["! replace any FEC0::/10 (site-local) IPv6 addresses with global or ULA addresses"]),
#|    "CISC-RT-000360": F(high=["no lldp run"]),
#|    "CISC-RT-000370": F(high=["no cdp run", "! (IP phones use CDP for the voice VLAN - use per-interface "
#|                                            "'no cdp enable' on external interfaces instead if needed)"]),
#|    "CISC-RT-000380": F(high=each("no ip proxy-arp")),
#|    "CISC-RT-000470": F(high=["router bgp <ASN>", " neighbor <EBGP_PEER> ttl-security hops 1"]),
#|    "CISC-RT-000490": F(high=["! build the Bogon prefix list (see check text) and apply it inbound to every eBGP peer:",
#|                              "router bgp <ASN>", " neighbor <EBGP_PEER> prefix-list <BOGON_PREFIX_LIST> in"]),
#|    "CISC-RT-000500": F(high=["ip prefix-list <INBOUND_FILTER> seq <SEQ> deny <LOCAL_AS_PREFIX> le 32",
#|                              "router bgp <ASN>", " neighbor <EBGP_PEER> prefix-list <INBOUND_FILTER> in"]),
#|    "CISC-RT-000510": F(high=["router bgp <ASN>", " neighbor <CE_PEER> prefix-list <CUSTOMER_PREFIX_LIST> in"]),
#|    "CISC-RT-000520": F(high=["router bgp <ASN>", " neighbor <CE_PEER> prefix-list <ADVERTISE_PREFIX_LIST> out"]),
#|    "CISC-RT-000530": F(high=["router bgp <ASN>", " neighbor <EBGP_PEER> prefix-list <FILTER_CORE_PREFIXES> out"]),
#|    "CISC-RT-000540": F(high=["router bgp <ASN>", " bgp enforce-first-as"]),
#|    "CISC-RT-000550": F(high=["ip as-path access-list <AS_PATH_ACL> permit ^<CUSTOMER_AS>$",
#|                              "router bgp <ASN>", " neighbor <CE_PEER> filter-list <AS_PATH_ACL> in"]),
#|    "CISC-RT-000560": F(high=["router bgp <ASN>", " neighbor <EBGP_PEER> maximum-prefix <MAX_PREFIXES>"]),
#|    "CISC-RT-000570": F(high=["ip prefix-list FILTER_PREFIX_LENGTH seq 5 permit 0.0.0.0/0 ge 8 le 24",
#|                              "ip prefix-list FILTER_PREFIX_LENGTH seq 10 deny 0.0.0.0/0 le 32",
#|                              "router bgp <ASN>", " neighbor <EBGP_PEER> prefix-list FILTER_PREFIX_LENGTH in"]),
#|    "CISC-RT-000580": F(high=["router bgp <ASN>", " neighbor <IBGP_PEER> update-source Loopback0"]),
#|    "CISC-RT-000590": F(high=["mpls ldp router-id Loopback0 force"]),
#|    "CISC-RT-000600": F(high=["router ospf <OSPF_PROCESS>", " mpls ldp sync"]),
#|    "CISC-RT-000610": F(high=["ip rsvp signalling rate-limit period 30 burst 9 maxsize 2100 limit 50"]),
#|    "CISC-RT-000620": F(high=["no mpls ip propagate-ttl"]),
#|    "CISC-RT-000690": F(high=["! remove 'no-split-horizon' from VFI neighbor statements (mesh VPLS only)"]),
#|    "CISC-RT-000700": F(high=each("storm-control broadcast cir <STORM_CIR>")),
#|    "CISC-RT-000710": F(low=["ip igmp snooping"]),
#|    "CISC-RT-000720": F(high=["bridge-domain <BRIDGE_DOMAIN>", " mac limit maximum addresses <MAX_MACS>"]),
#|    "CISC-RT-000750": F(high=["ip options drop"]),
#|    "CISC-RT-000760": F(high=["! build the QoS class-maps / policy-map per the GIG QoS profile, then on each interface:",
#|                              "interface <INTERFACE>", " service-policy output <QOS_POLICY>"]),
#|    "CISC-RT-000770": F(high=["! build the QoS class-maps / policy-map per the GIG QoS profile, then on each interface:",
#|                              "interface <INTERFACE>", " service-policy output <QOS_POLICY>"]),
#|    "CISC-RT-000780": F(high=["class-map match-all SCAVENGER", " match ip dscp cs1", "policy-map <QOS_POLICY>",
#|                              " class SCAVENGER", "  bandwidth percent 5"]),
#|    "CISC-RT-000800": F(high=each("ip pim neighbor-filter <PIM_NEIGHBOR_ACL>")),
#|    "CISC-RT-000810": F(high=["interface <EDGE_INTERFACE>", " ip multicast boundary <MULTICAST_SCOPE_ACL>"]),
#|    "CISC-RT-000820": F(high=["ip pim accept-register list <PIM_REGISTER_ACL>", "ip pim register-rate-limit <RATE>"]),
#|    "CISC-RT-000830": F(high=["ip pim accept-register list <PIM_REGISTER_ACL>"]),
#|    "CISC-RT-000840": F(high=["ip pim accept-rp <RP_ADDRESS> <PIM_JOIN_ACL>"]),
#|    "CISC-RT-000850": F(high=["ip pim register-rate-limit <RATE>"]),
#|    "CISC-RT-000860": F(high=each("ip igmp access-group <IGMP_JOIN_ACL>")),
#|    "CISC-RT-000870": F(high=each("ip igmp access-group <IGMP_JOIN_ACL>")),
#|    "CISC-RT-000880": F(high=["ip igmp limit <IGMP_LIMIT>"]),
#|    "CISC-RT-000890": F(high=["ip pim spt-threshold infinity"]),
#|    "CISC-RT-000910": F(high=["ip msdp password peer <MSDP_PEER> <MSDP_KEY>"]),
#|    "CISC-RT-000920": F(high=["ip msdp sa-filter in <MSDP_PEER> list <INBOUND_SA_ACL>"]),
#|    "CISC-RT-000930": F(high=["ip msdp sa-filter out <MSDP_PEER> list <OUTBOUND_SA_ACL>"]),
#|    "CISC-RT-000940": F(high=["ip msdp sa-limit <MSDP_PEER> <SA_LIMIT>"]),
#|    "CISC-RT-000950": F(high=["ip msdp peer <MSDP_PEER> connect-source Loopback0"]),
#|    # ---- L2S (Catalyst 9300)
#|    "CISC-L2-000020": F(high=["dot1x system-auth-control", "{each failing section of condition 1}",
#|                              " authentication port-control auto", " dot1x pae authenticator", " mab"]),
#|    "CISC-L2-000030": F(high=["vtp mode off"]),
#|    "CISC-L2-000040": F(high=["! build the QoS policy per the site QoS design, then on each port:",
#|                              "interface <INTERFACE>", " service-policy output <QOS_POLICY>"]),
#|    "CISC-L2-000090": F(high=each("spanning-tree guard root")),
#|    "CISC-L2-000100": F(high=["spanning-tree portfast edge bpduguard default"]),
#|    "CISC-L2-000110": F(high=["spanning-tree loopguard default"]),
#|    "CISC-L2-000120": F(high=each("switchport block unicast")),
#|    "CISC-L2-000130": F(high=["ip dhcp snooping vlan <USER_VLANS>", "ip dhcp snooping",
#|                              "{each failing section of condition 3}", " ip dhcp snooping trust",
#|                              "{each failing section of condition 4}", " no ip dhcp snooping trust"]),
#|    "CISC-L2-000140": F(high=each("ip verify source")),
#|    "CISC-L2-000150": F(high=["ip arp inspection vlan <USER_VLANS>",
#|                              "{each failing section of condition 2}", " ip arp inspection trust",
#|                              "{each failing section of condition 3}", " no ip arp inspection trust"]),
#|    "CISC-L2-000160": F(high=each("storm-control broadcast level <STORM_LEVEL_PERCENT>")),
#|    "CISC-L2-000170": F(low=["ip igmp snooping"]),
#|    "CISC-L2-000180": F(high=["spanning-tree mode rapid-pvst"]),
#|    "CISC-L2-000190": F(high=["udld enable"]),
#|    "CISC-L2-000200": F(high=["! for every port showing 'Negotiation of Trunking: On':",
#|                              "interface <PORT>", " switchport mode <ACCESS_OR_TRUNK>", " switchport nonegotiate"]),
#|    "CISC-L2-000210": F(low=each("switchport access vlan <PARKING_VLAN>")),
#|    "CISC-L2-000220": F(high=["! move every port listed under VLAN 1 to its proper VLAN:",
#|                              "interface <PORT>", " switchport access vlan <USER_VLAN>"]),
#|    "CISC-L2-000230": F(high=each("switchport trunk allowed vlan remove 1")),
#|    "CISC-L2-000240": F(high=["! move management to a dedicated VLAN first, then:",
#|                              "interface Vlan1", " no ip address", " shutdown"]),
#|    "CISC-L2-000260": F(high=each("switchport trunk native vlan <NATIVE_VLAN>")),
#|    "CISC-L2-000250": F(high=["{each failing section of condition 1}", " switchport mode access",
#|                              " switchport nonegotiate"],
#|                        low=["{each failing section of condition 2}",
#|                             " ! label this port: description UPLINK - ... / DOWNLINK - ... / ACCESS - ..."]),
#|}
#|
#|
#|# ---------------------------------------------------------------- NX-OS fix commands (Nexus 9000)
#|
#|NX_ACCT = F(low=["aaa accounting default group <AAA_GROUP>"])
#|
#|FIX_NXOS = {
#|    "CISC-ND-000010": F(high=["line vty", "  session-limit 2"]),
#|    **{k: NX_ACCT for k in ("CISC-ND-000090", "CISC-ND-000100", "CISC-ND-000110", "CISC-ND-000120", "CISC-ND-000210",
#|                            "CISC-ND-000330", "CISC-ND-000880", "CISC-ND-000940", "CISC-ND-001240", "CISC-ND-001250",
#|                            "CISC-ND-001270")},
#|    "CISC-ND-000140": F(high=["ip access-list MGMT_NET", "  10 permit ip <MGMT_SUBNET_CIDR> any",
#|                              "  20 deny ip any any log", "interface mgmt0", "  ip access-group MGMT_NET in",
#|                              "line vty", "  access-class MGMT_NET in"]),
#|    "CISC-ND-000150": F(high=["ssh login-attempts 3"]),
#|    "CISC-ND-000160": F(low=["banner motd ^"] + DOD_BANNER.splitlines() + ["^"]),
#|    "CISC-ND-000290": F(low=["logging ip access-list cache entries 8000"],
#|                        high=each("! add 'log' to every deny statement in this ACL")),
#|    "CISC-ND-000470": F(high=["no feature telnet"]),
#|    "CISC-ND-000490": F(high=["! remove every local account except the account of last resort:",
#|                              "! no username <EXTRA_ACCOUNT>",
#|                              "! and remove any 'no aaa authentication login default fallback error local'"]),
#|    "CISC-ND-000530": F(high=["ssh macs hmac-sha2-256 hmac-sha2-512"]),
#|    **{k: F(low=["password strength-check"]) for k in ("CISC-ND-000570", "CISC-ND-000580", "CISC-ND-000590",
#|                                                         "CISC-ND-000600")},
#|    "CISC-ND-000720": F(low=["line console", "  exec-timeout 5", "line vty", "  exec-timeout 5"]),
#|    "CISC-ND-000980": F(low=["logging logfile messages 6 size 4194304"]),
#|    "CISC-ND-001000": F(low=["logging server <SYSLOG_SERVER_1> 6 use-vrf management"]),
#|    "CISC-ND-001030": F(low=["ntp server <NTP_SERVER_1> use-vrf management", "ntp server <NTP_SERVER_2> use-vrf management"]),
#|    "CISC-ND-001130": F(high=["snmp-server user <SNMP_USER> network-operator auth sha <AUTH_PASSWORD> priv aes-128 "
#|                              "<PRIV_PASSWORD>", "! remove or re-key the default 'admin' SNMP user (auth md5)",
#|                              "no snmp-server community <OLD_COMMUNITY>"]),
#|    "CISC-ND-001140": F(high=["snmp-server user <SNMP_USER> network-operator auth sha <AUTH_PASSWORD> priv aes-128 "
#|                              "<PRIV_PASSWORD>"]),
#|    "CISC-ND-001200": F(high=["ssh macs hmac-sha2-256 hmac-sha2-512"]),
#|    "CISC-ND-001210": F(high=["ssh ciphers aes256-ctr aes128-ctr"]),
#|    "CISC-ND-001220": F(high=["copp profile strict"]),
#|    "CISC-ND-001260": F(low=["logging level authpri 6", "logging logfile messages 6"]),
#|    "CISC-ND-001280": F(low=["logging level authpri 6"]),
#|    "CISC-ND-001310": F(low=["logging server <SYSLOG_SERVER_1> 6 use-vrf management"]),
#|    "CISC-ND-001370": F(high=["tacacs-server host <AAA_IP_1> key <AAA_KEY>", "tacacs-server host <AAA_IP_2> key <AAA_KEY>",
#|                              "aaa group server tacacs+ <AAA_GROUP>", "    server <AAA_IP_1>", "    server <AAA_IP_2>",
#|                              "    use-vrf management", "aaa authentication login default group <AAA_GROUP>",
#|                              "aaa authentication login console group <AAA_GROUP>"]),
#|    "CISC-ND-001410": F(low=["event manager applet BACKUP_CONFIG", "  event syslog pattern \"VSHD_SYSLOG_CONFIG_I\"",
#|                             "  action 1 cli copy running-config scp://<SCP_USER>@<SCP_SERVER>/<SCP_PATH>/nx-config "
#|                             "vrf management"]),
#|    "CISC-ND-001440": F(high=["! enroll with a DoD / DoD-approved CA (NX-OS uses cut-and-paste enrollment):",
#|                              "crypto ca trustpoint <DOD_CA_TRUSTPOINT>", "  enrollment terminal"]),
#|    "CISC-ND-001450": F(low=["logging server <SYSLOG_SERVER_1> 6 use-vrf management",
#|                             "logging server <SYSLOG_SERVER_2> 6 use-vrf management"]),
#|    "CISC-ND-001470": F(high=["! upgrade the switch to a Cisco-supported NX-OS release (not a config change)"]),
#|    # ---- L2S
#|    "CISC-L2-000020": F(high=["feature dot1x", "{each failing section of condition 1}", "  dot1x port-control auto"]),
#|    "CISC-L2-000080": F(high=["feature dot1x", "{each failing section of condition 1}", "  dot1x port-control auto"]),
#|    "CISC-L2-000030": F(high=["no feature vtp", "! or: vtp mode transparent"]),
#|    "CISC-L2-000060": F(low=["! confirm SPAN is available: monitor session <N> / source interface <PORT> both / "
#|                             "destination interface <PORT>"]),
#|    "CISC-L2-000070": F(low=["! confirm SPAN is available: monitor session <N> / source interface <PORT> both / "
#|                             "destination interface <PORT>"]),
#|    "CISC-L2-000090": F(high=each("spanning-tree guard root")),
#|    "CISC-L2-000100": F(high=["spanning-tree port type edge bpduguard default"]),
#|    "CISC-L2-000110": F(high=["spanning-tree loopguard default"]),
#|    "CISC-L2-000120": F(high=each("switchport block unicast")),
#|    "CISC-L2-000130": F(high=["feature dhcp", "ip dhcp snooping", "ip dhcp snooping vlan <USER_VLANS>",
#|                              "{each failing section of condition 3}", "  ip dhcp snooping trust",
#|                              "{each failing section of condition 4}", "  no ip dhcp snooping trust"]),
#|    "CISC-L2-000140": F(high=each("ip verify source dhcp-snooping-vlan")),
#|    "CISC-L2-000150": F(high=["ip arp inspection vlan <USER_VLANS>",
#|                              "{each failing section of condition 2}", "  ip arp inspection trust",
#|                              "{each failing section of condition 3}", "  no ip arp inspection trust"]),
#|    "CISC-L2-000160": F(high=each("storm-control broadcast level <STORM_LEVEL_PERCENT>")),
#|    "CISC-L2-000170": F(low=["ip igmp snooping"]),
#|    "CISC-L2-000190": F(high=["feature udld"]),
#|    "CISC-L2-000210": F(low=each("switchport access vlan <PARKING_VLAN>")),
#|    "CISC-L2-000220": F(high=each("switchport access vlan <USER_VLAN>")),
#|    "CISC-L2-000230": F(high=each("switchport trunk allowed vlan remove 1")),
#|    "CISC-L2-000240": F(high=["! move management to a dedicated VLAN first, then:",
#|                              "interface Vlan1", "  no ip address", "  shutdown"]),
#|    "CISC-L2-000260": F(high=each("switchport trunk native vlan <NATIVE_VLAN>")),
#|    # ---- RTR
#|    "CISC-RT-000020": F(high=["! configure authentication for every routing protocol, e.g. OSPF:",
#|                              "interface <ROUTING_INTERFACE>", "  ip ospf authentication key-chain <KEY_CHAIN>",
#|                              "! BGP: router bgp <ASN> / neighbor <PEER> / password 3 <KEY>"]),
#|    "CISC-RT-000030": F(high=["! set accept-lifetime / send-lifetime of 180 days or less on every key in the key chains"]),
#|    "CISC-RT-000040": F(high=["interface <ROUTING_INTERFACE>", "  ip ospf authentication message-digest",
#|                              "  ip ospf message-digest-key 1 md5 3 <KEY>"]),
#|    "CISC-RT-000050": F(high=["key chain <KEY_CHAIN>", "  key 1", "    key-string <ROUTING_KEY>",
#|                              "    cryptographic-algorithm hmac-sha-256",
#|                              "interface <ROUTING_INTERFACE>", "  ip ospf authentication key-chain <KEY_CHAIN>"]),
#|    "CISC-RT-000060": F(high=["! shut down routed interfaces that are not in use:",
#|                              "interface <UNUSED_INTERFACE>", "  shutdown"]),
#|    "CISC-RT-000080": F(high=["! disable Smart Call Home: callhome / no enable (confirm syntax for the release)"]),
#|    "CISC-RT-000120": F(high=["copp profile strict"]),
#|    "CISC-RT-000140": F(high=["! in the external and internal ACLs, before any ICMP permit:",
#|                              "ip access-list <ACL>", "  <SEQ> deny icmp any <DEVICE_ADDRESS>/32 fragments log"]),
#|    "CISC-RT-000150": F(high=each("no ip arp gratuitous request")),
#|    "CISC-RT-000160": F(low=each("no ip directed-broadcast")),
#|    "CISC-RT-000170": F(low=each("no ip unreachables")),
#|    "CISC-RT-000190": F(low=each("no ip redirects")),
#|    "CISC-RT-000200": F(high=each("! add 'log' to every deny statement in this ACL")),
#|    "CISC-RT-000236": F(low=["! on every IPv6 interface:", "interface <IPV6_INTERFACE>", "  ipv6 nd hop-limit 64"]),
#|    "CISC-RT-000237": F(high=["! replace any FEC0::/10 (site-local) IPv6 addresses"]),
#|    "CISC-RT-000350": F(low=["no ip source-route"]),
#|    "CISC-RT-000360": F(high=["no feature lldp"]),
#|    "CISC-RT-000370": F(high=["no cdp enable"]),
#|    "CISC-RT-000380": F(high=each("no ip proxy-arp")),
#|    "CISC-RT-000470": F(high=["router bgp <ASN>", "  neighbor <EBGP_PEER>", "    no disable-connected-check"]),
#|    "CISC-RT-000490": F(high=["! build the Bogon prefix list (see check text), then for every eBGP peer:",
#|                              "router bgp <ASN>", "  neighbor <EBGP_PEER>", "    address-family ipv4 unicast",
#|                              "      prefix-list <BOGON_PREFIX_LIST> in"]),
#|    "CISC-RT-000500": F(high=["ip prefix-list <INBOUND_FILTER> seq <SEQ> deny <LOCAL_AS_PREFIX> le 32",
#|                              "router bgp <ASN>", "  neighbor <EBGP_PEER>", "    address-family ipv4 unicast",
#|                              "      prefix-list <INBOUND_FILTER> in"]),
#|    "CISC-RT-000510": F(high=["router bgp <ASN>", "  neighbor <CE_PEER>", "    address-family ipv4 unicast",
#|                              "      prefix-list <CUSTOMER_PREFIX_LIST> in"]),
#|    "CISC-RT-000520": F(high=["router bgp <ASN>", "  neighbor <CE_PEER>", "    address-family ipv4 unicast",
#|                              "      prefix-list <ADVERTISE_PREFIX_LIST> out"]),
#|    "CISC-RT-000530": F(high=["router bgp <ASN>", "  neighbor <EBGP_PEER>", "    address-family ipv4 unicast",
#|                              "      prefix-list <FILTER_CORE_PREFIXES> out"]),
#|    "CISC-RT-000540": F(high=["router bgp <ASN>", "  enforce-first-as"]),
#|    "CISC-RT-000550": F(high=["ip as-path access-list <AS_PATH_ACL> permit ^<CUSTOMER_AS>$", "router bgp <ASN>",
#|                              "  neighbor <CE_PEER>", "    address-family ipv4 unicast",
#|                              "      filter-list <AS_PATH_ACL> in"]),
#|    "CISC-RT-000560": F(high=["router bgp <ASN>", "  neighbor <EBGP_PEER>", "    address-family ipv4 unicast",
#|                              "      maximum-prefix <MAX_PREFIXES>"]),
#|    "CISC-RT-000570": F(high=["ip prefix-list FILTER_PREFIX_LENGTH seq 5 permit 0.0.0.0/0 ge 8 le 24",
#|                              "ip prefix-list FILTER_PREFIX_LENGTH seq 10 deny 0.0.0.0/0 le 32",
#|                              "router bgp <ASN>", "  neighbor <EBGP_PEER>", "    address-family ipv4 unicast",
#|                              "      prefix-list FILTER_PREFIX_LENGTH in"]),
#|    "CISC-RT-000580": F(high=["router bgp <ASN>", "  neighbor <IBGP_PEER>", "    update-source loopback0"]),
#|    "CISC-RT-000590": F(high=["mpls ldp configuration", "  router-id loopback0 force"]),
#|    "CISC-RT-000600": F(high=["router ospf <OSPF_PROCESS>", "  mpls ldp sync"]),
#|    "CISC-RT-000620": F(high=["no mpls ip propagate-ttl"]),
#|    "CISC-RT-000710": F(low=["ip igmp snooping"]),
#|    "CISC-RT-000750": F(low=["no ip source-route"]),
#|    "CISC-RT-000760": F(high=["! build the QoS policy per the GIG QoS profile, then on each interface:",
#|                              "interface <INTERFACE>", "  service-policy type qos output <QOS_POLICY>"]),
#|    "CISC-RT-000770": F(high=["! build the QoS policy per the GIG QoS profile, then on each interface:",
#|                              "interface <INTERFACE>", "  service-policy type qos output <QOS_POLICY>"]),
#|    "CISC-RT-000780": F(high=["class-map type qos match-all SCAVENGER", "  match dscp 8",
#|                              "! add the SCAVENGER class with low bandwidth to <QOS_POLICY>"]),
#|    "CISC-RT-000800": F(high=each("ip pim neighbor-policy prefix-list <PIM_NEIGHBOR_LIST>")),
#|    "CISC-RT-000810": F(high=["interface <EDGE_INTERFACE>", "  ip pim border"]),
#|    "CISC-RT-000820": F(high=["ip pim register-policy <PIM_REGISTER_FILTER>"]),
#|    "CISC-RT-000830": F(high=["ip pim register-policy <PIM_REGISTER_FILTER>"]),
#|    "CISC-RT-000840": F(high=each("ip pim jp-policy <PIM_JOIN_FILTER> in")),
#|    "CISC-RT-000860": F(high=each("ip igmp report-policy <ALLOWED_GROUPS>")),
#|    "CISC-RT-000870": F(high=each("ip igmp report-policy <ALLOWED_SOURCES>")),
#|    "CISC-RT-000880": F(high=each("ip igmp state-limit <IGMP_LIMIT>")),
#|    "CISC-RT-000890": F(high=["ip pim spt-threshold infinity group-list <SPT_GROUPS>"]),
#|    "CISC-RT-000910": F(high=["ip msdp password <MSDP_PEER> <MSDP_KEY>"]),
#|    "CISC-RT-000920": F(high=["ip msdp sa-policy <MSDP_PEER> <INBOUND_SA_FILTER> in"]),
#|    "CISC-RT-000930": F(high=["ip msdp sa-policy <MSDP_PEER> <OUTBOUND_SA_FILTER> out"]),
#|    "CISC-RT-000940": F(high=["ip msdp sa-limit <MSDP_PEER> <SA_LIMIT>"]),
#|    "CISC-RT-000950": F(high=["ip msdp peer <MSDP_PEER> connect-source loopback0 remote-as <ASN>"]),
#|    "CISC-L2-000250": F(high=["{each failing section of condition 1}", "  switchport mode access"],
#|                        low=["{each failing section of condition 2}",
#|                             "  ! label this port: description UPLINK - ... / DOWNLINK - ... / ACCESS - ..."]),
#|}
#|
#|FIX_LIBRARY = {"IOSXE_SW": FIX_IOSXE, "IOSXE_RTR": FIX_IOSXE, "NXOS": FIX_NXOS}
#|
#|
#|def starter_fix(platform, rule_ver):
#|    return dict(FIX_LIBRARY.get(platform, {}).get(rule_ver) or {"low": "", "high": ""})
#|
#|
#|# ---------------------------------------------------------------- script generation
#|
#|def _header_for(cond):
#|    section = cond.get("section", "")
#|    only = (cond.get("only") or "").strip().lower()
#|    if "interface" in section:
#|        role = only[5:].strip().upper() if only.startswith("role:") else ""
#|        return f"interface <{role + '_' if role else ''}INTERFACE>"
#|    if cond.get("section_how") == "regex" or not section.strip():
#|        return "<SECTION>"
#|    return f"{section.strip()} <{section.strip().split()[-1].upper().replace('-', '_')}>"
#|
#|
#|def _placeholder_header(rule, condition=None):
#|    """Header used for {each failing section ...} when there are no assessment results."""
#|    conds = (rule.get("pass_logic") or {}).get("conditions", [])
#|    if condition and 0 < condition <= len(conds):
#|        return _header_for(conds[condition - 1])
#|    for cond in conds:
#|        if cond.get("scope") == "every":
#|            return _header_for(cond)
#|    return "interface <INTERFACE>"
#|
#|
#|def render(fix_text, failed_sections, placeholder, by_condition=None, rule=None, have_results=None):
#|    """Expand {each failing section [of condition N]} blocks. Returns the command lines.
#|
#|    failed_sections: every failing section; by_condition: {"2": [...]} per condition. With assessment results
#|    (have_results True) a block whose condition passed is left out; without results a placeholder is written.
#|    """
#|    if have_results is None:
#|        have_results = bool(failed_sections)
#|    lines, out, i = (fix_text or "").splitlines(), [], 0
#|    while i < len(lines):
#|        m = EACH_RE.match(lines[i].strip())
#|        if m:
#|            block, i = [], i + 1
#|            while i < len(lines) and (lines[i][:1] in (" ", "\t") or not lines[i].strip()):
#|                if lines[i].strip():
#|                    block.append(lines[i])
#|                i += 1
#|            if m.group(1):
#|                n = int(m.group(1))
#|                failed = (by_condition or {}).get(str(n), [])
#|                header = _placeholder_header(rule, n) if rule else placeholder
#|            else:
#|                failed, header = failed_sections, placeholder
#|            if have_results and not failed:
#|                continue  # that condition passed on this device - nothing to fix
#|            heads = failed or [header]
#|            if not failed:
#|                out.append("! EDIT: repeat this block for every section that needs it")
#|            for head in heads:
#|                out.append(head)
#|                out += block
#|                out.append("exit")
#|            continue
#|        out.append(lines[i])
#|        i += 1
#|    return out
#|
#|
#|def has_fix(rule):
#|    fix = rule.get("fix") or {}
#|    return bool((fix.get("low") or "").strip() or (fix.get("high") or "").strip())
#|
#|
#|def _script(impact, title, items, source):
#|    """items: [(heading, [command lines])] -> full script text, or None if empty."""
#|    items = [(h, cmds) for h, cmds in items if any(c.strip() for c in cmds)]
#|    if not items:
#|        return None, 0
#|    body, seen = [], {}
#|    for heading, cmds in items:
#|        key = tuple(c.strip() for c in cmds if c.strip())
#|        if key in seen:  # several controls share one fix (e.g. archive / log config) - write it once
#|            body += ["!", f"! ---- {heading}", f"! (same fix as {seen[key]} above)"]
#|            continue
#|        seen[key] = heading.split(":")[0]
#|        body += ["!", f"! ---- {heading}"] + cmds
#|    placeholders = sorted({p for _, cmds in items for c in cmds for p in PLACEHOLDER_RE.findall(c)})
#|    head = [f"! STIGTOOL hardening script - {IMPACT[impact]}", f"! {title}",
#|            f"! Generated {store.now()} by {store.current_user()}", f"! Source: {source}",
#|            f"! Controls: {len(items)}"] + HEADER_WARNING[impact]
#|    if placeholders:
#|        head += ["!", "! EDIT BEFORE USE - replace every one of these values:"]
#|        head += [f"!   {p}" for p in placeholders]
#|    text = "\n".join(head + ["!", "configure terminal"] + body +
#|                     ["!", "end", "! Verify the device, then save: copy running-config startup-config", ""])
#|    return text, len(items)
#|
#|
#|def _heading(stig_short, control_like):
#|    return (f"{stig_short} {control_like['vuln_id']} ({control_like['rule_ver']}): "
#|            f"{control_like['title'][:90]}")
#|
#|
#|def _write(folder, name, text):
#|    path = folder / name
#|    path.write_text(text, encoding="utf-8", newline="\n")
#|    return path
#|
#|
#|def generate_baseline(group, rules_db, index, include_drafts=True):
#|    """Two scripts for the group covering every control whose rule has fix commands."""
#|    items = {"low": [], "high": []}
#|    for stig_id, control, rule in assess.group_plan(group, rules_db, index):
#|        if rule is None and include_drafts:
#|            rule = next((r for r in assess.rules_for_control(rules_db, stig_id, control["vuln_id"])
#|                         if r.get("state") == "draft" and has_fix(r)), None)
#|        if not rule or not has_fix(rule):
#|            continue
#|        placeholder = _placeholder_header(rule)
#|        for impact in ("low", "high"):
#|            cmds = render(rule["fix"].get(impact, ""), [], placeholder, rule=rule, have_results=False)
#|            if cmds:
#|                items[impact].append((_heading(index[stig_id]["short"], control), cmds))
#|    folder = store.paths.output / "hardening" / f"{group['id']}_baseline_{store.stamp()}"
#|    folder.mkdir(parents=True, exist_ok=True)
#|    written = []
#|    for impact, suffix in (("low", "LOW_IMPACT"), ("high", "IMPACTFUL")):
#|        text, n = _script(impact, f"Group {group['id']} - baseline for every device in the group",
#|                          items[impact], "baseline (every control with fix commands"
#|                          + (", including draft rules)" if include_drafts else ", active rules only)"))
#|        if text:
#|            written.append((_write(folder, f"{group['id']}_{suffix}.txt", text), n))
#|    return folder, written
#|
#|
#|def generate_from_run(run, group_id, rules_db):
#|    """Per-device scripts with only the controls that are Open on that device in the assessment run."""
#|    results = run["results"][group_id]
#|    per_device = {h: {"low": [], "high": []} for h in results["devices"]}
#|    rules_by_id = {r["id"]: r for r in rules_db["rules"]}
#|    for c in results["controls"].values():
#|        rule = rules_by_id.get(c["rule_id"])
#|        if not rule or not has_fix(rule) or assess.is_expected_open(c) or c.get("final") in (
#|                "not_applicable", "not_a_finding"):
#|            continue
#|        for host, r in c["per_device"].items():
#|            if r["status"] != "open":
#|                continue
#|            failed = r.get("failed_sections") or []
#|            by_cond = r.get("failed_by_condition") or {}
#|            for impact in ("low", "high"):
#|                cmds = render(rule["fix"].get(impact, ""), failed, _placeholder_header(rule), by_cond, rule,
#|                              have_results="failed_by_condition" in r)
#|                if cmds:
#|                    per_device[host][impact].append((_heading(c["family"], c), cmds))
#|    folder = store.paths.output / "hardening" / f"{group_id}_run{run['id']}_{store.stamp()}"
#|    folder.mkdir(parents=True, exist_ok=True)
#|    written = []
#|    for host, items in per_device.items():
#|        for impact, suffix in (("low", "LOW_IMPACT"), ("high", "IMPACTFUL")):
#|            text, n = _script(impact, f"Device {host} (group {group_id})", items[impact],
#|                              f"assessment run {run['id']} - only controls Open on this device")
#|            if text:
#|                written.append((_write(folder, f"{host}_{suffix}.txt", text), n))
#|    return folder, written
#@ END
#@ FILE src/rules.py SHA a9679ac673b07b57241ef375bf0786497485006aa2a915b5f34c56c98517c246 CHUNK 1 OF 1
#|"""Rule engine: plain-English conditions evaluated against show-command output.
#|
#|A rule belongs to one STIG control and says:
#|  - which show commands to collect
#|  - NOT A FINDING when ALL / ANY of its conditions are true (otherwise OPEN)
#|  - optionally NOT APPLICABLE when ALL / ANY of a second set of conditions are true (checked first)
#|Missing, failed or invalid command output always gives NOT REVIEWED.
#|
#|A condition is a dict:
#|  command   which collected command's output to look at
#|  scope     "all"   - the whole output
#|            "every" - every section whose first line matches `section` must pass
#|            "any"   - at least one such section must pass
#|  section, section_how   how to find section first lines (e.g. starts with "line vty")
#|  only      only check sections that have a line starting with this (e.g. "ip address")
#|  exclude   skip sections that have a line starting with this (e.g. "shutdown" - not "no shutdown")
#|            (only / exclude: start the text with "re:" to use a regular expression instead)
#|            Port roles: "role:uplink", "role:downlink", "role:access" or "role:any" (in only / exclude, or as
#|            the text to look for) mean an interface description starting with that role's keyword(s), which
#|            are a team setting (default UPLINK / DOWNLINK / ACCESS, UNTRUSTED).
#|  if_none   "fail" or "pass" when no sections are found
#|  check     has | lacks | number | count | pattern | no_pattern
#|  text, how, ignore_case   what to look for and how to match it
#|  op, value              comparison for number / count
#|
#|A "section" is a line plus the indented lines under it, which is how IOS / NX-OS
#|configuration is laid out (line vty 0 4 -> transport input ssh, interface X -> ...).
#|"""
#|import re
#|
#|HOWS = ["contains", "starts with", "whole line", "regex"]
#|SCOPES = {
#|    "all": "the whole output",
#|    "every": "EVERY section that",
#|    "any": "AT LEAST ONE section that",
#|}
#|CHECKS = {
#|    "has": "has a line that",
#|    "lacks": "has NO line that",
#|    "number": "has a line whose number is",
#|    "count": "has a number of matching lines that is",
#|    "pattern": "matches multi-line pattern (advanced regex)",
#|    "no_pattern": "does NOT match multi-line pattern (advanced regex)",
#|}
#|OPS = {
#|    ">=": lambda a, b: a >= b,
#|    "<=": lambda a, b: a <= b,
#|    "==": lambda a, b: a == b,
#|    "!=": lambda a, b: a != b,
#|    ">": lambda a, b: a > b,
#|    "<": lambda a, b: a < b,
#|}
#|OP_WORDS = {">=": "at least", "<=": "at most", "==": "exactly", "!=": "not", ">": "more than", "<": "less than"}
#|
#|# Highlight tags, strongest first. One line can only show one colour.
#|TAG_ORDER = ["problem", "match", "section", "skipped"]
#|
#|INVALID_RE = re.compile(
#|    r"^\s*(% ?(Invalid input|Incomplete command|Ambiguous command|Unknown command|Invalid command)"
#|    r"|Line has invalid autocommand|Syntax error)", re.I | re.M)
#|
#|NEW_CONDITION = {
#|    "command": "", "scope": "all", "section": "", "section_how": "starts with", "only": "", "exclude": "",
#|    "if_none": "fail", "check": "has", "text": "", "how": "contains", "ignore_case": False,
#|    "op": ">=", "value": "",
#|}
#|
#|
#|def classify_output(text):
#|    """'invalid' if the device rejected the command, otherwise 'ok' (empty output is valid evidence)."""
#|    return "invalid" if INVALID_RE.search(text or "") else "ok"
#|
#|
#|def split_lines(text):
#|    return (text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
#|
#|
#|# Port-role keywords (team setting, see set_port_roles). An interface is in a role when its description starts
#|# with one of the role's keywords, e.g. "description UPLINK - DIST-SW-01 Te2/0/14".
#|PORT_ROLES = {"uplink": "UPLINK", "downlink": "DOWNLINK", "access": "ACCESS, UNTRUSTED"}
#|DEFAULT_PORT_ROLES = dict(PORT_ROLES)
#|
#|
#|def set_port_roles(roles):
#|    PORT_ROLES.clear()
#|    PORT_ROLES.update(DEFAULT_PORT_ROLES)
#|    PORT_ROLES.update({k: v for k, v in (roles or {}).items() if k in PORT_ROLES and str(v).strip()})
#|
#|
#|def role_words(role):
#|    names = list(PORT_ROLES) if role == "any" else [role]
#|    return [w.strip() for name in names for w in PORT_ROLES.get(name, "").split(",") if w.strip()]
#|
#|
#|def is_role(text):
#|    return (text or "").strip().lower().startswith("role:")
#|
#|
#|def role_regex(text):
#|    role = text.strip()[5:].strip().lower()
#|    if role != "any" and role not in PORT_ROLES:
#|        raise re.error(f"unknown port role '{role}' (use uplink, downlink, access or any)")
#|    return re.compile(r"^\s*description\s+(" + "|".join(re.escape(w) for w in role_words(role)) + r")\b", re.I)
#|
#|
#|def describe_filter(text):
#|    if is_role(text):
#|        role = text.strip()[5:].strip().lower()
#|        return f"the {role} port role (description starting {' / '.join(role_words(role))})"
#|    return _quote(text)
#|
#|
#|def matcher(text, how, ignore_case=False):
#|    if is_role(text):
#|        return role_regex(text)
#|    flags = re.I if ignore_case else 0
#|    if how == "regex":
#|        return re.compile(text, flags)
#|    if how == "starts with":
#|        return re.compile(r"^\s*" + re.escape(text.strip()), flags)
#|    if how == "whole line":
#|        return re.compile(r"^\s*" + re.escape(text.strip()) + r"\s*$", flags)
#|    return re.compile(re.escape(text), flags)
#|
#|
#|def line_filter(text, ignore_case=False):
#|    """Section filters (only / exclude): a line starting with the text, a regex after "re:", or a port role."""
#|    if is_role(text):
#|        return role_regex(text)
#|    if text.startswith("re:"):
#|        return re.compile(text[3:], re.I if ignore_case else 0)
#|    return matcher(text, "starts with", ignore_case)
#|
#|
#|def _indent(line):
#|    return len(line) - len(line.lstrip(" \t"))
#|
#|
#|def find_sections(lines, header_rx):
#|    """[(header_index, [body_indexes])] - body is every following line indented deeper than the header."""
#|    out = []
#|    for i, line in enumerate(lines):
#|        if not line.strip() or not header_rx.search(line):
#|            continue
#|        depth, body, j = _indent(line), [], i + 1
#|        while j < len(lines) and lines[j].strip() and _indent(lines[j]) > depth:
#|            body.append(j)
#|            j += 1
#|        out.append((i, body))
#|    return out
#|
#|
#|def _quote(s):
#|    return f"'{s}'"
#|
#|
#|def describe(cond):
#|    """One plain-English sentence for a condition."""
#|    c = {**NEW_CONDITION, **cond}
#|    if c["scope"] == "all":
#|        where = "the output"
#|    else:
#|        where = f"{SCOPES[c['scope']]} {c['section_how']} {_quote(c['section'])}"
#|        if c.get("only"):
#|            where += (f" in {describe_filter(c['only'])}" if is_role(c["only"])
#|                      else f" with a line starting {_quote(c['only'])}")
#|        if c["exclude"]:
#|            where += (f" (skipping {describe_filter(c['exclude'])})" if is_role(c["exclude"])
#|                      else f" (skipping sections with a line starting {_quote(c['exclude'])})")
#|    check = c["check"]
#|    what = (f"is a description for {describe_filter(c['text'])}" if is_role(c["text"]) else
#|            f"{c['how']} {_quote(c['text'])}" + (" (any case)" if c["ignore_case"] else ""))
#|    if check == "has":
#|        tail = f"has a line that {what}"
#|    elif check == "lacks":
#|        tail = f"has NO line that {what}"
#|    elif check == "number":
#|        tail = f"has a line that {what} with a number {OP_WORDS[c['op']]} {c['value']}"
#|    elif check == "count":
#|        tail = f"has {OP_WORDS[c['op']]} {c['value']} line(s) that {what}"
#|    elif check == "pattern":
#|        tail = f"matches pattern {_quote(c['text'])}"
#|    else:
#|        tail = f"does NOT match pattern {_quote(c['text'])}"
#|    return f"[{c['command']}] {where} {tail}"
#|
#|
#|def condition_problems(cond, commands=None):
#|    """Reasons a condition cannot run (bad regex, missing values...)."""
#|    c = {**NEW_CONDITION, **cond}
#|    errs = []
#|    if not c["command"]:
#|        errs.append("no command chosen")
#|    elif commands is not None and c["command"] not in commands:
#|        errs.append(f"command {c['command']!r} is not in the rule's command list")
#|    if c["check"] not in CHECKS:
#|        errs.append(f"unknown check {c['check']!r}")
#|    if not c["text"]:
#|        errs.append("nothing to look for (text is empty)")
#|    if c["scope"] != "all" and not c["section"].strip():
#|        errs.append("section start text is empty")
#|    if c["check"] in ("number", "count"):
#|        try:
#|            float(c["value"])
#|        except (TypeError, ValueError):
#|            errs.append(f"'{c['value']}' is not a number")
#|        if c["op"] not in OPS:
#|            errs.append(f"unknown comparison {c['op']!r}")
#|    try:
#|        how = "regex" if c["check"] in ("pattern", "no_pattern") else c["how"]
#|        matcher(c["text"], how, c["ignore_case"])
#|        if c["scope"] != "all":
#|            matcher(c["section"], c["section_how"], c["ignore_case"])
#|            for f in (c.get("only"), c["exclude"]):
#|                if f:
#|                    line_filter(f, c["ignore_case"])
#|    except re.error as e:
#|        errs.append(f"pattern error: {e}")
#|    return errs
#|
#|
#|def _first_number(line, m):
#|    found = re.search(r"-?\d+(?:\.\d+)?", line[m.end():]) or re.search(r"-?\d+(?:\.\d+)?", line)
#|    return float(found.group(0)) if found else None
#|
#|
#|def _check_unit(c, lines, idxs, rx):
#|    """Run the check over the given line indexes. Returns (ok, note, marks[(idx, tag)])."""
#|    check = c["check"]
#|    marks = []
#|    if check in ("pattern", "no_pattern"):
#|        text = "\n".join(lines[i] for i in idxs)
#|        offsets, pos = [], 0
#|        for i in idxs:
#|            offsets.append((pos, i))
#|            pos += len(lines[i]) + 1
#|        hit_lines = set()
#|        for m in rx.finditer(text):
#|            if m.end() == m.start():
#|                continue
#|            for start, i in offsets:
#|                if start <= m.end() - 1 and start + len(lines[i]) >= m.start():
#|                    hit_lines.add(i)
#|        tag = "match" if check == "pattern" else "problem"
#|        marks = [(i, tag) for i in sorted(hit_lines)]
#|        found = bool(hit_lines)
#|        ok = found if check == "pattern" else not found
#|        return ok, ("pattern found" if found else "pattern not found"), marks
#|
#|    hits = [i for i in idxs if rx.search(lines[i])]
#|    if check == "has":
#|        return bool(hits), (f"found on line {hits[0] + 1}" if hits else "no matching line"), \
#|            [(i, "match") for i in hits]
#|    if check == "lacks":
#|        return not hits, (f"found on line {', '.join(str(i + 1) for i in hits[:5])}" if hits else "not present"), \
#|            [(i, "problem") for i in hits]
#|    value, op = float(c["value"]), OPS[c["op"]]
#|    if check == "count":
#|        ok = op(len(hits), value)
#|        return ok, f"{len(hits)} matching line(s)", [(i, "match" if ok else "problem") for i in hits]
#|    # number
#|    if not hits:
#|        return False, "no matching line", []
#|    ok, notes = True, []
#|    for i in hits:
#|        n = _first_number(lines[i], rx.search(lines[i]))
#|        good = n is not None and op(n, value)
#|        ok = ok and good
#|        marks.append((i, "match" if good else "problem"))
#|        notes.append(f"line {i + 1}: {('no number' if n is None else f'{n:g}')}")
#|    return ok, "; ".join(notes[:5]), marks
#|
#|
#|def eval_condition(cond, outputs):
#|    """Evaluate one condition.
#|
#|    outputs: {command: {"status": "ok"|"invalid"|"error"|"missing", "text": str}}
#|    Returns {"ok": True/False/None, "note": str, "marks": {command: [(idx, tag)]}}  (ok None = no evidence)
#|    """
#|    c = {**NEW_CONDITION, **cond}
#|    ev = outputs.get(c["command"])
#|    if not ev or ev.get("status") != "ok":
#|        state = ev.get("status") if ev else "missing"
#|        return {"ok": None, "note": f"no usable output for '{c['command']}' ({state})", "marks": {}}
#|    errs = condition_problems(c)
#|    if errs:
#|        return {"ok": None, "note": "rule error: " + "; ".join(errs), "marks": {}}
#|    lines = split_lines(ev.get("text", ""))
#|    how = "regex" if c["check"] in ("pattern", "no_pattern") else c["how"]
#|    rx = matcher(c["text"], how, c["ignore_case"])
#|    if c["check"] in ("pattern", "no_pattern"):
#|        rx = re.compile(rx.pattern, rx.flags | re.M)
#|
#|    if c["scope"] == "all":
#|        ok, note, marks = _check_unit(c, lines, range(len(lines)), rx)
#|        return {"ok": ok, "note": note, "marks": {c["command"]: marks}}
#|
#|    header_rx = matcher(c["section"], c["section_how"], c["ignore_case"])
#|    exclude_rx = line_filter(c["exclude"], c["ignore_case"]) if c["exclude"] else None
#|    only_rx = line_filter(c["only"], c["ignore_case"]) if c.get("only") else None
#|    marks, passed, failed, skipped = [], [], [], 0
#|    for head, body in find_sections(lines, header_rx):
#|        if only_rx and not any(only_rx.search(lines[i]) for i in [head] + body):
#|            continue
#|        if exclude_rx and any(exclude_rx.search(lines[i]) for i in [head] + body):
#|            marks.append((head, "skipped"))
#|            skipped += 1
#|            continue
#|        ok, _, unit_marks = _check_unit(c, lines, body, rx)
#|        marks += unit_marks
#|        marks.append((head, "section" if ok or c["scope"] == "any" else "problem"))
#|        (passed if ok else failed).append(head)
#|    total = len(passed) + len(failed)
#|    skip_note = f", {skipped} skipped" if skipped else ""
#|    if total == 0:
#|        ok = c["if_none"] == "pass"
#|        return {"ok": ok, "note": f"no matching sections found{skip_note} (counts as {'pass' if ok else 'fail'})",
#|                "marks": {c["command"]: marks}}
#|    if c["scope"] == "every":
#|        ok = not failed
#|        note = f"{len(passed)} of {total} section(s) OK{skip_note}"
#|        if failed:
#|            note += "; failing: " + ", ".join(f"'{lines[i].strip()}' (line {i + 1})" for i in failed[:5])
#|    else:
#|        ok = bool(passed)
#|        note = f"{len(passed)} of {total} section(s) OK{skip_note}"
#|    # The first line of each failing section (e.g. "interface GigabitEthernet1/0/5") - used by hardening scripts.
#|    failed_sections = [lines[i].strip() for i in failed] if c["scope"] == "every" else []
#|    return {"ok": ok, "note": note, "marks": {c["command"]: marks}, "failed_sections": failed_sections}
#|
#|
#|def _combine(mode, results):
#|    values = [r["ok"] for r in results]
#|    if mode == "ANY":
#|        return True if any(v is True for v in values) else (None if None in values else False)
#|    return False if any(v is False for v in values) else (None if None in values else True)
#|
#|
#|def _merge_marks(into, marks):
#|    for cmd, items in marks.items():
#|        slot = into.setdefault(cmd, {})
#|        for idx, tag in items:
#|            if idx not in slot or TAG_ORDER.index(tag) < TAG_ORDER.index(slot[idx]):
#|                slot[idx] = tag
#|
#|
#|def evaluate(rule, outputs):
#|    """Evaluate a rule against one device's evidence.
#|
#|    Returns {"status", "reasons": [str], "marks": {command: {idx: tag}}, "evidence": [str]}
#|    """
#|    marks, reasons = {}, []
#|    commands = [c for c in rule.get("commands", []) if c.strip()]
#|    if not commands:
#|        return {"status": "not_reviewed", "reasons": ["Rule has no commands."], "marks": {}, "evidence": []}
#|    bad = [f"{c} ({outputs[c]['status'] if c in outputs else 'missing'})"
#|           for c in commands if outputs.get(c, {}).get("status") != "ok"]
#|    if bad:
#|        return {"status": "not_reviewed", "reasons": ["No usable evidence for: " + ", ".join(bad)],
#|                "marks": {}, "evidence": []}
#|    pass_logic = rule.get("pass_logic") or {"mode": "ALL", "conditions": []}
#|    if not pass_logic.get("conditions"):
#|        return {"status": "not_reviewed", "reasons": ["Rule has no conditions."], "marks": {}, "evidence": []}
#|
#|    status, failed_sections, failed_by_condition = None, [], {}
#|    na_logic = rule.get("na_logic") or {}
#|    if rule.get("na_enabled") and na_logic.get("conditions"):
#|        na_results = [eval_condition(c, outputs) for c in na_logic["conditions"]]
#|        na = _combine(na_logic.get("mode", "ALL"), na_results)
#|        if na is True:
#|            status = "not_applicable"
#|            reasons.append(f"Not Applicable because {na_logic.get('mode', 'ALL')} of these are true:")
#|            for cond, r in zip(na_logic["conditions"], na_results):
#|                reasons.append(f"  {'TRUE ' if r['ok'] else 'FALSE'}  {describe(cond)} - {r['note']}")
#|                _merge_marks(marks, r["marks"])
#|        elif na is None:
#|            status = "not_reviewed"
#|            reasons.append("Could not decide Not Applicable check: " +
#|                           "; ".join(r["note"] for r in na_results if r["ok"] is None))
#|
#|    if status is None:
#|        results = [eval_condition(c, outputs) for c in pass_logic["conditions"]]
#|        verdict = _combine(pass_logic.get("mode", "ALL"), results)
#|        status = {True: "not_a_finding", False: "open", None: "not_reviewed"}[verdict]
#|        reasons.append(f"Needs {pass_logic.get('mode', 'ALL')} of these to pass:")
#|        for n, (cond, r) in enumerate(zip(pass_logic["conditions"], results), 1):
#|            label = {True: "PASS ", False: "FAIL ", None: "ERROR"}[r["ok"]]
#|            reasons.append(f"  {label}  {describe(cond)} - {r['note']}")
#|            _merge_marks(marks, r["marks"])
#|            if r["ok"] is False:
#|                failed_sections += [h for h in r.get("failed_sections", []) if h not in failed_sections]
#|                failed_by_condition[str(n)] = r.get("failed_sections", [])
#|
#|    evidence = []
#|    for cmd, slot in marks.items():
#|        lines = split_lines(outputs[cmd]["text"])
#|        shown = [i for i in sorted(slot) if slot[i] in ("match", "problem", "section")]
#|        if shown:
#|            evidence.append(f"{cmd}:")
#|            for i in shown[:40]:
#|                evidence.append(f"  {'!!' if slot[i] == 'problem' else '  '} {lines[i]}")
#|            if len(shown) > 40:
#|                evidence.append(f"     ... {len(shown) - 40} more line(s)")
#|    return {"status": status, "reasons": reasons, "marks": marks, "evidence": evidence,
#|            "failed_sections": failed_sections, "failed_by_condition": failed_by_condition}
#|
#|
#|def outcome_text(rule, status, devices=()):
#|    """The rule author's Finding Details text for this result, with {devices} / {device_count} filled in."""
#|    text = ((rule or {}).get("outcome_text") or {}).get(status, "").strip()
#|    if not text:
#|        return ""
#|    names = ", ".join(devices) or "(none)"
#|    return text.replace("{devices}", names).replace("{device_count}", str(len(devices)))
#|
#|
#|def test_outputs(test):
#|    """Saved test samples are stored as plain text per command."""
#|    return {cmd: {"status": classify_output(text), "text": text} for cmd, text in test.get("outputs", {}).items()}
#|
#|
#|def run_tests(rule):
#|    """[(test, actual_status, passed)]"""
#|    out = []
#|    for t in rule.get("tests", []):
#|        actual = evaluate(rule, test_outputs(t))["status"]
#|        out.append((t, actual, actual == t.get("expected")))
#|    return out
#|
#|
#|def activation_problems(rule):
#|    """Everything that must be fixed before a rule may be set Active."""
#|    errs = []
#|    commands = [c for c in rule.get("commands", []) if c.strip()]
#|    if not commands:
#|        errs.append("Add at least one show command.")
#|    conds = (rule.get("pass_logic") or {}).get("conditions") or []
#|    if not conds:
#|        errs.append("Add at least one Not a Finding condition.")
#|    all_conds = list(conds)
#|    if rule.get("na_enabled"):
#|        na = (rule.get("na_logic") or {}).get("conditions") or []
#|        if not na:
#|            errs.append("Not Applicable check is switched on but has no conditions.")
#|        all_conds += na
#|    for n, c in enumerate(all_conds, 1):
#|        for e in condition_problems(c, commands):
#|            errs.append(f"Condition {n}: {e}.")
#|    if rule.get("expected_open") and not (rule.get("outcome_text") or {}).get("open", "").strip():
#|        errs.append("Open is marked as an intentional finding: write the reason (e.g. risk acceptance) in the "
#|                    "Finding Details text for Open.")
#|    tests = rule.get("tests", [])
#|    if len(tests) < 2 or len({t.get("expected") for t in tests}) < 2:
#|        errs.append("Save at least two test samples with different expected results "
#|                    "(for example one that should pass and one that should be Open).")
#|    for t, actual, ok in run_tests(rule):
#|        if not ok:
#|            errs.append(f"Test '{t.get('name')}' expected {t.get('expected')} but rule gives {actual}.")
#|    return errs
#@ END
#@ FILE src/store.py SHA eaea8d81254834e1465d9588faab49bfb769799f36080975144c590122d046f3 CHUNK 1 OF 1
#|"""Project folders and data files - built so a team can share them.
#|
#|Everything lives in plain JSON under data/:
#|  data/rules/<rule id>.json     one file per rule, so two people editing different rules never clash
#|  data/groups/<group id>.json   one file per device group
#|  data/settings.json            team settings: output format, manual-only controls, device overrides
#|  data/templates/               imported CKL/CKLB files (read-only) + one catalog .json each
#|  data/locks/                   "who is editing this rule" markers
#|  data/runs/, data/evidence/, data/scripts/
#|
#|Saving a rule or group checks that nobody else saved it since you opened it (ConflictError).
#|
#|Shared location: put the path of a shared folder (e.g. \\\\server\\share\\stigtool) on the first line of
#|shared_data_path.txt next to main.py. data/, input/ and output/ then live there; logs stay local.
#|"""
#|import copy
#|import datetime
#|import getpass
#|import hashlib
#|import json
#|import os
#|import secrets
#|import shutil
#|import socket
#|import stat
#|from pathlib import Path
#|
#|import checklist
#|
#|LOCK_HOURS = 12
#|
#|
#|class ConflictError(Exception):
#|    """Someone else saved the record after you loaded it. .current holds their version."""
#|
#|    def __init__(self, current):
#|        super().__init__("changed by someone else")
#|        self.current = current
#|
#|
#|class Paths:
#|    def __init__(self, root):
#|        self.root = Path(root)
#|        self.workspace = self.root
#|        pointer = self.root / "shared_data_path.txt"
#|        if pointer.exists():
#|            target = pointer.read_text(encoding="utf-8").strip().splitlines()
#|            if target and target[0].strip():
#|                self.workspace = Path(target[0].strip())
#|        self.data = self.workspace / "data"
#|        self.templates = self.data / "templates"
#|        self.rules = self.data / "rules"
#|        self.groups = self.data / "groups"
#|        self.locks = self.data / "locks"
#|        self.scripts = self.data / "scripts"
#|        self.evidence = self.data / "evidence"
#|        self.runs = self.data / "runs"
#|        self.settings_file = self.data / "settings.json"
#|        self.input = self.workspace / "input"
#|        self.output = self.workspace / "output"
#|        self.logs = self.root / "logs"
#|
#|    def folders(self):
#|        return [self.data, self.templates, self.rules, self.groups, self.locks, self.scripts, self.evidence,
#|                self.runs, self.input, self.output, self.output / "scripts", self.logs]
#|
#|
#|paths = Paths(Path(__file__).resolve().parent.parent)
#|
#|
#|def use_root(root):
#|    """Point the tool at a different project root (used by tests)."""
#|    global paths
#|    paths = Paths(root)
#|    ensure_folders()
#|
#|
#|def ensure_folders():
#|    for folder in paths.folders():
#|        folder.mkdir(parents=True, exist_ok=True)
#|    migrate_legacy()
#|
#|
#|def now():
#|    return datetime.datetime.now().isoformat(timespec="seconds")
#|
#|
#|def stamp():
#|    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
#|
#|
#|def current_user():
#|    try:
#|        return getpass.getuser()
#|    except Exception:
#|        return "unknown"
#|
#|
#|def current_host():
#|    try:
#|        return socket.gethostname()
#|    except Exception:
#|        return "unknown"
#|
#|
#|def load_json(path, default):
#|    path = Path(path)
#|    if not path.exists():
#|        return copy.deepcopy(default)
#|    with open(path, encoding="utf-8") as f:
#|        return json.load(f)
#|
#|
#|def save_json(path, data):
#|    """Write to a temp file first so a crash never leaves a half-written data file."""
#|    path = Path(path)
#|    tmp = path.with_name(f"{path.name}.{secrets.token_hex(3)}.tmp")
#|    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
#|        json.dump(data, f, indent=2, ensure_ascii=False)
#|    os.replace(tmp, path)
#|
#|
#|def read_text(path):
#|    """Read a text export whose encoding is not guaranteed (SolarWinds output)."""
#|    raw = Path(path).read_bytes()
#|    for enc in ("utf-8-sig", "cp1252"):
#|        try:
#|            return raw.decode(enc)
#|        except UnicodeDecodeError:
#|            continue
#|    return raw.decode("utf-8", errors="replace")
#|
#|
#|def sha256_file(path):
#|    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
#|
#|
#|# ---------------------------------------------------------------- team settings
#|
#|# Where the reason/evidence text goes in the checklist for each result (team guidance).
#|DEFAULT_PLACEMENT = {"not_a_finding": "comments", "not_applicable": "comments", "open": "finding_details",
#|                     "not_reviewed": "comments"}
#|# Interface-description keywords that mark port roles (comma-separated alternatives).
#|DEFAULT_PORT_ROLES = {"uplink": "UPLINK", "downlink": "DOWNLINK", "access": "ACCESS, UNTRUSTED"}
#|DEFAULT_SETTINGS = {"output_format": "ckl", "manual_controls": [], "device_overrides": {}, "known_devices": {},
#|                    "text_placement": DEFAULT_PLACEMENT, "port_roles": DEFAULT_PORT_ROLES}
#|
#|
#|def load_settings():
#|    s = {**copy.deepcopy(DEFAULT_SETTINGS), **load_json(paths.settings_file, {})}
#|    s["text_placement"] = {**DEFAULT_PLACEMENT, **(s.get("text_placement") or {})}
#|    s["port_roles"] = {**DEFAULT_PORT_ROLES, **(s.get("port_roles") or {})}
#|    return s
#|
#|
#|def update_settings(change):
#|    """Re-read, apply change(settings), write - so a teammate's other edits are kept."""
#|    s = load_settings()
#|    change(s)
#|    save_json(paths.settings_file, s)
#|    return s
#|
#|
#|def set_setting(key, value):
#|    return update_settings(lambda s: s.__setitem__(key, value))
#|
#|
#|def set_manual(key, on):
#|    def change(s):
#|        manual = set(s["manual_controls"])
#|        manual.add(key) if on else manual.discard(key)
#|        s["manual_controls"] = sorted(manual)
#|    update_settings(change)
#|
#|
#|def set_override(host, group_id):
#|    def change(s):
#|        if group_id:
#|            s["device_overrides"][host.upper()] = group_id
#|        else:
#|            s["device_overrides"].pop(host.upper(), None)
#|    update_settings(change)
#|
#|
#|def add_known_devices(mapping):
#|    update_settings(lambda s: s["known_devices"].update({h.upper(): ip for h, ip in mapping.items()}))
#|
#|
#|def forget_device(host):
#|    def change(s):
#|        s["known_devices"].pop(host.upper(), None)
#|        s["device_overrides"].pop(host.upper(), None)
#|    update_settings(change)
#|
#|
#|# ---------------------------------------------------------------- records (rules, groups)
#|
#|def _save_record(path, record, check):
#|    disk = load_json(path, None)
#|    if check and disk and disk.get("_rev", 0) != record.get("_rev", 0):
#|        raise ConflictError(disk)
#|    record["_rev"] = (disk.get("_rev", 0) if disk else 0) + 1
#|    record["saved_by"], record["saved_at"] = current_user(), now()
#|    save_json(path, record)
#|    return record
#|
#|
#|def _modify_record(path, change):
#|    disk = load_json(path, None)
#|    if disk is None:
#|        return None
#|    change(disk)
#|    return _save_record(path, disk, check=False)
#|
#|
#|def rule_path(rule_id):
#|    return paths.rules / f"{rule_id}.json"
#|
#|
#|def group_path(group_id):
#|    return paths.groups / f"{group_id}.json"
#|
#|
#|def load_rules():
#|    rules = [load_json(p, None) for p in sorted(paths.rules.glob("*.json"))]
#|    return {"rules": [r for r in rules if r], "manual_controls": load_settings()["manual_controls"]}
#|
#|
#|def new_rule_id():
#|    while True:
#|        rid = "R-" + secrets.token_hex(3).upper()
#|        if not rule_path(rid).exists():
#|            return rid
#|
#|
#|def save_rule(rule, check=True):
#|    return _save_record(rule_path(rule["id"]), rule, check)
#|
#|
#|def modify_rule(rule_id, change):
#|    return _modify_record(rule_path(rule_id), change)
#|
#|
#|def delete_rule(rule_id):
#|    rule_path(rule_id).unlink(missing_ok=True)
#|
#|
#|def mark_rule_reviewed(rule_id, check_hash, release, note="Reviewed after STIG update - still valid"):
#|    def change(r):
#|        r["check_hash"] = check_hash
#|        r.setdefault("review_log", []).append({"at": now(), "by": current_user(), "release": release, "note": note})
#|    return modify_rule(rule_id, change)
#|
#|
#|RULES_EXPORT_FORMAT = "stigtool-rules"
#|# Fields that identify people or only make sense on this machine; never exported.
#|PERSONAL_FIELDS = ("created_by", "saved_by", "updated_by", "_rev", "history", "review_log")
#|
#|
#|def clean_rule(rule):
#|    """A copy of a rule without author names, edit history or local revision counters."""
#|    out = {k: copy.deepcopy(v) for k, v in rule.items() if k not in PERSONAL_FIELDS}
#|    for t in out.get("tests", []):
#|        t.pop("saved_by", None)
#|    return out
#|
#|
#|def bundled_rules_path():
#|    """The rules file shipped with the program (rules/stigtool_rules.json next to main.py)."""
#|    return paths.root / "rules" / "stigtool_rules.json"
#|
#|
#|def export_rules(path, rules=None):
#|    """Write every rule (cleaned) plus the manual-only list to one JSON file. Returns the rule count."""
#|    db = load_rules()
#|    chosen = rules if rules is not None else db["rules"]
#|    data = {"format": RULES_EXPORT_FORMAT, "version": 1, "exported_at": now(),
#|            "manual_controls": sorted(db.get("manual_controls", [])),
#|            "rules": [clean_rule(r) for r in sorted(chosen, key=lambda r: (r["stig_id"], r["vuln_id"], r["id"]))]}
#|    Path(path).parent.mkdir(parents=True, exist_ok=True)
#|    # One rule per line: still valid JSON, diff-friendly, and safe to copy / paste or split into parts.
#|    head = {k: v for k, v in data.items() if k != "rules"}
#|    lines = [json.dumps(r, ensure_ascii=True, separators=(",", ":")) for r in data["rules"]]
#|    text = json.dumps(head, ensure_ascii=True, separators=(",", ":"))[:-1] + ',"rules":[\n' + ",\n".join(lines) + "\n]}\n"
#|    json.loads(text)  # never write a file that would not load back
#|    with open(path, "w", encoding="utf-8", newline="\n") as f:
#|        f.write(text)
#|    return len(data["rules"])
#|
#|
#|def import_rules(path):
#|    """Add rules from an export file. Rules whose ID already exists here are left alone.
#|
#|    Returns {"added", "skipped", "manual_added"}.
#|    """
#|    data = load_json(path, None)
#|    if not isinstance(data, dict) or data.get("format") != RULES_EXPORT_FORMAT:
#|        raise ValueError(f"{Path(path).name} is not a STIGTOOL rules export")
#|    report = {"added": 0, "skipped": 0, "manual_added": 0}
#|    for rule in data.get("rules", []):
#|        if not rule.get("id") or rule_path(rule["id"]).exists():
#|            report["skipped"] += 1
#|            continue
#|        rule = clean_rule(rule)
#|        rule.setdefault("history", [])
#|        rule["imported_at"] = now()
#|        save_rule(rule, check=False)
#|        report["added"] += 1
#|    incoming = set(data.get("manual_controls", []))
#|
#|    def change(s):
#|        before = set(s["manual_controls"])
#|        report["manual_added"] = len(incoming - before)
#|        s["manual_controls"] = sorted(before | incoming)
#|    update_settings(change)
#|    return report
#|
#|
#|def load_groups():
#|    groups = [load_json(p, None) for p in sorted(paths.groups.glob("*.json"))]
#|    s = load_settings()
#|    return {"groups": [g for g in groups if g], "device_overrides": s["device_overrides"],
#|            "known_devices": s["known_devices"]}
#|
#|
#|def save_group(group, check=True):
#|    return _save_record(group_path(group["id"]), group, check)
#|
#|
#|def modify_group(group_id, change):
#|    return _modify_record(group_path(group_id), change)
#|
#|
#|def delete_group(group_id):
#|    group_path(group_id).unlink(missing_ok=True)
#|
#|    def change(s):
#|        s["device_overrides"] = {h: g for h, g in s["device_overrides"].items() if g != group_id}
#|    update_settings(change)
#|
#|
#|# ---------------------------------------------------------------- edit locks
#|
#|def _lock_path(kind, record_id):
#|    return paths.locks / f"{kind}_{record_id}.lock"
#|
#|
#|def lock_holder(kind, record_id):
#|    """Who else is editing this record, or None. Locks older than LOCK_HOURS are ignored."""
#|    lock = load_json(_lock_path(kind, record_id), None)
#|    if not lock:
#|        return None
#|    if lock.get("user") == current_user() and lock.get("host") == current_host():
#|        return None
#|    try:
#|        age = datetime.datetime.now() - datetime.datetime.fromisoformat(lock["since"])
#|        if age.total_seconds() > LOCK_HOURS * 3600:
#|            return None
#|    except (KeyError, ValueError):
#|        return None
#|    return lock
#|
#|
#|def acquire_lock(kind, record_id, force=False):
#|    """Returns the other holder (and does nothing) if someone else has it, else takes the lock."""
#|    holder = lock_holder(kind, record_id)
#|    if holder and not force:
#|        return holder
#|    save_json(_lock_path(kind, record_id), {"user": current_user(), "host": current_host(), "since": now()})
#|    return None
#|
#|
#|def release_lock(kind, record_id):
#|    path = _lock_path(kind, record_id)
#|    lock = load_json(path, None)
#|    if lock and lock.get("user") == current_user() and lock.get("host") == current_host():
#|        path.unlink(missing_ok=True)
#|
#|
#|# ---------------------------------------------------------------- checklist templates
#|
#|def _upgrade(cat):
#|    """Fill in fields added after a catalog was first imported."""
#|    for s in cat["stigs"]:
#|        s.setdefault("short", checklist.short_name(s.get("title"), s["stig_id"]))
#|    if "viewer" not in cat:
#|        try:
#|            cat["viewer"] = checklist.viewer_of(template_path(cat), cat["format"])
#|        except OSError:
#|            cat["viewer"] = checklist.FORMAT_LABELS[cat["format"]]
#|    return cat
#|
#|
#|_catalog_cache = {}
#|
#|
#|def list_catalogs():
#|    """All imported templates, oldest import first. Cached by file time (catalogs never change)."""
#|    cats = []
#|    for p in paths.templates.glob("*.json"):
#|        key = (str(p), p.stat().st_mtime)
#|        if key not in _catalog_cache:
#|            cat = load_json(p, None)
#|            _catalog_cache[key] = _upgrade(cat) if cat else None
#|        if _catalog_cache[key]:
#|            cats.append(_catalog_cache[key])
#|    return sorted(cats, key=lambda c: c["imported_at"])
#|
#|
#|def _key(cat, stig):
#|    return checklist.release_key(stig.get("version"), stig.get("release_info")), cat["imported_at"]
#|
#|
#|def releases_for(stig_id):
#|    """[(catalog, stig)] for every imported file containing this STIG, oldest release first."""
#|    found = [(cat, s) for cat in list_catalogs() for s in cat["stigs"] if s["stig_id"] == stig_id]
#|    return sorted(found, key=lambda cs: _key(*cs))
#|
#|
#|def control_index():
#|    """The newest release of each STIG (any format), keyed by stig_id.
#|
#|    {stig_id: {"family", "short", "title", "release_info", "release", "controls": {vuln_id: control},
#|               "order", "formats": {fmt: release label of newest file in that format}}}
#|    """
#|    index, fmt_keys = {}, {}
#|    for cat in list_catalogs():
#|        for stig in cat["stigs"]:
#|            sid, key = stig["stig_id"], _key(cat, stig)
#|            label = checklist.release_label(stig.get("version"), stig.get("release_info"))
#|            entry = index.get(sid)
#|            if entry is None or key >= entry["_key"]:
#|                index[sid] = {
#|                    "_key": key,
#|                    "family": stig["family"], "short": stig["short"], "title": stig["title"],
#|                    "release_info": stig["release_info"], "release": label, "version": stig.get("version"),
#|                    "template_id": cat["id"],
#|                    "controls": {c["vuln_id"]: c for c in stig["controls"]},
#|                    "order": [c["vuln_id"] for c in stig["controls"]],
#|                    "formats": entry["formats"] if entry else {},
#|                }
#|            fk = (sid, cat["format"])
#|            if fk not in fmt_keys or key >= fmt_keys[fk]:
#|                fmt_keys[fk] = key
#|                index[sid]["formats"][cat["format"]] = label
#|    return dict(sorted(index.items(), key=lambda kv: kv[1]["short"].lower()))
#|
#|
#|def templates_for(stig_id):
#|    """Newest-release template of each format (ckl / cklb) that contains this STIG."""
#|    found = {}
#|    for cat, _ in releases_for(stig_id):
#|        found[cat["format"]] = cat
#|    return found
#|
#|
#|def template_path(cat):
#|    return paths.templates / cat["file"]
#|
#|
#|def import_template(src, rules_db=None):
#|    """Copy a CKL/CKLB into data/templates (read-only) and build its control catalog.
#|
#|    Returns (catalog or None, report lines). A file identical to one already imported is skipped.
#|    """
#|    src = Path(src)
#|    parsed = checklist.read_checklist(src)
#|    digest = sha256_file(src)
#|    label = checklist.FORMAT_LABELS[parsed["format"]]
#|    for cat in list_catalogs():
#|        if cat["sha256"] == digest:
#|            return None, [f"{src.name}: already imported on {cat['imported_at'][:10]} - skipped."]
#|
#|    before = control_index()
#|    families = "-".join(s["family"] for s in parsed["stigs"]) or "CHECKLIST"
#|    tid = f"{families}_{parsed['format']}_{stamp()}_{secrets.token_hex(2)}"
#|    dest_name = f"{tid}{src.suffix.lower()}"
#|    dest = paths.templates / dest_name
#|    shutil.copy2(src, dest)
#|    os.chmod(dest, stat.S_IREAD)  # source templates are never edited
#|    catalog = {
#|        "id": tid, "file": dest_name, "source_name": src.name, "format": parsed["format"],
#|        "viewer": parsed["viewer"], "sha256": digest, "imported_at": now(), "imported_by": current_user(),
#|        "stigs": parsed["stigs"],
#|    }
#|    save_json(paths.templates / f"{tid}.json", catalog)
#|
#|    rules = (rules_db or load_rules())["rules"]
#|    report = []
#|    for stig in parsed["stigs"]:
#|        rel = checklist.release_label(stig.get("version"), stig.get("release_info"))
#|        head = f"{stig['short']} {rel} - {label} ({parsed['viewer']})"
#|        old = before.get(stig["stig_id"])
#|        new_key = checklist.release_key(stig.get("version"), stig.get("release_info"))
#|        if not old:
#|            report.append(f"{head}\n   NEW STIG: {len(stig['controls'])} controls added to the work queue.")
#|            continue
#|        old_key = checklist.release_key(old.get("version"), old.get("release_info"))
#|        if new_key < old_key:
#|            report.append(f"{head}\n   OLDER than the current {old['release']} - kept for history only.")
#|            continue
#|        if new_key == old_key:
#|            report.append(f"{head}\n   Same release as already imported (now available in this format too).")
#|            continue
#|        diffs = checklist.compare_controls(list(old["controls"].values()), stig["controls"])
#|        changed_checks = {d["vuln_id"] for d in diffs if d["kind"] == "changed" and "check" in d["fields"]}
#|        affected = [r for r in rules if r["stig_id"] == stig["stig_id"] and r.get("state") == "active"
#|                    and (r["vuln_id"] in changed_checks
#|                         or r["vuln_id"] in {d["vuln_id"] for d in diffs if d["kind"] == "removed"})]
#|        counts = {k: sum(1 for d in diffs if d["kind"] == k) for k in ("added", "removed", "changed")}
#|        report.append(f"{head}\n   NEW RELEASE (was {old['release']}): {counts['added']} added, "
#|                      f"{counts['removed']} removed, {counts['changed']} changed."
#|                      + (f"\n   {len(affected)} active rule(s) need review: "
#|                         + ", ".join(f"{r['vuln_id']} ({r['id']})" for r in affected) if affected
#|                         else "\n   No active rules are affected.")
#|                      + "\n   Use 'Compare releases' on the Checklists tab to see the changes.")
#|    return catalog, report
#|
#|
#|def remove_template(cat):
#|    path = template_path(cat)
#|    if path.exists():
#|        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
#|        path.unlink()
#|    (paths.templates / f"{cat['id']}.json").unlink(missing_ok=True)
#|
#|
#|def find_control_version(stig_id, vuln_id, check_hash):
#|    """(release label, control) of the release whose check text has this fingerprint, newest first."""
#|    for cat, stig in reversed(releases_for(stig_id)):
#|        for c in stig["controls"]:
#|            if c["vuln_id"] == vuln_id and c["check_hash"] == check_hash:
#|                return checklist.release_label(stig.get("version"), stig.get("release_info")), c
#|    return None, None
#|
#|
#|# ---------------------------------------------------------------- runs and scripts
#|
#|def run_path(run_id):
#|    return paths.runs / f"{run_id}.json"
#|
#|
#|def save_run(run):
#|    run["saved_by"], run["saved_at"] = current_user(), now()
#|    save_json(run_path(run["id"]), run)
#|    return run_path(run["id"]).stat().st_mtime
#|
#|
#|def list_runs():
#|    return sorted(paths.runs.glob("*.json"), reverse=True)
#|
#|
#|def load_run(path):
#|    return load_json(path, None)
#|
#|
#|def archive_evidence(src):
#|    """Keep an untouched copy of the imported SolarWinds file, original name preserved."""
#|    src = Path(src)
#|    folder = paths.evidence / f"{stamp()}_{secrets.token_hex(2)}"
#|    folder.mkdir(parents=True, exist_ok=True)
#|    dest = folder / src.name
#|    shutil.copy2(src, dest)
#|    return dest
#|
#|
#|def save_script_record(record):
#|    save_json(paths.scripts / f"{record['script_id']}.json", record)
#|
#|
#|def load_script_record(script_id):
#|    if not script_id:
#|        return None
#|    return load_json(paths.scripts / f"{script_id}.json", None)
#|
#|
#|# ---------------------------------------------------------------- one-time upgrade of older data
#|
#|def migrate_legacy():
#|    """Split the single rules.json / groups.json used by the first version into per-record files."""
#|    legacy_rules = paths.data / "rules.json"
#|    if legacy_rules.exists():
#|        db = load_json(legacy_rules, {})
#|        for r in db.get("rules", []):
#|            if not rule_path(r["id"]).exists():
#|                save_json(rule_path(r["id"]), r)
#|        manual = db.get("manual_controls", [])
#|        update_settings(lambda s: s.__setitem__("manual_controls", sorted(set(s["manual_controls"]) | set(manual))))
#|        legacy_rules.rename(legacy_rules.with_name(f"rules.json.migrated-{stamp()}"))
#|    legacy_groups = paths.data / "groups.json"
#|    if legacy_groups.exists():
#|        db = load_json(legacy_groups, {})
#|        for g in db.get("groups", []):
#|            if not group_path(g["id"]).exists():
#|                save_json(group_path(g["id"]), g)
#|
#|        def change(s):
#|            s["device_overrides"].update({k.upper(): v for k, v in db.get("device_overrides", {}).items()})
#|            s["known_devices"].update({k.upper(): v for k, v in db.get("known_devices", {}).items()})
#|        update_settings(change)
#|        legacy_groups.rename(legacy_groups.with_name(f"groups.json.migrated-{stamp()}"))
#@ END
#@ FILE tests/test_core.py SHA 55d0281fbbf79e4961b0dc2fb6461066de91b70486ad95a6dd95418b9ef7f827 CHUNK 1 OF 1
#|"""Core tests. Run from the project root:  python -m unittest discover tests"""
#|import json
#|import shutil
#|import sys
#|import tempfile
#|import unittest
#|from pathlib import Path
#|
#|HERE = Path(__file__).resolve().parent
#|sys.path.insert(0, str(HERE.parent / "src"))
#|
#|import assess  # noqa: E402
#|import checklist  # noqa: E402
#|import collect  # noqa: E402
#|import rules  # noqa: E402
#|import store  # noqa: E402
#|
#|FIX = HERE / "fixtures"
#|CKLB = FIX / "ios-xe-switch-ndm.cklb"
#|CKL = FIX / "ios-xe-switch-rtr.ckl"
#|# Tests that need the blank DISA checklists are skipped if tests/fixtures/ has not been filled in yet.
#|needs_fixtures = unittest.skipUnless(CKLB.exists() and CKL.exists(),
#|                                     "copy a blank IOS-XE Switch NDM .cklb and RTR .ckl into tests/fixtures/")
#|
#|# Made-up SolarWinds "Execute Command Script" output (documentation IP ranges, lab hostnames).
#|_BAR = "_" * 76
#|_BODY = """! collection_profile_id: iosxe_ndm_pilot_v1
#|! source_ckl_family: NDM
#|
#|! sources: V-220519,V-220521
#|! CMD: show run | section archive
#|show run | section archive
#|archive
#| log config
#|  logging enable
#|  logging size 1000
#|  notify syslog contenttype plaintext
#|
#|! sources: V-220524
#|! CMD: show running-config | include ^login block-for
#|show running-config | include ^login block-for
#|login block-for 900 attempts 3 within 120
#|"""
#|SW_TEXT = f"""{_BAR}
#|
#|9/29/2026 8:22:14 AM : Started test CKL builder job
#|
#|Execute Command Script on Devices
#|4 devices selected
#|{_BAR}
#|
#|LAB-EC-router (192.0.2.97):
#|
#|ERROR: Connection Refused by 192.0.2.97
#|{_BAR}
#|
#|LAB-1A-ACCESS (192.0.2.33):
#|
#|{_BODY}
#|{_BAR}
#|
#|LAB-1C-ACCESS (192.0.2.35):
#|
#|{_BODY}
#|{_BAR}
#|
#|LAB-1D-ACCESS (2001:DB8::36):
#|
#|{_BODY}
#|{_BAR}
#|9/29/2026 8:23:21 AM : Completed test CKL builder job
#|{_BAR}
#|"""
#|
#|
#|def sw_file(folder):
#|    path = Path(folder) / "solarwinds_output.txt"
#|    path.write_text(SW_TEXT, encoding="utf-8")
#|    return path
#|NDM = "Cisco_IOS_XE_Switch_NDM_STIG"
#|RTR = "Cisco_IOS_XE_Switch_RTR_STIG"
#|
#|VTY = """line con 0
#| exec-timeout 10 0
#|line vty 0 4
#| exec-timeout 10 0
#| transport input ssh
#|line vty 5 15
#| exec-timeout 30 0
#| transport input telnet ssh"""
#|
#|
#|def ok(text):
#|    return {"status": rules.classify_output(text), "text": text}
#|
#|
#|def cond(**kw):
#|    return {**rules.NEW_CONDITION, "command": "show run", **kw}
#|
#|
#|def rule(conds, mode="ALL", na=None, commands=("show run",)):
#|    r = {"commands": list(commands), "pass_logic": {"mode": mode, "conditions": conds}}
#|    if na:
#|        r["na_enabled"] = True
#|        r["na_logic"] = {"mode": "ALL", "conditions": na}
#|    return r
#|
#|
#|@needs_fixtures
#|class ChecklistTests(unittest.TestCase):
#|    def setUp(self):
#|        self.tmp = Path(tempfile.mkdtemp())
#|
#|    def tearDown(self):
#|        shutil.rmtree(self.tmp, ignore_errors=True)
#|
#|    def test_read_both_formats(self):
#|        b = checklist.read_checklist(CKLB)
#|        self.assertEqual(b["format"], "cklb")
#|        self.assertEqual(b["stigs"][0]["stig_id"], NDM)
#|        self.assertEqual(b["stigs"][0]["family"], "NDM")
#|        self.assertEqual(len(b["stigs"][0]["controls"]), 42)
#|        c = checklist.read_checklist(CKL)
#|        self.assertEqual(c["format"], "ckl")
#|        self.assertEqual(c["stigs"][0]["stig_id"], RTR)
#|        self.assertEqual(c["stigs"][0]["family"], "RTR")
#|        self.assertTrue(len(c["stigs"][0]["controls"]) > 0)
#|        self.assertTrue(all(x["vuln_id"].startswith("V-") for x in c["stigs"][0]["controls"]))
#|
#|    def test_cklb_patch_and_validate(self):
#|        dst = self.tmp / "out.cklb"
#|        upd = {(NDM, "V-220518"): {"status": "open", "finding_details": "line1\nline2 <&> \u2026", "comments": "c"},
#|               (NDM, "V-220519"): {"status": "not_applicable", "finding_details": None, "comments": None}}
#|        checklist.write_patched(CKLB, dst, upd, title="GROUP_NDM")
#|        ok_, lines = checklist.validate(CKLB, dst)
#|        self.assertTrue(ok_, lines)
#|        data = json.loads(dst.read_text(encoding="utf-8"))
#|        r = {x["group_id"]: x for x in data["stigs"][0]["rules"]}
#|        self.assertEqual(r["V-220518"]["status"], "open")
#|        self.assertEqual(r["V-220518"]["finding_details"], "line1\nline2 <&> \u2026")
#|        self.assertEqual(r["V-220519"]["status"], "not_applicable")
#|        self.assertEqual(r["V-220519"]["finding_details"], "")
#|        self.assertEqual(data["title"], "GROUP_NDM")
#|        # tampering with a protected field is caught
#|        data["stigs"][0]["rules"][0]["check_content"] = "changed"
#|        dst.write_text(json.dumps(data), encoding="utf-8")
#|        ok_, lines = checklist.validate(CKLB, dst)
#|        self.assertFalse(ok_)
#|        self.assertTrue(any("check_content" in l for l in lines))
#|
#|    def test_ckl_patch_and_validate(self):
#|        first = checklist.read_checklist(CKL)["stigs"][0]["controls"][0]["vuln_id"]
#|        dst = self.tmp / "out.ckl"
#|        # no updates -> byte-identical copy
#|        checklist.write_patched(CKL, dst, {})
#|        self.assertEqual(dst.read_bytes(), CKL.read_bytes())
#|        upd = {(RTR, first): {"status": "not_a_finding", "finding_details": "a < b & c", "comments": "ok"}}
#|        checklist.write_patched(CKL, dst, upd)
#|        ok_, lines = checklist.validate(CKL, dst)
#|        self.assertTrue(ok_, lines)
#|        again = checklist.read_checklist(dst)["stigs"][0]["controls"][0]
#|        self.assertEqual(again["template_status"], "not_a_finding")
#|        text = dst.read_text(encoding="utf-8")
#|        self.assertIn("<FINDING_DETAILS>a &lt; b &amp; c</FINDING_DETAILS>", text)
#|        self.assertTrue(text.startswith('<?xml version="1.0" encoding="UTF-8"?>\n<!--DISA STIG Viewer :: 2.10-->'))
#|        tampered = text.replace("<ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA>", "<ATTRIBUTE_DATA>low</ATTRIBUTE_DATA>", 1)
#|        dst.write_text(tampered, encoding="utf-8")
#|        self.assertFalse(checklist.validate(CKL, dst)[0])
#|
#|    def test_unknown_control_rejected(self):
#|        with self.assertRaises(checklist.ChecklistError):
#|            checklist.write_patched(CKLB, self.tmp / "x.cklb", {(NDM, "V-0"): {"status": "open"}})
#|
#|
#|class RuleTests(unittest.TestCase):
#|    def test_has_and_lacks(self):
#|        out = {"show run": ok(VTY)}
#|        self.assertEqual(rules.evaluate(rule([cond(check="has", text="transport input ssh")]), out)["status"],
#|                         "not_a_finding")
#|        self.assertEqual(rules.evaluate(rule([cond(check="lacks", text="telnet")]), out)["status"], "open")
#|
#|    def test_every_section(self):
#|        out = {"show run": ok(VTY)}
#|        r = rule([cond(scope="every", section="line vty", check="has", text="transport input ssh", how="whole line")])
#|        res = rules.evaluate(r, out)
#|        self.assertEqual(res["status"], "open")  # vty 5 15 has "telnet ssh", not a whole-line match
#|        self.assertEqual(res["marks"]["show run"][5], "problem")  # header of failing section
#|        self.assertEqual(res["marks"]["show run"][4], "match")
#|        r = rule([cond(scope="any", section="line vty", check="has", text="transport input ssh", how="whole line")])
#|        self.assertEqual(rules.evaluate(r, out)["status"], "not_a_finding")
#|
#|    def test_number_in_section(self):
#|        out = {"show run": ok(VTY)}
#|        r = rule([cond(scope="every", section="line", check="number", text="exec-timeout", op="<=", value="10")])
#|        self.assertEqual(rules.evaluate(r, out)["status"], "open")
#|        r = rule([cond(scope="every", section="line", exclude="re:5 15", check="number", text="exec-timeout",
#|                       op="<=", value="10")])
#|        self.assertEqual(rules.evaluate(r, out)["status"], "not_a_finding")
#|
#|    def test_count_and_pattern(self):
#|        out = {"show run": ok("ntp server 1.1.1.1\nntp server 2.2.2.2\n")}
#|        self.assertEqual(rules.evaluate(rule([cond(check="count", text="ntp server", op=">=", value="2")]),
#|                                        out)["status"], "not_a_finding")
#|        out = {"show run": ok(VTY)}
#|        r = rule([cond(check="pattern", text=r"line vty 0 4\n(\s.*\n)*?\s+transport input ssh")])
#|        self.assertEqual(rules.evaluate(r, out)["status"], "not_a_finding")
#|        r = rule([cond(check="no_pattern", text=r"transport input telnet")])
#|        self.assertEqual(rules.evaluate(r, out)["status"], "open")
#|
#|    def test_not_applicable_first(self):
#|        out = {"show run": ok("no ip http server\n")}
#|        r = rule([cond(check="has", text="ip http max-connections")],
#|                 na=[cond(check="lacks", text="ip http secure-server")])
#|        self.assertEqual(rules.evaluate(r, out)["status"], "not_applicable")
#|
#|    def test_missing_and_invalid_never_pass(self):
#|        r = rule([cond(check="lacks", text="telnet")])
#|        self.assertEqual(rules.evaluate(r, {})["status"], "not_reviewed")
#|        bad = {"show run": ok("        ^\n% Invalid input detected at '^' marker.")}
#|        self.assertEqual(rules.evaluate(r, bad)["status"], "not_reviewed")
#|        # empty output is real evidence: "lacks" passes
#|        self.assertEqual(rules.evaluate(r, {"show run": ok("")})["status"], "not_a_finding")
#|
#|    def test_outcome_text_and_expected_open(self):
#|        r = rule([cond(check="has", text="x")])
#|        r["outcome_text"] = {"open": "Recommend risk acceptance on {devices} ({device_count}): vendor limit."}
#|        self.assertEqual(rules.outcome_text(r, "open", ["SW1", "SW2"]),
#|                         "Recommend risk acceptance on SW1, SW2 (2): vendor limit.")
#|        self.assertEqual(rules.outcome_text(r, "not_a_finding", ["SW1"]), "")
#|        r["expected_open"] = True
#|        r["outcome_text"] = {}
#|        self.assertTrue(any("intentional" in e for e in rules.activation_problems(r)))
#|
#|    def test_activation_requires_tests(self):
#|        r = rule([cond(check="has", text="login block-for")])
#|        self.assertTrue(rules.activation_problems(r))
#|        r["tests"] = [{"name": "good", "expected": "not_a_finding", "outputs": {"show run": "login block-for 900"}},
#|                      {"name": "bad", "expected": "open", "outputs": {"show run": ""}}]
#|        self.assertEqual(rules.activation_problems(r), [])
#|
#|
#|class CollectTests(unittest.TestCase):
#|    @needs_fixtures
#|    def test_parse_sample(self):
#|        parsed = collect.parse_output(SW_TEXT)
#|        devs = {d["host"]: d for d in parsed["devices"]}
#|        self.assertEqual(len(devs), 4)
#|        self.assertEqual(devs["LAB-EC-router"]["status"], "error")
#|        self.assertIn("Connection Refused", devs["LAB-EC-router"]["error"])
#|        d = devs["LAB-1A-ACCESS"]
#|        self.assertEqual(d["ip"], "192.0.2.33")
#|        self.assertEqual(devs["LAB-1D-ACCESS"]["ip"], "2001:DB8::36")
#|        self.assertEqual(set(d["outputs"]), {"show run | section archive",
#|                                             "show running-config | include ^login block-for"})
#|        self.assertEqual(d["outputs"]["show running-config | include ^login block-for"]["text"],
#|                         "login block-for 900 attempts 3 within 120")
#|        self.assertTrue(d["outputs"]["show run | section archive"]["text"].startswith("archive\n log config"))
#|
#|    def test_script_round_trip(self):
#|        text, sid = collect.build_script({"show version": {"NDM V-1"}, "show clock": {"NDM V-2"}}, ["G"])
#|        self.assertIn("! CMD: show clock", text)
#|        body = text.replace("\nshow clock\n", "\nshow clock\n12:00 UTC\n", 1)  # device echo, then output
#|        fake = f"{'_' * 60}\nSW1 (10.0.0.1):\n\n{body}\n{'_' * 60}\n"
#|        parsed = collect.parse_output(fake)
#|        dev = parsed["devices"][0]
#|        self.assertEqual(dev["script_id"], sid)
#|        self.assertEqual(dev["outputs"]["show clock"]["text"], "12:00 UTC")
#|
#|    def test_fallback_without_markers(self):
#|        text = f"{'_' * 40}\nSW1 (1.1.1.1):\nSW1#show clock\n12:00\nSW1#show version\nCisco IOS XE\n{'_' * 40}"
#|        dev = collect.parse_output(text, {"show clock", "show version"})["devices"][0]
#|        self.assertEqual(dev["outputs"]["show clock"]["text"], "12:00")
#|        self.assertEqual(dev["outputs"]["show version"]["text"], "Cisco IOS XE")
#|
#|
#|class StoreCase(unittest.TestCase):
#|    """Runs against a throwaway project folder."""
#|
#|    def setUp(self):
#|        self.tmp = Path(tempfile.mkdtemp())
#|        self.old = store.paths
#|        store.use_root(self.tmp)
#|
#|    def tearDown(self):
#|        store.paths = self.old
#|        shutil.rmtree(self.tmp, ignore_errors=True)
#|
#|    def make_release(self, name, release, check_change=None, add=None, drop=None):
#|        """Copy the NDM CKLB fixture as another DISA release with optional control changes."""
#|        data = json.loads(CKLB.read_text(encoding="utf-8"))
#|        stig = data["stigs"][0]
#|        stig["release_info"] = f"Release: {release} Benchmark Date: 01 Jul 2026"
#|        rules_ = stig["rules"]
#|        if check_change:
#|            next(r for r in rules_ if r["group_id"] == check_change)["check_content"] += "\nNEW SENTENCE."
#|        if add:
#|            extra = json.loads(json.dumps(rules_[-1]))
#|            extra["group_id"] = add
#|            rules_.append(extra)
#|        if drop:
#|            stig["rules"] = [r for r in rules_ if r["group_id"] != drop]
#|        path = self.tmp / name
#|        path.write_text(json.dumps(data), encoding="utf-8")
#|        return path
#|
#|
#|def active_rule(index, stig_id, vuln_id, command, cond_, rid, tests=None, comment=""):
#|    return {"id": rid, "stig_id": stig_id, "vuln_id": vuln_id, "name": "Default", "state": "active",
#|            "is_default": True, "version": 1, "commands": [command], "comment": comment,
#|            "check_hash": index[stig_id]["controls"][vuln_id]["check_hash"],
#|            "pass_logic": {"mode": "ALL", "conditions": [{**rules.NEW_CONDITION, "command": command, **cond_}]},
#|            "tests": tests or []}
#|
#|
#|class TeamStoreTests(StoreCase):
#|    def test_migrates_first_version_data(self):
#|        (store.paths.data / "rules.json").write_text(json.dumps(
#|            {"next_id": 2, "rules": [{"id": "R-0001", "stig_id": NDM, "vuln_id": "V-1", "commands": []}],
#|             "manual_controls": [f"{NDM}|V-2"]}), encoding="utf-8")
#|        (store.paths.data / "groups.json").write_text(json.dumps(
#|            {"groups": [{"id": "G1", "stigs": [NDM]}], "device_overrides": {"sw1": "G1"},
#|             "known_devices": {"SW1": "1.1.1.1"}}), encoding="utf-8")
#|        store.ensure_folders()
#|        self.assertEqual([r["id"] for r in store.load_rules()["rules"]], ["R-0001"])
#|        self.assertEqual(store.load_rules()["manual_controls"], [f"{NDM}|V-2"])
#|        g = store.load_groups()
#|        self.assertEqual(g["groups"][0]["id"], "G1")
#|        self.assertEqual(g["device_overrides"], {"SW1": "G1"})
#|        self.assertFalse((store.paths.data / "rules.json").exists())
#|        self.assertTrue(list(store.paths.data.glob("rules.json.migrated-*")))
#|
#|    def test_conflicting_saves_are_caught(self):
#|        rule = store.save_rule({"id": store.new_rule_id(), "name": "a"}, check=False)
#|        mine = json.loads(json.dumps(rule))
#|        theirs = json.loads(json.dumps(rule))
#|        theirs["name"] = "theirs"
#|        store.save_rule(theirs)
#|        mine["name"] = "mine"
#|        with self.assertRaises(store.ConflictError) as ctx:
#|            store.save_rule(mine)
#|        self.assertEqual(ctx.exception.current["name"], "theirs")
#|
#|    def test_settings_updates_do_not_clobber(self):
#|        store.set_override("sw1", "G1")
#|        store.set_manual(f"{NDM}|V-1", True)
#|        store.add_known_devices({"sw2": "2.2.2.2"})
#|        s = store.load_settings()
#|        self.assertEqual(s["device_overrides"], {"SW1": "G1"})
#|        self.assertEqual(s["manual_controls"], [f"{NDM}|V-1"])
#|        self.assertEqual(s["known_devices"], {"SW2": "2.2.2.2"})
#|
#|    def test_rules_export_import_round_trip(self):
#|        rule = {"id": "R-EXP1", "stig_id": NDM, "vuln_id": "V-1", "name": "x", "commands": ["show run"],
#|                "history": [{"old": 1}], "review_log": [{"by": "someone"}],
#|                "tests": [{"name": "t", "expected": "open", "outputs": {"show run": ""}, "saved_by": "someone"}]}
#|        store.save_rule(rule, check=False)
#|        store.set_manual(f"{NDM}|V-2", True)
#|        out = self.tmp / "export.json"
#|        self.assertEqual(store.export_rules(out), 1)
#|        text = out.read_text(encoding="utf-8")
#|        for secret in ("someone", store.current_user(), "history", "saved_by", "_rev"):
#|            if secret:
#|                self.assertNotIn(f'"{secret}"' if secret in ("history", "saved_by", "_rev") else secret, text)
#|        self.assertTrue(text.isascii())
#|        # into a fresh project: added; second import skips existing
#|        other = Path(tempfile.mkdtemp())
#|        try:
#|            store.use_root(other)
#|            self.assertEqual(store.import_rules(out), {"added": 1, "skipped": 0, "manual_added": 1})
#|            self.assertEqual(store.import_rules(out)["skipped"], 1)
#|            got = store.load_rules()
#|            self.assertEqual(got["rules"][0]["commands"], ["show run"])
#|            self.assertEqual(got["manual_controls"], [f"{NDM}|V-2"])
#|        finally:
#|            store.use_root(self.tmp)
#|            shutil.rmtree(other, ignore_errors=True)
#|        with self.assertRaises(ValueError):
#|            bad = self.tmp / "bad.json"
#|            bad.write_text("{}", encoding="utf-8")
#|            store.import_rules(bad)
#|
#|    def test_locks(self):
#|        self.assertIsNone(store.acquire_lock("rule", "R-1"))
#|        store.save_json(store.paths.locks / "rule_R-1.lock",
#|                        {"user": "someone-else", "host": "PC9", "since": store.now()})
#|        holder = store.acquire_lock("rule", "R-1")
#|        self.assertEqual(holder["user"], "someone-else")
#|        self.assertIsNone(store.acquire_lock("rule", "R-1", force=True))
#|        store.release_lock("rule", "R-1")
#|        self.assertFalse((store.paths.locks / "rule_R-1.lock").exists())
#|
#|
#|@needs_fixtures
#|class ReleaseTests(StoreCase):
#|    def test_new_release_flags_rules_and_diffs(self):
#|        store.import_template(CKLB)
#|        index = store.control_index()
#|        store.save_rule(active_rule(index, NDM, "V-220524", "show run", {"check": "has", "text": "login"}, "R-A"),
#|                        check=False)
#|        store.save_rule(active_rule(index, NDM, "V-220518", "show run", {"check": "has", "text": "x"}, "R-B"),
#|                        check=False)
#|        newer = self.make_release("ndm_r7.cklb", 7, check_change="V-220524", add="V-999999", drop="V-220518")
#|        cat, report = store.import_template(newer)
#|        text = "\n".join(report)
#|        self.assertIn("NEW RELEASE (was V3R6", text)
#|        self.assertIn("1 added, 1 removed, 1 changed", text)
#|        self.assertIn("V-220524 (R-A)", text)
#|        self.assertIn("V-220518 (R-B)", text)
#|        index = store.control_index()
#|        self.assertEqual(index[NDM]["release"], "V3R7 (01 Jul 2026)")
#|        rules_db = store.load_rules()
#|        state = assess.control_state(rules_db, NDM, index[NDM]["controls"]["V-220524"])
#|        self.assertEqual(state, "STIG changed - review")
#|        old_rel, old_ctrl = store.find_control_version(NDM, "V-220524", store.rule_path and
#|                                                       rules_db["rules"][0]["check_hash"])
#|        self.assertTrue(old_rel.startswith("V3R6"))
#|        # mark reviewed clears the flag
#|        store.mark_rule_reviewed("R-A", index[NDM]["controls"]["V-220524"]["check_hash"], index[NDM]["release"])
#|        rules_db = store.load_rules()
#|        self.assertEqual(assess.control_state(rules_db, NDM, index[NDM]["controls"]["V-220524"]), "Active")
#|        self.assertEqual(rules_db["rules"][0]["review_log"][0]["release"], "V3R7 (01 Jul 2026)")
#|
#|    def test_duplicate_and_older_imports(self):
#|        store.import_template(self.make_release("r7.cklb", 7))
#|        cat, report = store.import_template(self.make_release("r7.cklb", 7))
#|        self.assertIsNone(cat)
#|        self.assertIn("already imported", report[0])
#|        cat, report = store.import_template(CKLB)  # release 6 after release 7
#|        self.assertIn("OLDER", report[0])
#|        self.assertEqual(store.control_index()[NDM]["release"], "V3R7 (01 Jul 2026)")
#|
#|    def test_compare_controls(self):
#|        old = checklist.read_checklist(CKLB)["stigs"][0]["controls"]
#|        new = checklist.read_checklist(self.make_release("n.cklb", 7, check_change="V-220519"))["stigs"][0][
#|            "controls"]
#|        diffs = checklist.compare_controls(old, new)
#|        self.assertEqual([(d["vuln_id"], d["kind"], d["fields"]) for d in diffs], [("V-220519", "changed", ["check"])])
#|        self.assertLess(checklist.release_key("3", "Release: 6 Benchmark Date: 01 Apr 2026"),
#|                        checklist.release_key("3", "Release: 10 Benchmark Date: 01 Jan 2027"))
#|
#|
#|@needs_fixtures
#|class EndToEndTests(StoreCase):
#|    def setup_project(self):
#|        store.import_template(CKLB)
#|        store.import_template(CKL)
#|        index = store.control_index()
#|        self.rtr_first = index[RTR]["order"][0]
#|        self.cmd = "show running-config | include ^login block-for"
#|        store.save_rule(active_rule(index, NDM, "V-220524", self.cmd,
#|                                    {"check": "number", "text": "attempts", "op": "<=", "value": "3"},
#|                                    "R-0001", comment="Checked login block-for."), check=False)
#|        rtr = active_rule(index, RTR, self.rtr_first, "show ip route", {"check": "has", "text": "via"}, "R-0002")
#|        store.save_rule(rtr, check=False)
#|        # an intentional finding: Open on purpose with a risk-acceptance reason
#|        login = active_rule(index, NDM, "V-220519", self.cmd, {"check": "has", "text": "never-present"}, "R-0003")
#|        login.update(expected_open=True,
#|                     outcome_text={"open": "Recommend risk acceptance for {devices}: platform cannot do this."})
#|        store.save_rule(login, check=False)
#|        store.set_manual(f"{NDM}|V-220518", True)
#|        store.save_group({"id": "CAMPUS-ACCESS", "patterns": ["*-ACCESS"], "stigs": [NDM, RTR],
#|                          "rule_choices": {}}, check=False)
#|        store.save_group({"id": "CAMPUS-HANGOFF", "patterns": [], "stigs": [NDM], "rule_choices": {}}, check=False)
#|        store.set_override("LAB-1D-ACCESS", "CAMPUS-HANGOFF")
#|        return index, store.load_rules(), store.load_groups()
#|
#|    def test_full_workflow(self):
#|        index, rules_db, groups_db = self.setup_project()
#|        cmds = assess.commands_for_groups(groups_db["groups"], rules_db, index)
#|        self.assertEqual(set(cmds), {self.cmd, "show ip route"})
#|        self.assertIn("Cisco IOS XE Switch NDM V-220524", cmds[self.cmd])
#|
#|        cov = {r["short"]: r for r in assess.coverage(groups_db["groups"][0], rules_db, index)}
#|        ndm = cov["Cisco IOS XE Switch NDM"]
#|        self.assertEqual((ndm["total"], ndm["automated"], ndm["manual"], ndm["no_rule"]), (42, 2, 1, 39))
#|        self.assertEqual(cov["Cisco IOS XE Switch RTR"]["automated"], 1)
#|
#|        run = assess.import_solarwinds(sw_file(self.tmp), groups_db, rules_db)
#|        self.assertEqual(run["membership"]["LAB-1D-ACCESS"]["group"], "CAMPUS-HANGOFF")
#|        self.assertEqual(run["membership"]["LAB-EC-router"]["group"], "")
#|        assess.evaluate_run(run, groups_db, rules_db, index)
#|        acc = run["results"]["CAMPUS-ACCESS"]["controls"]
#|        self.assertEqual(acc[f"{NDM}|V-220524"]["recommended"], "not_a_finding")
#|        self.assertEqual(acc[f"{RTR}|{self.rtr_first}"]["recommended"], "not_reviewed")
#|        self.assertIsNone(acc[f"{NDM}|V-220518"]["recommended"])
#|        self.assertNotIn(f"{RTR}|{self.rtr_first}", run["results"]["CAMPUS-HANGOFF"]["controls"])
#|
#|        acc[f"{RTR}|{self.rtr_first}"].update(final="not_applicable", reviewer_changed=True,
#|                                              reviewer_comment="No routing on this group.")
#|        assess.evaluate_run(run, groups_db, rules_db, index)
#|        self.assertEqual(run["results"]["CAMPUS-ACCESS"]["controls"][f"{RTR}|{self.rtr_first}"]["final"],
#|                         "not_applicable")
#|
#|        # Team output format = CKL: only .ckl files, and NDM (imported only as CKLB) is reported missing.
#|        folder, ok_, msgs = assess.write_package(run, "CAMPUS-ACCESS", "tester", groups_db, rules_db, "ckl")
#|        names = {p.name for p in folder.iterdir()}
#|        self.assertIn("CAMPUS-ACCESS_Cisco_IOS_XE_Switch_RTR.ckl", names)
#|        self.assertFalse(any(n.endswith(".cklb") for n in names))
#|        self.assertFalse(ok_)
#|        self.assertTrue(any("NO STIG Viewer 2.x (.ckl) TEMPLATE" in m for m in msgs))
#|        summary = (folder / "group_assessment_summary.txt").read_text(encoding="utf-8")
#|        self.assertIn("Rule coverage per STIG", summary)
#|        self.assertRegex(summary, r"Cisco IOS XE Switch NDM\s+V3R6 \(01 Apr 2026\)\s+42\s+2\s+1\s+39")
#|        rtr = checklist.read_checklist(folder / "CAMPUS-ACCESS_Cisco_IOS_XE_Switch_RTR.ckl")["stigs"][0]
#|        self.assertEqual(rtr["controls"][0]["template_status"], "not_applicable")
#|
#|        # Team output format = CKLB: only the NDM .cklb exists in that format.
#|        folder, ok_, msgs = assess.write_package(run, "CAMPUS-ACCESS", "tester", groups_db, rules_db, "cklb")
#|        names = {p.name for p in folder.iterdir()}
#|        self.assertIn("CAMPUS-ACCESS_Cisco_IOS_XE_Switch_NDM.cklb", names)
#|        self.assertFalse(any(n.endswith(".ckl") for n in names))
#|        out = json.loads((folder / "CAMPUS-ACCESS_Cisco_IOS_XE_Switch_NDM.cklb").read_text(encoding="utf-8"))
#|        r = {x["group_id"]: x for x in out["stigs"][0]["rules"]}
#|        self.assertEqual(r["V-220524"]["status"], "not_a_finding")
#|        # Team guidance: Not a Finding -> reason in Comments, Finding Details left as the template has it.
#|        self.assertEqual(r["V-220524"]["finding_details"], "")
#|        self.assertIn("LAB-1A-ACCESS", r["V-220524"]["comments"])
#|        self.assertTrue(r["V-220524"]["comments"].rstrip().endswith("Checked login block-for."))
#|        self.assertIn("REVIEW_REQUIRED", folder.name)
#|        self.assertEqual(r["V-220519"]["status"], "open")
#|        self.assertTrue(r["V-220519"]["finding_details"].startswith(
#|            "Recommend risk acceptance for LAB-1A-ACCESS, LAB-1C-ACCESS: platform cannot do this."))
#|        self.assertIn("Final determination by tester", r["V-220519"]["finding_details"])
#|        # same run, team switched Not a Finding to Finding Details
#|        c = run["results"]["CAMPUS-ACCESS"]["controls"][f"{NDM}|V-220524"]
#|        custom = assess.checklist_text(c, {**store.DEFAULT_PLACEMENT, "not_a_finding": "finding_details"}, "x")
#|        self.assertIn("LAB-1A-ACCESS", custom["finding_details"])
#|        self.assertEqual(custom["comments"], "Checked login block-for.")
#|        exc = (folder / "exceptions_and_review_required.txt").read_text(encoding="utf-8")
#|        self.assertIn("Expected (intentional) findings", exc)
#|        self.assertIn("Open (expected)", (folder / "group_assessment_summary.txt").read_text(encoding="utf-8"))
#|
#|        folder2, _, _ = assess.write_package(run, "CAMPUS-HANGOFF", "tester", groups_db, rules_db, "cklb")
#|        self.assertFalse(any("RTR" in p.name for p in folder2.iterdir()))
#|
#|if __name__ == "__main__":
#|    unittest.main()
#@ END
#@ FILE tests/test_drafts.py SHA f4183f61ab7095f8aae70b9479b4fd906ecc4d202fe527e462201c542e8e6479 CHUNK 1 OF 1
#|"""Checks the starter draft library against representative Catalyst 9300 / 8300 and Nexus 9000 output."""
#|import sys
#|import unittest
#|from pathlib import Path
#|
#|HERE = Path(__file__).resolve().parent
#|sys.path.insert(0, str(HERE.parent / "src"))
#|sys.path.insert(0, str(HERE))
#|
#|import drafts  # noqa: E402
#|import harden  # noqa: E402
#|import platform_samples as ps  # noqa: E402
#|import rules  # noqa: E402
#|
#|DEVICE = {"IOSXE_SW": "CAT9300", "IOSXE_RTR": "CAT8300", "NXOS": "N9K"}
#|# Hardened samples deliberately leave these unconfigured (data-center leaf without 802.1x / SPAN / QoS).
#|EXPECTED_OPEN_HARDENED = {"IOSXE_SW": set(), "IOSXE_RTR": set(),
#|                          "NXOS": {"CISC-L2-000020", "CISC-L2-000080", "CISC-L2-000060", "CISC-L2-000070",
#|                                   "CISC-RT-000140", "CISC-RT-000780"}}
#|
#|
#|def results(platform, variant):
#|    out = {}
#|    evidence = ps.outputs(f"{DEVICE[platform]}_{variant}")
#|    for ver, spec in drafts.LIBRARY[platform].items():
#|        if "manual" in spec or (platform == "IOSXE_RTR" and ver.startswith("CISC-L2")):
#|            continue
#|        rule = drafts.build_rule(spec, platform, "TEST_STIG", {"vuln_id": ver, "rule_ver": ver, "check_hash": ""})
#|        out[ver] = rules.evaluate(rule, evidence)["status"]
#|    return out
#|
#|
#|class DraftLibraryTests(unittest.TestCase):
#|    def test_every_condition_is_valid(self):
#|        self.assertEqual(drafts.problems_in_library(), [])
#|
#|    def test_platform_detection(self):
#|        self.assertEqual(drafts.platform_of("Cisco_IOS_XE_Switch_NDM_STIG"), "IOSXE_SW")
#|        self.assertEqual(drafts.platform_of("Cisco_IOS-XE_Router_RTR_STIG"), "IOSXE_RTR")
#|        self.assertEqual(drafts.platform_of("Cisco_NX-OS_Switch_L2S_STIG"), "NXOS")
#|        self.assertIsNone(drafts.platform_of("Juniper_SRX_STIG"))
#|
#|    def test_hardened_devices_pass(self):
#|        for platform in DEVICE:
#|            res = results(platform, "HARDENED")
#|            self.assertNotIn("not_reviewed", res.values(), platform)
#|            opened = {v for v, s in res.items() if s == "open"}
#|            self.assertEqual(opened, EXPECTED_OPEN_HARDENED[platform], platform)
#|
#|    def test_factory_defaults_are_caught(self):
#|        for platform, minimum in (("IOSXE_SW", 55), ("IOSXE_RTR", 35), ("NXOS", 50)):
#|            res = results(platform, "DEFAULT")
#|            self.assertNotIn("not_reviewed", res.values(), platform)
#|            self.assertGreaterEqual(sum(1 for s in res.values() if s == "open"), minimum, platform)
#|
#|    def test_platform_specific_cdp(self):
#|        # CDP: Catalyst 9300 is on by default (needs 'no cdp run'); the 8300 router is off by default.
#|        self.assertEqual(results("IOSXE_SW", "DEFAULT")["CISC-RT-000370"], "open")
#|        self.assertEqual(results("IOSXE_RTR", "DEFAULT")["CISC-RT-000370"], "not_a_finding")
#|
#|
#|class HardeningTests(unittest.TestCase):
#|    def test_every_draft_has_a_fix_or_is_verification_only(self):
#|        for platform, lib in drafts.LIBRARY.items():
#|            for ver, spec in lib.items():
#|                if "manual" in spec or (platform == "IOSXE_RTR" and ver.startswith("CISC-L2")):
#|                    continue
#|                self.assertTrue(harden.has_fix({"fix": harden.starter_fix(platform, ver)}), f"{platform} {ver}")
#|
#|    def test_fix_text_is_paste_safe(self):
#|        for platform, lib in harden.FIX_LIBRARY.items():
#|            for ver, fix in lib.items():
#|                for impact in ("low", "high"):
#|                    self.assertTrue((fix[impact] or "").isascii(), f"{platform} {ver}")
#|
#|    def test_each_failing_section_expands_per_interface(self):
#|        fix = "! comment\n{each failing section}\n storm-control broadcast level 1.00\nspanning-tree loopguard default"
#|        out = harden.render(fix, ["interface Gi1/0/5", "interface Gi1/0/7"], "interface <INTERFACE>")
#|        self.assertEqual(out, ["! comment", "interface Gi1/0/5", " storm-control broadcast level 1.00", "exit",
#|                               "interface Gi1/0/7", " storm-control broadcast level 1.00", "exit",
#|                               "spanning-tree loopguard default"])
#|        out = harden.render(fix, [], "interface <INTERFACE>")
#|        self.assertIn("interface <INTERFACE>", out)
#|
#|    def test_failing_sections_come_from_the_engine(self):
#|        spec = drafts.LIBRARY["IOSXE_SW"]["CISC-L2-000160"]
#|        rule = drafts.build_rule(spec, "IOSXE_SW", "X", {"vuln_id": "V-1", "rule_ver": "CISC-L2-000160",
#|                                                        "check_hash": ""})
#|        cfg = ("interface GigabitEthernet1/0/1\n description ACCESS - PC\n switchport mode access\n"
#|               " storm-control broadcast level 1.00\n!\ninterface GigabitEthernet1/0/2\n description ACCESS - PC\n"
#|               " switchport mode access\n!\ninterface TenGigabitEthernet1/1/1\n description UPLINK - DIST\n")
#|        res = rules.evaluate(rule, {"show running-config": {"status": "ok", "text": cfg}})
#|        self.assertEqual(res["status"], "open")
#|        self.assertEqual(res["failed_sections"], ["interface GigabitEthernet1/0/2"])
#|
#|    def test_unlabelled_switch_fails_access_checks(self):
#|        # factory config has no role labels: access checks must not quietly pass
#|        res = results("IOSXE_SW", "DEFAULT")
#|        for ver in ("CISC-L2-000020", "CISC-L2-000120", "CISC-L2-000160", "CISC-L2-000250"):
#|            self.assertEqual(res[ver], "open", ver)
#|
#|    def test_trust_added_on_uplinks_and_removed_elsewhere(self):
#|        spec = drafts.LIBRARY["IOSXE_SW"]["CISC-L2-000130"]
#|        rule = drafts.build_rule(spec, "IOSXE_SW", "X", {"vuln_id": "V-1", "rule_ver": "CISC-L2-000130",
#|                                                        "check_hash": ""})
#|        cfg = ("ip dhcp snooping vlan 10\nip dhcp snooping\n!\ninterface TenGigabitEthernet1/1/3\n"
#|               " description uplink - dist-02\n switchport mode trunk\n!\ninterface GigabitEthernet1/0/48\n"
#|               " description ACCESS - PRINTER\n ip dhcp snooping trust\n")
#|        res = rules.evaluate(rule, {"show running-config": {"status": "ok", "text": cfg}})
#|        self.assertEqual(res["status"], "open")
#|        cmds = harden.render(rule["fix"]["high"], res["failed_sections"], "interface <INTERFACE>",
#|                             res["failed_by_condition"], rule, have_results=True)
#|        text = "\n".join(cmds)
#|        self.assertIn("interface TenGigabitEthernet1/1/3\n ip dhcp snooping trust", text)
#|        self.assertIn("interface GigabitEthernet1/0/48\n no ip dhcp snooping trust", text)
#|        self.assertNotIn("interface GigabitEthernet1/0/48\n ip dhcp snooping trust", text)
#|
#|
#|if __name__ == "__main__":
#|    unittest.main()
#@ END
#@ FILE tests/platform_samples.py SHA 2cf4431390d9477b1cedf08cb8583909181889b1ca2aeb51ef5dc8dd5bc4ad0e CHUNK 1 OF 1
#|"""Representative command output for the target platforms, used to sanity-check the starter drafts.
#|
#|Written to match how each platform prints its configuration (lab addresses only):
#|  CAT9300_*  Catalyst 9300, IOS-XE 17.9
#|  CAT8300_*  Catalyst 8300, IOS-XE 17.9
#|  N9K_*      Nexus 93180YC-FX3 / 9336C-FX2, NX-OS 10.3
#|
#|*_HARDENED is configured the way the STIG check text asks; *_DEFAULT is close to factory settings.
#|"""
#|
#|BANNER = """You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
#|By using this IS (which includes any device attached to this IS), you consent to the following conditions:
#|-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations."""
#|
#|AAA_IOS = """aaa new-model
#|!
#|aaa group server tacacs+ ISE
#| server name ISE1
#| server name ISE2
#|!
#|aaa authentication login default group ISE local
#|aaa authentication dot1x default group ISE
#|aaa authorization exec default group ISE local
#|aaa accounting exec default start-stop group ISE
#|aaa accounting commands 15 default start-stop group ISE
#|!
#|aaa common-criteria policy PASSWORD_POLICY
#| min-length 15
#| upper-case 1
#| lower-case 1
#| numeric-count 1
#| special-case 1
#| char-changes 8
#|!
#|aaa session-id common"""
#|
#|MGMT_IOS = f"""ip http secure-server
#|ip http max-connections 2
#|ip http timeout-policy idle 300 life 86400 requests 10000
#|no ip http server
#|ip ssh version 2
#|ip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256
#|ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr
#|!
#|ip access-list extended MGMT_NET
#| 10 permit ip 10.10.100.0 0.0.0.255 any
#| 20 deny   ip any any log-input
#|!
#|logging host 10.10.50.10
#|logging host 10.10.50.11
#|!
#|snmp-server group V3GROUP v3 priv read V3READ
#|snmp-server view V3READ iso included
#|snmp-server host 10.10.50.20 version 3 priv V3USER
#|!
#|tacacs server ISE1
#| address ipv4 10.10.50.30
#| key 7 0822455D0A16
#|tacacs server ISE2
#| address ipv4 10.10.50.31
#| key 7 0822455D0A16
#|!
#|banner login ^C
#|{BANNER}
#|^C
#|!
#|line con 0
#| exec-timeout 5 0
#| stopbits 1
#|line vty 0 4
#| session-limit 2
#| access-class MGMT_NET in
#| exec-timeout 5 0
#| transport input ssh
#|line vty 5 31
#| transport input none
#|!
#|ntp authentication-key 1 hmac-sha2-256 104D000A0618 7
#|ntp authenticate
#|ntp trusted-key 1
#|ntp server 10.10.50.40 key 1
#|ntp server 10.10.50.41 key 1
#|!
#|event manager applet BACKUP_CONFIG authorization bypass
#| event syslog pattern "%SYS-5-CONFIG_I"
#| action 1.0 cli command "enable"
#| action 2.0 cli command "copy running-config scp://backup@10.10.50.50/$_info_routername-config"
#|!
#|archive
#| log config
#|  logging enable
#|  logging size 1000
#|!
#|end"""
#|
#|CAT9300_HARDENED = f"""Building configuration...
#|
#|Current configuration : 18233 bytes
#|!
#|version 17.9
#|service timestamps debug datetime msec localtime show-timezone
#|service timestamps log datetime msec localtime show-timezone
#|service password-encryption
#|no service pad
#|platform punt-keepalive disable-kernel-core
#|!
#|hostname SW-ACCESS-01
#|!
#|vrf definition Mgmt-vrf
#| !
#| address-family ipv4
#| exit-address-family
#|!
#|logging buffered 64000 informational
#|logging persistent url flash:/syslog size 134217728 filesize 16384
#|logging userinfo
#|no logging console
#|enable secret 9 $9$abcdefghijklmn
#|!
#|{AAA_IOS}
#|boot system switch all flash:packages.conf
#|switch 1 provision c9300-48p
#|!
#|ip routing
#|!
#|no ip domain lookup
#|ip domain name example.mil
#|!
#|login block-for 900 attempts 3 within 120
#|login on-failure log
#|login on-success log
#|!
#|ip dhcp snooping vlan 10,20
#|ip dhcp snooping
#|ip arp inspection vlan 10,20
#|!
#|crypto pki trustpoint SLA-TrustPoint
#| enrollment pkcs12
#| revocation-check crl
#|!
#|crypto pki trustpoint DOD_ID_CA
#| enrollment url http://ca.example.mil/certsrv/mscep/mscep.dll
#| revocation-check crl
#|!
#|license boot level network-advantage addon dna-advantage
#|!
#|dot1x system-auth-control
#|no cdp run
#|!
#|spanning-tree mode rapid-pvst
#|spanning-tree portfast edge bpduguard default
#|spanning-tree loopguard default
#|spanning-tree extend system-id
#|memory free low-watermark processor 134344
#|!
#|file prompt quiet
#|username breakglass privilege 15 common-criteria-policy PASSWORD_POLICY secret 9 $9$zyxwvutsrq
#|!
#|redundancy
#| mode sso
#|udld aggressive
#|!
#|vlan 999
#| name PARKING
#|!
#|class-map match-all VOICE
#| match ip dscp ef
#|class-map match-all SCAVENGER
#| match ip dscp cs1
#|!
#|policy-map QOS_OUT
#| class VOICE
#|  priority level 1 percent 10
#| class SCAVENGER
#|  bandwidth remaining percent 1
#| class class-default
#|  bandwidth remaining percent 89
#|policy-map system-cpp-policy
#|!
#|interface GigabitEthernet0/0
#| vrf forwarding Mgmt-vrf
#| no ip address
#| shutdown
#| negotiation auto
#|!
#|interface GigabitEthernet1/0/1
#| description ACCESS - USER PORT
#| switchport access vlan 10
#| switchport mode access
#| switchport block unicast
#| ip verify source
#| authentication port-control auto
#| mab
#| dot1x pae authenticator
#| spanning-tree portfast
#| storm-control broadcast level 1.00
#| service-policy output QOS_OUT
#|!
#|interface GigabitEthernet1/0/2
#| switchport access vlan 999
#| switchport mode access
#| shutdown
#|!
#|interface TenGigabitEthernet1/1/1
#| description UPLINK - DIST-SW-01 Te2/0/14
#| switchport trunk native vlan 900
#| switchport trunk allowed vlan 10,20,100
#| switchport mode trunk
#| switchport nonegotiate
#| ip dhcp snooping trust
#| ip arp inspection trust
#| udld port aggressive
#| service-policy output QOS_OUT
#|!
#|interface AppGigabitEthernet1/0/1
#| switchport mode trunk
#|!
#|interface Vlan1
#| no ip address
#| shutdown
#|!
#|interface Vlan100
#| description MGMT
#| ip address 10.10.100.11 255.255.255.0
#| no ip redirects
#| no ip unreachables
#| no ip proxy-arp
#|!
#|control-plane
#| service-policy input system-cpp-policy
#|!
#|{MGMT_IOS}"""
#|
#|CAT9300_DEFAULT = """version 17.9
#|service timestamps debug datetime msec
#|service timestamps log datetime msec
#|service call-home
#|platform punt-keepalive disable-kernel-core
#|!
#|hostname Switch
#|!
#|no aaa new-model
#|switch 1 provision c9300-48p
#|!
#|crypto pki trustpoint TP-self-signed-1234567
#| enrollment selfsigned
#|!
#|spanning-tree mode rapid-pvst
#|spanning-tree extend system-id
#|!
#|username admin privilege 15 password 0 cisco
#|username ops privilege 15 password 0 cisco
#|!
#|interface GigabitEthernet1/0/1
#|!
#|interface GigabitEthernet1/0/2
#| switchport mode access
#| shutdown
#|!
#|interface TenGigabitEthernet1/1/1
#| switchport mode trunk
#|!
#|interface Vlan1
#| ip address 10.1.1.10 255.255.255.0
#|!
#|ip http server
#|ip http secure-server
#|!
#|snmp-server community public RO
#|!
#|line con 0
#|line vty 0 4
#| login
#| transport input ssh telnet
#|line vty 5 15
#| login
#|!
#|call-home
#| contact-email-addr sch-smart-licensing@cisco.com
#| profile "CiscoTAC-1"
#|  active
#|!
#|end"""
#|
#|CAT8300_HARDENED = f"""version 17.9
#|service timestamps debug datetime msec localtime show-timezone
#|service timestamps log datetime msec localtime show-timezone
#|service password-encryption
#|platform qfp utilization monitor load 80
#|!
#|hostname RTR-01
#|!
#|boot-start-marker
#|boot-end-marker
#|!
#|logging buffered 64000 informational
#|logging userinfo
#|enable secret 9 $9$abcdefghijklmn
#|!
#|{AAA_IOS}
#|!
#|login block-for 900 attempts 3 within 120
#|login on-failure log
#|login on-success log
#|!
#|crypto pki trustpoint DOD_ID_CA
#| enrollment terminal
#| revocation-check crl
#|!
#|license udi pid C8300-1N1S-6T sn FDO12345678
#|memory free low-watermark processor 69584
#|file prompt quiet
#|username breakglass privilege 15 common-criteria-policy PASSWORD_POLICY secret 9 $9$zyxwvutsrq
#|!
#|redundancy
#|!
#|key chain OSPF_KEY
#| key 1
#|  key-string 7 0822455D0A16
#|  accept-lifetime 00:00:00 Jan 1 2026 duration 180
#|  send-lifetime 00:00:00 Jan 1 2026 duration 180
#|  cryptographic-algorithm hmac-sha-256
#|!
#|class-map match-all SCAVENGER
#| match ip dscp cs1
#|policy-map QOS_OUT
#| class SCAVENGER
#|  bandwidth percent 5
#|policy-map COPP
#| class class-default
#|  police 64000 conform-action transmit exceed-action drop
#|!
#|interface GigabitEthernet0/0/0
#| description WAN
#| ip address 192.0.2.2 255.255.255.252
#| no ip redirects
#| no ip unreachables
#| no ip proxy-arp
#| negotiation auto
#| service-policy output QOS_OUT
#|!
#|interface GigabitEthernet0/0/1
#| description LAN
#| ip address 10.20.0.1 255.255.255.0
#| no ip redirects
#| no ip unreachables
#| no ip proxy-arp
#| ip ospf authentication key-chain OSPF_KEY
#| negotiation auto
#|!
#|interface GigabitEthernet0/0/2
#| no ip address
#| shutdown
#| negotiation auto
#|!
#|router ospf 1
#| router-id 10.20.0.1
#|!
#|control-plane
#| service-policy input COPP
#|!
#|line aux 0
#| no exec
#| transport input none
#|!
#|{MGMT_IOS}"""
#|
#|CAT8300_DEFAULT = """version 17.9
#|service timestamps debug datetime msec
#|service timestamps log datetime msec
#|service call-home
#|!
#|hostname Router
#|!
#|no aaa new-model
#|!
#|interface GigabitEthernet0/0/0
#| ip address dhcp
#| negotiation auto
#|!
#|interface GigabitEthernet0/0/1
#| ip address 10.20.0.1 255.255.255.0
#| negotiation auto
#|!
#|ip http server
#|ip http secure-server
#|!
#|line con 0
#|line aux 0
#|line vty 0 4
#| login
#| transport input ssh
#|!
#|end"""
#|
#|N9K_HARDENED = f"""!Command: show running-config
#|!Running configuration last done at: Thu Oct  1 10:00:00 2026
#|!Time: Thu Oct  1 10:05:00 2026
#|
#|version 10.3(4a) Bios:version 05.47
#|hostname NX-LEAF-01
#|policy-map type network-qos jumbo
#|  class type network-qos class-default
#|    mtu 9216
#|vdc NX-LEAF-01 id 1
#|  limit-resource vlan minimum 16 maximum 4094
#|
#|feature tacacs+
#|feature scp-server
#|feature interface-vlan
#|feature dhcp
#|feature lacp
#|feature udld
#|
#|username admin password 5 $5$KDhHZi$abcdef  role network-admin
#|ip domain-lookup
#|copp profile strict
#|snmp-server user NETOPS network-operator auth sha 0x1234 priv aes-128 0x5678 localizedkey
#|snmp-server host 10.30.50.20 traps version 3 priv NETOPS
#|ntp authentication-key 1 md5 swwX 7
#|ntp server 10.30.50.40 use-vrf management key 1
#|ntp server 10.30.50.41 use-vrf management key 1
#|ntp authenticate
#|ntp trusted-key 1
#|tacacs-server host 10.30.50.30 key 7 "fewhg123"
#|tacacs-server host 10.30.50.31 key 7 "fewhg123"
#|aaa group server tacacs+ ISE
#|    server 10.30.50.30
#|    server 10.30.50.31
#|    use-vrf management
#|aaa authentication login default group ISE
#|aaa authentication login console group ISE
#|aaa accounting default group ISE
#|
#|class-map type control-plane match-any copp-system-p-class-critical
#|  match access-group name copp-system-p-acl-bgp
#|policy-map type control-plane copp-system-p-policy-strict
#|  class copp-system-p-class-critical
#|    set cos 7
#|    police cir 36000 kbps bc 1280000 bytes
#|control-plane
#|  service-policy input copp-system-p-policy-strict
#|
#|ip access-list MGMT_NET
#|  10 permit ip 10.30.100.0/24 any
#|  20 deny ip any any log
#|logging ip access-list cache entries 8000
#|ssh login-attempts 3
#|ssh ciphers aes256-ctr aes128-ctr
#|ssh macs hmac-sha2-256 hmac-sha2-512
#|no ip source-route
#|no cdp enable
#|spanning-tree port type edge bpduguard default
#|spanning-tree loopguard default
#|ip dhcp snooping
#|ip dhcp snooping vlan 10
#|ip arp inspection vlan 10
#|vlan 1,10,999
#|vlan 999
#|  name PARKING
#|
#|vrf context management
#|  ip route 0.0.0.0/0 10.30.100.1
#|
#|interface Vlan1
#|
#|interface Vlan10
#|  no shutdown
#|  no ip redirects
#|  ip address 10.30.10.1/24
#|  no ip arp gratuitous request
#|
#|interface Ethernet1/1
#|  description ACCESS - SERVER-01 eth0
#|  switchport access vlan 10
#|  spanning-tree port type edge
#|  switchport block unicast
#|  ip verify source dhcp-snooping-vlan
#|  storm-control broadcast level 1.00
#|  no shutdown
#|
#|interface Ethernet1/2
#|  shutdown
#|  switchport access vlan 999
#|
#|interface Ethernet1/3
#|
#|interface Ethernet1/49
#|  description UPLINK - SPINE-01 Eth1/1
#|  switchport mode trunk
#|  switchport trunk native vlan 900
#|  switchport trunk allowed vlan 10,20
#|  ip dhcp snooping trust
#|  ip arp inspection trust
#|  no shutdown
#|
#|interface mgmt0
#|  vrf member management
#|  ip access-group MGMT_NET in
#|  ip address 10.30.100.11/24
#|line console
#|  exec-timeout 5
#|line vty
#|  session-limit 2
#|  exec-timeout 5
#|  access-class MGMT_NET in
#|boot nxos bootflash:/nxos64-cs.10.3.4a.M.bin
#|logging logfile messages 6 size 4194304
#|logging server 10.30.50.10 6 use-vrf management
#|logging server 10.30.50.11 6 use-vrf management
#|logging level authpri 6
#|no logging console
#|banner motd ^
#|{BANNER}
#|^
#|event manager applet BACKUP_CONFIG
#|  event syslog pattern "VSHD_SYSLOG_CONFIG_I"
#|  action 1 cli copy running-config scp://backup@10.30.50.50/nx.cfg vrf management
#|"""
#|
#|N9K_DEFAULT = """!Command: show running-config
#|version 10.3(4a) Bios:version 05.47
#|hostname switch
#|feature telnet
#|feature lldp
#|
#|username admin password 5 $5$abc  role network-admin
#|username ops password 5 $5$def  role network-operator
#|snmp-server user admin network-admin auth md5 0x1111 priv 0x2222 localizedkey
#|no password strength-check
#|vlan 1
#|
#|vrf context management
#|
#|interface Vlan1
#|
#|interface Ethernet1/1
#|
#|interface Ethernet1/49
#|  switchport mode trunk
#|
#|interface mgmt0
#|  vrf member management
#|  ip address 10.30.100.11/24
#|line console
#|line vty
#|boot nxos bootflash:/nxos64-cs.10.3.4a.M.bin
#|"""
#|
#|SHOW = {
#|    "CAT9300_HARDENED": {
#|        "show snmp user": "User name: V3USER\nEngine ID: 800000090300F87B204E5C00\nstorage-type: nonvolatile        "
#|                          "active\nAuthentication Protocol: SHA\nPrivacy Protocol: AES256\nGroup-name: V3GROUP",
#|        "show vtp status": "VTP Version capable             : 1 to 3\nVTP version running             : 1\n"
#|                           "VTP Domain Name                 : \nVTP Operating Mode                : Off",
#|        "show vtp password": "The VTP password is not configured.",
#|        "show interfaces switchport": "Name: Gi1/0/1\nSwitchport: Enabled\nAdministrative Mode: static access\n"
#|                                      "Negotiation of Trunking: Off\n\nName: Te1/1/1\nSwitchport: Enabled\n"
#|                                      "Administrative Mode: trunk\nNegotiation of Trunking: Off",
#|        "show vlan brief": "VLAN Name                             Status    Ports\n---- ---- ----\n"
#|                           "1    default                          active    \n"
#|                           "10   USERS                            active    Gi1/0/1\n"
#|                           "999  PARKING                          active    Gi1/0/2",
#|        "show version": "Cisco IOS XE Software, Version 17.09.04a\nCisco IOS Software [Cupertino], Catalyst L3 Switch",
#|        "show ip interface brief": "Interface              IP-Address      OK? Method Status                Protocol\n"
#|                                   "Vlan1                  unassigned      YES NVRAM  administratively down down    \n"
#|                                   "Vlan100                10.10.100.11    YES NVRAM  up                    up      \n"
#|                                   "GigabitEthernet1/0/3   unassigned      YES unset  down                  down    ",
#|    },
#|    "CAT9300_DEFAULT": {
#|        "show snmp user": "",
#|        "show vtp status": "VTP Version capable             : 1 to 3\nVTP Operating Mode                : Server",
#|        "show vtp password": "The VTP password is not configured.",
#|        "show interfaces switchport": "Name: Gi1/0/1\nSwitchport: Enabled\nAdministrative Mode: dynamic auto\n"
#|                                      "Negotiation of Trunking: On",
#|        "show vlan brief": "VLAN Name                             Status    Ports\n"
#|                           "1    default                          active    Gi1/0/1, Gi1/0/2",
#|        "show version": "Cisco IOS XE Software, Version 17.03.05\n",
#|        "show ip interface brief": "Interface              IP-Address      OK? Method Status                Protocol\n"
#|                                   "Vlan1                  10.1.1.10       YES NVRAM  down                  down    ",
#|    },
#|    "CAT8300_HARDENED": {
#|        "show snmp user": "User name: V3USER\nAuthentication Protocol: SHA\nPrivacy Protocol: AES256\n",
#|        "show version": "Cisco IOS XE Software, Version 17.12.04\nCisco IOS Software [Dublin], c8000be",
#|        "show ip interface brief": "Interface              IP-Address      OK? Method Status                Protocol\n"
#|                                   "GigabitEthernet0/0/0   192.0.2.2       YES NVRAM  up                    up      \n"
#|                                   "GigabitEthernet0/0/1   10.20.0.1       YES NVRAM  up                    up      \n"
#|                                   "GigabitEthernet0/0/2   unassigned      YES unset  administratively down down    ",
#|    },
#|    "CAT8300_DEFAULT": {
#|        "show snmp user": "",
#|        "show version": "Cisco IOS XE Software, Version 17.06.01\n",
#|        "show ip interface brief": "Interface              IP-Address      OK? Method Status                Protocol\n"
#|                                   "GigabitEthernet0/0/1   10.20.0.1       YES NVRAM  down                  down    ",
#|    },
#|    "N9K_HARDENED": {
#|        "show version": "Cisco Nexus Operating System (NX-OS) Software\n  NXOS: version 10.3(4a)\n",
#|        "show ip interface brief vrf all": "IP Interface Status for VRF \"default\"(1)\nInterface            IP Address      "
#|                                           "Interface Status\nVlan10               10.30.10.1      protocol-up/link-up/admin-up",
#|    },
#|    "N9K_DEFAULT": {
#|        "show version": "Cisco Nexus Operating System (NX-OS) Software\n  NXOS: version 9.3(5)\n",
#|        "show ip interface brief vrf all": "IP Interface Status for VRF \"management\"(2)\nInterface            IP Address "
#|                                           "     Interface Status\nmgmt0                10.30.100.11    "
#|                                           "protocol-down/link-down/admin-up",
#|    },
#|}
#|
#|CONFIGS = {"CAT9300_HARDENED": CAT9300_HARDENED, "CAT9300_DEFAULT": CAT9300_DEFAULT,
#|           "CAT8300_HARDENED": CAT8300_HARDENED, "CAT8300_DEFAULT": CAT8300_DEFAULT,
#|           "N9K_HARDENED": N9K_HARDENED, "N9K_DEFAULT": N9K_DEFAULT}
#|
#|
#|def outputs(name):
#|    """Evidence dict for the rule engine: {command: {"status", "text"}}"""
#|    out = {"show running-config": CONFIGS[name]}
#|    out.update(SHOW[name])
#|    return {cmd: {"status": "ok", "text": text} for cmd, text in out.items()}
#@ END
#@ FILE rules/stigtool_rules.json SHA 5a309ccf4a5781d11ba69a023f9825c882d29e77124d4dbb2cb99562ff3a55e5 CHUNK 1 OF 1
#|{"format":"stigtool-rules","version":1,"exported_at":"2026-10-03T21:25:42","manual_controls":[],"rules":[
#|{"id":"R-221027","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215807","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"line vty","section_how":"starts with","only":"","exclude":"transport input none","if_none":"pass","check":"has","text":"session-limit","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nPlatforms without session-limit pass by limiting active vty lines instead (vty 0 1 transport ssh, others 'transport input none') - adjust if so. If 'ip http secure-server' is on, also require 'ip http max-connections'.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"df55065d60533f6e","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"ip http max-connections 2","high":"line vty 0 4\n session-limit 2"}},
#|{"id":"R-5855E5","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215808","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"archive","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"ef245cf38c3b2cd8","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"archive\n log config\n  logging enable\n  logging size 1000","high":""}},
#|{"id":"R-02DF2F","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215809","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"archive","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"d3b597c7c279a570","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"archive\n log config\n  logging enable\n  logging size 1000","high":""}},
#|{"id":"R-4E06EA","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215810","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"archive","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"de45b1a7e24b4d94","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"archive\n log config\n  logging enable\n  logging size 1000","high":""}},
#|{"id":"R-795CA7","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215811","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"archive","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"e6413301d1ba4cf6","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"archive\n log config\n  logging enable\n  logging size 1000","high":""}},
#|{"id":"R-E19E2C","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215812","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"line vty","section_how":"starts with","only":"","exclude":"transport input none","if_none":"pass","check":"has","text":"^\\s*access-class \\S+ in","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nAlso confirm the ACL only permits the management network.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"00fa210570782ced","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip access-list extended MGMT_NET\n permit ip <MGMT_SUBNET> <MGMT_WILDCARD> any\n deny ip any any log-input\nline vty 0 4\n access-class MGMT_NET in"}},
#|{"id":"R-4403D4","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215813","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"login block-for","how":"starts with","ignore_case":false,"op":">=","value":"900"},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"attempts","how":"contains","ignore_case":false,"op":"<=","value":"3"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"81d77d924ea35e4d","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"login block-for 900 attempts 3 within 120"}},
#|{"id":"R-46B095","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215814","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"banner login","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"You are accessing a U.S. Government (USG) Information System","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"9088f4aad07acabc","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"banner login ^C\nYou are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n-At any time, the USG may inspect and seize data stored on this IS.\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.\n^C","high":""}},
#|{"id":"R-733F7A","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215815","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging userinfo","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"archive","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"c439ccf8c25f80e5","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"logging userinfo\narchive\n log config\n  logging enable\n  logging size 1000","high":""}},
#|{"id":"R-BFB09E","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215817","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"service timestamps log datetime","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"4b5ca253d16b715a","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"service timestamps log datetime msec localtime show-timezone","high":""}},
#|{"id":"R-2E9997","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215818","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"ip access-list extended","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"^\\s*(\\d+\\s+)?deny\\b(?!.*\\blog-input\\b)","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nOnly interface-bound ACLs matter; CoPP / route-filter ACLs may need excluding.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"735eb18f9688c77a","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ! add 'log-input' to every deny statement in this ACL, e.g. <SEQ> deny ip any any log-input"}},
#|{"id":"R-F80B0D","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215819","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"archive","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"1c174fcf80d70b29","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"archive\n log config\n  logging enable\n  logging size 1000","high":""}},
#|{"id":"R-81CF22","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215820","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"file privilege","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"logging persistent","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"ed2658fe1674b5ef","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"file privilege 15","high":""}},
#|{"id":"R-FEA981","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215821","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"file privilege","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"logging persistent","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"ed2658fe1674b5ef","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"file privilege 15","high":""}},
#|{"id":"R-F6E93B","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215822","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"file privilege","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"logging persistent","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"54ff84e4ace3633b","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"file privilege 15","high":""}},
#|{"id":"R-A6EADF","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215823","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip boot server","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip bootp server","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip dns server","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip identd","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip finger","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip http server","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip rcmd rcp-enable","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip rcmd rsh-enable","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"service config","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"service finger","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"service tcp-small-servers","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"service udp-small-servers","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"service pad","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"service call-home","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"boot network","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nCatalyst 9300/8300 17.x often ship with 'service call-home' and 'ip http server' on. Call-home is allowed only on legacy devices that need it for Smart Licensing - otherwise a finding.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"99bd39e1cbe5bb9f","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"no service pad\nno service finger\nno service tcp-small-servers\nno service udp-small-servers\nno ip finger\nno ip identd\nno ip bootp server\nno ip dns server\nno ip rcmd rcp-enable\nno ip rcmd rsh-enable\nno service config\nno ip boot server","high":"no ip http server\nno service call-home"}},
#|{"id":"R-BACBBA","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215824","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"count","text":"username ","how":"starts with","ignore_case":false,"op":"==","value":"1"},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^aaa authentication login \\S+ group \\S+ .*\\blocal\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nExactly one local account; local must come after the AAA server group.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"1537cf5755584617","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! remove every local account except the account of last resort:\n! no username <EXTRA_ACCOUNT>\naaa authentication login default group <AAA_GROUP> local"}},
#|{"id":"R-5BBE09","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215826","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"aaa common-criteria policy","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"min-length","how":"starts with","ignore_case":false,"op":">=","value":"15"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"a555fc88d62b8ba3","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa common-criteria policy PASSWORD_POLICY\n min-length 15","high":""}},
#|{"id":"R-555903","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215827","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"aaa common-criteria policy","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"upper-case","how":"starts with","ignore_case":false,"op":">=","value":"1"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"68439eab0ee746f6","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa common-criteria policy PASSWORD_POLICY\n upper-case 1","high":""}},
#|{"id":"R-DE1C66","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215828","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"aaa common-criteria policy","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"lower-case","how":"starts with","ignore_case":false,"op":">=","value":"1"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"c39ebc5ba046d20b","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa common-criteria policy PASSWORD_POLICY\n lower-case 1","high":""}},
#|{"id":"R-818941","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215829","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"aaa common-criteria policy","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"numeric-count","how":"starts with","ignore_case":false,"op":">=","value":"1"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"5a80538c77e8f5dc","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa common-criteria policy PASSWORD_POLICY\n numeric-count 1","high":""}},
#|{"id":"R-6C750D","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215830","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"aaa common-criteria policy","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"special-case","how":"starts with","ignore_case":false,"op":">=","value":"1"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"5e8a5f0e9770d64d","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa common-criteria policy PASSWORD_POLICY\n special-case 1","high":""}},
#|{"id":"R-007980","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215831","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"aaa common-criteria policy","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"char-changes","how":"starts with","ignore_case":false,"op":">=","value":"8"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"d69a89a882348a19","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa common-criteria policy PASSWORD_POLICY\n char-changes 8","high":""}},
#|{"id":"R-3C1670","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215832","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"service password-encryption","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"enable secret","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"enable password","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"6eb26f6ae2fd3473","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"service password-encryption","high":"no enable password\nenable algorithm-type scrypt secret <ENABLE_SECRET>"}},
#|{"id":"R-162F7E","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215833","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"line vty","section_how":"starts with","only":"","exclude":"transport input none","if_none":"pass","check":"number","text":"exec-timeout","how":"starts with","ignore_case":false,"op":"<=","value":"5"},{"command":"show running-config","scope":"every","section":"line con","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"exec-timeout","how":"starts with","ignore_case":false,"op":"<=","value":"5"},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*exec-timeout 0 0\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nexec-timeout absent = default 10 minutes (finding). If 'ip http secure-server' is on, also check 'ip http timeout-policy idle 300' or less.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"d164e7d3e6ac587d","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"line con 0\n exec-timeout 5 0\nline vty 0 4\n exec-timeout 5 0\nip http timeout-policy idle 300 life 86400 requests 10000","high":""}},
#|{"id":"R-3C668F","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215834","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"archive","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"4ec2c3a7d5458ef4","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"archive\n log config\n  logging enable\n  logging size 1000","high":""}},
#|{"id":"R-8A175E","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215836","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^logging buffered \\d+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"8de4f85def0af2ca","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"logging buffered 64000 informational","high":""}},
#|{"id":"R-989625","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215837","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^logging trap (emergencies|alerts|0|1)\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nNo 'logging trap' line means informational (compliant).","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"4c18467f704bce85","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"logging trap critical","high":""}},
#|{"id":"R-79DD2F","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215838","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"count","text":"ntp server","how":"starts with","ignore_case":false,"op":">=","value":"2"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"053feb8c07358ff4","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"ntp server <NTP_SERVER_1>\nntp server <NTP_SERVER_2>","high":""}},
#|{"id":"R-9E52BB","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215841","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config","show snmp user"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^snmp-server group \\S+ v3 (auth|priv)\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^snmp-server group \\S+ v3 noauth\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"snmp-server community","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show snmp user","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"Authentication Protocol:\\s*(MD5|None)","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^snmp-server (group|user|host|community)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nIOS-XE does not print SNMPv3 users in the running-config, so the HMAC is read from 'show snmp user' (SHA / SHA-2 required).","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"2115d6ba482e5e0e","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"snmp-server group <SNMP_GROUP> v3 priv read <SNMP_VIEW>\nsnmp-server user <SNMP_USER> <SNMP_GROUP> v3 auth sha <AUTH_PASSWORD> priv aes 256 <PRIV_PASSWORD>\nno snmp-server community <OLD_COMMUNITY>"}},
#|{"id":"R-CCA568","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215842","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config","show snmp user"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^snmp-server group \\S+ v3 priv\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^snmp-server group \\S+ v3 (auth|noauth)\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show snmp user","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"Privacy Protocol:\\s*(None|DES|3DES)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^snmp-server (group|user|host|community)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"ef6f4868acd6afd1","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"snmp-server group <SNMP_GROUP> v3 priv read <SNMP_VIEW>\nsnmp-server user <SNMP_USER> <SNMP_GROUP> v3 auth sha <AUTH_PASSWORD> priv aes 256 <PRIV_PASSWORD>"}},
#|{"id":"R-32DCF3","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215843","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ntp authenticate","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ntp authentication-key \\d+ hmac-sha2","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ntp trusted-key","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^ntp server (?!.*\\bkey\\b)","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nhmac-sha2-256 NTP keys need a recent IOS-XE 17.x release; older releases only offer MD5.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"7c24da512114d94a","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ntp authentication-key 1 hmac-sha2-256 <NTP_KEY>\nntp authenticate\nntp trusted-key 1\nntp server <NTP_SERVER_1> key 1\nntp server <NTP_SERVER_2> key 1"}},
#|{"id":"R-693F60","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215844","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip ssh version 2","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip ssh server algorithm mac","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^ip ssh server algorithm mac .*hmac-sha1","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"490802fd2a615fb3","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip ssh version 2\nip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256"}},
#|{"id":"R-148754","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215845","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip ssh server algorithm encryption","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^ip ssh server algorithm encryption .*(cbc|3des)","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"c7d703b39f6e526e","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr"}},
#|{"id":"R-CEE65B","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215848","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"archive","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"b70f00fab900eed4","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"archive\n log config\n  logging enable\n  logging size 1000","high":""}},
#|{"id":"R-CFD6A4","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215849","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"login on-failure log","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"login on-success log","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"36f7c678276336ba","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"login on-failure log\nlogin on-success log","high":""}},
#|{"id":"R-A67AD4","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215850","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"archive","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"972a2cc8d3dee7e3","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"archive\n log config\n  logging enable\n  logging size 1000","high":""}},
#|{"id":"R-A8F9EE","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215854","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"count","text":"^(radius server|tacacs server|radius-server host|tacacs-server host) ","how":"regex","ignore_case":false,"op":">=","value":"2"},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^aaa authentication login \\S+ group ","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"036d3f92aa447ffe","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"tacacs server <AAA_SERVER_1>\n address ipv4 <AAA_IP_1>\n key <AAA_KEY>\ntacacs server <AAA_SERVER_2>\n address ipv4 <AAA_IP_2>\n key <AAA_KEY>\naaa group server tacacs+ <AAA_GROUP>\n server name <AAA_SERVER_1>\n server name <AAA_SERVER_2>\naaa authentication login default group <AAA_GROUP> local"}},
#|{"id":"R-D454E3","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215855","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"event manager applet","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"CONFIG_I","how":"contains","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"event manager applet","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"copy running-config (scp|sftp|https)://","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"file prompt quiet","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nAlso confirm no cleartext password is embedded in the copy URL.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"3f3eaa9b9fe09e9a","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"file prompt quiet\nevent manager applet BACKUP_CONFIG authorization bypass\n event syslog pattern \"%SYS-5-CONFIG_I\"\n action 1 cli command \"enable\"\n action 2 info type routername\n action 3 cli command \"copy running-config scp://<SCP_USER>@<SCP_SERVER>/<SCP_PATH>/$_info_routername-running-config\"","high":""}},
#|{"id":"R-E9EAC6","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-215856","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"crypto pki trustpoint","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s*enrollment (url|terminal|profile)\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*enrollment selfsigned\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"crypto pki trustpoint","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nReviewer must confirm the CA is DoD / DoD-approved. IOS-XE creates a self-signed trustpoint for HTTPS - remove it or replace it with a CA-issued certificate. Cisco's SLA-TrustPoint (licensing, 'enrollment pkcs12') is ignored.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"862720786e4c9713","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! enroll with a DoD / DoD-approved CA and remove self-signed trustpoints:\ncrypto pki trustpoint <DOD_CA_TRUSTPOINT>\n enrollment url <CA_ENROLLMENT_URL>\n revocation-check crl\n! no crypto pki trustpoint <SELF_SIGNED_TRUSTPOINT>"}},
#|{"id":"R-BFFA46","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-220139","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"count","text":"^logging (host \\S+|\\d+\\.\\d+\\.\\d+\\.\\d+)","how":"regex","ignore_case":false,"op":">=","value":"2"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"efe69bee3fe5af83","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"logging host <SYSLOG_SERVER_1>\nlogging host <SYSLOG_SERVER_2>","high":""}},
#|{"id":"R-10FB64","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","vuln_id":"V-220140","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show version"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show version","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"Cisco IOS XE Software, Version 17\\.(0?9|12|15)\\.","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nEDIT the version list to the Cisco-supported / site-approved releases before use.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"029c5c9296c65ee1","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! upgrade the device to a Cisco-supported IOS-XE release (not a config change)"}},
#|{"id":"R-F37851","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216645","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"key chain","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"key chain","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"cryptographic-algorithm hmac-sha","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^router (ospf|ospfv3|bgp|eigrp|isis|rip)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nCheck every routing protocol: OSPF interfaces 'ip ospf authentication key-chain', BGP neighbors 'ao <keychain>', key lifetimes 180 days or less. EIGRP/RIP/IS-IS (MD5 only) are a permanent finding.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"6afb27d124c700b0","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"key chain <KEY_CHAIN>\n key 1\n  key-string <ROUTING_KEY>\n  cryptographic-algorithm hmac-sha-256\n  send-lifetime 00:00:00 <START_DATE> duration 180\n  accept-lifetime 00:00:00 <START_DATE> duration 180\ninterface <ROUTING_INTERFACE>\n ip ospf authentication key-chain <KEY_CHAIN>"}},
#|{"id":"R-9D4658","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216646","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show ip interface brief"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show ip interface brief","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\S+\\s+\\d+\\.\\d+\\.\\d+\\.\\d+\\s+\\S+\\s+\\S+\\s+down\\s+down\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nFlags interfaces that have an IP address, are not shut down, and are down/down. Unaddressed switchports are ignored.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"5ba7c499dcda537b","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! shut down routed interfaces that are not in use:\ninterface <UNUSED_INTERFACE>\n shutdown"}},
#|{"id":"R-1BDB6E","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216649","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"service config","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"boot network","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"cns ","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"71dbde5607506cc0","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"no service config\n! also remove any 'boot network' and 'cns' lines","high":""}},
#|{"id":"R-14E14F","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216650","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ANY","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"policy-map system-cpp-policy","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"control-plane","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s*service-policy input \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nCatalyst 9300 uses the built-in system-cpp-policy; Catalyst 8300 uses a 'control-plane' service-policy. Also review policer rates with 'show policy-map control-plane'.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"a3002b8b389f6997","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! Catalyst 9300: keep the built-in 'policy-map system-cpp-policy' and tune rates;\n! Catalyst 8300: build a CoPP policy-map and apply it:\ncontrol-plane\n service-policy input <COPP_POLICY>"}},
#|{"id":"R-E3AF88","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216653","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip gratuitous-arps","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"9ffb7841784a72c0","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"no ip gratuitous-arps"}},
#|{"id":"R-F8AA50","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216654","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"ip directed-broadcast","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"95df7fc7ac78ac88","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"{each failing section}\n no ip directed-broadcast","high":""}},
#|{"id":"R-5E17BB","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216655","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"ip address","exclude":"shutdown","if_none":"pass","check":"has","text":"no ip unreachables","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nApplies to EXTERNAL interfaces only - narrow 'only' / 'skip' to your external interfaces (or use 'ip icmp rate-limit unreachable' on the DODIN backbone).","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"6531c42c4cd04978","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"{each failing section}\n no ip unreachables","high":""}},
#|{"id":"R-395556","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216656","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"ip mask-reply","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"d92c5e8c092f78d4","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"{each failing section}\n no ip mask-reply","high":""}},
#|{"id":"R-D3AE50","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216657","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"ip address","exclude":"shutdown","if_none":"pass","check":"has","text":"no ip redirects","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nApplies to EXTERNAL interfaces only - narrow to your external interfaces.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"1a7a32e5fe688598","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"{each failing section}\n no ip redirects","high":""}},
#|{"id":"R-3F9722","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216658","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"ip access-list extended","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"^\\s*(\\d+\\s+)?deny\\b(?!.*\\blog(-input)?\\b)","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"4640eab7afd6fb02","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ! add 'log' or 'log-input' to every deny statement in this ACL"}},
#|{"id":"R-504AB8","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216659","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"ip access-list extended","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"^\\s*(\\d+\\s+)?deny\\b(?!.*\\blog-input\\b)","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"ce007a0afb902ac3","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ! add 'log-input' to every deny statement in this ACL, e.g. <SEQ> deny ip any any log-input"}},
#|{"id":"R-D9F911","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216660","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"ip access-list extended","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"^\\s*(\\d+\\s+)?deny\\b(?!.*\\blog-input\\b)","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"cb109b6ab523be07","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ! add 'log-input' to every deny statement in this ACL, e.g. <SEQ> deny ip any any log-input"}},
#|{"id":"R-CEC86D","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216661","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"line aux","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"no exec","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"line aux","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"aa30ee5d79ad5073","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"line aux 0\n no exec\n transport input none","high":""}},
#|{"id":"R-647CC6","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216674","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"lldp run","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nIf LLDP is needed internally, change to: every EXTERNAL interface has 'no lldp transmit'.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"e8f4c494cc0b7e9e","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"no lldp run"}},
#|{"id":"R-83B281","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216675","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ANY","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"cdp run","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"no cdp run","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nCDP is off by default on IOS-XE routers ('cdp run' appears only when enabled).","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"bbc925297f6024db","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"no cdp run\n! (IP phones use CDP for the voice VLAN - use per-interface 'no cdp enable' on external interfaces instead if needed)"}},
#|{"id":"R-690DFD","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216676","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"ip address","exclude":"shutdown","if_none":"pass","check":"has","text":"no ip proxy-arp","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nProxy ARP is on by default. Applies to EXTERNAL interfaces - narrow as needed.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"e2b64cc7e3c7d140","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n no ip proxy-arp"}},
#|{"id":"R-D3DFD2","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216687","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip prefix-list \\S+ seq \\d+ deny 10\\.0\\.0\\.0/8","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"neighbor \\S+ (prefix-list|route-map) \\S+ in\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nConfirm the full current Bogon list and that it is applied to ALL external peers.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"88dd18092edeccab","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! build the Bogon prefix list (see check text) and apply it inbound to every eBGP peer:\nrouter bgp <ASN>\n neighbor <EBGP_PEER> prefix-list <BOGON_PREFIX_LIST> in"}},
#|{"id":"R-E45EBE","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216688","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"neighbor \\S+ (prefix-list|route-map) \\S+ in\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nReviewer must confirm the inbound filter denies the local AS prefixes.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"5badf9dbdaeca7e4","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip prefix-list <INBOUND_FILTER> seq <SEQ> deny <LOCAL_AS_PREFIX> le 32\nrouter bgp <ASN>\n neighbor <EBGP_PEER> prefix-list <INBOUND_FILTER> in"}},
#|{"id":"R-775AED","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216689","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"neighbor \\S+ prefix-list \\S+ in\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nOnly for CE peers; confirm each customer's list holds only its prefixes.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"8a8545767a5462c5","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n neighbor <CE_PEER> prefix-list <CUSTOMER_PREFIX_LIST> in"}},
#|{"id":"R-55A7E2","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216690","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"neighbor \\S+ prefix-list \\S+ out\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"060b2339e27ff5f3","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n neighbor <CE_PEER> prefix-list <ADVERTISE_PREFIX_LIST> out"}},
#|{"id":"R-7F371F","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216691","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"neighbor \\S+ prefix-list \\S+ out\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"3091ff3c9947d9df","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n neighbor <EBGP_PEER> prefix-list <FILTER_CORE_PREFIXES> out"}},
#|{"id":"R-CC52F3","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216692","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"no bgp enforce-first-as","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"aeb00f1f111929e2","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n bgp enforce-first-as"}},
#|{"id":"R-5986E4","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216693","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip as-path access-list","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"neighbor \\S+ filter-list \\S+ in","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"a46f8b5cd7a9a1a2","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip as-path access-list <AS_PATH_ACL> permit ^<CUSTOMER_AS>$\nrouter bgp <ASN>\n neighbor <CE_PEER> filter-list <AS_PATH_ACL> in"}},
#|{"id":"R-19DB9A","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216694","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"maximum-prefix","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"1625f800d16915af","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n neighbor <EBGP_PEER> maximum-prefix <MAX_PREFIXES>"}},
#|{"id":"R-3C8C08","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216695","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip prefix-list \\S+ .*le 24\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"neighbor \\S+ prefix-list \\S+ in\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"e0902b3706cf007f","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip prefix-list FILTER_PREFIX_LENGTH seq 5 permit 0.0.0.0/0 ge 8 le 24\nip prefix-list FILTER_PREFIX_LENGTH seq 10 deny 0.0.0.0/0 le 32\nrouter bgp <ASN>\n neighbor <EBGP_PEER> prefix-list FILTER_PREFIX_LENGTH in"}},
#|{"id":"R-EAED00","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216696","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"neighbor \\S+ update-source [Ll]oopback","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"0498158044d5feae","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n neighbor <IBGP_PEER> update-source Loopback0"}},
#|{"id":"R-4DBC21","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216697","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ANY","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"mpls ldp router-id","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^mpls ldp router-id [Ll]oopback","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*mpls (ip|label protocol|ldp)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"2dd91559f8c6041a","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"mpls ldp router-id Loopback0 force"}},
#|{"id":"R-0288C1","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216698","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"^router (ospf|isis)\\b","section_how":"regex","only":"","exclude":"","if_none":"fail","check":"has","text":"mpls ldp sync","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*mpls (ip|label protocol|ldp)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"9357a9bb714fd720","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router ospf <OSPF_PROCESS>\n mpls ldp sync"}},
#|{"id":"R-6CD83C","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216699","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip rsvp signalling rate-limit","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"mpls traffic-eng tunnels","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"502030d7b8348496","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip rsvp signalling rate-limit period 30 burst 9 maxsize 2100 limit 50"}},
#|{"id":"R-8AE7EB","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216700","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"no mpls ip propagate-ttl","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*mpls (ip|label protocol|ldp)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"3357338a20602805","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"no mpls ip propagate-ttl"}},
#|{"id":"R-01A1FE","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216707","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"no-split-horizon","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^(l2 vfi|l2vpn vfi|bridge-domain)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"b9aeec866c7b335f","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! remove 'no-split-horizon' from VFI neighbor statements (mesh VPLS only)"}},
#|{"id":"R-67240E","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216708","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"re:^\\s*bridge-domain","exclude":"","if_none":"pass","check":"has","text":"storm-control broadcast","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^(l2 vfi|l2vpn vfi|bridge-domain)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"e595c3889f70fcd2","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n storm-control broadcast cir <STORM_CIR>"}},
#|{"id":"R-47DC1D","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216709","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"no ip igmp snooping","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^(l2 vfi|l2vpn vfi|bridge-domain)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"1da6f605ebfb4802","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"ip igmp snooping","high":""}},
#|{"id":"R-D56111","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216710","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"bridge-domain","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"has","text":"mac limit maximum addresses","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^(l2 vfi|l2vpn vfi|bridge-domain)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"c4300cf523b69a67","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"bridge-domain <BRIDGE_DOMAIN>\n mac limit maximum addresses <MAX_MACS>"}},
#|{"id":"R-DA8B88","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216714","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"policy-map","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s*service-policy output \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*mpls (ip|label protocol|ldp)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nConfirm the classes / bandwidth match the GIG QoS technical profile.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"c31201d08927daf7","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! build the QoS class-maps / policy-map per the GIG QoS profile, then on each interface:\ninterface <INTERFACE>\n service-policy output <QOS_POLICY>"}},
#|{"id":"R-FEB4F1","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216715","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"policy-map","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s*service-policy output \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*mpls (ip|label protocol|ldp)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nConfirm the classes / bandwidth match the GIG QoS technical profile.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"021faec8136e3863","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! build the QoS class-maps / policy-map per the GIG QoS profile, then on each interface:\ninterface <INTERFACE>\n service-policy output <QOS_POLICY>"}},
#|{"id":"R-24DE51","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216716","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"match (ip )?dscp (cs1|8)\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s*service-policy (output|input) \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nScavenger (CS1) class with low priority in the QoS policy.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"be3746fa7b00db4a","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"class-map match-all SCAVENGER\n match ip dscp cs1\npolicy-map <QOS_POLICY>\n class SCAVENGER\n  bandwidth percent 5"}},
#|{"id":"R-FD80F6","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216718","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"re:^\\s*ip pim (sparse|dense)","exclude":"","if_none":"pass","check":"has","text":"ip pim neighbor-filter","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"8e6739244deda9ff","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ip pim neighbor-filter <PIM_NEIGHBOR_ACL>"}},
#|{"id":"R-F9847B","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216719","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"interface","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip multicast boundary","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nEdge multicast routers only.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"9a8c3a491e4f7bb0","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"interface <EDGE_INTERFACE>\n ip multicast boundary <MULTICAST_SCOPE_ACL>"}},
#|{"id":"R-F72A89","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216720","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip pim accept-register","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip pim register-rate-limit","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nRendezvous Point routers only; also verify MSDP peer filtering.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"0b50b27d3ccdecdc","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip pim accept-register list <PIM_REGISTER_ACL>\nip pim register-rate-limit <RATE>"}},
#|{"id":"R-4A1241","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216721","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip pim accept-register","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nRendezvous Point routers only.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"4bd68d62a66c25db","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip pim accept-register list <PIM_REGISTER_ACL>"}},
#|{"id":"R-C1FDD3","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216722","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip pim accept-rp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nRendezvous Point routers only.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"8eaf4bc4d97537b9","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip pim accept-rp <RP_ADDRESS> <PIM_JOIN_ACL>"}},
#|{"id":"R-0A28BE","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216723","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip pim register-rate-limit","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nRendezvous Point routers only.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"7cb75eb6ac61b7fb","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip pim register-rate-limit <RATE>"}},
#|{"id":"R-844932","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216724","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"re:^\\s*ip pim (sparse|dense)","exclude":"","if_none":"pass","check":"has","text":"ip igmp access-group","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nSource Specific Multicast only; N/A for Any Source Multicast.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"64c5d7b4d2e8d55a","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ip igmp access-group <IGMP_JOIN_ACL>"}},
#|{"id":"R-729DB9","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216725","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"re:^\\s*ip pim (sparse|dense)","exclude":"","if_none":"pass","check":"has","text":"ip igmp access-group","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nSource Specific Multicast only.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"5815a0a3a5979864","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ip igmp access-group <IGMP_JOIN_ACL>"}},
#|{"id":"R-80D7B9","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216726","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ANY","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip igmp limit","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"interface","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip igmp limit","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"0d93f7b8a2ea2950","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip igmp limit <IGMP_LIMIT>"}},
#|{"id":"R-777FD9","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216727","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip pim spt-threshold infinity","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"c2920988ca9bb37c","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip pim spt-threshold infinity"}},
#|{"id":"R-A35A98","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216729","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip msdp password peer","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip msdp peer","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"287fd57551833bf2","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip msdp password peer <MSDP_PEER> <MSDP_KEY>"}},
#|{"id":"R-7DB7D8","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216730","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip msdp sa-filter in ","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip msdp peer","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"033adec6af6619b0","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip msdp sa-filter in <MSDP_PEER> list <INBOUND_SA_ACL>"}},
#|{"id":"R-8F7763","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216731","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip msdp sa-filter out ","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip msdp peer","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"dd3322ce7a07f105","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip msdp sa-filter out <MSDP_PEER> list <OUTBOUND_SA_ACL>"}},
#|{"id":"R-83CEEB","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216732","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip msdp sa-limit","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip msdp peer","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"2e737391f0f5187d","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip msdp sa-limit <MSDP_PEER> <SA_LIMIT>"}},
#|{"id":"R-50FAED","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216733","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip msdp peer \\S+ connect-source [Ll]oopback","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip msdp peer","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"23a60f2d59d79994","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip msdp peer <MSDP_PEER> connect-source Loopback0"}},
#|{"id":"R-E6E174","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-216999","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ttl-security hops","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nEvery eBGP neighbor needs ttl-security; refine per neighbor.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"6a8317620b1f4f5d","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n neighbor <EBGP_PEER> ttl-security hops 1"}},
#|{"id":"R-337DD6","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-217001","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip options (drop|ignore)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*mpls (ip|label protocol|ldp)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"e9d201541bcd1418","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip options drop"}},
#|{"id":"R-69BF7C","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-229031","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"no ip cef","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"no ipv6 cef","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nCEF is on by default and only shows when disabled.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"5ae6c36313c56b03","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"ip cef\nipv6 cef","high":""}},
#|{"id":"R-FB635C","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-230039","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*ipv6 (nd )?hop-limit ([0-9]|[12][0-9]|3[01])\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*ipv6 address\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"9d1c44ad5d43879e","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"ipv6 hop-limit 64","high":""}},
#|{"id":"R-F76D28","stig_id":"Cisco_IOS-XE_Router_RTR_STIG","vuln_id":"V-230042","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ipv6 address fec","how":"contains","ignore_case":true,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*ipv6 address\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 8300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"e13e419bd34f4885","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! replace any FEC0::/10 (site-local) IPv6 addresses with global or ULA addresses"}},
#|{"id":"R-02EC6C","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220649","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"role:access","exclude":"re:^\\s*shutdown\\s*$","if_none":"fail","check":"has","text":"^\\s*(authentication port-control auto|access-session port-control auto|dot1x pae authenticator|mab)\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"dot1x system-auth-control","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. Every access port needs 802.1x / MAB (legacy 'authentication port-control' or IBNS 2.0 'access-session'). Ports in telecom rooms / wiring closets are exempt - label them differently.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"55ca41a605e208c6","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:59:05","fix":{"low":"","high":"dot1x system-auth-control\n{each failing section of condition 1}\n authentication port-control auto\n dot1x pae authenticator\n mab"}},
#|{"id":"R-57834C","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220650","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show vtp status","show vtp password"],"pass_logic":{"mode":"ANY","conditions":[{"command":"show vtp status","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"VTP Operating Mode\\s*:\\s*Off","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show vtp password","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"VTP Password:\\s*\\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nCatalyst 9300 defaults to VTP Server mode, so a password is required unless VTP is off.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"f1bf153b6333f85e","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"vtp mode off"}},
#|{"id":"R-90B9F1","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220651","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"policy-map","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s*service-policy (output|input) \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nConfirm the classes / bandwidth match the QoS policy.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"7ca30b494d202e38","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! build the QoS policy per the site QoS design, then on each port:\ninterface <INTERFACE>\n service-policy output <QOS_POLICY>"}},
#|{"id":"R-64E43F","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220655","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"role:downlink","exclude":"re:^\\s*shutdown\\s*$","if_none":"pass","check":"has","text":"spanning-tree guard root","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. Root Guard on every DOWNLINK (ports facing access-layer switches). Access switches with no downlinks pass.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"19fdddd97ffe3d45","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:59:05","fix":{"low":"","high":"{each failing section}\n spanning-tree guard root"}},
#|{"id":"R-CC10FE","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220656","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ANY","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^spanning-tree portfast (edge )?bpduguard default","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"role:access","exclude":"re:^\\s*shutdown\\s*$","if_none":"fail","check":"has","text":"spanning-tree bpduguard enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. Global portfast bpduguard default, or BPDU Guard on every access port.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"eddd0d0fba65edf9","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:59:05","fix":{"low":"","high":"spanning-tree portfast edge bpduguard default"}},
#|{"id":"R-5EEB70","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220657","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"spanning-tree loopguard default","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"c009497987a1b6cb","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"spanning-tree loopguard default"}},
#|{"id":"R-5C2A8C","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220658","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"role:access","exclude":"re:^\\s*shutdown\\s*$","if_none":"fail","check":"has","text":"switchport block unicast","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. ","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"f70a35182efa855f","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:59:05","fix":{"low":"","high":"{each failing section}\n switchport block unicast"}},
#|{"id":"R-2FFB8F","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220659","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip dhcp snooping","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip dhcp snooping vlan \\S+","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"role:uplink","exclude":"re:^\\s*shutdown\\s*$","if_none":"fail","check":"has","text":"ip dhcp snooping trust","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"","exclude":"role:uplink","if_none":"pass","check":"lacks","text":"ip dhcp snooping trust","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. Snooping on all user VLANs; 'ip dhcp snooping trust' on every UPLINK and on nothing else (trust on a client port lets a rogue DHCP server through).","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"fb8002ed7ff23d37","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:59:05","fix":{"low":"","high":"ip dhcp snooping vlan <USER_VLANS>\nip dhcp snooping\n{each failing section of condition 3}\n ip dhcp snooping trust\n{each failing section of condition 4}\n no ip dhcp snooping trust"}},
#|{"id":"R-A74AF4","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220660","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"role:access","exclude":"re:^\\s*shutdown\\s*$","if_none":"fail","check":"has","text":"ip verify source","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. 802.1x / MAB ports may be exempt - adjust if so.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"704e9907169b0018","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:59:05","fix":{"low":"","high":"{each failing section}\n ip verify source"}},
#|{"id":"R-F00C45","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220661","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip arp inspection vlan \\S+","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"role:uplink","exclude":"re:^\\s*shutdown\\s*$","if_none":"fail","check":"has","text":"ip arp inspection trust","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"","exclude":"role:uplink","if_none":"pass","check":"lacks","text":"ip arp inspection trust","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. DAI on all user VLANs; 'ip arp inspection trust' on every UPLINK and on nothing else.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"8cad0d4272561a38","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:59:05","fix":{"low":"","high":"ip arp inspection vlan <USER_VLANS>\n{each failing section of condition 2}\n ip arp inspection trust\n{each failing section of condition 3}\n no ip arp inspection trust"}},
#|{"id":"R-81901F","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220662","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"role:access","exclude":"re:^\\s*shutdown\\s*$","if_none":"fail","check":"has","text":"storm-control broadcast","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. ","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"9589b4008df8b31b","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:59:05","fix":{"low":"","high":"{each failing section}\n storm-control broadcast level <STORM_LEVEL_PERCENT>"}},
#|{"id":"R-01FCFD","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220663","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"no ip igmp snooping","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"84e680925c3f8c46","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"ip igmp snooping","high":""}},
#|{"id":"R-BADD84","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220664","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^spanning-tree mode (rapid-pvst|mst)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"b900fa1c5cda4984","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"spanning-tree mode rapid-pvst"}},
#|{"id":"R-BBCE16","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220665","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ANY","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^udld (enable|aggressive)\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"interface","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"udld port","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nOnly required where there are fiber links to neighbors.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"d5d70bf0fa7ae815","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"udld enable"}},
#|{"id":"R-34D99F","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220666","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show interfaces switchport"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show interfaces switchport","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"Negotiation of Trunking:\\s*On","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nCatalyst 9300 ports default to 'dynamic auto' (not shown in the config), so this reads 'show interfaces switchport'. AppGigabitEthernet ports may need excluding.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"67ec94395dcf4182","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! for every port showing 'Negotiation of Trunking: On':\ninterface <PORT>\n switchport mode <ACCESS_OR_TRUNK>\n switchport nonegotiate"}},
#|{"id":"R-221409","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220667","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"^interface (?!AppGig)\\S*(Ethernet|GigE)\\d","section_how":"regex","only":"re:^\\s*shutdown\\s*$","exclude":"re:^\\s*(no switchport|vrf forwarding)\\b","if_none":"pass","check":"has","text":"^\\s*switchport access vlan \\d+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nEDIT to your parking VLAN, e.g. text 'switchport access vlan 999' (whole line). Also confirm that VLAN is pruned from every trunk.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"b953f9da2171f354","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"{each failing section}\n switchport access vlan <PARKING_VLAN>","high":""}},
#|{"id":"R-607C77","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220668","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show vlan brief"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show vlan brief","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^1\\s+default\\s+active\\s+\\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nFails if any port is listed under VLAN 1.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"1859109029c440fa","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! move every port listed under VLAN 1 to its proper VLAN:\ninterface <PORT>\n switchport access vlan <USER_VLAN>"}},
#|{"id":"R-5E3323","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220669","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"^interface (?!AppGig)\\S*(Ethernet|GigE)\\d","section_how":"regex","only":"switchport mode trunk","exclude":"shutdown","if_none":"pass","check":"has","text":"switchport trunk allowed vlan","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"^interface (?!AppGig)\\S*(Ethernet|GigE)\\d","section_how":"regex","only":"switchport mode trunk","exclude":"shutdown","if_none":"pass","check":"lacks","text":"switchport trunk allowed vlan (add )?(.*,)?1(-\\d+)?(,.*)?\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"18ead6df02ae7478","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n switchport trunk allowed vlan remove 1"}},
#|{"id":"R-5B26C2","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220670","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface Vlan1","section_how":"whole line","only":"","exclude":"","if_none":"pass","check":"lacks","text":"^\\s*ip address \\d","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"802e6b1563f70ed9","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! move management to a dedicated VLAN first, then:\ninterface Vlan1\n no ip address\n shutdown"}},
#|{"id":"R-49E298","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220671","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"role:access","exclude":"re:^\\s*shutdown\\s*$","if_none":"fail","check":"has","text":"switchport mode access","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"^interface (?!AppGig)\\S*(Ethernet|GigE)\\d","section_how":"regex","only":"","exclude":"re:^\\s*(shutdown|no switchport|vrf forwarding|channel-group)\\b","if_none":"pass","check":"has","text":"role:any","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. Condition 1: every access-role port is a static access port. Condition 2: every live front-panel port carries a role label, so no port escapes the role-based checks.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"83c1eb399380f2c9","created_at":"2026-10-03T20:59:05","origin":"starter-drafts","fix":{"low":"{each failing section of condition 2}\n ! label this port: description UPLINK - ... / DOWNLINK - ... / ACCESS - ...","high":"{each failing section of condition 1}\n switchport mode access\n switchport nonegotiate"},"saved_at":"2026-10-03T20:59:05"},
#|{"id":"R-ACF13F","stig_id":"Cisco_IOS_XE_Switch_L2S_STIG","vuln_id":"V-220672","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"^interface (?!AppGig)\\S*(Ethernet|GigE)\\d","section_how":"regex","only":"switchport mode trunk","exclude":"shutdown","if_none":"pass","check":"has","text":"^\\s*switchport trunk native vlan ([2-9]|\\d{2,})\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nAlternative: 'vlan dot1q tag native' globally - add as an ANY option if used.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"512284118c9c25ea","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n switchport trunk native vlan <NATIVE_VLAN>"}},
#|{"id":"R-344FD8","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220518","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"line vty","section_how":"starts with","only":"","exclude":"transport input none","if_none":"pass","check":"has","text":"session-limit","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nPlatforms without session-limit pass by limiting active vty lines instead (vty 0 1 transport ssh, others 'transport input none') - adjust if so. If 'ip http secure-server' is on, also require 'ip http max-connections'.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"cf97f545c633833c","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"ip http max-connections 2","high":"line vty 0 4\n session-limit 2"}},
#|{"id":"R-CB6115","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220519","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"archive","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"a71c621d8cc4b610","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"archive\n log config\n  logging enable\n  logging size 1000","high":""}},
#|{"id":"R-A91749","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220520","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"archive","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"b63e828fd654f511","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"archive\n log config\n  logging enable\n  logging size 1000","high":""}},
#|{"id":"R-40A94A","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220521","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"archive","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"78d27c3eb547c284","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"archive\n log config\n  logging enable\n  logging size 1000","high":""}},
#|{"id":"R-DFAC3A","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220522","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"archive","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"c8ab409a5f547bd8","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"archive\n log config\n  logging enable\n  logging size 1000","high":""}},
#|{"id":"R-F37693","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220523","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"line vty","section_how":"starts with","only":"","exclude":"transport input none","if_none":"pass","check":"has","text":"^\\s*access-class \\S+ in","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nAlso confirm the ACL only permits the management network.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"030d07bce27d4da4","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip access-list extended MGMT_NET\n permit ip <MGMT_SUBNET> <MGMT_WILDCARD> any\n deny ip any any log-input\nline vty 0 4\n access-class MGMT_NET in"}},
#|{"id":"R-EC8C3C","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220524","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"login block-for","how":"starts with","ignore_case":false,"op":">=","value":"900"},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"attempts","how":"contains","ignore_case":false,"op":"<=","value":"3"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"7e3896b1afe6a726","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"login block-for 900 attempts 3 within 120"}},
#|{"id":"R-F69211","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220525","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"banner login","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"You are accessing a U.S. Government (USG) Information System","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"f5a23676cd841898","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"banner login ^C\nYou are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n-At any time, the USG may inspect and seize data stored on this IS.\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.\n^C","high":""}},
#|{"id":"R-DC973B","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220526","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging userinfo","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"archive","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"9e31d10af95b07b4","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"logging userinfo\narchive\n log config\n  logging enable\n  logging size 1000","high":""}},
#|{"id":"R-E9DF28","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220528","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"service timestamps log datetime","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"ed160dfb2126a6c2","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"service timestamps log datetime msec localtime show-timezone","high":""}},
#|{"id":"R-69A008","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220529","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"ip access-list extended","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"^\\s*(\\d+\\s+)?deny\\b(?!.*\\blog-input\\b)","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nOnly interface-bound ACLs matter; CoPP / route-filter ACLs may need excluding.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"5af12a202a75beee","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ! add 'log-input' to every deny statement in this ACL, e.g. <SEQ> deny ip any any log-input"}},
#|{"id":"R-BF0AA8","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220530","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"archive","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"b73979b71dfbf9dd","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"archive\n log config\n  logging enable\n  logging size 1000","high":""}},
#|{"id":"R-4EC951","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220531","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"file privilege","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"logging persistent","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"2217e04dca93bdd5","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"file privilege 15","high":""}},
#|{"id":"R-5D3DAE","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220532","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"file privilege","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"logging persistent","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"2217e04dca93bdd5","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"file privilege 15","high":""}},
#|{"id":"R-523496","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220533","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"file privilege","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"logging persistent","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"2217e04dca93bdd5","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"file privilege 15","high":""}},
#|{"id":"R-F1659F","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220534","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip boot server","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip bootp server","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip dns server","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip identd","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip finger","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip http server","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip rcmd rcp-enable","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip rcmd rsh-enable","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"service config","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"service finger","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"service tcp-small-servers","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"service udp-small-servers","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"service pad","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"service call-home","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"boot network","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nCatalyst 9300/8300 17.x often ship with 'service call-home' and 'ip http server' on. Call-home is allowed only on legacy devices that need it for Smart Licensing - otherwise a finding.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"3d822b21fcb116c7","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"no service pad\nno service finger\nno service tcp-small-servers\nno service udp-small-servers\nno ip finger\nno ip identd\nno ip bootp server\nno ip dns server\nno ip rcmd rcp-enable\nno ip rcmd rsh-enable\nno service config\nno ip boot server","high":"no ip http server\nno service call-home"}},
#|{"id":"R-272D86","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220535","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"count","text":"username ","how":"starts with","ignore_case":false,"op":"==","value":"1"},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^aaa authentication login \\S+ group \\S+ .*\\blocal\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nExactly one local account; local must come after the AAA server group.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"479c6ad10e2dfdb7","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! remove every local account except the account of last resort:\n! no username <EXTRA_ACCOUNT>\naaa authentication login default group <AAA_GROUP> local"}},
#|{"id":"R-D50A2A","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220537","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"aaa common-criteria policy","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"min-length","how":"starts with","ignore_case":false,"op":">=","value":"15"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"711317fea6236845","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa common-criteria policy PASSWORD_POLICY\n min-length 15","high":""}},
#|{"id":"R-BC7678","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220538","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"aaa common-criteria policy","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"upper-case","how":"starts with","ignore_case":false,"op":">=","value":"1"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"8583fb06d54697d7","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa common-criteria policy PASSWORD_POLICY\n upper-case 1","high":""}},
#|{"id":"R-285582","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220539","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"aaa common-criteria policy","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"lower-case","how":"starts with","ignore_case":false,"op":">=","value":"1"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"56461bfa57c1ff63","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa common-criteria policy PASSWORD_POLICY\n lower-case 1","high":""}},
#|{"id":"R-42F336","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220540","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"aaa common-criteria policy","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"numeric-count","how":"starts with","ignore_case":false,"op":">=","value":"1"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"69755e7b0115fde5","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa common-criteria policy PASSWORD_POLICY\n numeric-count 1","high":""}},
#|{"id":"R-EEC310","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220541","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"aaa common-criteria policy","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"special-case","how":"starts with","ignore_case":false,"op":">=","value":"1"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"1accae0d321e48d3","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa common-criteria policy PASSWORD_POLICY\n special-case 1","high":""}},
#|{"id":"R-0B127E","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220542","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"aaa common-criteria policy","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"char-changes","how":"starts with","ignore_case":false,"op":">=","value":"8"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"7ae534b00753ca6e","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa common-criteria policy PASSWORD_POLICY\n char-changes 8","high":""}},
#|{"id":"R-A3C997","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220543","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"service password-encryption","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"enable secret","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"enable password","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"fc31d02284286c2b","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"service password-encryption","high":"no enable password\nenable algorithm-type scrypt secret <ENABLE_SECRET>"}},
#|{"id":"R-3C16B8","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220544","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"line vty","section_how":"starts with","only":"","exclude":"transport input none","if_none":"pass","check":"number","text":"exec-timeout","how":"starts with","ignore_case":false,"op":"<=","value":"5"},{"command":"show running-config","scope":"every","section":"line con","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"exec-timeout","how":"starts with","ignore_case":false,"op":"<=","value":"5"},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*exec-timeout 0 0\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nexec-timeout absent = default 10 minutes (finding). If 'ip http secure-server' is on, also check 'ip http timeout-policy idle 300' or less.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"b0aaec86037913fe","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"line con 0\n exec-timeout 5 0\nline vty 0 4\n exec-timeout 5 0\nip http timeout-policy idle 300 life 86400 requests 10000","high":""}},
#|{"id":"R-5CF217","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220545","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"archive","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"da43f4d22b61225e","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"archive\n log config\n  logging enable\n  logging size 1000","high":""}},
#|{"id":"R-E2C527","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220547","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^logging buffered \\d+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"9d56d79a9380a727","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"logging buffered 64000 informational","high":""}},
#|{"id":"R-FC3D39","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220548","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^logging trap (emergencies|alerts|0|1)\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nNo 'logging trap' line means informational (compliant).","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"d72ad67c52ad5214","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"logging trap critical","high":""}},
#|{"id":"R-41C3CE","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220549","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"count","text":"ntp server","how":"starts with","ignore_case":false,"op":">=","value":"2"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"b4bb10276b3df5fb","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"ntp server <NTP_SERVER_1>\nntp server <NTP_SERVER_2>","high":""}},
#|{"id":"R-898AEA","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220552","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config","show snmp user"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^snmp-server group \\S+ v3 (auth|priv)\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^snmp-server group \\S+ v3 noauth\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"snmp-server community","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show snmp user","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"Authentication Protocol:\\s*(MD5|None)","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^snmp-server (group|user|host|community)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nIOS-XE does not print SNMPv3 users in the running-config, so the HMAC is read from 'show snmp user' (SHA / SHA-2 required).","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"7495fe85d83b1d61","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"snmp-server group <SNMP_GROUP> v3 priv read <SNMP_VIEW>\nsnmp-server user <SNMP_USER> <SNMP_GROUP> v3 auth sha <AUTH_PASSWORD> priv aes 256 <PRIV_PASSWORD>\nno snmp-server community <OLD_COMMUNITY>"}},
#|{"id":"R-88E7A0","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220553","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config","show snmp user"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^snmp-server group \\S+ v3 priv\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^snmp-server group \\S+ v3 (auth|noauth)\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show snmp user","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"Privacy Protocol:\\s*(None|DES|3DES)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^snmp-server (group|user|host|community)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"bc9b9cdef9df872a","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"snmp-server group <SNMP_GROUP> v3 priv read <SNMP_VIEW>\nsnmp-server user <SNMP_USER> <SNMP_GROUP> v3 auth sha <AUTH_PASSWORD> priv aes 256 <PRIV_PASSWORD>"}},
#|{"id":"R-5E5F29","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220554","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ntp authenticate","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ntp authentication-key \\d+ hmac-sha2","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ntp trusted-key","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^ntp server (?!.*\\bkey\\b)","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nhmac-sha2-256 NTP keys need a recent IOS-XE 17.x release; older releases only offer MD5.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"358b97536b5603f9","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ntp authentication-key 1 hmac-sha2-256 <NTP_KEY>\nntp authenticate\nntp trusted-key 1\nntp server <NTP_SERVER_1> key 1\nntp server <NTP_SERVER_2> key 1"}},
#|{"id":"R-30CECB","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220555","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip ssh version 2","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip ssh server algorithm mac","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^ip ssh server algorithm mac .*hmac-sha1","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"f82b68d658b241d2","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip ssh version 2\nip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256"}},
#|{"id":"R-4A2E1F","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220556","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip ssh server algorithm encryption","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^ip ssh server algorithm encryption .*(cbc|3des)","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"63224cfd2d30e640","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr"}},
#|{"id":"R-D33421","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220559","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"archive","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"2effd2875bd483e7","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"archive\n log config\n  logging enable\n  logging size 1000","high":""}},
#|{"id":"R-E55DA9","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220560","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"login on-failure log","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"login on-success log","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"8c37112fe8f7b9d4","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"login on-failure log\nlogin on-success log","high":""}},
#|{"id":"R-75A7BA","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220561","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"archive","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"53d9102d47c28695","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"archive\n log config\n  logging enable\n  logging size 1000","high":""}},
#|{"id":"R-9F7F71","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220565","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"count","text":"^(radius server|tacacs server|radius-server host|tacacs-server host) ","how":"regex","ignore_case":false,"op":">=","value":"2"},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^aaa authentication login \\S+ group ","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"8bae5710995c5f00","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"tacacs server <AAA_SERVER_1>\n address ipv4 <AAA_IP_1>\n key <AAA_KEY>\ntacacs server <AAA_SERVER_2>\n address ipv4 <AAA_IP_2>\n key <AAA_KEY>\naaa group server tacacs+ <AAA_GROUP>\n server name <AAA_SERVER_1>\n server name <AAA_SERVER_2>\naaa authentication login default group <AAA_GROUP> local"}},
#|{"id":"R-118371","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220566","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"event manager applet","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"CONFIG_I","how":"contains","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"event manager applet","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"copy running-config (scp|sftp|https)://","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"file prompt quiet","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nAlso confirm no cleartext password is embedded in the copy URL.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"94dfa07615e77c7f","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"file prompt quiet\nevent manager applet BACKUP_CONFIG authorization bypass\n event syslog pattern \"%SYS-5-CONFIG_I\"\n action 1 cli command \"enable\"\n action 2 info type routername\n action 3 cli command \"copy running-config scp://<SCP_USER>@<SCP_SERVER>/<SCP_PATH>/$_info_routername-running-config\"","high":""}},
#|{"id":"R-79FDD3","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220567","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"crypto pki trustpoint","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s*enrollment (url|terminal|profile)\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*enrollment selfsigned\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"crypto pki trustpoint","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nReviewer must confirm the CA is DoD / DoD-approved. IOS-XE creates a self-signed trustpoint for HTTPS - remove it or replace it with a CA-issued certificate. Cisco's SLA-TrustPoint (licensing, 'enrollment pkcs12') is ignored.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"90aeeaba32664a62","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! enroll with a DoD / DoD-approved CA and remove self-signed trustpoints:\ncrypto pki trustpoint <DOD_CA_TRUSTPOINT>\n enrollment url <CA_ENROLLMENT_URL>\n revocation-check crl\n! no crypto pki trustpoint <SELF_SIGNED_TRUSTPOINT>"}},
#|{"id":"R-AE679E","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220568","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"count","text":"^logging (host \\S+|\\d+\\.\\d+\\.\\d+\\.\\d+)","how":"regex","ignore_case":false,"op":">=","value":"2"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"dc2a54e6f5573b48","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"logging host <SYSLOG_SERVER_1>\nlogging host <SYSLOG_SERVER_2>","high":""}},
#|{"id":"R-348279","stig_id":"Cisco_IOS_XE_Switch_NDM_STIG","vuln_id":"V-220569","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show version"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show version","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"Cisco IOS XE Software, Version 17\\.(0?9|12|15)\\.","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nEDIT the version list to the Cisco-supported / site-approved releases before use.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"774622f0bc18d910","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! upgrade the device to a Cisco-supported IOS-XE release (not a config change)"}},
#|{"name":"access","state":"active","version":4,"commands":["show run | section archive"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show run | section archive","scope":"all","section":"archive","section_how":"starts with","exclude":"","if_none":"fail","check":"has","text":"archive","how":"starts with","ignore_case":true,"op":">=","value":""},{"command":"show run | section archive","scope":"all","section":"log config","section_how":"contains","exclude":"","if_none":"fail","check":"has","text":"log config","how":"contains","ignore_case":true,"op":">=","value":""},{"command":"show run | section archive","scope":"all","section":"","section_how":"starts with","exclude":"","if_none":"fail","check":"has","text":"logging","how":"contains","ignore_case":true,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"Not a finding because logging is enabled","notes":"","tests":[{"name":"Good config","expected":"not_a_finding","outputs":{"show run | section archive":"show run | section archive\narchive\n log config\n  logging enable"},"saved_at":"2026-10-03T09:30:09"},{"name":"bad config","expected":"open","outputs":{"show run | section archive":"show run | section archive\narchive\n log config\n  "},"saved_at":"2026-10-03T09:30:20"}],"id":"R-0001","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-220990","check_hash":"2c63abff18b6e4a4","created_at":"2026-10-03T09:24:53","updated_at":"2026-10-03T09:30:28","is_default":true},
#|{"id":"R-8B4DB7","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-220991","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show ip interface brief"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show ip interface brief","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\S+\\s+\\d+\\.\\d+\\.\\d+\\.\\d+\\s+\\S+\\s+\\S+\\s+down\\s+down\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nFlags interfaces that have an IP address, are not shut down, and are down/down. Unaddressed switchports are ignored.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"44482fe5415efbb4","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! shut down routed interfaces that are not in use:\ninterface <UNUSED_INTERFACE>\n shutdown"}},
#|{"id":"R-891A31","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-220994","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"service config","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"boot network","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"cns ","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"e512f486d0346de7","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"no service config\n! also remove any 'boot network' and 'cns' lines","high":""}},
#|{"id":"R-2602EA","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-220995","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ANY","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"policy-map system-cpp-policy","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"control-plane","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s*service-policy input \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nCatalyst 9300 uses the built-in system-cpp-policy; Catalyst 8300 uses a 'control-plane' service-policy. Also review policer rates with 'show policy-map control-plane'.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"2f9a265df439cd3e","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! Catalyst 9300: keep the built-in 'policy-map system-cpp-policy' and tune rates;\n! Catalyst 8300: build a CoPP policy-map and apply it:\ncontrol-plane\n service-policy input <COPP_POLICY>"}},
#|{"id":"R-E0D3FD","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-220998","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip gratuitous-arps","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"e07b3fa9bd58005d","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"no ip gratuitous-arps"}},
#|{"id":"R-250FB1","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-220999","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"ip directed-broadcast","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"9a1f08c2b3d649cf","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"{each failing section}\n no ip directed-broadcast","high":""}},
#|{"id":"R-E88D49","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221000","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"ip address","exclude":"shutdown","if_none":"pass","check":"has","text":"no ip unreachables","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nApplies to EXTERNAL interfaces only - narrow 'only' / 'skip' to your external interfaces (or use 'ip icmp rate-limit unreachable' on the DODIN backbone).","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"45bae240458a2e16","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"{each failing section}\n no ip unreachables","high":""}},
#|{"id":"R-A6FEC4","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221001","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"ip mask-reply","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"b6dbe52abb569e2d","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"{each failing section}\n no ip mask-reply","high":""}},
#|{"id":"R-3CB304","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221002","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"ip address","exclude":"shutdown","if_none":"pass","check":"has","text":"no ip redirects","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nApplies to EXTERNAL interfaces only - narrow to your external interfaces.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"c23a3f22622c45cb","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"{each failing section}\n no ip redirects","high":""}},
#|{"id":"R-9F5AE4","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221003","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"ip access-list extended","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"^\\s*(\\d+\\s+)?deny\\b(?!.*\\blog(-input)?\\b)","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"88d8532be53a7ae1","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ! add 'log' or 'log-input' to every deny statement in this ACL"}},
#|{"id":"R-3C5E13","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221004","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"ip access-list extended","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"^\\s*(\\d+\\s+)?deny\\b(?!.*\\blog-input\\b)","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"40b8e57c19b949b1","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ! add 'log-input' to every deny statement in this ACL, e.g. <SEQ> deny ip any any log-input"}},
#|{"id":"R-9A6BA5","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221005","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"ip access-list extended","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"^\\s*(\\d+\\s+)?deny\\b(?!.*\\blog-input\\b)","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"9dbaefb6cf6176fd","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ! add 'log-input' to every deny statement in this ACL, e.g. <SEQ> deny ip any any log-input"}},
#|{"id":"R-37402F","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221006","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"line aux","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"no exec","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"line aux","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"fa6c5a24bf2bffc5","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"line aux 0\n no exec\n transport input none","high":""}},
#|{"id":"R-286928","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221016","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"lldp run","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nIf LLDP is needed internally, change to: every EXTERNAL interface has 'no lldp transmit'.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"040cf765f37c8d63","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"no lldp run"}},
#|{"id":"R-0535BA","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221017","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"no cdp run","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nCDP is ON by default on Catalyst 9300 and only 'no cdp run' shows when disabled. If CDP is needed internally, change to: every EXTERNAL interface has 'no cdp enable'.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"99288734f8f59c0a","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"no cdp run\n! (IP phones use CDP for the voice VLAN - use per-interface 'no cdp enable' on external interfaces instead if needed)"}},
#|{"id":"R-385B19","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221018","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"ip address","exclude":"shutdown","if_none":"pass","check":"has","text":"no ip proxy-arp","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nProxy ARP is on by default. Applies to EXTERNAL interfaces - narrow as needed.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"1b91067edab9cb6a","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n no ip proxy-arp"}},
#|{"id":"R-7FC3DE","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221021","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ttl-security hops","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nEvery eBGP neighbor needs ttl-security; refine per neighbor.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"8c6b1366159dc1f0","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n neighbor <EBGP_PEER> ttl-security hops 1"}},
#|{"id":"R-984911","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221023","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip prefix-list \\S+ seq \\d+ deny 10\\.0\\.0\\.0/8","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"neighbor \\S+ (prefix-list|route-map) \\S+ in\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nConfirm the full current Bogon list and that it is applied to ALL external peers.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"8226871dc0a8021e","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! build the Bogon prefix list (see check text) and apply it inbound to every eBGP peer:\nrouter bgp <ASN>\n neighbor <EBGP_PEER> prefix-list <BOGON_PREFIX_LIST> in"}},
#|{"id":"R-D8D2F0","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221024","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"neighbor \\S+ (prefix-list|route-map) \\S+ in\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nReviewer must confirm the inbound filter denies the local AS prefixes.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"3a383ecfb183427f","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip prefix-list <INBOUND_FILTER> seq <SEQ> deny <LOCAL_AS_PREFIX> le 32\nrouter bgp <ASN>\n neighbor <EBGP_PEER> prefix-list <INBOUND_FILTER> in"}},
#|{"id":"R-116AC8","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221025","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"neighbor \\S+ prefix-list \\S+ in\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nOnly for CE peers; confirm each customer's list holds only its prefixes.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"03bb8088afa25261","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n neighbor <CE_PEER> prefix-list <CUSTOMER_PREFIX_LIST> in"}},
#|{"id":"R-668273","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221026","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"neighbor \\S+ prefix-list \\S+ out\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"46bcc16e0b170dfb","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n neighbor <CE_PEER> prefix-list <ADVERTISE_PREFIX_LIST> out"}},
#|{"id":"R-F59F9D","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221027","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"neighbor \\S+ prefix-list \\S+ out\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"0cbd4182663df221","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n neighbor <EBGP_PEER> prefix-list <FILTER_CORE_PREFIXES> out"}},
#|{"id":"R-881D7F","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221028","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"no bgp enforce-first-as","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"18cf7fba54db3a8e","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n bgp enforce-first-as"}},
#|{"id":"R-3AF7FE","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221029","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip as-path access-list","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"neighbor \\S+ filter-list \\S+ in","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"288ca40aaea1cbb7","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip as-path access-list <AS_PATH_ACL> permit ^<CUSTOMER_AS>$\nrouter bgp <ASN>\n neighbor <CE_PEER> filter-list <AS_PATH_ACL> in"}},
#|{"id":"R-39F61A","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221030","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"maximum-prefix","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"85e14f59f63af5a3","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n neighbor <EBGP_PEER> maximum-prefix <MAX_PREFIXES>"}},
#|{"id":"R-C8C7F0","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221031","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip prefix-list \\S+ .*le 24\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"neighbor \\S+ prefix-list \\S+ in\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"f1162197fbf7b8db","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip prefix-list FILTER_PREFIX_LENGTH seq 5 permit 0.0.0.0/0 ge 8 le 24\nip prefix-list FILTER_PREFIX_LENGTH seq 10 deny 0.0.0.0/0 le 32\nrouter bgp <ASN>\n neighbor <EBGP_PEER> prefix-list FILTER_PREFIX_LENGTH in"}},
#|{"id":"R-07E2D9","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221032","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"router bgp","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"neighbor \\S+ update-source [Ll]oopback","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"router bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"a0860c610282a242","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n neighbor <IBGP_PEER> update-source Loopback0"}},
#|{"id":"R-A57195","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221033","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ANY","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"mpls ldp router-id","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^mpls ldp router-id [Ll]oopback","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*mpls (ip|label protocol|ldp)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"16e53ff5f27dc413","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"mpls ldp router-id Loopback0 force"}},
#|{"id":"R-21ABE0","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221034","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"^router (ospf|isis)\\b","section_how":"regex","only":"","exclude":"","if_none":"fail","check":"has","text":"mpls ldp sync","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*mpls (ip|label protocol|ldp)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"2cca14694b4b19c9","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router ospf <OSPF_PROCESS>\n mpls ldp sync"}},
#|{"id":"R-DDF2B8","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221035","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip rsvp signalling rate-limit","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"mpls traffic-eng tunnels","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"19d634a427c6543d","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip rsvp signalling rate-limit period 30 burst 9 maxsize 2100 limit 50"}},
#|{"id":"R-EEE026","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221036","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"no mpls ip propagate-ttl","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*mpls (ip|label protocol|ldp)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"996fc1990859d92c","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"no mpls ip propagate-ttl"}},
#|{"id":"R-CBA7BB","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221043","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"no-split-horizon","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^(l2 vfi|l2vpn vfi|bridge-domain)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"0418d3787264afec","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! remove 'no-split-horizon' from VFI neighbor statements (mesh VPLS only)"}},
#|{"id":"R-1280A1","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221044","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"re:^\\s*bridge-domain","exclude":"","if_none":"pass","check":"has","text":"storm-control broadcast","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^(l2 vfi|l2vpn vfi|bridge-domain)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"271109e2c2e62b05","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n storm-control broadcast cir <STORM_CIR>"}},
#|{"id":"R-181F3F","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221045","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"no ip igmp snooping","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^(l2 vfi|l2vpn vfi|bridge-domain)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"906e17663b7b2034","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"ip igmp snooping","high":""}},
#|{"id":"R-8EAC9D","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221046","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"bridge-domain","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"has","text":"mac limit maximum addresses","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^(l2 vfi|l2vpn vfi|bridge-domain)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"0b5a30c7f64427f0","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"bridge-domain <BRIDGE_DOMAIN>\n mac limit maximum addresses <MAX_MACS>"}},
#|{"id":"R-6DC7EB","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221049","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip options (drop|ignore)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*mpls (ip|label protocol|ldp)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"7ae2861c89b58f93","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip options drop"}},
#|{"id":"R-EE96FF","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221050","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"policy-map","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s*service-policy output \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*mpls (ip|label protocol|ldp)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nConfirm the classes / bandwidth match the GIG QoS technical profile.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"2776c35500ec8b4a","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! build the QoS class-maps / policy-map per the GIG QoS profile, then on each interface:\ninterface <INTERFACE>\n service-policy output <QOS_POLICY>"}},
#|{"id":"R-BF224D","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221051","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"policy-map","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s*service-policy output \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*mpls (ip|label protocol|ldp)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nConfirm the classes / bandwidth match the GIG QoS technical profile.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"bfa7587feff15ba5","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! build the QoS class-maps / policy-map per the GIG QoS profile, then on each interface:\ninterface <INTERFACE>\n service-policy output <QOS_POLICY>"}},
#|{"id":"R-45A99F","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221052","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"match (ip )?dscp (cs1|8)\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s*service-policy (output|input) \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nScavenger (CS1) class with low priority in the QoS policy.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"c846f94705d8f94f","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"class-map match-all SCAVENGER\n match ip dscp cs1\npolicy-map <QOS_POLICY>\n class SCAVENGER\n  bandwidth percent 5"}},
#|{"id":"R-D3153C","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221054","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"re:^\\s*ip pim (sparse|dense)","exclude":"","if_none":"pass","check":"has","text":"ip pim neighbor-filter","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"dfd3c7fe76e171a9","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ip pim neighbor-filter <PIM_NEIGHBOR_ACL>"}},
#|{"id":"R-8F7B46","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221055","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"interface","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip multicast boundary","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nEdge multicast routers only.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"8b67e2d1aa1205b8","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"interface <EDGE_INTERFACE>\n ip multicast boundary <MULTICAST_SCOPE_ACL>"}},
#|{"id":"R-65A03F","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221056","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip pim accept-register","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip pim register-rate-limit","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nRendezvous Point routers only; also verify MSDP peer filtering.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"4890a2ea4564e39d","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip pim accept-register list <PIM_REGISTER_ACL>\nip pim register-rate-limit <RATE>"}},
#|{"id":"R-74F781","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221057","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip pim accept-register","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nRendezvous Point routers only.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"905180261f598594","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip pim accept-register list <PIM_REGISTER_ACL>"}},
#|{"id":"R-C2A48A","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221058","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip pim accept-rp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nRendezvous Point routers only.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"3e93c4799cf03dec","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip pim accept-rp <RP_ADDRESS> <PIM_JOIN_ACL>"}},
#|{"id":"R-E1CA38","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221059","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip pim register-rate-limit","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nRendezvous Point routers only.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"7cb75eb6ac61b7fb","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip pim register-rate-limit <RATE>"}},
#|{"id":"R-8DA815","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221060","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"re:^\\s*ip pim (sparse|dense)","exclude":"","if_none":"pass","check":"has","text":"ip igmp access-group","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nSource Specific Multicast only; N/A for Any Source Multicast.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"312b92ac7bc53f0e","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ip igmp access-group <IGMP_JOIN_ACL>"}},
#|{"id":"R-45B433","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221061","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"re:^\\s*ip pim (sparse|dense)","exclude":"","if_none":"pass","check":"has","text":"ip igmp access-group","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nSource Specific Multicast only.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"057972f2ea1cf182","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ip igmp access-group <IGMP_JOIN_ACL>"}},
#|{"id":"R-F92D76","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221062","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ANY","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip igmp limit","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"interface","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip igmp limit","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"b1ba7d9f66bd32d6","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip igmp limit <IGMP_LIMIT>"}},
#|{"id":"R-A24B63","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221063","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip pim spt-threshold infinity","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip multicast-routing","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"c2920988ca9bb37c","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip pim spt-threshold infinity"}},
#|{"id":"R-143013","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221065","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip msdp password peer","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip msdp peer","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"7e0215bd12281d2a","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip msdp password peer <MSDP_PEER> <MSDP_KEY>"}},
#|{"id":"R-3D9E9D","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221066","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip msdp sa-filter in ","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip msdp peer","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"aae73d7dca8394af","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip msdp sa-filter in <MSDP_PEER> list <INBOUND_SA_ACL>"}},
#|{"id":"R-FF0A31","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221067","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip msdp sa-filter out ","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip msdp peer","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"16839d0f4f8373d0","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip msdp sa-filter out <MSDP_PEER> list <OUTBOUND_SA_ACL>"}},
#|{"id":"R-5C8F93","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221068","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip msdp sa-limit","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip msdp peer","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"468efe7a31e6aaf6","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip msdp sa-limit <MSDP_PEER> <SA_LIMIT>"}},
#|{"id":"R-BFA437","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-221069","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip msdp peer \\S+ connect-source [Ll]oopback","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ip msdp peer","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"e12ba0c51d5463b9","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip msdp peer <MSDP_PEER> connect-source Loopback0"}},
#|{"id":"R-A2193B","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-237750","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"no ip cef","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"no ipv6 cef","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nCEF is on by default and only shows when disabled.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"ba6fe21b629c5ccb","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"ip cef\nipv6 cef","high":""}},
#|{"id":"R-46D135","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-237752","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*ipv6 (nd )?hop-limit ([0-9]|[12][0-9]|3[01])\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*ipv6 address\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"17b38df7322def94","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"ipv6 hop-limit 64","high":""}},
#|{"id":"R-7B045C","stig_id":"Cisco_IOS_XE_Switch_RTR_STIG","vuln_id":"V-237756","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ipv6 address fec","how":"contains","ignore_case":true,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*ipv6 address\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Catalyst 9300 (IOS-XE 17.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"228c5126dd919a92","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! replace any FEC0::/10 (site-local) IPv6 addresses with global or ULA addresses"}},
#|{"id":"R-1DC1E9","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220675","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"^interface Ethernet\\d","section_how":"regex","only":"role:access","exclude":"re:^\\s*shutdown\\s*$","if_none":"fail","check":"has","text":"^\\s*dot1x (port-control auto|mac-auth-bypass)","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"feature dot1x","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. Data-center leaf ports rarely face users; mark N/A per group if no LAN outlets connect.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"056bf82a0b5a4f71","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:59:05","fix":{"low":"","high":"feature dot1x\n{each failing section of condition 1}\n  dot1x port-control auto"}},
#|{"id":"R-FBE172","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220676","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ANY","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature vtp","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^vtp mode (transparent|off)\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"vtp password","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"65b3bfe59a9f06a0","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"no feature vtp\n! or: vtp mode transparent"}},
#|{"id":"R-AC74AC","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220677","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^monitor session \\d+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nThe STIG asks for the CAPABILITY to capture a session; a reviewer may accept NaF without a configured session.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"797d267571c13fdf","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"! confirm SPAN is available: monitor session <N> / source interface <PORT> both / destination interface <PORT>","high":""}},
#|{"id":"R-D11665","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220678","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^monitor session \\d+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nThe STIG asks for the CAPABILITY to capture a session; a reviewer may accept NaF without a configured session.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"b1da9839b85c98f5","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"! confirm SPAN is available: monitor session <N> / source interface <PORT> both / destination interface <PORT>","high":""}},
#|{"id":"R-6782DF","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220679","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"^interface Ethernet\\d","section_how":"regex","only":"role:access","exclude":"re:^\\s*shutdown\\s*$","if_none":"fail","check":"has","text":"^\\s*dot1x (port-control auto|mac-auth-bypass)","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"feature dot1x","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. Data-center leaf ports rarely face users; mark N/A per group if no LAN outlets connect.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"82c3dab7917abefa","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:59:05","fix":{"low":"","high":"feature dot1x\n{each failing section of condition 1}\n  dot1x port-control auto"}},
#|{"id":"R-EEE88D","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220680","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"role:downlink","exclude":"re:^\\s*shutdown\\s*$","if_none":"pass","check":"has","text":"spanning-tree guard root","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. Root Guard on every DOWNLINK (ports facing access-layer switches / hosts).","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"f418205fb98502fe","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:59:05","fix":{"low":"","high":"{each failing section}\n spanning-tree guard root"}},
#|{"id":"R-829C95","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220681","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ANY","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"spanning-tree port type edge bpduguard default","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"^interface Ethernet\\d","section_how":"regex","only":"role:access","exclude":"re:^\\s*shutdown\\s*$","if_none":"fail","check":"has","text":"spanning-tree bpduguard enable","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. ","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"fb305784db7d6eb3","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:59:05","fix":{"low":"","high":"spanning-tree port type edge bpduguard default"}},
#|{"id":"R-7EC109","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220682","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"spanning-tree loopguard default","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"d872d9848a744756","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"spanning-tree loopguard default"}},
#|{"id":"R-E35811","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220683","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"^interface Ethernet\\d","section_how":"regex","only":"role:access","exclude":"re:^\\s*shutdown\\s*$","if_none":"fail","check":"has","text":"switchport block unicast","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. ","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"2674d5a82eb0be8f","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:59:05","fix":{"low":"","high":"{each failing section}\n switchport block unicast"}},
#|{"id":"R-B404C5","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220684","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip dhcp snooping","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip dhcp snooping vlan \\S+","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"role:uplink","exclude":"re:^\\s*shutdown\\s*$","if_none":"fail","check":"has","text":"ip dhcp snooping trust","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"","exclude":"role:uplink","if_none":"pass","check":"lacks","text":"ip dhcp snooping trust","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. 'ip dhcp snooping trust' on every UPLINK and on nothing else.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"3221f81cbb574bb2","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:59:05","fix":{"low":"","high":"feature dhcp\nip dhcp snooping\nip dhcp snooping vlan <USER_VLANS>\n{each failing section of condition 3}\n  ip dhcp snooping trust\n{each failing section of condition 4}\n  no ip dhcp snooping trust"}},
#|{"id":"R-900A95","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220685","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"^interface Ethernet\\d","section_how":"regex","only":"role:access","exclude":"re:^\\s*shutdown\\s*$","if_none":"fail","check":"has","text":"ip verify source dhcp-snooping-vlan","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. 802.1x / MAB ports are exempt.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"8b2137cd40bcf55c","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:59:05","fix":{"low":"","high":"{each failing section}\n ip verify source dhcp-snooping-vlan"}},
#|{"id":"R-2A89BA","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220686","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip arp inspection vlan \\S+","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"role:uplink","exclude":"re:^\\s*shutdown\\s*$","if_none":"fail","check":"has","text":"ip arp inspection trust","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"","exclude":"role:uplink","if_none":"pass","check":"lacks","text":"ip arp inspection trust","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. 'ip arp inspection trust' on every UPLINK and on nothing else.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"8cad0d4272561a38","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:59:05","fix":{"low":"","high":"ip arp inspection vlan <USER_VLANS>\n{each failing section of condition 2}\n  ip arp inspection trust\n{each failing section of condition 3}\n  no ip arp inspection trust"}},
#|{"id":"R-E89AFC","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220687","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"^interface Ethernet\\d","section_how":"regex","only":"role:access","exclude":"re:^\\s*shutdown\\s*$","if_none":"fail","check":"has","text":"storm-control broadcast","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. ","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"2674d5fa5164fe27","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:59:05","fix":{"low":"","high":"{each failing section}\n storm-control broadcast level <STORM_LEVEL_PERCENT>"}},
#|{"id":"R-9876BC","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220688","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"no ip igmp snooping","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"15facaa4431c12d4","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"ip igmp snooping","high":""}},
#|{"id":"R-14980F","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220689","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"feature udld","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"^\\s*udld disable","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"c377550d3fe0f1c8","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"feature udld"}},
#|{"id":"R-01DE66","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220690","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"re:^\\s*shutdown\\s*$","exclude":"no switchport","if_none":"pass","check":"has","text":"^\\s*switchport access vlan \\d+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nEDIT to your parking VLAN, e.g. 'switchport access vlan 999' (whole line).","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"5aca1247c13a0eee","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"{each failing section}\n switchport access vlan <PARKING_VLAN>","high":""}},
#|{"id":"R-5AF028","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220691","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"^interface Ethernet\\d","section_how":"regex","only":"role:access","exclude":"re:^\\s*shutdown\\s*$","if_none":"fail","check":"has","text":"^\\s*switchport access vlan ([2-9]|\\d{2,})\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. Every access port names a VLAN other than 1 (NX-OS 'show vlan' also lists trunks, so the config is read instead).","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"31a90eeb4a7d89b8","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:59:05","fix":{"low":"","high":"{each failing section}\n switchport access vlan <USER_VLAN>"}},
#|{"id":"R-48C1A9","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220692","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"switchport mode trunk","exclude":"shutdown","if_none":"pass","check":"has","text":"switchport trunk allowed vlan","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"switchport mode trunk","exclude":"shutdown","if_none":"pass","check":"lacks","text":"switchport trunk allowed vlan (add )?(.*,)?1(-\\d+)?(,.*)?\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"43ff2bab98bc79de","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n switchport trunk allowed vlan remove 1"}},
#|{"id":"R-569BBF","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220693","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface Vlan1","section_how":"whole line","only":"","exclude":"","if_none":"pass","check":"lacks","text":"^\\s*ip address \\d","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"b491e47958614604","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! move management to a dedicated VLAN first, then:\ninterface Vlan1\n  no ip address\n  shutdown"}},
#|{"id":"R-49700C","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220694","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"^interface Ethernet\\d","section_how":"regex","only":"role:access","exclude":"re:^\\s*shutdown\\s*$","if_none":"fail","check":"lacks","text":"switchport mode trunk","how":"whole line","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"^interface Ethernet\\d","section_how":"regex","only":"re:^\\s*no shutdown\\s*$","exclude":"re:^\\s*(no switchport|channel-group)\\b","if_none":"pass","check":"has","text":"role:any","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nUses PORT ROLES from interface descriptions (keywords are a team setting on tab 3): uplinks 'description UPLINK - ...', downlinks 'description DOWNLINK - ...', client ports 'description ACCESS - ...' or 'UNTRUSTED - ...'. Condition 1: no access-role port is a trunk. Condition 2: every live Ethernet port carries a role label.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"857cbfa19a0f8f56","created_at":"2026-10-03T20:59:05","origin":"starter-drafts","fix":{"low":"{each failing section of condition 2}\n  ! label this port: description UPLINK - ... / DOWNLINK - ... / ACCESS - ...","high":"{each failing section of condition 1}\n  switchport mode access"},"saved_at":"2026-10-03T20:59:05"},
#|{"id":"R-401397","stig_id":"Cisco_NX-OS_Switch_L2S_STIG","vuln_id":"V-220695","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"switchport mode trunk","exclude":"shutdown","if_none":"pass","check":"has","text":"^\\s*switchport trunk native vlan ([2-9]|\\d{2,})\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"9fc633bbcc8a8e82","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n switchport trunk native vlan <NATIVE_VLAN>"}},
#|{"id":"R-B7062F","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220474","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"line vty","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"session-limit","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"006103bedb4dbbf3","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"line vty\n  session-limit 2"}},
#|{"id":"R-F51C6A","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220475","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^aaa accounting default group \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nAlso confirm the referenced group has reachable AAA servers.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"e7a1766b9ea4731b","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa accounting default group <AAA_GROUP>","high":""}},
#|{"id":"R-F49F61","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220476","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^aaa accounting default group \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nAlso confirm the referenced group has reachable AAA servers.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"c812715805b6a631","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa accounting default group <AAA_GROUP>","high":""}},
#|{"id":"R-00F71D","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220477","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^aaa accounting default group \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nAlso confirm the referenced group has reachable AAA servers.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"1db604b898b72894","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa accounting default group <AAA_GROUP>","high":""}},
#|{"id":"R-9F7BF3","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220478","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^aaa accounting default group \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nAlso confirm the referenced group has reachable AAA servers.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"dbfe48bb67ef3763","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa accounting default group <AAA_GROUP>","high":""}},
#|{"id":"R-FF4A5E","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220479","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ANY","conditions":[{"command":"show running-config","scope":"any","section":"line vty","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s*access-class \\S+ in","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"interface mgmt0","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s*ip access-group \\S+ in","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nAlso confirm the ACL only permits the management network.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"e6051e06cee23f96","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip access-list MGMT_NET\n  10 permit ip <MGMT_SUBNET_CIDR> any\n  20 deny ip any any log\ninterface mgmt0\n  ip access-group MGMT_NET in\nline vty\n  access-class MGMT_NET in"}},
#|{"id":"R-562CB9","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220480","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^ssh login-attempts ([4-9]|\\d{2,})\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nDefault is 3 attempts (not shown in the config).","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"4878ec157514d1ba","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ssh login-attempts 3"}},
#|{"id":"R-7788B2","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220481","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"banner motd","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"You are accessing a U.S. Government (USG) Information System","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"b9e5946c599846ed","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"banner motd ^\nYou are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n-At any time, the USG may inspect and seize data stored on this IS.\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.\n^","high":""}},
#|{"id":"R-017A21","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220482","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^aaa accounting default group \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nAlso confirm the referenced group has reachable AAA servers.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"0a5baff34cdf1060","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa accounting default group <AAA_GROUP>","high":""}},
#|{"id":"R-DD25C3","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220484","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"ip access-list","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"^\\s*(\\d+\\s+)?deny\\b(?!.*\\blog(-input)?\\b)","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging ip access-list cache entries","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"0a24671fb003a8d1","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"logging ip access-list cache entries 8000","high":"{each failing section}\n ! add 'log' to every deny statement in this ACL"}},
#|{"id":"R-2008F2","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220485","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^aaa accounting default group \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nAlso confirm the referenced group has reachable AAA servers.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"2f4ce4cb775e8df7","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa accounting default group <AAA_GROUP>","high":""}},
#|{"id":"R-D6F47C","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220486","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature telnet","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nAlso review: feature wccp, nxapi, imp, dhcp - allowed only when operationally required (feature dhcp is needed for DHCP snooping).","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"8b2ad815234ad6fa","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"no feature telnet"}},
#|{"id":"R-3CFF60","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220487","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"count","text":"username ","how":"starts with","ignore_case":false,"op":"==","value":"1"},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"no aaa authentication login default fallback error local","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"91401d8571f24e40","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! remove every local account except the account of last resort:\n! no username <EXTRA_ACCOUNT>\n! and remove any 'no aaa authentication login default fallback error local'"}},
#|{"id":"R-A7EFD3","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220488","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ssh macs .*hmac-sha2","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^ssh macs .*hmac-sha1\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\n'ssh macs' is available on NX-OS 10.x; on 9.3 confirm with 'show ssh server'.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"d970dda32b65e0f6","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ssh macs hmac-sha2-256 hmac-sha2-512"}},
#|{"id":"R-8C379E","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220489","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"no password strength-check","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"52e85e06ed299052","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"password strength-check","high":""}},
#|{"id":"R-B973B9","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220490","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"no password strength-check","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"d357e363010d0207","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"password strength-check","high":""}},
#|{"id":"R-1F1BE9","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220491","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"no password strength-check","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"26c6d92104f7bc8e","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"password strength-check","high":""}},
#|{"id":"R-B12030","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220492","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"no password strength-check","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"eacaf21f14ca1208","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"password strength-check","high":""}},
#|{"id":"R-8D48A7","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220493","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"line console","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"exec-timeout","how":"starts with","ignore_case":false,"op":"<=","value":"5"},{"command":"show running-config","scope":"any","section":"line vty","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"exec-timeout","how":"starts with","ignore_case":false,"op":"<=","value":"5"},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*exec-timeout 0\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"865205250424a7c5","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"line console\n  exec-timeout 5\nline vty\n  exec-timeout 5","high":""}},
#|{"id":"R-4171C9","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220494","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^aaa accounting default group \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nAlso confirm the referenced group has reachable AAA servers.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"b9cc9e484e176fa4","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa accounting default group <AAA_GROUP>","high":""}},
#|{"id":"R-579DA1","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220495","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^aaa accounting default group \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nAlso confirm the referenced group has reachable AAA servers.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"a20ad1d384a24c79","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa accounting default group <AAA_GROUP>","high":""}},
#|{"id":"R-A9AFA3","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220496","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^logging logfile \\S+ \\d+ size \\d+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"2fd857c2a1172690","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"logging logfile messages 6 size 4194304","high":""}},
#|{"id":"R-BD763A","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220497","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging server","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^logging server \\S+ [01](\\s|$)","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"2d593a1504e2ca38","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"logging server <SYSLOG_SERVER_1> 6 use-vrf management","high":""}},
#|{"id":"R-CD913B","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220498","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"count","text":"ntp server","how":"starts with","ignore_case":false,"op":">=","value":"2"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"8d915162fdd190d3","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"ntp server <NTP_SERVER_1> use-vrf management\nntp server <NTP_SERVER_2> use-vrf management","high":""}},
#|{"id":"R-1D43CE","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220500","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^snmp-server user \\S+ .*\\bauth (sha|sha-\\d+)\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^snmp-server user \\S+ .*\\bauth md5\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"snmp-server community","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^snmp-server (group|user|host|community)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nNexus ships with an 'admin' SNMP user using auth md5 - remove or change it.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"8079bf4ba1e5686d","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"snmp-server user <SNMP_USER> network-operator auth sha <AUTH_PASSWORD> priv aes-128 <PRIV_PASSWORD>\n! remove or re-key the default 'admin' SNMP user (auth md5)\nno snmp-server community <OLD_COMMUNITY>"}},
#|{"id":"R-A03B03","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220501","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^snmp-server user \\S+ .*\\bpriv (aes-128|aes)\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^snmp-server user \\S+ (?!.*\\bpriv\\b)","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^snmp-server (group|user|host|community)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"1683ab1120c28898","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"snmp-server user <SNMP_USER> network-operator auth sha <AUTH_PASSWORD> priv aes-128 <PRIV_PASSWORD>"}},
#|{"id":"R-A953CB","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220503","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ssh macs .*hmac-sha2","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^ssh macs .*hmac-sha1\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\n'ssh macs' is available on NX-OS 10.x; on 9.3 confirm with 'show ssh server'.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"d970dda32b65e0f6","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ssh macs hmac-sha2-256 hmac-sha2-512"}},
#|{"id":"R-730814","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220504","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ssh ciphers ","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^ssh ciphers .*(cbc|3des)","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\n'ssh ciphers' is available on NX-OS 10.x; on 9.3 confirm with 'show ssh server'.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"641a5cb5a8650499","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ssh ciphers aes256-ctr aes128-ctr"}},
#|{"id":"R-5160CE","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220506","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^aaa accounting default group \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nAlso confirm the referenced group has reachable AAA servers.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"714fcc0d87cd4563","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa accounting default group <AAA_GROUP>","high":""}},
#|{"id":"R-28F093","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220507","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^aaa accounting default group \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nAlso confirm the referenced group has reachable AAA servers.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"4f6d22d6891d6f80","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa accounting default group <AAA_GROUP>","high":""}},
#|{"id":"R-50FDEE","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220508","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"logging level authpri","how":"starts with","ignore_case":false,"op":">=","value":"6"},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging logfile","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"0bbfe879e16e1ba9","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"logging level authpri 6\nlogging logfile messages 6","high":""}},
#|{"id":"R-431970","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220509","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^aaa accounting default group \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nAlso confirm the referenced group has reachable AAA servers.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"165fcf1cb961dcc8","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"aaa accounting default group <AAA_GROUP>","high":""}},
#|{"id":"R-57A6D2","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220510","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"number","text":"logging level authpri","how":"starts with","ignore_case":false,"op":">=","value":"6"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"c08afb071afae331","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"logging level authpri 6","high":""}},
#|{"id":"R-AD5BFD","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220512","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"logging server","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"9c6adc015ca46e49","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"logging server <SYSLOG_SERVER_1> 6 use-vrf management","high":""}},
#|{"id":"R-7042C3","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220513","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"count","text":"^(radius|tacacs)-server host ","how":"regex","ignore_case":false,"op":">=","value":"2"},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^aaa authentication login (default|console) group ","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"091d07cc00438b05","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"tacacs-server host <AAA_IP_1> key <AAA_KEY>\ntacacs-server host <AAA_IP_2> key <AAA_KEY>\naaa group server tacacs+ <AAA_GROUP>\n    server <AAA_IP_1>\n    server <AAA_IP_2>\n    use-vrf management\naaa authentication login default group <AAA_GROUP>\naaa authentication login console group <AAA_GROUP>"}},
#|{"id":"R-4BA9E2","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220514","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"event manager applet","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"CONFIG_I","how":"contains","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"event manager applet","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"copy (running|startup)-config (scp|sftp)://","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"d52e601e493b77c2","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"event manager applet BACKUP_CONFIG\n  event syslog pattern \"VSHD_SYSLOG_CONFIG_I\"\n  action 1 cli copy running-config scp://<SCP_USER>@<SCP_SERVER>/<SCP_PATH>/nx-config vrf management","high":""}},
#|{"id":"R-05AC1A","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220515","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"crypto ca trustpoint","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"enrollment","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"crypto ca trustpoint","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nReviewer must confirm the CA is DoD / DoD-approved ('show crypto ca certificates').","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"2c6e18d672a61150","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! enroll with a DoD / DoD-approved CA (NX-OS uses cut-and-paste enrollment):\ncrypto ca trustpoint <DOD_CA_TRUSTPOINT>\n  enrollment terminal"}},
#|{"id":"R-3104B7","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220516","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"count","text":"logging server","how":"starts with","ignore_case":false,"op":">=","value":"2"}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"bc20313534c61b88","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"logging server <SYSLOG_SERVER_1> 6 use-vrf management\nlogging server <SYSLOG_SERVER_2> 6 use-vrf management","high":""}},
#|{"id":"R-EB9AE0","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-220517","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show version"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show version","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"NXOS: version (9\\.3\\(1[0-9]\\)|10\\.[2-5]\\()","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nEDIT the version list to the Cisco-supported / site-approved releases before use.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"774622f0bc18d910","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! upgrade the switch to a Cisco-supported NX-OS release (not a config change)"}},
#|{"id":"R-F6C1B1","stig_id":"Cisco_NX-OS_Switch_NDM_STIG","vuln_id":"V-260464","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^policy-map type control-plane ","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"control-plane","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s*service-policy input \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nNexus 9000 applies a default CoPP profile (copp-system-p-policy-*); review the rates.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"6cc13105ecbbe48c","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"copp profile strict"}},
#|{"id":"R-8E6C60","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221072","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"ip router ospf","exclude":"","if_none":"pass","check":"has","text":"^\\s*ip ospf authentication","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"ip router eigrp","exclude":"","if_none":"pass","check":"has","text":"^\\s*ip authentication (mode|key-chain) eigrp","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"ip router isis","exclude":"","if_none":"pass","check":"has","text":"^\\s*isis authentication","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"^\\s+neighbor \\S+","section_how":"regex","only":"","exclude":"re:^\\s*inherit peer","if_none":"pass","check":"has","text":"^\\s*password \\d","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^feature (ospf|ospfv3|bgp|eigrp|isis|rip)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nBGP: every neighbor needs 'password'; templates ('inherit peer') need checking by hand.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"d9abe986adca9bbd","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! configure authentication for every routing protocol, e.g. OSPF:\ninterface <ROUTING_INTERFACE>\n  ip ospf authentication key-chain <KEY_CHAIN>\n! BGP: router bgp <ASN> / neighbor <PEER> / password 3 <KEY>"}},
#|{"id":"R-2A3B45","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221073","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"^\\s+key \\d+","section_how":"regex","only":"","exclude":"","if_none":"pass","check":"has","text":"accept-lifetime","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"^\\s+key \\d+","section_how":"regex","only":"","exclude":"","if_none":"pass","check":"has","text":"send-lifetime","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^feature (ospf|ospfv3|bgp|eigrp|isis|rip)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nReviewer must confirm each key's lifetime is 180 days or less.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"e6d4c57148afabe6","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! set accept-lifetime / send-lifetime of 180 days or less on every key in the key chains"}},
#|{"id":"R-1A8FE2","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221074","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"ip router ospf","exclude":"","if_none":"pass","check":"has","text":"^\\s*ip ospf (message-digest-key|authentication key-chain|authentication message-digest)","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^feature (ospf|ospfv3|bgp|eigrp|isis|rip)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nCheck BGP / EIGRP / IS-IS authentication types as well.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"d9182a3faada0dff","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"interface <ROUTING_INTERFACE>\n  ip ospf authentication message-digest\n  ip ospf message-digest-key 1 md5 3 <KEY>"}},
#|{"id":"R-730532","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221075","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"key chain","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"cryptographic-algorithm hmac-sha","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature ospf","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nOnly OSPF supports FIPS 198-1 HMAC on NX-OS; BGP/RIP/EIGRP/IS-IS are a finding.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"4a907631c0e6fc1d","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"key chain <KEY_CHAIN>\n  key 1\n    key-string <ROUTING_KEY>\n    cryptographic-algorithm hmac-sha-256\ninterface <ROUTING_INTERFACE>\n  ip ospf authentication key-chain <KEY_CHAIN>"}},
#|{"id":"R-9C7FA5","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221076","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show ip interface brief vrf all"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show ip interface brief vrf all","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"link-down/admin-up","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nFlags routed interfaces that are admin-up but link-down.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"222a8d1342bbddcc","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! shut down routed interfaces that are not in use:\ninterface <UNUSED_INTERFACE>\n  shutdown"}},
#|{"id":"R-7E2E83","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221078","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"callhome","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"enable","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"a649a4e0d9b9b3bf","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! disable Smart Call Home: callhome / no enable (confirm syntax for the release)"}},
#|{"id":"R-FDC4F8","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221079","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^policy-map type control-plane ","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"any","section":"control-plane","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s*service-policy input \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nNexus 9000 applies a default CoPP profile (copp-system-p-policy-*); review the rates.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"6cc13105ecbbe48c","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"copp profile strict"}},
#|{"id":"R-AE0CCC","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221081","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"ip access-list","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"deny icmp .*\\bfragments\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nMust be on external and internal ACLs, before any ICMP permit.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"783950500ec3db75","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! in the external and internal ACLs, before any ICMP permit:\nip access-list <ACL>\n  <SEQ> deny icmp any <DEVICE_ADDRESS>/32 fragments log"}},
#|{"id":"R-47BFE4","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221082","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"ip address","exclude":"re:^\\s*(shutdown|vrf member management)\\s*$","if_none":"pass","check":"has","text":"no ip arp gratuitous","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nApplies to EXTERNAL interfaces only - narrow as needed.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"22d919ecc4abe517","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n no ip arp gratuitous request"}},
#|{"id":"R-17A9CC","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221083","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"ip directed-broadcast","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"9682da5ac087f4b6","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"{each failing section}\n no ip directed-broadcast","high":""}},
#|{"id":"R-3DF304","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221084","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"ip unreachables","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"50a92bb673857bed","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"{each failing section}\n no ip unreachables","high":""}},
#|{"id":"R-538F01","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221085","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"ip address","exclude":"re:^\\s*(shutdown|vrf member management)\\s*$","if_none":"pass","check":"has","text":"no ip redirects","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nApplies to EXTERNAL interfaces only - narrow as needed.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"ac648ccf89a863ae","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"{each failing section}\n no ip redirects","high":""}},
#|{"id":"R-EAD40A","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221086","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"ip access-list","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"^\\s*(\\d+\\s+)?deny\\b(?!.*\\blog(-input)?\\b)","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"405876a6afb5dde3","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ! add 'log' to every deny statement in this ACL"}},
#|{"id":"R-B90926","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221095","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"no ip source-route","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"c827ee746ecb1bee","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"no ip source-route","high":""}},
#|{"id":"R-12F029","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221096","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature lldp","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nIf LLDP is needed internally, change to: every EXTERNAL interface has 'no lldp transmit'.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"eec379c5b32346ee","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"no feature lldp"}},
#|{"id":"R-836AA6","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221097","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^no cdp enable\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nCDP is on by default. If needed internally, change to: every EXTERNAL interface has 'no cdp enable'.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"603fa617b9aaee95","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"no cdp enable"}},
#|{"id":"R-D5E1BB","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221098","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"ip proxy-arp","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"c89a5ab7731b25a0","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n no ip proxy-arp"}},
#|{"id":"R-0E2592","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221101","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"disable-connected-check","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"8fd7bc3b8304382a","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n  neighbor <EBGP_PEER>\n    no disable-connected-check"}},
#|{"id":"R-7B89DD","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221103","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip prefix-list \\S+ seq \\d+ deny 10\\.0\\.0\\.0/8","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s+(prefix-list|route-map) \\S+ in\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nConfirm the full Bogon list and that it is applied to ALL external peers.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"3523eb4bdb640ddd","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! build the Bogon prefix list (see check text), then for every eBGP peer:\nrouter bgp <ASN>\n  neighbor <EBGP_PEER>\n    address-family ipv4 unicast\n      prefix-list <BOGON_PREFIX_LIST> in"}},
#|{"id":"R-2BFA7F","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221104","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s+(prefix-list|route-map) \\S+ in\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nReviewer must confirm the inbound filter denies the local AS prefixes.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"8d914566a8e26a7e","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip prefix-list <INBOUND_FILTER> seq <SEQ> deny <LOCAL_AS_PREFIX> le 32\nrouter bgp <ASN>\n  neighbor <EBGP_PEER>\n    address-family ipv4 unicast\n      prefix-list <INBOUND_FILTER> in"}},
#|{"id":"R-A571CC","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221105","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s+prefix-list \\S+ in\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"7adda9c4041b5b73","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n  neighbor <CE_PEER>\n    address-family ipv4 unicast\n      prefix-list <CUSTOMER_PREFIX_LIST> in"}},
#|{"id":"R-51ACE0","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221106","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s+prefix-list \\S+ out\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"c52087e07f638684","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n  neighbor <CE_PEER>\n    address-family ipv4 unicast\n      prefix-list <ADVERTISE_PREFIX_LIST> out"}},
#|{"id":"R-4A56C0","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221107","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s+prefix-list \\S+ out\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"2d4fb71325a4aebc","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n  neighbor <EBGP_PEER>\n    address-family ipv4 unicast\n      prefix-list <FILTER_CORE_PREFIXES> out"}},
#|{"id":"R-20C90D","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221108","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"no enforce-first-as","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"cd169d8935f5df08","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n  enforce-first-as"}},
#|{"id":"R-7BB30D","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221109","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip as-path access-list","how":"starts with","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s+filter-list \\S+ in\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"a128fae5e7b67a40","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip as-path access-list <AS_PATH_ACL> permit ^<CUSTOMER_AS>$\nrouter bgp <ASN>\n  neighbor <CE_PEER>\n    address-family ipv4 unicast\n      filter-list <AS_PATH_ACL> in"}},
#|{"id":"R-1E7019","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221110","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s+maximum-prefix \\d+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"7bbd7c0caf64ac2b","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n  neighbor <EBGP_PEER>\n    address-family ipv4 unicast\n      maximum-prefix <MAX_PREFIXES>"}},
#|{"id":"R-D599F9","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221111","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip prefix-list \\S+ .*le 24\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s+prefix-list \\S+ in\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"bc92266553236f53","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip prefix-list FILTER_PREFIX_LENGTH seq 5 permit 0.0.0.0/0 ge 8 le 24\nip prefix-list FILTER_PREFIX_LENGTH seq 10 deny 0.0.0.0/0 le 32\nrouter bgp <ASN>\n  neighbor <EBGP_PEER>\n    address-family ipv4 unicast\n      prefix-list FILTER_PREFIX_LENGTH in"}},
#|{"id":"R-EB45DC","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221112","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s+update-source [Ll]oopback","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature bgp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"6777a1ce9fb8461f","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router bgp <ASN>\n  neighbor <IBGP_PEER>\n    update-source loopback0"}},
#|{"id":"R-C3939E","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221113","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ANY","conditions":[{"command":"show running-config","scope":"every","section":"mpls ldp configuration","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"lacks","text":"^\\s+router-id ","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"every","section":"mpls ldp configuration","section_how":"starts with","only":"","exclude":"","if_none":"pass","check":"has","text":"^\\s+router-id [Ll]oopback","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^(feature mpls|install feature-set mpls|feature-set mpls)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"e03540bf8cbef192","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"mpls ldp configuration\n  router-id loopback0 force"}},
#|{"id":"R-F076FF","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221114","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"^router (ospf|isis)\\b","section_how":"regex","only":"","exclude":"","if_none":"fail","check":"has","text":"mpls ldp sync","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^(feature mpls|install feature-set mpls|feature-set mpls)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"554e8f53ce7e8e40","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"router ospf <OSPF_PROCESS>\n  mpls ldp sync"}},
#|{"id":"R-6B7F67","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221116","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"no mpls ip propagate-ttl","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^(feature mpls|install feature-set mpls|feature-set mpls)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"996fc1990859d92c","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"no mpls ip propagate-ttl"}},
#|{"id":"R-58087D","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221124","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"no ip igmp snooping","how":"contains","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^(feature mpls|install feature-set mpls|feature-set mpls)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"e135c1e8363189f3","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"ip igmp snooping","high":""}},
#|{"id":"R-63AE20","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221128","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"no ip source-route","how":"whole line","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^(feature mpls|install feature-set mpls|feature-set mpls)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"c827ee746ecb1bee","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"no ip source-route","high":""}},
#|{"id":"R-0CA99D","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221129","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s*service-policy type qos (output|input) \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^(feature mpls|install feature-set mpls|feature-set mpls)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nConfirm the classes / bandwidth match the GIG QoS technical profile.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"12fa75e3e064c3ab","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! build the QoS policy per the GIG QoS profile, then on each interface:\ninterface <INTERFACE>\n  service-policy type qos output <QOS_POLICY>"}},
#|{"id":"R-31C2EC","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221130","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s*service-policy type qos (output|input) \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^(feature mpls|install feature-set mpls|feature-set mpls)\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nConfirm the classes / bandwidth match the GIG QoS technical profile.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"12fa75e3e064c3ab","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! build the QoS policy per the GIG QoS profile, then on each interface:\ninterface <INTERFACE>\n  service-policy type qos output <QOS_POLICY>"}},
#|{"id":"R-8D07F9","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221131","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"match (ip )?dscp (cs1|8)\\b","how":"regex","ignore_case":false,"op":">=","value":""},{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^\\s*service-policy type qos (output|input) \\S+","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":false,"na_logic":{"mode":"ALL","conditions":[]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nScavenger (CS1) class with low priority in the QoS policy.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"1535e197a21b6453","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"class-map type qos match-all SCAVENGER\n  match dscp 8\n! add the SCAVENGER class with low bandwidth to <QOS_POLICY>"}},
#|{"id":"R-21B4D2","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221133","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"ip pim sparse-mode","exclude":"","if_none":"pass","check":"has","text":"ip pim neighbor-policy","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature pim","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"0ec1361ea6afc28d","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ip pim neighbor-policy prefix-list <PIM_NEIGHBOR_LIST>"}},
#|{"id":"R-9E5B43","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221134","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"any","section":"interface","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip pim border","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature pim","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nEdge multicast switches only.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"ee8bf825cc126fd9","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"interface <EDGE_INTERFACE>\n  ip pim border"}},
#|{"id":"R-3F3B20","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221135","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip pim register-policy","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature pim","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nRendezvous Point only; also verify MSDP peer filtering.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"34fb091f18e5ea9e","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip pim register-policy <PIM_REGISTER_FILTER>"}},
#|{"id":"R-B336E7","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221136","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip pim register-policy","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature pim","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nRendezvous Point only.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"285a6b7a43d0438c","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip pim register-policy <PIM_REGISTER_FILTER>"}},
#|{"id":"R-FCB3C1","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221137","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"ip pim sparse-mode","exclude":"","if_none":"pass","check":"has","text":"ip pim jp-policy","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature pim","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nRendezvous Point only.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"0e733107b0f8380d","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ip pim jp-policy <PIM_JOIN_FILTER> in"}},
#|{"id":"R-06BD84","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221138","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"ip pim sparse-mode","exclude":"","if_none":"pass","check":"has","text":"ip igmp report-policy","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature pim","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nSource Specific Multicast only.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"fdb0cef7d54c1fc9","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ip igmp report-policy <ALLOWED_GROUPS>"}},
#|{"id":"R-EA8C84","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221139","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"ip pim sparse-mode","exclude":"","if_none":"pass","check":"has","text":"ip igmp report-policy","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature pim","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.\n\nSource Specific Multicast only.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"73a8a4658243dc5e","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ip igmp report-policy <ALLOWED_SOURCES>"}},
#|{"id":"R-C86117","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221140","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"every","section":"interface","section_how":"starts with","only":"ip pim sparse-mode","exclude":"","if_none":"pass","check":"has","text":"ip igmp state-limit","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature pim","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"1e2aa5e8f7ee7d1e","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"{each failing section}\n ip igmp state-limit <IGMP_LIMIT>"}},
#|{"id":"R-FA1CA5","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221141","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip pim spt-threshold infinity","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature pim","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"37208088c0854637","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip pim spt-threshold infinity group-list <SPT_GROUPS>"}},
#|{"id":"R-020280","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221143","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip msdp password ","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature msdp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"896dc60053d74368","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip msdp password <MSDP_PEER> <MSDP_KEY>"}},
#|{"id":"R-0116D6","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221144","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip msdp sa-policy \\S+ .*\\bin\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature msdp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"331ec086426f663c","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip msdp sa-policy <MSDP_PEER> <INBOUND_SA_FILTER> in"}},
#|{"id":"R-EB9607","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221145","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip msdp sa-policy \\S+ .*\\bout\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature msdp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"e3112c980873f533","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip msdp sa-policy <MSDP_PEER> <OUTBOUND_SA_FILTER> out"}},
#|{"id":"R-859CF6","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221146","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"ip msdp sa-limit","how":"starts with","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature msdp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"fb2b53616c5eeaaf","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip msdp sa-limit <MSDP_PEER> <SA_LIMIT>"}},
#|{"id":"R-959491","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-221147","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"has","text":"^ip msdp peer \\S+ connect-source [Ll]oopback","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"feature msdp","how":"starts with","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"d7ecf08c3c07bb0d","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"ip msdp peer <MSDP_PEER> connect-source loopback0 remote-as <ASN>"}},
#|{"id":"R-3336A2","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-237754","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*ipv6 nd hop-limit ([0-9]|[12][0-9]|3[01])\\s*$","how":"regex","ignore_case":false,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*ipv6 address\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"e2664001b0d87039","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"! on every IPv6 interface:\ninterface <IPV6_INTERFACE>\n  ipv6 nd hop-limit 64","high":""}},
#|{"id":"R-33EB69","stig_id":"Cisco_NX-OS_Switch_RTR_STIG","vuln_id":"V-237757","name":"Starter draft","state":"draft","is_default":true,"version":1,"commands":["show running-config"],"pass_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"ipv6 address fec","how":"contains","ignore_case":true,"op":">=","value":""}]},"na_enabled":true,"na_logic":{"mode":"ALL","conditions":[{"command":"show running-config","scope":"all","section":"","section_how":"starts with","only":"","exclude":"","if_none":"fail","check":"lacks","text":"^\\s*ipv6 address\\b","how":"regex","ignore_case":false,"op":">=","value":""}]},"comment":"","notes":"STARTER DRAFT generated from the STIG check text for Nexus 9300-series (NX-OS 9.3/10.x). Review it against the check text, save at least one passing and one failing test sample from a real device, then activate.","tests":[],"outcome_text":{},"expected_open":false,"check_hash":"228c5126dd919a92","created_at":"2026-10-03T20:15:58","origin":"starter-drafts","saved_at":"2026-10-03T20:23:46","fix":{"low":"","high":"! replace any FEC0::/10 (site-local) IPv6 addresses"}}
#|]}
#@ END
