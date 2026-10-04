"""Groups, rule selection, assessment runs, and output packages.

Group record (data/groups.json):
  {"id": "CAMPUS-ACCESS", "description": "...", "patterns": ["*-ACCESS"],
   "stigs": ["Cisco_IOS_XE_Switch_NDM_STIG", ...],
   "rule_choices": {"<stig_id>|<vuln_id>": "<rule id>" | "manual"}}

Group result for a control (worst device wins):
  any device Not Reviewed (missing / bad evidence) -> Not Reviewed
  else any device Open                             -> Open
  else every device Not Applicable                 -> Not Applicable
  else                                             -> Not a Finding
Controls with no rule are "manual": the template's values are left untouched unless a
reviewer sets a status.
"""
import fnmatch
import re
import shutil
from collections import Counter, defaultdict
from pathlib import Path

import checklist
import collect
import rules as engine
import store
from checklist import STATUS_LABELS

TOOL = "STIGTOOL"


def key_of(stig_id, vuln_id):
    return f"{stig_id}|{vuln_id}"


def label(status):
    return STATUS_LABELS.get(status, "Manual (unchanged)" if status is None else str(status))


def is_expected_open(c, which="final"):
    """Open on purpose: the rule says this finding is intentional (e.g. risk acceptance recommended)."""
    return c.get(which) == "open" and bool(c.get("expected_open"))


def result_label(c, which="final"):
    """Like label(), but shows intentional findings as 'Open (expected)'."""
    return "Open (expected)" if is_expected_open(c, which) else label(c.get(which))


def outcome_prefix(c):
    """The rule author's Finding Details text for this control's final result, placeholders filled in."""
    status = c.get("final")
    devices = [h for h, r in c.get("per_device", {}).items() if r["status"] == status]
    return engine.outcome_text({"outcome_text": c.get("outcome_text")}, status, devices)


# ---------------------------------------------------------------- rules and groups

def rules_for_control(rules_db, stig_id, vuln_id, include_retired=False):
    return [r for r in rules_db["rules"]
            if r["stig_id"] == stig_id and r["vuln_id"] == vuln_id
            and (include_retired or r.get("state") != "retired")]


def resolve_rule(group, rules_db, stig_id, vuln_id):
    """The active rule this group uses for a control, or None (manual)."""
    choice = (group.get("rule_choices") or {}).get(key_of(stig_id, vuln_id))
    if choice == "manual":
        return None
    active = [r for r in rules_for_control(rules_db, stig_id, vuln_id) if r.get("state") == "active"]
    for r in active:
        if r["id"] == choice:
            return r
    for r in active:
        if r.get("is_default"):
            return r
    return active[0] if active else None


def control_state(rules_db, stig_id, control):
    """Work queue state for a control."""
    key = key_of(stig_id, control["vuln_id"])
    if key in rules_db.get("manual_controls", []):
        return "Manual only"
    rs = rules_for_control(rules_db, stig_id, control["vuln_id"])
    if not rs:
        return "Needs rule"
    active = [r for r in rs if r.get("state") == "active"]
    if any(r.get("check_hash") != control["check_hash"] for r in active):
        return "STIG changed - review"
    return "Active" if active else "Draft"


def group_plan(group, rules_db, index):
    """[(stig_id, control, rule_or_None)] for every control in the group's STIGs."""
    plan = []
    for stig_id in group.get("stigs", []):
        stig = index.get(stig_id)
        if not stig:
            continue
        for vuln_id in stig["order"]:
            control = stig["controls"][vuln_id]
            plan.append((stig_id, control, resolve_rule(group, rules_db, stig_id, vuln_id)))
    return plan


def coverage(group, rules_db, index):
    """Per STIG in the group: how many controls are automated, manual-only, or not built yet."""
    manual = set(rules_db.get("manual_controls", []))
    choices = group.get("rule_choices") or {}
    rows = []
    for stig_id in group.get("stigs", []):
        stig = index.get(stig_id)
        if not stig:
            continue
        row = {"stig_id": stig_id, "short": stig["short"], "release": stig["release"], "total": 0,
               "automated": 0, "manual": 0, "no_rule": 0, "draft": 0, "changed": 0}
        for vuln_id in stig["order"]:
            control = stig["controls"][vuln_id]
            key = key_of(stig_id, vuln_id)
            rule = resolve_rule(group, rules_db, stig_id, vuln_id)
            row["total"] += 1
            if rule:
                row["automated"] += 1
                if rule.get("check_hash") != control["check_hash"]:
                    row["changed"] += 1
            elif key in manual or choices.get(key) == "manual":
                row["manual"] += 1
            elif rules_for_control(rules_db, stig_id, vuln_id):
                row["draft"] += 1
            else:
                row["no_rule"] += 1
        rows.append(row)
    return rows


def commands_for_groups(groups, rules_db, index):
    """{command: set('NDM V-220524', ...)} for every active rule the groups use."""
    sources = defaultdict(set)
    for g in groups:
        for stig_id, control, rule in group_plan(g, rules_db, index):
            if rule:
                for cmd in rule["commands"]:
                    if cmd.strip():
                        sources[cmd.strip()].add(f"{index[stig_id]['short']} {control['vuln_id']}")
    return dict(sources)


def assign_group(host, groups_db):
    """(group_id or "", how) - explicit override first, then hostname pattern."""
    override = groups_db.get("device_overrides", {}).get(host.upper())
    if override:
        return override, "override"
    for g in groups_db.get("groups", []):
        for pat in g.get("patterns", []):
            if pat.strip() and fnmatch.fnmatch(host.upper(), pat.strip().upper()):
                return g["id"], f"pattern {pat.strip()}"
    return "", "unassigned"


def find_group(groups_db, group_id):
    return next((g for g in groups_db.get("groups", []) if g["id"] == group_id), None)


# ---------------------------------------------------------------- runs

def new_run(parsed, source_file, groups_db):
    run_id = store.stamp()
    membership = {}
    for d in parsed["devices"]:
        gid, how = assign_group(d["host"], groups_db)
        membership[d["host"]] = {"group": gid, "how": how}
    return {
        "id": run_id,
        "created": store.now(),
        "created_by": store.current_user(),
        "source_file": str(source_file),
        "source_name": Path(source_file).name,
        "warnings": parsed["warnings"],
        "devices": parsed["devices"],
        "membership": membership,
        "results": {},
    }


def evaluate_run(run, groups_db, rules_db, index):
    """(Re)compute recommendations for every group in the run. Keeps reviewer decisions."""
    by_group = defaultdict(list)
    for d in run["devices"]:
        gid = run["membership"].get(d["host"], {}).get("group")
        if gid:
            by_group[gid].append(d)
    old = run.get("results", {})
    results = {}
    for gid, devices in sorted(by_group.items()):
        group = find_group(groups_db, gid)
        if not group:
            continue
        controls = {}
        for stig_id, control, rule in group_plan(group, rules_db, index):
            k = key_of(stig_id, control["vuln_id"])
            rec = {
                "stig_id": stig_id, "family": index[stig_id]["short"],
                "vuln_id": control["vuln_id"], "rule_ver": control["rule_ver"],
                "title": control["title"], "severity": control["severity"],
                "template_status": control.get("template_status", "not_reviewed"),
                "rule_id": rule["id"] if rule else None,
                "rule_name": rule.get("name", "") if rule else "",
                "rule_version": rule.get("version", 1) if rule else None,
                "rule_comment": rule.get("comment", "") if rule else "",
                "outcome_text": dict(rule.get("outcome_text") or {}) if rule else {},
                "expected_open": bool(rule.get("expected_open")) if rule else False,
                "per_device": {}, "recommended": None, "details": "",
            }
            if rule:
                for d in devices:
                    if d["status"] != "ok":
                        res = {"status": "not_reviewed", "reasons": [f"Collection failed: {d['error']}"],
                               "evidence": []}
                    else:
                        res = engine.evaluate(rule, d["outputs"])
                    rec["per_device"][d["host"]] = {"status": res["status"], "reasons": res["reasons"],
                                                    "evidence": res["evidence"],
                                                    "failed_sections": res.get("failed_sections", []),
                                                    "failed_by_condition": res.get("failed_by_condition", {})}
                rec["recommended"] = rollup([v["status"] for v in rec["per_device"].values()])
                rec["details"] = finding_details(rec, run)
            prev = old.get(gid, {}).get("controls", {}).get(k, {})
            rec["reviewer_comment"] = prev.get("reviewer_comment", "")
            if prev.get("reviewer_changed"):
                rec.update(final=prev["final"], reviewer_changed=prev["final"] != rec["recommended"])
            else:
                rec.update(final=rec["recommended"], reviewer_changed=False)
            controls[k] = rec
        results[gid] = {"devices": [d["host"] for d in devices], "controls": controls}
        run.setdefault("coverage", {})[gid] = coverage(group, rules_db, index)
    run["results"] = results
    run["stig_names"] = {sid: s["short"] for sid, s in index.items()}
    run["stig_releases"] = {sid: s["release"] for sid, s in index.items()}
    run["evaluated"] = store.now()
    return run


def rollup(statuses):
    if not statuses:
        return "not_reviewed"
    if "not_reviewed" in statuses:
        return "not_reviewed"
    if "open" in statuses:
        return "open"
    if all(s == "not_applicable" for s in statuses):
        return "not_applicable"
    return "not_a_finding"


def finding_details(rec, run):
    by_status = defaultdict(list)
    for host, r in rec["per_device"].items():
        by_status[r["status"]].append(host)
    counts = ", ".join(f"{len(h)} {label(s)}" for s, h in sorted(by_status.items()))
    out = [
        f"{TOOL} automated assessment (run {run['id']}, evidence file {run['source_name']})",
        f"Rule {rec['rule_id']} v{rec['rule_version']} \"{rec['rule_name']}\"",
        f"Devices assessed: {len(rec['per_device'])} - {counts}",
        f"Group result: {label(rec['recommended'])}",
    ]
    for status in ("open", "not_reviewed", "not_applicable", "not_a_finding"):
        hosts = by_status.get(status)
        if not hosts:
            continue
        out.append("")
        out.append(f"{label(status)} ({len(hosts)}): {', '.join(hosts)}")
        sample = rec["per_device"][hosts[0]]
        if status in ("open", "not_reviewed"):
            for h in hosts:
                bad = [r for r in rec["per_device"][h]["reasons"]
                       if r.strip().startswith(("FAIL", "ERROR", "No usable", "Collection", "Rule", "Could"))]
                for r in bad or rec["per_device"][h]["reasons"][:3]:
                    out.append(f"  {h}: {r.strip()}")
        if sample["evidence"]:
            out.append(f"  Evidence from {hosts[0]}:")
            out += [f"    {line}" for line in sample["evidence"]]
    return "\n".join(out)


# ---------------------------------------------------------------- output package

def unresolved_controls(results):
    """Controls that will still read Not Reviewed in the output checklist."""
    return [c for c in results["controls"].values()
            if c["final"] == "not_reviewed"
            or (c["final"] is None and c.get("template_status", "not_reviewed") == "not_reviewed")]


FIELD_LABELS = {"comments": "Comments", "finding_details": "Finding Details"}


def reason_text(c, stamp_line=""):
    """Why the control got its result: rule author's text, automated evidence, reviewer change, sign-off."""
    parts = [p for p in (outcome_prefix(c), c.get("details")) if p]
    if c.get("reviewer_changed"):
        parts.append(f"Reviewer changed result from {label(c['recommended'])} to {label(c['final'])}.")
    text = "\n\n".join(parts)
    return (text + "\n" if text else "") + stamp_line if stamp_line else text


def checklist_text(c, placement, stamp_line):
    """The status / finding details / comments to write for one control.

    The reason goes in the field the team's guidance names for that result (default: Not a Finding and
    Not Applicable -> Comments, Open -> Finding Details). The rule's extra comment and the reviewer's
    comment always go in Comments. A field with nothing to say is left as the template has it.
    """
    reason = reason_text(c, stamp_line)
    where = (placement or store.DEFAULT_PLACEMENT).get(c["final"], "comments")
    comments = [p for p in (reason if where == "comments" else "",
                            f"Reviewer: {c['reviewer_comment']}" if c.get("reviewer_comment") else "",
                            c.get("rule_comment")) if p]
    return {
        "status": c["final"],
        "finding_details": reason if where == "finding_details" else None,
        "comments": "\n\n".join(comments) if comments else None,
    }


def write_package(run, group_id, reviewer, groups_db, rules_db, fmt, placement=None):
    """Write one checklist per STIG (in the team's output format) plus reports for one group.

    placement: {result: "comments" | "finding_details"} - where the reason text goes (team setting).
    Returns (folder, ok, messages).
    """
    placement = placement or store.load_settings()["text_placement"]
    results = run["results"][group_id]
    group = find_group(groups_db, group_id) or {"stigs": []}
    unresolved = unresolved_controls(results)
    folder_name = f"{group_id}_{store.stamp()}" + ("_REVIEW_REQUIRED" if unresolved else "")
    folder, n = store.paths.output / folder_name, 1
    while folder.exists():  # two packages in the same second (e.g. two reviewers)
        n += 1
        folder = store.paths.output / f"{folder_name}_{n}"
    folder.mkdir(parents=True)
    messages, all_ok, written, validation, notes = [], True, [], [], []
    fmt_label = checklist.FORMAT_LABELS[fmt]

    # Group controls by the template file they live in (normally one file per STIG).
    targets = {}
    for stig_id in group.get("stigs", []):
        cat = store.templates_for(stig_id).get(fmt)
        short = (run.get("stig_names") or {}).get(stig_id, stig_id)
        if not cat:
            all_ok = False
            notes.append(f"NO {fmt_label} TEMPLATE imported for {short} - its checklist was not written. "
                         f"Import the {fmt_label} file on the Checklists tab.")
            continue
        targets.setdefault(cat["id"], (cat, []))[1].append(stig_id)

    stamp_line = f"Final determination by {reviewer} on {store.now()}"
    for cat, stig_ids in targets.values():
        in_template = {(s["stig_id"], c["vuln_id"]) for s in cat["stigs"] for c in s["controls"]}
        updates, skipped = {}, []
        for c in results["controls"].values():
            if c["stig_id"] not in stig_ids or c["final"] is None:
                continue
            if (c["stig_id"], c["vuln_id"]) not in in_template:
                skipped.append(c["vuln_id"])
                continue
            updates[(c["stig_id"], c["vuln_id"])] = checklist_text(c, placement, stamp_line)
        for s in cat["stigs"]:
            if s["stig_id"] in stig_ids:
                rel = checklist.release_label(s.get("version"), s.get("release_info"))
                newest = (run.get("stig_releases") or {}).get(s["stig_id"])
                if newest and newest != rel:
                    notes.append(f"{s['short']}: the {fmt_label} template is {rel} but rules were assessed "
                                 f"against {newest}. Import the {newest} {fmt_label} file.")
        if skipped:
            notes.append(f"{len(skipped)} control(s) are not in the {fmt_label} template and were left out: "
                         + ", ".join(skipped))
        names = "-".join(_safe(s["short"]) for s in cat["stigs"] if s["stig_id"] in stig_ids)
        dst = folder / f"{group_id}_{names}.{fmt}"
        src = store.template_path(cat)
        try:
            checklist.write_patched(src, dst, updates, title=dst.stem)
            ok, lines = checklist.validate(src, dst)
        except checklist.ChecklistError as e:
            ok, lines = False, [f"Output: {dst.name}", f"RESULT: FAILED - {e}"]
        validation += lines + [""]
        if not ok:
            all_ok = False
            if dst.exists():
                dst.replace(dst.with_name(dst.name + ".FAILED_VALIDATION"))
            messages.append(f"{dst.name} FAILED validation - see preservation_validation_report.txt")
        else:
            written.append(dst.name)

    evidence_dir = folder / "source_evidence"
    evidence_dir.mkdir()
    if Path(run["source_file"]).exists():
        shutil.copy2(run["source_file"], evidence_dir / run["source_name"])

    _write(folder / "preservation_validation_report.txt", validation or ["No checklists written."])
    _write(folder / "applicable_devices.txt", _devices_report(run, group_id))
    _write(folder / "group_assessment_summary.txt",
           _summary_report(run, group_id, reviewer, written, all_ok, unresolved, fmt_label, notes))
    _write(folder / "exceptions_and_review_required.txt", _exceptions_report(run, group_id))
    _write(folder / "device_drift_report.txt", _drift_report(run, group_id))
    _write(folder / "unused_command_report.txt", _command_report(run, group_id, group, rules_db))
    _write(folder / "assessment_register.txt", _register(run, group_id, reviewer))
    messages.insert(0, f"Package written to {folder}")
    messages += notes
    if unresolved:
        messages.append(f"{len(unresolved)} control(s) still Not Reviewed - package marked REVIEW_REQUIRED.")
    return folder, all_ok, messages


def _safe(name):
    return re.sub(r"[^A-Za-z0-9.-]+", "_", name).strip("_")


def _write(path, lines):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines).rstrip() + "\n")


def _header(run, group_id, title):
    return [f"{TOOL} - {title}", f"Group: {group_id}", f"Run: {run['id']}  Evidence: {run['source_name']}",
            "=" * 78, ""]


def _devices_report(run, group_id):
    out = _header(run, group_id, "Applicable devices")
    devices = {d["host"]: d for d in run["devices"]}
    for host in run["results"][group_id]["devices"]:
        d, m = devices[host], run["membership"][host]
        state = "collected" if d["status"] == "ok" else f"COLLECTION FAILED: {d['error']}"
        out.append(f"{host:<30} {d['ip']:<28} {m['how']:<22} {state}")
    return out


def coverage_table(rows):
    """Text table of how many controls each STIG has automated / manual / not built."""
    out = [f"{'STIG':<40}{'Release':<22}{'Controls':>9}{'Automated':>11}{'Manual':>8}{'No rule':>9}"
           f"{'Draft':>7}{'Review':>8}"]
    for r in rows:
        out.append(f"{r['short'][:39]:<40}{r['release'][:21]:<22}{r['total']:>9}{r['automated']:>11}"
                   f"{r['manual']:>8}{r['no_rule']:>9}{r['draft']:>7}{r['changed']:>8}")
    out.append("  Automated = an active rule is used for this group.  Manual = marked manual-only.")
    out.append("  No rule / Draft = still to be built.  Review = automated, but the STIG text changed since the "
               "rule was written.")
    return out


def _summary_report(run, group_id, reviewer, written, all_ok, unresolved, fmt_label, notes):
    res = run["results"][group_id]
    out = _header(run, group_id, "Group assessment summary")
    out.append(f"Reviewer: {reviewer}")
    out.append(f"Devices: {len(res['devices'])}")
    out.append(f"Checklist format: {fmt_label}")
    out.append(f"Checklists written: {', '.join(written) or 'none'}")
    out.append(f"Preservation validation: {'PASSED' if all_ok else 'FAILED / INCOMPLETE'}")
    if unresolved:
        out.append("")
        out.append(f"*** REVIEW PACKAGE - {len(unresolved)} control(s) are Not Reviewed. "
                   "Not a validated final turnover. ***")
    if notes:
        out.append("")
        out.append("Notes:")
        out += [f"  - {n}" for n in notes]
    out.append("")
    out.append("Rule coverage per STIG (at the time of assessment):")
    out += ["  " + line for line in coverage_table(run.get("coverage", {}).get(group_id, []))]
    out.append("")
    out.append("Final results per STIG:")
    by_stig = defaultdict(Counter)
    for c in res["controls"].values():
        by_stig[c["family"]][result_label(c)] += 1
    names = ["Not a Finding", "Open", "Open (expected)", "Not Applicable", "Not Reviewed", "Manual (unchanged)"]
    out.append(f"  {'STIG':<40}" + "".join(f"{n:>20}" for n in names))
    for stig, counts in sorted(by_stig.items()):
        out.append(f"  {stig[:39]:<40}" + "".join(f"{counts.get(n, 0):>20}" for n in names))
    return out


def _exceptions_report(run, group_id):
    out = _header(run, group_id, "Exceptions and review-required items")
    controls = list(run["results"][group_id]["controls"].values())
    expected = [c for c in controls if is_expected_open(c)]
    for c in controls:
        if c["final"] == "not_a_finding" and not c["reviewer_changed"]:
            continue
        if c["final"] is None or is_expected_open(c):
            continue
        out.append(f"{c['family']} {c['vuln_id']} ({c['rule_ver']}) - final {result_label(c)}, "
                   f"recommended {result_label(c, 'recommended')}")
        out.append(f"  {c['title']}")
        if c["reviewer_changed"]:
            out.append(f"  Reviewer comment: {c.get('reviewer_comment', '')}")
        for host, r in c["per_device"].items():
            if r["status"] != "not_a_finding":
                out.append(f"  {host}: {label(r['status'])}")
                for reason in r["reasons"]:
                    if reason.strip().startswith(("FAIL", "ERROR", "No usable", "Collection", "Rule", "Could",
                                                  "TRUE")):
                        out.append(f"      {reason.strip()}")
        out.append("")
    if expected:
        out.append(f"Expected (intentional) findings - Open on purpose, e.g. risk acceptance recommended: "
                   f"{len(expected)}")
        for c in expected:
            out.append(f"  {c['family']} {c['vuln_id']} ({c['rule_ver']}) {c['title'][:80]}")
            out.append(f"      {outcome_prefix(c).replace(chr(10), ' ')}")
        out.append("")
    manual = [c for c in run["results"][group_id]["controls"].values() if c["final"] is None]
    if manual:
        out.append(f"Manual controls (no rule; template values left unchanged): {len(manual)}")
        out += [f"  {c['family']} {c['vuln_id']} {c['title'][:90]}" for c in manual]
    return out


def _drift_report(run, group_id):
    out = _header(run, group_id, "Device drift (devices whose result differs from the group majority)")
    found = False
    for c in run["results"][group_id]["controls"].values():
        statuses = Counter(r["status"] for r in c["per_device"].values())
        if len(statuses) < 2:
            continue
        found = True
        majority = statuses.most_common(1)[0][0]
        odd = [f"{h} ({label(r['status'])})" for h, r in c["per_device"].items() if r["status"] != majority]
        out.append(f"{c['family']} {c['vuln_id']}: majority {label(majority)}; differs: {', '.join(odd)}")
    if not found:
        out.append("No drift: every device returned the same result for every automated control.")
    return out


def _command_report(run, group_id, group, rules_db):
    out = _header(run, group_id, "Command usage")
    used = set()
    for c in run["results"][group_id]["controls"].values():
        rule = next((r for r in rules_db["rules"] if r["id"] == c["rule_id"]), None)
        if rule:
            used |= {x.strip() for x in rule["commands"] if x.strip()}
    devices = {d["host"]: d for d in run["devices"]}
    collected = set()
    for host in run["results"][group_id]["devices"]:
        collected |= set(devices[host]["outputs"])
    out.append("Collected but not used by this group's rules:")
    out += [f"  {c}" for c in sorted(collected - used)] or ["  (none)"]
    out.append("")
    out.append("Needed by rules but missing, invalid or failed, per device:")
    any_missing = False
    for host in run["results"][group_id]["devices"]:
        d = devices[host]
        for cmd in sorted(used):
            ev = d["outputs"].get(cmd)
            if not ev or ev["status"] != "ok":
                any_missing = True
                out.append(f"  {host}: {cmd} ({ev['status'] if ev else d['status'] if d['status'] != 'ok' else 'missing'})")
    if not any_missing:
        out.append("  (none)")
    return out


def _register(run, group_id, reviewer):
    out = _header(run, group_id, "Assessment register")
    out.append(f"Reviewer: {reviewer}   Written: {store.now()}")
    out.append("")
    out.append(f"{'STIG':<34}{'Vuln':<11}{'Rule_Ver':<17}{'Rule':<14}{'Recommended':<17}{'Final':<17}Changed")
    for c in run["results"][group_id]["controls"].values():
        rule = f"{c['rule_id']} v{c['rule_version']}" if c["rule_id"] else "manual"
        out.append(f"{c['family'][:33]:<34}{c['vuln_id']:<11}{c['rule_ver']:<17}{rule:<14}"
                   f"{result_label(c, 'recommended'):<17}{result_label(c):<17}{'yes' if c['reviewer_changed'] else ''}")
        if c["reviewer_changed"] and c.get("reviewer_comment"):
            out.append(f"{'':<34}rationale: {c['reviewer_comment']}")
    return out


def import_solarwinds(path, groups_db, rules_db):
    """Parse a SolarWinds output file into a new run (not yet evaluated)."""
    text = store.read_text(path)
    probe = collect.parse_output(text)
    script_ids = {d["script_id"] for d in probe["devices"] if d["script_id"]}
    expected = set()
    for sid in script_ids:
        rec = store.load_script_record(sid)
        if rec:
            expected |= set(rec["commands"])
    if not expected:
        expected = {c.strip() for r in rules_db["rules"] for c in r["commands"] if c.strip()}
    parsed = collect.parse_output(text, expected)
    archived = store.archive_evidence(path)
    run = new_run(parsed, archived, groups_db)
    run["script_ids"] = sorted(script_ids)
    return run
