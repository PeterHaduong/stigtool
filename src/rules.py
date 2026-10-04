"""Rule engine: plain-English conditions evaluated against show-command output.

A rule belongs to one STIG control and says:
  - which show commands to collect
  - NOT A FINDING when ALL / ANY of its conditions are true (otherwise OPEN)
  - optionally NOT APPLICABLE when ALL / ANY of a second set of conditions are true (checked first)
Missing, failed or invalid command output always gives NOT REVIEWED.

A condition is a dict:
  command   which collected command's output to look at
  scope     "all"   - the whole output
            "every" - every section whose first line matches `section` must pass
            "any"   - at least one such section must pass
  section, section_how   how to find section first lines (e.g. starts with "line vty")
  only      only check sections that have a line starting with this (e.g. "ip address")
  exclude   skip sections that have a line starting with this (e.g. "shutdown" - not "no shutdown")
            (only / exclude: start the text with "re:" to use a regular expression instead)
            Port roles: "role:uplink", "role:downlink", "role:access" or "role:any" (in only / exclude, or as
            the text to look for) mean an interface description starting with that role's keyword(s), which
            are a team setting (default UPLINK / DOWNLINK / ACCESS, UNTRUSTED).
  if_none   "fail" or "pass" when no sections are found
  check     has | lacks | number | count | pattern | no_pattern
  text, how, ignore_case   what to look for and how to match it
  op, value              comparison for number / count

A "section" is a line plus the indented lines under it, which is how IOS / NX-OS
configuration is laid out (line vty 0 4 -> transport input ssh, interface X -> ...).
"""
import re

HOWS = ["contains", "starts with", "whole line", "regex"]
SCOPES = {
    "all": "the whole output",
    "every": "EVERY section that",
    "any": "AT LEAST ONE section that",
}
CHECKS = {
    "has": "has a line that",
    "lacks": "has NO line that",
    "number": "has a line whose number is",
    "count": "has a number of matching lines that is",
    "pattern": "matches multi-line pattern (advanced regex)",
    "no_pattern": "does NOT match multi-line pattern (advanced regex)",
}
OPS = {
    ">=": lambda a, b: a >= b,
    "<=": lambda a, b: a <= b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    ">": lambda a, b: a > b,
    "<": lambda a, b: a < b,
}
OP_WORDS = {">=": "at least", "<=": "at most", "==": "exactly", "!=": "not", ">": "more than", "<": "less than"}

# Highlight tags, strongest first. One line can only show one colour.
TAG_ORDER = ["problem", "match", "section", "skipped"]

INVALID_RE = re.compile(
    r"^\s*(% ?(Invalid input|Incomplete command|Ambiguous command|Unknown command|Invalid command)"
    r"|Line has invalid autocommand|Syntax error)", re.I | re.M)

NEW_CONDITION = {
    "command": "", "scope": "all", "section": "", "section_how": "starts with", "only": "", "exclude": "",
    "if_none": "fail", "check": "has", "text": "", "how": "contains", "ignore_case": False,
    "op": ">=", "value": "",
}


def classify_output(text):
    """'invalid' if the device rejected the command, otherwise 'ok' (empty output is valid evidence)."""
    return "invalid" if INVALID_RE.search(text or "") else "ok"


def split_lines(text):
    return (text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")


# Port-role keywords (team setting, see set_port_roles). An interface is in a role when its description starts
# with one of the role's keywords, e.g. "description UPLINK - DIST-SW-01 Te2/0/14".
PORT_ROLES = {"uplink": "UPLINK", "downlink": "DOWNLINK", "access": "ACCESS, UNTRUSTED"}
DEFAULT_PORT_ROLES = dict(PORT_ROLES)


def set_port_roles(roles):
    PORT_ROLES.clear()
    PORT_ROLES.update(DEFAULT_PORT_ROLES)
    PORT_ROLES.update({k: v for k, v in (roles or {}).items() if k in PORT_ROLES and str(v).strip()})


def role_words(role):
    names = list(PORT_ROLES) if role == "any" else [role]
    return [w.strip() for name in names for w in PORT_ROLES.get(name, "").split(",") if w.strip()]


def is_role(text):
    return (text or "").strip().lower().startswith("role:")


def role_regex(text):
    role = text.strip()[5:].strip().lower()
    if role != "any" and role not in PORT_ROLES:
        raise re.error(f"unknown port role '{role}' (use uplink, downlink, access or any)")
    return re.compile(r"^\s*description\s+(" + "|".join(re.escape(w) for w in role_words(role)) + r")\b", re.I)


def describe_filter(text):
    if is_role(text):
        role = text.strip()[5:].strip().lower()
        return f"the {role} port role (description starting {' / '.join(role_words(role))})"
    return _quote(text)


def matcher(text, how, ignore_case=False):
    if is_role(text):
        return role_regex(text)
    flags = re.I if ignore_case else 0
    if how == "regex":
        return re.compile(text, flags)
    if how == "starts with":
        return re.compile(r"^\s*" + re.escape(text.strip()), flags)
    if how == "whole line":
        return re.compile(r"^\s*" + re.escape(text.strip()) + r"\s*$", flags)
    return re.compile(re.escape(text), flags)


def line_filter(text, ignore_case=False):
    """Section filters (only / exclude): a line starting with the text, a regex after "re:", or a port role."""
    if is_role(text):
        return role_regex(text)
    if text.startswith("re:"):
        return re.compile(text[3:], re.I if ignore_case else 0)
    return matcher(text, "starts with", ignore_case)


def _indent(line):
    return len(line) - len(line.lstrip(" \t"))


def find_sections(lines, header_rx):
    """[(header_index, [body_indexes])] - body is every following line indented deeper than the header."""
    out = []
    for i, line in enumerate(lines):
        if not line.strip() or not header_rx.search(line):
            continue
        depth, body, j = _indent(line), [], i + 1
        while j < len(lines) and lines[j].strip() and _indent(lines[j]) > depth:
            body.append(j)
            j += 1
        out.append((i, body))
    return out


def _quote(s):
    return f"'{s}'"


def describe(cond):
    """One plain-English sentence for a condition."""
    c = {**NEW_CONDITION, **cond}
    if c["scope"] == "all":
        where = "the output"
    else:
        where = f"{SCOPES[c['scope']]} {c['section_how']} {_quote(c['section'])}"
        if c.get("only"):
            where += (f" in {describe_filter(c['only'])}" if is_role(c["only"])
                      else f" with a line starting {_quote(c['only'])}")
        if c["exclude"]:
            where += (f" (skipping {describe_filter(c['exclude'])})" if is_role(c["exclude"])
                      else f" (skipping sections with a line starting {_quote(c['exclude'])})")
    check = c["check"]
    what = (f"is a description for {describe_filter(c['text'])}" if is_role(c["text"]) else
            f"{c['how']} {_quote(c['text'])}" + (" (any case)" if c["ignore_case"] else ""))
    if check == "has":
        tail = f"has a line that {what}"
    elif check == "lacks":
        tail = f"has NO line that {what}"
    elif check == "number":
        tail = f"has a line that {what} with a number {OP_WORDS[c['op']]} {c['value']}"
    elif check == "count":
        tail = f"has {OP_WORDS[c['op']]} {c['value']} line(s) that {what}"
    elif check == "pattern":
        tail = f"matches pattern {_quote(c['text'])}"
    else:
        tail = f"does NOT match pattern {_quote(c['text'])}"
    return f"[{c['command']}] {where} {tail}"


def condition_problems(cond, commands=None):
    """Reasons a condition cannot run (bad regex, missing values...)."""
    c = {**NEW_CONDITION, **cond}
    errs = []
    if not c["command"]:
        errs.append("no command chosen")
    elif commands is not None and c["command"] not in commands:
        errs.append(f"command {c['command']!r} is not in the rule's command list")
    if c["check"] not in CHECKS:
        errs.append(f"unknown check {c['check']!r}")
    if not c["text"]:
        errs.append("nothing to look for (text is empty)")
    if c["scope"] != "all" and not c["section"].strip():
        errs.append("section start text is empty")
    if c["check"] in ("number", "count"):
        try:
            float(c["value"])
        except (TypeError, ValueError):
            errs.append(f"'{c['value']}' is not a number")
        if c["op"] not in OPS:
            errs.append(f"unknown comparison {c['op']!r}")
    try:
        how = "regex" if c["check"] in ("pattern", "no_pattern") else c["how"]
        matcher(c["text"], how, c["ignore_case"])
        if c["scope"] != "all":
            matcher(c["section"], c["section_how"], c["ignore_case"])
            for f in (c.get("only"), c["exclude"]):
                if f:
                    line_filter(f, c["ignore_case"])
    except re.error as e:
        errs.append(f"pattern error: {e}")
    return errs


def _first_number(line, m):
    found = re.search(r"-?\d+(?:\.\d+)?", line[m.end():]) or re.search(r"-?\d+(?:\.\d+)?", line)
    return float(found.group(0)) if found else None


def _check_unit(c, lines, idxs, rx):
    """Run the check over the given line indexes. Returns (ok, note, marks[(idx, tag)])."""
    check = c["check"]
    marks = []
    if check in ("pattern", "no_pattern"):
        text = "\n".join(lines[i] for i in idxs)
        offsets, pos = [], 0
        for i in idxs:
            offsets.append((pos, i))
            pos += len(lines[i]) + 1
        hit_lines = set()
        for m in rx.finditer(text):
            if m.end() == m.start():
                continue
            for start, i in offsets:
                if start <= m.end() - 1 and start + len(lines[i]) >= m.start():
                    hit_lines.add(i)
        tag = "match" if check == "pattern" else "problem"
        marks = [(i, tag) for i in sorted(hit_lines)]
        found = bool(hit_lines)
        ok = found if check == "pattern" else not found
        return ok, ("pattern found" if found else "pattern not found"), marks

    hits = [i for i in idxs if rx.search(lines[i])]
    if check == "has":
        return bool(hits), (f"found on line {hits[0] + 1}" if hits else "no matching line"), \
            [(i, "match") for i in hits]
    if check == "lacks":
        return not hits, (f"found on line {', '.join(str(i + 1) for i in hits[:5])}" if hits else "not present"), \
            [(i, "problem") for i in hits]
    value, op = float(c["value"]), OPS[c["op"]]
    if check == "count":
        ok = op(len(hits), value)
        return ok, f"{len(hits)} matching line(s)", [(i, "match" if ok else "problem") for i in hits]
    # number
    if not hits:
        return False, "no matching line", []
    ok, notes = True, []
    for i in hits:
        n = _first_number(lines[i], rx.search(lines[i]))
        good = n is not None and op(n, value)
        ok = ok and good
        marks.append((i, "match" if good else "problem"))
        notes.append(f"line {i + 1}: {('no number' if n is None else f'{n:g}')}")
    return ok, "; ".join(notes[:5]), marks


def eval_condition(cond, outputs):
    """Evaluate one condition.

    outputs: {command: {"status": "ok"|"invalid"|"error"|"missing", "text": str}}
    Returns {"ok": True/False/None, "note": str, "marks": {command: [(idx, tag)]}}  (ok None = no evidence)
    """
    c = {**NEW_CONDITION, **cond}
    ev = outputs.get(c["command"])
    if not ev or ev.get("status") != "ok":
        state = ev.get("status") if ev else "missing"
        return {"ok": None, "note": f"no usable output for '{c['command']}' ({state})", "marks": {}}
    errs = condition_problems(c)
    if errs:
        return {"ok": None, "note": "rule error: " + "; ".join(errs), "marks": {}}
    lines = split_lines(ev.get("text", ""))
    how = "regex" if c["check"] in ("pattern", "no_pattern") else c["how"]
    rx = matcher(c["text"], how, c["ignore_case"])
    if c["check"] in ("pattern", "no_pattern"):
        rx = re.compile(rx.pattern, rx.flags | re.M)

    if c["scope"] == "all":
        ok, note, marks = _check_unit(c, lines, range(len(lines)), rx)
        return {"ok": ok, "note": note, "marks": {c["command"]: marks}}

    header_rx = matcher(c["section"], c["section_how"], c["ignore_case"])
    exclude_rx = line_filter(c["exclude"], c["ignore_case"]) if c["exclude"] else None
    only_rx = line_filter(c["only"], c["ignore_case"]) if c.get("only") else None
    marks, passed, failed, skipped = [], [], [], 0
    for head, body in find_sections(lines, header_rx):
        if only_rx and not any(only_rx.search(lines[i]) for i in [head] + body):
            continue
        if exclude_rx and any(exclude_rx.search(lines[i]) for i in [head] + body):
            marks.append((head, "skipped"))
            skipped += 1
            continue
        ok, _, unit_marks = _check_unit(c, lines, body, rx)
        marks += unit_marks
        marks.append((head, "section" if ok or c["scope"] == "any" else "problem"))
        (passed if ok else failed).append(head)
    total = len(passed) + len(failed)
    skip_note = f", {skipped} skipped" if skipped else ""
    if total == 0:
        ok = c["if_none"] == "pass"
        return {"ok": ok, "note": f"no matching sections found{skip_note} (counts as {'pass' if ok else 'fail'})",
                "marks": {c["command"]: marks}}
    if c["scope"] == "every":
        ok = not failed
        note = f"{len(passed)} of {total} section(s) OK{skip_note}"
        if failed:
            note += "; failing: " + ", ".join(f"'{lines[i].strip()}' (line {i + 1})" for i in failed[:5])
    else:
        ok = bool(passed)
        note = f"{len(passed)} of {total} section(s) OK{skip_note}"
    # The first line of each failing section (e.g. "interface GigabitEthernet1/0/5") - used by hardening scripts.
    failed_sections = [lines[i].strip() for i in failed] if c["scope"] == "every" else []
    return {"ok": ok, "note": note, "marks": {c["command"]: marks}, "failed_sections": failed_sections}


def _combine(mode, results):
    values = [r["ok"] for r in results]
    if mode == "ANY":
        return True if any(v is True for v in values) else (None if None in values else False)
    return False if any(v is False for v in values) else (None if None in values else True)


def _merge_marks(into, marks):
    for cmd, items in marks.items():
        slot = into.setdefault(cmd, {})
        for idx, tag in items:
            if idx not in slot or TAG_ORDER.index(tag) < TAG_ORDER.index(slot[idx]):
                slot[idx] = tag


def evaluate(rule, outputs):
    """Evaluate a rule against one device's evidence.

    Returns {"status", "reasons": [str], "marks": {command: {idx: tag}}, "evidence": [str]}
    """
    marks, reasons = {}, []
    commands = [c for c in rule.get("commands", []) if c.strip()]
    if not commands:
        return {"status": "not_reviewed", "reasons": ["Rule has no commands."], "marks": {}, "evidence": []}
    bad = [f"{c} ({outputs[c]['status'] if c in outputs else 'missing'})"
           for c in commands if outputs.get(c, {}).get("status") != "ok"]
    if bad:
        return {"status": "not_reviewed", "reasons": ["No usable evidence for: " + ", ".join(bad)],
                "marks": {}, "evidence": []}
    pass_logic = rule.get("pass_logic") or {"mode": "ALL", "conditions": []}
    if not pass_logic.get("conditions"):
        return {"status": "not_reviewed", "reasons": ["Rule has no conditions."], "marks": {}, "evidence": []}

    status, failed_sections, failed_by_condition = None, [], {}
    na_logic = rule.get("na_logic") or {}
    if rule.get("na_enabled") and na_logic.get("conditions"):
        na_results = [eval_condition(c, outputs) for c in na_logic["conditions"]]
        na = _combine(na_logic.get("mode", "ALL"), na_results)
        if na is True:
            status = "not_applicable"
            reasons.append(f"Not Applicable because {na_logic.get('mode', 'ALL')} of these are true:")
            for cond, r in zip(na_logic["conditions"], na_results):
                reasons.append(f"  {'TRUE ' if r['ok'] else 'FALSE'}  {describe(cond)} - {r['note']}")
                _merge_marks(marks, r["marks"])
        elif na is None:
            status = "not_reviewed"
            reasons.append("Could not decide Not Applicable check: " +
                           "; ".join(r["note"] for r in na_results if r["ok"] is None))

    if status is None:
        results = [eval_condition(c, outputs) for c in pass_logic["conditions"]]
        verdict = _combine(pass_logic.get("mode", "ALL"), results)
        status = {True: "not_a_finding", False: "open", None: "not_reviewed"}[verdict]
        reasons.append(f"Needs {pass_logic.get('mode', 'ALL')} of these to pass:")
        for n, (cond, r) in enumerate(zip(pass_logic["conditions"], results), 1):
            label = {True: "PASS ", False: "FAIL ", None: "ERROR"}[r["ok"]]
            reasons.append(f"  {label}  {describe(cond)} - {r['note']}")
            _merge_marks(marks, r["marks"])
            if r["ok"] is False:
                failed_sections += [h for h in r.get("failed_sections", []) if h not in failed_sections]
                failed_by_condition[str(n)] = r.get("failed_sections", [])

    evidence = []
    for cmd, slot in marks.items():
        lines = split_lines(outputs[cmd]["text"])
        shown = [i for i in sorted(slot) if slot[i] in ("match", "problem", "section")]
        if shown:
            evidence.append(f"{cmd}:")
            for i in shown[:40]:
                evidence.append(f"  {'!!' if slot[i] == 'problem' else '  '} {lines[i]}")
            if len(shown) > 40:
                evidence.append(f"     ... {len(shown) - 40} more line(s)")
    return {"status": status, "reasons": reasons, "marks": marks, "evidence": evidence,
            "failed_sections": failed_sections, "failed_by_condition": failed_by_condition}


def outcome_text(rule, status, devices=()):
    """The rule author's Finding Details text for this result, with {devices} / {device_count} filled in."""
    text = ((rule or {}).get("outcome_text") or {}).get(status, "").strip()
    if not text:
        return ""
    names = ", ".join(devices) or "(none)"
    return text.replace("{devices}", names).replace("{device_count}", str(len(devices)))


def test_outputs(test):
    """Saved test samples are stored as plain text per command."""
    return {cmd: {"status": classify_output(text), "text": text} for cmd, text in test.get("outputs", {}).items()}


def run_tests(rule):
    """[(test, actual_status, passed)]"""
    out = []
    for t in rule.get("tests", []):
        actual = evaluate(rule, test_outputs(t))["status"]
        out.append((t, actual, actual == t.get("expected")))
    return out


def activation_problems(rule):
    """Everything that must be fixed before a rule may be set Active."""
    errs = []
    commands = [c for c in rule.get("commands", []) if c.strip()]
    if not commands:
        errs.append("Add at least one show command.")
    conds = (rule.get("pass_logic") or {}).get("conditions") or []
    if not conds:
        errs.append("Add at least one Not a Finding condition.")
    all_conds = list(conds)
    if rule.get("na_enabled"):
        na = (rule.get("na_logic") or {}).get("conditions") or []
        if not na:
            errs.append("Not Applicable check is switched on but has no conditions.")
        all_conds += na
    for n, c in enumerate(all_conds, 1):
        for e in condition_problems(c, commands):
            errs.append(f"Condition {n}: {e}.")
    if rule.get("expected_open") and not (rule.get("outcome_text") or {}).get("open", "").strip():
        errs.append("Open is marked as an intentional finding: write the reason (e.g. risk acceptance) in the "
                    "Finding Details text for Open.")
    tests = rule.get("tests", [])
    if len(tests) < 2 or len({t.get("expected") for t in tests}) < 2:
        errs.append("Save at least two test samples with different expected results "
                    "(for example one that should pass and one that should be Open).")
    for t, actual, ok in run_tests(rule):
        if not ok:
            errs.append(f"Test '{t.get('name')}' expected {t.get('expected')} but rule gives {actual}.")
    return errs
