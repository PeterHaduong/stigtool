"""Hand a rule to another AI (LLM) to write its conditions, and read its answer back.

build_prompt() writes one self-contained prompt: what the tool can check (generated from the rule engine, so it
always matches what the engine supports), the team's port roles, worked examples, the STIG check text, the
rule's commands and sample output (secrets masked), and the reviewer's goal and good / bad examples. The AI must
answer with one JSON object. parse_answer() reads that answer back, fills in defaults and checks every
condition, so nothing reaches the rule editor that the engine cannot run.

JSON, not CSV: rule texts are regular expressions full of commas, quotes and | characters.
"""
import json
import re

import rules as engine

FORMAT = "stigtool-conditions-1"

# Values that must never leave the building in a prompt. Each pattern keeps the keyword and masks what follows.
SECRET_RES = [
    # enable secret 9 X / username u privilege 15 secret 9 X / password 7 X / snmp ... password X
    re.compile(r"(?im)((?<!no )\b(?:secret|password)[ \t]+(?:level[ \t]+\d+[ \t]+)?(?:\d{1,2}[ \t]+(?=\S))?)\S+"),
    # key chains / tacacs / radius:  key 7 X, key-string 7 X, server-key X, pre-shared-key X (not 'key chain N')
    re.compile(r"(?im)^([ \t]*(?:key|key-string|server-key|pre-shared-key)[ \t]+(?!chain\b)(?!\d+[ \t]*$)(?:\d{1,2}[ \t]+(?=\S))?)\S+"),
    re.compile(r"(?im)^([ \t]*(?:tacacs|radius)-server[ \t]+(?:host[ \t]+\S+[ \t]+.*?)?key[ \t]+(?:\d{1,2}[ \t]+(?=\S))?)\S+"),
    # ntp authentication-key 1 md5 X 7 / hmac-sha2-256 X
    re.compile(r"(?im)(\bauthentication-key[ \t]+\d+[ \t]+\S+[ \t]+)\S+"),
    re.compile(r"(?im)^([ \t]*snmp-server community[ \t]+)\S+"),
    # snmp-server user U G v3 auth sha X priv aes 256 Y (NX-OS: auth sha 0x.. priv aes-128 0x.. / priv 0x..)
    re.compile(r"(?im)(\b(?:auth|priv)[ \t]+(?:md5|sha\S*|aes(?:-\d+)?(?:[ \t]+\d+)?|des|3des)[ \t]+)\S+"),
    re.compile(r"(?im)(\bpriv[ \t]+)0x\S+"),
    re.compile(r"(?im)(\bisakmp[ \t]+key[ \t]+(?:\d[ \t]+)?)\S+"),
]


def redact(text):
    """Mask passwords, secrets, keys and SNMP communities. A best effort: the person still reviews the prompt."""
    for rx in SECRET_RES:
        text = rx.sub(lambda m: m.group(1) + "<MASKED>", text)
    return text


# ---------------------------------------------------------------- the prompt

def reference():
    """What a condition can say - generated from the engine's own lists."""
    roles = "\n".join(f"    role:{name:<10} interface description starts with {' / '.join(engine.role_words(name))}"
                      for name in engine.PORT_ROLES)
    checks = "\n".join(f'    "{k}": {v}' for k, v in engine.CHECKS.items())
    ops = ", ".join(f'"{k}" ({v})' for k, v in engine.OP_WORDS.items())
    return f"""(Values below are written as JSON strings, so a regex backslash appears doubled: \\\\s means \\s.)

HOW THE TOOL EVALUATES A RULE
- A rule lists the show commands to collect, then NOT A FINDING conditions combined with "ALL" (AND) or "ANY" (OR).
  If they are not met the result is OPEN.
- Optional NOT APPLICABLE conditions (also ALL / ANY) are checked first; if they are met the result is NOT APPLICABLE.
- Missing, failed or rejected command output ("% Invalid input") always gives NOT REVIEWED. Never design a
  condition that passes because something is absent from output that was not collected.
- Matching is line by line on the raw text output, using Python regular expressions where a regex is asked for.

A CONDITION is a JSON object with these fields:
  "command"      exactly one of the rule's commands - which output to look in.
  "scope"        "all"   = {engine.SCOPES['all']}
                 "every" = every SECTION found must pass (the usual choice for interfaces, vty lines...)
                 "any"   = at least one SECTION must pass
  A SECTION is a line plus the lines under it that are indented deeper (stops at the first line that is not
  indented deeper, e.g. "!" or the next "interface ..."). This is how IOS-XE / NX-OS configuration is laid out.
  "section"      (scope every / any) text that finds the section FIRST lines, e.g. "interface" or "line vty".
  "section_how"  how "section" matches the first line: {', '.join(f'"{h}"' for h in engine.HOWS)}.
                 Useful regexes: front-panel switch ports on IOS-XE (no Vlan / Loopback / Port-channel /
                 AppGigabitEthernet): "^interface (?!AppGig)\\\\S*(Ethernet|GigE)\\\\d"; NX-OS: "^interface Ethernet\\\\d".
  "only"         list of filters; a section is checked only if it matches EVERY one (searched in the first line
                 and the body).
  "exclude"      list of filters; a section is skipped if it matches ANY one.
                 A filter is one of:
                   "text"        a line STARTING with the text (after indentation), so "shutdown" does not match
                                 "no shutdown"
                   "re:REGEX"    a line matching the regex, e.g. "re:^\\\\s*shutdown\\\\s*$"
                   "role:NAMES"  a port role (or several, comma separated: "role:uplink, downlink, trusted")
  "if_none"      "pass" or "fail": the result when no section is found (after only / exclude).
  "check"        what must be true of the section body (scope every / any) or of the whole output (scope all):
{checks}
                 has / lacks / number / count look at single lines. For scope every / any they look only at
                 the section BODY (not its first line). pattern / no_pattern search the text as one block
                 (multi-line regex, ^ and $ match at each line).
  "text"         what to look for.
  "how"          how "text" matches a line: {', '.join(f'"{h}"' for h in engine.HOWS)}.
                 "contains" = anywhere in the line, "starts with" = after indentation, "whole line" = the whole
                 line apart from indentation and trailing spaces, "regex" = Python regex searched in the line.
                 Not used by pattern / no_pattern (always regex).
  "ignore_case"  true / false.
  "op", "value"  for "number" and "count" only: op is one of {ops}; value is a number.
                 "number" reads the first number after the matched text on each matching line, and every
                 matching line must satisfy the comparison; no matching line = fail.
                 "count" compares how many lines match.
  "text" may also be "role:NAME" with check "has" to require a description in that role.

PORT ROLES (this team's interface-description keywords; a port with no matching description has no role):
{roles}
    role:any        any of the above (any labelled port)
"""


def _answer_condition(cond):
    """A stored condition in the answer format (only / exclude as lists, defaults left out)."""
    c = {**engine.NEW_CONDITION, **cond}
    out = {"command": c["command"], "scope": c["scope"]}
    if c["scope"] != "all":
        out.update(section=c["section"], section_how=c["section_how"],
                   only=engine.filter_lines(c.get("only")), exclude=engine.filter_lines(c["exclude"]),
                   if_none=c["if_none"])
    out.update(check=c["check"], text=c["text"])
    if c["check"] not in ("pattern", "no_pattern"):
        out["how"] = c["how"]
    if c["ignore_case"]:
        out["ignore_case"] = True
    if c["check"] in ("number", "count"):
        out.update(op=c["op"], value=c["value"])
    return out


def answer_for_rule(rule, explanation=""):
    """The rule's logic in the answer format (used for the examples and for 'the rule today')."""
    na = (rule.get("na_logic") or {}) if rule.get("na_enabled") else {}
    return {"format": FORMAT, "commands": list(rule.get("commands") or []),
            "pass_mode": (rule.get("pass_logic") or {}).get("mode", "ALL"),
            "pass_conditions": [_answer_condition(c) for c in (rule.get("pass_logic") or {}).get("conditions", [])],
            "na_mode": na.get("mode", "ALL"),
            "na_conditions": [_answer_condition(c) for c in na.get("conditions", [])],
            "tests": [], "explanation": explanation}


def _examples():
    import drafts  # late: drafts imports store / harden, which the prompt does not otherwise need
    lib = drafts.LIBRARY["IOSXE_SW"]
    picks = [("CISC-ND-000720", "Timeouts: numbers in sections, plus a line that must not exist anywhere."),
             ("CISC-L2-000130", "Port roles: trust on every uplink and on nothing else."),
             ("CISC-L2-000020", "Either / or per port: every port that is not an uplink, downlink or trusted "
                                "port runs 802.1x (conditions 1-2) or is shut down in the parking VLAN "
                                "(condition 3, which skips ports that have 802.1x); condition 4 catches open "
                                "authentication anywhere except trusted ports.")]
    out = []
    for ver, why in picks:
        spec = lib[ver]
        rule = {"commands": spec["cmds"] or list(dict.fromkeys(c["command"] for c in spec["conds"] + spec["na"])),
                "pass_logic": {"mode": spec["mode"], "conditions": spec["conds"]},
                "na_enabled": bool(spec["na"]), "na_logic": {"mode": "ALL", "conditions": spec["na"]}}
        out.append(f"Example - {why}\n```json\n{json.dumps(answer_for_rule(rule, why), indent=1)}\n```")
    return "\n\n".join(out)


def build_prompt(control, rule, platform, goal="", good="", bad="", samples=None, mask=True):
    """The whole prompt as text. samples: {command: output} to include (masked when mask is True)."""
    clean = redact if mask else (lambda t: t)
    parts = [
        "You are helping write a compliance-check rule for a STIG assessment tool. The tool runs show commands on "
        "Cisco network devices and decides Not a Finding / Open / Not Applicable from the text output using ONLY "
        "the conditions described below. Your job: write the conditions for the requirement below.",
        "Answer with ONE JSON object in a ```json code block and nothing else outside it, in exactly the "
        "format at the end. Use only the fields and values listed. Prefer simple checks (has / lacks with "
        "\"starts with\" or \"whole line\") over regexes; use a regex only when it is really needed. Do not "
        "invent commands the device does not have.",
        reference(),
        "WORKED EXAMPLES (real rules from this tool, in the answer format)\n\n" + _examples(),
        f"THE REQUIREMENT\nPlatform: {platform or 'Cisco'}\n{control.get('vuln_id', '')} {control.get('rule_ver', '')} "
        f"(severity {control.get('severity', '')}): {control.get('title', '')}\n\nCHECK TEXT:\n"
        f"{(control.get('check') or '').strip()}\n\nFIX TEXT:\n{(control.get('fix') or '').strip()}",
    ]
    if (rule.get("pass_logic") or {}).get("conditions"):
        parts.append("THE RULE TODAY (improve it or replace it):\n```json\n"
                     f"{json.dumps(answer_for_rule(rule), indent=1)}\n```")
    elif rule.get("commands"):
        parts.append("Commands the rule already collects: " + ", ".join(rule["commands"]))
    if goal.strip():
        parts.append(f"WHAT THE REVIEWER WANTS (this wins over everything else):\n{goal.strip()}")
    if good.strip():
        parts.append("An example that MUST give Not a Finding (pass):\n```\n" + clean(good.strip("\n")) + "\n```")
    if bad.strip():
        parts.append("An example that MUST give Open (fail):\n```\n" + clean(bad.strip("\n")) + "\n```")
    for cmd, text in (samples or {}).items():
        parts.append(f"Real output of '{cmd}' from a device (for the layout; it may pass or fail):\n```\n"
                     f"{clean(text.strip(chr(10)))}\n```")
    parts.append(
        "ANSWER FORMAT - one JSON object:\n```json\n" + json.dumps({
            "format": FORMAT,
            "commands": ["show running-config"],
            "pass_mode": "ALL",
            "pass_conditions": [{"command": "show running-config", "scope": "every", "section": "interface",
                                 "section_how": "starts with", "only": [], "exclude": ["role:uplink"],
                                 "if_none": "pass", "check": "has", "text": "...", "how": "whole line"}],
            "na_mode": "ALL",
            "na_conditions": [],
            "tests": [{"name": "short name", "expected": "not_a_finding",
                       "outputs": {"show running-config": "...device output that should pass..."}},
                      {"name": "short name", "expected": "open",
                       "outputs": {"show running-config": "...device output that should fail..."}}],
            "explanation": "One short paragraph: what each condition checks and anything the reviewer must "
                           "confirm by hand."}, indent=1) + "\n```\n"
        "- \"commands\": every show command the conditions use (exact text).\n"
        "- \"na_conditions\": empty list unless the requirement can be Not Applicable (e.g. a feature not in use).\n"
        "- \"tests\": at least one sample that should pass and one that should fail, as realistic device output. "
        "expected is one of not_a_finding, open, not_applicable.")
    return "\n\n".join(parts)


# ---------------------------------------------------------------- reading the answer

CONDITION_KEYS = set(engine.NEW_CONDITION)
STATUSES = ("not_a_finding", "open", "not_applicable", "not_reviewed")


def _json_text(text):
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fence:
        return fence.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise ValueError("No JSON object found in the answer.")
    return text[start:end + 1]


def _condition(raw, n, where, commands, problems):
    if not isinstance(raw, dict):
        problems.append(f"{where} {n}: not an object - left out.")
        return None
    unknown = sorted(set(raw) - CONDITION_KEYS)
    if unknown:
        problems.append(f"{where} {n}: ignored unknown field(s) {', '.join(unknown)}.")
    c = {**engine.NEW_CONDITION, **{k: v for k, v in raw.items() if k in CONDITION_KEYS}}
    for key in ("only", "exclude"):
        if isinstance(c[key], list):
            c[key] = "\n".join(str(f).strip() for f in c[key] if str(f).strip())
        c[key] = str(c[key] or "")
    for key in ("command", "section", "section_how", "if_none", "check", "text", "how", "op"):
        c[key] = str(c[key] if c[key] is not None else "")
    c["value"] = "" if c["value"] in (None, "") else str(c["value"])
    c["ignore_case"] = bool(c["ignore_case"]) and str(c["ignore_case"]).lower() != "false"
    if c["scope"] not in engine.SCOPES:
        problems.append(f"{where} {n}: unknown scope {c['scope']!r}.")
    if c["if_none"] not in ("pass", "fail"):
        problems.append(f"{where} {n}: if_none must be pass or fail.")
    if c["how"] not in engine.HOWS or c["section_how"] not in engine.HOWS:
        problems.append(f"{where} {n}: how / section_how must be one of {', '.join(engine.HOWS)}.")
    if c["scope"] in engine.SCOPES and c["how"] in engine.HOWS and c["section_how"] in engine.HOWS:
        problems += [f"{where} {n}: {e}." for e in engine.condition_problems(c, commands)]
    return c


def parse_answer(text):
    """Read an AI answer. Returns (answer, problems): answer has commands, pass_mode, pass_conditions, na_mode,
    na_conditions, tests and explanation in the tool's own format. Raises ValueError when it is not usable."""
    try:
        data = json.loads(_json_text(text))
    except json.JSONDecodeError as e:
        raise ValueError(f"The answer is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ValueError("The answer must be one JSON object.")
    problems = []
    commands = [str(c).strip() for c in data.get("commands") or [] if str(c).strip()]
    conds = {}
    for key, label in (("pass_conditions", "Not a Finding condition"), ("na_conditions", "Not Applicable condition")):
        raw = data.get(key) or []
        if not isinstance(raw, list):
            raise ValueError(f"'{key}' must be a list.")
        conds[key] = [c for c in (_condition(r, n, label, commands, problems) for n, r in enumerate(raw, 1)) if c]
    for c in conds["pass_conditions"] + conds["na_conditions"]:  # a used command left out of the list: add it
        if c["command"] and c["command"] not in commands:
            commands.append(c["command"])
            problems = [p for p in problems if f"command {c['command']!r} is not in" not in p]
    if not conds["pass_conditions"]:
        raise ValueError("The answer has no Not a Finding conditions.")
    modes = {}
    for key in ("pass_mode", "na_mode"):
        modes[key] = str(data.get(key) or "ALL").upper()
        if modes[key] not in ("ALL", "ANY"):
            problems.append(f"{key} {modes[key]!r} is not ALL or ANY - using ALL.")
            modes[key] = "ALL"
    tests = []
    for n, t in enumerate(data.get("tests") or [], 1):
        outputs = (t or {}).get("outputs") if isinstance(t, dict) else None
        if not isinstance(outputs, dict) or t.get("expected") not in STATUSES:
            problems.append(f"AI test {n}: needs 'expected' ({', '.join(STATUSES)}) and 'outputs' - left out.")
            continue
        tests.append({"name": str(t.get("name") or f"test {n}"), "expected": t["expected"],
                      "outputs": {str(k): str(v) for k, v in outputs.items()}})
    return {"commands": commands, **modes, **conds, "tests": tests,
            "explanation": str(data.get("explanation") or "")}, problems
