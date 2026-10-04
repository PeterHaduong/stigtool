"""Read, patch and validate STIG Viewer checklists.

  .ckl  - STIG Viewer 2.x (XML)
  .cklb - STIG Viewer 3.x (JSON; usually saved on one line, which is normal for JSON)

Output is always a copy of the source template with only these per-rule fields changed:
status, finding details, comments. For .cklb the checklist-level "id" and "title" are also
replaced so several group checklists made from one template do not collide in STIG Viewer 3.
validate() proves nothing else changed.
"""
import datetime
import hashlib
import json
import re
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.sax.saxutils import escape, unescape

STATUSES = ["not_a_finding", "open", "not_applicable", "not_reviewed"]
STATUS_LABELS = {
    "not_a_finding": "Not a Finding",
    "open": "Open",
    "not_applicable": "Not Applicable",
    "not_reviewed": "Not Reviewed",
}
LABEL_TO_STATUS = {v: k for k, v in STATUS_LABELS.items()}
CKL_STATUS = {
    "not_a_finding": "NotAFinding",
    "open": "Open",
    "not_applicable": "Not_Applicable",
    "not_reviewed": "Not_Reviewed",
}
CKL_TO_STATUS = {v: k for k, v in CKL_STATUS.items()}

FORMAT_LABELS = {"ckl": "STIG Viewer 2.x (.ckl)", "cklb": "STIG Viewer 3 (.cklb)"}
COMPARE_FIELDS = {"title": "title", "severity": "severity", "check": "check text", "fix": "fix text",
                  "rule_id": "rule ID", "rule_ver": "rule version"}

CKLB_RULE_FIELDS = ("status", "finding_details", "comments")
CKLB_TOP_FIELDS = ("id", "title")
CKL_VULN_FIELDS = ("STATUS", "FINDING_DETAILS", "COMMENTS")


class ChecklistError(Exception):
    pass


def family_of(stig_id):
    """Cisco_IOS_XE_Switch_NDM_STIG -> NDM"""
    m = re.search(r"_([A-Za-z0-9]+)_STIG$", stig_id or "")
    return m.group(1).upper() if m else (stig_id or "UNKNOWN")


def short_name(title, stig_id=""):
    """'Cisco IOS XE Switch NDM Security Technical Implementation Guide' -> 'Cisco IOS XE Switch NDM'"""
    name = re.sub(r"\s*(Security Technical Implementation Guide|STIG)\s*$", "", title or "", flags=re.I).strip()
    return name or stig_id or "Unknown STIG"


def release_key(version, release_info):
    """Sortable (version, release, benchmark date) so newer DISA releases sort last."""
    def num(pattern):
        m = re.search(pattern, release_info or "", re.I)
        return int(m.group(1)) if m else 0
    try:
        ver = int(str(version).strip() or 0)
    except ValueError:
        ver = 0
    date = re.search(r"Benchmark Date:\s*(\d{1,2}\s+\w+\s+\d{4})", release_info or "")
    stamp = ""
    if date:
        try:
            stamp = datetime.datetime.strptime(date.group(1), "%d %b %Y").strftime("%Y%m%d")
        except ValueError:
            stamp = ""
    return (ver, num(r"Release:\s*(\d+)"), stamp)


def release_label(version, release_info):
    """'V3R6 (01 Apr 2026)'"""
    rel = re.search(r"Release:\s*(\d+)", release_info or "")
    date = re.search(r"Benchmark Date:\s*(.+)$", release_info or "")
    label = f"V{version}R{rel.group(1)}" if rel else (release_info or "?")
    return f"{label} ({date.group(1).strip()})" if date else label


def compare_controls(old, new):
    """Differences between two releases' control lists.

    Returns [{"vuln_id", "kind": added|removed|changed, "fields": [...], "old", "new"}]
    """
    a = {c["vuln_id"]: c for c in old}
    b = {c["vuln_id"]: c for c in new}
    out = []
    for vid in [c["vuln_id"] for c in new] + [v for v in a if v not in b]:
        x, y = a.get(vid), b.get(vid)
        if x and y:
            fields = [f for f in COMPARE_FIELDS
                      if (f in ("check", "fix") and text_hash(x.get(f)) != text_hash(y.get(f)))
                      or (f not in ("check", "fix") and (x.get(f) or "") != (y.get(f) or ""))]
            if fields:
                out.append({"vuln_id": vid, "kind": "changed", "fields": fields, "old": x, "new": y})
        elif y:
            out.append({"vuln_id": vid, "kind": "added", "fields": [], "old": None, "new": y})
        else:
            out.append({"vuln_id": vid, "kind": "removed", "fields": [], "old": x, "new": None})
    return out


def viewer_of(path, fmt, data=None):
    """Which STIG Viewer wrote the file, e.g. 'STIG Viewer 2.10' or 'STIG Viewer 3 (CKLB 1.0)'."""
    if fmt == "cklb":
        return f"STIG Viewer 3 (CKLB {(data or {}).get('cklb_version') or '1.0'})"
    head = Path(path).read_bytes()[:400].decode("utf-8", errors="replace")
    m = re.search(r"STIG Viewer\s*::\s*([\d.]+)", head)
    return f"STIG Viewer {m.group(1)}" if m else "STIG Viewer 2.x"


def text_hash(text):
    """Fingerprint of check text, whitespace-insensitive. Used to flag rules after a STIG update."""
    return hashlib.sha256(" ".join((text or "").split()).encode("utf-8")).hexdigest()[:16]


def detect_format(path):
    path = Path(path)
    if path.suffix.lower() == ".cklb":
        return "cklb"
    if path.suffix.lower() == ".ckl":
        return "ckl"
    head = path.read_bytes()[:200].lstrip(b"\xef\xbb\xbf \r\n\t")
    if head.startswith(b"{"):
        return "cklb"
    if head.startswith(b"<"):
        return "ckl"
    raise ChecklistError(f"{path.name} is not a .ckl or .cklb checklist")


def _control(vuln_id, rule_ver, rule_id, severity, title, check, fix, status):
    return {
        "vuln_id": vuln_id,
        "rule_ver": rule_ver or "",
        "rule_id": rule_id or "",
        "severity": severity or "",
        "title": title or "",
        "check": check or "",
        "fix": fix or "",
        "template_status": status,
        "check_hash": text_hash(check),
    }


def read_checklist(path):
    """Return {"format", "stigs": [{"stig_id", "family", "title", "release_info", "version", "controls"}]}"""
    fmt = detect_format(path)
    stigs = []
    if fmt == "cklb":
        data = _load_cklb(path)
        for s in data.get("stigs") or []:
            controls = [_control(r.get("group_id"), r.get("rule_version"), r.get("rule_id"),
                                 r.get("severity"), r.get("rule_title"), r.get("check_content"),
                                 r.get("fix_text"), r.get("status", "not_reviewed"))
                        for r in s.get("rules") or []]
            stigs.append({"stig_id": s.get("stig_id", ""), "title": s.get("stig_name", ""),
                          "short": s.get("display_name") or short_name(s.get("stig_name"), s.get("stig_id")),
                          "release_info": s.get("release_info", ""), "version": str(s.get("version", "")),
                          "controls": controls})
    else:
        root = _load_ckl(path).getroot()
        for istig in root.iter("iSTIG"):
            info = {}
            for si in istig.iter("SI_DATA"):
                info[si.findtext("SID_NAME", "")] = si.findtext("SID_DATA", "")
            controls = []
            for vuln in istig.iter("VULN"):
                d = {}
                for sd in vuln.findall("STIG_DATA"):
                    d.setdefault(sd.findtext("VULN_ATTRIBUTE", ""), sd.findtext("ATTRIBUTE_DATA", ""))
                status = CKL_TO_STATUS.get(vuln.findtext("STATUS", ""), "not_reviewed")
                controls.append(_control(d.get("Vuln_Num"), d.get("Rule_Ver"), d.get("Rule_ID"),
                                         d.get("Severity"), d.get("Rule_Title"), d.get("Check_Content"),
                                         d.get("Fix_Text"), status))
            stigs.append({"stig_id": info.get("stigid", ""), "title": info.get("title", ""),
                          "short": short_name(info.get("title"), info.get("stigid")),
                          "release_info": info.get("releaseinfo", ""), "version": info.get("version", ""),
                          "controls": controls})
    if not stigs:
        raise ChecklistError(f"{Path(path).name} contains no STIGs")
    for s in stigs:
        s["family"] = family_of(s["stig_id"])
        missing = [c for c in s["controls"] if not c["vuln_id"]]
        if missing:
            raise ChecklistError(f"{s['stig_id']}: {len(missing)} rule(s) have no Vuln ID")
    return {"format": fmt, "viewer": viewer_of(path, fmt, data if fmt == "cklb" else None), "stigs": stigs}


def _load_cklb(path):
    try:
        with open(path, encoding="utf-8-sig") as f:
            return json.load(f)
    except ValueError as e:
        raise ChecklistError(f"{Path(path).name} is not valid CKLB JSON: {e}")


def _load_ckl(path):
    try:
        return ET.parse(path)
    except ET.ParseError as e:
        raise ChecklistError(f"{Path(path).name} is not valid CKL XML: {e}")


# ---------------------------------------------------------------- patching

def write_patched(src, dst, updates, title=None):
    """Copy src to dst, changing only the given fields.

    updates: {(stig_id, vuln_id): {"status": <STATUSES value>, "finding_details": str, "comments": str}}
             A field that is missing or None is left exactly as the template has it.
    Returns the number of controls changed.
    """
    for key, upd in updates.items():
        if upd.get("status") is not None and upd["status"] not in STATUSES:
            raise ChecklistError(f"{key}: invalid status {upd['status']!r}")
    if detect_format(src) == "cklb":
        return _patch_cklb(src, dst, updates, title)
    return _patch_ckl(src, dst, updates)


def _clean(text):
    return (text or "").replace("\r\n", "\n").replace("\r", "\n")


def _patch_cklb(src, dst, updates, title):
    data = _load_cklb(src)
    pending = dict(updates)
    for s in data.get("stigs") or []:
        for r in s.get("rules") or []:
            upd = pending.pop((s.get("stig_id"), r.get("group_id")), None)
            if not upd:
                continue
            for field in CKLB_RULE_FIELDS:
                if upd.get(field) is not None:
                    r[field] = _clean(upd[field]) if field != "status" else upd[field]
    if pending:
        raise ChecklistError(f"Controls not found in template: {', '.join(v for _, v in pending)}")
    data["id"] = str(uuid.uuid4())
    if title:
        data["title"] = title
    with open(dst, "w", encoding="utf-8", newline="") as f:
        f.write(json.dumps(data, ensure_ascii=False, separators=(",", ":")))
    return len(updates)


ISTIG_RE = re.compile(r"<iSTIG>.*?</iSTIG>", re.S)
VULN_RE = re.compile(r"<VULN>.*?</VULN>", re.S)
STIGID_RE = re.compile(r"<SID_NAME>stigid</SID_NAME>\s*<SID_DATA>(.*?)</SID_DATA>", re.S)
VULNNUM_RE = re.compile(r"<VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>(.*?)</ATTRIBUTE_DATA>", re.S)


def _set_element(block, tag, value):
    pattern = re.compile(rf"<{tag}>.*?</{tag}>|<{tag}\s*/>", re.S)
    if not pattern.search(block):
        raise ChecklistError(f"<{tag}> not found in VULN block")
    new = f"<{tag}>{escape(value)}</{tag}>"
    return pattern.sub(lambda m: new, block, count=1)


def _patch_ckl(src, dst, updates):
    # Edit the XML text in place (rather than re-serialising the whole tree) so every byte
    # outside the three edited elements stays exactly as STIG Viewer wrote it.
    with open(src, encoding="utf-8", newline="") as f:
        text = f.read()
    pending = dict(updates)

    def patch_vuln(stig_id, m):
        block = m.group(0)
        num = VULNNUM_RE.search(block)
        upd = pending.pop((stig_id, unescape(num.group(1)).strip()), None) if num else None
        if not upd:
            return block
        if upd.get("status") is not None:
            block = _set_element(block, "STATUS", CKL_STATUS[upd["status"]])
        if upd.get("finding_details") is not None:
            block = _set_element(block, "FINDING_DETAILS", _clean(upd["finding_details"]))
        if upd.get("comments") is not None:
            block = _set_element(block, "COMMENTS", _clean(upd["comments"]))
        return block

    def patch_istig(m):
        block = m.group(0)
        sid = STIGID_RE.search(block)
        stig_id = unescape(sid.group(1)).strip() if sid else ""
        return VULN_RE.sub(lambda vm: patch_vuln(stig_id, vm), block)

    text = ISTIG_RE.sub(patch_istig, text)
    if pending:
        raise ChecklistError(f"Controls not found in template: {', '.join(v for _, v in pending)}")
    with open(dst, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    return len(updates)


# ---------------------------------------------------------------- validation

def validate(src, dst):
    """Compare output to its source template. Returns (ok, lines)."""
    try:
        if detect_format(src) == "cklb":
            problems, changed = _validate_cklb(src, dst)
        else:
            problems, changed = _validate_ckl(src, dst)
    except Exception as e:  # unreadable output is a validation failure, not a crash
        problems, changed = [f"Could not read output: {e}"], 0
    lines = [f"Source: {Path(src).name}", f"Output: {Path(dst).name}",
             f"Controls with edited fields: {changed}"]
    if problems:
        lines.append(f"RESULT: FAILED ({len(problems)} problem(s))")
        lines += [f"  - {p}" for p in problems[:200]]
    else:
        lines.append("RESULT: PASSED - only status, finding details and comments differ"
                     + (" (plus checklist id/title)" if detect_format(src) == "cklb" else ""))
    return not problems, lines


def _validate_cklb(src, dst):
    a, b = _load_cklb(src), _load_cklb(dst)
    problems, changed = [], 0
    for key in set(a) | set(b):
        if key not in CKLB_TOP_FIELDS + ("stigs",) and a.get(key) != b.get(key):
            problems.append(f"Checklist field '{key}' changed")
    sa, sb = a.get("stigs") or [], b.get("stigs") or []
    if len(sa) != len(sb):
        return problems + ["Number of STIGs changed"], 0
    for x, y in zip(sa, sb):
        if {k: v for k, v in x.items() if k != "rules"} != {k: v for k, v in y.items() if k != "rules"}:
            problems.append(f"STIG header changed: {x.get('stig_id')}")
        rx, ry = x.get("rules") or [], y.get("rules") or []
        if len(rx) != len(ry):
            problems.append(f"{x.get('stig_id')}: number of rules changed")
            continue
        for r1, r2 in zip(rx, ry):
            strip1 = {k: v for k, v in r1.items() if k not in CKLB_RULE_FIELDS}
            strip2 = {k: v for k, v in r2.items() if k not in CKLB_RULE_FIELDS}
            if strip1 != strip2:
                diff = sorted(k for k in set(strip1) | set(strip2) if strip1.get(k) != strip2.get(k))
                problems.append(f"{r1.get('group_id')}: protected field(s) changed: {', '.join(diff)}")
            if r2.get("status") not in STATUSES:
                problems.append(f"{r2.get('group_id')}: invalid status {r2.get('status')!r}")
            if any(r1.get(k) != r2.get(k) for k in CKLB_RULE_FIELDS):
                changed += 1
    return problems, changed


def _canon(el, skip=()):
    return (el.tag, (el.text or "").strip() and el.text, tuple(sorted(el.attrib.items())),
            tuple(_canon(c) for c in el if c.tag not in skip))


def _validate_ckl(src, dst):
    problems, changed = [], 0
    with open(src, encoding="utf-8") as f:
        pre_a = f.read().split("<CHECKLIST", 1)[0]
    with open(dst, encoding="utf-8") as f:
        pre_b = f.read().split("<CHECKLIST", 1)[0]
    if pre_a != pre_b:
        problems.append("XML declaration / STIG Viewer header comment changed")
    ra, rb = _load_ckl(src).getroot(), _load_ckl(dst).getroot()
    if _canon(ra.find("ASSET")) != _canon(rb.find("ASSET")):
        problems.append("ASSET (target data) changed")
    ia, ib = ra.findall(".//iSTIG"), rb.findall(".//iSTIG")
    if len(ia) != len(ib):
        return problems + ["Number of STIGs changed"], 0
    for x, y in zip(ia, ib):
        if _canon(x.find("STIG_INFO")) != _canon(y.find("STIG_INFO")):
            problems.append("STIG_INFO changed")
        vx, vy = x.findall("VULN"), y.findall("VULN")
        if len(vx) != len(vy):
            problems.append("Number of VULNs changed")
            continue
        for v1, v2 in zip(vx, vy):
            num = next((sd.findtext("ATTRIBUTE_DATA") for sd in v1.findall("STIG_DATA")
                        if sd.findtext("VULN_ATTRIBUTE") == "Vuln_Num"), "?")
            if _canon(v1, CKL_VULN_FIELDS) != _canon(v2, CKL_VULN_FIELDS):
                problems.append(f"{num}: protected content changed")
            if v2.findtext("STATUS") not in CKL_TO_STATUS:
                problems.append(f"{num}: invalid status {v2.findtext('STATUS')!r}")
            if any((v1.findtext(t) or "") != (v2.findtext(t) or "") for t in CKL_VULN_FIELDS):
                changed += 1
    return problems, changed
