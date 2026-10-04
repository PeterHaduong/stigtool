"""Project folders and data files - built so a team can share them.

Everything lives in plain JSON under data/:
  data/rules/<rule id>.json     one file per rule, so two people editing different rules never clash
  data/groups/<group id>.json   one file per device group
  data/settings.json            team settings: output format, manual-only controls, device overrides
  data/templates/               imported CKL/CKLB files (read-only) + one catalog .json each
  data/locks/                   "who is editing this rule" markers
  data/runs/, data/evidence/, data/scripts/

Saving a rule or group checks that nobody else saved it since you opened it (ConflictError).

Shared location: put the path of a shared folder (e.g. \\\\server\\share\\stigtool) on the first line of
shared_data_path.txt next to main.py. data/, input/ and output/ then live there; logs stay local.
"""
import copy
import datetime
import getpass
import hashlib
import json
import os
import secrets
import shutil
import socket
import stat
from pathlib import Path

import checklist

LOCK_HOURS = 12


class ConflictError(Exception):
    """Someone else saved the record after you loaded it. .current holds their version."""

    def __init__(self, current):
        super().__init__("changed by someone else")
        self.current = current


class Paths:
    def __init__(self, root):
        self.root = Path(root)
        self.workspace = self.root
        pointer = self.root / "shared_data_path.txt"
        if pointer.exists():
            target = pointer.read_text(encoding="utf-8").strip().splitlines()
            if target and target[0].strip():
                self.workspace = Path(target[0].strip())
        self.data = self.workspace / "data"
        self.templates = self.data / "templates"
        self.rules = self.data / "rules"
        self.groups = self.data / "groups"
        self.locks = self.data / "locks"
        self.scripts = self.data / "scripts"
        self.evidence = self.data / "evidence"
        self.runs = self.data / "runs"
        self.settings_file = self.data / "settings.json"
        self.input = self.workspace / "input"
        self.output = self.workspace / "output"
        self.logs = self.root / "logs"

    def folders(self):
        return [self.data, self.templates, self.rules, self.groups, self.locks, self.scripts, self.evidence,
                self.runs, self.input, self.output, self.output / "scripts", self.logs]


paths = Paths(Path(__file__).resolve().parent.parent)


def use_root(root):
    """Point the tool at a different project root (used by tests)."""
    global paths
    paths = Paths(root)
    ensure_folders()


def ensure_folders():
    for folder in paths.folders():
        folder.mkdir(parents=True, exist_ok=True)
    migrate_legacy()


def now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def stamp():
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


def current_user():
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def current_host():
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def load_json(path, default):
    path = Path(path)
    if not path.exists():
        return copy.deepcopy(default)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    """Write to a temp file first so a crash never leaves a half-written data file."""
    path = Path(path)
    tmp = path.with_name(f"{path.name}.{secrets.token_hex(3)}.tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def read_text(path):
    """Read a text export whose encoding is not guaranteed (SolarWinds output)."""
    raw = Path(path).read_bytes()
    for enc in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# ---------------------------------------------------------------- team settings

# Where the reason/evidence text goes in the checklist for each result (team guidance).
DEFAULT_PLACEMENT = {"not_a_finding": "comments", "not_applicable": "comments", "open": "finding_details",
                     "not_reviewed": "comments"}
# Interface-description keywords that mark port roles (comma-separated alternatives).
DEFAULT_PORT_ROLES = {"uplink": "UPLINK", "downlink": "DOWNLINK", "access": "ACCESS, UNTRUSTED"}
DEFAULT_SETTINGS = {"output_format": "ckl", "manual_controls": [], "device_overrides": {}, "known_devices": {},
                    "text_placement": DEFAULT_PLACEMENT, "port_roles": DEFAULT_PORT_ROLES}


def load_settings():
    s = {**copy.deepcopy(DEFAULT_SETTINGS), **load_json(paths.settings_file, {})}
    s["text_placement"] = {**DEFAULT_PLACEMENT, **(s.get("text_placement") or {})}
    s["port_roles"] = {**DEFAULT_PORT_ROLES, **(s.get("port_roles") or {})}
    return s


def update_settings(change):
    """Re-read, apply change(settings), write - so a teammate's other edits are kept."""
    s = load_settings()
    change(s)
    save_json(paths.settings_file, s)
    return s


def set_setting(key, value):
    return update_settings(lambda s: s.__setitem__(key, value))


def set_manual(key, on):
    def change(s):
        manual = set(s["manual_controls"])
        manual.add(key) if on else manual.discard(key)
        s["manual_controls"] = sorted(manual)
    update_settings(change)


def set_override(host, group_id):
    def change(s):
        if group_id:
            s["device_overrides"][host.upper()] = group_id
        else:
            s["device_overrides"].pop(host.upper(), None)
    update_settings(change)


def add_known_devices(mapping):
    update_settings(lambda s: s["known_devices"].update({h.upper(): ip for h, ip in mapping.items()}))


def forget_device(host):
    def change(s):
        s["known_devices"].pop(host.upper(), None)
        s["device_overrides"].pop(host.upper(), None)
    update_settings(change)


# ---------------------------------------------------------------- records (rules, groups)

def _save_record(path, record, check):
    disk = load_json(path, None)
    if check and disk and disk.get("_rev", 0) != record.get("_rev", 0):
        raise ConflictError(disk)
    record["_rev"] = (disk.get("_rev", 0) if disk else 0) + 1
    record["saved_by"], record["saved_at"] = current_user(), now()
    save_json(path, record)
    return record


def _modify_record(path, change):
    disk = load_json(path, None)
    if disk is None:
        return None
    change(disk)
    return _save_record(path, disk, check=False)


def rule_path(rule_id):
    return paths.rules / f"{rule_id}.json"


def group_path(group_id):
    return paths.groups / f"{group_id}.json"


def load_rules():
    rules = [load_json(p, None) for p in sorted(paths.rules.glob("*.json"))]
    return {"rules": [r for r in rules if r], "manual_controls": load_settings()["manual_controls"]}


def new_rule_id():
    while True:
        rid = "R-" + secrets.token_hex(3).upper()
        if not rule_path(rid).exists():
            return rid


def save_rule(rule, check=True):
    return _save_record(rule_path(rule["id"]), rule, check)


def modify_rule(rule_id, change):
    return _modify_record(rule_path(rule_id), change)


def delete_rule(rule_id):
    rule_path(rule_id).unlink(missing_ok=True)


def mark_rule_reviewed(rule_id, check_hash, release, note="Reviewed after STIG update - still valid"):
    def change(r):
        r["check_hash"] = check_hash
        r.setdefault("review_log", []).append({"at": now(), "by": current_user(), "release": release, "note": note})
    return modify_rule(rule_id, change)


RULES_EXPORT_FORMAT = "stigtool-rules"
# Fields that identify people or only make sense on this machine; never exported.
PERSONAL_FIELDS = ("created_by", "saved_by", "updated_by", "_rev", "history", "review_log")


def clean_rule(rule):
    """A copy of a rule without author names, edit history or local revision counters."""
    out = {k: copy.deepcopy(v) for k, v in rule.items() if k not in PERSONAL_FIELDS}
    for t in out.get("tests", []):
        t.pop("saved_by", None)
    return out


def bundled_rules_path():
    """The rules file shipped with the program (rules/stigtool_rules.json next to main.py)."""
    return paths.root / "rules" / "stigtool_rules.json"


def export_rules(path, rules=None):
    """Write every rule (cleaned) plus the manual-only list to one JSON file. Returns the rule count."""
    db = load_rules()
    chosen = rules if rules is not None else db["rules"]
    data = {"format": RULES_EXPORT_FORMAT, "version": 1, "exported_at": now(),
            "manual_controls": sorted(db.get("manual_controls", [])),
            "rules": [clean_rule(r) for r in sorted(chosen, key=lambda r: (r["stig_id"], r["vuln_id"], r["id"]))]}
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    # One rule per line: still valid JSON, diff-friendly, and safe to copy / paste or split into parts.
    head = {k: v for k, v in data.items() if k != "rules"}
    lines = [json.dumps(r, ensure_ascii=True, separators=(",", ":")) for r in data["rules"]]
    text = json.dumps(head, ensure_ascii=True, separators=(",", ":"))[:-1] + ',"rules":[\n' + ",\n".join(lines) + "\n]}\n"
    json.loads(text)  # never write a file that would not load back
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return len(data["rules"])


def import_rules(path):
    """Add rules from an export file. Rules whose ID already exists here are left alone.

    Returns {"added", "skipped", "manual_added"}.
    """
    data = load_json(path, None)
    if not isinstance(data, dict) or data.get("format") != RULES_EXPORT_FORMAT:
        raise ValueError(f"{Path(path).name} is not a STIGTOOL rules export")
    report = {"added": 0, "skipped": 0, "manual_added": 0}
    for rule in data.get("rules", []):
        if not rule.get("id") or rule_path(rule["id"]).exists():
            report["skipped"] += 1
            continue
        rule = clean_rule(rule)
        rule.setdefault("history", [])
        rule["imported_at"] = now()
        save_rule(rule, check=False)
        report["added"] += 1
    incoming = set(data.get("manual_controls", []))

    def change(s):
        before = set(s["manual_controls"])
        report["manual_added"] = len(incoming - before)
        s["manual_controls"] = sorted(before | incoming)
    update_settings(change)
    return report


def load_groups():
    groups = [load_json(p, None) for p in sorted(paths.groups.glob("*.json"))]
    s = load_settings()
    return {"groups": [g for g in groups if g], "device_overrides": s["device_overrides"],
            "known_devices": s["known_devices"]}


def save_group(group, check=True):
    return _save_record(group_path(group["id"]), group, check)


def modify_group(group_id, change):
    return _modify_record(group_path(group_id), change)


def delete_group(group_id):
    group_path(group_id).unlink(missing_ok=True)

    def change(s):
        s["device_overrides"] = {h: g for h, g in s["device_overrides"].items() if g != group_id}
    update_settings(change)


# ---------------------------------------------------------------- edit locks

def _lock_path(kind, record_id):
    return paths.locks / f"{kind}_{record_id}.lock"


def lock_holder(kind, record_id):
    """Who else is editing this record, or None. Locks older than LOCK_HOURS are ignored."""
    lock = load_json(_lock_path(kind, record_id), None)
    if not lock:
        return None
    if lock.get("user") == current_user() and lock.get("host") == current_host():
        return None
    try:
        age = datetime.datetime.now() - datetime.datetime.fromisoformat(lock["since"])
        if age.total_seconds() > LOCK_HOURS * 3600:
            return None
    except (KeyError, ValueError):
        return None
    return lock


def acquire_lock(kind, record_id, force=False):
    """Returns the other holder (and does nothing) if someone else has it, else takes the lock."""
    holder = lock_holder(kind, record_id)
    if holder and not force:
        return holder
    save_json(_lock_path(kind, record_id), {"user": current_user(), "host": current_host(), "since": now()})
    return None


def release_lock(kind, record_id):
    path = _lock_path(kind, record_id)
    lock = load_json(path, None)
    if lock and lock.get("user") == current_user() and lock.get("host") == current_host():
        path.unlink(missing_ok=True)


# ---------------------------------------------------------------- checklist templates

def _upgrade(cat):
    """Fill in fields added after a catalog was first imported."""
    for s in cat["stigs"]:
        s.setdefault("short", checklist.short_name(s.get("title"), s["stig_id"]))
    if "viewer" not in cat:
        try:
            cat["viewer"] = checklist.viewer_of(template_path(cat), cat["format"])
        except OSError:
            cat["viewer"] = checklist.FORMAT_LABELS[cat["format"]]
    return cat


_catalog_cache = {}


def list_catalogs():
    """All imported templates, oldest import first. Cached by file time (catalogs never change)."""
    cats = []
    for p in paths.templates.glob("*.json"):
        key = (str(p), p.stat().st_mtime)
        if key not in _catalog_cache:
            cat = load_json(p, None)
            _catalog_cache[key] = _upgrade(cat) if cat else None
        if _catalog_cache[key]:
            cats.append(_catalog_cache[key])
    return sorted(cats, key=lambda c: c["imported_at"])


def _key(cat, stig):
    return checklist.release_key(stig.get("version"), stig.get("release_info")), cat["imported_at"]


def releases_for(stig_id):
    """[(catalog, stig)] for every imported file containing this STIG, oldest release first."""
    found = [(cat, s) for cat in list_catalogs() for s in cat["stigs"] if s["stig_id"] == stig_id]
    return sorted(found, key=lambda cs: _key(*cs))


def control_index():
    """The newest release of each STIG (any format), keyed by stig_id.

    {stig_id: {"family", "short", "title", "release_info", "release", "controls": {vuln_id: control},
               "order", "formats": {fmt: release label of newest file in that format}}}
    """
    index, fmt_keys = {}, {}
    for cat in list_catalogs():
        for stig in cat["stigs"]:
            sid, key = stig["stig_id"], _key(cat, stig)
            label = checklist.release_label(stig.get("version"), stig.get("release_info"))
            entry = index.get(sid)
            if entry is None or key >= entry["_key"]:
                index[sid] = {
                    "_key": key,
                    "family": stig["family"], "short": stig["short"], "title": stig["title"],
                    "release_info": stig["release_info"], "release": label, "version": stig.get("version"),
                    "template_id": cat["id"],
                    "controls": {c["vuln_id"]: c for c in stig["controls"]},
                    "order": [c["vuln_id"] for c in stig["controls"]],
                    "formats": entry["formats"] if entry else {},
                }
            fk = (sid, cat["format"])
            if fk not in fmt_keys or key >= fmt_keys[fk]:
                fmt_keys[fk] = key
                index[sid]["formats"][cat["format"]] = label
    return dict(sorted(index.items(), key=lambda kv: kv[1]["short"].lower()))


def templates_for(stig_id):
    """Newest-release template of each format (ckl / cklb) that contains this STIG."""
    found = {}
    for cat, _ in releases_for(stig_id):
        found[cat["format"]] = cat
    return found


def template_path(cat):
    return paths.templates / cat["file"]


def import_template(src, rules_db=None):
    """Copy a CKL/CKLB into data/templates (read-only) and build its control catalog.

    Returns (catalog or None, report lines). A file identical to one already imported is skipped.
    """
    src = Path(src)
    parsed = checklist.read_checklist(src)
    digest = sha256_file(src)
    label = checklist.FORMAT_LABELS[parsed["format"]]
    for cat in list_catalogs():
        if cat["sha256"] == digest:
            return None, [f"{src.name}: already imported on {cat['imported_at'][:10]} - skipped."]

    before = control_index()
    families = "-".join(s["family"] for s in parsed["stigs"]) or "CHECKLIST"
    tid = f"{families}_{parsed['format']}_{stamp()}_{secrets.token_hex(2)}"
    dest_name = f"{tid}{src.suffix.lower()}"
    dest = paths.templates / dest_name
    shutil.copy2(src, dest)
    os.chmod(dest, stat.S_IREAD)  # source templates are never edited
    catalog = {
        "id": tid, "file": dest_name, "source_name": src.name, "format": parsed["format"],
        "viewer": parsed["viewer"], "sha256": digest, "imported_at": now(), "imported_by": current_user(),
        "stigs": parsed["stigs"],
    }
    save_json(paths.templates / f"{tid}.json", catalog)

    rules = (rules_db or load_rules())["rules"]
    report = []
    for stig in parsed["stigs"]:
        rel = checklist.release_label(stig.get("version"), stig.get("release_info"))
        head = f"{stig['short']} {rel} - {label} ({parsed['viewer']})"
        old = before.get(stig["stig_id"])
        new_key = checklist.release_key(stig.get("version"), stig.get("release_info"))
        if not old:
            report.append(f"{head}\n   NEW STIG: {len(stig['controls'])} controls added to the work queue.")
            continue
        old_key = checklist.release_key(old.get("version"), old.get("release_info"))
        if new_key < old_key:
            report.append(f"{head}\n   OLDER than the current {old['release']} - kept for history only.")
            continue
        if new_key == old_key:
            report.append(f"{head}\n   Same release as already imported (now available in this format too).")
            continue
        diffs = checklist.compare_controls(list(old["controls"].values()), stig["controls"])
        changed_checks = {d["vuln_id"] for d in diffs if d["kind"] == "changed" and "check" in d["fields"]}
        affected = [r for r in rules if r["stig_id"] == stig["stig_id"] and r.get("state") == "active"
                    and (r["vuln_id"] in changed_checks
                         or r["vuln_id"] in {d["vuln_id"] for d in diffs if d["kind"] == "removed"})]
        counts = {k: sum(1 for d in diffs if d["kind"] == k) for k in ("added", "removed", "changed")}
        report.append(f"{head}\n   NEW RELEASE (was {old['release']}): {counts['added']} added, "
                      f"{counts['removed']} removed, {counts['changed']} changed."
                      + (f"\n   {len(affected)} active rule(s) need review: "
                         + ", ".join(f"{r['vuln_id']} ({r['id']})" for r in affected) if affected
                         else "\n   No active rules are affected.")
                      + "\n   Use 'Compare releases' on the Checklists tab to see the changes.")
    return catalog, report


def remove_template(cat):
    path = template_path(cat)
    if path.exists():
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        path.unlink()
    (paths.templates / f"{cat['id']}.json").unlink(missing_ok=True)


def find_control_version(stig_id, vuln_id, check_hash):
    """(release label, control) of the release whose check text has this fingerprint, newest first."""
    for cat, stig in reversed(releases_for(stig_id)):
        for c in stig["controls"]:
            if c["vuln_id"] == vuln_id and c["check_hash"] == check_hash:
                return checklist.release_label(stig.get("version"), stig.get("release_info")), c
    return None, None


# ---------------------------------------------------------------- runs and scripts

def run_path(run_id):
    return paths.runs / f"{run_id}.json"


def save_run(run):
    run["saved_by"], run["saved_at"] = current_user(), now()
    save_json(run_path(run["id"]), run)
    return run_path(run["id"]).stat().st_mtime


def list_runs():
    return sorted(paths.runs.glob("*.json"), reverse=True)


def load_run(path):
    return load_json(path, None)


def archive_evidence(src):
    """Keep an untouched copy of the imported SolarWinds file, original name preserved."""
    src = Path(src)
    folder = paths.evidence / f"{stamp()}_{secrets.token_hex(2)}"
    folder.mkdir(parents=True, exist_ok=True)
    dest = folder / src.name
    shutil.copy2(src, dest)
    return dest


def save_script_record(record):
    save_json(paths.scripts / f"{record['script_id']}.json", record)


def load_script_record(script_id):
    if not script_id:
        return None
    return load_json(paths.scripts / f"{script_id}.json", None)


# ---------------------------------------------------------------- one-time upgrade of older data

def migrate_legacy():
    """Split the single rules.json / groups.json used by the first version into per-record files."""
    legacy_rules = paths.data / "rules.json"
    if legacy_rules.exists():
        db = load_json(legacy_rules, {})
        for r in db.get("rules", []):
            if not rule_path(r["id"]).exists():
                save_json(rule_path(r["id"]), r)
        manual = db.get("manual_controls", [])
        update_settings(lambda s: s.__setitem__("manual_controls", sorted(set(s["manual_controls"]) | set(manual))))
        legacy_rules.rename(legacy_rules.with_name(f"rules.json.migrated-{stamp()}"))
    legacy_groups = paths.data / "groups.json"
    if legacy_groups.exists():
        db = load_json(legacy_groups, {})
        for g in db.get("groups", []):
            if not group_path(g["id"]).exists():
                save_json(group_path(g["id"]), g)

        def change(s):
            s["device_overrides"].update({k.upper(): v for k, v in db.get("device_overrides", {}).items()})
            s["known_devices"].update({k.upper(): v for k, v in db.get("known_devices", {}).items()})
        update_settings(change)
        legacy_groups.rename(legacy_groups.with_name(f"groups.json.migrated-{stamp()}"))
