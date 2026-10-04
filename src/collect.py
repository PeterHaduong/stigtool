"""SolarWinds side: build the show-command script, and split SolarWinds output back into
per-device, per-command evidence.

Expected SolarWinds "Execute Command Script" output (see _resources/test_output1.txt):

    ____________________________________________________________
    HOSTNAME (IP):
    <device output, or "ERROR: ..." if the connection failed>
    ____________________________________________________________

The generated script puts "! sources:" and "! CMD:" marker lines before every command, and
these come back in the output, so each block of output can be tied to its command safely.
If the markers are ever stripped, the echoed command line itself is used instead.
"""
import datetime
import hashlib
import re

from rules import classify_output

SEPARATOR_RE = re.compile(r"^\s*_{10,}\s*$")
HEADER_RE = re.compile(r"^(?P<host>[^\s()]+)\s*\((?P<ip>[^()]*)\)\s*:\s*$")
PROMPT_RE = re.compile(r"^[\w.\-]+(\([\w\-]+\))?[#>]\s?")


def build_script(command_sources, groups):
    """command_sources: {command: set of source labels like 'NDM V-220524'}.

    Returns (script_text, script_id). The id is a fingerprint of the command list, so the
    same set of commands always gets the same id.
    """
    commands = sorted(command_sources)
    script_id = hashlib.sha256("\n".join(commands).encode("utf-8")).hexdigest()[:12]
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    out = [
        "! STIGTOOL collection script",
        f"! script_id: {script_id}",
        f"! generated_at_utc: {now}",
        f"! groups: {', '.join(groups)}",
        "! reviewer_notice: Evidence collection only; no automated compliance determination.",
        "",
    ]
    for cmd in commands:
        out.append(f"! sources: {','.join(sorted(command_sources[cmd]))}")
        out.append(f"! CMD: {cmd}")
        out.append(cmd)
        out.append("")
    return "\n".join(out), script_id


def _strip_prompt(line):
    return PROMPT_RE.sub("", line, count=1).strip()


def _trim(lines):
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


def _parse_device(host, body, expected):
    device = {"host": host["host"], "ip": host["ip"], "status": "ok", "error": "",
              "script_id": "", "outputs": {}, "warnings": []}
    has_markers = any(l.startswith("! CMD:") for l in body)
    errors = [l.strip() for l in body if l.strip().upper().startswith("ERROR")]
    if errors and not has_markers:
        device["status"] = "error"
        device["error"] = errors[0]
        return device

    prompt_only = re.compile(rf"^{re.escape(host['host'])}(\([\w\-]+\))?[#>]\s*$", re.I)
    blocks, current, buf = [], None, []

    def flush():
        if current is not None:
            blocks.append((current, list(buf)))

    known = set(expected or [])
    for raw in body:
        line = raw.rstrip("\r")
        if line.startswith("! script_id:"):
            device["script_id"] = line.split(":", 1)[1].strip()
            continue
        if has_markers:
            if line.startswith("! CMD:"):
                flush()
                current, buf = line[6:].strip(), []
                continue
            if line.startswith("! sources:"):
                flush()
                current, buf = None, []
                continue
        elif _strip_prompt(line) in known and line.strip():
            flush()
            current, buf = _strip_prompt(line), []
            continue
        if current is None:
            continue
        if prompt_only.match(line.strip()):
            continue
        buf.append(line)
    flush()

    for cmd, lines in blocks:
        lines = _trim(lines)
        if lines and _strip_prompt(lines[0]) == cmd:  # device echo of the command
            lines = _trim(lines[1:])
        text = "\n".join(lines)
        if cmd in device["outputs"]:
            device["warnings"].append(f"'{cmd}' appears more than once; last copy used")
        device["outputs"][cmd] = {"status": classify_output(text), "text": text}
    if not device["outputs"]:
        device["status"] = "error"
        device["error"] = "No command output could be identified"
    return device


def parse_output(text, expected_commands=None):
    """Split a SolarWinds output file into devices.

    Returns {"devices": [device], "warnings": [str], "job_lines": [str]}
    device = {"host", "ip", "status": "ok"|"error", "error", "script_id",
              "outputs": {command: {"status": "ok"|"invalid", "text"}}, "warnings"}
    """
    chunks, chunk = [], []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if SEPARATOR_RE.match(line):
            chunks.append(chunk)
            chunk = []
        else:
            chunk.append(line)
    chunks.append(chunk)

    devices, warnings, job_lines, seen = [], [], [], {}
    for chunk in chunks:
        lines = list(chunk)
        while lines and not lines[0].strip():
            lines.pop(0)
        if not lines:
            continue
        m = HEADER_RE.match(lines[0].strip())
        if not m:
            job_lines += [l for l in lines if l.strip()]
            continue
        device = _parse_device(m.groupdict(), lines[1:], expected_commands)
        key = device["host"].lower()
        if key in seen:
            warnings.append(f"{device['host']} appears more than once; last copy used")
            devices[seen[key]] = device
        else:
            seen[key] = len(devices)
            devices.append(device)
    if not devices:
        warnings.append("No device sections found. Is this a SolarWinds 'Execute Command Script' output file?")
    return {"devices": devices, "warnings": warnings, "job_lines": job_lines}
