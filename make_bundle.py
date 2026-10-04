"""Pack the whole program into self-installing .py file(s) that can be moved by copy and paste.

    python make_bundle.py              -> transfer/STIGTOOL_install.py (one file)
    python make_bundle.py 60           -> several parts of at most ~60 KB each, for small clipboards

On the other computer: paste each part into a new .py file (e.g. in Notepad, save as
STIGTOOL_install_part1.py), then run each one with Python, in any order. When the last part has been
run, every program file is rebuilt and checked against its fingerprint. Rules, groups and imported
checklists (data/) are never included and never touched.
"""
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FILES = ["main.py", "make_bundle.py", "README.md", "src/assess.py", "src/checklist.py", "src/collect.py",
         "src/drafts.py", "src/gui.py", "src/harden.py", "src/rules.py", "src/store.py", "tests/test_core.py", "tests/test_drafts.py",
         "tests/platform_samples.py"]

INSTALLER = r'''"""STIGTOOL installer - part {part} of {parts} (bundle {bundle}).

HOW TO USE: save this text as a .py file and run it:   python <this file>
  - Run every part of the bundle ({parts} in total), in any order.
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
    files, manifest, current, buf = {{}}, {{}}, None, []
    for line in me.read_text(encoding="utf-8").splitlines():
        if line.startswith("#@ HAS "):
            manifest[line.split()[2]] = line.split()[3]
        elif line.startswith("#@ FILE "):
            # #@ FILE <path> SHA <hash> CHUNK <i> OF <n>
            f = line.split()
            current, buf = (f[2], f[4], int(f[6]), int(f[8])), []
        elif line.startswith("#@ END") and current:
            path, sha, i, n = current
            (stash / f"{bundle}_{{path.replace('/', '__')}}.{{i}}").write_text("\n".join(buf) + "\n", encoding="utf-8")
            files[path] = (sha, n)
            current = None
        elif current is not None and line.startswith("#|"):
            buf.append(line[2:])
    if not files:
        sys.exit("Nothing found to install - was the whole file pasted?")
    waiting, bad = 0, 0
    for path, (sha, n) in sorted(files.items()):
        pieces = [stash / f"{bundle}_{{path.replace('/', '__')}}.{{i}}" for i in range(1, n + 1)]
        if not all(p.exists() for p in pieces):
            have = sum(p.exists() for p in pieces)
            print(f"  waiting  {{path}}  ({{have}} of {{n}} pieces - run the other part(s))")
            waiting += 1
            continue
        text = norm("".join(p.read_text(encoding="utf-8") for p in pieces))
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != sha:
            print(f"  BROKEN   {{path}}  - the copy/paste changed it. Paste the part(s) holding it again.")
            bad += 1
            continue
        dest = target / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8", newline="\n")
        for p in pieces:
            p.unlink()
        print(f"  OK       {{path}}")
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
        print(f"{{bad}} file(s) failed the fingerprint check. Nothing is broken - paste those parts again and re-run.")
    elif missing:
        print("Not finished yet - still to come from the other part(s): " + ", ".join(missing))
    else:
        print(f"All {{len(manifest)}} files installed and verified in {{target}}")
        print(f"Start it with:   python \"{{target / 'main.py'}}\"")


main()

# ---------------------------------------------------------------- payload (do not edit below)
'''


def norm(text):
    return "\n".join(line.rstrip() for line in text.split("\n")).rstrip("\n") + "\n"


def build(max_kb=None):
    entries = []
    for rel in FILES:
        text = norm((ROOT / rel).read_text(encoding="utf-8"))
        if not text.isascii():
            sys.exit(f"{rel} contains non-ASCII characters - replace them so copy/paste is safe.")
        entries.append((rel, hashlib.sha256(text.encode("utf-8")).hexdigest(), text.rstrip("\n").split("\n")))
    bundle = hashlib.sha256("".join(e[1] for e in entries).encode()).hexdigest()[:8]
    budget = max_kb * 1024 if max_kb else float("inf")

    # Assign each file's lines to parts without exceeding the budget (files may span parts).
    parts, size = [[]], 0
    for rel, sha, lines in entries:
        start = 0
        while start < len(lines):
            end, chunk = start, 0
            while end < len(lines) and (size + chunk + len(lines[end]) + 3 <= budget or (size == 0 and end == start)):
                chunk += len(lines[end]) + 3
                end += 1
            if end == start:  # part full: start a new one
                parts.append([])
                size = 0
                continue
            parts[-1].append((rel, sha, lines[start:end]))
            size += chunk
            start = end
    counts = {}
    for part in parts:
        for rel, _, _ in part:
            counts[rel] = counts.get(rel, 0) + 1

    out_dir = ROOT / "transfer"
    out_dir.mkdir(exist_ok=True)
    for old in out_dir.glob("STIGTOOL_install*.py"):
        old.unlink()
    seen, written = {}, []
    for n, part in enumerate(parts, 1):
        body = [INSTALLER.format(part=n, parts=len(parts), bundle=bundle)]
        body += [f"#@ HAS {rel} {sha}" for rel, sha, _ in entries]
        for rel, sha, lines in part:
            seen[rel] = seen.get(rel, 0) + 1
            body.append(f"#@ FILE {rel} SHA {sha} CHUNK {seen[rel]} OF {counts[rel]}")
            body += [f"#|{line}" for line in lines]
            body.append("#@ END")
        name = "STIGTOOL_install.py" if len(parts) == 1 else f"STIGTOOL_install_part{n}_of_{len(parts)}.py"
        path = out_dir / name
        path.write_text("\n".join(body) + "\n", encoding="utf-8", newline="\n")
        written.append(path)
    print(f"Bundle {bundle}: {len(FILES)} files in {len(written)} part(s):")
    for p in written:
        print(f"  {p}  ({p.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    build(int(sys.argv[1]) if len(sys.argv) > 1 else None)
