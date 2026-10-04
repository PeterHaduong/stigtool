"""Tkinter user interface. Tabs follow the workflow left to right:

  1 Checklists  - import blank CKL / CKLB templates
  2 Work Queue  - build and test a rule for each control (or mark it manual)
  3 Groups      - device groups, which STIGs they get, which rule version per control
  4 Collect     - generate the SolarWinds show-command script
  5 Assess      - import SolarWinds output, review results, write checklist packages
"""
import copy
import difflib
import fnmatch
import json
import os
import re
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from tkinter.scrolledtext import ScrolledText

import assess
import checklist
import collect
import drafts
import harden
import rules as engine
import store
from checklist import LABEL_TO_STATUS, STATUS_LABELS, STATUSES

MONO = ("Consolas", 10)
HIGHLIGHT = {"match": "#b9f0b4", "problem": "#ffb3b3", "section": "#cfe2ff", "skipped": "#e4e4e4"}
STATUS_ROW = {"open": "#ffd6d6", "not_a_finding": "#d9f7d6", "not_applicable": "#e8e8e8",
              "not_reviewed": "#fff0c2", "manual": "#f4f4f4", "changed": "#e5d9ff", "expected": "#ffe5c7"}
STATE_ROW = {"Needs rule": "#fff0c2", "Draft": "#dde9ff", "Active": "#d9f7d6",
             "STIG changed - review": "#ffd6d6", "Manual only": "#ececec"}
RESULT_COLOR = {"not_a_finding": "#1b7a1b", "open": "#b00020", "not_applicable": "#555555",
                "not_reviewed": "#9a6a00"}
RULE_STATES = ["draft", "active", "retired"]
SHORT = {"not_a_finding": "NaF", "open": "Open", "not_applicable": "N/A", "not_reviewed": "NR"}
FORMAT_SHORT = {"ckl": ".ckl (Viewer 2.x)", "cklb": ".cklb (Viewer 3)"}
OUTCOMES = {"Open": "open", "Not Applicable": "not_applicable", "Not a Finding": "not_a_finding"}


# ---------------------------------------------------------------- small helpers

def text_get(widget):
    return widget.get("1.0", "end-1c")


def text_set(widget, value, readonly=False):
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", value or "")
    if readonly:
        widget.configure(state="disabled")


def help_label(parent, text):
    lbl = tk.Label(parent, text=text, justify="left", anchor="w", wraplength=1150,
                   bg="#fffbe6", fg="#333333", padx=8, pady=6, relief="groove")
    lbl.pack(fill="x", padx=6, pady=(6, 4))
    return lbl


def make_tree(parent, columns, height=10, selectmode="browse"):
    """columns: [(id, heading, width)]. Returns (frame, tree)."""
    frame = ttk.Frame(parent)
    tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings",
                        height=height, selectmode=selectmode)
    for cid, heading, width in columns:
        tree.heading(cid, text=heading)
        tree.column(cid, width=width, stretch=width >= 200, anchor="w")
    sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=sb.set)
    tree.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    return frame, tree


def color_tags(tree, mapping):
    for tag, color in mapping.items():
        tree.tag_configure(tag, background=color)


def ask_choice(parent, title, prompt, choices, initial=None):
    """Small modal dropdown dialog. Returns the chosen string or None."""
    dlg = tk.Toplevel(parent)
    dlg.title(title)
    dlg.transient(parent)
    dlg.resizable(False, False)
    ttk.Label(dlg, text=prompt, wraplength=460, justify="left").pack(padx=12, pady=(12, 6), anchor="w")
    var = tk.StringVar(value=initial if initial in choices else (choices[0] if choices else ""))
    box = ttk.Combobox(dlg, textvariable=var, values=choices, state="readonly", width=70)
    box.pack(padx=12, fill="x")
    result = {}

    def ok(_=None):
        result["value"] = var.get()
        dlg.destroy()

    row = ttk.Frame(dlg)
    row.pack(pady=10)
    ttk.Button(row, text="OK", command=ok).pack(side="left", padx=4)
    ttk.Button(row, text="Cancel", command=dlg.destroy).pack(side="left", padx=4)
    dlg.bind("<Return>", ok)
    dlg.bind("<Escape>", lambda e: dlg.destroy())
    dlg.grab_set()
    box.focus_set()
    parent.wait_window(dlg)
    return result.get("value")


def maximize(window, fallback):
    """Start maximised so the layout survives Windows display scaling."""
    window.geometry(fallback)
    try:
        window.state("zoomed")
    except tk.TclError:
        pass


def open_folder(path):
    try:
        os.startfile(path)  # Windows
    except Exception:
        pass


# ---------------------------------------------------------------- application

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("STIG Group Assessment Tool")
        maximize(self, "1320x840")
        self.minsize(1000, 650)
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Treeview", rowheight=22)
        style.configure("Big.TLabel", font=("Segoe UI", 12, "bold"))

        self.run, self.run_mtime = None, None
        self.open_editors = set()
        self.status = tk.Label(self, anchor="w", bg="#eef2f7", fg="#333", padx=8)
        self.status.pack(side="bottom", fill="x")
        self.load_data()

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True)
        self.tabs = [ChecklistsTab(self.nb, self), QueueTab(self.nb, self), GroupsTab(self.nb, self),
                     ScriptTab(self.nb, self), AssessTab(self.nb, self), HardenTab(self.nb, self)]
        for tab, name in zip(self.tabs, ["1. Checklists", "2. Rule Work Queue", "3. Device Groups",
                                         "4. Collection Script", "5. Import & Review", "6. Hardening Script"]):
            self.nb.add(tab, text=f"  {name}  ")
        # Teammates may have changed things: re-read the shared data whenever a tab is opened.
        self.nb.bind("<<NotebookTabChanged>>", lambda e: self.reload())
        self.bind("<F5>", lambda e: self.reload())
        self.protocol("WM_DELETE_WINDOW", self.quit_app)
        runs = store.list_runs()
        if runs:
            self.set_run(store.load_run(runs[0]), runs[0].stat().st_mtime)
        self.refresh_all()

    # -- shared data
    def load_data(self):
        self.settings = store.load_settings()
        engine.set_port_roles(self.settings["port_roles"])
        self.rules_db = store.load_rules()
        self.groups_db = store.load_groups()
        self.index = store.control_index()
        fmt = checklist.FORMAT_LABELS[self.settings["output_format"]]
        self.status.configure(text=f"Shared data: {store.paths.data}     Signed in as {store.current_user()} on "
                                   f"{store.current_host()}     Checklist output: {fmt}     F5 = refresh")

    def reload(self):
        """Re-read rules, groups, settings and templates (picks up teammates' changes)."""
        self.load_data()
        tab = self.tabs[self.nb.index("current")] if hasattr(self, "nb") else None
        if tab:
            tab.refresh()

    def refresh_all(self):
        for tab in self.tabs:
            tab.refresh()

    @property
    def output_format(self):
        return self.settings["output_format"]

    def formats_text(self, stig_id):
        """'.ckl (Viewer 2.x) + .cklb (Viewer 3)' - which checklist files exist for this STIG."""
        s = self.index.get(stig_id)
        if not s:
            return "not imported"
        return " + ".join(FORMAT_SHORT[f] for f in sorted(s["formats"]))

    def stig_label(self, stig_id):
        s = self.index.get(stig_id)
        return f"{s['short']}  {s['release']}  [{self.formats_text(stig_id)}]" if s else f"{stig_id} (not imported)"

    def short(self, stig_id):
        s = self.index.get(stig_id)
        return s["short"] if s else stig_id

    def rule_by_id(self, rule_id):
        return next((r for r in self.rules_db["rules"] if r["id"] == rule_id), None)

    # -- assessment run (one file per run, shared)
    def set_run(self, run, mtime=None):
        self.run, self.run_mtime = run, mtime

    def save_run(self):
        """Save the current run, unless a teammate saved it in the meantime and we should take theirs."""
        if not self.run:
            return
        path = store.run_path(self.run["id"])
        if self.run_mtime and path.exists() and abs(path.stat().st_mtime - self.run_mtime) > 0.01:
            other = store.load_run(path) or {}
            pick = ask_choice(self, "Someone else changed this run",
                              f"{other.get('saved_by', 'Someone')} saved this assessment run at "
                              f"{other.get('saved_at', '?')} while you had it open.",
                              ["Keep my version (overwrite theirs)", "Load their version (lose my last change)"])
            if pick and pick.startswith("Load"):
                self.set_run(other, path.stat().st_mtime)
                self.refresh_all()
                return
        self.run_mtime = store.save_run(self.run)

    def quit_app(self):
        for editor in list(self.open_editors):
            editor.release()
        self.destroy()


# ---------------------------------------------------------------- 1. checklists

def word_diff(widget, old, new):
    """Write old -> new into a Text widget: removed words red + struck out, added words green."""
    a, b = re.split(r"(\s+)", old or ""), re.split(r"(\s+)", new or "")
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if op == "equal":
            widget.insert("end", "".join(a[i1:i2]))
            continue
        if i2 > i1:
            widget.insert("end", "".join(a[i1:i2]), "del")
        if j2 > j1:
            widget.insert("end", "".join(b[j1:j2]), "ins")


def diff_text_widget(parent, height=20):
    t = ScrolledText(parent, wrap="word", font=("Segoe UI", 9), height=height)
    t.tag_configure("del", background="#ffc9c9", overstrike=True)
    t.tag_configure("ins", background="#b9f0b4")
    t.tag_configure("head", font=("Segoe UI", 10, "bold"), spacing1=8)
    return t


def show_control_diff(widget, old, new):
    """Fill a diff widget with every compared field of two versions of one control."""
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    if old is None or new is None:
        c = new or old
        widget.insert("end", ("ADDED in the newer release" if old is None else "REMOVED in the newer release")
                      + "\n", "head")
        widget.insert("end", f"{c['title']}\n\nCHECK:\n{c['check']}\n\nFIX:\n{c['fix']}")
    else:
        for field, name in checklist.COMPARE_FIELDS.items():
            same = (checklist.text_hash(old.get(field)) == checklist.text_hash(new.get(field))
                    if field in ("check", "fix") else (old.get(field) or "") == (new.get(field) or ""))
            widget.insert("end", f"{name.upper()}{'  (unchanged)' if same else '  (CHANGED)'}\n", "head")
            if same and field in ("check", "fix"):
                widget.insert("end", "(same as before)\n")
            else:
                word_diff(widget, old.get(field) or "", new.get(field) or "")
                widget.insert("end", "\n")
    widget.configure(state="disabled")


class ChecklistsTab(ttk.Frame):
    COLUMNS = [("release", "Current release", 170), ("formats", "Imported as", 330), ("controls", "Controls", 70),
               ("auto", "Automated", 80), ("manual", "Manual", 65), ("todo", "Not built", 75),
               ("review", "Need review", 85), ("note", "Notes", 420)]

    def __init__(self, nb, app):
        super().__init__(nb)
        self.app = app
        help_label(self, "Step 1 - Import the blank checklist for each STIG. Each STIG is one row; click the arrow "
                         "to see every file imported for it (older releases, and STIG Viewer 2.x .ckl vs STIG "
                         "Viewer 3 .cklb). When DISA publishes a new quarterly release, import it here, then use "
                         "'Compare releases' to see exactly what changed and which rules need a look.")
        row = ttk.Frame(self)
        row.pack(fill="x", padx=6)
        ttk.Button(row, text="Import checklist file(s)...", command=self.do_import).pack(side="left")
        ttk.Button(row, text="Compare releases...", command=self.compare).pack(side="left", padx=6)
        ttk.Button(row, text="Remove selected file", command=self.do_remove).pack(side="left")
        ttk.Label(row, text="Team checklist output format:").pack(side="left", padx=(30, 4))
        self.fmt_var = tk.StringVar()
        box = ttk.Combobox(row, textvariable=self.fmt_var, state="readonly", width=26,
                           values=list(checklist.FORMAT_LABELS.values()))
        box.pack(side="left")
        box.bind("<<ComboboxSelected>>", lambda e: self.set_format())
        ttk.Button(row, text="Where reasons go...", command=lambda: PlacementDialog(self.app)).pack(side="left",
                                                                                                   padx=8)

        frame = ttk.Frame(self)
        frame.pack(fill="both", expand=True, padx=6, pady=6)
        self.tree = ttk.Treeview(frame, columns=[c[0] for c in self.COLUMNS], show="tree headings")
        self.tree.heading("#0", text="STIG")
        self.tree.column("#0", width=330, stretch=False)
        for cid, heading, width in self.COLUMNS:
            self.tree.heading(cid, text=heading)
            self.tree.column(cid, width=width, stretch=cid == "note", anchor="w")
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.tag_configure("warn", background="#fff0c2")
        self.tree.tag_configure("file", foreground="#444")
        self.tree.bind("<Double-1>", lambda e: self.compare())

    def refresh(self):
        fmt = self.app.output_format
        self.fmt_var.set(checklist.FORMAT_LABELS[fmt])
        opened = {i for i in self.tree.get_children() if self.tree.item(i, "open")}
        keep = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        for stig_id, stig in self.app.index.items():
            counts = {}
            for vuln_id in stig["order"]:
                state = assess.control_state(self.app.rules_db, stig_id, stig["controls"][vuln_id])
                counts[state] = counts.get(state, 0) + 1
            formats = " | ".join(f"{checklist.FORMAT_LABELS[f]} {rel.split(' ')[0]}"
                                 for f, rel in sorted(stig["formats"].items()))
            notes = []
            if fmt not in stig["formats"]:
                notes.append(f"No {checklist.FORMAT_LABELS[fmt]} file - cannot write this checklist")
            elif stig["formats"][fmt] != stig["release"]:
                notes.append(f"Newest release only imported as the other format - import the "
                             f"{checklist.FORMAT_LABELS[fmt]} file")
            if counts.get("STIG changed - review"):
                notes.append(f"{counts['STIG changed - review']} rule(s) need review after a STIG update")
            pid = f"S|{stig_id}"
            self.tree.insert("", "end", iid=pid, text=stig["short"], open=pid in opened,
                             tags=("warn",) if notes else (),
                             values=(stig["release"], formats, len(stig["order"]), counts.get("Active", 0)
                                     + counts.get("STIG changed - review", 0), counts.get("Manual only", 0),
                                     counts.get("Needs rule", 0) + counts.get("Draft", 0),
                                     counts.get("STIG changed - review", 0), "; ".join(notes) or "OK"))
            current = {f: cat["id"] for f, cat in store.templates_for(stig_id).items()}
            for cat, s in reversed(store.releases_for(stig_id)):
                rel = checklist.release_label(s.get("version"), s.get("release_info"))
                mark = "CURRENT  " if current.get(cat["format"]) == cat["id"] else ""
                self.tree.insert(pid, "end", iid=f"C|{cat['id']}|{stig_id}", tags=("file",),
                                 text=checklist.FORMAT_LABELS[cat["format"]],
                                 values=(rel, cat.get("viewer", ""), len(s["controls"]), "", "", "", "",
                                         f"{mark}imported {cat['imported_at'][:16].replace('T', ' ')} by "
                                         f"{cat.get('imported_by', '?')} from {cat['source_name']}"))
        if not self.app.index:
            self.tree.insert("", "end", text="No checklists imported yet - click 'Import checklist file(s)'.")
        keep = [k for k in keep if self.tree.exists(k)]
        if keep:
            self.tree.selection_set(keep)

    def selected_stig(self):
        sel = self.tree.selection()
        if not sel or "|" not in sel[0]:
            return None
        return sel[0].split("|")[-1]

    def set_format(self):
        fmt = next(k for k, v in checklist.FORMAT_LABELS.items() if v == self.fmt_var.get())
        if fmt != self.app.output_format:
            store.set_setting("output_format", fmt)
            self.app.reload()

    def do_import(self):
        files = filedialog.askopenfilenames(title="Choose STIG checklist file(s)",
                                            filetypes=[("STIG checklists", "*.ckl *.cklb"), ("All files", "*.*")])
        report = []
        for f in files:
            try:
                _, lines = store.import_template(f, self.app.rules_db)
                report += lines
            except Exception as e:
                report.append(f"{os.path.basename(f)}: NOT imported - {e}")
        if report:
            self.app.reload()
            ImportReport(self, "\n\n".join(report))

    def do_remove(self):
        sel = self.tree.selection()
        if not sel or not sel[0].startswith("C|"):
            return messagebox.showinfo("Remove", "Expand a STIG and select the specific file to remove.")
        tid = sel[0].split("|")[1]
        cat = next((c for c in store.list_catalogs() if c["id"] == tid), None)
        if cat and messagebox.askyesno("Remove file", f"Remove {cat['source_name']} "
                                                      f"({checklist.FORMAT_LABELS[cat['format']]}) from the tool for "
                                                      "everyone? Rules are kept."):
            store.remove_template(cat)
            self.app.reload()

    def compare(self):
        stig_id = self.selected_stig()
        if not stig_id:
            return messagebox.showinfo("Compare releases", "Select a STIG first.")
        ReleaseCompareWindow(self.app, stig_id)


class PlacementDialog(tk.Toplevel):
    """Team setting: which checklist field holds the reason for each result."""

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Where reasons go in the checklist")
        self.transient(app)
        self.resizable(False, False)
        f = ttk.Frame(self, padding=12)
        f.pack()
        ttk.Label(f, text="For each result, which checklist field gets the reason (the rule's text, the evidence\n"
                          "found on the devices and the reviewer sign-off). Team setting - applies to everyone.",
                  justify="left").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        self.vars = {}
        current = app.settings["text_placement"]
        for r, status in enumerate(["not_a_finding", "not_applicable", "open", "not_reviewed"], 1):
            ttk.Label(f, text=STATUS_LABELS[status]).grid(row=r, column=0, sticky="w", pady=2)
            var = tk.StringVar(value=assess.FIELD_LABELS[current[status]])
            ttk.Combobox(f, textvariable=var, values=list(assess.FIELD_LABELS.values()), state="readonly",
                         width=18).grid(row=r, column=1, sticky="w", padx=8)
            self.vars[status] = var
        ttk.Label(f, text="The rule's extra comment and the reviewer's comment always go in Comments.",
                  foreground="#555").grid(row=6, column=0, columnspan=2, sticky="w", pady=(8, 0))
        b = ttk.Frame(f)
        b.grid(row=7, column=0, columnspan=2, pady=(10, 0))
        ttk.Button(b, text="Save", command=self.save).pack(side="left", padx=4)
        ttk.Button(b, text="Cancel", command=self.destroy).pack(side="left", padx=4)
        self.grab_set()
        app.wait_window(self)

    def save(self):
        to_key = {v: k for k, v in assess.FIELD_LABELS.items()}
        store.set_setting("text_placement", {s: to_key[v.get()] for s, v in self.vars.items()})
        self.app.reload()
        self.destroy()


class ImportReport(tk.Toplevel):
    def __init__(self, parent, text):
        super().__init__(parent)
        self.title("Import results")
        self.geometry("900x500")
        self.transient(parent)
        t = ScrolledText(self, wrap="word", font=("Segoe UI", 10))
        t.pack(fill="both", expand=True, padx=8, pady=8)
        text_set(t, text, readonly=True)
        ttk.Button(self, text="Close", command=self.destroy).pack(pady=(0, 8))


class ReleaseCompareWindow(tk.Toplevel):
    """Side-by-side view of what DISA changed between two releases of one STIG, and its effect on rules."""

    def __init__(self, app, stig_id):
        super().__init__(app)
        self.app, self.stig_id = app, stig_id
        self.title(f"Compare releases - {app.short(stig_id)}")
        maximize(self, "1300x800")
        releases = {}
        for cat, s in store.releases_for(stig_id):
            releases[checklist.release_label(s.get("version"), s.get("release_info"))] = s
        self.releases = releases
        labels = list(releases)

        top = ttk.Frame(self)
        top.pack(fill="x", padx=8, pady=8)
        ttk.Label(top, text=app.short(stig_id), style="Big.TLabel").pack(side="left")
        ttk.Label(top, text="   Compare").pack(side="left")
        self.old_var = tk.StringVar(value=labels[-2] if len(labels) > 1 else (labels[0] if labels else ""))
        self.new_var = tk.StringVar(value=labels[-1] if labels else "")
        for var, text in ((self.old_var, "with"), (self.new_var, "")):
            box = ttk.Combobox(top, textvariable=var, values=labels, state="readonly", width=24)
            box.pack(side="left", padx=4)
            box.bind("<<ComboboxSelected>>", lambda e: self.refresh())
            if text:
                ttk.Label(top, text=text).pack(side="left")
        self.only_rules = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Only changes that affect rules", variable=self.only_rules,
                        command=self.refresh).pack(side="left", padx=20)
        self.summary = ttk.Label(self, text="", foreground="#333")
        self.summary.pack(fill="x", padx=8)

        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=8, pady=8)
        left = ttk.Frame(paned)
        paned.add(left, weight=2)
        lf, self.tree = make_tree(left, [("vuln", "Vuln ID", 85), ("kind", "Change", 75),
                                         ("fields", "What changed", 170), ("rules", "Rules", 160),
                                         ("todo", "Rule status", 150)], height=25)
        lf.pack(fill="both", expand=True)
        color_tags(self.tree, {"review": "#ffd6d6", "ok": "#d9f7d6", "info": "#ffffff"})
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.show())
        btns = ttk.Frame(left)
        btns.pack(fill="x", pady=4)
        ttk.Button(btns, text="Open rule...", command=self.open_rule).pack(side="left")
        ttk.Button(btns, text="Rule still valid - mark reviewed", command=self.mark_reviewed).pack(side="left",
                                                                                                  padx=4)
        right = ttk.Frame(paned)
        paned.add(right, weight=3)
        ttk.Label(right, text="Red struck-out = removed by DISA, green = added.").pack(anchor="w")
        self.diff = diff_text_widget(right)
        self.diff.pack(fill="both", expand=True)
        self.diffs = {}
        if len(labels) < 2:
            self.summary.configure(text="Only one release of this STIG has been imported - import the newer "
                                        "release on the Checklists tab, then compare.")
        self.refresh()

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        old, new = self.releases.get(self.old_var.get()), self.releases.get(self.new_var.get())
        if not old or not new:
            return
        current = self.app.index[self.stig_id]
        is_current = self.new_var.get() == current["release"]
        diffs = checklist.compare_controls(old["controls"], new["controls"])
        self.diffs = {d["vuln_id"]: d for d in diffs}
        need = 0
        for d in diffs:
            rs = assess.rules_for_control(self.app.rules_db, self.stig_id, d["vuln_id"])
            new_hash = d["new"]["check_hash"] if d["new"] else None
            if not rs:
                todo, tag = "-", "info"
            elif d["kind"] == "removed":
                todo, tag = "Retire rule (control removed)", "review"
            elif not is_current:
                todo, tag = "(compare with current release)", "info"
            elif any(r.get("check_hash") != new_hash for r in rs if r.get("state") == "active"):
                todo, tag = "NEEDS REVIEW", "review"
            else:
                todo, tag = "Reviewed / unaffected", "ok"
            if tag == "review":
                need += 1
            if self.only_rules.get() and not rs:
                continue
            self.tree.insert("", "end", iid=d["vuln_id"], tags=(tag,),
                             values=(d["vuln_id"], d["kind"],
                                     ", ".join(checklist.COMPARE_FIELDS[f] for f in d["fields"]) or "-",
                                     ", ".join(f"{r['id']} ({r.get('state')})" for r in rs) or "-", todo))
        counts = {k: sum(1 for d in diffs if d["kind"] == k) for k in ("added", "removed", "changed")}
        self.summary.configure(text=f"{self.old_var.get()} -> {self.new_var.get()}:  {counts['added']} added, "
                                    f"{counts['removed']} removed, {counts['changed']} changed.   "
                                    f"Rules needing review: {need}.")
        self.show()

    def selected(self):
        sel = self.tree.selection()
        return self.diffs.get(sel[0]) if sel else None

    def show(self):
        d = self.selected()
        if d:
            show_control_diff(self.diff, d["old"], d["new"])
        else:
            text_set(self.diff, "Select a control on the left to see what changed.", readonly=True)

    def open_rule(self):
        d = self.selected()
        if not d or not d["new"]:
            return
        rs = assess.rules_for_control(self.app.rules_db, self.stig_id, d["vuln_id"])
        if not rs:
            return messagebox.showinfo("No rule", "This control has no rule.", parent=self)
        control = self.app.index[self.stig_id]["controls"].get(d["vuln_id"])
        if control:
            RuleEditor.open(self.app, self.stig_id, control, rs[0], self.after_change)

    def mark_reviewed(self):
        d = self.selected()
        current = self.app.index[self.stig_id]
        if not d or not d["new"] or self.new_var.get() != current["release"]:
            return messagebox.showinfo("Mark reviewed", "Select a changed control, comparing against the current "
                                                        f"release ({current['release']}).", parent=self)
        rs = [r for r in assess.rules_for_control(self.app.rules_db, self.stig_id, d["vuln_id"])
              if r.get("check_hash") != d["new"]["check_hash"]]
        if not rs:
            return messagebox.showinfo("Mark reviewed", "No rules need review for this control.", parent=self)
        if messagebox.askyesno("Mark reviewed", f"Confirm {', '.join(r['id'] for r in rs)} still check the right "
                                                f"thing after the {current['release']} change?", parent=self):
            for r in rs:
                store.mark_rule_reviewed(r["id"], d["new"]["check_hash"], current["release"])
            self.after_change()

    def after_change(self):
        self.app.reload()
        self.refresh()


# ---------------------------------------------------------------- 2. work queue

class QueueTab(ttk.Frame):
    STATES = ["All", "Needs rule", "Draft", "Active", "STIG changed - review", "Manual only"]

    def __init__(self, nb, app):
        super().__init__(nb)
        self.app = app
        help_label(self, "Step 2 - Every control needs a decision. Select a control, read its check text, then click "
                         "'New rule' to describe which show command to run and what text proves compliance. "
                         "Controls that cannot be checked from show output can be marked 'Manual only'. A control "
                         "can have several rule versions (for example one for access switches and one for cores); "
                         "each group picks which version it uses on the Device Groups tab. A rule someone else "
                         "has open is locked so two people do not overwrite each other.")
        filt = ttk.Frame(self)
        filt.pack(fill="x", padx=6)
        ttk.Label(filt, text="STIG:").pack(side="left")
        self.stig_var = tk.StringVar(value="All")
        self.stig_box = ttk.Combobox(filt, textvariable=self.stig_var, state="readonly", width=50)
        self.stig_box.pack(side="left", padx=4)
        ttk.Label(filt, text="State:").pack(side="left", padx=(10, 0))
        self.state_var = tk.StringVar(value="All")
        ttk.Combobox(filt, textvariable=self.state_var, values=self.STATES, state="readonly",
                     width=22).pack(side="left", padx=4)
        ttk.Label(filt, text="Search:").pack(side="left", padx=(10, 0))
        self.search_var = tk.StringVar()
        ttk.Entry(filt, textvariable=self.search_var, width=28).pack(side="left", padx=4)
        for var in (self.stig_var, self.state_var, self.search_var):
            var.trace_add("write", lambda *a: self.refresh())
        ttk.Button(filt, text="Create starter drafts...", command=self.starter_drafts).pack(side="right")
        self.progress = ttk.Label(self, text="", foreground="#333", wraplength=1500, justify="left")
        self.progress.pack(fill="x", padx=8, pady=(4, 0))

        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=6, pady=6)
        left, self.tree = make_tree(paned, [("stig", "STIG", 190), ("fmt", "Imported as", 150),
                                            ("vuln", "Vuln ID", 80), ("ver", "Rule Ver", 120),
                                            ("sev", "Severity", 65), ("state", "State", 150),
                                            ("rules", "Rules", 45), ("title", "Title", 400)], height=24)
        color_tags(self.tree, {k.replace(" ", "_"): v for k, v in STATE_ROW.items()})
        paned.add(left, weight=3)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.show_control())
        self.tree.bind("<Double-1>", lambda e: self.edit_rule(default=True))

        right = ttk.Frame(paned)
        paned.add(right, weight=2)
        ttk.Label(right, text="STIG check and fix text", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.details = ScrolledText(right, height=16, width=50, wrap="word", font=("Segoe UI", 9))
        self.details.pack(fill="both", expand=True)
        ttk.Label(right, text="Rules for this control", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(8, 0))
        rf, self.rule_tree = make_tree(right, [("id", "Rule", 75), ("name", "Version name", 150),
                                               ("state", "State", 60), ("ver", "Rev", 40),
                                               ("default", "Default", 55), ("tests", "Tests", 45),
                                               ("by", "Last saved by", 150)], height=5)
        rf.pack(fill="x")
        self.rule_tree.bind("<Double-1>", lambda e: self.edit_rule())
        for row in ((("New rule", self.new_rule), ("Edit", self.edit_rule), ("Copy as new version", self.copy_rule),
                     ("Manual only on/off", self.toggle_manual)),
                    (("Make default", self.make_default), ("Retire", self.retire_rule),
                     ("Delete draft", self.delete_rule))):
            btns = ttk.Frame(right)
            btns.pack(fill="x", pady=(4, 0))
            for text, cmd in row:
                ttk.Button(btns, text=text, command=cmd).pack(side="left", padx=2)
        self.stig_map = {}

    # -- data
    def refresh(self):
        self.stig_map = {self.app.stig_label(s): s for s in self.app.index}
        self.stig_box["values"] = ["All"] + list(self.stig_map)
        if self.stig_var.get() not in self.stig_box["values"]:
            self.stig_var.set("All")
        want_stig = self.stig_map.get(self.stig_var.get())
        want_state, needle = self.state_var.get(), self.search_var.get().lower().strip()
        keep = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        summary = []
        for stig_id, stig in self.app.index.items():
            counts = {}
            for vuln_id in stig["order"]:
                c = stig["controls"][vuln_id]
                state = assess.control_state(self.app.rules_db, stig_id, c)
                counts[state] = counts.get(state, 0) + 1
                if want_stig and stig_id != want_stig:
                    continue
                if want_state != "All" and state != want_state:
                    continue
                if needle and needle not in f"{vuln_id} {c['rule_ver']} {c['title']}".lower():
                    continue
                n = len(assess.rules_for_control(self.app.rules_db, stig_id, vuln_id))
                self.tree.insert("", "end", iid=assess.key_of(stig_id, vuln_id), tags=(state.replace(" ", "_"),),
                                 values=(stig["short"], self.app.formats_text(stig_id), vuln_id, c["rule_ver"],
                                         c["severity"], state, n, c["title"]))
            if want_stig and stig_id != want_stig:
                continue
            done = counts.get("Active", 0) + counts.get("Manual only", 0)
            summary.append(f"{stig['short']}: {done}/{len(stig['order'])} decided"
                           + (f", {counts['STIG changed - review']} need review"
                              if counts.get("STIG changed - review") else ""))
        self.progress.configure(text="     ".join(summary) or "No checklists imported yet - start on tab 1.")
        keep = [k for k in keep if self.tree.exists(k)]
        if keep:
            self.tree.selection_set(keep)
            self.tree.see(keep[0])
        self.show_control()

    def current(self):
        sel = self.tree.selection()
        if not sel:
            return None, None
        stig_id, vuln_id = sel[0].split("|", 1)
        return stig_id, self.app.index[stig_id]["controls"][vuln_id]

    def show_control(self):
        stig_id, c = self.current()
        self.rule_tree.delete(*self.rule_tree.get_children())
        if not c:
            text_set(self.details, "", readonly=True)
            return
        text_set(self.details, f"{self.app.stig_label(stig_id)}\n"
                               f"{c['vuln_id']}  {c['rule_ver']}  [{c['severity']}]\n{c['title']}\n\n"
                               f"CHECK:\n{c['check']}\n\nFIX:\n{c['fix']}", readonly=True)
        for r in assess.rules_for_control(self.app.rules_db, stig_id, c["vuln_id"], include_retired=True):
            lock = store.lock_holder("rule", r["id"])
            self.rule_tree.insert("", "end", iid=r["id"],
                                  values=(r["id"], r.get("name", ""), r.get("state", "draft"), r.get("version", 1),
                                          "yes" if r.get("is_default") else "", len(r.get("tests", [])),
                                          f"EDITING NOW: {lock['user']}" if lock else
                                          f"{r.get('saved_by', r.get('updated_by', ''))} "
                                          f"{(r.get('saved_at') or r.get('updated_at') or '')[:10]}"))

    def selected_rule(self):
        sel = self.rule_tree.selection()
        return self.app.rule_by_id(sel[0]) if sel else None

    # -- actions
    def new_rule(self):
        stig_id, c = self.current()
        if c:
            RuleEditor.open(self.app, stig_id, c, None, self.after_save)

    def edit_rule(self, default=False):
        stig_id, c = self.current()
        if not c:
            return
        r = self.selected_rule()
        if r is None and default:
            rs = assess.rules_for_control(self.app.rules_db, stig_id, c["vuln_id"])
            r = next((x for x in rs if x.get("is_default")), rs[0] if rs else None)
        if r is None and default:
            return self.new_rule()
        if r:
            RuleEditor.open(self.app, stig_id, c, r, self.after_save)

    def copy_rule(self):
        stig_id, c = self.current()
        r = self.selected_rule()
        if not r:
            return messagebox.showinfo("Copy", "Select a rule to copy first.")
        dup = copy.deepcopy(r)
        for k in ("id", "history", "review_log", "is_default", "created_at", "created_by", "_rev", "saved_by",
                  "saved_at"):
            dup.pop(k, None)
        dup.update(name=r.get("name", "") + " (copy)", state="draft", version=0)
        RuleEditor.open(self.app, stig_id, c, dup, self.after_save, is_copy=True)

    def make_default(self):
        stig_id, c = self.current()
        r = self.selected_rule()
        if not r:
            return
        for x in assess.rules_for_control(self.app.rules_db, stig_id, c["vuln_id"], include_retired=True):
            if bool(x.get("is_default")) != (x["id"] == r["id"]):
                store.modify_rule(x["id"], lambda d, on=x["id"] == r["id"]: d.__setitem__("is_default", on))
        self.after_save()

    def retire_rule(self):
        r = self.selected_rule()
        if r and messagebox.askyesno("Retire rule", f"Retire {r['id']} '{r.get('name')}'? "
                                                    "Groups using it will fall back to the default version."):
            store.modify_rule(r["id"], lambda d: d.update(state="retired", is_default=False))
            self.after_save()

    def delete_rule(self):
        r = self.selected_rule()
        if not r:
            return
        if r.get("state") != "draft" or r.get("history"):
            return messagebox.showinfo("Delete", "Only drafts that were never saved as Active can be deleted. "
                                                 "Use Retire instead so the history is kept.")
        if store.lock_holder("rule", r["id"]):
            return messagebox.showinfo("Delete", "Someone has this rule open. Try again when they are done.")
        if messagebox.askyesno("Delete draft", f"Delete draft {r['id']}?"):
            store.delete_rule(r["id"])
            self.after_save()

    def starter_drafts(self):
        stig_id = self.stig_map.get(self.stig_var.get())
        scope = self.app.short(stig_id) if stig_id else "ALL imported STIGs"
        if not messagebox.askyesno(
                "Create starter drafts",
                f"Create starter DRAFT rules for {scope}?\n\n"
                "Drafts are written from the STIG check text for Catalyst 9300 / 8300 (IOS-XE 17.x) and Nexus 9000 "
                "(NX-OS 9.3/10.x). Only controls with no rule yet get one - existing rules are never touched. "
                "Every draft must be reviewed and tested before it can be made Active."):
            return
        report = drafts.create_drafts(self.app.index, self.app.rules_db, [stig_id] if stig_id else None)
        text = drafts.report_text(report)
        path = store.paths.output / f"starter_drafts_report_{store.stamp()}.txt"
        path.write_text(text + "\n", encoding="utf-8")
        self.after_save()
        ImportReport(self, f"Saved to {path}\n\n{text}")
        if report["manual"] and messagebox.askyesno(
                "Manual only?", f"{len(report['manual'])} control(s) need a human or design decision (listed in the "
                                "report). Mark them 'Manual only' now? You can switch any back later."):
            for stig, vuln_id, *_ in report["manual"]:
                sid = next(s for s, v in self.app.index.items() if v["short"] == stig)
                store.set_manual(assess.key_of(sid, vuln_id), True)
            self.after_save()

    def toggle_manual(self):
        stig_id, c = self.current()
        if not c:
            return
        key = assess.key_of(stig_id, c["vuln_id"])
        store.set_manual(key, key not in self.app.rules_db.get("manual_controls", []))
        self.after_save()

    def after_save(self):
        self.app.load_data()
        self.refresh()


# ---------------------------------------------------------------- rule editor

class RuleEditor(tk.Toplevel):
    @classmethod
    def open(cls, app, stig_id, control, rule, on_saved, is_copy=False):
        """Open the editor, respecting a teammate's edit lock on the rule."""
        readonly = False
        if rule and rule.get("id") and not is_copy:
            holder = store.acquire_lock("rule", rule["id"])
            if holder:
                pick = ask_choice(app, "Rule is being edited",
                                  f"{holder['user']} (on {holder['host']}) has opened {rule['id']} for editing "
                                  f"since {holder['since'][11:16]}. If you both edit it, one of you will lose "
                                  "changes.", ["Open read-only", "Edit anyway (they have finished)", "Cancel"])
                if not pick or pick == "Cancel":
                    return None
                if pick.startswith("Edit"):
                    store.acquire_lock("rule", rule["id"], force=True)
                else:
                    readonly = True
            # always edit the latest saved copy, not what the list showed a minute ago
            rule = store.load_json(store.rule_path(rule["id"]), rule)
        return cls(app, stig_id, control, rule, on_saved, is_copy, readonly)

    def __init__(self, app, stig_id, control, rule, on_saved, is_copy=False, readonly=False):
        super().__init__(app)
        self.app, self.stig_id, self.control, self.on_saved = app, stig_id, control, on_saved
        self.readonly = readonly
        self.original = rule if (rule and not is_copy) else None
        self.r = copy.deepcopy(rule) if rule else {
            "name": "Default", "state": "draft", "version": 0, "commands": [],
            "pass_logic": {"mode": "ALL", "conditions": []}, "na_enabled": False,
            "na_logic": {"mode": "ALL", "conditions": []}, "comment": "", "notes": "", "tests": []}
        self.r.setdefault("na_logic", {"mode": "ALL", "conditions": []})
        self.r.setdefault("tests", [])
        name = app.short(stig_id)
        self.title(f"Rule - {name} {control['vuln_id']} {control['rule_ver']}"
                   + (f" - {self.r['id']}" if self.r.get("id") else " - new") + ("  (READ-ONLY)" if readonly else ""))
        maximize(self, "1420x900")
        self.sample, self.cur_cmd, self._job, self._loading = {}, None, None, False
        app.open_editors.add(self)

        top = ttk.Frame(self)
        top.pack(fill="x", padx=8, pady=(8, 0))
        ttk.Label(top, text=f"{name} {control['vuln_id']} ({control['rule_ver']}, {control['severity']}): "
                            f"{control['title']}", wraplength=1380, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Label(top, text=f"STIG release {app.index[stig_id]['release']}, imported as {app.formats_text(stig_id)}. "
                            "Rules apply to the STIG whichever checklist format is written.",
                  foreground="#555").pack(anchor="w")
        if readonly:
            tk.Label(top, text="READ-ONLY: someone else is editing this rule. You can test it but not save.",
                     bg="#fff0c2", anchor="w", padx=6).pack(fill="x", pady=(4, 0))
        if self.original and self.original.get("check_hash") != control["check_hash"]:
            self._changed_banner(top)
        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=8, pady=8)
        left, right = ttk.Frame(paned), ttk.Frame(paned)
        paned.add(left, weight=1)
        paned.add(right, weight=1)
        self._build_left(left)
        self._build_right(right)
        self.after(100, lambda: paned.sashpos(0, max(500, self.winfo_width() // 2)))
        self._load_form()
        if self.r["tests"]:
            self.load_test(self.r["tests"][0])
        self.run_all_tests(quiet=True)
        self.schedule()
        self.protocol("WM_DELETE_WINDOW", self.cancel)

    def _changed_banner(self, parent):
        old_rel, old = store.find_control_version(self.stig_id, self.control["vuln_id"], self.original["check_hash"])
        self.banner = tk.Frame(parent, bg="#ffd6d6")
        self.banner.pack(fill="x", pady=(4, 0))
        tk.Label(self.banner, bg="#ffd6d6", anchor="w", padx=6,
                 text=f"DISA changed this control's check text in {self.app.index[self.stig_id]['release']}"
                      + (f" (this rule was written against {old_rel})" if old_rel else "")
                      + ". Check the rule still fits. Saving the rule marks it reviewed.").pack(side="left")
        if old:
            ttk.Button(self.banner, text="What changed?",
                       command=lambda: self._show_change(old_rel, old)).pack(side="left", padx=4)
        ttk.Button(self.banner, text="Still valid - mark reviewed", command=self._mark_reviewed).pack(side="left")

    def _show_change(self, old_rel, old):
        win = tk.Toplevel(self)
        win.title(f"{self.control['vuln_id']}: {old_rel} -> {self.app.index[self.stig_id]['release']}")
        win.geometry("1000x700")
        ttk.Label(win, text="Red struck-out = removed by DISA, green = added.").pack(anchor="w", padx=8, pady=4)
        t = diff_text_widget(win)
        t.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        show_control_diff(t, old, self.control)

    def _mark_reviewed(self):
        if self.readonly:
            return
        saved = store.mark_rule_reviewed(self.original["id"], self.control["check_hash"],
                                         self.app.index[self.stig_id]["release"])
        for d in (self.original, self.r):
            d.update(check_hash=saved["check_hash"], _rev=saved["_rev"], review_log=saved.get("review_log", []))
        self.banner.destroy()
        self.on_saved()

    # -- layout
    def _build_left(self, f):
        btns = ttk.Frame(f)  # packed first at the bottom so it stays visible on small screens
        btns.pack(side="bottom", fill="x", pady=8)
        ttk.Button(btns, text="Save rule", command=self.save).pack(side="left")
        ttk.Button(btns, text="Cancel", command=self.cancel).pack(side="left", padx=6)
        ttk.Label(btns, text="To set State = active the rule needs 2+ saved tests with different expected "
                             "results, all passing.", foreground="#666", wraplength=420).pack(side="left", padx=10)

        ttk.Label(f, text="STIG check text (for reference)").pack(anchor="w")
        chk = ScrolledText(f, height=5, width=50, wrap="word", font=("Segoe UI", 9))
        chk.pack(fill="x")
        text_set(chk, f"{self.control['check']}\n\nFIX:\n{self.control['fix']}", readonly=True)

        row = ttk.Frame(f)
        row.pack(fill="x", pady=(8, 0))
        ttk.Label(row, text="Version name:").pack(side="left")
        self.name_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.name_var, width=28).pack(side="left", padx=4)
        ttk.Label(row, text="State:").pack(side="left", padx=(10, 0))
        self.state_var = tk.StringVar()
        ttk.Combobox(row, textvariable=self.state_var, values=RULE_STATES, state="readonly",
                     width=10).pack(side="left", padx=4)
        self.rev_label = ttk.Label(row, text="")
        self.rev_label.pack(side="left", padx=10)

        ttk.Label(f, text="Show commands to collect (one per line, exactly as typed on the device):").pack(
            anchor="w", pady=(8, 0))
        self.cmd_text = tk.Text(f, height=3, width=50, font=MONO)
        self.cmd_text.pack(fill="x")
        self.cmd_text.bind("<KeyRelease>", lambda e: self.commands_changed())

        self.pass_box, self.pass_mode = self._condition_block(
            f, "NOT A FINDING when", "of these are true.  Anything else = OPEN.", "pass_logic", height=4)
        na_head = ttk.Frame(f)
        na_head.pack(fill="x", pady=(10, 0))
        self.na_var = tk.BooleanVar()
        ttk.Checkbutton(na_head, text="Use a Not Applicable check (checked before the Not a Finding check)",
                        variable=self.na_var, command=self.schedule).pack(side="left")
        self.na_box, self.na_mode = self._condition_block(
            f, "NOT APPLICABLE when", "of these are true.", "na_logic", height=2)

        extra = ttk.Notebook(f)
        extra.pack(fill="x", pady=(8, 0))
        fd = ttk.Frame(extra, padding=4)
        extra.add(fd, text=" Reason text ")
        row = ttk.Frame(fd)
        row.pack(fill="x")
        ttk.Label(row, text="When the result is").pack(side="left")
        self.outcome_pick = tk.StringVar(value="Open")
        box = ttk.Combobox(row, textvariable=self.outcome_pick, values=list(OUTCOMES), state="readonly", width=15)
        box.pack(side="left", padx=4)
        box.bind("<<ComboboxSelected>>", lambda e: self.switch_outcome())
        self.outcome_where = ttk.Label(row, text="", foreground="#555")
        self.outcome_where.pack(side="left")
        self.outcome_box = tk.Text(fd, height=3, width=50, wrap="word", font=("Segoe UI", 9))
        self.outcome_box.pack(fill="x", pady=2)
        self.outcome_box.bind("<KeyRelease>", lambda e: (self.store_outcome(), self.schedule()))
        self.expected_var = tk.BooleanVar()
        ttk.Checkbutton(fd, variable=self.expected_var, command=self.schedule,
                        text="Open is INTENTIONAL for this rule (known finding, e.g. recommend risk acceptance). "
                             "Reviewers see 'Open (expected)'.").pack(anchor="w")
        cm = ttk.Frame(extra, padding=4)
        extra.add(cm, text=" Extra comment ")
        ttk.Label(cm, text="Always added to the checklist's Comments field, whatever the result:",
                  foreground="#555").pack(anchor="w")
        self.comment_text = tk.Text(cm, height=4, width=50, wrap="word", font=("Segoe UI", 9))
        self.comment_text.pack(fill="x")
        fx = ttk.Frame(extra, padding=4)
        extra.add(fx, text=" Fix commands ")
        fx.columnconfigure(0, weight=1)
        fx.columnconfigure(1, weight=1)
        ttk.Label(fx, text="LOW-IMPACT fix (banners, logging, archive...):").grid(row=0, column=0, sticky="w")
        ttk.Label(fx, text="IMPACTFUL fix (AAA, SSH, vty, ports, STP, SNMP...):").grid(row=0, column=1, sticky="w")
        self.fix_low = tk.Text(fx, height=4, width=25, wrap="none", font=MONO)
        self.fix_low.grid(row=1, column=0, sticky="we", padx=(0, 4))
        self.fix_high = tk.Text(fx, height=4, width=25, wrap="none", font=MONO)
        self.fix_high.grid(row=1, column=1, sticky="we")
        ttk.Label(fx, foreground="#555", wraplength=700, justify="left",
                  text="Config commands for the Hardening Script tab. <VALUE> = fill in per site. A line "
                       "'{each failing section}' followed by indented commands repeats them under every interface / "
                       "section that failed on the device; '{each failing section of condition 2}' only under the "
                       "ones that failed condition 2 (so one rule can add a command on uplinks and remove it on "
                       "access ports).").grid(row=2, column=0, columnspan=2, sticky="w")
        nt = ttk.Frame(extra, padding=4)
        extra.add(nt, text=" Reviewer guidance ")
        ttk.Label(nt, text="Notes for reviewers and rule authors (not written to the checklist):",
                  foreground="#555").pack(anchor="w")
        self.notes_text = tk.Text(nt, height=4, width=50, wrap="word", font=("Segoe UI", 9))
        self.notes_text.pack(fill="x")

    def _condition_block(self, parent, head, tail, logic_key, height):
        frame = ttk.LabelFrame(parent, text="")
        frame.pack(fill="x", pady=(8, 0))
        hdr = ttk.Frame(frame)
        hdr.pack(fill="x", padx=4, pady=2)
        ttk.Label(hdr, text=head, font=("Segoe UI", 9, "bold")).pack(side="left")
        mode = tk.StringVar(value="ALL")
        box = ttk.Combobox(hdr, textvariable=mode, values=["ALL", "ANY"], state="readonly", width=5)
        box.pack(side="left", padx=4)
        box.bind("<<ComboboxSelected>>", lambda e: self.schedule())
        ttk.Label(hdr, text=tail).pack(side="left")
        lb = tk.Listbox(frame, height=height, width=50, font=("Segoe UI", 9), activestyle="none")
        lb.pack(fill="x", padx=4)
        lb.bind("<Double-1>", lambda e: self.edit_condition(logic_key, lb))
        b = ttk.Frame(frame)
        b.pack(fill="x", padx=4, pady=2)
        ttk.Button(b, text="Add condition...", command=lambda: self.edit_condition(logic_key, lb, new=True)).pack(
            side="left")
        ttk.Button(b, text="Edit...", command=lambda: self.edit_condition(logic_key, lb)).pack(side="left", padx=2)
        ttk.Button(b, text="Remove", command=lambda: self.remove_condition(logic_key, lb)).pack(side="left", padx=2)
        return lb, mode

    def _build_right(self, f):
        ttk.Label(f, text="Test against sample output", style="Big.TLabel").pack(anchor="w")
        row = ttk.Frame(f)
        row.pack(fill="x", pady=4)
        ttk.Label(row, text="Output of command:").pack(side="left")
        self.cmd_pick = tk.StringVar()
        self.cmd_box = ttk.Combobox(row, textvariable=self.cmd_pick, state="readonly")
        self.cmd_box.pack(side="left", padx=4, fill="x", expand=True)
        self.cmd_box.bind("<<ComboboxSelected>>", lambda e: self.switch_command())
        row2 = ttk.Frame(f)
        row2.pack(fill="x")
        ttk.Button(row2, text="Load from imported device...", command=self.load_from_device).pack(side="left")
        ttk.Button(row2, text="Empty output", command=self.set_empty).pack(side="left", padx=4)
        ttk.Button(row2, text="No output (missing)", command=self.set_missing).pack(side="left")
        self.sample_state = ttk.Label(f, text="", foreground="#555")
        self.sample_state.pack(anchor="w")

        tf = ttk.Frame(f)  # packed last so the widgets below it always get their space
        self.sample_text = tk.Text(tf, height=12, width=50, font=MONO, wrap="none", undo=True)
        ys = ttk.Scrollbar(tf, orient="vertical", command=self.sample_text.yview)
        xs = ttk.Scrollbar(tf, orient="horizontal", command=self.sample_text.xview)
        self.sample_text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.sample_text.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        tf.rowconfigure(0, weight=1)
        tf.columnconfigure(0, weight=1)
        for tag, color in HIGHLIGHT.items():
            self.sample_text.tag_configure(tag, background=color)
        self.sample_text.bind("<<Modified>>", self.sample_modified)

        legend = ttk.Frame(f)

        for tag, text in (("match", "matched"), ("problem", "problem"),
                          ("section", "section OK"), ("skipped", "skipped")):
            tk.Label(legend, text=f"  {text}  ", bg=HIGHLIGHT[tag]).pack(side="left", padx=2)

        self.result_label = tk.Label(f, text="", font=("Segoe UI", 14, "bold"), anchor="w")

        self.explain = ScrolledText(f, height=8, width=50, wrap="none", font=MONO)


        tests = ttk.LabelFrame(f, text="Saved tests (re-run every time the rule changes)")

        tfr, self.test_tree = make_tree(tests, [("name", "Test name", 240), ("exp", "Expected", 120),
                                                ("got", "Rule gives", 120), ("res", "Result", 70)], height=4)
        tfr.pack(fill="x", padx=4)
        color_tags(self.test_tree, {"pass": "#d9f7d6", "fail": "#ffd6d6"})
        self.test_tree.bind("<Double-1>", lambda e: self.load_selected_test())
        b = ttk.Frame(tests)
        b.pack(fill="x", padx=4, pady=4)
        ttk.Button(b, text="Save current sample as a test...", command=self.save_test).pack(side="left")
        ttk.Button(b, text="Load test into sample", command=self.load_selected_test).pack(side="left", padx=4)
        ttk.Button(b, text="Delete test", command=self.delete_test).pack(side="left", padx=4)
        tests.pack(side="bottom", fill="x", pady=(6, 0))
        self.explain.pack(side="bottom", fill="x")
        self.result_label.pack(side="bottom", fill="x", pady=(6, 0))
        legend.pack(side="bottom", fill="x", pady=2)
        tf.pack(fill="both", expand=True)

    # -- form <-> rule
    def _load_form(self):
        self.name_var.set(self.r.get("name", ""))
        self.state_var.set(self.r.get("state", "draft"))
        self.rev_label.configure(text=f"Revision {self.r.get('version', 0)}" if self.r.get("version") else "New rule")
        text_set(self.cmd_text, "\n".join(self.r.get("commands", [])))
        self.pass_mode.set(self.r["pass_logic"].get("mode", "ALL"))
        self.na_mode.set(self.r["na_logic"].get("mode", "ALL"))
        self.na_var.set(bool(self.r.get("na_enabled")))
        text_set(self.comment_text, self.r.get("comment", ""))
        text_set(self.notes_text, self.r.get("notes", ""))
        text_set(self.fix_low, (self.r.get("fix") or {}).get("low", ""))
        text_set(self.fix_high, (self.r.get("fix") or {}).get("high", ""))
        self.outcomes = dict(self.r.get("outcome_text") or {})
        self.cur_outcome = "open"
        self.outcome_pick.set("Open")
        text_set(self.outcome_box, self.outcomes.get("open", ""))
        self.show_outcome_where()
        self.expected_var.set(bool(self.r.get("expected_open")))
        self.commands_changed()

    def commands(self):
        seen = []
        for line in text_get(self.cmd_text).splitlines():
            if line.strip() and line.strip() not in seen:
                seen.append(line.strip())
        return seen

    def collect(self):
        self.r["name"] = self.name_var.get().strip()
        self.r["state"] = self.state_var.get()
        self.r["commands"] = self.commands()
        self.r["pass_logic"]["mode"] = self.pass_mode.get()
        self.r["na_logic"]["mode"] = self.na_mode.get()
        self.r["na_enabled"] = self.na_var.get()
        self.r["comment"] = text_get(self.comment_text).strip()
        self.r["fix"] = {"low": text_get(self.fix_low).rstrip(), "high": text_get(self.fix_high).rstrip()}
        self.store_outcome()
        self.r["outcome_text"] = {k: v.strip() for k, v in self.outcomes.items() if v.strip()}
        self.r["expected_open"] = self.expected_var.get()
        self.r["notes"] = text_get(self.notes_text).strip()
        return self.r

    def store_outcome(self):
        if hasattr(self, "outcomes"):
            self.outcomes[self.cur_outcome] = text_get(self.outcome_box)

    def switch_outcome(self):
        self.store_outcome()
        self.cur_outcome = OUTCOMES[self.outcome_pick.get()]
        text_set(self.outcome_box, self.outcomes.get(self.cur_outcome, ""))
        self.show_outcome_where()

    def show_outcome_where(self):
        field = assess.FIELD_LABELS[self.app.settings["text_placement"][self.cur_outcome]]
        self.outcome_where.configure(text=f"this text goes in {field.upper()} (team setting).  "
                                          "{devices} = the device names.")

    def render_conditions(self):
        for lb, key in ((self.pass_box, "pass_logic"), (self.na_box, "na_logic")):
            lb.delete(0, "end")
            for i, c in enumerate(self.r[key]["conditions"], 1):
                errs = engine.condition_problems(c, self.commands())
                lb.insert("end", f"{i}. {engine.describe(c)}" + (f"   <-- {errs[0]}" if errs else ""))
                if errs:
                    lb.itemconfigure("end", foreground="#b00020")

    def commands_changed(self):
        cmds = self.commands()
        self.cmd_box["values"] = cmds
        if self.cur_cmd not in cmds:
            self.cur_cmd = None
            self.cmd_pick.set(cmds[0] if cmds else "")
            self.switch_command(store_current=False)
        self.render_conditions()
        self.schedule()

    # -- conditions
    def edit_condition(self, key, lb, new=False):
        if not self.commands():
            return messagebox.showinfo("Commands first", "Type at least one show command first.", parent=self)
        idx = None
        if not new:
            sel = lb.curselection()
            if not sel:
                return
            idx = sel[0]
        start = None if new else self.r[key]["conditions"][idx]
        dlg = ConditionDialog(self, self.commands(), start, default_cmd=self.cur_cmd)
        if dlg.result is None:
            return
        if new:
            self.r[key]["conditions"].append(dlg.result)
        else:
            self.r[key]["conditions"][idx] = dlg.result
        if key == "na_logic":
            self.na_var.set(True)
        self.render_conditions()
        self.schedule()

    def remove_condition(self, key, lb):
        sel = lb.curselection()
        if sel:
            del self.r[key]["conditions"][sel[0]]
            self.render_conditions()
            self.schedule()

    # -- sample handling
    def switch_command(self, store_current=True):
        if store_current:
            self.store_sample()
        self.cur_cmd = self.cmd_pick.get() or None
        self._loading = True
        text_set(self.sample_text, self.sample.get(self.cur_cmd, ""))
        self.sample_text.edit_modified(False)
        self._loading = False
        self.schedule()

    def store_sample(self):
        # Typing anything (or pressing Empty output) makes the sample count as collected evidence.
        if self.cur_cmd and (self.cur_cmd in self.sample or text_get(self.sample_text)):
            self.sample[self.cur_cmd] = text_get(self.sample_text)

    def sample_modified(self, _=None):
        if self.sample_text.edit_modified():
            self.sample_text.edit_modified(False)
            if not self._loading and self.cur_cmd:
                self.sample[self.cur_cmd] = text_get(self.sample_text)
                self.schedule()

    def set_empty(self):
        if self.cur_cmd:
            self.sample[self.cur_cmd] = ""
            self.switch_command(store_current=False)

    def set_missing(self):
        if self.cur_cmd:
            self.sample.pop(self.cur_cmd, None)
            self.switch_command(store_current=False)

    def load_from_device(self):
        run = self.app.run
        devices = [d for d in (run or {}).get("devices", []) if d["status"] == "ok"]
        if not devices:
            return messagebox.showinfo("No devices", "Import a SolarWinds output file on tab 5 first, "
                                                     "or paste sample output into the box.", parent=self)
        cmds = self.commands()
        choices = [f"{d['host']}  ({sum(1 for c in cmds if c in d['outputs'])}/{len(cmds)} commands)"
                   for d in devices]
        pick = ask_choice(self, "Load sample", "Load this rule's command output from which device "
                                               f"(run {run['id']})?", choices)
        if not pick:
            return
        device = devices[choices.index(pick)]
        for c in cmds:
            if c in device["outputs"]:
                self.sample[c] = device["outputs"][c]["text"]
            else:
                self.sample.pop(c, None)
        self.switch_command(store_current=False)

    def sample_outputs(self):
        return {c: {"status": engine.classify_output(self.sample[c]), "text": self.sample[c]}
                for c in self.commands() if c in self.sample}

    # -- testing
    def schedule(self, *_):
        if self._job:
            self.after_cancel(self._job)
        self._job = self.after(300, self.run_test)

    def run_test(self):
        self._job = None
        rule = self.collect()
        outputs = self.sample_outputs()
        res = engine.evaluate(rule, outputs)
        for tag in HIGHLIGHT:
            self.sample_text.tag_remove(tag, "1.0", "end")
        for idx, tag in res["marks"].get(self.cur_cmd, {}).items():
            self.sample_text.tag_add(tag, f"{idx + 1}.0", f"{idx + 1}.end+1c")
        status = res["status"]
        expected = status == "open" and rule.get("expected_open")
        self.result_label.configure(text=f"Result: {STATUS_LABELS[status].upper()}"
                                         + ("  (EXPECTED - intentional finding)" if expected else ""),
                                    fg="#b35c00" if expected else RESULT_COLOR[status])
        added = engine.outcome_text(rule, status, ["<device>"])
        field = assess.FIELD_LABELS[self.app.settings["text_placement"][status]]
        text_set(self.explain, f"The reason for {STATUS_LABELS[status]} goes in the checklist's {field}"
                 + (f", starting with:\n{added}\n\n" if added else ".\n\n") +
                 "\n".join(res["reasons"]) +
                 (f"\n\nEvidence lines that would go into {field}:\n" + "\n".join(res["evidence"])
                  if res["evidence"] else ""), readonly=True)
        if self.cur_cmd is None:
            state = "Add a show command on the left first."
        elif self.cur_cmd not in self.sample:
            state = "No sample for this command - the rule treats it as MISSING evidence (Not Reviewed)."
        elif outputs[self.cur_cmd]["status"] == "invalid":
            state = "The device rejected this command (% Invalid ...) - counts as INVALID evidence (Not Reviewed)."
        elif not self.sample[self.cur_cmd].strip():
            state = "Sample is EMPTY output (the command ran and printed nothing)."
        else:
            state = f"Sample: {len(engine.split_lines(self.sample[self.cur_cmd]))} lines. Paste or type to change it."
        self.sample_state.configure(text=state)
        self.run_all_tests(quiet=True)
        return status

    def run_all_tests(self, quiet=False):
        self.test_tree.delete(*self.test_tree.get_children())
        for i, (t, actual, ok) in enumerate(engine.run_tests(self.collect())):
            self.test_tree.insert("", "end", iid=str(i), tags=("pass" if ok else "fail",),
                                  values=(t["name"], STATUS_LABELS.get(t["expected"], t["expected"]),
                                          STATUS_LABELS.get(actual, actual), "PASS" if ok else "FAIL"))

    def save_test(self):
        self.store_sample()
        if not self.sample_outputs():
            return messagebox.showinfo("Nothing to save", "Load or paste sample output first.", parent=self)
        name = simpledialog.askstring("Save test", "Name this test (e.g. 'good config', 'telnet enabled'):",
                                      parent=self)
        if not name:
            return
        current = STATUS_LABELS[self.run_test()]
        labels = [STATUS_LABELS[s] for s in STATUSES]
        exp = ask_choice(self, "Expected result", "What SHOULD the result be for this sample? "
                                                  f"(the rule currently says {current})", labels, initial=current)
        if not exp:
            return
        self.r["tests"].append({"name": name.strip(), "expected": LABEL_TO_STATUS[exp],
                                "outputs": {c: self.sample[c] for c in self.commands() if c in self.sample},
                                "saved_at": store.now(), "saved_by": store.current_user()})
        self.run_all_tests()

    def selected_test(self):
        sel = self.test_tree.selection()
        return self.r["tests"][int(sel[0])] if sel else None

    def load_test(self, t):
        self.sample = dict(t.get("outputs", {}))
        self.switch_command(store_current=False)

    def load_selected_test(self):
        t = self.selected_test()
        if t:
            self.load_test(t)

    def delete_test(self):
        t = self.selected_test()
        if t and messagebox.askyesno("Delete test", f"Delete test '{t['name']}'?", parent=self):
            self.r["tests"].remove(t)
            self.run_all_tests()

    # -- save
    def save(self):
        if self.readonly:
            return messagebox.showinfo("Read-only", "Someone else is editing this rule, so it cannot be saved here.",
                                       parent=self)
        rule = self.collect()
        if not rule["name"]:
            return messagebox.showerror("Name needed", "Give this rule version a name (e.g. 'Default').", parent=self)
        if rule["state"] == "active":
            problems = engine.activation_problems(rule)
            if problems:
                if not messagebox.askyesno("Cannot activate yet",
                                           "This rule cannot be Active yet:\n\n- " + "\n- ".join(problems) +
                                           "\n\nSave it as a Draft instead?", parent=self):
                    return
                rule["state"] = "draft"
        content_keys = ("name", "state", "commands", "pass_logic", "na_enabled", "na_logic", "comment", "notes",
                        "outcome_text", "expected_open", "fix",
                        "tests")
        if self.original is not None:
            before = {k: self.original.get(k) for k in content_keys}
            after = {k: rule.get(k) for k in content_keys}
            if json.dumps(before, sort_keys=True) != json.dumps(after, sort_keys=True):
                snapshot = {k: v for k, v in self.original.items() if k not in ("history", "review_log")}
                rule.setdefault("history", []).append(snapshot)
                rule["version"] = self.original.get("version", 1) + 1
            rule["check_hash"] = self.control["check_hash"]
            try:
                store.save_rule(rule)
            except store.ConflictError as e:
                pick = ask_choice(self, "Changed by someone else",
                                  f"{e.current.get('saved_by')} saved {rule['id']} at {e.current.get('saved_at')} "
                                  "while you were editing.",
                                  ["Save mine as a separate new version (keeps both)",
                                   "Overwrite theirs with mine", "Cancel - keep editing"])
                if not pick or pick.startswith("Cancel"):
                    return
                if pick.startswith("Overwrite"):
                    rule["_rev"] = e.current.get("_rev", 0)
                    store.save_rule(rule)
                else:
                    self._save_new({**rule, "name": f"{rule['name']} ({store.current_user()})", "state": "draft",
                                    "history": [], "is_default": False})
        else:
            self._save_new(rule)
        self.on_saved()
        self.close()

    def _save_new(self, rule):
        rule = {k: v for k, v in rule.items() if k not in ("_rev", "review_log")}
        siblings = assess.rules_for_control(store.load_rules(), self.stig_id, self.control["vuln_id"])
        rule.update(id=store.new_rule_id(), stig_id=self.stig_id, vuln_id=self.control["vuln_id"], version=1,
                    check_hash=self.control["check_hash"], created_at=store.now(), created_by=store.current_user())
        rule.setdefault("is_default", not any(s.get("is_default") for s in siblings))
        rule.setdefault("history", [])
        store.save_rule(rule, check=False)

    def release(self):
        if self.original and not self.readonly:
            store.release_lock("rule", self.original["id"])
        self.app.open_editors.discard(self)

    def close(self):
        self.release()
        self.destroy()

    def cancel(self):
        if self.readonly or messagebox.askyesno("Close", "Close without saving changes?", parent=self):
            self.close()


# ---------------------------------------------------------------- condition dialog

CHECK_HELP = {
    "has": "Passes when at least one line matches. Example: has a line that starts with 'login block-for'.",
    "lacks": "Passes when NO line matches. Example: has NO line that contains 'transport input telnet'.",
    "number": "Finds matching line(s) and reads the first number after your text. "
              "Example: a line containing 'exec-timeout' with a number at most 10.",
    "count": "Counts matching lines. Example: at least 2 lines that start with 'ntp server'.",
    "pattern": "Advanced: a regular expression searched across the whole text. Use \\n to span lines.",
    "no_pattern": "Advanced: passes when the regular expression is NOT found anywhere.",
}
SCOPE_HELP = ("A section is a line plus the indented lines under it, e.g. 'line vty 0 4' and its settings, "
              "or 'interface GigabitEthernet1/0/1' and its settings. 'Only' / 'skip' look for a line STARTING "
              "with the text, so skip 'shutdown' does not skip 'no shutdown'. Start with re: for a regex. "
              "Port roles: type role:uplink, role:downlink, role:access or role:any to pick interfaces by their "
              "description keyword (set on the Device Groups tab).")


class ConditionDialog(tk.Toplevel):
    def __init__(self, parent, commands, cond, default_cmd=None):
        super().__init__(parent)
        self.title("Condition")
        self.transient(parent)
        self.resizable(False, False)
        self.result = None
        c = {**engine.NEW_CONDITION, **(cond or {})}
        if not c["command"]:
            c["command"] = default_cmd if default_cmd in commands else commands[0]
        self.v = {k: tk.StringVar(value=str(c[k])) for k in
                  ("command", "section", "section_how", "only", "exclude", "text", "how", "op", "value")}
        self.scope_labels = {v: k for k, v in engine.SCOPES.items()}
        self.check_labels = {v: k for k, v in engine.CHECKS.items()}
        self.v["scope"] = tk.StringVar(value=engine.SCOPES[c["scope"]])
        self.v["check"] = tk.StringVar(value=engine.CHECKS[c["check"]])
        self.v["if_none"] = tk.StringVar(value="counts as FAIL" if c["if_none"] == "fail" else "counts as PASS")
        self.ignore = tk.BooleanVar(value=bool(c["ignore_case"]))

        f = ttk.Frame(self, padding=12)
        f.pack(fill="both")
        r = 0

        def row(label, widget, colspan=3):
            nonlocal r
            ttk.Label(f, text=label).grid(row=r, column=0, sticky="w", pady=3)
            widget.grid(row=r, column=1, columnspan=colspan, sticky="we", pady=3)
            r += 1
            return widget

        row("In the output of:", ttk.Combobox(f, textvariable=self.v["command"], values=commands,
                                              state="readonly", width=60))
        row("Look in:", ttk.Combobox(f, textvariable=self.v["scope"], values=list(engine.SCOPES.values()),
                                     state="readonly", width=60))
        sec = ttk.Frame(f)
        self.w_section_how = ttk.Combobox(sec, textvariable=self.v["section_how"], values=engine.HOWS,
                                          state="readonly", width=11)
        self.w_section_how.pack(side="left")
        self.w_section = ttk.Entry(sec, textvariable=self.v["section"], width=46)
        self.w_section.pack(side="left", padx=4)
        row("   ...section first line:", sec)
        self.w_only = row("   ...only sections with a line starting:", ttk.Entry(f, textvariable=self.v["only"]))
        self.w_exclude = row("   ...skip sections with a line starting:", ttk.Entry(f, textvariable=self.v["exclude"]))
        self.w_if_none = row("   ...if no sections found:",
                             ttk.Combobox(f, textvariable=self.v["if_none"], state="readonly",
                                          values=["counts as FAIL", "counts as PASS"]))
        ttk.Label(f, text=SCOPE_HELP, foreground="#666", wraplength=560).grid(row=r, column=1, columnspan=3,
                                                                             sticky="w")
        r += 1
        ttk.Separator(f).grid(row=r, column=0, columnspan=4, sticky="we", pady=8)
        r += 1
        row("It:", ttk.Combobox(f, textvariable=self.v["check"], values=list(engine.CHECKS.values()),
                                state="readonly", width=60))
        txt = ttk.Frame(f)
        self.w_how = ttk.Combobox(txt, textvariable=self.v["how"], values=engine.HOWS, state="readonly", width=11)
        self.w_how.pack(side="left")
        ttk.Entry(txt, textvariable=self.v["text"], width=46).pack(side="left", padx=4)
        row("   ...text:", txt)
        num = ttk.Frame(f)
        self.w_op = ttk.Combobox(num, textvariable=self.v["op"], values=list(engine.OPS), state="readonly", width=4)
        self.w_op.pack(side="left")
        self.w_value = ttk.Entry(num, textvariable=self.v["value"], width=12)
        self.w_value.pack(side="left", padx=4)
        row("   ...number is:", num)
        row("", ttk.Checkbutton(f, text="Ignore upper/lower case", variable=self.ignore))
        self.help = ttk.Label(f, text="", foreground="#666", wraplength=560)
        self.help.grid(row=r, column=1, columnspan=3, sticky="w")
        r += 1
        ttk.Separator(f).grid(row=r, column=0, columnspan=4, sticky="we", pady=8)
        r += 1
        ttk.Label(f, text="Reads as:", font=("Segoe UI", 9, "bold")).grid(row=r, column=0, sticky="nw")
        self.preview = ttk.Label(f, text="", wraplength=560)
        self.preview.grid(row=r, column=1, columnspan=3, sticky="w")
        r += 1
        self.errors = ttk.Label(f, text="", foreground="#b00020", wraplength=560)
        self.errors.grid(row=r, column=1, columnspan=3, sticky="w")
        r += 1
        b = ttk.Frame(f)
        b.grid(row=r, column=0, columnspan=4, pady=(10, 0))
        ttk.Button(b, text="OK", command=self.ok).pack(side="left", padx=4)
        ttk.Button(b, text="Cancel", command=self.destroy).pack(side="left", padx=4)

        for var in list(self.v.values()) + [self.ignore]:
            var.trace_add("write", lambda *a: self.update_view())
        self.commands = commands
        self.update_view()
        self.bind("<Escape>", lambda e: self.destroy())
        self.grab_set()
        parent.wait_window(self)

    def current(self):
        return {
            "command": self.v["command"].get(), "scope": self.scope_labels[self.v["scope"].get()],
            "section": self.v["section"].get(), "section_how": self.v["section_how"].get(),
            "only": self.v["only"].get(), "exclude": self.v["exclude"].get(),
            "if_none": "fail" if "FAIL" in self.v["if_none"].get() else "pass",
            "check": self.check_labels[self.v["check"].get()], "text": self.v["text"].get(),
            "how": self.v["how"].get(), "ignore_case": self.ignore.get(),
            "op": self.v["op"].get(), "value": self.v["value"].get().strip(),
        }

    def update_view(self):
        c = self.current()
        sectioned = c["scope"] != "all"
        for w in (self.w_section, self.w_only, self.w_exclude):
            w.configure(state="normal" if sectioned else "disabled")
        for w in (self.w_section_how, self.w_if_none):
            w.configure(state="readonly" if sectioned else "disabled")
        numeric = c["check"] in ("number", "count")
        self.w_op.configure(state="readonly" if numeric else "disabled")
        self.w_value.configure(state="normal" if numeric else "disabled")
        self.w_how.configure(state="disabled" if c["check"] in ("pattern", "no_pattern") else "readonly")
        self.help.configure(text=CHECK_HELP[c["check"]])
        self.preview.configure(text=engine.describe(c))
        errs = engine.condition_problems(c, self.commands)
        self.errors.configure(text="\n".join(f"- {e}" for e in errs))

    def ok(self):
        c = self.current()
        errs = engine.condition_problems(c, self.commands)
        if errs:
            return messagebox.showerror("Fix the condition", "\n".join(errs), parent=self)
        self.result = c
        self.destroy()


# ---------------------------------------------------------------- 3. groups

class GroupsTab(ttk.Frame):
    def __init__(self, nb, app):
        super().__init__(nb)
        self.app = app
        help_label(self, "Step 3 - A device group is a set of devices configured alike, e.g. CAMPUS-ACCESS (NDM + "
                         "RTR + L2S) or CAMPUS-HANGOFF (NDM + L2S). Click 'New group' and answer the questions: "
                         "name, which STIGs apply, which devices belong. Devices are matched by hostname pattern; "
                         "anything the pattern gets wrong can be moved by hand in the device list below.")
        b = ttk.Frame(self)
        b.pack(fill="x", padx=6)
        for text, cmd in (("New group...", self.new_group), ("Edit group...", self.edit_group),
                          ("Copy group...", self.copy_group), ("Delete group", self.delete_group),
                          ("Rule versions...", self.choose_rules), ("Port roles...", lambda: PortRolesDialog(self.app))):
            ttk.Button(b, text=text, command=cmd).pack(side="left", padx=(0, 6))
        gf, self.tree = make_tree(self, [("id", "Group", 170), ("desc", "Description", 250),
                                         ("stigs", "STIG checklists", 420), ("patterns", "Hostname patterns", 160),
                                         ("devices", "Devices", 65), ("auto", "Controls automated", 140)], height=8)
        gf.pack(fill="both", expand=True, padx=6, pady=6)
        self.tree.bind("<Double-1>", lambda e: self.edit_group())
        self.tree.tag_configure("warn", background="#fff0c2")

        ttk.Label(self, text="Devices (from SolarWinds imports, or added by hand)",
                  font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=6)
        db = ttk.Frame(self)
        db.pack(fill="x", padx=6, pady=2)
        for text, cmd in (("Move to group...", self.set_override), ("Undo move (use pattern)", self.clear_override),
                          ("Add device...", self.add_device), ("Forget device", self.forget_device)):
            ttk.Button(db, text=text, command=cmd).pack(side="left", padx=(0, 6))
        df, self.dev_tree = make_tree(self, [("host", "Hostname", 220), ("ip", "IP", 180), ("group", "Group", 200),
                                             ("how", "How it got there", 260)], height=10, selectmode="extended")
        df.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.dev_tree.tag_configure("none", background="#fff0c2")

    def groups(self):
        return self.app.groups_db["groups"]

    def refresh(self):
        keep = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        members = {}
        for host in self.app.groups_db["known_devices"]:
            gid, _ = assess.assign_group(host, self.app.groups_db)
            members[gid] = members.get(gid, 0) + 1
        for g in self.groups():
            cov = assess.coverage(g, self.app.rules_db, self.app.index)
            auto, total = sum(r["automated"] for r in cov), sum(r["total"] for r in cov)
            missing = [s for s in g.get("stigs", []) if s not in self.app.index]
            self.tree.insert("", "end", iid=g["id"], tags=("warn",) if missing or not g.get("stigs") else (),
                             values=(g["id"], g.get("description", ""),
                                     ", ".join(f"{self.app.short(s)} [{self.app.formats_text(s)}]"
                                               for s in g.get("stigs", [])) or "(none chosen)",
                                     ", ".join(g.get("patterns", [])), members.get(g["id"], 0),
                                     f"{auto} of {total}"))
        keep = [k for k in keep if self.tree.exists(k)]
        if keep:
            self.tree.selection_set(keep)
        self.dev_tree.delete(*self.dev_tree.get_children())
        for host, ip in sorted(self.app.groups_db["known_devices"].items()):
            gid, how = assess.assign_group(host, self.app.groups_db)
            how = {"override": "moved by hand", "unassigned": "no pattern matches"}.get(how, how)
            self.dev_tree.insert("", "end", iid=host, tags=("none",) if not gid else (),
                                 values=(host, ip, gid or "(not in a group - will not be assessed)", how))

    def selected(self):
        sel = self.tree.selection()
        return assess.find_group(self.app.groups_db, sel[0]) if sel else None

    def new_group(self):
        if not self.app.index:
            return messagebox.showinfo("Groups", "Import checklists on tab 1 first.")
        GroupDialog(self.app, None)
        self.after_change()

    def edit_group(self):
        g = self.selected()
        if g:
            GroupDialog(self.app, g)
            self.after_change()

    def copy_group(self):
        g = self.selected()
        if g:
            GroupDialog(self.app, g, copy_of=True)
            self.after_change()

    def delete_group(self):
        g = self.selected()
        if g and messagebox.askyesno("Delete group", f"Delete group {g['id']} for everyone? Devices moved into it "
                                                     "by hand go back to pattern matching."):
            store.delete_group(g["id"])
            self.after_change()

    def choose_rules(self):
        g = self.selected()
        if not g:
            return messagebox.showinfo("Rule versions", "Select a group first.")
        RuleChoicesDialog(self.app, g)
        self.after_change()

    def set_override(self):
        hosts = self.dev_tree.selection()
        ids = [g["id"] for g in self.groups()]
        if not hosts or not ids:
            return
        gid = ask_choice(self, "Move devices", f"Put {len(hosts)} device(s) in which group?", ids)
        if gid:
            for h in hosts:
                store.set_override(h, gid)
            self.after_change()

    def clear_override(self):
        for h in self.dev_tree.selection():
            store.set_override(h, None)
        self.after_change()

    def add_device(self):
        host = simpledialog.askstring("Add device", "Hostname exactly as SolarWinds shows it:", parent=self)
        if not host or not host.strip():
            return
        ip = simpledialog.askstring("Add device", "IP address (optional):", parent=self) or ""
        store.add_known_devices({host.strip(): ip.strip()})
        self.after_change()

    def forget_device(self):
        hosts = self.dev_tree.selection()
        if hosts and messagebox.askyesno("Forget devices", f"Remove {len(hosts)} device(s) from the list? They come "
                                                           "back automatically the next time they appear in an "
                                                           "import."):
            for h in hosts:
                store.forget_device(h)
            self.after_change()

    def after_change(self):
        self.app.load_data()
        self.refresh()


class GroupDialog(tk.Toplevel):
    """Create or edit a group in three plain steps."""

    def __init__(self, app, group, copy_of=False):
        super().__init__(app)
        self.app = app
        self.is_new = group is None or copy_of
        self.group = copy.deepcopy(group) if group else {"id": "", "description": "", "patterns": [], "stigs": [],
                                                         "rule_choices": {}}
        if copy_of:
            self.group.update(id=group["id"] + "-COPY", _rev=0)
        self.title("New device group" if self.is_new else f"Edit group {group['id']}")
        self.transient(app)
        self.geometry("1050x760")
        self.added = set()      # hostnames to move into this group by hand on save
        self.removed = set()    # hostnames moved in by hand earlier, to release on save

        f = ttk.Frame(self, padding=10)
        f.pack(fill="both", expand=True)
        step = lambda n, text: ttk.Label(f, text=f"Step {n}.  {text}", font=("Segoe UI", 10, "bold")).pack(
            anchor="w", pady=(10, 2))

        step(1, "Name the group")
        row = ttk.Frame(f)
        row.pack(fill="x")
        ttk.Label(row, text="Group ID:").pack(side="left")
        self.id_var = tk.StringVar(value=self.group["id"])
        ttk.Entry(row, textvariable=self.id_var, width=24, state="normal" if self.is_new else "disabled").pack(
            side="left", padx=4)
        ttk.Label(row, text="e.g. CAMPUS-ACCESS (letters, numbers, - and _)", foreground="#666").pack(side="left")
        row2 = ttk.Frame(f)
        row2.pack(fill="x", pady=2)
        ttk.Label(row2, text="Description:").pack(side="left")
        self.desc_var = tk.StringVar(value=self.group.get("description", ""))
        ttk.Entry(row2, textvariable=self.desc_var, width=80).pack(side="left", padx=4)

        step(2, "Tick every STIG these devices must be assessed against (click a row to tick / untick)")
        team = app.output_format
        ttk.Label(f, text=f"The team writes {checklist.FORMAT_LABELS[team]} files (tab 1). A STIG with no file in that "
                          "format is highlighted - import that file on tab 1.", foreground="#555").pack(anchor="w")
        sf, self.stig_tree = make_tree(f, [("use", "Use", 45), ("stig", "STIG", 330), ("rel", "Release", 160),
                                           ("fmt", "Imported as", 230), ("auto", "Automated", 110)], height=6)
        sf.pack(fill="x")
        self.stig_tree.tag_configure("on", background="#d9f7d6")
        self.stig_tree.tag_configure("missing", foreground="#b00020")
        self.stig_tree.bind("<ButtonRelease-1>", lambda e: self.toggle_stig(self.stig_tree.identify_row(e.y)))
        self.stig_tree.bind("<space>", lambda e: self.toggle_stig(self.stig_tree.focus()))
        self.chosen = set(self.group["stigs"])
        self.render_stigs()

        step(3, "Say which devices belong")
        dev = ttk.Frame(f)
        dev.pack(fill="both", expand=True)
        dev.columnconfigure(0, weight=1)
        dev.columnconfigure(1, weight=2)
        dev.rowconfigure(1, weight=1)
        ttk.Label(dev, text="Hostname patterns, one per line.\n* means 'anything'. Examples:\n  *-ACCESS\n  SITE-1?-AS*",
                  justify="left").grid(row=0, column=0, sticky="w")
        self.patterns = tk.Text(dev, height=6, width=30, font=MONO)
        self.patterns.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
        self.patterns.insert("1.0", "\n".join(self.group.get("patterns", [])))
        self.patterns.bind("<KeyRelease>", lambda e: self.update_preview())
        ttk.Label(dev, text="Devices that will be in this group (live preview):").grid(row=0, column=1, sticky="sw")
        pf, self.preview = make_tree(dev, [("host", "Hostname", 200), ("why", "Why", 300)], height=8)
        pf.grid(row=1, column=1, sticky="nsew")
        self.preview.tag_configure("hand", background="#dde9ff")
        self.preview.tag_configure("lost", background="#fff0c2")
        pb = ttk.Frame(dev)
        pb.grid(row=2, column=1, sticky="w", pady=4)
        ttk.Button(pb, text="Add a device by hand...", command=self.add_by_hand).pack(side="left")
        ttk.Button(pb, text="Remove hand-added device", command=self.remove_by_hand).pack(side="left", padx=6)

        self.summary = ttk.Label(f, text="", font=("Segoe UI", 10), foreground="#1b4f8a")
        self.summary.pack(anchor="w", pady=(10, 0))
        b = ttk.Frame(f)
        b.pack(fill="x", pady=(8, 0))
        ttk.Button(b, text="Save group", command=self.save).pack(side="left")
        ttk.Button(b, text="Cancel", command=self.destroy).pack(side="left", padx=6)
        self.update_preview()
        self.grab_set()
        app.wait_window(self)

    def current(self):
        g = dict(self.group)
        g["id"] = self.id_var.get().strip().upper().replace(" ", "-")
        g["description"] = self.desc_var.get().strip()
        g["patterns"] = [p.strip() for p in text_get(self.patterns).splitlines() if p.strip()]
        g["stigs"] = [s for s in list(self.app.index) + sorted(self.chosen - set(self.app.index))
                      if s in self.chosen]
        return g

    def render_stigs(self):
        team = self.app.output_format
        self.stig_tree.delete(*self.stig_tree.get_children())
        for s in list(self.app.index) + sorted(self.chosen - set(self.app.index)):
            stig = self.app.index.get(s)
            on = s in self.chosen
            if stig:
                active = sum(1 for v in stig["order"] if assess.resolve_rule(self.group, self.app.rules_db, s, v))
                fmt = self.app.formats_text(s)
                if team not in stig["formats"]:
                    fmt += f"  - no {FORMAT_SHORT[team].split()[0]} file!"
                values = ("[X]" if on else "[  ]", stig["short"], stig["release"], fmt,
                          f"{active} of {len(stig['order'])}")
                tags = (("on",) if on else ()) + (("missing",) if team not in stig["formats"] else ())
            else:
                values, tags = ("[X]" if on else "[  ]", s, "-", "not imported any more", "-"), ("missing",)
            self.stig_tree.insert("", "end", iid=s, values=values, tags=tags)

    def toggle_stig(self, row):
        if not row:
            return
        self.chosen.symmetric_difference_update({row})
        self.render_stigs()
        self.stig_tree.focus(row)
        self.stig_tree.selection_set(row)
        self.update_preview()

    def simulated(self):
        """groups_db as it would be after saving, to preview membership."""
        g = self.current()
        db = copy.deepcopy(self.app.groups_db)
        db["groups"] = [x for x in db["groups"] if x["id"] != (self.group["id"] or g["id"])]
        db["groups"].append(g)
        db["groups"].sort(key=lambda x: x["id"])
        for h in self.removed:
            db["device_overrides"].pop(h, None)
        for h in self.added:
            db["device_overrides"][h] = g["id"]
        return g, db

    def update_preview(self):
        g, db = self.simulated()
        self.preview.delete(*self.preview.get_children())
        n = 0
        for host in sorted(db["known_devices"]):
            gid, how = assess.assign_group(host, db)
            mine = any(fnmatch.fnmatch(host, p.upper()) for p in g["patterns"])
            if gid == g["id"]:
                n += 1
                self.preview.insert("", "end", iid=host, tags=("hand",) if how == "override" else (),
                                    values=(host, "added by hand" if how == "override" else f"matches {how[8:]}"))
            elif mine:
                why = f"moved by hand to {gid}" if how == "override" else f"already taken by group {gid}"
                self.preview.insert("", "end", iid=host, tags=("lost",), values=(host, f"NOT included: {why}"))
        cov = assess.coverage(g, self.app.rules_db, self.app.index)
        auto, total = sum(r["automated"] for r in cov), sum(r["total"] for r in cov)
        self.summary.configure(text=f"This group will have {len(g['stigs'])} STIG checklist(s), {n} known "
                                    f"device(s), and {auto} of {total} controls automated.")

    def add_by_hand(self):
        g, db = self.simulated()
        others = sorted(h for h in db["known_devices"] if assess.assign_group(h, db)[0] != g["id"])
        typed = "(type a hostname that has not been imported yet)"
        pick = ask_choice(self, "Add device", "Which device should always be in this group?", [typed] + others)
        if pick == typed:
            pick = simpledialog.askstring("Add device", "Hostname exactly as SolarWinds shows it:", parent=self)
            if pick and pick.strip():
                store.add_known_devices({pick.strip(): ""})
                self.app.groups_db["known_devices"][pick.strip().upper()] = ""
        if pick and pick.strip():
            self.added.add(pick.strip().upper())
            self.removed.discard(pick.strip().upper())
            self.update_preview()

    def remove_by_hand(self):
        sel = self.preview.selection()
        if not sel:
            return
        host = sel[0]
        if host in self.added:
            self.added.discard(host)
        elif self.app.groups_db["device_overrides"].get(host) == self.group["id"]:
            self.removed.add(host)
        else:
            return messagebox.showinfo("Remove", "That device is here because it matches a pattern. Change the "
                                                 "patterns, or move it to another group in the device list.",
                                       parent=self)
        self.update_preview()

    def save(self):
        g = self.current()
        if not g["id"] or any(not (ch.isalnum() or ch in "-_") for ch in g["id"]):
            return messagebox.showerror("Group ID", "Use letters, numbers, - and _ only.", parent=self)
        if self.is_new and store.group_path(g["id"]).exists():
            return messagebox.showerror("Group ID", f"A group called {g['id']} already exists.", parent=self)
        if not g["stigs"] and not messagebox.askyesno("No STIGs", "No STIG checklists are ticked, so nothing will "
                                                                  "be assessed for this group. Save anyway?",
                                                      parent=self):
            return
        try:
            store.save_group(g, check=not self.is_new)
        except store.ConflictError as e:
            if not messagebox.askyesno("Changed by someone else",
                                       f"{e.current.get('saved_by')} saved this group at {e.current.get('saved_at')} "
                                       "while you were editing. Overwrite their changes with yours?", parent=self):
                return
            g["_rev"] = e.current.get("_rev", 0)
            store.save_group(g)
        for h in self.removed:
            store.set_override(h, None)
        for h in self.added:
            store.set_override(h, g["id"])
        self.destroy()


class PortRolesDialog(tk.Toplevel):
    """Team setting: the interface-description keywords that mark uplink / downlink / access ports."""

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Port roles")
        self.transient(app)
        self.resizable(False, False)
        f = ttk.Frame(self, padding=12)
        f.pack()
        ttk.Label(f, justify="left", wraplength=620, text=(
            "Rules find uplinks, downlinks and client ports by the START of the interface description, so the "
            "port number does not matter. Label ports like 'description UPLINK - DIST-SW-01 Te2/0/14' or "
            "'description ACCESS - Room 112 jack 4'. Separate several keywords with commas. Upper / lower case "
            "does not matter. In a rule, use role:uplink, role:downlink, role:access or role:any.")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
        self.vars = {}
        labels = {"uplink": "Uplinks (toward distribution / core):",
                  "downlink": "Downlinks (toward access switches):",
                  "access": "Access / client ports (untrusted):"}
        for r, role in enumerate(("uplink", "downlink", "access"), 1):
            ttk.Label(f, text=labels[role]).grid(row=r, column=0, sticky="w", pady=3)
            var = tk.StringVar(value=app.settings["port_roles"][role])
            ttk.Entry(f, textvariable=var, width=36).grid(row=r, column=1, sticky="w", padx=6)
            self.vars[role] = var
        b = ttk.Frame(f)
        b.grid(row=5, column=0, columnspan=2, pady=(10, 0))
        ttk.Button(b, text="Save", command=self.save).pack(side="left", padx=4)
        ttk.Button(b, text="Cancel", command=self.destroy).pack(side="left", padx=4)
        self.grab_set()
        app.wait_window(self)

    def save(self):
        roles = {k: ", ".join(w.strip() for w in v.get().split(",") if w.strip()) for k, v in self.vars.items()}
        if not all(roles.values()):
            return messagebox.showerror("Port roles", "Every role needs at least one keyword.", parent=self)
        store.set_setting("port_roles", roles)
        self.app.reload()
        self.destroy()


class RuleChoicesDialog(tk.Toplevel):
    def __init__(self, app, group):
        super().__init__(app)
        self.app, self.group_id = app, group["id"]
        self.title(f"Rule versions for {group['id']}")
        self.geometry("1100x650")
        self.transient(app)
        help_label(self, "Only needed when a control has more than one rule version (e.g. 'Access' and 'Core'). "
                         "Double-click a control to choose the version this group uses. 'Default' follows whichever "
                         "version is marked default in the work queue. 'Manual' means no automated check for this "
                         "group.")
        self.only_multi = tk.BooleanVar(value=True)
        ttk.Checkbutton(self, text="Only show controls with more than one active version", variable=self.only_multi,
                        command=self.refresh).pack(anchor="w", padx=6)
        frame, self.tree = make_tree(self, [("stig", "STIG", 200), ("vuln", "Vuln ID", 80), ("title", "Title", 420),
                                            ("choice", "Group uses", 260)], height=20)
        frame.pack(fill="both", expand=True, padx=6, pady=6)
        self.tree.bind("<Double-1>", lambda e: self.choose())
        self.empty = ttk.Label(self, text="", foreground="#666")
        self.empty.pack()
        ttk.Button(self, text="Close", command=self.destroy).pack(pady=6)
        self.refresh()
        self.grab_set()
        app.wait_window(self)

    def group(self):
        return store.load_json(store.group_path(self.group_id), None) or {"stigs": [], "rule_choices": {}}

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        group = self.group()
        choices = group.get("rule_choices") or {}
        shown = 0
        for stig_id, control, rule in assess.group_plan(group, self.app.rules_db, self.app.index):
            active = [r for r in assess.rules_for_control(self.app.rules_db, stig_id, control["vuln_id"])
                      if r.get("state") == "active"]
            if self.only_multi.get() and len(active) < 2:
                continue
            key = assess.key_of(stig_id, control["vuln_id"])
            raw = choices.get(key)
            if raw == "manual":
                label_ = "Manual (no automated check)"
            elif rule:
                label_ = f"{rule['id']} {rule.get('name', '')}" + ("" if raw else "  (default)")
            else:
                label_ = "- no active rule -"
            self.tree.insert("", "end", iid=key, values=(self.app.short(stig_id), control["vuln_id"],
                                                         control["title"], label_))
            shown += 1
        self.empty.configure(text="" if shown else "Nothing to choose: no control in this group has more than one "
                                                   "active rule version.")

    def choose(self):
        sel = self.tree.selection()
        if not sel:
            return
        stig_id, vuln_id = sel[0].split("|", 1)
        active = [r for r in assess.rules_for_control(self.app.rules_db, stig_id, vuln_id)
                  if r.get("state") == "active"]
        options = ["Default"] + [f"{r['id']} {r.get('name', '')}" for r in active] + ["Manual (no automated check)"]
        pick = ask_choice(self, "Rule version", f"Which version should {self.group_id} use for {vuln_id}?", options)
        if not pick:
            return

        def change(g):
            choices = g.setdefault("rule_choices", {})
            if pick == "Default":
                choices.pop(sel[0], None)
            elif pick.startswith("Manual"):
                choices[sel[0]] = "manual"
            else:
                choices[sel[0]] = pick.split()[0]
        store.modify_group(self.group_id, change)
        self.refresh()


# ---------------------------------------------------------------- 4. collection script

class ScriptTab(ttk.Frame):
    def __init__(self, nb, app):
        super().__init__(nb)
        self.app = app
        help_label(self, "Step 4 - Tick the groups you are collecting from and click Generate. One script covers "
                         "every ticked group. Paste it into SolarWinds 'Execute Command Script', run it against the "
                         "devices, and save the output as a text file (the input folder is a good place). Do not "
                         "remove the '! CMD:' lines - they tie each output block to its command.")
        top = ttk.Frame(self)
        top.pack(fill="x", padx=6)
        self.group_frame = ttk.LabelFrame(top, text="Groups")
        self.group_frame.pack(side="left", fill="y")
        btns = ttk.Frame(top)
        btns.pack(side="left", padx=10, anchor="n")
        ttk.Button(btns, text="Generate script", command=self.generate).pack(fill="x")
        ttk.Button(btns, text="Copy to clipboard", command=self.copy).pack(fill="x", pady=4)
        ttk.Button(btns, text="Open scripts folder", command=lambda: open_folder(store.paths.output / "scripts")).pack(
            fill="x")
        self.info = ttk.Label(top, text="", justify="left", wraplength=700)
        self.info.pack(side="left", padx=10, anchor="n")
        self.text = ScrolledText(self, font=MONO, wrap="none")
        self.text.pack(fill="both", expand=True, padx=6, pady=6)
        self.vars = {}

    def refresh(self):
        old = {k: v.get() for k, v in self.vars.items()}
        for w in self.group_frame.winfo_children():
            w.destroy()
        self.vars = {}
        for g in self.app.groups_db.get("groups", []):
            var = tk.BooleanVar(value=old.get(g["id"], False))
            names = ", ".join(self.app.short(s) for s in g.get("stigs", []))
            ttk.Checkbutton(self.group_frame, text=f"{g['id']}  ({names})", variable=var).pack(anchor="w", padx=6)
            self.vars[g["id"]] = var
        if not self.vars:
            ttk.Label(self.group_frame, text="Create groups on tab 3 first.").pack(padx=6, pady=6)

    def generate(self):
        groups = [g for g in self.app.groups_db.get("groups", []) if self.vars.get(g["id"], tk.BooleanVar()).get()]
        if not groups:
            return messagebox.showinfo("Script", "Tick at least one group.")
        sources = assess.commands_for_groups(groups, self.app.rules_db, self.app.index)
        if not sources:
            return messagebox.showinfo("Script", "These groups have no active rules yet, so there is nothing to "
                                                 "collect. Activate rules on the Work Queue tab.")
        script, sid = collect.build_script(sources, [g["id"] for g in groups])
        store.save_script_record({"script_id": sid, "created": store.now(), "created_by": store.current_user(),
                                  "groups": [g["id"] for g in groups], "commands": sorted(sources)})
        path = store.paths.output / "scripts" / f"collect_{'_'.join(g['id'] for g in groups)[:80]}_{sid}.txt"
        path.write_text(script, encoding="utf-8")
        text_set(self.text, script)
        lines = [f"{len(sources)} unique command(s). Saved to {path}"]
        for g in groups:
            lines.append(f"{g['id']}:")
            for r in assess.coverage(g, self.app.rules_db, self.app.index):
                line = (f"   {r['short']}: {r['automated']} of {r['total']} automated, {r['manual']} manual, "
                        f"{r['no_rule'] + r['draft']} not built yet")
                if r["changed"]:
                    line += f"  - WARNING: {r['changed']} rule(s) need review after a STIG update"
                lines.append(line)
        self.info.configure(text="\n".join(lines))

    def copy(self):
        self.clipboard_clear()
        self.clipboard_append(text_get(self.text))


# ---------------------------------------------------------------- 5. import and review

class AssessTab(ttk.Frame):
    FILTERS = ["Everything", "Needs attention (unexpected Open / Not Reviewed)", "Open", "Open (expected)",
               "Not Reviewed",
               "Not Applicable", "Not a Finding", "Manual (no rule)", "Changed by reviewer"]

    def __init__(self, nb, app):
        super().__init__(nb)
        self.app = app
        help_label(self, "Step 5 - Import the SolarWinds output file. Check every device landed in the right group, "
                         "then review the results group by group. The tool only RECOMMENDS a result: you can change "
                         "any of them (a reason is required). When done, write the checklist package for the group. "
                         "Missing, failed or invalid evidence is never treated as a pass.")
        top = ttk.Frame(self)
        top.pack(fill="x", padx=6)
        ttk.Button(top, text="Import SolarWinds output...", command=self.do_import).pack(side="left")
        ttk.Button(top, text="Open previous run...", command=self.open_run).pack(side="left", padx=4)
        ttk.Button(top, text="Re-run assessment", command=self.reevaluate).pack(side="left", padx=4)
        self.run_label = ttk.Label(top, text="", foreground="#333")
        self.run_label.pack(side="left", padx=10)

        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True, padx=6, pady=6)
        dev = ttk.Frame(paned)
        paned.add(dev, weight=1)
        df, self.dev_tree = make_tree(dev, [("host", "Device", 160), ("ip", "IP", 140), ("group", "Group", 150),
                                            ("how", "Assigned by", 130), ("state", "Collection", 260),
                                            ("cmds", "Commands", 100)], height=5, selectmode="extended")
        df.pack(fill="both", expand=True)
        color_tags(self.dev_tree, {"bad": "#ffd6d6", "nogroup": "#fff0c2"})
        db = ttk.Frame(dev)
        db.pack(fill="x", pady=2)
        ttk.Button(db, text="Change group of selected devices...", command=self.change_group).pack(side="left")
        self.warn_label = ttk.Label(db, text="", foreground="#9a6a00")
        self.warn_label.pack(side="left", padx=10)

        rev = ttk.Frame(paned)
        paned.add(rev, weight=3)
        bar = ttk.Frame(rev)
        bar.pack(fill="x")
        ttk.Label(bar, text="Group:").pack(side="left")
        self.group_var = tk.StringVar()
        self.group_box = ttk.Combobox(bar, textvariable=self.group_var, state="readonly", width=24)
        self.group_box.pack(side="left", padx=4)
        self.group_box.bind("<<ComboboxSelected>>", lambda e: self.show_results())
        ttk.Label(bar, text="Show:").pack(side="left", padx=(10, 0))
        self.filter_var = tk.StringVar(value=self.FILTERS[0])
        fb = ttk.Combobox(bar, textvariable=self.filter_var, values=self.FILTERS, state="readonly", width=34)
        fb.pack(side="left", padx=4)
        fb.bind("<<ComboboxSelected>>", lambda e: self.show_results())
        self.count_label = ttk.Label(bar, text="")
        self.count_label.pack(side="left", padx=10)

        inner = ttk.PanedWindow(rev, orient="horizontal")
        inner.pack(fill="both", expand=True, pady=4)
        rf, self.res_tree = make_tree(inner, [("fam", "STIG", 170), ("vuln", "Vuln ID", 75), ("ver", "Rule Ver", 110),
                                              ("rec", "Recommended", 120), ("final", "Final", 120),
                                              ("devs", "Devices", 110), ("title", "Title", 200)],
                                      height=14, selectmode="extended")
        color_tags(self.res_tree, STATUS_ROW)
        inner.add(rf, weight=3)
        self.res_tree.bind("<<TreeviewSelect>>", lambda e: self.show_detail())
        side = ttk.Frame(inner)
        inner.add(side, weight=2)
        self.detail = ScrolledText(side, height=14, wrap="none", font=("Consolas", 9))
        self.detail.pack(fill="both", expand=True)
        act = ttk.Frame(side)
        act.pack(fill="x", pady=4)
        ttk.Label(act, text="Final result:").grid(row=0, column=0, sticky="w")
        self.final_var = tk.StringVar()
        ttk.Combobox(act, textvariable=self.final_var, state="readonly", width=18,
                     values=[STATUS_LABELS[s] for s in STATUSES] + ["Manual (unchanged)"]).grid(row=0, column=1,
                                                                                            sticky="w")
        ttk.Label(act, text="Reviewer comment:").grid(row=1, column=0, sticky="nw")
        self.comment = tk.Text(act, height=3, width=48, wrap="word", font=("Segoe UI", 9))
        self.comment.grid(row=1, column=1, sticky="we")
        ab = ttk.Frame(act)
        ab.grid(row=2, column=1, sticky="w", pady=4)
        ttk.Button(ab, text="Apply to selected", command=self.apply).pack(side="left")
        ttk.Button(ab, text="Reset to recommendation", command=self.reset).pack(side="left", padx=4)

        bottom = ttk.Frame(self)
        bottom.pack(fill="x", padx=6, pady=(0, 6))
        ttk.Label(bottom, text="Reviewer name:").pack(side="left")
        self.reviewer = tk.StringVar(value=store.current_user())
        ttk.Entry(bottom, textvariable=self.reviewer, width=24).pack(side="left", padx=4)
        ttk.Button(bottom, text="Write checklist package for this group",
                   command=lambda: self.write(all_groups=False)).pack(side="left", padx=8)
        ttk.Button(bottom, text="Write packages for all groups",
                   command=lambda: self.write(all_groups=True)).pack(side="left")
        ttk.Button(bottom, text="Open output folder", command=lambda: open_folder(store.paths.output)).pack(
            side="left", padx=8)
        self.fmt_label = ttk.Label(bottom, text="", foreground="#1b4f8a")
        self.fmt_label.pack(side="left", padx=10)

    # -- data
    def refresh(self):
        run = self.app.run
        self.fmt_label.configure(text=f"Writes {checklist.FORMAT_LABELS[self.app.output_format]} files "
                                      "(team setting on tab 1)")
        self.dev_tree.delete(*self.dev_tree.get_children())
        if not run:
            self.run_label.configure(text="No run loaded. Import a SolarWinds output file to start.")
            self.group_box["values"] = []
            self.show_results()
            return
        self.run_label.configure(text=f"Run {run['id']} - {run['source_name']} - {len(run['devices'])} devices"
                                      + (f" - assessed {run['evaluated']}" if run.get("evaluated") else ""))
        for d in run["devices"]:
            m = run["membership"].get(d["host"], {"group": "", "how": "unassigned"})
            if d["status"] != "ok":
                state, tag = f"FAILED: {d['error']}", "bad"
            else:
                bad = [c for c, o in d["outputs"].items() if o["status"] != "ok"]
                state = "OK" + (f", {len(bad)} invalid command(s)" if bad else "")
                tag = "bad" if bad else ("nogroup" if not m["group"] else "")
            self.dev_tree.insert("", "end", iid=d["host"], tags=(tag,),
                                 values=(d["host"], d["ip"], m["group"] or "(none - not assessed)", m["how"], state,
                                         f"{len(d['outputs'])} collected"))
        self.warn_label.configure(text="; ".join(run.get("warnings", []))[:200])
        groups = sorted(run.get("results", {}))
        self.group_box["values"] = groups
        if self.group_var.get() not in groups:
            self.group_var.set(groups[0] if groups else "")
        self.show_results()

    def results(self):
        if not self.app.run:
            return None
        return self.app.run.get("results", {}).get(self.group_var.get())

    def show_results(self):
        keep = self.res_tree.selection()
        self.res_tree.delete(*self.res_tree.get_children())
        res = self.results()
        if not res:
            self.count_label.configure(text="")
            self.show_detail()
            return
        f = self.filter_var.get()
        counts = {}
        for key, c in res["controls"].items():
            final = c["final"]
            shown_as = assess.result_label(c)
            counts[shown_as] = counts.get(shown_as, 0) + 1
            if f.startswith("Needs") and (final not in ("open", "not_reviewed") or assess.is_expected_open(c)):
                continue
            if (f in STATUS_LABELS.values() or f == "Open (expected)") and shown_as != f:
                continue
            if f.startswith("Manual") and c["rule_id"]:
                continue
            if f.startswith("Changed") and not c["reviewer_changed"]:
                continue
            per = {}
            for r in c["per_device"].values():
                per[r["status"]] = per.get(r["status"], 0) + 1
            devs = ", ".join(f"{n} {SHORT[s]}" for s, n in sorted(per.items())) or "-"
            tag = "changed" if c["reviewer_changed"] else (
                "expected" if assess.is_expected_open(c) else (final or "manual"))
            self.res_tree.insert("", "end", iid=key, tags=(tag,),
                                 values=(c["family"], c["vuln_id"], c["rule_ver"],
                                         assess.result_label(c, "recommended"), shown_as, devs, c["title"]))
        self.count_label.configure(text="   ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
        keep = [k for k in keep if self.res_tree.exists(k)]
        if keep:
            self.res_tree.selection_set(keep)
        self.show_detail()

    def selected(self):
        res = self.results()
        return [res["controls"][k] for k in self.res_tree.selection()] if res else []

    def show_detail(self):
        sel = self.selected()
        if not sel:
            text_set(self.detail, "", readonly=True)
            return
        c = sel[0]
        lines = [f"{c['family']} {c['vuln_id']} {c['rule_ver']} [{c['severity']}]", c["title"], ""]
        if c["rule_id"]:
            prefix = assess.outcome_prefix(c)
            if assess.is_expected_open(c):
                lines += ["EXPECTED FINDING: the rule marks Open as intentional for this control.", ""]
            field = assess.FIELD_LABELS[self.app.settings["text_placement"].get(c["final"] or "", "comments")]
            lines += [f"For {assess.label(c['final'])} this reason is written to the checklist's {field.upper()}:",
                      ""]
            if prefix:
                lines += [prefix, ""]
            lines.append(c["details"])
        else:
            lines.append("No rule for this control in this group (manual). The checklist keeps the template's "
                         f"current value ({STATUS_LABELS.get(c.get('template_status'), '?')}) unless you set a "
                         "final result here.")
        if c["reviewer_changed"] or c.get("reviewer_comment"):
            lines += ["", f"Reviewer: final {assess.label(c['final'])} - {c.get('reviewer_comment', '')}"]
        text_set(self.detail, "\n".join(lines), readonly=True)
        self.final_var.set(assess.label(c["final"]))
        text_set(self.comment, c.get("reviewer_comment", ""))

    # -- actions
    def do_import(self):
        path = filedialog.askopenfilename(title="Choose SolarWinds output file", initialdir=str(store.paths.input),
                                          filetypes=[("Text files", "*.txt *.log"), ("All files", "*.*")])
        if not path:
            return
        run = assess.import_solarwinds(path, self.app.groups_db, self.app.rules_db)
        store.add_known_devices({d["host"]: d["ip"] for d in run["devices"]})
        assess.evaluate_run(run, self.app.groups_db, self.app.rules_db, self.app.index)
        self.app.set_run(run)
        self.app.save_run()
        self.refresh()
        bad = [d["host"] for d in run["devices"] if d["status"] != "ok"]
        nogroup = [h for h, m in run["membership"].items() if not m["group"]]
        msg = [f"{len(run['devices'])} device(s) imported."]
        if bad:
            msg.append(f"Collection failed for: {', '.join(bad)}")
        if nogroup:
            msg.append(f"Not in any group (not assessed): {', '.join(nogroup)}")
        msg += run.get("warnings", [])
        messagebox.showinfo("Import", "\n".join(msg))

    def open_run(self):
        runs = store.list_runs()
        if not runs:
            return messagebox.showinfo("Runs", "No previous runs.")
        loaded = [(p, store.load_run(p)) for p in runs[:50]]
        labels = [f"{r['id']}  {r['source_name']}  ({len(r['devices'])} devices, by {r.get('created_by', '?')}"
                  f"{', last saved by ' + r['saved_by'] if r.get('saved_by') else ''})" for _, r in loaded]
        pick = ask_choice(self, "Open run", "Open which assessment run?", labels)
        if pick:
            path, run = loaded[labels.index(pick)]
            self.app.set_run(run, path.stat().st_mtime)
            self.refresh()

    def reevaluate(self):
        run = self.app.run
        if not run:
            return
        for host, m in run["membership"].items():
            gid, how = assess.assign_group(host, self.app.groups_db)
            m.update(group=gid, how=how)
        assess.evaluate_run(run, self.app.groups_db, self.app.rules_db, self.app.index)
        self.app.save_run()
        self.refresh()

    def change_group(self):
        run = self.app.run
        hosts = self.dev_tree.selection()
        ids = [g["id"] for g in self.app.groups_db.get("groups", [])]
        if not run or not hosts or not ids:
            return
        gid = ask_choice(self, "Change group", f"Put {len(hosts)} device(s) in which group? "
                                               "(saved as an override for future runs too)", ids)
        if not gid:
            return
        for h in hosts:
            store.set_override(h, gid)
        self.app.load_data()
        self.reevaluate()

    def apply(self):
        sel = self.selected()
        if not sel:
            return
        label = self.final_var.get()
        final = None if label.startswith("Manual") else LABEL_TO_STATUS[label]
        comment = text_get(self.comment).strip()
        for c in sel:
            if final is None and c["rule_id"]:
                return messagebox.showerror("Not allowed", f"{c['vuln_id']} has a rule; choose a result.")
        if any(final != c["recommended"] for c in sel) and not comment:
            return messagebox.showerror("Reason needed", "You are changing the recommended result. "
                                                         "Type a reviewer comment explaining why.")
        for c in sel:
            c["final"] = final
            c["reviewer_comment"] = comment
            c["reviewer_changed"] = final != c["recommended"]
        self.app.save_run()
        self.show_results()

    def reset(self):
        for c in self.selected():
            c.update(final=c["recommended"], reviewer_comment="", reviewer_changed=False)
        self.app.save_run()
        self.show_results()

    def write(self, all_groups):
        run = self.app.run
        if not run or not run.get("results"):
            return messagebox.showinfo("Write", "Nothing to write - import and assess a SolarWinds output first.")
        reviewer = self.reviewer.get().strip()
        if not reviewer:
            return messagebox.showerror("Reviewer", "Enter the reviewer name.")
        groups = sorted(run["results"]) if all_groups else [self.group_var.get()]
        fmt = self.app.output_format
        summary = [f"Format: {checklist.FORMAT_LABELS[fmt]}", ""]
        for gid in groups:
            summary.append(f"{gid}:")
            per = {}
            for c in run["results"][gid]["controls"].values():
                per.setdefault(c["family"], {}).setdefault(assess.label(c["final"]), 0)
                per[c["family"]][assess.label(c["final"])] += 1
            cov = {r["short"]: r for r in run.get("coverage", {}).get(gid, [])}
            group = assess.find_group(self.app.groups_db, gid) or {"stigs": []}
            for stig_id in group["stigs"]:
                name = self.app.short(stig_id)
                r = cov.get(name)
                head = f"   {name}: {r['automated']}/{r['total']} automated" if r else f"   {name}:"
                if fmt not in store.templates_for(stig_id):
                    head += f"  - NO {checklist.FORMAT_LABELS[fmt]} FILE, will be skipped"
                summary.append(head)
                summary.append("      " + ", ".join(f"{v} {k}" for k, v in sorted(per.get(name, {}).items())))
        if not messagebox.askyesno("Confirm", "Write checklist package(s)?\n\n" + "\n".join(summary) +
                                   f"\n\nBy continuing, {reviewer} confirms these results were reviewed."):
            return
        report, last = [], None
        for gid in groups:
            folder, ok, msgs = assess.write_package(run, gid, reviewer, self.app.groups_db, self.app.rules_db, fmt,
                                                    self.app.settings["text_placement"])
            report += msgs + [""]
            last = folder
        self.app.save_run()
        if messagebox.askyesno("Done", "\n".join(report) + "\nOpen the output folder?"):
            open_folder(last if len(groups) == 1 else store.paths.output)


# ---------------------------------------------------------------- 6. hardening script

class HardenTab(ttk.Frame):
    def __init__(self, nb, app):
        super().__init__(nb)
        self.app = app
        help_label(self, "Step 6 (optional) - Build configuration scripts that FIX findings, from each rule's Fix "
                         "commands. Two scripts are always written separately: LOW IMPACT (banners, logging, "
                         "archive, timestamps, legacy services) and IMPACTFUL (AAA, SSH, vty access, ports, STP, "
                         "SNMP, routing). Review every line, fill in the <VALUES> listed at the top of each script, "
                         "and test on one device before pushing with SolarWinds.")
        top = ttk.Frame(self)
        top.pack(fill="x", padx=6)
        ttk.Label(top, text="Group:").grid(row=0, column=0, sticky="w")
        self.group_var = tk.StringVar()
        self.group_box = ttk.Combobox(top, textvariable=self.group_var, state="readonly", width=28)
        self.group_box.grid(row=0, column=1, sticky="w", padx=4)
        self.mode = tk.StringVar(value="run")
        ttk.Radiobutton(top, text="From the current assessment run: one script pair per device, only the controls "
                                  "that are Open on that device (interfaces filled in automatically)",
                        variable=self.mode, value="run").grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 0))
        ttk.Radiobutton(top, text="Baseline for the whole group: every control that has fix commands "
                                  "(interfaces left as <INTERFACE> to fill in)",
                        variable=self.mode, value="baseline").grid(row=2, column=0, columnspan=3, sticky="w")
        self.drafts_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Baseline: also use DRAFT rules that are not active yet",
                        variable=self.drafts_var).grid(row=3, column=0, columnspan=3, sticky="w", padx=(20, 0))
        b = ttk.Frame(top)
        b.grid(row=4, column=0, columnspan=3, sticky="w", pady=6)
        ttk.Button(b, text="Generate scripts", command=self.generate).pack(side="left")
        ttk.Button(b, text="Open hardening folder",
                   command=lambda: open_folder(store.paths.output / "hardening")).pack(side="left", padx=6)
        self.info = ttk.Label(self, text="", justify="left", foreground="#1b4f8a")
        self.info.pack(fill="x", padx=8)
        pane = ttk.PanedWindow(self, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=6, pady=6)
        lf, self.files = make_tree(pane, [("file", "Script", 320), ("n", "Controls", 70)], height=12)
        pane.add(lf, weight=1)
        self.files.bind("<<TreeviewSelect>>", lambda e: self.preview_selected())
        self.preview = ScrolledText(pane, font=MONO, wrap="none")
        pane.add(self.preview, weight=3)
        self.paths = {}

    def refresh(self):
        ids = [g["id"] for g in self.app.groups_db.get("groups", [])]
        self.group_box["values"] = ids
        if self.group_var.get() not in ids:
            self.group_var.set(ids[0] if ids else "")

    def generate(self):
        gid = self.group_var.get()
        group = assess.find_group(self.app.groups_db, gid)
        if not group:
            return messagebox.showinfo("Hardening", "Create a device group on tab 3 first.")
        if self.mode.get() == "run":
            run = self.app.run
            if not run or gid not in run.get("results", {}):
                return messagebox.showinfo("Hardening", f"The current assessment run has no results for {gid}. "
                                                        "Import and assess on tab 5, or choose Baseline.")
            folder, written = harden.generate_from_run(run, gid, self.app.rules_db)
        else:
            folder, written = harden.generate_baseline(group, self.app.rules_db, self.app.index,
                                                       include_drafts=self.drafts_var.get())
        self.files.delete(*self.files.get_children())
        self.paths = {}
        for path, n in written:
            iid = str(path)
            self.paths[iid] = path
            self.files.insert("", "end", iid=iid, values=(path.name, n))
        if not written:
            self.info.configure(text=f"Nothing to fix: no Open controls with fix commands ({folder}).")
            text_set(self.preview, "", readonly=True)
            return
        self.info.configure(text=f"{len(written)} script(s) written to {folder}")
        self.files.selection_set(self.files.get_children()[0])

    def preview_selected(self):
        sel = self.files.selection()
        if sel:
            text_set(self.preview, self.paths[sel[0]].read_text(encoding="utf-8"), readonly=True)
