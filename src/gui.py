"""Tkinter user interface, in two modes (switch at the top):

  Run an assessment   Assessment (collect -> import -> review -> write checklists), Hardening scripts
  Set up and rules    Checklists (import CKL / CKLB), Rules (build and test a rule per control), Device groups,
                      Fix commands (reviewed separately from the rules; only reviewed fixes reach hardening scripts)

Less common actions live in the menu bar, in "More..." buttons and on right-click.
"""
import contextlib
import copy
import difflib
import fnmatch
import json
import os
import re
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from tkinter import font as tkfont
from pathlib import Path
from tkinter.scrolledtext import ScrolledText

import assess
import checklist
import collect
import drafts
import harden
import llm_handoff
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


# ---------------------------------------------------------------- look and feel

ACCENT, ACCENT_HOVER, ACCENT_PRESSED = "#0067c0", "#1975c5", "#004e8c"
INFO_BG, BORDER = "#eaf3fc", "#c9c9c9"
UI_FONT = ("Segoe UI", 10)


def apply_theme(root):
    """A clean, current Windows look using only the built-in themes: Segoe UI 10, roomier lists, flat text boxes
    with a blue focus line, blue 'Accent.TButton' primary buttons and a two-part 'Mode' switch."""
    style = ttk.Style(root)
    if "vista" in style.theme_names():
        style.theme_use("vista")
    for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkCaptionFont", "TkIconFont", "TkTooltipFont"):
        try:
            tkfont.nametofont(name).configure(family=UI_FONT[0], size=UI_FONT[1])
        except tk.TclError:
            pass
    tkfont.nametofont("TkHeadingFont").configure(family="Segoe UI Semibold", size=UI_FONT[1])
    line = tkfont.nametofont("TkDefaultFont").metrics("linespace")
    style.configure("Treeview", rowheight=line + 10, font=UI_FONT)
    style.configure("Treeview.Heading", font=("Segoe UI Semibold", UI_FONT[1]), padding=(4, 4))
    style.configure("TButton", padding=(6, 3))
    style.configure("Big.TLabel", font=("Segoe UI Semibold", 13))
    style.configure("TLabelframe.Label", font=("Segoe UI Semibold", UI_FONT[1]), foreground="#1b4f8a")
    style.configure("TNotebook.Tab", padding=(12, 4))

    # Colours need elements from the 'clam' theme; the native Windows ones ignore them.
    def borrow(prefix, parts):
        for part in parts:
            try:
                style.element_create(f"{prefix}.{part}", "from", "clam")
            except tk.TclError:
                pass  # already created
    borrow("Accent", ["Button.border", "Button.focus", "Button.padding", "Button.label"])
    style.layout("Accent.TButton", [("Accent.Button.border", {"sticky": "nswe", "border": "1", "children": [
        ("Accent.Button.focus", {"sticky": "nswe", "children": [
            ("Accent.Button.padding", {"sticky": "nswe", "children": [
                ("Accent.Button.label", {"sticky": "nswe"})]})]})]})])
    style.configure("Accent.TButton", background=ACCENT, foreground="white", bordercolor=ACCENT_PRESSED,
                    lightcolor=ACCENT_HOVER, darkcolor=ACCENT_PRESSED, focuscolor=ACCENT, padding=(10, 4),
                    font=("Segoe UI Semibold", UI_FONT[1]))
    style.map("Accent.TButton", background=[("disabled", "#a9c7e6"), ("pressed", ACCENT_PRESSED),
                                            ("active", ACCENT_HOVER)],
              foreground=[("disabled", "#f3f3f3")])
    borrow("Mode", ["Toolbutton.border", "Toolbutton.padding", "Toolbutton.label"])
    style.layout("Mode.Toolbutton", [("Mode.Toolbutton.border", {"sticky": "nswe", "children": [
        ("Mode.Toolbutton.padding", {"sticky": "nswe", "children": [
            ("Mode.Toolbutton.label", {"sticky": "nswe"})]})]})])
    style.configure("Mode.Toolbutton", background="#e6e6e6", foreground="#1f1f1f", bordercolor=BORDER,
                    lightcolor="#e6e6e6", darkcolor="#e6e6e6", padding=(14, 5), font=("Segoe UI Semibold", 10))
    style.map("Mode.Toolbutton", background=[("selected", ACCENT), ("active", "#d6d6d6")],
              foreground=[("selected", "white")], lightcolor=[("selected", ACCENT)],
              darkcolor=[("selected", ACCENT)])

    # classic Tk widgets (text boxes, lists, menus): flat, thin border, blue line while typing
    for opt, value in (("*Text.relief", "flat"), ("*Text.borderWidth", 0), ("*Text.highlightThickness", 1),
                       ("*Text.highlightBackground", BORDER), ("*Text.highlightColor", ACCENT),
                       ("*Text.selectBackground", "#cce4f7"), ("*Text.selectForeground", "#000000"),
                       ("*Text.insertWidth", 2), ("*Listbox.relief", "flat"),
                       ("*Listbox.highlightThickness", 1), ("*Listbox.highlightBackground", BORDER),
                       ("*Listbox.highlightColor", ACCENT), ("*Menu.font", UI_FONT)):
        root.option_add(opt, value)


# ---------------------------------------------------------------- small helpers

def text_get(widget):
    return widget.get("1.0", "end-1c")


def text_set(widget, value, readonly=False):
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", value or "")
    if getattr(widget, "restyle", None):
        widget.restyle()
    if readonly:
        widget.configure(state="disabled")


def config_wrap(widget, stripes=True):
    """Wrap long device-config lines but keep each one visibly ONE line: the wrapped part hangs indented under it,
    and (stripes) every other line is lightly shaded, so a long command never looks like two commands."""
    widget.configure(wrap="word")
    widget.tag_configure("hang", lmargin1=0, lmargin2="1.6c")
    widget.tag_configure("stripe", background="#edf1f6")
    widget.tag_lower("stripe")  # match / problem highlights and the selection stay on top

    def restyle(_=None):
        widget.tag_add("hang", "1.0", "end")
        if stripes:
            widget.tag_remove("stripe", "1.0", "end")
            last = int(widget.index("end-1c").split(".")[0])
            for n in range(2, last + 1, 2):
                widget.tag_add("stripe", f"{n}.0", f"{n}.0 lineend+1c")
    widget.restyle = restyle
    widget.bind("<KeyRelease>", restyle, add="+")
    widget.bind("<<Paste>>", lambda e: widget.after(10, restyle), add="+")
    restyle()
    return widget


def fit_text(label, pad=10):
    """Re-wrap a label to the width it is actually given, so long text flows onto more lines instead of being cut
    off when the window or pane is narrow. Pack the label with fill="x" (and expand=True when side="left")."""
    label.configure(justify="left")
    label.bind("<Configure>", lambda e: label.configure(wraplength=max(e.width - pad, 60)), add="+")
    return label


def help_label(parent, text):
    """A light-blue info bar with a blue edge, explaining the screen."""
    bar = tk.Frame(parent, bg=INFO_BG, highlightthickness=1, highlightbackground="#c7dcf0")
    bar.pack(fill="x", padx=6, pady=(6, 4))
    tk.Frame(bar, bg=ACCENT, width=4).pack(side="left", fill="y")
    lbl = fit_text(tk.Label(bar, text=text, justify="left", anchor="w", bg=INFO_BG, fg="#1f1f1f", padx=10,
                            pady=6), pad=24)
    lbl.pack(side="left", fill="x", expand=True)
    return lbl


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
SEVERITY_LABELS = {"high": "high (CAT I)", "medium": "medium (CAT II)", "low": "low (CAT III)"}


def _sort_key(text):
    """Sort values the way people read them: severity high > low, numbers by value ('12 / 42 decided'), then text."""
    t = str(text).strip()
    if t.lower() in SEVERITY_ORDER:
        return (0, SEVERITY_ORDER[t.lower()], "")
    m = re.match(r"-?\d+(\.\d+)?", t)
    if m:
        return (1, float(m.group(0)), t.lower())
    return (2, 0, t.lower())


def enable_sorting(tree):
    """Click a column heading to sort by it (again to reverse). Rows that hold other rows (a product or a STIG)
    keep their place; the rows under them are sorted. The choice survives refreshes."""
    tree._sort = None
    tree._headings = {cid: tree.heading(cid, "text") for cid in ("#0", *tree["columns"])}

    def value(iid, col):
        return tree.item(iid, "text") if col == "#0" else tree.set(iid, col)

    def sort_level(parent):
        kids = list(tree.get_children(parent))
        if kids and not any(tree.get_children(k) for k in kids):
            col, reverse = tree._sort
            for i, iid in enumerate(sorted(kids, key=lambda k: _sort_key(value(k, col)), reverse=reverse)):
                tree.move(iid, parent, i)
        for k in kids:
            if tree.get_children(k):
                sort_level(k)

    def resort():
        tree._pending = False
        if tree._sort and tree.winfo_exists():
            sort_level("")

    def click(col):
        reverse = bool(tree._sort and tree._sort[0] == col and not tree._sort[1])
        tree._sort = (col, reverse)
        for cid, text in tree._headings.items():
            arrow = (" \u25bc" if reverse else " \u25b2") if cid == col else ""
            tree.heading(cid, text=text + arrow)
        resort()

    insert = tree.insert

    def insert_and_keep_sorted(*args, **kwargs):  # rows added by a refresh go back into the chosen order
        iid = insert(*args, **kwargs)
        if tree._sort and not getattr(tree, "_pending", False):
            tree._pending = True
            tree.after_idle(resort)
        return iid
    tree.insert = insert_and_keep_sorted
    for cid in tree._headings:
        tree.heading(cid, command=lambda c=cid: click(c))
    return tree


def make_tree(parent, columns, height=10, selectmode="browse", tree_column=None):
    """columns: [(id, heading, width)]. tree_column=(heading, width) adds a first column with open / close arrows
    for rows that have rows under them. Returns (frame, tree)."""
    frame = ttk.Frame(parent)
    tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="tree headings" if tree_column else "headings",
                        height=height, selectmode=selectmode)
    heading_font = tkfont.nametofont("TkHeadingFont")
    # widths are given for a 96-dpi screen; grow them with the text on a scaled (high-dpi) one
    scale = max(1.0, float(tree.tk.call("tk", "scaling")) / (96 / 72))
    if tree_column:
        tree.heading("#0", text=tree_column[0], anchor="w")
        tree.column("#0", width=int(tree_column[1] * scale), stretch=False)
    for cid, heading, width in columns:
        tree.heading(cid, text=heading)
        stretch = width >= 200  # the wide, wordy columns take any spare room
        width = max(int(width * scale), heading_font.measure(heading) + 24)  # never narrower than its heading
        tree.column(cid, width=width, stretch=stretch, anchor="w")
    sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=sb.set)
    tree.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    enable_sorting(tree)
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


def right_click_menu(tree, items):
    """Right-click a row to select it and pick from items [(label, command) or None for a line]."""
    menu = tk.Menu(tree, tearoff=0)
    for item in items:
        if item is None:
            menu.add_separator()
        else:
            menu.add_command(label=item[0], command=item[1])

    def popup(event):
        row = tree.identify_row(event.y)
        if row and row not in tree.selection():
            tree.selection_set(row)
        menu.tk_popup(event.x_root, event.y_root)
    tree.bind("<Button-3>", popup)
    return menu


def more_button(parent, items, text="More"):
    """A small dropdown button for the less common actions: items [(label, command) or None for a line]."""
    btn = ttk.Menubutton(parent, text=text)
    menu = tk.Menu(btn, tearoff=0)
    for item in items:
        if item is None:
            menu.add_separator()
        else:
            menu.add_command(label=item[0], command=item[1])
    btn["menu"] = menu
    return btn


class ScrollFrame(ttk.Frame):
    """Holds a pane's content. When there is room the content stretches to fill it (parts packed with expand=True
    still grow); when the window is too short the content scrolls instead of being cut off at the bottom."""

    def __init__(self, parent):
        super().__init__(parent)
        self.canvas = tk.Canvas(self, highlightthickness=0, borderwidth=0)
        self.bar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.bar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner = ttk.Frame(self.canvas)
        self.window = self.canvas.create_window(0, 0, window=self.inner, anchor="nw")
        self._pending = None
        self.canvas.bind("<Configure>", lambda e: self.schedule())
        self.inner.bind("<Configure>", lambda e: self.schedule())

    def schedule(self):
        """Lay out once things settle. The inner frame is given a fixed height, so it gets no <Configure> of its
        own when its content grows (text rewrapping, a list adding lines); the parts inside it do, as the room
        they are given changes. bind_wheel() hooks those up too."""
        if self._pending is None:
            self._pending = self.after_idle(self.layout)

    def layout(self):
        self._pending = None
        width, height, need = self.canvas.winfo_width(), self.canvas.winfo_height(), self.inner.winfo_reqheight()
        self.canvas.itemconfigure(self.window, width=width, height=max(height, need))
        self.canvas.configure(scrollregion=(0, 0, width, max(height, need)))
        if need > height + 1 and not self.bar.winfo_manager():
            self.bar.pack(side="right", fill="y", before=self.canvas)
        elif need <= height + 1 and self.bar.winfo_manager():
            self.bar.pack_forget()
            self.canvas.yview_moveto(0)

    def bind_wheel(self):
        """Mouse wheel over the pane scrolls it (boxes that scroll themselves keep their own wheel). Also re-lays
        out the pane whenever a part inside it changes size."""
        stack = [self.canvas]
        while stack:
            w = stack.pop()
            stack += w.winfo_children()
            if w is not self.canvas and w is not self.inner:
                w.bind("<Configure>", lambda e: self.schedule(), add="+")
            if not isinstance(w, (tk.Text, tk.Listbox, ttk.Treeview, ttk.Combobox, ttk.Scrollbar)):
                w.bind("<MouseWheel>", self.wheel, add="+")

    def wheel(self, event):
        if self.bar.winfo_manager():
            self.canvas.yview_scroll(int(-event.delta / 120) or (-1 if event.delta > 0 else 1), "units")


class PaneKeeper:
    """Keep a PanedWindow's dividers at the same proportions when the window is resized.

    Tk otherwise takes all of a shrink from the LAST pane, which can squeeze it to nothing. Dragging a divider
    sets the new proportions. shares: each divider's position as a fraction of the whole (0-1).
    first_min: the first pane's smallest size in pixels (or a function giving it), so a share that suits one
    screen does not squeeze the pane to nothing on another (DPI scaling, a shorter window). Capped at 60%.
    """

    def __init__(self, paned, shares, first_min=0):
        self.paned, self.shares, self.first_min = paned, list(shares), first_min
        paned.bind("<Configure>", lambda e: self.apply(), add="+")
        paned.bind("<ButtonRelease-1>", lambda e: (self.remember(), self.apply()), add="+")

    def total(self):
        vertical = str(self.paned.cget("orient")) == "vertical"
        return self.paned.winfo_height() if vertical else self.paned.winfo_width()

    def apply(self):
        total = self.total()
        if total < 50:  # not laid out yet
            return
        for i in range(min(len(self.paned.panes()) - 1, len(self.shares))):
            pos = int(total * self.shares[i])
            if i == 0 and self.first_min:
                least = self.first_min() if callable(self.first_min) else self.first_min
                pos = max(pos, min(least, int(total * 0.6)))
            self.paned.sashpos(i, pos)

    def remember(self):
        total = self.total()
        if total >= 50:
            dividers = len(self.paned.panes()) - 1
            self.shares[:dividers] = [self.paned.sashpos(i) / total for i in range(dividers)]

    def set(self, shares):
        self.shares = list(shares)
        self.apply()


@contextlib.contextmanager
def busy(widget):
    """Hourglass cursor while something slow runs (imports, writing packages), so the window does not look hung."""
    top = widget.winfo_toplevel()
    top.configure(cursor="watch")
    top.update_idletasks()
    try:
        yield
    finally:
        top.configure(cursor="")


def stig_families(app, stig_ids):
    """[(family name, grouped?, [(stig_id, part)])] in name order. 'grouped' is False for a STIG that has no family
    part (an OS or application STIG): it is shown on its own instead of under a heading."""
    families = {}
    for sid in sorted(stig_ids, key=app.short):
        family, part = assess.stig_family(app.short(sid))
        families.setdefault(family, []).append((sid, part))
    return [(name, any(part for _, part in items), items) for name, items in families.items()]


def select_first(parent, what):
    """A button was pressed with nothing selected: say what to select instead of silently doing nothing."""
    messagebox.showinfo("Select first", f"Select {what} first.", parent=parent)


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
        apply_theme(self)

        self.run, self.run_mtime = None, None
        self.open_editors = set()
        self.status = tk.Label(self, anchor="w", bg="#f3f3f3", fg="#5f6368", padx=10, pady=3)
        self.status.pack(side="bottom", fill="x")
        tk.Frame(self, bg="#dcdcdc", height=1).pack(side="bottom", fill="x")
        self.load_data()

        # Two modes: running an assessment (most people, most of the time) and setting up (STIGs, rules, groups,
        # fix commands). Each mode shows only its own tabs.
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=6, pady=(6, 0))
        self.mode = tk.StringVar(value=self.start_mode())
        for value, text in (("run", "  Run an assessment  "), ("setup", "  Set up and rules  ")):
            ttk.Radiobutton(bar, text=text.strip(), value=value, variable=self.mode, style="Mode.Toolbutton",
                            command=self.show_mode).pack(side="left")
        self.mode_hint = ttk.Label(bar, text="", foreground="#555")
        self.mode_hint.pack(side="left", padx=12)

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, pady=(4, 0))
        self.checklists, self.queue, self.groups = ChecklistsTab(self.nb, self), QueueTab(self.nb, self), \
            GroupsTab(self.nb, self)
        self.fixes, self.assess, self.harden = FixTab(self.nb, self), AssessTab(self.nb, self), HardenTab(self.nb, self)
        self.tabs = [self.checklists, self.queue, self.groups, self.fixes, self.assess, self.harden]
        for tab, name in zip(self.tabs, ["Checklists", "Rules", "Device groups", "Fix commands",
                                         "Assessment", "Hardening scripts"]):
            self.nb.add(tab, text=f"  {name}  ")
        self.modes = {"run": [self.assess, self.harden], "setup": [self.checklists, self.queue, self.groups,
                                                                   self.fixes]}
        self.build_menu()
        self.show_mode()
        # Teammates may have changed things: re-read the shared data whenever a tab is opened.
        self.nb.bind("<<NotebookTabChanged>>", lambda e: self.reload())
        self.bind("<F5>", lambda e: self.reload())
        self.protocol("WM_DELETE_WINDOW", self.quit_app)
        runs = store.list_runs()
        if runs:
            self.set_run(store.load_run(runs[0]), runs[0].stat().st_mtime)
        self.refresh_all()
        self.after(300, self.first_start_rules)
        self.after(600, self.tidy_fixes)
        if not store.load_my_view().get("quick_start_seen"):
            self.after(900, lambda: (QuickStart(self), store.save_my_view({"quick_start_seen": True})))

    def first_start_rules(self):
        """A fresh install with no rules picks up the rules file shipped with the program."""
        bundled = store.bundled_rules_path()
        if self.rules_db["rules"] or not bundled.exists():
            return
        try:
            rep = store.import_rules(bundled)
        except (ValueError, OSError) as e:
            return messagebox.showwarning("Rules", f"Could not load the shipped rules file: {e}")
        self.reload()
        self.tidy_fixes()
        messagebox.showinfo("Rules loaded", f"This looks like a new install, so the {rep['added']} rules shipped in "
                                            f"{bundled.name} were loaded.\n\nImport your checklists (Set up and "
                                            "rules > Checklists) - the rules attach to them automatically by STIG "
                                            "and Vuln ID.")

    def tidy_fixes(self):
        """One-time tidies of saved rules: fix commands holding the whole DoD banner are shortened to
        <DOD_BANNER> (a team site value); an old 'Extra comment' becomes per-result Reason text."""
        try:
            changed = harden.compact_stored_fixes(self.rules_db["rules"])
            changed += assess.move_extra_comments(self.rules_db["rules"])
            if changed:
                self.reload()
        except (OSError, ValueError):
            pass  # shared data not writable right now - try again next start

    # -- modes and menus
    MODE_HINTS = {"run": "Collect from SolarWinds, review the results, write the checklists.",
                  "setup": "Import STIG checklists, build and test rules, define device groups, review fix commands."}

    def start_mode(self):
        saved = store.load_my_view().get("mode")
        if saved in ("run", "setup"):
            return saved
        return "run" if self.index and self.groups_db.get("groups") else "setup"

    def show_mode(self):
        mode = self.mode.get()
        for tab in self.tabs:
            if tab in self.modes[mode]:
                self.nb.add(tab)
            else:
                self.nb.hide(tab)
        self.nb.select(self.modes[mode][0])
        self.mode_hint.configure(text=self.MODE_HINTS[mode])
        store.save_my_view({"mode": mode})

    def go_to(self, tab):
        mode = next(m for m, tabs in self.modes.items() if tab in tabs)
        if self.mode.get() != mode:
            self.mode.set(mode)
            self.show_mode()
        self.nb.select(tab)

    def build_menu(self):
        menu = tk.Menu(self)
        self.config(menu=menu)

        def cascade(label, items):
            sub = tk.Menu(menu, tearoff=0)
            for item in items:
                if item is None:
                    sub.add_separator()
                else:
                    sub.add_command(label=item[0], command=item[1])
            menu.add_cascade(label=label, menu=sub)
            return sub

        cascade("File", [("Open previous assessment run...", lambda: (self.go_to(self.assess),
                                                                     self.assess.open_run())),
                         ("Open input folder", lambda: open_folder(store.paths.input)),
                         ("Open output folder", lambda: open_folder(store.paths.output)),
                         None, ("Refresh (F5)", self.reload), ("Exit", self.quit_app)])
        cascade("Assessment", [("Show the last collection script", lambda: self.assess.show_script()),
                               ("Re-run the assessment with the latest rules and groups",
                                lambda: (self.go_to(self.assess), self.assess.reevaluate())),
                               ("Write checklist packages for ALL groups...",
                                lambda: (self.go_to(self.assess), self.assess.write(all_groups=True)))])
        cascade("Rules", [("Create starter drafts...", lambda: (self.go_to(self.queue), self.queue.starter_drafts())),
                          ("Try drafts on real output...", lambda: TryRulesWindow.open(self)),
                          None,
                          ("Import rules...", lambda: (self.go_to(self.queue), self.queue.import_rules())),
                          ("Export rules...", self.queue.export_rules)])
        team = cascade("Team settings", [])
        self.fmt_var = tk.StringVar(value=self.settings["output_format"])
        team.add_command(label="Checklist output format:", state="disabled")
        for fmt, label in checklist.FORMAT_LABELS.items():
            team.add_radiobutton(label=f"    {label}", value=fmt, variable=self.fmt_var, command=self.set_format)
        team.add_separator()
        team.add_command(label="Where reasons go in the checklist...", command=lambda: PlacementDialog(self))
        team.add_command(label="Port roles (uplink / downlink / access / trusted / your own)...",
                         command=lambda: PortRolesDialog(self))
        team.add_command(label="Site values (DoD banner, NTP / AAA / syslog servers...)...",
                         command=lambda: SiteValuesDialog(self))
        cascade("Help", [("Quick start", lambda: QuickStart(self)),
                         ("Open the README", lambda: open_folder(store.paths.root / "README.md"))])

    def set_format(self):
        fmt = self.fmt_var.get()
        if fmt != self.output_format:
            store.set_setting("output_format", fmt)
            self.reload()

    # -- shared data
    def load_data(self):
        self.settings = store.load_settings()
        engine.set_port_roles(self.settings["port_roles"])
        self.rules_db = store.load_rules()
        self.groups_db = store.load_groups()
        self.index = store.control_index()
        fmt = checklist.FORMAT_LABELS[self.settings["output_format"]]
        if hasattr(self, "fmt_var"):
            self.fmt_var.set(self.settings["output_format"])
        self.status.configure(text=f"Shared data: {store.paths.data}     Signed in as {store.current_user()} on "
                                   f"{store.current_host()}     Checklist output: {fmt}     F5 = refresh")

    def reload(self):
        """Re-read rules, groups, settings and templates (picks up teammates' changes)."""
        self.load_data()
        tab = self.nametowidget(self.nb.select()) if hasattr(self, "nb") and self.nb.select() else None
        if tab in getattr(self, "tabs", []):
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
        editing = [e for e in self.open_editors if not e.readonly]
        unsaved = []
        if editing:
            unsaved.append(f"{len(editing)} rule editor(s) are still open")
        if self.fixes.dirty():
            unsaved.append(f"the fix commands of {self.fixes.loaded[0]} are not saved")
        if self.assess.pending:
            unsaved.append(f"{len(self.assess.pending)} review change(s) were not applied")
        if unsaved and not messagebox.askyesno(
                "Close the tool?", "Unsaved work will be lost:\n\n- " + "\n- ".join(unsaved) + "\n\nClose anyway?",
                icon="warning"):
            return
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
    t = ScrolledText(parent, wrap="word", font=("Segoe UI", 10), height=height)
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
    COLUMNS = [("release", "Current release", 170), ("formats", "Imported as", 330), ("controls", "Checks", 70),
               ("auto", "Automated", 80), ("manual", "Manual", 65), ("todo", "Not built", 75),
               ("review", "Need review", 85), ("note", "Notes", 420)]

    def __init__(self, nb, app):
        super().__init__(nb)
        self.app = app
        help_label(self, "Import the blank checklist for each STIG. Each STIG is one row; click the arrow to see "
                         "every file imported for it. When DISA publishes a new quarterly release, import it here, "
                         "then select the STIG and click 'Compare releases' to see what changed and which rules "
                         "need a look. Right-click a file to remove it.")
        row = ttk.Frame(self)
        row.pack(fill="x", padx=6)
        ttk.Button(row, text="Import checklist file(s)...", command=self.do_import, style="Accent.TButton").pack(side="left")
        ttk.Button(row, text="Compare releases...", command=self.compare).pack(side="left", padx=6)

        frame = ttk.Frame(self)
        frame.pack(fill="both", expand=True, padx=6, pady=6)
        self.tree = ttk.Treeview(frame, columns=[c[0] for c in self.COLUMNS], show="tree headings")
        self.tree.heading("#0", text="STIG")
        self.tree.column("#0", width=330, stretch=False)
        heading_font = tkfont.nametofont("TkHeadingFont")
        for cid, heading, width in self.COLUMNS:
            self.tree.heading(cid, text=heading)
            self.tree.column(cid, width=max(width, heading_font.measure(heading) + 24), stretch=cid == "note",
                             anchor="w")
        enable_sorting(self.tree)
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.tag_configure("warn", background="#fff0c2")
        self.tree.tag_configure("file", foreground="#444")
        self.tree.tag_configure("family", font=("Segoe UI Semibold", 10))
        self.tree.bind("<Double-1>", lambda e: self.compare())
        right_click_menu(self.tree, [("Compare releases...", self.compare), ("Remove this file...", self.do_remove)])

    def refresh(self):
        fmt = self.app.output_format
        opened = {i for top in self.tree.get_children() for i in [top, *self.tree.get_children(top)]
                  if self.tree.item(i, "open")}
        first_fill = not self.tree.get_children()
        keep = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        rows = []
        for family, grouped, items in stig_families(self.app, self.app.index):
            fam_iid = f"F::{family}"
            if grouped:
                self.tree.insert("", "end", iid=fam_iid, text=family, tags=("family",),
                                 open=first_fill or fam_iid in opened)
            rows += [(fam_iid if grouped else "", stig_id, part) for stig_id, part in items]
        totals = {}
        for parent, stig_id, part in rows:
            stig = self.app.index[stig_id]
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
            self.tree.insert(parent, "end", iid=pid, text=part or stig["short"], open=pid in opened,
                             tags=("warn",) if notes else (),
                             values=(stig["release"], formats, len(stig["order"]), counts.get("Active", 0)
                                     + counts.get("STIG changed - review", 0), counts.get("Manual only", 0),
                                     counts.get("Needs rule", 0) + counts.get("Draft", 0),
                                     counts.get("STIG changed - review", 0), "; ".join(notes) or "OK"))
            if parent:
                t = totals.setdefault(parent, [0, 0, 0, 0, 0, 0])
                for i, n in enumerate((len(stig["order"]), counts.get("Active", 0)
                                       + counts.get("STIG changed - review", 0), counts.get("Manual only", 0),
                                       counts.get("Needs rule", 0) + counts.get("Draft", 0),
                                       counts.get("STIG changed - review", 0), 1 if notes else 0)):
                    t[i] += n
            current = {f: cat["id"] for f, cat in store.templates_for(stig_id).items()}
            for cat, s in reversed(store.releases_for(stig_id)):
                rel = checklist.release_label(s.get("version"), s.get("release_info"))
                mark = "CURRENT  " if current.get(cat["format"]) == cat["id"] else ""
                self.tree.insert(pid, "end", iid=f"C|{cat['id']}|{stig_id}", tags=("file",),
                                 text=checklist.FORMAT_LABELS[cat["format"]],
                                 values=(rel, cat.get("viewer", ""), len(s["controls"]), "", "", "", "",
                                         f"{mark}imported {cat['imported_at'][:16].replace('T', ' ')} by "
                                         f"{cat.get('imported_by', '?')} from {cat['source_name']}"))
        for fam_iid, (n, auto, manual, todo, review, warn) in totals.items():
            self.tree.item(fam_iid, tags=("family", "warn") if warn else ("family",),
                           values=("", f"{len(self.tree.get_children(fam_iid))} STIG(s)", n, auto, manual, todo,
                                   review, f"{warn} STIG(s) need attention - open to see" if warn else "OK"))
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

    def do_import(self):
        files = filedialog.askopenfilenames(title="Choose STIG checklist file(s)",
                                            filetypes=[("STIG checklists", "*.ckl *.cklb"), ("All files", "*.*")])
        report = []
        with busy(self):
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
            return messagebox.showinfo("Remove", "Expand a STIG and right-click the specific file to remove.")
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
        ttk.Label(f, text="The reviewer's comment always goes in Comments.",
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


QUICK_START = [
    ("Operators - Run an assessment", [
        ("1  Collect", "Choose the groups, click 'Copy collection script', paste it into SolarWinds 'Execute Command "
                       "Script', run it, and save the output as a text file."),
        ("2  Import", "Click 'Import SolarWinds output...'. Check every device landed in the right group: Show 'Not "
                      "in a group yet', select them, 'Change group of selected devices'."),
        ("3  Review", "The list opens on what needs your decision (Open / Not Reviewed nobody has looked at). For "
                      "each one, type why in Reviewer comment and click Apply (Ctrl+Enter) - to agree, keep the "
                      "result; to change it, pick another first. 'Not automated' checks are not checked by the "
                      "tool - assess them in STIG Viewer after writing, or set them here."),
        ("4  Write", "Type your full name and click 'Write checklist package'. A folder ending in _REVIEW_REQUIRED "
                     "still has Not Reviewed checks in it."),
        ("If a yellow bar says the results may be out of date", "Click 'Re-run now'. Nothing is collected again and "
                                                               "your decisions are kept."),
    ]),
    ("Admins - Set up and rules", [
        ("1  Checklists", "Import the blank CKL / CKLB for each STIG. Every quarter, import DISA's new release and use "
                          "'Compare releases' to see which rules need a look."),
        ("2  Device groups", "'New group': a name, the STIGs it gets, and hostname patterns like *-ACCESS. Use 'Add "
                             "devices...' for devices whose names follow no pattern."),
        ("3  Rules", "Open a STIG, pick a check, open its starter draft (or 'New rule'). Test it on real output, save "
                     "a passing and a failing sample as tests, then 'Activate and save'. The same check in another "
                     "STIG: 'Use for other checks...'. Some devices need different logic: add a version and pick "
                     "the device groups that use it."),
        ("4  Fix commands", "Review each fix before hardening scripts use it. Put the DoD banner and server addresses "
                            "in Team settings > Site values once."),
        ("5  Team settings", "Checklist output format, where reasons go, port role keywords, site values."),
    ]),
]


class QuickStart(tk.Toplevel):
    """The two workflows on one page (Help > Quick start; shown once on each PC's first start)."""

    def __init__(self, parent):
        super().__init__(parent)
        self.title("Quick start")
        self.transient(parent)
        self.geometry("980x700")
        t = ScrolledText(self, wrap="word", font=UI_FONT, padx=14, pady=10, relief="flat")
        t.pack(fill="both", expand=True)
        t.tag_configure("h", font=("Segoe UI Semibold", 13), foreground="#1b4f8a", spacing1=10, spacing3=6)
        t.tag_configure("step", font=("Segoe UI Semibold", 10), lmargin1=10, spacing1=6)
        t.tag_configure("text", lmargin1=36, lmargin2=36, spacing3=4)
        t.insert("end", "The switch at the top picks the mode: 'Run an assessment' or 'Set up and rules'.\n")
        for head, steps in QUICK_START:
            t.insert("end", head + "\n", "h")
            for step, text in steps:
                t.insert("end", step + "\n", "step")
                t.insert("end", text + "\n", "text")
        t.insert("end", "\nOpen this again from Help > Quick start. The README has the details.\n")
        t.configure(state="disabled")
        ttk.Button(self, text="Close", command=self.destroy, style="Accent.TButton").pack(pady=8)


class ImportReport(tk.Toplevel):
    def __init__(self, parent, text, title="Import results", mono=False):
        super().__init__(parent)
        self.title(title)
        self.geometry("900x500")
        self.transient(parent)
        t = ScrolledText(self, wrap="word", font=MONO if mono else ("Segoe UI", 10))
        if mono:
            config_wrap(t)
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
        btns.pack(side="bottom", fill="x", pady=4, before=lf)
        ttk.Button(btns, text="Open rule...", command=self.open_rule).pack(side="left")
        ttk.Button(btns, text="Rule still valid - mark reviewed", command=self.mark_reviewed).pack(side="left",
                                                                                                  padx=4)
        right = ttk.Frame(paned)
        paned.add(right, weight=3)
        PaneKeeper(paned, [0.45])
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
                todo, tag = "Retire rule (check removed)", "review"
            elif not is_current:
                todo, tag = "(compare with current release)", "info"
            elif any(store.rule_check_hash(r, self.stig_id, d["vuln_id"]) != new_hash
                     for r in rs if r.get("state") == "active"):
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
            text_set(self.diff, "Select a check on the left to see what changed.", readonly=True)

    def open_rule(self):
        d = self.selected()
        if not d:
            return select_first(self, "a check in the list")
        if not d["new"]:
            return messagebox.showinfo("Open rule", "DISA removed this check, so there is nothing to open in the "
                                                    "current release.", parent=self)
        rs = assess.rules_for_control(self.app.rules_db, self.stig_id, d["vuln_id"])
        if not rs:
            return messagebox.showinfo("No rule", "This check has no rule.", parent=self)
        control = self.app.index[self.stig_id]["controls"].get(d["vuln_id"])
        if control:
            RuleEditor.open(self.app, self.stig_id, control, rs[0], self.after_change)

    def mark_reviewed(self):
        d = self.selected()
        current = self.app.index[self.stig_id]
        if not d or not d["new"] or self.new_var.get() != current["release"]:
            return messagebox.showinfo("Mark reviewed", "Select a changed check, comparing against the current "
                                                        f"release ({current['release']}).", parent=self)
        rs = [r for r in assess.rules_for_control(self.app.rules_db, self.stig_id, d["vuln_id"])
              if store.rule_check_hash(r, self.stig_id, d["vuln_id"]) != d["new"]["check_hash"]]
        if not rs:
            return messagebox.showinfo("Mark reviewed", "No rules need review for this check.", parent=self)
        if messagebox.askyesno("Mark reviewed", f"Confirm {', '.join(r['id'] for r in rs)} still check the right "
                                                f"thing after the {current['release']} change?", parent=self):
            for r in rs:
                store.mark_rule_reviewed(r["id"], self.stig_id, d["vuln_id"], d["new"]["check_hash"],
                                         current["release"])
            self.after_change()

    def after_change(self):
        self.app.reload()
        self.refresh()


# ---------------------------------------------------------------- rules tab

class QueueTab(ttk.Frame):
    STATES = ["All", "Needs rule", "Draft", "Active", "STIG changed - review", "Manual only"]

    def __init__(self, nb, app):
        super().__init__(nb)
        self.app = app
        help_label(self, "Every check needs a decision. Select a check, read its check text, then click "
                         "'New rule' to describe which show command to run and what text proves compliance, or "
                         "'Manual only' if show output cannot answer it. If the same check is in another STIG, open "
                         "the rule and use 'Use for other checks...' instead of writing it twice. Fix commands are "
                         "reviewed separately, on the Fix commands tab.")
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
        ttk.Label(filt, text="Severity:").pack(side="left", padx=(10, 0))
        self.sev_var = tk.StringVar(value="All")
        ttk.Combobox(filt, textvariable=self.sev_var, values=["All"] + list(SEVERITY_LABELS.values()),
                     state="readonly", width=16).pack(side="left", padx=4)
        ttk.Label(filt, text="Search:").pack(side="left", padx=(10, 0))
        self.search_var = tk.StringVar()
        ttk.Entry(filt, textvariable=self.search_var, width=24).pack(side="left", padx=4)
        for var in (self.stig_var, self.state_var, self.sev_var, self.search_var):
            var.trace_add("write", lambda *a: self.refresh())
        prow = ttk.Frame(self)
        prow.pack(fill="x", padx=8, pady=(4, 0))
        # a setup helper: shown only while there are draft rules to try (Rules menu has it always)
        self.try_btn = ttk.Button(prow, text="Try drafts on real output...",
                                  command=lambda: TryRulesWindow.open(self.app))
        self.progress = fit_text(ttk.Label(prow, text="", foreground="#333"))
        self.progress.pack(side="left", fill="x", expand=True)

        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=6, pady=6)
        # STIGs grouped under their product (Cisco IOS XE Switch > NDM / RTR / L2S); open a STIG to see its checks
        left, self.tree = make_tree(paned, [("ver", "STIG ID", 120), ("sev", "Severity", 65),
                                            ("state", "State", 170), ("rules", "Rules", 45),
                                            ("title", "Title", 400)], height=24,
                                    tree_column=("STIG / Vuln ID", 240))
        color_tags(self.tree, {k.replace(" ", "_"): v for k, v in STATE_ROW.items()})
        self.tree.tag_configure("family", background="#e8eef6", font=("Segoe UI Semibold", 10))
        self.tree.tag_configure("stig", background="#f4f7fb", font=("Segoe UI Semibold", 10))
        paned.add(left, weight=3)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.show_control())
        self.tree.bind("<Double-1>", self.double_click)
        self.tree.bind("<Return>", lambda e: self.edit_rule(default=True) if self.current()[1] else None)

        right = ttk.Frame(paned)
        paned.add(right, weight=2)
        PaneKeeper(paned, [0.6])
        ttk.Label(right, text="STIG check and fix text", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.details = ScrolledText(right, height=16, width=50, wrap="word", font=("Segoe UI", 10))
        self.details.pack(fill="both", expand=True)
        # the rule list and its buttons are pinned to the bottom; a short window shrinks the check text instead
        rules_label = ttk.Label(right, text="Rules for this check", font=("Segoe UI", 10, "bold"))
        rules_label.pack(side="bottom", anchor="w", pady=(8, 0), before=self.details)
        rf, self.rule_tree = make_tree(right, [("id", "Rule", 75), ("name", "Rule name", 150),
                                               ("state", "State", 60), ("ver", "Rev", 40),
                                               ("used", "Used by", 180), ("tests", "Tests", 45),
                                               ("shared", "Shared with", 150),
                                               ("by", "Last saved by", 150)], height=5)
        rf.pack(side="bottom", fill="x", before=rules_label)
        self.rule_tree.bind("<Double-1>", lambda e: self.edit_rule())
        btns = ttk.Frame(right)
        btns.pack(side="bottom", fill="x", pady=(4, 0), before=rf)
        for text, cmd in (("New rule", self.new_rule), ("Edit rule", self.edit_rule),
                          ("Manual only", self.toggle_manual)):
            ttk.Button(btns, text=text, command=cmd,
                       style="Accent.TButton" if text == "New rule" else "TButton").pack(side="left", padx=2)
        rarely = [("Add a version for some device groups...", self.copy_rule),
                  ("Make this the default version (all other groups)", self.make_default), None,
                  ("Retire this rule", self.retire_rule), ("Delete this draft", self.delete_rule)]
        more_button(btns, rarely, "More...").pack(side="left", padx=2)
        right_click_menu(self.rule_tree, [("Edit rule", self.edit_rule), None] + rarely)
        self.stig_map = {}

    # -- data
    def refresh(self):
        self.stig_map = {self.app.stig_label(s): s for s in self.app.index}
        self.stig_box["values"] = ["All"] + list(self.stig_map)
        if self.stig_var.get() not in self.stig_box["values"]:
            self.stig_var.set("All")
        want_stig = self.stig_map.get(self.stig_var.get())
        want_state, needle = self.state_var.get(), self.search_var.get().lower().strip()
        want_sev = next((k for k, v in SEVERITY_LABELS.items() if v == self.sev_var.get()), None)
        filtering = bool(want_stig or want_state != "All" or needle or want_sev)
        keep = self.tree.selection()
        was_open = {i for i in self.all_rows() if self.tree.item(i, "open")}
        first_fill = not self.tree.get_children()
        self.tree.delete(*self.tree.get_children())
        families, total = {}, {"checks": 0, "done": 0, "review": 0}
        for stig_id, stig in sorted(self.app.index.items(), key=lambda kv: kv[1]["short"]):
            family, part = assess.stig_family(stig["short"])
            families.setdefault(family, []).append((stig_id, stig, part))
        for family, stigs in families.items():
            grouped = any(part for _, _, part in stigs)  # a STIG with no family part stands on its own
            fam_iid = f"F::{family}"
            if grouped:
                self.tree.insert("", "end", iid=fam_iid, text=family, tags=("family",),
                                 open=first_fill or filtering or fam_iid in was_open)
            fam_counts = {"checks": 0, "done": 0, "review": 0}
            for stig_id, stig, part in stigs:
                counts, rows = {}, []
                for vuln_id in stig["order"]:
                    c = stig["controls"][vuln_id]
                    state = assess.control_state(self.app.rules_db, stig_id, c)
                    counts[state] = counts.get(state, 0) + 1
                    if want_stig and stig_id != want_stig:
                        continue
                    if want_state != "All" and state != want_state:
                        continue
                    if want_sev and c["severity"] != want_sev:
                        continue
                    if needle and needle not in f"{vuln_id} {c['rule_ver']} {c['title']}".lower():
                        continue
                    rows.append((vuln_id, c, state))
                done = counts.get("Active", 0) + counts.get("Manual only", 0)
                review = counts.get("STIG changed - review", 0)
                for key, n in (("checks", len(stig["order"])), ("done", done), ("review", review)):
                    fam_counts[key] += n
                    total[key] += n
                if filtering and not rows:
                    continue
                stig_iid = f"S::{stig_id}"
                self.tree.insert(fam_iid if grouped else "", "end", iid=stig_iid, tags=("stig",),
                                 text=f"{part}   {stig['release']}" if grouped else f"{stig['short']}   {stig['release']}",
                                 open=filtering or stig_iid in was_open,
                                 values=("", "", f"{done} / {len(stig['order'])} decided"
                                         + (f", {review} need review" if review else ""), "", ""))
                for vuln_id, c, state in rows:
                    n = len(assess.rules_for_control(self.app.rules_db, stig_id, vuln_id))
                    self.tree.insert(stig_iid, "end", iid=assess.key_of(stig_id, vuln_id), text=vuln_id,
                                     tags=(state.replace(" ", "_"),),
                                     values=(c["rule_ver"], c["severity"], state, n, c["title"]))
            if grouped:
                if not self.tree.get_children(fam_iid):
                    self.tree.delete(fam_iid)
                else:
                    self.tree.item(fam_iid, values=("", "", f"{fam_counts['done']} / {fam_counts['checks']} decided"
                                                    + (f", {fam_counts['review']} need review"
                                                       if fam_counts["review"] else ""), "", ""))
        drafts = sum(1 for r in self.app.rules_db["rules"] if r.get("state") == "draft")
        if drafts and not self.try_btn.winfo_manager():
            self.try_btn.pack(side="right", padx=(8, 0), before=self.progress)
        elif not drafts and self.try_btn.winfo_manager():
            self.try_btn.pack_forget()
        self.try_btn.configure(text=f"Try {drafts} draft(s) on real output...")
        self.progress.configure(
            text=(f"{len(self.app.index)} STIG(s), {total['checks']} checks: {total['done']} decided"
                  + (f", {total['review']} need review after a STIG update" if total["review"] else "")
                  + ". Open a STIG (click its arrow) to see its checks.") if self.app.index else
            "No checklists imported yet - start on the Checklists tab.")
        keep = [k for k in keep if self.tree.exists(k)]
        if keep:
            self.tree.selection_set(keep)
            self.tree.see(keep[0])
        self.show_control()

    def all_rows(self, parent=""):
        for iid in self.tree.get_children(parent):
            yield iid
            yield from self.all_rows(iid)

    def double_click(self, event):
        """Double-click a check to open its rule; on a STIG or product row it just opens / closes the row."""
        row = self.tree.identify_row(event.y)
        if row and not row.startswith(("F::", "S::")):
            self.edit_rule(default=True)

    def current(self):
        sel = self.tree.selection()
        if not sel or sel[0].startswith(("F::", "S::")):
            return None, None
        stig_id, vuln_id = sel[0].split("|", 1)
        return stig_id, self.app.index[stig_id]["controls"][vuln_id]

    def show_control(self):
        stig_id, c = self.current()
        self.rule_tree.delete(*self.rule_tree.get_children())
        if not c:
            sel = self.tree.selection()
            if sel and sel[0].startswith("S::"):
                sid = sel[0][3:]
                stig = self.app.index.get(sid, {})
                counts = {}
                for vuln_id in stig.get("order", []):
                    state = assess.control_state(self.app.rules_db, sid, stig["controls"][vuln_id])
                    counts[state] = counts.get(state, 0) + 1
                text_set(self.details, f"{self.app.stig_label(sid)}\n\n{len(stig.get('order', []))} checks:\n"
                         + "\n".join(f"   {n:4d}  {state}" for state, n in sorted(counts.items()))
                         + "\n\nClick the arrow next to the STIG to see its checks, then select a check.",
                         readonly=True)
            else:
                text_set(self.details, "Select a check to see its STIG text and its rules." if sel else
                         "Nothing selected.\n\nOn the left, click the arrow next to a STIG (e.g. NDM) to list its "
                         "checks, then click a check. Its STIG check and fix text appear here, and its rules "
                         "below.", readonly=True)
            return
        text_set(self.details, f"{self.app.stig_label(stig_id)}\n"
                               f"{c['vuln_id']}  {c['rule_ver']}  [{c['severity']}]\n{c['title']}\n\n"
                               f"CHECK:\n{c['check']}\n\nFIX:\n{c['fix']}", readonly=True)
        for r in assess.rules_for_control(self.app.rules_db, stig_id, c["vuln_id"], include_retired=True):
            lock = store.lock_holder("rule", r["id"])
            self.rule_tree.insert("", "end", iid=r["id"],
                                  values=(r["id"], r.get("name", ""), r.get("state", "draft"), r.get("version", 1),
                                          assess.used_by_text(r), len(r.get("tests", [])),
                                          self.shared_text(r, stig_id, c["vuln_id"]),
                                          f"EDITING NOW: {lock['user']}" if lock else
                                          f"{r.get('saved_by', r.get('updated_by', ''))} "
                                          f"{(r.get('saved_at') or r.get('updated_at') or '')[:10]}"))

    def shared_text(self, rule, stig_id, vuln_id):
        others = [t for t in store.rule_targets(rule) if (t["stig_id"], t["vuln_id"]) != (stig_id, vuln_id)]
        if not others:
            return ""
        first = others[0]
        return f"{self.app.short(first['stig_id'])} {first['vuln_id']}" + (f" +{len(others) - 1}" if len(others) > 1
                                                                           else "")

    def selected_rule(self):
        sel = self.rule_tree.selection()
        return self.app.rule_by_id(sel[0]) if sel else None

    # -- actions
    def new_rule(self):
        stig_id, c = self.current()
        if not c:
            return select_first(self, "a check in the list on the left")
        RuleEditor.open(self.app, stig_id, c, None, self.after_save)

    def edit_rule(self, default=False):
        stig_id, c = self.current()
        if not c:
            return select_first(self, "a check in the list on the left")
        r = self.selected_rule()
        rs = assess.rules_for_control(self.app.rules_db, stig_id, c["vuln_id"])
        if r is None and (default or len(rs) == 1):
            r = next((x for x in rs if x.get("is_default")), rs[0] if rs else None)
        if r is None and not rs:
            if default:
                return self.new_rule()
            return messagebox.showinfo("Edit rule", "This check has no rule yet. Click 'New rule' to write one.")
        if r is None:
            return select_first(self, "a rule under 'Rules for this check'")
        RuleEditor.open(self.app, stig_id, c, r, self.after_save)

    def copy_rule(self):
        stig_id, c = self.current()
        r = self.selected_rule()
        if not r:
            return select_first(self, "the rule to start the new version from (under 'Rules for this check')")
        dup = copy.deepcopy(r)
        for k in ("id", "history", "review_log", "is_default", "created_at", "created_by", "_rev", "saved_by",
                  "saved_at", "links", "fix_review"):
            dup.pop(k, None)
        dlg = UsedByDialog(self, self.app, [stig_id], [], title="Which device groups need a different version?")
        if dlg.result is None:
            return
        name = ("For " + ", ".join(dlg.result)) if dlg.result else r.get("name", "") + " (copy)"
        dup.update(name=name, state="draft", version=0, groups=dlg.result, is_default=False)
        RuleEditor.open(self.app, stig_id, c, dup, self.after_save, is_copy=True)

    def make_default(self):
        stig_id, c = self.current()
        r = self.selected_rule()
        if not r:
            return select_first(self, "a rule under 'Rules for this check'")
        if r.get("groups"):
            return messagebox.showinfo("Default version", f"{r['id']} is only for {', '.join(r['groups'])}. The "
                                                          "default is the version every OTHER group uses - pick one "
                                                          "that is used by all groups, or open this one and change "
                                                          "'Used by' to all groups.")
        for x in assess.rules_for_control(self.app.rules_db, stig_id, c["vuln_id"], include_retired=True):
            if bool(x.get("is_default")) != (x["id"] == r["id"]):
                store.modify_rule(x["id"], lambda d, on=x["id"] == r["id"]: d.__setitem__("is_default", on))
        self.after_save()

    def retire_rule(self):
        r = self.selected_rule()
        if not r:
            return select_first(self, "a rule under 'Rules for this check'")
        shared = len(store.rule_targets(r)) - 1 if r else 0
        if r and messagebox.askyesno("Retire rule", f"Retire {r['id']} '{r.get('name')}'? "
                                                    "Groups using it will fall back to the default version."
                                                    + (f"\n\nThis rule is shared: it is retired for all "
                                                       f"{shared + 1} checks it answers." if shared else "")):
            store.modify_rule(r["id"], lambda d: d.update(state="retired", is_default=False))
            self.after_save()

    def delete_rule(self):
        r = self.selected_rule()
        if not r:
            return select_first(self, "a rule under 'Rules for this check'")
        if r.get("state") != "draft" or r.get("history"):
            return messagebox.showinfo("Delete", "Only drafts that were never saved as Active can be deleted. "
                                                 "Use Retire instead so the history is kept.")
        if store.lock_holder("rule", r["id"]):
            return messagebox.showinfo("Delete", "Someone has this rule open. Try again when they are done.")
        if messagebox.askyesno("Delete draft", f"Delete draft {r['id']}?"):
            store.delete_rule(r["id"])
            self.after_save()

    def export_rules(self):
        path = filedialog.asksaveasfilename(
            title="Export rules", defaultextension=".json", initialdir=str(store.paths.output),
            initialfile=f"stigtool_rules_{store.stamp()}.json", filetypes=[("STIGTOOL rules", "*.json")])
        if path:
            n = store.export_rules(path)
            messagebox.showinfo("Export rules", f"{n} rules (and the manual-only list) written to\n{path}\n\n"
                                                "Author names and edit history are left out.")

    def import_rules(self):
        path = filedialog.askopenfilename(title="Import rules", filetypes=[("STIGTOOL rules", "*.json")],
                                          initialdir=str(store.bundled_rules_path().parent))
        if not path:
            return
        try:
            rep = store.import_rules(path)
        except ValueError as e:
            return messagebox.showerror("Import rules", str(e))
        self.app.load_data()
        self.app.tidy_fixes()  # rules from older versions: banner / Extra comment tidies
        self.after_save()
        messagebox.showinfo("Import rules", f"Added {rep['added']} rule(s). Skipped {rep['skipped']} that already "
                                            f"exist here (not overwritten). {rep['manual_added']} check(s) newly "
                                            "marked Manual only.")

    def starter_drafts(self):
        stig_id = self.stig_map.get(self.stig_var.get())
        scope = self.app.short(stig_id) if stig_id else "ALL imported STIGs"
        if not messagebox.askyesno(
                "Create starter drafts",
                f"Create starter DRAFT rules for {scope}?\n\n"
                "Drafts are written from the STIG check text for Catalyst 9300 / 8300 (IOS-XE 17.x) and Nexus 9000 "
                "(NX-OS 9.3/10.x). Only checks with no rule yet get one - existing rules are never touched. "
                "Every draft must be reviewed and tested before it can be made Active."):
            return
        with busy(self):
            report = drafts.create_drafts(self.app.index, self.app.rules_db, [stig_id] if stig_id else None)
        text = drafts.report_text(report)
        path = store.paths.output / f"starter_drafts_report_{store.stamp()}.txt"
        path.write_text(text + "\n", encoding="utf-8")
        self.after_save()
        ImportReport(self, f"Saved to {path}\n\n{text}")
        if report["manual"] and messagebox.askyesno(
                "Manual only?", f"{len(report['manual'])} check(s) need a human or design decision (listed in the "
                                "report). Mark them 'Manual only' now? You can switch any back later."):
            for stig, vuln_id, *_ in report["manual"]:
                sid = next(s for s, v in self.app.index.items() if v["short"] == stig)
                store.set_manual(assess.key_of(sid, vuln_id), True)
            self.after_save()

    def toggle_manual(self):
        stig_id, c = self.current()
        if not c:
            return select_first(self, "a check in the list on the left")
        key = assess.key_of(stig_id, c["vuln_id"])
        store.set_manual(key, key not in self.app.rules_db.get("manual_controls", []))
        self.after_save()

    def after_save(self):
        self.app.load_data()
        self.refresh()


# ---------------------------------------------------------------- rule editor

class ConditionList(ttk.Frame):
    """A rule's conditions as wrapped cards ('Condition 1' / Command / Look in / Passes if it) joined by AND or OR.

    Click a card to select it, double-click to edit. curselection() works like a Listbox's.
    """

    def __init__(self, parent, on_open, min_lines=4, max_lines=16, grow=True, on_delete=None):
        super().__init__(parent)
        self.min_lines, self.max_lines, self.selected, self.count = min_lines, max_lines, None, 0
        self.grow = grow  # False: the list is given its height by the layout instead of sizing itself
        t = self.t = tk.Text(self, wrap="word", height=min_lines, width=50, font=("Segoe UI", 10), cursor="arrow",
                             padx=4, pady=4, relief="flat", highlightthickness=1, highlightbackground="#c8c8c8",
                             selectbackground="#ffffff", selectforeground="#000000", inactiveselectbackground="#ffffff",
                             tabs=("2.6c",))
        sb = ttk.Scrollbar(self, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        t.tag_configure("card", background="#f3f6fa", lmargin1="0.2c", lmargin2="2.6c", rmargin="0.2c")
        t.tag_configure("head", font=("Segoe UI", 10, "bold"), foreground="#1b4f8a", spacing1=4, lmargin2="0.2c")
        t.tag_configure("label", foreground="#555555")
        t.tag_configure("err", foreground="#b00020", font=("Segoe UI", 10, "bold"))
        t.tag_configure("join", justify="center", foreground="#7a4b00", font=("Segoe UI", 10, "bold"),
                        spacing1=3, spacing3=3)
        t.tag_configure("empty", foreground="#888888", font=("Segoe UI", 10, "italic"))
        t.tag_configure("picked", background="#cfe2ff")
        t.tag_configure("line", background="#f3f6fa", lmargin1="0.2c", lmargin2="1.4c", rmargin="0.2c",
                        spacing1=2, spacing3=2, tabs=("1.4c",))
        t.tag_configure("num", font=("Segoe UI", 10, "bold"), foreground="#1b4f8a")
        t.tag_configure("joinword", font=("Segoe UI", 10, "bold"), foreground="#7a4b00")
        t.configure(state="disabled")
        t.bind("<Button-1>", self.click)
        t.bind("<Double-1>", lambda e: (self.click(e), on_open(), "break")[-1])
        t.bind("<Return>", lambda e: (on_open(), "break")[-1] if self.selected is not None else None)
        if on_delete:
            t.bind("<Delete>", lambda e: (on_delete(), "break")[-1] if self.selected is not None else None)
        t.bind("<Configure>", lambda e: self.after_idle(self.fit))

    def set_items(self, items, joiner, compact=False, one_command=False):
        """items: [((command, where, check), problem or '')]; joiner: 'AND' or 'OR'.

        compact: one wrapped line per condition (for rules with many conditions); one_command leaves out the
        command when the rule only has one.
        """
        t = self.t
        t.configure(state="normal")
        t.delete("1.0", "end")
        if not items:
            t.insert("end", "No conditions yet - click 'Add condition...'.", "empty")
        for i, ((command, where, check), problem) in enumerate(items if compact else []):
            tags = ("line", f"item{i}")
            t.insert("end", f"{joiner:>3}  " if i else "     ", tags + ("joinword",))
            t.insert("end", f"{i + 1}.\t", tags + ("num",))
            t.insert("end", ("" if one_command else f"[{command}] ") + f"{where} {check}", tags)
            t.insert("end", (f"  - Problem: {problem}" if problem else "") + "\n", tags + ("err",))
        for i, ((command, where, check), problem) in enumerate([] if compact else items):
            if i:
                t.insert("end", f"{joiner}\n", "join")
            tags = ("card", f"item{i}")
            t.insert("end", f"Condition {i + 1}\n", tags + ("head",))
            for label, text in (("Command:", command), ("Look in:", where), ("Passes if it:", check)):
                t.insert("end", f"{label}\t", tags + ("label",))
                t.insert("end", f"{text}\n", tags)
            if problem:
                t.insert("end", f"Problem: {problem}\n", tags + ("err",))
        self.count = len(items)
        if self.selected is not None and self.selected >= self.count:
            self.selected = None
        self.paint()
        t.configure(state="disabled")
        self.after_idle(self.fit)

    def fit(self):
        """Grow with the conditions, up to max_lines, then scroll."""
        if not self.grow:
            return
        try:
            lines = self.t.count("1.0", "end", "displaylines")
        except tk.TclError:
            return
        lines = lines[0] if isinstance(lines, tuple) else (lines or 0)
        height = max(self.min_lines, min(self.max_lines, lines))
        if int(self.t.cget("height")) != height:
            self.t.configure(height=height)

    def click(self, event):
        index = self.t.index(f"@{event.x},{event.y}")
        item = next((tag for tag in self.t.tag_names(index) if tag.startswith("item")), None)
        self.selected = int(item[4:]) if item else None
        self.t.focus_set()  # so Delete / Enter act on the selected card
        self.paint()
        return "break"

    def paint(self):
        self.t.tag_remove("picked", "1.0", "end")
        if self.selected is not None:
            ranges = self.t.tag_ranges(f"item{self.selected}")
            for start, end in zip(ranges[0::2], ranges[1::2]):
                self.t.tag_add("picked", start, end)
            self.t.tag_raise("picked")

    def curselection(self):
        return () if self.selected is None else (self.selected,)


# STIG text: lines that are device commands or config examples, and the sentence that says what is a finding.
PROMPT_RE = re.compile(r"^\s*\S*[#>]\s*")
CLI_LINE = re.compile(r"^(\s*\S*[#>]\s*\S|\s*(show|sh)\s+\S|\s+\S"  # prompt, show command, indented
                      r"|[a-z!<.\u2026].*[^.:\s]\s*$|[!.\u2026]+\s*$)")       # config example: starts lower-case, no full stop
FINDING_RE = re.compile(r"[^.\n]*\bthis is (not )?a finding\b[^.\n]*\.?", re.I)


class TryRulesWindow(tk.Toplevel):
    """Run draft rules against the devices in the current SolarWinds import, all at once: see which drafts pass,
    find problems or cannot run, open one with a device's output loaded, save real samples as tests, and
    activate the ones that are ready."""

    SHOW = ["Ready to save tests (2+ different results)", "All drafts", "Show command not collected"]
    OWN_GROUP = "Each device's own group"

    @classmethod
    def open(cls, app):
        return cls(app)

    @staticmethod
    def copy_draft_script(app, parent):
        """A collection script for the show commands draft rules use (for the STIGs your device groups use)."""
        used = {sid for g in app.groups_db.get("groups", []) for sid in g.get("stigs", [])}
        sources = {}
        for r in app.rules_db["rules"]:
            if r.get("state") != "draft" or (used and not {t["stig_id"] for t in store.rule_targets(r)} & used):
                continue
            for c in r.get("commands") or []:
                sources.setdefault(c.strip(), set()).add(f"{app.short(r['stig_id'])} {r['vuln_id']}")
        if not sources:
            return messagebox.showinfo("Collection script", "No draft rule for your groups' STIGs has a show "
                                                            "command yet.", parent=parent)
        script, sid = collect.build_script(sources, ["DRAFT-TRIAL"])
        store.save_script_record({"script_id": sid, "created": store.now(), "created_by": store.current_user(),
                                  "groups": ["DRAFT-TRIAL"], "commands": sorted(sources)})
        path = store.paths.output / "scripts" / f"collect_draft_trial_{sid}.txt"
        path.write_text(script, encoding="utf-8")
        parent.clipboard_clear()
        parent.clipboard_append(script)
        messagebox.showinfo("Collection script", f"A script for {len(sources)} show command(s) used by the drafts "
                                                 f"is on the clipboard (also saved to {path}).\n\nRun it in "
                                                 "SolarWinds on a few representative devices, save the output, "
                                                 "import it on Run an assessment > 2. Import, then open Try drafts.",
                            parent=parent)

    def __init__(self, app):
        super().__init__(app)
        self.app, self.results, self.run, self.devices = app, {}, None, []
        self.ungrouped = self.tried_on = 0
        self.title("Try drafts on real output")
        maximize(self, "1300x860")
        help_label(self, "Turn draft rules into tested, active rules using real device output - all in this window. "
                         "The results only show what each draft WOULD say; nothing changes until you save tests or "
                         "activate. This import is only for trying drafts: it does not replace the assessment.")
        steps = ttk.LabelFrame(self, text=" Get real output ")
        steps.pack(fill="x", padx=6, pady=(2, 6))
        r1 = ttk.Frame(steps)
        r1.pack(fill="x", padx=6, pady=3)
        ttk.Button(r1, text="1. Copy collection script for the drafts", command=self.copy_script).pack(side="left")
        fit_text(ttk.Label(r1, foreground="#5f6368", text="Run it in SolarWinds on a few devices of one type - "
                                                          "ideally one well configured and one not - and save the "
                                                          "output as a text file.")).pack(
            side="left", fill="x", expand=True, padx=8)
        r2 = ttk.Frame(steps)
        r2.pack(fill="x", padx=6, pady=3)
        ttk.Button(r2, text="2. Import SolarWinds output...", style="Accent.TButton",
                   command=self.import_output).pack(side="left")
        self.use_run_btn = ttk.Button(r2, text="Use the assessment import instead", command=self.use_assessment)
        if app.run and any(d["status"] == "ok" for d in app.run["devices"]):
            self.use_run_btn.pack(side="left", padx=6)
        self.source_label = fit_text(ttk.Label(r2, text="", font=("Segoe UI Semibold", 10)))
        self.source_label.pack(side="left", fill="x", expand=True, padx=8)
        r3 = ttk.Frame(steps)
        r3.pack(fill="x", padx=6, pady=(3, 6))
        ttk.Label(r3, text="3. Try the drafts as device group:").pack(side="left")
        self.as_group = tk.StringVar(value=self.OWN_GROUP)
        groups = [g["id"] for g in app.groups_db.get("groups", [])]
        box = ttk.Combobox(r3, textvariable=self.as_group, values=[self.OWN_GROUP] + groups, state="readonly", width=30)
        box.pack(side="left", padx=6)
        box.bind("<<ComboboxSelected>>", lambda e: self.compute())
        fit_text(ttk.Label(r3, foreground="#5f6368", text="Only drafts for that group's STIGs are tried. Pick a "
                                                          "group if the devices are not in one yet.")).pack(
            side="left", fill="x", expand=True, padx=6)
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=6)
        ttk.Label(bar, text="Show:").pack(side="left")
        self.show_var = tk.StringVar(value=self.SHOW[1])
        ttk.Combobox(bar, textvariable=self.show_var, values=self.SHOW, state="readonly", width=40).pack(
            side="left", padx=4)
        ttk.Label(bar, text="Search:").pack(side="left", padx=(10, 0))
        self.search_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.search_var, width=22).pack(side="left", padx=4)
        ttk.Label(bar, text="Try on:").pack(side="left", padx=(10, 0))
        self.limit_var = tk.StringVar(value="up to 10 devices")
        self.limit_box = ttk.Combobox(bar, textvariable=self.limit_var, values=["up to 10 devices"],
                                      state="readonly", width=16)
        self.limit_box.pack(side="left", padx=4)
        self.limit_box.bind("<<ComboboxSelected>>", lambda e: self.compute())
        for var in (self.show_var, self.search_var):
            var.trace_add("write", lambda *a: self.refresh())
        self.summary = fit_text(ttk.Label(bar, text="", foreground="#333"))
        self.summary.pack(side="left", fill="x", expand=True, padx=10)

        b = ttk.Frame(self)
        b.pack(side="bottom", fill="x", padx=6, pady=6)
        ttk.Button(b, text="Open in rule editor", command=self.open_editor).pack(side="left")
        ttk.Button(b, text="Save samples as tests...", command=self.save_tests).pack(side="left", padx=6)
        ttk.Button(b, text="Activate selected...", command=self.activate, style="Accent.TButton").pack(side="left")
        ttk.Button(b, text="Close", command=self.destroy).pack(side="right")
        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True, padx=6, pady=6)
        top, self.tree = make_tree(paned, [("results", "Results on devices", 330), ("tests", "Tests", 60),
                                           ("rule", "Rule", 80), ("title", "Title", 300)], height=16,
                                   selectmode="extended", tree_column=("STIG / Vuln ID", 220))
        self.tree.tag_configure("ready", background="#d9f7d6")
        self.tree.tag_configure("missing", background="#f4f4f4", foreground="#666")
        self.tree.tag_configure("family", font=("Segoe UI Semibold", 10))
        self.tree.tag_configure("stig", font=("Segoe UI Semibold", 10))
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.show_detail())
        self.tree.bind("<Double-1>", lambda e: self.open_editor() if self.selected_rules() else None)
        paned.add(top, weight=3)
        self.detail = ScrolledText(paned, height=8, wrap="word", font=MONO)
        paned.add(self.detail, weight=1)
        PaneKeeper(paned, [0.7])
        last = store.load_my_view().get("try_drafts_file")
        if last and Path(last).exists():
            self.load_file(last, quiet=True)
        else:
            self.compute()

    # -- where the device output comes from
    def load(self, run, label):
        self.run = run
        self.devices = [d for d in run["devices"] if d["status"] == "ok"]
        self.limit_box["values"] = ["up to 10 devices", f"all {len(self.devices)} devices"]
        self.limit_var.set("up to 10 devices")
        note = ""
        groups = [g["id"] for g in self.app.groups_db.get("groups", [])]
        if self.as_group.get() == self.OWN_GROUP and groups and                 not any(run["membership"].get(d["host"], {}).get("group") for d in self.devices):
            self.as_group.set(groups[0])  # none of these devices is in a group yet: try them as one
            note = f" - none is in a group, so they are tried as {groups[0]} (change it in step 3)"
        self.source_label.configure(text=f"{label}: {len(self.devices)} device(s) with output{note}")
        self.compute()

    def load_file(self, path, quiet=False):
        with busy(self):
            run = assess.import_solarwinds(path, self.app.groups_db, self.app.rules_db, keep_evidence=False)
        if not any(d["status"] == "ok" for d in run["devices"]):
            if not quiet:
                messagebox.showerror("Not SolarWinds output", f"No device output was found in "
                                                              f"{Path(path).name}.", parent=self)
            return
        store.save_my_view({"try_drafts_file": str(path)})
        self.load(run, f"Using {Path(path).name}")

    def import_output(self):
        path = filedialog.askopenfilename(parent=self, title="SolarWinds output to try the drafts on",
                                          initialdir=str(store.paths.input),
                                          filetypes=[("Text files", "*.txt *.log"), ("All files", "*.*")])
        if path:
            self.load_file(path)

    def use_assessment(self):
        run = self.app.run
        if run:
            self.load(run, f"Using the assessment import ({run['source_name']})")

    def drafts(self):
        return [r for r in self.app.rules_db["rules"] if r.get("state") == "draft" and r.get("commands")]

    def stigs_of(self, host):
        """The STIGs a device's group uses: a draft is only tried on devices it is meant for."""
        gid = self.as_group.get()
        if gid == self.OWN_GROUP:
            gid = self.run["membership"].get(host, {}).get("group")
        group = assess.find_group(self.app.groups_db, gid) if gid else None
        return set(group.get("stigs", [])) if group else set()

    def compute(self):
        if not self.run:
            self.results = {}
            self.refresh()
            return
        devices = [d for d in self.devices if self.stigs_of(d["host"])]
        self.ungrouped = len(self.devices) - len(devices)
        devices = devices if self.limit_var.get().startswith("all") else devices[:10]
        self.tried_on = len(devices)
        self.results = {}
        with busy(self):
            for r in self.drafts():
                per = {}
                targets = {t["stig_id"] for t in store.rule_targets(r)}
                for d in devices:
                    if not targets & self.stigs_of(d["host"]):
                        continue  # this device's group does not use the draft's STIG
                    if not all(c in d["outputs"] for c in r["commands"]):
                        per[d["host"]] = ("missing", ["show command not in this import"])
                        continue
                    res = engine.evaluate(r, d["outputs"])
                    per[d["host"]] = (res["status"], res["reasons"])
                self.results[r["id"]] = per
        self.refresh()

    def kinds(self, rid):
        """Distinct results a rule gives (Not a Finding / Open / Not Applicable), ignoring missing output."""
        return {st for st, _ in self.results.get(rid, {}).values() if st in ("not_a_finding", "open", "not_applicable")}

    def refresh(self):
        show, needle = self.show_var.get(), self.search_var.get().lower().strip()
        keep = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        by_stig, ready, missing = {}, 0, 0
        for r in self.drafts():
            per = self.results.get(r["id"], {})
            if not per and not show.startswith("All"):
                continue
            kinds = self.kinds(r["id"])
            is_missing = per and all(st == "missing" for st, _ in per.values())
            ready += len(kinds) >= 2
            missing += bool(is_missing)
            if show.startswith("Ready") and len(kinds) < 2:
                continue
            if show.startswith("Show command") and not is_missing:
                continue
            c = self.app.index.get(r["stig_id"], {}).get("controls", {}).get(r["vuln_id"])
            title = c["title"] if c else ""
            if needle and needle not in f"{r['vuln_id']} {r['id']} {title}".lower():
                continue
            by_stig.setdefault(r["stig_id"], []).append((r, per, kinds, title, is_missing))
        for family, grouped, items in stig_families(self.app, by_stig):
            fam_iid = f"F::{family}"
            if grouped:
                self.tree.insert("", "end", iid=fam_iid, text=family, tags=("family",), open=True)
            for sid, part in items:
                stig_iid = f"S::{sid}"
                self.tree.insert(fam_iid if grouped else "", "end", iid=stig_iid, tags=("stig",), open=True,
                                 text=part or self.app.short(sid), values=(f"{len(by_stig[sid])} draft(s)", "", "", ""))
                for r, per, kinds, title, is_missing in by_stig[sid]:
                    counts = {}
                    for st, _ in per.values():
                        counts[st] = counts.get(st, 0) + 1
                    text = ", ".join(f"{n} {STATUS_LABELS.get(st, 'not collected')}" for st, n in
                                     sorted(counts.items())) or "-"
                    tag = "missing" if is_missing else "ready" if len(kinds) >= 2 else ""
                    self.tree.insert(stig_iid, "end", iid=r["id"], text=r["vuln_id"], tags=(tag,),
                                     values=(text, len(r.get("tests", [])), r["id"], title))
        untried = sum(1 for r in self.drafts() if not self.results.get(r["id"]))
        if not self.run:
            self.summary.configure(text="No device output yet - do steps 1 and 2 above.")
            return
        self.summary.configure(
            text=f"Tried on {self.tried_on} device(s): {ready} draft(s) give 2+ different results (ready to save "
                 f"tests), {missing} cannot run (show command not collected), {untried} not tried (no device in "
                 "this import belongs to a group that uses their STIG)."
                 + (f" {self.ungrouped} device(s) are in no group and were skipped - pick a group in step 3."
                    if self.ungrouped else ""))
        keep = [k for k in keep if self.tree.exists(k)]
        if keep:
            self.tree.selection_set(keep)

    def selected_rules(self):
        return [self.app.rule_by_id(i) for i in self.tree.selection()
                if not i.startswith(("F::", "S::")) and self.app.rule_by_id(i)]

    def show_detail(self):
        rules = self.selected_rules()
        if not rules:
            text_set(self.detail, "Select a draft to see what it found on each device.", readonly=True)
            return
        r = rules[0]
        lines = [f"{r['id']} '{r.get('name', '')}' - {', '.join(r['commands'])}", ""]
        for host, (st, reasons) in sorted(self.results.get(r["id"], {}).items()):
            lines.append(f"{host:<28} {STATUS_LABELS.get(st, 'NOT COLLECTED')}")
            lines += [f"    {x}" for x in reasons[:3]]
        text_set(self.detail, "\n".join(lines), readonly=True)

    def open_editor(self):
        rules = self.selected_rules()
        if not rules:
            return select_first(self, "a draft in the list")
        r = rules[0]
        control = self.app.index.get(r["stig_id"], {}).get("controls", {}).get(r["vuln_id"])
        if not control:
            return messagebox.showinfo("Open", "That STIG is not imported.", parent=self)
        ed = RuleEditor.open(self.app, r["stig_id"], control, r, lambda: (self.app.load_data(), self.compute()))
        if not ed:
            return
        host = next((h for h, (st, _) in self.results.get(r["id"], {}).items() if st != "missing"), None)
        device = next((d for d in self.devices if d["host"] == host), None)
        if device:
            ed.sample = {c: device["outputs"][c]["text"] for c in r["commands"] if c in device["outputs"]}
            ed.switch_command(store_current=False)

    def save_tests(self):
        rules = [r for r in self.selected_rules() if len(self.kinds(r["id"])) >= 1]
        if not rules:
            return select_first(self, "one or more drafts that gave a result (Ctrl-click for several)")
        if not messagebox.askyesno(
                "Save samples as tests",
                f"Save real device output as tests for {len(rules)} rule(s)? Each test expects the result the rule "
                "gives NOW (one sample per different result).\n\nOnly do this for rules whose results you checked "
                "are right: a test that expects a wrong result makes a wrong rule look right.", parent=self):
            return
        run_id, saved, skipped = self.run["id"], 0, []
        for r in rules:
            if store.lock_holder("rule", r["id"]):
                skipped.append(f"{r['id']} (someone has it open)")
                continue
            picks = {}
            for host, (st, _) in self.results[r["id"]].items():
                if st in ("not_a_finding", "open", "not_applicable") and st not in picks:
                    picks[st] = next(d for d in self.devices if d["host"] == host)
            new = [{"name": f"{d['host']} (import {run_id})", "expected": st,
                    "outputs": {c: d["outputs"][c]["text"] for c in r["commands"]},
                    "saved_at": store.now(), "saved_by": store.current_user()} for st, d in picks.items()]

            def change(rule, new=new):
                names = {t["name"] for t in rule.get("tests", [])}
                rule.setdefault("tests", []).extend(t for t in new if t["name"] not in names)
            store.modify_rule(r["id"], change)
            saved += len(new)
        self.app.load_data()
        self.refresh()
        messagebox.showinfo("Tests saved", f"{saved} test sample(s) saved." + (
            "\nSkipped: " + ", ".join(skipped) if skipped else ""), parent=self)

    def activate(self):
        rules = self.selected_rules()
        if not rules:
            return select_first(self, "the drafts to activate (Ctrl-click for several)")
        ready, not_ready = [], []
        for r in rules:
            problems = engine.activation_problems(r)
            (not_ready if problems else ready).append((r, problems))
        msg = f"Activate {len(ready)} rule(s)? Device groups start using them in the next assessment."
        if not_ready:
            msg += f"\n\n{len(not_ready)} are not ready and stay drafts, e.g. {not_ready[0][0]['id']}: " \
                   f"{not_ready[0][1][0]}"
        if not ready:
            return messagebox.showinfo("Activate", msg, parent=self)
        if not messagebox.askyesno("Activate", msg, parent=self):
            return
        for r, _ in ready:
            def change(rule):
                rule.setdefault("history", []).append({k: v for k, v in rule.items()
                                                       if k not in ("history", "review_log")})
                rule.update(state="active", version=rule.get("version", 1) + 1)
            store.modify_rule(r["id"], change)
        self.app.load_data()
        self.compute()
        messagebox.showinfo("Activated", f"{len(ready)} rule(s) are now active.", parent=self)

    def copy_script(self):
        TryRulesWindow.copy_draft_script(self.app, self)


class UsedByDialog(tk.Toplevel):
    """Pick the device groups that use a rule version. result = [] (all groups), [group ids], or None (cancel)."""

    def __init__(self, parent, app, stig_ids, current, title="Which device groups use this version?"):
        super().__init__(parent)
        self.title("Used by")
        self.transient(parent)
        self.resizable(False, True)
        self.result = None
        f = ttk.Frame(self, padding=12)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text=title, font=("Segoe UI Semibold", 11)).pack(anchor="w")
        fit_text(ttk.Label(f, foreground="#5f6368", text=(
            "A version for some groups is used by those groups for this check; every other group keeps the "
            "default version. Only groups that are assessed against this check's STIG are listed."))).pack(
            fill="x", pady=(2, 8))
        self.all_var = tk.BooleanVar(value=not current)
        ttk.Radiobutton(f, text="All device groups (default)", variable=self.all_var, value=True,
                        command=self.toggle).pack(anchor="w")
        ttk.Radiobutton(f, text="Only these device groups:", variable=self.all_var, value=False,
                        command=self.toggle).pack(anchor="w", pady=(4, 0))
        box = ttk.Frame(f, padding=(22, 2, 0, 0))
        box.pack(fill="both", expand=True)
        groups = [g for g in app.groups_db.get("groups", []) if set(g.get("stigs", [])) & set(stig_ids)]
        self.vars, self.boxes = {}, []
        for g in groups:
            var = tk.BooleanVar(value=g["id"] in (current or []))
            cb = ttk.Checkbutton(box, text=g["id"] + (f"   - {g['description']}" if g.get("description") else ""),
                                 variable=var)
            cb.pack(anchor="w")
            self.vars[g["id"]], self.boxes = var, self.boxes + [cb]
        for gid in current or []:
            if gid not in self.vars:  # a group that no longer uses this STIG (or was deleted): keep it visible
                var = tk.BooleanVar(value=True)
                cb = ttk.Checkbutton(box, text=f"{gid}   (does not use this STIG now)", variable=var)
                cb.pack(anchor="w")
                self.vars[gid], self.boxes = var, self.boxes + [cb]
        if not self.vars:
            ttk.Label(box, text="No device group uses this STIG yet.", foreground="#5f6368").pack(anchor="w")
        b = ttk.Frame(f)
        b.pack(fill="x", pady=(10, 0))
        ttk.Button(b, text="OK", style="Accent.TButton", command=self.ok).pack(side="left")
        ttk.Button(b, text="Cancel", command=self.destroy).pack(side="left", padx=6)
        self.toggle()
        self.grab_set()
        parent.wait_window(self)

    def toggle(self):
        for cb in self.boxes:
            cb.state(["disabled"] if self.all_var.get() else ["!disabled"])

    def ok(self):
        if self.all_var.get():
            self.result = []
        else:
            picked = [gid for gid, var in self.vars.items() if var.get()]
            if not picked:
                return messagebox.showinfo("Used by", "Tick at least one group, or choose 'All device groups'.",
                                           parent=self)
            self.result = picked
        self.destroy()


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
            "na_logic": {"mode": "ALL", "conditions": []}, "notes": "", "tests": []}
        self.r.setdefault("na_logic", {"mode": "ALL", "conditions": []})
        self.r.setdefault("tests", [])
        if self.original is None:
            self.r.update(stig_id=stig_id, vuln_id=control["vuln_id"])
        self.unmanual = set()  # Manual-only controls this rule was just shared with; cleared on save
        self.clear_choices = set()  # groups whose own choice for this check is removed on save (see 'Used by')
        name = app.short(stig_id)
        self.title(f"Rule - {name} {control['vuln_id']} {control['rule_ver']}"
                   + (f" - {self.r['id']}" if self.r.get("id") else " - new") + ("  (READ-ONLY)" if readonly else ""))
        maximize(self, "1420x900")
        self.sample, self.cur_cmd, self._job, self._loading = {}, None, None, False
        app.open_editors.add(self)

        top = ttk.Frame(self)
        top.pack(fill="x", padx=8, pady=(8, 0))
        fit_text(ttk.Label(top, text=f"{name} {control['vuln_id']} ({control['rule_ver']}, {control['severity']}): "
                                     f"{control['title']}", font=("Segoe UI", 10, "bold"))).pack(fill="x")
        fit_text(ttk.Label(top, text=f"STIG release {app.index[stig_id]['release']}, imported as {app.formats_text(stig_id)}. "
                            "Rules apply to the STIG whichever checklist format is written.",
                  foreground="#555")).pack(fill="x")
        share = ttk.Frame(top)
        share.pack(fill="x", pady=(2, 0))
        ttk.Button(share, text="Use for other checks...", command=self.share).pack(side="left")
        self.share_label = fit_text(ttk.Label(share, text=""))
        self.share_label.pack(side="left", fill="x", expand=True, padx=8)
        self.show_shared()
        self.show_stig_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Show the STIG requirement on the left", variable=self.show_stig_var,
                        command=self.toggle_stig).pack(anchor="e")
        if harden.has_fix(self.r):
            fit_text(ttk.Label(top, foreground="#555",
                      text=f"Fix commands: {harden.FIX_STATUS[harden.fix_status(self.r)].lower()} (edited and "
                           "reviewed on the Fix commands tab). Changing this rule's commands or conditions sends "
                           "them back for review.")).pack(fill="x")
        if readonly:
            tk.Label(top, text="READ-ONLY: someone else is editing this rule. You can test it but not save.",
                     bg="#fff0c2", anchor="w", padx=6).pack(fill="x", pady=(4, 0))
        if self.original and (store.rule_check_hash(self.original, stig_id, control["vuln_id"])
                              != control["check_hash"]):
            self._changed_banner(top)
        self.paned = paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=8, pady=8)
        self.stig_pane, left, right = ttk.Frame(paned), ttk.Frame(paned), ttk.Frame(paned)
        for pane in (self.stig_pane, left, right):
            paned.add(pane, weight=1)
        self._build_stig(self.stig_pane)
        self._build_left(left)
        self._build_right(right)
        self.show_stig_var.set(store.load_my_view().get("editor_stig_text", True))
        self.pane_keeper = PaneKeeper(paned, [0.30, 0.64])
        self.after(100, self._place_sashes)
        self._load_form()
        if self.r["tests"]:
            self.load_test(self.r["tests"][0])
        self.run_all_tests(quiet=True)
        self.schedule()
        self._baseline = self.fingerprint()
        self.protocol("WM_DELETE_WINDOW", self.cancel)

    def _changed_banner(self, parent):
        old_rel, old = store.find_control_version(
            self.stig_id, self.control["vuln_id"],
            store.rule_check_hash(self.original, self.stig_id, self.control["vuln_id"]))
        self.banner = tk.Frame(parent, bg="#ffd6d6")
        self.banner.pack(fill="x", pady=(4, 0))
        tk.Label(self.banner, bg="#ffd6d6", anchor="w", padx=6,
                 text=f"DISA changed this check's text in {self.app.index[self.stig_id]['release']}"
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
        saved = store.mark_rule_reviewed(self.original["id"], self.stig_id, self.control["vuln_id"],
                                         self.control["check_hash"], self.app.index[self.stig_id]["release"])
        for d in (self.original, self.r):
            store.set_rule_check_hash(d, self.stig_id, self.control["vuln_id"], self.control["check_hash"])
            d.update(_rev=saved["_rev"], review_log=saved.get("review_log", []))
        self.banner.destroy()
        self.on_saved()

    # -- STIG requirement pane
    def _build_stig(self, f):
        head = ttk.Frame(f)
        head.pack(fill="x")
        ttk.Label(head, text="STIG requirement", style="Big.TLabel").pack(side="left")
        ttk.Label(head, text="Find:").pack(side="left", padx=(14, 2))
        self.find_var = tk.StringVar()
        find = ttk.Entry(head, textvariable=self.find_var, width=16)
        find.pack(side="left")
        find.bind("<Return>", lambda e: self.find_in_stig(next_hit=True))
        self.find_var.trace_add("write", lambda *a: self.find_in_stig())
        self.find_count = ttk.Label(head, text="", foreground="#555")
        self.find_count.pack(side="left", padx=6)
        fit_text(ttk.Label(f, foreground="#555",
                           text="Commands are in grey. Right-click a 'show' command to add it to the rule.")).pack(
            side="bottom", fill="x", pady=(4, 0))
        t = ScrolledText(f, wrap="word", font=("Segoe UI", 10), padx=8, pady=6, width=40)
        t.pack(fill="both", expand=True, pady=(4, 0))
        t.tag_configure("title", font=("Segoe UI", 11, "bold"), spacing3=4)
        t.tag_configure("meta", foreground="#555")
        t.tag_configure("head", font=("Segoe UI", 10, "bold"), foreground="#1b4f8a", spacing1=10, spacing3=4)
        t.tag_configure("cli", font=MONO, background="#eeeeee", lmargin1=12, lmargin2=12)
        t.tag_configure("finding", background="#ffe2b8", font=("Segoe UI", 10, "bold"))
        t.tag_configure("hit", background="#fff36b")
        c = self.control
        t.insert("end", c["title"] + "\n", "title")
        t.insert("end", f"{c['vuln_id']}   {c['rule_ver']}   severity: {c['severity']}\n", "meta")
        for name, body in (("CHECK", c["check"]), ("FIX", c["fix"])):
            t.insert("end", f"\n{name}\n", "head")
            for line in (body or "").replace("\r\n", "\n").split("\n"):
                if CLI_LINE.match(line):
                    t.insert("end", line + "\n", "cli")
                    continue
                pos = 0
                for m in FINDING_RE.finditer(line):
                    t.insert("end", line[pos:m.start()])
                    t.insert("end", m.group(0), "finding")
                    pos = m.end()
                t.insert("end", line[pos:] + "\n")
        t.configure(state="disabled")
        t.bind("<Button-3>", self.stig_menu)
        self.stig_text, self._hit = t, -1

    def _place_sashes(self):
        if self.show_stig_var.get():
            self.pane_keeper.set([0.30, 0.64])
        else:
            if str(self.stig_pane) in self.paned.panes():
                self.paned.forget(self.stig_pane)
            self.pane_keeper.set([0.5])

    def toggle_stig(self):
        show = self.show_stig_var.get()
        store.save_my_view({"editor_stig_text": show})
        if show and str(self.stig_pane) not in self.paned.panes():
            self.paned.insert(0, self.stig_pane, weight=1)
        self.after(50, self._place_sashes)

    def find_in_stig(self, next_hit=False):
        t, needle = self.stig_text, self.find_var.get().strip()
        t.tag_remove("hit", "1.0", "end")
        hits, idx = [], "1.0"
        while needle:
            idx = t.search(needle, idx, "end", nocase=True)
            if not idx:
                break
            end = f"{idx}+{len(needle)}c"
            t.tag_add("hit", idx, end)
            hits.append(idx)
            idx = end
        self.find_count.configure(text=f"{len(hits)} found" if needle else "")
        if hits:
            self._hit = (self._hit + 1) % len(hits) if next_hit else 0
            t.see(hits[self._hit])

    def stig_menu(self, event):
        t = self.stig_text
        try:
            text = t.get("sel.first", "sel.last")
        except tk.TclError:
            text = t.get(f"@{event.x},{event.y} linestart", f"@{event.x},{event.y} lineend")
        first = text.strip().splitlines()[0] if text.strip() else ""
        cmd = PROMPT_RE.sub("", first).strip()
        menu = tk.Menu(self, tearoff=0)
        if re.match(r"(show|sh)\s", cmd, re.I):
            menu.add_command(label=f"Add '{cmd[:70]}' as a show command", command=lambda: self.add_command(cmd))
        menu.add_command(label="Copy", command=lambda: (self.clipboard_clear(), self.clipboard_append(text)))
        menu.tk_popup(event.x_root, event.y_root)

    def add_command(self, cmd):
        cmds = self.commands()
        if cmd not in cmds:
            text_set(self.cmd_text, "\n".join(cmds + [cmd]))
            self.commands_changed()

    # -- layout
    def _build_left(self, f):
        btns = ttk.Frame(f)  # packed first at the bottom so it stays visible on small screens
        btns.pack(side="bottom", fill="x", pady=8)
        ttk.Button(btns, text="Save rule (Ctrl+S)", command=self.save, style="Accent.TButton").pack(side="left")
        self.bind("<Control-s>", lambda e: (self.save(), "break")[-1])
        ttk.Button(btns, text="Cancel", command=self.cancel).pack(side="left", padx=6)
        self.activate_btn = ttk.Button(btns, text="Activate and save", style="Accent.TButton",
                                       command=self.activate)
        self.ready_label = fit_text(ttk.Label(btns, text="", foreground="#666"))
        self.ready_label.pack(side="left", fill="x", expand=True, padx=10)
        self.rule_scroll = ScrollFrame(f)  # a short window scrolls this pane instead of cutting off its bottom
        self.rule_scroll.pack(fill="both", expand=True)
        f = self.rule_scroll.inner

        ttk.Label(f, text="Rule", style="Big.TLabel").pack(anchor="w")
        row = ttk.Frame(f)
        row.pack(fill="x", pady=(4, 0))
        ttk.Label(row, text="Rule name:").pack(side="left")
        # State and revision claim their room first; the name box gives way on a narrow pane
        self.rev_label = ttk.Label(row, text="")
        self.rev_label.pack(side="right", padx=(10, 0))
        self.state_var = tk.StringVar()
        state_box = ttk.Combobox(row, textvariable=self.state_var, values=RULE_STATES, state="readonly", width=9)
        state_box.pack(side="right", padx=4)
        state_box.bind("<<ComboboxSelected>>", lambda e: self.show_readiness())
        ttk.Label(row, text="State:").pack(side="right", padx=(10, 0))
        self.name_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.name_var, width=28).pack(side="left", fill="x", expand=True, padx=4)
        used = ttk.Frame(f)
        used.pack(fill="x", pady=(4, 0))
        ttk.Label(used, text="Used by:").pack(side="left")
        ttk.Button(used, text="Change...", command=self.change_used_by).pack(side="right")
        self.used_label = fit_text(ttk.Label(used, text="", font=("Segoe UI Semibold", 10)))
        self.used_label.pack(side="left", fill="x", expand=True, padx=(12, 4))

        fit_text(ttk.Label(f, text="Show commands to collect (one per line, exactly as typed on the device):")).pack(
            fill="x", pady=(8, 0))
        self.cmd_text = config_wrap(tk.Text(f, height=3, width=50, font=MONO))
        self.cmd_text.pack(fill="x")
        self.cmd_text.bind("<KeyRelease>", lambda e: self.commands_changed())
        ai = ttk.Frame(f)
        ai.pack(fill="x", pady=(4, 0))
        ttk.Button(ai, text="Ask an AI to write the conditions...", command=lambda: AiHandoffDialog(self)).pack(
            side="left")
        fit_text(ttk.Label(ai, foreground="#555", text="Copies a prompt for an approved AI; paste its answer back "
                                                       "and it is checked before it is used.")).pack(
            side="left", fill="x", expand=True, padx=6)

        self.compact_var = tk.BooleanVar(value=store.load_my_view().get("compact_conditions", False))
        self.pass_box, self.pass_mode = self._condition_block(
            f, "NOT A FINDING when", "...of the conditions below are true. Anything else = OPEN.", "pass_logic", height=6, grow=True)
        na_head = ttk.Frame(f)
        na_head.pack(fill="x", pady=(10, 0))
        self.na_var = tk.BooleanVar()
        ttk.Checkbutton(na_head, text="Use a Not Applicable check", variable=self.na_var,
                        command=self.schedule).pack(side="left")
        fit_text(ttk.Label(na_head, text="(checked before the Not a Finding check)", foreground="#555")).pack(
            side="left", fill="x", expand=True, padx=4)
        self.na_box, self.na_mode = self._condition_block(
            f, "NOT APPLICABLE when", "...of the conditions below are true.", "na_logic", height=2)

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
        self.outcome_where = fit_text(ttk.Label(row, text="", foreground="#555"))
        self.outcome_where.pack(side="left", fill="x", expand=True)
        self.outcome_box = tk.Text(fd, height=3, width=50, wrap="word", font=("Segoe UI", 10))
        self.outcome_box.pack(fill="x", pady=2)
        self.outcome_box.bind("<KeyRelease>", lambda e: (self.store_outcome(), self.schedule()))
        self.expected_var = tk.BooleanVar()
        ttk.Checkbutton(fd, variable=self.expected_var, command=self.schedule,
                        text="Open is INTENTIONAL for this rule").pack(anchor="w")
        fit_text(ttk.Label(fd, foreground="#555", text="A known finding, e.g. you recommend risk acceptance. "
                                                       "Reviewers see 'Open (expected)'.")).pack(fill="x", padx=(22, 0))
        nt = ttk.Frame(extra, padding=4)
        extra.add(nt, text=" Reviewer guidance ")
        ttk.Label(nt, text="Notes for reviewers and rule authors (not written to the checklist):",
                  foreground="#555").pack(anchor="w")
        self.notes_text = tk.Text(nt, height=4, width=50, wrap="word", font=("Segoe UI", 10))
        self.notes_text.pack(fill="x")
        self.after_idle(self.rule_scroll.bind_wheel)

    def _condition_block(self, parent, head, tail, logic_key, height, grow=False):
        frame = ttk.LabelFrame(parent, text="")
        frame.pack(fill="both" if grow else "x", expand=grow, pady=(8, 0))
        hdr = ttk.Frame(frame)
        hdr.pack(fill="x", padx=4, pady=2)
        ttk.Label(hdr, text=head, font=("Segoe UI", 10, "bold")).pack(side="left")
        mode = tk.StringVar(value="ALL")
        box = ttk.Combobox(hdr, textvariable=mode, values=["ALL", "ANY"], state="readonly", width=5)
        box.pack(side="left", padx=4)
        box.bind("<<ComboboxSelected>>", lambda e: (self.render_conditions(), self.schedule()))
        if grow:  # packed before the wrapping text so it always keeps its room
            ttk.Checkbutton(hdr, text="Compact", variable=self.compact_var,
                            command=self.toggle_compact).pack(side="right")
        fit_text(ttk.Label(frame, text=tail, foreground="#5f6368")).pack(fill="x", padx=6)
        lb = ConditionList(frame, on_open=lambda: self.edit_condition(logic_key, lb), min_lines=height, grow=not grow,
                           on_delete=lambda: self.remove_condition(logic_key, lb))
        lb.pack(fill="both" if grow else "x", expand=grow, padx=4)
        b = ttk.Frame(frame)
        b.pack(fill="x", padx=4, pady=2)
        ttk.Button(b, text="Add condition...", command=lambda: self.edit_condition(logic_key, lb, new=True)).pack(
            side="left")
        ttk.Button(b, text="Edit...", width=7,
                   command=lambda: self.edit_condition(logic_key, lb)).pack(side="left", padx=2)
        ttk.Button(b, text="Remove", width=8,
                   command=lambda: self.remove_condition(logic_key, lb)).pack(side="left", padx=2)
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
        fill = ttk.Frame(f)
        fill.pack(fill="x", pady=(0, 2))
        more_button(fill, [("Copy it from a device in the last SolarWinds import...", self.load_from_device), None,
                           ("EMPTY - the command ran and printed nothing (counts as evidence)", self.set_empty),
                           ("MISSING - the command did not run (always Not Reviewed)", self.set_missing)],
                    "Fill sample").pack(side="left")
        fit_text(ttk.Label(fill, foreground="#555", text="...or paste real device output into the box below.")).pack(
            side="left", fill="x", expand=True, padx=6)
        self.sample_state = fit_text(ttk.Label(f, text="", foreground="#555"))
        self.sample_state.pack(fill="x")

        tf = ttk.Frame(f)  # packed last so the widgets below it always get their space
        self.sample_text = config_wrap(tk.Text(tf, height=12, width=50, font=MONO, undo=True), stripes=False)
        ys = ttk.Scrollbar(tf, orient="vertical", command=self.sample_text.yview)
        self.sample_text.configure(yscrollcommand=ys.set)
        self.sample_text.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
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

        self.explain = ScrolledText(f, height=5, width=50, wrap="word", font=MONO)


        tests = ttk.LabelFrame(f, text="Saved tests (re-run every time the rule changes)")

        tfr, self.test_tree = make_tree(tests, [("name", "Test name", 240), ("exp", "Expected", 120),
                                                ("got", "Rule gives", 120), ("res", "Result", 70)], height=4)
        tfr.pack(fill="x", padx=4)
        color_tags(self.test_tree, {"pass": "#d9f7d6", "fail": "#ffd6d6"})
        self.test_tree.bind("<Double-1>", lambda e: self.load_selected_test())
        right_click_menu(self.test_tree, [("Load this test into the sample", self.load_selected_test), None,
                                          ("Delete test", self.delete_test)])
        b = ttk.Frame(tests)
        b.pack(fill="x", padx=4, pady=4)
        ttk.Button(b, text="Save current sample as a test...", command=self.save_test).pack(side="left")
        fit_text(ttk.Label(b, text="Double-click a test to load it. Right-click to delete.", foreground="#555")).pack(
            side="left", fill="x", expand=True, padx=8)
        tests.pack(side="bottom", fill="x", pady=(6, 0))
        self.explain.pack(side="bottom", fill="x")
        self.result_label.pack(side="bottom", fill="x", pady=(6, 0))
        legend.pack(side="bottom", fill="x", pady=2)
        tf.pack(fill="both", expand=True)

    # -- form <-> rule
    def _load_form(self):
        self.name_var.set(self.r.get("name", ""))
        self.show_used_by()
        self.state_var.set(self.r.get("state", "draft"))
        self.rev_label.configure(text=f"Revision {self.r.get('version', 0)}" if self.r.get("version") else "New rule")
        text_set(self.cmd_text, "\n".join(self.r.get("commands", [])))
        self.pass_mode.set(self.r["pass_logic"].get("mode", "ALL"))
        self.na_mode.set(self.r["na_logic"].get("mode", "ALL"))
        self.na_var.set(bool(self.r.get("na_enabled")))
        text_set(self.notes_text, self.r.get("notes", ""))
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

    def show_used_by(self):
        self.used_label.configure(text=assess.used_by_text(self.r))

    def change_used_by(self):
        if self.readonly:
            return
        targets = [t["stig_id"] for t in store.rule_targets(self.r)]
        dlg = UsedByDialog(self, self.app, targets, self.r.get("groups") or [])
        if dlg.result is None:
            return
        self.r["groups"] = dlg.result
        if dlg.result:
            self.r["is_default"] = False  # a version for some groups is never the all-groups default
        else:  # back to all groups: it is the default unless another all-groups version already is
            others = [x for x in assess.rules_for_control(self.app.rules_db, self.stig_id, self.control["vuln_id"])
                      if x.get("id") != self.r.get("id") and not x.get("groups") and x.get("is_default")]
            self.r["is_default"] = not others
        self.show_used_by()

    def ask_about_group_choices(self, rule):
        """A group that picked a version for this check by hand keeps that choice over 'Used by'. Say so, and offer
        to remove the choice so the group uses this version."""
        key = assess.key_of(self.stig_id, self.control["vuln_id"])
        blocked = [g["id"] for g in self.app.groups_db.get("groups", [])
                   if g["id"] in (rule.get("groups") or []) and (g.get("rule_choices") or {}).get(key)
                   and (g.get("rule_choices") or {}).get(key) != rule.get("id")]
        self.clear_choices = set()
        if blocked and messagebox.askyesno(
                "Group has its own choice",
                f"{', '.join(blocked)} already picked a version for this check by hand (Device groups > Rule "
                "versions), and that choice wins over 'Used by'.\n\nRemove that choice, so "
                f"{', '.join(blocked)} use{'s' if len(blocked) == 1 else ''} this version?", parent=self):
            self.clear_choices = set(blocked)

    def toggle_compact(self):
        store.save_my_view({"compact_conditions": self.compact_var.get()})
        self.render_conditions()

    def render_conditions(self):
        for lb, key, mode in ((self.pass_box, "pass_logic", self.pass_mode), (self.na_box, "na_logic", self.na_mode)):
            items = []
            for c in self.r[key]["conditions"]:
                errs = engine.condition_problems(c, self.commands())
                items.append((engine.describe_parts(c), errs[0] if errs else ""))
            lb.set_items(items, "AND" if mode.get() == "ALL" else "OR", compact=self.compact_var.get(),
                         one_command=len(self.commands()) <= 1)

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
                return select_first(self, "a condition (click its card)")
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
        if not sel:
            return select_first(self, "a condition (click its card)")
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
            return messagebox.showinfo("No devices", "Import a SolarWinds output file (Run an assessment) first, "
                                                     "or paste sample output into the box.", parent=self)
        cmds = self.commands()
        have = {d["host"]: sum(1 for c in cmds if c in d["outputs"]) for d in devices}
        not_collected = ("The last SolarWinds import (run {}) has no output for this rule's command(s): {}.\n\n"
                         "A collection script only includes the commands of ACTIVE rules, so a draft's commands "
                         "are usually missing. Use Rules > 'Try drafts on real output...' (it copies a script "
                         "with the drafts' commands), or paste the output into the box by hand.")
        if not any(have.values()):
            return messagebox.showinfo("Not collected yet", not_collected.format(run["id"], ", ".join(cmds)),
                                       parent=self)
        devices = sorted(devices, key=lambda d: -have[d["host"]])  # devices with the output first
        choices = [f"{d['host']}  ({have[d['host']]}/{len(cmds)} commands)" for d in devices]
        pick = ask_choice(self, "Load sample", "Load this rule's command output from which device "
                                               f"(run {run['id']})?", choices)
        if not pick:
            return
        device = devices[choices.index(pick)]
        if not have[device["host"]]:
            return messagebox.showinfo("Not collected yet", not_collected.format(run["id"], ", ".join(cmds)),
                                       parent=self)
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
            state = "No sample yet - paste output below. Until then the command counts as MISSING (Not Reviewed)."
        elif outputs[self.cur_cmd]["status"] == "invalid":
            state = "The device rejected this command (% Invalid ...) - counts as INVALID evidence (Not Reviewed)."
        elif not self.sample[self.cur_cmd].strip():
            state = "Sample is EMPTY output (the command ran and printed nothing)."
        else:
            state = f"Sample: {len(engine.split_lines(self.sample[self.cur_cmd]))} lines. Paste or type to change it."
        self.sample_state.configure(text=state)
        self.run_all_tests(quiet=True)
        return status

    def show_readiness(self):
        """Next to Save: is this rule active, ready to activate, or what is still missing?"""
        rule = self.collect()
        problems = engine.activation_problems(rule)
        ready = not problems and rule.get("state") != "active" and not self.readonly
        if rule.get("state") == "active":
            text, colour = "Active - groups use this rule.", "#1b7a1b"
        elif problems:
            text = "Not ready to activate yet: " + problems[0] + (f" (+{len(problems) - 1} more)"
                                                                   if len(problems) > 1 else "")
            colour = "#666"
        else:
            text, colour = "Ready: all tests pass. Activate it so groups start using it.", "#1b7a1b"
        self.ready_label.configure(text=text, foreground=colour)
        if ready and not self.activate_btn.winfo_manager():
            self.activate_btn.pack(side="left", padx=(0, 6), before=self.ready_label)
        elif not ready and self.activate_btn.winfo_manager():
            self.activate_btn.pack_forget()

    def activate(self):
        self.state_var.set("active")
        self.save()

    def run_all_tests(self, quiet=False):
        self.test_tree.delete(*self.test_tree.get_children())
        for i, (t, actual, ok) in enumerate(engine.run_tests(self.collect())):
            self.test_tree.insert("", "end", iid=str(i), tags=("pass" if ok else "fail",),
                                  values=(t["name"], STATUS_LABELS.get(t["expected"], t["expected"]),
                                          STATUS_LABELS.get(actual, actual), "PASS" if ok else "FAIL"))
        self.show_readiness()

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

    # -- sharing with other controls
    def home(self):
        return self.r["stig_id"], self.r["vuln_id"]

    def show_shared(self):
        here = (self.stig_id, self.control["vuln_id"])
        others = [t for t in store.rule_targets(self.r) if (t["stig_id"], t["vuln_id"]) != here]
        if not others:
            text = ("Used for this check only. If another check tests the same thing, share this rule with it "
                    "instead of writing it again.")
        else:
            names = ", ".join(f"{self.app.short(t['stig_id'])} {t['vuln_id']}" for t in others)
            text = f"SHARED - this rule also answers {len(others)} other check(s): {names}. Changes apply to all."
        unsaved = self.original is not None and (self.r.get("links") or []) != (self.original.get("links") or [])
        self.share_label.configure(text=text + ("   (not saved yet - click Save rule)" if unsaved else ""),
                                   foreground="#a05a00" if others else "#555")

    def share(self):
        dlg = ShareDialog(self)
        if not dlg.result:
            return
        action, picked = dlg.result
        if action == "copy":
            return self._copy_to(picked)
        old = {(t["stig_id"], t["vuln_id"]): t for t in self.r.get("links") or []}
        manual = set(self.app.rules_db.get("manual_controls", []))
        self.r["links"] = [old.get(k) or {"stig_id": k[0], "vuln_id": k[1],
                                          "check_hash": self.app.index[k[0]]["controls"][k[1]]["check_hash"]}
                           for k in picked if k != self.home()]
        self.unmanual = {assess.key_of(*k) for k in picked if k not in old and assess.key_of(*k) in manual}
        self.show_shared()

    def _copy_to(self, picked):
        base = {k: v for k, v in copy.deepcopy(self.collect()).items()
                if k not in ("id", "history", "review_log", "is_default", "_rev", "links", "saved_by", "saved_at",
                             "created_at", "created_by", "imported_at", "fix_review")}
        made = []
        for sid, vid in picked:
            control = self.app.index[sid]["controls"][vid]
            siblings = assess.rules_for_control(store.load_rules(), sid, vid)
            rule = {**copy.deepcopy(base), "id": store.new_rule_id(), "stig_id": sid, "vuln_id": vid, "version": 1,
                    "state": "draft", "check_hash": control["check_hash"], "history": [], "links": [],
                    "name": f"{base.get('name') or 'Default'} (copied from {self.app.short(self.stig_id)} "
                            f"{self.control['vuln_id']})",
                    "is_default": not any(x.get("is_default") for x in siblings),
                    "created_at": store.now(), "created_by": store.current_user()}
            store.save_rule(rule, check=False)
            made.append(f"{self.app.short(sid)} {vid} -> {rule['id']}")
        self.on_saved()
        messagebox.showinfo("Copied", f"Created {len(made)} DRAFT rule(s):\n\n" + "\n".join(made) +
                            "\n\nEach copy is separate from now on. Check it against its own STIG text, then set it "
                            "Active.", parent=self)

    # -- save
    def save(self):
        if self.readonly:
            return messagebox.showinfo("Read-only", "Someone else is editing this rule, so it cannot be saved here.",
                                       parent=self)
        rule = self.collect()
        if not rule["name"]:
            return messagebox.showerror("Name needed", "Give this rule a name (e.g. 'Default', or 'Core switches').",
                                        parent=self)
        if rule["state"] == "active":
            problems = engine.activation_problems(rule)
            if problems:
                if not messagebox.askyesno("Cannot activate yet",
                                           "This rule cannot be Active yet:\n\n- " + "\n- ".join(problems) +
                                           "\n\nSave it as a Draft instead?", parent=self):
                    return
                rule["state"] = "draft"
        self.ask_about_group_choices(rule)
        content_keys = ("name", "state", "commands", "pass_logic", "na_enabled", "na_logic", "notes",
                        "outcome_text", "expected_open", "groups",
                        "tests", "links")
        if self.original is not None:
            before = {k: self.original.get(k) for k in content_keys}
            after = {k: rule.get(k) for k in content_keys}
            if json.dumps(before, sort_keys=True) != json.dumps(after, sort_keys=True):
                snapshot = {k: v for k, v in self.original.items() if k not in ("history", "review_log")}
                rule.setdefault("history", []).append(snapshot)
                rule["version"] = self.original.get("version", 1) + 1
            store.set_rule_check_hash(rule, self.stig_id, self.control["vuln_id"], self.control["check_hash"])
            self._take_fix_from_disk(rule)
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
        for key in self.unmanual:
            store.set_manual(key, False)
        check_key = assess.key_of(self.stig_id, self.control["vuln_id"])
        for gid in self.clear_choices:
            store.modify_group(gid, lambda g: (g.get("rule_choices") or {}).pop(check_key, None))
        self.on_saved()
        self.close()

    def _take_fix_from_disk(self, rule):
        """Fix commands are edited on the Fix commands tab. Keep what is saved there; if that is all that changed
        on disk since this editor opened, it is not a conflict."""
        disk = store.load_json(store.rule_path(rule["id"]), None)
        if not disk:
            return
        for k in ("fix", "fix_review"):
            if k in disk:
                rule[k] = disk[k]
            else:
                rule.pop(k, None)
        ignore = ("fix", "fix_review", "history", "_rev", "saved_by", "saved_at")
        if {k: v for k, v in disk.items() if k not in ignore} ==                 {k: v for k, v in self.original.items() if k not in ignore}:
            rule["_rev"] = disk.get("_rev", 0)

    def _save_new(self, rule):
        rule = {k: v for k, v in rule.items() if k not in ("_rev", "review_log")}
        siblings = assess.rules_for_control(store.load_rules(), self.stig_id, self.control["vuln_id"])
        rule.update(id=store.new_rule_id(), stig_id=self.stig_id, vuln_id=self.control["vuln_id"], version=1,
                    check_hash=self.control["check_hash"], created_at=store.now(), created_by=store.current_user())
        rule["links"] = [t for t in rule.get("links") or []
                         if (t["stig_id"], t["vuln_id"]) != (self.stig_id, self.control["vuln_id"])]
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

    def fingerprint(self):
        """Everything the editor would save, to tell whether anything changed since it opened."""
        return json.dumps(self.collect(), sort_keys=True, default=str)

    def cancel(self):
        unchanged = getattr(self, "_baseline", None) == self.fingerprint() and not self.unmanual
        if self.readonly or unchanged or messagebox.askyesno("Close", "Close without saving your changes?",
                                                             parent=self):
            self.close()


# ---------------------------------------------------------------- share a rule with other controls

SIMILAR_CHECK = 80  # % of check-text words in common that makes a control a likely match


class AiHandoffDialog(tk.Toplevel):
    """Rule editor: copy a prompt for another AI to write the conditions, then read its answer back in.

    Nothing is sent from the tool. The person pastes the prompt into whichever AI their organisation allows,
    and the answer is checked (every condition must be one the engine can run) before it touches the rule."""

    def __init__(self, editor):
        super().__init__(editor)
        self.editor, self.answer = editor, None
        self.title(f"Ask an AI - {editor.control['vuln_id']} {editor.control['rule_ver']}")
        self.transient(editor)
        maximize(self, "1100x860")
        tk.Label(self, bg="#fff4ce", fg="#5c4300", anchor="w", justify="left", padx=8, pady=4, wraplength=1050,
                 text="Nothing is sent from this tool: it copies a prompt, you paste it into an AI your "
                      "organisation approves. Passwords, keys and SNMP communities are masked, but hostnames, "
                      "IP addresses and descriptions are not - check the prompt (Preview) before sending it, and "
                      "use made-up examples if the output is sensitive.").pack(fill="x", padx=8, pady=(8, 0))

        one = ttk.LabelFrame(self, text=" 1. Describe what you want and copy the prompt ", padding=6)
        one.pack(fill="both", expand=True, padx=8, pady=6)
        ttk.Label(one, text="What should the rule check? Plain words, e.g. 'every port that is not an uplink, "
                            "downlink or trusted port must have dot1x, or be shut down in vlan 2':").pack(anchor="w")
        self.goal = tk.Text(one, height=3, wrap="word", font=("Segoe UI", 10))
        self.goal.pack(fill="x", pady=(2, 6))
        ex = ttk.Frame(one)
        ex.pack(fill="both", expand=True)
        ex.columnconfigure(0, weight=1)
        ex.columnconfigure(1, weight=1)
        ex.rowconfigure(1, weight=1)
        ttk.Label(ex, text="Example that should PASS (e.g. a good interface):").grid(row=0, column=0, sticky="w")
        ttk.Label(ex, text="Example that should FAIL (e.g. a bad interface):").grid(row=0, column=1, sticky="w",
                                                                                    padx=(8, 0))
        self.good = tk.Text(ex, height=7, wrap="none", font=MONO)
        self.good.grid(row=1, column=0, sticky="nsew")
        self.bad = tk.Text(ex, height=7, wrap="none", font=MONO)
        self.bad.grid(row=1, column=1, sticky="nsew", padx=(8, 0))
        opts = ttk.Frame(one)
        opts.pack(fill="x", pady=(6, 0))
        editor.store_sample()
        self.samples = {c: t for c, t in editor.sample.items() if c in editor.commands() and t.strip()}
        lines = sum(len(engine.split_lines(t)) for t in self.samples.values())
        self.with_sample = tk.BooleanVar(value=bool(self.samples))
        cb = ttk.Checkbutton(opts, variable=self.with_sample,
                             text=f"Include the sample output from the test box ({lines} lines)" if self.samples
                             else "Include sample output (none in the test box yet)")
        cb.pack(side="left")
        if not self.samples:
            cb.state(["disabled"])
        self.mask = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Mask passwords / keys / communities", variable=self.mask).pack(side="left",
                                                                                                padx=12)
        ttk.Button(opts, text="Preview prompt...", command=self.preview).pack(side="right")
        ttk.Button(opts, text="Copy prompt", style="Accent.TButton", command=self.copy).pack(side="right", padx=6)

        two = ttk.LabelFrame(self, text=" 2. Paste the AI's answer and check it ", padding=6)
        two.pack(fill="both", expand=True, padx=8, pady=(0, 6))
        self.reply = tk.Text(two, height=7, wrap="none", font=MONO)
        self.reply.pack(fill="both", expand=True)
        row = ttk.Frame(two)
        row.pack(fill="x", pady=4)
        ttk.Button(row, text="Check answer", command=self.check).pack(side="left")
        self.add_mine = tk.BooleanVar(value=True)
        self.add_ai_tests = tk.BooleanVar(value=True)
        self.w_mine = ttk.Checkbutton(row, text="Save my pass / fail examples as tests", variable=self.add_mine)
        self.w_mine.pack(side="left", padx=(12, 0))
        ttk.Checkbutton(row, text="Add the AI's test samples (named 'AI: ...')",
                        variable=self.add_ai_tests).pack(side="left", padx=(12, 0))
        self.result = ScrolledText(two, height=9, wrap="word", font=("Segoe UI", 10))
        self.result.pack(fill="both", expand=True)
        self.result.tag_configure("bad", foreground="#b00020")
        self.result.tag_configure("head", font=("Segoe UI", 10, "bold"))
        text_set(self.result, "The checked answer appears here: each condition in plain words, and anything "
                              "that is wrong with it.", readonly=True)

        b = ttk.Frame(self)
        b.pack(fill="x", padx=8, pady=(0, 8))
        self.replace_btn = ttk.Button(b, text="Replace the rule's conditions", style="Accent.TButton",
                                      command=lambda: self.apply(replace=True))
        self.add_btn = ttk.Button(b, text="Add to the rule's conditions", command=lambda: self.apply(replace=False))
        for w in (self.replace_btn, self.add_btn):
            w.pack(side="left", padx=(0, 6))
            w.state(["disabled"])
        ttk.Button(b, text="Close", command=self.destroy).pack(side="right")
        self.bind("<Escape>", lambda e: self.destroy())

    def prompt(self):
        ed = self.editor
        platform = drafts.PLATFORM_LABEL.get(drafts.platform_of(ed.stig_id) or "", "")
        return llm_handoff.build_prompt(ed.control, ed.collect(), platform, text_get(self.goal),
                                        text_get(self.good), text_get(self.bad),
                                        self.samples if self.with_sample.get() else None, mask=self.mask.get())

    def copy(self):
        text = self.prompt()
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Prompt copied", f"Copied {len(text):,} characters. Paste it into the AI, then paste "
                                             "its whole answer into box 2 and click 'Check answer'.", parent=self)

    def preview(self):
        win = tk.Toplevel(self)
        win.title("Prompt preview")
        win.geometry("1000x760")
        t = ScrolledText(win, wrap="word", font=MONO)
        t.pack(fill="both", expand=True)
        text_set(t, self.prompt(), readonly=True)

    def examples_as_tests(self, commands):
        """My pass / fail examples, as tests of the rule's only command (several commands: cannot tell which)."""
        if len(commands) != 1:
            return []
        return [{"name": name, "expected": expected, "outputs": {commands[0]: text}}
                for name, expected, text in (("My example (should pass)", "not_a_finding", text_get(self.good)),
                                             ("My example (should fail)", "open", text_get(self.bad)))
                if text.strip()]

    def check(self):
        self.answer = None
        for w in (self.replace_btn, self.add_btn):
            w.state(["disabled"])
        t = self.result
        t.configure(state="normal")
        t.delete("1.0", "end")
        try:
            answer, problems = llm_handoff.parse_answer(text_get(self.reply))
        except ValueError as e:
            t.insert("end", f"Cannot use this answer: {e}\n", "bad")
            t.configure(state="disabled")
            return
        t.insert("end", "Commands: " + ", ".join(answer["commands"]) + "\n", "head")
        for key, mode, label in (("pass_conditions", "pass_mode", "NOT A FINDING when"),
                                 ("na_conditions", "na_mode", "NOT APPLICABLE when")):
            if answer[key]:
                t.insert("end", f"\n{label} {answer[mode]} of:\n", "head")
                for n, c in enumerate(answer[key], 1):
                    t.insert("end", f"  {n}. {engine.describe(c)}\n")
        if answer["explanation"]:
            t.insert("end", "\nThe AI says: ", "head")
            t.insert("end", answer["explanation"] + "\n")
        trial = {"commands": answer["commands"], "pass_logic": {"mode": answer["pass_mode"],
                                                                "conditions": answer["pass_conditions"]},
                 "na_enabled": bool(answer["na_conditions"]),
                 "na_logic": {"mode": answer["na_mode"], "conditions": answer["na_conditions"]},
                 "tests": self.examples_as_tests(answer["commands"]) + answer["tests"]}
        if trial["tests"]:
            t.insert("end", "\nTried against the examples and the AI's samples:\n", "head")
            for test, actual, ok in engine.run_tests(trial):
                t.insert("end", f"  {'PASS' if ok else 'FAIL'}  {test['name']}: expected "
                                f"{STATUS_LABELS[test['expected']]}, the rule gives {STATUS_LABELS[actual]}\n",
                         () if ok else ("bad",))
        if problems:
            t.insert("end", "\nProblems (fix them in the AI or in the editor after using it):\n", "head")
            for p in problems:
                t.insert("end", f"  - {p}\n", "bad")
        t.configure(state="disabled")
        self.answer = answer
        self.w_mine.state(["!disabled"] if len(answer["commands"]) == 1 else ["disabled"])
        if not self.editor.readonly:
            for w in (self.replace_btn, self.add_btn):
                w.state(["!disabled"])

    def apply(self, replace):
        ed, a = self.editor, self.answer
        if not a:
            return
        r = ed.r
        commands = ed.commands() + [c for c in a["commands"] if c not in ed.commands()]
        if replace:
            r["pass_logic"] = {"mode": a["pass_mode"], "conditions": a["pass_conditions"]}
            r["na_logic"] = {"mode": a["na_mode"], "conditions": a["na_conditions"]}
            ed.pass_mode.set(a["pass_mode"])
            ed.na_mode.set(a["na_mode"])
            ed.na_var.set(bool(a["na_conditions"]))
        else:
            r["pass_logic"]["conditions"] += a["pass_conditions"]
            r["na_logic"]["conditions"] += a["na_conditions"]
            if a["na_conditions"]:
                ed.na_var.set(True)
        tests = self.examples_as_tests(a["commands"]) if self.add_mine.get() else []
        tests += [{**t, "name": f"AI: {t['name']}"} for t in a["tests"]] if self.add_ai_tests.get() else []
        for t in tests:
            r["tests"].append({**t, "saved_at": store.now(), "saved_by": store.current_user()})
        if a["explanation"]:
            notes = text_get(ed.notes_text).strip()
            text_set(ed.notes_text, (notes + "\n\n" if notes else "") + "AI notes: " + a["explanation"])
        text_set(ed.cmd_text, "\n".join(commands))
        ed.commands_changed()
        ed.run_all_tests()
        self.destroy()
        messagebox.showinfo("Conditions added", "The AI's conditions are in the editor (not saved yet). Check "
                                                "each one against the STIG text and the tests, then Save.",
                            parent=ed)


class ShareDialog(tk.Toplevel):
    """Pick the other checks a rule should answer. result = ("share" | "copy", [(stig_id, vuln_id)]) or None."""

    def __init__(self, editor):
        super().__init__(editor)
        self.editor, self.app, self.result = editor, editor.app, None
        self.title("Use this rule for other checks")
        self.transient(editor)
        maximize(self, "1300x900")
        home = editor.home()
        self.mine = editor.control  # the check this rule is being looked at from
        refs = [editor.control, self.app.index.get(home[0], {}).get("controls", {}).get(home[1], editor.control)]
        self.ticked = {(t["stig_id"], t["vuln_id"]) for t in store.rule_targets(editor.r)} - {home}
        self.os = assess.platform(self.app.short(home[0]))
        self.rows = []
        for sid, stig in self.app.index.items():
            for vid in stig["order"]:
                if (sid, vid) == home:
                    continue
                c = stig["controls"][vid]
                same = assess.text_similarity(self.mine["check"], c["check"])
                why = assess.match_reason(c, refs) or ("similar check text" if same >= SIMILAR_CHECK else "")
                if why and assess.platform(stig["short"]) != self.os:
                    why += f", other OS ({assess.platform(stig['short'])})"
                self.rows.append(((sid, vid), why, stig["short"], c,
                                  assess.control_state(self.app.rules_db, sid, c), same))
        self.rows.sort(key=lambda r: (not r[1], "other OS" in r[1], -r[5], r[2], r[0][1]))

        fit_text(ttk.Label(self,
                  text="Several STIGs check the same thing (for example the same requirement in the Switch and the "
                       "Router STIG). Share this ONE rule with those checks: write it once, test it once, fix it "
                       "once. Likely matches are listed first. Click a row to compare its check text with this one "
                       "below, then click 'Share with ...' (or the row's Shared box). Ctrl-click / Shift-click to "
                       "pick several rows at once."
                  )).pack(fill="x", padx=10, pady=(10, 4))
        filt = ttk.Frame(self)
        filt.pack(fill="x", padx=10)
        ttk.Label(filt, text="Search:").pack(side="left")
        self.search = tk.StringVar()
        ttk.Entry(filt, textvariable=self.search, width=30).pack(side="left", padx=4)
        self.only = tk.BooleanVar(value=any(r[1] for r in self.rows))
        ttk.Checkbutton(filt, text="Likely matches only", variable=self.only).pack(side="left", padx=10)
        self.count = ttk.Label(filt, text="")
        self.count.pack(side="left", padx=10)
        for var in (self.search, self.only):
            var.trace_add("write", lambda *a: self.refresh())

        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True, padx=10, pady=6)
        PaneKeeper(paned, [0.42])
        frame, self.tree = make_tree(paned, [("tick", "Shared", 60), ("same", "Check text same", 105),
                                             ("why", "Why suggested", 150), ("stig", "STIG", 180),
                                             ("vuln", "Vuln ID", 80), ("ver", "STIG ID", 120),
                                             ("state", "State now", 140), ("title", "Title", 450)], height=10,
                                     selectmode="extended")
        paned.add(frame, weight=1)
        color_tags(self.tree, {"on": "#d9f7d6"})
        self.tree.bind("<ButtonRelease-1>", self.click)
        self.tree.bind("<Double-1>", lambda e: self.toggle(self.tree.identify_row(e.y)))
        self.tree.bind("<space>", lambda e: self.tick_selected())
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.compare())

        box = ttk.Frame(paned)
        paned.add(box, weight=2)
        bar = ttk.Frame(box)
        bar.pack(fill="x")
        self.what = tk.StringVar(value="check")
        for value, text in (("check", "Check text"), ("fix", "Fix text")):
            ttk.Radiobutton(bar, text=text, value=value, variable=self.what, command=self.compare).pack(side="left")
        self.loose = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Ignore case, punctuation and switch / router wording", variable=self.loose,
                        command=self.compare).pack(side="left", padx=12)
        self.tick_btn = ttk.Button(bar, text="Share with...", command=self.tick_selected)
        self.tick_btn.pack(side="left", padx=6)
        self.compare_head = fit_text(ttk.Label(box, text="", font=("Segoe UI", 10, "bold")))
        self.compare_head.pack(fill="x", pady=(4, 2))
        self.diff = diff_text_widget(box, height=14)
        self.diff.pack(fill="both", expand=True)

        btns = ttk.Frame(self)
        btns.pack(side="bottom", fill="x", padx=10, pady=(0, 10), before=paned)
        share = ttk.Button(btns, text="Save: share with the checks marked Yes", command=self.share, style="Accent.TButton")
        share.pack(side="left")
        copy_btn = ttk.Button(btns, text="Make separate copies instead...", command=self.copy)
        copy_btn.pack(side="left", padx=6)
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="left")
        fit_text(ttk.Label(btns, foreground="#555",
                           text="Copies are independent drafts. Use them only when a check needs different logic; "
                                "copies have to be fixed one by one.")).pack(side="left", fill="x", expand=True,
                                                                             padx=12)
        if editor.readonly:
            share.state(["disabled"])
            copy_btn.state(["disabled"])
        self.refresh()
        first = self.tree.get_children()
        if first:
            self.tree.selection_set(first[0])
            self.tree.focus(first[0])
        else:
            self.compare()
        self.grab_set()
        editor.wait_window(self)

    def refresh(self):
        needle = self.search.get().lower().strip()
        self.tree.delete(*self.tree.get_children())
        for key, why, short, c, state, same in self.rows:
            on = key in self.ticked
            if not on and self.only.get() and not why:
                continue
            if not on and needle and needle not in f"{short} {c['vuln_id']} {c['rule_ver']} {c['title']}".lower():
                continue
            self.tree.insert("", "end", iid=assess.key_of(*key), tags=("on",) if on else (),
                             values=("Yes" if on else "", f"{same}%", why, short, c["vuln_id"], c["rule_ver"],
                                     state, c["title"]))
        self.count.configure(text=f"Shared with {len(self.ticked)} other check(s)")

    def click(self, event):
        if self.tree.identify_column(event.x) == "#1":  # the Shared box
            self.toggle(self.tree.identify_row(event.y))

    def toggle(self, iid):
        if not iid or not self.tree.exists(iid):
            return
        key = tuple(iid.split("|", 1))
        self.ticked ^= {key}
        on = key in self.ticked
        self.tree.item(iid, tags=("on",) if on else ())
        self.tree.set(iid, "tick", "Yes" if on else "")
        self.count.configure(text=f"Shared with {len(self.ticked)} other check(s)")
        self.compare()

    def tick_selected(self):
        """Tick every highlighted row; if they are all ticked already, untick them."""
        sel = [i for i in self.tree.selection() if self.tree.exists(i)]
        keys = [tuple(i.split("|", 1)) for i in sel]
        on = not all(k in self.ticked for k in keys)
        for iid, key in zip(sel, keys):
            if on:
                self.ticked.add(key)
            else:
                self.ticked.discard(key)
            self.tree.item(iid, tags=("on",) if on else ())
            self.tree.set(iid, "tick", "Yes" if on else "")
        self.count.configure(text=f"Shared with {len(self.ticked)} other check(s)")
        self.compare()
        return "break"

    def compare(self):
        """Word diff of this rule's check (or fix) text against the highlighted control's."""
        sel = self.tree.selection()
        shown = self.tree.focus() if self.tree.focus() in sel else (sel[-1] if sel else None)
        row = next((r for r in self.rows if shown and assess.key_of(*r[0]) == shown), None)
        self.diff.configure(state="normal")
        self.diff.delete("1.0", "end")
        if not row:
            self.compare_head.configure(text="Click a row above to compare it with this rule's check.")
            self.tick_btn.state(["disabled"])
            self.diff.configure(state="disabled")
            return
        key, _why, short, c, _state, _same = row
        field = self.what.get()
        mine_name = f"{self.app.short(self.editor.stig_id)} {self.mine['vuln_id']}"
        other_name = f"{short} {c['vuln_id']}"
        same = assess.text_similarity(self.mine[field], c[field])
        self.tick_btn.state(["!disabled"])
        keys = [tuple(i.split("|", 1)) for i in sel]
        verb = "Stop sharing with" if all(k in self.ticked for k in keys) else "Share with"
        self.tick_btn.configure(text=f"{verb} {c['vuln_id']}" if len(sel) == 1 else
                                f"{verb} the {len(sel)} highlighted checks")
        self.compare_head.configure(
            text=(f"{len(sel)} highlighted - comparing the one you clicked last. " if len(sel) > 1 else "")
                 + f"{field.capitalize()} text: {mine_name} (this rule)  vs  {other_name}  -  {same}% the same.   "
                 f"Red struck-out = only in {mine_name}.  Green = only in {other_name}.")
        parts = assess.text_diff(self.mine[field], c[field], loose=self.loose.get())
        if all(kind == "same" for kind, _ in parts):
            self.diff.insert("end", "No differences" + (" (ignoring case, punctuation and switch / router wording)"
                                                        if self.loose.get() else "") + ".\n\n", "head")
        for kind, text in parts:
            self.diff.insert("end", text, {"mine": "del", "other": "ins"}.get(kind, ()))
        self.diff.configure(state="disabled")

    def share(self):
        picked = sorted(self.ticked)
        already = {(t["stig_id"], t["vuln_id"]) for t in store.rule_targets(self.editor.r)}
        notes = []
        for key, _why, short, c, state, _same in self.rows:
            if key not in self.ticked or key in already:
                continue
            if assess.platform(short) != self.os:
                notes.append(f"{short} {c['vuln_id']} is {assess.platform(short)}, not {self.os}: the same show "
                             "commands may not work there. Check its tests pass, or make a copy instead.")
            if state == "Manual only":
                notes.append(f"{short} {c['vuln_id']} stops being Manual only.")
            elif state == "Draft":
                notes.append(f"{short} {c['vuln_id']} has a draft rule of its own. Delete that draft if this "
                             "rule replaces it.")
            elif state != "Needs rule":
                notes.append(f"{short} {c['vuln_id']} already has its own active rule and keeps using it. Retire "
                             "that rule if this one should replace it.")
        msg = (f"This rule will answer {len(picked)} other check(s) besides its own."
               if picked else "This rule will no longer be shared.")
        if notes:
            msg += "\n\n" + "\n".join(notes)
        if messagebox.askokcancel("Share rule", msg + "\n\nClick Save rule in the editor to keep the change.",
                                  parent=self):
            self.result = ("share", picked)
            self.destroy()

    def copy(self):
        here = (self.editor.stig_id, self.editor.control["vuln_id"])
        picked = [k for k in sorted(self.ticked) if k != here]
        if not picked:
            return messagebox.showinfo("Copy", "Pick the checks to copy this rule to first (Share with...).",
                                       parent=self)
        if messagebox.askokcancel("Make copies", f"Create {len(picked)} separate DRAFT rule(s) from what is in the "
                                                 "editor now? They will not follow later changes to this rule.",
                                  parent=self):
            self.result = ("copy", picked)
            self.destroy()


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
SCOPE_HELP = ("A section is a line plus the indented lines under it, e.g. 'interface GigabitEthernet1/0/1' and "
              "its settings. Port roles come from the interface description (Team settings > Port roles); a port "
              "with no role label is not in any role, so 'every port EXCEPT uplink, trusted' still checks "
              "unlabelled ports. The 'also' boxes take one filter per line, matched at the START of a line (so "
              "'shutdown' is not 'no shutdown'); start a line with re: for a regex.")
PORT_MODES = {"all": "Any port (no role filter)", "only": "Only ports with these roles:",
              "except": "Every port EXCEPT these roles:"}
SECTION_PRESETS = [
    ("Every interface", "interface", "starts with"),
    ("Front-panel switch ports, IOS-XE (no Vlan / Loopback / Port-channel / AppGig)",
     r"^interface (?!AppGig)\S*(Ethernet|GigE)\d", "regex"),
    ("Ethernet ports, NX-OS", r"^interface Ethernet\d", "regex"),
    ("vty lines", "line vty", "starts with"),
    ("Console line", "line con", "starts with"),
]


# Worked examples for the condition dialog: (menu text, condition fields)
CONDITION_EXAMPLES = [
    ("A line must be there - e.g. 'service password-encryption'",
     {"scope": "all", "check": "has", "how": "starts with", "text": "service password-encryption"}),
    ("A line must NOT be there - e.g. 'ip http server'",
     {"scope": "all", "check": "lacks", "how": "whole line", "text": "ip http server"}),
    ("Every 'line vty' section must have a setting - e.g. 'transport input ssh'",
     {"scope": "every", "section": "line vty", "section_how": "starts with", "if_none": "fail", "check": "has",
      "how": "contains", "text": "transport input ssh"}),
    ("Every access port must have a setting (port role, shut ports skipped) - e.g. BPDU Guard",
     {"scope": "every", "section": "interface", "section_how": "starts with", "only": "role:access",
      "exclude": "shutdown", "if_none": "pass", "check": "has", "how": "starts with",
      "text": "spanning-tree bpduguard enable"}),
    ("Every live port that is not an uplink / downlink / trusted must have 802.1x",
     {"scope": "every", "section": "interface", "section_how": "starts with", "only": "",
      "exclude": "role:uplink, downlink, trusted\n"
                 "re:^\\s*(shutdown|switchport mode trunk|no switchport|channel-group)\\b",
      "if_none": "pass", "check": "has", "how": "whole line", "text": "dot1x pae authenticator"}),
    ("Shut ports without 802.1x must be parked in a VLAN - e.g. vlan 2",
     {"scope": "every", "section": "interface", "section_how": "starts with", "only": "shutdown",
      "exclude": "role:uplink, downlink, trusted\ndot1x pae authenticator\n"
                 "re:^\\s*(switchport mode trunk|no switchport|channel-group)\\b",
      "if_none": "pass", "check": "has", "how": "whole line", "text": "switchport access vlan 2"}),
    ("No port (except trusted ones) may have open authentication",
     {"scope": "every", "section": "interface", "section_how": "starts with", "exclude": "role:trusted",
      "if_none": "pass", "check": "lacks", "how": "regex",
      "text": "^\\s*(authentication open|(authentication|access-session) port-control force-authorized)\\b"}),
    ("A number must be at most / at least N - e.g. vty exec-timeout at most 10",
     {"scope": "every", "section": "line vty", "section_how": "starts with", "if_none": "fail", "check": "number",
      "how": "starts with", "text": "exec-timeout", "op": "<=", "value": "10"}),
    ("At least N matching lines - e.g. 2 'ntp server' lines",
     {"scope": "all", "check": "count", "how": "starts with", "text": "ntp server", "op": ">=", "value": "2"}),
]


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
                  ("command", "section", "section_how", "text", "how", "op", "value")}
        self.scope_labels = {v: k for k, v in engine.SCOPES.items()}
        self.check_labels = {v: k for k, v in engine.CHECKS.items()}
        self.v["scope"] = tk.StringVar(value=engine.SCOPES[c["scope"]])
        self.v["check"] = tk.StringVar(value=engine.CHECKS[c["check"]])
        self.v["if_none"] = tk.StringVar(value="counts as FAIL" if c["if_none"] == "fail" else "counts as PASS")
        self.ignore = tk.BooleanVar(value=bool(c["ignore_case"]))

        f = ttk.Frame(self, padding=12)
        f.pack(fill="both")
        r = 0
        top = ttk.Frame(f)
        top.grid(row=r, column=0, columnspan=4, sticky="we", pady=(0, 8))
        more_button(top, [(text, lambda ex=ex: self.use_example(ex)) for text, ex in CONDITION_EXAMPLES],
                    "Start from an example").pack(side="left")
        ttk.Label(top, text="  fills in the form; then change the text to what your check needs.",
                  foreground="#5f6368").pack(side="left")
        r += 1

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
        self.w_section = ttk.Entry(sec, textvariable=self.v["section"], width=36)
        self.w_section.pack(side="left", fill="x", expand=True, padx=4)
        self.w_section_pick = more_button(sec, [(label, lambda s=s, h=h: (self.v["section"].set(s),
                                                                          self.v["section_how"].set(h)))
                                                for label, s, h in SECTION_PRESETS], "Pick")
        self.w_section_pick.pack(side="left")
        row("   ...section first line:", sec)

        # Port roles and shut ports as plain choices; they are stored as role: / shutdown filter lines
        split = engine.split_port_filters(c.get("only"), c["exclude"])
        self.port_mode = tk.StringVar(value=PORT_MODES[split["mode"]])
        self.role_vars = {name: tk.BooleanVar(value=name in split["roles"]) for name in engine.PORT_ROLES}
        for name in split["roles"]:  # a role the rule uses that is no longer a team role: keep it visible
            self.role_vars.setdefault(name, tk.BooleanVar(value=True))
        self.skip_shut = tk.BooleanVar(value=split["skip_shut"])
        ports = ttk.Frame(f)
        self.w_port_mode = ttk.Combobox(ports, textvariable=self.port_mode, values=list(PORT_MODES.values()),
                                        state="readonly", width=30)
        self.w_port_mode.pack(side="left")
        self.w_roles = []
        for name, var in self.role_vars.items():
            cb = ttk.Checkbutton(ports, text=name, variable=var)
            cb.pack(side="left", padx=(6, 0))
            self.w_roles.append(cb)
        row("   ...which ports (by role):", ports)
        self.w_skip_shut = row("", ttk.Checkbutton(f, text="Skip shut-down ports / sections ('shutdown', not "
                                                           "'no shutdown')", variable=self.skip_shut))
        # Anything else: one filter per line
        self.w_only = row("   ...also only sections with a line starting:", self.filter_box(f, split["only"]))
        self.w_exclude = row("   ...also skip sections with a line starting:", self.filter_box(f, split["exclude"]))
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
        ttk.Entry(txt, textvariable=self.v["text"], width=46).pack(side="left", fill="x", expand=True, padx=4)
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
        ttk.Label(f, text="Reads as:", font=("Segoe UI", 10, "bold")).grid(row=r, column=0, sticky="nw")
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

        for var in list(self.v.values()) + [self.ignore, self.port_mode, self.skip_shut] + list(self.role_vars.values()):
            var.trace_add("write", lambda *a: self.update_view())
        self.commands = commands
        self.update_view()
        self.bind("<Escape>", lambda e: self.destroy())
        self.grab_set()
        parent.wait_window(self)

    def filter_box(self, parent, value):
        box = tk.Text(parent, height=2, width=60, wrap="none", font=("Segoe UI", 10), undo=True)
        box.insert("1.0", value or "")
        box.bind("<KeyRelease>", lambda e: self.update_view(), add="+")
        box.bind("<<Paste>>", lambda e: self.after_idle(self.update_view), add="+")
        return box

    def use_example(self, example):
        c = {**engine.NEW_CONDITION, "command": self.v["command"].get(), **example}
        split = engine.split_port_filters(c["only"], c["exclude"])
        for box, k in ((self.w_only, "only"), (self.w_exclude, "exclude")):
            text_set(box, split[k])
        self.port_mode.set(PORT_MODES[split["mode"]])
        for name, var in self.role_vars.items():
            var.set(name in split["roles"])
        self.skip_shut.set(split["skip_shut"])
        for k in ("section", "section_how", "text", "how", "op", "value"):
            self.v[k].set(str(c[k]))
        self.v["scope"].set(engine.SCOPES[c["scope"]])
        self.v["check"].set(engine.CHECKS[c["check"]])
        self.v["if_none"].set("counts as FAIL" if c["if_none"] == "fail" else "counts as PASS")
        self.ignore.set(bool(c["ignore_case"]))
        self.update_view()

    def port_choice(self):
        mode = next(k for k, v in PORT_MODES.items() if v == self.port_mode.get())
        return mode, [name for name, var in self.role_vars.items() if var.get()]

    def current(self):
        mode, roles = self.port_choice()
        only, exclude = engine.join_port_filters(mode, roles, self.skip_shut.get(), text_get(self.w_only),
                                                 text_get(self.w_exclude))
        return {
            "command": self.v["command"].get(), "scope": self.scope_labels[self.v["scope"].get()],
            "section": self.v["section"].get(), "section_how": self.v["section_how"].get(),
            "only": only, "exclude": exclude,
            "if_none": "fail" if "FAIL" in self.v["if_none"].get() else "pass",
            "check": self.check_labels[self.v["check"].get()], "text": self.v["text"].get(),
            "how": self.v["how"].get(), "ignore_case": self.ignore.get(),
            "op": self.v["op"].get(), "value": self.v["value"].get().strip(),
        }

    def problems(self, c):
        errs = engine.condition_problems(c, self.commands)
        mode, roles = self.port_choice()
        if c["scope"] != "all" and mode != "all" and not roles:
            errs.append("tick at least one port role (or choose 'Any port')")
        return errs

    def update_view(self):
        c = self.current()
        sectioned = c["scope"] != "all"
        self.w_section.configure(state="normal" if sectioned else "disabled")
        for w in (self.w_only, self.w_exclude):
            w.configure(state="normal" if sectioned else "disabled", background="white" if sectioned else "#f0f0f0")
        for w in (self.w_section_how, self.w_if_none, self.w_port_mode):
            w.configure(state="readonly" if sectioned else "disabled")
        mode, _ = self.port_choice()
        for w in self.w_roles:
            w.configure(state="normal" if sectioned and mode != "all" else "disabled")
        for w in (self.w_skip_shut, self.w_section_pick):
            w.configure(state="normal" if sectioned else "disabled")
        numeric = c["check"] in ("number", "count")
        self.w_op.configure(state="readonly" if numeric else "disabled")
        self.w_value.configure(state="normal" if numeric else "disabled")
        self.w_how.configure(state="disabled" if c["check"] in ("pattern", "no_pattern") else "readonly")
        self.help.configure(text=CHECK_HELP[c["check"]])
        self.preview.configure(text=engine.describe(c))
        self.errors.configure(text="\n".join(f"- {e}" for e in self.problems(c)))

    def ok(self):
        c = self.current()
        errs = self.problems(c)
        if errs:
            return messagebox.showerror("Fix the condition", "\n".join(errs), parent=self)
        self.result = c
        self.destroy()


# ---------------------------------------------------------------- 3. groups

class GroupsTab(ttk.Frame):
    def __init__(self, nb, app):
        super().__init__(nb)
        self.app = app
        help_label(self, "A device group is a set of devices configured alike, e.g. CAMPUS-ACCESS (NDM + RTR + L2S) "
                         "or CAMPUS-HANGOFF (NDM + L2S). Click 'New group' and answer the questions: name, which "
                         "STIGs apply, which devices belong. Devices are matched by hostname pattern; anything the "
                         "pattern gets wrong can be moved by hand in the device list below.")
        b = ttk.Frame(self)
        b.pack(fill="x", padx=6)
        ttk.Button(b, text="New group...", command=self.new_group, style="Accent.TButton").pack(side="left", padx=(0, 6))
        ttk.Button(b, text="Edit group...", command=self.edit_group).pack(side="left", padx=(0, 6))
        group_more = [("Copy group...", self.copy_group),
                      ("Rule versions (when a check has more than one)...", self.choose_rules), None,
                      ("Delete group", self.delete_group)]
        more_button(b, group_more, "More...").pack(side="left")
        gf, self.tree = make_tree(self, [("id", "Group", 170), ("desc", "Description", 250),
                                         ("stigs", "STIG checklists", 420), ("patterns", "Hostname patterns", 160),
                                         ("devices", "Devices", 65), ("auto", "Checks automated", 140)], height=8)
        gf.pack(fill="both", expand=True, padx=6, pady=6)
        self.tree.bind("<Double-1>", lambda e: self.edit_group())
        self.tree.tag_configure("warn", background="#fff0c2")
        right_click_menu(self.tree, [("Edit group...", self.edit_group), None] + group_more)

        ttk.Label(self, text="Devices (from SolarWinds imports, or added by hand)",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=6)
        db = ttk.Frame(self)
        db.pack(fill="x", padx=6, pady=2)
        ttk.Button(db, text="Move to group...", command=self.set_override).pack(side="left", padx=(0, 6))
        dev_more = [("Undo move (use the hostname pattern again)", self.clear_override),
                    ("Add devices the tool has not seen yet...", self.add_device), None,
                    ("Forget device", self.forget_device)]
        more_button(db, dev_more, "More...").pack(side="left")
        ttk.Label(db, text="Find:").pack(side="left", padx=(16, 2))
        self.dev_search = tk.StringVar()
        ttk.Entry(db, textvariable=self.dev_search, width=24).pack(side="left")
        self.dev_search.trace_add("write", lambda *a: self.refresh_devices())
        ttk.Button(db, text="Select all shown",
                   command=lambda: self.dev_tree.selection_set(self.dev_tree.get_children())).pack(side="left",
                                                                                                    padx=6)
        self.dev_count = ttk.Label(db, text="", foreground="#555")
        self.dev_count.pack(side="left", padx=6)
        df, self.dev_tree = make_tree(self, [("host", "Hostname", 220), ("ip", "IP", 180), ("group", "Group", 200),
                                             ("how", "How it got there", 260)], height=10, selectmode="extended")
        df.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.dev_tree.tag_configure("none", background="#fff0c2")
        right_click_menu(self.dev_tree, [("Move to group...", self.set_override), None] + dev_more)

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
        self.refresh_devices()

    def refresh_devices(self):
        needle = self.dev_search.get().strip().upper()
        keep = set(self.dev_tree.selection())
        self.dev_tree.delete(*self.dev_tree.get_children())
        for host, ip in sorted(self.app.groups_db["known_devices"].items()):
            gid, how = assess.assign_group(host, self.app.groups_db)
            how = {"override": "moved by hand", "unassigned": "no pattern matches"}.get(how, how)
            group = gid or "(not in a group - will not be assessed)"
            if needle and needle not in f"{host} {ip} {group}".upper():
                continue
            self.dev_tree.insert("", "end", iid=host, tags=("none",) if not gid else (),
                                 values=(host, ip, group, how))
        self.dev_tree.selection_set([h for h in keep if self.dev_tree.exists(h)])
        shown, total = len(self.dev_tree.get_children()), len(self.app.groups_db["known_devices"])
        self.dev_count.configure(text=f"{shown} of {total} devices shown" if needle else f"{total} devices")

    def selected(self):
        sel = self.tree.selection()
        return assess.find_group(self.app.groups_db, sel[0]) if sel else None

    def new_group(self):
        if not self.app.index:
            return messagebox.showinfo("Groups", "Import checklists on the Checklists tab first.")
        GroupDialog(self.app, None)
        self.after_change()

    def edit_group(self):
        g = self.selected()
        if not g:
            return select_first(self, "a group")
        GroupDialog(self.app, g)
        self.after_change()

    def copy_group(self):
        g = self.selected()
        if not g:
            return select_first(self, "the group to copy")
        GroupDialog(self.app, g, copy_of=True)
        self.after_change()

    def delete_group(self):
        g = self.selected()
        if not g:
            return select_first(self, "the group to delete")
        if messagebox.askyesno("Delete group", f"Delete group {g['id']} for everyone? Devices moved into it "
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
        if not hosts:
            return select_first(self, "one or more devices in the device list")
        if not ids:
            return messagebox.showinfo("Move devices", "There are no groups yet. Click 'New group...' first.")
        gid = ask_choice(self, "Move devices", f"Put {len(hosts)} device(s) in which group?", ids)
        if gid:
            store.set_overrides(hosts, gid)
            self.after_change()

    def clear_override(self):
        if not self.dev_tree.selection():
            return select_first(self, "one or more devices in the device list")
        store.set_overrides(self.dev_tree.selection(), None)
        self.after_change()

    def add_device(self):
        hosts = AddDevicesDialog(self, [], title="Add devices the tool has not seen yet").result
        if not hosts:
            return
        store.add_known_devices({h: "" for h in hosts if h not in self.app.groups_db["known_devices"]})
        self.after_change()
        gid = ask_choice(self, "Group", f"Put the {len(hosts)} device(s) in a group now? (Cancel = leave them to "
                                        "the hostname patterns)", [g["id"] for g in self.groups()])
        if gid:
            store.set_overrides(hosts, gid)
            self.after_change()

    def forget_device(self):
        hosts = self.dev_tree.selection()
        if not hosts:
            return select_first(self, "one or more devices in the device list")
        if messagebox.askyesno("Forget devices", f"Remove {len(hosts)} device(s) from the list? They come "
                                                           "back automatically the next time they appear in an "
                                                           "import."):
            for h in hosts:
                store.forget_device(h)
            self.after_change()

    def after_change(self):
        self.app.load_data()
        self.refresh()


class AddDevicesDialog(tk.Toplevel):
    """Add many devices at once: select them in the known-device list, or paste a list of hostnames.

    candidates: [(hostname, where it is now)]. result = [hostnames] (upper-case) or None.
    """

    def __init__(self, parent, candidates, title="Add devices", action="Add"):
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        self.geometry("1100x620")
        self.candidates, self.action, self.result = candidates, action, None
        self.where = dict(candidates)
        f = ttk.Frame(self, padding=10)
        f.pack(fill="both", expand=True)
        f.columnconfigure(0, weight=3)
        f.columnconfigure(1, weight=2)
        f.rowconfigure(2, weight=1)
        ttk.Label(f, text="Pick from devices the tool already knows", font=("Segoe UI", 10, "bold")).grid(
            row=0, column=0, sticky="w")
        ttk.Label(f, text="...or paste hostnames", font=("Segoe UI", 10, "bold")).grid(row=0, column=1, sticky="w",
                                                                                        padx=(12, 0))
        bar = ttk.Frame(f)
        bar.grid(row=1, column=0, sticky="we", pady=4)
        ttk.Label(bar, text="Search:").pack(side="left")
        self.search = tk.StringVar()
        ttk.Entry(bar, textvariable=self.search, width=24).pack(side="left", padx=4)
        self.search.trace_add("write", lambda *a: self.refresh())
        ttk.Button(bar, text="Select all shown", command=self.select_shown).pack(side="left", padx=4)
        ttk.Label(f, foreground="#555", wraplength=400, justify="left",
                  text="One per line, or separated by commas or spaces - e.g. a column copied from Excel or "
                       "SolarWinds. IP addresses are ignored. New hostnames are added to the device list.").grid(
            row=1, column=1, sticky="w", padx=(12, 0))
        tf, self.tree = make_tree(f, [("host", "Hostname", 240), ("now", "In group now", 220)], height=16,
                                  selectmode="extended")
        tf.grid(row=2, column=0, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.update_count())
        ttk.Label(f, text="Ctrl-click or Shift-click to select several.", foreground="#555").grid(
            row=3, column=0, sticky="w")
        self.paste = tk.Text(f, width=36, font=MONO)
        self.paste.grid(row=2, column=1, rowspan=2, sticky="nsew", padx=(12, 0))
        self.paste.bind("<KeyRelease>", lambda e: self.update_count())
        self.paste.bind("<<Paste>>", lambda e: self.after(10, self.update_count))
        b = ttk.Frame(f)
        b.grid(row=4, column=0, columnspan=2, sticky="we", pady=(10, 0))
        self.ok = ttk.Button(b, text=action, command=self.done, style="Accent.TButton")
        self.ok.pack(side="left")
        ttk.Button(b, text="Cancel", command=self.destroy).pack(side="left", padx=6)
        self.count = ttk.Label(b, text="", foreground="#1b4f8a")
        self.count.pack(side="left", padx=10)
        self.refresh()
        self.grab_set()
        parent.wait_window(self)

    def refresh(self):
        needle = self.search.get().strip().upper()
        keep = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children())
        for host, where in self.candidates:
            if needle and needle not in host.upper() and needle not in where.upper():
                continue
            self.tree.insert("", "end", iid=host, values=(host, where))
        self.tree.selection_set([h for h in keep if self.tree.exists(h)])
        self.update_count()

    def select_shown(self):
        self.tree.selection_set(self.tree.get_children())

    def chosen(self):
        hosts = [h.upper() for h in self.tree.selection()]
        return hosts + [h for h in assess.parse_hostnames(text_get(self.paste)) if h not in hosts]

    def update_count(self):
        hosts = self.chosen()
        moving = sum(1 for h in hosts if self.where.get(h, "(no group)") not in ("(no group)", ""))
        new = sum(1 for h in hosts if h not in self.where)
        self.ok.configure(text=f"{self.action} {len(hosts)} device(s)")
        self.count.configure(text=(f"{moving} of them are in another group now and will move. " if moving else "")
                             + (f"{new} are new to the tool." if new else ""))

    def done(self):
        hosts = self.chosen()
        if not hosts:
            return messagebox.showinfo(self.title(), "Select devices on the left or paste hostnames on the right.",
                                       parent=self)
        self.result = hosts
        self.destroy()


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
        ttk.Label(f, text=f"The team writes {checklist.FORMAT_LABELS[team]} files (Team settings menu). A STIG with no "
                          "file in that format is highlighted - import that file on the Checklists tab.",
                  foreground="#555").pack(anchor="w")
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
        pf, self.preview = make_tree(dev, [("host", "Hostname", 200), ("why", "Why", 300)], height=8,
                                     selectmode="extended")
        pf.grid(row=1, column=1, sticky="nsew")
        self.preview.tag_configure("hand", background="#dde9ff")
        self.preview.tag_configure("lost", background="#fff0c2")
        pb = ttk.Frame(dev)
        pb.grid(row=2, column=1, sticky="w", pady=4)
        ttk.Button(pb, text="Add devices...", command=self.add_by_hand).pack(side="left")
        ttk.Button(pb, text="Remove selected hand-added devices", command=self.remove_by_hand).pack(side="left",
                                                                                                   padx=6)
        ttk.Label(pb, text="Patterns are best when hostnames follow a naming rule; add the rest here.",
                  foreground="#555").pack(side="left", padx=6)

        self.summary = ttk.Label(f, text="", font=("Segoe UI", 10), foreground="#1b4f8a")
        self.summary.pack(anchor="w", pady=(10, 0))
        b = ttk.Frame(f)
        b.pack(fill="x", pady=(8, 0))
        ttk.Button(b, text="Save group", command=self.save, style="Accent.TButton").pack(side="left")
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
            if gid and gid == g["id"]:  # (a new group has no name yet; unassigned devices have none either)
                n += 1
                self.preview.insert("", "end", iid=host, tags=("hand",) if how == "override" else (),
                                    values=(host, "added by hand" if how == "override" else f"matches {how[8:]}"))
            elif mine:
                why = f"moved by hand to {gid}" if how == "override" else f"already taken by group {gid}"
                self.preview.insert("", "end", iid=host, tags=("lost",), values=(host, f"NOT included: {why}"))
        cov = assess.coverage(g, self.app.rules_db, self.app.index)
        auto, total = sum(r["automated"] for r in cov), sum(r["total"] for r in cov)
        self.summary.configure(text=f"This group will have {len(g['stigs'])} STIG checklist(s), {n} known "
                                    f"device(s), and {auto} of {total} checks automated.")

    def add_by_hand(self):
        g, db = self.simulated()
        others = [(h, assess.assign_group(h, db)[0] or "(no group)") for h in sorted(db["known_devices"])
                  if assess.assign_group(h, db)[0] != g["id"]]
        hosts = AddDevicesDialog(self, others, title=f"Add devices to {g['id'] or 'this group'}").result
        if not hosts:
            return
        new = {h: "" for h in hosts if h not in db["known_devices"]}
        if new:
            store.add_known_devices(new)
            self.app.groups_db["known_devices"].update(new)
        self.added |= set(hosts)
        self.removed -= set(hosts)
        self.update_preview()

    def remove_by_hand(self):
        sel = self.preview.selection()
        if not sel:
            return select_first(self, "the devices to remove (in the list above)")
        by_pattern = []
        for host in sel:
            if host in self.added:
                self.added.discard(host)
            elif self.app.groups_db["device_overrides"].get(host) == self.group["id"]:
                self.removed.add(host)
            else:
                by_pattern.append(host)
        self.update_preview()
        if by_pattern:
            messagebox.showinfo("Remove", f"{len(by_pattern)} selected device(s) are here because they match a "
                                          "pattern. Change the patterns, or move them to another group in the "
                                          "device list.", parent=self)

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
        store.set_overrides(self.removed, None)
        store.set_overrides(self.added, g["id"])
        self.destroy()


class SiteValuesDialog(tk.Toplevel):
    """Team setting: text written once and used by name in fix commands, e.g. <DOD_BANNER>, <NTP_SERVER_1>."""

    def __init__(self, app):
        super().__init__(app)
        self.app, self.current = app, None
        self.title("Site values")
        self.transient(app)
        self.geometry("1100x640")
        f = ttk.Frame(self, padding=10)
        f.pack(fill="both", expand=True)
        fit_text(ttk.Label(f, text="Write long or site-specific text ONCE here and use it by name in fix commands: "
                                   "<DOD_BANNER>, <NTP_SERVER_1>, <AAA_GROUP>... Hardening scripts fill these in. "
                                   "Anything not set stays as <NAME> in the script, listed under EDIT BEFORE USE. "
                                   "Leave per-device values such as <INTERFACE> unset.")).pack(fill="x")
        fit_text(ttk.Label(f, foreground="#b00020",
                           text="Do NOT store passwords, keys or SNMP community strings here: everyone with access to "
                                "the shared data can read them, and they are copied into every script.")).pack(
            fill="x", pady=(4, 8))
        body = ttk.Frame(f)
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)
        tf, self.tree = make_tree(body, [("name", "Name", 190), ("state", "Value", 90), ("used", "Used by", 80)],
                                  height=16)
        tf.grid(row=0, column=0, sticky="ns")
        color_tags(self.tree, {"unset": "#fff0c2"})
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.show())
        right = ttk.Frame(body)
        right.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        self.head = ttk.Label(right, text="", font=("Segoe UI", 10, "bold"))
        self.head.pack(anchor="w")
        self.text = tk.Text(right, wrap="word", font=MONO, height=14)
        self.text.pack(fill="both", expand=True, pady=4)
        b = ttk.Frame(right)
        b.pack(fill="x")
        ttk.Button(b, text="Save value", command=self.save, style="Accent.TButton").pack(side="left")
        self.reset_btn = ttk.Button(b, text="Remove value", command=self.remove)
        self.reset_btn.pack(side="left", padx=6)
        ttk.Button(b, text="New value...", command=self.new).pack(side="left")
        ttk.Button(f, text="Close", command=self.destroy).pack(anchor="w", pady=(8, 0))
        self.refresh()
        self.grab_set()

    def usage(self):
        used = {}
        for r in self.app.rules_db["rules"]:
            names = {n for v in (r.get("fix") or {}).values() for n in harden.placeholders_in(v)}
            for n in names:
                used[n] = used.get(n, 0) + 1
        return used

    def refresh(self, pick=None):
        self.app.load_data()
        values, used = harden.site_values(self.app.settings), self.usage()
        names = sorted(set(values) | set(self.app.settings.get("site_values") or {}) | set(used),
                       key=lambda n: (n not in values, n))
        self.tree.delete(*self.tree.get_children())
        for n in names:
            self.tree.insert("", "end", iid=n, tags=() if n in values else ("unset",),
                             values=(f"<{n}>", "set" if n in values else "NOT SET", f"{used.get(n, 0)} fix(es)"))
        pick = pick or self.current or (names[0] if names else None)
        if pick and self.tree.exists(pick):
            self.tree.selection_set(pick)
            self.tree.see(pick)

    def show(self):
        sel = self.tree.selection()
        if not sel:
            return
        self.current = sel[0]
        values = harden.site_values(self.app.settings)
        self.head.configure(text=f"<{self.current}>")
        text_set(self.text, values.get(self.current, ""))
        default = self.current in harden.DEFAULT_SITE_VALUES
        self.reset_btn.configure(text="Back to the built-in text" if default else "Remove value")

    def save(self):
        if self.current:
            store.set_site_value(self.current, text_get(self.text).strip("\n"))
            self.refresh()

    def remove(self):
        if self.current and messagebox.askyesno("Site value", f"Remove the team's value for <{self.current}>?",
                                                parent=self):
            store.set_site_value(self.current, None)
            self.refresh()

    def new(self):
        name = simpledialog.askstring("New site value", "Name (capitals, numbers and _), e.g. SYSLOG_SERVER:",
                                      parent=self)
        name = (name or "").strip().strip("<>").upper().replace(" ", "_")
        if not name:
            return
        if not re.fullmatch(r"[A-Z0-9_]+", name):
            return messagebox.showerror("New site value", "Use capitals, numbers and _ only.", parent=self)
        store.set_site_value(name, "")
        self.current = name
        self.refresh(pick=name)
        self.text.focus_set()


class PortRolesDialog(tk.Toplevel):
    """Team setting: the interface-description keywords that mark port roles. The built-in roles (used by the
    starter rules) can be re-worded but not removed; the team can add its own."""

    BUILT_IN = {"uplink": "Uplinks (toward distribution / core):",
                "downlink": "Downlinks (toward access switches):",
                "access": "Access / client ports (untrusted):",
                "trusted": "Trusted ports (e.g. analog gateways in a secure room - no 802.1x):"}

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Port roles")
        self.transient(app)
        self.resizable(False, False)
        f = ttk.Frame(self, padding=12)
        f.pack()
        ttk.Label(f, justify="left", wraplength=640, text=(
            "Rules find ports by the START of the interface description, so the port number does not matter. "
            "Label ports like 'description UPLINK - DIST-SW-01 Te2/0/14' or 'description TRUSTED - analog "
            "gateway rm 112'. Separate several keywords with commas. Upper / lower case does not matter. In a "
            "rule, use role:trusted, several roles at once (role:uplink, downlink, trusted) or role:any (any "
            "labelled port).")).pack(anchor="w", pady=(0, 10))
        self.rows_frame = ttk.Frame(f)
        self.rows_frame.pack(fill="x")
        self.vars = {}
        saved = app.settings["port_roles"]
        for role, label in self.BUILT_IN.items():
            self.add_row(role, saved.get(role, ""), label)
        for role, words in saved.items():
            if role not in self.BUILT_IN:
                self.add_row(role, words)
        add = ttk.Frame(f)
        add.pack(fill="x", pady=(10, 0))
        ttk.Label(add, text="New role name:").pack(side="left")
        self.new_name = tk.StringVar()
        entry = ttk.Entry(add, textvariable=self.new_name, width=16)
        entry.pack(side="left", padx=4)
        entry.bind("<Return>", lambda e: self.add_role())
        ttk.Button(add, text="Add role", command=self.add_role).pack(side="left")
        ttk.Label(add, text="  lower case, e.g. camera or voice", foreground="#555").pack(side="left")
        b = ttk.Frame(f)
        b.pack(pady=(12, 0))
        ttk.Button(b, text="Save", command=self.save, style="Accent.TButton").pack(side="left", padx=4)
        ttk.Button(b, text="Cancel", command=self.destroy).pack(side="left", padx=4)
        self.grab_set()
        app.wait_window(self)

    def add_row(self, role, words, label=None):
        row = ttk.Frame(self.rows_frame)
        row.pack(fill="x", pady=2)
        ttk.Label(row, text=label or f"role:{role}", width=58 if label else 20).pack(side="left")
        if not label:
            ttk.Label(row, text="(team role)", foreground="#555", width=36).pack(side="left")
        var = tk.StringVar(value=words)
        ttk.Entry(row, textvariable=var, width=30).pack(side="left", padx=6)
        if not label:
            ttk.Button(row, text="Remove", width=8,
                       command=lambda: (row.destroy(), self.vars.pop(role, None))).pack(side="left")
        self.vars[role] = var

    def add_role(self):
        name = self.new_name.get().strip().lower()
        if not engine.ROLE_NAME_RE.match(name) or name == "any":
            return messagebox.showerror("Port roles", "A role name is one lower-case word (letters, digits, - or _), "
                                                      "starting with a letter, and not 'any'.", parent=self)
        if name in self.vars:
            return messagebox.showerror("Port roles", f"There is already a role called {name}.", parent=self)
        self.add_row(name, name.upper())
        self.new_name.set("")

    def save(self):
        roles = {k: ", ".join(w.strip() for w in v.get().split(",") if w.strip()) for k, v in self.vars.items()}
        if not all(roles.values()):
            return messagebox.showerror("Port roles", "Every role needs at least one keyword.", parent=self)
        owners = {}
        for role, words in roles.items():
            for w in words.split(", "):
                owners.setdefault(w.upper(), []).append(role)
        clash = {w: r for w, r in owners.items() if len(r) > 1}
        if clash:
            return messagebox.showerror("Port roles", "A keyword can only mark one role:\n" + "\n".join(
                f"{w}: {', '.join(r)}" for w, r in clash.items()), parent=self)
        used = self.used_roles()
        gone = sorted(r for r in used if r not in roles)
        if gone and not messagebox.askokcancel(
                "Port roles", f"Rules still use role(s) you removed: {', '.join(gone)}. Those conditions will show "
                              "a problem (and give Not Reviewed) until they are changed. Save anyway?", parent=self):
            return
        store.set_setting("port_roles", roles)
        self.app.reload()
        self.destroy()

    def used_roles(self):
        """Role names that saved rules refer to."""
        found = set()
        for rule in self.app.rules_db["rules"]:
            for key in ("pass_logic", "na_logic"):
                for cond in (rule.get(key) or {}).get("conditions", []):
                    for text in engine.filter_lines(cond.get("only")) + engine.filter_lines(cond.get("exclude")) \
                            + [cond.get("text", "")]:
                        if engine.is_role(text):
                            found |= {n.strip().lower() for n in text.strip()[5:].split(",") if n.strip()}
        return found - {"any"}


class RuleChoicesDialog(tk.Toplevel):
    def __init__(self, app, group):
        super().__init__(app)
        self.app, self.group_id = app, group["id"]
        self.title(f"Rule versions for {group['id']}")
        self.geometry("1100x650")
        self.transient(app)
        help_label(self, "Usually not needed: a rule version made for some device groups is used by them "
                         "automatically (Rules tab > More > Add a version for some device groups). Use this only for "
                         "exceptions: double-click a check to pick the version this group uses, or 'Manual' for no "
                         "automated check. 'Automatic' follows the versions' 'Used by' settings.")
        self.only_multi = tk.BooleanVar(value=True)
        ttk.Checkbutton(self, text="Only show checks with more than one active version", variable=self.only_multi,
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
                label_ = f"{rule['id']} {rule.get('name', '')}" + ("  (this group's choice)" if raw else
                                                                   "  (automatic)")
            else:
                label_ = "- no active rule -"
            self.tree.insert("", "end", iid=key, values=(self.app.short(stig_id), control["vuln_id"],
                                                         control["title"], label_))
            shown += 1
        self.empty.configure(text="" if shown else "Nothing to choose: no check in this group has more than one "
                                                   "active rule version.")

    def choose(self):
        sel = self.tree.selection()
        if not sel:
            return select_first(self, "a check in the list")
        stig_id, vuln_id = sel[0].split("|", 1)
        active = [r for r in assess.rules_for_control(self.app.rules_db, stig_id, vuln_id)
                  if r.get("state") == "active"]
        options = ["Automatic (follows each version's 'Used by')"] +             [f"{r['id']} {r.get('name', '')}  - {assess.used_by_text(r)}" for r in active] +             ["Manual (no automated check)"]
        pick = ask_choice(self, "Rule version", f"Which version should {self.group_id} use for {vuln_id}?", options)
        if not pick:
            return

        def change(g):
            choices = g.setdefault("rule_choices", {})
            if pick.startswith("Automatic"):
                choices.pop(sel[0], None)
            elif pick.startswith("Manual"):
                choices[sel[0]] = "manual"
            else:
                choices[sel[0]] = pick.split()[0]
        store.modify_group(self.group_id, change)
        self.refresh()


# ---------------------------------------------------------------- fix commands (reviewed apart from the rule check)

FIX_ROW = {"unreviewed": "#fff0c2", "stale": "#ffd6d6", "reviewed": "#d9f7d6", "none": "#f4f4f4"}


def rule_logic_text(rule):
    """The rule's commands and numbered conditions, as the fix reviewer needs to see them."""
    lines = ["Show commands: " + (", ".join(rule.get("commands") or []) or "(none)"), ""]
    logic = rule.get("pass_logic") or {}
    lines.append(f"NOT A FINDING when {logic.get('mode', 'ALL')} of these are true:")
    lines += [f"  condition {i}: {engine.describe(c)}" for i, c in enumerate(logic.get("conditions", []), 1)]
    na = rule.get("na_logic") or {}
    if rule.get("na_enabled") and na.get("conditions"):
        lines += ["", f"NOT APPLICABLE when {na.get('mode', 'ALL')} of these are true (checked first):"]
        lines += [f"  - {engine.describe(c)}" for c in na["conditions"]]
    return "\n".join(lines)


class FixTab(ttk.Frame):
    SHOW = ["Needs review", "Reviewed", "All with fix commands", "No fix commands yet"]

    def __init__(self, nb, app):
        super().__init__(nb)
        self.app, self.loaded = app, None
        help_label(self, "Fix commands are what the Hardening scripts push to devices. A rule's tests prove its CHECK "
                         "works, not that its fix is right, so fixes are reviewed here, separately. Only REVIEWED "
                         "fixes go into hardening scripts. If someone later changes a rule's commands or conditions, "
                         "its fix comes back here as 'Rule changed - re-check'.")
        filt = ttk.Frame(self)
        filt.pack(fill="x", padx=6)
        ttk.Label(filt, text="STIG:").pack(side="left")
        self.stig_var = tk.StringVar(value="All")
        self.stig_box = ttk.Combobox(filt, textvariable=self.stig_var, state="readonly", width=32)
        self.stig_box.pack(side="left", padx=4)
        ttk.Label(filt, text="Show:").pack(side="left", padx=(10, 0))
        self.show_var = tk.StringVar(value=self.SHOW[0])
        ttk.Combobox(filt, textvariable=self.show_var, values=self.SHOW, state="readonly",
                     width=22).pack(side="left", padx=4)
        ttk.Label(filt, text="Search:").pack(side="left", padx=(10, 0))
        self.search_var = tk.StringVar()
        ttk.Entry(filt, textvariable=self.search_var, width=24).pack(side="left", padx=4)
        for var in (self.stig_var, self.show_var, self.search_var):
            var.trace_add("write", lambda *a: self.refresh())
        self.used_only = tk.BooleanVar(value=store.load_my_view().get("fixes_used_only", True))
        ttk.Checkbutton(filt, text="Only STIGs groups use", variable=self.used_only,
                        command=lambda: (store.save_my_view({"fixes_used_only": self.used_only.get()}),
                                         self.refresh())).pack(side="left", padx=(10, 0))
        self.progress = fit_text(ttk.Label(self, text="", foreground="#333"))
        self.progress.pack(fill="x", padx=8, pady=(4, 0))

        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=6, pady=6)
        left, self.tree = make_tree(paned, [("status", "Fix", 170), ("state", "Rule state", 70),
                                            ("rule", "Rule", 75), ("title", "Title", 200)], height=24,
                                    tree_column=("STIG / Vuln ID", 220))
        color_tags(self.tree, FIX_ROW)
        self.tree.tag_configure("family", background="#e8eef6", font=("Segoe UI Semibold", 10))
        self.tree.tag_configure("stig", background="#f4f7fb", font=("Segoe UI Semibold", 10))
        paned.add(left, weight=3)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.show_rule())

        right = ttk.Frame(paned)
        paned.add(right, weight=4)
        PaneKeeper(paned, [0.43])
        self.head = fit_text(ttk.Label(right, text="", font=("Segoe UI", 10, "bold")))
        self.head.pack(fill="x")
        fit_text(ttk.Label(right, text="What the rule checks ('{each failing section of condition N}' refers to these "
                                       "numbers):")).pack(fill="x", pady=(6, 0))
        self.logic = ScrolledText(right, height=6, wrap="word", font=("Segoe UI", 10))
        self.logic.pack(fill="x")
        ttk.Label(right, text="STIG fix text (for reference):").pack(anchor="w", pady=(6, 0))
        self.stig_fix = ScrolledText(right, height=5, wrap="word", font=("Segoe UI", 10))
        self.stig_fix.pack(fill="x")
        boxes = ttk.Frame(right)
        boxes.pack(fill="both", expand=True, pady=(6, 0))
        boxes.columnconfigure(0, weight=1)
        boxes.columnconfigure(1, weight=1)
        boxes.rowconfigure(1, weight=1)
        fit_text(ttk.Label(boxes, text="LOW-IMPACT fix (banners, logging, archive...):")).grid(
            row=0, column=0, sticky="we")
        fit_text(ttk.Label(boxes, text="IMPACTFUL fix (AAA, SSH, vty, ports, STP, SNMP...):")).grid(
            row=0, column=1, sticky="we")
        self.fix_low = config_wrap(tk.Text(boxes, height=8, width=30, font=MONO))
        self.fix_low.grid(row=1, column=0, sticky="nsew", padx=(0, 4))
        self.fix_high = config_wrap(tk.Text(boxes, height=8, width=30, font=MONO))
        self.fix_high.grid(row=1, column=1, sticky="nsew")
        for box in (self.fix_low, self.fix_high):
            box.tag_configure("value_set", background="#cdeec8", foreground="#1b5e20")
            box.tag_configure("value_unset", background="#ffe6a8", foreground="#7a4b00")
            box.bind("<KeyRelease>", lambda e, w=box: self.mark_values(w), add="+")
        hint = ttk.Label(right, foreground="#555",
                         text="<NAME> = a site value. GREEN ones are filled in automatically from Team settings > "
                              "Site values (e.g. <DOD_BANNER>); YELLOW ones are not set yet and must be edited in the "
                              "script. A line '{each failing section}' followed by indented commands "
                       "repeats them under every interface / section that failed on the device; '{each failing "
                       "section of condition 2}' only under the ones that failed condition 2. Lines starting with ! "
                       "are comments.")
        fit_text(hint).pack(side="bottom", fill="x", pady=(2, 0), before=boxes)
        b = ttk.Frame(right)
        b.pack(side="bottom", fill="x", pady=6, before=hint)
        self.review_btn = ttk.Button(b, text="Save and mark reviewed", command=lambda: self.save(reviewed=True), style="Accent.TButton")
        self.review_btn.pack(side="left")
        ttk.Button(b, text="Save without review", command=lambda: self.save(reviewed=False)).pack(side="left",
                                                                                                padx=6)
        self.review_label = fit_text(ttk.Label(b, text="", foreground="#555"))
        self.review_label.pack(side="left", fill="x", expand=True, padx=8)
        self.stig_map = {}

    def rows(self):
        """[(rule, stig_id, control or None, status)] for every rule that is not retired."""
        out = []
        for r in self.app.rules_db["rules"]:
            if r.get("state") == "retired":
                continue
            control = self.app.index.get(r["stig_id"], {}).get("controls", {}).get(r["vuln_id"])
            out.append((r, r["stig_id"], control, harden.fix_status(r)))
        order = {sid: i for i, sid in enumerate(self.app.index)}
        out.sort(key=lambda x: (order.get(x[1], 99), x[0]["vuln_id"], x[0]["id"]))
        return out

    def refresh(self):
        self.stig_map = {self.app.stig_label(sid): sid for sid in self.app.index}
        self.stig_box["values"] = ["All"] + list(self.stig_map)
        if self.stig_var.get() not in self.stig_box["values"]:
            self.stig_var.set("All")
        want_stig = self.stig_map.get(self.stig_var.get())
        show, needle = self.show_var.get(), self.search_var.get().lower().strip()
        used = {sid for g in self.app.groups_db.get("groups", []) for sid in g.get("stigs", [])}
        limit = self.used_only.get() and bool(used)
        keep = self.tree.selection()
        opened = {i for top in self.tree.get_children() for i in [top, *self.tree.get_children(top)]
                  if self.tree.item(i, "open")}
        first_fill = not self.tree.get_children()
        self.tree.delete(*self.tree.get_children())
        counts, hidden, by_stig = {}, 0, {}
        for r, sid, c, status in self.rows():
            if want_stig and sid != want_stig:
                continue
            if limit and not any(t["stig_id"] in used for t in store.rule_targets(r)):
                hidden += status != "none"
                continue
            counts[status] = counts.get(status, 0) + 1
            if show == "Needs review" and status not in ("unreviewed", "stale"):
                continue
            if show == "Reviewed" and status != "reviewed":
                continue
            if show == "All with fix commands" and status == "none":
                continue
            if show.startswith("No fix") and status != "none":
                continue
            title = c["title"] if c else "(STIG not imported)"
            if needle and needle not in f"{r['vuln_id']} {r['id']} {c['rule_ver'] if c else ''} {title}".lower():
                continue
            by_stig.setdefault(sid, []).append((r, c, status, title))
        for family, grouped, items in stig_families(self.app, by_stig):
            fam_iid = f"F::{family}"
            if grouped:
                self.tree.insert("", "end", iid=fam_iid, text=family, tags=("family",),
                                 open=first_fill or bool(needle) or fam_iid in opened)
            for sid, part in items:
                stig_iid = f"S::{sid}"
                rows = by_stig[sid]
                done = sum(1 for _, _, st, _ in rows if st == "reviewed")
                release = self.app.index.get(sid, {}).get("release", "")
                self.tree.insert(fam_iid if grouped else "", "end", iid=stig_iid, tags=("stig",),
                                 text=f"{part or self.app.short(sid)}   {release}",
                                 open=bool(needle) or stig_iid in opened,
                                 values=(f"{len(rows)} shown, {done} reviewed", "", "", ""))
                for r, c, status, title in rows:
                    self.tree.insert(stig_iid, "end", iid=r["id"], text=r["vuln_id"], tags=(status,),
                                     values=(harden.FIX_STATUS[status], r.get("state", "draft"), r["id"], title))
        with_fix = sum(n for k, n in counts.items() if k != "none")
        self.progress.configure(
            text=f"{counts.get('reviewed', 0)} of {with_fix} fixes reviewed"
                 + (f", {counts['stale']} need a re-check" if counts.get("stale") else "")
                 + (f"  ({hidden} more for STIGs no device group uses - untick to see them)" if hidden else ""))
        keep = [k for k in keep if self.tree.exists(k)]
        if keep:
            self.tree.selection_set(keep)
            self.tree.see(keep[0])
        else:
            self.show_rule()

    def current(self):
        sel = self.tree.selection()
        return self.app.rule_by_id(sel[0]) if sel and not sel[0].startswith(("F::", "S::")) else None

    def mark_values(self, box):
        """Colour each <NAME>: green when the team has set that site value, yellow when not."""
        known = harden.site_values(self.app.settings)
        for tag in ("value_set", "value_unset"):
            box.tag_remove(tag, "1.0", "end")
        for m in harden.PLACEHOLDER_RE.finditer(text_get(box)):
            start, end = f"1.0+{m.start()}c", f"1.0+{m.end()}c"
            box.tag_add("value_set" if m.group(0)[1:-1] in known else "value_unset", start, end)

    def boxes(self):
        return {"low": text_get(self.fix_low).rstrip(), "high": text_get(self.fix_high).rstrip()}

    def dirty(self):
        return self.loaded is not None and self.boxes() != self.loaded[1]

    def show_rule(self):
        r = self.current()
        if r and self.loaded and r["id"] == self.loaded[0] and self.dirty():
            return  # same rule re-selected after a refresh: keep the unsaved edits on screen
        if self.loaded and (not r or r["id"] != self.loaded[0]) and self.dirty():
            if messagebox.askyesno("Unsaved fix commands", f"Save your changes to the fix commands of "
                                                           f"{self.loaded[0]} first (not marked reviewed)?"):
                harden.save_fix(self.loaded[0], self.boxes(), reviewed=False)
                self.app.load_data()
                r = self.current() and self.app.rule_by_id(self.current()["id"])
        if not r:
            self.loaded = None
            self.head.configure(text="Select a rule on the left.")
            for w in (self.logic, self.stig_fix):
                text_set(w, "", readonly=True)
            for w in (self.fix_low, self.fix_high):
                text_set(w, "")
            self.review_label.configure(text="")
            return
        c = self.app.index.get(r["stig_id"], {}).get("controls", {}).get(r["vuln_id"])
        shared = [f"{self.app.short(t['stig_id'])} {t['vuln_id']}" for t in store.rule_targets(r)[1:]]
        self.head.configure(text=f"{self.app.short(r['stig_id'])} {r['vuln_id']}  {r['id']} '{r.get('name', '')}' "
                                 f"({r.get('state', 'draft')})\n{c['title'] if c else ''}"
                                 + (f"\nShared rule - this fix is also used for {', '.join(shared)}" if shared else ""))
        text_set(self.logic, rule_logic_text(r), readonly=True)
        text_set(self.stig_fix, c["fix"] if c else "", readonly=True)
        fix = r.get("fix") or {}
        text_set(self.fix_low, fix.get("low", ""))
        text_set(self.fix_high, fix.get("high", ""))
        for box in (self.fix_low, self.fix_high):
            self.mark_values(box)
        self.loaded = (r["id"], self.boxes())
        status, review = harden.fix_status(r), r.get("fix_review") or {}
        who = f"{review.get('by', 'someone')} on {(review.get('at') or '')[:10]}"
        self.review_label.configure(text={
            "none": "No fix commands. Type them above, then save.",
            "unreviewed": "Not reviewed yet - these fix commands are left out of hardening scripts.",
            "stale": f"Reviewed by {who}, but the rule's commands, conditions or this fix changed since. Check the "
                     "condition numbers still match, then mark reviewed again.",
            "reviewed": f"Reviewed by {who}."}[status])

    def save(self, reviewed):
        r = self.current()
        if not r:
            return select_first(self, "a rule in the list on the left")
        fix = self.boxes()
        if reviewed and not (fix["low"].strip() or fix["high"].strip()):
            return messagebox.showinfo("Fix commands", "There are no fix commands to review.")
        if reviewed and not messagebox.askyesno(
                "Mark reviewed", f"Confirm you checked the fix commands of {r['id']}: the commands are right for "
                                 "this platform, the IMPACTFUL ones are in the impactful box, and every '{each failing "
                                 "section of condition N}' points at the right condition?"):
            return
        harden.save_fix(r["id"], fix, reviewed)
        self.loaded = None
        self.app.load_data()
        self.refresh()
        if self.tree.exists(r["id"]):
            self.tree.selection_set(r["id"])
            self.tree.see(r["id"])
        else:
            self.show_rule()


# ---------------------------------------------------------------- run an assessment

class AssessTab(ttk.Frame):
    DEVICE_SHOW = ["All devices", "Not in a group yet", "Collection failed or invalid"]
    FILTERS = ["Everything", "Needs your decision", "Open", "Open (expected)",
               "Not Reviewed",
               "Not Applicable", "Not a Finding", "Not automated (no rule)", "Changed by reviewer"]

    def __init__(self, nb, app):
        super().__init__(nb)
        self.app = app
        self.vars, self.last_script = {}, ""
        self.pending, self.shown = {}, None  # (group, check) -> (final, comment) changed but not applied yet
        step1 = ttk.LabelFrame(self, text=" 1. Collect ")
        step1.pack(fill="x", padx=6, pady=(6, 0))
        fit_text(ttk.Label(step1, foreground="#555", text="Choose the groups, copy the script, paste it into "
                                                          "SolarWinds 'Execute Command Script' and save the output as "
                                                          "a text file.")).pack(fill="x", padx=6)
        row = ttk.Frame(step1)
        row.pack(fill="x", padx=6, pady=4)
        self.group_frame = ttk.Frame(row)
        self.group_frame.pack(side="left")
        ttk.Button(row, text="Copy collection script", command=self.collect, style="Accent.TButton").pack(side="left", padx=(12, 0))
        self.collect_label = ttk.Label(row, text="", foreground="#1b4f8a")
        fit_text(self.collect_label).pack(side="left", fill="x", expand=True, padx=10)

        step2 = ttk.LabelFrame(self, text=" 2. Import the SolarWinds output ")
        step2.pack(fill="x", padx=6, pady=(6, 0))
        top = ttk.Frame(step2)
        top.pack(fill="x", padx=6, pady=4)
        ttk.Button(top, text="Import SolarWinds output...", command=self.do_import, style="Accent.TButton").pack(side="left")
        self.run_label = ttk.Label(top, text="", foreground="#333")
        fit_text(self.run_label).pack(side="left", fill="x", expand=True, padx=10)
        self.stale_bar = tk.Frame(step2, bg="#fff4ce", highlightthickness=1, highlightbackground="#e8c95c")
        self.stale_label = fit_text(tk.Label(self.stale_bar, text="", bg="#fff4ce", fg="#5c4300", anchor="w"))
        ttk.Button(self.stale_bar, text="Re-run now", style="Accent.TButton",
                   command=self.reevaluate).pack(side="right", padx=6, pady=4)
        self.stale_label.pack(side="left", fill="x", expand=True, padx=8, pady=4)

        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True, padx=6, pady=6)
        self.run_paned, self._roomy = paned, None
        dev = ttk.LabelFrame(paned, text=" Devices in this run - check each one is in the right group ")
        # Never smaller than the filter bar, the buttons and 5 device rows, whatever the screen's scaling
        self.run_keeper = PaneKeeper(paned, [0.3], first_min=dev.winfo_reqheight)
        paned.add(dev, weight=0)  # a few rows (drag the divider for more); the review list gets the room
        fb = ttk.Frame(dev)
        fb.pack(fill="x", pady=(2, 2))
        ttk.Label(fb, text="Find:").pack(side="left")
        self.dev_search = tk.StringVar()
        ttk.Entry(fb, textvariable=self.dev_search, width=20).pack(side="left", padx=(2, 8))
        ttk.Label(fb, text="Show:").pack(side="left")
        self.dev_show = tk.StringVar(value=self.DEVICE_SHOW[0])
        self.dev_show_box = ttk.Combobox(fb, textvariable=self.dev_show, state="readonly", width=26,
                                         values=self.DEVICE_SHOW)
        self.dev_show_box.pack(side="left", padx=(2, 8))
        for var in (self.dev_search, self.dev_show):
            var.trace_add("write", lambda *a: self.refresh_devices())
        ttk.Button(fb, text="Select all shown",
                   command=lambda: self.dev_tree.selection_set(self.dev_tree.get_children())).pack(side="left")
        self.dev_summary = ttk.Label(fb, text="", foreground="#333")
        fit_text(self.dev_summary).pack(side="left", fill="x", expand=True, padx=10)
        db = ttk.Frame(dev)
        db.pack(side="bottom", fill="x", pady=2)
        self.change_btn = ttk.Button(db, text="Change group of selected devices...", command=self.change_group)
        self.change_btn.pack(side="left")
        self.warn_label = ttk.Label(db, text="", foreground="#9a6a00")
        self.warn_label.pack(side="left", padx=10)
        df, self.dev_tree = make_tree(dev, [("host", "Device", 160), ("ip", "IP", 140), ("group", "Group", 150),
                                            ("how", "Assigned by", 130), ("state", "Collection", 260),
                                            ("cmds", "Commands", 100)], height=5, selectmode="extended")
        df.pack(fill="both", expand=True)
        color_tags(self.dev_tree, {"bad": "#ffd6d6", "nogroup": "#fff0c2"})
        self.dev_tree.bind("<<TreeviewSelect>>", lambda e: self.show_dev_selection())
        right_click_menu(self.dev_tree, [("Change group of selected devices...", self.change_group)])

        rev = ttk.LabelFrame(paned, text=" 3. Review - the tool only RECOMMENDS a result; change any of them "
                                         "(a reason is required). Missing or failed evidence is never a pass. ")
        paned.add(rev, weight=3)
        bar = ttk.Frame(rev)
        bar.pack(fill="x")
        ttk.Label(bar, text="Group:").pack(side="left")
        self.group_var = tk.StringVar()
        self.group_box = ttk.Combobox(bar, textvariable=self.group_var, state="readonly", width=24)
        self.group_box.pack(side="left", padx=4)
        self.group_box.bind("<<ComboboxSelected>>", lambda e: self.show_results())
        ttk.Label(bar, text="Show:").pack(side="left", padx=(10, 0))
        self.filter_var = tk.StringVar(value=self.FILTERS[1])  # what needs a decision first
        fb = ttk.Combobox(bar, textvariable=self.filter_var, values=self.FILTERS, state="readonly", width=34)
        fb.pack(side="left", padx=4)
        fb.bind("<<ComboboxSelected>>", lambda e: self.show_results())
        self.count_label = fit_text(ttk.Label(bar, text=""))
        self.count_label.pack(side="left", fill="x", expand=True, padx=10)
        self.manual_note = fit_text(tk.Label(rev, text="", bg=INFO_BG, fg="#1f1f1f", anchor="w", padx=8, pady=3),
                                    pad=28)

        self.review_split = inner = ttk.PanedWindow(rev, orient="horizontal")
        inner.pack(fill="both", expand=True, pady=4)
        rf, self.res_tree = make_tree(inner, [("fam", "STIG", 170), ("vuln", "Vuln ID", 75), ("ver", "Rule Ver", 110),
                                              ("rec", "Recommended", 185), ("final", "Final", 185),
                                              ("devs", "Devices", 220), ("title", "Title", 200)],
                                      height=14, selectmode="extended")
        color_tags(self.res_tree, STATUS_ROW)
        inner.add(rf, weight=3)
        self.res_tree.bind("<<TreeviewSelect>>", lambda e: self.show_detail())
        side = ttk.Frame(inner)
        inner.add(side, weight=2)
        PaneKeeper(inner, [0.6])
        self.detail = ScrolledText(side, height=14, wrap="word", font=MONO)
        self.detail.pack(fill="both", expand=True)
        act = ttk.Frame(side)
        act.pack(fill="x", pady=4)
        ttk.Label(act, text="Final result:").grid(row=0, column=0, sticky="w")
        self.final_var = tk.StringVar()
        ttk.Combobox(act, textvariable=self.final_var, state="readonly", width=26,
                     values=[STATUS_LABELS[s] for s in STATUSES] + [assess.NOT_AUTOMATED]).grid(row=0, column=1,
                                                                                            sticky="w")
        ttk.Label(act, text="Reviewer comment:").grid(row=1, column=0, sticky="nw")
        self.comment = tk.Text(act, height=3, width=48, wrap="word", font=("Segoe UI", 10))
        self.comment.grid(row=1, column=1, sticky="we")
        self.unapplied = ttk.Label(act, text="", foreground="#b00020")
        self.unapplied.grid(row=3, column=1, sticky="w")
        ab = ttk.Frame(act)
        ab.grid(row=2, column=1, sticky="w", pady=4)
        ttk.Button(ab, text="Apply to selected (Ctrl+Enter)", command=self.apply).pack(side="left")
        for w in (self.comment, self.res_tree):
            w.bind("<Control-Return>", lambda e: (self.apply(), "break")[-1])
        ttk.Button(ab, text="Reset to recommendation", command=self.reset).pack(side="left", padx=4)

        step4 = ttk.LabelFrame(self, text=" 4. Write the checklist ")
        step4.pack(side="bottom", fill="x", padx=6, pady=(0, 6), before=paned)  # never squeezed out
        bottom = ttk.Frame(step4)
        bottom.pack(fill="x", padx=6, pady=4)
        ttk.Label(bottom, text="Reviewer (full name):").pack(side="left")
        self.reviewer = tk.StringVar(value=store.load_my_view().get("reviewer", ""))
        ttk.Entry(bottom, textvariable=self.reviewer, width=24).pack(side="left", padx=4)
        self.write_btn = ttk.Button(bottom, text="Write checklist package", style="Accent.TButton",
                                    command=lambda: self.write(all_groups=False))
        self.write_btn.pack(side="left", padx=8)
        self.fmt_label = ttk.Label(bottom, text="", foreground="#1b4f8a")
        self.fmt_label.pack(side="left", padx=10)
        self.written = ttk.Frame(step4)  # 'Last written: <folder> - Open folder', shown after writing
        self.written_label = fit_text(ttk.Label(self.written, text="", foreground="#1b7a1b",
                                                font=("Segoe UI Semibold", 10)))
        self.written_btn = ttk.Button(self.written, text="Open folder")
        self.written_btn.pack(side="right", padx=6)
        self.written_label.pack(side="left", fill="x", expand=True, padx=6)

    # -- step 1: collection script
    def refresh_groups(self):
        old = {k: v.get() for k, v in self.vars.items()}
        for w in self.group_frame.winfo_children():
            w.destroy()
        self.vars = {}
        groups = self.app.groups_db.get("groups", [])
        if not groups:
            ttk.Label(self.group_frame, text="No device groups yet - create them in Set up and rules > Device "
                                             "groups.").pack(side="left")
            return
        # One dropdown of ticked groups: stays one line however many groups there are.
        self.group_btn = ttk.Menubutton(self.group_frame, width=60)
        menu = tk.Menu(self.group_btn, tearoff=0)
        menu.add_command(label="All groups", command=lambda: self.tick_groups(True))
        menu.add_command(label="None", command=lambda: self.tick_groups(False))
        menu.add_separator()
        for g in groups:
            var = tk.BooleanVar(value=old.get(g["id"], len(groups) == 1))
            names = ", ".join(self.app.short(s) for s in g.get("stigs", []))
            menu.add_checkbutton(label=f"{g['id']}   ({names})", variable=var, command=self.show_ticked)
            self.vars[g["id"]] = var
        self.group_btn["menu"] = menu
        self.group_btn.pack(side="left")
        self.show_ticked()

    def tick_groups(self, on):
        for var in self.vars.values():
            var.set(on)
        self.show_ticked()

    def show_ticked(self):
        ticked = [gid for gid, var in self.vars.items() if var.get()]
        names = ", ".join(ticked[:3]) + (f", +{len(ticked) - 3}" if len(ticked) > 3 else "")
        self.group_btn.configure(text=f"{len(ticked)} of {len(self.vars)} groups: {names}" if ticked
                                 else "Choose groups...")

    def collect(self):
        groups = [g for g in self.app.groups_db.get("groups", []) if self.vars.get(g["id"], tk.BooleanVar()).get()]
        if not groups:
            return messagebox.showinfo("Collection script", "Choose at least one group in the groups dropdown." if
                                       self.vars else "There are no device groups yet. Create them in Set up and "
                                                      "rules > Device groups.")
        sources = assess.commands_for_groups(groups, self.app.rules_db, self.app.index)
        if not sources:
            return messagebox.showinfo("Collection script", "These groups have no active rules yet, so there is "
                                                            "nothing to collect. Activate rules in Set up and rules.")
        script, sid = collect.build_script(sources, [g["id"] for g in groups])
        store.save_script_record({"script_id": sid, "created": store.now(), "created_by": store.current_user(),
                                  "groups": [g["id"] for g in groups], "commands": sorted(sources)})
        path = store.paths.output / "scripts" / f"collect_{'_'.join(g['id'] for g in groups)[:80]}_{sid}.txt"
        path.write_text(script, encoding="utf-8")
        self.clipboard_clear()
        self.clipboard_append(script)
        lines = [f"Collection script for {', '.join(g['id'] for g in groups)}: {len(sources)} unique command(s).",
                 f"Saved to {path}", "Do not remove the '! CMD:' lines - they tie each output block to its command.",
                 ""]
        warn = 0
        for g in groups:
            for r in assess.coverage(g, self.app.rules_db, self.app.index):
                lines.append(f"{g['id']} - {r['short']}: {r['automated']} of {r['total']} automated, "
                             f"{r['manual']} manual, {r['no_rule'] + r['draft']} not built yet"
                             + (f" - {r['changed']} rule(s) need review after a STIG update" if r["changed"] else ""))
                warn += r["changed"]
        self.last_script = "\n".join(lines) + "\n\n" + "=" * 70 + "\n\n" + script
        self.collect_label.configure(text=f"Copied to the clipboard ({len(sources)} commands). Paste it into "
                                          "SolarWinds." + (f"  {warn} rule(s) need review after a STIG update."
                                                           if warn else ""))

    def show_script(self):
        if not self.last_script:
            files = sorted((store.paths.output / "scripts").glob("collect_*.txt"), key=lambda f: f.stat().st_mtime)
            if not files:
                return messagebox.showinfo("Collection script", "No collection script made yet.")
            self.last_script = f"{files[-1]}\n\n" + files[-1].read_text(encoding="utf-8")
        ImportReport(self, self.last_script, title="Collection script", mono=True)

    # -- data
    def refresh(self):
        self.refresh_groups()
        run = self.app.run
        self.fmt_label.configure(text=f"Writes {checklist.FORMAT_LABELS[self.app.output_format]} files "
                                      "(Team settings menu)")
        self.dev_tree.delete(*self.dev_tree.get_children())
        self.stale_bar.pack_forget()
        if not run:
            self.run_label.configure(text="No run loaded. Import a SolarWinds output file to start.")
            self.group_box["values"] = []
            self.show_results()
            return
        self.run_label.configure(text=f"Run {run['id']} - {run['source_name']} - {len(run['devices'])} devices"
                                      + (f" - assessed {run['evaluated']}" if run.get("evaluated") else ""))
        self.refresh_devices()
        self.warn_label.configure(text="; ".join(run.get("warnings", []))[:200])
        stale = assess.out_of_date(run, self.app.groups_db, self.app.rules_db, self.app.index)
        if stale["checks"] or stale["devices"]:
            parts = ([f"the rules behind {stale['checks']} result(s) were changed"] if stale["checks"] else []) + \
                    ([f"{stale['devices']} device(s) were moved to another group"] if stale["devices"] else [])
            self.stale_label.configure(
                text="These results may be out of date: after they were made, " + " and ".join(parts) + ". "
                     "Click 'Re-run now' to check the same SolarWinds output again with the latest rules and groups. "
                     "Nothing is collected from the devices again, and your review decisions and comments are kept.")
            if not self.stale_bar.winfo_manager():
                self.stale_bar.pack(fill="x", padx=6, pady=(0, 4))
        else:
            self.stale_bar.pack_forget()
        groups = sorted(run.get("results", {}))
        self.group_box["values"] = groups
        if self.group_var.get() not in groups:
            self.group_var.set(groups[0] if groups else "")
        self.show_results()

    def device_rows(self):
        """[(device, group, how, collection text, tag)] for every device in the run."""
        rows = []
        for d in (self.app.run or {}).get("devices", []):
            m = self.app.run["membership"].get(d["host"], {"group": "", "how": "unassigned"})
            if d["status"] != "ok":
                state, tag = f"FAILED: {d['error']}", "bad"
            else:
                bad = [c for c, o in d["outputs"].items() if o["status"] != "ok"]
                state = "OK" + (f", {len(bad)} invalid command(s)" if bad else "")
                tag = "bad" if bad else ("nogroup" if not m["group"] else "")
            rows.append((d, m["group"], m["how"], state, tag))
        return rows

    def refresh_devices(self):
        rows = self.device_rows()
        groups = sorted({g for _, g, _, _, _ in rows if g})
        self.dev_show_box["values"] = self.DEVICE_SHOW + [f"Group {g}" for g in groups]
        show, needle = self.dev_show.get(), self.dev_search.get().strip().upper()
        if show not in self.dev_show_box["values"]:
            self.dev_show.set(self.DEVICE_SHOW[0])
            return  # the trace calls back in
        keep = set(self.dev_tree.selection())
        self.dev_tree.delete(*self.dev_tree.get_children())
        for d, group, how, state, tag in rows:
            if show == "Not in a group yet" and group:
                continue
            if show.startswith("Collection") and tag != "bad":
                continue
            if show.startswith("Group ") and group != show[6:]:
                continue
            if needle and needle not in f"{d['host']} {d['ip']} {group}".upper():
                continue
            self.dev_tree.insert("", "end", iid=d["host"], tags=(tag,),
                                 values=(d["host"], d["ip"], group or "(none - not assessed)", how, state,
                                         f"{len(d['outputs'])} collected"))
        self.dev_tree.selection_set([h for h in keep if self.dev_tree.exists(h)])
        total = len(rows)
        nogroup = sum(1 for _, g, _, _, t in rows if not g)
        failed = sum(1 for *_, t in rows if t == "bad")
        shown = len(self.dev_tree.get_children())
        # While devices still need a group, give the device list half the height; once sorted, keep it compact.
        roomy = ((self.app.run or {}).get("id"), nogroup > 0)
        if roomy != self._roomy:
            self._roomy = roomy
            self.after(100, lambda: self.size_device_list(0.5 if nogroup else 0.3))
        self.dev_summary.configure(
            text=(f"{shown} of {total} shown.  " if shown != total else f"{total} devices:  ")
            + f"{total - nogroup} in groups" + (f", {nogroup} NOT in a group" if nogroup else "")
            + (f", {failed} failed or invalid" if failed else ""))
        self.show_dev_selection()

    def size_device_list(self, share):
        self.run_keeper.set([share])

    def show_dev_selection(self):
        n = len(self.dev_tree.selection())
        self.change_btn.configure(text=f"Change group of the {n} selected devices..." if n > 1 else
                                  "Change group of selected devices...")

    def results(self):
        if not self.app.run:
            return None
        return self.app.run.get("results", {}).get(self.group_var.get())

    def show_results(self):
        keep = self.res_tree.selection()
        self.res_tree.delete(*self.res_tree.get_children())
        res = self.results()
        gid = self.group_var.get()
        if not res:
            self.manual_note.pack_forget()
            self.written.pack_forget()
        self.write_btn.configure(text=f"Write checklist package for {gid}" if res else "Write checklist package")
        if not res:
            self.count_label.configure(text="")
            self.show_detail()
            return
        f = self.filter_var.get()
        counts, need = {}, 0
        not_auto = sum(1 for c in res["controls"].values() if not c["rule_id"] and c["final"] is None)
        if not_auto:
            self.manual_note.configure(
                text=f"{not_auto} check(s) are not automated: the tool did not check them, so the checklist keeps "
                     "them as they are (usually Not Reviewed). After writing the package, assess them in STIG "
                     "Viewer - or set a result for them here.")
            if not self.manual_note.winfo_manager():
                self.manual_note.pack(fill="x", before=self.review_split, pady=(2, 2))
        else:
            self.manual_note.pack_forget()
        for key, c in res["controls"].items():
            if assess.needs_decision(c):
                need += 1
            final = c["final"]
            shown_as = assess.result_label(c)
            counts[shown_as] = counts.get(shown_as, 0) + 1
            if f.startswith("Needs") and not assess.needs_decision(c):
                continue
            if (f in STATUS_LABELS.values() or f == "Open (expected)") and shown_as != f:
                continue
            if f.startswith("Not automated") and c["rule_id"]:
                continue
            if f.startswith("Changed") and not c["reviewer_changed"]:
                continue
            per = {}
            for r in c["per_device"].values():
                per[r["status"]] = per.get(r["status"], 0) + 1
            devs = ", ".join(f"{n} {STATUS_LABELS[s]}" for s, n in sorted(per.items())) or "-"
            tag = "changed" if c["reviewer_changed"] else (
                "expected" if assess.is_expected_open(c) else (final or "manual"))
            self.res_tree.insert("", "end", iid=key, tags=(tag,),
                                 values=(c["family"], c["vuln_id"], c["rule_ver"],
                                         assess.result_label(c, "recommended"), shown_as, devs, c["title"]))
        self.count_label.configure(
            text=(f"{need} need your decision" if need else "Nothing needs your decision")
            + ("" if f.startswith("Needs") else " (Show 'Needs your decision' to list them)" if need else "")
            + "      " + "   ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
        if f.startswith("Needs") and not need:
            self.res_tree.insert("", "end", iid="__none__", values=(
                "Nothing needs your decision.", "", "", "", "", "", "Choose Show: Everything to see all results."))
        keep = [k for k in keep if self.res_tree.exists(k)]
        if keep:
            self.res_tree.selection_set(keep)
        self.show_detail()

    def selected(self):
        res = self.results()
        return [res["controls"][k] for k in self.res_tree.selection() if k in res["controls"]] if res else []

    def remember_unapplied(self):
        """Keep a final result / comment the reviewer changed but did not Apply, for the result on screen."""
        if not self.shown:
            return
        gid, key = self.shown
        c = (self.app.run or {}).get("results", {}).get(gid, {}).get("controls", {}).get(key)
        if not c:
            return
        now = (self.final_var.get(), text_get(self.comment).strip())
        if now != (assess.label(c["final"]), (c.get("reviewer_comment") or "").strip()):
            self.pending[self.shown] = now
        else:
            self.pending.pop(self.shown, None)

    def show_detail(self):
        self.remember_unapplied()
        sel = self.selected()
        self.shown = (self.group_var.get(), self.res_tree.selection()[0]) if len(sel) == 1 else None
        self.unapplied.configure(text="")
        if not sel:
            text_set(self.detail, "", readonly=True)
            return
        c = sel[0]
        lines = [f"{c['family']} {c['vuln_id']} {c['rule_ver']} [{c['severity']}]", c["title"], ""]
        if c["rule_id"]:
            prefix = assess.outcome_prefix(c)
            if assess.is_expected_open(c):
                lines += ["EXPECTED FINDING: the rule marks Open as intentional for this check.", ""]
            field = assess.FIELD_LABELS[self.app.settings["text_placement"].get(c["final"] or "", "comments")]
            lines += [f"For {assess.label(c['final'])} this reason is written to the checklist's {field.upper()}:",
                      ""]
            if prefix:
                lines += [prefix, ""]
            lines.append(c["details"])
        else:
            lines.append("Not automated: there is no rule for this check in this group. The checklist keeps its "
                         f"current value ({STATUS_LABELS.get(c.get('template_status'), '?')}) unless you set a "
                         "final result here.")
        if c["reviewer_changed"] or c.get("reviewer_comment"):
            lines += ["", f"Reviewer: final {assess.label(c['final'])} - {c.get('reviewer_comment', '')}"]
        elif assess.needs_decision(c):
            lines += ["", "NEEDS YOUR DECISION. Agree with this result? Leave it as it is, type why in Reviewer "
                          "comment and click Apply. To change it, pick another Final result, type why and Apply."]
        text_set(self.detail, "\n".join(lines), readonly=True)
        final, comment = self.pending.get(self.shown, (assess.label(c["final"]), c.get("reviewer_comment", "")))
        self.final_var.set(final)
        text_set(self.comment, comment)
        if self.shown in self.pending:
            self.unapplied.configure(text="Changed but not applied yet - click 'Apply to selected' to keep it.")

    # -- actions
    def do_import(self):
        path = filedialog.askopenfilename(title="Choose SolarWinds output file", initialdir=str(store.paths.input),
                                          filetypes=[("Text files", "*.txt *.log"), ("All files", "*.*")])
        if not path:
            return
        with busy(self):
            run = assess.import_solarwinds(path, self.app.groups_db, self.app.rules_db)
        if not run["devices"]:
            return messagebox.showerror(
                "Not a SolarWinds output file",
                f"No devices were found in {os.path.basename(path)}.\n\n" + "\n".join(run.get("warnings", []))
                + "\n\nChoose the text file saved from SolarWinds 'Execute Command Script'. The current results "
                  "were left as they were.")
        if not self.leave_run_ok():
            return
        store.add_known_devices({d["host"]: d["ip"] for d in run["devices"]})
        with busy(self):
            assess.evaluate_run(run, self.app.groups_db, self.app.rules_db, self.app.index)
        self.pending, self.shown = {}, None
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

    def leave_run_ok(self):
        """Before another run replaces this one: warn about review changes that were never applied."""
        self.remember_unapplied()
        if self.pending and not messagebox.askyesno(
                "Changes not applied", f"{len(self.pending)} result(s) in the current run have a final result or "
                                       "comment you changed but did not Apply. They will be lost.\n\nContinue?",
                icon="warning"):
            return False
        self.pending, self.shown = {}, None
        return True

    def open_run(self):
        runs = store.list_runs()
        if not runs:
            return messagebox.showinfo("Runs", "No previous runs.")
        if not self.leave_run_ok():
            return
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
            return messagebox.showinfo("Re-run", "There are no results yet. Import a SolarWinds output file first.")
        self.remember_unapplied()
        with busy(self):
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
        if not run:
            return messagebox.showinfo("Change group", "Import a SolarWinds output file first.")
        if not hosts:
            return select_first(self, "one or more devices in the device list")
        if not ids:
            return messagebox.showinfo("Change group", "There are no device groups yet. Create them in Set up and "
                                                       "rules > Device groups.")
        back = "(no group of its own - go back to the hostname patterns)"
        gid = ask_choice(self, "Change group", f"Put {len(hosts)} device(s) in which group? This is remembered "
                                               "for future runs too.", ids + [back])
        if not gid:
            return
        store.set_overrides(hosts, None if gid == back else gid)
        self.app.load_data()
        self.reevaluate()

    def apply(self):
        sel = self.selected()
        if not sel:
            return select_first(self, "one or more results in the list")
        label = self.final_var.get()
        final = None if label == assess.NOT_AUTOMATED else LABEL_TO_STATUS[label]
        comment = text_get(self.comment).strip()
        for c in sel:
            if final is None and c["rule_id"]:
                return messagebox.showerror("Not allowed", f"{c['vuln_id']} has a rule; choose a result.")
        if any(final != c["recommended"] for c in sel) and not comment:
            return messagebox.showerror("Reason needed", "You are changing the recommended result. "
                                                         "Type a reviewer comment explaining why.")
        if not comment and any(final in ("open", "not_reviewed") for c in sel):
            return messagebox.showerror("Reason needed", "Type a reviewer comment saying why you agree with this "
                                                         f"{assess.label(final)} result, then Apply. That marks it "
                                                         "as decided.")
        for c in sel:
            c["final"] = final
            c["reviewer_comment"] = comment
            c["reviewer_changed"] = final != c["recommended"]
        gid = self.group_var.get()
        for key in self.res_tree.selection():
            self.pending.pop((gid, key), None)
        self.shown = None
        self.app.save_run()
        self.show_results()

    def reset(self):
        if not self.selected():
            return select_first(self, "one or more results in the list")
        for c in self.selected():
            c.update(final=c["recommended"], reviewer_comment="", reviewer_changed=False)
        gid = self.group_var.get()
        for key in self.res_tree.selection():
            self.pending.pop((gid, key), None)
        self.shown = None
        self.app.save_run()
        self.show_results()

    def write(self, all_groups):
        run = self.app.run
        if not run or not run.get("results"):
            return messagebox.showinfo("Write", "Nothing to write - import and assess a SolarWinds output first.")
        reviewer = self.reviewer.get().strip()
        if not reviewer:
            return messagebox.showerror("Reviewer", "Type your full name in 'Reviewer (full name)'. It is written into "
                                                    "the checklist as the person who reviewed these results.")
        store.save_my_view({"reviewer": reviewer})
        self.remember_unapplied()
        if self.pending and not messagebox.askyesno(
                "Changes not applied", f"{len(self.pending)} result(s) have a final result or comment you changed "
                                       "but did not Apply. Those changes will NOT be in the checklist.\n\n"
                                       "Write anyway?", icon="warning"):
            return
        groups = sorted(run["results"]) if all_groups else [self.group_var.get()]
        fmt = self.app.output_format
        summary = [f"Format: {checklist.FORMAT_LABELS[fmt]}", ""]
        for gid in groups:
            summary.append(f"{gid}:")
            not_auto = sum(1 for c in run["results"][gid]["controls"].values()
                           if not c["rule_id"] and c["final"] is None)
            if not_auto:
                summary.append(f"   {not_auto} check(s) not automated - left as they are in the blank checklist "
                               "(usually Not Reviewed). Assess them in STIG Viewer afterwards.")
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
        report, folders = [], []
        with busy(self):
            for gid in groups:
                folder, ok, msgs = assess.write_package(run, gid, reviewer, self.app.groups_db, self.app.rules_db,
                                                        fmt, self.app.settings["text_placement"])
                report += msgs + [""]
                folders.append(folder)
        self.app.save_run()
        ext = ".cklb" if fmt == "cklb" else ".ckl"
        files = [f for folder in folders for f in sorted(folder.glob(f"*{ext}"))]
        where = folders[0] if len(folders) == 1 else store.paths.output
        review = [f.name for f in folders if f.name.endswith("_REVIEW_REQUIRED")]
        self.written_label.configure(
            text=f"Last written {store.now()[11:16]}: {len(files)} checklist(s) in "
                 + (folders[0].name if len(folders) == 1 else f"{len(folders)} folders under {where}")
                 + ("  - still has Not Reviewed checks (folder name ends in _REVIEW_REQUIRED)" if review else ""))
        self.written_btn.configure(command=lambda: open_folder(where))
        if not self.written.winfo_manager():
            self.written.pack(fill="x", pady=(0, 4))
        head = [f"Written to:\n{where}", "",
                f"{len(files)} checklist file(s):"] + [f"   {f.parent.name if len(folders) > 1 else ''}"
                                                       f"{'/' if len(folders) > 1 else ''}{f.name}" for f in files]
        if review:
            head += ["", "Some checks are still Not Reviewed, so the folder name ends in _REVIEW_REQUIRED. Assess "
                         "them in STIG Viewer before submitting."]
        if messagebox.askyesno("Checklist package written", "\n".join(head) + "\n\nDetails:\n" + "\n".join(report)
                               + "\nOpen the folder now?", parent=self):
            open_folder(where)


# ---------------------------------------------------------------- 6. hardening script

class HardenTab(ttk.Frame):
    def __init__(self, nb, app):
        super().__init__(nb)
        self.app = app
        help_label(self, "Optional - build configuration scripts that FIX findings. Only fix commands that were "
                         "reviewed (Set up and rules > Fix commands) are used. Two scripts are always written "
                         "separately: LOW IMPACT (banners, logging, archive, timestamps, legacy services) and "
                         "IMPACTFUL (AAA, SSH, vty access, ports, STP, SNMP, routing). Fill in the <VALUES> listed at "
                         "the top of each script and test on one device before pushing with SolarWinds.")
        top = ttk.Frame(self)
        top.pack(fill="x", padx=6)
        ttk.Label(top, text="Group:").grid(row=0, column=0, sticky="w")
        self.group_var = tk.StringVar()
        self.group_box = ttk.Combobox(top, textvariable=self.group_var, state="readonly", width=28)
        self.group_box.grid(row=0, column=1, sticky="w", padx=4)
        self.mode = tk.StringVar(value="run")
        ttk.Radiobutton(top, text="From the current assessment run: one script pair per device, only the checks "
                                  "that are Open on that device (interfaces filled in automatically)",
                        variable=self.mode, value="run").grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 0))
        ttk.Radiobutton(top, text="Baseline for the whole group: every check that has fix commands "
                                  "(interfaces left as <INTERFACE> to fill in)",
                        variable=self.mode, value="baseline").grid(row=2, column=0, columnspan=3, sticky="w")
        b = ttk.Frame(top)
        b.grid(row=4, column=0, columnspan=3, sticky="w", pady=6)
        ttk.Button(b, text="Generate scripts", command=self.generate, style="Accent.TButton").pack(side="left")
        ttk.Button(b, text="Open hardening folder",
                   command=lambda: open_folder(store.paths.output / "hardening")).pack(side="left", padx=6)
        self.info = fit_text(ttk.Label(self, text="", foreground="#1b4f8a"))
        self.info.pack(fill="x", padx=8)
        pane = ttk.PanedWindow(self, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=6, pady=6)
        lf, self.files = make_tree(pane, [("file", "Script", 320), ("n", "Controls", 70)], height=12)
        pane.add(lf, weight=1)
        self.files.bind("<<TreeviewSelect>>", lambda e: self.preview_selected())
        self.preview = config_wrap(ScrolledText(pane, font=MONO))
        pane.add(self.preview, weight=3)
        PaneKeeper(pane, [0.25])
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
            return messagebox.showinfo("Hardening", "Create a device group first (Set up and rules > Device groups).")
        with busy(self):
            self._generate(gid, group)

    def _generate(self, gid, group):
        if self.mode.get() == "run":
            run = self.app.run
            if not run or gid not in run.get("results", {}):
                return messagebox.showinfo("Hardening", f"The current assessment run has no results for {gid}. "
                                                        "Import and review it on the Run an assessment tab, or "
                                                        "choose Baseline.")
            folder, written, skipped = harden.generate_from_run(run, gid, self.app.rules_db,
                                                                harden.site_values(self.app.settings))
        else:
            folder, written, skipped = harden.generate_baseline(group, self.app.rules_db, self.app.index,
                                                                values=harden.site_values(self.app.settings))
        not_reviewed = (f"   {len(skipped)} check(s) left out because their fix commands are not reviewed yet"
                        + (" (listed at the top of each script)" if written else "")
                        + ". Review them in Set up and rules > Fix commands." if skipped else "")
        self.files.delete(*self.files.get_children())
        self.paths = {}
        for path, n in written:
            iid = str(path)
            self.paths[iid] = path
            self.files.insert("", "end", iid=iid, values=(path.name, n))
        if not written:
            what = "checks" if self.mode.get() == "baseline" else "Open checks"
            self.info.configure(text=f"No scripts written: no {what} with reviewed fix commands." + not_reviewed)
            text_set(self.preview, "", readonly=True)
            return
        self.info.configure(text=f"{len(written)} script(s) written to {folder}." + not_reviewed)
        self.files.selection_set(self.files.get_children()[0])

    def preview_selected(self):
        sel = self.files.selection()
        if sel:
            text_set(self.preview, self.paths[sel[0]].read_text(encoding="utf-8"), readonly=True)
