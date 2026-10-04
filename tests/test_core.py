"""Core tests. Run from the project root:  python -m unittest discover tests"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

import assess  # noqa: E402
import checklist  # noqa: E402
import collect  # noqa: E402
import rules  # noqa: E402
import store  # noqa: E402

FIX = HERE / "fixtures"
CKLB = FIX / "ios-xe-switch-ndm.cklb"
CKL = FIX / "ios-xe-switch-rtr.ckl"
# Tests that need the blank DISA checklists are skipped if tests/fixtures/ has not been filled in yet.
needs_fixtures = unittest.skipUnless(CKLB.exists() and CKL.exists(),
                                     "copy a blank IOS-XE Switch NDM .cklb and RTR .ckl into tests/fixtures/")

# Made-up SolarWinds "Execute Command Script" output (documentation IP ranges, lab hostnames).
_BAR = "_" * 76
_BODY = """! collection_profile_id: iosxe_ndm_pilot_v1
! source_ckl_family: NDM

! sources: V-220519,V-220521
! CMD: show run | section archive
show run | section archive
archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext

! sources: V-220524
! CMD: show running-config | include ^login block-for
show running-config | include ^login block-for
login block-for 900 attempts 3 within 120
"""
SW_TEXT = f"""{_BAR}

9/29/2026 8:22:14 AM : Started test CKL builder job

Execute Command Script on Devices
4 devices selected
{_BAR}

LAB-EC-router (192.0.2.97):

ERROR: Connection Refused by 192.0.2.97
{_BAR}

LAB-1A-ACCESS (192.0.2.33):

{_BODY}
{_BAR}

LAB-1C-ACCESS (192.0.2.35):

{_BODY}
{_BAR}

LAB-1D-ACCESS (2001:DB8::36):

{_BODY}
{_BAR}
9/29/2026 8:23:21 AM : Completed test CKL builder job
{_BAR}
"""


def sw_file(folder):
    path = Path(folder) / "solarwinds_output.txt"
    path.write_text(SW_TEXT, encoding="utf-8")
    return path
NDM = "Cisco_IOS_XE_Switch_NDM_STIG"
RTR = "Cisco_IOS_XE_Switch_RTR_STIG"

VTY = """line con 0
 exec-timeout 10 0
line vty 0 4
 exec-timeout 10 0
 transport input ssh
line vty 5 15
 exec-timeout 30 0
 transport input telnet ssh"""


def ok(text):
    return {"status": rules.classify_output(text), "text": text}


def cond(**kw):
    return {**rules.NEW_CONDITION, "command": "show run", **kw}


def rule(conds, mode="ALL", na=None, commands=("show run",)):
    r = {"commands": list(commands), "pass_logic": {"mode": mode, "conditions": conds}}
    if na:
        r["na_enabled"] = True
        r["na_logic"] = {"mode": "ALL", "conditions": na}
    return r


@needs_fixtures
class ChecklistTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_read_both_formats(self):
        b = checklist.read_checklist(CKLB)
        self.assertEqual(b["format"], "cklb")
        self.assertEqual(b["stigs"][0]["stig_id"], NDM)
        self.assertEqual(b["stigs"][0]["family"], "NDM")
        self.assertEqual(len(b["stigs"][0]["controls"]), 42)
        c = checklist.read_checklist(CKL)
        self.assertEqual(c["format"], "ckl")
        self.assertEqual(c["stigs"][0]["stig_id"], RTR)
        self.assertEqual(c["stigs"][0]["family"], "RTR")
        self.assertTrue(len(c["stigs"][0]["controls"]) > 0)
        self.assertTrue(all(x["vuln_id"].startswith("V-") for x in c["stigs"][0]["controls"]))

    def test_cklb_patch_and_validate(self):
        dst = self.tmp / "out.cklb"
        upd = {(NDM, "V-220518"): {"status": "open", "finding_details": "line1\nline2 <&> \u2026", "comments": "c"},
               (NDM, "V-220519"): {"status": "not_applicable", "finding_details": None, "comments": None}}
        checklist.write_patched(CKLB, dst, upd, title="GROUP_NDM")
        ok_, lines = checklist.validate(CKLB, dst)
        self.assertTrue(ok_, lines)
        data = json.loads(dst.read_text(encoding="utf-8"))
        r = {x["group_id"]: x for x in data["stigs"][0]["rules"]}
        self.assertEqual(r["V-220518"]["status"], "open")
        self.assertEqual(r["V-220518"]["finding_details"], "line1\nline2 <&> \u2026")
        self.assertEqual(r["V-220519"]["status"], "not_applicable")
        self.assertEqual(r["V-220519"]["finding_details"], "")
        self.assertEqual(data["title"], "GROUP_NDM")
        # tampering with a protected field is caught
        data["stigs"][0]["rules"][0]["check_content"] = "changed"
        dst.write_text(json.dumps(data), encoding="utf-8")
        ok_, lines = checklist.validate(CKLB, dst)
        self.assertFalse(ok_)
        self.assertTrue(any("check_content" in l for l in lines))

    def test_ckl_patch_and_validate(self):
        first = checklist.read_checklist(CKL)["stigs"][0]["controls"][0]["vuln_id"]
        dst = self.tmp / "out.ckl"
        # no updates -> byte-identical copy
        checklist.write_patched(CKL, dst, {})
        self.assertEqual(dst.read_bytes(), CKL.read_bytes())
        upd = {(RTR, first): {"status": "not_a_finding", "finding_details": "a < b & c", "comments": "ok"}}
        checklist.write_patched(CKL, dst, upd)
        ok_, lines = checklist.validate(CKL, dst)
        self.assertTrue(ok_, lines)
        again = checklist.read_checklist(dst)["stigs"][0]["controls"][0]
        self.assertEqual(again["template_status"], "not_a_finding")
        text = dst.read_text(encoding="utf-8")
        self.assertIn("<FINDING_DETAILS>a &lt; b &amp; c</FINDING_DETAILS>", text)
        self.assertTrue(text.startswith('<?xml version="1.0" encoding="UTF-8"?>\n<!--DISA STIG Viewer :: 2.10-->'))
        tampered = text.replace("<ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA>", "<ATTRIBUTE_DATA>low</ATTRIBUTE_DATA>", 1)
        dst.write_text(tampered, encoding="utf-8")
        self.assertFalse(checklist.validate(CKL, dst)[0])

    def test_unknown_control_rejected(self):
        with self.assertRaises(checklist.ChecklistError):
            checklist.write_patched(CKLB, self.tmp / "x.cklb", {(NDM, "V-0"): {"status": "open"}})


class RuleTests(unittest.TestCase):
    def test_has_and_lacks(self):
        out = {"show run": ok(VTY)}
        self.assertEqual(rules.evaluate(rule([cond(check="has", text="transport input ssh")]), out)["status"],
                         "not_a_finding")
        self.assertEqual(rules.evaluate(rule([cond(check="lacks", text="telnet")]), out)["status"], "open")

    def test_every_section(self):
        out = {"show run": ok(VTY)}
        r = rule([cond(scope="every", section="line vty", check="has", text="transport input ssh", how="whole line")])
        res = rules.evaluate(r, out)
        self.assertEqual(res["status"], "open")  # vty 5 15 has "telnet ssh", not a whole-line match
        self.assertEqual(res["marks"]["show run"][5], "problem")  # header of failing section
        self.assertEqual(res["marks"]["show run"][4], "match")
        r = rule([cond(scope="any", section="line vty", check="has", text="transport input ssh", how="whole line")])
        self.assertEqual(rules.evaluate(r, out)["status"], "not_a_finding")

    def test_number_in_section(self):
        out = {"show run": ok(VTY)}
        r = rule([cond(scope="every", section="line", check="number", text="exec-timeout", op="<=", value="10")])
        self.assertEqual(rules.evaluate(r, out)["status"], "open")
        r = rule([cond(scope="every", section="line", exclude="re:5 15", check="number", text="exec-timeout",
                       op="<=", value="10")])
        self.assertEqual(rules.evaluate(r, out)["status"], "not_a_finding")

    def test_count_and_pattern(self):
        out = {"show run": ok("ntp server 1.1.1.1\nntp server 2.2.2.2\n")}
        self.assertEqual(rules.evaluate(rule([cond(check="count", text="ntp server", op=">=", value="2")]),
                                        out)["status"], "not_a_finding")
        out = {"show run": ok(VTY)}
        r = rule([cond(check="pattern", text=r"line vty 0 4\n(\s.*\n)*?\s+transport input ssh")])
        self.assertEqual(rules.evaluate(r, out)["status"], "not_a_finding")
        r = rule([cond(check="no_pattern", text=r"transport input telnet")])
        self.assertEqual(rules.evaluate(r, out)["status"], "open")

    def test_not_applicable_first(self):
        out = {"show run": ok("no ip http server\n")}
        r = rule([cond(check="has", text="ip http max-connections")],
                 na=[cond(check="lacks", text="ip http secure-server")])
        self.assertEqual(rules.evaluate(r, out)["status"], "not_applicable")

    def test_missing_and_invalid_never_pass(self):
        r = rule([cond(check="lacks", text="telnet")])
        self.assertEqual(rules.evaluate(r, {})["status"], "not_reviewed")
        bad = {"show run": ok("        ^\n% Invalid input detected at '^' marker.")}
        self.assertEqual(rules.evaluate(r, bad)["status"], "not_reviewed")
        # empty output is real evidence: "lacks" passes
        self.assertEqual(rules.evaluate(r, {"show run": ok("")})["status"], "not_a_finding")

    def test_outcome_text_and_expected_open(self):
        r = rule([cond(check="has", text="x")])
        r["outcome_text"] = {"open": "Recommend risk acceptance on {devices} ({device_count}): vendor limit."}
        self.assertEqual(rules.outcome_text(r, "open", ["SW1", "SW2"]),
                         "Recommend risk acceptance on SW1, SW2 (2): vendor limit.")
        self.assertEqual(rules.outcome_text(r, "not_a_finding", ["SW1"]), "")
        r["expected_open"] = True
        r["outcome_text"] = {}
        self.assertTrue(any("intentional" in e for e in rules.activation_problems(r)))

    def test_activation_requires_tests(self):
        r = rule([cond(check="has", text="login block-for")])
        self.assertTrue(rules.activation_problems(r))
        r["tests"] = [{"name": "good", "expected": "not_a_finding", "outputs": {"show run": "login block-for 900"}},
                      {"name": "bad", "expected": "open", "outputs": {"show run": ""}}]
        self.assertEqual(rules.activation_problems(r), [])


class CollectTests(unittest.TestCase):
    @needs_fixtures
    def test_parse_sample(self):
        parsed = collect.parse_output(SW_TEXT)
        devs = {d["host"]: d for d in parsed["devices"]}
        self.assertEqual(len(devs), 4)
        self.assertEqual(devs["LAB-EC-router"]["status"], "error")
        self.assertIn("Connection Refused", devs["LAB-EC-router"]["error"])
        d = devs["LAB-1A-ACCESS"]
        self.assertEqual(d["ip"], "192.0.2.33")
        self.assertEqual(devs["LAB-1D-ACCESS"]["ip"], "2001:DB8::36")
        self.assertEqual(set(d["outputs"]), {"show run | section archive",
                                             "show running-config | include ^login block-for"})
        self.assertEqual(d["outputs"]["show running-config | include ^login block-for"]["text"],
                         "login block-for 900 attempts 3 within 120")
        self.assertTrue(d["outputs"]["show run | section archive"]["text"].startswith("archive\n log config"))

    def test_script_round_trip(self):
        text, sid = collect.build_script({"show version": {"NDM V-1"}, "show clock": {"NDM V-2"}}, ["G"])
        self.assertIn("! CMD: show clock", text)
        body = text.replace("\nshow clock\n", "\nshow clock\n12:00 UTC\n", 1)  # device echo, then output
        fake = f"{'_' * 60}\nSW1 (10.0.0.1):\n\n{body}\n{'_' * 60}\n"
        parsed = collect.parse_output(fake)
        dev = parsed["devices"][0]
        self.assertEqual(dev["script_id"], sid)
        self.assertEqual(dev["outputs"]["show clock"]["text"], "12:00 UTC")

    def test_fallback_without_markers(self):
        text = f"{'_' * 40}\nSW1 (1.1.1.1):\nSW1#show clock\n12:00\nSW1#show version\nCisco IOS XE\n{'_' * 40}"
        dev = collect.parse_output(text, {"show clock", "show version"})["devices"][0]
        self.assertEqual(dev["outputs"]["show clock"]["text"], "12:00")
        self.assertEqual(dev["outputs"]["show version"]["text"], "Cisco IOS XE")


class StoreCase(unittest.TestCase):
    """Runs against a throwaway project folder."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.old = store.paths
        store.use_root(self.tmp)

    def tearDown(self):
        store.paths = self.old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_release(self, name, release, check_change=None, add=None, drop=None):
        """Copy the NDM CKLB fixture as another DISA release with optional control changes."""
        data = json.loads(CKLB.read_text(encoding="utf-8"))
        stig = data["stigs"][0]
        stig["release_info"] = f"Release: {release} Benchmark Date: 01 Jul 2026"
        rules_ = stig["rules"]
        if check_change:
            next(r for r in rules_ if r["group_id"] == check_change)["check_content"] += "\nNEW SENTENCE."
        if add:
            extra = json.loads(json.dumps(rules_[-1]))
            extra["group_id"] = add
            rules_.append(extra)
        if drop:
            stig["rules"] = [r for r in rules_ if r["group_id"] != drop]
        path = self.tmp / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path


def active_rule(index, stig_id, vuln_id, command, cond_, rid, tests=None, comment=""):
    return {"id": rid, "stig_id": stig_id, "vuln_id": vuln_id, "name": "Default", "state": "active",
            "is_default": True, "version": 1, "commands": [command], "comment": comment,
            "check_hash": index[stig_id]["controls"][vuln_id]["check_hash"],
            "pass_logic": {"mode": "ALL", "conditions": [{**rules.NEW_CONDITION, "command": command, **cond_}]},
            "tests": tests or []}


class TeamStoreTests(StoreCase):
    def test_migrates_first_version_data(self):
        (store.paths.data / "rules.json").write_text(json.dumps(
            {"next_id": 2, "rules": [{"id": "R-0001", "stig_id": NDM, "vuln_id": "V-1", "commands": []}],
             "manual_controls": [f"{NDM}|V-2"]}), encoding="utf-8")
        (store.paths.data / "groups.json").write_text(json.dumps(
            {"groups": [{"id": "G1", "stigs": [NDM]}], "device_overrides": {"sw1": "G1"},
             "known_devices": {"SW1": "1.1.1.1"}}), encoding="utf-8")
        store.ensure_folders()
        self.assertEqual([r["id"] for r in store.load_rules()["rules"]], ["R-0001"])
        self.assertEqual(store.load_rules()["manual_controls"], [f"{NDM}|V-2"])
        g = store.load_groups()
        self.assertEqual(g["groups"][0]["id"], "G1")
        self.assertEqual(g["device_overrides"], {"SW1": "G1"})
        self.assertFalse((store.paths.data / "rules.json").exists())
        self.assertTrue(list(store.paths.data.glob("rules.json.migrated-*")))

    def test_conflicting_saves_are_caught(self):
        rule = store.save_rule({"id": store.new_rule_id(), "name": "a"}, check=False)
        mine = json.loads(json.dumps(rule))
        theirs = json.loads(json.dumps(rule))
        theirs["name"] = "theirs"
        store.save_rule(theirs)
        mine["name"] = "mine"
        with self.assertRaises(store.ConflictError) as ctx:
            store.save_rule(mine)
        self.assertEqual(ctx.exception.current["name"], "theirs")

    def test_settings_updates_do_not_clobber(self):
        store.set_override("sw1", "G1")
        store.set_manual(f"{NDM}|V-1", True)
        store.add_known_devices({"sw2": "2.2.2.2"})
        s = store.load_settings()
        self.assertEqual(s["device_overrides"], {"SW1": "G1"})
        self.assertEqual(s["manual_controls"], [f"{NDM}|V-1"])
        self.assertEqual(s["known_devices"], {"SW2": "2.2.2.2"})

    def test_locks(self):
        self.assertIsNone(store.acquire_lock("rule", "R-1"))
        store.save_json(store.paths.locks / "rule_R-1.lock",
                        {"user": "someone-else", "host": "PC9", "since": store.now()})
        holder = store.acquire_lock("rule", "R-1")
        self.assertEqual(holder["user"], "someone-else")
        self.assertIsNone(store.acquire_lock("rule", "R-1", force=True))
        store.release_lock("rule", "R-1")
        self.assertFalse((store.paths.locks / "rule_R-1.lock").exists())


@needs_fixtures
class ReleaseTests(StoreCase):
    def test_new_release_flags_rules_and_diffs(self):
        store.import_template(CKLB)
        index = store.control_index()
        store.save_rule(active_rule(index, NDM, "V-220524", "show run", {"check": "has", "text": "login"}, "R-A"),
                        check=False)
        store.save_rule(active_rule(index, NDM, "V-220518", "show run", {"check": "has", "text": "x"}, "R-B"),
                        check=False)
        newer = self.make_release("ndm_r7.cklb", 7, check_change="V-220524", add="V-999999", drop="V-220518")
        cat, report = store.import_template(newer)
        text = "\n".join(report)
        self.assertIn("NEW RELEASE (was V3R6", text)
        self.assertIn("1 added, 1 removed, 1 changed", text)
        self.assertIn("V-220524 (R-A)", text)
        self.assertIn("V-220518 (R-B)", text)
        index = store.control_index()
        self.assertEqual(index[NDM]["release"], "V3R7 (01 Jul 2026)")
        rules_db = store.load_rules()
        state = assess.control_state(rules_db, NDM, index[NDM]["controls"]["V-220524"])
        self.assertEqual(state, "STIG changed - review")
        old_rel, old_ctrl = store.find_control_version(NDM, "V-220524", store.rule_path and
                                                       rules_db["rules"][0]["check_hash"])
        self.assertTrue(old_rel.startswith("V3R6"))
        # mark reviewed clears the flag
        store.mark_rule_reviewed("R-A", index[NDM]["controls"]["V-220524"]["check_hash"], index[NDM]["release"])
        rules_db = store.load_rules()
        self.assertEqual(assess.control_state(rules_db, NDM, index[NDM]["controls"]["V-220524"]), "Active")
        self.assertEqual(rules_db["rules"][0]["review_log"][0]["release"], "V3R7 (01 Jul 2026)")

    def test_duplicate_and_older_imports(self):
        store.import_template(self.make_release("r7.cklb", 7))
        cat, report = store.import_template(self.make_release("r7.cklb", 7))
        self.assertIsNone(cat)
        self.assertIn("already imported", report[0])
        cat, report = store.import_template(CKLB)  # release 6 after release 7
        self.assertIn("OLDER", report[0])
        self.assertEqual(store.control_index()[NDM]["release"], "V3R7 (01 Jul 2026)")

    def test_compare_controls(self):
        old = checklist.read_checklist(CKLB)["stigs"][0]["controls"]
        new = checklist.read_checklist(self.make_release("n.cklb", 7, check_change="V-220519"))["stigs"][0][
            "controls"]
        diffs = checklist.compare_controls(old, new)
        self.assertEqual([(d["vuln_id"], d["kind"], d["fields"]) for d in diffs], [("V-220519", "changed", ["check"])])
        self.assertLess(checklist.release_key("3", "Release: 6 Benchmark Date: 01 Apr 2026"),
                        checklist.release_key("3", "Release: 10 Benchmark Date: 01 Jan 2027"))


@needs_fixtures
class EndToEndTests(StoreCase):
    def setup_project(self):
        store.import_template(CKLB)
        store.import_template(CKL)
        index = store.control_index()
        self.rtr_first = index[RTR]["order"][0]
        self.cmd = "show running-config | include ^login block-for"
        store.save_rule(active_rule(index, NDM, "V-220524", self.cmd,
                                    {"check": "number", "text": "attempts", "op": "<=", "value": "3"},
                                    "R-0001", comment="Checked login block-for."), check=False)
        rtr = active_rule(index, RTR, self.rtr_first, "show ip route", {"check": "has", "text": "via"}, "R-0002")
        store.save_rule(rtr, check=False)
        # an intentional finding: Open on purpose with a risk-acceptance reason
        login = active_rule(index, NDM, "V-220519", self.cmd, {"check": "has", "text": "never-present"}, "R-0003")
        login.update(expected_open=True,
                     outcome_text={"open": "Recommend risk acceptance for {devices}: platform cannot do this."})
        store.save_rule(login, check=False)
        store.set_manual(f"{NDM}|V-220518", True)
        store.save_group({"id": "CAMPUS-ACCESS", "patterns": ["*-ACCESS"], "stigs": [NDM, RTR],
                          "rule_choices": {}}, check=False)
        store.save_group({"id": "CAMPUS-HANGOFF", "patterns": [], "stigs": [NDM], "rule_choices": {}}, check=False)
        store.set_override("LAB-1D-ACCESS", "CAMPUS-HANGOFF")
        return index, store.load_rules(), store.load_groups()

    def test_full_workflow(self):
        index, rules_db, groups_db = self.setup_project()
        cmds = assess.commands_for_groups(groups_db["groups"], rules_db, index)
        self.assertEqual(set(cmds), {self.cmd, "show ip route"})
        self.assertIn("Cisco IOS XE Switch NDM V-220524", cmds[self.cmd])

        cov = {r["short"]: r for r in assess.coverage(groups_db["groups"][0], rules_db, index)}
        ndm = cov["Cisco IOS XE Switch NDM"]
        self.assertEqual((ndm["total"], ndm["automated"], ndm["manual"], ndm["no_rule"]), (42, 2, 1, 39))
        self.assertEqual(cov["Cisco IOS XE Switch RTR"]["automated"], 1)

        run = assess.import_solarwinds(sw_file(self.tmp), groups_db, rules_db)
        self.assertEqual(run["membership"]["LAB-1D-ACCESS"]["group"], "CAMPUS-HANGOFF")
        self.assertEqual(run["membership"]["LAB-EC-router"]["group"], "")
        assess.evaluate_run(run, groups_db, rules_db, index)
        acc = run["results"]["CAMPUS-ACCESS"]["controls"]
        self.assertEqual(acc[f"{NDM}|V-220524"]["recommended"], "not_a_finding")
        self.assertEqual(acc[f"{RTR}|{self.rtr_first}"]["recommended"], "not_reviewed")
        self.assertIsNone(acc[f"{NDM}|V-220518"]["recommended"])
        self.assertNotIn(f"{RTR}|{self.rtr_first}", run["results"]["CAMPUS-HANGOFF"]["controls"])

        acc[f"{RTR}|{self.rtr_first}"].update(final="not_applicable", reviewer_changed=True,
                                              reviewer_comment="No routing on this group.")
        assess.evaluate_run(run, groups_db, rules_db, index)
        self.assertEqual(run["results"]["CAMPUS-ACCESS"]["controls"][f"{RTR}|{self.rtr_first}"]["final"],
                         "not_applicable")

        # Team output format = CKL: only .ckl files, and NDM (imported only as CKLB) is reported missing.
        folder, ok_, msgs = assess.write_package(run, "CAMPUS-ACCESS", "tester", groups_db, rules_db, "ckl")
        names = {p.name for p in folder.iterdir()}
        self.assertIn("CAMPUS-ACCESS_Cisco_IOS_XE_Switch_RTR.ckl", names)
        self.assertFalse(any(n.endswith(".cklb") for n in names))
        self.assertFalse(ok_)
        self.assertTrue(any("NO STIG Viewer 2.x (.ckl) TEMPLATE" in m for m in msgs))
        summary = (folder / "group_assessment_summary.txt").read_text(encoding="utf-8")
        self.assertIn("Rule coverage per STIG", summary)
        self.assertRegex(summary, r"Cisco IOS XE Switch NDM\s+V3R6 \(01 Apr 2026\)\s+42\s+2\s+1\s+39")
        rtr = checklist.read_checklist(folder / "CAMPUS-ACCESS_Cisco_IOS_XE_Switch_RTR.ckl")["stigs"][0]
        self.assertEqual(rtr["controls"][0]["template_status"], "not_applicable")

        # Team output format = CKLB: only the NDM .cklb exists in that format.
        folder, ok_, msgs = assess.write_package(run, "CAMPUS-ACCESS", "tester", groups_db, rules_db, "cklb")
        names = {p.name for p in folder.iterdir()}
        self.assertIn("CAMPUS-ACCESS_Cisco_IOS_XE_Switch_NDM.cklb", names)
        self.assertFalse(any(n.endswith(".ckl") for n in names))
        out = json.loads((folder / "CAMPUS-ACCESS_Cisco_IOS_XE_Switch_NDM.cklb").read_text(encoding="utf-8"))
        r = {x["group_id"]: x for x in out["stigs"][0]["rules"]}
        self.assertEqual(r["V-220524"]["status"], "not_a_finding")
        # Team guidance: Not a Finding -> reason in Comments, Finding Details left as the template has it.
        self.assertEqual(r["V-220524"]["finding_details"], "")
        self.assertIn("LAB-1A-ACCESS", r["V-220524"]["comments"])
        self.assertTrue(r["V-220524"]["comments"].rstrip().endswith("Checked login block-for."))
        self.assertIn("REVIEW_REQUIRED", folder.name)
        self.assertEqual(r["V-220519"]["status"], "open")
        self.assertTrue(r["V-220519"]["finding_details"].startswith(
            "Recommend risk acceptance for LAB-1A-ACCESS, LAB-1C-ACCESS: platform cannot do this."))
        self.assertIn("Final determination by tester", r["V-220519"]["finding_details"])
        # same run, team switched Not a Finding to Finding Details
        c = run["results"]["CAMPUS-ACCESS"]["controls"][f"{NDM}|V-220524"]
        custom = assess.checklist_text(c, {**store.DEFAULT_PLACEMENT, "not_a_finding": "finding_details"}, "x")
        self.assertIn("LAB-1A-ACCESS", custom["finding_details"])
        self.assertEqual(custom["comments"], "Checked login block-for.")
        exc = (folder / "exceptions_and_review_required.txt").read_text(encoding="utf-8")
        self.assertIn("Expected (intentional) findings", exc)
        self.assertIn("Open (expected)", (folder / "group_assessment_summary.txt").read_text(encoding="utf-8"))

        folder2, _, _ = assess.write_package(run, "CAMPUS-HANGOFF", "tester", groups_db, rules_db, "cklb")
        self.assertFalse(any("RTR" in p.name for p in folder2.iterdir()))

if __name__ == "__main__":
    unittest.main()
