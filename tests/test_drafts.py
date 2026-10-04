"""Checks the starter draft library against representative Catalyst 9300 / 8300 and Nexus 9000 output."""
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.path.insert(0, str(HERE))

import drafts  # noqa: E402
import harden  # noqa: E402
import platform_samples as ps  # noqa: E402
import rules  # noqa: E402

DEVICE = {"IOSXE_SW": "CAT9300", "IOSXE_RTR": "CAT8300", "NXOS": "N9K"}
# Hardened samples deliberately leave these unconfigured (data-center leaf without 802.1x / SPAN / QoS).
EXPECTED_OPEN_HARDENED = {"IOSXE_SW": set(), "IOSXE_RTR": set(),
                          "NXOS": {"CISC-L2-000020", "CISC-L2-000080", "CISC-L2-000060", "CISC-L2-000070",
                                   "CISC-RT-000140", "CISC-RT-000780"}}


def results(platform, variant):
    out = {}
    evidence = ps.outputs(f"{DEVICE[platform]}_{variant}")
    for ver, spec in drafts.LIBRARY[platform].items():
        if "manual" in spec or (platform == "IOSXE_RTR" and ver.startswith("CISC-L2")):
            continue
        rule = drafts.build_rule(spec, platform, "TEST_STIG", {"vuln_id": ver, "rule_ver": ver, "check_hash": ""})
        out[ver] = rules.evaluate(rule, evidence)["status"]
    return out


class DraftLibraryTests(unittest.TestCase):
    def test_every_condition_is_valid(self):
        self.assertEqual(drafts.problems_in_library(), [])

    def test_platform_detection(self):
        self.assertEqual(drafts.platform_of("Cisco_IOS_XE_Switch_NDM_STIG"), "IOSXE_SW")
        self.assertEqual(drafts.platform_of("Cisco_IOS-XE_Router_RTR_STIG"), "IOSXE_RTR")
        self.assertEqual(drafts.platform_of("Cisco_NX-OS_Switch_L2S_STIG"), "NXOS")
        self.assertIsNone(drafts.platform_of("Juniper_SRX_STIG"))

    def test_hardened_devices_pass(self):
        for platform in DEVICE:
            res = results(platform, "HARDENED")
            self.assertNotIn("not_reviewed", res.values(), platform)
            opened = {v for v, s in res.items() if s == "open"}
            self.assertEqual(opened, EXPECTED_OPEN_HARDENED[platform], platform)

    def test_factory_defaults_are_caught(self):
        for platform, minimum in (("IOSXE_SW", 55), ("IOSXE_RTR", 35), ("NXOS", 50)):
            res = results(platform, "DEFAULT")
            self.assertNotIn("not_reviewed", res.values(), platform)
            self.assertGreaterEqual(sum(1 for s in res.values() if s == "open"), minimum, platform)

    def test_platform_specific_cdp(self):
        # CDP: Catalyst 9300 is on by default (needs 'no cdp run'); the 8300 router is off by default.
        self.assertEqual(results("IOSXE_SW", "DEFAULT")["CISC-RT-000370"], "open")
        self.assertEqual(results("IOSXE_RTR", "DEFAULT")["CISC-RT-000370"], "not_a_finding")


class HardeningTests(unittest.TestCase):
    def test_every_draft_has_a_fix_or_is_verification_only(self):
        for platform, lib in drafts.LIBRARY.items():
            for ver, spec in lib.items():
                if "manual" in spec or (platform == "IOSXE_RTR" and ver.startswith("CISC-L2")):
                    continue
                self.assertTrue(harden.has_fix({"fix": harden.starter_fix(platform, ver)}), f"{platform} {ver}")

    def test_fix_text_is_paste_safe(self):
        for platform, lib in harden.FIX_LIBRARY.items():
            for ver, fix in lib.items():
                for impact in ("low", "high"):
                    self.assertTrue((fix[impact] or "").isascii(), f"{platform} {ver}")

    def test_each_failing_section_expands_per_interface(self):
        fix = "! comment\n{each failing section}\n storm-control broadcast level 1.00\nspanning-tree loopguard default"
        out = harden.render(fix, ["interface Gi1/0/5", "interface Gi1/0/7"], "interface <INTERFACE>")
        self.assertEqual(out, ["! comment", "interface Gi1/0/5", " storm-control broadcast level 1.00", "exit",
                               "interface Gi1/0/7", " storm-control broadcast level 1.00", "exit",
                               "spanning-tree loopguard default"])
        out = harden.render(fix, [], "interface <INTERFACE>")
        self.assertIn("interface <INTERFACE>", out)

    def test_failing_sections_come_from_the_engine(self):
        spec = drafts.LIBRARY["IOSXE_SW"]["CISC-L2-000160"]
        rule = drafts.build_rule(spec, "IOSXE_SW", "X", {"vuln_id": "V-1", "rule_ver": "CISC-L2-000160",
                                                        "check_hash": ""})
        cfg = ("interface GigabitEthernet1/0/1\n description ACCESS - PC\n switchport mode access\n"
               " storm-control broadcast level 1.00\n!\ninterface GigabitEthernet1/0/2\n description ACCESS - PC\n"
               " switchport mode access\n!\ninterface TenGigabitEthernet1/1/1\n description UPLINK - DIST\n")
        res = rules.evaluate(rule, {"show running-config": {"status": "ok", "text": cfg}})
        self.assertEqual(res["status"], "open")
        self.assertEqual(res["failed_sections"], ["interface GigabitEthernet1/0/2"])

    def test_unlabelled_switch_fails_access_checks(self):
        # factory config has no role labels: access checks must not quietly pass
        res = results("IOSXE_SW", "DEFAULT")
        for ver in ("CISC-L2-000020", "CISC-L2-000120", "CISC-L2-000160", "CISC-L2-000250"):
            self.assertEqual(res[ver], "open", ver)

    def test_trust_added_on_uplinks_and_removed_elsewhere(self):
        spec = drafts.LIBRARY["IOSXE_SW"]["CISC-L2-000130"]
        rule = drafts.build_rule(spec, "IOSXE_SW", "X", {"vuln_id": "V-1", "rule_ver": "CISC-L2-000130",
                                                        "check_hash": ""})
        cfg = ("ip dhcp snooping vlan 10\nip dhcp snooping\n!\ninterface TenGigabitEthernet1/1/3\n"
               " description uplink - dist-02\n switchport mode trunk\n!\ninterface GigabitEthernet1/0/48\n"
               " description ACCESS - PRINTER\n ip dhcp snooping trust\n")
        res = rules.evaluate(rule, {"show running-config": {"status": "ok", "text": cfg}})
        self.assertEqual(res["status"], "open")
        cmds = harden.render(rule["fix"]["high"], res["failed_sections"], "interface <INTERFACE>",
                             res["failed_by_condition"], rule, have_results=True)
        text = "\n".join(cmds)
        self.assertIn("interface TenGigabitEthernet1/1/3\n ip dhcp snooping trust", text)
        self.assertIn("interface GigabitEthernet1/0/48\n no ip dhcp snooping trust", text)
        self.assertNotIn("interface GigabitEthernet1/0/48\n ip dhcp snooping trust", text)


if __name__ == "__main__":
    unittest.main()
