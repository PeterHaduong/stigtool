"""The AI handoff: the prompt is complete and safe, and answers are read back strictly."""
import json
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.path.insert(0, str(HERE))

import llm_handoff as h  # noqa: E402
import platform_samples as ps  # noqa: E402
import rules  # noqa: E402

CONTROL = {"vuln_id": "V-1", "rule_ver": "CISC-L2-000020", "severity": "high", "title": "802.1x",
           "check": "Verify 802.1x.", "fix": "Configure 802.1x."}


class PromptTests(unittest.TestCase):
    def test_secrets_are_masked_but_config_is_kept(self):
        text = h.redact("enable secret 9 $9$abc\nusername a privilege 15 secret 9 $9$def\n"
                        "tacacs-server host 10.1.1.1 key 7 \"xyz\"\nkey chain OSPF_KEY\n key 1\n  key-string 7 0822\n"
                        "snmp-server community public RO\nno password strength-check\n"
                        "snmp-server user U G v3 auth sha AUTHPW priv aes 256 PRIVPW\n")
        for secret in ("$9$abc", "$9$def", "xyz", "0822", "public", "AUTHPW", "PRIVPW"):
            self.assertNotIn(secret, text)
        for kept in ("key chain OSPF_KEY", " key 1\n", "no password strength-check"):
            self.assertIn(kept, text)

    def test_prompt_has_reference_roles_examples_and_masked_sample(self):
        p = h.build_prompt(CONTROL, {"commands": ["show running-config"]}, "Catalyst 9300", goal="dot1x or parked",
                           samples={"show running-config": ps.CONFIGS["CAT9300_HARDENED"]})
        for part in ("role:trusted", "dot1x or parked", '"no_pattern"', "<MASKED>", h.FORMAT):
            self.assertIn(part, p)
        self.assertNotIn("$9$", p)
        # every worked example in the prompt reads back with no problems
        for block in re.findall(r"```json\n(.*?)\n```", p, re.S)[:3]:
            answer, problems = h.parse_answer(block)
            self.assertEqual(problems, [])
            self.assertTrue(answer["pass_conditions"])


class AnswerTests(unittest.TestCase):
    def test_answer_in_chatty_text_with_lists_and_numbers(self):
        reply = "Here you go:\n```json\n" + json.dumps({
            "commands": [], "pass_mode": "any",
            "pass_conditions": [{"command": "show running-config", "scope": "every", "section": "line vty",
                                 "exclude": ["transport input none", "re:^\s*shutdown"], "check": "number",
                                 "text": "exec-timeout", "op": "<=", "value": 10, "colour": "red"}],
            "tests": [{"name": "good", "expected": "not_a_finding", "outputs": {"show running-config": "x"}},
                      {"name": "broken", "expected": "maybe"}]}) + "\n```\nThanks!"
        answer, problems = h.parse_answer(reply)
        c = answer["pass_conditions"][0]
        self.assertEqual(answer["commands"], ["show running-config"])  # added from the condition
        self.assertEqual(answer["pass_mode"], "ANY")
        self.assertEqual(c["exclude"], "transport input none\nre:^\s*shutdown")
        self.assertEqual(c["value"], "10")
        self.assertEqual([t["name"] for t in answer["tests"]], ["good"])
        self.assertTrue(any("colour" in p for p in problems))
        self.assertTrue(any("AI test 2" in p for p in problems))
        self.assertFalse(any("not in the rule's command list" in p for p in problems))

    def test_bad_answers_are_refused_or_flagged(self):
        with self.assertRaises(ValueError):
            h.parse_answer("I cannot help with that.")
        with self.assertRaises(ValueError):
            h.parse_answer('{"pass_conditions": []}')
        _, problems = h.parse_answer(json.dumps({"commands": ["show run"], "pass_conditions": [
            {"command": "show run", "check": "has", "how": "regex", "text": "(unclosed"},
            {"command": "show run", "scope": "every", "section": "interface", "exclude": ["role:nosuchrole"],
             "check": "has", "text": "x"}]}))
        self.assertTrue(any("pattern error" in p for p in problems))
        self.assertTrue(any("unknown port role" in p for p in problems))

    def test_rule_round_trip(self):
        rule = {"commands": ["show running-config"], "pass_logic": {"mode": "ALL", "conditions": [
            {**rules.NEW_CONDITION, "command": "show running-config", "scope": "every", "section": "interface",
             "exclude": "role:uplink\nshutdown", "check": "has", "text": "x"}]}}
        answer, problems = h.parse_answer(json.dumps(h.answer_for_rule(rule)))
        self.assertEqual(problems, [])
        self.assertEqual(answer["pass_conditions"], rule["pass_logic"]["conditions"])


if __name__ == "__main__":
    unittest.main()
