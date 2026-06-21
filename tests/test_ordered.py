# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Antonio Huete Jimenez <tuxillo@quantumachine.net>
"""
Offline tests for the ordered (comment-tag) firewall engine, focused on the
``place_before`` insert feature plus regression coverage of the existing
ownership/idempotency guarantees.

Run:  python3 -m unittest discover -s tests -v
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import FakeDevice, load_engine  # noqa: E402

FILTER = ("ip", "firewall", "filter")
ADDRLIST = ("ip", "firewall", "address-list")


def dummy_input_chain():
    """A synthetic /ip/firewall/filter input chain (RFC5737 addresses).

    Three managed (tagged) rules ending in a 'drop !LAN' catch-all, one
    hand-written UNTAGGED rule (must stay invisible), and one dead tagged rule
    stranded *below* the catch-all drop (the cleanup target).
    """
    return [
        {"chain": "input", "action": "accept", "connection-state": "established,related",
         "comment": "accept established [salt:input-001]"},
        {"chain": "input", "action": "accept", "protocol": "icmp",
         "comment": "accept icmp [salt:input-002]"},
        {"chain": "input", "action": "drop", "in-interface-list": "!LAN",
         "comment": "drop not-LAN [salt:input-010]"},
        {"chain": "input", "action": "accept", "protocol": "tcp", "dst-port": "22",
         "comment": "hand-written, untagged"},           # invisible to engine
        {"chain": "input", "action": "accept", "protocol": "tcp", "dst-port": "443",
         "comment": "https DEAD below drop [salt:input-011]"},
    ]


def desired_mirror():
    """Desired pillar that exactly mirrors the three live tagged rules."""
    return [
        {"tag": "input-001", "chain": "input", "action": "accept",
         "connection-state": "established,related", "comment": "accept established"},
        {"tag": "input-002", "chain": "input", "action": "accept",
         "protocol": "icmp", "comment": "accept icmp"},
        {"tag": "input-010", "chain": "input", "action": "drop",
         "in-interface-list": "!LAN", "comment": "drop not-LAN"},
        {"tag": "input-011", "chain": "input", "action": "accept",
         "protocol": "tcp", "dst-port": "443", "comment": "https DEAD below drop"},
    ]


class OrderedBase(unittest.TestCase):
    def setUp(self):
        self.mik = load_engine()
        self.dev = FakeDevice().seed(FILTER, dummy_input_chain())
        self.mik.__proxy__ = self.dev.proxy()


class TestRegression(OrderedBase):
    """Existing guarantees must keep holding after the place_before change."""

    def test_mirror_is_zero_diff(self):
        ch = self.mik.manage(list(FILTER), desired_mirror(), test=True)
        self.assertEqual(ch["added"], [])
        self.assertEqual(ch["updated"], [])
        self.assertEqual(ch["removed"], [])

    def test_untagged_rule_is_invisible_even_under_purge(self):
        # purge=True, desired = all four tagged rules -> the untagged dst-port 22
        # rule must NOT be removed.
        ch = self.mik.manage(list(FILTER), desired_mirror(), purge=True, test=True)
        self.assertEqual(ch["removed"], [])

    def test_tag_helpers_roundtrip(self):
        rendered = self.mik._render_comment("free text", "input-007")
        self.assertEqual(rendered, "free text [salt:input-007]")
        self.assertEqual(self.mik._extract_tag(rendered), "input-007")
        self.assertEqual(self.mik._strip_tag(rendered), "free text")


class TestPlaceBefore(OrderedBase):

    def _new_rule(self, **over):
        rule = {"tag": "input-005", "chain": "input", "action": "accept",
                "protocol": "tcp", "dst-port": "10050", "src-address": "192.0.2.29",
                "comment": "zabbix agent", "place_before": "input-010"}
        rule.update(over)
        return rule

    def test_plan_records_anchor_id(self):
        ch = self.mik.manage(list(FILTER), [self._new_rule()], test=True)
        self.assertEqual(len(ch["added"]), 1)
        add = ch["added"][0]
        self.assertEqual(add["tag"], "input-005")
        self.assertEqual(add["place_before"], "input-010")
        # anchor .id resolved from the live row at plan time
        self.assertEqual(add["place_before_id"], self.dev.tables[FILTER][2][".id"])
        # the directive never leaks into the device write payload
        self.assertNotIn("place_before", add["entry"])
        self.assertNotIn("place-before", add["entry"])

    def test_apply_inserts_immediately_before_anchor(self):
        self.mik.manage(list(FILTER), [self._new_rule()], test=False)
        # input-005 lands between input-002 and the input-010 drop; untagged stays put
        self.assertEqual(self.dev.tags(FILTER),
                         ["input-001", "input-002", "input-005", "input-010", "input-011"])

    def test_insert_is_idempotent_and_never_moves(self):
        desired = desired_mirror() + [self._new_rule()]
        self.mik.manage(list(FILTER), desired, test=False)
        order_after_first = self.dev.tags(FILTER)
        # second run: rule now exists -> place_before ignored, zero changes, no move
        ch = self.mik.manage(list(FILTER), desired, test=True)
        self.assertEqual((ch["added"], ch["updated"], ch["removed"]), ([], [], []))
        self.assertEqual(self.dev.tags(FILTER), order_after_first)

    def test_stray_place_before_on_existing_rule_is_not_a_diff(self):
        # input-001 already exists; carrying a place_before must not fabricate an
        # update (it must be stripped before diffing).
        desired = [{"tag": "input-001", "chain": "input", "action": "accept",
                    "connection-state": "established,related",
                    "comment": "accept established", "place_before": "input-010"}]
        ch = self.mik.manage(list(FILTER), desired, test=True)
        self.assertEqual(ch["updated"], [])
        self.assertEqual(ch["added"], [])

    def test_two_new_rules_same_anchor_keep_pillar_order(self):
        a = self._new_rule(tag="input-004")
        b = self._new_rule(tag="input-006")
        self.mik.manage(list(FILTER), [a, b], test=False)
        order = self.dev.tags(FILTER)
        self.assertEqual(order.index("input-004") + 1, order.index("input-006"))
        self.assertEqual(order.index("input-006") + 1, order.index("input-010"))

    def test_missing_anchor_is_hard_error(self):
        with self.assertRaises(ValueError) as cm:
            self.mik.manage(list(FILTER), [self._new_rule(place_before="input-999")],
                            test=True)
        self.assertIn("place_before anchor", str(cm.exception))

    def test_place_after_is_rejected(self):
        rule = self._new_rule()
        rule.pop("place_before")
        rule["place_after"] = "input-002"
        with self.assertRaises(ValueError) as cm:
            self.mik.manage(list(FILTER), [rule], test=True)
        self.assertIn("place_after is not supported", str(cm.exception))

    def test_place_before_rejected_on_collection(self):
        dev = FakeDevice().seed(ADDRLIST, [])
        self.mik.__proxy__ = dev.proxy()
        bad = [{"list": "WAN", "address": "192.0.2.0/24", "place_before": "x"}]
        with self.assertRaises(ValueError) as cm:
            self.mik.manage(list(ADDRLIST), bad, test=True)
        self.assertIn("only supported on", str(cm.exception))


class TestRollbackSafety(OrderedBase):

    def test_inverse_script_for_insert_is_a_plain_remove(self):
        new = {"tag": "input-005", "chain": "input", "action": "accept",
               "protocol": "tcp", "dst-port": "10050", "comment": "zabbix",
               "place_before": "input-010"}
        _, schema = self.mik._schema(list(FILTER))
        changes = self.mik._plan_ordered(list(FILTER), schema, [new])
        script = self.mik._build_inverse_script(list(FILTER), schema, changes, "salt-rollback-test")
        # the undo of an insert is a position-independent remove-by-tag (brackets
        # are double-escaped for the RouterOS console-string layer by _ros_quote)...
        self.assertIn(r'remove [find comment~"\\[salt:input-005\\]"]', script)
        # ...and crucially never a `move` command or place-before (those can't be
        # rolled back). \bmove\b excludes the "move" inside "remove".
        self.assertIsNone(re.search(r"\bmove\b", script))
        self.assertNotIn("place-before", script)

    def test_commit_confirm_arms_inverse_then_inserts(self):
        new = {"tag": "input-005", "chain": "input", "action": "accept",
               "protocol": "tcp", "dst-port": "10050", "comment": "zabbix",
               "place_before": "input-010"}
        res = self.mik.commit_confirm(list(FILTER), [new], timeout_minutes=3,
                                      _skip_confirm=True)
        self.assertTrue(res["armed"])
        # rule actually inserted at the right slot
        self.assertEqual(self.dev.tags(FILTER),
                         ["input-001", "input-002", "input-005", "input-010", "input-011"])
        # the armed scheduler's revert script removes the inserted rule by tag
        sched = self.dev.tables[("system", "scheduler")][0]
        self.assertIn(r'remove [find comment~"\\[salt:input-005\\]"]', sched["on-event"])


class TestCleanupScenario(OrderedBase):
    """The real workflow: delete a dead rule AND insert a new one, in one apply."""

    def test_delete_dead_and_insert_new(self):
        # Desired = the three good rules (drop input-011, the dead https) + a new
        # rule placed before the catch-all drop. purge removes the now-absent
        # input-011; the untagged hand-written rule is untouched.
        desired = [
            {"tag": "input-001", "chain": "input", "action": "accept",
             "connection-state": "established,related", "comment": "accept established"},
            {"tag": "input-002", "chain": "input", "action": "accept",
             "protocol": "icmp", "comment": "accept icmp"},
            {"tag": "input-005", "chain": "input", "action": "accept", "protocol": "tcp",
             "dst-port": "10050", "src-address": "192.0.2.29", "comment": "zabbix agent",
             "place_before": "input-010"},
            {"tag": "input-010", "chain": "input", "action": "drop",
             "in-interface-list": "!LAN", "comment": "drop not-LAN"},
        ]
        ch = self.mik.manage(list(FILTER), desired, purge=True,
                             restrict={"chain": "input"}, test=False)
        self.assertEqual([r["tag"] for r in ch["removed"]], ["input-011"])
        self.assertEqual([a["tag"] for a in ch["added"]], ["input-005"])
        # final device order: dead rule gone, new rule slotted before the drop,
        # untagged hand-written rule preserved.
        self.assertEqual(self.dev.tags(FILTER),
                         ["input-001", "input-002", "input-005", "input-010"])
        self.assertIn("hand-written, untagged", self.dev.comments(FILTER))


if __name__ == "__main__":
    unittest.main()
