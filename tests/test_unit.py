#!/usr/bin/env python3
"""Unit tests that do not need Wazuh: logtest output parser and ossec.conf editing.

    python3 -m unittest discover -s tests -p 'test_*.py' -v
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "lib"))

import ossec_remote  # noqa: E402
import run_logtest  # noqa: E402

FIXTURE_CONF = os.path.join(HERE, "fixtures", "ossec.conf.sample")
KSC_IP, LISTEN_IP = "192.0.2.5", "192.0.2.7"


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class ParserTest(unittest.TestCase):
    def setUp(self):
        self.results = run_logtest.parse_output(read(os.path.join(HERE, "fixtures", "logtest_output_sample.txt")))

    def test_event_count(self):
        self.assertEqual(len(self.results), 3)

    def test_malware_event(self):
        r = self.results[0]
        self.assertEqual(r["decoder"], "kaspersky-ksc")
        self.assertEqual(r["rule_id"], "100701")
        self.assertEqual(r["level"], 10)
        self.assertTrue(r["alert"])
        self.assertEqual(r["fields"]["ksc.host"], "PC-TEST01")
        self.assertEqual(r["fields"]["ksc.user"], "EXAMPLE\\\\testuser")
        self.assertEqual(r["fields"]["ksc.event_name"], "Обнаружен вредоносный объект")

    def test_low_level_event_has_no_alert(self):
        r = self.results[1]
        self.assertEqual((r["rule_id"], r["level"], r["alert"]), ("100702", 3, False))

    def test_no_decoder(self):
        r = self.results[2]
        self.assertIsNone(r["decoder"])
        self.assertIsNone(r["rule_id"])
        self.assertNotIn("hostname", r["fields"])  # phase 1 keys must not leak into decoder fields

    def test_check(self):
        self.assertEqual(run_logtest.check(self.results[0], {"rule_id": "100701", "level": 10}), [])
        self.assertTrue(run_logtest.check(self.results[0], {"rule_id": "100709"}))
        self.assertEqual(run_logtest.check(self.results[2], {"decoder_not": "kaspersky-ksc"}), [])


class OssecRemoteTest(unittest.TestCase):
    def setUp(self):
        self.text = read(FIXTURE_CONF)

    def test_conflict_detected(self):
        found = ossec_remote.conflicts(self.text, 514, "tcp")
        self.assertEqual(len(found), 1)
        self.assertEqual(ossec_remote.conflicts(self.text, 514, "udp"), [])

    def test_render_refuses_without_adopt(self):
        new, found = ossec_remote.render(self.text, 514, "tcp", KSC_IP, LISTEN_IP, adopt=False)
        self.assertIsNone(new)
        self.assertEqual(len(found), 1)

    def test_adopt_replaces_unmanaged_block(self):
        new, _ = ossec_remote.render(self.text, 514, "tcp", KSC_IP, LISTEN_IP, adopt=True)
        self.assertEqual(new.count("<connection>syslog</connection>"), 1)
        self.assertEqual(new.count(ossec_remote.BEGIN), 1)
        self.assertNotIn("KSC: export of events", new)          # adopted comment removed
        self.assertIn("<!-- Policy monitoring -->", new)        # unrelated comment kept
        self.assertIn("<port>1514</port>", new)                 # agents block kept
        self.assertEqual(ossec_remote.conflicts(new, 514, "tcp"), [])

    def test_idempotent(self):
        once, _ = ossec_remote.render(self.text, 514, "tcp", KSC_IP, LISTEN_IP, adopt=True)
        twice, found = ossec_remote.render(once, 514, "tcp", KSC_IP, LISTEN_IP, adopt=False)
        self.assertEqual(found, [])
        self.assertEqual(once, twice)

    def test_update_changes_only_managed_block(self):
        once, _ = ossec_remote.render(self.text, 514, "tcp", KSC_IP, LISTEN_IP, adopt=True)
        changed, _ = ossec_remote.render(once, 514, "tcp", "192.0.2.6", LISTEN_IP, adopt=False)
        self.assertIn("<allowed-ips>192.0.2.6/32</allowed-ips>", changed)
        self.assertEqual(changed.count(ossec_remote.BEGIN), 1)

    def test_remove_restores_clean_config(self):
        base = self.text.replace(ossec_remote.conflicts(self.text, 514, "tcp")[0]["text"], "")
        once, _ = ossec_remote.render(self.text, 514, "tcp", KSC_IP, LISTEN_IP, adopt=True)
        removed, existed = ossec_remote.remove(once)
        self.assertTrue(existed)
        self.assertNotIn(ossec_remote.BEGIN, removed)
        self.assertNotIn("<connection>syslog</connection>", removed)
        self.assertIn("<port>1514</port>", removed)
        self.assertNotIn("<connection>syslog</connection>", base)

    def test_insert_without_existing_remote(self):
        text = "<ossec_config>\n  <global/>\n</ossec_config>\n"
        new, _ = ossec_remote.render(text, 514, "tcp", KSC_IP, LISTEN_IP, adopt=False)
        self.assertLess(new.index(ossec_remote.BEGIN), new.index("</ossec_config>"))

    def test_cli_exit_code_on_conflict(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "new.conf")
            cmd = [sys.executable, os.path.join(ROOT, "lib", "ossec_remote.py"), "render", "--conf", FIXTURE_CONF,
                   "--port", "514", "--proto", "tcp", "--ksc-ip", KSC_IP, "--listen-ip", LISTEN_IP, "--out", out]
            self.assertEqual(subprocess.run(cmd, stderr=subprocess.DEVNULL).returncode, 3)
            self.assertEqual(subprocess.run(cmd + ["--adopt"]).returncode, 0)
            insp = subprocess.run([sys.executable, os.path.join(ROOT, "lib", "ossec_remote.py"), "inspect",
                                   "--conf", out, "--port", "514", "--proto", "tcp"],
                                  stdout=subprocess.PIPE, universal_newlines=True)
            state = json.loads(insp.stdout)
            self.assertTrue(state["managed"])
            self.assertEqual(state["conflicts"], [])


class RepoFilesTest(unittest.TestCase):
    def test_rule_ids_in_range(self):
        import re
        ids = [int(i) for i in re.findall(r'rule id="(\d+)"', read(os.path.join(ROOT, "wazuh", "rules", "kaspersky_ksc_rules.xml")))]
        self.assertTrue(ids)
        self.assertTrue(all(100700 <= i <= 100799 for i in ids), ids)
        self.assertEqual(len(ids), len(set(ids)))

    def test_cases_reference_existing_samples(self):
        cases = json.loads(read(os.path.join(HERE, "cases.json")))["cases"]
        for case in cases:
            for e in case["events"]:
                self.assertTrue(os.path.isfile(os.path.join(HERE, e["file"])), e["file"])


if __name__ == "__main__":
    unittest.main()
