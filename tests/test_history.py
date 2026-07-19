"""Tests for the history module."""
import os
import sys
import unittest
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from scam_shield import detector, history as hist_mod
from scam_shield.llm_judge import JudgeResult


def _heur_msg(msg="Microsoft support wants AnyDesk and gift cards",
              channel="sms"):
    return detector.analyze(msg, channel=channel)


class HistoryTests(unittest.TestCase):

    def setUp(self):
        # Use a per-test temp file so tests don't collide
        fd, self.db = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        self.h = hist_mod.History(self.db)

    def tearDown(self):
        self.h.close()
        for _ in range(5):
            try: os.unlink(self.db); break
            except PermissionError: import time; time.sleep(0.1)

    def test_record_and_list(self):
        r = _heur_msg()
        rid = self.h.record(r, text="microsoft support sample text")
        self.assertGreater(rid, 0)
        rows = self.h.list_reports()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], rid)
        self.assertEqual(rows[0]["verdict"], r.verdict)

    def test_record_full_report(self):
        from scam_shield.detector import FullReport
        from scam_shield.llm_judge import Comparison
        h = _heur_msg()
        llm = JudgeResult(verdict="scam", scam_type="tech_support", confidence=92,
                          reason="classic", model="qwen")
        cmp = Comparison(heuristic=h, llm=llm,
                         agree_verdict=True, agree_type=True,
                         final_verdict="scam", final_score=85, boost=6,
                         notes=["agree"])
        full = FullReport(heuristic=h, llm=llm, comparison=cmp)
        rid = self.h.record(full, text="x")
        stored = self.h.get_report(rid)
        self.assertIn("llm", stored)
        self.assertEqual(stored["llm"]["verdict"], "scam")
        self.assertEqual(stored["llm"]["confidence"], 92)

    def test_list_filters_by_verdict(self):
        self.h.record(_heur_msg("Microsoft wants AnyDesk"))         # scam
        self.h.record(detector.ScamReport(score=10, verdict="clean", scam_type="unknown",
                                          channel="sms"))            # clean
        rows = self.h.list_reports(verdict="clean")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], "clean")

    def test_list_filters_by_scam_type(self):
        self.h.record(_heur_msg("Microsoft wants AnyDesk"))         # tech_support
        # fake a romance report
        r = detector.ScamReport(score=70, verdict="scam", scam_type="romance", channel="dm")
        self.h.record(r, text="stranded in Istanbul")
        rows = self.h.list_reports(scam_type="romance")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["scam_type"], "romance")

    def test_get_report_round_trip(self):
        r = _heur_msg()
        rid = self.h.record(r, text="microsoft support wants AnyDesk")
        stored = self.h.get_report(rid)
        self.assertIsNotNone(stored)
        self.assertEqual(stored["text"], "microsoft support wants AnyDesk")
        self.assertGreater(len(stored["signals"]), 0)
        self.assertIn("phones", stored["entities"])

    def test_search(self):
        self.h.record(_heur_msg("microsoft support wants AnyDesk"),
                      text="the message had AnyDesk and 299 USD in gift cards")
        self.h.record(_heur_msg("Amazon package held at customs"),
                      text="fedex redelivery scam 1.99 USD")
        rows = self.h.search("AnyDesk")
        self.assertGreater(len(rows), 0)

    def test_search_falls_back_to_like(self):
        # ensure search doesn't crash even if FTS is unavailable
        self.h.record(_heur_msg("test"), text="unusual-keyword-12345")
        rows = self.h.search("unusual-keyword-12345")
        self.assertEqual(len(rows), 1)

    def test_stats(self):
        # messages that actually score as scam
        self.h.record(_heur_msg("Microsoft Security detected a virus, "
                                "download AnyDesk and pay 299 USD in gift cards"),
                      text="microsoft AnyDesk gift cards")
        self.h.record(_heur_msg("This is the IRS, pay 4850 USD in gift cards"),
                      text="IRS threat gift cards")
        self.h.record(detector.ScamReport(score=5, verdict="clean",
                                          scam_type="unknown", channel="sms"),
                      text="legit amazon shipment")
        s = self.h.stats()
        self.assertEqual(s["total_reports"], 3)
        self.assertIn("scam", s["by_verdict"], f"got by_verdict={s['by_verdict']}")
        self.assertIn("clean", s["by_verdict"])
        self.assertGreater(len(s["by_scam_type"]), 0)

    def test_record_pack(self):
        r = _heur_msg()
        rid = self.h.record(r, text="x")
        pid = self.h.record_pack(rid, "SCAM-20260101-ABCD1234", "/tmp/pack",
                                 ["INDEX.md", "complaint_narrative.txt"])
        self.assertGreater(pid, 0)
        s = self.h.stats()
        self.assertEqual(s["total_packs"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
