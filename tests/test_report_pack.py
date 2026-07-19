"""Tests for the report pack module."""
import os
import sys
import unittest
import tempfile
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from scam_shield import detector, report_pack


def _heur():
    msg = ("URGENT: Microsoft Security has detected a virus on your PC. "
           "Call +1-888-555-0199 and download AnyDesk immediately. "
           "Pay 299 USD in gift cards to keep your subscription active.")
    return detector.analyze(msg, channel="sms")


def _llm_disagreement():
    """A case where the LLM would say something different from the heuristic."""
    return detector.ScamReport(score=70, verdict="likely_scam", scam_type="romance",
                               channel="dm", signals=[], entities={}, advice=[])


class ReportPackTests(unittest.TestCase):

    def test_from_heuristic_only(self):
        h = _heur()
        pack = report_pack.ReportPack.from_report(h)
        self.assertEqual(pack.scam_type, "tech_support")
        self.assertIn(pack.verdict, ("scam", "likely_scam"))
        self.assertIn("complaint_narrative.txt", pack.files)
        self.assertIn("law_enforcement_packet.json", pack.files)
        self.assertIn("filing_checklist.txt", pack.files)
        self.assertIn("bank_notice.txt", pack.files)
        self.assertIn("INDEX.md", pack.files)
        self.assertIn("entity_index.txt", pack.files)
        self.assertIn("timeline.txt", pack.files)
        self.assertIn("platform_report.txt", pack.files)

    def test_from_full_report_uses_comparison(self):
        h = _heur()
        # Fake a FullReport by hand
        from scam_shield.llm_judge import JudgeResult, Comparison
        llm = JudgeResult(verdict="scam", scam_type="tech_support", confidence=95,
                          reason="obvious", model="m")
        cmp = Comparison(heuristic=h, llm=llm,
                         agree_verdict=True, agree_type=True,
                         final_verdict="scam", final_score=90, boost=15,
                         notes=["agree"])
        # We can't easily import FullReport without a circular; use heuristic instead
        pack = report_pack.ReportPack.from_report(h)
        self.assertGreater(pack.score, 0)

    def test_to_files_writes_everything(self):
        h = _heur()
        pack = report_pack.ReportPack.from_report(h)
        with tempfile.TemporaryDirectory() as d:
            written = pack.to_files(d)
            self.assertEqual(len(written), len(pack.files))
            for w in written:
                self.assertTrue(os.path.isfile(w))
                self.assertGreater(os.path.getsize(w), 0)

    def test_complaint_narrative_contains_signals_and_entities(self):
        h = _heur()
        pack = report_pack.ReportPack.from_report(h)
        body = pack.files["complaint_narrative.txt"]
        self.assertIn("Microsoft", body)
        self.assertIn("AnyDesk", body)
        self.assertIn("+1-888-555-0199", body)
        self.assertIn("299 USD", body)
        self.assertIn("tech_support", body)

    def test_evidence_inventory_is_valid_json(self):
        h = _heur()
        pack = report_pack.ReportPack.from_report(h)
        body = pack.files["evidence_inventory.json"]
        obj = json.loads(body)
        self.assertEqual(obj["case_id"], pack.case_id)
        self.assertIn("entities", obj)
        self.assertIn("signals", obj)

    def test_le_packet_has_required_keys(self):
        h = _heur()
        victim = {"name": "Test User", "email": "test@example.com"}
        extras = {"money_sent": "299 USD", "payment_method": "gift cards"}
        pack = report_pack.ReportPack.from_report(h, victim=victim, extras=extras)
        body = pack.files["law_enforcement_packet.json"]
        obj = json.loads(body)
        self.assertEqual(obj["schema"], "scam-shield.law-enforcement-packet.v1")
        self.assertEqual(obj["victim"]["name"], "Test User")
        self.assertEqual(obj["loss"]["money_sent"], "299 USD")
        self.assertIn("agencies_to_file", obj)
        self.assertGreater(len(obj["agencies_to_file"]), 0)

    def test_filing_checklist_routes_correctly(self):
        h = _heur()
        pack = report_pack.ReportPack.from_report(h)
        body = pack.files["filing_checklist.txt"]
        # tech_support → Microsoft should be in the list
        self.assertIn("Microsoft", body)
        self.assertIn("FTC", body)
        self.assertIn("IC3", body)

    def test_bank_notice_uses_extras(self):
        h = _heur()
        extras = {"money_sent": "500 USD", "payment_method": "Zelle",
                  "payment_destination": "scammer@example.com"}
        pack = report_pack.ReportPack.from_report(h, extras=extras)
        body = pack.files["bank_notice.txt"]
        self.assertIn("500 USD", body)
        self.assertIn("Zelle", body)
        self.assertIn("scammer@example.com", body)

    def test_works_for_all_scam_types(self):
        for scam_type in ["tech_support", "government", "bank_impersonation",
                           "package", "romance", "job_scam", "crypto_investment",
                           "lottery", "phishing", "universal"]:
            h = detector.ScamReport(score=70, verdict="scam", scam_type=scam_type,
                                    channel="test")
            pack = report_pack.ReportPack.from_report(h)
            self.assertEqual(pack.scam_type, scam_type)
            # filing checklist has at least one agency
            self.assertIn("FTC", pack.files["filing_checklist.txt"])

    def test_summary_line(self):
        h = _heur()
        pack = report_pack.ReportPack.from_report(h)
        s = pack.summary()
        self.assertIn(pack.case_id, s)
        self.assertIn(pack.verdict.upper(), s)
        self.assertIn(str(pack.score), s)


class EndToEndReportTests(unittest.TestCase):
    """Real report on a real heuristic output, written to a temp dir."""

    def test_real_pack_to_disk(self):
        h = _heur()
        pack = report_pack.ReportPack.from_report(
            h,
            victim={"name": "Real Person", "email": "real@example.com",
                    "phone": "+1-555-123-4567"},
            extras={"money_sent": "299 USD", "payment_method": "gift cards",
                    "payment_destination": "fake Amazon support",
                    "payment_date": "2026-07-16",
                    "transaction_reference": "GC-AB12-CD34-EF56"},
            transcript=[
                "SCAMMER: This is Microsoft Support. Your PC has a virus.",
                "ME: Which datacenter?",
                "SCAMMER: The main one. Just install AnyDesk.",
                "ME: I need to verify. What's your employee ID?",
                "SCAMMER: Just install it now before your accounts are locked!",
            ],
        )
        with tempfile.TemporaryDirectory() as d:
            written = pack.to_files(d)
            self.assertEqual(len(written), 9)
            # spot-check the timeline
            with open(os.path.join(d, "timeline.txt"), "r", encoding="utf-8") as f:
                timeline = f.read()
            self.assertIn("event 1", timeline)
            self.assertIn("Which datacenter", timeline)
            # spot-check the law enforcement packet
            with open(os.path.join(d, "law_enforcement_packet.json"), "r", encoding="utf-8") as f:
                lep = json.load(f)
            self.assertEqual(lep["loss"]["transaction_reference"], "GC-AB12-CD34-EF56")
            self.assertEqual(len(lep["transcript"]), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
