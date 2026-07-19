"""Tests for scam_shield — runs on stdlib unittest, no pytest needed."""
import os
import sys
import unittest
import tempfile

# make package importable when running this file directly
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from scam_shield import detector, playbook, honeypot


class DetectorTests(unittest.TestCase):

    def test_empty_message_is_clean(self):
        r = detector.analyze("")
        self.assertEqual(r.verdict, "clean")
        self.assertEqual(r.score, 0)

    def test_microsoft_tech_support_is_scam(self):
        msg = ("URGENT: Microsoft Security has detected a virus on your PC. "
               "Call +1-888-555-0199 and download AnyDesk immediately. "
               "Pay $299 in gift cards to keep your subscription active.")
        r = detector.analyze(msg)
        self.assertIn(r.verdict, ("scam", "likely_scam"))
        self.assertEqual(r.scam_type, "tech_support")
        self.assertGreaterEqual(r.score, 50)
        # entities
        self.assertTrue(any("555-0199" in p for p in r.entities["phones"]))
        self.assertIn("$299", r.entities["money"])
        # AnyDesk shows up as a *signal* snippet, not a URL entity
        all_text = " ".join(s["snippet"] for s in r.signals).lower()
        self.assertIn("anydesk", all_text)

    def test_irs_arrest_warrant(self):
        msg = ("This is Officer Daniels from the Internal Revenue Service. "
               "A warrant has been issued for your arrest due to unpaid "
               "back taxes. Pay $4,850 in Google Play gift cards within 30 "
               "minutes. Do not tell your family or your bank.")
        r = detector.analyze(msg)
        self.assertIn(r.verdict, ("scam", "likely_scam"))
        self.assertEqual(r.scam_type, "government")
        self.assertGreaterEqual(r.score, 50)

    def test_fake_fedex(self):
        msg = ("FEDEX: Your package is being held at customs. A small "
               "redelivery fee of $1.99 is required. Confirm at "
               "https://fedex-redelivery.top/track?id=9921 to avoid return.")
        r = detector.analyze(msg)
        self.assertIn(r.verdict, ("scam", "likely_scam"))
        self.assertIn("phishing", [s["scam_type"] for s in r.signals])
        self.assertTrue(any("fedex" in u for u in r.entities["urls"]))

    def test_romance_stranded(self):
        msg = ("My dearest Margaret, I miss you so much. I am stuck in "
               "Istanbul at customs and my wallet was stolen. Could you "
               "please send $850 via Western Union so I can get home? "
               "Please keep this between us.")
        r = detector.analyze(msg)
        self.assertIn(r.verdict, ("scam", "likely_scam"))
        self.assertEqual(r.scam_type, "romance")

    def test_crypto_giveaway(self):
        msg = ("ELON MUSK BITCOIN GIVEAWAY — Send 0.1 BTC to the address "
               "below and receive 1 BTC back GUARANTEED within 24 hours. "
               "Connect your wallet to claim. Risk-free passive income.")
        r = detector.analyze(msg)
        self.assertIn(r.verdict, ("scam", "likely_scam"))
        self.assertEqual(r.scam_type, "crypto_investment")

    def test_job_scam(self):
        msg = ("Work from home, $3,500/week, no experience needed. Send a "
               "$200 training fee via Zelle to get started. You'll receive "
               "client payments and forward them to our HQ.")
        r = detector.analyze(msg)
        self.assertIn(r.verdict, ("scam", "likely_scam"))
        self.assertEqual(r.scam_type, "job_scam")

    def test_paypal_phishing_lookalike(self):
        msg = ("Your PayPal account has been LIMITED. Click here to verify: "
               "http://paypa1-secure-login.com/verify?id=99. Failure to act "
               "within 24 hours will result in permanent suspension.")
        r = detector.analyze(msg)
        self.assertIn(r.verdict, ("scam", "likely_scam"))
        self.assertTrue(any("phishing" == s["scam_type"] for s in r.signals))

    def test_legit_amazon_shipment(self):
        msg = ("Hi Zach, your Amazon order #112-3344556-7788990 has shipped! "
               "Track at amazon.com/orders. Estimated delivery: Tuesday.")
        r = detector.analyze(msg)
        self.assertIn(r.verdict, ("clean", "suspicious"))
        self.assertLess(r.score, 30)

    def test_legit_capital_one_alert(self):
        msg = ("Capital One: A $42.19 charge at TARGET T-1234 was made on "
               "your card ending in 4471. If this was not you, call the "
               "number on the back of your card. Reply HELP for help.")
        r = detector.analyze(msg)
        self.assertIn(r.verdict, ("clean", "suspicious"))
        self.assertLess(r.score, 40)

    def test_bank_impersonation_flagged(self):
        msg = ("This is Chase Fraud Department. Your account has been "
               "compromised. To protect your funds, please verify your "
               "online banking password and one-time code.")
        r = detector.analyze(msg)
        self.assertIn(r.verdict, ("scam", "likely_scam"))
        self.assertEqual(r.scam_type, "bank_impersonation")

    def test_lottery(self):
        msg = ("Congratulations! You have been selected as the lucky winner "
               "of the Microsoft Lottery. Claim your prize of $50,000 now "
               "by sending $500 in iTunes gift cards.")
        r = detector.analyze(msg)
        self.assertIn(r.verdict, ("scam", "likely_scam"))
        self.assertEqual(r.scam_type, "lottery")

    def test_signals_are_transparent(self):
        msg = "Pay $999 in gift cards now. Don't tell your bank."
        r = detector.analyze(msg)
        self.assertGreater(len(r.signals), 0)
        for s in r.signals:
            self.assertIn("scam_type", s)
            self.assertIn("category", s)
            self.assertIn("weight", s)
            self.assertIn("snippet", s)


class PlaybookTests(unittest.TestCase):

    def test_universal_questions_always_in_pool(self):
        for t in ("tech_support", "romance", "crypto_investment", "lottery",
                  "job_scam", "bank_impersonation", "package", "government",
                  "phishing", "universal", "unknown"):
            qs = playbook.pick_questions(t, n=3, also_universal=True)
            self.assertGreater(len(qs), 0)
            # every question should have a populated question string
            for q in qs:
                self.assertTrue(q.question)
                self.assertTrue(q.rationale)

    def test_pick_returns_n(self):
        qs = playbook.pick_questions("romance", n=4)
        self.assertEqual(len(qs), 4)

    def test_pick_with_no_universal(self):
        qs = playbook.pick_questions("romance", n=3, also_universal=False)
        for q in qs:
            self.assertFalse(q.universal)

    def test_question_lookups(self):
        q = playbook.get("uni-employee-id")
        self.assertIsNotNone(q)
        self.assertIn("universal", q.scam_types)


class HoneypotTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        self.tmp.close()
        self.db = self.tmp.name

    def tearDown(self):
        # Force-release the file on Windows: garbage-collect any lingering
        # sqlite connections and retry the unlink.
        import gc, sqlite3, time
        gc.collect()
        for _ in range(5):
            try:
                # open and close to release any shared locks
                try:
                    c = sqlite3.connect(self.db); c.close()
                except Exception:
                    pass
                os.unlink(self.db)
                return
            except PermissionError:
                time.sleep(0.1)
        # best-effort
        try: os.unlink(self.db)
        except OSError: pass

    def test_session_creates_and_closes(self):
        s = honeypot.start_session(persona="margaret", scam_type="romance", db_path=self.db)
        s.close()
        # verify rows persisted
        import sqlite3
        conn = sqlite3.connect(self.db)
        n = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        self.assertEqual(n, 1)

    def test_ingest_returns_reply_and_logs(self):
        s = honeypot.start_session(persona="bob", scam_type="tech_support", db_path=self.db)
        reply = s.ingest("Hi this is Microsoft Support, your PC has a virus, "
                         "please install AnyDesk and pay $299 in gift cards.")
        self.assertIsInstance(reply, str)
        self.assertGreater(len(reply), 0)
        # should have logged 1 scammer msg + 1 honeypot reply
        import sqlite3
        conn = sqlite3.connect(self.db)
        n_scammer = conn.execute("SELECT COUNT(*) FROM messages WHERE role='scammer' AND session_id=?",
                                 (s.session_id,)).fetchone()[0]
        n_honey   = conn.execute("SELECT COUNT(*) FROM messages WHERE role='honeypot' AND session_id=?",
                                 (s.session_id,)).fetchone()[0]
        n_evid    = conn.execute("SELECT COUNT(*) FROM evidence WHERE session_id=?",
                                 (s.session_id,)).fetchone()[0]
        self.assertEqual(n_scammer, 1)
        self.assertEqual(n_honey, 1)
        self.assertGreater(n_evid, 0)
        s.close()

    def test_scam_type_adapts_to_message(self):
        s = honeypot.start_session(persona="margaret", scam_type="universal", db_path=self.db)
        s.ingest("This is the IRS. Pay $5,000 in Google Play gift cards now.")
        self.assertEqual(s.scam_type, "government")
        s.close()


class IntegrationTest(unittest.TestCase):
    """End-to-end: detect, pick questions, start honeypot, ingest reply."""

    def test_full_flow(self):
        msg = ("Hi, I'm calling from Microsoft Tech Support. Your computer "
               "is infected. Please install AnyDesk and pay $299 in gift cards "
               "to keep your subscription active.")
        report = detector.analyze(msg)
        self.assertIn(report.verdict, ("scam", "likely_scam"))
        qs = playbook.pick_questions(report.scam_type, n=3)
        self.assertGreater(len(qs), 0)

        import tempfile, gc
        tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        tmp.close()
        sess = None
        try:
            sess = honeypot.start_session(persona="margaret", scam_type=report.scam_type, db_path=tmp.name)
            reply = sess.ingest(msg)
            self.assertIsInstance(reply, str)
            export = honeypot.export_report(sess)
            self.assertIn("messages", export)
            self.assertIn("evidence", export)
        finally:
            if sess is not None:
                sess.close()
            gc.collect()
            try: os.unlink(tmp.name)
            except OSError: pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
