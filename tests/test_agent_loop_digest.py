"""Tests for the agent loop, the digest, and the /quiet /verbose bot commands."""
import os
import sys
import unittest
import tempfile
import json
from datetime import datetime, timezone, timedelta
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from scam_shield import detector, history as hist_mod, agent_loop, digest
from scam_shield import telegram_bot as tb


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_history(h: hist_mod.History, msgs: list) -> list:
    """Record a list of (text, channel) pairs, return their row ids."""
    ids = []
    for text, channel in msgs:
        r = detector.analyze(text, channel=channel)
        rid = h.record(r, text=text)
        ids.append(rid)
    return ids


# ---------------------------------------------------------------------------
# /quiet and /verbose in the bot
# ---------------------------------------------------------------------------

class QuietVerboseTests(unittest.TestCase):
    def setUp(self):
        self.sent = []
        def fake_api(token, method, **params):
            if method == "sendMessage":
                self.sent.append({"text": params.get("text", ""),
                                  "chat_id": params.get("chat_id")})
            return {"ok": True, "result": {"message_id": len(self.sent)}}
        self._api_patch = mock.patch.object(tb, "_api", side_effect=fake_api)
        self._api_patch.start()
        self.tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        self.tmp.close()
        self._db_patch = mock.patch.object(tb.hp, "DEFAULT_DB", self.tmp.name)
        self._db_patch.start()
        self._hist_patch = mock.patch.object(tb.hist_mod, "DEFAULT_PATH", self.tmp.name)
        self._hist_patch.start()

    def tearDown(self):
        self._api_patch.stop()
        self._db_patch.stop()
        self._hist_patch.stop()
        import gc, sqlite3, time
        gc.collect()
        for _ in range(5):
            try:
                try: c = sqlite3.connect(self.tmp.name); c.close()
                except Exception: pass
                os.unlink(self.tmp.name); break
            except PermissionError: time.sleep(0.1)

    def test_verbose_mode_by_default(self):
        s = tb.UserState()
        self.assertTrue(s.verbose)
        tb._handle_message("tok", 1, "/score Microsoft wants AnyDesk and 299 USD in gift cards", s)
        # verbose should send a full report
        joined = "\n".join(x["text"] for x in self.sent)
        # The format may say "Verdict:" (ScamReport) or "FINAL verdict:" (FullReport)
        self.assertIn("verdict:", joined.lower())

    def test_quiet_toggle(self):
        s = tb.UserState()
        tb._handle_message("tok", 1, "/quiet", s)
        self.assertFalse(s.verbose)
        tb._handle_message("tok", 1, "/q", s)  # alias
        self.assertFalse(s.verbose)
        tb._handle_message("tok", 1, "/verbose", s)
        self.assertTrue(s.verbose)
        tb._handle_message("tok", 1, "/v", s)  # alias
        self.assertTrue(s.verbose)

    def test_quiet_mode_sends_one_liner(self):
        s = tb.UserState()
        s.verbose = False
        tb._handle_message("tok", 1, "/score Microsoft wants AnyDesk and 299 USD in gift cards", s)
        joined = "\n".join(x["text"] for x in self.sent)
        # one-liner uses emoji + uppercase verdict
        self.assertIn("🚨", joined)
        self.assertIn("SCAM", joined)
        # no "Verdict:" full report header
        self.assertNotIn("Verdict:", joined)

    def test_forwarded_message_respects_quiet(self):
        s = tb.UserState()
        s.verbose = False
        # default branch: forwarded text (not a command)
        tb._handle_message("tok", 1, "Microsoft wants AnyDesk and 299 USD in gift cards", s)
        joined = "\n".join(x["text"] for x in self.sent)
        self.assertIn("🚨", joined)


# ---------------------------------------------------------------------------
# agent_loop: process unprocessed reports
# ---------------------------------------------------------------------------

class AgentLoopTests(unittest.TestCase):
    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        self.h = hist_mod.History(self.db)
        # seed with a mix of verdicts
        self.ids = _seed_history(self.h, [
            ("Microsoft wants AnyDesk and 299 USD in gift cards",   "telegram"),
            ("This is the IRS, pay 4850 USD in gift cards or face arrest", "telegram"),
            ("Hi, your Amazon order has shipped",                    "telegram"),
        ])

    def tearDown(self):
        self.h.close()
        import gc, time
        gc.collect()
        for _ in range(5):
            try: os.unlink(self.db); break
            except PermissionError: time.sleep(0.1)

    def test_unprocessed_reports_lists_unseeded(self):
        rows = self.h.unprocessed_reports()
        self.assertEqual(len(rows), 3)
        for r in rows:
            self.assertEqual(r.get("notes"), "")

    def test_mark_processed_excludes_from_unprocessed(self):
        self.h.mark_processed(self.ids[0])
        self.h.mark_processed(self.ids[2])
        rows = self.h.unprocessed_reports()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], self.ids[1])

    def test_run_once_with_no_telegram(self):
        # no telegram token → no notify, but auto-pack still runs
        results = agent_loop.run_once(db_path=self.db, telegram_token=None,
                                      notify_chat_id=None)
        self.assertEqual(len(results), 3)
        # the two scam-y ones should have generated packs
        scam_results = [r for r in results if r["verdict"] in ("scam", "likely_scam")]
        for r in scam_results:
            self.assertEqual(r["action_taken"], "auto_report_pack")
            self.assertIsNotNone(r["pack_path"])
            self.assertTrue(os.path.isdir(r["pack_path"]))
        # the legit one should have been no_action
        legit = [r for r in results if r["verdict"] == "clean"]
        for r in legit:
            self.assertEqual(r["action_taken"], "no_action")
        # all marked processed
        self.assertEqual(len(self.h.unprocessed_reports()), 0)
        # cleanup packs
        for r in results:
            if r.get("pack_path"):
                import shutil
                shutil.rmtree(r["pack_path"], ignore_errors=True)

    def test_run_once_respects_batch_size(self):
        results = agent_loop.run_once(db_path=self.db, batch_size=1)
        self.assertEqual(len(results), 1)
        # cleanup
        for r in results:
            if r.get("pack_path"):
                import shutil
                shutil.rmtree(r["pack_path"], ignore_errors=True)

    def test_run_once_handles_suspicious_verdict(self):
        # craft a suspicious (not full scam) message
        self.h.record(
            detector.ScamReport(score=30, verdict="suspicious", scam_type="universal",
                                channel="telegram", signals=[], entities={}, advice=[]),
            text="unusual message",
        )
        results = agent_loop.run_once(db_path=self.db, telegram_token=None)
        sus = [r for r in results if r["verdict"] == "suspicious"]
        self.assertGreater(len(sus), 0)
        for r in sus:
            self.assertEqual(r["action_taken"], "notified_suspicious")
        # cleanup any packs
        for r in results:
            if r.get("pack_path"):
                import shutil
                shutil.rmtree(r["pack_path"], ignore_errors=True)

    def test_no_unprocessed_returns_empty(self):
        # mark everything processed
        for rid in self.ids:
            self.h.mark_processed(rid)
        results = agent_loop.run_once(db_path=self.db)
        self.assertEqual(results, [])


# ---------------------------------------------------------------------------
# digest: build, render
# ---------------------------------------------------------------------------

class DigestTests(unittest.TestCase):
    def setUp(self):
        fd, self.db = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        self.h = hist_mod.History(self.db)
        _seed_history(self.h, [
            ("Microsoft wants AnyDesk and 299 USD in gift cards",   "telegram"),
            ("Microsoft support calling about your PC",             "telegram"),
            ("This is the IRS, pay 4850 USD in gift cards or face arrest", "telegram"),
            ("Hi, your Amazon order has shipped",                    "telegram"),
        ])

    def tearDown(self):
        self.h.close()
        import gc, time
        gc.collect()
        for _ in range(5):
            try: os.unlink(self.db); break
            except PermissionError: time.sleep(0.1)

    def test_build_digest(self):
        d = digest.build_digest(self.h)
        self.assertEqual(d["total"], 4)
        self.assertIn("scam", d["by_verdict"])
        self.assertIn("likely_scam", d["by_verdict"])
        self.assertIn("clean", d["by_verdict"])
        # by_scam_type should be a list of tuples
        self.assertGreater(len(d["by_scam_type"]), 0)
        # top types should include tech_support and government
        type_names = [t for t, _ in d["by_scam_type"]]
        self.assertIn("tech_support", type_names)
        self.assertIn("government", type_names)

    def test_build_digest_with_empty_db(self):
        self.h.close()
        empty_db = self.db
        # wipe and recreate
        import os as _os
        _os.unlink(empty_db)
        empty = hist_mod.History(empty_db)
        d = digest.build_digest(empty)
        empty.close()
        self.assertEqual(d["total"], 0)
        self.assertEqual(d["by_verdict"], {})

    def test_format_digest_with_data(self):
        d = digest.build_digest(self.h)
        text = digest.format_digest(d)
        self.assertIn("Scam-Shield weekly digest", text)
        self.assertIn("Total forwards: 4", text)
        self.assertIn("tech_support", text)
        self.assertIn("government", text)

    def test_format_digest_with_no_data(self):
        empty = hist_mod.History(self.db)
        try:
            # delete all rows
            empty.conn.execute("DELETE FROM reports")
            empty.conn.commit()
            d = digest.build_digest(empty)
            text = digest.format_digest(d)
            self.assertIn("Nothing forwarded this period", text)
        finally:
            empty.close()

    def test_format_digest_includes_examples(self):
        d = digest.build_digest(self.h)
        text = digest.format_digest(d)
        self.assertIn("Worst offenders", text)

    def test_send_digest_without_token_returns_false(self):
        d = digest.build_digest(self.h)
        ok = digest.send_digest("", 0, d)
        self.assertFalse(ok)
        ok = digest.send_digest("anything", 0, d)
        self.assertFalse(ok)


# ---------------------------------------------------------------------------
# Integration: bot records → agent_loop processes
# ---------------------------------------------------------------------------

class BotAgentIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.sent = []
        def fake_api(token, method, **params):
            if method == "sendMessage":
                self.sent.append({"text": params.get("text", ""),
                                  "chat_id": params.get("chat_id")})
            return {"ok": True, "result": {"message_id": len(self.sent)}}
        self._api_patch = mock.patch.object(tb, "_api", side_effect=fake_api)
        self._api_patch.start()
        self.tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        self.tmp.close()
        self._db_patch = mock.patch.object(tb.hp, "DEFAULT_DB", self.tmp.name)
        self._db_patch.start()
        self._hist_patch = mock.patch.object(tb.hist_mod, "DEFAULT_PATH", self.tmp.name)
        self._hist_patch.start()
        # keep track of any auto-packs we write so tearDown cleans them
        self._packs_to_clean = []

    def tearDown(self):
        # remove any auto-packs the agent wrote
        for p in self._packs_to_clean:
            import shutil
            shutil.rmtree(p, ignore_errors=True)
        # also clean anything written under the default root
        for p in agent_loop.glob_packs():
            import shutil
            shutil.rmtree(p, ignore_errors=True)
        self._api_patch.stop()
        self._db_patch.stop()
        self._hist_patch.stop()
        import gc, sqlite3, time
        gc.collect()
        for _ in range(5):
            try:
                try: c = sqlite3.connect(self.tmp.name); c.close()
                except Exception: pass
                os.unlink(self.tmp.name); break
            except PermissionError: time.sleep(0.1)

    def test_bot_score_then_agent_processes(self):
        s = tb.UserState()
        # user forwards a scam
        tb._handle_message("tok", 1, "/score Microsoft wants AnyDesk and 299 USD in gift cards", s)
        # the bot's record should be in the (mocked) history DB
        h = hist_mod.History(self.tmp.name)
        try:
            unprocessed = h.unprocessed_reports()
            self.assertEqual(len(unprocessed), 1)
            # now the agent runs, with a mocked telegram send
            with mock.patch.object(agent_loop, "_send_telegram", return_value=True) as mocked:
                results = agent_loop.run_once(db_path=self.tmp.name,
                                              telegram_token="tok", notify_chat_id=1)
                self.assertTrue(mocked.called, "agent should have called _send_telegram")
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["action_taken"], "auto_report_pack")
            self.assertTrue(results[0]["pack_path"])
            self.assertTrue(os.path.isdir(results[0]["pack_path"]))
            self.assertTrue(results[0]["notified"])
            # no more unprocessed
            self.assertEqual(len(h.unprocessed_reports()), 0)
            self._packs_to_clean.append(results[0]["pack_path"])
        finally:
            h.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
