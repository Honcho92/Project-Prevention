"""Tests for the Telegram bot module.

We mock the Telegram API by monkey-patching _api so the handler logic can be
exercised without a real bot token or network.
"""
import os
import sys
import unittest
import tempfile
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from scam_shield import telegram_bot as tb


class TelegramBotTests(unittest.TestCase):

    def setUp(self):
        self.sent = []
        # patch _api to record sendMessage calls
        def fake_api(token, method, **params):
            if method == "sendMessage":
                self.sent.append({"text": params.get("text", ""),
                                  "chat_id": params.get("chat_id")})
            return {"ok": True, "result": {"message_id": len(self.sent)}}
        self._api_patch = mock.patch.object(tb, "_api", side_effect=fake_api)
        self._api_patch.start()
        self.tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        self.tmp.close()
        # point the default honeypot db at a temp file
        self._db_patch = mock.patch.object(tb.hp, "DEFAULT_DB", self.tmp.name)
        self._db_patch.start()

    def tearDown(self):
        self._api_patch.stop()
        self._db_patch.stop()
        try: os.unlink(self.tmp.name)
        except OSError: pass

    def _new_state(self):
        return tb.UserState()

    def test_help_command(self):
        s = self._new_state()
        tb._handle_message("tok", 1, "/help", s)
        self.assertGreater(len(self.sent), 0)
        self.assertIn("Scam-Shield", self.sent[0]["text"])

    def test_score_command(self):
        s = self._new_state()
        tb._handle_message("tok", 1, "/score URGENT: pay $999 in gift cards now.", s)
        self.assertGreater(len(self.sent), 0)
        # score text mentions verdict
        joined = "\n".join(x["text"] for x in self.sent)
        self.assertTrue(any(v in joined for v in ("SCAM", "LIKELY_SCAM", "SUSPICIOUS")))

    def test_unscored_message_runs_analyze(self):
        s = self._new_state()
        tb._handle_message("tok", 1, "Pay $999 in gift cards now.", s)
        joined = "\n".join(x["text"] for x in self.sent)
        self.assertIn("score:", joined.lower())

    def test_honey_session_bridge(self):
        s = self._new_state()
        tb._handle_message("tok", 1, "/honey romance", s)
        # next message is from "scammer"
        self.sent.clear()
        tb._handle_message("tok", 1, "Hello dear, I am stranded in Istanbul", s)
        joined = "\n".join(x["text"] for x in self.sent)
        # Margaret persona should respond
        self.assertTrue(any("[" in x and "]" in x for x in joined.splitlines() if x))

    def test_stop_command_ends_session(self):
        s = self._new_state()
        tb._handle_message("tok", 1, "/honey romance", s)
        tb._handle_message("tok", 1, "/stop", s)
        self.assertEqual(s.mode, "idle")

    def test_questions_command(self):
        s = self._new_state()
        tb._handle_message("tok", 1, "/questions romance", s)
        joined = "\n".join(x["text"] for x in self.sent)
        self.assertIn("romance", joined.lower())
        self.assertIn("Why:", joined)

    def test_persona_switch(self):
        s = self._new_state()
        tb._handle_message("tok", 1, "/persona bob", s)
        joined = "\n".join(x["text"] for x in self.sent)
        self.assertIn("bob", joined.lower())

    def test_demo_command(self):
        s = self._new_state()
        tb._handle_message("tok", 1, "/demo", s)
        joined = "\n".join(x["text"] for x in self.sent)
        self.assertIn("CASE", joined)
        self.assertIn("microsoft", joined.lower())

    def test_llm_toggle(self):
        s = self._new_state()
        tb._handle_message("tok", 1, "/llm on", s)
        self.assertTrue(s.use_llm)
        tb._handle_message("tok", 1, "/llm off", s)
        self.assertFalse(s.use_llm)
        tb._handle_message("tok", 1, "/llm", s)
        joined = "\n".join(x["text"] for x in self.sent)
        self.assertIn("OFF", joined)

    def test_llm_on_runs_full_analysis(self):
        s = self._new_state()
        s.use_llm = True
        # Mock the LLM call inside the llm_judge module (which detector.analyze_full uses)
        body = {"model": "m", "response": '{"verdict":"scam","scam_type":"tech_support","confidence":95,"reason":"AnyDesk request."}', "done": True}
        from scam_shield import llm_judge
        with mock.patch.object(llm_judge, "_ollama_generate", return_value=body):
            tb._handle_message("tok", 1, "/score Microsoft wants AnyDesk and 299 USD in gift cards", s)
        joined = "\n".join(x["text"] for x in self.sent)
        # Should now show the LLM block
        self.assertIn("FINAL", joined)
        self.assertIn("LLM", joined)

    def test_report_command_writes_pack(self):
        s = self._new_state()
        # First score a message
        tb._handle_message("tok", 1, "/score Microsoft wants AnyDesk and 299 USD in gift cards", s)
        self.sent.clear()
        # Now ask for a report
        tb._handle_message("tok", 1, "/report", s)
        joined = "\n".join(x["text"] for x in self.sent)
        self.assertIn("Report pack", joined)
        # Verify files were written
        import glob
        packs = glob.glob(os.path.expanduser("~/.scam-shield/reports/tg-1-*"))
        self.assertGreater(len(packs), 0, "no report pack written")
        # Cleanup
        import shutil
        for p in packs:
            shutil.rmtree(p, ignore_errors=True)

    def test_report_without_score_says_so(self):
        s = self._new_state()
        tb._handle_message("tok", 1, "/report", s)
        joined = "\n".join(x["text"] for x in self.sent)
        self.assertIn("No recent score", joined)


if __name__ == "__main__":
    unittest.main(verbosity=2)
