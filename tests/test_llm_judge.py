"""Tests for the LLM judge and the heuristic+LLM combination.

We mock _ollama_generate so the tests don't need a running Ollama.
"""
import os
import sys
import unittest
import json
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from scam_shield import detector, llm_judge
from scam_shield.llm_judge import judge, compare, JudgeResult, Comparison


def fake_ollama(payload: dict):
    """Build a fake ollama response."""
    return {
        "model": "qwen2.5-coder:7b",
        "response": json.dumps(payload),
        "done": True,
    }


class JudgeParsingTests(unittest.TestCase):

    def test_perfect_json(self):
        r = judge.__wrapped__ if hasattr(judge, "__wrapped__") else judge
        # just call the internal parser via a constructed JudgeResult instead
        # since judge() also calls Ollama
        pass

    def test_extract_json_direct(self):
        self.assertEqual(llm_judge._extract_json('{"a": 1}'), {"a": 1})

    def test_extract_json_with_fences(self):
        self.assertEqual(llm_judge._extract_json('```json\n{"a": 1}\n```'),
                         {"a": 1})

    def test_extract_json_in_prose(self):
        self.assertEqual(llm_judge._extract_json('Sure! {"a": 1, "b": 2} ok?'),
                         {"a": 1, "b": 2})

    def test_extract_json_none(self):
        self.assertIsNone(llm_judge._extract_json("no json here"))

    def test_coerce_verdict_clean_aliases(self):
        for s in ("clean", "ok", "safe", "legit", "legitimate"):
            self.assertEqual(llm_judge._coerce_verdict(s), "clean")

    def test_coerce_verdict_scam_aliases(self):
        for s in ("scam", "fraud", "phishing"):
            self.assertEqual(llm_judge._coerce_verdict(s), "scam")

    def test_coerce_type_aliases(self):
        self.assertEqual(llm_judge._coerce_type("tech"), "tech_support")
        self.assertEqual(llm_judge._coerce_type("irs"), "government")
        self.assertEqual(llm_judge._coerce_type("crypto"), "crypto_investment")
        self.assertEqual(llm_judge._coerce_type("weird"), "unknown")

    def test_coerce_confidence_clamps(self):
        self.assertEqual(llm_judge._coerce_confidence(150), 100)
        self.assertEqual(llm_judge._coerce_confidence(-5), 0)
        self.assertEqual(llm_judge._coerce_confidence("73.5"), 73)
        self.assertEqual(llm_judge._coerce_confidence(None), 50)


class JudgeFunctionTests(unittest.TestCase):

    def test_judge_happy_path(self):
        body = {
            "model": "qwen2.5-coder:7b",
            "response": json.dumps({
                "verdict": "scam", "scam_type": "tech_support",
                "confidence": 92, "reason": "Classic Microsoft support scam with AnyDesk ask."
            }),
            "done": True,
        }
        with mock.patch.object(llm_judge, "_ollama_generate", return_value=body):
            r = judge("Microsoft support asking for AnyDesk access")
        self.assertTrue(r.ok)
        self.assertEqual(r.verdict, "scam")
        self.assertEqual(r.scam_type, "tech_support")
        self.assertEqual(r.confidence, 92)
        self.assertIn("AnyDesk", r.reason)

    def test_judge_malformed_json_falls_back_to_suspicious(self):
        body = {"model": "m", "response": "I think it's probably a scam", "done": True}
        with mock.patch.object(llm_judge, "_ollama_generate", return_value=body):
            r = judge("Microsoft support asking for AnyDesk access")
        # We got a structured response, even though we couldn't parse it.
        # Defaults: suspicious / unknown / confidence 0.
        self.assertEqual(r.verdict, "suspicious")
        self.assertEqual(r.scam_type, "unknown")
        self.assertEqual(r.confidence, 0)

    def test_judge_ollama_down(self):
        import urllib.error
        with mock.patch.object(llm_judge, "_ollama_generate",
                               side_effect=urllib.error.URLError("connection refused")):
            r = judge("test")
        self.assertFalse(r.ok)
        self.assertIn("unavailable", r.reason.lower())
        self.assertIsNotNone(r.error)


class CompareTests(unittest.TestCase):

    def _heur(self, verdict="scam", score=80, scam_type="tech_support"):
        return detector.ScamReport(score=score, verdict=verdict, scam_type=scam_type,
                                    channel="test")

    def _llm(self, verdict="scam", scam_type="tech_support", confidence=90):
        return JudgeResult(verdict=verdict, scam_type=scam_type,
                           confidence=confidence, reason="x", model="m")

    def test_agreement_boosts_score(self):
        h = self._heur()
        l = self._llm(confidence=90)
        c = compare(h, l)
        self.assertTrue(c.agree_verdict)
        self.assertTrue(c.agree_type)
        self.assertGreater(c.boost, 0)
        self.assertEqual(c.final_verdict, "scam")

    def test_llm_stricter_takes_over(self):
        h = self._heur(verdict="suspicious", score=30, scam_type="universal")
        l = self._llm(verdict="scam", scam_type="crypto_investment", confidence=95)
        c = compare(h, l)
        self.assertFalse(c.agree_verdict)
        self.assertEqual(c.final_verdict, "scam")
        self.assertIn("stricter", " ".join(c.notes).lower())

    def test_heuristic_stricter_holds(self):
        h = self._heur(verdict="scam", score=90, scam_type="tech_support")
        l = self._llm(verdict="clean", scam_type="unknown", confidence=60)
        c = compare(h, l)
        # we never downgrade below the heuristic
        self.assertEqual(c.final_verdict, "scam")


class FullPipelineTests(unittest.TestCase):

    def test_analyze_full_with_skipped_llm(self):
        # Heuristic alone: "URGENT: pay 999 USD in gift cards now."
        # This produces ~1 universal + 1 payment signal, scoring suspicious.
        msg = "URGENT: pay 999 USD in gift cards now. Don't tell your bank."
        full = detector.analyze_full(msg, use_llm=False)
        # Heuristic should call it suspicious or worse.
        self.assertIn(full.verdict, ("suspicious", "likely_scam", "scam"))
        # When LLM is skipped, we report its verdict as matching the heuristic
        self.assertEqual(full.llm.verdict, full.heuristic.verdict)
        self.assertEqual(full.llm.model, "(skipped)")

    def test_analyze_full_with_mocked_llm(self):
        # The IRS test message: heuristic returns likely_scam / government.
        # LLM mock returns scam / government. They agree on type but differ
        # on verdict strictness — final should be scam (stricter wins).
        body = {"model": "m", "response": json.dumps(
            {"verdict": "scam", "scam_type": "government", "confidence": 88,
             "reason": "IRS threat with gift card payment demand."}), "done": True}
        with mock.patch.object(llm_judge, "_ollama_generate", return_value=body):
            msg = "This is the IRS. Pay 4850 USD in Google Play gift cards or face arrest."
            full = detector.analyze_full(msg, use_llm=True)
        # Heuristic = likely_scam. LLM = scam. Final = scam (stricter).
        self.assertEqual(full.verdict, "scam")
        self.assertEqual(full.scam_type, "government")
        # LLM was stricter → final score should not be lower than heuristic
        self.assertGreaterEqual(full.score, full.heuristic.score)


if __name__ == "__main__":
    unittest.main(verbosity=2)
