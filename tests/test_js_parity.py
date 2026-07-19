"""Regression: assert the JS detector produces the same scores as the Python one.

We shell out to node, which loads detector.js, runs the same test corpus,
and prints a JSON array of {name, score, verdict, scam_type}. We parse it
and compare to the Python detector.
"""
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from scam_shield import detector

JS_RUNNER = os.path.join(HERE, "test_js_detector.js")


CASES = [
    ("microsoft cold call",
     "URGENT: Microsoft Security has detected a virus. Call +1-888-555-0199 "
     "and download AnyDesk. Pay 299 USD in gift cards."),
    ("irs warrant scam",
     "This is Officer Daniels from the Internal Revenue Service. "
     "A warrant has been issued for your arrest due to unpaid back taxes. "
     "Pay 4850 USD in Google Play gift cards within 30 minutes. Do not tell your family or your bank."),
    ("fedex package",
     "FEDEX: Your package is being held at customs. A small "
     "redelivery fee of 1.99 USD is required. Confirm at "
     "https://fedex-redelivery.top/track?id=9921 to avoid return."),
    ("legit package",
     "Hi Zach, your Amazon order #112-3344556-7788990 has shipped! "
     "Track at amazon.com/orders. Estimated delivery: Tuesday."),
    ("legit banking alert",
     "Capital One: A 42.19 USD charge at TARGET T-1234 was made on "
     "your card ending in 4471. If this was not you, call the "
     "number on the back of your card. Reply HELP for help."),
]


@unittest.skipUnless(
    subprocess.run(["node", "--version"], capture_output=True).returncode == 0,
    "node not installed"
)
class JsParityTests(unittest.TestCase):

    def setUp(self):
        # The existing test_js_detector.js prints a table, not JSON.
        # We re-run it through a small inline shim. On Windows we need
        # to forward-slash the path or escape backslashes for the JS string.
        det_path = os.path.join(ROOT, "chrome-extension", "detector.js").replace("\\", "/")
        cases_json = json.dumps(CASES)
        self.shim = os.path.join(HERE, "test_js_detector_json.js")
        shim_src = (
            "const { analyzeText } = (function () {\n"
            "  const fs = require('fs');\n"
            f"  const src = fs.readFileSync('{det_path}', 'utf8');\n"
            "  const m = { exports: {} };\n"
            "  new Function('module', 'self', 'window', "
            "              src + '\\nmodule.exports = { analyzeText, pickQuestions };')(m);\n"
            "  return m.exports;\n"
            "})();\n"
            f"const cases = {cases_json};\n"
            "const out = cases.map(([name, msg]) => {\n"
            "  const r = analyzeText(msg);\n"
            "  return { name, score: r.score, verdict: r.verdict, scam_type: r.scam_type };\n"
            "});\n"
            "console.log('__JSON_START__' + JSON.stringify(out) + '__JSON_END__');\n"
        )
        with open(self.shim, "w") as f:
            f.write(shim_src)

    def tearDown(self):
        try: os.unlink(self.shim)
        except OSError: pass

    def _js_results(self):
        r = subprocess.run(["node", self.shim], capture_output=True, text=True, timeout=15)
        self.assertEqual(r.returncode, 0, f"node failed: {r.stderr}")
        out = r.stdout
        i = out.find("__JSON_START__")
        j = out.find("__JSON_END__")
        self.assertGreater(i, -1)
        return json.loads(out[i + len("__JSON_START__"):j])

    def test_python_and_js_agree(self):
        js = self._js_results()
        for (name, msg), jsrow in zip(CASES, js):
            with self.subTest(name=name):
                py = detector.analyze(msg)
                self.assertEqual(jsrow["name"], name)
                self.assertEqual(jsrow["score"], py.score,
                                 f"score mismatch for {name}: js={jsrow['score']} py={py.score}")
                self.assertEqual(jsrow["verdict"], py.verdict,
                                 f"verdict mismatch for {name}")
                self.assertEqual(jsrow["scam_type"], py.scam_type,
                                 f"type mismatch for {name}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
