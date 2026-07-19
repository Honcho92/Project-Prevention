# Contributing to scam-shield

Thanks for helping. This is a small project so the rules are simple.

## Adding a new scam pattern

1. Open `scam_shield/detector.py`
2. Find the `SCAM_PATTERNS` list near the top
3. Add a new entry as a tuple: `(scam_type, category, weight, compiled_regex)`
4. Mirror the same change to `chrome-extension/detector.js` (look for the
   same `SCAM_PATTERNS` array in JS)
5. Add a test case in `tests/test_scam_shield.py` with a real-looking example
6. Run the suite: `PYTHONPATH=. python -m unittest discover -s tests`
7. Run the JS parity test: `PYTHONPATH=. python -m unittest tests.test_js_parity -v`

Pick weights thoughtfully:
- 5-10:  soft signals (e.g. urgency language, generic greetings)
- 15-25:  strong signals (e.g. mentions a brand impersonated, asks for money)
- 30-40:  smoking guns (e.g. explicit gift card demand, threats of arrest)

If you find a new scam type not yet in the priority list, add it there too
(search for `PRIORITY` in detector.py and chrome-extension/detector.js).

## Adding a new playbook question

1. Open `scam_shield/playbook.py`
2. Find the `QUESTIONS` list
3. Add a new `Question(...)` with id, scam_types, question, rationale, followups
4. Add the same question to `chrome-extension/detector.js` (the `PLAYBOOK` object)
5. Add a test in `tests/test_scam_shield.py` that asserts your question shows
   up for the right scam type

## Adding a new scam type

If you're adding a brand-new bucket of scam (e.g. "ai_investment_pitch"):

1. In `scam_shield/detector.py`:
   - Add the new type to `SCAM_PATTERNS` entries
   - Add it to the `PRIORITY` list
   - Add advice to `_advice_for()` for that type
2. In `chrome-extension/detector.js`:
   - Mirror the same pattern
   - Add the type to `PRIORITY`
   - Add the advice
3. In tests:
   - `tests/test_scam_shield.py`: add a test case that uses a real example
   - `tests/test_js_parity.py`: add the same example (this verifies both
     engines agree)

## Reporting a false positive or false negative

Open an issue with:
1. The original text (or screenshot if it's a webpage)
2. What the detector said (verdict, score, type)
3. What you think it should have said
4. Which signals fired (from the report's `signals` list)

False positives hurt user trust. False negatives are dangerous. Either is
worth a fix.

## Code style

- Python: PEP 8, ~100 char line length, type hints where they help
- JS: standard modern style, ~100 char line length, no frameworks
- Tests: `unittest` only, no pytest, no external test deps
- Every public function gets a docstring
- Comments explain *why*, not *what*

## Commit messages

Short and specific. `Add lottery pattern for Microsoft Award scam`,
`Fix crypto giveaway misclassified as government`, `Migrate history DB
schema`. Not `Update detector.py`.

## Before you open a PR

```bash
PYTHONPATH=. python -m unittest discover -s tests
PYTHONPATH=. python -m scam_shield demo
node test_js_detector.js   # parity test
```

All three should pass. The demo should show the same output as before.
The JS parity test should print identical scores to the Python demo.
