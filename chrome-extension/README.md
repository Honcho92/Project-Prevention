# Scam-Shield Chrome Extension

A Manifest V3 extension that scores every web page you load against the same
heuristic engine the Python package uses. 100% offline — nothing leaves the
browser.

## What it does

* Content script runs on every page after load, scores the visible text
* If the page scores `suspicious` or worse, the toolbar icon gets a badge:
  * `..`  yellow   = suspicious
  * `?`   amber    = likely_scam
  * `!!`  red      = scam
* Click the icon to see the full report, signals, entities, and bait questions
* Popup has a manual paste-and-score field too

## Install (developer mode)

1. Open Chrome and go to `chrome://extensions`
2. Toggle **Developer mode** on (top right)
3. Click **Load unpacked**
4. Select the `chrome-extension/` folder from this repo:
   `C:\Users\folle\scam-shield\chrome-extension\`
5. Pin the Scam-Shield icon to your toolbar (puzzle icon → pin)

The extension is now active. Open any page and watch the badge.

## Files

```
chrome-extension/
  manifest.json      Manifest V3, requests activeTab + scripting + storage
  background.js      Service worker, holds per-tab scores, sets badge
  content.js         Runs on every page, scores text, posts to background
  detector.js        Port of the Python heuristic engine to vanilla JS
  popup.html         The toolbar popup UI
  popup.css          Popup styles
  popup.js           Popup behavior
  icons/
    icon-16.png      16x16 shield
    icon-48.png      48x48 shield
    icon-128.png     128x128 shield
```

## Verify

Open any of these in a tab and watch the badge:

* `https://www.google.com/search?q=urgent+pay+gift+cards+irs` (any search
  results page with "urgent pay gift cards irs" in the title will likely
  score `suspicious`+)
* `https://www.fedex.com/` (clean, no badge)
* A known scam text from your own history: forward a screenshot of a scam
  message into Google Lens or copy-paste the text into a web page and load it.

## Keep in sync with the Python engine

When you change `scam_shield/detector.py`, mirror the changes to
`chrome-extension/detector.js`. The JS parity test
(`tests/test_js_parity.py`) catches drift: it runs the same test corpus
through both engines and asserts identical scores/verdicts/types.

```sh
PYTHONPATH=. python -m unittest tests.test_js_parity -v
```

## Permissions

* `activeTab`   — to run content scripts on the current tab
* `scripting`   — required for content script injection
* `storage`     — future use: persist your whitelist / custom questions
* `<all_urls>`  — needed so the content script can run on any site

The extension does NOT make any network requests. Open DevTools on any page
and the Network tab will show zero traffic from Scam-Shield.
