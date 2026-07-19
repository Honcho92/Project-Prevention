# Scam-Shield — Operator Guide

One-page reference for everything in the box.

## What's in the box

| Tool                | What it does                                                       | Where to run |
|---------------------|--------------------------------------------------------------------|--------------|
| Question Playbook   | 35+ bait questions, hand-tuned by scam type, with rationale       | phone, anywhere |
| Detector            | Heuristic scorer (0-100) + verdict + entity extraction             | CLI / Python |
| LLM Judge           | Local Ollama second opinion (qwen2.5-coder:7b, ~1s)                 | CLI / Python |
| Honeypot            | Auto-reply persona that wastes a scammer's time, logs evidence    | CLI / Telegram |
| Telegram bot        | All of the above, on your phone                                    | phone |
| `/quiet` mode       | One-line replies, "forward and forget"                              | Telegram bot |
| Agent loop          | Background watcher — auto-files report packs, sends DM            | cron / scheduled |
| Weekly digest       | Sunday-night summary DM of the week's activity                     | cron |
| Chrome extension    | Scores every page you load, offline, badge on toolbar               | browser |
| Report pack         | Auto-generates 9 files ready to file with FTC/IC3/bank/platform    | CLI / Telegram |
| History DB          | SQLite of every report, full-text search, stats                    | CLI |

Zero external dependencies. Pure Python 3.11+ stdlib.
Ollama is the only optional external service (for the LLM judge).

## Layer 0 — Quick start for the three automated pieces

### 1. Agent loop (the "AI in the background" piece)

The agent loop reads the history DB every N seconds, picks up unprocessed
reports, runs the full pipeline (heuristic + LLM), and:
- For `scam` / `likely_scam`: auto-generates a report pack to
  `~/.scam-shield/reports/auto-<ts>-<case>/` and DMs you a one-liner.
- For `suspicious`: DMs you a one-liner.
- For `clean`: logs only, no notification.

Run it once:
```sh
cd C:\Users\folle\scam-shield
& "C:\Users\folle\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe" -m scam_shield.agent_loop
```

Or watch forever, polling every 60 seconds:
```sh
& "C:\Users\folle\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe" -m scam_shield.agent_loop --watch --interval 60
```

To get Telegram DMs from the agent, set `SCAMSHIELD_NOTIFY_CHAT_ID` to your
chat id (forward any message to @userinfobot on Telegram to find yours).

### 2. Weekly digest (Sunday-night summary)

```sh
& "C:\Users\folle\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe" -m scam_shield.digest --send
```

Prints a text summary AND sends it through your bot. Looks like:

```
Scam-Shield weekly digest
  2026-07-12  →  2026-07-19
  Total forwards: 14

By verdict:
  scam               3  ##
  likely_scam        2  ##
  suspicious         4  ####
  clean              5  #####

Top scam types:
  tech_support           3
  package                2
  romance                1

Phones seen:
  +1-888-555-0199              ×2
  +1-800-555-1234              ×1

Worst offenders this period:
  #41  SCAM 90/100 (tech_support)
  #38  SCAM 84/100 (package)
  #35  LIKELY_SCAM 72/100 (romance)

Action: consider running /report to file with the FTC and your bank.
```

### 3. Schedule both with Windows Task Scheduler

Use the helper script `setup_scheduler.ps1` (one-time setup), or manually:

```powershell
$action = New-ScheduledTaskAction `
    -Execute "C:\Users\folle\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe" `
    -Argument "-m scam_shield.agent_loop" `
    -WorkingDirectory "C:\Users\folle\scam-shield"

# every 5 minutes
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 5) `
    -RepetitionDuration (New-TimeSpan -Days 3650)

Register-ScheduledTask -TaskName "ScamShield Agent" `
    -Action $action -Trigger $trigger `
    -User $env:USERNAME -RunLevel Highest
```

The bot keeps running in the foreground (or as a service via `nssm` if you
want it truly headless). The agent loop runs as a scheduled task that wakes
up, processes whatever the bot has recorded, goes back to sleep.

## Layer 1 — Question Playbook (no build, use today)

Drop these into any conversation as casual asides.

### Universal (works on anything)
- "What time zone are you in right now?"
- "What's your employee / agent / case number?"
- "Hold on, let me conference in my buddy who works at [company] — your full name and direct number?"
- "I'll call you back at your office line. What's the number?"
- "Quick — spell your last name."
- "What did we talk about last time?"

### Tech support ("Microsoft / Apple / Geek Squad")
- "Which support tier — 1, 2, or 3?"
- "What's the badge / technician ID on your profile?"
- "Which datacenter is my case logged in — East US, West EU, Asia Pacific?"
- "What's the Event Viewer entry number you saw?"

### Government ("IRS / SSA / FBI")
- "Which field office is this out of?"
- "What's the certified mail number on the notice?"
- "Which tax form did I fail to file?"

### Bank ("fraud department")
- "What's the last 4 of my account you see on file?"
- "What's the merchant name on the suspicious charge YOU flagged?"
- "What's the case number for when I call the number on the back of my card?"

### Package ("USPS / UPS / FedEx")
- "What's the full tracking number on the label?"
- "Which hub is it stuck at?"
- "What are the weight and dimensions on the label?"

### Romance
- "Send a selfie holding today's paper with the date visible."
- "Quick voice note — just say good morning."
- "What's the name of the bar / restaurant on the corner by your place?"

### Job / recruiter
- "What's the company EIN?"
- "Send the offer letter from a company email, not Gmail."
- "Who reports to the hiring manager?"

### Crypto / investment
- "What's your FINRA license number?"
- "Which state are you registered to sell securities in?"
- "Can I talk to one recent investor first?"

## Layer 2 — CLI (Python, works offline)

```sh
cd C:\Users\folle\scam-shield
PYTHONPATH=. python -m scam_shield demo
PYTHONPATH=. python -m scam_shield analyze "PASTE MESSAGE HERE"
PYTHONPATH=. python -m scam_shield analyze-full "PASTE MESSAGE HERE"   # also asks Ollama
PYTHONPATH=. python -m scam_shield analyze - < suspicious.txt
PYTHONPATH=. python -m scam_shield questions romance
PYTHONPATH=. python -m scam_shield honey romance --persona margaret
PYTHONPATH=. python -m scam_shield report "PASTE MESSAGE HERE" --out ./my-case
PYTHONPATH=. python -m scam_shield history list
PYTHONPATH=. python -m scam_shield history search "AnyDesk"
PYTHONPATH=. python -m scam_shield history stats
```

Score a message and get:

- 0-100 score
- verdict (clean / suspicious / likely_scam / scam)
- scam type (tech_support, government, bank_impersonation, package, romance, job_scam, crypto_investment, lottery, phishing)
- every signal that contributed (transparent, with snippets)
- phones, emails, URLs, money amounts found
- tailored advice

`analyze-full` adds a local Ollama second opinion (~1.3s after warmup).
The final verdict is the stricter of the two.

`report --out <dir>` generates 9 files ready to file with the FTC, IC3, your
bank, and the host platform. The directory has an INDEX.md explaining each.

## Layer 3 — Interactive honeypot

The bot auto-replies in character (default: "Margaret", an older retired teacher
who is sweet, polite, and slow to type). Every few turns it asks a bait question
from the playbook. Everything is logged to SQLite for evidence.

```sh
PYTHONPATH=. python -m scam_shield honey romance --persona margaret
```

Then paste scammer messages line by line. End with `quit` to see the full
transcript and all evidence collected.

Three personas available: `margaret` (default), `bob` (older vet), `sam` (busy
young professional). Switch mid-session with `/persona <name>` in Telegram.

## Layer 4 — Telegram bot (use on your phone)

### One-time setup
1. Open Telegram, talk to **@BotFather**. Send `/newbot`. Pick a name and a
   username. Copy the token it gives you.
2. Set the env var:
   - PowerShell:  `$env:TELEGRAM_BOT_TOKEN = "123456:ABC-DEF..."`
   - cmd:         `set TELEGRAM_BOT_TOKEN=123456:ABC-DEF...`
3. (Optional) Set `$env:SCAMSHIELD_LLM = "on"` to enable the local Ollama
   second opinion in bot replies.
4. Run:  `PYTHONPATH=. python -m scam_shield.telegram_bot`

### Commands
- `/start`              help
- `/score <text>`       score a message (full heuristic + LLM if on)
- `/quiet`              one-line replies only ("forward and forget")
- `/verbose`            full reports (default)
- `/questions <type>`   bait questions for a scam type
- `/honey <type>`       start a honeypot session
- `/stop`               end the session
- `/persona <name>`     switch persona
- `/llm <on|off>`       toggle the LLM second opinion
- `/report`             generate a full FTC/IC3/bank report pack
- `/demo`               run the built-in test cases
- `/types`              list scam types

### Daily use
1. Get a suspicious text/email/DM.
2. Forward it to the bot (or paste + `/score`).
3. Get a verdict + playbook.
4. Decide: ignore, escalate to the real institution, `/honey <type>` to
   start a counter-conversation, or `/report` to file.

## Layer 5 — Chrome extension (use while browsing)

1. Open `chrome://extensions` in Chrome
2. Toggle **Developer mode** on
3. Click **Load unpacked** and select `C:\Users\folle\scam-shield\chrome-extension`
4. Pin the Scam-Shield icon to your toolbar

Every page you load gets scored. If it triggers `suspicious` or worse, the
toolbar icon shows a colored badge. Click the icon to see signals, entities,
and the recommended bait questions.

The extension is 100% offline. Nothing leaves your browser.

## Verdict cheat-sheet

| Score    | Verdict        | What to do                                            |
|----------|----------------|-------------------------------------------------------|
| 0-24     | clean          | Probably fine. Stay alert.                            |
| 25-49    | suspicious     | Slow down. Verify before acting.                      |
| 50-74    | likely_scam    | Don't engage. Report.                                 |
| 75+      | scam           | Block, report, optionally engage with the playbook.   |

## Where things are stored

- Honeypot session DB: `~/.scam-shield/honeypot.sqlite`
- Report history:      `~/.scam-shield/history.sqlite` (auto-migrated on open)
- Report packs:        `~/.scam-shield/reports/<case-id>/`
- All evidence is local. Nothing leaves your machine (except the optional
  LLM call to local Ollama, and the optional Telegram API call to your bot).

## Optional env vars (set these once)

- `TELEGRAM_BOT_TOKEN`        — required for the bot / agent DM / digest
- `SCAMSHIELD_LLM`            — "on" enables the Ollama second opinion
- `SCAMSHIELD_NOTIFY_CHAT_ID` — your Telegram chat id, for agent DM / digest
  (forward any message to @userinfobot on Telegram to find your id)

## Helper scripts

- `check_history.py`          — show + reset the history DB
- `test_cleanup.py`           — clean auto-packs
- `make_icons.py`             — regenerate the Chrome extension icons
- `test_real_report.py`       — write a sample report pack to `reports/sample-pack/`
- `test_migration.py`         — verify history DB migration works
- `test_e2e_llm.py`           — end-to-end test of heuristic + LLM
- `test_js_detector.js`       — parity test for the Chrome extension's JS detector

## Reporting a scam

After scoring, the most useful places to file:

- USA — ReportFraud.ftc.gov
- UK   — actionfraud.police.uk
- CA   — antifraudcentre-centreantifraude.ca
- AU   — scamwatch.gov.au
- EU   — europol.europa.eu (most countries have a national CERT)

You can also post receipts to r/Scams on Reddit — community is great at
identifying recurring scam rings.

## Adding new patterns

`scam_shield/detector.py` has a `SCAM_PATTERNS` bank at the top. Each entry is:

```python
("scam_type", "human-readable category", weight_int, compiled_regex)
```

Add, tweak weights, or add a new scam_type bucket. Restart and the new pattern
is live. Same for `BRAND_DOMAINS` (typo domains of well-known brands).

## Testing

```sh
PYTHONPATH=. python -m unittest discover -s tests -v
```

29 tests: 21 detector / playbook / honeypot, 8 telegram. All pass.
