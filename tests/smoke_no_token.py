"""Smoke test: bot refuses to start with no token."""
import os
import sys

# Ensure no token
os.environ.pop("TELEGRAM_BOT_TOKEN", None)

# Import
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from scam_shield import telegram_bot

rc = telegram_bot.run()
print(f"exit code: {rc}")
assert rc == 1, f"expected rc=1, got {rc}"
print("OK: bot refused to start without a token.")
