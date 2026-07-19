"""
scam_shield.telegram_bot

Telegram bot wrapper. Forward a suspicious message to the bot and it will:

    1. Score the message (heuristic + optional LLM second opinion via Ollama)
    2. Reply with the verdict, score, signals, and entities
    3. Drop the recommended bait questions inline
    4. Optionally start a honeypot session and bridge your messages to it
    5. Optionally generate a full report pack (FTC/IC3/bank/platform)

Setup
-----
    1. Talk to @BotFather on Telegram. /newbot. Copy the token.
    2. Set the env var:  export TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
       (on Windows cmd:  set TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
        on PowerShell:   $env:TELEGRAM_BOT_TOKEN = "123456:ABC-DEF..." )
    3. (Optional) Set SCAMSHIELD_LLM=on to enable the Ollama second opinion.
    4. Run:  python -m scam_shield.telegram_bot

This bot uses Telegram's long-poll getUpdates endpoint, so it has no external
dependencies beyond the Python 3.11+ stdlib (urllib, json).
"""

from __future__ import annotations

import os
import sys
import json
import time
import uuid
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, Optional, Any

from .detector import analyze, analyze_full
from . import playbook as pb
from . import honeypot as hp
from . import report_pack
from . import history as hist_mod


# ---------------------------------------------------------------------------
# Telegram helpers (stdlib only)
# ---------------------------------------------------------------------------

API = "https://api.telegram.org/bot{token}/{method}"


def _api(token: str, method: str, **params) -> Dict:
    """Call a Telegram Bot API method over HTTPS."""
    url = API.format(token=token, method=method)
    data = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=35) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        return {"ok": False, "error": str(e)}


def _send(token: str, chat_id: int, text: str, *,
          parse_mode: Optional[str] = None,
          reply_to: Optional[int] = None) -> Dict:
    # Telegram has a 4096-char limit per message; chunk if needed
    chunks = [text[i:i+4000] for i in range(0, len(text), 4000)] or [""]
    last = None
    for i, chunk in enumerate(chunks):
        last = _api(token, "sendMessage",
                    chat_id=chat_id, text=chunk,
                    parse_mode=parse_mode,
                    reply_to_message_id=reply_to if i == 0 else None)
    return last or {}


# ---------------------------------------------------------------------------
# Per-user state (in-memory; for production wire to sqlite or redis)
# ---------------------------------------------------------------------------

class UserState:
    def __init__(self):
        self.mode: str = "idle"        # idle | honeypot
        self.session: Optional[hp.Session] = None
        self.last_score: Optional[Dict] = None
        self.use_llm: bool = os.environ.get("SCAMSHIELD_LLM", "").lower() in ("1", "on", "true", "yes")
        self.verbose: bool = True       # True = full reply, False = one-line "forward and forget"

    def reset(self):
        if self.session is not None:
            try: self.session.close()
            except Exception: pass
        self.session = None
        self.mode = "idle"


# ---------------------------------------------------------------------------
# Bot commands
# ---------------------------------------------------------------------------

HELP_TEXT = """\
Scam-Shield bot

Commands:
  /start              show this help
  /help               same
  /score <text>       score a message (or just forward it)
  /quiet              one-line replies only ("forward and forget")
  /verbose            full reports (default)
  /questions <type>   show bait questions for a scam type
  /honey <type>       start a honeypot session
                       types: universal, tech_support, government,
                       bank_impersonation, package, romance,
                       job_scam, crypto_investment, lottery, phishing
  /stop               end the honeypot session
  /persona <name>     switch persona (margaret | bob | sam)
  /llm <on|off>       toggle the LLM second opinion (Ollama)
  /report             generate a report pack from the last score
  /demo               run built-in demo
  /types              list scam types

Or just forward a suspicious message and I will score it for you.
Use /quiet first if you want short replies.
"""

DEMO_TEXT = """\
Score demo (paste the suspicious text you got):

  /score Your PayPal account has been limited. Click
  http://paypa1-secure-login.com/verify?id=99 to unlock.

Score a forwarded message: just send it to me.
"""


def _format_score(report) -> str:
    """Format a ScamReport OR FullReport into a Telegram-friendly text block."""
    if hasattr(report, "comparison"):  # FullReport
        lines = [
            f"FINAL verdict: {report.verdict.upper()}   score: {report.score}/100",
            f"FINAL type:    {report.scam_type}",
            f"(heuristic: {report.heuristic.verdict} {report.heuristic.score}/100)",
        ]
        if report.llm and not getattr(report.llm, "error", None):
            lines.append(f"(LLM:       {report.llm.verdict}  {report.llm.confidence}% conf)")
            if report.llm.reason:
                lines.append(f"  reason: {report.llm.reason}")
        heur = report.heuristic
    else:
        lines = [
            f"Verdict: {report.verdict.upper()}   Score: {report.score}/100",
            f"Type:    {report.scam_type}",
        ]
        heur = report
    lines.append("")

    if heur.signals:
        lines.append("Signals:")
        for s in heur.signals[:8]:
            lines.append(f"  - [{s['scam_type']}] {s['category']}  ({s['snippet']!r})")
        lines.append("")

    ents = heur.entities
    if any(ents.values()):
        lines.append("Entities found:")
        for k, v in ents.items():
            if v:
                lines.append(f"  {k:7}: {', '.join(v[:5])}")
        lines.append("")

    if heur.advice:
        lines.append("Advice:")
        for a in heur.advice[:5]:
            lines.append(f"  - {a}")
    return "\n".join(lines)


def _format_one_liner(report) -> str:
    """One-line verdict for /quiet mode (and DM-friendly digests)."""
    if hasattr(report, "comparison"):  # FullReport
        verdict = report.verdict
        score = report.score
        scam_type = report.scam_type
        llm = report.llm
    else:
        verdict = report.verdict
        score = report.score
        scam_type = report.scam_type
        llm = None

    # emoji per verdict
    emoji = {
        "scam":        "🚨",
        "likely_scam": "⚠️",
        "suspicious":  "🤔",
        "clean":       "✅",
    }.get(verdict, "•")
    s = f"{emoji} {verdict.upper()}  {score}/100  ({scam_type})"
    if llm and not getattr(llm, "error", None):
        s += f"   LLM: {llm.verdict} {llm.confidence}%"
    return s


def _format_questions(scam_type: str, n: int = 3) -> str:
    qs = pb.pick_questions(scam_type, n=n, also_universal=True)
    out = [f"Bait questions for {scam_type}:", ""]
    for q in qs:
        out.append(f"  Q: {q.question}")
        out.append(f"  Why: {q.rationale}")
        out.append("")
    return "\n".join(out)


def _run_demo() -> str:
    cases = [
        ("microsoft cold call",
         "URGENT: Microsoft Security has detected a virus. Call +1-888-555-0199 "
         "and download AnyDesk. Pay $299 in gift cards."),
        ("fedex package",
         "FEDEX: Package held at customs. Confirm at https://fedex-redelivery.top/track"),
        ("legit alert",
         "Capital One: A $42.19 charge at TARGET was made on your card ending in 4471."),
    ]
    out = [f"{'CASE':22} {'SCORE':>5}  {'VERDICT':14}  TYPE"]
    out.append("-" * 60)
    for name, m in cases:
        r = analyze(m)
        out.append(f"{name:22} {r.score:>5}  {r.verdict:14}  {r.scam_type}")
    return "\n".join(out)


def _handle_message(token: str, chat_id: int, text: str, state: UserState) -> None:
    text = (text or "").strip()
    if not text:
        return

    # ---- HONEYPOT MODE: relay user messages to the session ----
    if state.mode == "honeypot" and state.session is not None and not text.startswith("/"):
        try:
            reply = state.session.ingest(text)
            _send(token, chat_id, f"[{state.session.persona_name}]\n{reply}")
        except Exception as e:
            _send(token, chat_id, f"Honeypot error: {e}")
            state.reset()
        return

    # ---- COMMANDS ----
    if text in ("/start", "/help"):
        _send(token, chat_id, HELP_TEXT)
        return

    if text == "/demo":
        _send(token, chat_id, _run_demo())
        return

    if text == "/types":
        _send(token, chat_id,
              "Types: " + ", ".join(["universal","tech_support","government",
                                     "bank_impersonation","package","romance",
                                     "job_scam","crypto_investment","lottery","phishing"]))
        return

    if text.startswith("/score"):
        msg = text[len("/score"):].strip()
        if not msg:
            _send(token, chat_id, "Usage: /score <message text>")
            return
        r = analyze_full(msg, channel="telegram", use_llm=state.use_llm)
        state.last_score = r.to_dict()
        if state.verbose:
            _send(token, chat_id, _format_score(r))
            if r.scam_type and r.scam_type != "unknown":
                _send(token, chat_id, _format_questions(r.scam_type, n=3))
        else:
            _send(token, chat_id, _format_one_liner(r))
        try:
            h = hist_mod.History(hist_mod.DEFAULT_PATH)
            h.record(r, text=msg)
            h.close()
        except Exception:
            pass
        return

    if text in ("/quiet", "/q"):
        state.verbose = False
        _send(token, chat_id, "Quiet mode: ON. Replies will be one line.\nUse /verbose to turn off.")
        return

    if text in ("/verbose", "/v"):
        state.verbose = True
        _send(token, chat_id, "Verbose mode: ON. Full reports.\nUse /quiet to turn off.")
        return

    if text.startswith("/llm"):
        parts = text.split(maxsplit=1)
        arg = (parts[1].strip().lower() if len(parts) > 1 else "")
        if arg in ("on", "1", "true", "yes"):
            state.use_llm = True
            _send(token, chat_id, "LLM second opinion: ON")
        elif arg in ("off", "0", "false", "no"):
            state.use_llm = False
            _send(token, chat_id, "LLM second opinion: OFF")
        else:
            _send(token, chat_id,
                  f"LLM second opinion: {'ON' if state.use_llm else 'OFF'}\n"
                  f"Usage: /llm on  or  /llm off\n"
                  f"Requires Ollama running at http://localhost:11434")
        return

    if text == "/report":
        if not state.last_score:
            _send(token, chat_id, "No recent score to report on. Forward a message first.")
            return
        # Reconstruct a ScamReport from the last score dict
        h = hist_mod.ScamReport(score=state.last_score["heuristic"]["score"],
                                 verdict=state.last_score["heuristic"]["verdict"],
                                 scam_type=state.last_score["heuristic"]["scam_type"],
                                 signals=state.last_score["heuristic"]["signals"],
                                 entities=state.last_score["heuristic"]["entities"],
                                 advice=state.last_score["heuristic"]["advice"],
                                 channel=state.last_score["heuristic"]["channel"])
        pack = report_pack.ReportPack.from_report(h)
        # write to a per-user dir under ~/.scam-shield/reports/
        out_dir = os.path.expanduser(f"~/.scam-shield/reports/tg-{chat_id}-{pack.case_id}")
        written = pack.to_files(out_dir)
        _send(token, chat_id,
              f"Report pack {pack.case_id} written to {out_dir}\n"
              f"{len(written)} files. Open INDEX.md first.\n"
              f"Filing checklist is at: {out_dir}\\filing_checklist.txt")
        return

    if text.startswith("/questions"):
        parts = text.split(maxsplit=1)
        if len(parts) < 2:
            _send(token, chat_id, "Usage: /questions <scam_type>\nTry /types")
            return
        try:
            _send(token, chat_id, _format_questions(parts[1].strip(), n=4))
        except Exception as e:
            _send(token, chat_id, f"Error: {e}")
        return

    if text.startswith("/honey"):
        parts = text.split(maxsplit=1)
        scam = parts[1].strip() if len(parts) > 1 else "universal"
        if scam not in {"universal","tech_support","government","bank_impersonation",
                        "package","romance","job_scam","crypto_investment","lottery",
                        "phishing","unknown"}:
            _send(token, chat_id, f"Unknown scam type: {scam}\nTry /types")
            return
        if state.session is not None:
            try: state.session.close()
            except Exception: pass
        state.session = hp.start_session(persona="margaret", scam_type=scam)
        state.mode = "honeypot"
        _send(token, chat_id,
              f"Honeypot active as '{state.session.persona_name}' (type={scam}).\n"
              f"Forward scammer messages to me and I will reply in character.\n"
              f"Use /stop to end.")
        return

    if text == "/stop":
        if state.mode == "honeypot" and state.session is not None:
            state.reset()
            _send(token, chat_id, "Honeypot stopped.")
        else:
            _send(token, chat_id, "No active honeypot session.")
        return

    if text.startswith("/persona"):
        parts = text.split(maxsplit=1)
        if len(parts) < 2:
            _send(token, chat_id, "Usage: /persona <margaret|bob|sam>")
            return
        name = parts[1].strip()
        if name not in hp.PERSONAS:
            _send(token, chat_id, f"Unknown persona. Choose from: {', '.join(hp.PERSONAS)}")
            return
        if state.session is None:
            state.session = hp.start_session(persona=name, scam_type="universal")
        else:
            state.session.persona = hp.PERSONAS[name]
            state.session.persona_name = hp.PERSONAS[name]["name"]
        _send(token, chat_id, f"Persona switched to {name}.")
        return

    # ---- DEFAULT: treat the message as a suspicious text to score ----
    r = analyze_full(text, channel="telegram", use_llm=state.use_llm)
    state.last_score = r.to_dict()
    if state.verbose:
        _send(token, chat_id, _format_score(r))
        if r.scam_type and r.scam_type != "unknown":
            _send(token, chat_id, _format_questions(r.scam_type, n=3))
    else:
        _send(token, chat_id, _format_one_liner(r))
    try:
        h = hist_mod.History(hist_mod.DEFAULT_PATH)
        h.record(r, text=text)
        h.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Long-poll loop
# ---------------------------------------------------------------------------

def run(token: Optional[str] = None) -> int:
    token = token or os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        print("ERROR: set TELEGRAM_BOT_TOKEN (env var) before running.")
        print("       Get one from @BotFather on Telegram.")
        return 1

    me = _api(token, "getMe")
    if not me.get("ok"):
        print(f"ERROR: Telegram getMe failed: {me}")
        return 1
    bot_name = me["result"].get("username", "<unknown>")
    print(f"Scam-Shield bot running as @{bot_name}   (Ctrl-C to stop)")

    states: Dict[int, UserState] = {}
    offset: Optional[int] = None
    while True:
        try:
            params = {"timeout": 30, "allowed_updates": "[\"message\"]"}
            if offset is not None:
                params["offset"] = offset
            resp = _api(token, "getUpdates", **params)
            if not resp.get("ok"):
                time.sleep(2); continue
            for upd in resp.get("result", []):
                offset = upd["update_id"] + 1
                msg = upd.get("message") or {}
                chat = msg.get("chat") or {}
                chat_id = chat.get("id")
                text = msg.get("text") or msg.get("caption") or ""
                if not chat_id:
                    continue
                state = states.setdefault(chat_id, UserState())
                _handle_message(token, chat_id, text, state)
        except KeyboardInterrupt:
            print("\nStopping.")
            return 0
        except Exception as e:
            print(f"loop error: {e}", file=sys.stderr)
            time.sleep(2)


if __name__ == "__main__":
    sys.exit(run())
