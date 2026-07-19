"""
scam_shield.agent_loop

A background watcher that runs the full Scam-Shield pipeline for every
unprocessed report in the history DB.

Designed to be invoked from cron, Windows Task Scheduler, or a long-lived
process. Each invocation:

    1. Reads up to N unprocessed reports from history.sqlite
    2. For each, runs analyze_full() (heuristic + LLM second opinion)
    3. Decides an action based on the verdict:
         scam / likely_scam  →  auto-generate a report pack to disk,
                                 DM the user the filing checklist path
         suspicious          →  DM the user a one-line verdict + suggestion
         clean               →  log only, no notification
    4. Sends DM(s) through the Telegram bot
    5. Marks each report processed

Two operational modes:

    python -m scam_shield.agent_loop              -- one-shot run, then exit
    python -m scam_shield.agent_loop --watch      -- loop forever, sleep N sec
    python -m scam_shield.agent_loop --watch --interval 60
"""

from __future__ import annotations

import os
import sys
import time
import json
import argparse
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Iterable

from .detector import analyze, analyze_full, ScamReport
from . import history as hist_mod
from . import report_pack
from . import playbook as pb


# ---------------------------------------------------------------------------
# Telegram notifier (very small, no dependency on the bot's long-poll loop)
# ---------------------------------------------------------------------------

def _send_telegram(token: str, chat_id: int, text: str) -> bool:
    """Send one message via Telegram Bot API. Returns True on success."""
    if not token or not chat_id:
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    # Telegram caps at 4096; chunk if needed
    chunks = [text[i:i+4000] for i in range(0, len(text), 4000)] or [""]
    try:
        for chunk in chunks:
            data = urllib.parse.urlencode({
                "chat_id": chat_id, "text": chunk, "parse_mode": "",
            }).encode("utf-8")
            req = urllib.request.Request(url, data=data, method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                pass
        return True
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        print(f"  telegram send failed: {e}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Action policy
# ---------------------------------------------------------------------------

def _one_liner(report) -> str:
    """Compact verdict for SMS-style notifications."""
    if hasattr(report, "comparison"):
        verdict = report.verdict
        score = report.score
        scam_type = report.scam_type
    else:
        verdict = report.verdict
        score = report.score
        scam_type = report.scam_type
    emoji = {
        "scam": "🚨", "likely_scam": "⚠️",
        "suspicious": "🤔", "clean": "✅",
    }.get(verdict, "•")
    return f"{emoji} {verdict.upper()}  {score}/100  ({scam_type})"


def _act_on_report(report_row: Dict, *,
                    telegram_token: Optional[str] = None,
                    notify_chat_id: Optional[int] = None,
                    auto_pack: bool = True,
                    out_root: Optional[str] = None) -> Dict:
    """
    Apply the action policy to one report. Returns a summary dict.
    Never raises — every failure is captured in the result.
    """
    rid = report_row["id"]
    text = report_row["text"]
    verdict = report_row["verdict"]
    scam_type = report_row["scam_type"]
    score = report_row["score"]
    summary = {
        "report_id": rid,
        "verdict": verdict,
        "score": score,
        "scam_type": scam_type,
        "action_taken": None,
        "pack_path": None,
        "notified": False,
        "error": None,
    }

    try:
        # Re-run analyze_full to get the FullReport (heuristic + LLM)
        full = analyze_full(text, channel=report_row.get("channel") or "agent_loop",
                            use_llm=os.environ.get("SCAMSHIELD_LLM", "").lower() in
                                  ("1", "on", "true", "yes"))

        # ---- action by verdict ----
        if verdict in ("scam", "likely_scam") and auto_pack:
            # Re-construct a ScamReport from the row so the report pack module can use it
            heur = full.heuristic
            pack = report_pack.ReportPack.from_report(full)
            ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            out_dir = out_root or os.path.expanduser("~/.scam-shield/reports")
            pack_dir = os.path.join(out_dir, f"auto-{ts}-{pack.case_id}")
            written = pack.to_files(pack_dir)
            summary["action_taken"] = "auto_report_pack"
            summary["pack_path"] = pack_dir

            if telegram_token and notify_chat_id:
                msg = (
                    f"🚨 Auto-flagged: {verdict.upper()} {score}/100 ({scam_type})\n"
                    f"Report pack written: {pack_dir}\n"
                    f"{len(written)} files. Filing checklist: {pack_dir}\\filing_checklist.txt\n"
                    f"Use /honey {scam_type} to start a counter-conversation, or /score again to inspect."
                )
                summary["notified"] = _send_telegram(telegram_token, notify_chat_id, msg)

        elif verdict == "suspicious":
            if telegram_token and notify_chat_id:
                msg = f"🤔 Suspicious {score}/100 ({scam_type})\n{_one_liner(full)}"
                summary["notified"] = _send_telegram(telegram_token, notify_chat_id, msg)
            summary["action_taken"] = "notified_suspicious"

        else:
            # clean — no notification, just log
            summary["action_taken"] = "no_action"

    except Exception as e:
        summary["error"] = str(e)
        summary["action_taken"] = "error"

    return summary


# ---------------------------------------------------------------------------
# Loop
# ---------------------------------------------------------------------------

def run_once(*, db_path: str = hist_mod.DEFAULT_PATH,
             telegram_token: Optional[str] = None,
             notify_chat_id: Optional[int] = None,
             channel_filter: Optional[str] = None,
             batch_size: int = 25,
             auto_pack: bool = True,
             out_root: Optional[str] = None) -> List[Dict]:
    """Process up to `batch_size` unprocessed reports. Returns the summaries."""
    if not os.environ.get("TELEGRAM_BOT_TOKEN") and not telegram_token:
        # default: pull from env
        telegram_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    h = hist_mod.History(db_path)
    try:
        rows = h.unprocessed_reports(channel=channel_filter, limit=batch_size)
        if not rows:
            return []
        results: List[Dict] = []
        for row in rows:
            res = _act_on_report(row, telegram_token=telegram_token,
                                 notify_chat_id=notify_chat_id,
                                 auto_pack=auto_pack,
                                 out_root=out_root)
            h.mark_processed(row["id"])
            results.append(res)
            print(f"  #{row['id']}  {res['verdict']:14}  {res['action_taken']:24}  "
                  f"{res['pack_path'] or ''}")
        return results
    finally:
        h.close()


def run_watch(*, db_path: str = hist_mod.DEFAULT_PATH,
              telegram_token: Optional[str] = None,
              notify_chat_id: Optional[int] = None,
              channel_filter: Optional[str] = None,
              batch_size: int = 25,
              interval: int = 60,
              auto_pack: bool = True,
              out_root: Optional[str] = None) -> int:
    """Loop forever, processing new reports every `interval` seconds."""
    print(f"Scam-Shield agent loop watching {db_path}  (interval={interval}s, "
          f"channel={channel_filter or 'all'}, batch={batch_size})")
    print("Ctrl-C to stop.")
    try:
        while True:
            results = run_once(db_path=db_path, telegram_token=telegram_token,
                               notify_chat_id=notify_chat_id,
                               channel_filter=channel_filter,
                               batch_size=batch_size,
                               auto_pack=auto_pack, out_root=out_root)
            if results:
                print(f"  [{datetime.now(timezone.utc).isoformat()[:19]}] processed {len(results)}")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopping.")
        return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="scam_shield.agent_loop",
        description="Background watcher that processes unprocessed Scam-Shield reports.",
    )
    p.add_argument("--watch", action="store_true",
                   help="loop forever, polling every --interval seconds")
    p.add_argument("--interval", type=int, default=60,
                   help="polling interval in seconds (default 60)")
    p.add_argument("--db", default=hist_mod.DEFAULT_PATH,
                   help="history sqlite path")
    p.add_argument("--channel", default=None,
                   help="only process reports from this channel (e.g. telegram)")
    p.add_argument("--batch", type=int, default=25,
                   help="max reports per batch")
    p.add_argument("--notify-chat-id", type=int, default=None,
                   help="Telegram chat id to DM notifications to. "
                        "Defaults to env SCAMSHIELD_NOTIFY_CHAT_ID")
    p.add_argument("--no-pack", action="store_true",
                   help="don't auto-generate report packs")
    p.add_argument("--out", default=None,
                   help="root directory for auto-generated report packs")
    args = p.parse_args(argv)

    telegram_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    notify_chat_id = (args.notify_chat_id or
                      int(os.environ.get("SCAMSHIELD_NOTIFY_CHAT_ID", "0")) or None)

    if args.watch:
        return run_watch(db_path=args.db, telegram_token=telegram_token,
                         notify_chat_id=notify_chat_id,
                         channel_filter=args.channel, batch_size=args.batch,
                         interval=args.interval,
                         auto_pack=not args.no_pack,
                         out_root=args.out)

    results = run_once(db_path=args.db, telegram_token=telegram_token,
                       notify_chat_id=notify_chat_id,
                       channel_filter=args.channel, batch_size=args.batch,
                       auto_pack=not args.no_pack,
                       out_root=args.out)
    if not results:
        print("(nothing to process)")
        return 0
    print(f"\nProcessed {len(results)} report(s):")
    for r in results:
        line = f"  #{r['report_id']:>4}  {r['verdict']:14}  score={r['score']:>3}  "
        line += f"action={r['action_taken']}"
        if r.get("pack_path"):
            line += f"\n            pack: {r['pack_path']}"
        if r.get("notified"):
            line += f"\n            notified: True"
        if r.get("error"):
            line += f"\n            error: {r['error']}"
        print(line)
    return 0


def glob_packs(root: Optional[str] = None) -> List[str]:
    """Return all auto-* pack directories under root (default: ~/.scam-shield/reports)."""
    import glob
    base = root or os.path.expanduser("~/.scam-shield/reports")
    return glob.glob(os.path.join(base, "auto-*"))


if __name__ == "__main__":
    sys.exit(main())
