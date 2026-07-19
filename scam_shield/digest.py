"""
scam_shield.digest

Builds a weekly / daily / per-N-reports digest of recent activity and sends
it through the Telegram bot.

Public API
----------
    build_digest(history, *, since=None, until=None) -> dict
        Returns the digest payload (counts, top types, top entities, examples).

    format_digest(d) -> str
        Renders the digest as plain text ready to send.

    send_digest(telegram_token, chat_id, digest) -> bool
        Sends the digest via Telegram Bot API.
"""

from __future__ import annotations

import os
import sys
import json
import urllib.request
import urllib.error
import urllib.parse
from collections import Counter
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Iterable

from . import history as hist_mod
from .detector import analyze


def _bucket_verdict(verdict: str) -> str:
    return verdict  # already normalized


def _top_entities(rows: List[Dict], kind: str, k: int = 5) -> List[tuple]:
    """Find the most-common phones / emails / urls across the rows."""
    counter: Counter = Counter()
    for r in rows:
        h = hist_mod.History(hist_mod.DEFAULT_PATH)
        try:
            full = h.get_report(r["id"])
        finally:
            h.close()
        if not full:
            continue
        for v in (full.get("entities") or {}).get(kind, []):
            counter[v] += 1
    return counter.most_common(k)


def build_digest(history: hist_mod.History, *,
                 since: Optional[str] = None,
                 until: Optional[str] = None) -> Dict:
    """
    Build a digest of reports between `since` and `until` (ISO strings).
    If both None, defaults to the last 7 days.
    """
    if until is None:
        until = datetime.now(timezone.utc).isoformat()
    if since is None:
        since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()

    # We don't have a direct "between" helper, so we use list_reports(since=)
    # then filter by until in Python.
    rows = history.list_reports(limit=2000, since=since)
    rows = [r for r in rows if r["created_at"] <= until]

    if not rows:
        return {
            "since": since, "until": until, "total": 0,
            "by_verdict": {}, "by_scam_type": [],
            "top_phones": [], "top_emails": [], "top_urls": [],
            "examples": [],
        }

    by_verdict = Counter(r["verdict"] for r in rows)
    by_type = Counter(r["scam_type"] for r in rows if r["scam_type"])
    top_phones = _top_entities(rows, "phones", 5)
    top_emails = _top_entities(rows, "emails", 5)
    top_urls = _top_entities(rows, "urls", 5)

    # top 3 examples (highest-scoring)
    examples = sorted(rows, key=lambda r: -r["score"])[:3]

    return {
        "since": since,
        "until": until,
        "total": len(rows),
        "by_verdict": dict(by_verdict),
        "by_scam_type": by_type.most_common(),
        "top_phones": top_phones,
        "top_emails": top_emails,
        "top_urls": top_urls,
        "examples": examples,
    }


def format_digest(d: Dict) -> str:
    """Render digest as plain text, ready to send through any channel."""
    if d["total"] == 0:
        return (
            f"Scam-Shield weekly digest\n"
            f"  {d['since'][:10]}  →  {d['until'][:10]}\n"
            f"  Nothing forwarded this period. Stay alert."
        )

    lines = [
        f"Scam-Shield weekly digest",
        f"  {d['since'][:10]}  →  {d['until'][:10]}",
        f"  Total forwards: {d['total']}",
        "",
        "By verdict:",
    ]
    for verdict in ("scam", "likely_scam", "suspicious", "clean"):
        n = d["by_verdict"].get(verdict, 0)
        if n:
            bar = "#" * min(40, n)
            lines.append(f"  {verdict:14}  {n:>4}  {bar}")
    lines.append("")
    if d["by_scam_type"]:
        lines.append("Top scam types:")
        for t, n in d["by_scam_type"][:5]:
            lines.append(f"  {t:18}  {n}")
        lines.append("")
    if d["top_phones"]:
        lines.append("Phones seen:")
        for v, n in d["top_phones"]:
            lines.append(f"  {v:30}  ×{n}")
        lines.append("")
    if d["top_emails"]:
        lines.append("Emails seen:")
        for v, n in d["top_emails"]:
            lines.append(f"  {v:30}  ×{n}")
        lines.append("")
    if d["top_urls"]:
        lines.append("URLs seen:")
        for v, n in d["top_urls"]:
            short = v if len(v) <= 50 else v[:47] + "..."
            lines.append(f"  {short:52}  ×{n}")
        lines.append("")
    if d["examples"]:
        lines.append("Worst offenders this period:")
        for r in d["examples"]:
            label = f"#{r['id']}  {r['verdict'].upper()} {r['score']}/100  ({r['scam_type']})"
            lines.append(f"  {label}")
            preview = (r.get("notes") or "")[:60]
            if preview:
                lines.append(f"    note: {preview}")
        lines.append("")

    # closing nudge
    if d["by_verdict"].get("scam", 0) > 0 or d["by_verdict"].get("likely_scam", 0) > 0:
        lines.append("Action: consider running /report to file with the FTC and your bank.")
    else:
        lines.append("All quiet on the scam front. Nice.")
    return "\n".join(lines)


def send_digest(token: str, chat_id: int, digest: Dict) -> bool:
    """Send the rendered digest via Telegram Bot API."""
    if not token or not chat_id:
        return False
    text = format_digest(digest)
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    chunks = [text[i:i+4000] for i in range(0, len(text), 4000)]
    try:
        for chunk in chunks:
            data = urllib.parse.urlencode(
                {"chat_id": chat_id, "text": chunk, "parse_mode": ""}
            ).encode("utf-8")
            req = urllib.request.Request(url, data=data, method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                pass
        return True
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        print(f"  telegram send failed: {e}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# CLI entry: build a digest and optionally send it
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="scam_shield.digest",
        description="Build and (optionally) send a Scam-Shield activity digest.",
    )
    p.add_argument("--db", default=hist_mod.DEFAULT_PATH, help="history sqlite path")
    p.add_argument("--days", type=int, default=7, help="how many days back to cover")
    p.add_argument("--send", action="store_true",
                   help="send via Telegram (needs TELEGRAM_BOT_TOKEN + --chat-id)")
    p.add_argument("--chat-id", type=int, default=None,
                   help="Telegram chat id to send to "
                        "(defaults to env SCAMSHIELD_NOTIFY_CHAT_ID)")
    args = p.parse_args(argv)

    h = hist_mod.History(args.db)
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=args.days)).isoformat()
        until = datetime.now(timezone.utc).isoformat()
        d = build_digest(h, since=since, until=until)
    finally:
        h.close()

    text = format_digest(d)
    print(text)
    print()

    if args.send:
        token = os.environ.get("TELEGRAM_BOT_TOKEN")
        chat_id = (args.chat_id or
                   int(os.environ.get("SCAMSHIELD_NOTIFY_CHAT_ID", "0")) or None)
        if not token or not chat_id:
            print("ERROR: --send needs TELEGRAM_BOT_TOKEN and --chat-id (or SCAMSHIELD_NOTIFY_CHAT_ID)",
                  file=sys.stderr)
            return 1
        ok = send_digest(token, chat_id, d)
        print(f"sent: {ok}")
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
