"""
scam_shield.cli

Command-line interface. Subcommands:

    analyze <file|->       analyze a message (or stdin) and print a report
    analyze-full <file|->  heuristic + LLM second opinion (needs Ollama)
    questions <scam_type>  print recommended bait questions
    honey <scam_type>      start an interactive honeypot session
    play <file>            analyze + start honeypot in one go (great for tests)
    report <file>          generate a full report pack (FTC/IC3/bank/platform)
    history <cmd>          list/get/search/stats past reports
    demo                   run canned test messages through the detector

External scripts (run with `python -m scam_shield.<name>`):
    agent_loop [--watch]   process unprocessed reports, auto-file, send DMs
    digest [--send]        build (and optionally send) a weekly activity digest
    telegram_bot           long-poll bot for interactive use on your phone
"""

from __future__ import annotations

import argparse
import os
import sys
import json
from typing import Optional

from .detector import analyze, analyze_file, analyze_full, ScamReport
from . import playbook as pb
from . import honeypot as hp
from . import report_pack
from . import history as hist_mod
from . import agent_loop
from . import digest


# ---------------------------------------------------------------------------

def _read_input(target: str) -> str:
    if target == "-":
        return sys.stdin.read()
    if os.path.isfile(target):
        with open(target, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    return target


def cmd_analyze(args: argparse.Namespace) -> int:
    text = _read_input(args.input)
    if args.channel:
        report = analyze(text, channel=args.channel)
    else:
        report = analyze(text, channel=args.input if args.input != "-" else "stdin")
    if not args.no_record:
        try:
            h = hist_mod.History(hist_mod.DEFAULT_PATH)
            h.record(report, text=text)
            h.close()
        except Exception as e:
            print(f"(history write failed: {e})", file=sys.stderr)
    if args.json:
        print(report.to_json())
    else:
        print(report)
    return 0 if report.verdict in ("clean", "suspicious") else 2


def cmd_analyze_full(args: argparse.Namespace) -> int:
    """Heuristic + LLM second opinion."""
    text = _read_input(args.input)
    channel = args.channel or (args.input if args.input != "-" else "stdin")
    report = analyze_full(text, channel=channel, use_llm=not args.no_llm,
                          llm_timeout=args.timeout)
    if not args.no_record:
        try:
            h = hist_mod.History(hist_mod.DEFAULT_PATH)
            h.record(report, text=text)
            h.close()
        except Exception as e:
            print(f"(history write failed: {e})", file=sys.stderr)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(report)
    return 0 if report.verdict in ("clean", "suspicious") else 2


def cmd_questions(args: argparse.Namespace) -> int:
    qs = pb.pick_questions(args.scam_type, n=args.n, also_universal=not args.no_universal)
    print(f"\nRecommended questions for scam type: {args.scam_type}")
    print("=" * 60)
    for q in qs:
        print()
        print(q)
    print()
    return 0


def cmd_honey(args: argparse.Namespace) -> int:
    print(f"\nStarting honeypot as '{args.persona}' against '{args.scam_type}'")
    print("Paste each scammer message on its own line, then press Enter twice (Ctrl-D / Ctrl-Z) to submit.")
    print("Type 'quit' on a line by itself to end the session and see the report.\n")
    sess = hp.start_session(persona=args.persona, scam_type=args.scam_type,
                            db_path=args.db)
    print(f"Session #{sess.session_id}  (db: {args.db})\n")
    try:
        while True:
            print("--- paste scammer message (Enter twice to send, 'quit' to end) ---")
            buf: list[str] = []
            empty = 0
            while True:
                try:
                    line = input()
                except EOFError:
                    if buf:
                        break
                    line = "quit"
                if line.strip() == "quit":
                    sess.close()
                    _print_session_summary(sess.session_id, args.db)
                    return 0
                if line == "":
                    empty += 1
                    if empty >= 2 and buf:
                        break
                else:
                    empty = 0
                    buf.append(line)
            if not buf:
                continue
            msg = "\n".join(buf)
            print(f"\n[scammer]\n{msg}\n")
            reply = sess.ingest(msg)
            print(f"[{sess.persona_name}]\n{reply}\n")
    except KeyboardInterrupt:
        print("\n\n[ctrl-c — closing session]")
        sess.close()
        _print_session_summary(sess.session_id, args.db)
        return 0


def cmd_play(args: argparse.Namespace) -> int:
    text = _read_input(args.input)
    report = analyze(text, channel="play")
    print(report)
    print()
    print("=" * 60)
    print(f"Auto-starting honeypot in '{args.persona}' persona.")
    print("=" * 60)
    qs = pb.pick_questions(report.scam_type, n=3)
    for q in qs:
        print(f"  - {q.question}")
    print()
    print("Re-paste the message to start the interactive session.")
    print()
    sess = hp.start_session(persona=args.persona, scam_type=report.scam_type,
                            db_path=args.db)
    print(f"Session #{sess.session_id}  (db: {args.db})\n")
    sess.ingest(text)
    sess.close()
    _print_session_summary(sess.session_id, args.db)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Generate a full report pack (FTC / IC3 / bank / platform)."""
    text = _read_input(args.input)
    channel = args.channel or (args.input if args.input != "-" else "stdin")
    if args.full:
        from .detector import analyze_full
        report = analyze_full(text, channel=channel, use_llm=not args.no_llm,
                              llm_timeout=args.timeout)
    else:
        report = analyze(text, channel=channel)

    # Parse optional --victim and --extras as JSON
    victim = json.loads(args.victim) if args.victim else None
    extras = json.loads(args.extras)  if args.extras  else None

    # Read transcript file if provided
    transcript = None
    if args.transcript:
        with open(args.transcript, "r", encoding="utf-8", errors="replace") as f:
            transcript = [l.rstrip() for l in f if l.strip()]

    pack = report_pack.ReportPack.from_report(
        report, victim=victim, transcript=transcript, extras=extras
    )
    if args.out:
        written = pack.to_files(args.out)
        print(f"Wrote {len(written)} files to {args.out}:")
        for w in written:
            print(f"  - {w}")
    else:
        print(pack.summary())
        print()
        print("Pass --out <dir> to write the pack to disk. Files:")
        for name in pack.files:
            print(f"  - {name}")

    if not args.no_record:
        try:
            h = hist_mod.History(hist_mod.DEFAULT_PATH)
            rid = h.record(report, text=text, notes=pack.case_id)
            if args.out:
                h.record_pack(rid, pack.case_id, args.out, pack.files.keys())
            h.close()
        except Exception as e:
            print(f"(history write failed: {e})", file=sys.stderr)
    return 0


def cmd_history_list(args: argparse.Namespace) -> int:
    h = hist_mod.History(hist_mod.DEFAULT_PATH)
    rows = h.list_reports(limit=args.limit, verdict=args.verdict, scam_type=args.scam_type)
    h.close()
    if not rows:
        print("(no reports yet)")
        return 0
    print(f"{'ID':>4}  {'WHEN':19}  {'VERDICT':14}  {'SCORE':>5}  {'TYPE':18}  CHANNEL    NOTE")
    print("-" * 100)
    for r in rows:
        print(f"{r['id']:>4}  {r['created_at'][:19]:19}  "
              f"{r['verdict']:14}  {r['score']:>5}  "
              f"{(r['scam_type'] or '-'):18}  "
              f"{(r['channel'] or '-'):10}  "
              f"{r['notes'] or ''}")
    return 0


def cmd_history_get(args: argparse.Namespace) -> int:
    h = hist_mod.History(hist_mod.DEFAULT_PATH)
    r = h.get_report(args.id)
    h.close()
    if r is None:
        print(f"(no report with id {args.id})")
        return 1
    print(f"Report #{r['id']}  {r['created_at']}")
    print(f"channel: {r['channel']}   verdict: {r['verdict']}   "
          f"score: {r['score']}   type: {r['scam_type']}")
    if r.get('notes'):
        print(f"notes:   {r['notes']}")
    print()
    print("Text:")
    print(r['text'])
    print()
    print(f"Signals ({len(r['signals'])}):")
    for s in r['signals']:
        print(f"  - [{s.get('scam_type')}] {s.get('category')}  ({s.get('snippet')!r})")
    print()
    if r.get('llm') and not r['llm'].get('error'):
        print("LLM judge:")
        print(f"  verdict: {r['llm'].get('verdict')}   confidence: {r['llm'].get('confidence')}%")
        print(f"  reason:  {r['llm'].get('reason')}")
    return 0


def cmd_history_search(args: argparse.Namespace) -> int:
    h = hist_mod.History(hist_mod.DEFAULT_PATH)
    rows = h.search(args.query, limit=args.limit)
    h.close()
    if not rows:
        print("(no matches)")
        return 0
    for r in rows:
        print(f"[#{r['id']}] {r['created_at'][:19]}  {r['verdict']}  "
              f"{r['score']:>3}  {r['scam_type']}")
        print(f"    {r['snippet']}")
        print()
    return 0


def cmd_history_stats(_: argparse.Namespace) -> int:
    h = hist_mod.History(hist_mod.DEFAULT_PATH)
    s = h.stats()
    h.close()
    print(f"Total reports: {s['total_reports']}   Packs generated: {s['total_packs']}")
    print()
    print("By verdict:")
    for v, n in s['by_verdict'].items():
        bar = "#" * min(50, n)
        print(f"  {v:14}  {n:>4}  {bar}")
    print()
    print("By scam type:")
    for x in s['by_scam_type'][:15]:
        bar = "#" * min(50, x['n'])
        print(f"  {x['scam_type']:18}  {x['n']:>4}  {bar}")
    return 0


def cmd_demo(_: argparse.Namespace) -> int:
    cases = [
        ("microsoft cold call",
         "sms",
         "URGENT: Suspicious activity detected on your Microsoft account. Your computer "
         "has been compromised. Call our certified technicians immediately at +1-888-555-0199 "
         "and download AnyDesk so we can secure your system. Failure to act within 24 hours "
         "will result in your accounts being locked. Pay $299 via gift cards to keep your "
         "subscription active."),
        ("irs warrant scam",
         "sms",
         "This is Officer Daniels from the Internal Revenue Service. A warrant has been issued "
         "for your arrest due to unpaid back taxes. To avoid jail, you must pay $4,850 in "
         "Google Play gift cards within 30 minutes. Do not tell your family or your bank. "
         "Reply with the codes from the back of the cards."),
        ("fedex package",
         "sms",
         "FEDEX: Your package is being held at customs. A small redelivery fee of $1.99 is "
         "required. Confirm at https://fedex-redelivery.top/track?id=9921 to avoid return "
         "to sender."),
        ("romance stranded",
         "dm",
         "My dearest Margaret, I miss you so much. I am stuck in Istanbul at customs and "
         "my wallet was stolen. Could you please send $850 via Western Union so I can get "
         "home to you? I have fallen deeply in love and cannot wait to hold you. Honey, "
         "please keep this between us for now."),
        ("crypto giveaway",
         "dm",
         "🚨 ELON MUSK BITCOIN GIVEAWAY 🚨 Send 0.1 BTC to the address below and receive "
         "1 BTC back GUARANTEED within 24 hours. Connect your wallet to claim. This is a "
         "limited time offer, do not delay. Risk-free passive income of $5,000/week."),
        ("job recruiter",
         "email",
         "Hi! I'm Sarah from Apex Talent Group. We saw your resume and have a perfect "
         "work-from-home opportunity paying $3,500/week, no experience needed. To get "
         "started, just send a $200 training fee via Zelle and we'll send you the "
         "equipment. You'll be receiving client payments and forwarding them to our HQ."),
        ("paypal phishing",
         "email",
         "Your PayPal account has been LIMITED due to suspicious activity. To unlock "
         "your account, click here immediately and verify your details: "
         "http://paypa1-secure-login.com/verify?id=99. Failure to act within 24 hours "
         "will result in permanent suspension."),
        ("legit package",
         "sms",
         "Hi Zach, your Amazon order #112-3344556-7788990 has shipped! Track at "
         "amazon.com/orders. Estimated delivery: Tuesday."),
        ("legit banking alert",
         "sms",
         "Capital One: A $42.19 charge at TARGET T-1234 was made on your card ending "
         "in 4471 at 2:14pm ET. If this was not you, call the number on the back of "
         "your card. Reply HELP for help, STOP to opt out."),
    ]
    print(f"{'CASE':25} {'SCORE':>5}  {'VERDICT':14}  TYPE")
    print("-" * 70)
    for name, channel, msg in cases:
        r = analyze(msg, channel=channel)
        print(f"{name:25} {r.score:>5}  {r.verdict:14}  {r.scam_type}")
    print()
    return 0


def _print_session_summary(session_id: int, db_path: str) -> None:
    import sqlite3
    conn = sqlite3.connect(db_path)
    print()
    print("=" * 60)
    print(f"SESSION {session_id} SUMMARY")
    print("=" * 60)
    msgs = conn.execute(
        "SELECT role, content FROM messages WHERE session_id=? ORDER BY id",
        (session_id,),
    ).fetchall()
    ev = conn.execute(
        "SELECT kind, detail FROM evidence WHERE session_id=? ORDER BY id",
        (session_id,),
    ).fetchall()
    print(f"\nFull transcript ({len(msgs)} messages):")
    for role, content in msgs:
        tag = "[SCAMMER]" if role == "scammer" else "[HONEYPOT]"
        print(f"  {tag} {content[:200]}{'…' if len(content) > 200 else ''}")
    print(f"\nEvidence collected ({len(ev)} items):")
    for kind, detail in ev:
        print(f"  - {kind:8}  {detail[:200]}")
    conn.close()


# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scam-shield",
        description="Fool-proof scam detection and counter-engagement.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_a = sub.add_parser("analyze", help="score a single message or file")
    p_a.add_argument("input", help="file path, '-' for stdin, or the message text itself")
    p_a.add_argument("--channel", default=None, help="channel label (sms, email, dm, call)")
    p_a.add_argument("--json", action="store_true", help="JSON output")
    p_a.add_argument("--no-record", action="store_true", help="don't save to history")
    p_a.set_defaults(func=cmd_analyze)

    p_af = sub.add_parser("analyze-full", aliases=["full"],
                          help="heuristic + local LLM (Ollama) second opinion")
    p_af.add_argument("input", help="file path, '-' for stdin, or the message text itself")
    p_af.add_argument("--channel", default=None, help="channel label")
    p_af.add_argument("--json", action="store_true", help="JSON output")
    p_af.add_argument("--no-llm", action="store_true", help="skip the LLM pass")
    p_af.add_argument("--no-record", action="store_true", help="don't save to history")
    p_af.add_argument("--timeout", type=float, default=60.0, help="LLM call timeout (s)")
    p_af.set_defaults(func=cmd_analyze_full)

    p_q = sub.add_parser("questions", help="show bait questions for a scam type")
    p_q.add_argument("scam_type", help="scam type (universal, tech_support, government, "
                    "bank_impersonation, package, romance, job_scam, crypto_investment, "
                    "lottery, phishing)")
    p_q.add_argument("-n", type=int, default=3, help="how many questions to show")
    p_q.add_argument("--no-universal", action="store_true", help="don't mix in universal bait")
    p_q.set_defaults(func=cmd_questions)

    p_h = sub.add_parser("honey", help="start an interactive honeypot session")
    p_h.add_argument("scam_type", nargs="?", default="universal")
    p_h.add_argument("--persona", default="margaret",
                     choices=list(hp.PERSONAS), help="persona to play")
    p_h.add_argument("--db", default=hp.DEFAULT_DB, help="sqlite path for logs")
    p_h.set_defaults(func=cmd_honey)

    p_p = sub.add_parser("play", help="analyze then auto-start a honeypot")
    p_p.add_argument("input", help="file path, '-' for stdin, or the message text itself")
    p_p.add_argument("--persona", default="margaret", choices=list(hp.PERSONAS))
    p_p.add_argument("--db", default=hp.DEFAULT_DB)
    p_p.set_defaults(func=cmd_play)

    p_d = sub.add_parser("demo", help="run built-in demo cases")
    p_d.set_defaults(func=cmd_demo)

    p_r = sub.add_parser("report", help="generate a full report pack (FTC/IC3/bank/platform)")
    p_r.add_argument("input", help="file path, '-' for stdin, or the message text itself")
    p_r.add_argument("--channel", default=None, help="channel label")
    p_r.add_argument("--out", default=None, help="output directory")
    p_r.add_argument("--transcript", default=None, help="path to a transcript file (one message per line)")
    p_r.add_argument("--victim", default=None, help='JSON: \'{"name":"...", "email":"..."}\'')
    p_r.add_argument("--extras", default=None, help='JSON: \'{"money_sent":"500 USD", "payment_method":"Zelle"}\'')
    p_r.add_argument("--full", action="store_true", help="also run the LLM judge")
    p_r.add_argument("--no-llm", action="store_true", help="skip the LLM even with --full")
    p_r.add_argument("--no-record", action="store_true", help="don't save to history")
    p_r.add_argument("--timeout", type=float, default=60.0, help="LLM timeout (s)")
    p_r.set_defaults(func=cmd_report)

    # ---- history subcommand (with its own sub-subcommands) ----
    p_h = sub.add_parser("history", help="browse saved reports")
    hsub = p_h.add_subparsers(dest="hist_cmd", required=True)

    p_h_l = hsub.add_parser("list", help="list recent reports")
    p_h_l.add_argument("--limit", type=int, default=20)
    p_h_l.add_argument("--verdict", default=None, help="filter by verdict")
    p_h_l.add_argument("--type", dest="scam_type", default=None, help="filter by scam type")
    p_h_l.set_defaults(func=cmd_history_list)

    p_h_g = hsub.add_parser("get", help="fetch a specific report by id")
    p_h_g.add_argument("id", type=int)
    p_h_g.set_defaults(func=cmd_history_get)

    p_h_s = hsub.add_parser("search", help="full-text search")
    p_h_s.add_argument("query")
    p_h_s.add_argument("--limit", type=int, default=20)
    p_h_s.set_defaults(func=cmd_history_search)

    p_h_st = hsub.add_parser("stats", help="counts by verdict and type")
    p_h_st.set_defaults(func=cmd_history_stats)

    return p


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
