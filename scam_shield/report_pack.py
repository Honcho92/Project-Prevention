"""
scam_shield.report_pack

Generates a "report pack" — the bundle of files a victim (or the platform
hosting the scam) can hand to:

    * FTC (ReportFraud.ftc.gov)
    * FBI / IC3 (ic3.gov)
    * BBB Scam Tracker (bbb.org/scamtracker)
    * Your bank (if money was sent)
    * USPS Inspection Service (if mail was involved)
    * FCC (if robocall, +1-888-CALL-FCC)
    * State Attorney General
    * The platform hosting the scam (Instagram, Telegram, WhatsApp, etc.)

Public API
----------
    ReportPack.from_report(report, *, victim=None, transcript=None, extras=None)
        → ReportPack dataclass

    pack.to_files(out_dir)              writes:
        complaint_narrative.txt         ready to paste into ReportFraud
        evidence_inventory.json         machine-readable entity dump
        entity_index.txt                human-readable phone/email/URL list
        timeline.txt                    event-by-event narrative
        bank_notice.txt                 one-pager for your bank (if you paid)
        platform_report.txt             short report for the host platform
        law_enforcement_packet.json     full structured record
        INDEX.md                        short readme explaining what each file is

    pack.render_all()                   returns a dict of filename → contents
"""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Iterable

from .detector import ScamReport, FullReport
from . import playbook as pb


# ---------------------------------------------------------------------------
# Agency routing table
# ---------------------------------------------------------------------------

# For each scam type, list which agencies are most relevant. Order = priority.
AGENCY_TABLE: Dict[str, List[Dict]] = {
    "tech_support": [
        {"name": "FTC",         "url": "https://reportfraud.ftc.gov",  "how": "web form"},
        {"name": "FBI / IC3",   "url": "https://ic3.gov",              "how": "web form"},
        {"name": "Microsoft",   "url": "https://microsoft.com/reportascam",
            "how": "report the impersonator to Microsoft directly"},
        {"name": "Apple",       "url": "https://support.apple.com/en-us/108777",
            "how": "report to Apple if Apple was impersonated"},
    ],
    "government": [
        {"name": "FTC",              "url": "https://reportfraud.ftc.gov", "how": "web form"},
        {"name": "FBI / IC3",        "url": "https://ic3.gov",             "how": "web form"},
        {"name": "IRS (impersonation)", "url": "https://www.irs.gov/privacy-disclosure/report-phishing",
            "how": "email phishing@irs.gov with the message"},
        {"name": "SSA Inspector General", "url": "https://oig.ssa.gov/scam",
            "how": "report if SSA was impersonated"},
        {"name": "Treasury Inspector General (TIGTA)",
            "url": "https://www.treasury.gov/tigta/contact_report_scam.shtml",
            "how": "report IRS impersonation"},
    ],
    "bank_impersonation": [
        {"name": "Your bank fraud department",
            "url": "(number on back of your card)",
            "how": "call immediately, then visit branch"},
        {"name": "FTC",         "url": "https://reportfraud.ftc.gov", "how": "web form"},
        {"name": "FBI / IC3",   "url": "https://ic3.gov",             "how": "web form"},
        {"name": "CFPB",        "url": "https://www.consumerfinance.gov/complaint/",
            "how": "file a complaint against the bank if it failed to protect you"},
    ],
    "package": [
        {"name": "FTC",                   "url": "https://reportfraud.ftc.gov", "how": "web form"},
        {"name": "USPS Inspection Service", "url": "https://www.uspis.gov/report",
            "how": "if USPS was impersonated"},
        {"name": "UPS Fraud",             "url": "https://www.ups.com/us/en/help-center/shipping-support.page",
            "how": "if UPS was impersonated"},
        {"name": "FedEx Fraud",           "url": "https://www.fedex.com/en-us/customer-support.html",
            "how": "if FedEx was impersonated"},
    ],
    "romance": [
        {"name": "FTC",         "url": "https://reportfraud.ftc.gov", "how": "web form"},
        {"name": "FBI / IC3",   "url": "https://ic3.gov",             "how": "web form"},
        {"name": "BBB Romance Scam", "url": "https://www.bbb.org/all/scamtracker",
            "how": "post to BBB Scam Tracker"},
        {"name": "Dating platform", "url": "(see the app's report-abuse button)",
            "how": "report the profile in-app AND via web"},
    ],
    "job_scam": [
        {"name": "FTC",         "url": "https://reportfraud.ftc.gov", "how": "web form"},
        {"name": "FBI / IC3",   "url": "https://ic3.gov",             "how": "web form"},
        {"name": "BBB Scam Tracker", "url": "https://www.bbb.org/all/scamtracker",
            "how": "post to BBB"},
        {"name": "Job platform", "url": "(LinkedIn / Indeed / ZipRecruiter / etc.)",
            "how": "report the posting using the platform's report button"},
    ],
    "crypto_investment": [
        {"name": "FTC",           "url": "https://reportfraud.ftc.gov", "how": "web form"},
        {"name": "FBI / IC3",     "url": "https://ic3.gov",             "how": "web form"},
        {"name": "SEC (if US-based)", "url": "https://www.sec.gov/tcr",
            "how": "report if the seller claims to be SEC-registered"},
        {"name": "CFTC",          "url": "https://www.cftc.gov/complaint",
            "how": "if it was a commodity / forex fraud"},
        {"name": "Your crypto exchange", "url": "(Coinbase / Binance / etc. support)",
            "how": "report the wallet address to the exchange"},
    ],
    "lottery": [
        {"name": "FTC",         "url": "https://reportfraud.ftc.gov", "how": "web form"},
        {"name": "FBI / IC3",   "url": "https://ic3.gov",             "how": "web form"},
        {"name": "BBB Scam Tracker", "url": "https://www.bbb.org/all/scamtracker", "how": "post"},
        {"name": "USPS (if check by mail)", "url": "https://www.uspis.gov/report",
            "how": "report the fake check"},
    ],
    "phishing": [
        {"name": "FTC",         "url": "https://reportfraud.ftc.gov", "how": "web form"},
        {"name": "FBI / IC3",   "url": "https://ic3.gov",             "how": "web form"},
        {"name": "Anti-Phishing Working Group", "url": "https://apwg.org/reportphishing/",
            "how": "forward the email to reportphishing@apwg.org"},
        {"name": "The impersonated company (PayPal, Amazon, etc.)",
            "url": "(see their report-abuse page)", "how": "report the link"},
    ],
    "universal": [
        {"name": "FTC",         "url": "https://reportfraud.ftc.gov", "how": "web form"},
        {"name": "FBI / IC3",   "url": "https://ic3.gov",             "how": "web form"},
    ],
}


# ---------------------------------------------------------------------------
# ReportPack dataclass
# ---------------------------------------------------------------------------

@dataclass
class ReportPack:
    case_id: str
    generated_at: str
    victim: Optional[Dict]
    scam_type: str
    verdict: str
    score: int
    channel: str
    files: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_report(cls, report, *,
                    victim: Optional[Dict] = None,
                    transcript: Optional[Iterable[str]] = None,
                    extras: Optional[Dict] = None) -> "ReportPack":
        """Build a ReportPack from a ScamReport or FullReport."""
        if isinstance(report, FullReport):
            score = report.score
            verdict = report.verdict
            scam_type = report.scam_type
            heur = report.heuristic
            llm = report.llm
        else:
            score = report.score
            verdict = report.verdict
            scam_type = report.scam_type
            heur = report
            llm = None

        case_id = "SCAM-" + datetime.now(timezone.utc).strftime("%Y%m%d") + "-" + \
                  uuid.uuid4().hex[:8].upper()
        pack = cls(
            case_id=case_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            victim=victim or {},
            scam_type=scam_type,
            verdict=verdict,
            score=score,
            channel=heur.channel,
        )
        pack.files["INDEX.md"] = _render_index(pack)
        pack.files["complaint_narrative.txt"] = _render_complaint(pack, heur, llm, transcript, extras)
        pack.files["evidence_inventory.json"] = _render_evidence_json(pack, heur, llm, transcript, extras)
        pack.files["entity_index.txt"] = _render_entity_index(pack, heur)
        pack.files["timeline.txt"] = _render_timeline(pack, transcript)
        pack.files["bank_notice.txt"] = _render_bank_notice(pack, heur, victim, extras)
        pack.files["platform_report.txt"] = _render_platform_report(pack, heur)
        pack.files["law_enforcement_packet.json"] = _render_le_packet(pack, heur, llm, transcript, victim, extras)
        pack.files["filing_checklist.txt"] = _render_filing_checklist(pack)
        return pack

    def to_files(self, out_dir: str) -> List[str]:
        """Write all files to out_dir. Returns list of written paths."""
        os.makedirs(out_dir, exist_ok=True)
        written: List[str] = []
        for name, content in self.files.items():
            path = os.path.join(out_dir, name)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            written.append(path)
        return written

    def render_all(self) -> Dict[str, str]:
        return dict(self.files)

    def summary(self) -> str:
        n = len(self.files)
        size = sum(len(c) for c in self.files.values())
        return (f"Report pack {self.case_id}: {self.verdict} {self.score}/100 "
                f"({self.scam_type}); {n} files, {size:,} chars")


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def _victim_str(v: Optional[Dict]) -> str:
    if not v:
        return "(left blank)"
    return ", ".join(f"{k}={v[k]}" for k in v)


def _render_index(pack: ReportPack) -> str:
    return f"""\
# Scam-Shield Report Pack — {pack.case_id}

Generated:   {pack.generated_at}
Verdict:     {pack.verdict.upper()}   Score: {pack.score}/100
Scam type:   {pack.scam_type}
Channel:     {pack.channel}
Victim info: {_victim_str(pack.victim)}

## Files in this pack

| File                          | What it is                                           | Who needs it                  |
|-------------------------------|------------------------------------------------------|-------------------------------|
| complaint_narrative.txt       | Plain-English description of what happened           | FTC, IC3, BBB, state AG        |
| evidence_inventory.json       | Machine-readable entity dump (phones, emails, URLs)  | Law enforcement, researchers   |
| entity_index.txt              | Human-readable list of all entities                  | Quick reference                |
| timeline.txt                  | Event-by-event narrative                             | Investigators                  |
| bank_notice.txt               | One-pager for your bank                              | Your bank (if money was sent)  |
| platform_report.txt           | Short report for the host platform                   | Instagram, Telegram, etc.       |
| law_enforcement_packet.json   | Full structured record                               | LE, researchers                |
| filing_checklist.txt          | Where to file, in priority order                     | You                            |

## How to use

1. Read `filing_checklist.txt` first to see which agencies to file with.
2. Open each agency's URL and paste the contents of `complaint_narrative.txt`.
3. If you sent money, take `bank_notice.txt` to your bank immediately.
4. Report the scammer's profile on the host platform using `platform_report.txt`.
5. Keep all original screenshots, emails, and chat logs in a separate folder.
"""


def _render_complaint(pack, heur, llm, transcript, extras) -> str:
    msgs = list(transcript) if transcript else []
    signals_bullets = "\n".join(
        f"   - [{s['scam_type']}] {s['category']}  (matched: {s['snippet']!r})"
        for s in heur.signals
    ) or "   (no specific signals recorded — the scam was identified by the overall pattern)"
    llm_str = ""
    if llm is not None and not llm.error:
        llm_str = (f"\nLLM second opinion: {llm.verdict} ({llm.confidence}% confidence, "
                   f"type={llm.scam_type})\nLLM reasoning: {llm.reason}\n")
    elif llm is not None and llm.error:
        llm_str = f"\nLLM second opinion: unavailable ({llm.error})\n"

    ent = heur.entities
    phones = ", ".join(ent.get("phones", [])) or "(none extracted)"
    emails = ", ".join(ent.get("emails", [])) or "(none extracted)"
    urls = ", ".join(ent.get("urls", [])) or "(none extracted)"
    money = ", ".join(ent.get("money", [])) or "(none extracted)"

    transcript_section = ""
    if msgs:
        transcript_section = "\n\n## Conversation transcript\n"
        for i, m in enumerate(msgs, 1):
            transcript_section += f"\n[{i}] {m}\n"

    victim_block = ""
    if pack.victim:
        victim_block = "\n## Victim information\n"
        for k, v in pack.victim.items():
            victim_block += f"   {k}: {v}\n"

    money_lost_block = ""
    if extras and extras.get("money_sent"):
        money_lost_block = f"\n## Money lost\n   Amount: {extras['money_sent']}\n"
        if extras.get("payment_method"):
            money_lost_block += f"   Method: {extras['payment_method']}\n"
        if extras.get("payment_date"):
            money_lost_block += f"   Date:   {extras['payment_date']}\n"
        if extras.get("payment_destination"):
            money_lost_block += f"   To:     {extras['payment_destination']}\n"

    return f"""\
COMPLAINT NARRATIVE — Case {pack.case_id}
========================================

## What happened

I am reporting a {pack.scam_type} scam I encountered on {pack.channel} on or
around {pack.generated_at[:10]}. Scam-Shield scored this as {pack.verdict.upper()}
({pack.score}/100) and identified {len(heur.signals)} specific scam signals.

## How the scam worked

Describe in your own words what happened, who contacted you, what they asked
you to do, and what you did. Include dates and times if you have them.

(The original message analyzed by Scam-Shield is reproduced verbatim at the
end of this document.)
{victim_block}{money_lost_block}
## Specific scam signals detected

{signals_bullets}{llm_str}
## Contact information used by the scammer

   Phone(s): {phones}
   Email(s): {emails}
   URL(s):   {urls}
   Money amount(s) requested: {money}

## What I want to happen

   1. Investigation and (where possible) prosecution of the parties involved.
   2. Takedown of the website(s) and phone number(s) listed above.
   3. If I sent money, recovery and/or restitution (see bank_notice.txt).

## Original message text

\"\"\"
{heur.signals and '(see the raw input — keep the original verbatim, including any URLs)' or '(see attached screenshots)'}
\"\"\"
{transcript_section}
## Reporter information

   Name:        {pack.victim.get('name', '(provide on the form)')}
   Email:       {pack.victim.get('email', '(provide on the form)')}
   Phone:       {pack.victim.get('phone', '(provide on the form)')}
   Best contact: {pack.victim.get('best_contact', 'email')}

I declare under penalty of perjury that the information above is true and
accurate to the best of my knowledge.
"""


def _render_evidence_json(pack, heur, llm, transcript, extras) -> str:
    obj = {
        "case_id": pack.case_id,
        "generated_at": pack.generated_at,
        "scam_type": pack.scam_type,
        "verdict": pack.verdict,
        "score": pack.score,
        "channel": pack.channel,
        "victim": pack.victim,
        "extras": extras or {},
        "entities": heur.entities,
        "signals": heur.signals,
        "advice": heur.advice,
        "llm_judge": (llm.to_dict() if llm is not None else None),
        "transcript": list(transcript) if transcript else [],
    }
    return json.dumps(obj, indent=2, ensure_ascii=False)


def _render_entity_index(pack, heur) -> str:
    e = heur.entities
    out = [f"ENTITY INDEX — {pack.case_id}", "=" * 60, ""]
    for kind in ("phones", "emails", "urls", "handles", "money"):
        items = e.get(kind, [])
        out.append(f"{kind.upper()} ({len(items)}):")
        if not items:
            out.append("  (none)")
        else:
            for x in items:
                out.append(f"  - {x}")
        out.append("")
    return "\n".join(out)


def _render_timeline(pack, transcript) -> str:
    out = [f"TIMELINE — {pack.case_id}", "=" * 60, ""]
    out.append(f"{pack.generated_at[:19]}  Report generated by Scam-Shield")
    out.append(f"{pack.generated_at[:19]}  Verdict: {pack.verdict.upper()} "
               f"({pack.score}/100)  type={pack.scam_type}")
    out.append("")
    if transcript:
        out.append("--- events (in order) ---")
        for i, m in enumerate(transcript, 1):
            out.append(f"[event {i}]")
            out.append(m)
            out.append("")
    else:
        out.append("(No timestamped transcript provided. Add dated entries below.)")
        out.append("")
        out.append("Use the format:  YYYY-MM-DD HH:MM  <what happened>")
    return "\n".join(out)


def _render_bank_notice(pack, heur, victim, extras) -> str:
    money = (extras or {}).get("money_sent", "(specify amount)")
    method = (extras or {}).get("payment_method", "(wire / Zelle / gift cards / crypto / etc.)")
    dest = (extras or {}).get("payment_destination", "(account / wallet / recipient)")
    pdate = (extras or {}).get("payment_date", "(date)")
    ref = (extras or {}).get("transaction_reference", "(reference / confirmation #)")
    ent = heur.entities
    return f"""\
FRAUD NOTIFICATION — to be presented to your bank
================================================

Date:           {pack.generated_at[:10]}
Customer name:  {victim.get('name', '(your name)') if victim else '(your name)'}
Account:        (your account number, last 4 only)

I am writing to notify you of an unauthorized / fraudulent transaction
on my account. Below are the details.

Transaction details
-------------------
   Date:    {pdate}
   Amount:  {money}
   Method:  {method}
   Sent to: {dest}
   Reference / confirmation: {ref}

Description of fraud
--------------------
This payment was made in response to a {pack.scam_type} scam.
Scam-Shield scored the original solicitation as {pack.verdict.upper()} on a
scale of 100, with {len(heur.signals)} specific scam signals detected.

The scammer's contact information is:
   Phone(s): {', '.join(ent.get('phones', [])) or '(unknown)'}
   Email(s): {', '.join(ent.get('emails', [])) or '(unknown)'}
   URL(s):   {', '.join(ent.get('urls', [])) or '(unknown)'}

I am requesting
---------------
   1. Immediate reversal / chargeback of the transaction (if within the
      Reg E / Reg Z window).
   2. Freezing of the destination account / wallet where possible.
   3. A written confirmation of receipt of this fraud report (case number).
   4. An enhanced fraud alert or credit freeze if appropriate.
   5. Review of any subsequent transactions in case the account is
      further compromised.

Supporting evidence
--------------------
- Scam-Shield report (case {pack.case_id}) attached.
- Original messages / screenshots provided on request.
- Law enforcement report #: (file with FTC and IC3 first if not already done)

I have also filed reports with:
   [ ] FTC          (https://reportfraud.ftc.gov)
   [ ] FBI / IC3    (https://ic3.gov)
   [ ] BBB Scam Tracker
   [ ] State Attorney General
   [ ] Local police (if amount justifies)

Signature: ____________________________   Date: ______________

Print name: ____________________________
"""


def _render_platform_report(pack, heur) -> str:
    e = heur.entities
    handles = e.get("handles", []) or []
    handle = handles[0] if handles else "(scammer's @handle on the platform)"
    return f"""\
PLATFORM ABUSE REPORT — copy/paste into the app's Report Abuse form
==================================================================

User being reported: {handle}
Reason:             Scam / phishing ({pack.scam_type})
Verdict (auto):     {pack.verdict.upper()} ({pack.score}/100)

Message / profile evidence
--------------------------
(Attach the original screenshots, links, and message text. The app's form
usually accepts up to 5 images.)

Summary (for the platform's free-text field)
--------------------------------------------
This account is operating a {pack.scam_type} scam. They contacted me via
{pack.channel} and attempted to obtain money / personal information through
deception. Scam-Shield's automated analysis confirmed {len(heur.signals)} scam
signals. Specific items of note:

   - Phones: {', '.join(e.get('phones', [])) or '(none recorded)'}
   - Emails: {', '.join(e.get('emails', [])) or '(none recorded)'}
   - URLs:   {', '.join(e.get('urls', [])) or '(none recorded)'}

I request that this account be suspended, that the content be removed, and
that any evidence be preserved for potential law enforcement use.

Reporter contact: (the platform's form will collect this)
"""


def _render_le_packet(pack, heur, llm, transcript, victim, extras) -> str:
    return json.dumps({
        "schema": "scam-shield.law-enforcement-packet.v1",
        "case_id": pack.case_id,
        "generated_at": pack.generated_at,
        "victim": victim or {},
        "incident": {
            "scam_type": pack.scam_type,
            "verdict": pack.verdict,
            "score": pack.score,
            "channel": pack.channel,
            "occurred_at": (extras or {}).get("occurred_at"),
            "reported_at": pack.generated_at,
        },
        "loss": {
            "money_sent": (extras or {}).get("money_sent"),
            "currency": (extras or {}).get("currency", "USD"),
            "payment_method": (extras or {}).get("payment_method"),
            "payment_destination": (extras or {}).get("payment_destination"),
            "payment_date": (extras or {}).get("payment_date"),
            "transaction_reference": (extras or {}).get("transaction_reference"),
        },
        "entities": heur.entities,
        "signals": heur.signals,
        "llm_judge": (llm.to_dict() if llm is not None else None),
        "transcript": list(transcript) if transcript else [],
        "advice": heur.advice,
        "agencies_to_file": AGENCY_TABLE.get(pack.scam_type, AGENCY_TABLE["universal"]),
    }, indent=2, ensure_ascii=False)


def _render_filing_checklist(pack) -> str:
    agencies = AGENCY_TABLE.get(pack.scam_type, AGENCY_TABLE["universal"])
    out = [f"FILING CHECKLIST — {pack.case_id}",
           "=" * 60, "",
           "Work through these in order. Each one takes 2-10 minutes.",
           "Most need a free account, no payment ever.", ""]
    for i, a in enumerate(agencies, 1):
        out.append(f"[ ] {i}. {a['name']}")
        out.append(f"      URL:  {a['url']}")
        out.append(f"      How:  {a['how']}")
        out.append(f"      File: complaint_narrative.txt (copy/paste the body)")
        out.append("")
    # additional universal steps
    out.append("Additional steps to take regardless of scam type:")
    out.append("  [ ] Screenshot everything in the original app before the scammer deletes their account.")
    out.append("  [ ] Save the original email headers if email-borne (View > Show Original in Gmail).")
    out.append("  [ ] If you sent money: visit your bank branch in person with bank_notice.txt.")
    out.append("  [ ] Place a free fraud alert with one of the three credit bureaus:")
    out.append("        Equifax   1-800-685-1111")
    out.append("        Experian  1-888-397-3742")
    out.append("        TransUnion 1-888-909-8872")
    out.append("  [ ] Consider a free credit freeze (more restrictive than an alert).")
    out.append("  [ ] Change passwords for any account the scammer may have touched.")
    out.append("  [ ] If the scam was romance/employment: keep originals for at least 7 years")
    out.append("        (statute of limitations on wire fraud).")
    out.append("")
    out.append(f"Pack generated: {pack.generated_at}")
    return "\n".join(out)
