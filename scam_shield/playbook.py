"""
scam_shield.playbook

The Question Playbook: a bank of bait questions a person (or honeypot) can
insert into a conversation with a suspected scammer.

Each question has:
    id            : short slug
    scam_types    : which scam types this question is most useful against
    question      : the actual wording (casual, "off the cuff")
    rationale     : why it works
    followups     : things to listen for in the answer

Use `pick_questions(scam_type, n=3)` to get a ranked set for a given suspect.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Optional
import random


@dataclass
class Question:
    id: str
    scam_types: List[str]
    question: str
    rationale: str
    followups: List[str] = field(default_factory=list)
    universal: bool = False

    def __str__(self) -> str:
        lines = [f"[{self.id}]  ({', '.join(self.scam_types)})",
                 f"  Q: {self.question}",
                 f"  Why: {self.rationale}"]
        if self.followups:
            lines.append("  Listen for:")
            for f in self.followups:
                lines.append(f"    - {f}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# The bank
# ---------------------------------------------------------------------------

QUESTIONS: List[Question] = [
    # ===== Universal =====
    Question(
        "uni-timezone",
        ["universal"],
        "What time zone are you in right now?",
        "Scammers cluster in specific time zones. Their answer often contradicts their claimed identity (e.g. 'IRS officer' who's 'in Singapore right now').",
        ["Any hesitation, vague answer, or 'EST' said by an obvious non-American voice."],
        universal=True,
    ),
    Question(
        "uni-employee-id",
        ["universal"],
        "What's your employee / agent / case number?",
        "Real agents have one. Scammers either make one up that won't match later, or they dodge the question.",
        ["Confident, alphanumeric, matches later documents.",
         "Deflection, 'I'll have to check' or refusal."],
        universal=True,
    ),
    Question(
        "uni-conference",
        ["universal"],
        "Hold on, my buddy works at [company]. Let me conference him in real quick — what's your full name and direct number so he can dial you?",
        "Scammers vanish the second you threaten to bring in a third party. The real test: do they stay on the line?",
        ["Hang-up, sudden connection issues, or 'call me back later'."],
        universal=True,
    ),
    Question(
        "uni-call-back",
        ["universal"],
        "I'll call you back at your office line. What's the number?",
        "The moment they have to provide a verifiable number, the script breaks.",
        ["Made-up number, refusal, or 'just keep me on the line'."],
        universal=True,
    ),
    Question(
        "uni-spell-name",
        ["universal"],
        "Quick — spell your last name for me.",
        "Real people do this in under 2 seconds. Scammers using a fake name stumble, misspell, or use a common surname.",
        ["Instant correct spelling, or stalling and rephrasing."],
        universal=True,
    ),
    Question(
        "uni-last-time",
        ["universal"],
        "What did we talk about last time?",
        "Memory test. Anyone working from a script collapses on this. Anyone running a personal scam on multiple people also collapses.",
        ["Specific details, or vague 'I don't remember, let me check my notes'."],
        universal=True,
    ),

    # ===== Tech support =====
    Question(
        "tech-tier",
        ["tech_support"],
        "Which support tier is this being escalated through — Tier 1, 2, or 3?",
        "Real support uses tiers; scammers copy the lingo from one script and don't know which tier they're 'in'.",
        ["Confident tier + a plausible department, or hesitation."],
    ),
    Question(
        "tech-badge",
        ["tech_support"],
        "What's the badge / technician ID on your profile so I can log it with my notes?",
        "Microsoft, Apple, Geek Squad all have actual IDs. Scammers invent one and it never matches later documents.",
        ["Long alphanumeric ID, or 'I don't have that on me right now'."],
    ),
    Question(
        "tech-server",
        ["tech_support"],
        "Which datacenter is my case logged in? East US, West EU, Asia Pacific?",
        "Specific regional naming is rarely in the script. Wrong answer = scam.",
        ["Confident region + city, or 'our main hub' / 'we have many'."],
    ),
    Question(
        "tech-event-id",
        ["tech_support"],
        "What's the Event Viewer entry number you saw for the error on my machine?",
        "Windows Event Viewer entries are numbered. Real technicians can read it; scammers bluff.",
        ["Specific number like 10016, 7000, etc. — or waffle."],
    ),

    # ===== Government =====
    Question(
        "gov-office",
        ["government"],
        "Which field office is this case out of? (IRS has 65+ named ones — Brookhaven, Fresno, Memphis, etc.)",
        "Real IRS letters name a specific office. Scammers almost always say 'New York' or 'Washington DC'.",
        ["Real office name that matches the letterhead, or generic 'downtown' / 'headquarters'."],
    ),
    Question(
        "gov-letter",
        ["government"],
        "What's the certified mail number on the notice you sent me?",
        "USPS Certified Mail has a real 20-digit number. Scammers have none.",
        ["Real 20-digit number starting with 7, or 'I don't have that handy'."],
    ),
    Question(
        "gov-dds",
        ["government"],
        "What's the DDS claim number on my disability file?",
        "Disability Determination Services (DDS) — specific SSA term. Scammers don't know it.",
        ["Looks like NNN-NN-NNNN, or total confusion."],
    ),
    Question(
        "gov-form",
        ["government"],
        "Which tax form did you say I failed to file?",
        "Specific form (1040, 941, 1120). Scammers say 'taxes' generically.",
        ["Specific form number, or vague 'federal taxes'."],
    ),

    # ===== Bank impersonation =====
    Question(
        "bank-last4",
        ["bank_impersonation"],
        "What's the last 4 of my account you see on file?",
        "Your real bank knows. A scammer who initiated the call usually does not — they guessed or read it back to you.",
        ["Correct last 4, or stall / 'for security I can't say it back'."],
    ),
    Question(
        "bank-merchant",
        ["bank_impersonation"],
        "What's the merchant name on the suspicious charge YOU flagged?",
        "Script-flip: they made up the charge. Asking them to recall the merchant of the very alert they're using to scare you = total freeze.",
        ["Specific merchant like 'AMZN Mktp US*1A2B', or blank stare."],
    ),
    Question(
        "bank-case",
        ["bank_impersonation"],
        "What's the case number I should reference when I call the number on the back of my card?",
        "Real fraud departments dole out case numbers. If they refuse or say there isn't one, hang up.",
        ["Alphanumeric case number, or 'just call the general line'."],
    ),

    # ===== Package =====
    Question(
        "pkg-tracking",
        ["package"],
        "What's the full tracking number on the label?",
        "Real ops have it. Scammers send a 'short link' instead.",
        ["Format like 1Z999AA10123456784 (UPS), 9405511899223197428490 (USPS), or 774912345678 (FedEx)."],
    ),
    Question(
        "pkg-hub",
        ["package"],
        "Which hub is it stuck at?",
        "FedEx has Memphis, UPS has Louisville Worldport, USPS has regional NDCs. Scammers guess 'the local one'.",
        ["Specific hub + city, or 'the main distribution center'."],
    ),
    Question(
        "pkg-weight",
        ["package"],
        "What are the weight and dimensions on the label?",
        "Specifics ops have, scripts do not.",
        ["Real numbers like '2.3 kg, 30×20×15 cm'."],
    ),

    # ===== Romance =====
    Question(
        "rom-selfie",
        ["romance"],
        "Send me a quick selfie holding today's paper with the date visible.",
        "Gold standard. Stock-photo scammers cannot do this.",
        ["Real selfie, or 'my camera is broken' / 'phone is locked'."],
    ),
    Question(
        "rom-video",
        ["romance"],
        "Quick voice note — just say good morning. Or a 5-second video call?",
        "Most scammers will not risk exposing themselves. AI voice cloning is possible but rarely used this early.",
        ["Actual voice/video, or endless excuses."],
    ),
    Question(
        "rom-place",
        ["romance"],
        "What's the name of the bar / restaurant on the corner by your place? What's the street you grew up on?",
        "Hyperlocal detail. Script-free zone.",
        ["Real names that can be cross-checked, or vague 'a small town'."],
    ),
    Question(
        "rom-reason",
        ["romance"],
        "If you were a scammer, how would you run this exact pitch? Be honest — what tells you off?",
        "Asks them to meta-analyze their own script. They usually cannot.",
        ["Insightful self-aware answer, or confused silence."],
    ),

    # ===== Job =====
    Question(
        "job-ein",
        ["job_scam"],
        "What's the company EIN?",
        "Employer Identification Number. Free to look up on the IRS site in 10 seconds.",
        ["9-digit EIN, or 'we're incorporated overseas / it's pending'."],
    ),
    Question(
        "job-glassdoor",
        ["job_scam"],
        "What does the company's Glassdoor say about this team?",
        "Real companies have reviews. Fake ones don't, or have a brand-new profile.",
        ["Specific team / manager name, or 'we just launched'."],
    ),
    Question(
        "job-letter",
        ["job_scam"],
        "Send the offer letter from a company email, not Gmail. What's your company domain?",
        "Real recruiters email from a corporate domain. The few who do use Gmail are usually scams.",
        ["Corporate domain matching the company, or gmail/outlook."],
    ),
    Question(
        "job-mgr",
        ["job_scam"],
        "Who reports to the hiring manager? What's their title?",
        "Layered org detail. Scammers often invent a flat org with one person.",
        ["Real org chart, or 'just the CEO and me'."],
    ),

    # ===== Crypto / investment =====
    Question(
        "crypto-finra",
        ["crypto_investment"],
        "What's your FINRA license number?",
        "Anyone selling securities in the US must have one. Free look-up at brokercheck.finra.org.",
        ["Real 6-7 digit CRD number, or 'we don't operate in the US'."],
    ),
    Question(
        "crypto-state",
        ["crypto_investment"],
        "Which state are you registered to sell securities in?",
        "Real sellers can list it. Scammers say 'international' to dodge.",
        ["Specific US state, or 'we work globally'."],
    ),
    Question(
        "crypto-reference",
        ["crypto_investment"],
        "Send me the name of one recent investor I can call. Just one.",
        "Real opportunity: they will. Fake: 'our clients value privacy'.",
        ["A real name + number, or total refusal."],
    ),
    Question(
        "crypto-tax",
        ["crypto_investment"],
        "If I invest, what tax form will I get — 1099-B? K-1?",
        "Specific US tax forms. Most international scammers don't know which one applies.",
        ["Correct form for the structure, or blank."],
    ),

    # ===== Lottery =====
    Question(
        "lot-entry",
        ["lottery"],
        "When did I enter this drawing? Which ticket number?",
        "You never entered. They cannot produce a real ticket.",
        ["Stall, or 'the system selected you automatically'."],
    ),
    Question(
        "lot-tax",
        ["lottery"],
        "If I won, does the IRS get a 1099-MISC or W-2G on it?",
        "Specific US tax form. Most foreign lottery scammers don't know.",
        ["W-2G for gambling, 1099-MISC for sweepstakes, or waffle."],
    ),

    # ===== Phishing (impersonation of known brand via link) =====
    Question(
        "phish-domain",
        ["phishing"],
        "What's the company's official domain? I'll go there myself.",
        "If they can't tell you (or give you the same lookalike link) it's a phishing link.",
        ["Clean match like 'paypal.com', or the impersonating link again."],
    ),
    Question(
        "phish-https",
        ["phishing"],
        "Open the site yourself and tell me the certificate issuer.",
        "EV certs show the real company name in the browser bar. Phishers can't fake that.",
        ["DigiCert / Entrust / Sectigo for the real brand, or 'I don't know'."],
    ),
]


_BY_ID: Dict[str, Question] = {q.id: q for q in QUESTIONS}
_BY_TYPE: Dict[str, List[Question]] = {}


def _index() -> None:
    for q in QUESTIONS:
        if q.universal:
            _BY_TYPE.setdefault("universal", []).append(q)
        for t in q.scam_types:
            _BY_TYPE.setdefault(t, []).append(q)


_index()


def get(qid: str) -> Optional[Question]:
    return _BY_ID.get(qid)


def pick_questions(scam_type: str, n: int = 3, *, also_universal: bool = True) -> List[Question]:
    """
    Return up to `n` questions best suited to the given scam_type.
    Always mixes in universal questions if `also_universal`.
    """
    pool: List[Question] = []
    seen = set()

    if also_universal:
        for q in _BY_TYPE.get("universal", []):
            if q.id not in seen:
                pool.append(q); seen.add(q.id)

    for q in _BY_TYPE.get(scam_type, []):
        if q.id not in seen:
            pool.append(q); seen.add(q.id)

    random.shuffle(pool)
    return pool[:n]


def all_for(scam_type: str) -> List[Question]:
    return list(_BY_TYPE.get(scam_type, []))
