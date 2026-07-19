"""
scam_shield.detector

Heuristic scam detector. Pure stdlib. No network calls. Safe to run on
suspicious text — it does not touch any of the links it finds.

Public API
----------
    analyze(message: str, *, channel: str = "unknown") -> ScamReport
    ScamReport.score      # 0-100, higher = more scam-like
    ScamReport.verdict    # "clean" | "suspicious" | "likely_scam" | "scam"
    ScamReport.signals    # list of (category, weight, snippet) hits
    ScamReport.scam_type  # best-guess category (or "unknown")
    ScamReport.entities   # phones, emails, urls, handles, money asks

The engine is deliberately:
    * conservative — false positives cost the user time
    * transparent — every signal that contributed to the score is exposed
    * extension-friendly — add new patterns in SCAM_PATTERNS below
"""

from __future__ import annotations

import re
import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Tuple, Optional
# ---------------------------------------------------------------------------
# Pattern bank
# ---------------------------------------------------------------------------
# Each entry: (scam_type, category, weight, regex)
#   scam_type : which bucket this signal suggests
#   category  : human-readable signal name (shown in the report)
#   weight    : how much this signal nudges the score (0-100 total possible)
#   pattern   : compiled regex
#
# Tweak freely. Weights are tuned so a single message with a few hits from
# the same scam type lands in "likely_scam"; many hits push into "scam".
# ---------------------------------------------------------------------------

SCAM_PATTERNS: List[Tuple[str, str, int, "re.Pattern"]] = [
    # === TECH SUPPORT / REFUND SCAM ===
    ("tech_support", "claims to be Microsoft/Apple/Geek Squad/Amazon support", 25,
        re.compile(r"\b(microsoft|apple support|geek squad|amazon (?:support|security)|norton|mcafee|avast)\b", re.I)),
    ("tech_support", "remote-access request (AnyDesk, TeamViewer, Quick Support)", 30,
        re.compile(r"\b(anydesk|teamviewer|quick ?support|rustdesk|supremo|connectwise)\b", re.I)),
    ("tech_support", "asks to install software / grant access", 15,
        re.compile(r"\b(install|download|run|open|type)\b.{0,40}\b(software|program|app|command|cmd|terminal|this (?:link|file))\b", re.I)),

    # === IRS / SSA / "government" ===
    ("government", "claims to be IRS/SSA/FBI/marshall/court", 30,
        re.compile(r"\b(internal revenue|IRS|social security (?:administration|office)|SSA|FBI|U\.?S\.? Marshal|Department of Justice|federal court|warrant (?:for your )?arrest)\b", re.I)),
    ("government", "demands payment to avoid arrest", 25,
        re.compile(r"\b(arrest|jail|prison|legal action|criminal charges|warrant)\b.{0,80}\b(pay|payment|owe|back\s*taxes|unpaid)\b", re.I)),
    ("government", "asks for gift cards / wire / crypto as tax payment", 30,
        re.compile(r"\b(gift ?cards?|itunes|google play|steam cards?|bitcoin|crypto ?wallet|wire transfer|western union|moneygram)\b", re.I)),

    # === BANK / "FRAUD DEPARTMENT" CALLING YOU ===
    ("bank_impersonation", "claims to be bank fraud / Visa / Mastercard security", 25,
        re.compile(r"\b(bank (?:fraud|security)|visa (?:security|fraud)|mastercard (?:security|fraud)|fraud (?:department|unit|team)|account (?:is )?compromised|unauthorized (?:charge|transaction))\b", re.I)),
    ("bank_impersonation", "asks for full card number / PIN / SSN / online banking password", 35,
        re.compile(r"\b(card number|cvv|security code|pin (?:number|code)|social security number|ssn|online (?:banking|password)|one[- ]time (?:code|password|passcode)|otp)\b", re.I)),
    ("bank_impersonation", "asks you to move money to 'safe' account", 25,
        re.compile(r"\b(safe (?:account|wallet)|protect (?:your )?funds|transfer (?:to|into) .{0,30}account|verify (?:your )?(?:account|identity))\b", re.I)),

    # === PACKAGE / DELIVERY ===
    ("package", "fake USPS / UPS / FedEx / DHL package problem", 25,
        re.compile(r"\b(usps|ups|fedex|dhl)\b.{0,80}\b(deliver(?:ed|ing)?|package|parcel|shipment|redeliver|address (?:issue|problem)|held|customs)\b|\bpackage\b.{0,80}\b(customs|redeliver|small fee|verification|reschedule)\b", re.I)),
    ("package", "asks for small redelivery / customs fee", 15,
        re.compile(r"\b(customs (?:fee|charge)|redelivery (?:fee|charge)|small (?:re-?)?shipment fee|confirm (?:your )?(?:address|details) (?:to|for) delivery)\b", re.I)),
    ("package", "fake redelivery / customs link domain", 20,
        re.compile(r"\b[a-z0-9\-]*\b(?:usps|ups|fedex|dhl)\b[a-z0-9\-]*\.(?:top|xyz|click|support|help|online|delivery|track)\b", re.I)),

    # === ROMANCE / "LONELY HEART" ===
    ("romance", "long-distance / military / oil-rig / doctor abroad", 25,
        re.compile(r"\b(deployed (?:in|to)|on (?:a|an) (?:oil rig|ship|military base)|stranded|stuck in|customs (?:in|at) [A-Z])\b", re.I)),
    ("romance", "lovesick / soulmate language early on", 15,
        re.compile(r"\b(my (?:dear(?:est)?|love|beautiful|queen|king|soul ?mate|everything|heart)|i (?:fell|am falling) (?:deeply )?in love|missing you (?:so much|already)|can'?t wait to (?:see|meet|hold) you)\b", re.I)),
    ("romance", "money / gift card ask from romantic partner", 30,
        re.compile(r"\b(can you (?:help|send|lend|wire|transfer|gift)|need (?:a little|some) (?:help|money|favor)|i('?m| am) (?:stuck|in trouble|stranded) and need)\b", re.I)),

    # === JOB / RECRUITER ===
    ("job_scam", "unusually high pay / easy work / immediate start", 20,
        re.compile(r"\b(\$\s?\d{2,4}\s?(?:/|per|a|an) (?:day|hour|week|task)|easy (?:money|cash|work)|work[- ]from[- ]home (?:and earn|opportunity)|no experience (?:needed|required)|immediate (?:start|hiring))\b", re.I)),
    ("job_scam", "asks for upfront payment / training fee / equipment buy-in", 25,
        re.compile(r"\b(training fee|startup (?:fee|cost)|equipment (?:fee|deposit)|send (?:a|us) (?:money|funds) (?:to|for)|pay (?:first|upfront) (?:a|the))\b", re.I)),
    ("job_scam", "asks for bank details or to receive + forward money", 30,
        re.compile(r"\b(receive (?:payments?|funds?|transfers?) and (?:forward|send|wire)|deposit (?:into|to) your (?:bank|account)|provide (?:your )?(?:bank|account) (?:details|info))\b", re.I)),

    # === CRYPTO / "INVESTMENT" ===
    ("crypto_investment", "guaranteed / risk-free / huge returns", 25,
        re.compile(r"\b(guaranteed (?:return|profit|earnings)|risk[- ]free (?:invest|trading)|(100|x|10x|20x) (?:return|lever|gain)|passive income of \$?\d{3,}|get (?:rich|wealthy) (?:with|using|through))\b", re.I)),
    ("crypto_investment", "fake celebrity endorsement or 'insider' pitch", 20,
        re.compile(r"\b(elon (?:musk )?giveaway|crypto (?:airdrop|signal (?:group|channel))|forex (?:mentor|signal)|whale (?:wallet|alert)|insider (?:tip|info)|pump (?:and|&) dump)\b", re.I)),
    ("crypto_investment", "asks to send crypto / connect wallet to 'claim'", 30,
        re.compile(r"\b(connect (?:your )?(?:wallet|metamask|trust wallet)|send (?:a|0\.\d+) (?:eth|btc|usdt) to (?:claim|verify|activate|unlock))\b", re.I)),

    # === LOTTERY / "YOU WON" ===
    ("lottery", "you won / claim prize / lucky winner", 25,
        re.compile(r"\b(congratulations? (?:you|on winning)|you(?:'ve| have) (?:won|been selected)|claim (?:your )?(?:prize|reward|winnings?)|lucky (?:winner|draw))\b", re.I)),
    ("lottery", "lottery you never entered", 15,
        re.compile(r"\b(microsoft (?:lotto|lottery|award)|amazon (?:lottery|award)|bmw (?:giveaway|lottery)|mega (?:millions|lotto) (?:winner|prize))\b", re.I)),

    # === UNSOLICITED TECHNICALLY-ANYTHING: URGENCY + SECRECY ===
    ("universal", "urgency / countdown / act now", 10,
        re.compile(r"\b(within (?:the next )?(?:\d{1,3} (?:minutes?|hours?)|24 hours|48 hours)|act (?:now|immediately|fast|quickly)|don'?t (?:delay|wait)|time[- ]sensitive|expires? (?:today|in \d+ (?:min|hour|day)))\b", re.I)),
    ("universal", "secrecy / don't tell anyone", 15,
        re.compile(r"\b(don'?t (?:tell|inform|notify) (?:anyone|your (?:bank|family|partner))|keep (?:this )?(?:between us|confidential|private)|(?:this )?must (?:remain|be) (?:confidential|a secret))\b", re.I)),
    ("universal", "payment in untraceable form (gift cards, crypto, wire, Zelle-to-yourself)", 20,
        re.compile(r"\b(gift ?cards?|itunes cards?|google play cards?|steam cards?|vanilla (?:visa )?cards?|bitcoin|crypto|usdt|wire (?:transfer)?|western union|moneygram|zelle|venmo|cash ?app)\b", re.I)),
    ("universal", "click here / tap here / log in via link", 10,
        re.compile(r"\b(click (?:here|below|the link)|tap (?:here|the link)|follow (?:this )?(?:link|url)|log ?in (?:here|via (?:this )?link)|verify (?:your )?account (?:now|here|via))\b", re.I)),
    ("universal", "shortened / lookalike / punycode link", 15,
        re.compile(r"\b((?:bit\.ly|tinyurl\.com|t\.co|is\.gd|ow\.ly|rebrand\.ly|cutt\.ly|shorturl\.at|rb\.gy|lnkd\.in|tiny\.cc)/\S+|(?:[a-z0-9-]+\.){1,3}(?:xyz|top|click|support|help|secure|login|verify|account|update)(?:/\S*)?)\b", re.I)),
]

# Brand-impersonation table: official domain → list of common typo domains.
# If the message contains a brand word + a link, we flag the mismatch.
BRAND_DOMAINS: Dict[str, List[str]] = {
    "paypal":     ["paypa1", "paypall", "paypaI", "paypai", "paypa.l"],
    "amazon":     ["amaz0n", "amazom", "amazn", "amaz.on", "arnazon"],
    "apple":      ["app1e", "appie", "app1e-id", "apple-id"],
    "microsoft":  ["microsft", "micros0ft", "mircosoft", "micros oft", "msft-login"],
    "google":     ["go0gle", "g00gle", "gogle", "goog1e"],
    "fedex":      ["fedexx", "fed-ex", "fede-x"],
    "ups":        ["ups-tracking", "ups-delivery"],
    "usps":       ["uspss", "us-ps", "usps-track"],
    "dhl":        ["dh1", "dhl-tracking"],
    "chase":      ["chase-bank", "chaseonline-"],
    "wells fargo":["wellsfarg0", "wellfargo", "wels-fargo"],
    "netflix":    ["netf1ix", "netfllx"],
    "facebook":   ["faceb00k", "facebok", "facebook-login"],
    "instagram":  ["1nstagram", "instagrarn"],
    "linkedin":   ["1inkedin", "linkedln", "linked-in"],
}

# Words that should appear in monetary asks of $5+; we use these to extract
# any dollar/euro/pound amounts a scammer is requesting. We match either:
#   symbol-first:   $299, €1,500.00, £20
#   currency-first: USD 299, EUR 1,500.00
#   number-first:   299 dollars, 1,500 euros
MONEY_REGEX = re.compile(
    r"(?:[$€£]\s?\d[\d,.\s]*|\b(?:usd|eur|gbp)\s?\$?\s?\d[\d,.\s]*"
    r"|\b\d[\d,.\s]*\s?(?:dollars?|usd|euros?|eur|gbp|pounds?))",
    re.I,
)


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------

@dataclass
class ScamReport:
    score: int
    verdict: str
    scam_type: str
    signals: List[Dict] = field(default_factory=list)
    entities: Dict[str, List[str]] = field(default_factory=dict)
    advice: List[str] = field(default_factory=list)
    channel: str = "unknown"

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def __str__(self) -> str:
        lines = [
            f"Scam-Shield report",
            f"==================",
            f"channel       : {self.channel}",
            f"score         : {self.score}/100  ({self.verdict})",
            f"scam type     : {self.scam_type}",
            f"signals       : {len(self.signals)}",
        ]
        if self.signals:
            lines.append("")
            lines.append("signals:")
            for s in self.signals:
                lines.append(f"  [{s['scam_type']}] {s['category']}  (+{s['weight']})  {s['snippet']!r}")
        if self.entities:
            lines.append("")
            lines.append("entities:")
            for k, v in self.entities.items():
                if v:
                    lines.append(f"  {k:9}: {', '.join(v[:5])}")
        if self.advice:
            lines.append("")
            lines.append("advice:")
            for a in self.advice:
                lines.append(f"  - {a}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entity extractors
# ---------------------------------------------------------------------------

PHONE_RE  = re.compile(r"(?:(?<=\s)|(?<=\b))(\+?\d{1,3}[ \-]?\(?\d{2,4}\)?[ \-]?\d{3,4}[ \-]?\d{3,4})(?=\s|$|[.,;])")
EMAIL_RE  = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
URL_RE    = re.compile(r"\b((?:https?://|www\.)[^\s<>\"']+|[a-z0-9\-]+\.[a-z]{2,}(?:/\S*)?)", re.I)
HANDLE_RE = re.compile(r"(?<![A-Za-z0-9._])@([A-Za-z0-9_]{3,30})\b")

# Carriers / country codes commonly abused; just a hint, not a verdict.
HIGH_RISK_CC = {"+91", "+92", "+234", "+254", "+63", "+62", "+880", "+375"}


def _extract_entities(text: str) -> Dict[str, List[str]]:
    phones = []
    for m in PHONE_RE.finditer(text):
        num = re.sub(r"[^\d+]", "", m.group(1))
        if 7 <= len(num) <= 15:
            phones.append(m.group(1).strip(" .-,"))
    phones = list(dict.fromkeys(phones))[:5]

    emails = list(dict.fromkeys(EMAIL_RE.findall(text)))[:5]

    urls: List[str] = []
    for m in URL_RE.finditer(text):
        u = m.group(1).rstrip(".,;:!?)")
        # drop stray trailing punctuation
        if u and u not in urls:
            urls.append(u)
    urls = urls[:10]

    handles = list(dict.fromkeys(HANDLE_RE.findall(text)))[:5]

    money: List[str] = []
    for m in MONEY_REGEX.finditer(text):
        money.append(m.group(0).strip())

    return {
        "phones": phones,
        "emails": emails,
        "urls": urls,
        "handles": handles,
        "money": money,
    }


# ---------------------------------------------------------------------------
# Verdict logic
# ---------------------------------------------------------------------------

def _verdict(score: int) -> str:
    if score >= 75: return "scam"
    if score >= 50: return "likely_scam"
    if score >= 25: return "suspicious"
    return "clean"


def _advice_for(scam_type: str) -> List[str]:
    base = [
        "Never send money, gift cards, crypto, or wire transfers to someone you cannot meet in person.",
        "Never share full SSN, full card number, CVV, PIN, or one-time codes over phone/email/chat.",
        "Hang up and call the institution back on a number you look up yourself (back of card, official site).",
    ]
    extra = {
        "tech_support":     [
            "Real Microsoft/Apple support will never cold-call you about a problem.",
            "Never install remote-access software at the request of an unsolicited caller.",
        ],
        "government":       [
            "The IRS, SSA, and FBI NEVER demand gift cards, crypto, or wire transfers.",
            "Real agencies send official correspondence by mail first. Threats of immediate arrest are always a scam.",
        ],
        "bank_impersonation": [
            "Your bank already has your account info — they will not ask you to 'verify' the full number or PIN.",
            "If a 'fraud department' calls you, hang up and call the number on the back of your card.",
        ],
        "package":          [
            "Carriers charge redelivery/customs via the official site or app, never via a link in a text.",
        ],
        "romance":          [
            "Reverse-search their photos. Never send money to someone you have not met in person.",
            "Insist on a live video call early. Most scammers will refuse.",
        ],
        "job_scam":         [
            "Legitimate employers never charge upfront fees for training or equipment.",
            "Never receive and forward payments on behalf of a 'client' — that is money laundering.",
        ],
        "crypto_investment": [
            "There is no such thing as guaranteed returns in crypto. Anyone promising them is committing fraud.",
            "Never connect your wallet to a site sent by a stranger.",
        ],
        "lottery":          [
            "You cannot win a lottery you did not enter. Real lotteries do not require you to pay to claim.",
        ],
        "universal":        [
            "Urgency + secrecy + untraceable payment = scam. Full stop.",
        ],
    }
    return base + extra.get(scam_type, [])


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyze(message: str, *, channel: str = "unknown") -> ScamReport:
    """
    Run the full heuristic analysis on a single message (or pasted thread).
    Returns a ScamReport.
    """
    if not message or not message.strip():
        return ScamReport(score=0, verdict="clean", scam_type="unknown",
                          channel=channel, advice=["Empty input."])

    text = message
    lower = text.lower()
    signals: List[Dict] = []
    type_score: Dict[str, int] = {}

    # 1. Pattern hits
    for scam_type, category, weight, pat in SCAM_PATTERNS:
        m = pat.search(text)
        if m:
            signals.append({
                "scam_type": scam_type,
                "category": category,
                "weight": weight,
                "snippet": m.group(0)[:120],
            })
            type_score[scam_type] = type_score.get(scam_type, 0) + weight

    # 2. Brand-impersonation: lookalike domain next to a brand word
    urls_in_text = URL_RE.findall(text)
    for brand, typos in BRAND_DOMAINS.items():
        if brand in lower:
            for url in urls_in_text:
                u = url.lower()
                if any(typo in u for typo in typos) or (
                    brand in u and not re.search(rf"\b{re.escape(brand)}\.(com|net|org|co|gov|io|ca|uk|de)\b", u)
                ):
                    signals.append({
                        "scam_type": "phishing",
                        "category": f"impersonating {brand} via lookalike link",
                        "weight": 30,
                        "snippet": url[:120],
                    })
                    type_score["phishing"] = type_score.get("phishing", 0) + 30

    # 2b. Phishing urgency: phishing link + "click here" / "verify account"
    if "phishing" in type_score:
        if re.search(r"\b(click (?:here|below|the link)|verify (?:your )?account|log ?in (?:here|via) (?:this )?link|suspended|locked|limited)\b", lower):
            signals.append({
                "scam_type": "phishing",
                "category": "phishing link + account-suspension urgency",
                "weight": 15,
                "snippet": "phishing + urgency combo",
            })
            type_score["phishing"] = type_score.get("phishing", 0) + 15

    # 3. Domain-age / punycode / IP-as-host heuristic
    for url in urls_in_text:
        host = re.sub(r"^https?://", "", url).split("/")[0].split("?")[0].lower()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            signals.append({"scam_type": "phishing", "category": "raw IP address in link",
                            "weight": 20, "snippet": url[:120]})
            type_score["phishing"] = type_score.get("phishing", 0) + 20
        if "xn--" in host:
            signals.append({"scam_type": "phishing", "category": "punycode / IDN homograph link",
                            "weight": 20, "snippet": url[:120]})
            type_score["phishing"] = type_score.get("phishing", 0) + 20

    # 4. Free webmail in a "from" context
    for email in EMAIL_RE.findall(text):
        domain = email.split("@", 1)[1].lower()
        if domain in {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "proton.me", "icloud.com"}:
            # only count if the message claims a corporate role
            corporate_words = re.search(
                r"\b(support|agent|representative|recruiter|manager|officer|administrator|security|compliance|department|team)\b",
                lower)
            if corporate_words:
                signals.append({
                    "scam_type": "impersonation",
                    "category": f"claims corporate role but emails from {domain}",
                    "weight": 20, "snippet": email,
                })
                type_score["impersonation"] = type_score.get("impersonation", 0) + 20

    # 5. Suspicious phone country code
    for phone in PHONE_RE.findall(text):
        if any(phone.strip().startswith(cc) for cc in HIGH_RISK_CC):
            # soft signal — country code alone is not a scam
            pass

    # 6. Pick best scam type
    scam_type = max(type_score, key=type_score.get) if type_score else "unknown"
    if not type_score:
        # universal-only hits roll up to "unknown"
        if any(s["scam_type"] == "universal" for s in signals):
            scam_type = "universal"

    # 7. Score (clamped 0-100, dimishing returns after several signals)
    raw = sum(s["weight"] for s in signals)
    # sqrt-ish damping so 100 doesn't require 4x signals
    score = min(100, int(round(100 * (1 - (1 - 0.05) ** (raw / 5)))))
    # if many distinct scam types are firing, bump the score a bit
    if len(type_score) >= 2:
        score = min(100, score + 5)
    if len(type_score) >= 3:
        score = min(100, score + 5)

    # 8. Tie-break scam_type when scores are close. Higher-priority types win.
    priority = [
        "phishing",            # impersonating a known brand via link
        "crypto_investment",   # crypto giveaway is more specific than gov
        "tech_support",
        "bank_impersonation",
        "government",
        "romance",
        "job_scam",
        "package",
        "lottery",
        "universal",
    ]
    if type_score:
        max_score = max(type_score.values())
        top = [t for t, s in type_score.items() if s >= max_score - 5]
        # among close-scoring types, take the highest-priority one
        for t in priority:
            if t in top:
                scam_type = t
                break

    verdict = _verdict(score)
    entities = _extract_entities(text)
    advice = _advice_for(scam_type) if verdict != "clean" else [
        "Nothing obvious triggered. Stay alert — no detector is perfect."
    ]

    return ScamReport(
        score=score,
        verdict=verdict,
        scam_type=scam_type,
        signals=signals,
        entities=entities,
        advice=advice,
        channel=channel,
    )


# ---------------------------------------------------------------------------
# Convenience: detect on a file
# ---------------------------------------------------------------------------

def analyze_file(path: str, *, channel: str = "unknown") -> ScamReport:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return analyze(f.read(), channel=channel)


# ---------------------------------------------------------------------------
# analyze_full — heuristic + (optional) LLM second opinion
# ---------------------------------------------------------------------------

def analyze_full(message: str, *, channel: str = "unknown",
                 use_llm: bool = True, llm_timeout: float = 60.0) -> "FullReport":
    """
    Run the heuristic pass, then ask the local LLM for a second opinion.
    Returns a FullReport that carries both, the comparison, and a final verdict.

    Set use_llm=False to skip the LLM call (offline, fast, deterministic).
    """
    from .llm_judge import judge, compare, JudgeResult
    heur = analyze(message, channel=channel)
    if not use_llm:
        llm = JudgeResult(verdict=heur.verdict, scam_type=heur.scam_type,
                          confidence=0, reason="(LLM pass skipped)",
                          model="(skipped)")
        cmp = compare(heur, llm)
        return FullReport(heuristic=heur, llm=llm, comparison=cmp)
    llm = judge(message, timeout=llm_timeout)
    cmp = compare(heur, llm)
    return FullReport(heuristic=heur, llm=llm, comparison=cmp)


@dataclass
class FullReport:
    heuristic: ScamReport
    llm: "JudgeResult"
    comparison: "Comparison"

    @property
    def score(self) -> int:
        return self.comparison.final_score

    @property
    def verdict(self) -> str:
        return self.comparison.final_verdict

    @property
    def scam_type(self) -> str:
        # prefer the agreed-upon type, else heuristic
        if self.comparison.agree_type and self.llm.scam_type != "unknown":
            return self.llm.scam_type
        return self.heuristic.scam_type

    def to_dict(self) -> Dict:
        return self.comparison.to_dict()

    def __str__(self) -> str:
        lines = [
            f"Scam-Shield FULL report",
            f"=======================",
            f"channel       : {self.heuristic.channel}",
            f"FINAL verdict : {self.verdict}   score: {self.score}/100",
            f"FINAL type    : {self.scam_type}",
            f"",
            f"-- Heuristic --",
            f"  verdict: {self.heuristic.verdict}   score: {self.heuristic.score}/100   type: {self.heuristic.scam_type}",
            f"  signals: {len(self.heuristic.signals)}",
        ]
        if self.heuristic.signals:
            for s in self.heuristic.signals[:5]:
                lines.append(f"    [{s['scam_type']}] {s['category']}  (+{s['weight']})  {s['snippet']!r}")
            if len(self.heuristic.signals) > 5:
                lines.append(f"    ... and {len(self.heuristic.signals) - 5} more")
        lines.append("")
        lines.append("-- LLM judge --")
        if self.llm.error:
            lines.append(f"  (unavailable)  {self.llm.error}")
        else:
            lines.append(f"  verdict: {self.llm.verdict}   confidence: {self.llm.confidence}%   type: {self.llm.scam_type}")
            lines.append(f"  reason: {self.llm.reason}")
            lines.append(f"  model: {self.llm.model}   elapsed: {self.llm.elapsed_ms}ms")
        lines.append("")
        lines.append("-- Comparison --")
        for n in self.comparison.notes:
            lines.append(f"  {n}")
        return "\n".join(lines)
