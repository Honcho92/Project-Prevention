"""
scam_shield.honeypot

A auto-reply persona designed to waste a scammer's time, harvest their
inconsistencies, and never let them reach a real victim.

Design:
    * Persona is a target the scammer thinks is gullible (slightly confused,
      older, willing but slow). That keeps them on the line.
    * Each reply is built from the detected scam_type and the previous turns
      in the conversation.
    * Every few turns the persona "asks" a question from the playbook so we
      gather evidence.
    * All exchanges are logged in SQLite for later evidence-packing.

This is a TEMPLATE engine — replies come from a hand-tuned bank. We do not
use a live LLM in the default path, so the bot works offline and is safe
to expose to a scammer's content.
"""

from __future__ import annotations

import os
import re
import json
import sqlite3
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Optional

from .detector import ScamReport, analyze
from . import playbook as pb


# ---------------------------------------------------------------------------
# Personas — slight flavor, kept interchangeable
# ---------------------------------------------------------------------------

PERSONAS = {
    "margaret": {
        "name": "Margaret",
        "voice": "older retired teacher, polite, slow to type, easily confused by technology",
        "filler": ["oh dear", "let me see", "honey, slow down a moment",
                   "my grandson set this up for me, just a sec",
                   "wait, what was that last part?",
                   "ok ok, just tell me what to click"],
        "objections": [
            "I'm not very good with computers — is there an easier way?",
            "Could you walk me through it again, slower?",
            "I don't have that info in front of me, can I get back to you tomorrow?",
        ],
        "stalls": [
            "Hold on, my cat just jumped on the keyboard...",
            "The mailman is at the door, one moment please.",
            "I'm having trouble finding my reading glasses, be right back.",
            "Oh wait, I think I have to reboot this thing, it froze.",
        ],
    },
    "bob": {
        "name": "Bob",
        "voice": "retired veteran, polite, asks lots of clarifying questions, slightly suspicious",
        "filler": ["alright", "ok", "say again?", "go on",
                   "now hold on a second",
                   "let me make sure I understand"],
        "objections": [
            "I need to talk to my wife before I do anything like that.",
            "Why does the government need me to do this over the phone?",
            "Can you mail me the paperwork instead? I'm not great with all this.",
        ],
        "stalls": [
            "One moment, the wife is calling me from the other room.",
            "Hold on, the dog needs to go out.",
            "My phone is acting up, give me a sec to restart it.",
        ],
    },
    "sam": {
        "name": "Sam",
        "voice": "young professional, busy, slightly distracted, willing but rushed",
        "filler": ["ok cool", "got it", "hmm", "makes sense",
                   "wait what", "let me check"],
        "objections": [
            "I'm in a meeting, can we keep this short?",
            "Is there a form I can fill out online instead?",
            "I'll do it later tonight, send me the link in writing.",
        ],
        "stalls": [
            "Sorry, my boss just pinged me, brb 2 min.",
            "Phone glitched, what was the last thing?",
            "Switching to my laptop, one sec.",
        ],
    },
}


# ---------------------------------------------------------------------------
# Reply templates by scam_type
# ---------------------------------------------------------------------------

REPLY_TEMPLATES: Dict[str, List[str]] = {
    "tech_support": [
        "Oh my, that does sound serious. Which tier are you with, dear — 1, 2, or 3? My grandson usually handles this but he's not here.",
        "Ok ok, just to be safe — what is your employee ID and which data center shows my case?",
        "I tried to type what you said but I think I made a mistake. Can you tell me again, slowly?",
        "You know what, I can't find the start menu you mentioned. Where exactly is it?",
    ],
    "government": [
        "Oh dear, an arrest warrant? That's terrifying. Which field office is this out of — I want to make sure I'm sending the right place.",
        "I want to cooperate, I really do. But can you mail me the official notice first? I don't trust phone calls for this kind of thing.",
        "Before I do anything, I need to call my nephew who's a lawyer. Just give me your name and case number and I'll get back to you.",
    ],
    "bank_impersonation": [
        "I'm shaking right now. Before we go on, can you tell me the last four of the card you see on your screen? Just to make sure I'm talking to my real bank.",
        "Which merchant was the suspicious charge from? I want to write that down.",
        "Can you give me a case number so when I call the number on the back of my card they can pull this up?",
    ],
    "package": [
        "Oh good, I was wondering where that was! What's the full tracking number so I can look it up too?",
        "Which hub is it stuck at? My daughter lives near the Memphis one, maybe I can have her pick it up.",
        "The little fee — is that for sure the only charge? My husband is going to ask.",
    ],
    "romance": [
        "I miss you so much too, honey. Tell me — what's the name of the cafe on the corner near your place? I want to picture you there.",
        "Before I do anything, can you send me a selfie holding today's paper? Just so I know it's really you, baby.",
        "Money's tight right now, but if you really need help, what is it exactly for? I love you and I want to trust you.",
    ],
    "job_scam": [
        "That sounds perfect! Quick — what's the company EIN? I like to keep records.",
        "Before I fill anything out, can you send the offer letter from a company email? My last job tried to scam me and I don't want that again.",
        "Who reports to the hiring manager? I'd like to know my future team.",
    ],
    "crypto_investment": [
        "Wow, that's a lot of money. Just to verify — what's your FINRA license number? I want to be smart about this.",
        "Which state are you registered to sell in? My accountant will ask.",
        "Can I talk to one other investor before I commit? Just one name and number.",
    ],
    "lottery": [
        "Oh my goodness! I don't remember entering a lottery though... when exactly did I sign up?",
        "That's amazing. Quick — which form will the IRS want, 1099-MISC or W-2G? My tax guy will ask.",
    ],
    "phishing": [
        "The link isn't loading for me. What's the company's official domain so I can type it in myself?",
        "I'm a little nervous clicking links. Can you tell me what's on the page first?",
    ],
    "universal": [
        "Hold on, my husband/wife is calling from the other room. Just one second.",
        "I need to think about this for a bit. Can I get back to you in an hour?",
        "Could you spell your last name for me? I want to write it down correctly.",
    ],
}


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

DEFAULT_DB = os.path.expanduser("~/.scam-shield/honeypot.sqlite")


def _connect(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            persona TEXT NOT NULL,
            scam_type TEXT,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            turns INTEGER DEFAULT 0,
            metadata TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL REFERENCES sessions(id),
            role TEXT NOT NULL,    -- 'scammer' or 'honeypot'
            content TEXT NOT NULL,
            at TEXT NOT NULL,
            meta TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL REFERENCES sessions(id),
            kind TEXT NOT NULL,
            detail TEXT NOT NULL,
            at TEXT NOT NULL
        )
    """)
    return conn


@dataclass
class Session:
    db_path: str
    conn: sqlite3.Connection
    session_id: int
    persona: Dict
    persona_name: str
    scam_type: str
    turn: int = 0

    def log_scammer(self, message: str, meta: Optional[Dict] = None) -> None:
        self.turn += 1
        self.conn.execute(
            "INSERT INTO messages (session_id, role, content, at, meta) VALUES (?,?,?,?,?)",
            (self.session_id, "scammer", message,
             datetime.now(timezone.utc).isoformat(),
             json.dumps(meta or {})),
        )
        self.conn.execute(
            "UPDATE sessions SET turns = ? WHERE id = ?", (self.turn, self.session_id))
        self.conn.commit()

    def log_reply(self, message: str, meta: Optional[Dict] = None) -> None:
        self.conn.execute(
            "INSERT INTO messages (session_id, role, content, at, meta) VALUES (?,?,?,?,?)",
            (self.session_id, "honeypot", message,
             datetime.now(timezone.utc).isoformat(),
             json.dumps(meta or {})),
        )
        self.conn.commit()

    def log_evidence(self, kind: str, detail: str) -> None:
        self.conn.execute(
            "INSERT INTO evidence (session_id, kind, detail, at) VALUES (?,?,?,?)",
            (self.session_id, kind, detail,
             datetime.now(timezone.utc).isoformat()),
        )
        self.conn.commit()

    def ingest(self, scammer_message: str) -> str:
        """
        Feed one scammer message into the session and return the honeypot's reply.
        Updates the session DB.
        """
        last_messages = [m["content"] for m in self.history()[-3:]]

        # Re-analyze on every message so the persona adapts if the scammer pivots
        report = analyze(scammer_message, channel="honeypot")
        if report.scam_type != "unknown" and report.scam_type != self.scam_type:
            self.scam_type = report.scam_type
            self.conn.execute(
                "UPDATE sessions SET scam_type=? WHERE id=?",
                (self.scam_type, self.session_id),
            )

        self.log_scammer(scammer_message, meta=report.to_dict())

        # Capture signals as evidence
        for s in report.signals:
            self.log_evidence("signal", f"[{s['scam_type']}] {s['category']}  ({s['snippet']!r})")
        for url in report.entities.get("urls", []):
            self.log_evidence("url", url)
        for email in report.entities.get("emails", []):
            self.log_evidence("email", email)
        for phone in report.entities.get("phones", []):
            self.log_evidence("phone", phone)

        reply = _generate_reply(scammer_message, self.scam_type, self.persona,
                                self.turn, last_messages)
        self.log_reply(reply, meta={"scam_type": self.scam_type})
        return reply

    def history(self) -> List[Dict]:
        cur = self.conn.execute(
            "SELECT role, content, at FROM messages WHERE session_id=? ORDER BY id",
            (self.session_id,),
        )
        return [{"role": r[0], "content": r[1], "at": r[2]} for r in cur.fetchall()]

    def close(self) -> None:
        self.conn.execute(
            "UPDATE sessions SET ended_at=? WHERE id=?",
            (datetime.now(timezone.utc).isoformat(), self.session_id),
        )
        self.conn.commit()
        self.conn.close()


# ---------------------------------------------------------------------------
# Reply generation
# ---------------------------------------------------------------------------

QUESTION_FREQ = 4  # ask a playbook question every Nth turn


def _generate_reply(scammer_message: str, scam_type: str, persona: Dict,
                    turn: int, last_messages: List[str]) -> str:
    """Build one in-character reply."""
    pool = REPLY_TEMPLATES.get(scam_type, REPLY_TEMPLATES["universal"])
    parts: List[str] = []

    # 1. Light acknowledgement / filler
    parts.append(random.choice(persona["filler"]))

    # 2. A question from the playbook every Nth turn
    if turn > 0 and turn % QUESTION_FREQ == 0:
        qs = pb.pick_questions(scam_type, n=1, also_universal=True)
        if qs:
            parts.append(qs[0].question)

    # 3. A body sentence (from the reply pool, avoiding the last reply's)
    candidates = [t for t in pool if t not in last_messages]
    if not candidates:
        candidates = pool
    body = random.choice(candidates)
    parts.append(body)

    # 4. Sometimes a stall
    if random.random() < 0.25:
        parts.append(random.choice(persona["stalls"]))

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start_session(*, persona: str = "margaret", scam_type: str = "universal",
                  db_path: str = DEFAULT_DB) -> Session:
    if persona not in PERSONAS:
        raise ValueError(f"unknown persona: {persona}. choose from {list(PERSONAS)}")
    p = PERSONAS[persona]
    conn = _connect(db_path)
    cur = conn.execute(
        "INSERT INTO sessions (persona, scam_type, started_at) VALUES (?,?,?)",
        (persona, scam_type, datetime.now(timezone.utc).isoformat()),
    )
    sid = cur.lastrowid
    conn.commit()
    return Session(db_path=db_path, conn=conn, session_id=sid,
                   persona=p, persona_name=p["name"], scam_type=scam_type)


def ingest(session: Session, scammer_message: str) -> str:
    """Module-level alias for Session.ingest (kept for backwards compat)."""
    return session.ingest(scammer_message)


def export_report(session: Session) -> Dict:
    """Return everything in the session as a dict for the evidence pack."""
    return {
        "session_id": session.session_id,
        "persona": session.persona_name,
        "scam_type": session.scam_type,
        "turns": session.turn,
        "messages": session.history(),
        "evidence": [
            {"kind": r[0], "detail": r[1], "at": r[2]}
            for r in session.conn.execute(
                "SELECT kind, detail, at FROM evidence WHERE session_id=? ORDER BY id",
                (session.session_id,),
            ).fetchall()
        ],
    }
