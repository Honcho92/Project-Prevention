"""
scam_shield.llm_judge

A second-opinion LLM pass over a message, using your local Ollama
(qwen2.5-coder:7b by default). The judge:

    * looks at the SAME message the heuristic scored
    * is asked structured questions (verdict, scam_type, why)
    * returns its answer parsed into a structured object
    * is compared to the heuristic — if they disagree, we surface that

The judge is NEVER the only signal. It is a soft second pass: if the
heuristic says "scam" and the LLM says "clean", we trust the heuristic
and log the disagreement. If they agree, we boost confidence.

No external services. No API keys. Just your local Ollama at
http://localhost:11434.

Public API
----------
    JudgeResult        dataclass with verdict, scam_type, confidence, reason, raw
    judge(text)        → JudgeResult
    compare(heur, llm) → Comparison  (heuristic + LLM, agreement, deltas)
"""

from __future__ import annotations

import json
import re
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List

from .detector import ScamReport


OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5-coder:7b"

# Verdict vocabulary we accept from the LLM.
_VALID_VERDICTS = {"clean", "suspicious", "likely_scam", "scam"}
_VALID_TYPES = {
    "universal", "tech_support", "government", "bank_impersonation",
    "package", "romance", "job_scam", "crypto_investment", "lottery",
    "phishing", "unknown",
}


SYSTEM_PROMPT = """You are a scam-detection expert. Read the message and answer in STRICT JSON with these keys:
  - verdict:    one of "clean", "suspicious", "likely_scam", "scam"
  - scam_type:  one of "universal", "tech_support", "government", "bank_impersonation",
                "package", "romance", "job_scam", "crypto_investment", "lottery",
                "phishing", "unknown"
  - confidence: integer 0-100, how confident you are in your verdict
  - reason:     one short sentence, max 25 words, explaining the verdict

JSON only. No prose before or after. No markdown fences. If unsure, "suspicious" with low confidence."""


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class JudgeResult:
    verdict: str
    scam_type: str
    confidence: int
    reason: str
    raw: str = ""
    model: str = ""
    elapsed_ms: int = 0
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.verdict in _VALID_VERDICTS

    def to_dict(self) -> Dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Ollama transport
# ---------------------------------------------------------------------------

def _ollama_generate(prompt: str, *, model: str, system: str,
                     timeout: float = 60.0) -> Dict:
    """POST /api/generate. Returns parsed JSON. Raises on transport error."""
    body = json.dumps({
        "model": model,
        "prompt": prompt,
        "system": system,
        "stream": False,
        "options": {
            "temperature": 0.0,        # deterministic
            "num_predict": 200,        # short answers only
            "stop": ["\n\n", "</s>"],
        },
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# Output parsing — strict, with multiple fallbacks
# ---------------------------------------------------------------------------

_JSON_RE = re.compile(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", re.S)


def _extract_json(text: str) -> Optional[Dict]:
    """Pull the first JSON object out of a possibly-noisy LLM response."""
    if not text:
        return None
    text = text.strip()
    # Strip markdown fences if the model added them anyway
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.M).strip()
    # First try direct parse
    try:
        return json.loads(text)
    except Exception:
        pass
    # Then try first {...} block
    m = _JSON_RE.search(text)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return None


def _coerce_verdict(v: Any) -> str:
    if not isinstance(v, str):
        return "suspicious"
    v = v.strip().lower().replace("-", "_").replace(" ", "_")
    if v in _VALID_VERDICTS:
        return v
    # fuzzy mapping
    if v in {"ok", "safe", "legit", "legitimate", "fine", "good"}:
        return "clean"
    if v in {"scam", "fraud", "phishing", "malicious"}:
        return "scam"
    if v in {"likely", "probably", "probably_scam", "likely_scam"}:
        return "likely_scam"
    if v in {"maybe", "unsure", "uncertain", "ambiguous"}:
        return "suspicious"
    return "suspicious"


def _coerce_type(t: Any) -> str:
    if not isinstance(t, str):
        return "unknown"
    t = t.strip().lower().replace("-", "_").replace(" ", "_")
    if t in _VALID_TYPES:
        return t
    # fuzzy
    aliases = {
        "tech": "tech_support", "support": "tech_support", "microsoft": "tech_support",
        "apple": "tech_support", "irs": "government", "ssa": "government", "fbi": "government",
        "tax": "government", "romance": "romance", "dating": "romance", "love": "romance",
        "crypto": "crypto_investment", "bitcoin": "crypto_investment", "investment": "crypto_investment",
        "job": "job_scam", "employment": "job_scam", "recruiter": "job_scam",
        "delivery": "package", "parcel": "package", "fedex": "package", "usps": "package",
        "ups": "package", "dhl": "package",
        "bank": "bank_impersonation", "credit": "bank_impersonation", "fraud_dept": "bank_impersonation",
        "lottery": "lottery", "prize": "lottery", "sweepstakes": "lottery",
        "phish": "phishing", "phishing_link": "phishing",
    }
    return aliases.get(t, "unknown")


def _coerce_confidence(c: Any) -> int:
    try:
        n = int(float(c))
    except Exception:
        return 50
    return max(0, min(100, n))


# ---------------------------------------------------------------------------
# Public judge()
# ---------------------------------------------------------------------------

def judge(text: str, *, model: str = DEFAULT_MODEL,
          timeout: float = 60.0) -> JudgeResult:
    """
    Ask the local LLM to classify `text` and return a parsed JudgeResult.
    Falls back to a "suspicious / unknown / 0%" result on any error
    (so the rest of the system can still proceed).
    """
    if not text or not text.strip():
        return JudgeResult(verdict="suspicious", scam_type="unknown",
                           confidence=0, reason="empty input",
                           model=model, error="empty")

    # Trim very long inputs so we don't blow the context
    snippet = text.strip()
    if len(snippet) > 4000:
        snippet = snippet[:4000] + "\n\n[truncated]"

    user_prompt = (
        "Classify this message:\n\n"
        f"\"\"\"\n{snippet}\n\"\"\"\n\n"
        "Respond with strict JSON only."
    )

    import time
    t0 = time.time()
    try:
        resp = _ollama_generate(user_prompt, model=model, system=SYSTEM_PROMPT,
                                timeout=timeout)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        return JudgeResult(verdict="suspicious", scam_type="unknown",
                           confidence=0, reason="LLM unavailable",
                           model=model, elapsed_ms=int((time.time() - t0) * 1000),
                           error=str(e))

    elapsed_ms = int((time.time() - t0) * 1000)
    raw = (resp.get("response") or "").strip()
    parsed = _extract_json(raw)

    if parsed is None:
        # we got a response, but couldn't parse it
        return JudgeResult(
            verdict="suspicious",
            scam_type="unknown",
            confidence=0,        # signal that we couldn't parse
            reason="could not parse LLM response",
            raw=raw,
            model=resp.get("model", model),
            elapsed_ms=elapsed_ms,
            error="unparseable",
        )

    return JudgeResult(
        verdict=_coerce_verdict(parsed.get("verdict")),
        scam_type=_coerce_type(parsed.get("scam_type")),
        confidence=_coerce_confidence(parsed.get("confidence")),
        reason=str(parsed.get("reason") or "").strip()[:200],
        raw=raw,
        model=resp.get("model", model),
        elapsed_ms=elapsed_ms,
    )


# ---------------------------------------------------------------------------
# Heuristic ↔ LLM comparison
# ---------------------------------------------------------------------------

@dataclass
class Comparison:
    heuristic: ScamReport
    llm: JudgeResult
    agree_verdict: bool
    agree_type: bool
    final_verdict: str
    final_score: int
    boost: int
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "heuristic": self.heuristic.to_dict(),
            "llm": self.llm.to_dict(),
            "agree_verdict": self.agree_verdict,
            "agree_type": self.agree_type,
            "final_verdict": self.final_verdict,
            "final_score": self.final_score,
            "boost": self.boost,
            "notes": self.notes,
        }


_VERDICT_RANK = {"clean": 0, "suspicious": 1, "likely_scam": 2, "scam": 3}


def _max_rank(a: str, b: str) -> str:
    return a if _VERDICT_RANK.get(a, 1) >= _VERDICT_RANK.get(b, 1) else b


def compare(heur: ScamReport, llm: JudgeResult) -> Comparison:
    """Combine heuristic + LLM into a final verdict."""
    agree_v = (heur.verdict == llm.verdict)
    agree_t = (heur.scam_type == llm.scam_type) or (heur.scam_type == "unknown") or (llm.scam_type == "unknown")

    notes: List[str] = []
    boost = 0
    if agree_v and agree_t:
        # both agree, both confident → boost the score
        boost = min(15, llm.confidence // 7)
        notes.append(f"heuristic and LLM agree on {llm.verdict}/{llm.scam_type}")
    elif agree_v and not agree_t:
        # agree on danger level, disagree on type
        notes.append(f"verdicts agree ({llm.verdict}); types differ "
                     f"(heur={heur.scam_type}, llm={llm.scam_type})")
        boost = 5
    elif not agree_v:
        # disagreement — never lower the score below the heuristic
        notes.append(f"DISAGREEMENT: heuristic={heur.verdict}, llm={llm.verdict}")
        if _VERDICT_RANK[llm.verdict] > _VERDICT_RANK[heur.verdict]:
            notes.append("LLM is stricter; trusting the stricter verdict")
            boost = 5
        else:
            notes.append("Heuristic is stricter; keeping heuristic verdict")

    final_verdict = _max_rank(heur.verdict, llm.verdict)
    final_score = min(100, heur.score + boost)

    return Comparison(
        heuristic=heur,
        llm=llm,
        agree_verdict=agree_v,
        agree_type=agree_t,
        final_verdict=final_verdict,
        final_score=final_score,
        boost=boost,
        notes=notes,
    )
