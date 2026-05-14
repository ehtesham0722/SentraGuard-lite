"""
Core detection logic — pure functions only.
All detectors are heuristic/regex-based for offline, deterministic operation.
"""
import re
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Detector 1 — Prompt Injection / Jailbreak Heuristic
# ---------------------------------------------------------------------------
INJECTION_PHRASES = [
    "ignore previous instructions",
    "ignore all prior instructions",
    "ignore all previous instructions",
    "ignore your instructions",
    "reveal your system prompt",
    "reveal system prompt",
    "show me your system prompt",
    "act as dan",
    "act as an ai with no restrictions",
    "you are now",
    "disregard your instructions",
    "disregard all instructions",
    "forget everything",
    "forget what you were told",
    "override your instructions",
    "pretend you have no restrictions",
    "ignore your guidelines",
    "bypass your restrictions",
    "jailbreak",
    "do anything now",
    "dan mode",
    "developer mode",
    "ignore safety",
    "ignore content policy",
    "no restrictions mode",
    "without any restrictions",
    "act as if you have no",
    "pretend you are",
    "you must ignore",
    "disregard safety",
    "skip your filters",
]

# ---------------------------------------------------------------------------
# Detector 3 — RAG Injection Heuristic (scans context_docs only)
# ---------------------------------------------------------------------------
RAG_INJECTION_PHRASES = [
    "system:",
    "override policy",
    "override instructions",
    "override all instructions",
    "ignore guidelines",
    "ignore your rules",
    "ignore all rules",
    "[inst]",
    "<|system|>",
    "<system>",
    "you must now",
    "new instruction:",
    "updated instructions:",
    "admin override",
    "secret instructions",
    "hidden instruction",
    "disregard previous",
    "forget your training",
    "new directive:",
    "attention: ai",
    "attention ai",
]

# ---------------------------------------------------------------------------
# Detector 2 — PII Patterns
# ---------------------------------------------------------------------------
# Email: standard RFC-ish pattern
EMAIL_PATTERN = re.compile(r"[\w.+\-]+@[\w\-]+\.[\w.]+")

# Phone: US formats — (555) 867-5309 | 555-867-5309 | +1 555 867 5309 | 555.867.5309
# The optional country-code prefix is grouped to prevent its trailing separator
# from greedily consuming the whitespace before the number when no "+1" is present.
PHONE_PATTERN = re.compile(
    r"(?:\+?1[\s.\-])?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]\d{4}"
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_prompt_injection(text: str) -> Tuple[bool, List[str]]:
    """
    Check for prompt injection / jailbreak patterns in text.
    Returns (found: bool, evidence: List[str]).
    """
    text_lower = text.lower()
    matches = []
    for phrase in INJECTION_PHRASES:
        if phrase in text_lower:
            matches.append(f"matched phrase: {phrase}")
    return len(matches) > 0, matches


def detect_pii(text: str) -> Tuple[bool, List[str]]:
    """
    Check for PII (email addresses, phone numbers) in text.
    Returns (found: bool, evidence: List[str]).
    """
    evidence = []
    emails = EMAIL_PATTERN.findall(text)
    phones = PHONE_PATTERN.findall(text)

    if emails:
        evidence.append(f"email pattern found: {len(emails)} instance(s)")
    if phones:
        evidence.append(f"phone pattern found: {len(phones)} instance(s)")

    return len(evidence) > 0, evidence


def redact_pii(text: str) -> str:
    """
    Replace PII in text with redaction placeholders.
    Order matters: redact emails before phones to avoid partial matches.
    """
    text = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", text)
    text = PHONE_PATTERN.sub("[REDACTED_PHONE]", text)
    return text


def detect_rag_injection(text: str) -> Tuple[bool, List[str]]:
    """
    Check for RAG/context-injection patterns in a document's text.
    Returns (found: bool, evidence: List[str]).
    """
    text_lower = text.lower()
    matches = []
    for phrase in RAG_INJECTION_PHRASES:
        if phrase in text_lower:
            matches.append(f"matched phrase: {phrase}")
    return len(matches) > 0, matches
