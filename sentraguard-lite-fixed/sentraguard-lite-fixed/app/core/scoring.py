"""
Risk scoring and decision logic.

Scoring model (additive, capped at 100):
  - prompt_injection triggered : +50
  - pii triggered              : +40
  - rag_injection triggered    : +50

Decision thresholds:
  - score >= 80 → block
  - score >= 40 → transform  (sanitized content returned)
  - score <  40 → allow

Tradeoff: flat per-detector scores are easy to explain and debug,
but do not distinguish severity within a detector (e.g. 1 injection
phrase vs. 5 injection phrases both score +50).  See design notes.
"""

DETECTOR_SCORES = {
    "prompt_injection": 50,
    "pii": 40,
    "rag_injection": 50,
}

THRESHOLDS = {
    "block_score": 80,
    "transform_score": 40,
}


def compute_risk_score(triggered_detectors: list[str]) -> int:
    """
    Sum scores for each triggered detector, cap at 100.
    triggered_detectors: list of detector tag strings that fired.
    """
    total = sum(DETECTOR_SCORES.get(tag, 0) for tag in triggered_detectors)
    return min(total, 100)


def compute_decision(score: int) -> str:
    """Map a risk score to allow / transform / block."""
    if score >= THRESHOLDS["block_score"]:
        return "block"
    if score >= THRESHOLDS["transform_score"]:
        return "transform"
    return "allow"
