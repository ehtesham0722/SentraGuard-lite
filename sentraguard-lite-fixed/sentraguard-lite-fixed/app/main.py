"""
SentraGuard Lite — FastAPI entrypoint.
Exactly 2 endpoints as specified:
  POST /analyze
  GET  /policy
"""
from fastapi import FastAPI

from app.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    ContextDoc,
    PolicyResponse,
    Reason,
)
from app.core.detectors import (
    detect_prompt_injection,
    detect_pii,
    detect_rag_injection,
    redact_pii,
)
from app.core.scoring import (
    THRESHOLDS,
    compute_decision,
    compute_risk_score,
)

app = FastAPI(
    title="SentraGuard Lite",
    description="Minimal GenAI guardrails gateway — prompt/context analysis and policy decisions.",
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# Static policy config
# ---------------------------------------------------------------------------
_POLICY = {
    "version": "1",
    "detectors": ["prompt_injection", "pii", "rag_injection"],
    "thresholds": THRESHOLDS,
}


# ---------------------------------------------------------------------------
# POST /analyze
# ---------------------------------------------------------------------------
@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Analyze a prompt + optional context docs.
    Returns a policy decision with risk score, tags, reasons,
    and sanitized outputs when decision is 'transform' or 'block'.
    """
    risk_tags: list[str] = []
    reasons: list[Reason] = []
    triggered_detectors: list[str] = []

    # ── Detector 1: Prompt Injection ────────────────────────────────────────
    inj_found, inj_evidence = detect_prompt_injection(request.prompt)
    if inj_found:
        triggered_detectors.append("prompt_injection")
        risk_tags.append("prompt_injection")
        for ev in inj_evidence:
            reasons.append(Reason(tag="prompt_injection", evidence=ev))

    # ── Detector 2: PII in prompt ───────────────────────────────────────────
    pii_found, pii_evidence = detect_pii(request.prompt)
    if pii_found:
        triggered_detectors.append("pii")
        risk_tags.append("pii")
        for ev in pii_evidence:
            reasons.append(Reason(tag="pii", evidence=ev))

    # ── Detector 3: RAG Injection + PII in context docs ─────────────────────
    rag_doc_results: list[tuple[ContextDoc, bool, list[str], bool]] = []
    for doc in request.context_docs or []:
        rag_found, rag_evidence = detect_rag_injection(doc.text)
        # Also check for PII inside context docs
        doc_pii_found, doc_pii_evidence = detect_pii(doc.text)
        rag_doc_results.append((doc, rag_found, rag_evidence, doc_pii_found))
        if rag_found:
            for ev in rag_evidence:
                reasons.append(
                    Reason(tag="rag_injection", evidence=f"doc {doc.id}: {ev}")
                )
        if doc_pii_found:
            for ev in doc_pii_evidence:
                reasons.append(
                    Reason(tag="pii", evidence=f"doc {doc.id}: {ev}")
                )

    rag_any_found = any(r[1] for r in rag_doc_results)
    if rag_any_found and "rag_injection" not in triggered_detectors:
        triggered_detectors.append("rag_injection")
        risk_tags.append("rag_injection")

    doc_pii_any = any(r[3] for r in rag_doc_results)
    if doc_pii_any and "pii" not in triggered_detectors:
        triggered_detectors.append("pii")
        risk_tags.append("pii")

    # ── Scoring & Decision ──────────────────────────────────────────────────
    risk_score = compute_risk_score(triggered_detectors)
    decision = compute_decision(risk_score)

    # ── Sanitize Outputs ────────────────────────────────────────────────────
    # Sanitization is applied for both 'transform' and 'block' decisions.
    # 'allow' returns the original content unchanged.
    should_sanitize = decision in ("transform", "block")

    sanitized_prompt = redact_pii(request.prompt) if should_sanitize else request.prompt

    sanitized_docs: list[ContextDoc] = []
    for doc, rag_found, _, doc_pii_found in rag_doc_results:
        if should_sanitize and rag_found:
            # Blank out the entire doc if RAG injection was detected
            sanitized_docs.append(
                ContextDoc(id=doc.id, text="[BLOCKED: RAG injection detected]")
            )
        elif should_sanitize and doc_pii_found:
            # Redact PII from the doc text
            sanitized_docs.append(ContextDoc(id=doc.id, text=redact_pii(doc.text)))
        else:
            sanitized_docs.append(ContextDoc(id=doc.id, text=doc.text))

    return AnalyzeResponse(
        decision=decision,
        risk_score=risk_score,
        risk_tags=risk_tags,
        sanitized_prompt=sanitized_prompt,
        sanitized_context_docs=sanitized_docs,
        reasons=reasons,
    )


# ---------------------------------------------------------------------------
# GET /policy
# ---------------------------------------------------------------------------
@app.get("/policy", response_model=PolicyResponse)
def get_policy() -> PolicyResponse:
    """Return the active policy / detector configuration."""
    return PolicyResponse(**_POLICY)
