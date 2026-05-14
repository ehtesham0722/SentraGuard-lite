"""
SentraGuard Lite — FastAPI entrypoint.
Exactly 2 endpoints as specified:
  POST /analyze
  GET  /policy

OpenAPI surface (docs/redoc/openapi.json) is disabled to comply with the
'exactly 2 endpoints' constraint in the technical handbook.
"""
import logging
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

# ---------------------------------------------------------------------------
# Logging — one structured INFO line per request; never logs raw prompts or PII
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App — OpenAPI surface disabled (spec mandates exactly 2 endpoints)
# ---------------------------------------------------------------------------
app = FastAPI(
    title="SentraGuard Lite",
    description="Minimal GenAI guardrails gateway — prompt/context analysis and policy decisions.",
    version="1.0.0",
    openapi_url=None,
    docs_url=None,
    redoc_url=None,
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

    Sanitized outputs:
      allow     — original content unchanged
      transform — PII redacted; RAG-injected docs blanked
      block     — opaque '[BLOCKED]' sentinel for all content fields;
                  audit record captured in the structured log line.
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
    for doc in request.context_docs:
        rag_found, rag_evidence = detect_rag_injection(doc.text)
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

    # ── Structured audit log (no raw prompt, no raw PII) ───────────────────
    logger.info(
        "analyze rid=%s decision=%s score=%d tags=%s",
        request.metadata.request_id,
        decision,
        risk_score,
        ",".join(risk_tags),
    )

    # ── Sanitize Outputs ────────────────────────────────────────────────────
    if decision == "block":
        # Opaque sentinels on block — prevents callers from accidentally forwarding
        # blocked content to downstream LLMs. Audit record is in the log above.
        sanitized_prompt = "[BLOCKED]"
        sanitized_docs = [
            ContextDoc(id=doc.id, text="[BLOCKED]")
            for doc in request.context_docs
        ]

    elif decision == "transform":
        sanitized_prompt = redact_pii(request.prompt)
        sanitized_docs = []
        for doc, rag_found, _, doc_pii_found in rag_doc_results:
            if rag_found:
                sanitized_docs.append(
                    ContextDoc(id=doc.id, text="[BLOCKED: RAG injection detected]")
                )
            elif doc_pii_found:
                sanitized_docs.append(
                    ContextDoc(id=doc.id, text=redact_pii(doc.text))
                )
            else:
                sanitized_docs.append(ContextDoc(id=doc.id, text=doc.text))

    else:  # allow
        sanitized_prompt = request.prompt
        sanitized_docs = [
            ContextDoc(id=doc.id, text=doc.text) for doc in request.context_docs
        ]

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
