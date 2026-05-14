from pydantic import BaseModel
from typing import List, Optional, Dict, Literal


class ContextDoc(BaseModel):
    id: str
    text: str


class Metadata(BaseModel):
    app_id: str
    user_id: str
    request_id: str


class AnalyzeRequest(BaseModel):
    prompt: str
    context_docs: Optional[List[ContextDoc]] = []
    metadata: Metadata


class Reason(BaseModel):
    tag: str
    evidence: str


class AnalyzeResponse(BaseModel):
    decision: Literal["allow", "block", "transform"]
    risk_score: int
    risk_tags: List[str]
    sanitized_prompt: str
    sanitized_context_docs: List[ContextDoc]
    reasons: List[Reason]


class PolicyResponse(BaseModel):
    version: str
    detectors: List[str]
    thresholds: Dict[str, int]
