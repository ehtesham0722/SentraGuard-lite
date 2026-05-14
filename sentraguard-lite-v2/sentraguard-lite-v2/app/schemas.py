"""
Pydantic request/response models — the API data contract.

Typing uses Python 3.10+ built-in generics (list, dict, X | None)
throughout for consistency.
"""
from pydantic import BaseModel, Field, field_validator
from typing import Literal


class ContextDoc(BaseModel):
    id: str
    text: str


class Metadata(BaseModel):
    app_id: str
    user_id: str
    request_id: str


class AnalyzeRequest(BaseModel):
    prompt: str
    # Field(default_factory=list) avoids the mutable-default anti-pattern.
    context_docs: list[ContextDoc] = Field(default_factory=list)
    metadata: Metadata

    @field_validator("context_docs")
    @classmethod
    def max_three_context_docs(cls, v: list) -> list:
        """Server-side enforcement of the 0–3 context-doc limit."""
        if len(v) > 3:
            raise ValueError(
                f"context_docs accepts at most 3 documents; received {len(v)}"
            )
        return v


class Reason(BaseModel):
    tag: str
    evidence: str


class AnalyzeResponse(BaseModel):
    decision: Literal["allow", "block", "transform"]
    risk_score: int
    risk_tags: list[str]
    sanitized_prompt: str
    sanitized_context_docs: list[ContextDoc]
    reasons: list[Reason]


class PolicyResponse(BaseModel):
    version: str
    detectors: list[str]
    thresholds: dict[str, int]
