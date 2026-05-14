"""
SentraGuard Lite — Streamlit UI

Reads API_BASE_URL env var (set automatically by Docker Compose).
Defaults to http://localhost:8000 for local development.
"""
import os
import json

import requests
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="SentraGuard Lite",
    page_icon="🛡️",
    layout="centered",
)

st.title("🛡️ SentraGuard Lite")
st.caption("GenAI Guardrails Gateway — Prompt & Context Analyzer")
st.divider()

# ---------------------------------------------------------------------------
# Input section
# ---------------------------------------------------------------------------
st.subheader("📝 Input")

prompt = st.text_area(
    "Prompt",
    height=140,
    placeholder="Enter the user prompt to analyze…",
)

st.markdown("**Context Documents** (0 – 3)")
num_docs = st.number_input(
    "Number of context documents",
    min_value=0,
    max_value=3,
    value=0,
    step=1,
)

context_docs = []
for i in range(int(num_docs)):
    doc_text = st.text_area(
        f"Document {i + 1}",
        key=f"doc_{i}",
        height=100,
        placeholder=f"Paste retrieved document {i + 1} text here…",
    )
    if doc_text.strip():
        context_docs.append({"id": f"doc-{i + 1}", "text": doc_text})

with st.expander("⚙️ Metadata (optional — defaults provided)"):
    col1, col2, col3 = st.columns(3)
    with col1:
        app_id = st.text_input("App ID", value="streamlit-ui")
    with col2:
        user_id = st.text_input("User ID", value="user-001")
    with col3:
        request_id = st.text_input("Request ID", value="req-001")

st.divider()

# ---------------------------------------------------------------------------
# Analyze button
# ---------------------------------------------------------------------------
analyze_clicked = st.button("🔍 Analyze", type="primary", use_container_width=True)

if analyze_clicked:
    if not prompt.strip():
        st.error("❌ Prompt is required.")
        st.stop()

    payload = {
        "prompt": prompt,
        "context_docs": context_docs,
        "metadata": {
            "app_id": app_id,
            "user_id": user_id,
            "request_id": request_id,
        },
    }

    with st.spinner("Analyzing…"):
        try:
            resp = requests.post(
                f"{API_BASE_URL}/analyze", json=payload, timeout=30
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.ConnectionError:
            st.error(
                f"❌ Cannot reach API at **{API_BASE_URL}**. "
                "Is the service running?"
            )
            st.stop()
        except requests.exceptions.HTTPError as exc:
            st.error(f"❌ API error {exc.response.status_code}: {exc.response.text}")
            st.stop()

    # ── Results ─────────────────────────────────────────────────────────────
    st.divider()
    st.subheader("📊 Results")

    decision = data["decision"]
    score = data["risk_score"]
    tags = data.get("risk_tags", [])
    reasons = data.get("reasons", [])

    # Decision badge + score
    col_dec, col_score = st.columns([2, 1])
    with col_dec:
        if decision == "allow":
            st.success(f"✅  Decision: **ALLOW**")
        elif decision == "transform":
            st.warning(f"⚠️  Decision: **TRANSFORM** (content sanitized)")
        else:
            st.error(f"🚫  Decision: **BLOCK**")

    with col_score:
        st.metric(label="Risk Score", value=f"{score} / 100")

    # Risk tags
    if tags:
        st.markdown("**Risk Tags detected:**")
        tag_colors = {
            "prompt_injection": "🔴",
            "pii": "🟡",
            "rag_injection": "🟠",
        }
        st.markdown(
            "  ".join(
                f"{tag_colors.get(t, '⚪')} `{t}`" for t in tags
            )
        )
    else:
        st.markdown("**Risk Tags:** _none_")

    st.divider()

    # Sanitized prompt
    st.subheader("🧹 Sanitized Prompt")
    st.code(data["sanitized_prompt"], language=None)

    # Sanitized context docs
    if data.get("sanitized_context_docs"):
        st.subheader("🧹 Sanitized Context Documents")
        for doc in data["sanitized_context_docs"]:
            st.markdown(f"**{doc['id']}**")
            st.code(doc["text"], language=None)

    # Detection reasons
    if reasons:
        st.subheader("🔎 Detection Reasons")
        for r in reasons:
            st.markdown(f"- `{r['tag']}` → {r['evidence']}")

    # Raw JSON (collapsible)
    with st.expander("🗂️ Raw JSON Response"):
        st.json(data)
