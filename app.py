import os

import streamlit as st

from src.engine import sentinel_engine

# --- 1. PAGE SETUP ---
st.set_page_config(page_title="Sentinel-AI Auditor", page_icon="🛡️", layout="wide")

# Custom Style for the Dashboard
st.markdown(
    """
    <style>
    .main { background-color: #0e1117; }
    .stCodeBlock { border: 1px solid #30363d; border-radius: 8px; }
    </style>
    """,
    unsafe_allow_html=True,
)

# --- 2. HEADER & SIDEBAR ---
st.title("🛡️ Sentinel-AI: Multi-Agent Auditor")
st.write("Upload your code to run a dual-agent security audit (Hunter + Skeptic).")

with st.sidebar:
    st.header("⚙️ Audit Settings")
    # File uploader widget
    uploaded_file = st.file_uploader(
        "Upload Code File",
        type=["py", "js", "cpp", "java", "sql"],
        help="Supports Python, JavaScript, C++, Java, and SQL.",
    )
    st.divider()
    st.caption("Internship Project: Automated Security Analysis v1.0")

# --- 3. MAIN LOGIC ---
if uploaded_file:
    # Read the file content
    code_content = uploaded_file.read().decode("utf-8")

    # Create two columns: Original Code vs. AI Audit
    col1, col2 = st.columns([1, 1], gap="large")

    with col1:
        st.subheader(f"📄 File: {uploaded_file.name}")
        st.code(code_content, line_numbers=True)

    with col2:
        st.subheader("🔍 Security Audit Report")

        # This button triggers the LangChain engine
        if st.button("🚀 Start Sequential Audit"):
            with st.spinner("Hunter is scanning... Skeptic is verifying..."):
                try:
                    # We pass the code to the engine we made in engine.py
                    # Input key 'code' must match what we defined in src/engine.py
                    response = sentinel_engine.invoke({"code": code_content})

                    st.success("Audit Complete!")
                    st.markdown(response["final_audit_report"])

                except Exception as e:
                    st.error(f"Audit failed: {e}")
                    st.info("Check if your API Key in the .env file is correct.")
else:
    # Display this when no file is uploaded
    st.image("https://img.icons8.com/clouds/200/security-shield.png")
    st.info("Waiting for a file upload to begin the audit...")
