import os

from dotenv import load_dotenv
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnableLambda, RunnablePassthrough
from langchain_xai import ChatXAI

# --------------------------------------------------
# 1. Setup Environment
# --------------------------------------------------
load_dotenv()
api_key ="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"

if not api_key:
    raise ValueError("XAI_API_KEY not found in environment variables")


# --------------------------------------------------
# 2. Initialize LLM (Grok-Beta)
# --------------------------------------------------
llm = ChatXAI(
    model="grok-beta",
    xai_api_key=api_key,
    temperature=0.0
)


# --------------------------------------------------
# AGENT 1: HUNTER (Find vulnerabilities)
# --------------------------------------------------
hunter_template = """
You are 'Hunter-AI', a specialized Cybersecurity Research Agent.
Your goal is to perform a comprehensive vulnerability scan on the provided code.

SPECIFIC VULNERABILITIES TO LOOK FOR:
1. SQL Injection: Direct string concatenation in SQL queries, lack of parameterized queries
2. Cross-Site Scripting (XSS): User input directly inserted into HTML without sanitization
3. Hardcoded Credentials: Passwords, API keys, or secrets stored directly in code
4. Improper Authentication: Weak password checks, missing validation
5. Command Injection: User input passed to system commands
6. Path Traversal: User input used in file paths
7. Insecure Random: Use of predictable random number generators for security purposes

CODE TO SCAN:
{code}

OUTPUT FORMAT:
For each vulnerability found, provide:
- Vulnerability Type: [Type]
- Location: Line X (approximate)
- Description: [Brief explanation]
- Risk Level: [High/Medium/Low]
- Code Snippet: [The problematic code]

If no vulnerabilities found, state "No security vulnerabilities detected."
"""

hunter_prompt = PromptTemplate(
    input_variables=["code"],
    template=hunter_template
)

hunter_runnable = (
    hunter_prompt
    | llm
    | RunnableLambda(lambda x: {"raw_findings": x.content})
)


# --------------------------------------------------
# AGENT 2: SKEPTIC (Validate + Fix)
# --------------------------------------------------
skeptic_template = """
You are 'Skeptic-Auditor', a Senior Security Engineer with 15+ years of experience.

You have received vulnerability findings from a junior scanner. Your job is to validate, filter, and provide professional security recommendations.

JUNIOR SCANNER FINDINGS:
{raw_findings}

ORIGINAL CODE:
{code}

YOUR TASK:
1. VALIDATE FINDINGS: Review each reported vulnerability and determine if it's a real security issue or a false positive.

2. CONFIRMED VULNERABILITIES: For each legitimate vulnerability, provide:
   - Vulnerability Type and Severity (Critical/High/Medium/Low)
   - Exact Location in code
   - Security Impact (what an attacker could achieve)
   - Recommended Fix with secure code example

3. SECURE CODE PATCH: Provide the COMPLETE corrected code with all vulnerabilities fixed.

4. SUMMARY: Brief summary of findings and overall security assessment.

OUTPUT FORMAT:
## Security Audit Report

### Confirmed Vulnerabilities
[List each confirmed vulnerability with details]

### Secure Code Patch
```python
[Complete fixed code here]
```

### Summary
[Brief assessment]
"""

skeptic_prompt = PromptTemplate(
    input_variables=["raw_findings", "code"],
    template=skeptic_template
)

skeptic_runnable = (
    skeptic_prompt
    | llm
    | RunnableLambda(lambda x: {"final_audit_report": x.content})
)


# --------------------------------------------------
# ORCHESTRATOR (Sentinel Engine)
# --------------------------------------------------
sentinel_engine = (
    RunnablePassthrough()                          # keeps original input
    .assign(raw_findings=hunter_runnable)          # run hunter
    | skeptic_runnable                              # run skeptic
)


# --------------------------------------------------
# Example Invocation
# --------------------------------------------------
if __name__ == "__main__":
    sample_code = """
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    """

    result = sentinel_engine.invoke(
        {"code": sample_code}
    )

    print("\n===== FINAL SECURITY AUDIT =====\n")
    print(result["final_audit_report"])
