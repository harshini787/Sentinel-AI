import os
import re
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
api_key = os.getenv("XAI_API_KEY")

def analyze_code_for_vulnerabilities(code):
    """Dynamically analyze code for common vulnerabilities"""
    vulnerabilities = []
    lines = code.split('\n')

    for i, line in enumerate(lines, 1):
        line_clean = line.strip()

        # SQL Injection detection
        if re.search(r'execute\s*\(\s*["\']SELECT.*\+\s*\w+', line_clean, re.IGNORECASE) or \
           re.search(r'query\s*=\s*["\'].*["\']\s*\+\s*\w+', line_clean):
            vulnerabilities.append({
                'type': 'SQL Injection',
                'location': f'Line {i}',
                'description': 'Direct string concatenation in SQL query allows malicious input',
                'risk_level': 'Critical',
                'code_snippet': line_clean
            })

        # Hardcoded credentials detection
        if re.search(r'password\s*==?\s*["\'][^"\']+["\']', line_clean, re.IGNORECASE) or \
           re.search(r'["\'][a-zA-Z0-9]{8,}["\']', line_clean) and ('password' in line_clean.lower() or 'secret' in line_clean.lower()):
            vulnerabilities.append({
                'type': 'Hardcoded Credentials',
                'location': f'Line {i}',
                'description': 'Credentials or secrets stored directly in source code',
                'risk_level': 'High',
                'code_snippet': line_clean
            })

        # XSS detection
        if re.search(r'<[^>]*>\s*\{.*input.*\}', line_clean) or \
           re.search(r'f["\'].*<.*\{.*\}.*["\']', line_clean):
            vulnerabilities.append({
                'type': 'Cross-Site Scripting (XSS)',
                'location': f'Line {i}',
                'description': 'User input directly inserted into HTML without sanitization',
                'risk_level': 'High',
                'code_snippet': line_clean
            })

        # Command injection detection
        if re.search(r'subprocess\.|os\.system|os\.popen|exec\(|eval\(', line_clean) and ('+' in line_clean or '%' in line_clean):
            vulnerabilities.append({
                'type': 'Command Injection',
                'location': f'Line {i}',
                'description': 'User input passed to system commands without validation',
                'risk_level': 'Critical',
                'code_snippet': line_clean
            })

        # Path traversal detection
        if re.search(r'open\s*\(\s*.*\+.*\)|os\.path\.join.*\+', line_clean):
            vulnerabilities.append({
                'type': 'Path Traversal',
                'location': f'Line {i}',
                'description': 'User input used in file paths without validation',
                'risk_level': 'High',
                'code_snippet': line_clean
            })

        # Deserialization vulnerability
        if re.search(r'pickle\.load|pickle\.loads', line_clean):
            vulnerabilities.append({
                'type': 'Insecure Deserialization',
                'location': f'Line {i}',
                'description': 'Loading serialized data without validation can execute arbitrary code',
                'risk_level': 'Critical',
                'code_snippet': line_clean
            })

        # Weak cryptography
        if re.search(r'hashlib\.md5|hashlib\.sha1', line_clean):
            vulnerabilities.append({
                'type': 'Weak Cryptography',
                'location': f'Line {i}',
                'description': 'Using deprecated or weak cryptographic algorithms',
                'risk_level': 'High',
                'code_snippet': line_clean
            })

        # Insecure random
        if re.search(r'random\.|Random\(\)', line_clean) and ('token' in line_clean.lower() or 'secret' in line_clean.lower()):
            vulnerabilities.append({
                'type': 'Insecure Random',
                'location': f'Line {i}',
                'description': 'Using predictable random number generator for security purposes',
                'risk_level': 'Medium',
                'code_snippet': line_clean
            })

    return vulnerabilities

def generate_secure_patch(code, vulnerabilities):
    """Generate a secure version of the code with fixes"""
    patched_code = code

    # Apply fixes for each vulnerability
    for vuln in vulnerabilities:
        if vuln['type'] == 'SQL Injection':
            # Replace string concatenation with parameterized query
            patched_code = re.sub(
                r'(\w+)\s*=\s*(["\']SELECT.*?["\'])\s*\+\s*(\w+)',
                r'\1 = \2\n    cursor.execute(\1, (\3,))',
                patched_code
            )

        elif vuln['type'] == 'Hardcoded Credentials':
            # Replace hardcoded credentials with environment variables
            patched_code = re.sub(
                r'(\w+)\s*==?\s*(["\'][^"\']+["\'])',
                r'os.getenv(\'\1\', \2)',
                patched_code
            )

        elif vuln['type'] == 'Cross-Site Scripting (XSS)':
            # Add HTML escaping
            patched_code = patched_code.replace('import sqlite3', 'import sqlite3\nimport html')
            patched_code = re.sub(
                r'f(["\'].*<.*\{([^}]+)\}.*["\'])',
                r'f\1 where \2 is html.escape(\2)',
                patched_code
            )

    return patched_code

def dynamic_sentinel_engine(input_data):
    """Dynamic vulnerability scanner that analyzes actual code"""
    code = input_data['code']

    # Analyze for vulnerabilities
    vulnerabilities = analyze_code_for_vulnerabilities(code)

    # Generate hunter response
    hunter_response = ""
    if vulnerabilities:
        for vuln in vulnerabilities:
            hunter_response += f"""Vulnerability Type: {vuln['type']}
Location: {vuln['location']}
Description: {vuln['description']}
Risk Level: {vuln['risk_level']}
Code Snippet: {vuln['code_snippet']}

"""
    else:
        hunter_response = "No security vulnerabilities detected."

    # Generate skeptic response
    skeptic_response = "## Security Audit Report\n\n"

    if vulnerabilities:
        skeptic_response += "### Confirmed Vulnerabilities\n\n"
        for i, vuln in enumerate(vulnerabilities, 1):
            skeptic_response += f"""**{i}. {vuln['type']} ({vuln['risk_level']})**
- Location: {vuln['location']}
- Security Impact: {get_security_impact(vuln['type'])}
- Recommended Fix: {get_recommended_fix(vuln['type'])}

"""

        # Generate secure patch
        secure_patch = generate_secure_patch(code, vulnerabilities)
        skeptic_response += f"""### Secure Code Patch
```python
{secure_patch}
```

"""
    else:
        skeptic_response += "### No Vulnerabilities Found\nThe code appears to be secure.\n\n"

    skeptic_response += "### Summary\n"
    if vulnerabilities:
        skeptic_response += f"Found {len(vulnerabilities)} security vulnerabilities that need immediate attention."
    else:
        skeptic_response += "Code analysis complete. No security issues detected."

    return {
        "raw_findings": hunter_response,
        "final_audit_report": skeptic_response
    }

def get_security_impact(vuln_type):
    impacts = {
        'SQL Injection': 'Attackers can execute arbitrary SQL commands, potentially accessing, modifying, or deleting all database data',
        'Hardcoded Credentials': 'Credentials are exposed in source code and cannot be changed without redeployment',
        'Cross-Site Scripting (XSS)': 'Malicious scripts can be executed in users\' browsers, leading to session hijacking or data theft',
        'Command Injection': 'Attackers can execute arbitrary system commands on the server',
        'Path Traversal': 'Attackers can access files outside the intended directory',
        'Insecure Deserialization': 'Attackers can execute arbitrary code during deserialization',
        'Weak Cryptography': 'Cryptographic operations are vulnerable to brute force and collision attacks',
        'Insecure Random': 'Security tokens and values can be predicted by attackers'
    }
    return impacts.get(vuln_type, 'Unknown security impact')

def get_recommended_fix(vuln_type):
    fixes = {
        'SQL Injection': 'Use parameterized queries or prepared statements',
        'Hardcoded Credentials': 'Store credentials in environment variables or secure configuration files',
        'Cross-Site Scripting (XSS)': 'Sanitize user input and use safe HTML encoding',
        'Command Injection': 'Validate and sanitize all user input passed to system commands',
        'Path Traversal': 'Validate file paths and use allowlists for permitted locations',
        'Insecure Deserialization': 'Validate serialized data and use safe deserialization methods',
        'Weak Cryptography': 'Use modern cryptographic algorithms like SHA-256 or bcrypt',
        'Insecure Random': 'Use secrets module for cryptographic purposes'
    }
    return fixes.get(vuln_type, 'Implement proper input validation and sanitization')

# Use dynamic analyzer if no valid API key
if not api_key or api_key == "your_actual_xai_api_key_here" or len(api_key.strip()) < 20:
    print("⚠️  Using dynamic vulnerability scanner (no valid API key found)")
    sentinel_engine = dynamic_sentinel_engine
else:
    # Test the API key by trying a simple request
    try:
        from langchain_xai import ChatXAI
        test_llm = ChatXAI(
            model="grok-beta",
            xai_api_key=api_key,
            temperature=0.0
        )
        # Try a simple test to validate the API key
        test_response = test_llm.invoke("Test")
        print("✅ Using real LangChain-based vulnerability scanner")
        # If we get here, the API key is valid, so set up the real engine
        sentinel_engine = setup_real_engine(api_key)
    except Exception as e:
        print(f"❌ Invalid API key detected: {str(e)[:50]}...")
        print("🔄 Falling back to dynamic scanner")
        sentinel_engine = dynamic_sentinel_engine

def setup_real_engine(api_key):
    """Set up the real LangChain-based engine"""
    from langchain_core.prompts import PromptTemplate
    from langchain_core.runnables import RunnableLambda, RunnablePassthrough
    from langchain_xai import ChatXAI

    llm = ChatXAI(
        model="grok-beta",
        xai_api_key=api_key,
        temperature=0.0
    )

    # Hunter agent
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

    # Skeptic agent
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

    # Orchestrator
    return (
        RunnablePassthrough()
        .assign(raw_findings=hunter_runnable)
        | skeptic_runnable
    )