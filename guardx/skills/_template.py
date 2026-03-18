"""
SKILL TEMPLATE - Copy this file to create a new skill.

Rename to: skill_name.py (e.g., xss_reflected.py)
"""

SKILL = {
    # Unique identifier
    "id": "template",

    # Display name
    "name": "Skill Template",

    # Category: injection | auth | config | crypto | exposure | network | web
    "category": "web",

    # Severity: critical | high | medium | low
    "severity": "medium",

    # How to detect this vulnerability
    "detection": """
- Step 1: describe what to look for
- Step 2: what tools to use
- Step 3: what indicators confirm the vuln
""",

    # How to exploit and prove impact
    "exploitation": """
- Step 1: describe the attack
- Step 2: what evidence to collect
- Step 3: what data proves the vuln is real
""",

    # How to fix it
    "remediation": """
- Step 1: immediate fix
- Step 2: long-term hardening
- Step 3: verification
""",

    # Which GuardX tools are useful for this skill
    "tools": ["port_check", "http_headers_check"],

    # Payloads or test strings
    "payloads": [],

    # References (CVE, OWASP, CWE)
    "references": [],
}
