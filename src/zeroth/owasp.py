"""OWASP Top 10 for LLM Applications (2025 edition) identifiers used in reports.

Verify names against the current OWASP GenAI publication before citing.
"""

OWASP_LLM = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM07": "System Prompt Leakage",
}


def label(ids) -> str:
    return ", ".join(f"{i}:2025 {OWASP_LLM.get(i, '')}".strip() for i in ids)
