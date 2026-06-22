"""Brief CWE reference text for AI prompts and triage context."""

from __future__ import annotations

CWE_KNOWLEDGE: dict[str, str] = {
    "CWE-79": "Cross-site Scripting (XSS) — untrusted input rendered as HTML/script in a browser.",
    "CWE-89": "SQL Injection — untrusted input concatenated into SQL queries.",
    "CWE-94": "Code Injection — dynamic code execution (eval/exec) with untrusted input.",
    "CWE-259": "Use of Hard-coded Password — credentials embedded in source code.",
    "CWE-295": "Improper Certificate Validation — TLS trust or certificate checks are weak.",
    "CWE-319": "Cleartext Transmission — sensitive data sent without encryption.",
    "CWE-321": "Use of Hard-coded Cryptographic Key — keys embedded in code or config.",
    "CWE-489": "Active Debug Code — debug features enabled in production.",
    "CWE-798": "Use of Hard-coded Credentials — API keys, tokens, or secrets in code.",
    "CWE-942": "Overly Permissive CORS — wildcard or unsafe cross-origin policies.",
    "CWE-1021": "Improper Restriction of Rendered UI Layers — missing clickjacking protections.",
}


def cwe_context(cwe_id: str | None) -> str:
    if not cwe_id:
        return ""
    normalized = cwe_id.upper()
    if not normalized.startswith("CWE-"):
        normalized = f"CWE-{normalized}"
    return CWE_KNOWLEDGE.get(normalized, f"{normalized} — see MITRE CWE database for details.")
