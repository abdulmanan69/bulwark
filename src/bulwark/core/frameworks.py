"""Control-framework mappings.

Every rule carries mappings into the frameworks auditors and security teams
actually report against.  Keeping them in one table (rather than sprinkled
through rule files) means a framework revision is a single-file edit, and the
reporters can render a coverage matrix without guessing.

Identifiers only -- no framework text is reproduced here.
"""

from __future__ import annotations

from typing import Dict, List

OWASP_LLM = "OWASP-LLM-2025"
MITRE_ATLAS = "MITRE-ATLAS"
NIST_AI_RMF = "NIST-AI-600-1"
CWE = "CWE"
ISO_42001 = "ISO-42001"
EU_AI_ACT = "EU-AI-ACT"

#: Human-readable titles for the identifiers we emit, so reports are readable
#: without the reader holding the standards open in another tab.
TITLES: Dict[str, str] = {
    # OWASP Top 10 for LLM Applications
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
    # MITRE ATLAS techniques (subset relevant to agent tooling)
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0053": "LLM Plugin Compromise",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0010": "ML Supply Chain Compromise",
    "AML.T0011": "User Execution",
    "AML.T0024": "Exfiltration via ML Inference API",
    "AML.T0025": "Exfiltration via Cyber Means",
    "AML.T0029": "Denial of ML Service",
    "AML.T0031": "Erode ML Model Integrity",
    # NIST AI 600-1 (Generative AI Profile) risk categories
    "NIST.GAI.CBRN": "Dangerous capability misuse",
    "NIST.GAI.CONF": "Confabulation",
    "NIST.GAI.DATA": "Data privacy",
    "NIST.GAI.INFO": "Information security",
    "NIST.GAI.SUPPLY": "Value chain and component integration",
    "NIST.GAI.HUMAN": "Human-AI configuration",
    # CWE
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-94": "Code Injection",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-269": "Improper Privilege Management",
    "CWE-284": "Improper Access Control",
    "CWE-295": "Improper Certificate Validation",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-319": "Cleartext Transmission",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-494": "Download of Code Without Integrity Check",
    "CWE-497": "Exposure of System Data to Unauthorized Control Sphere",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-598": "Sensitive Data in Query String",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-1236": "Formula Injection",
    # ISO/IEC 42001 AI management system clauses
    "ISO42001.A.6.2.4": "AI system verification and validation",
    "ISO42001.A.7.4": "Quality of data for AI systems",
    "ISO42001.A.8.3": "Third-party and customer responsibilities",
    "ISO42001.A.10.2": "Allocating responsibilities in the AI value chain",
    # EU AI Act articles commonly cited for GPAI / high-risk obligations
    "EUAIACT.ART15": "Accuracy, robustness and cybersecurity",
    "EUAIACT.ART12": "Record-keeping / logging",
    "EUAIACT.ART14": "Human oversight",
}


def title_for(identifier: str) -> str:
    """Return a readable title for a framework identifier, or the id itself."""
    return TITLES.get(identifier, identifier)


def describe(mapping: Dict[str, List[str]]) -> List[str]:
    """Flatten a framework mapping into readable "FRAMEWORK ID - Title" lines."""
    lines: List[str] = []
    for framework in sorted(mapping):
        for identifier in mapping[framework]:
            lines.append(
                f"{framework} {identifier} - {title_for(identifier)}"
            )
    return lines


def coverage(mappings: List[Dict[str, List[str]]]) -> Dict[str, Dict[str, int]]:
    """Count how many findings hit each framework identifier.

    Used by the HTML and markdown reporters to render a compliance matrix.
    """
    out: Dict[str, Dict[str, int]] = {}
    for mapping in mappings:
        for framework, identifiers in mapping.items():
            bucket = out.setdefault(framework, {})
            for identifier in identifiers:
                bucket[identifier] = bucket.get(identifier, 0) + 1
    return out
