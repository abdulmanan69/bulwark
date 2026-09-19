"""Infer what a tool can actually do, from the only evidence we have.

A tool advertises a name, a description and a JSON input schema.  None of that
is trustworthy in the adversarial case, but all of it is informative in the
common case, and the *union* of the three is a good deal better than any one.

Capabilities feed two things that nothing else in the ecosystem computes:

* **excessive agency** -- how much power one tool concentrates; and
* **the trifecta** -- whether an agent simultaneously holds private data
  access, exposure to attacker-controlled content, and an outbound channel.
  Any two of those is a normal integration.  All three is the shape of every
  agent data-exfiltration chain reported so far, regardless of which specific
  tool is compromised.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

# --------------------------------------------------------------------------
# Taxonomy
# --------------------------------------------------------------------------

#: Every capability we can infer, with the risk weight used for agency scoring.
CAPABILITY_WEIGHTS: Dict[str, int] = {
    "exec": 10,            # runs shell commands or arbitrary processes
    "code_eval": 10,       # evaluates code in-process
    "cloud_admin": 9,      # IAM, infrastructure, cluster control
    "payment": 9,          # moves money
    "fs_delete": 8,        # destructive filesystem access
    "identity": 8,         # creates or alters accounts and permissions
    "secrets": 8,          # reads credential stores
    "db_write": 7,         # mutates a datastore
    "fs_write": 6,         # writes to disk
    "net_send": 6,         # outbound POST / webhook / publish
    "messaging": 6,        # email, chat, SMS to humans
    "browser": 6,          # drives a real browser session
    "db_read": 4,          # reads a datastore
    "net_fetch": 4,        # fetches remote content
    "fs_read": 3,          # reads from disk
    "search": 2,           # queries an index
    "compute": 1,          # pure computation
}

#: Trust-boundary roles, orthogonal to capability.
PRIVATE_DATA = "private_data"        # reaches data the org would not publish
UNTRUSTED_INPUT = "untrusted_input"  # returns content an attacker can author
EGRESS = "egress"                    # can move bytes outside the boundary

TRIFECTA: Tuple[str, str, str] = (PRIVATE_DATA, UNTRUSTED_INPUT, EGRESS)


@dataclass(frozen=True)
class Signature:
    capability: str
    keywords: Sequence[str]
    roles: Sequence[str] = ()

    def matches(self, haystack: str) -> Optional[str]:
        for keyword in self.keywords:
            if re.search(keyword, haystack, re.IGNORECASE):
                return keyword
        return None


def _s(capability: str, keywords: Sequence[str], roles: Sequence[str] = ()) -> Signature:
    return Signature(capability, tuple(keywords), tuple(roles))


#: Keyword signatures.  Word-bounded so "execute" does not match "executive"
#: and "rm" does not match "form".
SIGNATURES: List[Signature] = [
    _s("exec", [
        r"\b(?:exec|execute|run|spawn|invoke)\s+(?:a\s+)?"
        r"(?:shell|command|process|binary|script|program)\b",
        r"\b(?:shell|bash|zsh|powershell|pwsh|cmd\.exe|subprocess|"
        r"command[_-]?line|terminal)\b",
        r"\bos\.system\b", r"\bchild_process\b",
    ], roles=[EGRESS]),

    _s("code_eval", [
        r"\b(?:eval|evaluate|interpret|compile\s+and\s+run)\s+"
        r"(?:the\s+)?(?:code|expression|script|python|javascript|snippet)\b",
        r"\barbitrary\s+code\b", r"\bcode\s+interpreter\b", r"\bsandbox\s+exec",
    ], roles=[EGRESS]),

    _s("fs_read", [
        r"\bread\b[^.\n]{0,20}\b(?:file|path|directory|folder|disk)\b",
        r"\b(?:cat|open|load|fetch)\s+(?:a\s+|the\s+)?file\b",
        r"\b(?:list|glob|walk|enumerate)\b[^.\n]{0,20}\b(?:files?|director)",
        r"\bfilesystem\b", r"\bfile\s+contents?\b",
    ], roles=[PRIVATE_DATA, UNTRUSTED_INPUT]),

    _s("fs_write", [
        r"\b(?:write|save|create|append|modify|edit|patch|overwrite)\b"
        r"[^.\n]{0,25}\b(?:file|path|disk|document)\b",
        r"\bwrites?\s+to\s+(?:disk|the\s+filesystem)\b",
    ]),

    _s("fs_delete", [
        r"\b(?:delete|remove|unlink|purge|wipe|destroy|truncate)\b"
        r"[^.\n]{0,25}\b(?:file|path|director|folder|disk)\b",
        r"\brecursively\s+(?:delete|remove)\b",
    ]),

    _s("net_fetch", [
        r"\b(?:fetch|retrieve|download|scrape|crawl|GET)\b[^.\n]{0,25}"
        r"\b(?:url|web\s*page|website|http|endpoint|feed|resource)\b",
        r"\bweb\s+(?:search|browse|fetch|request)\b",
        r"\bhttp\s+(?:get|request|client)\b",
    ], roles=[UNTRUSTED_INPUT]),

    _s("net_send", [
        r"\b(?:post|put|patch|upload|submit|publish|push)\b[^.\n]{0,25}"
        r"\b(?:to\s+)?(?:url|endpoint|api|webhook|server|http)\b",
        r"\bwebhook\b", r"\boutbound\s+request\b",
    ], roles=[EGRESS]),

    _s("messaging", [
        r"\b(?:send|post|draft|deliver)\b[^.\n]{0,25}"
        r"\b(?:email|e-mail|message|sms|dm|notification|slack|discord|teams|"
        r"telegram|whatsapp)\b",
        r"\b(?:smtp|sendgrid|mailgun|twilio)\b",
    ], roles=[EGRESS]),

    _s("browser", [
        r"\b(?:browser|playwright|puppeteer|selenium|headless\s+chrome)\b",
        r"\b(?:click|navigate|type\s+into|screenshot)\b[^.\n]{0,25}\bpage\b",
    ], roles=[UNTRUSTED_INPUT, EGRESS]),

    _s("db_read", [
        r"\b(?:query|select|read|fetch|search)\b[^.\n]{0,25}"
        r"\b(?:database|table|collection|sql|postgres|mysql|mongo|sqlite|"
        r"bigquery|snowflake|redshift|dynamodb)\b",
        r"\brun\s+(?:a\s+)?(?:sql|query)\b",
    ], roles=[PRIVATE_DATA]),

    _s("db_write", [
        r"\b(?:insert|update|delete|upsert|drop|alter|truncate|migrate)\b"
        r"[^.\n]{0,25}\b(?:database|table|row|record|collection|schema)\b",
        r"\bwrite\s+to\s+(?:the\s+)?database\b",
    ]),

    _s("secrets", [
        r"\b(?:secret|credential|api[\s_-]?key|token|password|passphrase|"
        r"private\s+key|certificate)s?\b",
        r"\b(?:vault|keychain|keyring|secrets?\s+manager|parameter\s+store|"
        r"1password|lastpass|bitwarden)\b",
        r"\.env\b", r"\bid_rsa\b",
    ], roles=[PRIVATE_DATA]),

    _s("cloud_admin", [
        r"\b(?:iam|role|policy|permission|security\s+group|firewall)\b"
        r"[^.\n]{0,25}\b(?:create|update|attach|grant|modify|delete)\b",
        r"\b(?:terraform|cloudformation|kubectl|kubernetes|helm|ansible|"
        r"pulumi)\b",
        r"\b(?:ec2|s3\s+bucket|lambda|gke|eks|aks|vpc)\b[^.\n]{0,25}"
        r"\b(?:create|delete|modify|launch|terminate)\b",
    ], roles=[EGRESS]),

    _s("identity", [
        r"\b(?:create|delete|disable|suspend|impersonate|elevate)\b"
        r"[^.\n]{0,25}\b(?:user|account|member|principal|service\s+account)\b",
        r"\b(?:grant|revoke)\b[^.\n]{0,20}\b(?:access|role|permission)\b",
        r"\b(?:sso|oauth|saml|ldap|active\s+directory)\b",
    ]),

    _s("payment", [
        r"\b(?:payment|invoice|charge|refund|payout|transfer\s+funds|"
        r"transaction|wire|settlement)\b",
        r"\b(?:stripe|paypal|adyen|braintree|plaid|square)\b",
        r"\b(?:crypto|wallet|on[\s-]?chain)\b[^.\n]{0,20}"
        r"\b(?:send|transfer|sign|approve)\b",
    ], roles=[EGRESS]),

    _s("search", [
        r"\b(?:search|lookup|index|find|retrieve)\b[^.\n]{0,25}"
        r"\b(?:index|documents?|knowledge\s+base|vector|embedding|corpus)\b",
    ], roles=[UNTRUSTED_INPUT]),

    _s("compute", [
        r"\b(?:calculate|compute|convert|format|transform|multiply|divide|"
        r"subtract|sums?|adds?|encode|decode)\b",
    ]),
]

#: Tools whose *output* is authored by third parties.  Reading a GitHub issue,
#: an inbox or a support ticket pulls attacker-writable prose into the context
#: window; that is the injection entry point in almost every real incident.
#:
#: Each pattern pairs an ingestion verb with the third-party surface.  Without
#: the verb these over-fire badly: "post a message to Slack" is an outbound
#: action, not an untrusted input, and tagging it as both makes the trifecta
#: rule meaningless.
_INGEST = r"(?:read|fetch|get|list|search|retrieve|load|pull|receive|view|parse|extract|scrape|download|browse|check|monitor|watch)"

UNTRUSTED_SOURCE_HINTS = [
    r"\b" + _INGEST + r"\b[^.\n]{0,30}\b(?:issue|pull\s+request|comment|review)s?\b",
    r"\b" + _INGEST + r"\b[^.\n]{0,30}\b(?:inbox|email|mail|message|thread|conversation)s?\b",
    r"\b" + _INGEST + r"\b[^.\n]{0,30}\b(?:ticket|case|support|helpdesk|zendesk|intercom|jira)\b",
    r"\b" + _INGEST + r"\b[^.\n]{0,30}\b(?:web\s*page|website|url|rss|feed|tweet|post)s?\b",
    r"\b" + _INGEST + r"\b[^.\n]{0,30}\b(?:pdf|document|spreadsheet|attachment|upload)s?\b",
    r"\buser[\s-]?(?:provided|supplied|generated|submitted)\b",
    r"\b(?:third[\s-]party|external|untrusted|public)\s+(?:content|data|input|source)\b",
]

#: Tools that reach data an organisation would not publish.
PRIVATE_SOURCE_HINTS = [
    r"\b(?:internal|private|confidential|proprietary|sensitive|restricted)\b",
    r"\b(?:customer|employee|patient|payroll|hr|financial|pii|phi|salary)\b",
    r"\b(?:source\s+code|repository|repo|codebase|monorepo)\b",
    r"\b(?:local|home)\s+(?:file|director|folder|disk|drive)",
    r"\b(?:crm|erp|salesforce|workday|netsuite|sap)\b",
]

#: Argument names that indicate a free-form channel out of the trust boundary.
EGRESS_ARG_HINTS = {
    "url", "uri", "endpoint", "webhook", "callback", "callback_url", "host",
    "destination", "target_url", "to", "recipient", "recipients", "email",
    "address", "channel", "remote", "upload_url", "sink", "forward_to",
}

#: Argument names free-form enough to carry a smuggled payload.
FREEFORM_ARG_HINTS = {
    "context", "note", "notes", "sidenote", "metadata", "extra", "payload",
    "data", "comment", "annotation", "debug", "trace", "info", "detail",
}


@dataclass
class CapabilityReport:
    capabilities: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    evidence: Dict[str, str] = field(default_factory=dict)
    agency_score: int = 0

    @property
    def is_trifecta_complete(self) -> bool:
        return all(role in self.roles for role in TRIFECTA)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capabilities": list(self.capabilities),
            "roles": list(self.roles),
            "agency_score": self.agency_score,
            "evidence": dict(self.evidence),
        }


# --------------------------------------------------------------------------
# Inference
# --------------------------------------------------------------------------


def infer(
    name: str = "",
    description: str = "",
    schema: Optional[Dict[str, Any]] = None,
    annotations: Optional[Dict[str, Any]] = None,
) -> CapabilityReport:
    """Infer capabilities and trust roles for one tool."""
    report = CapabilityReport()
    haystack = " ".join(part for part in (_humanise(name), description) if part)

    found: Set[str] = set()
    roles: Set[str] = set()

    for signature in SIGNATURES:
        keyword = signature.matches(haystack)
        if keyword:
            found.add(signature.capability)
            roles.update(signature.roles)
            report.evidence.setdefault(signature.capability, keyword)

    for pattern in UNTRUSTED_SOURCE_HINTS:
        if re.search(pattern, haystack, re.IGNORECASE):
            roles.add(UNTRUSTED_INPUT)
            report.evidence.setdefault("untrusted_input", pattern)
            break

    for pattern in PRIVATE_SOURCE_HINTS:
        if re.search(pattern, haystack, re.IGNORECASE):
            roles.add(PRIVATE_DATA)
            report.evidence.setdefault("private_data", pattern)
            break

    # The JSON schema is the least deniable evidence: an argument called
    # "webhook_url" is an outbound channel whatever the description claims.
    for arg_name, arg_schema in _iter_properties(schema):
        lowered = arg_name.lower()
        if lowered in EGRESS_ARG_HINTS or lowered.endswith("_url"):
            roles.add(EGRESS)
            found.add("net_send")
            report.evidence.setdefault("egress", "argument:" + arg_name)
        if lowered in FREEFORM_ARG_HINTS and _is_string(arg_schema):
            report.evidence.setdefault("freeform_arg", "argument:" + arg_name)
        if lowered in {"command", "cmd", "script", "code", "shell", "exec"}:
            found.add("exec")
            report.evidence.setdefault("exec", "argument:" + arg_name)
        if lowered in {"query", "sql", "statement"} and _is_string(arg_schema):
            found.add("db_read")
            report.evidence.setdefault("db_read", "argument:" + arg_name)
        if lowered in {"path", "file", "filename", "filepath", "directory"}:
            found.add("fs_read")
            report.evidence.setdefault("fs_read", "argument:" + arg_name)

    # MCP tool annotations are self-declared, so they can only *add* risk:
    # a server claiming readOnlyHint is not evidence of anything, but a server
    # admitting destructiveHint is.
    for key, capability in (
        ("destructiveHint", "fs_delete"),
        ("openWorldHint", "net_fetch"),
    ):
        if annotations and annotations.get(key) is True:
            found.add(capability)
            report.evidence.setdefault(capability, "annotation:" + key)
            if key == "openWorldHint":
                roles.add(UNTRUSTED_INPUT)

    report.capabilities = sorted(found)
    report.roles = sorted(roles)
    report.agency_score = sum(CAPABILITY_WEIGHTS.get(c, 1) for c in report.capabilities)
    return report


def _humanise(name: str) -> str:
    """Split create_issue / createIssue into words the patterns can see."""
    spaced = re.sub(r"[_\-.:]+", " ", name)
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", spaced)


def _iter_properties(
    schema: Optional[Dict[str, Any]],
) -> Iterator[Tuple[str, Dict[str, Any]]]:
    if not isinstance(schema, dict):
        return
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for key, value in properties.items():
            yield str(key), value if isinstance(value, dict) else {}
    # Walk one level of composition keywords; deeper nesting is rare in MCP
    # schemas and not worth the traversal cost on every tool.
    for keyword in ("allOf", "anyOf", "oneOf"):
        for sub in schema.get(keyword) or []:
            if isinstance(sub, dict):
                yield from _iter_properties(sub)


def _is_string(arg_schema: Dict[str, Any]) -> bool:
    kind = arg_schema.get("type")
    if isinstance(kind, list):
        return "string" in kind
    return kind == "string" or kind is None


# --------------------------------------------------------------------------
# Aggregation across a whole agent
# --------------------------------------------------------------------------


def aggregate_roles(reports: Iterable[CapabilityReport]) -> Dict[str, List[str]]:
    """Map each trust role to the capabilities that supplied it."""
    out: Dict[str, List[str]] = {role: [] for role in TRIFECTA}
    for report in reports:
        for role in report.roles:
            if role in out:
                out[role].extend(report.capabilities)
    return {role: sorted(set(caps)) for role, caps in out.items()}


def roles_present(reports: Iterable[CapabilityReport]) -> Set[str]:
    """Every trust role held by at least one tool.

    Distinct from :func:`aggregate_roles`, which answers "which capabilities
    supplied this role".  A tool can hold a role with no named capability --
    "list unread emails" is untrusted input and nothing else -- so asking
    whether the capability list is non-empty is the wrong question for the
    trifecta, and answering it that way silently under-reports.
    """
    return {role for report in reports for role in report.roles}


def trifecta_complete(reports: Iterable[CapabilityReport]) -> bool:
    present = roles_present(reports)
    return all(role in present for role in TRIFECTA)


def describe_capability(capability: str) -> str:
    """One-line explanation used in reports."""
    return {
        "exec": "runs shell commands or external processes",
        "code_eval": "evaluates arbitrary code",
        "cloud_admin": "changes cloud or cluster configuration",
        "payment": "initiates financial transactions",
        "fs_delete": "deletes files or directories",
        "identity": "creates or changes accounts and permissions",
        "secrets": "reads credentials or secret stores",
        "db_write": "modifies database contents",
        "fs_write": "writes files to disk",
        "net_send": "sends data to a remote endpoint",
        "messaging": "sends messages to people outside the session",
        "browser": "drives a live browser session",
        "db_read": "reads database contents",
        "net_fetch": "fetches remote content into context",
        "fs_read": "reads files from disk",
        "search": "queries a search index",
        "compute": "performs local computation only",
    }.get(capability, capability)
