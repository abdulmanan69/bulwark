"""Rule base class, scan context and the rule registry.

A rule is a small, self-describing unit: metadata (id, title, severity,
framework mappings) plus one method that turns artifacts into findings.
Rules never touch the filesystem or the network -- discovery already did that.
That separation is what makes the whole engine testable from fixtures.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Sequence,
    Type,
)

from .models import (
    Artifact,
    ArtifactKind,
    Confidence,
    Evidence,
    Finding,
    ScanError,
    Severity,
    SourceRef,
)

# --------------------------------------------------------------------------
# Scan context
# --------------------------------------------------------------------------


@dataclass
class ScanContext:
    """Everything a rule is allowed to see.

    Holds the full artifact set so graph-shaped rules (shadowing, the lethal
    trifecta) can reason across servers, plus a scratch ``shared`` dict for
    analyzers that want to memoise expensive work between rules.
    """

    artifacts: List[Artifact] = field(default_factory=list)
    root: str = ""
    platform_hints: Dict[str, Any] = field(default_factory=dict)
    settings: Dict[str, Any] = field(default_factory=dict)
    lock: Dict[str, Any] = field(default_factory=dict)
    online: bool = False
    shared: Dict[str, Any] = field(default_factory=dict)
    errors: List[ScanError] = field(default_factory=list)

    # ---- queries rules use ---------------------------------------------

    def of_kind(self, *kinds: ArtifactKind) -> List[Artifact]:
        wanted = set(kinds)
        return [a for a in self.artifacts if a.kind in wanted]

    def children_of(self, identity: str) -> List[Artifact]:
        return [a for a in self.artifacts if a.parent == identity]

    def by_identity(self, identity: str) -> Optional[Artifact]:
        for a in self.artifacts:
            if a.identity == identity:
                return a
        return None

    def servers(self) -> List[Artifact]:
        return self.of_kind(ArtifactKind.MCP_SERVER)

    def tools(self) -> List[Artifact]:
        return self.of_kind(ArtifactKind.MCP_TOOL)

    def model_visible(self) -> List[Artifact]:
        """Artifacts whose text is injected into the model's context.

        These are the ones where an attacker's words become instructions, so
        every text-based injection rule iterates exactly this set.
        """
        return self.of_kind(
            ArtifactKind.MCP_TOOL,
            ArtifactKind.MCP_PROMPT,
            ArtifactKind.MCP_RESOURCE,
            ArtifactKind.SKILL,
            ArtifactKind.SUBAGENT,
            ArtifactKind.SLASH_COMMAND,
        )

    def memo(self, key: str, factory: Callable[[], Any]) -> Any:
        """Compute ``factory()`` once per scan and cache under ``key``."""
        if key not in self.shared:
            self.shared[key] = factory()
        return self.shared[key]


# --------------------------------------------------------------------------
# Rule
# --------------------------------------------------------------------------


class Rule:
    """Base class for all detections.

    Subclasses set the class-level metadata and implement :meth:`check`.
    """

    # Declarative metadata, read but never mutated: finding() copies the
    # containers before handing them to a Finding, so the class-level defaults
    # stay shared and effectively immutable.
    id: ClassVar[str] = ""
    title: ClassVar[str] = ""
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    description: ClassVar[str] = ""
    remediation: ClassVar[str] = ""
    category: ClassVar[str] = "general"
    frameworks: ClassVar[Dict[str, List[str]]] = {}
    references: ClassVar[List[str]] = []
    tags: ClassVar[List[str]] = []
    #: Rules that need a live connection to an MCP server are skipped unless
    #: the user opted in with --online.
    requires_online: ClassVar[bool] = False
    #: Set False to keep a rule out of the default profile (opt-in only).
    default_enabled: ClassVar[bool] = True

    # ---- the one method subclasses implement ---------------------------

    def check(self, ctx: ScanContext) -> Iterable[Finding]:  # pragma: no cover
        raise NotImplementedError

    # ---- helper so subclasses stay short -------------------------------

    def finding(
        self,
        artifact: Optional[Artifact] = None,
        *,
        title: Optional[str] = None,
        severity: Optional[Severity] = None,
        confidence: Optional[Confidence] = None,
        description: Optional[str] = None,
        remediation: Optional[str] = None,
        evidence: Optional[Sequence[Evidence]] = None,
        source: Optional[SourceRef] = None,
        related: Optional[Sequence[str]] = None,
        extra_tags: Optional[Sequence[str]] = None,
    ) -> Finding:
        return Finding(
            rule_id=self.id,
            title=title or self.title,
            severity=severity if severity is not None else self.severity,
            confidence=confidence if confidence is not None else self.confidence,
            artifact=artifact,
            description=description if description is not None else self.description,
            remediation=remediation if remediation is not None else self.remediation,
            evidence=list(evidence or []),
            references=list(self.references),
            frameworks={k: list(v) for k, v in self.frameworks.items()},
            source=source,
            tags=sorted(set(list(self.tags) + list(extra_tags or []) + [self.category])),
            related=list(related or []),
        )

    # ---- introspection used by `bulwark rules` -------------------------

    @classmethod
    def describe(cls) -> Dict[str, Any]:
        return {
            "id": cls.id,
            "title": cls.title,
            "severity": cls.severity.label,
            "confidence": cls.confidence.name,
            "category": cls.category,
            "description": cls.description,
            "remediation": cls.remediation,
            "frameworks": {k: list(v) for k, v in cls.frameworks.items()},
            "references": list(cls.references),
            "tags": sorted(cls.tags),
            "requires_online": cls.requires_online,
            "default_enabled": cls.default_enabled,
        }


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------


class RuleRegistry:
    """Holds every known rule and applies enable/disable selection."""

    def __init__(self) -> None:
        self._rules: Dict[str, Type[Rule]] = {}

    def register(self, rule_cls: Type[Rule]) -> Type[Rule]:
        if not rule_cls.id:
            raise ValueError("rule %s has no id" % rule_cls.__name__)
        if rule_cls.id in self._rules and self._rules[rule_cls.id] is not rule_cls:
            raise ValueError("duplicate rule id: %s" % rule_cls.id)
        self._rules[rule_cls.id] = rule_cls
        return rule_cls

    def __len__(self) -> int:
        return len(self._rules)

    def __iter__(self) -> Iterator[Type[Rule]]:
        return iter(sorted(self._rules.values(), key=lambda r: r.id))

    def get(self, rule_id: str) -> Optional[Type[Rule]]:
        return self._rules.get(rule_id)

    def ids(self) -> List[str]:
        return sorted(self._rules)

    def categories(self) -> List[str]:
        return sorted({r.category for r in self._rules.values()})

    def select(
        self,
        enabled: Optional[Sequence[str]] = None,
        disabled: Optional[Sequence[str]] = None,
        categories: Optional[Sequence[str]] = None,
        online: bool = False,
    ) -> List[Rule]:
        """Instantiate the rules that should run for this scan.

        ``enabled``/``disabled`` accept exact ids, glob patterns
        (``BW-INJ-*``) and ``category:name`` selectors, so a policy file can
        turn off a whole family without listing every id.
        """
        chosen: List[Rule] = []
        for rule_cls in self:
            if rule_cls.requires_online and not online:
                continue
            if categories and rule_cls.category not in categories:
                continue
            if enabled:
                if not any(_matches(rule_cls, pattern) for pattern in enabled):
                    continue
            elif not rule_cls.default_enabled:
                continue
            if disabled and any(_matches(rule_cls, pattern) for pattern in disabled):
                continue
            chosen.append(rule_cls())
        return chosen


def _matches(rule_cls: Type[Rule], pattern: str) -> bool:
    pattern = pattern.strip()
    if not pattern:
        return False
    if pattern == "*" or pattern.lower() == "all":
        return True
    if pattern.startswith("category:"):
        return rule_cls.category == pattern.split(":", 1)[1]
    if pattern.startswith("tag:"):
        return pattern.split(":", 1)[1] in rule_cls.tags
    return fnmatch.fnmatch(rule_cls.id, pattern) or rule_cls.id == pattern


#: The single process-wide registry.  Rule modules decorate into it on import.
REGISTRY = RuleRegistry()


def register(rule_cls: Type[Rule]) -> Type[Rule]:
    """Class decorator: ``@register`` adds a rule to the global registry."""
    return REGISTRY.register(rule_cls)


def run_rules(rules: Sequence[Rule], ctx: ScanContext) -> List[Finding]:
    """Execute rules, isolating failures so one bad rule cannot kill a scan."""
    findings: List[Finding] = []
    for rule in rules:
        try:
            produced = rule.check(ctx)
            if produced:
                findings.extend(produced)
        except Exception as exc:
            ctx.errors.append(
                ScanError(
                    where="rule:" + rule.id,
                    message="%s: %s" % (type(exc).__name__, exc),
                    kind="rule_error",
                )
            )
    return findings
