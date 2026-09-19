"""Policy: turning findings into a decision the organisation actually made.

A scanner that only reports is a scanner people stop reading.  What makes one
survive contact with a real team is the ability to say, in a file that lives in
version control: this rule does not apply to us, this finding is accepted until
March, this severity blocks the build and that one does not.

The policy file is YAML when PyYAML is installed and JSON otherwise, so the
tool keeps working in a minimal container.

Waivers expire on purpose.  A waiver with no end date is a decision nobody will
revisit, so an expired waiver stops suppressing and the finding comes back --
loudly enough to be re-decided, not quietly enough to be forgotten.
"""

from __future__ import annotations

import calendar
import datetime
import fnmatch
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .core.models import Finding, Severity

DEFAULT_POLICY_NAMES = (
    "bulwark.policy.yaml",
    "bulwark.policy.yml",
    "bulwark.policy.json",
    ".bulwark.yaml",
    ".bulwark.yml",
    ".bulwark.json",
)

#: Dates in policy files are plain calendar dates: YYYY-MM-DD, no time, no
#: zone.  A waiver expiring "on the 14th" should not depend on the reviewer's
#: timezone, so expiry is evaluated at end-of-day UTC.
DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")


def parse_date(value: str) -> Optional[float]:
    """Parse YYYY-MM-DD into an end-of-day UTC epoch, or None if malformed."""
    match = DATE_RE.match(str(value).strip())
    if not match:
        return None
    year, month, day = (int(part) for part in match.groups())
    try:
        moment = datetime.datetime(
            year, month, day, 23, 59, 59, tzinfo=datetime.timezone.utc
        )
    except ValueError:
        return None
    return calendar.timegm(moment.utctimetuple())


@dataclass
class Waiver:
    """One accepted finding, with a reason and an end date."""

    rule: str = "*"
    artifact: str = "*"
    path: str = "*"
    finding_id: str = ""
    reason: str = ""
    owner: str = ""
    expires: str = ""
    downgrade_to: str = ""

    def matches(self, finding: Finding) -> bool:
        if self.finding_id:
            return self.finding_id == finding.fingerprint
        if not fnmatch.fnmatch(finding.rule_id, self.rule):
            return False
        if self.artifact != "*" and not fnmatch.fnmatch(
            finding.artifact_identity, self.artifact
        ):
            return False
        if self.path != "*":
            actual = finding.location.path.replace("\\", "/")
            if not fnmatch.fnmatch(actual, self.path):
                return False
        return True

    @property
    def expired(self) -> bool:
        if not self.expires:
            return False
        deadline = parse_date(self.expires)
        if deadline is None:
            # An unparseable date is treated as expired: a waiver nobody can
            # read is not a decision anyone can rely on.
            return True
        return time.time() > deadline

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Waiver":
        return cls(
            rule=str(data.get("rule") or data.get("rule_id") or "*"),
            artifact=str(data.get("artifact") or "*"),
            path=str(data.get("path") or "*"),
            finding_id=str(data.get("id") or data.get("finding_id") or ""),
            reason=str(data.get("reason") or ""),
            owner=str(data.get("owner") or ""),
            expires=str(data.get("expires") or data.get("until") or ""),
            downgrade_to=str(data.get("downgrade_to") or ""),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "artifact": self.artifact,
            "path": self.path,
            "id": self.finding_id,
            "reason": self.reason,
            "owner": self.owner,
            "expires": self.expires,
            "downgrade_to": self.downgrade_to,
        }


@dataclass
class Policy:
    """Everything an operator can decide without editing code."""

    fail_on: Severity = Severity.HIGH
    enabled_rules: List[str] = field(default_factory=list)
    disabled_rules: List[str] = field(default_factory=list)
    severity_overrides: Dict[str, Severity] = field(default_factory=dict)
    waivers: List[Waiver] = field(default_factory=list)
    baseline: List[str] = field(default_factory=list)
    injection_patterns: List[Dict[str, str]] = field(default_factory=list)
    known_packages: List[str] = field(default_factory=list)
    plugin_paths: List[str] = field(default_factory=list)
    #: Paths never scanned. Deliberately part of policy rather than only a
    #: flag, so "we do not scan our test fixtures" is committed and reviewable
    #: rather than living in whatever command someone typed.
    exclude: List[str] = field(default_factory=list)
    source_path: str = ""
    #: Populated during apply() so reports can surface stale decisions.
    expired_waivers: List[Waiver] = field(default_factory=list)

    # ---- loading ---------------------------------------------------------

    @classmethod
    def load(cls, path: str) -> "Policy":
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        data = _parse_structured(text, path)
        policy = cls.from_dict(data if isinstance(data, dict) else {})
        policy.source_path = path
        return policy

    @classmethod
    def discover(cls, roots: Sequence[str]) -> "Policy":
        """Find a policy file next to the code it governs."""
        for root in roots:
            for name in DEFAULT_POLICY_NAMES:
                candidate = os.path.join(root, name)
                if os.path.isfile(candidate):
                    try:
                        return cls.load(candidate)
                    except (OSError, ValueError):
                        continue
        return cls()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Policy":
        raw_rules = data.get("rules")
        rules = raw_rules if isinstance(raw_rules, dict) else {}

        overrides: Dict[str, Severity] = {}
        for rule_id, value in (rules.get("severity") or {}).items():
            try:
                overrides[str(rule_id)] = Severity.parse(value)
            except ValueError:
                continue

        try:
            fail_on = Severity.parse(data.get("fail_on", "HIGH"))
        except ValueError:
            fail_on = Severity.HIGH

        return cls(
            fail_on=fail_on,
            enabled_rules=[str(r) for r in (rules.get("enable") or [])],
            disabled_rules=[str(r) for r in (rules.get("disable") or [])],
            severity_overrides=overrides,
            waivers=[
                Waiver.from_dict(w)
                for w in (data.get("waivers") or [])
                if isinstance(w, dict)
            ],
            baseline=[str(b) for b in (data.get("baseline") or [])],
            injection_patterns=[
                p for p in (data.get("injection_patterns") or []) if isinstance(p, dict)
            ],
            known_packages=[str(p) for p in (data.get("known_packages") or [])],
            plugin_paths=[str(p) for p in (data.get("plugins") or [])],
            exclude=[str(p) for p in (data.get("exclude") or [])],
        )

    def rule_settings(self) -> Dict[str, Any]:
        """The subset of policy that individual rules read."""
        return {
            "injection_patterns": self.injection_patterns,
            "known_packages": self.known_packages,
        }

    # ---- application -----------------------------------------------------

    def apply(self, findings: Sequence[Finding]) -> List[Finding]:
        """Re-score and suppress according to policy.

        Suppressed findings are marked, not dropped: a report that silently
        omits accepted risk is how accepted risk becomes forgotten risk.  Every
        reporter shows the waived count, and ``--show-waived`` shows the detail.
        """
        self.expired_waivers = []
        baseline = set(self.baseline)
        out: List[Finding] = []

        for finding in findings:
            override = self.severity_overrides.get(finding.rule_id)
            if override is not None and override != finding.severity:
                finding.original_severity = finding.severity
                finding.severity = override

            if finding.fingerprint in baseline:
                finding.waived = True
                finding.waiver_reason = "accepted in baseline"
                out.append(finding)
                continue

            waiver = self._match(finding)
            if waiver is not None:
                if waiver.downgrade_to:
                    try:
                        downgraded = Severity.parse(waiver.downgrade_to)
                    except ValueError:
                        downgraded = None
                    if downgraded is not None:
                        finding.original_severity = finding.severity
                        finding.severity = downgraded
                        finding.waiver_reason = _describe_waiver(waiver)
                else:
                    finding.waived = True
                    finding.waiver_reason = _describe_waiver(waiver)
            out.append(finding)

        return out

    def _match(self, finding: Finding) -> Optional[Waiver]:
        for waiver in self.waivers:
            if not waiver.matches(finding):
                continue
            if waiver.expired:
                if waiver not in self.expired_waivers:
                    self.expired_waivers.append(waiver)
                continue
            return waiver
        return None

    def should_fail(self, highest: Severity, has_findings: bool = True) -> bool:
        """Exit-code decision for CI."""
        if not has_findings:
            return False
        return highest >= self.fail_on

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fail_on": self.fail_on.label,
            "rules": {
                "enable": list(self.enabled_rules),
                "disable": list(self.disabled_rules),
                "severity": {
                    k: v.label for k, v in sorted(self.severity_overrides.items())
                },
            },
            "waivers": [w.to_dict() for w in self.waivers],
            "baseline": list(self.baseline),
            "injection_patterns": list(self.injection_patterns),
            "known_packages": list(self.known_packages),
            "plugins": list(self.plugin_paths),
            "exclude": list(self.exclude),
            "source": self.source_path,
        }


def _describe_waiver(waiver: Waiver) -> str:
    parts = [waiver.reason or "accepted"]
    if waiver.owner:
        parts.append("owner: " + waiver.owner)
    if waiver.expires:
        parts.append("expires: " + waiver.expires)
    return " | ".join(parts)


def _parse_structured(text: str, path: str) -> Any:
    """Parse YAML when available, else JSON, whatever the extension says."""
    stripped = text.strip()
    if not stripped:
        return {}

    if path.lower().endswith(".json") or stripped.startswith("{"):
        return json.loads(text)

    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise ValueError(
            "policy file %s is YAML but PyYAML is not installed; "
            "install it, or write the policy as JSON" % path
        ) from exc
    return yaml.safe_load(text)
