# Contributing

Thanks for considering it. This is a security tool, so the bar for a few
specific things is higher than usual — but most of it is ordinary Python.

## Getting set up

```bash
git clone https://github.com/abdulmanan69/bulwark
cd bulwark
pip install -e ".[dev]"
pytest                     # 266 tests, under 10 seconds
ruff check src tests
mypy src/bulwark
```

## The one rule that matters most

**A false positive is a P1 bug.**

A scanner that fires on a reasonable setup gets muted, and a muted scanner
catches nothing. `tests/conftest.py` holds `BENIGN_DESCRIPTIONS` and the
`clean_project` fixture; both must stay completely clean. If your change makes
either produce a finding, the change is wrong, not the fixture.

## Adding a detection rule

A rule is a class with metadata and one method:

```python
from bulwark.core.models import ArtifactKind, Evidence, Severity
from bulwark.core.rulebase import Rule, register


@register
class MyRule(Rule):
    id = "BW-XXX-00N"
    title = "One line, states the problem not the symptom"
    severity = Severity.HIGH
    category = "injection"
    description = "..."      # why it matters, in prose, not a slogan
    remediation = "..."      # what to actually type or change
    frameworks = {"OWASP-LLM-2025": ["LLM01"], "CWE": ["CWE-94"]}

    def check(self, ctx):
        for tool in ctx.tools():
            if bad(tool):
                yield self.finding(
                    tool,
                    evidence=[Evidence(label="why", value=quote_the_string)],
                )
```

A rule is accepted when it has:

- a **true-positive test** with a realistic hostile input,
- a **false-positive test** with realistic benign input that must stay silent,
- **evidence** quoting the exact string that fired, so a reader can verify it,
- **remediation** that names a command or a concrete change,
- **framework mappings**, which is what makes findings usable in an audit.

Then regenerate the reference:

```bash
python scripts/gen_rules_doc.py
```

## Non-negotiables

- **No runtime dependencies.** A tool people install to prevent supply-chain
  incidents must not become one. Dev and test dependencies are fine.
- **No network calls during a scan.** Ever. Not telemetry, not version checks,
  not reaching a remote MCP endpoint.
- **Never emit a secret.** Detected credentials get a masked preview and a
  hash. Not to a report, not to a log, not to stdout.
- **Linear regexes only.** No nested unbounded quantifiers — hostile input must
  not be able to cause catastrophic backtracking.
- **Discovery never raises.** A malformed config becomes a recorded error and
  an otherwise complete scan.

## Style

- `%`-formatting throughout; it is the house style, not a backlog.
- Comments explain *why*, not *what*. If a line needs a comment to say what it
  does, rename something instead.
- Docstrings on modules and non-obvious functions, written for someone who has
  not read the rest of the file.

## Pull requests

Small and focused beats large and complete. Include the tests. If it changes
detection behaviour, say in the description what it now catches and what it
deliberately still does not.
