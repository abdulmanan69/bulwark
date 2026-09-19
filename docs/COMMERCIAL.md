# Commercialising Bulwark

Written for whoever owns this repository and is deciding what to do with it.
It is deliberately blunt about what is built, what is missing, and what is
uncertain, because a plan built on a flattering summary is worse than no plan.

---

## 1. What exists right now

A complete, tested, installable product:

- 26 detection rules across seven families, each with evidence, remediation
  and control-framework mappings
- discovery across nine agent hosts and six config dialects
- a lockfile with pin / diff / verify, which is the one capability no other
  tool in this space has
- a runtime MCP guard proxy with audit logging
- SARIF, JUnit, JSON, Markdown and HTML reporting
- CycloneDX AIBOM output
- policy as code with expiring waivers and a plugin interface
- 266 tests, 82% coverage, zero runtime dependencies, clean lint and types
- a reusable GitHub Action and pre-commit hooks

That is a credible open-source release. It is **not yet a business**, and the
gap between those two things is mostly distribution, not code.

## 2. Why the timing is unusually good

Three things are true at once, and that combination is what creates an opening:

1. **Adoption is vertical.** MCP went from a proposal to something shipped in
   Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Zed, Cline and a
   long tail of hosts. Every one of those installs is unmanaged surface.
2. **The controls do not exist.** Ask any security team for an inventory of
   which MCP servers their engineers run and what those servers can reach.
   Nobody can produce one. There is no CMDB entry, no dependency manifest, no
   approval workflow.
3. **Compliance is arriving.** The EU AI Act, ISO/IEC 42001 and NIST AI 600-1
   all create an obligation to document and control AI system components.
   Auditors will start asking for an agent inventory before most organisations
   have one. Bulwark's AIBOM output is that artifact.

Windows like this close. The realistic span is twelve to twenty-four months
before either a platform vendor ships this natively or a funded startup owns
the category.

## 3. Who actually buys, and what they buy

| Segment | Pain | What they pay for | Rough range |
|---|---|---|---|
| Individual developers | "Is this MCP server safe to install?" | Nothing. They are distribution, not revenue. | free |
| Security-conscious startups (20-200 eng) | No visibility into what engineers installed | Hosted dashboard, org-wide rollup, Slack alerts | $500-2k/mo |
| Regulated enterprises (finance, health, defence) | Need an auditable AI component inventory | On-prem, SSO, policy federation, support SLA, the AIBOM | $25k-150k/yr |
| AI platform vendors | Need to show their marketplace is vetted | OEM licence: scan every listed server | one-off + recurring |
| Consultancies and auditors | Need a repeatable AI security assessment | Per-seat professional licence, white-label reports | $1-5k/seat/yr |

These ranges are estimates extrapolated from comparable developer-security
tooling, not quotes from anyone. Treat them as a hypothesis to test, not a
forecast.

The enterprise row is where the money is, and it is reachable *because* of the
compliance angle, not despite it. "Show me your AI component inventory" is a
question with a budget attached.

## 4. Three viable paths

### Path A — Open core (recommended)

Keep everything in this repository free and Apache-2.0 forever. Sell the
things that only make sense across many machines:

- **Fleet server.** Agents on developer laptops report posture to a central
  dashboard. Answers "which of my 400 engineers is running an unpinned
  filesystem server with write access".
- **Policy federation.** Security writes one policy; it applies everywhere.
- **Drift alerting.** A rug pull on any machine pages someone.
- **Findings history.** Trend lines, per-team scores, audit evidence.
- **SSO, RBAC, SOC 2, support SLA.** Boring, and the actual reason enterprises
  sign.

Why this works: the free tool has to be genuinely good and genuinely free, or
it never gets installed, and nothing else in the plan happens. The paid layer
is the part an individual developer would never want anyway.

Why it might not: open core needs enough adoption that some fraction converts.
That means the free tool must become the default answer to "how do I check an
MCP server", which is a distribution problem measured in months.

### Path B — Services first

Use the tool as the engine for an "AI agent security assessment" offering.
Scan a client estate, produce the report, present the findings, sell the
remediation work.

Faster to revenue — weeks, not quarters — and it funds the product. The catch
is that it consumes the time that would otherwise go into distribution, and
services revenue does not compound the way a product does. It is a good bridge
and a poor destination.

### Path C — Acquisition target

Build adoption and sell to an existing security vendor who needs an AI-security
story: Snyk, Wiz, Semgrep, JFrog, Chainguard, Endor Labs, or a cloud provider.

Not a plan you can execute directly; it is an outcome of Path A going well. But
it is worth structuring for: keep the licence clean, keep the dependency tree
empty, keep every contribution under a CLA, and do not accept code you cannot
relicense.

## 5. The first ninety days

**Days 1-14 — ship it.**
Publish to PyPI and GitHub. Register the GitHub Action on the Marketplace.
Publish [the launch post](launch-post.md), which demonstrates a rug pull end to
end rather than describing one, because the demo is the argument. Submit to the MCP ecosystem
lists. This costs nothing and is the whole foundation.

**Days 15-45 — earn credibility.**
Scan the top few hundred public MCP servers. Publish the aggregate findings —
no naming and shaming, disclose privately first, report percentages. A figure
like "two in five public MCP servers ship unpinned" is the kind of number
journalists and security leads both repeat, and it is a number only you would
have. Submit a talk to an applied security conference.

**Days 46-90 — find the ten.**
Talk to ten security engineers at companies with 50+ developers. Not a survey;
watch them run it. The question is not "would you pay" but "what did you do
with the output". If three of them ask for a central view, Path A is real. If
none do, the honest read is that this is a valuable open-source tool and a
services business, and that is a fine outcome — but stop building the SaaS.

## 6. Where this could fail

**A platform vendor ships it natively.** Anthropic, Microsoft or the MCP spec
itself could add signing and pinning. *Mitigation:* the multi-host,
multi-dialect inventory stays valuable regardless, and the compliance
reporting is not something a platform will build.

**A funded competitor moves faster.** Several will. *Mitigation:* the lockfile
and the trifecta analysis are genuinely differentiated today, and being first
with a credible free tool is worth more than being second with a better one.

**Detection quality erodes trust.** One noisy release and teams mute it
permanently. *Mitigation:* the benign-corpus test is not a nicety — treat a
false positive as a P1 bug, always.

**Nobody cares until there is an incident.** Very possible. Security tools in a
new category usually sell after the first public breach, not before.
*Mitigation:* the compliance angle creates demand that does not wait for an
incident. Lead with the audit requirement, not the scary scenario.

**The owner underestimates distribution.** The most likely failure by a wide
margin. The code is done; that was the easy part. The next ninety days are
writing, talking and answering issues, and none of it looks like progress
while it is happening.

## 7. Things not to do

- **Do not add runtime dependencies.** "Zero dependencies" is a real
  differentiator for a security tool and it gets harder to claim every time
  you take one.
- **Do not gate core detection.** The moment a rule is enterprise-only, the
  free tool stops being trustworthy and adoption stops.
- **Do not send scan data anywhere by default.** Not even anonymised. The
  product reads the most sensitive configuration on a developer's machine;
  the first telemetry scandal would be terminal.
- **Do not name vendors in vulnerability research before disclosing.** Ninety
  days, privately, every time. The credibility is the asset.
- **Do not build the dashboard before ten people ask for it.**

## 8. The honest summary

What is built is real, complete and unusually well-tested for a first release.
The technical differentiators — the lockfile, the trifecta analysis, the
Unicode forensics, the runtime guard — are genuine and not trivially copied.

What is unproven is whether enough people will install it, and whether enough
of those will pay for the layer above it. Those are distribution and market
questions, and no amount of additional code answers either one.

The next commit that matters is not in this repository. It is a PyPI release
and a blog post.
