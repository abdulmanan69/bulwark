# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - unreleased

First release.

### Added

- **Discovery** across Claude Code, Claude Desktop, Cursor, VS Code, Windsurf,
  Cline, Roo, Zed and Continue, plus skills, subagents, slash commands, hooks,
  permission rules, instruction files and `.env` files.
- **26 rules** in seven families - injection, composite, supply-chain, drift,
  permissions, hooks and secrets - each mapped to OWASP LLM Top 10, MITRE
  ATLAS, NIST AI 600-1, CWE, ISO/IEC 42001 and EU AI Act identifiers.
- **Unicode forensics**: recovery of payloads hidden in the Unicode Tag block,
  zero-width characters, bidi overrides, variation selectors, private-use
  characters, homoglyphs, base64/hex blobs and CSS-hidden markup.
- **Capability inference** from tool names, descriptions and JSON schemas, and
  the trust-boundary roles that make the trifecta rule possible.
- **`bulwark.lock`**: content pinning of every model-visible string, with
  `pin`, `diff` and `verify` for detecting changes made after review.
- **`bulwark proxy`**: a runtime MCP guard with tool allow/deny lists,
  bidirectional credential redaction, live drift detection, tool-result
  injection scanning and an append-only JSONL audit log.
- **`bulwark aibom`**: CycloneDX 1.5 bill of materials for the agent's
  reachable surface.
- **Reports** in terminal, JSON, SARIF 2.1.0, JUnit, Markdown and
  self-contained HTML.
- **Policy as code** with expiring waivers, severity overrides, baselines,
  custom injection patterns and Python rule plugins.
- A reusable GitHub Action and pre-commit hooks.

### Security

- No runtime dependencies.
- No network egress; remote MCP endpoints are never contacted during a scan.
- Detected credentials are never written to any output - masked preview and
  hash only.
- All detection patterns are linear, so hostile input cannot cause
  catastrophic backtracking.
