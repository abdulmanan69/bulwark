## What this changes

<!-- One or two sentences. What is different after this merges? -->

## Why

<!-- The problem, not the solution. -->

## If this changes detection

- [ ] Added a true-positive test with realistic hostile input
- [ ] Added a false-positive test with realistic benign input that stays silent
- [ ] `BENIGN_DESCRIPTIONS` and `clean_project` still produce zero findings
- [ ] Finding carries evidence quoting the string that fired
- [ ] Remediation names a concrete command or change
- [ ] Framework mappings filled in
- [ ] Ran `python scripts/gen_rules_doc.py`

**What it now catches, and what it deliberately still does not:**

<!-- Be explicit about the limits. -->

## Checks

- [ ] `pytest` passes
- [ ] `ruff check src tests` is clean
- [ ] `mypy src/bulwark` is clean
- [ ] No new runtime dependencies
- [ ] No new network calls
