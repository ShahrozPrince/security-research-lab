# Security Research Agents v1 — zero-cost, offline only

This package adds **15 deterministic Python security checks**, not 15 autonomous expert AI systems. It reviews **your own repository files** and produces a human-review report. No networking, credential requests, exploitation, website scanning, bounty submission, or payment is required.

## Add to existing repository

Preserve the following exact file paths relative to the repository root:

- `security_agents.py`
- `scope-config.json`
- `.github/workflows/security-agents.yml`
- `SECURITY_AGENTS_README.md` (optional but recommended)
- `.gitignore` and `SECURITY.md` (recommended security hygiene)
- `tests/test_agents.py` (optional offline regression tests)

Do not replace or delete existing Semgrep or Python syntax workflows. Keep the training file in `practice_lab/` while you are learning; your existing Semgrep run may continue to show a red cross due to the intentionally insecure lab code.

## Using it

Visit **GitHub → Actions → Security Agents (Offline Review) → Run workflow**. On completion, select the run, then click **Summary** to read the findings. GitHub also triggers it on commits, pull requests, and weekly schedule; GitHub may delay scheduled runs and they do not provide nonstop monitoring.

To test locally on Mac in this repository: `python3 -m unittest discover -s tests`, then `python3 security_agents.py`. This writes `agent-reports/report.md` and `agent-reports/report.json` (do not commit reports or confidential findings to public GitHub).

## Fifteen modules

1. Scope guard (offline/no external scanning)
2. Repository file inventory
3. Python syntax validation
4. Dangerous shell execution patterns
5. Dynamic code execution
6. Unsafe deserialization patterns
7. Weak cryptographic hashing
8. Disabled TLS verification
9. Potential hard-coded credentials (without printing values)
10. Potential private key files (without printing values)
11. Requirements dependency pinning
12. GitHub Action commit SHA pinning
13. GitHub workflow token permission review
14. Privileged GitHub workflow triggers
15. Repository security hygiene

A finding is **not proof** of an exploitable vulnerability, let alone eligibility for a bounty. Human validation and program-specific authorization are still required. Never put sensitive bounty data, live target credentials, private exploits, or non-public reports in a public repository.
