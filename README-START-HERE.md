# Finding Investigation Engine — starter upgrade

This improves the existing GitLab Runner public-source scanning by adding static rule-match categorization and within-run duplicate removal.

**What it does:** Takes Semgrep's JSON from public GitLab Runner source, groups by severity and broad vulnerability category, removes exact duplicates, prints safe aggregate counts. Includes unit tests with fake findings. The `--private-json` local-only mode can save exact rule/path/line details on your own trusted computer, but is intentionally refused on GitHub Actions in a public repo.

**What it does NOT do:** Prove vulnerabilities; scan any website; execute a real exploit; provide independent LLM agents; cross-run dedup or historical baselines; automatically identify bounty eligibility; disclose or submit to HackerOne; email/notify new verified bugs.

## Installation into ShahrozPrince/security-research-lab

1. Extract the ZIP. Mac Finder: Cmd + Shift + . shows the hidden `.github` folder.
2. On GitHub use Add file > Upload files. Drag the CONTENTS of the extracted package. Keep exact paths:
   - `finding_investigation_engine.py`
   - `tests/test_finding_investigation_engine.py`
   - `.github/workflows/finding-investigation-engine.yml`
   - `README-START-HERE.md`
3. Commit changes. If the workflow YAML lands in repository root, rename/move it via GitHub pencil editor into `.github/workflows/`.
4. Go to Actions > Finding Investigation Engine (Private-safe Triage) > Run workflow > main.
5. Check for a green workflow. Logs show aggregate counts only and zero independently verified vulnerabilities.

**Existing hourly workflow:** The `GitLab Runner Public Source Review` continues running hourly separately; this additional upgraded investigation workflow is **manual-only** until the new job has been verified. Avoid enabling two independent hourly scans of the same target unnecessarily. After testing, merge the new triage step into the existing hourly workflow and delete/disable the standalone duplicate.

**Privacy warning:** GitHub Actions runs and uploaded artifacts in a public repository should be treated as publicly visible. Do not print rule IDs, exact paths, code snippets, PoCs, or credentials in public logs. Exact rule matches are not verified vulnerabilities. To perform private detailed investigation, use a private repo/runner or the parser's local private-output mode; do not commit that output.
