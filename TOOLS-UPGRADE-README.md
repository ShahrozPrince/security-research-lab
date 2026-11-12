# Advanced security toolchain upgrade v2

**Budget:** no paid APIs or subscriptions required in the proposed setup, subject to GitHub usage limits.

## What this actually adds

- **CodeQL**: weekly/on-commit Python security-extended code analysis; uploads findings to GitHub code scanning if available. The workflow needs `security-events: write` only for the CodeQL job.
- **Trivy**: dependency, misconfiguration, and secret indicators from repository files; JSON artifact. Indicators need review.
- **OSV-Scanner**: published vulnerability advisory matching for dependencies, not novel-bug discovery.
- **Hypothesis**: 100+ locally generated test cases for invariants on the existing Python analyzer. No websites.
- **Nuclei**: manual workflow with a single custom health-check template aimed only at `127.0.0.1:8765`.
- **OWASP ZAP**: manual baseline passive scan of the same synthetic local server. Never point at a third-party target without explicit current program authorization.
- **Burp Suite Community**: manual desktop tool; **not installed in GitHub Actions** and cannot autonomously run as an AI agent. Official website: https://portswigger.net/burp/communitydownload
- **AI orchestration**: the existing 15 local checks plus the separately scheduled 15-role research watch remain analytical workflows. **No paid API key, no 15 separate LLMs, and no autonomous world-wide live scanning are included.**

## Install into GitHub

Upload the files **maintaining the folder paths** to the root of `ShahrozPrince/security-research-lab`. Do NOT upload the enclosing `security-upgrade-v2` folder itself. The two workflow files MUST end up as:

- `.github/workflows/advanced-security.yml`
- `.github/workflows/local-web-lab.yml`

After committing, open GitHub > Actions > **Advanced Security Toolchain**. The jobs may take time and can flag the deliberately insecure training file. The **Authorized Local Web-Tool Lab** is manual: Actions > workflow > Run workflow. It ONLY checks its own localhost fixture. Do not run suspicious externally supplied templates.

The existing Semgrep workflow and old 15-check workflow are preserved; this package does not overwrite them. Some duplicate checks and warnings are expected.

## Scope and safety

This is not an unattended production website scanner or money-making guarantee. `scope-config.json` must keep external scanning false until you have read current asset-scope and automation policies and configured a separate authorized target workflow. A company's bug-bounty listing alone is not unlimited testing permission.

**Caution:** ZAP uses an upstream image tag (`stable`) here; for a production-grade pinned toolchain, replace it with a reviewed container digest after testing. Dependencies in existing `requirements.txt` are currently unpinned; pin them after compatibility testing. New workflow actions themselves are pinned to exact Git commits.

## Notes and verification

- CodeQL Action v4.39.2, Trivy Action v0.36.0, OSV Action v2.7.1 are pinned to official tag commits.
- Hypothesis is pinned to 6.170.15.
- Nuclei 3.11.1 release asset is verified against official checksums.
- ZAP uses the official GHCR stable container, baseline passive mode, on loopback only.
- CI execution has **not** been verified until you upload and observe run logs. Do not equate a green tick with confirmed vulnerability discovery.
