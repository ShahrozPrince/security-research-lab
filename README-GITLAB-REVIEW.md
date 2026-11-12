# GitLab Runner — public-source research workflow

This workflow is an OPTIONAL read-only public code review, scheduled once every hour at minute 23 UTC. GitHub may delay or skip individual runs.
It clones the public GitLab Runner repository, checks two Go source
directories with Semgrep, and prints only aggregate unverified rule-match counts.

DOES NOT:
- probe/scan GitLab.com or other websites
- submit bounty reports
- prove that GitLab Runner is presently bounty-eligible
- reproduce vulnerabilities or preserve private evidence
- install 15 independent AI models or continuously operate

Official program: https://hackerone.com/gitlab
Official scope: https://hackerone.com/gitlab/policy_scopes
Source repository: https://gitlab.com/gitlab-org/gitlab-runner

Before investigating/reporting suspected issues, confirm GitLab Runner is
explicitly eligible in the current official HackerOne scope and follow
all restrictions. GitLab recommends local, self-managed testing with
reproducible evidence. This workflow makes only read-only Git requests
to retrieve openly published source code; there is no live-target testing.

INSTALL:
1. Extract this ZIP on your Mac.
2. GitHub repo: ShahrozPrince/security-research-lab -> Add file -> Upload files.
3. Drag the *contents* of this package so the resulting file lands at:
   .github/workflows/gitlab-runner-public-source-review.yml
4. Commit changes.
5. Actions -> GitLab Runner Public Source Review -> Run workflow.
6. Review its status. Scanner rule matches are leads, not verified bugs.

Note: The public GitHub run only prints counts. This is intentional:
sensitive vulnerability hypotheses and proof-of-concept evidence
should not be published in your public CI logs or artifacts.
