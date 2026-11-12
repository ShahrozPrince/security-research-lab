#!/usr/bin/env python3
"""Review Semgrep JSON for local/public-source research, without leaking leads to public CI.

This is static triage, NOT vulnerability reproduction or an autonomous AI agent.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter
from pathlib import Path

CATEGORIES = (
    ('command execution', ('command-injection', 'os-command', 'subprocess', 'shell')), 
    ('injection', ('injection', 'sql', 'template', 'xss')),
    ('access control', ('authorization', 'authentication', 'access-control', 'idor', 'permission')),
    ('paths and files', ('path-traversal', 'file-read', 'file-write', 'filepath')),
    ('secrets', ('secret', 'credential', 'password', 'token')),
    ('cryptography', ('cryptograph', 'weak-hash', 'insecure-random', 'tls')),
    ('deserialization', ('deserializ', 'pickle', 'unsafe-load')),
    ('network requests', ('ssrf', 'request-forgery', 'url-fetch')),
)


def category_for(rule_id: str) -> str:
    value = rule_id.lower()
    for label, words in CATEGORIES:
        if any(word in value for word in words):
            return label
    return 'other / manual review'


def normalize(raw: dict) -> list[dict]:
    results = raw.get('results', [])
    if not isinstance(results, list):
        raise ValueError('Semgrep JSON must contain a results list')
    if raw.get('errors'):
        raise ValueError('Semgrep reported analysis errors; review locally')
    seen = set()
    findings = []
    for result in results:
        if not isinstance(result, dict):
            continue
        rule_id = str(result.get('check_id') or 'unknown')
        path = str(result.get('path') or 'unknown')
        start = result.get('start') or {}
        line = start.get('line') if isinstance(start, dict) else None
        try:
            line = max(0, int(line))
        except (ValueError, TypeError):
            line = 0
        extra = result.get('extra') or {}
        if not isinstance(extra, dict):
            extra = {}
        severity = str(extra.get('severity') or 'UNKNOWN').upper()
        # SHA not exposed in public CI logs. Deduplicates repeated reports within one run.
        fingerprint = hashlib.sha256(f'{rule_id}\0{path}\0{line}'.encode('utf-8')).hexdigest()
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        findings.append({
            'id': fingerprint,
            'rule': rule_id,
            'path': path,
            'line': line,
            'severity': severity,
            'category': category_for(rule_id),
            'status': 'UNVERIFIED',
        })
    return sorted(findings, key=lambda f: (f['category'], f['severity'], f['path'], f['line']))


def summary(findings: list[dict]) -> dict:
    return {
        'unique_unverified_matches': len(findings),
        'by_severity': dict(sorted(Counter(x['severity'] for x in findings).items())),
        'by_category': dict(sorted(Counter(x['category'] for x in findings).items())),
        'independently_reproduced_vulnerabilities': 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description='Offline Semgrep findings triage; private by default')
    parser.add_argument('--input', required=True, help='Existing Semgrep JSON output')
    parser.add_argument('--private-json', help='OPTIONAL: exact findings on a trusted local machine only')
    args = parser.parse_args()
    raw = json.loads(Path(args.input).read_text(encoding='utf-8'))
    findings = normalize(raw)
    print('PUBLIC SAFE TRIAGE SUMMARY (rule matches are not validated vulnerabilities)')
    print(json.dumps(summary(findings), indent=2, sort_keys=True))
    if args.private_json:
        if os.environ.get('GITHUB_ACTIONS', '').lower() == 'true':
            parser.error('Refusing to create a detailed findings report on public GitHub Actions')
        destination = Path(args.private_json).resolve()
        if destination.exists():
            parser.error('Refusing to overwrite an existing report')
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(str(destination), flags, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            json.dump({'findings': findings, 'notice': 'UNVERIFIED. Confirm scope and reproduce locally.'}, out, indent=2)
            out.write('\n')
        print('Private details saved locally; never upload to a public repository.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
