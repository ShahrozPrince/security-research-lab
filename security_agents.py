#!/usr/bin/env python3
"""Offline, zero-dependency repository security review with 15 independent checks.

No network requests, exploitation, target crawling, or automatic bug-bounty submission.
Potential findings require human verification.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

SKIP_DIRS = {'.git', '.venv', 'venv', 'node_modules', 'dist', 'build', '__pycache__', '.mypy_cache', '.pytest_cache', '.next'}
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 3_000
SOURCE_SUFFIXES = {'.py', '.js', '.ts', '.tsx', '.jsx', '.env', '.json', '.yml', '.yaml', '.toml', '.ini', '.cfg', '.sh'}

@dataclass(frozen=True)
class Finding:
    check: str
    severity: str
    file: str
    line: int
    detail: str
    recommendation: str
    training_only: bool = False

@dataclass
class Context:
    root: Path
    files: list[Path]
    texts: dict[Path, str]


def rel(ctx: Context, p: Path) -> str:
    return p.relative_to(ctx.root).as_posix()


def make(ctx: Context, check: str, severity: str, p: Path | None, line: int, detail: str, remedy: str) -> Finding:
    name = rel(ctx, p) if p else '(repository)'
    lab = name.startswith('practice_lab/') or name.startswith('.github/workflows/practice_lab/')
    return Finding(check, severity, name, line, detail, remedy, lab)


def lines(text: str) -> Iterable[tuple[int, str]]:
    return enumerate(text.splitlines(), 1)


def each_text(ctx: Context, suffixes: set[str] | None = None) -> Iterable[tuple[Path, str]]:
    for p, t in ctx.texts.items():
        if suffixes is None or p.suffix.lower() in suffixes:
            yield p, t


def load_context(root: Path) -> Context:
    paths = []
    texts = {}
    for p in root.rglob('*'):
        if len(paths) >= MAX_FILES:
            break
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts) or p.is_symlink() or not p.is_file():
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
            paths.append(p)
            if p.suffix.lower() in SOURCE_SUFFIXES or p.name.startswith('requirements') or p.name in {'SECURITY.md', 'README.md', '.gitignore', 'scope-config.json'}:
                texts[p] = p.read_text('utf-8', errors='replace')
        except (OSError, UnicodeError):
            continue
    return Context(root, paths, texts)


def python_asts(ctx: Context) -> Iterable[tuple[Path, ast.AST]]:
    for p, t in each_text(ctx, {'.py'}):
        try:
            yield p, ast.parse(t, filename=rel(ctx, p))
        except (SyntaxError, ValueError):
            continue


def call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return (call_name(node.value) + '.' + node.attr).strip('.')
    return ''


def check_scope(ctx: Context) -> list[Finding]:  # 01
    p = ctx.root / 'scope-config.json'
    try:
        data = json.loads(ctx.texts[p])
    except (KeyError, ValueError, TypeError):
        return [make(ctx, '01-scope-guard', 'LOW', p, 1, 'Missing or invalid scope configuration.', 'Use the included disabled scope-config.json; never scan a real site without program authorization.')]
    if data.get('external_scanning') is not False:
        return [make(ctx, '01-scope-guard', 'HIGH', p, 1, 'External scanning is not disabled.', 'Set external_scanning to false; this version never contacts websites.')]
    return []


def check_inventory(ctx: Context) -> list[Finding]:  # 02
    if len(ctx.files) >= MAX_FILES:
        return [make(ctx, '02-inventory', 'LOW', None, 0, 'Repository reached review file limit.', 'Reduce repository size or increase limit after review.')]
    return []


def check_syntax(ctx: Context) -> list[Finding]:  # 03
    found = []
    for p, t in each_text(ctx, {'.py'}):
        try:
            compile(t, rel(ctx, p), 'exec')
        except SyntaxError as e:
            found.append(make(ctx, '03-python-syntax', 'MEDIUM', p, e.lineno or 0, 'Python syntax error.', 'Fix syntax before running code.'))
    return found


def check_shell(ctx: Context) -> list[Finding]:  # 04
    out = []
    for p, tree in python_asts(ctx):
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call): continue
            name = call_name(n.func)
            if name in {'os.system', 'os.popen'}:
                out.append(make(ctx, '04-shell-execution', 'HIGH', p, n.lineno, 'Shell command execution needs input review.', 'Avoid shell execution with user-controlled strings.'))
            if name in {'subprocess.call', 'subprocess.run', 'subprocess.Popen', 'subprocess.check_output', 'subprocess.check_call'} and any(k.arg == 'shell' and isinstance(k.value, ast.Constant) and k.value.value is True for k in n.keywords):
                out.append(make(ctx, '04-shell-execution', 'HIGH', p, n.lineno, 'subprocess shell=True is risky with untrusted input.', 'Use an argument list and shell=False.'))
    return out


def check_dynamic_execution(ctx: Context) -> list[Finding]:  # 05
    out = []
    for p, tree in python_asts(ctx):
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and call_name(n.func) in {'eval', 'exec'}:
                out.append(make(ctx, '05-dynamic-execution', 'HIGH', p, n.lineno, 'Dynamic code execution detected.', 'Avoid eval/exec with untrusted data.'))
    return out


def check_pickle(ctx: Context) -> list[Finding]:  # 06
    out = []
    for p, tree in python_asts(ctx):
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and call_name(n.func) in {'pickle.load', 'pickle.loads', 'dill.load', 'dill.loads'}:
                out.append(make(ctx, '06-deserialization', 'HIGH', p, n.lineno, 'Unsafe deserialization may execute code.', 'Never deserialize untrusted pickle/dill input.'))
    return out


def check_weak_hash(ctx: Context) -> list[Finding]:  # 07
    out = []
    for p, tree in python_asts(ctx):
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and call_name(n.func) in {'hashlib.md5', 'hashlib.sha1'}:
                out.append(make(ctx, '07-weak-hashing', 'LOW', p, n.lineno, 'MD5/SHA1 used; check whether cryptographic security is required.', 'Prefer SHA-256 or a password hashing KDF where appropriate.'))
    return out


def check_tls(ctx: Context) -> list[Finding]:  # 08
    out = []
    for p, tree in python_asts(ctx):
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and any(k.arg == 'verify' and isinstance(k.value, ast.Constant) and k.value.value is False for k in n.keywords):
                out.append(make(ctx, '08-tls-verification', 'HIGH', p, n.lineno, 'verify=False can disable TLS certificate checks.', 'Use TLS verification for production connections.'))
    return out


CREDENTIAL = re.compile(r'''(?i)\b(password|api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[:=]\s*["']([^"']{8,})["']''')
PLACEHOLDER = re.compile(r'(?i)(example|dummy|replace|changeme|placeholder|your[_-]|<|\{)')

def check_credentials(ctx: Context) -> list[Finding]:  # 09
    out=[]
    for p,t in each_text(ctx, SOURCE_SUFFIXES):
        for number,line in lines(t):
            if line.lstrip().startswith('#'): continue
            m=CREDENTIAL.search(line)
            if m and not PLACEHOLDER.search(m.group(2)):
                out.append(make(ctx,'09-credentials','HIGH',p,number,'Possible hardcoded credential (value intentionally hidden).','Review securely; revoke real exposed tokens and use environment secrets.'))
    return out


def check_private_keys(ctx: Context) -> list[Finding]:  # 10
    out=[]
    for p,t in each_text(ctx):
        # Match PEM header on its own line, not a string literal in our scanner source.
        if re.search(r'(?m)^\s*-----BEGIN (?:RSA )?PRIVATE KEY-----\s*$', t):
            out.append(make(ctx,'10-private-keys','CRITICAL',p,1,'Private key marker found (key contents withheld).','Remove key from repository history and rotate exposed key.'))
    return out


def check_dependencies(ctx: Context) -> list[Finding]:  # 11
    out=[]
    for p,t in each_text(ctx):
        if not p.name.startswith('requirements') or p.suffix != '.txt': continue
        for n,l in lines(t):
            v=l.strip()
            if v and not v.startswith(('#','-')) and '==' not in v and '@' not in v and not v.startswith('git+'):
                out.append(make(ctx,'11-dependency-pinning','LOW',p,n,'Dependency version is not pinned.','Pin reviewed dependencies to a tested version.'))
    return out


def workflow_files(ctx: Context) -> Iterable[tuple[Path,str]]:
    for p,t in ctx.texts.items():
        if rel(ctx,p).startswith('.github/workflows/') and p.suffix.lower() in {'.yml','.yaml'}:
            yield p,t


def check_action_pinning(ctx: Context) -> list[Finding]:  # 12
    out=[]
    for p,t in workflow_files(ctx):
        for n,l in lines(t):
            m=re.search(r'^\s*(?:-\s*)?uses:\s*([^\s#]+)',l)
            if m and not re.search(r'@[a-f0-9]{40}$',m.group(1)) and not m.group(1).startswith('./'):
                out.append(make(ctx,'12-action-pinning','MEDIUM',p,n,'GitHub Action is not pinned to a full SHA.','Pin third-party actions to reviewed commit SHA.'))
    return out


def check_workflow_permissions(ctx: Context) -> list[Finding]:  # 13
    out=[]
    for p,t in workflow_files(ctx):
        for n,l in lines(t):
            if re.search(r'\bpermissions:\s*write-all\b',l) or re.search(r'^\s*(contents|actions|pull-requests|issues):\s*write\s*(?:#.*)?$',l):
                out.append(make(ctx,'13-workflow-permissions','MEDIUM',p,n,'Workflow includes write access; review necessity.','Grant the minimum job-specific permissions.'))
    return out


def check_workflow_triggers(ctx: Context) -> list[Finding]:  # 14
    out=[]
    for p,t in workflow_files(ctx):
        for n,l in lines(t):
            if re.search(r'^\s*(pull_request_target|workflow_run)\s*:',l):
                out.append(make(ctx,'14-workflow-triggers','MEDIUM',p,n,'Privileged workflow trigger requires extra review.','Avoid executing untrusted code with privileged tokens.'))
    return out


def check_hygiene(ctx: Context) -> list[Finding]:  # 15
    out=[]
    if not (ctx.root/'.gitignore').exists():
        out.append(make(ctx,'15-repo-hygiene','LOW',None,0,'No .gitignore found.','Add exclusions for caches, local credentials, and virtual environments.'))
    if not (ctx.root/'SECURITY.md').exists():
        out.append(make(ctx,'15-repo-hygiene','INFO',None,0,'No SECURITY.md responsible disclosure instructions found.','Document how findings should be reported privately.'))
    return out


CHECKS: list[Callable[[Context],list[Finding]]] = [
    check_scope,check_inventory,check_syntax,check_shell,check_dynamic_execution,
    check_pickle,check_weak_hash,check_tls,check_credentials,check_private_keys,
    check_dependencies,check_action_pinning,check_workflow_permissions,
    check_workflow_triggers,check_hygiene,
]


def main() -> int:
    parser=argparse.ArgumentParser(description='Run 15 offline security checks on a repository.')
    parser.add_argument('--root',default='.',help='Repository root to inspect (offline only).')
    parser.add_argument('--output',default='agent-reports',help='Directory for JSON and Markdown reports.')
    args=parser.parse_args()
    root=Path(args.root).resolve()
    if not root.is_dir(): parser.error('Root is not a directory')
    ctx=load_context(root)
    all_findings=[]
    by_check=[]
    for check in CHECKS:
        results=check(ctx)
        all_findings.extend(results)
        by_check.append({'module':check.__name__,'findings':len(results)})
    # Stable deduplication without disclosing source lines or secret values.
    unique={ (f.check,f.file,f.line,f.detail):f for f in all_findings }
    findings=sorted(unique.values(),key=lambda f:(f.training_only,f.file,f.line,f.check))
    summary={'generated_utc':datetime.now(timezone.utc).isoformat(), 'mode':'offline-repository-only',
             'real_websites_scanned':0,'modules_run':len(CHECKS),'files_reviewed':len(ctx.files),
             'findings_for_review':sum(not f.training_only for f in findings),
             'training_lab_findings':sum(f.training_only for f in findings),
             'modules':by_check,'findings':[asdict(f) for f in findings]}
    out=Path(args.output)
    if not out.is_absolute(): out=root/out
    out.mkdir(parents=True,exist_ok=True)
    (out/'report.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    md=['# Security Research Agents — Offline report','',
        f"- Modules run: **{len(CHECKS)}**",f"- Files reviewed: **{len(ctx.files)}**",
        f"- Potential findings requiring review: **{summary['findings_for_review']}**",
        f"- Training-only findings: **{summary['training_lab_findings']}**",
        '- Real websites contacted: **0**','',
        '> Findings are indicators, not verified exploitable vulnerabilities or bounty claims.','',
        '## Potential findings','']
    if not findings: md.append('None reported by these checks.')
    else:
        for f in findings:
            label=' (training lab)' if f.training_only else ''
            md.append(f"- **{f.severity}** {f.check}: `{f.file}:{f.line}`{label} — {f.detail} {f.recommendation}")
    (out/'report.md').write_text('\n'.join(md)+'\n',encoding='utf-8')
    print(f"Completed {len(CHECKS)} offline checks, {len(ctx.files)} files, "
          f"{summary['findings_for_review']} review findings, {summary['training_lab_findings']} lab findings. Zero website requests.")
    print(f"Reports: {out/'report.md'} and {out/'report.json'}")
    return 0  # Findings are reviewed manually; do not silently claim any bug is verified.


if __name__=='__main__':
    raise SystemExit(main())
