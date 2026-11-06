"""Simple local hygiene gate. This is NOT a replacement for a real secret scanner."""
from __future__ import annotations
from pathlib import Path
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
blocked_names = ('.env', '.env.local', '.env.production', 'credentials.json',
                 'service-account.json', 'id_rsa', 'id_ed25519')
blocked_extensions = ('.pem', '.key', '.p12', '.pfx', '.sqlite', '.db')
secrets = [
    re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    re.compile(rb'\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{20,}\b'),
    re.compile(rb'\bgithub_pat_[A-Za-z0-9_]{20,}\b'),
    re.compile(rb'\bAKIA[0-9A-Z]{16}\b'),
    re.compile(rb'\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b'),
]


def check() -> list[str]:
    try:
        result = subprocess.run(['git', 'ls-files', '-z'], cwd=root, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, check=True)
        relative = [Path(p.decode()) for p in result.stdout.split(b'\0') if p]
    except (FileNotFoundError, subprocess.CalledProcessError):
        # Source archive without .git: scan working source tree instead.
        relative = [p.relative_to(root) for p in root.rglob('*')
                    if p.is_file() and '.git' not in p.parts and '__pycache__' not in p.parts
                    and '.egg-info' not in p.parts]
    issues = []
    for path in relative:
        if path.name in blocked_names or path.suffix.lower() in blocked_extensions:
            issues.append(f'Forbidden sensitive file name: {path}')
            continue
        full = root / path
        if not full.exists() or full.is_symlink():
            issues.append(f'Missing/symlink file in manifest: {path}')
            continue
        if full.stat().st_size > 1024 * 1024:
            issues.append(f'Unexpected large file (>1MiB): {path}')
            continue
        contents = full.read_bytes()
        if any(pattern.search(contents) for pattern in secrets):
            issues.append(f'Potential hardcoded secret: {path}')
    return issues


if __name__ == '__main__':
    problems = check()
    if problems:
        for problem in problems:
            print('BLOCK:', problem)
        sys.exit(1)
    print('Basic repository hygiene: PASS (not a full secret audit)')
