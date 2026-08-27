from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Iterable

REQUIRED_FILES = {
    '.gitattributes',
    '.gitignore',
    'LICENSE',
    'NOTICE.md',
    'README.md',
    'SECURITY.md',
    'TRADEMARKS.md',
    'pyproject.toml',
}

FORBIDDEN_DIR_NAMES = {
    '.git',
    '.idea',
    '.mypy_cache',
    '.pytest_cache',
    '.ruff_cache',
    '.venv',
    '.vscode',
    '__pycache__',
    'build',
    'dist',
}
LOCAL_ARTIFACT_DIR_NAMES = {'.git', '.idea', '.mypy_cache', '.pytest_cache', '.ruff_cache', '.venv', '.vscode', '__pycache__', 'build', 'dist'}

FORBIDDEN_FILE_GLOBS = (
    '.env',
    '.env.*',
    '*.pem',
    '*.key',
    '*.p12',
    '*.pfx',
    '*.aryxkey',
    '*.aryxkey.json',
    '*.aryxvault',
    '*.aryxvault.json',
    '*.aryxdevice',
    '*.aryxbak',
    '*.aryxbak.json',
    '*.aryxdev',
    '*.aryxowner',
    '*.aryxowner.json',
    '*.aryxcert.json',
    '*.aryxtrust.json',
    '*_Patch.ps1',
    'FINAL_QUALITY_GATE.json',
    'PRIVATE_Arenyxa_Developer_Authority*.zip',
)

BINARY_SUFFIXES = {
    '.7z', '.bmp', '.dll', '.exe', '.gif', '.ico', '.jpeg', '.jpg', '.pdf', '.png',
    '.so', '.tar', '.tgz', '.webp', '.whl', '.zip',
}

                                                              
MAX_FILE_BYTES = 95 * 1024 * 1024
MAX_TEXT_SCAN_BYTES = 5 * 1024 * 1024

SECRET_PATTERNS = (
    ('private-key PEM block', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----')),
    ('AWS access-key-like token', re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ('GitHub classic token-like value', re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{20,}\b')),
    ('GitHub fine-grained token-like value', re.compile(r'\bgithub_pat_[A-Za-z0-9_]{20,}\b')),
    ('Google API-key-like value', re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b')),
    ('AI-provider-key-like value', re.compile(r'\bsk-[A-Za-z0-9_-]{20,}\b')),
)

PERSONAL_OR_PRIVATE_PATTERNS = (
    ('local Jerry profile path', re.compile(r'(?i)C:\\\\Users\\\\Jerry(?:\\\\|\b)')),
    ('local Arenyxa development path', re.compile(r'(?i)D:\\\\Project\\\\Arenyxa')),
    ('private owner email', re.compile(r'(?i)wangyixuan\.2013\.4@gmail\.com')),
    ('forbidden assistant/provider branding', re.compile(r'(?i)\b(?:' + 'Open' + 'AI' + '|' + 'Chat' + 'GPT' + r')\b')),
)


def iter_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob('*')):
        if path.is_file():
            yield path


def relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def is_forbidden_filename(path: Path) -> bool:
    name = path.name
    for pattern in FORBIDDEN_FILE_GLOBS:
        if Path(name).match(pattern):
            return True
    return False


def scan_text(path: Path) -> str | None:
    if path.suffix.casefold() in BINARY_SUFFIXES:
        return None
    if path.stat().st_size > MAX_TEXT_SCAN_BYTES:
        return None
    try:
        return path.read_text(encoding='utf-8')
    except (UnicodeDecodeError, OSError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description='Fail closed if an Arenyxa tree is unsafe to publish on GitHub.')
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        '--allow-local-artifacts', action='store_true',
        help='exclude known local build/cache roots while auditing the publishable source inventory',
    )
    args = parser.parse_args()
    root = args.root.resolve()

    findings: list[str] = []

    for required in sorted(REQUIRED_FILES):
        if not (root / required).is_file():
            findings.append(f'missing required public repository file: {required}')

    attributes = root / '.gitattributes'
    if attributes.is_file():
        attributes_text = attributes.read_text(encoding='utf-8')
        if '* text=auto eol=lf' not in attributes_text:
            findings.append('.gitattributes must pin text checkout bytes to LF for source-manifest stability')

    files = list(iter_files(root))
    total_bytes = 0
    scanned_files: list[Path] = []
    for path in files:
        rel = relative(path, root)
        parts = set(path.relative_to(root).parts[:-1])
        if args.allow_local_artifacts and parts & LOCAL_ARTIFACT_DIR_NAMES:
            continue
        if parts & FORBIDDEN_DIR_NAMES:
            findings.append(f'forbidden generated/local directory content: {rel}')
            continue
        if is_forbidden_filename(path):
            findings.append(f'private/transient artifact filename: {rel}')
            continue

        size = path.stat().st_size
        total_bytes += size
        scanned_files.append(path)
        if size > MAX_FILE_BYTES:
            findings.append(f'file exceeds GitHub-safe 95 MiB threshold: {rel} ({size} bytes)')

        text = scan_text(path)
        if text is None:
            continue
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                findings.append(f'{label}: {rel}')
        for label, pattern in PERSONAL_OR_PRIVATE_PATTERNS:
            if pattern.search(text):
                findings.append(f'{label}: {rel}')

                                                                                             
                                                                                            
    for path in files:
        parts = set(path.relative_to(root).parts[:-1])
        if args.allow_local_artifacts and parts & LOCAL_ARTIFACT_DIR_NAMES:
            continue
        rel = relative(path, root)
        lowered = rel.casefold()
        if 'arenyxa_dev_authority' in lowered or 'private_arenyxa_developer_authority' in lowered:
            findings.append(f'private Developer Authority implementation/artifact present: {rel}')

    if findings:
        print('Arenyxa GitHub publication gate: FAIL')
        for finding in sorted(set(findings)):
            print(f'- {finding}')
        return 1

    largest = max((path.stat().st_size for path in scanned_files), default=0)
    print('Arenyxa GitHub publication gate: PASS')
    print(f'- files scanned: {len(scanned_files)}')
    print(f'- repository bytes scanned: {total_bytes}')
    print(f'- largest file: {largest} bytes')
    print('- no private key/vault/Authority artifacts detected')
    print('- no common credential-token signatures detected')
    print('- no user-specific Jerry/email paths detected')
    print('- no forbidden assistant/provider branding detected')
    print('- required GPL/public repository documents are present')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
