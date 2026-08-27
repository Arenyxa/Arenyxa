from __future__ import annotations
import os, sys

BLOCKED = {
    'ARENYXA_SKIP_QUALITY_GATE',
    'SKIP_STATIC_CHECKS',
    'DISABLE_MYPY_GATE',
}

def main() -> int:
    bad = [x for x in BLOCKED if os.environ.get(x)]
    if bad:
        print('Strict quality gate blocked bypass variables:', ', '.join(bad))
        return 1
    print('Strict quality gate: environment bypass protection OK')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
