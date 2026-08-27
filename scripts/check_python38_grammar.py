from __future__ import annotations

import ast
from pathlib import Path


def _iter_python_files(root: Path):
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" not in path.parts:
            yield path


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    source_root = project_root / "legacy" / "win7" / "src" / "arenyxa"
    if not source_root.is_dir():
        print(f"Win7 legacy Python 3.8 grammar gate: source directory not found: {source_root}")
        return 2

    checked = 0
    failures: list[tuple[Path, BaseException]] = []
    for path in _iter_python_files(source_root):
        checked += 1
        try:
            source = path.read_text(encoding="utf-8")
                                                                                  
                                                                                  
                                                                                
            ast.parse(source, filename=str(path), feature_version=(3, 8))
        except (OSError, UnicodeError, SyntaxError) as exc:
            failures.append((path, exc))

    if failures:
        print(f"Win7 legacy Python 3.8 grammar gate failed: {len(failures)} of {checked} files")
        for path, exc in failures:
            print(f"  {path}: {exc}")
        return 1

    print(f"Win7 legacy Python 3.8 grammar gate passed: {checked} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
