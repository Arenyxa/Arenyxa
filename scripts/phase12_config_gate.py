from __future__ import annotations

import json
from pathlib import Path

try:
    import tomllib
except ImportError:                                                                  
    tomllib = None


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    if tomllib is None:
        print("Config gate requires Python 3.11+ tomllib on the modern release lane.")
        return 2
    with (root / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)
    assert project["project"]["name"] == "arenyxa"
    assert project["project"]["version"] == "8.1.0"
    assert project["project"]["scripts"]["arenyxa"] == "arenyxa.cli:main"
    assert project["project"]["scripts"]["arenyxa-gui"] == "arenyxa.app:main"
    for relative in (
        "src/arenyxa/resources/repair_manifest.json",
        "src/arenyxa/resources/release_trust_store.json",
    ):
        payload = json.loads((root / relative).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(relative + " must contain a JSON object")
    print("Phase 12 config parse gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
