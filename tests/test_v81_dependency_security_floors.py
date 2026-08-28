from __future__ import annotations

import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _all_project_requirements() -> list[str]:
    with (ROOT / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)
    requirements = list(project["project"]["dependencies"])
    for group in project["project"]["optional-dependencies"].values():
        requirements.extend(group)
    return requirements


def test_release_security_floors_cover_known_2026_direct_dependency_fixes() -> None:
    requirements = _all_project_requirements()
    assert any(requirement.startswith("cryptography>=50,<51") for requirement in requirements)
    assert any(requirement.startswith("lxml>=6.1,<7") for requirement in requirements)


def test_source_runtime_requirement_files_keep_lxml_security_floor() -> None:
    for name in ("requirements.txt", "requirements-full.txt"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "lxml>=6.1,<7" in text
        assert "lxml>=5.3,<7" not in text
