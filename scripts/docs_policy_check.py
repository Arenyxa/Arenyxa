#!/usr/bin/env python3
"""Warning-only documentation layout policy; use --strict when backlog is closed."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import unquote, urlsplit
import re

ROOT = Path(__file__).resolve().parents[1]
ALLOW = {"README.md", "SECURITY.md", "VERSIONING.md", "CHANGELOG.md"}
REQUIRED = ("status:", "owner:", "last_reviewed:")
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+[^)]*)?\)")


def is_archived(path: Path) -> bool:
    parts = tuple(item.casefold() for item in path.relative_to(ROOT).parts)
    return any(parts[i:i + 2] == ("internal", "history") for i in range(len(parts) - 1))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true", help="fail on any documentation-policy warning")
    args = parser.parse_args()
    warnings: list[str] = []

    extras = sorted(path.name for path in ROOT.glob("*.md") if path.name not in ALLOW)
    if extras:
        warnings.append("root Markdown files outside allowlist: " + ", ".join(extras))

    missing: list[str] = []
    malformed: list[str] = []
    for path in sorted(item for item in (ROOT / "docs").rglob("*.md") if not is_archived(item)):
        rel = path.relative_to(ROOT).as_posix()
        body = path.read_text(encoding="utf-8")
        if not body.startswith("---\n"):
            missing.append(rel)
            continue
        end = body.find("\n---", 4)
        header = body[4:end] if end >= 0 else ""
        if end < 0 or any(field not in header for field in REQUIRED):
            malformed.append(rel)
    if missing:
        warnings.append(f"{len(missing)} active Markdown file(s) lack required front matter; sample: {', '.join(missing[:12])}")
    if malformed:
        warnings.append("Markdown front matter missing required fields: " + ", ".join(malformed[:12]))

    # Relative Markdown links are checked locally without making network calls.
    link_pattern = MARKDOWN_LINK
    broken_links: list[str] = []
    markdown_files = sorted(
        path for path in list(ROOT.glob("*.md")) + list((ROOT / "docs").rglob("*.md"))
        if not is_archived(path)
    )
    for source in markdown_files:
        text = source.read_text(encoding="utf-8")
        for match in link_pattern.finditer(text):
            raw_target = match.group(1).strip("<>")
            parsed = urlsplit(raw_target)
            if parsed.scheme or parsed.netloc or raw_target.startswith("#"):
                continue
            relative_target = unquote(parsed.path)
            target_path = (ROOT / relative_target.lstrip("/")) if relative_target.startswith("/") else (source.parent / relative_target if relative_target else source)
            if target_path.exists():
                continue
            if not target_path.suffix and (target_path / "README.md").is_file():
                continue
            line_number = text.count("\n", 0, match.start()) + 1
            broken_links.append(f"{source.relative_to(ROOT).as_posix()}:{line_number} -> {relative_target or raw_target}")
    if broken_links:
        warnings.append(f"{len(broken_links)} broken local Markdown link(s); sample: " + ", ".join(broken_links[:12]))

    identity_path = ROOT / "metadata" / "release-identity.json"
    schema_path = ROOT / "metadata" / "schemas" / "release-identity.schema.json"
    try:
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        required = schema.get("required", [])
        missing_identity = sorted(key for key in required if key not in identity)
        if missing_identity:
            warnings.append("release identity missing schema-required fields: " + ", ".join(missing_identity))
        if identity.get("schema") != schema.get("properties", {}).get("schema", {}).get("const"):
            warnings.append("release identity schema identifier does not match its schema")
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(identity.get("package_version", ""))):
            warnings.append("release identity package_version has invalid format")
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", str(identity.get("windows_file_version", ""))):
            warnings.append("release identity windows_file_version has invalid format")
    except (OSError, json.JSONDecodeError) as exc:
        warnings.append(f"release identity/schema cannot be parsed: {exc}")

    if warnings:
        print("Documentation policy: WARNING (non-blocking)")
        for item in warnings:
            print("- " + item)
    else:
        print("Documentation policy: PASS")
    return 1 if args.strict and warnings else 0


if __name__ == "__main__":
    raise SystemExit(main())
