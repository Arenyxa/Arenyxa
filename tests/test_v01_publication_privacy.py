from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _gate():
    path = ROOT / "scripts" / "github_publication_gate.py"
    spec = importlib.util.spec_from_file_location("publication_privacy_gate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _personal_matches(value):
    return [label for label, pattern in _gate().PERSONAL_OR_PRIVATE_PATTERNS if pattern.search(value)]


@pytest.mark.parametrize("separator", [chr(92), chr(92) * 2, "/"])
@pytest.mark.parametrize("account", ["publication-fixture", "Build Fixture", "fixture.user-42"])
def test_any_concrete_local_profile_is_reviewed(separator, account):
    value = "D:" + separator + separator.join(("Users", account, "workspace"))
    assert _personal_matches(value)


@pytest.mark.parametrize("account", ["<username>", "{username}", "%USERNAME%", "${USERNAME}"])
def test_explicit_profile_placeholders_are_not_personal_paths(account):
    value = f"C:/Users/{account}/workspace"
    assert not _personal_matches(value)


@pytest.mark.parametrize("domain", [
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "yahoo.co.uk", "icloud.com", "me.com", "protonmail.com",
    "proton.me", "qq.com", "163.com", "126.com",
])
@pytest.mark.parametrize("escaped_dots", [False, True])
def test_consumer_mailbox_is_reviewed_without_an_owner_specific_literal(domain, escaped_dots):
    # Every address is synthetic; no real person's mailbox is used as a fixture.
    value = f"publication.fixture@{domain}"
    if escaped_dots:
        value = value.replace(".", chr(92) + ".")
    assert _personal_matches(value)


@pytest.mark.parametrize("domain", ["example.test", "fsf.org", "gmail.com.example.test"])
def test_non_consumer_contact_is_left_for_contextual_review(domain):
    assert not _personal_matches(f"publication.fixture@{domain}")


def test_gate_source_does_not_match_its_own_publication_rules():
    source = (ROOT / "scripts" / "github_publication_gate.py").read_text(encoding="utf-8")
    gate = _gate()
    assert not [label for label, pattern in gate.SECRET_PATTERNS if pattern.search(source)]
    assert not _personal_matches(source)


def test_publication_rejects_synthetic_mailbox_without_echoing_it(tmp_path, monkeypatch, capsys):
    gate = _gate()
    for name in gate.REQUIRED_FILES:
        (tmp_path / name).write_text(
            "* text=auto eol=lf" if name == ".gitattributes" else "public source", encoding="utf-8"
        )
    domain = "gmail.com"
    mailbox = f"publication.fixture@{domain}"
    (tmp_path / "notes.txt").write_text(mailbox, encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["gate", "--root", str(tmp_path)])
    assert gate.main() == 1
    output = capsys.readouterr().out
    assert "notes.txt" in output
    assert mailbox not in output
