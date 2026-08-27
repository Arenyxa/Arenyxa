from __future__ import annotations

from pathlib import Path


def test_public_source_does_not_ship_private_hardware_root_ceremonies() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "arenyxa"
    forbidden = {
        "provision_hardware_root(": [],
        "issue_issuer_certificate(": [],
        "revoke_issuer_certificate(": [],
        "prepare_root_rotation(": [],
        "sign_root_rotation(": [],
        "create_recovery_activation(": [],
        "HardwareRootAuthority": [],
    }
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for marker in forbidden:
            if marker in text:
                forbidden[marker].append(path.relative_to(root).as_posix())
    leaked = {marker: paths for marker, paths in forbidden.items() if paths}
    assert not leaked, leaked


def test_public_source_keeps_only_generic_tpm_provider_and_verifiers() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "arenyxa"
    identity = (root / "security" / "hardware_identity.py").read_text(encoding="utf-8")
    lifecycle = (root / "security" / "hardware_root_lifecycle.py").read_text(encoding="utf-8")
    assert "WindowsTPMEcdsaP256Provider" in identity
    assert "validate_root_rotation" in lifecycle
    assert "validate_root_recovery_activation" in lifecycle
    lowered = lifecycle.casefold()
    assert "private_key =" not in lowered
    assert "private_bytes(" not in lowered
    assert "ed25519privatekey" not in lowered
    assert "ec.generate_private_key" not in lowered
