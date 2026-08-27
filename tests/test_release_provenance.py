from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import arenyxa.provenance as provenance_module
from arenyxa import __version__
from arenyxa.provenance import ProvenanceState, verify_release_attestation


def _canonical(value: dict[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path, str, str]:
    install = tmp_path / "install"
    repair = install / "repair"
    repair.mkdir(parents=True)
    app_file = install / "Arenyxa.exe"
    app_file.write_bytes(b"known-good")
    file_hash = hashlib.sha256(app_file.read_bytes()).hexdigest()
    recovery_payload = repair / "recovery_payload.zip"
    recovery_payload.write_bytes(b"")
    manifest = {
        "schema_version": 2,
        "product": "Arenyxa",
        "files": {"Arenyxa.exe": {"sha256": file_hash, "size": app_file.stat().st_size}},
        "critical_files": ["Arenyxa.exe"],
        "recovery_payload": {
            "name": "recovery_payload.zip",
            "sha256": hashlib.sha256(recovery_payload.read_bytes()).hexdigest(),
            "size": recovery_payload.stat().st_size,
        },
    }
    manifest_path = repair / "install_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    private = Ed25519PrivateKey.generate()
    public_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = hashlib.sha256(public_raw).hexdigest()[:20]
    signed: dict[str, object] = {
        "schema_version": 1,
        "product": "Arenyxa",
        "version": __version__,
        "channel": "official",
        "build_id": "test-build",
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "key_id": key_id,
        "license": "GPL-3.0-or-later",
    }
    attestation = {
        "signed": signed,
        "signature_algorithm": "Ed25519",
        "signature": base64.b64encode(private.sign(_canonical(signed))).decode("ascii"),
    }
    attestation_path = repair / "release_attestation.json"
    attestation_path.write_text(json.dumps(attestation, ensure_ascii=False, indent=2), encoding="utf-8")
    trust_store = tmp_path / "trust.json"
    trust_store.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "product": "Arenyxa",
                "keys": {
                    key_id: {
                        "public_key": base64.b64encode(public_raw).decode("ascii"),
                        "role": "official",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return install, attestation_path, manifest_path, trust_store, key_id, base64.b64encode(public_raw).decode("ascii")


def test_verified_official_release(tmp_path: Path, monkeypatch) -> None:
    install, attestation, manifest, trust, key_id, public_key = _fixture(tmp_path)
    monkeypatch.setattr(provenance_module, "OFFICIAL_RELEASE_KEYS", {key_id: {"public_key": public_key, "role": "official", "status": "active"}})
    report = verify_release_attestation(
        install,
        attestation_path=attestation,
        manifest_path=manifest,
        trust_store_path=trust,
        deep_files=True,
    )
    assert report.state == ProvenanceState.VERIFIED_OFFICIAL
    assert report.signature_valid is True
    assert report.trusted_signer is True


def test_manifest_replacement_breaks_attestation(tmp_path: Path) -> None:
    install, attestation, manifest, trust, _key_id, _public_key = _fixture(tmp_path)
    parsed = json.loads(manifest.read_text(encoding="utf-8"))
    parsed["files"] = {}
    manifest.write_text(json.dumps(parsed), encoding="utf-8")
    report = verify_release_attestation(
        install, attestation_path=attestation, manifest_path=manifest, trust_store_path=trust
    )
    assert report.state == ProvenanceState.MODIFIED


def test_program_file_modification_is_detected(tmp_path: Path) -> None:
    install, attestation, manifest, trust, _key_id, _public_key = _fixture(tmp_path)
    (install / "Arenyxa.exe").write_bytes(b"tampered")
    report = verify_release_attestation(
        install,
        attestation_path=attestation,
        manifest_path=manifest,
        trust_store_path=trust,
        deep_files=True,
    )
    assert report.state == ProvenanceState.MODIFIED
    assert "Arenyxa.exe" in report.modified_files


def test_self_declared_signer_is_not_trusted(tmp_path: Path) -> None:
    install, attestation, manifest, _trust, _key_id, _public_key = _fixture(tmp_path)
    empty_trust = tmp_path / "empty.json"
    empty_trust.write_text('{"keys": {}}', encoding="utf-8")
    report = verify_release_attestation(
        install, attestation_path=attestation, manifest_path=manifest, trust_store_path=empty_trust
    )
    assert report.state == ProvenanceState.UNVERIFIED
    assert report.trusted_signer is False


def test_external_trust_store_cannot_mint_official_identity(tmp_path: Path) -> None:
    install, attestation, manifest, trust, _key_id, _public_key = _fixture(tmp_path)
    report = verify_release_attestation(
        install, attestation_path=attestation, manifest_path=manifest, trust_store_path=trust
    )
    assert report.state == ProvenanceState.INVALID
    assert any("official key embedded" in note for note in report.notes)


def _mutate_signed_attestation(attestation: Path, **updates: object) -> None:
    parsed = json.loads(attestation.read_text(encoding="utf-8"))
    parsed["signed"].update(updates)
                                                                                         
                                                                                       
    attestation.write_text(json.dumps(parsed), encoding="utf-8")


def test_attestation_rejects_unknown_schema(tmp_path: Path) -> None:
    install, attestation, manifest, trust, _key_id, _public_key = _fixture(tmp_path)
    _mutate_signed_attestation(attestation, schema_version=99)
    report = verify_release_attestation(install, attestation_path=attestation, manifest_path=manifest, trust_store_path=trust)
    assert report.state == ProvenanceState.INVALID


def test_attestation_rejects_wrong_license_identifier(tmp_path: Path) -> None:
    install, attestation, manifest, trust, _key_id, _public_key = _fixture(tmp_path)
    _mutate_signed_attestation(attestation, license="Proprietary")
    report = verify_release_attestation(install, attestation_path=attestation, manifest_path=manifest, trust_store_path=trust)
    assert report.state == ProvenanceState.INVALID


def test_attestation_rejects_unknown_channel(tmp_path: Path) -> None:
    install, attestation, manifest, trust, _key_id, _public_key = _fixture(tmp_path)
    _mutate_signed_attestation(attestation, channel="pirated-official")
    report = verify_release_attestation(install, attestation_path=attestation, manifest_path=manifest, trust_store_path=trust)
    assert report.state == ProvenanceState.INVALID


def test_attestation_rejects_empty_build_id(tmp_path: Path) -> None:
    install, attestation, manifest, trust, _key_id, _public_key = _fixture(tmp_path)
    _mutate_signed_attestation(attestation, build_id="")
    report = verify_release_attestation(install, attestation_path=attestation, manifest_path=manifest, trust_store_path=trust)
    assert report.state == ProvenanceState.INVALID


def test_unexpected_loadable_file_is_detected(tmp_path: Path, monkeypatch) -> None:
    install, attestation, manifest, trust, key_id, public_key = _fixture(tmp_path)
    monkeypatch.setattr(
        provenance_module,
        "OFFICIAL_RELEASE_KEYS",
        {key_id: {"public_key": public_key, "role": "official", "status": "active"}},
    )
    (install / "injected.dll").write_bytes(b"not-in-signed-manifest")
    report = verify_release_attestation(
        install,
        attestation_path=attestation,
        manifest_path=manifest,
        trust_store_path=trust,
        deep_files=True,
    )
    assert report.state == ProvenanceState.MODIFIED
    assert "injected.dll" in report.unexpected_files
