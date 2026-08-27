from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.atomic_io import read_text_limited

_MAX_TRUST_STORE_BYTES = 512 * 1024
_MAX_SIGNATURE_BYTES = 512 * 1024
_MAX_SIGNED_FILES = 4096
_MAX_FILE_BYTES = 64 * 1024 * 1024
_SIGNATURE_FILE = "plugin.sig.json"


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64decode(value: str) -> bytes:
    text = str(value).strip()
    padding = "=" * ((4 - len(text) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding)
    except (ValueError, TypeError) as exc:
        raise ArenyxaError("PLUGIN_SIGNATURE_INVALID", "Plugin signature encoding is invalid", domain="PLUGIN") from exc


def _safe_relative(root: Path, relative: str) -> Path:
    if not relative or "\\" in relative:
        raise ArenyxaError("PLUGIN_SIGNATURE_INVALID", "Plugin signed path is invalid", domain="PLUGIN")
    candidate = (root / relative).resolve()
    resolved_root = root.resolve()
    if candidate == resolved_root or resolved_root not in candidate.parents:
        raise ArenyxaError("PLUGIN_SIGNATURE_INVALID", "Plugin signed path escapes plugin root", domain="PLUGIN")
    return candidate


def build_plugin_inventory(plugin_root: Path) -> dict[str, str]:
    root = Path(plugin_root).resolve()
    rows: dict[str, str] = {}
    files = sorted(path for path in root.rglob("*") if path.is_file() and path.name != _SIGNATURE_FILE)
    if len(files) > _MAX_SIGNED_FILES:
        raise ArenyxaError("PLUGIN_SIGNATURE_BUDGET_EXCEEDED", "Plugin contains too many signed files", domain="PLUGIN")
    for path in files:
        if path.is_symlink():
            raise ArenyxaError("PLUGIN_SIGNATURE_INVALID", "Plugin signed inventory cannot contain symlinks", domain="PLUGIN")
        size = path.stat().st_size
        if size > _MAX_FILE_BYTES:
            raise ArenyxaError("PLUGIN_SIGNATURE_BUDGET_EXCEEDED", "Plugin file exceeds signature budget", domain="PLUGIN")
        relative = path.relative_to(root).as_posix()
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        rows[relative] = digest.hexdigest()
    return rows


def verify_plugin_signature(plugin_root: Path, trust_store_path: Path) -> dict[str, Any]:
    root = Path(plugin_root).resolve()
    signature_path = root / _SIGNATURE_FILE
    if not signature_path.is_file():
        raise ArenyxaError("PLUGIN_SIGNATURE_REQUIRED", "Plugin signature file is missing", domain="PLUGIN")
    try:
        signature_doc = json.loads(read_text_limited(signature_path, _MAX_SIGNATURE_BYTES, encoding="utf-8"))
        trust_doc = json.loads(read_text_limited(Path(trust_store_path), _MAX_TRUST_STORE_BYTES, encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ArenyxaError("PLUGIN_SIGNATURE_INVALID", "Plugin signature or trust store cannot be parsed", domain="PLUGIN") from exc
    if not isinstance(signature_doc, dict) or not isinstance(trust_doc, dict):
        raise ArenyxaError("PLUGIN_SIGNATURE_INVALID", "Plugin signature/trust store must be JSON objects", domain="PLUGIN")
    if signature_doc.get("schema") != "arenyxa.plugin-signature/v1" or signature_doc.get("algorithm") != "Ed25519":
        raise ArenyxaError("PLUGIN_SIGNATURE_UNSUPPORTED", "Plugin signature schema or algorithm is unsupported", domain="PLUGIN")
    key_id = str(signature_doc.get("key_id", "")).strip()
    signed = signature_doc.get("signed")
    if not key_id or not isinstance(signed, dict):
        raise ArenyxaError("PLUGIN_SIGNATURE_INVALID", "Plugin signature metadata is incomplete", domain="PLUGIN")
    keys = trust_doc.get("keys", {})
    if not isinstance(keys, dict) or key_id not in keys:
        raise ArenyxaError("PLUGIN_SIGNER_UNTRUSTED", "Plugin signer is not trusted", domain="PLUGIN")
    key_value = keys[key_id]
    if isinstance(key_value, dict):
        key_value = key_value.get("public_key", "")
    public_raw = _b64decode(str(key_value))
    if len(public_raw) != 32:
        raise ArenyxaError("PLUGIN_SIGNER_INVALID", "Plugin signer public key is invalid", domain="PLUGIN")
    inventory = signed.get("files")
    if not isinstance(inventory, dict) or len(inventory) > _MAX_SIGNED_FILES:
        raise ArenyxaError("PLUGIN_SIGNATURE_INVALID", "Plugin signed inventory is invalid", domain="PLUGIN")
    normalized: dict[str, str] = {}
    for relative, digest in inventory.items():
        relative_text = str(relative)
        path = _safe_relative(root, relative_text)
        if not path.is_file() or path.is_symlink():
            raise ArenyxaError("PLUGIN_SIGNATURE_MISMATCH", f"Signed plugin file is missing: {relative_text}", domain="PLUGIN")
        digest_text = str(digest).casefold()
        if len(digest_text) != 64 or any(ch not in "0123456789abcdef" for ch in digest_text):
            raise ArenyxaError("PLUGIN_SIGNATURE_INVALID", "Plugin inventory digest is invalid", domain="PLUGIN")
        normalized[relative_text] = digest_text
    actual = build_plugin_inventory(root)
    if actual != normalized:
        raise ArenyxaError("PLUGIN_SIGNATURE_MISMATCH", "Plugin signed inventory does not match installed files", domain="PLUGIN")
    signature = _b64decode(str(signature_doc.get("signature", "")))
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, _canonical(signed))
    except (InvalidSignature, ValueError) as exc:
        raise ArenyxaError("PLUGIN_SIGNATURE_INVALID", "Plugin signature verification failed", domain="PLUGIN") from exc
    manifest = signed.get("manifest")
    if not isinstance(manifest, dict):
        raise ArenyxaError("PLUGIN_SIGNATURE_INVALID", "Signed plugin manifest is missing", domain="PLUGIN")
    actual_manifest = json.loads(read_text_limited(root / "plugin.json", 1024 * 1024, encoding="utf-8"))
    if actual_manifest != manifest:
        raise ArenyxaError("PLUGIN_SIGNATURE_MISMATCH", "Signed plugin manifest does not match plugin.json", domain="PLUGIN")
    return {
        "verified": True,
        "schema": "arenyxa.plugin-signature/v1",
        "algorithm": "Ed25519",
        "key_id": key_id,
        "files": len(actual),
    }
