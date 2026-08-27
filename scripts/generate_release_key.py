from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an offline Ed25519 Arenyxa release signing key")
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--trust-store", type=Path, required=True)
    parser.add_argument("--compiled-keys", type=Path, default=Path("src/arenyxa/release_keys.py"))
    parser.add_argument("--label", default="Arenyxa official release key")
    args = parser.parse_args()

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if args.private_key.exists():
        parser.error("Refusing to overwrite an existing private key")
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    args.private_key.parent.mkdir(parents=True, exist_ok=True)
                                                                                            
                                                                                               
                                                                                         
    fd = os.open(str(args.private_key), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(private_bytes)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("release private-key write made no progress")
            view = view[written:]
        os.fsync(fd)
    except Exception:
        try:
            os.close(fd)
        finally:
            fd = -1
            try:
                args.private_key.unlink(missing_ok=True)
            except OSError as cleanup_exc:
                parser.error(f"Failed to remove incomplete private key: {cleanup_exc}")
        raise
    finally:
        if fd >= 0:
            os.close(fd)

    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = hashlib.sha256(public_raw).hexdigest()[:20]
    trust_store = {"schema_version": 1, "product": "Arenyxa", "keys": {}}
    if args.trust_store.exists():
        trust_store = json.loads(args.trust_store.read_text(encoding="utf-8"))
    keys = trust_store.setdefault("keys", {})
    keys[key_id] = {
        "public_key": base64.b64encode(public_raw).decode("ascii"),
        "label": args.label,
        "role": "official",
        "status": "active",
    }
    args.trust_store.parent.mkdir(parents=True, exist_ok=True)
    args.trust_store.write_text(json.dumps(trust_store, ensure_ascii=False, indent=2), encoding="utf-8")

    official = {
        str(existing_id): {str(k): str(v) for k, v in metadata.items()}
        for existing_id, metadata in keys.items()
        if isinstance(metadata, dict)
        and str(metadata.get("role", "")).casefold() == "official"
        and str(metadata.get("status", "active")).casefold() == "active"
        and isinstance(metadata.get("public_key"), str)
    }
    args.compiled_keys.parent.mkdir(parents=True, exist_ok=True)
    args.compiled_keys.write_text(
        '"""Compiled release trust anchors. Private keys must never be committed."""\n\n'
        'from __future__ import annotations\n\n'
        + "OFFICIAL_RELEASE_KEYS: dict[str, dict[str, str]] = "
        + repr(official)
        + "\n",
        encoding="utf-8",
    )
    print(f"Private key created at: {args.private_key}")
    print(f"Trusted public key added to: {args.trust_store}")
    print(f"Compiled official key module updated: {args.compiled_keys}")
    print(f"Key id: {key_id}")
    print("Keep the private key offline and never commit/package it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
