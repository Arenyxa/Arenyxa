from __future__ import annotations

import argparse
import base64
import hashlib
import json
import importlib.util
import os
import secrets
from pathlib import Path


def canonical(value: dict[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a detached Ed25519 Arenyxa release attestation")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--channel", choices=("official", "community"), default="community")
    parser.add_argument("--version", default="8.1.1")
    parser.add_argument("--build-id", default="")
    parser.add_argument("--compiled-keys", type=Path, default=Path("src/arenyxa/release_keys.py"))
    args = parser.parse_args()

    key_path = args.private_key
    if key_path is None:
        env_path = os.getenv("ARENYXA_RELEASE_SIGNING_KEY")
        if env_path:
            key_path = Path(env_path)
    if key_path is None or not key_path.is_file():
        parser.error("A PEM Ed25519 private key is required via --private-key or ARENYXA_RELEASE_SIGNING_KEY")

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        parser.error("Release key must be an Ed25519 private key")
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = hashlib.sha256(public_raw).hexdigest()[:20]
    if args.channel == "official":
        if not args.compiled_keys.is_file():
            parser.error("Official build requires src/arenyxa/release_keys.py with the matching compiled public key")
        spec = importlib.util.spec_from_file_location("arenyxa_release_keys_build", args.compiled_keys)
        if spec is None or spec.loader is None:
            parser.error("Unable to load compiled release key module")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        compiled = getattr(module, "OFFICIAL_RELEASE_KEYS", {})
        metadata = compiled.get(key_id) if isinstance(compiled, dict) else None
        expected_public = base64.b64encode(public_raw).decode("ascii")
        if not isinstance(metadata, dict) or metadata.get("public_key") != expected_public:
            parser.error(
                "Official signing key is not embedded in src/arenyxa/release_keys.py. "
                "Generate/provision the public trust anchor before building the binary."
            )
    manifest_hash = hashlib.sha256(args.manifest.read_bytes()).hexdigest()
    signed: dict[str, object] = {
        "schema_version": 1,
        "product": "Arenyxa",
        "version": args.version,
        "channel": args.channel,
        "build_id": args.build_id or secrets.token_hex(8),
        "manifest_sha256": manifest_hash,
        "key_id": key_id,
        "license": "GPL-3.0-or-later",
    }
    signature = private_key.sign(canonical(signed))
    output = {
        "signed": signed,
        "signature_algorithm": "Ed25519",
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Release attestation: {args.output}")
    print(f"Signer key id: {key_id}")
    print("Ensure the matching public key is embedded in src/arenyxa/release_keys.py before building the official binary.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
