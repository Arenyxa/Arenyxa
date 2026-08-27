# Release provenance and anti-tamper design

## Goals

Arenyxa keeps GPL freedoms and local-first operation while making official-release identity, program integrity, and repair-source provenance independently verifiable.

## Trust layers

1. `repair/install_manifest.json` records SHA-256 and size for installed files and the offline recovery payload.
2. `repair/release_attestation.json` signs the exact SHA-256 of that manifest with Ed25519.
3. Official trust anchors live in `src/arenyxa/release_keys.py` and are compiled into frozen builds. The external `resources/release_trust_store.json` may extend community/third-party trust but cannot mint official identity by itself. A key declared by the attestation itself is never trusted automatically.
4. Startup integrity checks refuse to promote an invalid signed recovery source to the user's `known_good` cache; an invalid release attestation forces recovery from previously verified known-good material rather than the current installation payload.
5. Repair plans are schema-validated, path-bound to the current installation/data repair directory, and written atomically before the independent worker starts.
6. Source/development builds remain intentionally mutable and are reported as development builds instead of being forcibly restored.

## Official release process

Generate a signing key on an offline machine:

```powershell
python scripts/generate_release_key.py --private-key D:\Secure\arenyxa-release.pem --trust-store src\arenyxa\resources\release_trust_store.json
```

Commit the updated public trust data and `src/arenyxa/release_keys.py`; the latter embeds official public-key anchors into frozen builds. Never commit the private key.

For an official build:

```powershell
$env:ARENYXA_RELEASE_CHANNEL='official'
$env:ARENYXA_RELEASE_SIGNING_KEY='D:\Secure\arenyxa-release.pem'
.\scripts\build.ps1
```

`build.ps1` refuses to label a build `official` unless a signing key is supplied, and the attestation builder also refuses an official signature unless the matching public key is already embedded in `src/arenyxa/release_keys.py`.

## Freedom-preserving behavior

- No feature is disabled solely because a build is modified or unverified.
- Source builds can be modified without self-repair fighting the developer.
- The About page exposes provenance status so users can distinguish verified-official, community, modified, unverified, and development builds.
- GPL commercial redistribution remains lawful; provenance only prevents a modified build from cryptographically inheriting official identity.

## Security limitations

No client-side anti-tamper scheme can be mathematically unbreakable when the attacker controls the machine and the full open-source program. The design raises the cost of silent modification and, more importantly, gives users a verifiable provenance signal without introducing DRM or mandatory network services.

## Source development mode

Source trees are editable by design. Normal edits do not trigger automatic anti-tamper repair. CI or release-source verification can opt into strict source hashing with:

```text
ARENYXA_ENFORCE_SOURCE_INTEGRITY=1
```

This separation prevents the self-healing feature from fighting legitimate development work.
