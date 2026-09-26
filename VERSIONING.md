# Arenyxa Versioning Policy

Arenyxa uses separate **public release**, **internal engineering**, and **compatibility** version identities. They must not be treated as interchangeable.

## Public release version

The GitHub release line starts at **v0.1**.

| Surface | Current value |
|---|---|
| GitHub/public display version | `v0.1` |
| Python package / PEP 440 version | `0.1.0` |
| Windows product version | `0.1.0` |
| Windows file version | `0.1.0.0` |
| Installer label | `Arenyxa_v0.1_...` |

Only public versions are used for GitHub releases, user-facing product version labels, installer names, package metadata, release attestations, and current release documentation.

## Internal engineering versions

The repository contains historical labels such as `v6.x`, `v7.x`, `v8.0`, `v8.1`, and `v8.2`.

These labels are **internal engineering milestones** used while the architecture, compatibility boundaries, performance gates, security model, UI, packaging, and enterprise runtime were being developed. They are retained because they are useful provenance for tests, audit reports, migration records, and design history.

They are **not prior GitHub public releases** and must not be published as GitHub release tags or advertised as public product versions.

The current internal engineering baseline is **v8.2.0**.

Historical files may preserve wording such as "stable", "official", or "public" because those documents record the terminology used inside the engineering process at the time. In the current repository versioning model, those terms describe an internal promotion state unless the version is on the public `v0.x` release line.

## Compatibility identities

Compatibility versions are independent from the public product version.

- Runtime/plugin compatibility identity: `6.8.0`
- Enterprise protocol: current `2`, minimum `1`
- Workflow schema: `arenyxa.workflow/v1`
- Settings/schema migration numbers retain their existing values

These values must not be reset to `0.1`. Changing them can affect plugin loading, persisted data, migrations, workers, or protocol negotiation.

## Source constants

The modern and legacy runtimes expose both namespaces:

```python
__version__ = "0.1"
__package_version__ = "0.1.0"
__display_version__ = "0.1"
__distribution_version__ = "0.1.0"

__engineering_build__ = "v8.2.0"
__internal_version__ = "8.2.0"
__compat_version__ = "6.8.0"
```

## Release rule

A future GitHub release increments the public release line independently of the engineering baseline. Internal engineering milestone names may continue to be used in development evidence, but they must remain explicitly marked as internal and must not replace the public release identity.
