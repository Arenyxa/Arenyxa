# Arenyxa V8.2 I18N System Report

## Implementation

The existing runtime translation dictionaries and `LanguageManager` remain compatible with legacy pages. Packaged JSON catalogs in `src/arenyxa/locale/` continue to merge over compatibility dictionaries at startup.

Catalog-backed semantic UI keys are now supported directly by `LanguageManager`. Shared `PageHeader` and `SectionCard` widgets can bind semantic translation keys, and combo-box items can bind per-item keys. This allows locale changes to re-render from stable catalog identifiers rather than depending on Chinese/English literal phrase matching.

Packaged catalogs currently include:

- `zh_CN.json`
- `en_US.json`
- `ja_JP.json`
- `fr_FR.json`
- `de_DE.json`

The language picker continues to expose the compatibility locales in addition to the packaged catalogs.

## Migrated surfaces

The following high-visibility surfaces no longer embed Chinese user-facing copy directly in their page source:

- Welcome Center / work-mode selection
- Personalization / visual presets / motion / interface scaling

Their user-facing copy is now sourced from semantic catalog keys under the `welcome.*` and `personalization.*` namespaces.

## Regression protection

`tests/test_i18n_semantic_keys.py` enforces:

- no CJK UI literals are reintroduced in the migrated page source files;
- every referenced semantic key exists in each packaged locale catalog;
- semantic widget keys re-render correctly when the active locale changes.

## Remaining migration work

Legacy pages still contain compatibility phrase mappings and hard-coded UI text that are translated through the existing `translate_tree` compatibility path. Migration should continue incrementally by page and should not internationalize machine identifiers, database keys, protocol/event codes, permission identifiers, or persisted enum values.
