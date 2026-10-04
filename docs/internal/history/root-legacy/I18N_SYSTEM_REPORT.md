# Arenyxa v8.0 beta17 I18N System Report

## Implementation

The existing runtime translation dictionaries and `LanguageManager` were preserved. A packaged `src/arenyxa/locale/` JSON catalog layer now merges over those compatibility dictionaries at startup.

Catalogs added for:

- `zh_CN.json`
- `en_US.json`
- `ja_JP.json`
- `fr_FR.json`
- `de_DE.json`

The language picker continues to expose English, 中文（简体）, 日本語, Français, Deutsch, Русский, 한국어, and العربية, plus the pre-existing compatibility locales. New Experience, Developer Center, and Enterprise Enrollment terminology is catalogued.

## Remaining migration work

beta13 contains a large body of compatibility phrase mappings and hard-coded legacy page text. beta17 does not perform a risky bulk rewrite. New identity/mode strings are catalogued, while older pages continue through the existing `translate_tree` compatibility path.
