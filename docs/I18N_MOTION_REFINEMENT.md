# Arenyxa V6.0 — I18N & Professional Motion Refinement

This refinement is based on `Arenyxa_V6.0_I18N_Motion_Repair_Center.zip` and preserves the agreed Dashboard, six visual presets, Repair Center, capture/network stack, terminal, database, plugins, and other business modules.

## Internationalization

- `Follow system` remains the default for new settings and resolves the supported OS locale at startup.
- Supported locales: Simplified Chinese, Traditional Chinese, English, French, Russian, German, Japanese, Korean, Arabic, and Latin.
- Replaced the old 700 ms whole-window localization polling loop with event-driven localization through the Qt application event filter. Newly shown widgets and dynamically added child widgets are localized immediately without repeatedly rescanning the full window.
- Extended the native phrase catalogue for navigation, Dashboard, task/search/data workflows, capture/network tools, settings, logs, terminal, visualization, and common diagnostics.
- Legacy Simplified-Chinese presentation literals are resolved through a stable English semantic intermediate before native localization. Unknown specialist text safely falls back to English instead of leaking mixed Chinese into non-Chinese sessions.
- Runtime language changes preserve existing pages and business state rather than rebuilding views.
- Added localization support for labels, buttons, group boxes, placeholders, tooltips, tabs, combo-box items, table headers, read-only helper text, dialog/window titles, and custom-painted labels.
- Arabic switches the application to RTL while technical content (URL, JSON, SQL, code, paths, IDs, hashes, HTTP text, diagnostic consoles) stays explicitly LTR.
- Traditional Chinese conversion remains separate from the non-Chinese semantic translation path.
- Dynamic user/business content is protected from stale localization overwrite.

### Static i18n audit

A source-level audit of presentation code (excluding the independently localized Repair Center dialog and the language catalog itself) found 287 legacy CJK string literals. The semantic resolver produced an English intermediate with **0 residual CJK literals** for those 287 strings. This does not replace a native-speaker linguistic review, but it eliminates the earlier large-scale mixed-Chinese UI failure mode.

## Professional motion system

The motion language is intentionally restrained and tool-oriented. No screen-edge marquee animation and no power-button-style reveal are used.

- Retuned the spring response/damping for less bounce and faster visual settling.
- Page transitions use a subtle interruptible spring fade plus a small vertical lift instead of a theatrical slide.
- Command Palette uses the same semantic expand/reveal language.
- Buttons receive short opacity micro-feedback on hover/press/release without changing layout geometry.
- The navigation rail and Context Inspector now use short non-overshooting width transitions; they preserve the existing layout and release temporary fixed-width constraints after the animation.
- Dashboard KPI values interpolate continuously and re-target from their current displayed value when data changes mid-animation.
- Progress bars and the circular capture gauge interpolate from their current visual state rather than restarting.
- KPI sparklines smoothly morph from the previous series into the new series.
- Capture trend charts now continuously morph between datasets; they no longer replay a left-to-right drawing animation on every refresh.
- File-type donut data smoothly morphs between distributions.
- Domain and content-size bars use short restrained progress motion when the Dashboard is rebuilt.
- Success/warning/error state changes use short semantic color emphasis rather than decorative glow effects.
- Glass pointer specular response eases in/out and now responds to actual material strength, blur-strength, high-contrast, Reduce Motion, and adaptive quality settings.
- Removed the inactive Edge Flow renderer from the presentation layer; the legacy configuration field remains `false` only for backward-compatible settings migration.

## Adaptive performance

- `FrameSampler` feeds real Qt event-loop timing into `FrameProfiler`.
- User-selected motion quality and automatically detected performance quality are now combined conservatively; automatic adaptation can lower quality but never silently exceed the user-selected level.
- Adaptive quality uses hysteresis: degradation happens quickly under sustained frame pressure, while recovery requires a longer stable window. This prevents high/balanced/efficiency oscillation.
- Large suspend/debugger gaps are ignored by the sampler.
- `Reduce Motion` bypasses enhanced transitions and live-data interpolation.
- `Live Data Motion` now has real consumers in Dashboard values, progress, sparklines, trends, and donut visualization.

## Validation performed in this build environment

- Python `compileall`: PASS
- AST parse of all Python files under `src`, `tests`, and `scripts`: PASS
- Static i18n semantic-resolution audit: 287 legacy CJK literals -> 0 residual CJK in the English intermediate
- No active Edge Flow renderer/call path remains in `src/arenyxa/presentation`
- Repair Center source recovery seed and SHA-256 manifest are regenerated after these changes
- Repair Center unit tests are re-run after regenerating the recovery seed

PySide6 is not installed in this build container, so a real Qt runtime/visual smoke test cannot be executed here. The final visual acceptance should therefore still be performed on the target Windows machine with the project dependencies installed.
