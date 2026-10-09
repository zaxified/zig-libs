# `ini` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-09** — tests: deterministic fuzz driver `INI_FUZZ` over the existing harnesses.
- **2026-10-03** — Audit: review and a 77-mutant run (all killed; 17 survived the first pass).
  Seven tests added for the gaps (locale-key rule, inline comments after a tab and without
  `trim_values`, `unquote` and `unescapeDesktop` escapes, `getBool` words, `case_insensitive_keys`,
  allocation failure at every point of a parse). No behaviour change.
- **2026-09-28** — New module: an INI reader (sections, `key = value`, comments, line numbers,
  strict and lenient modes) with a Python `configparser` and a Desktop Entry preset, requested by
  ttydesk for Midnight Commander skins. Verified against CPython 3.14 `configparser` and GLib
  2.88 `GKeyFile` on 905 texts (`tools/gen_goldens.py`), all in agreement.
