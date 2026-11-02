# `ini` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-02** — **Added, all opt-in; every existing `Document` user keeps compiling and `parse`'s error set is unchanged:** `Editor` (edit a file and write it back, untouched lines byte for byte, an edit either reads back as asked or is `error.NotRepresentable`), `Document.write`, `Scanner` and `StreamScanner` (allocation-free pull readers), `getInt`, `getFloat`, `getList`, `getLocale`, `getInherited`, `mapSection`, `merged`, `sectionNames`, `firstDuplicate`, `interpolated` (`%(name)s`, `${section:key}`, with depth, size and step limits), `Options.default_section` / `empty_lines_in_values` / `no_value_keys`, `Options.configparser`, `quote`, `escapeDesktop`. Anchored by `tools/gen_goldens_ext.py` (goldens from configparser and GKeyFile) and `tools/writer_oracle.py` (they read back what we wrote); new fuzz harness `ini-edit`. **BEHAVIOURAL, only with `inline_comments = true` (no preset sets it, ttydesk does not):** the comment is now cut from the whole line before classification, as `configparser` does, so `x ; y = z` is a `MissingSeparator` and `w = ;` an empty value (audit LOW of 2026-10-03, closed). `Document.EntryIterator` is unchanged; `Entry` gains `has_value`, with a default.

- **2026-10-31** — **Tests:** delta mutation audit of the § GY no-panic sweep (schemata over the sweep diff; new `(sweep audit GY-…)` tests). No code change.

- **2026-10-31** — **BEHAVIOURAL, not breaking for callers of `parse`/`entries()`:** no-panic sweep + blind review (§ GY). `Document.get`/`hasSection`/`entries` were a linear scan per call (a hostile 1 MiB file: 2000 lookups took ~6 s). They now use a flat hash index built by `parse` (seeded per document, peak memory 1.007× the old). `Document.EntryIterator` changed its fields (`section` → `sections`), so code that builds the struct literally must change. Same lookup semantics.

- **2026-10-09** — tests: deterministic fuzz driver `INI_FUZZ` over the existing harnesses.
- **2026-10-03** — Audit: review and a 77-mutant run (all killed; 17 survived the first pass).
  Seven tests added for the gaps (locale-key rule, inline comments after a tab and without
  `trim_values`, `unquote` and `unescapeDesktop` escapes, `getBool` words, `case_insensitive_keys`,
  allocation failure at every point of a parse). No behaviour change.
- **2026-09-28** — New module: an INI reader (sections, `key = value`, comments, line numbers,
  strict and lenient modes) with a Python `configparser` and a Desktop Entry preset, requested by
  ttydesk for Midnight Commander skins. Verified against CPython 3.14 `configparser` and GLib
  2.88 `GKeyFile` on 905 texts (`tools/gen_goldens.py`), all in agreement.
