# `ini` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-02** — **Fixed, from an independent review; none of it shipped before:** `Editor.setComment` kept a slice of the caller's text when a line already had its marker (use after free). `Document.write(.merged)` wrote `[DEFAULT]` before the headerless entries, which then read back as its keys; and dropped the document's `[DEFAULT]` when the target options named none. A failed edit now changes nothing under `error.OutOfMemory` too (`set`, `setNoValue`, `addSection`, `setComment` prepare and reserve, then commit). A line skipped for continuing a bare key is no longer absorbed: `set` on that key is `error.NotRepresentable`, `remove` takes the line along. `setNoValue` keeps the line's own ending; on a bare key it is a no-op. `WriteOptions.eol` other than `\n`, `\r\n` is refused. `Node.indent` widened (a `u32` `@intCast` over 4 GiB of blanks). `Event.invalid` gains `continues_bare_key`, with a default. Docs: edits are amortized O(1), `StreamScanner`'s limit includes the newline, `escapeDesktop` and trailing blanks. Backlog names rust-ini as not measured.

- **2026-11-02** — Docs: mark an inferred claim about the `write` row as inferred; say how far the foreign sources were read.

- **2026-11-02** — Card: survey redone (`parity`, reference go-ini, fastest measured the Rust `configparser` crate), `zig build bench-ini` with go-ini, `configparser`, `ini_core` and inih (`tools/go_bench`, `tools/rust_bench`, `tools/c_bench.c`), SPEC and README updated, stale claims removed. `parseList` follows go-ini's `Strings` by default (empty elements kept, `\\` an escape).

- **2026-11-02** — **Added, all opt-in; every existing `Document` user keeps compiling and `parse`'s error set is unchanged:** `Editor` (edit a file and write it back, untouched lines byte for byte, an edit either reads back as asked or is `error.NotRepresentable`), `Document.write`, `Scanner` and `StreamScanner` (allocation-free pull readers), `getInt`, `getFloat`, `getList`, `getLocale`, `getInherited`, `mapSection`, `merged`, `sectionNames`, `firstDuplicate`, `interpolated` (`%(name)s`, `${section:key}`, with depth, size and step limits), `Options.default_section` / `empty_lines_in_values` / `no_value_keys`, `Options.configparser`, `quote`, `escapeDesktop`. Anchored by `tools/gen_goldens_ext.py` (goldens from configparser and GKeyFile) and `tools/writer_oracle.py` (they read back what we wrote); new fuzz harness `ini-edit`. **CONSUMER-VISIBLE, only with `inline_comments = true` (no preset sets it, ttydesk does not):** the comment is now cut from the whole line before classification, as `configparser` does, so `x ; y = z` is a `MissingSeparator` and `w = ;` an empty value (audit LOW of 2026-10-03, closed). `Document.EntryIterator` is unchanged; `Entry` gains `has_value`, with a default.

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
