# linkheader — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Allocation-free both ways.** The builder writes into a caller buffer (`bufPrint`) or any
  `*std.Io.Writer` (`write`); the parser is a forward-only `Iterator` whose yielded `Link`s borrow
  the input header (string fields point into it — the header must outlive them). Reentrant, no
  shared state. Clean-room from RFC 8288 (Web Linking) — see NOTICE.
- **Modelled param set:** `rel` (required), `title`, `type`, `hreflang`. Unknown params (`media`,
  `anchor`, …) are tolerated on parse — the grammar is still honoured so they never desync the
  scanner — but not surfaced. First occurrence of each param wins (RFC 8288 §3.3/§3.4).
- **Quoting.** The builder quotes every param value and backslash-escapes `"`/`\`. The parser
  tracks those escapes while scanning (so a quoted `,`/`;`/`>` never ends a link early) but returns
  the quoted content verbatim, escapes included — it borrows and never allocates to unescape. The
  URI passes through verbatim between `<>`; percent-encoding is the caller's responsibility.
- **Error policy = skip, never panic.** A segment with no `<…>`, an unterminated `<`, or a stray
  separator advances the iterator to the next top-level comma and parsing continues; a link with no
  `rel` is dropped. `bufPrint` returns `error.NoSpaceLeft` on a short buffer.
- **Convenience:** `pagination(&[4]Link, opts)` fills present first/prev/next/last relations in
  order; `find(header, rel)` returns the first link whose `rel` matches ASCII-case-insensitively,
  including any single token of a whitespace-separated `rel` list.

## Threat model / out of scope

Not a security control, but hardened against desync: quotes, escapes, and commas/semicolons inside
the `<uri>` or inside quoted values are handled so a crafted header cannot split a link early or
run the scanner off the end; forward progress out of any malformed segment is guaranteed. It does
**not** validate or percent-decode URIs, does not unescape quoted values, does not model the full
RFC 8288 param set (`anchor`, extended `*`-encoded values, media, etc.), and does not parse the
whole `Link:` header line (it works on the header *value*).

## Verification

Build: single link, multiple joined with `", "`, all optional params in order, quote/backslash
escaping, `NoSpaceLeft` on a tiny buffer, growable writer. Parse: single and multi links with all
params, bare-token values, surrounding/inter-token whitespace, commas inside the URI and
commas+semicolons inside quoted values (no early split), unknown params without desync,
first-occurrence-wins, case-insensitive names, malformed-segments-skipped, empty/whitespace input,
unterminated `<`. A build→parse round-trip, and `find`/`pagination` coverage (incl. a rel-list
token match). Run: `zig build test-linkheader`.

## Backlog / deferred

None recorded — no deferred-gap note found in PLAN.md (only a build-history mention among the
prod-API hardening batch) and the module README has no Deferred section.

## Status

`gap · any · codec · reentrant` + deps: none (std only) — canonical source is `pub const meta` in
src/root.zig.
