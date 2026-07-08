# SPEC — `linkheader`

**Purpose** — The little codec every REST client needs for RFC 5988/8288 pagination: serialise a
`[]const Link` into a `Link:` header *value* and parse one back —
`<…?page=2>; rel="next", <…?page=1>; rel="prev"`. std has no Web-Linking codec; this fills the gap
for `http`-client consumers that follow `next`/`prev`/`first`/`last`.

**Model after / Seed** — clean-room from RFC 8288 (Web Linking — the `Link` header grammar).
Greenfield, no seed; no third-party source consulted or copied. See `NOTICE`.

**Design & invariants**
- **Allocation-free both ways.** The builder writes into a caller buffer (`bufPrint`) or any
  `*std.Io.Writer` (`write`); the parser is a forward-only `Iterator` whose yielded `Link`s **borrow
  the input header** (string fields point into it — the header must outlive them). Reentrant, no
  shared state.
- **Modelled param set:** `rel` (required), `title`, `type`, `hreflang`. On parse, unknown params
  (`media`, `anchor`, …) are tolerated — the grammar is still honoured so they never desync the
  scanner — but not surfaced. First occurrence of each param wins (RFC 8288 §3.3/§3.4).
- **Quoting.** The builder quotes every param value and backslash-escapes `"`/`\`. The parser tracks
  those escapes while scanning (so a quoted `,`/`;`/`>` never ends a link early) but returns the
  quoted content **verbatim, escapes included** — it borrows and never allocates to unescape; for
  plain-ASCII values (the overwhelming case) that is byte-identical. The URI passes through verbatim
  between `<>`; percent-encoding is the caller's responsibility.
- **Error policy = skip, never panic.** A segment with no `<…>`, an unterminated `<`, or a stray
  separator advances the iterator to the next top-level comma and parsing continues; a link with no
  `rel` is dropped (RFC 8288 requires `rel`). `bufPrint` returns `error.NoSpaceLeft` on a short buffer.
- **Convenience:** `pagination(&[4]Link, opts)` fills present first/prev/next/last relations in
  order; `find(header, rel)` returns the first link whose `rel` matches ASCII-case-insensitively,
  including any single token of a whitespace-separated `rel` list.

**Threat model / out of scope** — Not a security control, but hardened against desync: quotes,
escapes, and commas/semicolons inside the `<uri>` or inside quoted values are handled so a crafted
header cannot split a link early or run the scanner off the end; forward progress out of any
malformed segment is guaranteed. It does **not** validate or percent-decode URIs, does not unescape
quoted values, does not model the full RFC 8288 param set (`anchor`, extended `*`-encoded values,
media, etc.), and does not parse the whole `Link:` header line (it works on the header *value*).

**Verification** — Unit tests: build a single link, multiple joined with `", "`, all optional params
in order, quote/backslash escaping, `NoSpaceLeft` on a tiny buffer, growable writer. Parse: single
and multi links with all params, bare-token values, surrounding/inter-token whitespace, commas
inside the URI and commas+semicolons inside quoted values (no early split), unknown params without
desync, first-occurrence-wins, case-insensitive names, malformed-segments-skipped, empty/whitespace
input, unterminated `<`. A build→parse round-trip, and `find`/`pagination` coverage (incl. a rel-list
token match).

**Status** — `gap · any · codec · reentrant` · deps: none (std only).
