# cookies — spec

HTTP cookies (RFC 6265): `Cookie` request-header parser + `Set-Cookie` response-header builder.
Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
- **Allocation-free.** `parse` returns an `Iterator` whose `Cookie{name,value}` pairs **borrow the
  header**; `SetCookie.write` streams to a `*std.Io.Writer`, `bufPrint` into a caller buffer.
  Reentrant, no state.
- **Liberal parse, strict build.** Parse follows §5.4: split on `;`, OWS-trim, split each segment on
  the first `=` (valueless → empty value), strip a matching pair of surrounding DQUOTEs, skip
  empty-name segments; no charset validation on read. `find` is case-sensitive.
- **Injection guard is the point of the build side.** `SetCookie.write` validates everything first —
  name against the RFC 2616 token set, value against §4.1.1 cookie-octet, Path/Domain against a
  bare attribute-octet check (no CTL, no `;`) — so a control char or separator that could inject a
  second attribute/header is refused with `error.InvalidCookie` before any byte is written. Bad
  values are rejected, not auto-quoted.
- **SameSite=None ⇒ Secure enforced.** `.none` without `secure` → `error.InsecureSameSiteNone`
  (browsers silently drop such a cookie otherwise), surfaced at build time.
- **Dateless.** Std-only, no clock: `expires` is a pre-formatted IMF-fixdate string the caller
  supplies (prefer `max_age`). Attributes emitted in RFC 6265 §4.1 order; null/false ones omitted.
- **`set` owns its formatting buffer.** The `http` helper takes no caller buffer: the response
  writer copies header bytes into its own storage at `setHeader` time, so nothing has to outlive
  the call. `set` formats into `max_set_cookie_bytes` = 4096 — RFC 6265 §6.1's "at least 4096
  bytes per cookie (name + value + attributes)", i.e. the largest cookie a conforming user agent
  must keep, and the same size as `http`'s whole per-response header copy store, so this buffer
  is never the binding constraint. Over-long ⇒ `error.BufferTooSmall`; a `Set-Cookie` is never
  truncated, since a truncated one still parses and would be stored silently corrupted.

## Threat model / out of scope
Defends against `Set-Cookie` header/attribute injection via a reflected name/value/Path/Domain, and
against the SameSite=None-without-Secure footgun. Does not: encrypt/sign/verify cookie values (no
session-token integrity — a signed-cookie scheme is the caller's), enforce Domain/Path scoping or
the public-suffix list, evaluate Expires/Max-Age (no clock), or emit more than one `Set-Cookie` per
response through the `set` helper (the server's `setHeader` replaces by name). The parser is
deliberately non-validating on read.

## Verification
Offline tests, green in Debug + ReleaseFast. Parser (7): simple pairs + `find`, OWS trimming,
valueless cookies, quoted/unbalanced-quote values (incl. a quoted value containing a `;`, which
does not end the segment), empty-name/first-`=` splitting, degenerate headers. Builder (11): full
attribute set in RFC order, `__Host-`/`__Secure-` prefix constraints, minimal `name=value`,
Domain + pre-formatted Expires, negative Max-Age,
`SameSite=Strict`, invalid name/value/Path/Domain rejection, `SameSite=None` both branches,
`BufferTooSmall`. Constants (1): `max_set_cookie_bytes` pinned by value and to `http`'s
`header_copy_bytes`. `http` helpers (3): an end-to-end `get`+`set` over `http.Server.serveStream`;
an anchor for the copy `set` depends on — a `noinline` helper sets the cookie from its own frame,
returns, and a second `noinline` deliberately clobbers that frame before `end()` runs, so the
value read off the wire proves `setHeader` copied rather than borrowed (`serveStream` offers no
seam between the handler returning and `end()`, so the writer is driven by hand); and an
over-long cookie refused with `BufferTooSmall`/`HeaderBytesExhausted` rather than truncated. Run:
`zig build test-cookies`.

**External anchor** (`golden_test.zig`): python3's stdlib `http.cookies` run once as a black-box
oracle over the same awkward header shapes (quoted values incl. an embedded `;`, valueless
attributes, empty names, duplicate names, attribute-keyword collisions), frozen and asserted
offline — no python3 needed to run the suite. This comparison caught one real bug (the quoted-`;`
segment split, fixed in `root.zig`'s `Iterator.next`) and surfaced several judged, NOT-adopted
divergences (python's whole-header abort on one bad segment; its Set-Cookie-attribute-keyword
capture applied to what is really a `Cookie` request header; last-write-wins on duplicate names;
DQUOTE-in-name rejection) — each argued against RFC 6265 at its test site, not copied blind.

## Backlog / deferred
None.

## Status
`gap · any · codec · reentrant` + deps: `http` (the `get`/`set` helpers only; parser + builder are
std-only) — canonical source is `pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/golden_test.zig runs CPython 3.14.4's http.cookies as a black-box oracle over the Cookie-header parse direction (16 tests, 5 divergences judged against RFC 6265, one real quote-aware split bug found); the Set-Cookie BUILD direction in root.zig is hand-authored against the RFC only

**How it got there.** The anchoring work landed. DONE be61caa: python http.cookies oracle; quote-aware split BUG fixed; 5 divergences judged
