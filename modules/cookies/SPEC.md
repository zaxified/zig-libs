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

## Threat model / out of scope
Defends against `Set-Cookie` header/attribute injection via a reflected name/value/Path/Domain, and
against the SameSite=None-without-Secure footgun. Does not: encrypt/sign/verify cookie values (no
session-token integrity — a signed-cookie scheme is the caller's), enforce Domain/Path scoping or
the public-suffix list, evaluate Expires/Max-Age (no clock), or emit more than one `Set-Cookie` per
response through the `set` helper (the server's `setHeader` replaces by name). The parser is
deliberately non-validating on read.

## Verification
16 offline tests, green in Debug + ReleaseFast. Parser (6): simple pairs + `find`, OWS trimming,
valueless cookies, quoted/unbalanced-quote values, empty-name/first-`=` splitting, degenerate
headers. Builder (10): full attribute set in RFC order, minimal `name=value`, Domain + pre-formatted
Expires, negative Max-Age, `SameSite=Strict`, invalid name/value/Path/Domain rejection, `SameSite=None`
both branches, `BufferTooSmall`. Plus an end-to-end `get`+`set` over `http.Server.serveStream`. Run:
`zig build test-cookies`.

## Backlog / deferred
None.

## Status
`gap · any · codec · reentrant` + deps: `http` (the `get`/`set` helpers only; parser + builder are
std-only) — canonical source is `pub const meta` in src/root.zig.
