# SPEC — `cookies`

**Purpose** — HTTP cookies (RFC 6265) for a server: parse the inbound `Cookie` request header into
name/value pairs (`parse`/`find`), and build a `Set-Cookie` response header value (`SetCookie`,
attributes Path/Domain/Max-Age/Expires/Secure/HttpOnly/SameSite) with header-injection validation
baked in. Plus two thin `http` helpers (`get`/`set`) that read a cookie off a request and set one on
a response.

**Model after / Seed** — clean-room from RFC 6265 (HTTP State Management Mechanism): the Cookie
request-header grammar (§5.4) and the Set-Cookie attribute order/format (§4.1), with the
`SameSite` attribute per RFC 6265bis. Greenfield; no third-party source consulted or copied. See
`NOTICE`.

**Design & invariants**
- **Allocation-free.** `parse` returns an `Iterator` whose `Cookie{name,value}` pairs **borrow the
  header**; `SetCookie.write` streams to a `*std.Io.Writer`, `bufPrint` into a caller buffer.
  Reentrant, no state.
- **Liberal parse, strict build.** Parse follows §5.4: split on `;`, OWS-trim, split each segment on
  the **first** `=` (a valueless segment → empty value), strip a matching pair of surrounding
  DQUOTEs, skip empty-name segments; no charset validation on read (a real-world header is accepted
  as-is). `find` is case-sensitive per §5.4.
- **Injection guard is the point of the build side.** `SetCookie.write` **validates everything
  first** — the name against the RFC 2616 token set, the value against §4.1.1 cookie-octet, and
  Path/Domain against a bare attribute-octet check (no CTL, no `;`) — so a control char or a
  separator (`;`/`,`/`"`/`\`/SP) that could inject a second attribute or a second header is refused
  with `error.InvalidCookie` **before any byte is written** (a rejected cookie never leaves a
  half-written header). Bad values are **rejected, not auto-quoted**.
- **SameSite=None ⇒ Secure enforced.** `same_site == .none` without `secure` → `error.InsecureSameSiteNone`
  (modern browsers silently drop such a cookie), surfacing the mistake at build time.
- **Dateless.** The module is std-only and carries no clock: `expires` is a **pre-formatted**
  IMF-fixdate string the caller supplies (prefer `max_age`). Attributes are emitted in RFC 6265 §4.1
  order; null/false ones are omitted.

**Threat model / out of scope** — Defends against **`Set-Cookie` header/attribute injection** via a
reflected name/value/Path/Domain (the validation above) and against a footgun that would silently
drop a cross-site cookie (`SameSite=None` without `Secure`). It does **not**: encrypt/sign/verify
cookie values (no session-token integrity — a signed-cookie scheme is the caller's), enforce
Domain/Path scoping or the public-suffix list, evaluate `Expires`/`Max-Age` (no clock), or emit more
than one `Set-Cookie` per response through the `set` helper (the server's `setHeader` replaces by
name — multiple cookies need direct header writes). The parser is deliberately non-validating on
read.

**Verification** — 16 offline tests, green in Debug + ReleaseFast. Parser (6): simple pairs +
`find`, OWS trimming, valueless cookies, quoted/unbalanced-quote values, empty-name/first-`=`
splitting, degenerate headers. Builder (10): full attribute set in RFC order, minimal `name=value`,
Domain + pre-formatted Expires, negative Max-Age, `SameSite=Strict`, invalid name/value/Path/Domain
rejection (control chars + separators), `SameSite=None` both branches (rejected without Secure,
accepted with), `BufferTooSmall`. Plus an end-to-end `get`+`set` over `http.Server.serveStream`
asserting the emitted `Set-Cookie` line and the echoed inbound cookie.

**Status** — `gap · any · codec · reentrant` · deps: `http` (the `get`/`set` helpers; the
parser + builder are std-only).
