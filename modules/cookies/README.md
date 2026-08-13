# cookies

HTTP cookies (RFC 6265): the `Cookie` request-header **parser** and the
`Set-Cookie` response-header **builder** (attributes Path/Domain/Max-Age/
Expires/Secure/HttpOnly/SameSite, with header-injection validation).

Allocation-free — parsed pairs borrow the header.

```zig
var it = cookies.parse(req.header("cookie") orelse "");
while (it.next()) |c| { … c.name … c.value … }

const sid = cookies.find(req.header("cookie") orelse "", "session") orelse return;
```

- `Cookie{ name, value }` — a parsed pair (borrows the header).
- `parse(header) Iterator` / `Iterator.next() ?Cookie` — RFC 6265 §5.4: split on
  `;`, OWS-trim, split each on the first `=` (valueless cookie ⇒ empty value),
  strip a matching pair of surrounding DQUOTEs, skip empty-name segments.
- `find(header, name) ?[]const u8` — the first value for `name`
  (case-sensitive).
- `SetCookie{ name, value, path?, domain?, max_age?, expires?, secure, http_only,
  same_site? }` + `write(w)` / `bufPrint(buf)` — the `Set-Cookie` header value,
  attributes in RFC 6265 §4.1 order. Validates FIRST (name token, value
  cookie-octet, no header-injection bytes) so a rejected cookie never leaves a
  half-written header; `SameSite=None` without `Secure` → `InsecureSameSiteNone`.
  `expires` is a pre-formatted date (module is std-only/dateless; prefer `max_age`).

The parser is deliberately liberal (no charset validation on read); strictness
belongs on the `Set-Cookie` build side (next part).

- `get(req, name) ?[]const u8` / `set(res, sc) !void` — thin `http`
  helpers: read a cookie off a request, or serialize a `SetCookie` into the
  response's `Set-Cookie` header (the server emits one Set-Cookie per
  response — `setHeader` replaces by name). `set` needs no buffer from the
  caller: it formats into a `max_set_cookie_bytes` (4096, RFC 6265 §6.1)
  buffer of its own, and `setHeader` copies the bytes into the response
  writer before returning. Longer than that ⇒ `BufferTooSmall`, never a
  truncated cookie.

- **Role:** codec. **Platform:** any. **Deps:** `http`
  (the `get`/`set` helpers; the parser + builder are std-only logic).
  **Concurrency:** reentrant — no state; results borrow the input.

Provenance: clean-room from RFC 6265 (HTTP State Management Mechanism). No
third-party source consulted or copied.

## Verification

`zig build test-cookies` — 39 offline tests (23 here + 16 frozen python-oracle
goldens). Parser (7): simple pairs + `find`, OWS trimming, valueless cookies,
quoted/unbalanced values, a quoted value containing a `;`, empty-name skipping,
degenerate headers. Builder (11): full attribute set, `__Host-`/`__Secure-`
prefix constraints, minimal, Domain+Expires, negative Max-Age, Strict, invalid
name/value/Path/Domain rejection, SameSite=None both branches, BufferTooSmall.
Constants (1): `max_set_cookie_bytes` pinned by value and to `http`'s
`header_copy_bytes`.
`http` helpers (3): `get`+`set` over `http.Server.serveStream`, the cookie
surviving the dead frame it was formatted in, and an over-long cookie refused
rather than truncated. Green in Debug + ReleaseFast.
