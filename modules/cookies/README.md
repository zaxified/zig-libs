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

- `get(req, name) ?[]const u8` / `set(res, sc, buf) !void` — thin `http`
  helpers: read a cookie off a request, or serialize a `SetCookie` into the
  response's `Set-Cookie` header (the server emits one Set-Cookie per
  response — `setHeader` replaces by name).

- **Status:** `gap`. **Role:** codec. **Platform:** any. **Deps:** `http`
  (the `get`/`set` helpers; the parser + builder are std-only logic).
  **Concurrency:** reentrant — no state; results borrow the input.

Provenance: clean-room from RFC 6265 (HTTP State Management Mechanism). No
third-party source consulted or copied.

## Verification

`zig build test-cookies` — 16 offline tests. Parser (6): simple pairs + `find`,
OWS trimming, valueless cookies, quoted/unbalanced values, empty-name skipping,
degenerate headers. Builder (10): full attribute set, minimal, Domain+Expires,
negative Max-Age, Strict, invalid name/value/Path/Domain rejection, SameSite=None
both branches, BufferTooSmall. Green in Debug + ReleaseFast.
