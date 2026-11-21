# cookies

HTTP cookies (RFC 6265): the `Cookie` request-header **parser** and the
`Set-Cookie` response-header **builder** (attributes Path/Domain/Max-Age/
Expires/Secure/HttpOnly/SameSite, with header-injection validation) for a
server, and a client-side **cookie jar** with the **Public Suffix List**
algorithm for a client.

The server half is allocation-free — parsed pairs borrow the header.

```zig
var it = cookies.parse(req.header("cookie") orelse "");
while (it.next()) |c| { … c.name … c.value … }

const sid = cookies.find(req.header("cookie") orelse "", "session") orelse return;
```

- `Cookie{ name, value }` — a parsed pair (borrows the header).
- `parse(header) Iterator` / `Iterator.next() ?Cookie` — RFC 6265 §5.4: split on
  every `;` (quoted or not), OWS-trim, split each on the first `=` (valueless cookie ⇒ empty value),
  strip a matching pair of surrounding DQUOTEs, skip empty-name segments.
- `find(header, name) ?[]const u8` — the first value for `name`
  (case-sensitive).
- `SetCookie{ name, value, path?, domain?, max_age?, expires?, secure, http_only,
  same_site?, partitioned }` + `write(w)` / `bufPrint(buf)` — the `Set-Cookie` header value,
  attributes in RFC 6265 §4.1 order. Validates FIRST (name token, value
  cookie-octet, no header-injection bytes) so a rejected cookie never leaves a
  half-written header; `SameSite=None` without `Secure` → `InsecureSameSiteNone`, `partitioned`
  without `Secure` → `InsecurePartitioned`, a `__Host-`/`__Secure-` name that
  breaks its prefix rules is refused.
  `expires` is a pre-formatted date (module is std-only/dateless; prefer `max_age`).

The parser is deliberately liberal (no charset validation on read); strictness
belongs on the `Set-Cookie` build side (next part).

- `get(req, name) ?[]const u8` / `set(res, sc) !void` — thin `http`
  helpers: read a cookie off a request, or serialize a `SetCookie` into the
  response as one more `Set-Cookie` line (each call appends, in call
  order, so a session and a CSRF cookie are two lines). `set` needs no buffer from the
  caller: it formats into a `max_set_cookie_bytes` (4096, RFC 6265 §6.1)
  buffer of its own, and `addSetCookie` copies the bytes into the response
  writer before returning. Longer than that ⇒ `BufferTooSmall`, never a
  truncated cookie.

## Signed and encrypted values

```zig
var key: cookies.Key = undefined;
try cookies.Key.deriveInto(&key, master); // >= 32 random bytes (cookie-rs derive_from)
defer key.wipe();

// Encrypted + authenticated, bound to the cookie name (cookie-rs PrivateJar format):
var buf: [512]u8 = undefined;
const sealed = try cookies.private.sealRandom(io, &key, "sid", "user=42", &buf);
try cookies.set(res, .{ .name = "sid", .value = sealed, .secure = true, .http_only = true });
var plain: [512]u8 = undefined;
const v = cookies.private.open(&.{ key, old_key }, "sid", cookies.get(req, "sid") orelse "", &plain);

// Authenticated only; `.bound` (default) ties it to the name, `.cookie_rs` is SignedJar's format:
const s = try cookies.signed.sign(&key, "theme", "dark", &buf, .{});
const t = cookies.signed.verify(&.{key}, "theme", s, .{}) orelse "light";
```

`verify`/`open` return the value or null, never why; a list of keys gives
rotation (seal with the newest, accept any). For a server-side lifetime use the
timed variants: `sealTimed(io, &key, name, value, now_s, &buf)` /
`openTimed(&keys, name, sealed, now_s, max_age_s, &plain)` (and
`signTimed`/`verifyTimed`) — the issue time is sealed in, so a stolen cookie
stops working after `max_age_s` whatever the browser was told. `percentEncode` /
`percentDecode` make any bytes a valid cookie value (cookie-rs `encoded()`).

## Client: the cookie jar

```zig
// The list is the caller's (MPL-2.0 data, updated weekly): the `publicsuffix`
// package's /usr/share/publicsuffix/public_suffix_list.dat, or a shipped copy.
var list = try cookies.PublicSuffixList.parse(gpa, list_text);
defer list.deinit();
var jar = cookies.Jar.init(gpa, io, .{ .psl = &list });
defer jar.deinit();
var client = http.Client.init(io, gpa, .{ .cookie_jar = jar.cookieJar() });
```

- `Jar` — RFC 6265 §5.2 parsing (`jar.SetCookie.parse`, the §5.1.1
  cookie-date algorithm), §5.3 storage, §5.4 retrieval (longest path, then
  oldest), RFC 6265bis's Secure rules (`Secure` only from `https://`, a plain
  response cannot shadow a secure cookie), 4096-byte name+value cap, LRU
  eviction past `max_cookies`/`max_per_domain`, and the `__Secure-`/`__Host-`
  name-prefix rules (§4.1.3: a cookie that breaks them is ignored, a deletion
  included). At most 256 matching cookies are sent per request, the most
  specific first. Thread-safe; the lock is not held while the caller's writer runs.
  `saveNetscapeAt`/`loadNetscapeAt` (and the clock variants) keep the cookies
  that outlive the session in a Netscape `cookies.txt`, the file curl, wget
  and Python's `MozillaCookieJar` read and write.
  `setCookieAt`/`writeCookiesAt` take the time explicitly; `cookieJar()` is
  the `http.Client.CookieJar` view on the `Io`'s real clock, which the client
  calls for every request and response, redirect hops included.
- **Without a list the jar is fail-closed:** every `Domain` attribute counts
  as a public suffix, so a cookie is host-only when `Domain` names the host and
  dropped otherwise. Go's jar without a list lets any server set cookies for
  any domain.
- `PublicSuffixList` — `parse(gpa, text)`, `publicSuffix`, `isPublicSuffix`,
  `registrableDomain`; ICANN and private sections, wildcards and exceptions,
  Unicode rules matched in punycode (`psl.toAscii`).

## Not provided

No server-side jar with delta tracking, no `Set-Cookie2`, no `SameSite`
enforcement or partitioned storage in the client jar, no
bundled Public Suffix List. See SPEC *What is deliberately not
done* and *Backlog / deferred*.

- **Role:** codec. **Platform:** any. **Deps:** `http`
  (the `get`/`set` helpers), `aesgcm` (`private` values), `datefmt` (the civil calendar under cookie-date), `unitext` (IDNA for the list's Unicode rules); the parser + builder are std-only logic.
  **Concurrency:** threadsafe — `Jar` locks itself; the parser and the
  builder have no state and borrow their input.

Provenance: clean-room from RFC 6265 (HTTP State Management Mechanism),
RFC 6265bis (draft, the Secure rules), the Public Suffix List's published
algorithm (publicsuffix.org/list) and RFC 3492 (punycode). The signed /
private value FORMAT and the percent-encode set follow the Rust `cookie` crate
(MIT OR Apache-2.0), read for the wire layout only (`src/secure/*.rs`, the
`encoding` set in `lib.rs`); no code copied, the implementation is our own over
std's HMAC/HKDF and the `aesgcm` module. A design reference under a permissive
licence, so no NOTICE entry is owed (root `NOTICE` §0). `src/secure_vectors.zig` is computed by
pyca/cryptography (`tools/secure_vectors.py`). Test data is generated by our own tooling:
`src/psl_vectors.zig` holds libpsl's answers (run as a black-box oracle) over
our own made-up list `src/psl_mini.dat`, `src/jar_go_vectors.zig` Go's
`net/http/cookiejar` answers over our own scenarios; no Public Suffix List data
is shipped.

## Verification

`scripts/modtest cookies` (Debug and ReleaseFast): offline tests for the
parser, the builder, the `http` helpers, the jar, the Public Suffix List and
the signed/private values, plus frozen oracle goldens (CPython `http.cookies`,
Go `cookiejar`, libpsl, headless Chrome, cookie-rs via pyca/cryptography).
`zig build interop-cookies` runs libpsl over the system list. Details: SPEC
*Verification*.
