# cookies

HTTP cookies (RFC 6265). **P1 (done):** the `Cookie` request-header parser —
iterate the `name=value` pairs a client sends back. **Next:** `Set-Cookie`
building with attributes (Path/Domain/Max-Age/Expires/Secure/HttpOnly/SameSite).

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

The parser is deliberately liberal (no charset validation on read); strictness
belongs on the `Set-Cookie` build side (next part).

- **Status:** `gap`. **Role:** codec. **Platform:** any. **Deps:** none (std
  only). **Concurrency:** reentrant — no state; results borrow the input.

Provenance: clean-room from RFC 6265 (HTTP State Management Mechanism). No
third-party source consulted or copied.

## Verification

`zig build test-cookies` — 6 offline tests (simple pairs + `find`, OWS trimming,
valueless cookies, quoted/unbalanced values, empty-name skipping + first-`=`
split, empty/degenerate headers), green in Debug + ReleaseFast.
