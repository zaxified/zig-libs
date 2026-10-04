# linkheader

Web Linking (**RFC 8288**) `Link` header **builder + parser** — the little
codec every REST client needs for pagination:
`<https://api/x?page=2>; rel="next", <https://api/x?page=1>; rel="prev"`.

- Std has no Web-Linking codec; clean-room from the RFC.
- **Model after:** RFC 8288 (Web Linking), the `Link` header field.
- **Platform:** any (pure byte logic, no OS calls). **Role:** codec.
  **Concurrency:** reentrant (no shared state). **Allocation:** none — the
  builder writes into a caller buffer / `*std.Io.Writer`, the parser borrows the
  input header.

Provenance: clean-room from RFC 8288 (Web Linking). No third-party code.

## Model

```zig
pub const Link = struct {
    uri: []const u8,               // written between <> ; caller owns %-encoding; may be relative
    rel: []const u8,               // required; may be a space-separated rel list
    anchor: ?[]const u8 = null,    // context override (RFC 8288 §3.2)
    title: ?[]const u8 = null,
    title_star: ?[]const u8 = null, // `title*`, raw RFC 8187 ext-value
    type: ?[]const u8 = null,
    hreflang: ?[]const u8 = null,
    media: ?[]const u8 = null,
    extra: []const Param = &.{},   // build only: further params (as, crossorigin, …)
    raw_params: []const u8 = "",   // parse only: the link's whole param region

    fn params(self) ParamIterator;          // EVERY param, header order, repeats included
    fn param(self, name) ?Param;            // first, case-insensitive
    fn preferredTitle(self, out) !?[]const u8; // decoded title*, else unquoted title
};
pub const Param = struct { name: []const u8, value: []const u8 = "", quoted: bool = false };
```

## API

```zig
const lh = @import("linkheader");

// build (serialise a header VALUE, not the whole "Link:" line)
fn write(w: *std.Io.Writer, links: []const lh.Link) (std.Io.Writer.Error || error{InvalidLink})!void;
fn bufPrint(buf: []u8, links: []const lh.Link) error{ NoSpaceLeft, InvalidLink }![]const u8;
fn validate(link: lh.Link) error{InvalidLink}!void;

// parse (allocation-free iterator; yielded Links borrow `header`)
fn parse(header: []const u8) lh.Iterator;
//   lh.Iterator.next(self) ?Link

// values
fn unquote(out: []u8, quoted_value: []const u8) error{NoSpaceLeft}![]const u8;
fn decodeExtValue(out: []u8, raw: []const u8) ExtValueError!lh.ExtValue; // RFC 8187
fn encodeExtValue(out: []u8, language: []const u8, text: []const u8) ![]const u8;
fn resolve(out: []u8, base: []const u8, ref: []const u8) ResolveError![]const u8; // RFC 3986 §5.2

// convenience
fn pagination(out: *[4]Link, opts: lh.PaginationOpts) []const Link; // first/prev/next/last
fn find(header: []const u8, rel: []const u8) ?Link;                 // first match
```

### Build

```zig
var buf: [256]u8 = undefined;
const value = try lh.bufPrint(&buf, &.{
    .{ .uri = "https://api/x?page=2", .rel = "next" },
    .{ .uri = "https://api/x?page=1", .rel = "prev" },
});
// value == `<https://api/x?page=2>; rel="next", <https://api/x?page=1>; rel="prev"`
```

`pagination` fills a caller `[4]Link` with the present relations, in
first/prev/next/last order, ready to hand to `write`/`bufPrint`:

```zig
var slots: [4]Link = undefined;
const links = lh.pagination(&slots, .{ .first = "/p/1", .next = "/p/3", .last = "/p/9" });
const value = try lh.bufPrint(&buf, links);
```

### Parse

```zig
var it = lh.parse(resp_header_value);
while (it.next()) |link| {
    // link.uri / link.rel / link.title? / link.type? / link.hreflang?
}

// or jump straight to the one you want, and make it absolute:
if (lh.find(resp_header_value, "next")) |next| {
    var buf: [2048]u8 = undefined;
    const url = try lh.resolve(&buf, request_url, next.uri);
}

// every param, incl. unknown and repeated ones; a label in any language
var it2 = lh.parse("</s.css>; rel=preload; as=style; title*=UTF-8'de'n%c3%a4chstes%20Kapitel");
const l = it2.next().?;
_ = l.param("as").?.value;                       // "style"
var tb: [64]u8 = undefined;
_ = (try l.preferredTitle(&tb)).?;               // "nächstes Kapitel"
```

## Semantics

- **Build:** links joined with `", "`; each is `<uri>; rel="…"` then the present
  params in `anchor`, `title`, `title*`, `type`, `hreflang`, `media` order, then
  `extra`. Ordinary values are quoted with `"`/`\` backslash-escaped; `*`-params
  are written bare as RFC 8187 ext-values. The URI passes through verbatim —
  percent-encoding is the caller's responsibility.
- **Build refuses injection:** `error.InvalidLink`, before any byte of that link
  is written, for a URI holding a control byte, SP, `<`, `>` or `"`; a quoted
  value holding CR, LF or another control byte (HTAB is fine); a `*`-param that is
  not a UTF-8 ext-value; an empty `rel`; a non-token `extra` name.
- **Parse:** handles quoted **and** bare-token values, arbitrary surrounding /
  inter-token whitespace, commas and semicolons **inside** the `<uri>` or inside
  quoted values (they don't split a link), case-insensitive param names, and
  "first occurrence wins" for a repeated param.
- **Borrowing:** yielded string fields point into `header`; a quoted value is
  returned **verbatim** (escapes intact, `Param.quoted` set) — `unquote` removes
  the escapes into a caller buffer (or in place).
- **`title*`:** `preferredTitle` returns the decoded `title*` when it decodes
  (RFC 8288 §3.4.1), else the unquoted `title`; only UTF-8 ext-values decode
  (RFC 8187 reserves the other charsets).
- **`resolve`:** RFC 3986 §5.2, strict; `out` needs about 3 × (base + ref) bytes
  (it is also the merge scratch).
- **Malformed → skipped, never a panic:** a segment with no `<…>`, an
  unterminated `<`, or a stray separator advances the iterator to the next
  top-level comma; a link with no `rel` is dropped (RFC 8288 requires `rel`).
- **find:** matches `rel` ASCII-case-insensitively, including any single token
  of a whitespace-separated `rel` list (`rel="prev start"` matches `start`).

## Verify

```
zig build test-linkheader
```
