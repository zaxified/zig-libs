# linkheader

Web Linking (**RFC 8288**) `Link` header **builder + parser** — the little
codec every REST client needs for pagination:
`<https://api/x?page=2>; rel="next", <https://api/x?page=1>; rel="prev"`.

- **Status:** `gap` — std has no Web-Linking codec; clean-room from the RFC.
- **Model after:** RFC 8288 (Web Linking), the `Link` header field.
- **Platform:** any (pure byte logic, no OS calls). **Role:** codec.
  **Concurrency:** reentrant (no shared state). **Allocation:** none — the
  builder writes into a caller buffer / `*std.Io.Writer`, the parser borrows the
  input header.

Provenance: clean-room from RFC 8288 (Web Linking). No third-party code.

## Model

```zig
pub const Link = struct {
    uri: []const u8,            // written between <> ; caller owns %-encoding
    rel: []const u8,            // required; may be a space-separated rel list
    title: ?[]const u8 = null,
    type: ?[]const u8 = null,
    hreflang: ?[]const u8 = null,
};
```

The common param set is modelled explicitly. On parse, unknown params
(`media`, `anchor`, …) are tolerated — the grammar is still honoured so they
never desync the scanner — but not surfaced.

## API

```zig
const lh = @import("linkheader");

// build (serialise a header VALUE, not the whole "Link:" line)
fn write(w: *std.Io.Writer, links: []const lh.Link) std.Io.Writer.Error!void;
fn bufPrint(buf: []u8, links: []const lh.Link) error{NoSpaceLeft}![]const u8;

// parse (allocation-free iterator; yielded Links borrow `header`)
fn parse(header: []const u8) lh.Iterator;
//   lh.Iterator.next(self) ?Link

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

// or jump straight to the one you want:
if (lh.find(resp_header_value, "next")) |next| { /* follow next.uri */ }
```

## Semantics

- **Build:** links joined with `", "`; each is `<uri>; rel="…"` then the present
  optional params in `title`, `type`, `hreflang` order. Every param value is
  quoted and `"`/`\` are backslash-escaped. The URI passes through verbatim —
  percent-encoding is the caller's responsibility.
- **Parse:** handles quoted **and** bare-token values, arbitrary surrounding /
  inter-token whitespace, commas and semicolons **inside** the `<uri>` or inside
  quoted values (they don't split a link), case-insensitive param names, and
  "first occurrence wins" for a repeated param.
- **Borrowing, no unescape:** yielded string fields point into `header`; a
  quoted value is returned **verbatim** (escapes intact), never allocated to
  unescape. For plain-ASCII values (the overwhelming case) that is
  byte-identical to the intended content.
- **Malformed → skipped, never a panic:** a segment with no `<…>`, an
  unterminated `<`, or a stray separator advances the iterator to the next
  top-level comma; a link with no `rel` is dropped (RFC 8288 requires `rel`).
- **find:** matches `rel` ASCII-case-insensitively, including any single token
  of a whitespace-separated `rel` list (`rel="prev start"` matches `start`).

## Verify

```
zig build test-linkheader
```
