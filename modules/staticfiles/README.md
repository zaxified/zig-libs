# staticfiles

A path-traversal-safe static file handler over `http`. Serves assets from a configured root
directory with the caching, conditional-request and byte-range semantics a production HTTPS
server needs — and, above all, **hard path-traversal safety**: the request path is
attacker-controlled, and a request can never read a byte outside the configured root, via any
percent-encoding, separator, `..` walk, NUL trick or symlink.

- **Model after:** Go `net/http` FileServer / `http.Dir` (root-confined open + index resolution)
  and the nginx static handler (Range / conditional / Cache-Control), with the traversal defense
  modeled on `openat`-relative resolution with `O_NOFOLLOW`.
- **Platform:** any. **Role:** server. **Concurrency:** shared-read (one `Handler` created once,
  shared read-only across the server's connection threads; per-request scratch is threadlocal).
  **Deps:** `http` + std only.

Provenance: original work of the zig-libs authors (MIT). No third-party code.

## What it does

- **`GET` / `HEAD` only** — anything else answers **405** with an `Allow: GET, HEAD` header.
- **`Content-Type`** from an embedded MIME table (html/css/js/json/svg/png/jpg/webp/woff2/wasm/
  txt/xml/pdf/… ), a caller override list, and a configurable default (`application/octet-stream`).
- **`Content-Length`**, **`Last-Modified`** (file mtime) and a strong **`ETag`** from
  **size + mtime** (the cheap default — no file read; see SPEC.md for the content-hash alternative).
- **Conditional requests** (RFC 9110): `If-None-Match` / `If-Modified-Since` → **304**,
  `If-Match` / `If-Unmodified-Since` → **412** — via the `http.conditional` helper.
- **Byte ranges** (RFC 7233) via the `http.range` helper: a single range → **206** +
  `Content-Range`, an unsatisfiable range → **416**, `Accept-Ranges: bytes` always. A multi-range
  request is served as a full **200** (RFC 7233 §6.1 permits ignoring `Range`; multipart/byteranges
  is out of scope — a known amplification vector). **`If-Range`** (RFC 9110 §13.1.5) gates the
  whole range path: a stale or weak validator means the client's copy is out of date, so the
  `Range` is ignored and the full resource is served instead of a 206 it would have to discard.
- **Directory `index`** (`index.html` by default) for a directory request. **Directory listing is
  off by default** (opt-in; entry names are HTML-escaped when on).
- **`Cache-Control`** when configured (`Options.cache_control`, emitted verbatim).

## Path-traversal safety (the make-or-break requirement)

Two independent layers, both required — string checks are necessary but not sufficient (a symlink
defeats them). See SPEC.md for the full threat model and the vector list.

1. **`sanitizePath`** percent-decodes the path, then rejects the whole request on a `..` segment
   (post-decode, so `%2e%2e` / `..%2f` are caught), an embedded NUL (`%00` or literal), a
   backslash, and — by default — any dotfile segment (`.git`, `.env`). `.` and empty (`//`)
   segments collapse; the result is a clean, root-**relative** path with no `..` and no leading
   `/`. An absolute path can never survive.
2. **`openWithinRoot`** opens the sanitized path **one component at a time, each relative to the
   parent directory handle** (`openat`-style — a single slash-free segment ever reaches the OS
   resolver), with `follow_symlinks = false` by default. No traversed symlink + no `..` ⇒ the
   opened file is provably inside the root. `resolve_beneath` is additionally requested where the
   OS supports it.

**Symlink policy:** not followed by default (a symlinked component → 403). Set
`follow_symlinks = true` to follow them; the resolved file's real path is then additionally
verified to stay under the root, so an escaping symlink is still refused.

**Dotfile policy:** dotfile segments refused by default; `serve_dotfiles = true` allows them.

## Quick start — mount on the http server

```zig
const http = @import("http");
const staticfiles = @import("staticfiles");

// `root` is an open std.Io.Dir for the directory you want to serve.
var files = staticfiles.Handler.init(io, root, .{
    .cache_control = "public, max-age=3600",
    // .directory_listing = true,   // opt-in
    // .follow_symlinks = true,     // opt-in (still contained)
    // .serve_dotfiles = true,      // opt-in
});

var server = http.Server.init(io, gpa, .{
    .handler = staticfiles.httpHandler, // recovers the Handler from req.context
    .context = &files,
    .addr = "127.0.0.1",
    .port = 8080,
});
try server.listen();
```

## Standalone pieces (testable without a server)

- `mimeType(name, overrides, default)` — extension → media type.
- `sanitizePath(raw, out, .{})` — percent-decode + validate + normalize to a root-relative path,
  or a typed `SanitizeError` (the layer-1 traversal check).
- `openWithinRoot(root, io, rel, opts)` / `resolveFile(root, io, raw_path, opts)` — resolve to an
  open regular file within the root, or a typed `ResolveError` (the layer-2 guarantee).
- `Handler.sendFile(req, rw, *Opened)` — serve an already-resolved/opened file (headers,
  conditional/range handling, body) without a second `resolveFile`. Use this to compose an
  app-specific 404 or similar: `resolveFile` once yourself, and on `error.NotFound` serve your own
  page instead of falling through to `serve`'s built-in 404; on success, hand the `Opened` straight
  to `sendFile`. `sendFile` only borrows `opened` — closing it (`opened.close(io)`) stays the
  caller's job, exactly as it is for `serve`'s own internal call.

## Options

| Field | Default | Meaning |
|---|---|---|
| `index` | `"index.html"` | File served for a directory request; empty disables index lookup. |
| `serve_dotfiles` | `false` | Serve `.`-prefixed segments (`.git`, `.env`). |
| `follow_symlinks` | `false` | Follow symlinks (still verified contained under root). |
| `directory_listing` | `false` | HTML listing when a directory has no index (names HTML-escaped). |
| `cache_control` | `null` | `Cache-Control` value, emitted verbatim on 200/206. |
| `mime_overrides` | `&.{}` | `extension → media-type` overrides, consulted before the table. |
| `default_mime` | `"application/octet-stream"` | `Content-Type` for an unknown extension. |
