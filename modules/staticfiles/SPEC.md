# staticfiles — spec

A path-traversal-safe static file handler over `http`. Resolves an attacker-controlled request
path to a file under a configured root directory and streams it as an HTTP response, with correct
caching, conditional-request and byte-range semantics. Usage: see ./README.md.

The two make-or-break invariants:

1. **Containment.** A served file is *always* inside the configured root. No request — under any
   percent-encoding, path separator, `..` sequence, NUL byte or symlink — ever reads a byte
   outside it.
2. **No panics.** Every failure maps to an HTTP status (400/403/404/405/414/416/500); only a
   genuine response-write failure propagates (so the server can close the connection).

## 1. Path-traversal threat model

The request path (`req.path`) is untrusted. The defense is **two independent layers**, both
required — string sanitization alone is necessary but not sufficient (a symlink defeats it), and
`openat`-relative opening alone would still let a decoded `..` or an absolute path through.

### Layer 1 — `sanitizePath` (string)

Percent-decode `req.path`, then, on the **decoded** bytes:

| Vector | Handling |
|---|---|
| `..` segment (`/../`, `..%2f`, `%2e%2e/`, doubly-encoded) | **rejected** — `error.Traversal`. Decode happens first, so every encoding of `..` collapses to the same literal segment before the check. |
| NUL byte (`%00` or literal `\x00`) | **rejected** — `error.InvalidByte` (defeats C-string path truncation). |
| Backslash (`\` or `%5c`) | **rejected** — `error.InvalidByte` (a Windows path separator; refused cross-platform). |
| Absolute path (`/etc/passwd`) | **neutralized** — the leading `/` is stripped and the result is root-relative; there is no way to express an absolute filesystem path. |
| Dotfile segment (`.git`, `.env`) | **rejected by default** — `error.DotfileForbidden` (opt-in via `serve_dotfiles`). |
| `.` and empty (`//`) segments | **collapsed** (dropped). |
| Malformed `%`-encoding | **rejected** — `error.Malformed`. |
| Decoded path > `max_path_bytes` (8 KiB) | **rejected** — `error.TooLong`. |

The output is a clean path with single `/` separators, no leading/trailing slash, and no
`.`/`..`/empty segments. An empty result means the request targets the root directory itself.
Compaction is in-place and allocation-free.

Note: `%2f` decodes to a real `/` — after decoding it is a genuine segment separator, not a
traversal (a nested path like `a%2fb.txt` becomes `a/b.txt`). Because every `..` is rejected
regardless of encoding, an encoded slash can never help an escape.

### Layer 2 — `openWithinRoot` (filesystem)

The sanitized path is opened **one component at a time, each relative to the previous directory
handle** (`std.Io.Dir.openDir` / `openFile`): a single slash-free segment is all the OS resolver
ever sees, so a decoded `..` — even if layer 1 somehow missed one — cannot combine across
components. `follow_symlinks = false` (the default) passes `O_NOFOLLOW`, so a symlinked component
is an open error rather than a traversal. `resolve_beneath = true` is additionally requested
(`openat2(RESOLVE_BENEATH)` / `O_BENEATH` where supported; ignored elsewhere) as defense-in-depth.

Given: (a) no `..` segment survives layer 1, (b) each component is opened relative to a handle
rooted at the configured root, and (c) no symlink is traversed — the opened file is **provably**
within the root.

### Symlink policy

- **Default (`follow_symlinks = false`):** symlinks are never traversed. A symlinked path
  component yields an open error → **403**. A symlink inside the root pointing anywhere outside it
  is therefore unreachable. This is the hard, portable guarantee and the mode the test suite
  exercises against a real out-of-root file.
- **Opt-in (`follow_symlinks = true`):** symlinks are followed, but after opening, the file's real
  path (`realPath`) is verified to be a path-separated prefix match under the root's real path
  (`verifyContained`); an escaping symlink is still refused (**403**). If the OS cannot produce a
  real path, the file is treated as uncontained and refused (fail-closed).

### Dotfile policy

Segments beginning with `.` are refused by default (so `.git`, `.env`, `.htaccess` are never
served) at layer 1, and the directory listing likewise skips them. `serve_dotfiles = true` allows
them everywhere.

### Tested vectors

`../../etc/passwd`, `..%2f..%2fetc%2fpasswd`, `%2e%2e/…`, `....//…` (refused as a dotfile),
absolute `/etc/passwd`, `foo%00.png`, `..\..\…`, a symlink inside the root pointing to an
out-of-root secret, and `sub/../../secret.txt` — each must be a 4xx and must never return the
out-of-root content. Positive controls (`/hello.txt`, `/sub/dir/file.txt`, `/` → index) are served
alongside. See the module tests (`std.testing.tmpDir` builds the root, a real out-of-root secret,
and the escaping symlink).

## 2. Response semantics

### MIME

`Content-Type` by file extension: `Options.mime_overrides` first (case-insensitive), then the
embedded table (html, htm, css, js, mjs, json, map, xml, txt, md, csv, svg, png, jpg, jpeg, gif,
webp, avif, ico, bmp, woff, woff2, ttf, otf, eot, wasm, pdf, zip, gz, wav, mp3, mp4, webm, ogg),
then `Options.default_mime` (`application/octet-stream`). No dot / unknown extension → default.

### Validators

- **`Last-Modified`**: the file's mtime (`stat.mtime`), formatted as an IMF-fixdate.
- **`ETag`**: a **strong** tag `"<size:hex>-<mtime_seconds:hex>"`. This is the cheap default — no
  file read, and it changes on any edit that moves the size or mtime. A content hash (strong
  against mtime-only touches, at the cost of reading the file) is the documented alternative; it is
  intentionally not the default because it turns every conditional GET into a full read.

Both computed header values live in threadlocal scratch, because the response writer stores header
value slices without copying and emits them after the handler returns (one request per thread, as
throughout the http stack).

### Conditional requests (RFC 9110 §8.8/§13)

Delegated to `http.conditional.apply`, evaluated **before** range handling so a 304/412
short-circuits early. `If-None-Match` / `If-Modified-Since` (GET/HEAD) → **304 Not Modified** (no
body); `If-Match` / `If-Unmodified-Since` → **412 Precondition Failed**. A 304 carries `ETag`,
`Last-Modified` and `Cache-Control` (representation-specific headers are set only on the
proceeding 200/206 path).

### Range requests (RFC 7233)

Delegated to `http.range.apply`. `Accept-Ranges: bytes` is always set.

| Request | Response |
|---|---|
| No (or malformed) `Range` | **200**, `Content-Length: <size>`, full body. |
| Single satisfiable range | **206**, `Content-Range: bytes s-e/total`, `Content-Length: <range len>`, the range bytes (streamed positionally). |
| Unsatisfiable range | **416**, `Content-Range: bytes */total`, empty body. |
| Multiple ranges | **200**, full body (multi-range served as a whole; RFC 7233 §6.1 permits ignoring `Range`). |

Body bytes are streamed positionally in 64 KiB chunks (`readPositionalAll`) — the whole file is
never buffered, so large files cost bounded memory. A `HEAD` sets the same framing headers and
writes no body.

### Directory handling

A directory request resolves to `Options.index` (`index.html`). With no index: **403** by default,
or an HTML listing when `directory_listing = true`. Listing entry names are HTML-escaped
(`& < > " '`) so a crafted filename cannot inject markup; dotfile entries are skipped unless
`serve_dotfiles` is set.

### Cache-Control

`Options.cache_control`, when set, is emitted verbatim on 200/206 responses (e.g.
`public, max-age=31536000, immutable` for fingerprinted assets).

## 3. Status mapping

| Condition | Status |
|---|---|
| Non-GET/HEAD method | 405 (+ `Allow: GET, HEAD`) |
| Traversal / dotfile / backslash-or-NUL / forbidden (symlink, non-regular file, escape) | 403 |
| Malformed percent-encoding | 400 |
| Decoded path too long | 414 |
| Missing file/directory | 404 |
| Unsatisfiable range | 416 |
| Real I/O / filesystem failure | 500 |
| 304 / 412 | per conditional evaluation |

## 4. Concurrency & memory

A `Handler` is created once and shared read-only across the server's connection threads; it holds
no mutable state, so `serve` is concurrency-safe. Per-request scratch (ETag, Last-Modified,
Content-Length buffers) is threadlocal — one request is served to completion per thread, the same
model `http.range` uses. No dynamic allocation on the serve path; the 64 KiB streaming buffer is
stack-local per request.
