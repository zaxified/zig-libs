// SPDX-License-Identifier: MIT

//! staticfiles — a path-traversal-safe static file handler over `http`.
//!
//! Serves assets from a configured root directory as HTTP responses, with the
//! caching / conditional-request / byte-range semantics a production HTTPS
//! server needs — and, above all, **hard path-traversal safety**: the request
//! path is attacker-controlled, and a request must NEVER read a byte outside
//! the configured root, via any percent-encoding, separator, `..` walk, NUL
//! trick or symlink. See `SPEC.md` for the full threat model.
//!
//! ## What it does
//!
//! - `GET` / `HEAD` only (anything else → 405 with an `Allow` header).
//! - `Content-Type` from an embedded MIME table (the common web types) plus a
//!   caller override list and a configurable default (`application/octet-stream`).
//! - `Content-Length`, `Last-Modified` (file mtime) and a strong `ETag` derived
//!   from **size + mtime** (the cheap default; see `buildETag` /`SPEC.md`).
//! - Conditional requests (RFC 9110 §8.8/§13) via the `http.conditional`
//!   helper: `If-None-Match` / `If-Modified-Since` → **304**, `If-Match` /
//!   `If-Unmodified-Since` → **412**, no body.
//! - Byte ranges (RFC 7233) via the `http.range` helper: a single range →
//!   **206** + `Content-Range`, an unsatisfiable range → **416**,
//!   `Accept-Ranges: bytes` always. A multi-range request is served as a full
//!   **200** (RFC 7233 §6.1 permits ignoring `Range`; multipart/byteranges is
//!   deliberately out of scope — it is a documented amplification vector).
//! - An `index` file (`index.html` by default) for a directory request;
//!   directory listing is **off by default** (opt-in, HTML-escaped when on).
//! - `Cache-Control` when configured (`Options.cache_control`, verbatim).
//!
//! ## Path-traversal safety — the make-or-break requirement
//!
//! Two independent layers, both required (string checks alone are necessary
//! but not sufficient — a symlink defeats them):
//!
//! 1. **`sanitizePath`** percent-decodes the request path, then rejects the
//!    whole request on: a `..` segment (post-decode, so `%2e%2e` and `..%2f`
//!    are caught), an embedded NUL (`%00` or literal), a backslash, and — by
//!    default — any dotfile segment (`.git`, `.env`). `.` and empty (`//`)
//!    segments collapse; the result is a clean, root-**relative** path with no
//!    `..`, no leading `/`. An absolute path can never survive (the leading
//!    slash and every `..` are stripped/rejected).
//! 2. **`openWithinRoot`** opens the sanitized path **component by component,
//!    each relative to the parent directory handle** (`openat`-style — a single
//!    path segment with no slashes ever reaches the OS resolver), with
//!    `follow_symlinks = false` by default. Because no component is ever a
//!    symlink that is traversed and no `..` is ever present, the opened file is
//!    provably within the root. `resolve_beneath` is additionally requested as
//!    defense-in-depth where the OS supports it — which, to be precise, does
//!    **NOT include Linux**: `std.Io` sets the flag under
//!    `@hasField(posix.O, "RESOLVE_BENEATH")`, and `std.os.linux.O` has no
//!    such field (it is a FreeBSD flag; Linux exposes the equivalent only
//!    through `openat2`, which std does not use here). So on Linux the option
//!    is a silent no-op and containment rests ENTIRELY on `sanitizePath`, the
//!    no-follow component walk, and `verifyContained`. Do not read the
//!    option's presence as a kernel-level backstop.
//!
//! **Symlink policy**: NOT followed by default — a symlinked component yields
//! an open error → 403, so a symlink pointing outside the root is unreachable.
//! Set `Options.follow_symlinks = true` to follow them (then the opened path is
//! additionally verified to be contained under the root's real path, so an
//! escaping symlink is still refused; see `openWithinRoot`).
//!
//! **Dotfile policy**: dotfile segments are refused by default so `.git` /
//! `.env` are never served; set `Options.serve_dotfiles = true` to allow them.
//!
//! ## Mounting on the `http` server
//!
//! `Handler` holds the root `Dir`, the `Io` and the `Options`. Point the
//! server's handler at `httpHandler` and pass the `Handler` as the context:
//!
//! ```zig
//! var files = staticfiles.Handler.init(io, root_dir, .{});
//! var server = http.Server.init(io, gpa, .{
//!     .handler = staticfiles.httpHandler,
//!     .context = &files,
//! });
//! ```
//!
//! The lower-level pieces — `mimeType`, `sanitizePath`, `openWithinRoot` /
//! `resolveFile` — are `pub` and testable standalone.

const std = @import("std");
const http = @import("http");

const Io = std.Io;
const Dir = std.Io.Dir;
const File = std.Io.File;
const Writer = std.Io.Writer;
const mem = std.mem;

pub const meta = .{
    .platform = .any,
    .role = .server,
    // A `Handler` is created once and shared read-only across the server's
    // connection threads; it holds no mutable state, so `serve` is safe to
    // call concurrently. The per-request scratch is threadlocal (one request
    // per thread, as elsewhere in the http stack).
    .concurrency = .shared_read,
    .model_after = "Go net/http FileServer / http.Dir (root-confined open + index) + nginx static handler (Range/conditional/Cache-Control); traversal defense modeled on openat-relative resolution with O_NOFOLLOW",
    .deps = .{"http"},
};

/// Largest request path (after percent-decoding) this handler will resolve.
/// A longer path is refused rather than routed. Matches the http server's own
/// origin-form normalization bound.
pub const max_path_bytes: usize = 8 * 1024;

// ── configuration ───────────────────────────────────────────────────────────

/// A caller-supplied `extension → media-type` override, consulted (case-
/// insensitively) before the embedded MIME table. `ext` is WITHOUT the dot
/// (e.g. `"wasm"`); `media_type` is the full `Content-Type` value.
pub const MimeOverride = struct {
    ext: []const u8,
    media_type: []const u8,
};

pub const Options = struct {
    /// File served when a directory is requested; empty disables index lookup
    /// (a directory then lists or 403s per `directory_listing`).
    index: []const u8 = "index.html",
    /// Serve dotfiles (segments beginning with `.`). Default false so `.git`,
    /// `.env` and friends are never exposed.
    serve_dotfiles: bool = false,
    /// Follow symlinks. Default false: a symlinked path component is an open
    /// error (403), so a symlink can never escape the root. When true, the
    /// resolved file's real path is verified to stay under the root (an
    /// escaping symlink is still refused). See the module + `SPEC.md`.
    follow_symlinks: bool = false,
    /// Generate an HTML directory listing when a directory has no index file.
    /// Default false (a directory then answers 403). When on, every entry name
    /// is HTML-escaped (no markup / log injection).
    directory_listing: bool = false,
    /// `Cache-Control` header value emitted verbatim on 200/206 (e.g.
    /// `"public, max-age=3600"` or `"public, max-age=31536000, immutable"`);
    /// null omits it. Must be caller-owned / static (stored, not copied).
    cache_control: ?[]const u8 = null,
    /// Extension→type overrides, consulted before the embedded table.
    mime_overrides: []const MimeOverride = &.{},
    /// `Content-Type` when the extension matches nothing.
    default_mime: []const u8 = "application/octet-stream",
};

// ── MIME table ───────────────────────────────────────────────────────────────

/// The embedded extension→media-type table (lower-case extension, no dot).
/// Covers the common web asset types; extend via `Options.mime_overrides`.
const mime_table = std.StaticStringMap([]const u8).initComptime(.{
    .{ "html", "text/html; charset=utf-8" },
    .{ "htm", "text/html; charset=utf-8" },
    .{ "css", "text/css; charset=utf-8" },
    .{ "js", "text/javascript; charset=utf-8" },
    .{ "mjs", "text/javascript; charset=utf-8" },
    .{ "json", "application/json" },
    .{ "map", "application/json" },
    .{ "xml", "application/xml" },
    .{ "txt", "text/plain; charset=utf-8" },
    .{ "md", "text/markdown; charset=utf-8" },
    .{ "csv", "text/csv; charset=utf-8" },
    .{ "svg", "image/svg+xml" },
    .{ "png", "image/png" },
    .{ "jpg", "image/jpeg" },
    .{ "jpeg", "image/jpeg" },
    .{ "gif", "image/gif" },
    .{ "webp", "image/webp" },
    .{ "avif", "image/avif" },
    .{ "ico", "image/x-icon" },
    .{ "bmp", "image/bmp" },
    .{ "woff", "font/woff" },
    .{ "woff2", "font/woff2" },
    .{ "ttf", "font/ttf" },
    .{ "otf", "font/otf" },
    .{ "eot", "application/vnd.ms-fontobject" },
    .{ "wasm", "application/wasm" },
    .{ "pdf", "application/pdf" },
    .{ "zip", "application/zip" },
    .{ "gz", "application/gzip" },
    .{ "wav", "audio/wav" },
    .{ "mp3", "audio/mpeg" },
    .{ "mp4", "video/mp4" },
    .{ "webm", "video/webm" },
    .{ "ogg", "audio/ogg" },
});

/// The `Content-Type` for `name`, by its extension: `overrides` first
/// (case-insensitive), then the embedded table, then `default`. A name with no
/// dot — or an unknown extension — gets `default`. The extension match is
/// case-insensitive (`.PNG` → image/png).
pub fn mimeType(name: []const u8, overrides: []const MimeOverride, default: []const u8) []const u8 {
    const dot = mem.lastIndexOfScalar(u8, name, '.') orelse return default;
    const ext = name[dot + 1 ..];
    if (ext.len == 0 or ext.len > 16) return default;
    var buf: [16]u8 = undefined;
    const lower = std.ascii.lowerString(buf[0..ext.len], ext);
    for (overrides) |o| {
        if (std.ascii.eqlIgnoreCase(o.ext, lower)) return o.media_type;
    }
    return mime_table.get(lower) orelse default;
}

// ── path sanitization (layer 1) ──────────────────────────────────────────────

pub const SanitizeError = error{
    /// A `..` segment (any encoding) — an attempt to walk out of the root.
    Traversal,
    /// A NUL or backslash byte (path-truncation / separator tricks).
    InvalidByte,
    /// Malformed percent-encoding (`%` not followed by two hex digits).
    Malformed,
    /// A dotfile segment while `serve_dotfiles` is off.
    DotfileForbidden,
    /// The decoded path exceeds `max_path_bytes`.
    TooLong,
};

pub const SanitizeOptions = struct {
    allow_dotfiles: bool = false,
};

/// Percent-decode + validate + normalize `raw` (the attacker-controlled
/// request path) into a clean, root-**relative** path written into `out`,
/// returning the filled slice. The result has single `/` separators, no
/// leading/trailing slash, and NO `.`/`..`/empty segments. Any traversal or
/// injection vector fails (see `SanitizeError`). An empty result means the
/// request targets the root directory itself (→ index / listing).
///
/// This is layer 1 of the traversal defense; `openWithinRoot` is layer 2. It
/// is pure and allocation-free — `out` must be at least `max_path_bytes`.
pub fn sanitizePath(raw: []const u8, out: []u8, opts: SanitizeOptions) SanitizeError![]const u8 {
    const n = try percentDecode(raw, out);
    const dec = out[0..n];
    // Reject NUL (path truncation) and backslash (Windows separator) anywhere,
    // in the DECODED bytes — this catches both literal and `%00`/`%5c` forms.
    for (dec) |c| {
        if (c == 0 or c == '\\') return error.InvalidByte;
    }
    // Split on '/', drop empty and `.` segments, reject `..` and (optionally)
    // dotfiles, and compact the survivors back into `out`. Compaction only ever
    // removes bytes and writes at or before the read cursor, so it is safe
    // in-place.
    var w: usize = 0;
    var i: usize = 0;
    while (i < dec.len) {
        while (i < dec.len and dec[i] == '/') i += 1;
        const start = i;
        while (i < dec.len and dec[i] != '/') i += 1;
        const seg = dec[start..i];
        if (seg.len == 0) continue; // trailing slash
        if (mem.eql(u8, seg, ".")) continue;
        if (mem.eql(u8, seg, "..")) return error.Traversal;
        if (!opts.allow_dotfiles and seg[0] == '.') return error.DotfileForbidden;
        if (w != 0) {
            out[w] = '/';
            w += 1;
        }
        mem.copyForwards(u8, out[w .. w + seg.len], seg);
        w += seg.len;
    }
    return out[0..w];
}

/// Percent-decode `raw` into `out` (`%XX` → byte; `+` is left as-is — it is a
/// query-string convention, not a path one). `error.TooLong` if the output
/// would exceed `out.len`, `error.Malformed` on a `%` not followed by two hex
/// digits.
fn percentDecode(raw: []const u8, out: []u8) error{ TooLong, Malformed }!usize {
    var w: usize = 0;
    var i: usize = 0;
    while (i < raw.len) {
        if (w == out.len) return error.TooLong;
        const c = raw[i];
        if (c == '%') {
            if (i + 2 >= raw.len) return error.Malformed;
            const hi = hexVal(raw[i + 1]) orelse return error.Malformed;
            const lo = hexVal(raw[i + 2]) orelse return error.Malformed;
            out[w] = (@as(u8, hi) << 4) | lo;
            i += 3;
        } else {
            out[w] = c;
            i += 1;
        }
        w += 1;
    }
    return w;
}

fn hexVal(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => null,
    };
}

// ── open-within-root (layer 2) ───────────────────────────────────────────────

pub const ResolveError = error{
    /// Path escaped (or would escape) the root — a symlink out of root under
    /// `follow_symlinks`, or (defensively) any resolution the OS rejected as
    /// escaping. → 403.
    Forbidden,
    /// No such file/directory under the root. → 404.
    NotFound,
    /// The target is a directory with no index file. The caller decides
    /// (listing vs 403). Not an error at the HTTP boundary on its own.
    IsDir,
    /// A real I/O / filesystem failure. → 500.
    IoError,
};

/// An opened regular file within the root, plus the metadata a response needs.
/// The caller owns `file` and must `close` it.
pub const Opened = struct {
    file: File,
    stat: File.Stat,
    /// The leaf name whose extension selects the `Content-Type` (the index
    /// file name when a directory resolved to its index).
    mime_name: []const u8,

    pub fn close(o: *Opened, io: Io) void {
        o.file.close(io);
    }
};

/// Open `rel` (a sanitized, root-relative path from `sanitizePath`) as a
/// regular file within `root`, walking one component at a time relative to the
/// parent handle so no multi-segment path — and thus no `..` — ever reaches the
/// OS resolver, and (by default) refusing any symlink component. This is
/// layer 2 of the traversal defense.
///
/// `rel == ""` (the root directory) and a directory target both trigger index
/// lookup (`opts.index`); a directory with no index returns `error.IsDir`.
pub fn openWithinRoot(root: Dir, io: Io, rel: []const u8, opts: Options) ResolveError!Opened {
    const follow = opts.follow_symlinks;

    if (rel.len == 0) return openIndex(root, io, opts);

    // Walk every parent component as a directory, relative to the previous
    // handle; keep only the deepest (closing the rest). `root` is never closed.
    const last_slash = mem.lastIndexOfScalar(u8, rel, '/');
    const dir_part: []const u8 = if (last_slash) |s| rel[0..s] else "";
    const leaf: []const u8 = if (last_slash) |s| rel[s + 1 ..] else rel;

    var parent: Dir = root;
    var parent_owned = false;
    defer if (parent_owned) parent.close(io);

    if (dir_part.len != 0) {
        var it = mem.splitScalar(u8, dir_part, '/');
        while (it.next()) |seg| {
            const next = parent.openDir(io, seg, .{
                .follow_symlinks = follow,
                .access_sub_paths = true,
            }) catch |e| return mapOpenError(e);
            if (parent_owned) parent.close(io);
            parent = next;
            parent_owned = true;
        }
    }

    // The leaf: try it as a regular file first. `allow_directory = false` turns
    // a directory target into `error.IsDir` (cheaply on Windows, one fstat
    // elsewhere) instead of handing back a directory fd.
    const file = parent.openFile(io, leaf, .{
        .follow_symlinks = follow,
        .allow_directory = false,
        .resolve_beneath = true,
    }) catch |e| switch (e) {
        error.IsDir => {
            // A directory: descend into it and serve its index.
            var d = parent.openDir(io, leaf, .{
                .follow_symlinks = follow,
                .access_sub_paths = true,
            }) catch |de| return mapOpenError(de);
            defer d.close(io);
            return openIndex(d, io, opts);
        },
        else => return mapOpenError(e),
    };

    var f = file;
    const st = f.stat(io) catch {
        f.close(io);
        return error.IoError;
    };
    // Only ever serve regular files — never a device, fifo or socket.
    if (st.kind != .file) {
        f.close(io);
        return error.Forbidden;
    }
    if (follow) verifyContained(root, io, &f) catch {
        f.close(io);
        return error.Forbidden;
    };
    return .{ .file = f, .stat = st, .mime_name = leaf };
}

/// Open `dir`'s configured index file as a regular file, or `error.IsDir` when
/// there is no index (index disabled, missing, or itself a directory).
fn openIndex(dir: Dir, io: Io, opts: Options) ResolveError!Opened {
    if (opts.index.len == 0) return error.IsDir;
    var f = dir.openFile(io, opts.index, .{
        .follow_symlinks = opts.follow_symlinks,
        .allow_directory = false,
        .resolve_beneath = true,
    }) catch |e| switch (e) {
        error.FileNotFound, error.IsDir => return error.IsDir,
        else => return mapOpenError(e),
    };
    const st = f.stat(io) catch {
        f.close(io);
        return error.IoError;
    };
    if (st.kind != .file) {
        f.close(io);
        return error.IsDir;
    }
    return .{ .file = f, .stat = st, .mime_name = opts.index };
}

/// Backstop for `follow_symlinks = true`: confirm the opened file's real path
/// is under the root's real path. Best-effort — if the OS cannot produce a
/// real path we treat it as uncontained (refuse), never as contained.
fn verifyContained(root: Dir, io: Io, f: *File) error{Escaped}!void {
    var root_buf: [Dir.max_path_bytes]u8 = undefined;
    var file_buf: [Dir.max_path_bytes]u8 = undefined;
    const root_fd: File = .{ .handle = root.handle, .flags = .{ .nonblocking = false } };
    const root_n = root_fd.realPath(io, &root_buf) catch return error.Escaped;
    const file_n = f.realPath(io, &file_buf) catch return error.Escaped;
    const root_path = root_buf[0..root_n];
    const file_path = file_buf[0..file_n];
    if (!mem.startsWith(u8, file_path, root_path)) return error.Escaped;
    // Guard against a sibling prefix ("/srv/wwwroot" vs root "/srv/www"): the
    // byte after the root prefix must be a separator (or the paths are equal).
    if (file_path.len > root_path.len and file_path[root_path.len] != '/')
        return error.Escaped;
}

fn mapOpenError(e: anyerror) ResolveError {
    return switch (e) {
        error.FileNotFound, error.NotDir => error.NotFound,
        // O_NOFOLLOW on a symlink, or a resolve-beneath / permission refusal:
        // treat as forbidden rather than leak existence.
        error.SymLinkLoop, error.AccessDenied, error.PermissionDenied => error.Forbidden,
        else => error.IoError,
    };
}

/// One-shot resolution: sanitize `raw_path` then open it within `root`.
/// `raw_path` is the raw, percent-encoded request path (`req.path`).
pub fn resolveFile(root: Dir, io: Io, raw_path: []const u8, opts: Options) (SanitizeError || ResolveError)!Opened {
    var buf: [max_path_bytes]u8 = undefined;
    const rel = try sanitizePath(raw_path, &buf, .{ .allow_dotfiles = opts.serve_dotfiles });
    return openWithinRoot(root, io, rel, opts);
}

// ── the HTTP handler ─────────────────────────────────────────────────────────

/// A static-file handler bound to one root directory. Created once, shared
/// read-only across the server's connection threads (`serve` is concurrency-
/// safe). The `Dir` and `Io` outlive the server.
pub const Handler = struct {
    io: Io,
    root: Dir,
    options: Options,

    pub fn init(io: Io, root: Dir, options: Options) Handler {
        return .{ .io = io, .root = root, .options = options };
    }

    /// Serve `req` from the root directory onto `rw`. Never panics; every
    /// failure maps to a status (404/403/405/416/500) rather than an error,
    /// except genuine response-write failures, which propagate so the server
    /// can close the connection.
    pub fn serve(h: *const Handler, req: *http.Server.Request, rw: *http.Server.ResponseWriter) Writer.Error!void {
        if (req.method != .get and req.method != .head) {
            rw.setStatus(405);
            // Best-effort, deliberately: RFC 9110 §15.5.6 makes `Allow` a
            // MUST on a 405, but answering 500 instead would throw away the
            // "method not allowed" answer entirely, which serves the client
            // worse than a 405 missing its hint. Reachable only if a
            // middleware already spent the copy budget — this response is
            // otherwise empty.
            rw.setHeader("Allow", "GET, HEAD") catch {};
            return;
        }

        var opened = resolveFile(h.root, h.io, req.path, h.options) catch |e| switch (e) {
            error.Traversal, error.DotfileForbidden, error.InvalidByte, error.Forbidden => return sendStatus(rw, 403),
            error.Malformed => return sendStatus(rw, 400),
            error.TooLong => return sendStatus(rw, 414),
            error.NotFound => return sendStatus(rw, 404),
            error.IsDir => return h.serveDirectory(req, rw),
            error.IoError => return sendStatus(rw, 500),
        };
        defer opened.close(h.io);
        return h.sendFile(req, rw, &opened);
    }

    /// Emit the representation headers + body (or 304/412/206/416) for an
    /// already-opened file.
    fn sendFile(h: *const Handler, req: *http.Server.Request, rw: *http.Server.ResponseWriter, opened: *Opened) Writer.Error!void {
        const total = opened.stat.size;
        const mtime_s = opened.stat.mtime.toSeconds();
        // Locals, not thread-locals: setHeader copies the bytes into its own
        // header_buf at call time, so these only need to outlive the calls
        // below, not the response.
        var etag_buf: [etag_max]u8 = undefined;
        var lastmod_buf: [http.Server.http_date_len]u8 = undefined;
        const etag = buildETag(&etag_buf, total, mtime_s);

        // Validators first, so a 304/412 short-circuit carries ETag +
        // Last-Modified + Cache-Control (and nothing representation-specific).
        // Best-effort, deliberately: `Last-Modified` is a cache validator.
        // Losing it costs a conditional-request round trip and nothing else —
        // the response stays correct, so a 500 would be strictly worse.
        rw.setHeader("Last-Modified", http.Server.formatHttpDate(mtime_s, &lastmod_buf)) catch {};
        // NOT best-effort: an operator that configured `Cache-Control` did so
        // to control where this file may be stored. Dropping it silently can
        // put private content in a shared cache.
        if (h.options.cache_control) |cc|
            rw.setHeader("Cache-Control", cc) catch return failUnsafeResponse(rw);
        if (http.conditional.apply(req, rw, .{ .etag = etag, .last_modified = mtime_s }) catch false) {
            return; // 304 / 412 staged (body suppressed by the server core)
        }

        // NOT best-effort: a body served without `Content-Type` is sniffed.
        rw.setHeader("Content-Type", mimeType(opened.mime_name, h.options.mime_overrides, h.options.default_mime)) catch
            return failUnsafeResponse(rw);
        // Best-effort, deliberately: `Accept-Ranges` only advertises that
        // range requests are supported. Losing it costs resumable downloads,
        // not correctness.
        rw.setHeader("Accept-Ranges", "bytes") catch {};

        // Range resolution (RFC 7233): single range → 206 + Content-Range,
        // unsatisfiable → 416, multi-range → fall back to a full 200.
        //
        // `If-Range` (RFC 9110 §13.1.5) gates the whole range path: when the
        // client's validator no longer matches this file, its copy is stale
        // and it wants the entire resource, so the `Range` is ignored and the
        // full 200 below is exactly the right answer. Skipping `range.apply`
        // also keeps `Content-Range` off the response.
        var start: u64 = 0;
        var length: u64 = total;
        var rbuf: [http.range.default_max_ranges]http.range.ResolvedRange = undefined;
        const applied = if (http.conditional.ifRangeAllows(req, .{ .etag = etag, .last_modified = mtime_s }))
            http.range.apply(req, rw, total, &rbuf) catch return sendStatus(rw, 500)
        else
            http.range.Applied{ .outcome = .no_range, .ranges = &.{} };

        switch (applied.outcome) {
            .no_range => {},
            .single => {
                start = applied.ranges[0].start;
                length = applied.ranges[0].len();
            },
            .not_satisfiable => {
                // 416 + Content-Range staged; no body (server frames CL 0).
                return;
            },
            .multiple => {
                // Multi-range unsupported — serve the whole thing as 200.
                rw.setStatus(200);
            },
        }

        setContentLength(rw, length);
        if (req.method == .head) return; // headers only
        return streamRange(h.io, opened.file, rw, start, length);
    }

    /// A directory with no index file: list it (opt-in, HTML-escaped) or 403.
    fn serveDirectory(h: *const Handler, req: *http.Server.Request, rw: *http.Server.ResponseWriter) Writer.Error!void {
        if (!h.options.directory_listing) return sendStatus(rw, 403);

        // Re-walk to the directory (the resolve pass opened it only to look for
        // an index). Same one-component-at-a-time, no-follow discipline.
        var dh = h.openDirWithinRoot(req.path) catch |e| switch (e) {
            error.Traversal, error.DotfileForbidden, error.InvalidByte, error.Forbidden => return sendStatus(rw, 403),
            error.Malformed => return sendStatus(rw, 400),
            error.TooLong => return sendStatus(rw, 414),
            error.NotFound, error.IsDir => return sendStatus(rw, 404),
            error.IoError => return sendStatus(rw, 500),
        };
        defer if (dh.owned) dh.dir.close(h.io);

        rw.setStatus(200);
        // NOT best-effort, for the same reason as the file path above: this
        // body IS HTML, and serving it unlabelled leaves the browser to sniff
        // it — with attacker-influenced file names inside it.
        rw.setHeader("Content-Type", "text/html; charset=utf-8") catch
            return failUnsafeResponse(rw);
        if (req.method == .head) return;

        const w = rw.writer();
        try w.writeAll("<!DOCTYPE html>\n<meta charset=\"utf-8\">\n<title>Index</title>\n<ul>\n");
        var it = dh.dir.iterate();
        while (it.next(h.io) catch null) |entry| {
            if (!h.options.serve_dotfiles and entry.name.len != 0 and entry.name[0] == '.') continue;
            try w.writeAll("<li>");
            try writeHtmlEscaped(w, entry.name);
            if (entry.kind == .directory) try w.writeAll("/");
            try w.writeAll("</li>\n");
        }
        try w.writeAll("</ul>\n");
    }

    const DirHandle = struct { dir: Dir, owned: bool };

    /// Walk the sanitized `raw_path` as directories (every component, no-follow
    /// by default), returning the target directory handle. `owned` is false
    /// only for the root itself (which the handler owns and must not close).
    fn openDirWithinRoot(h: *const Handler, raw_path: []const u8) (SanitizeError || ResolveError)!DirHandle {
        var buf: [max_path_bytes]u8 = undefined;
        const rel = try sanitizePath(raw_path, &buf, .{ .allow_dotfiles = h.options.serve_dotfiles });
        if (rel.len == 0) return .{ .dir = h.root, .owned = false };

        var parent: Dir = h.root;
        var owned = false;
        errdefer if (owned) parent.close(h.io);
        var it = mem.splitScalar(u8, rel, '/');
        while (it.next()) |seg| {
            const next = parent.openDir(h.io, seg, .{
                .follow_symlinks = h.options.follow_symlinks,
                .access_sub_paths = true,
                .iterate = true,
            }) catch |e| return mapOpenError(e);
            if (owned) parent.close(h.io);
            parent = next;
            owned = true;
        }
        return .{ .dir = parent, .owned = owned };
    }
};

/// The `http.Server.Handler`-shaped entry point: recover the `Handler` from
/// `req.context` and serve. Wire it as `.{ .handler = staticfiles.httpHandler,
/// .context = &your_handler }`.
pub fn httpHandler(req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
    const h: *const Handler = @ptrCast(@alignCast(req.context orelse return error.NoStaticFilesContext));
    return h.serve(req, rw);
}

// ── response helpers ─────────────────────────────────────────────────────────

/// A strong `ETag` from size + mtime: `"<size:x>-<mtime:x>"`, written into
/// `buf` (the caller's — `setHeader` copies at call time, so `buf` only has
/// to outlive the calls made with the returned slice, not the response).
/// Cheap (no file read) and changes on any content edit that moves size or
/// mtime. Documented alternative (content hash) is intentionally not the
/// default — see SPEC.md.
/// Widest `"{x}-{x}"` this can produce: two quotes, a separator, and two u64s
/// at 16 hex digits each. DERIVED rather than picked, because `bufPrint`'s
/// failure here is `catch unreachable` — a buffer one byte short would not be
/// an error, it would be a crash on the first large file. It was a bare 48
/// until 2026-08-12, which happened to be enough; shrinking it to 24 broke no
/// test, since nothing exercised a size or mtime big enough to need the room.
const etag_max = 2 + 1 + 2 * 16;

fn buildETag(buf: *[etag_max]u8, size: u64, mtime_s: i64) []const u8 {
    const m: u64 = if (mtime_s < 0) 0 else @intCast(mtime_s);
    return std.fmt.bufPrint(buf, "\"{x}-{x}\"", .{ size, m }) catch unreachable;
}

/// Content-Length is both consumed immediately by `setHeader` (parsed into an
/// integer, not retained) and copied at call time for every other header, so
/// a function-local buffer is fine either way.
fn setContentLength(rw: *http.Server.ResponseWriter, n: u64) void {
    // 20 digits is the widest decimal u64; same reasoning as `etag_max`, same
    // `catch unreachable` consequence for getting it wrong.
    var clen_buf: [20]u8 = undefined;
    const s = std.fmt.bufPrint(&clen_buf, "{d}", .{n}) catch unreachable;
    // The only `catch {}` on this surface that cannot drop anything:
    // `setHeader` intercepts `Content-Length` by name, parses it into
    // `declared_len` and returns before it ever reaches the copy store, so
    // `HeaderBytesExhausted` and `TooManyHeaders` are unreachable here; `s`
    // is a formatted integer, so `InvalidHeader` is too. Only `HeadersSent`
    // remains, and then the framing is already decided.
    rw.setHeader("Content-Length", s) catch {};
}

/// Set a bare status with an empty body (no representation headers).
fn sendStatus(rw: *http.Server.ResponseWriter, status: u16) Writer.Error!void {
    rw.setStatus(status);
    setContentLength(rw, 0);
}

/// A representation header that could not be set leaves a response it is not
/// safe to send — discard what was composed and answer 500 instead.
///
/// Used only where dropping the header is a downgrade rather than a lost
/// optimisation: `Content-Type` (a body served without it is MIME-sniffed by
/// the browser, which turns an uploaded text or image file into stored XSS)
/// and a configured `Cache-Control` (an operator that set `no-store` on
/// private files gets it stored by a shared cache instead). The alternative —
/// `catch {}` — is a 200 with the right body and the wrong, or absent,
/// safety headers, which is exactly the silent-drop shape this sweep closed.
fn failUnsafeResponse(rw: *http.Server.ResponseWriter) Writer.Error!void {
    // Nothing is on the wire at any of the call sites (no body byte has been
    // written yet), so this discards the half-composed representation. If a
    // middleware did flush early, `reset` refuses and the 500 below is inert —
    // there is nothing better available once the head has gone.
    rw.reset() catch {};
    return sendStatus(rw, 500);
}

/// Stream `length` bytes of `file` starting at `start` to the response body,
/// reading positionally in bounded chunks (never buffers the whole file). A
/// read failure after the head is on the wire aborts the connection.
fn streamRange(io: Io, file: File, rw: *http.Server.ResponseWriter, start: u64, length: u64) Writer.Error!void {
    var buf: [64 * 1024]u8 = undefined;
    const w = rw.writer();
    var off = start;
    var remaining = length;
    while (remaining != 0) {
        const want: usize = @intCast(@min(remaining, buf.len));
        const n = file.readPositionalAll(io, buf[0..want], off) catch return error.WriteFailed;
        if (n == 0) break; // file truncated under us; stop (framing then fails)
        try w.writeAll(buf[0..n]);
        off += n;
        remaining -= n;
    }
}

/// Minimal HTML text escaping for directory-listing entry names (defense
/// against markup / log injection via crafted filenames).
fn writeHtmlEscaped(w: *Writer, s: []const u8) Writer.Error!void {
    for (s) |c| switch (c) {
        '&' => try w.writeAll("&amp;"),
        '<' => try w.writeAll("&lt;"),
        '>' => try w.writeAll("&gt;"),
        '"' => try w.writeAll("&quot;"),
        '\'' => try w.writeAll("&#39;"),
        else => try w.writeByte(c),
    };
}

// ── tests ─────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "mimeType: table, overrides, case, default" {
    try testing.expectEqualStrings("text/html; charset=utf-8", mimeType("index.html", &.{}, "x"));
    try testing.expectEqualStrings("application/wasm", mimeType("app.WASM", &.{}, "x"));
    try testing.expectEqualStrings("image/png", mimeType("a/b/c.png", &.{}, "x"));
    try testing.expectEqualStrings("font/woff2", mimeType("f.woff2", &.{}, "x"));
    // No extension / unknown → default.
    try testing.expectEqualStrings("dflt", mimeType("README", &.{}, "dflt"));
    try testing.expectEqualStrings("dflt", mimeType("a.unknownext", &.{}, "dflt"));
    // Override wins over the table, case-insensitively.
    const ov = [_]MimeOverride{.{ .ext = "js", .media_type = "application/javascript" }};
    try testing.expectEqualStrings("application/javascript", mimeType("app.JS", &ov, "x"));
}

fn expectSan(raw: []const u8, expected: []const u8) !void {
    var buf: [max_path_bytes]u8 = undefined;
    const got = try sanitizePath(raw, &buf, .{});
    try testing.expectEqualStrings(expected, got);
}

test "sanitizePath: clean paths normalize" {
    try expectSan("/index.html", "index.html");
    try expectSan("/sub/dir/file.txt", "sub/dir/file.txt");
    try expectSan("/", ""); // root
    try expectSan("//a//b/", "a/b"); // collapse empties + trailing slash
    try expectSan("/a/./b", "a/b"); // drop `.`
    try expectSan("/a%2Fb.txt", "a/b.txt"); // %2F decodes to a real separator (but no traversal)
    try expectSan("/hello%20world.txt", "hello world.txt"); // %20 → space
}

test "sanitizePath: traversal + injection vectors all rejected" {
    var buf: [max_path_bytes]u8 = undefined;
    const bad = [_]struct { raw: []const u8, err: SanitizeError }{
        .{ .raw = "/../etc/passwd", .err = error.Traversal },
        .{ .raw = "/../../etc/passwd", .err = error.Traversal },
        .{ .raw = "/a/../../b", .err = error.Traversal },
        .{ .raw = "/..%2f..%2fetc%2fpasswd", .err = error.Traversal }, // encoded ../
        .{ .raw = "/%2e%2e/x", .err = error.Traversal }, // encoded ..
        .{ .raw = "/a/%2e%2e/%2e%2e/b", .err = error.Traversal },
        .{ .raw = "/foo%00.png", .err = error.InvalidByte }, // NUL truncation
        .{ .raw = "/a\x00b", .err = error.InvalidByte }, // literal NUL
        .{ .raw = "/..\\..\\x", .err = error.InvalidByte }, // backslash
        .{ .raw = "/%2e%2e%5cx", .err = error.InvalidByte }, // encoded backslash
        .{ .raw = "/.env", .err = error.DotfileForbidden },
        .{ .raw = "/.git/config", .err = error.DotfileForbidden },
        .{ .raw = "/%ZZ", .err = error.Malformed }, // bad percent-encoding
        .{ .raw = "/a%2", .err = error.Malformed }, // truncated percent
    };
    for (bad) |c| {
        try testing.expectError(c.err, sanitizePath(c.raw, &buf, .{}));
    }
    // `....//` is NOT a `..` segment (segment is literally "...."). It starts
    // with a dot, so by default it is refused as a dotfile — never a traversal.
    try testing.expectError(error.DotfileForbidden, sanitizePath("/....//x", &buf, .{}));
    // With dotfiles allowed it is a valid — if odd — filename, still no escape.
    try testing.expectEqualStrings("..../x", try sanitizePath("/....//x", &buf, .{ .allow_dotfiles = true }));
    // Dotfiles allowed when opted in.
    try testing.expectEqualStrings(".env", try sanitizePath("/.env", &buf, .{ .allow_dotfiles = true }));
}

test "sanitizePath: absolute-looking input cannot escape" {
    var buf: [max_path_bytes]u8 = undefined;
    // A leading slash is always stripped; a doubled one collapses. There is no
    // way to express an absolute filesystem path.
    try testing.expectEqualStrings("etc/passwd", try sanitizePath("/etc/passwd", &buf, .{}));
    try testing.expectEqualStrings("etc/passwd", try sanitizePath("///etc/passwd", &buf, .{}));
}

// ── fuzz: sanitizePath's own traversal-safety contract, on arbitrary bytes ─
//
// W2 A3 (F1): CLASS A, zero `testing.fuzz(` harnesses — this module was
// absent from `scripts/fuzz-sweep.sh`'s target list entirely, despite
// `sanitizePath`/`percentDecode` being the module's own doc comment's
// "make-or-break requirement": the request path is attacker-controlled and
// must never escape the root via percent-encoding, `..`, a NUL trick or a
// backslash. The hand-picked vectors above pin known attack shapes; this
// harness checks the CONTRACT itself holds for bytes nobody picked.
//
// Oracle: not "never panics". A successful `sanitizePath` result is a
// specific claim — every segment is non-empty, is not `.`/`..`, contains no
// NUL/backslash, and (unless opted in) does not start with `.`, and the
// whole result has no leading/trailing slash. The harness re-derives that
// claim from the output and checks it holds, which would catch e.g. a
// `..` that survived because it arrived alongside an unrelated encoding
// quirk the hand-picked vectors did not happen to combine.
test "fuzz: sanitizePath's traversal-safety contract holds for arbitrary bytes" {
    try testing.fuzz({}, fuzzSanitizePath, .{});
}

fn fuzzSanitizePath(_: void, smith: *testing.Smith) !void {
    // Length drawn BEFORE the bytes it bounds: every mutated byte the
    // fuzzer spends then lands inside the slice actually passed to
    // `sanitizePath`, instead of diluting mutations across a fixed 4096-byte
    // draw most of which gets discarded by a length picked afterward.
    var raw_buf: [4096]u8 = undefined;
    const raw_len = smith.valueRangeAtMost(u16, 0, raw_buf.len);
    smith.bytes(raw_buf[0..raw_len]);
    const raw = raw_buf[0..raw_len];
    const allow_dotfiles = smith.value(bool);

    var out: [max_path_bytes]u8 = undefined;
    const clean = sanitizePath(raw, &out, .{ .allow_dotfiles = allow_dotfiles }) catch return;

    // An empty result is a valid outcome (the doc comment: "means the
    // request targets the root directory itself") -- not a segment to check.
    if (clean.len == 0) return;
    try testing.expect(clean[0] != '/');
    try testing.expect(clean[clean.len - 1] != '/');
    var it = mem.splitScalar(u8, clean, '/');
    while (it.next()) |seg| {
        try testing.expect(seg.len != 0);
        try testing.expect(!mem.eql(u8, seg, "."));
        try testing.expect(!mem.eql(u8, seg, ".."));
        if (!allow_dotfiles) try testing.expect(seg[0] != '.');
        for (seg) |c| try testing.expect(c != 0 and c != '\\');
    }
}

// ── filesystem / serving tests ────────────────────────────────────────────────

/// Build a root with real files + a real out-of-root secret + a symlink into
/// it, run `body` with the handler, then clean up.
const Fixture = struct {
    tmp: testing.TmpDir,
    root: Dir,

    fn init() !Fixture {
        var tmp = testing.tmpDir(.{ .iterate = true });
        errdefer tmp.cleanup();
        const io = testing.io;
        // Layout under tmp:
        //   root/                  (the served root)
        //     index.html
        //     hello.txt
        //     sub/dir/file.txt
        //     .env                 (dotfile)
        //     escape -> ../secret.txt   (symlink escaping root)
        //   secret.txt             (OUT of root — the canonical /etc/passwd stand-in)
        try tmp.dir.writeFile(io, .{ .sub_path = "secret.txt", .data = "TOP SECRET" });
        var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
        errdefer root.close(io);
        try root.writeFile(io, .{ .sub_path = "index.html", .data = "<h1>home</h1>" });
        try root.writeFile(io, .{ .sub_path = "hello.txt", .data = "hello world" });
        try root.writeFile(io, .{ .sub_path = ".env", .data = "SECRET=1" });
        _ = try root.createDirPathOpen(io, "sub/dir", .{});
        try root.writeFile(io, .{ .sub_path = "sub/dir/file.txt", .data = "nested" });
        // A symlink inside root pointing OUT of root (to ../secret.txt).
        root.symLink(io, "../secret.txt", "escape", .{}) catch {};
        // A symlink inside root pointing to another file INSIDE root — safe
        // under `follow_symlinks = true` (unlike `escape` above).
        root.symLink(io, "hello.txt", "inside_link", .{}) catch {};
        return .{ .tmp = tmp, .root = root };
    }

    fn deinit(f: *Fixture) void {
        f.root.close(testing.io);
        f.tmp.cleanup();
    }
};

/// Drive one request through the real `Server.serveStream` codec against a
/// `staticfiles.Handler` and return the raw response bytes.
fn runRequest(handler: *Handler, wire: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(wire);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [256]u8 = undefined;
    var chunk_buf: [512]u8 = undefined;
    http.Server.serveStream(.{
        .handler = httpHandler,
        .context = handler,
        .server_name = "test",
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn get(handler: *Handler, path: []const u8, out_buf: []u8) []const u8 {
    var wire_buf: [512]u8 = undefined;
    const wire = std.fmt.bufPrint(&wire_buf, "GET {s} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", .{path}) catch unreachable;
    return runRequest(handler, wire, out_buf);
}

fn statusOf(resp: []const u8) u16 {
    // "HTTP/1.1 NNN ..."
    if (resp.len < 12) return 0;
    return std.fmt.parseInt(u16, resp[9..12], 10) catch 0;
}

/// A middleware that spends the response writer's 4 KiB header copy store
/// before `staticfiles` gets to compose anything — four hundred-byte headers
/// at a time until the store refuses, which leaves ~26 bytes: too few for
/// `Last-Modified` (42) or `Content-Type` (37).
///
/// This is what makes `HeaderBytesExhausted` reachable at all. It is not
/// exotic: one large `Content-Security-Policy` plus a couple of long
/// `Set-Cookie`s gets to the same place.
var test_leave_bytes: usize = 0;

fn budgetEatingHandler(req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
    // One header, sized exactly, so the remaining budget is a known number
    // rather than whatever a fill loop happened to leave. Reads the real
    // constant from `http` — the F8 fix is what makes that possible.
    var pad: [http.Server.header_copy_bytes]u8 = undefined;
    @memset(&pad, 'x');
    const name = "X-Pad";
    rw.setHeader(name, pad[0 .. http.Server.header_copy_bytes - name.len - test_leave_bytes]) catch unreachable;
    const h: *const Handler = @ptrCast(@alignCast(req.context orelse return error.NoStaticFilesContext));
    return h.serve(req, rw);
}

fn getUnderBudgetPressure(handler: *Handler, path: []const u8, out_buf: []u8) []const u8 {
    var wire_buf: [512]u8 = undefined;
    const wire = std.fmt.bufPrint(&wire_buf, "GET {s} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", .{path}) catch unreachable;
    var in: std.Io.Reader = .fixed(wire);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [256]u8 = undefined;
    var chunk_buf: [512]u8 = undefined;
    http.Server.serveStream(.{
        .handler = budgetEatingHandler,
        .context = handler,
        .server_name = "test",
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

test "serve: a Content-Type that cannot be set answers 500, never a sniffable body" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var out: [8192]u8 = undefined;

    // Positive control first: the same file, same handler shape, no budget
    // pressure — 200 with the label on it.
    const ok = get(&h, "/hello.txt", &out);
    try testing.expectEqual(@as(u16, 200), statusOf(ok));
    try testing.expect(mem.indexOf(u8, ok, "Content-Type: text/plain; charset=utf-8\r\n") != null);

    // Now with the copy store spent. `Content-Type` cannot be written, so the
    // body must NOT go out: an unlabelled `text/plain` file is MIME-sniffed
    // by the browser, which is how an uploaded .txt becomes stored XSS.
    test_leave_bytes = 20; // < "Content-Type" + "text/plain; charset=utf-8"
    defer test_leave_bytes = 0;
    var out2: [8192]u8 = undefined;
    const resp = getUnderBudgetPressure(&h, "/hello.txt", &out2);
    try testing.expectEqual(@as(u16, 500), statusOf(resp));
    // The whole half-composed representation is discarded, not just relabelled.
    try testing.expect(mem.indexOf(u8, resp, "Content-Type:") == null);
    try testing.expect(mem.indexOf(u8, resp, "X-Pad-") == null);
    // And above all: not one byte of the file.
    try testing.expect(mem.indexOf(u8, resp, "hello world") == null);
}

test "serve: a configured Cache-Control that cannot be set answers 500, not a quietly cacheable 200" {
    var fx = try Fixture.init();
    defer fx.deinit();
    // Long enough that it is the header which does not fit while
    // `Content-Type` still would — otherwise a 500 here would prove nothing,
    // since `Content-Type` failing further down produces one anyway.
    // Deliberately far longer than the budget left below, so that
    // Cache-Control is the ONLY header that cannot fit. An earlier version of
    // this test tried to tune the budget to a few bytes and proved nothing:
    // `conditional.apply` sets `ETag` between Cache-Control and Content-Type,
    // Content-Type then failed too, and the 500 it produced made the
    // mutation-with-`catch {}` pass. Generous margins, not tight arithmetic.
    const cc = "public, max-age=31536000" ++ (", no-transform" ** 30);
    var h = Handler.init(testing.io, fx.root, .{ .cache_control = cc });
    var out: [8192]u8 = undefined;

    // ~200 bytes is ample for Last-Modified (42), ETag, Content-Type (37) and
    // Accept-Ranges together, and hopeless for a 444-byte Cache-Control —
    // even after the rejected header leaks its own name into the store (the
    // copy store is a bump allocator that does not rewind; http audit F11).
    test_leave_bytes = 200;
    defer test_leave_bytes = 0;

    const resp = getUnderBudgetPressure(&h, "/hello.txt", &out);
    // Escalated: an operator asked for a specific storage policy and it could
    // not be applied, so the file is not served under the wrong one.
    try testing.expectEqual(@as(u16, 500), statusOf(resp));
    try testing.expect(mem.indexOf(u8, resp, "hello world") == null);
    // The discriminating assertion: Content-Type had room. Without the
    // escalation this response is a 200 carrying the body and the right
    // Content-Type, silently missing only its Cache-Control.
    try testing.expect(mem.indexOf(u8, resp, cc) == null);
}

test "serve: 200 with correct Content-Type, ETag, Last-Modified, body" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var out: [4096]u8 = undefined;
    const resp = get(&h, "/hello.txt", &out);
    try testing.expectEqual(@as(u16, 200), statusOf(resp));
    try testing.expect(mem.indexOf(u8, resp, "Content-Type: text/plain; charset=utf-8\r\n") != null);
    try testing.expect(mem.indexOf(u8, resp, "ETag: \"") != null);
    try testing.expect(mem.indexOf(u8, resp, "Last-Modified: ") != null);
    try testing.expect(mem.indexOf(u8, resp, "Accept-Ranges: bytes\r\n") != null);
    try testing.expect(mem.endsWith(u8, resp, "hello world"));
}

test "serve: directory request serves index.html" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var out: [4096]u8 = undefined;
    for ([_][]const u8{ "/", "/sub", "/sub/" }) |p| {
        const resp = get(&h, p, &out);
        // "/" serves root index; "/sub" has no index → 404 (no listing).
        if (mem.eql(u8, p, "/")) {
            try testing.expectEqual(@as(u16, 200), statusOf(resp));
            try testing.expect(mem.endsWith(u8, resp, "<h1>home</h1>"));
        }
    }
}

test "serve: nested path (positive control) is served" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var out: [4096]u8 = undefined;
    const resp = get(&h, "/sub/dir/file.txt", &out);
    try testing.expectEqual(@as(u16, 200), statusOf(resp));
    try testing.expect(mem.endsWith(u8, resp, "nested"));
}

test "serve: HEAD returns headers, no body" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var out: [4096]u8 = undefined;
    const resp = runRequest(&h, "HEAD /hello.txt HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out);
    try testing.expectEqual(@as(u16, 200), statusOf(resp));
    try testing.expect(mem.indexOf(u8, resp, "Content-Length: 11\r\n") != null);
    try testing.expect(mem.endsWith(u8, resp, "\r\n\r\n")); // no body after headers
}

test "serve: 404 on a missing file, 405 on POST" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var out: [4096]u8 = undefined;
    try testing.expectEqual(@as(u16, 404), statusOf(get(&h, "/nope.txt", &out)));
    const resp = runRequest(&h, "POST /hello.txt HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", &out);
    try testing.expectEqual(@as(u16, 405), statusOf(resp));
    try testing.expect(mem.indexOf(u8, resp, "Allow: GET, HEAD\r\n") != null);
}

test "serve: dotfile refused by default, served when opted in" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var out: [4096]u8 = undefined;
    var h_off = Handler.init(testing.io, fx.root, .{});
    try testing.expectEqual(@as(u16, 403), statusOf(get(&h_off, "/.env", &out)));
    var h_on = Handler.init(testing.io, fx.root, .{ .serve_dotfiles = true });
    const resp = get(&h_on, "/.env", &out);
    try testing.expectEqual(@as(u16, 200), statusOf(resp));
    try testing.expect(mem.endsWith(u8, resp, "SECRET=1"));
}

test "serve: TRAVERSAL TEETH — every vector refused, secret never read" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var out: [8192]u8 = undefined;
    // Each of these must NOT return "TOP SECRET" and must be a 4xx.
    const attacks = [_][]const u8{
        "/../secret.txt",
        "/../../etc/passwd",
        "/..%2f..%2fetc%2fpasswd",
        "/%2e%2e/secret.txt",
        "/....//secret.txt", // "...." is a real (nonexistent) name → 404, never escapes
        "/etc/passwd", // absolute stripped → looked up under root → 404
        "/foo%00.png", // NUL truncation
        "/..\\..\\secret.txt", // backslash separators
        "/escape", // symlink inside root → ../secret.txt (no-follow → refused)
        "/sub/../../secret.txt",
    };
    for (attacks) |a| {
        const resp = get(&h, a, &out);
        const st = statusOf(resp);
        try testing.expect(st >= 400 and st < 500); // refused
        try testing.expect(mem.indexOf(u8, resp, "TOP SECRET") == null); // never leaked
    }
    // Positive control alongside the attacks: a legit file still serves.
    try testing.expectEqual(@as(u16, 200), statusOf(get(&h, "/hello.txt", &out)));
}

test "serve: symlink escaping root refused (no-follow), the target is real" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const io = testing.io;
    // Prove the out-of-root secret actually exists and is reachable via the
    // symlink's target from tmp — i.e. the refusal is real containment, not a
    // missing file.
    var secret = try fx.tmp.dir.openFile(io, "secret.txt", .{});
    defer secret.close(io);
    var sbuf: [32]u8 = undefined;
    const n = try secret.readPositionalAll(io, &sbuf, 0);
    try testing.expectEqualStrings("TOP SECRET", sbuf[0..n]);

    var h = Handler.init(testing.io, fx.root, .{});
    var out: [4096]u8 = undefined;
    const resp = get(&h, "/escape", &out);
    try testing.expect(statusOf(resp) >= 400);
    try testing.expect(mem.indexOf(u8, resp, "TOP SECRET") == null);
}

test "serve: follow_symlinks=true serves an in-root symlink but still refuses an escaping one" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{ .follow_symlinks = true });
    var out: [4096]u8 = undefined;

    // Symlink target stays under root → verifyContained passes → served.
    const ok = get(&h, "/inside_link", &out);
    try testing.expectEqual(@as(u16, 200), statusOf(ok));
    try testing.expect(mem.endsWith(u8, ok, "hello world"));

    // Symlink target escapes root → verifyContained must still refuse it even
    // though symlinks are now followed.
    const escaped = get(&h, "/escape", &out);
    try testing.expect(statusOf(escaped) >= 400);
    try testing.expect(mem.indexOf(u8, escaped, "TOP SECRET") == null);
}

test "serve: 304 on matching If-None-Match / If-Modified-Since" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var out: [4096]u8 = undefined;

    // First fetch the ETag + Last-Modified.
    const first = get(&h, "/hello.txt", &out);
    const etag = extractHeader(first, "ETag: ") orelse return error.NoETag;
    const lm = extractHeader(first, "Last-Modified: ") orelse return error.NoLastModified;

    var wire: [512]u8 = undefined;
    var out2: [4096]u8 = undefined;
    const inm = std.fmt.bufPrint(&wire, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nIf-None-Match: {s}\r\nConnection: close\r\n\r\n", .{etag}) catch unreachable;
    const r_inm = runRequest(&h, inm, &out2);
    try testing.expectEqual(@as(u16, 304), statusOf(r_inm));
    try testing.expect(mem.indexOf(u8, r_inm, "TOP SECRET") == null);

    const ims = std.fmt.bufPrint(&wire, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nIf-Modified-Since: {s}\r\nConnection: close\r\n\r\n", .{lm}) catch unreachable;
    try testing.expectEqual(@as(u16, 304), statusOf(runRequest(&h, ims, &out2)));
}

test "serve: 206 + Content-Range on a range, 416 on unsatisfiable" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var out: [4096]u8 = undefined;
    // "hello world" is 11 bytes; bytes 0-4 → "hello".
    const r206 = runRequest(&h, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nRange: bytes=0-4\r\nConnection: close\r\n\r\n", &out);
    try testing.expectEqual(@as(u16, 206), statusOf(r206));
    try testing.expect(mem.indexOf(u8, r206, "Content-Range: bytes 0-4/11\r\n") != null);
    try testing.expect(mem.indexOf(u8, r206, "Content-Length: 5\r\n") != null);
    try testing.expect(mem.endsWith(u8, r206, "hello"));

    const r416 = runRequest(&h, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nRange: bytes=50-60\r\nConnection: close\r\n\r\n", &out);
    try testing.expectEqual(@as(u16, 416), statusOf(r416));
    try testing.expect(mem.indexOf(u8, r416, "Content-Range: bytes */11\r\n") != null);
}

test "serve: multi-range request falls back to a full 200, not a 206/416" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var out: [4096]u8 = undefined;
    // Two disjoint ranges — RFC 7233 permits ignoring Range entirely here.
    const resp = runRequest(&h, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nRange: bytes=0-2,4-6\r\nConnection: close\r\n\r\n", &out);
    try testing.expectEqual(@as(u16, 200), statusOf(resp));
    try testing.expect(mem.indexOf(u8, resp, "Content-Range:") == null);
    try testing.expect(mem.endsWith(u8, resp, "hello world")); // full body, not a slice
}

test "serve: directory listing (opt-in) escapes names, off = 403" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const io = testing.io;
    // A subdir with an injection-y filename and no index.
    _ = try fx.root.createDirPathOpen(io, "list", .{});
    try fx.root.writeFile(io, .{ .sub_path = "list/a<b>.txt", .data = "x" });

    var out: [8192]u8 = undefined;
    var h_off = Handler.init(io, fx.root, .{});
    try testing.expectEqual(@as(u16, 403), statusOf(get(&h_off, "/list/", &out)));

    var h_on = Handler.init(io, fx.root, .{ .directory_listing = true });
    const resp = get(&h_on, "/list/", &out);
    try testing.expectEqual(@as(u16, 200), statusOf(resp));
    // The raw "<b>" must not appear; the escaped form must.
    try testing.expect(mem.indexOf(u8, resp, "a<b>.txt") == null);
    try testing.expect(mem.indexOf(u8, resp, "a&lt;b&gt;.txt") != null);
}

test "resolveFile standalone: opens within root, refuses escape" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const io = testing.io;
    var opened = try resolveFile(fx.root, io, "/sub/dir/file.txt", .{});
    defer opened.close(io);
    try testing.expectEqual(File.Kind.file, opened.stat.kind);
    var b: [16]u8 = undefined;
    const n = try opened.file.readPositionalAll(io, &b, 0);
    try testing.expectEqualStrings("nested", b[0..n]);

    try testing.expectError(error.Traversal, resolveFile(fx.root, io, "/../secret.txt", .{}));
    try testing.expectError(error.Forbidden, resolveFile(fx.root, io, "/escape", .{}));
    try testing.expectError(error.NotFound, resolveFile(fx.root, io, "/missing", .{}));
}

/// Pull a header value (up to CRLF) out of a raw response, for the conditional
/// tests. `prefix` includes the "Name: " part.
fn extractHeader(resp: []const u8, prefix: []const u8) ?[]const u8 {
    const i = mem.indexOf(u8, resp, prefix) orelse return null;
    const start = i + prefix.len;
    const end = mem.indexOfScalarPos(u8, resp, start, '\r') orelse return null;
    return resp[start..end];
}

// ── external anchor: starlette.staticfiles (independent Range/ETag/       ──
// ── conditional-request oracle)                                          ──
//
// `starlette` 1.3.1 (Python 3.14.4) implements the same Range/ETag/
// conditional-request semantics independently (`starlette.responses.
// FileResponse` for Range/If-Range, `starlette.staticfiles.StaticFiles.
// is_not_modified` for If-None-Match/If-Modified-Since). Run here purely as
// a black-box test oracle (root `NOTICE` §0's carve-out applies — no
// starlette source was consulted as a design reference while writing this
// module, only its observable request/response behavior read here for the
// FIRST time during this audit; confirmed via `check-catalog`, no NOTICE
// entry needed).
//
// Captured ONCE, offline, via a throwaway Python script driving
// `starlette.staticfiles.StaticFiles` directly over the ASGI interface (a
// plain in-process async function call with hand-built scope/receive/send
// callables — no `httpx`, no TestClient, no socket, even at capture time).
// Fixture: a single 11-byte file `hello.txt` = "hello world", mtime pinned
// to a fixed Unix timestamp (1700000000) so Last-Modified/ETag are
// reproducible. Reproduction: see this campaign's session notes for the
// exact script.
//
// Our `buildETag` (size+mtime, hex) and starlette's (`md5(mtime-size)`,
// hex) are two independently-chosen, RFC-9110-legal validator schemes —
// RFC 9110 §8.8.3 only requires an ETag to be a quoted opaque string that
// changes when the representation does, not any particular construction.
// The tests below therefore compare STATUS CODES, `Content-Range`,
// `Content-Length` and body bytes (all directly comparable), never literal
// ETag values — a matching-ETag test instead round-trips OUR OWN computed
// ETag back as `If-None-Match`, which is a same-implementation check, not
// an external anchor (already covered by the existing "serve: 304 on
// matching If-None-Match / If-Modified-Since" test above).
//
// ── divergence ledger ────────────────────────────────────────────────────
//
// 1. `If-None-Match: *` (wildcard). RFC 9110 §13.1.2 defines `*` as
//    matching "any current representation of the target resource" — a GET
//    for an existing resource with `If-None-Match: *` MUST get 304. Our
//    `http.conditional.listMatches` implements this (`std.mem.eql(u8, elem,
//    "*")` short-circuits to a match; see conditional.zig's "evaluate:
//    If-None-Match ... star" test). Captured: starlette's
//    `is_not_modified` does `etag in [tag.strip().removeprefix("W/") for
//    tag in if_none_match.split(",")]` — a literal string-membership test
//    that never special-cases `"*"`, so `If-None-Match: *` against an
//    existing file returns a plain 200, NOT 304. This is a real RFC 9110
//    §13.1.2 conformance gap in starlette's `StaticFiles`, found by this
//    audit. Judgement: our wildcard handling is correct per spec; NOT
//    changed to match starlette's gap. See the divergence test below.
//
// 2. A `Range` header with a unit other than `bytes` (e.g. malformed/
//    unrecognized). RFC 7233 §2.1 / §3.1: "An origin server MUST ignore a
//    Range header field that contains a range unit it does not
//    understand" — the request is served as if `Range` were absent (200).
//    Our `http.range.parse` reports `error.InvalidUnit`, and `apply`'s
//    caller (this module's `sendFile`) treats any parse error identically
//    to "no Range" (falls through to `.no_range`, full 200). Captured:
//    starlette's `FileResponse._parse_range_header` instead raises
//    `MalformedRangeHeader("Only support bytes range")`, which
//    `starlette.staticfiles` (via `FileResponse.__call__`) turns into an
//    explicit `400 Bad Request` + a plain-text body. Judgement: RFC 7233's
//    "MUST ignore" is unambiguous for an unrecognized UNIT (as opposed to a
//    malformed byte-range-set under the recognized `bytes` unit, where
//    server discretion is more defensible) — starlette's 400 here is the
//    non-compliant side of this divergence. NOT adopted; we keep the
//    RFC-mandated ignore→200. See the divergence test below.
//
// 3. Multi-range requests. Starlette's `FileResponse` fully implements
//    `multipart/byteranges` (RFC 7233 §4.1) for a request with more than
//    one satisfiable range — captured: two disjoint ranges → 206,
//    `Content-Type: multipart/byteranges; boundary=...`, a real multipart
//    body. This module deliberately does NOT implement multipart ranges
//    (see the module doc: "a documented amplification vector... out of
//    scope") — RFC 7233 §6.1 explicitly permits ignoring `Range` entirely
//    in this case, which is what "serve: multi-range request falls back to
//    a full 200" (above) already tests. Scoped down per campaign policy
//    ("do not adopt behaviour we do not implement") — no golden to freeze
//    for functionality we don't have; starlette's fuller implementation is
//    simply out of our scope, not a bug on either side.
//
// 4. `If-Match` / `If-Unmodified-Since` (412 Precondition Failed).
//    Starlette's `StaticFiles.is_not_modified` implements ONLY the
//    not-modified (304) direction — there is no 412 code path anywhere in
//    `starlette.staticfiles` or `FileResponse`; `If-Match`/
//    `If-Unmodified-Since` request headers are read nowhere in either
//    (captured: both send a 200 as if the headers were absent). This
//    module DOES implement 412 via `http.conditional.apply` (see
//    conditional.zig's "evaluate: If-Match hit / miss / star / weak-current"
//    tests and this file's own SPEC.md). No oracle is available for this
//    half of the module at all — scoped down per campaign policy; our
//    existing in-house tests are the only anchor for 412 and stay as-is.
//
// 5. `If-Range` — FIXED 2026-08-02, was a real gap this comparison found.
//    Neither `http.range` nor this module read `If-Range` at all, so a
//    `Range` was honored unconditionally. A client resuming a download
//    ("if the file changed, send me the whole thing instead of a stale
//    byte range") silently got a range of whatever the CURRENT file holds
//    and could splice bytes from two file versions together.
//    `http.conditional.ifRangeAllows` now gates the range path; the canary
//    test below became the conformance test for it. One deliberate
//    divergence from starlette: it compares the `If-Range` value with plain
//    string equality against the current ETag or Last-Modified
//    (`_should_use_range`), which accepts a weak entity-tag and rejects a
//    date written in a different-but-equivalent HTTP-date format. We follow
//    RFC 9110 §13.1.5 instead — strong comparison for tags, parsed-date
//    equality for dates.

test "interop (starlette oracle): single/open-ended/suffix ranges agree on Content-Range, Content-Length, and body bytes" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var out: [4096]u8 = undefined;

    // Captured "3": Range: bytes=0-4 on the 11-byte "hello world" fixture →
    // 206, Content-Range: bytes 0-4/11, Content-Length: 5, body "hello".
    const single = runRequest(&h, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nRange: bytes=0-4\r\nConnection: close\r\n\r\n", &out);
    try testing.expectEqual(@as(u16, 206), statusOf(single));
    try testing.expect(mem.indexOf(u8, single, "Content-Range: bytes 0-4/11\r\n") != null);
    try testing.expect(mem.indexOf(u8, single, "Content-Length: 5\r\n") != null);
    try testing.expect(mem.endsWith(u8, single, "hello"));

    // Captured "4": Range: bytes=6- (open-ended) → 206, Content-Range:
    // bytes 6-10/11, body "world".
    const open = runRequest(&h, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nRange: bytes=6-\r\nConnection: close\r\n\r\n", &out);
    try testing.expectEqual(@as(u16, 206), statusOf(open));
    try testing.expect(mem.indexOf(u8, open, "Content-Range: bytes 6-10/11\r\n") != null);
    try testing.expect(mem.endsWith(u8, open, "world"));

    // Captured "5": Range: bytes=-5 (last 5 bytes) → identical result to
    // "6-" on an 11-byte file (both resolve to bytes 6-10).
    const suffix = runRequest(&h, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nRange: bytes=-5\r\nConnection: close\r\n\r\n", &out);
    try testing.expectEqual(@as(u16, 206), statusOf(suffix));
    try testing.expect(mem.indexOf(u8, suffix, "Content-Range: bytes 6-10/11\r\n") != null);
    try testing.expect(mem.endsWith(u8, suffix, "world"));

    // Captured "7": Range: bytes=0-100 (end past EOF) → clamps to the
    // actual length, 206, Content-Range: bytes 0-10/11, full body.
    const clamped = runRequest(&h, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nRange: bytes=0-100\r\nConnection: close\r\n\r\n", &out);
    try testing.expectEqual(@as(u16, 206), statusOf(clamped));
    try testing.expect(mem.indexOf(u8, clamped, "Content-Range: bytes 0-10/11\r\n") != null);
    try testing.expect(mem.endsWith(u8, clamped, "hello world"));
}

test "interop (starlette oracle): HEAD + Range still answers 206 with the range's Content-Length and no body" {
    // Captured "23": HEAD with Range: bytes=0-4 → 206, Content-Length: 5,
    // empty body. Not previously covered by this module's own tests (the
    // existing HEAD test has no Range, the existing Range tests are all
    // GET).
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var out: [4096]u8 = undefined;
    const resp = runRequest(&h, "HEAD /hello.txt HTTP/1.1\r\nHost: t\r\nRange: bytes=0-4\r\nConnection: close\r\n\r\n", &out);
    try testing.expectEqual(@as(u16, 206), statusOf(resp));
    try testing.expect(mem.indexOf(u8, resp, "Content-Range: bytes 0-4/11\r\n") != null);
    try testing.expect(mem.indexOf(u8, resp, "Content-Length: 5\r\n") != null);
    try testing.expect(mem.endsWith(u8, resp, "\r\n\r\n")); // no body after headers
}

test "interop (starlette oracle) DIVERGES: If-None-Match: * gets 304 from us (RFC 9110 §13.1.2), 200 from starlette's StaticFiles (ledger #1)" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var out: [4096]u8 = undefined;
    var out2: [4096]u8 = undefined;

    const first = get(&h, "/hello.txt", &out);
    try testing.expectEqual(@as(u16, 200), statusOf(first));

    const resp = runRequest(&h, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nIf-None-Match: *\r\nConnection: close\r\n\r\n", &out2);
    // We correctly treat `*` as "matches any current representation" → 304.
    // Captured: starlette's StaticFiles answered 200 here (a real
    // conformance gap in starlette, not adopted).
    try testing.expectEqual(@as(u16, 304), statusOf(resp));
    try testing.expect(mem.indexOf(u8, resp, "TOP SECRET") == null);
}

test "interop (starlette oracle) DIVERGES: a Range with an unrecognized unit is ignored (RFC 7233 MUST) -> 200, not starlette's 400 (ledger #2)" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var out: [4096]u8 = undefined;

    // Captured "18": Range: lines=0-4 (not "bytes") -> starlette answers 400
    // "Only support bytes range". RFC 7233 explicitly requires ignoring an
    // unrecognized unit, which is what we do: full 200, whole body, no
    // Content-Range.
    const resp = runRequest(&h, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nRange: lines=0-4\r\nConnection: close\r\n\r\n", &out);
    try testing.expectEqual(@as(u16, 200), statusOf(resp));
    try testing.expect(mem.indexOf(u8, resp, "Content-Range:") == null);
    try testing.expect(mem.endsWith(u8, resp, "hello world"));
}

// This was the "GAP CANARY" test for ledger #5: it pinned the pre-fix
// behavior (a stale `If-Range` was ignored and the Range honored anyway) so
// it would fail the moment support landed. It did exactly that, and is now
// the conformance test for the implementation — kept, not deleted, because
// the starlette comparison that found the gap is what makes it an anchor.
test "If-Range (RFC 9110 §13.1.5): a stale validator falls back to a full 200, a current one keeps the 206" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var out: [4096]u8 = undefined;
    var wire: [512]u8 = undefined;

    // Stale entity-tag: the client's copy is not this file, so it gets the
    // whole resource — and no Content-Range, since no range was applied.
    const stale = runRequest(&h, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nRange: bytes=0-4\r\n" ++
        "If-Range: \"not-a-real-etag\"\r\nConnection: close\r\n\r\n", &out);
    try testing.expectEqual(@as(u16, 200), statusOf(stale));
    try testing.expect(mem.indexOf(u8, stale, "Content-Range:") == null);
    try testing.expect(mem.endsWith(u8, stale, "hello world"));

    // The current validators, read off a plain response, must let the range
    // through — otherwise "always 200" would pass the check above vacuously.
    const first = runRequest(&h, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out);
    const etag = extractHeader(first, "ETag: ") orelse return error.NoETag;
    const lm = extractHeader(first, "Last-Modified: ") orelse return error.NoLastModified;

    for ([_][]const u8{ etag, lm }) |validator| {
        const req = std.fmt.bufPrint(&wire, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nRange: bytes=0-4\r\n" ++
            "If-Range: {s}\r\nConnection: close\r\n\r\n", .{validator}) catch unreachable;
        var buf: [4096]u8 = undefined;
        const resp = runRequest(&h, req, &buf);
        try testing.expectEqual(@as(u16, 206), statusOf(resp));
        try testing.expect(mem.endsWith(u8, resp, "hello"));
    }

    // A weak entity-tag is not a strong validator: §13.1.5 says ignore the
    // Range even though the tag's value is the current one.
    const weak = std.fmt.bufPrint(&wire, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nRange: bytes=0-4\r\n" ++
        "If-Range: W/{s}\r\nConnection: close\r\n\r\n", .{etag}) catch unreachable;
    var wbuf: [4096]u8 = undefined;
    const weak_resp = runRequest(&h, weak, &wbuf);
    try testing.expectEqual(@as(u16, 200), statusOf(weak_resp));

    // An If-Range with no Range at all changes nothing.
    const no_range = runRequest(&h, "GET /hello.txt HTTP/1.1\r\nHost: t\r\n" ++
        "If-Range: \"not-a-real-etag\"\r\nConnection: close\r\n\r\n", &out);
    try testing.expectEqual(@as(u16, 200), statusOf(no_range));
    try testing.expect(mem.endsWith(u8, no_range, "hello world"));
}

test "buildETag / setContentLength: the widest possible values still fit" {
    // The buffers behind both are sized by derivation and their overflow path
    // is `catch unreachable`, so being wrong is a crash rather than an error.
    // Nothing exercised that: shrinking the ETag buffer from 48 to 24 broke no
    // test, because every fixture used small sizes and recent mtimes. These
    // two calls are the widest inputs the types admit.
    var etag_buf: [etag_max]u8 = undefined;
    const widest = buildETag(&etag_buf, std.math.maxInt(u64), std.math.maxInt(i64));
    try std.testing.expectEqualStrings("\"ffffffffffffffff-7fffffffffffffff\"", widest);
    try std.testing.expect(widest.len <= etag_max);

    var clen_buf: [20]u8 = undefined;
    const n = try std.fmt.bufPrint(&clen_buf, "{d}", .{@as(u64, std.math.maxInt(u64))});
    try std.testing.expectEqualStrings("18446744073709551615", n);
}
