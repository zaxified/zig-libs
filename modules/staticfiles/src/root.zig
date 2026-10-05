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
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Path-traversal-safe static file handler over `http` — MIME by extension, ETag/conditional 304, byte-range 206/416; symlinks not followed, dotfiles refused by default",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
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
    /// Emit `ETag` as a STRONG validator (`"<size:hex>-<mtime_seconds:hex>"`,
    /// no `W/` prefix) instead of the default weak one. Default false (A1
    /// F5, round-2 Q8 — safe default + opt-in for the exception): the tag's
    /// granularity is one SECOND of `mtime`, so a same-second, same-size
    /// edit (an atomic `rename` over a file of identical length — a config
    /// flip, a redeployed `.json` with one boolean changed) does not change
    /// the strong tag despite RFC 9110 §8.8.1 requiring a strong validator
    /// to change on every representation edit, and a strong tag authorizes
    /// `If-Range` to splice bytes from two file versions into one response
    /// (see SPEC.md). A weak tag closes both: `ifRangeAllows` rejects a weak
    /// validator outright (falls back to a full 200, never a spliced 206),
    /// and `If-None-Match`'s weak comparison is exactly as forgiving as
    /// before. **The cost:** `If-Range`-conditioned byte-range RESUME never
    /// succeeds for any client (weak validators cannot authorize a range
    /// response at all, RFC 9110 §13.1.5) — set this to `true` only when
    /// resumable downloads matter more than the same-second edit gap, and
    /// preferably alongside a deploy process that does not do same-size
    /// same-second in-place edits.
    strong_etag: bool = false,
    /// Redirect (301) a directory URL missing its trailing slash to the
    /// slash-terminated form, matching Go `net/http` `FileServer` — the
    /// model this module names itself after — and nginx. Default true (A1
    /// F17, round-2 Q8 — safe default + opt-out): without this, `/sub` and
    /// `/sub/` silently serve the identical `sub/index.html` under two
    /// different URLs, and any relative link/asset INSIDE that page (e.g.
    /// `<link href="style.css">`) resolves against whichever one the
    /// browser's address bar shows — correct only from `/sub/`, one
    /// directory too high from `/sub`. Set false to keep the pre-fix dual
    /// serving (e.g. a caller with its own, different rules for bare vs.
    /// slash-terminated directory URLs upstream of this handler).
    redirect_to_trailing_slash: bool = true,
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

/// Largest leaf/index name `Opened.mimeName()` will hold in full. Filesystem
/// leaf names fit `NAME_MAX` (255 on Linux); a longer `Options.index` is a
/// caller misconfiguration, truncated defensively rather than overflowed.
pub const mime_name_max: usize = 255;

/// An opened regular file within the root, plus the metadata a response needs.
/// The caller owns `file` and must `close` it.
pub const Opened = struct {
    file: File,
    stat: File.Stat,
    /// Backing storage for `mimeName()` — NOT the leaf name's slice
    /// borrowed from a caller's scratch buffer. (A1 F2: the previous
    /// `mime_name: []const u8` field aliased a `resolveFile`-local `buf`,
    /// so it dangled the moment `resolveFile` returned — a read of freed
    /// stack after any intervening call. Copying the bytes into the struct
    /// itself, and computing the slice fresh from `self` on every read,
    /// means `mimeName()` is safe no matter where `Opened` has moved to.)
    mime_name_buf: [mime_name_max]u8 = undefined,
    mime_name_len: u8 = 0,

    fn setMimeName(o: *Opened, name: []const u8) void {
        const n = @min(name.len, mime_name_max);
        @memcpy(o.mime_name_buf[0..n], name[0..n]);
        o.mime_name_len = @intCast(n);
    }

    /// The name whose extension selects `Content-Type` (the index file name
    /// when a directory resolved to its index). Safe to call any time after
    /// `resolveFile`/`openWithinRoot` returns.
    pub fn mimeName(o: *const Opened) []const u8 {
        return o.mime_name_buf[0..o.mime_name_len];
    }

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
    return openWithinRootAs(root, io, rel, opts, false);
}

/// `openWithinRoot`, told whether the request named a DIRECTORY (its path
/// ended in `/`, which `sanitizePath` drops): then the leaf is opened as a
/// directory only, so a regular file there is `NotFound` (POSIX `ENOTDIR`),
/// never served at `/file.txt/`.
fn openWithinRootAs(root: Dir, io: Io, rel: []const u8, opts: Options, want_dir: bool) ResolveError!Opened {
    const follow = opts.follow_symlinks;

    if (rel.len == 0) return openIndex(root, root, io, opts);

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
            // Layer-2 hardening (A1 F3): reject `..` here too, independent
            // of `sanitizePath`. `openat(dirfd, "..")` is a legal syscall
            // that neither `O_NOFOLLOW` nor `resolve_beneath` stops (it is
            // not a symlink), and `Dir.OpenOptions` — unlike
            // `OpenFileOptions` — has no `resolve_beneath` field at all. So
            // a caller who reaches this `pub` function with an unsanitized
            // `rel` walks straight out of root, one `..` at a time, with
            // nothing here to stop it.
            if (mem.eql(u8, seg, "..")) return error.Forbidden;
            const next = parent.openDir(io, seg, .{
                .follow_symlinks = follow,
                .access_sub_paths = true,
            }) catch |e| {
                // A1 F16: a symlinked DIRECTORY component under no-follow
                // came back 404, while a symlinked LEAF file came back the
                // documented 403 — `openDir`'s own error alone doesn't
                // reliably say "refused because it's a symlink" the way
                // `openFile`'s `error.SymLinkLoop` does. Ask directly with a
                // no-follow stat (cheap, and only on this already-slow error
                // path) so both shapes answer the same way.
                if (!follow and e != error.NameTooLong and isSymlinkComponent(parent, io, seg)) return error.Forbidden;
                return mapOpenError(e);
            };
            if (parent_owned) parent.close(io);
            parent = next;
            parent_owned = true;
        }
    }

    // Same hardening for the leaf itself (`rel == ".."` with no slash).
    if (mem.eql(u8, leaf, "..")) return error.Forbidden;

    // The leaf: try it as a regular file first. `allow_directory = false` turns
    // a directory target into `error.IsDir` (cheaply on Windows, one fstat
    // elsewhere) instead of handing back a directory fd. A request that named
    // a directory goes straight to the directory branch.
    const leaf_file: Io.File.OpenError!Io.File = if (want_dir) error.IsDir else parent.openFile(io, leaf, .{
        .follow_symlinks = follow,
        .allow_directory = false,
        .resolve_beneath = true,
    });
    const file = leaf_file catch |e| switch (e) {
        error.IsDir => {
            // A directory: descend into it and serve its index.
            var d = parent.openDir(io, leaf, .{
                .follow_symlinks = follow,
                .access_sub_paths = true,
            }) catch |de| {
                // Reached without opening the leaf as a file (`want_dir`):
                // a symlinked leaf answers 403 here too, as it does there.
                if (want_dir and !follow and de != error.NameTooLong and isSymlinkComponent(parent, io, leaf)) return error.Forbidden;
                return mapOpenError(de);
            };
            defer d.close(io);
            return openIndex(d, root, io, opts);
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
    var o: Opened = .{ .file = f, .stat = st };
    o.setMimeName(leaf);
    return o;
}

/// Open `dir`'s configured index file as a regular file, or `error.IsDir` when
/// there is no index (index disabled, missing, or itself a directory).
/// `root` is the scan root (distinct from `dir` whenever the caller already
/// descended into a subdirectory) — needed to verify containment when
/// `opts.follow_symlinks` is on (A1 F1).
fn openIndex(dir: Dir, root: Dir, io: Io, opts: Options) ResolveError!Opened {
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
    // A1 F1: the walk to `dir` may have crossed a symlinked component (or
    // `dir` itself may be `root` with a symlinked `index.html`) when
    // `follow_symlinks` is on, so this open can succeed on a file OUTSIDE
    // `root` even though every individual `openDir`/`openFile` call along
    // the way "succeeded". Verify containment exactly like the single-leaf-
    // file path (`openWithinRoot` above) already does — this call was the
    // gap: index lookups never ran it at all.
    if (opts.follow_symlinks) verifyContained(root, io, &f) catch {
        f.close(io);
        return error.Forbidden;
    };
    var o: Opened = .{ .file = f, .stat = st };
    o.setMimeName(opts.index);
    return o;
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

/// Like `verifyContained`, but for a directory handle — used by the
/// directory-listing path (A1 F1's 4th shape), which has no single opened
/// file to check.
fn verifyContainedDir(root: Dir, io: Io, d: Dir) error{Escaped}!void {
    var root_buf: [Dir.max_path_bytes]u8 = undefined;
    var dir_buf: [Dir.max_path_bytes]u8 = undefined;
    const root_n = root.realPath(io, &root_buf) catch return error.Escaped;
    const dir_n = d.realPath(io, &dir_buf) catch return error.Escaped;
    const root_path = root_buf[0..root_n];
    const dir_path = dir_buf[0..dir_n];
    if (!mem.startsWith(u8, dir_path, root_path)) return error.Escaped;
    if (dir_path.len > root_path.len and dir_path[root_path.len] != '/')
        return error.Escaped;
}

/// Best-effort: is `seg` (a single path component under `parent`) a
/// symlink? Used only on an already-failed `openDir`'s error path (A1 F16)
/// to tell "refused because it's a symlink" apart from "doesn't exist" —
/// `statFile` with `follow_symlinks = false` is a single stat-family call,
/// never blocks (unlike opening e.g. a FIFO would), and any failure here
/// just falls back to the original error mapping.
///
/// Never called after `error.NameTooLong`: such a segment cannot be a
/// symlink, and zig 0.16's Linux `dirStatFile` treats `ENAMETOOLONG` as a
/// programmer bug -- a Debug build PANICS on `/dir/<256 bytes>/x` (Go's
/// net/http oracle, 2026-10-05; Release maps it to `Unexpected`).
fn isSymlinkComponent(parent: Dir, io: Io, seg: []const u8) bool {
    const st = parent.statFile(io, seg, .{ .follow_symlinks = false }) catch return false;
    return st.kind == .sym_link;
}

fn mapOpenError(e: anyerror) error{ NotFound, Forbidden, IoError } {
    return switch (e) {
        error.FileNotFound, error.NotDir => error.NotFound,
        // A1 F13 (round-2 Q5): a single path segment over `NAME_MAX` fell
        // into `else` -> 500, read by the client as a server fault, when it
        // is entirely client-supplied input. RFC 9110 §15.5.15's 414 is
        // about a target URI longer than THIS SERVER is willing to
        // interpret — the request line / header budgets (`max_header_bytes`
        // etc.) already answer that one level up, before this handler ever
        // runs; a segment too long for the FILESYSTEM to hold is a
        // different fact; no file of that name can exist, so it is exactly
        // what every other "this name cannot exist" case here maps to.
        error.NameTooLong => error.NotFound,
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
    return openWithinRootAs(root, io, rel, opts, namesDirectory(raw_path));
}

/// Does the raw request path name a directory -- end in `/` once decoded,
/// ignoring trailing `.` segments (`/a/`, `/a%2f`, `/a/.`)? `sanitizePath`
/// drops that slash, and without this a regular file answered at
/// `/secret.txt/` as at `/secret.txt` -- a rule matching the exact path in
/// front of the server is walked around by one character (Go's net/http
/// oracle, 2026-10-05: Go redirects, nginx/Apache/POSIX say not found).
/// Undecodable input answers false; `sanitizePath` refuses it anyway.
fn namesDirectory(raw: []const u8) bool {
    var buf: [max_path_bytes]u8 = undefined;
    const n = percentDecode(raw, &buf) catch return false;
    var d = buf[0..n];
    while (mem.endsWith(u8, d, "/.")) d = d[0 .. d.len - 1];
    return d.len > 0 and d[d.len - 1] == '/';
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

        var via_directory = false;
        var resolved = h.resolveForServe(req.path, &via_directory) catch |e| switch (e) {
            error.Traversal, error.DotfileForbidden, error.InvalidByte, error.Forbidden => return sendStatus(rw, 403),
            error.Malformed => return sendStatus(rw, 400),
            error.TooLong => return sendStatus(rw, 414),
            error.NotFound => return sendStatus(rw, 404),
            error.IoError => return sendStatus(rw, 500),
        };
        // A1 F17 (round-2 Q8): a directory route reached by a URL missing
        // its trailing slash is canonicalized with a redirect BEFORE
        // anything is served at the bare URL — matching Go `net/http`
        // `FileServer` / nginx, and avoiding the "relative links inside the
        // page resolve one directory too high" class of bug a silent dual
        // serve invites.
        if (via_directory and h.options.redirect_to_trailing_slash and
            (req.path.len == 0 or req.path[req.path.len - 1] != '/'))
        {
            switch (resolved) {
                .opened => |*opened| opened.close(h.io),
                .dir_listing => |dh| {
                    var dirhandle = dh;
                    if (dirhandle.owned) dirhandle.dir.close(h.io);
                },
            }
            return redirectTrailingSlash(req, rw);
        }
        switch (resolved) {
            .opened => |*opened| {
                defer opened.close(h.io);
                return h.sendFile(req, rw, opened);
            },
            .dir_listing => |dh| {
                var dirhandle = dh;
                defer if (dirhandle.owned) dirhandle.dir.close(h.io);
                return h.serveDirectory(req, rw, dirhandle);
            },
        }
    }

    /// Emit the representation headers + body (or 304/412/206/416) for an
    /// already-opened file.
    ///
    /// Public so a caller who already holds a resolved `Opened` (e.g.
    /// `resolveFile`'d up front to compose an app-specific 404 page, or one
    /// opened by some other means entirely) can serve it directly without a
    /// second resolve inside `serve`. Ownership: `opened` is borrowed —
    /// `sendFile` never closes it, exactly like the internal `serve` call
    /// site above (`defer opened.close(h.io)` stays the caller's job).
    /// Same status-mapping and never-panics contract as `serve`, but the
    /// 403/404/etc. mapping for a *failed resolve* is the caller's own
    /// responsibility — this only covers what happens after a resolve
    /// already succeeded.
    pub fn sendFile(h: *const Handler, req: *http.Server.Request, rw: *http.Server.ResponseWriter, opened: *Opened) Writer.Error!void {
        return h.sendFileTagged(req, rw, opened, null);
    }

    /// `sendFile` with the entity tag given rather than derived from size
    /// and mtime -- a content hash, say, which is a STRONG validator in the
    /// full RFC 9110 §8.8.1 sense (it changes exactly when the bytes do), so
    /// it may authorize `If-Range`. `etag` includes its quotes (and `W/` if
    /// weak); null is `sendFile`'s own tag.
    pub fn sendFileTagged(h: *const Handler, req: *http.Server.Request, rw: *http.Server.ResponseWriter, opened: *Opened, etag_in: ?[]const u8) Writer.Error!void {
        const total = opened.stat.size;
        const mtime_s = opened.stat.mtime.toSeconds();
        // Locals, not thread-locals: setHeader copies the bytes into its own
        // header_buf at call time, so these only need to outlive the calls
        // below, not the response.
        var etag_buf: [etag_max]u8 = undefined;
        var lastmod_buf: [http.Server.http_date_len]u8 = undefined;
        const etag = etag_in orelse buildETag(&etag_buf, total, mtime_s, !h.options.strong_etag);

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
        // NOT a silent drop, and not an escalation either — see below.
        // `conditional.apply` stages the 304 status BEFORE it writes the
        // validator (`http/src/conditional.zig:223-226`), so a `setHeader`
        // failure there leaves 304 staged while the error sends this handler
        // down the 200 path: the measured wire was `304 Not Modified` with
        // `Content-Length: 11` for a body the server core then suppressed,
        // and no `ETag` for the client to revalidate with next time. Framing
        // that contradicts itself, and a validator-less 304 that guarantees
        // the same failure on the next request.
        //
        // Reachable through header-TABLE exhaustion (32 slots), not the byte
        // budget: once a middleware has set `Content-Type`, this handler's
        // own `setHeader` for it is a replace that needs no slot, so the
        // `Content-Type` escalation below succeeds and cannot rescue this.
        //
        // The answer is NOT `failUnsafeResponse`: a 304 is an optimisation
        // the origin may always decline (RFC 9110 §15.4.5 — "the server
        // SHOULD" send 304, never MUST), so the full representation is a
        // completely conformant answer to a conditional request, and it is
        // the one the client can use. A 500 would throw away a response that
        // is correct and safe in order to advertise a lost round trip. That
        // is the opposite trade from `Content-Type`/`Cache-Control`, where
        // what would go out is *unsafe* (sniffable body, mis-cached private
        // file) and no correct response exists. So: un-stage the 304 and
        // serve the whole file, with `Content-Type` still guarded below.
        //
        // The `.proceed` arm fails the same call for the same reason but
        // stages nothing, and there the lost `ETag` is exactly the lost
        // `Last-Modified` above — a cache validator, deliberately
        // best-effort. `rw.status` is what tells the two apart; if `apply`
        // ever moves its `setHeader` ahead of its `setStatus`, this reads 200
        // and takes the same (correct) full-representation path.
        const conditional_done = http.conditional.apply(req, rw, .{ .etag = etag, .last_modified = mtime_s }) catch done: {
            if (rw.status == 304) rw.setStatus(200);
            break :done false;
        };
        if (conditional_done) {
            return; // 304 / 412 staged (body suppressed by the server core)
        }

        // NOT best-effort: a body served without `Content-Type` is sniffed.
        rw.setHeader("Content-Type", mimeType(opened.mimeName(), h.options.mime_overrides, h.options.default_mime)) catch
            return failUnsafeResponse(rw);
        // Best-effort, deliberately: `Accept-Ranges` only advertises that
        // range requests are supported. Losing it costs resumable downloads,
        // not correctness.
        rw.setHeader("Accept-Ranges", "bytes") catch {};
        // Best-effort, deliberately (A1 F18): `Content-Type` above is
        // already the strong guard against MIME-sniffing (`failUnsafeResponse`
        // escalates rather than serve without it); `nosniff` is defense in
        // depth against browsers that second-guess a correct `Content-Type`
        // anyway. Losing this one header on budget exhaustion is not worth
        // a 500 — the primary guard already held.
        rw.setHeader("X-Content-Type-Options", "nosniff") catch {};

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
    /// `dh` is ALREADY the resolved, already-open directory handle from
    /// `resolveForServe` (A1 F11) — this no longer re-walks the path itself.
    fn serveDirectory(h: *const Handler, req: *http.Server.Request, rw: *http.Server.ResponseWriter, dh: DirHandle) Writer.Error!void {
        if (!h.options.directory_listing) return sendStatus(rw, 403);

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

    /// What one resolve pass through `serve` can produce: either a regular
    /// file ready to send, or an already-open directory (no index) ready to
    /// list. See `resolveForServe`.
    const ServeResolve = union(enum) {
        opened: Opened,
        dir_listing: DirHandle,
    };

    /// The error set `resolveForServe`/`openIndexOrListing` can actually
    /// return — `ResolveError` minus `IsDir`: that case is consumed
    /// internally and turned into `ServeResolve.dir_listing` instead of
    /// being propagated as an error `serve` would have to re-resolve for.
    const ServeResolveError = error{ Forbidden, NotFound, IoError };

    /// Single resolve pass used by `serve` (A1 F11). The PUBLIC
    /// `resolveFile`/`openWithinRoot` fold "directory with no index" into
    /// `error.IsDir` and leave it to the caller to open the directory AGAIN
    /// to list it — which is exactly what `serve`/`serveDirectory` used to
    /// do, via a full second sanitize-and-walk from `h.root`. That is a
    /// TOCTOU shape (a component's identity can change between the two
    /// walks) and doubles the `openat` cost of every directory-listing
    /// request. This does the SAME sanitization, the SAME one-component-at-
    /// a-time no-follow walk and the SAME containment checks as
    /// `openWithinRoot`'s own leaf-is-directory branch, but keeps the
    /// already-open directory handle and hands it straight back for
    /// listing instead of closing it and making `serveDirectory` re-walk.
    /// It is an internal refactor of that one branch, not a new resolution
    /// policy — the public `resolveFile`/`openWithinRoot` are untouched,
    /// byte-for-byte, and keep their documented `Opened-or-error.IsDir`
    /// contract for any caller that still wants it.
    /// `via_directory.*` is set to whether the resolution went through a
    /// DIRECTORY route (root, or a leaf that turned out to be a directory)
    /// as opposed to a plain leaf file — `serve` uses it to decide whether
    /// a missing trailing slash needs a redirect first (A1 F17). Always
    /// set, on every return path including errors.
    fn resolveForServe(h: *const Handler, raw_path: []const u8, via_directory: *bool) (SanitizeError || ServeResolveError)!ServeResolve {
        via_directory.* = false;
        var buf: [max_path_bytes]u8 = undefined;
        const rel = try sanitizePath(raw_path, &buf, .{ .allow_dotfiles = h.options.serve_dotfiles });
        const follow = h.options.follow_symlinks;
        const want_dir = namesDirectory(raw_path);

        if (rel.len == 0) {
            via_directory.* = true;
            return openIndexOrListing(h.root, h.root, h.io, h.options, false);
        }

        const last_slash = mem.lastIndexOfScalar(u8, rel, '/');
        const dir_part: []const u8 = if (last_slash) |s| rel[0..s] else "";
        const leaf: []const u8 = if (last_slash) |s| rel[s + 1 ..] else rel;

        var parent: Dir = h.root;
        var parent_owned = false;
        defer if (parent_owned) parent.close(h.io);

        if (dir_part.len != 0) {
            var it = mem.splitScalar(u8, dir_part, '/');
            while (it.next()) |seg| {
                // Same layer-2 hardening as `openWithinRoot` (A1 F3).
                if (mem.eql(u8, seg, "..")) return error.Forbidden;
                const next = parent.openDir(h.io, seg, .{
                    .follow_symlinks = follow,
                    .access_sub_paths = true,
                }) catch |e| {
                    if (!follow and e != error.NameTooLong and isSymlinkComponent(parent, h.io, seg)) return error.Forbidden;
                    return mapOpenError(e);
                };
                if (parent_owned) parent.close(h.io);
                parent = next;
                parent_owned = true;
            }
        }

        if (mem.eql(u8, leaf, "..")) return error.Forbidden;

        // A request that named a directory (`/a.txt/`) never opens the leaf
        // as a file -- see `namesDirectory`.
        const leaf_file: Io.File.OpenError!Io.File = if (want_dir) error.IsDir else parent.openFile(h.io, leaf, .{
            .follow_symlinks = follow,
            .allow_directory = false,
            .resolve_beneath = true,
        });
        const file = leaf_file catch |e| switch (e) {
            error.IsDir => {
                via_directory.* = true;
                // The leaf IS a directory: open it ONCE, with `.iterate`
                // (unlike `openWithinRoot`'s own copy of this branch, which
                // never needs to list it), and either find an index inside
                // it or keep it open for `serveDirectory`.
                var d = parent.openDir(h.io, leaf, .{
                    .follow_symlinks = follow,
                    .access_sub_paths = true,
                    .iterate = true,
                }) catch |de| {
                    // As in `openWithinRootAs`: under `want_dir` a symlinked
                    // leaf still answers 403.
                    if (want_dir and !follow and de != error.NameTooLong and isSymlinkComponent(parent, h.io, leaf)) return error.Forbidden;
                    return mapOpenError(de);
                };
                test_f11_leaf_dir_opens += 1; // A1 F11 measurement
                if (follow) {
                    verifyContainedDir(h.root, h.io, d) catch {
                        d.close(h.io);
                        return error.Forbidden;
                    };
                }
                return openIndexOrListing(d, h.root, h.io, h.options, true);
            },
            else => return mapOpenError(e),
        };

        var f = file;
        const st = f.stat(h.io) catch {
            f.close(h.io);
            return error.IoError;
        };
        if (st.kind != .file) {
            f.close(h.io);
            return error.Forbidden;
        }
        if (follow) verifyContained(h.root, h.io, &f) catch {
            f.close(h.io);
            return error.Forbidden;
        };
        var o: Opened = .{ .file = f, .stat = st };
        o.setMimeName(leaf);
        return .{ .opened = o };
    }

    /// Try `dir`'s configured index file; on success, `dir` was only a
    /// means to find it (close it if we own it). On `error.IsDir` (no
    /// index configured, missing, or itself a directory), keep `dir` open
    /// and hand it back as the directory to list instead of closing it —
    /// this is the step that removes F11's second `openat` walk.
    fn openIndexOrListing(dir_in: Dir, root: Dir, io: Io, opts: Options, dir_owned: bool) ServeResolveError!ServeResolve {
        var dir = dir_in;
        if (openIndex(dir, root, io, opts)) |opened| {
            if (dir_owned) dir.close(io);
            return .{ .opened = opened };
        } else |e| switch (e) {
            error.IsDir => return .{ .dir_listing = .{ .dir = dir, .owned = dir_owned } },
            else => |e2| {
                if (dir_owned) dir.close(io);
                return e2;
            },
        }
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

/// An `ETag` from size + mtime: `"<size:x>-<mtime:x>"`, weak (`W/` prefix)
/// unless `weak` is false, written into `buf` (the caller's — `setHeader`
/// copies at call time, so `buf` only has to outlive the calls made with the
/// returned slice, not the response). Cheap (no file read) and changes on
/// any content edit that moves size or mtime. Documented alternative
/// (content hash) is intentionally not the default — see SPEC.md.
/// Widest this can produce: `W/` plus two quotes, a separator, and two u64s
/// at 16 hex digits each. DERIVED rather than picked, because `bufPrint`'s
/// failure here is `catch unreachable` — a buffer one byte short would not be
/// an error, it would be a crash on the first large file. It was a bare 48
/// until 2026-08-12, which happened to be enough; shrinking it to 24 broke no
/// test, since nothing exercised a size or mtime big enough to need the room.
/// +2 for `W/` (A1 F5, round-2 Q8) on top of that same 24.
const etag_max = 2 + 2 + 1 + 2 * 16;

fn buildETag(buf: *[etag_max]u8, size: u64, mtime_s: i64, weak: bool) []const u8 {
    const m: u64 = if (mtime_s < 0) 0 else @intCast(mtime_s);
    return if (weak)
        std.fmt.bufPrint(buf, "W/\"{x}-{x}\"", .{ size, m }) catch unreachable
    else
        std.fmt.bufPrint(buf, "\"{x}-{x}\"", .{ size, m }) catch unreachable;
}

/// Content-Length is both consumed immediately by `setHeader` (parsed into an
/// integer, not retained) and copied at call time for every other header, so
/// a function-local buffer is fine either way.
fn setContentLength(rw: *http.Server.ResponseWriter, n: u64) void {
    // 20 digits is the widest decimal u64; same reasoning as `etag_max`, same
    // `catch unreachable` consequence for getting it wrong.
    var clen_buf: [20]u8 = undefined;
    const s = std.fmt.bufPrint(&clen_buf, "{d}", .{n}) catch unreachable;
    // `setHeader` intercepts `Content-Length` by name, parses it into
    // `declared_len` and returns before it ever reaches the copy store
    // (`http/src/Server.zig:1703-1711`), so `HeaderBytesExhausted` and
    // `TooManyHeaders` are unreachable here — budget pressure cannot cost
    // this response its framing.
    //
    // `InvalidHeader` IS reachable, and not through `s`: that same
    // interception rejects a `Content-Length` on a response which has already
    // declared trailers (`Server.zig:1709`), since trailers exist only under
    // chunked framing. Measured (a middleware calling `declareTrailers` and
    // then delegating here): `200 OK` + `Trailer: X-Checksum` + no
    // `Content-Length` + `Transfer-Encoding: chunked` + the correct body.
    // That is why the `catch {}` stays — the drop is not silent breakage but
    // the server core choosing the only framing left, and escalating would
    // turn a correct chunked response into a 500. `HeadersSent` is the same:
    // by then the framing is already decided.
    rw.setHeader("Content-Length", s) catch {};
}

/// Set a bare status with an empty body (no representation headers).
fn sendStatus(rw: *http.Server.ResponseWriter, status: u16) Writer.Error!void {
    rw.setStatus(status);
    setContentLength(rw, 0);
}

/// A1 F17: 301 to `req.path` + `/` (+ `?` + query, if any) — the directory
/// route's canonical, slash-terminated URL. `req.path`/`req.query` are
/// already bounded (by `max_path_bytes` and the `http` request-line/header
/// caps respectively), so the fixed buffer below is sized generously rather
/// than derived; on the astronomically unlikely overflow this answers 500
/// rather than send a truncated `Location` a client would follow to the
/// wrong place.
fn redirectTrailingSlash(req: *http.Server.Request, rw: *http.Server.ResponseWriter) Writer.Error!void {
    var buf: [max_path_bytes + 1 + max_path_bytes]u8 = undefined;
    const location = (if (req.query.len != 0)
        std.fmt.bufPrint(&buf, "{s}/?{s}", .{ req.path, req.query })
    else
        std.fmt.bufPrint(&buf, "{s}/", .{req.path})) catch return failUnsafeResponse(rw);
    rw.setStatus(301);
    rw.setHeader("Location", location) catch return failUnsafeResponse(rw);
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

// ── Snapshot: a root opened once, served without opening anything ───────────

/// Precompressed siblings a `Snapshot` serves in place of a file, in server
/// preference order (a tie in the client's weights goes to the earlier one):
/// `name.br`, `name.zst`, `name.gz` next to `name`.
pub const Precompressed = struct {
    br: bool = true,
    zstd: bool = true,
    gzip: bool = true,
};

pub const SnapshotOptions = struct {
    /// The rules `Handler` applies -- index, dotfiles, validators,
    /// `Cache-Control`, MIME, the trailing-slash redirect. A snapshot never
    /// follows a symlink and never lists a directory: `follow_symlinks` or
    /// `directory_listing` set is `error.Unsupported`.
    serve: Options = .{},
    precompressed: Precompressed = .{},
    /// Most regular files held -- one open descriptor each. A larger tree is
    /// `error.TooManyFiles`, never a silently partial snapshot.
    max_files: usize = 4096,
    /// Deepest directory nesting walked; deeper is `error.TooDeep`.
    max_depth: usize = 32,
    /// Tag every file by its content: SHA-256 of its bytes, read once when
    /// the file enters the snapshot, as a STRONG `ETag` (`"` + the first 128
    /// bits in hex + `"`). A content tag changes exactly when the bytes do --
    /// a same-second, same-size edit included, the case `Options.strong_etag`
    /// warns about -- so it may authorize `If-Range` and resumed downloads
    /// work; a rewrite with the same bytes keeps its tag. Off: `Handler`'s
    /// size+mtime tag. `Live` compares generations by it either way.
    fingerprint: bool = true,
};

pub const SnapshotError = error{
    /// `SnapshotOptions.serve` asks for something a snapshot does not do.
    Unsupported,
    TooManyFiles,
    TooDeep,
    IoError,
    OutOfMemory,
};

/// A content tag: `"` + 32 hex digits + `"`.
const tag_len = 34;

/// A root directory opened once -- every regular file under it, stat'ed and
/// held open -- and served from memory afterwards: **no `openat`, `stat` or
/// `getdents` per request.** For where those cannot run: a process that
/// sandboxes path-based opens away after startup (Landlock checks every
/// open, even one relative to a directory opened before), or an event loop
/// whose file opens would block the thread every connection shares. Only
/// positional reads of the held descriptors remain, through the `Io` each
/// `serve` call is given. For a tree that changes while it is served, see
/// `Live`.
///
/// What is served is what existed when `open` walked the tree: a file added
/// later is a 404 until the next snapshot, and one replaced by a rename keeps
/// serving the old inode. Symlinks and every other non-regular entry are
/// absent (404) rather than refused (`Handler` answers 403 for a symlink).
/// Otherwise the answers are `Handler.serve`'s -- the same sanitizer, the same
/// open checks (`openWithinRoot` per file), the same `sendFile` -- which a
/// test holds side by side over one tree.
///
/// Precompressed variants: when `app.js.br` / `.zst` / `.gz` exist next to
/// `app.js`, a request for `app.js` whose `Accept-Encoding` prefers one of
/// them over identity gets its bytes with `Content-Encoding`, `app.js`'s
/// `Content-Type` and the variant's own `ETag`; every answer for a file that
/// has variants carries `Vary: Accept-Encoding`. No `Accept-Encoding` is
/// identity. The variants stay reachable under their own names too.
pub const Snapshot = struct {
    gpa: std.mem.Allocator,
    options: SnapshotOptions,
    /// Path bytes of every entry.
    arena: std.heap.ArenaAllocator,
    files: std.ArrayListUnmanaged(Opened) = .empty,
    /// Per file: its content tag, with `fingerprint`.
    tags: std.ArrayListUnmanaged([tag_len]u8) = .empty,
    /// Per file: whether this snapshot closes it. A `Live` generation hands
    /// an unchanged file's descriptor on to the next one instead of reopening
    /// it; the one that holds it last closes it.
    owned: std.ArrayListUnmanaged(bool) = .empty,
    /// Per file: its id in the snapshot it was taken over from -- so a build
    /// that fails half-way can hand every descriptor back.
    reused: std.ArrayListUnmanaged(?u32) = .empty,
    /// Per file: its precompressed siblings' ids, in `codings` order.
    variants: std.ArrayListUnmanaged([codings.len]?u32) = .empty,
    /// Sanitized root-relative path ("" is the root) → file id, or a
    /// directory and its index file's id.
    paths: std.StringHashMapUnmanaged(Node) = .empty,
    /// Files opened (and hashed) by this build rather than taken over.
    fresh: usize = 0,

    const Node = union(enum) { file: u32, dir: ?u32 };

    const Coding = struct { token: []const u8, suffix: []const u8 };
    const codings = [_]Coding{
        .{ .token = "br", .suffix = ".br" },
        .{ .token = "zstd", .suffix = ".zst" },
        .{ .token = "gzip", .suffix = ".gz" },
    };

    /// Walk `root` and open every regular file under it. `root` must be
    /// opened with `.iterate = true`; the caller keeps it, and the snapshot
    /// never touches it again once this returns.
    pub fn open(gpa: std.mem.Allocator, io: Io, root: Dir, opts: SnapshotOptions) SnapshotError!Snapshot {
        return build(gpa, io, root, opts, null);
    }

    /// `open`, taking over from `prev` every file whose `stat` (inode, size,
    /// mtime) is unchanged: its descriptor, stat and tag, with no open and no
    /// read. On failure every taken-over descriptor is handed back to `prev`.
    fn build(gpa: std.mem.Allocator, io: Io, root: Dir, opts: SnapshotOptions, prev: ?*Snapshot) SnapshotError!Snapshot {
        if (opts.serve.follow_symlinks or opts.serve.directory_listing) return error.Unsupported;
        var s: Snapshot = .{ .gpa = gpa, .options = opts, .arena = .init(gpa) };
        errdefer s.abandon(io, prev);
        try s.paths.put(gpa, "", .{ .dir = null });
        try s.walk(io, root, root, "", 0, prev);

        // Directories find their index, files their variants.
        const index = opts.serve.index;
        var it = s.paths.iterator();
        while (it.next()) |e| switch (e.value_ptr.*) {
            .dir => |*idx| if (index.len != 0) {
                const key = try s.join(e.key_ptr.*, index);
                if (s.paths.get(key)) |n| switch (n) {
                    .file => |id| idx.* = id,
                    .dir => {},
                };
            },
            .file => |id| {
                const enabled = [codings.len]bool{ opts.precompressed.br, opts.precompressed.zstd, opts.precompressed.gzip };
                for (codings, enabled, 0..) |c, on, i| {
                    if (!on) continue;
                    const key = try std.mem.concat(s.arena.allocator(), u8, &.{ e.key_ptr.*, c.suffix });
                    if (s.paths.get(key)) |n| switch (n) {
                        .file => |vid| s.variants.items[id][i] = vid,
                        .dir => {},
                    };
                }
            },
        };
        return s;
    }

    pub fn deinit(s: *Snapshot, io: Io) void {
        for (s.files.items, s.owned.items) |*o, own| if (own) o.close(io);
        s.files.deinit(s.gpa);
        s.tags.deinit(s.gpa);
        s.owned.deinit(s.gpa);
        s.reused.deinit(s.gpa);
        s.variants.deinit(s.gpa);
        s.paths.deinit(s.gpa);
        s.arena.deinit();
    }

    /// A failed or unwanted build: descriptors taken over go back to `prev`,
    /// the ones this build opened are closed.
    fn abandon(s: *Snapshot, io: Io, prev: ?*Snapshot) void {
        if (prev) |p| for (s.reused.items, 0..) |r, id| if (r) |pid| {
            p.owned.items[pid] = true;
            s.owned.items[id] = false;
        };
        s.deinit(io);
    }

    /// How many regular files the snapshot holds.
    pub fn count(s: *const Snapshot) usize {
        return s.files.items.len;
    }

    /// Whether `s` serves exactly what `prev` did: every file taken over
    /// unchanged, and the same directories.
    fn sameAs(s: *const Snapshot, prev: *const Snapshot) bool {
        if (s.fresh != 0 or s.files.items.len != prev.files.items.len or s.paths.count() != prev.paths.count()) return false;
        var it = s.paths.iterator();
        while (it.next()) |e| {
            const p = prev.paths.get(e.key_ptr.*) orelse return false;
            if (std.meta.activeTag(p) != std.meta.activeTag(e.value_ptr.*)) return false;
        }
        return true;
    }

    fn join(s: *Snapshot, dir: []const u8, name: []const u8) error{OutOfMemory}![]const u8 {
        if (dir.len == 0) return s.arena.allocator().dupe(u8, name);
        return std.mem.concat(s.arena.allocator(), u8, &.{ dir, "/", name });
    }

    fn sameStat(a: File.Stat, b: File.Stat) bool {
        return a.inode == b.inode and a.size == b.size and std.meta.eql(a.mtime, b.mtime);
    }

    fn add(s: *Snapshot, rel: []const u8, opened: Opened, tag: [tag_len]u8, from: ?u32) SnapshotError!void {
        const id: u32 = @intCast(s.files.items.len);
        try s.files.ensureUnusedCapacity(s.gpa, 1);
        try s.tags.ensureUnusedCapacity(s.gpa, 1);
        try s.owned.ensureUnusedCapacity(s.gpa, 1);
        try s.reused.ensureUnusedCapacity(s.gpa, 1);
        try s.variants.ensureUnusedCapacity(s.gpa, 1);
        try s.paths.ensureUnusedCapacity(s.gpa, 1);
        s.files.appendAssumeCapacity(opened);
        s.tags.appendAssumeCapacity(tag);
        s.owned.appendAssumeCapacity(true);
        s.reused.appendAssumeCapacity(from);
        s.variants.appendAssumeCapacity(@splat(null));
        s.paths.putAssumeCapacity(rel, .{ .file = id });
    }

    fn walk(s: *Snapshot, io: Io, root: Dir, dir: Dir, prefix: []const u8, depth: usize, prev: ?*Snapshot) SnapshotError!void {
        var it = dir.iterate();
        while (it.next(io) catch return error.IoError) |entry| {
            if (!s.options.serve.serve_dotfiles and entry.name.len != 0 and entry.name[0] == '.') continue;
            switch (entry.kind) {
                .file => {
                    if (s.files.items.len == s.options.max_files) return error.TooManyFiles;
                    const rel = try s.join(prefix, entry.name);
                    // Unchanged since `prev`: take its descriptor over --
                    // one `fstatat`, no open, no read.
                    if (prev) |p| if (p.paths.get(rel)) |n| switch (n) {
                        .file => |pid| if (p.owned.items[pid]) {
                            if (dir.statFile(io, entry.name, .{ .follow_symlinks = false })) |st| {
                                if (sameStat(st, p.files.items[pid].stat)) {
                                    try s.add(rel, p.files.items[pid], p.tags.items[pid], pid);
                                    p.owned.items[pid] = false;
                                    continue;
                                }
                            } else |_| {}
                        },
                        .dir => {},
                    };
                    // The per-request open, once: component by component,
                    // no symlink, a regular file or nothing.
                    var opened = openWithinRoot(root, io, rel, s.options.serve) catch |e| switch (e) {
                        error.NotFound, error.Forbidden, error.IsDir => continue, // changed under the walk
                        error.IoError => return error.IoError,
                    };
                    var tag: [tag_len]u8 = @splat(0);
                    if (s.options.fingerprint) contentTag(io, opened.file, &tag) catch {
                        opened.close(io);
                        return error.IoError;
                    };
                    s.add(rel, opened, tag, null) catch |e| {
                        opened.close(io);
                        return e;
                    };
                    s.fresh += 1;
                },
                .directory => {
                    if (depth + 1 > s.options.max_depth) return error.TooDeep;
                    var sub = dir.openDir(io, entry.name, .{ .follow_symlinks = false, .iterate = true }) catch |e| switch (e) {
                        error.FileNotFound, error.NotDir, error.SymLinkLoop => continue, // changed under the walk
                        else => return error.IoError,
                    };
                    defer sub.close(io);
                    const rel = try s.join(prefix, entry.name);
                    try s.paths.put(s.gpa, rel, .{ .dir = null });
                    try s.walk(io, root, sub, rel, depth + 1, prev);
                },
                else => {}, // symlinks, sockets, devices: never served
            }
        }
    }

    /// SHA-256 of the whole file, as `"` + the first 128 bits in hex + `"`.
    fn contentTag(io: Io, file: File, out: *[tag_len]u8) !void {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        var buf: [64 * 1024]u8 = undefined;
        var off: u64 = 0;
        while (true) {
            const n = try file.readPositionalAll(io, &buf, off);
            if (n == 0) break;
            h.update(buf[0..n]);
            off += n;
            if (n < buf.len) break;
        }
        const digest = h.finalResult();
        out[0] = '"';
        _ = std.fmt.bufPrint(out[1 .. tag_len - 1], "{x}", .{digest[0..16]}) catch unreachable;
        out[tag_len - 1] = '"';
    }

    /// Answer `req` for `raw_path` -- the part of the request path below
    /// wherever the snapshot is mounted (the whole `req.path` when it serves
    /// the site root) -- reading file bytes through `io`. Same status mapping
    /// and never-panics contract as `Handler.serve`; directory redirects use
    /// `req.path`, so they stay right under a mount.
    pub fn serve(s: *const Snapshot, io: Io, req: *http.Server.Request, rw: *http.Server.ResponseWriter, raw_path: []const u8) Writer.Error!void {
        if (req.method != .get and req.method != .head) {
            rw.setStatus(405);
            rw.setHeader("Allow", "GET, HEAD") catch {};
            return;
        }
        var buf: [max_path_bytes]u8 = undefined;
        const rel = sanitizePath(raw_path, &buf, .{ .allow_dotfiles = s.options.serve.serve_dotfiles }) catch |e| switch (e) {
            error.Traversal, error.DotfileForbidden, error.InvalidByte => return sendStatus(rw, 403),
            error.Malformed => return sendStatus(rw, 400),
            error.TooLong => return sendStatus(rw, 414),
        };
        const node = s.paths.get(rel) orelse return sendStatus(rw, 404);
        const id = switch (node) {
            // A file asked for as a directory (`/a.txt/`): not found, as in
            // `Handler.serve` -- see `namesDirectory`.
            .file => |id| if (namesDirectory(raw_path)) return sendStatus(rw, 404) else id,
            .dir => |index| blk: {
                if (s.options.serve.redirect_to_trailing_slash and
                    (req.path.len == 0 or req.path[req.path.len - 1] != '/'))
                    return redirectTrailingSlash(req, rw);
                break :blk index orelse return sendStatus(rw, 403);
            },
        };
        const h: Handler = .init(io, undefined, s.options.serve);
        const vars = s.variants.items[id];
        var any = false;
        for (vars) |v| any = any or v != null;
        if (any) {
            // A cache that is not told serves one client's coding to another.
            rw.setHeader("Vary", "Accept-Encoding") catch return failUnsafeResponse(rw);
            if (pickVariant(req, vars)) |c| {
                const vid = vars[c].?;
                var o = s.files.items[vid];
                o.setMimeName(s.files.items[id].mimeName());
                rw.setHeader("Content-Encoding", codings[c].token) catch return failUnsafeResponse(rw);
                return h.sendFileTagged(req, rw, &o, s.tagOf(vid));
            }
        }
        var o = s.files.items[id];
        return h.sendFileTagged(req, rw, &o, s.tagOf(id));
    }

    fn tagOf(s: *const Snapshot, id: u32) ?[]const u8 {
        return if (s.options.fingerprint) &s.tags.items[id] else null;
    }

    /// The `codings` index of the variant this request prefers to identity,
    /// or null. No `Accept-Encoding` is identity: a client that said nothing
    /// gets the bytes every client can read.
    fn pickVariant(req: *const http.Server.Request, vars: [codings.len]?u32) ?usize {
        const ae = req.header("accept-encoding") orelse return null;
        var offers: [codings.len][]const u8 = undefined;
        var which: [codings.len]usize = undefined;
        var n: usize = 0;
        for (codings, vars, 0..) |c, v, i| if (v != null) {
            offers[n] = c.token;
            which[n] = i;
            n += 1;
        };
        const best = http.conneg.negotiateEncoding(ae, offers[0..n]) orelse return null;
        if (http.conneg.encodingQuality(ae, "identity")) |q| if (q > best.weight) return null;
        return which[best.index];
    }
};

// ── Live: a snapshot that follows its directory ─────────────────────────────

pub const LiveOptions = struct {
    /// The snapshots' rules. `fingerprint` is forced on: generations are
    /// compared, and tagged, by content.
    snapshot: SnapshotOptions = .{},
    /// How often `start`'s thread rescans the root, in milliseconds. Each
    /// rescan is one `getdents` per directory and one `fstatat` per file; a
    /// file whose inode, size or mtime moved is reopened and rehashed.
    rescan_ms: u32 = 2000,
    /// Told after every rescan, on the thread that ran it (`start`'s, or
    /// `reload`'s caller) -- to log a published generation or a failure.
    observer: ?Observer = null,

    pub const Observer = struct {
        ctx: ?*anyopaque = null,
        rescanned: *const fn (ctx: ?*anyopaque, outcome: Outcome) void,
    };

    pub const Outcome = union(enum) {
        /// Nothing moved; nothing was published.
        unchanged,
        /// A new generation is being served: its number (the first is 1)
        /// and how many of its files were opened and hashed anew.
        published: struct { generation: u64, fresh: usize },
        /// The rescan failed; the current generation stays.
        failed: SnapshotError,
    };
};

/// A `Snapshot` that follows its directory while it is served: a rescan --
/// by `start`'s thread every `rescan_ms`, or an explicit `reload` -- builds a
/// new generation when anything changed (a file edited, added, removed, a
/// directory added or removed) and publishes it, and requests move to it at
/// once. A request never opens, stats or hashes anything: it takes the
/// current generation, serves from its held descriptors, and lets go.
///
/// A generation is built from the previous one, not from scratch: a file
/// whose `stat` is unchanged hands its descriptor and content tag on as they
/// are; only what moved is reopened and hashed, off the request path. A
/// rewrite with the same bytes keeps its tag (the tag is the content's).
///
/// Reclamation: a request holds its generation (a counter on it) for the
/// whole answer, so a download that started before an edit finishes with the
/// bytes it started with. A retired generation closes its descriptors only
/// when no request holds it -- and generations are freed oldest first, so a
/// descriptor handed on from an older one is never closed while that older
/// one still serves it. Taking a generation is two counters and a pointer
/// load; the only wait is the publisher's, for requests caught between
/// reading which counter to use and taking the generation (nanoseconds).
///
/// **Replace a served file atomically** -- write it under another name and
/// rename it over the old one (what `rsync`, `install` and most deploy tools
/// do). A request reads the descriptor its generation holds, and a rename
/// leaves that descriptor on the old inode: requests in flight finish the
/// old bytes, later ones get the new. A rewrite IN PLACE changes the very
/// inode those descriptors read, so until the next rescan a request may see
/// the file half-written (and a length that no longer matches) -- the same
/// as any file server that reads files as it sends them.
///
/// The rescan opens files by path after startup: a sandboxed process must
/// leave the root readable (Landlock: a read rule on it), and its thread
/// must be one the sandbox covers -- start it after sandboxing.
/// Test-only seam in `Live.acquire`; see the test that sets it.
var test_acquire_pause: if (@import("builtin").is_test) ?*const fn () void else void =
    if (@import("builtin").is_test) null else {};

pub const Live = struct {
    gpa: std.mem.Allocator,
    root: Dir,
    options: LiveOptions,
    current: std.atomic.Value(*Gen),
    /// Which of `readers` a request entering now counts itself in.
    side: std.atomic.Value(u8) = .init(0),
    /// Requests between reading `side` and taking a generation.
    readers: [2]std.atomic.Value(u32) = .{ .init(0), .init(0) },
    /// Replaced generations, oldest first; freed when unheld, in order.
    retired: std.ArrayListUnmanaged(*Gen) = .empty,
    /// Generations published since `open`, the first included.
    generations: std.atomic.Value(u64) = .init(1),
    /// Rescans that failed (the current generation stays).
    failures: std.atomic.Value(u64) = .init(0),
    thread: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = .init(false),

    pub const Gen = struct {
        snap: Snapshot,
        holds: std.atomic.Value(u32) = .init(0),
    };

    /// Snapshot `root` (opened with `.iterate = true`; the `Live` owns it
    /// from here and closes it in `deinit`).
    pub fn open(gpa: std.mem.Allocator, io: Io, root: Dir, opts: LiveOptions) SnapshotError!Live {
        var o = opts;
        o.snapshot.fingerprint = true;
        const g = try gpa.create(Gen);
        errdefer gpa.destroy(g);
        g.* = .{ .snap = try Snapshot.open(gpa, io, root, o.snapshot) };
        return .{ .gpa = gpa, .root = root, .options = o, .current = .init(g) };
    }

    /// Stop the thread if it runs, then free every generation. No request
    /// may be in flight.
    pub fn deinit(l: *Live, io: Io) void {
        l.stop();
        for (l.retired.items) |g| l.free(io, g);
        l.retired.deinit(l.gpa);
        l.free(io, l.current.raw);
        l.root.close(io);
    }

    fn free(l: *Live, io: Io, g: *Gen) void {
        g.snap.deinit(io);
        l.gpa.destroy(g);
    }

    /// The generation requests are served from now. Pair with `release`.
    pub fn acquire(l: *Live) *Gen {
        const side = l.side.load(.seq_cst);
        _ = l.readers[side].fetchAdd(1, .seq_cst);
        const g = l.current.load(.seq_cst);
        // Test-only: a request stopped exactly where a publisher that did not
        // wait for it would free the generation it just read.
        if (@import("builtin").is_test) if (test_acquire_pause) |pause| pause();
        _ = g.holds.fetchAdd(1, .seq_cst);
        _ = l.readers[side].fetchSub(1, .seq_cst);
        return g;
    }

    pub fn release(_: *Live, g: *Gen) void {
        _ = g.holds.fetchSub(1, .seq_cst);
    }

    /// `Snapshot.serve` on the current generation, held for the answer.
    pub fn serve(l: *Live, io: Io, req: *http.Server.Request, rw: *http.Server.ResponseWriter, raw_path: []const u8) Writer.Error!void {
        const g = l.acquire();
        defer l.release(g);
        return g.snap.serve(io, req, rw, raw_path);
    }

    /// Rescan now: true when a new generation was published. One caller at
    /// a time (`start`'s thread, or the owner when it runs none). `io` must
    /// be one that may block -- this opens, stats and reads files.
    pub fn reload(l: *Live, io: Io) SnapshotError!bool {
        const published = l.rescan(io) catch |e| {
            l.tell(.{ .failed = e });
            return e;
        };
        if (published) |fresh| {
            l.tell(.{ .published = .{ .generation = l.generations.load(.monotonic), .fresh = fresh } });
            return true;
        }
        l.tell(.unchanged);
        return false;
    }

    fn tell(l: *Live, outcome: LiveOptions.Outcome) void {
        const o = l.options.observer orelse return;
        o.rescanned(o.ctx, outcome);
    }

    /// `reload` without the report: the new generation's fresh-file count,
    /// or null when nothing changed.
    fn rescan(l: *Live, io: Io) SnapshotError!?usize {
        defer l.reclaim(io);
        const prev = l.current.load(.seq_cst);
        var next = Snapshot.build(l.gpa, io, l.root, l.options.snapshot, &prev.snap) catch |e| {
            _ = l.failures.fetchAdd(1, .monotonic);
            return e;
        };
        if (next.sameAs(&prev.snap)) {
            next.abandon(io, &prev.snap);
            return null;
        }
        const g = l.gpa.create(Gen) catch {
            next.abandon(io, &prev.snap);
            return error.OutOfMemory;
        };
        g.* = .{ .snap = next };
        l.retired.append(l.gpa, prev) catch {
            g.snap.abandon(io, &prev.snap);
            l.gpa.destroy(g);
            return error.OutOfMemory;
        };
        l.publish(g);
        _ = l.generations.fetchAdd(1, .monotonic);
        return g.snap.fresh;
    }

    /// Make `g` current. Afterwards no request can take the old generation:
    /// one that read the old `side` before the flip is waited out here, and
    /// every later one reads `current` after the swap.
    fn publish(l: *Live, g: *Gen) void {
        _ = l.current.swap(g, .seq_cst);
        const side = l.side.load(.seq_cst);
        l.side.store(1 - side, .seq_cst);
        while (l.readers[side].load(.seq_cst) != 0) std.Thread.yield() catch {};
    }

    /// Free retired generations nobody holds, oldest first, stopping at the
    /// first still held: a descriptor it handed on may be closed only by the
    /// generation that holds it last, after every older one is gone.
    fn reclaim(l: *Live, io: Io) void {
        var n: usize = 0;
        while (n < l.retired.items.len and l.retired.items[n].holds.load(.seq_cst) == 0) : (n += 1)
            l.free(io, l.retired.items[n]);
        if (n != 0) l.retired.replaceRangeAssumeCapacity(0, n, &.{});
    }

    /// Rescan every `options.rescan_ms` on a thread of its own, until `stop`.
    /// `io` must be one a plain thread may block on (`std.Io.Threaded`'s).
    pub fn start(l: *Live, io: Io) std.Thread.SpawnError!void {
        std.debug.assert(l.thread == null);
        l.stopping.store(false, .seq_cst);
        l.thread = try std.Thread.spawn(.{}, run, .{ l, io });
    }

    pub fn stop(l: *Live) void {
        const t = l.thread orelse return;
        l.stopping.store(true, .seq_cst);
        t.join();
        l.thread = null;
    }

    fn run(l: *Live, io: Io) void {
        const step_ms: u32 = 50;
        var waited: u32 = 0;
        while (!l.stopping.load(.seq_cst)) {
            io.sleep(.fromMilliseconds(step_ms), .awake) catch {};
            waited += step_ms;
            if (waited < l.options.rescan_ms) continue;
            waited = 0;
            _ = l.reload(io) catch {};
        }
    }
};

// ── tests ─────────────────────────────────────────────────────────────────────

const testing = std.testing;

test {
    _ = @import("go_oracle_test.zig");
}

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

    // A1 F9: every traversal vector above was only ever tried with default
    // options. `serve_dotfiles = true` is a documented, real `Options`
    // setting — the `..` rejection must hold under it too, not just when
    // dotfiles are refused. (A weakened guard that only special-cased the
    // default-options path would sail through the block above and only
    // show up here.)
    for (bad) |c| {
        if (c.err != error.Traversal) continue;
        try testing.expectError(error.Traversal, sanitizePath(c.raw, &buf, .{ .allow_dotfiles = true }));
    }
    try testing.expectError(error.Traversal, sanitizePath("/../secret.txt", &buf, .{ .allow_dotfiles = true }));
    try testing.expectError(error.Traversal, sanitizePath("/a/../../b", &buf, .{ .allow_dotfiles = true }));
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
/// ⛔ The comment that was false when it was written: "Length drawn BEFORE the
/// bytes it bounds: every mutated byte the fuzzer spends then lands inside the
/// slice". A ranged `Smith` draw returns the range MINIMUM unless a whole
/// eight-octet word already lies inside the range, so `raw_len` was **0** on
/// every input this target ever ran outside `--fuzz` — `smith.bytes` was
/// handed a zero-length slice, and `sanitizePath` was called on `""` every
/// round. The traversal contract this harness exists to check had never been
/// evaluated on a path.
///
/// A seed is the request path as a `testkit.fuzz` slice seed, then the `u64`
/// word `allow_dotfiles` reads (`1` is true). ⛔ Without that word the knob is
/// dead on a corpus replay and the `allow_dotfiles = true` half of the
/// contract — which is a DIFFERENT contract, since a leading dot stops being a
/// refusal — would never run.
const path_seeds = [_][]const u8{
    // The clean paths the value tests above normalize.
    pathSeed("/index.html", 0),
    pathSeed("/sub/dir/file.txt", 0),
    pathSeed("/", 0),
    pathSeed("//a//b/", 0),
    pathSeed("/a/./b", 0),
    pathSeed("/a%2Fb.txt", 0), // %2F decodes to a real separator
    pathSeed("/hello%20world.txt", 0),
    // Every traversal/injection vector the table above pins, so the corpus is
    // not "accepted paths only" — these are the shapes the contract is about.
    pathSeed("/../etc/passwd", 0),
    pathSeed("/a/../../b", 0),
    pathSeed("/..%2f..%2fetc%2fpasswd", 0), // encoded ../
    pathSeed("/%2e%2e/x", 0), // encoded ..
    pathSeed("/foo%00.png", 0), // NUL truncation
    pathSeed("/..\\..\\x", 0), // backslash
    pathSeed("/%2e%2e%5cx", 0), // encoded backslash
    pathSeed("/%ZZ", 0), // bad percent-encoding
    pathSeed("/a%2", 0), // truncated percent
    // The dotfile knob, both ways round the SAME input — the pair a
    // tail-less seed could not have produced.
    pathSeed("/.env", 0),
    pathSeed("/.env", 1),
    pathSeed("/....//x", 0),
    pathSeed("/....//x", 1),
    pathSeed("", 0), // and the input this target used to run for ever
};

fn pathSeed(comptime raw: []const u8, comptime allow_dotfiles: u64) []const u8 {
    return &struct {
        const bytes = std.mem.toBytes(@as(u32, raw.len)) ++ raw[0..raw.len].* ++
            std.mem.toBytes(allow_dotfiles);
    }.bytes;
}

test "fuzz: sanitizePath's traversal-safety contract holds for arbitrary bytes" {
    try testing.fuzz({}, fuzzSanitizePath, .{ .corpus = &path_seeds });
}

fn fuzzSanitizePath(_: void, smith: *testing.Smith) !void {
    // ⚠ One `smith.slice` call: bytes and length in a single draw, so every
    // mutated byte really does land inside the slice `sanitizePath` sees.
    var raw_buf: [4096]u8 = undefined;
    const raw_len: usize = smith.slice(&raw_buf);
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

test "corpus: every path seed reaches sanitizePath, and the counts are pinned" {
    var nonempty: usize = 0;
    var accepted: usize = 0;
    // ⛔ Not `accepted > 0`: `sanitizePath("")` succeeds — the empty path IS
    // the root, per the module's own doc comment — so an acceptance guard
    // would have read as a pass over the collapsed corpus that reached
    // nothing. `segments` only moves when a seed's own octets are walked.
    var segments: usize = 0;
    var dotfiles_allowed: usize = 0;
    for (path_seeds) |sd| {
        var smith: testing.Smith = .{ .in = sd };
        var raw_buf: [4096]u8 = undefined;
        const raw_len: usize = smith.slice(&raw_buf);
        if (raw_len != 0) nonempty += 1;
        const allow_dotfiles = smith.value(bool);
        if (allow_dotfiles) dotfiles_allowed += 1;
        var out: [max_path_bytes]u8 = undefined;
        const clean = sanitizePath(raw_buf[0..raw_len], &out, .{ .allow_dotfiles = allow_dotfiles }) catch continue;
        accepted += 1;
        if (clean.len == 0) continue;
        var it = mem.splitScalar(u8, clean, '/');
        while (it.next()) |_| segments += 1;
    }
    try testing.expectEqual(path_seeds.len - 1, nonempty); // all but the empty path
    try testing.expectEqual(@as(usize, 10), accepted);
    try testing.expectEqual(@as(usize, 14), segments);
    // The knob is alive on a corpus replay: two seeds run with dotfiles
    // allowed, which is a different contract (a leading dot stops being a
    // refusal) and which no tail-less seed could have reached.
    try testing.expectEqual(@as(usize, 2), dotfiles_allowed);
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

        // A1 F1/F4 fixtures: symlinked DIRECTORY components (not just leaf
        // files), so `follow_symlinks` containment can be exercised on the
        // index and directory-listing routes, not only the single-file one.
        var outside = try tmp.dir.createDirPathOpen(io, "outside", .{});
        defer outside.close(io);
        try outside.writeFile(io, .{ .sub_path = "index.html", .data = "OUTSIDE-INDEX-LEAK" });
        try outside.writeFile(io, .{ .sub_path = "loot.txt", .data = "LOOT-LEAK" });
        var outside_nofile = try tmp.dir.createDirPathOpen(io, "outside_nofile", .{ .open_options = .{ .iterate = true } });
        defer outside_nofile.close(io);
        try outside_nofile.writeFile(io, .{ .sub_path = "marker.txt", .data = "LISTING-LEAK" });
        // A directory COMPONENT that is a symlink out of root, to a
        // directory that has both an index and a plain file.
        root.symLink(io, "../outside", "linkdir", .{}) catch {};
        // Same, but the target has no index — the directory-LISTING leak
        // shape (F1's 4th case), reachable only with `directory_listing`.
        root.symLink(io, "../outside_nofile", "linklist", .{}) catch {};
        // A directory genuinely INSIDE root whose own index.html is a
        // symlink pointing out — the "index that escapes" shape, distinct
        // from a symlinked directory component.
        _ = try root.createDirPathOpen(io, "symidx", .{});
        root.symLink(io, "../../secret.txt", "symidx/index.html", .{}) catch {};

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
    // A1 http/staticfiles F6: negotiable but inert for every EXISTING test
    // here — none send `Accept-Encoding`, and `shouldCompress` requires it
    // before looking at anything else. `min_size = 1` (well under
    // `gzip.Compression`'s 1024 default) so the F6 regression tests below
    // can trigger it off the fixture's own tiny files — including a 5-byte
    // RANGE body — instead of needing a dedicated large one. The scratch
    // memory is what actually gates it
    // (`Server.zig`: "compression stays off without it") — `.compression`
    // alone in `StreamOptions` is not enough.
    var gzip_scratch: http.Server.GzipScratch = undefined;
    http.Server.serveStream(.{
        .handler = httpHandler,
        .context = handler,
        .server_name = "test",
        .compression = .{ .min_size = 1 },
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
        .gzip = &gzip_scratch,
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

/// A1 F11: counts how many times `resolveForServe` opens the REQUEST'S OWN
/// target directory (the leaf-is-directory branch) during one `serve` call
/// — the specific "doubled `openat`" F11 measured. Test-only instrumentation,
/// same pattern as `test_leave_bytes`/`test_fill_table` below.
var test_f11_leaf_dir_opens: usize = 0;

/// A middleware that spends the response writer's 4 KiB header copy store
/// before `staticfiles` gets to compose anything — one header sized so that
/// exactly `test_leave_bytes` remain, which at the values used below is too
/// few for `Last-Modified` (42) or `Content-Type` (37).
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

/// A middleware that spends the response writer's header **table** — its 32
/// slots — instead of its 4 KiB byte budget. The two exhaustion routes are
/// not interchangeable, which is the whole reason this harness exists next to
/// `budgetEatingHandler`: `putHeader` needs a free slot only when the name is
/// new, so once an upstream middleware has set `Content-Type`, this handler's
/// own `setHeader` for it is a *replace* that succeeds on a full table — and
/// the `Content-Type` escalation, the one thing that could rescue a
/// half-composed response, never fires.
///
/// `test_fill_error` records which exhaustion the fill loop actually hit, so
/// a test built on this harness can assert it is pinning the table route and
/// has not silently drifted onto the byte budget.
var test_fill_table = false;
var test_preset_content_type = false;
var test_fill_error: ?anyerror = null;

fn tablePressureHandler(req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
    if (test_preset_content_type)
        rw.setHeader("Content-Type", "text/plain; charset=utf-8") catch unreachable;
    if (test_fill_table) {
        test_fill_error = null;
        var name_buf: [16]u8 = undefined;
        // Bounded far above `max_response_headers` so a table that stopped
        // refusing could not spin here; the assertion on `test_fill_error` is
        // what proves the loop ended for the intended reason. Values are one
        // byte, so the copy store stays nearly untouched: what runs out here
        // is slots, not bytes.
        for (0..64) |i| {
            const n = std.fmt.bufPrint(&name_buf, "X-Fill{d}", .{i}) catch unreachable;
            rw.setHeader(n, "1") catch |e| {
                test_fill_error = e;
                break;
            };
        }
    }
    const h: *const Handler = @ptrCast(@alignCast(req.context orelse return error.NoStaticFilesContext));
    return h.serve(req, rw);
}

/// Drive one request through `Server.serveStream` with `entry` as the top of
/// the chain (a middleware that then delegates to `staticfiles`).
fn runVia(entry: http.Server.Handler, handler: *Handler, wire: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(wire);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [256]u8 = undefined;
    var chunk_buf: [512]u8 = undefined;
    http.Server.serveStream(.{
        .handler = entry,
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

test "serve: a 304 whose ETag cannot be written is not sent as a 304" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    const wire = "GET /hello.txt HTTP/1.1\r\nHost: t\r\nIf-None-Match: *\r\nConnection: close\r\n\r\n";

    // Positive control: the same conditional request with room to answer it —
    // a real 304, carrying the validator, carrying no body.
    var out: [8192]u8 = undefined;
    const ok = runVia(tablePressureHandler, &h, wire, &out);
    try testing.expectEqual(@as(u16, 304), statusOf(ok));
    try testing.expect(mem.indexOf(u8, ok, "ETag: W/\"") != null); // weak by default, A1 F5
    try testing.expect(mem.indexOf(u8, ok, "hello world") == null);

    // Now with the header table spent and `Content-Type` already in it, so
    // that the `Content-Type` escalation cannot stand in for this one.
    test_preset_content_type = true;
    test_fill_table = true;
    defer {
        test_preset_content_type = false;
        test_fill_table = false;
        test_fill_error = null;
    }
    var out2: [8192]u8 = undefined;
    const resp = runVia(tablePressureHandler, &h, wire, &out2);

    // Pin the ROUTE, not a byte count: this must be slot exhaustion. If a
    // future edit made the fill spend bytes instead, the test would still be
    // "red on mutation" but for the wrong mechanism.
    try testing.expectEqual(@as(anyerror, error.TooManyHeaders), test_fill_error.?);

    // The defect this pins: `conditional.apply` stages 304 before it writes
    // the `ETag`, so swallowing its error used to put a `304 Not Modified`
    // on the wire with `Content-Length: 11` and no validator at all.
    try testing.expect(mem.indexOf(u8, resp, "ETag:") == null);
    if (statusOf(resp) == 304) return error.IncompleteNotModifiedWasSent;

    // What goes out instead: the full representation, which RFC 9110 §15.4.5
    // always permits in place of a 304 — self-consistent framing, a body the
    // client can use, and `Content-Type` still on it.
    try testing.expectEqual(@as(u16, 200), statusOf(resp));
    try testing.expect(mem.indexOf(u8, resp, "Content-Type: text/plain; charset=utf-8\r\n") != null);
    try testing.expect(mem.indexOf(u8, resp, "Content-Length: 11\r\n") != null);
    try testing.expect(mem.endsWith(u8, resp, "hello world"));
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
    // `X-Pad:` with the colon, as it goes on the wire. This is the ONLY
    // assertion here that distinguishes `failUnsafeResponse` from a bare
    // `sendStatus(rw, 500)`: everything else above is equally true of a 500
    // composed on top of the upstream middleware's headers. Until 2026-08-13
    // the needle was `X-Pad-`, which the writer can never emit, so dropping
    // the `rw.reset()` left this test green.
    try testing.expect(mem.indexOf(u8, resp, "X-Pad:") == null);
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
    // Same `reset()` pin as the Content-Type test, on the second escalation
    // site: the half-composed representation goes, upstream padding included.
    try testing.expect(mem.indexOf(u8, resp, "X-Pad:") == null);
}

test "serveDirectory: a listing that cannot be labelled text/html answers 500, never a sniffable index" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{ .directory_listing = true });
    // Trailing slash: this test is about `serveDirectory`'s sniffing-safety
    // escalation, not about F17's redirect, so the request already names
    // the canonical directory URL.
    const wire = "GET /sub/ HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";

    // Positive control: the listing this handler would otherwise emit.
    var out: [8192]u8 = undefined;
    const ok = runVia(tablePressureHandler, &h, wire, &out);
    try testing.expectEqual(@as(u16, 200), statusOf(ok));
    try testing.expect(mem.indexOf(u8, ok, "Content-Type: text/html; charset=utf-8\r\n") != null);
    try testing.expect(mem.indexOf(u8, ok, "<li>dir/</li>") != null);

    // With the header table spent — and, unlike the 304 test above, WITHOUT
    // an upstream `Content-Type`, so this handler's own call needs a slot and
    // is the one that fails.
    test_fill_table = true;
    defer {
        test_fill_table = false;
        test_fill_error = null;
    }
    var out2: [8192]u8 = undefined;
    const resp = runVia(tablePressureHandler, &h, wire, &out2);
    try testing.expectEqual(@as(anyerror, error.TooManyHeaders), test_fill_error.?);

    // This is the strongest of the escalation sites, because the body it
    // suppresses is HTML built out of attacker-influenced file names: served
    // unlabelled, a browser sniffs it and the listing becomes stored XSS.
    try testing.expectEqual(@as(u16, 500), statusOf(resp));
    try testing.expect(mem.indexOf(u8, resp, "<!DOCTYPE html>") == null);
    try testing.expect(mem.indexOf(u8, resp, "<li>") == null);
    // `reset()` again: the fill headers are gone, so this is a discarded
    // response and not a 500 stapled onto a half-composed one.
    try testing.expect(mem.indexOf(u8, resp, "X-Fill0:") == null);
}

test "serve: 200 with correct Content-Type, ETag, Last-Modified, body" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var out: [4096]u8 = undefined;
    const resp = get(&h, "/hello.txt", &out);
    try testing.expectEqual(@as(u16, 200), statusOf(resp));
    try testing.expect(mem.indexOf(u8, resp, "Content-Type: text/plain; charset=utf-8\r\n") != null);
    // Weak by default since A1 F5 (round-2 Q8) — see the dedicated F5 tests
    // for why; this test is just checking an ETag is present at all.
    try testing.expect(mem.indexOf(u8, resp, "ETag: W/\"") != null);
    try testing.expect(mem.indexOf(u8, resp, "Last-Modified: ") != null);
    try testing.expect(mem.indexOf(u8, resp, "Accept-Ranges: bytes\r\n") != null);
    // A1 F18: nosniff alongside the correct Content-Type — defense in
    // depth, not a substitute for it.
    try testing.expect(mem.indexOf(u8, resp, "X-Content-Type-Options: nosniff\r\n") != null);
    try testing.expect(mem.endsWith(u8, resp, "hello world"));
}

/// Stand-in for an app that already resolved/opened the file itself (e.g. to
/// compose an app-specific 404 page) and wants to serve it without paying a
/// second `resolveFile` inside `serve` — exactly the `sendFile` use case.
fn resolvedSendFileHandler(req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
    const h: *const Handler = @ptrCast(@alignCast(req.context orelse return error.NoStaticFilesContext));
    var opened = resolveFile(h.root, h.io, req.path, h.options) catch return sendStatus(rw, 404);
    defer opened.close(h.io);
    return h.sendFile(req, rw, &opened);
}

test "sendFile: serving an already-resolved Opened is byte-identical to the resolve-inside-serve path" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});

    var buf_serve: [4096]u8 = undefined;
    const via_serve = get(&h, "/sub/dir/file.txt", &buf_serve);
    try testing.expectEqual(@as(u16, 200), statusOf(via_serve));
    try testing.expect(mem.endsWith(u8, via_serve, "nested"));

    var buf_sendfile: [4096]u8 = undefined;
    var in: std.Io.Reader = .fixed("GET /sub/dir/file.txt HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    var out: std.Io.Writer = .fixed(&buf_sendfile);
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [256]u8 = undefined;
    var chunk_buf: [512]u8 = undefined;
    // Same `.compression`/`.gzip` scratch as `runRequest` (which `get()`
    // above goes through) — otherwise this comparison would differ by the
    // `Vary: Accept-Encoding` line compression adds to EVERY response, an
    // artifact of the two call sites' options rather than of `sendFile`
    // actually behaving differently from `serve`.
    var gzip_scratch: http.Server.GzipScratch = undefined;
    http.Server.serveStream(.{
        .handler = resolvedSendFileHandler,
        .context = &h,
        .server_name = "test",
        .compression = .{ .min_size = 1 },
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
        .gzip = &gzip_scratch,
    });
    const via_sendfile = out.buffered();

    // Identical response bytes: same status, same headers (Content-Type,
    // ETag, Last-Modified, Accept-Ranges), same body — proving `sendFile`
    // called directly on a caller-held `Opened` behaves exactly like the
    // resolve done internally by `serve`.
    try testing.expectEqualStrings(via_serve, via_sendfile);
}

test "serve: directory request serves index.html" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var out: [4096]u8 = undefined;
    // A1 F15: this test used to assert nothing for 2 of its 3 cases, and
    // its comment claimed a 404 that the code never sends — `serveDirectory`
    // answers 403 for "no index, listing off" (confirmed against SPEC.md
    // and against `serveDirectory`'s own `sendStatus(rw, 403)`), not 404.
    //
    // A1 F17: "/sub" (no trailing slash) no longer reaches the SAME
    // resolution as "/sub/" — it is a directory route missing its slash, so
    // it redirects before `serveDirectory` (or an index lookup) ever runs.
    // "/" is the one path with no non-slash form to begin with.
    for ([_][]const u8{ "/", "/sub/" }) |p| {
        const resp = get(&h, p, &out);
        if (mem.eql(u8, p, "/")) {
            // "/" has an index → served.
            try testing.expectEqual(@as(u16, 200), statusOf(resp));
            try testing.expect(mem.endsWith(u8, resp, "<h1>home</h1>"));
        } else {
            // "/sub/" has no index and listing is off → 403, per SPEC.md
            // and `serveDirectory`'s `directory_listing` gate.
            try testing.expectEqual(@as(u16, 403), statusOf(resp));
        }
    }

    const bare = get(&h, "/sub", &out);
    try testing.expectEqual(@as(u16, 301), statusOf(bare));
    try testing.expect(mem.indexOf(u8, bare, "Location: /sub/\r\n") != null);
}

test "serve: a directory URL missing its trailing slash redirects to the canonical one (A1 F17)" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var out: [4096]u8 = undefined;

    // `sub/dir` has no index.html in the fixture — same shape as the other
    // test above, redirect first either way. What THIS test adds: the
    // query string, the opt-out, and that a plain file is never touched.
    var h = Handler.init(testing.io, fx.root, .{});
    const bare = get(&h, "/sub/dir", &out);
    try testing.expectEqual(@as(u16, 301), statusOf(bare));
    try testing.expect(mem.indexOf(u8, bare, "Location: /sub/dir/\r\n") != null);
    try testing.expect(mem.indexOf(u8, bare, "nested") == null); // no body served yet

    // Query string survives the redirect.
    const with_query = get(&h, "/sub/dir?x=1", &out);
    try testing.expectEqual(@as(u16, 301), statusOf(with_query));
    try testing.expect(mem.indexOf(u8, with_query, "Location: /sub/dir/?x=1\r\n") != null);

    // The canonical form reaches the SAME outcome the bare form would have
    // reached anyway (403: no index, listing off) — this is a redirect to
    // the equivalent resolution, not a status change. Own buffer: held
    // alongside `bare_off` below for the byte-identity comparison.
    var out_slash: [4096]u8 = undefined;
    const slash = get(&h, "/sub/dir/", &out_slash);
    try testing.expectEqual(@as(u16, 403), statusOf(slash));

    // Opt-out (`redirect_to_trailing_slash = false`): the pre-fix dual
    // serve is available for a caller that needs it — same 403 as the
    // canonical form above, reached WITHOUT a redirect this time.
    var h_off = Handler.init(testing.io, fx.root, .{ .redirect_to_trailing_slash = false });
    var out_off: [4096]u8 = undefined;
    const bare_off = get(&h_off, "/sub/dir", &out_off);
    try testing.expectEqual(@as(u16, 403), statusOf(bare_off));
    try testing.expect(mem.indexOf(u8, bare_off, "Location:") == null);
    try testing.expectEqualStrings(slash, bare_off); // same content, no redirect either way

    // A plain FILE (never a directory route) is never redirected, whatever
    // its name looks like.
    const file_resp = get(&h, "/hello.txt", &out);
    try testing.expectEqual(@as(u16, 200), statusOf(file_resp));
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

// A1 F8: "only ever serve regular files" (root.zig:443/475) had no test —
// the fixture never had a non-regular file, so mutation M13 (deleting the
// `st.kind != .file` check) passed 30/30 green. The reason the ORIGINAL
// audit and the first fixer pass both left this alone: `open()` on a FIFO
// for reading, in the default blocking mode `openFile` uses, blocks on the
// open() syscall itself until a writer attaches — with no writer, forever,
// on a shared machine other agents are using.
//
// The fix is not to touch `openFile` (production code has no business
// opening things O_NONBLOCK) but to make sure a writer is ALREADY attached
// before the module's blocking open ever runs, by holding both a
// non-blocking reader AND a non-blocking writer fd open on the FIFO for the
// lifetime of the test:
//   1. mknodat the FIFO (skip the test if unsupported, e.g. non-Linux CI).
//   2. open it O_RDONLY|O_NONBLOCK — this succeeds immediately even with no
//      writer (that is the whole point of O_NONBLOCK on the read side).
//   3. open it O_WRONLY|O_NONBLOCK — now succeeds immediately too, because
//      step 2's reader is already attached (no ENXIO).
// With both ends held, the module's own default-blocking `openFile` call
// in step 4 never actually blocks: at least one writer is present the
// instant it asks, which is the only thing a blocking reader-open waits
// for. No thread, no timing, no risk of hanging the shared box.
const linux = std.os.linux;

fn openFifoBothEndsNonblocking(dir: Dir, name: [:0]const u8) !struct { r: linux.fd_t, w: linux.fd_t } {
    const mknod_rc = linux.mknodat(dir.handle, name, linux.S.IFIFO | 0o644, 0);
    if (linux.errno(mknod_rc) != .SUCCESS) return error.SkipZigTest;
    const r_rc = linux.openat(dir.handle, name, .{ .ACCMODE = .RDONLY, .NONBLOCK = true }, 0);
    if (linux.errno(r_rc) != .SUCCESS) return error.SkipZigTest;
    const r_fd: linux.fd_t = @intCast(r_rc);
    errdefer _ = linux.close(r_fd);
    const w_rc = linux.openat(dir.handle, name, .{ .ACCMODE = .WRONLY, .NONBLOCK = true }, 0);
    if (linux.errno(w_rc) != .SUCCESS) return error.SkipZigTest;
    const w_fd: linux.fd_t = @intCast(w_rc);
    return .{ .r = r_fd, .w = w_fd };
}

test "serve: a FIFO in the root is refused (403), not opened and blocked on (A1 F8, audit mutation M13)" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const ends = try openFifoBothEndsNonblocking(fx.root, "afifo");
    defer {
        _ = linux.close(ends.r);
        _ = linux.close(ends.w);
    }

    var h = Handler.init(testing.io, fx.root, .{});
    var out: [4096]u8 = undefined;
    // The real, un-mutated regular-file check: the module's own blocking
    // `openFile` runs here and must not hang (see the fixture helper above
    // for why it cannot), and the FIFO must never be handed to a client.
    try testing.expectEqual(@as(u16, 403), statusOf(get(&h, "/afifo", &out)));
    // Positive control: an actual regular file next to it still serves 200
    // — the FIFO fixture did not disturb ordinary resolution.
    try testing.expectEqual(@as(u16, 200), statusOf(get(&h, "/hello.txt", &out)));
}

test "serve: a directory-listing request opens its target directory once, not twice (A1 F11)" {
    // F11: `serveDirectory` used to re-walk the whole path from `h.root`
    // via a second, independent `openDirWithinRoot`, because `resolveFile`'s
    // own walk only opened the target directory to look for an index and
    // then closed it before returning `error.IsDir`. That is a TOCTOU shape
    // (the two walks can observe different filesystem state) as well as a
    // doubled `openat` cost on every listing request. `resolveForServe` now
    // does one walk and hands the already-open directory straight to
    // `serveDirectory`. `test_f11_leaf_dir_opens` counts specifically the
    // "open the request's own target directory" call, which is the one
    // F11 found duplicated.
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{ .directory_listing = true });
    test_f11_leaf_dir_opens = 0;
    var out: [8192]u8 = undefined;
    // Trailing slash: this test measures `resolveForServe`'s open count,
    // not F17's redirect — a bare "/sub/dir" would redirect first.
    const resp = get(&h, "/sub/dir/", &out);
    try testing.expectEqual(@as(u16, 200), statusOf(resp));
    try testing.expect(mem.indexOf(u8, resp, "<li>file.txt</li>") != null);
    try testing.expectEqual(@as(usize, 1), test_f11_leaf_dir_opens);
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

test "serve: follow_symlinks containment reaches directory & index routes, not just leaf files (A1 F1, F4)" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var out: [4096]u8 = undefined;

    // Default mode (no-follow): every one of these must already be refused.
    // This is F4's missing coverage — the default symlink policy on a
    // DIRECTORY component (as opposed to a leaf file) had no test at all.
    {
        var h = Handler.init(testing.io, fx.root, .{ .directory_listing = true });
        for ([_][]const u8{ "/linkdir/", "/linkdir/loot.txt", "/linklist/" }) |p| {
            const resp = get(&h, p, &out);
            // A1 F16: every one of these must be 403 (a refused symlinked
            // component per SPEC.md), never 404 — a 404 here would tell an
            // attacker "no such name" instead of "exists, refused",
            // leaking existence and contradicting the documented policy.
            try testing.expectEqual(@as(u16, 403), statusOf(resp));
            try testing.expect(statusOf(resp) >= 400 and statusOf(resp) < 500);
            try testing.expect(mem.indexOf(u8, resp, "LEAK") == null);
        }
        const r_symidx = get(&h, "/symidx/", &out);
        try testing.expect(statusOf(r_symidx) >= 400 and statusOf(r_symidx) < 500);
    }

    // follow_symlinks = true: every escaping shape must STILL be refused.
    // This is F1: `verifyContained` used to run only on the single-leaf-file
    // open, never on the index-lookup or directory-listing routes.
    {
        var h = Handler.init(testing.io, fx.root, .{ .follow_symlinks = true, .directory_listing = true });

        // (1) directory component is a symlink out; target has an index.
        const r1 = get(&h, "/linkdir/", &out);
        try testing.expect(statusOf(r1) >= 400 and statusOf(r1) < 500);
        try testing.expect(mem.indexOf(u8, r1, "OUTSIDE-INDEX-LEAK") == null);

        // (2) same directory, requesting the leaf directly — this path was
        // already safe before the fix (the leaf-file check always ran); kept
        // here as a positive-safety control alongside (1).
        const r2 = get(&h, "/linkdir/loot.txt", &out);
        try testing.expect(statusOf(r2) >= 400 and statusOf(r2) < 500);
        try testing.expect(mem.indexOf(u8, r2, "LOOT-LEAK") == null);

        // (3) directory component is a symlink out; target has NO index —
        // the directory-LISTING route.
        const r3 = get(&h, "/linklist/", &out);
        try testing.expect(statusOf(r3) >= 400 and statusOf(r3) < 500);
        try testing.expect(mem.indexOf(u8, r3, "LISTING-LEAK") == null);
        try testing.expect(mem.indexOf(u8, r3, "marker.txt") == null);

        // (4) the directory is genuinely inside root, but ITS index is a
        // symlink pointing out.
        const r4 = get(&h, "/symidx/", &out);
        try testing.expect(statusOf(r4) >= 400 and statusOf(r4) < 500);
        try testing.expect(mem.indexOf(u8, r4, "TOP SECRET") == null);

        // Positive control: a legitimate in-root symlink still serves.
        const ok = get(&h, "/inside_link", &out);
        try testing.expectEqual(@as(u16, 200), statusOf(ok));
    }
}

test "serve: root's own index behind a symlink is still verified for containment (A1 F1, root-index case)" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "outside_index.html", .data = "ROOT-INDEX-LEAK" });
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    root.symLink(io, "../outside_index.html", "index.html", .{}) catch {};

    var out: [4096]u8 = undefined;

    // Default mode already refuses a symlinked index.html (no-follow open
    // error) — the positive-safety control for F4.
    var h_default = Handler.init(io, root, .{});
    const r_default = get(&h_default, "/", &out);
    try testing.expect(statusOf(r_default) >= 400 and statusOf(r_default) < 500);

    var h_follow = Handler.init(io, root, .{ .follow_symlinks = true });
    const r_follow = get(&h_follow, "/", &out);
    try testing.expect(statusOf(r_follow) >= 400 and statusOf(r_follow) < 500);
    try testing.expect(mem.indexOf(u8, r_follow, "ROOT-INDEX-LEAK") == null);
}

test "serve: verifyContained rejects a sibling whose name is a string-prefix of root (A1 F7, sibling guard)" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    // "rootBAD" has "root" as a literal string prefix but is a DIFFERENT
    // directory — the "/srv/wwwroot" vs "/srv/www" shape the audit named.
    var sibling = try tmp.dir.createDirPathOpen(io, "rootBAD", .{});
    defer sibling.close(io);
    try sibling.writeFile(io, .{ .sub_path = "secret2.txt", .data = "SIBLING-LEAK" });
    root.symLink(io, "../rootBAD/secret2.txt", "escape2", .{}) catch {};

    var out: [4096]u8 = undefined;
    var h = Handler.init(io, root, .{ .follow_symlinks = true });
    const resp = get(&h, "/escape2", &out);
    try testing.expect(statusOf(resp) >= 400 and statusOf(resp) < 500);
    try testing.expect(mem.indexOf(u8, resp, "SIBLING-LEAK") == null);
}

test "serve: verifyContained's prefix check covers the FULL root path, not just its first byte (A1 F7, prefix strength)" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    // "roo2" is the SAME LENGTH as "root" (so the sibling guard's separator
    // check coincidentally lines up too) but different content — only a
    // full-length prefix compare, not a truncated one, tells them apart.
    var decoy = try tmp.dir.createDirPathOpen(io, "roo2", .{});
    defer decoy.close(io);
    try decoy.writeFile(io, .{ .sub_path = "secret3.txt", .data = "DECOY-LEAK" });
    root.symLink(io, "../roo2/secret3.txt", "escape3", .{}) catch {};

    var out: [4096]u8 = undefined;
    var h = Handler.init(io, root, .{ .follow_symlinks = true });
    const resp = get(&h, "/escape3", &out);
    try testing.expect(statusOf(resp) >= 400 and statusOf(resp) < 500);
    try testing.expect(mem.indexOf(u8, resp, "DECOY-LEAK") == null);
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

test "serve: a path segment over NAME_MAX answers 404, not 500 (A1 F13)" {
    // `mapOpenError`'s `else` branch used to catch `error.NameTooLong` and
    // map it to `IoError` -> 500, read by the client as a server fault for
    // input it supplied. No file of a name this long can ever exist on the
    // filesystem, so this is the exact same fact every `FileNotFound` case
    // here already answers 404 to.
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var wire_buf: [1024]u8 = undefined;
    const too_long_name = "A" ** 300; // NAME_MAX is 255 on Linux
    const wire = std.fmt.bufPrint(&wire_buf, "GET /{s} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", .{too_long_name}) catch unreachable;
    var out: [1024]u8 = undefined;
    const resp = runRequest(&h, wire, &out);
    try testing.expectEqual(@as(u16, 404), statusOf(resp));

    // Positive control: a name just inside the limit that genuinely does
    // not exist also answers 404 — proves this is the SAME code path, not
    // a special case for "too long" alone.
    var wire_buf2: [1024]u8 = undefined;
    const ok_len_name = "B" ** 254;
    const wire2 = std.fmt.bufPrint(&wire_buf2, "GET /{s} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", .{ok_len_name}) catch unreachable;
    const resp2 = runRequest(&h, wire2, &out);
    try testing.expectEqual(@as(u16, 404), statusOf(resp2));

    // The same over-long name as a DIRECTORY component: its failed openDir
    // used to go on to a no-follow statFile, which zig 0.16 panics on in
    // Debug for ENAMETOOLONG (Go net/http oracle, 2026-10-05).
    var wire_buf3: [1024]u8 = undefined;
    const wire3 = std.fmt.bufPrint(&wire_buf3, "GET /sub/{s}/x HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", .{too_long_name}) catch unreachable;
    try testing.expectEqual(@as(u16, 404), statusOf(runRequest(&h, wire3, &out)));
}

test "serve: a file asked for as a directory (/hello.txt/) is 404, never the file" {
    // Go net/http oracle, 2026-10-05: `sanitizePath` drops a trailing slash,
    // so `/hello.txt/` was served as `/hello.txt` -- an exact-path rule in
    // a proxy in front is walked around by one character. POSIX (ENOTDIR),
    // nginx and Apache say not found; Go redirects to the file.
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var out: [4096]u8 = undefined;
    for ([_][]const u8{ "/hello.txt/", "/hello.txt%2f", "/hello.txt%2F", "/sub/dir/file.txt/", "/hello.txt/." }) |p| {
        try testing.expectEqual(@as(u16, 404), statusOf(get(&h, p, &out)));
        try testing.expectError(error.NotFound, resolveFile(fx.root, testing.io, p, .{}));
    }
    // A symlink asked for as a directory is still refused as a symlink.
    try testing.expectEqual(@as(u16, 403), statusOf(get(&h, "/inside_link/", &out)));
    try testing.expectEqual(@as(u16, 403), statusOf(get(&h, "/escape/", &out)));
    try testing.expectError(error.Forbidden, resolveFile(fx.root, testing.io, "/escape/", .{}));
    // Positive controls: the file without the slash, a directory with one.
    try testing.expectEqual(@as(u16, 200), statusOf(get(&h, "/hello.txt", &out)));
    try testing.expectEqual(@as(u16, 200), statusOf(get(&h, "/", &out)));
    var o = try resolveFile(fx.root, testing.io, "/", .{});
    o.close(testing.io);
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

test "serve: a 206 range response is never gzip-compressed, even with Accept-Encoding (A1 http/staticfiles F6)" {
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{});
    var out: [4096]u8 = undefined;
    const r206 = runRequest(&h, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\nRange: bytes=0-4\r\nConnection: close\r\n\r\n", &out);
    try testing.expectEqual(@as(u16, 206), statusOf(r206));
    // Before the `http`-side fix, this exact combination answered 206 with
    // `Content-Encoding: gzip` and a `Content-Range` describing offsets
    // into the IDENTITY body while the bytes on the wire were compressed.
    try testing.expect(mem.indexOf(u8, r206, "Content-Encoding") == null);
    try testing.expect(mem.indexOf(u8, r206, "Content-Range: bytes 0-4/11\r\n") != null);
    try testing.expect(mem.indexOf(u8, r206, "Content-Length: 5\r\n") != null);
    try testing.expect(mem.endsWith(u8, r206, "hello"));

    // Positive control: the SAME file, same negotiation, no Range -> 200
    // DOES compress (proves the exclusion is about the status, not about
    // `hello.txt` somehow being ineligible).
    const identity_ok = runRequest(&h, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n", &out);
    try testing.expectEqual(@as(u16, 200), statusOf(identity_ok));
    try testing.expect(mem.indexOf(u8, identity_ok, "Content-Encoding: gzip\r\n") != null);
}

test "serve: ETag reaches the wire weak when the response is actually gzip-compressed (A1 http/staticfiles F6)" {
    var fx = try Fixture.init();
    defer fx.deinit();
    // `strong_etag = true`: this test is specifically about `http`'s gzip
    // seam turning a STRONG tag weak on the wire (F6) — a baseline that is
    // already weak by F5's own default would not distinguish "F6 weakened
    // it" from "F5's default already made it weak".
    var h = Handler.init(testing.io, fx.root, .{ .strong_etag = true });
    var out: [4096]u8 = undefined;

    const plain = runRequest(&h, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out);
    try testing.expectEqual(@as(u16, 200), statusOf(plain));
    try testing.expect(mem.indexOf(u8, plain, "Content-Encoding") == null);
    const strong_needle = "ETag: \"";
    const strong_at = mem.indexOf(u8, plain, strong_needle).?;
    // Every strong ETag `buildETag` emits starts right after `ETag: `, with
    // no `W/` — confirms the baseline before comparing the gzipped case.
    try testing.expectEqualStrings("ETag: \"", plain[strong_at .. strong_at + strong_needle.len]);

    var out2: [4096]u8 = undefined;
    const gzipped = runRequest(&h, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n", &out2);
    try testing.expectEqual(@as(u16, 200), statusOf(gzipped));
    try testing.expect(mem.indexOf(u8, gzipped, "Content-Encoding: gzip\r\n") != null);
    try testing.expect(mem.indexOf(u8, gzipped, "ETag: W/\"") != null);
    // Same underlying tag value on both, only the wire strength differs.
    const plain_tag_end = mem.indexOf(u8, plain[strong_at..], "\r\n").? + strong_at;
    const plain_tag = plain[strong_at + "ETag: ".len .. plain_tag_end];
    const gzip_tag_at = mem.indexOf(u8, gzipped, "ETag: W/").? + "ETag: W/".len;
    const gzip_tag_end = mem.indexOf(u8, gzipped[gzip_tag_at..], "\r\n").? + gzip_tag_at;
    try testing.expectEqualStrings(plain_tag, gzipped[gzip_tag_at..gzip_tag_end]);
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
    // A subdir with an injection-y filename, a dotfile, and no index.
    _ = try fx.root.createDirPathOpen(io, "list", .{});
    try fx.root.writeFile(io, .{ .sub_path = "list/a<b>.txt", .data = "x" });
    try fx.root.writeFile(io, .{ .sub_path = "list/.env", .data = "SECRET=1" });

    var out: [8192]u8 = undefined;
    var h_off = Handler.init(io, fx.root, .{});
    try testing.expectEqual(@as(u16, 403), statusOf(get(&h_off, "/list/", &out)));

    var h_on = Handler.init(io, fx.root, .{ .directory_listing = true });
    const resp = get(&h_on, "/list/", &out);
    try testing.expectEqual(@as(u16, 200), statusOf(resp));
    // The raw "<b>" must not appear; the escaped form must.
    try testing.expect(mem.indexOf(u8, resp, "a<b>.txt") == null);
    try testing.expect(mem.indexOf(u8, resp, "a&lt;b&gt;.txt") != null);
    // A1 F12: dotfiles must not appear in the listing by default — the
    // listing route has its own dotfile-skip (root.zig, `serveDirectory`),
    // separate from `sanitizePath`'s, and nothing exercised it.
    try testing.expect(mem.indexOf(u8, resp, ".env") == null);

    // Opting into `serve_dotfiles` must show it — the skip is a policy
    // default, not a hardcoded omission.
    var h_dot = Handler.init(io, fx.root, .{ .directory_listing = true, .serve_dotfiles = true });
    const resp_dot = get(&h_dot, "/list/", &out);
    try testing.expectEqual(@as(u16, 200), statusOf(resp_dot));
    try testing.expect(mem.indexOf(u8, resp_dot, ".env") != null);
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

test "Opened.mimeName is backed by Opened's own storage, not a caller's scratch buffer (A1 F2)" {
    var fx = try Fixture.init();
    defer fx.deinit();
    const io = testing.io;
    var opened = try resolveFile(fx.root, io, "/hello.txt", .{});
    defer opened.close(io);
    try testing.expectEqualStrings("hello.txt", opened.mimeName());
    try testing.expectEqualStrings(
        "text/plain; charset=utf-8",
        mimeType(opened.mimeName(), &.{}, "application/octet-stream"),
    );

    // Structural check, deliberately NOT a "scribble the stack and see if
    // the bytes changed" one: whether stale bytes are actually visible by
    // the time anyone reads them is a UB timing question that manifests
    // differently every run (this campaign has hit that class before).
    // `mimeName()`'s bytes must live INSIDE `opened`'s own storage — a
    // slice borrowed from a caller's local buffer (the pre-fix shape,
    // A1 F2: `resolveFile`'s `buf`) never can, by construction, because
    // that buffer is a different variable in a different, by-then-returned
    // stack frame. This is true or false independent of what the compiler
    // happened to leave lying around, so it can't flip between runs.
    const struct_start = @intFromPtr(&opened);
    const struct_end = struct_start + @sizeOf(Opened);
    const name_ptr = @intFromPtr(opened.mimeName().ptr);
    try testing.expect(name_ptr >= struct_start and name_ptr < struct_end);
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
    // A1 F5 (round-2 Q8) made the DEFAULT `ETag` weak, and a weak validator
    // can never authorize `If-Range` (that is the whole point of F5's fix —
    // see the dedicated test below). This test is about `ifRangeAllows`'s
    // mechanism specifically — stale-vs-current, strong-vs-weak — so it
    // opts into `strong_etag` to keep a validator strength that CAN
    // authorize a range, same as before F5 existed as a choice at all.
    var h = Handler.init(testing.io, fx.root, .{ .strong_etag = true });
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

test "serve: with the DEFAULT weak ETag, If-Range never authorizes a range — not even with the current, served tag (A1 F5)" {
    // The direct behavioral proof of F5's fix, as distinct from the test
    // above (which deliberately opts INTO `strong_etag` to keep testing
    // `ifRangeAllows`'s own stale/current logic). Under the default this
    // is the exact splice risk F5 closes: a same-second, same-size edit
    // would keep the OLD strong tag unchanged, so a resuming client's
    // `If-Range` would splice bytes from two file versions. Weak means
    // `If-Range` can never authorize a 206 at all, regardless of staleness.
    var fx = try Fixture.init();
    defer fx.deinit();
    var h = Handler.init(testing.io, fx.root, .{}); // strong_etag defaults false
    var out: [4096]u8 = undefined;
    var wire: [512]u8 = undefined;

    const first = runRequest(&h, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &out);
    const etag = extractHeader(first, "ETag: ") orelse return error.NoETag;
    try testing.expect(mem.startsWith(u8, etag, "W/\""));

    const req = std.fmt.bufPrint(&wire, "GET /hello.txt HTTP/1.1\r\nHost: t\r\nRange: bytes=0-4\r\n" ++
        "If-Range: {s}\r\nConnection: close\r\n\r\n", .{etag}) catch unreachable;
    var buf: [4096]u8 = undefined;
    const resp = runRequest(&h, req, &buf);
    // Falls back to a full 200, not the 206 the pre-F5 strong default gave.
    try testing.expectEqual(@as(u16, 200), statusOf(resp));
    try testing.expect(mem.endsWith(u8, resp, "hello world"));
}

test "buildETag / setContentLength: the widest possible values still fit" {
    // The buffers behind both are sized by derivation and their overflow path
    // is `catch unreachable`, so being wrong is a crash rather than an error.
    // Nothing exercised that: shrinking the ETag buffer from 48 to 24 broke no
    // test, because every fixture used small sizes and recent mtimes. These
    // two calls are the widest inputs the types admit.
    var etag_buf: [etag_max]u8 = undefined;
    const widest_strong = buildETag(&etag_buf, std.math.maxInt(u64), std.math.maxInt(i64), false);
    try std.testing.expectEqualStrings("\"ffffffffffffffff-7fffffffffffffff\"", widest_strong);
    try std.testing.expect(widest_strong.len <= etag_max);
    // The weak form (the default, A1 F5) is two bytes wider still — the one
    // that actually determines `etag_max`.
    var etag_buf2: [etag_max]u8 = undefined;
    const widest_weak = buildETag(&etag_buf2, std.math.maxInt(u64), std.math.maxInt(i64), true);
    try std.testing.expectEqualStrings("W/\"ffffffffffffffff-7fffffffffffffff\"", widest_weak);
    try std.testing.expect(widest_weak.len <= etag_max);

    var clen_buf: [20]u8 = undefined;
    const n = try std.fmt.bufPrint(&clen_buf, "{d}", .{@as(u64, std.math.maxInt(u64))});
    try std.testing.expectEqualStrings("18446744073709551615", n);
}

// ── Snapshot tests ──────────────────────────────────────────────────────────

/// What a test's request is served by: a snapshot mounted at `prefix`.
const SnapshotCtx = struct {
    snap: *const Snapshot,
    prefix: []const u8 = "",

    fn handler(req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
        const c: *const SnapshotCtx = @ptrCast(@alignCast(req.context.?));
        const rest = if (mem.startsWith(u8, req.path, c.prefix)) req.path[c.prefix.len..] else return error.NotMounted;
        return c.snap.serve(testing.io, req, rw, rest);
    }
};

fn runSnapshot(ctx: *const SnapshotCtx, wire: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(wire);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [256]u8 = undefined;
    var chunk_buf: [512]u8 = undefined;
    http.Server.serveStream(.{
        .handler = SnapshotCtx.handler,
        .context = @constCast(ctx),
        .server_name = "test",
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn snapGet(ctx: *const SnapshotCtx, path: []const u8, extra: []const u8, out_buf: []u8) []const u8 {
    var wire_buf: [1024]u8 = undefined;
    const wire = std.fmt.bufPrint(&wire_buf, "GET {s} HTTP/1.1\r\nHost: t\r\n{s}Connection: close\r\n\r\n", .{ path, extra }) catch unreachable;
    return runSnapshot(ctx, wire, out_buf);
}

fn bodyOf(resp: []const u8) []const u8 {
    const at = mem.indexOf(u8, resp, "\r\n\r\n") orelse return "";
    return resp[at + 4 ..];
}

fn headerOf(resp: []const u8, name: []const u8) ?[]const u8 {
    const end = mem.indexOf(u8, resp, "\r\n\r\n") orelse return null;
    var lines = mem.splitSequence(u8, resp[0..end], "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], name)) return mem.trim(u8, line[colon + 1 ..], " ");
    }
    return null;
}

test "Snapshot: every path answers as Handler does, except a symlink is absent rather than refused" {
    var f = try Fixture.init();
    defer f.deinit();
    var h = Handler.init(testing.io, f.root, .{});
    // Handler's size+mtime tag, to compare tags too; content tags are below.
    var snap = try Snapshot.open(testing.allocator, testing.io, f.root, .{ .fingerprint = false });
    defer snap.deinit(testing.io);
    const ctx: SnapshotCtx = .{ .snap = &snap };

    // `symlink`: Handler refuses (403), the snapshot has no such entry --
    // `snap` is what it answers instead (404, or 301 for a directory whose
    // index is a symlink: to the snapshot a directory with no index).
    const Case = struct { path: []const u8, symlink: bool = false, snap: u16 = 404 };
    const corpus = [_]Case{
        .{ .path = "/" },                                     .{ .path = "/index.html" },
        .{ .path = "/hello.txt" },                            .{ .path = "/sub/dir/file.txt" },
        .{ .path = "/sub" },                                  .{ .path = "/sub/" },
        .{ .path = "/sub/dir" },                              .{ .path = "/sub/dir/" },
        .{ .path = "/missing.txt" },                          .{ .path = "/sub/missing/x" },
        .{ .path = "/.env" },                                 .{ .path = "/sub/.hidden" },
        .{ .path = "/../secret.txt" },                        .{ .path = "/..%2fsecret.txt" },
        .{ .path = "/%2e%2e/secret.txt" },                    .{ .path = "/sub/../../secret.txt" },
        .{ .path = "/foo%00.txt" },                           .{ .path = "/..\\..\\secret.txt" },
        .{ .path = "/%zz" },                                  .{ .path = "/hello.txt?x=1" },
        .{ .path = "/hello.txt/" },                           .{ .path = "/hello.txt%2f" },
        .{ .path = "/sub/dir/file.txt/." },                   .{ .path = "/symidx/" },
        .{ .path = "/symidx", .symlink = true, .snap = 301 }, .{ .path = "/escape", .symlink = true },
        .{ .path = "/inside_link", .symlink = true },         .{ .path = "/linkdir/", .symlink = true },
        .{ .path = "/linkdir/loot.txt", .symlink = true },    .{ .path = "/linklist/", .symlink = true },
    };
    for (corpus) |c| {
        var a_buf: [4096]u8 = undefined;
        var b_buf: [4096]u8 = undefined;
        const a = get(&h, c.path, &a_buf);
        const b = snapGet(&ctx, c.path, "", &b_buf);
        errdefer std.debug.print("{s}: Handler {d}, Snapshot {d}\n", .{ c.path, statusOf(a), statusOf(b) });
        try testing.expect(mem.indexOf(u8, b, "SECRET") == null and mem.indexOf(u8, b, "LEAK") == null);
        if (c.symlink) {
            try testing.expectEqual(@as(u16, 403), statusOf(a));
            try testing.expectEqual(c.snap, statusOf(b));
            continue;
        }
        try testing.expectEqual(statusOf(a), statusOf(b));
        try testing.expectEqualStrings(bodyOf(a), bodyOf(b));
        if (headerOf(a, "location")) |loc| try testing.expectEqualStrings(loc, headerOf(b, "location").?);
        if (headerOf(a, "etag")) |tag| try testing.expectEqualStrings(tag, headerOf(b, "etag").?);
    }
    // The fixture's three regular files outside dotfiles and symlinks.
    try testing.expectEqual(@as(usize, 3), snap.count());
}

test "Snapshot: precompressed siblings -- the client's preference over identity, Vary on every answer, Range and 304 on the variant" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    try root.writeFile(io, .{ .sub_path = "app.js", .data = "console.log(1)" });
    try root.writeFile(io, .{ .sub_path = "app.js.gz", .data = "GZ-BYTES" });
    try root.writeFile(io, .{ .sub_path = "app.js.br", .data = "BR-BYTES!" });
    try root.writeFile(io, .{ .sub_path = "plain.txt", .data = "plain" });
    var snap = try Snapshot.open(testing.allocator, io, root, .{});
    defer snap.deinit(io);
    const ctx: SnapshotCtx = .{ .snap = &snap };

    const Case = struct { ae: []const u8, body: []const u8, ce: ?[]const u8 };
    const cases = [_]Case{
        .{ .ae = "", .body = "console.log(1)", .ce = null }, // no header: identity
        .{ .ae = "Accept-Encoding: gzip\r\n", .body = "GZ-BYTES", .ce = "gzip" },
        .{ .ae = "Accept-Encoding: gzip, br\r\n", .body = "BR-BYTES!", .ce = "br" }, // tie → server preference
        .{ .ae = "Accept-Encoding: br;q=0.5, gzip\r\n", .body = "GZ-BYTES", .ce = "gzip" },
        .{ .ae = "Accept-Encoding: gzip;q=0.1\r\n", .body = "console.log(1)", .ce = null }, // identity implicit at q=1
        .{ .ae = "Accept-Encoding: zstd\r\n", .body = "console.log(1)", .ce = null }, // no such sibling
        .{ .ae = "Accept-Encoding: *\r\n", .body = "BR-BYTES!", .ce = "br" },
    };
    for (cases) |c| {
        var buf: [4096]u8 = undefined;
        const r = snapGet(&ctx, "/app.js", c.ae, &buf);
        errdefer std.debug.print("{s}-> {s}\n", .{ c.ae, r });
        try testing.expectEqual(@as(u16, 200), statusOf(r));
        try testing.expectEqualStrings(c.body, bodyOf(r));
        try testing.expectEqualStrings("Accept-Encoding", headerOf(r, "vary").?);
        try testing.expectEqualStrings("text/javascript; charset=utf-8", headerOf(r, "content-type").?);
        if (c.ce) |ce| try testing.expectEqualStrings(ce, headerOf(r, "content-encoding").?) else try testing.expect(headerOf(r, "content-encoding") == null);
    }

    // The variant's own validator, and a range over its bytes.
    var b1: [4096]u8 = undefined;
    const gz = snapGet(&ctx, "/app.js", "Accept-Encoding: gzip\r\n", &b1);
    var b0: [4096]u8 = undefined;
    const plain_js = snapGet(&ctx, "/app.js", "", &b0);
    try testing.expect(!mem.eql(u8, headerOf(gz, "etag").?, headerOf(plain_js, "etag").?));
    var inm_buf: [256]u8 = undefined;
    const inm = try std.fmt.bufPrint(&inm_buf, "Accept-Encoding: gzip\r\nIf-None-Match: {s}\r\n", .{headerOf(gz, "etag").?});
    var b2: [4096]u8 = undefined;
    try testing.expectEqual(@as(u16, 304), statusOf(snapGet(&ctx, "/app.js", inm, &b2)));
    var b3: [4096]u8 = undefined;
    const part = snapGet(&ctx, "/app.js", "Accept-Encoding: gzip\r\nRange: bytes=0-1\r\n", &b3);
    try testing.expectEqual(@as(u16, 206), statusOf(part));
    try testing.expectEqualStrings("GZ", bodyOf(part));

    // A file with no siblings says nothing about encodings; a sibling is a
    // file of its own under its own name.
    var b4: [4096]u8 = undefined;
    const plain = snapGet(&ctx, "/plain.txt", "Accept-Encoding: gzip\r\n", &b4);
    try testing.expect(headerOf(plain, "vary") == null);
    var b5: [4096]u8 = undefined;
    const raw = snapGet(&ctx, "/app.js.gz", "Accept-Encoding: gzip\r\n", &b5);
    try testing.expectEqualStrings("application/gzip", headerOf(raw, "content-type").?);
    try testing.expect(headerOf(raw, "content-encoding") == null);

    // Switched off: identity only, no Vary.
    var snap_off = try Snapshot.open(testing.allocator, io, root, .{ .precompressed = .{ .br = false, .zstd = false, .gzip = false } });
    defer snap_off.deinit(io);
    const ctx_off: SnapshotCtx = .{ .snap = &snap_off };
    var b6: [4096]u8 = undefined;
    const off = snapGet(&ctx_off, "/app.js", "Accept-Encoding: gzip, br\r\n", &b6);
    try testing.expectEqualStrings("console.log(1)", bodyOf(off));
    try testing.expect(headerOf(off, "vary") == null);
}

test "Snapshot: what exists at open is what is served; mounted, a redirect keeps the mount" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    try root.writeFile(io, .{ .sub_path = "a.txt", .data = "A" });
    _ = try root.createDirPathOpen(io, "docs", .{});
    try root.writeFile(io, .{ .sub_path = "docs/index.html", .data = "DOCS" });
    var snap = try Snapshot.open(testing.allocator, io, root, .{});
    defer snap.deinit(io);
    try root.writeFile(io, .{ .sub_path = "late.txt", .data = "LATE" });

    const ctx: SnapshotCtx = .{ .snap = &snap, .prefix = "/assets" };
    var b1: [4096]u8 = undefined;
    try testing.expectEqualStrings("A", bodyOf(snapGet(&ctx, "/assets/a.txt", "", &b1)));
    var b2: [4096]u8 = undefined;
    try testing.expectEqual(@as(u16, 404), statusOf(snapGet(&ctx, "/assets/late.txt", "", &b2)));
    var b3: [4096]u8 = undefined;
    const redirect = snapGet(&ctx, "/assets/docs?v=1", "", &b3);
    try testing.expectEqual(@as(u16, 301), statusOf(redirect));
    try testing.expectEqualStrings("/assets/docs/?v=1", headerOf(redirect, "location").?);
    var b4: [4096]u8 = undefined;
    try testing.expectEqualStrings("DOCS", bodyOf(snapGet(&ctx, "/assets/docs/", "", &b4)));
    var b5: [4096]u8 = undefined;
    const post = runSnapshot(&ctx, "POST /assets/a.txt HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", &b5);
    try testing.expectEqual(@as(u16, 405), statusOf(post));
}

test "Snapshot.open refuses what it would not serve right: symlink following, listings, too many files, too deep" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    try root.writeFile(io, .{ .sub_path = "a.txt", .data = "A" });
    try root.writeFile(io, .{ .sub_path = "b.txt", .data = "B" });
    _ = try root.createDirPathOpen(io, "x/y", .{});
    const gpa = testing.allocator;
    try testing.expectError(error.Unsupported, Snapshot.open(gpa, io, root, .{ .serve = .{ .follow_symlinks = true } }));
    try testing.expectError(error.Unsupported, Snapshot.open(gpa, io, root, .{ .serve = .{ .directory_listing = true } }));
    try testing.expectError(error.TooManyFiles, Snapshot.open(gpa, io, root, .{ .max_files = 1 }));
    try testing.expectError(error.TooDeep, Snapshot.open(gpa, io, root, .{ .max_depth = 1 }));
    var ok = try Snapshot.open(gpa, io, root, .{ .max_files = 2, .max_depth = 2 });
    ok.deinit(io);
}

test "Snapshot: a file the walk cannot open is left out, not an error; deinit closes every descriptor" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    try root.writeFile(io, .{ .sub_path = "a.txt", .data = "A" });
    try root.writeFile(io, .{ .sub_path = "b.txt", .data = "B" });
    try root.writeFile(io, .{ .sub_path = "locked.txt", .data = "L" });

    const fds = struct {
        fn count() !usize {
            var d = try Dir.cwd().openDir(testing.io, "/proc/self/fd", .{ .iterate = true });
            defer d.close(testing.io);
            var n: usize = 0;
            var it = d.iterate();
            while (try it.next(testing.io)) |_| n += 1;
            return n;
        }
    };
    const before = try fds.count();
    var snap = try Snapshot.open(testing.allocator, io, root, .{});
    try testing.expectEqual(before + 3, try fds.count());
    snap.deinit(io);
    try testing.expectEqual(before, try fds.count());

    // Unreadable: the open fails (EACCES → Forbidden) and the walk goes on.
    if (linux.geteuid() == 0) return; // root reads it anyway
    try testing.expectEqual(@as(usize, 0), linux.fchmodat(root.handle, "locked.txt", 0));
    var partial = try Snapshot.open(testing.allocator, io, root, .{});
    defer partial.deinit(io);
    try testing.expectEqual(@as(usize, 2), partial.count());
    const ctx: SnapshotCtx = .{ .snap = &partial };
    var b: [4096]u8 = undefined;
    try testing.expectEqual(@as(u16, 404), statusOf(snapGet(&ctx, "/locked.txt", "", &b)));
}

test "Snapshot: redirect_to_trailing_slash = false serves a directory's index at both URLs" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    _ = try root.createDirPathOpen(io, "docs", .{});
    try root.writeFile(io, .{ .sub_path = "docs/index.html", .data = "DOCS" });
    var snap = try Snapshot.open(testing.allocator, io, root, .{ .serve = .{ .redirect_to_trailing_slash = false } });
    defer snap.deinit(io);
    const ctx: SnapshotCtx = .{ .snap = &snap };
    var b1: [4096]u8 = undefined;
    const bare = snapGet(&ctx, "/docs", "", &b1);
    try testing.expectEqual(@as(u16, 200), statusOf(bare));
    try testing.expectEqualStrings("DOCS", bodyOf(bare));
}

// ── fingerprints and Live ────────────────────────────────────────────────────

fn writeTree(root: Dir, files: []const [2][]const u8) !void {
    for (files) |f| try root.writeFile(testing.io, .{ .sub_path = f[0], .data = f[1] });
}

test "Snapshot fingerprint: a strong content tag -- same bytes, same tag; If-Range resumes" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    try writeTree(root, &.{ .{ "a.txt", "same bytes" }, .{ "b.txt", "same bytes" }, .{ "c.txt", "other bytes" } });
    var snap = try Snapshot.open(testing.allocator, io, root, .{});
    defer snap.deinit(io);
    const ctx: SnapshotCtx = .{ .snap = &snap };

    var ba: [4096]u8 = undefined;
    var bb: [4096]u8 = undefined;
    var bc: [4096]u8 = undefined;
    const ta = headerOf(snapGet(&ctx, "/a.txt", "", &ba), "etag").?;
    const tb = headerOf(snapGet(&ctx, "/b.txt", "", &bb), "etag").?;
    const tc = headerOf(snapGet(&ctx, "/c.txt", "", &bc), "etag").?;
    try testing.expectEqualStrings(ta, tb); // the content's tag, not the file's
    try testing.expect(!mem.eql(u8, ta, tc));
    try testing.expectEqual(@as(usize, tag_len), ta.len);
    try testing.expect(ta[0] == '"'); // strong: no W/

    // A strong tag authorizes If-Range: the range is served, not the whole.
    var extra: [256]u8 = undefined;
    const hdrs = try std.fmt.bufPrint(&extra, "Range: bytes=0-3\r\nIf-Range: {s}\r\n", .{ta});
    var br: [4096]u8 = undefined;
    const part = snapGet(&ctx, "/a.txt", hdrs, &br);
    try testing.expectEqual(@as(u16, 206), statusOf(part));
    try testing.expectEqualStrings("same", bodyOf(part));
}

/// A request through a `Live` mounted at the root.
const LiveCtx = struct {
    live: *Live,
    fn handler(req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
        const c: *const LiveCtx = @ptrCast(@alignCast(req.context.?));
        return c.live.serve(testing.io, req, rw, req.path);
    }
};

fn liveGet(live: *Live, path: []const u8, out_buf: []u8) []const u8 {
    var ctx: LiveCtx = .{ .live = live };
    var wire_buf: [512]u8 = undefined;
    const wire = std.fmt.bufPrint(&wire_buf, "GET {s} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", .{path}) catch unreachable;
    var in: std.Io.Reader = .fixed(wire);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [256]u8 = undefined;
    var chunk_buf: [512]u8 = undefined;
    http.Server.serveStream(.{ .handler = LiveCtx.handler, .context = &ctx, .server_name = "test" }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn openLive(tmp: *testing.TmpDir) !Live {
    const root = try tmp.dir.openDir(testing.io, "root", .{ .iterate = true });
    return Live.open(testing.allocator, testing.io, root, .{});
}

/// An mtime the rescan cannot mistake for the old one, whatever the
/// filesystem's timestamp granularity.
fn bumpMtime(root: Dir, name: []const u8, secs: i64) !void {
    const f = try root.openFile(testing.io, name, .{ .mode = .read_write });
    defer f.close(testing.io);
    const st = try f.stat(testing.io);
    const t: Io.Timestamp = .{ .nanoseconds = st.mtime.nanoseconds + @as(i96, secs) * std.time.ns_per_s };
    try f.setTimestamps(testing.io, .{ .access_timestamp = .{ .new = t }, .modify_timestamp = .{ .new = t } });
}

test "Live.reload: an edit, a new file, a removal and a new directory are served after the next rescan; nothing changed publishes nothing" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    try writeTree(root, &.{ .{ "a.txt", "one" }, .{ "gone.txt", "bye" } });
    var live = try openLive(&tmp);
    defer live.deinit(io);

    var b: [4096]u8 = undefined;
    try testing.expectEqualStrings("one", bodyOf(liveGet(&live, "/a.txt", &b)));
    const tag1 = try testing.allocator.dupe(u8, headerOf(liveGet(&live, "/a.txt", &b), "etag").?);
    defer testing.allocator.free(tag1);
    try testing.expect(!try live.reload(io)); // nothing moved
    try testing.expectEqual(@as(u64, 1), live.generations.load(.monotonic));

    try root.writeFile(io, .{ .sub_path = "a.txt", .data = "two!" });
    try bumpMtime(root, "a.txt", 5);
    try root.writeFile(io, .{ .sub_path = "new.txt", .data = "fresh" });
    try root.deleteFile(io, "gone.txt");
    _ = try root.createDirPathOpen(io, "docs", .{});
    try root.writeFile(io, .{ .sub_path = "docs/index.html", .data = "DOCS" });
    try testing.expect(try live.reload(io));
    try testing.expectEqual(@as(u64, 2), live.generations.load(.monotonic));

    try testing.expectEqualStrings("two!", bodyOf(liveGet(&live, "/a.txt", &b)));
    try testing.expect(!mem.eql(u8, tag1, headerOf(liveGet(&live, "/a.txt", &b), "etag").?));
    try testing.expectEqualStrings("fresh", bodyOf(liveGet(&live, "/new.txt", &b)));
    try testing.expectEqual(@as(u16, 404), statusOf(liveGet(&live, "/gone.txt", &b)));
    try testing.expectEqualStrings("DOCS", bodyOf(liveGet(&live, "/docs/", &b)));
}

test "Live.reload: a rewrite with the same bytes keeps the tag; a held generation keeps its bytes until released" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    try writeTree(root, &.{.{ "a.txt", "version-1" }});
    var live = try openLive(&tmp);
    defer live.deinit(io);

    var b: [4096]u8 = undefined;
    const tag1 = try testing.allocator.dupe(u8, headerOf(liveGet(&live, "/a.txt", &b), "etag").?);
    defer testing.allocator.free(tag1);
    // Same bytes, new mtime (a redeploy of an unchanged file): reopened,
    // rehashed -- and the same tag, so clients keep their 304s.
    try root.writeFile(io, .{ .sub_path = "a.txt", .data = "version-1" });
    try bumpMtime(root, "a.txt", 5);
    _ = try live.reload(io);
    try testing.expectEqualStrings(tag1, headerOf(liveGet(&live, "/a.txt", &b), "etag").?);

    // A request in flight across an edit: it holds its generation, and that
    // generation's descriptor, until it lets go.
    const held = live.acquire();
    // Replaced by rename: a new inode, the old one alive only through `held`.
    try tmp.dir.writeFile(io, .{ .sub_path = "next.txt", .data = "version-2" });
    try Dir.rename(tmp.dir, "next.txt", root, "a.txt", io);
    try testing.expect(try live.reload(io));
    try testing.expectEqualStrings("version-2", bodyOf(liveGet(&live, "/a.txt", &b)));
    try testing.expectEqual(@as(usize, 1), live.retired.items.len); // held: not freed
    var ctx: SnapshotCtx = .{ .snap = &held.snap };
    try testing.expectEqualStrings("version-1", bodyOf(snapGet(&ctx, "/a.txt", "", &b)));
    live.release(held);
    _ = try live.reload(io); // nothing new; reclaims
    try testing.expectEqual(@as(usize, 0), live.retired.items.len);
}

test "Live: descriptors handed on are closed once, by the last holder, oldest generation first" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    try writeTree(root, &.{ .{ "keep.txt", "K" }, .{ "edit.txt", "E1" } });
    const fds = struct {
        fn count() !usize {
            var d = try Dir.cwd().openDir(testing.io, "/proc/self/fd", .{ .iterate = true });
            defer d.close(testing.io);
            var n: usize = 0;
            var it = d.iterate();
            while (try it.next(testing.io)) |_| n += 1;
            return n;
        }
    };
    const before = try fds.count();
    var live = try openLive(&tmp);
    // root + two files
    try testing.expectEqual(before + 3, try fds.count());
    const g1 = live.acquire(); // generation 1 stays held
    for (0..3) |i| {
        try root.writeFile(io, .{ .sub_path = "edit.txt", .data = if (i % 2 == 0) "E2" else "E3" });
        try bumpMtime(root, "edit.txt", @intCast(10 * (i + 1)));
        try testing.expect(try live.reload(io));
    }
    // keep.txt's descriptor went from generation to generation (one fd);
    // every edit added one, and nothing was freed behind the held oldest.
    try testing.expectEqual(before + 3 + 3, try fds.count());
    try testing.expectEqual(@as(usize, 3), live.retired.items.len);
    var b: [4096]u8 = undefined;
    var ctx: SnapshotCtx = .{ .snap = &g1.snap };
    try testing.expectEqualStrings("K", bodyOf(snapGet(&ctx, "/keep.txt", "", &b)));
    live.release(g1);
    _ = try live.reload(io);
    try testing.expectEqual(@as(usize, 0), live.retired.items.len);
    try testing.expectEqual(before + 3, try fds.count());
    try testing.expectEqualStrings("K", bodyOf(liveGet(&live, "/keep.txt", &b)));
    live.deinit(io);
    try testing.expectEqual(before, try fds.count());
}

test "Live: a failed rescan keeps serving the current generation, every descriptor intact" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    try writeTree(root, &.{ .{ "a.txt", "A" }, .{ "b.txt", "B" } });
    const r = try tmp.dir.openDir(io, "root", .{ .iterate = true });
    var live = try Live.open(testing.allocator, io, r, .{ .snapshot = .{ .max_files = 2 } });
    defer live.deinit(io);
    try root.writeFile(io, .{ .sub_path = "c.txt", .data = "C" }); // one over the cap
    try testing.expectError(error.TooManyFiles, live.reload(io));
    try testing.expectEqual(@as(u64, 1), live.failures.load(.monotonic));
    var b: [4096]u8 = undefined;
    try testing.expectEqualStrings("A", bodyOf(liveGet(&live, "/a.txt", &b)));
    try testing.expectEqualStrings("B", bodyOf(liveGet(&live, "/b.txt", &b)));
    try root.deleteFile(io, "c.txt");
    try testing.expect(!try live.reload(io)); // back to what is served
}

test "Live.start: the thread picks up an edit; readers on other threads always see one whole version" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    const v1 = "v1:" ++ "a" ** 3000;
    const v2 = "v2:" ++ "b" ** 5000;
    try writeTree(root, &.{.{ "f.txt", v1 }});
    const r = try tmp.dir.openDir(io, "root", .{ .iterate = true });
    var live = try Live.open(testing.allocator, io, r, .{ .rescan_ms = 50 });
    defer live.deinit(io);

    const Reader = struct {
        live: *Live,
        stop: *std.atomic.Value(bool),
        bad: std.atomic.Value(u32) = .init(0),
        seen_v2: std.atomic.Value(bool) = .init(false),
        fn go(rd: *@This()) void {
            var buf: [16 * 1024]u8 = undefined;
            while (!rd.stop.load(.acquire)) {
                const body = bodyOf(liveGet(rd.live, "/f.txt", &buf));
                if (mem.eql(u8, body, v2)) {
                    rd.seen_v2.store(true, .release);
                } else if (!mem.eql(u8, body, v1)) _ = rd.bad.fetchAdd(1, .acq_rel);
            }
        }
    };
    var stop: std.atomic.Value(bool) = .init(false);
    var readers: [3]Reader = @splat(.{ .live = &live, .stop = &stop });
    var threads: [3]std.Thread = undefined;
    for (&readers, &threads) |*rd, *t| t.* = try std.Thread.spawn(.{}, Reader.go, .{rd});
    try live.start(io);
    // Replaced atomically -- the supported way to change a served file (see
    // `Live`): an in-place rewrite changes the inode the held descriptors
    // point to, under requests already reading it.
    try tmp.dir.writeFile(io, .{ .sub_path = "f.next", .data = v2 });
    try Dir.rename(tmp.dir, "f.next", root, "f.txt", io);
    var waited: u32 = 0;
    while (waited < 5000 and !readers[0].seen_v2.load(.acquire)) : (waited += 10) try io.sleep(.fromMilliseconds(10), .awake);
    live.stop();
    stop.store(true, .release);
    for (threads) |t| t.join();
    for (readers) |rd| try testing.expectEqual(@as(u32, 0), rd.bad.load(.acquire));
    try testing.expect(readers[0].seen_v2.load(.acquire));
}

test "Live: a file swapped for another of the same size and mtime is still seen (the inode tells them apart)" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    try writeTree(root, &.{.{ "a.txt", "AAAA" }});
    var live = try openLive(&tmp);
    defer live.deinit(io);
    const old = try root.statFile(io, "a.txt", .{});
    try tmp.dir.writeFile(io, .{ .sub_path = "b.next", .data = "BBBB" });
    const f = try tmp.dir.openFile(io, "b.next", .{ .mode = .read_write });
    try f.setTimestamps(io, .{ .access_timestamp = .{ .new = old.mtime }, .modify_timestamp = .{ .new = old.mtime } });
    f.close(io);
    try Dir.rename(tmp.dir, "b.next", root, "a.txt", io);
    try testing.expect(try live.reload(io));
    var b: [4096]u8 = undefined;
    try testing.expectEqualStrings("BBBB", bodyOf(liveGet(&live, "/a.txt", &b)));
}

test "Live: a renamed empty directory is a change (no file moved)" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    try writeTree(root, &.{.{ "a.txt", "A" }});
    _ = try root.createDirPathOpen(io, "empty", .{});
    var live = try openLive(&tmp);
    defer live.deinit(io);
    try Dir.rename(root, "empty", root, "moved", io);
    try testing.expect(try live.reload(io));
    var b: [4096]u8 = undefined;
    try testing.expectEqual(@as(u16, 404), statusOf(liveGet(&live, "/empty/", &b)));
    try testing.expectEqual(@as(u16, 403), statusOf(liveGet(&live, "/moved/", &b))); // a directory, no index
}

test "Snapshot fingerprint: the whole file is hashed, not its first chunk" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    const gpa = testing.allocator;
    const x = try gpa.alloc(u8, 200 * 1024);
    defer gpa.free(x);
    @memset(x, 'x');
    try root.writeFile(io, .{ .sub_path = "one.bin", .data = x });
    x[x.len - 1] = 'y'; // differs only in the last octet, far past 64 KiB
    try root.writeFile(io, .{ .sub_path = "two.bin", .data = x });
    var snap = try Snapshot.open(gpa, io, root, .{});
    defer snap.deinit(io);
    const one = snap.paths.get("one.bin").?.file;
    const two = snap.paths.get("two.bin").?.file;
    try testing.expect(!mem.eql(u8, &snap.tags.items[one], &snap.tags.items[two]));
}

test "Live.open tags by content even when the snapshot options say otherwise" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    try writeTree(root, &.{.{ "a.txt", "A" }});
    const r = try tmp.dir.openDir(io, "root", .{ .iterate = true });
    var live = try Live.open(testing.allocator, io, r, .{ .snapshot = .{ .fingerprint = false } });
    defer live.deinit(io);
    var b: [4096]u8 = undefined;
    const tag = headerOf(liveGet(&live, "/a.txt", &b), "etag").?;
    try testing.expectEqual(@as(usize, tag_len), tag.len);
    try testing.expect(tag[0] == '"');
}

test "Live.start: the thread keeps to rescan_ms" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    try writeTree(root, &.{.{ "a.txt", "A" }});
    const r = try tmp.dir.openDir(io, "root", .{ .iterate = true });
    var live = try Live.open(testing.allocator, io, r, .{ .rescan_ms = 1500 });
    defer live.deinit(io);
    try live.start(io);
    try root.writeFile(io, .{ .sub_path = "new.txt", .data = "N" });
    try io.sleep(.fromMilliseconds(600), .awake);
    try testing.expectEqual(@as(u64, 1), live.generations.load(.monotonic)); // not yet
    var waited: u32 = 0;
    while (waited < 5000 and live.generations.load(.monotonic) == 1) : (waited += 50) try io.sleep(.fromMilliseconds(50), .awake);
    live.stop();
    try testing.expectEqual(@as(u64, 2), live.generations.load(.monotonic));
}

/// For the test below: the acquiring thread stops in `acquire`'s window
/// until the main thread lets it go.
const PauseGate = struct {
    var paused = std.atomic.Value(bool).init(false);
    var go = std.atomic.Value(bool).init(false);
    fn pause() void {
        paused.store(true, .seq_cst);
        while (!go.load(.seq_cst)) std.Thread.yield() catch {};
    }
};

test "Live: publishing waits for a request caught between reading the generation and holding it" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    try writeTree(root, &.{.{ "a.txt", "old" }});
    var live = try openLive(&tmp);
    defer live.deinit(io);
    const side_before = live.side.load(.seq_cst);

    PauseGate.paused.store(false, .seq_cst);
    PauseGate.go.store(false, .seq_cst);
    test_acquire_pause = PauseGate.pause;
    defer test_acquire_pause = null;
    const Req = struct {
        live: *Live,
        body: [16]u8 = undefined,
        len: usize = 0,
        fn go(q: *@This()) void {
            const g = q.live.acquire(); // stops in the window
            defer q.live.release(g);
            var buf: [4096]u8 = undefined;
            var ctx: SnapshotCtx = .{ .snap = &g.snap };
            const body = bodyOf(snapGet(&ctx, "/a.txt", "", &buf));
            @memcpy(q.body[0..body.len], body);
            q.len = body.len;
        }
    };
    var req: Req = .{ .live = &live };
    const t = try std.Thread.spawn(.{}, Req.go, .{&req});
    while (!PauseGate.paused.load(.seq_cst)) std.Thread.yield() catch {};

    // The request holds the OLD generation's pointer but no hold on it yet.
    // Let it go only after a while, from another thread; the publisher must
    // still be waiting for it then, or it would free what the request holds.
    const Releaser = struct {
        fn go() void {
            std.Io.sleep(testing.io, .fromMilliseconds(150), .awake) catch {};
            PauseGate.go.store(true, .seq_cst);
        }
    };
    const rel = try std.Thread.spawn(.{}, Releaser.go, .{});
    try tmp.dir.writeFile(io, .{ .sub_path = "a.next", .data = "new" });
    try Dir.rename(tmp.dir, "a.next", root, "a.txt", io);
    test_acquire_pause = null; // only the request in flight pauses
    try testing.expect(try live.reload(io));
    // Returned only once the request left the window.
    try testing.expect(PauseGate.go.load(.seq_cst));
    rel.join();
    t.join();
    try testing.expectEqualStrings("old", req.body[0..req.len]); // served whole from the generation it took
    try testing.expect(live.side.load(.seq_cst) != side_before); // the next requests count on the other side
    var b: [4096]u8 = undefined;
    try testing.expectEqualStrings("new", bodyOf(liveGet(&live, "/a.txt", &b)));
}

test "Live observer: told unchanged, published (with the generation and fresh files), failed" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var root = try tmp.dir.createDirPathOpen(io, "root", .{ .open_options = .{ .iterate = true } });
    defer root.close(io);
    try writeTree(root, &.{ .{ "a.txt", "A" }, .{ "b.txt", "B" } });
    const Log = struct {
        seen: [4]LiveOptions.Outcome = undefined,
        n: usize = 0,
        fn rescanned(ctx: ?*anyopaque, o: LiveOptions.Outcome) void {
            const log: *@This() = @ptrCast(@alignCast(ctx.?));
            log.seen[log.n] = o;
            log.n += 1;
        }
    };
    var log: Log = .{};
    const r = try tmp.dir.openDir(io, "root", .{ .iterate = true });
    var live = try Live.open(testing.allocator, io, r, .{ .snapshot = .{ .max_files = 2 }, .observer = .{ .ctx = &log, .rescanned = Log.rescanned } });
    defer live.deinit(io);
    _ = try live.reload(io);
    try root.writeFile(io, .{ .sub_path = "c.txt", .data = "C" });
    try testing.expectError(error.TooManyFiles, live.reload(io));
    try root.deleteFile(io, "c.txt");
    try root.deleteFile(io, "b.txt");
    try tmp.dir.writeFile(io, .{ .sub_path = "a.next", .data = "A2" });
    try Dir.rename(tmp.dir, "a.next", root, "a.txt", io);
    try testing.expect(try live.reload(io));
    try testing.expectEqual(@as(usize, 3), log.n);
    try testing.expect(log.seen[0] == .unchanged);
    try testing.expectEqual(error.TooManyFiles, log.seen[1].failed);
    try testing.expectEqual(@as(u64, 2), log.seen[2].published.generation);
    try testing.expectEqual(@as(usize, 1), log.seen[2].published.fresh);
}
