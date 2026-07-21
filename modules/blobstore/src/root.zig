// SPDX-License-Identifier: MIT
//! blobstore — content-addressed blob store (git-object / restic style):
//! atomic rename-on-commit, sha256 fan-out layout, dedup, namespaced blobs.
//!
//! Layout under `base`:
//!  - `cas/<hh>/<hex>`   content-addressed store; a blob's bytes live once,
//!    keyed by their SHA-256 (`hh` = first two hex chars = 256-way fan-out so
//!    no directory holds the whole corpus, repeated per `Options.fanout`
//!    level for deeper nesting). Identical content dedups. A `<hex>.rc`
//!    sidecar next to each blob tracks its reference count.
//!  - `raw/<ns>/<key>`   a plain namespaced blob layer (name-addressed, not
//!    dedup'd) for when the caller owns the key.
//!  - `named/<ns>/<key>` small opaque byte records (manifests, indexes) under
//!    a `namespace/key` scheme.
//!  - `tmp/`             scratch space + in-flight ingest temps + the
//!    cross-process ingest lock file (`tmp/.ingest.lock`).
//!
//! **Crash safety.** Every write goes to a hidden `.part` temp and is made
//! visible by a single `rename(2)` — atomic on POSIX. A crash mid-write leaves
//! only a temp (swept as garbage); a live blob is never torn or partial.
//!
//! **Path safety.** `ns` and `key` are single path segments validated by
//! `segmentSafe` ([A-Za-z0-9._-], no leading dot, no `.`/`..`), so a request
//! can never escape `base`. CAS hex keys are generated internally and always
//! safe.
//!
//! **Reference counting + GC.** `put`/`casCommit` increment a per-blob
//! refcount sidecar (even on a dedup hit); `delete`/`casDelete` only
//! decrement it (floored at zero) — they never unlink the blob themselves.
//! `gc(keep)` is the sole reclaim path: it sweeps every CAS blob whose
//! refcount has reached zero and is not named in the caller-supplied `keep`
//! list, plus stale abandoned ingest temps. A blob with no `.rc` sidecar at
//! all (written before this feature, never `delete`d since) is treated as
//! still-referenced and left alone — see `gc`'s doc comment for the full
//! reachability contract and why refcounting (not pure mark-sweep) was
//! chosen.
//!
//! **Cross-process ingest locking.** The commit-and-refcount-mutate section
//! of `put`/`casDelete`/`gc` is serialized across processes with an advisory
//! `flock` on `tmp/.ingest.lock` — see those functions' doc comments for the
//! exact boundary.
//!
//! Provenance: original work of the zig-libs authors (MIT). Provides the
//! raw/CAS/scratch/manifest layers and `segmentSafe`, `put` (single-pass
//! hash-while-write), `verify` (bit-rot detection), the `Digest` type,
//! segment validation on every entry point, a `named` record scheme
//! (arbitrary namespace/key), refcounted `gc`, configurable fan-out, and the
//! cross-process ingest lock. sha256 comes from the sibling `hashdigest`
//! module; nothing cryptographic is reimplemented here.

const std = @import("std");
const linux = std.os.linux;
const hashdigest = @import("hashdigest");

pub const meta = .{
    .platform = .posix, // atomic rename-on-commit; advisory flock; std.Io filesystem API
    .role = .util,
    .concurrency = .reentrant, // shared state (refcounts, gc) is coordinated via advisory flock
    .model_after = "git object store / restic",
    .deps = .{"hashdigest"},
};

/// Errors specific to this module (I/O errors from `std.Io` are unioned in).
pub const Error = error{
    /// An `ns`/`key` argument is not a safe single path segment (`segmentSafe`).
    InvalidName,
    /// `verify`/`open` on a digest whose CAS blob does not exist.
    NotFound,
    /// `Options.fanout` is 0 or too large to leave room in a 64-char hex digest.
    InvalidFanout,
};

/// Store construction options. Default matches the on-disk layout every
/// store has always used, so opening a store written before this option
/// existed needs no migration.
pub const Options = struct {
    /// Number of leading 2-hex-char directory levels the CAS fan-out uses
    /// before the blob file itself, e.g. `fanout = 1` ⇒ `cas/<hh>/<hex>`
    /// (the historical, default layout); `fanout = 2` ⇒
    /// `cas/<hh>/<hh>/<hex>`. Deeper fan-out bounds directory size for
    /// stores with tens of millions of objects. Must be `1..=32` (a 64-char
    /// hex digest has 32 two-char groups). Changing `fanout` on a store that
    /// already has blobs on disk does *not* migrate them — pick it once at
    /// creation time.
    fanout: u8 = 1,
};

/// A content address: the lowercase-hex SHA-256 of a blob's bytes.
pub const Digest = struct {
    hex: [hashdigest.hex_len]u8,

    /// The 64-char lowercase hex string (borrowed from the digest).
    pub fn slice(self: *const Digest) []const u8 {
        return &self.hex;
    }

    /// Parse a 64-char lowercase-hex string into a `Digest`. Rejects wrong
    /// length or any non-`[0-9a-f]` byte (uppercase included) — never panics.
    pub fn fromHex(s: []const u8) Error!Digest {
        if (s.len != hashdigest.hex_len) return error.InvalidName;
        var d: Digest = .{ .hex = undefined };
        for (s, 0..) |c, i| {
            const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
            if (!ok) return error.InvalidName;
            d.hex[i] = c;
        }
        return d;
    }
};

/// An open temp file plus its path; stream into `file`, then `commit`/`casCommit`
/// (rename into place) or `discardTemp` (remove) it.
pub const Temp = struct { file: std.Io.File, tmp: []const u8 };

/// A raw-layer directory listing entry.
pub const Entry = struct { key: []const u8, bytes: u64 };

/// Process-local monotonically increasing counter for collision-free temp
/// names within a process. Temp *names* additionally fold in the PID
/// (`nextUniq`), so a same-name clash across processes racing the same
/// counter value is astronomically unlikely; `createFile(.truncate)` means
/// even a clash would only corrupt an in-flight *ingest*, never a live blob.
/// The commit-and-refcount step that follows is further serialized
/// cross-process by the advisory ingest lock (see `lockIngest`).
var ingest_counter: std.atomic.Value(u64) = .init(0);

pub const Store = struct {
    io: std.Io,
    base: []const u8,
    /// CAS fan-out depth (2-hex-char directory levels); see `Options.fanout`.
    fanout: u8,

    /// Ensure `base` and its `cas/`, `raw/`, `named/`, `tmp/` subdirs exist,
    /// with the default (historical) fan-out. Equivalent to
    /// `initOptions(io, base, .{})`.
    pub fn init(io: std.Io, base: []const u8) !Store {
        return initOptions(io, base, .{});
    }

    /// Like `init`, but with configurable CAS fan-out depth (see `Options`).
    pub fn initOptions(io: std.Io, base: []const u8, options: Options) !Store {
        if (options.fanout < 1 or options.fanout > 32) return error.InvalidFanout;
        try ensureDir(io, base);
        var buf: [512]u8 = undefined;
        try ensureDir(io, try std.fmt.bufPrint(&buf, "{s}/cas", .{base}));
        try ensureDir(io, try std.fmt.bufPrint(&buf, "{s}/raw", .{base}));
        try ensureDir(io, try std.fmt.bufPrint(&buf, "{s}/named", .{base}));
        try ensureDir(io, try std.fmt.bufPrint(&buf, "{s}/tmp", .{base}));
        return .{ .io = io, .base = base, .fanout = options.fanout };
    }

    // ── content-addressed store (dedup at the file level) ──────────────────────
    // A blob's content lives once at `<base>/cas/<hex[0:2]>/<hex>` (2-char
    // fan-out so a directory never holds the whole corpus).

    /// The fan-out directory for `hex` (no trailing filename), e.g.
    /// `<base>/cas/<hh>` at the default `fanout = 1`, `<base>/cas/<hh>/<hh>`
    /// at `fanout = 2`.
    fn casDir(self: Store, buf: []u8, hex: []const u8) ![]const u8 {
        var n = (try std.fmt.bufPrint(buf, "{s}/cas", .{self.base})).len;
        var i: u8 = 0;
        while (i < self.fanout) : (i += 1) {
            const seg = try std.fmt.bufPrint(buf[n..], "/{s}", .{hex[2 * i .. 2 * i + 2]});
            n += seg.len;
        }
        return buf[0..n];
    }

    /// `<base>/cas/<hh...>/<hex>` written into `buf` (`hex` is a 64-char
    /// sha256; the fan-out prefix repeats per `self.fanout`).
    pub fn casPath(self: Store, buf: []u8, hex: []const u8) ![]const u8 {
        const dir = try self.casDir(buf, hex);
        const rest = try std.fmt.bufPrint(buf[dir.len..], "/{s}", .{hex});
        return buf[0 .. dir.len + rest.len];
    }

    /// `<base>/cas/<hh...>/<hex>.rc` — the refcount sidecar for a blob.
    fn casRefPath(self: Store, buf: []u8, hex: []const u8) ![]const u8 {
        const dir = try self.casDir(buf, hex);
        const rest = try std.fmt.bufPrint(buf[dir.len..], "/{s}.rc", .{hex});
        return buf[0 .. dir.len + rest.len];
    }

    /// Create every fan-out directory level for `hex` if missing.
    fn ensureCasDir(self: Store, hex: []const u8) !void {
        var buf: [640]u8 = undefined;
        var n = (try std.fmt.bufPrint(&buf, "{s}/cas", .{self.base})).len;
        var i: u8 = 0;
        while (i < self.fanout) : (i += 1) {
            const seg = try std.fmt.bufPrint(buf[n..], "/{s}", .{hex[2 * i .. 2 * i + 2]});
            n += seg.len;
            try ensureDir(self.io, buf[0..n]);
        }
    }

    /// Read a refcount sidecar; `default_if_missing` on absence *or* on any
    /// parse/read failure (a torn/corrupt sidecar is never allowed to wedge
    /// `put`/`delete`/`gc` — it is treated the same as "not tracked").
    fn casRefRead(self: Store, hex: []const u8, default_if_missing: u64) u64 {
        var pbuf: [800]u8 = undefined;
        const path = self.casRefPath(&pbuf, hex) catch return default_if_missing;
        var vbuf: [24]u8 = undefined;
        const data = std.Io.Dir.cwd().readFile(self.io, path, &vbuf) catch return default_if_missing;
        return std.fmt.parseInt(u64, std.mem.trim(u8, data, " \t\r\n"), 10) catch default_if_missing;
    }

    /// Overwrite a refcount sidecar with `count`. Not itself crash-atomic
    /// (no temp+rename) — a torn write just falls back to
    /// `default_if_missing` on the next `casRefRead`, which is the safe
    /// direction for bookkeeping metadata (never worse than "untracked").
    fn casRefWrite(self: Store, hex: []const u8, count: u64) !void {
        var pbuf: [800]u8 = undefined;
        const path = try self.casRefPath(&pbuf, hex);
        var vbuf: [24]u8 = undefined;
        const s = try std.fmt.bufPrint(&vbuf, "{d}", .{count});
        try std.Io.Dir.cwd().writeFile(self.io, .{ .sub_path = path, .data = s });
    }

    /// True if the content blob already exists (the dedup-hit check).
    pub fn casHas(self: Store, hex: []const u8) bool {
        var buf: [768]u8 = undefined;
        const path = self.casPath(&buf, hex) catch return false;
        std.Io.Dir.cwd().access(self.io, path, .{}) catch return false;
        return true;
    }

    /// Open a content blob for reading (caller closes), or null if absent.
    pub fn casOpen(self: Store, hex: []const u8) !?std.Io.File {
        var buf: [768]u8 = undefined;
        const path = try self.casPath(&buf, hex);
        return std.Io.Dir.cwd().openFile(self.io, path, .{}) catch |e| switch (e) {
            error.FileNotFound => return null,
            else => return e,
        };
    }

    /// Create a uniquely-named temp under `cas/` to stream one blob's content
    /// into while hashing it (the content hash is unknown until the stream ends).
    pub fn casCreateTemp(self: Store, uniq: []const u8, tmp_buf: []u8) !Temp {
        const tmp = try std.fmt.bufPrint(tmp_buf, "{s}/cas/.ingest-{s}.part", .{ self.base, uniq });
        const file = try std.Io.Dir.cwd().createFile(self.io, tmp, .{ .truncate = true });
        return .{ .file = file, .tmp = tmp };
    }

    /// Commit a hashed temp into the CAS as `<hex>` and bump its refcount
    /// (creating it at 1 if new, incrementing it if this is a dedup hit —
    /// every `put` of the same content counts as a live reference). Returns
    /// true if newly stored, false if the content already existed (dedup —
    /// the temp is removed). Runs under the cross-process ingest lock (see
    /// `lockIngest`) so the has-check, rename, and refcount bump are atomic
    /// with respect to another process's `put`/`casDelete`/`gc`.
    pub fn casCommit(self: Store, hex: []const u8, tmp: []const u8) !bool {
        const lockf = try self.lockIngest();
        defer self.unlockIngest(lockf);

        if (self.casHas(hex)) {
            self.discardTemp(tmp);
            try self.casRefWrite(hex, self.casRefRead(hex, 0) + 1);
            return false;
        }
        try self.ensureCasDir(hex);
        var pbuf: [768]u8 = undefined;
        const path = try self.casPath(&pbuf, hex);
        const cwd = std.Io.Dir.cwd();
        try cwd.rename(tmp, cwd, path, self.io);
        try self.casRefWrite(hex, self.casRefRead(hex, 0) + 1);
        return true;
    }

    /// Decrement a content blob's refcount; returns false if the blob does
    /// not exist. **Does not unlink the blob** — a blob backing several
    /// `put`s (dedup) or referenced by more than one manifest survives until
    /// its refcount reaches zero, and even then physical reclaim only
    /// happens via `gc`, never here. A blob with no refcount sidecar yet
    /// (written before this feature existed) is assumed to carry exactly one
    /// implicit reference, so a single `casDelete` brings a never-before-put
    /// legacy blob to zero, matching the old unconditional-delete behavior
    /// for the common single-owner case. Runs under the cross-process
    /// ingest lock — see `casCommit`.
    pub fn casDelete(self: Store, hex: []const u8) !bool {
        const lockf = try self.lockIngest();
        defer self.unlockIngest(lockf);

        if (!self.casHas(hex)) return false;
        const cur = self.casRefRead(hex, 1);
        const next = if (cur == 0) 0 else cur - 1;
        try self.casRefWrite(hex, next);
        return true;
    }

    // ── high-level content-addressed API ───────────────────────────────────────

    /// Stream `reader` to EOF, hashing while writing (single pass), and commit the
    /// content under its SHA-256. Crash-safe: the bytes land in a temp and are
    /// made visible by one atomic rename; a partial ingest never becomes a live
    /// blob. Returns the content's `Digest` (whether newly stored or deduped).
    pub fn put(self: Store, reader: *std.Io.Reader) !Digest {
        var uniq_buf: [40]u8 = undefined;
        const uniq = nextUniq(&uniq_buf);
        var tmp_buf: [768]u8 = undefined;
        const tf = try self.casCreateTemp(uniq, &tmp_buf);
        errdefer self.discardTemp(tf.tmp);

        var hex: [hashdigest.hex_len]u8 = undefined;
        {
            errdefer tf.file.close(self.io);
            var wbuf: [64 * 1024]u8 = undefined;
            var fw = tf.file.writer(self.io, &wbuf);
            var hasher = hashdigest.Hasher.init();
            var chunk: [64 * 1024]u8 = undefined;
            while (true) {
                const n = try reader.readSliceShort(&chunk);
                if (n == 0) break;
                hasher.update(chunk[0..n]);
                try fw.interface.writeAll(chunk[0..n]);
            }
            try fw.interface.flush();
            try tf.file.sync(self.io); // durability: fsync before it becomes visible
            tf.file.close(self.io);
            hasher.finalHex(&hex);
        }
        _ = try self.casCommit(&hex, tf.tmp);
        return .{ .hex = hex };
    }

    /// Put an in-memory slice (convenience over `put`).
    pub fn putBytes(self: Store, bytes: []const u8) !Digest {
        var reader: std.Io.Reader = .fixed(bytes);
        return self.put(&reader);
    }

    /// True if a blob with this digest is stored.
    pub fn has(self: Store, digest: Digest) bool {
        return self.casHas(&digest.hex);
    }

    /// Open a stored blob for reading (caller closes), or null if absent.
    pub fn open(self: Store, digest: Digest) !?std.Io.File {
        return self.casOpen(&digest.hex);
    }

    /// Delete a stored blob; false if it did not exist. See `casDelete` caveat.
    pub fn delete(self: Store, digest: Digest) !bool {
        return self.casDelete(&digest.hex);
    }

    /// Re-hash the stored content and compare against its address: true if intact,
    /// false if the bytes on disk no longer hash to `digest` (bit-rot / tamper).
    /// Returns `error.NotFound` if no such blob exists.
    pub fn verify(self: Store, digest: Digest) !bool {
        var buf: [768]u8 = undefined;
        const path = try self.casPath(&buf, &digest.hex);
        var got: [hashdigest.hex_len]u8 = undefined;
        if (hashdigest.sha256File(self.io, path, &got) == null) return error.NotFound;
        return std.mem.eql(u8, &got, &digest.hex);
    }

    // ── raw namespaced blob layer (name-addressed, no dedup) ───────────────────
    // `<base>/raw/<ns>/<key>`; the caller owns the key. Atomic rename-on-commit
    // like the CAS layer, but keyed by a caller-chosen name instead of a hash.

    fn nsDir(self: Store, buf: []u8, ns: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "{s}/raw/{s}", .{ self.base, ns });
    }

    /// `<base>/raw/<ns>/<key>` written into `buf`. Validates `ns`+`key`.
    pub fn blobPath(self: Store, buf: []u8, ns: []const u8, key: []const u8) ![]const u8 {
        if (!segmentSafe(ns) or !segmentSafe(key)) return error.InvalidName;
        return std.fmt.bufPrint(buf, "{s}/raw/{s}/{s}", .{ self.base, ns, key });
    }

    /// Open a raw blob for reading (caller closes), or null if it does not exist.
    pub fn openBlob(self: Store, ns: []const u8, key: []const u8) !?std.Io.File {
        var buf: [768]u8 = undefined;
        const path = try self.blobPath(&buf, ns, key);
        return std.Io.Dir.cwd().openFile(self.io, path, .{}) catch |e| switch (e) {
            error.FileNotFound => return null,
            else => return e,
        };
    }

    /// Create the ns dir and open a fresh temp to stream a raw blob into. Stream
    /// the body, flush, close, then `commit` to move it into place atomically (a
    /// failed/partial upload never leaves a live blob).
    pub fn createTemp(self: Store, ns: []const u8, key: []const u8, tmp_buf: []u8) !Temp {
        if (!segmentSafe(ns) or !segmentSafe(key)) return error.InvalidName;
        var dbuf: [640]u8 = undefined;
        const dir = try self.nsDir(&dbuf, ns);
        try ensureDir(self.io, dir);
        const tmp = try std.fmt.bufPrint(tmp_buf, "{s}/.{s}.part", .{ dir, key });
        const file = try std.Io.Dir.cwd().createFile(self.io, tmp, .{ .truncate = true });
        return .{ .file = file, .tmp = tmp };
    }

    /// Move a fully-written temp into place as the live raw blob.
    pub fn commit(self: Store, ns: []const u8, key: []const u8, tmp: []const u8) !void {
        var buf: [768]u8 = undefined;
        const path = try self.blobPath(&buf, ns, key);
        const cwd = std.Io.Dir.cwd();
        try cwd.rename(tmp, cwd, path, self.io);
    }

    /// Best-effort removal of a temp file (on a failed upload).
    pub fn discardTemp(self: Store, tmp: []const u8) void {
        std.Io.Dir.cwd().deleteFile(self.io, tmp) catch {};
    }

    /// Delete a live raw blob; returns false if it did not exist.
    pub fn deleteBlob(self: Store, ns: []const u8, key: []const u8) !bool {
        var buf: [768]u8 = undefined;
        const path = try self.blobPath(&buf, ns, key);
        std.Io.Dir.cwd().deleteFile(self.io, path) catch |e| switch (e) {
            error.FileNotFound => return false,
            else => return e,
        };
        return true;
    }

    /// List a namespace's raw blobs (name + size). Missing ns dir ⇒ empty. Hidden
    /// files (our `.…​.part` temps) are skipped. Allocations in `arena`.
    pub fn list(self: Store, arena: std.mem.Allocator, ns: []const u8) ![]Entry {
        if (!segmentSafe(ns)) return error.InvalidName;
        var entries: std.ArrayList(Entry) = .empty;
        var dbuf: [640]u8 = undefined;
        const dir_path = try self.nsDir(&dbuf, ns);
        var dir = std.Io.Dir.cwd().openDir(self.io, dir_path, .{ .iterate = true }) catch |e| switch (e) {
            error.FileNotFound => return entries.toOwnedSlice(arena),
            else => return e,
        };
        defer dir.close(self.io);

        var it = dir.iterate();
        while (try it.next(self.io)) |entry| {
            if (entry.kind != .file) continue;
            if (entry.name.len > 0 and entry.name[0] == '.') continue; // temp
            const st = dir.statFile(self.io, entry.name, .{}) catch continue;
            try entries.append(arena, .{ .key = try arena.dupe(u8, entry.name), .bytes = st.size });
        }
        return entries.toOwnedSlice(arena);
    }

    // ── named records (opaque bytes under a namespace/key scheme) ──────────────
    // `<base>/named/<ns>/<key>`; any small byte record (manifest, index) under
    // an arbitrary namespace/key — not restricted to JSON.

    fn namedDir(self: Store, buf: []u8, ns: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "{s}/named/{s}", .{ self.base, ns });
    }

    /// Write (overwrite) a named record. Validates `ns`+`key`. Atomic: the bytes
    /// land in a hidden temp and are made visible by one `rename(2)`, so a crash
    /// mid-write never leaves a torn record (matches the cas/raw layers).
    pub fn putNamed(self: Store, ns: []const u8, key: []const u8, bytes: []const u8) !void {
        if (!segmentSafe(ns) or !segmentSafe(key)) return error.InvalidName;
        var dbuf: [640]u8 = undefined;
        const dir = try self.namedDir(&dbuf, ns);
        try ensureDir(self.io, dir);
        var uniq_buf: [40]u8 = undefined;
        const uniq = nextUniq(&uniq_buf);
        var tbuf: [820]u8 = undefined;
        const tmp = try std.fmt.bufPrint(&tbuf, "{s}/.{s}.part", .{ dir, uniq });
        var pbuf: [768]u8 = undefined;
        const path = try std.fmt.bufPrint(&pbuf, "{s}/{s}", .{ dir, key });
        const cwd = std.Io.Dir.cwd();
        try cwd.writeFile(self.io, .{ .sub_path = tmp, .data = bytes });
        errdefer cwd.deleteFile(self.io, tmp) catch {};
        try cwd.rename(tmp, cwd, path, self.io);
    }

    /// Read a named record (allocated in `arena`), or null if absent.
    pub fn readNamed(self: Store, arena: std.mem.Allocator, ns: []const u8, key: []const u8) !?[]u8 {
        if (!segmentSafe(ns) or !segmentSafe(key)) return error.InvalidName;
        var dbuf: [640]u8 = undefined;
        const dir = try self.namedDir(&dbuf, ns);
        var pbuf: [768]u8 = undefined;
        const path = try std.fmt.bufPrint(&pbuf, "{s}/{s}", .{ dir, key });
        return std.Io.Dir.cwd().readFileAlloc(self.io, path, arena, .limited(64 * 1024 * 1024)) catch |e| switch (e) {
            error.FileNotFound => return null,
            else => return e,
        };
    }

    /// List a namespace's record keys. Missing ns dir ⇒ empty. Allocations in
    /// `arena`.
    pub fn listNamed(self: Store, arena: std.mem.Allocator, ns: []const u8) ![][]const u8 {
        if (!segmentSafe(ns)) return error.InvalidName;
        var keys: std.ArrayList([]const u8) = .empty;
        var dbuf: [640]u8 = undefined;
        const dir_path = try self.namedDir(&dbuf, ns);
        var dir = std.Io.Dir.cwd().openDir(self.io, dir_path, .{ .iterate = true }) catch |e| switch (e) {
            error.FileNotFound => return keys.toOwnedSlice(arena),
            else => return e,
        };
        defer dir.close(self.io);
        var it = dir.iterate();
        while (try it.next(self.io)) |entry| {
            if (entry.kind != .file) continue;
            if (entry.name.len > 0 and entry.name[0] == '.') continue;
            try keys.append(arena, try arena.dupe(u8, entry.name));
        }
        return keys.toOwnedSlice(arena);
    }

    // ── scratch space (reassemble large artifacts, then stream them out) ───────

    /// Create a uniquely-named scratch file under `<base>/tmp/`. Returns the open
    /// file + its path (clean up with `discardTemp`).
    pub fn scratchCreate(self: Store, uniq: []const u8, path_buf: []u8) !Temp {
        const path = try std.fmt.bufPrint(path_buf, "{s}/tmp/{s}", .{ self.base, uniq });
        const file = try std.Io.Dir.cwd().createFile(self.io, path, .{ .truncate = true });
        return .{ .file = file, .tmp = path };
    }

    // ── cross-process ingest lock ───────────────────────────────────────────────
    // A single advisory flock on `<base>/tmp/.ingest.lock` serializes the
    // commit-and-refcount-mutate section of `casCommit`/`casDelete`/`gc` across
    // processes (and threads sharing them). It does NOT cover the streaming
    // phase of `put` (hashing + writing the temp) — only the section that
    // touches shared on-disk state (the CAS entry + its `.rc` sidecar) needs
    // mutual exclusion; letting concurrent ingests stream into their own
    // (PID+counter-uniquified) temps in parallel is the whole point of
    // per-ingest temp files. The lock is released on every path (defer), so a
    // panic/early-return inside the critical section still drops it rather
    // than wedging every other process open on this store.

    /// Open (creating if needed) and exclusively lock `tmp/.ingest.lock`,
    /// blocking until any other process's/thread's lock on it is released.
    fn lockIngest(self: Store) !std.Io.File {
        var buf: [768]u8 = undefined;
        const path = try std.fmt.bufPrint(&buf, "{s}/tmp/.ingest.lock", .{self.base});
        return std.Io.Dir.cwd().createFile(self.io, path, .{ .truncate = false, .lock = .exclusive });
    }

    fn unlockIngest(self: Store, f: std.Io.File) void {
        f.unlock(self.io);
        f.close(self.io);
    }

    // ── garbage collection (refcounted reachability sweep) ─────────────────────

    /// Result of a `gc` sweep.
    pub const GcStats = struct {
        /// CAS blobs actually unlinked (refcount was zero, not in `keep`).
        blobs_removed: u64 = 0,
        /// Sum of the removed blobs' sizes.
        bytes_reclaimed: u64 = 0,
        /// Abandoned `cas/.ingest-*.part` temps reaped (crash debris).
        temps_removed: u64 = 0,
    };

    pub const GcOptions = struct {
        /// Only reap an ingest temp whose mtime is at least this old, so `gc`
        /// never races a slow-but-live `put` that is still streaming into its
        /// temp on another process/thread. Default 10 minutes: generous for
        /// any single blob ingest, tight enough to actually reclaim crash
        /// debris in routine maintenance sweeps.
        stale_after_ns: u64 = 10 * std.time.ns_per_min,
    };

    /// Reachability sweep and the *only* path that physically reclaims CAS
    /// blobs. Design: **refcounting**, not mark-and-sweep over a full
    /// manifest walk — `put`/`casCommit` already touch every blob's refcount
    /// at the moment they establish a reference (including on a dedup hit),
    /// and `delete`/`casDelete` at the moment they drop one, so the store
    /// always has an accurate zero/nonzero signal without `gc` needing to
    /// know how to parse `named` manifests or any other caller-defined
    /// reference format. `keep` is *additive* on top of that: an explicit
    /// allow-list of digests that must survive this sweep regardless of
    /// their tracked refcount, for callers who want to double-check
    /// reachability against their own root set (e.g. digests pulled live out
    /// of `named` manifests) rather than trust bookkeeping alone — pass
    /// `&.{}` to rely purely on refcounts.
    ///
    /// A CAS blob with **no** `.rc` sidecar at all is left untouched (treated
    /// as still-referenced): sidecars only start existing once `put` or
    /// `delete` touches that digest, so a blob written by a store predating
    /// this feature — and never `delete`d since — has no zero/nonzero signal
    /// to sweep on. It becomes collectible the moment `delete` is called on
    /// it (see `casDelete`'s legacy-blob note).
    ///
    /// Also reaps abandoned `cas/.ingest-*.part` temps older than
    /// `options.stale_after_ns`. Runs the whole sweep under the ingest lock
    /// (see `lockIngest`) so it can't race a concurrent `put`/`casDelete`
    /// refcount mutation on the same store.
    ///
    /// `allocator` is used only for a scratch lookup table built and freed
    /// entirely within this call (to hold `keep`) — any allocator works,
    /// not just an arena; `gc` never leaks or retains it.
    pub fn gc(self: Store, allocator: std.mem.Allocator, keep: []const Digest, options: GcOptions) !GcStats {
        const lockf = try self.lockIngest();
        defer self.unlockIngest(lockf);

        var keep_set: std.StringHashMapUnmanaged(void) = .empty;
        defer keep_set.deinit(allocator);
        try keep_set.ensureTotalCapacity(allocator, @intCast(keep.len));
        for (keep) |*d| keep_set.putAssumeCapacity(d.slice(), {});

        var stats: GcStats = .{};
        stats.temps_removed = try self.reapStaleIngestTemps(options.stale_after_ns);

        var dbuf: [768]u8 = undefined;
        const casdir = try std.fmt.bufPrint(&dbuf, "{s}/cas", .{self.base});
        try self.gcWalk(casdir, self.fanout, &keep_set, &stats);
        return stats;
    }

    /// Recursively walk `self.fanout` levels of CAS fan-out directories,
    /// then sweep zero-refcount, non-`keep`'d blobs at the leaf level.
    fn gcWalk(
        self: Store,
        dir_path: []const u8,
        depth_remaining: u8,
        keep_set: *const std.StringHashMapUnmanaged(void),
        stats: *GcStats,
    ) !void {
        var dir = std.Io.Dir.cwd().openDir(self.io, dir_path, .{ .iterate = true }) catch |e| switch (e) {
            error.FileNotFound => return,
            else => return e,
        };
        defer dir.close(self.io);

        var it = dir.iterate();
        while (try it.next(self.io)) |entry| {
            if (depth_remaining > 0) {
                if (entry.kind != .directory) continue;
                var pbuf: [768]u8 = undefined;
                const sub = try std.fmt.bufPrint(&pbuf, "{s}/{s}", .{ dir_path, entry.name });
                try self.gcWalk(sub, depth_remaining - 1, keep_set, stats);
                continue;
            }
            // Leaf level: blob files. Skip `.rc` sidecars and any hidden
            // (dot-prefixed) temp so a partially-ingested `.ingest-*.part`
            // that happens to live at this depth is never treated as a blob.
            if (entry.kind != .file) continue;
            if (entry.name.len == 0 or entry.name[0] == '.') continue;
            if (std.mem.endsWith(u8, entry.name, ".rc")) continue;
            const hex = entry.name;
            if (keep_set.contains(hex)) continue;

            const rc = self.readRcInDir(dir, hex) orelse continue; // no sidecar ⇒ untracked, keep
            if (rc != 0) continue; // still referenced

            const size = if (dir.statFile(self.io, hex, .{}) catch null) |st| st.size else 0;
            dir.deleteFile(self.io, hex) catch continue;
            var rcbuf: [80]u8 = undefined;
            if (std.fmt.bufPrint(&rcbuf, "{s}.rc", .{hex})) |rc_name| {
                dir.deleteFile(self.io, rc_name) catch {};
            } else |_| {}
            stats.blobs_removed += 1;
            stats.bytes_reclaimed += size;
        }
    }

    /// Read a blob's `.rc` sidecar relative to its already-open fan-out
    /// `dir`. Null means "no sidecar" (untracked/legacy), distinct from a
    /// tracked refcount of zero.
    fn readRcInDir(self: Store, dir: std.Io.Dir, hex: []const u8) ?u64 {
        var rcbuf: [80]u8 = undefined;
        const rc_name = std.fmt.bufPrint(&rcbuf, "{s}.rc", .{hex}) catch return null;
        var vbuf: [24]u8 = undefined;
        const data = dir.readFile(self.io, rc_name, &vbuf) catch return null;
        return std.fmt.parseInt(u64, std.mem.trim(u8, data, " \t\r\n"), 10) catch null;
    }

    /// Reap `cas/.ingest-*.part` temps (abandoned mid-`put` streams) whose
    /// mtime is at least `stale_after_ns` old. Ingest temps always live
    /// directly under `cas/`, never inside a fan-out subdirectory, regardless
    /// of `self.fanout` (see `casCreateTemp`), so this needs no recursion.
    fn reapStaleIngestTemps(self: Store, stale_after_ns: u64) !u64 {
        var dbuf: [768]u8 = undefined;
        const casdir = try std.fmt.bufPrint(&dbuf, "{s}/cas", .{self.base});
        var dir = std.Io.Dir.cwd().openDir(self.io, casdir, .{ .iterate = true }) catch |e| switch (e) {
            error.FileNotFound => return 0,
            else => return e,
        };
        defer dir.close(self.io);

        const now = std.Io.Timestamp.now(self.io, .real);
        var removed: u64 = 0;
        var it = dir.iterate();
        while (try it.next(self.io)) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.startsWith(u8, entry.name, ".ingest-")) continue;
            const st = dir.statFile(self.io, entry.name, .{}) catch continue;
            const age_ns = st.mtime.durationTo(now).nanoseconds;
            if (age_ns < 0 or @as(u64, @intCast(age_ns)) < stale_after_ns) continue;
            dir.deleteFile(self.io, entry.name) catch continue;
            removed += 1;
        }
        return removed;
    }
};

/// A path segment is safe if it is non-empty, ≤128 chars, not `.`/`..`, has no
/// leading dot (reserves the `.part` temp convention), and contains only
/// `[A-Za-z0-9._-]` (so it cannot contain `/` or traverse the store).
pub fn segmentSafe(s: []const u8) bool {
    if (s.len == 0 or s.len > 128) return false;
    if (s[0] == '.') return false;
    for (s) |c| {
        const ok = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.';
        if (!ok) return false;
    }
    return true;
}

fn ensureDir(io: std.Io, path: []const u8) !void {
    std.Io.Dir.cwd().createDir(io, path, .default_dir) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };
}

fn nextUniq(buf: []u8) []const u8 {
    const n = ingest_counter.fetchAdd(1, .monotonic);
    // PID + process-local counter: makes the temp name unique across
    // processes too (not just within one), not only within a process.
    return std.fmt.bufPrint(buf, "{d}-{d}", .{ linux.getpid(), n }) catch unreachable; // fits in 40
}

// ── tests ──────────────────────────────────────────────────────────────────────

const t = std.testing;

/// Open a fresh store rooted in a throwaway tmpdir. Returns the store and the
/// `.zig-cache/tmp/<sub>` base path; caller keeps `tmp` alive and cleans it up.
fn testStore(tmp: *std.testing.TmpDir, base_buf: []u8) !Store {
    const io = std.testing.io;
    const base = try std.fmt.bufPrint(base_buf, ".zig-cache/tmp/{s}/store", .{&tmp.sub_path});
    return Store.init(io, base);
}

test "segmentSafe accepts blob names, rejects traversal" {
    try t.expect(segmentSafe("dev-SN-001"));
    try t.expect(segmentSafe("2026-06-28.tar.gz"));
    try t.expect(segmentSafe("config_backup.bin"));
    try t.expect(!segmentSafe(""));
    try t.expect(!segmentSafe(".."));
    try t.expect(!segmentSafe("."));
    try t.expect(!segmentSafe(".hidden"));
    try t.expect(!segmentSafe("a/b"));
    try t.expect(!segmentSafe("a b"));
    try t.expect(!segmentSafe("../etc/passwd"));
}

test "Digest.fromHex validates length and lowercase-hex alphabet" {
    const ok = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const d = try Digest.fromHex(ok);
    try t.expectEqualStrings(ok, d.slice());
    try t.expectError(error.InvalidName, Digest.fromHex("abc")); // too short
    try t.expectError(error.InvalidName, Digest.fromHex("x" ++ ok[1..])); // non-hex
    var upper: [64]u8 = undefined;
    for (ok, 0..) |c, i| upper[i] = std.ascii.toUpper(c);
    try t.expectError(error.InvalidName, Digest.fromHex(&upper)); // uppercase rejected
}

test "put: content-address round-trip (small + large > pipe buffer)" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);

    // small
    const small = "the quick brown fox";
    const ds = try store.putBytes(small);
    var want: [hashdigest.hex_len]u8 = undefined;
    hashdigest.sha256Hex(&want, small);
    try t.expectEqualStrings(&want, ds.slice());
    try t.expect(store.has(ds));

    // large: 1 MiB, well past any pipe/stack buffer, exercises multi-chunk stream
    const gpa = std.testing.allocator;
    const big = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i *% 2654435761);
    const dbig = try store.putBytes(big);
    hashdigest.sha256Hex(&want, big);
    try t.expectEqualStrings(&want, dbig.slice());

    // read the large blob back and assert byte-identity
    var f = (try store.open(dbig)).?;
    defer f.close(io);
    var rbuf: [64 * 1024]u8 = undefined;
    var fr = std.Io.File.Reader.initStreaming(f, io, &rbuf);
    const got = try fr.interface.allocRemaining(gpa, .unlimited);
    defer gpa.free(got);
    try t.expectEqualSlices(u8, big, got);
    try t.expect(try store.verify(dbig));
}

test "put: identical content dedups to one on-disk blob" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const io = std.testing.io;

    const data = "dedup me please";
    const d1 = try store.putBytes(data);
    const d2 = try store.putBytes(data);
    try t.expectEqualStrings(d1.slice(), d2.slice());

    // exactly one blob file in the fan-out dir cas/<hh>/ (plus its `.rc`
    // refcount sidecar, bumped to 2 by the second, deduped put).
    var fbuf: [300]u8 = undefined;
    const fan = try std.fmt.bufPrint(&fbuf, "{s}/cas/{s}", .{ store.base, d1.hex[0..2] });
    var dir = try std.Io.Dir.cwd().openDir(io, fan, .{ .iterate = true });
    defer dir.close(io);
    var count: usize = 0;
    var rc_count: usize = 0;
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (e.kind != .file) continue;
        if (std.mem.endsWith(u8, e.name, ".rc")) rc_count += 1 else count += 1;
    }
    try t.expectEqual(@as(usize, 1), count);
    try t.expectEqual(@as(usize, 1), rc_count);
    try t.expectEqual(@as(u64, 2), store.casRefRead(&d1.hex, 0));

    // no leftover ingest temps in cas/
    var cbuf: [300]u8 = undefined;
    const casdir = try std.fmt.bufPrint(&cbuf, "{s}/cas", .{store.base});
    var cd = try std.Io.Dir.cwd().openDir(io, casdir, .{ .iterate = true });
    defer cd.close(io);
    var temps: usize = 0;
    var cit = cd.iterate();
    while (try cit.next(io)) |e| {
        if (e.kind == .file and std.mem.startsWith(u8, e.name, ".ingest-")) temps += 1;
    }
    try t.expectEqual(@as(usize, 0), temps);
}

test "verify: detects deliberate corruption; NotFound on absent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const io = std.testing.io;

    const d = try store.putBytes("content worth protecting");
    try t.expect(try store.verify(d));

    // flip the stored bytes behind the CAS's back → verify must catch it
    var pbuf: [768]u8 = undefined;
    const path = try store.casPath(&pbuf, &d.hex);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "tampered!" });
    try t.expect(!try store.verify(d));

    // absent digest
    const absent = try Digest.fromHex("0000000000000000000000000000000000000000000000000000000000000000");
    try t.expectError(error.NotFound, store.verify(absent));
    try t.expect(!store.has(absent));
}

test "crash safety: an abandoned temp never becomes a live blob" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const io = std.testing.io;

    // a committed blob we will prove stays untouched
    const live = try store.putBytes("i am safely committed");

    // simulate a torn upload: create an ingest temp, write partial bytes, then
    // "crash" (never commit). Delete it as a crash-recovery sweep would.
    var tbuf: [768]u8 = undefined;
    const temp = try store.casCreateTemp("crashy", &tbuf);
    {
        var wbuf: [64]u8 = undefined;
        var fw = temp.file.writer(io, &wbuf);
        try fw.interface.writeAll("half-written garbage");
        try fw.interface.flush();
        temp.file.close(io);
    }
    // the temp exists but no live blob was ever created from it
    store.discardTemp(temp.tmp);

    // the previously committed blob is intact and still verifies
    try t.expect(store.has(live));
    try t.expect(try store.verify(live));
    // and nothing leaked into the fan-out as a live object other than `live`
    var fbuf: [300]u8 = undefined;
    const fan = try std.fmt.bufPrint(&fbuf, "{s}/cas/{s}", .{ store.base, live.hex[0..2] });
    var dir = try std.Io.Dir.cwd().openDir(io, fan, .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (e.kind != .file) continue;
        if (std.mem.endsWith(u8, e.name, ".rc")) continue; // refcount sidecar, not a blob
        try t.expectEqualStrings(&live.hex, e.name);
    }
}

test "raw layer: create/commit/open/delete + traversal rejected" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const io = std.testing.io;
    const gpa = std.testing.allocator;

    // path-safety guards on every entry point
    try t.expectError(error.InvalidName, store.openBlob("..", "x"));
    var junk: [768]u8 = undefined;
    try t.expectError(error.InvalidName, store.createTemp("ns", "a/b", &junk));

    // atomic create → commit
    var tbuf: [768]u8 = undefined;
    const w = try store.createTemp("dev1", "backup.bin", &tbuf);
    {
        var wbuf: [64]u8 = undefined;
        var fw = w.file.writer(io, &wbuf);
        try fw.interface.writeAll("raw payload");
        try fw.interface.flush();
        w.file.close(io);
    }
    // not visible before commit
    try t.expect((try store.openBlob("dev1", "backup.bin")) == null);
    try store.commit("dev1", "backup.bin", w.tmp);

    var f = (try store.openBlob("dev1", "backup.bin")).?;
    var rbuf: [64]u8 = undefined;
    var fr = std.Io.File.Reader.initStreaming(f, io, &rbuf);
    const got = try fr.interface.allocRemaining(gpa, .unlimited);
    f.close(io);
    defer gpa.free(got);
    try t.expectEqualStrings("raw payload", got);

    // list shows it, hides temps
    const items = try store.list(gpa, "dev1");
    defer {
        for (items) |it| gpa.free(it.key);
        gpa.free(items);
    }
    try t.expectEqual(@as(usize, 1), items.len);
    try t.expectEqualStrings("backup.bin", items[0].key);
    try t.expectEqual(@as(u64, "raw payload".len), items[0].bytes);

    try t.expect(try store.deleteBlob("dev1", "backup.bin"));
    try t.expect(!try store.deleteBlob("dev1", "backup.bin"));
    try t.expect((try store.openBlob("dev1", "backup.bin")) == null);
}

test "named records: put/read/list, namespaced, missing ⇒ null/empty" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const gpa = std.testing.allocator;

    try t.expect((try store.readNamed(gpa, "hostA", "snap-1")) == null);
    try t.expectError(error.InvalidName, store.putNamed("..", "k", "x"));

    try store.putNamed("hostA", "snap-1", "manifest bytes 1");
    try store.putNamed("hostA", "snap-2", "manifest bytes 2");
    try store.putNamed("hostB", "snap-1", "other host");

    const r = (try store.readNamed(gpa, "hostA", "snap-1")).?;
    defer gpa.free(r);
    try t.expectEqualStrings("manifest bytes 1", r);

    // overwrite semantics
    try store.putNamed("hostA", "snap-1", "rewritten");
    const r2 = (try store.readNamed(gpa, "hostA", "snap-1")).?;
    defer gpa.free(r2);
    try t.expectEqualStrings("rewritten", r2);

    const keys = try store.listNamed(gpa, "hostA");
    defer {
        for (keys) |k| gpa.free(k);
        gpa.free(keys);
    }
    try t.expectEqual(@as(usize, 2), keys.len);

    // listing an unknown namespace is empty, not an error
    const none = try store.listNamed(gpa, "nope");
    defer gpa.free(none);
    try t.expectEqual(@as(usize, 0), none.len);
}

test "gc: sweeps a zero-refcount orphan, keeps a live one AND an explicit keep" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const gpa = std.testing.allocator;

    // live: put, never deleted ⇒ refcount 1, must survive gc untouched.
    const live = try store.putBytes("kept alive by a real reference");
    // orphan: put then deleted to zero ⇒ must be swept.
    const orphan = try store.putBytes("nobody references me anymore");
    try t.expect(try store.delete(orphan));
    // rescued: put then deleted to zero too, but named in `keep` ⇒ survives
    // despite a zero refcount (the mark-sweep escape hatch on top of
    // refcounting).
    const rescued = try store.putBytes("zero refcount but explicitly kept");
    try t.expect(try store.delete(rescued));

    try t.expect(store.has(live));
    try t.expect(store.has(orphan)); // not yet physically reclaimed
    try t.expect(store.has(rescued));

    const stats = try store.gc(gpa, &.{rescued}, .{});
    try t.expectEqual(@as(u64, 1), stats.blobs_removed);
    try t.expectEqual(@as(u64, "nobody references me anymore".len), stats.bytes_reclaimed);

    // positive control: the kept blobs are still readable end-to-end.
    try t.expect(store.has(live));
    var f = (try store.open(live)).?;
    const io = std.testing.io;
    var rbuf: [64]u8 = undefined;
    var fr = std.Io.File.Reader.initStreaming(f, io, &rbuf);
    const got = try fr.interface.allocRemaining(gpa, .unlimited);
    f.close(io);
    defer gpa.free(got);
    try t.expectEqualStrings("kept alive by a real reference", got);
    try t.expect(store.has(rescued));

    // the orphan is actually gone from disk, not just logically deleted.
    try t.expect(!store.has(orphan));
    var pbuf: [768]u8 = undefined;
    const orphan_path = try store.casPath(&pbuf, &orphan.hex);
    try t.expectError(error.FileNotFound, std.Io.Dir.cwd().access(io, orphan_path, .{}));

    // running gc again is a no-op (idempotent — nothing left to sweep).
    const stats2 = try store.gc(gpa, &.{rescued}, .{});
    try t.expectEqual(@as(u64, 0), stats2.blobs_removed);
}

test "refcount: survives repeated puts of the same content, only collectible at zero" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const gpa = std.testing.allocator;

    const data = "deduped content, three live references";
    const d1 = try store.putBytes(data); // refcount 1
    const d2 = try store.putBytes(data); // dedup hit ⇒ refcount 2
    const d3 = try store.putBytes(data); // dedup hit ⇒ refcount 3
    try t.expectEqualStrings(d1.slice(), d2.slice());
    try t.expectEqualStrings(d1.slice(), d3.slice());

    // drop two of the three references; one remains ⇒ gc must NOT collect it.
    try t.expect(try store.delete(d1));
    try t.expect(try store.delete(d2));
    var stats = try store.gc(gpa, &.{}, .{});
    try t.expectEqual(@as(u64, 0), stats.blobs_removed);
    try t.expect(store.has(d3));

    // drop the last reference ⇒ now collectible.
    try t.expect(try store.delete(d3));
    stats = try store.gc(gpa, &.{}, .{});
    try t.expectEqual(@as(u64, 1), stats.blobs_removed);
    try t.expect(!store.has(d1));

    // deleting an absent digest is a no-op false, not an error.
    try t.expect(!try store.delete(d1));
}

test "configurable fan-out: round-trips at fanout=1 (default), 2, and 3" {
    const gpa = std.testing.allocator;
    inline for (.{ 1, 2, 3 }) |fanout| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var base_buf: [256]u8 = undefined;
        const base = try std.fmt.bufPrint(&base_buf, ".zig-cache/tmp/{s}/store", .{&tmp.sub_path});
        const store = try Store.initOptions(std.testing.io, base, .{ .fanout = fanout });
        try t.expectEqual(@as(u8, fanout), store.fanout);

        const payload = "fan-out round-trip payload";
        const d = try store.putBytes(payload);

        // the blob physically lives `fanout` directories deep.
        var pbuf: [768]u8 = undefined;
        const path = try store.casPath(&pbuf, &d.hex);
        var want_buf: [768]u8 = undefined;
        var w: usize = (try std.fmt.bufPrint(&want_buf, "{s}/cas", .{base})).len;
        var i: u8 = 0;
        while (i < fanout) : (i += 1) {
            w += (try std.fmt.bufPrint(want_buf[w..], "/{s}", .{d.hex[2 * i .. 2 * i + 2]})).len;
        }
        w += (try std.fmt.bufPrint(want_buf[w..], "/{s}", .{&d.hex})).len;
        try t.expectEqualStrings(want_buf[0..w], path);

        // and reads back byte-identical regardless of nesting depth.
        try t.expect(store.has(d));
        var f = (try store.open(d)).?;
        const io = std.testing.io;
        var rbuf: [64]u8 = undefined;
        var fr = std.Io.File.Reader.initStreaming(f, io, &rbuf);
        const got = try fr.interface.allocRemaining(gpa, .unlimited);
        f.close(io);
        defer gpa.free(got);
        try t.expectEqualStrings(payload, got);
    }
}

test "Store.init still opens a store written at the default (fanout=1) layout" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const base = try std.fmt.bufPrint(&base_buf, ".zig-cache/tmp/{s}/store", .{&tmp.sub_path});

    // a store created the plain way (no Options) ...
    const store = try Store.init(std.testing.io, base);
    const d = try store.putBytes("back-compat payload");

    // ... reopens fine via init() and finds the same blob at cas/<hh>/<hex>,
    // proving the default fan-out is unchanged.
    const reopened = try Store.init(std.testing.io, base);
    try t.expectEqual(@as(u8, 1), reopened.fanout);
    try t.expect(reopened.has(d));
    var buf: [768]u8 = undefined;
    const path = try reopened.casPath(&buf, &d.hex);
    try t.expect(std.mem.indexOf(u8, path, d.hex[0..2]) != null);
}

test "cross-process ingest lock: repeated put/delete/gc from one writer never deadlocks" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const gpa = std.testing.allocator;

    // Each of put/delete/gc independently acquires-and-releases the ingest
    // lock; a single writer doing this in a tight sequence (including two
    // back-to-back lock acquisitions inside one gc call, and a gc that finds
    // nothing to do) must never hang. If the lock leaked instead of being
    // released, the second `putBytes` below would block forever and the test
    // would time out.
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        const d = try store.putBytes("lock round-trip payload");
        try t.expect(try store.delete(d));
        _ = try store.gc(gpa, &.{}, .{});
    }
    // a second handle re-opened over the same base must also be able to
    // acquire the (now-existing) lock file without issue.
    const store2 = try Store.init(std.testing.io, store.base);
    const d2 = try store2.putBytes("second handle, same base");
    try t.expect(store2.has(d2));
}
