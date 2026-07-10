// SPDX-License-Identifier: MIT
//! blobstore — content-addressed blob store (git-object / restic style):
//! atomic rename-on-commit, sha256 fan-out layout, dedup, namespaced blobs.
//!
//! Layout under `base`:
//!  - `cas/<hh>/<hex>`   content-addressed store; a blob's bytes live once,
//!    keyed by their SHA-256 (`hh` = first two hex chars = 256-way fan-out so
//!    no directory holds the whole corpus). Identical content dedups.
//!  - `raw/<ns>/<key>`   a plain namespaced blob layer (name-addressed, not
//!    dedup'd) for when the caller owns the key.
//!  - `named/<ns>/<key>` small opaque byte records (manifests, indexes) under
//!    a `namespace/key` scheme.
//!  - `tmp/`             scratch space + in-flight ingest temps.
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
//! Provenance: original work of the zig-libs authors (MIT). Provides the
//! raw/CAS/scratch/manifest layers and `segmentSafe`, `put` (single-pass
//! hash-while-write), `verify` (bit-rot detection), the `Digest` type,
//! segment validation on every entry point, and a `named` record scheme
//! (arbitrary namespace/key). sha256 comes from the sibling `hashdigest`
//! module; nothing cryptographic is reimplemented here.

const std = @import("std");
const hashdigest = @import("hashdigest");

pub const meta = .{
    .platform = .posix, // atomic rename-on-commit; std.Io filesystem API
    .role = .util,
    .concurrency = .reentrant, // no shared state bar a process-local ingest counter
    .model_after = "git object store / restic",
    .deps = .{"hashdigest"},
};

/// Errors specific to this module (I/O errors from `std.Io` are unioned in).
pub const Error = error{
    /// An `ns`/`key` argument is not a safe single path segment (`segmentSafe`).
    InvalidName,
    /// `verify`/`open` on a digest whose CAS blob does not exist.
    NotFound,
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

/// Process-local monotonically increasing counter for collision-free temp names
/// within a process. Cross-process uniqueness is out of scope — see the README
/// backlog (cross-process locking); `createFile(.truncate)` means a same-name
/// clash across processes is a corrupted *ingest*, never a corrupted live blob.
var ingest_counter: std.atomic.Value(u64) = .init(0);

pub const Store = struct {
    io: std.Io,
    base: []const u8,

    /// Ensure `base` and its `cas/`, `raw/`, `named/`, `tmp/` subdirs exist.
    pub fn init(io: std.Io, base: []const u8) !Store {
        try ensureDir(io, base);
        var buf: [512]u8 = undefined;
        try ensureDir(io, try std.fmt.bufPrint(&buf, "{s}/cas", .{base}));
        try ensureDir(io, try std.fmt.bufPrint(&buf, "{s}/raw", .{base}));
        try ensureDir(io, try std.fmt.bufPrint(&buf, "{s}/named", .{base}));
        try ensureDir(io, try std.fmt.bufPrint(&buf, "{s}/tmp", .{base}));
        return .{ .io = io, .base = base };
    }

    // ── content-addressed store (dedup at the file level) ──────────────────────
    // A blob's content lives once at `<base>/cas/<hex[0:2]>/<hex>` (2-char
    // fan-out so a directory never holds the whole corpus).

    /// `<base>/cas/<hh>/<hex>` written into `buf` (`hex` is a 64-char sha256).
    pub fn casPath(self: Store, buf: []u8, hex: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "{s}/cas/{s}/{s}", .{ self.base, hex[0..2], hex });
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

    /// Commit a hashed temp into the CAS as `<hex>`. Returns true if newly stored,
    /// false if the content already existed (dedup — the temp is removed).
    pub fn casCommit(self: Store, hex: []const u8, tmp: []const u8) !bool {
        if (self.casHas(hex)) {
            self.discardTemp(tmp);
            return false;
        }
        var dbuf: [640]u8 = undefined;
        try ensureDir(self.io, try std.fmt.bufPrint(&dbuf, "{s}/cas/{s}", .{ self.base, hex[0..2] }));
        var pbuf: [768]u8 = undefined;
        const path = try self.casPath(&pbuf, hex);
        const cwd = std.Io.Dir.cwd();
        try cwd.rename(tmp, cwd, path, self.io);
        return true;
    }

    /// Delete a content blob; returns false if it did not exist. NOTE: no
    /// reference counting — deleting a blob still referenced by a manifest breaks
    /// that manifest (see the README backlog).
    pub fn casDelete(self: Store, hex: []const u8) !bool {
        var buf: [768]u8 = undefined;
        const path = try self.casPath(&buf, hex);
        std.Io.Dir.cwd().deleteFile(self.io, path) catch |e| switch (e) {
            error.FileNotFound => return false,
            else => return e,
        };
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
    return std.fmt.bufPrint(buf, "{d}", .{n}) catch unreachable; // u64 fits in 40
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

    // exactly one file in the fan-out dir cas/<hh>/
    var fbuf: [300]u8 = undefined;
    const fan = try std.fmt.bufPrint(&fbuf, "{s}/cas/{s}", .{ store.base, d1.hex[0..2] });
    var dir = try std.Io.Dir.cwd().openDir(io, fan, .{ .iterate = true });
    defer dir.close(io);
    var count: usize = 0;
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (e.kind == .file) count += 1;
    }
    try t.expectEqual(@as(usize, 1), count);

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
        if (e.kind == .file) try t.expectEqualStrings(&live.hex, e.name);
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
