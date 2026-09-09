// SPDX-License-Identifier: MIT
//! filestore — DB-less durable keyed document store: kind/key files with
//! atomic temp-then-rename writes + typed-JSON convenience. std-only.
//!
//! Layout: `<base>/<kind>/<key>` — one flat file per record, grouped under a
//! per-kind directory. `putBytes`/`getBytes`/`delete`/`list` are opaque bytes;
//! `put`/`get`/`listTyped` (typed JSON) round-trip through the very same files
//! — JSON encode/decode is the only difference, not a separate layout.
//!
//! **Crash safety.** Every write lands in a hidden `.part` temp (named with a
//! process-local ingest counter, so concurrent writers *within one process*
//! never collide on the same temp path) and is made visible by a single
//! `rename(2)` — atomic on POSIX. A crash mid-write leaves only an orphaned
//! temp (never listed, never read); a live record is never torn or partial.
//! The temp is `fsync`ed BEFORE the rename and the directory `fsync`ed
//! after it, so a `putBytes` that returned survives a power loss — without
//! those two, temp-then-rename buys tear avoidance only, and this module
//! issued neither until 2026-09-03 while calling itself durable (measured
//! on its own example with `strace`: 5 renames, 0 fsyncs; now 5 and 10).
//!
//! **Path safety.** `kind` and `key` are each validated by `segmentSafe`
//! (`[A-Za-z0-9._-]`, no leading dot, no `.`/`..`, no `/`), checked on every
//! public entry point, so a request can never escape `base`.
//!
//! **TTL, CAS and locking (sidecars, not headers).** Three optional layers
//! sit beside the raw-bytes/typed-JSON layer, all keyed off the same
//! `kind`/`key` and stored as hidden per-key sidecar files next to the
//! record (never a header inside the record — so a plain `getBytes` on a
//! TTL'd or CAS'd record still returns exactly the caller's bytes, nothing
//! prepended):
//!   - `putWithTTL`/`sweep` — `.{key}.expiry` holds the absolute deadline
//!     (decimal ns since epoch, wall-clock via `Store.clock`). `get`/
//!     `getBytes` treat an expired record as absent (read-only — they never
//!     delete); `sweep` is the only thing that actually removes expired
//!     records. `putBytes`/`casPutBytes` do **not** touch a prior `.expiry`
//!     sidecar — see the doc comment on `putWithTTL` for the mixing caveat.
//!   - `casPutBytes`/`getBytesVersioned` — no sidecar at all: `Version` is a
//!     `Wyhash` fingerprint of the record's own bytes, recomputed on read,
//!     so there is nothing to keep in sync.
//!   - `lockKey` — `.{key}.lock`, an advisory `flock` held for the duration
//!     of a read-check-write. Used internally by `casPutBytes`/`putWithTTL`/
//!     `sweep`; exposed so callers doing their own multi-step
//!     read-modify-write across processes can serialize on it too. Plain
//!     `putBytes`/`getBytes`/`delete` stay lock-free (last-write-wins on the
//!     bare `rename(2)`, as before) — no perf cost for callers who never
//!     touch TTL/CAS.
//!
//! Provenance: original work of the zig-libs authors (MIT). A `kind/id.json`
//! layout with a read/list/delete shape, atomic temp-then-rename writes,
//! `segmentSafe` path validation (no traversal escape), a
//! raw-bytes-vs-typed-JSON split, and a `listTyped` skipped-count report
//! (unparseable files are tolerantly skipped but *counted*, never silently
//! dropped).

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

/// Test-only instrumentation: how many times `Store.syncDir` actually ran.
/// Guarded by `builtin.is_test` so it costs nothing (dead branch, eliminated
/// at comptime) in a real build — see the F1/F5 dispositions in the audit
/// record for what this proves (durable `delete`, and `putManyBytes`
/// amortizing the directory fsync across a batch instead of one per record).
var test_sync_dir_calls: std.atomic.Value(u32) = .init(0);

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "DB-less durable keyed document store — one atomically-written file per record, plus a typed-JSON convenience layer.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "posix",
    .targets = .{.linux64},
    .platform = .posix, // atomic rename-on-commit; std.Io filesystem API
    .role = .util,
    .concurrency = .reentrant, // no shared state bar a process-local ingest counter
    .model_after = "content-addressed / flat-file document store",
    .deps = .{},
};

pub const Error = error{
    /// A `kind`/`key` argument is not a safe single path segment (`segmentSafe`).
    InvalidName,
    /// `casPutBytes`: the record's current version did not match `expected`
    /// (or existed/didn't-exist opposite of what `expected` implied).
    VersionMismatch,
    /// `putWithTTL` called on a store opened with `Store.ttl = false`: that
    /// store's own `getBytes` never checks the `.expiry` sidecar this call
    /// would create, so the record it just wrote would never expire from
    /// this store's point of view — refused loudly instead of silently
    /// writing a sidecar the store will then ignore. See `Store.ttl`'s doc
    /// comment.
    TtlDisabled,
};

/// Process-local monotonically increasing counter for collision-free ingest
/// temp names within a process (mirrors the sibling `blobstore` module).
/// `nextUniq` mixes in the pid too, so this is collision-free *across*
/// processes as well — see `nextUniq`.
var ingest_counter: std.atomic.Value(u64) = .init(0);

// ── clock injection (deterministic under test) ──────────────────────────────

/// Wall-clock time source for TTL accounting, injected so tests are
/// deterministic. Unlike a monotonic clock, this must be wall-clock: the
/// store is durable on disk, so an expiry recorded before a process restart
/// must still compare sensibly against `now` after one.
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (?*anyopaque) i64,

    /// The OS realtime clock (ns since the Unix epoch) — the production
    /// default and the only place the module reads a real clock.
    pub const wall_clock: Clock = .{ .nowFn = wallNow };

    fn now(c: Clock) i64 {
        return c.nowFn(c.ctx);
    }
};

fn wallNow(_: ?*anyopaque) i64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts)) != .SUCCESS) return 0;
    return @as(i64, @intCast(ts.sec)) * std.time.ns_per_s + @as(i64, @intCast(ts.nsec));
}

// ── version / ETag (content fingerprint, no sidecar needed) ────────────────

/// A record's version/ETag — a `Wyhash` fingerprint of its bytes, fixed-seed
/// so it is stable across process restarts (a caller may hold a `Version`
/// captured in a previous run). Two records with identical bytes always
/// compare equal: this is a *content* fingerprint (like an HTTP strong
/// ETag), not a monotonic counter — it detects "did the bytes change from
/// what I last saw", which is exactly what CAS needs, without needing any
/// extra on-disk state to keep in sync with the record.
pub const Version = u64;

/// Fixed seed ("filestor" as bytes) so `Version` is stable across process
/// restarts and Zig versions (not derived from ASLR/ptr/PID).
const version_seed: u64 = 0x66696c6573746f72;

pub fn versionOf(bytes: []const u8) Version {
    return std.hash.Wyhash.hash(version_seed, bytes);
}

pub const Store = struct {
    io: std.Io,
    base: []const u8,
    /// Time source for TTL accounting (injected in tests). Wall-clock by
    /// default — see `Clock`.
    clock: Clock = .wall_clock,
    /// Whether `getBytes` (and everything built on it — `get`/`listTyped`)
    /// checks the `.expiry` sidecar at all. Defaults to `true`, reproducing
    /// the original behaviour: every `getBytes` call opens/reads
    /// `.{key}.expiry` (an extra syscall that fails with `FileNotFound` for
    /// a key that was never `putWithTTL`'d) before it reads the record.
    ///
    /// Set `ttl = false` on a store that **never calls `putWithTTL`** to
    /// skip that probe on every `getBytes` — for a `list`-then-`get` sweep
    /// over a large roster this halves the syscall count. `putWithTTL`
    /// refuses with `error.TtlDisabled` on a `ttl = false` store (see its
    /// doc comment) rather than creating a sidecar the store's own
    /// `getBytes` would then never check — this closes off the "opted-out
    /// store resurrects its own TTL'd record" case by construction; it is
    /// not reachable. `sweep` is still unaffected either way (it does not
    /// consult this flag), so a store that already has TTL'd records from
    /// before it was reconfigured keeps its exact existing `sweep` behaviour.
    ///
    /// **Hazard, still reachable:** `ttl = false` does not delete or ignore
    /// an *existing* `.expiry` sidecar, it only stops `getBytes` from
    /// looking for one. A record TTL'd while `ttl` was `true` (or by a
    /// differently configured writer sharing the same `base`) and then read
    /// through a store later reconfigured to `ttl = false` will keep being
    /// returned by `getBytes` **after its deadline has passed** — silently,
    /// since the check that would report it absent never runs. Only opt out
    /// on a store you are certain has no pre-existing TTL'd records; `sweep`
    /// still physically removes expired records if called, but nothing
    /// calls it automatically.
    ttl: bool = true,

    /// Ensure `base` exists.
    pub fn init(io: std.Io, base: []const u8) !Store {
        try ensureDir(io, base);
        return .{ .io = io, .base = base };
    }

    fn kindDir(self: Store, buf: []u8, kind: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, "{s}/{s}", .{ self.base, kind });
    }

    /// `<base>/<kind>/<key>` written into `buf`. Validates both segments.
    fn recordPath(self: Store, buf: []u8, kind: []const u8, key: []const u8) ![]const u8 {
        if (!segmentSafe(kind) or !segmentSafe(key)) return error.InvalidName;
        return std.fmt.bufPrint(buf, "{s}/{s}/{s}", .{ self.base, kind, key });
    }

    /// `.{key}{suffix}` written into `buf` — the hidden sidecar filename
    /// convention for TTL (`.expiry`) and lock (`.lock`) metadata. A leading
    /// dot means it can never collide with a real key (`segmentSafe` forbids
    /// leading dots) and is already skipped by `list`'s hidden-file filter.
    fn sidecarName(buf: []u8, key: []const u8, comptime suffix: []const u8) ![]const u8 {
        return std.fmt.bufPrint(buf, ".{s}" ++ suffix, .{key});
    }

    /// `<base>/<kind>/.<key>{suffix}` written into `buf`. `kind`/`key` are
    /// assumed already `segmentSafe`-validated by the caller.
    fn sidecarPath(self: Store, buf: []u8, kind: []const u8, key: []const u8, comptime suffix: []const u8) ![]const u8 {
        var dbuf: [640]u8 = undefined;
        const dir = try self.kindDir(&dbuf, kind);
        var nbuf: [160]u8 = undefined;
        const name = try sidecarName(&nbuf, key, suffix);
        return std.fmt.bufPrint(buf, "{s}/{s}", .{ dir, name });
    }

    // ── raw bytes layer (atomic, opaque) ────────────────────────────────────

    /// Write `bytes` to `<dir>/<name>` atomically (temp + rename). `name` is
    /// used verbatim, not `segmentSafe`-checked — callers pre-validate (a
    /// real record's `key`) or build it internally (a `.`-prefixed sidecar
    /// name, which can never collide with a validated key). Shared by
    /// `putBytes` and the TTL/lock sidecar writers so there is exactly one
    /// temp-then-rename implementation.
    fn writeFileAtomicIn(self: Store, dir: []const u8, name: []const u8, bytes: []const u8) !void {
        try self.writeFileAtomicInEx(dir, name, bytes, .{ .sync_dir = true });
    }

    /// Same as `writeFileAtomicIn`, but the directory fsync is optional —
    /// `putManyBytes` writes a whole batch with `.sync_dir = false` and syncs
    /// the directory itself exactly once, after the loop. Every other caller
    /// keeps `sync_dir = true` (one file, one fsync, same as before F5).
    fn writeFileAtomicInEx(self: Store, dir: []const u8, name: []const u8, bytes: []const u8, opts: struct { sync_dir: bool }) !void {
        try ensureDir(self.io, dir);

        var uniq_buf: [48]u8 = undefined; // "{pid}-{u64}" fits well inside 48
        const uniq = nextUniq(&uniq_buf);
        var tbuf: [896]u8 = undefined;
        const tmp = try std.fmt.bufPrint(&tbuf, "{s}/.{s}-{s}.part", .{ dir, name, uniq });
        const cwd = std.Io.Dir.cwd();

        // `writeFile` + `rename` alone is NOT crash safety, only tear
        // avoidance: it stops a reader seeing a half-written record, and
        // that is all it stops. Without an `fsync` of the temp before the
        // rename, a crash can leave the directory entry pointing at blocks
        // that were never written; without an `fsync` of the DIRECTORY
        // after it, the rename itself is not durable, so a `putBytes` that
        // RETURNED can be missing entirely after a power loss. This module
        // called itself a "durable" store and issued no `fsync` at all --
        // measured on its own example with `strace`: 5 renames, 0 fsyncs --
        // while the sibling `blobstore`, same shape, has fsynced its temp
        // since its own audit ("durability: fsync before it becomes
        // visible"). Both syncs are here now; the directory one is the half
        // `blobstore` is still missing.
        {
            const f = try cwd.createFile(self.io, tmp, .{ .truncate = true });
            errdefer {
                f.close(self.io);
                cwd.deleteFile(self.io, tmp) catch {};
            }
            var wbuf: [64 * 1024]u8 = undefined;
            var fw = f.writer(self.io, &wbuf);
            try fw.interface.writeAll(bytes);
            try fw.interface.flush();
            try f.sync(self.io);
            f.close(self.io);
        }

        var pbuf: [896]u8 = undefined;
        const path = try std.fmt.bufPrint(&pbuf, "{s}/{s}", .{ dir, name });
        cwd.rename(tmp, cwd, path, self.io) catch |e| {
            cwd.deleteFile(self.io, tmp) catch {};
            return e;
        };
        if (opts.sync_dir) try self.syncDir(dir);
    }

    /// `fsync` a directory, so a `rename` into it is durable.
    ///
    /// The directory must be re-opened with `.iterate = true`: std's default
    /// for a plain directory handle is `O_PATH`, which cannot be fsynced at
    /// all (`EBADF`). Same reasoning, and same workaround, as `kv`'s
    /// `FsStorage.vSyncDir` -- taken from there rather than re-derived.
    fn syncDir(self: Store, dir: []const u8) !void {
        if (builtin.is_test) _ = test_sync_dir_calls.fetchAdd(1, .monotonic);
        var d = try std.Io.Dir.cwd().openDir(self.io, dir, .{ .iterate = true });
        defer d.close(self.io);
        const as_file = std.Io.File{ .handle = d.handle, .flags = .{ .nonblocking = false } };
        try as_file.sync(self.io);
    }

    /// Write (overwrite) `bytes` as `<base>/<kind>/<key>`, atomically (temp +
    /// rename). Crash-safe: a partial write never becomes a live record.
    ///
    /// Does **not** touch a `.expiry` sidecar left by a prior `putWithTTL` on
    /// the same key — if a key was ever TTL'd, calling plain `putBytes` on it
    /// again leaves the *old* deadline in force for the *new* bytes. Call
    /// `delete` first, or use `putWithTTL` consistently for keys whose TTL
    /// may be re-set, to avoid inheriting a stale expiry.
    pub fn putBytes(self: Store, kind: []const u8, key: []const u8, bytes: []const u8) !void {
        if (!segmentSafe(kind) or !segmentSafe(key)) return error.InvalidName;
        var dbuf: [640]u8 = undefined;
        const dir = try self.kindDir(&dbuf, kind);
        try self.writeFileAtomicIn(dir, key, bytes);
    }

    /// A single `key`/`bytes` pair for `putManyBytes`.
    pub const Entry = struct { key: []const u8, bytes: []const u8 };

    /// Write every entry to `<base>/<kind>/<entry.key>`, same atomicity and
    /// per-file durability as `putBytes` (temp + `fsync` + rename), but with
    /// **one** directory `fsync` for the whole batch instead of one per
    /// record. Not atomic *across* entries — a crash partway through leaves
    /// whichever prefix of the batch had already been renamed durably
    /// committed, same as calling `putBytes` that many times in a row would.
    ///
    /// Exists because the per-record directory `fsync` is real, measured
    /// cost that a caller writing many records at once does not need to pay
    /// N times: audited at 98-112x plain-write throughput for durable
    /// `putBytes` on this module's own benchmark, with the directory
    /// `fsync` responsible for roughly half of that (the other half is the
    /// per-file `fsync`, still paid once per record here — batching cannot
    /// remove that half without giving up per-record durability). See the
    /// F5 disposition in the audit record for the measured fsync-count
    /// reduction this buys.
    pub fn putManyBytes(self: Store, kind: []const u8, entries: []const Entry) !void {
        if (!segmentSafe(kind)) return error.InvalidName;
        for (entries) |e| {
            if (!segmentSafe(e.key)) return error.InvalidName;
        }
        var dbuf: [640]u8 = undefined;
        const dir = try self.kindDir(&dbuf, kind);
        for (entries) |e| {
            try self.writeFileAtomicInEx(dir, e.key, e.bytes, .{ .sync_dir = false });
        }
        if (entries.len > 0) try self.syncDir(dir);
    }

    /// Read `<base>/<kind>/<key>` (allocated in `arena`), or null if absent
    /// *or expired* (a live `.expiry` sidecar whose deadline has passed,
    /// per `self.clock.now()`). Read-only: an expired record is reported as
    /// absent but not removed — see `sweep`.
    ///
    /// Skips the `.expiry` sidecar probe entirely when `self.ttl == false`
    /// — see the doc comment on `Store.ttl` for what that means for
    /// already-expired data.
    pub fn getBytes(self: Store, arena: std.mem.Allocator, kind: []const u8, key: []const u8) !?[]u8 {
        var pbuf: [768]u8 = undefined;
        const path = try self.recordPath(&pbuf, kind, key);
        if (self.ttl and try self.isExpired(kind, key)) return null;
        return std.Io.Dir.cwd().readFileAlloc(self.io, path, arena, .limited(64 * 1024 * 1024)) catch |e| switch (e) {
            error.FileNotFound => return null,
            else => return e,
        };
    }

    /// Like `getBytes`, but also returns the current `Version` (content
    /// fingerprint) — the value to pass back to `casPutBytes` to detect a
    /// lost update. Null if absent or expired, same as `getBytes`.
    pub fn getBytesVersioned(self: Store, arena: std.mem.Allocator, kind: []const u8, key: []const u8) !?struct { bytes: []u8, version: Version } {
        const bytes = try self.getBytes(arena, kind, key) orelse return null;
        return .{ .bytes = bytes, .version = versionOf(bytes) };
    }

    /// `putBytes`, returning the new record's `Version` (a cheap in-memory
    /// hash of what was just written — no extra I/O).
    pub fn putBytesVersioned(self: Store, kind: []const u8, key: []const u8, bytes: []const u8) !Version {
        try self.putBytes(kind, key, bytes);
        return versionOf(bytes);
    }

    /// Compare-and-swap write: writes `bytes` to `<base>/<kind>/<key>` only
    /// if the record's *current* version matches `expected` — `null` means
    /// "must not currently exist" (first-writer-wins create); a non-null
    /// `expected` means "must currently exist with exactly that version"
    /// (absent, or present-but-different, both fail). Returns
    /// `error.VersionMismatch` on failure — the caller should re-`get` and
    /// retry, never blindly overwrite.
    ///
    /// The whole read-check-write is serialized against other CAS/TTL
    /// writers to the same key via `lockKey` (an advisory cross-process
    /// `flock`), so the check is atomic across processes, not just within
    /// one — this is what makes CAS actually safe to rely on (see the
    /// module doc's "TTL, CAS and locking" section for the boundary: plain
    /// `getBytes`+`putBytes` readers/writers are *not* locked against this).
    /// Like `putBytes`, does not touch a prior `.expiry` TTL sidecar.
    pub fn casPutBytes(self: Store, arena: std.mem.Allocator, kind: []const u8, key: []const u8, bytes: []const u8, expected: ?Version) !Version {
        if (!segmentSafe(kind) or !segmentSafe(key)) return error.InvalidName;
        var kl = try self.lockKey(kind, key);
        defer kl.unlock();

        const current = try self.getBytes(arena, kind, key);
        const current_version: ?Version = if (current) |b| versionOf(b) else null;
        if (!std.meta.eql(current_version, expected)) return error.VersionMismatch;

        try self.putBytes(kind, key, bytes);
        return versionOf(bytes);
    }

    /// Delete `<base>/<kind>/<key>` (and any `.expiry` TTL sidecar for it —
    /// `delete` always leaves no trace, so a later `putBytes` on the same
    /// key never inherits a stale deadline). Returns false if the record did
    /// not exist (a dangling sidecar alone, with no record, still counts as
    /// "did not exist").
    ///
    /// Durable, same as `putBytes`: the directory is `fsync`ed after the
    /// `unlinkat`(s), so a `delete` that returned survives a power loss too.
    /// Before 2026-09-10 this synced nothing — `putBytes`' 2026-09-03 fsync
    /// fix covered the write path only, and a deleted record could come back
    /// after a crash (measured: 20 `delete`s -> 40 `unlinkat`, 0 `fsync`).
    pub fn delete(self: Store, kind: []const u8, key: []const u8) !bool {
        var pbuf: [768]u8 = undefined;
        const path = try self.recordPath(&pbuf, kind, key);
        const existed = blk: {
            std.Io.Dir.cwd().deleteFile(self.io, path) catch |e| switch (e) {
                error.FileNotFound => break :blk false,
                else => return e,
            };
            break :blk true;
        };
        self.clearExpiry(kind, key);
        var dbuf: [640]u8 = undefined;
        const dir = try self.kindDir(&dbuf, kind);
        try self.syncDir(dir);
        return existed;
    }

    // ── TTL / expiry (sidecar: `.<key>.expiry`) ─────────────────────────────

    /// Like `putBytes`, but also records an expiry `ttl_ns` nanoseconds from
    /// now (per `self.clock`, wall-clock by default; saturating add, so a
    /// huge `ttl_ns` clamps rather than overflowing). The expiry lives in a
    /// sidecar file `<base>/<kind>/.<key>.expiry` (decimal ns-since-epoch
    /// deadline) — the record itself is untouched raw bytes, so `getBytes`
    /// on a live (non-expired) TTL'd record returns exactly `bytes`, no
    /// header. `get`/`getBytes` treat an expired record as absent without
    /// deleting it; call `sweep` to actually reclaim expired records.
    ///
    /// The blob write and the sidecar write happen under the same `lockKey`
    /// hold, so a concurrent `sweep`/CAS on the same key never observes the
    /// pair half-updated. A plain concurrent `getBytes` reader is *not*
    /// blocked by that lock (readers stay lock-free) — it can observe the
    /// new blob a moment before or after the new deadline, which only
    /// affects expiry precision at the nanosecond scale, never torn bytes.
    ///
    /// **Crash between the two writes is fail-closed, not fail-open**: the
    /// `.expiry` sidecar is written *first*. A crash right after it leaves an
    /// orphaned sidecar with no record — `getBytes` reports absent either way
    /// (`FileNotFound`), so the caller sees exactly what it would see for a
    /// deadline that had already passed. The old order (record first, then
    /// sidecar) made the *opposite* failure reachable: a crash after the
    /// record write left a record with no deadline at all, i.e. a supposedly
    /// TTL'd record that in fact never expired — the wrong direction for a
    /// module documented as crash-safe. See the F4 disposition in the audit
    /// record for the measured before/after.
    ///
    /// Returns `error.TtlDisabled` when `self.ttl` is `false`: that store's
    /// own `getBytes` never checks the `.expiry` sidecar this call would
    /// create, so the record would be written with a deadline this store
    /// can never observe — refused instead of silently creating a sidecar
    /// that only makes the record resurrectable if the store is later
    /// reconfigured back to `ttl = true`. See `Store.ttl`.
    pub fn putWithTTL(self: Store, kind: []const u8, key: []const u8, bytes: []const u8, ttl_ns: i64) !void {
        if (!self.ttl) return error.TtlDisabled;
        if (!segmentSafe(kind) or !segmentSafe(key)) return error.InvalidName;
        var kl = try self.lockKey(kind, key);
        defer kl.unlock();
        try self.writeExpiryAt(kind, key, self.clock.now() +| ttl_ns);
        try self.putBytes(kind, key, bytes);
    }

    /// Scan `<base>/<kind>` and delete every record (blob + `.expiry`
    /// sidecar) whose deadline has passed as of `self.clock.now()`. Records
    /// with no `.expiry` sidecar are never touched. Returns the count
    /// swept.
    ///
    /// A key is `lockKey`'d only once it looks like a candidate (an
    /// unlocked `isExpired` pre-check says so) — a `sweep` over keys with no
    /// TTL, or a live one, creates no `.lock` file for them at all. Before
    /// 2026-09-10 every listed key got a lock file up front regardless, so a
    /// `sweep` that reaped nothing still left one `.lock` per key behind
    /// forever (nothing ever cleans a held-then-released lock file — see
    /// `lockKey`'s doc comment). The deadline is still re-checked *after*
    /// the lock is held for a real candidate, so a sweep can never race a
    /// concurrent `putWithTTL` renewal into deleting a just-extended live
    /// record — the pre-check only decides who gets a lock at all, it is
    /// never trusted on its own to delete.
    pub fn sweep(self: Store, arena: std.mem.Allocator, kind: []const u8) !usize {
        if (!segmentSafe(kind)) return error.InvalidName;
        const keys = try self.list(arena, kind);
        var swept: usize = 0;
        for (keys) |key| {
            if (!try self.isExpired(kind, key)) continue;
            var kl = try self.lockKey(kind, key);
            defer kl.unlock();
            if (try self.isExpired(kind, key)) {
                _ = try self.delete(kind, key);
                swept += 1;
            }
        }
        return swept;
    }

    fn writeExpiryAt(self: Store, kind: []const u8, key: []const u8, deadline_ns: i64) !void {
        var dbuf: [640]u8 = undefined;
        const dir = try self.kindDir(&dbuf, kind);
        var nbuf: [160]u8 = undefined;
        const name = try sidecarName(&nbuf, key, ".expiry");
        var vbuf: [24]u8 = undefined;
        const text = try std.fmt.bufPrint(&vbuf, "{d}", .{deadline_ns});
        try self.writeFileAtomicIn(dir, name, text);
    }

    /// The absolute expiry deadline (ns since epoch) for `kind/key`, or null
    /// if it has no `.expiry` sidecar (never TTL'd, or `delete`d — sidecar
    /// and blob are removed together). Assumes `kind`/`key` are already
    /// `segmentSafe`-validated by the caller.
    fn readExpiry(self: Store, kind: []const u8, key: []const u8) !?i64 {
        var pbuf: [900]u8 = undefined;
        const path = try self.sidecarPath(&pbuf, kind, key, ".expiry");
        // A tiny, throwaway read (a decimal i64 fits in ~20 bytes): a fixed
        // stack buffer and a direct positional read, no allocator at all —
        // CONVENTIONS.md §1.2 rules out a hidden global allocator here, and
        // this size never needed one in the first place.
        var file = std.Io.Dir.cwd().openFile(self.io, path, .{}) catch |e| switch (e) {
            error.FileNotFound => return null,
            else => return e,
        };
        defer file.close(self.io);
        var buf: [32]u8 = undefined;
        const n = try file.readPositionalAll(self.io, &buf, 0);
        return try std.fmt.parseInt(i64, std.mem.trim(u8, buf[0..n], " \t\r\n"), 10);
    }

    /// A corrupt `.expiry` sidecar (truncated, non-numeric, overflowing —
    /// anything `readExpiry`'s `parseInt` rejects) is treated as "no TTL",
    /// the same as a missing sidecar, rather than propagating the parse
    /// error up through `getBytes`. Before 2026-09-10 it did the latter: one
    /// bad byte in the *sidecar* made an otherwise-healthy record
    /// unreadable through `getBytes`/`get`/`listTyped`, an error neither
    /// `Error` nor `getBytes`' doc comment ever named — and it was
    /// inconsistent with `listTyped`'s own stated policy of tolerating
    /// corrupt input rather than refusing a request over it.
    fn isExpired(self: Store, kind: []const u8, key: []const u8) !bool {
        const deadline = (self.readExpiry(kind, key) catch |e| switch (e) {
            error.InvalidCharacter, error.Overflow => return false,
            else => return e,
        }) orelse return false;
        return self.clock.now() >= deadline;
    }

    /// Best-effort removal of a `.expiry` sidecar; a missing sidecar (the
    /// common case — most records never had a TTL) is not an error.
    fn clearExpiry(self: Store, kind: []const u8, key: []const u8) void {
        var pbuf: [900]u8 = undefined;
        const path = self.sidecarPath(&pbuf, kind, key, ".expiry") catch return;
        std.Io.Dir.cwd().deleteFile(self.io, path) catch {};
    }

    // ── cross-process advisory locking (sidecar: `.<key>.lock`) ────────────

    /// A held advisory per-key lock — see `Store.lockKey`.
    pub const KeyLock = struct {
        file: std.Io.File,
        io: std.Io,

        pub fn unlock(kl: *KeyLock) void {
            kl.file.unlock(kl.io);
            kl.file.close(kl.io);
        }
    };

    /// Acquire an advisory `flock` (exclusive, blocking) on
    /// `<base>/<kind>/.<key>.lock`, creating it if needed. Serializes the
    /// read-check-write sequence of `casPutBytes`/`putWithTTL`/`sweep` for a
    /// given key *across processes* — the atomic `rename(2)` in `putBytes`
    /// already prevents a torn read of a single write, but does nothing to
    /// stop two processes' multi-step CAS/TTL sequences from interleaving.
    ///
    /// A caller doing its own multi-step read-modify-write across processes
    /// (e.g. `getBytes` then `putBytes`) should wrap it with
    /// `lockKey`/`.unlock()` too. Plain `putBytes`/`getBytes`/`delete` are
    /// intentionally *not* locked — single-shot writers pay no locking cost,
    /// and last-write-wins on a bare `rename(2)` (never a torn file) remains
    /// the documented behavior for them.
    ///
    /// The lock file itself is never deleted (an empty file persists per key
    /// that was ever locked) — harmless bookkeeping, hidden from `list`,
    /// cheaper than trying to clean it up racily against another locker.
    pub fn lockKey(self: Store, kind: []const u8, key: []const u8) !KeyLock {
        if (!segmentSafe(kind) or !segmentSafe(key)) return error.InvalidName;
        var dbuf: [640]u8 = undefined;
        const dir = try self.kindDir(&dbuf, kind);
        try ensureDir(self.io, dir);
        var nbuf: [160]u8 = undefined;
        const name = try sidecarName(&nbuf, key, ".lock");
        var pbuf: [900]u8 = undefined;
        const path = try std.fmt.bufPrint(&pbuf, "{s}/{s}", .{ dir, name });
        const file = try std.Io.Dir.cwd().createFile(self.io, path, .{ .lock = .exclusive });
        return .{ .file = file, .io = self.io };
    }

    /// List a kind's record keys. Missing kind dir ⇒ empty. Hidden files (our
    /// `.<key>-<n>.part` ingest temps) are skipped. Allocations in `arena`.
    pub fn list(self: Store, arena: std.mem.Allocator, kind: []const u8) ![][]const u8 {
        if (!segmentSafe(kind)) return error.InvalidName;
        var keys: std.ArrayList([]const u8) = .empty;
        var dbuf: [640]u8 = undefined;
        const dir_path = try self.kindDir(&dbuf, kind);
        var dir = std.Io.Dir.cwd().openDir(self.io, dir_path, .{ .iterate = true }) catch |e| switch (e) {
            error.FileNotFound => return keys.toOwnedSlice(arena),
            else => return e,
        };
        defer dir.close(self.io);

        var it = dir.iterate();
        while (try it.next(self.io)) |entry| {
            if (entry.kind != .file) continue;
            if (entry.name.len > 0 and entry.name[0] == '.') continue; // ingest temp
            try keys.append(arena, try arena.dupe(u8, entry.name));
        }
        return keys.toOwnedSlice(arena);
    }

    // ── typed JSON convenience (same files, JSON-encoded) ───────────────────

    /// Serialize `value` as JSON and write it as `<base>/<kind>/<key>` (via
    /// `putBytes` — same atomicity guarantee, no separate layout).
    pub fn put(self: Store, gpa: std.mem.Allocator, comptime T: type, kind: []const u8, key: []const u8, value: T) !void {
        const json = try std.json.Stringify.valueAlloc(gpa, value, .{});
        defer gpa.free(json);
        try self.putBytes(kind, key, json);
    }

    /// Read `<base>/<kind>/<key>` and parse it as `T`, or null if absent.
    /// Allocations (including `T`'s, e.g. any strings/slices it holds) live in
    /// `arena`.
    pub fn get(self: Store, comptime T: type, arena: std.mem.Allocator, kind: []const u8, key: []const u8) !?T {
        const bytes = try self.getBytes(arena, kind, key) orelse return null;
        return try std.json.parseFromSliceLeaky(T, arena, bytes, .{});
    }

    /// Parse every `<base>/<kind>/*` file as `T`. A missing kind dir ⇒ empty
    /// result, not an error. Unparseable files are tolerantly skipped — but
    /// *counted* (`skipped`), never silently discarded via a bare
    /// `catch continue`. Allocations in `arena`.
    pub fn listTyped(self: Store, comptime T: type, arena: std.mem.Allocator, kind: []const u8) !struct { items: []T, skipped: usize } {
        const keys = try self.list(arena, kind);
        var items: std.ArrayList(T) = .empty;
        var skipped: usize = 0;
        for (keys) |key| {
            // A key could vanish between `list` and here (concurrent delete);
            // treat that the same as "not present in this snapshot".
            const bytes = (try self.getBytes(arena, kind, key)) orelse continue;
            const value = std.json.parseFromSliceLeaky(T, arena, bytes, .{}) catch {
                skipped += 1;
                continue;
            };
            try items.append(arena, value);
        }
        return .{ .items = try items.toOwnedSlice(arena), .skipped = skipped };
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
    return nextUniqFor(linux.getpid(), buf);
}

/// `nextUniq`'s actual formula, with the pid injectable — so a test can
/// prove two different *pids* never collide without needing to fork a real
/// second process (pid is otherwise unobservable/unfakeable from within one
/// process, since `nextUniq` itself always asks the kernel for its own).
///
/// PID + process-local counter: makes the temp name unique across processes
/// too, not only within one — see the F2 disposition in the audit record.
/// Before 2026-09-10 this was the counter alone, and every process's atomic
/// starts at 0: two processes `putBytes`ing the same key concurrently
/// produced identical `.rec-0.part` / `.rec-1.part` / ... temp paths, so the
/// loser's `rename` target was already gone (`error.FileNotFound`) instead
/// of the documented last-write-wins.
fn nextUniqFor(pid: linux.pid_t, buf: []u8) []const u8 {
    const n = ingest_counter.fetchAdd(1, .monotonic);
    return std.fmt.bufPrint(buf, "{d}-{d}", .{ pid, n }) catch unreachable; // fits in 40
}

// ── tests ──────────────────────────────────────────────────────────────────────

const t = std.testing;

/// Open a fresh store rooted in a throwaway tmpdir. Returns the store; caller
/// keeps `tmp` alive and cleans it up.
fn testStore(tmp: *std.testing.TmpDir, base_buf: []u8) !Store {
    const io = std.testing.io;
    const base = try std.fmt.bufPrint(base_buf, ".zig-cache/tmp/{s}/store", .{&tmp.sub_path});
    return Store.init(io, base);
}

test "segmentSafe accepts kind/key names, rejects traversal" {
    try t.expect(segmentSafe("devices"));
    try t.expect(segmentSafe("2026-06-28.snap"));
    try t.expect(segmentSafe("dev_SN-001"));
    try t.expect(!segmentSafe(""));
    try t.expect(!segmentSafe(".."));
    try t.expect(!segmentSafe("."));
    try t.expect(!segmentSafe(".hidden"));
    try t.expect(!segmentSafe("a/b"));
    try t.expect(!segmentSafe("a b"));
    try t.expect(!segmentSafe("../etc/passwd"));
}

test "segmentSafe rejects traversal on every public entry point" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const gpa = std.testing.allocator;

    try t.expectError(error.InvalidName, store.putBytes("..", "k", "x"));
    try t.expectError(error.InvalidName, store.putBytes("k", "../../etc/passwd", "x"));
    try t.expectError(error.InvalidName, store.getBytes(gpa, "..", "k"));
    try t.expectError(error.InvalidName, store.delete("k", "a/b"));
    try t.expectError(error.InvalidName, store.list(gpa, "."));
}

test "putBytes/getBytes/list/delete round-trip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const gpa = std.testing.allocator;

    // absent ⇒ null, not error
    try t.expect((try store.getBytes(gpa, "devices", "dev-1")) == null);

    try store.putBytes("devices", "dev-1", "hello device");
    try store.putBytes("devices", "dev-2", "hello device 2");
    try store.putBytes("hosts", "host-1", "unrelated kind");

    const got = (try store.getBytes(gpa, "devices", "dev-1")).?;
    defer gpa.free(got);
    try t.expectEqualStrings("hello device", got);

    // overwrite semantics
    try store.putBytes("devices", "dev-1", "rewritten");
    const got2 = (try store.getBytes(gpa, "devices", "dev-1")).?;
    defer gpa.free(got2);
    try t.expectEqualStrings("rewritten", got2);

    // list is scoped per kind and hides nothing but temps
    const keys = try store.list(gpa, "devices");
    defer {
        for (keys) |k| gpa.free(k);
        gpa.free(keys);
    }
    try t.expectEqual(@as(usize, 2), keys.len);

    // missing kind ⇒ empty, not error
    const none = try store.list(gpa, "nope");
    defer gpa.free(none);
    try t.expectEqual(@as(usize, 0), none.len);

    try t.expect(try store.delete("devices", "dev-1"));
    try t.expect(!try store.delete("devices", "dev-1")); // already gone
    try t.expect((try store.getBytes(gpa, "devices", "dev-1")) == null);
}

test "atomicity-by-construction: a stray .part temp is invisible to list/get" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const io = std.testing.io;
    const gpa = std.testing.allocator;

    try store.putBytes("devices", "dev-1", "live record");

    // simulate a torn/abandoned ingest: write a hidden temp directly into the
    // kind dir, exactly like an in-flight `putBytes` that never reached rename.
    var pbuf: [768]u8 = undefined;
    const kind_dir = try std.fmt.bufPrint(&pbuf, "{s}/devices", .{store.base});
    var tbuf: [800]u8 = undefined;
    const stray = try std.fmt.bufPrint(&tbuf, "{s}/.dev-2-crashed.part", .{kind_dir});
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = stray, .data = "half-written garbage" });

    // the stray temp's name is not even a valid key (leading dot) — rejected,
    // not silently treated as absent
    try t.expectError(error.InvalidName, store.getBytes(gpa, "devices", ".dev-2-crashed.part"));

    // and it is hidden from list
    const keys = try store.list(gpa, "devices");
    defer {
        for (keys) |k| gpa.free(k);
        gpa.free(keys);
    }
    try t.expectEqual(@as(usize, 1), keys.len);
    try t.expectEqualStrings("dev-1", keys[0]);

    // the live record is untouched
    const got = (try store.getBytes(gpa, "devices", "dev-1")).?;
    defer gpa.free(got);
    try t.expectEqualStrings("live record", got);
}

const TestRecord = struct {
    id: []const u8,
    count: u32,
};

test "typed JSON: put/get round-trip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try t.expect((try store.get(TestRecord, arena, "records", "r1")) == null);

    try store.put(gpa, TestRecord, "records", "r1", .{ .id = "r1", .count = 7 });
    const rec = (try store.get(TestRecord, arena, "records", "r1")).?;
    try t.expectEqualStrings("r1", rec.id);
    try t.expectEqual(@as(u32, 7), rec.count);

    // overwrite
    try store.put(gpa, TestRecord, "records", "r1", .{ .id = "r1", .count = 8 });
    const rec2 = (try store.get(TestRecord, arena, "records", "r1")).?;
    try t.expectEqual(@as(u32, 8), rec2.count);
}

test "listTyped: parses every record, tolerantly skips corrupt JSON, reports count" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try store.put(gpa, TestRecord, "records", "r1", .{ .id = "r1", .count = 1 });
    try store.put(gpa, TestRecord, "records", "r2", .{ .id = "r2", .count = 2 });
    // corrupt: not valid JSON for TestRecord at all
    try store.putBytes("records", "r3", "{not json");
    // corrupt: valid JSON but wrong shape (missing required fields)
    try store.putBytes("records", "r4", "{\"unexpected\":true}");

    const result = try store.listTyped(TestRecord, arena, "records");
    try t.expectEqual(@as(usize, 2), result.items.len);
    try t.expectEqual(@as(usize, 2), result.skipped);

    var seen1 = false;
    var seen2 = false;
    for (result.items) |r| {
        if (std.mem.eql(u8, r.id, "r1")) seen1 = true;
        if (std.mem.eql(u8, r.id, "r2")) seen2 = true;
    }
    try t.expect(seen1);
    try t.expect(seen2);

    // missing kind ⇒ empty, zero skipped, not an error
    const none = try store.listTyped(TestRecord, arena, "nope");
    try t.expectEqual(@as(usize, 0), none.items.len);
    try t.expectEqual(@as(usize, 0), none.skipped);
}

// ── TTL / expiry ─────────────────────────────────────────────────────────

/// Injectable fake clock (mirrors the sibling `idempotency` module's test
/// pattern) so TTL tests are deterministic instead of racing the wall clock.
const ManualClock = struct {
    now_ns: i64 = 0,
    fn clock(mc: *ManualClock) Clock {
        return .{ .ctx = mc, .nowFn = read };
    }
    fn read(ctx: ?*anyopaque) i64 {
        const mc: *ManualClock = @ptrCast(@alignCast(ctx.?));
        return mc.now_ns;
    }
};

test "putWithTTL: present before the deadline, absent (via get) after — but list still sees the unswept file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    var store = try testStore(&tmp, &base_buf);
    var clk = ManualClock{ .now_ns = 1_000 };
    store.clock = clk.clock();
    const gpa = std.testing.allocator;

    try store.putWithTTL("sessions", "s1", "alive", 500); // deadline = 1500

    // just before the deadline: still present
    clk.now_ns = 1_499;
    {
        const got = (try store.getBytes(gpa, "sessions", "s1")).?;
        defer gpa.free(got);
        try t.expectEqualStrings("alive", got);
    }

    // at (>=) the deadline: get/getBytes report it absent...
    clk.now_ns = 1_500;
    try t.expect((try store.getBytes(gpa, "sessions", "s1")) == null);

    // ...but expiry is read-only: the file is still physically there until a
    // sweep, which `list` (a raw directory scan) faithfully reports — this
    // is the documented get-vs-list visibility split, not a bug.
    const keys = try store.list(gpa, "sessions");
    defer {
        for (keys) |k| gpa.free(k);
        gpa.free(keys);
    }
    try t.expectEqual(@as(usize, 1), keys.len);
    try t.expectEqualStrings("s1", keys[0]);
}

test "sweep: removes only expired keys, leaves live-TTL and no-TTL keys untouched, returns the count" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    var store = try testStore(&tmp, &base_buf);
    var clk = ManualClock{ .now_ns = 1_000 };
    store.clock = clk.clock();
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try store.putWithTTL("cache", "expired-1", "old-1", 100); // deadline 1100
    try store.putWithTTL("cache", "expired-2", "old-2", 100); // deadline 1100
    try store.putWithTTL("cache", "still-live", "fresh", 10_000); // deadline 11000
    try store.putBytes("cache", "no-ttl", "forever"); // never expires

    clk.now_ns = 1_200; // past 1100, well before 11000

    const swept = try store.sweep(arena, "cache");
    try t.expectEqual(@as(usize, 2), swept);

    // expired keys are now GONE (not just get-hidden) — list confirms
    const keys = try store.list(arena, "cache");
    try t.expectEqual(@as(usize, 2), keys.len);

    try t.expect((try store.getBytes(gpa, "cache", "expired-1")) == null);
    try t.expect((try store.getBytes(gpa, "cache", "expired-2")) == null);
    {
        const live = (try store.getBytes(gpa, "cache", "still-live")).?;
        defer gpa.free(live);
        try t.expectEqualStrings("fresh", live);
    }
    {
        const perm = (try store.getBytes(gpa, "cache", "no-ttl")).?;
        defer gpa.free(perm);
        try t.expectEqualStrings("forever", perm);
    }

    // a second sweep is a no-op — nothing left to reap
    try t.expectEqual(@as(usize, 0), try store.sweep(arena, "cache"));
}

test "ttl=false: getBytes never opens the .expiry sidecar (observable via a corrupt sidecar the default path would choke on)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    var store = try testStore(&tmp, &base_buf);
    store.ttl = false;
    const io = std.testing.io;
    const gpa = std.testing.allocator;

    try store.putBytes("sessions", "s1", "alive");

    // Write a sidecar directly (bypassing putWithTTL) as a DIRECTORY, not a
    // file — not a merely non-numeric string, because F6 (2026-09-10) made a
    // corrupt-but-parseable-shape sidecar (non-numeric text, overflow, …)
    // tolerated as "no TTL" rather than erroring (see the F6 test below), so
    // that shape no longer distinguishes "opened and tolerated" from "never
    // opened". Opening/reading a directory where a regular file is expected
    // still fails a different way, which F6's tolerance does not swallow.
    var pbuf: [900]u8 = undefined;
    const sidecar_path = try store.sidecarPath(&pbuf, "sessions", "s1", ".expiry");
    try std.Io.Dir.cwd().createDir(io, sidecar_path, .default_dir);

    const got = (try store.getBytes(gpa, "sessions", "s1")).?;
    defer gpa.free(got);
    try t.expectEqualStrings("alive", got);

    // Control: the identical store with ttl=true (the default) DOES open the
    // sidecar and fails on it — proving the opt-out above genuinely skipped
    // the probe rather than happening to tolerate it. The failure must not
    // be one of the two shapes F6 now tolerates (InvalidCharacter/Overflow),
    // or this control would no longer be proving what it claims to.
    var control = store;
    control.ttl = true;
    if (control.getBytes(gpa, "sessions", "s1")) |_| {
        return error.TestUnexpectedResult; // ttl=true must fail opening a directory as the sidecar
    } else |err| {
        try t.expect(err != error.InvalidCharacter and err != error.Overflow);
    }
}

test "putWithTTL refuses with error.TtlDisabled on a ttl=false store — no sidecar the store would then never check" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    var store = try testStore(&tmp, &base_buf);
    store.ttl = false;
    const gpa = std.testing.allocator;

    try t.expectError(error.TtlDisabled, store.putWithTTL("sessions", "s3", "nope", 500));

    // No record and no sidecar were created by the refused call.
    try t.expect((try store.getBytes(gpa, "sessions", "s3")) == null);
    var pbuf: [900]u8 = undefined;
    const sidecar_path = try store.sidecarPath(&pbuf, "sessions", "s3", ".expiry");
    try t.expectError(error.FileNotFound, std.Io.Dir.cwd().openFile(std.testing.io, sidecar_path, .{}));
}

test "ttl=false hazard, still reachable: a record TTL'd BEFORE the store opted out keeps being served past its deadline" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    var store = try testStore(&tmp, &base_buf);
    var clk = ManualClock{ .now_ns = 1_000 };
    store.clock = clk.clock();
    const gpa = std.testing.allocator;

    // ttl is still true here — this is the only way a `.expiry` sidecar can
    // come to exist at all now that putWithTTL refuses outright on a
    // ttl=false store (see the test above). Models a store TTL'd under one
    // configuration and later reconfigured, or a sidecar left by a
    // differently configured writer sharing the same base.
    try store.putWithTTL("sessions", "s2", "still-around", 500); // deadline 1500
    clk.now_ns = 2_000; // well past the deadline, never swept

    // Default (ttl=true): correctly reports it as absent.
    try t.expect((try store.getBytes(gpa, "sessions", "s2")) == null);

    // Opted out AFTER the sidecar already existed: the exact same on-disk
    // state, but getBytes resurrects the expired record instead of
    // reporting it absent — the one hazard `ttl = false` still carries,
    // since it cannot retroactively erase a pre-existing sidecar.
    store.ttl = false;
    const got = (try store.getBytes(gpa, "sessions", "s2")).?;
    defer gpa.free(got);
    try t.expectEqualStrings("still-around", got);

    // sweep is unaffected by the flag — it still reaps the expired record.
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    try t.expectEqual(@as(usize, 1), try store.sweep(arena_state.allocator(), "sessions"));
}

// ── ETag / version CAS ───────────────────────────────────────────────────

test "casPutBytes: create requires expected=null, update requires the current version, else VersionMismatch" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // "create" with a nonsense expected version on an absent key: mismatch
    try t.expectError(error.VersionMismatch, store.casPutBytes(arena, "accounts", "a1", "v1", 0xdead_beef));

    // "create" (expected=null ⇒ must not exist) succeeds
    const v1 = try store.casPutBytes(arena, "accounts", "a1", "v1", null);

    // creating again with expected=null now fails: it exists now
    try t.expectError(error.VersionMismatch, store.casPutBytes(arena, "accounts", "a1", "v1-again", null));

    // update with the correct current version succeeds, version changes
    const v2 = try store.casPutBytes(arena, "accounts", "a1", "v2", v1);
    try t.expect(v1 != v2);

    // update with the now-stale v1 fails
    try t.expectError(error.VersionMismatch, store.casPutBytes(arena, "accounts", "a1", "v3-stale", v1));

    // final state is v2, the rejected v3-stale write never landed
    const got = (try store.getBytes(gpa, "accounts", "a1")).?;
    defer gpa.free(got);
    try t.expectEqualStrings("v2", got);

    // getBytesVersioned reports a version matching what a fresh put returns
    const roundtrip = (try store.getBytesVersioned(arena, "accounts", "a1")).?;
    try t.expectEqual(v2, roundtrip.version);
    try t.expectEqual(versionOf("v2"), roundtrip.version);
}

test "positive control: plain putBytes silently loses a concurrent update; casPutBytes catches the same race" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // ── without CAS: two "writers" read the same base state, then both
    // write — the second plain putBytes silently clobbers the first with no
    // error, which is exactly the lost-update bug CAS exists to prevent.
    try store.putBytes("counters", "c1", "base");
    const r1 = (try store.getBytesVersioned(arena, "counters", "c1")).?; // writer 1's read
    const r2 = (try store.getBytesVersioned(arena, "counters", "c1")).?; // writer 2's read (same base)
    try t.expectEqual(r1.version, r2.version);

    try store.putBytes("counters", "c1", "writer-1-update"); // writer 1 commits
    try store.putBytes("counters", "c1", "writer-2-update"); // writer 2 clobbers, unaware

    const lost = (try store.getBytes(gpa, "counters", "c1")).?;
    defer gpa.free(lost);
    try t.expectEqualStrings("writer-2-update", lost); // writer-1's update: gone, silently, no error

    // ── same scenario with casPutBytes: writer 2's write is keyed off its
    // stale read and is rejected instead of clobbering writer 1's commit.
    try store.putBytes("counters", "c2", "base");
    const s1 = (try store.getBytesVersioned(arena, "counters", "c2")).?;
    const s2 = (try store.getBytesVersioned(arena, "counters", "c2")).?;

    _ = try store.casPutBytes(arena, "counters", "c2", "writer-1-update", s1.version); // writer 1 commits
    try t.expectError( // writer 2's stale-version write is rejected, not silently applied
        error.VersionMismatch,
        store.casPutBytes(arena, "counters", "c2", "writer-2-update", s2.version),
    );

    const safe = (try store.getBytes(gpa, "counters", "c2")).?;
    defer gpa.free(safe);
    try t.expectEqualStrings("writer-1-update", safe); // writer-1's commit survives, uncorrupted
}

// ── cross-process advisory locking ──────────────────────────────────────

test "lockKey: exclusive flock actually contends between independent file descriptors on the same path" {
    // A second, independent `openFile` of the exact same lock path stands in
    // for "a second process opening it" — flock contention is scoped to the
    // open file description, not to this process, so this genuinely
    // exercises the same kernel behavior a second process would hit.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const io = std.testing.io;

    var kl = try store.lockKey("locks", "resource-1");

    var pbuf: [900]u8 = undefined;
    const lock_path = try store.sidecarPath(&pbuf, "locks", "resource-1", ".lock");
    const rival = try std.Io.Dir.cwd().openFile(io, lock_path, .{});
    defer rival.close(io);

    // held by `kl` ⇒ the rival's non-blocking attempt must fail
    try t.expect(!(try rival.tryLock(io, .exclusive)));

    kl.unlock();

    // released ⇒ the rival can now get it
    try t.expect(try rival.tryLock(io, .exclusive));
    rival.unlock(io);
}

fn testSleepNs(ns: u64) void {
    var req: std.posix.timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    var rem: std.posix.timespec = undefined;
    while (std.posix.errno(std.posix.system.nanosleep(&req, &rem)) == .INTR) req = rem;
}

/// Monotonic ns, for timing how long a test blocked (never for TTL — that
/// uses `Store.clock`, wall-clock, injected via `ManualClock`).
fn testMonoNs() i64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return 0;
    return @as(i64, @intCast(ts.sec)) * std.time.ns_per_s + @as(i64, @intCast(ts.nsec));
}

/// The handshake between the lock holder and the waiter, so the test asserts
/// a *happens-before* relation rather than a stopwatch reading.
///
/// The old version of this test slept 20 ms to "give the thread a head start"
/// and then asserted `elapsed >= hold_ns / 2`. Both halves are wall-clock bets:
/// on a loaded machine the holder may not have the lock yet when the waiter
/// starts (so the waiter sails through and the assertion fires on a *correct*
/// implementation), and a descheduled waiter can inflate `elapsed` without
/// having blocked on anything. It flaked exactly that way during a full-suite
/// run with three other builds going.
const LockHandshake = struct {
    /// The holder has the flock. Published before the waiter is allowed to
    /// start, so "the lock was held when casPutBytes was called" is a fact.
    held: std.atomic.Value(bool) = .init(false),
    /// The waiter is about to call `casPutBytes`. The holder waits for this
    /// before starting its hold window, so the window always covers the call.
    waiter_started: std.atomic.Value(bool) = .init(false),
    /// The waiter's `casPutBytes` has returned.
    waiter_done: std.atomic.Value(bool) = .init(false),
    /// Sampled by the holder immediately before it unlocks: true means the
    /// waiter completed *while the lock was still held*, i.e. it never blocked.
    waiter_done_before_release: bool = false,
    /// Published by the holder immediately before it unlocks.
    released: std.atomic.Value(bool) = .init(false),
};

fn spinUntil(flag: *std.atomic.Value(bool)) void {
    while (!flag.load(.acquire)) testSleepNs(200 * std.time.ns_per_us);
}

/// Test-thread body: take the per-key lock, tell the waiter it may start, hold
/// for `hold_ns` *after* the waiter has begun, then release.
fn holdLockThenRelease(store: Store, hold_ns: u64, hs: *LockHandshake) void {
    var kl = store.lockKey("accounts", "a-locked") catch return;
    hs.held.store(true, .release);
    spinUntil(&hs.waiter_started);
    testSleepNs(hold_ns);
    // Read the waiter's completion flag while the lock is still ours: if it is
    // already set, `casPutBytes` did not block on this lock at all.
    hs.waiter_done_before_release = hs.waiter_done.load(.acquire);
    hs.released.store(true, .release);
    kl.unlock();
}

test "casPutBytes actually blocks on a lock held by another thread (real cross-holder serialization, not just tryLock contention)" {
    // casPutBytes acquires `lockKey` internally (blocking flock). The intent
    // is to prove a *real cross-holder* block — a second process-level flock
    // holder, not just a `tryLock` that returns false — so a refactor that
    // dropped the `lockKey` call would be caught.
    //
    // Proved by ordering, not by a stopwatch: the holder publishes "I have the
    // lock" before the waiter is allowed to call, and samples "has the waiter
    // finished?" while it still holds it. See `LockHandshake`.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try store.putBytes("accounts", "a-locked", "base");
    const base_version = versionOf("base");

    const hold_ns: u64 = 150 * std.time.ns_per_ms;
    var hs = LockHandshake{};
    const th = try std.Thread.spawn(.{}, holdLockThenRelease, .{ store, hold_ns, &hs });

    // Not a sleep: wait until the holder has *actually* acquired the flock.
    spinUntil(&hs.held);

    hs.waiter_started.store(true, .release);
    const start_ns = testMonoNs();
    _ = try store.casPutBytes(arena, "accounts", "a-locked", "cas-write", base_version);
    const elapsed_ns: u64 = @intCast(testMonoNs() - start_ns);
    hs.waiter_done.store(true, .release);
    th.join();

    // Two independent order checks, no timing threshold anywhere:
    //
    //  1. The waiter observed the release. `released` is stored before
    //     `unlock()`, and the waiter can only take the lock after that unlock,
    //     so a `casPutBytes` that returns without the flag set never waited.
    //  2. The holder, still holding the lock, did not see the waiter finish.
    //     A `casPutBytes` that skipped `lockKey` would have completed in
    //     microseconds, well inside the hold window.
    //
    // Neither depends on how fast the machine is: the hold window is opened
    // *after* `waiter_started` and closed only by the holder, so load can only
    // make the test wait longer, never make it fail.
    try t.expect(hs.released.load(.acquire));
    try t.expect(!hs.waiter_done_before_release);
    // Kept as diagnostics only — never asserted on.
    if (elapsed_ns < hold_ns / 4) {
        std.debug.print(
            "note: casPutBytes returned after {d} ns (hold window {d} ns)\n",
            .{ elapsed_ns, hold_ns },
        );
    }

    const got = (try store.getBytes(gpa, "accounts", "a-locked")).?;
    defer gpa.free(got);
    try t.expectEqualStrings("cas-write", got);
}

// ── A1 fix campaign, 2026-09-10 ─────────────────────────────────────────

test "F1: delete durably syncs the directory, not just unlinkat — putBytes still syncs its own dir too" {
    // `test_sync_dir_calls` is a single process-wide counter shared by every
    // test in this binary (zig test runs them all in one process) — snapshot
    // it as a baseline and compare deltas, never assume it starts at 0.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);

    const before_put = test_sync_dir_calls.load(.monotonic);
    try store.putBytes("devices", "dev-1", "hello");
    // one record write -> one directory fsync (the file fsync inside
    // writeFileAtomicIn is not counted here, only syncDir calls)
    try t.expectEqual(@as(u32, 1), test_sync_dir_calls.load(.monotonic) - before_put);

    const before_delete = test_sync_dir_calls.load(.monotonic);
    try t.expect(try store.delete("devices", "dev-1"));
    // RED before the 2026-09-10 fix: this delta was 0 (delete never called
    // syncDir at all — measured externally via strace as 40 unlinkat, 0
    // fsync across 20 deletes). GREEN now: exactly 1, same shape as putBytes.
    try t.expectEqual(@as(u32, 1), test_sync_dir_calls.load(.monotonic) - before_delete);
}

test "F2: two different pids (simulating two real processes, whose ingest_counter both start at 0) never produce the same temp name" {
    // Two independent processes each have their own zero-initialized
    // `ingest_counter` — that IS the mechanism `nextUniqFor` closes over by
    // taking the pid as a parameter (real `nextUniq` always passes its own
    // real pid; a test cannot fake that from inside one process, so it goes
    // through `nextUniqFor` directly instead to supply two DIFFERENT pids,
    // reproducing exactly what two real processes' first N calls look like).
    var collisions: u32 = 0;
    const trials = 2000;
    var i: u32 = 0;
    while (i < trials) : (i += 1) {
        ingest_counter.store(0, .monotonic); // process A's counter, fresh
        var buf_a: [48]u8 = undefined;
        const a = nextUniqFor(1111, &buf_a);
        ingest_counter.store(0, .monotonic); // process B's counter, fresh
        var buf_b: [48]u8 = undefined;
        const b = nextUniqFor(2222, &buf_b);
        if (std.mem.eql(u8, a, b)) collisions += 1;
    }
    // GREEN: 0/2000 — the pid prefix differs ("1111-0" vs "2222-0", etc.)
    // even though both processes' counters produce the identical sequence
    // 0, 1, 2, ... The next test pins the RED number this replaced.
    try t.expectEqual(@as(u32, 0), collisions);
}

test "F2 mutation control: the pre-fix shape (counter only, no pid) DOES collide 2000/2000 under the same reset simulation" {
    // Same reproduction as above, but calling the OLD formula directly
    // (counter alone) to pin the exact RED number the fix closed, without
    // needing to check out the pre-fix commit.
    const oldNextUniq = struct {
        fn f(buf: []u8, counter: *std.atomic.Value(u64)) []const u8 {
            const n = counter.fetchAdd(1, .monotonic);
            return std.fmt.bufPrint(buf, "{d}", .{n}) catch unreachable;
        }
    }.f;
    var counter: std.atomic.Value(u64) = .init(0);
    var collisions: u32 = 0;
    const trials = 2000;
    var i: u32 = 0;
    while (i < trials) : (i += 1) {
        counter.store(0, .monotonic);
        var buf_a: [24]u8 = undefined;
        const a = oldNextUniq(&buf_a, &counter);
        counter.store(0, .monotonic);
        var buf_b: [24]u8 = undefined;
        const b = oldNextUniq(&buf_b, &counter);
        if (std.mem.eql(u8, a, b)) collisions += 1;
    }
    try t.expectEqual(@as(u32, 2000), collisions);
}

test "F3: sweep does not lockKey (or leave a .lock file behind for) a key that was never a candidate" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // 20 records, none ever TTL'd.
    var buf: [16]u8 = undefined;
    var idx: u32 = 0;
    while (idx < 20) : (idx += 1) {
        const key = try std.fmt.bufPrint(&buf, "k{d}", .{idx});
        try store.putBytes("nottl", key, "x");
    }

    const swept = try store.sweep(arena, "nottl");
    try t.expectEqual(@as(usize, 0), swept);

    // Raw directory scan (unlike `list`, does not hide hidden files) — this
    // is the audit's own measurement shape: 500 records / 0 TTL / one sweep
    // that reaped 0 still left 500 `.lock` files (1000 total) before the
    // fix. Here: 20 records in, 20 files out — GREEN means no `.lock` grew.
    var dbuf: [640]u8 = undefined;
    const dir_path = try std.fmt.bufPrint(&dbuf, "{s}/nottl", .{store.base});
    var dir = try std.Io.Dir.cwd().openDir(store.io, dir_path, .{ .iterate = true });
    defer dir.close(store.io);
    var total: usize = 0;
    var it = dir.iterate();
    while (try it.next(store.io)) |entry| {
        if (entry.kind != .file) continue;
        total += 1;
    }
    // RED before the fix: 40 (20 records + 20 `.lock` files created by the
    // unconditional pre-delete lockKey). GREEN now: 20.
    try t.expectEqual(@as(usize, 20), total);
}

test "F4: crash between putWithTTL's two writes is fail-closed (no record), not fail-open (a permanent one)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    var store = try testStore(&tmp, &base_buf);
    var clk = ManualClock{ .now_ns = 1_000 };
    store.clock = clk.clock();
    const gpa = std.testing.allocator;

    // Simulate a crash right after the FIRST of putWithTTL's two internal
    // writes by calling that first step directly and stopping — this is
    // exactly the state a real crash would leave on disk, without needing
    // to actually kill the process mid-call.
    //
    // New (fixed) order: sidecar first. A crash after only the sidecar
    // write leaves no record at all.
    try store.writeExpiryAt("sessions", "crash-key", clk.now_ns +| 500);
    try t.expect((try store.getBytes(gpa, "sessions", "crash-key")) == null);

    // Old (pre-fix) order: record first. A crash after only the record
    // write left a record with NO deadline ever written — i.e. permanent,
    // the exact fail-open bug F4 reported. Reproduced directly (not by
    // reverting putWithTTL) to pin the contrast the reorder fixed.
    try store.putBytes("sessions", "old-order-crash-key", "permanent-by-accident");
    const resurrected = (try store.getBytes(gpa, "sessions", "old-order-crash-key")).?;
    defer gpa.free(resurrected);
    try t.expectEqualStrings("permanent-by-accident", resurrected);
    // No `.expiry` sidecar exists for it — under the OLD order this key,
    // meant to be short-lived, in fact never expires at all.
    var pbuf: [900]u8 = undefined;
    const sidecar_path = try store.sidecarPath(&pbuf, "sessions", "old-order-crash-key", ".expiry");
    try t.expectError(error.FileNotFound, std.Io.Dir.cwd().openFile(std.testing.io, sidecar_path, .{}));

    // Positive control: an uninterrupted putWithTTL still round-trips.
    try store.putWithTTL("sessions", "clean", "alive", 500);
    const clean = (try store.getBytes(gpa, "sessions", "clean")).?;
    defer gpa.free(clean);
    try t.expectEqualStrings("alive", clean);
}

test "F5: putManyBytes syncs the directory once per batch, not once per record — records still all readable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const gpa = std.testing.allocator;

    const n = 20;
    var keybuf: [n][8]u8 = undefined;
    var entries: [n]Store.Entry = undefined;
    for (0..n) |i| {
        entries[i] = .{
            .key = std.fmt.bufPrint(&keybuf[i], "k{d}", .{i}) catch unreachable,
            .bytes = "batched",
        };
    }

    test_sync_dir_calls.store(0, .monotonic);
    for (entries) |e| try store.putBytes("individually", e.key, e.bytes);
    const per_record_syncs = test_sync_dir_calls.load(.monotonic);
    try t.expectEqual(@as(u32, n), per_record_syncs);

    test_sync_dir_calls.store(0, .monotonic);
    try store.putManyBytes("batched", &entries);
    const batch_syncs = test_sync_dir_calls.load(.monotonic);
    // RED-equivalent (what calling putBytes n times costs): n directory
    // fsyncs. GREEN: putManyBytes over the same n records costs exactly 1 —
    // per the audit's own breakdown the directory fsync is roughly half of
    // durable-write cost, so this removes very close to (n-1)/n of that
    // half for a batch of n.
    try t.expectEqual(@as(u32, 1), batch_syncs);

    for (entries) |e| {
        const got = (try store.getBytes(gpa, "batched", e.key)).?;
        defer gpa.free(got);
        try t.expectEqualStrings("batched", got);
    }
}

test "F6: a corrupt .expiry sidecar is treated as no-TTL, not propagated as a read error on an otherwise-healthy record" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var base_buf: [256]u8 = undefined;
    const store = try testStore(&tmp, &base_buf);
    const io = std.testing.io;
    const gpa = std.testing.allocator;

    const shapes = [_][]const u8{
        "not-a-number",
        "",
        "99999999999999999999999999",
        "12 34",
        "\x00\x00",
    };
    var buf: [16]u8 = undefined;
    for (shapes, 0..) |shape, i| {
        const key = try std.fmt.bufPrint(&buf, "k{d}", .{i});
        try store.putBytes("sessions", key, "still readable");
        var pbuf: [900]u8 = undefined;
        const sidecar_path = try store.sidecarPath(&pbuf, "sessions", key, ".expiry");
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = sidecar_path, .data = shape });

        // RED before the fix: each of these propagated error.InvalidCharacter
        // or error.Overflow out of getBytes. GREEN now: the record reads back
        // exactly as if it had never been TTL'd.
        const got = (try store.getBytes(gpa, "sessions", key)).?;
        defer gpa.free(got);
        try t.expectEqualStrings("still readable", got);
    }

    // Positive control: a well-formed but already-past sidecar still expires
    // the record — the tolerant path above did not disable TTL altogether.
    var store2 = store;
    var clk = ManualClock{ .now_ns = 1_000 };
    store2.clock = clk.clock();
    try store2.putWithTTL("sessions", "well-formed", "bye", 100); // deadline 1100
    clk.now_ns = 2_000;
    try t.expect((try store2.getBytes(gpa, "sessions", "well-formed")) == null);
}
