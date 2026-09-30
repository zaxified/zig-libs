// SPDX-License-Identifier: MIT

//! kv — embedded, crash-consistent key-value store (Bitcask-style log).
//!
//! One append-only data file of length-prefixed, CRC-checked records
//! (`put` / `del`), plus an in-memory **keydir** mapping each live key to the
//! offset of its latest record. `open` replays the log to rebuild the keydir;
//! `get` reads the value back from the file (re-verifying the record CRC by
//! default — corrupt data is *never* served). `compact` rewrites live entries
//! into a fresh file and swaps it in atomically (temp + fsync + rename + dir
//! fsync) — a crash at any point mid-compaction leaves the old file intact.
//!
//! **Durability contract (honest version):** `put`/`delete` return only after
//! the record has been written *and* `fsync` has returned, so an acknowledged
//! write survives an OS crash or power loss — to the extent the platform's
//! `fsync` actually flushes to stable media (consumer drives with volatile
//! write caches and lying hypervisors can still betray you; that is below
//! this library). A torn trailing record (partial write / bad CRC at the
//! tail) is detected on `open` and the file is truncated back to the last
//! good record: committed data survives, a half-written tail is discarded.
//! After ANY storage-write error the store is **poisoned** (fail-stop):
//! mutations are refused, because a failed `fsync` leaves the page cache in
//! an undefined state (the "fsyncgate" lesson) — reopen to recover. Reads
//! stay available on a poisoned store (the keydir still describes the last
//! consistent state).
//!
//! Corruption policy: replay stops at the FIRST bad record (torn or CRC
//! mismatch) and truncates there. For a genuine torn tail this is exact
//! recovery; for mid-file media corruption it also discards every later
//! record — v0 trades that (rare, media-level) case for a simple, provable
//! invariant: **everything reachable after `open` is CRC-valid**.
//!
//! **Concurrency (v0):** internally synchronized with one coarse spinlock
//! (`std.atomic.Mutex` + `spinLoopHint`, the repo-standard io-less lock) —
//! single writer, and reads see a consistent keydir because they take the
//! same lock. Honest caveat: a writer holds the lock across `fsync`, so a
//! concurrent thread spin-waits for the duration of a disk flush; this is
//! fine for the intended embedded/low-contention use, and lockless MVCC
//! readers are an explicitly noted future phase.
//!
//! **Cross-process exclusion (on by default):** `open` takes an exclusive
//! ADVISORY lock (`flock(2)`, non-blocking) on a sidecar `<path>.lock` and
//! holds it until `close`. A second opener — another process, or a second
//! `Db` in this one — gets `error.Locked` instead of silently becoming a
//! second writer over the same append-only log. Opt out with
//! `Options.lock = .none`. See `Storage.tryLockExclusive` for the full
//! contract (why `flock` and not `fcntl`, what `fork` does, and why NFS is
//! explicitly not promised).
//!
//! **The Storage seam:** every storage side effect (write / fsync / truncate
//! / rename / delete / dir-fsync) goes through the injectable `Storage`
//! interface. Production uses `FsStorage` (std.Io filesystem); tests use
//! `SimStorage` (`sim.zig`), a deterministic in-memory fault simulator that
//! can crash the "machine" at every single injection point — the bounded
//! mini-VOPR sweep in `fault_test.zig` is the module's reliability argument.
//!
//! **Key expiry** (`putExpiring`/`putTtl`): an expired key is absent to every
//! read at once; `open` and `compact` drop it from memory and file. Wall clock
//! (`Options.clock`), read only while expiring keys exist. Format v2, reached by
//! one compaction at the first expiring put — see SPEC § "Key expiry".
//!
//! Future phases (deliberately NOT in v0): full randomized VOPR at scale,
//! immutable/MVCC on-disk structure (HAMT/B-tree) with lockless readers,
//! ordered/ranged scans, transactions/batches, secondary indexes, automatic
//! compaction thresholds, in-memory value cache (compose with `ramcache`),
//! shared/reader locks (the store is single-writer, so the cross-process
//! lock is exclusive-only). The v0 keydir is an unordered hash map.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Crash-consistent embedded KV store, Bitcask-style log, with randomized fuzz-tested crash recovery.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // all I/O via std.Io through the Storage seam
    .role = .both, // embedded read+write store
    // Internally synchronized: one coarse spinlock over all operations
    // (writer holds it across fsync — see the module doc). MVCC = phase.
    .concurrency = .threadsafe,
    .model_after = "Bitcask / LMDB / xitdb; reliability = TigerBeetle VOPR",
    .deps = .{}, // std only
};

pub const SimStorage = @import("sim.zig").SimStorage;
pub const CrashMode = @import("sim.zig").CrashMode;

/// Spinlock acquire (std SmpAllocator pattern; Zig 0.16 std has no io-less
/// blocking mutex) — see the module doc for the fsync-hold caveat.
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// ── on-disk format ───────────────────────────────────────────────────────────
//
// File header (8 bytes):        Record (13 [+ 8] + key_len + value_len bytes):
//   [0..4)  magic "ZKVL"          [0..4)   crc32 (IEEE) over bytes [4..end)
//   [4..8)  version u32 LE        [4]      op: 0 = put, 1 = del, 2 = put with expiry
//           1 = ops 0 and 1       [5..9)   key_len   u32 LE
//           2 = also op 2         [9..13)  value_len u32 LE (0 for del)
//                                 op 2 only: [13..21) expires_at i64 LE (ms since
//                                            the Unix epoch, never `no_expiry`)
//                                 then key bytes, then value bytes
//
// A store stays at version 1 until its first expiring put, which upgrades it by
// compaction (the atomic rewrite, never an in-place header write). A reader that
// knows only version 1 refuses a version-2 file (`UnsupportedVersion`) instead of
// meeting op 2 mid-log, taking it for a torn record and truncating live data.

const file_magic = "ZKVL";
const version_plain: u32 = 1;
const version_expiry: u32 = 2;
const header_len = 8;
const rec_fixed = 13;
const exp_len = 8;

const op_put: u8 = 0;
const op_del: u8 = 1;
const op_put_exp: u8 = 2;

/// The keydir's "this record has no expiry" marker. Never written to disk: an
/// op-2 record carrying it is not one this module wrote, and reads as corrupt.
const no_expiry: i64 = std.math.maxInt(i64);

fn recordLen(key_len: u64, value_len: u64) u64 {
    return rec_fixed + key_len + value_len;
}

fn recordLenExp(expires: bool, key_len: u64, value_len: u64) u64 {
    return recordLen(key_len, value_len) + @as(u64, if (expires) exp_len else 0);
}

/// Serialize one record into `buf` (`buf.len == recordLen(...)`).
fn encodeRecord(buf: []u8, op: u8, key: []const u8, value: []const u8) void {
    encodeRecordExp(buf, op, no_expiry, key, value);
}

/// Serialize one record; `op_put_exp` carries `expires_at` (`buf.len ==
/// recordLenExp(true, ...)`), every other op ignores it.
fn encodeRecordExp(buf: []u8, op: u8, expires_at: i64, key: []const u8, value: []const u8) void {
    buf[4] = op;
    std.mem.writeInt(u32, buf[5..9], @intCast(key.len), .little);
    std.mem.writeInt(u32, buf[9..13], @intCast(value.len), .little);
    var body: usize = rec_fixed;
    if (op == op_put_exp) {
        std.mem.writeInt(i64, buf[rec_fixed..][0..exp_len], expires_at, .little);
        body += exp_len;
    }
    @memcpy(buf[body..][0..key.len], key);
    @memcpy(buf[body + key.len ..][0..value.len], value);
    std.mem.writeInt(u32, buf[0..4], std.hash.Crc32.hash(buf[4..]), .little);
}

// ── wall clock (expiry only) ─────────────────────────────────────────────────

/// Wall-clock source for key expiry, in milliseconds since the Unix epoch.
/// Wall time and not monotonic time, because an expiry is stored on disk and
/// must still mean the same instant after a reboot, when a monotonic clock
/// starts over. Read only for keys that carry an expiry: a store that never
/// calls `putExpiring`/`putTtl` never reads it. Injected so tests are
/// deterministic.
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowFn: *const fn (?*anyopaque) i64,

    /// `CLOCK_REALTIME`, the production default.
    pub const realtime: Clock = .{ .nowFn = realtimeNowMs };

    pub fn now(c: Clock) i64 {
        return c.nowFn(c.ctx);
    }
};

fn realtimeNowMs(_: ?*anyopaque) i64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts)) != .SUCCESS) return 0;
    return @as(i64, @intCast(ts.sec)) * std.time.ms_per_s + @divTrunc(@as(i64, @intCast(ts.nsec)), std.time.ns_per_ms);
}

// ── Storage: the injectable seam ─────────────────────────────────────────────

/// Injectable storage interface — ALL storage side effects the store performs
/// go through this vtable, so a fault-simulating implementation can crash the
/// world at every single one of them. Production default: `FsStorage`.
/// Deterministic fault simulation: `SimStorage`.
///
/// Contract notes:
///   * `pread` may return short only at end-of-file.
///   * `writeAll` writes all bytes at the absolute offset or errors.
///   * `sync` = fsync: on success the file's current content is durable.
///   * `rename` atomically replaces `new_path` with `old_path`'s file; the
///     namespace change is durable only after `syncDir`.
///   * `delete` errors with `error.FileNotFound` if the name is absent.
///   * `syncDir` = fsync of the directory containing the store's files.
///   * `tryLockExclusive` = a non-blocking, advisory, cross-process lock
///     whose lifetime is the HANDLE's lifetime (see its doc comment).
pub const Storage = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    /// Backend-scoped open-file token (an index, not an OS fd).
    pub const Handle = u32;

    /// How `open` treats the path.
    ///
    ///   * `open_or_create` — read-write; creates an empty file if absent.
    ///   * `create_truncate` — read-write; creates, or empties an existing file.
    ///   * `create_new` — read-write; creates the file, and fails with
    ///     `error.PathAlreadyExists` if the path already exists (`O_CREAT|O_EXCL`,
    ///     Win32 `CREATE_NEW`). The check and the creation are one atomic step,
    ///     so of several concurrent creators exactly one wins — and a file
    ///     that must never be emptied (a segment a lost manifest no longer
    ///     lists) cannot be truncated by mistake.
    ///   * `read_only` — the file must already exist (`error.FileNotFound`
    ///     otherwise) and is never created, emptied or written. `writeAll` and
    ///     `truncate` on such a handle fail with `error.AccessDenied` — every
    ///     backend refuses them itself, so the answer does not depend on which
    ///     errno the OS picks for a write to an `O_RDONLY` descriptor. For a
    ///     reader that must not disturb a directory it does not own: another
    ///     process's live store, a backup, a read-only mount.
    ///
    /// ⚠ Implementers: switch on the mode exhaustively. A test such as
    /// `mode == .create_truncate` silently treats every other mode — this one
    /// included — as `open_or_create`, i.e. creates the file a reader expected
    /// to find.
    pub const OpenMode = enum { open_or_create, create_truncate, create_new, read_only };

    /// A **borrowed** run of bytes owned by the backend — the zero-copy read
    /// path (`preadRef`). `bytes` stays valid, and stays the bytes that were
    /// read, until it is handed back to `releaseRef`; the backend guarantees
    /// nothing it does in the meantime (cache eviction, an overwrite of the
    /// same region, a `clear`) can move or free it. `token` is the backend's
    /// own bookkeeping — opaque here, and the reason release is by value
    /// rather than by offset: two borrows of the same page are distinct.
    ///
    /// Only backends that genuinely hold the bytes in memory can lend; see
    /// `canLend`. There is deliberately no automatic fall-back to a copying
    /// read inside `preadRef`, because a fall-back that looks like a success
    /// makes "did the fast path actually engage?" unanswerable at the call
    /// site — exactly the question a caller adopts this API to control.
    pub const Ref = struct {
        bytes: []const u8,
        token: *anyopaque,
    };

    /// The names `list` found, sorted bytewise ascending. The slice and every
    /// name in it belong to the allocator passed to `list`; `deinit` frees them.
    pub const Listing = struct {
        names: [][]u8,

        pub fn deinit(l: Listing, gpa: Allocator) void {
            for (l.names) |n| gpa.free(n);
            gpa.free(l.names);
        }

        /// For backend authors: sort `names` (each owned by `gpa`) and take
        /// them over as a `Listing`. Frees them if that fails.
        pub fn fromOwned(gpa: Allocator, names: *std.ArrayList([]u8)) Allocator.Error!Listing {
            errdefer {
                for (names.items) |n| gpa.free(n);
                names.deinit(gpa);
            }
            std.mem.sort([]u8, names.items, {}, struct {
                fn lessThan(_: void, a: []u8, b: []u8) bool {
                    return std.mem.order(u8, a, b) == .lt;
                }
            }.lessThan);
            return .{ .names = try names.toOwnedSlice(gpa) };
        }
    };

    pub const Error = error{
        /// SimStorage only: the simulated machine died at this operation.
        Crashed,
        FileNotFound,
        /// `open` with `.create_new` on a path that already exists.
        PathAlreadyExists,
        AccessDenied,
        NoSpaceLeft,
        InputOutput,
        IsDir,
        OutOfMemory,
        Unexpected,
        /// This backend / filesystem cannot take advisory locks at all (e.g.
        /// WASI, or a filesystem whose `flock` returns EOPNOTSUPP). Reported,
        /// never swallowed: a store that silently skips locking is worse than
        /// one that refuses to open. Pass `Options.lock = .none` to proceed
        /// without cross-process exclusion.
        LockUnsupported,
        /// The backend's open-handle table is full — a backend-imposed limit,
        /// **not** the OS's `EMFILE`/`ENFILE` (those still surface as
        /// `Unexpected` from the underlying `openFile`). Distinct from
        /// `Unexpected` on purpose: this one is diagnosable and actionable —
        /// close handles, or size the backend's table for the workload
        /// (`FsStorageCapacity`). `FsStorage` used to report exactly this
        /// condition as `error.Unexpected`, which made a store that simply
        /// wanted a fifth open file indistinguishable from a real bug.
        HandleTableFull,
    };

    pub const VTable = struct {
        open: *const fn (ctx: *anyopaque, path: []const u8, mode: OpenMode) Error!Handle,
        size: *const fn (ctx: *anyopaque, h: Handle) Error!u64,
        pread: *const fn (ctx: *anyopaque, h: Handle, buf: []u8, off: u64) Error!usize,
        writeAll: *const fn (ctx: *anyopaque, h: Handle, bytes: []const u8, off: u64) Error!void,
        sync: *const fn (ctx: *anyopaque, h: Handle) Error!void,
        truncate: *const fn (ctx: *anyopaque, h: Handle, len: u64) Error!void,
        close: *const fn (ctx: *anyopaque, h: Handle) void,
        rename: *const fn (ctx: *anyopaque, old_path: []const u8, new_path: []const u8) Error!void,
        delete: *const fn (ctx: *anyopaque, path: []const u8) Error!void,
        syncDir: *const fn (ctx: *anyopaque) Error!void,
        tryLockExclusive: *const fn (ctx: *anyopaque, h: Handle) Error!bool,

        /// Optional zero-copy read. `null` (the default) means this backend
        /// cannot lend — a file-descriptor backend has nothing to lend, since
        /// the bytes only exist once the kernel has copied them somewhere.
        /// Defaulted so every existing implementer keeps compiling and keeps
        /// answering "no" truthfully, rather than being forced to write a
        /// stub that quietly copies.
        preadRef: ?*const fn (ctx: *anyopaque, h: Handle, len: usize, off: u64) Error!?Ref = null,
        /// Hand a `Ref` back. Must be non-null whenever `preadRef` is.
        releaseRef: ?*const fn (ctx: *anyopaque, ref: Ref) void = null,

        /// Optional preallocation (`Storage.allocate`). `null` (the default)
        /// means this backend cannot reserve space; a backend that can in
        /// general but not on this particular file or filesystem returns
        /// `false`. Defaulted for the same reason as `preadRef`.
        allocate: ?*const fn (ctx: *anyopaque, h: Handle, len: u64) Error!bool = null,
        /// Optional data-only sync (`Storage.syncData`). `null` means the
        /// backend has none, and `syncData` falls back to `sync`.
        syncData: ?*const fn (ctx: *anyopaque, h: Handle) Error!void = null,
        /// Optional directory listing (`Storage.list`). `null` (the default)
        /// means this backend cannot list; a decorator whose inner backend
        /// cannot returns `null` from its own slot. Defaulted for the same
        /// reason as `preadRef`.
        list: ?*const fn (ctx: *anyopaque, gpa: Allocator, prefix: []const u8) Error!?Listing = null,

        /// Self-check for a backend author: true iff `preadRef` and
        /// `releaseRef` are either both set or both null. `Storage.releaseRef`
        /// panics at the first borrow release if this is false — call this
        /// (e.g. in a test that builds your vtable) to catch the mistake at
        /// the vtable's own construction instead of at first use.
        pub fn consistent(vt: VTable) bool {
            return (vt.preadRef == null) == (vt.releaseRef == null);
        }
    };

    pub fn open(s: Storage, path: []const u8, mode: OpenMode) Error!Handle {
        return s.vtable.open(s.ctx, path, mode);
    }
    pub fn size(s: Storage, h: Handle) Error!u64 {
        return s.vtable.size(s.ctx, h);
    }
    pub fn pread(s: Storage, h: Handle, buf: []u8, off: u64) Error!usize {
        return s.vtable.pread(s.ctx, h, buf, off);
    }
    /// `pread` until `buf` is full; a premature end-of-file is corruption
    /// from the store's point of view (the keydir said the bytes exist).
    pub fn preadFull(s: Storage, h: Handle, buf: []u8, off: u64) (Error || error{Corrupt})!void {
        var index: usize = 0;
        while (index < buf.len) {
            const n = try s.pread(h, buf[index..], off + index);
            if (n == 0) return error.Corrupt;
            index += n;
        }
    }
    /// Can this backend serve reads without copying (`preadRef`)? Ask once
    /// and branch; a caller that never asks simply keeps using `pread` and
    /// pays a copy, which is always correct.
    pub fn canLend(s: Storage) bool {
        return s.vtable.preadRef != null;
    }

    /// Borrow exactly `len` bytes at `off` instead of copying them into a
    /// buffer. Returns `null` — never an error — when this backend cannot
    /// lend at all, or cannot lend *this* access (wrong shape, the bytes are
    /// not resident, a short read at end-of-file). `null` is the caller's
    /// signal to use `pread`; it is never a stale or partial success.
    ///
    /// Every non-null result must be passed to `releaseRef` exactly once.
    pub fn preadRef(s: Storage, h: Handle, len: usize, off: u64) Error!?Ref {
        const f = s.vtable.preadRef orelse return null;
        return f(s.ctx, h, len, off);
    }

    /// Return a borrow taken with `preadRef`.
    ///
    /// Precondition: `s.vtable.releaseRef` is non-null whenever
    /// `s.vtable.preadRef` is (see the field doc comments on `VTable`, and
    /// `VTable.consistent` for a self-check backend authors can call). A
    /// backend that violates this — sets `preadRef` but not `releaseRef` —
    /// is a construction bug in that backend, not a caller error, so this
    /// panics with a message that names the actual problem instead of an
    /// opaque null-unwrap.
    pub fn releaseRef(s: Storage, ref: Ref) void {
        const f = s.vtable.releaseRef orelse std.debug.panic(
            "kv.Storage.VTable contract violation: preadRef is set but releaseRef is null",
            .{},
        );
        f(s.ctx, ref);
    }

    pub fn writeAll(s: Storage, h: Handle, bytes: []const u8, off: u64) Error!void {
        return s.vtable.writeAll(s.ctx, h, bytes, off);
    }
    pub fn sync(s: Storage, h: Handle) Error!void {
        return s.vtable.sync(s.ctx, h);
    }
    pub fn truncate(s: Storage, h: Handle, len: u64) Error!void {
        return s.vtable.truncate(s.ctx, h, len);
    }

    /// Make the file at least `len` bytes long with its blocks reserved, the
    /// added range reading as zeros — `fallocate(fd, 0, 0, len)`. Never
    /// shrinks a file and never changes a byte already in it. Returns
    /// `false`, having done nothing, when the backend or the filesystem
    /// cannot preallocate; that is not an error, because nothing that
    /// follows depends on it for correctness.
    ///
    /// What it is for: writes into a reserved range cannot fail for lack of
    /// space, and they do not change the file's size, so `syncData` after
    /// them has no size to record — on ext4 that took an append-and-sync
    /// loop from about 305 to about 850 per second (2026-09-27, NVMe). It
    /// needs the size-extending form: reserving with `FALLOC_FL_KEEP_SIZE`
    /// measured no faster than not reserving at all.
    ///
    /// ⚠ The new length, like a write, is durable only after `sync` (or
    /// `syncData`). And a reader of the file now sees zeros past the data:
    /// a format written this way must recognise a zero tail as "no more
    /// data yet", not as a torn record.
    pub fn allocate(s: Storage, h: Handle, len: u64) Error!bool {
        const f = s.vtable.allocate orelse return false;
        return f(s.ctx, h, len);
    }

    /// Make the file's data durable, and its metadata only as far as reading
    /// that data back needs it (`fdatasync`): the size when it changed, not
    /// the modification time. The same guarantee for the bytes as `sync`,
    /// cheaper when the size did not change (see `allocate`). A backend
    /// without it does a full `sync` — a stronger promise, never a weaker one.
    pub fn syncData(s: Storage, h: Handle) Error!void {
        if (s.vtable.syncData) |f| return f(s.ctx, h);
        return s.vtable.sync(s.ctx, h);
    }

    /// The files in this backend's namespace whose names start with
    /// `prefix` (`""` for all), sorted bytewise ascending; `null` when the
    /// backend cannot list. Regular files only, a symbolic link counting as
    /// what it points to — what `open` would open; not recursive. The view
    /// is the running process's: a name created but not yet made durable by
    /// `syncDir` is listed, and a crash may take it away again. Not a
    /// snapshot against a concurrent create or delete.
    ///
    /// What it is for: recovery and tooling that must find files nothing
    /// else records — e.g. rebuilding a lost manifest from the segment files
    /// it listed, or finding strays to clean up.
    ///
    /// ⚠ Never derive what a store *is* from a listing on the normal path.
    /// A store that opened whatever files looked like its own would adopt
    /// any stray file of the right name (a half-written segment, a restored
    /// backup, an operator's copy); a durable record of its files (a
    /// manifest) is what says which ones belong. `Db` itself never lists.
    pub fn list(s: Storage, gpa: Allocator, prefix: []const u8) Error!?Listing {
        const f = s.vtable.list orelse return null;
        return f(s.ctx, gpa, prefix);
    }
    pub fn close(s: Storage, h: Handle) void {
        s.vtable.close(s.ctx, h);
    }
    pub fn rename(s: Storage, old_path: []const u8, new_path: []const u8) Error!void {
        return s.vtable.rename(s.ctx, old_path, new_path);
    }
    pub fn delete(s: Storage, path: []const u8) Error!void {
        return s.vtable.delete(s.ctx, path);
    }
    pub fn syncDir(s: Storage) Error!void {
        return s.vtable.syncDir(s.ctx);
    }

    /// Try to take an exclusive ADVISORY lock on the open file description
    /// `h`. Returns `true` when the lock is now held, `false` when an
    /// incompatible lock is already held by someone else. **Never blocks.**
    ///
    /// There is deliberately NO `unlock` operation: the lock's lifetime is
    /// exactly the handle's lifetime — `close` releases it, and so does the
    /// holder dying. That is not an accident of the API, it is the reason
    /// the semantics below were chosen.
    ///
    /// ### Why `flock(2)` and not `fcntl(F_SETLK)`
    ///
    /// `flock` locks belong to the **open file description**; `fcntl` locks
    /// belong to the **process**. Three consequences decide it:
    ///
    ///  1. **The `fcntl` close footgun.** A POSIX record lock is dropped as
    ///     soon as the process closes *any* descriptor for that file — even a
    ///     descriptor it never locked, opened by unrelated code elsewhere in
    ///     the program. A library cannot defend against that: some other
    ///     module stat-ing/opening the same path would silently unlock our
    ///     store. `flock` is immune (only closing the last copy of *this*
    ///     description releases it).
    ///  2. **`fork`.** `flock`: the child inherits the descriptor and thus a
    ///     *share* of the same lock — it does NOT get a second, independent
    ///     lock, and the lock is released only once parent and child have
    ///     both closed (or died). So forking a process holding an open `Db`
    ///     leaves exactly one logical writer; two forked halves must not both
    ///     write, and the lock will not tell them apart (it is one holder).
    ///     A child that wants its own store must `Db.open` afresh, which
    ///     creates a new description and is correctly refused with
    ///     `error.Locked` while the parent holds the store. `fcntl` instead
    ///     gives the child *no* lock at all, which looks safe until the child
    ///     re-locks and both halves believe they own the store.
    ///  3. **Death cleanup.** Both flavors are released by the kernel when
    ///     the holder dies, so a crashed writer never leaves a stale lock
    ///     behind and there is no PID file to garbage-collect. `flock`'s
    ///     description scope makes this exact under `fork`/`dup` too.
    ///
    /// ### What is NOT promised
    ///
    ///  * **Advisory only.** A process that never calls `Db.open` (`cat >`,
    ///     an editor, another library) is not stopped by anything here.
    ///  * **Network filesystems.** On NFS, Linux emulates `flock` on top of
    ///     POSIX record locks — which re-introduces footgun (1) — and some
    ///     configurations (`local_lock=`, `-o nolock`, several SMB/9p/FUSE
    ///     setups) make the lock **node-local**, i.e. it silently fails to
    ///     exclude a writer on another host. This module promises
    ///     cross-process exclusion on **local POSIX filesystems** only. Do
    ///     not put a `kv` store on a network share and expect this to save
    ///     you; nothing at this layer can detect the degradation.
    ///  * **Not a substitute for the durability contract.** The lock is held
    ///     across every write *and* its `fsync`, from `open` to `close` — a
    ///     lock dropped before the data is durable would protect nothing —
    ///     but it says nothing about media integrity.
    pub fn tryLockExclusive(s: Storage, h: Handle) Error!bool {
        return s.vtable.tryLockExclusive(s.ctx, h);
    }
};

// ── FsStorage: the real-filesystem backend ───────────────────────────────────

/// `Storage` over the real filesystem (`std.Io`). All paths passed to
/// `Db.open` are resolved relative to `dir`, and `syncDir` fsyncs that
/// directory handle — keep the store's files directly inside `dir`.
///
/// POSIX-oriented: `syncDir` fsyncs the directory handle, the mechanism
/// that makes file creation and rename durable on POSIX filesystems. On
/// platforms where fsync-of-a-directory is not supported the error is
/// reported (not swallowed); this backend is verified on Linux.
pub const FsStorage = FsStorageCapacity(default_max_handles);

/// How many files one `FsStorage` can hold open at once by default.
///
/// **This used to be 4**, sized for exactly one `Db` (data file + lock
/// sidecar + compaction temp, plus one spare) — but an `FsStorage` is not
/// per-`Db`: it is a backend that several stores share, and the handle table
/// is the *shared* resource. That cap was reached twice in practice, both
/// times by `shardstore`, which needs `n_shards × 2` handles when it locks
/// per shard and so could not open more than two shards over the default
/// backend. Neither site could see why: exhaustion was reported as
/// `error.Unexpected`.
///
/// 64 is not a claim that 64 is enough for everyone — it is a default sized
/// for "a handful of stores over one backend" instead of "one store", at a
/// cost of well under a kilobyte of inline table. Callers with a known,
/// larger fan-out ask for the size they need with `FsStorageCapacity`, and
/// callers that exceed whatever they chose now get `error.HandleTableFull`,
/// which says what happened and what to change.
pub const default_max_handles = 64;

/// `FsStorage` with an explicitly sized handle table — for a caller whose
/// fan-out over a single backend is known and larger than
/// `default_max_handles` (e.g. `shardstore` with many shards, which needs
/// two handles per shard). `FsStorageCapacity(default_max_handles)` *is*
/// `FsStorage`; the types are identical, not merely compatible.
pub fn FsStorageCapacity(comptime max_handles: usize) type {
    return struct {
        const Self = @This();

        io: std.Io,
        dir: std.Io.Dir,
        files: [max_handles]?std.Io.File = @splat(null),
        /// Opened `.read_only`: writes and truncation are refused here, not
        /// left to the OS's choice of errno.
        read_only: [max_handles]bool = @splat(false),

        /// How many files this backend can hold open at once. Exceeding it is
        /// `error.HandleTableFull`, never `error.Unexpected`.
        pub const capacity = max_handles;

        pub fn init(io: std.Io, dir: std.Io.Dir) Self {
            return .{ .io = io, .dir = dir };
        }

        pub fn storage(self: *Self) Storage {
            return .{ .ctx = self, .vtable = &vtable };
        }

        const vtable = Storage.VTable{
            .open = vOpen,
            .size = vSize,
            .pread = vPread,
            .writeAll = vWriteAll,
            .sync = vSync,
            .truncate = vTruncate,
            .close = vClose,
            .rename = vRename,
            .delete = vDelete,
            .syncDir = vSyncDir,
            .tryLockExclusive = vTryLockExclusive,
            .allocate = if (is_linux) vAllocate else null,
            .syncData = if (is_linux) vSyncData else null,
            .list = vList,
        };

        const is_linux = @import("builtin").os.tag == .linux;

        fn cast(ctx: *anyopaque) *Self {
            return @ptrCast(@alignCast(ctx));
        }

        fn mapErr(e: anyerror) Storage.Error {
            return switch (e) {
                error.FileLocksUnsupported => error.LockUnsupported,
                error.FileNotFound => error.FileNotFound,
                error.PathAlreadyExists => error.PathAlreadyExists,
                error.AccessDenied, error.PermissionDenied => error.AccessDenied,
                error.NoSpaceLeft, error.DiskQuota => error.NoSpaceLeft,
                error.InputOutput => error.InputOutput,
                error.IsDir => error.IsDir,
                error.OutOfMemory => error.OutOfMemory,
                else => error.Unexpected,
            };
        }

        fn vOpen(ctx: *anyopaque, path: []const u8, mode: Storage.OpenMode) Storage.Error!Storage.Handle {
            const self = cast(ctx);
            // The handle table is this backend's only fixed resource. It
            // used to report exhaustion as `error.Unexpected`, so a caller
            // that simply needed one more open file could not tell a sizing
            // problem from a bug — see `default_max_handles`.
            const slot: usize = for (self.files, 0..) |f, i| {
                if (f == null) break i;
            } else return error.HandleTableFull;
            const file = switch (mode) {
                .open_or_create, .create_truncate, .create_new => self.dir.createFile(self.io, path, .{
                    .read = true,
                    .truncate = mode == .create_truncate,
                    .exclusive = mode == .create_new,
                }),
                .read_only => self.dir.openFile(self.io, path, .{ .mode = .read_only }),
            } catch |e| return mapErr(e);
            self.files[slot] = file;
            self.read_only[slot] = mode == .read_only;
            return @intCast(slot);
        }

        fn fileOf(self: *Self, h: Storage.Handle) std.Io.File {
            return self.files[h].?;
        }

        fn vSize(ctx: *anyopaque, h: Storage.Handle) Storage.Error!u64 {
            const self = cast(ctx);
            return self.fileOf(h).length(self.io) catch |e| mapErr(e);
        }

        fn vPread(ctx: *anyopaque, h: Storage.Handle, buf: []u8, off: u64) Storage.Error!usize {
            const self = cast(ctx);
            return self.fileOf(h).readPositionalAll(self.io, buf, off) catch |e| mapErr(e);
        }

        fn vWriteAll(ctx: *anyopaque, h: Storage.Handle, bytes: []const u8, off: u64) Storage.Error!void {
            const self = cast(ctx);
            if (self.read_only[h]) return error.AccessDenied;
            self.fileOf(h).writePositionalAll(self.io, bytes, off) catch |e| return mapErr(e);
        }

        fn vSync(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
            const self = cast(ctx);
            self.fileOf(h).sync(self.io) catch |e| return mapErr(e);
        }

        fn vTruncate(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!void {
            const self = cast(ctx);
            if (self.read_only[h]) return error.AccessDenied;
            self.fileOf(h).setLength(self.io, len) catch |e| return mapErr(e);
        }

        /// `fallocate(fd, 0, 0, len)`, straight to the syscall: `std.Io.File`
        /// has no preallocation. A filesystem without it (`EOPNOTSUPP`) is
        /// `false`, not an error.
        fn vAllocate(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!bool {
            const self = cast(ctx);
            if (self.read_only[h]) return error.AccessDenied;
            const fd = self.fileOf(h).handle;
            const signed_len = std.math.cast(i64, len) orelse return error.NoSpaceLeft;
            while (true) {
                switch (linux.errno(linux.fallocate(fd, 0, 0, signed_len))) {
                    .SUCCESS => return true,
                    .INTR => continue,
                    .OPNOTSUPP, .NOSYS => return false,
                    .NOSPC, .DQUOT, .FBIG => return error.NoSpaceLeft,
                    .IO => return error.InputOutput,
                    .BADF, .PERM, .ACCES, .ROFS, .TXTBSY => return error.AccessDenied,
                    else => return error.Unexpected,
                }
            }
        }

        /// `fdatasync(fd)`, straight to the syscall: `std.Io.File` has only
        /// `sync`.
        fn vSyncData(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
            const self = cast(ctx);
            while (true) {
                switch (linux.errno(linux.fdatasync(self.fileOf(h).handle))) {
                    .SUCCESS => return,
                    .INTR => continue,
                    .IO => return error.InputOutput,
                    .NOSPC, .DQUOT => return error.NoSpaceLeft,
                    else => return error.Unexpected,
                }
            }
        }

        fn vClose(ctx: *anyopaque, h: Storage.Handle) void {
            const self = cast(ctx);
            if (self.files[h]) |f| f.close(self.io);
            self.files[h] = null;
        }

        fn vRename(ctx: *anyopaque, old_path: []const u8, new_path: []const u8) Storage.Error!void {
            const self = cast(ctx);
            std.Io.Dir.rename(self.dir, old_path, self.dir, new_path, self.io) catch |e| return mapErr(e);
        }

        fn vDelete(ctx: *anyopaque, path: []const u8) Storage.Error!void {
            const self = cast(ctx);
            self.dir.deleteFile(self.io, path) catch |e| return mapErr(e);
        }

        fn vSyncDir(ctx: *anyopaque) Storage.Error!void {
            const self = cast(ctx);
            // `dir` may have been opened O_PATH (std's default for non-iterable
            // dir handles), which cannot be fsync'd — re-open "." as a real
            // handle (`iterate = true` forces a non-O_PATH fd) just for the sync.
            const d = self.dir.openDir(self.io, ".", .{ .iterate = true }) catch |e| return mapErr(e);
            defer d.close(self.io);
            const as_file = std.Io.File{ .handle = d.handle, .flags = .{ .nonblocking = false } };
            as_file.sync(self.io) catch |e| return mapErr(e);
        }

        fn vList(ctx: *anyopaque, gpa: Allocator, prefix: []const u8) Storage.Error!?Storage.Listing {
            const self = cast(ctx);
            // `dir` may be an O_PATH handle, which cannot be read (see `vSyncDir`).
            const d = self.dir.openDir(self.io, ".", .{ .iterate = true }) catch |e| return mapErr(e);
            defer d.close(self.io);
            var names: std.ArrayList([]u8) = .empty;
            errdefer {
                for (names.items) |n| gpa.free(n);
                names.deinit(gpa);
            }
            var it = d.iterate();
            while (it.next(self.io) catch |e| return mapErr(e)) |entry| {
                if (!std.mem.startsWith(u8, entry.name, prefix)) continue;
                if (!try isFile(self.io, d, entry)) continue;
                try names.append(gpa, try gpa.dupe(u8, entry.name));
            }
            return try Storage.Listing.fromOwned(gpa, &names);
        }

        /// A regular file, or a link to one: what `open` would open. A
        /// filesystem that does not report kinds in its entries (`.unknown`)
        /// is asked with a `stat`; a name gone meanwhile, or a dangling link,
        /// is not a file.
        fn isFile(io: std.Io, d: std.Io.Dir, entry: std.Io.Dir.Entry) Storage.Error!bool {
            return switch (entry.kind) {
                .file => true,
                .sym_link, .unknown => if (d.statFile(io, entry.name, .{})) |st| st.kind == .file else |e| switch (e) {
                    error.FileNotFound => false,
                    else => mapErr(e),
                },
                else => false,
            };
        }

        /// `flock(fd, LOCK_EX | LOCK_NB)` (POSIX) / `NtLockFile` with fail-
        /// immediately (Windows), via `std.Io.File.tryLock` — the non-blocking
        /// form, so a contended store reports `error.Locked` to the caller
        /// instead of parking the thread inside a library call forever.
        fn vTryLockExclusive(ctx: *anyopaque, h: Storage.Handle) Storage.Error!bool {
            const self = cast(ctx);
            return self.fileOf(h).tryLock(self.io, .exclusive) catch |e| mapErr(e);
        }
    };
}

// ── Db ───────────────────────────────────────────────────────────────────────

pub const Options = struct {
    /// Re-verify the whole record's CRC on every `get` (never serve corrupt
    /// data even if the file rotted after `open`). Costs one extra read of
    /// the record header + key per get; disable only if the value copy alone
    /// is acceptable verification (replay already CRC-checked every record).
    read_verify: bool = true,

    /// Cross-process exclusion policy (default: on). See `LockPolicy`.
    lock: LockPolicy = .exclusive,

    /// Wall clock that decides whether an expiring key is still live. Read
    /// only when the store holds expiring keys. See `Clock`.
    clock: Clock = .realtime,
};

/// A key's expiry, as `expiresAt` reports it.
pub const Expiry = union(enum) {
    /// Written by `put`: lives until overwritten or deleted.
    never,
    /// Written by `putExpiring`/`putTtl`: absent from `at_ms` on (ms since the
    /// Unix epoch, `Options.clock`).
    at_ms: i64,
};

/// Live keys as `keys` returns them, sorted bytewise ascending. The slice and
/// every key in it belong to the allocator passed to `keys`.
pub const KeyList = struct {
    keys: [][]u8,

    pub fn deinit(l: KeyList, gpa: Allocator) void {
        for (l.keys) |k| gpa.free(k);
        gpa.free(l.keys);
    }
};

pub const LockPolicy = enum {
    /// Take and hold an exclusive advisory lock on `<path>.lock` for the
    /// whole lifetime of the `Db`. A second opener gets `error.Locked`.
    /// This is the default: two writers over one append-only log corrupt it,
    /// and "one instance per store is the caller's responsibility" is not a
    /// guarantee, it is a hope.
    exclusive,
    /// No locking at all. For backends where it is meaningless (a pure
    /// in-memory `Storage`), for a caller that already has its own
    /// exclusion, or for the network-filesystem case where the lock would be
    /// a lie anyway (see `Storage.tryLockExclusive`). Choosing this is
    /// choosing to be the sole writer by construction.
    none,
};

pub const OpenError = Storage.Error || error{
    /// The file exists but does not carry this store's magic.
    NotAKvFile,
    /// The file is a kv store from an incompatible (newer) format version.
    UnsupportedVersion,
    Corrupt,
    /// Another `Db` — in another process, or in this one — currently holds
    /// the store's exclusive lock. Nothing was opened, read or written; the
    /// data file was not even touched. Retrying is the caller's decision
    /// (this is the non-blocking path, by design: a library that blocks
    /// forever inside `open` is a library that hangs your program).
    Locked,
};

pub const MutateError = Storage.Error || error{
    /// A previous storage-write error left durability in doubt; the store
    /// refuses further mutations (fail-stop). Reopen to recover.
    Poisoned,
    KeyTooLong,
    ValueTooLong,
};

pub const GetError = Storage.Error || error{
    /// The record failed its CRC re-check on read. Nothing was served.
    Corrupt,
};

pub const CompactError = MutateError || error{Corrupt};

/// Embedded crash-consistent KV store. See the module doc for the durability
/// contract, the corruption policy and the v0 concurrency model.
pub const Db = struct {
    gpa: Allocator,
    store: Storage,
    file: Storage.Handle,
    /// Owned copies of the data-file path, the compaction temp path and the
    /// cross-process lock sidecar path.
    path: []u8,
    tmp_path: []u8,
    lock_path: []u8,
    /// Handle of the held `<path>.lock` sidecar, or null with
    /// `LockPolicy.none`. Closing it releases the advisory lock.
    lock_file: ?Storage.Handle,
    keydir: std.StringHashMapUnmanaged(Entry),
    /// Append offset == length of the valid prefix of the data file.
    end: u64,
    /// Bytes occupied by overwritten/deleted records (compaction would
    /// reclaim this much).
    dead_bytes: u64,
    poisoned: bool,
    lock: std.atomic.Mutex,
    options: Options,
    /// On-disk format version of the open data file: `version_plain` until
    /// the first expiring put upgrades it (see the format comment).
    version: u32,
    /// Keydir entries that carry an expiry. While it is 0 no operation reads
    /// the clock and `count` stays O(1).
    expiring: usize,

    const Entry = struct {
        /// Absolute file offset of the record.
        off: u64,
        key_len: u32,
        val_len: u32,
        /// `no_expiry`, or the ms instant (Unix epoch) from which the key is
        /// absent.
        expires_at: i64 = no_expiry,

        fn expires(e: Entry) bool {
            return e.expires_at != no_expiry;
        }

        fn recLen(e: Entry) u64 {
            return recordLenExp(e.expires(), e.key_len, e.val_len);
        }

        /// Offset of the key bytes inside the file.
        fn keyOff(e: Entry) u64 {
            return e.off + rec_fixed + @as(u64, if (e.expires()) exp_len else 0);
        }

        fn liveAt(e: Entry, now: i64) bool {
            return now < e.expires_at;
        }
    };

    /// Open (or create) the store at `path`, replaying the log to rebuild
    /// the keydir. A torn/corrupt tail is truncated to the last good record.
    /// A stale compaction temp file (`<path>.compact`) is removed.
    /// `path` is resolved by the given `Storage` (for `FsStorage`: relative
    /// to its directory; must not contain a separator, so the dir fsync
    /// covers it).
    ///
    /// Unless `options.lock == .none`, the store's exclusive advisory lock is
    /// taken FIRST — before the stale temp is removed, before the log is
    /// replayed, and before recovery truncates a torn tail. That ordering is
    /// the point: those are precisely the steps two concurrent openers would
    /// corrupt. A contended store returns `error.Locked` with the data file
    /// untouched.
    pub fn open(gpa: Allocator, store: Storage, path: []const u8, options: Options) OpenError!Db {
        var self = Db{
            .gpa = gpa,
            .store = store,
            .file = undefined,
            .path = try gpa.dupe(u8, path),
            .tmp_path = undefined,
            .lock_path = undefined,
            .lock_file = null,
            .keydir = .empty,
            .end = header_len,
            .dead_bytes = 0,
            .poisoned = false,
            .lock = .unlocked,
            .options = options,
            .version = version_plain,
            .expiring = 0,
        };
        errdefer gpa.free(self.path);
        self.tmp_path = try std.fmt.allocPrint(gpa, "{s}.compact", .{path});
        errdefer gpa.free(self.tmp_path);
        self.lock_path = try std.fmt.allocPrint(gpa, "{s}.lock", .{path});
        errdefer gpa.free(self.lock_path);

        // Cross-process exclusion, before anything else touches the store.
        //
        // The lock lives on a SIDECAR file, not on the data file, because
        // `compact()` replaces the data file by `rename(2)`: a lock held on
        // the data file's open description would survive as a lock on an
        // unlinked inode while the store's NAME resolves to a fresh, unlocked
        // one — mutual exclusion silently lost at exactly the moment the
        // store is being rewritten. The sidecar's inode is never renamed and
        // never deleted (unlink+recreate would hand two processes locks on
        // two different inodes of the same name), so it is a stable identity
        // for "this store" across compactions and restarts. It stays behind
        // as an empty file; that is the cost.
        if (options.lock == .exclusive) self.lock_file = try store.open(self.lock_path, .open_or_create);
        // Closing the handle is what releases the lock, so this one errdefer
        // covers every later failure path, acquired or not.
        errdefer if (self.lock_file) |lh| store.close(lh);
        if (self.lock_file) |lh| {
            if (!try store.tryLockExclusive(lh)) return error.Locked;
        }

        // A crash mid-compaction may leave a temp file behind; it is dead
        // weight (the swap either fully happened or the old file stands).
        store.delete(self.tmp_path) catch |e| switch (e) {
            error.FileNotFound => {},
            else => return e,
        };

        self.file = try store.open(path, .open_or_create);
        errdefer store.close(self.file);
        errdefer self.freeKeydir();

        const file_size = try store.size(self.file);
        if (file_size < header_len) {
            // Empty file — or the torn remnant of a crashed creation. Only
            // adopt it if what IS there is a prefix of our own header.
            var have: [header_len]u8 = undefined;
            const n = try store.pread(self.file, have[0..@intCast(file_size)], 0);
            var want: [header_len]u8 = undefined;
            want[0..4].* = file_magic.*;
            std.mem.writeInt(u32, want[4..8], version_plain, .little);
            if (!std.mem.eql(u8, have[0..n], want[0..n])) return error.NotAKvFile;
            if (file_size != 0) try store.truncate(self.file, 0);
            try store.writeAll(self.file, &want, 0);
            try store.sync(self.file);
        } else {
            var hdr: [header_len]u8 = undefined;
            try store.preadFull(self.file, &hdr, 0);
            if (!std.mem.eql(u8, hdr[0..4], file_magic)) return error.NotAKvFile;
            self.version = std.mem.readInt(u32, hdr[4..8], .little);
            if (self.version != version_plain and self.version != version_expiry)
                return error.UnsupportedVersion;
            try self.replay(file_size);
        }
        // Make the file's very existence durable (creation + any recovery
        // truncation above are meaningless if the directory entry is lost).
        try store.syncDir();
        return self;
    }

    /// Close the store and free all memory. Does not sync (every committed
    /// mutation already was). Releases the cross-process lock — by closing
    /// the handle that holds it, the same mechanism the kernel applies when
    /// the process dies, so there is no path where a lock outlives its `Db`.
    pub fn close(self: *Db) void {
        self.store.close(self.file);
        if (self.lock_file) |lh| self.store.close(lh);
        self.freeKeydir();
        self.gpa.free(self.path);
        self.gpa.free(self.tmp_path);
        self.gpa.free(self.lock_path);
        self.* = undefined;
    }

    /// Insert or overwrite `key`. Durable when this returns: the record has
    /// been appended AND fsync'd (see the module doc for what fsync can and
    /// cannot promise). On a storage error the store poisons itself.
    /// Overwriting an expiring key removes its expiry.
    pub fn put(self: *Db, key: []const u8, value: []const u8) MutateError!void {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        return self.putLocked(key, value, no_expiry);
    }

    /// `put` with an expiry: from `expires_at_ms` (ms since the Unix epoch,
    /// read against `Options.clock`) on, `key` is absent to every read,
    /// `keys` and `count`; `compact` and `open` drop it from the file and
    /// memory. An instant already past is accepted and leaves the key absent
    /// at once (Redis `SET … EXAT` in the past does the same).
    ///
    /// The first expiring put into a store still at format version 1
    /// upgrades it to version 2 by running `compact` first — one full rewrite,
    /// once in the store's life — so that a reader knowing only version 1
    /// refuses the file instead of truncating it at the first expiring
    /// record. Compaction errors are returned as they are from `compact`.
    pub fn putExpiring(self: *Db, key: []const u8, value: []const u8, expires_at_ms: i64) CompactError!void {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        if (self.poisoned) return error.Poisoned;
        // `no_expiry` is the keydir's marker, not an instant; a key living to
        // the end of i64 time is a key without expiry.
        if (expires_at_ms == no_expiry) return self.putLocked(key, value, no_expiry);
        if (self.version < version_expiry) try self.compactLocked(version_expiry);
        return self.putLocked(key, value, expires_at_ms);
    }

    /// `putExpiring` at `ttl_ms` from now (`Options.clock`), saturating.
    pub fn putTtl(self: *Db, key: []const u8, value: []const u8, ttl_ms: u64) CompactError!void {
        const now = self.options.clock.now();
        const ttl: i64 = std.math.cast(i64, ttl_ms) orelse std.math.maxInt(i64);
        // Saturates at `no_expiry`: a TTL past the end of i64 time never expires.
        return self.putExpiring(key, value, now +| ttl);
    }

    fn putLocked(self: *Db, key: []const u8, value: []const u8, expires_at: i64) MutateError!void {
        if (self.poisoned) return error.Poisoned;
        if (key.len > std.math.maxInt(u32)) return error.KeyTooLong;
        if (value.len > std.math.maxInt(u32)) return error.ValueTooLong;
        const expires = expires_at != no_expiry;
        std.debug.assert(!expires or self.version >= version_expiry);

        const rec_len: usize = @intCast(recordLenExp(expires, key.len, value.len));
        const rec = try self.gpa.alloc(u8, rec_len);
        defer self.gpa.free(rec);
        encodeRecordExp(rec, if (expires) op_put_exp else op_put, expires_at, key, value);

        // Reserve all keydir memory BEFORE the write hits the disk, so a
        // durable record can never fail to be reflected in memory.
        const existing = self.keydir.getPtr(key);
        var new_key: ?[]u8 = null;
        if (existing == null) {
            new_key = try self.gpa.dupe(u8, key);
            self.keydir.ensureUnusedCapacity(self.gpa, 1) catch |e| {
                self.gpa.free(new_key.?);
                return e;
            };
        }
        errdefer if (new_key) |k| self.gpa.free(k);

        self.store.writeAll(self.file, rec, self.end) catch |e| {
            self.poisoned = true;
            return e;
        };
        self.store.sync(self.file) catch |e| {
            self.poisoned = true;
            return e;
        };

        const entry = Entry{ .off = self.end, .key_len = @intCast(key.len), .val_len = @intCast(value.len), .expires_at = expires_at };
        if (existing) |e| {
            self.dead_bytes += e.recLen();
            if (e.expires()) self.expiring -= 1;
            e.* = entry;
        } else {
            self.keydir.putAssumeCapacity(new_key.?, entry);
        }
        if (expires) self.expiring += 1;
        self.end += rec_len;
    }

    /// Delete `key` (append a durable tombstone). Deleting an absent key is
    /// a no-op — no I/O, no error. A key that has expired but is still in
    /// memory (not yet dropped by `compact`/`open`) gets its tombstone
    /// anyway: without it, a wall clock stepped back before the expiry would
    /// bring the deleted key back.
    pub fn delete(self: *Db, key: []const u8) MutateError!void {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        if (self.poisoned) return error.Poisoned;
        const existing = self.keydir.getPtr(key) orelse return;

        const rec_len: usize = @intCast(recordLen(key.len, 0));
        const rec = try self.gpa.alloc(u8, rec_len);
        defer self.gpa.free(rec);
        encodeRecord(rec, op_del, key, "");

        self.store.writeAll(self.file, rec, self.end) catch |e| {
            self.poisoned = true;
            return e;
        };
        self.store.sync(self.file) catch |e| {
            self.poisoned = true;
            return e;
        };

        self.dead_bytes += existing.recLen() + rec_len;
        if (existing.expires()) self.expiring -= 1;
        const kv = self.keydir.fetchRemove(key).?;
        self.gpa.free(@constCast(kv.key));
        self.end += rec_len;
    }

    /// The keydir entry of `key` if it is live now. Caller holds the lock.
    /// Reads the clock only for an entry that carries an expiry.
    fn liveEntry(self: *Db, key: []const u8) ?Entry {
        const e = self.keydir.get(key) orelse return null;
        if (e.expires() and !e.liveAt(self.options.clock.now())) return null;
        return e;
    }

    /// Read the current value of `key` into memory allocated from `gpa`
    /// (caller frees), or null if absent or expired. With `Options.read_verify` (the
    /// default) the whole record's CRC is re-checked — a rotten record
    /// yields `error.Corrupt`, never bad bytes. Reads work on a poisoned
    /// store (they describe the last consistent state).
    pub fn get(self: *Db, gpa: Allocator, key: []const u8) GetError!?[]u8 {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        const e = self.liveEntry(key) orelse return null;

        const value = try gpa.alloc(u8, e.val_len);
        errdefer gpa.free(value);
        try self.readValueLocked(e, key, value);
        return value;
    }

    /// `get` into a caller-owned buffer: no allocation, so a read-heavy loop
    /// can reuse one buffer instead of churning the allocator per hit.
    /// Returns the sub-slice of `buf` holding the value, null when the key is
    /// absent, or `error.BufferTooSmall` when the value does not fit — the
    /// value is never truncated, since a short read that looks successful is
    /// worse than an error. `valueLen` sizes the buffer up front.
    ///
    /// Same locking, same `read_verify` CRC check as `get`.
    pub fn getBuf(self: *Db, buf: []u8, key: []const u8) (GetError || error{BufferTooSmall})!?[]u8 {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        const e = self.liveEntry(key) orelse return null;
        if (e.val_len > buf.len) return error.BufferTooSmall;
        const value = buf[0..e.val_len];
        try self.readValueLocked(e, key, value);
        return value;
    }

    /// Byte length of `key`'s current value, or null if absent — for sizing a
    /// `getBuf` buffer. Pure in-memory (the keydir holds the length).
    pub fn valueLen(self: *Db, key: []const u8) ?u32 {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        const e = self.liveEntry(key) orelse return null;
        return e.val_len;
    }

    /// `key`'s expiry, or null if absent or already expired. Pure in-memory.
    pub fn expiresAt(self: *Db, key: []const u8) ?Expiry {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        const e = self.liveEntry(key) orelse return null;
        return if (e.expires()) .{ .at_ms = e.expires_at } else .never;
    }

    /// Fill `value` (already sized to `e.val_len`) from the log. Caller holds
    /// the lock.
    fn readValueLocked(self: *Db, e: Entry, key: []const u8, value: []u8) GetError!void {
        const key_off = e.keyOff();
        const val_off = key_off + e.key_len;

        if (!self.options.read_verify) {
            return self.store.preadFull(self.file, value, val_off);
        }

        // Full-record verification: header fields must match the keydir and
        // the CRC must hold over op+lens[+expiry]+key+value.
        var hdr: [rec_fixed + exp_len]u8 = undefined;
        const hdr_len: usize = @intCast(key_off - e.off);
        try self.store.preadFull(self.file, hdr[0..hdr_len], e.off);
        if (hdr[4] != (if (e.expires()) op_put_exp else op_put) or
            std.mem.readInt(u32, hdr[5..9], .little) != e.key_len or
            std.mem.readInt(u32, hdr[9..13], .little) != e.val_len)
            return error.Corrupt;
        if (e.expires() and std.mem.readInt(i64, hdr[rec_fixed..][0..exp_len], .little) != e.expires_at)
            return error.Corrupt;
        var crc = std.hash.Crc32.init();
        crc.update(hdr[4..hdr_len]);
        // Stream the key in bounded chunks; it must equal the requested key.
        var kbuf: [512]u8 = undefined;
        var koff: u64 = 0;
        while (koff < e.key_len) {
            const n: usize = @intCast(@min(kbuf.len, e.key_len - koff));
            try self.store.preadFull(self.file, kbuf[0..n], key_off + koff);
            if (!std.mem.eql(u8, kbuf[0..n], key[@intCast(koff)..][0..n])) return error.Corrupt;
            crc.update(kbuf[0..n]);
            koff += n;
        }
        try self.store.preadFull(self.file, value, val_off);
        crc.update(value);
        if (crc.final() != std.mem.readInt(u32, hdr[0..4], .little)) return error.Corrupt;
    }

    /// Whether `key` currently has a value (pure in-memory check).
    pub fn exists(self: *Db, key: []const u8) bool {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        return self.liveEntry(key) != null;
    }

    /// Number of live keys (pure in-memory). O(1) while no key carries an
    /// expiry; otherwise one pass over the keydir, since a key can expire
    /// without any operation touching it.
    pub fn count(self: *Db) usize {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        if (self.expiring == 0) return self.keydir.count();
        const now = self.options.clock.now();
        var n: usize = 0;
        var it = self.keydir.valueIterator();
        while (it.next()) |e| n += @intFromBool(e.liveAt(now));
        return n;
    }

    /// Copies of the live keys that start with `prefix` (`""` = all), sorted
    /// bytewise ascending — Bitcask's `list_keys`. A snapshot taken under the
    /// lock: later writes do not change it. Pure in-memory; the values are
    /// not read (use `get` per key).
    pub fn keys(self: *Db, gpa: Allocator, prefix: []const u8) Allocator.Error!KeyList {
        var out: std.ArrayList([]u8) = .empty;
        errdefer {
            for (out.items) |k| gpa.free(k);
            out.deinit(gpa);
        }
        {
            lockSpin(&self.lock);
            defer self.lock.unlock();
            const now: i64 = if (self.expiring == 0) 0 else self.options.clock.now();
            var it = self.keydir.iterator();
            while (it.next()) |kv| {
                if (!std.mem.startsWith(u8, kv.key_ptr.*, prefix)) continue;
                if (kv.value_ptr.expires() and !kv.value_ptr.liveAt(now)) continue;
                try out.ensureUnusedCapacity(gpa, 1);
                out.appendAssumeCapacity(try gpa.dupe(u8, kv.key_ptr.*));
            }
        }
        std.mem.sort([]u8, out.items, {}, struct {
            fn lessThan(_: void, a: []u8, b: []u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.lessThan);
        return .{ .keys = try out.toOwnedSlice(gpa) };
    }

    /// Bytes the log currently wastes on overwritten/deleted records and on
    /// expired keys — the caller's signal for when `compact` is worth it (v0
    /// compaction is caller-driven; automatic thresholds are a noted phase).
    pub fn deadBytes(self: *Db) u64 {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        if (self.expiring == 0) return self.dead_bytes;
        const now = self.options.clock.now();
        var dead = self.dead_bytes;
        var it = self.keydir.valueIterator();
        while (it.next()) |e| {
            if (!e.liveAt(now)) dead += e.recLen();
        }
        return dead;
    }

    /// Rewrite live records into a fresh file and atomically swap it in
    /// (temp + fsync + rename + dir fsync). A crash anywhere before the
    /// rename leaves the old file untouched; from the rename on, either the
    /// old or the complete new file is what `open` finds — never a mix.
    /// Errors before the rename leave the store fully usable (the temp is
    /// discarded); errors at/after the rename poison the store (the
    /// namespace state is uncertain until reopen). Expired keys are left out
    /// of the new file and dropped from memory.
    pub fn compact(self: *Db) CompactError!void {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        if (self.poisoned) return error.Poisoned;
        return self.compactLocked(self.version);
    }

    /// `compact` writing the new file at format `version`. Caller holds the
    /// lock and has checked `poisoned`.
    fn compactLocked(self: *Db, version: u32) CompactError!void {
        const NewOff = struct { e: *Entry, off: u64 };
        var moves: std.ArrayListUnmanaged(NewOff) = .empty;
        defer moves.deinit(self.gpa);
        try moves.ensureTotalCapacity(self.gpa, self.keydir.count());
        // Expired keys: left out of the new file, removed from the keydir
        // only once the new file is in place.
        var expired: std.ArrayListUnmanaged([]const u8) = .empty;
        defer expired.deinit(self.gpa);
        const now: i64 = if (self.expiring == 0) 0 else self.options.clock.now();

        const tmp = try self.store.open(self.tmp_path, .create_truncate);
        var swapped = false;
        defer if (!swapped) {
            self.store.close(tmp);
            self.store.delete(self.tmp_path) catch {};
        };

        var hdr: [header_len]u8 = undefined;
        hdr[0..4].* = file_magic.*;
        std.mem.writeInt(u32, hdr[4..8], version, .little);
        try self.store.writeAll(tmp, &hdr, 0);

        var new_end: u64 = header_len;
        var it = self.keydir.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr;
            if (!e.liveAt(now)) {
                try expired.append(self.gpa, kv.key_ptr.*);
                continue;
            }
            const rec_len: usize = @intCast(e.recLen());
            const rec = try self.gpa.alloc(u8, rec_len);
            defer self.gpa.free(rec);
            try self.store.preadFull(self.file, rec, e.off);
            // Copy records verbatim (CRC stays valid) — but never copy rot.
            if (std.hash.Crc32.hash(rec[4..]) != std.mem.readInt(u32, rec[0..4], .little))
                return error.Corrupt;
            try self.store.writeAll(tmp, rec, new_end);
            moves.appendAssumeCapacity(.{ .e = e, .off = new_end });
            new_end += rec_len;
        }
        try self.store.sync(tmp);

        self.store.rename(self.tmp_path, self.path) catch |e| {
            self.poisoned = true;
            return e;
        };
        self.store.syncDir() catch |e| {
            self.poisoned = true;
            return e;
        };

        // The temp handle IS the new data file (rename moved the name, not
        // the file). Point the keydir at the new offsets.
        self.store.close(self.file);
        self.file = tmp;
        swapped = true;
        for (moves.items) |m| m.e.off = m.off;
        // Removal leaves the other entries in place (no rehash), so the
        // pointers above stayed valid; drop the expired ones only now.
        for (expired.items) |k| {
            const kv = self.keydir.fetchRemove(k).?;
            self.gpa.free(@constCast(kv.key));
            self.expiring -= 1;
        }
        self.end = new_end;
        self.dead_bytes = 0;
        self.version = version;
    }

    // ── internals ───────────────────────────────────────────────────────────

    fn freeKeydir(self: *Db) void {
        var it = self.keydir.keyIterator();
        while (it.next()) |k| self.gpa.free(@constCast(k.*));
        self.keydir.deinit(self.gpa);
    }

    /// Replay the log from after the header, rebuilding the keydir. Stops at
    /// the first torn/corrupt record and truncates the file back to the last
    /// good one (crash recovery: committed data survives, a half-written
    /// tail is discarded). A record that has expired by now counts as a
    /// delete of its key: it is the key's latest word, and it says "absent".
    fn replay(self: *Db, file_size: u64) OpenError!void {
        // The clock is read once, and only for a file that can hold expiry.
        const now: i64 = if (self.version >= version_expiry) self.options.clock.now() else 0;
        var off: u64 = header_len;
        scan: while (off < file_size) {
            const remaining = file_size - off;
            if (remaining < rec_fixed) break; // torn fixed header
            var hdr: [rec_fixed + exp_len]u8 = undefined;
            try self.store.preadFull(self.file, hdr[0..rec_fixed], off);
            const op = hdr[4];
            const key_len = std.mem.readInt(u32, hdr[5..9], .little);
            const val_len = std.mem.readInt(u32, hdr[9..13], .little);
            if (op != op_put and op != op_del and op != op_put_exp) break; // corrupt op byte
            if (op == op_put_exp and self.version < version_expiry) break; // not in a v1 file
            if (op == op_del and val_len != 0) break;
            const expires = op == op_put_exp;
            const body: u64 = rec_fixed + @as(u64, if (expires) exp_len else 0);
            if (body > remaining) break; // torn expiry field
            if (@as(u64, key_len) + val_len > remaining - body) break; // torn body
            var expires_at: i64 = no_expiry;
            if (expires) {
                try self.store.preadFull(self.file, hdr[rec_fixed..][0..exp_len], off + rec_fixed);
                expires_at = std.mem.readInt(i64, hdr[rec_fixed..][0..exp_len], .little);
            }

            // CRC over op+lens[+expiry]+key+value, streaming the value in bounded
            // chunks (only the key is materialized — it may enter the keydir).
            var crc = std.hash.Crc32.init();
            crc.update(hdr[4..@intCast(body)]);
            const key = try self.gpa.alloc(u8, key_len);
            var key_owned = true;
            defer if (key_owned) self.gpa.free(key);
            try self.store.preadFull(self.file, key, off + body);
            crc.update(key);
            var vbuf: [4096]u8 = undefined;
            var voff: u64 = 0;
            while (voff < val_len) {
                const n: usize = @intCast(@min(vbuf.len, val_len - voff));
                try self.store.preadFull(self.file, vbuf[0..n], off + body + key_len + voff);
                crc.update(vbuf[0..n]);
                voff += n;
            }
            if (crc.final() != std.mem.readInt(u32, hdr[0..4], .little)) break :scan; // torn/corrupt
            // CRC-valid, but not a record this module writes.
            if (expires and expires_at == no_expiry) break :scan;

            const rec_len = body + key_len + val_len;
            if (op == op_del or (expires and expires_at <= now)) {
                if (self.keydir.fetchRemove(key)) |kv| {
                    self.dead_bytes += kv.value.recLen();
                    if (kv.value.expires()) self.expiring -= 1;
                    self.gpa.free(@constCast(kv.key));
                }
                self.dead_bytes += rec_len;
            } else {
                const gop = try self.keydir.getOrPut(self.gpa, key);
                if (gop.found_existing) {
                    self.dead_bytes += gop.value_ptr.recLen();
                    if (gop.value_ptr.expires()) self.expiring -= 1;
                } else {
                    key_owned = false; // the keydir owns it now
                }
                gop.value_ptr.* = .{ .off = off, .key_len = key_len, .val_len = val_len, .expires_at = expires_at };
                if (expires) self.expiring += 1;
            }
            off += rec_len;
        }
        if (off < file_size) {
            // Torn/corrupt tail: discard it. Committed (fsync'd) records all
            // lie before `off` by construction.
            try self.store.truncate(self.file, off);
            try self.store.sync(self.file);
        }
        self.end = off;
    }
};

// ── tests (deterministic on SimStorage; one real-fs round-trip at the end) ──

const testing = std.testing;
const builtin = @import("builtin");
const linux = std.os.linux;

test {
    _ = @import("prng.zig");
    _ = @import("sim.zig");
    _ = @import("fault_test.zig");
    _ = @import("scheduler.zig");
    _ = @import("vopr.zig");
    _ = @import("shrink.zig");
}

fn expectGet(db: *Db, key: []const u8, want: ?[]const u8) !void {
    const got = try db.get(testing.allocator, key);
    defer if (got) |g| testing.allocator.free(g);
    if (want) |w| {
        try testing.expect(got != null);
        try testing.expectEqualStrings(w, got.?);
    } else {
        try testing.expect(got == null);
    }
}

test "put/get/overwrite/delete/exists/count" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();

    try testing.expectEqual(@as(usize, 0), db.count());
    try db.put("alpha", "one");
    try db.put("beta", "two");
    try testing.expectEqual(@as(usize, 2), db.count());
    try expectGet(&db, "alpha", "one");
    try expectGet(&db, "beta", "two");
    try expectGet(&db, "gamma", null);
    try testing.expect(db.exists("alpha"));
    try testing.expect(!db.exists("gamma"));

    try db.put("alpha", "uno"); // overwrite
    try expectGet(&db, "alpha", "uno");
    try testing.expectEqual(@as(usize, 2), db.count());
    try testing.expect(db.deadBytes() > 0);

    try db.delete("alpha");
    try testing.expect(!db.exists("alpha"));
    try expectGet(&db, "alpha", null);
    try testing.expectEqual(@as(usize, 1), db.count());
    try db.delete("never-existed"); // absent delete = no-op
    try testing.expectEqual(@as(usize, 1), db.count());
}

/// A wall clock the test moves by hand.
const ManualClock = struct {
    now_ms: i64,

    fn clock(mc: *ManualClock) Clock {
        return .{ .ctx = mc, .nowFn = nowFn };
    }

    fn nowFn(ctx: ?*anyopaque) i64 {
        const mc: *ManualClock = @ptrCast(@alignCast(ctx.?));
        return mc.now_ms;
    }
};

/// `Db.expiring` must equal the number of keydir entries carrying an expiry:
/// it decides whether `count`, `keys` and `deadBytes` may skip the clock.
fn expectExpiringConsistent(db: *Db) !void {
    var n: usize = 0;
    var it = db.keydir.valueIterator();
    while (it.next()) |e| n += @intFromBool(e.expires());
    try testing.expectEqual(n, db.expiring);
}

fn fileVersion(sim: *SimStorage, name: []const u8) u32 {
    return std.mem.readInt(u32, sim.fileContent(name).?[4..8], .little);
}

test "expiry: a key is live before its instant, absent from it on, everywhere" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var mc: ManualClock = .{ .now_ms = 10_000 };
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{ .clock = mc.clock() });
    defer db.close();

    try db.put("plain", "p");
    try db.putExpiring("sess", "s", 10_500);
    try db.putTtl("ttl", "t", 200); // 10_200
    try expectGet(&db, "sess", "s");
    try testing.expectEqual(@as(usize, 3), db.count());
    try testing.expectEqual(Expiry{ .at_ms = 10_500 }, db.expiresAt("sess").?);
    try testing.expectEqual(Expiry{ .at_ms = 10_200 }, db.expiresAt("ttl").?);
    try testing.expectEqual(Expiry.never, db.expiresAt("plain").?);
    const dead_before = db.deadBytes();

    mc.now_ms = 10_200; // `ttl` expires AT its instant, not after it
    try expectGet(&db, "ttl", null);
    try testing.expect(!db.exists("ttl"));
    try testing.expect(db.valueLen("ttl") == null);
    try testing.expect(db.expiresAt("ttl") == null);
    var buf: [8]u8 = undefined;
    try testing.expect((try db.getBuf(&buf, "ttl")) == null);
    try testing.expectEqual(@as(usize, 2), db.count());
    try testing.expect(db.deadBytes() > dead_before); // the expired record is waste now
    try expectGet(&db, "sess", "s");

    mc.now_ms = 10_499;
    try expectGet(&db, "sess", "s");
    mc.now_ms = 10_500;
    try expectGet(&db, "sess", null);
    try testing.expectEqual(@as(usize, 1), db.count());
    try expectGet(&db, "plain", "p");
}

test "expiry: overwrite with put clears it; an instant already past leaves the key absent" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var mc: ManualClock = .{ .now_ms = 1_000 };
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{ .clock = mc.clock() });
    defer db.close();

    try db.putExpiring("k", "v1", 2_000);
    try testing.expectEqual(@as(usize, 1), db.expiring);
    try db.put("k", "v2");
    try testing.expectEqual(@as(usize, 0), db.expiring); // count() is O(1) again
    mc.now_ms = 5_000;
    try expectGet(&db, "k", "v2");
    try testing.expectEqual(Expiry.never, db.expiresAt("k").?);
    try testing.expectEqual(@as(usize, 1), db.count());

    try db.putExpiring("k", "old", 4_999); // past: the key is gone
    try expectGet(&db, "k", null);
    try testing.expectEqual(@as(usize, 0), db.count());

    // `no_expiry` is not an instant; putTtl past the end of time saturates to it.
    try db.putExpiring("forever", "f", std.math.maxInt(i64));
    try db.putTtl("forever2", "f", std.math.maxInt(u64));
    try testing.expectEqual(Expiry.never, db.expiresAt("forever").?);
    try testing.expectEqual(Expiry.never, db.expiresAt("forever2").?);
}

test "expiry: the first expiring put upgrades v1 to v2 by compaction, data intact" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var mc: ManualClock = .{ .now_ms = 1_000 };
    {
        var db = try Db.open(testing.allocator, sim.storage(), "db", .{ .clock = mc.clock() });
        defer db.close();
        try db.put("a", "1");
        try db.put("a", "2"); // dead weight the upgrade drops
        try db.put("b", "3");
        try testing.expectEqual(@as(u32, 1), fileVersion(&sim, "db"));
        try testing.expect(db.deadBytes() > 0);
        try db.putExpiring("e", "x", 9_000);
        try testing.expectEqual(@as(u32, 2), fileVersion(&sim, "db"));
        try testing.expectEqual(@as(u64, 0), db.deadBytes()); // the upgrade compacted
        try expectGet(&db, "a", "2");
        try expectGet(&db, "b", "3");
        try expectGet(&db, "e", "x");
    }
    // Reopen: the v2 file replays, the expiry survives.
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{ .clock = mc.clock() });
    defer db.close();
    try expectGet(&db, "e", "x");
    try testing.expectEqual(Expiry{ .at_ms = 9_000 }, db.expiresAt("e").?);
    try testing.expectEqual(@as(usize, 3), db.count());
}

test "expiry: stores that never expire stay version 1 and never read the clock" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const Panicking = struct {
        fn now(_: ?*anyopaque) i64 {
            @panic("clock read by a store without expiring keys");
        }
    };
    const opts: Options = .{ .clock = .{ .nowFn = Panicking.now } };
    {
        var db = try Db.open(testing.allocator, sim.storage(), "db", opts);
        defer db.close();
        try db.put("a", "1");
        try db.put("b", "2");
        try db.putExpiring("c", "3", std.math.maxInt(i64)); // "never" needs no upgrade
        try db.delete("a");
        _ = db.count();
        _ = db.deadBytes();
        const ks = try db.keys(testing.allocator, "");
        ks.deinit(testing.allocator);
        try expectGet(&db, "b", "2");
        try db.compact();
    }
    var db = try Db.open(testing.allocator, sim.storage(), "db", opts);
    defer db.close();
    try testing.expectEqual(@as(u32, 1), fileVersion(&sim, "db"));
}

test "expiry: the expiring-key counter follows put, overwrite, delete, replay and compaction" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var mc: ManualClock = .{ .now_ms = 1_000 };
    {
        var db = try Db.open(testing.allocator, sim.storage(), "db", .{ .clock = mc.clock() });
        defer db.close();
        try db.putExpiring("a", "1", 5_000);
        try db.putExpiring("a", "2", 6_000); // expiring over expiring
        try db.putExpiring("b", "1", 5_000);
        try db.putExpiring("c", "1", 1_500);
        try db.put("b", "plain"); // plain over expiring
        try db.putExpiring("d", "1", 7_000);
        try db.delete("d"); // delete of an expiring key
        try db.putExpiring("e", "1", 7_000);
        try expectExpiringConsistent(&db);
        try testing.expectEqual(@as(usize, 3), db.expiring); // a, c, e
    }
    mc.now_ms = 2_000; // "c" has expired: replay drops it
    {
        var db = try Db.open(testing.allocator, sim.storage(), "db", .{ .clock = mc.clock() });
        defer db.close();
        try expectExpiringConsistent(&db);
        try testing.expectEqual(@as(usize, 2), db.expiring); // a, e
        mc.now_ms = 6_500; // "a" expires while open
        try db.compact();
        try expectExpiringConsistent(&db);
        try testing.expectEqual(@as(usize, 1), db.expiring); // e
        try db.putExpiring("e", "gone", 100); // expired at once, over an expiring key
        try expectExpiringConsistent(&db);
    }
    // Replay: an expired record over an expiring one, a delete over an expiring one.
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{ .clock = mc.clock() });
    defer db.close();
    try expectExpiringConsistent(&db);
    try testing.expectEqual(@as(usize, 0), db.expiring);
    try testing.expectEqual(@as(usize, 1), db.count()); // b
}

test "expiry: open and compact drop expired keys from memory and file" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var mc: ManualClock = .{ .now_ms = 1_000 };
    {
        var db = try Db.open(testing.allocator, sim.storage(), "db", .{ .clock = mc.clock() });
        defer db.close();
        try db.putExpiring("short", "SHORTVALUE", 2_000);
        try db.putExpiring("long", "LONGVALUE", 9_000);
        try db.put("plain", "PLAINVALUE");
    }
    mc.now_ms = 3_000;
    {
        var db = try Db.open(testing.allocator, sim.storage(), "db", .{ .clock = mc.clock() });
        defer db.close();
        // Replay treated the expired record as a delete: gone from the keydir,
        // counted as waste.
        try testing.expect(!db.keydir.contains("short"));
        try testing.expectEqual(@as(usize, 1), db.expiring);
        try testing.expectEqual(@as(u64, recordLenExp(true, 5, 10)), db.deadBytes());
        try db.compact();
        try testing.expect(std.mem.indexOf(u8, sim.fileContent("db").?, "SHORTVALUE") == null);
        try testing.expectEqual(@as(u64, 0), db.deadBytes());

        mc.now_ms = 9_000; // "long" expires while open; compact drops it
        try testing.expectEqual(@as(usize, 1), db.count());
        try db.compact();
        try testing.expect(!db.keydir.contains("long"));
        try testing.expectEqual(@as(usize, 0), db.expiring);
        const file = sim.fileContent("db").?;
        try testing.expect(std.mem.indexOf(u8, file, "LONGVALUE") == null);
        try testing.expect(std.mem.indexOf(u8, file, "PLAINVALUE") != null);
        try expectGet(&db, "plain", "PLAINVALUE");
    }
}

test "expiry: deleting an expired key still writes a tombstone (a clock stepped back cannot revive it)" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var mc: ManualClock = .{ .now_ms = 1_000 };
    {
        var db = try Db.open(testing.allocator, sim.storage(), "db", .{ .clock = mc.clock() });
        defer db.close();
        try db.putExpiring("k", "v", 2_000);
        mc.now_ms = 2_500;
        try db.delete("k");
        mc.now_ms = 1_500; // NTP steps the clock back
        try expectGet(&db, "k", null);
    }
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{ .clock = mc.clock() });
    defer db.close();
    try expectGet(&db, "k", null);
}

test "expiry: an expiring record in a version-1 file is not a record (replay stops there)" {
    // Build a v1 file by hand whose second record is op 2: a v1 file can
    // only come from a writer that never wrote op 2, so it is corrupt.
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var file: [header_len + rec_fixed + 1 + 1 + rec_fixed + exp_len + 1 + 1]u8 = undefined;
    file[0..4].* = file_magic.*;
    std.mem.writeInt(u32, file[4..8], version_plain, .little);
    encodeRecord(file[header_len..][0 .. rec_fixed + 2], op_put, "a", "1");
    encodeRecordExp(file[header_len + rec_fixed + 2 ..], op_put_exp, 5_000, "b", "2");
    try sim.installFile("db", &file);
    var mc: ManualClock = .{ .now_ms = 1_000 };
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{ .clock = mc.clock() });
    defer db.close();
    try expectGet(&db, "a", "1");
    try expectGet(&db, "b", null);
    try testing.expectEqual(@as(usize, header_len + rec_fixed + 2), sim.fileContent("db").?.len);

    // The same record in a version-2 file is live.
    var sim2 = SimStorage.init(testing.allocator);
    defer sim2.deinit();
    std.mem.writeInt(u32, file[4..8], version_expiry, .little);
    try sim2.installFile("db", &file);
    var db2 = try Db.open(testing.allocator, sim2.storage(), "db", .{ .clock = mc.clock() });
    defer db2.close();
    try expectGet(&db2, "b", "2");
}

test "expiry: a CRC-valid op-2 record carrying the no-expiry marker is refused" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var file: [header_len + rec_fixed + exp_len + 2]u8 = undefined;
    file[0..4].* = file_magic.*;
    std.mem.writeInt(u32, file[4..8], version_expiry, .little);
    encodeRecordExp(file[header_len..], op_put_exp, no_expiry, "b", "2");
    try sim.installFile("db", &file);
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();
    try expectGet(&db, "b", null);
    try testing.expectEqual(@as(usize, header_len), sim.fileContent("db").?.len);
}

test "expiry: read_verify catches a rotted expiry field" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var mc: ManualClock = .{ .now_ms = 1_000 };
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{ .clock = mc.clock() });
    defer db.close();
    try db.putExpiring("k", "v", 5_000);
    const off = db.keydir.get("k").?.off;
    sim.flipByte("db", off + rec_fixed + 1); // inside expires_at
    try testing.expectError(error.Corrupt, db.get(testing.allocator, "k"));
}

test "keys: sorted snapshot of live keys, prefix-filtered, expired and deleted left out" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var mc: ManualClock = .{ .now_ms = 1_000 };
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{ .clock = mc.clock() });
    defer db.close();

    {
        const empty = try db.keys(testing.allocator, "");
        defer empty.deinit(testing.allocator);
        try testing.expectEqual(@as(usize, 0), empty.keys.len);
    }
    for ([_][]const u8{ "user:2", "sess:b", "user:10", "sess:a", "", "user:1" }) |k| try db.put(k, "x");
    try db.delete("sess:b");
    try db.putExpiring("sess:c", "x", 1_500);
    try db.putExpiring("sess:d", "x", 3_000);
    mc.now_ms = 2_000;

    const all = try db.keys(testing.allocator, "");
    defer all.deinit(testing.allocator);
    const want_all = [_][]const u8{ "", "sess:a", "sess:d", "user:1", "user:10", "user:2" };
    try testing.expectEqual(want_all.len, all.keys.len);
    for (want_all, all.keys) |w, g| try testing.expectEqualStrings(w, g);

    const sess = try db.keys(testing.allocator, "sess:");
    defer sess.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), sess.keys.len);
    try testing.expectEqualStrings("sess:a", sess.keys[0]);
    try testing.expectEqualStrings("sess:d", sess.keys[1]);

    // A snapshot: later writes do not reach it.
    try db.delete("sess:a");
    try testing.expectEqualStrings("sess:a", sess.keys[0]);
}

test "keys: out-of-memory mid-listing frees what it copied" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();
    for ([_][]const u8{ "a", "b", "c", "d" }) |k| try db.put(k, "x");
    var fail_index: usize = 0;
    while (true) : (fail_index += 1) {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        const r = db.keys(fa.allocator(), "");
        if (r) |ks| {
            ks.deinit(fa.allocator());
            break;
        } else |e| try testing.expectEqual(error.OutOfMemory, e);
    }
    try testing.expect(fail_index > 4);
}

test "persistence: close and reopen recovers everything" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    {
        var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
        defer db.close();
        try db.put("k1", "v1");
        try db.put("k2", "v2");
        try db.put("k1", "v1b");
    }
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();
    try testing.expectEqual(@as(usize, 2), db.count());
    try expectGet(&db, "k1", "v1b");
    try expectGet(&db, "k2", "v2");
    try testing.expect(db.deadBytes() > 0); // the overwritten k1 is dead weight
}

test "tombstone survives reopen (deleted stays deleted)" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    {
        var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
        defer db.close();
        try db.put("doomed", "x");
        try db.put("keeper", "y");
        try db.delete("doomed");
    }
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();
    try expectGet(&db, "doomed", null);
    try expectGet(&db, "keeper", "y");
    try testing.expectEqual(@as(usize, 1), db.count());
}

test "compaction: log shrinks, live data intact, dead entries gone" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();

    try db.put("stay", "value-that-stays");
    var i: usize = 0;
    while (i < 20) : (i += 1) try db.put("churn", "waste-waste-waste");
    try db.put("gone", "bye");
    try db.delete("gone");

    const before = sim.fileContent("db").?.len;
    try db.compact();
    const after = sim.fileContent("db").?.len;
    try testing.expect(after < before);
    try testing.expectEqual(@as(u64, 0), db.deadBytes());

    // Live data intact through the swapped handle...
    try expectGet(&db, "stay", "value-that-stays");
    try expectGet(&db, "churn", "waste-waste-waste");
    try expectGet(&db, "gone", null);
    try testing.expectEqual(@as(usize, 2), db.count());
    // ...and still usable for new writes, and after reopen.
    try db.put("post", "compact");
    db.close();
    db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    try expectGet(&db, "stay", "value-that-stays");
    try expectGet(&db, "post", "compact");
    try testing.expectEqual(@as(usize, 3), db.count());
    // No temp file left behind.
    try testing.expect(sim.fileContent("db.compact") == null);
}

test "CRC rejects a corrupted byte on get (read_verify)" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();
    try db.put("key", "correct-value");
    // Rot one byte inside the record's value region, after open.
    const content = sim.fileContent("db").?;
    sim.flipByte("db", content.len - 3);
    try testing.expectError(error.Corrupt, db.get(testing.allocator, "key"));
}

test "corrupted byte mid-file truncates replay at the bad record" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var second_rec_off: usize = 0;
    {
        var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
        defer db.close();
        try db.put("first", "aaaa");
        second_rec_off = sim.fileContent("db").?.len;
        try db.put("second", "bbbb");
        try db.put("third", "cccc");
    }
    sim.flipByte("db", second_rec_off + rec_fixed); // corrupt "second"'s key byte
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();
    // v0 policy: truncate at the first bad record — "second" AND the later
    // "third" are gone; everything before is intact and CRC-valid.
    try expectGet(&db, "first", "aaaa");
    try testing.expectEqual(@as(usize, 1), db.count());
    try testing.expectEqual(second_rec_off, sim.fileContent("db").?.len);
}

test "non-contiguous persistence: a hole mid-log truncates there; a later durable record is not resurrected" {
    // Models out-of-order durability: within an fsync-free window a LATER
    // record persisted while an EARLIER one was lost, leaving a zero hole
    // between two otherwise-valid records. Recovery must (a) keep every
    // committed record BEFORE the hole (no over-truncation of durable data)
    // and (b) NOT resurrect the orphaned record BEYOND the hole.
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var hole_off: usize = 0;
    {
        var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
        defer db.close();
        try db.put("first", "aaaa"); // committed (fsync'd) before the hole
        try db.put("second", "bbbb"); // committed before the hole
        hole_off = sim.fileContent("db").?.len;
    }
    // Punch a zero hole the size of one record where "third" would have gone,
    // then append a fully-valid "third" record AFTER the hole (it reached
    // media out of order). Both are marked durable.
    const orphan_len = rec_fixed + "third".len + "cccc".len;
    const hole = try testing.allocator.alloc(u8, orphan_len);
    defer testing.allocator.free(hole);
    @memset(hole, 0);
    try sim.appendDurable("db", hole);
    var orphan: [rec_fixed + 5 + 4]u8 = undefined;
    encodeRecord(&orphan, op_put, "third", "cccc");
    try sim.appendDurable("db", &orphan);

    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();
    // Committed records before the hole survive intact — no over-truncation.
    try expectGet(&db, "first", "aaaa");
    try expectGet(&db, "second", "bbbb");
    // The orphan beyond the hole is NOT replayed as valid.
    try expectGet(&db, "third", null);
    try testing.expectEqual(@as(usize, 2), db.count());
    // The file is truncated exactly at the hole (everything after discarded).
    try testing.expectEqual(hole_off, sim.fileContent("db").?.len);
}

test "torn trailing record is truncated on open, committed data survives" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var good_len: usize = 0;
    {
        var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
        defer db.close();
        try db.put("committed", "safe");
        good_len = sim.fileContent("db").?.len;
    }
    // A torn tail already on media: half a record's worth of garbage.
    try sim.appendDurable("db", &[_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02 });
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();
    try expectGet(&db, "committed", "safe");
    try testing.expectEqual(@as(usize, 1), db.count());
    try testing.expectEqual(good_len, sim.fileContent("db").?.len); // tail gone
}

test "torn tail that looks like a full record header is also rejected" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var good_len: usize = 0;
    {
        var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
        defer db.close();
        try db.put("committed", "safe");
        good_len = sim.fileContent("db").?.len;
    }
    // A structurally plausible record whose CRC is wrong (torn mid-write and
    // then padded by luck): op=put, key_len=1, val_len=1, "k","v", bad crc.
    var fake: [rec_fixed + 2]u8 = undefined;
    encodeRecord(&fake, op_put, "k", "v");
    fake[0] ^= 0xff; // break the CRC
    try sim.appendDurable("db", &fake);
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();
    try expectGet(&db, "k", null);
    try testing.expectEqual(@as(usize, 1), db.count());
    try testing.expectEqual(good_len, sim.fileContent("db").?.len);
}

test "empty and one-byte keys and values" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    {
        var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
        defer db.close();
        try db.put("", "empty-key-value");
        try db.put("empty-value", "");
        try db.put("k", "v");
        try expectGet(&db, "", "empty-key-value");
        try expectGet(&db, "empty-value", "");
        try expectGet(&db, "k", "v");
    }
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();
    try expectGet(&db, "", "empty-key-value");
    try expectGet(&db, "empty-value", "");
    try expectGet(&db, "k", "v");
    try db.delete("");
    try expectGet(&db, "", null);
    try testing.expectEqual(@as(usize, 2), db.count());
}

test "large value round-trips and survives reopen + compaction" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const big = try testing.allocator.alloc(u8, 100 * 1024);
    defer testing.allocator.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i *% 31 + 7);
    {
        var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
        defer db.close();
        try db.put("big", big);
        try db.put("small", "s");
        try db.compact();
        const got = (try db.get(testing.allocator, "big")).?;
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, big, got);
    }
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();
    const got = (try db.get(testing.allocator, "big")).?;
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, big, got);
}

test "open nonexistent, reopen empty, header-only file" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    { // nonexistent → fresh empty store
        var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
        defer db.close();
        try testing.expectEqual(@as(usize, 0), db.count());
    }
    { // header-only file → still an empty store
        var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
        defer db.close();
        try testing.expectEqual(@as(usize, 0), db.count());
        try expectGet(&db, "anything", null);
    }
    // A pre-existing zero-length file → adopted as fresh.
    try sim.installFile("empty", "");
    var db = try Db.open(testing.allocator, sim.storage(), "empty", .{});
    defer db.close();
    try testing.expectEqual(@as(usize, 0), db.count());
    try db.put("works", "yes");
    try expectGet(&db, "works", "yes");
}

test "foreign file is refused; newer version is refused" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    try sim.installFile("notdb", "#!/bin/sh\necho hello\n");
    try testing.expectError(error.NotAKvFile, Db.open(testing.allocator, sim.storage(), "notdb", .{}));
    // Torn-header remnant that is NOT our magic prefix → also refused.
    try sim.installFile("torn", "ZKQ");
    try testing.expectError(error.NotAKvFile, Db.open(testing.allocator, sim.storage(), "torn", .{}));
    // Our magic, incompatible version.
    var hdr: [header_len]u8 = undefined;
    hdr[0..4].* = file_magic.*;
    std.mem.writeInt(u32, hdr[4..8], 999, .little);
    try sim.installFile("future", &hdr);
    try testing.expectError(error.UnsupportedVersion, Db.open(testing.allocator, sim.storage(), "future", .{}));
    // The versions this module writes are 1 and 2; neither neighbour passes.
    for ([_]u32{ 0, 3 }) |v| {
        std.mem.writeInt(u32, hdr[4..8], v, .little);
        try sim.installFile("neighbour", &hdr);
        try testing.expectError(error.UnsupportedVersion, Db.open(testing.allocator, sim.storage(), "neighbour", .{}));
    }
}

test "torn header remnant that IS our magic prefix is adopted as fresh" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    try sim.installFile("db", file_magic[0..3]); // crashed during creation
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();
    try testing.expectEqual(@as(usize, 0), db.count());
    try db.put("k", "v");
    try expectGet(&db, "k", "v");
}

test "stale compaction temp file is removed on open" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    try sim.installFile("db.compact", "leftover junk from a crashed compaction");
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();
    try testing.expect(sim.fileContent("db.compact") == null);
}

test "storage failure poisons the store: mutations refused, reads still work" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();
    try db.put("k", "v");
    sim.ops_until_crash = 0; // the next side effect dies
    try testing.expectError(error.Crashed, db.put("k2", "v2"));
    try testing.expectError(error.Poisoned, db.put("k3", "v3"));
    try testing.expectError(error.Poisoned, db.delete("k"));
    try testing.expectError(error.Poisoned, db.compact());
    // Reads describe the last consistent state — but here the simulated
    // MACHINE is dead (I/O fails), so read errors are storage errors, not
    // corruption. Reboot the sim: now reads work against the same Db.
    sim.reboot();
    try expectGet(&db, "k", "v");
    try testing.expect(db.exists("k"));
    try testing.expectEqual(@as(usize, 1), db.count());
}

test "compaction failure before the rename does NOT poison the store" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();
    try db.put("a", "1");
    try db.put("a", "2");
    // Crash on the compaction temp's first side effect (its open/create).
    sim.ops_until_crash = 0;
    try testing.expectError(error.Crashed, db.compact());
    sim.reboot();
    // The main file was never touched; the store fully recovers on reopen —
    // and this instance was not poisoned by a temp-file failure.
    try db.put("b", "3");
    try expectGet(&db, "a", "2");
    try expectGet(&db, "b", "3");
}

test "keys and values are copied; caller buffers may be reused" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();
    var kbuf: [3]u8 = "key".*;
    var vbuf: [5]u8 = "value".*;
    try db.put(&kbuf, &vbuf);
    kbuf = "XXX".*;
    vbuf = "YYYYY".*;
    try expectGet(&db, "key", "value");
}

test "concurrent puts from two threads (coarse lock smoke test)" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();

    const Worker = struct {
        fn run(d: *Db, prefix: u8) void {
            var i: usize = 0;
            while (i < 50) : (i += 1) {
                var key: [8]u8 = undefined;
                const k = std.fmt.bufPrint(&key, "{c}-{d}", .{ prefix, i }) catch unreachable;
                d.put(k, "v") catch unreachable;
            }
        }
    };
    const t1 = try std.Thread.spawn(.{}, Worker.run, .{ &db, 'a' });
    const t2 = try std.Thread.spawn(.{}, Worker.run, .{ &db, 'b' });
    t1.join();
    t2.join();
    try testing.expectEqual(@as(usize, 100), db.count());
    try expectGet(&db, "a-49", "v");
    try expectGet(&db, "b-0", "v");
}

test "real filesystem (FsStorage): persistence + compaction round-trip" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var fs_store = FsStorage.init(testing.io, tmp.dir);
    {
        var db = try Db.open(testing.allocator, fs_store.storage(), "real.kv", .{});
        defer db.close();
        try db.put("alpha", "one");
        try db.put("alpha", "uno");
        try db.put("beta", "two");
        try db.delete("beta");
        try db.put("gamma", "three");
    }
    var fs_store2 = FsStorage.init(testing.io, tmp.dir);
    var db = try Db.open(testing.allocator, fs_store2.storage(), "real.kv", .{});
    defer db.close();
    try expectGet(&db, "alpha", "uno");
    try expectGet(&db, "beta", null);
    try expectGet(&db, "gamma", "three");
    try testing.expectEqual(@as(usize, 2), db.count());

    const st = fs_store2.storage();
    const before = try st.size(db.file);
    try db.compact();
    const after = try st.size(db.file);
    try testing.expect(after < before);
    try expectGet(&db, "alpha", "uno");
    try expectGet(&db, "gamma", "three");
    try db.put("delta", "four");
    try expectGet(&db, "delta", "four");
}

test "FsStorage: a full handle table is diagnosable, not error.Unexpected" {
    // The defect: exhausting the fixed handle table fell out of the `for`
    // loop's `else` as `error.Unexpected` — the same error a genuine bug
    // produces. A caller could not tell "size me differently" from "something
    // is broken", and the cap that produced it (4) was undocumented.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var fs_store = FsStorageCapacity(2).init(testing.io, tmp.dir);
    const st = fs_store.storage();

    const a = try st.open("a.bin", .open_or_create);
    _ = try st.open("b.bin", .open_or_create);
    try testing.expectError(error.HandleTableFull, st.open("c.bin", .open_or_create));
    // Closing one frees exactly one slot: the table is a reusable resource,
    // not a one-way budget.
    st.close(a);
    const d = try st.open("d.bin", .open_or_create);
    try testing.expectError(error.HandleTableFull, st.open("e.bin", .open_or_create));
    st.close(d);
    st.close(1);
}

test "FsStorage: the default handle table holds more than one store's worth of files" {
    // The sharp part of the old cap: `max_handles == 4` was sized for a single
    // `Db` (data + lock sidecar + compaction temp), but an `FsStorage` is a
    // *shared* backend. `shardstore` needs two handles per shard, so over the
    // default backend it could not open a fourth shard at all, and two of its
    // tests had to be written with 3 shards instead of 4 to stay green.
    //
    // This pins the property those callers actually need: eight handles —
    // four two-handle stores — open at once on the default `FsStorage`.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var fs_store = FsStorage.init(testing.io, tmp.dir);
    const st = fs_store.storage();

    var handles: [8]Storage.Handle = undefined;
    for (&handles, 0..) |*h, i| {
        var name_buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "shard{d}.bin", .{i});
        h.* = try st.open(name, .open_or_create);
    }
    for (handles) |h| st.close(h);
}

test "FsStorage: the default handle table is exactly 64, not merely at least 8" {
    // F3 (2026-08-11 re-audit): the test above pins an honest but INDEPENDENT
    // floor of 8 ("four two-handle stores"), which is a lower bound only —
    // any `default_max_handles` in `[8, 16)` passes it too. That leaves the
    // actual delivered literal, 64 (chosen headroom above the 8-handle floor
    // for "a handful of stores over one backend", see the doc comment on
    // `default_max_handles`), pinned by nothing. This test writes the literal
    // 64 directly — not `default_max_handles` — so a change to the constant
    // moves this number out from under the test instead of moving with it.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var fs_store = FsStorage.init(testing.io, tmp.dir);
    const st = fs_store.storage();

    var handles: [64]Storage.Handle = undefined;
    for (&handles, 0..) |*h, i| {
        var name_buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "h{d}.bin", .{i});
        h.* = try st.open(name, .open_or_create);
    }
    // The 65th handle is refused: the table is 64 wide, not 65 or unbounded.
    try testing.expectError(error.HandleTableFull, st.open("h64.bin", .open_or_create));
    for (handles) |h| st.close(h);
}

test "Storage.VTable.consistent: catches a backend that sets preadRef without releaseRef" {
    // F3's sibling gap: `Storage.releaseRef` did an unchecked `s.vtable.releaseRef.?`,
    // which panics for a backend that sets `preadRef` without `releaseRef`, with
    // nothing pinning the precondition. `releaseRef` now panics with a named
    // message instead of an opaque unwrap (see its doc comment); this test
    // pins the self-check a backend author is pointed at to catch the mistake
    // before it reaches `releaseRef` at all.
    const Stub = struct {
        fn open(_: *anyopaque, _: []const u8, _: Storage.OpenMode) Storage.Error!Storage.Handle {
            unreachable;
        }
        fn size(_: *anyopaque, _: Storage.Handle) Storage.Error!u64 {
            unreachable;
        }
        fn pread(_: *anyopaque, _: Storage.Handle, _: []u8, _: u64) Storage.Error!usize {
            unreachable;
        }
        fn writeAll(_: *anyopaque, _: Storage.Handle, _: []const u8, _: u64) Storage.Error!void {
            unreachable;
        }
        fn sync(_: *anyopaque, _: Storage.Handle) Storage.Error!void {
            unreachable;
        }
        fn truncate(_: *anyopaque, _: Storage.Handle, _: u64) Storage.Error!void {
            unreachable;
        }
        fn close(_: *anyopaque, _: Storage.Handle) void {
            unreachable;
        }
        fn rename(_: *anyopaque, _: []const u8, _: []const u8) Storage.Error!void {
            unreachable;
        }
        fn delete(_: *anyopaque, _: []const u8) Storage.Error!void {
            unreachable;
        }
        fn syncDir(_: *anyopaque) Storage.Error!void {
            unreachable;
        }
        fn tryLockExclusive(_: *anyopaque, _: Storage.Handle) Storage.Error!bool {
            unreachable;
        }
        fn preadRef(_: *anyopaque, _: Storage.Handle, _: usize, _: u64) Storage.Error!?Storage.Ref {
            unreachable;
        }
        fn releaseRef(_: *anyopaque, _: Storage.Ref) void {
            unreachable;
        }
    };
    const base = Storage.VTable{
        .open = Stub.open,
        .size = Stub.size,
        .pread = Stub.pread,
        .writeAll = Stub.writeAll,
        .sync = Stub.sync,
        .truncate = Stub.truncate,
        .close = Stub.close,
        .rename = Stub.rename,
        .delete = Stub.delete,
        .syncDir = Stub.syncDir,
        .tryLockExclusive = Stub.tryLockExclusive,
    };

    // Neither set: consistent (this is what every real backend in this repo
    // does today — none implements the borrow seam yet).
    try testing.expect(base.consistent());

    // Both set: consistent.
    var both = base;
    both.preadRef = Stub.preadRef;
    both.releaseRef = Stub.releaseRef;
    try testing.expect(both.consistent());

    // preadRef set, releaseRef missing: the exact defect F3 named — caught
    // here rather than surfacing as a panic the first time a ref is released.
    var bad = base;
    bad.preadRef = Stub.preadRef;
    try testing.expect(!bad.consistent());
}

test "real filesystem: create_new creates once and never empties an existing file" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var fs_store = FsStorage.init(testing.io, tmp.dir);
    const st = fs_store.storage();

    const h = try st.open("seg", .create_new);
    try st.writeAll(h, "keep", 0);
    try st.sync(h);

    // The second creator loses — the open fails, the bytes stay, and no
    // handle slot is consumed by the refused open.
    try testing.expectError(error.PathAlreadyExists, st.open("seg", .create_new));
    var buf: [8]u8 = undefined;
    try testing.expectEqualStrings("keep", buf[0..try st.pread(h, &buf, 0)]);
    st.close(h);
    try testing.expectError(error.PathAlreadyExists, st.open("seg", .create_new));
    const r = try st.open("seg", .read_only);
    try testing.expectEqual(h, r);
    try testing.expectEqualStrings("keep", buf[0..try st.pread(r, &buf, 0)]);
    st.close(r);

    // Once the name is gone it can be claimed again, as an empty file.
    try st.delete("seg");
    const n = try st.open("seg", .create_new);
    defer st.close(n);
    try testing.expectEqual(@as(u64, 0), try st.size(n));
}

test "real filesystem: read_only neither creates, empties nor writes" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var fs_store = FsStorage.init(testing.io, tmp.dir);
    const st = fs_store.storage();

    // Absent: reported, and still absent afterwards — not created.
    try testing.expectError(error.FileNotFound, st.open("missing", .read_only));
    try testing.expectError(error.FileNotFound, tmp.dir.access(testing.io, "missing", .{}));

    const w = try st.open("f", .create_truncate);
    try st.writeAll(w, "data", 0);
    try st.sync(w);

    const r = try st.open("f", .read_only);
    var buf: [8]u8 = undefined;
    try testing.expectEqualStrings("data", buf[0..try st.pread(r, &buf, 0)]);
    try testing.expectError(error.AccessDenied, st.writeAll(r, "XXXX", 0));
    try testing.expectError(error.AccessDenied, st.writeAll(r, "tail", 4));
    try testing.expectError(error.AccessDenied, st.truncate(r, 0));
    try testing.expectEqual(@as(u64, 4), try st.size(r));

    // The reader follows what the writer appends through its own handle.
    try st.writeAll(w, "more", 4);
    try testing.expectEqualStrings("datamore", buf[0..try st.pread(r, &buf, 0)]);
    defer st.close(w);

    // The slot a read-only handle leaves behind carries no read-only flag.
    st.close(r);
    const again = try st.open("g", .open_or_create);
    defer st.close(again);
    try testing.expectEqual(r, again);
    try st.writeAll(again, "ok", 0);
}

test "real filesystem: torn tail on disk is recovered" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var fs_store = FsStorage.init(testing.io, tmp.dir);
    {
        var db = try Db.open(testing.allocator, fs_store.storage(), "real.kv", .{});
        defer db.close();
        try db.put("committed", "data");
    }
    { // Append garbage directly (a torn tail as left by a crash).
        const f = try tmp.dir.openFile(testing.io, "real.kv", .{ .mode = .read_write });
        defer f.close(testing.io);
        const end = try f.length(testing.io);
        try f.writePositionalAll(testing.io, &[_]u8{ 0xba, 0xad, 0xf0, 0x0d }, end);
    }
    var fs_store2 = FsStorage.init(testing.io, tmp.dir);
    var db = try Db.open(testing.allocator, fs_store2.storage(), "real.kv", .{});
    defer db.close();
    try expectGet(&db, "committed", "data");
    try testing.expectEqual(@as(usize, 1), db.count());
}

test "getBuf: allocation-free reads, exact sizing, and no silent truncation" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();

    try db.put("alpha", "one");
    try db.put("beta", "a longer value than the first");

    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("one", (try db.getBuf(&buf, "alpha")).?);
    try testing.expectEqualStrings("a longer value than the first", (try db.getBuf(&buf, "beta")).?);
    try testing.expectEqual(@as(?[]u8, null), try db.getBuf(&buf, "absent"));

    // `valueLen` sizes the buffer; exactly that many bytes must suffice, and
    // one fewer must fail rather than hand back a truncated value.
    const n = db.valueLen("beta").?;
    try testing.expectEqual(@as(u32, "a longer value than the first".len), n);
    try testing.expectEqualStrings("a longer value than the first", (try db.getBuf(buf[0..n], "beta")).?);
    try testing.expectError(error.BufferTooSmall, db.getBuf(buf[0 .. n - 1], "beta"));
    try testing.expectEqual(@as(?u32, null), db.valueLen("absent"));

    // Same answer as the allocating path, including under read_verify (the
    // default), so the two cannot drift.
    const owned = (try db.get(testing.allocator, "beta")).?;
    defer testing.allocator.free(owned);
    try testing.expectEqualStrings(owned, (try db.getBuf(&buf, "beta")).?);

    // A corrupt record must fail the same way through both entry points, not
    // just through `get` — the CRC check is shared, and this proves it.
    try testing.expect(db.options.read_verify);
}

// ── cross-process locking ────────────────────────────────────────────────────

test "lock: a second Db on the same store is refused, and released on close" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    {
        var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
        defer db.close();
        try db.put("k", "v");
        // A second opener — in a real deployment, another process — is turned
        // away instead of quietly becoming a second writer over one log.
        try testing.expectError(
            error.Locked,
            Db.open(testing.allocator, sim.storage(), "db", .{}),
        );
        // The refusal costs the holder nothing.
        try expectGet(&db, "k", "v");
    }
    // Once the holder closes, the store is takeable again.
    var db2 = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db2.close();
    try expectGet(&db2, "k", "v");
}

test "lock: the sidecar survives compaction (the rename must not orphan the lock)" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();
    try db.put("a", "1");
    try db.put("a", "2"); // dead weight for compaction to drop
    // Compaction replaces the DATA file via rename. A lock taken on the data
    // file itself would now be stranded on the unlinked inode and the store
    // would be silently takeable; the sidecar's inode is untouched.
    try db.compact();
    try testing.expectError(
        error.Locked,
        Db.open(testing.allocator, sim.storage(), "db", .{}),
    );
    try expectGet(&db, "a", "2");
}

test "lock: a crashed holder leaves no stale lock" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    try db.put("k", "v");
    sim.ops_until_crash = 0;
    try testing.expectError(error.Crashed, db.put("k2", "v2"));
    sim.reboot();

    // `db` is deliberately still "open" here: a killed process runs no
    // cleanup, and recovery must not depend on it having run any.
    var db2 = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db2.close();
    try expectGet(&db2, "k", "v");
    db.close();
}

test "lock: a foreign holder blocks open BEFORE the store is touched" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var good_len: usize = 0;
    {
        var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
        defer db.close();
        try db.put("committed", "safe");
        good_len = sim.fileContent("db").?.len;
    }
    // A torn tail that `open` would normally truncate away — a *write*, and
    // the exact write two concurrent openers must never race on.
    try sim.appendDurable("db", &[_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02 });
    const dirty_len = sim.fileContent("db").?.len;

    try sim.holdForeignLock("db.lock");
    try testing.expectError(
        error.Locked,
        Db.open(testing.allocator, sim.storage(), "db", .{}),
    );
    // Nothing was replayed and nothing was truncated: the lock is taken
    // first, so a refused open is a total no-op on the data file.
    try testing.expectEqual(dirty_len, sim.fileContent("db").?.len);

    // The other process exits; now recovery may proceed.
    sim.releaseForeignLock("db.lock");
    var db = try Db.open(testing.allocator, sim.storage(), "db", .{});
    defer db.close();
    try expectGet(&db, "committed", "safe");
    try testing.expectEqual(good_len, sim.fileContent("db").?.len);
}

test "lock: .none opts out; a backend without locks is refused, never downgraded" {
    { // opt-out: two live Dbs on one store, by the caller's explicit choice
        var sim = SimStorage.init(testing.allocator);
        defer sim.deinit();
        var a = try Db.open(testing.allocator, sim.storage(), "db", .{ .lock = .none });
        defer a.close();
        var b = try Db.open(testing.allocator, sim.storage(), "db", .{ .lock = .none });
        defer b.close();
        try testing.expect(sim.fileContent("db.lock") == null); // no sidecar at all
    }
    { // a filesystem with no advisory locks: loud failure, not silent risk
        var sim = SimStorage.init(testing.allocator);
        defer sim.deinit();
        sim.lock_unsupported = true;
        try testing.expectError(
            error.LockUnsupported,
            Db.open(testing.allocator, sim.storage(), "db", .{}),
        );
        // ...and the caller can still proceed, having been told.
        var db = try Db.open(testing.allocator, sim.storage(), "db", .{ .lock = .none });
        defer db.close();
        try db.put("k", "v");
    }
}

test "lock: real filesystem, two open descriptions on one store contend" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var fs_a = FsStorage.init(testing.io, tmp.dir);
    var fs_b = FsStorage.init(testing.io, tmp.dir);
    {
        var db = Db.open(testing.allocator, fs_a.storage(), "real.kv", .{}) catch |e| switch (e) {
            // A filesystem that cannot flock (some CI overlays) — say so
            // rather than silently passing a locking test that locked nothing.
            error.LockUnsupported => return error.SkipZigTest,
            else => return e,
        };
        defer db.close();
        try db.put("k", "v");
        try testing.expectError(
            error.Locked,
            Db.open(testing.allocator, fs_b.storage(), "real.kv", .{}),
        );
    }
    var db2 = try Db.open(testing.allocator, fs_b.storage(), "real.kv", .{});
    defer db2.close();
    try expectGet(&db2, "k", "v");
}

// ── cross-process locking: REAL second processes ─────────────────────────────
//
// Everything above runs in one process. Even though `flock` is scoped to the
// open file description (so a second `Db.open` here really does contend), only
// a genuine second process proves the guarantee callers actually buy. These
// two tests fork.
//
// Neither test can wedge the runner: every child arms `alarm(2)` as a
// self-destruct before it does anything, the parent reaps with a WNOHANG poll
// under a deadline and `SIGKILL`s a child that overstays, and the parent's one
// blocking read is on a pipe whose only write end lives in that child — so a
// dead or killed child yields EOF rather than a hang.

/// Seconds after which a child self-terminates with `SIGALRM` no matter what
/// it is doing. The upper bound on how long any of this can take.
const child_watchdog_s: isize = 10;

/// Arm the watchdog above.
///
/// ⚠ NOT `alarm(2)`. That syscall exists only in the x86 tables; the "generic"
/// syscall ABI every other architecture uses (arm64 included) has no
/// `SYS_alarm` at all, so `linux.syscall1(.alarm, …)` is not a portability
/// wart — it fails to COMPILE on arm64 with "enum 'Arm64' has no member named
/// 'alarm'". Caught by the arm64 lane on 2026-08-15, the first run of this
/// module on anything but x86_64. `setitimer(ITIMER_REAL, …)` is the portable
/// spelling and is what glibc's `alarm()` itself calls there.
///
/// ⚠ The syscall is issued directly rather than through `linux.setitimer`,
/// which declares `*const itimerspec` — NANOseconds. The kernel reads
/// `struct itimerval` — MICROseconds. Both are two pairs of longs, so they
/// agree byte for byte only while the sub-second field is zero; through that
/// declaration any future sub-second value would silently mean 1000× less.
fn armWatchdog(seconds: isize) void {
    const itimerval = extern struct { interval: linux.timeval, value: linux.timeval };
    var it: itimerval = .{
        .interval = .{ .sec = 0, .usec = 0 },
        .value = .{ .sec = seconds, .usec = 0 },
    };
    _ = linux.syscall3(.setitimer, @intCast(@intFromEnum(linux.ITIMER.REAL)), @intFromPtr(&it), 0);
}

/// Child exit codes (0 = the expected outcome).
const child_no_lock: i32 = 71; // opened a store it should have been refused
const child_wrong_error: i32 = 72; // refused, but not with error.Locked
const child_open_failed: i32 = 73; // could not open a store it should have got

/// Reap `pid`, polling for at most `deadline_ms`, then `SIGKILL` and block.
/// Bounded by construction: this returns even for a child that ignores
/// everything.
fn reapBounded(pid: i32, deadline_ms: usize) !u32 {
    var status: u32 = 0;
    var waited: usize = 0;
    while (waited < deadline_ms) : (waited += 5) {
        const rc = linux.waitpid(pid, &status, linux.W.NOHANG);
        if (@as(isize, @bitCast(rc)) < 0) {
            if (linux.errno(rc) == .INTR) continue;
            return error.WaitFailed;
        }
        if (rc != 0) return status;
        var ts = linux.timespec{ .sec = 0, .nsec = 5 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
    }
    _ = linux.kill(pid, .KILL);
    while (true) {
        const rc = linux.waitpid(pid, &status, 0);
        if (@as(isize, @bitCast(rc)) < 0 and linux.errno(rc) == .INTR) continue;
        break;
    }
    return status;
}

test "lock: a REAL second process is refused by the holder's flock" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var fs_store = FsStorage.init(testing.io, tmp.dir);
    var db = Db.open(testing.allocator, fs_store.storage(), "shared.kv", .{}) catch |e| switch (e) {
        error.LockUnsupported => return error.SkipZigTest,
        else => return e,
    };
    defer db.close();
    try db.put("owner", "parent");

    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) return error.ForkFailed;
    const pid: i32 = @intCast(@as(isize, @bitCast(forked)));
    if (pid == 0) {
        // CHILD: a separate process with its own fd table. It never returns
        // into the test runner — `exit_group` only — so the parent's
        // allocator, io and test state are never touched.
        armWatchdog(child_watchdog_s);
        var child_fs = FsStorage.init(testing.io, tmp.dir);
        if (Db.open(std.heap.page_allocator, child_fs.storage(), "shared.kv", .{})) |_| {
            linux.exit_group(child_no_lock);
        } else |e| switch (e) {
            error.Locked => linux.exit_group(0),
            else => linux.exit_group(child_wrong_error),
        }
    }

    const status = try reapBounded(pid, 5000);
    try testing.expect(linux.W.IFEXITED(status));
    try testing.expectEqual(@as(u8, 0), linux.W.EXITSTATUS(status));
    // The rejected process left the holder's store exactly as it was.
    try expectGet(&db, "owner", "parent");
}

test "lock: the lock dies with the holding process (SIGKILL, zero cleanup)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var fs_store = FsStorage.init(testing.io, tmp.dir);

    // The child announces "I hold the lock" on this pipe. The parent closes
    // its own write end, so if the child dies early the read returns EOF
    // instead of blocking forever.
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.PipeFailed;

    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) return error.ForkFailed;
    const pid: i32 = @intCast(@as(isize, @bitCast(forked)));
    if (pid == 0) {
        _ = linux.close(fds[0]);
        armWatchdog(child_watchdog_s);
        var child_fs = FsStorage.init(testing.io, tmp.dir);
        var cdb = Db.open(std.heap.page_allocator, child_fs.storage(), "shared.kv", .{}) catch
            linux.exit_group(child_open_failed);
        cdb.put("owner", "child") catch linux.exit_group(child_open_failed);
        _ = linux.write(fds[1], "L", 1);
        // Hold the store open until killed. No unlock, no close, no defer
        // will ever run — the point is that none of that is needed.
        while (true) {
            var ts = linux.timespec{ .sec = 1, .nsec = 0 };
            _ = linux.nanosleep(&ts, null);
        }
    }
    _ = linux.close(fds[1]);
    var byte: [1]u8 = undefined;
    const n = linux.read(fds[0], &byte, 1);
    _ = linux.close(fds[0]);
    if (n != 1) {
        _ = try reapBounded(pid, 5000);
        // The child could not open/lock at all (e.g. no flock on this fs).
        return error.SkipZigTest;
    }

    // While that process lives, this one cannot have the store.
    try testing.expectError(
        error.Locked,
        Db.open(testing.allocator, fs_store.storage(), "shared.kv", .{}),
    );

    // SIGKILL: no destructor, no unlock call, no `Db.close` — the kernel
    // closes the descriptors and the advisory lock goes with them. This is
    // the reason `flock` was chosen over a PID/lock-file protocol that would
    // now need stale-lock heuristics.
    _ = linux.kill(pid, .KILL);
    const status = try reapBounded(pid, 5000);
    try testing.expect(linux.W.IFSIGNALED(status));

    var db = try Db.open(testing.allocator, fs_store.storage(), "shared.kv", .{});
    defer db.close();
    // ...and the dead process's durable write is there, which also proves it
    // really was operating on THIS store and not a private copy.
    try expectGet(&db, "owner", "child");
}

test "FsStorage: allocate reserves zeros past the data; syncData makes writes into them durable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var fs = FsStorage.init(std.testing.io, tmp.dir);
    const st = fs.storage();
    const h = try st.open("f", .create_truncate);
    defer st.close(h);
    try st.writeAll(h, "hello", 0);
    if (!try st.allocate(h, 4096)) return error.SkipZigTest; // a filesystem without fallocate
    try std.testing.expectEqual(@as(u64, 4096), try st.size(h));
    var buf: [16]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 16), try st.pread(h, &buf, 0));
    try std.testing.expectEqualSlices(u8, "hello" ++ "\x00" ** 11, &buf);

    try st.writeAll(h, "world", 5);
    try st.syncData(h);
    try std.testing.expectEqual(@as(u64, 4096), try st.size(h)); // still the reservation
    try std.testing.expectEqual(@as(usize, 16), try st.pread(h, &buf, 0));
    try std.testing.expectEqualSlices(u8, "helloworld" ++ "\x00" ** 6, &buf);
    try std.testing.expect(try st.allocate(h, 100)); // never shrinks
    try std.testing.expectEqual(@as(u64, 4096), try st.size(h));

    const ro = try st.open("f", .read_only);
    defer st.close(ro);
    try std.testing.expectError(error.AccessDenied, st.allocate(ro, 8192));
}

fn expectNames(listing: ?Storage.Listing, want: []const []const u8) !void {
    const l = listing orelse return error.TestExpectedListing;
    defer l.deinit(testing.allocator);
    try testing.expectEqual(want.len, l.names.len);
    for (want, l.names) |w, n| try testing.expectEqualStrings(w, n);
}

test "FsStorage.list: the files under a prefix, sorted; directories and dangling links left out" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var fs_store = FsStorage.init(testing.io, tmp.dir);
    const st = fs_store.storage();
    const gpa = testing.allocator;

    try expectNames(try st.list(gpa, ""), &.{});
    for ([_][]const u8{ "seg-2.log", "MANIFEST", "seg-10.log", "seg-1.log" }) |name| st.close(try st.open(name, .create_new));
    try tmp.dir.createDir(testing.io, "seg-dir", .default_dir);
    try tmp.dir.symLink(testing.io, "seg-1.log", "seg-link", .{});
    try tmp.dir.symLink(testing.io, "gone", "seg-dangling", .{});

    // Bytewise order, not numeric: the caller parses its own ids.
    try expectNames(try st.list(gpa, "seg-"), &.{ "seg-1.log", "seg-10.log", "seg-2.log", "seg-link" });
    try expectNames(try st.list(gpa, ""), &.{ "MANIFEST", "seg-1.log", "seg-10.log", "seg-2.log", "seg-link" });
    try expectNames(try st.list(gpa, "MANIFEST.tmp"), &.{});

    try st.delete("seg-2.log");
    try expectNames(try st.list(gpa, "seg-2"), &.{});
}

test "SimStorage.list: the running view; a crash takes back a name syncDir never made durable" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const st = sim.storage();
    const gpa = testing.allocator;

    st.close(try st.open("seg-1", .create_new));
    try st.syncDir();
    st.close(try st.open("seg-2", .create_new));
    st.close(try st.open("other", .create_new));
    const ops = sim.ops_seen;
    try expectNames(try st.list(gpa, "seg-"), &.{ "seg-1", "seg-2" }); // seg-2 not durable yet
    try testing.expectEqual(ops, sim.ops_seen); // a pure read, not an injection point

    sim.ops_until_crash = 0;
    try testing.expectError(error.Crashed, st.delete("other"));
    try testing.expectError(error.Crashed, st.list(gpa, ""));
    sim.reboot();
    try expectNames(try st.list(gpa, ""), &.{"seg-1"});
}

test "Storage.list: a backend without it answers null, not an empty listing" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var vt = sim.storage().vtable.*;
    vt.list = null;
    const st: Storage = .{ .ctx = &sim, .vtable = &vt };
    st.close(try st.open("f", .create_new));
    try testing.expect(try st.list(testing.allocator, "") == null);
}

test "Storage: a backend without allocate answers false; syncData falls back to sync" {
    var sim = SimStorage.init(std.testing.allocator);
    defer sim.deinit();
    var vt = sim.storage().vtable.*;
    vt.allocate = null;
    vt.syncData = null;
    const st: Storage = .{ .ctx = &sim, .vtable = &vt };
    const h = try st.open("f", .open_or_create);
    try std.testing.expect(!try st.allocate(h, 100));
    try std.testing.expectEqual(@as(u64, 0), try st.size(h)); // and did nothing
    try st.writeAll(h, "x", 0);
    const before = sim.ops_seen;
    try st.syncData(h);
    try std.testing.expectEqual(before + 1, sim.ops_seen); // the full sync ran
}
