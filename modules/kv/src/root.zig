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
//! Future phases (deliberately NOT in v0): full randomized VOPR at scale,
//! immutable/MVCC on-disk structure (HAMT/B-tree) with lockless readers,
//! ordered/ranged scans, transactions/batches, secondary indexes, automatic
//! compaction thresholds, in-memory value cache (compose with `ramcache`),
//! shared/reader locks (the store is single-writer, so the cross-process
//! lock is exclusive-only). The v0 keydir is an unordered hash map.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const meta = .{
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
// File header (8 bytes):        Record (13 + key_len + value_len bytes):
//   [0..4)  magic "ZKVL"          [0..4)   crc32 (IEEE) over bytes [4..end)
//   [4..8)  version u32 LE = 1    [4]      op: 0 = put, 1 = del
//                                 [5..9)   key_len   u32 LE
//                                 [9..13)  value_len u32 LE (0 for del)
//                                 [13..13+key_len)        key bytes
//                                 [13+key_len .. end)     value bytes

const file_magic = "ZKVL";
const file_version: u32 = 1;
const header_len = 8;
const rec_fixed = 13;

const op_put: u8 = 0;
const op_del: u8 = 1;

fn recordLen(key_len: u64, value_len: u64) u64 {
    return rec_fixed + key_len + value_len;
}

/// Serialize one record into `buf` (`buf.len == recordLen(...)`).
fn encodeRecord(buf: []u8, op: u8, key: []const u8, value: []const u8) void {
    buf[4] = op;
    std.mem.writeInt(u32, buf[5..9], @intCast(key.len), .little);
    std.mem.writeInt(u32, buf[9..13], @intCast(value.len), .little);
    @memcpy(buf[rec_fixed..][0..key.len], key);
    @memcpy(buf[rec_fixed + key.len ..][0..value.len], value);
    std.mem.writeInt(u32, buf[0..4], std.hash.Crc32.hash(buf[4..]), .little);
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

    pub const OpenMode = enum { open_or_create, create_truncate };

    pub const Error = error{
        /// SimStorage only: the simulated machine died at this operation.
        Crashed,
        FileNotFound,
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
    pub fn writeAll(s: Storage, h: Handle, bytes: []const u8, off: u64) Error!void {
        return s.vtable.writeAll(s.ctx, h, bytes, off);
    }
    pub fn sync(s: Storage, h: Handle) Error!void {
        return s.vtable.sync(s.ctx, h);
    }
    pub fn truncate(s: Storage, h: Handle, len: u64) Error!void {
        return s.vtable.truncate(s.ctx, h, len);
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
pub const FsStorage = struct {
    io: std.Io,
    dir: std.Io.Dir,
    files: [max_handles]?std.Io.File = @splat(null),

    /// The store needs at most 3 concurrently open files (data + lock
    /// sidecar + compaction temp); a little headroom is left.
    const max_handles = 4;

    pub fn init(io: std.Io, dir: std.Io.Dir) FsStorage {
        return .{ .io = io, .dir = dir };
    }

    pub fn storage(self: *FsStorage) Storage {
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
    };

    fn cast(ctx: *anyopaque) *FsStorage {
        return @ptrCast(@alignCast(ctx));
    }

    fn mapErr(e: anyerror) Storage.Error {
        return switch (e) {
            error.FileLocksUnsupported => error.LockUnsupported,
            error.FileNotFound => error.FileNotFound,
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
        const slot: usize = for (self.files, 0..) |f, i| {
            if (f == null) break i;
        } else return error.Unexpected;
        const file = self.dir.createFile(self.io, path, .{
            .read = true,
            .truncate = mode == .create_truncate,
        }) catch |e| return mapErr(e);
        self.files[slot] = file;
        return @intCast(slot);
    }

    fn fileOf(self: *FsStorage, h: Storage.Handle) std.Io.File {
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
        self.fileOf(h).writePositionalAll(self.io, bytes, off) catch |e| return mapErr(e);
    }

    fn vSync(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
        const self = cast(ctx);
        self.fileOf(h).sync(self.io) catch |e| return mapErr(e);
    }

    fn vTruncate(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!void {
        const self = cast(ctx);
        self.fileOf(h).setLength(self.io, len) catch |e| return mapErr(e);
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

    /// `flock(fd, LOCK_EX | LOCK_NB)` (POSIX) / `NtLockFile` with fail-
    /// immediately (Windows), via `std.Io.File.tryLock` — the non-blocking
    /// form, so a contended store reports `error.Locked` to the caller
    /// instead of parking the thread inside a library call forever.
    fn vTryLockExclusive(ctx: *anyopaque, h: Storage.Handle) Storage.Error!bool {
        const self = cast(ctx);
        return self.fileOf(h).tryLock(self.io, .exclusive) catch |e| mapErr(e);
    }
};

// ── Db ───────────────────────────────────────────────────────────────────────

pub const Options = struct {
    /// Re-verify the whole record's CRC on every `get` (never serve corrupt
    /// data even if the file rotted after `open`). Costs one extra read of
    /// the record header + key per get; disable only if the value copy alone
    /// is acceptable verification (replay already CRC-checked every record).
    read_verify: bool = true,

    /// Cross-process exclusion policy (default: on). See `LockPolicy`.
    lock: LockPolicy = .exclusive,
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

    const Entry = struct {
        /// Absolute file offset of the record.
        off: u64,
        key_len: u32,
        val_len: u32,

        fn recLen(e: Entry) u64 {
            return recordLen(e.key_len, e.val_len);
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
            std.mem.writeInt(u32, want[4..8], file_version, .little);
            if (!std.mem.eql(u8, have[0..n], want[0..n])) return error.NotAKvFile;
            if (file_size != 0) try store.truncate(self.file, 0);
            try store.writeAll(self.file, &want, 0);
            try store.sync(self.file);
        } else {
            var hdr: [header_len]u8 = undefined;
            try store.preadFull(self.file, &hdr, 0);
            if (!std.mem.eql(u8, hdr[0..4], file_magic)) return error.NotAKvFile;
            if (std.mem.readInt(u32, hdr[4..8], .little) != file_version)
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
    pub fn put(self: *Db, key: []const u8, value: []const u8) MutateError!void {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        if (self.poisoned) return error.Poisoned;
        if (key.len > std.math.maxInt(u32)) return error.KeyTooLong;
        if (value.len > std.math.maxInt(u32)) return error.ValueTooLong;

        const rec_len: usize = @intCast(recordLen(key.len, value.len));
        const rec = try self.gpa.alloc(u8, rec_len);
        defer self.gpa.free(rec);
        encodeRecord(rec, op_put, key, value);

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

        const entry = Entry{ .off = self.end, .key_len = @intCast(key.len), .val_len = @intCast(value.len) };
        if (existing) |e| {
            self.dead_bytes += e.recLen();
            e.* = entry;
        } else {
            self.keydir.putAssumeCapacity(new_key.?, entry);
        }
        self.end += rec_len;
    }

    /// Delete `key` (append a durable tombstone). Deleting an absent key is
    /// a no-op — no I/O, no error.
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
        const kv = self.keydir.fetchRemove(key).?;
        self.gpa.free(@constCast(kv.key));
        self.end += rec_len;
    }

    /// Read the current value of `key` into memory allocated from `gpa`
    /// (caller frees), or null if absent. With `Options.read_verify` (the
    /// default) the whole record's CRC is re-checked — a rotten record
    /// yields `error.Corrupt`, never bad bytes. Reads work on a poisoned
    /// store (they describe the last consistent state).
    pub fn get(self: *Db, gpa: Allocator, key: []const u8) GetError!?[]u8 {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        const e = self.keydir.get(key) orelse return null;

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
        const e = self.keydir.get(key) orelse return null;
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
        const e = self.keydir.get(key) orelse return null;
        return e.val_len;
    }

    /// Fill `value` (already sized to `e.val_len`) from the log. Caller holds
    /// the lock.
    fn readValueLocked(self: *Db, e: anytype, key: []const u8, value: []u8) GetError!void {
        const val_off = e.off + rec_fixed + e.key_len;

        if (!self.options.read_verify) {
            return self.store.preadFull(self.file, value, val_off);
        }

        // Full-record verification: header fields must match the keydir and
        // the CRC must hold over op+lens+key+value.
        var hdr: [rec_fixed]u8 = undefined;
        try self.store.preadFull(self.file, &hdr, e.off);
        if (hdr[4] != op_put or
            std.mem.readInt(u32, hdr[5..9], .little) != e.key_len or
            std.mem.readInt(u32, hdr[9..13], .little) != e.val_len)
            return error.Corrupt;
        var crc = std.hash.Crc32.init();
        crc.update(hdr[4..]);
        // Stream the key in bounded chunks; it must equal the requested key.
        var kbuf: [512]u8 = undefined;
        var koff: u64 = 0;
        while (koff < e.key_len) {
            const n: usize = @intCast(@min(kbuf.len, e.key_len - koff));
            try self.store.preadFull(self.file, kbuf[0..n], e.off + rec_fixed + koff);
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
        return self.keydir.contains(key);
    }

    /// Number of live keys (pure in-memory).
    pub fn count(self: *Db) usize {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        return self.keydir.count();
    }

    /// Bytes the log currently wastes on overwritten/deleted records —
    /// the caller's signal for when `compact` is worth it (v0 compaction is
    /// caller-driven; automatic thresholds are a noted phase).
    pub fn deadBytes(self: *Db) u64 {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        return self.dead_bytes;
    }

    /// Rewrite live records into a fresh file and atomically swap it in
    /// (temp + fsync + rename + dir fsync). A crash anywhere before the
    /// rename leaves the old file untouched; from the rename on, either the
    /// old or the complete new file is what `open` finds — never a mix.
    /// Errors before the rename leave the store fully usable (the temp is
    /// discarded); errors at/after the rename poison the store (the
    /// namespace state is uncertain until reopen).
    pub fn compact(self: *Db) CompactError!void {
        lockSpin(&self.lock);
        defer self.lock.unlock();
        if (self.poisoned) return error.Poisoned;

        const NewOff = struct { e: *Entry, off: u64 };
        var moves: std.ArrayListUnmanaged(NewOff) = .empty;
        defer moves.deinit(self.gpa);
        try moves.ensureTotalCapacity(self.gpa, self.keydir.count());

        const tmp = try self.store.open(self.tmp_path, .create_truncate);
        var swapped = false;
        defer if (!swapped) {
            self.store.close(tmp);
            self.store.delete(self.tmp_path) catch {};
        };

        var hdr: [header_len]u8 = undefined;
        hdr[0..4].* = file_magic.*;
        std.mem.writeInt(u32, hdr[4..8], file_version, .little);
        try self.store.writeAll(tmp, &hdr, 0);

        var new_end: u64 = header_len;
        var it = self.keydir.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr;
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
        self.end = new_end;
        self.dead_bytes = 0;
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
    /// tail is discarded).
    fn replay(self: *Db, file_size: u64) OpenError!void {
        var off: u64 = header_len;
        scan: while (off < file_size) {
            const remaining = file_size - off;
            if (remaining < rec_fixed) break; // torn fixed header
            var hdr: [rec_fixed]u8 = undefined;
            try self.store.preadFull(self.file, &hdr, off);
            const op = hdr[4];
            const key_len = std.mem.readInt(u32, hdr[5..9], .little);
            const val_len = std.mem.readInt(u32, hdr[9..13], .little);
            if (op != op_put and op != op_del) break; // corrupt op byte
            if (op == op_del and val_len != 0) break;
            if (@as(u64, key_len) + val_len > remaining - rec_fixed) break; // torn body

            // CRC over op+lens+key+value, streaming the value in bounded
            // chunks (only the key is materialized — it may enter the keydir).
            var crc = std.hash.Crc32.init();
            crc.update(hdr[4..]);
            const key = try self.gpa.alloc(u8, key_len);
            var key_owned = true;
            defer if (key_owned) self.gpa.free(key);
            try self.store.preadFull(self.file, key, off + rec_fixed);
            crc.update(key);
            var vbuf: [4096]u8 = undefined;
            var voff: u64 = 0;
            while (voff < val_len) {
                const n: usize = @intCast(@min(vbuf.len, val_len - voff));
                try self.store.preadFull(self.file, vbuf[0..n], off + rec_fixed + key_len + voff);
                crc.update(vbuf[0..n]);
                voff += n;
            }
            if (crc.final() != std.mem.readInt(u32, hdr[0..4], .little)) break :scan; // torn/corrupt

            const rec_len = recordLen(key_len, val_len);
            switch (op) {
                op_put => {
                    const gop = try self.keydir.getOrPut(self.gpa, key);
                    if (gop.found_existing) {
                        self.dead_bytes += gop.value_ptr.recLen();
                    } else {
                        key_owned = false; // the keydir owns it now
                    }
                    gop.value_ptr.* = .{ .off = off, .key_len = key_len, .val_len = val_len };
                },
                op_del => {
                    if (self.keydir.fetchRemove(key)) |kv| {
                        self.dead_bytes += kv.value.recLen();
                        self.gpa.free(@constCast(kv.key));
                    }
                    self.dead_bytes += rec_len;
                },
                else => unreachable,
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
const child_watchdog_s: usize = 10;

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
        _ = linux.syscall1(.alarm, child_watchdog_s);
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
        _ = linux.syscall1(.alarm, child_watchdog_s);
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
