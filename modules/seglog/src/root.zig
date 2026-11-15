// SPDX-License-Identifier: MIT

//! seglog — a segmented, crash-consistent, append-only log.
//!
//! A log is a sequence of **segments**; a segment is one file of
//! length-prefixed, CRC32C-checked records. The caller names each segment
//! with a strictly increasing `u64` (egw-hub uses the UTC day number), appends
//! to the newest one, and deletes old ones whole. Nothing is ever rewritten in
//! place: a record, once `append` has returned, stays at its `Position` until
//! its segment is dropped.
//!
//! **Two addresses per record.** Every record carries a **log sequence number**
//! (LSN): 1 for the first record the log ever took, one more for each after
//! it, across segments, forever — an address that means the same thing in
//! every copy of the log and survives any change of representation. And it
//! has a `Position` (segment, byte offset): the cheapest place to resume a
//! read from. Every record also carries a timestamp the caller supplies
//! (`appendAt`) or the log's clock stamps (`Options.now`).
//!
//! **Durability contract.** `append` returns only after the record has been
//! written *and* `fsync` has returned. A torn record at the tail of the newest
//! segment — a write the crash interrupted — is detected on `open` and cut
//! off; everything before it survives. After any storage-write error the log
//! is **poisoned** (fail-stop): mutations are refused, because a failed
//! `fsync` leaves the page cache in an undefined state — reopen to recover.
//! This is `kv`'s contract, applied to more than one file.
//!
//! **Only the newest segment is ever repaired.** It is the only one a crash
//! can have interrupted. Every older segment is closed with a **seal** — a
//! final record holding the segment's record count, its own offset, and the
//! first and last LSN and the time range of its records — so a closed segment
//! that lost its tail, a byte, or a whole record is *reported* as
//! `error.Corrupt` by the reader, never quietly shortened. Without the seal
//! a truncated closed segment would read as a valid shorter one. Closed
//! segments are verified lazily, as they are read; `open` does not scan them.
//!
//! **The manifest is the only source of truth for which segments exist.** The
//! `Storage` seam has no directory listing, and a log that inferred its
//! segments from file names would adopt any stray file that looked like one.
//! `MANIFEST` is replaced whole (temp + fsync + rename + dir-fsync). It names
//! each live segment with the LSN its first record gets. A new segment is
//! committed to it *before* its file is written, so a crash in between leaves
//! a named segment with no file — which `open` finishes creating, since an
//! empty segment and a missing one are the same thing. A dropped segment is
//! moved to the manifest's *pending* list before its file is deleted, so a
//! crash in between is finished by the next `open`. Neither order can leave a
//! file nothing refers to.
//!
//! **One writer, any number of readers.** `open` takes an exclusive advisory
//! lock on `LOCK` (see `kv.Storage.tryLockExclusive` for the full `flock`
//! contract). `openReadOnly` takes no lock and never writes, creates, repairs
//! or deletes anything, so it can read beside a live writer in another process
//! — or a copy, or a read-only mount. It follows the writer by re-reading the
//! manifest at its live end, and treats an unfinished tail of the newest
//! segment — a missing file, a short header, a record whose bytes have not all
//! arrived — as "nothing more yet", never as corruption. ⚠ Unlike the writer's
//! own iterator it cannot know what is *durable*: it may return a record whose
//! `append` has not yet returned, which a power failure before that `fsync`
//! would take back. Each `Log` is `single_owner`: one thread or event loop
//! drives it, iterators included.
//!
//! **The Storage seam.** Every side effect goes through `kv.Storage`, so the
//! same `SimStorage` that crash-tests `kv` and `kvtree` crashes this at every
//! write, sync, rename and delete (`fault_test.zig`). With `SimStorage`'s
//! default `allow_overwrite = false`, every write the sweep makes is also
//! asserted to land at or above the durable watermark — the append-only
//! claim, checked rather than stated. ⚠ One path it cannot reach: a torn
//! header on a segment whose *name* survived the crash. The simulator makes
//! a new name durable only at `syncDir`, which comes after the header's fsync,
//! so there a torn header always takes its name with it. Real filesystems
//! can persist a name before its data, so that path truncates first anyway,
//! and a direct test holds it.
//!
//! **Reading is done in blocks** (`read_block` bytes at a time, larger for a
//! larger record), not one `pread` per record — the recovery walk of `open`
//! and every iterator alike.
//!
//! All files live directly in the backend's directory: `MANIFEST`,
//! `MANIFEST.tmp`, `LOCK`, and `seg-<id, 20 decimal digits>.log`. One log per
//! directory.

const std = @import("std");
const kv = @import("kv");
const crc32c_mod = @import("crc32c");
const zstd = @import("zstd");
const Allocator = std.mem.Allocator;

pub const meta = .{
    .doc = "Segmented crash-consistent append-only log — CRC32C records with LSNs and timestamps, sealed closed segments, whole-segment retention.",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // all I/O through kv's Storage seam
    .role = .both, // embedded read+write
    .concurrency = .single_owner,
    .model_after = "LevelDB log format / Prometheus TSDB WAL (repair the last segment only); Kafka segments (retention by whole segment, offsets as LSNs); VOPR = kv's SimStorage",
    .deps = .{ "kv", "crc32c", "zstd" },
};

pub const Storage = kv.Storage;
pub const FsStorage = kv.FsStorage;
pub const SimStorage = kv.SimStorage;
pub const CrashMode = kv.CrashMode;

// ── on-disk format (version 2) ───────────────────────────────────────────────
//
// Segment header (40 bytes):          Record (25 + len bytes):
//   [0..4)   magic "SGLS"               [0..4)   crc32c over [4 .. 25+len)
//   [4..8)   version u32 = 2            [4]      type: 1 = data, 2 = seal
//   [8..16)  segment id u64             [5..9)   len u32
//   [16..24) base LSN u64               [9..17)  LSN u64 (0 on a seal)
//   [24..32) created i64                [17..25) timestamp i64 (0 on a seal)
//   [32..36) flags u32 = 0              [25..)   payload
//   [36..40) crc32c over [0..36)
//
// Seal payload (48 bytes): data-record count u64, the seal's own offset u64,
// first LSN u64, last LSN u64, min timestamp i64, max timestamp i64. An empty
// segment's seal has first = base, last = base − 1 and both times 0. The seal
// is the last record of every closed segment.
//
// Data records in a segment carry consecutive LSNs from the header's base.
//
// MANIFEST:
//   [0..4)   magic "SGLM"
//   [4..8)   version u32 = 2
//   [8..12)  live count u32
//   [12..16) pending count u32
//   [16..)   live entries, 24 bytes each: id u64 (strictly increasing), first
//            LSN u64, form u8 (0 = raw, 1 = zstd seekable), 7 zero bytes;
//            then pending ids u64
//   [-4..)   crc32c over everything before it
//
// All integers little-endian, explicitly — the format does not depend on the
// host's byte order.

const seg_magic = "SGLS";
const man_magic = "SGLM";
const format_version: u32 = 2;

/// Where the first record of every segment starts.
pub const segment_header_len: u64 = 40;
/// Bytes a record costs beyond its payload.
pub const record_overhead: u64 = rec_header_len;
/// How much a reader asks the storage for at a time.
/// 512 bytes in a test build, so that the tests and the fuzz harness, whose
/// segments are a few kilobytes, still cross block boundaries — the window's
/// extend-and-drop path went unreached at 64 KiB (a planted off-by-one there
/// survived 20 000 fuzz runs).
pub const read_block: usize = if (@import("builtin").is_test) 512 else 64 * 1024;

const rec_header_len = 25;
const rec_data: u8 = 1;
const rec_seal: u8 = 2;
const seal_payload_len = 48;

const man_fixed = 16;
const man_entry_len = 24;
const man_crc_len = 4;
/// A bound on how many segment ids a manifest may hold, so a corrupt size
/// field cannot make `open` allocate without limit. 24 megabytes of entries.
const max_manifest_ids = 1 << 20;

const form_raw: u8 = 0;

const manifest_name = "MANIFEST";
const manifest_tmp = "MANIFEST.tmp";
/// Where `compact` builds a segment before renaming it into place.
const compact_tmp = "COMPACT.tmp";
/// Where a migration builds a segment in the current format before renaming
/// it over the old one.
const migrate_tmp = "MIGRATE.tmp";

// ── the previous format (version 1), read only to migrate from ──────────────
//
// Segment: a 16-byte header (magic `SGLS`, version u32 = 1, id u64), records of
// `crc32c u32 over [4 .. 9+len), type u8, len u32, payload`, and on a closed
// segment a seal of `count u64, own offset u64`. MANIFEST: magic `SGLM`,
// version u32 = 1, live count u32, pending count u32, the live ids, the
// pending ids (u64 each), a crc32c over everything before it. No LSNs, no
// timestamps, no index, no compression.
const legacy_version: u32 = 1;
const legacy_header_len: u64 = 16;
const legacy_rec_header_len: u64 = 9;
const legacy_seal_payload_len = 16;
/// A live segment of the manifest still in the previous format: a migration
/// is under way (`Log.open` finishes it).
const form_legacy: u8 = 2;
const lock_name = "LOCK";

const seg_name_len = 28; // "seg-" ++ 20 digits ++ ".log"

fn segName(buf: *[seg_name_len]u8, id: u64) []const u8 {
    return std.mem.print(buf, "seg-{d:0>20}.log", .{id}) catch unreachable;
}

fn idxName(buf: *[seg_name_len]u8, id: u64) []const u8 {
    return std.mem.print(buf, "seg-{d:0>20}.idx", .{id}) catch unreachable;
}

// ── the sparse index ─────────────────────────────────────────────────────────
//
// Index file `seg-<id>.idx` (derived: written unsynced when the segment is
// sealed, checked on every load, rebuilt from the segment when absent or
// wrong — Kafka's rule for its `.index`):
//   [0..4)   magic "SGLI"
//   [4..8)   version u32 = 1
//   [8..16)  segment id u64
//   [16..24) the segment file's size u64 — a compacted (rewritten)
//            segment no longer matches its old index
//   [24..28) entry count u32
//   [28..)   entries, 24 bytes each: LSN u64, offset u64, max_before i64
//   [-4..)   crc32c over everything before it

const idx_magic = "SGLI";
const idx_version: u32 = 1;
const idx_fixed = 28;
const idx_entry_len = 24;

/// A record the index can jump to: its LSN, where it starts, and the newest
/// timestamp of the segment's records before it (minInt for none).
const IndexEntry = struct { lsn: u64, offset: u64, max_before: i64 };

const SparseIndex = struct {
    entries: std.ArrayList(IndexEntry) = .empty,

    fn deinit(ix: *SparseIndex, gpa: Allocator) void {
        ix.entries.deinit(gpa);
    }

    /// Take `e` if it is the first record, or `interval` bytes past the
    /// last entry. Capacity must be there.
    fn note(ix: *SparseIndex, interval: u32, e: IndexEntry) void {
        if (ix.entries.last()) |last| if (e.offset - last.offset < interval) return;
        ix.entries.appendAssumeCapacity(e);
    }

    /// The last entry at or before `lsn`, if any.
    fn byLsn(entries: []const IndexEntry, lsn: u64) ?IndexEntry {
        var lo: usize = 0;
        var hi: usize = entries.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (entries[mid].lsn <= lsn) lo = mid + 1 else hi = mid;
        }
        return if (lo == 0) null else entries[lo - 1];
    }

    /// The last entry whose records before it are all older than `t`.
    fn byTime(entries: []const IndexEntry, t: i64) ?IndexEntry {
        var lo: usize = 0;
        var hi: usize = entries.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (entries[mid].max_before < t) lo = mid + 1 else hi = mid;
        }
        return if (lo == 0) null else entries[lo - 1];
    }
};

/// The one place the checksum is computed: with the CPU's CRC instructions
/// where there are any (the std table version runs at about 0.45 GB/s and
/// made reading CRC-bound).
fn crc32c(bytes: []const u8) u32 {
    return crc32c_mod.hash(bytes);
}

fn encodeRecord(buf: []u8, typ: u8, lsn: u64, ts: i64, payload: []const u8) void {
    std.debug.assert(buf.len == rec_header_len + payload.len);
    buf[4] = typ;
    std.mem.writeInt(u32, buf[5..9], @intCast(payload.len), .little);
    std.mem.writeInt(u64, buf[9..17], lsn, .little);
    std.mem.writeInt(i64, buf[17..25], ts, .little);
    @memcpy(buf[rec_header_len..], payload);
    std.mem.writeInt(u32, buf[0..4], crc32c(buf[4..]), .little);
}

/// Header flag: the segment was compacted — its LSNs only rise, with gaps
/// where records were dropped, instead of running on one by one.
const flag_compacted: u32 = 1;

fn encodeHeader(hdr: *[segment_header_len]u8, id: u64, base_lsn: u64, created: i64) void {
    encodeHeaderFlags(hdr, id, base_lsn, created, 0);
}

fn encodeHeaderFlags(hdr: *[segment_header_len]u8, id: u64, base_lsn: u64, created: i64, flags: u32) void {
    @memcpy(hdr[0..4], seg_magic);
    std.mem.writeInt(u32, hdr[4..8], format_version, .little);
    std.mem.writeInt(u64, hdr[8..16], id, .little);
    std.mem.writeInt(u64, hdr[16..24], base_lsn, .little);
    std.mem.writeInt(i64, hdr[24..32], created, .little);
    std.mem.writeInt(u32, hdr[32..36], flags, .little);
    std.mem.writeInt(u32, hdr[36..40], crc32c(hdr[0..36]), .little);
}

/// What a closed segment's seal says about it.
const Seal = struct {
    count: u64,
    offset: u64,
    first_lsn: u64,
    last_lsn: u64,
    min_ts: i64,
    max_ts: i64,

    fn encode(s: Seal, out: *[seal_payload_len]u8) void {
        std.mem.writeInt(u64, out[0..8], s.count, .little);
        std.mem.writeInt(u64, out[8..16], s.offset, .little);
        std.mem.writeInt(u64, out[16..24], s.first_lsn, .little);
        std.mem.writeInt(u64, out[24..32], s.last_lsn, .little);
        std.mem.writeInt(i64, out[32..40], s.min_ts, .little);
        std.mem.writeInt(i64, out[40..48], s.max_ts, .little);
    }

    fn decode(p: []const u8) ?Seal {
        if (p.len != seal_payload_len) return null;
        return .{
            .count = std.mem.readInt(u64, p[0..8], .little),
            .offset = std.mem.readInt(u64, p[8..16], .little),
            .first_lsn = std.mem.readInt(u64, p[16..24], .little),
            .last_lsn = std.mem.readInt(u64, p[24..32], .little),
            .min_ts = std.mem.readInt(i64, p[32..40], .little),
            .max_ts = std.mem.readInt(i64, p[40..48], .little),
        };
    }
};

/// Running totals of the data records in a segment, read from its first
/// record on: what its seal must agree with.
const Tally = struct {
    base: u64,
    count: u64 = 0,
    min_ts: i64 = 0,
    max_ts: i64 = 0,
    /// A compacted segment: LSNs need only rise.
    compacted: bool = false,
    /// The LSN of the last record counted (base − 1 before the first).
    last_lsn: u64 = 0,

    fn init(base: u64, compacted: bool) Tally {
        return .{ .base = base, .compacted = compacted, .last_lsn = base -% 1 };
    }

    /// Whether `lsn` may come next.
    fn fits(t: Tally, lsn: u64) bool {
        return if (t.compacted) lsn > t.last_lsn and lsn >= t.base else lsn == t.base + t.count;
    }

    fn add(t: *Tally, ts: i64, lsn: u64) void {
        if (t.count == 0) {
            t.min_ts = ts;
            t.max_ts = ts;
        } else {
            t.min_ts = @min(t.min_ts, ts);
            t.max_ts = @max(t.max_ts, ts);
        }
        t.count += 1;
        t.last_lsn = lsn;
    }

    fn nextLsn(t: Tally) u64 {
        return t.base + t.count;
    }

    /// The newest timestamp so far, or the smallest there is for none.
    fn maxOrMin(t: Tally) i64 {
        return if (t.count == 0) std.math.minInt(i64) else t.max_ts;
    }

    fn seal(t: Tally, at: u64) Seal {
        return .{
            .count = t.count,
            .offset = at,
            .first_lsn = t.base,
            .last_lsn = t.base + t.count -% 1,
            .min_ts = t.min_ts,
            .max_ts = t.max_ts,
        };
    }
};

// ── block reads ──────────────────────────────────────────────────────────────

/// A window of one file's bytes, read `read_block` at a time. Bytes below
/// what the log treats as written never change (append-only), so a window
/// stays valid as the file grows; `forget` drops what a reader must not
/// trust, such as the tail of an append still arriving.
const Window = struct {
    buf: std.ArrayList(u8) = .empty,
    /// File offset of `buf.items[0]`.
    off: u64 = 0,
    /// How much to read at a time: `read_block` for a walk, less for a
    /// seek that needs only the stretch up to the next index entry.
    block: usize = read_block,
    /// Where a read came up short under `short_limit`: nothing lies there
    /// yet, so asking again for more than that answers null without reading.
    /// `resync` asks at every byte, each time for whatever length the bytes
    /// there claim; without this, and without extending the window rather
    /// than reloading it, a damaged segment cost a block read per byte.
    short_at: ?u64 = null,
    short_limit: u64 = 0,

    fn deinit(w: *Window, gpa: Allocator) void {
        w.buf.deinit(gpa);
    }

    fn reset(w: *Window) void {
        w.buf.clearRetainingCapacity();
        w.off = 0;
        w.short_at = null;
    }

    /// Keep only what lies below `at`.
    fn forget(w: *Window, at: u64) void {
        w.short_at = null;
        if (at <= w.off) return w.reset();
        const keep = at - w.off;
        if (keep < w.buf.items.len) w.buf.shrinkRetainingCapacity(@intCast(keep));
    }

    /// `need` bytes at `start`, or null when fewer than that exist below
    /// `limit` (or in the file).
    fn get(w: *Window, gpa: Allocator, store: Storage, h: Storage.Handle, start: u64, need: u64, limit: u64) (Storage.Error || error{OutOfMemory})!?[]const u8 {
        if (start + need > limit) return null;
        const have_end = w.off + w.buf.items.len;
        if (start >= w.off and start + need <= have_end) {
            const i: usize = @intCast(start - w.off);
            return w.buf.items[i..][0..@intCast(need)];
        }
        if (w.short_at) |s| if (limit == w.short_limit and start + need > s) return null;
        if (start >= w.off and start <= have_end) {
            // Extend the window instead of reloading it: drop what lies
            // before `start` once that is a block's worth, then read on.
            if (start - w.off >= w.block) {
                const drop: usize = @intCast(start - w.off);
                const rest = w.buf.items.len - drop;
                std.mem.copyForwards(u8, w.buf.items[0..rest], w.buf.items[drop..]);
                w.buf.shrinkRetainingCapacity(rest);
                w.off = start;
            }
        } else {
            w.buf.clearRetainingCapacity();
            w.off = start;
        }
        const old: usize = w.buf.items.len;
        const from = w.off + old;
        const want_end = @min(@max(start + need, from + w.block), limit);
        const add: usize = @intCast(want_end - from);
        try w.buf.ensureUnusedCapacity(gpa, add);
        const room = w.buf.unusedCapacitySlice()[0..add];
        var got: usize = 0;
        while (got < add) {
            const n = try store.pread(h, room[got..], from + got);
            if (n == 0) break;
            got += n;
        }
        w.buf.items.len += got;
        if (got < add) {
            w.short_at = from + got;
            w.short_limit = limit;
        }
        if (start + need > w.off + w.buf.items.len) return null;
        const i: usize = @intCast(start - w.off);
        return w.buf.items[i..][0..@intCast(need)];
    }
};

// ── compressed segments ──────────────────────────────────────────────────────

const form_zstd: u8 = 1;
/// Where `compress` (and `compact`, for a compressed segment) builds a
/// compressed segment before renaming it into place.
const compress_tmp = "COMPRESS.tmp";

fn zstName(buf: *[seg_name_len]u8, id: u64) []const u8 {
    return std.mem.print(buf, "seg-{d:0>20}.zst", .{id}) catch unreachable;
}

/// The `Storage` a `Log` works through: the caller's, with one addition. A
/// segment opened for reading whose `.log` file is not there is looked for
/// as `.zst` — the same bytes in the zstd seekable format — and read
/// decompressed: `size` is the segment's, `pread` decodes only the frames it
/// touches. So every read path is the same for both forms, and a reader
/// that meets a segment mid-compression reads whichever file it opens: the
/// bytes are the same. What cannot be decoded reads as bytes that are not
/// there, so damage in a compressed segment is reported as `Corrupt`, the
/// way a truncated closed segment is.
const SegStore = struct {
    gpa: Allocator,
    inner: Storage,
    /// Open compressed segments; a handle with `zst_bit` set indexes this.
    zst: std.ArrayList(?*Zst) = .empty,
    /// The decoder of the compressed segment closed last, kept for the next
    /// one (`Seekable.reset`): a walk over closed days opens them one after
    /// another, and each used to allocate its own buffers and decoder (audit
    /// L6). Its source is stale until `reset` gives it a new one.
    spare: ?zstd.seekable.Seekable = null,

    const zst_bit: Storage.Handle = 1 << 31;

    const Zst = struct {
        inner: Storage,
        handle: Storage.Handle,
        /// Null when the seek table could not be read: then the segment
        /// reads as empty.
        sk: ?zstd.seekable.Seekable = null,
        size: u64 = 0,
        /// A storage error met while decoding, handed on by `pread`.
        io_err: ?Storage.Error = null,
        /// Frames that failed to decode: read as nothing at once, without
        /// decoding them again for every byte a `resync` tries.
        bad: std.ArrayList(u32) = .empty,
    };

    fn create(gpa: Allocator, inner: Storage) error{OutOfMemory}!*SegStore {
        const self = try gpa.create(SegStore);
        self.* = .{ .gpa = gpa, .inner = inner };
        return self;
    }

    fn destroy(self: *SegStore) void {
        for (self.zst.items) |slot| if (slot) |z| self.closeZst(z);
        self.zst.deinit(self.gpa);
        if (self.spare) |*sk| sk.deinit();
        self.gpa.destroy(self);
    }

    fn storage(self: *SegStore) Storage {
        return .{ .ctx = self, .vtable = &vtable };
    }

    const vtable: Storage.VTable = .{
        .open = open,
        .size = size,
        .pread = pread,
        .writeAll = writeAll,
        .sync = sync,
        .truncate = truncate,
        .close = close,
        .rename = rename,
        .delete = delete,
        .syncDir = syncDir,
        .tryLockExclusive = tryLockExclusive,
        .allocate = allocate,
        .syncData = syncData,
    };

    fn cast(ctx: *anyopaque) *SegStore {
        return @ptrCast(@alignCast(ctx));
    }

    fn isSegment(path: []const u8) bool {
        return path.len == seg_name_len and std.mem.startsWith(u8, path, "seg-") and std.mem.endsWith(u8, path, ".log");
    }

    fn open(ctx: *anyopaque, path: []const u8, mode: Storage.OpenMode) Storage.Error!Storage.Handle {
        const self = cast(ctx);
        const h = self.inner.open(path, mode) catch |e| switch (e) {
            error.FileNotFound => if (mode == .read_only and isSegment(path)) return self.openZst(path) else return e,
            else => return e,
        };
        std.debug.assert(h & zst_bit == 0);
        return h;
    }

    fn openZst(self: *SegStore, path: []const u8) Storage.Error!Storage.Handle {
        var nb: [seg_name_len]u8 = undefined;
        @memcpy(&nb, path);
        @memcpy(nb[seg_name_len - 3 ..], "zst");
        const h = try self.inner.open(&nb, .read_only);
        errdefer self.inner.close(h);
        const len = try self.inner.size(h);
        const slot = for (self.zst.items, 0..) |z, i| {
            if (z == null) break i;
        } else blk: {
            try self.zst.append(self.gpa, null);
            break :blk self.zst.items.len - 1;
        };
        if (slot >= zst_bit) return error.HandleTableFull;
        const z = try self.gpa.create(Zst);
        errdefer self.gpa.destroy(z);
        z.* = .{ .inner = self.inner, .handle = h };
        const src: zstd.seekable.Source = .{ .custom = .{ .context = z, .size = len, .readAt = readAt } };
        const got: zstd.seekable.ReadError!zstd.seekable.Seekable = if (self.spare) |*sk| blk: {
            // On an error the spare stays as it was, for the next open.
            sk.reset(src) catch |e| break :blk e;
            const reused = sk.*;
            self.spare = null;
            break :blk reused;
        } else zstd.seekable.Seekable.init(self.gpa, src);
        if (got) |sk| {
            z.sk = sk;
            z.size = sk.table.decompressedSize();
        } else |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => if (z.io_err) |ie| return ie,
        }
        self.zst.items[slot] = z;
        return zst_bit | @as(Storage.Handle, @intCast(slot));
    }

    fn readAt(context: *anyopaque, buf: []u8, offset: u64) error{ReadFailed}!void {
        const z: *Zst = @ptrCast(@alignCast(context));
        var got: usize = 0;
        while (got < buf.len) {
            const n = z.inner.pread(z.handle, buf[got..], offset + got) catch |e| {
                z.io_err = e;
                return error.ReadFailed;
            };
            if (n == 0) return error.ReadFailed;
            got += n;
        }
    }

    fn zstOf(self: *SegStore, h: Storage.Handle) ?*Zst {
        if (h & zst_bit == 0) return null;
        return self.zst.items[h & ~zst_bit].?;
    }

    fn closeZst(self: *SegStore, z: *Zst) void {
        if (z.sk) |*sk| {
            if (self.spare == null) self.spare = sk.* else sk.deinit();
        }
        z.bad.deinit(self.gpa);
        z.inner.close(z.handle);
        self.gpa.destroy(z);
    }

    fn size(ctx: *anyopaque, h: Storage.Handle) Storage.Error!u64 {
        const self = cast(ctx);
        if (self.zstOf(h)) |z| return z.size;
        return self.inner.size(h);
    }

    /// Frame by frame, so that a read reaching a frame that does not decode
    /// returns what came before it (a short read), and that frame then reads
    /// as nothing — the bytes up to damage, as from a truncated file.
    fn pread(ctx: *anyopaque, h: Storage.Handle, buf: []u8, off: u64) Storage.Error!usize {
        const self = cast(ctx);
        const z = self.zstOf(h) orelse return self.inner.pread(h, buf, off);
        const sk = if (z.sk) |*sk| sk else return 0;
        var done: usize = 0;
        while (done < buf.len and off + done < z.size) {
            const at = off + done;
            const f = sk.table.offsetToFrameIndex(at);
            if (std.mem.findScalar(u32, z.bad.items, f) != null) break;
            const frame_end = sk.table.entries[f + 1].d_offset;
            const want: usize = @intCast(@min(buf.len - done, frame_end - at));
            const n = sk.decompress(buf[done..][0..want], at) catch |e| {
                // Start the frame over next time: its decoder stopped mid-way.
                sk.cur_frame = std.math.maxInt(u32);
                if (z.io_err) |ie| {
                    z.io_err = null;
                    if (done > 0) return done;
                    return ie;
                }
                if (e == error.OutOfMemory) return if (done > 0) done else error.OutOfMemory;
                try z.bad.append(self.gpa, f);
                break;
            };
            if (n == 0) break;
            done += n;
        }
        return done;
    }

    fn close(ctx: *anyopaque, h: Storage.Handle) void {
        const self = cast(ctx);
        if (self.zstOf(h)) |z| {
            self.closeZst(z);
            self.zst.items[h & ~zst_bit] = null;
        } else self.inner.close(h);
    }

    // Everything else is the caller's storage: a compressed segment is only
    // ever opened read-only.
    fn writeAll(ctx: *anyopaque, h: Storage.Handle, bytes: []const u8, off: u64) Storage.Error!void {
        if (h & zst_bit != 0) return error.AccessDenied;
        return cast(ctx).inner.writeAll(h, bytes, off);
    }
    fn sync(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
        if (h & zst_bit != 0) return error.AccessDenied;
        return cast(ctx).inner.sync(h);
    }
    fn truncate(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!void {
        if (h & zst_bit != 0) return error.AccessDenied;
        return cast(ctx).inner.truncate(h, len);
    }
    fn rename(ctx: *anyopaque, a: []const u8, b: []const u8) Storage.Error!void {
        return cast(ctx).inner.rename(a, b);
    }
    fn delete(ctx: *anyopaque, path: []const u8) Storage.Error!void {
        return cast(ctx).inner.delete(path);
    }
    fn syncDir(ctx: *anyopaque) Storage.Error!void {
        return cast(ctx).inner.syncDir();
    }
    fn tryLockExclusive(ctx: *anyopaque, h: Storage.Handle) Storage.Error!bool {
        if (h & zst_bit != 0) return error.AccessDenied;
        return cast(ctx).inner.tryLockExclusive(h);
    }
    fn allocate(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!bool {
        if (h & zst_bit != 0) return error.AccessDenied;
        return cast(ctx).inner.allocate(h, len);
    }
    fn syncData(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
        if (h & zst_bit != 0) return error.AccessDenied;
        return cast(ctx).inner.syncData(h);
    }
};

/// One record as it lies in a segment, checked against its CRC.
const Raw = struct {
    typ: u8,
    lsn: u64,
    ts: i64,
    payload: []const u8,
    len: u64,
};

const Parse = union(enum) {
    /// A whole record that passed its CRC.
    record: Raw,
    /// Not a whole record below the limit: too few bytes, or a length
    /// field that runs past the limit.
    short,
    /// A length above `max_record_len`: never believed.
    too_long,
    /// All bytes present, CRC wrong.
    bad_crc,
};

fn parseAt(w: *Window, gpa: Allocator, store: Storage, h: Storage.Handle, at: u64, limit: u64, max_len: u32) (Storage.Error || error{OutOfMemory})!Parse {
    const hdr = (try w.get(gpa, store, h, at, rec_header_len, limit)) orelse return .short;
    const len = std.mem.readInt(u32, hdr[5..9], .little);
    if (len > max_len) return .too_long;
    const rec_len = rec_header_len + @as(u64, len);
    const rec = (try w.get(gpa, store, h, at, rec_len, limit)) orelse return .short;
    if (crc32c(rec[4..]) != std.mem.readInt(u32, rec[0..4], .little)) return .bad_crc;
    return .{ .record = .{
        .typ = rec[4],
        .lsn = std.mem.readInt(u64, rec[9..17], .little),
        .ts = std.mem.readInt(i64, rec[17..25], .little),
        .payload = rec[rec_header_len..],
        .len = rec_len,
    } };
}

/// The offset just past the last nonzero byte in `[from, to)`, or `from`
/// when every byte there is zero.
fn lastNonZero(store: Storage, h: Storage.Handle, from: u64, to: u64) Storage.Error!u64 {
    var buf: [16 * 1024]u8 = undefined;
    var last = from;
    var at = from;
    while (at < to) {
        const want: usize = @intCast(@min(buf.len, to - at));
        const n = try store.pread(h, buf[0..want], at);
        if (n == 0) break;
        if (std.mem.findLastNone(u8, buf[0..n], &.{0})) |i| last = at + i + 1;
        at += n;
    }
    return last;
}

/// `parseAt` for the previous format: a 9-byte record header, no LSN, no
/// timestamp (both 0 in the result).
fn parseLegacyAt(w: *Window, gpa: Allocator, store: Storage, h: Storage.Handle, at: u64, limit: u64, max_len: u32) (Storage.Error || error{OutOfMemory})!Parse {
    const hdr = (try w.get(gpa, store, h, at, legacy_rec_header_len, limit)) orelse return .short;
    const len = std.mem.readInt(u32, hdr[5..9], .little);
    if (len > max_len) return .too_long;
    const rec_len = legacy_rec_header_len + @as(u64, len);
    const rec = (try w.get(gpa, store, h, at, rec_len, limit)) orelse return .short;
    if (crc32c(rec[4..]) != std.mem.readInt(u32, rec[0..4], .little)) return .bad_crc;
    return .{ .record = .{ .typ = rec[4], .lsn = 0, .ts = 0, .payload = rec[legacy_rec_header_len..], .len = rec_len } };
}

fn hashPayload(hh: *std.hash.Wyhash, payload: []const u8) void {
    var lb: [4]u8 = undefined;
    std.mem.writeInt(u32, &lb, @intCast(payload.len), .little);
    hh.update(&lb);
    hh.update(payload);
}

const HeaderCheck = enum { ok, short, mismatch, unsupported };

/// Whether a segment's header is the one the manifest promises: its id and
/// the LSN of its first record.
fn checkHeader(store: Storage, h: Storage.Handle, id: u64, base_lsn: u64) Storage.Error!HeaderCheck {
    var flags: u32 = 0;
    return checkHeaderFlags(store, h, id, base_lsn, &flags);
}

/// `checkHeader`, and the header's flags when it is `.ok`.
fn checkHeaderFlags(store: Storage, h: Storage.Handle, id: u64, base_lsn: u64, flags: *u32) Storage.Error!HeaderCheck {
    var hdr: [segment_header_len]u8 = undefined;
    var got: usize = 0;
    while (got < hdr.len) {
        const n = try store.pread(h, hdr[got..], got);
        if (n == 0) break;
        got += n;
    }
    if (got < 8) return .short;
    if (!std.mem.eql(u8, hdr[0..4], seg_magic)) return .mismatch;
    if (std.mem.readInt(u32, hdr[4..8], .little) != format_version) return .unsupported;
    if (got < hdr.len) return .short;
    if (crc32c(hdr[0..36]) != std.mem.readInt(u32, hdr[36..40], .little)) return .mismatch;
    if (std.mem.readInt(u64, hdr[8..16], .little) != id) return .mismatch;
    if (std.mem.readInt(u64, hdr[16..24], .little) != base_lsn) return .mismatch;
    const f = std.mem.readInt(u32, hdr[32..36], .little);
    if (f & ~flag_compacted != 0) return .unsupported;
    flags.* = f;
    return .ok;
}

// ── public API ───────────────────────────────────────────────────────────────

/// Where a record starts: a segment and a byte offset in it. Positions are
/// stable for as long as the segment exists, so a consumer can persist one
/// and resume from it after a restart (`Log.iterator`). Only positions this
/// log produced are meaningful.
pub const Position = struct {
    segment: u64,
    offset: u64,
    /// The LSN of the record that starts here (for a position at the live
    /// end: the next LSN). Every position the log hands out has it; one a
    /// caller builds by hand may leave it out. With it, an iterator started
    /// here checks that this record is still there — after compaction or a
    /// rewrite it is not — and finds its place by `seek` instead.
    lsn: ?u64 = null,

    /// The same place in the file (the LSN is not compared).
    pub fn eql(a: Position, b: Position) bool {
        return a.segment == b.segment and a.offset == b.offset;
    }
};

pub const Record = struct {
    /// Where this record starts.
    pos: Position,
    /// Where the record after it starts — the position to persist once this
    /// record has been consumed.
    next: Position,
    /// This record's log sequence number.
    lsn: u64,
    /// The timestamp it was appended with.
    ts: i64,
    /// Valid until the iterator's next call.
    payload: []const u8,
};

/// What `append` returns: where the record went. For `appendMany`, the
/// first record of the batch; the rest follow at consecutive LSNs.
/// One record of `appendEntries`: its timestamp and payload.
pub const Entry = struct {
    ts: i64,
    payload: []const u8,
};

pub const Appended = struct {
    pos: Position,
    lsn: u64,
};

/// Where a reader found the log damaged, and how (`Iterator.damage`).
pub const Damage = struct {
    segment: u64,
    /// Where the bad bytes start (0: the segment header).
    offset: u64,
    reason: Reason,

    pub const Reason = enum {
        /// The header is not this segment's: wrong magic, id, base LSN or CRC.
        bad_header,
        /// A record's CRC or length does not check out.
        bad_record,
        /// A record that checks out carries the wrong LSN.
        lsn_out_of_sequence,
        /// The seal disagrees with the segment it closes.
        bad_seal,
        /// A closed segment ends without a seal: it lost its tail.
        missing_seal,
        /// Bytes follow a seal.
        bytes_after_seal,
        /// The segment is shorter than where the reader stood.
        truncated,
        /// A record's length field is over this open's `Options.max_record_len`
        /// (L5): distinct from `bad_record` because it is not necessarily
        /// damage — a record legitimately written under a larger
        /// `max_record_len`, since read since, reads exactly like this too.
        /// Nothing on disk says which; check whether `max_record_len` changed
        /// before assuming corruption.
        record_too_long,
    };
};

/// The LSNs a recovering reader stepped over: `from_lsn` … `to_lsn`,
/// inclusive. Null where the damage hides the bound — no record read in
/// that segment yet, or no later segment to bound it.
pub const Gap = struct {
    from_lsn: ?u64,
    to_lsn: ?u64,
};

/// What `Log.verify` found.
pub const VerifyReport = struct {
    /// Live segments at the end of the walk.
    segments: usize = 0,
    /// Data records read intact.
    records: u64 = 0,
    /// The LSN of the last record read, 0 for none.
    last_lsn: u64 = 0,
    /// Every damage met, in log order.
    damage: std.ArrayList(Damage) = .empty,
    /// The LSNs stepped over at each, parallel to `damage`.
    gaps: std.ArrayList(Gap) = .empty,

    pub fn clean(r: *const VerifyReport) bool {
        return r.damage.items.len == 0;
    }

    pub fn deinit(r: *VerifyReport, gpa: Allocator) void {
        r.damage.deinit(gpa);
        r.gaps.deinit(gpa);
    }
};

/// What `Log.enforceRetention` keeps. Null keeps everything on that count.
pub const Retention = struct {
    /// The most bytes the log's segment files may take.
    max_bytes: ?u64 = null,
    /// The oldest a segment's newest record may be, in the timestamps' unit.
    max_age: ?i64 = null,
};

/// How long data fsyncs took (`Options.monotonic_ns`): bucket `i` counts
/// those under 2^i microseconds, the last one everything longer — etcd's
/// `wal_fsync_duration_seconds`, in powers of two.
pub const SyncLatency = struct {
    buckets: [24]u64 = @splat(0),
    count: u64 = 0,
    total_ns: u64 = 0,
    max_ns: u64 = 0,

    fn record(l: *SyncLatency, ns: u64) void {
        const us = ns / std.time.ns_per_us;
        const i: usize = if (us == 0) 0 else @min(l.buckets.len - 1, std.math.log2_int(u64, us) + 1);
        l.buckets[i] += 1;
        l.count += 1;
        l.total_ns += ns;
        l.max_ns = @max(l.max_ns, ns);
    }

    /// An upper bound, in microseconds, under which at least the fraction
    /// `q` of the fsyncs fell: the bound of the first bucket that reaches it.
    pub fn quantileUpperUs(l: SyncLatency, q: f64) u64 {
        if (l.count == 0) return 0;
        const want: u64 = @intFromFloat(@ceil(q * @as(f64, @floatFromInt(l.count))));
        var seen: u64 = 0;
        for (l.buckets, 0..) |n, i| {
            seen += n;
            if (seen >= want) return @as(u64, 1) << @intCast(i);
        }
        return std.math.maxInt(u64);
    }
};

/// What `Log.stats` reports: counters since `open`, gauges now.
pub const Stats = struct {
    /// `append` calls (a batch is one).
    appends: u64 = 0,
    records: u64 = 0,
    /// Record bytes written, headers included.
    bytes: u64 = 0,
    /// Data fsyncs: syncs of appended records, and of seals.
    syncs: u64 = 0,
    rotations: u64 = 0,
    segments_dropped: u64 = 0,
    compactions: u64 = 0,
    records_compacted_away: u64 = 0,
    compressions: u64 = 0,
    /// A `compress` refused because the decoded `.zst` did not read back the
    /// same bytes as the raw segment (L2): the raw segment is kept, the bad
    /// `.zst` deleted. Should stay 0; the encoder is a young zig-libs port.
    compress_verify_failed: u64 = 0,
    bytes_cut_on_open: u64 = 0,
    segments: usize = 0,
    next_lsn: u64 = 0,
    durable_lsn: u64 = 0,
    /// Bytes in the active segment, 0 without one.
    active_bytes: u64 = 0,
    sync_latency: SyncLatency = .{},
};

pub const SeekError = IterError || error{OutOfMemory};

pub const CompactError = IterError || error{
    OutOfMemory,
    Poisoned,
    ReadOnly,
    /// Rewriting a compressed segment: see `CompressError`.
    BadCompressOptions,
    /// Not a live segment, or the newest.
    NotCompactable,
};

/// What `compact` did.
pub const CompressError = Storage.Error || error{
    OutOfMemory,
    Poisoned,
    ReadOnly,
    /// Not a live segment, or the newest (it is still written to).
    NotCompressible,
    SegmentGone,
    /// The segment's file is shorter than it was a moment ago.
    Corrupt,
    /// `Options.compression` names a level or frame size zstd refuses.
    BadCompressOptions,
    /// L2: the `.zst` `compress` just wrote does not decode back to the same
    /// bytes as the raw segment. The raw segment is untouched and the bad
    /// `.zst` deleted (`Stats.compress_verify_failed` counts it) — not a
    /// storage fault (that is `Corrupt`/a `Storage.Error`), but a wrong,
    /// self-consistent stream: the class of bug a checksum inside the frame
    /// cannot catch, exactly what migration's own read-back-and-compare
    /// guards against on the other conversion path in this file.
    CompressVerifyFailed,
};

pub const CompressStats = struct {
    bytes_before: u64 = 0,
    bytes_after: u64 = 0,
};

/// How `compress` (and `compact`, rewriting a compressed segment) compresses.
pub const CompressOptions = struct {
    /// zstd's level: 1 … 22, or negative for faster.
    level: i32 = 3,
    /// Bytes of segment per independent zstd frame. A read decodes the
    /// frames it touches, so a seek costs up to one frame; smaller frames
    /// compress a little worse.
    frame_size: u32 = 256 * 1024,
};

pub const CompactStats = struct {
    kept: u64 = 0,
    dropped: u64 = 0,
    bytes_before: u64 = 0,
    bytes_after: u64 = 0,
};

pub const LockPolicy = enum {
    /// Hold an exclusive advisory lock on `LOCK` from `open` to `close`.
    exclusive,
    /// No cross-process exclusion. Only for a caller that excludes a second
    /// writer some other way.
    none,
};

pub const ReadOnlyOptions = struct {
    /// As `Options.max_record_len`: the largest length field the reader will
    /// believe. Use the writer's value.
    max_record_len: u32 = 1 << 20,
};

pub const Options = struct {
    /// Create an empty log when there is none. Off by default, so a log
    /// whose `MANIFEST` went missing is reported rather than silently
    /// restarted over the segment files still beside it.
    create: bool = false,
    lock: LockPolicy = .exclusive,
    /// The largest payload `append` accepts and the largest length field a
    /// reader will believe. A corrupt length can therefore never make a
    /// reader allocate more than this.
    max_record_len: u32 = 1 << 20,
    /// The clock `append` and `appendMany` stamp records with, and `rotate`
    /// stamps a segment's creation with. Null stamps 0; `appendAt` takes the
    /// caller's own time. The unit is the caller's (egw-hub: epoch seconds).
    /// Times need not be monotonic: a seal records their range, not order.
    now: ?*const fn () i64 = null,
    /// How far `append`/`appendAt`/`appendMany`/`appendEntries` trust a
    /// timestamp (L3, egw-audit-2026-09-27): one absurd value — a caller's
    /// bug, not necessarily a crash — otherwise becomes the segment's
    /// permanent seal `max_ts`/`min_ts` (a plain running min/max has no way
    /// to un-see it), which makes `seekTime` match that one record for every
    /// real `t` from then on and can wedge `enforceRetention`'s age policy
    /// on that segment, and every older one behind it, forever. `.unbounded`
    /// (the default) changes nothing: times need not be monotonic, and a
    /// caller that never passes a wild `ts` sees no difference.
    timestamps: TimestampPolicy = .unbounded,
    /// When an append is made durable. See `SyncPolicy`.
    sync: SyncPolicy = .always,
    /// A monotonic clock in nanoseconds. With it, `stats()` includes the
    /// latency of every data fsync (`SyncLatency`); without it, the log has
    /// no clock of its own (the simulator stays deterministic).
    monotonic_ns: ?*const fn () u64 = null,
    /// Bytes between two entries of a segment's sparse index (`seek`,
    /// `seekTime`). 0: no index — a seek walks the segment from its start.
    index_interval: u32 = 4096,
    /// Rotate on its own, to the newest id + 1, before an append that would
    /// take the active segment past `max_bytes`, or once the segment is
    /// `max_age` old by `now`. With it set, an append to a log with no
    /// segment creates segment 1. Null: segments change only by `rotate`.
    auto_rotate: ?AutoRotate = null,
    /// Reserve the active segment's space on disk this many bytes at a time
    /// (`kv.Storage.allocate`, `fallocate`): at `rotate`, and whenever an
    /// append would run past the reservation. 0: never. Two things follow.
    /// A full disk is `error.NoSpaceLeft` from the reservation — refused
    /// cleanly, the log not poisoned — rather than from a write halfway into
    /// a record. And appends into reserved zeros do not grow the file, so
    /// their sync has no size to record: on ext4 an `.always` append loop
    /// went from about 305 to about 850 a second (2026-09-27, NVMe). The
    /// reserved zeros are cut off when the segment is sealed, and a zero
    /// tail on `open` is taken for the end of the data, not for damage. A
    /// backend or filesystem without preallocation simply goes without.
    preallocate: u64 = 0,
    /// What `compress` does to a closed segment.
    compression: CompressOptions = .{},
    /// A log in the previous format version: `.auto` converts it inside
    /// `open` (see `MigrationReport`); `.refuse` makes `open` return
    /// `error.NeedsMigration` and leaves it as it is.
    migration: MigrationPolicy = .auto,
    /// The previous format stored no timestamp. Given this, a migrated
    /// record gets the one it returns for its payload; without it, 0.
    legacy_ts: ?*const fn (payload: []const u8) i64 = null,
    /// Told after each migrated segment, for a caller that shows progress:
    /// a large log takes a while (egw-hub: 285 MB in about 15 s).
    on_migration_progress: ?*const fn (ctx: ?*anyopaque, p: MigrationProgress) void = null,
    migration_ctx: ?*anyopaque = null,
    /// Filled by `open` whenever it migrates or refuses to, success or not —
    /// the one place a failed migration's details reach the caller.
    migration_report: ?*MigrationReport = null,
};

pub const MigrationPolicy = enum { auto, refuse };

pub const MigrationProgress = struct {
    /// Segments done, of `segments`.
    done: u64,
    segments: u64,
    records: u64,
};

/// What `open` did to a log in the previous format. On success the log is
/// in the current format, every record kept with its bytes, and the old
/// segments deleted (back up the directory before an upgrade: they are not
/// kept). Damaged old data is refused before anything is written: the log
/// stays as it was, and `failure` says where.
pub const MigrationReport = struct {
    from_version: u32 = 0,
    to_version: u32 = format_version,
    segments: u64 = 0,
    records: u64 = 0,
    /// A torn record at the end of the newest segment, cut as `open` cuts
    /// one: the previous writer died mid-append. Not damage.
    torn_bytes: u64 = 0,
    bytes_before: u64 = 0,
    bytes_after: u64 = 0,
    /// With `Options.monotonic_ns`; 0 without a clock.
    duration_ns: u64 = 0,
    /// Positions saved before the migration: from version 1, which had no
    /// LSNs, `Log.translatePosition` turns one into its place now.
    positions: enum { unchanged, translate_from_v1 } = .unchanged,
    failure: ?MigrationFailure = null,
};

pub const MigrationFailure = struct {
    segment: u64,
    offset: u64,
    reason: enum {
        /// A record whose CRC fails, or a length past the end, in a closed
        /// segment or before the end of the newest.
        bad_record,
        /// The seal disagrees with the records before it, or is missing.
        bad_seal,
        /// The header names another segment, or the file is missing.
        bad_header,
        /// A record longer than `Options.max_record_len`.
        too_long,
        /// The converted segment did not read back as the original.
        mismatch,
    },
};

/// When `Options.auto_rotate` starts a new segment. A segment with no record
/// yet is never rotated away, so a single batch larger than `max_bytes` goes
/// whole into a fresh segment rather than being split.
pub const AutoRotate = struct {
    max_bytes: ?u64 = null,
    /// In the unit of `Options.now`, which it needs.
    max_age: ?i64 = null,
};

/// When appended records reach stable storage. Whatever the policy, a
/// reader of the writer's own `Log` sees only what has, and `rotate` makes
/// everything before its seal durable.
pub const SyncPolicy = union(enum) {
    /// `append` returns after its own `fsync`. The default: nothing an
    /// `append` returned for is lost.
    always,
    /// `fsync` once at least this many bytes are waiting. An `append` that
    /// did not cross the line returns before its record is durable.
    every_bytes: u64,
    /// Only `Log.sync` (and `rotate`) make records durable: the caller
    /// batches — once per poll round, per timer tick, per client ack.
    manual,
};

/// How `Options.timestamps` treats a caller's `ts` (L3). A range's `min`/
/// `max` are inclusive, in the same unit as every other timestamp.
pub const TimestampPolicy = union(enum) {
    /// Any `i64`, unchanged: today's behaviour, and the module's original
    /// contract ("times need not be monotonic").
    unbounded,
    /// A `ts` outside `[min, max]` refuses the whole append with
    /// `error.TimestampOutOfRange` — nothing is written, so a batch is
    /// refused or accepted as one (like the `max_record_len` check already
    /// does for length).
    refuse: Range,
    /// A `ts` outside `[min, max]` is pulled to the nearer bound before it
    /// reaches the seal, the sparse index, or the stored record.
    clamp: Range,

    pub const Range = struct {
        min: i64 = std.math.minInt(i64),
        max: i64 = std.math.maxInt(i64),
    };
};

pub const OpenError = Storage.Error || error{
    /// A manifest or the newest segment is structurally invalid in a way a
    /// torn write cannot produce.
    Corrupt,
    /// Another writer holds the log.
    Locked,
    /// There is no log here and `Options.create` is off.
    NotFound,
    /// A manifest or segment of a format version, or with a feature, this
    /// build does not read.
    UnsupportedVersion,
    /// The log is in the previous format and `Options.migration` is
    /// `.refuse`.
    NeedsMigration,
    /// A read-only open of a log in the previous format, or one a writer
    /// is migrating: try again once the writer's `open` has finished.
    MigrationInProgress,
    /// The previous format's data is damaged: nothing was migrated
    /// (`Options.migration_report` says where).
    MigrationFailed,
    /// L5: the active (newest, unsealed) segment holds a record whose length
    /// is over this open's `Options.max_record_len`. Refused rather than cut
    /// as a torn tail — a torn write's garbage length and a real record
    /// written under a larger `max_record_len` are the same shape on disk,
    /// and treating this one as a torn tail would truncate, silently and
    /// irreversibly, whatever a caller actually wrote there. Raise
    /// `max_record_len` back (or accept the data loss deliberately, by
    /// opening as read-only and repairing by hand) before opening for
    /// appends again.
    RecordTooLongForOptions,
};

/// What `Log.rebuildManifest` refuses (L4).
pub const RebuildError = Storage.Error || error{
    /// No segment ids were given.
    NoSegments,
    /// More ids than one manifest can name (`max_manifest_ids`).
    TooManySegments,
    /// A `MANIFEST` already opens here: `rebuildManifest` never overwrites
    /// one `Log.open` could still read.
    ManifestPresent,
    /// A named id has neither `seg-<id>.log` nor `seg-<id>.zst`.
    SegmentGone,
    /// `ids` was not strictly increasing; a segment's header does not name
    /// the id it was found under, or is otherwise structurally invalid; a
    /// non-last segment has no readable seal; or two segments' LSN ranges
    /// disagree (a gap or an overlap).
    Corrupt,
    /// A segment's header names a version or a flag this build does not
    /// read.
    UnsupportedVersion,
};

pub const AppendError = Storage.Error || error{
    Poisoned,
    /// The log was opened with `openReadOnly`.
    ReadOnly,
    /// The log has no segment that accepts appends: it is new, or its newest
    /// segment is sealed. `rotate` first.
    NoActiveSegment,
    RecordTooLarge,
    /// See `RotateError.OrphanSegment` — `Options.auto_rotate` can reach it
    /// through `append` too.
    OrphanSegment,
    /// `Options.timestamps = .refuse` and a record's `ts` is outside its
    /// range (L3): nothing in the batch was written.
    TimestampOutOfRange,
};

pub const RotateError = Storage.Error || error{
    Poisoned,
    ReadOnly,
    /// Segment ids only grow, and a sealed segment never reopens.
    NonMonotonic,
    /// A file already sits under the name this id would rotate to, and it is
    /// not empty. Only reachable on a manifest `open` just (re)created empty
    /// (L1): a normal manifest never lets an already-used id reach `rotate`
    /// in the first place (`NonMonotonic` catches that). The log is poisoned:
    /// this is not a transient failure to retry, since retrying finds the
    /// same orphan file. Most likely a partial restore that copied segments
    /// but lost `MANIFEST` — restore the whole state tree again, or repair
    /// `MANIFEST` by hand from SPEC.md's layout.
    OrphanSegment,
};

pub const DropError = Storage.Error || error{ Poisoned, ReadOnly };

pub const IterError = Storage.Error || error{
    /// A record failed its CRC, a length ran past the segment, a closed
    /// segment ended without its seal, its seal disagrees with what was
    /// read, or an LSN is out of sequence. Never repaired by the reader.
    Corrupt,
    /// The position is in a segment that has been dropped.
    SegmentGone,
    /// The position is inside a segment's header, so it cannot be one this
    /// log produced.
    InvalidPosition,
    /// A segment of a format version this build does not read.
    UnsupportedVersion,
    /// A read-only log whose writer has begun migrating it to the current
    /// format: open it again once that writer's `open` has finished.
    MigrationInProgress,
};

pub const Log = struct {
    gpa: Allocator,
    store: Storage,
    opts: Options,
    lock_handle: ?Storage.Handle = null,
    /// Live segment ids, strictly increasing; the last is the newest.
    live: std.ArrayList(u64) = .empty,
    /// The LSN of each live segment's first record, parallel to `live`.
    live_lsn: std.ArrayList(u64) = .empty,
    /// Each live segment's form on disk (`form_raw`, `form_zstd`), parallel
    /// to `live`.
    live_form: std.ArrayList(u8) = .empty,
    /// The storage `store` wraps, to read compressed segments; owned.
    segs: ?*SegStore = null,
    /// Dropped from the log; the file may still exist until deleted.
    pending: std.ArrayList(u64) = .empty,
    /// The newest segment while it accepts appends. Null when the log has no
    /// segment, or when its newest segment is sealed.
    active: ?Active = null,
    /// The LSN the next appended record gets.
    next_lsn: u64 = 1,
    /// LSN of the first record not yet durable, or `next_lsn` when all are.
    synced_next_lsn: u64 = 1,
    poisoned: bool = false,
    /// Opened with `openReadOnly`: no lock, no writes, and the manifest is
    /// re-read to follow the writer.
    read_only: bool = false,
    /// Bytes `open` cut from the newest segment: a torn record, or a torn
    /// header of a segment whose creation it finished.
    cut_on_open: u64 = 0,
    /// Scratch for encoding records and the manifest.
    scratch: std.ArrayList(u8) = .empty,
    /// What `stats` reports; its gauges are filled in when asked.
    counters: Stats = .{},
    /// Syncs begun (`syncBegin`) and not yet finished — `Concurrent` runs
    /// its fsync outside the lock.
    syncs_in_flight: u32 = 0,
    /// Handles of segments rotated away while a sync was in flight: closed
    /// when the last one finishes, never under a running fsync.
    retired: std.ArrayList(Storage.Handle) = .empty,
    /// The manifest read was the previous format's (no LSNs yet in `live_lsn`).
    legacy_manifest: bool = false,
    /// What `open` migrated, if it did.
    migrated: ?MigrationReport = null,

    const Active = struct {
        id: u64,
        handle: Storage.Handle,
        /// The next record goes here.
        end: u64,
        /// Every byte below this is synced. `end` itself under `.always`.
        synced: u64,
        /// Where the reserved space ends (`Options.preallocate`). Above `end`,
        /// the file's length, and the bytes between are zeros nothing wrote;
        /// at or below `end`, nothing is reserved.
        reserved: u64,
        tally: Tally,
        /// The header's creation stamp (`Options.now` at `rotate`).
        created: i64,
        /// The segment's sparse index so far, written out when it is sealed.
        index: SparseIndex = .{},
    };

    /// Open the log in `store`'s directory. Repairs the newest segment's
    /// tail, finishes a creation or a drop a crash interrupted, and leaves
    /// every closed segment unread.
    pub fn open(gpa: Allocator, store: Storage, opts: Options) OpenError!Log {
        var log: Log = .{ .gpa = gpa, .store = store, .opts = opts };
        errdefer log.release();
        log.segs = try SegStore.create(gpa, store);
        log.store = log.segs.?.storage();

        if (opts.lock == .exclusive) {
            const lh = try store.open(lock_name, .open_or_create);
            const held = store.tryLockExclusive(lh) catch |e| {
                store.close(lh);
                return e;
            };
            if (!held) {
                store.close(lh);
                return error.Locked;
            }
            log.lock_handle = lh;
        }

        try log.loadManifest();
        if (log.needsMigration()) {
            if (opts.migration == .refuse) {
                if (opts.migration_report) |r| r.* = .{ .from_version = legacy_version };
                return error.NeedsMigration;
            }
            try log.migrate();
        }
        try log.finishDrops();
        // A compaction a crash interrupted before its rename: the old
        // segment is intact, and this is nobody's file.
        store.delete(compact_tmp) catch |e| switch (e) {
            error.FileNotFound => {},
            else => |x| return x,
        };
        try log.finishCompressions();
        try log.openNewest();
        return log;
    }

    /// Open the log in `store`'s directory for reading only, beside whatever
    /// writer may hold it. Takes no lock and touches no file: a missing log
    /// is `error.NotFound` and leaves the directory as it was. See the module
    /// doc for what a reader can and cannot know.
    pub fn openReadOnly(gpa: Allocator, store: Storage, opts: ReadOnlyOptions) OpenError!Log {
        var log: Log = .{
            .gpa = gpa,
            .store = store,
            .opts = .{ .lock = .none, .max_record_len = opts.max_record_len },
            .read_only = true,
        };
        errdefer log.release();
        log.segs = try SegStore.create(gpa, store);
        log.store = log.segs.?.storage();
        try log.loadManifest();
        if (log.needsMigration()) return error.MigrationInProgress;
        return log;
    }

    /// Rebuild a lost or unreadable `MANIFEST` from `ids`' own segment
    /// headers and seals (audit finding L4, egw-audit-2026-09-27: a torn or
    /// corrupt `MANIFEST` otherwise has no recovery path in the library or
    /// its tools — every other kind of damage does). `ids`, ascending, are
    /// the segments to include, in the order they form the log. `kv.Storage`
    /// has no directory listing (zig-libs request, `ziglibs-requests.md`,
    /// module `kv` — the same gap `open`'s own design already declines to
    /// work around, since a log that derived its segments from file names
    /// would adopt any stray file that looked like one), so this cannot
    /// discover `ids` by itself; a caller that can list the directory (an
    /// operator's `ls seg-*.log seg-*.zst`, or `egw-hub`'s
    /// `seglog_cli.manifestRebuild`) supplies them.
    ///
    /// Every id but the last must be a closed segment: its header already
    /// carries its own first LSN (the format's base-LSN field), and its seal
    /// gives its last — checked to be exactly one less than the next
    /// segment's base LSN. Segments that disagree (a gap, an overlap, a
    /// non-last segment with no readable seal) refuse the whole rebuild
    /// (`error.Corrupt`) rather than write a manifest a reader would later
    /// trust over a wrong LSN sequence — the same "refuse instead of guess"
    /// choice `rotate`'s L1 fix makes. The last id may be closed or the
    /// writer's own still-active segment (no seal expected there).
    ///
    /// Refuses outright (`error.ManifestPresent`) if a `MANIFEST` already
    /// opens here — this is for a directory `Log.open` cannot read, not a
    /// way to override one it can. Writes nothing else: no `.idx` files (the
    /// next `open`'s walk rebuilds one that is missing or wrong regardless),
    /// no pending drops (a rebuild cannot know what a crash left mid-drop; a
    /// leftover file from one just outlives this log instead of being swept
    /// — harmless, `dropBefore` never adopts a stray file either).
    ///
    /// This checks each segment's own header and seal, never a single data
    /// record's CRC or LSN sequence inside a segment: run `Log.verify` after
    /// a rebuild for that.
    pub fn rebuildManifest(gpa: Allocator, store: Storage, ids: []const u64) RebuildError!void {
        if (ids.len == 0) return error.NoSegments;
        if (ids.len > max_manifest_ids) return error.TooManySegments;
        for (ids[1..], ids[0 .. ids.len - 1]) |b, a| if (b <= a) return error.Corrupt;

        // Never overwrite a manifest `Log.open` could still read.
        if (store.open(manifest_name, .read_only)) |h| {
            store.close(h);
            return error.ManifestPresent;
        } else |e| switch (e) {
            error.FileNotFound => {},
            else => |x| return x,
        }

        var ss = try SegStore.create(gpa, store);
        defer ss.destroy();
        const wrapped = ss.storage();

        const first_lsns = try gpa.alloc(u64, ids.len);
        defer gpa.free(first_lsns);
        const forms = try gpa.alloc(u8, ids.len);
        defer gpa.free(forms);

        // Every named segment must exist before any is judged: a wrong id in
        // the list is `SegmentGone` whatever its position, not hidden behind
        // an earlier segment's `Corrupt`.
        for (ids, 0..) |id, i| {
            var nb: [seg_name_len]u8 = undefined;
            const raw_name = segName(&nb, id);
            var zb: [seg_name_len]u8 = undefined;
            forms[i] = blk: {
                if (store.open(raw_name, .read_only)) |h0| {
                    store.close(h0);
                    break :blk form_raw;
                } else |e0| switch (e0) {
                    error.FileNotFound => {},
                    else => |x| return x,
                }
                if (store.open(zstName(&zb, id), .read_only)) |h1| {
                    store.close(h1);
                    break :blk form_zstd;
                } else |e1| switch (e1) {
                    error.FileNotFound => return error.SegmentGone,
                    else => |x| return x,
                }
            };
        }

        var prev_last_lsn: ?u64 = null;
        for (ids, 0..) |id, i| {
            var nb: [seg_name_len]u8 = undefined;
            const raw_name = segName(&nb, id);

            // `wrapped` reads whichever file is really there (`SegStore`
            // decodes a `.zst` transparently), so the header/seal parsing
            // below is the same regardless of `forms[i]`.
            const h = try wrapped.open(raw_name, .read_only);
            defer wrapped.close(h);
            var hdr: [segment_header_len]u8 = undefined;
            wrapped.preadFull(h, &hdr, 0) catch |e| switch (e) {
                error.Corrupt => return error.Corrupt,
                else => |x| return x,
            };
            if (!std.mem.eql(u8, hdr[0..4], seg_magic)) return error.Corrupt;
            if (std.mem.readInt(u32, hdr[4..8], .little) != format_version) return error.UnsupportedVersion;
            if (crc32c(hdr[0..36]) != std.mem.readInt(u32, hdr[36..40], .little)) return error.Corrupt;
            if (std.mem.readInt(u64, hdr[8..16], .little) != id) return error.Corrupt;
            const base_lsn = std.mem.readInt(u64, hdr[16..24], .little);
            const flags = std.mem.readInt(u32, hdr[32..36], .little);
            if (flags & ~flag_compacted != 0) return error.UnsupportedVersion;
            // LSNs start at 1 and never go back (as `loadManifest` checks).
            if (base_lsn == 0) return error.Corrupt;
            if (prev_last_lsn) |p| if (base_lsn != p +% 1) return error.Corrupt;

            // The seal, if this segment has one: the last record of a closed
            // segment always lies exactly here (a closed segment ends at its
            // seal — see SPEC.md, *Preallocation*), never checked against a
            // walked tally (an empty `Tally`/`null` — `sealAgrees` then only
            // checks the seal's own self-consistency and its offset).
            const size = try wrapped.size(h);
            var seal_last_lsn: ?u64 = null;
            if (size >= segment_header_len + rec_header_len + seal_payload_len) {
                const seal_at = size - (rec_header_len + seal_payload_len);
                var w: Window = .{};
                defer w.deinit(gpa);
                switch (try parseAt(&w, gpa, wrapped, h, seal_at, size, seal_payload_len)) {
                    .record => |raw| if (raw.typ == rec_seal and sealAgrees(raw, null, seal_at)) {
                        if (Seal.decode(raw.payload)) |s| seal_last_lsn = s.last_lsn;
                    },
                    else => {},
                }
            }
            if (seal_last_lsn == null and i + 1 != ids.len) return error.Corrupt;

            first_lsns[i] = base_lsn;
            prev_last_lsn = seal_last_lsn;
        }

        // The same layout `commitManifest` writes, with no pending drops.
        const size = man_fixed + man_entry_len * ids.len + man_crc_len;
        const b = try gpa.alloc(u8, size);
        defer gpa.free(b);
        @memset(b, 0);
        @memcpy(b[0..4], man_magic);
        std.mem.writeInt(u32, b[4..8], format_version, .little);
        std.mem.writeInt(u32, b[8..12], @intCast(ids.len), .little);
        std.mem.writeInt(u32, b[12..16], 0, .little);
        var off: usize = man_fixed;
        for (ids, first_lsns, forms) |id, first, form| {
            std.mem.writeInt(u64, b[off..][0..8], id, .little);
            std.mem.writeInt(u64, b[off + 8 ..][0..8], first, .little);
            b[off + 16] = form;
            off += man_entry_len;
        }
        std.mem.writeInt(u32, b[off..][0..4], crc32c(b[0..off]), .little);

        const h = try store.open(manifest_tmp, .create_truncate);
        {
            defer store.close(h);
            try store.writeAll(h, b, 0);
            try store.sync(h);
        }
        try store.rename(manifest_tmp, manifest_name);
        try store.syncDir();
    }

    /// Re-read the manifest, to see segments the writer has rotated to or
    /// dropped since. For a read-only log only — a writer's own view is the
    /// truth, and this returns at once. A reader's iterators call it
    /// themselves at the live end; call it directly to refresh `segments()`.
    /// On failure the previous view is kept.
    pub fn refresh(self: *Log) OpenError!void {
        if (!self.read_only) return;
        var fresh: Log = .{ .gpa = self.gpa, .store = self.store, .opts = self.opts, .read_only = true };
        defer fresh.release();
        try fresh.loadManifest();
        if (fresh.needsMigration()) return error.MigrationInProgress;
        std.mem.swap(std.ArrayList(u64), &self.live, &fresh.live);
        std.mem.swap(std.ArrayList(u64), &self.live_lsn, &fresh.live_lsn);
        std.mem.swap(std.ArrayList(u8), &self.live_form, &fresh.live_form);
        std.mem.swap(std.ArrayList(u64), &self.pending, &fresh.pending);
    }

    pub fn isReadOnly(self: *const Log) bool {
        return self.read_only;
    }

    /// Release every handle and buffer. Iterators must be gone first.
    pub fn close(self: *Log) void {
        self.release();
        self.* = undefined;
    }

    fn release(self: *Log) void {
        if (self.active) |*a| {
            self.store.close(a.handle);
            a.index.deinit(self.gpa);
        }
        self.active = null;
        if (self.lock_handle) |h| self.store.close(h);
        self.lock_handle = null;
        for (self.retired.items) |h| self.store.close(h);
        self.retired.deinit(self.gpa);
        self.live.deinit(self.gpa);
        self.live_lsn.deinit(self.gpa);
        self.live_form.deinit(self.gpa);
        self.pending.deinit(self.gpa);
        self.scratch.deinit(self.gpa);
        if (self.segs) |sg| sg.destroy();
        self.segs = null;
    }

    /// Live segment ids, oldest first.
    pub fn segments(self: *const Log) []const u64 {
        return self.live.items;
    }

    /// The LSN of the first record of live segment `id` (the next LSN, for
    /// a segment that has none yet), or null when `id` is not live.
    pub fn segmentFirstLsn(self: *const Log, id: u64) ?u64 {
        const i = std.mem.findScalar(u64, self.live.items, id) orelse return null;
        return self.live_lsn.items[i];
    }

    pub fn newest(self: *const Log) ?u64 {
        const n = self.live.items.len;
        return if (n == 0) null else self.live.items[n - 1];
    }

    /// The segment appends go to, if any.
    pub fn activeSegment(self: *const Log) ?u64 {
        return if (self.active) |a| a.id else null;
    }

    /// Where the next appended record will start, if the log accepts
    /// appends.
    pub fn end(self: *const Log) ?Position {
        const a = self.active orelse return null;
        return .{ .segment = a.id, .offset = a.end, .lsn = self.next_lsn };
    }

    /// The LSN the next appended record will get. Of a writer only.
    pub fn nextLsn(self: *const Log) u64 {
        return self.next_lsn;
    }

    /// Every record below this LSN is durable. `nextLsn()` unless the sync
    /// policy has let appends run ahead of `fsync`. Of a writer only.
    pub fn durableLsn(self: *const Log) u64 {
        return self.synced_next_lsn;
    }

    /// `fsync` what has been appended and not yet synced; nothing when
    /// nothing is waiting. After a failure the log is poisoned.
    pub fn sync(self: *Log) AppendError!void {
        const t = (try self.syncBegin()) orelse return;
        const t0 = self.clockNs();
        const r = self.store.syncData(t.handle);
        self.syncFinish(t, r, self.clockNs() -| t0);
        return r;
    }

    fn clockNs(self: *const Log) u64 {
        return if (self.opts.monotonic_ns) |f| f() else 0;
    }

    /// A data fsync done, `ns` long (0 without a clock).
    fn countSync(self: *Log, ns: u64) void {
        self.counters.syncs += 1;
        if (self.opts.monotonic_ns != null) self.counters.sync_latency.record(ns);
    }

    /// Counters since `open`, and the log's state now. Of a writer.
    pub fn stats(self: *const Log) Stats {
        var st = self.counters;
        st.bytes_cut_on_open = self.cut_on_open;
        st.segments = self.live.items.len;
        st.next_lsn = self.next_lsn;
        st.durable_lsn = self.synced_next_lsn;
        st.active_bytes = if (self.active) |a| a.end else 0;
        return st;
    }

    /// What a sync begun by `syncBegin` covers.
    const SyncTarget = struct { segment: u64, handle: Storage.Handle, end: u64, lsn: u64 };

    /// Start a sync of everything appended so far, to be run — possibly
    /// without the caller's lock, while more is appended — and then handed to
    /// `syncFinish`. Null when nothing is waiting.
    fn syncBegin(self: *Log) AppendError!?SyncTarget {
        if (self.read_only) return error.ReadOnly;
        if (self.poisoned) return error.Poisoned;
        const a = if (self.active) |act| act else return null;
        if (a.synced == a.end) return null;
        self.syncs_in_flight += 1;
        return .{ .segment = a.id, .handle = a.handle, .end = a.end, .lsn = self.next_lsn };
    }

    /// Record the outcome of a sync `syncBegin` started. Only ever moves the
    /// durable marks forward: a `rotate` in between has already synced the
    /// old segment with its seal.
    fn syncFinish(self: *Log, t: SyncTarget, result: Storage.Error!void, ns: u64) void {
        self.syncs_in_flight -= 1;
        if (result) |_| {
            self.countSync(ns);
            if (self.active) |*a| if (a.id == t.segment) {
                a.synced = @max(a.synced, t.end);
            };
            self.synced_next_lsn = @max(self.synced_next_lsn, t.lsn);
        } else |_| self.poisoned = true;
        if (self.syncs_in_flight == 0) {
            for (self.retired.items) |h| self.store.close(h);
            self.retired.clearRetainingCapacity();
        }
    }

    /// Close a handle — or, while a sync may be running on it, later.
    fn retire(self: *Log, h: Storage.Handle) void {
        if (self.syncs_in_flight == 0) return self.store.close(h);
        self.retired.appendAssumeCapacity(h);
    }

    pub fn isPoisoned(self: *const Log) bool {
        return self.poisoned;
    }

    /// How many bytes `open` cut from the newest segment's tail, counted to
    /// the last nonzero one: zeros past the data are reserved space
    /// (`Options.preallocate`) and not counted. Nonzero means the previous
    /// writer died mid-write — worth a line in a log.
    pub fn bytesCutOnOpen(self: *const Log) u64 {
        return self.cut_on_open;
    }

    fn stamp(self: *const Log) i64 {
        return if (self.opts.now) |f| f() else 0;
    }

    /// `ts` under `Options.timestamps` (L3): unchanged for `.unbounded` and
    /// `.refuse` (a `.refuse` batch already passed its pre-pass, so `ts` is
    /// in range here), pulled into `[min, max]` for `.clamp`.
    fn boundedTs(self: *const Log, ts: i64) i64 {
        return switch (self.opts.timestamps) {
            .unbounded, .refuse => ts,
            .clamp => |c| std.math.clamp(ts, c.min, c.max),
        };
    }

    /// Append one record and `fsync` it before returning where it went. The
    /// record is stamped with `Options.now`.
    pub fn append(self: *Log, payload: []const u8) AppendError!Appended {
        return self.appendManyAt(self.stamp(), &.{payload});
    }

    /// `append` with the caller's timestamp.
    pub fn appendAt(self: *Log, ts: i64, payload: []const u8) AppendError!Appended {
        return self.appendManyAt(ts, &.{payload});
    }

    /// Append several records with one write and one `fsync`. ⚠ Each record
    /// is atomic; the batch is not — a crash may keep any whole-record prefix
    /// of it, and never a part of a record.
    pub fn appendMany(self: *Log, payloads: []const []const u8) AppendError!Appended {
        return self.appendManyAt(self.stamp(), payloads);
    }

    /// `appendMany` with one timestamp, the caller's, for every record.
    pub fn appendManyAt(self: *Log, ts: i64, payloads: []const []const u8) AppendError!Appended {
        const Batch = struct {
            ts: i64,
            payloads: []const []const u8,
            fn len(b: @This()) usize {
                return b.payloads.len;
            }
            fn payload(b: @This(), i: usize) []const u8 {
                return b.payloads[i];
            }
            fn tsOf(b: @This(), _: usize) i64 {
                return b.ts;
            }
        };
        return self.appendBatch(Batch{ .ts = ts, .payloads = payloads });
    }

    /// `appendMany` with each record's own timestamp: an import of records
    /// that already have one, batched into one write and one `fsync`.
    pub fn appendEntries(self: *Log, entries: []const Entry) AppendError!Appended {
        const Batch = struct {
            entries: []const Entry,
            fn len(b: @This()) usize {
                return b.entries.len;
            }
            fn payload(b: @This(), i: usize) []const u8 {
                return b.entries[i].payload;
            }
            fn tsOf(b: @This(), i: usize) i64 {
                return b.entries[i].ts;
            }
        };
        return self.appendBatch(Batch{ .entries = entries });
    }

    fn appendBatch(self: *Log, batch: anytype) AppendError!Appended {
        if (self.read_only) return error.ReadOnly;
        if (self.poisoned) return error.Poisoned;
        const n = batch.len();
        var total: usize = 0;
        for (0..n) |i| {
            const p = batch.payload(i);
            if (p.len > self.opts.max_record_len) return error.RecordTooLarge;
            total += rec_header_len + p.len;
        }
        // ⛔⛔ L3 fix (2026-09-27): `.refuse` checked, and the whole batch
        // refused, before anything (including a possible auto-rotate) has
        // happened — the same "checked before any write" shape as the
        // length check just above. `.clamp`/`.unbounded` need no pre-pass:
        // `boundedTs` is applied per record below, where `ts` reaches the
        // seal, the index and the stored record.
        switch (self.opts.timestamps) {
            .unbounded, .clamp => {},
            .refuse => |r| for (0..n) |i| {
                const ts = batch.tsOf(i);
                if (ts < r.min or ts > r.max) return error.TimestampOutOfRange;
            },
        }
        if (self.opts.auto_rotate) |ar| try self.autoRotate(ar, total);
        const a: *Active = if (self.active) |*act| act else return error.NoActiveSegment;
        const first: Appended = .{ .pos = .{ .segment = a.id, .offset = a.end, .lsn = self.next_lsn }, .lsn = self.next_lsn };
        if (total == 0) return first;

        if (self.opts.index_interval != 0) try a.index.entries.ensureUnusedCapacity(self.gpa, n);
        if (a.end + total > a.reserved) a.reserved = try self.reserve(a.handle, a.reserved, a.end + total);
        try self.scratch.resize(self.gpa, total);
        var off: usize = 0;
        var lsn = self.next_lsn;
        for (0..n) |i| {
            const p = batch.payload(i);
            const len = rec_header_len + p.len;
            encodeRecord(self.scratch.items[off..][0..len], rec_data, lsn, self.boundedTs(batch.tsOf(i)), p);
            off += len;
            lsn += 1;
        }
        self.store.writeAll(a.handle, self.scratch.items, a.end) catch |e| return self.poison(e);
        var rec_off = a.end;
        for (0..n) |i| {
            const rec_lsn = self.next_lsn + i;
            if (self.opts.index_interval != 0) a.index.note(self.opts.index_interval, .{ .lsn = rec_lsn, .offset = rec_off, .max_before = a.tally.maxOrMin() });
            a.tally.add(self.boundedTs(batch.tsOf(i)), rec_lsn);
            rec_off += rec_header_len + batch.payload(i).len;
        }
        a.end += total;
        self.next_lsn = lsn;
        self.counters.appends += 1;
        self.counters.records += n;
        self.counters.bytes += total;
        const due = switch (self.opts.sync) {
            .always => true,
            .every_bytes => |nb| a.end - a.synced >= nb,
            .manual => false,
        };
        if (due) try self.sync();
        return first;
    }

    /// Reserve segment `h`, `have` bytes long, up to at least `need` bytes,
    /// in whole `Options.preallocate` steps; returns its length after. A
    /// failure changes nothing that was written, so an append does not poison
    /// the log over it: a full disk refuses the append before a byte of it
    /// lands. What a failed `fallocate` may have reserved after all is zeros
    /// past the data, which is harmless.
    fn reserve(self: *Log, h: Storage.Handle, have: u64, need: u64) Storage.Error!u64 {
        const step = self.opts.preallocate;
        if (step == 0) return have;
        const want = std.math.mul(u64, std.math.divCeil(u64, need, step) catch unreachable, step) catch need;
        if (try self.store.allocate(h, want)) return want;
        // This backend or filesystem cannot: stop asking.
        self.opts.preallocate = 0;
        return have;
    }

    /// `rotate`'s segment name is taken though the probe found no content
    /// under it: an empty file (L1). Open it — never emptying it — and keep
    /// it only if it is still empty; otherwise the log is poisoned with
    /// `error.OrphanSegment`.
    fn adoptEmpty(self: *Log, seg_name: []const u8) RotateError!Storage.Handle {
        const h = self.store.open(seg_name, .open_or_create) catch |e| return self.poison(e);
        const size = self.store.size(h) catch |e| {
            self.store.close(h);
            return self.poison(e);
        };
        if (size != 0) {
            self.store.close(h);
            self.poisoned = true;
            return error.OrphanSegment;
        }
        return h;
    }

    /// `total`: the bytes the append about to happen will write.
    fn autoRotate(self: *Log, ar: AutoRotate, total: u64) AppendError!void {
        const due = if (self.active) |a| blk: {
            if (a.tally.count == 0) break :blk false;
            if (ar.max_bytes) |m| if (a.end + total > m) break :blk true;
            if (ar.max_age) |age| if (self.stamp() -| a.created >= age) break :blk true;
            break :blk false;
        } else true;
        if (!due) return;
        const id = std.math.add(u64, self.newest() orelse 0, 1) catch return error.NoActiveSegment;
        self.rotate(id) catch |e| return switch (e) {
            error.NonMonotonic => unreachable, // newest + 1 never is
            else => |x| x,
        };
    }

    /// Make `id` the segment appends go to. The current one, if any, is
    /// sealed first. Rotating to the id that is already active does nothing,
    /// so a caller can rotate to "today" unconditionally at startup.
    pub fn rotate(self: *Log, id: u64) RotateError!void {
        if (self.read_only) return error.ReadOnly;
        if (self.poisoned) return error.Poisoned;
        if (self.newest()) |last| {
            if (id < last) return error.NonMonotonic;
            if (id == last) {
                if (self.active != null) return;
                return error.NonMonotonic;
            }
        }

        // ⛔⛔ L1 fix (2026-09-27): a manifest that was just (re)created empty
        // by `open` (`Options.create`, no `MANIFEST` on disk — e.g. one lost
        // to a partial backup/restore while every segment file survived) has
        // no `newest()`, so the monotonic checks above let ANY id through,
        // including one a previous life of this same log already used. The
        // truncating open would then silently destroy real, fsynced records
        // the moment this segment name is reused. Refuse instead of guessing
        // "empty" whenever a segment already sits under this name with real
        // content in it (its `.zst` too: the probe goes through `SegStore`).
        //
        // Probed here, before the manifest names the segment, so a refusal
        // leaves the manifest as it was; the file itself is created after
        // the manifest commit (no crash may leave a file the manifest does
        // not name), with `.create_new` — atomic, so nothing between here
        // and there can get an existing file emptied (`adoptEmpty`).
        {
            var nb: [seg_name_len]u8 = undefined;
            const seg_name = segName(&nb, id);
            if (self.store.open(seg_name, .read_only)) |probe_h| {
                const probe_size = self.store.size(probe_h) catch |e| {
                    self.store.close(probe_h);
                    return self.poison(e);
                };
                self.store.close(probe_h);
                if (probe_size != 0) {
                    self.poisoned = true;
                    return error.OrphanSegment;
                }
            } else |e| switch (e) {
                error.FileNotFound => {},
                else => |x| return self.poison(x),
            }
        }

        try self.live.ensureUnusedCapacity(self.gpa, 1);
        try self.live_lsn.ensureUnusedCapacity(self.gpa, 1);
        try self.live_form.ensureUnusedCapacity(self.gpa, 1);
        // Room to park the old handle if a sync is running on it.
        try self.retired.ensureUnusedCapacity(self.gpa, 1);

        if (self.active) |*a| {
            try self.seal(a);
            self.writeIndexFile(a.id, a.end, a.index.entries.items);
            a.index.deinit(self.gpa);
            self.retire(a.handle);
            self.active = null;
        }

        // Committed before the file exists: a crash from here on leaves a
        // named segment with no file, which `open` finishes creating.
        self.live.appendAssumeCapacity(id);
        self.live_lsn.appendAssumeCapacity(self.next_lsn);
        self.live_form.appendAssumeCapacity(form_raw);
        self.commitManifest() catch |e| {
            _ = self.live.pop();
            _ = self.live_lsn.pop();
            _ = self.live_form.pop();
            return e;
        };

        var nb: [seg_name_len]u8 = undefined;
        const seg_name = segName(&nb, id);
        const h = self.store.open(seg_name, .create_new) catch |e| switch (e) {
            error.PathAlreadyExists => try self.adoptEmpty(seg_name),
            else => return self.poison(e),
        };
        errdefer self.store.close(h);
        const created = self.stamp();
        // Reserved before the header, so that its sync makes the
        // reservation durable too — and a full disk shows here.
        const reserved = self.reserve(h, 0, segment_header_len + 1) catch |e| return self.poison(e);
        self.writeHeader(h, id, self.next_lsn, created) catch |e| return self.poison(e);
        self.store.syncDir() catch |e| return self.poison(e);
        self.active = .{ .id = id, .handle = h, .end = segment_header_len, .synced = segment_header_len, .reserved = @max(reserved, segment_header_len), .tally = Tally.init(self.next_lsn, false), .created = created };
        self.counters.rotations += 1;
    }

    /// Drop every segment older than `id` and delete its file. The newest
    /// segment is never dropped, whatever `id` is — it is where the log's
    /// id sequence is remembered. Returns how many segments went.
    pub fn dropBefore(self: *Log, id: u64) DropError!usize {
        if (self.read_only) return error.ReadOnly;
        if (self.poisoned) return error.Poisoned;
        const n = self.live.items.len;
        var k: usize = 0;
        while (k + 1 < n and self.live.items[k] < id) k += 1;
        if (k == 0) return 0;

        try self.pending.appendSlice(self.gpa, self.live.items[0..k]);
        std.mem.copyForwards(u64, self.live.items[0 .. n - k], self.live.items[k..n]);
        self.live.shrinkRetainingCapacity(n - k);
        std.mem.copyForwards(u64, self.live_lsn.items[0 .. n - k], self.live_lsn.items[k..n]);
        self.live_lsn.shrinkRetainingCapacity(n - k);
        std.mem.copyForwards(u8, self.live_form.items[0 .. n - k], self.live_form.items[k..n]);
        self.live_form.shrinkRetainingCapacity(n - k);
        // The segments leave the log here, atomically. What follows only
        // deletes files, and `open` finishes it if a crash interrupts.
        try self.commitManifest();
        try self.deletePending();
        self.counters.segments_dropped += k;
        return k;
    }

    /// Read every record and seal of the log and check them, stepping past
    /// damage with `Iterator.resync` so that one bad spot does not hide the
    /// rest. Nothing is repaired. Linear in the log's size; closed segments
    /// are otherwise only checked as they are read.
    pub fn verify(self: *Log, gpa: Allocator) (IterError || error{OutOfMemory})!VerifyReport {
        var r: VerifyReport = .{};
        errdefer r.deinit(gpa);
        var it = self.iterator(null);
        defer it.deinit();
        while (true) {
            const rec = it.next() catch |e| switch (e) {
                error.Corrupt => {
                    try r.damage.ensureUnusedCapacity(gpa, 1);
                    try r.gaps.ensureUnusedCapacity(gpa, 1);
                    r.damage.appendAssumeCapacity(it.damage().?);
                    r.gaps.appendAssumeCapacity((try it.resync()).?);
                    continue;
                },
                else => |x| return x,
            } orelse break;
            r.records += 1;
            r.last_lsn = rec.lsn;
        }
        r.segments = self.live.items.len;
        return r;
    }

    /// Drop the oldest segments while the log's files take more than
    /// `max_bytes`, or while a segment's newest record is older than
    /// `now - max_age` (the unit of the timestamps). Oldest first, and only
    /// a prefix: the first segment that may stay ends it. The newest segment
    /// is never dropped (`dropBefore`). A closed segment whose seal cannot be
    /// read has no known age, so age alone never drops it. Returns how many
    /// segments went.
    pub fn enforceRetention(self: *Log, r: Retention, now: i64) DropError!usize {
        if (self.read_only) return error.ReadOnly;
        if (self.poisoned) return error.Poisoned;
        const n = self.live.items.len;
        if (n < 2) return 0;
        const sizes = try self.gpa.alloc(u64, n);
        defer self.gpa.free(sizes);
        var total: u64 = 0;
        for (self.live.items, sizes) |id, *sz| {
            sz.* = try self.segmentSize(id);
            total += sz.*;
        }
        var k: usize = 0;
        while (k + 1 < n) : (k += 1) {
            const over_size = if (r.max_bytes) |m| total > m else false;
            const too_old = if (r.max_age) |age| blk: {
                const newest_ts = (try self.sealMaxTs(self.live.items[k])) orelse break :blk false;
                break :blk newest_ts < now -| age;
            } else false;
            if (!over_size and !too_old) break;
            total -= sizes[k];
        }
        if (k == 0) return 0;
        return self.dropBefore(self.live.items[k]);
    }

    fn segmentSize(self: *Log, id: u64) Storage.Error!u64 {
        // Its data, not its reservation.
        if (self.active) |a| if (a.id == id) return a.end;
        // The bytes on disk: a compressed segment's file, not what it holds.
        const inner = self.segs.?.inner;
        var nb: [seg_name_len]u8 = undefined;
        const i = std.mem.findScalar(u64, self.live.items, id);
        const zst = if (i) |k| self.live_form.items[k] == form_zstd else false;
        const h = inner.open(if (zst) zstName(&nb, id) else segName(&nb, id), .read_only) catch |e| switch (e) {
            error.FileNotFound => return 0,
            else => |x| return x,
        };
        defer inner.close(h);
        return inner.size(h);
    }

    /// The newest timestamp a closed segment's seal records, or null when
    /// its seal cannot be read (no records: its range is empty, so it is as
    /// old as anything can be).
    fn sealMaxTs(self: *Log, id: u64) Storage.Error!?i64 {
        const seal_len = rec_header_len + seal_payload_len;
        var nb: [seg_name_len]u8 = undefined;
        const h = self.store.open(segName(&nb, id), .read_only) catch |e| switch (e) {
            error.FileNotFound => return null,
            else => |x| return x,
        };
        defer self.store.close(h);
        // The segment's size, decompressed if it is compressed.
        const size = try self.store.size(h);
        if (size < segment_header_len + seal_len) return null;
        var w: Window = .{};
        defer w.deinit(self.gpa);
        const at = size - seal_len;
        const raw = switch (try parseAt(&w, self.gpa, self.store, h, at, size, seal_payload_len)) {
            .record => |x| x,
            else => return null,
        };
        if (raw.typ != rec_seal or !sealAgrees(raw, null, at)) return null;
        const s = Seal.decode(raw.payload).?;
        return if (s.count == 0) std.math.minInt(i64) else s.max_ts;
    }

    /// Compress closed segment `id` into the zstd seekable format: the same
    /// bytes, so every `Position`, LSN, index entry and read is unchanged, and
    /// `zstd -d` gives the segment back byte for byte. Frames of
    /// `Options.compression.frame_size`, each with a checksum in the seek
    /// table. Written to `COMPRESS.tmp`, synced, renamed to
    /// `seg-<id>.zst`; then the manifest says so, and the `.log` goes. A crash
    /// anywhere leaves the raw segment or the compressed one, and `open`
    /// removes what is left of the other. Never the newest segment. Compressing
    /// a compressed segment does nothing. Under `Concurrent` this holds the
    /// lock throughout (level 3: tens of milliseconds for a 10 MB segment).
    pub fn compress(self: *Log, id: u64) CompressError!CompressStats {
        if (self.read_only) return error.ReadOnly;
        if (self.poisoned) return error.Poisoned;
        const k = std.mem.findScalar(u64, self.live.items, id) orelse return error.NotCompressible;
        if (k + 1 == self.live.items.len) return error.NotCompressible;
        if (self.live_form.items[k] == form_zstd) {
            const sz = try self.segmentSize(id);
            return .{ .bytes_before = sz, .bytes_after = sz };
        }
        const inner = self.segs.?.inner;
        var nb: [seg_name_len]u8 = undefined;
        const src = inner.open(segName(&nb, id), .read_only) catch |e| switch (e) {
            error.FileNotFound => return error.SegmentGone,
            else => |x| return x,
        };
        defer inner.close(src);
        const size = try inner.size(src);
        const after = try self.writeCompressed(inner, src, size);

        // ⛔⛔ L2 fix (2026-09-27): `writeCompressed` only proves the encoder
        // produced a self-consistent stream whose frame checksums match its
        // own bytes -- it does not prove those bytes decode back to what
        // `src` holds. A wrong-but-well-formed stream (an encoder bug, not
        // storage corruption -- exactly the class of bug a young zig-libs
        // port is more likely to have than a mature one) would pass every
        // check so far and then be trusted with the only remaining copy of
        // the day's data, since the raw `.log` is deleted right after this.
        // `migrate`'s `convertLegacy`/`checkConverted` already read its own
        // conversion back and compare before trusting it (see SPEC.md,
        // *Format versions and migration*); this mirrors that for
        // compression: decode `COMPRESS.tmp` and compare it byte for byte
        // against the raw segment before the rename that starts deleting it.
        self.verifyCompressed(inner, src, size) catch |e| {
            self.counters.compress_verify_failed += 1;
            self.store.delete(compress_tmp) catch {};
            return e;
        };

        // From here the segment's files change: a failure leaves this process
        // unsure which one is on disk.
        self.store.rename(compress_tmp, zstName(&nb, id)) catch |e| return self.poison(e);
        self.store.syncDir() catch |e| return self.poison(e);
        self.live_form.items[k] = form_zstd;
        try self.commitManifest();
        // A failure here only leaves the raw file behind; `open` removes it.
        self.store.delete(segName(&nb, id)) catch {};
        self.counters.compressions += 1;
        return .{ .bytes_before = size, .bytes_after = after };
    }

    /// Compress the first `size` bytes of `src` (read through `from`) into a
    /// synced, closed `COMPRESS.tmp`; returns its length. On failure there
    /// is no `COMPRESS.tmp`.
    fn writeCompressed(self: *Log, from: Storage, src: Storage.Handle, size: u64) CompressError!u64 {
        const co = self.opts.compression;
        var zs = zstd.seekable.SeekableStream.init(self.gpa, .{
            .level = co.level,
            .max_frame_size = co.frame_size,
            .frame_checksums = true,
        }) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.BadCompressOptions,
        };
        defer zs.deinit();
        const bufs = try self.gpa.alloc(u8, 2 * read_block);
        defer self.gpa.free(bufs);
        const in_buf = bufs[0..read_block];
        const out_buf = bufs[read_block..];

        const tmp = try self.store.open(compress_tmp, .create_truncate);
        var tmp_open = true;
        errdefer {
            if (tmp_open) self.store.close(tmp);
            self.store.delete(compress_tmp) catch {};
        }
        var out_off: u64 = 0;
        var off: u64 = 0;
        while (off < size) {
            const want: usize = @intCast(@min(in_buf.len, size - off));
            const n = try from.pread(src, in_buf[0..want], off);
            if (n == 0) return error.Corrupt;
            var in: zstd.seekable.InBuffer = .{ .src = in_buf[0..n] };
            while (in.pos < in.src.len) {
                var out: zstd.seekable.OutBuffer = .{ .dst = out_buf };
                _ = zs.compressStream(&out, &in) catch |e| return mapZstd(e);
                try self.store.writeAll(tmp, out_buf[0..out.pos], out_off);
                out_off += out.pos;
            }
            off += n;
        }
        while (true) {
            var out: zstd.seekable.OutBuffer = .{ .dst = out_buf };
            const left = zs.endStream(&out) catch |e| return mapZstd(e);
            try self.store.writeAll(tmp, out_buf[0..out.pos], out_off);
            out_off += out.pos;
            if (left == 0) break;
        }
        try self.store.sync(tmp);
        self.store.close(tmp);
        tmp_open = false;
        return out_off;
    }

    fn mapZstd(e: zstd.seekable.CompressError) CompressError {
        return if (e == error.OutOfMemory) error.OutOfMemory else error.BadCompressOptions;
    }

    /// L2: decode the just-written, synced `COMPRESS.tmp` back through the
    /// same zstd seekable reader a caller would use, and compare it byte for
    /// byte against the `size` raw bytes already open at `src` (read through
    /// `from`) — before anything renames over or deletes the raw segment.
    /// This is `checkConverted`'s check, adapted: migration hashes payloads
    /// after re-parsing v2 records; compression keeps the same bytes, so a
    /// straight byte comparison of the decoded stream against the source is
    /// the equivalent (and simpler) check for this conversion.
    fn verifyCompressed(self: *Log, from: Storage, src: Storage.Handle, size: u64) CompressError!void {
        const h = try self.store.open(compress_tmp, .read_only);
        defer self.store.close(h);
        const clen = try self.store.size(h);
        var vsrc: VerifyZstSource = .{ .store = self.store, .handle = h };
        const zsrc: zstd.seekable.Source = .{ .custom = .{
            .context = &vsrc,
            .size = clen,
            .readAt = VerifyZstSource.readAt,
        } };
        var sk = zstd.seekable.Seekable.init(self.gpa, zsrc) catch |e| {
            if (e == error.OutOfMemory) return error.OutOfMemory;
            if (vsrc.io_err) |ie| return ie;
            return error.CompressVerifyFailed;
        };
        defer sk.deinit();
        if (sk.table.decompressedSize() != size) return error.CompressVerifyFailed;

        const bufs = try self.gpa.alloc(u8, 2 * read_block);
        defer self.gpa.free(bufs);
        const raw_buf = bufs[0..read_block];
        const dec_buf = bufs[read_block..];
        var off: u64 = 0;
        while (off < size) {
            const want: usize = @intCast(@min(raw_buf.len, size - off));
            const n = try from.pread(src, raw_buf[0..want], off);
            if (n == 0) return error.CompressVerifyFailed;
            const got = sk.decompress(dec_buf[0..n], off) catch |e| {
                if (e == error.OutOfMemory) return error.OutOfMemory;
                if (vsrc.io_err) |ie| return ie;
                return error.CompressVerifyFailed;
            };
            if (got != n or !std.mem.eql(u8, raw_buf[0..n], dec_buf[0..n])) return error.CompressVerifyFailed;
            off += n;
        }
    }

    /// A `zstd.seekable.Source.custom` over one already-open `Storage`
    /// handle, for `verifyCompressed`. Mirrors `SegStore.readAt`.
    const VerifyZstSource = struct {
        store: Storage,
        handle: Storage.Handle,
        io_err: ?Storage.Error = null,

        fn readAt(context: *anyopaque, buf: []u8, offset: u64) error{ReadFailed}!void {
            const self: *VerifyZstSource = @ptrCast(@alignCast(context));
            var got: usize = 0;
            while (got < buf.len) {
                const n = self.store.pread(self.handle, buf[got..], offset + got) catch |e| {
                    self.io_err = e;
                    return error.ReadFailed;
                };
                if (n == 0) return error.ReadFailed;
                got += n;
            }
        }
    };

    /// Rewrite closed segment `id` keeping only the records `keep` accepts,
    /// at their LSNs: what it drops leaves a gap in the sequence, the
    /// segment keeps its place, first LSN and LSN range. The new segment is
    /// written whole to `COMPACT.tmp`, synced, and renamed over the old one —
    /// a crash leaves the old segment or the new, never a mix, and `open`
    /// removes a `COMPACT.tmp` left behind. Never the newest segment (it is
    /// where appends go and where the LSN sequence is remembered). A damaged
    /// segment is refused with `error.Corrupt` and left as it is.
    ///
    /// `Position`s into the segment from before move: one carrying its LSN
    /// finds its record again through `seek` when an iterator starts there
    /// (or the next kept one); a hand-made one without it is not safe.
    pub fn compact(self: *Log, id: u64, ctx: anytype, comptime keep: fn (@TypeOf(ctx), Record) bool) CompactError!CompactStats {
        if (self.read_only) return error.ReadOnly;
        if (self.poisoned) return error.Poisoned;
        const k = std.mem.findScalar(u64, self.live.items, id) orelse return error.NotCompactable;
        if (k + 1 == self.live.items.len) return error.NotCompactable;
        const base = self.live_lsn.items[k];

        var nb: [seg_name_len]u8 = undefined;
        const old = self.store.open(segName(&nb, id), .read_only) catch |e| switch (e) {
            error.FileNotFound => return error.SegmentGone,
            else => |x| return x,
        };
        defer self.store.close(old);
        var flags: u32 = 0;
        switch (try checkHeaderFlags(self.store, old, id, base, &flags)) {
            .ok => {},
            .unsupported => return error.UnsupportedVersion,
            .short, .mismatch => return error.Corrupt,
        }
        const size = try self.store.size(old);
        var stamp_buf: [8]u8 = undefined;
        try self.store.preadFull(old, &stamp_buf, 24);

        const tmp = try self.store.open(compact_tmp, .create_truncate);
        var tmp_open = true;
        errdefer {
            if (tmp_open) self.store.close(tmp);
            self.store.delete(compact_tmp) catch {};
        }
        var hdr: [segment_header_len]u8 = undefined;
        encodeHeaderFlags(&hdr, id, base, std.mem.readInt(i64, &stamp_buf, .little), flag_compacted);
        try self.store.writeAll(tmp, &hdr, 0);

        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.gpa);
        var out_off: u64 = segment_header_len;
        var w: Window = .{};
        defer w.deinit(self.gpa);
        var seen = Tally.init(base, flags & flag_compacted != 0);
        var kept = Tally.init(base, true);
        var result: CompactStats = .{ .bytes_before = size };
        var off: u64 = segment_header_len;
        const old_seal: Seal = while (true) {
            const raw = switch (try parseAt(&w, self.gpa, self.store, old, off, size, self.opts.max_record_len)) {
                .record => |r| r,
                else => return error.Corrupt,
            };
            switch (raw.typ) {
                rec_data => {
                    if (!seen.fits(raw.lsn)) return error.Corrupt;
                    seen.add(raw.ts, raw.lsn);
                    const rec: Record = .{
                        .pos = .{ .segment = id, .offset = off, .lsn = raw.lsn },
                        .next = .{ .segment = id, .offset = off + raw.len, .lsn = raw.lsn + 1 },
                        .lsn = raw.lsn,
                        .ts = raw.ts,
                        .payload = raw.payload,
                    };
                    if (keep(ctx, rec)) {
                        const at = out.items.len;
                        try out.resize(self.gpa, at + raw.len);
                        encodeRecord(out.items[at..][0..@intCast(raw.len)], rec_data, raw.lsn, raw.ts, raw.payload);
                        kept.add(raw.ts, raw.lsn);
                        result.kept += 1;
                        if (out.items.len >= read_block) {
                            try self.store.writeAll(tmp, out.items, out_off);
                            out_off += out.items.len;
                            out.clearRetainingCapacity();
                        }
                    } else result.dropped += 1;
                },
                rec_seal => {
                    if (!sealAgrees(raw, seen, off) or off + raw.len != size) return error.Corrupt;
                    break Seal.decode(raw.payload).?;
                },
                else => return error.Corrupt,
            }
            off += raw.len;
        };
        try self.store.writeAll(tmp, out.items, out_off);
        out_off += out.items.len;
        var new_seal = kept.seal(out_off);
        new_seal.last_lsn = old_seal.last_lsn; // the segment's range, not its survivors'
        var payload: [seal_payload_len]u8 = undefined;
        new_seal.encode(&payload);
        var rec: [rec_header_len + seal_payload_len]u8 = undefined;
        encodeRecord(&rec, rec_seal, 0, 0, &payload);
        try self.store.writeAll(tmp, &rec, out_off);
        out_off += rec.len;
        try self.store.sync(tmp);
        self.store.close(tmp);
        tmp_open = false;

        // A compressed segment stays compressed: the new one is compressed
        // too and renamed over the `.zst`, one rename as for a raw one.
        const zst = self.live_form.items[k] == form_zstd;
        if (zst) {
            result.bytes_before = try self.segmentSize(id); // on disk, compressed
            const inner = self.segs.?.inner;
            const raw = try inner.open(compact_tmp, .read_only);
            defer inner.close(raw);
            out_off = self.writeCompressed(inner, raw, out_off) catch |e| return switch (e) {
                error.NotCompressible, error.SegmentGone => unreachable,
                // L2: `writeCompressed` only ever encodes here — the
                // read-back-and-compare is `verifyCompressed`'s, called only
                // from `compress`, never from this recompression of an
                // already-compressed segment during `compact`.
                error.CompressVerifyFailed => unreachable,
                else => |x| x,
            };
        }

        // From here the live segment changes: a failure leaves this process
        // unsure which one is on disk.
        if (zst) {
            self.store.rename(compress_tmp, zstName(&nb, id)) catch |e| return self.poison(e);
            self.store.syncDir() catch |e| return self.poison(e);
            self.store.delete(compact_tmp) catch {};
        } else {
            self.store.rename(compact_tmp, segName(&nb, id)) catch |e| return self.poison(e);
            self.store.syncDir() catch |e| return self.poison(e);
        }
        // Its old index no longer fits (the size in it would say so too).
        var ib: [seg_name_len]u8 = undefined;
        self.store.delete(idxName(&ib, id)) catch {};
        result.bytes_after = out_off;
        self.counters.compactions += 1;
        self.counters.records_compacted_away += result.dropped;
        return result;
    }

    /// Keep, in the closed segments `ids`, only the newest record of each
    /// key — Kafka's log compaction. `keyOf` names a payload's key, or null
    /// for a record that is always kept. "Newest" looks at the whole log from
    /// the first of `ids` to its end, the active segment included, so a key
    /// updated since keeps none of its older records here. Two passes; the
    /// keys are held in memory between them.
    pub fn compactByKey(self: *Log, ids: []const u64, ctx: anytype, comptime keyOf: fn (@TypeOf(ctx), []const u8) ?[]const u8) CompactError!CompactStats {
        if (ids.len == 0) return .{};
        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var latest: std.StringHashMapUnmanaged(u64) = .empty;
        const first = std.mem.min(u64, ids);
        {
            var it = self.iterator(.{ .segment = first, .offset = segment_header_len });
            defer it.deinit();
            while (try it.next()) |r| {
                const key = keyOf(ctx, r.payload) orelse continue;
                const gop = try latest.getOrPut(arena, key);
                if (!gop.found_existing) gop.key_ptr.* = try arena.dupe(u8, key);
                gop.value_ptr.* = r.lsn;
            }
        }
        const Newest = struct {
            latest: *const std.StringHashMapUnmanaged(u64),
            ctx: @TypeOf(ctx),
            fn keep(n: @This(), r: Record) bool {
                const key = keyOf(n.ctx, r.payload) orelse return true;
                return n.latest.get(key).? == r.lsn;
            }
        };
        var total: CompactStats = .{};
        for (ids) |id| {
            const st = try self.compact(id, Newest{ .latest = &latest, .ctx = ctx }, Newest.keep);
            total.kept += st.kept;
            total.dropped += st.dropped;
            total.bytes_before += st.bytes_before;
            total.bytes_after += st.bytes_after;
        }
        return total;
    }

    /// Where the first record with an LSN at or after `lsn` starts — the
    /// record `lsn` itself unless compaction dropped it: the segment from the
    /// manifest, the place in it from the segment's sparse index, then a
    /// short walk. Null when the log has no such record yet (for the writer:
    /// none durable); `error.SegmentGone` when retention took `lsn`. Hand the
    /// result to `iterator` to read on from there.
    pub fn seek(self: *Log, lsn: u64) SeekError!?Position {
        if (self.read_only) try self.refreshForSeek();
        const live = self.live.items;
        if (live.len == 0) return null;
        if (lsn < self.live_lsn.items[0]) return error.SegmentGone;
        // The last segment whose first LSN is at or below `lsn`.
        var i: usize = live.len;
        while (i > 0 and self.live_lsn.items[i - 1] > lsn) i -= 1;
        i -= 1;
        while (i < self.live.items.len) : (i += 1) {
            const id = self.live.items[i];
            var seg = try self.openForSeek(id, false);
            defer seg.close(self);
            // The walk ends within one index interval: read about that much.
            seg.window.block = @max(4096, 2 * @as(usize, self.opts.index_interval));
            const from = SparseIndex.byLsn(seg.entries(), lsn);
            var off: u64 = if (from) |e| e.offset else segment_header_len;
            while (true) {
                const raw = switch (try parseAt(&seg.window, self.gpa, self.store, seg.handle, off, seg.bound, self.opts.max_record_len)) {
                    .record => |r| r,
                    else => if (seg.is_newest) return null else return error.Corrupt,
                };
                if (raw.typ != rec_data) {
                    // The seal. Only a compacted segment can end before `lsn`
                    // without holding it: the next one has what follows.
                    if (seg.is_newest) return null;
                    if (!seg.compacted) return error.Corrupt;
                    break;
                }
                if (raw.lsn == lsn or (raw.lsn > lsn and seg.compacted)) return .{ .segment = id, .offset = off, .lsn = raw.lsn };
                if (raw.lsn > lsn) return error.Corrupt;
                off += raw.len;
            }
        }
        return null;
    }

    /// Where to read from to see every record with a timestamp at or after
    /// `t`: the first record at which the newest timestamp so far reaches
    /// `t`, so that every record before it is older — Kafka's time index,
    /// right for timestamps that are only roughly in order. Null when no
    /// record has reached `t` yet.
    pub fn seekTime(self: *Log, t: i64) SeekError!?Position {
        if (self.read_only) try self.refreshForSeek();
        for (self.live.items) |id| {
            var seg = try self.openForSeek(id, true);
            defer seg.close(self);
            // A segment whose newest record is older than `t` holds nothing
            // for it; its seal says so without a walk.
            if (seg.max_ts) |m| if (m < t) continue;
            const from = SparseIndex.byTime(seg.entries(), t);
            var off: u64 = if (from) |e| e.offset else segment_header_len;
            while (true) {
                const raw = switch (try parseAt(&seg.window, self.gpa, self.store, seg.handle, off, seg.bound, self.opts.max_record_len)) {
                    .record => |r| r,
                    else => break,
                };
                if (raw.typ != rec_data) break;
                if (raw.ts >= t) return .{ .segment = id, .offset = off, .lsn = raw.lsn };
                off += raw.len;
            }
        }
        return null;
    }

    fn refreshForSeek(self: *Log) SeekError!void {
        self.refresh() catch |e| switch (e) {
            error.NotFound => return error.SegmentGone,
            error.Locked => unreachable,
            error.NeedsMigration, error.MigrationFailed => unreachable, // a reader never migrates
            // L5: `RecordTooLongForOptions` is `scanTail`'s alone (a
            // writer's own active-segment repair, reached only from
            // `openNewest`, itself only from `Log.open`); `refresh` calls
            // `loadManifest` and nothing else, so a reader can never meet it.
            error.RecordTooLongForOptions => unreachable,
            else => |x| return x,
        };
    }

    /// One segment opened for a seek, with its index.
    const SeekSegment = struct {
        handle: Storage.Handle,
        owned: bool,
        /// The active segment's index (borrowed) or one loaded or rebuilt.
        borrowed: []const IndexEntry = &.{},
        loaded: SparseIndex = .{},
        window: Window = .{},
        /// How far a seek may read.
        bound: u64,
        is_newest: bool,
        /// The newest timestamp, when known without a walk.
        max_ts: ?i64,
        compacted: bool = false,

        fn entries(seg: *const SeekSegment) []const IndexEntry {
            return if (seg.borrowed.len != 0) seg.borrowed else seg.loaded.entries.items;
        }

        fn close(seg: *SeekSegment, log: *Log) void {
            seg.window.deinit(log.gpa);
            seg.loaded.deinit(log.gpa);
            if (seg.owned) log.store.close(seg.handle);
        }
    };

    /// `want_time`: find the segment's newest timestamp (from its seal) too.
    fn openForSeek(self: *Log, id: u64, want_time: bool) SeekError!SeekSegment {
        const is_newest = self.newest() == id;
        if (!self.read_only) if (self.active) |*a| if (a.id == id) return .{
            .handle = a.handle,
            .owned = false,
            .borrowed = a.index.entries.items,
            .bound = a.synced,
            .is_newest = true,
            .max_ts = if (a.tally.count == 0) std.math.minInt(i64) else a.tally.max_ts,
        };
        var nb: [seg_name_len]u8 = undefined;
        const h = self.store.open(segName(&nb, id), .read_only) catch |e| switch (e) {
            error.FileNotFound => return error.SegmentGone,
            else => |x| return x,
        };
        errdefer self.store.close(h);
        var flags: u32 = 0;
        switch (try checkHeaderFlags(self.store, h, id, self.segmentFirstLsn(id).?, &flags)) {
            .ok => {},
            .unsupported => return error.UnsupportedVersion,
            .short => if (!is_newest) return error.Corrupt,
            .mismatch => return error.Corrupt,
        }
        const size = try self.store.size(h);
        var seg: SeekSegment = .{ .handle = h, .owned = true, .bound = size, .is_newest = is_newest, .max_ts = null, .compacted = flags & flag_compacted != 0 };
        errdefer seg.loaded.deinit(self.gpa);
        if (want_time and (!is_newest or self.read_only)) seg.max_ts = try self.sealMaxTs(id);
        if (self.opts.index_interval != 0) try self.loadIndex(id, h, size, &seg.loaded);
        return seg;
    }

    /// The segment's index from its `.idx` file, if that is whole and fits
    /// the segment; otherwise rebuilt by a walk (and not written back: the
    /// reader may be read-only, and the next seal rewrites nothing old).
    fn loadIndex(self: *Log, id: u64, h: Storage.Handle, size: u64, out: *SparseIndex) SeekError!void {
        if (try self.readIndexFile(id, size, out)) return;
        out.entries.clearRetainingCapacity();
        var w: Window = .{};
        defer w.deinit(self.gpa);
        var off: u64 = segment_header_len;
        var tally: Tally = Tally.init(self.segmentFirstLsn(id).?, false);
        while (true) {
            const raw = switch (try parseAt(&w, self.gpa, self.store, h, off, size, self.opts.max_record_len)) {
                .record => |r| r,
                else => break,
            };
            if (raw.typ != rec_data) break;
            try out.entries.ensureUnusedCapacity(self.gpa, 1);
            out.note(self.opts.index_interval, .{ .lsn = raw.lsn, .offset = off, .max_before = tally.maxOrMin() });
            tally.add(raw.ts, raw.lsn);
            off += raw.len;
        }
    }

    fn readIndexFile(self: *Log, id: u64, seg_size: u64, out: *SparseIndex) SeekError!bool {
        var nb: [seg_name_len]u8 = undefined;
        const h = self.store.open(idxName(&nb, id), .read_only) catch |e| switch (e) {
            error.FileNotFound => return false,
            else => |x| return x,
        };
        defer self.store.close(h);
        const size = try self.store.size(h);
        if (size < idx_fixed + man_crc_len or (size - idx_fixed - man_crc_len) % idx_entry_len != 0) return false;
        const buf = try self.gpa.alloc(u8, @intCast(size));
        defer self.gpa.free(buf);
        self.store.preadFull(h, buf, 0) catch |e| switch (e) {
            error.Corrupt => return false,
            else => |x| return x,
        };
        const body = buf[0 .. buf.len - man_crc_len];
        if (crc32c(body) != std.mem.readInt(u32, buf[buf.len - man_crc_len ..][0..4], .little)) return false;
        if (!std.mem.eql(u8, buf[0..4], idx_magic)) return false;
        if (std.mem.readInt(u32, buf[4..8], .little) != idx_version) return false;
        if (std.mem.readInt(u64, buf[8..16], .little) != id) return false;
        if (std.mem.readInt(u64, buf[16..24], .little) != seg_size) return false;
        const n = std.mem.readInt(u32, buf[24..28], .little);
        if (body.len != idx_fixed + @as(usize, n) * idx_entry_len) return false;
        try out.entries.ensureTotalCapacity(self.gpa, n);
        var prev: ?IndexEntry = null;
        for (0..n) |k| {
            const e = body[idx_fixed + k * idx_entry_len ..][0..idx_entry_len];
            const entry: IndexEntry = .{
                .lsn = std.mem.readInt(u64, e[0..8], .little),
                .offset = std.mem.readInt(u64, e[8..16], .little),
                .max_before = std.mem.readInt(i64, e[16..24], .little),
            };
            // An index that does not fit its segment is someone else's.
            if (entry.offset < segment_header_len or entry.offset >= seg_size) return false;
            if (prev) |q| if (entry.lsn <= q.lsn or entry.offset <= q.offset or entry.max_before < q.max_before) return false;
            out.entries.appendAssumeCapacity(entry);
            prev = entry;
        }
        return true;
    }

    /// Write a sealed segment's index. Derived data: not synced, and a
    /// failure costs only a walk on the next seek, so it is not an error.
    fn writeIndexFile(self: *Log, id: u64, seg_size: u64, entries: []const IndexEntry) void {
        if (self.opts.index_interval == 0) return;
        const size = idx_fixed + entries.len * idx_entry_len + man_crc_len;
        self.scratch.resize(self.gpa, size) catch return;
        const b = self.scratch.items;
        @memcpy(b[0..4], idx_magic);
        std.mem.writeInt(u32, b[4..8], idx_version, .little);
        std.mem.writeInt(u64, b[8..16], id, .little);
        std.mem.writeInt(u64, b[16..24], seg_size, .little);
        std.mem.writeInt(u32, b[24..28], @intCast(entries.len), .little);
        for (entries, 0..) |e, k| {
            const o = b[idx_fixed + k * idx_entry_len ..][0..idx_entry_len];
            std.mem.writeInt(u64, o[0..8], e.lsn, .little);
            std.mem.writeInt(u64, o[8..16], e.offset, .little);
            std.mem.writeInt(i64, o[16..24], e.max_before, .little);
        }
        std.mem.writeInt(u32, b[size - man_crc_len ..][0..4], crc32c(b[0 .. size - man_crc_len]), .little);
        var nb: [seg_name_len]u8 = undefined;
        const h = self.store.open(idxName(&nb, id), .create_truncate) catch return;
        defer self.store.close(h);
        self.store.writeAll(h, b, 0) catch return;
    }

    /// Read the log from `from`, or from its oldest record when `from` is
    /// null. The iterator follows the writer: at the live end it returns
    /// null, and a later call picks up whatever has been appended or rotated
    /// to since. It never reads past what `append` has made durable.
    pub fn iterator(self: *Log, from: ?Position) Iterator {
        return .{ .log = self, .start = from };
    }

    // ── internals ───────────────────────────────────────────────────────────

    fn poison(self: *Log, e: Storage.Error) Storage.Error {
        self.poisoned = true;
        return e;
    }

    fn loadManifest(self: *Log) OpenError!void {
        // Read-only, so looking for a log never leaves an empty `MANIFEST`
        // behind in a directory that had none.
        const h = self.store.open(manifest_name, .read_only) catch |e| switch (e) {
            error.FileNotFound => {
                if (!self.opts.create or self.read_only) return error.NotFound;
                try self.commitManifest();
                return;
            },
            else => |x| return x,
        };
        defer self.store.close(h);
        const size = try self.store.size(h);
        // A committed manifest is never empty — it is only ever created by
        // renaming a written, synced temp over it. Empty therefore means
        // "no log": the file an older version created while looking for one.
        if (size == 0) {
            if (!self.opts.create or self.read_only) return error.NotFound;
            try self.commitManifest();
            return;
        }
        const max_size = man_fixed + man_entry_len * max_manifest_ids + man_crc_len;
        if (size < man_fixed + man_crc_len or size > max_size) return error.Corrupt;

        const buf = try self.gpa.alloc(u8, @intCast(size));
        defer self.gpa.free(buf);
        self.store.preadFull(h, buf, 0) catch |e| switch (e) {
            error.Corrupt => return error.Corrupt,
            else => |x| return x,
        };

        const body = buf[0 .. buf.len - man_crc_len];
        if (crc32c(body) != std.mem.readInt(u32, buf[buf.len - man_crc_len ..][0..4], .little))
            return error.Corrupt;
        if (!std.mem.eql(u8, buf[0..4], man_magic)) return error.Corrupt;
        const version = std.mem.readInt(u32, buf[4..8], .little);
        if (version == legacy_version) return self.loadLegacyManifest(body);
        if (version != format_version) return error.UnsupportedVersion;
        const nl = std.mem.readInt(u32, buf[8..12], .little);
        const np = std.mem.readInt(u32, buf[12..16], .little);
        if (@as(u64, nl) + np > max_manifest_ids) return error.Corrupt;
        if (body.len != man_fixed + man_entry_len * @as(usize, nl) + 8 * @as(usize, np)) return error.Corrupt;

        try self.live.ensureTotalCapacity(self.gpa, nl);
        try self.live_lsn.ensureTotalCapacity(self.gpa, nl);
        try self.live_form.ensureTotalCapacity(self.gpa, nl);
        try self.pending.ensureTotalCapacity(self.gpa, np);
        var off: usize = man_fixed;
        for (0..nl) |_| {
            const e = buf[off..][0..man_entry_len];
            const id = std.mem.readInt(u64, e[0..8], .little);
            const first = std.mem.readInt(u64, e[8..16], .little);
            if (e[16] != form_raw and e[16] != form_zstd and e[16] != form_legacy) return error.UnsupportedVersion;
            if (!std.mem.allEqual(u8, e[17..24], 0)) return error.Corrupt;
            if (self.newest()) |prev| if (id <= prev) return error.Corrupt;
            // LSNs start at 1 and never go back.
            if (first == 0) return error.Corrupt;
            if (self.live_lsn.last()) |prev| if (first < prev) return error.Corrupt;
            self.live.appendAssumeCapacity(id);
            self.live_lsn.appendAssumeCapacity(first);
            self.live_form.appendAssumeCapacity(e[16]);
            off += man_entry_len;
        }
        for (0..np) |_| {
            const id = std.mem.readInt(u64, buf[off..][0..8], .little);
            if (std.mem.findScalar(u64, self.live.items, id) != null) return error.Corrupt;
            self.pending.appendAssumeCapacity(id);
            off += 8;
        }
    }

    // ── migration from the previous format ──────────────────────────────────

    /// One segment of the previous format, as its read-only scan found it.
    const LegacyScan = struct {
        records: u64 = 0,
        /// The seal's offset, or the end of the last whole record.
        data_end: u64 = legacy_header_len,
        sealed: bool = false,
        torn: u64 = 0,
        hash: u64 = 0,
        file_bytes: u64 = 0,
        /// No file, or not even a whole header: an empty newest segment.
        empty: bool = false,
        /// Already in the current format: a crash came after its rename and
        /// before the manifest said so.
        converted: bool = false,
    };

    fn migrationFailed(self: *Log, rep: *MigrationReport, segment: u64, offset: u64, reason: @FieldType(MigrationFailure, "reason")) OpenError {
        _ = self;
        rep.failure = .{ .segment = segment, .offset = offset, .reason = reason };
        return error.MigrationFailed;
    }

    /// Convert a log of the previous format, in place, segment by segment.
    /// First every segment is read and checked and nothing is written:
    /// damage refuses the whole migration there. Then the manifest takes the
    /// current format with each segment marked as not yet converted — from
    /// here a crash is resumed by the next `open`, and readers are told
    /// `MigrationInProgress`. Each segment is written to `MIGRATE.tmp`, read
    /// back and compared (count, LSNs, the payloads' hash, the seal), synced,
    /// and renamed over the old file; then the manifest says so.
    fn migrate(self: *Log) OpenError!void {
        const t0 = self.clockNs();
        var rep: MigrationReport = .{ .from_version = legacy_version, .positions = .translate_from_v1 };
        defer if (self.opts.migration_report) |r| {
            r.* = rep;
        };
        self.store.delete(migrate_tmp) catch |e| switch (e) {
            error.FileNotFound => {},
            else => |x| return x,
        };
        const n = self.live.items.len;
        const scans = try self.gpa.alloc(LegacyScan, n);
        defer self.gpa.free(scans);
        for (self.live.items, self.live_form.items, 0..) |id, form, i| {
            scans[i] = .{};
            if (form != form_legacy) continue;
            scans[i] = try self.scanLegacy(id, i + 1 == n, &rep);
            rep.bytes_before += scans[i].file_bytes;
        }
        if (self.legacy_manifest) {
            var next: u64 = 1;
            for (self.live_lsn.items, scans) |*first, sc| {
                first.* = next;
                next += sc.records;
            }
            try self.commitManifest();
            self.legacy_manifest = false;
        }
        var done: u64 = 0;
        for (self.live.items, 0..) |id, i| {
            if (self.live_form.items[i] != form_legacy) continue;
            const sc = scans[i];
            if (!sc.converted) try self.convertLegacy(id, self.live_lsn.items[i], sc, &rep);
            self.live_form.items[i] = form_raw;
            try self.commitManifest();
            rep.segments += 1;
            rep.records += sc.records;
            rep.torn_bytes += sc.torn;
            done += 1;
            if (self.opts.on_migration_progress) |f| f(self.opts.migration_ctx, .{ .done = done, .segments = n, .records = rep.records });
        }
        for (self.live.items) |id| rep.bytes_after += try self.segmentSize(id);
        rep.duration_ns = self.clockNs() -| t0;
        self.migrated = rep;
    }

    /// Read one segment of the previous format and check it, writing nothing.
    fn scanLegacy(self: *Log, id: u64, is_newest: bool, rep: *MigrationReport) OpenError!LegacyScan {
        var sc: LegacyScan = .{};
        var nb: [seg_name_len]u8 = undefined;
        const h = self.store.open(segName(&nb, id), .read_only) catch |e| switch (e) {
            error.FileNotFound => {
                // The previous format named a segment before creating it.
                if (is_newest) return .{ .empty = true };
                return self.migrationFailed(rep, id, 0, .bad_header);
            },
            else => |x| return x,
        };
        defer self.store.close(h);
        const size = try self.store.size(h);
        sc.file_bytes = size;
        var head: [legacy_header_len]u8 = undefined;
        var got: usize = 0;
        while (got < head.len) {
            const k = try self.store.pread(h, head[got..], got);
            if (k == 0) break;
            got += k;
        }
        if (got >= 8 and std.mem.eql(u8, head[0..4], seg_magic) and std.mem.readInt(u32, head[4..8], .little) == format_version) {
            // Converted already; its manifest entry did not say so yet.
            return self.scanConverted(h, id, size, sc, rep);
        }
        if (got < legacy_header_len) {
            if (is_newest) return .{ .empty = true, .torn = size, .file_bytes = size };
            return self.migrationFailed(rep, id, 0, .bad_header);
        }
        if (!std.mem.eql(u8, head[0..4], seg_magic) or std.mem.readInt(u32, head[4..8], .little) != legacy_version or
            std.mem.readInt(u64, head[8..16], .little) != id)
            return self.migrationFailed(rep, id, 0, .bad_header);

        var hh = std.hash.Wyhash.init(0);
        var w: Window = .{};
        defer w.deinit(self.gpa);
        var off: u64 = legacy_header_len;
        while (true) {
            const raw = switch (try parseLegacyAt(&w, self.gpa, self.store, h, off, size, self.opts.max_record_len)) {
                .record => |r| r,
                .short => {
                    if (off == size) break;
                    if (is_newest) {
                        sc.torn = size - off;
                        break;
                    }
                    return self.migrationFailed(rep, id, off, .bad_record);
                },
                .bad_crc, .too_long => {
                    if (is_newest) {
                        sc.torn = size - off;
                        break;
                    }
                    return self.migrationFailed(rep, id, off, .bad_record);
                },
            };
            switch (raw.typ) {
                rec_data => {
                    sc.records += 1;
                    hashPayload(&hh, raw.payload);
                    off += raw.len;
                },
                rec_seal => {
                    if (raw.payload.len != legacy_seal_payload_len or
                        std.mem.readInt(u64, raw.payload[0..8], .little) != sc.records or
                        std.mem.readInt(u64, raw.payload[8..16], .little) != off or
                        off + raw.len != size)
                        return self.migrationFailed(rep, id, off, .bad_seal);
                    sc.sealed = true;
                    break;
                },
                else => return self.migrationFailed(rep, id, off, .bad_record),
            }
        }
        if (!sc.sealed and !is_newest) return self.migrationFailed(rep, id, off, .bad_seal);
        sc.data_end = off;
        sc.hash = hh.final();
        return sc;
    }

    /// A segment a crash left converted: it must hold consecutive LSNs from
    /// its manifest entry's first one, and read clean to its end or seal.
    fn scanConverted(self: *Log, h: Storage.Handle, id: u64, size: u64, sc_in: LegacyScan, rep: *MigrationReport) OpenError!LegacyScan {
        var sc = sc_in;
        sc.converted = true;
        const i = std.mem.findScalar(u64, self.live.items, id).?;
        const base = self.live_lsn.items[i];
        if (self.legacy_manifest or try checkHeader(self.store, h, id, base) != .ok)
            return self.migrationFailed(rep, id, 0, .bad_header);
        var w: Window = .{};
        defer w.deinit(self.gpa);
        var off: u64 = segment_header_len;
        var tally = Tally.init(base, false);
        while (off < size) {
            const raw = switch (try parseAt(&w, self.gpa, self.store, h, off, size, self.opts.max_record_len)) {
                .record => |r| r,
                else => return self.migrationFailed(rep, id, off, .mismatch),
            };
            if (raw.typ == rec_seal) {
                if (!sealAgrees(raw, tally, off) or off + raw.len != size) return self.migrationFailed(rep, id, off, .mismatch);
                sc.sealed = true;
                break;
            }
            if (raw.typ != rec_data or !tally.fits(raw.lsn)) return self.migrationFailed(rep, id, off, .mismatch);
            tally.add(raw.ts, raw.lsn);
            off += raw.len;
        }
        sc.records = tally.count;
        return sc;
    }

    /// Write segment `id` in the current format to `MIGRATE.tmp`, read it
    /// back against the scan, and rename it over the old file.
    fn convertLegacy(self: *Log, id: u64, base: u64, sc: LegacyScan, rep: *MigrationReport) OpenError!void {
        var nb: [seg_name_len]u8 = undefined;
        const src: ?Storage.Handle = if (sc.empty) null else try self.store.open(segName(&nb, id), .read_only);
        defer if (src) |h| self.store.close(h);

        const tmp = try self.store.open(migrate_tmp, .create_truncate);
        var tmp_open = true;
        errdefer {
            if (tmp_open) self.store.close(tmp);
            self.store.delete(migrate_tmp) catch {};
        }
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.gpa);
        var tally = Tally.init(base, false);
        var out_off: u64 = segment_header_len;
        var created: i64 = 0;
        if (src) |h| {
            var w: Window = .{};
            defer w.deinit(self.gpa);
            var off: u64 = legacy_header_len;
            var lsn = base;
            while (off < sc.data_end) {
                const raw = switch (try parseLegacyAt(&w, self.gpa, self.store, h, off, sc.data_end, self.opts.max_record_len)) {
                    .record => |r| r,
                    // It read clean a moment ago: the file changed under us.
                    else => return self.migrationFailed(rep, id, off, .mismatch),
                };
                const ts: i64 = if (self.opts.legacy_ts) |f| f(raw.payload) else 0;
                if (lsn == base) created = ts;
                const at = out.items.len;
                const len = rec_header_len + raw.payload.len;
                try out.resize(self.gpa, at + len);
                encodeRecord(out.items[at..][0..len], rec_data, lsn, ts, raw.payload);
                tally.add(ts, lsn);
                lsn += 1;
                off += raw.len;
                if (out.items.len >= read_block) {
                    try self.store.writeAll(tmp, out.items, out_off);
                    out_off += out.items.len;
                    out.clearRetainingCapacity();
                }
            }
        }
        try self.store.writeAll(tmp, out.items, out_off);
        out_off += out.items.len;
        if (sc.sealed) {
            var payload: [seal_payload_len]u8 = undefined;
            tally.seal(out_off).encode(&payload);
            var rec: [rec_header_len + seal_payload_len]u8 = undefined;
            encodeRecord(&rec, rec_seal, 0, 0, &payload);
            try self.store.writeAll(tmp, &rec, out_off);
            out_off += rec.len;
        }
        var hdr: [segment_header_len]u8 = undefined;
        encodeHeader(&hdr, id, base, created);
        try self.store.writeAll(tmp, &hdr, 0);
        try self.store.sync(tmp);
        self.store.close(tmp);
        tmp_open = false;

        try self.checkConverted(id, base, sc, out_off, rep);
        self.store.rename(migrate_tmp, segName(&nb, id)) catch |e| return self.poison(e);
        self.store.syncDir() catch |e| return self.poison(e);
    }

    /// `MIGRATE.tmp` against the scan of the segment it came from.
    fn checkConverted(self: *Log, id: u64, base: u64, sc: LegacyScan, size: u64, rep: *MigrationReport) OpenError!void {
        const h = try self.store.open(migrate_tmp, .read_only);
        defer self.store.close(h);
        if (try self.store.size(h) != size or try checkHeader(self.store, h, id, base) != .ok)
            return self.migrationFailed(rep, id, 0, .mismatch);
        var w: Window = .{};
        defer w.deinit(self.gpa);
        var hh = std.hash.Wyhash.init(0);
        var tally = Tally.init(base, false);
        var off: u64 = segment_header_len;
        var sealed = false;
        while (off < size) {
            const raw = switch (try parseAt(&w, self.gpa, self.store, h, off, size, self.opts.max_record_len)) {
                .record => |r| r,
                else => return self.migrationFailed(rep, id, off, .mismatch),
            };
            if (raw.typ == rec_seal) {
                if (!sc.sealed or !sealAgrees(raw, tally, off) or off + raw.len != size) return self.migrationFailed(rep, id, off, .mismatch);
                sealed = true;
                break;
            }
            if (raw.typ != rec_data or raw.lsn != base + tally.count) return self.migrationFailed(rep, id, off, .mismatch);
            tally.add(raw.ts, raw.lsn);
            hashPayload(&hh, raw.payload);
            off += raw.len;
        }
        if (sealed != sc.sealed or tally.count != sc.records or (sc.records > 0 and hh.final() != sc.hash))
            return self.migrationFailed(rep, id, off, .mismatch);
    }

    /// What `open` migrated, if it did: see `MigrationReport`.
    pub fn migration(self: *const Log) ?MigrationReport {
        return self.migrated;
    }

    /// A position saved before a migration from version 1 (no LSNs then),
    /// where it is now: the same record, or the same end. The payloads kept
    /// their lengths, so the old offsets are recomputed by walking the
    /// segment. Null when no record started there. For segments not changed
    /// since the migration (compaction moves records).
    pub fn translatePosition(self: *Log, old: Position) (IterError || error{OutOfMemory})!?Position {
        const i = std.mem.findScalar(u64, self.live.items, old.segment) orelse return error.SegmentGone;
        var nb: [seg_name_len]u8 = undefined;
        const h = self.store.open(segName(&nb, old.segment), .read_only) catch |e| switch (e) {
            error.FileNotFound => return error.SegmentGone,
            else => |x| return x,
        };
        defer self.store.close(h);
        const size = try self.store.size(h);
        const bound = if (self.active) |a| (if (a.id == old.segment) a.synced else size) else size;
        var w: Window = .{};
        defer w.deinit(self.gpa);
        var v1: u64 = legacy_header_len;
        var v2: u64 = segment_header_len;
        var lsn = self.live_lsn.items[i];
        while (true) {
            if (v1 == old.offset) return .{ .segment = old.segment, .offset = v2, .lsn = lsn };
            if (v1 > old.offset) return null;
            const raw = switch (try parseAt(&w, self.gpa, self.store, h, v2, bound, self.opts.max_record_len)) {
                .record => |r| r,
                else => return null,
            };
            if (raw.typ != rec_data) return null;
            v1 += legacy_rec_header_len + raw.payload.len;
            v2 += raw.len;
            lsn = raw.lsn + 1;
        }
    }

    /// The previous format's manifest (its CRC already checked): ids only.
    /// Every segment is `form_legacy`, its first LSN unknown until the
    /// migration has counted the records before it.
    fn loadLegacyManifest(self: *Log, body: []const u8) OpenError!void {
        const nl = std.mem.readInt(u32, body[8..12], .little);
        const np = std.mem.readInt(u32, body[12..16], .little);
        if (@as(u64, nl) + np > max_manifest_ids) return error.Corrupt;
        if (body.len != man_fixed + 8 * (@as(usize, nl) + np)) return error.Corrupt;
        try self.live.ensureTotalCapacity(self.gpa, nl);
        try self.live_lsn.ensureTotalCapacity(self.gpa, nl);
        try self.live_form.ensureTotalCapacity(self.gpa, nl);
        try self.pending.ensureTotalCapacity(self.gpa, np);
        var off: usize = man_fixed;
        for (0..nl) |_| {
            const id = std.mem.readInt(u64, body[off..][0..8], .little);
            if (self.newest()) |prev| if (id <= prev) return error.Corrupt;
            self.live.appendAssumeCapacity(id);
            self.live_lsn.appendAssumeCapacity(0);
            self.live_form.appendAssumeCapacity(form_legacy);
            off += 8;
        }
        for (0..np) |_| {
            const id = std.mem.readInt(u64, body[off..][0..8], .little);
            if (std.mem.findScalar(u64, self.live.items, id) != null) return error.Corrupt;
            self.pending.appendAssumeCapacity(id);
            off += 8;
        }
        self.legacy_manifest = true;
    }

    fn needsMigration(self: *const Log) bool {
        return self.legacy_manifest or std.mem.findScalar(u8, self.live_form.items, form_legacy) != null;
    }

    /// Replace `MANIFEST` with the current `live` and `pending` lists.
    fn commitManifest(self: *Log) Storage.Error!void {
        const nl = self.live.items.len;
        const np = self.pending.items.len;
        const size = man_fixed + man_entry_len * nl + 8 * np + man_crc_len;
        try self.scratch.resize(self.gpa, size);
        const b = self.scratch.items;
        @memset(b, 0);
        @memcpy(b[0..4], man_magic);
        std.mem.writeInt(u32, b[4..8], format_version, .little);
        std.mem.writeInt(u32, b[8..12], @intCast(nl), .little);
        std.mem.writeInt(u32, b[12..16], @intCast(np), .little);
        var off: usize = man_fixed;
        for (self.live.items, self.live_lsn.items, self.live_form.items) |id, first, form| {
            std.mem.writeInt(u64, b[off..][0..8], id, .little);
            std.mem.writeInt(u64, b[off + 8 ..][0..8], first, .little);
            b[off + 16] = form;
            off += man_entry_len;
        }
        for (self.pending.items) |id| {
            std.mem.writeInt(u64, b[off..][0..8], id, .little);
            off += 8;
        }
        std.mem.writeInt(u32, b[off..][0..4], crc32c(b[0..off]), .little);

        // From here every failure poisons: the manifest on media may now be
        // the old one or the new one, and this process can no longer say which.
        const h = self.store.open(manifest_tmp, .create_truncate) catch |e| return self.poison(e);
        {
            defer self.store.close(h);
            self.store.writeAll(h, b, 0) catch |e| return self.poison(e);
            self.store.sync(h) catch |e| return self.poison(e);
        }
        self.store.rename(manifest_tmp, manifest_name) catch |e| return self.poison(e);
        self.store.syncDir() catch |e| return self.poison(e);
    }

    /// What a crash can leave of a compression: its temp file, the `.zst`
    /// renamed into place before the manifest said so (the segment is still
    /// raw), or the `.log` not yet deleted after it did. Of each live segment
    /// only the file of its form is kept. (The newest is never compressed;
    /// deleting a `.zst` it cannot have costs one failed delete.)
    fn finishCompressions(self: *Log) Storage.Error!void {
        self.store.delete(compress_tmp) catch |e| switch (e) {
            error.FileNotFound => {},
            else => |x| return x,
        };
        for (self.live.items, self.live_form.items) |id, form| {
            var nb: [seg_name_len]u8 = undefined;
            const stray = if (form == form_zstd) segName(&nb, id) else zstName(&nb, id);
            self.store.delete(stray) catch |e| switch (e) {
                error.FileNotFound => {},
                else => |x| return x,
            };
        }
    }

    fn finishDrops(self: *Log) Storage.Error!void {
        if (self.pending.items.len == 0) return;
        try self.deletePending();
    }

    /// Delete the files of every pending segment, then commit an empty
    /// pending list. A failure leaves the rest pending, for the next call or
    /// the next `open`; a file already gone counts as deleted.
    fn deletePending(self: *Log) Storage.Error!void {
        while (self.pending.items.len > 0) {
            const victim = self.pending.items[self.pending.items.len - 1];
            var nb: [seg_name_len]u8 = undefined;
            self.store.delete(segName(&nb, victim)) catch |e| switch (e) {
                error.FileNotFound => {},
                else => |x| return x,
            };
            self.store.delete(zstName(&nb, victim)) catch |e| switch (e) {
                error.FileNotFound => {},
                else => |x| return x,
            };
            var ib: [seg_name_len]u8 = undefined;
            self.store.delete(idxName(&ib, victim)) catch |e| switch (e) {
                error.FileNotFound => {},
                else => |x| return x,
            };
            _ = self.pending.pop();
        }
        try self.commitManifest();
    }

    fn writeHeader(self: *Log, h: Storage.Handle, id: u64, base_lsn: u64, created: i64) Storage.Error!void {
        var hdr: [segment_header_len]u8 = undefined;
        encodeHeader(&hdr, id, base_lsn, created);
        try self.store.writeAll(h, &hdr, 0);
        try self.store.sync(h);
    }

    fn seal(self: *Log, a: *Active) Storage.Error!void {
        var payload: [seal_payload_len]u8 = undefined;
        a.tally.seal(a.end).encode(&payload);
        var rec: [rec_header_len + seal_payload_len]u8 = undefined;
        encodeRecord(&rec, rec_seal, 0, 0, &payload);
        // A closed segment ends at its seal: give the reservation back first.
        // A crash can keep the seal and lose the cut (the cut is metadata
        // the seal's own sync commits); `scanTail` reads zeros after a seal
        // as exactly that.
        if (a.reserved > a.end) {
            self.store.truncate(a.handle, a.end) catch |e| return self.poison(e);
            a.reserved = a.end;
        }
        self.store.writeAll(a.handle, &rec, a.end) catch |e| return self.poison(e);
        const t0 = self.clockNs();
        self.store.sync(a.handle) catch |e| return self.poison(e);
        self.countSync(self.clockNs() -| t0);
        a.end += rec.len;
        // One fsync for the seal and whatever the policy left waiting.
        a.synced = a.end;
        self.synced_next_lsn = self.next_lsn;
    }

    /// Open the newest segment for appending, repairing its tail. Leaves
    /// `active` null when the newest segment is sealed. Sets `next_lsn`.
    fn openNewest(self: *Log) OpenError!void {
        const id = self.newest() orelse return;
        const base = self.live_lsn.items[self.live_lsn.items.len - 1];
        self.next_lsn = base;
        var nb: [seg_name_len]u8 = undefined;
        const name = segName(&nb, id);
        const h = try self.store.open(name, .open_or_create);
        var keep = false;
        defer if (!keep) self.store.close(h);

        const size = try self.store.size(h);
        if (size < segment_header_len) {
            // Named in the manifest, but `rotate` did not get to write it.
            // Truncate first: a torn header's surviving bytes are durable,
            // and rewriting them in place is not an append.
            try self.store.truncate(h, 0);
            const created = self.stamp();
            try self.writeHeader(h, id, base, created);
            try self.store.syncDir();
            self.cut_on_open = size;
            self.active = .{ .id = id, .handle = h, .end = segment_header_len, .synced = segment_header_len, .reserved = segment_header_len, .tally = Tally.init(base, false), .created = created };
            keep = true;
            return;
        }
        var flags: u32 = 0;
        switch (try checkHeaderFlags(self.store, h, id, base, &flags)) {
            .ok => {},
            .unsupported => return error.UnsupportedVersion,
            .short, .mismatch => return error.Corrupt,
        }

        var index: SparseIndex = .{};
        errdefer index.deinit(self.gpa);
        const tail = try self.scanTail(h, size, base, flags & flag_compacted != 0, if (self.opts.index_interval != 0) &index else null);
        if (tail.end < size) {
            // Zeros are reserved space (`Options.preallocate`), not a torn
            // write: only what ends at the last nonzero byte was cut. The
            // reservation goes too — rewriting whatever a torn write left in
            // it would be an overwrite — and comes back with the next append.
            const dirty_end = try lastNonZero(self.store, h, tail.end, size);
            try self.store.truncate(h, tail.end);
            try self.store.sync(h);
            self.cut_on_open = dirty_end - tail.end;
        }
        self.next_lsn = tail.tally.nextLsn();
        self.synced_next_lsn = self.next_lsn;
        if (tail.sealed) {
            index.deinit(self.gpa);
            return;
        }
        // What `open` found on disk may still sit in the page cache, never
        // synced by the writer that died: sync it before trusting it.
        try self.store.sync(h);
        var stamp_buf: [8]u8 = undefined;
        try self.store.preadFull(h, &stamp_buf, 24);
        const created = std.mem.readInt(i64, &stamp_buf, .little);
        self.active = .{ .id = id, .handle = h, .end = tail.end, .synced = tail.end, .reserved = tail.end, .tally = tail.tally, .created = created, .index = index };
        keep = true;
    }

    const Tail = struct { end: u64, tally: Tally, sealed: bool };

    /// Walk the newest segment to the end of its last good record. Anything
    /// a torn write can leave — a short header, a length running past the
    /// file, a CRC that does not match — ends the walk there, to be cut off.
    /// A record that passes its CRC and is still wrong cannot come from a
    /// torn write, and is `error.Corrupt`.
    fn scanTail(self: *Log, h: Storage.Handle, size: u64, base: u64, compacted: bool, index: ?*SparseIndex) OpenError!Tail {
        var w: Window = .{};
        defer w.deinit(self.gpa);
        var off: u64 = segment_header_len;
        var tally: Tally = Tally.init(base, compacted);
        while (true) {
            const raw = switch (try parseAt(&w, self.gpa, self.store, h, off, size, self.opts.max_record_len)) {
                .record => |r| r,
                .short, .bad_crc => break,
                // ⛔⛔ L5 fix (2026-09-27): a length field over this open's
                // `max_record_len` is never believed (`parseAt`'s contract),
                // but treating it as a torn tail here -- like `.short` and
                // `.bad_crc`, which genuinely can be one -- would TRUNCATE
                // whatever follows the moment `Options.max_record_len` is
                // lowered below a record a caller legitimately wrote here
                // under a larger one: silent, irreversible data loss in the
                // active segment, not merely a read-time `Corrupt` (which is
                // all a *closed* segment risks; see `Iterator.next`). Refuse
                // the option instead of guessing which case this is.
                .too_long => return error.RecordTooLongForOptions,
            };
            switch (raw.typ) {
                rec_data => {
                    if (!tally.fits(raw.lsn)) return error.Corrupt;
                    if (index) |ix| {
                        try ix.entries.ensureUnusedCapacity(self.gpa, 1);
                        ix.note(self.opts.index_interval, .{ .lsn = raw.lsn, .offset = off, .max_before = tally.maxOrMin() });
                    }
                    tally.add(raw.ts, raw.lsn);
                },
                rec_seal => {
                    if (!sealAgrees(raw, tally, off)) return error.Corrupt;
                    // Nothing is ever written after a seal, so bytes beyond
                    // it cannot be a torn write of ours. Zeros can be: the
                    // reservation `seal` cut, with the cut lost to a crash.
                    const sealed_end = off + raw.len;
                    if (try lastNonZero(self.store, h, sealed_end, size) != sealed_end) return error.Corrupt;
                    return .{ .end = sealed_end, .tally = tally, .sealed = true };
                },
                else => return error.Corrupt,
            }
            off += raw.len;
        }
        return .{ .end = off, .tally = tally, .sealed = false };
    }
};

/// A `Log` for many threads: every call takes one lock, and under the
/// default `.always` policy appends from different threads share an fsync —
/// **group commit**. An append writes its records under the lock; then either
/// its thread becomes the one that runs the fsync — outside the lock, for
/// everything written so far — or it waits for a running fsync that covers it,
/// while others go on appending for the next round. `append` still returns
/// only once its records are durable. RocksDB's write group and PostgreSQL's
/// commit_delay do the same.
///
/// Iterators take the lock for each `next`, reads included, so a long scan
/// slows appends down; a reader in its own thread or process that can live
/// with the read-only caveats opens the log with `Log.openReadOnly` instead.
/// The `Concurrent` must not move once it is shared.
pub const Concurrent = struct {
    log: Log,
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    /// An fsync is running outside the lock.
    syncing: bool = false,
    /// `.always` was asked for: appends wait for a group fsync.
    group: bool,

    pub fn open(gpa: Allocator, store: Storage, io: std.Io, opts: Options) OpenError!Concurrent {
        var inner = opts;
        const group = opts.sync == .always;
        if (group) inner.sync = .manual; // the group fsync replaces the per-append one
        return .{ .log = try Log.open(gpa, store, inner), .io = io, .group = group };
    }

    /// No other thread may use it any more.
    pub fn close(c: *Concurrent) void {
        c.log.close();
        c.* = undefined;
    }

    pub fn append(c: *Concurrent, payload: []const u8) AppendError!Appended {
        return c.appendManyAt(c.log.stamp(), &.{payload});
    }

    pub fn appendAt(c: *Concurrent, ts: i64, payload: []const u8) AppendError!Appended {
        return c.appendManyAt(ts, &.{payload});
    }

    pub fn appendMany(c: *Concurrent, payloads: []const []const u8) AppendError!Appended {
        return c.appendManyAt(c.log.stamp(), payloads);
    }

    pub fn appendManyAt(c: *Concurrent, ts: i64, payloads: []const []const u8) AppendError!Appended {
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        const first = try c.log.appendManyAt(ts, payloads);
        if (c.group) try c.waitDurable(c.log.nextLsn());
        return first;
    }

    pub fn appendEntries(c: *Concurrent, entries: []const Entry) AppendError!Appended {
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        const first = try c.log.appendEntries(entries);
        if (c.group) try c.waitDurable(c.log.nextLsn());
        return first;
    }

    /// Under the lock: return once every record below `want` is durable,
    /// running the fsync if no one else is.
    fn waitDurable(c: *Concurrent, want: u64) AppendError!void {
        while (c.log.durableLsn() < want) {
            if (c.log.poisoned) return error.Poisoned;
            if (c.syncing) {
                c.cond.waitUncancelable(c.io, &c.mutex);
                continue;
            }
            const t = (try c.log.syncBegin()) orelse return;
            c.syncing = true;
            c.mutex.unlock(c.io);
            const t0 = c.log.clockNs();
            const r = c.log.store.syncData(t.handle);
            const ns = c.log.clockNs() -| t0;
            c.mutex.lockUncancelable(c.io);
            c.syncing = false;
            c.log.syncFinish(t, r, ns);
            c.cond.broadcast(c.io);
            try r;
        }
    }

    /// `Log.sync`, shared with any group fsync running.
    pub fn sync(c: *Concurrent) AppendError!void {
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        try c.waitDurable(c.log.nextLsn());
    }

    pub fn rotate(c: *Concurrent, id: u64) RotateError!void {
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        return c.log.rotate(id);
    }

    pub fn dropBefore(c: *Concurrent, id: u64) DropError!usize {
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        return c.log.dropBefore(id);
    }

    pub fn enforceRetention(c: *Concurrent, r: Retention, now: i64) DropError!usize {
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        return c.log.enforceRetention(r, now);
    }

    pub fn nextLsn(c: *Concurrent) u64 {
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        return c.log.nextLsn();
    }

    pub fn durableLsn(c: *Concurrent) u64 {
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        return c.log.durableLsn();
    }

    pub fn stats(c: *Concurrent) Stats {
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        return c.log.stats();
    }

    /// `Log.compact`, holding the lock throughout.
    pub fn compact(c: *Concurrent, id: u64, ctx: anytype, comptime keep: fn (@TypeOf(ctx), Record) bool) CompactError!CompactStats {
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        return c.log.compact(id, ctx, keep);
    }

    pub fn compress(c: *Concurrent, id: u64) CompressError!CompressStats {
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        return c.log.compress(id);
    }

    pub fn seek(c: *Concurrent, lsn: u64) SeekError!?Position {
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        return c.log.seek(lsn);
    }

    pub fn seekTime(c: *Concurrent, t: i64) SeekError!?Position {
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        return c.log.seekTime(t);
    }

    pub fn iterator(c: *Concurrent, from: ?Position) LockedIterator {
        return .{ .c = c, .inner = c.log.iterator(from) };
    }

    /// `Iterator` under the `Concurrent`'s lock. A returned payload stays
    /// valid until this iterator's next call, as with `Iterator`.
    pub const LockedIterator = struct {
        c: *Concurrent,
        inner: Iterator,

        pub fn next(it: *LockedIterator) IterError!?Record {
            it.c.mutex.lockUncancelable(it.c.io);
            defer it.c.mutex.unlock(it.c.io);
            return it.inner.next();
        }

        pub fn deinit(it: *LockedIterator) void {
            it.c.mutex.lockUncancelable(it.c.io);
            defer it.c.mutex.unlock(it.c.io);
            it.inner.deinit();
        }
    };
};

/// Whether a seal record agrees with the data records read before it, when
/// the reader saw them all from the segment's first record (`tally`), or
/// at least with its own place in the file.
fn sealAgrees(raw: Raw, tally: ?Tally, at: u64) bool {
    if (raw.lsn != 0 or raw.ts != 0) return false;
    const s = Seal.decode(raw.payload) orelse return false;
    if (s.offset != at) return false;
    if (tally) |t| {
        const want = t.seal(at);
        if (t.compacted) {
            // Its LSN range is the segment's, not its surviving records'.
            if (s.count != want.count or s.first_lsn != t.base or s.min_ts != want.min_ts or s.max_ts != want.max_ts) return false;
            if (s.last_lsn +% 1 < t.last_lsn +% 1) return false;
        } else if (!std.meta.eql(s, want)) return false;
    }
    return true;
}

/// Reads records in order, across segments, following the writer. Borrows
/// the `Log`: it must not outlive it, and the `Log` must not move.
pub const Iterator = struct {
    log: *Log,
    /// Where to begin, until the first segment has been entered.
    start: ?Position,
    seg: ?u64 = null,
    handle: ?Storage.Handle = null,
    offset: u64 = 0,
    /// The data records read in this segment — known only when the iterator
    /// entered it at its first record, and only then checked against the seal.
    tally: ?Tally = null,
    /// The LSN the next data record must carry, once one has been read in
    /// this segment (or from its first record on).
    expect_lsn: ?u64 = null,
    sealed: bool = false,
    /// The segment was compacted: its LSNs only rise.
    compacted: bool = false,
    window: Window = .{},
    /// What the last `error.Corrupt` was about, until the next move.
    damaged: ?Damage = null,

    pub fn deinit(it: *Iterator) void {
        it.leave();
        it.window.deinit(it.log.gpa);
        it.* = undefined;
    }

    /// The next record, or null at the live end of the log (call again
    /// later to see what has been appended since).
    pub fn next(it: *Iterator) IterError!?Record {
        const reader = it.log.read_only;
        while (true) {
            if (it.handle == null and !try it.enter()) return null;
            const seg = it.seg.?;
            const h = it.handle.?;
            const store = it.log.store;

            // The segment the writer may still be appending to. A writer knows
            // it; a reader takes the newest segment it has heard of, until a
            // seal or a newer manifest says otherwise.
            const live_tail = if (reader)
                !it.sealed and it.log.newest() == seg
            else if (it.log.active) |a| a.id == seg else false;
            const bound = if (!reader and live_tail) it.log.active.?.synced else try store.size(h);

            if (it.offset >= bound) {
                if (it.offset > bound) return it.corrupt(seg, bound, .truncated);
                // A reader needs no manifest here to notice a rotation:
                // `rotate` syncs the seal onto this segment before it commits
                // the manifest naming the next one, so the reader meets the
                // seal first, and `enter` then looks the successor up.
                if (live_tail) return null;
                // A closed segment has to end exactly at the end of its seal.
                if (!it.sealed) return it.corrupt(seg, it.offset, .missing_seal);
                it.leave();
                continue;
            }
            if (it.sealed) return it.corrupt(seg, it.offset, .bytes_after_seal);
            // In a reader's live tail, bytes that do not yet make one whole,
            // checked record are an append still arriving: stop there and
            // come back — and forget them, for they are still changing.
            // Anywhere else they are corruption.
            const soft = reader and live_tail;
            const raw = switch (try parseAt(&it.window, it.log.gpa, store, h, it.offset, bound, it.log.opts.max_record_len)) {
                .record => |r| r,
                // ⛔⛔ L5 fix (2026-09-27): `.too_long` gets its own reason —
                // `record_too_long`, not `bad_record` — since a length field
                // over this open's `max_record_len` is not necessarily
                // damage: a record legitimately written under a larger
                // `max_record_len` reads exactly the same way, and an
                // operator or an automated `resync` had no way to tell the
                // two apart from the same `Corrupt`/`bad_record` every other
                // "not a whole record" case gets.
                .too_long => blk: {
                    if (!soft) return it.corrupt(seg, it.offset, .record_too_long);
                    break :blk (try it.retrySoft(store, h, bound)) orelse return null;
                },
                .short, .bad_crc => blk: {
                    if (!soft) return it.corrupt(seg, it.offset, .bad_record);
                    break :blk (try it.retrySoft(store, h, bound)) orelse return null;
                },
            };

            const pos: Position = .{ .segment = seg, .offset = it.offset, .lsn = if (raw.typ == rec_data) raw.lsn else null };
            it.damaged = null;
            switch (raw.typ) {
                rec_data => {
                    if (it.expect_lsn) |want| {
                        const bad = if (it.compacted) raw.lsn < want else raw.lsn != want;
                        if (bad) return it.corrupt(seg, pos.offset, .lsn_out_of_sequence);
                    }
                    it.expect_lsn = raw.lsn + 1;
                    if (it.tally) |*t| t.add(raw.ts, raw.lsn);
                    it.offset += raw.len;
                    return .{
                        .pos = pos,
                        .next = .{ .segment = seg, .offset = it.offset, .lsn = raw.lsn + 1 },
                        .lsn = raw.lsn,
                        .ts = raw.ts,
                        .payload = raw.payload,
                    };
                },
                rec_seal => {
                    if (!sealAgrees(raw, it.tally, pos.offset)) return it.corrupt(seg, pos.offset, .bad_seal);
                    if (it.expect_lsn) |want| {
                        const s = Seal.decode(raw.payload).?;
                        const bad = if (it.compacted) s.last_lsn +% 1 < want else s.last_lsn +% 1 != want;
                        if (bad) return it.corrupt(seg, pos.offset, .bad_seal);
                    }
                    it.offset += raw.len;
                    it.sealed = true;
                },
                else => return it.corrupt(seg, pos.offset, .bad_record),
            }
        }
    }

    fn corrupt(it: *Iterator, seg: u64, offset: u64, reason: Damage.Reason) IterError {
        it.damaged = .{ .segment = seg, .offset = offset, .reason = reason };
        return error.Corrupt;
    }

    /// `next`'s live-tail retry: the window may hold reserved zeros read
    /// before the writer filled them or cut them at its seal, so a "not a
    /// whole record" the first time is read once more before it is called
    /// the end. Returns the record if the retry found one, else null (the
    /// live end: come back later). Only called when `soft`.
    fn retrySoft(it: *Iterator, store: Storage, h: Storage.Handle, bound: u64) IterError!?Raw {
        it.window.forget(it.offset);
        return switch (try parseAt(&it.window, it.log.gpa, store, h, it.offset, bound, it.log.opts.max_record_len)) {
            .record => |r| r,
            .short, .too_long, .bad_crc => {
                it.window.forget(it.offset);
                return null;
            },
        };
    }

    /// After `next` failed with `error.Corrupt`: where, and what was wrong.
    /// Null otherwise.
    pub fn damage(it: *const Iterator) ?Damage {
        return it.damaged;
    }

    /// After `error.Corrupt`: give the rest of the damaged segment up, and
    /// go on with the next one. Returns the LSNs that were not read — as far
    /// as they are known — or null when there is no damage to step over.
    /// Nothing is repaired or deleted; the segment stays as it is.
    pub fn skipSegment(it: *Iterator) ?Gap {
        const d = it.damaged orelse return null;
        const from: ?u64 = if (it.seg == d.segment and it.expect_lsn != null)
            it.expect_lsn
        else if (d.offset == segment_header_len or it.seg != d.segment)
            it.log.segmentFirstLsn(d.segment)
        else
            null;
        it.leave();
        it.start = null;
        it.seg = d.segment;
        it.damaged = null;
        const next_first: ?u64 = if (it.following()) |n| it.log.segmentFirstLsn(n) else null;
        return .{ .from_lsn = from, .to_lsn = if (next_first) |n| n - 1 else null };
    }

    /// After `error.Corrupt` inside a segment: look past the damage for the
    /// next record that is whole, checks out, and fits the LSN sequence —
    /// LevelDB's resynchronisation, made exact by the LSN every record
    /// carries. Returns the LSNs skipped over, as far as known. When nothing
    /// intact follows in the segment this is `skipSegment`. The seal, if
    /// found, is still checked against its own offset and LSN range, but no
    /// longer against a count the damage has made unknowable.
    pub fn resync(it: *Iterator) IterError!?Gap {
        const d = it.damaged orelse return null;
        const h = it.handle orelse return it.skipSegment(); // the header itself was bad
        if (it.seg != d.segment) return it.skipSegment();
        const store = it.log.store;
        const bound = if (!it.log.read_only and it.log.activeSegment() == d.segment)
            it.log.active.?.synced
        else
            try store.size(h);
        const floor = it.expect_lsn orelse 0;
        const next_first: ?u64 = if (it.following()) |n| it.log.segmentFirstLsn(n) else null;
        var off = d.offset + 1;
        while (off + rec_header_len <= bound) : (off += 1) {
            const raw = switch (try parseAt(&it.window, it.log.gpa, store, h, off, bound, it.log.opts.max_record_len)) {
                .record => |r| r,
                else => {
                    // Past where the bytes really end — a size the file or a
                    // damaged seek table claims — no record can start.
                    if (it.window.short_at) |end| if (off + rec_header_len > end) break;
                    continue;
                },
            };
            const to: u64 = switch (raw.typ) {
                rec_data => blk: {
                    if (raw.lsn < floor or raw.lsn == 0) continue;
                    if (next_first) |n| if (raw.lsn >= n) continue;
                    break :blk raw.lsn - 1;
                },
                rec_seal => blk: {
                    if (!sealAgrees(raw, null, off)) continue;
                    const s = Seal.decode(raw.payload).?;
                    if (s.last_lsn +% 1 < floor) continue;
                    break :blk s.last_lsn;
                },
                else => continue,
            };
            const from = it.expect_lsn;
            it.offset = off;
            it.tally = null; // the seal's count can no longer be checked
            it.expect_lsn = if (raw.typ == rec_data) raw.lsn else null;
            it.damaged = null;
            return .{ .from_lsn = from, .to_lsn = to };
        }
        return it.skipSegment();
    }

    /// A reader's view of the manifest, brought up to date.
    fn refreshLog(it: *Iterator) IterError!void {
        it.log.refresh() catch |e| switch (e) {
            // The manifest itself went away: nothing of the log is left.
            error.NotFound => return error.SegmentGone,
            error.Locked => unreachable, // a reader takes no lock
            error.NeedsMigration, error.MigrationFailed => unreachable, // a reader never migrates
            // L5: see `refreshForSeek` — `scanTail`'s error, unreachable
            // through `refresh`'s own call to `loadManifest` alone.
            error.RecordTooLongForOptions => unreachable,
            else => |x| return x,
        };
    }

    /// Open the segment to read next. False when there is none yet.
    fn enter(it: *Iterator) IterError!bool {
        const reader = it.log.read_only;
        var target: u64 = undefined;
        var offset: u64 = segment_header_len;

        if (it.start) |s| {
            if (s.offset < segment_header_len) return error.InvalidPosition;
            // A reader may simply not have heard of the segment yet.
            if (reader and !it.knows(s.segment)) try it.refreshLog();
            const live = it.log.live.items;
            if (live.len == 0 or s.segment < live[0]) return error.SegmentGone;
            // Segments are only ever dropped from the old end, so a position
            // between two live segments, or past the newest, was never one
            // this log handed out. Skipping to the next segment would read
            // on from somewhere nobody asked for.
            if (std.mem.findScalar(u64, live, s.segment) == null) return error.InvalidPosition;
            target = s.segment;
            offset = s.offset;
        } else {
            target = it.following() orelse blk: {
                if (!reader) return false;
                try it.refreshLog();
                break :blk it.following() orelse return false;
            };
        }
        const base = it.log.segmentFirstLsn(target).?;

        // The newest segment of a reader's view may be one the writer is
        // still creating: `rotate` names it in the manifest before its file
        // exists, and writes the header after. Neither is corruption yet.
        const unfinished_ok = reader and it.log.newest() == target;
        var nb: [seg_name_len]u8 = undefined;
        const store = it.log.store;
        const h = store.open(segName(&nb, target), .read_only) catch |e| switch (e) {
            error.FileNotFound => return if (unfinished_ok) false else error.SegmentGone,
            else => |x| return x,
        };
        errdefer store.close(h);
        var flags: u32 = 0;
        switch (try checkHeaderFlags(store, h, target, base, &flags)) {
            .ok => {},
            .unsupported => return error.UnsupportedVersion,
            .short => {
                if (unfinished_ok) {
                    store.close(h);
                    return false;
                }
                return it.corrupt(target, 0, .bad_header);
            },
            .mismatch => return it.corrupt(target, 0, .bad_header),
        }

        // A position that names its record is checked: is it still there?
        if (it.start) |s| if (s.lsn) |want| {
            if (!try it.startStillValid(h, target, offset, want)) {
                store.close(h);
                const moved = it.log.seek(want) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => |x| return x,
                };
                if (moved) |m| {
                    // Where `seek` says is authoritative: not checked again.
                    it.start = .{ .segment = m.segment, .offset = m.offset };
                    return it.enter();
                }
                // Not reached yet: the position was the live end, and is.
                return it.enterUnchecked(target, offset, base);
            }
        };
        return it.finishEnter(h, target, offset, base, flags & flag_compacted != 0);
    }

    /// Whether the record at `offset` of the segment is the one with LSN
    /// `want` — or `offset` is its live end and `want` the next LSN.
    fn startStillValid(it: *Iterator, h: Storage.Handle, target: u64, offset: u64, want: u64) IterError!bool {
        const store = it.log.store;
        const writer_live = !it.log.read_only and it.log.activeSegment() == target;
        const bound = if (writer_live) it.log.active.?.synced else try store.size(h);
        if (offset == bound) return !writer_live or want == it.log.durableLsn();
        const raw = switch (try parseAt(&it.window, it.log.gpa, store, h, offset, bound, it.log.opts.max_record_len)) {
            .record => |r| r,
            else => return false,
        };
        return raw.typ == rec_data and raw.lsn == want;
    }

    /// `enter` without the LSN check, for a live-end position.
    fn enterUnchecked(it: *Iterator, target: u64, offset: u64, base: u64) IterError!bool {
        var nb: [seg_name_len]u8 = undefined;
        const h = it.log.store.open(segName(&nb, target), .read_only) catch |e| switch (e) {
            error.FileNotFound => return error.SegmentGone,
            else => |x| return x,
        };
        errdefer it.log.store.close(h);
        var flags: u32 = 0;
        switch (try checkHeaderFlags(it.log.store, h, target, base, &flags)) {
            .ok => {},
            .unsupported => return error.UnsupportedVersion,
            .short, .mismatch => return it.corrupt(target, 0, .bad_header),
        }
        return it.finishEnter(h, target, offset, base, flags & flag_compacted != 0);
    }

    fn finishEnter(it: *Iterator, h: Storage.Handle, target: u64, offset: u64, base: u64, compacted: bool) IterError!bool {
        it.start = null;
        it.seg = target;
        it.handle = h;
        it.offset = offset;
        it.compacted = compacted;
        const from_first = offset == segment_header_len;
        it.tally = if (from_first) Tally.init(base, compacted) else null;
        it.expect_lsn = if (from_first) base else null;
        it.sealed = false;
        it.window.reset();
        return true;
    }

    /// The segment after the current one, or the oldest when none has been
    /// entered yet.
    fn following(it: *const Iterator) ?u64 {
        const live = it.log.live.items;
        if (it.seg) |cur| return firstAfter(live, cur);
        return if (live.len == 0) null else live[0];
    }

    fn knows(it: *const Iterator, id: u64) bool {
        return std.mem.findScalar(u64, it.log.live.items, id) != null;
    }

    fn leave(it: *Iterator) void {
        if (it.handle) |h| it.log.store.close(h);
        it.handle = null;
    }

    fn firstAfter(live: []const u64, id: u64) ?u64 {
        for (live) |x| if (x > id) return x;
        return null;
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

test {
    _ = @import("fault_test.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("migrate_test.zig");
}

const testing = std.testing;

/// Every record from `from`, as owned copies, for comparing against a model.
fn readAll(log: *Log, from: ?Position) !std.ArrayList([]u8) {
    var out: std.ArrayList([]u8) = .empty;
    errdefer freeAll(&out);
    var it = log.iterator(from);
    defer it.deinit();
    while (try it.next()) |r| try out.append(testing.allocator, try testing.allocator.dupe(u8, r.payload));
    return out;
}

fn freeAll(list: *std.ArrayList([]u8)) void {
    for (list.items) |p| testing.allocator.free(p);
    list.deinit(testing.allocator);
}

fn expectPayloads(log: *Log, from: ?Position, want: []const []const u8) !void {
    var got = try readAll(log, from);
    defer freeAll(&got);
    try testing.expectEqual(want.len, got.items.len);
    for (want, got.items) |w, g| try testing.expectEqualStrings(w, g);
}

fn openSim(sim: *SimStorage) !Log {
    return Log.open(testing.allocator, sim.storage(), .{ .create = true });
}

test "records come back in order, at the positions append returned" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try openSim(&sim);
    defer log.close();

    try log.rotate(7);
    const p0 = try log.append("alpha");
    const p1 = try log.append("");
    const p2 = try log.append("gamma-gamma");

    // Positions are arithmetic on the format, not an artefact of the reader:
    // the first record starts right after the header, and each next one
    // after the previous one's header and payload.
    try testing.expectEqual(Position{ .segment = 7, .offset = 40, .lsn = 1 }, p0.pos);
    try testing.expectEqual(Position{ .segment = 7, .offset = 40 + 25 + 5, .lsn = 2 }, p1.pos);
    try testing.expectEqual(Position{ .segment = 7, .offset = 40 + 25 + 5 + 25, .lsn = 3 }, p2.pos);
    try testing.expectEqual(Position{ .segment = 7, .offset = 40 + 25 + 5 + 25 + 25 + 11, .lsn = 4 }, log.end().?);
    // LSNs count records from 1, whatever the segment ids are.
    try testing.expectEqual(@as(u64, 1), p0.lsn);
    try testing.expectEqual(@as(u64, 2), p1.lsn);
    try testing.expectEqual(@as(u64, 3), p2.lsn);
    try testing.expectEqual(@as(u64, 4), log.nextLsn());

    var it = log.iterator(null);
    defer it.deinit();
    const want = [_]struct { []const u8, Appended }{ .{ "alpha", p0 }, .{ "", p1 }, .{ "gamma-gamma", p2 } };
    for (want, 0..) |w, i| {
        const r = (try it.next()).?;
        try testing.expectEqualStrings(w[0], r.payload);
        try testing.expectEqual(w[1].pos, r.pos);
        try testing.expectEqual(w[1].lsn, r.lsn);
        const after = if (i + 1 < want.len) want[i + 1][1].pos else log.end().?;
        try testing.expectEqual(after, r.next);
    }
    try testing.expectEqual(@as(?Record, null), try it.next());
}

test "a new log has nothing to read, and refuses appends until rotate" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try openSim(&sim);
    defer log.close();

    try testing.expectEqual(@as(?u64, null), log.newest());
    try testing.expectError(error.NoActiveSegment, log.append("x"));
    try expectPayloads(&log, null, &.{});
    // A refused append must not have poisoned anything.
    try log.rotate(1);
    _ = try log.append("x");
    try expectPayloads(&log, null, &.{"x"});
}

test "L1: a manifest lost while its segments survive refuses instead of truncating them" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    {
        var log = try openSim(&sim);
        try log.rotate(20722); // a day id, as egw-hub uses
        _ = try log.append("alpha");
        _ = try log.append("beta");
        log.close();
    }
    const before = try testing.allocator.dupe(u8, sim.fileContent("seg-00000000000000020722.log").?);
    defer testing.allocator.free(before);

    // What an incomplete backup/restore step leaves: every segment file
    // survives, only MANIFEST is gone (audit finding L1).
    try sim.storage().delete(manifest_name);

    // Reopening with `create = true`, as the hub always does, must not read
    // this as an empty log.
    var log2 = try openSim(&sim);
    try testing.expectEqual(@as(usize, 0), log2.segments().len);

    // The hub always rotates to "today" unconditionally at startup; a
    // same-day restart names exactly the segment that is already there.
    try testing.expectError(error.OrphanSegment, log2.rotate(20722));
    try testing.expect(log2.isPoisoned());
    // The refusal must not have touched the bytes it refused to adopt.
    try testing.expectEqualSlices(u8, before, sim.fileContent("seg-00000000000000020722.log").?);
    log2.close();

    // The other side of the same check: a name that merely EXISTS with zero
    // bytes (indistinguishable from "nothing written there yet") is not an
    // orphan. Only real content refuses.
    try sim.installFile("seg-00000000000000020723.log", &.{});
    var log3 = try openSim(&sim);
    defer log3.close();
    try log3.rotate(20723);
    _ = try log3.append("gamma");
    try testing.expect(!log3.isPoisoned());
}

test "L4: rebuildManifest recreates a manifest that reopens exactly like the original" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    {
        var log = try openSim(&sim);
        defer log.close();
        try log.rotate(1);
        _ = try log.append("a");
        _ = try log.append("b");
        try log.rotate(2);
        _ = try log.append("c");
        _ = try log.compress(1); // segment 1 becomes seg-1.zst
        try log.rotate(3);
        _ = try log.append("d");
    }
    try sim.storage().delete(manifest_name);

    try Log.rebuildManifest(testing.allocator, sim.storage(), &.{ 1, 2, 3 });

    var log = try Log.open(testing.allocator, sim.storage(), .{});
    defer log.close();
    try testing.expectEqualSlices(u64, &.{ 1, 2, 3 }, log.segments());
    try expectPayloads(&log, null, &.{ "a", "b", "c", "d" });
    var r = try log.verify(testing.allocator);
    defer r.deinit(testing.allocator);
    try testing.expect(r.clean());
    try testing.expectEqual(@as(u64, 4), r.records);
}

test "L4: rebuildManifest refuses when segments' LSN ranges disagree" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    {
        var log = try openSim(&sim);
        defer log.close();
        try log.rotate(1);
        _ = try log.append("a"); // segment 1's seal: last LSN 1
        try log.rotate(2);
        _ = try log.append("b"); // segment 2's header base LSN: 2, correctly
    }
    // Corrupt segment 2's header to claim base LSN 5: it and segment 1's
    // seal now disagree about where the sequence continues.
    var nb: [seg_name_len]u8 = undefined;
    const seg2 = sim.fileContent(segName(&nb, 2)).?;
    std.mem.writeInt(u64, seg2[16..24], 5, .little);
    std.mem.writeInt(u32, seg2[36..40], crc32c(seg2[0..36]), .little);

    try sim.storage().delete(manifest_name);
    try testing.expectError(error.Corrupt, Log.rebuildManifest(testing.allocator, sim.storage(), &.{ 1, 2 }));
}

test "L4: rebuildManifest refuses when a MANIFEST already opens" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try openSim(&sim);
    defer log.close();
    try log.rotate(1);
    _ = try log.append("a");
    try testing.expectError(error.ManifestPresent, Log.rebuildManifest(testing.allocator, sim.storage(), &.{1}));
}

test "L4: rebuildManifest refuses bad input before writing anything" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    {
        var log = try openSim(&sim);
        defer log.close();
        try log.rotate(1);
        _ = try log.append("a");
    }
    try sim.storage().delete(manifest_name);
    try testing.expectError(error.NoSegments, Log.rebuildManifest(testing.allocator, sim.storage(), &.{}));
    try testing.expectError(error.Corrupt, Log.rebuildManifest(testing.allocator, sim.storage(), &.{ 2, 1 }));
    try testing.expectError(error.SegmentGone, Log.rebuildManifest(testing.allocator, sim.storage(), &.{ 1, 9 }));
    // None of the refusals above wrote a manifest.
    try testing.expect(sim.fileContent(manifest_name) == null);
    try Log.rebuildManifest(testing.allocator, sim.storage(), &.{1});
    try testing.expect(sim.fileContent(manifest_name) != null);
}

test "without create, a missing log is NotFound, and a created one opens" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    try testing.expectError(error.NotFound, Log.open(testing.allocator, sim.storage(), .{}));
    {
        var log = try openSim(&sim);
        log.close();
    }
    var log = try Log.open(testing.allocator, sim.storage(), .{});
    log.close();
}

test "rotate seals the old segment, and reading crosses into the new one" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try openSim(&sim);
    defer log.close();

    try log.rotate(1);
    _ = try log.append("a1");
    _ = try log.append("a2");
    try log.rotate(2);
    _ = try log.append("b1");
    try log.rotate(5); // gaps are fine; order is what is enforced
    _ = try log.append("c1");

    try testing.expectEqualSlices(u64, &.{ 1, 2, 5 }, log.segments());
    try testing.expectEqual(@as(?u64, 5), log.activeSegment());
    try expectPayloads(&log, null, &.{ "a1", "a2", "b1", "c1" });

    // The closed segment really carries a seal: count 2, at its own offset.
    const seg1 = sim.fileContent("seg-00000000000000000001.log").?;
    const seal_at = 40 + (25 + 2) * 2;
    try testing.expectEqual(@as(usize, seal_at + 25 + 48), seg1.len);
    try testing.expectEqual(rec_seal, seg1[seal_at + 4]);
    const sp = seg1[seal_at + 25 ..];
    try testing.expectEqual(@as(u64, 2), std.mem.readInt(u64, sp[0..8], .little)); // count
    try testing.expectEqual(@as(u64, seal_at), std.mem.readInt(u64, sp[8..16], .little)); // own offset
    try testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, sp[16..24], .little)); // first LSN
    try testing.expectEqual(@as(u64, 2), std.mem.readInt(u64, sp[24..32], .little)); // last LSN
}

test "rotate to the active id is a no-op, and ids never go back" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try openSim(&sim);
    defer log.close();

    try log.rotate(10);
    _ = try log.append("x");
    try log.rotate(10);
    try testing.expectEqualSlices(u64, &.{10}, log.segments());
    _ = try log.append("y"); // still the same, unsealed segment
    try testing.expectError(error.NonMonotonic, log.rotate(9));
    try log.rotate(11);
    // 10 is sealed now; it cannot become active again.
    try testing.expectError(error.NonMonotonic, log.rotate(10));
    try expectPayloads(&log, null, &.{ "x", "y" });
}

test "a reopened log resumes appending exactly where it left off" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var end_before: Position = undefined;
    {
        var log = try openSim(&sim);
        defer log.close();
        try log.rotate(3);
        _ = try log.append("one");
        try log.rotate(4);
        _ = try log.append("two");
        end_before = log.end().?;
    }
    var log = try openSim(&sim);
    defer log.close();
    try testing.expectEqual(end_before, log.end().?);
    try testing.expectEqualSlices(u64, &.{ 3, 4 }, log.segments());
    const p = try log.append("three");
    try testing.expectEqual(end_before, p.pos);
    try testing.expectEqual(@as(u64, 3), p.lsn); // the LSN sequence survives a reopen
    try expectPayloads(&log, null, &.{ "one", "two", "three" });
}

test "a torn tail on the newest segment is cut on open; everything before survives" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const name = "seg-00000000000000000001.log";
    var good_end: u64 = undefined;
    {
        var log = try openSim(&sim);
        defer log.close();
        try log.rotate(1);
        _ = try log.append("kept-1");
        _ = try log.append("kept-2");
        good_end = log.end().?.offset;
    }
    // Leave half a record behind, the way a crash mid-write does.
    {
        const st = sim.storage();
        const h = try st.open(name, .open_or_create);
        defer st.close(h);
        var rec: [25 + 8]u8 = undefined;
        encodeRecord(&rec, rec_data, 3, 0, "torn-rec");
        // Into the payload, so the torn bytes end in a nonzero one: zeros
        // at the very end would count as reserved space, not as cut.
        try st.writeAll(h, rec[0..29], good_end);
        try st.sync(h);
    }
    try testing.expectEqual(@as(usize, good_end + 29), sim.fileContent(name).?.len);

    var log = try openSim(&sim);
    defer log.close();
    try testing.expectEqual(@as(usize, good_end), sim.fileContent(name).?.len);
    try testing.expectEqual(@as(u64, 29), log.bytesCutOnOpen());
    try testing.expectEqual(good_end, log.end().?.offset);
    try expectPayloads(&log, null, &.{ "kept-1", "kept-2" });
    _ = try log.append("after-repair");
    try expectPayloads(&log, null, &.{ "kept-1", "kept-2", "after-repair" });
}

test "a flipped byte in a CLOSED segment is reported, never repaired" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const name = "seg-00000000000000000001.log";
    {
        var log = try openSim(&sim);
        defer log.close();
        try log.rotate(1);
        _ = try log.append("closed-a");
        _ = try log.append("closed-b");
        try log.rotate(2);
        _ = try log.append("open-c");
    }
    const before = sim.fileContent(name).?.len;
    sim.flipByte(name, 40 + 25 + 2); // inside the first payload

    var log = try openSim(&sim);
    defer log.close();
    // `open` does not read closed segments, so it succeeds and changes nothing…
    try testing.expectEqual(before, sim.fileContent(name).?.len);
    // …and the reader refuses the bad record instead of skipping past it.
    var it = log.iterator(null);
    defer it.deinit();
    try testing.expectError(error.Corrupt, it.next());
    // The open segment is unaffected and still readable from its own start.
    try expectPayloads(&log, .{ .segment = 2, .offset = segment_header_len }, &.{"open-c"});
}

test "a closed segment that lost its seal is reported as truncated" {
    // The seal's reason to exist: without it this segment would read as a
    // valid, shorter one and the lost records would simply not be there.
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const name = "seg-00000000000000000001.log";
    var cut: u64 = undefined;
    {
        var log = try openSim(&sim);
        defer log.close();
        try log.rotate(1);
        _ = try log.append("r1");
        const p2 = try log.append("r2");
        cut = p2.pos.offset; // keep r1 whole, lose r2 and the seal
        try log.rotate(2);
    }
    {
        const st = sim.storage();
        const h = try st.open(name, .open_or_create);
        defer st.close(h);
        try st.truncate(h, cut);
        try st.sync(h);
    }
    var log = try openSim(&sim);
    defer log.close();
    var it = log.iterator(null);
    defer it.deinit();
    try testing.expectEqualStrings("r1", (try it.next()).?.payload);
    try testing.expectError(error.Corrupt, it.next());
}

test "a seal that disagrees with its segment is corrupt, even with a valid CRC" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const name = "seg-00000000000000000001.log";
    {
        var log = try openSim(&sim);
        defer log.close();
        try log.rotate(1);
        _ = try log.append("only");
        try log.rotate(2);
    }
    // Rewrite the seal to claim two records, with a correct CRC.
    const file = sim.fileContent(name).?;
    const seal_at = 40 + 25 + 4;
    var payload: [48]u8 = undefined;
    (Seal{ .count = 2, .offset = seal_at, .first_lsn = 1, .last_lsn = 2, .min_ts = 0, .max_ts = 0 }).encode(&payload);
    encodeRecord(file[seal_at..][0 .. 25 + 48], rec_seal, 0, 0, &payload);

    var log = try openSim(&sim);
    defer log.close();
    var it = log.iterator(null);
    defer it.deinit();
    try testing.expectEqualStrings("only", (try it.next()).?.payload);
    try testing.expectError(error.Corrupt, it.next());
}

test "a newest segment left sealed reopens with no active segment" {
    // The state a crash leaves between `rotate` sealing the old segment and
    // committing the new one: the seal is durable, the successor is not.
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    {
        var log = try openSim(&sim);
        defer log.close();
        try log.rotate(1);
        _ = try log.append("x");
        try log.seal(&log.active.?);
        log.store.close(log.active.?.handle);
        log.active.?.index.deinit(testing.allocator);
        log.active = null;
    }
    var log = try openSim(&sim);
    defer log.close();
    try testing.expectEqual(@as(?u64, 1), log.newest());
    try testing.expectEqual(@as(?u64, null), log.activeSegment());
    try testing.expectError(error.NoActiveSegment, log.append("y"));
    try testing.expectError(error.NonMonotonic, log.rotate(1)); // sealed ids never reopen
    try log.rotate(2);
    _ = try log.append("y");
    try expectPayloads(&log, null, &.{ "x", "y" });
}

test "bytes after a seal in the newest segment are corrupt, not a torn tail" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const name = "seg-00000000000000000001.log";
    {
        var log = try openSim(&sim);
        defer log.close();
        try log.rotate(1);
        _ = try log.append("x");
        try log.seal(&log.active.?);
        log.store.close(log.active.?.handle);
        log.active.?.index.deinit(testing.allocator);
        log.active = null;
    }
    {
        const st = sim.storage();
        const h = try st.open(name, .open_or_create);
        defer st.close(h);
        try st.writeAll(h, "junk", try st.size(h));
        try st.sync(h);
    }
    // Nothing is ever written after a seal, so this is not a torn write to
    // cut off — and cutting it would destroy the evidence.
    try testing.expectError(error.Corrupt, openSim(&sim));
    try testing.expectEqual(@as(usize, 40 + 25 + 1 + 25 + 48 + 4), sim.fileContent(name).?.len);
}

test "a position that this log never handed out is refused" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try openSim(&sim);
    defer log.close();
    try log.rotate(1);
    _ = try log.append("a");
    try log.rotate(5);
    _ = try log.append("b");
    for ([_]Position{
        .{ .segment = 3, .offset = 40 }, // between two live segments
        .{ .segment = 9, .offset = 40 }, // past the newest
        .{ .segment = 5, .offset = 4 }, // inside a header
    }) |bogus| {
        var it = log.iterator(bogus);
        defer it.deinit();
        try testing.expectError(error.InvalidPosition, it.next());
    }
}

test "a half-created segment whose name survived is finished, truncating first" {
    // `SimStorage` cannot make this state on its own (see the module doc),
    // so it is built by hand: the manifest names segment 5, and its file
    // holds the first half of a header, durably.
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const name = "seg-00000000000000000005.log";
    {
        var log = try openSim(&sim);
        defer log.close();
        try log.rotate(5);
    }
    {
        const st = sim.storage();
        const h = try st.open(name, .open_or_create);
        defer st.close(h);
        try st.truncate(h, 8);
        try st.sync(h);
    }
    // Rewriting those 8 durable bytes in place would trip the simulator's
    // append-only tripwire; truncating first is what keeps it an append.
    var log = try openSim(&sim);
    defer log.close();
    try testing.expectEqual(@as(u64, 8), log.bytesCutOnOpen());
    try testing.expectEqual(@as(?u64, 5), log.activeSegment());
    try testing.expectEqual(@as(usize, 40), sim.fileContent(name).?.len);
    _ = try log.append("finished");
    try expectPayloads(&log, null, &.{"finished"});
}

test "a full-length record with bad bytes at the tail is cut, not believed" {
    // What a torn multi-sector write can leave that a torn prefix cannot: the
    // length is intact and the payload is not. Only the CRC can tell.
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const name = "seg-00000000000000000001.log";
    var good_end: u64 = undefined;
    {
        var log = try openSim(&sim);
        defer log.close();
        try log.rotate(1);
        _ = try log.append("good");
        good_end = log.end().?.offset;
    }
    {
        const st = sim.storage();
        const h = try st.open(name, .open_or_create);
        defer st.close(h);
        var rec: [25 + 6]u8 = undefined;
        encodeRecord(&rec, rec_data, 2, 0, "mangle");
        rec[25 + 2] ^= 0x20;
        try st.writeAll(h, &rec, good_end);
        try st.sync(h);
    }
    var log = try openSim(&sim);
    defer log.close();
    try testing.expectEqual(@as(u64, 31), log.bytesCutOnOpen());
    try expectPayloads(&log, null, &.{"good"});
}

test "a closed segment whose header names another id is refused by the reader" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    {
        var log = try openSim(&sim);
        defer log.close();
        try log.rotate(1);
        _ = try log.append("x");
        try log.rotate(2);
        _ = try log.append("y");
    }
    // A well-formed header, CRC and all, for the wrong id.
    const file = sim.fileContent("seg-00000000000000000001.log").?;
    encodeHeader(file[0..40], 7, 1, 0);
    // `open` reads only the newest segment, so this is the reader's to catch.
    var log = try openSim(&sim);
    defer log.close();
    var it = log.iterator(null);
    defer it.deinit();
    try testing.expectError(error.Corrupt, it.next());
}

/// A backend whose `sync` fails with an I/O error while the process lives
/// on — the fsyncgate case. `SimStorage` models crashes only, so on its own
/// it cannot tell whether the log keeps readers below what fsync confirmed.
const FailingSync = struct {
    inner: Storage,
    fail: bool = false,
    /// `allocate` answers `error.NoSpaceLeft`.
    full: bool = false,

    fn storage(self: *FailingSync) Storage {
        return .{ .ctx = self, .vtable = &vtable };
    }
    const vtable: Storage.VTable = .{
        .open = open_,
        .size = size_,
        .pread = pread_,
        .writeAll = writeAll_,
        .sync = sync_,
        .truncate = truncate_,
        .close = close_,
        .rename = rename_,
        .delete = delete_,
        .syncDir = syncDir_,
        .tryLockExclusive = lock_,
        .allocate = allocate_,
        .syncData = syncData_,
    };
    fn c(ctx: *anyopaque) *FailingSync {
        return @ptrCast(@alignCast(ctx));
    }
    fn open_(ctx: *anyopaque, p: []const u8, m: Storage.OpenMode) Storage.Error!Storage.Handle {
        return c(ctx).inner.open(p, m);
    }
    fn size_(ctx: *anyopaque, h: Storage.Handle) Storage.Error!u64 {
        return c(ctx).inner.size(h);
    }
    fn pread_(ctx: *anyopaque, h: Storage.Handle, b: []u8, off: u64) Storage.Error!usize {
        return c(ctx).inner.pread(h, b, off);
    }
    fn writeAll_(ctx: *anyopaque, h: Storage.Handle, b: []const u8, off: u64) Storage.Error!void {
        return c(ctx).inner.writeAll(h, b, off);
    }
    fn sync_(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
        if (c(ctx).fail) return error.InputOutput;
        return c(ctx).inner.sync(h);
    }
    fn truncate_(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!void {
        return c(ctx).inner.truncate(h, len);
    }
    fn close_(ctx: *anyopaque, h: Storage.Handle) void {
        c(ctx).inner.close(h);
    }
    fn rename_(ctx: *anyopaque, a: []const u8, b: []const u8) Storage.Error!void {
        return c(ctx).inner.rename(a, b);
    }
    fn delete_(ctx: *anyopaque, p: []const u8) Storage.Error!void {
        return c(ctx).inner.delete(p);
    }
    fn syncDir_(ctx: *anyopaque) Storage.Error!void {
        return c(ctx).inner.syncDir();
    }
    fn lock_(ctx: *anyopaque, h: Storage.Handle) Storage.Error!bool {
        return c(ctx).inner.tryLockExclusive(h);
    }
    fn allocate_(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!bool {
        if (c(ctx).full) return error.NoSpaceLeft;
        return c(ctx).inner.allocate(h, len);
    }
    fn syncData_(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
        if (c(ctx).fail) return error.InputOutput;
        return c(ctx).inner.syncData(h);
    }
};

test "a record whose fsync failed is never handed to a reader of this log" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var flaky: FailingSync = .{ .inner = sim.storage() };
    {
        var log = try Log.open(testing.allocator, flaky.storage(), .{ .create = true });
        defer log.close();
        try log.rotate(1);
        _ = try log.append("synced");

        flaky.fail = true;
        try testing.expectError(error.InputOutput, log.append("unsynced"));
        try testing.expect(log.isPoisoned());
        flaky.fail = false;

        // The bytes are in the file — the write succeeded — but fsync never
        // confirmed them, so a reader here must stop short of them.
        try expectPayloads(&log, null, &.{"synced"});
        try testing.expectError(error.Poisoned, log.append("refused"));
    }
    // A failed append has an unknown outcome, as its error said: after a
    // reopen the record may be there. It was never acknowledged, so a caller
    // that resends it gets a duplicate, never a loss.
    var log = try Log.open(testing.allocator, flaky.storage(), .{});
    defer log.close();
    try expectPayloads(&log, null, &.{ "synced", "unsynced" });
}

test "a segment file under the wrong id is refused" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    {
        var log = try openSim(&sim);
        defer log.close();
        try log.rotate(1);
        _ = try log.append("x");
    }
    // A well-formed header, CRC and all, claiming segment 9.
    const file = sim.fileContent("seg-00000000000000000001.log").?;
    encodeHeader(file[0..40], 9, 1, 0);
    try testing.expectError(error.Corrupt, openSim(&sim));
}

test "dropBefore deletes old segments and never the newest" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try openSim(&sim);
    defer log.close();

    for ([_]u64{ 1, 2, 3, 4 }) |id| {
        try log.rotate(id);
        var b: [8]u8 = undefined;
        _ = try log.append(try std.mem.print(&b, "r{d}", .{id}));
    }
    try testing.expectEqual(@as(usize, 2), try log.dropBefore(3));
    try testing.expectEqualSlices(u64, &.{ 3, 4 }, log.segments());
    try testing.expect(sim.fileContent("seg-00000000000000000001.log") == null);
    try testing.expect(sim.fileContent("seg-00000000000000000002.log") == null);
    try expectPayloads(&log, null, &.{ "r3", "r4" });

    // Asking to drop everything still keeps the newest.
    try testing.expectEqual(@as(usize, 1), try log.dropBefore(1000));
    try testing.expectEqualSlices(u64, &.{4}, log.segments());
    try testing.expectEqual(@as(usize, 0), try log.dropBefore(1000));
    _ = try log.append("r4b");
    try expectPayloads(&log, null, &.{ "r4", "r4b" });
}

test "a position in a dropped segment is SegmentGone; a later one still resumes" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try openSim(&sim);
    defer log.close();

    try log.rotate(1);
    const old = try log.append("old");
    try log.rotate(2);
    const mid = try log.append("mid");
    _ = try log.append("new");
    _ = try log.dropBefore(2);

    var it = log.iterator(old.pos);
    defer it.deinit();
    try testing.expectError(error.SegmentGone, it.next());
    try expectPayloads(&log, mid.pos, &.{ "mid", "new" });
}

test "an iterator resumes from a saved position after a reopen" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var saved: Position = undefined;
    {
        var log = try openSim(&sim);
        defer log.close();
        try log.rotate(1);
        _ = try log.append("a");
        _ = try log.append("b");
        try log.rotate(2);
        _ = try log.append("c");
        var it = log.iterator(null);
        defer it.deinit();
        _ = (try it.next()).?;
        saved = (try it.next()).?.next; // consumed "a" and "b"
    }
    var log = try openSim(&sim);
    defer log.close();
    _ = try log.append("d");
    try expectPayloads(&log, saved, &.{ "c", "d" });
}

test "a live iterator sees what is appended later, and follows a rotation" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try openSim(&sim);
    defer log.close();

    var it = log.iterator(null);
    defer it.deinit();
    try testing.expectEqual(@as(?Record, null), try it.next()); // empty log

    try log.rotate(1);
    _ = try log.append("first");
    try testing.expectEqualStrings("first", (try it.next()).?.payload);
    try testing.expectEqual(@as(?Record, null), try it.next()); // caught up

    _ = try log.append("second");
    try log.rotate(2);
    _ = try log.append("third");
    try testing.expectEqualStrings("second", (try it.next()).?.payload);
    try testing.expectEqualStrings("third", (try it.next()).?.payload);
    try testing.expectEqual(@as(?Record, null), try it.next());
}

test "a second writer is Locked; the first keeps working" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try openSim(&sim);
    defer log.close();
    try testing.expectError(error.Locked, openSim(&sim));
    try log.rotate(1);
    _ = try log.append("still mine");
    try expectPayloads(&log, null, &.{"still mine"});
}

test "an oversized record is refused on append, and a huge length on disk is never believed" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const name = "seg-00000000000000000001.log";
    {
        var log = try Log.open(testing.allocator, sim.storage(), .{ .create = true, .max_record_len = 8 });
        defer log.close();
        try log.rotate(1);
        _ = try log.append("12345678");
        try testing.expectError(error.RecordTooLarge, log.append("123456789"));
        try testing.expectError(error.RecordTooLarge, log.appendMany(&.{ "ok", "123456789" }));
        try testing.expect(!log.isPoisoned());
        try log.rotate(2);
    }
    // A closed segment whose length field claims 4 GiB: the reader must say
    // Corrupt without trying to allocate it.
    const file = sim.fileContent(name).?;
    std.mem.writeInt(u32, file[40 + 5 ..][0..4], 0xffff_fff0, .little);
    var log = try Log.open(testing.allocator, sim.storage(), .{ .max_record_len = 8 });
    defer log.close();
    var it = log.iterator(null);
    defer it.deinit();
    try testing.expectError(error.Corrupt, it.next());
}

test "L5: a length over max_record_len in a closed segment gets its own damage reason" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const name = "seg-00000000000000000001.log";
    {
        var log = try Log.open(testing.allocator, sim.storage(), .{ .create = true, .max_record_len = 8 });
        defer log.close();
        try log.rotate(1);
        _ = try log.append("12345678");
        try log.rotate(2);
    }
    // A length field over max_record_len, but not absurdly so -- exactly
    // the shape of a record legitimately written under a larger limit, not
    // obviously garbage. Still `Corrupt` (nothing on disk can tell the two
    // apart), but named `record_too_long`, not `bad_record` (L5).
    const file = sim.fileContent(name).?;
    std.mem.writeInt(u32, file[40 + 5 ..][0..4], 9, .little);
    var log = try Log.open(testing.allocator, sim.storage(), .{ .max_record_len = 8 });
    defer log.close();
    var it = log.iterator(null);
    defer it.deinit();
    try testing.expectError(error.Corrupt, it.next());
    try testing.expectEqual(Damage.Reason.record_too_long, it.damage().?.reason);
}

test "L5: lowering max_record_len below what the active segment holds refuses to open, rather than truncate it" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const name = "seg-00000000000000000001.log";
    {
        var log = try Log.open(testing.allocator, sim.storage(), .{ .create = true, .max_record_len = 1024 });
        defer log.close();
        try log.rotate(1);
        _ = try log.append("a rather long record, written while the limit still allowed it");
        // No rotate: segment 1 stays the active, unsealed segment.
    }
    const before = try testing.allocator.dupe(u8, sim.fileContent(name).?);
    defer testing.allocator.free(before);

    // Reopening with a smaller limit must refuse -- not silently truncate
    // the record as if it were a torn tail (the pre-L5 bug: `scanTail`
    // could not tell the two apart and cut the "unreadable" suffix off).
    try testing.expectError(error.RecordTooLongForOptions, Log.open(testing.allocator, sim.storage(), .{ .max_record_len = 8 }));
    try testing.expectEqualSlices(u8, before, sim.fileContent(name).?);

    // Raising the limit back opens cleanly, the record intact.
    var log = try Log.open(testing.allocator, sim.storage(), .{ .max_record_len = 1024 });
    defer log.close();
    try expectPayloads(&log, null, &.{"a rather long record, written while the limit still allowed it"});
}

test "after a failed write the log is poisoned and refuses every mutation" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try openSim(&sim);
    defer log.close();
    try log.rotate(1);
    _ = try log.append("durable");

    sim.ops_until_crash = 0; // the next write fails
    try testing.expectError(error.Crashed, log.append("lost"));
    try testing.expect(log.isPoisoned());
    sim.reboot();
    // The storage works again, but this Log no longer trusts its own view.
    try testing.expectError(error.Poisoned, log.append("refused"));
    try testing.expectError(error.Poisoned, log.rotate(2));
    try testing.expectError(error.Poisoned, log.dropBefore(5));
}

test "appendMany writes once and syncs once" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try openSim(&sim);
    defer log.close();
    try log.rotate(1);
    const before = sim.ops_seen;
    const first = try log.appendMany(&.{ "m1", "m2", "m3" });
    try testing.expectEqual(@as(usize, 2), sim.ops_seen - before);
    try testing.expectEqual(Position{ .segment = 1, .offset = 40, .lsn = 1 }, first.pos);
    try testing.expectEqual(@as(u64, 1), first.lsn);
    try testing.expectEqual(@as(u64, 4), log.nextLsn());
    try expectPayloads(&log, null, &.{ "m1", "m2", "m3" });
    // An empty batch says where the next record would go, and touches nothing.
    const end_now = log.end().?;
    const ops_now = sim.ops_seen;
    try testing.expectEqual(end_now, (try log.appendMany(&.{})).pos);
    try testing.expectEqual(ops_now, sim.ops_seen);
}

test "the real filesystem: round trip, reopen, and a torn tail repaired" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var fs = FsStorage.init(testing.io, tmp.dir);
    const st = fs.storage();
    const name = "seg-00000000000000000002.log";
    var good_end: u64 = undefined;
    {
        var log = try Log.open(testing.allocator, st, .{ .create = true });
        defer log.close();
        try log.rotate(1);
        _ = try log.append("disk-1");
        try log.rotate(2);
        _ = try log.appendMany(&.{ "disk-2", "disk-3" });
        good_end = log.end().?.offset;
    }
    {
        const h = try st.open(name, .open_or_create);
        defer st.close(h);
        try st.writeAll(h, "\x01\x02\x03\x04\x01\xff", good_end); // a torn record header
        try st.sync(h);
        try testing.expectEqual(good_end + 6, try st.size(h));
    }
    var log = try Log.open(testing.allocator, st, .{});
    defer log.close();
    try testing.expectEqual(good_end, log.end().?.offset);
    try expectPayloads(&log, null, &.{ "disk-1", "disk-2", "disk-3" });
    _ = try log.append("disk-4");
    try expectPayloads(&log, null, &.{ "disk-1", "disk-2", "disk-3", "disk-4" });
}

// ── preallocation ───────────────────────────────────────────────────────────

fn fileLen(sim: *SimStorage, id: u64) usize {
    var nb: [seg_name_len]u8 = undefined;
    return sim.fileContent(segName(&nb, id)).?.len;
}

test "preallocate: reserved in steps, cut at the seal, and a zero tail is the end on open" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const opts: Options = .{ .create = true, .preallocate = 1000 };
    {
        var log = try Log.open(testing.allocator, sim.storage(), opts);
        defer log.close();
        try log.rotate(1);
        try testing.expectEqual(@as(usize, 1000), fileLen(&sim, 1)); // reserved at rotate
        _ = try log.append(comptime &@as([100:0]u8, @splat('a')));
        try testing.expectEqual(@as(usize, 1000), fileLen(&sim, 1)); // written into it
        _ = try log.append(comptime &@as([900:0]u8, @splat('b'))); // past the reservation: the next whole step
        try testing.expectEqual(@as(usize, 2000), fileLen(&sim, 1));
        const data_end = log.end().?.offset;
        try log.rotate(2);
        // A closed segment ends at its seal: the reservation is given back.
        try testing.expectEqual(data_end + rec_header_len + seal_payload_len, fileLen(&sim, 1));
        _ = try log.append("c");
        try testing.expectEqual(@as(usize, 1000), fileLen(&sim, 2));
    }
    // Reopened: the zeros are not damage and not a cut; they go, and the
    // next append reserves again.
    var log = try Log.open(testing.allocator, sim.storage(), opts);
    defer log.close();
    try testing.expectEqual(@as(u64, 0), log.bytesCutOnOpen());
    try testing.expectEqual(log.end().?.offset, fileLen(&sim, 2));
    try expectPayloads(&log, null, &.{ comptime &@as([100:0]u8, @splat('a')), comptime &@as([900:0]u8, @splat('b')), "c" });
    _ = try log.append("d");
    try testing.expectEqual(@as(usize, 1000), fileLen(&sim, 2));
    var r = try log.verify(testing.allocator);
    defer r.deinit(testing.allocator);
    try testing.expect(r.clean());
}

test "preallocate: a torn record in the reservation is cut to its last nonzero byte" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const opts: Options = .{ .create = true, .preallocate = 4096 };
    var good_end: u64 = undefined;
    {
        var log = try Log.open(testing.allocator, sim.storage(), opts);
        defer log.close();
        try log.rotate(1);
        _ = try log.append("kept");
        good_end = log.end().?.offset;
    }
    {
        const st = sim.storage();
        var nb: [seg_name_len]u8 = undefined;
        const h = try st.open(segName(&nb, 1), .open_or_create);
        defer st.close(h);
        try st.writeAll(h, "\x01\x02\x03\x04\x01\xff\x07", good_end); // a torn record, zeros after
        try st.sync(h);
        try testing.expectEqual(@as(u64, 4096), try st.size(h));
    }
    var log = try Log.open(testing.allocator, sim.storage(), opts);
    defer log.close();
    try testing.expectEqual(@as(u64, 7), log.bytesCutOnOpen());
    try testing.expectEqual(good_end, log.end().?.offset);
    try testing.expectEqual(good_end, fileLen(&sim, 1));
    try expectPayloads(&log, null, &.{"kept"});
}

test "preallocate: zeros after a seal are a cut the crash lost; anything else after it is damage" {
    for ([_]bool{ false, true }) |garbage| {
        var sim = SimStorage.init(testing.allocator);
        defer sim.deinit();
        var sealed_end: u64 = undefined;
        {
            var log = try Log.open(testing.allocator, sim.storage(), .{ .create = true });
            defer log.close();
            try log.rotate(1);
            _ = try log.append("x");
            try log.rotate(2);
        }
        // Make segment 2 sealed and newest, then put zeros (or a byte) after
        // its seal, as a lost truncate would leave them.
        {
            var log = try Log.open(testing.allocator, sim.storage(), .{});
            defer log.close();
            _ = try log.append("y");
            const a = &log.active.?;
            a.reserved = a.end + 500;
            _ = try log.store.allocate(a.handle, a.reserved);
            try log.seal(a);
            sealed_end = a.end;
            // The truncate `seal` did is undone: the zeros are back.
            _ = try log.store.allocate(a.handle, sealed_end + 500);
            if (garbage) try log.store.writeAll(a.handle, "\x09", sealed_end + 100);
            try log.store.sync(a.handle);
        }
        const got = Log.open(testing.allocator, sim.storage(), .{});
        if (garbage) {
            try testing.expectError(error.Corrupt, got);
            continue;
        }
        var log = try got;
        defer log.close();
        try testing.expectEqual(@as(?u64, null), log.activeSegment()); // still sealed
        try testing.expectEqual(@as(u64, 0), log.bytesCutOnOpen());
        try testing.expectEqual(sealed_end, fileLen(&sim, 2));
        try expectPayloads(&log, null, &.{ "x", "y" });
    }
}

test "preallocate: a full disk refuses the append cleanly, and the log goes on" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var disk: FailingSync = .{ .inner = sim.storage() };
    var log = try Log.open(testing.allocator, disk.storage(), .{ .create = true, .preallocate = 100 });
    defer log.close();
    try log.rotate(1);
    _ = try log.append("fits");
    disk.full = true;
    try testing.expectError(error.NoSpaceLeft, log.append(comptime &@as([200:0]u8, @splat('x'))));
    try testing.expect(!log.isPoisoned());
    disk.full = false;
    _ = try log.append("later");
    try expectPayloads(&log, null, &.{ "fits", "later" });
}

test "preallocate: retention by size counts the active segment's data, not its reservation" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try Log.open(testing.allocator, sim.storage(), .{ .create = true, .preallocate = 1 << 20 });
    defer log.close();
    try log.rotate(1);
    _ = try log.append("old");
    try log.rotate(2);
    _ = try log.append("new");
    try testing.expectEqual(@as(usize, 1 << 20), fileLen(&sim, 2));
    // Both segments' data is a few hundred bytes: nothing is over 4 KiB.
    try testing.expectEqual(@as(usize, 0), try log.enforceRetention(.{ .max_bytes = 4096 }, 0));
    try testing.expectEqualSlices(u64, &.{ 1, 2 }, log.segments());
}

test "preallocate: a backend without it goes without, and says nothing" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var vt = sim.storage().vtable.*;
    vt.allocate = null;
    const st: Storage = .{ .ctx = &sim, .vtable = &vt };
    var log = try Log.open(testing.allocator, st, .{ .create = true, .preallocate = 4096 });
    defer log.close();
    try log.rotate(1);
    _ = try log.append("a");
    try testing.expectEqual(log.end().?.offset, fileLen(&sim, 1));
    try expectPayloads(&log, null, &.{"a"});
}

test "preallocate: a read-only reader beside the writer takes the zeros for the live end" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var w = try Log.open(testing.allocator, sim.storage(), .{ .create = true, .preallocate = 4096 });
    defer w.close();
    try w.rotate(1);
    _ = try w.append("one");
    var r = try Log.openReadOnly(testing.allocator, sim.storage(), .{});
    defer r.close();
    var it = r.iterator(null);
    defer it.deinit();
    try testing.expectEqualStrings("one", ((try it.next()) orelse return error.NoOne).payload);
    try testing.expectEqual(@as(?Record, null), try it.next());
    _ = try w.append("two");
    try testing.expectEqualStrings("two", ((try it.next()) orelse return error.NoTwo).payload);
    try w.rotate(2); // seal, cut
    _ = try w.append("three");
    try testing.expectEqualStrings("three", ((try it.next()) orelse return error.NoThree).payload);
    try testing.expectEqual(@as(?Record, null), try it.next());
}

test "preallocate on the real filesystem: the reservation is real, and reopen finds the end" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var fs = FsStorage.init(testing.io, tmp.dir);
    const st = fs.storage();
    var end_at: u64 = undefined;
    {
        var log = try Log.open(testing.allocator, st, .{ .create = true, .preallocate = 1 << 20 });
        defer log.close();
        try log.rotate(1);
        for (0..100) |_| _ = try log.append(comptime &@as([150:0]u8, @splat('r')));
        end_at = log.end().?.offset;
        const h = try st.open("seg-00000000000000000001.log", .read_only);
        defer st.close(h);
        const size = try st.size(h);
        // A filesystem without fallocate (tmpfs has it) leaves the file as long as its data.
        try testing.expect(size == 1 << 20 or size == end_at);
    }
    var log = try Log.open(testing.allocator, st, .{});
    defer log.close();
    try testing.expectEqual(@as(u64, 0), log.bytesCutOnOpen());
    try testing.expectEqual(end_at, log.end().?.offset);
    var r = try log.verify(testing.allocator);
    defer r.deinit(testing.allocator);
    try testing.expect(r.clean());
    try testing.expectEqual(@as(u64, 100), r.records);
}

test "appendEntries: one write and one fsync, each record with its own time" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try openSim(&sim);
    defer log.close();
    try log.rotate(1);
    const ops0 = sim.ops_seen;
    const a = try log.appendEntries(&.{
        .{ .ts = 30, .payload = "c" },
        .{ .ts = 10, .payload = "a" },
        .{ .ts = 20, .payload = "b" },
    });
    try testing.expectEqual(@as(u64, 1), a.lsn);
    try testing.expectEqual(@as(usize, 2), sim.ops_seen - ops0); // the write, the fsync
    var it = log.iterator(null);
    defer it.deinit();
    for ([_]i64{ 30, 10, 20 }) |ts| try testing.expectEqual(ts, (try it.next()).?.ts);
    // The seal records the range of all three, not the first one's time.
    try log.rotate(2);
    try testing.expectEqual(@as(u64, 1), (try log.seekTime(21)).?.lsn);
    try testing.expectEqual(@as(?Position, null), try log.seekTime(31));
}

// ── compression ─────────────────────────────────────────────────────────────

fn zstFile(sim: *SimStorage, id: u64) ?[]u8 {
    var nb: [seg_name_len]u8 = undefined;
    return sim.fileContent(zstName(&nb, id));
}

fn logFile(sim: *SimStorage, id: u64) ?[]u8 {
    var nb: [seg_name_len]u8 = undefined;
    return sim.fileContent(segName(&nb, id));
}

/// Segment 1 with `n` compressible records, closed; segment 2 active.
fn compressibleLog(sim: *SimStorage, opts: Options, n: usize) !Log {
    var log = try Log.open(testing.allocator, sim.storage(), opts);
    errdefer log.close();
    try log.rotate(1);
    for (0..n) |i| {
        var buf: [64]u8 = undefined;
        _ = try log.appendAt(@intCast(1000 + i), std.mem.print(&buf, "reading {d:0>6} kWh 0.{d}", .{ i, i % 10 }) catch unreachable);
    }
    try log.rotate(2);
    _ = try log.append("live");
    return log;
}

const small_frames: Options = .{ .create = true, .compression = .{ .frame_size = 1024 } };

test "compress: the same records at the same places, a smaller file, and zstd -d gives the segment back" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try compressibleLog(&sim, small_frames, 2000);
    defer log.close();
    var before = try readAll(&log, null);
    defer freeAll(&before);
    const raw = try testing.allocator.dupe(u8, logFile(&sim, 1).?);
    defer testing.allocator.free(raw);
    const p500 = (try log.seek(500)).?;

    const st = try log.compress(1);
    try testing.expectEqual(@as(u64, raw.len), st.bytes_before);
    // 1 KiB frames, and every record's CRC is noise: about 3.5x here.
    try testing.expect(st.bytes_after * 3 < st.bytes_before);
    try testing.expect(logFile(&sim, 1) == null);
    try testing.expectEqual(@as(usize, @intCast(st.bytes_after)), zstFile(&sim, 1).?.len);
    try testing.expectEqual(@as(u64, 1), log.stats().compressions);

    // Byte for byte the segment, for any zstd decoder.
    const back = try zstd.decompressAlloc(testing.allocator, zstFile(&sim, 1).?, 1 << 24);
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u8, raw, back);

    var after = try readAll(&log, null);
    defer freeAll(&after);
    try testing.expectEqual(before.items.len, after.items.len);
    for (before.items, after.items) |a, b| try testing.expectEqualStrings(a, b);
    try testing.expectEqual(p500, (try log.seek(500)).?);
    var it = log.iterator(p500);
    defer it.deinit();
    try testing.expectEqual(@as(u64, 500), (try it.next()).?.lsn);
    try testing.expectEqual(@as(u64, 1), (try log.seekTime(1000)).?.lsn);
    var r = try log.verify(testing.allocator);
    defer r.deinit(testing.allocator);
    try testing.expect(r.clean());
    try testing.expectEqual(@as(u64, 2001), r.records);

    // Again: nothing to do.
    const again = try log.compress(1);
    try testing.expectEqual(again.bytes_before, again.bytes_after);
    try testing.expectEqual(@as(u64, 1), log.stats().compressions);
}

test "L2: the read-back-and-compare accepts a correct compression" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try compressibleLog(&sim, small_frames, 300);
    defer log.close();
    const raw = try testing.allocator.dupe(u8, logFile(&sim, 1).?);
    defer testing.allocator.free(raw);
    const good_zst = try zstd.seekable.compressAlloc(testing.allocator, raw, .{ .max_frame_size = 1024, .frame_checksums = true });
    defer testing.allocator.free(good_zst);

    var nb: [seg_name_len]u8 = undefined;
    const src = try log.store.open(segName(&nb, 1), .read_only);
    defer log.store.close(src);
    const tmp = try log.store.open(compress_tmp, .create_truncate);
    try log.store.writeAll(tmp, good_zst, 0);
    try log.store.sync(tmp);
    log.store.close(tmp);

    try log.verifyCompressed(log.store, src, raw.len);
    log.store.delete(compress_tmp) catch {};
}

test "L2: the read-back-and-compare refuses a well-formed but wrong .zst, and touches nothing" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try compressibleLog(&sim, small_frames, 300);
    defer log.close();
    const raw = try testing.allocator.dupe(u8, logFile(&sim, 1).?);
    defer testing.allocator.free(raw);

    // A well-formed, self-consistent zstd seekable stream (valid frame
    // checksums throughout, exactly what `writeCompressed` would also
    // produce) that encodes the WRONG bytes -- a stand-in for an encoder
    // bug, which a checksum carried inside the compressed stream itself
    // cannot catch (audit finding L2/E13 = S2's D9). This is what a
    // read-back-and-compare against the source, done here, is for.
    const wrong = try testing.allocator.dupe(u8, raw);
    defer testing.allocator.free(wrong);
    wrong[wrong.len - 1] ^= 0xFF;
    const bad_zst = try zstd.seekable.compressAlloc(testing.allocator, wrong, .{ .max_frame_size = 1024, .frame_checksums = true });
    defer testing.allocator.free(bad_zst);

    var nb: [seg_name_len]u8 = undefined;
    const src = try log.store.open(segName(&nb, 1), .read_only);
    defer log.store.close(src);
    const tmp = try log.store.open(compress_tmp, .create_truncate);
    try log.store.writeAll(tmp, bad_zst, 0);
    try log.store.sync(tmp);
    log.store.close(tmp);

    try testing.expectError(error.CompressVerifyFailed, log.verifyCompressed(log.store, src, raw.len));
    // Only a read happened: the raw segment is exactly as this test left it.
    // (`compress` itself is what deletes `COMPRESS.tmp` on this path; the
    // check alone, as called here, does not.)
    try testing.expectEqualSlices(u8, raw, logFile(&sim, 1).?);
    log.store.delete(compress_tmp) catch {};
}

test "L6: compressed segments read one after another share one decoder, and read right" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try Log.open(testing.allocator, sim.storage(), small_frames);
    defer log.close();
    for (1..4) |seg| {
        try log.rotate(seg);
        for (0..300) |i| {
            var buf: [64]u8 = undefined;
            _ = try log.appendAt(@intCast(1000 * seg + i), std.mem.print(&buf, "seg {d} reading {d:0>6}", .{ seg, i }) catch unreachable);
        }
    }
    var before = try readAll(&log, null);
    defer freeAll(&before);
    _ = try log.compress(1);
    _ = try log.compress(2);
    try testing.expect(log.segs.?.spare == null); // nothing read compressed yet

    // Twice over both: the second segment, and the second walk, decode
    // with the decoder the first one left.
    for (0..2) |_| {
        var after = try readAll(&log, null);
        defer freeAll(&after);
        try testing.expectEqual(before.items.len, after.items.len);
        for (before.items, after.items) |a, b| try testing.expectEqualStrings(a, b);
        try testing.expect(log.segs.?.spare != null);
    }
    var r = try log.verify(testing.allocator);
    defer r.deinit(testing.allocator);
    try testing.expect(r.clean());
}

test "compress: the form survives a reopen, and a read-only reader reads it too" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    {
        var log = try compressibleLog(&sim, small_frames, 300);
        defer log.close();
        _ = try log.compress(1);
    }
    var log = try Log.open(testing.allocator, sim.storage(), .{});
    defer log.close();
    var got = try readAll(&log, null);
    defer freeAll(&got);
    try testing.expectEqual(@as(usize, 301), got.items.len);
    try testing.expect(zstFile(&sim, 1) != null and logFile(&sim, 1) == null);

    var ro = try Log.openReadOnly(testing.allocator, sim.storage(), .{});
    defer ro.close();
    var got2 = try readAll(&ro, null);
    defer freeAll(&got2);
    try testing.expectEqual(@as(usize, 301), got2.items.len);
}

test "compress: never the newest segment, nor one that is not live" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try compressibleLog(&sim, small_frames, 10);
    defer log.close();
    try testing.expectError(error.NotCompressible, log.compress(2));
    try testing.expectError(error.NotCompressible, log.compress(7));
    var bad = try Log.open(testing.allocator, sim.storage(), .{ .lock = .none, .compression = .{ .level = 99 } });
    defer bad.close();
    try testing.expectError(error.BadCompressOptions, bad.compress(1));
    try testing.expect(sim.fileContent(compress_tmp) == null);
    try testing.expect(logFile(&sim, 1) != null);
}

test "compress: damage inside a compressed segment is Corrupt, never garbage, and resync steps over it" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try compressibleLog(&sim, small_frames, 2000);
    defer log.close();
    _ = try log.compress(1);
    const z = zstFile(&sim, 1).?;
    z[z.len / 3] ^= 0xff; // inside some frame: its checksum no longer matches
    var r = try log.verify(testing.allocator);
    defer r.deinit(testing.allocator);
    try testing.expect(!r.clean());
    try testing.expect(r.records < 2001);
    // The live segment is still read after the damage.
    try testing.expectEqual(@as(u64, 2001), r.last_lsn);
}

test "compress: a seek table that cannot be read makes the segment Corrupt at its header" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try compressibleLog(&sim, small_frames, 100);
    defer log.close();
    _ = try log.compress(1);
    const z = zstFile(&sim, 1).?;
    z[z.len - 1] ^= 0xff; // the seek table's magic
    var it = log.iterator(null);
    defer it.deinit();
    try testing.expectError(error.Corrupt, it.next());
    try testing.expectEqual(Damage.Reason.bad_header, it.damage().?.reason);
}

test "compress: open removes what a crash left of a compression" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    {
        var log = try compressibleLog(&sim, small_frames, 50);
        defer log.close();
        try log.rotate(3);
        _ = try log.compress(1);
    }
    // Segment 1 compressed with its raw file not yet deleted; segment 2 raw
    // with a `.zst` renamed into place before the manifest said so; a temp.
    const one = try testing.allocator.dupe(u8, "stale raw copy");
    defer testing.allocator.free(one);
    try sim.installFile("seg-00000000000000000001.log", one);
    try sim.installFile("seg-00000000000000000002.zst", "not yet committed");
    try sim.installFile(compress_tmp, "half");
    var log = try Log.open(testing.allocator, sim.storage(), .{});
    defer log.close();
    try testing.expect(logFile(&sim, 1) == null and zstFile(&sim, 1) != null);
    try testing.expect(zstFile(&sim, 2) == null and logFile(&sim, 2) != null);
    try testing.expect(sim.fileContent(compress_tmp) == null);
    var got = try readAll(&log, null);
    defer freeAll(&got);
    try testing.expectEqual(@as(usize, 51), got.items.len);
}

test "compress: retention weighs the compressed file, and ages it by its seal" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try compressibleLog(&sim, small_frames, 2000);
    defer log.close();
    const raw_len = logFile(&sim, 1).?.len;
    const st = try log.compress(1);
    // Over the compressed size but under the raw one: nothing goes.
    const limit = st.bytes_after + logFile(&sim, 2).?.len + 16;
    try testing.expect(limit < raw_len);
    try testing.expectEqual(@as(usize, 0), try log.enforceRetention(.{ .max_bytes = limit }, 0));
    // Its newest record is at 2999: older than 3000 - 0 goes, by the seal.
    try testing.expectEqual(@as(usize, 1), try log.enforceRetention(.{ .max_age = 0 }, 3000));
    try testing.expect(zstFile(&sim, 1) == null);
}

fn dropEven(_: void, r: Record) bool {
    return r.lsn % 2 == 1;
}

test "compress: compacting a compressed segment leaves it compressed" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try compressibleLog(&sim, small_frames, 1000);
    defer log.close();
    _ = try log.compress(1);
    const cs = try log.compact(1, {}, dropEven);
    try testing.expectEqual(@as(u64, 500), cs.kept);
    try testing.expect(logFile(&sim, 1) == null and zstFile(&sim, 1) != null);
    try testing.expect(sim.fileContent(compact_tmp) == null and sim.fileContent(compress_tmp) == null);
    var got = try readAll(&log, null);
    defer freeAll(&got);
    try testing.expectEqual(@as(usize, 501), got.items.len);
    var r = try log.verify(testing.allocator);
    defer r.deinit(testing.allocator);
    try testing.expect(r.clean());
}

test "compress on the real filesystem, and through Concurrent" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var fs = FsStorage.init(testing.io, tmp.dir);
    var c = try Concurrent.open(testing.allocator, fs.storage(), testing.io, .{ .create = true });
    defer c.close();
    try c.rotate(1);
    for (0..500) |_| _ = try c.append("the same line again and again");
    try c.rotate(2);
    const st = try c.compress(1);
    try testing.expect(st.bytes_after < st.bytes_before);
    var it = c.iterator(null);
    defer it.deinit();
    var n: usize = 0;
    while (try it.next()) |_| n += 1;
    try testing.expectEqual(@as(usize, 500), n);
}

// ── format v2: LSNs, timestamps, versions, block reads ──────────────────────

fn fakeClock() i64 {
    return 1_700_000_000;
}

test "LSNs run across segments and reopens; timestamps are the caller's or the clock's" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    {
        var log = try Log.open(testing.allocator, sim.storage(), .{ .create = true, .now = fakeClock });
        defer log.close();
        try log.rotate(1);
        try testing.expectEqual(@as(u64, 1), (try log.appendAt(50, "a")).lsn);
        try testing.expectEqual(@as(u64, 2), (try log.appendAt(20, "b")).lsn); // time may step back
        try log.rotate(2);
        try testing.expectEqual(@as(?u64, 3), log.segmentFirstLsn(2));
        try testing.expectEqual(@as(u64, 3), (try log.append("c")).lsn); // stamped by the clock
        try testing.expectEqual(@as(u64, 4), (try log.appendManyAt(7, &.{ "d", "e" })).lsn);
    }
    var log = try Log.open(testing.allocator, sim.storage(), .{});
    defer log.close();
    try testing.expectEqual(@as(u64, 6), log.nextLsn());
    try testing.expectEqual(@as(?u64, 1), log.segmentFirstLsn(1));
    try testing.expectEqual(@as(?u64, null), log.segmentFirstLsn(9));

    const want = [_]struct { u64, i64, []const u8 }{
        .{ 1, 50, "a" }, .{ 2, 20, "b" }, .{ 3, 1_700_000_000, "c" }, .{ 4, 7, "d" }, .{ 5, 7, "e" },
    };
    var it = log.iterator(null);
    defer it.deinit();
    for (want) |w| {
        const r = (try it.next()).?;
        try testing.expectEqual(w[0], r.lsn);
        try testing.expectEqual(w[1], r.ts);
        try testing.expectEqualStrings(w[2], r.payload);
    }
    try testing.expectEqual(@as(?Record, null), try it.next());

    // Segment 1's seal holds its LSN range and the range, not the order, of its times.
    const seg1 = sim.fileContent("seg-00000000000000000001.log").?;
    const seal = Seal.decode(seg1[40 + 2 * (25 + 1) + 25 ..]).?;
    try testing.expectEqual(Seal{ .count = 2, .offset = 40 + 2 * (25 + 1), .first_lsn = 1, .last_lsn = 2, .min_ts = 20, .max_ts = 50 }, seal);
}

test "L3: .refuse rejects an out-of-range timestamp, and writes nothing of that append" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try Log.open(testing.allocator, sim.storage(), .{
        .create = true,
        .timestamps = .{ .refuse = .{ .min = 0, .max = 1_000_000 } },
    });
    defer log.close();
    try log.rotate(1);
    _ = try log.appendAt(100, "a");
    try testing.expectError(error.TimestampOutOfRange, log.appendAt(-1, "bad"));
    try testing.expectError(error.TimestampOutOfRange, log.appendAt(std.math.maxInt(i64), "bad2"));
    try testing.expectError(error.TimestampOutOfRange, log.appendManyAt(-1, &.{ "x", "y" }));
    // Refused before anything was written: still only the one good record,
    // and the next LSN is unmoved.
    try testing.expectEqual(@as(u64, 1), log.stats().records);
    try testing.expectEqual(@as(u64, 2), log.nextLsn());
    _ = try log.appendAt(200, "b");
    try testing.expectEqual(@as(u64, 2), log.stats().records);
    try expectPayloads(&log, null, &.{ "a", "b" });
}

test "L3: .clamp bounds a seal's max_ts, so retention is not wedged forever" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try Log.open(testing.allocator, sim.storage(), .{
        .create = true,
        .timestamps = .{ .clamp = .{ .min = 0, .max = 1000 } },
    });
    defer log.close();
    try log.rotate(1);
    _ = try log.appendAt(100, "a");
    // A stand-in for a badly stepped clock (cf. S1 R8 / S3 L3): without
    // `.clamp` this becomes the seal's permanent max_ts, and no `max_age`
    // policy — however far `now` is pushed — ever drops this segment again.
    _ = try log.appendAt(std.math.maxInt(i64), "poison");
    try log.rotate(2);
    _ = try log.append("live");

    // The seal holds the configured ceiling, not maxInt(i64).
    try testing.expectEqual(@as(?i64, 1000), try log.sealMaxTs(1));

    // Below the ceiling, a query still meets the clamped record — the same
    // "newest timestamp so far" semantics SPEC.md documents, unclamped or
    // not (`.clamp` bounds the poison, it does not make seekTime forget a
    // record its own clamped timestamp still satisfies).
    try testing.expectEqual(@as(usize, 0), try log.enforceRetention(.{ .max_age = 1 }, 1000));
    // Past it, retention is no longer wedged forever: unlike `.unbounded`
    // (today's default), whose ceiling is maxInt(i64) and so is never
    // exceeded by any real `now`.
    try testing.expectEqual(@as(usize, 1), try log.enforceRetention(.{ .max_age = 1 }, 1002));
    try testing.expectEqualSlices(u64, &.{2}, log.segments());
}

test "an empty segment keeps the LSN sequence, and its seal says so" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try openSim(&sim);
    defer log.close();
    try log.rotate(1);
    _ = try log.append("a");
    try log.rotate(2); // stays empty
    try log.rotate(3);
    try testing.expectEqual(@as(u64, 2), (try log.append("b")).lsn);
    const seg2 = sim.fileContent("seg-00000000000000000002.log").?;
    try testing.expectEqual(Seal{ .count = 0, .offset = 40, .first_lsn = 2, .last_lsn = 1, .min_ts = 0, .max_ts = 0 }, Seal.decode(seg2[40 + 25 ..]).?);
    try expectPayloads(&log, null, &.{ "a", "b" });
}

test "a whole record with a valid CRC but the wrong LSN is corrupt, in the tail and in a closed segment" {
    // No torn write makes a record whose CRC holds, so `open` must not cut it
    // as one: the bytes are someone else's, and the evidence stays.
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const name = "seg-00000000000000000001.log";
    var good_end: u64 = undefined;
    {
        var log = try openSim(&sim);
        defer log.close();
        try log.rotate(1);
        _ = try log.append("one");
        good_end = log.end().?.offset;
    }
    {
        const st = sim.storage();
        const h = try st.open(name, .open_or_create);
        defer st.close(h);
        var rec: [25 + 3]u8 = undefined;
        encodeRecord(&rec, rec_data, 5, 0, "two"); // should be 2
        try st.writeAll(h, &rec, good_end);
        try st.sync(h);
    }
    try testing.expectError(error.Corrupt, openSim(&sim));
    try testing.expectEqual(@as(usize, good_end + 28), sim.fileContent(name).?.len);

    // The same record met by a reader in what is by now a closed segment.
    var r = try openReader(&sim);
    defer r.close();
    var it = r.iterator(null);
    defer it.deinit();
    try expectNext(&it, "one");
    // In a reader's live tail it cannot tell a bad record from one still
    // arriving — but this one is whole and checks out, so it is corrupt.
    try testing.expectError(error.Corrupt, it.next());
}

test "a manifest whose first LSN disagrees with the segment header is corrupt" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    {
        var log = try openSim(&sim);
        defer log.close();
        try log.rotate(1);
        _ = try log.append("x");
    }
    const file = sim.fileContent("seg-00000000000000000001.log").?;
    encodeHeader(file[0..40], 1, 2, 0); // well-formed, base LSN 2 where the manifest says 1
    try testing.expectError(error.Corrupt, openSim(&sim));
}

test "an unknown format is UnsupportedVersion, not Corrupt; the previous one needs a migration" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    {
        var log = try openSim(&sim);
        defer log.close();
        try log.rotate(1);
        _ = try log.append("x");
        try log.rotate(2);
    }
    // A segment that says version 1 (the pre-LSN format), in a v2 log.
    const seg1 = sim.fileContent("seg-00000000000000000001.log").?;
    std.mem.writeInt(u32, seg1[4..8], 1, .little);
    {
        var log = try openSim(&sim);
        defer log.close();
        var it = log.iterator(null);
        defer it.deinit();
        try testing.expectError(error.UnsupportedVersion, it.next());
    }
    // A version-1 manifest: magic, version, counts, one id, its CRC.
    var man: [16 + 8 + 4]u8 = undefined;
    @memcpy(man[0..4], man_magic);
    std.mem.writeInt(u32, man[4..8], 1, .little);
    std.mem.writeInt(u32, man[8..12], 1, .little);
    std.mem.writeInt(u32, man[12..16], 0, .little);
    std.mem.writeInt(u64, man[16..24], 2, .little);
    std.mem.writeInt(u32, man[24..28], crc32c(man[0..24]), .little);
    const st = sim.storage();
    const h = try st.open("MANIFEST", .create_truncate);
    try st.writeAll(h, &man, 0);
    try st.sync(h);
    // Version 1 is the one this build migrates from: refused on request, and
    // not for readers.
    try testing.expectError(error.NeedsMigration, Log.open(testing.allocator, st, .{ .migration = .refuse }));
    try testing.expectError(error.MigrationInProgress, openReader(&sim));
    // A version it knows nothing of.
    std.mem.writeInt(u32, man[4..8], 99, .little);
    std.mem.writeInt(u32, man[24..28], crc32c(man[0..24]), .little);
    try st.truncate(h, 0);
    try st.writeAll(h, &man, 0);
    try st.sync(h);
    st.close(h);
    try testing.expectError(error.UnsupportedVersion, openSim(&sim));
    try testing.expectError(error.UnsupportedVersion, openReader(&sim));
}

test "reads cross block boundaries: records that straddle one, and one larger than a block" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try Log.open(testing.allocator, sim.storage(), .{ .create = true, .max_record_len = 256 * 1024 });
    defer log.close();
    try log.rotate(1);

    // 1000-byte records never divide a block evenly, so many straddle one;
    // the 200 KiB record needs a window larger than a block.
    var payloads: [300][]u8 = undefined;
    for (&payloads, 0..) |*pl, i| {
        const len: usize = if (i == 150) 200 * 1024 else 1000;
        pl.* = try testing.allocator.alloc(u8, len);
        @memset(pl.*, @truncate(i));
        std.mem.writeInt(u32, pl.*[0..4], @intCast(i), .little);
    }
    defer for (payloads) |pl| testing.allocator.free(pl);
    for (payloads[0..100]) |pl| _ = try log.append(pl);
    try log.rotate(2);
    for (payloads[100..]) |pl| _ = try log.append(pl);

    for ([_]bool{ false, true }) |from_reader| {
        var r = try openReader(&sim);
        defer r.close();
        const src = if (from_reader) &r else &log;
        var it = src.iterator(null);
        defer it.deinit();
        for (payloads, 0..) |pl, i| {
            const got = (try it.next()).?;
            try testing.expectEqual(@as(u64, i + 1), got.lsn);
            try testing.expectEqualSlices(u8, pl, got.payload);
        }
        try testing.expectEqual(@as(?Record, null), try it.next());
    }
    // And the recovery walk of `open` over the same segment.
    log.close();
    log = try Log.open(testing.allocator, sim.storage(), .{ .max_record_len = 256 * 1024 });
    try testing.expectEqual(@as(u64, 301), log.nextLsn());
    try testing.expectEqual(@as(u64, 0), log.bytesCutOnOpen());
}

// ── sync policy ─────────────────────────────────────────────────────────────

test "the sync policy decides when an append is made durable; readers see only what is" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    {
        // manual: appends write and do not sync; `sync` does, once.
        var log = try Log.open(testing.allocator, sim.storage(), .{ .create = true, .sync = .manual });
        defer log.close();
        try log.rotate(1);
        var it = log.iterator(null);
        defer it.deinit();
        try expectNext(&it, null); // opens the segment: counted before, not in, the measure
        const before = sim.ops_seen;
        _ = try log.append("a");
        _ = try log.append("b");
        try testing.expectEqual(before + 2, sim.ops_seen); // two writes, no sync
        try testing.expectEqual(@as(u64, 3), log.nextLsn());
        try testing.expectEqual(@as(u64, 1), log.durableLsn());
        try expectNext(&it, null); // not durable, not handed out
        try log.sync();
        try testing.expectEqual(before + 3, sim.ops_seen);
        try testing.expectEqual(@as(u64, 3), log.durableLsn());
        try expectNext(&it, "a");
        try expectNext(&it, "b");
        try log.sync(); // nothing waiting: no I/O
        try testing.expectEqual(before + 3, sim.ops_seen);
        // rotate's seal syncs what was waiting, in the same fsync.
        _ = try log.append("c");
        try log.rotate(2);
        try testing.expectEqual(log.nextLsn(), log.durableLsn());
    }
    {
        // every_bytes: a sync once 2 records (2 × 26 bytes) are waiting.
        var log = try Log.open(testing.allocator, sim.storage(), .{ .sync = .{ .every_bytes = 52 } });
        defer log.close();
        const before = sim.ops_seen;
        _ = try log.append("d");
        try testing.expectEqual(before + 1, sim.ops_seen);
        _ = try log.append("e");
        try testing.expectEqual(before + 3, sim.ops_seen); // write + the due sync
        try testing.expectEqual(log.nextLsn(), log.durableLsn());
        _ = try log.append("f");
        try testing.expectEqual(before + 4, sim.ops_seen);
        try testing.expectEqual(log.nextLsn() - 1, log.durableLsn());
    }
}

// ── automatic rotation ─────────────────────────────────────────────────────

var test_clock: i64 = 0;
fn testClock() i64 {
    return test_clock;
}

test "auto-rotation by size: the next id before an append that would overflow; a big batch goes whole" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    // Room for the header and two 1-byte records (2 × 26), not three.
    var log = try Log.open(testing.allocator, sim.storage(), .{ .create = true, .auto_rotate = .{ .max_bytes = 40 + 2 * 26 } });
    defer log.close();
    // No segment yet: the first append creates segment 1.
    try testing.expectEqual(Position{ .segment = 1, .offset = 40, .lsn = 1 }, (try log.append("a")).pos);
    _ = try log.append("b");
    try testing.expectEqual(Position{ .segment = 2, .offset = 40, .lsn = 3 }, (try log.append("c")).pos);
    // A batch larger than the limit is not split: it takes a fresh segment whole.
    const big = try log.appendMany(&.{ "1", "2", "3", "4" });
    try testing.expectEqual(Position{ .segment = 3, .offset = 40, .lsn = 4 }, big.pos);
    try testing.expectEqual(@as(u64, 4), big.lsn);
    try testing.expectEqual(Position{ .segment = 4, .offset = 40, .lsn = 8 }, (try log.append("d")).pos);
    try testing.expectEqualSlices(u64, &.{ 1, 2, 3, 4 }, log.segments());
    try expectPayloads(&log, null, &.{ "a", "b", "c", "1", "2", "3", "4", "d" });
}

test "auto-rotation by age, by the log's clock, and remembered across a reopen" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    test_clock = 1000;
    const opts: Options = .{ .create = true, .now = testClock, .auto_rotate = .{ .max_age = 60 } };
    {
        var log = try Log.open(testing.allocator, sim.storage(), opts);
        defer log.close();
        _ = try log.append("a"); // segment 1, created at 1000
        test_clock = 1059;
        _ = try log.append("b");
        try testing.expectEqual(@as(?u64, 1), log.activeSegment());
    }
    test_clock = 1060; // segment 1 is now 60 old: its creation time came from its header
    var log = try Log.open(testing.allocator, sim.storage(), opts);
    defer log.close();
    try testing.expectEqual(@as(u64, 2), (try log.append("c")).pos.segment);
    // An empty segment is never rotated away, however old.
    test_clock = 5000;
    try log.rotate(9);
    test_clock = 9000;
    try testing.expectEqual(@as(u64, 9), (try log.append("d")).pos.segment);
}

// ── many threads: Concurrent ────────────────────────────────────────────────

/// A `Storage.VTable` whose every slot forwards to `Self.inner`, for test
/// backends that change one slot and pass the rest through.
fn Forwarding(comptime Self: type) Storage.VTable {
    return .{
        .open = struct {
            fn f(ctx: *anyopaque, p: []const u8, m: Storage.OpenMode) Storage.Error!Storage.Handle {
                return @as(*Self, @ptrCast(@alignCast(ctx))).inner.open(p, m);
            }
        }.f,
        .size = struct {
            fn f(ctx: *anyopaque, h: Storage.Handle) Storage.Error!u64 {
                return @as(*Self, @ptrCast(@alignCast(ctx))).inner.size(h);
            }
        }.f,
        .pread = struct {
            fn f(ctx: *anyopaque, h: Storage.Handle, buf: []u8, off: u64) Storage.Error!usize {
                return @as(*Self, @ptrCast(@alignCast(ctx))).inner.pread(h, buf, off);
            }
        }.f,
        .writeAll = struct {
            fn f(ctx: *anyopaque, h: Storage.Handle, bytes: []const u8, off: u64) Storage.Error!void {
                return @as(*Self, @ptrCast(@alignCast(ctx))).inner.writeAll(h, bytes, off);
            }
        }.f,
        .sync = struct {
            fn f(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
                return @as(*Self, @ptrCast(@alignCast(ctx))).inner.sync(h);
            }
        }.f,
        .truncate = struct {
            fn f(ctx: *anyopaque, h: Storage.Handle, len: u64) Storage.Error!void {
                return @as(*Self, @ptrCast(@alignCast(ctx))).inner.truncate(h, len);
            }
        }.f,
        .close = struct {
            fn f(ctx: *anyopaque, h: Storage.Handle) void {
                @as(*Self, @ptrCast(@alignCast(ctx))).inner.close(h);
            }
        }.f,
        .rename = struct {
            fn f(ctx: *anyopaque, x: []const u8, y: []const u8) Storage.Error!void {
                return @as(*Self, @ptrCast(@alignCast(ctx))).inner.rename(x, y);
            }
        }.f,
        .delete = struct {
            fn f(ctx: *anyopaque, path: []const u8) Storage.Error!void {
                return @as(*Self, @ptrCast(@alignCast(ctx))).inner.delete(path);
            }
        }.f,
        .syncDir = struct {
            fn f(ctx: *anyopaque) Storage.Error!void {
                return @as(*Self, @ptrCast(@alignCast(ctx))).inner.syncDir();
            }
        }.f,
        .tryLockExclusive = struct {
            fn f(ctx: *anyopaque, h: Storage.Handle) Storage.Error!bool {
                return @as(*Self, @ptrCast(@alignCast(ctx))).inner.tryLockExclusive(h);
            }
        }.f,
    };
}

/// A backend that counts syncs from any thread.
const CountingSync = struct {
    inner: Storage,
    syncs: std.atomic.Value(u32) = .init(0),

    fn storage(self: *CountingSync) Storage {
        return .{ .ctx = self, .vtable = &vtable };
    }
    const vtable: Storage.VTable = blk: {
        var v = Forwarding(CountingSync);
        v.sync = sync_;
        break :blk v;
    };
    fn sync_(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
        const self: *CountingSync = @ptrCast(@alignCast(ctx));
        _ = self.syncs.fetchAdd(1, .monotonic);
        return self.inner.sync(h);
    }
};

const threads_n = 8;
const per_thread = 60;

fn appender(log: *Concurrent, id: u8, failed: *std.atomic.Value(bool)) void {
    var buf: [8]u8 = undefined;
    for (0..per_thread) |k| {
        buf[0] = id;
        std.mem.writeInt(u32, buf[1..5], @intCast(k), .little);
        // Mixed sizes, so segments fill at different record counts.
        const n: usize = if (k % 3 == 0) 8 else 5;
        _ = log.append(buf[0..n]) catch {
            failed.store(true, .monotonic);
            return;
        };
    }
}

test "Concurrent: many threads append; every record once, LSNs gapless, each thread in order, fsyncs shared" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var fs = FsStorage.init(testing.io, tmp.dir);
    var counting: CountingSync = .{ .inner = fs.storage() };
    // Small segments: rotations land while another thread's fsync runs, so a
    // retired handle must outlive it.
    var log = try Concurrent.open(testing.allocator, counting.storage(), testing.io, .{
        .create = true,
        .auto_rotate = .{ .max_bytes = 40 + 30 * 30 },
    });
    defer log.close();

    var failed: std.atomic.Value(bool) = .init(false);
    var threads: [threads_n]std.Thread = undefined;
    const syncs_before = counting.syncs.load(.monotonic);
    for (&threads, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, appender, .{ &log, @as(u8, @intCast(i)), &failed });
    for (threads) |t| t.join();
    try testing.expect(!failed.load(.monotonic));

    const total = threads_n * per_thread;
    try testing.expectEqual(@as(u64, total + 1), log.nextLsn());
    try testing.expectEqual(log.nextLsn(), log.durableLsn());
    // Group commit: fewer fsyncs than appends (rotations add their own).
    const syncs = counting.syncs.load(.monotonic) - syncs_before;
    try testing.expect(syncs < total);

    var next_k = @as([threads_n]u32, @splat(0));
    var it = log.iterator(null);
    defer it.deinit();
    var lsn: u64 = 1;
    while (try it.next()) |r| : (lsn += 1) {
        try testing.expectEqual(lsn, r.lsn);
        const id = r.payload[0];
        const k = std.mem.readInt(u32, r.payload[1..5], .little);
        try testing.expectEqual(next_k[id], k); // each thread's records in its own order
        next_k[id] += 1;
    }
    try testing.expectEqual(@as(u64, total + 1), lsn);
    for (next_k) |k| try testing.expectEqual(@as(u32, per_thread), k);
    try testing.expect(log.log.segments().len > 3); // it really rotated
}

/// A backend whose next `sync` stops before it reaches the storage, until
/// released — to put another thread's `rotate` exactly inside a running
/// group fsync, which real timing reaches too rarely to test by chance
/// (a `rotate` that closed the handle there went unnoticed by the
/// many-thread test in six runs out of six).
const PausedSync = struct {
    inner: Storage,
    io: std.Io,
    /// To see which file a handle names: backends reuse a closed handle's
    /// number at once, so a sync on a handle closed under it lands on
    /// whatever was opened next — no crash, just the wrong file (and on a
    /// real one, `EBADF` and a poisoned log).
    sim: *SimStorage,
    armed: std.atomic.Value(bool) = .init(false),
    entered: std.Io.Event = .unset,
    release: std.Io.Event = .unset,
    /// The paused sync's handle named another file once released.
    handle_moved: bool = false,

    fn storage(self: *PausedSync) Storage {
        return .{ .ctx = self, .vtable = &vtable };
    }
    const vtable: Storage.VTable = blk: {
        var v = Forwarding(PausedSync);
        v.sync = sync_;
        break :blk v;
    };
    fn sync_(ctx: *anyopaque, h: Storage.Handle) Storage.Error!void {
        const self: *PausedSync = @ptrCast(@alignCast(ctx));
        if (self.armed.swap(false, .acq_rel)) {
            const file = self.sim.handles.items[h];
            self.entered.set(self.io);
            self.release.waitUncancelable(self.io);
            if (self.sim.handles.items[h] != file) self.handle_moved = true;
        }
        return self.inner.sync(h);
    }
};

fn appendOne(c: *Concurrent, result: *?AppendError) void {
    _ = c.append("a") catch |e| {
        result.* = e;
    };
}

test "Concurrent: a rotate inside a running group fsync leaves that fsync its handle" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var paused: PausedSync = .{ .inner = sim.storage(), .io = testing.io, .sim = &sim };
    {
        var c = try Concurrent.open(testing.allocator, paused.storage(), testing.io, .{ .create = true });
        defer c.close();
        try c.rotate(1);

        paused.armed.store(true, .release);
        var result: ?AppendError = null;
        const t = try std.Thread.spawn(.{}, appendOne, .{ &c, &result });
        paused.entered.waitUncancelable(testing.io); // the leader is inside its fsync, lock released
        try c.rotate(2); // seals segment 1 — and must not close the handle under that fsync
        paused.release.set(testing.io);
        t.join();
        try testing.expect(!paused.handle_moved);
        try testing.expectEqual(@as(?AppendError, null), result);
        try testing.expectEqual(@as(u64, 2), c.durableLsn());
        try testing.expectEqual(@as(usize, 0), c.log.retired.items.len); // closed once it finished
    }
    // Nothing leaked: every handle the log opened is closed.
    for (sim.handles.items) |h| try testing.expect(h == null);
    var log = try openSim(&sim);
    defer log.close();
    try expectPayloads(&log, null, &.{"a"});
}

// ── seek by LSN and by time ─────────────────────────────────────────────────

const seek_n = 400;

/// Timestamps only roughly in order: a rising trend with jitter.
fn seekTs(k: usize) i64 {
    return @as(i64, @intCast(k / 4)) + @as(i64, @intCast((k * 37) % 11)) - 5;
}

/// The model's answer for seekTime(t): the first record at which the newest
/// timestamp so far reaches `t`.
fn expectedTime(t: i64, pos: []const Position) ?Position {
    var max: i64 = std.math.minInt(i64);
    for (pos, 0..) |ps, k| {
        max = @max(max, seekTs(k));
        if (max >= t) return ps;
    }
    return null;
}

fn checkSeeks(log: *Log, pos: []const Position, first_lsn: u64) !void {
    for (pos, 0..) |want, k| {
        const lsn = first_lsn + k;
        try testing.expectEqual(@as(?Position, want), try log.seek(lsn));
    }
    try testing.expectEqual(@as(?Position, null), try log.seek(first_lsn + pos.len));
    var t: i64 = seekTs(0) - 3;
    while (t < seekTs(pos.len - 1) + 8) : (t += 1) {
        try testing.expectEqual(expectedTime(t, pos), try log.seekTime(t));
    }
}

test "seek and seekTime find every record, live, reopened, without or with a bad index, and from a reader" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const opts: Options = .{ .create = true, .index_interval = 100, .auto_rotate = .{ .max_bytes = 3000 } };
    var pos: [seek_n]Position = undefined;
    {
        var log = try Log.open(testing.allocator, sim.storage(), opts);
        defer log.close();
        var buf: [16]u8 = undefined;
        for (0..seek_n) |k| {
            const payload = buf[0 .. 3 + k % 13];
            @memset(payload, @truncate(k));
            pos[k] = (try log.appendAt(seekTs(k), payload)).pos;
        }
        try testing.expect(log.segments().len >= 4);
        try checkSeeks(&log, &pos, 1); // the active segment's index is in memory
    }
    {
        var log = try Log.open(testing.allocator, sim.storage(), opts);
        defer log.close();
        try checkSeeks(&log, &pos, 1); // closed segments' `.idx` files
    }
    {
        var r = try openReader(&sim);
        defer r.close();
        try checkSeeks(&r, &pos, 1);
    }
    // A damaged index is not believed, a missing one is rebuilt.
    var log = try Log.open(testing.allocator, sim.storage(), opts);
    defer log.close();
    const segs = try testing.allocator.dupe(u64, log.segments());
    defer testing.allocator.free(segs);
    var nb: [seg_name_len]u8 = undefined;
    sim.flipByte(idxName(&nb, segs[2]), 30);
    try sim.storage().delete(idxName(&nb, segs[1]));
    // The damage no structural check can see: an entry's max_before lowered
    // to its predecessor's — still in order, still inside the segment, and it
    // would send seekTime past records that do reach the time. Only the CRC
    // knows. In the first segment, where every such time's answer lies.
    try testing.expect(lowerOneMaxBefore(sim.fileContent(idxName(&nb, segs[0])).?));
    try checkSeeks(&log, &pos, 1);
    // Retention takes the index with the segment.
    _ = try log.dropBefore(segs[2]);
    try testing.expect(sim.fileContent(idxName(&nb, segs[0])) == null);
    try testing.expectError(error.SegmentGone, log.seek(1));
    try testing.expectEqual(@as(?Position, pos[seek_n - 1]), try log.seek(seek_n));
}

/// In an `.idx` file's bytes: set the first entry whose max_before is above
/// its predecessor's to the predecessor's. False when none is.
fn lowerOneMaxBefore(file: []u8) bool {
    const n = std.mem.readInt(u32, file[24..28], .little);
    var k: usize = 1;
    while (k < n) : (k += 1) {
        const prev = std.mem.readInt(i64, file[idx_fixed + (k - 1) * idx_entry_len + 16 ..][0..8], .little);
        const cur = file[idx_fixed + k * idx_entry_len + 16 ..][0..8];
        if (std.mem.readInt(i64, cur, .little) > prev) {
            std.mem.writeInt(i64, cur, prev, .little);
            return true;
        }
    }
    return false;
}

/// A backend that counts the bytes `pread` returns.
const CountingReads = struct {
    inner: Storage,
    bytes: u64 = 0,

    fn storage(self: *CountingReads) Storage {
        return .{ .ctx = self, .vtable = &vtable };
    }
    const vtable: Storage.VTable = blk: {
        var v = Forwarding(CountingReads);
        v.pread = pread_;
        break :blk v;
    };
    fn pread_(ctx: *anyopaque, h: Storage.Handle, buf: []u8, off: u64) Storage.Error!usize {
        const self: *CountingReads = @ptrCast(@alignCast(ctx));
        const n = try self.inner.pread(h, buf, off);
        self.bytes += n;
        return n;
    }
};

test "a seek reads a sliver of a big segment, not the segment" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var counting: CountingReads = .{ .inner = sim.storage() };
    var log = try Log.open(testing.allocator, counting.storage(), .{ .create = true });
    defer log.close();
    try log.rotate(1);
    var buf: [100]u8 = @splat(7);
    for (0..10_000) |k| _ = try log.appendAt(@intCast(k), &buf); // ~1.25 MB
    try log.rotate(2);
    const size = sim.fileContent("seg-00000000000000000001.log").?.len;
    try testing.expect(size > 1_000_000);

    counting.bytes = 0;
    const last = (try log.seek(10_000)).?;
    try testing.expectEqual(@as(u64, 1), last.segment);
    // The index, one seek block (2 index intervals, at least 4 KiB), the
    // seal: far below the segment.
    const seek_block = 3 * @max(4096, 2 * 4096);
    try testing.expect(counting.bytes < seek_block);

    counting.bytes = 0;
    try testing.expectEqual(last, (try log.seekTime(9_999)).?);
    try testing.expect(counting.bytes < seek_block);
}

// ── compaction ──────────────────────────────────────────────────────────────

fn dropX(_: void, r: Record) bool {
    return !std.mem.startsWith(u8, r.payload, "x");
}

fn keepAll(_: void, _: Record) bool {
    return true;
}

fn expectLsns(log: *Log, from: ?Position, want: []const struct { u64, []const u8 }) !void {
    var it = log.iterator(from);
    defer it.deinit();
    for (want) |w| {
        const r = (try it.next()) orelse return error.TooFewRecords;
        try testing.expectEqual(w[0], r.lsn);
        try testing.expectEqualStrings(w[1], r.payload);
    }
    try testing.expectEqual(@as(?Record, null), try it.next());
}

test "compact drops what keep refuses, keeps the LSNs, and reading, seeking and old positions go on across the gaps" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try openSim(&sim);
    defer log.close();
    try log.rotate(1);
    var at: [5]Appended = undefined;
    for ([_][]const u8{ "a", "x1", "b", "x2", "c" }, 0..) |x, i| at[i] = try log.appendAt(@intCast(10 * i), x);
    try log.rotate(2);
    _ = try log.appendAt(100, "d");
    try log.rotate(3);
    _ = try log.appendAt(200, "e");

    try testing.expectError(error.NotCompactable, log.compact(3, {}, keepAll)); // the newest
    try testing.expectError(error.NotCompactable, log.compact(9, {}, keepAll));

    const st = try log.compact(1, {}, dropX);
    try testing.expectEqual(@as(u64, 3), st.kept);
    try testing.expectEqual(@as(u64, 2), st.dropped);
    try testing.expectEqual(@as(u64, 40 + (5 * 25 + 7) + 73), st.bytes_before); // payloads a x1 b x2 c
    try testing.expectEqual(@as(u64, 40 + 3 * 26 + 73), st.bytes_after);
    try testing.expectEqual(@as(usize, st.bytes_after), sim.fileContent("seg-00000000000000000001.log").?.len);
    try testing.expect(sim.fileContent(compact_tmp) == null);

    const all = [_]struct { u64, []const u8 }{ .{ 1, "a" }, .{ 3, "b" }, .{ 5, "c" }, .{ 6, "d" }, .{ 7, "e" } };
    try expectLsns(&log, null, &all);
    {
        var r = try log.verify(testing.allocator);
        defer r.deinit(testing.allocator);
        try testing.expect(r.clean());
        try testing.expectEqual(@as(u64, 5), r.records);
    }
    // seek: a dropped LSN gives the next record kept.
    try testing.expectEqual(@as(?u64, 3), (try log.seek(2)).?.lsn);
    try testing.expectEqual(@as(?u64, 5), (try log.seek(4)).?.lsn);
    try testing.expectEqual(@as(?u64, 6), (try log.seek(6)).?.lsn);
    try testing.expectEqual(@as(?u64, 3), (try log.seekTime(15)).?.lsn); // b at t=20
    // Positions from before: the offsets moved, the LSNs find the records.
    try expectLsns(&log, at[4].pos, all[2..]); // "c"
    try expectLsns(&log, at[1].pos, all[1..]); // "x1", dropped: on from "b"
    try expectLsns(&log, at[3].pos, all[2..]); // "x2", dropped: on from "c"

    // Reopened: the old index file no longer fits the segment, and is not used.
    log.close();
    log = try openSim(&sim);
    try expectLsns(&log, null, &all);
    try testing.expectEqual(@as(?u64, 5), (try log.seek(5)).?.lsn);
    // Compacting a compacted segment again keeps what it has.
    const again = try log.compact(1, {}, keepAll);
    try testing.expectEqual(@as(u64, 3), again.kept);
    try testing.expectEqual(st.bytes_after, again.bytes_after);
    try expectLsns(&log, null, &all);
}

fn keyOfEq(_: void, payload: []const u8) ?[]const u8 {
    const eq = std.mem.findScalar(u8, payload, '=') orelse return null;
    return payload[0..eq];
}

test "compactByKey keeps only the newest record of each key, looking at the whole log" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try openSim(&sim);
    defer log.close();
    try log.rotate(1);
    for ([_][]const u8{ "a=1", "b=1", "note", "a=2" }) |x| _ = try log.append(x);
    try log.rotate(2);
    for ([_][]const u8{ "c=1", "b=2" }) |x| _ = try log.append(x);
    try log.rotate(3);
    _ = try log.append("a=3"); // the active segment: newest a, not compacted itself

    const st = try log.compactByKey(&.{ 1, 2 }, {}, keyOfEq);
    try testing.expectEqual(@as(u64, 3), st.kept); // note, c=1, b=2
    try testing.expectEqual(@as(u64, 3), st.dropped); // a=1, b=1, a=2
    try expectLsns(&log, null, &.{ .{ 3, "note" }, .{ 5, "c=1" }, .{ 6, "b=2" }, .{ 7, "a=3" } });
}

test "a damaged segment is not compacted: refused, left as it was, no temp file behind" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    try twoSegments(&sim); // segment 1 closed, 2 newest
    sim.flipByte(seg1_name, 40 + 26 + 25);
    const before = try testing.allocator.dupe(u8, sim.fileContent(seg1_name).?);
    defer testing.allocator.free(before);
    var log = try openSim(&sim);
    defer log.close();
    try testing.expectError(error.Corrupt, log.compact(1, {}, keepAll));
    try testing.expectEqualSlices(u8, before, sim.fileContent(seg1_name).?);
    try testing.expect(sim.fileContent(compact_tmp) == null);
    try testing.expect(!log.isPoisoned());
}

test "open removes a COMPACT.tmp an interrupted compaction left" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    try twoSegments(&sim);
    try sim.installFile(compact_tmp, "half a segment");
    var log = try openSim(&sim);
    defer log.close();
    try testing.expect(sim.fileContent(compact_tmp) == null);
    try expectPayloads(&log, null, &.{ "a", "b", "c", "d", "e" });
}

// ── stats ───────────────────────────────────────────────────────────────────

var fake_ns: u64 = 0;
fn fakeMonotonic() u64 {
    fake_ns += 3 * std.time.ns_per_ms; // every reading 3 ms after the last
    return fake_ns;
}

test "stats count what the log did, and time its fsyncs when given a clock" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try Log.open(testing.allocator, sim.storage(), .{ .create = true, .monotonic_ns = fakeMonotonic });
    defer log.close();
    try log.rotate(1);
    _ = try log.append("a");
    _ = try log.appendMany(&.{ "bb", "ccc" });
    try log.rotate(2); // seals 1: one more fsync
    _ = try log.append("x");
    try log.rotate(3);
    _ = try log.compact(2, {}, dropX);
    _ = try log.dropBefore(2);

    const st = log.stats();
    try testing.expectEqual(@as(u64, 3), st.appends);
    try testing.expectEqual(@as(u64, 4), st.records);
    try testing.expectEqual(@as(u64, 4 * 25 + 1 + 2 + 3 + 1), st.bytes);
    try testing.expectEqual(@as(u64, 3 + 2), st.syncs); // 3 appends + 2 seals
    try testing.expectEqual(@as(u64, 3), st.rotations);
    try testing.expectEqual(@as(u64, 1), st.segments_dropped);
    try testing.expectEqual(@as(u64, 1), st.compactions);
    try testing.expectEqual(@as(u64, 1), st.records_compacted_away);
    try testing.expectEqual(@as(usize, 2), st.segments);
    try testing.expectEqual(@as(u64, 5), st.next_lsn);
    try testing.expectEqual(@as(u64, 5), st.durable_lsn);
    try testing.expectEqual(@as(u64, 40), st.active_bytes);
    // Each fsync measured 3 ms: 3000 µs lands in the bucket under 2^12.
    try testing.expectEqual(@as(u64, 5), st.sync_latency.count);
    try testing.expectEqual(@as(u64, 5), st.sync_latency.buckets[12]);
    try testing.expectEqual(@as(u64, 3 * std.time.ns_per_ms), st.sync_latency.max_ns);
    try testing.expectEqual(@as(u64, 4096), st.sync_latency.quantileUpperUs(0.99));

    // No clock: counted, not timed.
    var sim2 = SimStorage.init(testing.allocator);
    defer sim2.deinit();
    var plain = try openSim(&sim2);
    defer plain.close();
    try plain.rotate(1);
    _ = try plain.append("a");
    try testing.expectEqual(@as(u64, 1), plain.stats().syncs);
    try testing.expectEqual(@as(u64, 0), plain.stats().sync_latency.count);
}

// ── damage, recovery, verify, retention ─────────────────────────────────────

/// Segment 1: "a" "b" "c" (LSN 1–3), sealed; segment 2: "d" "e" (4–5).
/// Record k (0-based) of segment 1 starts at 40 + 26k; its payload byte at +25.
fn twoSegments(sim: *SimStorage) !void {
    var log = try openSim(sim);
    defer log.close();
    try log.rotate(1);
    for ([_][]const u8{ "a", "b", "c" }) |x| _ = try log.append(x);
    try log.rotate(2);
    for ([_][]const u8{ "d", "e" }) |x| _ = try log.append(x);
}

const seg1_name = "seg-00000000000000000001.log";

test "damage is named, and skipSegment goes on with the next segment, saying which LSNs it lost" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    try twoSegments(&sim);
    sim.flipByte(seg1_name, 40 + 26 + 25); // inside "b"
    var log = try openSim(&sim);
    defer log.close();
    var it = log.iterator(null);
    defer it.deinit();
    try expectNext(&it, "a");
    try testing.expectEqual(@as(?Damage, null), it.damage());
    try testing.expectError(error.Corrupt, it.next());
    try testing.expectEqual(Damage{ .segment = 1, .offset = 66, .reason = .bad_record }, it.damage().?);
    try testing.expectEqual(Gap{ .from_lsn = 2, .to_lsn = 3 }, it.skipSegment().?);
    try testing.expectEqual(@as(?Gap, null), it.skipSegment()); // nothing left to step over
    try expectNext(&it, "d");
    try expectNext(&it, "e");
    try expectNext(&it, null);
}

test "resync steps over one bad record and reads on in the same segment" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    try twoSegments(&sim);
    sim.flipByte(seg1_name, 40 + 26 + 25); // inside "b"
    var log = try openSim(&sim);
    defer log.close();
    var it = log.iterator(null);
    defer it.deinit();
    try expectNext(&it, "a");
    try testing.expectError(error.Corrupt, it.next());
    try testing.expectEqual(Gap{ .from_lsn = 2, .to_lsn = 2 }, (try it.resync()).?);
    const c = (try it.next()).?;
    try testing.expectEqualStrings("c", c.payload);
    try testing.expectEqual(@as(u64, 3), c.lsn);
    // The seal is still checked against its offset and LSN range.
    try expectNext(&it, "d");
    try expectNext(&it, "e");
    try expectNext(&it, null);
}

test "resync past a damaged seal finds nothing more in the segment, and loses nothing" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    try twoSegments(&sim);
    sim.flipByte(seg1_name, 40 + 3 * 26 + 25 + 3); // inside the seal's payload
    var log = try openSim(&sim);
    defer log.close();
    var it = log.iterator(null);
    defer it.deinit();
    for ([_][]const u8{ "a", "b", "c" }) |x| try expectNext(&it, x);
    try testing.expectError(error.Corrupt, it.next());
    try testing.expectEqual(Damage.Reason.bad_record, it.damage().?.reason);
    // Every record of segment 1 was read: the gap is empty, from > to.
    try testing.expectEqual(Gap{ .from_lsn = 4, .to_lsn = 3 }, (try it.resync()).?);
    try expectNext(&it, "d");
}

test "a bad header is named, and the whole segment is stepped over" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    try twoSegments(&sim);
    sim.flipByte(seg1_name, 10); // the id, under the header CRC
    var log = try openSim(&sim);
    defer log.close();
    var it = log.iterator(null);
    defer it.deinit();
    try testing.expectError(error.Corrupt, it.next());
    try testing.expectEqual(Damage{ .segment = 1, .offset = 0, .reason = .bad_header }, it.damage().?);
    try testing.expectEqual(Gap{ .from_lsn = 1, .to_lsn = 3 }, (try it.resync()).?);
    try expectNext(&it, "d");
}

test "verify: a clean log, then one with damage in two segments" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    try twoSegments(&sim);
    {
        var log = try openSim(&sim);
        defer log.close();
        try log.rotate(3);
        _ = try log.append("f");
        var r = try log.verify(testing.allocator);
        defer r.deinit(testing.allocator);
        try testing.expect(r.clean());
        try testing.expectEqual(@as(usize, 3), r.segments);
        try testing.expectEqual(@as(u64, 6), r.records);
        try testing.expectEqual(@as(u64, 6), r.last_lsn);
    }
    sim.flipByte(seg1_name, 40 + 26 + 25); // "b"
    sim.flipByte("seg-00000000000000000002.log", 12); // segment 2's header
    var log = try openSim(&sim);
    defer log.close();
    var r = try log.verify(testing.allocator);
    defer r.deinit(testing.allocator);
    try testing.expect(!r.clean());
    try testing.expectEqualSlices(Damage, &.{
        .{ .segment = 1, .offset = 66, .reason = .bad_record },
        .{ .segment = 2, .offset = 0, .reason = .bad_header },
    }, r.damage.items);
    try testing.expectEqualSlices(Gap, &.{ .{ .from_lsn = 2, .to_lsn = 2 }, .{ .from_lsn = 4, .to_lsn = 5 } }, r.gaps.items);
    try testing.expectEqual(@as(u64, 3), r.records); // a, c, f
}

test "retention drops the oldest segments by size and by age, never the newest" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var log = try openSim(&sim);
    defer log.close();
    // Segment 1 newest record at t=100, 2 at t=200, 3 empty, 4 active at t=400.
    try log.rotate(1);
    _ = try log.appendAt(100, "x");
    try log.rotate(2);
    _ = try log.appendAt(150, "y");
    _ = try log.appendAt(200, "z");
    try log.rotate(3);
    try log.rotate(4);
    _ = try log.appendAt(400, "w");

    // Age: 1 (100) is older than 420 − 250 = 170; 2 (200) is not, and ends it.
    try testing.expectEqual(@as(usize, 1), try log.enforceRetention(.{ .max_age = 250 }, 420));
    try testing.expectEqualSlices(u64, &.{ 2, 3, 4 }, log.segments());
    // Nothing to drop: a no-op.
    try testing.expectEqual(@as(usize, 0), try log.enforceRetention(.{ .max_age = 250 }, 420));

    // Size: segment 2 = 40 + 2·26 + 73 bytes, 3 = 40 + 73, 4 = 40 + 26 (unsealed).
    const s2: u64 = 40 + 2 * 26 + 73;
    const s3: u64 = 40 + 73;
    const s4: u64 = 40 + 26;
    try testing.expectEqual(@as(usize, 0), try log.enforceRetention(.{ .max_bytes = s2 + s3 + s4 }, 0));
    try testing.expectEqual(@as(usize, 1), try log.enforceRetention(.{ .max_bytes = s2 + s3 + s4 - 1 }, 0));
    try testing.expectEqualSlices(u64, &.{ 3, 4 }, log.segments());
    // An empty segment is as old as can be; the newest stays whatever is asked.
    try testing.expectEqual(@as(usize, 1), try log.enforceRetention(.{ .max_bytes = 0, .max_age = 0 }, 1_000_000));
    try testing.expectEqualSlices(u64, &.{4}, log.segments());
    try expectPayloads(&log, null, &.{"w"});
}

// ── read-only open ───────────────────────────────────────────────────────────

fn openReader(sim: *SimStorage) !Log {
    return Log.openReadOnly(testing.allocator, sim.storage(), .{});
}

fn expectNext(it: *Iterator, want: ?[]const u8) !void {
    const got = try it.next();
    if (want) |w| {
        try testing.expect(got != null);
        try testing.expectEqualStrings(w, got.?.payload);
    } else try testing.expect(got == null);
}

test "looking for a missing log creates nothing, reader or writer" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    try testing.expectError(error.NotFound, openReader(&sim));
    try testing.expect(sim.fileContent("MANIFEST") == null);
    try testing.expect(sim.fileContent("LOCK") == null);
    // The writer without `create` used to leave an empty MANIFEST behind.
    try testing.expectError(error.NotFound, Log.open(testing.allocator, sim.storage(), .{}));
    try testing.expect(sim.fileContent("MANIFEST") == null);
}

test "a reader beside a live writer takes no lock and follows appends, rotations and drops" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var w = try openSim(&sim);
    try w.rotate(1);
    const pos_a = try w.append("a");
    _ = try w.append("b");

    var r = try openReader(&sim); // the writer holds LOCK; the reader does not care
    defer r.close();
    try testing.expect(r.isReadOnly());
    var it = r.iterator(null);
    defer it.deinit();
    try expectNext(&it, "a");
    try expectNext(&it, "b");
    try expectNext(&it, null);

    _ = try w.append("c");
    try expectNext(&it, "c");
    try expectNext(&it, null);

    // Across a rotation the reader only learns of segment 2 from the manifest.
    try w.rotate(2);
    _ = try w.append("d");
    try expectNext(&it, "d");
    try expectNext(&it, null);
    try testing.expectEqualSlices(u64, &.{ 1, 2 }, r.segments());

    // A drop behind the reader's back: its view still names segment 1, the
    // file is gone, and asking for it neither succeeds nor recreates it.
    _ = try w.dropBefore(2);
    const seg1 = "seg-00000000000000000001.log";
    try testing.expect(sim.fileContent(seg1) == null);
    {
        var old = r.iterator(pos_a.pos);
        defer old.deinit();
        try testing.expectError(error.SegmentGone, old.next());
    }
    try testing.expect(sim.fileContent(seg1) == null);
    try r.refresh();
    try testing.expectEqualSlices(u64, &.{2}, r.segments());

    // Every mutation is refused, and none of them touched a file.
    try testing.expectError(error.ReadOnly, r.append("x"));
    try testing.expectError(error.ReadOnly, r.rotate(3));
    try testing.expectError(error.ReadOnly, r.dropBefore(3));
    try testing.expect(sim.fileContent("MANIFEST.tmp") == null);

    // The reader never held the lock: a new writer opens while it is still open.
    w.close();
    var w2 = try openSim(&sim);
    defer w2.close();
    _ = try w2.append("e");
    try expectNext(&it, "e");
}

test "a reader stops at a record still arriving, and cuts nothing" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const name = "seg-00000000000000000001.log";
    var end: u64 = undefined;
    {
        var w = try openSim(&sim);
        defer w.close();
        try w.rotate(1);
        _ = try w.append("kept");
        end = w.end().?.offset;
    }
    const st = sim.storage();
    var rec: [25 + 8]u8 = undefined;
    encodeRecord(&rec, rec_data, 2, 0, "arriving");
    const h = try st.open(name, .open_or_create);
    defer st.close(h);

    var r = try openReader(&sim);
    defer r.close();
    var it = r.iterator(null);
    defer it.deinit();
    try expectNext(&it, "kept");
    // Each partial state an in-flight write can show: part of the header,
    // the header without all of its payload, and all bytes but a stale CRC.
    try st.writeAll(h, rec[0..5], end);
    try expectNext(&it, null);
    try st.writeAll(h, rec[5..12], end + 5);
    try expectNext(&it, null);
    try st.writeAll(h, rec[12..], end + 12);
    try st.writeAll(h, "\x00\x00\x00\x00", end); // CRC not written yet
    try expectNext(&it, null);
    try testing.expectEqual(@as(usize, end + rec.len), sim.fileContent(name).?.len);
    try st.writeAll(h, rec[0..4], end);
    try expectNext(&it, "arriving");
    try expectNext(&it, null);
}

test "a reader waits for a segment the writer has named but not yet written" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    const st = sim.storage();
    const seg2 = "seg-00000000000000000002.log";
    {
        var w = try openSim(&sim);
        defer w.close();
        try w.rotate(1);
        _ = try w.append("x");
        try w.rotate(2);
    }
    // `rotate` commits the manifest before the file: take the file away to
    // stand in for the moment in between.
    try st.delete(seg2);

    var r = try openReader(&sim);
    defer r.close();
    var it = r.iterator(null);
    defer it.deinit();
    try expectNext(&it, "x");
    try expectNext(&it, null); // named, no file
    try testing.expect(sim.fileContent(seg2) == null);

    var hdr: [segment_header_len]u8 = undefined;
    encodeHeader(&hdr, 2, 2, 0);
    const h = try st.open(seg2, .open_or_create);
    defer st.close(h);
    try st.writeAll(h, hdr[0..7], 0);
    try expectNext(&it, null); // a header still being written

    try st.writeAll(h, hdr[7..], 7);
    var rec: [25 + 1]u8 = undefined;
    encodeRecord(&rec, rec_data, 2, 0, "y");
    try st.writeAll(h, &rec, segment_header_len);
    try expectNext(&it, "y");

    // Only the newest segment gets that patience: a closed one whose file is
    // missing is gone.
    var r2 = try openReader(&sim);
    defer r2.close();
    try st.delete("seg-00000000000000000001.log");
    var it2 = r2.iterator(null);
    defer it2.deinit();
    try testing.expectError(error.SegmentGone, it2.next());
}

test "the real filesystem: a reader in its own backend beside a locked writer" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // Two backends, two sets of file descriptions — what two processes have.
    var fs_w = FsStorage.init(testing.io, tmp.dir);
    var fs_r = FsStorage.init(testing.io, tmp.dir);
    var w = try Log.open(testing.allocator, fs_w.storage(), .{ .create = true });
    defer w.close();
    try w.rotate(1);
    _ = try w.append("disk-1");

    try testing.expectError(error.Locked, Log.open(testing.allocator, fs_r.storage(), .{}));
    var r = try Log.openReadOnly(testing.allocator, fs_r.storage(), .{});
    defer r.close();
    var it = r.iterator(null);
    defer it.deinit();
    try expectNext(&it, "disk-1");
    try expectNext(&it, null);
    try w.rotate(2);
    _ = try w.appendMany(&.{ "disk-2", "disk-3" });
    try expectNext(&it, "disk-2");
    try expectNext(&it, "disk-3");
    try expectNext(&it, null);
}

test "a reader resumes from a position in a segment it has not heard of yet" {
    var sim = SimStorage.init(testing.allocator);
    defer sim.deinit();
    var w = try openSim(&sim);
    defer w.close();
    try w.rotate(1);
    _ = try w.append("a");
    var r = try openReader(&sim);
    defer r.close();

    // Saved by a consumer of the writer after the reader opened.
    try w.rotate(2);
    const pos = try w.append("b");
    _ = try w.append("c");
    try expectPayloads(&r, pos.pos, &.{ "b", "c" });
}
