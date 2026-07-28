// SPDX-License-Identifier: MIT
//! Ring-buffer consumer — the userspace side of `BPF_MAP_TYPE_RINGBUF`: mmap
//! the kernel-side map into this process and poll it for records written by
//! `programs.ringbufEmit`-shaped programs. No verifier is involved on this
//! side (that's entirely a kernel-side/program-build-time concern, see
//! `programs.zig`) — this is mmap + memory-barrier + epoll bookkeeping.
//!
//! ## The mmap ABI (`kernel/bpf/ringbuf.c`, `ringbuf_map_mmap_user`)
//!
//! The map fd is mmap-able at two page offsets, and the kernel — not
//! userspace — is what makes wrap-around records contiguous:
//!
//! ```text
//! pgoff 0   | consumer page | PROT_READ|PROT_WRITE, exactly 1 page.
//!           |               | [0..8) = consumer_pos (this side writes it).
//!           |               | A writable mapping of any other offset or
//!           |               | length is rejected with EPERM.
//! pgoff 1   | producer page | PROT_READ only, 1 page.
//!           |               | [0..8) = producer_pos (the kernel writes it).
//! pgoff 2.. | data          | PROT_READ only, `max_entries` bytes — but
//!           |               | mapped TWICE back-to-back by the kernel
//!           |               | itself (its page array aliases each data page
//!           |               | at both `i` and `i + nr_data_pages`).
//! ```
//!
//! So the whole producer side is ONE mmap of `page_size + 2 * max_entries` at
//! offset `page_size`, exactly as libbpf's `ring_buffer__add` does. This
//! module deliberately does NOT do the userspace "reserve `2*len` PROT_NONE
//! then `MAP_FIXED`-overlay two copies" trick that `io_uring`-style SPSC
//! rings need: the BPF ringbuf's double mapping is a property of the kernel
//! object, and re-doing it here would map the same pages a third and fourth
//! time for no benefit.
//!
//! ## Record framing
//!
//! Each record is preceded by an 8-byte header (`struct bpf_ringbuf_hdr {
//! u32 len; u32 pg_off; }`), and the whole `header + payload` is rounded up
//! to 8 bytes. The header's `len` carries two flags in its top bits:
//! `BPF_RINGBUF_BUSY_BIT` (1<<31, the kernel reserved the space but has not
//! submitted it yet — the payload is NOT readable) and
//! `BPF_RINGBUF_DISCARD_BIT` (1<<30, the program called
//! `bpf_ringbuf_discard` — skip the bytes, never surface them to a caller).
//!
//! ## Barrier discipline (the part a missing barrier silently breaks)
//!
//! Three atomics, three different orderings, each pairing with a specific
//! kernel-side one:
//!
//! 1. **`producer_pos`: acquire load.** Pairs with the kernel's
//!    `smp_store_release(&rb->producer_pos, ...)`. Without acquire, the
//!    record bytes written *before* the kernel published the new position
//!    may not be visible to this CPU even though the position is — a real
//!    data race that reads stale/garbage payloads, not a theoretical one.
//! 2. **The record header `len`: acquire load.** Pairs with the kernel's
//!    `smp_store_release(&hdr->len, new_len)` inside
//!    `bpf_ringbuf_commit()`, which is what clears `BUSY`. Seeing the
//!    cleared BUSY bit must therefore also mean seeing the payload the
//!    program wrote into the reservation; a relaxed load here is the classic
//!    "record contents lag the flag" bug.
//! 3. **`consumer_pos`: release store.** Pairs with the kernel's acquire
//!    load in `__bpf_ringbuf_reserve` (via `smp_load_acquire(&rb->
//!    consumer_pos)`). It must not become visible before this side has
//!    finished *reading* the record, or the kernel may hand that space to a
//!    new reservation while the caller still holds a slice into it.
//!
//! Everything else is plain loads: the consumer position is also cached in
//! this struct (only this thread writes it), and the payload bytes are
//! ordered by (2).
//!
//! ## Bounds
//!
//! Every field in a record header is kernel-supplied and is therefore
//! treated as untrusted: a length that exceeds the ring, runs past
//! `producer_pos`, or would make the consumer position move backwards is a
//! typed `ConsumeError`, never a panic and never an out-of-bounds read.

const std = @import("std");
const builtin = @import("builtin");

// Skip diagnostics are opt-in: `zig build test` must be silent on
// success (any stderr triggers the build runner's `failed command:`
// line even when the step succeeded), while the skip *count* still
// shows up in the summary regardless. Set ZIG_LIBS_VERBOSE_SKIP to any
// non-empty value to see the reasons. (std.posix.getenv doesn't exist
// in 0.16 — std.testing.environ + Environ.getPosix is the repo's
// existing env-read pattern for tests, see netconf's `envVar`.)
fn verboseSkip() bool {
    const v = std.process.Environ.getPosix(std.testing.environ, "ZIG_LIBS_VERBOSE_SKIP") orelse return false;
    return v.len > 0;
}
const linux = std.os.linux;
const BPF = linux.BPF;

const native_endian = builtin.cpu.arch.endian();

// ── wire constants (include/uapi/linux/bpf.h) ───────────────────────────────

/// Set while the kernel is still writing a reservation — the record must not
/// be read, and the consumer must stop (not skip) at it.
pub const BPF_RINGBUF_BUSY_BIT: u32 = 1 << 31;
/// Set when the program called `bpf_ringbuf_discard` — skip these bytes.
pub const BPF_RINGBUF_DISCARD_BIT: u32 = 1 << 30;
/// `sizeof(struct bpf_ringbuf_hdr)` — u32 len + u32 pg_off.
pub const BPF_RINGBUF_HDR_SZ: usize = 8;
/// Mask isolating the length from the two flag bits.
pub const BPF_RINGBUF_LEN_MASK: u32 = ~(BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT);

/// Round a record header's length field up to the ring's 8-byte granule,
/// header included — the amount `consumer_pos` advances per record.
/// `len` must already have its flag bits masked off.
pub fn recordStride(len: u32) usize {
    return std.mem.alignForward(usize, @as(usize, len) + BPF_RINGBUF_HDR_SZ, 8);
}

/// A record read out of the ring buffer: a borrowed view into the mmap'd
/// region, valid only until the next `next()`/`advance()` call (the kernel
/// may overwrite it once the consumer position moves past it).
pub const Record = struct {
    data: []const u8,
};

pub const OpenError = error{
    /// `map_fd` is not a `BPF_MAP_TYPE_RINGBUF` map, or its `max_entries`
    /// is not a power of 2 (both required by the kernel's mmap layout).
    NotARingbufMap,
    MmapFailed,
    EpollFailed,
    PermissionDenied,
    Unexpected,
};

pub const PollError = error{
    /// No epoll fd on this reader (a hand-built one, e.g. in tests).
    NotPollable,
    EpollFailed,
    Unexpected,
};

/// Failures decoding kernel-supplied record framing. Every one of these means
/// the ring's contents are inconsistent with its positions; none of them can
/// be caused by a well-behaved kernel + a well-behaved consumer.
pub const ConsumeError = error{
    /// A record header declares a length that does not fit inside the ring,
    /// or that runs past `producer_pos`.
    CorruptRecord,
    /// `producer_pos` is behind `consumer_pos`, or the two are not 8-byte
    /// aligned relative to each other.
    InconsistentPositions,
};

/// What a `SampleFn` wants the consume loop to do next.
pub const Action = enum { proceed, stop };

/// Per-record callback. `data` borrows the mmap'd ring and is invalid as soon
/// as the callback returns (the consumer position advances immediately
/// after) — copy anything that must outlive it.
pub const SampleFn = *const fn (ctx: ?*anyopaque, data: []const u8) Action;

/// An open consumer for one `BPF_MAP_TYPE_RINGBUF` map.
///
/// Single-owner: the mmap'd state and the epoll fd are not internally
/// synchronized, matching the module's declared `.concurrency =
/// .single_owner`. One `Reader` per thread; the kernel side is MPSC, so
/// multiple producers are fine but a second consumer is not.
pub const Reader = struct {
    /// Borrowed — the caller created it and closes it (same convention as
    /// `load.zig`'s returned `prog_fd`).
    map_fd: linux.fd_t,
    /// The consumer page: 1 kernel page, PROT_READ|PROT_WRITE, mmap offset 0.
    /// `[0..8)` is `consumer_pos`, written with a RELEASE store.
    cons_page: []align(std.heap.page_size_min) u8,
    /// The producer page + the kernel's double-mapped data region, in one
    /// mapping of `page_size + 2 * ring_size` at mmap offset `page_size`.
    /// `[0..8)` is `producer_pos` (ACQUIRE load); the records start at
    /// `data_off`.
    data_pages: []align(std.heap.page_size_min) u8,
    /// Byte offset of the record area inside `data_pages` — the kernel page
    /// size, kept as a field so a hand-built (test) ring can use a different
    /// stride without pretending to know the host's page size.
    data_off: usize,
    /// `max_entries`: the ring's byte capacity. Always a power of two.
    ring_size: usize,
    /// `ring_size - 1`, the offset mask.
    mask: usize,
    /// Cached consumer position. Only this side writes it, so plain reads of
    /// the cache are fine; the RELEASE store into `cons_page` is what the
    /// kernel observes.
    consumer_pos: u64,
    /// Bytes `advance()` will consume — set by `next()`, cleared by
    /// `advance()`. Zero means "no record is being held".
    pending: usize,
    /// `-1` when the reader was constructed without epoll (test rings).
    epoll_fd: linux.fd_t,
    /// False for a hand-built reader whose pages are not mmap'd, so `close()`
    /// does not `munmap` memory it does not own.
    owns_mappings: bool,

    /// Open a consumer for `map_fd` (must be a `BPF_MAP_TYPE_RINGBUF` map).
    /// The ring's size is read back from the kernel with
    /// `BPF_OBJ_GET_INFO_BY_FD` so the caller cannot desynchronize it from
    /// what `map_create` actually allocated.
    ///
    /// The returned reader borrows `map_fd`; `close()` unmaps and closes only
    /// what it created itself.
    pub fn open(map_fd: linux.fd_t) OpenError!Reader {
        const info = try mapInfo(map_fd);
        if (info.type != @intFromEnum(BPF.MapType.ringbuf)) return error.NotARingbufMap;
        return openWithRingSize(map_fd, info.max_entries);
    }

    /// `open` for callers that already know `max_entries` (and want to skip
    /// the `BPF_OBJ_GET_INFO_BY_FD` round trip, e.g. on a kernel too old for
    /// it). `ring_size` must equal the map's `max_entries` — a mismatch
    /// produces a mask that walks the ring wrongly, so it is validated
    /// against the mmap layout the kernel grants, not trusted outright.
    pub fn openWithRingSize(map_fd: linux.fd_t, ring_size: u32) OpenError!Reader {
        if (comptime builtin.os.tag != .linux)
            @compileError("ebpf.RingbufReader is Linux-only (mmap of a BPF map fd)");

        const page_size = std.heap.pageSize();
        if (ring_size == 0 or !std.math.isPowerOfTwo(ring_size)) return error.NotARingbufMap;
        if (ring_size % page_size != 0) return error.NotARingbufMap;

        const cons = try mapPages(map_fd, page_size, 0, true);
        errdefer _ = linux.munmap(cons.ptr, cons.len);

        // page_size (producer page) + 2 * ring_size (the kernel's own double
        // mapping of the data pages).
        const data_len = page_size + 2 * @as(usize, ring_size);
        const data = try mapPages(map_fd, data_len, @intCast(page_size), false);
        errdefer _ = linux.munmap(data.ptr, data.len);

        const efd = try openEpoll(map_fd);
        errdefer _ = linux.close(efd);

        var self: Reader = .{
            .map_fd = map_fd,
            .cons_page = cons,
            .data_pages = data,
            .data_off = page_size,
            .ring_size = ring_size,
            .mask = @as(usize, ring_size) - 1,
            .consumer_pos = 0,
            .pending = 0,
            .epoll_fd = efd,
            .owns_mappings = true,
        };
        // Adopt whatever position the kernel-visible consumer page already
        // holds: re-opening a reader on a map another process consumed from
        // must not replay (or skip) records.
        self.consumer_pos = @atomicLoad(u64, self.consumerPosPtr(), .acquire);
        return self;
    }

    /// Unmap both regions and close the epoll fd. `map_fd` stays owned by the
    /// caller (this `Reader` borrows it, mirroring how `load.zig`'s `load`
    /// returns an fd the CALLER closes).
    pub fn close(self: *Reader) void {
        if (self.owns_mappings) {
            // One munmap per mapping: `data_pages` is a single mapping that
            // already spans both copies of the data area, so unmapping it
            // per-copy would be wrong (and would leave half of it live).
            _ = linux.munmap(self.data_pages.ptr, self.data_pages.len);
            _ = linux.munmap(self.cons_page.ptr, self.cons_page.len);
        }
        if (self.epoll_fd >= 0) _ = linux.close(self.epoll_fd);
        self.* = undefined;
    }

    /// The fd to register in a caller-owned event loop, if you would rather
    /// not use `poll()`. Level-triggered `EPOLLIN`.
    pub fn pollFd(self: *const Reader) linux.fd_t {
        return self.map_fd;
    }

    /// Block (via `epoll_wait`) until at least one record is available or
    /// `timeout_ms` elapses (`-1` = forever, `0` = immediate poll). Returns
    /// true if data is actually pending.
    ///
    /// The kernel signals the map fd whenever `producer_pos` advances (unless
    /// the program passed `BPF_RB_NO_WAKEUP` to submit/output, which none of
    /// `programs.zig`'s builders do). An epoll wakeup is a HINT, not a
    /// guarantee, so the return value comes from re-checking the positions,
    /// not from `epoll_wait`'s return value.
    pub fn poll(self: *Reader, timeout_ms: i32) PollError!bool {
        if (self.available()) return true;
        if (self.epoll_fd < 0) return error.NotPollable;

        var events: [1]linux.epoll_event = undefined;
        while (true) {
            const rc = linux.epoll_wait(self.epoll_fd, &events, events.len, timeout_ms);
            switch (linux.errno(rc)) {
                .SUCCESS => break,
                .INTR => continue,
                .BADF, .INVAL => return error.EpollFailed,
                else => return error.Unexpected,
            }
        }
        return self.available();
    }

    /// True if the producer is ahead of the consumer. Cheap (one acquire
    /// load); does not decode any record, so a ring holding only a
    /// still-BUSY reservation reports true and the following `next()`
    /// correctly returns null.
    pub fn available(self: *Reader) bool {
        const prod = @atomicLoad(u64, self.producerPosPtr(), .acquire);
        return prod > self.consumer_pos;
    }

    /// Return the next unread, non-discarded record, or `null` if the
    /// consumer has caught up to the producer (or the next record is still
    /// being written). Call `advance()` after processing it to release the
    /// space back to the kernel.
    ///
    /// Idempotent between `advance()` calls: calling `next()` twice without
    /// an intervening `advance()` returns the same record, because nothing
    /// moved the consumer position.
    ///
    /// Discarded records are consumed internally (their space is released
    /// immediately) and never surface to the caller, matching libbpf's
    /// `ring_buffer__consume`.
    pub fn next(self: *Reader) ConsumeError!?Record {
        // (1) ACQUIRE load of producer_pos — see the barrier discipline note
        //     at the top of this file. Everything the kernel wrote before
        //     publishing this value is visible to us afterwards.
        const prod = @atomicLoad(u64, self.producerPosPtr(), .acquire);
        if (prod < self.consumer_pos) return error.InconsistentPositions;

        while (self.consumer_pos < prod) {
            // The ring's granule is 8 bytes; a position that is not aligned
            // cannot be a record boundary.
            if (self.consumer_pos % 8 != 0) return error.InconsistentPositions;
            if (prod - self.consumer_pos < BPF_RINGBUF_HDR_SZ) return error.CorruptRecord;

            const off: usize = @intCast(self.consumer_pos & self.mask);
            const hdr_ptr: *const u32 = @ptrCast(@alignCast(&self.data_pages[self.data_off + off]));
            // (2) ACQUIRE load of the record header — pairs with the kernel's
            //     release store that CLEARS the busy bit on commit, so a
            //     cleared bit implies the payload is visible too.
            const raw_len = @atomicLoad(u32, hdr_ptr, .acquire);

            // Still being written: stop here (do NOT skip forward — records
            // commit in ring order and the next one is not readable either).
            if (raw_len & BPF_RINGBUF_BUSY_BIT != 0) return null;

            const len = raw_len & BPF_RINGBUF_LEN_MASK;
            const stride = recordStride(len);
            // Untrusted framing: a record can neither exceed the ring nor
            // claim bytes the producer has not published.
            if (stride > self.ring_size) return error.CorruptRecord;
            if (stride > prod - self.consumer_pos) return error.CorruptRecord;

            if (raw_len & BPF_RINGBUF_DISCARD_BIT != 0) {
                // Release the discarded span immediately and keep walking.
                self.consumer_pos += stride;
                self.commitConsumerPos();
                continue;
            }

            self.pending = stride;
            const start = self.data_off + off + BPF_RINGBUF_HDR_SZ;
            // Safe by construction: `off < ring_size` and `len <= ring_size`,
            // and `data_pages` holds TWO copies of the ring after
            // `data_off` — so a record straddling the physical end is still
            // one contiguous slice. Asserted rather than assumed.
            std.debug.assert(start + len <= self.data_pages.len);
            return .{ .data = self.data_pages[start..][0..len] };
        }
        return null;
    }

    /// Release the space `next()`'s most recently returned record occupied
    /// back to the kernel. No-op if no record is being held.
    pub fn advance(self: *Reader) void {
        if (self.pending == 0) return;
        self.consumer_pos += self.pending;
        self.pending = 0;
        self.commitConsumerPos();
    }

    /// Non-blocking drain: walk every currently-committed record, handing
    /// each payload to `cb`, and return how many were consumed. Stops early
    /// on `Action.stop`, on an incomplete (busy) record, or after
    /// `max_records` — so a producer faster than this consumer cannot starve
    /// the caller's loop.
    pub fn consume(
        self: *Reader,
        ctx: ?*anyopaque,
        cb: SampleFn,
        max_records: usize,
    ) ConsumeError!usize {
        var n: usize = 0;
        while (n < max_records) {
            const rec = (try self.next()) orelse break;
            const action = cb(ctx, rec.data);
            self.advance();
            n += 1;
            if (action == .stop) break;
        }
        return n;
    }

    /// `poll` then `consume`: block up to `timeout_ms`, then drain whatever
    /// arrived. Returns the number of records handed to `cb` (0 on timeout).
    pub fn pollAndConsume(
        self: *Reader,
        timeout_ms: i32,
        ctx: ?*anyopaque,
        cb: SampleFn,
        max_records: usize,
    ) (PollError || ConsumeError)!usize {
        if (!try self.poll(timeout_ms)) return 0;
        return self.consume(ctx, cb, max_records);
    }

    // ── internals ───────────────────────────────────────────────────────────

    fn consumerPosPtr(self: *Reader) *u64 {
        return @ptrCast(@alignCast(self.cons_page.ptr));
    }

    fn producerPosPtr(self: *Reader) *const u64 {
        return @ptrCast(@alignCast(self.data_pages.ptr));
    }

    /// (3) RELEASE store of consumer_pos — must not be reordered before the
    /// reads of the record it releases, or the kernel could reuse that space
    /// while a `Record` slice still points into it.
    fn commitConsumerPos(self: *Reader) void {
        @atomicStore(u64, self.consumerPosPtr(), self.consumer_pos, .release);
    }
};

/// `mmap` one region of the ring buffer map.
fn mapPages(
    map_fd: linux.fd_t,
    len: usize,
    offset: i64,
    writable: bool,
) OpenError![]align(std.heap.page_size_min) u8 {
    const prot: linux.PROT = if (writable)
        .{ .READ = true, .WRITE = true }
    else
        .{ .READ = true };
    const rc = linux.mmap(null, len, prot, .{ .TYPE = .SHARED }, map_fd, offset);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.PermissionDenied,
        // The kernel rejects a writable mapping of anything but page 0, and
        // any mapping at all of a non-ringbuf map.
        .INVAL, .NODEV => return error.NotARingbufMap,
        .NOMEM, .AGAIN => return error.MmapFailed,
        else => return error.Unexpected,
    }
    const ptr: [*]align(std.heap.page_size_min) u8 = @ptrFromInt(rc);
    return ptr[0..len];
}

/// Register `map_fd` on a fresh epoll fd (level-triggered `EPOLLIN`).
fn openEpoll(map_fd: linux.fd_t) OpenError!linux.fd_t {
    const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.PermissionDenied,
        else => return error.EpollFailed,
    }
    const efd: linux.fd_t = @intCast(rc);
    errdefer _ = linux.close(efd);

    var ev: linux.epoll_event = .{ .events = linux.EPOLL.IN, .data = .{ .fd = map_fd } };
    switch (linux.errno(linux.epoll_ctl(efd, linux.EPOLL.CTL_ADD, map_fd, &ev))) {
        .SUCCESS => {},
        else => return error.EpollFailed,
    }
    return efd;
}

/// The prefix of `struct bpf_map_info` (`include/uapi/linux/bpf.h`) this
/// module needs. std defines `InfoAttr` (the syscall argument) but no
/// `bpf_map_info`, so the layout is declared here; the kernel copies
/// `min(info_len, sizeof(its own struct))` bytes, so declaring a prefix is
/// ABI-safe in both directions.
pub const MapInfo = extern struct {
    type: u32,
    id: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    name: [16]u8,
    ifindex: u32,
    btf_vmlinux_value_type_id: u32,
    netns_dev: u64,
    netns_ino: u64,
    btf_id: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    _pad: u32,
    map_extra: u64,
};

/// `bpf(BPF_OBJ_GET_INFO_BY_FD)` for a map fd — the wrapper std never grew
/// (it defines `Cmd.obj_get_info_by_fd` and `InfoAttr`, nothing more).
pub fn mapInfo(map_fd: linux.fd_t) OpenError!MapInfo {
    var info: MapInfo = std.mem.zeroes(MapInfo);
    var attr: BPF.Attr = .{ .info = .{
        .bpf_fd = map_fd,
        .info_len = @sizeOf(MapInfo),
        .info = @intFromPtr(&info),
    } };
    const rc = linux.bpf(.obj_get_info_by_fd, &attr, @sizeOf(BPF.InfoAttr));
    switch (linux.errno(rc)) {
        .SUCCESS => return info,
        .ACCES, .PERM => return error.PermissionDenied,
        .BADF, .INVAL => return error.NotARingbufMap,
        else => return error.Unexpected,
    }
}

// ── tests ────────────────────────────────────────────────────────────────────
//
// Two layers, per this module's SPEC.md:
//  1. UNPRIVILEGED, always run: a hand-built in-memory FAKE RING driving the
//     real `Reader` consumer — multi-record walks, wrap-around, discard,
//     busy-skip, truncated/hostile headers, and the barrier-ordered position
//     updates, all without a kernel. This is the backbone of this file's
//     coverage: everything except the mmap/epoll syscalls themselves is
//     exercised here.
//  2. PRIVILEGED, gracefully skipped: a real `BPF_MAP_TYPE_RINGBUF` map,
//     mmap'd and consumed end-to-end. Prints a SKIPPED line and PASSES when
//     CAP_BPF is missing.

const testing = std.testing;

fn hasBpfCapability() bool {
    return linux.geteuid() == 0;
}

/// An in-memory stand-in for the kernel side of a ring buffer: the same three
/// regions at the same offsets, with the same double mapping of the data area
/// (emulated by mirroring every write into the second copy, which is exactly
/// what the kernel's aliased page array does for real).
const FakeRing = struct {
    gpa: std.mem.Allocator,
    ring_size: usize,
    page: usize,
    cons: []align(std.heap.page_size_min) u8,
    data: []align(std.heap.page_size_min) u8,
    producer_pos: u64 = 0,

    const alignment: std.mem.Alignment = .fromByteUnits(std.heap.page_size_min);

    fn init(gpa: std.mem.Allocator, ring_size: usize) !FakeRing {
        std.debug.assert(std.math.isPowerOfTwo(ring_size));
        const page = std.heap.page_size_min;
        const cons = try gpa.alignedAlloc(u8, alignment, page);
        errdefer gpa.free(cons);
        const data = try gpa.alignedAlloc(u8, alignment, page + 2 * ring_size);
        @memset(cons, 0);
        @memset(data, 0);
        return .{ .gpa = gpa, .ring_size = ring_size, .page = page, .cons = cons, .data = data };
    }

    fn deinit(self: *FakeRing) void {
        self.gpa.free(self.cons);
        self.gpa.free(self.data);
        self.* = undefined;
    }

    fn reader(self: *FakeRing) Reader {
        return .{
            .map_fd = -1,
            .cons_page = self.cons,
            .data_pages = self.data,
            .data_off = self.page,
            .ring_size = self.ring_size,
            .mask = self.ring_size - 1,
            .consumer_pos = 0,
            .pending = 0,
            .epoll_fd = -1,
            .owns_mappings = false,
        };
    }

    /// Write one byte into the ring at a logical position, mirroring it into
    /// the second copy of the data area (the kernel's aliasing).
    fn pokeByte(self: *FakeRing, pos: u64, byte: u8) void {
        const off: usize = @intCast(pos & (self.ring_size - 1));
        self.data[self.page + off] = byte;
        self.data[self.page + self.ring_size + off] = byte;
    }

    fn pokeU32(self: *FakeRing, pos: u64, value: u32) void {
        var raw: [4]u8 = undefined;
        std.mem.writeInt(u32, &raw, value, native_endian);
        for (raw, 0..) |b, i| self.pokeByte(pos + i, b);
    }

    /// Append a record. `flags` may carry BUSY and/or DISCARD.
    fn append(self: *FakeRing, payload: []const u8, flags: u32) void {
        const pos = self.producer_pos;
        self.pokeU32(pos, @as(u32, @intCast(payload.len)) | flags);
        self.pokeU32(pos + 4, 0); // pg_off, unused by the consumer
        for (payload, 0..) |b, i| self.pokeByte(pos + BPF_RINGBUF_HDR_SZ + i, b);
        self.producer_pos = pos + recordStride(@intCast(payload.len));
        self.publish();
    }

    /// Reserve a still-BUSY record (the kernel state between
    /// `bpf_ringbuf_reserve` and `bpf_ringbuf_submit`) and return the
    /// position of its header so a later `commit` can clear the bit.
    fn reserve(self: *FakeRing, len: usize) u64 {
        const pos = self.producer_pos;
        self.pokeU32(pos, @as(u32, @intCast(len)) | BPF_RINGBUF_BUSY_BIT);
        self.pokeU32(pos + 4, 0);
        self.producer_pos = pos + recordStride(@intCast(len));
        self.publish();
        return pos;
    }

    fn commit(self: *FakeRing, hdr_pos: u64, payload: []const u8) void {
        for (payload, 0..) |b, i| self.pokeByte(hdr_pos + BPF_RINGBUF_HDR_SZ + i, b);
        // Clearing BUSY is what the kernel does with a release store; the
        // consumer's acquire load of the header pairs with it.
        const hdr_off: usize = @intCast(hdr_pos & (self.ring_size - 1));
        const p: *u32 = @ptrCast(@alignCast(&self.data[self.page + hdr_off]));
        @atomicStore(u32, p, @intCast(payload.len), .release);
        const mirror: *u32 = @ptrCast(@alignCast(&self.data[self.page + self.ring_size + hdr_off]));
        @atomicStore(u32, mirror, @intCast(payload.len), .release);
    }

    /// Publish `producer_pos` the way the kernel does — release store.
    fn publish(self: *FakeRing) void {
        const p: *u64 = @ptrCast(@alignCast(self.data.ptr));
        @atomicStore(u64, p, self.producer_pos, .release);
    }

    /// The consumer position as the kernel would see it (acquire load of the
    /// consumer page), i.e. what actually got released back.
    fn kernelVisibleConsumerPos(self: *FakeRing) u64 {
        const p: *const u64 = @ptrCast(@alignCast(self.cons.ptr));
        return @atomicLoad(u64, p, .acquire);
    }
};

const Collector = struct {
    buf: [64][32]u8 = undefined,
    lens: [64]usize = @splat(0),
    n: usize = 0,
    stop_after: usize = std.math.maxInt(usize),

    fn cb(ctx: ?*anyopaque, data: []const u8) Action {
        const self: *Collector = @ptrCast(@alignCast(ctx.?));
        if (self.n < self.buf.len and data.len <= self.buf[0].len) {
            @memcpy(self.buf[self.n][0..data.len], data);
            self.lens[self.n] = data.len;
        }
        self.n += 1;
        return if (self.n >= self.stop_after) .stop else .proceed;
    }

    fn item(self: *const Collector, i: usize) []const u8 {
        return self.buf[i][0..self.lens[i]];
    }
};

test "recordStride rounds header+payload up to the 8-byte granule" {
    try testing.expectEqual(@as(usize, 8), recordStride(0));
    try testing.expectEqual(@as(usize, 16), recordStride(1));
    try testing.expectEqual(@as(usize, 16), recordStride(8));
    try testing.expectEqual(@as(usize, 24), recordStride(9));
    try testing.expectEqual(@as(usize, 24), recordStride(16));
    // Flag bits are the caller's job to mask before calling.
    try testing.expectEqual(@as(u32, 5), 5 & BPF_RINGBUF_LEN_MASK);
    try testing.expectEqual(@as(u32, 5), (5 | BPF_RINGBUF_BUSY_BIT) & BPF_RINGBUF_LEN_MASK);
    try testing.expectEqual(@as(u32, 5), (5 | BPF_RINGBUF_DISCARD_BIT) & BPF_RINGBUF_LEN_MASK);
}

test "fake ring: multi-record walk, payloads and position arithmetic" {
    var ring = try FakeRing.init(testing.allocator, 4096);
    defer ring.deinit();

    ring.append("alpha", 0); // stride 16
    ring.append("bb", 0); // stride 16
    ring.append("0123456789abcdef", 0); // stride 24

    var rb = ring.reader();
    try testing.expect(rb.available());

    const r1 = (try rb.next()).?;
    try testing.expectEqualStrings("alpha", r1.data);
    // next() is idempotent until advance().
    const again = (try rb.next()).?;
    try testing.expectEqualStrings("alpha", again.data);
    try testing.expectEqual(@as(u64, 0), ring.kernelVisibleConsumerPos());
    rb.advance();
    try testing.expectEqual(@as(u64, 16), ring.kernelVisibleConsumerPos());

    const r2 = (try rb.next()).?;
    try testing.expectEqualStrings("bb", r2.data);
    rb.advance();
    try testing.expectEqual(@as(u64, 32), ring.kernelVisibleConsumerPos());

    const r3 = (try rb.next()).?;
    try testing.expectEqualStrings("0123456789abcdef", r3.data);
    rb.advance();
    try testing.expectEqual(@as(u64, 56), ring.kernelVisibleConsumerPos());
    try testing.expectEqual(ring.producer_pos, ring.kernelVisibleConsumerPos());

    try testing.expect(!rb.available());
    try testing.expectEqual(@as(?Record, null), try rb.next());
    // advance() with nothing held must not move anything.
    rb.advance();
    try testing.expectEqual(@as(u64, 56), ring.kernelVisibleConsumerPos());
}

test "fake ring: BUSY record stops the walk and resumes after commit" {
    var ring = try FakeRing.init(testing.allocator, 4096);
    defer ring.deinit();

    ring.append("first", 0);
    const busy_at = ring.reserve(4); // reserved, not yet submitted
    ring.append("third", 0); // committed, but BEHIND the busy one in ring order

    var rb = ring.reader();
    const r1 = (try rb.next()).?;
    try testing.expectEqualStrings("first", r1.data);
    rb.advance();

    // The busy record blocks the walk: records commit in ring order, so
    // "third" must NOT be surfaced early even though its own bit is clear.
    try testing.expectEqual(@as(?Record, null), try rb.next());
    // available() still reports true — the producer IS ahead; only the
    // record walk knows the next one is not readable yet.
    try testing.expect(rb.available());
    try testing.expectEqual(@as(u64, 16), ring.kernelVisibleConsumerPos());

    ring.commit(busy_at, "wxyz");
    const r2 = (try rb.next()).?;
    try testing.expectEqualStrings("wxyz", r2.data);
    rb.advance();
    const r3 = (try rb.next()).?;
    try testing.expectEqualStrings("third", r3.data);
    rb.advance();
    try testing.expectEqual(@as(?Record, null), try rb.next());
}

test "fake ring: DISCARD records are skipped, never surfaced" {
    var ring = try FakeRing.init(testing.allocator, 4096);
    defer ring.deinit();

    ring.append("keep-1", 0);
    ring.append("dropped-payload", BPF_RINGBUF_DISCARD_BIT);
    ring.append("dropped-2", BPF_RINGBUF_DISCARD_BIT);
    ring.append("keep-2", 0);

    var rb = ring.reader();
    var col: Collector = .{};
    const n = try rb.consume(&col, Collector.cb, 16);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqual(@as(usize, 2), col.n);
    try testing.expectEqualStrings("keep-1", col.item(0));
    try testing.expectEqualStrings("keep-2", col.item(1));
    // Every byte, discarded ones included, was released back to the kernel.
    try testing.expectEqual(ring.producer_pos, ring.kernelVisibleConsumerPos());
}

test "fake ring: a record straddling the ring end reads as one contiguous slice" {
    // 64-byte ring: fill it to just short of the end, then write a record
    // whose payload physically wraps.
    var ring = try FakeRing.init(testing.allocator, 64);
    defer ring.deinit();

    var rb = ring.reader();
    var col: Collector = .{};

    // Three 16-byte-stride records take the position to 48/64.
    ring.append("aaaaaaaa", 0);
    ring.append("bbbbbbbb", 0);
    ring.append("cccccccc", 0);
    try testing.expectEqual(@as(usize, 3), try rb.consume(&col, Collector.cb, 16));
    try testing.expectEqual(@as(u64, 48), ring.kernelVisibleConsumerPos());

    // A 24-byte-stride record at offset 48 occupies [48, 72) — bytes 64..72
    // land in the SECOND copy of the data area.
    const wrapping = "0123456789abcdef";
    ring.append(wrapping, 0);
    try testing.expectEqual(@as(u64, 72), ring.producer_pos);

    const rec = (try rb.next()).?;
    try testing.expectEqualStrings(wrapping, rec.data);
    // Proof it really came from the wrap: the slice starts inside the first
    // copy and ends inside the second.
    const base = @intFromPtr(ring.data.ptr) + ring.page;
    try testing.expect(@intFromPtr(rec.data.ptr) < base + ring.ring_size);
    try testing.expect(@intFromPtr(rec.data.ptr) + rec.data.len > base + ring.ring_size);
    rb.advance();
    try testing.expectEqual(@as(u64, 72), ring.kernelVisibleConsumerPos());

    // And the walk keeps working past the wrap.
    ring.append("after-wrap", 0);
    const post = (try rb.next()).?;
    try testing.expectEqualStrings("after-wrap", post.data);
    rb.advance();
    try testing.expectEqual(ring.producer_pos, ring.kernelVisibleConsumerPos());
}

test "fake ring: hostile record headers are typed errors, never panics" {
    // (a) A length larger than the whole ring.
    {
        var ring = try FakeRing.init(testing.allocator, 4096);
        defer ring.deinit();
        ring.pokeU32(0, 100_000);
        ring.pokeU32(4, 0);
        ring.producer_pos = 4096;
        ring.publish();
        var rb = ring.reader();
        try testing.expectError(error.CorruptRecord, rb.next());
    }
    // (b) A length that runs past producer_pos (a truncated record: the
    //     header claims more bytes than were ever published).
    {
        var ring = try FakeRing.init(testing.allocator, 4096);
        defer ring.deinit();
        ring.pokeU32(0, 512);
        ring.pokeU32(4, 0);
        ring.producer_pos = 16; // only 16 bytes published, header claims 520
        ring.publish();
        var rb = ring.reader();
        try testing.expectError(error.CorruptRecord, rb.next());
    }
    // (c) A producer position that does not even cover a header.
    {
        var ring = try FakeRing.init(testing.allocator, 4096);
        defer ring.deinit();
        ring.producer_pos = 4; // less than BPF_RINGBUF_HDR_SZ
        ring.publish();
        var rb = ring.reader();
        try testing.expectError(error.CorruptRecord, rb.next());
    }
    // (d) producer_pos behind consumer_pos.
    {
        var ring = try FakeRing.init(testing.allocator, 4096);
        defer ring.deinit();
        ring.append("x", 0);
        var rb = ring.reader();
        rb.consumer_pos = 64; // pretend we consumed further than published
        try testing.expectError(error.InconsistentPositions, rb.next());
    }
    // (e) A consumer position off the 8-byte granule.
    {
        var ring = try FakeRing.init(testing.allocator, 4096);
        defer ring.deinit();
        ring.append("x", 0);
        var rb = ring.reader();
        rb.consumer_pos = 3;
        try testing.expectError(error.InconsistentPositions, rb.next());
    }
    // (f) A DISCARD record with a hostile length must be rejected, not
    //     skipped by an unchecked amount.
    {
        var ring = try FakeRing.init(testing.allocator, 4096);
        defer ring.deinit();
        ring.pokeU32(0, 100_000 | BPF_RINGBUF_DISCARD_BIT);
        ring.pokeU32(4, 0);
        ring.producer_pos = 4096;
        ring.publish();
        var rb = ring.reader();
        try testing.expectError(error.CorruptRecord, rb.next());
    }
}

test "fake ring: a zero-length record is legal and yields an empty payload" {
    var ring = try FakeRing.init(testing.allocator, 4096);
    defer ring.deinit();
    ring.append("", 0);
    ring.append("tail", 0);

    var rb = ring.reader();
    const empty = (try rb.next()).?;
    try testing.expectEqual(@as(usize, 0), empty.data.len);
    rb.advance();
    try testing.expectEqual(@as(u64, 8), ring.kernelVisibleConsumerPos());
    const tail = (try rb.next()).?;
    try testing.expectEqualStrings("tail", tail.data);
    rb.advance();
}

test "fake ring: consume() honors max_records and the stop action" {
    var ring = try FakeRing.init(testing.allocator, 4096);
    defer ring.deinit();
    for (0..8) |i| {
        var buf: [8]u8 = undefined;
        const s = try std.fmt.bufPrint(&buf, "rec-{d}", .{i});
        ring.append(s, 0);
    }

    var rb = ring.reader();

    var col: Collector = .{};
    try testing.expectEqual(@as(usize, 3), try rb.consume(&col, Collector.cb, 3));
    try testing.expectEqualStrings("rec-0", col.item(0));
    try testing.expectEqualStrings("rec-2", col.item(2));
    // Exactly three records' worth of space was released.
    try testing.expectEqual(@as(u64, 48), ring.kernelVisibleConsumerPos());

    // A callback asking to stop still releases the record it just saw.
    var col2: Collector = .{ .stop_after = 2 };
    try testing.expectEqual(@as(usize, 2), try rb.consume(&col2, Collector.cb, 16));
    try testing.expectEqualStrings("rec-3", col2.item(0));
    try testing.expectEqual(@as(u64, 80), ring.kernelVisibleConsumerPos());

    // The rest drains normally.
    var col3: Collector = .{};
    try testing.expectEqual(@as(usize, 3), try rb.consume(&col3, Collector.cb, 16));
    try testing.expectEqual(ring.producer_pos, ring.kernelVisibleConsumerPos());
}

test "fake ring: a reader adopts the consumer position already on the page" {
    var ring = try FakeRing.init(testing.allocator, 4096);
    defer ring.deinit();
    ring.append("one", 0);
    ring.append("two", 0);

    var rb = ring.reader();
    const first = (try rb.next()).?;
    try testing.expectEqualStrings("one", first.data);
    rb.advance();

    // A second reader starting from the page's position (what
    // openWithRingSize does) must resume, not replay.
    var rb2 = ring.reader();
    rb2.consumer_pos = ring.kernelVisibleConsumerPos();
    const second = (try rb2.next()).?;
    try testing.expectEqualStrings("two", second.data);
    rb2.advance();
    try testing.expectEqual(ring.producer_pos, ring.kernelVisibleConsumerPos());
}

test "poll() on a non-pollable (hand-built) reader is a typed error" {
    var ring = try FakeRing.init(testing.allocator, 4096);
    defer ring.deinit();
    var rb = ring.reader();
    // Empty ring + no epoll fd.
    try testing.expectError(error.NotPollable, rb.poll(0));
    // With data pending, poll() short-circuits before touching epoll.
    ring.append("x", 0);
    try testing.expect(try rb.poll(0));
}

test "MapInfo mirrors the kernel's bpf_map_info prefix layout" {
    try testing.expectEqual(@as(usize, 0), @offsetOf(MapInfo, "type"));
    try testing.expectEqual(@as(usize, 8), @offsetOf(MapInfo, "key_size"));
    try testing.expectEqual(@as(usize, 16), @offsetOf(MapInfo, "max_entries"));
    try testing.expectEqual(@as(usize, 24), @offsetOf(MapInfo, "name"));
    try testing.expectEqual(@as(usize, 40), @offsetOf(MapInfo, "ifindex"));
    try testing.expectEqual(@as(usize, 48), @offsetOf(MapInfo, "netns_dev"));
    try testing.expectEqual(@as(usize, 80), @offsetOf(MapInfo, "map_extra"));
    try testing.expectEqual(@as(usize, 88), @sizeOf(MapInfo));
}

test "LIVE: mmap a real ringbuf map and consume a record end-to-end" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!hasBpfCapability()) {
        if (verboseSkip()) std.debug.print(
            "\nLIVE ebpf ringbuf test SKIPPED: needs CAP_BPF (running as uid {d}).\n",
            .{linux.geteuid()},
        );
        return;
    }

    const page = std.heap.pageSize();
    // max_entries must be a power of two AND a multiple of the page size.
    const ring_size: u32 = @intCast(page * 4);

    const map_fd = BPF.map_create(.ringbuf, 0, 0, ring_size) catch {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf ringbuf test SKIPPED: BPF_MAP_CREATE(.ringbuf) refused.\n", .{});
        return;
    };
    defer _ = linux.close(map_fd);

    var rb = Reader.open(map_fd) catch |e| {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf ringbuf test SKIPPED: mmap of the ringbuf map failed ({s}).\n", .{@errorName(e)});
        return;
    };
    defer rb.close();

    // The mapping itself is already a real assertion: the kernel only grants
    // these exact offsets/lengths/protections for a ringbuf map.
    try testing.expectEqual(@as(usize, ring_size), rb.ring_size);
    try testing.expectEqual(page, rb.data_off);
    try testing.expectEqual(page + 2 * @as(usize, ring_size), rb.data_pages.len);
    try testing.expect(!rb.available());
    try testing.expectEqual(@as(?Record, null), try rb.next());
    // Nothing to read: epoll must time out rather than report data.
    try testing.expect(!try rb.poll(0));

    // Now drive a real producer: a ringbuf-emit program on a kprobe.
    const programs = @import("programs.zig");
    const attach = @import("attach.zig");
    const load = @import("load.zig").load;

    const record_size: u32 = 16;
    const insns = programs.ringbufEmit(.{
        .ringbuf_map_fd = map_fd,
        .record_size = record_size,
    }) catch {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf ringbuf test SKIPPED: ringbufEmit builder rejected the options.\n", .{});
        return;
    };
    const prog_fd = load(.{ .prog_type = .kprobe, .insns = insns }, "MIT") catch {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf ringbuf test SKIPPED: BPF_PROG_LOAD refused the ringbuf-emit program.\n", .{});
        return;
    };
    defer _ = linux.close(prog_fd);

    const candidates = [_][]const u8{ "do_sys_openat2", "vfs_read", "do_sys_open" };
    var handle: ?attach.KprobeHandle = null;
    for (candidates) |sym| {
        handle = attach.attachKprobe(testing.allocator, sym, prog_fd) catch continue;
        break;
    }
    var kp = handle orelse {
        if (verboseSkip()) std.debug.print("\nLIVE ebpf ringbuf test SKIPPED: no probeable symbol among the candidates.\n", .{});
        return;
    };
    defer kp.detach();

    // Trigger the probe.
    for (0..8) |_| {
        const fd = linux.open("/proc/self/status", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (linux.errno(fd) == .SUCCESS) _ = linux.close(@intCast(fd));
    }

    var col: Collector = .{};
    const n = try rb.pollAndConsume(1000, &col, Collector.cb, 16);
    try testing.expect(n > 0);
    try testing.expectEqual(@as(usize, record_size), col.lens[0]);
    // The consumer position must have been released back to the kernel.
    const cons: *const u64 = @ptrCast(@alignCast(rb.cons_page.ptr));
    try testing.expectEqual(rb.consumer_pos, @atomicLoad(u64, cons, .acquire));
    try testing.expect(rb.consumer_pos >= n * recordStride(record_size));
}
