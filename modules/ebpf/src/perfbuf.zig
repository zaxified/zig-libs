// SPDX-License-Identifier: MIT
//! Perf-buffer consumer — the userspace side of
//! `BPF_MAP_TYPE_PERF_EVENT_ARRAY`, the per-CPU event channel that predates
//! `BPF_MAP_TYPE_RINGBUF` and is still the only option on kernels older than
//! 5.8 (and still the right one when per-CPU ordering/attribution matters).
//!
//! It is **not** a variation on `ringbuf.zig`; three things differ, and each
//! one is a place a naive port of the ringbuf consumer breaks:
//!
//! | | `ringbuf.zig` (`BPF_MAP_TYPE_RINGBUF`) | this file (`PERF_EVENT_ARRAY`) |
//! |---|---|---|
//! | rings | ONE, shared by all CPUs (MPSC) | ONE PER CPU, each with its own perf fd |
//! | wrap | the kernel **double-maps** the data pages, so a wrapping record is contiguous | **no** double mapping — a wrapping record must be reassembled by hand |
//! | commit | per-record `BUSY` bit in the record header | none: `data_head` alone publishes the record |
//! | loss | impossible (a full ring fails the reservation in-program) | `PERF_RECORD_LOST` records, which MUST be surfaced |
//!
//! ## mmap layout (`kernel/events/core.c`, `perf_mmap`)
//!
//! ```text
//! page 0        | control page (`struct perf_event_mmap_page`),
//!               | PROT_READ|PROT_WRITE. [1024..1032) = data_head (kernel
//!               | writes), [1032..1040) = data_tail (this side writes).
//! page 1..1+2^n | the data area, `2^n` pages, power-of-two BYTES.
//! ```
//!
//! One mmap of `(1 + 2^n) * page_size` at offset 0 covers both. `PROT_WRITE`
//! is required even though only `data_tail` is written by userspace.
//!
//! ## Barrier discipline
//!
//! The same two-sided contract `ringbuf.zig` documents, minus the per-record
//! step (there is no commit flag here):
//!
//! 1. **`data_head`: acquire load.** Pairs with the kernel's
//!    `smp_store_release(&rb->user_page->data_head, head)` at the end of
//!    `perf_output_end`. Because the release store happens *after* the whole
//!    record is written, one acquire load of `data_head` orders EVERY byte
//!    below it — which is exactly why no per-record acquire is needed here
//!    and one is needed in the ring buffer.
//! 2. **`data_tail`: release store.** Pairs with the kernel's
//!    `smp_load_acquire(&rb->user_page->data_tail)` in
//!    `perf_output_begin`. It must not become visible before this side has
//!    finished *reading* the record, or the kernel may overwrite bytes a
//!    caller still holds a slice into.
//!
//! ## Lost events
//!
//! When a CPU's ring is full the kernel drops the sample and (once space
//! frees up) emits a `PERF_RECORD_LOST` carrying the number dropped. Those
//! are surfaced to the caller as `Event.lost` and accumulated in
//! `Reader.lost_records`; they are **never** silently skipped, because "my
//! numbers are slightly wrong" is the failure mode a tracing tool most needs
//! to know about and least often notices.
//!
//! ## Untrusted framing
//!
//! Every header field is kernel-supplied and treated as untrusted: a zero,
//! misaligned or oversized record size, a `PERF_RECORD_SAMPLE` whose raw
//! length runs past its own record, or positions that move backwards are all
//! typed `ConsumeError`s — never a panic, never an out-of-bounds read.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const BPF = linux.BPF;
const attach = @import("attach.zig");

const native_endian = builtin.cpu.arch.endian();

// ── wire constants (include/uapi/linux/perf_event.h) ────────────────────────

/// `sizeof(struct perf_event_header)` — u32 type, u16 misc, u16 size.
pub const PERF_EVENT_HDR_SZ: usize = 8;

/// Byte offset of `data_head` inside `struct perf_event_mmap_page`. The
/// struct pads itself "to 1k" precisely so these two fields sit on their own
/// cache lines; asserted against std's struct in this file's tests.
pub const DATA_HEAD_OFF: usize = 1024;
/// Byte offset of `data_tail`.
pub const DATA_TAIL_OFF: usize = 1032;

/// `PERF_RECORD_SAMPLE` — the record `bpf_perf_event_output` produces.
pub const PERF_RECORD_SAMPLE: u32 = @intFromEnum(linux.PERF.RECORD.SAMPLE);
/// `PERF_RECORD_LOST` — samples the kernel had to drop.
pub const PERF_RECORD_LOST: u32 = @intFromEnum(linux.PERF.RECORD.LOST);

/// `PERF_COUNT_SW_BPF_OUTPUT` — the software event
/// `bpf_perf_event_output` writes into.
pub const PERF_COUNT_SW_BPF_OUTPUT: u64 = @intFromEnum(linux.PERF.COUNT.SW.BPF_OUTPUT);

// ── errors ──────────────────────────────────────────────────────────────────

pub const OpenError = error{
    /// `map_fd` is not a `BPF_MAP_TYPE_PERF_EVENT_ARRAY`.
    NotAPerfEventArray,
    /// `pages` is zero or not a power of two.
    InvalidPageCount,
    /// Could not enumerate the machine's CPUs (`/sys/devices/system/cpu/…`).
    CpuEnumerationFailed,
    PerfEventOpenFailed,
    MmapFailed,
    EpollFailed,
    MapUpdateFailed,
    PermissionDenied,
    OutOfMemory,
    Unexpected,
};

pub const PollError = error{
    /// No epoll fd on this consumer (a hand-built one, e.g. in tests).
    NotPollable,
    EpollFailed,
    Unexpected,
};

/// Failures decoding kernel-supplied record framing. None of these can be
/// produced by a well-behaved kernel plus a well-behaved consumer.
pub const ConsumeError = error{
    /// A record header declares a size that is zero, not a multiple of 8,
    /// larger than the ring, or larger than what the producer published; or
    /// a `PERF_RECORD_SAMPLE`/`_LOST` body too short for its own fields.
    CorruptRecord,
    /// `data_head` is behind `data_tail`, or `data_tail` is off the 8-byte
    /// granule.
    InconsistentPositions,
    /// A record that wraps the ring end is larger than the reassembly buffer
    /// this reader was given. Only reachable with an under-sized scratch
    /// buffer; `PerfBuffer` always sizes it to the ring.
    RecordTooLarge,
};

/// What a callback wants the consume loop to do next.
pub const Action = enum { proceed, stop };

/// One decoded record.
pub const Event = union(enum) {
    /// A `PERF_RECORD_SAMPLE` payload. Borrows either the mmap'd ring or the
    /// reader's reassembly buffer — invalid as soon as the next
    /// `next()`/`advance()` call happens.
    ///
    /// NOTE: the length is the kernel's, which rounds the program's
    /// `bpf_perf_event_output` size up so that `4 + len` is a multiple of 8.
    /// A payload may therefore carry up to 4 bytes of trailing zero padding
    /// — same as what libbpf hands its `sample_cb`.
    sample: []const u8,
    /// A `PERF_RECORD_LOST`: this many samples were dropped because the
    /// CPU's ring was full.
    lost: u64,
};

/// Per-sample callback.
pub const SampleFn = *const fn (ctx: ?*anyopaque, cpu: u32, data: []const u8) Action;
/// Per-`PERF_RECORD_LOST` callback. Optional at the `PerfBuffer` level, but
/// losses are always counted even without one.
pub const LostFn = *const fn (ctx: ?*anyopaque, cpu: u32, lost: u64) Action;

// ── one CPU's ring ──────────────────────────────────────────────────────────

/// A consumer for ONE CPU's perf ring. Single-owner, exactly like
/// `ringbuf.Reader`: the mmap'd positions are not internally synchronized.
///
/// Constructible by hand (that is what the in-memory tests do) — every field
/// is public and `owns_mapping = false` keeps `close()` from unmapping
/// memory it did not create.
pub const Reader = struct {
    /// Which CPU this ring belongs to; passed through to callbacks.
    cpu: u32,
    /// The perf event fd. `-1` for a hand-built reader.
    perf_fd: linux.fd_t,
    /// The whole mapping: control page followed by the data area.
    base: []align(std.heap.page_size_min) u8,
    /// Byte offset of the data area inside `base` (one page).
    data_off: usize,
    /// Data-area size in bytes. Always a power of two.
    size: usize,
    /// `size - 1`, the offset mask.
    mask: usize,
    /// Cached `data_tail`. Only this side writes it.
    tail: u64,
    /// Bytes `advance()` will release; 0 when no record is held.
    pending: usize,
    /// Borrowed reassembly buffer for records that wrap the ring end. Must
    /// be at least as large as the biggest record that can occur; sizing it
    /// to `size` makes `RecordTooLarge` unreachable.
    scratch: []u8,
    /// False when `base`/`scratch` are caller-owned (test rings).
    owns_mapping: bool,
    /// Running total of samples the kernel reported dropping.
    lost_records: u64 = 0,
    /// Records whose `type` this consumer does not decode (e.g.
    /// `PERF_RECORD_THROTTLE`). Skipped, but counted rather than ignored.
    unknown_records: u64 = 0,

    /// The kernel's `data_head` (ACQUIRE — see the barrier note at the top).
    pub fn head(self: *const Reader) u64 {
        return @atomicLoad(u64, self.headPtr(), .acquire);
    }

    /// True when the producer is ahead of this consumer.
    pub fn available(self: *const Reader) bool {
        return self.head() > self.tail;
    }

    /// Decode the next record, or `null` when caught up. Unknown record
    /// types are consumed internally and never surface. Call `advance()`
    /// after handling the returned event.
    ///
    /// Idempotent between `advance()` calls (nothing moves `data_tail`).
    pub fn next(self: *Reader) ConsumeError!?Event {
        const h = self.head();
        if (h < self.tail) return error.InconsistentPositions;

        while (self.tail < h) {
            if (self.tail % 8 != 0) return error.InconsistentPositions;
            if (h - self.tail < PERF_EVENT_HDR_SZ) return error.CorruptRecord;

            var hdr: [PERF_EVENT_HDR_SZ]u8 = undefined;
            self.copyOut(self.tail, &hdr);
            const rec_type = std.mem.readInt(u32, hdr[0..4], native_endian);
            const rec_size: usize = std.mem.readInt(u16, hdr[6..8], native_endian);

            // Untrusted framing. Perf records are always a multiple of 8
            // bytes and never exceed the ring or the published head.
            if (rec_size < PERF_EVENT_HDR_SZ) return error.CorruptRecord;
            if (rec_size % 8 != 0) return error.CorruptRecord;
            if (rec_size > self.size) return error.CorruptRecord;
            if (rec_size > h - self.tail) return error.CorruptRecord;

            switch (rec_type) {
                PERF_RECORD_SAMPLE => {
                    // struct { header; u32 size; char data[size]; }
                    if (rec_size < PERF_EVENT_HDR_SZ + 4) return error.CorruptRecord;
                    var raw: [4]u8 = undefined;
                    self.copyOut(self.tail + PERF_EVENT_HDR_SZ, &raw);
                    const raw_len: usize = std.mem.readInt(u32, &raw, native_endian);
                    if (raw_len > rec_size - PERF_EVENT_HDR_SZ - 4) return error.CorruptRecord;
                    const at = self.tail + PERF_EVENT_HDR_SZ + 4;
                    const data = try self.view(at, raw_len);
                    self.pending = rec_size;
                    return .{ .sample = data };
                },
                PERF_RECORD_LOST => {
                    // struct { header; u64 id; u64 lost; }
                    if (rec_size < PERF_EVENT_HDR_SZ + 16) return error.CorruptRecord;
                    var body: [8]u8 = undefined;
                    self.copyOut(self.tail + PERF_EVENT_HDR_SZ + 8, &body);
                    const lost = std.mem.readInt(u64, &body, native_endian);
                    self.lost_records +|= lost;
                    self.pending = rec_size;
                    return .{ .lost = lost };
                },
                else => {
                    // Not ours to interpret — release the space and keep
                    // walking, but count it so "why is my stream odd" has an
                    // answer.
                    self.unknown_records +|= 1;
                    self.tail += rec_size;
                    self.commitTail();
                },
            }
        }
        return null;
    }

    /// Release the space the most recent `next()` record occupied. No-op if
    /// nothing is held.
    pub fn advance(self: *Reader) void {
        if (self.pending == 0) return;
        self.tail += self.pending;
        self.pending = 0;
        self.commitTail();
    }

    /// Non-blocking drain of this one ring. `on_lost` may be null; losses
    /// are still counted in `lost_records`.
    pub fn consume(
        self: *Reader,
        ctx: ?*anyopaque,
        on_sample: SampleFn,
        on_lost: ?LostFn,
        max_records: usize,
    ) ConsumeError!usize {
        var n: usize = 0;
        while (n < max_records) {
            const ev = (try self.next()) orelse break;
            const action: Action = switch (ev) {
                .sample => |d| on_sample(ctx, self.cpu, d),
                .lost => |l| if (on_lost) |cb| cb(ctx, self.cpu, l) else .proceed,
            };
            self.advance();
            n += 1;
            if (action == .stop) break;
        }
        return n;
    }

    /// Unmap (when owned) and close the perf fd.
    pub fn close(self: *Reader) void {
        if (self.owns_mapping) _ = linux.munmap(self.base.ptr, self.base.len);
        if (self.perf_fd >= 0) {
            _ = linux.ioctl(self.perf_fd, attach.PERF_EVENT_IOC.DISABLE, 0);
            _ = linux.close(self.perf_fd);
        }
        self.perf_fd = -1;
        self.owns_mapping = false;
    }

    // ── internals ───────────────────────────────────────────────────────────

    fn headPtr(self: *const Reader) *const u64 {
        return @ptrCast(@alignCast(&self.base[DATA_HEAD_OFF]));
    }

    fn tailPtr(self: *Reader) *u64 {
        return @ptrCast(@alignCast(&self.base[DATA_TAIL_OFF]));
    }

    /// RELEASE store of `data_tail` — must not be reordered before the reads
    /// of the record it releases.
    fn commitTail(self: *Reader) void {
        @atomicStore(u64, self.tailPtr(), self.tail, .release);
    }

    fn dataConst(self: *const Reader) []const u8 {
        return self.base[self.data_off..][0..self.size];
    }

    /// Copy `out.len` bytes starting at logical position `pos`, wrapping the
    /// ring end. Used for the small fixed-size headers, where a straddling
    /// read is entirely possible (the header itself can be split).
    fn copyOut(self: *const Reader, pos: u64, out: []u8) void {
        const off: usize = @intCast(pos & self.mask);
        const d = self.dataConst();
        const first = @min(out.len, self.size - off);
        @memcpy(out[0..first], d[off..][0..first]);
        if (first < out.len) @memcpy(out[first..], d[0 .. out.len - first]);
    }

    /// A borrowed view of `len` bytes at logical position `pos`: the mmap'd
    /// bytes directly when contiguous, or the reassembly buffer when the
    /// range straddles the ring end.
    fn view(self: *Reader, pos: u64, len: usize) ConsumeError![]const u8 {
        const off: usize = @intCast(pos & self.mask);
        if (off + len <= self.size) return self.dataConst()[off..][0..len];
        if (len > self.scratch.len) return error.RecordTooLarge;
        const d = self.dataConst();
        const first = self.size - off;
        @memcpy(self.scratch[0..first], d[off..][0..first]);
        @memcpy(self.scratch[first..len], d[0 .. len - first]);
        return self.scratch[0..len];
    }
};

// ── the whole per-CPU fan-out ───────────────────────────────────────────────

pub const Options = struct {
    /// Data pages per CPU. Must be a power of two; the total mmap per CPU is
    /// `(1 + pages) * page_size`. 8 pages (32 KiB on x86-64) is libbpf's
    /// default for `perf_buffer__new`.
    pages: u32 = 8,
    /// Open rings only for these CPUs. `null` = every online CPU. Useful
    /// when the map was created with fewer entries than the machine has
    /// CPUs, or to pin a consumer to one CPU.
    cpus: ?[]const u32 = null,
    /// `perf_event_attr.wakeup_events` — how many samples accumulate before
    /// the kernel wakes a poller. 1 = lowest latency, highest overhead.
    wakeup_events: u32 = 1,
};

/// Every CPU's ring behind one `poll`/`consume` pair, with the
/// `PERF_EVENT_ARRAY` map entries pointed at the per-CPU perf fds.
///
/// The map fd is BORROWED (the caller created and closes it), matching
/// `load.zig`'s convention; everything this struct opens itself — perf fds,
/// mappings, the epoll fd — it closes in `close()`.
pub const PerfBuffer = struct {
    gpa: std.mem.Allocator,
    map_fd: linux.fd_t,
    readers: []Reader,
    /// One reassembly buffer per CPU, sized to the ring so that
    /// `RecordTooLarge` cannot happen.
    scratch: []u8,
    epoll_fd: linux.fd_t,

    /// Open one ring per CPU, install each perf fd into `map_fd`, arm them,
    /// and register them all on a private epoll fd.
    pub fn open(gpa: std.mem.Allocator, map_fd: linux.fd_t, opts: Options) OpenError!PerfBuffer {
        if (comptime builtin.os.tag != .linux)
            @compileError("ebpf.PerfBuffer is Linux-only (perf_event_open + mmap)");
        if (opts.pages == 0 or !std.math.isPowerOfTwo(opts.pages)) return error.InvalidPageCount;

        const page = std.heap.pageSize();
        const ring = @as(usize, opts.pages) * page;

        var owned_cpus: ?[]u32 = null;
        defer if (owned_cpus) |c| gpa.free(c);
        const cpus: []const u32 = if (opts.cpus) |c| c else blk: {
            const list = try onlineCpus(gpa);
            owned_cpus = list;
            break :blk list;
        };
        if (cpus.len == 0) return error.CpuEnumerationFailed;

        const readers = gpa.alloc(Reader, cpus.len) catch return error.OutOfMemory;
        errdefer gpa.free(readers);
        const scratch = gpa.alloc(u8, ring * cpus.len) catch return error.OutOfMemory;
        errdefer gpa.free(scratch);

        const efd = try openEpoll();
        errdefer _ = linux.close(efd);

        var built: usize = 0;
        errdefer for (readers[0..built]) |*r| r.close();

        for (cpus, 0..) |cpu, i| {
            var attr = buildPerfBufferAttr(opts.wakeup_events);
            const rc = linux.perf_event_open(&attr, -1, @intCast(cpu), -1, attach.PERF_FLAG_FD_CLOEXEC);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .ACCES, .PERM => return error.PermissionDenied,
                else => return error.PerfEventOpenFailed,
            }
            const perf_fd: linux.fd_t = @intCast(rc);
            const mapping = mapRing(perf_fd, page + ring) catch |e| {
                _ = linux.close(perf_fd);
                return e;
            };

            readers[i] = .{
                .cpu = cpu,
                .perf_fd = perf_fd,
                .base = mapping,
                .data_off = page,
                .size = ring,
                .mask = ring - 1,
                .tail = 0,
                .pending = 0,
                .scratch = scratch[i * ring ..][0..ring],
                .owns_mapping = true,
            };
            built = i + 1;
            // Adopt whatever tail the control page already carries, so a
            // re-opened consumer neither replays nor skips.
            readers[i].tail = @atomicLoad(u64, readers[i].tailPtr(), .acquire);

            // Point the map's per-CPU slot at this event: this is what makes
            // `bpf_perf_event_output(ctx, &map, BPF_F_CURRENT_CPU, ...)`
            // land in THIS ring.
            var key: [4]u8 = undefined;
            var val: [4]u8 = undefined;
            std.mem.writeInt(u32, &key, cpu, native_endian);
            std.mem.writeInt(i32, &val, perf_fd, native_endian);
            BPF.map_update_elem(map_fd, &key, &val, 0) catch |e| return switch (e) {
                error.PermissionDenied => error.PermissionDenied,
                error.BadFd, error.FieldInAttrNeedsZeroing, error.ReachedMaxEntries => error.MapUpdateFailed,
                else => error.MapUpdateFailed,
            };

            switch (linux.errno(linux.ioctl(perf_fd, attach.PERF_EVENT_IOC.ENABLE, 0))) {
                .SUCCESS => {},
                .ACCES, .PERM => return error.PermissionDenied,
                else => return error.PerfEventOpenFailed,
            }

            var ev: linux.epoll_event = .{
                .events = linux.EPOLL.IN,
                .data = .{ .u32 = @intCast(i) },
            };
            switch (linux.errno(linux.epoll_ctl(efd, linux.EPOLL.CTL_ADD, perf_fd, &ev))) {
                .SUCCESS => {},
                else => return error.EpollFailed,
            }
        }

        return .{
            .gpa = gpa,
            .map_fd = map_fd,
            .readers = readers,
            .scratch = scratch,
            .epoll_fd = efd,
        };
    }

    /// Close every perf fd, unmap every ring, close the epoll fd. `map_fd`
    /// stays owned by the caller.
    pub fn close(self: *PerfBuffer) void {
        for (self.readers) |*r| r.close();
        if (self.epoll_fd >= 0) _ = linux.close(self.epoll_fd);
        self.gpa.free(self.readers);
        self.gpa.free(self.scratch);
        self.* = undefined;
    }

    /// Total samples reported dropped across every CPU.
    pub fn lostRecords(self: *const PerfBuffer) u64 {
        var n: u64 = 0;
        for (self.readers) |r| n +|= r.lost_records;
        return n;
    }

    /// True if any CPU has data pending (one acquire load per ring).
    pub fn available(self: *const PerfBuffer) bool {
        for (self.readers) |*r| if (r.available()) return true;
        return false;
    }

    /// Block until at least one ring has data or `timeout_ms` elapses
    /// (`-1` = forever, `0` = immediate). Returns whether data is actually
    /// pending — an epoll wakeup is a hint, so the answer comes from
    /// re-checking the positions.
    pub fn poll(self: *PerfBuffer, timeout_ms: i32) PollError!bool {
        if (self.available()) return true;
        if (self.epoll_fd < 0) return error.NotPollable;

        var events: [16]linux.epoll_event = undefined;
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

    /// Drain every CPU's ring, at most `max_records_per_cpu` from each.
    /// Returns the total number of events dispatched (samples + losses).
    pub fn consume(
        self: *PerfBuffer,
        ctx: ?*anyopaque,
        on_sample: SampleFn,
        on_lost: ?LostFn,
        max_records_per_cpu: usize,
    ) ConsumeError!usize {
        var n: usize = 0;
        for (self.readers) |*r| n += try r.consume(ctx, on_sample, on_lost, max_records_per_cpu);
        return n;
    }

    /// `poll` then `consume`.
    pub fn pollAndConsume(
        self: *PerfBuffer,
        timeout_ms: i32,
        ctx: ?*anyopaque,
        on_sample: SampleFn,
        on_lost: ?LostFn,
        max_records_per_cpu: usize,
    ) (PollError || ConsumeError)!usize {
        if (!try self.poll(timeout_ms)) return 0;
        return self.consume(ctx, on_sample, on_lost, max_records_per_cpu);
    }
};

/// The `perf_event_attr` a perf-buffer ring is opened with — pure, so its
/// layout is testable without any privilege. Matches libbpf's
/// `perf_buffer__new`: a `PERF_COUNT_SW_BPF_OUTPUT` software event sampling
/// raw records, one sample per wakeup.
pub fn buildPerfBufferAttr(wakeup_events: u32) linux.perf_event_attr {
    var attr: linux.perf_event_attr = .{
        .type = .SOFTWARE,
        .size = @sizeOf(linux.perf_event_attr),
        .config = PERF_COUNT_SW_BPF_OUTPUT,
    };
    attr.sample_type = linux.PERF.SAMPLE.RAW;
    attr.sample_period_or_freq = 1;
    attr.wakeup_events_or_watermark = wakeup_events;
    return attr;
}

/// `mmap` one CPU's control page + data area.
fn mapRing(perf_fd: linux.fd_t, len: usize) OpenError![]align(std.heap.page_size_min) u8 {
    const rc = linux.mmap(null, len, .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED }, perf_fd, 0);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.PermissionDenied,
        .INVAL, .NODEV => return error.NotAPerfEventArray,
        .NOMEM, .AGAIN => return error.MmapFailed,
        else => return error.Unexpected,
    }
    const ptr: [*]align(std.heap.page_size_min) u8 = @ptrFromInt(rc);
    return ptr[0..len];
}

fn openEpoll() OpenError!linux.fd_t {
    const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
    switch (linux.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .ACCES, .PERM => return error.PermissionDenied,
        else => return error.EpollFailed,
    }
}

/// Parse `/sys/devices/system/cpu/online` (e.g. `"0-3,8,10-11"`).
pub fn onlineCpus(gpa: std.mem.Allocator) OpenError![]u32 {
    var buf: [512]u8 = undefined;
    const raw = readSmallFile("/sys/devices/system/cpu/online", &buf) orelse
        return error.CpuEnumerationFailed;
    return parseCpuList(gpa, raw);
}

/// Parse a kernel CPU-list string into an explicit list. Pure, so the
/// range/comma syntax is testable without touching sysfs.
pub fn parseCpuList(gpa: std.mem.Allocator, text: []const u8) OpenError![]u32 {
    var out: std.ArrayList(u32) = .empty;
    errdefer out.deinit(gpa);

    var it = std.mem.tokenizeAny(u8, text, ", \t\r\n");
    while (it.next()) |part| {
        if (std.mem.indexOfScalar(u8, part, '-')) |dash| {
            const lo = std.fmt.parseInt(u32, part[0..dash], 10) catch return error.CpuEnumerationFailed;
            const hi = std.fmt.parseInt(u32, part[dash + 1 ..], 10) catch return error.CpuEnumerationFailed;
            if (hi < lo or hi - lo > 4095) return error.CpuEnumerationFailed;
            var c = lo;
            while (c <= hi) : (c += 1) out.append(gpa, c) catch return error.OutOfMemory;
        } else {
            const c = std.fmt.parseInt(u32, part, 10) catch return error.CpuEnumerationFailed;
            out.append(gpa, c) catch return error.OutOfMemory;
        }
    }
    return out.toOwnedSlice(gpa) catch error.OutOfMemory;
}

/// Read at most `buf.len` bytes of a small sysfs file; `null` on any failure.
fn readSmallFile(path: [*:0]const u8, buf: []u8) ?[]u8 {
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => return null,
    }
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    var n: usize = 0;
    while (n < buf.len) {
        const r = linux.read(fd, buf.ptr + n, buf.len - n);
        switch (linux.errno(r)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return null,
        }
        if (r == 0) break;
        n += r;
    }
    return buf[0..n];
}

// ── tests ────────────────────────────────────────────────────────────────────
//
// Same two layers the rest of this module uses:
//  1. UNPRIVILEGED, always run: an in-memory FAKE PERF RING driving the real
//     `Reader` — wrap-around, a record SPLIT ACROSS the ring boundary (the
//     case `ringbuf.zig` gets for free from the kernel's double mapping and
//     this file must handle itself), `PERF_RECORD_LOST`, hostile headers,
//     unknown record types, and a head that MOVES mid-iteration.
//  2. PRIVILEGED, gracefully skipped: a real `PERF_EVENT_ARRAY` behind a
//     real tracepoint, consumed end-to-end. Prints `SKIPPED:` and passes
//     without CAP_BPF.

const testing = std.testing;

fn hasBpfCapability() bool {
    return linux.geteuid() == 0;
}

/// An in-memory stand-in for one CPU's perf ring: the same control page at
/// the same offsets, and — deliberately — NO double mapping, so a record
/// that runs off the end really is split in two.
const FakePerfRing = struct {
    gpa: std.mem.Allocator,
    size: usize,
    page: usize,
    buf: []align(std.heap.page_size_min) u8,
    scratch: []u8,
    head: u64 = 0,

    const alignment: std.mem.Alignment = .fromByteUnits(std.heap.page_size_min);

    fn init(gpa: std.mem.Allocator, size: usize) !FakePerfRing {
        std.debug.assert(std.math.isPowerOfTwo(size));
        const page = std.heap.page_size_min;
        const buf = try gpa.alignedAlloc(u8, alignment, page + size);
        errdefer gpa.free(buf);
        const scratch = try gpa.alloc(u8, size);
        @memset(buf, 0);
        @memset(scratch, 0);
        return .{ .gpa = gpa, .size = size, .page = page, .buf = buf, .scratch = scratch };
    }

    fn deinit(self: *FakePerfRing) void {
        self.gpa.free(self.buf);
        self.gpa.free(self.scratch);
        self.* = undefined;
    }

    fn reader(self: *FakePerfRing) Reader {
        return .{
            .cpu = 3,
            .perf_fd = -1,
            .base = self.buf,
            .data_off = self.page,
            .size = self.size,
            .mask = self.size - 1,
            .tail = 0,
            .pending = 0,
            .scratch = self.scratch,
            .owns_mapping = false,
        };
    }

    /// Write bytes at a logical position, wrapping — exactly one copy, since
    /// the real perf ring is not aliased.
    fn poke(self: *FakePerfRing, pos: u64, bytes: []const u8) void {
        for (bytes, 0..) |b, i| {
            const off: usize = @intCast((pos + i) & (self.size - 1));
            self.buf[self.page + off] = b;
        }
    }

    fn pokeU32(self: *FakePerfRing, pos: u64, v: u32) void {
        var raw: [4]u8 = undefined;
        std.mem.writeInt(u32, &raw, v, native_endian);
        self.poke(pos, &raw);
    }

    fn pokeU64(self: *FakePerfRing, pos: u64, v: u64) void {
        var raw: [8]u8 = undefined;
        std.mem.writeInt(u64, &raw, v, native_endian);
        self.poke(pos, &raw);
    }

    fn writeHeader(self: *FakePerfRing, pos: u64, rec_type: u32, misc: u16, size: u16) void {
        self.pokeU32(pos, rec_type);
        var m: [2]u8 = undefined;
        std.mem.writeInt(u16, &m, misc, native_endian);
        self.poke(pos + 4, &m);
        var s: [2]u8 = undefined;
        std.mem.writeInt(u16, &s, size, native_endian);
        self.poke(pos + 6, &s);
    }

    /// Append a `PERF_RECORD_SAMPLE` the way the kernel frames one: the raw
    /// length is rounded so that `4 + len` is a multiple of 8.
    fn appendSample(self: *FakePerfRing, payload: []const u8) void {
        const raw_len: usize = std.mem.alignForward(usize, payload.len + 4, 8) - 4;
        const rec: usize = PERF_EVENT_HDR_SZ + 4 + raw_len;
        const pos = self.head;
        self.writeHeader(pos, PERF_RECORD_SAMPLE, 0, @intCast(rec));
        self.pokeU32(pos + PERF_EVENT_HDR_SZ, @intCast(raw_len));
        self.poke(pos + PERF_EVENT_HDR_SZ + 4, payload);
        // Zero the kernel's padding explicitly.
        var i = payload.len;
        while (i < raw_len) : (i += 1) self.poke(pos + PERF_EVENT_HDR_SZ + 4 + i, &.{0});
        self.head = pos + rec;
        self.publish();
    }

    fn appendLost(self: *FakePerfRing, id: u64, lost: u64) void {
        const pos = self.head;
        const rec: usize = PERF_EVENT_HDR_SZ + 16;
        self.writeHeader(pos, PERF_RECORD_LOST, 0, @intCast(rec));
        self.pokeU64(pos + PERF_EVENT_HDR_SZ, id);
        self.pokeU64(pos + PERF_EVENT_HDR_SZ + 8, lost);
        self.head = pos + rec;
        self.publish();
    }

    /// Append a record of some type this consumer does not decode.
    fn appendOther(self: *FakePerfRing, rec_type: u32, body_len: usize) void {
        const pos = self.head;
        const rec = PERF_EVENT_HDR_SZ + std.mem.alignForward(usize, body_len, 8);
        self.writeHeader(pos, rec_type, 0, @intCast(rec));
        self.head = pos + rec;
        self.publish();
    }

    /// Publish `data_head` the way the kernel does — release store.
    fn publish(self: *FakePerfRing) void {
        const p: *u64 = @ptrCast(@alignCast(&self.buf[DATA_HEAD_OFF]));
        @atomicStore(u64, p, self.head, .release);
    }

    /// `data_tail` as the kernel would see it.
    fn kernelVisibleTail(self: *FakePerfRing) u64 {
        const p: *const u64 = @ptrCast(@alignCast(&self.buf[DATA_TAIL_OFF]));
        return @atomicLoad(u64, p, .acquire);
    }
};

const Collector = struct {
    buf: [64][64]u8 = undefined,
    lens: [64]usize = @splat(0),
    cpus: [64]u32 = @splat(0),
    n: usize = 0,
    lost_calls: usize = 0,
    lost_total: u64 = 0,
    stop_after: usize = std.math.maxInt(usize),

    fn onSample(ctx: ?*anyopaque, cpu: u32, data: []const u8) Action {
        const self: *Collector = @ptrCast(@alignCast(ctx.?));
        if (self.n < self.buf.len and data.len <= self.buf[0].len) {
            @memcpy(self.buf[self.n][0..data.len], data);
            self.lens[self.n] = data.len;
            self.cpus[self.n] = cpu;
        }
        self.n += 1;
        return if (self.n >= self.stop_after) .stop else .proceed;
    }

    fn onLost(ctx: ?*anyopaque, cpu: u32, lost: u64) Action {
        _ = cpu;
        const self: *Collector = @ptrCast(@alignCast(ctx.?));
        self.lost_calls += 1;
        self.lost_total += lost;
        return .proceed;
    }

    fn item(self: *const Collector, i: usize) []const u8 {
        return self.buf[i][0..self.lens[i]];
    }
};

test "control-page offsets match the kernel's perf_event_mmap_page" {
    try testing.expectEqual(DATA_HEAD_OFF, @offsetOf(linux.perf_event_mmap_page, "data_head"));
    try testing.expectEqual(DATA_TAIL_OFF, @offsetOf(linux.perf_event_mmap_page, "data_tail"));
    // The kernel pads the struct "to 1k" exactly so these two land on their
    // own cache lines; a shifted offset would read a timestamp as a position.
    try testing.expectEqual(@as(usize, 1024), DATA_HEAD_OFF);
    try testing.expectEqual(DATA_HEAD_OFF + 8, DATA_TAIL_OFF);
    try testing.expectEqual(@as(u32, 9), PERF_RECORD_SAMPLE);
    try testing.expectEqual(@as(u32, 2), PERF_RECORD_LOST);
    try testing.expectEqual(@as(u64, 10), PERF_COUNT_SW_BPF_OUTPUT);
}

test "golden: the perf_event_attr a perf-buffer ring is opened with" {
    const attr = buildPerfBufferAttr(1);
    try testing.expectEqual(linux.PERF.TYPE.SOFTWARE, attr.type);
    try testing.expectEqual(@as(u32, @sizeOf(linux.perf_event_attr)), attr.size);
    try testing.expectEqual(@as(u64, 10), attr.config); // PERF_COUNT_SW_BPF_OUTPUT
    try testing.expectEqual(@as(u64, 1024), attr.sample_type); // PERF_SAMPLE_RAW
    try testing.expectEqual(@as(u64, 1), attr.sample_period_or_freq);
    try testing.expectEqual(@as(u32, 1), attr.wakeup_events_or_watermark);
    // Nothing else may be set: `disabled`/`inherit`/`freq` all change what
    // the event means, and `config1`/`config2` are for probe PMUs.
    try testing.expectEqual(@as(u64, 0), @as(u64, @bitCast(attr.flags)));
    try testing.expectEqual(@as(u64, 0), attr.config1);
    try testing.expectEqual(@as(u64, 0), attr.config2);
    try testing.expectEqual(@as(u64, 0), attr.read_format);

    const w = buildPerfBufferAttr(64);
    try testing.expectEqual(@as(u32, 64), w.wakeup_events_or_watermark);
}

test "fake perf ring: multi-record walk and position arithmetic" {
    var ring = try FakePerfRing.init(testing.allocator, 4096);
    defer ring.deinit();

    ring.appendSample("alpha"); // raw_len 8 -> record 20 -> padded to 8: 8+4+8 = 20? see below
    ring.appendSample("0123456789ab");
    ring.appendSample("");

    var rb = ring.reader();
    try testing.expect(rb.available());

    // "alpha" (5 bytes): raw_len = align8(5+4)-4 = 12-4 = 8, record = 8+4+8 = 20.
    // Perf records are 8-byte multiples, so the kernel's rounding produces
    // record sizes of 8 + align8(len+4): 8+12 = 20 is NOT a multiple of 8 —
    // hence align8(5+4)=16, raw_len=12, record = 8+4+12 = 24.
    const e1 = (try rb.next()).?;
    try testing.expectEqual(@as(usize, 12), e1.sample.len);
    try testing.expectEqualStrings("alpha", e1.sample[0..5]);
    // The trailing bytes are the kernel's zero padding.
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0 }, e1.sample[5..]);
    // next() is idempotent until advance().
    const again = (try rb.next()).?;
    try testing.expectEqual(@as(usize, 12), again.sample.len);
    try testing.expectEqual(@as(u64, 0), ring.kernelVisibleTail());
    rb.advance();
    try testing.expectEqual(@as(u64, 24), ring.kernelVisibleTail());

    const e2 = (try rb.next()).?;
    try testing.expectEqual(@as(usize, 12), e2.sample.len);
    try testing.expectEqualStrings("0123456789ab", e2.sample);
    rb.advance();
    try testing.expectEqual(@as(u64, 48), ring.kernelVisibleTail());

    const e3 = (try rb.next()).?;
    try testing.expectEqual(@as(usize, 4), e3.sample.len);
    rb.advance();
    try testing.expectEqual(ring.head, ring.kernelVisibleTail());

    try testing.expect(!rb.available());
    try testing.expectEqual(@as(?Event, null), try rb.next());
    rb.advance(); // no-op
    try testing.expectEqual(ring.head, ring.kernelVisibleTail());
}

test "fake perf ring: a record split across the ring end is reassembled" {
    // 128-byte ring: walk the tail forward, then place a record that
    // physically straddles the boundary. Unlike the BPF ring buffer there is
    // NO second copy of the data area, so this is the case that must be
    // stitched together by hand.
    var ring = try FakePerfRing.init(testing.allocator, 128);
    defer ring.deinit();

    var rb = ring.reader();
    var col: Collector = .{};

    // 4 records of 24 bytes take head/tail to 96.
    for (0..4) |_| ring.appendSample("aaaaa");
    try testing.expectEqual(@as(usize, 4), try rb.consume(&col, Collector.onSample, null, 16));
    try testing.expectEqual(@as(u64, 96), ring.kernelVisibleTail());

    // A 40-byte record at 96 occupies [96, 136) — its payload crosses 128.
    const payload = "0123456789abcdefghijklmnopq";
    ring.appendSample(payload);
    try testing.expectEqual(@as(u64, 136), ring.head);

    const ev = (try rb.next()).?;
    try testing.expectEqualStrings(payload, ev.sample[0..payload.len]);
    // Proof it really came from the reassembly buffer, not the mapping.
    const scratch_base = @intFromPtr(ring.scratch.ptr);
    try testing.expectEqual(scratch_base, @intFromPtr(ev.sample.ptr));
    rb.advance();
    try testing.expectEqual(@as(u64, 136), ring.kernelVisibleTail());

    // The 8-byte HEADER itself can never straddle (perf record sizes are
    // multiples of 8 and positions stay 8-aligned, so a header always starts
    // at an 8-aligned ring offset) — but the 4-byte RAW LENGTH that follows
    // it can land entirely on the far side of the wrap. Place a record whose
    // header ends exactly at the ring end so that everything after it is
    // read through the wrap.
    ring.head = 120; // 120 + 8 = 128 = the ring end
    ring.publish();
    rb.tail = 120;
    ring.appendSample("xy");
    const wrapped_len = (try rb.next()).?;
    try testing.expectEqualStrings("xy", wrapped_len.sample[0..2]);
    rb.advance();
    try testing.expectEqual(ring.head, ring.kernelVisibleTail());

    // And the walk keeps working afterwards.
    ring.appendSample("after");
    const post = (try rb.next()).?;
    try testing.expectEqualStrings("after", post.sample[0..5]);
    rb.advance();
}

test "fake perf ring: PERF_RECORD_LOST is surfaced, never silently dropped" {
    var ring = try FakePerfRing.init(testing.allocator, 4096);
    defer ring.deinit();

    ring.appendSample("before");
    ring.appendLost(7, 42);
    ring.appendSample("after");
    ring.appendLost(7, 5);

    var rb = ring.reader();

    const s1 = (try rb.next()).?;
    try testing.expectEqualStrings("before", s1.sample[0..6]);
    rb.advance();

    const lost = (try rb.next()).?;
    try testing.expectEqual(Event{ .lost = 42 }, lost);
    try testing.expectEqual(@as(u64, 42), rb.lost_records);
    rb.advance();

    // The callback form reports losses through `on_lost` AND keeps counting
    // when no callback is supplied.
    var col: Collector = .{};
    const n = try rb.consume(&col, Collector.onSample, Collector.onLost, 16);
    try testing.expectEqual(@as(usize, 2), n); // one sample + one loss
    try testing.expectEqual(@as(usize, 1), col.n);
    try testing.expectEqualStrings("after", col.item(0)[0..5]);
    try testing.expectEqual(@as(usize, 1), col.lost_calls);
    try testing.expectEqual(@as(u64, 5), col.lost_total);
    try testing.expectEqual(@as(u64, 47), rb.lost_records);
    try testing.expectEqual(ring.head, ring.kernelVisibleTail());
    // The CPU index travels with every callback.
    try testing.expectEqual(@as(u32, 3), col.cpus[0]);
}

test "fake perf ring: unknown record types are skipped but counted" {
    var ring = try FakePerfRing.init(testing.allocator, 4096);
    defer ring.deinit();

    ring.appendOther(@intFromEnum(linux.PERF.RECORD.THROTTLE), 24);
    ring.appendSample("real");
    ring.appendOther(@intFromEnum(linux.PERF.RECORD.COMM), 16);
    ring.appendSample("also-real");

    var rb = ring.reader();
    var col: Collector = .{};
    const n = try rb.consume(&col, Collector.onSample, Collector.onLost, 16);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("real", col.item(0)[0..4]);
    try testing.expectEqualStrings("also-real", col.item(1)[0..9]);
    try testing.expectEqual(@as(u64, 2), rb.unknown_records);
    // Their space was still released.
    try testing.expectEqual(ring.head, ring.kernelVisibleTail());
}

test "fake perf ring: the head may move mid-iteration" {
    var ring = try FakePerfRing.init(testing.allocator, 4096);
    defer ring.deinit();

    ring.appendSample("one");
    var rb = ring.reader();

    const a = (try rb.next()).?;
    try testing.expectEqualStrings("one", a.sample[0..3]);
    rb.advance();
    try testing.expectEqual(@as(?Event, null), try rb.next());

    // The producer publishes more WHILE the consumer is mid-loop: `next()`
    // re-reads data_head with an acquire load every call, so the new records
    // become visible without re-opening anything.
    ring.appendSample("two");
    const b = (try rb.next()).?;
    try testing.expectEqualStrings("two", b.sample[0..3]);
    rb.advance();

    ring.appendSample("three");
    ring.appendSample("four");
    var col: Collector = .{};
    try testing.expectEqual(@as(usize, 2), try rb.consume(&col, Collector.onSample, null, 16));
    try testing.expectEqualStrings("three", col.item(0)[0..5]);
    try testing.expectEqualStrings("four", col.item(1)[0..4]);
    try testing.expectEqual(ring.head, ring.kernelVisibleTail());
}

test "fake perf ring: consume() honors max_records and the stop action" {
    var ring = try FakePerfRing.init(testing.allocator, 4096);
    defer ring.deinit();
    for (0..8) |i| {
        var buf: [8]u8 = undefined;
        const s = try std.fmt.bufPrint(&buf, "rec-{d}", .{i});
        ring.appendSample(s);
    }

    var rb = ring.reader();
    var col: Collector = .{};
    try testing.expectEqual(@as(usize, 3), try rb.consume(&col, Collector.onSample, null, 3));
    try testing.expectEqualStrings("rec-0", col.item(0)[0..5]);
    try testing.expectEqualStrings("rec-2", col.item(2)[0..5]);
    try testing.expectEqual(@as(u64, 3 * 24), ring.kernelVisibleTail());

    var col2: Collector = .{ .stop_after = 2 };
    try testing.expectEqual(@as(usize, 2), try rb.consume(&col2, Collector.onSample, null, 16));
    try testing.expectEqual(@as(u64, 5 * 24), ring.kernelVisibleTail());

    var col3: Collector = .{};
    try testing.expectEqual(@as(usize, 3), try rb.consume(&col3, Collector.onSample, null, 16));
    try testing.expectEqual(ring.head, ring.kernelVisibleTail());
}

test "fake perf ring: hostile record headers are typed errors, never panics" {
    // (a) size = 0 would make the walk spin forever.
    {
        var ring = try FakePerfRing.init(testing.allocator, 4096);
        defer ring.deinit();
        ring.writeHeader(0, PERF_RECORD_SAMPLE, 0, 0);
        ring.head = 4096;
        ring.publish();
        var rb = ring.reader();
        try testing.expectError(error.CorruptRecord, rb.next());
    }
    // (b) a size that is not a multiple of 8 cannot be a perf record.
    {
        var ring = try FakePerfRing.init(testing.allocator, 4096);
        defer ring.deinit();
        ring.writeHeader(0, PERF_RECORD_SAMPLE, 0, 13);
        ring.head = 4096;
        ring.publish();
        var rb = ring.reader();
        try testing.expectError(error.CorruptRecord, rb.next());
    }
    // (c) a size larger than the whole ring.
    {
        var ring = try FakePerfRing.init(testing.allocator, 64);
        defer ring.deinit();
        ring.writeHeader(0, PERF_RECORD_SAMPLE, 0, 256);
        ring.head = 64;
        ring.publish();
        var rb = ring.reader();
        try testing.expectError(error.CorruptRecord, rb.next());
    }
    // (d) a size running past what the producer published.
    {
        var ring = try FakePerfRing.init(testing.allocator, 4096);
        defer ring.deinit();
        ring.writeHeader(0, PERF_RECORD_SAMPLE, 0, 128);
        ring.head = 16;
        ring.publish();
        var rb = ring.reader();
        try testing.expectError(error.CorruptRecord, rb.next());
    }
    // (e) a SAMPLE too short to even hold its raw-length field.
    {
        var ring = try FakePerfRing.init(testing.allocator, 4096);
        defer ring.deinit();
        ring.writeHeader(0, PERF_RECORD_SAMPLE, 0, 8);
        ring.head = 8;
        ring.publish();
        var rb = ring.reader();
        try testing.expectError(error.CorruptRecord, rb.next());
    }
    // (f) a SAMPLE whose raw length overflows its own record.
    {
        var ring = try FakePerfRing.init(testing.allocator, 4096);
        defer ring.deinit();
        ring.writeHeader(0, PERF_RECORD_SAMPLE, 0, 24);
        ring.pokeU32(PERF_EVENT_HDR_SZ, 4096);
        ring.head = 24;
        ring.publish();
        var rb = ring.reader();
        try testing.expectError(error.CorruptRecord, rb.next());
    }
    // (g) a LOST record too short for its two u64s.
    {
        var ring = try FakePerfRing.init(testing.allocator, 4096);
        defer ring.deinit();
        ring.writeHeader(0, PERF_RECORD_LOST, 0, 16);
        ring.head = 16;
        ring.publish();
        var rb = ring.reader();
        try testing.expectError(error.CorruptRecord, rb.next());
    }
    // (h) head behind tail.
    {
        var ring = try FakePerfRing.init(testing.allocator, 4096);
        defer ring.deinit();
        ring.appendSample("x");
        var rb = ring.reader();
        rb.tail = 512;
        try testing.expectError(error.InconsistentPositions, rb.next());
    }
    // (i) a tail off the 8-byte granule.
    {
        var ring = try FakePerfRing.init(testing.allocator, 4096);
        defer ring.deinit();
        ring.appendSample("x");
        var rb = ring.reader();
        rb.tail = 3;
        try testing.expectError(error.InconsistentPositions, rb.next());
    }
    // (j) a wrapping record bigger than the reassembly buffer.
    {
        var ring = try FakePerfRing.init(testing.allocator, 256);
        defer ring.deinit();
        var rb = ring.reader();
        rb.scratch = ring.scratch[0..8]; // deliberately too small
        // A 32-byte record at 232 puts its 20-byte payload at ring offset
        // 244, which runs 8 bytes past the 256-byte end — so it MUST be
        // reassembled, and the buffer cannot hold it.
        ring.head = 232;
        ring.publish();
        rb.tail = 232;
        ring.appendSample("0123456789abcdef");
        try testing.expectError(error.RecordTooLarge, rb.next());
    }
}

test "parseCpuList handles the kernel's range/comma syntax" {
    const gpa = testing.allocator;

    const a = try parseCpuList(gpa, "0-3\n");
    defer gpa.free(a);
    try testing.expectEqualSlices(u32, &.{ 0, 1, 2, 3 }, a);

    const b = try parseCpuList(gpa, "0-1,4,6-7");
    defer gpa.free(b);
    try testing.expectEqualSlices(u32, &.{ 0, 1, 4, 6, 7 }, b);

    const c = try parseCpuList(gpa, "0");
    defer gpa.free(c);
    try testing.expectEqualSlices(u32, &.{0}, c);

    try testing.expectError(error.CpuEnumerationFailed, parseCpuList(gpa, "3-1"));
    try testing.expectError(error.CpuEnumerationFailed, parseCpuList(gpa, "abc"));
    try testing.expectError(error.CpuEnumerationFailed, parseCpuList(gpa, "0-"));
}

test "onlineCpus reports at least one CPU on this machine" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const cpus = onlineCpus(testing.allocator) catch |e| {
        std.debug.print("\nebpf perfbuf onlineCpus SKIPPED: {s}\n", .{@errorName(e)});
        return;
    };
    defer testing.allocator.free(cpus);
    try testing.expect(cpus.len >= 1);
}

test "PerfBuffer.open rejects a bad page count before any syscall" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    try testing.expectError(
        error.InvalidPageCount,
        PerfBuffer.open(testing.allocator, -1, .{ .pages = 0 }),
    );
    try testing.expectError(
        error.InvalidPageCount,
        PerfBuffer.open(testing.allocator, -1, .{ .pages = 3 }),
    );
}

test "LIVE: a real PERF_EVENT_ARRAY consumed end-to-end through a tracepoint" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!hasBpfCapability()) {
        std.debug.print(
            "\nLIVE ebpf perfbuf test SKIPPED: needs CAP_BPF+CAP_PERFMON (running as uid {d}).\n",
            .{linux.geteuid()},
        );
        return;
    }

    const load = @import("load.zig").load;

    const cpus = onlineCpus(testing.allocator) catch {
        std.debug.print("\nLIVE ebpf perfbuf test SKIPPED: cannot enumerate CPUs.\n", .{});
        return;
    };
    defer testing.allocator.free(cpus);

    // key = u32 cpu, value = u32 perf fd, one slot per CPU.
    const map_fd = BPF.map_create(.perf_event_array, 4, 4, @intCast(cpus.len)) catch {
        std.debug.print("\nLIVE ebpf perfbuf test SKIPPED: BPF_MAP_CREATE(.perf_event_array) refused.\n", .{});
        return;
    };
    defer _ = linux.close(map_fd);

    var pb = PerfBuffer.open(testing.allocator, map_fd, .{ .pages = 8 }) catch |e| {
        std.debug.print("\nLIVE ebpf perfbuf test SKIPPED: PerfBuffer.open failed ({s}).\n", .{@errorName(e)});
        return;
    };
    defer pb.close();

    try testing.expectEqual(cpus.len, pb.readers.len);
    try testing.expect(!pb.available());
    try testing.expect(!try pb.poll(0));

    // A test-local producer: the smallest tracepoint program that emits a
    // fixed-size record into a `PERF_EVENT_ARRAY`. Deliberately NOT added to
    // `programs.zig`'s public, golden-vector-tested builder set — it exists
    // only to drive this one live test, and (unlike those three) it has no
    // clang-derived golden vector behind it.
    //
    //   *(u64*)(r10 - 16) = 0     zero the stack record so the verifier
    //   *(u64*)(r10 -  8) = 0     sees every byte initialized
    //   r2 = &perf_map            map-fd pseudo load
    //   r3 = BPF_F_CURRENT_CPU    0xffffffff — the UPPER 32 bits must be
    //                             zero, so this is a 64-bit immediate load,
    //                             not `mov r3, -1` (which sign-extends and
    //                             is rejected with EINVAL)
    //   r4 = r10 - 16; r5 = 16
    //   call bpf_perf_event_output; r0 = 0; exit
    const record_size: u32 = 16;
    const BPF_F_CURRENT_CPU: u64 = 0xffff_ffff;
    const insns = [_]BPF.Insn{
        BPF.Insn.st(.double_word, .r10, -16, 0),
        BPF.Insn.st(.double_word, .r10, -8, 0),
        BPF.Insn.ld_map_fd1(.r2, map_fd),
        BPF.Insn.ld_map_fd2(map_fd),
        BPF.Insn.ld_dw1(.r3, BPF_F_CURRENT_CPU),
        BPF.Insn.ld_dw2(BPF_F_CURRENT_CPU),
        BPF.Insn.mov(.r4, .r10),
        BPF.Insn.add(.r4, -16),
        BPF.Insn.mov(.r5, @as(i32, @intCast(record_size))),
        BPF.Insn.call(.perf_event_output),
        BPF.Insn.mov(.r0, 0),
        BPF.Insn.exit(),
    };
    const prog_fd = load(.{ .prog_type = .tracepoint, .insns = &insns }, "MIT") catch |e| {
        std.debug.print("\nLIVE ebpf perfbuf test SKIPPED: BPF_PROG_LOAD refused ({s}).\n", .{@errorName(e)});
        return;
    };
    defer _ = linux.close(prog_fd);

    var tp = attach.attachTracepoint(testing.allocator, "syscalls", "sys_enter_write", prog_fd) catch |e| {
        std.debug.print("\nLIVE ebpf perfbuf test SKIPPED: tracepoint attach failed ({s}).\n", .{@errorName(e)});
        return;
    };
    defer tp.deinit();

    // Trigger the tracepoint.
    for (0..16) |_| {
        const msg = "x";
        _ = linux.write(2, msg.ptr, 0); // a zero-length write still enters the syscall
    }

    var col: Collector = .{};
    const n = try pb.pollAndConsume(1000, &col, Collector.onSample, Collector.onLost, 32);
    try testing.expect(n > 0);
    try testing.expect(col.n > 0);
    try testing.expect(col.lens[0] >= record_size);
    // Whatever was consumed must have been released back to the kernel.
    for (pb.readers) |*r| {
        const t: *const u64 = @ptrCast(@alignCast(&r.base[DATA_TAIL_OFF]));
        try testing.expectEqual(r.tail, @atomicLoad(u64, t, .acquire));
    }
}
