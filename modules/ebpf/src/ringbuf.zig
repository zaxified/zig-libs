// SPDX-License-Identifier: MIT
//! Ring-buffer consumer — OPUS-tier syscall plumbing: mmap the kernel-side
//! `BPF_MAP_TYPE_RINGBUF` map into this process and poll it for records
//! written by `programs.ringbufEmit`-shaped programs. No verifier is
//! involved on this side (that's entirely a kernel-side/program-build-time
//! concern, see `programs.zig`) — this is userspace mmap + memory-barrier +
//! epoll bookkeeping, mechanical once the kernel's ringbuf mmap ABI is in
//! front of you.

const std = @import("std");
const linux = std.os.linux;
const BPF = linux.BPF;

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
    PermissionDenied,
    Unexpected,
};

pub const PollError = error{
    EpollFailed,
    Unexpected,
};

/// An open consumer for one `BPF_MAP_TYPE_RINGBUF` map.
pub const Reader = struct {
    map_fd: linux.fd_t,
    /// The consumer (position) page: 1 kernel page, PROT_READ|PROT_WRITE,
    /// offset 0. Holds `consumer_pos` (an 8-byte atomic counter this side
    /// writes to acknowledge consumed records) at the start of the page.
    cons_page: []align(std.heap.page_size_min) u8,
    /// The producer/data region: mmap'd TWICE, back-to-back, starting at
    /// page offset 1 (i.e. `mmap(NULL, 2*data_len, PROT_READ, MAP_SHARED,
    /// map_fd, page_size)` then a second `MAP_FIXED` mapping of the same
    /// `data_len` bytes immediately after the first) so a record that
    /// physically wraps around the ring's end is still readable as one
    /// contiguous slice without the consumer special-casing the wrap.
    /// Holds `producer_pos` (an 8-byte atomic counter the KERNEL writes) at
    /// the start of its first copy, followed by the actual record bytes.
    data_pages: []align(std.heap.page_size_min) u8,
    epoll_fd: linux.fd_t,

    /// Open a consumer for `map_fd` (must already be `BPF_PROG_LOAD`'d as
    /// `BPF_MAP_TYPE_RINGBUF` and passed to a loaded+attached program).
    ///
    /// TODO(opus): the mmap layout per `include/uapi/linux/bpf.h` +
    /// `kernel/bpf/ringbuf.c` is:
    ///   - page 0 (offset 0, length = 1 page): the CONSUMER page,
    ///     `PROT_READ|PROT_WRITE`, `MAP_SHARED`. Its first 8 bytes are
    ///     `consumer_pos` — userspace writes this (with a release-store /
    ///     `@atomicStore(.release)`-equivalent, since the kernel reads it
    ///     with acquire semantics) to tell the kernel how far records have
    ///     been consumed, freeing that ring space for reuse.
    ///   - pages 1..N (offset = 1 page, length = the ring's `max_entries`
    ///     bytes, which is the map's mmap-reported data length): the
    ///     PRODUCER region, mapped `PROT_READ` (consumer never writes
    ///     record bytes) `MAP_SHARED`, done TWICE back-to-back (second
    ///     mapping via `MAP_FIXED` at `first_mapping_addr + data_len`) so
    ///     wrap-around records read as one contiguous slice. Its first 8
    ///     bytes (of the FIRST copy only — both copies alias the same
    ///     physical pages) are `producer_pos`, which userspace reads with
    ///     acquire semantics; the kernel writes it with release semantics
    ///     after a record's header+payload are fully written.
    ///   - Each record inside the data region has an 8-byte header: a
    ///     `u32` length (low 31 bits) + 2 flag bits — `BPF_RINGBUF_BUSY_BIT`
    ///     (kernel is still writing / hasn't submitted yet — must not be
    ///     read) and `BPF_RINGBUF_DISCARD_BIT` (the program called
    ///     `bpf_ringbuf_discard` — skip these bytes, don't surface as a
    ///     `Record`) — followed by the payload, padded to 8-byte alignment.
    ///   - `std.os.linux.mmap`/`munmap` are the primitives to use for both
    ///     mappings (already in std, no gap there); `MAP.FIXED` for the
    ///     second producer-region mapping is the one flag combination that
    ///     needs getting exactly right (reserve `2*data_len` with an
    ///     anonymous `PROT_NONE` mapping first to get a stable base
    ///     address, then `MAP_FIXED`-overlay both real mappings into it —
    ///     the standard "double mmap ring buffer" trick, same one
    ///     `io_uring`/most lock-free SPSC ring implementations use).
    pub fn open(map_fd: linux.fd_t) OpenError!Reader {
        _ = map_fd;
        @panic("TODO(opus): mmap the ringbuf consumer+producer pages (double-mapped producer region for wrap-around-free reads) per the layout in this function's doc comment — std.os.linux.mmap/munmap are the only primitives needed, none of this is missing from std, it's just unwritten.");
    }

    pub fn close(self: *Reader) void {
        _ = self;
        @panic("TODO(opus): munmap both regions (data_pages is 2x data_len — unmap the whole double-mapped span in one call, not per-copy) and leave map_fd owned by the caller (this Reader borrows it, mirroring how load.zig's `load` returns a fd the CALLER closes).");
    }

    /// Block (via `epoll_wait`) until at least one record is available or
    /// `timeout_ms` elapses (`-1` = forever).
    ///
    /// TODO(opus): `BPF_MAP_TYPE_RINGBUF` supports epoll notification: the
    /// map fd itself is epoll-able (`epoll_ctl(epoll_fd, EPOLL_CTL_ADD,
    /// map_fd, &.{ .events = EPOLLIN, .data = ... })` once, at `open()`
    /// time, using `linux.epoll_ctl`/`EPOLL` already in std), signaled by
    /// the kernel whenever `producer_pos` advances past what was visible at
    /// the last `epoll_wait` (unless `BPF_RB_NO_WAKEUP` was passed to
    /// `bpf_ringbuf_submit`/`_output`, which this module's `programs.zig`
    /// builders do not use). `epoll_wait(epoll_fd, &events, 1, timeout_ms)`
    /// is the actual block; on return, re-check `producer_pos` (an
    /// acquire-load) against the cached `consumer_pos` to see if anything
    /// is actually there (an epoll wakeup is a hint, not a guarantee, same
    /// as any other level-triggered fd).
    pub fn poll(self: *Reader, timeout_ms: i32) PollError!bool {
        _ = self;
        _ = timeout_ms;
        @panic("TODO(opus): epoll_wait on the ringbuf map fd (already epoll-ctl'd onto self.epoll_fd in open()); std.os.linux.epoll_wait/epoll_ctl/EPOLL are already present, nothing missing from std here. See this function's doc comment.");
    }

    /// Return the next unread, non-discarded record, or `null` if the
    /// consumer has caught up to the producer. Call `advance` after
    /// processing it to release the space back to the kernel.
    ///
    /// TODO(opus): acquire-load `producer_pos` from `data_pages` (offset 0,
    /// first copy) and the locally-cached `consumer_pos`; if equal, return
    /// `null`. Otherwise read the 8-byte record header at
    /// `data_pages[8 + (consumer_pos % ring_len)..]` (the `+8` skips the
    /// `producer_pos` counter itself — record data starts one page-aligned
    /// counter-width in); if `BPF_RINGBUF_BUSY_BIT` is set, the kernel
    /// hasn't finished writing yet — treat as `null` (bail out this call,
    /// don't spin). If `BPF_RINGBUF_DISCARD_BIT` is set, silently skip this
    /// record's length and recurse/loop to the next one (matches libbpf's
    /// `ring_buffer__consume` behavior — discarded records are invisible to
    /// callers, not surfaced as empty `Record`s). Otherwise return a
    /// `Record{ .data = ... }` slice of exactly the header's length field,
    /// taken from the DOUBLE-mapped region so a wrap never truncates it.
    pub fn next(self: *Reader) ?Record {
        _ = self;
        @panic("TODO(opus): read+decode one ringbuf record header (len + BUSY/DISCARD bits) at the current consumer_pos offset into the double-mapped data region, per this function's doc comment.");
    }

    /// Release the space `next()`'s most recently returned record occupied
    /// back to the kernel (release-store the advanced `consumer_pos` into
    /// `cons_page`).
    pub fn advance(self: *Reader) void {
        _ = self;
        @panic("TODO(opus): release-store the advanced consumer_pos (8-byte header + record length, rounded up to 8-byte alignment) into cons_page[0..8] — an @atomicStore(u64, ..., .release), matching the kernel's acquire-load of the same field.");
    }
};

// ── tests ────────────────────────────────────────────────────────────────────
//
// Opening a real ringbuf needs a real BPF_MAP_TYPE_RINGBUF map fd (map_create
// is already real, non-stub code in std — see std.os.linux.BPF.map_create —
// so a future pass CAN build this test without needing programs.zig's
// TODO(fable/core) builders at all, only CAP_BPF). Nothing here calls into
// Reader's panicking methods.

const testing = std.testing;
const builtin = @import("builtin");

fn hasBpfCapability() bool {
    return linux.geteuid() == 0;
}

test "ringbuf map_create succeeds (needs CAP_BPF/root); Reader.open left for TODO(opus)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!hasBpfCapability()) return error.SkipZigTest;

    // BPF_MAP_TYPE_RINGBUF: key_size = value_size = 0, max_entries = ring
    // size in bytes (must be a power of 2 and a multiple of the page size —
    // 4096 satisfies both on every common page size).
    const map_fd = BPF.map_create(.ringbuf, 0, 0, 4096) catch |e| switch (e) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return e,
    };
    defer _ = linux.close(map_fd);
    try testing.expect(map_fd >= 0);

    // Reader.open(map_fd) is intentionally NOT called here — it panics
    // until TODO(opus) is implemented.
}
