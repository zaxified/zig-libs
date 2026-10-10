// SPDX-License-Identifier: MIT

//! The kernel's vDSO `getrandom` (Linux 6.11+): the same CRNG `getrandom(2)`
//! reads, run in user space from a per-caller state the kernel keys and
//! reseeds, so a draw costs no syscall. Go's `crypto/rand.Read` (1.24+) and
//! glibc's `arc4random` (2.41+) take the same path.
//!
//! What lives here and why:
//! - The kernel hands out the state's size and how to map it (one query call
//!   with `opaque_len = ~0`); states are carved from one mapping made with
//!   exactly those flags (MAP_DROPPABLE: the kernel may zero the pages under
//!   memory pressure or across fork, and the vDSO reseeds a zeroed state).
//! - A state must never be used by two threads at once. `slots` is a fixed
//!   pool with one busy flag each, taken by compare-and-swap and returned
//!   after the draw. The flags live in ordinary memory, never in the
//!   droppable mapping, whose pages can read back as zero at any time.
//! - No lock and no wait anywhere: while the pool is being set up, when every
//!   slot is taken, or when the kernel has no vDSO symbol, `draw` returns
//!   false and the caller takes the syscall path. A fork while another thread
//!   holds a slot leaves that slot busy in the child for ever; the child just
//!   has one slot fewer.
//! - Fail-closed is the caller's: `draw` returns true only when the vDSO
//!   filled the whole buffer; any negative return sends the caller to
//!   `randomSecure`, which aborts on a real entropy fault.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

/// The vDSO symbol per architecture (kernel `vdso.lds`); other targets never
/// take this path.
const sym: ?struct { name: []const u8, version: []const u8 } = switch (builtin.cpu.arch) {
    .x86_64 => .{ .name = "__vdso_getrandom", .version = "LINUX_2.6" },
    .aarch64 => .{ .name = "__kernel_getrandom", .version = "LINUX_2.6.39" },
    else => null,
};

pub const supported = builtin.os.tag == .linux and !builtin.link_libc and sym != null;

const VGetRandom = *const fn (buf: ?*anyopaque, len: usize, flags: u32, state: ?*anyopaque, state_len: usize) callconv(.c) isize;

/// `struct vgetrandom_opaque_params` (uapi `linux/random.h`).
const Params = extern struct {
    size_of_opaque_state: u32,
    mmap_prot: u32,
    mmap_flags: u32,
    reserved: [13]u32,
};

/// Slots in the pool. One per concurrently drawing thread; more threads than
/// this at the same instant fall back to the syscall, which is correct, only
/// slower.
pub const slot_count = 64;

const State = enum(u8) { uninit, initializing, ready, unavailable };

var state: std.atomic.Value(State) = .init(.uninit);
var func: VGetRandom = undefined;
var base: [*]u8 = undefined;
var state_len: usize = 0;
var busy: [slot_count]std.atomic.Value(bool) = @splat(.init(false));
/// Where this thread found a free slot last time, so a thread keeps hitting
/// its own slot without scanning.
threadlocal var hint: u8 = 0;

fn init() void {
    const s = sym.?;
    const addr = vdsoLookup(s.version, s.name);
    if (addr == 0) return state.store(.unavailable, .release);
    const f: VGetRandom = @ptrFromInt(addr);
    var params: Params = undefined;
    if (f(null, 0, 0, &params, ~@as(usize, 0)) != 0 or params.size_of_opaque_state == 0)
        return state.store(.unavailable, .release);

    // A state may not straddle a page boundary: pack whole states per page.
    // `page_size_min` is safe even under a larger real page, since every
    // larger page boundary is also a boundary of the minimum.
    const page = std.heap.page_size_min;
    const size: usize = params.size_of_opaque_state;
    if (size > page) return state.store(.unavailable, .release);
    const per_page = page / size;
    const pages = (slot_count + per_page - 1) / per_page;
    const rc = linux.mmap(null, pages * page, @bitCast(params.mmap_prot), @bitCast(params.mmap_flags), -1, 0);
    if (linux.errno(rc) != .SUCCESS) return state.store(.unavailable, .release);

    func = f;
    base = @ptrFromInt(rc);
    state_len = size;
    state.store(.ready, .release);
}

/// The address of a versioned vDSO symbol, or 0. std 0.16 has exactly this
/// (`std.os.linux.vdso.lookup`) but does not export it (`const vdso`, not
/// `pub`), so it is restated here: DT_HASH bounds the symbol table, a symbol
/// must be a defined global/weak function or object, and its DT_VERSYM entry
/// must name `version` in DT_VERDEF.
fn vdsoLookup(version: []const u8, name: []const u8) usize {
    const elf = std.elf;
    const vdso_addr = linux.getauxval(elf.AT_SYSINFO_EHDR);
    if (vdso_addr == 0) return 0;
    const eh: *const elf.Ehdr = @ptrFromInt(vdso_addr);

    var dynv_opt: ?[*]const usize = null;
    var load_base: ?usize = null;
    for (0..eh.e_phnum) |i| {
        const ph: *const elf.Phdr = @ptrFromInt(vdso_addr + eh.e_phoff + i * eh.e_phentsize);
        switch (ph.p_type) {
            // Wrapping: some kernels pre-link the image in the upper half.
            elf.PT_LOAD => load_base = vdso_addr +% ph.p_offset -% ph.p_vaddr,
            elf.PT_DYNAMIC => dynv_opt = @ptrFromInt(vdso_addr + ph.p_offset),
            else => {},
        }
    }
    const dynv = dynv_opt orelse return 0;
    const b = load_base orelse return 0;

    var strings_opt: ?[*:0]const u8 = null;
    var syms_opt: ?[*]const elf.Sym = null;
    var hash_opt: ?[*]const linux.Elf_Symndx = null;
    var versym: ?[*]const elf.Versym = null;
    var verdef: ?*const elf.Verdef = null;
    var i: usize = 0;
    while (dynv[i] != 0) : (i += 2) {
        const p = b +% dynv[i + 1];
        switch (dynv[i]) {
            elf.DT_STRTAB => strings_opt = @ptrFromInt(p),
            elf.DT_SYMTAB => syms_opt = @ptrFromInt(p),
            elf.DT_HASH => hash_opt = @ptrFromInt(p),
            elf.DT_VERSYM => versym = @ptrFromInt(p),
            elf.DT_VERDEF => verdef = @ptrFromInt(p),
            else => {},
        }
    }
    const strings = strings_opt orelse return 0;
    const syms = syms_opt orelse return 0;
    const hash = hash_opt orelse return 0;

    const ok_types: u32 = 1 << elf.STT_NOTYPE | 1 << elf.STT_OBJECT | 1 << elf.STT_FUNC | 1 << elf.STT_COMMON;
    const ok_binds: u32 = 1 << elf.STB_GLOBAL | 1 << elf.STB_WEAK | 1 << elf.STB_GNU_UNIQUE;
    for (0..hash[1]) |k| {
        const st = syms[k];
        if ((@as(u32, 1) << @intCast(st.st_info & 0xf)) & ok_types == 0) continue;
        if ((@as(u32, 1) << @intCast(st.st_info >> 4)) & ok_binds == 0) continue;
        if (st.st_shndx == 0) continue;
        if (!std.mem.eql(u8, name, std.mem.sliceTo(strings + st.st_name, 0))) continue;
        if (versym != null and verdef != null and !versionMatches(verdef.?, versym.?[k], version, strings)) continue;
        return b +% st.st_value;
    }
    return 0;
}

fn versionMatches(first: *const std.elf.Verdef, vsym: std.elf.Versym, version: []const u8, strings: [*:0]const u8) bool {
    var def = first;
    while (true) {
        if (def.flags & std.elf.VER_FLG_BASE == 0 and @intFromEnum(def.ndx) == vsym.VERSION) break;
        if (def.next == 0) return false;
        def = @ptrFromInt(@intFromPtr(def) + def.next);
    }
    const aux: *const std.elf.Verdaux = @ptrFromInt(@intFromPtr(def) + def.aux);
    return std.mem.eql(u8, version, std.mem.sliceTo(strings + aux.name, 0));
}

fn slotPtr(i: usize) *anyopaque {
    const page = std.heap.page_size_min;
    const per_page = page / state_len;
    return @ptrCast(base + (i / per_page) * page + (i % per_page) * state_len);
}

/// Fills `buf` from the vDSO and returns true, or returns false having
/// written nothing the caller may use (it must then draw `buf` another way).
pub fn draw(buf: []u8) bool {
    if (!supported) return false;
    switch (state.load(.acquire)) {
        .ready => {},
        .unavailable, .initializing => return false,
        .uninit => {
            if (state.cmpxchgStrong(.uninit, .initializing, .acquire, .acquire) != null) return false;
            init();
            if (state.load(.acquire) != .ready) return false;
        },
    }

    const start: usize = hint;
    var i = start;
    while (true) {
        if (busy[i].cmpxchgWeak(false, true, .acquire, .monotonic) == null) break;
        i = (i + 1) % slot_count;
        if (i == start) return false;
    }
    defer busy[i].store(false, .release);
    hint = @intCast(i);

    const st = slotPtr(i);
    var done: usize = 0;
    while (done < buf.len) {
        const r = func(buf[done..].ptr, buf.len - done, 0, st, state_len);
        if (r <= 0) return false;
        done += @intCast(r);
    }
    return true;
}

test "draw fills the whole buffer, differently each time, on a kernel with the vDSO symbol" {
    if (!supported) return error.SkipZigTest;
    var a: [4096 + 3]u8 = @splat(0);
    if (!draw(&a)) return error.SkipZigTest; // kernel < 6.11 or no symbol
    try std.testing.expectEqual(State.ready, state.load(.acquire));
    var b: [a.len]u8 = @splat(0);
    try std.testing.expect(draw(&b));
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
    // The last bytes are written too, not just whole ChaCha blocks.
    var zero_tail: usize = 0;
    for (0..64) |_| {
        var c: [33]u8 = @splat(0);
        try std.testing.expect(draw(&c));
        if (c[32] == 0) zero_tail += 1;
    }
    try std.testing.expect(zero_tail < 8);
}

test "draw from more threads than slots at once: every buffer filled, no slot left busy" {
    if (!supported) return error.SkipZigTest;
    var probe: [1]u8 = undefined;
    if (!draw(&probe)) return error.SkipZigTest;
    const n_threads = slot_count + 16;
    const Worker = struct {
        fn run(failed: *std.atomic.Value(u32)) void {
            for (0..2000) |_| {
                var buf: [48]u8 = @splat(0);
                // `false` (pool full) is allowed; a short fill reported as true is not.
                if (draw(&buf) and std.mem.allEqual(u8, &buf, 0)) _ = failed.fetchAdd(1, .monotonic);
            }
        }
    };
    var failed: std.atomic.Value(u32) = .init(0);
    var threads: [n_threads]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Worker.run, .{&failed});
    for (threads) |t| t.join();
    try std.testing.expectEqual(@as(u32, 0), failed.load(.monotonic));
    for (&busy) |*f| try std.testing.expect(!f.load(.acquire));
}
