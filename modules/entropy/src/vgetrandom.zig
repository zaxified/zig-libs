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
/// `pub` so a test can stand a scripted function in for the vDSO's (module-internal: root.zig does not re-export this file).
pub var func: VGetRandom = undefined;
var base: [*]u8 = undefined;
var state_len: usize = 0;
/// Length of the mapping `init` made (what a test checks the slots against).
var mapped_len: usize = 0;
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
    const map_len = pages * page;
    const rc = linux.mmap(null, map_len, @bitCast(params.mmap_prot), @bitCast(params.mmap_flags), -1, 0);
    if (linux.errno(rc) != .SUCCESS) return state.store(.unavailable, .release);

    func = f;
    base = @ptrFromInt(rc);
    state_len = size;
    mapped_len = map_len;
    state.store(.ready, .release);
}

/// The address of a versioned vDSO symbol, or 0. std 0.16 has exactly this
/// (`std.os.linux.vdso.lookup`) but does not export it (`const vdso`, not
/// `pub`), so it is restated here: DT_HASH bounds the symbol table, a symbol
/// must be a defined global/weak function or object, and its DT_VERSYM entry
/// must name `version` in DT_VERDEF.
fn vdsoLookup(version: []const u8, name: []const u8) usize {
    const vdso_addr = linux.getauxval(std.elf.AT.SYSINFO_EHDR);
    if (vdso_addr == 0) return 0;
    return vdsoLookupAt(vdso_addr, version, name);
}

/// `vdsoLookup` over the image mapped at `vdso_addr`; split out so the test
/// below can check it against a model that reaches the tables another way.
fn vdsoLookupAt(vdso_addr: usize, version: []const u8, name: []const u8) usize {
    const elf = std.elf;
    const eh: *const elf.Ehdr = @ptrFromInt(vdso_addr);

    var dynv_opt: ?[*]const usize = null;
    var load_base: ?usize = null;
    for (0..eh.e_phnum) |i| {
        const ph: *const elf.ElfN.Phdr = @ptrFromInt(vdso_addr + eh.e_phoff + i * eh.e_phentsize);
        switch (ph.type) {
            // Wrapping: some kernels pre-link the image in the upper half.
            .LOAD => load_base = vdso_addr +% ph.offset -% ph.vaddr,
            .DYNAMIC => dynv_opt = @ptrFromInt(vdso_addr + ph.offset),
            else => {},
        }
    }
    const dynv = dynv_opt orelse return 0;
    const b = load_base orelse return 0;

    var strings_opt: ?[*:0]const u8 = null;
    var syms_opt: ?[*]const elf.Sym = null;
    var hash_opt: ?[*]const linux.Elf_Symndx = null;
    var gnu_hash_opt: ?[*]const u32 = null;
    var versym: ?[*]const elf.Versym = null;
    var verdef: ?*const elf.Verdef = null;
    var i: usize = 0;
    while (dynv[i] != 0) : (i += 2) {
        const p = b +% dynv[i + 1];
        switch (dynv[i]) {
            elf.DT_STRTAB => strings_opt = @ptrFromInt(p),
            elf.DT_SYMTAB => syms_opt = @ptrFromInt(p),
            elf.DT_HASH => hash_opt = @ptrFromInt(p),
            elf.DT_GNU_HASH => gnu_hash_opt = @ptrFromInt(p),
            elf.DT_VERSYM => versym = @ptrFromInt(p),
            elf.DT_VERDEF => verdef = @ptrFromInt(p),
            else => {},
        }
    }
    const strings = strings_opt orelse return 0;
    const syms = syms_opt orelse return 0;
    // The symbol count: DT_HASH's nchain, else walked out of DT_GNU_HASH.
    // std's `os/linux/vdso.zig` reads DT_HASH only, and the arm64 vDSO of
    // the GitHub runner (2026-10-17) has only DT_GNU_HASH -- there std finds
    // no symbol at all and silently falls back to syscalls.
    const nsyms: usize = if (hash_opt) |hash| hash[1] else if (gnu_hash_opt) |gh| gnuHashSymCount(gh) else return 0;

    const ok_types: u32 = 1 << elf.STT_NOTYPE | 1 << elf.STT_OBJECT | 1 << elf.STT_FUNC | 1 << elf.STT_COMMON;
    const ok_binds: u32 = 1 << elf.STB_GLOBAL | 1 << elf.STB_WEAK | 1 << elf.STB_GNU_UNIQUE;
    for (0..nsyms) |k| {
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

/// Symbol count of a DT_GNU_HASH table: one past the highest index any
/// bucket's chain reaches (a chain ends at the entry whose low bit is set);
/// symbols below `symoffset` are not hashed but still counted.
fn gnuHashSymCount(gh: [*]const u32) usize {
    const nbuckets = gh[0];
    const symoffset = gh[1];
    const bloom_words = gh[2]; // ELFCLASS words, `usize` each
    const buckets = gh + 4 + bloom_words * (@sizeOf(usize) / 4);
    const chains = buckets + nbuckets;
    var last: u32 = 0;
    for (0..nbuckets) |k| last = @max(last, buckets[k]);
    if (last < symoffset) return symoffset;
    while (chains[last - symoffset] & 1 == 0) last += 1;
    return last + 1;
}

fn versionMatches(first: *const std.elf.Verdef, vsym: std.elf.Versym, version: []const u8, strings: [*:0]const u8) bool {
    var def = first;
    while (true) {
        if (def.flags & std.elf.VER_FLG_BASE == 0 and @backingInt(def.ndx) == vsym.VERSION) break;
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

/// True where `draw` must succeed: this build takes the vDSO path and the
/// running kernel exports the symbol (6.11+). Tests gate on this instead of on
/// `draw` returning false, which would also let a broken `draw` skip them.
pub fn symbolPresent() bool {
    return supported and vdsoLookup(sym.?.version, sym.?.name) != 0;
}

/// Why `vdsoLookupAt` missed a symbol the model found: replays its walk and
/// prints the step that rejected it. Seen only on the arm64 CI runner
/// (Neoverse-N2, 2026-10-17: lookup 0, model 0xff703f383948); qemu-user
/// maps its own vDSO and passes, so the runner's log is the only witness.
fn diagLookup(vdso_addr: usize, s: ModelSym) void {
    const elf = std.elf;
    const eh: *const elf.Ehdr = @ptrFromInt(vdso_addr);
    std.debug.print("vdso diag: {s}@{s} model 0x{x} (vdso 0x{x}, phnum {d})\n", .{ s.name, s.version, s.addr, vdso_addr, eh.e_phnum });
    var dynv_opt: ?[*]const usize = null;
    var load_base: ?usize = null;
    for (0..eh.e_phnum) |i| {
        const ph: *const elf.ElfN.Phdr = @ptrFromInt(vdso_addr + eh.e_phoff + i * eh.e_phentsize);
        std.debug.print("vdso diag:   phdr {d} type 0x{x} off 0x{x} vaddr 0x{x}\n", .{ i, ph.type, ph.offset, ph.vaddr });
        switch (ph.type) {
            .LOAD => load_base = vdso_addr +% ph.offset -% ph.vaddr,
            .DYNAMIC => dynv_opt = @ptrFromInt(vdso_addr + ph.offset),
            else => {},
        }
    }
    const dynv = dynv_opt orelse return std.debug.print("vdso diag:   no PT_DYNAMIC\n", .{});
    const b = load_base orelse return std.debug.print("vdso diag:   no PT_LOAD\n", .{});
    var strings_opt: ?[*:0]const u8 = null;
    var syms_opt: ?[*]const elf.Sym = null;
    var hash_opt: ?[*]const linux.Elf_Symndx = null;
    var versym: ?[*]const elf.Versym = null;
    var verdef: ?*const elf.Verdef = null;
    var i: usize = 0;
    while (dynv[i] != 0) : (i += 2) {
        std.debug.print("vdso diag:   dyn tag 0x{x} val 0x{x}\n", .{ dynv[i], dynv[i + 1] });
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
    const strings = strings_opt orelse return std.debug.print("vdso diag:   no DT_STRTAB\n", .{});
    const syms = syms_opt orelse return std.debug.print("vdso diag:   no DT_SYMTAB\n", .{});
    const hash = hash_opt orelse return std.debug.print("vdso diag:   no DT_HASH (only a GNU hash?)\n", .{});
    std.debug.print("vdso diag:   nchain {d}, base 0x{x}\n", .{ hash[1], b });
    for (0..hash[1]) |k| {
        const st = syms[k];
        if (!std.mem.eql(u8, s.name, std.mem.sliceTo(strings + st.st_name, 0))) continue;
        const vok = versym == null or verdef == null or versionMatches(verdef.?, versym.?[k], s.version, strings);
        std.debug.print("vdso diag:   sym {d}: info 0x{x} shndx {d} value 0x{x} versym 0x{x} version ok {}\n", .{
            k, st.st_info, st.st_shndx, st.st_value, if (versym) |v| @as(u16, @bitCast(v[k])) else 0, vok,
        });
    }
}

/// One exported symbol as the model sees it.
const ModelSym = struct { name: []const u8, version: []const u8, addr: usize };

/// Reference model for `vdsoLookupAt`, reaching the same tables by another
/// route: the SECTION header table (SHT_DYNSYM, its sh_link string table,
/// SHT_GNU_VERSYM, SHT_GNU_VERDEF) instead of PT_DYNAMIC + DT_HASH, every
/// read bounds-checked through a slice and copied out unaligned, the load
/// bias taken from the symbol table section's sh_offset − sh_addr instead of
/// PT_LOAD. Shared with the implementation is only the ELF gABI rule for
/// which symbol a versioned lookup may bind (defined, global/weak/unique,
/// a data or code type, the non-base version definition named). The kernel
/// maps its whole vDSO image, section headers included.
fn modelSymbols(vdso_addr: usize, out: []ModelSym) []ModelSym {
    const elf = std.elf;
    const head: [*]const u8 = @ptrFromInt(vdso_addr);
    const eh = std.mem.bytesToValue(elf.Elf64_Ehdr, head[0..@sizeOf(elf.Elf64_Ehdr)]);
    const img = head[0 .. eh.e_shoff + @as(usize, eh.e_shnum) * eh.e_shentsize];
    const shdr = struct {
        fn at(image: []const u8, e: elf.Elf64_Ehdr, i: usize) elf.Elf64_Shdr {
            const off = e.e_shoff + i * e.e_shentsize;
            return std.mem.bytesToValue(elf.Elf64_Shdr, image[off..][0..@sizeOf(elf.Elf64_Shdr)]);
        }
    }.at;
    const cstr = struct {
        fn at(image: []const u8, table: elf.Elf64_Shdr, off: usize) []const u8 {
            const s = image[table.sh_offset..][0..table.sh_size];
            return std.mem.sliceTo(s[off..], 0);
        }
    }.at;

    var dynsym: ?elf.Elf64_Shdr = null;
    var versym: ?elf.Elf64_Shdr = null;
    var verdef: ?elf.Elf64_Shdr = null;
    for (0..eh.e_shnum) |i| {
        const sh = shdr(img, eh, i);
        switch (sh.sh_type) {
            elf.SHT_DYNSYM => dynsym = sh,
            elf.SHT_GNU_VERSYM => versym = sh,
            elf.SHT_GNU_VERDEF => verdef = sh,
            else => {},
        }
    }
    const ds = dynsym orelse return out[0..0];
    const strtab = shdr(img, eh, ds.sh_link);
    const bias = vdso_addr +% ds.sh_offset -% ds.sh_addr;

    var n: usize = 0;
    for (0..ds.sh_size / ds.sh_entsize) |k| {
        const st = std.mem.bytesToValue(elf.Elf64_Sym, img[ds.sh_offset + k * ds.sh_entsize ..][0..@sizeOf(elf.Elf64_Sym)]);
        const bind = st.st_info >> 4;
        const typ = st.st_info & 0xf;
        if (st.st_shndx == elf.SHN_UNDEF) continue;
        if (bind != elf.STB_GLOBAL and bind != elf.STB_WEAK and bind != elf.STB_GNU_UNIQUE) continue;
        if (typ != elf.STT_NOTYPE and typ != elf.STT_OBJECT and typ != elf.STT_FUNC and typ != elf.STT_COMMON) continue;
        // Unversioned images: the implementation skips the version check, so
        // the model reports an empty version and the test passes any string.
        var ver: []const u8 = "";
        if (versym != null and verdef != null) {
            const vs = std.mem.readInt(u16, img[versym.?.sh_offset + k * 2 ..][0..2], .little) & 0x7fff;
            var off: usize = verdef.?.sh_offset;
            var found = false;
            for (0..verdef.?.sh_info) |_| {
                const vd = std.mem.bytesToValue(elf.Verdef, img[off..][0..@sizeOf(elf.Verdef)]);
                if (vd.flags & elf.VER_FLG_BASE == 0 and @backingInt(vd.ndx) == vs) {
                    const aux = std.mem.bytesToValue(elf.Verdaux, img[off + vd.aux ..][0..@sizeOf(elf.Verdaux)]);
                    ver = cstr(img, strtab, aux.name);
                    found = true;
                    break;
                }
                off += vd.next;
            }
            if (!found) continue;
        }
        if (n == out.len) break;
        out[n] = .{ .name = cstr(img, strtab, st.st_name), .version = ver, .addr = bias +% st.st_value };
        n += 1;
    }
    return out[0..n];
}

test "vdsoLookup agrees with the section-table model on every exported vDSO symbol" {
    if (builtin.os.tag != .linux or @sizeOf(usize) != 8) return error.SkipZigTest;
    const vdso_addr = linux.getauxval(std.elf.AT.SYSINFO_EHDR);
    if (vdso_addr == 0) return error.SkipZigTest;
    var buf: [256]ModelSym = undefined;
    const syms = modelSymbols(vdso_addr, &buf);
    // x86_64 Linux 7.0 exports 14 (clock_gettime, time, getcpu, getrandom, ...
    // each under two names); a model that finds next to nothing is broken.
    try std.testing.expect(syms.len >= 4);

    var saw_getrandom = false;
    for (syms) |s| {
        const got = vdsoLookupAt(vdso_addr, s.version, s.name);
        if (got != s.addr) diagLookup(vdso_addr, s);
        try std.testing.expectEqual(s.addr, got);
        // Right name, wrong version: never bound.
        try std.testing.expectEqual(@as(usize, 0), vdsoLookupAt(vdso_addr, "LINUX_0.0", s.name));
        if (s.version.len != 0 and sym != null and std.mem.eql(u8, s.name, sym.?.name)) saw_getrandom = true;
    }
    try std.testing.expectEqual(@as(usize, 0), vdsoLookupAt(vdso_addr, syms[0].version, "__vdso_no_such_symbol"));
    // The base version definition (the image's own soname) names no symbol.
    try std.testing.expectEqual(@as(usize, 0), vdsoLookupAt(vdso_addr, "linux-vdso.so.1", syms[0].name));
    // The symbol `init` binds is among them where the kernel has it (6.11+);
    // the agreement above then covers the address `draw` will call.
    if (sym != null and vdsoLookup(sym.?.version, sym.?.name) != 0) try std.testing.expect(saw_getrandom);
    // `vdsoLookup` (the auxv entry, not an address passed in) lands on the model's address for it.
    if (sym) |want| for (syms) |s| {
        if (std.mem.eql(u8, s.name, want.name) and std.mem.eql(u8, s.version, want.version))
            try std.testing.expectEqual(s.addr, vdsoLookup(want.version, want.name));
    };
}

test "draw fills the whole buffer, differently each time, on a kernel with the vDSO symbol" {
    if (!supported) return error.SkipZigTest;
    if (!symbolPresent()) return error.SkipZigTest; // kernel < 6.11 or no symbol
    var a: [4096 + 3]u8 = @splat(0);
    try std.testing.expect(draw(&a));
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
    if (!symbolPresent()) return error.SkipZigTest;
    var probe: [1]u8 = undefined;
    try std.testing.expect(draw(&probe));
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

test "gnuHashSymCount agrees with DT_HASH's nchain where the vDSO carries both" {
    if (builtin.os.tag != .linux or @sizeOf(usize) != 8) return error.SkipZigTest;
    const vdso_addr = linux.getauxval(std.elf.AT.SYSINFO_EHDR);
    if (vdso_addr == 0) return error.SkipZigTest;
    const elf = std.elf;
    const eh: *const elf.Ehdr = @ptrFromInt(vdso_addr);
    var dynv_opt: ?[*]const usize = null;
    var load_base: ?usize = null;
    for (0..eh.e_phnum) |i| {
        const ph: *const elf.ElfN.Phdr = @ptrFromInt(vdso_addr + eh.e_phoff + i * eh.e_phentsize);
        switch (ph.type) {
            .LOAD => load_base = vdso_addr +% ph.offset -% ph.vaddr,
            .DYNAMIC => dynv_opt = @ptrFromInt(vdso_addr + ph.offset),
            else => {},
        }
    }
    const dynv = dynv_opt orelse return error.SkipZigTest;
    const b = load_base orelse return error.SkipZigTest;
    var hash: ?[*]const linux.Elf_Symndx = null;
    var gnu: ?[*]const u32 = null;
    var i: usize = 0;
    while (dynv[i] != 0) : (i += 2) switch (dynv[i]) {
        elf.DT_HASH => hash = @ptrFromInt(b +% dynv[i + 1]),
        elf.DT_GNU_HASH => gnu = @ptrFromInt(b +% dynv[i + 1]),
        else => {},
    };
    if (hash == null or gnu == null) return error.SkipZigTest; // arm64: GNU only, covered by the model test
    try std.testing.expectEqual(@as(usize, hash.?[1]), gnuHashSymCount(gnu.?));
}

// ── tests of the pool and the draw loop (whole-module mutation, 2026-11-17) ──

test "draw succeeds wherever the kernel exports the vDSO symbol, and the pool is set up" {
    if (!symbolPresent()) return error.SkipZigTest;
    var buf: [48]u8 = @splat(0);
    try std.testing.expect(draw(&buf));
    try std.testing.expect(!std.mem.allEqual(u8, &buf, 0));
    try std.testing.expectEqual(State.ready, state.load(.acquire));
    try std.testing.expect(state_len != 0 and state_len <= std.heap.page_size_min);
}

test "every slot's state lies whole inside the mapping, apart from the others, and draws" {
    if (!symbolPresent()) return error.SkipZigTest;
    var probe: [1]u8 = undefined;
    try std.testing.expect(draw(&probe));
    const page = std.heap.page_size_min;
    var prev_end: usize = 0;
    // The mapping is exactly the pages the slots need: the last slot ends in the
    // last page, and no page past it was mapped. (A neighbouring mapping would
    // hide a short one from a fault test.)
    const last_end = @intFromPtr(slotPtr(slot_count - 1)) - @intFromPtr(base) + state_len;
    try std.testing.expectEqual(std.mem.alignForward(usize, last_end, page), mapped_len);
    for (0..slot_count) |i| {
        const off = @intFromPtr(slotPtr(i)) - @intFromPtr(base);
        try std.testing.expect(off >= prev_end); // no two states overlap
        try std.testing.expect(off % page + state_len <= page); // none straddles a page
        prev_end = off + state_len;
        // Claim the slot so no other draw uses it, then draw on its state:
        // a mapping that stops short of it faults here.
        try std.testing.expect(!busy[i].swap(true, .acquire));
        defer busy[i].store(false, .release);
        var out: [32]u8 = @splat(0);
        const r = func(&out, out.len, 0, slotPtr(i), state_len);
        try std.testing.expectEqual(@as(isize, out.len), r);
        try std.testing.expect(!std.mem.allEqual(u8, &out, 0));
    }
}

test "draw refuses while the pool is initializing or unavailable, and writes nothing" {
    if (!symbolPresent()) return error.SkipZigTest;
    var probe: [1]u8 = undefined;
    try std.testing.expect(draw(&probe));
    defer state.store(.ready, .release);
    inline for (.{ State.initializing, State.unavailable }) |s| {
        state.store(s, .release);
        var buf: [16]u8 = @splat(0xa5);
        try std.testing.expect(!draw(&buf));
        try std.testing.expect(std.mem.allEqual(u8, &buf, 0xa5));
    }
}

test "draw from the uninitialised state runs init and then draws" {
    if (!symbolPresent()) return error.SkipZigTest;
    var probe: [1]u8 = undefined;
    try std.testing.expect(draw(&probe));
    const old_base = base;
    state.store(.uninit, .release);
    var buf: [16]u8 = @splat(0);
    try std.testing.expect(draw(&buf));
    try std.testing.expectEqual(State.ready, state.load(.acquire));
    try std.testing.expect(base != old_base); // a fresh mapping: init ran again
    try std.testing.expect(!std.mem.allEqual(u8, &buf, 0));
}

test "draw scans from the hint, wraps at slot_count, and gives up when every slot is taken" {
    if (!symbolPresent()) return error.SkipZigTest;
    var probe: [1]u8 = undefined;
    try std.testing.expect(draw(&probe));
    for (&busy) |*f| f.store(true, .release);
    defer for (&busy) |*f| f.store(false, .release);
    defer hint = 0;

    // Every slot taken: false, nothing written, no flag disturbed.
    hint = 5;
    var buf: [16]u8 = @splat(0xa5);
    try std.testing.expect(!draw(&buf));
    try std.testing.expect(std.mem.allEqual(u8, &buf, 0xa5));
    for (&busy) |*f| try std.testing.expect(f.load(.acquire));

    // One free slot below the hint: found after the wrap, remembered, released.
    busy[3].store(false, .release);
    hint = 60;
    try std.testing.expect(draw(&buf));
    try std.testing.expectEqual(@as(u8, 3), hint);
    try std.testing.expect(!busy[3].load(.acquire));
    for (&busy, 0..) |*f, i| if (i != 3) try std.testing.expect(f.load(.acquire));

    // An odd distance away: a scan that steps by two never gets there.
    busy[3].store(false, .release);
    hint = 4;
    try std.testing.expect(draw(&buf));
    try std.testing.expectEqual(@as(u8, 3), hint);

    // Two free slots: the scan starts at the hint, so the one at the hint wins.
    busy[3].store(false, .release);
    busy[40].store(false, .release);
    hint = 40;
    buf = @splat(0);
    try std.testing.expect(draw(&buf));
    try std.testing.expectEqual(@as(u8, 40), hint);
    try std.testing.expect(!std.mem.allEqual(u8, &buf, 0));
}

/// A scripted stand-in for the vDSO function: records every call and writes
/// `0xc0 + call index` into the bytes it claims to have produced.
const Script = struct {
    var returns: []const isize = &.{};
    var calls: usize = 0;
    var bufs: [8]usize = undefined;
    var lens: [8]usize = undefined;
    var flags: [8]u32 = undefined;
    var states: [8]usize = undefined;
    var state_lens: [8]usize = undefined;

    fn reset(rets: []const isize) void {
        returns = rets;
        calls = 0;
    }

    fn call(buf: ?*anyopaque, len: usize, fl: u32, st: ?*anyopaque, st_len: usize) callconv(.c) isize {
        const i = calls;
        calls += 1;
        bufs[i] = @intFromPtr(buf);
        lens[i] = len;
        flags[i] = fl;
        states[i] = @intFromPtr(st);
        state_lens[i] = st_len;
        const r = if (i < returns.len) returns[i] else 0;
        if (r > 0) @memset(@as([*]u8, @ptrCast(buf.?))[0..@intCast(r)], @as(u8, 0xc0) + @as(u8, @intCast(i)));
        return r;
    }
};

test "draw loops over short returns from the vDSO function, at the right offsets" {
    if (!symbolPresent()) return error.SkipZigTest;
    var probe: [1]u8 = undefined;
    try std.testing.expect(draw(&probe));
    const real = func;
    defer func = real;
    func = Script.call;
    defer hint = 0;

    // 20 bytes delivered as 7 + 7 + 6.
    hint = 7;
    Script.reset(&.{ 7, 7, 6 });
    var buf: [20]u8 = @splat(0);
    try std.testing.expect(draw(&buf));
    try std.testing.expectEqual(@as(usize, 3), Script.calls);
    var off: usize = 0;
    for ([_]usize{ 7, 7, 6 }, 0..) |n, i| {
        try std.testing.expectEqual(@intFromPtr(&buf) + off, Script.bufs[i]);
        try std.testing.expectEqual(buf.len - off, Script.lens[i]);
        try std.testing.expectEqual(@as(u32, 0), Script.flags[i]);
        try std.testing.expectEqual(@intFromPtr(slotPtr(7)), Script.states[i]);
        try std.testing.expectEqual(state_len, Script.state_lens[i]);
        for (buf[off..][0..n]) |b| try std.testing.expectEqual(@as(u8, 0xc0) + @as(u8, @intCast(i)), b);
        off += n;
    }

    // A single byte at a time is still progress.
    Script.reset(&.{ 1, 19 });
    buf = @splat(0);
    try std.testing.expect(draw(&buf));
    try std.testing.expectEqual(@as(usize, 2), Script.calls);
    try std.testing.expectEqual(@as(u8, 0xc0), buf[0]);
    try std.testing.expectEqual(@as(u8, 0xc1), buf[1]);
    try std.testing.expectEqual(@as(u8, 0xc1), buf[19]);

    // Zero bytes or an error ends the draw at once, reported as false.
    Script.reset(&.{ 0, 20 });
    try std.testing.expect(!draw(&buf));
    try std.testing.expectEqual(@as(usize, 1), Script.calls);
    Script.reset(&.{ 5, -1 });
    try std.testing.expect(!draw(&buf));
    try std.testing.expectEqual(@as(usize, 2), Script.calls);
    // A buffer filled exactly by one call is not asked for more.
    Script.reset(&.{20});
    try std.testing.expect(draw(&buf));
    try std.testing.expectEqual(@as(usize, 1), Script.calls);
    // No slot stays taken after any of it.
    for (&busy) |*f| try std.testing.expect(!f.load(.acquire));
}

// ── a synthetic vDSO image: the paths the real one cannot reach ──────────────

/// A tiny ELF64 little-endian image in memory, laid out so every table sits at
/// a fixed offset, with the options a test varies. The real vDSO is linked at
/// 0 (`p_vaddr == p_offset`), carries both hash tables and defines every
/// symbol, so it cannot tell a load bias from the image address, a hash table
/// from the other, or a defined symbol from an undefined one.
const Synth = struct {
    img: [2048]u8 align(16) = @splat(0),

    const ph_at = 64;
    const dyn_at = 0x100;
    const str_at = 0x200;
    const sym_at = 0x300;
    const hash_at = 0x500;
    const gnu_at = 0x540;
    const versym_at = 0x600;
    const verdef_at = 0x680;
    /// `target` at 1, `V1` at 8, `base` at 11 in the string table.
    const target = "target";
    const sym_value = 0x40;

    const Opts = struct {
        load_vaddr: u64 = 0x1000,
        dyn_vaddr: u64 = 0x7000,
        load: bool = true,
        dynamic: bool = true,
        strtab: bool = true,
        symtab: bool = true,
        hash_nchain: ?u32 = 4,
        gnu_count: ?u32 = null,
        versym: bool = false,
        verdef: bool = false,
        sym_type: u8 = 2, // STT_FUNC
        sym_bind: u8 = 1, // STB_GLOBAL
        sym_shndx: u16 = 1,
        sym_index: usize = 1,
    };

    fn put(s: *Synth, comptime T: type, at: usize, v: T) void {
        std.mem.writeInt(T, s.img[at..][0..@sizeOf(T)], v, .little);
    }

    fn build(o: Opts) Synth {
        var s: Synth = .{};
        // ELF header: e_phoff @32, e_phentsize @54, e_phnum @56.
        s.put(u64, 32, ph_at);
        s.put(u16, 54, 56);
        var n: u16 = 0;
        if (o.load) { // PT_LOAD, p_offset 0, p_vaddr
            s.put(u32, ph_at + 56 * n, 1);
            s.put(u64, ph_at + 56 * n + 8, 0);
            s.put(u64, ph_at + 56 * n + 16, o.load_vaddr);
            n += 1;
        }
        if (o.dynamic) { // PT_DYNAMIC: p_offset is where the array really is, p_vaddr somewhere else
            s.put(u32, ph_at + 56 * n, 2);
            s.put(u64, ph_at + 56 * n + 8, dyn_at);
            s.put(u64, ph_at + 56 * n + 16, o.dyn_vaddr);
            n += 1;
        }
        s.put(u16, 56, n);

        @memcpy(s.img[str_at + 1 ..][0..target.len], target);
        @memcpy(s.img[str_at + 8 ..][0..2], "V1");
        @memcpy(s.img[str_at + 11 ..][0..4], "base");

        const sym_off = sym_at + 24 * o.sym_index;
        s.put(u32, sym_off, 1);
        s.img[sym_off + 4] = (o.sym_bind << 4) | o.sym_type;
        s.put(u16, sym_off + 6, o.sym_shndx);
        s.put(u64, sym_off + 8, sym_value);

        if (o.hash_nchain) |c| {
            s.put(u32, hash_at, 1);
            s.put(u32, hash_at + 4, c);
        }
        if (o.gnu_count) |c| { // nbuckets 1, symoffset 1, one bloom word; chain ends at the last symbol
            s.put(u32, gnu_at, 1);
            s.put(u32, gnu_at + 4, 1);
            s.put(u32, gnu_at + 8, 1);
            s.put(u32, gnu_at + 24, 1); // bucket 0 starts at symbol 1
            for (0..c - 1) |k| s.put(u32, gnu_at + 28 + 4 * k, if (k == c - 2) 1 else 0);
        }
        if (o.versym) s.put(u16, versym_at + 2 * o.sym_index, 2);
        if (o.verdef) {
            // def 1: the image's own (BASE) definition, index 1, aux "base"; def 2: index 2, aux "V1".
            s.put(u16, verdef_at + 2, 1);
            s.put(u16, verdef_at + 4, 1);
            s.put(u32, verdef_at + 12, 20);
            s.put(u32, verdef_at + 16, 28);
            s.put(u32, verdef_at + 20, 11);
            s.put(u16, verdef_at + 28 + 2, 0);
            s.put(u16, verdef_at + 28 + 4, 2);
            s.put(u32, verdef_at + 28 + 12, 20);
            s.put(u32, verdef_at + 28 + 20, 8);
        }

        var d: usize = 0;
        const v = o.load_vaddr; // dynamic values are addresses: bias + file offset
        const tags = [_]struct { on: bool, tag: usize, at: usize }{
            .{ .on = o.strtab, .tag = std.elf.DT_STRTAB, .at = str_at },
            .{ .on = o.symtab, .tag = std.elf.DT_SYMTAB, .at = sym_at },
            .{ .on = o.hash_nchain != null, .tag = std.elf.DT_HASH, .at = hash_at },
            .{ .on = o.gnu_count != null, .tag = std.elf.DT_GNU_HASH, .at = gnu_at },
            .{ .on = o.versym, .tag = std.elf.DT_VERSYM, .at = versym_at },
            .{ .on = o.verdef, .tag = std.elf.DT_VERDEF, .at = verdef_at },
        };
        for (tags) |t| if (t.on) {
            s.put(u64, dyn_at + 16 * d, t.tag);
            s.put(u64, dyn_at + 16 * d + 8, v + @as(u64, t.at));
            d += 1;
        };
        return s;
    }

    fn lookup(s: *const Synth, version: []const u8) usize {
        return vdsoLookupAt(@intFromPtr(&s.img), version, target);
    }

    fn expected(s: *const Synth, o: Opts) usize {
        return @intFromPtr(&s.img) -% o.load_vaddr +% sym_value;
    }
};

fn synthSupported() bool {
    return builtin.os.tag == .linux and @sizeOf(usize) == 8 and builtin.cpu.arch.endian() == .little;
}

test "vdsoLookupAt on a synthetic image: load bias, dynamic section and symbol address" {
    if (!synthSupported()) return error.SkipZigTest;
    const o: Synth.Opts = .{};
    const s = Synth.build(o);
    try std.testing.expectEqual(s.expected(o), s.lookup(""));
    // p_vaddr 0 (the real vDSO) is the same arithmetic with a zero bias.
    const o0: Synth.Opts = .{ .load_vaddr = 0 };
    const s0 = Synth.build(o0);
    try std.testing.expectEqual(s0.expected(o0), s0.lookup(""));
    // Each table the walk needs is needed.
    const missing = [_]Synth.Opts{
        .{ .load = false }, .{ .dynamic = false }, .{ .strtab = false }, .{ .symtab = false },
        .{ .hash_nchain = null }, // neither hash table: no symbol count
    };
    for (missing) |m| try std.testing.expectEqual(@as(usize, 0), Synth.build(m).lookup(""));
}

test "vdsoLookupAt on a synthetic image: which symbols may bind" {
    if (!synthSupported()) return error.SkipZigTest;
    // Types: NOTYPE 0, OBJECT 1, FUNC 2, COMMON 5 bind; SECTION 3, FILE 4, TLS 6, IFUNC 10 do not.
    for ([_]u8{ 0, 1, 2, 5 }) |t| {
        const o: Synth.Opts = .{ .sym_type = t };
        const s = Synth.build(o);
        try std.testing.expectEqual(s.expected(o), s.lookup(""));
    }
    for ([_]u8{ 3, 4, 6, 10 }) |t| try std.testing.expectEqual(@as(usize, 0), Synth.build(.{ .sym_type = t }).lookup(""));
    // Binds: GLOBAL 1, WEAK 2, GNU_UNIQUE 10 bind; LOCAL 0 and 3 do not.
    for ([_]u8{ 1, 2, 10 }) |b| {
        const o: Synth.Opts = .{ .sym_bind = b };
        const s = Synth.build(o);
        try std.testing.expectEqual(s.expected(o), s.lookup(""));
    }
    for ([_]u8{ 0, 3 }) |b| try std.testing.expectEqual(@as(usize, 0), Synth.build(.{ .sym_bind = b }).lookup(""));
    // An undefined symbol (section index 0) never binds.
    try std.testing.expectEqual(@as(usize, 0), Synth.build(.{ .sym_shndx = 0 }).lookup(""));
}

test "vdsoLookupAt on a synthetic image: the symbol count comes from DT_HASH first, else DT_GNU_HASH" {
    if (!synthSupported()) return error.SkipZigTest;
    // The target is symbol 3: DT_HASH says 4 symbols, DT_GNU_HASH says 2. DT_HASH wins.
    const both: Synth.Opts = .{ .hash_nchain = 4, .gnu_count = 2, .sym_index = 3 };
    const sb = Synth.build(both);
    try std.testing.expectEqual(sb.expected(both), sb.lookup(""));
    // GNU hash alone (the arm64 vDSO): 4 symbols walked out of the chains.
    const gnu: Synth.Opts = .{ .hash_nchain = null, .gnu_count = 4, .sym_index = 3 };
    const sg = Synth.build(gnu);
    try std.testing.expectEqual(sg.expected(gnu), sg.lookup(""));
    // ...and a count that stops short of the symbol does not find it.
    try std.testing.expectEqual(@as(usize, 0), Synth.build(.{ .hash_nchain = 3, .sym_index = 3 }).lookup(""));
    try std.testing.expectEqual(@as(usize, 0), Synth.build(.{ .hash_nchain = null, .gnu_count = 3, .sym_index = 3 }).lookup(""));
}

test "vdsoLookupAt on a synthetic image: the version check needs both DT_VERSYM and DT_VERDEF" {
    if (!synthSupported()) return error.SkipZigTest;
    const o: Synth.Opts = .{ .versym = true, .verdef = true };
    const s = Synth.build(o);
    try std.testing.expectEqual(s.expected(o), s.lookup("V1"));
    try std.testing.expectEqual(@as(usize, 0), s.lookup("V2"));
    try std.testing.expectEqual(@as(usize, 0), s.lookup("base")); // the base definition names no symbol
    // Only one of the two tables: the check is skipped, whatever version is asked for.
    const only_versym: Synth.Opts = .{ .versym = true };
    const sv = Synth.build(only_versym);
    try std.testing.expectEqual(sv.expected(only_versym), sv.lookup("V9"));
    const only_verdef: Synth.Opts = .{ .verdef = true };
    const sd = Synth.build(only_verdef);
    try std.testing.expectEqual(sd.expected(only_verdef), sd.lookup("V9"));
}

test "versionMatches skips the BASE definition and needs the index and the name to agree" {
    if (!synthSupported()) return error.SkipZigTest;
    const s = Synth.build(.{ .versym = true, .verdef = true });
    const first: *const std.elf.Verdef = @ptrCast(@alignCast(&s.img[Synth.verdef_at]));
    const strings: [*:0]const u8 = @ptrCast(&s.img[Synth.str_at]);
    const v1: std.elf.Versym = .{ .VERSION = 1, .HIDDEN = false };
    const v2: std.elf.Versym = .{ .VERSION = 2, .HIDDEN = false };
    const v3: std.elf.Versym = .{ .VERSION = 3, .HIDDEN = false };
    try std.testing.expect(versionMatches(first, v2, "V1", strings));
    try std.testing.expect(!versionMatches(first, v2, "base", strings)); // index found, name differs
    try std.testing.expect(!versionMatches(first, v1, "base", strings)); // index 1 is the BASE definition: never matched
    try std.testing.expect(!versionMatches(first, v1, "V1", strings));
    try std.testing.expect(!versionMatches(first, v3, "V1", strings)); // no such index: end of chain
}

test "gnuHashSymCount: one past the last chain entry, symbols below symoffset counted" {
    // nbuckets 1, symoffset 2, bloom_words 1 (a 64-bit word = 2 u32), shift 0.
    const eq = std.testing.expectEqual;
    var t = [_]u32{ 1, 2, 1, 0, 0, 0, 2, 1 }; // bucket 0 starts at symbol 2, chain[0] ends it
    try eq(@as(usize, 3), gnuHashSymCount(&t));
    t[6] = 0; // an empty bucket: only the unhashed symbols below symoffset
    try eq(@as(usize, 2), gnuHashSymCount(&t));
    t[6] = 1; // a bucket start below symoffset is clamped the same way
    try eq(@as(usize, 2), gnuHashSymCount(&t));
    // The chain from symbol 3 walks two entries before its end bit: symbols 3 and 4.
    var longer = [_]u32{ 1, 2, 1, 0, 0, 0, 3, 0, 0, 1 };
    try eq(@as(usize, 5), gnuHashSymCount(&longer));
}
