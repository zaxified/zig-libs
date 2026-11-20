// SPDX-License-Identifier: MIT
//! USDT (SystemTap `<sys/sdt.h>`) probe discovery: find the probes an ELF
//! executable or shared object carries and turn each into what a uprobe attach
//! needs, a **file offset** and, when the probe is guarded by a semaphore, the
//! semaphore's file offset (`UprobeOptions.ref_ctr_offset`).
//!
//! ## The note format
//!
//! Every `STAP_PROBE` leaves one `NT_STAPSDT` (type 3, owner `"stapsdt"`) note
//! in `.note.stapsdt`. Its descriptor is three native-width words, `pc` (the
//! address of the probe's `nop`), `base` (the address `_.stapsdt.base` had when
//! the note was written) and `semaphore` (0 when there is none), followed by
//! three NUL-terminated strings: provider, name and the argument descriptor
//! (`"-4@%edi 8@-8(%rbp)"`, possibly empty). Note name and descriptor are each
//! padded to 4 bytes. ELF64 only, as everywhere in `elfsym`.
//!
//! ## Prelink
//!
//! `pc` and `semaphore` are link-time addresses; a tool such as `prelink` moves
//! sections without rewriting the notes, which is what `base` is for: the
//! difference between the `.stapsdt.base` section's *current* address and the
//! `base` recorded in the note is added to both (libbpf and `perf` do the same).
//! Without a `.stapsdt.base` section or with `base == 0` the addresses are used
//! as written.
//!
//! ## From address to file offset
//!
//! An address is converted through the allocated, file-backed section that
//! contains it (`file_offset = sh_offset + (addr - sh_addr)`), the same
//! mapping a `PT_LOAD` segment gives for a section; an address in `.bss` (no
//! file bytes) or outside every section is `error.UnmappedAddress`.
//!
//! ## Arguments
//!
//! `Probe.args` is the raw descriptor and `Probe.argIter()` splits it into
//! `{ size, signed, location }` triples (the `-4@` / `8@` prefix is the byte
//! size, negative meaning signed). Decoding `location` (`%edi`, `-8(%rbp)`,
//! `$5`) is architecture-specific and left to the caller.

const std = @import("std");
const builtin = @import("builtin");

const elfsym = @import("elfsym.zig");

pub const Error = error{
    /// A note whose lengths run past the section, or whose descriptor is too
    /// short or has no three strings.
    MalformedNote,
    /// A probe or semaphore address that no allocated, file-backed section holds.
    UnmappedAddress,
    OutOfMemory,
} || elfsym.ImageError || elfsym.ImageOpenError;

/// One probe site. A probe declared in an inlined function appears once per
/// site: `find` yields them all.
pub const Probe = struct {
    provider: []const u8,
    name: []const u8,
    /// The raw argument descriptor (empty for a probe without arguments).
    args: []const u8,
    /// The probe's address after the prelink adjustment.
    address: u64,
    /// Where to put the uprobe: the offset of `address` in the file.
    file_offset: u64,
    /// The semaphore's file offset (`ref_ctr_offset`), if the probe has one.
    semaphore_offset: ?u64,

    pub fn argIter(self: Probe) ArgIter {
        return .{ .it = std.mem.tokenizeScalar(u8, self.args, ' ') };
    }
};

pub const Arg = struct {
    /// Width in bytes.
    size: u8,
    signed: bool,
    /// The location text after `@`: register, memory operand or immediate, in
    /// the target architecture's assembler syntax.
    location: []const u8,
};

pub const ArgIter = struct {
    it: std.mem.TokenIterator(u8, .scalar),

    /// The next argument, or `null`. A token that is not `size@location` ends
    /// the walk with `error.MalformedNote`.
    pub fn next(self: *ArgIter) error{MalformedNote}!?Arg {
        const tok = self.it.next() orelse return null;
        const at = std.mem.findScalar(u8, tok, '@') orelse return error.MalformedNote;
        const n = std.fmt.parseInt(i8, tok[0..at], 10) catch return error.MalformedNote;
        if (n == 0 or n == std.math.minInt(i8)) return error.MalformedNote;
        return .{
            .size = @intCast(@abs(n)),
            .signed = n < 0,
            .location = tok[at + 1 ..],
        };
    }
};

/// The probes of one binary. Strings point into the owned copy of the image.
pub const ProbeSet = struct {
    gpa: std.mem.Allocator,
    image: elfsym.Image,
    probes: []Probe,

    pub fn deinit(self: *ProbeSet) void {
        self.gpa.free(self.probes);
        self.image.deinit();
        self.* = undefined;
    }

    /// Every site of `provider:name`.
    pub fn find(self: *const ProbeSet, provider: []const u8, name: []const u8) FindIter {
        return .{ .probes = self.probes, .provider = provider, .name = name };
    }
};

pub const FindIter = struct {
    probes: []const Probe,
    provider: []const u8,
    name: []const u8,
    i: usize = 0,

    pub fn next(self: *FindIter) ?Probe {
        while (self.i < self.probes.len) {
            const p = self.probes[self.i];
            self.i += 1;
            if (std.mem.eql(u8, p.provider, self.provider) and std.mem.eql(u8, p.name, self.name)) return p;
        }
        return null;
    }
};

/// Probes of the ELF file at `path`.
pub fn discover(gpa: std.mem.Allocator, path: []const u8) Error!ProbeSet {
    var image = try elfsym.openImageFile(gpa, path);
    errdefer image.deinit();
    return fromImage(gpa, image);
}

/// Probes of an ELF image in memory (`bytes` is copied).
pub fn discoverBytes(gpa: std.mem.Allocator, bytes: []const u8) Error!ProbeSet {
    const copy = gpa.dupe(u8, bytes) catch return error.OutOfMemory;
    var image = try elfsym.openImage(gpa, copy, true);
    errdefer image.deinit();
    return fromImage(gpa, image);
}

const NT_STAPSDT: u32 = 3;
const SHF_ALLOC: u64 = 0x2;
const SHT_NOBITS: u32 = 8;

fn align4(n: usize) usize {
    return (n + 3) & ~@as(usize, 3);
}

fn fromImage(gpa: std.mem.Allocator, image: elfsym.Image) Error!ProbeSet {
    var out: std.ArrayList(Probe) = .empty;
    errdefer out.deinit(gpa);

    // The `.stapsdt.base` section's current address: prelink's adjustment.
    const base_sec: ?elfsym.SectionHeader = if (image.findSection(".stapsdt.base")) |i| image.sections[i] else null;

    for (image.sections, 0..) |sec, si| {
        if (sec.sh_type != 7) continue; // SHT_NOTE
        if (!std.mem.eql(u8, image.sectionName(si), ".note.stapsdt")) continue;
        const data = try image.sectionData(si);
        var off: usize = 0;
        while (off + 12 <= data.len) {
            const namesz: usize = std.mem.readInt(u32, data[off..][0..4], native_endian);
            const descsz: usize = std.mem.readInt(u32, data[off + 4 ..][0..4], native_endian);
            const ntype = std.mem.readInt(u32, data[off + 8 ..][0..4], native_endian);
            const name_at = off + 12;
            const desc_at = std.math.add(usize, name_at, align4(namesz)) catch return error.MalformedNote;
            const next = std.math.add(usize, desc_at, align4(descsz)) catch return error.MalformedNote;
            if (name_at + namesz > data.len or desc_at + descsz > data.len) return error.MalformedNote;
            off = @min(next, data.len);
            if (ntype != NT_STAPSDT) continue;
            if (!std.mem.eql(u8, data[name_at..][0..namesz], "stapsdt\x00")) continue;
            const desc = data[desc_at..][0..descsz];
            if (desc.len < 24) return error.MalformedNote;
            const pc = std.mem.readInt(u64, desc[0..8], native_endian);
            const base = std.mem.readInt(u64, desc[8..16], native_endian);
            const sema = std.mem.readInt(u64, desc[16..24], native_endian);
            var strs = std.mem.splitScalar(u8, desc[24..], 0);
            const provider = strs.next() orelse return error.MalformedNote;
            const name = strs.next() orelse return error.MalformedNote;
            const args = strs.next() orelse return error.MalformedNote;
            if (strs.next() == null) return error.MalformedNote; // the last string must be NUL-terminated

            const adj: u64 = if (base_sec) |b| (if (base != 0) b.sh_addr -% base else 0) else 0;
            const address = pc +% adj;
            const sema_addr = if (sema != 0) sema +% adj else 0;
            try out.append(gpa, .{
                .provider = provider,
                .name = name,
                .args = args,
                .address = address,
                .file_offset = addrToOffset(image, address) orelse return error.UnmappedAddress,
                .semaphore_offset = if (sema_addr != 0)
                    addrToOffset(image, sema_addr) orelse return error.UnmappedAddress
                else
                    null,
            });
        }
    }
    return .{ .gpa = gpa, .image = image, .probes = out.toOwnedSlice(gpa) catch return error.OutOfMemory };
}

const native_endian = builtin.cpu.arch.endian();

/// `address` -> file offset through the allocated, file-backed section holding
/// it.
fn addrToOffset(image: elfsym.Image, address: u64) ?u64 {
    for (image.sections) |s| {
        if (s.sh_flags & SHF_ALLOC == 0 or s.sh_type == SHT_NOBITS or s.sh_size == 0) continue;
        if (address < s.sh_addr) continue;
        const delta = address - s.sh_addr;
        if (delta >= s.sh_size) continue;
        return std.math.add(u64, s.sh_offset, delta) catch return null;
    }
    return null;
}

// ── tests ────────────────────────────────────────────────────────────────────
//
// `testdata/usdt_probe` is a genuine gcc/ld output: two probes written the way
// <sys/sdt.h> writes them (see usdt_probe.c for the recipe). `readelf -n` is
// the black-box oracle for what it contains:
//   myprov:myprobe  Location 0x401004  Base 0x402000  Semaphore 0x403000  "-4@%edi 8@-8(%rbp)"
//   myprov:other    Location 0x401005  Base 0x402000  Semaphore 0          ""
// with `.text` at 0x401000 / file 0x1000 and `.probes` at 0x403000 / file 0x3000.

const testing = std.testing;
const fx_usdt = @embedFile("testdata/usdt_probe");

test "usdt: a real executable's two probes, semaphore and file offsets" {
    const gpa = testing.allocator;
    var set = try discoverBytes(gpa, fx_usdt);
    defer set.deinit();
    try testing.expectEqual(@as(usize, 2), set.probes.len);

    var it = set.find("myprov", "myprobe");
    const p = it.next().?;
    try testing.expect(it.next() == null);
    try testing.expectEqualStrings("-4@%edi 8@-8(%rbp)", p.args);
    try testing.expectEqual(@as(u64, 0x401004), p.address);
    try testing.expectEqual(@as(u64, 0x1004), p.file_offset);
    try testing.expectEqual(@as(?u64, 0x3000), p.semaphore_offset);

    var o = set.find("myprov", "other");
    const q = o.next().?;
    try testing.expectEqual(@as(u64, 0x1005), q.file_offset);
    try testing.expectEqual(@as(?u64, null), q.semaphore_offset);
    try testing.expectEqualStrings("", q.args);
    var none = set.find("myprov", "nope");
    try testing.expect(none.next() == null);
    var wrong_provider = set.find("x", "myprobe");
    try testing.expect(wrong_provider.next() == null);
}

test "usdt: argument descriptors split into size, sign and location" {
    const gpa = testing.allocator;
    var set = try discoverBytes(gpa, fx_usdt);
    defer set.deinit();
    var it0 = set.find("myprov", "myprobe");
    var args = it0.next().?.argIter();
    const a = (try args.next()).?;
    try testing.expectEqual(@as(u8, 4), a.size);
    try testing.expect(a.signed);
    try testing.expectEqualStrings("%edi", a.location);
    const b = (try args.next()).?;
    try testing.expectEqual(@as(u8, 8), b.size);
    try testing.expect(!b.signed);
    try testing.expectEqualStrings("-8(%rbp)", b.location);
    try testing.expect((try args.next()) == null);
    // malformed tokens
    for ([_][]const u8{ "nosize", "0@%eax", "x@%eax", "-128@%eax" }) |bad| {
        var bi = (Probe{ .provider = "", .name = "", .args = bad, .address = 0, .file_offset = 0, .semaphore_offset = null }).argIter();
        try testing.expectError(error.MalformedNote, bi.next());
    }
}

test "usdt: a binary with no probes has none; a hostile note is typed" {
    const gpa = testing.allocator;
    var none = try discoverBytes(gpa, @embedFile("testdata/xdp_pass.bpf.o"));
    defer none.deinit();
    try testing.expectEqual(@as(usize, 0), none.probes.len);

    // Corrupt the first note's `namesz` and `descsz` in the file image: a note
    // that claims more than its section holds is refused, never read past.
    const copy = try gpa.dupe(u8, fx_usdt);
    defer gpa.free(copy);
    const note_off = 0x3028; // `.note.stapsdt` file offset (readelf -S)
    std.mem.writeInt(u32, copy[note_off + 4 ..][0..4], 0x7fff_ff00, native_endian);
    try testing.expectError(error.MalformedNote, discoverBytes(gpa, copy));
    std.mem.writeInt(u32, copy[note_off + 4 ..][0..4], 4, native_endian); // descsz too short for pc/base/sema
    try testing.expectError(error.MalformedNote, discoverBytes(gpa, copy));
}

test "usdt: a probe pointing into .bss or nowhere is unmapped" {
    const gpa = testing.allocator;
    const copy = try gpa.dupe(u8, fx_usdt);
    defer gpa.free(copy);
    const note_off = 0x3028;
    // first note: 12-byte header + "stapsdt\0" (8) = descriptor at +20; pc is its first word
    std.mem.writeInt(u64, copy[note_off + 20 ..][0..8], 0xdead_0000, native_endian);
    try testing.expectError(error.UnmappedAddress, discoverBytes(gpa, copy));
}
