// SPDX-License-Identifier: MIT
//! Minimal ELF64 symbol resolution — exactly the slice a **uprobe** attach
//! needs and nothing more: given an executable or shared-library path and a
//! symbol name, produce the symbol's **file offset**, which is what the
//! uprobe PMU wants in `perf_event_attr.config2` (`uprobe_offset`).
//!
//! ## Why this is not just "read `st_value`"
//!
//! The symbol table stores a **virtual address** (`st_value`), i.e. an offset
//! into the object's own link-time address space. The kernel's uprobe
//! registration instead takes an **offset into the file** (it installs the
//! breakpoint by inode + offset, so that every process mapping that inode is
//! probed). For an object whose text happens to be mapped 1:1 those two
//! numbers coincide, which is why the bug hides: it only shows up for a
//! symbol in a segment where `p_vaddr != p_offset`.
//!
//! On any modern glibc that is a real, present case — e.g. on this machine
//! `libc.so.6`'s writable `PT_LOAD` is
//! `offset 0x20db98 -> vaddr 0x20eb98`, a 0x1000 skew introduced by the
//! linker's `-z separate-code`/RELRO padding. A data symbol resolved as
//! "st_value == file offset" would point one page past its real bytes.
//!
//! So the conversion is: find the `PT_LOAD` program header whose
//! **file-backed** range covers the address —
//! `p_vaddr <= st_value < p_vaddr + p_filesz` — and return
//! `p_offset + (st_value - p_vaddr)`. A symbol covered only by `p_memsz`
//! (i.e. `.bss`) has no file bytes at all and is reported as
//! `error.NoFileMapping` rather than silently given a bogus offset.
//!
//! ## Scope
//!
//! - **ELF64 only**, in the host's byte order. A 32-bit or foreign-endian
//!   object is `error.UnsupportedElf`, never a mis-parse — uprobes are
//!   registered against a file this process can also execute, so a
//!   cross-class object is a caller mistake, not a case to guess at.
//! - `.symtab` is searched first, then `.dynsym` (the order libbpf uses):
//!   a stripped shared library has only the latter, and where both exist
//!   `.symtab` additionally carries local/static functions.
//! - Versioned names: `.dynsym` entries normally carry the bare name
//!   (`malloc`), with the version in a parallel section, but some toolchains
//!   emit `name@VERSION` / `name@@VERSION` directly in the string table. A
//!   lookup for `malloc` therefore also matches `malloc@…`, matching what
//!   `bpftrace`/libbpf do.
//! - No BTF, no debug info, no DWARF line lookup, no symbol demangling.

const std = @import("std");
const builtin = @import("builtin");

// Skip diagnostics are opt-in: `zig build test` must be silent on
// success (any stderr triggers the build runner's `failed command:`
// line even when the step succeeded), while the skip *count* still
// shows up in the summary regardless. Set ZIG_LIBS_VERBOSE_SKIP to any
// non-empty value to see the reasons. (std.posix.getenv doesn't exist
// in 0.16 — std.testing.environ + Environ.getPosix is the repo's
// existing env-read pattern for tests, see netconf's `envVar`.)
const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;
const linux = std.os.linux;
const elf = std.elf;

const native_endian = builtin.cpu.arch.endian();

// ── ELF64 field offsets (System V gABI + the ELF-64 supplement) ─────────────
//
// Parsed by explicit `readInt` at these offsets rather than by `@ptrCast`ing
// the buffer to `std.elf.Elf64_*`: those structs type several fields as
// non-exhaustive-looking enums (`e_type`, `e_machine`), and a hostile or
// merely unusual file must not be able to produce an invalid enum value in a
// safety-checked build. The offsets are asserted against std's structs in
// this file's tests, so a std layout change cannot silently desynchronize
// them.

const EHDR_SIZE: usize = 64;
const ehdr_type = 16;
const ehdr_machine = 18;
const ehdr_phoff = 32;
const ehdr_shoff = 40;
const ehdr_ehsize = 52;
const ehdr_phentsize = 54;
const ehdr_phnum = 56;
const ehdr_shentsize = 58;
const ehdr_shnum = 60;
const ehdr_shstrndx = 62;

const PHDR_SIZE: usize = 56;
const phdr_type = 0;
const phdr_offset = 8;
const phdr_vaddr = 16;
const phdr_filesz = 32;
const phdr_memsz = 40;

const SHDR_SIZE: usize = 64;
const shdr_name = 0;
const shdr_type = 4;
const shdr_flags = 8;
const shdr_addr = 16;
const shdr_offset = 24;
const shdr_size = 32;
const shdr_link = 40;
const shdr_info = 44;
const shdr_addralign = 48;
const shdr_entsize = 56;

const SYM_SIZE: usize = 24;
const sym_name = 0;
const sym_info = 4;
const sym_other = 5;
const sym_shndx = 6;
const sym_value = 8;
const sym_size = 16;

/// `Elf64_Rel` — a `SHT_REL` entry. BPF objects use REL, not RELA: the
/// addend lives inside the instruction stream, not in the relocation record.
const REL_SIZE: usize = 16;
const rel_offset = 0;
const rel_info = 8;

/// `PT_LOAD`, `SHT_SYMTAB`, `SHT_DYNSYM`, `STT_FUNC`, `STT_GNU_IFUNC`,
/// `SHN_UNDEF` — taken from std rather than re-declared.
const PT_LOAD: u32 = @intFromEnum(elf.PT.LOAD);
const SHT_SYMTAB: u32 = @intFromEnum(elf.SHT.SYMTAB);
const SHT_DYNSYM: u32 = @intFromEnum(elf.SHT.DYNSYM);
const STT_FUNC: u4 = @intFromEnum(elf.STT.FUNC);
const STT_GNU_IFUNC: u4 = @intFromEnum(elf.STT.GNU_IFUNC);
const STT_OBJECT: u4 = @intFromEnum(elf.STT.OBJECT);
const SHN_UNDEF: u16 = elf.SHN_UNDEF;

// ── sanity ceilings ─────────────────────────────────────────────────────────
//
// Every count below is read out of the file, so each gets an explicit bound:
// a corrupt `e_shnum`/`sh_size` must fail as a typed error, not as a
// multi-gigabyte allocation.

const max_sections: u64 = 1 << 16;
const max_segments: u64 = 1 << 12;
const max_table_bytes: u64 = 64 << 20;

pub const ResolveError = error{
    FileOpenFailed,
    FileReadFailed,
    /// The file does not start with `\x7fELF`.
    NotAnElf,
    /// Well-formed ELF this reader deliberately does not handle: not
    /// ELFCLASS64, or not the host's byte order.
    UnsupportedElf,
    /// Structurally inconsistent: a header/table size or index that cannot
    /// describe a real object.
    MalformedElf,
    SymbolNotFound,
    /// The symbol exists but has no bytes in the file (a `.bss`/`SHN_UNDEF`
    /// symbol, or an address outside every `PT_LOAD`'s file-backed range).
    NoFileMapping,
    OutOfMemory,
};

/// Which symbol tables a lookup may consult, in order.
pub const Table = enum {
    /// `.symtab` first, then `.dynsym` — the default, and what libbpf does.
    any,
    /// `.symtab` only (fails on a stripped object).
    symtab,
    /// `.dynsym` only (exported symbols).
    dynsym,
};

/// A resolved symbol. `file_offset` is the value a uprobe attach needs;
/// `vaddr` is kept because it is what `nm`/`readelf -s` print, which is what
/// a human cross-checks against.
pub const Symbol = struct {
    /// `st_value` — the link-time virtual address.
    vaddr: u64,
    /// Byte offset of the symbol inside the file (the uprobe offset).
    file_offset: u64,
    /// `st_size` (0 when the producer did not record one).
    size: u64,
    /// `ELF64_ST_TYPE(st_info)`.
    kind: Kind,
    /// Which table it came from.
    table: Table,

    pub const Kind = enum { func, ifunc, object, other };
};

/// One `PT_LOAD`'s file-vs-memory mapping. Split out so the vaddr -> offset
/// conversion — the step this whole file exists for — is a pure function
/// testable without any file at all.
pub const Segment = struct {
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
};

/// Convert a link-time virtual address to a file offset using the object's
/// `PT_LOAD` segments. `null` when no segment's **file-backed** range covers
/// the address.
///
/// Deliberately checks `p_filesz`, not `p_memsz`: the tail of a segment
/// between `p_filesz` and `p_memsz` is `.bss`, which has no bytes in the file
/// and therefore no valid uprobe offset. Returning `p_offset + delta` there
/// would name some unrelated later section's bytes.
pub fn vaddrToFileOffset(segments: []const Segment, vaddr: u64) ?u64 {
    for (segments) |s| {
        if (s.p_filesz == 0) continue;
        if (vaddr < s.p_vaddr) continue;
        const delta = vaddr - s.p_vaddr;
        if (delta >= s.p_filesz) continue;
        return s.p_offset + delta;
    }
    return null;
}

/// Resolve `name` in the object at `path`, returning its file offset and
/// virtual address. Searches `.symtab` then `.dynsym`.
pub fn resolve(gpa: std.mem.Allocator, path: []const u8, name: []const u8) ResolveError!Symbol {
    return resolveOpts(gpa, path, name, .{});
}

/// `resolve`, restricted to function symbols — what a uprobe almost always
/// wants (probing a data symbol installs a breakpoint on data, which the
/// kernel accepts and which then never fires or corrupts execution).
pub fn resolveFunc(gpa: std.mem.Allocator, path: []const u8, name: []const u8) ResolveError!Symbol {
    return resolveOpts(gpa, path, name, .{ .funcs_only = true });
}

/// Just the number a uprobe attach needs.
pub fn resolveFuncOffset(gpa: std.mem.Allocator, path: []const u8, name: []const u8) ResolveError!u64 {
    const sym = try resolveFunc(gpa, path, name);
    return sym.file_offset;
}

pub const Options = struct {
    table: Table = .any,
    /// Reject `STT_OBJECT`/other kinds — see `resolveFunc`.
    funcs_only: bool = false,
};

pub fn resolveOpts(
    gpa: std.mem.Allocator,
    path: []const u8,
    name: []const u8,
    opts: Options,
) ResolveError!Symbol {
    if (comptime builtin.os.tag != .linux)
        @compileError("ebpf.elfsym is Linux-only (raw open/pread syscalls)");
    if (name.len == 0) return error.SymbolNotFound;

    const path_z = gpa.dupeZ(u8, path) catch return error.OutOfMemory;
    defer gpa.free(path_z);

    var file = try File.open(path_z.ptr);
    defer file.close();

    var ehdr: [EHDR_SIZE]u8 = undefined;
    try file.readExact(0, &ehdr);
    if (!std.mem.eql(u8, ehdr[0..4], elf.MAGIC)) return error.NotAnElf;
    if (ehdr[elf.EI.CLASS] != @intFromEnum(elf.CLASS.@"64")) return error.UnsupportedElf;
    const want_data: u8 = switch (native_endian) {
        .little => @intFromEnum(elf.DATA.@"2LSB"),
        .big => @intFromEnum(elf.DATA.@"2MSB"),
    };
    if (ehdr[elf.EI.DATA] != want_data) return error.UnsupportedElf;
    if (rd(u16, &ehdr, ehdr_ehsize) < EHDR_SIZE) return error.MalformedElf;

    const segments = try readSegments(gpa, &file, &ehdr);
    defer gpa.free(segments);

    const sections = try readSections(gpa, &file, &ehdr);
    defer gpa.free(sections);

    // `.symtab` first, then `.dynsym` (see the header note). `any` walks
    // both; the explicit variants walk exactly one.
    const order: []const u32 = switch (opts.table) {
        .any => &.{ SHT_SYMTAB, SHT_DYNSYM },
        .symtab => &.{SHT_SYMTAB},
        .dynsym => &.{SHT_DYNSYM},
    };

    var saw_table = false;
    for (order) |want| {
        const tbl = findSection(sections, want) orelse continue;
        saw_table = true;
        const which: Table = if (want == SHT_SYMTAB) .symtab else .dynsym;
        if (try searchTable(gpa, &file, sections, tbl, name, opts, which, segments)) |sym| return sym;
    }
    if (!saw_table) return error.SymbolNotFound;
    return error.SymbolNotFound;
}

// ── internals ───────────────────────────────────────────────────────────────

fn rd(comptime T: type, buf: []const u8, off: usize) T {
    return std.mem.readInt(T, buf[off..][0..@divExact(@typeInfo(T).int.bits, 8)], native_endian);
}

/// One decoded `Elf64_Shdr`. Every field is kept (rather than only the five
/// the uprobe path needs) because the BPF-object loader in `object.zig`
/// keys off `sh_flags`/`sh_addralign`/`sh_info` as well — one decoder, two
/// consumers, rather than a second ELF parser.
pub const SectionHeader = struct {
    /// Index of this header in the section header table.
    index: u16,
    /// Offset into the **section-header string table**, not into `.strtab`.
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
};

/// Kept as the old private name so the uprobe path below reads unchanged.
const Section = SectionHeader;

fn readSegments(gpa: std.mem.Allocator, file: *File, ehdr: *const [EHDR_SIZE]u8) ResolveError![]Segment {
    const phoff = rd(u64, ehdr, ehdr_phoff);
    const phentsize = rd(u16, ehdr, ehdr_phentsize);
    const phnum = rd(u16, ehdr, ehdr_phnum);
    if (phnum == 0) return gpa.alloc(Segment, 0) catch error.OutOfMemory;
    if (phentsize < PHDR_SIZE) return error.MalformedElf;
    if (phnum > max_segments) return error.MalformedElf;

    var out: std.ArrayList(Segment) = .empty;
    errdefer out.deinit(gpa);

    var buf: [PHDR_SIZE]u8 = undefined;
    var i: u64 = 0;
    while (i < phnum) : (i += 1) {
        try file.readExact(phoff + i * phentsize, &buf);
        if (rd(u32, &buf, phdr_type) != PT_LOAD) continue;
        out.append(gpa, .{
            .p_offset = rd(u64, &buf, phdr_offset),
            .p_vaddr = rd(u64, &buf, phdr_vaddr),
            .p_filesz = rd(u64, &buf, phdr_filesz),
            .p_memsz = rd(u64, &buf, phdr_memsz),
        }) catch return error.OutOfMemory;
    }
    return out.toOwnedSlice(gpa) catch error.OutOfMemory;
}

fn readSections(gpa: std.mem.Allocator, file: *File, ehdr: *const [EHDR_SIZE]u8) ResolveError![]Section {
    const shoff = rd(u64, ehdr, ehdr_shoff);
    const shentsize = rd(u16, ehdr, ehdr_shentsize);
    var shnum: u64 = rd(u16, ehdr, ehdr_shnum);
    if (shoff == 0) return gpa.alloc(Section, 0) catch error.OutOfMemory;
    if (shentsize < SHDR_SIZE) return error.MalformedElf;

    var buf: [SHDR_SIZE]u8 = undefined;
    // The "more than 0xff00 sections" escape hatch: `e_shnum == 0` means the
    // real count lives in section 0's `sh_size` (gABI). Objects that big are
    // rare but real (heavily -ffunction-sections builds).
    if (shnum == 0) {
        try file.readExact(shoff, &buf);
        shnum = rd(u64, &buf, shdr_size);
    }
    if (shnum > max_sections) return error.MalformedElf;

    const out = gpa.alloc(Section, @intCast(shnum)) catch return error.OutOfMemory;
    errdefer gpa.free(out);
    var i: u64 = 0;
    while (i < shnum) : (i += 1) {
        try file.readExact(shoff + i * shentsize, &buf);
        out[@intCast(i)] = decodeShdr(&buf, @intCast(i));
    }
    return out;
}

fn decodeShdr(buf: *const [SHDR_SIZE]u8, index: u16) SectionHeader {
    return .{
        .index = index,
        .sh_name = rd(u32, buf, shdr_name),
        .sh_type = rd(u32, buf, shdr_type),
        .sh_flags = rd(u64, buf, shdr_flags),
        .sh_addr = rd(u64, buf, shdr_addr),
        .sh_offset = rd(u64, buf, shdr_offset),
        .sh_size = rd(u64, buf, shdr_size),
        .sh_link = rd(u32, buf, shdr_link),
        .sh_info = rd(u32, buf, shdr_info),
        .sh_addralign = rd(u64, buf, shdr_addralign),
        .sh_entsize = rd(u64, buf, shdr_entsize),
    };
}

fn findSection(sections: []const Section, sh_type: u32) ?usize {
    for (sections, 0..) |s, i| {
        if (s.sh_type == sh_type and s.sh_size != 0) return i;
    }
    return null;
}

fn searchTable(
    gpa: std.mem.Allocator,
    file: *File,
    sections: []const Section,
    tbl_idx: usize,
    name: []const u8,
    opts: Options,
    which: Table,
    segments: []const Segment,
) ResolveError!?Symbol {
    const tbl = sections[tbl_idx];
    const entsize = if (tbl.sh_entsize == 0) SYM_SIZE else tbl.sh_entsize;
    if (entsize < SYM_SIZE) return error.MalformedElf;
    if (tbl.sh_link >= sections.len) return error.MalformedElf;
    const strtab = sections[tbl.sh_link];
    if (strtab.sh_size == 0 or strtab.sh_size > max_table_bytes) return error.MalformedElf;
    if (tbl.sh_size > max_table_bytes) return error.MalformedElf;

    const strings = gpa.alloc(u8, @intCast(strtab.sh_size)) catch return error.OutOfMemory;
    defer gpa.free(strings);
    try file.readExact(strtab.sh_offset, strings);

    const count = tbl.sh_size / entsize;
    var buf: [SYM_SIZE]u8 = undefined;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        try file.readExact(tbl.sh_offset + i * entsize, &buf);
        const st_name = rd(u32, &buf, sym_name);
        if (st_name == 0) continue;
        if (st_name >= strings.len) continue;
        if (!nameMatches(strings[st_name..], name)) continue;

        // An undefined symbol (an import) has no address in THIS object.
        if (rd(u16, &buf, sym_shndx) == SHN_UNDEF) continue;

        const info = buf[sym_info];
        const kind: Symbol.Kind = switch (@as(u4, @truncate(info))) {
            STT_FUNC => .func,
            STT_GNU_IFUNC => .ifunc,
            STT_OBJECT => .object,
            else => .other,
        };
        if (opts.funcs_only and kind != .func and kind != .ifunc) continue;

        const vaddr = rd(u64, &buf, sym_value);
        const off = vaddrToFileOffset(segments, vaddr) orelse return error.NoFileMapping;
        return .{
            .vaddr = vaddr,
            .file_offset = off,
            .size = rd(u64, &buf, sym_size),
            .kind = kind,
            .table = which,
        };
    }
    return null;
}

/// True when the NUL-terminated string at `s` equals `want`, either exactly
/// or up to a `@`/`@@` version suffix.
fn nameMatches(s: []const u8, want: []const u8) bool {
    const end = std.mem.indexOfScalar(u8, s, 0) orelse s.len;
    const full = s[0..end];
    if (std.mem.eql(u8, full, want)) return true;
    const at = std.mem.indexOfScalar(u8, full, '@') orelse return false;
    return std.mem.eql(u8, full[0..at], want);
}

// ── whole-image reader: sections BY NAME ────────────────────────────────────
//
// The uprobe path above never needs a section's NAME — it walks section
// *types* (`SHT_SYMTAB`/`SHT_DYNSYM`). A BPF object loader needs the exact
// opposite: every interesting section (`xdp`, `kprobe/…`, `.maps`, `license`,
// `.BTF`, `.rodata`, `.rel<section>`) is identified purely by name, which
// lives in the section-header string table named by `e_shstrndx`.
//
// This reader is deliberately whole-image rather than `pread`-per-record: a
// relocatable `.o` is kilobytes, is read many times over (headers, names,
// symbols, relocations, instruction streams), and the loader must hand out
// slices of the instruction stream anyway.

pub const ImageError = error{
    NotAnElf,
    UnsupportedElf,
    MalformedElf,
    OutOfMemory,
};

pub const ImageOpenError = ImageError || error{ FileOpenFailed, FileReadFailed, FileTooLarge };

/// `SHN_XINDEX` — "the real value is elsewhere" escape for the 16-bit
/// `e_shstrndx`/`st_shndx` fields.
pub const SHN_XINDEX: u16 = 0xffff;
/// `SHN_LORESERVE` — `st_shndx` values at or above this are not section
/// indices (`SHN_ABS`, `SHN_COMMON`, `SHN_XINDEX`).
pub const SHN_LORESERVE: u16 = 0xff00;
/// `EM_BPF`.
pub const EM_BPF: u16 = 247;

/// One decoded `Elf64_Sym`.
pub const RawSymbol = struct {
    /// Index in the symbol table it came from — what a relocation names.
    index: u32,
    /// Offset into the string table `sh_link` of the symbol table points at.
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,

    /// `ELF64_ST_TYPE`.
    pub fn kind(self: RawSymbol) u4 {
        return @truncate(self.st_info);
    }
    /// `ELF64_ST_BIND`.
    pub fn bind(self: RawSymbol) u4 {
        return @truncate(self.st_info >> 4);
    }
    /// True when `st_shndx` names a real section (not `SHN_UNDEF`/`SHN_ABS`/…).
    pub fn hasSection(self: RawSymbol) bool {
        return self.st_shndx != SHN_UNDEF and self.st_shndx < SHN_LORESERVE;
    }
};

/// One decoded `Elf64_Rel`.
pub const Relocation = struct {
    r_offset: u64,
    /// `ELF64_R_SYM(r_info)` — an index into the relocation section's
    /// `sh_link` symbol table.
    sym: u32,
    /// `ELF64_R_TYPE(r_info)` — `R_BPF_64_*` for a BPF object.
    type: u32,
};

/// A whole ELF64 image held in memory, with its section names resolved.
///
/// Borrows or owns `bytes` (see `openImage`); every slice it hands back
/// points into that buffer, so the `Image` must outlive them.
pub const Image = struct {
    gpa: std.mem.Allocator,
    bytes: []const u8,
    owns_bytes: bool,
    e_type: u16,
    e_machine: u16,
    /// Section headers, in file order (`sections[i].index == i`).
    sections: []const SectionHeader,
    /// The section-header string table's bytes. Empty when the object has
    /// none (`e_shstrndx == SHN_UNDEF`), in which case every name is `""`.
    shstrtab: []const u8,

    pub fn deinit(self: *Image) void {
        self.gpa.free(self.sections);
        if (self.owns_bytes) self.gpa.free(self.bytes);
        self.* = undefined;
    }

    /// Name of section `i`, or `""` when the object carries no section-header
    /// string table or the offset is out of range. Never fails: a bogus name
    /// offset must not make the whole object unreadable, it must make that
    /// one section anonymous.
    pub fn sectionName(self: *const Image, i: usize) []const u8 {
        if (i >= self.sections.len) return "";
        return cstr(self.shstrtab, self.sections[i].sh_name);
    }

    /// The section's file bytes. `SHT_NOBITS` (`.bss`) occupies no file space
    /// and yields an empty slice rather than an error — its *size* is still
    /// `sh_size`, which is what an internal `.bss` map is sized from.
    pub fn sectionData(self: *const Image, i: usize) ImageError![]const u8 {
        if (i >= self.sections.len) return error.MalformedElf;
        const s = self.sections[i];
        if (s.sh_type == SHT_NOBITS) return self.bytes[0..0];
        if (s.sh_offset > self.bytes.len) return error.MalformedElf;
        if (s.sh_size > self.bytes.len - s.sh_offset) return error.MalformedElf;
        return self.bytes[@intCast(s.sh_offset)..][0..@intCast(s.sh_size)];
    }

    /// Index of the first section named `name`, or `null`.
    pub fn findSection(self: *const Image, name: []const u8) ?usize {
        for (0..self.sections.len) |i| {
            if (std.mem.eql(u8, self.sectionName(i), name)) return i;
        }
        return null;
    }

    /// Index of the first `SHT_SYMTAB` section, or `null` (a fully stripped
    /// relocatable object — which cannot be relocated at all).
    pub fn symtabIndex(self: *const Image) ?usize {
        for (self.sections, 0..) |s, i| {
            if (s.sh_type == SHT_SYMTAB and s.sh_size != 0) return i;
        }
        return null;
    }

    /// How many `Elf64_Sym` entries section `i` holds.
    pub fn symbolCount(self: *const Image, i: usize) ImageError!u32 {
        const data = try self.sectionData(i);
        const ent = self.entSize(i, SYM_SIZE);
        if (ent < SYM_SIZE) return error.MalformedElf;
        return @intCast(data.len / ent);
    }

    /// Decode symbol `n` of symbol-table section `i`.
    ///
    /// `n` is UNBOUNDED by contract: `object.zig`'s relocation walk passes
    /// `rel.sym`, which is the high half of a raw `r_info` straight off the
    /// wire, with no count check. See `entryOffset` for why that is safe.
    pub fn symbol(self: *const Image, i: usize, n: u32) ImageError!RawSymbol {
        const data = try self.sectionData(i);
        const at = try entryOffset(data.len, self.entSize(i, SYM_SIZE), n, SYM_SIZE);
        const r = data[@intCast(at)..][0..SYM_SIZE];
        return .{
            .index = n,
            .st_name = rd(u32, r, sym_name),
            .st_info = r[sym_info],
            .st_other = r[sym_other],
            .st_shndx = rd(u16, r, sym_shndx),
            .st_value = rd(u64, r, sym_value),
            .st_size = rd(u64, r, sym_size),
        };
    }

    /// The name of a symbol from table `i`, resolved through that table's
    /// `sh_link` string section.
    pub fn symbolName(self: *const Image, i: usize, sym: RawSymbol) []const u8 {
        if (i >= self.sections.len) return "";
        const link = self.sections[i].sh_link;
        if (link >= self.sections.len) return "";
        const strings = self.sectionData(link) catch return "";
        return cstr(strings, sym.st_name);
    }

    /// How many `Elf64_Rel` entries relocation section `i` holds.
    pub fn relocationCount(self: *const Image, i: usize) ImageError!u32 {
        const data = try self.sectionData(i);
        const ent = self.entSize(i, REL_SIZE);
        if (ent < REL_SIZE) return error.MalformedElf;
        return @intCast(data.len / ent);
    }

    /// Decode relocation `n` of `SHT_REL` section `i`. `n` is unbounded by
    /// contract, exactly as in `symbol` — same shape, same guard.
    pub fn relocation(self: *const Image, i: usize, n: u32) ImageError!Relocation {
        const data = try self.sectionData(i);
        const at = try entryOffset(data.len, self.entSize(i, REL_SIZE), n, REL_SIZE);
        const r = data[@intCast(at)..][0..REL_SIZE];
        const info = rd(u64, r, rel_info);
        return .{
            .r_offset = rd(u64, r, rel_offset),
            .sym = @intCast(info >> 32),
            .type = @truncate(info),
        };
    }

    fn entSize(self: *const Image, i: usize, dflt: usize) u64 {
        const e = self.sections[i].sh_entsize;
        return if (e == 0) dflt else e;
    }
};

/// Byte offset of entry `n` in a table of `len` bytes whose entries are
/// `ent` bytes wide and whose decoded record needs `min` bytes — or
/// `error.MalformedElf`.
///
/// **Why this is a function and not two lines in each accessor.** `symbol`
/// and `relocation` used to carry an identical copy of
///
/// ```zig
/// if (ent < min) return error.MalformedElf;
/// const at = @as(u64, n) * ent;          // ① overflows
/// if (at + min > data.len) return ...;   // ② also overflows
/// ```
///
/// and both were wrong the same way. `ent` is the section header's raw
/// `sh_entsize`, an unvalidated `u64` out of the file, bounded only from
/// BELOW; `n` is an unvalidated `u32` off the wire at `symbol`'s one
/// unbounded call site. `n * ent` overflows `u64`, and even with a
/// checked multiply the `at + min` in ② overflows whenever `at` lands near
/// `maxInt(u64)` — so a crafted `.o` PANICKED (`integer overflow`) where it
/// had to return a typed error. Two byte-identical bugs is what a copied
/// guard buys.
///
/// The repair does the whole check by DIVISION, so no product and no sum is
/// ever formed that could wrap: bound `ent` from above by the table itself
/// (`ent > len` is nonsense on its face), which also makes `len - min`
/// non-negative since `len >= ent >= min`; then `n <= (len - min) / ent` is
/// exactly `n * ent + min <= len`, decided without multiplying.
fn entryOffset(len: usize, ent: u64, n: u32, min: usize) ImageError!u64 {
    if (ent < min or ent > len) return error.MalformedElf;
    if (n > (len - min) / ent) return error.MalformedElf;
    const at = @as(u64, n) * ent; // < len by the line above; cannot wrap
    std.debug.assert(at + min <= len);
    return at;
}

/// `SHT_NOBITS` / `SHT_REL` / `SHT_STRTAB`, from std.
const SHT_NOBITS: u32 = @intFromEnum(elf.SHT.NOBITS);
pub const SHT_REL: u32 = @intFromEnum(elf.SHT.REL);
const SHT_STRTAB: u32 = @intFromEnum(elf.SHT.STRTAB);
/// `SHT_PROGBITS`.
pub const SHT_PROGBITS: u32 = @intFromEnum(elf.SHT.PROGBITS);

/// `SHF_ALLOC` / `SHF_EXECINSTR` — how a *program* section is told apart from
/// a data section without knowing its name.
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;

fn cstr(strings: []const u8, off: u32) []const u8 {
    if (off >= strings.len) return "";
    const s = strings[off..];
    const end = std.mem.indexOfScalar(u8, s, 0) orelse s.len;
    return s[0..end];
}

/// Parse an ELF64 image already in memory. With `own_bytes`, the returned
/// `Image` frees `bytes` in `deinit`.
///
/// Only the header and the section-header table are validated eagerly; a
/// section whose `sh_offset`/`sh_size` runs past the end of the buffer is
/// caught when its data is asked for, so one bad section cannot make the
/// object unopenable.
pub fn openImage(gpa: std.mem.Allocator, bytes: []const u8, own_bytes: bool) ImageError!Image {
    errdefer if (own_bytes) gpa.free(@constCast(bytes));

    if (bytes.len < EHDR_SIZE) return error.NotAnElf;
    if (!std.mem.eql(u8, bytes[0..4], elf.MAGIC)) return error.NotAnElf;
    if (bytes[elf.EI.CLASS] != @intFromEnum(elf.CLASS.@"64")) return error.UnsupportedElf;
    const want_data: u8 = switch (native_endian) {
        .little => @intFromEnum(elf.DATA.@"2LSB"),
        .big => @intFromEnum(elf.DATA.@"2MSB"),
    };
    if (bytes[elf.EI.DATA] != want_data) return error.UnsupportedElf;
    const ehdr = bytes[0..EHDR_SIZE];
    if (rd(u16, ehdr, ehdr_ehsize) < EHDR_SIZE) return error.MalformedElf;

    const shoff = rd(u64, ehdr, ehdr_shoff);
    const shentsize = rd(u16, ehdr, ehdr_shentsize);
    var shnum: u64 = rd(u16, ehdr, ehdr_shnum);
    var shstrndx: u32 = rd(u16, ehdr, ehdr_shstrndx);

    var sections: []SectionHeader = &.{};
    if (shoff != 0) {
        if (shentsize < SHDR_SIZE) return error.MalformedElf;
        if (shoff >= bytes.len) return error.MalformedElf;
        // The ">= 0xff00 sections" escape: the real count is in section 0's
        // `sh_size`, and the real `e_shstrndx` in its `sh_link`.
        if (shnum == 0 or shstrndx == SHN_XINDEX) {
            if (shoff + SHDR_SIZE > bytes.len) return error.MalformedElf;
            const zero = decodeShdr(bytes[@intCast(shoff)..][0..SHDR_SIZE], 0);
            if (shnum == 0) shnum = zero.sh_size;
            if (shstrndx == SHN_XINDEX) shstrndx = zero.sh_link;
        }
        if (shnum > max_sections) return error.MalformedElf;
        // The whole table must be inside the file — this is the one bound
        // that has to be eager, since every later lookup indexes it.
        const table_bytes = shnum * @as(u64, shentsize);
        if (table_bytes > bytes.len or shoff > bytes.len - table_bytes) return error.MalformedElf;

        sections = gpa.alloc(SectionHeader, @intCast(shnum)) catch return error.OutOfMemory;
        for (0..@as(usize, @intCast(shnum))) |i| {
            const at: usize = @intCast(shoff + @as(u64, i) * shentsize);
            sections[i] = decodeShdr(bytes[at..][0..SHDR_SIZE], @intCast(i));
        }
    }
    errdefer gpa.free(sections);

    // A bogus `e_shstrndx` (past the table, or naming a non-STRTAB section)
    // costs the NAMES, not the object: every section then reads as "".
    var shstrtab: []const u8 = bytes[0..0];
    if (shstrndx != 0 and shstrndx < sections.len) {
        const s = sections[shstrndx];
        if (s.sh_type == SHT_STRTAB and
            s.sh_offset <= bytes.len and s.sh_size <= bytes.len - s.sh_offset)
        {
            shstrtab = bytes[@intCast(s.sh_offset)..][0..@intCast(s.sh_size)];
        }
    }

    return .{
        .gpa = gpa,
        .bytes = bytes,
        .owns_bytes = own_bytes,
        .e_type = rd(u16, ehdr, ehdr_type),
        .e_machine = rd(u16, ehdr, ehdr_machine),
        .sections = sections,
        .shstrtab = shstrtab,
    };
}

/// Read a whole file into memory (raw syscalls; this repo forbids libc).
/// Caller frees.
pub fn readFileAlloc(gpa: std.mem.Allocator, path: []const u8, max_bytes: usize) ImageOpenError![]u8 {
    if (comptime builtin.os.tag != .linux)
        @compileError("ebpf.elfsym is Linux-only (raw open/pread syscalls)");

    const path_z = gpa.dupeZ(u8, path) catch return error.OutOfMemory;
    defer gpa.free(path_z);

    var file = File.open(path_z.ptr) catch return error.FileOpenFailed;
    defer file.close();

    const len = file.size() catch return error.FileReadFailed;
    if (len > max_bytes) return error.FileTooLarge;
    const buf = gpa.alloc(u8, @intCast(len)) catch return error.OutOfMemory;
    errdefer gpa.free(buf);
    if (len != 0) file.readExact(0, buf) catch return error.FileReadFailed;
    return buf;
}

/// Default ceiling for `openImageFile` — a relocatable BPF object is tens of
/// kilobytes; 256 MB is "something is wrong", not a real object.
pub const max_image_bytes: usize = 256 << 20;

/// `readFileAlloc` + `openImage`, with the resulting `Image` owning the bytes.
pub fn openImageFile(gpa: std.mem.Allocator, path: []const u8) ImageOpenError!Image {
    const bytes = try readFileAlloc(gpa, path, max_image_bytes);
    return openImage(gpa, bytes, true);
}

/// A read-only file, raw syscalls only (this repo forbids libc).
const File = struct {
    fd: linux.fd_t,

    fn open(path_z: [*:0]const u8) ResolveError!File {
        const rc = linux.open(path_z, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            else => return error.FileOpenFailed,
        }
        return .{ .fd = @intCast(rc) };
    }

    fn close(self: *File) void {
        _ = linux.close(self.fd);
        self.* = undefined;
    }

    /// Fill `buf` completely from `off`, or fail. A short read means the
    /// header pointed past the end of the file — a malformed object, not a
    /// transient condition.
    fn readExact(self: *File, off: u64, buf: []u8) ResolveError!void {
        if (off > std.math.maxInt(i64)) return error.MalformedElf;
        var n: usize = 0;
        while (n < buf.len) {
            const rc = linux.pread(self.fd, buf.ptr + n, buf.len - n, @intCast(off + n));
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                else => return error.FileReadFailed,
            }
            if (rc == 0) return error.MalformedElf; // EOF mid-structure
            n += rc;
        }
    }

    fn size(self: *File) ResolveError!u64 {
        const rc = linux.lseek(self.fd, 0, linux.SEEK.END);
        switch (linux.errno(rc)) {
            .SUCCESS => return rc,
            else => return error.FileReadFailed,
        }
    }
};

// ── tests ────────────────────────────────────────────────────────────────────
//
// Three layers, none of them needing any privilege:
//  1. Pure: the vaddr -> file-offset conversion against hand-written
//     segments, including the skewed case that motivates this whole file.
//  2. A SYNTHETIC ELF64 built byte-by-byte in the test and written to a temp
//     file: full control over the layout, so the expected offsets are exact
//     constants rather than whatever the host's libc happens to look like.
//  3. A REAL on-disk library (`libc.so.6`), cross-checked by an INDEPENDENT
//     derivation — the section headers (`sh_addr`/`sh_offset`) rather than
//     the program headers this module uses. Both must agree; a
//     vaddr-vs-offset mix-up shows up as a mismatch. Skips (never fails) if
//     no such library is present.

const testing = std.testing;

test "ELF64 field offsets match std's struct layout" {
    try testing.expectEqual(EHDR_SIZE, @sizeOf(elf.Elf64_Ehdr));
    try testing.expectEqual(ehdr_type, @offsetOf(elf.Elf64_Ehdr, "e_type"));
    try testing.expectEqual(ehdr_phoff, @offsetOf(elf.Elf64_Ehdr, "e_phoff"));
    try testing.expectEqual(ehdr_shoff, @offsetOf(elf.Elf64_Ehdr, "e_shoff"));
    try testing.expectEqual(ehdr_ehsize, @offsetOf(elf.Elf64_Ehdr, "e_ehsize"));
    try testing.expectEqual(ehdr_phentsize, @offsetOf(elf.Elf64_Ehdr, "e_phentsize"));
    try testing.expectEqual(ehdr_phnum, @offsetOf(elf.Elf64_Ehdr, "e_phnum"));
    try testing.expectEqual(ehdr_shentsize, @offsetOf(elf.Elf64_Ehdr, "e_shentsize"));
    try testing.expectEqual(ehdr_shnum, @offsetOf(elf.Elf64_Ehdr, "e_shnum"));

    try testing.expectEqual(PHDR_SIZE, @sizeOf(elf.Elf64_Phdr));
    try testing.expectEqual(phdr_type, @offsetOf(elf.Elf64_Phdr, "p_type"));
    try testing.expectEqual(phdr_offset, @offsetOf(elf.Elf64_Phdr, "p_offset"));
    try testing.expectEqual(phdr_vaddr, @offsetOf(elf.Elf64_Phdr, "p_vaddr"));
    try testing.expectEqual(phdr_filesz, @offsetOf(elf.Elf64_Phdr, "p_filesz"));
    try testing.expectEqual(phdr_memsz, @offsetOf(elf.Elf64_Phdr, "p_memsz"));

    try testing.expectEqual(SHDR_SIZE, @sizeOf(elf.Elf64_Shdr));
    try testing.expectEqual(shdr_type, @offsetOf(elf.Elf64_Shdr, "sh_type"));
    try testing.expectEqual(shdr_offset, @offsetOf(elf.Elf64_Shdr, "sh_offset"));
    try testing.expectEqual(shdr_size, @offsetOf(elf.Elf64_Shdr, "sh_size"));
    try testing.expectEqual(shdr_link, @offsetOf(elf.Elf64_Shdr, "sh_link"));
    try testing.expectEqual(shdr_entsize, @offsetOf(elf.Elf64_Shdr, "sh_entsize"));

    try testing.expectEqual(SYM_SIZE, @sizeOf(elf.Elf64_Sym));
    try testing.expectEqual(sym_name, @offsetOf(elf.Elf64_Sym, "st_name"));
    try testing.expectEqual(sym_info, @offsetOf(elf.Elf64_Sym, "st_info"));
    try testing.expectEqual(sym_shndx, @offsetOf(elf.Elf64_Sym, "st_shndx"));
    try testing.expectEqual(sym_value, @offsetOf(elf.Elf64_Sym, "st_value"));
    try testing.expectEqual(sym_size, @offsetOf(elf.Elf64_Sym, "st_size"));
}

test "vaddrToFileOffset: the skewed segment is the whole point" {
    // Modeled on a real glibc layout: three 1:1 segments and one whose
    // vaddr runs 0x1000 ahead of its file offset.
    const segs = [_]Segment{
        .{ .p_offset = 0x0, .p_vaddr = 0x0, .p_filesz = 0x27000, .p_memsz = 0x27000 },
        .{ .p_offset = 0x28000, .p_vaddr = 0x28000, .p_filesz = 0x198000, .p_memsz = 0x198000 },
        .{ .p_offset = 0x20db98, .p_vaddr = 0x20eb98, .p_filesz = 0x4af0, .p_memsz = 0x121f8 },
    };

    // 1:1 segments.
    try testing.expectEqual(@as(?u64, 0x100), vaddrToFileOffset(&segs, 0x100));
    try testing.expectEqual(@as(?u64, 0xb5110), vaddrToFileOffset(&segs, 0xb5110));
    // The skewed one: offset = vaddr - 0x1000.
    try testing.expectEqual(@as(?u64, 0x20db98), vaddrToFileOffset(&segs, 0x20eb98));
    try testing.expectEqual(@as(?u64, 0x20eb98), vaddrToFileOffset(&segs, 0x20fb98));
    // Last byte still inside p_filesz.
    try testing.expectEqual(@as(?u64, 0x212687), vaddrToFileOffset(&segs, 0x213687));
    // One past p_filesz = .bss: no file bytes, must NOT fall through to
    // "offset + delta".
    try testing.expectEqual(@as(?u64, null), vaddrToFileOffset(&segs, 0x213688));
    // Between segments, and before everything.
    try testing.expectEqual(@as(?u64, null), vaddrToFileOffset(&segs, 0x27500));
    try testing.expectEqual(@as(?u64, null), vaddrToFileOffset(&segs, 0x400000));
    // A zero-filesz segment never matches.
    const empty = [_]Segment{.{ .p_offset = 0x10, .p_vaddr = 0x1000, .p_filesz = 0, .p_memsz = 0x2000 }};
    try testing.expectEqual(@as(?u64, null), vaddrToFileOffset(&empty, 0x1000));
}

test "nameMatches handles bare and version-suffixed symbol names" {
    try testing.expect(nameMatches("malloc\x00", "malloc"));
    try testing.expect(nameMatches("malloc@@GLIBC_2.2.5\x00", "malloc"));
    try testing.expect(nameMatches("malloc@GLIBC_2.2.5\x00", "malloc"));
    try testing.expect(!nameMatches("mallocx\x00", "malloc"));
    try testing.expect(!nameMatches("xmalloc\x00", "malloc"));
    try testing.expect(!nameMatches("\x00", "malloc"));
}

/// Build a small but structurally complete ELF64 shared object in memory.
/// Layout (all offsets are exact and asserted by the tests below):
///
/// ```text
/// 0x0000  Ehdr (64)
/// 0x0040  Phdr[0] PT_LOAD  off 0x0000 vaddr 0x0000 filesz 0x1000   (1:1)
/// 0x0078  Phdr[1] PT_LOAD  off 0x1000 vaddr 0x2000 filesz 0x0800   (skew 0x1000)
/// 0x0100  .strtab
/// 0x0200  .symtab (4 entries)
/// 0x0400  Shdr[0..4]
/// 0x1000  the second segment's bytes
/// ```
const SynthElf = struct {
    bytes: []u8,

    const strtab_off: usize = 0x100;
    const symtab_off: usize = 0x200;
    const shdr_off: usize = 0x400;
    const total: usize = 0x1800;

    // Symbols placed in the image.
    const flat_vaddr: u64 = 0x0400; // in segment 0 -> file offset 0x0400
    const skewed_vaddr: u64 = 0x2040; // in segment 1 -> file offset 0x1040
    const bss_vaddr: u64 = 0x2900; // past p_filesz -> no file mapping

    fn build(gpa: std.mem.Allocator) ![]u8 {
        const b = try gpa.alloc(u8, total);
        @memset(b, 0);

        // ── Ehdr ──
        @memcpy(b[0..4], elf.MAGIC);
        b[elf.EI.CLASS] = @intFromEnum(elf.CLASS.@"64");
        b[elf.EI.DATA] = switch (native_endian) {
            .little => @intFromEnum(elf.DATA.@"2LSB"),
            .big => @intFromEnum(elf.DATA.@"2MSB"),
        };
        b[elf.EI.VERSION] = 1;
        wr(u16, b, ehdr_type, 3); // ET_DYN
        wr(u64, b, ehdr_phoff, 0x40);
        wr(u64, b, ehdr_shoff, shdr_off);
        wr(u16, b, ehdr_ehsize, EHDR_SIZE);
        wr(u16, b, ehdr_phentsize, PHDR_SIZE);
        wr(u16, b, ehdr_phnum, 2);
        wr(u16, b, ehdr_shentsize, SHDR_SIZE);
        wr(u16, b, ehdr_shnum, 4);

        // ── Phdrs ──
        putPhdr(b, 0x40, 0x0000, 0x0000, 0x1000, 0x1000);
        putPhdr(b, 0x40 + PHDR_SIZE, 0x1000, 0x2000, 0x0800, 0x1000);

        // ── .strtab ── (index 0 must be the empty string)
        const names = "\x00flat_fn\x00skewed_fn\x00bss_obj\x00a_data_sym\x00";
        @memcpy(b[strtab_off..][0..names.len], names);
        const off_flat: u32 = 1;
        const off_skewed: u32 = 9;
        const off_bss: u32 = 19;
        const off_data: u32 = 27;

        // ── .symtab ── entry 0 is the reserved null symbol
        putSym(b, symtab_off + 1 * SYM_SIZE, off_flat, STT_FUNC, 1, flat_vaddr, 0x20);
        putSym(b, symtab_off + 2 * SYM_SIZE, off_skewed, STT_FUNC, 2, skewed_vaddr, 0x30);
        putSym(b, symtab_off + 3 * SYM_SIZE, off_bss, STT_OBJECT, 3, bss_vaddr, 8);
        putSym(b, symtab_off + 4 * SYM_SIZE, off_data, STT_OBJECT, 2, skewed_vaddr + 0x10, 4);

        // ── Shdrs ── 0 = null, 1 = .strtab, 2 = .symtab, 3 = a decoy
        putShdr(b, shdr_off + 1 * SHDR_SIZE, @intFromEnum(elf.SHT.STRTAB), strtab_off, names.len, 0, 0);
        putShdr(b, shdr_off + 2 * SHDR_SIZE, SHT_SYMTAB, symtab_off, 5 * SYM_SIZE, 1, SYM_SIZE);
        putShdr(b, shdr_off + 3 * SHDR_SIZE, @intFromEnum(elf.SHT.PROGBITS), 0x1000, 0x800, 0, 0);

        // Recognizable payload bytes at the two resolvable symbols, so a
        // test can prove the offset names the right place.
        b[0x0400] = 0xAA;
        b[0x1040] = 0xBB;
        return b;
    }

    fn wr(comptime T: type, buf: []u8, off: usize, v: T) void {
        std.mem.writeInt(T, buf[off..][0..@divExact(@typeInfo(T).int.bits, 8)], v, native_endian);
    }

    fn putPhdr(b: []u8, at: usize, p_off: u64, p_vaddr: u64, p_filesz: u64, p_memsz: u64) void {
        wr(u32, b, at + phdr_type, PT_LOAD);
        wr(u64, b, at + phdr_offset, p_off);
        wr(u64, b, at + phdr_vaddr, p_vaddr);
        wr(u64, b, at + phdr_filesz, p_filesz);
        wr(u64, b, at + phdr_memsz, p_memsz);
    }

    fn putSym(b: []u8, at: usize, st_name: u32, kind: u4, shndx: u16, value: u64, sz: u64) void {
        wr(u32, b, at + sym_name, st_name);
        b[at + sym_info] = (1 << 4) | @as(u8, kind); // STB_GLOBAL | kind
        wr(u16, b, at + sym_shndx, shndx);
        wr(u64, b, at + sym_value, value);
        wr(u64, b, at + sym_size, sz);
    }

    fn putShdr(b: []u8, at: usize, sh_ty: u32, off: u64, sz: u64, link: u32, ent: u64) void {
        wr(u32, b, at + shdr_type, sh_ty);
        wr(u64, b, at + shdr_offset, off);
        wr(u64, b, at + shdr_size, sz);
        wr(u32, b, at + shdr_link, link);
        wr(u64, b, at + shdr_entsize, ent);
    }
};

// ── fuzz: openImage off the wire, never panics ──────────────────────────────
//
// `openImage` is the entry point for a BPF loader's ELF64 container parse —
// bytes from a `.o` a caller asks to load, an attacker-supplied binary with
// offset/count tables (`e_shoff`/`e_shnum`, `sh_offset`/`sh_size`) that point
// into each other exactly like this file's own module doc warns about
// ("only the header and the section-header table are validated eagerly; a
// section whose sh_offset/sh_size runs past the end of the buffer is caught
// when its data is asked for"). Build a structurally valid image via the
// same `SynthElf` builder the round-trip tests above already use (so the
// fuzzer reaches the section-table walk and every accessor's deferred
// bounds-check, instead of bouncing off `NotAnElf` on the first four
// bytes), then truncate and/or flip bytes.
//
// NOTE: `readFileAlloc` (also named in the task this harness closes out) is
// deliberately NOT fuzzed here — it is a thin file-read wrapper (open +
// size-check against a caller-supplied cap + pread), not a parser; it never
// interprets the bytes it reads, so there is nothing structural to fuzz.
// `openImage` is the actual untrusted-container parser: it takes bytes
// directly with no file I/O at all, which is the real boundary and the
// target below.

test "fuzz: openImage never panics on a truncated/mutated synthetic ELF image" {
    try testing.fuzz({}, fuzzOpenImage, .{});
}

fn fuzzOpenImage(_: void, smith: *std.testing.Smith) !void {
    const gpa = testing.allocator;
    const seed = SynthElf.build(gpa) catch return;
    defer gpa.free(seed);

    const len: u32 = smith.valueRangeAtMost(u32, 0, @intCast(seed.len));
    const mutant = gpa.dupe(u8, seed[0..len]) catch return;
    defer gpa.free(mutant);

    const n_flips: u8 = smith.valueRangeAtMost(u8, 0, 12);
    var k: u8 = 0;
    while (k < n_flips and mutant.len > 0) : (k += 1) {
        mutant[smith.index(mutant.len)] = smith.value(u8);
    }

    var image = openImage(gpa, mutant, false) catch return;
    defer image.deinit();

    if (image.sections.len > 0) {
        fuzzWalkAccessors(&image, smith.index(image.sections.len), smith.value(u32));
    }
    _ = image.symtabIndex();
    _ = image.findSection("license");
}

/// The accessor walk one fuzz iteration performs, factored out so the
/// reachability test below drives the SAME calls the fuzzer makes rather
/// than a look-alike. Every one of these must fail closed (a typed
/// `ImageError`), never panic, against a section table whose
/// `sh_offset`/`sh_size`/`sh_entsize` a mutation may have pushed anywhere.
///
/// **`n` is an UNBOUNDED `u32`, and that is the point.** This walk used to
/// draw its index as `smith.index(symbolCount(i))` — i.e. always
/// `n < data.len / ent`, which is precisely the constraint that makes
/// `n * ent` unable to overflow. The harness therefore excluded, by
/// construction, the one domain in which the accessors' index arithmetic
/// could go wrong; the overflow panic that lived there was found by reading
/// the code, not by this fuzzer, and `object.zig`'s relocation walk feeds
/// exactly that domain (`rel.sym`, the high half of a raw `r_info`).
/// The in-range case is kept too — reduced from the same draw so it costs
/// no extra entropy — because the success path has to stay covered.
fn fuzzWalkAccessors(image: *const Image, i: usize, n: u32) void {
    _ = image.sectionName(i);
    _ = image.sectionData(i) catch {};
    _ = image.symbol(i, n) catch {};
    _ = image.relocation(i, n) catch {};
    if (image.symbolCount(i) catch null) |cnt| {
        if (cnt > 0) _ = image.symbol(i, n % cnt) catch {};
    }
    if (image.relocationCount(i) catch null) |rcnt| {
        if (rcnt > 0) _ = image.relocation(i, n % rcnt) catch {};
    }
}

test "the elfsym fuzz harness reaches the unbounded entry-index domain (reachability)" {
    // Guards the harness that guards the parser. The hostile shape is a
    // `sh_entsize` the file format never bounds from above; combined with an
    // index straight off the wire it is the arithmetic that used to panic.
    const gpa = testing.allocator;
    const seed = try SynthElf.build(gpa);
    defer gpa.free(seed);

    // Non-vacuity first, on the UNPATCHED image: the same walk over the
    // synthetic symtab (section 2) really does reach working accessors and
    // decode a symbol, so this test is not merely watching everything fail.
    {
        var ok_image = try openImage(gpa, seed, false);
        defer ok_image.deinit();
        try testing.expectEqual(@as(u32, 5), try ok_image.symbolCount(2));
        const sym = try ok_image.symbol(2, 1);
        try testing.expectEqualStrings("flat_fn", ok_image.symbolName(2, sym));
        fuzzWalkAccessors(&ok_image, 2, std.math.maxInt(u32));
    }

    // `1 << 62` is chosen so that the product with any index above 3
    // exceeds `maxInt(u64)` — the value the reject path must reach without
    // ever forming that product.
    const huge: u64 = 1 << 62;
    SynthElf.wr(u64, seed, SynthElf.shdr_off + 2 * SHDR_SIZE + shdr_entsize, huge);
    SynthElf.wr(u64, seed, SynthElf.shdr_off + 3 * SHDR_SIZE + shdr_entsize, huge);

    var image = try openImage(gpa, seed, false);
    defer image.deinit();

    // The exact call `object.zig:collectRelocations` makes — an index with
    // no count check in front of it — on both accessors, because the two
    // are byte-identical in shape and only one of them had a caller.
    try testing.expectError(error.MalformedElf, image.symbol(2, std.math.maxInt(u32)));
    try testing.expectError(error.MalformedElf, image.relocation(3, std.math.maxInt(u32)));
    // And the boundary of the overflow itself: n = 4 is the smallest index
    // whose product with `1 << 62` wraps.
    try testing.expectError(error.MalformedElf, image.symbol(2, 4));
    try testing.expectError(error.MalformedElf, image.relocation(3, 4));

    // Finally the harness's own walk, with the same unbounded index, over
    // both patched sections: it returns, which is the whole claim.
    fuzzWalkAccessors(&image, 2, std.math.maxInt(u32));
    fuzzWalkAccessors(&image, 3, std.math.maxInt(u32));
}

/// Write `bytes` to a private temp path and return the path (caller frees).
/// Raw syscalls only — this module forbids libc, and `std.fs`'s 0.16 API
/// needs an `Io` this module deliberately does not take.
fn writeTempFile(gpa: std.mem.Allocator, tag: []const u8, bytes: []const u8) ![:0]u8 {
    const path = try std.fmt.allocPrintSentinel(gpa, "/tmp/zig-libs-ebpf-{s}-{d}.bin", .{ tag, linux.getpid() }, 0);
    errdefer gpa.free(path);
    const rc = linux.open(path.ptr, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = true,
        .CLOEXEC = true,
    }, 0o600);
    if (linux.errno(rc) != .SUCCESS) return error.TempFileFailed;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    var n: usize = 0;
    while (n < bytes.len) {
        const w = linux.write(fd, bytes.ptr + n, bytes.len - n);
        switch (linux.errno(w)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.TempFileFailed,
        }
        n += w;
    }
    return path;
}

test "synthetic ELF: symbol offsets, including the skewed segment" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;

    const image = try SynthElf.build(gpa);
    defer gpa.free(image);
    const path = try writeTempFile(gpa, "synth", image);
    defer {
        _ = linux.unlink(path.ptr);
        gpa.free(path);
    }

    // A symbol in the 1:1 segment: offset == vaddr.
    const flat = try resolveFunc(gpa, path, "flat_fn");
    try testing.expectEqual(@as(u64, SynthElf.flat_vaddr), flat.vaddr);
    try testing.expectEqual(@as(u64, 0x0400), flat.file_offset);
    try testing.expectEqual(@as(u64, 0x20), flat.size);
    try testing.expectEqual(Symbol.Kind.func, flat.kind);
    try testing.expectEqual(Table.symtab, flat.table);
    try testing.expectEqual(@as(u8, 0xAA), image[@intCast(flat.file_offset)]);

    // The one that matters: vaddr 0x2040 in a segment mapped from 0x1000.
    const skew = try resolveFunc(gpa, path, "skewed_fn");
    try testing.expectEqual(@as(u64, SynthElf.skewed_vaddr), skew.vaddr);
    try testing.expectEqual(@as(u64, 0x1040), skew.file_offset);
    try testing.expect(skew.file_offset != skew.vaddr);
    try testing.expectEqual(@as(u8, 0xBB), image[@intCast(skew.file_offset)]);

    // A .bss-style symbol past p_filesz has no file bytes at all.
    try testing.expectError(error.NoFileMapping, resolve(gpa, path, "bss_obj"));

    // funcs_only filters data symbols out; the default does not.
    try testing.expectError(error.SymbolNotFound, resolveFunc(gpa, path, "a_data_sym"));
    const data = try resolve(gpa, path, "a_data_sym");
    try testing.expectEqual(Symbol.Kind.object, data.kind);
    try testing.expectEqual(@as(u64, 0x1050), data.file_offset);

    // Missing symbols and a .dynsym-only lookup on an object without one.
    try testing.expectError(error.SymbolNotFound, resolve(gpa, path, "nope"));
    try testing.expectError(
        error.SymbolNotFound,
        resolveOpts(gpa, path, "flat_fn", .{ .table = .dynsym }),
    );
    // The convenience wrapper agrees with the full result.
    try testing.expectEqual(@as(u64, 0x1040), try resolveFuncOffset(gpa, path, "skewed_fn"));
}

test "malformed inputs are typed errors, never a mis-parse" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;

    try testing.expectError(error.FileOpenFailed, resolve(gpa, "/nonexistent/zig-libs-ebpf", "x"));

    // Not an ELF at all.
    {
        const path = try writeTempFile(gpa, "notelf", "#!/bin/sh\necho hi\n" ** 8);
        defer {
            _ = linux.unlink(path.ptr);
            gpa.free(path);
        }
        try testing.expectError(error.NotAnElf, resolve(gpa, path, "x"));
    }
    // ELF magic, wrong class (32-bit).
    {
        const img = try SynthElf.build(gpa);
        defer gpa.free(img);
        img[elf.EI.CLASS] = @intFromEnum(elf.CLASS.@"32");
        const path = try writeTempFile(gpa, "elf32", img);
        defer {
            _ = linux.unlink(path.ptr);
            gpa.free(path);
        }
        try testing.expectError(error.UnsupportedElf, resolve(gpa, path, "x"));
    }
    // A section header table pointing past the end of the file.
    {
        const img = try SynthElf.build(gpa);
        defer gpa.free(img);
        SynthElf.wr(u64, img, ehdr_shoff, 0x100000);
        const path = try writeTempFile(gpa, "shoff", img);
        defer {
            _ = linux.unlink(path.ptr);
            gpa.free(path);
        }
        try testing.expectError(error.MalformedElf, resolve(gpa, path, "x"));
    }
    // An absurd section count.
    {
        const img = try SynthElf.build(gpa);
        defer gpa.free(img);
        SynthElf.wr(u16, img, ehdr_shnum, 0xffff);
        SynthElf.wr(u16, img, ehdr_shentsize, 0); // also under-sized
        const path = try writeTempFile(gpa, "shnum", img);
        defer {
            _ = linux.unlink(path.ptr);
            gpa.free(path);
        }
        try testing.expectError(error.MalformedElf, resolve(gpa, path, "x"));
    }
    // An empty name never resolves.
    try testing.expectError(error.SymbolNotFound, resolve(gpa, "/proc/self/exe", ""));
}

/// Independent oracle for the real-library test: derive a file offset from
/// the SECTION headers (`sh_addr` + `sh_offset`) instead of the program
/// headers `vaddrToFileOffset` uses. Two different tables that must agree.
fn fileOffsetViaSections(gpa: std.mem.Allocator, path: []const u8, vaddr: u64) !?u64 {
    const path_z = try gpa.dupeZ(u8, path);
    defer gpa.free(path_z);
    var file = try File.open(path_z.ptr);
    defer file.close();

    var ehdr: [EHDR_SIZE]u8 = undefined;
    try file.readExact(0, &ehdr);
    const shoff = rd(u64, &ehdr, ehdr_shoff);
    const shentsize = rd(u16, &ehdr, ehdr_shentsize);
    const shnum = rd(u16, &ehdr, ehdr_shnum);

    var buf: [SHDR_SIZE]u8 = undefined;
    var i: u64 = 0;
    while (i < shnum) : (i += 1) {
        try file.readExact(shoff + i * shentsize, &buf);
        const sh_addr = rd(u64, &buf, 16); // sh_addr
        const sh_off = rd(u64, &buf, shdr_offset);
        const sh_size = rd(u64, &buf, shdr_size);
        const sh_ty = rd(u32, &buf, shdr_type);
        if (sh_addr == 0 or sh_size == 0) continue;
        if (sh_ty == 8) continue; // SHT_NOBITS = .bss, no file bytes
        if (vaddr < sh_addr or vaddr >= sh_addr + sh_size) continue;
        return sh_off + (vaddr - sh_addr);
    }
    return null;
}

test "the elfsym size ceilings are the shipped literals, and each one rejects BEFORE it allocates" {
    // These three are the only guards on allocations sized straight from
    // the file: `max_sections` bounds `gpa.alloc(Section, shnum)` in the
    // file-reading path (which, unlike `openImage`, has no "the table must
    // fit in the file" cross-check), and `max_table_bytes` is the ONLY
    // bound on `gpa.alloc(u8, strtab.sh_size)` — `sh_size` is never
    // compared to the file length before that allocation.
    //
    // Written as decimal literals rather than as `1 << 16` / `64 << 20`,
    // and never as `max_sections + 1`: a test phrased in terms of the
    // constant re-asserts whatever the constant happens to be and stays
    // green for any value at all.
    try testing.expectEqual(@as(u64, 65536), max_sections); // 1 << 16
    try testing.expectEqual(@as(u64, 4096), max_segments); // 1 << 12
    try testing.expectEqual(@as(u64, 67108864), max_table_bytes); // 64 << 20

    if (builtin.os.tag != .linux) return error.SkipZigTest;

    // Every oversized *read* in this file already ends in
    // `error.MalformedElf` (that is what `readExact` returns at EOF), so an
    // error code alone cannot tell "the ceiling refused it" from "it was
    // allowed through and died later". A budgeted allocator can: the whole
    // resolve runs inside 1 MiB, so anything that gets PAST a ceiling and
    // allocates from the file's own numbers comes back `OutOfMemory`
    // instead. That is the discriminator below.
    const budget = try testing.allocator.alloc(u8, 1 << 20);
    defer testing.allocator.free(budget);

    // Non-vacuity: an untouched image resolves inside that budget, so the
    // two `MalformedElf`s below are the ceilings and not the budget.
    {
        const img = try SynthElf.build(testing.allocator);
        defer testing.allocator.free(img);
        const path = try writeTempFile(testing.allocator, "capok", img);
        defer {
            _ = linux.unlink(path.ptr);
            testing.allocator.free(path);
        }
        var fba = std.heap.FixedBufferAllocator.init(budget);
        const sym = try resolve(fba.allocator(), path, "flat_fn");
        try testing.expectEqual(SynthElf.flat_vaddr, sym.vaddr);
    }

    // `max_sections`. `e_shnum == 0` is the gABI escape that moves the real
    // count into section 0's `sh_size`, so the count is a full u64 and this
    // ceiling is the only thing in its way. One past the shipped value.
    {
        const img = try SynthElf.build(testing.allocator);
        defer testing.allocator.free(img);
        SynthElf.wr(u16, img, ehdr_shnum, 0);
        SynthElf.wr(u64, img, SynthElf.shdr_off + shdr_size, 65537);
        const path = try writeTempFile(testing.allocator, "shcap", img);
        defer {
            _ = linux.unlink(path.ptr);
            testing.allocator.free(path);
        }
        var fba = std.heap.FixedBufferAllocator.init(budget);
        // With the ceiling: refused. Without it: 65537 `Section`s are
        // allocated from a 1 MiB budget and the answer is `OutOfMemory`.
        try testing.expectError(error.MalformedElf, resolve(fba.allocator(), path, "flat_fn"));
    }

    // `max_table_bytes`, same shape: the string table's `sh_size` is what
    // sizes the allocation, and nothing has compared it to the file length.
    {
        const img = try SynthElf.build(testing.allocator);
        defer testing.allocator.free(img);
        SynthElf.wr(u64, img, SynthElf.shdr_off + 1 * SHDR_SIZE + shdr_size, 67108865);
        const path = try writeTempFile(testing.allocator, "tblcap", img);
        defer {
            _ = linux.unlink(path.ptr);
            testing.allocator.free(path);
        }
        var fba = std.heap.FixedBufferAllocator.init(budget);
        try testing.expectError(error.MalformedElf, resolve(fba.allocator(), path, "flat_fn"));
    }
}

test "real library: resolved offsets agree with an independent derivation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;

    // Verified by hand on the machine this was written on:
    //   readelf -lW /lib/x86_64-linux-gnu/libc.so.6   # PT_LOAD table
    //   nm -D --defined-only /lib/x86_64-linux-gnu/libc.so.6 | grep -w malloc
    //     -> 00000000000b5110 T malloc@@GLIBC_2.2.5
    //   readelf -sW /lib/x86_64-linux-gnu/libc.so.6 | grep -w environ
    // The exact numbers are NOT asserted (they change with every libc
    // update); what is asserted is that this module's program-header
    // derivation matches the section-header derivation for the same symbol,
    // which is what a vaddr-vs-file-offset mix-up would break.
    const candidates = [_][]const u8{
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib/libc.so.6",
        "/lib/aarch64-linux-gnu/libc.so.6",
    };
    const path: []const u8 = for (candidates) |c| {
        const rc = linux.open(@ptrCast(c.ptr), .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (linux.errno(rc) == .SUCCESS) {
            _ = linux.close(@intCast(rc));
            break c;
        }
    } else {
        if (verboseSkip()) std.debug.print("\nebpf elfsym real-library test SKIPPED: no libc.so.6 found.\n", .{});
        return error.SkipZigTest;
    };

    const sym = resolveFunc(gpa, path, "malloc") catch |e| {
        if (verboseSkip()) std.debug.print("\nebpf elfsym real-library test SKIPPED: malloc unresolvable ({s}).\n", .{@errorName(e)});
        return error.SkipZigTest;
    };
    try testing.expect(sym.vaddr != 0);
    try testing.expect(sym.kind == .func or sym.kind == .ifunc);

    const oracle = (try fileOffsetViaSections(gpa, path, sym.vaddr)) orelse {
        if (verboseSkip()) std.debug.print("\nebpf elfsym cross-check SKIPPED: no section covers malloc's vaddr.\n", .{});
        return error.SkipZigTest;
    };
    try testing.expectEqual(oracle, sym.file_offset);

    // The offset must also be inside the file.
    {
        const path_z = try gpa.dupeZ(u8, path);
        defer gpa.free(path_z);
        var f = try File.open(path_z.ptr);
        defer f.close();
        try testing.expect(sym.file_offset < try f.size());
    }

    // Every exported function in .dynsym must convert consistently too —
    // a broader sweep than one hand-picked symbol, still free of hardcoded
    // numbers. (A handful of symbols legitimately live outside any
    // addressed section; those are skipped, not failed.)
    for ([_][]const u8{ "free", "calloc", "getpid", "strlen", "memcpy" }) |name| {
        const s = resolveFunc(gpa, path, name) catch continue;
        const o = (try fileOffsetViaSections(gpa, path, s.vaddr)) orelse continue;
        try testing.expectEqual(o, s.file_offset);
    }
}
