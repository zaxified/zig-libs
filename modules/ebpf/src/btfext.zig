// SPDX-License-Identifier: MIT
//! `.BTF.ext` — the companion section a BPF object carries beside `.BTF`,
//! holding per-instruction **`func_info`**, **`line_info`** and **`core_relo`**
//! records — plus the part of **CO-RE** that is genuinely implementable and
//! testable here: resolving a field access against a *different* BTF (the
//! running kernel's) and computing the value the relocation would patch in.
//!
//! ## What CO-RE actually is, and what fraction of it lives here
//!
//! "Compile Once – Run Everywhere" is a compiler/loader contract: clang, told
//! `__attribute__((preserve_access_index))`, emits every struct field access
//! as a `ldx`/`stx` with a **placeholder offset** plus a `bpf_core_relo`
//! record saying "instruction N reads field `0:2:0` of local type `T`". The
//! loader then looks the same field up **by name** in the *target* BTF
//! (normally `/sys/kernel/btf/vmlinux`) and rewrites the instruction's
//! immediate. A program compiled against one kernel's headers therefore runs
//! on a kernel whose `struct task_struct` has a completely different layout.
//!
//! **Implemented here, and proved against real clang output:**
//! - the `.BTF.ext` container: header (including the *optional*
//!   `core_relo_off`/`_len` tail older producers omit), the per-section
//!   `rec_size` + `{sec_name_off, num_info, records…}` framing, and
//!   forward-compatible over-long records,
//! - access-string parsing (`"0:2:0"`) and the **local** spec walk that turns
//!   it into a member-name path plus array indices,
//! - **field-offset relocation against a target BTF**: candidate root type
//!   matched by name (with `___flavor` suffixes stripped) and kind, then each
//!   step re-resolved *by name* in the target — including descent through
//!   anonymous members, which `struct sk_buff` requires,
//! - all six `BPF_CORE_FIELD_*` values (`BYTE_OFFSET`, `BYTE_SIZE`,
//!   `EXISTS`, `SIGNED`, `LSHIFT_U64`, `RSHIFT_U64`), including the bitfield
//!   load-widening rule that makes `LSHIFT`/`RSHIFT` correct.
//!
//! **Deliberately NOT implemented (and not pretended):**
//! - **Instruction patching.** `computeFieldRelo` returns the value; nothing
//!   here rewrites a `[]Insn`. Wiring that needs a BPF-object loader
//!   (section-to-program mapping, map relocation, `fd_array`) this module
//!   does not have.
//! - **Multi-candidate matching and ambiguity detection.** libbpf collects
//!   *every* target type with a matching name, relocates against each, and
//!   errors if they disagree. This takes the **first** match and says so.
//!   On vmlinux BTF that is almost always the only one; it is not a
//!   guarantee.
//! - **The non-field relocation kinds**: `TYPE_ID_LOCAL`/`_TARGET`,
//!   `TYPE_EXISTS`, `TYPE_SIZE`, `TYPE_MATCHES`, `ENUMVAL_EXISTS`,
//!   `ENUMVAL_VALUE`. They are parsed and reported as
//!   `error.UnsupportedReloKind`, never silently computed wrong.
//! - **`.BTF.ext` relocation of the section-name offsets** (`.rel.BTF.ext`)
//!   and BPF-object ELF loading generally.
//!
//! Provenance: container format from kernel `Documentation/bpf/btf.rst`,
//! relocation kinds from `include/uapi/linux/bpf.h`
//! (`enum bpf_core_relo_kind`) and `Documentation/bpf/llvm_reloc.rst`; the
//! bitfield `LSHIFT`/`RSHIFT` derivation follows the semantics those
//! documents define for `BPF_CORE_READ_BITFIELD`. Validated against a real
//! `clang -target bpf -O2 -g` object (embedded as a fixture in this file's
//! tests) and against `/sys/kernel/btf/vmlinux`.

const std = @import("std");
const builtin = @import("builtin");
const btf = @import("btf.zig");

// Skip diagnostics are opt-in: `zig build test` must be silent on
// success (any stderr triggers the build runner's `failed command:`
// line even when the step succeeded), while the skip *count* still
// shows up in the summary regardless. Set ZIG_LIBS_VERBOSE_SKIP to any
// non-empty value to see the reasons. (std.posix.getenv doesn't exist
// in 0.16 — std.testing.environ + Environ.getPosix is the repo's
// existing env-read pattern for tests, see netconf's `envVar`.)
const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;

const native_endian = builtin.cpu.arch.endian();

const Btf = btf.Btf;
const Kind = btf.Kind;

// ── wire constants ──────────────────────────────────────────────────────────

/// `.BTF.ext` reuses `BTF_MAGIC`.
pub const magic: u16 = btf.magic;
pub const version: u8 = 1;

/// `sizeof(struct btf_ext_header)` before the optional `core_relo` pair.
pub const header_size_min: usize = 24;
/// …and with it.
pub const header_size_full: usize = 32;

/// Longest access string this parser will accept, in steps.
/// (libbpf's `BPF_CORE_SPEC_MAX_LEN`.)
pub const max_spec_len: usize = 64;

/// A `rec_size` larger than this is treated as corruption rather than
/// forward compatibility.
pub const max_rec_size: u32 = 256;

/// `struct bpf_func_info` — maps an instruction offset to the `BTF_KIND_FUNC`
/// describing the subprogram that starts there. Passed to `BPF_PROG_LOAD` as
/// `func_info`.
pub const FuncInfo = extern struct {
    /// Instruction index (NOT a byte offset) inside the program.
    insn_off: u32,
    /// A `BTF_KIND_FUNC` type id in the program's own BTF.
    type_id: u32,
};

/// `struct bpf_line_info` — source attribution for one instruction. Passed to
/// `BPF_PROG_LOAD` as `line_info`; it is what makes a verifier log quote your
/// source line.
pub const LineInfo = extern struct {
    insn_off: u32,
    /// Offsets into the program's BTF **string** section.
    file_name_off: u32,
    line_off: u32,
    /// `(line << 10) | col`.
    line_col: u32,

    pub fn line(self: LineInfo) u22 {
        return @truncate(self.line_col >> 10);
    }
    pub fn column(self: LineInfo) u10 {
        return @truncate(self.line_col);
    }
};

/// `struct bpf_core_relo` (`include/uapi/linux/bpf.h`).
pub const CoreRelo = extern struct {
    insn_off: u32,
    /// The **local** type id the access starts from.
    type_id: u32,
    /// Offset into the local BTF's string section of the access spec
    /// (`"0:2:0"`).
    access_str_off: u32,
    /// A `ReloKind`, kept as a raw u32 so an unknown future kind is data,
    /// not an invalid enum.
    kind: u32,

    pub fn reloKind(self: CoreRelo) ReloKind {
        return @enumFromInt(self.kind);
    }
};

/// `enum bpf_core_relo_kind`. Non-exhaustive: the kernel keeps adding kinds.
pub const ReloKind = enum(u32) {
    field_byte_offset = 0,
    field_byte_size = 1,
    field_exists = 2,
    field_signed = 3,
    field_lshift_u64 = 4,
    field_rshift_u64 = 5,
    type_id_local = 6,
    type_id_target = 7,
    type_exists = 8,
    type_size = 9,
    enumval_exists = 10,
    enumval_value = 11,
    type_matches = 12,
    _,

    /// True for the six kinds this module computes.
    pub fn isField(self: ReloKind) bool {
        return switch (self) {
            .field_byte_offset,
            .field_byte_size,
            .field_exists,
            .field_signed,
            .field_lshift_u64,
            .field_rshift_u64,
            => true,
            else => false,
        };
    }
};

// ── errors ──────────────────────────────────────────────────────────────────

pub const ExtParseError = error{
    /// Wrong magic.
    NotBtfExt,
    /// Right magic, a version or byte order this parser declines.
    UnsupportedExt,
    /// Structurally inconsistent: a section past the blob, a `rec_size` that
    /// cannot hold the record it describes, a `num_info` the section cannot
    /// hold.
    MalformedExt,
};

pub const CoreError = error{
    /// The access string is empty, has a non-numeric component, or is longer
    /// than `max_spec_len`.
    BadAccessSpec,
    /// A step indexes a member/element that does not exist in the LOCAL type.
    BadLocalSpec,
    /// No target type with the local root's (flavor-stripped) name and kind.
    TargetTypeNotFound,
    /// A bitfield whose bits do not fit in any load of <= 8 bytes.
    BitfieldTooWide,
    /// An array index times an element size overflowed the accumulated bit
    /// offset. Both factors come off the wire and neither is otherwise
    /// bounded: the index is parsed from a CO-RE access string in the BTF
    /// string section (`parseAccessIndices` bounds how MANY components there
    /// are, not how large each is), and the size is `sizeOf`, which for a
    /// struct returns the raw `size` word. Refused rather than wrapped: in
    /// ReleaseFast a wrapped `bit_offset` is not a crash but a wrong offset
    /// patched into a loaded BPF instruction, which is the worse outcome.
    FieldOffsetOverflow,
    /// One of the relocation kinds this module deliberately does not compute
    /// (see this file's header).
    UnsupportedReloKind,
} || btf.TypeError;

// ── the container ───────────────────────────────────────────────────────────

/// `struct btf_ext_header`, decoded. `core_relo_*` are 0 when the producer
/// emitted the short (pre-5.16) header.
pub const Header = struct {
    flags: u8,
    hdr_len: u32,
    func_info_off: u32,
    func_info_len: u32,
    line_info_off: u32,
    line_info_len: u32,
    core_relo_off: u32,
    core_relo_len: u32,

    pub fn hasCoreRelos(self: Header) bool {
        return self.hdr_len >= header_size_full and self.core_relo_len != 0;
    }
};

/// One `{sec_name_off, num_info, records…}` group inside a `.BTF.ext`
/// sub-section. `rec_size` may be **larger** than the struct this build knows
/// — a newer producer appending fields is forward-compatible, and the
/// accessors below read only the known prefix.
pub const SectionInfo = struct {
    /// Offset into the *program's* BTF string section of the ELF section name
    /// these records belong to (e.g. `"kprobe/x"`).
    sec_name_off: u32,
    rec_size: u32,
    count: u32,
    /// `count * rec_size` bytes.
    records: []const u8,

    /// Raw bytes of record `i`.
    pub fn raw(self: SectionInfo, i: u32) []const u8 {
        std.debug.assert(i < self.count);
        return self.records[i * self.rec_size ..][0..self.rec_size];
    }

    pub fn funcInfo(self: SectionInfo, i: u32) FuncInfo {
        const r = self.raw(i);
        return .{ .insn_off = rd32(r, 0), .type_id = rd32(r, 4) };
    }

    pub fn lineInfo(self: SectionInfo, i: u32) LineInfo {
        const r = self.raw(i);
        return .{
            .insn_off = rd32(r, 0),
            .file_name_off = rd32(r, 4),
            .line_off = rd32(r, 8),
            .line_col = rd32(r, 12),
        };
    }

    pub fn coreRelo(self: SectionInfo, i: u32) CoreRelo {
        const r = self.raw(i);
        return .{
            .insn_off = rd32(r, 0),
            .type_id = rd32(r, 4),
            .access_str_off = rd32(r, 8),
            .kind = rd32(r, 12),
        };
    }
};

/// Walks the `{sec_name_off, num_info, records…}` groups of one sub-section.
/// Cannot fail: `Ext.parse` already validated every group.
pub const SectionIter = struct {
    rec_size: u32,
    data: []const u8,
    pos: usize = 0,

    pub fn next(self: *SectionIter) ?SectionInfo {
        if (self.pos + 8 > self.data.len) return null;
        const sec_name_off = rd32(self.data, self.pos);
        const count = rd32(self.data, self.pos + 4);
        const start = self.pos + 8;
        const bytes = @as(usize, count) * self.rec_size;
        if (start + bytes > self.data.len) return null;
        self.pos = start + bytes;
        return .{
            .sec_name_off = sec_name_off,
            .rec_size = self.rec_size,
            .count = count,
            .records = self.data[start..][0..bytes],
        };
    }
};

/// A parsed `.BTF.ext`. Borrows `bytes`; holds no allocation, so there is
/// nothing to `deinit`.
pub const Ext = struct {
    raw: []const u8,
    hdr: Header,
    /// `rec_size` + payload for each sub-section (payload excludes the
    /// leading `rec_size` word). A zero-length sub-section has `rec_size` 0.
    func_info_rec_size: u32,
    func_info: []const u8,
    line_info_rec_size: u32,
    line_info: []const u8,
    core_relo_rec_size: u32,
    core_relo: []const u8,

    pub fn funcInfos(self: *const Ext) SectionIter {
        return .{ .rec_size = self.func_info_rec_size, .data = self.func_info };
    }
    pub fn lineInfos(self: *const Ext) SectionIter {
        return .{ .rec_size = self.line_info_rec_size, .data = self.line_info };
    }
    pub fn coreRelos(self: *const Ext) SectionIter {
        return .{ .rec_size = self.core_relo_rec_size, .data = self.core_relo };
    }
};

/// Parse a `.BTF.ext` blob. Every sub-section is walked here, so the
/// iterators above can be infallible.
pub fn parseExt(bytes: []const u8) ExtParseError!Ext {
    if (bytes.len < 8) return error.NotBtfExt;
    const m = std.mem.readInt(u16, bytes[0..2], native_endian);
    if (m != magic) {
        if (@byteSwap(m) == magic) return error.UnsupportedExt;
        return error.NotBtfExt;
    }
    if (bytes[2] != version) return error.UnsupportedExt;
    const flags = bytes[3];
    const hdr_len = rd32(bytes, 4);
    if (hdr_len < header_size_min) return error.MalformedExt;
    if (hdr_len > bytes.len) return error.MalformedExt;

    var hdr: Header = .{
        .flags = flags,
        .hdr_len = hdr_len,
        .func_info_off = rd32(bytes, 8),
        .func_info_len = rd32(bytes, 12),
        .line_info_off = rd32(bytes, 16),
        .line_info_len = rd32(bytes, 20),
        .core_relo_off = 0,
        .core_relo_len = 0,
    };
    if (hdr_len >= header_size_full) {
        hdr.core_relo_off = rd32(bytes, 24);
        hdr.core_relo_len = rd32(bytes, 28);
    }

    const data = bytes[hdr_len..];
    var out: Ext = .{
        .raw = bytes,
        .hdr = hdr,
        .func_info_rec_size = 0,
        .func_info = &.{},
        .line_info_rec_size = 0,
        .line_info = &.{},
        .core_relo_rec_size = 0,
        .core_relo = &.{},
    };

    const parts = [_]struct { off: u32, len: u32, min_rec: u32, which: u8 }{
        .{ .off = hdr.func_info_off, .len = hdr.func_info_len, .min_rec = @sizeOf(FuncInfo), .which = 0 },
        .{ .off = hdr.line_info_off, .len = hdr.line_info_len, .min_rec = @sizeOf(LineInfo), .which = 1 },
        .{ .off = hdr.core_relo_off, .len = hdr.core_relo_len, .min_rec = @sizeOf(CoreRelo), .which = 2 },
    };
    for (parts) |p| {
        if (p.len == 0) continue;
        // u64 arithmetic: a 0xffffffff offset must not wrap into range.
        if (@as(u64, p.off) + @as(u64, p.len) > data.len) return error.MalformedExt;
        if (p.len < 4) return error.MalformedExt;
        const sec = data[p.off..][0..p.len];
        const rec_size = rd32(sec, 0);
        if (rec_size < p.min_rec or rec_size > max_rec_size or rec_size % 4 != 0) return error.MalformedExt;
        const payload = sec[4..];
        try validateGroups(payload, rec_size);
        switch (p.which) {
            0 => {
                out.func_info_rec_size = rec_size;
                out.func_info = payload;
            },
            1 => {
                out.line_info_rec_size = rec_size;
                out.line_info = payload;
            },
            else => {
                out.core_relo_rec_size = rec_size;
                out.core_relo = payload;
            },
        }
    }
    return out;
}

fn validateGroups(payload: []const u8, rec_size: u32) ExtParseError!void {
    var pos: usize = 0;
    while (pos < payload.len) {
        if (payload.len - pos < 8) return error.MalformedExt;
        const count = rd32(payload, pos + 4);
        const bytes = @as(u64, count) * rec_size;
        if (payload.len - pos - 8 < bytes) return error.MalformedExt;
        pos += 8 + @as(usize, @intCast(bytes));
    }
}

fn rd32(buf: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, buf[off..][0..4], native_endian);
}

// ── CO-RE: access specs ─────────────────────────────────────────────────────

/// One step of a parsed access spec. `name` is `null` when the step indexes
/// an **array** (including the mandatory leading root index, which treats the
/// root type as `root[]` — that is how `&ptr[3]->field` is expressed).
pub const SpecStep = struct {
    index: u32,
    name: ?[]const u8,
};

/// A local access spec, resolved: the member-name path a target BTF is
/// searched by, plus the local bit offset it lands at.
pub const FieldSpec = struct {
    root_type_id: u32,
    steps: [max_spec_len]SpecStep,
    len: usize,
    /// Bit offset within the root type, in the BTF the spec was parsed
    /// against.
    bit_offset: u64,
    /// Type id of the accessed field.
    leaf_type_id: u32,
    /// Non-zero when the leaf is a bitfield member.
    bitfield_size: u8,

    pub fn slice(self: *const FieldSpec) []const SpecStep {
        return self.steps[0..self.len];
    }
};

/// Parse `"0:2:0"` into raw indices. At least one component is mandatory.
pub fn parseAccessIndices(access: []const u8, out: *[max_spec_len]u32) CoreError!usize {
    if (access.len == 0) return error.BadAccessSpec;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, access, ':');
    while (it.next()) |part| {
        if (n >= max_spec_len) return error.BadAccessSpec;
        if (part.len == 0) return error.BadAccessSpec;
        out[n] = std.fmt.parseInt(u32, part, 10) catch return error.BadAccessSpec;
        n += 1;
    }
    return n;
}

/// Walk `access` through `local`, starting at `root_type_id`, accumulating
/// the local bit offset and recording each member's **name** — the names are
/// what the target lookup uses, because a member's *index* is exactly the
/// thing CO-RE exists to stop depending on.
/// `bit_offset += index * size * 8`, with every step checked.
///
/// Four sites needed this — two walking the local BTF and two the target — so
/// it is one rule rather than four guards, and a fifth caller cannot get it
/// wrong by omission.
fn addIndexedBitOffset(bit_offset: *u64, index: u32, size: u64) error{FieldOffsetOverflow}!void {
    const bits = std.math.mul(u64, size, 8) catch return error.FieldOffsetOverflow;
    const delta = std.math.mul(u64, @as(u64, index), bits) catch return error.FieldOffsetOverflow;
    bit_offset.* = std.math.add(u64, bit_offset.*, delta) catch return error.FieldOffsetOverflow;
}

pub fn parseFieldSpec(local: *const Btf, root_type_id: u32, access: []const u8) CoreError!FieldSpec {
    var idx: [max_spec_len]u32 = undefined;
    const n = try parseAccessIndices(access, &idx);

    var spec: FieldSpec = .{
        .root_type_id = root_type_id,
        .steps = undefined,
        .len = 0,
        .bit_offset = 0,
        .leaf_type_id = root_type_id,
        .bitfield_size = 0,
    };

    // Step 0 is an ARRAY index over the root type (`root[i]`).
    var cur = try local.skipModifiers(root_type_id);
    if (idx[0] != 0) {
        const sz = try local.sizeOf(cur);
        try addIndexedBitOffset(&spec.bit_offset, idx[0], sz);
    }
    spec.steps[0] = .{ .index = idx[0], .name = null };
    spec.len = 1;

    var i: usize = 1;
    while (i < n) : (i += 1) {
        const t = try local.byId(cur);
        switch (t.kind) {
            .@"struct", .@"union" => {
                if (idx[i] >= t.vlen) return error.BadLocalSpec;
                const m = try local.member(t, @intCast(idx[i]));
                spec.bit_offset += m.bit_offset;
                spec.bitfield_size = m.bitfield_size;
                const name = local.str(m.name_off) orelse return error.BadLocalSpec;
                spec.steps[spec.len] = .{ .index = idx[i], .name = if (name.len == 0) null else name };
                spec.len += 1;
                cur = try local.skipModifiers(m.type_id);
                spec.leaf_type_id = m.type_id;
            },
            .array => {
                const a = try local.arrayInfo(t);
                const esz = try local.sizeOf(a.elem_type);
                try addIndexedBitOffset(&spec.bit_offset, idx[i], esz);
                spec.bitfield_size = 0;
                spec.steps[spec.len] = .{ .index = idx[i], .name = null };
                spec.len += 1;
                cur = try local.skipModifiers(a.elem_type);
                spec.leaf_type_id = a.elem_type;
            },
            else => return error.BadLocalSpec,
        }
    }
    return spec;
}

/// Strip a CO-RE **flavor** suffix: `task_struct___v58` names the same target
/// type as `task_struct`. Everything from the first `___` on is dropped.
pub fn stripFlavor(name: []const u8) []const u8 {
    const at = std.mem.indexOf(u8, name, "___") orelse return name;
    return name[0..at];
}

/// Re-resolve a local spec against `target`, **by name**. Returns `null` when
/// the root type or any named member is absent — which is exactly what a
/// `BPF_CORE_FIELD_EXISTS` relocation reports as 0.
///
/// Matching is single-candidate: the first target type with the root's
/// flavor-stripped name and kind wins. See this file's header for why that is
/// weaker than libbpf.
pub fn matchFieldSpec(
    local: *const Btf,
    spec: FieldSpec,
    target: *const Btf,
) CoreError!?FieldSpec {
    const root_local = try local.byId(try local.skipModifiers(spec.root_type_id));
    const raw_name = local.str(root_local.name_off) orelse return error.TargetTypeNotFound;
    if (raw_name.len == 0) return error.TargetTypeNotFound; // an anonymous root cannot be matched by name
    const want = stripFlavor(raw_name);

    const root_target = target.findByNameKind(want, root_local.kind) orelse return null;

    var out: FieldSpec = .{
        .root_type_id = root_target,
        .steps = undefined,
        .len = 0,
        .bit_offset = 0,
        .leaf_type_id = root_target,
        .bitfield_size = 0,
    };

    var cur = try target.skipModifiers(root_target);
    const steps = spec.slice();
    if (steps[0].index != 0) {
        const sz = try target.sizeOf(cur);
        try addIndexedBitOffset(&out.bit_offset, steps[0].index, sz);
    }
    out.steps[0] = .{ .index = steps[0].index, .name = null };
    out.len = 1;

    for (steps[1..]) |st| {
        const t = try target.byId(cur);
        if (st.name) |name| {
            if (!t.isComposite()) return null;
            const f = (try target.findMember(cur, name)) orelse return null;
            out.bit_offset += f.bit_offset;
            out.bitfield_size = f.bitfield_size;
            out.steps[out.len] = .{ .index = f.index, .name = name };
            out.len += 1;
            cur = try target.skipModifiers(f.type_id);
            out.leaf_type_id = f.type_id;
        } else {
            // An array step, or an anonymous member step. Anonymous members
            // cannot be matched by name, so their index is used as-is —
            // the one place this falls back to positional matching, and the
            // same thing libbpf does for unnamed members.
            switch (t.kind) {
                .array => {
                    const a = try target.arrayInfo(t);
                    const esz = try target.sizeOf(a.elem_type);
                    try addIndexedBitOffset(&out.bit_offset, st.index, esz);
                    out.bitfield_size = 0;
                    out.steps[out.len] = .{ .index = st.index, .name = null };
                    out.len += 1;
                    cur = try target.skipModifiers(a.elem_type);
                    out.leaf_type_id = a.elem_type;
                },
                .@"struct", .@"union" => {
                    if (st.index >= t.vlen) return null;
                    const m = try target.member(t, @intCast(st.index));
                    out.bit_offset += m.bit_offset;
                    out.bitfield_size = m.bitfield_size;
                    out.steps[out.len] = .{ .index = st.index, .name = null };
                    out.len += 1;
                    cur = try target.skipModifiers(m.type_id);
                    out.leaf_type_id = m.type_id;
                },
                else => return null,
            }
        }
    }
    return out;
}

// ── CO-RE: the computed values ──────────────────────────────────────────────

/// Everything the six `BPF_CORE_FIELD_*` relocations are derived from, for
/// one resolved field.
pub const FieldInfo = struct {
    /// `BPF_CORE_FIELD_BYTE_OFFSET` — the offset of the **load**, which for a
    /// bitfield is the start of the widened access, not of the bits.
    byte_offset: u64,
    /// `BPF_CORE_FIELD_BYTE_SIZE` — the width of that load.
    byte_size: u64,
    /// `BPF_CORE_FIELD_LSHIFT_U64`.
    lshift_u64: u8,
    /// `BPF_CORE_FIELD_RSHIFT_U64`.
    rshift_u64: u8,
    /// `BPF_CORE_FIELD_SIGNED`.
    signed: bool,
    /// Raw bit offset of the field within the root type.
    bit_offset: u64,
    /// Width in bits (`8 * byte_size` for a non-bitfield).
    bit_size: u8,
    /// Non-zero iff the field is a bitfield.
    bitfield_size: u8,
    /// Type id of the field, in the BTF it was resolved against.
    type_id: u32,

    /// The value the named relocation kind would patch into an instruction.
    pub fn value(self: FieldInfo, kind: ReloKind) CoreError!u64 {
        return switch (kind) {
            .field_byte_offset => self.byte_offset,
            .field_byte_size => self.byte_size,
            .field_exists => 1,
            .field_signed => @intFromBool(self.signed),
            .field_lshift_u64 => self.lshift_u64,
            .field_rshift_u64 => self.rshift_u64,
            else => error.UnsupportedReloKind,
        };
    }
};

/// The outcome of one field relocation.
pub const ReloResult = struct {
    kind: ReloKind,
    /// False when the field is absent from the target BTF. Only
    /// `field_exists` survives that (as 0); every other kind is meaningless
    /// and `value` is 0.
    exists: bool,
    /// The value to patch in.
    value: u64,
    /// `null` when `exists` is false.
    field: ?FieldInfo,
};

/// Derive the load geometry for a field at `bit_offset` of type `type_id`.
///
/// The bitfield rule is the subtle part: a bitfield is read with an *aligned*
/// load of the member's own base type, widened (1 -> 2 -> 4 -> 8 bytes) until
/// the bits actually fit inside it. `LSHIFT_U64`/`RSHIFT_U64` then position
/// the value in a 64-bit register:
/// `(x << lshift) >> rshift` yields the field (arithmetic shift when signed).
pub fn fieldGeometry(b: *const Btf, type_id: u32, bit_offset: u64, bitfield_size: u8) CoreError!FieldInfo {
    const mt = try b.resolve(type_id);
    const signed = switch (mt.kind) {
        .int => (try b.intInfo(mt)).isSigned(),
        .@"enum", .enum64 => mt.kind_flag,
        else => false,
    };

    var byte_size: u64 = undefined;
    var byte_offset: u64 = undefined;
    var bit_size: u8 = undefined;

    if (bitfield_size == 0) {
        byte_size = try b.sizeOf(type_id);
        if (byte_size == 0 or byte_size > 8) {
            // Not a scalar load (a nested struct, or a >8-byte type): the
            // offset is still meaningful, the shifts are not.
            return .{
                .byte_offset = bit_offset / 8,
                .byte_size = byte_size,
                .lshift_u64 = 0,
                .rshift_u64 = 0,
                .signed = signed,
                .bit_offset = bit_offset,
                .bit_size = 0,
                .bitfield_size = 0,
                .type_id = type_id,
            };
        }
        bit_size = @intCast(byte_size * 8);
        byte_offset = bit_offset / 8;
    } else {
        bit_size = bitfield_size;
        byte_size = try b.sizeOf(type_id);
        if (byte_size == 0) return error.BitfieldTooWide;
        byte_offset = bit_offset / 8 / byte_size * byte_size;
        // Widen until the bits fit inside one aligned load.
        while (bit_offset + bit_size - byte_offset * 8 > byte_size * 8) {
            if (byte_size >= 8) return error.BitfieldTooWide;
            byte_size *= 2;
            byte_offset = bit_offset / 8 / byte_size * byte_size;
        }
    }

    const inner = bit_offset + bit_size - byte_offset * 8;
    const lshift: u64 = switch (native_endian) {
        .little => 64 - inner,
        .big => (8 - byte_size) * 8 + (bit_offset - byte_offset * 8),
    };
    return .{
        .byte_offset = byte_offset,
        .byte_size = byte_size,
        .lshift_u64 = @intCast(lshift),
        .rshift_u64 = @intCast(64 - bit_size),
        .signed = signed,
        .bit_offset = bit_offset,
        .bit_size = bit_size,
        .bitfield_size = bitfield_size,
        .type_id = type_id,
    };
}

/// Resolve `path` (a chain of member names) inside the type named `type_name`
/// in `b`, and return its load geometry — the "field offset by name" case,
/// usable with no `.BTF.ext` at all:
///
/// ```zig
/// const f = (try btfext.fieldByName(&vmlinux, "task_struct", &.{"pid"})).?;
/// // f.byte_offset is where `pid` lives in THIS kernel.
/// ```
pub fn fieldByName(b: *const Btf, type_name: []const u8, path: []const []const u8) CoreError!?FieldInfo {
    const root = b.findByNameKind(stripFlavor(type_name), .@"struct") orelse
        b.findByNameKind(stripFlavor(type_name), .@"union") orelse
        return null;
    const f = (try b.findPath(root, path)) orelse return null;
    return try fieldGeometry(b, f.type_id, f.bit_offset, f.bitfield_size);
}

/// Apply one `bpf_core_relo` from `local` against `target`.
///
/// `relo.access_str_off` is read out of **`local`**'s string section, which is
/// where clang put it. A relocation kind outside the six `FIELD_*` ones is
/// `error.UnsupportedReloKind` — never a silently wrong number.
pub fn computeFieldRelo(local: *const Btf, target: *const Btf, relo: CoreRelo) CoreError!ReloResult {
    const kind = relo.reloKind();
    if (!kind.isField()) return error.UnsupportedReloKind;
    const access = local.str(relo.access_str_off) orelse return error.BadAccessSpec;

    const lspec = try parseFieldSpec(local, relo.type_id, access);
    const tspec = (try matchFieldSpec(local, lspec, target)) orelse {
        // Absent in the target. Only FIELD_EXISTS has a defined answer.
        if (kind == .field_exists) return .{ .kind = kind, .exists = false, .value = 0, .field = null };
        return .{ .kind = kind, .exists = false, .value = 0, .field = null };
    };

    const geo = try fieldGeometry(target, tspec.leaf_type_id, tspec.bit_offset, tspec.bitfield_size);
    return .{ .kind = kind, .exists = true, .value = try geo.value(kind), .field = geo };
}

// ── tests ────────────────────────────────────────────────────────────────────
//
// Three layers, none needing privilege:
//  1. SYNTHETIC `.BTF.ext` blobs built byte-by-byte, well-formed and hostile
//     (bad magic, short header, a section past the blob, a `rec_size` too
//     small / not a multiple of 4 / absurd, a `num_info` the section cannot
//     hold, a truncated group header).
//  2. A REAL `clang -target bpf -O2 -g` object's `.BTF` + `.BTF.ext`,
//     embedded below as a byte fixture, whose four `core_relo` records are
//     genuine compiler output. Regenerate with the recipe above the fixture.
//  3. That fixture RELOCATED AGAINST THE RUNNING KERNEL's
//     `/sys/kernel/btf/vmlinux` — the actual CO-RE operation. The local
//     `struct task_struct` in the fixture has `pid` at byte 0; the kernel's
//     has it thousands of bytes in, so a relocation that did nothing would be
//     visible immediately. Structural assertions only (offsets change with
//     every kernel build); cross-checked by hand with
//       bpftool btf dump file /sys/kernel/btf/vmlinux format raw
//     which on the machine this was written on reported
//     `task_struct.pid bits_offset=22400` (= byte 2800) and
//     `sk_buff.fclone bits_offset=1010 bitfield_size=2`.

const testing = std.testing;

test "wire layout: the .BTF.ext record structs" {
    try testing.expectEqual(@as(usize, 8), @sizeOf(FuncInfo));
    try testing.expectEqual(@as(usize, 16), @sizeOf(LineInfo));
    try testing.expectEqual(@as(usize, 16), @sizeOf(CoreRelo));
    try testing.expectEqual(@as(usize, 0), @offsetOf(CoreRelo, "insn_off"));
    try testing.expectEqual(@as(usize, 4), @offsetOf(CoreRelo, "type_id"));
    try testing.expectEqual(@as(usize, 8), @offsetOf(CoreRelo, "access_str_off"));
    try testing.expectEqual(@as(usize, 12), @offsetOf(CoreRelo, "kind"));

    const li: LineInfo = .{ .insn_off = 0, .file_name_off = 0, .line_off = 0, .line_col = (17 << 10) | 9 };
    try testing.expectEqual(@as(u22, 17), li.line());
    try testing.expectEqual(@as(u10, 9), li.column());

    try testing.expect(ReloKind.field_byte_offset.isField());
    try testing.expect(ReloKind.field_rshift_u64.isField());
    try testing.expect(!ReloKind.type_id_local.isField());
    try testing.expect(!ReloKind.enumval_value.isField());
    // A kind this build has never heard of must not be an invalid enum.
    const future: CoreRelo = .{ .insn_off = 0, .type_id = 1, .access_str_off = 1, .kind = 999 };
    try testing.expectEqual(@as(u32, 999), @intFromEnum(future.reloKind()));
    try testing.expect(!future.reloKind().isField());
}

test "access-spec parsing accepts what clang emits and refuses the rest" {
    var out: [max_spec_len]u32 = undefined;
    try testing.expectEqual(@as(usize, 1), try parseAccessIndices("0", &out));
    try testing.expectEqual(@as(u32, 0), out[0]);
    try testing.expectEqual(@as(usize, 3), try parseAccessIndices("0:2:0", &out));
    try testing.expectEqual(@as(u32, 2), out[1]);
    try testing.expectEqual(@as(usize, 2), try parseAccessIndices("3:17", &out));
    try testing.expectEqual(@as(u32, 3), out[0]);
    try testing.expectEqual(@as(u32, 17), out[1]);

    try testing.expectError(error.BadAccessSpec, parseAccessIndices("", &out));
    try testing.expectError(error.BadAccessSpec, parseAccessIndices("0:", &out));
    try testing.expectError(error.BadAccessSpec, parseAccessIndices(":0", &out));
    try testing.expectError(error.BadAccessSpec, parseAccessIndices("0::1", &out));
    try testing.expectError(error.BadAccessSpec, parseAccessIndices("x", &out));
    try testing.expectError(error.BadAccessSpec, parseAccessIndices("-1", &out));
    try testing.expectError(error.BadAccessSpec, parseAccessIndices("99999999999", &out));
    // Longer than max_spec_len.
    {
        var buf: [max_spec_len * 2 + 4]u8 = undefined;
        var n: usize = 0;
        for (0..max_spec_len + 1) |i| {
            if (i != 0) {
                buf[n] = ':';
                n += 1;
            }
            buf[n] = '1';
            n += 1;
        }
        try testing.expectError(error.BadAccessSpec, parseAccessIndices(buf[0..n], &out));
    }
}

test "stripFlavor" {
    try testing.expectEqualStrings("task_struct", stripFlavor("task_struct"));
    try testing.expectEqualStrings("task_struct", stripFlavor("task_struct___v58"));
    try testing.expectEqualStrings("t", stripFlavor("t___"));
    try testing.expectEqualStrings("a__b", stripFlavor("a__b"));
}

// ── synthetic .BTF.ext ──────────────────────────────────────────────────────

/// Assemble a `.BTF.ext` blob byte by byte.
const SynthExt = struct {
    fn build(
        gpa: std.mem.Allocator,
        func: []const u8,
        line: []const u8,
        core: []const u8,
        hdr_len: u32,
    ) ![]u8 {
        const total = hdr_len + func.len + line.len + core.len;
        const out = try gpa.alloc(u8, total);
        @memset(out, 0);
        std.mem.writeInt(u16, out[0..2], magic, native_endian);
        out[2] = version;
        std.mem.writeInt(u32, out[4..8], hdr_len, native_endian);
        std.mem.writeInt(u32, out[8..12], 0, native_endian);
        std.mem.writeInt(u32, out[12..16], @intCast(func.len), native_endian);
        std.mem.writeInt(u32, out[16..20], @intCast(func.len), native_endian);
        std.mem.writeInt(u32, out[20..24], @intCast(line.len), native_endian);
        if (hdr_len >= header_size_full) {
            std.mem.writeInt(u32, out[24..28], @intCast(func.len + line.len), native_endian);
            std.mem.writeInt(u32, out[28..32], @intCast(core.len), native_endian);
        }
        @memcpy(out[hdr_len..][0..func.len], func);
        @memcpy(out[hdr_len + func.len ..][0..line.len], line);
        @memcpy(out[hdr_len + func.len + line.len ..][0..core.len], core);
        return out;
    }

    /// `rec_size` word + one group of `n` records of `rec_size` bytes.
    fn section(gpa: std.mem.Allocator, rec_size: u32, sec_name_off: u32, records: []const u32) ![]u8 {
        const n: u32 = @intCast(records.len * 4 / rec_size);
        const out = try gpa.alloc(u8, 4 + 8 + records.len * 4);
        std.mem.writeInt(u32, out[0..4], rec_size, native_endian);
        std.mem.writeInt(u32, out[4..8], sec_name_off, native_endian);
        std.mem.writeInt(u32, out[8..12], n, native_endian);
        for (records, 0..) |w, i| {
            std.mem.writeInt(u32, out[12 + i * 4 ..][0..4], w, native_endian);
        }
        return out;
    }
};

// ── fuzz: parseExt off the wire, never panics ───────────────────────────────
//
// `parseExt` is the entry point for a `.BTF.ext` blob lifted out of an
// untrusted object file — same container shape as `btf.parse` (magic gate,
// header length, offset/length pairs into `data` checked in u64 so a
// `0xffffffff` offset cannot wrap), plus its own layer of
// `{sec_name_off, num_info, records…}` groups per sub-section
// (`validateGroups`). Build a structurally valid three-sub-section blob via
// the same `SynthExt` fixture the hand-written tests below already use, so
// the fuzzer reaches the group walk and the per-record accessors instead of
// bouncing off `NotBtfExt` on the first two bytes, then truncate and/or
// flip bytes.

test "fuzz: parseExt never panics on a truncated/mutated synthetic .BTF.ext blob" {
    try testing.fuzz({}, fuzzParseExt, .{});
}

fn fuzzParseExt(_: void, smith: *std.testing.Smith) !void {
    const gpa = testing.allocator;
    const func = SynthExt.section(gpa, 8, 1, &.{ 0, 7, 16, 9 }) catch return; // 2 FuncInfo
    defer gpa.free(func);
    const line = SynthExt.section(gpa, 16, 1, &.{ 0, 2, 3, (5 << 10) | 4 }) catch return; // 1 LineInfo
    defer gpa.free(line);
    const core = SynthExt.section(gpa, 16, 1, &.{ 8, 4, 11, 0, 24, 4, 15, 5 }) catch return; // 2 CoreRelo
    defer gpa.free(core);
    const seed = SynthExt.build(gpa, func, line, core, header_size_full) catch return;
    defer gpa.free(seed);

    const len: u32 = smith.valueRangeAtMost(u32, 0, @intCast(seed.len));
    const mutant = gpa.dupe(u8, seed[0..len]) catch return;
    defer gpa.free(mutant);

    const n_flips: u8 = smith.valueRangeAtMost(u8, 0, 16);
    var k: u8 = 0;
    while (k < n_flips and mutant.len > 0) : (k += 1) {
        mutant[smith.index(mutant.len)] = smith.value(u8);
    }

    const ext = parseExt(mutant) catch return;
    _ = ext.hdr.hasCoreRelos();

    // `parseExt` validates every group eagerly (`SectionIter.next` "cannot
    // fail"), so walking every iterator to exhaustion and decoding every
    // record is exactly the deferred-looking-but-actually-immediate surface
    // worth exercising here.
    var fit = ext.funcInfos();
    var fi_groups: u32 = 0;
    while (fit.next()) |s| : (fi_groups += 1) {
        if (fi_groups > 64) break;
        var i: u32 = 0;
        while (i < s.count and i < 64) : (i += 1) _ = s.funcInfo(i);
    }
    var lit = ext.lineInfos();
    var li_groups: u32 = 0;
    while (lit.next()) |s| : (li_groups += 1) {
        if (li_groups > 64) break;
        var i: u32 = 0;
        while (i < s.count and i < 64) : (i += 1) _ = s.lineInfo(i);
    }
    var cit = ext.coreRelos();
    var cr_groups: u32 = 0;
    while (cit.next()) |s| : (cr_groups += 1) {
        if (cr_groups > 64) break;
        var i: u32 = 0;
        while (i < s.count and i < 64) : (i += 1) _ = s.coreRelo(i);
    }
}

test "synthetic .BTF.ext: sections, groups and forward-compatible records" {
    const gpa = testing.allocator;

    const func = try SynthExt.section(gpa, 8, 1, &.{ 0, 7, 16, 9 }); // 2 FuncInfo
    defer gpa.free(func);
    const line = try SynthExt.section(gpa, 16, 1, &.{ 0, 2, 3, (5 << 10) | 4 }); // 1 LineInfo
    defer gpa.free(line);
    const core = try SynthExt.section(gpa, 16, 1, &.{ 8, 4, 11, 0, 24, 4, 15, 5 }); // 2 CoreRelo
    defer gpa.free(core);

    const blob = try SynthExt.build(gpa, func, line, core, header_size_full);
    defer gpa.free(blob);

    const ext = try parseExt(blob);
    try testing.expectEqual(@as(u32, header_size_full), ext.hdr.hdr_len);
    try testing.expect(ext.hdr.hasCoreRelos());

    {
        var it = ext.funcInfos();
        const s = it.next().?;
        try testing.expectEqual(@as(u32, 1), s.sec_name_off);
        try testing.expectEqual(@as(u32, 2), s.count);
        try testing.expectEqual(@as(u32, 0), s.funcInfo(0).insn_off);
        try testing.expectEqual(@as(u32, 7), s.funcInfo(0).type_id);
        try testing.expectEqual(@as(u32, 16), s.funcInfo(1).insn_off);
        try testing.expectEqual(@as(?SectionInfo, null), it.next());
    }
    {
        var it = ext.lineInfos();
        const s = it.next().?;
        const li = s.lineInfo(0);
        try testing.expectEqual(@as(u32, 2), li.file_name_off);
        try testing.expectEqual(@as(u22, 5), li.line());
        try testing.expectEqual(@as(u10, 4), li.column());
    }
    {
        var it = ext.coreRelos();
        const s = it.next().?;
        try testing.expectEqual(@as(u32, 2), s.count);
        const r0 = s.coreRelo(0);
        try testing.expectEqual(@as(u32, 8), r0.insn_off);
        try testing.expectEqual(@as(u32, 4), r0.type_id);
        try testing.expectEqual(@as(u32, 11), r0.access_str_off);
        try testing.expectEqual(ReloKind.field_byte_offset, r0.reloKind());
        try testing.expectEqual(ReloKind.field_rshift_u64, s.coreRelo(1).reloKind());
    }

    // A producer that appended fields: rec_size 24 for a 16-byte CoreRelo.
    {
        const wide = try SynthExt.section(gpa, 24, 1, &.{ 8, 4, 11, 0, 0xdead, 0xbeef });
        defer gpa.free(wide);
        const b2 = try SynthExt.build(gpa, &.{}, &.{}, wide, header_size_full);
        defer gpa.free(b2);
        const e2 = try parseExt(b2);
        var it = e2.coreRelos();
        const s = it.next().?;
        try testing.expectEqual(@as(u32, 24), s.rec_size);
        try testing.expectEqual(@as(u32, 1), s.count);
        // The known prefix still decodes; the tail is simply ignored.
        try testing.expectEqual(@as(u32, 4), s.coreRelo(0).type_id);
    }

    // The pre-5.16 short header: no core_relo pair at all.
    {
        const b3 = try SynthExt.build(gpa, func, line, &.{}, header_size_min);
        defer gpa.free(b3);
        const e3 = try parseExt(b3);
        try testing.expect(!e3.hdr.hasCoreRelos());
        try testing.expectEqual(@as(u32, 0), e3.hdr.core_relo_len);
        var it = e3.coreRelos();
        try testing.expectEqual(@as(?SectionInfo, null), it.next());
        // …but func_info still works.
        var fit = e3.funcInfos();
        try testing.expectEqual(@as(u32, 2), fit.next().?.count);
    }
}

test "hostile .BTF.ext: every malformation is a typed error" {
    const gpa = testing.allocator;

    try testing.expectError(error.NotBtfExt, parseExt(&.{ 1, 2 }));
    {
        var b = [_]u8{0} ** 64;
        std.mem.writeInt(u16, b[0..2], 0x1234, native_endian);
        try testing.expectError(error.NotBtfExt, parseExt(&b));
        std.mem.writeInt(u16, b[0..2], @byteSwap(magic), native_endian);
        try testing.expectError(error.UnsupportedExt, parseExt(&b));
        std.mem.writeInt(u16, b[0..2], magic, native_endian);
        b[2] = 7;
        try testing.expectError(error.UnsupportedExt, parseExt(&b));
        b[2] = version;
        std.mem.writeInt(u32, b[4..8], 12, native_endian); // hdr_len too small
        try testing.expectError(error.MalformedExt, parseExt(&b));
        std.mem.writeInt(u32, b[4..8], 0xffff_ffff, native_endian); // past the blob
        try testing.expectError(error.MalformedExt, parseExt(&b));
    }

    const func = try SynthExt.section(gpa, 8, 1, &.{ 0, 7 });
    defer gpa.free(func);

    // A section length that runs past the blob (and one that would wrap in
    // 32-bit arithmetic).
    {
        const blob = try SynthExt.build(gpa, func, &.{}, &.{}, header_size_full);
        defer gpa.free(blob);
        {
            const c = try gpa.dupe(u8, blob);
            defer gpa.free(c);
            std.mem.writeInt(u32, c[12..16], 0xffff_ffff, native_endian);
            try testing.expectError(error.MalformedExt, parseExt(c));
        }
        {
            const c = try gpa.dupe(u8, blob);
            defer gpa.free(c);
            std.mem.writeInt(u32, c[8..12], 0xffff_fff0, native_endian);
            std.mem.writeInt(u32, c[12..16], 0x20, native_endian);
            try testing.expectError(error.MalformedExt, parseExt(c));
        }
        // A section too short to even hold its rec_size word.
        {
            const c = try gpa.dupe(u8, blob);
            defer gpa.free(c);
            std.mem.writeInt(u32, c[12..16], 2, native_endian);
            try testing.expectError(error.MalformedExt, parseExt(c));
        }
    }
    // rec_size smaller than the record it claims to hold, not 4-aligned, or
    // absurd.
    for ([_]u32{ 4, 9, 1000, 0 }) |bad_rec| {
        const s = try gpa.alloc(u8, 4 + 8);
        defer gpa.free(s);
        @memset(s, 0);
        std.mem.writeInt(u32, s[0..4], bad_rec, native_endian);
        const blob = try SynthExt.build(gpa, s, &.{}, &.{}, header_size_full);
        defer gpa.free(blob);
        try testing.expectError(error.MalformedExt, parseExt(blob));
    }
    // A num_info the section cannot possibly hold.
    {
        const s = try gpa.alloc(u8, 4 + 8 + 8);
        defer gpa.free(s);
        @memset(s, 0);
        std.mem.writeInt(u32, s[0..4], 8, native_endian);
        std.mem.writeInt(u32, s[4..8], 1, native_endian);
        std.mem.writeInt(u32, s[8..12], 0xffff, native_endian); // num_info
        const blob = try SynthExt.build(gpa, s, &.{}, &.{}, header_size_full);
        defer gpa.free(blob);
        try testing.expectError(error.MalformedExt, parseExt(blob));
    }
    // A truncated group header (4 bytes where 8 are needed).
    {
        const s = try gpa.alloc(u8, 4 + 4);
        defer gpa.free(s);
        @memset(s, 0);
        std.mem.writeInt(u32, s[0..4], 8, native_endian);
        const blob = try SynthExt.build(gpa, s, &.{}, &.{}, header_size_full);
        defer gpa.free(blob);
        try testing.expectError(error.MalformedExt, parseExt(blob));
    }
}

// ── the real clang fixture ──────────────────────────────────────────────────
//
// `.BTF` and `.BTF.ext` lifted verbatim from an object produced by:
//
//   $ cat > /tmp/zlbtf/core.c <<'EOF'
//   struct task_struct { int pid; int tgid; char comm[16]; }
//       __attribute__((preserve_access_index));
//   struct sk_buff {
//       unsigned int len;
//       unsigned char cloned:1; unsigned char nohdr:1; unsigned char fclone:2;
//   } __attribute__((preserve_access_index));
//   __attribute__((section("kprobe/x"), used))
//   long zig_libs_core(struct task_struct *t, struct sk_buff *s)
//   { return t->pid + t->comm[0] + s->len + s->fclone; }
//   EOF
//   $ clang -target bpf -O2 -g -c core.c -o core.o     # clang 21.1.8
//
// The four `core_relo` records it contains are, verbatim:
//
//   insn 0  type 2 (task_struct) access "0:0"    FIELD_BYTE_OFFSET
//   insn 8  type 2 (task_struct) access "0:2:0"  FIELD_BYTE_OFFSET
//   insn 40 type 8 (sk_buff)     access "0:0"    FIELD_BYTE_OFFSET
//   insn 56 type 8 (sk_buff)     access "0:3"    FIELD_BYTE_OFFSET  <- bitfield

const core_btf_bytes = [_]u8{
    0x9f, 0xeb, 0x01, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x01, 0x00, 0x00,
    0x24, 0x01, 0x00, 0x00, 0xe5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x04, 0x18, 0x00, 0x00, 0x00,
    0x0d, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x01, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x08, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x84,
    0x08, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x44, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x01, 0x4b, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
    0x22, 0x00, 0x00, 0x02, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0d, 0x0c, 0x00, 0x00, 0x00,
    0x73, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x75, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x01,
    0x7c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x0c, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x74, 0x61, 0x73,
    0x6b, 0x5f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x00, 0x70, 0x69, 0x64, 0x00, 0x74, 0x67, 0x69,
    0x64, 0x00, 0x63, 0x6f, 0x6d, 0x6d, 0x00, 0x69, 0x6e, 0x74, 0x00, 0x63, 0x68, 0x61, 0x72, 0x00,
    0x5f, 0x5f, 0x41, 0x52, 0x52, 0x41, 0x59, 0x5f, 0x53, 0x49, 0x5a, 0x45, 0x5f, 0x54, 0x59, 0x50,
    0x45, 0x5f, 0x5f, 0x00, 0x73, 0x6b, 0x5f, 0x62, 0x75, 0x66, 0x66, 0x00, 0x6c, 0x65, 0x6e, 0x00,
    0x63, 0x6c, 0x6f, 0x6e, 0x65, 0x64, 0x00, 0x6e, 0x6f, 0x68, 0x64, 0x72, 0x00, 0x66, 0x63, 0x6c,
    0x6f, 0x6e, 0x65, 0x00, 0x75, 0x6e, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x20, 0x69, 0x6e, 0x74,
    0x00, 0x75, 0x6e, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x20, 0x63, 0x68, 0x61, 0x72, 0x00, 0x74,
    0x00, 0x73, 0x00, 0x6c, 0x6f, 0x6e, 0x67, 0x00, 0x7a, 0x69, 0x67, 0x5f, 0x6c, 0x69, 0x62, 0x73,
    0x5f, 0x63, 0x6f, 0x72, 0x65, 0x00, 0x6b, 0x70, 0x72, 0x6f, 0x62, 0x65, 0x2f, 0x78, 0x00, 0x30,
    0x3a, 0x30, 0x00, 0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x7a, 0x6c, 0x62, 0x74, 0x66, 0x2f, 0x63, 0x6f,
    0x72, 0x65, 0x2e, 0x63, 0x00, 0x09, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x20, 0x74, 0x2d, 0x3e,
    0x70, 0x69, 0x64, 0x20, 0x2b, 0x20, 0x74, 0x2d, 0x3e, 0x63, 0x6f, 0x6d, 0x6d, 0x5b, 0x30, 0x5d,
    0x20, 0x2b, 0x20, 0x73, 0x2d, 0x3e, 0x6c, 0x65, 0x6e, 0x20, 0x2b, 0x20, 0x73, 0x2d, 0x3e, 0x66,
    0x63, 0x6c, 0x6f, 0x6e, 0x65, 0x3b, 0x00, 0x30, 0x3a, 0x32, 0x3a, 0x30, 0x00, 0x30, 0x3a, 0x33,
    0x00,
};

const core_btf_ext_bytes = [_]u8{
    0x9f, 0xeb, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
    0x14, 0x00, 0x00, 0x00, 0x8c, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x8a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0d, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x8a, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x97, 0x00, 0x00, 0x00, 0xa9, 0x00, 0x00, 0x00, 0x0c, 0x50, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x97, 0x00, 0x00, 0x00, 0xa9, 0x00, 0x00, 0x00, 0x12, 0x50, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00, 0x97, 0x00, 0x00, 0x00, 0xa9, 0x00, 0x00, 0x00, 0x10, 0x50, 0x00, 0x00,
    0x28, 0x00, 0x00, 0x00, 0x97, 0x00, 0x00, 0x00, 0xa9, 0x00, 0x00, 0x00, 0x22, 0x50, 0x00, 0x00,
    0x30, 0x00, 0x00, 0x00, 0x97, 0x00, 0x00, 0x00, 0xa9, 0x00, 0x00, 0x00, 0x1d, 0x50, 0x00, 0x00,
    0x38, 0x00, 0x00, 0x00, 0x97, 0x00, 0x00, 0x00, 0xa9, 0x00, 0x00, 0x00, 0x2b, 0x50, 0x00, 0x00,
    0x50, 0x00, 0x00, 0x00, 0x97, 0x00, 0x00, 0x00, 0xa9, 0x00, 0x00, 0x00, 0x26, 0x50, 0x00, 0x00,
    0x58, 0x00, 0x00, 0x00, 0x97, 0x00, 0x00, 0x00, 0xa9, 0x00, 0x00, 0x00, 0x02, 0x50, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x8a, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x93, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0xdb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x93, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0xe1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

test "real clang object: .BTF + .BTF.ext parse and agree with the compiler" {
    const gpa = testing.allocator;

    var local = try btf.parse(gpa, &core_btf_bytes, .{});
    defer local.deinit();
    try local.validateReferences(null);
    try testing.expectEqual(@as(u32, 13), local.typeCount());

    // The local types, exactly as bpftool reports them for this object.
    const task = local.findByNameKind("task_struct", .@"struct").?;
    const skb = local.findByNameKind("sk_buff", .@"struct").?;
    try testing.expectEqual(@as(u32, 2), task);
    try testing.expectEqual(@as(u32, 8), skb);
    try testing.expectEqual(@as(u64, 24), try local.sizeOf(task));
    try testing.expectEqual(@as(u64, 8), try local.sizeOf(skb));
    try testing.expectEqual(@as(?u32, 13), local.findByNameKind("zig_libs_core", .func));

    const ext = try parseExt(&core_btf_ext_bytes);
    try testing.expectEqual(@as(u32, header_size_full), ext.hdr.hdr_len);
    try testing.expect(ext.hdr.hasCoreRelos());

    // func_info: one record naming the FUNC for `kprobe/x`.
    {
        var it = ext.funcInfos();
        const s = it.next().?;
        try testing.expectEqualStrings("kprobe/x", local.str(s.sec_name_off).?);
        try testing.expectEqual(@as(u32, 1), s.count);
        const fi = s.funcInfo(0);
        try testing.expectEqual(@as(u32, 0), fi.insn_off);
        try testing.expectEqual(@as(u32, 13), fi.type_id);
        try testing.expectEqualStrings("zig_libs_core", local.typeName(fi.type_id).?);
        try testing.expectEqual(btf.Kind.func, (try local.byId(fi.type_id)).kind);
    }
    // line_info: the file name is a path with no user identity in it.
    {
        var it = ext.lineInfos();
        const s = it.next().?;
        try testing.expectEqual(@as(u32, 8), s.count);
        const li = s.lineInfo(0);
        try testing.expectEqualStrings("/tmp/zlbtf/core.c", local.str(li.file_name_off).?);
        try testing.expect(std.mem.indexOf(u8, local.str(li.line_off).?, "t->pid") != null);
        try testing.expectEqual(@as(u22, 20), li.line()); // the `return` line of the fixture source
    }
    // core_relo: four FIELD_BYTE_OFFSET records, exactly as clang emitted.
    {
        var it = ext.coreRelos();
        const s = it.next().?;
        try testing.expectEqual(@as(u32, 4), s.count);
        const want = [_]struct { insn: u32, type_id: u32, access: []const u8 }{
            .{ .insn = 0, .type_id = 2, .access = "0:0" },
            .{ .insn = 8, .type_id = 2, .access = "0:2:0" },
            .{ .insn = 40, .type_id = 8, .access = "0:0" },
            .{ .insn = 56, .type_id = 8, .access = "0:3" },
        };
        for (want, 0..) |w, i| {
            const r = s.coreRelo(@intCast(i));
            try testing.expectEqual(w.insn, r.insn_off);
            try testing.expectEqual(w.type_id, r.type_id);
            try testing.expectEqualStrings(w.access, local.str(r.access_str_off).?);
            try testing.expectEqual(ReloKind.field_byte_offset, r.reloKind());
        }
    }
}

test "CO-RE: a spec relocated against ITSELF reproduces the compiler's layout" {
    const gpa = testing.allocator;
    var local = try btf.parse(gpa, &core_btf_bytes, .{});
    defer local.deinit();

    const ext = try parseExt(&core_btf_ext_bytes);
    var it = ext.coreRelos();
    const s = it.next().?;

    // Relocating local-against-local must be the identity: these are the
    // offsets clang compiled in, so they are exact constants here.
    const expect = [_]struct { off: u64, size: u64, lsh: u8, rsh: u8, signed: bool }{
        // task_struct.pid: int at byte 0.
        .{ .off = 0, .size = 4, .lsh = 32, .rsh = 32, .signed = true },
        // task_struct.comm[0]: char at byte 8.
        .{ .off = 8, .size = 1, .lsh = 56, .rsh = 56, .signed = true },
        // sk_buff.len: unsigned int at byte 0.
        .{ .off = 0, .size = 4, .lsh = 32, .rsh = 32, .signed = false },
        // sk_buff.fclone: a 2-bit bitfield at bit 34 of an `unsigned char`.
        // The load is 1 byte at offset 4; the bits sit at 34-32 = 2..4, so
        // lshift = 64 - (34 + 2 - 32) = 60 and rshift = 64 - 2 = 62.
        .{ .off = 4, .size = 1, .lsh = 60, .rsh = 62, .signed = false },
    };
    for (expect, 0..) |e, i| {
        const r = s.coreRelo(@intCast(i));
        const res = try computeFieldRelo(&local, &local, r);
        try testing.expect(res.exists);
        try testing.expectEqual(e.off, res.value); // the relo kind IS byte_offset
        const f = res.field.?;
        try testing.expectEqual(e.off, f.byte_offset);
        try testing.expectEqual(e.size, f.byte_size);
        try testing.expectEqual(e.lsh, f.lshift_u64);
        try testing.expectEqual(e.rsh, f.rshift_u64);
        try testing.expectEqual(e.signed, f.signed);

        // Every FIELD_* kind derives from the same geometry.
        try testing.expectEqual(e.size, try f.value(.field_byte_size));
        try testing.expectEqual(@as(u64, 1), try f.value(.field_exists));
        try testing.expectEqual(@as(u64, @intFromBool(e.signed)), try f.value(.field_signed));
        try testing.expectEqual(@as(u64, e.lsh), try f.value(.field_lshift_u64));
        try testing.expectEqual(@as(u64, e.rsh), try f.value(.field_rshift_u64));
        // …and the kinds this module refuses stay refused.
        try testing.expectError(error.UnsupportedReloKind, f.value(.type_size));
        try testing.expectError(error.UnsupportedReloKind, f.value(.enumval_value));
    }

    // A relo kind outside FIELD_* is refused before any work happens.
    {
        const bad: CoreRelo = .{ .insn_off = 0, .type_id = 2, .access_str_off = s.coreRelo(0).access_str_off, .kind = @intFromEnum(ReloKind.type_size) };
        try testing.expectError(error.UnsupportedReloKind, computeFieldRelo(&local, &local, bad));
    }
    // An access string that names a member index the local type does not
    // have. (Access strings are interned in the BTF, so build one by pointing
    // at a string that parses but over-indexes: "0:9".)
    {
        const spec = parseFieldSpec(&local, 2, "0:9");
        try testing.expectError(error.BadLocalSpec, spec);
        try testing.expectError(error.BadAccessSpec, parseFieldSpec(&local, 2, ""));
    }
}

test "CO-RE: the local spec walk records names, not just offsets" {
    const gpa = testing.allocator;
    var local = try btf.parse(gpa, &core_btf_bytes, .{});
    defer local.deinit();

    // "0:2:0" = task_struct[0].comm[0]
    const spec = try parseFieldSpec(&local, 2, "0:2:0");
    try testing.expectEqual(@as(usize, 3), spec.len);
    try testing.expectEqual(@as(?[]const u8, null), spec.steps[0].name); // root array index
    try testing.expectEqualStrings("comm", spec.steps[1].name.?);
    try testing.expectEqual(@as(?[]const u8, null), spec.steps[2].name); // array index
    try testing.expectEqual(@as(u64, 64), spec.bit_offset);
    try testing.expectEqual(@as(u8, 0), spec.bitfield_size);

    // A non-zero ROOT index steps over whole structs: task_struct[2].pid.
    const spec2 = try parseFieldSpec(&local, 2, "2:0");
    try testing.expectEqual(@as(u64, 2 * 24 * 8), spec2.bit_offset);

    // The bitfield leaf carries its width through the spec.
    const spec3 = try parseFieldSpec(&local, 8, "0:3");
    try testing.expectEqualStrings("fclone", spec3.steps[1].name.?);
    try testing.expectEqual(@as(u8, 2), spec3.bitfield_size);
    try testing.expectEqual(@as(u64, 34), spec3.bit_offset);
}

// ── the real thing: relocate the fixture against the running kernel ─────────

fn kernelAvailable() bool {
    const linux = std.os.linux;
    const rc = linux.open(btf.sysfs_vmlinux, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    _ = linux.close(@intCast(rc));
    return true;
}

test "CO-RE: relocate a real clang object against /sys/kernel/btf/vmlinux" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!kernelAvailable()) {
        if (verboseSkip()) std.debug.print("\nSKIPPED: ebpf CO-RE kernel test — no /sys/kernel/btf/vmlinux.\n", .{});
        return error.SkipZigTest;
    }
    const gpa = testing.allocator;

    var local = try btf.parse(gpa, &core_btf_bytes, .{});
    defer local.deinit();
    var kernel = try btf.loadKernel(gpa);
    defer kernel.deinit();

    const ext = try parseExt(&core_btf_ext_bytes);
    var it = ext.coreRelos();
    const s = it.next().?;

    // relo[0]: task_struct.pid. In the FIXTURE it is at byte 0; in any real
    // kernel `struct task_struct` it is thousands of bytes in — so a
    // relocation that silently did nothing would show up as `value == 0`.
    // (Hand-checked on the machine this was written on with
    //  `bpftool btf dump file /sys/kernel/btf/vmlinux format raw`, which
    //  reported `'pid' type_id=141016 bits_offset=22400` -> byte 2800. That
    //  NUMBER is not asserted; it changes with every kernel build.)
    const task_k = kernel.findByNameKind("task_struct", .@"struct") orelse {
        if (verboseSkip()) std.debug.print("\nSKIPPED: ebpf CO-RE — this kernel's BTF has no task_struct.\n", .{});
        return error.SkipZigTest;
    };
    const task_size = try kernel.sizeOf(task_k);
    {
        const res = try computeFieldRelo(&local, &kernel, s.coreRelo(0));
        try testing.expect(res.exists);
        const f = res.field.?;
        try testing.expect(res.value > 0); // it MOVED
        try testing.expect(res.value < task_size);
        try testing.expectEqual(@as(u64, 4), f.byte_size); // still an int
        try testing.expect(f.signed);
        try testing.expectEqual(@as(u8, 0), f.bitfield_size);
        try testing.expectEqual(@as(u64, 0), res.value % 4); // naturally aligned
        // The independent cross-check: the same answer through the
        // name-based helper, which does not go near `.BTF.ext` at all.
        const byname = (try fieldByName(&kernel, "task_struct", &.{"pid"})).?;
        try testing.expectEqual(byname.byte_offset, f.byte_offset);
        try testing.expectEqual(byname.byte_size, f.byte_size);
    }

    // relo[1]: task_struct.comm[0] — a member reached by name, then an ARRAY
    // step by index. `comm` is `char[16]` (TASK_COMM_LEN) on every kernel.
    {
        const res = try computeFieldRelo(&local, &kernel, s.coreRelo(1));
        try testing.expect(res.exists);
        const f = res.field.?;
        try testing.expectEqual(@as(u64, 1), f.byte_size);
        try testing.expect(res.value < task_size);
        const comm = (try kernel.findMember(task_k, "comm")).?;
        try testing.expectEqual(comm.byteOffset(), res.value);
    }

    // relo[2] and [3]: sk_buff.len and the sk_buff.fclone BITFIELD. Both are
    // in the kernel's `struct sk_buff` behind anonymous unions, which is the
    // anonymous-descent path doing real work.
    if (kernel.findByNameKind("sk_buff", .@"struct")) |skb_k| {
        const skb_size = try kernel.sizeOf(skb_k);
        {
            const res = try computeFieldRelo(&local, &kernel, s.coreRelo(2));
            try testing.expect(res.exists);
            try testing.expect(res.value > 0); // NOT at byte 0 like the fixture
            try testing.expect(res.value < skb_size);
            try testing.expectEqual(@as(u64, 4), res.field.?.byte_size);
        }
        {
            const res = try computeFieldRelo(&local, &kernel, s.coreRelo(3));
            try testing.expect(res.exists);
            const f = res.field.?;
            // Structural facts that hold on any kernel where fclone is still
            // a bitfield: it is one, the load covers its bits, and the
            // shifts are self-consistent.
            try testing.expect(f.bitfield_size > 0);
            try testing.expectEqual(@as(u8, @intCast(64 - f.bit_size)), f.rshift_u64);
            try testing.expect(f.byte_offset * 8 <= f.bit_offset);
            try testing.expect(f.bit_offset + f.bit_size <= (f.byte_offset + f.byte_size) * 8);
            try testing.expect(f.byte_size <= 8);
            try testing.expect(res.value < skb_size);
            // `(x << lshift) >> rshift` must select exactly `bit_size` bits:
            // on little-endian that is lshift == 64 - (bits above the load
            // base), which is the identity the two shifts are derived from.
            const above = f.bit_offset + f.bit_size - f.byte_offset * 8;
            try testing.expectEqual(@as(u64, 64) - above, @as(u64, f.lshift_u64));
            try testing.expectEqual(@as(u64, 64), @as(u64, f.rshift_u64) + f.bit_size);
        }
    }

    // A struct that DOES exist in the kernel but whose member does not:
    // the match fails cleanly (which is what FIELD_EXISTS reports as 0)
    // instead of producing a wrong offset.
    {
        var b = btf.Builder.init(gpa);
        defer b.deinit();
        const i32_id = try b.addInt("int", 4, 32, 0b001);
        _ = try b.addComposite(.@"struct", "task_struct", 8, &.{
            .{ .name = "zig_libs_definitely_absent", .type_id = i32_id, .bit_offset = 0 },
        });
        const blob = try b.finish();
        defer gpa.free(blob);
        var fake = try btf.parse(gpa, blob, .{});
        defer fake.deinit();
        const lspec = try parseFieldSpec(&fake, 2, "0:0");
        try testing.expectEqual(@as(?FieldSpec, null), try matchFieldSpec(&fake, lspec, &kernel));
    }

    // An array index times an element size that overflows the accumulated bit
    // offset is REFUSED, not wrapped. Both factors are attacker-chosen: the
    // index comes from the CO-RE access string (`parseAccessIndices` bounds how
    // MANY components there are, not how large each is) and the size is the
    // struct's raw wire `size` word.
    //
    // Measured before the fix on exactly this input: `integer overflow` panic
    // in Debug and ReleaseSafe, and in ReleaseFast a silently wrapped
    // `bit_offset` that flows on into `fieldGeometry` and `patchCoreInsn` --
    // a wrong offset written into a loaded BPF program, which is worse than
    // the crash. Four sites shared the defect; they now share one checked
    // helper, so this test pins the rule rather than one of its cases.
    {
        var b = btf.Builder.init(gpa);
        defer b.deinit();
        const i32_id = try b.addInt("int", 4, 32, 0b001);
        _ = try b.addComposite(.@"struct", "big", 0xFFFF_FFFF, &.{
            .{ .name = "x", .type_id = i32_id, .bit_offset = 0 },
        });
        const blob = try b.finish();
        defer gpa.free(blob);
        var fake = try btf.parse(gpa, blob, .{});
        defer fake.deinit();
        // 4294967295 * 0xFFFFFFFF * 8 is ~1.5e20, far past u64.
        try testing.expectError(error.FieldOffsetOverflow, parseFieldSpec(&fake, 2, "4294967295"));
    }

    // A root type name that does not exist anywhere.
    {
        var b = btf.Builder.init(gpa);
        defer b.deinit();
        const i32_id = try b.addInt("int", 4, 32, 0b001);
        _ = try b.addComposite(.@"struct", "zig_libs_no_such_struct", 4, &.{
            .{ .name = "x", .type_id = i32_id, .bit_offset = 0 },
        });
        const blob = try b.finish();
        defer gpa.free(blob);
        var fake = try btf.parse(gpa, blob, .{});
        defer fake.deinit();
        const lspec = try parseFieldSpec(&fake, 2, "0:0");
        try testing.expectEqual(@as(?FieldSpec, null), try matchFieldSpec(&fake, lspec, &kernel));
    }
}

test "fieldByName resolves against the running kernel" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!kernelAvailable()) {
        if (verboseSkip()) std.debug.print("\nSKIPPED: ebpf fieldByName kernel test — no kernel BTF.\n", .{});
        return error.SkipZigTest;
    }
    const gpa = testing.allocator;
    var k = try btf.loadKernel(gpa);
    defer k.deinit();

    // Structural, not numeric — see the header of this test section.
    if (try fieldByName(&k, "task_struct", &.{"pid"})) |f| {
        try testing.expectEqual(@as(u64, 4), f.byte_size);
        try testing.expect(f.signed);
        try testing.expectEqual(@as(u8, 32), f.rshift_u64);
        try testing.expect(f.byte_offset < try k.sizeOf(k.findByNameKind("task_struct", .@"struct").?));
    }
    // A nested path: task_struct.mm is a pointer, so a path THROUGH it must
    // not silently pretend to follow it.
    try testing.expectEqual(@as(?FieldInfo, null), try fieldByName(&k, "task_struct", &.{ "mm", "pgd" }));
    // A flavored name resolves to the plain one.
    try testing.expect((try fieldByName(&k, "task_struct___v99", &.{"pid"})) != null);
    // Nonsense stays nonsense.
    try testing.expectEqual(@as(?FieldInfo, null), try fieldByName(&k, "zig_libs_nope", &.{"x"}));
    try testing.expectEqual(@as(?FieldInfo, null), try fieldByName(&k, "task_struct", &.{"zig_libs_nope"}));
}
