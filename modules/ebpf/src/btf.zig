// SPDX-License-Identifier: MIT
//! BTF (BPF Type Format) — the type graph the kernel exports at
//! `/sys/kernel/btf/vmlinux`, and the thing that turns a *function name* into
//! the `attach_btf_id` `fentry`/`fexit`/`tp_btf`/LSM programs are matched by.
//!
//! ## Why this file exists
//!
//! `std.os.linux.BPF.btf` already declares the **wire structs**
//! (`Header`, `Type`, `Kind`, `Member`, `Array`, `Enum`, `Enum64`, `Param`,
//! `Var`, `VarSecInfo`, `DeclTag`) — this module reuses `Kind` directly and
//! asserts the rest against std's layout in its tests rather than restating
//! them. What std does *not* have is a **parser**: nothing walks the type
//! section, nothing indexes type ids, nothing resolves a name, and nothing
//! bounds-checks a blob that a hostile (or merely truncated) producer wrote.
//! That gap is what this file fills.
//!
//! ## Bounds safety is the entire risk surface
//!
//! A BTF blob is untrusted input: `/sys/kernel/btf/*` is trustworthy, but a
//! `.BTF` section lifted out of somebody's object file is not, and neither is
//! a blob read off the network. Every one of these has to be a **typed
//! error**, never a crash and never a wrong answer:
//!
//! - a header whose `type_off`/`type_len`/`str_off`/`str_len` run past the
//!   blob (checked in `u64` so the addition cannot wrap),
//! - a `vlen` claiming more members/params/values than the remaining type
//!   section can hold (`parse` walks the whole section once and sizes every
//!   record, so a later accessor cannot read out of bounds),
//! - a type id past the end of the type section (`byId` -> `TypeIdOutOfRange`),
//! - a `name_off` past the end of the string section, or one that is not
//!   NUL-terminated inside it (`str` -> `null`),
//! - a **cycle** — `typedef A -> const A`, an array whose element type is
//!   itself — which every resolving walk here bounds with
//!   `max_resolve_depth` instead of recursing until the stack dies.
//!
//! ## Fields decoded by hand, not by `@ptrCast`
//!
//! Same discipline as `elfsym.zig`, for the same reason plus one more:
//! std's `btf.Type.info.kind` is an `enum(u5)` with 20 values and
//! `btf.IntInfo.encoding` is an `enum(u4)` with **three** — but a perfectly
//! ordinary `unsigned int` in real kernel BTF has `encoding == 0`, which is
//! not one of them. `@ptrCast`ing a blob onto those structs would therefore
//! produce an invalid enum value on the *first* INT it met in
//! `/sys/kernel/btf/vmlinux`. Everything here is read with `std.mem.readInt`
//! at asserted offsets and validated before it becomes an enum.
//!
//! ## Split BTF is handled, not guessed at
//!
//! `/sys/kernel/btf/<module>` is **split** BTF: its type ids continue from
//! the base (vmlinux) blob's last id, and its string section is a *second*
//! section addressed by `name_off - base.str_len`. Parsing one without its
//! base would silently resolve every id and every name to the wrong thing, so
//! `parse` detects it (a base blob's string section starts with `"\0"`; a
//! split one's does not) and refuses with `error.SplitBtfNeedsBase` unless a
//! `base` was supplied.
//!
//! ```zig
//! var vmlinux = try btf.loadKernel(gpa);
//! defer vmlinux.deinit();
//! const id = vmlinux.findByNameKind("vfs_read", .func).?;  // attach_btf_id
//! const f = try vmlinux.findMember(
//!     vmlinux.findByNameKind("task_struct", .@"struct").?, "pid");
//! ```
//!
//! Provenance: clean-room from the kernel UAPI (`include/uapi/linux/btf.h`)
//! and `Documentation/bpf/btf.rst`; cross-checked against
//! `bpftool btf dump file /sys/kernel/btf/vmlinux format raw`.

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
const BPF = linux.BPF;
const std_btf = BPF.btf;

const native_endian = builtin.cpu.arch.endian();

// ── wire constants (include/uapi/linux/btf.h) ───────────────────────────────

/// `BTF_MAGIC`.
pub const magic: u16 = 0xeb9f;
/// `BTF_VERSION`.
pub const version: u8 = 1;

/// `sizeof(struct btf_header)`.
pub const header_size: usize = 24;
/// `sizeof(struct btf_type)` — the fixed part every type record starts with.
pub const type_header_size: usize = 12;

/// `BTF_MAX_TYPE`.
pub const max_type: u32 = 0x000f_ffff;
/// `BTF_MAX_NAME_OFFSET`.
pub const max_name_offset: u32 = 0x00ff_ffff;
/// `BTF_MAX_VLEN`.
pub const max_vlen: u32 = 0xffff;

/// How many modifier/alias hops any resolving walk will take before calling
/// it a cycle. libbpf uses the same ceiling (`MAX_RESOLVE_DEPTH`), and no
/// legitimate C type comes anywhere near it.
pub const max_resolve_depth: u32 = 32;

/// Ceiling on a blob this module will read off disk. `/sys/kernel/btf/vmlinux`
/// is ~7 MiB on a distro kernel; 256 MiB is "something is wrong", not a
/// legitimate BTF.
pub const max_blob_bytes: usize = 256 << 20;

/// eBPF is a 64-bit ISA regardless of the host, so a `BTF_KIND_PTR` is always
/// 8 bytes wide — `sizeOf` does not consult the host's `usize`.
pub const pointer_size: u64 = 8;

/// `BTF_KIND_*`, taken from std rather than re-declared.
pub const Kind = std_btf.Kind;

/// The largest `BTF_KIND_*` this parser knows. A blob using a higher kind is
/// `error.MalformedBtf` rather than a silently-mis-sized record: the record's
/// trailing data length depends on the kind, so guessing would desynchronize
/// the whole type section.
pub const max_kind: u5 = @intFromEnum(Kind.enum64);

/// `enum btf_func_linkage` — carried in a `BTF_KIND_FUNC`'s `vlen`, which is
/// why `FUNC` records have no trailing data despite a non-zero `vlen`.
pub const FuncLinkage = enum(u16) { static = 0, global = 1, external = 2, _ };

/// `BTF_VAR_*` — a `BTF_KIND_VAR`'s `linkage` word.
pub const VarLinkage = enum(u32) { static = 0, global_allocated = 1, global_extern = 2, _ };

/// Well-known sysfs locations. Module BTF lives beside vmlinux under the
/// module's name and is **split** BTF (see this file's header).
pub const sysfs_btf_dir = "/sys/kernel/btf";
pub const sysfs_vmlinux = sysfs_btf_dir ++ "/vmlinux";

// ── errors ──────────────────────────────────────────────────────────────────

pub const ParseError = error{
    /// The blob does not start with `BTF_MAGIC`.
    NotBtf,
    /// Well-formed BTF this parser deliberately declines: a byte-swapped
    /// blob (BTF is written in the producer's byte order), or `version != 1`.
    UnsupportedBtf,
    /// Structurally inconsistent: a section running past the blob, a `vlen`
    /// the type section cannot hold, an unknown `BTF_KIND_*`, a string
    /// section that is not NUL-framed.
    MalformedBtf,
    /// The blob is split BTF (its ids continue from a base blob's) but no
    /// base was supplied. Resolving it alone would silently mis-answer every
    /// id and every name — see this file's header.
    SplitBtfNeedsBase,
    /// More than `max_type` type records.
    TooManyTypes,
    OutOfMemory,
};

pub const FileError = error{
    FileOpenFailed,
    FileReadFailed,
    /// Bigger than `max_blob_bytes`.
    BtfTooLarge,
    /// A module name that cannot name a file under `/sys/kernel/btf`
    /// (empty, over-long, or containing `/` or NUL).
    InvalidModuleName,
};

pub const LoadError = ParseError || FileError;

pub const TypeError = error{
    /// Id 0 (void), or an id outside this blob and its base.
    TypeIdOutOfRange,
    /// A modifier/alias/array chain longer than `max_resolve_depth` — a
    /// cycle, or something close enough to one to be indistinguishable.
    TypeChainTooDeep,
    /// The requested accessor does not apply to this kind.
    WrongKind,
    /// The type has no computable size (`FWD`, `FUNC_PROTO`, a `VAR`,
    /// an array whose element count overflows).
    NoSize,
};

pub const KernelLoadError = error{
    PermissionDenied,
    /// The kernel's own BTF verifier rejected the blob.
    InvalidBtf,
    SystemResources,
    Unexpected,
};

// ── decoded header ──────────────────────────────────────────────────────────

/// `struct btf_header`, decoded. All four section fields are byte offsets
/// **relative to the end of the header** (i.e. to `hdr_len`), which is why
/// nothing here is a file offset.
pub const Header = struct {
    flags: u8,
    hdr_len: u32,
    type_off: u32,
    type_len: u32,
    str_off: u32,
    str_len: u32,
};

// ── decoded type records ────────────────────────────────────────────────────

/// One type record, decoded. `extra` is the kind-specific trailing data,
/// already bounds-checked by `parse` — every accessor below can therefore
/// index it without re-validating the length.
pub const Type = struct {
    /// This record's type id (in the owning blob's id space).
    id: u32,
    name_off: u32,
    kind: Kind,
    /// `BTF_INFO_VLEN` — member/param/value count for the composite kinds,
    /// and the **linkage** for `FUNC` (see `FuncLinkage`).
    vlen: u16,
    /// `BTF_INFO_KFLAG` — for `STRUCT`/`UNION` it means the members' `offset`
    /// words carry a packed bitfield size; for `FWD` it selects union vs
    /// struct; for `ENUM`/`ENUM64` it means the values are signed.
    kind_flag: bool,
    /// The `size`/`type` union word. Use `byteSize()`/`refType()` rather than
    /// reading this directly — which one it is depends on the kind.
    size_type: u32,
    /// The bytes following the 12-byte record header.
    extra: []const u8,

    /// True when `size_type` is a **size in bytes**.
    pub fn hasSize(self: Type) bool {
        return switch (self.kind) {
            .int, .@"enum", .@"struct", .@"union", .datasec, .float, .enum64 => true,
            else => false,
        };
    }

    /// True when `size_type` is a **type id**.
    pub fn hasRef(self: Type) bool {
        return switch (self.kind) {
            .ptr, .typedef, .@"volatile", .@"const", .restrict, .func, .func_proto, .@"var", .decl_tag, .type_tag, .fwd => true,
            else => false,
        };
    }

    /// The declared byte size, or `null` for a kind whose `size_type` is a
    /// type id. (`FWD`'s `size_type` is unused by the kernel; it is reported
    /// through `hasRef` as a reference for uniformity and is normally 0.)
    pub fn byteSize(self: Type) ?u32 {
        return if (self.hasSize()) self.size_type else null;
    }

    /// The referenced type id, or `null` for a size-carrying kind. May be 0,
    /// which means `void` (e.g. `void *`, or a `FUNC_PROTO` returning void).
    pub fn refType(self: Type) ?u32 {
        return if (self.hasRef()) self.size_type else null;
    }

    /// A `FUNC`'s linkage lives in `vlen`, not in trailing data.
    pub fn funcLinkage(self: Type) ?FuncLinkage {
        return if (self.kind == .func) @enumFromInt(self.vlen) else null;
    }

    /// True for the kinds `skipModifiers` walks through.
    pub fn isModifier(self: Type) bool {
        return switch (self.kind) {
            .typedef, .@"volatile", .@"const", .restrict, .type_tag => true,
            else => false,
        };
    }

    /// True for `STRUCT` or `UNION`.
    pub fn isComposite(self: Type) bool {
        return self.kind == .@"struct" or self.kind == .@"union";
    }
};

/// `BTF_INT_ENCODING`/`_OFFSET`/`_BITS`, unpacked. Deliberately NOT std's
/// `btf.IntInfo`: its `encoding` field is an `enum(u4)` with only the three
/// named bits, and a plain `unsigned int` — the most common INT in any
/// kernel's BTF — encodes as 0, which is not a member of that enum.
pub const IntInfo = struct {
    /// `BTF_INT_BITS` — the *used* width, which for a bitfield-ish base type
    /// can be smaller than `8 * byteSize()`.
    bits: u8,
    /// `BTF_INT_OFFSET` — bit offset of the value inside its storage.
    offset: u8,
    /// `BTF_INT_ENCODING` — a bit set, not an enumeration; 0 (plain
    /// unsigned) is legal and common.
    encoding: u4,

    /// `BTF_INT_SIGNED`.
    pub fn isSigned(self: IntInfo) bool {
        return self.encoding & 0b001 != 0;
    }
    /// `BTF_INT_CHAR`.
    pub fn isChar(self: IntInfo) bool {
        return self.encoding & 0b010 != 0;
    }
    /// `BTF_INT_BOOL`.
    pub fn isBool(self: IntInfo) bool {
        return self.encoding & 0b100 != 0;
    }
};

/// `struct btf_array`.
pub const ArrayInfo = struct {
    elem_type: u32,
    index_type: u32,
    nelems: u32,
};

/// `struct btf_member`, with the `KFLAG` split already applied — which is the
/// whole trap: when the enclosing `STRUCT`/`UNION` has `kind_flag` set, the
/// 32-bit `offset` word is `(bitfield_size << 24) | bit_offset`, and reading
/// it as a plain bit offset gives an answer that is wrong by megabytes for
/// every bitfield member. `struct sk_buff` in any real kernel BTF has such
/// members (`cloned`, `nohdr`, `fclone`, …), so this is not a theoretical case.
pub const Member = struct {
    name_off: u32,
    type_id: u32,
    /// Bit offset from the start of the enclosing struct/union.
    bit_offset: u32,
    /// Width in bits, or 0 for a non-bitfield member.
    bitfield_size: u8,
    /// The raw `offset` word, kept so a caller can re-derive either half.
    raw_offset: u32,
};

/// `struct btf_enum` / `struct btf_enum64`, unified. `signed` mirrors the
/// enclosing type's `kind_flag`.
pub const EnumValue = struct {
    name_off: u32,
    value: i64,
};

/// `struct btf_param`.
pub const Param = struct {
    name_off: u32,
    type_id: u32,
};

/// `struct btf_var_secinfo`.
pub const VarSecInfo = struct {
    type_id: u32,
    offset: u32,
    size: u32,
};

/// A member located inside a (possibly nested-anonymous) composite type —
/// what `findMember` returns and what a CO-RE field relocation is computed
/// from.
pub const Field = struct {
    /// Bit offset from the start of the type `findMember` was called on,
    /// accumulated across any anonymous struct/union hops.
    bit_offset: u64,
    /// The member's own type id.
    type_id: u32,
    /// Width in bits, or 0 when the member is not a bitfield.
    bitfield_size: u8,
    /// Index of the member inside its *immediately* enclosing composite.
    index: u16,
    /// Type id of that immediately enclosing composite (differs from the
    /// type searched when the member was found through an anonymous one).
    parent_type_id: u32,

    /// Byte offset, valid only for a non-bitfield member (a bitfield does not
    /// start on a byte boundary in general).
    pub fn byteOffset(self: Field) u64 {
        return self.bit_offset / 8;
    }
};

// ── the parsed blob ─────────────────────────────────────────────────────────

/// A parsed BTF blob. Holds no kernel resources — it is a view over bytes
/// plus a type-id index — so `deinit` only frees memory.
///
/// **Split BTF**: `base` points at the blob whose ids and strings this one
/// continues. The base must outlive this `Btf` (it is borrowed, not owned).
pub const Btf = struct {
    gpa: std.mem.Allocator,
    /// The whole blob. Owned by this `Btf` iff `owns_raw`.
    raw: []const u8,
    owns_raw: bool,
    hdr: Header,
    /// The type section (a sub-slice of `raw`).
    types: []const u8,
    /// The string section (a sub-slice of `raw`).
    strings: []const u8,
    /// `offsets[i]` = byte offset of type `start_id + i` inside `types`.
    offsets: []const u32,
    base: ?*const Btf,
    /// First type id this blob defines: 1 for a base blob, `base.endId()` for
    /// split BTF.
    start_id: u32,
    /// Value that must be subtracted from a `name_off` before indexing
    /// `strings`: 0 for a base blob, the base's `str_len` for split BTF.
    start_str_off: u32,

    pub fn deinit(self: *Btf) void {
        self.gpa.free(self.offsets);
        if (self.owns_raw) self.gpa.free(self.raw);
        self.* = undefined;
    }

    /// Number of types **this blob** defines (excludes the base's).
    pub fn typeCount(self: *const Btf) u32 {
        return @intCast(self.offsets.len);
    }

    /// One past the last type id this blob defines. For split BTF this is
    /// where a further split blob would start.
    pub fn endId(self: *const Btf) u32 {
        return self.start_id + self.typeCount();
    }

    /// True when this blob's ids continue another's.
    pub fn isSplit(self: *const Btf) bool {
        return self.base != null;
    }

    /// Decode type `id`, delegating to the base blob for an id below
    /// `start_id`. Id 0 is `void` and is **not** a decodable type.
    pub fn byId(self: *const Btf, id: u32) TypeError!Type {
        if (id == 0) return error.TypeIdOutOfRange;
        if (id < self.start_id) {
            const b = self.base orelse return error.TypeIdOutOfRange;
            return b.byId(id);
        }
        const idx = id - self.start_id;
        if (idx >= self.offsets.len) return error.TypeIdOutOfRange;
        const off = self.offsets[idx];
        return decodeAt(self.types, off, id) catch error.TypeIdOutOfRange;
    }

    /// True when `id` names a type in this blob or its base (0 = void is
    /// *not* a type, but IS a legal reference target).
    pub fn validId(self: *const Btf, id: u32) bool {
        if (id == 0) return false;
        if (id < self.start_id) {
            const b = self.base orelse return false;
            return b.validId(id);
        }
        return id - self.start_id < self.offsets.len;
    }

    /// The NUL-terminated string at `name_off`, or `null` when the offset is
    /// past the string section (of this blob *and* its base) or the section
    /// is not NUL-terminated there. `name_off == 0` is the empty string,
    /// which BTF uses for "anonymous".
    pub fn str(self: *const Btf, name_off: u32) ?[]const u8 {
        if (name_off < self.start_str_off) {
            const b = self.base orelse return null;
            return b.str(name_off);
        }
        const rel = name_off - self.start_str_off;
        if (rel >= self.strings.len) return null;
        const tail = self.strings[rel..];
        const end = std.mem.indexOfScalar(u8, tail, 0) orelse return null;
        return tail[0..end];
    }

    /// The name of type `id`, or `null` when it is anonymous or the offset is
    /// bad. Note the deliberate conflation: an anonymous type and a corrupt
    /// `name_off` both read as "no usable name", and neither may be matched
    /// by `findByNameKind`.
    pub fn typeName(self: *const Btf, id: u32) ?[]const u8 {
        const t = self.byId(id) catch return null;
        const s = self.str(t.name_off) orelse return null;
        return if (s.len == 0) null else s;
    }

    // ── kind-specific accessors ─────────────────────────────────────────────

    /// `BTF_KIND_INT`'s trailing word.
    pub fn intInfo(self: *const Btf, t: Type) TypeError!IntInfo {
        _ = self;
        if (t.kind != .int) return error.WrongKind;
        const w = rd32(t.extra, 0);
        return .{
            .bits = @truncate(w & 0xff),
            .offset = @truncate((w >> 16) & 0xff),
            .encoding = @truncate((w >> 24) & 0x0f),
        };
    }

    /// `BTF_KIND_ARRAY`'s trailing `struct btf_array`.
    pub fn arrayInfo(self: *const Btf, t: Type) TypeError!ArrayInfo {
        _ = self;
        if (t.kind != .array) return error.WrongKind;
        return .{
            .elem_type = rd32(t.extra, 0),
            .index_type = rd32(t.extra, 4),
            .nelems = rd32(t.extra, 8),
        };
    }

    /// Member `i` of a `STRUCT`/`UNION`, with the `KFLAG` bitfield split
    /// applied. `i` must be `< t.vlen`.
    pub fn member(self: *const Btf, t: Type, i: u16) TypeError!Member {
        _ = self;
        if (!t.isComposite()) return error.WrongKind;
        if (i >= t.vlen) return error.WrongKind;
        const at: usize = @as(usize, i) * 12;
        const raw = rd32(t.extra, at + 8);
        return .{
            .name_off = rd32(t.extra, at),
            .type_id = rd32(t.extra, at + 4),
            .bit_offset = if (t.kind_flag) raw & 0x00ff_ffff else raw,
            .bitfield_size = if (t.kind_flag) @truncate(raw >> 24) else 0,
            .raw_offset = raw,
        };
    }

    /// Value `i` of an `ENUM` (32-bit) or `ENUM64`. The enclosing type's
    /// `kind_flag` says whether the value is signed.
    pub fn enumValue(self: *const Btf, t: Type, i: u16) TypeError!EnumValue {
        _ = self;
        if (i >= t.vlen) return error.WrongKind;
        switch (t.kind) {
            .@"enum" => {
                const at: usize = @as(usize, i) * 8;
                const raw = rd32(t.extra, at + 4);
                return .{
                    .name_off = rd32(t.extra, at),
                    .value = if (t.kind_flag) @as(i32, @bitCast(raw)) else @as(i64, raw),
                };
            },
            .enum64 => {
                const at: usize = @as(usize, i) * 12;
                const lo: u64 = rd32(t.extra, at + 4);
                const hi: u64 = rd32(t.extra, at + 8);
                const v = (hi << 32) | lo;
                return .{
                    .name_off = rd32(t.extra, at),
                    .value = if (t.kind_flag) @as(i64, @bitCast(v)) else @as(i64, @bitCast(v)),
                };
            },
            else => return error.WrongKind,
        }
    }

    /// Parameter `i` of a `FUNC_PROTO`. A trailing param whose `name_off` and
    /// `type_id` are both 0 is C's `...` (varargs).
    pub fn param(self: *const Btf, t: Type, i: u16) TypeError!Param {
        _ = self;
        if (t.kind != .func_proto) return error.WrongKind;
        if (i >= t.vlen) return error.WrongKind;
        const at: usize = @as(usize, i) * 8;
        return .{ .name_off = rd32(t.extra, at), .type_id = rd32(t.extra, at + 4) };
    }

    /// A `BTF_KIND_VAR`'s linkage word.
    pub fn varLinkage(self: *const Btf, t: Type) TypeError!VarLinkage {
        _ = self;
        if (t.kind != .@"var") return error.WrongKind;
        return @enumFromInt(rd32(t.extra, 0));
    }

    /// Entry `i` of a `DATASEC`.
    pub fn varSecInfo(self: *const Btf, t: Type, i: u16) TypeError!VarSecInfo {
        _ = self;
        if (t.kind != .datasec) return error.WrongKind;
        if (i >= t.vlen) return error.WrongKind;
        const at: usize = @as(usize, i) * 12;
        return .{
            .type_id = rd32(t.extra, at),
            .offset = rd32(t.extra, at + 4),
            .size = rd32(t.extra, at + 8),
        };
    }

    /// A `BTF_KIND_DECL_TAG`'s `component_idx`: `-1` when the tag applies to
    /// the whole struct/union/var/func, otherwise the member or argument
    /// index it applies to.
    pub fn declTagComponent(self: *const Btf, t: Type) TypeError!i32 {
        _ = self;
        if (t.kind != .decl_tag) return error.WrongKind;
        return @bitCast(rd32(t.extra, 0));
    }

    // ── resolution ──────────────────────────────────────────────────────────

    /// Walk through `TYPEDEF`/`VOLATILE`/`CONST`/`RESTRICT`/`TYPE_TAG` to the
    /// first type that actually describes storage. Cycle-safe: a chain longer
    /// than `max_resolve_depth` is `error.TypeChainTooDeep`, not a hang.
    pub fn skipModifiers(self: *const Btf, id: u32) TypeError!u32 {
        var cur = id;
        var depth: u32 = 0;
        while (depth <= max_resolve_depth) : (depth += 1) {
            const t = try self.byId(cur);
            if (!t.isModifier()) return cur;
            cur = t.size_type;
        }
        return error.TypeChainTooDeep;
    }

    /// `skipModifiers`, returning the decoded type.
    pub fn resolve(self: *const Btf, id: u32) TypeError!Type {
        return self.byId(try self.skipModifiers(id));
    }

    /// Size in bytes of the type `id` describes, following modifiers and
    /// multiplying array extents out. `PTR` is 8 (eBPF is a 64-bit ISA).
    /// `FWD`, `FUNC_PROTO` and friends have no size — `error.NoSize`.
    pub fn sizeOf(self: *const Btf, id: u32) TypeError!u64 {
        return self.sizeOfDepth(id, 0);
    }

    fn sizeOfDepth(self: *const Btf, id: u32, depth: u32) TypeError!u64 {
        if (depth > max_resolve_depth) return error.TypeChainTooDeep;
        const t = try self.byId(id);
        switch (t.kind) {
            .int, .@"enum", .enum64, .@"struct", .@"union", .datasec, .float => return t.size_type,
            .ptr => return pointer_size,
            .typedef, .@"volatile", .@"const", .restrict, .type_tag => return self.sizeOfDepth(t.size_type, depth + 1),
            .array => {
                const a = try self.arrayInfo(t);
                const elem = try self.sizeOfDepth(a.elem_type, depth + 1);
                return std.math.mul(u64, elem, a.nelems) catch error.NoSize;
            },
            else => return error.NoSize,
        }
    }

    // ── lookups ─────────────────────────────────────────────────────────────

    /// First type named `name`, optionally restricted to one kind. The base
    /// blob is searched first, so a split blob never shadows a vmlinux type
    /// with a same-named one — matching how the kernel resolves ids.
    ///
    /// O(number of types): `/sys/kernel/btf/vmlinux` has ~170 000 of them, so
    /// this is a linear scan of a few megabytes. Fine for the handful of
    /// lookups an attach needs; build your own index if you need thousands.
    pub fn findByNameKind(self: *const Btf, name: []const u8, kind: ?Kind) ?u32 {
        if (name.len == 0) return null;
        if (self.base) |b| {
            if (b.findByNameKind(name, kind)) |id| return id;
        }
        var i: u32 = 0;
        while (i < self.offsets.len) : (i += 1) {
            const id = self.start_id + i;
            const t = self.byId(id) catch continue;
            if (kind) |k| {
                if (t.kind != k) continue;
            }
            const n = self.str(t.name_off) orelse continue;
            if (std.mem.eql(u8, n, name)) return id;
        }
        return null;
    }

    /// `findByNameKind` with no kind restriction.
    pub fn findByName(self: *const Btf, name: []const u8) ?u32 {
        return self.findByNameKind(name, null);
    }

    /// Locate `name` inside the composite type `id`, descending into
    /// **anonymous** members (which is how `struct sk_buff`'s `len` is
    /// reachable at all — several of its members are unnamed unions). The
    /// returned `bit_offset` is accumulated across those hops.
    pub fn findMember(self: *const Btf, id: u32, name: []const u8) TypeError!?Field {
        return self.findMemberDepth(id, name, 0, 0);
    }

    fn findMemberDepth(self: *const Btf, id: u32, name: []const u8, base_bits: u64, depth: u32) TypeError!?Field {
        if (depth > max_resolve_depth) return error.TypeChainTooDeep;
        const cid = try self.skipModifiers(id);
        const t = try self.byId(cid);
        if (!t.isComposite()) return error.WrongKind;

        var i: u16 = 0;
        while (i < t.vlen) : (i += 1) {
            const m = try self.member(t, i);
            const mname = self.str(m.name_off) orelse "";
            if (mname.len != 0) {
                if (std.mem.eql(u8, mname, name)) {
                    return Field{
                        .bit_offset = base_bits + m.bit_offset,
                        .type_id = m.type_id,
                        .bitfield_size = m.bitfield_size,
                        .index = i,
                        .parent_type_id = cid,
                    };
                }
                continue;
            }
            // Anonymous member: descend if it is itself a composite.
            const inner_id = self.skipModifiers(m.type_id) catch continue;
            const inner = self.byId(inner_id) catch continue;
            if (!inner.isComposite()) continue;
            if (try self.findMemberDepth(inner_id, name, base_bits + m.bit_offset, depth + 1)) |f| return f;
        }
        return null;
    }

    /// Walk a path of member names (`&.{"thread_info", "flags"}`). Pointers
    /// are **not** followed — a `PTR` hop needs a kernel read, which is a
    /// program-side concern, not a parser one, so a path that tries to step
    /// through one is `null` rather than a guess. Also `null` when any
    /// component is missing.
    pub fn findPath(self: *const Btf, id: u32, path: []const []const u8) TypeError!?Field {
        if (path.len == 0) return null;
        var cur = id;
        var bits: u64 = 0;
        var last: Field = undefined;
        for (path) |seg| {
            // A non-composite intermediate (typically a PTR) ends the walk.
            const cur_resolved = self.skipModifiers(cur) catch return null;
            if (!(self.byId(cur_resolved) catch return null).isComposite()) return null;
            const f = (try self.findMemberDepth(cur, seg, 0, 0)) orelse return null;
            last = .{
                .bit_offset = bits + f.bit_offset,
                .type_id = f.type_id,
                .bitfield_size = f.bitfield_size,
                .index = f.index,
                .parent_type_id = f.parent_type_id,
            };
            bits = last.bit_offset;
            cur = f.type_id;
        }
        return last;
    }

    // ── hostile-input hardening ─────────────────────────────────────────────

    /// Walk every type and check that every id it references is in range and
    /// every `name_off` resolves. `parse` deliberately does NOT do this — the
    /// kernel's own BTF is 7 MiB and a caller that only wants one
    /// `attach_btf_id` should not pay for a full graph audit — but a caller
    /// handing an untrusted blob to `loadIntoKernel`, or walking it
    /// exhaustively, should.
    ///
    /// Returns the offending type id in `error`-adjacent form: the error is
    /// typed, and `first_bad_id` is set when one is found.
    pub fn validateReferences(self: *const Btf, first_bad_id: ?*u32) TypeError!void {
        var i: u32 = 0;
        while (i < self.offsets.len) : (i += 1) {
            const id = self.start_id + i;
            const t = try self.byId(id);
            if (self.str(t.name_off) == null) {
                if (first_bad_id) |p| p.* = id;
                return error.TypeIdOutOfRange;
            }
            const bad: bool = switch (t.kind) {
                // A 0 reference is `void` and legal for these.
                .ptr, .typedef, .@"volatile", .@"const", .restrict, .func_proto, .type_tag => t.size_type != 0 and !self.validId(t.size_type),
                // These must name a real type.
                .func, .@"var", .decl_tag => !self.validId(t.size_type),
                .array => blk: {
                    const a = try self.arrayInfo(t);
                    break :blk !self.validId(a.elem_type) or !self.validId(a.index_type);
                },
                .@"struct", .@"union" => blk: {
                    var k: u16 = 0;
                    while (k < t.vlen) : (k += 1) {
                        const m = try self.member(t, k);
                        if (!self.validId(m.type_id)) break :blk true;
                        if (self.str(m.name_off) == null) break :blk true;
                    }
                    break :blk false;
                },
                .datasec => blk: {
                    var k: u16 = 0;
                    while (k < t.vlen) : (k += 1) {
                        const v = try self.varSecInfo(t, k);
                        if (!self.validId(v.type_id)) break :blk true;
                    }
                    break :blk false;
                },
                else => false,
            };
            if (bad) {
                if (first_bad_id) |p| p.* = id;
                return error.TypeIdOutOfRange;
            }
            // FUNC_PROTO params and ENUM value names live in trailing data.
            if (t.kind == .func_proto) {
                var k: u16 = 0;
                while (k < t.vlen) : (k += 1) {
                    const p = try self.param(t, k);
                    // (0, 0) is the varargs marker and references nothing.
                    if (p.type_id != 0 and !self.validId(p.type_id)) {
                        if (first_bad_id) |q| q.* = id;
                        return error.TypeIdOutOfRange;
                    }
                    if (self.str(p.name_off) == null) {
                        if (first_bad_id) |q| q.* = id;
                        return error.TypeIdOutOfRange;
                    }
                }
            }
        }
    }
};

// ── parsing ─────────────────────────────────────────────────────────────────

pub const ParseOptions = struct {
    /// The blob whose ids/strings this one continues (split BTF). Must
    /// outlive the returned `Btf`.
    base: ?*const Btf = null,
    /// Take ownership of `bytes` (freeing it in `deinit`). `parse` never
    /// copies: the returned `Btf` borrows `bytes` either way.
    own_bytes: bool = false,
};

/// Parse a BTF blob. `bytes` must outlive the returned `Btf` (it is borrowed,
/// not copied); set `opts.own_bytes` to hand ownership over.
pub fn parse(gpa: std.mem.Allocator, bytes: []const u8, opts: ParseOptions) ParseError!Btf {
    errdefer if (opts.own_bytes) gpa.free(@constCast(bytes));

    if (bytes.len < 8) return error.NotBtf;
    const m = std.mem.readInt(u16, bytes[0..2], native_endian);
    if (m != magic) {
        // A blob written by a producer of the other endianness reads as the
        // byte-swapped magic. Say so instead of failing as "not BTF".
        if (@byteSwap(m) == magic) return error.UnsupportedBtf;
        return error.NotBtf;
    }
    if (bytes[2] != version) return error.UnsupportedBtf;

    const flags = bytes[3];
    const hdr_len = rd32(bytes, 4);
    if (hdr_len < header_size) return error.MalformedBtf;
    if (hdr_len > bytes.len) return error.MalformedBtf;

    const type_off = rd32(bytes, 8);
    const type_len = rd32(bytes, 12);
    const str_off = rd32(bytes, 16);
    const str_len = rd32(bytes, 20);

    const data = bytes[hdr_len..];
    // u64 arithmetic so a `0xffffffff` offset cannot wrap into range.
    if (@as(u64, type_off) + @as(u64, type_len) > data.len) return error.MalformedBtf;
    if (@as(u64, str_off) + @as(u64, str_len) > data.len) return error.MalformedBtf;
    if (type_off % 4 != 0) return error.MalformedBtf; // btf_type is u32-aligned

    const types = data[type_off..][0..type_len];
    const strings = data[str_off..][0..str_len];

    // The string section must be NUL-framed. A BASE blob additionally starts
    // with the empty string (so `name_off == 0` means "anonymous"); a SPLIT
    // blob does not, which is exactly how one is recognized without any
    // out-of-band flag.
    if (opts.base == null) {
        if (str_len == 0) return error.MalformedBtf;
        if (strings[0] != 0) return error.SplitBtfNeedsBase;
        if (strings[str_len - 1] != 0) return error.MalformedBtf;
    } else if (str_len != 0) {
        if (strings[str_len - 1] != 0) return error.MalformedBtf;
    }

    // Walk the type section once, sizing every record. This is what makes
    // every later accessor safe to index without re-checking: a `vlen` that
    // does not fit is rejected here, not discovered halfway through a member
    // list.
    var offsets: std.ArrayList(u32) = .empty;
    errdefer offsets.deinit(gpa);

    var off: u32 = 0;
    while (off < type_len) {
        if (type_len - off < type_header_size) return error.MalformedBtf;
        const info = rd32(types, off + 4);
        const vlen: u16 = @truncate(info & 0xffff);
        const kind_raw: u5 = @truncate((info >> 24) & 0x1f);
        if (kind_raw > max_kind or kind_raw == @intFromEnum(Kind.unknown)) return error.MalformedBtf;
        const kind: Kind = @enumFromInt(kind_raw);
        const extra = extraLen(kind, vlen);
        const total = @as(u64, type_header_size) + extra;
        if (type_len - off < total) return error.MalformedBtf;
        if (offsets.items.len >= max_type) return error.TooManyTypes;
        offsets.append(gpa, off) catch return error.OutOfMemory;
        off += @intCast(total);
    }

    const base = opts.base;
    return .{
        .gpa = gpa,
        .raw = bytes,
        .owns_raw = opts.own_bytes,
        .hdr = .{
            .flags = flags,
            .hdr_len = hdr_len,
            .type_off = type_off,
            .type_len = type_len,
            .str_off = str_off,
            .str_len = str_len,
        },
        .types = types,
        .strings = strings,
        .offsets = offsets.toOwnedSlice(gpa) catch return error.OutOfMemory,
        .base = base,
        .start_id = if (base) |b| b.endId() else 1,
        .start_str_off = if (base) |b| b.start_str_off + b.hdr.str_len else 0,
    };
}

/// Trailing-data length for a kind, in bytes. **`FUNC` is the trap**: its
/// `vlen` carries the linkage, not a member count, so it has no trailing data
/// at all — sizing it as `8 * vlen` would desynchronize the type section.
fn extraLen(kind: Kind, vlen: u16) u64 {
    const n: u64 = vlen;
    return switch (kind) {
        .int => 4,
        .array => 12,
        .@"struct", .@"union" => 12 * n,
        .@"enum" => 8 * n,
        .enum64 => 12 * n,
        .func_proto => 8 * n,
        .@"var" => 4,
        .datasec => 12 * n,
        .decl_tag => 4,
        // ptr / fwd / typedef / volatile / const / restrict / func / float /
        // type_tag: nothing follows the 12-byte record.
        else => 0,
    };
}

fn decodeAt(types: []const u8, off: u32, id: u32) TypeError!Type {
    if (off + type_header_size > types.len) return error.TypeIdOutOfRange;
    const info = rd32(types, off + 4);
    const vlen: u16 = @truncate(info & 0xffff);
    const kind: Kind = @enumFromInt(@as(u5, @truncate((info >> 24) & 0x1f)));
    const extra_len = extraLen(kind, vlen);
    const start = off + type_header_size;
    if (start + extra_len > types.len) return error.TypeIdOutOfRange;
    return .{
        .id = id,
        .name_off = rd32(types, off),
        .kind = kind,
        .vlen = vlen,
        .kind_flag = (info >> 31) != 0,
        .size_type = rd32(types, off + 8),
        .extra = types[start..][0..@intCast(extra_len)],
    };
}

fn rd32(buf: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, buf[off..][0..4], native_endian);
}

// ── loading from the filesystem ─────────────────────────────────────────────

/// Parse `/sys/kernel/btf/vmlinux` — the kernel's own type graph, and the
/// only BTF a plain `fentry`/`fexit` attach needs. World-readable on a normal
/// kernel (mode 0444), so this needs **no privilege at all**; only the attach
/// that follows does.
pub fn loadKernel(gpa: std.mem.Allocator) LoadError!Btf {
    return loadFile(gpa, sysfs_vmlinux, null);
}

/// Parse `/sys/kernel/btf/<module>` — **split** BTF whose ids continue
/// `base`'s. `base` must be the vmlinux BTF the module was built against and
/// must outlive the result.
pub fn loadModule(gpa: std.mem.Allocator, module: []const u8, base: *const Btf) LoadError!Btf {
    if (module.len == 0 or module.len > 96) return error.InvalidModuleName;
    if (std.mem.indexOfScalar(u8, module, '/') != null) return error.InvalidModuleName;
    if (std.mem.indexOfScalar(u8, module, 0) != null) return error.InvalidModuleName;
    if (std.mem.eql(u8, module, ".") or std.mem.eql(u8, module, "..")) return error.InvalidModuleName;

    var buf: [160]u8 = undefined;
    const path = std.fmt.bufPrint(&buf, sysfs_btf_dir ++ "/{s}", .{module}) catch return error.InvalidModuleName;
    return loadFile(gpa, path, base);
}

/// Read and parse a BTF blob from a file. The bytes are owned by the returned
/// `Btf` (freed by `deinit`).
pub fn loadFile(gpa: std.mem.Allocator, path: []const u8, base: ?*const Btf) LoadError!Btf {
    if (comptime builtin.os.tag != .linux)
        @compileError("ebpf.btf file loading is Linux-only (raw open/read syscalls)");

    var path_buf: [4096]u8 = undefined;
    if (path.len >= path_buf.len) return error.FileOpenFailed;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    const bytes = try readWholeFile(gpa, @ptrCast(&path_buf));
    return parse(gpa, bytes, .{ .base = base, .own_bytes = true });
}

fn readWholeFile(gpa: std.mem.Allocator, path_z: [*:0]const u8) LoadError![]u8 {
    const rc = linux.open(path_z, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return error.FileOpenFailed;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    // sysfs BTF is a binary attribute; a sequential read loop works whether or
    // not the backing file reports a size through `stat`.
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const r = linux.read(fd, &chunk, chunk.len);
        switch (linux.errno(r)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.FileReadFailed,
        }
        if (r == 0) break;
        if (out.items.len + r > max_blob_bytes) return error.BtfTooLarge;
        out.appendSlice(gpa, chunk[0..r]) catch return error.OutOfMemory;
    }
    return out.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

// ── BPF_BTF_LOAD ────────────────────────────────────────────────────────────

/// `bpf_attr` for `BPF_BTF_LOAD`, extended past what std declares
/// (`BPF.BtfLoadAttr` stops after `btf_log_level`). Passing a longer attr is
/// ABI-safe in both directions as long as the tail is zero — the same rule
/// `bpflink.zig` documents for `link_create`.
pub const BtfLoadAttr = extern struct {
    btf: u64,
    btf_log_buf: u64,
    btf_size: u32,
    btf_log_size: u32,
    btf_log_level: u32,
    /// Output: the log size the kernel *would* have written (>= 6.4).
    btf_log_true_size: u32 = 0,
    btf_flags: u32 = 0,
    btf_token_fd: i32 = 0,
};

/// A `bpf_attr`-sized staging area, so the kernel never receives a pointer to
/// an allocation smaller than its own `union bpf_attr`.
const AttrBuf = extern union {
    base: BPF.Attr,
    btf_load: BtfLoadAttr,
};

/// Build the attr a `BPF_BTF_LOAD` sends — pure, so the layout is testable
/// without `CAP_BPF`. `blob` and `log` must outlive the syscall.
pub fn buildBtfLoadAttr(blob: []const u8, log: ?[]u8, log_level: u32) BtfLoadAttr {
    return .{
        .btf = @intFromPtr(blob.ptr),
        .btf_log_buf = if (log) |l| @intFromPtr(l.ptr) else 0,
        .btf_size = @intCast(blob.len),
        .btf_log_size = if (log) |l| @intCast(l.len) else 0,
        .btf_log_level = log_level,
    };
}

/// `bpf(BPF_BTF_LOAD)` — hand a BTF blob to the kernel's BTF verifier and get
/// back an fd. That fd is what a program load passes as `prog_btf_fd` so its
/// `func_info`/`line_info` records mean something, and what
/// `attach_btf_obj_fd` names when attaching to a **module's** function rather
/// than a vmlinux one.
///
/// Needs `CAP_BPF` (or root). The kernel re-validates everything this file
/// validates and more; `error.InvalidBtf` means *its* verifier said no, and
/// `log` (when supplied) holds its explanation.
pub fn loadIntoKernel(blob: []const u8, log: ?[]u8) KernelLoadError!linux.fd_t {
    if (comptime builtin.os.tag != .linux)
        @compileError("ebpf.btf.loadIntoKernel is Linux-only (bpf() raw syscall)");

    var buf: AttrBuf = .{ .btf_load = buildBtfLoadAttr(blob, log, if (log != null) 1 else 0) };
    const rc = linux.bpf(.btf_load, @ptrCast(&buf), @sizeOf(BtfLoadAttr));
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .ACCES, .PERM => error.PermissionDenied,
        .INVAL, .OPNOTSUPP => error.InvalidBtf,
        .NOMEM, .NOSPC, .MFILE, .NFILE => error.SystemResources,
        else => error.Unexpected,
    };
}

// ── a minimal blob builder ──────────────────────────────────────────────────

/// Emit a *valid* BTF blob. Deliberately small: enough to describe the
/// functions and types a hand-built program carries (so `BPF_BTF_LOAD` +
/// `prog_btf_fd` + `func_info` is usable end-to-end), not a general BTF
/// compiler. It performs no cross-checking beyond keeping its own ids
/// consistent — the kernel's verifier is the authority.
pub const Builder = struct {
    gpa: std.mem.Allocator,
    strings: std.ArrayList(u8),
    types: std.ArrayList(u8),
    count: u32,

    pub fn init(gpa: std.mem.Allocator) Builder {
        return .{ .gpa = gpa, .strings = .empty, .types = .empty, .count = 0 };
    }

    pub fn deinit(self: *Builder) void {
        self.strings.deinit(self.gpa);
        self.types.deinit(self.gpa);
        self.* = undefined;
    }

    /// Intern `s`, returning its `name_off`. The empty string is always 0.
    pub fn addString(self: *Builder, s: []const u8) !u32 {
        if (self.strings.items.len == 0) try self.strings.append(self.gpa, 0);
        if (s.len == 0) return 0;
        const off: u32 = @intCast(self.strings.items.len);
        try self.strings.appendSlice(self.gpa, s);
        try self.strings.append(self.gpa, 0);
        return off;
    }

    fn emit(self: *Builder, name_off: u32, kind: Kind, vlen: u16, kind_flag: bool, size_type: u32) !u32 {
        var hdr: [12]u8 = undefined;
        const info: u32 = @as(u32, vlen) |
            (@as(u32, @intFromEnum(kind)) << 24) |
            (@as(u32, @intFromBool(kind_flag)) << 31);
        std.mem.writeInt(u32, hdr[0..4], name_off, native_endian);
        std.mem.writeInt(u32, hdr[4..8], info, native_endian);
        std.mem.writeInt(u32, hdr[8..12], size_type, native_endian);
        try self.types.appendSlice(self.gpa, &hdr);
        self.count += 1;
        return self.count; // ids are 1-based
    }

    fn emitU32(self: *Builder, v: u32) !void {
        var w: [4]u8 = undefined;
        std.mem.writeInt(u32, &w, v, native_endian);
        try self.types.appendSlice(self.gpa, &w);
    }

    /// `BTF_KIND_INT`. `bits` is the used width; `encoding` is the
    /// `BTF_INT_SIGNED|CHAR|BOOL` bit set (0 = plain unsigned).
    pub fn addInt(self: *Builder, name: []const u8, byte_size: u32, bits: u8, encoding: u4) !u32 {
        const n = try self.addString(name);
        const id = try self.emit(n, .int, 0, false, byte_size);
        try self.emitU32((@as(u32, encoding) << 24) | bits);
        return id;
    }

    /// `BTF_KIND_PTR`. `target` may be 0 (`void *`).
    pub fn addPtr(self: *Builder, target: u32) !u32 {
        return self.emit(0, .ptr, 0, false, target);
    }

    /// `BTF_KIND_TYPEDEF`.
    pub fn addTypedef(self: *Builder, name: []const u8, target: u32) !u32 {
        const n = try self.addString(name);
        return self.emit(n, .typedef, 0, false, target);
    }

    /// `BTF_KIND_CONST` / `_VOLATILE` / `_RESTRICT`.
    pub fn addModifier(self: *Builder, kind: Kind, target: u32) !u32 {
        return self.emit(0, kind, 0, false, target);
    }

    /// `BTF_KIND_ARRAY`.
    pub fn addArray(self: *Builder, elem: u32, index_type: u32, nelems: u32) !u32 {
        const id = try self.emit(0, .array, 0, false, 0);
        try self.emitU32(elem);
        try self.emitU32(index_type);
        try self.emitU32(nelems);
        return id;
    }

    pub const MemberSpec = struct {
        name: []const u8,
        type_id: u32,
        /// Bit offset from the start of the composite.
        bit_offset: u32,
        /// Non-zero makes this a bitfield, which forces `kind_flag` on the
        /// enclosing type.
        bitfield_size: u8 = 0,
    };

    /// `BTF_KIND_STRUCT` or `_UNION`. `kind_flag` is set automatically when
    /// any member declares a `bitfield_size`.
    pub fn addComposite(self: *Builder, kind: Kind, name: []const u8, byte_size: u32, members: []const MemberSpec) !u32 {
        var kflag = false;
        for (members) |m| {
            if (m.bitfield_size != 0) kflag = true;
        }
        var name_offs: [64]u32 = undefined;
        if (members.len > name_offs.len) return error.TooManyMembers;
        for (members, 0..) |m, i| name_offs[i] = try self.addString(m.name);
        const n = try self.addString(name);
        const id = try self.emit(n, kind, @intCast(members.len), kflag, byte_size);
        for (members, 0..) |m, i| {
            try self.emitU32(name_offs[i]);
            try self.emitU32(m.type_id);
            const off: u32 = if (kflag)
                (@as(u32, m.bitfield_size) << 24) | (m.bit_offset & 0x00ff_ffff)
            else
                m.bit_offset;
            try self.emitU32(off);
        }
        return id;
    }

    /// `BTF_KIND_FUNC_PROTO`. `ret` may be 0 (void).
    pub fn addFuncProto(self: *Builder, ret: u32, params: []const Param) !u32 {
        const id = try self.emit(0, .func_proto, @intCast(params.len), false, ret);
        for (params) |p| {
            try self.emitU32(p.name_off);
            try self.emitU32(p.type_id);
        }
        return id;
    }

    /// `BTF_KIND_FUNC`. `proto` must be a `FUNC_PROTO` id.
    pub fn addFunc(self: *Builder, name: []const u8, proto: u32, linkage: FuncLinkage) !u32 {
        const n = try self.addString(name);
        return self.emit(n, .func, @intFromEnum(linkage), false, proto);
    }

    /// Serialize. The caller owns the returned bytes.
    pub fn finish(self: *Builder) ![]u8 {
        if (self.strings.items.len == 0) try self.strings.append(self.gpa, 0);
        const type_len: u32 = @intCast(self.types.items.len);
        const str_len: u32 = @intCast(self.strings.items.len);
        const total = header_size + type_len + str_len;
        const out = try self.gpa.alloc(u8, total);
        errdefer self.gpa.free(out);

        std.mem.writeInt(u16, out[0..2], magic, native_endian);
        out[2] = version;
        out[3] = 0;
        std.mem.writeInt(u32, out[4..8], header_size, native_endian);
        std.mem.writeInt(u32, out[8..12], 0, native_endian); // type_off
        std.mem.writeInt(u32, out[12..16], type_len, native_endian);
        std.mem.writeInt(u32, out[16..20], type_len, native_endian); // str_off
        std.mem.writeInt(u32, out[20..24], str_len, native_endian);
        @memcpy(out[header_size..][0..type_len], self.types.items);
        @memcpy(out[header_size + type_len ..][0..str_len], self.strings.items);
        return out;
    }
};

// ── tests ────────────────────────────────────────────────────────────────────
//
// Three layers, none of them needing any privilege:
//  1. Pure/layout: this file's hand-decoded field offsets against std's
//     `BPF.btf` structs, and the `BPF_BTF_LOAD` attr as golden bytes.
//  2. SYNTHETIC blobs built byte-by-byte — both a well-formed one (whose
//     every offset is an exact constant) and a battery of hostile ones (bad
//     magic, truncated header, section past the blob, `vlen` overrun, type id
//     out of range, string offset past the string section, a typedef cycle, a
//     DATASEC naming a type that does not exist, split BTF with no base).
//     Same shape as `elfsym.zig`'s `SynthElf` and `ringbuf.zig`'s `FakeRing`.
//  3. REAL kernel BTF: `/sys/kernel/btf/vmlinux`, cross-checked against
//     STRUCTURAL facts that survive a kernel rebuild (a member exists, a kind
//     is what it must be) rather than ids or offsets, which do not. Verified
//     against an independent tool with:
//       bpftool btf dump file /sys/kernel/btf/vmlinux format raw | head
//     Skips (never fails) when the file is absent.

const testing = std.testing;

test "wire layout agrees with std's BPF.btf structs" {
    try testing.expectEqual(@as(u16, std_btf.magic), magic);
    try testing.expectEqual(@as(u8, std_btf.version), version);
    try testing.expectEqual(header_size, @sizeOf(std_btf.Header));
    try testing.expectEqual(@as(usize, 0), @offsetOf(std_btf.Header, "magic"));
    try testing.expectEqual(@as(usize, 4), @offsetOf(std_btf.Header, "hdr_len"));
    try testing.expectEqual(@as(usize, 8), @offsetOf(std_btf.Header, "type_off"));
    try testing.expectEqual(@as(usize, 12), @offsetOf(std_btf.Header, "type_len"));
    try testing.expectEqual(@as(usize, 16), @offsetOf(std_btf.Header, "str_off"));
    try testing.expectEqual(@as(usize, 20), @offsetOf(std_btf.Header, "str_len"));

    try testing.expectEqual(type_header_size, @sizeOf(std_btf.Type));
    try testing.expectEqual(@as(usize, 12), @sizeOf(std_btf.Member));
    try testing.expectEqual(@as(usize, 12), @sizeOf(std_btf.Array));
    try testing.expectEqual(@as(usize, 8), @sizeOf(std_btf.Enum));
    try testing.expectEqual(@as(usize, 12), @sizeOf(std_btf.Enum64));
    try testing.expectEqual(@as(usize, 8), @sizeOf(std_btf.Param));
    try testing.expectEqual(@as(usize, 12), @sizeOf(std_btf.VarSecInfo));
    try testing.expectEqual(@as(usize, 4), @sizeOf(std_btf.Var));
    try testing.expectEqual(@as(usize, 4), @sizeOf(std_btf.DeclTag));

    try testing.expectEqual(@as(u32, std_btf.max_type), max_type);
    try testing.expectEqual(@as(u32, std_btf.max_name_offset), max_name_offset);
    try testing.expectEqual(@as(u32, std_btf.max_vlen), max_vlen);
    try testing.expectEqual(@as(u5, 19), max_kind);

    // The `Kind` values this file switches on must be std's, in the UAPI's
    // order — a renumbering would silently re-size every trailing record.
    try testing.expectEqual(@as(u5, 1), @intFromEnum(Kind.int));
    try testing.expectEqual(@as(u5, 4), @intFromEnum(Kind.@"struct"));
    try testing.expectEqual(@as(u5, 12), @intFromEnum(Kind.func));
    try testing.expectEqual(@as(u5, 13), @intFromEnum(Kind.func_proto));
    try testing.expectEqual(@as(u5, 15), @intFromEnum(Kind.datasec));
    try testing.expectEqual(@as(u5, 19), @intFromEnum(Kind.enum64));
}

test "extraLen: FUNC's vlen is a linkage, not a member count" {
    // The one case where sizing by vlen would desynchronize everything after
    // it: a global FUNC has vlen == 1 and NO trailing data.
    try testing.expectEqual(@as(u64, 0), extraLen(.func, 1));
    try testing.expectEqual(@as(u64, 0), extraLen(.func, 2));
    try testing.expectEqual(@as(u64, 8), extraLen(.func_proto, 1));
    try testing.expectEqual(@as(u64, 4), extraLen(.int, 0));
    try testing.expectEqual(@as(u64, 12), extraLen(.array, 0));
    try testing.expectEqual(@as(u64, 12 * 3), extraLen(.@"struct", 3));
    try testing.expectEqual(@as(u64, 8 * 3), extraLen(.@"enum", 3));
    try testing.expectEqual(@as(u64, 12 * 3), extraLen(.enum64, 3));
    try testing.expectEqual(@as(u64, 12 * 3), extraLen(.datasec, 3));
    try testing.expectEqual(@as(u64, 4), extraLen(.@"var", 0));
    try testing.expectEqual(@as(u64, 4), extraLen(.decl_tag, 0));
    try testing.expectEqual(@as(u64, 0), extraLen(.ptr, 0));
    try testing.expectEqual(@as(u64, 0), extraLen(.fwd, 0));
    try testing.expectEqual(@as(u64, 0), extraLen(.float, 0));
    try testing.expectEqual(@as(u64, 0), extraLen(.type_tag, 0));
    // The worst case must not overflow a u32 offset computation.
    try testing.expectEqual(@as(u64, 12 * 65535), extraLen(.@"struct", 65535));
}

test "golden: BPF_BTF_LOAD attr bytes" {
    if (native_endian != .little) return error.SkipZigTest;

    var blob = [_]u8{0xAB} ** 3;
    var log = [_]u8{0} ** 5;
    const attr = buildBtfLoadAttr(&blob, &log, 1);
    const bytes = std.mem.asBytes(&attr);

    try testing.expectEqual(@as(usize, 40), @sizeOf(BtfLoadAttr));
    try testing.expectEqual(@as(usize, 0), @offsetOf(BtfLoadAttr, "btf"));
    try testing.expectEqual(@as(usize, 8), @offsetOf(BtfLoadAttr, "btf_log_buf"));
    try testing.expectEqual(@as(usize, 16), @offsetOf(BtfLoadAttr, "btf_size"));
    try testing.expectEqual(@as(usize, 20), @offsetOf(BtfLoadAttr, "btf_log_size"));
    try testing.expectEqual(@as(usize, 24), @offsetOf(BtfLoadAttr, "btf_log_level"));
    try testing.expectEqual(@as(usize, 28), @offsetOf(BtfLoadAttr, "btf_log_true_size"));
    try testing.expectEqual(@as(usize, 32), @offsetOf(BtfLoadAttr, "btf_flags"));
    try testing.expectEqual(@as(usize, 36), @offsetOf(BtfLoadAttr, "btf_token_fd"));

    // std's shorter declaration must agree field-for-field on the prefix.
    try testing.expectEqual(@offsetOf(BPF.BtfLoadAttr, "btf"), @offsetOf(BtfLoadAttr, "btf"));
    try testing.expectEqual(@offsetOf(BPF.BtfLoadAttr, "btf_log_buf"), @offsetOf(BtfLoadAttr, "btf_log_buf"));
    try testing.expectEqual(@offsetOf(BPF.BtfLoadAttr, "btf_size"), @offsetOf(BtfLoadAttr, "btf_size"));
    try testing.expectEqual(@offsetOf(BPF.BtfLoadAttr, "btf_log_size"), @offsetOf(BtfLoadAttr, "btf_log_size"));
    try testing.expectEqual(@offsetOf(BPF.BtfLoadAttr, "btf_log_level"), @offsetOf(BtfLoadAttr, "btf_log_level"));

    try testing.expectEqual(@as(u64, @intFromPtr(&blob)), std.mem.readInt(u64, bytes[0..8], .little));
    try testing.expectEqual(@as(u64, @intFromPtr(&log)), std.mem.readInt(u64, bytes[8..16], .little));
    try testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, bytes[16..20], .little));
    try testing.expectEqual(@as(u32, 5), std.mem.readInt(u32, bytes[20..24], .little));
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, bytes[24..28], .little));
    // The tail the kernel may or may not know about must be zero.
    try testing.expectEqualSlices(u8, &@as([12]u8, @splat(0)), bytes[28..40]);

    // A log-less call: no buffer, no size.
    const bare = buildBtfLoadAttr(&blob, null, 0);
    try testing.expectEqual(@as(u64, 0), bare.btf_log_buf);
    try testing.expectEqual(@as(u32, 0), bare.btf_log_size);

    try testing.expect(@sizeOf(AttrBuf) >= @sizeOf(BPF.Attr));
}

// ── synthetic blobs ─────────────────────────────────────────────────────────

/// Hand-assembled BTF, byte by byte. Every offset below is an exact constant,
/// which is what makes the expectations in the tests constants too.
const Synth = struct {
    /// A structurally complete blob:
    ///
    /// ```text
    /// [1] INT  "int"            size 4, bits 32, SIGNED
    /// [2] INT  "unsigned int"   size 4, bits 32, encoding 0  <- the case
    ///                                                            std's enum
    ///                                                            cannot hold
    /// [3] PTR  -> [1]
    /// [4] STRUCT "point"  size 8   { x:[1]@0, y:[1]@32 }
    /// [5] STRUCT "bits"   size 4   KFLAG { a:[2]@0 sz1, b:[2]@1 sz3 }
    /// [6] TYPEDEF "point_t" -> [4]
    /// [7] CONST -> [6]
    /// [8] ARRAY [1] x 4  (index [2])
    /// [9] ENUM "color" size 4 { red=0, green=1 }
    /// [10] FUNC_PROTO -> [1] (a:[1], b:[3])
    /// [11] FUNC "do_thing" -> [10], GLOBAL
    /// [12] FWD "opaque"
    /// [13] VAR "gvar" -> [1], global-allocated
    /// [14] DATASEC ".data" size 4 { [13] @0 size 4 }
    /// [15] FLOAT "float" size 4
    /// [16] ENUM64 "big" size 8 { huge = 0x1_0000_0000 }
    /// [17] DECL_TAG "tagged" -> [4], component -1
    /// [18] TYPE_TAG "rcu" -> [3]
    /// [19] STRUCT "outer" size 16 { (anon):[20]@0, tail:[1]@64 }
    /// [20] STRUCT (anon) size 8 { inner_a:[1]@0, inner_b:[1]@32 }
    /// ```
    fn good(gpa: std.mem.Allocator) ![]u8 {
        var b = Builder.init(gpa);
        defer b.deinit();

        const int_id = try b.addInt("int", 4, 32, 0b001);
        const uint_id = try b.addInt("unsigned int", 4, 32, 0);
        const ptr_id = try b.addPtr(int_id);
        const point_id = try b.addComposite(.@"struct", "point", 8, &.{
            .{ .name = "x", .type_id = int_id, .bit_offset = 0 },
            .{ .name = "y", .type_id = int_id, .bit_offset = 32 },
        });
        _ = try b.addComposite(.@"struct", "bits", 4, &.{
            .{ .name = "a", .type_id = uint_id, .bit_offset = 0, .bitfield_size = 1 },
            .{ .name = "b", .type_id = uint_id, .bit_offset = 1, .bitfield_size = 3 },
        });
        const td_id = try b.addTypedef("point_t", point_id);
        _ = try b.addModifier(.@"const", td_id);
        _ = try b.addArray(int_id, uint_id, 4);

        // ENUM / ENUM64 / VAR / DATASEC / DECL_TAG have no Builder helper —
        // emit them by hand, which also exercises `emit` directly.
        _ = try b.emit(try b.addString("color"), .@"enum", 2, false, 4);
        try b.emitU32(try b.addString("red"));
        try b.emitU32(0);
        try b.emitU32(try b.addString("green"));
        try b.emitU32(1);

        const proto_id = try b.addFuncProto(int_id, &.{
            .{ .name_off = try b.addString("a"), .type_id = int_id },
            .{ .name_off = try b.addString("b"), .type_id = ptr_id },
        });
        _ = try b.addFunc("do_thing", proto_id, .global);
        _ = try b.emit(try b.addString("opaque"), .fwd, 0, false, 0);

        const var_id = try b.emit(try b.addString("gvar"), .@"var", 0, false, int_id);
        try b.emitU32(@intFromEnum(VarLinkage.global_allocated));

        _ = try b.emit(try b.addString(".data"), .datasec, 1, false, 4);
        try b.emitU32(var_id);
        try b.emitU32(0);
        try b.emitU32(4);

        _ = try b.emit(try b.addString("float"), .float, 0, false, 4);

        _ = try b.emit(try b.addString("big"), .enum64, 1, false, 8);
        try b.emitU32(try b.addString("huge"));
        try b.emitU32(0); // lo32
        try b.emitU32(1); // hi32 -> 0x1_0000_0000

        _ = try b.emit(try b.addString("tagged"), .decl_tag, 0, false, point_id);
        try b.emitU32(@bitCast(@as(i32, -1)));

        _ = try b.emit(try b.addString("rcu"), .type_tag, 0, false, ptr_id);

        // [19] outer contains an ANONYMOUS [20]; the anon struct is emitted
        // after it, which is legal (BTF ids may refer forward).
        _ = try b.addComposite(.@"struct", "outer", 16, &.{
            .{ .name = "", .type_id = 20, .bit_offset = 0 },
            .{ .name = "tail", .type_id = int_id, .bit_offset = 64 },
        });
        _ = try b.addComposite(.@"struct", "", 8, &.{
            .{ .name = "inner_a", .type_id = int_id, .bit_offset = 0 },
            .{ .name = "inner_b", .type_id = int_id, .bit_offset = 32 },
        });
        return b.finish();
    }

    /// A blob with exactly one type record, whose 12 header bytes and
    /// trailing data the caller supplies — the base for the hostile cases.
    fn oneType(gpa: std.mem.Allocator, recs: []const u8, strs: []const u8) ![]u8 {
        const out = try gpa.alloc(u8, header_size + recs.len + strs.len);
        @memset(out, 0);
        std.mem.writeInt(u16, out[0..2], magic, native_endian);
        out[2] = version;
        std.mem.writeInt(u32, out[4..8], header_size, native_endian);
        std.mem.writeInt(u32, out[8..12], 0, native_endian);
        std.mem.writeInt(u32, out[12..16], @intCast(recs.len), native_endian);
        std.mem.writeInt(u32, out[16..20], @intCast(recs.len), native_endian);
        std.mem.writeInt(u32, out[20..24], @intCast(strs.len), native_endian);
        @memcpy(out[header_size..][0..recs.len], recs);
        @memcpy(out[header_size + recs.len ..][0..strs.len], strs);
        return out;
    }

    fn rec(name_off: u32, kind: Kind, vlen: u16, kflag: bool, size_type: u32) [12]u8 {
        var r: [12]u8 = undefined;
        const info: u32 = @as(u32, vlen) |
            (@as(u32, @intFromEnum(kind)) << 24) |
            (@as(u32, @intFromBool(kflag)) << 31);
        std.mem.writeInt(u32, r[0..4], name_off, native_endian);
        std.mem.writeInt(u32, r[4..8], info, native_endian);
        std.mem.writeInt(u32, r[8..12], size_type, native_endian);
        return r;
    }
};

// ── fuzz: parse off the wire, never panics ──────────────────────────────────
//
// `parse` is the entry point for a BTF blob straight off the wire or lifted
// out of an untrusted object file's `.BTF` section — this file's own module
// doc calls out exactly this threat model (header offset/length fields
// that must be checked in u64 so they cannot wrap, a `vlen` that must not
// overrun the remaining type section, cyclic type graphs). Build a
// structurally valid, richly-varied blob via the same `Synth.good` fixture
// the hand-written hostile-input tests below already use — 20 types across
// every `Kind` the format defines — so the fuzzer reaches the type-section
// walk and every per-kind accessor instead of bouncing off `NotBtf` on the
// first two magic bytes, then truncate and/or flip bytes.

test "fuzz: parse never panics on a truncated/mutated synthetic BTF blob" {
    try testing.fuzz({}, fuzzParse, .{});
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    const gpa = testing.allocator;
    const seed = Synth.good(gpa) catch return;
    defer gpa.free(seed);

    const len: u32 = smith.valueRangeAtMost(u32, 0, @intCast(seed.len));
    const mutant = gpa.dupe(u8, seed[0..len]) catch return;
    defer gpa.free(mutant);

    const n_flips: u8 = smith.valueRangeAtMost(u8, 0, 16);
    var k: u8 = 0;
    while (k < n_flips and mutant.len > 0) : (k += 1) {
        mutant[smith.index(mutant.len)] = smith.value(u8);
    }

    var b = parse(gpa, mutant, .{}) catch return;
    defer b.deinit();

    // Walk the deferred-validation surface the module doc calls out: `byId`
    // on a fuzzer-chosen id (very possibly out of range after mutation), and
    // every per-kind accessor the doc says must reject a bad `vlen`/
    // `name_off` cleanly rather than read out of bounds.
    const id: u32 = smith.value(u32);
    if (b.byId(id) catch null) |t| {
        var i: u16 = 0;
        while (i < t.vlen and i < 64) : (i += 1) {
            _ = b.member(t, i) catch {};
            _ = b.param(t, i) catch {};
            _ = b.varSecInfo(t, i) catch {};
        }
        _ = b.str(t.name_off);
        _ = b.resolve(id) catch {};
        _ = b.sizeOf(id) catch {};
    }
    _ = b.findByNameKind("point_t", .typedef);
}

test "synthetic BTF: every kind decodes, with exact expectations" {
    const gpa = testing.allocator;
    const blob = try Synth.good(gpa);
    var b = try parse(gpa, blob, .{ .own_bytes = true });
    defer b.deinit();

    try testing.expectEqual(@as(u32, 20), b.typeCount());
    try testing.expectEqual(@as(u32, 1), b.start_id);
    try testing.expectEqual(@as(u32, 21), b.endId());
    try testing.expect(!b.isSplit());

    // INT, including the encoding-0 case std's enum cannot represent.
    {
        const t = try b.byId(1);
        try testing.expectEqual(Kind.int, t.kind);
        try testing.expectEqualStrings("int", b.typeName(1).?);
        try testing.expectEqual(@as(?u32, 4), t.byteSize());
        try testing.expectEqual(@as(?u32, null), t.refType());
        const ii = try b.intInfo(t);
        try testing.expectEqual(@as(u8, 32), ii.bits);
        try testing.expectEqual(@as(u8, 0), ii.offset);
        try testing.expect(ii.isSigned());
        try testing.expect(!ii.isChar());

        const u = try b.byId(2);
        const ui = try b.intInfo(u);
        try testing.expectEqual(@as(u4, 0), ui.encoding);
        try testing.expect(!ui.isSigned());
    }

    // PTR: a reference, always 8 bytes on the BPF ISA.
    {
        const t = try b.byId(3);
        try testing.expectEqual(Kind.ptr, t.kind);
        try testing.expectEqual(@as(?u32, 1), t.refType());
        try testing.expectEqual(@as(u64, 8), try b.sizeOf(3));
    }

    // STRUCT + members.
    {
        const t = try b.byId(4);
        try testing.expectEqual(Kind.@"struct", t.kind);
        try testing.expect(!t.kind_flag);
        try testing.expectEqual(@as(u16, 2), t.vlen);
        const m0 = try b.member(t, 0);
        try testing.expectEqualStrings("x", b.str(m0.name_off).?);
        try testing.expectEqual(@as(u32, 0), m0.bit_offset);
        try testing.expectEqual(@as(u8, 0), m0.bitfield_size);
        const m1 = try b.member(t, 1);
        try testing.expectEqualStrings("y", b.str(m1.name_off).?);
        try testing.expectEqual(@as(u32, 32), m1.bit_offset);
        try testing.expectError(error.WrongKind, b.member(t, 2));
        try testing.expectEqual(@as(u64, 8), try b.sizeOf(4));
    }

    // KFLAG bitfields: the offset word carries BOTH numbers.
    {
        const t = try b.byId(5);
        try testing.expect(t.kind_flag);
        const a = try b.member(t, 0);
        try testing.expectEqual(@as(u32, 0), a.bit_offset);
        try testing.expectEqual(@as(u8, 1), a.bitfield_size);
        const bb = try b.member(t, 1);
        try testing.expectEqual(@as(u32, 1), bb.bit_offset);
        try testing.expectEqual(@as(u8, 3), bb.bitfield_size);
        // Read as a plain offset the second member would claim bit 50331649.
        try testing.expectEqual(@as(u32, (3 << 24) | 1), bb.raw_offset);
    }

    // TYPEDEF / CONST chains resolve to the struct, and carry its size.
    {
        try testing.expectEqual(@as(u32, 4), try b.skipModifiers(7));
        try testing.expectEqual(Kind.@"struct", (try b.resolve(7)).kind);
        try testing.expectEqual(@as(u64, 8), try b.sizeOf(7));
    }

    // ARRAY.
    {
        const t = try b.byId(8);
        const a = try b.arrayInfo(t);
        try testing.expectEqual(@as(u32, 1), a.elem_type);
        try testing.expectEqual(@as(u32, 2), a.index_type);
        try testing.expectEqual(@as(u32, 4), a.nelems);
        try testing.expectEqual(@as(u64, 16), try b.sizeOf(8));
    }

    // ENUM.
    {
        const t = try b.byId(9);
        try testing.expectEqual(Kind.@"enum", t.kind);
        try testing.expectEqual(@as(u16, 2), t.vlen);
        const v0 = try b.enumValue(t, 0);
        try testing.expectEqualStrings("red", b.str(v0.name_off).?);
        try testing.expectEqual(@as(i64, 0), v0.value);
        const v1 = try b.enumValue(t, 1);
        try testing.expectEqualStrings("green", b.str(v1.name_off).?);
        try testing.expectEqual(@as(i64, 1), v1.value);
    }

    // FUNC_PROTO params, then FUNC (whose vlen is a LINKAGE).
    {
        const p = try b.byId(10);
        try testing.expectEqual(Kind.func_proto, p.kind);
        try testing.expectEqual(@as(?u32, 1), p.refType());
        try testing.expectEqualStrings("a", b.str((try b.param(p, 0)).name_off).?);
        try testing.expectEqual(@as(u32, 3), (try b.param(p, 1)).type_id);

        const f = try b.byId(11);
        try testing.expectEqual(Kind.func, f.kind);
        try testing.expectEqualStrings("do_thing", b.typeName(11).?);
        try testing.expectEqual(FuncLinkage.global, f.funcLinkage().?);
        try testing.expectEqual(@as(?u32, 10), f.refType());
        try testing.expectError(error.NoSize, b.sizeOf(11));
    }

    // FWD has no size.
    try testing.expectEqual(Kind.fwd, (try b.byId(12)).kind);
    try testing.expectError(error.NoSize, b.sizeOf(12));

    // VAR + DATASEC.
    {
        const v = try b.byId(13);
        try testing.expectEqual(VarLinkage.global_allocated, try b.varLinkage(v));
        const ds = try b.byId(14);
        try testing.expectEqual(Kind.datasec, ds.kind);
        const si = try b.varSecInfo(ds, 0);
        try testing.expectEqual(@as(u32, 13), si.type_id);
        try testing.expectEqual(@as(u32, 4), si.size);
    }

    // FLOAT / ENUM64 / DECL_TAG / TYPE_TAG.
    try testing.expectEqual(@as(u64, 4), try b.sizeOf(15));
    {
        const e = try b.byId(16);
        try testing.expectEqual(Kind.enum64, e.kind);
        try testing.expectEqual(@as(i64, 0x1_0000_0000), (try b.enumValue(e, 0)).value);
        const dt = try b.byId(17);
        try testing.expectEqual(@as(i32, -1), try b.declTagComponent(dt));
        const tt = try b.byId(18);
        try testing.expectEqual(Kind.type_tag, tt.kind);
        try testing.expect(tt.isModifier());
        try testing.expectEqual(@as(u32, 3), try b.skipModifiers(18));
    }

    // Anonymous-member descent: `inner_b` is not a member of `outer`, but it
    // is reachable through `outer`'s unnamed first member.
    {
        const outer = b.findByNameKind("outer", .@"struct").?;
        try testing.expectEqual(@as(u32, 19), outer);
        const f = (try b.findMember(outer, "inner_b")).?;
        try testing.expectEqual(@as(u64, 32), f.bit_offset);
        try testing.expectEqual(@as(u64, 4), f.byteOffset());
        try testing.expectEqual(@as(u32, 20), f.parent_type_id);
        const tail = (try b.findMember(outer, "tail")).?;
        try testing.expectEqual(@as(u64, 64), tail.bit_offset);
        try testing.expectEqual(@as(?Field, null), try b.findMember(outer, "nope"));
    }

    // Name lookups, kind-filtered.
    try testing.expectEqual(@as(?u32, 11), b.findByNameKind("do_thing", .func));
    try testing.expectEqual(@as(?u32, null), b.findByNameKind("do_thing", .@"struct"));
    try testing.expectEqual(@as(?u32, 6), b.findByNameKind("point_t", .typedef));
    try testing.expectEqual(@as(?u32, null), b.findByName(""));
    try testing.expectEqual(@as(?u32, null), b.findByName("no_such_type"));

    // An anonymous type has no name, and must not be matched by "".
    try testing.expectEqual(@as(?[]const u8, null), b.typeName(3));

    // The whole graph is internally consistent.
    var bad_id: u32 = 0;
    try b.validateReferences(&bad_id);
}

test "hostile BTF: every malformation is a typed error, never a crash" {
    const gpa = testing.allocator;

    // Too short to even hold a magic.
    try testing.expectError(error.NotBtf, parse(gpa, &.{ 0x9f, 0xeb }, .{}));
    // Wrong magic.
    {
        var buf = [_]u8{0} ** 64;
        std.mem.writeInt(u16, buf[0..2], 0x1234, native_endian);
        try testing.expectError(error.NotBtf, parse(gpa, &buf, .{}));
    }
    // Byte-swapped magic = a foreign-endian producer, which is refused as
    // UNSUPPORTED rather than mis-parsed.
    {
        var buf = [_]u8{0} ** 64;
        std.mem.writeInt(u16, buf[0..2], @byteSwap(magic), native_endian);
        try testing.expectError(error.UnsupportedBtf, parse(gpa, &buf, .{}));
    }
    // Wrong version.
    {
        var buf = [_]u8{0} ** 64;
        std.mem.writeInt(u16, buf[0..2], magic, native_endian);
        buf[2] = 2;
        try testing.expectError(error.UnsupportedBtf, parse(gpa, &buf, .{}));
    }
    // hdr_len shorter than the header, and hdr_len past the blob.
    {
        var buf = [_]u8{0} ** 64;
        std.mem.writeInt(u16, buf[0..2], magic, native_endian);
        buf[2] = version;
        std.mem.writeInt(u32, buf[4..8], 16, native_endian);
        try testing.expectError(error.MalformedBtf, parse(gpa, &buf, .{}));
        std.mem.writeInt(u32, buf[4..8], 0xffff_ffff, native_endian);
        try testing.expectError(error.MalformedBtf, parse(gpa, &buf, .{}));
    }
    // Section lengths that overflow the blob — including the pair that would
    // wrap if the addition were done in u32.
    {
        const blob = try Synth.good(gpa);
        defer gpa.free(blob);
        {
            const c = try gpa.dupe(u8, blob);
            defer gpa.free(c);
            std.mem.writeInt(u32, c[12..16], 0xffff_ffff, native_endian);
            try testing.expectError(error.MalformedBtf, parse(gpa, c, .{}));
        }
        {
            const c = try gpa.dupe(u8, blob);
            defer gpa.free(c);
            std.mem.writeInt(u32, c[8..12], 0xffff_fff0, native_endian);
            std.mem.writeInt(u32, c[12..16], 0x20, native_endian);
            try testing.expectError(error.MalformedBtf, parse(gpa, c, .{}));
        }
        {
            const c = try gpa.dupe(u8, blob);
            defer gpa.free(c);
            std.mem.writeInt(u32, c[20..24], 0xffff_ffff, native_endian);
            try testing.expectError(error.MalformedBtf, parse(gpa, c, .{}));
        }
        // A type section that is not u32-aligned.
        {
            const c = try gpa.dupe(u8, blob);
            defer gpa.free(c);
            std.mem.writeInt(u32, c[8..12], 2, native_endian);
            try testing.expectError(error.MalformedBtf, parse(gpa, c, .{}));
        }
        // A string section whose last byte is not NUL.
        {
            const c = try gpa.dupe(u8, blob);
            defer gpa.free(c);
            c[c.len - 1] = 'x';
            try testing.expectError(error.MalformedBtf, parse(gpa, c, .{}));
        }
    }
    // A vlen claiming more members than the type section holds.
    {
        const r = Synth.rec(0, .@"struct", 1000, false, 8);
        const blob = try Synth.oneType(gpa, &r, &.{0});
        defer gpa.free(blob);
        try testing.expectError(error.MalformedBtf, parse(gpa, blob, .{}));
    }
    // A truncated record: 8 bytes where 12 are needed.
    {
        const r = Synth.rec(0, .ptr, 0, false, 1);
        const blob = try Synth.oneType(gpa, r[0..8], &.{0});
        defer gpa.free(blob);
        try testing.expectError(error.MalformedBtf, parse(gpa, blob, .{}));
    }
    // An INT whose 4-byte trailing word is missing.
    {
        const r = Synth.rec(0, .int, 0, false, 4);
        const blob = try Synth.oneType(gpa, &r, &.{0});
        defer gpa.free(blob);
        try testing.expectError(error.MalformedBtf, parse(gpa, blob, .{}));
    }
    // An unknown BTF_KIND (20 and 31 — the top of the 5-bit field).
    for ([_]u32{ 20, 31 }) |k| {
        var r = Synth.rec(0, .ptr, 0, false, 1);
        std.mem.writeInt(u32, r[4..8], k << 24, native_endian);
        const blob = try Synth.oneType(gpa, &r, &.{0});
        defer gpa.free(blob);
        try testing.expectError(error.MalformedBtf, parse(gpa, blob, .{}));
    }
    // KIND_UNKN (0) is not a decodable record either.
    {
        var r = Synth.rec(0, .ptr, 0, false, 1);
        std.mem.writeInt(u32, r[4..8], 0, native_endian);
        const blob = try Synth.oneType(gpa, &r, &.{0});
        defer gpa.free(blob);
        try testing.expectError(error.MalformedBtf, parse(gpa, blob, .{}));
    }
    // An empty string section in a BASE blob.
    {
        const r = Synth.rec(0, .ptr, 0, false, 1);
        const blob = try Synth.oneType(gpa, &r, &.{});
        defer gpa.free(blob);
        try testing.expectError(error.MalformedBtf, parse(gpa, blob, .{}));
    }
}

test "hostile BTF: bad ids, bad string offsets, cycles and a bogus DATASEC" {
    const gpa = testing.allocator;

    // A PTR to a type id far past the end.
    {
        const r = Synth.rec(0, .ptr, 0, false, 9999);
        const blob = try Synth.oneType(gpa, &r, &.{0});
        var b = try parse(gpa, blob, .{ .own_bytes = true });
        defer b.deinit();
        try testing.expectError(error.TypeIdOutOfRange, b.byId(9999));
        // A PTR's own size is 8 without ever touching the pointee — but
        // following it must fail rather than read out of bounds.
        try testing.expectEqual(@as(u64, 8), try b.sizeOf(1));
        try testing.expect(!b.validId(9999));
        try testing.expectError(error.TypeIdOutOfRange, b.sizeOf((try b.byId(1)).refType().?));
        try testing.expectError(error.TypeIdOutOfRange, b.validateReferences(null));
    }
    // Id 0 is `void`, never a decodable type.
    {
        const r = Synth.rec(0, .ptr, 0, false, 0);
        const blob = try Synth.oneType(gpa, &r, &.{0});
        var b = try parse(gpa, blob, .{ .own_bytes = true });
        defer b.deinit();
        try testing.expectError(error.TypeIdOutOfRange, b.byId(0));
        // A `void *` is legal, though — validateReferences must accept it.
        try b.validateReferences(null);
    }
    // A name_off past the end of the string section.
    {
        const r = Synth.rec(500, .ptr, 0, false, 1);
        const blob = try Synth.oneType(gpa, &r, &.{0});
        var b = try parse(gpa, blob, .{ .own_bytes = true });
        defer b.deinit();
        try testing.expectEqual(@as(?[]const u8, null), b.str(500));
        try testing.expectEqual(@as(?[]const u8, null), b.typeName(1));
        try testing.expectError(error.TypeIdOutOfRange, b.validateReferences(null));
    }
    // A string section whose last entry has no NUL inside the section: the
    // section is NUL-terminated overall (so `parse` accepts it) but an offset
    // landing in the middle still resolves — this pins the exact boundary.
    {
        const r = Synth.rec(1, .ptr, 0, false, 1);
        const blob = try Synth.oneType(gpa, &r, "\x00ab\x00");
        var b = try parse(gpa, blob, .{ .own_bytes = true });
        defer b.deinit();
        try testing.expectEqualStrings("ab", b.str(1).?);
        try testing.expectEqualStrings("b", b.str(2).?);
        try testing.expectEqualStrings("", b.str(3).?);
        try testing.expectEqual(@as(?[]const u8, null), b.str(4));
    }
    // A TYPEDEF cycle: [1] -> [2] -> [1]. Must terminate.
    {
        var recs: [24]u8 = undefined;
        @memcpy(recs[0..12], &Synth.rec(0, .typedef, 0, false, 2));
        @memcpy(recs[12..24], &Synth.rec(0, .typedef, 0, false, 1));
        const blob = try Synth.oneType(gpa, &recs, &.{0});
        var b = try parse(gpa, blob, .{ .own_bytes = true });
        defer b.deinit();
        try testing.expectError(error.TypeChainTooDeep, b.skipModifiers(1));
        try testing.expectError(error.TypeChainTooDeep, b.resolve(2));
        try testing.expectError(error.TypeChainTooDeep, b.sizeOf(1));
    }
    // A self-referential ARRAY (element type == the array itself).
    {
        var recs: [24]u8 = undefined;
        @memcpy(recs[0..12], &Synth.rec(0, .array, 0, false, 0));
        std.mem.writeInt(u32, recs[12..16], 1, native_endian); // elem = [1]
        std.mem.writeInt(u32, recs[16..20], 1, native_endian); // index
        std.mem.writeInt(u32, recs[20..24], 2, native_endian); // nelems
        const blob = try Synth.oneType(gpa, &recs, &.{0});
        var b = try parse(gpa, blob, .{ .own_bytes = true });
        defer b.deinit();
        try testing.expectError(error.TypeChainTooDeep, b.sizeOf(1));
    }
    // A DATASEC naming a VAR that does not exist.
    {
        var recs: [24]u8 = undefined;
        @memcpy(recs[0..12], &Synth.rec(0, .datasec, 1, false, 4));
        std.mem.writeInt(u32, recs[12..16], 777, native_endian); // type = bogus
        std.mem.writeInt(u32, recs[16..20], 0, native_endian);
        std.mem.writeInt(u32, recs[20..24], 4, native_endian);
        const blob = try Synth.oneType(gpa, &recs, &.{0});
        var b = try parse(gpa, blob, .{ .own_bytes = true });
        defer b.deinit();
        const t = try b.byId(1);
        try testing.expectEqual(@as(u32, 777), (try b.varSecInfo(t, 0)).type_id);
        var bad: u32 = 0;
        try testing.expectError(error.TypeIdOutOfRange, b.validateReferences(&bad));
        try testing.expectEqual(@as(u32, 1), bad);
    }
    // Wrong-kind accessors are refusals, not reinterpretations.
    {
        const r = Synth.rec(0, .ptr, 0, false, 1);
        const blob = try Synth.oneType(gpa, &r, &.{0});
        var b = try parse(gpa, blob, .{ .own_bytes = true });
        defer b.deinit();
        const t = try b.byId(1);
        try testing.expectError(error.WrongKind, b.intInfo(t));
        try testing.expectError(error.WrongKind, b.arrayInfo(t));
        try testing.expectError(error.WrongKind, b.member(t, 0));
        try testing.expectError(error.WrongKind, b.param(t, 0));
        try testing.expectError(error.WrongKind, b.varLinkage(t));
        try testing.expectError(error.WrongKind, b.varSecInfo(t, 0));
        try testing.expectError(error.WrongKind, b.declTagComponent(t));
        try testing.expectError(error.WrongKind, b.findMember(1, "x"));
    }
}

test "split BTF: refused without a base, correct with one" {
    const gpa = testing.allocator;

    const base_blob = try Synth.good(gpa);
    var base = try parse(gpa, base_blob, .{ .own_bytes = true });
    defer base.deinit();

    // Build a split blob by hand: one STRUCT whose name lives in the SPLIT
    // string section (so its name_off is >= the base's str_len) and whose
    // member's type refers BACK into the base's id space.
    const split_strs = "split_only\x00";
    const name_off: u32 = base.hdr.str_len; // first byte of the split strings
    var recs: [12 + 12]u8 = undefined;
    @memcpy(recs[0..12], &Synth.rec(name_off, .@"struct", 1, false, 4));
    std.mem.writeInt(u32, recs[12..16], name_off, native_endian); // member name
    std.mem.writeInt(u32, recs[16..20], 1, native_endian); // type [1] = base's "int"
    std.mem.writeInt(u32, recs[20..24], 0, native_endian);
    const split_blob = try Synth.oneType(gpa, &recs, split_strs);

    // Without a base, the non-NUL first string byte gives it away.
    try testing.expectError(error.SplitBtfNeedsBase, parse(gpa, split_blob, .{}));

    var split = try parse(gpa, split_blob, .{ .base = &base, .own_bytes = true });
    defer split.deinit();

    // Ids continue where the base stopped.
    try testing.expectEqual(base.endId(), split.start_id);
    try testing.expectEqual(@as(u32, 21), split.start_id);
    try testing.expectEqual(@as(u32, 1), split.typeCount());
    try testing.expect(split.isSplit());

    // Names resolve out of the SPLIT section...
    try testing.expectEqualStrings("split_only", split.typeName(21).?);
    // ...and base ids and base names still resolve through the base.
    try testing.expectEqualStrings("int", split.typeName(1).?);
    try testing.expectEqual(@as(?u32, 4), split.findByNameKind("point", .@"struct"));
    try testing.expectEqual(@as(?u32, 21), split.findByNameKind("split_only", .@"struct"));

    // A member whose type lives in the base resolves through it.
    const f = (try split.findMember(21, "split_only")).?;
    try testing.expectEqual(@as(u32, 1), f.type_id);
    try testing.expectEqual(@as(u64, 4), try split.sizeOf(f.type_id));

    // An id below the base's start is still out of range.
    try testing.expectError(error.TypeIdOutOfRange, split.byId(0));
    try testing.expectError(error.TypeIdOutOfRange, split.byId(999));
    try split.validateReferences(null);
}

// ── real kernel BTF ─────────────────────────────────────────────────────────

/// Open `/sys/kernel/btf/vmlinux` or explain why the test is being skipped.
/// It is world-readable (0444) on a normal kernel, so this needs no
/// privilege — a skip here means CONFIG_DEBUG_INFO_BTF=n or a container
/// without /sys.
fn kernelBtfAvailable() bool {
    const rc = linux.open(sysfs_vmlinux, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    _ = linux.close(@intCast(rc));
    return true;
}

test "real kernel BTF: /sys/kernel/btf/vmlinux parses and resolves" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!kernelBtfAvailable()) {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: ebpf.btf kernel test — {s} not readable (CONFIG_DEBUG_INFO_BTF=n?).\n",
            .{sysfs_vmlinux},
        );
        return;
    }
    const gpa = testing.allocator;
    var k = try loadKernel(gpa);
    defer k.deinit();

    // Cross-checked against an INDEPENDENT tool:
    //   bpftool btf dump file /sys/kernel/btf/vmlinux format raw | head
    // On the machine this was written on that prints ids 1.. and a final
    // `[168880] FUNC 'zswpout_show'`; `k.endId() - 1` matched it exactly.
    // NONE of those numbers are asserted here — they change with every
    // kernel build. What IS asserted is structure: the shapes below are
    // true of any kernel that can host an fentry program at all.
    try testing.expect(k.typeCount() > 1000);
    try testing.expect(!k.isSplit());
    try testing.expectEqual(@as(u32, 1), k.start_id);
    try testing.expectEqual(@as(u8, 0), k.hdr.flags);
    try testing.expectEqual(@as(u32, header_size), k.hdr.hdr_len);

    // `struct task_struct` and a few members every kernel since ~2.6 has.
    const task = k.findByNameKind("task_struct", .@"struct") orelse {
        if (verboseSkip()) std.debug.print("\nSKIPPED: no `struct task_struct` in this kernel's BTF.\n", .{});
        return;
    };
    {
        const t = try k.byId(task);
        try testing.expectEqual(Kind.@"struct", t.kind);
        try testing.expect(t.vlen > 10);
        try testing.expect((try k.sizeOf(task)) > 100);

        for ([_][]const u8{ "pid", "tgid", "comm", "flags", "mm" }) |name| {
            const f = (try k.findMember(task, name)) orelse {
                std.debug.print("\nebpf.btf: task_struct has no `{s}` on this kernel.\n", .{name});
                continue;
            };
            // Structural, not numeric: every one of these is a plain
            // (non-bitfield) member somewhere inside the struct.
            try testing.expectEqual(@as(u8, 0), f.bitfield_size);
            try testing.expect(f.bit_offset % 8 == 0);
            try testing.expect(f.byteOffset() < try k.sizeOf(task));
            try testing.expect(k.validId(f.type_id));
        }
        // `comm` is a char array, `mm` is a pointer — the kinds are stable
        // even though the offsets are not.
        if (try k.findMember(task, "comm")) |f| {
            try testing.expectEqual(Kind.array, (try k.resolve(f.type_id)).kind);
            try testing.expectEqual(@as(u64, 16), try k.sizeOf(f.type_id)); // TASK_COMM_LEN
        }
        if (try k.findMember(task, "mm")) |f| {
            try testing.expectEqual(Kind.ptr, (try k.resolve(f.type_id)).kind);
            try testing.expectEqual(@as(u64, 8), try k.sizeOf(f.type_id));
        }
        // A name that is definitely not a member.
        try testing.expectEqual(@as(?Field, null), try k.findMember(task, "zig_libs_not_a_member"));
    }

    // `struct sk_buff` — the BITFIELD case. `cloned`/`nohdr`/`fclone` are
    // 1-3 bit members, so a parser that ignored BTF_INFO_KFLAG would report
    // absurd bit offsets for them.
    if (k.findByNameKind("sk_buff", .@"struct")) |skb| {
        try testing.expectEqual(Kind.@"struct", (try k.byId(skb)).kind);
        const size = try k.sizeOf(skb);
        try testing.expect(size > 64 and size < 4096);

        // `len` is reachable only THROUGH an anonymous union on any modern
        // kernel — this is the anonymous-descent path, exercised for real.
        const len = (try k.findMember(skb, "len")).?;
        try testing.expectEqual(@as(u8, 0), len.bitfield_size);
        try testing.expect(len.byteOffset() < size);
        try testing.expectEqual(@as(u64, 4), try k.sizeOf(len.type_id));

        for ([_][]const u8{ "cloned", "nohdr", "fclone" }) |name| {
            const f = (try k.findMember(skb, name)) orelse continue;
            // The structural fact: it IS a bitfield, and its bit offset lands
            // inside the struct. Both would be violated by a KFLAG-blind read
            // (which would decode `fclone`'s offset as ~50 million).
            try testing.expect(f.bitfield_size > 0 and f.bitfield_size <= 8);
            try testing.expect(f.bit_offset < size * 8);
        }
    }

    // A FUNC for a stable kernel entry point — this is literally the number
    // `linkCreateTracing` needs.
    {
        var found: usize = 0;
        for ([_][]const u8{ "vfs_read", "vfs_write", "do_sys_openat2", "ksys_write", "tcp_v4_connect" }) |name| {
            const id = k.findByNameKind(name, .func) orelse continue;
            found += 1;
            const f = try k.byId(id);
            try testing.expectEqual(Kind.func, f.kind);
            try testing.expectEqualStrings(name, k.typeName(id).?);
            // A FUNC always points at a FUNC_PROTO, and its vlen is a
            // LINKAGE (0..2), never a member count.
            const proto_id = f.refType().?;
            try testing.expectEqual(Kind.func_proto, (try k.byId(proto_id)).kind);
            try testing.expect(f.vlen <= 2);
            // Looking the same name up as a STRUCT must not find it.
            try testing.expectEqual(@as(?u32, null), k.findByNameKind(name, .@"struct"));
        }
        try testing.expect(found > 0);
    }

    // `btf_trace_<x>` — the TYPEDEFs `tp_btf` attaches to. (Note: these are
    // TYPEDEFs, not FUNCs; see `tracing.zig`.)
    {
        var seen: usize = 0;
        for ([_][]const u8{ "btf_trace_sched_switch", "btf_trace_sys_enter", "btf_trace_kfree_skb" }) |name| {
            const id = k.findByNameKind(name, .typedef) orelse continue;
            seen += 1;
            const t = try k.byId(id);
            try testing.expectEqual(Kind.typedef, t.kind);
            // It aliases a pointer-to-FUNC_PROTO.
            const target = try k.resolve(t.size_type);
            try testing.expectEqual(Kind.ptr, target.kind);
        }
        if (seen == 0) std.debug.print("\nebpf.btf: no btf_trace_* typedefs on this kernel (no tracepoint BTF).\n", .{});
    }

    // A well-known INT, decoded through the encoding word.
    if (k.findByNameKind("int", .int)) |id| {
        const t = try k.byId(id);
        const ii = try k.intInfo(t);
        try testing.expectEqual(@as(u32, 4), t.byteSize().?);
        try testing.expectEqual(@as(u8, 32), ii.bits);
        try testing.expect(ii.isSigned());
    }
    if (k.findByNameKind("unsigned int", .int)) |id| {
        const ii = try k.intInfo(try k.byId(id));
        // The case std's `IntInfo.encoding` enum cannot represent.
        try testing.expectEqual(@as(u4, 0), ii.encoding);
    }
}

test "real kernel BTF: a module's split BTF resolves only with vmlinux as its base" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!kernelBtfAvailable()) {
        if (verboseSkip()) std.debug.print("\nSKIPPED: ebpf.btf module-BTF test — no kernel BTF.\n", .{});
        return;
    }
    const gpa = testing.allocator;
    var k = try loadKernel(gpa);
    defer k.deinit();

    // Any module that is loaded on this machine will do; try a few that are
    // common and skip if none is present (a minimal/monolithic kernel has no
    // module BTF at all).
    const candidates = [_][]const u8{ "bluetooth", "nf_tables", "kvm", "ext4", "vfat", "e1000e", "iwlwifi", "binfmt_misc" };
    for (candidates) |name| {
        var m = loadModule(gpa, name, &k) catch continue;
        defer m.deinit();

        // The defining property of split BTF: ids continue from the base.
        try testing.expect(m.isSplit());
        try testing.expectEqual(k.endId(), m.start_id);
        try testing.expectEqual(k.hdr.str_len, m.start_str_off);
        try testing.expect(m.typeCount() > 0);

        // Every base id still resolves through the module blob...
        try testing.expectEqualStrings("task_struct", m.typeName(k.findByNameKind("task_struct", .@"struct").?).?);
        // ...and at least one of the module's own types has a name that came
        // out of the SPLIT string section.
        var named: usize = 0;
        var i: u32 = 0;
        while (i < m.typeCount() and named < 4) : (i += 1) {
            const id = m.start_id + i;
            const t = try m.byId(id);
            if (t.name_off < m.start_str_off) continue; // a base string
            if (m.str(t.name_off)) |s| {
                if (s.len != 0) named += 1;
            }
        }
        try testing.expect(named > 0);

        // Parsing the same blob WITHOUT the base must be refused, not
        // silently mis-resolved.
        var path_buf: [160]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, sysfs_btf_dir ++ "/{s}", .{name});
        var pz: [176]u8 = undefined;
        @memcpy(pz[0..path.len], path);
        pz[path.len] = 0;
        const bytes = try readWholeFile(gpa, @ptrCast(&pz));
        defer gpa.free(bytes);
        try testing.expectError(error.SplitBtfNeedsBase, parse(gpa, bytes, .{}));

        // Informational, not a failure — same stderr rule as the skip reasons.
        if (verboseSkip()) std.debug.print("\nebpf.btf: verified split BTF against module `{s}` ({d} types, ids from {d}).\n", .{ name, m.typeCount(), m.start_id });
        return;
    }
    if (verboseSkip()) std.debug.print("\nSKIPPED: ebpf.btf module-BTF test — none of the candidate modules has BTF here.\n", .{});
}

test "loadModule rejects a name that could escape /sys/kernel/btf" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    var dummy: Btf = undefined;
    // These must fail on the NAME, before any file is touched.
    try testing.expectError(error.InvalidModuleName, loadModule(gpa, "", &dummy));
    try testing.expectError(error.InvalidModuleName, loadModule(gpa, "../../etc/passwd", &dummy));
    try testing.expectError(error.InvalidModuleName, loadModule(gpa, "a/b", &dummy));
    try testing.expectError(error.InvalidModuleName, loadModule(gpa, "..", &dummy));
    try testing.expectError(error.InvalidModuleName, loadModule(gpa, "x" ** 200, &dummy));
}

test "LIVE: BPF_BTF_LOAD accepts a blob this module built" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;

    var b = Builder.init(gpa);
    defer b.deinit();
    const int_id = try b.addInt("int", 4, 32, 0b001);
    const proto = try b.addFuncProto(int_id, &.{});
    _ = try b.addFunc("zig_libs_prog", proto, .global);
    const blob = try b.finish();
    defer gpa.free(blob);

    // It must at minimum round-trip through this module's own parser.
    {
        var parsed = try parse(gpa, blob, .{});
        defer parsed.deinit();
        try testing.expectEqual(@as(u32, 3), parsed.typeCount());
        try testing.expectEqual(@as(?u32, 3), parsed.findByNameKind("zig_libs_prog", .func));
        try parsed.validateReferences(null);
    }

    if (linux.geteuid() != 0) {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: LIVE ebpf.btf BPF_BTF_LOAD — needs CAP_BPF (running as uid {d}).\n",
            .{linux.geteuid()},
        );
        return;
    }

    var log: [4096]u8 = undefined;
    const fd = loadIntoKernel(blob, &log) catch |e| {
        if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE ebpf.btf BPF_BTF_LOAD refused ({s}): {s}\n", .{ @errorName(e), std.mem.sliceTo(&log, 0) });
        return;
    };
    defer _ = linux.close(fd);
    try testing.expect(fd >= 0);

    // A blob the kernel must reject: a FUNC pointing at itself.
    var bad = Builder.init(gpa);
    defer bad.deinit();
    _ = try bad.addFunc("bad", 1, .global);
    const bad_blob = try bad.finish();
    defer gpa.free(bad_blob);
    if (loadIntoKernel(bad_blob, null)) |ok_fd| {
        _ = linux.close(ok_fd);
        return error.TestUnexpectedResult;
    } else |e| {
        try testing.expectEqual(KernelLoadError.InvalidBtf, e);
    }
}
