// SPDX-License-Identifier: MIT

//! **SCL** — the IEC 61850-6 Substation Configuration Language: the XML that
//! describes what an IED actually contains, and the only thing that lets a
//! client address a substation without being told every object reference by
//! hand.
//!
//! An SCL file is not a list of variables. It is a **type graph**, and walking
//! it is the whole job:
//!
//! ```text
//! IED → AccessPoint → Server → LDevice → LN0/LN ──lnType──► LNodeType
//!                                                             │ DO(type)
//!                                                             ▼
//!                                                           DOType
//!                                                        DA(type) │ SDO(type)
//!                                                             ▼
//!                                                           DAType ──BDA──► DAType…
//! ```
//!
//! `resolve` walks that graph and produces the flat list of MMS names the rest
//! of this module speaks — `GGIO1$ST$Ind1$stVal`, `GGIO1$CO$SPCSO4$SBOw$ctlNum`
//! — which is exactly what a `GetNameList` returns from the IED the file
//! configures. Three things make that walk non-trivial:
//!
//! * **The functional constraint lives on the `DA`, not on the `DO`,** and it
//!   applies to the whole subtree below it. A `DO` therefore appears under
//!   *every* FC any of its attributes carries: `Mod` shows up under `ST` (its
//!   `q` and `t`) **and** under `CF` (its `ctlModel`), with different children
//!   each time. A resolver that hangs the FC off the data object produces names
//!   the IED reports as non-existent.
//! * **The graph can lie.** A `DO` may name an unknown `DOType`, a `DAType` may
//!   reference itself, an `FCDA` may point at a data object that is not in the
//!   `LNodeType`. All three are typed errors here, and the cycle is caught by a
//!   depth budget plus an explicit on-path check rather than by blowing the
//!   stack.
//! * **Control blocks are part of the name space.** A `ReportControl` with
//!   `<RptEnabled max="2"/>` becomes `LLN0$RP$<name>01` *and* `…02`, each with
//!   the eleven URCB attributes; a `GSEControl` becomes `LLN0$GO$<name>` with
//!   its `DstAddress` sub-structure taken from the `Communication` section. A
//!   client configured from SCL that omits them cannot enable reporting.
//!
//! **This is the only file in this module that allocates.** An SCL document is
//! a graph of unbounded shape and the `xml` sibling hands back an allocated
//! tree; pretending otherwise would mean a fixed ceiling on every substation.
//! Everything is arena-backed and freed by one `deinit`, and every decoded
//! slice points into the caller's source or into that arena.
//!
//! The parser underneath is the `xml` sibling, which is XXE- and
//! billion-laughs-proof and rejects DOCTYPE by default. SCL has no legitimate
//! use for either.

const std = @import("std");
const acsi = @import("acsi.zig");
const control = @import("control.zig");
const xml = @import("xml");

pub const Error = error{
    /// The document root is not `<SCL>`.
    NotScl,
    /// A `lnType`, `DO type`, `DA type` or `SDO type` names a template that is
    /// not in `DataTypeTemplates`.
    UnresolvedType,
    /// The type graph contains a cycle — a `DAType` that reaches itself.
    CyclicType,
    /// The type graph nests deeper than `max_type_depth`.
    TypeTooDeep,
    /// A functional constraint that IEC 61850-7-2 does not define.
    UnknownFunctionalConstraint,
    /// A `bType` outside the IEC 61850-6 basic type list.
    UnknownBasicType,
    /// A `Val` whose text cannot be a value of its `bType`.
    ValueTypeMismatch,
    /// An `FCDA` naming a logical node or data object that does not exist.
    UnresolvedFcda,
    /// A required attribute is missing.
    MissingAttribute,
    /// An identifier longer than IEC 61850 allows, or a resolved MMS name that
    /// does not fit `acsi.max_reference_len`.
    NameTooLong,
    /// More logical devices, logical nodes, attributes or templates than the
    /// resolver's ceilings allow.
    TooLarge,
} || xml.ParseError || std.mem.Allocator.Error;

/// The SCL namespace of IEC 61850-6 editions 1 and 2. Both are accepted, and so
/// is a document with no namespace at all — plenty of tools emit one.
pub const ns_2003 = "http://www.iec.ch/61850/2003/SCL";
pub const ns_2007 = "http://www.iec.ch/61850/2007/SCL";

/// Deeper than any real common data class; a cyclic `DAType` hits it at once.
pub const max_type_depth: u8 = 12;

// ── functional constraints as SCL spells them ───────────────────────────────

/// SCL's `fc` attribute. This is a **superset** of `acsi.FunctionalConstraint`:
/// edition 2 adds `OR` (operate received — the `opRcvd`/`opOk` attributes of a
/// control object) and `BL` (blocked), and both appear in shipped SCL files and
/// in a real IED's `GetNameList`. They are kept here rather than added to the
/// ACSI enum so the wire-level naming layer stays exactly the 17 constraints
/// IEC 61850-7-2 Table 21 lists.
pub const Fc = enum {
    ST,
    MX,
    CO,
    SP,
    SV,
    CF,
    DC,
    SG,
    SE,
    EX,
    BR,
    RP,
    LG,
    GO,
    GS,
    MS,
    US,
    /// Operate received — edition 2.
    OR,
    /// Blocked — edition 2.
    BL,
    /// Service tracking — edition 2.1.
    SR,

    pub fn parse(s: []const u8) Error!Fc {
        inline for (@typeInfo(Fc).@"enum".fields) |f| {
            if (std.mem.eql(u8, s, f.name)) return @enumFromInt(f.value);
        }
        return error.UnknownFunctionalConstraint;
    }

    pub fn name(self: Fc) []const u8 {
        return @tagName(self);
    }

    /// The ACSI constraint, or null for the two edition-2 additions the
    /// wire-level naming layer does not model.
    pub fn toAcsi(self: Fc) ?acsi.FunctionalConstraint {
        return acsi.FunctionalConstraint.parse(@tagName(self)) catch null;
    }
};

/// IEC 61850-6 Table "Basic types". `Struct` is the one that means "recurse".
pub const BType = enum {
    BOOLEAN,
    INT8,
    INT16,
    INT24,
    INT32,
    INT64,
    INT8U,
    INT16U,
    INT24U,
    INT32U,
    FLOAT32,
    FLOAT64,
    Enum,
    Dbpos,
    Tcmd,
    Quality,
    Timestamp,
    VisString32,
    VisString64,
    VisString65,
    VisString129,
    VisString255,
    Octet64,
    Octet6,
    Octet16,
    Unicode255,
    Struct,
    EntryTime,
    Check,
    ObjRef,
    Currency,
    PhyComAddr,
    EntryID,
    OptFlds,
    TrgOps,
    SvOptFlds,
    /// Only produced when `Options.allow_unknown_btype` is set.
    unknown,

    pub fn parse(s: []const u8) Error!BType {
        inline for (@typeInfo(BType).@"enum".fields) |f| {
            if (std.mem.eql(u8, s, f.name)) return @enumFromInt(f.value);
        }
        return error.UnknownBasicType;
    }

    /// The SCL spelling of this basic type — what `parse` accepts back.
    pub fn name(self: BType) []const u8 {
        return @tagName(self);
    }

    /// Maximum string length, for the `VisString*`/`Octet*`/`Unicode*` types.
    pub fn maxLen(self: BType) ?usize {
        return switch (self) {
            .VisString32 => 32,
            .VisString64 => 64,
            .VisString65 => 65,
            .VisString129 => 129,
            .VisString255, .Unicode255 => 255,
            .Octet6 => 6,
            .Octet16 => 16,
            .Octet64 => 64,
            .ObjRef => acsi.max_reference_len,
            else => null,
        };
    }

    fn intRange(self: BType) ?struct { min: i64, max: i64 } {
        return switch (self) {
            .INT8 => .{ .min = -128, .max = 127 },
            .INT16 => .{ .min = -32768, .max = 32767 },
            .INT24 => .{ .min = -8388608, .max = 8388607 },
            .INT32 => .{ .min = -2147483648, .max = 2147483647 },
            .INT64 => .{ .min = std.math.minInt(i64), .max = std.math.maxInt(i64) },
            .INT8U => .{ .min = 0, .max = 255 },
            .INT16U => .{ .min = 0, .max = 65535 },
            .INT24U => .{ .min = 0, .max = 16777215 },
            .INT32U, .EntryTime => .{ .min = 0, .max = 4294967295 },
            else => null,
        };
    }
};

// ── the document ────────────────────────────────────────────────────────────

pub const Header = struct {
    id: []const u8 = "",
    version: []const u8 = "",
    revision: []const u8 = "",
    tool_id: []const u8 = "",
    /// `IEDName` (the only value edition 2 allows) or `FuncName`.
    name_structure: []const u8 = "",
};

/// One `<P type="…">value</P>`.
pub const Param = struct {
    type: []const u8,
    value: []const u8,
};

/// An `<Address>` — the IP/OSI parameters of an MMS access point, or the
/// MAC/APPID/VLAN parameters of a GOOSE or sampled-value control block.
pub const Address = struct {
    params: []const Param = &.{},

    pub fn get(self: Address, t: []const u8) ?[]const u8 {
        for (self.params) |p| {
            if (std.mem.eql(u8, p.type, t)) return p.value;
        }
        return null;
    }

    pub fn ip(self: Address) ?[]const u8 {
        return self.get("IP");
    }
    pub fn mac(self: Address) ?[]const u8 {
        return self.get("MAC-Address");
    }
    /// The GOOSE/SV APPID, parsed. SCL writes it in decimal or hex depending on
    /// the tool, so both are accepted.
    pub fn appId(self: Address) ?u16 {
        const s = self.get("APPID") orelse return null;
        return std.fmt.parseInt(u16, s, 10) catch std.fmt.parseInt(u16, s, 16) catch null;
    }
    pub fn vlanId(self: Address) ?u12 {
        const s = self.get("VLAN-ID") orelse return null;
        return std.fmt.parseInt(u12, s, 10) catch std.fmt.parseInt(u12, s, 16) catch null;
    }
    pub fn vlanPriority(self: Address) ?u3 {
        const s = self.get("VLAN-PRIORITY") orelse return null;
        return std.fmt.parseInt(u3, s, 10) catch null;
    }
};

/// A `<GSE>` or `<SMV>` under a `<ConnectedAP>`: the layer-2 address a control
/// block publishes on. It lives in `Communication`, not next to the control
/// block itself, which is the single most surprising thing about SCL.
pub const CbAddress = struct {
    ld_inst: []const u8,
    cb_name: []const u8,
    address: Address = .{},
    min_time_ms: ?u32 = null,
    max_time_ms: ?u32 = null,
};

pub const ConnectedAp = struct {
    ied_name: []const u8,
    ap_name: []const u8,
    address: Address = .{},
    gse: []const CbAddress = &.{},
    smv: []const CbAddress = &.{},
};

pub const Subnetwork = struct {
    name: []const u8,
    type: []const u8 = "",
    aps: []const ConnectedAp = &.{},
};

/// One `<FCDA>` of a data set: a *functionally constrained* data attribute, or
/// a whole data object when `da_name` is empty.
pub const Fcda = struct {
    ld_inst: []const u8,
    prefix: []const u8 = "",
    ln_class: []const u8,
    ln_inst: []const u8 = "",
    do_name: []const u8,
    da_name: []const u8 = "",
    fc: Fc,

    /// The MMS item id this entry addresses: `LN$FC$DO[$DA]`. `do_name` and
    /// `da_name` may themselves be `.`-separated paths (an SDO or a nested BDA),
    /// which become further `$` components.
    pub fn mmsItem(self: Fcda, out: []u8) Error![]const u8 {
        var w: usize = 0;
        w += try put(out, w, self.prefix);
        w += try put(out, w, self.ln_class);
        w += try put(out, w, self.ln_inst);
        w += try put(out, w, "$");
        w += try put(out, w, self.fc.name());
        var it = std.mem.splitScalar(u8, self.do_name, '.');
        while (it.next()) |c| {
            if (c.len == 0) continue;
            w += try put(out, w, "$");
            w += try put(out, w, stripIndex(c));
            if (std.mem.indexOfScalar(u8, c, '(') != null) return out[0..w];
        }
        if (self.da_name.len > 0) {
            var da = std.mem.splitScalar(u8, self.da_name, '.');
            while (da.next()) |c| {
                if (c.len == 0) continue;
                w += try put(out, w, "$");
                w += try put(out, w, stripIndex(c));
                // `phsAHar(9).cVal` names a *component of an array element*,
                // which MMS reaches by alternate access below the array
                // variable. The name stops at the array.
                if (std.mem.indexOfScalar(u8, c, '(') != null) return out[0..w];
            }
        }
        return out[0..w];
    }
};

/// Strips an SCL array index: `phsAHar(7)` → `phsAHar`.
fn stripIndex(component: []const u8) []const u8 {
    const paren = std.mem.indexOfScalar(u8, component, '(') orelse return component;
    return component[0..paren];
}

pub const DataSet = struct {
    name: []const u8,
    desc: []const u8 = "",
    fcdas: []const Fcda = &.{},
};

pub const TrgOps = struct {
    dchg: bool = false,
    qchg: bool = false,
    dupd: bool = false,
    period: bool = false,
    gi: bool = true,
};

pub const OptFields = struct {
    seq_num: bool = false,
    time_stamp: bool = false,
    data_set: bool = false,
    reason_code: bool = false,
    data_ref: bool = false,
    entry_id: bool = false,
    config_ref: bool = false,
    /// **Defaults to true**, unlike every other flag here. IEC 61850-6 gives
    /// `bufOvfl` a schema default of `"true"`, so a `<OptFields>` that does not
    /// mention it still asks for the buffer-overflow field — which is why a
    /// parser that defaults it to false quietly produces a different RCB from
    /// every other tool reading the same file.
    buf_ovfl: bool = true,
    segmentation: bool = false,
};

pub const ReportControl = struct {
    name: []const u8,
    rpt_id: []const u8 = "",
    dat_set: []const u8 = "",
    conf_rev: u32 = 1,
    buffered: bool = false,
    intg_pd: u32 = 0,
    buf_time: u32 = 0,
    indexed: bool = true,
    /// `<RptEnabled max="N"/>` — how many *instances* of the control block the
    /// IED exposes. Each becomes its own MMS name, suffixed `01`, `02`, …
    max_instances: u8 = 1,
    trg_ops: TrgOps = .{},
    opt_fields: OptFields = .{},
};

/// A `<LogControl>` — the log control block that decides what goes into a log.
pub const LogControl = struct {
    name: []const u8,
    dat_set: []const u8 = "",
    log_name: []const u8 = "",
    log_ena: bool = true,
    intg_pd: u32 = 0,
    reason_code: bool = false,
    trg_ops: TrgOps = .{},
};

/// A `<SettingControl>` — the setting-group control block. There is at most one
/// per logical device and it is always called `SGCB`.
pub const SettingControl = struct {
    num_of_sgs: u8 = 1,
    act_sg: u8 = 1,
    desc: []const u8 = "",
};

pub const GseControl = struct {
    name: []const u8,
    app_id: []const u8 = "",
    dat_set: []const u8 = "",
    conf_rev: u32 = 1,
    /// `GOOSE` or `GSSE`.
    type: []const u8 = "GOOSE",
    fixed_offs: bool = false,
};

/// One `<DAI>` (or a `<DAI>` nested under `<SDI>`s): an instance value that
/// overrides the template default. `path` is the `.`-separated attribute path
/// below the data object, e.g. `"ctlModel"` or `"origin.orCat"`.
pub const Dai = struct {
    path: []const u8,
    values: []const []const u8 = &.{},

    pub fn first(self: Dai) ?[]const u8 {
        return if (self.values.len > 0) self.values[0] else null;
    }
};

pub const Doi = struct {
    name: []const u8,
    desc: []const u8 = "",
    dais: []const Dai = &.{},
};

pub const Ln = struct {
    prefix: []const u8 = "",
    ln_class: []const u8,
    inst: []const u8 = "",
    ln_type: []const u8,
    /// `<LN0>` rather than `<LN>` — the one that owns the data sets and the
    /// control blocks.
    is_ln0: bool = false,
    dois: []const Doi = &.{},
    data_sets: []const DataSet = &.{},
    report_controls: []const ReportControl = &.{},
    gse_controls: []const GseControl = &.{},
    log_controls: []const LogControl = &.{},
    /// At most one per logical device, on `LN0`.
    setting_control: ?SettingControl = null,

    /// The MMS name of this logical node: prefix + class + instance.
    pub fn mmsName(self: Ln, out: []u8) Error![]const u8 {
        var w: usize = 0;
        w += try put(out, w, self.prefix);
        w += try put(out, w, self.ln_class);
        w += try put(out, w, self.inst);
        return out[0..w];
    }
};

pub const LDevice = struct {
    inst: []const u8,
    /// Edition 2's explicit `ldName`, when the file gives one. Otherwise the
    /// MMS domain is `<IED name><LDevice inst>`.
    ld_name: []const u8 = "",
    lns: []const Ln = &.{},

    /// The MMS domain this logical device is served under.
    pub fn domain(self: LDevice, ied_name: []const u8, out: []u8) Error![]const u8 {
        if (self.ld_name.len > 0) {
            const n = self.ld_name.len;
            if (out.len < n) return error.NameTooLong;
            @memcpy(out[0..n], self.ld_name);
            return out[0..n];
        }
        var w: usize = 0;
        w += try put(out, w, ied_name);
        w += try put(out, w, self.inst);
        return out[0..w];
    }
};

pub const AccessPoint = struct {
    name: []const u8,
    devices: []const LDevice = &.{},
};

pub const Ied = struct {
    name: []const u8,
    type: []const u8 = "",
    manufacturer: []const u8 = "",
    config_version: []const u8 = "",
    access_points: []const AccessPoint = &.{},
};

// ── data type templates ─────────────────────────────────────────────────────

pub const DoRef = struct {
    name: []const u8,
    type: []const u8,
    transient: bool = false,
};

pub const LNodeType = struct {
    id: []const u8,
    ln_class: []const u8 = "",
    dos: []const DoRef = &.{},
};

/// A `DA` of a `DOType` or a `BDA` of a `DAType`. A `BDA` has no `fc` — it
/// inherits the one on the `DA` above it, which is why `fc` is optional.
pub const DaRef = struct {
    name: []const u8,
    fc: ?Fc = null,
    b_type: BType,
    /// The `DAType` (for `bType="Struct"`) or the `EnumType` (`bType="Enum"`).
    type: []const u8 = "",
    dchg: bool = false,
    qchg: bool = false,
    dupd: bool = false,
    count: u32 = 0,
    /// A template default value.
    val: ?[]const u8 = null,
};

/// A `SDO` — a data object nested inside a data object.
pub const SdoRef = struct {
    name: []const u8,
    type: []const u8,
    /// Non-zero for an **array** of sub-data-objects. An array is one MMS name:
    /// its elements are addressed with the alternate-access sub-specification,
    /// not with further `$` components, so the resolver stops here.
    count: u32 = 0,
};

pub const DoType = struct {
    id: []const u8,
    cdc: []const u8 = "",
    das: []const DaRef = &.{},
    sdos: []const SdoRef = &.{},
};

pub const DaType = struct {
    id: []const u8,
    bdas: []const DaRef = &.{},
};

pub const EnumVal = struct {
    ord: i32,
    text: []const u8,
};

pub const EnumType = struct {
    id: []const u8,
    vals: []const EnumVal = &.{},

    pub fn ordOf(self: EnumType, text: []const u8) ?i32 {
        for (self.vals) |v| {
            if (std.mem.eql(u8, v.text, text)) return v.ord;
        }
        return null;
    }
};

pub const Templates = struct {
    ln_types: []const LNodeType = &.{},
    do_types: []const DoType = &.{},
    da_types: []const DaType = &.{},
    enum_types: []const EnumType = &.{},

    pub fn lnType(self: Templates, id: []const u8) ?*const LNodeType {
        for (self.ln_types) |*t| {
            if (std.mem.eql(u8, t.id, id)) return t;
        }
        return null;
    }
    pub fn doType(self: Templates, id: []const u8) ?*const DoType {
        for (self.do_types) |*t| {
            if (std.mem.eql(u8, t.id, id)) return t;
        }
        return null;
    }
    pub fn daType(self: Templates, id: []const u8) ?*const DaType {
        for (self.da_types) |*t| {
            if (std.mem.eql(u8, t.id, id)) return t;
        }
        return null;
    }
    pub fn enumType(self: Templates, id: []const u8) ?*const EnumType {
        for (self.enum_types) |*t| {
            if (std.mem.eql(u8, t.id, id)) return t;
        }
        return null;
    }
};

// ── the parsed document ─────────────────────────────────────────────────────

/// What kind of SCL document this is. SCL carries no declaration of its own
/// type — the *file extension* does — so this is a **heuristic** and says so:
/// an `.scd` has a substation section and usually several IEDs, an `.icd` is
/// one IED with templates and no addresses, a `.cid` is one IED with its
/// communication parameters filled in.
pub const Kind = enum { scd, icd, cid, unknown };

pub const Scl = struct {
    arena: std.heap.ArenaAllocator,
    doc: xml.Document,
    header: Header,
    subnetworks: []const Subnetwork,
    ieds: []const Ied,
    templates: Templates,
    has_substation: bool,
    options: Options,

    pub fn deinit(self: *Scl) void {
        self.doc.deinit();
        self.arena.deinit();
    }

    pub fn ied(self: *const Scl, name: []const u8) ?*const Ied {
        for (self.ieds) |*i| {
            if (std.mem.eql(u8, i.name, name)) return i;
        }
        return null;
    }

    pub fn kind(self: *const Scl) Kind {
        if (self.has_substation and self.ieds.len >= 1) return .scd;
        if (self.ieds.len != 1) return .unknown;
        // A configured IED has its addresses filled in; a template does not.
        for (self.subnetworks) |s| {
            for (s.aps) |ap| {
                if (ap.address.ip()) |v| {
                    if (v.len > 0) return .cid;
                }
                if (ap.gse.len > 0 or ap.smv.len > 0) return .cid;
            }
        }
        return .icd;
    }

    /// The `<GSE>`/`<SMV>` address a control block publishes on, looked up the
    /// way the standard scopes it: by IED name, logical-device instance and
    /// control-block name, across every subnetwork.
    pub fn cbAddress(
        self: *const Scl,
        ied_name: []const u8,
        ld_inst: []const u8,
        cb_name: []const u8,
    ) ?*const CbAddress {
        for (self.subnetworks) |s| {
            for (s.aps) |ap| {
                if (!std.mem.eql(u8, ap.ied_name, ied_name)) continue;
                for (ap.gse) |*g| {
                    if (std.mem.eql(u8, g.ld_inst, ld_inst) and std.mem.eql(u8, g.cb_name, cb_name)) return g;
                }
                for (ap.smv) |*g| {
                    if (std.mem.eql(u8, g.ld_inst, ld_inst) and std.mem.eql(u8, g.cb_name, cb_name)) return g;
                }
            }
        }
        return null;
    }
};

pub const Options = struct {
    /// Defaults differ from `xml`'s own in exactly one way: SCL's `id`
    /// attribute is a **type identifier**, not an XML ID, and the same value
    /// legitimately appears on an `LNodeType` and on nothing else — but
    /// `Header id` and `LNode` references collide with it often enough that
    /// treating `id` as an XML ID makes real files fail with `DuplicateId`.
    xml: xml.Options = .{ .id_attr_names = &.{} },
    /// The MMS attribute names of a **buffered** report control block. This is
    /// a knob because implementations disagree: IEC 61850-8-1 spells the
    /// timestamp `TimeOfEntry`, and at least one widely deployed stack spells
    /// it `TimeofEntry`. Matching a specific IED's name space needs its
    /// spelling, so the caller can supply it.
    brcb_attributes: []const []const u8 = &default_brcb_attributes,
    /// The MMS attribute names of the setting-group control block. Edition 2
    /// adds `ResvTms` (multi-client edit reservation) and plenty of IEDs do not
    /// expose it, so the mandatory five are the default.
    sgcb_attributes: []const []const u8 = &default_sgcb_attributes,
    /// Accept a `bType` outside the standard list rather than refusing the
    /// document. Vendor extensions do exist; the default is strict.
    allow_unknown_btype: bool = false,
    /// Check every `Val`/`DAI` against its `bType`. A file that says a
    /// `BOOLEAN` is `"maybe"` is a configuration error that will surface as a
    /// runtime type mismatch, so it is caught here by default.
    check_values: bool = true,
};

// ── resolution ──────────────────────────────────────────────────────────────

/// One resolved node of the object model. Every name a `GetNameList` returns
/// for the configured IED appears here exactly once, at every level: the
/// logical node, each functional constraint below it, each data object, and
/// each attribute and sub-attribute.
pub const Node = struct {
    /// MMS domain, e.g. `simpleIOGenericIO`.
    domain: []const u8,
    /// MMS item id, e.g. `GGIO1$CO$SPCSO4$SBOw$origin$orCat`.
    item: []const u8,
    /// Null on the bare logical-node name.
    fc: ?Fc = null,
    /// Null on the logical-node and functional-constraint levels.
    b_type: ?BType = null,
    /// 0 = logical node, 1 = functional constraint, 2 = data object, 3+ = a
    /// data attribute and below.
    depth: u8,
    /// True when nothing hangs below this name — the values a client reads.
    leaf: bool,
    /// The configured or default value, when the file supplies one.
    value: ?[]const u8 = null,
    /// For `bType="Enum"`, the enumeration this attribute takes values from.
    enum_type: []const u8 = "",
};

pub const Model = struct {
    arena: std.heap.ArenaAllocator,
    ied_name: []const u8,
    nodes: []const Node,

    pub fn deinit(self: *Model) void {
        self.arena.deinit();
    }

    pub fn find(self: *const Model, domain: []const u8, item: []const u8) ?*const Node {
        for (self.nodes) |*n| {
            if (std.mem.eql(u8, n.domain, domain) and std.mem.eql(u8, n.item, item)) return n;
        }
        return null;
    }

    pub fn has(self: *const Model, domain: []const u8, item: []const u8) bool {
        return self.find(domain, item) != null;
    }

    pub fn leafCount(self: *const Model) usize {
        var n: usize = 0;
        for (self.nodes) |x| {
            if (x.leaf) n += 1;
        }
        return n;
    }

    /// The `ctlModel` of a control object, read out of the resolved model —
    /// which is what lets a client pick the right control state machine without
    /// a round trip to the IED.
    pub fn ctlModel(self: *const Model, domain: []const u8, item_prefix: []const u8) ?control.CtlModel {
        var buf: [acsi.max_reference_len]u8 = undefined;
        // `GGIO1$CO$SPCSO4` → `GGIO1$CF$SPCSO4$ctlModel`.
        const dollar = std.mem.indexOfScalar(u8, item_prefix, '$') orelse return null;
        const rest = std.mem.indexOfScalarPos(u8, item_prefix, dollar + 1, '$') orelse return null;
        const name = std.fmt.bufPrint(&buf, "{s}$CF{s}$ctlModel", .{
            item_prefix[0..dollar],
            item_prefix[rest..],
        }) catch return null;
        const n = self.find(domain, name) orelse return null;
        const v = n.value orelse return null;
        return control.CtlModel.parseScl(v) catch null;
    }
};

// ── parsing ─────────────────────────────────────────────────────────────────

/// Parses an SCL document (`.scd`, `.icd`, `.cid` or `.iid`). `source` must
/// outlive the returned `Scl`: every string points into it or into the arena.
pub fn parse(gpa: std.mem.Allocator, source: []const u8, options: Options) Error!Scl {
    var doc = try xml.parse(gpa, source, options.xml);
    errdefer doc.deinit();
    if (!std.mem.eql(u8, doc.root.local, "SCL")) return error.NotScl;

    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    var p = Parser{ .a = a, .options = options };

    var header = Header{};
    var subnetworks: std.ArrayList(Subnetwork) = .empty;
    var ieds: std.ArrayList(Ied) = .empty;
    var templates = Templates{};
    var has_substation = false;

    var it = doc.root.elementIterator();
    while (it.next()) |el| {
        if (std.mem.eql(u8, el.local, "Header")) {
            header = .{
                .id = attrOr(el, "id", ""),
                .version = attrOr(el, "version", ""),
                .revision = attrOr(el, "revision", ""),
                .tool_id = attrOr(el, "toolID", ""),
                .name_structure = attrOr(el, "nameStructure", ""),
            };
        } else if (std.mem.eql(u8, el.local, "Substation")) {
            has_substation = true;
        } else if (std.mem.eql(u8, el.local, "Communication")) {
            try p.communication(el, &subnetworks);
        } else if (std.mem.eql(u8, el.local, "IED")) {
            try ieds.append(a, try p.ied(el));
        } else if (std.mem.eql(u8, el.local, "DataTypeTemplates")) {
            templates = try p.dataTypeTemplates(el);
        }
    }

    return .{
        .arena = arena,
        .doc = doc,
        .header = header,
        .subnetworks = try subnetworks.toOwnedSlice(a),
        .ieds = try ieds.toOwnedSlice(a),
        .templates = templates,
        .has_substation = has_substation,
        .options = options,
    };
}

const Parser = struct {
    a: std.mem.Allocator,
    options: Options,

    fn communication(self: *Parser, el: *xml.Element, out: *std.ArrayList(Subnetwork)) Error!void {
        var it = el.elementIterator();
        while (it.next()) |sub| {
            if (!std.mem.eql(u8, sub.local, "SubNetwork")) continue;
            var aps: std.ArrayList(ConnectedAp) = .empty;
            var ap_it = sub.elementIterator();
            while (ap_it.next()) |ap| {
                if (!std.mem.eql(u8, ap.local, "ConnectedAP")) continue;
                var gse: std.ArrayList(CbAddress) = .empty;
                var smv: std.ArrayList(CbAddress) = .empty;
                var addr = Address{};
                var c = ap.elementIterator();
                while (c.next()) |child| {
                    if (std.mem.eql(u8, child.local, "Address")) {
                        addr = try self.address(child);
                    } else if (std.mem.eql(u8, child.local, "GSE")) {
                        try gse.append(self.a, try self.cbAddress(child));
                    } else if (std.mem.eql(u8, child.local, "SMV")) {
                        try smv.append(self.a, try self.cbAddress(child));
                    }
                }
                try aps.append(self.a, .{
                    .ied_name = attrOr(ap, "iedName", ""),
                    .ap_name = attrOr(ap, "apName", ""),
                    .address = addr,
                    .gse = try gse.toOwnedSlice(self.a),
                    .smv = try smv.toOwnedSlice(self.a),
                });
            }
            try out.append(self.a, .{
                .name = attrOr(sub, "name", ""),
                .type = attrOr(sub, "type", ""),
                .aps = try aps.toOwnedSlice(self.a),
            });
        }
    }

    fn address(self: *Parser, el: *xml.Element) Error!Address {
        var params: std.ArrayList(Param) = .empty;
        var it = el.elementIterator();
        while (it.next()) |p| {
            if (!std.mem.eql(u8, p.local, "P")) continue;
            try params.append(self.a, .{
                .type = attrOr(p, "type", ""),
                .value = std.mem.trim(u8, try p.textContent(self.a), " \t\r\n"),
            });
        }
        return .{ .params = try params.toOwnedSlice(self.a) };
    }

    fn cbAddress(self: *Parser, el: *xml.Element) Error!CbAddress {
        var out = CbAddress{
            .ld_inst = attrOr(el, "ldInst", ""),
            .cb_name = attrOr(el, "cbName", ""),
        };
        var it = el.elementIterator();
        while (it.next()) |c| {
            if (std.mem.eql(u8, c.local, "Address")) {
                out.address = try self.address(c);
            } else if (std.mem.eql(u8, c.local, "MinTime")) {
                out.min_time_ms = try self.uintText(c);
            } else if (std.mem.eql(u8, c.local, "MaxTime")) {
                out.max_time_ms = try self.uintText(c);
            }
        }
        return out;
    }

    fn uintText(self: *Parser, el: *xml.Element) Error!?u32 {
        const t = std.mem.trim(u8, try el.textContent(self.a), " \t\r\n");
        return std.fmt.parseInt(u32, t, 10) catch null;
    }

    fn ied(self: *Parser, el: *xml.Element) Error!Ied {
        var aps: std.ArrayList(AccessPoint) = .empty;
        var it = el.elementIterator();
        while (it.next()) |ap| {
            if (!std.mem.eql(u8, ap.local, "AccessPoint")) continue;
            var devices: std.ArrayList(LDevice) = .empty;
            var s = ap.elementIterator();
            while (s.next()) |server| {
                if (!std.mem.eql(u8, server.local, "Server")) continue;
                var d = server.elementIterator();
                while (d.next()) |ld| {
                    if (!std.mem.eql(u8, ld.local, "LDevice")) continue;
                    try devices.append(self.a, try self.lDevice(ld));
                }
            }
            try aps.append(self.a, .{
                .name = attrOr(ap, "name", ""),
                .devices = try devices.toOwnedSlice(self.a),
            });
        }
        return .{
            .name = el.attr("", "name") orelse return error.MissingAttribute,
            .type = attrOr(el, "type", ""),
            .manufacturer = attrOr(el, "manufacturer", ""),
            .config_version = attrOr(el, "configVersion", ""),
            .access_points = try aps.toOwnedSlice(self.a),
        };
    }

    fn lDevice(self: *Parser, el: *xml.Element) Error!LDevice {
        var lns: std.ArrayList(Ln) = .empty;
        var it = el.elementIterator();
        while (it.next()) |el_ln| {
            const is_ln0 = std.mem.eql(u8, el_ln.local, "LN0");
            if (!is_ln0 and !std.mem.eql(u8, el_ln.local, "LN")) continue;
            try lns.append(self.a, try self.ln(el_ln, is_ln0));
        }
        return .{
            .inst = el.attr("", "inst") orelse return error.MissingAttribute,
            .ld_name = attrOr(el, "ldName", ""),
            .lns = try lns.toOwnedSlice(self.a),
        };
    }

    fn ln(self: *Parser, el: *xml.Element, is_ln0: bool) Error!Ln {
        var dois: std.ArrayList(Doi) = .empty;
        var sets: std.ArrayList(DataSet) = .empty;
        var rcbs: std.ArrayList(ReportControl) = .empty;
        var gcbs: std.ArrayList(GseControl) = .empty;
        var lcbs: std.ArrayList(LogControl) = .empty;
        var sgcb: ?SettingControl = null;

        var it = el.elementIterator();
        while (it.next()) |c| {
            if (std.mem.eql(u8, c.local, "DOI")) {
                try dois.append(self.a, try self.doi(c));
            } else if (std.mem.eql(u8, c.local, "DataSet")) {
                try sets.append(self.a, try self.dataSet(c));
            } else if (std.mem.eql(u8, c.local, "ReportControl")) {
                try rcbs.append(self.a, try self.reportControl(c));
            } else if (std.mem.eql(u8, c.local, "LogControl")) {
                var lcb = LogControl{
                    .name = c.attr("", "name") orelse return error.MissingAttribute,
                    .dat_set = attrOr(c, "datSet", ""),
                    .log_name = attrOr(c, "logName", ""),
                    .log_ena = boolAttr(c, "logEna", true),
                    .intg_pd = parseU32(attrOr(c, "intgPd", "0")) orelse 0,
                    .reason_code = boolAttr(c, "reasonCode", false),
                };
                var t = c.elementIterator();
                while (t.next()) |tc| {
                    if (!std.mem.eql(u8, tc.local, "TrgOps")) continue;
                    lcb.trg_ops = .{
                        .dchg = boolAttr(tc, "dchg", false),
                        .qchg = boolAttr(tc, "qchg", false),
                        .dupd = boolAttr(tc, "dupd", false),
                        .period = boolAttr(tc, "period", false),
                        .gi = boolAttr(tc, "gi", true),
                    };
                }
                try lcbs.append(self.a, lcb);
            } else if (std.mem.eql(u8, c.local, "SettingControl")) {
                sgcb = .{
                    .num_of_sgs = @intCast(@min(parseU32(attrOr(c, "numOfSGs", "1")) orelse 1, 255)),
                    .act_sg = @intCast(@min(parseU32(attrOr(c, "actSG", "1")) orelse 1, 255)),
                    .desc = attrOr(c, "desc", ""),
                };
            } else if (std.mem.eql(u8, c.local, "GSEControl")) {
                try gcbs.append(self.a, .{
                    .name = c.attr("", "name") orelse return error.MissingAttribute,
                    .app_id = attrOr(c, "appID", ""),
                    .dat_set = attrOr(c, "datSet", ""),
                    .conf_rev = parseU32(attrOr(c, "confRev", "1")) orelse 1,
                    .type = attrOr(c, "type", "GOOSE"),
                    .fixed_offs = boolAttr(c, "fixedOffs", false),
                });
            }
        }
        return .{
            .prefix = attrOr(el, "prefix", ""),
            .ln_class = el.attr("", "lnClass") orelse return error.MissingAttribute,
            .inst = attrOr(el, "inst", ""),
            .ln_type = el.attr("", "lnType") orelse return error.MissingAttribute,
            .is_ln0 = is_ln0,
            .dois = try dois.toOwnedSlice(self.a),
            .data_sets = try sets.toOwnedSlice(self.a),
            .report_controls = try rcbs.toOwnedSlice(self.a),
            .gse_controls = try gcbs.toOwnedSlice(self.a),
            .log_controls = try lcbs.toOwnedSlice(self.a),
            .setting_control = sgcb,
        };
    }

    fn dataSet(self: *Parser, el: *xml.Element) Error!DataSet {
        var fcdas: std.ArrayList(Fcda) = .empty;
        var it = el.elementIterator();
        while (it.next()) |f| {
            if (!std.mem.eql(u8, f.local, "FCDA")) continue;
            try fcdas.append(self.a, .{
                .ld_inst = attrOr(f, "ldInst", ""),
                .prefix = attrOr(f, "prefix", ""),
                .ln_class = f.attr("", "lnClass") orelse return error.MissingAttribute,
                .ln_inst = attrOr(f, "lnInst", ""),
                .do_name = f.attr("", "doName") orelse return error.MissingAttribute,
                .da_name = attrOr(f, "daName", ""),
                .fc = try Fc.parse(f.attr("", "fc") orelse return error.MissingAttribute),
            });
        }
        return .{
            .name = el.attr("", "name") orelse return error.MissingAttribute,
            .desc = attrOr(el, "desc", ""),
            .fcdas = try fcdas.toOwnedSlice(self.a),
        };
    }

    fn reportControl(self: *Parser, el: *xml.Element) Error!ReportControl {
        _ = self;
        var out = ReportControl{
            .name = el.attr("", "name") orelse return error.MissingAttribute,
            .rpt_id = attrOr(el, "rptID", ""),
            .dat_set = attrOr(el, "datSet", ""),
            .conf_rev = parseU32(attrOr(el, "confRev", "1")) orelse 1,
            .buffered = boolAttr(el, "buffered", false),
            .intg_pd = parseU32(attrOr(el, "intgPd", "0")) orelse 0,
            .buf_time = parseU32(attrOr(el, "bufTime", "0")) orelse 0,
            .indexed = boolAttr(el, "indexed", true),
        };
        var it = el.elementIterator();
        while (it.next()) |c| {
            if (std.mem.eql(u8, c.local, "TrgOps")) {
                out.trg_ops = .{
                    .dchg = boolAttr(c, "dchg", false),
                    .qchg = boolAttr(c, "qchg", false),
                    .dupd = boolAttr(c, "dupd", false),
                    .period = boolAttr(c, "period", false),
                    .gi = boolAttr(c, "gi", true),
                };
            } else if (std.mem.eql(u8, c.local, "OptFields")) {
                out.opt_fields = .{
                    .seq_num = boolAttr(c, "seqNum", false),
                    .time_stamp = boolAttr(c, "timeStamp", false),
                    .data_set = boolAttr(c, "dataSet", false),
                    .reason_code = boolAttr(c, "reasonCode", false),
                    .data_ref = boolAttr(c, "dataRef", false),
                    .entry_id = boolAttr(c, "entryID", false),
                    .config_ref = boolAttr(c, "configRef", false),
                    .buf_ovfl = boolAttr(c, "bufOvfl", true),
                    .segmentation = boolAttr(c, "segmentation", false),
                };
            } else if (std.mem.eql(u8, c.local, "RptEnabled")) {
                const m = parseU32(attrOr(c, "max", "1")) orelse 1;
                out.max_instances = @intCast(@min(m, 99));
            }
        }
        if (out.max_instances == 0) out.max_instances = 1;
        return out;
    }

    fn doi(self: *Parser, el: *xml.Element) Error!Doi {
        var dais: std.ArrayList(Dai) = .empty;
        try self.collectDais(el, "", &dais);
        return .{
            .name = el.attr("", "name") orelse return error.MissingAttribute,
            .desc = attrOr(el, "desc", ""),
            .dais = try dais.toOwnedSlice(self.a),
        };
    }

    /// `<SDI>` nests arbitrarily; the path is accumulated with `.` separators so
    /// a `DAI` under `<SDI name="origin">` becomes `origin.orCat`.
    fn collectDais(self: *Parser, el: *xml.Element, prefix: []const u8, out: *std.ArrayList(Dai)) Error!void {
        var it = el.elementIterator();
        while (it.next()) |c| {
            const name = c.attr("", "name") orelse continue;
            const path = if (prefix.len == 0)
                name
            else
                try std.fmt.allocPrint(self.a, "{s}.{s}", .{ prefix, name });
            if (std.mem.eql(u8, c.local, "SDI")) {
                try self.collectDais(c, path, out);
            } else if (std.mem.eql(u8, c.local, "DAI")) {
                var values: std.ArrayList([]const u8) = .empty;
                var v = c.elementIterator();
                while (v.next()) |val| {
                    if (!std.mem.eql(u8, val.local, "Val")) continue;
                    try values.append(self.a, std.mem.trim(u8, try val.textContent(self.a), " \t\r\n"));
                }
                try out.append(self.a, .{ .path = path, .values = try values.toOwnedSlice(self.a) });
            }
        }
    }

    fn dataTypeTemplates(self: *Parser, el: *xml.Element) Error!Templates {
        var ln_types: std.ArrayList(LNodeType) = .empty;
        var do_types: std.ArrayList(DoType) = .empty;
        var da_types: std.ArrayList(DaType) = .empty;
        var enum_types: std.ArrayList(EnumType) = .empty;

        var it = el.elementIterator();
        while (it.next()) |t| {
            if (std.mem.eql(u8, t.local, "LNodeType")) {
                var dos: std.ArrayList(DoRef) = .empty;
                var d = t.elementIterator();
                while (d.next()) |do_el| {
                    if (!std.mem.eql(u8, do_el.local, "DO")) continue;
                    try dos.append(self.a, .{
                        .name = do_el.attr("", "name") orelse return error.MissingAttribute,
                        .type = do_el.attr("", "type") orelse return error.MissingAttribute,
                        .transient = boolAttr(do_el, "transient", false),
                    });
                }
                try ln_types.append(self.a, .{
                    .id = t.attr("", "id") orelse return error.MissingAttribute,
                    .ln_class = attrOr(t, "lnClass", ""),
                    .dos = try dos.toOwnedSlice(self.a),
                });
            } else if (std.mem.eql(u8, t.local, "DOType")) {
                var das: std.ArrayList(DaRef) = .empty;
                var sdos: std.ArrayList(SdoRef) = .empty;
                var d = t.elementIterator();
                while (d.next()) |c| {
                    if (std.mem.eql(u8, c.local, "DA")) {
                        try das.append(self.a, try self.daRef(c, true));
                    } else if (std.mem.eql(u8, c.local, "SDO")) {
                        try sdos.append(self.a, .{
                            .name = c.attr("", "name") orelse return error.MissingAttribute,
                            .type = c.attr("", "type") orelse return error.MissingAttribute,
                            .count = parseU32(attrOr(c, "count", "0")) orelse 0,
                        });
                    }
                }
                try do_types.append(self.a, .{
                    .id = t.attr("", "id") orelse return error.MissingAttribute,
                    .cdc = attrOr(t, "cdc", ""),
                    .das = try das.toOwnedSlice(self.a),
                    .sdos = try sdos.toOwnedSlice(self.a),
                });
            } else if (std.mem.eql(u8, t.local, "DAType")) {
                var bdas: std.ArrayList(DaRef) = .empty;
                var d = t.elementIterator();
                while (d.next()) |c| {
                    if (!std.mem.eql(u8, c.local, "BDA")) continue;
                    try bdas.append(self.a, try self.daRef(c, false));
                }
                try da_types.append(self.a, .{
                    .id = t.attr("", "id") orelse return error.MissingAttribute,
                    .bdas = try bdas.toOwnedSlice(self.a),
                });
            } else if (std.mem.eql(u8, t.local, "EnumType")) {
                var vals: std.ArrayList(EnumVal) = .empty;
                var d = t.elementIterator();
                while (d.next()) |c| {
                    if (!std.mem.eql(u8, c.local, "EnumVal")) continue;
                    const ord = std.fmt.parseInt(i32, attrOr(c, "ord", "0"), 10) catch 0;
                    try vals.append(self.a, .{
                        .ord = ord,
                        .text = std.mem.trim(u8, try c.textContent(self.a), " \t\r\n"),
                    });
                }
                try enum_types.append(self.a, .{
                    .id = t.attr("", "id") orelse return error.MissingAttribute,
                    .vals = try vals.toOwnedSlice(self.a),
                });
            }
        }
        return .{
            .ln_types = try ln_types.toOwnedSlice(self.a),
            .do_types = try do_types.toOwnedSlice(self.a),
            .da_types = try da_types.toOwnedSlice(self.a),
            .enum_types = try enum_types.toOwnedSlice(self.a),
        };
    }

    fn daRef(self: *Parser, el: *xml.Element, want_fc: bool) Error!DaRef {
        const b_type_text = el.attr("", "bType") orelse return error.MissingAttribute;
        const b_type = BType.parse(b_type_text) catch |e| blk: {
            if (self.options.allow_unknown_btype) break :blk BType.unknown;
            return e;
        };
        var val: ?[]const u8 = null;
        var it = el.elementIterator();
        while (it.next()) |c| {
            if (!std.mem.eql(u8, c.local, "Val")) continue;
            val = std.mem.trim(u8, try c.textContent(self.a), " \t\r\n");
            break;
        }
        return .{
            .name = el.attr("", "name") orelse return error.MissingAttribute,
            .fc = if (want_fc)
                try Fc.parse(el.attr("", "fc") orelse return error.MissingAttribute)
            else
                null,
            .b_type = b_type,
            .type = attrOr(el, "type", ""),
            .dchg = boolAttr(el, "dchg", false),
            .qchg = boolAttr(el, "qchg", false),
            .dupd = boolAttr(el, "dupd", false),
            .count = parseU32(attrOr(el, "count", "0")) orelse 0,
            .val = val,
        };
    }
};

fn attrOr(el: *xml.Element, name: []const u8, default: []const u8) []const u8 {
    return el.attr("", name) orelse default;
}

fn boolAttr(el: *xml.Element, name: []const u8, default: bool) bool {
    const v = el.attr("", name) orelse return default;
    if (std.mem.eql(u8, v, "true") or std.mem.eql(u8, v, "1")) return true;
    if (std.mem.eql(u8, v, "false") or std.mem.eql(u8, v, "0")) return false;
    return default;
}

fn parseU32(s: []const u8) ?u32 {
    return std.fmt.parseInt(u32, s, 10) catch null;
}

fn put(out: []u8, at: usize, s: []const u8) Error!usize {
    if (out.len < at + s.len) return error.NameTooLong;
    @memcpy(out[at..][0..s.len], s);
    return s.len;
}

/// The `gocbRef` a GOOSE publisher configured from this file puts on the wire:
/// `<domain>/<LN>$GO$<control block>`. A subscriber matches on this string, so
/// getting it out of the SCL rather than hand-writing it is the difference
/// between a subscriber that binds and one that silently never fires.
pub fn controlBlockRef(
    domain: []const u8,
    ln_name: []const u8,
    fc: Fc,
    cb_name: []const u8,
    out: []u8,
) Error![]const u8 {
    var w: usize = 0;
    w += try put(out, w, domain);
    w += try put(out, w, "/");
    w += try put(out, w, ln_name);
    w += try put(out, w, "$");
    w += try put(out, w, fc.name());
    w += try put(out, w, "$");
    w += try put(out, w, cb_name);
    return out[0..w];
}

/// The `datSet` reference a GOOSE PDU carries: `<domain>/<LN>$<data set>`.
/// Note there is **no functional constraint** in it — a data set is a plain
/// named variable list, which is why `acsi.parseMms` refuses this string.
pub fn dataSetRef(
    domain: []const u8,
    ln_name: []const u8,
    ds_name: []const u8,
    out: []u8,
) Error![]const u8 {
    var w: usize = 0;
    w += try put(out, w, domain);
    w += try put(out, w, "/");
    w += try put(out, w, ln_name);
    w += try put(out, w, "$");
    w += try put(out, w, ds_name);
    return out[0..w];
}

// ── the resolver ────────────────────────────────────────────────────────────

/// The eleven attributes of an **unbuffered** report control block, in the
/// order IEC 61850-8-1 puts them in the MMS structure — which is the order
/// `report.Rcb.decode` reads them in.
pub const default_urcb_attributes = [_][]const u8{
    "RptID", "RptEna", "Resv",   "DatSet", "ConfRev", "OptFlds",
    "BufTm", "SqNum",  "TrgOps", "IntgPd", "GI",
};

/// A **buffered** report control block. Self-derived from IEC 61850-7-2 §17;
/// the oracle model available here has no BRCB to confirm it against.
pub const default_brcb_attributes = [_][]const u8{
    "RptID",       "RptEna",  "DatSet", "ConfRev", "OptFlds",  "BufTm",
    "SqNum",       "TrgOps",  "IntgPd", "GI",      "PurgeBuf", "EntryID",
    "TimeOfEntry", "ResvTms",
};

/// A GOOSE control block. `DstAddress` is a **structure**, which is why it is
/// listed with its members.
pub const default_gocb_attributes = [_][]const u8{
    "GoEna", "GoID", "DatSet", "ConfRev", "NdsCom", "DstAddress", "MinTime", "MaxTime", "FixedOffs",
};

/// A log control block (IEC 61850-7-2 §16).
pub const default_lcb_attributes = [_][]const u8{
    "LogEna", "LogRef", "DatSet", "OldEntrTm", "NewEntrTm", "OldEntr", "NewEntr", "TrgOps", "IntgPd",
};

/// The setting-group control block (IEC 61850-7-2 §12).
pub const default_sgcb_attributes = [_][]const u8{
    "NumOfSG", "ActSG", "EditSG", "CnfEdit", "LActTm",
};

/// `PhyComAddr` (IEC 61850-7-2) is a **composite** basic type, not a leaf: the
/// MMS mapping expands it into four components. A `DstAddress` of a GOOSE
/// control block is one, and so is any `DA` declared `bType="PhyComAddr"` —
/// the tracking logical nodes of edition 2.1 have several.
pub const phy_com_addr_members = [_][]const u8{ "Addr", "PRIORITY", "VID", "APPID" };

pub const dst_address_members = phy_com_addr_members;

const ResolveCtx = struct {
    a: std.mem.Allocator,
    scl: *const Scl,
    nodes: std.ArrayList(Node),
    domain: []const u8,
    /// The `DAType` ids currently on the resolution path — an explicit cycle
    /// check, because a depth budget alone would let a two-node cycle produce
    /// twelve levels of plausible-looking names before failing.
    path: std.ArrayList([]const u8),
    /// True when the logical device has a setting-group control block. IEC
    /// 61850-7-2 §12 then makes every **editable** setting (`SE`) also visible
    /// as the **active** group's value (`SG`), read-only — so an SCL that
    /// declares only `SE` still yields both halves of the name space. A
    /// resolver that takes the file literally here misses every `SG` name the
    /// IED serves.
    mirror_se_to_sg: bool = false,
};

/// Walks the type graph of one IED and produces every MMS name it serves.
///
/// This is the deliverable: an `.icd` in, the list of
/// `LD/LN$FC$DO$DA`-style references the MMS layer needs out. Cycles and
/// unresolvable references are typed errors, never a hang.
pub fn resolve(scl: *const Scl, gpa: std.mem.Allocator, ied_name: []const u8) Error!Model {
    const target = scl.ied(ied_name) orelse return error.UnresolvedFcda;

    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    var ctx = ResolveCtx{
        .a = a,
        .scl = scl,
        .nodes = .empty,
        .domain = "",
        .path = .empty,
    };

    var domain_buf: [acsi.max_reference_len]u8 = undefined;
    for (target.access_points) |ap| {
        for (ap.devices) |ld| {
            ctx.domain = try a.dupe(u8, try ld.domain(target.name, &domain_buf));
            ctx.mirror_se_to_sg = false;
            for (ld.lns) |logical_node| {
                if (logical_node.setting_control != null) ctx.mirror_se_to_sg = true;
            }
            for (ld.lns) |logical_node| {
                try resolveLn(&ctx, scl, logical_node);
            }
            // Data sets are checked only once every logical node of the device
            // is in the model: an `FCDA` in `LLN0` routinely names a data
            // object of a `GGIO` that appears later in the document.
            for (ld.lns) |logical_node| {
                try checkDataSets(&ctx, ld, logical_node);
            }
        }
    }

    return .{
        .arena = arena,
        .ied_name = target.name,
        .nodes = try ctx.nodes.toOwnedSlice(a),
    };
}

fn checkDataSets(ctx: *ResolveCtx, ld: LDevice, node: Ln) Error!void {
    for (node.data_sets) |ds| {
        for (ds.fcdas) |f| {
            // An FCDA may address another logical device; only the ones that
            // name this device can be checked against what was just resolved.
            if (f.ld_inst.len > 0 and !std.mem.eql(u8, f.ld_inst, ld.inst)) continue;
            var item_buf: [acsi.max_reference_len]u8 = undefined;
            const item = try f.mmsItem(&item_buf);
            if (!hasItem(ctx, item)) return error.UnresolvedFcda;
        }
    }
}

fn resolveLn(ctx: *ResolveCtx, scl: *const Scl, node: Ln) Error!void {
    var name_buf: [acsi.max_reference_len]u8 = undefined;
    const ln_name = try node.mmsName(&name_buf);
    try emit(ctx, ln_name, null, null, 0, false, null, "");

    const ln_type = scl.templates.lnType(node.ln_type) orelse return error.UnresolvedType;

    // Which functional constraints appear anywhere below this logical node?
    // The FC lives on the DA, so this cannot be known without walking the
    // types first.
    var seen = std.EnumSet(Fc).initEmpty();
    for (ln_type.dos) |do_ref| {
        const do_type = scl.templates.doType(do_ref.type) orelse return error.UnresolvedType;
        try collectFcs(scl, do_type, &seen, max_type_depth);
    }
    // The control blocks add their own constraints.
    for (node.report_controls) |rcb| seen.insert(if (rcb.buffered) .BR else .RP);
    for (node.gse_controls) |gcb| {
        seen.insert(if (std.mem.eql(u8, gcb.type, "GSSE")) .GS else .GO);
    }
    if (node.log_controls.len > 0) seen.insert(.LG);
    // The setting-group control block lives under `SP`, which is otherwise the
    // setpoint constraint — one of SCL's less obvious overloads.
    if (node.setting_control != null) seen.insert(.SP);
    if (ctx.mirror_se_to_sg and seen.contains(.SE)) seen.insert(.SG);

    var fc_it = seen.iterator();
    while (fc_it.next()) |fc| {
        var fc_buf: [acsi.max_reference_len]u8 = undefined;
        const fc_name = try join(&fc_buf, ln_name, fc.name());
        try emit(ctx, fc_name, fc, null, 1, false, null, "");

        switch (fc) {
            .RP, .BR => try resolveRcbs(ctx, node, fc_name, fc),
            .GO, .GS => try resolveGocbs(ctx, node, fc_name, fc),
            .LG => try resolveLcbs(ctx, node, fc_name),
            .SP => try resolveSgcb(ctx, node, fc_name),
            else => {},
        }

        for (ln_type.dos) |do_ref| {
            const do_type = scl.templates.doType(do_ref.type) orelse return error.UnresolvedType;
            var below = std.EnumSet(Fc).initEmpty();
            try collectFcs(scl, do_type, &below, max_type_depth);
            if (!contains(&below, fc, ctx.mirror_se_to_sg)) continue;

            var do_buf: [acsi.max_reference_len]u8 = undefined;
            const do_name = try join(&do_buf, fc_name, do_ref.name);
            try emit(ctx, do_name, fc, null, 2, false, null, "");
            try resolveDoType(ctx, scl, do_type, fc, do_name, 3, node, do_ref.name, "");
        }
    }
}

fn resolveRcbs(ctx: *ResolveCtx, node: Ln, fc_name: []const u8, fc: Fc) Error!void {
    const attrs: []const []const u8 = if (fc == .BR)
        ctx.scl.options.brcb_attributes
    else
        &default_urcb_attributes;
    for (node.report_controls) |rcb| {
        const want_buffered = fc == .BR;
        if (rcb.buffered != want_buffered) continue;
        var i: u8 = 1;
        while (i <= rcb.max_instances) : (i += 1) {
            var inst_buf: [acsi.max_reference_len]u8 = undefined;
            // `<RptEnabled max="2"/>` → `…RCB01`, `…RCB02`. An unindexed control
            // block keeps its bare name.
            const inst_name = if (rcb.indexed)
                std.fmt.bufPrint(&inst_buf, "{s}{d:0>2}", .{ rcb.name, i }) catch
                    return error.NameTooLong
            else
                rcb.name;
            var rcb_buf: [acsi.max_reference_len]u8 = undefined;
            const rcb_name = try join(&rcb_buf, fc_name, inst_name);
            try emit(ctx, rcb_name, fc, null, 2, false, null, "");
            for (attrs) |attr| {
                var attr_buf: [acsi.max_reference_len]u8 = undefined;
                const an = try join(&attr_buf, rcb_name, attr);
                try emit(ctx, an, fc, null, 3, true, null, "");
            }
        }
    }
}

fn resolveGocbs(ctx: *ResolveCtx, node: Ln, fc_name: []const u8, fc: Fc) Error!void {
    for (node.gse_controls) |gcb| {
        const is_gsse = std.mem.eql(u8, gcb.type, "GSSE");
        if ((fc == .GS) != is_gsse) continue;
        var gcb_buf: [acsi.max_reference_len]u8 = undefined;
        const gcb_name = try join(&gcb_buf, fc_name, gcb.name);
        try emit(ctx, gcb_name, fc, null, 2, false, null, "");
        for (default_gocb_attributes) |attr| {
            var attr_buf: [acsi.max_reference_len]u8 = undefined;
            const an = try join(&attr_buf, gcb_name, attr);
            const is_struct = std.mem.eql(u8, attr, "DstAddress");
            try emit(ctx, an, fc, null, 3, !is_struct, null, "");
            if (!is_struct) continue;
            for (dst_address_members) |m| {
                var m_buf: [acsi.max_reference_len]u8 = undefined;
                try emit(ctx, try join(&m_buf, an, m), fc, null, 4, true, null, "");
            }
        }
    }
}

fn resolveLcbs(ctx: *ResolveCtx, node: Ln, fc_name: []const u8) Error!void {
    for (node.log_controls) |lcb| {
        var buf: [acsi.max_reference_len]u8 = undefined;
        const name = try join(&buf, fc_name, lcb.name);
        try emit(ctx, name, .LG, null, 2, false, null, "");
        for (default_lcb_attributes) |attr| {
            var abuf: [acsi.max_reference_len]u8 = undefined;
            try emit(ctx, try join(&abuf, name, attr), .LG, null, 3, true, null, "");
        }
    }
}

fn resolveSgcb(ctx: *ResolveCtx, node: Ln, fc_name: []const u8) Error!void {
    if (node.setting_control == null) return;
    var buf: [acsi.max_reference_len]u8 = undefined;
    const name = try join(&buf, fc_name, "SGCB");
    try emit(ctx, name, .SP, null, 2, false, null, "");
    for (ctx.scl.options.sgcb_attributes) |attr| {
        var abuf: [acsi.max_reference_len]u8 = undefined;
        try emit(ctx, try join(&abuf, name, attr), .SP, null, 3, true, null, "");
    }
}

/// Are any of this data object's attributes (or its sub-objects') under `fc`?
fn collectFcs(scl: *const Scl, do_type: *const DoType, out: *std.EnumSet(Fc), budget: u8) Error!void {
    if (budget == 0) return error.TypeTooDeep;
    for (do_type.das) |da| {
        if (da.fc) |fc| out.insert(fc);
    }
    for (do_type.sdos) |sdo| {
        const sub = scl.templates.doType(sdo.type) orelse return error.UnresolvedType;
        try collectFcs(scl, sub, out, budget - 1);
    }
}

/// `SG` also matches an `SE` attribute when the device mirrors setting groups.
fn contains(set: *const std.EnumSet(Fc), fc: Fc, mirror: bool) bool {
    if (set.contains(fc)) return true;
    return mirror and fc == .SG and set.contains(.SE);
}

fn resolveDoType(
    ctx: *ResolveCtx,
    scl: *const Scl,
    do_type: *const DoType,
    fc: Fc,
    parent: []const u8,
    depth: u8,
    node: Ln,
    doi_name: []const u8,
    dai_prefix: []const u8,
) Error!void {
    if (depth > max_type_depth + 3) return error.TypeTooDeep;
    for (do_type.das) |da| {
        if (da.fc != fc) {
            if (!(ctx.mirror_se_to_sg and fc == .SG and da.fc == .SE)) continue;
            // Do not mirror when the file already declares the `SG` half
            // itself, or the name would be emitted twice.
            var declared = false;
            for (do_type.das) |other| {
                if (other.fc == .SG and std.mem.eql(u8, other.name, da.name)) declared = true;
            }
            if (declared) continue;
        }
        var buf: [acsi.max_reference_len]u8 = undefined;
        const name = try join(&buf, parent, da.name);
        try resolveDa(ctx, scl, da, fc, name, depth, node, doi_name, dai_prefix, da.name);
    }
    for (do_type.sdos) |sdo| {
        const sub = scl.templates.doType(sdo.type) orelse return error.UnresolvedType;
        var below = std.EnumSet(Fc).initEmpty();
        try collectFcs(scl, sub, &below, max_type_depth);
        if (!contains(&below, fc, ctx.mirror_se_to_sg)) continue;
        var buf: [acsi.max_reference_len]u8 = undefined;
        const name = try join(&buf, parent, sdo.name);
        if (sdo.count > 0) {
            // An array is a single MMS variable. Its elements are reached with
            // the alternate-access sub-specification (`[5]` in the read
            // request), never with more `$` components — a resolver that
            // flattens `phsAHar[0..15]` into sixteen names invents fifteen
            // objects the IED does not serve.
            try emit(ctx, name, fc, null, depth, true, null, "");
            continue;
        }
        try emit(ctx, name, fc, null, depth, false, null, "");
        var prefix_buf: [acsi.max_reference_len]u8 = undefined;
        const sub_prefix = try joinDots(&prefix_buf, dai_prefix, sdo.name);
        try resolveDoType(ctx, scl, sub, fc, name, depth + 1, node, doi_name, sub_prefix);
    }
}

fn resolveDa(
    ctx: *ResolveCtx,
    scl: *const Scl,
    da: DaRef,
    fc: Fc,
    name: []const u8,
    depth: u8,
    node: Ln,
    doi_name: []const u8,
    dai_prefix: []const u8,
    da_path_tail: []const u8,
) Error!void {
    if (depth > max_type_depth + 3) return error.TypeTooDeep;
    var path_buf: [acsi.max_reference_len]u8 = undefined;
    const dai_path = try joinDots(&path_buf, dai_prefix, da_path_tail);

    if (da.b_type == .PhyComAddr) {
        try emit(ctx, name, fc, .PhyComAddr, depth, false, null, "");
        for (phy_com_addr_members) |m| {
            var mbuf: [acsi.max_reference_len]u8 = undefined;
            try emit(ctx, try join(&mbuf, name, m), fc, null, depth + 1, true, null, "");
        }
        return;
    }
    if (da.count > 0) {
        // Same rule as an array of sub-data-objects: one name, elements by
        // alternate access.
        try emit(ctx, name, fc, da.b_type, depth, true, null, da.type);
        return;
    }
    if (da.b_type == .Struct) {
        const da_type = scl.templates.daType(da.type) orelse return error.UnresolvedType;
        // The explicit on-path check: a DAType that reaches itself would
        // otherwise produce twelve levels of plausible names before the depth
        // budget noticed.
        for (ctx.path.items) |on_path| {
            if (std.mem.eql(u8, on_path, da_type.id)) return error.CyclicType;
        }
        try ctx.path.append(ctx.a, da_type.id);
        defer _ = ctx.path.pop();

        try emit(ctx, name, fc, .Struct, depth, false, null, "");
        for (da_type.bdas) |bda| {
            var buf: [acsi.max_reference_len]u8 = undefined;
            const child = try join(&buf, name, bda.name);
            var child_tail: [acsi.max_reference_len]u8 = undefined;
            const tail = try joinDots(&child_tail, da_path_tail, bda.name);
            try resolveDa(ctx, scl, bda, fc, child, depth + 1, node, doi_name, dai_prefix, tail);
        }
        return;
    }

    // The configured value wins over the template default.
    const value = daiValue(node, doi_name, dai_path) orelse da.val;
    if (value) |v| {
        if (ctx.scl.options.check_values) try checkValue(scl, da, v);
    }
    try emit(ctx, name, fc, da.b_type, depth, true, value, da.type);
}

fn daiValue(node: Ln, doi_name: []const u8, path: []const u8) ?[]const u8 {
    for (node.dois) |d| {
        if (!std.mem.eql(u8, d.name, doi_name)) continue;
        for (d.dais) |dai| {
            if (std.mem.eql(u8, dai.path, path)) return dai.first();
        }
    }
    return null;
}

/// A `Val` must be a value of its `bType`. A `BOOLEAN` that says `"maybe"` and
/// an `INT8U` that says `"400"` are configuration errors that would otherwise
/// only appear as a type mismatch on the wire, long after commissioning.
pub fn checkValue(scl: *const Scl, da: DaRef, text: []const u8) Error!void {
    switch (da.b_type) {
        .BOOLEAN => {
            const ok = std.mem.eql(u8, text, "true") or std.mem.eql(u8, text, "false") or
                std.mem.eql(u8, text, "1") or std.mem.eql(u8, text, "0");
            if (!ok) return error.ValueTypeMismatch;
        },
        .FLOAT32, .FLOAT64 => {
            _ = std.fmt.parseFloat(f64, text) catch return error.ValueTypeMismatch;
        },
        .Enum => {
            if (da.type.len == 0) return;
            const et = scl.templates.enumType(da.type) orelse return error.UnresolvedType;
            if (et.ordOf(text) != null) return;
            // A bare ordinal is also legal.
            const ord = std.fmt.parseInt(i32, text, 10) catch return error.ValueTypeMismatch;
            for (et.vals) |v| {
                if (v.ord == ord) return;
            }
            return error.ValueTypeMismatch;
        },
        .Dbpos => {
            const names = [_][]const u8{ "intermediate-state", "off", "on", "bad-state" };
            for (names) |n| {
                if (std.mem.eql(u8, text, n)) return;
            }
            return error.ValueTypeMismatch;
        },
        .Struct => return error.ValueTypeMismatch,
        else => {
            if (da.b_type.intRange()) |r| {
                const v = std.fmt.parseInt(i64, text, 10) catch return error.ValueTypeMismatch;
                if (v < r.min or v > r.max) return error.ValueTypeMismatch;
                return;
            }
            if (da.b_type.maxLen()) |max| {
                if (text.len > max) return error.ValueTypeMismatch;
            }
        },
    }
}

fn emit(
    ctx: *ResolveCtx,
    item: []const u8,
    fc: ?Fc,
    b_type: ?BType,
    depth: u8,
    leaf: bool,
    value: ?[]const u8,
    enum_type: []const u8,
) Error!void {
    try ctx.nodes.append(ctx.a, .{
        .domain = ctx.domain,
        .item = try ctx.a.dupe(u8, item),
        .fc = fc,
        .b_type = b_type,
        .depth = depth,
        .leaf = leaf,
        .value = value,
        .enum_type = enum_type,
    });
}

fn hasItem(ctx: *const ResolveCtx, item: []const u8) bool {
    for (ctx.nodes.items) |n| {
        if (std.mem.eql(u8, n.item, item)) return true;
    }
    return false;
}

fn join(out: []u8, parent: []const u8, child: []const u8) Error![]const u8 {
    var w: usize = 0;
    w += try put(out, w, parent);
    w += try put(out, w, "$");
    w += try put(out, w, child);
    return out[0..w];
}

fn joinDots(out: []u8, parent: []const u8, child: []const u8) Error![]const u8 {
    if (parent.len == 0) {
        const n = child.len;
        if (out.len < n) return error.NameTooLong;
        @memcpy(out[0..n], child);
        return out[0..n];
    }
    var w: usize = 0;
    w += try put(out, w, parent);
    w += try put(out, w, ".");
    w += try put(out, w, child);
    return out[0..w];
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A small but complete SCL document: two logical nodes, a control object with
/// every SBO attribute, a data set, an unbuffered report control block with two
/// instances, and a GOOSE control block with its address in `Communication`.
pub const sample =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<SCL xmlns="http://www.iec.ch/61850/2003/SCL">
    \\  <Header id="ZIGLIBS" version="1.0.0" revision="A" toolID="zig-libs" nameStructure="IEDName"/>
    \\  <Communication>
    \\    <SubNetwork name="station" type="8-MMS">
    \\      <ConnectedAP iedName="TESTIED" apName="AP1">
    \\        <Address>
    \\          <P type="IP">10.0.0.2</P>
    \\          <P type="IP-SUBNET">255.255.255.0</P>
    \\          <P type="OSI-TSEL">0001</P>
    \\        </Address>
    \\        <GSE ldInst="GenericIO" cbName="gcbEvents">
    \\          <Address>
    \\            <P type="VLAN-ID">100</P>
    \\            <P type="VLAN-PRIORITY">4</P>
    \\            <P type="MAC-Address">01-0c-cd-01-00-01</P>
    \\            <P type="APPID">1000</P>
    \\          </Address>
    \\          <MinTime>10</MinTime>
    \\          <MaxTime>2000</MaxTime>
    \\        </GSE>
    \\      </ConnectedAP>
    \\    </SubNetwork>
    \\  </Communication>
    \\  <IED name="TESTIED" manufacturer="zig-libs" configVersion="1">
    \\    <AccessPoint name="AP1">
    \\      <Server>
    \\        <LDevice inst="GenericIO">
    \\          <LN0 lnClass="LLN0" lnType="LLN01" inst="">
    \\            <DataSet name="Events">
    \\              <FCDA ldInst="GenericIO" lnClass="GGIO" fc="ST" lnInst="1" doName="SPCSO1" daName="stVal"/>
    \\            </DataSet>
    \\            <ReportControl name="EventsRCB" confRev="1" datSet="Events" rptID="Events" buffered="false" intgPd="1000" bufTime="50">
    \\              <TrgOps dchg="true"/>
    \\              <OptFields seqNum="true" timeStamp="true" dataSet="true" reasonCode="true"/>
    \\              <RptEnabled max="2"/>
    \\            </ReportControl>
    \\            <GSEControl appID="events" name="gcbEvents" type="GOOSE" datSet="Events" confRev="2"/>
    \\          </LN0>
    \\          <LN lnClass="GGIO" lnType="GGIO1" inst="1" prefix="">
    \\            <DOI name="SPCSO1">
    \\              <DAI name="ctlModel"><Val>sbo-with-enhanced-security</Val></DAI>
    \\              <SDI name="Oper"><DAI name="ctlNum"><Val>7</Val></DAI></SDI>
    \\            </DOI>
    \\          </LN>
    \\        </LDevice>
    \\      </Server>
    \\    </AccessPoint>
    \\  </IED>
    \\  <DataTypeTemplates>
    \\    <LNodeType id="LLN01" lnClass="LLN0">
    \\      <DO name="Beh" type="INS1"/>
    \\    </LNodeType>
    \\    <LNodeType id="GGIO1" lnClass="GGIO">
    \\      <DO name="SPCSO1" type="SPC1"/>
    \\    </LNodeType>
    \\    <DOType id="INS1" cdc="INS">
    \\      <DA name="stVal" bType="INT32" fc="ST" dchg="true"/>
    \\      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
    \\      <DA name="t" bType="Timestamp" fc="ST"/>
    \\    </DOType>
    \\    <DOType id="SPC1" cdc="SPC">
    \\      <DA name="SBOw" type="Operate1" bType="Struct" fc="CO"/>
    \\      <DA name="Oper" type="Operate1" bType="Struct" fc="CO"/>
    \\      <DA name="Cancel" type="Cancel1" bType="Struct" fc="CO"/>
    \\      <DA name="stVal" bType="BOOLEAN" fc="ST" dchg="true"/>
    \\      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
    \\      <DA name="t" bType="Timestamp" fc="ST"/>
    \\      <DA name="ctlModel" type="CtlModels" bType="Enum" fc="CF"/>
    \\      <DA name="sboTimeout" bType="INT32U" fc="CF"/>
    \\    </DOType>
    \\    <DAType id="Operate1">
    \\      <BDA name="ctlVal" bType="BOOLEAN"/>
    \\      <BDA name="origin" type="Originator1" bType="Struct"/>
    \\      <BDA name="ctlNum" bType="INT8U"/>
    \\      <BDA name="T" bType="Timestamp"/>
    \\      <BDA name="Test" bType="BOOLEAN"/>
    \\      <BDA name="Check" bType="Check"/>
    \\    </DAType>
    \\    <DAType id="Cancel1">
    \\      <BDA name="ctlVal" bType="BOOLEAN"/>
    \\      <BDA name="origin" type="Originator1" bType="Struct"/>
    \\      <BDA name="ctlNum" bType="INT8U"/>
    \\      <BDA name="T" bType="Timestamp"/>
    \\      <BDA name="Test" bType="BOOLEAN"/>
    \\    </DAType>
    \\    <DAType id="Originator1">
    \\      <BDA name="orCat" type="OrCat" bType="Enum"/>
    \\      <BDA name="orIdent" bType="Octet64"/>
    \\    </DAType>
    \\    <EnumType id="CtlModels">
    \\      <EnumVal ord="0">status-only</EnumVal>
    \\      <EnumVal ord="1">direct-with-normal-security</EnumVal>
    \\      <EnumVal ord="2">sbo-with-normal-security</EnumVal>
    \\      <EnumVal ord="3">direct-with-enhanced-security</EnumVal>
    \\      <EnumVal ord="4">sbo-with-enhanced-security</EnumVal>
    \\    </EnumType>
    \\    <EnumType id="OrCat">
    \\      <EnumVal ord="0">not-supported</EnumVal>
    \\      <EnumVal ord="2">station-control</EnumVal>
    \\    </EnumType>
    \\  </DataTypeTemplates>
    \\</SCL>
;

test "the document structure parses: header, communication, IED and templates" {
    var s = try parse(testing.allocator, sample, .{});
    defer s.deinit();

    try testing.expectEqualStrings("ZIGLIBS", s.header.id);
    try testing.expectEqualStrings("IEDName", s.header.name_structure);
    try testing.expectEqual(@as(usize, 1), s.subnetworks.len);
    try testing.expectEqualStrings("station", s.subnetworks[0].name);
    try testing.expectEqualStrings("8-MMS", s.subnetworks[0].type);

    const ap = s.subnetworks[0].aps[0];
    try testing.expectEqualStrings("TESTIED", ap.ied_name);
    try testing.expectEqualStrings("10.0.0.2", ap.address.ip().?);
    try testing.expectEqualStrings("0001", ap.address.get("OSI-TSEL").?);

    // The GOOSE address lives in Communication, not next to the control block.
    const g = s.cbAddress("TESTIED", "GenericIO", "gcbEvents").?;
    try testing.expectEqualStrings("01-0c-cd-01-00-01", g.address.mac().?);
    try testing.expectEqual(@as(u16, 1000), g.address.appId().?);
    try testing.expectEqual(@as(u12, 100), g.address.vlanId().?);
    try testing.expectEqual(@as(u3, 4), g.address.vlanPriority().?);
    try testing.expectEqual(@as(u32, 10), g.min_time_ms.?);
    try testing.expectEqual(@as(u32, 2000), g.max_time_ms.?);
    try testing.expect(s.cbAddress("TESTIED", "GenericIO", "nope") == null);

    const ied = s.ied("TESTIED").?;
    try testing.expectEqualStrings("zig-libs", ied.manufacturer);
    try testing.expectEqual(@as(usize, 1), ied.access_points.len);
    const ld = ied.access_points[0].devices[0];
    try testing.expectEqualStrings("GenericIO", ld.inst);
    try testing.expectEqual(@as(usize, 2), ld.lns.len);
    try testing.expect(ld.lns[0].is_ln0);

    var dbuf: [64]u8 = undefined;
    try testing.expectEqualStrings("TESTIEDGenericIO", try ld.domain(ied.name, &dbuf));

    // Templates.
    try testing.expectEqual(@as(usize, 2), s.templates.ln_types.len);
    try testing.expectEqual(@as(usize, 2), s.templates.do_types.len);
    try testing.expectEqual(@as(usize, 3), s.templates.da_types.len);
    try testing.expectEqual(@as(i32, 4), s.templates.enumType("CtlModels").?.ordOf("sbo-with-enhanced-security").?);
    try testing.expect(s.templates.doType("nope") == null);

    // A `.cid`: one IED with its communication parameters filled in.
    try testing.expectEqual(Kind.cid, s.kind());
}

test "the type graph resolves into the MMS names the wire uses" {
    var s = try parse(testing.allocator, sample, .{});
    defer s.deinit();
    var m = try resolve(&s, testing.allocator, "TESTIED");
    defer m.deinit();

    const d = "TESTIEDGenericIO";
    // The logical node, the functional constraint, the data object, the
    // attribute — every level is a name the IED serves.
    try testing.expect(m.has(d, "GGIO1"));
    try testing.expect(m.has(d, "GGIO1$ST"));
    try testing.expect(m.has(d, "GGIO1$ST$SPCSO1"));
    try testing.expect(m.has(d, "GGIO1$ST$SPCSO1$stVal"));
    try testing.expect(m.has(d, "GGIO1$ST$SPCSO1$q"));
    try testing.expect(m.has(d, "GGIO1$ST$SPCSO1$t"));

    // The same data object appears under CF and CO with different children —
    // the thing a resolver that hangs the FC off the DO gets wrong.
    try testing.expect(m.has(d, "GGIO1$CF$SPCSO1$ctlModel"));
    try testing.expect(m.has(d, "GGIO1$CF$SPCSO1$sboTimeout"));
    try testing.expect(m.has(d, "GGIO1$CO$SPCSO1$Oper"));
    try testing.expect(m.has(d, "GGIO1$CO$SPCSO1$SBOw"));
    try testing.expect(m.has(d, "GGIO1$CO$SPCSO1$Cancel"));
    // …and it does NOT appear where it does not belong.
    try testing.expect(!m.has(d, "GGIO1$ST$SPCSO1$ctlModel"));
    try testing.expect(!m.has(d, "GGIO1$CO$SPCSO1$stVal"));
    try testing.expect(!m.has(d, "GGIO1$CF$SPCSO1$Oper"));

    // Nested DAType members, two levels down.
    try testing.expect(m.has(d, "GGIO1$CO$SPCSO1$Oper$ctlVal"));
    try testing.expect(m.has(d, "GGIO1$CO$SPCSO1$Oper$origin"));
    try testing.expect(m.has(d, "GGIO1$CO$SPCSO1$Oper$origin$orCat"));
    try testing.expect(m.has(d, "GGIO1$CO$SPCSO1$Oper$origin$orIdent"));
    try testing.expect(m.has(d, "GGIO1$CO$SPCSO1$Oper$Check"));
    // Cancel has no Check.
    try testing.expect(m.has(d, "GGIO1$CO$SPCSO1$Cancel$Test"));
    try testing.expect(!m.has(d, "GGIO1$CO$SPCSO1$Cancel$Check"));

    // Types and leaf-ness come out with the names.
    const ctl_val = m.find(d, "GGIO1$CO$SPCSO1$Oper$ctlVal").?;
    try testing.expectEqual(BType.BOOLEAN, ctl_val.b_type.?);
    try testing.expectEqual(Fc.CO, ctl_val.fc.?);
    try testing.expect(ctl_val.leaf);
    const origin = m.find(d, "GGIO1$CO$SPCSO1$Oper$origin").?;
    try testing.expectEqual(BType.Struct, origin.b_type.?);
    try testing.expect(!origin.leaf);

    // Configured values from DOI/DAI, including one under an SDI.
    try testing.expectEqualStrings(
        "sbo-with-enhanced-security",
        m.find(d, "GGIO1$CF$SPCSO1$ctlModel").?.value.?,
    );
    try testing.expectEqualStrings("7", m.find(d, "GGIO1$CO$SPCSO1$Oper$ctlNum").?.value.?);

    // Which means a client can pick its control state machine from the file.
    try testing.expectEqual(
        control.CtlModel.sbo_with_enhanced_security,
        m.ctlModel(d, "GGIO1$CO$SPCSO1").?,
    );
}

test "report and GOOSE control blocks become names a client can enable" {
    var s = try parse(testing.allocator, sample, .{});
    defer s.deinit();
    var m = try resolve(&s, testing.allocator, "TESTIED");
    defer m.deinit();
    const d = "TESTIEDGenericIO";

    // `<RptEnabled max="2"/>` is two instances, suffixed — not one control
    // block. A client that writes to `EventsRCB` finds nothing there.
    try testing.expect(!m.has(d, "LLN0$RP$EventsRCB"));
    try testing.expect(m.has(d, "LLN0$RP$EventsRCB01"));
    try testing.expect(m.has(d, "LLN0$RP$EventsRCB02"));
    for (default_urcb_attributes) |attr| {
        var buf: [128]u8 = undefined;
        const name = try std.fmt.bufPrint(&buf, "LLN0$RP$EventsRCB01${s}", .{attr});
        try testing.expect(m.has(d, name));
    }
    // The three a client writes to enable reporting.
    try testing.expect(m.has(d, "LLN0$RP$EventsRCB01$TrgOps"));
    try testing.expect(m.has(d, "LLN0$RP$EventsRCB01$IntgPd"));
    try testing.expect(m.has(d, "LLN0$RP$EventsRCB01$RptEna"));

    try testing.expect(m.has(d, "LLN0$GO$gcbEvents"));
    try testing.expect(m.has(d, "LLN0$GO$gcbEvents$GoEna"));
    try testing.expect(m.has(d, "LLN0$GO$gcbEvents$DatSet"));
    try testing.expect(m.has(d, "LLN0$GO$gcbEvents$DstAddress$APPID"));

    // And the control-block configuration itself is readable from the file.
    const ln0 = s.ied("TESTIED").?.access_points[0].devices[0].lns[0];
    try testing.expectEqual(@as(u8, 2), ln0.report_controls[0].max_instances);
    try testing.expect(ln0.report_controls[0].trg_ops.dchg);
    try testing.expect(ln0.report_controls[0].opt_fields.seq_num);
    try testing.expect(!ln0.report_controls[0].opt_fields.entry_id);
    try testing.expectEqual(@as(u32, 1000), ln0.report_controls[0].intg_pd);
    try testing.expectEqualStrings("GOOSE", ln0.gse_controls[0].type);
    try testing.expectEqual(@as(u32, 2), ln0.gse_controls[0].conf_rev);
}

test "an FCDA resolves to the MMS item the GOOSE decoder will see" {
    var s = try parse(testing.allocator, sample, .{});
    defer s.deinit();
    const ln0 = s.ied("TESTIED").?.access_points[0].devices[0].lns[0];
    const f = ln0.data_sets[0].fcdas[0];
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("GGIO1$ST$SPCSO1$stVal", try f.mmsItem(&buf));
    try testing.expectEqual(Fc.ST, f.fc);

    // A whole data object (no daName) and a nested path both work.
    const whole = Fcda{ .ld_inst = "GenericIO", .ln_class = "GGIO", .ln_inst = "1", .do_name = "AnIn1", .fc = .MX };
    try testing.expectEqualStrings("GGIO1$MX$AnIn1", try whole.mmsItem(&buf));
    const nested = Fcda{ .ld_inst = "GenericIO", .ln_class = "GGIO", .ln_inst = "1", .do_name = "AnIn1", .da_name = "mag.f", .fc = .MX };
    try testing.expectEqualStrings("GGIO1$MX$AnIn1$mag$f", try nested.mmsItem(&buf));
}

test "the SCL functional constraints are a superset of the ACSI ones" {
    // Every ACSI constraint is an SCL one…
    inline for (@typeInfo(acsi.FunctionalConstraint).@"enum".fields) |f| {
        const fc = try Fc.parse(f.name);
        try testing.expectEqual(
            @as(?acsi.FunctionalConstraint, @enumFromInt(f.value)),
            fc.toAcsi(),
        );
    }
    // …plus the two edition-2 additions, which the wire naming layer does not
    // model and which therefore map to null rather than to a wrong constraint.
    try testing.expect(Fc.OR.toAcsi() == null);
    try testing.expect(Fc.BL.toAcsi() == null);
    try testing.expect(Fc.SR.toAcsi() == null);
    try testing.expectEqual(@as(usize, 20), @typeInfo(Fc).@"enum".fields.len);
    try testing.expectError(error.UnknownFunctionalConstraint, Fc.parse("XX"));
    try testing.expectError(error.UnknownFunctionalConstraint, Fc.parse("st"));
}

// ── hostile input ───────────────────────────────────────────────────────────

fn resolveText(text: []const u8) Error!void {
    var s = try parse(testing.allocator, text, .{});
    defer s.deinit();
    var m = try resolve(&s, testing.allocator, "TESTIED");
    defer m.deinit();
}

/// Wraps a `DataTypeTemplates` body and one GGIO logical node around it.
fn wrap(comptime templates: []const u8, comptime doi: []const u8) []const u8 {
    return "<SCL xmlns=\"http://www.iec.ch/61850/2003/SCL\"><IED name=\"TESTIED\"><AccessPoint name=\"AP1\"><Server>" ++
        "<LDevice inst=\"LD\"><LN lnClass=\"GGIO\" lnType=\"T1\" inst=\"1\">" ++ doi ++ "</LN></LDevice>" ++
        "</Server></AccessPoint></IED><DataTypeTemplates>" ++ templates ++ "</DataTypeTemplates></SCL>";
}

test "a type reference that does not resolve is a typed error" {
    const missing_do_type = wrap(
        \\<LNodeType id="T1" lnClass="GGIO"><DO name="X" type="NOPE"/></LNodeType>
    , "");
    try testing.expectError(error.UnresolvedType, resolveText(missing_do_type));

    const missing_ln_type = wrap(
        \\<LNodeType id="OTHER" lnClass="GGIO"><DO name="X" type="D1"/></LNodeType>
        \\<DOType id="D1"><DA name="stVal" bType="BOOLEAN" fc="ST"/></DOType>
    , "");
    try testing.expectError(error.UnresolvedType, resolveText(missing_ln_type));

    const missing_da_type = wrap(
        \\<LNodeType id="T1" lnClass="GGIO"><DO name="X" type="D1"/></LNodeType>
        \\<DOType id="D1"><DA name="Oper" type="NOPE" bType="Struct" fc="CO"/></DOType>
    , "");
    try testing.expectError(error.UnresolvedType, resolveText(missing_da_type));
}

test "a cyclic type reference is caught on the path, not by blowing the stack" {
    const direct = wrap(
        \\<LNodeType id="T1" lnClass="GGIO"><DO name="X" type="D1"/></LNodeType>
        \\<DOType id="D1"><DA name="a" type="A1" bType="Struct" fc="ST"/></DOType>
        \\<DAType id="A1"><BDA name="b" type="A1" bType="Struct"/></DAType>
    , "");
    try testing.expectError(error.CyclicType, resolveText(direct));

    // A two-step cycle, which a naive "same id as my parent" check misses.
    const indirect = wrap(
        \\<LNodeType id="T1" lnClass="GGIO"><DO name="X" type="D1"/></LNodeType>
        \\<DOType id="D1"><DA name="a" type="A1" bType="Struct" fc="ST"/></DOType>
        \\<DAType id="A1"><BDA name="b" type="A2" bType="Struct"/></DAType>
        \\<DAType id="A2"><BDA name="c" type="A1" bType="Struct"/></DAType>
    , "");
    try testing.expectError(error.CyclicType, resolveText(indirect));

    // An SDO cycle is caught by the depth budget.
    const sdo_cycle = wrap(
        \\<LNodeType id="T1" lnClass="GGIO"><DO name="X" type="D1"/></LNodeType>
        \\<DOType id="D1"><SDO name="s" type="D1"/><DA name="stVal" bType="BOOLEAN" fc="ST"/></DOType>
    , "");
    try testing.expectError(error.TypeTooDeep, resolveText(sdo_cycle));
}

test "a DAI whose value contradicts its bType is refused" {
    const bad_bool = wrap(
        \\<LNodeType id="T1" lnClass="GGIO"><DO name="X" type="D1"/></LNodeType>
        \\<DOType id="D1"><DA name="stVal" bType="BOOLEAN" fc="ST"/></DOType>
    ,
        \\<DOI name="X"><DAI name="stVal"><Val>maybe</Val></DAI></DOI>
    );
    try testing.expectError(error.ValueTypeMismatch, resolveText(bad_bool));

    const out_of_range = wrap(
        \\<LNodeType id="T1" lnClass="GGIO"><DO name="X" type="D1"/></LNodeType>
        \\<DOType id="D1"><DA name="n" bType="INT8U" fc="CF"/></DOType>
    ,
        \\<DOI name="X"><DAI name="n"><Val>400</Val></DAI></DOI>
    );
    try testing.expectError(error.ValueTypeMismatch, resolveText(out_of_range));

    const bad_enum = wrap(
        \\<LNodeType id="T1" lnClass="GGIO"><DO name="X" type="D1"/></LNodeType>
        \\<DOType id="D1"><DA name="ctlModel" type="E1" bType="Enum" fc="CF"/></DOType>
        \\<EnumType id="E1"><EnumVal ord="0">status-only</EnumVal></EnumType>
    ,
        \\<DOI name="X"><DAI name="ctlModel"><Val>sbo-with-teleportation</Val></DAI></DOI>
    );
    try testing.expectError(error.ValueTypeMismatch, resolveText(bad_enum));

    const too_long = wrap(
        \\<LNodeType id="T1" lnClass="GGIO"><DO name="X" type="D1"/></LNodeType>
        \\<DOType id="D1"><DA name="s" bType="VisString32" fc="DC"/></DOType>
    ,
        \\<DOI name="X"><DAI name="s"><Val>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</Val></DAI></DOI>
    );
    try testing.expectError(error.ValueTypeMismatch, resolveText(too_long));

    // A well-typed value is accepted, and the ordinal spelling of an enum too.
    const ok = wrap(
        \\<LNodeType id="T1" lnClass="GGIO"><DO name="X" type="D1"/></LNodeType>
        \\<DOType id="D1"><DA name="ctlModel" type="E1" bType="Enum" fc="CF"/></DOType>
        \\<EnumType id="E1"><EnumVal ord="0">status-only</EnumVal><EnumVal ord="1">direct-with-normal-security</EnumVal></EnumType>
    ,
        \\<DOI name="X"><DAI name="ctlModel"><Val>1</Val></DAI></DOI>
    );
    try resolveText(ok);
}

test "an FCDA pointing at a data object that is not there is refused" {
    const text = "<SCL xmlns=\"http://www.iec.ch/61850/2003/SCL\"><IED name=\"TESTIED\"><AccessPoint name=\"AP1\"><Server>" ++
        "<LDevice inst=\"LD\"><LN0 lnClass=\"LLN0\" lnType=\"T0\" inst=\"\">" ++
        "<DataSet name=\"DS\"><FCDA ldInst=\"LD\" lnClass=\"LLN0\" fc=\"ST\" doName=\"NoSuchThing\" daName=\"stVal\"/></DataSet>" ++
        "</LN0></LDevice></Server></AccessPoint></IED><DataTypeTemplates>" ++
        "<LNodeType id=\"T0\" lnClass=\"LLN0\"><DO name=\"Beh\" type=\"D1\"/></LNodeType>" ++
        "<DOType id=\"D1\"><DA name=\"stVal\" bType=\"INT32\" fc=\"ST\"/></DOType>" ++
        "</DataTypeTemplates></SCL>";
    try testing.expectError(error.UnresolvedFcda, resolveText(text));
}

test "an unknown bType is refused unless the caller opts in" {
    const text = wrap(
        \\<LNodeType id="T1" lnClass="GGIO"><DO name="X" type="D1"/></LNodeType>
        \\<DOType id="D1"><DA name="v" bType="VendorMagic" fc="ST"/></DOType>
    , "");
    var strict = parse(testing.allocator, text, .{});
    if (strict) |*s| {
        s.deinit();
        return error.TestUnexpectedResult;
    } else |e| try testing.expectEqual(Error.UnknownBasicType, e);

    var lax = try parse(testing.allocator, text, .{ .allow_unknown_btype = true });
    defer lax.deinit();
    var m = try resolve(&lax, testing.allocator, "TESTIED");
    defer m.deinit();
    try testing.expectEqual(BType.unknown, m.find("TESTIEDLD", "GGIO1$ST$X$v").?.b_type.?);
}

test "a document that is not SCL, and one that is hostile XML, are refused" {
    try testing.expectError(
        error.NotScl,
        parse(testing.allocator, "<Envelope xmlns=\"urn:x\"/>", .{}),
    );
    // The xml sibling's hardening applies unchanged: DOCTYPE is rejected, so an
    // external entity never even gets looked at.
    const xxe =
        \\<!DOCTYPE SCL [<!ENTITY x SYSTEM "file:///etc/passwd">]>
        \\<SCL xmlns="http://www.iec.ch/61850/2003/SCL"><Header id="&x;"/></SCL>
    ;
    try testing.expectError(error.DoctypeForbidden, parse(testing.allocator, xxe, .{}));
}

test "an IED the file does not contain is a typed error" {
    var s = try parse(testing.allocator, sample, .{});
    defer s.deinit();
    try testing.expectError(error.UnresolvedFcda, resolve(&s, testing.allocator, "OTHERIED"));
}

test "fuzz: SCL parsing and resolution never panic" {
    try std.testing.fuzz({}, fuzzScl, .{});
}

fn fuzzScl(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    var s = parse(testing.allocator, buf[0..len], .{ .allow_unknown_btype = true }) catch return;
    defer s.deinit();
    for (s.ieds) |i| {
        var m = resolve(&s, testing.allocator, i.name) catch continue;
        defer m.deinit();
        // Every resolved name must be a legal MMS item id under a domain.
        for (m.nodes) |n| {
            try testing.expect(n.item.len > 0);
            try testing.expect(n.item.len <= acsi.max_reference_len);
        }
    }
}

test "fuzz: a hostile SCL fragment glued into a valid skeleton never panics" {
    try std.testing.fuzz({}, fuzzFragment, .{});
}

fn fuzzFragment(_: void, smith: *std.testing.Smith) !void {
    var frag: [256]u8 = undefined;
    smith.bytes(&frag);
    const n: usize = smith.valueRangeAtMost(u8, 0, 200);
    // Keep it XML-legal: only name characters, so the parser gets past the
    // lexer and the *resolver* is what is being exercised.
    for (frag[0..n]) |*c| {
        c.* = switch (c.* % 4) {
            0 => 'a' + (c.* % 26),
            1 => 'A' + (c.* % 26),
            2 => '0' + (c.* % 10),
            else => '_',
        };
    }
    const id = frag[0..n];

    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(testing.allocator);
    const rendered = try std.fmt.allocPrint(
        testing.allocator,
        "<SCL xmlns=\"http://www.iec.ch/61850/2003/SCL\"><IED name=\"I\"><AccessPoint name=\"A\"><Server>" ++
            "<LDevice inst=\"LD\"><LN lnClass=\"GGIO\" lnType=\"{s}\" inst=\"1\"/></LDevice>" ++
            "</Server></AccessPoint></IED><DataTypeTemplates>" ++
            "<LNodeType id=\"{s}\" lnClass=\"GGIO\"><DO name=\"X\" type=\"{s}\"/></LNodeType>" ++
            "<DOType id=\"{s}\"><DA name=\"v\" bType=\"BOOLEAN\" fc=\"ST\"/></DOType>" ++
            "</DataTypeTemplates></SCL>",
        .{ id, id, id, id },
    );
    defer testing.allocator.free(rendered);
    var s = parse(testing.allocator, rendered, .{}) catch return;
    defer s.deinit();
    var m = resolve(&s, testing.allocator, "I") catch return;
    defer m.deinit();
}
