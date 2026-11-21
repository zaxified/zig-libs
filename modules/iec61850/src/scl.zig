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
        inline for (@typeInfo(Fc).@"enum".field_names, @typeInfo(Fc).@"enum".field_values) |f_name, f_value| {
            if (std.mem.eql(u8, s, f_name)) return @fromBackingInt(@intCast(f_value));
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
        inline for (@typeInfo(BType).@"enum".field_names, @typeInfo(BType).@"enum".field_values) |f_name, f_value| {
            if (std.mem.eql(u8, s, f_name)) return @fromBackingInt(@intCast(f_value));
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
    /// `Text` and the `History` of `Hitem`s.
    extras: Extras = .{},
};

/// An element this model keeps **verbatim**: it points into the document tree
/// that the `Scl` owns, so it lives exactly as long as the `Scl` does.
pub const Raw = *const xml.Element;

/// What a container carries that no typed field above models: `Text` and
/// `Private` (the schema puts them first, and `Private` is by definition the
/// vendor's own — it is carried, never interpreted) and any other child element
/// the model has no field for (`Line`, `Process`, `Function`, `SubEquipment`,
/// `TapChanger`, …). `sclwrite` writes `head` before the typed children and
/// `tail` after them, so a document comes back with them in a schema-valid
/// position.
pub const Extras = struct {
    head: []const Raw = &.{},
    tail: []const Raw = &.{},

    pub fn isEmpty(self: Extras) bool {
        return self.head.len == 0 and self.tail.len == 0;
    }

    /// The first carried element with this local name, or null.
    pub fn find(self: Extras, local: []const u8) ?Raw {
        for (self.head) |e| {
            if (std.mem.eql(u8, e.local, local)) return e;
        }
        for (self.tail) |e| {
            if (std.mem.eql(u8, e.local, local)) return e;
        }
        return null;
    }
};

// ── the Substation section (IEC 61850-6 §9) ─────────────────────────────────

/// A `<LNode>`: the link from a place in the single-line diagram to a logical
/// node of an IED — the reason the `Substation` section exists at all.
pub const LNodeRef = struct {
    ied_name: []const u8 = "None",
    ld_inst: []const u8 = "",
    prefix: []const u8 = "",
    ln_class: []const u8,
    ln_inst: []const u8 = "",
    /// Set when the node is not yet bound to an IED (the specification phase).
    ln_type: []const u8 = "",
    desc: []const u8 = "",
};

/// A `<Terminal>`: where a piece of equipment attaches to a connectivity node.
pub const Terminal = struct {
    name: []const u8 = "",
    c_node_name: []const u8,
    connectivity_node: []const u8,
    substation_name: []const u8 = "",
    voltage_level_name: []const u8 = "",
    bay_name: []const u8 = "",
    line_name: []const u8 = "",
    desc: []const u8 = "",
};

/// A `<ConnectivityNode>` of a bay.
pub const ConnectivityNode = struct {
    name: []const u8,
    path_name: []const u8,
    desc: []const u8 = "",
};

pub const EquipmentKind = enum {
    /// `<ConductingEquipment>` — a breaker, a disconnector, a CT, …; `type` is its
    /// three-letter class (`CBR`, `DIS`, `CTR`, …).
    conducting,
    /// `<GeneralEquipment>` — equipment without a conducting role (`AXN`, `BAT`, …).
    general,
    /// `<TransformerWinding>` of a power transformer (`type` is `PTW`).
    winding,
};

pub const Equipment = struct {
    kind: EquipmentKind = .conducting,
    name: []const u8,
    desc: []const u8 = "",
    type: []const u8 = "",
    /// `virtual="true"`: a stand-in for equipment outside the substation.
    virtual: bool = false,
    terminals: []const Terminal = &.{},
    lnodes: []const LNodeRef = &.{},
    /// `SubEquipment`, `TapChanger`, `EqFunction`, `Text`, `Private`.
    extras: Extras = .{},
};

pub const PowerTransformer = struct {
    name: []const u8,
    desc: []const u8 = "",
    /// `PTR` — the only value the schema allows.
    type: []const u8 = "PTR",
    virtual: bool = false,
    windings: []const Equipment = &.{},
    terminals: []const Terminal = &.{},
    lnodes: []const LNodeRef = &.{},
    extras: Extras = .{},
};

pub const Bay = struct {
    name: []const u8,
    desc: []const u8 = "",
    equipment: []const Equipment = &.{},
    general_equipment: []const Equipment = &.{},
    power_transformers: []const PowerTransformer = &.{},
    connectivity_nodes: []const ConnectivityNode = &.{},
    lnodes: []const LNodeRef = &.{},
    /// `Function`, `Text`, `Private`.
    extras: Extras = .{},
};

/// `<Voltage unit="V" multiplier="k">110</Voltage>` of a voltage level.
pub const Voltage = struct {
    value: []const u8,
    unit: []const u8 = "V",
    multiplier: []const u8 = "",
};

pub const VoltageLevel = struct {
    name: []const u8,
    desc: []const u8 = "",
    /// Absent when the file does not say.
    nom_freq: []const u8 = "",
    num_phases: []const u8 = "",
    voltage: ?Voltage = null,
    bays: []const Bay = &.{},
    general_equipment: []const Equipment = &.{},
    power_transformers: []const PowerTransformer = &.{},
    lnodes: []const LNodeRef = &.{},
    extras: Extras = .{},
};

pub const Substation = struct {
    name: []const u8,
    desc: []const u8 = "",
    voltage_levels: []const VoltageLevel = &.{},
    general_equipment: []const Equipment = &.{},
    power_transformers: []const PowerTransformer = &.{},
    lnodes: []const LNodeRef = &.{},
    extras: Extras = .{},

    /// The logical nodes bound to an IED anywhere below this substation — the
    /// answer to "which IED belongs to which breaker". Counts, not copies:
    /// walk the tree for the references themselves.
    pub fn boundLnodeCount(self: Substation) usize {
        var n: usize = countBound(self.lnodes);
        for (self.general_equipment) |e| n += countBound(e.lnodes);
        for (self.power_transformers) |p| n += countPt(p);
        for (self.voltage_levels) |v| {
            n += countBound(v.lnodes);
            for (v.general_equipment) |e| n += countBound(e.lnodes);
            for (v.power_transformers) |p| n += countPt(p);
            for (v.bays) |b| {
                n += countBound(b.lnodes);
                for (b.equipment) |e| n += countBound(e.lnodes);
                for (b.general_equipment) |e| n += countBound(e.lnodes);
                for (b.power_transformers) |p| n += countPt(p);
            }
        }
        return n;
    }
};

fn countBound(lnodes: []const LNodeRef) usize {
    var n: usize = 0;
    for (lnodes) |l| {
        if (l.ied_name.len > 0 and !std.mem.eql(u8, l.ied_name, "None")) n += 1;
    }
    return n;
}

fn countPt(p: PowerTransformer) usize {
    var n = countBound(p.lnodes);
    for (p.windings) |w| n += countBound(w.lnodes);
    return n;
}

// ── Services (IEC 61850-6 §9.4.5) ───────────────────────────────────────────

/// An IED's `<Services>`: the capability statement of the device. Each child
/// (`GetDirectory`, `ConfDataSet`, `GOOSE`, `ReportSettings`, …) is carried
/// verbatim, because the set is open-ended — every edition adds some — and a
/// tool that only needs "does this IED offer `ConfReportControl`" asks `has`.
pub const Services = struct {
    /// `nameLength` — the longest object name the IED supports (8, 16, 32, 64, …).
    name_length: []const u8 = "",
    elements: []const Raw = &.{},

    /// Does the IED declare this service (`GetDirectory`, `FileHandling`, …)?
    pub fn has(self: Services, service: []const u8) bool {
        return self.get(service) != null;
    }

    /// The element declaring a service, for its attributes and children.
    pub fn get(self: Services, service: []const u8) ?Raw {
        for (self.elements) |e| {
            if (std.mem.eql(u8, e.local, service)) return e;
        }
        return null;
    }

    /// One attribute of a service, e.g. `attribute("ConfDataSet", "max")`.
    pub fn attribute(self: Services, service: []const u8, name: []const u8) ?[]const u8 {
        const e = self.get(service) orelse return null;
        return e.attr("", name);
    }

    /// An unsigned attribute of a service, e.g. `number("GOOSE", "max")`.
    pub fn number(self: Services, service: []const u8, name: []const u8) ?u32 {
        const v = self.attribute(service, name) orelse return null;
        return parseU32(v);
    }
};

// ── Inputs / ExtRef (IEC 61850-6 §9.3.x) ────────────────────────────────────

/// An `<ExtRef>` of an `<Inputs>` section: a data object or attribute this
/// logical node *consumes* from another IED — the subscription half of a
/// GOOSE or SV link, which the `GSEControl`/`SampledValueControl` of the
/// publisher alone does not describe. Every attribute is optional in the schema.
pub const ExtRef = struct {
    ied_name: []const u8 = "",
    ld_inst: []const u8 = "",
    prefix: []const u8 = "",
    ln_class: []const u8 = "",
    ln_inst: []const u8 = "",
    do_name: []const u8 = "",
    da_name: []const u8 = "",
    /// Where the value lands in *this* IED's own model (`intAddr`).
    int_addr: []const u8 = "",
    desc: []const u8 = "",
    /// `Poll`, `Report`, `GOOSE` or `SMV` (edition 2).
    service_type: []const u8 = "",
    src_ld_inst: []const u8 = "",
    src_prefix: []const u8 = "",
    src_ln_class: []const u8 = "",
    src_ln_inst: []const u8 = "",
    src_cb_name: []const u8 = "",
    /// Edition 2.1 pre-defined-attribute references (`pLN`, `pDO`, `pDA`, `pServT`).
    p_ln: []const u8 = "",
    p_do: []const u8 = "",
    p_da: []const u8 = "",
    p_serv_t: []const u8 = "",
};

pub const Inputs = struct {
    ext_refs: []const ExtRef = &.{},
    /// `SourceRef` (edition 2.1), `Text`, `Private`.
    extras: Extras = .{},
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
    extras: Extras = .{},
};

pub const ConnectedAp = struct {
    ied_name: []const u8,
    ap_name: []const u8,
    address: Address = .{},
    gse: []const CbAddress = &.{},
    smv: []const CbAddress = &.{},
    /// `PhysConn`, `Text`, `Private`.
    extras: Extras = .{},
};

pub const Subnetwork = struct {
    name: []const u8,
    type: []const u8 = "",
    desc: []const u8 = "",
    aps: []const ConnectedAp = &.{},
    /// `BitRate`, `Text`, `Private`.
    extras: Extras = .{},
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
            if (std.mem.findScalar(u8, c, '(') != null) return out[0..w];
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
                if (std.mem.findScalar(u8, c, '(') != null) return out[0..w];
            }
        }
        return out[0..w];
    }
};

/// Strips an SCL array index: `phsAHar(7)` → `phsAHar`.
fn stripIndex(component: []const u8) []const u8 {
    const paren = std.mem.findScalar(u8, component, '(') orelse return component;
    return component[0..paren];
}

pub const DataSet = struct {
    name: []const u8,
    desc: []const u8 = "",
    fcdas: []const Fcda = &.{},
    extras: Extras = .{},
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
    desc: []const u8 = "",
    extras: Extras = .{},
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
    desc: []const u8 = "",
};

/// A `<Log>` — the log *itself*, as opposed to the `<LogControl>` that decides
/// what goes into it. An IED may hold several, and a `LogControl` picks one by
/// `logName`; a log with no name is the logical node's default log, which is
/// what `LogControl/@logName=""` refers to.
///
/// It is a leaf element with nothing but a name and a description, and it
/// exists in this parser for one reason: a model generator reading the same
/// file emits a `Log` object per element, so a document that loses them
/// describes a different IED.
pub const Log = struct {
    name: []const u8 = "",
    desc: []const u8 = "",
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
    desc: []const u8 = "",
    extras: Extras = .{},
};

/// A `<SampledValueControl>` — the sampled-value control block, the SV twin of
/// `GseControl`. `multicast` (the default) is an `MSVCB` under `MS`; a unicast
/// one is a `USVCB` under `US`.
pub const SmvControl = struct {
    name: []const u8,
    desc: []const u8 = "",
    dat_set: []const u8 = "",
    conf_rev: u32 = 1,
    /// `smvID`.
    smv_id: []const u8 = "",
    multicast: bool = true,
    /// `smpRate`, samples per `smpMod` unit.
    smp_rate: u32 = 0,
    /// `nofASDU` — ASDUs per frame.
    nof_asdu: u32 = 0,
    /// `SmpPerPeriod`, `SmpPerSec` or `SecPerSmp`.
    smp_mod: []const u8 = "SmpPerPeriod",
    /// The `<SmvOpts>` flags; the schema default of every one is false.
    opts: SmvOpts = .{},
    /// `securityEnable`: `None`, `Signature` or `SignatureAndEncryption`.
    security_enable: []const u8 = "",
    extras: Extras = .{},
};

pub const SmvOpts = struct {
    refresh_time: bool = false,
    sample_synchronized: bool = false,
    sample_rate: bool = false,
    data_set: bool = false,
    security: bool = false,
    timestamp: bool = false,
    synch_source_id: bool = false,
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
    extras: Extras = .{},
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
    /// `SampledValueControl`s (on `LN0`).
    smv_controls: []const SmvControl = &.{},
    /// The `<Inputs>` section: what this node consumes from other IEDs.
    inputs: ?Inputs = null,
    desc: []const u8 = "",
    /// `Text`, `Private`, `SCLControl`, `SGVal`, … .
    extras: Extras = .{},
    /// The `<Log>` elements this node owns. Parsed and emitted; nothing here
    /// interprets them beyond that — the runtime log lives in `logging.zig` and
    /// is configured by the caller, not by SCL.
    logs: []const Log = &.{},
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
    desc: []const u8 = "",
    lns: []const Ln = &.{},
    /// `Text`, `Private`, `AccessControl`.
    extras: Extras = .{},

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
    desc: []const u8 = "",
    devices: []const LDevice = &.{},
    /// The access point's own `<Services>`, when it has one.
    services: ?Services = null,
    /// `Text`, `Private`, `LN`s hung directly on the access point,
    /// `ServerAt`, `GOOSESecurity`, `SMVSecurity`.
    extras: Extras = .{},
    /// What the `<Server>` element carries besides logical devices:
    /// `Authentication`, `Association`, `Private`.
    server_extras: Extras = .{},
};

pub const Ied = struct {
    name: []const u8,
    type: []const u8 = "",
    manufacturer: []const u8 = "",
    config_version: []const u8 = "",
    desc: []const u8 = "",
    owner: []const u8 = "",
    access_points: []const AccessPoint = &.{},
    /// The IED's capability statement.
    services: ?Services = null,
    /// `Text`, `Private`, `KDC`.
    extras: Extras = .{},
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
    /// The `Substation` elements, in document order.
    substations: []const Substation,
    has_substation: bool,
    options: Options,
    /// The `SCL` element's own `version` (`2007`), `revision` (`B`) and `release`
    /// (`4`) — which edition's schema the file claims.
    version: []const u8,
    revision: []const u8,
    release: []const u8,
    /// Namespace declarations other than the default one on the root, which
    /// `Private` content routinely uses (`xmlns:xsi`, a vendor's own).
    extra_namespaces: []const xml.NsDecl,
    /// Root-level `Text`/`Private` (`head`) and `Line`/`Process` (`tail`).
    extras: Extras,
    /// What `Communication` carries besides `SubNetwork`s (`Text`, `Private`).
    comm_extras: Extras,

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
    /// The MMS attribute names of a **multicast** sampled-value control block
    /// (`MS`) and of a **unicast** one (`US`). Self-derived from IEC 61850-7-2
    /// and not confirmed against a peer, so a knob like the two above.
    msvcb_attributes: []const []const u8 = &default_msvcb_attributes,
    usvcb_attributes: []const []const u8 = &default_usvcb_attributes,
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
        const dollar = std.mem.findScalar(u8, item_prefix, '$') orelse return null;
        const rest = std.mem.findScalarPos(u8, item_prefix, dollar + 1, '$') orelse return null;
        const name = std.mem.print(&buf, "{s}$CF{s}$ctlModel", .{
            item_prefix[0..dollar],
            item_prefix[rest..],
        }) catch return null;
        const n = self.find(domain, name) orelse return null;
        const v = n.value orelse return null;
        return control.CtlModel.parseScl(v) catch null;
    }

    /// The `sboClass` of a control object (`GGIO1$CO$SPCSO4` →
    /// `GGIO1$CF$SPCSO4$sboClass`), when the file gives one; an object that does
    /// not is `operate-once`, which is the schema default.
    pub fn sboClass(self: *const Model, domain: []const u8, item_prefix: []const u8) ?control.SboClass {
        var buf: [acsi.max_reference_len]u8 = undefined;
        const dollar = std.mem.findScalar(u8, item_prefix, '$') orelse return null;
        const rest = std.mem.findScalarPos(u8, item_prefix, dollar + 1, '$') orelse return null;
        const name = std.mem.print(&buf, "{s}$CF{s}$sboClass", .{
            item_prefix[0..dollar],
            item_prefix[rest..],
        }) catch return null;
        const n = self.find(domain, name) orelse return null;
        return control.SboClass.parseScl(n.value orelse return null);
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
    var substations: std.ArrayList(Substation) = .empty;
    var comm_extras = Extras{};

    var it = doc.root.elementIterator();
    while (it.next()) |el| {
        if (std.mem.eql(u8, el.local, "Header")) {
            header = .{
                .id = attrOr(el, "id", ""),
                .version = attrOr(el, "version", ""),
                .revision = attrOr(el, "revision", ""),
                .tool_id = attrOr(el, "toolID", ""),
                .name_structure = attrOr(el, "nameStructure", ""),
                .extras = try p.extrasOf(el, &.{}),
            };
        } else if (std.mem.eql(u8, el.local, "Substation")) {
            has_substation = true;
            try substations.append(a, try p.substation(el));
        } else if (std.mem.eql(u8, el.local, "Communication")) {
            comm_extras = try p.extrasOf(el, &.{"SubNetwork"});
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
        .substations = try substations.toOwnedSlice(a),
        .has_substation = has_substation,
        .options = options,
        .version = attrOr(doc.root, "version", ""),
        .revision = attrOr(doc.root, "revision", ""),
        .release = attrOr(doc.root, "release", ""),
        .extra_namespaces = try p.extraNamespaces(doc.root),
        .extras = try p.extrasOf(doc.root, &.{ "Header", "Substation", "Communication", "IED", "DataTypeTemplates" }),
        .comm_extras = comm_extras,
    };
}

const Parser = struct {
    a: std.mem.Allocator,
    options: Options,

    /// The children of `el` that are not in `known`, sorted into `Text`/`Private`
    /// (which the schema puts first) and everything else.
    fn extrasOf(self: *Parser, el: *xml.Element, known: []const []const u8) Error!Extras {
        var head: std.ArrayList(Raw) = .empty;
        var tail: std.ArrayList(Raw) = .empty;
        var it = el.elementIterator();
        next: while (it.next()) |c| {
            for (known) |k| {
                if (std.mem.eql(u8, c.local, k)) continue :next;
            }
            if (std.mem.eql(u8, c.local, "Text") or std.mem.eql(u8, c.local, "Private")) {
                try head.append(self.a, c);
            } else {
                try tail.append(self.a, c);
            }
        }
        return .{
            .head = try head.toOwnedSlice(self.a),
            .tail = try tail.toOwnedSlice(self.a),
        };
    }

    fn extraNamespaces(self: *Parser, root: *xml.Element) Error![]const xml.NsDecl {
        var out: std.ArrayList(xml.NsDecl) = .empty;
        for (root.ns_decls) |d| {
            if (d.prefix.len > 0) try out.append(self.a, d);
        }
        return out.toOwnedSlice(self.a);
    }

    fn lnodeRefs(self: *Parser, el: *xml.Element) Error![]const LNodeRef {
        var out: std.ArrayList(LNodeRef) = .empty;
        var it = el.elementIterator();
        while (it.next()) |c| {
            if (!std.mem.eql(u8, c.local, "LNode")) continue;
            try out.append(self.a, .{
                .ied_name = attrOr(c, "iedName", "None"),
                .ld_inst = attrOr(c, "ldInst", ""),
                .prefix = attrOr(c, "prefix", ""),
                .ln_class = c.attr("", "lnClass") orelse return error.MissingAttribute,
                .ln_inst = attrOr(c, "lnInst", ""),
                .ln_type = attrOr(c, "lnType", ""),
                .desc = attrOr(c, "desc", ""),
            });
        }
        return out.toOwnedSlice(self.a);
    }

    fn terminals(self: *Parser, el: *xml.Element) Error![]const Terminal {
        var out: std.ArrayList(Terminal) = .empty;
        var it = el.elementIterator();
        while (it.next()) |c| {
            if (!std.mem.eql(u8, c.local, "Terminal")) continue;
            try out.append(self.a, .{
                .name = attrOr(c, "name", ""),
                .c_node_name = c.attr("", "cNodeName") orelse return error.MissingAttribute,
                .connectivity_node = c.attr("", "connectivityNode") orelse return error.MissingAttribute,
                .substation_name = attrOr(c, "substationName", ""),
                .voltage_level_name = attrOr(c, "voltageLevelName", ""),
                .bay_name = attrOr(c, "bayName", ""),
                .line_name = attrOr(c, "lineName", ""),
                .desc = attrOr(c, "desc", ""),
            });
        }
        return out.toOwnedSlice(self.a);
    }

    fn equipment(self: *Parser, el: *xml.Element, kind: EquipmentKind) Error!Equipment {
        return .{
            .kind = kind,
            .name = el.attr("", "name") orelse return error.MissingAttribute,
            .desc = attrOr(el, "desc", ""),
            .type = attrOr(el, "type", ""),
            .virtual = boolAttr(el, "virtual", false),
            .terminals = try self.terminals(el),
            .lnodes = try self.lnodeRefs(el),
            .extras = try self.extrasOf(el, &.{ "Terminal", "LNode" }),
        };
    }

    fn powerTransformer(self: *Parser, el: *xml.Element) Error!PowerTransformer {
        var windings: std.ArrayList(Equipment) = .empty;
        var it = el.elementIterator();
        while (it.next()) |c| {
            if (!std.mem.eql(u8, c.local, "TransformerWinding")) continue;
            try windings.append(self.a, try self.equipment(c, .winding));
        }
        return .{
            .name = el.attr("", "name") orelse return error.MissingAttribute,
            .desc = attrOr(el, "desc", ""),
            .type = attrOr(el, "type", "PTR"),
            .virtual = boolAttr(el, "virtual", false),
            .windings = try windings.toOwnedSlice(self.a),
            .terminals = try self.terminals(el),
            .lnodes = try self.lnodeRefs(el),
            .extras = try self.extrasOf(el, &.{ "TransformerWinding", "Terminal", "LNode" }),
        };
    }

    /// The `GeneralEquipment` and `PowerTransformer` children every level of the
    /// single-line diagram may carry.
    fn equipmentChildren(
        self: *Parser,
        el: *xml.Element,
        general: *[]const Equipment,
        transformers: *[]const PowerTransformer,
    ) Error!void {
        var ge: std.ArrayList(Equipment) = .empty;
        var pt: std.ArrayList(PowerTransformer) = .empty;
        var it = el.elementIterator();
        while (it.next()) |c| {
            if (std.mem.eql(u8, c.local, "GeneralEquipment")) {
                try ge.append(self.a, try self.equipment(c, .general));
            } else if (std.mem.eql(u8, c.local, "PowerTransformer")) {
                try pt.append(self.a, try self.powerTransformer(c));
            }
        }
        general.* = try ge.toOwnedSlice(self.a);
        transformers.* = try pt.toOwnedSlice(self.a);
    }

    fn substation(self: *Parser, el: *xml.Element) Error!Substation {
        var out = Substation{ .name = el.attr("", "name") orelse return error.MissingAttribute };
        out.desc = attrOr(el, "desc", "");
        try self.equipmentChildren(el, &out.general_equipment, &out.power_transformers);
        out.lnodes = try self.lnodeRefs(el);
        var levels: std.ArrayList(VoltageLevel) = .empty;
        var it = el.elementIterator();
        while (it.next()) |c| {
            if (!std.mem.eql(u8, c.local, "VoltageLevel")) continue;
            try levels.append(self.a, try self.voltageLevel(c));
        }
        out.voltage_levels = try levels.toOwnedSlice(self.a);
        out.extras = try self.extrasOf(el, &.{ "VoltageLevel", "GeneralEquipment", "PowerTransformer", "LNode" });
        return out;
    }

    fn voltageLevel(self: *Parser, el: *xml.Element) Error!VoltageLevel {
        var out = VoltageLevel{ .name = el.attr("", "name") orelse return error.MissingAttribute };
        out.desc = attrOr(el, "desc", "");
        out.nom_freq = attrOr(el, "nomFreq", "");
        out.num_phases = attrOr(el, "numPhases", "");
        try self.equipmentChildren(el, &out.general_equipment, &out.power_transformers);
        out.lnodes = try self.lnodeRefs(el);
        var bays: std.ArrayList(Bay) = .empty;
        var it = el.elementIterator();
        while (it.next()) |c| {
            if (std.mem.eql(u8, c.local, "Voltage")) {
                out.voltage = .{
                    .value = std.mem.trim(u8, try c.textContent(self.a), " \t\r\n"),
                    .unit = attrOr(c, "unit", "V"),
                    .multiplier = attrOr(c, "multiplier", ""),
                };
            } else if (std.mem.eql(u8, c.local, "Bay")) {
                try bays.append(self.a, try self.bay(c));
            }
        }
        out.bays = try bays.toOwnedSlice(self.a);
        out.extras = try self.extrasOf(el, &.{ "Voltage", "Bay", "GeneralEquipment", "PowerTransformer", "LNode" });
        return out;
    }

    fn bay(self: *Parser, el: *xml.Element) Error!Bay {
        var out = Bay{ .name = el.attr("", "name") orelse return error.MissingAttribute };
        out.desc = attrOr(el, "desc", "");
        try self.equipmentChildren(el, &out.general_equipment, &out.power_transformers);
        out.lnodes = try self.lnodeRefs(el);
        var eq: std.ArrayList(Equipment) = .empty;
        var nodes: std.ArrayList(ConnectivityNode) = .empty;
        var it = el.elementIterator();
        while (it.next()) |c| {
            if (std.mem.eql(u8, c.local, "ConductingEquipment")) {
                try eq.append(self.a, try self.equipment(c, .conducting));
            } else if (std.mem.eql(u8, c.local, "ConnectivityNode")) {
                try nodes.append(self.a, .{
                    .name = c.attr("", "name") orelse return error.MissingAttribute,
                    .path_name = c.attr("", "pathName") orelse return error.MissingAttribute,
                    .desc = attrOr(c, "desc", ""),
                });
            }
        }
        out.equipment = try eq.toOwnedSlice(self.a);
        out.connectivity_nodes = try nodes.toOwnedSlice(self.a);
        out.extras = try self.extrasOf(el, &.{ "ConductingEquipment", "ConnectivityNode", "GeneralEquipment", "PowerTransformer", "LNode" });
        return out;
    }

    fn services(self: *Parser, el: *xml.Element) Error!Services {
        var out: std.ArrayList(Raw) = .empty;
        var it = el.elementIterator();
        while (it.next()) |c| try out.append(self.a, c);
        return .{
            .name_length = attrOr(el, "nameLength", ""),
            .elements = try out.toOwnedSlice(self.a),
        };
    }

    fn inputs(self: *Parser, el: *xml.Element) Error!Inputs {
        var refs: std.ArrayList(ExtRef) = .empty;
        var it = el.elementIterator();
        while (it.next()) |c| {
            if (!std.mem.eql(u8, c.local, "ExtRef")) continue;
            try refs.append(self.a, .{
                .ied_name = attrOr(c, "iedName", ""),
                .ld_inst = attrOr(c, "ldInst", ""),
                .prefix = attrOr(c, "prefix", ""),
                .ln_class = attrOr(c, "lnClass", ""),
                .ln_inst = attrOr(c, "lnInst", ""),
                .do_name = attrOr(c, "doName", ""),
                .da_name = attrOr(c, "daName", ""),
                .int_addr = attrOr(c, "intAddr", ""),
                .desc = attrOr(c, "desc", ""),
                .service_type = attrOr(c, "serviceType", ""),
                .src_ld_inst = attrOr(c, "srcLDInst", ""),
                .src_prefix = attrOr(c, "srcPrefix", ""),
                .src_ln_class = attrOr(c, "srcLNClass", ""),
                .src_ln_inst = attrOr(c, "srcLNInst", ""),
                .src_cb_name = attrOr(c, "srcCBName", ""),
                .p_ln = attrOr(c, "pLN", ""),
                .p_do = attrOr(c, "pDO", ""),
                .p_da = attrOr(c, "pDA", ""),
                .p_serv_t = attrOr(c, "pServT", ""),
            });
        }
        return .{
            .ext_refs = try refs.toOwnedSlice(self.a),
            .extras = try self.extrasOf(el, &.{"ExtRef"}),
        };
    }

    fn smvControl(self: *Parser, c: *xml.Element) Error!SmvControl {
        var out = SmvControl{
            .name = c.attr("", "name") orelse return error.MissingAttribute,
            .desc = attrOr(c, "desc", ""),
            .dat_set = attrOr(c, "datSet", ""),
            .conf_rev = parseU32(attrOr(c, "confRev", "1")) orelse 1,
            .smv_id = attrOr(c, "smvID", ""),
            .multicast = boolAttr(c, "multicast", true),
            .smp_rate = parseU32(attrOr(c, "smpRate", "0")) orelse 0,
            .nof_asdu = parseU32(attrOr(c, "nofASDU", "0")) orelse 0,
            .smp_mod = attrOr(c, "smpMod", "SmpPerPeriod"),
            .security_enable = attrOr(c, "securityEnable", ""),
        };
        var it = c.elementIterator();
        while (it.next()) |o| {
            if (!std.mem.eql(u8, o.local, "SmvOpts")) continue;
            out.opts = .{
                .refresh_time = boolAttr(o, "refreshTime", false),
                .sample_synchronized = boolAttr(o, "sampleSynchronized", false),
                .sample_rate = boolAttr(o, "sampleRate", false),
                .data_set = boolAttr(o, "dataSet", false),
                .security = boolAttr(o, "security", false),
                .timestamp = boolAttr(o, "timestamp", false),
                .synch_source_id = boolAttr(o, "synchSourceId", false),
            };
        }
        out.extras = try self.extrasOf(c, &.{"SmvOpts"});
        return out;
    }

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
                const ap_extras = try self.extrasOf(ap, &.{ "Address", "GSE", "SMV" });
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
                    .extras = ap_extras,
                });
            }
            try out.append(self.a, .{
                .name = attrOr(sub, "name", ""),
                .type = attrOr(sub, "type", ""),
                .desc = attrOr(sub, "desc", ""),
                .aps = try aps.toOwnedSlice(self.a),
                .extras = try self.extrasOf(sub, &.{"ConnectedAP"}),
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
        out.extras = try self.extrasOf(el, &.{ "Address", "MinTime", "MaxTime" });
        return out;
    }

    fn uintText(self: *Parser, el: *xml.Element) Error!?u32 {
        const t = std.mem.trim(u8, try el.textContent(self.a), " \t\r\n");
        return std.fmt.parseInt(u32, t, 10) catch null;
    }

    fn ied(self: *Parser, el: *xml.Element) Error!Ied {
        var aps: std.ArrayList(AccessPoint) = .empty;
        var services_el: ?Services = null;
        var it = el.elementIterator();
        while (it.next()) |ap| {
            if (std.mem.eql(u8, ap.local, "Services")) {
                services_el = try self.services(ap);
                continue;
            }
            if (!std.mem.eql(u8, ap.local, "AccessPoint")) continue;
            var devices: std.ArrayList(LDevice) = .empty;
            var ap_services: ?Services = null;
            var server_extras = Extras{};
            var s = ap.elementIterator();
            while (s.next()) |server| {
                if (std.mem.eql(u8, server.local, "Services")) {
                    ap_services = try self.services(server);
                    continue;
                }
                if (!std.mem.eql(u8, server.local, "Server")) continue;
                server_extras = try self.extrasOf(server, &.{"LDevice"});
                var d = server.elementIterator();
                while (d.next()) |ld| {
                    if (!std.mem.eql(u8, ld.local, "LDevice")) continue;
                    try devices.append(self.a, try self.lDevice(ld));
                }
            }
            try aps.append(self.a, .{
                .name = attrOr(ap, "name", ""),
                .desc = attrOr(ap, "desc", ""),
                .devices = try devices.toOwnedSlice(self.a),
                .services = ap_services,
                .extras = try self.extrasOf(ap, &.{ "Server", "Services" }),
                .server_extras = server_extras,
            });
        }
        return .{
            .name = el.attr("", "name") orelse return error.MissingAttribute,
            .type = attrOr(el, "type", ""),
            .manufacturer = attrOr(el, "manufacturer", ""),
            .config_version = attrOr(el, "configVersion", ""),
            .desc = attrOr(el, "desc", ""),
            .owner = attrOr(el, "owner", ""),
            .access_points = try aps.toOwnedSlice(self.a),
            .services = services_el,
            .extras = try self.extrasOf(el, &.{ "AccessPoint", "Services" }),
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
            .desc = attrOr(el, "desc", ""),
            .lns = try lns.toOwnedSlice(self.a),
            .extras = try self.extrasOf(el, &.{ "LN0", "LN" }),
        };
    }

    fn ln(self: *Parser, el: *xml.Element, is_ln0: bool) Error!Ln {
        var dois: std.ArrayList(Doi) = .empty;
        var sets: std.ArrayList(DataSet) = .empty;
        var rcbs: std.ArrayList(ReportControl) = .empty;
        var gcbs: std.ArrayList(GseControl) = .empty;
        var lcbs: std.ArrayList(LogControl) = .empty;
        var logs: std.ArrayList(Log) = .empty;
        var smvs: std.ArrayList(SmvControl) = .empty;
        var inputs_el: ?Inputs = null;
        var sgcb: ?SettingControl = null;

        var it = el.elementIterator();
        while (it.next()) |c| {
            if (std.mem.eql(u8, c.local, "DOI")) {
                try dois.append(self.a, try self.doi(c));
            } else if (std.mem.eql(u8, c.local, "DataSet")) {
                try sets.append(self.a, try self.dataSet(c));
            } else if (std.mem.eql(u8, c.local, "ReportControl")) {
                try rcbs.append(self.a, try self.reportControl(c));
            } else if (std.mem.eql(u8, c.local, "SampledValueControl")) {
                try smvs.append(self.a, try self.smvControl(c));
            } else if (std.mem.eql(u8, c.local, "Inputs")) {
                inputs_el = try self.inputs(c);
            } else if (std.mem.eql(u8, c.local, "LogControl")) {
                var lcb = LogControl{
                    .name = c.attr("", "name") orelse return error.MissingAttribute,
                    .desc = attrOr(c, "desc", ""),
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
            } else if (std.mem.eql(u8, c.local, "Log")) {
                try logs.append(self.a, .{
                    .name = attrOr(c, "name", ""),
                    .desc = attrOr(c, "desc", ""),
                });
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
                    .desc = attrOr(c, "desc", ""),
                    .extras = try self.extrasOf(c, &.{}),
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
            .logs = try logs.toOwnedSlice(self.a),
            .setting_control = sgcb,
            .smv_controls = try smvs.toOwnedSlice(self.a),
            .inputs = inputs_el,
            .desc = attrOr(el, "desc", ""),
            .extras = try self.extrasOf(el, &.{ "DOI", "DataSet", "ReportControl", "LogControl", "Log", "SettingControl", "GSEControl", "SampledValueControl", "Inputs" }),
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
            .extras = try self.extrasOf(el, &.{"FCDA"}),
        };
    }

    fn reportControl(self: *Parser, el: *xml.Element) Error!ReportControl {
        var out = ReportControl{
            .desc = attrOr(el, "desc", ""),
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
        out.extras = try self.extrasOf(el, &.{ "TrgOps", "OptFields", "RptEnabled" });
        return out;
    }

    fn doi(self: *Parser, el: *xml.Element) Error!Doi {
        var dais: std.ArrayList(Dai) = .empty;
        try self.collectDais(el, "", &dais);
        return .{
            .name = el.attr("", "name") orelse return error.MissingAttribute,
            .desc = attrOr(el, "desc", ""),
            .dais = try dais.toOwnedSlice(self.a),
            .extras = try self.extrasOf(el, &.{ "SDI", "DAI" }),
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
                try self.a.print("{s}.{s}", .{ prefix, name });
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

/// A multicast sampled-value control block (IEC 61850-7-2 §18). `DstAddress`
/// is a structure, like a GOOSE control block's.
pub const default_msvcb_attributes = [_][]const u8{
    "SvEna", "MsvID", "DatSet", "ConfRev", "SmpMod", "SmpRate", "OptFlds", "DstAddress",
};

/// A unicast sampled-value control block: no destination address, but a
/// reservation, because one client at a time owns it.
pub const default_usvcb_attributes = [_][]const u8{
    "SvEna", "UsvID", "DatSet", "ConfRev", "SmpMod", "SmpRate", "OptFlds", "Resv",
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
    var seen = std.EnumSet(Fc).empty;
    for (ln_type.dos) |do_ref| {
        const do_type = scl.templates.doType(do_ref.type) orelse return error.UnresolvedType;
        try collectFcs(scl, do_type, &seen, max_type_depth);
    }
    // The control blocks add their own constraints.
    for (node.report_controls) |rcb| seen.insert(if (rcb.buffered) .BR else .RP);
    for (node.gse_controls) |gcb| {
        seen.insert(if (std.mem.eql(u8, gcb.type, "GSSE")) .GS else .GO);
    }
    for (node.smv_controls) |scb| seen.insert(if (scb.multicast) .MS else .US);
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
            .MS, .US => try resolveSvcbs(ctx, node, fc_name, fc),
            .LG => try resolveLcbs(ctx, node, fc_name),
            .SP => try resolveSgcb(ctx, node, fc_name),
            else => {},
        }

        for (ln_type.dos) |do_ref| {
            const do_type = scl.templates.doType(do_ref.type) orelse return error.UnresolvedType;
            var below = std.EnumSet(Fc).empty;
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
                std.mem.print(&inst_buf, "{s}{d:0>2}", .{ rcb.name, i }) catch
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

fn resolveSvcbs(ctx: *ResolveCtx, node: Ln, fc_name: []const u8, fc: Fc) Error!void {
    const attrs = if (fc == .MS) ctx.scl.options.msvcb_attributes else ctx.scl.options.usvcb_attributes;
    for (node.smv_controls) |scb| {
        if (scb.multicast != (fc == .MS)) continue;
        var scb_buf: [acsi.max_reference_len]u8 = undefined;
        const scb_name = try join(&scb_buf, fc_name, scb.name);
        try emit(ctx, scb_name, fc, null, 2, false, null, "");
        for (attrs) |attr| {
            var attr_buf: [acsi.max_reference_len]u8 = undefined;
            const an = try join(&attr_buf, scb_name, attr);
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
        var below = std.EnumSet(Fc).empty;
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
        const name = try std.mem.print(&buf, "LLN0$RP$EventsRCB01${s}", .{attr});
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
    inline for (@typeInfo(acsi.FunctionalConstraint).@"enum".field_names, @typeInfo(acsi.FunctionalConstraint).@"enum".field_values) |f_name, f_value| {
        const fc = try Fc.parse(f_name);
        try testing.expectEqual(
            @as(?acsi.FunctionalConstraint, @fromBackingInt(@intCast(f_value))),
            fc.toAcsi(),
        );
    }
    // …plus the two edition-2 additions, which the wire naming layer does not
    // model and which therefore map to null rather than to a wrong constraint.
    try testing.expect(Fc.OR.toAcsi() == null);
    try testing.expect(Fc.BL.toAcsi() == null);
    try testing.expect(Fc.SR.toAcsi() == null);
    try testing.expectEqual(@as(usize, 20), @typeInfo(Fc).@"enum".field_names.len);
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

const testkit = @import("testkit");
const fz = @import("fuzz_test.zig");
/// `testkit.fuzz.seed`, aliased so the corpora below read as the documents they
/// are. A corpus entry is not the document: `Smith.slice` reads a little-endian
/// `u32` length first, so a raw document would arrive minus its own first four
/// octets. `testkit/src/fuzz.zig` carries the other two hazards.
const seed = testkit.fuzz.seed;

/// The harness's buffer, at 8 kB rather than the 1 kB it used to be.
///
/// ⚠ This is a finding about the harness, not a preference. `sample` — this
/// module's own reference document, and the only complete SCL it has — is 4065
/// octets, and `Smith.slice` reads a seed longer than the buffer back as the
/// EMPTY one, silently. At 1024 the reference document could not have passed
/// through this harness at all; it would have looked like a seed and behaved
/// like no seed. The same shape emptied three harnesses elsewhere in this tree.
const scl_input_len: usize = 8192;

/// SCL documents, in the format `Smith.slice` reads (see `testkit.fuzz`).
///
/// `parse` refuses anything whose root is not `<SCL>` in the 2003 namespace, so
/// uniform random octets never reach the resolver — which is the half of this
/// harness worth exercising.
const scl_seeds = [_][]const u8{
    seed(sample), // the module's own reference document: two LNs, a control object, an RCB, a GSE
    // The smallest document `resolve` accepts: one IED, one LN, one DO, one DA.
    seed("<SCL xmlns=\"http://www.iec.ch/61850/2003/SCL\"><IED name=\"I\"><AccessPoint name=\"A\"><Server>" ++
        "<LDevice inst=\"LD\"><LN lnClass=\"GGIO\" lnType=\"T1\" inst=\"1\"/></LDevice>" ++
        "</Server></AccessPoint></IED><DataTypeTemplates>" ++
        "<LNodeType id=\"T1\" lnClass=\"GGIO\"><DO name=\"X\" type=\"D1\"/></LNodeType>" ++
        "<DOType id=\"D1\"><DA name=\"v\" bType=\"BOOLEAN\" fc=\"ST\"/></DOType>" ++
        "</DataTypeTemplates></SCL>"),
    // UnresolvedType: the `DOType` the `LNodeType` names is not there.
    seed("<SCL xmlns=\"http://www.iec.ch/61850/2003/SCL\"><IED name=\"I\"><AccessPoint name=\"A\"><Server>" ++
        "<LDevice inst=\"LD\"><LN lnClass=\"GGIO\" lnType=\"T1\" inst=\"1\"/></LDevice>" ++
        "</Server></AccessPoint></IED><DataTypeTemplates>" ++
        "<LNodeType id=\"T1\" lnClass=\"GGIO\"><DO name=\"X\" type=\"NOPE\"/></LNodeType>" ++
        "</DataTypeTemplates></SCL>"),
    // An SCL root with nothing in it at all.
    seed("<SCL xmlns=\"http://www.iec.ch/61850/2003/SCL\"/>"),
    seed("<Envelope xmlns=\"urn:x\"/>"), // NotScl
    // DoctypeForbidden — the XXE the xml sibling's hardening refuses.
    seed("<!DOCTYPE SCL [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>\n" ++
        "<SCL xmlns=\"http://www.iec.ch/61850/2003/SCL\"><Header id=\"&x;\"/></SCL>"),
    seed("<SCL"), // an unterminated start tag
    seed("<"), // one octet
};

test "fuzz: SCL parsing and resolution never panic" {
    try std.testing.fuzz({}, fuzzSclSmith, .{ .corpus = &scl_seeds });
}

const fuzzSclMark = fz.Marker(enum { ran, nonempty });

fn fuzzSclSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzScl(std.testing.Smith, smith, std.testing.allocator);
}

fn fuzzScl(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [scl_input_len]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and `parse` was handed an empty string —
    // which fails, so the resolver below was unreachable.
    const len: usize = fz.drawInput(S, src, &buf, &scl_seeds);
    fuzzSclMark.mark(.ran);
    if (len != 0) fuzzSclMark.mark(.nonempty);
    var s = parse(gpa, buf[0..len], .{ .allow_unknown_btype = true }) catch return;
    defer s.deinit();
    for (s.ieds) |i| {
        var m = resolve(&s, gpa, i.name) catch continue;
        defer m.deinit();
        // Every resolved name must be a legal MMS item id under a domain.
        for (m.nodes) |n| {
            try testing.expect(n.item.len > 0);
            try testing.expect(n.item.len <= acsi.max_reference_len);
        }
    }
}

test "fuzz driver: IEC61850_FUZZ (fuzzScl)" {
    try fz.fuzz_driver.run(fuzzScl, .{ .prefix = "IEC61850_FUZZ", .name = "iec61850-scl-scl" });
}

test "fuzz harness: fuzzScl, 400 seeds, reaches every outcome" {
    try fuzzSclMark.reach(fuzzScl, "iec61850-scl-scl", 400);
}

/// Octets for the type id that gets spliced into the skeleton four times over.
///
/// The harness maps each octet onto an XML name character before use, so what a
/// seed selects is a **length** and a pattern, not a literal id; the comments
/// name the length, which is the axis that matters (an empty id, a one-character
/// id, and one longer than any real `lnType`).
const fragment_seeds = [_][]const u8{
    seed("T1"), // the two-character id the value tests use
    seed("a"), // one character
    seed(""), // the empty id: four empty `id=""` attributes
    seed("GGIO1_stVal_type"), // an ordinary-looking type id
    seed(strRepeat(".", 200)), // 200 octets, all mapping to the same class of character
    seed(strRepeat("\x00\x01\x02\x03", 50)), // 200 octets cycling all four character classes
    seed(strRepeat("\xff", 256)), // the whole buffer: 256 octets, the longest a seed can be
};

test "fuzz: a hostile SCL fragment glued into a valid skeleton never panics" {
    try std.testing.fuzz({}, fuzzFragmentSmith, .{ .corpus = &fragment_seeds });
}

const fuzzFragmentMark = fz.Marker(enum { ran, nonempty });

fn fuzzFragmentSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzFragment(std.testing.Smith, smith, std.testing.allocator);
}

fn fuzzFragment(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var frag: [256]u8 = undefined;
    // ⚠ Same collapse as `fuzzScl`: `n` was 0 for every seed, so the id spliced
    // into the skeleton was always the empty string and this harness rendered
    // exactly one document, for ever.
    const n: usize = fz.drawInput(S, src, &frag, &fragment_seeds);
    fuzzFragmentMark.mark(.ran);
    if (n != 0) fuzzFragmentMark.mark(.nonempty);
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
    defer text.deinit(gpa);
    const rendered = try gpa.print(
        "<SCL xmlns=\"http://www.iec.ch/61850/2003/SCL\"><IED name=\"I\"><AccessPoint name=\"A\"><Server>" ++
            "<LDevice inst=\"LD\"><LN lnClass=\"GGIO\" lnType=\"{s}\" inst=\"1\"/></LDevice>" ++
            "</Server></AccessPoint></IED><DataTypeTemplates>" ++
            "<LNodeType id=\"{s}\" lnClass=\"GGIO\"><DO name=\"X\" type=\"{s}\"/></LNodeType>" ++
            "<DOType id=\"{s}\"><DA name=\"v\" bType=\"BOOLEAN\" fc=\"ST\"/></DOType>" ++
            "</DataTypeTemplates></SCL>",
        .{ id, id, id, id },
    );
    defer gpa.free(rendered);
    var s = parse(gpa, rendered, .{}) catch return;
    defer s.deinit();
    var m = resolve(&s, gpa, "I") catch return;
    defer m.deinit();
}

test "fuzz driver: IEC61850_FUZZ (fuzzFragment)" {
    try fz.fuzz_driver.run(fuzzFragment, .{ .prefix = "IEC61850_FUZZ", .name = "iec61850-scl-fragment" });
}

test "fuzz harness: fuzzFragment, 400 seeds, reaches every outcome" {
    try fuzzFragmentMark.reach(fuzzFragment, "iec61850-scl-fragment", 400);
}

test "corpus: every SCL seed reaches the parser, and the accepted counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment. Two
    // things it holds that no other test does: a seed longer than the harness's
    // buffer reads back EMPTY (`Smith.slice` falls back to the range minimum) —
    // which is precisely why `scl_input_len` is 8192 and not 1024, because
    // `sample` is 4065 octets — and a corpus where nothing is accepted is a
    // corpus that only exercises the refusal path. Acceptance is not reach —
    // `bacnet/service` once scored 19 of 19 because decoding "" is legal there.
    var nonempty: usize = 0;
    var parsed: usize = 0;
    var resolved: usize = 0;
    for (scl_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [scl_input_len]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var s = parse(testing.allocator, buf[0..len], .{ .allow_unknown_btype = true }) catch continue;
        defer s.deinit();
        parsed += 1;
        for (s.ieds) |i| {
            var m = resolve(&s, testing.allocator, i.name) catch continue;
            defer m.deinit();
            resolved += 1;
        }
    }
    try testing.expectEqual(scl_seeds.len, nonempty);
    try testing.expectEqual(@as(usize, 4), parsed);
    try testing.expectEqual(@as(usize, 2), resolved);

    // The fragment corpus is measured by how many of the rendered skeletons the
    // parser accepts: the harness's whole point is that the id is spliced in
    // four times, so an id that breaks the document breaks all four.
    var frag_nonempty: usize = 0;
    var rendered_ok: usize = 0;
    for (fragment_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var frag: [256]u8 = undefined;
        const n: usize = smith.slice(&frag);
        if (n != 0) frag_nonempty += 1;
        for (frag[0..n]) |*c| {
            c.* = switch (c.* % 4) {
                0 => 'a' + (c.* % 26),
                1 => 'A' + (c.* % 26),
                2 => '0' + (c.* % 10),
                else => '_',
            };
        }
        const id = frag[0..n];
        const rendered = try testing.allocator.print(
            "<SCL xmlns=\"http://www.iec.ch/61850/2003/SCL\"><IED name=\"I\"><AccessPoint name=\"A\"><Server>" ++
                "<LDevice inst=\"LD\"><LN lnClass=\"GGIO\" lnType=\"{s}\" inst=\"1\"/></LDevice>" ++
                "</Server></AccessPoint></IED><DataTypeTemplates>" ++
                "<LNodeType id=\"{s}\" lnClass=\"GGIO\"><DO name=\"X\" type=\"{s}\"/></LNodeType>" ++
                "<DOType id=\"{s}\"><DA name=\"v\" bType=\"BOOLEAN\" fc=\"ST\"/></DOType>" ++
                "</DataTypeTemplates></SCL>",
            .{ id, id, id, id },
        );
        defer testing.allocator.free(rendered);
        var s = parse(testing.allocator, rendered, .{}) catch continue;
        defer s.deinit();
        rendered_ok += 1;
    }
    // One seed is the empty id on purpose, and it reads back as the empty slice.
    try testing.expectEqual(fragment_seeds.len - 1, frag_nonempty);
    try testing.expectEqual(@as(usize, 7), rendered_ok);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}

// ── whole-module mutation audit 2026-11-18 (second pass): the parser of untrusted SCL ──

const hdr = "<SCL xmlns=\"http://www.iec.ch/61850/2003/SCL\">";

test "Communication: decoy elements are skipped and every address is read from its own access point" {
    const doc = hdr ++
        \\<Communication>
        \\  <Text>not a subnetwork</Text>
        \\  <SubNetwork name="n1" type="8-MMS">
        \\    <Text>not an access point</Text>
        \\    <ConnectedAP iedName="A" apName="AP1">
        \\      <Address><P type="IP">10.0.0.1</P><Q type="IP">9.9.9.9</Q></Address>
        \\      <GSE ldInst="L1" cbName="g1"><Address><P type="APPID">1000</P></Address></GSE>
        \\      <SMV ldInst="L1" cbName="s1"><Address><P type="APPID">4000</P></Address></SMV>
        \\    </ConnectedAP>
        \\    <ConnectedAP iedName="B" apName="AP1">
        \\      <GSE ldInst="L1" cbName="g1"><Address><P type="APPID">2000</P></Address></GSE>
        \\      <SMV ldInst="L2" cbName="s1"><Address><P type="APPID">5000</P></Address></SMV>
        \\    </ConnectedAP>
        \\  </SubNetwork>
        \\</Communication>
        \\<IED name="A">
        \\  <Services><Server><LDevice inst="GHOSTA"><LN0 lnClass="LLN0" lnType="T"/></LDevice></Server></Services>
        \\  <AccessPoint name="AP1">
        \\    <Services><LDevice inst="GHOSTB"><LN0 lnClass="LLN0" lnType="T"/></LDevice></Services>
        \\    <Server>
        \\      <Authentication/>
        \\      <LDevice inst="L1"><LN0 lnClass="LLN0" lnType="T"/></LDevice>
        \\    </Server>
        \\  </AccessPoint>
        \\</IED>
        \\</SCL>
    ;
    var s = try parse(testing.allocator, doc, .{});
    defer s.deinit();
    try testing.expectEqual(@as(usize, 1), s.subnetworks.len);
    try testing.expectEqual(@as(usize, 2), s.subnetworks[0].aps.len);
    const a = s.subnetworks[0].aps[0];
    try testing.expectEqual(@as(usize, 1), a.address.params.len);
    try testing.expectEqual(@as(usize, 1), a.gse.len);
    try testing.expectEqual(@as(usize, 1), a.smv.len);
    try testing.expectEqualStrings("s1", a.smv[0].cb_name);
    try testing.expectEqual(@as(usize, 1), s.ieds.len);
    try testing.expectEqual(@as(usize, 1), s.ieds[0].access_points.len);
    try testing.expectEqual(@as(usize, 1), s.ieds[0].access_points[0].devices.len);
    try testing.expectEqualStrings("L1", s.ieds[0].access_points[0].devices[0].inst);

    // A control block is found by IED, logical device and name, in GSE and SMV alike.
    try testing.expectEqual(@as(?u16, 1000), s.cbAddress("A", "L1", "g1").?.address.appId());
    try testing.expectEqual(@as(?u16, 2000), s.cbAddress("B", "L1", "g1").?.address.appId());
    try testing.expectEqual(@as(?u16, 4000), s.cbAddress("A", "L1", "s1").?.address.appId());
    try testing.expectEqual(@as(?u16, 5000), s.cbAddress("B", "L2", "s1").?.address.appId());
    try testing.expect(s.cbAddress("B", "L9", "g1") == null);
    try testing.expect(s.cbAddress("B", "L1", "s1") == null);
    try testing.expect(s.cbAddress("B", "L2", "zzz") == null);
    try testing.expect(s.cbAddress("A", "L1", "nope") == null);
}

fn kindOf(comptime body: []const u8) !Kind {
    var s = try parse(testing.allocator, hdr ++ body ++ "</SCL>", .{});
    defer s.deinit();
    return s.kind();
}

test "Scl.kind: a substation with an IED is an SCD, an address makes a CID, nothing makes an ICD" {
    try testing.expectEqual(Kind.scd, try kindOf("<Substation name=\"S\"/><IED name=\"A\"/>"));
    try testing.expectEqual(Kind.scd, try kindOf("<Substation name=\"S\"/><IED name=\"A\"/><IED name=\"B\"/>"));
    try testing.expectEqual(Kind.unknown, try kindOf("<Substation name=\"S\"/>"));
    try testing.expectEqual(Kind.unknown, try kindOf("<IED name=\"A\"/><IED name=\"B\"/>"));
    const ap = "<Communication><SubNetwork name=\"n\"><ConnectedAP iedName=\"A\" apName=\"p\">";
    const end = "</ConnectedAP></SubNetwork></Communication><IED name=\"A\"/>";
    try testing.expectEqual(Kind.icd, try kindOf(ap ++ end));
    try testing.expectEqual(Kind.icd, try kindOf(ap ++ "<Address><P type=\"IP\"></P></Address>" ++ end));
    try testing.expectEqual(Kind.cid, try kindOf(ap ++ "<Address><P type=\"IP\">10.0.0.1</P></Address>" ++ end));
    try testing.expectEqual(Kind.cid, try kindOf(ap ++ "<GSE ldInst=\"L\" cbName=\"g\"/>" ++ end));
    try testing.expectEqual(Kind.cid, try kindOf(ap ++ "<SMV ldInst=\"L\" cbName=\"s\"/>" ++ end));
}

test "the logical-node level parses its control blocks, flags and values exactly" {
    const doc = hdr ++
        \\<IED name="TESTIED"><AccessPoint name="AP1"><Server><LDevice inst="LD">
        \\  <LN0 lnClass="LLN0" lnType="T0" inst="">
        \\    <DataSet name="DS"><Text>decoy</Text><FCDA ldInst="LD" lnClass="LLN0" fc="ST" doName="Beh" daName="stVal"/></DataSet>
        \\    <ReportControl name="R1" buffered="1" indexed="0"><RptEnabled max="0"/></ReportControl>
        \\    <ReportControl name="R2" buffered="false" indexed="false"><TrgOps dchg="1" gi="0"/></ReportControl>
        \\    <LogControl name="L1" logName="x"><TrgOps dchg="true"/><Text>decoy</Text></LogControl>
        \\    <SettingControl numOfSGs="4" actSG="2"/>
        \\    <DOI name="Beh"><DAI name="stVal"><Val>5</Val><Text>decoy</Text></DAI></DOI>
        \\  </LN0>
        \\</LDevice></Server></AccessPoint></IED>
        \\<DataTypeTemplates>
        \\  <LNodeType id="T0" lnClass="LLN0"><Text/><DO name="Beh" type="D0"/></LNodeType>
        \\  <DOType id="D0"><DA name="stVal" bType="INT32" fc="ST"><Text>x</Text><Val>7</Val></DA><DA name="a" bType="Struct" type="Z" fc="ST"/></DOType>
        \\  <DAType id="Z"><Text/><BDA name="q" bType="BOOLEAN"/></DAType>
        \\  <EnumType id="E"><Text>x</Text><EnumVal ord="3">  three </EnumVal></EnumType>
        \\</DataTypeTemplates>
        \\</SCL>
    ;
    var s = try parse(testing.allocator, doc, .{});
    defer s.deinit();
    const ln0 = s.ieds[0].access_points[0].devices[0].lns[0];
    try testing.expectEqual(@as(usize, 1), ln0.data_sets[0].fcdas.len);
    try testing.expectEqual(@as(usize, 2), ln0.report_controls.len);
    const r1 = ln0.report_controls[0];
    try testing.expect(r1.buffered);
    try testing.expect(!r1.indexed);
    try testing.expectEqual(@as(u8, 1), r1.max_instances);
    const r2 = ln0.report_controls[1];
    try testing.expect(!r2.buffered);
    try testing.expect(!r2.indexed);
    try testing.expect(r2.trg_ops.dchg);
    try testing.expect(!r2.trg_ops.gi);
    try testing.expect(ln0.log_controls[0].trg_ops.dchg);
    try testing.expectEqual(@as(u8, 4), ln0.setting_control.?.num_of_sgs);
    try testing.expectEqual(@as(u8, 2), ln0.setting_control.?.act_sg);
    const dai = ln0.dois[0].dais[0];
    try testing.expectEqual(@as(usize, 1), dai.values.len);
    try testing.expectEqualStrings("5", dai.first().?);
    try testing.expectEqual(@as(usize, 1), s.templates.ln_types[0].dos.len);
    try testing.expectEqualStrings("7", s.templates.do_types[0].das[0].val.?);
    try testing.expectEqual(@as(usize, 1), s.templates.da_types[0].bdas.len);
    try testing.expectEqual(@as(usize, 1), s.templates.enum_types[0].vals.len);
    try testing.expectEqualStrings("three", s.templates.enum_types[0].vals[0].text);
}

test "Fcda.mmsItem, Dai.first, Ln.mmsName, LDevice.domain and joinDots at their buffer bounds" {
    const f = Fcda{
        .ld_inst = "LD",
        .prefix = "pre",
        .ln_class = "GGIO",
        .ln_inst = "1",
        .do_name = "Ind..Sub",
        .da_name = "a..b",
        .fc = .ST,
    };
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("preGGIO1$ST$Ind$Sub$a$b", try f.mmsItem(&buf));
    var exact: [23]u8 = undefined;
    try testing.expectEqualStrings("preGGIO1$ST$Ind$Sub$a$b", try f.mmsItem(&exact));
    var short: [22]u8 = undefined;
    try testing.expectError(error.NameTooLong, f.mmsItem(&short));

    try testing.expect((Dai{ .path = "p" }).first() == null);

    const ln = Ln{ .prefix = "P", .ln_class = "GGIO", .inst = "1", .ln_type = "T" };
    try testing.expectEqualStrings("PGGIO1", try ln.mmsName(&buf));

    const named = LDevice{ .inst = "I", .ld_name = "MyLD" };
    try testing.expectEqualStrings("MyLD", try named.domain("IED", &buf));
    var four: [4]u8 = undefined;
    try testing.expectEqualStrings("MyLD", try named.domain("IED", &four));
    var three: [3]u8 = undefined;
    try testing.expectError(error.NameTooLong, named.domain("IED", &three));
    const plain = LDevice{ .inst = "I" };
    try testing.expectEqualStrings("IEDI", try plain.domain("IED", &buf));

    var b129: [129]u8 = undefined;
    const long: [130]u8 = @splat('x');
    try testing.expectEqual(@as(usize, 129), (try joinDots(&b129, "", long[0..129])).len);
    try testing.expectError(error.NameTooLong, joinDots(&b129, "", &long));
}

/// Two logical devices of one IED. `LD1` has a setting-group control block (so
/// it mirrors `SE` to `SG`) and every kind of control block; `LD2` has none of
/// them and must not inherit anything.
const resolve_doc = hdr ++
    \\<IED name="TESTIED"><AccessPoint name="AP1"><Server>
    \\<LDevice inst="LD1">
    \\  <LN0 lnClass="LLN0" lnType="T0" inst="">
    \\    <DataSet name="DS"><FCDA ldInst="LD2" lnClass="GGIO" lnInst="1" fc="ST" doName="Ind" daName="stVal"/></DataSet>
    \\    <ReportControl name="BRCB" buffered="true"/>
    \\    <ReportControl name="URCB" buffered="false"/>
    \\    <GSEControl name="goose1" type="GOOSE"/>
    \\    <GSEControl name="gsse1" type="GSSE"/>
    \\    <LogControl name="lcb1"/>
    \\    <SettingControl numOfSGs="3" actSG="1"/>
    \\    <DOI name="DoA"><DAI name="n"><Val>1</Val></DAI></DOI>
    \\    <DOI name="DoB"><DAI name="n"><Val>2</Val></DAI></DOI>
    \\  </LN0>
    \\  <LN lnClass="GGIO" lnType="TG" inst="1"/>
    \\  <LN lnClass="GGIO" lnType="TP" inst="2"/>
    \\</LDevice>
    \\<LDevice inst="LD2">
    \\  <LN0 lnClass="LLN0" lnType="T0" inst=""/>
    \\  <LN lnClass="GGIO" lnType="TG" inst="1"/>
    \\  <LN lnClass="GGIO" lnType="TS" inst="2"/>
    \\</LDevice>
    \\</Server></AccessPoint></IED>
    \\<DataTypeTemplates>
    \\  <LNodeType id="T0" lnClass="LLN0"><DO name="Beh" type="INS"/><DO name="Set" type="SET"/><DO name="DoA" type="NN"/><DO name="DoB" type="NN"/></LNodeType>
    \\  <LNodeType id="TG" lnClass="GGIO"><DO name="Ind" type="INS"/></LNodeType>
    \\  <LNodeType id="TP" lnClass="GGIO"><DO name="Sp" type="SPD"/></LNodeType>
    \\  <LNodeType id="TS" lnClass="GGIO"><DO name="Sx" type="SEO"/></LNodeType>
    \\  <DOType id="SEO" cdc="ASG"><DA name="x" bType="INT32" fc="SE"/></DOType>
    \\  <DOType id="INS" cdc="INS"><DA name="stVal" bType="INT32" fc="ST"/></DOType>
    \\  <DOType id="NN" cdc="ING"><DA name="n" bType="INT32" fc="CF"/></DOType>
    \\  <DOType id="SPD" cdc="ASG"><DA name="setVal" bType="INT32" fc="SP"/></DOType>
    \\  <DOType id="SET" cdc="ASG">
    \\    <DA name="x" bType="INT32" fc="SE"/>
    \\    <DA name="y" bType="INT32" fc="SE"/>
    \\    <DA name="y" bType="INT32" fc="SG"/>
    \\    <DA name="z" bType="INT32" fc="SG"/>
    \\    <SDO name="deep" type="SUB"/>
    \\    <SDO name="arr" type="SUB" count="3"/>
    \\    <SDO name="plain" type="INS"/>
    \\  </DOType>
    \\  <DOType id="SUB"><DA name="v" bType="INT32" fc="SE"/></DOType>
    \\</DataTypeTemplates>
    \\</SCL>
;

test "resolve: functional constraints, control blocks and the SE to SG mirror, per logical device" {
    var s = try parse(testing.allocator, resolve_doc, .{});
    defer s.deinit();
    var m = try resolve(&s, testing.allocator, "TESTIED");
    defer m.deinit();
    const d1 = "TESTIEDLD1";
    const d2 = "TESTIEDLD2";

    // Report control blocks sit under their own constraint, with their own attributes.
    try testing.expect(m.has(d1, "LLN0$BR$BRCB01"));
    try testing.expect(m.has(d1, "LLN0$BR$BRCB01$EntryID"));
    try testing.expect(m.has(d1, "LLN0$RP$URCB01$Resv"));
    try testing.expect(!m.has(d1, "LLN0$RP$URCB01$EntryID"));
    try testing.expect(!m.has(d1, "LLN0$RP$BRCB01"));
    try testing.expect(!m.has(d1, "LLN0$BR$URCB01"));
    // GOOSE and GSSE blocks are told apart, and only DstAddress has members.
    try testing.expect(m.has(d1, "LLN0$GO$goose1"));
    try testing.expect(m.has(d1, "LLN0$GS$gsse1"));
    try testing.expect(!m.has(d1, "LLN0$GO$gsse1"));
    try testing.expect(!m.has(d1, "LLN0$GS$goose1"));
    try testing.expect(m.has(d1, "LLN0$GO$goose1$DstAddress$Addr"));
    try testing.expect(!m.has(d1, "LLN0$GO$goose1$GoID$Addr"));
    // A log control block adds LG, and only where there is one.
    try testing.expect(m.has(d1, "LLN0$LG$lcb1"));
    try testing.expect(!m.has(d1, "GGIO1$LG"));
    // The setting-group block lives under SP; an SP attribute alone does not make one.
    try testing.expect(m.has(d1, "LLN0$SP$SGCB"));
    try testing.expect(m.has(d1, "LLN0$SP$SGCB$NumOfSG"));
    try testing.expect(m.has(d1, "GGIO2$SP$Sp$setVal"));
    try testing.expect(!m.has(d1, "GGIO2$SP$SGCB"));
    // A data object appears only under a constraint it has attributes in.
    try testing.expect(m.has(d1, "LLN0$ST$Beh$stVal"));
    try testing.expect(!m.has(d1, "LLN0$RP$Beh"));
    try testing.expect(!m.has(d1, "LLN0$SE$Beh"));
    // SE mirrored to SG where the device has an SGCB: once per name, and only for LN0's SE.
    try testing.expect(m.has(d1, "LLN0$SE$Set$x"));
    try testing.expect(m.has(d1, "LLN0$SG$Set$x"));
    try testing.expect(m.has(d1, "LLN0$SG$Set$z"));
    var y_sg: usize = 0;
    for (m.nodes) |n| {
        if (std.mem.eql(u8, n.domain, d1) and std.mem.eql(u8, n.item, "LLN0$SG$Set$y")) y_sg += 1;
    }
    try testing.expectEqual(@as(usize, 1), y_sg);
    try testing.expect(!m.has(d1, "GGIO1$SG"));
    // SDOs: a nested one opens up, an array is one leaf, one without the constraint is absent.
    try testing.expect(!m.find(d1, "LLN0$SE$Set$deep").?.leaf);
    try testing.expect(m.has(d1, "LLN0$SE$Set$deep$v"));
    try testing.expect(m.find(d1, "LLN0$SE$Set$arr").?.leaf);
    try testing.expect(!m.has(d1, "LLN0$SE$Set$arr$v"));
    try testing.expect(!m.has(d1, "LLN0$SE$Set$plain"));
    // The configured value belongs to its own data object.
    try testing.expectEqualStrings("1", m.find(d1, "LLN0$CF$DoA$n").?.value.?);
    try testing.expectEqualStrings("2", m.find(d1, "LLN0$CF$DoB$n").?.value.?);

    // LD2 has no setting-group control block: nothing is mirrored there, and a
    // lookup names its own device.
    try testing.expect(m.has(d2, "LLN0$SE$Set$x"));
    try testing.expect(m.has(d2, "LLN0$SG$Set$z")); // declared, so written
    try testing.expect(!m.has(d2, "LLN0$SG$Set$x"));
    try testing.expect(!m.has(d2, "LLN0$SG$Set$deep$v"));
    try testing.expect(m.has(d2, "GGIO2$SE$Sx$x"));
    try testing.expect(!m.has(d2, "GGIO2$SG"));
    try testing.expect(m.has(d1, "LLN0$SG$Set$deep$v"));
    try testing.expectEqualStrings(d2, m.find(d2, "LLN0$ST$Beh$stVal").?.domain);
    try testing.expectEqualStrings(d1, m.find(d1, "LLN0$ST$Beh$stVal").?.domain);
    var leaves: usize = 0;
    for (m.nodes) |n| {
        if (n.leaf) leaves += 1;
    }
    try testing.expect(leaves > 0);
    try testing.expectEqual(leaves, m.leafCount());
}

test "an FCDA that names no logical device must resolve in its own, and one that names another is left alone" {
    const base = hdr ++
        \\<IED name="TESTIED"><AccessPoint name="AP1"><Server><LDevice inst="LD">
        \\<LN0 lnClass="LLN0" lnType="T0" inst="">
        \\<DataSet name="DS">
    ;
    const tail =
        \\</DataSet></LN0></LDevice></Server></AccessPoint></IED>
        \\<DataTypeTemplates>
        \\<LNodeType id="T0" lnClass="LLN0"><DO name="Beh" type="INS"/></LNodeType>
        \\<DOType id="INS"><DA name="stVal" bType="INT32" fc="ST"/></DOType>
        \\</DataTypeTemplates></SCL>
    ;
    // No ldInst, naming something that is not there: refused.
    try testing.expectError(error.UnresolvedFcda, resolveText(base ++
        "<FCDA lnClass=\"GGIO\" lnInst=\"9\" fc=\"ST\" doName=\"Ind\" daName=\"stVal\"/>" ++ tail));
    // Another logical device is named: not checked here.
    try resolveText(base ++
        "<FCDA ldInst=\"OTHER\" lnClass=\"GGIO\" lnInst=\"9\" fc=\"ST\" doName=\"Ind\" daName=\"stVal\"/>" ++ tail);
    // Its own, and present: fine.
    try resolveText(base ++
        "<FCDA ldInst=\"LD\" lnClass=\"LLN0\" fc=\"ST\" doName=\"Beh\" daName=\"stVal\"/>" ++ tail);
}

fn checkOne(a: std.mem.Allocator, b_type: []const u8, type_attr: []const u8, extra: []const u8, val: []const u8) !void {
    const text = try std.fmt.allocPrint(a,
        \\<SCL xmlns="http://www.iec.ch/61850/2003/SCL"><IED name="TESTIED"><AccessPoint name="AP1"><Server>
        \\<LDevice inst="LD"><LN lnClass="GGIO" lnType="T1" inst="1"><DOI name="X"><DAI name="v"><Val>{s}</Val></DAI></DOI></LN></LDevice>
        \\</Server></AccessPoint></IED><DataTypeTemplates>
        \\<LNodeType id="T1" lnClass="GGIO"><DO name="X" type="D1"/></LNodeType>
        \\<DOType id="D1"><DA name="v" bType="{s}"{s} fc="CF"/></DOType>{s}
        \\</DataTypeTemplates></SCL>
    , .{ val, b_type, type_attr, extra });
    defer a.free(text);
    try resolveText(text);
}

test "a DAI value is checked against the exact range and length of its bType" {
    const a = testing.allocator;
    const ok = [_][2][]const u8{
        .{ "INT8U", "0" },        .{ "INT8U", "255" },                                    .{ "INT8", "-128" }, .{ "INT8", "127" },
        .{ "INT16U", "65535" },   .{ "INT32", "-2147483648" },                            .{ "BOOLEAN", "1" }, .{ "BOOLEAN", "0" },
        .{ "FLOAT32", "-1.5e3" }, .{ "VisString32", "12345678901234567890123456789012" },
    };
    for (ok) |c| try checkOne(a, c[0], "", "", c[1]);
    const bad = [_][2][]const u8{
        .{ "INT8U", "256" },    .{ "INT8U", "-1" },    .{ "INT8", "128" },    .{ "INT8", "-129" },
        .{ "INT16U", "65536" }, .{ "BOOLEAN", "yes" }, .{ "FLOAT32", "one" }, .{ "VisString32", "123456789012345678901234567890123" },
    };
    for (bad) |c| try testing.expectError(error.ValueTypeMismatch, checkOne(a, c[0], "", "", c[1]));
    // Octet64: 64 characters is the longest.
    const o64: [64]u8 = @splat('o');
    const o65: [65]u8 = @splat('o');
    try checkOne(a, "Octet64", "", "", &o64);
    try testing.expectError(error.ValueTypeMismatch, checkOne(a, "Octet64", "", "", &o65));
    // Dbpos names, and an Enum that names no enumeration accepts anything.
    try checkOne(a, "Dbpos", "", "", "on");
    try checkOne(a, "Dbpos", "", "", "intermediate-state");
    try testing.expectError(error.ValueTypeMismatch, checkOne(a, "Dbpos", "", "", "sideways"));
    try checkOne(a, "Enum", "", "", "whatever");
}

test "the type graph is bounded at max_type_depth structure levels, not one more" {
    const a = testing.allocator;
    for ([_]usize{ max_type_depth, max_type_depth + 1 }) |levels| {
        var types: std.ArrayList(u8) = .empty;
        defer types.deinit(a);
        for (0..levels) |i| {
            if (i + 1 < levels) {
                try types.print(a, "<DAType id=\"S{d}\"><BDA name=\"c\" bType=\"Struct\" type=\"S{d}\"/></DAType>", .{ i, i + 1 });
            } else {
                try types.print(a, "<DAType id=\"S{d}\"><BDA name=\"c\" bType=\"BOOLEAN\"/></DAType>", .{i});
            }
        }
        const text = try std.fmt.allocPrint(a,
            \\<SCL xmlns="http://www.iec.ch/61850/2003/SCL"><IED name="TESTIED"><AccessPoint name="AP1"><Server>
            \\<LDevice inst="LD"><LN lnClass="GGIO" lnType="T1" inst="1"/></LDevice></Server></AccessPoint></IED>
            \\<DataTypeTemplates><LNodeType id="T1" lnClass="GGIO"><DO name="X" type="D1"/></LNodeType>
            \\<DOType id="D1"><DA name="s" bType="Struct" type="S0" fc="ST"/></DOType>{s}</DataTypeTemplates></SCL>
        , .{types.items});
        defer a.free(text);
        if (levels <= max_type_depth) {
            try resolveText(text);
        } else {
            try testing.expectError(error.TypeTooDeep, resolveText(text));
        }
    }
}

test "a PhyComAddr and an array attribute are each one name with the members the standard gives them" {
    const text = wrap(
        \\<LNodeType id="T1" lnClass="GGIO"><DO name="X" type="D1"/></LNodeType>
        \\<DOType id="D1"><DA name="addr" bType="PhyComAddr" fc="ST"/><DA name="arr" bType="Struct" type="Z" count="4" fc="ST"/></DOType>
        \\<DAType id="Z"><BDA name="q" bType="BOOLEAN"/></DAType>
    , "");
    var s = try parse(testing.allocator, text, .{});
    defer s.deinit();
    var m = try resolve(&s, testing.allocator, "TESTIED");
    defer m.deinit();
    try testing.expectEqual(BType.PhyComAddr, m.find("TESTIEDLD", "GGIO1$ST$X$addr").?.b_type.?);
    try testing.expect(!m.find("TESTIEDLD", "GGIO1$ST$X$addr").?.leaf);
    for (phy_com_addr_members) |member| {
        var item_buf: [64]u8 = undefined;
        const item = try std.mem.print(&item_buf, "GGIO1$ST$X$addr${s}", .{member});
        try testing.expect(m.find("TESTIEDLD", item).?.leaf);
    }
    try testing.expect(m.find("TESTIEDLD", "GGIO1$ST$X$arr").?.leaf);
    try testing.expect(!m.has("TESTIEDLD", "GGIO1$ST$X$arr$q"));
}

test "Model.sboClass reads the configured value, and an object without one has none" {
    const src = hdr ++
        \\<IED name="A"><AccessPoint name="P"><Server><LDevice inst="LD">
        \\  <LN0 lnClass="LLN0" lnType="L"/>
        \\  <LN lnClass="GGIO" inst="1" lnType="G">
        \\    <DOI name="SPCSO1"><DAI name="sboClass"><Val>operate-many</Val></DAI></DOI>
        \\  </LN>
        \\</LDevice></Server></AccessPoint></IED>
        \\<DataTypeTemplates>
        \\  <LNodeType id="L" lnClass="LLN0"/>
        \\  <LNodeType id="G" lnClass="GGIO"><DO name="SPCSO1" type="SPC"/><DO name="SPCSO2" type="SPC"/></LNodeType>
        \\  <DOType id="SPC" cdc="SPC"><DA name="sboClass" fc="CF" bType="Enum" type="SboClasses"/></DOType>
        \\  <EnumType id="SboClasses"><EnumVal ord="0">operate-once</EnumVal><EnumVal ord="1">operate-many</EnumVal></EnumType>
        \\</DataTypeTemplates></SCL>
    ;
    var s = try parse(testing.allocator, src, .{});
    defer s.deinit();
    var m = try resolve(&s, testing.allocator, "A");
    defer m.deinit();
    try testing.expectEqual(@as(?control.SboClass, .operate_many), m.sboClass("ALD", "GGIO1$CO$SPCSO1"));
    try testing.expectEqual(@as(?control.SboClass, null), m.sboClass("ALD", "GGIO1$CO$SPCSO2"));
    try testing.expectEqual(@as(?control.SboClass, null), m.sboClass("ALD", "GGIO1"));
}
