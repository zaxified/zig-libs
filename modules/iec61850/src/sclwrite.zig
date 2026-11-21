// SPDX-License-Identifier: MIT

//! **Emitting SCL** (IEC 61850-6) — the other direction of `scl.zig`.
//!
//! `scl.parse` turns a configuration file into a tree and `scl.resolve` turns
//! that tree into the flat list of MMS names an IED serves. This file turns the
//! tree back into a document, which is what lets a tool built on this module
//! *produce* an `.icd` or a `.cid` rather than only consume one.
//!
//! The claim is deliberately narrow and the test that backs it is a **round
//! trip through the resolver**: parse a file, emit it, parse the emission, and
//! assert the two resolved name spaces are identical, name for name. A writer
//! whose output re-parses to a different name space is worse than no writer,
//! because the difference only shows up when a client cannot find an object.
//!
//! What is emitted: `Header`, `Communication` (subnetworks, connected access
//! points, addresses, `GSE`/`SMV` with their `MinTime`/`MaxTime`), every `IED`
//! with its access points, logical devices, logical nodes, data sets, report /
//! log / setting-group / GOOSE control blocks and instance values, and the whole
//! `DataTypeTemplates` section.
//!
//! Also emitted: the `Substation` section, `Services`, `Inputs`/`ExtRef`,
//! `SampledValueControl`, the `desc` of the nodes and control blocks, and every
//! `Text`/`Private` (and any other element the model has no field for) that
//! `scl.zig` carried verbatim in an `Extras`. What is still the writer's own:
//! attribute order, whitespace, comments and processing instructions, and an
//! attribute that no field models (`emitParsed` cannot tell it was there).
//!
//! Two structural notes:
//!
//! * A `DAI` path like `origin.orCat` is written back as nested `SDI` elements,
//!   which is the only form the schema allows. Sibling `DAI`s that share a
//!   prefix each get their own `SDI` chain — legal (`SDI` is unbounded) and
//!   round-trip exact, but not the most compact rendering a human would write.
//! * A **cyclic type graph** (`DAType` → `BDA` of `Struct` → the same `DAType`)
//!   is refused with `error.CyclicType` before a single octet is written. The
//!   emitter itself walks flat lists and could not loop, but a document with a
//!   cycle in it is a trap for every tool downstream, so it is not produced.

const std = @import("std");
const xml = @import("xml");
const scl = @import("scl.zig");

pub const Error = error{
    OutOfMemory,
    /// The type graph contains a cycle, or nests deeper than the bound.
    CyclicType,
    /// A name or value contains a character that cannot appear in XML at all.
    IllegalCharacter,
    /// The document carries sections this writer does not model.
    LossyDocument,
};

/// How deep the type graph may nest before it is treated as a cycle. Matches
/// `scl.max_type_depth`, so a document this writer emits is one the sibling
/// resolver can walk.
pub const max_type_depth: u8 = scl.max_type_depth;

pub const Options = struct {
    /// The SCL namespace to declare. Null means **the source document's own**
    /// when there is one, and edition 2 (`2007`) otherwise.
    ///
    /// This is not cosmetic. A tool reading the emission decides which edition's
    /// schema defaults to apply from this URI, so re-namespacing an edition-1
    /// file to edition 2 silently changes what its omitted attributes mean.
    namespace: ?[]const u8 = null,
    /// Indent nested elements. Off produces one line per element with no
    /// leading whitespace, which is what a diffing tool wants.
    indent: bool = true,
    /// Refuse a type graph with a cycle rather than writing it out.
    check_types: bool = true,
    /// Retained for source compatibility; it has no effect. Before the
    /// `Substation` section was modelled, `emitParsed` refused a document that
    /// had one unless this was set.
    allow_lossy: bool = false,
};

/// Everything this writer serialises. Taking the parts rather than an `Scl`
/// keeps the emitter testable with a hand-built model — including a hostile one.
pub const Document = struct {
    header: scl.Header = .{},
    subnetworks: []const scl.Subnetwork = &.{},
    ieds: []const scl.Ied = &.{},
    templates: scl.Templates = .{},
    substations: []const scl.Substation = &.{},
    /// The `SCL` element's `version`, `revision` and `release`.
    version: []const u8 = "",
    revision: []const u8 = "",
    release: []const u8 = "",
    /// Prefixed namespace declarations to put on the root.
    extra_namespaces: []const xml.NsDecl = &.{},
    extras: scl.Extras = .{},
    comm_extras: scl.Extras = .{},
};

/// Serialises a parsed document, `Substation` section and all. The caller owns
/// the returned bytes. `LossyDocument` is no longer returned (see
/// `Options.allow_lossy`).
pub fn emitParsed(gpa: std.mem.Allocator, s: *const scl.Scl, options: Options) Error![]u8 {
    var o = options;
    if (o.namespace == null and s.doc.root.uri.len > 0) o.namespace = s.doc.root.uri;
    return emit(gpa, .{
        .header = s.header,
        .subnetworks = s.subnetworks,
        .ieds = s.ieds,
        .templates = s.templates,
        .substations = s.substations,
        .version = s.version,
        .revision = s.revision,
        .release = s.release,
        .extra_namespaces = s.extra_namespaces,
        .extras = s.extras,
        .comm_extras = s.comm_extras,
    }, o);
}

/// Serialises a model. The caller owns the returned bytes.
pub fn emit(gpa: std.mem.Allocator, doc: Document, options: Options) Error![]u8 {
    if (options.check_types) try checkTypeGraph(doc.templates);

    var w = Writer{ .gpa = gpa, .options = options };
    errdefer w.buf.deinit(gpa);

    try w.raw("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    w.extra_namespaces = doc.extra_namespaces;
    try w.raw("<SCL xmlns=\"");
    try w.text(options.namespace orelse scl.ns_2007);
    try w.raw("\"");
    for (doc.extra_namespaces) |d| {
        try w.raw(" xmlns:");
        try w.raw(d.prefix);
        try w.raw("=\"");
        try w.attrValue(d.uri);
        try w.raw("\"");
    }
    try w.attrIf("version", doc.version);
    try w.attrIf("revision", doc.revision);
    try w.attrIf("release", doc.release);
    try w.raw(">\n");
    w.depth = 1;

    try w.rawAll(doc.extras.head);
    try w.open("Header");
    try w.attr("id", doc.header.id);
    try w.attrIf("version", doc.header.version);
    try w.attrIf("revision", doc.header.revision);
    try w.attrIf("toolID", doc.header.tool_id);
    try w.attrIf("nameStructure", doc.header.name_structure);
    try w.closeExtras(doc.header.extras, "Header");

    for (doc.substations) |sub| try emitSubstation(&w, sub);

    if (doc.subnetworks.len > 0 or !doc.comm_extras.isEmpty()) {
        try w.openDone("Communication");
        try w.rawAll(doc.comm_extras.head);
        for (doc.subnetworks) |sub| try emitSubnetwork(&w, sub);
        try w.rawAll(doc.comm_extras.tail);
        try w.end("Communication");
    }

    for (doc.ieds) |ied| try emitIed(&w, ied);
    try emitTemplates(&w, doc.templates);
    try w.rawAll(doc.extras.tail);

    w.depth = 0;
    try w.raw("</SCL>\n");
    return w.buf.toOwnedSlice(gpa);
}

// ── the cycle check ─────────────────────────────────────────────────────────

/// Walks `DOType` → `SDO`/`DA` → `DAType` → `BDA` and refuses a graph that
/// re-enters a type already on the path. A depth bound alone is not enough: a
/// two-node cycle would produce twelve levels of plausible-looking output before
/// anything noticed.
pub fn checkTypeGraph(t: scl.Templates) Error!void {
    var path: [max_type_depth][]const u8 = undefined;
    for (t.ln_types) |ln| {
        for (ln.dos) |d| try walkDo(t, d.type, &path, 0);
    }
    // A DOType or DAType nobody references still has to be sound: a later edit
    // could point at it.
    for (t.do_types) |d| try walkDo(t, d.id, &path, 0);
    for (t.da_types) |d| try walkDa(t, d.id, &path, 0);
}

fn onPath(path: []const []const u8, id: []const u8) bool {
    for (path) |p| {
        if (std.mem.eql(u8, p, id)) return true;
    }
    return false;
}

fn walkDo(t: scl.Templates, id: []const u8, path: *[max_type_depth][]const u8, depth: u8) Error!void {
    if (depth >= max_type_depth) return error.CyclicType;
    if (onPath(path[0..depth], id)) return error.CyclicType;
    const dt = t.doType(id) orelse return;
    path[depth] = id;
    for (dt.sdos) |s| try walkDo(t, s.type, path, depth + 1);
    for (dt.das) |d| {
        if (d.b_type == .Struct and d.type.len > 0) try walkDa(t, d.type, path, depth + 1);
    }
}

fn walkDa(t: scl.Templates, id: []const u8, path: *[max_type_depth][]const u8, depth: u8) Error!void {
    if (depth >= max_type_depth) return error.CyclicType;
    if (onPath(path[0..depth], id)) return error.CyclicType;
    const dt = t.daType(id) orelse return;
    path[depth] = id;
    for (dt.bdas) |b| {
        if (b.b_type == .Struct and b.type.len > 0) try walkDa(t, b.type, path, depth + 1);
    }
}

// ── the sections ────────────────────────────────────────────────────────────

fn emitSubstation(w: *Writer, sub: scl.Substation) Error!void {
    try w.open("Substation");
    try w.attr("name", sub.name);
    try w.attrIf("desc", sub.desc);
    const empty = sub.voltage_levels.len == 0 and sub.general_equipment.len == 0 and
        sub.power_transformers.len == 0 and sub.lnodes.len == 0 and sub.extras.isEmpty();
    if (empty) return w.closeEmpty();
    try w.closeOpen();
    try w.rawAll(sub.extras.head);
    for (sub.power_transformers) |p| try emitPowerTransformer(w, p);
    for (sub.general_equipment) |e| try emitEquipment(w, e);
    for (sub.lnodes) |l| try emitLNode(w, l);
    for (sub.voltage_levels) |v| try emitVoltageLevel(w, v);
    try w.rawAll(sub.extras.tail);
    try w.end("Substation");
}

fn emitVoltageLevel(w: *Writer, v: scl.VoltageLevel) Error!void {
    try w.open("VoltageLevel");
    try w.attr("name", v.name);
    try w.attrIf("desc", v.desc);
    try w.attrIf("nomFreq", v.nom_freq);
    try w.attrIf("numPhases", v.num_phases);
    const empty = v.voltage == null and v.bays.len == 0 and v.general_equipment.len == 0 and
        v.power_transformers.len == 0 and v.lnodes.len == 0 and v.extras.isEmpty();
    if (empty) return w.closeEmpty();
    try w.closeOpen();
    try w.rawAll(v.extras.head);
    for (v.power_transformers) |p| try emitPowerTransformer(w, p);
    for (v.general_equipment) |e| try emitEquipment(w, e);
    for (v.lnodes) |l| try emitLNode(w, l);
    if (v.voltage) |vo| {
        try w.open("Voltage");
        if (!std.mem.eql(u8, vo.unit, "V")) try w.attrIf("unit", vo.unit);
        try w.attrIf("multiplier", vo.multiplier);
        try w.closeInline();
        try w.text(vo.value);
        try w.rawEnd("Voltage");
    }
    for (v.bays) |b| try emitBay(w, b);
    try w.rawAll(v.extras.tail);
    try w.end("VoltageLevel");
}

fn emitBay(w: *Writer, b: scl.Bay) Error!void {
    try w.open("Bay");
    try w.attr("name", b.name);
    try w.attrIf("desc", b.desc);
    const empty = b.equipment.len == 0 and b.general_equipment.len == 0 and
        b.power_transformers.len == 0 and b.connectivity_nodes.len == 0 and
        b.lnodes.len == 0 and b.extras.isEmpty();
    if (empty) return w.closeEmpty();
    try w.closeOpen();
    try w.rawAll(b.extras.head);
    for (b.power_transformers) |p| try emitPowerTransformer(w, p);
    for (b.general_equipment) |e| try emitEquipment(w, e);
    for (b.lnodes) |l| try emitLNode(w, l);
    for (b.equipment) |e| try emitEquipment(w, e);
    for (b.connectivity_nodes) |c| {
        try w.open("ConnectivityNode");
        try w.attr("name", c.name);
        try w.attr("pathName", c.path_name);
        try w.attrIf("desc", c.desc);
        try w.closeEmpty();
    }
    try w.rawAll(b.extras.tail);
    try w.end("Bay");
}

fn emitPowerTransformer(w: *Writer, p: scl.PowerTransformer) Error!void {
    try w.open("PowerTransformer");
    try w.attr("name", p.name);
    try w.attrIf("desc", p.desc);
    try w.attr("type", p.type);
    if (p.virtual) try w.attrBool("virtual", true);
    const empty = p.windings.len == 0 and p.terminals.len == 0 and p.lnodes.len == 0 and p.extras.isEmpty();
    if (empty) return w.closeEmpty();
    try w.closeOpen();
    try w.rawAll(p.extras.head);
    for (p.lnodes) |l| try emitLNode(w, l);
    for (p.terminals) |t| try emitTerminal(w, t);
    for (p.windings) |e| try emitEquipment(w, e);
    try w.rawAll(p.extras.tail);
    try w.end("PowerTransformer");
}

fn emitEquipment(w: *Writer, e: scl.Equipment) Error!void {
    const tag: []const u8 = switch (e.kind) {
        .conducting => "ConductingEquipment",
        .general => "GeneralEquipment",
        .winding => "TransformerWinding",
    };
    try w.open(tag);
    try w.attr("name", e.name);
    try w.attrIf("desc", e.desc);
    try w.attr("type", e.type);
    if (e.virtual) try w.attrBool("virtual", true);
    if (e.terminals.len == 0 and e.lnodes.len == 0 and e.extras.isEmpty()) return w.closeEmpty();
    try w.closeOpen();
    try w.rawAll(e.extras.head);
    for (e.lnodes) |l| try emitLNode(w, l);
    for (e.terminals) |t| try emitTerminal(w, t);
    try w.rawAll(e.extras.tail);
    try w.end(tag);
}

fn emitLNode(w: *Writer, l: scl.LNodeRef) Error!void {
    try w.open("LNode");
    if (!std.mem.eql(u8, l.ied_name, "None")) try w.attrIf("iedName", l.ied_name);
    try w.attrIf("ldInst", l.ld_inst);
    try w.attrIf("prefix", l.prefix);
    try w.attr("lnClass", l.ln_class);
    try w.attrIf("lnInst", l.ln_inst);
    try w.attrIf("lnType", l.ln_type);
    try w.attrIf("desc", l.desc);
    try w.closeEmpty();
}

fn emitTerminal(w: *Writer, t: scl.Terminal) Error!void {
    try w.open("Terminal");
    try w.attrIf("name", t.name);
    try w.attr("connectivityNode", t.connectivity_node);
    try w.attrIf("substationName", t.substation_name);
    try w.attrIf("voltageLevelName", t.voltage_level_name);
    try w.attrIf("bayName", t.bay_name);
    try w.attrIf("lineName", t.line_name);
    try w.attr("cNodeName", t.c_node_name);
    try w.attrIf("desc", t.desc);
    try w.closeEmpty();
}

fn emitSubnetwork(w: *Writer, sub: scl.Subnetwork) Error!void {
    try w.open("SubNetwork");
    try w.attr("name", sub.name);
    try w.attrIf("type", sub.type);
    try w.attrIf("desc", sub.desc);
    if (sub.aps.len == 0 and sub.extras.isEmpty()) return w.closeEmpty();
    try w.closeOpen();
    try w.rawAll(sub.extras.head);
    for (sub.aps) |ap| {
        try w.open("ConnectedAP");
        try w.attr("iedName", ap.ied_name);
        try w.attr("apName", ap.ap_name);
        const empty = ap.address.params.len == 0 and ap.gse.len == 0 and ap.smv.len == 0 and ap.extras.isEmpty();
        if (empty) {
            try w.closeEmpty();
            continue;
        }
        try w.closeOpen();
        try w.rawAll(ap.extras.head);
        try emitAddress(w, ap.address);
        for (ap.gse) |g| try emitCbAddress(w, "GSE", g);
        for (ap.smv) |g| try emitCbAddress(w, "SMV", g);
        try w.rawAll(ap.extras.tail);
        try w.end("ConnectedAP");
    }
    try w.rawAll(sub.extras.tail);
    try w.end("SubNetwork");
}

fn emitAddress(w: *Writer, a: scl.Address) Error!void {
    if (a.params.len == 0) return;
    try w.openDone("Address");
    for (a.params) |p| {
        try w.open("P");
        try w.attr("type", p.type);
        try w.closeInline();
        try w.text(p.value);
        try w.rawEnd("P");
    }
    try w.end("Address");
}

fn emitCbAddress(w: *Writer, tag: []const u8, g: scl.CbAddress) Error!void {
    try w.open(tag);
    try w.attr("ldInst", g.ld_inst);
    try w.attr("cbName", g.cb_name);
    try w.closeOpen();
    try w.rawAll(g.extras.head);
    try emitAddress(w, g.address);
    if (g.min_time_ms) |v| try w.textElement("MinTime", v);
    if (g.max_time_ms) |v| try w.textElement("MaxTime", v);
    try w.rawAll(g.extras.tail);
    try w.end(tag);
}

fn emitIed(w: *Writer, ied: scl.Ied) Error!void {
    try w.open("IED");
    try w.attr("name", ied.name);
    try w.attrIf("type", ied.type);
    try w.attrIf("desc", ied.desc);
    try w.attrIf("manufacturer", ied.manufacturer);
    try w.attrIf("configVersion", ied.config_version);
    try w.attrIf("owner", ied.owner);
    if (ied.access_points.len == 0 and ied.services == null and ied.extras.isEmpty()) return w.closeEmpty();
    try w.closeOpen();
    try w.rawAll(ied.extras.head);
    if (ied.services) |sv| try emitServices(w, sv);
    for (ied.access_points) |ap| {
        try w.open("AccessPoint");
        try w.attr("name", ap.name);
        try w.attrIf("desc", ap.desc);
        const empty = ap.devices.len == 0 and ap.services == null and
            ap.extras.isEmpty() and ap.server_extras.isEmpty();
        if (empty) {
            try w.closeEmpty();
            continue;
        }
        try w.closeOpen();
        try w.rawAll(ap.extras.head);
        if (ap.devices.len > 0 or !ap.server_extras.isEmpty()) {
            try w.openDone("Server");
            try w.rawAll(ap.server_extras.head);
            for (ap.devices) |ld| try emitLDevice(w, ld);
            try w.rawAll(ap.server_extras.tail);
            try w.end("Server");
        }
        if (ap.services) |sv| try emitServices(w, sv);
        try w.rawAll(ap.extras.tail);
        try w.end("AccessPoint");
    }
    try w.rawAll(ied.extras.tail);
    try w.end("IED");
}

fn emitServices(w: *Writer, sv: scl.Services) Error!void {
    try w.open("Services");
    try w.attrIf("nameLength", sv.name_length);
    if (sv.elements.len == 0) return w.closeEmpty();
    try w.closeOpen();
    try w.rawAll(sv.elements);
    try w.end("Services");
}

fn emitLDevice(w: *Writer, ld: scl.LDevice) Error!void {
    try w.open("LDevice");
    try w.attr("inst", ld.inst);
    try w.attrIf("ldName", ld.ld_name);
    try w.attrIf("desc", ld.desc);
    if (ld.lns.len == 0 and ld.extras.isEmpty()) return w.closeEmpty();
    try w.closeOpen();
    try w.rawAll(ld.extras.head);
    // `LN0` must come first — the schema sequences it before the `LN`s.
    for (ld.lns) |ln| {
        if (ln.is_ln0) try emitLn(w, ln);
    }
    for (ld.lns) |ln| {
        if (!ln.is_ln0) try emitLn(w, ln);
    }
    try w.rawAll(ld.extras.tail);
    try w.end("LDevice");
}

fn emitLn(w: *Writer, ln: scl.Ln) Error!void {
    const tag: []const u8 = if (ln.is_ln0) "LN0" else "LN";
    try w.open(tag);
    try w.attrIf("desc", ln.desc);
    try w.attrIf("prefix", ln.prefix);
    try w.attr("lnClass", ln.ln_class);
    try w.attr("inst", ln.inst);
    try w.attr("lnType", ln.ln_type);
    const empty = ln.dois.len == 0 and ln.data_sets.len == 0 and
        ln.report_controls.len == 0 and ln.gse_controls.len == 0 and
        ln.smv_controls.len == 0 and ln.inputs == null and ln.extras.isEmpty() and
        ln.log_controls.len == 0 and ln.logs.len == 0 and ln.setting_control == null;
    if (empty) return w.closeEmpty();
    try w.closeOpen();
    try w.rawAll(ln.extras.head);

    for (ln.data_sets) |ds| {
        try w.open("DataSet");
        try w.attr("name", ds.name);
        try w.attrIf("desc", ds.desc);
        if (ds.fcdas.len == 0 and ds.extras.isEmpty()) {
            try w.closeEmpty();
            continue;
        }
        try w.closeOpen();
        try w.rawAll(ds.extras.head);
        for (ds.fcdas) |f| {
            try w.open("FCDA");
            try w.attrIf("ldInst", f.ld_inst);
            try w.attrIf("prefix", f.prefix);
            try w.attr("lnClass", f.ln_class);
            try w.attrIf("lnInst", f.ln_inst);
            try w.attr("doName", f.do_name);
            try w.attrIf("daName", f.da_name);
            try w.attr("fc", f.fc.name());
            try w.closeEmpty();
        }
        try w.rawAll(ds.extras.tail);
        try w.end("DataSet");
    }

    for (ln.report_controls) |r| try emitReportControl(w, r);

    for (ln.log_controls) |l| {
        try w.open("LogControl");
        try w.attr("name", l.name);
        try w.attrIf("desc", l.desc);
        // `datSet` and `logName` are written even when empty: the schema makes
        // `logName` mandatory, and a third-party model generator refuses a
        // `LogControl` without it. An empty attribute and an absent one are
        // indistinguishable once parsed, so the writer picks the form that
        // every consumer accepts.
        try w.attr("datSet", l.dat_set);
        try w.attr("logName", l.log_name);
        try w.attrBoolDefault("logEna", l.log_ena, true);
        try w.attrUintDefault("intgPd", l.intg_pd, 0);
        try w.attrBoolDefault("reasonCode", l.reason_code, false);
        try w.closeOpen();
        try emitTrgOps(w, l.trg_ops);
        try w.end("LogControl");
    }

    if (ln.setting_control) |sg| {
        try w.open("SettingControl");
        try w.attrIf("desc", sg.desc);
        try w.attrUintDefault("numOfSGs", sg.num_of_sgs, 1);
        try w.attrUintDefault("actSG", sg.act_sg, 1);
        try w.closeEmpty();
    }

    for (ln.gse_controls) |g| {
        try w.open("GSEControl");
        try w.attr("name", g.name);
        try w.attrIf("desc", g.desc);
        try w.attrIf("appID", g.app_id);
        try w.attrIf("datSet", g.dat_set);
        try w.attrUintDefault("confRev", g.conf_rev, 1);
        if (!std.mem.eql(u8, g.type, "GOOSE")) try w.attrIf("type", g.type);
        try w.attrBoolDefault("fixedOffs", g.fixed_offs, false);
        try w.closeExtras(g.extras, "GSEControl");
    }

    for (ln.smv_controls) |sv| try emitSmvControl(w, sv);

    for (ln.dois) |d| try emitDoi(w, d);

    if (ln.inputs) |inp| {
        try w.openDone("Inputs");
        try w.rawAll(inp.extras.head);
        for (inp.ext_refs) |r| try emitExtRef(w, r);
        try w.rawAll(inp.extras.tail);
        try w.end("Inputs");
    }

    // `<Log>` sits after the `DOI`s in `tAnyLN`'s sequence, which is where the
    // schema puts it and where every generator reading the file back expects
    // it. A log with no name is legal — it is the node's default log.
    for (ln.logs) |l| {
        try w.open("Log");
        try w.attrIf("name", l.name);
        try w.attrIf("desc", l.desc);
        try w.closeEmpty();
    }
    try w.rawAll(ln.extras.tail);
    try w.end(tag);
}

fn emitSmvControl(w: *Writer, sv: scl.SmvControl) Error!void {
    try w.open("SampledValueControl");
    try w.attr("name", sv.name);
    try w.attrIf("desc", sv.desc);
    try w.attrIf("datSet", sv.dat_set);
    try w.attrUintDefault("confRev", sv.conf_rev, 1);
    try w.attrIf("smvID", sv.smv_id);
    try w.attrBoolDefault("multicast", sv.multicast, true);
    try w.attrUint("smpRate", sv.smp_rate);
    try w.attrUint("nofASDU", sv.nof_asdu);
    if (!std.mem.eql(u8, sv.smp_mod, "SmpPerPeriod")) try w.attrIf("smpMod", sv.smp_mod);
    try w.attrIf("securityEnable", sv.security_enable);
    try w.closeOpen();
    try w.rawAll(sv.extras.head);
    const d = scl.SmvOpts{};
    try w.open("SmvOpts");
    try w.attrBoolDefault("refreshTime", sv.opts.refresh_time, d.refresh_time);
    try w.attrBoolDefault("sampleSynchronized", sv.opts.sample_synchronized, d.sample_synchronized);
    try w.attrBoolDefault("sampleRate", sv.opts.sample_rate, d.sample_rate);
    try w.attrBoolDefault("dataSet", sv.opts.data_set, d.data_set);
    try w.attrBoolDefault("security", sv.opts.security, d.security);
    try w.attrBoolDefault("timestamp", sv.opts.timestamp, d.timestamp);
    try w.attrBoolDefault("synchSourceId", sv.opts.synch_source_id, d.synch_source_id);
    try w.closeEmpty();
    try w.rawAll(sv.extras.tail);
    try w.end("SampledValueControl");
}

fn emitExtRef(w: *Writer, r: scl.ExtRef) Error!void {
    try w.open("ExtRef");
    try w.attrIf("iedName", r.ied_name);
    try w.attrIf("ldInst", r.ld_inst);
    try w.attrIf("prefix", r.prefix);
    try w.attrIf("lnClass", r.ln_class);
    try w.attrIf("lnInst", r.ln_inst);
    try w.attrIf("doName", r.do_name);
    try w.attrIf("daName", r.da_name);
    try w.attrIf("intAddr", r.int_addr);
    try w.attrIf("desc", r.desc);
    try w.attrIf("serviceType", r.service_type);
    try w.attrIf("srcLDInst", r.src_ld_inst);
    try w.attrIf("srcPrefix", r.src_prefix);
    try w.attrIf("srcLNClass", r.src_ln_class);
    try w.attrIf("srcLNInst", r.src_ln_inst);
    try w.attrIf("srcCBName", r.src_cb_name);
    try w.attrIf("pLN", r.p_ln);
    try w.attrIf("pDO", r.p_do);
    try w.attrIf("pDA", r.p_da);
    try w.attrIf("pServT", r.p_serv_t);
    try w.closeEmpty();
}

fn emitReportControl(w: *Writer, r: scl.ReportControl) Error!void {
    try w.open("ReportControl");
    try w.attr("name", r.name);
    try w.attrIf("desc", r.desc);
    try w.attrIf("rptID", r.rpt_id);
    try w.attr("datSet", r.dat_set);
    try w.attrUint("confRev", r.conf_rev);
    try w.attrBoolDefault("buffered", r.buffered, false);
    try w.attrUintDefault("intgPd", r.intg_pd, 0);
    try w.attrUintDefault("bufTime", r.buf_time, 0);
    try w.attrBoolDefault("indexed", r.indexed, true);
    try w.closeOpen();
    try w.rawAll(r.extras.head);
    try emitTrgOps(w, r.trg_ops);
    const d = scl.OptFields{};
    try w.open("OptFields");
    try w.attrBoolDefault("seqNum", r.opt_fields.seq_num, d.seq_num);
    try w.attrBoolDefault("timeStamp", r.opt_fields.time_stamp, d.time_stamp);
    try w.attrBoolDefault("dataSet", r.opt_fields.data_set, d.data_set);
    try w.attrBoolDefault("reasonCode", r.opt_fields.reason_code, d.reason_code);
    try w.attrBoolDefault("dataRef", r.opt_fields.data_ref, d.data_ref);
    try w.attrBoolDefault("entryID", r.opt_fields.entry_id, d.entry_id);
    try w.attrBoolDefault("configRef", r.opt_fields.config_ref, d.config_ref);
    try w.attrBoolDefault("bufOvfl", r.opt_fields.buf_ovfl, d.buf_ovfl);
    try w.attrBoolDefault("segmentation", r.opt_fields.segmentation, d.segmentation);
    try w.closeEmpty();
    try w.open("RptEnabled");
    try w.attrUintDefault("max", r.max_instances, 1);
    try w.closeEmpty();
    try w.rawAll(r.extras.tail);
    try w.end("ReportControl");
}

fn emitTrgOps(w: *Writer, t: scl.TrgOps) Error!void {
    const d = scl.TrgOps{};
    try w.open("TrgOps");
    try w.attrBoolDefault("dchg", t.dchg, d.dchg);
    try w.attrBoolDefault("qchg", t.qchg, d.qchg);
    try w.attrBoolDefault("dupd", t.dupd, d.dupd);
    try w.attrBoolDefault("period", t.period, d.period);
    try w.attrBoolDefault("gi", t.gi, d.gi);
    try w.closeEmpty();
}

fn emitDoi(w: *Writer, d: scl.Doi) Error!void {
    try w.open("DOI");
    try w.attr("name", d.name);
    try w.attrIf("desc", d.desc);
    if (d.dais.len == 0 and d.extras.isEmpty()) return w.closeEmpty();
    try w.closeOpen();
    try w.rawAll(d.extras.head);
    for (d.dais) |dai| try emitDai(w, dai);
    try w.rawAll(d.extras.tail);
    try w.end("DOI");
}

/// `origin.orCat` becomes `<SDI name="origin"><DAI name="orCat">…`.
fn emitDai(w: *Writer, dai: scl.Dai) Error!void {
    var it = std.mem.splitScalar(u8, dai.path, '.');
    var parts: [max_type_depth][]const u8 = undefined;
    var n: usize = 0;
    while (it.next()) |p| {
        if (p.len == 0) continue;
        if (n == parts.len) return error.CyclicType;
        parts[n] = p;
        n += 1;
    }
    if (n == 0) return;
    var i: usize = 0;
    while (i + 1 < n) : (i += 1) {
        try w.open("SDI");
        try w.attr("name", parts[i]);
        try w.closeOpen();
    }
    try w.open("DAI");
    try w.attr("name", parts[n - 1]);
    if (dai.values.len == 0) {
        try w.closeEmpty();
    } else {
        try w.closeOpen();
        for (dai.values) |v| {
            try w.open("Val");
            try w.closeInline();
            try w.text(v);
            try w.rawEnd("Val");
        }
        try w.end("DAI");
    }
    i = n - 1;
    while (i > 0) : (i -= 1) try w.end("SDI");
}

fn emitTemplates(w: *Writer, t: scl.Templates) Error!void {
    const empty = t.ln_types.len == 0 and t.do_types.len == 0 and
        t.da_types.len == 0 and t.enum_types.len == 0;
    if (empty) return;
    try w.openDone("DataTypeTemplates");
    for (t.ln_types) |ln| {
        try w.open("LNodeType");
        try w.attr("id", ln.id);
        try w.attrIf("lnClass", ln.ln_class);
        if (ln.dos.len == 0) {
            try w.closeEmpty();
            continue;
        }
        try w.closeOpen();
        for (ln.dos) |d| {
            try w.open("DO");
            try w.attr("name", d.name);
            try w.attr("type", d.type);
            if (d.transient) try w.attrBool("transient", true);
            try w.closeEmpty();
        }
        try w.end("LNodeType");
    }
    for (t.do_types) |dt| {
        try w.open("DOType");
        try w.attr("id", dt.id);
        try w.attrIf("cdc", dt.cdc);
        if (dt.das.len == 0 and dt.sdos.len == 0) {
            try w.closeEmpty();
            continue;
        }
        try w.closeOpen();
        for (dt.sdos) |s| {
            try w.open("SDO");
            try w.attr("name", s.name);
            try w.attr("type", s.type);
            if (s.count > 0) try w.attrUint("count", s.count);
            try w.closeEmpty();
        }
        for (dt.das) |d| try emitDaRef(w, "DA", d);
        try w.end("DOType");
    }
    for (t.da_types) |dt| {
        try w.open("DAType");
        try w.attr("id", dt.id);
        if (dt.bdas.len == 0) {
            try w.closeEmpty();
            continue;
        }
        try w.closeOpen();
        for (dt.bdas) |b| try emitDaRef(w, "BDA", b);
        try w.end("DAType");
    }
    for (t.enum_types) |et| {
        try w.open("EnumType");
        try w.attr("id", et.id);
        if (et.vals.len == 0) {
            try w.closeEmpty();
            continue;
        }
        try w.closeOpen();
        for (et.vals) |v| {
            try w.open("EnumVal");
            try w.attrInt("ord", v.ord);
            try w.closeInline();
            try w.text(v.text);
            try w.rawEnd("EnumVal");
        }
        try w.end("EnumType");
    }
    try w.end("DataTypeTemplates");
}

fn emitDaRef(w: *Writer, tag: []const u8, d: scl.DaRef) Error!void {
    try w.open(tag);
    try w.attr("name", d.name);
    if (d.fc) |fc| try w.attr("fc", fc.name());
    try w.attr("bType", d.b_type.name());
    try w.attrIf("type", d.type);
    if (d.dchg) try w.attrBool("dchg", true);
    if (d.qchg) try w.attrBool("qchg", true);
    if (d.dupd) try w.attrBool("dupd", true);
    if (d.count > 0) try w.attrUint("count", d.count);
    if (d.val) |v| {
        try w.closeOpen();
        try w.open("Val");
        try w.closeInline();
        try w.text(v);
        try w.rawEnd("Val");
        try w.end(tag);
    } else {
        try w.closeEmpty();
    }
}

// ── the writer ──────────────────────────────────────────────────────────────

/// A tiny, escaping XML writer. It is deliberately not a general one: it takes
/// no prefixes, declares one namespace at the root, and never emits a
/// processing instruction or a DOCTYPE — the last of which is what the sibling
/// `xml` parser refuses on the way back in.
const Writer = struct {
    gpa: std.mem.Allocator,
    options: Options,
    buf: std.ArrayList(u8) = .empty,
    depth: usize = 0,
    extra_namespaces: []const xml.NsDecl = &.{},

    fn raw(self: *Writer, s: []const u8) Error!void {
        try self.buf.appendSlice(self.gpa, s);
    }

    fn pad(self: *Writer) Error!void {
        if (!self.options.indent) return;
        var i: usize = 0;
        while (i < self.depth) : (i += 1) try self.raw("  ");
    }

    /// `<Name` — attributes follow, then `closeEmpty` or `closeOpen`.
    fn open(self: *Writer, name: []const u8) Error!void {
        try self.pad();
        try self.raw("<");
        try self.raw(name);
    }

    /// `<Name>` on its own line, and descend.
    fn openDone(self: *Writer, name: []const u8) Error!void {
        try self.open(name);
        try self.closeOpen();
    }

    fn closeEmpty(self: *Writer) Error!void {
        try self.raw("/>\n");
    }

    /// Closes the start tag of an element whose only possible children are
    /// carried `Extras`.
    fn closeExtras(self: *Writer, extras: scl.Extras, name: []const u8) Error!void {
        if (extras.isEmpty()) return self.closeEmpty();
        try self.closeOpen();
        try self.rawAll(extras.head);
        try self.rawAll(extras.tail);
        try self.end(name);
    }

    fn rawAll(self: *Writer, els: []const scl.Raw) Error!void {
        for (els) |e| try self.rawElement(e);
    }

    /// Writes an element the model carried verbatim. The element is serialised
    /// with its own prefixes; a prefix it uses that was declared on an ancestor
    /// (and not on the root, where `extra_namespaces` puts it) is declared on
    /// the element itself, so the output stays well-formed namespace-wise.
    fn rawElement(self: *Writer, el: scl.Raw) Error!void {
        var decls: std.ArrayList(xml.NsDecl) = .empty;
        defer decls.deinit(self.gpa);
        try decls.appendSlice(self.gpa, el.ns_decls);
        const scope = try el.inScopeNamespaces(self.gpa);
        defer self.gpa.free(scope);
        next: for (scope) |d| {
            if (d.prefix.len == 0) continue;
            for (el.ns_decls) |own| {
                if (std.mem.eql(u8, own.prefix, d.prefix)) continue :next;
            }
            for (self.extra_namespaces) |root| {
                if (std.mem.eql(u8, root.prefix, d.prefix) and std.mem.eql(u8, root.uri, d.uri)) continue :next;
            }
            try decls.append(self.gpa, d);
        }
        var copy = el.*;
        copy.ns_decls = decls.items;
        var aw: std.Io.Writer.Allocating = .init(self.gpa);
        defer aw.deinit();
        xml.writer.writeElement(self.gpa, &aw.writer, &copy) catch |e| switch (e) {
            error.OutOfMemory, error.WriteFailed => return error.OutOfMemory,
            else => return error.IllegalCharacter,
        };
        try self.pad();
        try self.raw(aw.written());
        try self.raw("\n");
    }

    fn closeOpen(self: *Writer) Error!void {
        try self.raw(">");
        if (self.options.indent) try self.raw("\n");
        self.depth += 1;
    }

    /// `>` with the content following on the same line — for the handful of
    /// elements whose body is text (`P`, `Val`, `EnumVal`, `MinTime`).
    fn closeInline(self: *Writer) Error!void {
        try self.raw(">");
        self.depth += 1;
    }

    fn end(self: *Writer, name: []const u8) Error!void {
        self.depth -= 1;
        try self.pad();
        try self.raw("</");
        try self.raw(name);
        try self.raw(">\n");
    }

    /// Closes an element whose content was written inline (no indent, no
    /// newline before the tag).
    fn rawEnd(self: *Writer, name: []const u8) Error!void {
        self.depth -= 1;
        try self.raw("</");
        try self.raw(name);
        try self.raw(">\n");
    }

    fn attr(self: *Writer, name: []const u8, value: []const u8) Error!void {
        try self.raw(" ");
        try self.raw(name);
        try self.raw("=\"");
        try self.attrValue(value);
        try self.raw("\"");
    }

    fn attrIf(self: *Writer, name: []const u8, value: []const u8) Error!void {
        if (value.len == 0) return;
        try self.attr(name, value);
    }

    fn attrBool(self: *Writer, name: []const u8, value: bool) Error!void {
        try self.attr(name, if (value) "true" else "false");
    }

    /// Emits the attribute **only when it differs from the schema default**.
    ///
    /// This is what keeps the emission faithful to the *source*: SCL is full of
    /// optional attributes whose default a reader supplies, and writing every
    /// one of them explicitly is how a round trip quietly changes a document's
    /// meaning for any tool whose defaults differ by one flag.
    fn attrBoolDefault(self: *Writer, name: []const u8, value: bool, default: bool) Error!void {
        if (value == default) return;
        try self.attrBool(name, value);
    }

    fn attrUintDefault(self: *Writer, name: []const u8, value: u64, default: u64) Error!void {
        if (value == default) return;
        try self.attrUint(name, value);
    }

    fn attrUint(self: *Writer, name: []const u8, value: u64) Error!void {
        var tmp: [24]u8 = undefined;
        try self.attr(name, std.mem.print(&tmp, "{d}", .{value}) catch unreachable);
    }

    fn attrInt(self: *Writer, name: []const u8, value: i64) Error!void {
        var tmp: [24]u8 = undefined;
        try self.attr(name, std.mem.print(&tmp, "{d}", .{value}) catch unreachable);
    }

    fn textElement(self: *Writer, name: []const u8, value: u64) Error!void {
        try self.open(name);
        try self.closeInline();
        var tmp: [24]u8 = undefined;
        try self.text(std.mem.print(&tmp, "{d}", .{value}) catch unreachable);
        try self.rawEnd(name);
    }

    /// Character data. `&`, `<` and `>` are escaped; `>` because `]]>` inside
    /// text is not well-formed and escaping it unconditionally is cheaper than
    /// looking for the sequence.
    fn text(self: *Writer, s: []const u8) Error!void {
        for (s) |c| switch (c) {
            '&' => try self.raw("&amp;"),
            '<' => try self.raw("&lt;"),
            '>' => try self.raw("&gt;"),
            0x00...0x08, 0x0B, 0x0C, 0x0E...0x1F => return error.IllegalCharacter,
            else => try self.buf.append(self.gpa, c),
        };
    }

    /// An attribute value: the same plus the quote, and whitespace that would
    /// otherwise be normalised away on the way back in.
    fn attrValue(self: *Writer, s: []const u8) Error!void {
        for (s) |c| switch (c) {
            '&' => try self.raw("&amp;"),
            '<' => try self.raw("&lt;"),
            '>' => try self.raw("&gt;"),
            '"' => try self.raw("&quot;"),
            '\t' => try self.raw("&#9;"),
            '\n' => try self.raw("&#10;"),
            '\r' => try self.raw("&#13;"),
            0x00...0x08, 0x0B, 0x0C, 0x0E...0x1F => return error.IllegalCharacter,
            else => try self.buf.append(self.gpa, c),
        };
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// The strong test: parse → emit → parse → resolve, and the two name spaces
/// must be identical. Anything the writer loses shows up here as a missing or
/// an extra MMS name.
fn roundTrip(source: []const u8, ied_name: []const u8) !void {
    var a = try scl.parse(testing.allocator, source, .{});
    defer a.deinit();
    var model_a = try scl.resolve(&a, testing.allocator, ied_name);
    defer model_a.deinit();

    const emitted = try emitParsed(testing.allocator, &a, .{ .allow_lossy = true });
    defer testing.allocator.free(emitted);

    var b = try scl.parse(testing.allocator, emitted, .{});
    defer b.deinit();
    var model_b = try scl.resolve(&b, testing.allocator, ied_name);
    defer model_b.deinit();

    // A **set** comparison, not a positional one: the emitter puts `LN0` first
    // because the schema sequences it there, and real files do not always. The
    // claim is that the name space is identical, not that the document order is.
    try testing.expectEqual(model_a.nodes.len, model_b.nodes.len);
    for (model_a.nodes) |x| {
        const y = model_b.find(x.domain, x.item) orelse {
            std.debug.print("emitted SCL lost {s}/{s}\n", .{ x.domain, x.item });
            return error.TestExpectedEqual;
        };
        try testing.expectEqual(x.fc, y.fc);
        try testing.expectEqual(x.b_type, y.b_type);
        try testing.expectEqual(x.depth, y.depth);
        try testing.expectEqual(x.leaf, y.leaf);
        try testing.expectEqualStrings(x.enum_type, y.enum_type);
        if (x.value) |v| {
            try testing.expectEqualStrings(v, y.value orelse return error.TestExpectedEqual);
        } else {
            try testing.expect(y.value == null);
        }
    }
}

test "the sample document survives parse → emit → parse with an identical name space" {
    try roundTrip(scl.sample, "TESTIED");
}

test "the emission is well-formed, namespaced SCL that our own parser accepts" {
    var doc = try scl.parse(testing.allocator, scl.sample, .{});
    defer doc.deinit();
    const out = try emitParsed(testing.allocator, &doc, .{});
    defer testing.allocator.free(out);

    try testing.expect(std.mem.startsWith(u8, out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<SCL xmlns="));
    // The sample declares edition 1, and the emission keeps it — an edition is
    // not a formatting choice.
    try testing.expect(std.mem.find(u8, out, scl.ns_2003) != null);
    try testing.expect(std.mem.endsWith(u8, out, "</SCL>\n"));
    // No DOCTYPE — the sibling parser refuses one, and so should every other.
    try testing.expect(std.mem.find(u8, out, "<!DOCTYPE") == null);

    // Every piece of the model is there by name.
    for ([_][]const u8{
        "<Header",               "<Communication>", "<SubNetwork",
        "<ConnectedAP",          "<Address>",       "<GSE",
        "<MinTime>10</MinTime>", "<IED",            "<AccessPoint",
        "<Server>",              "<LDevice",        "<LN0",
        "<DataSet",              "<FCDA",           "<ReportControl",
        "<TrgOps",               "<OptFields",      "<RptEnabled",
        "<GSEControl",           "<DOI",            "<SDI",
        "<DAI",                  "<Val>",           "<DataTypeTemplates>",
        "<LNodeType",            "<DOType",         "<DAType",
    }) |needle| {
        if (std.mem.find(u8, out, needle) == null) {
            std.debug.print("missing from the emitted SCL: {s}\n", .{needle});
            return error.TestExpectedEqual;
        }
    }
    // …and the round trip really goes through the sibling `xml` parser.
    var back = try xml.parse(testing.allocator, out, .{ .id_attr_names = &.{} });
    defer back.deinit();
    try testing.expectEqualStrings("SCL", back.root.local);
    try testing.expectEqualStrings(scl.ns_2003, back.root.uri);
}

test "a nested DAI path comes back as the same dotted path" {
    var doc = try scl.parse(testing.allocator, scl.sample, .{});
    defer doc.deinit();
    const out = try emitParsed(testing.allocator, &doc, .{});
    defer testing.allocator.free(out);
    var back = try scl.parse(testing.allocator, out, .{});
    defer back.deinit();

    const ied = back.ied("TESTIED").?;
    const ld = ied.access_points[0].devices[0];
    var found_ctl = false;
    var found_nested = false;
    for (ld.lns) |ln| {
        for (ln.dois) |d| {
            for (d.dais) |dai| {
                if (std.mem.eql(u8, dai.path, "ctlModel")) {
                    found_ctl = true;
                    try testing.expectEqualStrings("sbo-with-enhanced-security", dai.first().?);
                }
                if (std.mem.eql(u8, dai.path, "Oper.ctlNum")) {
                    found_nested = true;
                    try testing.expectEqualStrings("7", dai.first().?);
                }
            }
        }
    }
    try testing.expect(found_ctl and found_nested);
}

/// A substation configuration with everything `scl.zig` used to drop: the
/// single-line diagram, `Services`, `Inputs`, `SampledValueControl`, `desc`
/// attributes and vendor `Private` content with its own namespace.
const scd_source =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<SCL xmlns="http://www.iec.ch/61850/2007/SCL" xmlns:ext="urn:vendor:ext" version="2007" revision="B" release="4">
    \\  <Private type="top"><ext:Tool xmlns:inner="urn:inner" inner:k="v">one</ext:Tool></Private>
    \\  <Header id="X" version="1" nameStructure="IEDName"><Text>about</Text><History><Hitem version="1" revision="a" when="today"/></History></Header>
    \\  <Substation name="S1" desc="main">
    \\    <PowerTransformer name="T1" type="PTR">
    \\      <TransformerWinding name="W1" type="PTW"><Terminal name="T" connectivityNode="S1/E1/Q1/N1" cNodeName="N1"/></TransformerWinding>
    \\    </PowerTransformer>
    \\    <VoltageLevel name="E1" nomFreq="50" numPhases="3">
    \\      <Voltage unit="V" multiplier="k">110</Voltage>
    \\      <Bay name="Q1" desc="feeder">
    \\        <LNode iedName="A" ldInst="LD0" lnClass="LLN0"/>
    \\        <LNode lnClass="XCBR" lnInst="1" lnType="Spec"/>
    \\        <ConductingEquipment name="QA1" type="CBR" virtual="true">
    \\          <LNode iedName="A" ldInst="LD0" lnClass="XCBR" lnInst="1"/>
    \\          <Terminal name="T1" connectivityNode="S1/E1/Q1/N1" cNodeName="N1"/>
    \\          <SubEquipment name="ph" phase="A"/>
    \\        </ConductingEquipment>
    \\        <GeneralEquipment name="G" type="AXN"/>
    \\        <ConnectivityNode name="N1" pathName="S1/E1/Q1/N1"/>
    \\        <Function name="F1"><LNode lnClass="PDIS"/></Function>
    \\      </Bay>
    \\    </VoltageLevel>
    \\  </Substation>
    \\  <Communication>
    \\    <Text>comm</Text>
    \\    <SubNetwork name="N" type="8-MMS" desc="bus"><BitRate unit="b/s">100</BitRate>
    \\      <ConnectedAP iedName="A" apName="P1">
    \\        <Address><P type="IP">10.0.0.1</P></Address>
    \\        <SMV ldInst="LD0" cbName="sv1"><Address><P type="APPID">4000</P></Address></SMV>
    \\        <PhysConn type="Connection"><P type="Plug">RJ45</P></PhysConn>
    \\      </ConnectedAP>
    \\    </SubNetwork>
    \\  </Communication>
    \\  <IED name="A" desc="relay" owner="grid">
    \\    <Services nameLength="64">
    \\      <GetDirectory/><ConfDataSet max="8" maxAttributes="64" modify="false"/><GOOSE max="4"/>
    \\      <SettingGroups><SGEdit/><ConfSG/></SettingGroups>
    \\    </Services>
    \\    <AccessPoint name="P1" desc="ap">
    \\      <Server><Authentication/>
    \\        <LDevice inst="LD0" desc="ld">
    \\          <LN0 lnClass="LLN0" inst="" lnType="L" desc="zero">
    \\            <DataSet name="DS" desc="ds"><FCDA ldInst="LD0" lnClass="XCBR" lnInst="1" doName="Pos" daName="stVal" fc="ST"/></DataSet>
    \\            <ReportControl name="R" desc="rc" datSet="DS" confRev="1" buffered="false"><TrgOps dchg="true"/><OptFields/><RptEnabled max="2"/></ReportControl>
    \\            <GSEControl name="G1" desc="gc" datSet="DS" appID="g"><Private type="p"/></GSEControl>
    \\            <SampledValueControl name="MSVCB01" desc="sv" datSet="DS" smvID="svid" smpRate="80" nofASDU="1" confRev="2"><SmvOpts refreshTime="true" sampleRate="true"/></SampledValueControl>
    \\            <SampledValueControl name="USV" datSet="DS" multicast="false" smvID="u" smpRate="4000" nofASDU="8" smpMod="SmpPerSec"><SmvOpts/></SampledValueControl>
    \\            <Inputs>
    \\              <ExtRef iedName="B" ldInst="LD0" lnClass="XCBR" lnInst="2" doName="Pos" daName="stVal" intAddr="in1" serviceType="GOOSE" srcLDInst="LD0" srcCBName="gcb" desc="sub"/>
    \\              <ExtRef intAddr="loose"/>
    \\              <SourceRef/>
    \\            </Inputs>
    \\            <Private type="ln"/>
    \\          </LN0>
    \\          <LN lnClass="XCBR" inst="1" lnType="X" desc="breaker"/>
    \\        </LDevice>
    \\      </Server>
    \\      <Services><GetDirectory/></Services>
    \\    </AccessPoint>
    \\  </IED>
    \\  <DataTypeTemplates>
    \\    <LNodeType id="L" lnClass="LLN0"><DO name="Mod" type="MOD"/></LNodeType>
    \\    <LNodeType id="X" lnClass="XCBR"><DO name="Pos" type="POS"/></LNodeType>
    \\    <DOType id="MOD" cdc="ENC"><DA name="stVal" fc="ST" bType="INT32"/></DOType>
    \\    <DOType id="POS" cdc="DPC"><DA name="stVal" fc="ST" bType="Dbpos"/></DOType>
    \\  </DataTypeTemplates>
    \\  <Line name="ln1"/>
    \\</SCL>
;

test "a Substation section, Services, Inputs and SampledValueControl are parsed and carried through emit" {
    var doc = try scl.parse(testing.allocator, scd_source, .{});
    defer doc.deinit();
    try testing.expect(doc.has_substation);
    try testing.expectEqualStrings("2007", doc.version);
    try testing.expectEqualStrings("B", doc.revision);
    try testing.expectEqualStrings("4", doc.release);
    try checkScd(&doc);

    // What the old writer refused is now written, and what it wrote is read
    // back into the same model.
    const out = try emitParsed(testing.allocator, &doc, .{});
    defer testing.allocator.free(out);
    var again = try scl.parse(testing.allocator, out, .{});
    defer again.deinit();
    try checkScd(&again);

    // A second emission is byte-identical: the writer is a fixed point.
    const out2 = try emitParsed(testing.allocator, &again, .{});
    defer testing.allocator.free(out2);
    try testing.expectEqualStrings(out, out2);

    // `allow_lossy` is a no-op now.
    const out3 = try emitParsed(testing.allocator, &doc, .{ .allow_lossy = true });
    defer testing.allocator.free(out3);
    try testing.expectEqualStrings(out, out3);
}

fn checkScd(doc: *const scl.Scl) !void {
    // Substation.
    try testing.expectEqual(@as(usize, 1), doc.substations.len);
    const sub = doc.substations[0];
    try testing.expectEqualStrings("S1", sub.name);
    try testing.expectEqualStrings("main", sub.desc);
    try testing.expectEqual(@as(usize, 1), sub.power_transformers.len);
    try testing.expectEqual(@as(usize, 1), sub.power_transformers[0].windings.len);
    try testing.expectEqual(scl.EquipmentKind.winding, sub.power_transformers[0].windings[0].kind);
    try testing.expectEqual(@as(usize, 1), sub.power_transformers[0].windings[0].terminals.len);
    const vl = sub.voltage_levels[0];
    try testing.expectEqualStrings("50", vl.nom_freq);
    try testing.expectEqualStrings("110", vl.voltage.?.value);
    try testing.expectEqualStrings("k", vl.voltage.?.multiplier);
    const bay = vl.bays[0];
    try testing.expectEqualStrings("feeder", bay.desc);
    try testing.expectEqual(@as(usize, 2), bay.lnodes.len);
    try testing.expectEqualStrings("A", bay.lnodes[0].ied_name);
    try testing.expectEqualStrings("None", bay.lnodes[1].ied_name);
    try testing.expectEqualStrings("Spec", bay.lnodes[1].ln_type);
    try testing.expectEqual(@as(usize, 1), bay.equipment.len);
    const cbr = bay.equipment[0];
    try testing.expectEqualStrings("CBR", cbr.type);
    try testing.expect(cbr.virtual);
    try testing.expectEqualStrings("N1", cbr.terminals[0].c_node_name);
    try testing.expect(cbr.extras.find("SubEquipment") != null);
    try testing.expectEqual(@as(usize, 1), bay.general_equipment.len);
    try testing.expectEqualStrings("AXN", bay.general_equipment[0].type);
    try testing.expectEqual(@as(usize, 1), bay.connectivity_nodes.len);
    try testing.expect(bay.extras.find("Function") != null);
    try testing.expectEqual(@as(usize, 2), sub.boundLnodeCount());

    // Private / Text / History survive, with their own namespaces.
    try testing.expect(doc.extras.find("Private") != null);
    try testing.expect(doc.extras.find("Line") != null);
    try testing.expect(doc.header.extras.find("History") != null);
    try testing.expect(doc.header.extras.find("Text") != null);
    try testing.expect(doc.comm_extras.find("Text") != null);
    try testing.expectEqual(@as(usize, 1), doc.extra_namespaces.len);
    const tool = doc.extras.find("Private").?.firstElementChild().?;
    try testing.expectEqualStrings("Tool", tool.local);
    try testing.expectEqualStrings("urn:vendor:ext", tool.uri);
    try testing.expectEqualStrings("v", tool.attr("urn:inner", "k").?);

    // Communication extras.
    const net = doc.subnetworks[0];
    try testing.expectEqualStrings("bus", net.desc);
    try testing.expect(net.extras.find("BitRate") != null);
    try testing.expect(net.aps[0].extras.find("PhysConn") != null);

    // Services.
    const ied = doc.ieds[0];
    try testing.expectEqualStrings("relay", ied.desc);
    try testing.expectEqualStrings("grid", ied.owner);
    const sv = ied.services.?;
    try testing.expectEqualStrings("64", sv.name_length);
    try testing.expect(sv.has("GetDirectory"));
    try testing.expect(!sv.has("FileHandling"));
    try testing.expectEqual(@as(?u32, 8), sv.number("ConfDataSet", "max"));
    try testing.expectEqualStrings("false", sv.attribute("ConfDataSet", "modify").?);
    try testing.expectEqual(@as(?u32, 4), sv.number("GOOSE", "max"));
    try testing.expect(sv.has("SettingGroups"));
    try testing.expect(ied.access_points[0].services.?.has("GetDirectory"));
    try testing.expect(!ied.access_points[0].server_extras.isEmpty());
    try testing.expectEqualStrings("ap", ied.access_points[0].desc);

    // Logical nodes.
    const ld = ied.access_points[0].devices[0];
    try testing.expectEqualStrings("ld", ld.desc);
    const ln0 = ld.lns[0];
    try testing.expectEqualStrings("zero", ln0.desc);
    try testing.expectEqualStrings("breaker", ld.lns[1].desc);
    try testing.expectEqualStrings("rc", ln0.report_controls[0].desc);
    try testing.expectEqualStrings("gc", ln0.gse_controls[0].desc);
    try testing.expect(ln0.gse_controls[0].extras.find("Private") != null);
    try testing.expectEqualStrings("ds", ln0.data_sets[0].desc);
    try testing.expect(ln0.extras.find("Private") != null);

    // SampledValueControl.
    try testing.expectEqual(@as(usize, 2), ln0.smv_controls.len);
    const m = ln0.smv_controls[0];
    try testing.expectEqualStrings("MSVCB01", m.name);
    try testing.expect(m.multicast);
    try testing.expectEqualStrings("svid", m.smv_id);
    try testing.expectEqual(@as(u32, 80), m.smp_rate);
    try testing.expectEqual(@as(u32, 1), m.nof_asdu);
    try testing.expectEqual(@as(u32, 2), m.conf_rev);
    try testing.expectEqualStrings("SmpPerPeriod", m.smp_mod);
    try testing.expect(m.opts.refresh_time and m.opts.sample_rate and !m.opts.data_set);
    const u = ln0.smv_controls[1];
    try testing.expect(!u.multicast);
    try testing.expectEqualStrings("SmpPerSec", u.smp_mod);
    try testing.expectEqual(@as(u32, 8), u.nof_asdu);

    // Inputs.
    const inp = ln0.inputs.?;
    try testing.expectEqual(@as(usize, 2), inp.ext_refs.len);
    try testing.expectEqualStrings("B", inp.ext_refs[0].ied_name);
    try testing.expectEqualStrings("in1", inp.ext_refs[0].int_addr);
    try testing.expectEqualStrings("GOOSE", inp.ext_refs[0].service_type);
    try testing.expectEqualStrings("gcb", inp.ext_refs[0].src_cb_name);
    try testing.expectEqualStrings("loose", inp.ext_refs[1].int_addr);
    try testing.expectEqualStrings("", inp.ext_refs[1].ied_name);
    try testing.expect(inp.extras.find("SourceRef") != null);
}

test "sampled-value control blocks are part of the resolved name space, multicast under MS and unicast under US" {
    var doc = try scl.parse(testing.allocator, scd_source, .{});
    defer doc.deinit();
    var model = try scl.resolve(&doc, testing.allocator, "A");
    defer model.deinit();
    try testing.expect(model.has("ALD0", "LLN0$MS$MSVCB01"));
    try testing.expect(model.has("ALD0", "LLN0$MS$MSVCB01$MsvID"));
    try testing.expect(model.has("ALD0", "LLN0$MS$MSVCB01$DstAddress$APPID"));
    try testing.expect(model.has("ALD0", "LLN0$US$USV"));
    try testing.expect(model.has("ALD0", "LLN0$US$USV$UsvID"));
    try testing.expect(!model.has("ALD0", "LLN0$US$MSVCB01"));
    try testing.expect(!model.has("ALD0", "LLN0$MS$USV"));
}

test "Private content keeps a prefix declared on an ancestor other than the root" {
    const src =
        \\<SCL xmlns="http://www.iec.ch/61850/2007/SCL">
        \\  <Header id="X"/>
        \\  <IED name="A" xmlns:v="urn:v"><Private type="p"><v:Item v:a="1"/></Private></IED>
        \\</SCL>
    ;
    var doc = try scl.parse(testing.allocator, src, .{});
    defer doc.deinit();
    const out = try emitParsed(testing.allocator, &doc, .{});
    defer testing.allocator.free(out);
    var again = try scl.parse(testing.allocator, out, .{});
    defer again.deinit();
    const item = again.ieds[0].extras.find("Private").?.firstElementChild().?;
    try testing.expectEqualStrings("urn:v", item.uri);
    try testing.expectEqualStrings("1", item.attr("urn:v", "a").?);
}

test "an IED without Services keeps services null and LossyDocument is no longer returned" {
    const src =
        \\<SCL xmlns="http://www.iec.ch/61850/2003/SCL">
        \\  <Header id="X"/>
        \\  <Substation name="S1"/>
        \\  <IED name="A"/>
        \\</SCL>
    ;
    var doc = try scl.parse(testing.allocator, src, .{});
    defer doc.deinit();
    try testing.expect(doc.has_substation);
    try testing.expect(doc.ieds[0].services == null);
    const out = try emitParsed(testing.allocator, &doc, .{});
    defer testing.allocator.free(out);
    try testing.expect(std.mem.find(u8, out, "<Substation name=\"S1\"/>") != null);
}

test "a cyclic type graph is refused before anything is written" {
    // `Vector` holds a `Point`, which holds a `Vector`.
    const vector_bdas = [_]scl.DaRef{.{ .name = "p", .b_type = .Struct, .type = "Point" }};
    const point_bdas = [_]scl.DaRef{.{ .name = "v", .b_type = .Struct, .type = "Vector" }};
    const da_types = [_]scl.DaType{
        .{ .id = "Vector", .bdas = &vector_bdas },
        .{ .id = "Point", .bdas = &point_bdas },
    };
    const templates = scl.Templates{ .da_types = &da_types };
    try testing.expectError(error.CyclicType, checkTypeGraph(templates));
    try testing.expectError(error.CyclicType, emit(testing.allocator, .{
        .templates = templates,
    }, .{}));
    // A self-reference is the degenerate case and is caught the same way.
    const self_bdas = [_]scl.DaRef{.{ .name = "me", .b_type = .Struct, .type = "Loop" }};
    const self_types = [_]scl.DaType{.{ .id = "Loop", .bdas = &self_bdas }};
    try testing.expectError(error.CyclicType, checkTypeGraph(.{ .da_types = &self_types }));

    // A DOType cycle through SDO is caught too.
    const sdos = [_]scl.SdoRef{.{ .name = "sub", .type = "D1" }};
    const do_types = [_]scl.DoType{.{ .id = "D1", .sdos = &sdos }};
    try testing.expectError(error.CyclicType, checkTypeGraph(.{ .do_types = &do_types }));

    // With the check turned off the emitter still terminates — it walks flat
    // lists — which is what makes the refusal a policy and not a crash guard.
    const out = try emit(testing.allocator, .{ .templates = templates }, .{ .check_types = false });
    defer testing.allocator.free(out);
    try testing.expect(std.mem.find(u8, out, "<DAType id=\"Vector\"") != null);
}

test "markup in a name or a value is escaped, and a control character is refused" {
    const dais = [_]scl.Dai{.{ .path = "desc", .values = &.{"a < b & c > d \"q\""} }};
    const dois = [_]scl.Doi{.{ .name = "X", .desc = "<script>&\"", .dais = &dais }};
    const lns = [_]scl.Ln{.{ .ln_class = "GGIO", .ln_type = "T", .inst = "1", .dois = &dois }};
    const lds = [_]scl.LDevice{.{ .inst = "LD0", .lns = &lns }};
    const aps = [_]scl.AccessPoint{.{ .name = "AP1", .devices = &lds }};
    const ieds = [_]scl.Ied{.{ .name = "IED1", .access_points = &aps }};

    const out = try emit(testing.allocator, .{ .header = .{ .id = "H" }, .ieds = &ieds }, .{});
    defer testing.allocator.free(out);
    try testing.expect(std.mem.find(u8, out, "&lt;script&gt;&amp;&quot;") != null);
    try testing.expect(std.mem.find(u8, out, "a &lt; b &amp; c &gt; d \"q\"") != null);
    // And it re-parses to the original strings.
    var back = try scl.parse(testing.allocator, out, .{});
    defer back.deinit();
    const doi = back.ied("IED1").?.access_points[0].devices[0].lns[0].dois[0];
    try testing.expectEqualStrings("<script>&\"", doi.desc);
    try testing.expectEqualStrings("a < b & c > d \"q\"", doi.dais[0].first().?);

    // A raw control character has no XML representation at all.
    const bad_dais = [_]scl.Dai{.{ .path = "desc", .values = &.{"a\x01b"} }};
    const bad_dois = [_]scl.Doi{.{ .name = "X", .dais = &bad_dais }};
    const bad_lns = [_]scl.Ln{.{ .ln_class = "GGIO", .ln_type = "T", .inst = "1", .dois = &bad_dois }};
    const bad_lds = [_]scl.LDevice{.{ .inst = "LD0", .lns = &bad_lns }};
    const bad_aps = [_]scl.AccessPoint{.{ .name = "AP1", .devices = &bad_lds }};
    const bad_ieds = [_]scl.Ied{.{ .name = "IED1", .access_points = &bad_aps }};
    try testing.expectError(error.IllegalCharacter, emit(testing.allocator, .{ .ieds = &bad_ieds }, .{}));
}

test "an unindented emission parses to the same model as an indented one" {
    var doc = try scl.parse(testing.allocator, scl.sample, .{});
    defer doc.deinit();
    const flat = try emitParsed(testing.allocator, &doc, .{ .indent = false });
    defer testing.allocator.free(flat);
    const pretty = try emitParsed(testing.allocator, &doc, .{});
    defer testing.allocator.free(pretty);
    try testing.expect(flat.len < pretty.len);

    var a = try scl.parse(testing.allocator, flat, .{});
    defer a.deinit();
    var model_a = try scl.resolve(&a, testing.allocator, "TESTIED");
    defer model_a.deinit();
    var b = try scl.parse(testing.allocator, pretty, .{});
    defer b.deinit();
    var model_b = try scl.resolve(&b, testing.allocator, "TESTIED");
    defer model_b.deinit();
    try testing.expectEqual(model_a.nodes.len, model_b.nodes.len);
}

test "an empty model still emits a valid document" {
    const out = try emit(testing.allocator, .{}, .{});
    defer testing.allocator.free(out);
    var back = try xml.parse(testing.allocator, out, .{ .id_attr_names = &.{} });
    defer back.deinit();
    try testing.expectEqualStrings("SCL", back.root.local);
    var doc = try scl.parse(testing.allocator, out, .{});
    defer doc.deinit();
    try testing.expectEqual(@as(usize, 0), doc.ieds.len);
}

test "the emitted namespace is the one the caller asked for" {
    const out = try emit(testing.allocator, .{}, .{ .namespace = scl.ns_2003 });
    defer testing.allocator.free(out);
    var back = try xml.parse(testing.allocator, out, .{ .id_attr_names = &.{} });
    defer back.deinit();
    try testing.expectEqualStrings(scl.ns_2003, back.root.uri);
}

test "a Log element survives the round trip and is emitted after the DOIs" {
    const src =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<SCL xmlns="http://www.iec.ch/61850/2003/SCL">
        \\  <IED name="LOGIED">
        \\    <AccessPoint name="AP1">
        \\      <Server>
        \\        <LDevice inst="LD0">
        \\          <LN0 lnClass="LLN0" inst="" lnType="LLN0type">
        \\            <DataSet name="Events">
        \\              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
        \\            </DataSet>
        \\            <LogControl name="LogCB" datSet="Events" logName="GeneralLog" logEna="true"/>
        \\            <Log name="GeneralLog"/>
        \\            <Log name="SecondLog" desc="the other one"/>
        \\            <Log/>
        \\          </LN0>
        \\          <LN lnClass="GGIO" inst="1" lnType="GGIOtype"/>
        \\        </LDevice>
        \\      </Server>
        \\    </AccessPoint>
        \\  </IED>
        \\  <DataTypeTemplates>
        \\    <LNodeType id="LLN0type" lnClass="LLN0">
        \\      <DO name="Mod" type="INCtype"/>
        \\    </LNodeType>
        \\    <LNodeType id="GGIOtype" lnClass="GGIO">
        \\      <DO name="Ind1" type="SPStype"/>
        \\    </LNodeType>
        \\    <DOType id="INCtype" cdc="INC">
        \\      <DA name="stVal" bType="INT32" fc="ST"/>
        \\    </DOType>
        \\    <DOType id="SPStype" cdc="SPS">
        \\      <DA name="stVal" bType="BOOLEAN" fc="ST"/>
        \\    </DOType>
        \\  </DataTypeTemplates>
        \\</SCL>
    ;
    var a = try scl.parse(testing.allocator, src, .{});
    defer a.deinit();
    const ln0 = a.ieds[0].access_points[0].devices[0].lns[0];
    try testing.expectEqual(@as(usize, 3), ln0.logs.len);
    try testing.expectEqualStrings("GeneralLog", ln0.logs[0].name);
    try testing.expectEqualStrings("the other one", ln0.logs[1].desc);
    // A `<Log/>` with no name is the node's default log, not an error.
    try testing.expectEqualStrings("", ln0.logs[2].name);

    const out = try emitParsed(testing.allocator, &a, .{});
    defer testing.allocator.free(out);
    try testing.expect(std.mem.find(u8, out, "<Log name=\"GeneralLog\"/>") != null);
    try testing.expect(std.mem.find(u8, out, "<Log name=\"SecondLog\" desc=\"the other one\"/>") != null);
    try testing.expect(std.mem.find(u8, out, "<Log/>") != null);
    // …after the DOIs, which is where `tAnyLN` sequences it.
    const log_at = std.mem.find(u8, out, "<Log ").?;
    const lcb_at = std.mem.find(u8, out, "<LogControl ").?;
    try testing.expect(lcb_at < log_at);

    var b = try scl.parse(testing.allocator, out, .{});
    defer b.deinit();
    const ln0b = b.ieds[0].access_points[0].devices[0].lns[0];
    try testing.expectEqual(@as(usize, 3), ln0b.logs.len);
    try testing.expectEqualStrings("SecondLog", ln0b.logs[1].name);

    try roundTrip(src, "LOGIED");
}

// ── whole-module mutation audit 2026-11-18 (second pass): the emitter, exactly ──

fn has(hay: []const u8, needle: []const u8) bool {
    return std.mem.find(u8, hay, needle) != null;
}

/// A hand-built document with every empty-element case, every default that must
/// be left out and every flag that must be written.
const hand_params = [_]scl.Param{.{ .type = "IP", .value = "1.2.3.4" }};
const hand_gse = [_]scl.CbAddress{.{ .ld_inst = "L1", .cb_name = "g1", .min_time_ms = 10, .max_time_ms = 20 }};
const hand_aps = [_]scl.ConnectedAp{
    .{ .ied_name = "A", .ap_name = "p0" },
    .{ .ied_name = "B", .ap_name = "p1", .gse = &hand_gse },
    .{ .ied_name = "C", .ap_name = "p2", .address = .{ .params = &hand_params } },
};
const hand_subs = [_]scl.Subnetwork{
    .{ .name = "empty" },
    .{ .name = "n1", .type = "8-MMS", .aps = &hand_aps },
};
const hand_fcda = [_]scl.Fcda{.{ .ld_inst = "LD", .ln_class = "GGIO", .do_name = "Ind", .fc = .ST }};
const hand_sets = [_]scl.DataSet{
    .{ .name = "DS0" },
    .{ .name = "DS1", .fcdas = &hand_fcda },
};
const hand_rcb = [_]scl.ReportControl{.{ .name = "R", .dat_set = "DS1", .conf_rev = 2, .buffered = true, .indexed = false }};
const hand_lcb = [_]scl.LogControl{.{ .name = "L", .log_ena = false }};
const hand_gcb = [_]scl.GseControl{
    .{ .name = "g1" },
    .{ .name = "g2", .type = "GSSE" },
};
const hand_dai_values = [_][]const u8{"1"};
const hand_dais = [_]scl.Dai{
    .{ .path = "a..b", .values = &hand_dai_values },
    .{ .path = "", .values = &[_][]const u8{"ghost"} },
    .{ .path = "c" },
};
const hand_dois = [_]scl.Doi{
    .{ .name = "D0" },
    .{ .name = "D1", .dais = &hand_dais },
};
const hand_lns = [_]scl.Ln{
    .{ .ln_class = "GGIO", .ln_type = "TG", .inst = "1" },
    .{
        .ln_class = "LLN0",
        .ln_type = "T0",
        .is_ln0 = true,
        .data_sets = &hand_sets,
        .report_controls = &hand_rcb,
        .log_controls = &hand_lcb,
        .gse_controls = &hand_gcb,
        .setting_control = .{},
        .dois = &hand_dois,
    },
};
const hand_lds = [_]scl.LDevice{
    .{ .inst = "LNone" },
    .{ .inst = "LFull", .lns = &hand_lns },
};
const hand_ied_aps = [_]scl.AccessPoint{
    .{ .name = "apNo" },
    .{ .name = "apLd", .devices = &hand_lds },
};
const hand_ieds = [_]scl.Ied{
    .{ .name = "I0" },
    .{ .name = "I1", .access_points = &hand_ied_aps },
};
const hand_dos = [_]scl.DoRef{.{ .name = "Beh", .type = "DO1", .transient = true }};
const hand_ln_types = [_]scl.LNodeType{
    .{ .id = "T0" },
    .{ .id = "T1", .ln_class = "GGIO", .dos = &hand_dos },
};
const hand_sdos = [_]scl.SdoRef{
    .{ .name = "s0", .type = "DO0" },
    .{ .name = "s1", .type = "DO0", .count = 3 },
};
const hand_das = [_]scl.DaRef{.{ .name = "stVal", .fc = .ST, .b_type = .INT32, .dchg = true, .qchg = true, .dupd = true, .count = 4 }};
const hand_do_types = [_]scl.DoType{
    .{ .id = "DO0" },
    .{ .id = "DO1", .cdc = "INS", .sdos = &hand_sdos },
    .{ .id = "DO2", .das = &hand_das },
};
const hand_bdas = [_]scl.DaRef{.{ .name = "b", .b_type = .BOOLEAN }};
const hand_da_types = [_]scl.DaType{
    .{ .id = "DT0" },
    .{ .id = "DT1", .bdas = &hand_bdas },
};
const hand_vals = [_]scl.EnumVal{.{ .ord = 1, .text = "one" }};
const hand_enums = [_]scl.EnumType{
    .{ .id = "E0" },
    .{ .id = "E1", .vals = &hand_vals },
};
const hand_doc = Document{
    .subnetworks = &hand_subs,
    .ieds = &hand_ieds,
    .templates = .{
        .ln_types = &hand_ln_types,
        .do_types = &hand_do_types,
        .da_types = &hand_da_types,
        .enum_types = &hand_enums,
    },
};

test "emit: every element with no content is self-closing, every default is left out, every flag is written" {
    const out = try emit(testing.allocator, hand_doc, .{ .indent = false });
    defer testing.allocator.free(out);
    // Empty containers.
    try testing.expect(has(out, "<SubNetwork name=\"empty\"/>\n"));
    try testing.expect(has(out, "<ConnectedAP iedName=\"A\" apName=\"p0\"/>\n"));
    try testing.expect(has(out, "<IED name=\"I0\"/>\n"));
    try testing.expect(has(out, "<AccessPoint name=\"apNo\"/>\n"));
    try testing.expect(has(out, "<LDevice inst=\"LNone\"/>\n"));
    try testing.expect(has(out, "<LN lnClass=\"GGIO\" inst=\"1\" lnType=\"TG\"/>\n"));
    try testing.expect(has(out, "<DataSet name=\"DS0\"/>\n"));
    try testing.expect(has(out, "<DOI name=\"D0\"/>\n"));
    try testing.expect(has(out, "<LNodeType id=\"T0\"/>\n"));
    try testing.expect(has(out, "<DOType id=\"DO0\"/>\n"));
    try testing.expect(has(out, "<DAType id=\"DT0\"/>\n"));
    try testing.expect(has(out, "<EnumType id=\"E0\"/>\n"));
    // An address element only where there are parameters; the GSE is kept without one.
    try testing.expect(!has(out, "<Address></Address>"));
    try testing.expect(!has(out, "<Address>\n</Address>"));
    try testing.expect(has(out, "<GSE ldInst=\"L1\" cbName=\"g1\"><MinTime>10</MinTime>\n<MaxTime>20</MaxTime>\n</GSE>\n"));
    // LN0 is written before the LNs.
    try testing.expect(std.mem.find(u8, out, "<LN0 ").? < std.mem.find(u8, out, "<LN lnClass=\"GGIO\"").?);
    // Flags and counts that differ from the default are written, the others are not.
    try testing.expect(has(out, "<ReportControl name=\"R\" datSet=\"DS1\" confRev=\"2\" buffered=\"true\" indexed=\"false\">"));
    try testing.expect(has(out, "<LogControl name=\"L\" datSet=\"\" logName=\"\" logEna=\"false\">"));
    try testing.expect(has(out, "<SettingControl/>\n"));
    try testing.expect(has(out, "<GSEControl name=\"g1\"/>\n"));
    try testing.expect(has(out, "<GSEControl name=\"g2\" type=\"GSSE\"/>\n"));
    try testing.expect(has(out, "<DO name=\"Beh\" type=\"DO1\" transient=\"true\"/>\n"));
    try testing.expect(has(out, "<SDO name=\"s0\" type=\"DO0\"/>\n"));
    try testing.expect(has(out, "<SDO name=\"s1\" type=\"DO0\" count=\"3\"/>\n"));
    try testing.expect(has(out, "<DA name=\"stVal\" fc=\"ST\" bType=\"INT32\" dchg=\"true\" qchg=\"true\" dupd=\"true\" count=\"4\"/>\n"));
    // A DOType with only SDOs is not empty.
    try testing.expect(has(out, "<DOType id=\"DO1\" cdc=\"INS\"><SDO "));
    // DAI paths: empty components vanish, an empty path writes nothing.
    try testing.expect(has(out, "<SDI name=\"a\"><DAI name=\"b\"><Val>1</Val>\n</DAI>\n</SDI>\n"));
    try testing.expect(has(out, "<DAI name=\"c\"/>\n"));
    try testing.expect(!has(out, "ghost"));
    try testing.expect(!has(out, "name=\"\""));
    // Defaults are not written.
    try testing.expect(!has(out, "intgPd="));
    try testing.expect(!has(out, "bufTime="));
    try testing.expect(!has(out, "numOfSGs="));
    try testing.expect(!has(out, "fixedOffs="));
    try testing.expect(!has(out, "count=\"0\""));
    try testing.expect(!has(out, "<Communication>\n</Communication>"));
}

test "emit: indentation follows the depth, and every end tag gives its level back" {
    const out = try emit(testing.allocator, hand_doc, .{});
    defer testing.allocator.free(out);
    try testing.expect(has(out, "\n  <Header id=\"\"/>\n"));
    // Communication > SubNetwork > ConnectedAP > Address > P: five levels below the root.
    try testing.expect(has(out, "\n          <P type=\"IP\">1.2.3.4</P>\n"));
    // The last section starts at the level of the first, however much came before it.
    try testing.expect(has(out, "\n  <DataTypeTemplates>\n"));
    try testing.expect(has(out, "\n    <EnumType id=\"E0\"/>\n"));
    try testing.expect(has(out, "\n  </DataTypeTemplates>\n"));
    try testing.expect(has(out, "\n  <IED name=\"I1\">\n"));
    try testing.expect(has(out, "\n  </IED>\n"));
    try testing.expect(std.mem.endsWith(u8, out, "\n</SCL>\n"));
    // The same document without indentation has no leading blanks at all.
    const flat = try emit(testing.allocator, hand_doc, .{ .indent = false });
    defer testing.allocator.free(flat);
    try testing.expect(!has(flat, "\n "));
    try testing.expect(has(flat, "<IED name=\"I1\"><AccessPoint "));
}

test "emit with no subnetworks and no templates writes neither section" {
    const out = try emit(testing.allocator, .{}, .{});
    defer testing.allocator.free(out);
    try testing.expect(!has(out, "Communication"));
    try testing.expect(!has(out, "DataTypeTemplates"));
}

test "emitParsed takes the source namespace unless the caller names one" {
    var s = try scl.parse(testing.allocator, scl.sample, .{});
    defer s.deinit();
    const a = try emitParsed(testing.allocator, &s, .{ .allow_lossy = true });
    defer testing.allocator.free(a);
    try testing.expect(has(a, "xmlns=\"http://www.iec.ch/61850/2003/SCL\""));
    const b = try emitParsed(testing.allocator, &s, .{ .namespace = "urn:caller" });
    defer testing.allocator.free(b);
    try testing.expect(has(b, "xmlns=\"urn:caller\""));
    try testing.expect(!has(b, "2003/SCL"));
    // A source with no namespace is written in edition 2.
    var bare = try scl.parse(testing.allocator, "<SCL><Header id=\"x\"/></SCL>", .{});
    defer bare.deinit();
    const c = try emitParsed(testing.allocator, &bare, .{});
    defer testing.allocator.free(c);
    try testing.expect(has(c, "xmlns=\"" ++ scl.ns_2007 ++ "\""));
}

/// A document whose only content is one DOI carrying a DAI of the given path.
fn emitWithDaiPath(path: []const u8) Error![]u8 {
    const dais = [_]scl.Dai{.{ .path = path }};
    const dois = [_]scl.Doi{.{ .name = "D", .dais = &dais }};
    const lns = [_]scl.Ln{.{ .ln_class = "GGIO", .ln_type = "T", .dois = &dois }};
    const lds = [_]scl.LDevice{.{ .inst = "L", .lns = &lns }};
    const aps = [_]scl.AccessPoint{.{ .name = "p", .devices = &lds }};
    const ieds = [_]scl.Ied{.{ .name = "I", .access_points = &aps }};
    return emit(testing.allocator, .{ .ieds = &ieds }, .{});
}

test "a DAI path of twelve components is written, thirteen are refused" {
    const ok = try emitWithDaiPath("a.b.c.d.e.f.g.h.i.j.k.l");
    defer testing.allocator.free(ok);
    try testing.expect(has(ok, "<DAI name=\"l\"/>"));
    try testing.expectError(error.CyclicType, emitWithDaiPath("a.b.c.d.e.f.g.h.i.j.k.l.m"));
    // Nothing at all to write: no element.
    const none = try emitWithDaiPath("..");
    defer testing.allocator.free(none);
    try testing.expect(!has(none, "<DAI"));
}

test "the type-graph bound is exact: twelve levels pass, thirteen are a cycle" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_]usize{ max_type_depth, max_type_depth + 1 }) |levels| {
        const do_types = try a.alloc(scl.DoType, levels);
        const da_types = try a.alloc(scl.DaType, levels);
        for (0..levels) |i| {
            const next_do = try std.fmt.allocPrint(a, "D{d}", .{i + 1});
            const next_da = try std.fmt.allocPrint(a, "T{d}", .{i + 1});
            const sdos = try a.alloc(scl.SdoRef, if (i + 1 < levels) 1 else 0);
            if (sdos.len == 1) sdos[0] = .{ .name = "s", .type = next_do };
            do_types[i] = .{ .id = try std.fmt.allocPrint(a, "D{d}", .{i}), .sdos = sdos };
            const bdas = try a.alloc(scl.DaRef, 1);
            bdas[0] = if (i + 1 < levels)
                .{ .name = "b", .b_type = .Struct, .type = next_da }
            else
                .{ .name = "b", .b_type = .BOOLEAN };
            da_types[i] = .{ .id = try std.fmt.allocPrint(a, "T{d}", .{i}), .bdas = bdas };
        }
        // Each chain on its own, so the one under test is the only one deep enough.
        const do_only = scl.Templates{ .do_types = do_types };
        const da_only = scl.Templates{ .da_types = da_types };
        if (levels <= max_type_depth) {
            try checkTypeGraph(do_only);
            try checkTypeGraph(da_only);
        } else {
            try testing.expectError(error.CyclicType, checkTypeGraph(do_only));
            try testing.expectError(error.CyclicType, checkTypeGraph(da_only));
        }
    }
}

test "a data attribute that merely names a long structure type does not make the walk deeper" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Twelve structure levels are the deepest a walk from the root accepts.
    const levels = max_type_depth;
    const da_types = try a.alloc(scl.DaType, levels + 1);
    for (0..levels) |i| {
        const bdas = try a.alloc(scl.DaRef, 1);
        bdas[0] = if (i + 1 < levels)
            .{ .name = "b", .b_type = .Struct, .type = try std.fmt.allocPrint(a, "T{d}", .{i + 1}) }
        else
            .{ .name = "b", .b_type = .BOOLEAN };
        da_types[i] = .{ .id = try std.fmt.allocPrint(a, "T{d}", .{i}), .bdas = bdas };
    }
    // One more type whose member is an Enum that happens to be spelled like the chain's head.
    const enum_bda = [_]scl.DaRef{.{ .name = "e", .b_type = .Enum, .type = "T0" }};
    da_types[levels] = .{ .id = "TX", .bdas = &enum_bda };
    const enum_da = [_]scl.DaRef{.{ .name = "e", .fc = .ST, .b_type = .Enum, .type = "T0" }};
    const do_types = [_]scl.DoType{.{ .id = "DX", .das = &enum_da }};
    try checkTypeGraph(.{ .do_types = &do_types, .da_types = da_types });
}
