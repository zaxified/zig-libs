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
//! What is **not** emitted, because `scl.zig` does not parse it and inventing it
//! would be worse than leaving it out: the `Substation` section, `Private` and
//! `Text` elements, `Services`, `SampledValueControl` and `Inputs`/`ExtRef`.
//! A document that had them loses them; `emitParsed` says so by refusing when
//! `Scl.has_substation` is set unless the caller opts in. This is a *model*
//! writer, not a round-tripping editor for someone else's file.
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
    /// Emit a document even though the source had sections this writer drops.
    allow_lossy: bool = false,
};

/// Everything this writer serialises. Taking the parts rather than an `Scl`
/// keeps the emitter testable with a hand-built model — including a hostile one.
pub const Document = struct {
    header: scl.Header = .{},
    subnetworks: []const scl.Subnetwork = &.{},
    ieds: []const scl.Ied = &.{},
    templates: scl.Templates = .{},
};

/// Serialises a parsed document. Fails with `LossyDocument` when the source had
/// a `Substation` section, because dropping the single-line diagram silently is
/// exactly the kind of thing that makes a round trip a lie.
pub fn emitParsed(gpa: std.mem.Allocator, s: *const scl.Scl, options: Options) Error![]u8 {
    if (s.has_substation and !options.allow_lossy) return error.LossyDocument;
    var o = options;
    if (o.namespace == null and s.doc.root.uri.len > 0) o.namespace = s.doc.root.uri;
    return emit(gpa, .{
        .header = s.header,
        .subnetworks = s.subnetworks,
        .ieds = s.ieds,
        .templates = s.templates,
    }, o);
}

/// Serialises a model. The caller owns the returned bytes.
pub fn emit(gpa: std.mem.Allocator, doc: Document, options: Options) Error![]u8 {
    if (options.check_types) try checkTypeGraph(doc.templates);

    var w = Writer{ .gpa = gpa, .options = options };
    errdefer w.buf.deinit(gpa);

    try w.raw("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    try w.raw("<SCL xmlns=\"");
    try w.text(options.namespace orelse scl.ns_2007);
    try w.raw("\">\n");
    w.depth = 1;

    try w.open("Header");
    try w.attr("id", doc.header.id);
    try w.attrIf("version", doc.header.version);
    try w.attrIf("revision", doc.header.revision);
    try w.attrIf("toolID", doc.header.tool_id);
    try w.attrIf("nameStructure", doc.header.name_structure);
    try w.closeEmpty();

    if (doc.subnetworks.len > 0) {
        try w.openDone("Communication");
        for (doc.subnetworks) |sub| try emitSubnetwork(&w, sub);
        try w.end("Communication");
    }

    for (doc.ieds) |ied| try emitIed(&w, ied);
    try emitTemplates(&w, doc.templates);

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

fn emitSubnetwork(w: *Writer, sub: scl.Subnetwork) Error!void {
    try w.open("SubNetwork");
    try w.attr("name", sub.name);
    try w.attrIf("type", sub.type);
    if (sub.aps.len == 0) return w.closeEmpty();
    try w.closeOpen();
    for (sub.aps) |ap| {
        try w.open("ConnectedAP");
        try w.attr("iedName", ap.ied_name);
        try w.attr("apName", ap.ap_name);
        const empty = ap.address.params.len == 0 and ap.gse.len == 0 and ap.smv.len == 0;
        if (empty) {
            try w.closeEmpty();
            continue;
        }
        try w.closeOpen();
        try emitAddress(w, ap.address);
        for (ap.gse) |g| try emitCbAddress(w, "GSE", g);
        for (ap.smv) |g| try emitCbAddress(w, "SMV", g);
        try w.end("ConnectedAP");
    }
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
    try emitAddress(w, g.address);
    if (g.min_time_ms) |v| try w.textElement("MinTime", v);
    if (g.max_time_ms) |v| try w.textElement("MaxTime", v);
    try w.end(tag);
}

fn emitIed(w: *Writer, ied: scl.Ied) Error!void {
    try w.open("IED");
    try w.attr("name", ied.name);
    try w.attrIf("type", ied.type);
    try w.attrIf("manufacturer", ied.manufacturer);
    try w.attrIf("configVersion", ied.config_version);
    if (ied.access_points.len == 0) return w.closeEmpty();
    try w.closeOpen();
    for (ied.access_points) |ap| {
        try w.open("AccessPoint");
        try w.attr("name", ap.name);
        if (ap.devices.len == 0) {
            try w.closeEmpty();
            continue;
        }
        try w.closeOpen();
        try w.openDone("Server");
        for (ap.devices) |ld| try emitLDevice(w, ld);
        try w.end("Server");
        try w.end("AccessPoint");
    }
    try w.end("IED");
}

fn emitLDevice(w: *Writer, ld: scl.LDevice) Error!void {
    try w.open("LDevice");
    try w.attr("inst", ld.inst);
    try w.attrIf("ldName", ld.ld_name);
    if (ld.lns.len == 0) return w.closeEmpty();
    try w.closeOpen();
    // `LN0` must come first — the schema sequences it before the `LN`s.
    for (ld.lns) |ln| {
        if (ln.is_ln0) try emitLn(w, ln);
    }
    for (ld.lns) |ln| {
        if (!ln.is_ln0) try emitLn(w, ln);
    }
    try w.end("LDevice");
}

fn emitLn(w: *Writer, ln: scl.Ln) Error!void {
    const tag: []const u8 = if (ln.is_ln0) "LN0" else "LN";
    try w.open(tag);
    try w.attrIf("prefix", ln.prefix);
    try w.attr("lnClass", ln.ln_class);
    try w.attr("inst", ln.inst);
    try w.attr("lnType", ln.ln_type);
    const empty = ln.dois.len == 0 and ln.data_sets.len == 0 and
        ln.report_controls.len == 0 and ln.gse_controls.len == 0 and
        ln.log_controls.len == 0 and ln.logs.len == 0 and ln.setting_control == null;
    if (empty) return w.closeEmpty();
    try w.closeOpen();

    for (ln.data_sets) |ds| {
        try w.open("DataSet");
        try w.attr("name", ds.name);
        try w.attrIf("desc", ds.desc);
        if (ds.fcdas.len == 0) {
            try w.closeEmpty();
            continue;
        }
        try w.closeOpen();
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
        try w.end("DataSet");
    }

    for (ln.report_controls) |r| try emitReportControl(w, r);

    for (ln.log_controls) |l| {
        try w.open("LogControl");
        try w.attr("name", l.name);
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
        try w.attrIf("appID", g.app_id);
        try w.attrIf("datSet", g.dat_set);
        try w.attrUintDefault("confRev", g.conf_rev, 1);
        if (!std.mem.eql(u8, g.type, "GOOSE")) try w.attrIf("type", g.type);
        try w.attrBoolDefault("fixedOffs", g.fixed_offs, false);
        try w.closeEmpty();
    }

    for (ln.dois) |d| try emitDoi(w, d);

    // `<Log>` sits after the `DOI`s in `tAnyLN`'s sequence, which is where the
    // schema puts it and where every generator reading the file back expects
    // it. A log with no name is legal — it is the node's default log.
    for (ln.logs) |l| {
        try w.open("Log");
        try w.attrIf("name", l.name);
        try w.attrIf("desc", l.desc);
        try w.closeEmpty();
    }
    try w.end(tag);
}

fn emitReportControl(w: *Writer, r: scl.ReportControl) Error!void {
    try w.open("ReportControl");
    try w.attr("name", r.name);
    try w.attrIf("rptID", r.rpt_id);
    try w.attr("datSet", r.dat_set);
    try w.attrUint("confRev", r.conf_rev);
    try w.attrBoolDefault("buffered", r.buffered, false);
    try w.attrUintDefault("intgPd", r.intg_pd, 0);
    try w.attrUintDefault("bufTime", r.buf_time, 0);
    try w.attrBoolDefault("indexed", r.indexed, true);
    try w.closeOpen();
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
    if (d.dais.len == 0) return w.closeEmpty();
    try w.closeOpen();
    for (d.dais) |dai| try emitDai(w, dai);
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
        try self.attr(name, std.fmt.bufPrint(&tmp, "{d}", .{value}) catch unreachable);
    }

    fn attrInt(self: *Writer, name: []const u8, value: i64) Error!void {
        var tmp: [24]u8 = undefined;
        try self.attr(name, std.fmt.bufPrint(&tmp, "{d}", .{value}) catch unreachable);
    }

    fn textElement(self: *Writer, name: []const u8, value: u64) Error!void {
        try self.open(name);
        try self.closeInline();
        var tmp: [24]u8 = undefined;
        try self.text(std.fmt.bufPrint(&tmp, "{d}", .{value}) catch unreachable);
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
    try testing.expect(std.mem.indexOf(u8, out, scl.ns_2003) != null);
    try testing.expect(std.mem.endsWith(u8, out, "</SCL>\n"));
    // No DOCTYPE — the sibling parser refuses one, and so should every other.
    try testing.expect(std.mem.indexOf(u8, out, "<!DOCTYPE") == null);

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
        if (std.mem.indexOf(u8, out, needle) == null) {
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

test "a document with a Substation section is refused rather than silently trimmed" {
    const with_substation =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<SCL xmlns="http://www.iec.ch/61850/2003/SCL">
        \\  <Header id="X"/>
        \\  <Substation name="S1"/>
        \\</SCL>
    ;
    var doc = try scl.parse(testing.allocator, with_substation, .{});
    defer doc.deinit();
    try testing.expect(doc.has_substation);
    try testing.expectError(error.LossyDocument, emitParsed(testing.allocator, &doc, .{}));
    // …and the caller can say "yes, I know".
    const out = try emitParsed(testing.allocator, &doc, .{ .allow_lossy = true });
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "Substation") == null);
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
    try testing.expect(std.mem.indexOf(u8, out, "<DAType id=\"Vector\"") != null);
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
    try testing.expect(std.mem.indexOf(u8, out, "&lt;script&gt;&amp;&quot;") != null);
    try testing.expect(std.mem.indexOf(u8, out, "a &lt; b &amp; c &gt; d \"q\"") != null);
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
    try testing.expect(std.mem.indexOf(u8, out, "<Log name=\"GeneralLog\"/>") != null);
    try testing.expect(std.mem.indexOf(u8, out, "<Log name=\"SecondLog\" desc=\"the other one\"/>") != null);
    try testing.expect(std.mem.indexOf(u8, out, "<Log/>") != null);
    // …after the DOIs, which is where `tAnyLN` sequences it.
    const log_at = std.mem.indexOf(u8, out, "<Log ").?;
    const lcb_at = std.mem.indexOf(u8, out, "<LogControl ").?;
    try testing.expect(lcb_at < log_at);

    var b = try scl.parse(testing.allocator, out, .{});
    defer b.deinit();
    const ln0b = b.ieds[0].access_points[0].devices[0].lns[0];
    try testing.expectEqual(@as(usize, 3), ln0b.logs.len);
    try testing.expectEqualStrings("SecondLog", ln0b.logs[1].name);

    try roundTrip(src, "LOGIED");
}
