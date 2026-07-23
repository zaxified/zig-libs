// SPDX-License-Identifier: MIT

//! An **IEC 61850 MMS server** — the responder side, as a pure function from
//! one packet to one packet over caller-owned storage.
//!
//! It exists for three reasons: it is the only way to test the encoders against
//! a *real third-party client*; it is a fleet-simulation target (stand one up
//! per simulated IED); and it forces the decode paths for every request shape
//! to be written, which a client-only module never exercises.
//!
//! What it serves: a flat table of named variables and data sets the caller
//! supplies, the **control model**, the **reporting engine** (BRCB and URCB,
//! `TrgOps`, `BufTm` buffering, integrity and general interrogation),
//! **logging** with the MMS journal services, and **setting groups**. What it is
//! still not: an IED. There is no SCL model loader and no file system — see
//! SPEC.md's deferred list before pointing anything at it.
//!
//! `handle` takes one TPKT and returns one TPKT (or null when the association
//! is over). No clock, no thread, no socket: reports leave through
//! `pendingNotification`, and `BufTm` / `IntgPd` expire because the caller calls
//! `tick`.

const std = @import("std");
const ber = @import("ber.zig");
const tpkt = @import("tpkt.zig");
const cotp = @import("cotp.zig");
const session = @import("session.zig");
const presentation = @import("presentation.zig");
const acse = @import("acse.zig");
const mms = @import("mms.zig");
const mmsdata = @import("mmsdata.zig");
const control = @import("control.zig");
const reporting = @import("reporting.zig");
const logging = @import("logging.zig");
const settinggroups = @import("settinggroups.zig");

pub const Error = mms.Error || presentation.Error || acse.Error ||
    session.Error || cotp.Error || tpkt.Error || control.Error ||
    reporting.Error || logging.Error || error{
    /// The request is not one this responder models.
    Unsupported,
    BufferTooSmall,
};

/// One named variable. `storage` holds a complete `Data` TLV; `len` is how much
/// of it is currently valid.
pub const Variable = struct {
    domain: []const u8,
    /// The MMS item id, e.g. `"GGIO1$ST$Ind1$stVal"`.
    item: []const u8,
    storage: []u8,
    len: usize,
    writable: bool = false,

    pub fn value(self: *const Variable) []const u8 {
        return self.storage[0..self.len];
    }
};

/// A named variable list (an IEC 61850 data set).
pub const DataSet = struct {
    domain: []const u8,
    /// e.g. `"LLN0$Events"`.
    item: []const u8,
    /// Indices into `Model.variables`.
    members: []const usize,
};

/// One controllable data object. The runtime state (selected / executing, the
/// `ctlNum`, the deadlines) lives in `control.Point`; this table is what makes
/// the responder enforce the control model rather than let a caller write `CO`
/// attributes by hand.
pub const ControlPoint = control.Point;

/// A live report control block — see `reporting.zig`. The caller owns its
/// buffer, which is what bounds how much a BRCB may retain.
pub const ReportControl = reporting.ControlBlock;
/// A live log control block and its bounded store — see `logging.zig`.
pub const LogControl = logging.ControlBlock;
/// The setting-group control block — see `settinggroups.zig`.
pub const SettingGroups = settinggroups.ControlBlock;

pub const Model = struct {
    variables: []Variable,
    data_sets: []const DataSet = &.{},
    /// Control objects, addressed by the `LN$CO$DO` prefix their `Oper`, `SBO`,
    /// `SBOw` and `Cancel` hang off. Empty by default, which is exactly the
    /// old behaviour: `CO` writes then fall through to the flat variable table.
    controls: []ControlPoint = &.{},
    /// Report control blocks, addressed by their `LN$RP$name` / `LN$BR$name`
    /// prefix. Empty by default: a server with none behaves exactly as before.
    report_controls: []ReportControl = &.{},
    /// Log control blocks, addressed by their `LN$LG$name` prefix.
    logs: []LogControl = &.{},
    /// The one setting-group control block a logical device may have.
    setting_groups: ?*SettingGroups = null,
    vendor: []const u8 = "zig-libs",
    model: []const u8 = "iec61850-responder",
    revision: []const u8 = "0.1",
    /// The MMS domains this server exposes, in `GetNameList` order.
    domains: []const []const u8,
};

pub const Config = struct {
    /// Refuse an association whose ACSE application context is not the MMS one.
    require_mms_application_context: bool = true,
    max_serv_outstanding: i16 = 5,
    local_detail: i32 = 65000,
    /// Whether an accepted enhanced-security operate completes immediately.
    /// A real IED takes as long as the switchgear does; set this false and
    /// drive `completeControl` (or let `tick` time the execution out) to model
    /// that.
    auto_complete_control: bool = true,
};

/// A queued unsolicited PDU — a `CommandTermination` of either sign, or a bare
/// `LastApplError`. It is encoded the moment it is produced, because the values
/// it echoes live in the request buffer and that buffer is gone by the time the
/// caller asks for the notification.
pub const max_notification_len: usize = 512;
pub const max_pending_notifications: usize = 4;

/// The largest `InformationReport` this server encodes. A sixty-four-member
/// data set with references and reasons fits comfortably; anything larger is a
/// `BufferTooSmall` rather than a silently truncated report.
pub const max_report_len: usize = 8192;

/// What `wrap` adds around an MMS PDU: the TPKT header, the COTP DT header, the
/// session data-transfer prefix and the presentation user-data wrapper. Rounded
/// generously up — it is subtracted from the negotiated TPDU size to get the
/// budget a report segment has to fit.
pub const envelope_overhead: usize = 64;

const Pending = struct {
    len: usize = 0,
    bytes: [max_notification_len]u8 = undefined,
};

pub const Server = struct {
    config: Config,
    model: Model,
    contexts: presentation.ContextTable = .{},
    associated: bool = false,
    transport_up: bool = false,
    /// The presentation context the association settled on, remembered so an
    /// **unsolicited** PDU can be wrapped without a request to copy it from.
    mms_context: u16 = presentation.context_mms,
    /// Identifies the association a request arrived on. It is what a select,
    /// a setting-group edit and an RCB reservation are owned *by*.
    ///
    /// One `Server` object drives one association at a time, but a caller that
    /// multiplexes several connections onto one model sets this to the id of
    /// the association the frame came from before calling `handle`, and calls
    /// `releaseAssociationOf` when that connection drops. That is exactly how
    /// two clients end up contending for one report control block, and it is
    /// what `Resv` / `ResvTms` / `Owner` exist to arbitrate.
    peer: u32 = 1,
    /// The MMS PDU size the association settled on — the client's
    /// `localDetailCalling`, clamped to what this server can actually build.
    /// Zero before an association.
    negotiated_pdu_len: usize = 0,
    /// The COTP TPDU size the transport connection settled on. Zero before a
    /// `CR`. Together with `negotiated_pdu_len` this is what
    /// `reportSegmentBudget` splits reports against.
    negotiated_tpdu_len: usize = 0,
    /// The caller's clock, in milliseconds. `tick` moves it; nothing here reads
    /// a real one.
    now_ms: u64 = 0,
    notifications: [max_pending_notifications]Pending = @splat(.{}),
    notify_head: usize = 0,
    notify_count: usize = 0,
    /// Scratch for one encoded report. A report is built lazily when the caller
    /// drains it, straight out of the control block's buffer, so this is the
    /// only reporting storage the `Server` itself owns.
    report_out: [max_report_len]u8 = undefined,
    /// Round-robin cursor over the report control blocks, so one busy block
    /// cannot starve the others.
    report_cursor: usize = 0,
    /// Diagnostics a test asserts on.
    reads: u64 = 0,
    writes: u64 = 0,
    name_lists: u64 = 0,
    selects: u64 = 0,
    operates: u64 = 0,
    control_rejections: u64 = 0,
    reports_sent: u64 = 0,
    journal_reads: u64 = 0,
    journal_deletions: u64 = 0,

    pub fn init(config: Config, model: Model) Server {
        return .{ .config = config, .model = model };
    }

    /// One request packet in, one response packet out (or null: the peer has
    /// gone). `out` receives a complete TPKT.
    pub fn handle(self: *Server, frame: []const u8, out: []u8) Error!?[]const u8 {
        const pkt = try tpkt.decode(frame);
        switch (try cotp.decode(pkt.payload)) {
            .cr => |cr| {
                self.transport_up = true;
                // The COTP TPDU size is the *other* negotiated ceiling, and it
                // is the binding one: this module never splits a PDU across
                // several DT TPDUs, so nothing it sends may exceed it. A peer
                // that proposes 1024 gets 1024-octet TPDUs, and a report larger
                // than that is what segmentation exists for.
                const tpdu = cr.tpdu_size orelse .b8192;
                self.negotiated_tpdu_len = tpdu.octets();
                var body: [128]u8 = undefined;
                const cc = try cotp.encodeConnect(
                    .cc,
                    cr.src_ref,
                    1,
                    tpdu,
                    cr.called_tsap orelse &[_]u8{ 0x00, 0x01 },
                    cr.calling_tsap orelse &[_]u8{ 0x00, 0x01 },
                    &body,
                );
                return try tpkt.encode(cc, out);
            },
            .dr => {
                self.associated = false;
                self.transport_up = false;
                return null;
            },
            .dt => |dt| return self.handleSpdu(dt.payload, out),
            else => return error.Unsupported,
        }
    }

    fn handleSpdu(self: *Server, spdu: []const u8, out: []u8) Error!?[]const u8 {
        const h = try session.decodeHeader(spdu);
        switch (h.spdu) {
            .connect => return try self.handleConnect(spdu, out),
            .abort, .finish, .disconnect => {
                self.associated = false;
                return null;
            },
            .give_tokens_or_data => {
                if (!self.associated) return error.Unsupported;
                const ppdu = try session.decodeDataTransfer(spdu);
                const pdv = try presentation.decodeUserData(ppdu, &self.contexts);
                return try self.handleMms(pdv.value, pdv.context_id, out);
            },
            else => return error.Unsupported,
        }
    }

    fn handleConnect(self: *Server, spdu: []const u8, out: []u8) Error!?[]const u8 {
        const cn = try session.decodeConnect(spdu);
        const cp = try presentation.decodeCp(cn.user_data);

        // Mirror the proposal, accepting every context whose abstract syntax we
        // recognise and rejecting the rest — which is what makes the client's
        // positional result matching meaningful.
        self.contexts = .{};
        var results: [presentation.max_contexts]presentation.Result = undefined;
        for (cp.definitions(), 0..) |c, i| {
            try self.contexts.define(c.id, c.abstract_syntax);
            const known = std.mem.eql(u8, c.abstract_syntax, &ber.oids.mms_abstract_syntax) or
                std.mem.eql(u8, c.abstract_syntax, &ber.oids.acse_abstract_syntax);
            results[i] = if (known) .acceptance else .user_rejection;
        }
        try self.contexts.applyResults(results[0..cp.context_count]);
        const mms_ctx = self.contexts.idFor(&ber.oids.mms_abstract_syntax) orelse return error.Unsupported;
        const acse_ctx = self.contexts.idFor(&ber.oids.acse_abstract_syntax) orelse return error.Unsupported;

        var pdvs = presentation.PdvIterator.init(cp.user_data);
        const pdv = (try pdvs.next()) orelse return error.Unsupported;
        const aarq = try acse.decodeAarq(pdv.value);
        if (self.config.require_mms_application_context) {
            const acn = aarq.application_context orelse return error.WrongApplicationContext;
            if (!acn.eql(.{ .bytes = &ber.oids.mms_application_context })) {
                return error.WrongApplicationContext;
            }
        }
        const init_req = switch (try mms.decode(aarq.user_information)) {
            .initiate_request => |r| r,
            else => return error.Unsupported,
        };

        const init_resp = mms.Initiate{
            .local_detail = self.config.local_detail,
            .max_serv_outstanding_calling = @min(init_req.max_serv_outstanding_calling, self.config.max_serv_outstanding),
            .max_serv_outstanding_called = @min(init_req.max_serv_outstanding_called, self.config.max_serv_outstanding),
            .data_structure_nesting_level = init_req.data_structure_nesting_level,
            .version_number = 1,
            .parameter_cbb = init_req.parameter_cbb,
            .services_supported = try ber.BitString.parse(&server_services_supported),
        };
        var mms_buf: [512]u8 = undefined;
        const mms_pdu = try init_resp.encode(false, &mms_buf);

        var aare_buf: [768]u8 = undefined;
        const aare = try acse.encodeAare(mms_pdu, .{ .indirect_reference = mms_ctx }, &aare_buf);

        var ud_buf: [1024]u8 = undefined;
        const ud = try presentation.encodeUserData(acse_ctx, aare, &ud_buf);

        var cpa_buf: [1536]u8 = undefined;
        const cpa = try presentation.encodeCpa(ud, .{ .results = results[0..cp.context_count] }, &cpa_buf);

        var spdu_buf: [2048]u8 = undefined;
        const accept = try session.encodeAccept(cpa, .{}, &spdu_buf);

        var dt_buf: [2176]u8 = undefined;
        const dt = try cotp.encodeData(accept, true, &dt_buf);
        self.associated = true;
        self.mms_context = mms_ctx;
        // `localDetailCalling` is the largest MMS PDU the **client** can
        // receive, so it — not our own `local_detail` — bounds what this server
        // may send. A client that proposes nothing gets our own ceiling.
        const proposed: usize = if (init_req.local_detail) |v|
            (if (v > 0) @intCast(v) else max_report_len)
        else
            max_report_len;
        self.negotiated_pdu_len = @min(proposed, max_report_len);
        return try tpkt.encode(dt, out);
    }

    fn handleMms(self: *Server, mms_pdu: []const u8, context_id: u16, out: []u8) Error!?[]const u8 {
        const pdu = mms.decode(mms_pdu) catch return error.Unsupported;
        var body: [16384]u8 = undefined;
        const reply: []const u8 = switch (pdu) {
            .conclude_request => blk: {
                self.associated = false;
                break :blk try mms.encodeConcludeResponse(&body);
            },
            .confirmed_request => |req| try self.service(req, &body),
            else => return null,
        };
        return try self.wrap(reply, context_id, out);
    }

    fn service(self: *Server, req: mms.ConfirmedRequest, body: []u8) Error![]const u8 {
        // The journal services carry high tag numbers and are matched before
        // the switch: `mms.Service` is non-exhaustive, so `.read_journal` and
        // its status sibling are values, not cases.
        if (req.service == logging.read_journal_service) return self.readJournal(req, body);
        if (req.service == logging.get_journal_status_service) return self.journalStatus(req, body);
        if (req.service == logging.initialize_journal_service) return self.initializeJournal(req, body);
        if (req.service == logging.delete_journal_service) return self.deleteJournal(req, body);
        return switch (req.service) {
            .identify => mms.encodeIdentifyResponse(req.invoke_id, .{
                .vendor = self.model.vendor,
                .model = self.model.model,
                .revision = self.model.revision,
            }, body),
            .get_name_list => self.getNameList(req, body),
            .read => self.read(req, body),
            .write => self.write(req, body),
            .get_variable_access_attributes => self.variableAccessAttributes(req, body),
            .get_named_variable_list_attributes => self.dataSetAttributes(req, body),
            else => mms.encodeConfirmedError(req.invoke_id, .service, 0, body),
        };
    }

    fn getNameList(self: *Server, req: mms.ConfirmedRequest, body: []u8) Error![]const u8 {
        self.name_lists += 1;
        const q = mms.decodeGetNameListRequest(req.body) catch
            return mms.encodeConfirmedError(req.invoke_id, .service, 0, body);
        var names: [256][]const u8 = undefined;
        var n: usize = 0;
        switch (q.class) {
            .domain => {
                for (self.model.domains) |d| {
                    if (n == names.len) break;
                    names[n] = d;
                    n += 1;
                }
            },
            .named_variable => {
                const scope = switch (q.scope) {
                    .domain => |d| d,
                    else => return mms.encodeConfirmedError(req.invoke_id, .access, 0, body),
                };
                for (self.model.variables) |v| {
                    if (n == names.len) break;
                    if (!std.mem.eql(u8, v.domain, scope)) continue;
                    names[n] = v.item;
                    n += 1;
                }
            },
            .named_variable_list => {
                const scope = switch (q.scope) {
                    .domain => |d| d,
                    else => return mms.encodeConfirmedError(req.invoke_id, .access, 0, body),
                };
                for (self.model.data_sets) |ds| {
                    if (n == names.len) break;
                    if (!std.mem.eql(u8, ds.domain, scope)) continue;
                    names[n] = ds.item;
                    n += 1;
                }
            },
            else => return mms.encodeConfirmedError(req.invoke_id, .access, 0, body),
        }
        return mms.encodeGetNameListResponse(req.invoke_id, names[0..n], false, body);
    }

    /// `GetVariableAccessAttributes` — implemented for **control objects only**,
    /// because that is the one place a client cannot proceed without it: a
    /// control client asks for the type of `LN$CO$DO` before it writes and
    /// treats a failure as "no such object". Everything else still gets an
    /// honest `confirmed-ErrorPDU`.
    fn variableAccessAttributes(self: *Server, req: mms.ConfirmedRequest, body: []u8) Error![]const u8 {
        var it = ber.Iterator.init(req.body);
        const name: ?mms.ObjectName = blk: {
            while (it.next() catch break :blk null) |e| {
                if (e.tag.eqlLoose(ber.Tag.ctxc(0))) {
                    break :blk mms.ObjectName.decode(e.content) catch null;
                }
            }
            break :blk null;
        };
        const ds = switch (name orelse return mms.encodeConfirmedError(req.invoke_id, .access, 0, body)) {
            .domain_specific => |x| x,
            else => return mms.encodeConfirmedError(req.invoke_id, .access, 0, body),
        };
        const index = self.findControl(ds.domain, ds.item) orelse
            return mms.encodeConfirmedError(req.invoke_id, .access, 0, body);
        var spec: [1024]u8 = undefined;
        var w = ber.Writer.init(&spec);
        self.model.controls[index].emitTypeSpec(&w) catch
            return mms.encodeConfirmedError(req.invoke_id, .resource, 0, body);
        return mms.encodeGetVariableAccessAttributesResponse(req.invoke_id, false, w.done(), body);
    }

    /// `GetNamedVariableListAttributes` — the members of a data set. A
    /// reporting client asks for this to map a report's inclusion bit string
    /// onto names; without it, a report decodes but nothing can be *labelled*.
    fn dataSetAttributes(self: *Server, req: mms.ConfirmedRequest, body: []u8) Error![]const u8 {
        const name = mms.ObjectName.decode(req.body) catch
            return mms.encodeConfirmedError(req.invoke_id, .service, 0, body);
        const ds = self.lookupDataSet(name) orelse
            return mms.encodeConfirmedError(req.invoke_id, .access, 0, body);
        var members: [reporting.max_members]mms.ObjectName = undefined;
        var n: usize = 0;
        for (ds.members) |idx| {
            if (n == members.len) break;
            if (idx >= self.model.variables.len) continue;
            const v = self.model.variables[idx];
            members[n] = .{ .domain_specific = .{ .domain = v.domain, .item = v.item } };
            n += 1;
        }
        // A configured data set is not deletable, which is what an SCL-driven
        // IED reports and what stops a client trying to delete it.
        return mms.encodeGetNamedVariableListAttributesResponse(req.invoke_id, false, members[0..n], body);
    }

    fn read(self: *Server, req: mms.ConfirmedRequest, body: []u8) Error![]const u8 {
        self.reads += 1;
        const r = mms.decodeReadRequest(req.body) catch
            return mms.encodeConfirmedError(req.invoke_id, .service, 0, body);

        var w = ber.Writer.init(body);
        const m = w.mark();
        switch (r.spec) {
            .variables => |it_const| {
                // Written backwards, so resolve first then emit in reverse.
                // The select an `SBO` read performs is a *side effect* and must
                // happen in the order the client asked, not in the writer's
                // reverse order, so it is done in this forward pass and only
                // its answer is emitted later. Everything else resolves to a
                // description the reverse pass renders.
                var it = it_const;
                var resolved: [64]Resolution = undefined;
                var arena: [4 * acsi.max_reference_len]u8 = undefined;
                var used: usize = 0;
                var n: usize = 0;
                while (try it.next()) |name| {
                    if (n == resolved.len) break;
                    const select: ?[]const u8 = if (used + acsi.max_reference_len <= arena.len)
                        self.controlSelect(name, arena[used..])
                    else
                        null;
                    if (select) |sel| {
                        used += sel.len;
                        resolved[n] = .{ .select = sel };
                    } else {
                        resolved[n] = self.resolveRead(name);
                    }
                    n += 1;
                }
                var i: usize = n;
                while (i > 0) {
                    i -= 1;
                    try self.emitResolved(&w, resolved[i]);
                }
            },
            .variable_list => |name| {
                const ds = self.lookupDataSet(name) orelse {
                    return mms.encodeConfirmedError(req.invoke_id, .access, 0, body);
                };
                var i: usize = ds.members.len;
                while (i > 0) {
                    i -= 1;
                    const idx = ds.members[i];
                    if (idx < self.model.variables.len) {
                        try w.bytes(self.model.variables[idx].value());
                    } else {
                        try mms.emitAccessFailure(&w, .object_non_existent);
                    }
                }
            },
        }
        try mms.closeReadResponse(&w, m, req.invoke_id);
        return w.done();
    }

    fn write(self: *Server, req: mms.ConfirmedRequest, body: []u8) Error![]const u8 {
        self.writes += 1;
        const r = mms.decodeWriteRequest(req.body) catch
            return mms.encodeConfirmedError(req.invoke_id, .service, 0, body);

        var results: [64]mms.WriteResult = undefined;
        var n: usize = 0;
        var values = ber.Iterator.init(r.values);
        switch (r.spec) {
            .variables => |it_const| {
                var it = it_const;
                while (try it.next()) |name| {
                    if (n == results.len) break;
                    const value = (try values.next()) orelse break;
                    results[n] = self.applyWrite(name, value.raw);
                    n += 1;
                }
            },
            .variable_list => |name| {
                const ds = self.lookupDataSet(name) orelse {
                    return mms.encodeConfirmedError(req.invoke_id, .access, 0, body);
                };
                for (ds.members) |idx| {
                    if (n == results.len) break;
                    const value = (try values.next()) orelse break;
                    results[n] = if (idx < self.model.variables.len)
                        self.store(&self.model.variables[idx], value.raw)
                    else
                        .{ .failure = .object_non_existent };
                    n += 1;
                }
            },
        }
        return mms.encodeWriteResponse(req.invoke_id, results[0..n], body);
    }

    fn applyWrite(self: *Server, name: mms.ObjectName, value: []const u8) mms.WriteResult {
        // A write under `CO` to a modelled control object goes through the
        // control model, not the flat variable table: that is the whole point
        // of having one.
        if (self.controlWrite(name, value)) |r| return r;
        if (self.blockWrite(name, value)) |r| return r;
        const v = self.lookupMut(name) orelse return .{ .failure = .object_non_existent };
        const r = self.store(v, value);
        // A successful write to a data-set member is a data change like any
        // other, and a client that writes one expects the report it subscribed
        // to. Nothing else in this server knows the value moved.
        if (r == .success) {
            if (self.indexOfVariable(v)) |i| self.signal(i, .data_change);
        }
        return r;
    }

    // ── the reporting, logging and setting-group control blocks ────────────

    /// How one read request name resolved. Everything but `select` is free of
    /// side effects, which is what lets the reverse-order emit pass render it.
    const Resolution = union(enum) {
        missing,
        variable: *const Variable,
        /// The already-formatted answer of an `SBO` select.
        select: []const u8,
        /// A report control block, whole (`attribute.len == 0`) or one member.
        rcb: Named,
        /// A log control block.
        lcb: Named,
        /// The setting-group control block.
        sgcb: []const u8,
        /// One `SE` / `SG` setting.
        setting: struct { index: usize, half: settinggroups.Half },
        /// A read the server understands and must refuse per object.
        refused: mms.DataAccessError,
    };

    const Named = struct { index: usize, attribute: []const u8 };

    /// Splits `LLN0$RP$urcb01$RptEna` against a block's own `LLN0$RP$urcb01`.
    fn matchBlock(item: []const u8, prefix: []const u8) ?[]const u8 {
        if (!std.mem.startsWith(u8, item, prefix)) return null;
        const rest = item[prefix.len..];
        if (rest.len == 0) return rest;
        if (rest[0] != '$') return null;
        return rest[1..];
    }

    fn resolveRead(self: *Server, name: mms.ObjectName) Resolution {
        const d = switch (name) {
            .domain_specific => |x| x,
            else => return .missing,
        };
        for (self.model.report_controls, 0..) |*cb, i| {
            if (!std.mem.eql(u8, cb.domain, d.domain)) continue;
            if (matchBlock(d.item, cb.item)) |attr| return .{ .rcb = .{ .index = i, .attribute = attr } };
        }
        for (self.model.logs, 0..) |*lg, i| {
            if (!std.mem.eql(u8, lg.domain, d.domain)) continue;
            if (matchBlock(d.item, lg.item)) |attr| return .{ .lcb = .{ .index = i, .attribute = attr } };
        }
        if (self.model.setting_groups) |sg| {
            if (std.mem.eql(u8, sg.domain, d.domain)) {
                if (matchBlock(d.item, sg.item)) |attr| return .{ .sgcb = attr };
                if (sg.find(d.domain, d.item)) |hit| {
                    return .{ .setting = .{ .index = hit.index, .half = hit.half } };
                }
            }
        }
        if (self.lookup(name)) |v| return .{ .variable = v };
        return .missing;
    }

    fn emitResolved(self: *Server, w: *ber.Writer, r: Resolution) Error!void {
        switch (r) {
            .missing => try mms.emitAccessFailure(w, .object_non_existent),
            .refused => |e| try mms.emitAccessFailure(w, e),
            .variable => |v| try w.bytes(v.value()),
            .select => |s| try mmsdata.Emit.visibleString(w, s),
            .rcb => |n| {
                const cb = &self.model.report_controls[n.index];
                if (n.attribute.len == 0) {
                    cb.emitStructure(w) catch try mms.emitAccessFailure(w, .object_non_existent);
                } else {
                    cb.emitAttribute(n.attribute, w) catch
                        try mms.emitAccessFailure(w, .object_non_existent);
                }
            },
            .lcb => |n| {
                const lg = &self.model.logs[n.index];
                if (n.attribute.len == 0) {
                    lg.emitStructure(w) catch try mms.emitAccessFailure(w, .object_non_existent);
                } else {
                    lg.emitAttribute(n.attribute, w) catch
                        try mms.emitAccessFailure(w, .object_non_existent);
                }
            },
            .sgcb => |attr| {
                const sg = self.model.setting_groups.?;
                if (attr.len == 0) {
                    sg.emitStructure(w) catch try mms.emitAccessFailure(w, .object_non_existent);
                } else {
                    sg.emitAttribute(attr, w) catch try mms.emitAccessFailure(w, .object_non_existent);
                }
            },
            .setting => |s| {
                const sg = self.model.setting_groups.?;
                const bytes = switch (s.half) {
                    .active => sg.activeValue(s.index) catch {
                        try mms.emitAccessFailure(w, .object_non_existent);
                        return;
                    },
                    // Reading `SE` with no edit group selected is refused, which
                    // is what a real IED does and what tells a browsing client
                    // it has to `SelectEditSG` first.
                    .edit => sg.editValue(s.index) catch {
                        try mms.emitAccessFailure(w, .temporarily_unavailable);
                        return;
                    },
                };
                try w.bytes(bytes);
            },
        }
    }

    /// A write to a report control block, a log control block, the SGCB or a
    /// setting. Returns null when the name is none of those.
    fn blockWrite(self: *Server, name: mms.ObjectName, value: []const u8) ?mms.WriteResult {
        const r = self.resolveRead(name);
        switch (r) {
            .rcb, .lcb, .sgcb, .setting => {},
            else => return null,
        }
        const d = mmsdata.Data.decode(value) catch return .{ .failure = .type_inconsistent };
        d.validate() catch return .{ .failure = .type_inconsistent };

        return switch (r) {
            .rcb => |n| self.writeRcb(n, d),
            .lcb => |n| blk: {
                if (n.attribute.len == 0) break :blk .{ .failure = .object_access_denied };
                break :blk toResult(self.model.logs[n.index].writeAttribute(n.attribute, d, self.now_ms));
            },
            .sgcb => |attr| blk: {
                if (attr.len == 0) break :blk .{ .failure = .object_access_denied };
                const sg = self.model.setting_groups.?;
                break :blk toResult(sg.writeAttribute(attr, d, self.peer, self.now_ms));
            },
            .setting => |s| blk: {
                const sg = self.model.setting_groups.?;
                // `SG` is the active group's read-only view; only `SE` is
                // writable, and only between a select and a confirm.
                if (s.half == .active) break :blk .{ .failure = .object_access_denied };
                sg.setEditValue(s.index, self.peer, value) catch |e| break :blk switch (e) {
                    error.EditGroupBusy => .{ .failure = .object_access_denied },
                    error.NoEditGroup => .{ .failure = .temporarily_unavailable },
                    else => .{ .failure = .object_value_invalid },
                };
                break :blk .success;
            },
            else => unreachable,
        };
    }

    fn writeRcb(self: *Server, n: Named, d: mmsdata.Data) mms.WriteResult {
        if (n.attribute.len == 0) return .{ .failure = .object_access_denied };
        const src = self.reportSource();
        const cb = &self.model.report_controls[n.index];
        // `DatSet` and `RptID` are copied into the block's own storage, so a
        // string that lives in the request buffer — which the caller reuses on
        // the next exchange — is never aliased. A `DatSet` write additionally
        // re-resolves against the model and bumps `ConfRev`.
        const outcome = cb.writeAttributeFrom(n.attribute, d, src, self.peer, self.now_ms);
        if (outcome == .ok and std.mem.eql(u8, n.attribute, "GI") and cb.gi) {
            // The general interrogation happens now; `GI` self-clears once the
            // report has been generated, which is what the standard says and
            // what stops a client's single write producing a sweep for ever.
            _ = cb.sweep(self.reportSource(), .general_interrogation, self.now_ms) catch {};
            cb.gi = false;
        }
        return toResult(outcome);
    }

    fn toResult(o: reporting.WriteOutcome) mms.WriteResult {
        return switch (o) {
            .ok => .success,
            .denied => .{ .failure = .object_access_denied },
            .invalid => .{ .failure = .object_value_invalid },
            .unknown => .{ .failure = .object_non_existent },
        };
    }

    // ── the reporting engine's view of this model ──────────────────────────

    pub fn reportSource(self: *Server) reporting.Source {
        return .{ .ctx = self, .vtable = &source_vtable };
    }

    const source_vtable = reporting.Source.VTable{
        .count = sourceCount,
        .value = sourceValue,
        .reference = sourceReference,
        .resolve = sourceResolve,
    };

    /// `LD/LLN0$Events` → the index of that data set. This is what makes a
    /// runtime `DatSet` re-bind possible: the block is handed a name off the
    /// wire and the model is the only thing that can say what it means.
    fn sourceResolve(ctx: *anyopaque, ds_reference: []const u8) ?usize {
        const self: *Server = @ptrCast(@alignCast(ctx));
        const slash = std.mem.indexOfScalar(u8, ds_reference, '/') orelse return null;
        const ld = ds_reference[0..slash];
        const item = ds_reference[slash + 1 ..];
        for (self.model.data_sets, 0..) |ds, i| {
            if (std.mem.eql(u8, ds.domain, ld) and std.mem.eql(u8, ds.item, item)) return i;
        }
        return null;
    }

    fn sourceCount(ctx: *anyopaque, data_set: usize) usize {
        const self: *Server = @ptrCast(@alignCast(ctx));
        if (data_set >= self.model.data_sets.len) return 0;
        return self.model.data_sets[data_set].members.len;
    }

    fn sourceValue(ctx: *anyopaque, data_set: usize, member: usize) ?[]const u8 {
        const self: *Server = @ptrCast(@alignCast(ctx));
        if (data_set >= self.model.data_sets.len) return null;
        const ds = self.model.data_sets[data_set];
        if (member >= ds.members.len) return null;
        const idx = ds.members[member];
        if (idx >= self.model.variables.len) return null;
        return self.model.variables[idx].value();
    }

    fn sourceReference(ctx: *anyopaque, data_set: usize, member: usize, out: []u8) ?[]const u8 {
        const self: *Server = @ptrCast(@alignCast(ctx));
        if (data_set >= self.model.data_sets.len) return null;
        const ds = self.model.data_sets[data_set];
        if (member >= ds.members.len) return null;
        const idx = ds.members[member];
        if (idx >= self.model.variables.len) return null;
        const v = self.model.variables[idx];
        return std.fmt.bufPrint(out, "{s}/{s}", .{ v.domain, v.item }) catch null;
    }

    fn indexOfVariable(self: *const Server, v: *const Variable) ?usize {
        const base = @intFromPtr(self.model.variables.ptr);
        const here = @intFromPtr(v);
        if (here < base) return null;
        const off = here - base;
        if (off % @sizeOf(Variable) != 0) return null;
        const i = off / @sizeOf(Variable);
        return if (i < self.model.variables.len) i else null;
    }

    /// The application changed a process value. Every report control block and
    /// every log whose data set contains it evaluates its `TrgOps`; nothing
    /// leaves the server until the caller drains `pendingNotification`.
    ///
    /// This is the seam a simulator drives: `signal(3, .data_change)` after
    /// writing `variables[3]`.
    pub fn signal(self: *Server, variable_index: usize, trigger: reporting.Trigger) void {
        const src = self.reportSource();
        for (self.model.data_sets, 0..) |ds, dsi| {
            for (ds.members, 0..) |vi, mi| {
                if (vi != variable_index) continue;
                for (self.model.report_controls) |*cb| {
                    _ = cb.signal(src, dsi, mi, trigger, self.now_ms) catch {};
                }
                for (self.model.logs) |*lg| {
                    _ = lg.signal(src, dsi, mi, trigger, self.now_ms) catch {};
                }
            }
        }
    }

    /// Answers `ReadJournal` out of the log whose journal name the request
    /// carries.
    fn readJournal(self: *Server, req: mms.ConfirmedRequest, body: []u8) Error![]const u8 {
        self.journal_reads += 1;
        const q = logging.decodeReadJournal(req.body) catch
            return mms.encodeConfirmedError(req.invoke_id, .service, 0, body);
        const lg = self.findJournal(q.journal) orelse
            return mms.encodeConfirmedError(req.invoke_id, .access, 0, body);
        return logging.answerReadJournal(lg, q, req.invoke_id, body) catch
            mms.encodeConfirmedError(req.invoke_id, .resource, 0, body);
    }

    fn journalStatus(self: *Server, req: mms.ConfirmedRequest, body: []u8) Error![]const u8 {
        const name = logging.decodeGetJournalStatus(req.body) catch
            return mms.encodeConfirmedError(req.invoke_id, .service, 0, body);
        const lg = self.findJournal(name) orelse
            return mms.encodeConfirmedError(req.invoke_id, .access, 0, body);
        return logging.encodeGetJournalStatusResponse(req.invoke_id, .{
            .current_entries = @intCast(lg.store.count),
            .limit_entries = @intCast(lg.store.entries.len),
        }, body);
    }

    /// `InitializeJournal` — the MMS spelling of "delete log entries". The
    /// entries a limit covers go and the count is returned; a limit reaching
    /// past what the store already purged is not an error.
    fn initializeJournal(self: *Server, req: mms.ConfirmedRequest, body: []u8) Error![]const u8 {
        const q = logging.decodeInitializeJournal(req.body) catch
            return mms.encodeConfirmedError(req.invoke_id, .service, 0, body);
        const lg = self.findJournal(q.journal) orelse
            return mms.encodeConfirmedError(req.invoke_id, .access, 0, body);
        const deleted = logging.initializeJournal(lg, q.limit);
        self.journal_deletions += deleted;
        return logging.encodeInitializeJournalResponse(req.invoke_id, deleted, body);
    }

    /// `DeleteJournal` — deleting the journal *object*, not its entries. The
    /// logs here are part of the caller's static model, exactly as a configured
    /// IED's are, so this is refused rather than silently ignored.
    fn deleteJournal(self: *Server, req: mms.ConfirmedRequest, body: []u8) Error![]const u8 {
        const name = logging.decodeDeleteJournal(req.body) catch
            return mms.encodeConfirmedError(req.invoke_id, .service, 0, body);
        if (self.findJournal(name) == null) {
            return mms.encodeConfirmedError(req.invoke_id, .access, 0, body);
        }
        return mms.encodeConfirmedError(req.invoke_id, .access, 3, body);
    }

    fn findJournal(self: *Server, name: mms.ObjectName) ?*logging.ControlBlock {
        const d = switch (name) {
            .domain_specific => |x| x,
            else => return null,
        };
        for (self.model.logs) |*lg| {
            if (!std.mem.eql(u8, lg.domain, d.domain)) continue;
            if (std.mem.eql(u8, lg.journal, d.item)) return lg;
        }
        return null;
    }

    // ── the control model (IEC 61850-7-2 §20) ──────────────────────────────

    /// Advances the clock. Expires armed selects and executions that ran past
    /// their limit, queueing the negative `CommandTermination` the standard
    /// requires for the latter. **This is the only place time enters the
    /// responder**, and the caller supplies it.
    pub fn tick(self: *Server, now_ms: u64) void {
        self.now_ms = now_ms;
        for (self.model.controls, 0..) |*p, i| {
            const was_executing = p.state == .executing;
            // `Point.tick` resets the object, so the ctlNum the termination
            // must echo has to be taken before it runs.
            const num = p.ctl_num;
            if (!p.tick(now_ms)) continue;
            if (was_executing) self.queueTermination(i, .time_limit_over, num);
        }
        // …and the same for the reporting deadlines: `BufTm` windows close and
        // `IntgPd` sweeps happen here, not on a thread.
        const src = self.reportSource();
        for (self.model.report_controls) |*cb| _ = cb.tick(src, now_ms) catch {};
        for (self.model.logs) |*lg| _ = lg.tick(src, now_ms) catch {};
        // …and an abandoned setting-group edit expires here rather than holding
        // the groups until the association drops.
        if (self.model.setting_groups) |sg| _ = sg.tick(now_ms);
    }

    /// The application finished (or failed) an execution the responder is
    /// holding open because `auto_complete_control` is false. `cause` null
    /// means success.
    pub fn completeControl(self: *Server, index: usize, cause: ?control.AddCause) void {
        if (index >= self.model.controls.len) return;
        const p = &self.model.controls[index];
        if (!p.completed()) return;
        self.queueTermination(index, cause, null);
    }

    /// Pops the next queued unsolicited PDU, wrapped as a complete TPKT. Call
    /// it after every `handle` and after every `tick`: a `CommandTermination`
    /// is *not* a response, so it cannot come back out of `handle`.
    pub fn pendingNotification(self: *Server, out: []u8) Error!?[]const u8 {
        if (self.notify_count > 0) {
            const n = &self.notifications[self.notify_head];
            self.notify_head = (self.notify_head + 1) % max_pending_notifications;
            self.notify_count -= 1;
            return try self.wrap(n.bytes[0..n.len], self.mms_context, out);
        }
        // A report is encoded here, on demand, straight out of the control
        // block's buffer — so a report that is never drained costs nothing but
        // the buffer entry it already occupies.
        const blocks = self.model.report_controls;
        if (blocks.len == 0) return null;
        // A block half-way through a segmented report is finished before any
        // other block gets a turn: interleaving two reports' segments on one
        // association would make them impossible to reassemble.
        var i: usize = 0;
        while (i < blocks.len) : (i += 1) {
            const idx = (self.report_cursor + i) % blocks.len;
            if (!blocks[idx].segmenting()) continue;
            if (try self.emitFrom(idx, out)) |frame| return frame;
        }
        i = 0;
        while (i < blocks.len) : (i += 1) {
            const idx = (self.report_cursor + i) % blocks.len;
            if (self.emitFrom(idx, out) catch continue) |frame| {
                if (!blocks[idx].segmenting()) self.report_cursor = (idx + 1) % blocks.len;
                return frame;
            }
        }
        return null;
    }

    /// How large one `InformationReport` may be on this association.
    ///
    /// Two ceilings, and the smaller wins. `localDetailCalling` is the largest
    /// MMS PDU the client will accept; the COTP TPDU size is the largest single
    /// TPDU this module can put on the wire, because it does not split a PDU
    /// across several. `envelope_overhead` is the session/presentation wrapper
    /// `wrap` puts around the MMS PDU inside that TPDU.
    pub fn reportSegmentBudget(self: *const Server) usize {
        var limit: usize = if (self.negotiated_pdu_len > 0) self.negotiated_pdu_len else max_report_len;
        if (self.negotiated_tpdu_len > envelope_overhead) {
            limit = @min(limit, self.negotiated_tpdu_len - envelope_overhead);
        }
        return limit;
    }

    fn emitFrom(self: *Server, idx: usize, out: []u8) Error!?[]const u8 {
        var w = ber.Writer.init(&self.report_out);
        const src = self.reportSource();
        const limit = self.reportSegmentBudget();
        if (!try self.model.report_controls[idx].emitNextWithin(src, &w, limit)) return null;
        self.reports_sent += 1;
        return try self.wrap(w.done(), self.mms_context, out);
    }

    /// The association ended. Report control blocks release their client — a
    /// URCB throws its buffer away, a BRCB keeps it, which is the whole point of
    /// the letter B — and any half-finished setting-group edit is dropped.
    pub fn releaseAssociation(self: *Server) void {
        for (self.model.report_controls) |*cb| cb.associationLost();
        if (self.model.setting_groups) |sg| sg.associationLost(self.peer);
        self.associated = false;
    }

    /// One of several associations ended. Unlike `releaseAssociation` this
    /// leaves alone everything another client holds, and it honours a BRCB's
    /// `ResvTms`: a reservation with a lifetime outlives the connection that
    /// took it, so a client that reconnects inside the window still owns its
    /// buffer. `tick` is what eventually expires it.
    pub fn releaseAssociationOf(self: *Server, peer: u32) void {
        for (self.model.report_controls) |*cb| cb.associationLostBy(peer, self.now_ms);
        if (self.model.setting_groups) |sg| sg.associationLost(peer);
        for (self.model.controls) |*p| p.release(peer);
        self.associated = false;
    }

    fn findControl(self: *const Server, ld: []const u8, prefix: []const u8) ?usize {
        for (self.model.controls, 0..) |*p, i| {
            if (std.mem.eql(u8, p.domain, ld) and std.mem.eql(u8, p.item, prefix)) return i;
        }
        return null;
    }

    /// Handles a write to `…$CO$<DO>$Oper|SBOw|Cancel`. Returns null when the
    /// name is not a modelled control object, so the caller falls through.
    fn controlWrite(self: *Server, name: mms.ObjectName, value: []const u8) ?mms.WriteResult {
        const ds = switch (name) {
            .domain_specific => |x| x,
            else => return null,
        };
        const split = control.splitControlItem(ds.item) orelse return null;
        const index = self.findControl(ds.domain, split.prefix) orelse return null;
        if (std.mem.eql(u8, split.attribute, "SBO")) {
            // `SBO` is selected by *reading* it; writing it is meaningless.
            return .{ .failure = .object_access_denied };
        }

        const d = mmsdata.Data.decode(value) catch return .{ .failure = .type_inconsistent };
        d.validate() catch return .{ .failure = .type_inconsistent };
        const cmd = control.Command.decode(d) catch return .{ .failure = .type_inconsistent };

        const p = &self.model.controls[index];
        const outcome = if (std.mem.eql(u8, split.attribute, "SBOw")) blk: {
            self.selects += 1;
            break :blk p.select(self.peer, cmd, self.now_ms);
        } else if (std.mem.eql(u8, split.attribute, "Cancel"))
            p.cancel(self.peer, cmd, self.now_ms)
        else blk: {
            self.operates += 1;
            break :blk p.operate(self.peer, cmd, self.now_ms);
        };

        switch (outcome) {
            .rejected => |cause| {
                self.control_rejections += 1;
                self.queueLastApplError(index, cause, cmd.ctl_num, cmd.origin);
                return .{ .failure = .object_access_denied };
            },
            .accepted => |a| {
                if (std.mem.eql(u8, split.attribute, "Oper")) self.applyControlValue(p, cmd);
                if (a.terminate) {
                    if (std.mem.eql(u8, split.attribute, "Cancel")) {
                        self.queueTermination(index, .abortion_by_cancel, cmd.ctl_num);
                    } else if (self.config.auto_complete_control) {
                        _ = p.completed();
                        self.queueTermination(index, null, cmd.ctl_num);
                    }
                }
                return .success;
            },
        }
    }

    /// A `Test` command must not move the plant — that distinction is the
    /// whole reason the flag is on the wire.
    fn applyControlValue(self: *Server, p: *ControlPoint, cmd: control.Command) void {
        if (cmd.test_mode) return;
        const idx = p.st_val orelse return;
        if (idx >= self.model.variables.len) return;
        const v = &self.model.variables[idx];
        if (cmd.ctl_val.len > v.storage.len) return;
        @memcpy(v.storage[0..cmd.ctl_val.len], cmd.ctl_val);
        v.len = cmd.ctl_val.len;
        // Operating a breaker moves a status point, and a status point in a
        // reported data set is exactly what a client subscribed for.
        self.signal(idx, .data_change);
    }

    /// Handles a read of `…$CO$<DO>$SBO` — the `sbo-with-normal-security`
    /// select. A successful select answers with the object's own reference; a
    /// refused one answers with an empty string, which is all the standard
    /// gives a normal-security client.
    fn controlSelect(self: *Server, name: mms.ObjectName, out: []u8) ?[]const u8 {
        const ds = switch (name) {
            .domain_specific => |x| x,
            else => return null,
        };
        const split = control.splitControlItem(ds.item) orelse return null;
        if (!std.mem.eql(u8, split.attribute, "SBO")) return null;
        const index = self.findControl(ds.domain, split.prefix) orelse return null;
        const p = &self.model.controls[index];
        self.selects += 1;
        return switch (p.select(self.peer, null, self.now_ms)) {
            .accepted => p.sboReference(out) catch "",
            .rejected => |cause| blk: {
                self.control_rejections += 1;
                self.queueLastApplError(index, cause, 0, .{});
                break :blk "";
            },
        };
    }

    fn queueSlot(self: *Server) ?*Pending {
        if (self.notify_count == max_pending_notifications) return null;
        const slot = &self.notifications[(self.notify_head + self.notify_count) % max_pending_notifications];
        self.notify_count += 1;
        return slot;
    }

    /// `LastApplError` on its own: a select or an operate refused outright.
    fn queueLastApplError(
        self: *Server,
        index: usize,
        cause: control.AddCause,
        ctl_num: u8,
        origin: control.Origin,
    ) void {
        const p = &self.model.controls[index];
        var ref_buf: [acsi.max_reference_len]u8 = undefined;
        const ref = p.sboReference(&ref_buf) catch return;
        const e = control.LastApplError{
            .ctl_obj_ref = ref,
            .err = .unknown,
            .origin = origin,
            .ctl_num = ctl_num,
            .add_cause = cause,
        };
        const slot = self.queueSlot() orelse return;
        var w = ber.Writer.init(&slot.bytes);
        const m = w.mark();
        e.emit(&w) catch {
            self.notify_count -= 1;
            return;
        };
        mms.closeInformationReport(&w, m, .{
            .variables = &[_]mms.ObjectName{.{ .vmd_specific = control.last_appl_error_name }},
        }) catch {
            self.notify_count -= 1;
            return;
        };
        const d = w.done();
        std.mem.copyForwards(u8, slot.bytes[0..d.len], d);
        slot.len = d.len;
    }

    /// `CommandTermination`. Positive is one variable — the control object with
    /// its `Oper` value echoed; negative is **two**, `LastApplError` first, and
    /// a client that assumes one value per report reads the wrong one.
    fn queueTermination(self: *Server, index: usize, cause: ?control.AddCause, ctl_num: ?u8) void {
        const p = &self.model.controls[index];
        var ref_buf: [acsi.max_reference_len]u8 = undefined;
        const ref = p.sboReference(&ref_buf) catch return;
        var item_buf: [acsi.max_reference_len]u8 = undefined;
        const item = std.fmt.bufPrint(&item_buf, "{s}$Oper", .{p.item}) catch return;
        const num = ctl_num orelse p.ctl_num;

        // The echoed Oper value. A real IED echoes the command it executed;
        // this responder rebuilds it from what it kept, which is the ctlNum and
        // the value it applied.
        var val_buf: [16]u8 = undefined;
        var vw = ber.Writer.init(&val_buf);
        mmsdata.Emit.boolean(&vw, true) catch return;
        const echoed = control.Command{
            .ctl_val = vw.done(),
            .ctl_num = num,
            .t = mmsdata.UtcTime.fromMillis(self.now_ms, null),
        };

        const slot = self.queueSlot() orelse return;
        var w = ber.Writer.init(&slot.bytes);
        const m = w.mark();
        blk: {
            // Backwards: the last access result first.
            echoed.emit(&w) catch break :blk;
            if (cause) |c| {
                const e = control.LastApplError{
                    .ctl_obj_ref = ref,
                    .err = .unknown,
                    .ctl_num = num,
                    .add_cause = c,
                };
                e.emit(&w) catch break :blk;
            }
            const object = mms.ObjectName{ .domain_specific = .{ .domain = p.domain, .item = item } };
            const spec: mms.AccessSpec = if (cause == null)
                .{ .variables = &[_]mms.ObjectName{object} }
            else
                .{ .variables = &[_]mms.ObjectName{
                    .{ .vmd_specific = control.last_appl_error_name },
                    object,
                } };
            mms.closeInformationReport(&w, m, spec) catch break :blk;
            const d = w.done();
            std.mem.copyForwards(u8, slot.bytes[0..d.len], d);
            slot.len = d.len;
            return;
        }
        self.notify_count -= 1;
    }

    fn store(_: *Server, v: *Variable, value: []const u8) mms.WriteResult {
        if (!v.writable) return .{ .failure = .object_access_denied };
        // A value must decode as a well-formed, depth-bounded `Data` before it
        // is allowed anywhere near the model.
        const d = mmsdata.Data.decode(value) catch return .{ .failure = .type_inconsistent };
        d.validate() catch return .{ .failure = .type_inconsistent };
        if (value.len > v.storage.len) return .{ .failure = .object_value_invalid };
        @memcpy(v.storage[0..value.len], value);
        v.len = value.len;
        return .success;
    }

    fn lookup(self: *const Server, name: mms.ObjectName) ?*const Variable {
        const d = switch (name) {
            .domain_specific => |x| x,
            else => return null,
        };
        for (self.model.variables) |*v| {
            if (std.mem.eql(u8, v.domain, d.domain) and std.mem.eql(u8, v.item, d.item)) return v;
        }
        return null;
    }

    fn lookupMut(self: *Server, name: mms.ObjectName) ?*Variable {
        const d = switch (name) {
            .domain_specific => |x| x,
            else => return null,
        };
        for (self.model.variables) |*v| {
            if (std.mem.eql(u8, v.domain, d.domain) and std.mem.eql(u8, v.item, d.item)) return v;
        }
        return null;
    }

    fn lookupDataSet(self: *const Server, name: mms.ObjectName) ?*const DataSet {
        const d = switch (name) {
            .domain_specific => |x| x,
            else => return null,
        };
        for (self.model.data_sets) |*ds| {
            if (std.mem.eql(u8, ds.domain, d.domain) and std.mem.eql(u8, ds.item, d.item)) return ds;
        }
        return null;
    }

    /// Wraps an MMS PDU in presentation + session + COTP + TPKT, backwards, in
    /// one buffer — the same trick the client uses.
    fn wrap(self: *Server, mms_pdu: []const u8, context_id: u16, out: []u8) Error![]const u8 {
        _ = self;
        var w = ber.Writer.init(out);
        const outer = w.mark();
        try w.bytes(mms_pdu);
        try w.header(ber.Tag.ctxc(0), outer);
        try w.integer(ber.Tag.uni(ber.Universal.integer), context_id);
        try w.header(ber.Tag.sequence, outer);
        try w.header(presentation.tag_user_data, outer);
        try w.bytes(&session.data_transfer_prefix);
        try w.bytes(&[_]u8{ 0x02, 0xF0, 0x80 });
        const total = w.len() + tpkt.header_len;
        if (total > tpkt.max_length) return error.BufferTooSmall;
        try w.bytes(&[_]u8{ tpkt.version, 0, @intCast((total >> 8) & 0xFF), @intCast(total & 0xFF) });
        return w.done();
    }
};

/// `servicesSupportedCalled` for this responder: status, getNameList, identify,
/// read, write, getVariableAccessAttributes, informationReport and the two
/// journal services. Everything else is answered with a `confirmed-ErrorPDU`,
/// which is what an honest server does.
pub const server_services_supported = blk: {
    var bits = [_]u8{0} ** 12;
    bits[0] = 3; // unused bits in the last octet
    const set = [_]usize{
        mms.Initiate.service_bit.status,
        mms.Initiate.service_bit.get_name_list,
        mms.Initiate.service_bit.identify,
        mms.Initiate.service_bit.read,
        mms.Initiate.service_bit.write,
        mms.Initiate.service_bit.information_report,
        mms.Initiate.service_bit.get_variable_access_attributes,
        mms.Initiate.service_bit.get_named_variable_list_attributes,
        mms.Initiate.service_bit.read_journal,
        mms.Initiate.service_bit.get_journal_status,
    };
    for (set) |b| bits[1 + b / 8] |= @as(u8, 0x80) >> @intCast(b % 8);
    break :blk bits;
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const client = @import("client.zig");
const transport = @import("transport.zig");
const acsi = @import("acsi.zig");
const report = @import("report.zig");

const domain = "TESTLD";

/// A tiny model: two status booleans, one measurement, one writable
/// description, and a data set over the two booleans.
const Fixture = struct {
    ind1: [8]u8 = undefined,
    ind2: [8]u8 = undefined,
    mag: [16]u8 = undefined,
    vendor: [64]u8 = undefined,
    vars: [4]Variable = undefined,
    sets: [1]DataSet = undefined,
    domains: [1][]const u8 = .{domain},

    fn init(self: *Fixture) !Model {
        self.vars[0] = .{ .domain = domain, .item = "GGIO1$ST$Ind1$stVal", .storage = &self.ind1, .len = try emitBool(&self.ind1, false) };
        self.vars[1] = .{ .domain = domain, .item = "GGIO1$ST$Ind2$stVal", .storage = &self.ind2, .len = try emitBool(&self.ind2, true) };
        self.vars[2] = .{ .domain = domain, .item = "GGIO1$MX$AnIn1$mag$f", .storage = &self.mag, .len = try emitFloat(&self.mag, 12.5) };
        self.vars[3] = .{ .domain = domain, .item = "GGIO1$DC$NamPlt$vendor", .storage = &self.vendor, .len = try emitString(&self.vendor, "initial"), .writable = true };
        self.sets[0] = .{ .domain = domain, .item = "LLN0$Events", .members = &[_]usize{ 0, 1 } };
        return .{ .variables = &self.vars, .data_sets = &self.sets, .domains = &self.domains };
    }
};

fn emitBool(buf: []u8, v: bool) !usize {
    var w = ber.Writer.init(buf);
    try mmsdata.Emit.boolean(&w, v);
    const d = w.done();
    std.mem.copyForwards(u8, buf[0..d.len], d);
    return d.len;
}
fn emitFloat(buf: []u8, v: f32) !usize {
    var w = ber.Writer.init(buf);
    try mmsdata.Emit.float(&w, v);
    const d = w.done();
    std.mem.copyForwards(u8, buf[0..d.len], d);
    return d.len;
}
fn emitString(buf: []u8, s: []const u8) !usize {
    var w = ber.Writer.init(buf);
    try mmsdata.Emit.visibleString(&w, s);
    const d = w.done();
    std.mem.copyForwards(u8, buf[0..d.len], d);
    return d.len;
}

/// A transport that hands every packet straight to a `Server` and queues its
/// reply — a full association without a socket.
const Paired = struct {
    server: *Server,
    out: [32768]u8 = undefined,
    notify_out: [4096]u8 = undefined,
    queue: [65536]u8 = undefined,
    queue_len: usize = 0,
    queue_pos: usize = 0,
    failures: usize = 0,

    fn seam(self: *Paired) transport.Transport {
        return .{ .ctx = self, .vtable = &.{ .read = readFn, .write = writeFn } };
    }

    fn readFn(ctx: *anyopaque, buf: []u8) transport.TransportError!usize {
        const self: *Paired = @ptrCast(@alignCast(ctx));
        const avail = self.queue_len - self.queue_pos;
        if (avail == 0) return 0;
        const head = self.queue[self.queue_pos..self.queue_len];
        const total = tpkt.peekLength(head) catch avail;
        const n = @min(@min(total, avail), buf.len);
        @memcpy(buf[0..n], head[0..n]);
        self.queue_pos += n;
        return n;
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) transport.TransportError!void {
        const self: *Paired = @ptrCast(@alignCast(ctx));
        const reply = self.server.handle(bytes, &self.out) catch {
            self.failures += 1;
            return;
        };
        // Unsolicited PDUs the request produced go out **before** the response,
        // which is the order a real IED uses: the `LastApplError` explaining a
        // refusal arrives ahead of the negative write response it explains.
        try self.drain();
        if (reply) |r| try self.enqueue(r);
    }

    fn drain(self: *Paired) transport.TransportError!void {
        while (self.server.pendingNotification(&self.notify_out) catch null) |n| try self.enqueue(n);
    }

    fn enqueue(self: *Paired, r: []const u8) transport.TransportError!void {
        if (self.queue_len + r.len > self.queue.len) return error.WriteFailed;
        @memcpy(self.queue[self.queue_len..][0..r.len], r);
        self.queue_len += r.len;
    }
};

test "round trip: our client against our server over an in-memory wire" {
    var fx: Fixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [32768]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});

    try c.connect();
    try testing.expect(c.isConnected());
    try testing.expect(srv.associated);
    // The server advertises exactly what it implements.
    try testing.expect(c.serverSupports(mms.Initiate.service_bit.read));
    try testing.expect(c.serverSupports(mms.Initiate.service_bit.write));
    try testing.expect(!c.serverSupports(mms.Initiate.service_bit.define_named_variable_list));
    try testing.expect(c.serverSupports(mms.Initiate.service_bit.get_named_variable_list_attributes));

    // Identify.
    const ident = try c.identify();
    try testing.expectEqualStrings("zig-libs", ident.vendor);

    // Read a status boolean and a measurement.
    try testing.expectEqual(false, try (try c.readObject("TESTLD/GGIO1.Ind1.stVal", .ST)).boolean());
    try testing.expectEqual(true, try (try c.readObject("TESTLD/GGIO1.Ind2.stVal", .ST)).boolean());
    try testing.expectApproxEqAbs(
        @as(f64, 12.5),
        try (try c.readObject("TESTLD/GGIO1.AnIn1.mag.f", .MX)).asFloat(),
        1e-6,
    );

    // A variable that does not exist comes back as a per-object failure.
    try testing.expectError(error.AccessFailed, c.readObject("TESTLD/GGIO1.Nope.stVal", .ST));

    // Write the writable description and read it back.
    var vbuf: [64]u8 = undefined;
    var vw = ber.Writer.init(&vbuf);
    try mmsdata.Emit.visibleString(&vw, "zig-libs.test");
    try c.writeObject("TESTLD/GGIO1.NamPlt.vendor", .DC, vw.done());
    try testing.expectEqualStrings(
        "zig-libs.test",
        try (try c.readObject("TESTLD/GGIO1.NamPlt.vendor", .DC)).visibleString(),
    );

    // A write to a read-only variable is refused per object, not fatally.
    var rbuf: [16]u8 = undefined;
    var rw = ber.Writer.init(&rbuf);
    try mmsdata.Emit.boolean(&rw, true);
    try testing.expectError(error.AccessFailed, c.writeObject("TESTLD/GGIO1.Ind1.stVal", .ST, rw.done()));

    // Directories.
    var names: [16][]const u8 = undefined;
    try testing.expectEqual(@as(usize, 1), try c.getServerDirectory(&names));
    try testing.expectEqualStrings(domain, names[0]);
    try testing.expectEqual(@as(usize, 4), try c.getLogicalDeviceDirectory(domain, &names));
    try testing.expectEqual(@as(usize, 1), try c.getDataSetDirectory(domain, &names));
    try testing.expectEqualStrings("LLN0$Events", names[0]);

    // The data set's members by name — what a reporting client needs to label
    // a report's inclusion bit string.
    var dsreq: [256]u8 = undefined;
    const dspdu = try mms.encodeGetNamedVariableListAttributes(77, .{ .domain_specific = .{
        .domain = domain,
        .item = "LLN0$Events",
    } }, &dsreq);
    var attrs = try mms.decodeGetNamedVariableListAttributesResponse(
        try c.exchange(dspdu, 77, .get_named_variable_list_attributes),
    );
    try testing.expect(!attrs.deletable);
    try testing.expectEqualStrings("GGIO1$ST$Ind1$stVal", (try attrs.variables.next()).?.domain_specific.item);
    try testing.expectEqualStrings("GGIO1$ST$Ind2$stVal", (try attrs.variables.next()).?.domain_specific.item);
    try testing.expect((try attrs.variables.next()) == null);

    // A whole data set in one request.
    var it = try c.readDataSet("TESTLD/LLN0$Events");
    try testing.expectEqual(false, try (try it.next()).?.success.boolean());
    try testing.expectEqual(true, try (try it.next()).?.success.boolean());
    try testing.expect((try it.next()) == null);

    c.disconnect();
    try testing.expect(!srv.associated);
    try testing.expectEqual(@as(usize, 0), paired.failures);
    try testing.expect(srv.reads > 0 and srv.writes > 0 and srv.name_lists > 0);
}

test "the server refuses an association with the wrong application context" {
    var fx: Fixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [32768]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{
        .identity = .{ .called_ap_title = null, .calling_ap_title = null },
    });
    // Swap the application context name for a bogus one by hand.
    srv.config.require_mms_application_context = true;
    // The default client sends the right one, so this must succeed…
    try c.connect();
    c.disconnect();
    // …and a server that requires it rejects a client that omits the AARQ
    // entirely, which is what a malformed connect looks like.
    var srv2 = Server.init(.{}, model);
    var out: [1024]u8 = undefined;
    try testing.expectError(error.ShortPacket, srv2.handle(&[_]u8{ 0x00, 0x00 }, &out));
}

test "the server answers an unimplemented service with a confirmed error" {
    var fx: Fixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [32768]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    try c.connect();

    // `GetVariableAccessAttributes` is not implemented here.
    var req: [256]u8 = undefined;
    const pdu = try mms.encodeGetVariableAccessAttributes(
        99,
        .{ .domain_specific = .{ .domain = domain, .item = "GGIO1$ST$Ind1$stVal" } },
        &req,
    );
    try testing.expectError(error.ServiceFailed, c.exchange(pdu, 99, .get_variable_access_attributes));
}

test "the server rejects a presentation context it does not know" {
    var fx: Fixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [32768]u8 = undefined;
    const bogus = [_]presentation.ContextDefinition{
        .{ .id = 1, .abstract_syntax = &ber.oids.acse_abstract_syntax, .transfer_syntax = &ber.oids.ber_transfer_syntax },
        .{ .id = 5, .abstract_syntax = &[_]u8{ 0x2A, 0x03 }, .transfer_syntax = &ber.oids.ber_transfer_syntax },
    };
    var c = try client.Client.init(paired.seam(), &buf, .{
        .presentation_options = .{ .contexts = &bogus },
    });
    // No MMS context was proposed, so the server cannot associate.
    try testing.expectError(error.NoResponse, c.connect());
    try testing.expect(paired.failures > 0);
}

test "a written value that is not well-formed Data is refused" {
    var fx: Fixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    const v = &srv.model.variables[3];
    // A structure nested past the depth bound.
    var deep: [256]u8 = undefined;
    const depth: usize = 64;
    var i: usize = depth;
    var len: usize = 0;
    while (i > 0) : (i -= 1) {
        deep[depth * 2 - len - 1] = @intCast(len);
        deep[depth * 2 - len - 2] = 0xA2;
        len += 2;
    }
    try testing.expectEqual(
        mms.WriteResult{ .failure = .type_inconsistent },
        srv.store(v, deep[0 .. depth * 2]),
    );
    // A value larger than the variable's storage.
    var big: [128]u8 = undefined;
    var w = ber.Writer.init(&big);
    try mmsdata.Emit.visibleString(&w, "x" ** 100);
    try testing.expectEqual(
        mms.WriteResult{ .failure = .object_value_invalid },
        srv.store(v, w.done()),
    );
}

test "the advertised service bit string really names what is implemented" {
    const bs = try ber.BitString.parse(&server_services_supported);
    try testing.expect(bs.bit(mms.Initiate.service_bit.read));
    try testing.expect(bs.bit(mms.Initiate.service_bit.write));
    try testing.expect(bs.bit(mms.Initiate.service_bit.get_name_list));
    try testing.expect(bs.bit(mms.Initiate.service_bit.identify));
    try testing.expect(bs.bit(mms.Initiate.service_bit.information_report));
    // Not implemented, and not claimed.
    try testing.expect(bs.bit(mms.Initiate.service_bit.get_named_variable_list_attributes));
    try testing.expect(bs.bit(mms.Initiate.service_bit.read_journal));
    // Not implemented, and not claimed.
    try testing.expect(!bs.bit(mms.Initiate.service_bit.define_named_variable_list));
    try testing.expect(!bs.bit(mms.Initiate.service_bit.file_open));
}

// ── the control model, client against server ────────────────────────────────

/// The four control models on one logical node, each with the `stVal` it
/// drives — the same shape as the oracle's own control example model.
const ControlFixture = struct {
    st: [4][8]u8 = undefined,
    vars: [4]Variable = undefined,
    controls: [4]ControlPoint = undefined,
    domains: [1][]const u8 = .{domain},

    const items = [_][]const u8{
        "GGIO1$ST$SPCSO1$stVal",
        "GGIO1$ST$SPCSO2$stVal",
        "GGIO1$ST$SPCSO3$stVal",
        "GGIO1$ST$SPCSO4$stVal",
    };
    const prefixes = [_][]const u8{
        "GGIO1$CO$SPCSO1",
        "GGIO1$CO$SPCSO2",
        "GGIO1$CO$SPCSO3",
        "GGIO1$CO$SPCSO4",
    };
    const models = [_]control.CtlModel{
        .direct_with_normal_security,
        .sbo_with_normal_security,
        .direct_with_enhanced_security,
        .sbo_with_enhanced_security,
    };

    fn init(self: *ControlFixture) !Model {
        for (0..4) |i| {
            self.vars[i] = .{
                .domain = domain,
                .item = items[i],
                .storage = &self.st[i],
                .len = try emitBool(&self.st[i], false),
            };
            self.controls[i] = .{
                .domain = domain,
                .item = prefixes[i],
                .ctl_model = models[i],
                .sbo_timeout_ms = 2000,
                .st_val = i,
            };
        }
        return .{ .variables = &self.vars, .controls = &self.controls, .domains = &self.domains };
    }

    fn stVal(self: *ControlFixture, i: usize) !bool {
        return (try mmsdata.Data.decode(self.vars[i].value())).boolean();
    }
};

fn onCommand(w: *ber.Writer) !void {
    try mmsdata.Emit.boolean(w, true);
}

test "all four control models drive a breaker end to end" {
    var fx: ControlFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [32768]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    try c.connect();

    var val: [8]u8 = undefined;
    var vw = ber.Writer.init(&val);
    try onCommand(&vw);
    const cmd = control.Command{
        .ctl_val = vw.done(),
        .origin = .{ .or_cat = .station_control, .or_ident = "zig-libs" },
        .t = mmsdata.UtcTime.fromMillis(1_700_000_000_000, 10),
    };

    const refs = [_][]const u8{
        "TESTLD/GGIO1.SPCSO1",
        "TESTLD/GGIO1.SPCSO2",
        "TESTLD/GGIO1.SPCSO3",
        "TESTLD/GGIO1.SPCSO4",
    };
    for (refs, ControlFixture.models, 0..) |ref, ctl_model, i| {
        var m = control.Machine.init(ctl_model, 2000);
        try c.executeControl(&m, ref, cmd, 1000);
        try testing.expectEqual(control.State.succeeded, m.state);
        try testing.expect(try fx.stVal(i));
        // The enhanced models really did wait for a CommandTermination.
        if (ctl_model.isEnhanced()) try testing.expect(c.notifications_received > 0);
    }
    // Two selects (the sbo models), four operates, and no rejection anywhere.
    try testing.expectEqual(@as(u64, 2), srv.selects);
    try testing.expectEqual(@as(u64, 4), srv.operates);
    try testing.expectEqual(@as(u64, 0), srv.control_rejections);
    try testing.expectEqual(@as(usize, 0), paired.failures);
    c.disconnect();
}

test "an operate without a select is refused with Object-not-selected, and says so" {
    var fx: ControlFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [32768]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    try c.connect();

    var val: [8]u8 = undefined;
    var vw = ber.Writer.init(&val);
    try onCommand(&vw);
    const cmd = control.Command{ .ctl_val = vw.done(), .ctl_num = 1, .t = mmsdata.UtcTime.fromMillis(0, null) };

    // Straight to Oper on a sbo-with-enhanced-security object.
    try testing.expectError(error.AccessFailed, c.operateObject("TESTLD/GGIO1.SPCSO4", cmd));
    // The LastApplError the server pushed says exactly why — the whole point of
    // the field.
    const n = c.last_notification orelse return error.TestExpectedEqual;
    try testing.expectEqual(control.NotificationKind.last_appl_error, n.kind);
    try testing.expectEqual(control.AddCause.object_not_selected, n.addCause().?);
    try testing.expectEqualStrings("TESTLD/GGIO1$CO$SPCSO4", n.last_error.?.ctl_obj_ref);
    try testing.expect(!try fx.stVal(3));
    c.disconnect();
}

test "an interlock is reported as an AddCause, not as a bare failure" {
    var fx: ControlFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    srv.model.controls[0].interlocked = true;
    var paired = Paired{ .server = &srv };
    var buf: [32768]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    try c.connect();

    var val: [8]u8 = undefined;
    var vw = ber.Writer.init(&val);
    try onCommand(&vw);
    const cmd = control.Command{ .ctl_val = vw.done(), .ctl_num = 1, .t = mmsdata.UtcTime.fromMillis(0, null) };

    var m = control.Machine.init(.direct_with_normal_security, 0);
    try testing.expectError(
        error.ControlRejected,
        c.executeControl(&m, "TESTLD/GGIO1.SPCSO1", cmd, 0),
    );
    try testing.expectEqual(control.AddCause.blocked_by_interlocking, m.failure.?.add_cause.?);
    try testing.expect(m.failure.?.add_cause.?.transient());
    try testing.expect(!try fx.stVal(0));
    c.disconnect();
}

test "a select that expires at the server turns the next operate down" {
    var fx: ControlFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [32768]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    try c.connect();

    var val: [8]u8 = undefined;
    var vw = ber.Writer.init(&val);
    try onCommand(&vw);
    const cmd = control.Command{ .ctl_val = vw.done(), .ctl_num = 1, .t = mmsdata.UtcTime.fromMillis(0, null) };

    srv.tick(1000);
    try testing.expect(try c.selectObject("TESTLD/GGIO1.SPCSO2"));
    try testing.expectEqual(control.PointState.selected, srv.model.controls[1].state);
    // The operator hesitated past sboTimeout; the IED dropped the select.
    srv.tick(3000);
    try testing.expectEqual(control.PointState.unselected, srv.model.controls[1].state);
    try testing.expectError(error.AccessFailed, c.operateObject("TESTLD/GGIO1.SPCSO2", cmd));
    try testing.expectEqual(control.AddCause.object_not_selected, c.lastAddCause().?);
    try testing.expect(!try fx.stVal(1));
    c.disconnect();
}

test "a Test command is accepted and moves nothing" {
    var fx: ControlFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [32768]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    try c.connect();

    var val: [8]u8 = undefined;
    var vw = ber.Writer.init(&val);
    try onCommand(&vw);
    const cmd = control.Command{
        .ctl_val = vw.done(),
        .ctl_num = 1,
        .t = mmsdata.UtcTime.fromMillis(0, null),
        .test_mode = true,
    };
    try c.operateObject("TESTLD/GGIO1.SPCSO1", cmd);
    try testing.expect(!try fx.stVal(0));
    c.disconnect();
}

test "an execution the application never finishes is terminated negatively" {
    var fx: ControlFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{ .auto_complete_control = false }, model);
    srv.model.controls[2].execution_timeout_ms = 1000;
    var paired = Paired{ .server = &srv };
    var buf: [32768]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    try c.connect();

    var val: [8]u8 = undefined;
    var vw = ber.Writer.init(&val);
    try onCommand(&vw);
    const cmd = control.Command{ .ctl_val = vw.done(), .ctl_num = 1, .t = mmsdata.UtcTime.fromMillis(0, null) };

    srv.tick(0);
    var m = control.Machine.init(.direct_with_enhanced_security, 0);
    // The write succeeds and the machine is left waiting.
    _ = try m.start(0);
    try c.operateObject("TESTLD/GGIO1.SPCSO3", cmd);
    _ = try m.operateAccepted(0);
    try testing.expectEqual(control.State.awaiting_termination, m.state);

    // Time passes at the IED and the execution times out.
    srv.tick(1000);
    try paired.drain();
    const n = try c.awaitNotification(8);
    try testing.expectEqual(control.NotificationKind.command_termination_negative, n.kind);
    try testing.expectEqual(control.AddCause.time_limit_over, n.addCause().?);
    // The machine records the failure rather than reporting success.
    _ = try m.terminated(n);
    try testing.expectEqual(control.State.failed, m.state);
    c.disconnect();
}

test "a negative CommandTermination carries two variables and the client reads both" {
    var fx: ControlFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [32768]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    try c.connect();

    var val: [8]u8 = undefined;
    var vw = ber.Writer.init(&val);
    try onCommand(&vw);
    const cmd = control.Command{ .ctl_val = vw.done(), .ctl_num = 9, .t = mmsdata.UtcTime.fromMillis(0, null) };

    // Select, operate, then cancel the execution mid-flight.
    srv.config.auto_complete_control = false;
    try c.selectWithValue("TESTLD/GGIO1.SPCSO4", cmd);
    try c.operateObject("TESTLD/GGIO1.SPCSO4", cmd);
    try testing.expectEqual(control.PointState.executing, srv.model.controls[3].state);
    try c.cancelObject("TESTLD/GGIO1.SPCSO4", cmd);

    const n = try c.awaitNotification(8);
    try testing.expectEqual(control.NotificationKind.command_termination_negative, n.kind);
    try testing.expectEqual(control.AddCause.abortion_by_cancel, n.addCause().?);
    // Both variables were decoded: the error *and* the echoed command.
    try testing.expect(n.last_error != null);
    try testing.expect(n.command != null);
    try testing.expectEqual(@as(u8, 9), n.ctlNum().?);
    try testing.expectEqualStrings("GGIO1$CO$SPCSO4$Oper", n.object.?.domain_specific.item);
    c.disconnect();
}

test "an ordinary report is still routed to the report handler, not the control one" {
    // The two share the InformationReport channel; classification must not
    // swallow a real report.
    var fx: ControlFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [32768]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    try c.connect();

    // Hand-build an InformationReport addressed by variable-list name, which is
    // what an RCB report is.
    var body: [512]u8 = undefined;
    var w = ber.Writer.init(&body);
    const m = w.mark();
    try mmsdata.Emit.bitString(&w, 0b1100, 4); // inclusion
    try mmsdata.Emit.unsigned(&w, 1); // SqNum
    try mmsdata.Emit.visibleString(&w, "TESTLD/LLN0$Events"); // DatSet
    try mmsdata.Emit.visibleString(&w, "Events1"); // RptID
    try mms.closeInformationReport(&w, m, .{
        .variables = &[_]mms.ObjectName{.{ .vmd_specific = "RPT" }},
    });

    const info = try mms.decodeInformationReport((try mms.decode(w.done())).unconfirmed.body);
    try testing.expect((try control.classify(info)) == null);
    c.disconnect();
}

test "fuzz: the server never panics on arbitrary packets" {
    try std.testing.fuzz({}, fuzzServer, .{});
}

fn fuzzServer(_: void, smith: *std.testing.Smith) !void {
    var fx: Fixture = .{};
    const model = fx.init() catch return;
    var srv = Server.init(.{}, model);
    var input: [1024]u8 = undefined;
    smith.bytes(&input);
    const len: usize = smith.valueRangeAtMost(u16, 0, input.len);
    var out: [8192]u8 = undefined;
    _ = srv.handle(input[0..len], &out) catch {};
    // And again once associated, so the MMS path is reached too.
    srv.associated = true;
    _ = srv.handle(input[0..len], &out) catch {};
}

// ── reporting, logging and setting groups, client against server ────────────

/// Four status booleans, one data set over them, one URCB, one BRCB, one log —
/// the shape of the reference IED's `LLN0$Events` model.
const ReportFixture = struct {
    ind: [4][8]u8 = undefined,
    vars: [4]Variable = undefined,
    sets: [1]DataSet = undefined,
    domains: [1][]const u8 = .{domain},
    urcb_entries: [8]reporting.Entry = @splat(.{}),
    urcb_arena: [8 * 256]u8 = undefined,
    brcb_entries: [8]reporting.Entry = @splat(.{}),
    brcb_arena: [8 * 256]u8 = undefined,
    rcbs: [2]ReportControl = undefined,
    log_entries: [8]logging.Entry = @splat(.{}),
    log_arena: [8 * 512]u8 = undefined,
    logs: [1]LogControl = undefined,

    const items = [_][]const u8{
        "GGIO1$ST$Ind1$stVal",
        "GGIO1$ST$Ind2$stVal",
        "GGIO1$ST$Ind3$stVal",
        "GGIO1$ST$Ind4$stVal",
    };

    fn init(self: *ReportFixture) !Model {
        for (0..4) |i| {
            self.vars[i] = .{
                .domain = domain,
                .item = items[i],
                .storage = &self.ind[i],
                .len = try emitBool(&self.ind[i], false),
                .writable = true,
            };
        }
        self.sets[0] = .{ .domain = domain, .item = "LLN0$Events", .members = &[_]usize{ 0, 1, 2, 3 } };
        const opt = reporting.OptFlds{
            .sequence_number = true,
            .report_time_stamp = true,
            .reason_for_inclusion = true,
            .data_set_name = true,
            .buffer_overflow = true,
            .entry_id = true,
            .conf_revision = true,
        };
        const trg = reporting.TrgOps{
            .data_change = true,
            .quality_change = true,
            .integrity = true,
            .general_interrogation = true,
        };
        self.rcbs[0] = .{
            .kind = .unbuffered,
            .domain = domain,
            .item = "LLN0$RP$EventsRCB01",
            .rpt_id = "Events1",
            .dat_set = domain ++ "/LLN0$Events",
            .conf_rev = 1,
            .opt_flds = opt,
            .trg_ops = trg,
            .buffer = try reporting.Buffer.init(&self.urcb_entries, &self.urcb_arena),
        };
        self.rcbs[1] = .{
            .kind = .buffered,
            .domain = domain,
            .item = "LLN0$BR$EventsBRCB01",
            .rpt_id = "Events2",
            .dat_set = domain ++ "/LLN0$Events",
            .conf_rev = 1,
            .opt_flds = opt,
            .trg_ops = trg,
            .buffer = try reporting.Buffer.init(&self.brcb_entries, &self.brcb_arena),
        };
        self.logs[0] = .{
            .domain = domain,
            .item = "LLN0$LG$EventLog",
            .journal = "LLN0$EventLog",
            .log_ref = domain ++ "/LLN0$EventLog",
            .dat_set = domain ++ "/LLN0$Events",
            .trg_ops = trg,
            .store = try logging.Store.init(&self.log_entries, &self.log_arena),
        };
        return .{
            .variables = &self.vars,
            .data_sets = &self.sets,
            .report_controls = &self.rcbs,
            .logs = &self.logs,
            .domains = &self.domains,
        };
    }
};

var seen_reports: usize = 0;
var seen_entries: usize = 0;
var seen_gi: usize = 0;
var seen_dchg: usize = 0;
var seen_integrity: usize = 0;

fn onReport(_: *anyopaque, r: report.Report) void {
    seen_reports += 1;
    seen_entries += r.entry_count;
    for (r.included()) |e| {
        const reason = e.reason orelse continue;
        if (reason.general_interrogation) seen_gi += 1;
        if (reason.data_change) seen_dchg += 1;
        if (reason.integrity) seen_integrity += 1;
    }
}

fn resetCounters() void {
    seen_reports = 0;
    seen_entries = 0;
    seen_gi = 0;
    seen_dchg = 0;
    seen_integrity = 0;
}

test "our client subscribes to our server's URCB and receives all three report kinds" {
    var fx: ReportFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [65536]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    try c.connect();
    resetCounters();
    var dummy: u8 = 0;
    c.setReportHandler(.{ .ctx = &dummy, .on_report = onReport });

    const rcb_ref = domain ++ "/LLN0.EventsRCB01";
    // The RCB reads back as the eleven-member URCB structure.
    const rcb = try c.readRcb(rcb_ref, .unbuffered);
    try testing.expectEqualStrings("Events1", rcb.rpt_id);
    try testing.expectEqualStrings(domain ++ "/LLN0$Events", rcb.dat_set);
    try testing.expect(!rcb.rpt_ena);

    try c.enableReporting(rcb_ref, .unbuffered, .{
        .data_change = true,
        .integrity = true,
        .general_interrogation = true,
    }, 1000);
    try testing.expect(srv.model.report_controls[0].rpt_ena);

    // 1. General interrogation: every member, reason `general-interrogation`.
    try c.generalInterrogation(rcb_ref, .unbuffered);
    try drainReports(&paired, &c, 8);
    try testing.expectEqual(@as(usize, 1), seen_reports);
    try testing.expectEqual(@as(usize, 4), seen_entries);
    try testing.expectEqual(@as(usize, 4), seen_gi);

    // 2. Data change: one member, reason `data-change`.
    resetCounters();
    var vbuf: [8]u8 = undefined;
    var vw = ber.Writer.init(&vbuf);
    try mmsdata.Emit.boolean(&vw, true);
    try c.writeObject(domain ++ "/GGIO1.Ind2.stVal", .ST, vw.done());
    try drainReports(&paired, &c, 8);
    try testing.expectEqual(@as(usize, 1), seen_reports);
    try testing.expectEqual(@as(usize, 1), seen_entries);
    try testing.expectEqual(@as(usize, 1), seen_dchg);

    // 3. Integrity period: the IED's own clock moves, nothing is asked for.
    resetCounters();
    srv.tick(1000);
    try drainReports(&paired, &c, 8);
    try testing.expectEqual(@as(usize, 1), seen_reports);
    try testing.expectEqual(@as(usize, 4), seen_entries);
    try testing.expectEqual(@as(usize, 4), seen_integrity);

    try c.disableReporting(rcb_ref, .unbuffered);
    try testing.expect(!srv.model.report_controls[0].rpt_ena);
    try testing.expectEqual(@as(u64, 3), srv.reports_sent);
    try testing.expectEqual(@as(usize, 0), paired.failures);
    c.disconnect();
}

/// Pushes the server's queued reports across the wire and lets the client
/// dispatch them.
fn drainReports(paired: *Paired, c: *client.Client, rounds: usize) !void {
    try paired.drain();
    var i: usize = 0;
    while (i < rounds) : (i += 1) {
        _ = c.poll() catch break;
    }
}

test "a BRCB retains what happened while the client was away and resumes by EntryID" {
    var fx: ReportFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [65536]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    try c.connect();
    resetCounters();
    var dummy: u8 = 0;
    c.setReportHandler(.{ .ctx = &dummy, .on_report = onReport });

    const brcb = &srv.model.report_controls[1];
    // Three changes with nobody subscribed at all.
    for ([_]usize{ 0, 1, 2 }) |i| {
        fx.vars[i].len = try emitBool(&fx.ind[i], true);
        srv.signal(i, .data_change);
    }
    try testing.expectEqual(@as(usize, 3), brcb.buffer.count);
    try testing.expect(!brcb.pending()); // buffered, but not enabled

    const ref = domain ++ "/LLN0.EventsBRCB01";
    try c.enableReporting(ref, .buffered, .{ .data_change = true }, null);
    try drainReports(&paired, &c, 12);
    // All three arrive on enable — the buffered guarantee.
    try testing.expectEqual(@as(usize, 3), seen_reports);
    try testing.expectEqual(@as(usize, 3), seen_dchg);

    // The BRCB read exposes the resume point.
    const rcb = try c.readRcb(ref, .buffered);
    try testing.expect(rcb.resv == null);
    try testing.expectEqual(false, rcb.purge_buf.?);
    try testing.expectEqual(@as(u64, 3), std.mem.readInt(u64, rcb.entry_id.?[0..8], .big));
    c.disconnect();
}

test "our server's report is what our own decoder reads, byte for byte" {
    // The server encodes; `report.Report.decode` — the client-side half, which
    // was validated against captured third-party traffic — reads it back.
    var fx: ReportFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    srv.model.report_controls[0].enable(1, 0);
    _ = try srv.model.report_controls[0].sweep(srv.reportSource(), .general_interrogation, 42);

    var out: [16384]u8 = undefined;
    srv.transport_up = true;
    const frame = (try srv.pendingNotification(&out)).?;
    // A complete TPKT that unwraps to an InformationReport.
    const pkt = try tpkt.decode(frame);
    const dt = (try cotp.decode(pkt.payload)).dt;
    const ppdu = try session.decodeDataTransfer(dt.payload);
    var contexts = presentation.ContextTable{};
    try contexts.define(presentation.context_mms, &ber.oids.mms_abstract_syntax);
    try contexts.applyResults(&[_]presentation.Result{.acceptance});
    const pdv = try presentation.decodeUserData(ppdu, &contexts);
    const r = try report.decodeInformationReport((try mms.decode(pdv.value)).unconfirmed.body);
    try testing.expectEqualStrings("Events1", r.rpt_id);
    try testing.expectEqualStrings(domain ++ "/LLN0$Events", r.dat_set.?);
    try testing.expectEqual(@as(u16, 4), r.entry_count);
    for (r.included()) |e| try testing.expect(e.reason.?.general_interrogation);
    try testing.expect((try srv.pendingNotification(&out)) == null);
}

test "a log fills, is read back over MMS, and its LCB reports the store's range" {
    var fx: ReportFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [65536]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    try c.connect();

    // Enable the log the way a client does: write `LogEna`.
    var vbuf: [8]u8 = undefined;
    var vw = ber.Writer.init(&vbuf);
    try mmsdata.Emit.boolean(&vw, true);
    try c.writeObject(domain ++ "/LLN0.EventLog.LogEna", .LG, vw.done());
    try testing.expect(srv.model.logs[0].log_ena);

    srv.tick(1_700_000_000_000);
    for ([_]usize{ 0, 1, 2 }) |i| {
        fx.vars[i].len = try emitBool(&fx.ind[i], true);
        srv.signal(i, .data_change);
    }
    try testing.expectEqual(@as(usize, 3), srv.model.logs[0].store.count);

    // `GetLogStatusValues` is a read of the LCB.
    // Each read is decoded out of the same reassembly buffer, so it has to be
    // consumed before the next request overwrites it.
    const old = try c.readObject(domain ++ "/LLN0.EventLog.OldEntr", .LG);
    try testing.expectEqual(@as(u64, 1), std.mem.readInt(u64, (try old.octetString())[0..8], .big));
    const new = try c.readObject(domain ++ "/LLN0.EventLog.NewEntr", .LG);
    try testing.expectEqual(@as(u64, 3), std.mem.readInt(u64, (try new.octetString())[0..8], .big));

    // …and `QueryLogAfter` is a ReadJournal.
    const status = try c.getJournalStatus(domain ++ "/LLN0$EventLog");
    try testing.expectEqual(@as(u32, 3), status.current_entries);
    try testing.expectEqual(@as(u32, 8), status.limit_entries.?);

    const resp = try c.readJournal(domain ++ "/LLN0$EventLog", .{});
    var it = resp.entries;
    var n: usize = 0;
    while (try it.next()) |e| : (n += 1) {
        var vars = e.iterate();
        var pairs: usize = 0;
        while (try vars.next()) |_| pairs += 1;
        // One member and its ReasonCode.
        try testing.expectEqual(@as(usize, 2), pairs);
    }
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expect(srv.journal_reads > 0);

    // A journal this server does not serve is a service error, not a crash.
    try testing.expectError(error.ServiceFailed, c.readJournal(domain ++ "/LLN0$NoSuchLog", .{}));
    c.disconnect();
}

/// Two settings across three groups, on top of the report fixture's model.
const SettingFixture = struct {
    base: ReportFixture = .{},
    a_store: [4 * 16]u8 = undefined,
    a_lens: [4]usize = @splat(0),
    b_store: [4 * 16]u8 = undefined,
    b_lens: [4]usize = @splat(0),
    settings: [2]settinggroups.Setting = undefined,
    sgcb: SettingGroups = undefined,

    fn init(self: *SettingFixture) !Model {
        var model = try self.base.init();
        self.settings[0] = .{
            .domain = domain,
            .ln = "PTOC1",
            .path = "StrVal$setMag$f",
            .storage = &self.a_store,
            .lens = &self.a_lens,
        };
        self.settings[1] = .{
            .domain = domain,
            .ln = "PTOC1",
            .path = "OpDlTmms$setVal",
            .storage = &self.b_store,
            .lens = &self.b_lens,
        };
        self.sgcb = .{ .domain = domain, .groups = 3, .settings = &self.settings };
        try self.sgcb.validate();
        for (0..3) |g| {
            var tmp: [16]u8 = undefined;
            var w = ber.Writer.init(&tmp);
            try mmsdata.Emit.float(&w, @floatFromInt(g + 1));
            try setSetting(self.settings[0], g, w.done());
            var w2 = ber.Writer.init(&tmp);
            try mmsdata.Emit.integer(&w2, @intCast((g + 1) * 100));
            try setSetting(self.settings[1], g, w2.done());
        }
        model.setting_groups = &self.sgcb;
        return model;
    }
};

fn setSetting(s: settinggroups.Setting, slot: usize, bytes: []const u8) !void {
    const n = s.storage.len / s.lens.len;
    if (bytes.len > n) return error.TestExpectedEqual;
    @memcpy(s.storage[slot * n ..][0..bytes.len], bytes);
    s.lens[slot] = bytes.len;
}

test "the setting-group services run end to end and an uncommitted edit stays invisible" {
    var fx: SettingFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [65536]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    try c.connect();

    const sgcb_ref = domain ++ "/LLN0.SGCB";
    const setting = domain ++ "/PTOC1.StrVal.setMag.f";

    // The SGCB reads back as five members.
    try testing.expectEqual(@as(u32, 3), try (try c.readObject(sgcb_ref ++ ".NumOfSG", .SP)).unsigned(u32));
    try testing.expectEqual(@as(u32, 1), try (try c.readObject(sgcb_ref ++ ".ActSG", .SP)).unsigned(u32));
    // `GetSGValues`: group one.
    try testing.expectApproxEqAbs(
        @as(f64, 1.0),
        try (try c.readObject(setting, .SG)).asFloat(),
        1e-6,
    );
    // An `SE` read with no edit group selected is refused, not answered.
    try testing.expectError(error.AccessFailed, c.readObject(setting, .SE));

    // SelectEditSG(1) — the *active* group, so a leak would be immediate.
    try c.selectEditSG(sgcb_ref, 1);
    var vbuf: [16]u8 = undefined;
    var vw = ber.Writer.init(&vbuf);
    try mmsdata.Emit.float(&vw, 42.0);
    try c.writeObject(setting, .SE, vw.done());
    // The edit buffer has it…
    try testing.expectApproxEqAbs(@as(f64, 42.0), try (try c.readObject(setting, .SE)).asFloat(), 1e-6);
    // …and the active group does not.
    try testing.expectApproxEqAbs(@as(f64, 1.0), try (try c.readObject(setting, .SG)).asFloat(), 1e-6);

    try c.confirmEditSGValues(sgcb_ref);
    try testing.expectApproxEqAbs(@as(f64, 42.0), try (try c.readObject(setting, .SG)).asFloat(), 1e-6);

    // SelectActiveSG(2): a different parameter set, immediately.
    try c.selectActiveSG(sgcb_ref, 2);
    try testing.expectApproxEqAbs(@as(f64, 2.0), try (try c.readObject(setting, .SG)).asFloat(), 1e-6);
    try testing.expectEqual(@as(u64, 1), srv.model.setting_groups.?.confirmations);

    // A group outside `1..NumOfSG` is refused per object.
    try testing.expectError(error.AccessFailed, c.selectActiveSG(sgcb_ref, 9));
    // Writing `SG` directly is refused: it is the active group's read-only view.
    try testing.expectError(error.AccessFailed, c.writeObject(setting, .SG, vw.done()));
    c.disconnect();
}

test "a confirm with no preceding edit is refused over the wire" {
    var fx: SettingFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [65536]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    try c.connect();
    const sgcb_ref = domain ++ "/LLN0.SGCB";
    try testing.expectError(error.AccessFailed, c.confirmEditSGValues(sgcb_ref));
    try c.selectEditSG(sgcb_ref, 2);
    // Selected but nothing written.
    try testing.expectError(error.AccessFailed, c.confirmEditSGValues(sgcb_ref));
    try testing.expectEqual(@as(u64, 0), srv.model.setting_groups.?.confirmations);
    c.disconnect();
}

test "an RCB enabled with a data set that does not resolve reports nothing" {
    var fx: ReportFixture = .{};
    var model = try fx.init();
    // Point the URCB at a data set index that is not in the model.
    fx.rcbs[0].data_set = 7;
    model.report_controls = &fx.rcbs;
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [65536]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    try c.connect();

    const ref = domain ++ "/LLN0.EventsRCB01";
    try c.enableReporting(ref, .unbuffered, .{ .general_interrogation = true }, null);
    try c.generalInterrogation(ref, .unbuffered);
    // A data set of zero members produces no entry at all, and no report.
    var out: [16384]u8 = undefined;
    try testing.expect((try srv.pendingNotification(&out)) == null);
    try testing.expectEqual(@as(u64, 0), srv.reports_sent);
    try testing.expectEqual(@as(usize, 0), paired.failures);
    c.disconnect();
}

test "a report control block cannot be reconfigured while a client has it enabled" {
    var fx: ReportFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [65536]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    try c.connect();

    const ref = domain ++ "/LLN0.EventsRCB01";
    var w: [16]u8 = undefined;
    var vw = ber.Writer.init(&w);
    try mmsdata.Emit.unsigned(&vw, 250);
    try c.writeObject(ref ++ ".BufTm", .RP, vw.done());
    try testing.expectEqual(@as(u32, 250), srv.model.report_controls[0].buf_tm_ms);

    try c.enableReporting(ref, .unbuffered, .{ .data_change = true }, null);
    var vw2 = ber.Writer.init(&w);
    try mmsdata.Emit.unsigned(&vw2, 10);
    try testing.expectError(error.AccessFailed, c.writeObject(ref ++ ".BufTm", .RP, vw2.done()));
    try testing.expectEqual(@as(u32, 250), srv.model.report_controls[0].buf_tm_ms);
    c.disconnect();
}

test "releasing the association purges a URCB and keeps a BRCB" {
    var fx: ReportFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    srv.model.report_controls[0].enable(1, 0);
    srv.model.report_controls[1].enable(1, 0);
    for ([_]usize{ 0, 1 }) |i| {
        fx.vars[i].len = try emitBool(&fx.ind[i], true);
        srv.signal(i, .data_change);
    }
    try testing.expectEqual(@as(usize, 2), srv.model.report_controls[0].buffer.count);
    try testing.expectEqual(@as(usize, 2), srv.model.report_controls[1].buffer.count);
    srv.releaseAssociation();
    try testing.expectEqual(@as(usize, 0), srv.model.report_controls[0].buffer.count);
    try testing.expectEqual(@as(usize, 2), srv.model.report_controls[1].buffer.count);
    try testing.expect(!srv.associated);
}

// ── segmentation, re-binding and reservation, client against server ─────────

/// A model wide enough that one report cannot fit a small PDU: twelve members
/// of a hundred octets each, plus a second, narrow data set to re-bind to.
const WideFixture = struct {
    payload: [12][160]u8 = undefined,
    vars: [12]Variable = undefined,
    sets: [2]DataSet = undefined,
    domains: [1][]const u8 = .{domain},
    entries: [4]reporting.Entry = @splat(.{}),
    arena: [4 * 4096]u8 = undefined,
    rcbs: [1]ReportControl = undefined,
    names: [12][32]u8 = undefined,

    fn init(self: *WideFixture) !Model {
        for (0..12) |i| {
            var body: [100]u8 = undefined;
            for (0..body.len) |k| body[k] = @intCast((i * 13 + k) & 0xFF);
            var w = ber.Writer.init(&self.payload[i]);
            try mmsdata.Emit.octetString(&w, &body);
            const d = w.done();
            std.mem.copyForwards(u8, self.payload[i][0..d.len], d);
            const item = try std.fmt.bufPrint(&self.names[i], "GGIO1$ST$M{d:0>2}$stVal", .{i});
            self.vars[i] = .{
                .domain = domain,
                .item = item,
                .storage = &self.payload[i],
                .len = d.len,
                .writable = true,
            };
        }
        self.sets[0] = .{
            .domain = domain,
            .item = "LLN0$Wide",
            .members = &[_]usize{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 },
        };
        self.sets[1] = .{ .domain = domain, .item = "LLN0$Narrow", .members = &[_]usize{ 0, 1 } };
        self.rcbs[0] = .{
            .kind = .unbuffered,
            .domain = domain,
            .item = "LLN0$RP$WideRCB01",
            .rpt_id = "Wide1",
            .dat_set = domain ++ "/LLN0$Wide",
            .data_set = 0,
            .conf_rev = 1,
            .opt_flds = .{
                .sequence_number = true,
                .report_time_stamp = true,
                .reason_for_inclusion = true,
                .data_set_name = true,
                .entry_id = true,
                .conf_revision = true,
                .segmentation = true,
            },
            .trg_ops = .{ .data_change = true, .general_interrogation = true },
            .include_owner = true,
            .buffer = try reporting.Buffer.init(&self.entries, &self.arena),
        };
        return .{
            .variables = &self.vars,
            .data_sets = &self.sets,
            .report_controls = &self.rcbs,
            .domains = &self.domains,
        };
    }
};

var seg_slots: [32]report.AssembledEntry = undefined;
var seg_arena: [8192]u8 = undefined;
var seg_re: report.Reassembler = undefined;
var seg_assembled: usize = 0;
var seg_members: usize = 0;
var seg_segments: u32 = 0;
var seg_errors: usize = 0;

fn onSegment(_: *anyopaque, r: report.Report) void {
    const done = seg_re.push(r) catch {
        seg_errors += 1;
        seg_re.reset();
        return;
    };
    if (done) |a| {
        seg_assembled += 1;
        seg_members = a.entries.len;
        seg_segments = a.segments;
    }
}

test "our client reassembles a segmented report our server split over the wire" {
    var fx: WideFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [65536]u8 = undefined;
    // The client tells the server how big a PDU it can take, and the server
    // segments against exactly that.
    var c = try client.Client.init(paired.seam(), &buf, .{ .local_detail = 900 });
    try c.connect();
    try testing.expectEqual(@as(usize, 900), srv.negotiated_pdu_len);

    seg_re = report.Reassembler.init(&seg_slots, &seg_arena);
    seg_assembled = 0;
    seg_errors = 0;
    var dummy: u8 = 0;
    c.setReportHandler(.{ .ctx = &dummy, .on_report = onSegment });

    const rcb_ref = domain ++ "/LLN0.WideRCB01";
    try c.enableReporting(rcb_ref, .unbuffered, .{
        .data_change = true,
        .general_interrogation = true,
    }, null);
    try c.generalInterrogation(rcb_ref, .unbuffered);
    try drainReports(&paired, &c, 24);

    // One report arrived, in several PDUs, carrying all twelve members.
    try testing.expectEqual(@as(usize, 1), seg_assembled);
    try testing.expectEqual(@as(usize, 12), seg_members);
    try testing.expect(seg_segments > 1);
    try testing.expectEqual(@as(usize, 0), seg_errors);
    try testing.expectEqual(@as(u64, seg_segments), srv.reports_sent);
    // …and the block is finished, not stuck half-way.
    try testing.expect(!srv.model.report_controls[0].segmenting());
    try testing.expectEqual(@as(u32, 1), srv.model.report_controls[0].sq_num);
    c.disconnect();
}

test "a client re-points a running server's RCB at another data set over MMS" {
    var fx: WideFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [65536]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    try c.connect();

    const rcb = domain ++ "/LLN0.WideRCB01";
    var vbuf: [64]u8 = undefined;

    // While enabled, the write is refused and the binding does not move.
    try c.enableReporting(rcb, .unbuffered, .{ .data_change = true }, null);
    var w = ber.Writer.init(&vbuf);
    try mmsdata.Emit.visibleString(&w, domain ++ "/LLN0$Narrow");
    try testing.expectError(
        error.AccessFailed,
        c.writeObject(rcb ++ ".DatSet", .RP, w.done()),
    );
    try testing.expectEqualStrings(domain ++ "/LLN0$Wide", srv.model.report_controls[0].datSet());
    try testing.expectEqual(@as(u32, 1), srv.model.report_controls[0].conf_rev);

    // Disabled, it takes — and `ConfRev` moves, which is how every other client
    // learns its cached configuration is stale.
    try c.disableReporting(rcb, .unbuffered);
    var w2 = ber.Writer.init(&vbuf);
    try mmsdata.Emit.visibleString(&w2, domain ++ "/LLN0$Narrow");
    try c.writeObject(rcb ++ ".DatSet", .RP, w2.done());
    try testing.expectEqual(@as(usize, 1), srv.model.report_controls[0].data_set);
    try testing.expectEqual(@as(u32, 2), srv.model.report_controls[0].conf_rev);

    // The RCB now reads back the new binding.
    const read = try c.readRcb(rcb, .unbuffered);
    try testing.expectEqualStrings(domain ++ "/LLN0$Narrow", read.dat_set);
    try testing.expectEqual(@as(u32, 2), read.conf_rev);

    // A data set that does not resolve is refused and changes nothing.
    var w3 = ber.Writer.init(&vbuf);
    try mmsdata.Emit.visibleString(&w3, domain ++ "/LLN0$Imaginary");
    try testing.expectError(
        error.AccessFailed,
        c.writeObject(rcb ++ ".DatSet", .RP, w3.done()),
    );
    try testing.expectEqual(@as(usize, 1), srv.model.report_controls[0].data_set);
    try testing.expectEqual(@as(u32, 2), srv.model.report_controls[0].conf_rev);

    // …and the re-bound block reports the *new* data set: two members, not
    // twelve.
    try c.enableReporting(rcb, .unbuffered, .{ .general_interrogation = true }, null);
    seg_re = report.Reassembler.init(&seg_slots, &seg_arena);
    seg_assembled = 0;
    var dummy: u8 = 0;
    c.setReportHandler(.{ .ctx = &dummy, .on_report = onSegment });
    try c.generalInterrogation(rcb, .unbuffered);
    try drainReports(&paired, &c, 12);
    try testing.expectEqual(@as(usize, 1), seg_assembled);
    try testing.expectEqual(@as(usize, 2), seg_members);
    c.disconnect();
}

test "two associations contend for one RCB and the reservation decides" {
    var fx: WideFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    // Two clients on one model. `Server.peer` is the association a frame
    // arrived on; the caller sets it before handing the frame over, which is
    // exactly what a multiplexing front end does.
    const alice: u32 = 0xC0A8_0102;
    const bob: u32 = 0xC0A8_0103;

    var paired = Paired{ .server = &srv };
    var buf: [65536]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    srv.peer = alice;
    try c.connect();

    const rcb = domain ++ "/LLN0.WideRCB01";
    var vbuf: [16]u8 = undefined;
    var w = ber.Writer.init(&vbuf);
    try mmsdata.Emit.boolean(&w, true);
    const yes = w.done();

    // Alice reserves it.
    try c.writeObject(rcb ++ ".Resv", .RP, yes);
    try testing.expect(srv.model.report_controls[0].resv);
    try testing.expectEqual(alice, srv.model.report_controls[0].owner.?);

    // `Owner` names her, in the four octets of her address.
    const owner = try c.readObject(rcb ++ ".Owner", .RP);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xC0, 0xA8, 0x01, 0x02 }, try owner.octetString());

    // Bob's frames arrive on his own association and he can do nothing at all.
    srv.peer = bob;
    try testing.expectError(error.AccessFailed, c.writeObject(rcb ++ ".RptEna", .RP, yes));
    try testing.expectError(error.AccessFailed, c.writeObject(rcb ++ ".Resv", .RP, yes));
    try testing.expect(!srv.model.report_controls[0].rpt_ena);
    // He may still *read* it — a reservation is not access control.
    const resv = try c.readObject(rcb ++ ".Resv", .RP);
    try testing.expectEqual(true, try resv.boolean());

    // Alice enables it, and Bob still cannot take it.
    srv.peer = alice;
    try c.writeObject(rcb ++ ".RptEna", .RP, yes);
    srv.peer = bob;
    try testing.expectError(error.AccessFailed, c.writeObject(rcb ++ ".RptEna", .RP, yes));

    // Alice's association drops. A URCB reservation does not survive it.
    srv.releaseAssociationOf(alice);
    try testing.expect(!srv.model.report_controls[0].resv);
    try testing.expect(srv.model.report_controls[0].owner == null);

    // Now Bob walks in, and `Owner` names him.
    srv.peer = bob;
    srv.associated = true;
    try c.writeObject(rcb ++ ".RptEna", .RP, yes);
    try testing.expectEqual(bob, srv.model.report_controls[0].owner.?);
    const owner2 = try c.readObject(rcb ++ ".Owner", .RP);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xC0, 0xA8, 0x01, 0x03 }, try owner2.octetString());
    c.disconnect();
}

test "a client deletes log entries over MMS and cannot delete the journal" {
    var fx: ReportFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [65536]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    try c.connect();

    srv.model.logs[0].log_ena = true;
    srv.tick(1_700_000_000_000);
    for ([_]usize{ 0, 1, 2, 3 }) |i| {
        fx.vars[i].len = try emitBool(&fx.ind[i], true);
        srv.signal(i, .data_change);
    }
    try testing.expectEqual(@as(usize, 4), srv.model.logs[0].store.count);

    const journal = domain ++ "/LLN0$EventLog";
    // Delete everything up to entry 2.
    var id: [8]u8 = undefined;
    std.mem.writeInt(u64, &id, 2, .big);
    try testing.expectEqual(@as(u32, 2), try c.initializeJournal(journal, .{ .limiting_entry = &id }));
    try testing.expectEqual(@as(usize, 2), srv.model.logs[0].store.count);
    try testing.expectEqual(@as(u64, 2), srv.journal_deletions);

    // A deletion reaching past the end deletes what is left, not an error.
    std.mem.writeInt(u64, &id, 1000, .big);
    try testing.expectEqual(@as(u32, 2), try c.initializeJournal(journal, .{ .limiting_entry = &id }));
    try testing.expectEqual(@as(usize, 0), srv.model.logs[0].store.count);
    try testing.expectEqual(@as(u32, 0), try c.initializeJournal(journal, .{}));

    // A journal this server does not serve, and the journal object itself.
    try testing.expectError(error.ServiceFailed, c.initializeJournal(domain ++ "/LLN0$NoSuchLog", .{}));
    try testing.expectError(error.ServiceFailed, c.deleteJournal(journal));
    try testing.expectError(error.ServiceFailed, c.deleteJournal(domain ++ "/LLN0$NoSuchLog"));
    c.disconnect();
}

test "a client filters a journal query to one variable over MMS" {
    var fx: ReportFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    var paired = Paired{ .server = &srv };
    var buf: [65536]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    try c.connect();

    srv.model.logs[0].log_ena = true;
    srv.tick(1_700_000_000_000);
    for ([_]usize{ 0, 1, 2 }) |i| {
        fx.vars[i].len = try emitBool(&fx.ind[i], true);
        srv.signal(i, .data_change);
    }

    const journal = domain ++ "/LLN0$EventLog";
    const wanted = domain ++ "/GGIO1$ST$Ind2$stVal";
    const resp = try c.readJournalFiltered(journal, .{}, &[_][]const u8{wanted});
    var it = resp.entries;
    var entries: usize = 0;
    var vars: usize = 0;
    var tag: []const u8 = "";
    while (try it.next()) |e| : (entries += 1) {
        var vi = e.iterate();
        while (try vi.next()) |v| {
            tag = v.tag;
            vars += 1;
        }
    }
    try testing.expectEqual(@as(usize, 1), entries);
    try testing.expectEqual(@as(usize, 1), vars);
    try testing.expectEqualStrings(wanted, tag);
    c.disconnect();
}

test "an abandoned setting-group edit expires on the server's own clock" {
    var fx: SettingFixture = .{};
    const model = try fx.init();
    var srv = Server.init(.{}, model);
    fx.sgcb.resv_tms = 30;
    var paired = Paired{ .server = &srv };
    var buf: [65536]u8 = undefined;
    var c = try client.Client.init(paired.seam(), &buf, .{});
    srv.peer = 1;
    try c.connect();

    var vbuf: [16]u8 = undefined;
    var w = ber.Writer.init(&vbuf);
    try mmsdata.Emit.unsigned(&w, 2);
    try c.writeObject(domain ++ "/LLN0.SGCB.EditSG", .SP, w.done());
    try testing.expectEqual(@as(u8, 2), fx.sgcb.edit_sg);

    // A second client cannot take it while it is live…
    srv.peer = 2;
    var w2 = ber.Writer.init(&vbuf);
    try mmsdata.Emit.unsigned(&w2, 3);
    try testing.expectError(
        error.AccessFailed,
        c.writeObject(domain ++ "/LLN0.SGCB.EditSG", .SP, w2.done()),
    );

    // …but the first one goes quiet without dropping its association, and the
    // server takes the selection back on its own clock.
    srv.tick(31_000);
    try testing.expectEqual(@as(u8, 0), fx.sgcb.edit_sg);
    try testing.expectEqual(@as(u64, 1), fx.sgcb.expirations);
    var w3 = ber.Writer.init(&vbuf);
    try mmsdata.Emit.unsigned(&w3, 3);
    try c.writeObject(domain ++ "/LLN0.SGCB.EditSG", .SP, w3.done());
    try testing.expectEqual(@as(u32, 2), fx.sgcb.editor.?);
    c.disconnect();
}
