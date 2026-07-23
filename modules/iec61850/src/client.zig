// SPDX-License-Identifier: MIT

//! An **IEC 61850 MMS client** — the association machine plus the services a
//! SCADA client, a test set or a fleet simulator actually uses.
//!
//! Connecting is five nested handshakes in one round trip, and every one of
//! them can fail on its own terms:
//!
//! ```text
//! TPKT  →  COTP CR / CC
//!          └─ session CONNECT / ACCEPT
//!             └─ presentation CP / CPA   (context list negotiated here)
//!                └─ ACSE AARQ / AARE      (result != 0 means refused)
//!                   └─ MMS Initiate       (service-supported bitstrings)
//! ```
//!
//! The client therefore checks each layer separately rather than reporting
//! "connected" the moment TCP is up: a CPA that rejected the MMS presentation
//! context, or an AARE with `result = rejected-permanent`, both look like a
//! healthy socket.
//!
//! **Unsolicited PDUs arrive mid-exchange.** Once reporting is enabled an IED
//! pushes `InformationReport`s whenever it likes, including between a request
//! and its response. `exchange` therefore loops: anything unconfirmed is handed
//! to the report handler and reading continues, and only a confirmed PDU with
//! the matching invoke id ends the wait.
//!
//! Buffers are caller-supplied and split three ways (receive, reassembly,
//! transmit). Decoded values point into the reassembly buffer and are
//! **invalidated by the next request** — the same contract every zero-copy
//! decoder in this repo has.

const std = @import("std");
const ber = @import("ber.zig");
const tpkt = @import("tpkt.zig");
const cotp = @import("cotp.zig");
const session = @import("session.zig");
const presentation = @import("presentation.zig");
const acse = @import("acse.zig");
const mms = @import("mms.zig");
const mmsdata = @import("mmsdata.zig");
const acsi = @import("acsi.zig");
const report = @import("report.zig");
const control = @import("control.zig");
const logging = @import("logging.zig");
const transport = @import("transport.zig");

pub const Error = mms.Error || presentation.Error || acse.Error ||
    session.Error || cotp.Error || tpkt.Error || acsi.Error || report.Error ||
    control.Error || logging.Error || transport.TransportError || error{
    NotConnected,
    AlreadyConnected,
    /// The peer refused the transport connection.
    TransportRefused,
    /// The peer rejected one of the presentation contexts we need.
    ContextRejected,
    /// The peer's AARE said the association was not accepted.
    AssociationRefused,
    /// A confirmed response never arrived.
    NoResponse,
    /// The server answered with a `confirmed-ErrorPDU`.
    ServiceFailed,
    /// The value could not be read or written (per-variable failure).
    AccessFailed,
    /// The caller's buffer is too small for this exchange.
    BufferTooSmall,
    /// A reference this client cannot parse into an object name.
    BadReference,
};

pub const Config = struct {
    /// COTP TSAPs. `00 01` is what every IEC 61850 stack observed here uses.
    called_tsap: []const u8 = &[_]u8{ 0x00, 0x01 },
    calling_tsap: []const u8 = &[_]u8{ 0x00, 0x01 },
    tpdu_size: cotp.TpduSize = .b8192,
    session_options: session.ConnectOptions = .{},
    presentation_options: presentation.CpOptions = .{},
    identity: acse.Identity = .{},
    /// `localDetailCalling` — the largest MMS PDU we will accept.
    local_detail: i32 = 65000,
    max_serv_outstanding: i16 = 5,
    nesting_level: i8 = 10,
    /// How many reads to spend waiting for one response before giving up.
    /// The transport's own timeout decides how long each read blocks.
    max_read_rounds: u32 = 64,
};

/// Called for every `InformationReport` the server pushes.
pub const ReportHandler = struct {
    ctx: *anyopaque,
    on_report: *const fn (ctx: *anyopaque, r: report.Report) void,
};

/// Called for every unsolicited **control** notification — a
/// `CommandTermination` of either sign, or a bare `LastApplError`. These arrive
/// on the same `InformationReport` channel as ordinary reports and are told
/// apart by `control.classify`, so a client that only registers a
/// `ReportHandler` would decode a termination as a report and read nonsense.
pub const ControlHandler = struct {
    ctx: *anyopaque,
    on_notification: *const fn (ctx: *anyopaque, n: control.Notification) void,
};

/// The smallest sensible buffer: one 8 kB TPDU each for receive, reassembly,
/// transmit and request scratch.
pub const min_buffer_size: usize = 4 * 8192;

pub const Client = struct {
    link: transport.Transport,
    config: Config,
    rx: []u8,
    reasm: []u8,
    tx: []u8,
    /// Scratch for building a request body before `sendMms` wraps it. Kept
    /// separate from `tx` because the wrapper writes into `tx` and a request
    /// built there would alias itself.
    scratch: []u8,

    contexts: presentation.ContextTable = .{},
    mms_context: u16 = presentation.context_mms,
    acse_context: u16 = presentation.context_acse,
    connected: bool = false,
    next_invoke_id: u32 = 1,
    /// The server's `Initiate` response — its service-supported bit string is
    /// the only reliable way to know what it implements.
    server: ?mms.Initiate = null,
    /// Negotiated ceiling on an MMS PDU.
    max_pdu: usize = 8192,
    handler: ?ReportHandler = null,
    control_handler: ?ControlHandler = null,
    /// The most recent control notification. Like every decoded value here it
    /// points into the reassembly buffer and is invalidated by the next
    /// request — copy what you need out of it.
    last_notification: ?control.Notification = null,
    /// Octets held by a partially reassembled COTP sequence.
    reasm_len: usize = 0,
    /// Diagnostics.
    reports_received: u64 = 0,
    notifications_received: u64 = 0,

    pub fn init(link: transport.Transport, buf: []u8, config: Config) Error!Client {
        if (buf.len < 4 * 512) return error.BufferTooSmall;
        const q = buf.len / 4;
        return .{
            .link = link,
            .config = config,
            .rx = buf[0..q],
            .reasm = buf[q .. 2 * q],
            .tx = buf[2 * q .. 3 * q],
            .scratch = buf[3 * q ..],
        };
    }

    pub fn setReportHandler(self: *Client, h: ReportHandler) void {
        self.handler = h;
    }

    pub fn setControlHandler(self: *Client, h: ControlHandler) void {
        self.control_handler = h;
    }

    // ── association ────────────────────────────────────────────────────────

    pub fn connect(self: *Client) Error!void {
        if (self.connected) return error.AlreadyConnected;

        // 1. COTP connection request.
        var cr_buf: [128]u8 = undefined;
        const cr = try cotp.encodeConnect(
            .cr,
            0,
            1,
            self.config.tpdu_size,
            self.config.called_tsap,
            self.config.calling_tsap,
            &cr_buf,
        );
        try self.writeTpkt(cr);
        const cc_payload = try self.readTpkt();
        const cc = switch (try cotp.decode(cc_payload)) {
            .cc => |c| c,
            else => return error.TransportRefused,
        };
        if (cc.tpdu_size) |s| {
            const octets = s.octets();
            if (octets != 0) self.max_pdu = octets;
        }

        // 2..5. Session CONNECT wrapping presentation CP wrapping ACSE AARQ
        //       wrapping the MMS Initiate request — one packet.
        self.contexts = .{};
        for (self.config.presentation_options.contexts) |c| {
            try self.contexts.define(c.id, c.abstract_syntax);
        }

        const init_req = mms.Initiate{
            .local_detail = self.config.local_detail,
            .max_serv_outstanding_calling = self.config.max_serv_outstanding,
            .max_serv_outstanding_called = self.config.max_serv_outstanding,
            .data_structure_nesting_level = self.config.nesting_level,
            .version_number = 1,
            .parameter_cbb = try ber.BitString.parse(&default_parameter_cbb),
            .services_supported = try ber.BitString.parse(&default_services_supported),
        };
        var mms_buf: [512]u8 = undefined;
        const mms_pdu = try init_req.encode(true, &mms_buf);

        var aarq_buf: [768]u8 = undefined;
        var id = self.config.identity;
        id.indirect_reference = self.mmsContextId();
        const aarq = try acse.encodeAarq(mms_pdu, id, &aarq_buf);

        var ud_buf: [1024]u8 = undefined;
        const ud = try presentation.encodeUserData(self.acseContextId(), aarq, &ud_buf);

        var cp_buf: [1536]u8 = undefined;
        const cp = try presentation.encodeCp(ud, self.config.presentation_options, &cp_buf);

        var spdu_buf: [2048]u8 = undefined;
        const spdu = try session.encodeConnect(cp, self.config.session_options, &spdu_buf);

        var dt_buf: [2176]u8 = undefined;
        try self.writeTpkt(try cotp.encodeData(spdu, true, &dt_buf));

        // The response comes back as ACCEPT / CPA / AARE / Initiate-Response.
        const spdu_in = try self.readSpdu();
        const accept = try session.decodeConnect(spdu_in);
        if (accept.spdu != .accept) return error.AssociationRefused;
        const cpa = try presentation.decodeCp(accept.user_data);
        // The result list is positional against what we proposed.
        try self.contexts.applyResults(cpa.resultList());
        self.mms_context = self.contexts.idFor(&ber.oids.mms_abstract_syntax) orelse
            return error.ContextRejected;
        self.acse_context = self.contexts.idFor(&ber.oids.acse_abstract_syntax) orelse
            return error.ContextRejected;

        var pdvs = presentation.PdvIterator.init(cpa.user_data);
        const pdv = (try pdvs.next()) orelse return error.AssociationRefused;
        _ = try self.contexts.check(pdv.context_id);
        const aare = try acse.decodeAare(pdv.value);
        if (!aare.accepted()) return error.AssociationRefused;

        const init_resp = try mms.decode(aare.user_information);
        self.server = switch (init_resp) {
            .initiate_response => |r| r,
            else => return error.AssociationRefused,
        };
        if (self.server.?.local_detail) |d| {
            if (d > 0) self.max_pdu = @min(self.max_pdu, @as(usize, @intCast(d)));
        }
        self.connected = true;
    }

    /// Orderly release: MMS `Conclude`, then a session ABORT carrying an ACSE
    /// `ABRT` — the shape the reference client uses. Best effort; the socket is
    /// the caller's to close.
    pub fn disconnect(self: *Client) void {
        if (!self.connected) return;
        self.connected = false;
        var mms_buf: [16]u8 = undefined;
        const conclude = mms.encodeConcludeRequest(&mms_buf) catch return;
        _ = self.sendMms(conclude) catch {};

        var abrt_buf: [16]u8 = undefined;
        const abrt = acse.encodeAbrt(0, &abrt_buf) catch return;
        var ud_buf: [64]u8 = undefined;
        const ud = presentation.encodeUserData(self.acse_context, abrt, &ud_buf) catch return;
        // ARU-PPDU: normal-mode-parameters [0] { user-data }.
        var aru_buf: [128]u8 = undefined;
        var w = ber.Writer.init(&aru_buf);
        const m = w.mark();
        w.bytes(ud) catch return;
        w.header(ber.Tag.ctxc(0), m) catch return;
        var spdu_buf: [192]u8 = undefined;
        const spdu = session.encodeAbort(w.done(), 0x0B, &spdu_buf) catch return;
        var dt_buf: [256]u8 = undefined;
        const dt = cotp.encodeData(spdu, true, &dt_buf) catch return;
        self.writeTpkt(dt) catch {};
    }

    pub fn isConnected(self: *const Client) bool {
        return self.connected;
    }

    /// Does the server advertise this service? `mms.Initiate.service_bit` names
    /// the positions.
    pub fn serverSupports(self: *const Client, bit: usize) bool {
        const s = self.server orelse return false;
        return s.supports(bit);
    }

    fn mmsContextId(self: *const Client) u16 {
        return self.mms_context;
    }
    fn acseContextId(self: *const Client) u16 {
        return self.acse_context;
    }

    // ── services ───────────────────────────────────────────────────────────

    /// Reads one data attribute by its ACSI reference and functional
    /// constraint. The returned value points into the client's reassembly
    /// buffer and is invalidated by the next request.
    pub fn readObject(self: *Client, reference: []const u8, fc: acsi.FunctionalConstraint) Error!mmsdata.Data {
        var item: [acsi.max_reference_len]u8 = undefined;
        const name = try acsi.objectNameFor(reference, fc, &item);
        return self.readName(name);
    }

    pub fn readName(self: *Client, name: mms.ObjectName) Error!mmsdata.Data {
        const id = self.takeInvokeId();
        var req: [512]u8 = undefined;
        const pdu = try mms.encodeRead(id, .{ .variables = &[_]mms.ObjectName{name} }, false, &req);
        const resp = try self.exchange(pdu, id, .read);
        var r = try mms.decodeReadResponse(resp);
        const first = (try r.results.next()) orelse return error.NoResponse;
        return switch (first) {
            .success => |d| blk: {
                try d.validate();
                break :blk d;
            },
            .failure => error.AccessFailed,
        };
    }

    /// Reads a whole data set (named variable list) in one request.
    pub fn readDataSet(self: *Client, reference: []const u8) Error!mms.AccessResultIterator {
        const slash = std.mem.indexOfScalar(u8, reference, '/') orelse return error.MissingLogicalDevice;
        const name = mms.ObjectName{ .domain_specific = .{
            .domain = reference[0..slash],
            .item = reference[slash + 1 ..],
        } };
        const id = self.takeInvokeId();
        var req: [512]u8 = undefined;
        const pdu = try mms.encodeRead(id, .{ .variable_list = name }, false, &req);
        const resp = try self.exchange(pdu, id, .read);
        const r = try mms.decodeReadResponse(resp);
        return r.results;
    }

    /// Writes one data attribute. `value` is a complete, already encoded `Data`
    /// TLV — build it with `mmsdata.Emit` through a `ber.Writer`.
    pub fn writeObject(
        self: *Client,
        reference: []const u8,
        fc: acsi.FunctionalConstraint,
        value: []const u8,
    ) Error!void {
        var item: [acsi.max_reference_len]u8 = undefined;
        const name = try acsi.objectNameFor(reference, fc, &item);
        return self.writeName(name, value);
    }

    pub fn writeName(self: *Client, name: mms.ObjectName, value: []const u8) Error!void {
        const id = self.takeInvokeId();
        if (value.len + 256 > self.scratch.len) return error.BufferTooSmall;
        const pdu = try mms.encodeWrite(
            id,
            .{ .variables = &[_]mms.ObjectName{name} },
            &[_][]const u8{value},
            self.scratch,
        );
        const resp = try self.exchange(pdu, id, .write);
        var it = mms.decodeWriteResponse(resp);
        const first = (try it.next()) orelse return error.NoResponse;
        return switch (first) {
            .success => {},
            .failure => error.AccessFailed,
        };
    }

    /// `GetNameList` over domains — the list of logical devices.
    pub fn getServerDirectory(self: *Client, names: [][]const u8) Error!usize {
        return self.getNameList(.domain, .vmd, names);
    }

    /// `GetNameList` over the named variables of one logical device.
    pub fn getLogicalDeviceDirectory(self: *Client, ld: []const u8, names: [][]const u8) Error!usize {
        return self.getNameList(.named_variable, .{ .domain = ld }, names);
    }

    /// `GetNameList` over the data sets of one logical device.
    pub fn getDataSetDirectory(self: *Client, ld: []const u8, names: [][]const u8) Error!usize {
        return self.getNameList(.named_variable_list, .{ .domain = ld }, names);
    }

    /// Runs `GetNameList` to exhaustion, following `moreFollows` with the
    /// continuation point the standard prescribes. Fills `names` and returns
    /// how many were written; names point into the reassembly buffer, so a
    /// caller that needs them past the next call must copy.
    pub fn getNameList(
        self: *Client,
        class: mms.ObjectClass,
        scope: mms.Scope,
        names: [][]const u8,
    ) Error!usize {
        var written: usize = 0;
        var continue_after: ?[]const u8 = null;
        var rounds: usize = 0;
        while (rounds < 256) : (rounds += 1) {
            const id = self.takeInvokeId();
            var req: [512]u8 = undefined;
            const pdu = try mms.encodeGetNameList(id, class, scope, continue_after, &req);
            const resp = try self.exchange(pdu, id, .get_name_list);
            var r = try mms.decodeGetNameListResponse(resp);
            var last: ?[]const u8 = null;
            while (try r.names.next()) |n| {
                last = n;
                if (written < names.len) {
                    names[written] = n;
                    written += 1;
                }
            }
            if (!r.more_follows or last == null) return written;
            continue_after = last;
            // A server that says "more follow" but sends nothing would loop.
            if (written == 0 and last == null) return written;
        }
        return written;
    }

    pub fn identify(self: *Client) Error!mms.IdentifyResponse {
        const id = self.takeInvokeId();
        var req: [64]u8 = undefined;
        const pdu = try mms.encodeIdentify(id, &req);
        return mms.decodeIdentifyResponse(try self.exchange(pdu, id, .identify));
    }

    /// Reads a report control block and decodes it.
    pub fn readRcb(self: *Client, reference: []const u8, kind: report.RcbKind) Error!report.Rcb {
        const fc: acsi.FunctionalConstraint = switch (kind) {
            .buffered => .BR,
            .unbuffered => .RP,
        };
        const d = try self.readObject(reference, fc);
        return report.Rcb.decode(d, kind);
    }

    /// Enables reporting on an RCB: writes `TrgOps`, `IntgPd` and finally
    /// `RptEna`. The order matters — an IED refuses a configuration write while
    /// the RCB is enabled, which is the single most common reporting bug.
    pub fn enableReporting(
        self: *Client,
        rcb_reference: []const u8,
        kind: report.RcbKind,
        trg_ops: report.TrgOps,
        integrity_period_ms: ?u32,
    ) Error!void {
        const fc: acsi.FunctionalConstraint = switch (kind) {
            .buffered => .BR,
            .unbuffered => .RP,
        };
        var ref_buf: [acsi.max_reference_len]u8 = undefined;

        var w1: [64]u8 = undefined;
        var wr = ber.Writer.init(&w1);
        try trg_ops.emit(&wr);
        try self.writeObject(try attribute(rcb_reference, "TrgOps", &ref_buf), fc, wr.done());

        if (integrity_period_ms) |ms| {
            var w2: [64]u8 = undefined;
            var wr2 = ber.Writer.init(&w2);
            try mmsdata.Emit.unsigned(&wr2, ms);
            try self.writeObject(try attribute(rcb_reference, "IntgPd", &ref_buf), fc, wr2.done());
        }

        var w3: [16]u8 = undefined;
        var wr3 = ber.Writer.init(&w3);
        try mmsdata.Emit.boolean(&wr3, true);
        try self.writeObject(try attribute(rcb_reference, "RptEna", &ref_buf), fc, wr3.done());
    }

    /// Triggers a general interrogation on an enabled RCB.
    pub fn generalInterrogation(self: *Client, rcb_reference: []const u8, kind: report.RcbKind) Error!void {
        const fc: acsi.FunctionalConstraint = switch (kind) {
            .buffered => .BR,
            .unbuffered => .RP,
        };
        var ref_buf: [acsi.max_reference_len]u8 = undefined;
        var w: [16]u8 = undefined;
        var wr = ber.Writer.init(&w);
        try mmsdata.Emit.boolean(&wr, true);
        try self.writeObject(try attribute(rcb_reference, "GI", &ref_buf), fc, wr.done());
    }

    pub fn disableReporting(self: *Client, rcb_reference: []const u8, kind: report.RcbKind) Error!void {
        const fc: acsi.FunctionalConstraint = switch (kind) {
            .buffered => .BR,
            .unbuffered => .RP,
        };
        var ref_buf: [acsi.max_reference_len]u8 = undefined;
        var w: [16]u8 = undefined;
        var wr = ber.Writer.init(&w);
        try mmsdata.Emit.boolean(&wr, false);
        try self.writeObject(try attribute(rcb_reference, "RptEna", &ref_buf), fc, wr.done());
    }

    // ── logs (IEC 61850-7-2 §18) ───────────────────────────────────────────

    /// `QueryLogByTime` / `QueryLogAfter` — one MMS `ReadJournal`.
    ///
    /// `journal_reference` is the log's own reference, `LD/LLN0$EventLog`: no
    /// functional constraint, because a journal is not a named variable. The
    /// returned iterator points into the client's reassembly buffer and is
    /// invalidated by the next request, exactly like a read result.
    pub fn readJournal(
        self: *Client,
        journal_reference: []const u8,
        range: logging.Range,
    ) Error!logging.ReadJournalResponse {
        const name = try journalName(journal_reference);
        const id = self.takeInvokeId();
        var req: [512]u8 = undefined;
        const pdu = try logging.encodeReadJournal(id, name, range, &req);
        const resp = try self.exchange(pdu, id, logging.read_journal_service);
        return logging.decodeReadJournalResponse(resp);
    }

    /// `GetJournalStatus` — how many entries the log holds.
    pub fn getJournalStatus(self: *Client, journal_reference: []const u8) Error!logging.JournalStatus {
        const name = try journalName(journal_reference);
        const id = self.takeInvokeId();
        var req: [256]u8 = undefined;
        const pdu = try logging.encodeGetJournalStatus(id, name, &req);
        const resp = try self.exchange(pdu, id, logging.get_journal_status_service);
        return logging.decodeGetJournalStatusResponse(resp);
    }

    fn journalName(reference: []const u8) Error!mms.ObjectName {
        const slash = std.mem.indexOfScalar(u8, reference, '/') orelse return error.BadReference;
        return .{ .domain_specific = .{
            .domain = reference[0..slash],
            .item = reference[slash + 1 ..],
        } };
    }

    // ── setting groups (IEC 61850-7-2 §19) ─────────────────────────────────

    /// `SelectActiveSG` — a write of `ActSG` on the SGCB.
    pub fn selectActiveSG(self: *Client, sgcb_reference: []const u8, group: u8) Error!void {
        try self.writeSgcb(sgcb_reference, "ActSG", group);
    }

    /// `SelectEditSG`. Group 0 releases the selection.
    pub fn selectEditSG(self: *Client, sgcb_reference: []const u8, group: u8) Error!void {
        try self.writeSgcb(sgcb_reference, "EditSG", group);
    }

    /// `ConfirmEditSGValues` — a write of `CnfEdit = true`. Until this lands,
    /// nothing the client wrote under `SE` has any effect.
    pub fn confirmEditSGValues(self: *Client, sgcb_reference: []const u8) Error!void {
        var ref_buf: [acsi.max_reference_len]u8 = undefined;
        var buf: [16]u8 = undefined;
        var w = ber.Writer.init(&buf);
        try mmsdata.Emit.boolean(&w, true);
        try self.writeObject(try attribute(sgcb_reference, "CnfEdit", &ref_buf), .SP, w.done());
    }

    fn writeSgcb(self: *Client, sgcb_reference: []const u8, attr: []const u8, group: u8) Error!void {
        var ref_buf: [acsi.max_reference_len]u8 = undefined;
        var buf: [16]u8 = undefined;
        var w = ber.Writer.init(&buf);
        try mmsdata.Emit.unsigned(&w, group);
        try self.writeObject(try attribute(sgcb_reference, attr, &ref_buf), .SP, w.done());
    }

    // ── the control model (IEC 61850-7-2 §20) ──────────────────────────────

    /// Reads `<object>.ctlModel` under `CF` — the first thing a control client
    /// must do, because it decides whether to select and whether to wait for a
    /// `CommandTermination`.
    pub fn readCtlModel(self: *Client, object_reference: []const u8) Error!control.CtlModel {
        var item: [acsi.max_reference_len]u8 = undefined;
        const name = try control.controlName(object_reference, .CF, "ctlModel", &item);
        return control.CtlModel.fromData(try self.readName(name));
    }

    /// Reads `<object>.sboTimeout` under `CF`, in milliseconds. Null when the
    /// IED does not publish one — most do not, and then nothing expires
    /// client-side.
    pub fn readSboTimeout(self: *Client, object_reference: []const u8) Error!?u32 {
        var item: [acsi.max_reference_len]u8 = undefined;
        const name = try control.controlName(object_reference, .CF, "sboTimeout", &item);
        const d = self.readName(name) catch return null;
        const v = d.asInt() catch return null;
        if (v < 0) return null;
        return @intCast(@min(v, std.math.maxInt(u32)));
    }

    /// `sbo-with-normal-security` select: a **read** of `SBO`. A successful
    /// select answers with the object's own reference; an empty string is the
    /// standard's "refused", and the IED reports no reason at all.
    pub fn selectObject(self: *Client, object_reference: []const u8) Error!bool {
        var item: [acsi.max_reference_len]u8 = undefined;
        const name = try control.controlName(object_reference, .CO, "SBO", &item);
        self.last_notification = null;
        const d = self.readName(name) catch |e| switch (e) {
            error.AccessFailed => return false,
            else => return e,
        };
        const s = try d.visibleString();
        return s.len > 0;
    }

    /// `sbo-with-enhanced-security` select: a **write** of `SBOw`, carrying the
    /// same structure the `Oper` will carry — including the `ctlNum` the
    /// operate must repeat.
    pub fn selectWithValue(self: *Client, object_reference: []const u8, cmd: control.Command) Error!void {
        return self.writeControl(object_reference, "SBOw", cmd);
    }

    /// Writes `Oper`. A positive answer under an **enhanced** model means only
    /// "accepted for execution" — call `awaitNotification` for the verdict.
    pub fn operateObject(self: *Client, object_reference: []const u8, cmd: control.Command) Error!void {
        return self.writeControl(object_reference, "Oper", cmd);
    }

    /// Writes `Cancel`. Legal at any point: it deselects an armed select and
    /// aborts an execution in flight.
    pub fn cancelObject(self: *Client, object_reference: []const u8, cmd: control.Command) Error!void {
        var c = cmd;
        c.check = null; // Cancel has no Check member.
        return self.writeControl(object_reference, "Cancel", c);
    }

    /// The `AddCause` of the most recent rejection, when the IED sent a
    /// `LastApplError` alongside the negative write response. Null when it did
    /// not — normal-security models usually do not.
    pub fn lastAddCause(self: *const Client) ?control.AddCause {
        const n = self.last_notification orelse return null;
        return n.addCause();
    }

    fn writeControl(
        self: *Client,
        object_reference: []const u8,
        attr: []const u8,
        cmd: control.Command,
    ) Error!void {
        var item: [acsi.max_reference_len]u8 = undefined;
        const name = try control.controlName(object_reference, .CO, attr, &item);
        var value: [control.Command.max_encoded_len]u8 = undefined;
        const encoded = try cmd.encode(&value);
        // A `LastApplError` for this command arrives *before* the negative
        // write response, so clear the slot first and it is waiting when the
        // write fails.
        self.last_notification = null;
        return self.writeName(name, encoded);
    }

    /// Discards any control notification already received. `writeControl` calls
    /// it before every command, so `awaitNotification` afterwards cannot return
    /// a stale one.
    pub fn clearNotification(self: *Client) void {
        self.last_notification = null;
    }

    /// Waits for an unsolicited control notification. **Returns one that has
    /// already arrived**: a `CommandTermination` frequently overtakes the write
    /// response it follows — the two are separate TPKTs and `exchange` reads
    /// past anything unconfirmed — so a client that unconditionally polls again
    /// waits for a second termination that never comes. The slot is cleared by
    /// the next command, not here.
    pub fn awaitNotification(self: *Client, rounds: u32) Error!control.Notification {
        if (!self.connected) return error.NotConnected;
        if (self.last_notification) |n| return n;
        var i: u32 = 0;
        while (i < rounds) : (i += 1) {
            _ = self.poll() catch continue;
            if (self.last_notification) |n| return n;
        }
        return error.NoResponse;
    }

    /// Drives one whole command through `machine`: select if the model needs
    /// one, operate, and — under an enhanced model — wait for the
    /// `CommandTermination`. `now_ms` is the caller's clock; nothing here owns
    /// a timer, so a `sboTimeout` can only expire across calls.
    ///
    /// The command's `ctlNum` is taken from the machine, never from the
    /// caller: matching it is the machine's job.
    pub fn executeControl(
        self: *Client,
        machine: *control.Machine,
        object_reference: []const u8,
        command: control.Command,
        now_ms: u64,
    ) Error!void {
        var cmd = command;
        var step = try machine.start(now_ms);
        while (true) {
            cmd.ctl_num = machine.ctl_num;
            switch (step) {
                .read_sbo => {
                    const ok = try self.selectObject(object_reference);
                    if (!ok) {
                        _ = machine.selectFailed(self.lastAddCause(), null);
                        return error.ControlRejected;
                    }
                    step = try machine.selectSucceeded(now_ms);
                },
                .write_sbow => {
                    self.selectWithValue(object_reference, cmd) catch {
                        _ = machine.selectFailed(self.lastAddCause(), null);
                        return error.ControlRejected;
                    };
                    step = try machine.selectSucceeded(now_ms);
                },
                .write_oper => {
                    _ = try machine.beginOperate(now_ms);
                    self.operateObject(object_reference, cmd) catch {
                        _ = machine.operateRejected(self.lastAddCause(), null);
                        return error.ControlRejected;
                    };
                    step = try machine.operateAccepted(now_ms);
                },
                .wait_termination => {
                    const n = try self.awaitNotification(self.config.max_read_rounds);
                    step = try machine.terminated(n);
                    if (machine.state == .failed) return error.ControlRejected;
                },
                .finished => return,
            }
        }
    }

    /// Reads one pending unsolicited PDU, if any, dispatching reports to the
    /// handler. Returns true when something was processed.
    pub fn poll(self: *Client) Error!bool {
        if (!self.connected) return error.NotConnected;
        const n = try self.link.read(self.rx);
        if (n == 0) return false;
        const spdu = try self.pushTpkt(self.rx[0..n]) orelse return false;
        const mms_pdu = try self.unwrap(spdu);
        const pdu = try mms.decode(mms_pdu);
        switch (pdu) {
            .unconfirmed => |u| {
                try self.dispatchUnconfirmed(u);
                return true;
            },
            else => return true,
        }
    }

    // ── plumbing ───────────────────────────────────────────────────────────

    fn takeInvokeId(self: *Client) u32 {
        const id = self.next_invoke_id;
        self.next_invoke_id +%= 1;
        if (self.next_invoke_id == 0) self.next_invoke_id = 1;
        return id;
    }

    /// Sends an MMS PDU wrapped in presentation + session + COTP + TPKT.
    ///
    /// Every one of those layers is a **prefix**, and the BER writer builds
    /// backwards, so the whole stack is assembled in one buffer with the MMS
    /// PDU copied exactly once and no scratch allocation anywhere.
    fn sendMms(self: *Client, mms_pdu: []const u8) Error!void {
        var w = ber.Writer.init(self.tx);
        // presentation: fully-encoded-data { PDV-list { pci, [0] value } }
        const outer = w.mark();
        try w.bytes(mms_pdu);
        try w.header(ber.Tag.ctxc(0), outer);
        try w.integer(ber.Tag.uni(ber.Universal.integer), self.mms_context);
        try w.header(ber.Tag.sequence, outer);
        try w.header(presentation.tag_user_data, outer);
        // session: GIVE TOKENS + DATA TRANSFER, both LI 0
        try w.bytes(&session.data_transfer_prefix);
        // COTP: class-0 DT with EOT set
        try w.bytes(&[_]u8{ 0x02, 0xF0, 0x80 });
        // TPKT: the length counts the header too
        const total = w.len() + tpkt.header_len;
        if (total > tpkt.max_length) return error.BufferTooSmall;
        try w.bytes(&[_]u8{ tpkt.version, 0, @intCast((total >> 8) & 0xFF), @intCast(total & 0xFF) });
        try self.link.write(w.done());
    }

    /// One confirmed request/response exchange. Unsolicited PDUs arriving in
    /// between are dispatched and skipped.
    pub fn exchange(self: *Client, mms_pdu: []const u8, invoke_id: u32, service: mms.Service) Error![]const u8 {
        if (!self.connected) return error.NotConnected;
        try self.sendMms(mms_pdu);
        var rounds: u32 = 0;
        while (rounds < self.config.max_read_rounds) : (rounds += 1) {
            const spdu = self.readSpduOrNull() catch |e| return e;
            const s = spdu orelse continue;
            const body = try self.unwrap(s);
            const pdu = try mms.decode(body);
            switch (pdu) {
                .unconfirmed => |u| try self.dispatchUnconfirmed(u),
                .confirmed_response => |r| {
                    if (r.invoke_id != invoke_id) continue;
                    if (r.service != service) return error.UnsupportedService;
                    return r.body;
                },
                .confirmed_error => |e| {
                    if (e.invoke_id != invoke_id) continue;
                    return error.ServiceFailed;
                },
                .reject => return error.Rejected,
                else => continue,
            }
        }
        return error.NoResponse;
    }

    fn dispatchUnconfirmed(self: *Client, u: mms.UnconfirmedPdu) Error!void {
        if (u.service != .information_report) return;
        // A `CommandTermination` and an ordinary report arrive on the same
        // channel and are not distinguishable by the service tag: the control
        // one names the control object (or `LastApplError`) rather than a
        // report control block. Classify first, or a termination is decoded as
        // a report and its `Oper` structure read as a sequence number.
        if (mms.decodeInformationReport(u.body)) |info| {
            if (control.classify(info) catch null) |n| {
                self.notifications_received += 1;
                self.last_notification = n;
                if (self.control_handler) |ch| ch.on_notification(ch.ctx, n);
                return;
            }
        } else |_| {}
        self.reports_received += 1;
        const h = self.handler orelse return;
        const r = report.decodeInformationReport(u.body) catch return;
        h.on_report(h.ctx, r);
    }

    /// Strips session + presentation and checks the context id.
    fn unwrap(self: *Client, spdu: []const u8) Error![]const u8 {
        const ppdu = try session.decodeDataTransfer(spdu);
        const pdv = try presentation.decodeUserData(ppdu, &self.contexts);
        if (pdv.context_id != self.mms_context) return error.UndefinedContext;
        return pdv.value;
    }

    fn writeTpkt(self: *Client, payload: []const u8) Error!void {
        if (payload.len + tpkt.header_len > self.tx.len) return error.BufferTooSmall;
        const frame = try tpkt.encode(payload, self.tx);
        try self.link.write(frame);
    }

    fn readTpkt(self: *Client) Error![]const u8 {
        var rounds: u32 = 0;
        while (rounds < self.config.max_read_rounds) : (rounds += 1) {
            const n = try self.link.read(self.rx);
            if (n == 0) continue;
            return (try tpkt.decode(self.rx[0..n])).payload;
        }
        return error.NoResponse;
    }

    /// Reads TPKTs until a complete session PDU is reassembled.
    fn readSpdu(self: *Client) Error![]const u8 {
        var rounds: u32 = 0;
        while (rounds < self.config.max_read_rounds) : (rounds += 1) {
            const n = try self.link.read(self.rx);
            if (n == 0) continue;
            if (try self.pushTpkt(self.rx[0..n])) |s| return s;
        }
        return error.NoResponse;
    }

    fn readSpduOrNull(self: *Client) Error!?[]const u8 {
        const n = try self.link.read(self.rx);
        if (n == 0) return null;
        return self.pushTpkt(self.rx[0..n]);
    }

    /// Feeds one TPKT into COTP reassembly. Returns the session PDU when the
    /// EOT segment arrives.
    fn pushTpkt(self: *Client, frame: []const u8) Error!?[]const u8 {
        const pkt = try tpkt.decode(frame);
        const dt = switch (try cotp.decode(pkt.payload)) {
            .dt => |d| d,
            .dr => return error.NotConnected,
            else => return error.TransportRefused,
        };
        var r = cotp.Reassembler.init(self.reasm);
        // Reassembly state lives across calls only when a segment is pending;
        // keep it in the client so a segmented reply survives several reads.
        r.len = self.reasm_len;
        const done = try r.push(dt);
        self.reasm_len = r.len;
        return done;
    }
};

/// `LD/LN$FC$RCB` + `$Attr` → the ACSI reference of one RCB attribute.
fn attribute(rcb_reference: []const u8, attr: []const u8, out: []u8) Error![]const u8 {
    if (rcb_reference.len + 1 + attr.len > out.len) return error.BufferTooSmall;
    @memcpy(out[0..rcb_reference.len], rcb_reference);
    out[rcb_reference.len] = '.';
    @memcpy(out[rcb_reference.len + 1 ..][0..attr.len], attr);
    return out[0 .. rcb_reference.len + 1 + attr.len];
}

/// `proposedParameterCBB` — the MMS parameter options an IEC 61850 client
/// needs: str1, str2, vnam, valt, vadr, vsca. These are the octets the
/// reference client sends.
pub const default_parameter_cbb = [_]u8{ 0x05, 0xF1, 0x00 };

/// `servicesSupportedCalling` — the services this client implements. Taken from
/// the reference client's own bit string, which advertises the same set.
pub const default_services_supported = [_]u8{ 0x03, 0xEE, 0x1C, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x79, 0xEF, 0x18 };

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "the parameter CBB and services-supported bit strings parse" {
    const cbb = try ber.BitString.parse(&default_parameter_cbb);
    try testing.expectEqual(@as(usize, 11), cbb.bitCount());
    const svc = try ber.BitString.parse(&default_services_supported);
    try testing.expectEqual(@as(usize, 85), svc.bitCount());
    // The services this client actually implements must be advertised.
    try testing.expect(svc.bit(mms.Initiate.service_bit.get_name_list));
    try testing.expect(svc.bit(mms.Initiate.service_bit.identify));
    try testing.expect(svc.bit(mms.Initiate.service_bit.read));
    try testing.expect(svc.bit(mms.Initiate.service_bit.write));
    try testing.expect(svc.bit(mms.Initiate.service_bit.get_variable_access_attributes));
    try testing.expect(svc.bit(mms.Initiate.service_bit.information_report));
}

test "an RCB attribute reference is built by appending" {
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "simpleIOGenericIO/LLN0.EventsRCB01.RptEna",
        try attribute("simpleIOGenericIO/LLN0.EventsRCB01", "RptEna", &buf),
    );
    var small: [4]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, attribute("LD/LN.RCB", "RptEna", &small));
}

test "init refuses a buffer that cannot hold an exchange" {
    var lt: transport.LoopTransport = .{};
    var tiny: [16]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, Client.init(lt.transport(), &tiny, .{}));
    var ok: [4096]u8 = undefined;
    const c = try Client.init(lt.transport(), &ok, .{});
    try testing.expect(!c.isConnected());
}

test "the connect request this client emits is the shape a real IED expects" {
    var lt: transport.LoopTransport = .{};
    var buf: [8192]u8 = undefined;
    var c = try Client.init(lt.transport(), &buf, .{});
    // Nothing is delivered, so connect fails after the CR — but the CR is on
    // the wire and can be checked.
    try testing.expectError(error.NoResponse, c.connect());
    const sent = lt.sent();
    const pkt = try tpkt.decode(sent);
    const cr = (try cotp.decode(pkt.payload)).cr;
    try testing.expectEqual(cotp.TpduSize.b8192, cr.tpdu_size.?);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 }, cr.called_tsap.?);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 }, cr.calling_tsap.?);
    // Byte-for-byte the connect request the reference client sends.
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xC0, 0x01, 0x0D, 0xC2, 0x02, 0x00, 0x01, 0xC1, 0x02, 0x00, 0x01 },
        sent[0..22],
    );
}

test "a service on a disconnected client is a typed error" {
    var lt: transport.LoopTransport = .{};
    var buf: [8192]u8 = undefined;
    var c = try Client.init(lt.transport(), &buf, .{});
    try testing.expectError(error.NotConnected, c.readObject("LD/GGIO1.Ind1.stVal", .ST));
    try testing.expectError(error.NotConnected, c.poll());
}

test "invoke ids advance and never reach the reserved zero" {
    var lt: transport.LoopTransport = .{};
    var buf: [8192]u8 = undefined;
    var c = try Client.init(lt.transport(), &buf, .{});
    c.next_invoke_id = std.math.maxInt(u32);
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), c.takeInvokeId());
    try testing.expectEqual(@as(u32, 1), c.takeInvokeId());
    try testing.expectEqual(@as(u32, 2), c.takeInvokeId());
}
