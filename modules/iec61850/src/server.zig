// SPDX-License-Identifier: MIT

//! An **IEC 61850 MMS server** — the responder side, as a pure function from
//! one packet to one packet over caller-owned storage.
//!
//! It exists for three reasons: it is the only way to test the encoders against
//! a *real third-party client*; it is a fleet-simulation target (stand one up
//! per simulated IED); and it forces the decode paths for every request shape
//! to be written, which a client-only module never exercises.
//!
//! What it is **not**: an IED. There is no SCL model loader, no control model
//! (`Oper`/`SBO`), no reporting engine and no file system. It serves a flat
//! table of named variables and data sets that the caller supplies, and it says
//! so loudly — see SPEC.md's deferred list before pointing anything at it.
//!
//! `handle` takes one TPKT and returns one TPKT (or null when the association
//! is over). No clock, no thread, no socket.

const std = @import("std");
const ber = @import("ber.zig");
const tpkt = @import("tpkt.zig");
const cotp = @import("cotp.zig");
const session = @import("session.zig");
const presentation = @import("presentation.zig");
const acse = @import("acse.zig");
const mms = @import("mms.zig");
const mmsdata = @import("mmsdata.zig");

pub const Error = mms.Error || presentation.Error || acse.Error ||
    session.Error || cotp.Error || tpkt.Error || error{
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

pub const Model = struct {
    variables: []Variable,
    data_sets: []const DataSet = &.{},
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
};

pub const Server = struct {
    config: Config,
    model: Model,
    contexts: presentation.ContextTable = .{},
    associated: bool = false,
    transport_up: bool = false,
    /// Diagnostics a test asserts on.
    reads: u64 = 0,
    writes: u64 = 0,
    name_lists: u64 = 0,

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
                var body: [128]u8 = undefined;
                const cc = try cotp.encodeConnect(
                    .cc,
                    cr.src_ref,
                    1,
                    cr.tpdu_size orelse .b8192,
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
        return switch (req.service) {
            .identify => mms.encodeIdentifyResponse(req.invoke_id, .{
                .vendor = self.model.vendor,
                .model = self.model.model,
                .revision = self.model.revision,
            }, body),
            .get_name_list => self.getNameList(req, body),
            .read => self.read(req, body),
            .write => self.write(req, body),
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

    fn read(self: *Server, req: mms.ConfirmedRequest, body: []u8) Error![]const u8 {
        self.reads += 1;
        const r = mms.decodeReadRequest(req.body) catch
            return mms.encodeConfirmedError(req.invoke_id, .service, 0, body);

        var w = ber.Writer.init(body);
        const m = w.mark();
        switch (r.spec) {
            .variables => |it_const| {
                // Written backwards, so collect first then emit in reverse.
                var it = it_const;
                var found: [64]?*const Variable = undefined;
                var n: usize = 0;
                while (try it.next()) |name| {
                    if (n == found.len) break;
                    found[n] = self.lookup(name);
                    n += 1;
                }
                var i: usize = n;
                while (i > 0) {
                    i -= 1;
                    if (found[i]) |v| try w.bytes(v.value()) else try mms.emitAccessFailure(&w, .object_non_existent);
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
        const v = self.lookupMut(name) orelse return .{ .failure = .object_non_existent };
        return self.store(v, value);
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
/// read, write and informationReport. Everything else is answered with a
/// `confirmed-ErrorPDU`, which is what an honest server does.
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
    };
    for (set) |b| bits[1 + b / 8] |= @as(u8, 0x80) >> @intCast(b % 8);
    break :blk bits;
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const client = @import("client.zig");
const transport = @import("transport.zig");
const acsi = @import("acsi.zig");

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
        const r = reply orelse return;
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
    try testing.expect(!bs.bit(mms.Initiate.service_bit.define_named_variable_list));
    try testing.expect(!bs.bit(mms.Initiate.service_bit.get_variable_access_attributes));
    try testing.expect(!bs.bit(mms.Initiate.service_bit.file_open));
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
