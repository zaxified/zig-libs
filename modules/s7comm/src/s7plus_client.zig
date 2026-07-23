// SPDX-License-Identifier: MIT

//! An S7CommPlus **client** and **responder** over the shared `Transport` seam.
//!
//! Both ride the same `TPKT | COTP DT | 0x72` framing as the classic client, so
//! the transport layers (`tpkt.zig`, `cotp.zig`, `transport.zig`) are reused
//! unchanged. On top of them this file drives the S7CommPlus session:
//!
//! 1. **Connect** — a COTP `CR`/`CC`, then a `CreateObject` request whose
//!    response carries the session id and (optionally) turns on the integrity
//!    id.
//! 2. **GetVariable / SetVariable** — a read or write against a relative object
//!    id, resolved from a symbolic path (`s7plus_path.zig`) or given directly.
//!    Each request advances the sequence number, and on a V3 session each
//!    carries the running integrity id the responder verifies.
//!
//! ## Codec-only vs driven — stated plainly
//!
//! There was **no S7-1200/1500 and no S7CommPlus-capable Wireshark** available
//! in this environment, so the wire is **not** validated against a real peer.
//! What *is* real: the client and the responder here drive each other over an
//! in-memory transport through the actual value/object/session/integrity codecs
//! — a full round trip, including the anti-replay check. Treat this pair as a
//! self-consistent reference and a **fleet-simulation target**, exactly as the
//! classic `Responder` is described, **not** as a validated S7-1200 driver. The
//! request/response object *shapes* below are a self-derived model; the parts
//! that are third-party-anchored are the value codec and the header, not the
//! choreography. See SPEC.md.

const std = @import("std");
const tpkt = @import("tpkt.zig");
const cotp = @import("cotp.zig");
const transport = @import("transport.zig");
const s7plus = @import("s7plus.zig");
const value = @import("s7plus_value.zig");
const object = @import("s7plus_object.zig");
const path = @import("s7plus_path.zig");

pub const Error = error{
    NotConnected,
    ConnectionRefused,
    UnexpectedReply,
    SequenceMismatch,
    ObjectNotFound,
    BufferTooSmall,
    ShortReply,
    EndOfStream,
} || transport.TransportError || tpkt.Error || cotp.Error || s7plus.Error ||
    object.Error || value.Error || path.Error;

/// TPKT (4) + COTP DT (3) in front of every S7CommPlus frame.
pub const frame_overhead: usize = tpkt.header_len + 3;

/// The relative object id used for the session object (self-derived constant).
pub const session_class_id: u32 = 0x0000_0522;
/// The attribute id under which a connect response returns the session id.
pub const attr_session_id: u32 = 1;

// ── client ──────────────────────────────────────────────────────────────────

pub const Config = struct {
    remote_tsap: cotp.Tsap = cotp.Tsap.rackSlot(.pg, 0, 1),
    local_tsap: cotp.Tsap = cotp.Tsap.rackSlot(.pg, 0, 1),
    src_ref: u16 = 0x0001,
    tpdu_size: cotp.TpduSize = .size_1024,
    /// Ask the responder for a V3 session that enforces the integrity id.
    request_integrity: bool = false,
};

pub const Client = struct {
    tr: transport.Transport,
    tx: []u8,
    rx: []u8,
    rx_len: usize = 0,
    rx_pos: usize = 0,
    connected: bool = false,
    session: object.Session = .{},
    config: Config,

    /// Split one caller buffer into a transmit and a receive half.
    pub fn init(tr: transport.Transport, buf: []u8, config: Config) Client {
        const half = buf.len / 2;
        return .{ .tr = tr, .tx = buf[0..half], .rx = buf[half..], .config = config };
    }

    pub fn sessionId(self: *const Client) u32 {
        return self.session.session_id;
    }

    // ── connect ──────────────────────────────────────────────────────────────

    pub fn connect(self: *Client) Error!void {
        try self.cotpConnect();

        // CreateObject request for the session object.
        var body: [64]u8 = undefined;
        var w: usize = 0;
        const seq = self.session.nextSeq();
        w += (try (object.DataHeader{ .opcode = .request, .function = .create_object, .seqnum = seq }).encode(body[w..])).len;
        w += (try object.beginObject(0, session_class_id, body[w..])).len;
        w += (try object.endObject(body[w..])).len;

        const reply = try self.exchange(.connect, body[0..w], &.{});
        const dh = try object.DataHeader.decode(reply.data);
        if (dh.opcode != .response or dh.function != .create_object) return error.UnexpectedReply;
        if (dh.seqnum != seq) return error.SequenceMismatch;

        // The response object carries the session id as attribute 1 (udint).
        self.session.session_id = try findUdintAttr(reply.data[object.data_header_len..], attr_session_id);
        if (self.config.request_integrity) {
            self.session.integrity_enabled = true;
            self.session.integrity_id = self.session.session_id; // seed from the id
        }
        self.connected = true;
    }

    fn cotpConnect(self: *Client) Error!void {
        var body: [64]u8 = undefined;
        const cr = try cotp.encodeConnect(.{
            .code = .cr,
            .dst_ref = 0,
            .src_ref = self.config.src_ref,
            .src_tsap = self.config.local_tsap,
            .dst_tsap = self.config.remote_tsap,
            .tpdu_size = self.config.tpdu_size,
        }, &body);
        try self.tr.write(try tpkt.encode(cr, self.tx));
        switch (try cotp.decode(try self.readPacket())) {
            .cc => {},
            .dr, .dc, .er => return error.ConnectionRefused,
            else => return error.UnexpectedReply,
        }
    }

    pub fn disconnect(self: *Client) void {
        defer self.connected = false;
        var body: [16]u8 = undefined;
        const dr = cotp.encodeDisconnect(.{ .dst_ref = 0, .src_ref = self.config.src_ref, .reason = 0 }, &body) catch return;
        const frame = tpkt.encode(dr, self.tx) catch return;
        self.tr.write(frame) catch {};
    }

    // ── read / write a variable by object id ─────────────────────────────────

    /// Reads the value of object `object_id`; returns its encoded value bytes
    /// (flags+datatype+body) in `out`. Decode with `s7plus.value.decodeScalar`.
    pub fn getVariable(self: *Client, object_id: u32, out: []u8) Error![]const u8 {
        if (!self.connected) return error.NotConnected;
        var body: [32]u8 = undefined;
        var w: usize = 0;
        const seq = self.session.nextSeq();
        w += (try (object.DataHeader{ .opcode = .request, .function = .get_variable, .seqnum = seq }).encode(body[w..])).len;
        std.mem.writeInt(u32, body[w..][0..4], object_id, .big);
        w += 4;

        const reply = try self.exchangeWithIntegrity(body[0..w]);
        const dh = try object.DataHeader.decode(reply.data);
        if (dh.opcode != .response or dh.function != .get_variable) return error.UnexpectedReply;
        if (dh.seqnum != seq) return error.SequenceMismatch;
        const after = reply.data[object.data_header_len..];
        if (after.len < 1) return error.ShortReply;
        if (after[0] != 0) return error.ObjectNotFound; // per-request return code
        const val = after[1..];
        const vlen = try value.valueLen(val);
        if (out.len < vlen) return error.BufferTooSmall;
        @memcpy(out[0..vlen], val[0..vlen]);
        return out[0..vlen];
    }

    /// Reads and decodes a scalar in one call.
    pub fn getScalar(self: *Client, object_id: u32) Error!value.Scalar {
        var out: [64]u8 = undefined;
        const v = try self.getVariable(object_id, &out);
        return (try value.decodeScalar(v)).value;
    }

    /// Writes `encoded_value` (flags+datatype+body, e.g. from
    /// `s7plus.value.encodeScalar`) to object `object_id`.
    pub fn setVariable(self: *Client, object_id: u32, encoded_value: []const u8) Error!void {
        if (!self.connected) return error.NotConnected;
        var body: [128]u8 = undefined;
        var w: usize = 0;
        const seq = self.session.nextSeq();
        w += (try (object.DataHeader{ .opcode = .request, .function = .set_variable, .seqnum = seq }).encode(body[w..])).len;
        std.mem.writeInt(u32, body[w..][0..4], object_id, .big);
        w += 4;
        if (w + encoded_value.len > body.len) return error.BufferTooSmall;
        @memcpy(body[w..][0..encoded_value.len], encoded_value);
        w += encoded_value.len;

        const reply = try self.exchangeWithIntegrity(body[0..w]);
        const dh = try object.DataHeader.decode(reply.data);
        if (dh.opcode != .response or dh.function != .set_variable) return error.UnexpectedReply;
        if (dh.seqnum != seq) return error.SequenceMismatch;
        const after = reply.data[object.data_header_len..];
        if (after.len < 1) return error.ShortReply;
        if (after[0] != 0) return error.ObjectNotFound;
    }

    /// Resolves a symbolic path to a relative object id (via `roots`) and reads
    /// it. Member/index steps beyond the root are not walked here — a symbolic
    /// object graph deep enough to need them is deferred (see SPEC.md); this
    /// reads the root object itself.
    pub fn getByPath(self: *Client, text: []const u8, roots: []const path.RootBinding, out: []u8) Error![]const u8 {
        var comps: [16]path.Component = undefined;
        const p = try path.parse(text, &comps);
        const r = try path.resolve(p, roots);
        return self.getVariable(r.object_id, out);
    }

    // ── framing ──────────────────────────────────────────────────────────────

    fn exchangeWithIntegrity(self: *Client, data: []const u8) Error!s7plus.Frame {
        if (self.session.integrity_enabled) {
            var ib: [8]u8 = undefined;
            const integ = try (object.Integrity{ .id = self.session.nextIntegrity() }).encode(&ib);
            return self.exchange(.data_fw3, data, integ);
        }
        return self.exchange(.data, data, &.{});
    }

    fn exchange(self: *Client, pt: s7plus.PduType, data: []const u8, integ: []const u8) Error!s7plus.Frame {
        var frame_buf: [512]u8 = undefined;
        const frame = try s7plus.encode(pt, data, integ, &frame_buf);
        // Build TPKT | COTP DT | frame into the transmit half.
        var scratch: [600]u8 = undefined;
        const cotp_dt = try cotp.encodeData(.{ .payload = frame }, &scratch);
        try self.tr.write(try tpkt.encode(cotp_dt, self.tx));

        const payload = try self.readPacket();
        const tp = switch (try cotp.decode(payload)) {
            .dt => |d| d,
            else => return error.UnexpectedReply,
        };
        return s7plus.decode(tp.payload);
    }

    fn readPacket(self: *Client) Error![]const u8 {
        while (true) {
            const avail = self.rx[self.rx_pos..self.rx_len];
            if (avail.len >= tpkt.header_len) {
                const total = try tpkt.peekLength(avail);
                if (total > self.rx.len) return error.BufferTooSmall;
                if (avail.len >= total) {
                    const pkt = try tpkt.decode(avail);
                    self.rx_pos += total;
                    return pkt.payload;
                }
            }
            if (self.rx_pos > 0) {
                const keep = self.rx_len - self.rx_pos;
                std.mem.copyForwards(u8, self.rx[0..keep], self.rx[self.rx_pos..self.rx_len]);
                self.rx_len = keep;
                self.rx_pos = 0;
            }
            if (self.rx_len == self.rx.len) return error.BufferTooSmall;
            const n = try self.tr.read(self.rx[self.rx_len..]);
            if (n == 0) return error.EndOfStream;
            self.rx_len += n;
        }
    }
};

/// Finds attribute `attr_id` in an object stream and returns its `udint` value.
fn findUdintAttr(bytes: []const u8, attr_id: u32) Error!u32 {
    var cur = value.Cursor{ .bytes = bytes };
    if (try cur.byte() != object.elem_start_object) return error.BadObject;
    _ = try cur.take(8);
    while (true) {
        const marker = try cur.byte();
        switch (marker) {
            object.elem_terminating_object => return error.ObjectNotFound,
            object.elem_attribute => {
                const id = try cur.varUint(u32, 5);
                const rest = cur.bytes[cur.pos..];
                const dec = try value.decodeScalar(rest);
                cur.pos += dec.len;
                if (id == attr_id) return @intCast(dec.value.unsigned);
            },
            else => return error.BadObject,
        }
    }
}

// ── responder (fleet-simulation target) ─────────────────────────────────────

/// One variable the responder serves: a relative object id and a caller-owned
/// buffer holding an encoded value. `len` is the current encoded length and is
/// updated on `SetVariable`.
pub const VarBinding = struct {
    object_id: u32,
    storage: []u8,
    len: usize,
};

pub const ResponderConfig = struct {
    /// The session id handed out at connect.
    session_id: u32 = 0x0000_0100,
    /// Whether this simulated CPU enforces the integrity id (a V3 firmware).
    integrity_enabled: bool = false,
};

/// The PLC side: a pure function from one TPKT frame to one TPKT reply over
/// caller-owned variable buffers. Stand up one per simulated S7-1200/1500.
pub const Responder = struct {
    config: ResponderConfig,
    vars: []VarBinding,
    session: object.Session = .{},
    connected: bool = false,

    pub fn init(config: ResponderConfig, vars: []VarBinding) Responder {
        return .{
            .config = config,
            .vars = vars,
            .session = .{ .integrity_enabled = config.integrity_enabled, .integrity_id = config.session_id },
        };
    }

    /// Handles one whole TPKT frame, returning a TPKT reply (or null to close).
    pub fn handle(self: *Responder, frame: []const u8, out: []u8) Error!?[]u8 {
        const pkt = try tpkt.decode(frame);
        switch (try cotp.decode(pkt.payload)) {
            .cr => |cr| return try self.replyCc(cr, out),
            .dr, .dc => {
                self.connected = false;
                return null;
            },
            .dt => |dt| return try self.replyData(dt.payload, out),
            else => return error.UnexpectedReply,
        }
    }

    fn replyCc(self: *Responder, cr: cotp.ConnectTpdu, out: []u8) Error!?[]u8 {
        self.connected = true;
        var body: [64]u8 = undefined;
        const cc = try cotp.encodeConnect(.{
            .code = .cc,
            .dst_ref = cr.src_ref,
            .src_ref = 0x0002,
            .src_tsap = cr.dst_tsap,
            .dst_tsap = cr.src_tsap,
            .tpdu_size = cr.tpdu_size,
        }, &body);
        return try tpkt.encode(cc, out);
    }

    fn replyData(self: *Responder, cotp_payload: []const u8, out: []u8) Error!?[]u8 {
        const req = try s7plus.decode(cotp_payload);

        // Verify the anti-replay integrity progression on a V3 request.
        if (req.pdu_type == .data_fw3) {
            const integ = try object.Integrity.decode(req.integrity);
            try self.session.verifyIntegrity(integ.id);
        }

        const dh = try object.DataHeader.decode(req.data);
        var body: [256]u8 = undefined;
        const resp = switch (dh.function) {
            .create_object => try self.doConnect(dh.seqnum, &body),
            .get_variable => try self.doGet(dh.seqnum, req.data[object.data_header_len..], &body),
            .set_variable => try self.doSet(dh.seqnum, req.data[object.data_header_len..], &body),
            else => return error.UnexpectedReply,
        };

        // The anti-replay guard is on the request direction (a replayed
        // *command* is the threat); replies come back as plain Data (or Connect
        // for the handshake) and are not themselves integrity-stamped.
        var frame_buf: [512]u8 = undefined;
        const reply_pt: s7plus.PduType = if (req.pdu_type == .connect) .connect else .data;
        const frame = try s7plus.encode(reply_pt, resp, &.{}, &frame_buf);

        var scratch: [600]u8 = undefined;
        const cotp_dt = try cotp.encodeData(.{ .payload = frame }, &scratch);
        return try tpkt.encode(cotp_dt, out);
    }

    fn doConnect(self: *Responder, seq: u16, body: []u8) Error![]u8 {
        var w: usize = 0;
        w += (try (object.DataHeader{ .opcode = .response, .function = .create_object, .seqnum = seq }).encode(body[w..])).len;
        w += (try object.beginObject(self.config.session_id, session_class_id, body[w..])).len;
        w += (try object.beginAttribute(attr_session_id, body[w..])).len;
        w += (try value.encodeScalar(.udint, i64, self.config.session_id, body[w..])).len;
        w += (try object.endObject(body[w..])).len;
        return body[0..w];
    }

    fn doGet(self: *Responder, seq: u16, args: []const u8, body: []u8) Error![]u8 {
        if (args.len < 4) return error.ShortReply;
        const object_id = std.mem.readInt(u32, args[0..4], .big);
        var w: usize = 0;
        w += (try (object.DataHeader{ .opcode = .response, .function = .get_variable, .seqnum = seq }).encode(body[w..])).len;
        // A missing object is a per-request return code, not a dropped
        // connection — exactly how a real peer answers.
        const vb = self.find(object_id) orelse {
            body[w] = 0x03; // "address does not exist"
            return body[0 .. w + 1];
        };
        body[w] = 0; // return code: success
        w += 1;
        if (w + vb.len > body.len) return error.BufferTooSmall;
        @memcpy(body[w..][0..vb.len], vb.storage[0..vb.len]);
        w += vb.len;
        return body[0..w];
    }

    fn doSet(self: *Responder, seq: u16, args: []const u8, body: []u8) Error![]u8 {
        if (args.len < 4) return error.ShortReply;
        const object_id = std.mem.readInt(u32, args[0..4], .big);
        var w: usize = 0;
        w += (try (object.DataHeader{ .opcode = .response, .function = .set_variable, .seqnum = seq }).encode(body[w..])).len;
        const vb = self.find(object_id) orelse {
            body[w] = 0x03;
            return body[0 .. w + 1];
        };
        const val = args[4..];
        const vlen = try value.valueLen(val);
        if (vlen > vb.storage.len) return error.BufferTooSmall;
        @memcpy(vb.storage[0..vlen], val[0..vlen]);
        vb.len = vlen;
        body[w] = 0; // return code: success
        return body[0 .. w + 1];
    }

    fn find(self: *Responder, object_id: u32) ?*VarBinding {
        for (self.vars) |*vb| if (vb.object_id == object_id) return vb;
        return null;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Hands each packet the client writes straight to a `Responder` and queues its
/// reply — a full round trip as synchronous code.
const Paired = struct {
    responder: *Responder,
    out: [4096]u8 = undefined,
    queue: [8192]u8 = undefined,
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
        const n = @min(avail, buf.len);
        @memcpy(buf[0..n], self.queue[self.queue_pos..][0..n]);
        self.queue_pos += n;
        return n;
    }
    fn writeFn(ctx: *anyopaque, bytes: []const u8) transport.TransportError!void {
        const self: *Paired = @ptrCast(@alignCast(ctx));
        const reply = self.responder.handle(bytes, &self.out) catch {
            self.failures += 1;
            return;
        };
        const r = reply orelse return;
        if (self.queue_len + r.len > self.queue.len) return error.WriteFailed;
        @memcpy(self.queue[self.queue_len..][0..r.len], r);
        self.queue_len += r.len;
    }
};

test "round trip: connect, set and get a variable over an in-memory wire" {
    var store: [64]u8 = undefined;
    var vars = [_]VarBinding{.{ .object_id = 260, .storage = &store, .len = 0 }};
    var r = Responder.init(.{ .session_id = 0x0abc }, &vars);
    var paired = Paired{ .responder = &r };
    var buf: [2048]u8 = undefined;
    var c = Client.init(paired.seam(), &buf, .{});

    try c.connect();
    try testing.expectEqual(@as(u32, 0x0abc), c.sessionId());

    // Write a udint, read it back.
    var enc: [16]u8 = undefined;
    const v = try value.encodeScalar(.udint, i64, 123456, &enc);
    try c.setVariable(260, v);
    const got = try c.getScalar(260);
    try testing.expectEqual(@as(u64, 123456), got.unsigned);

    // A missing object is a typed error, not a crash.
    var out: [16]u8 = undefined;
    try testing.expectError(error.ObjectNotFound, c.getVariable(999, &out));

    c.disconnect();
    try testing.expectEqual(@as(usize, 0), paired.failures);
}

test "round trip: a V3 session enforces the integrity id end to end" {
    var store: [64]u8 = undefined;
    var vars = [_]VarBinding{.{ .object_id = 7, .storage = &store, .len = 0 }};
    var r = Responder.init(.{ .session_id = 0x50, .integrity_enabled = true }, &vars);
    var paired = Paired{ .responder = &r };
    var buf: [2048]u8 = undefined;
    var c = Client.init(paired.seam(), &buf, .{ .request_integrity = true });

    try c.connect();
    try testing.expect(c.session.integrity_enabled);

    var enc: [16]u8 = undefined;
    const v = try value.encodeScalar(.uint, i64, 0x0102, &enc);
    try c.setVariable(7, v); // integrity id progresses
    const got = try c.getScalar(7); // progresses again
    try testing.expectEqual(@as(u64, 0x0102), got.unsigned);
    try testing.expectEqual(@as(usize, 0), paired.failures);
}

test "responder rejects a replayed integrity id" {
    var store: [64]u8 = undefined;
    var vars = [_]VarBinding{.{ .object_id = 7, .storage = &store, .len = 0 }};
    var r = Responder.init(.{ .session_id = 0x50, .integrity_enabled = true }, &vars);
    r.connected = true;
    r.session.session_id = 0x50;

    // Build a get_variable request with a stale integrity id (below expected).
    var data: [16]u8 = undefined;
    var w: usize = 0;
    w += (try (object.DataHeader{ .opcode = .request, .function = .get_variable, .seqnum = 1 }).encode(data[w..])).len;
    std.mem.writeInt(u32, data[w..][0..4], 7, .big);
    w += 4;
    var ib: [4]u8 = undefined;
    const integ = try (object.Integrity{ .id = 0x50 - 1 }).encode(&ib); // stale
    var frame_buf: [128]u8 = undefined;
    const frame = try s7plus.encode(.data_fw3, data[0..w], integ, &frame_buf);
    var scratch: [128]u8 = undefined;
    const cotp_dt = try cotp.encodeData(.{ .payload = frame }, &scratch);
    var tp: [160]u8 = undefined;
    const tframe = try tpkt.encode(cotp_dt, &tp);

    var out: [256]u8 = undefined;
    try testing.expectError(error.IntegrityReplay, r.handle(tframe, &out));
}
