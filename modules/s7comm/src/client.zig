// SPDX-License-Identifier: MIT

//! An S7 client over the `Transport` seam: COTP connect, `Setup
//! communication`, typed reads and writes, `Read SZL`, and — behind
//! deliberately explicit names — the PLC control services.
//!
//! Two properties shape the whole API:
//!
//! * **Nothing is allocated.** The caller supplies one buffer, split in two:
//!   a transmit half a request is built into, and a receive half packets are
//!   reassembled in. A reply's slices point into the receive half and are
//!   invalidated by the next call — copy what you need. The buffer must be at
//!   least `2 * (frame_overhead + requested_pdu_length)`.
//! * **The negotiated PDU length is enforced, not assumed.** After `connect`,
//!   `pduLength()` is what the PLC agreed to, which is often smaller than what
//!   was asked for. `readBytes`/`writeBytes` split transfers to fit it; the
//!   single-item entry points refuse a transfer that would not fit rather than
//!   emitting a PDU the peer will drop.

const std = @import("std");
const tpkt = @import("tpkt.zig");
const cotp = @import("cotp.zig");
const s7 = @import("s7.zig");
const items = @import("items.zig");
const vars = @import("vars.zig");
const userdata = @import("userdata.zig");
const address = @import("address.zig");
const transport = @import("transport.zig");

pub const Error = error{
    /// A call that needs a live connection was made before `connect`.
    NotConnected,
    /// The peer replied with a ROSCTR or function that does not answer the
    /// request that was sent.
    UnexpectedReply,
    /// The peer echoed a different PDU reference.
    PduReferenceMismatch,
    /// The peer's Ack-Data header reported an error class/code.
    PlcError,
    /// A per-item return code was not `success`.
    ItemError,
    /// The COTP connection request was refused (DR/ER instead of CC).
    ConnectionRefused,
    /// The transfer does not fit the negotiated PDU length.
    PduTooSmall,
    /// The caller's buffer is too small.
    BufferTooSmall,
    /// The peer replied with fewer octets than were asked for.
    ShortReply,
    /// The peer's reply carried a different item count than was requested.
    ItemCountMismatch,
    /// More items than a single request may carry.
    TooManyItems,
} || transport.TransportError || tpkt.Error || cotp.Error || s7.Error ||
    items.Error || vars.Error || userdata.Error || address.Error;

/// Octets of framing in front of every S7 PDU: TPKT (4) + COTP DT (3).
pub const frame_overhead: usize = tpkt.header_len + 3;

/// Ceiling on a single multi-item request, so the parameter scratch is a fixed
/// size. Well above what any negotiated PDU allows (480 bytes fits 39).
pub const max_multi_items: usize = 64;

pub const Config = struct {
    /// Our own TSAP. Any value the PLC accepts; the rack/slot form with rack 0
    /// slot 0 is what programming devices use.
    local_tsap: cotp.Tsap = cotp.Tsap.rackSlot(.pg, 0, 0),
    /// The PLC's TSAP — **this is where rack and slot live**.
    /// S7-300/400: `rackSlot(.pg, rack, slot)`, slot 2 for a classic CPU.
    /// S7-1200/1500: rack 0, slot 0 or 1.
    remote_tsap: cotp.Tsap = cotp.Tsap.rackSlot(.pg, 0, 2),
    /// COTP TPDU size to request.
    tpdu_size: cotp.TpduSize = .size_1024,
    /// S7 PDU length to request. The PLC may return less.
    requested_pdu_length: u16 = 480,
    max_amq_calling: u16 = 1,
    max_amq_called: u16 = 1,
    /// Source reference for the COTP connection.
    src_ref: u16 = 1,
};

/// One item's outcome in a multi-item read.
pub const ItemResult = struct {
    return_code: items.ReturnCode,
    payload: []const u8,
};

pub const Client = struct {
    tr: transport.Transport,
    tx: []u8,
    rx: []u8,
    rx_len: usize = 0,
    rx_pos: usize = 0,
    config: Config,
    connected: bool = false,
    negotiated_pdu_length: u16 = 0,
    pdu_ref: u16 = 0,

    /// `buf` must hold two whole packets: `2 * (frame_overhead +
    /// requested_pdu_length)`. It is split into a transmit and a receive half.
    pub fn init(tr: transport.Transport, buf: []u8, config: Config) Error!Client {
        const half = frame_overhead + @as(usize, config.requested_pdu_length);
        if (buf.len < 2 * half) return error.BufferTooSmall;
        return .{ .tr = tr, .tx = buf[0..half], .rx = buf[half..], .config = config };
    }

    /// Buffer size `init` needs for a given requested PDU length.
    pub fn bufferSize(requested_pdu_length: u16) usize {
        return 2 * (frame_overhead + @as(usize, requested_pdu_length));
    }

    /// The PDU length the PLC agreed to. Zero before `connect`.
    pub fn pduLength(self: *const Client) u16 {
        return self.negotiated_pdu_length;
    }

    /// Largest payload a single read can return under the negotiated PDU.
    pub fn maxReadBytes(self: *const Client) usize {
        return vars.maxReadPayload(self.negotiated_pdu_length);
    }

    /// Largest payload a single write can carry under the negotiated PDU.
    pub fn maxWriteBytes(self: *const Client) usize {
        return vars.maxWritePayload(self.negotiated_pdu_length);
    }

    // ── connection ─────────────────────────────────────────────────────────

    /// COTP connect followed by `Setup communication`. On return
    /// `pduLength()` is authoritative.
    pub fn connect(self: *Client) Error!void {
        try self.cotpConnect();
        try self.setup();
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

        const reply = try self.readPacket();
        switch (try cotp.decode(reply)) {
            .cc => {},
            .dr, .dc, .er => return error.ConnectionRefused,
            else => return error.UnexpectedReply,
        }
    }

    fn setup(self: *Client) Error!void {
        var params: [s7.Setup.wire_len]u8 = undefined;
        _ = try (s7.Setup{
            .max_amq_calling = self.config.max_amq_calling,
            .max_amq_called = self.config.max_amq_called,
            .pdu_length = self.config.requested_pdu_length,
        }).encode(&params);

        const pdu = try self.exchange(.job, &params, &.{});
        if (pdu.header.rosctr != .ack_data) return error.UnexpectedReply;
        const agreed = try s7.Setup.decode(pdu.parameters);
        // A PLC must not raise the ceiling; clamp rather than trust it,
        // because every buffer downstream is sized from this number.
        self.negotiated_pdu_length = @min(agreed.pdu_length, self.config.requested_pdu_length);
    }

    /// Sends a COTP disconnect request. Best effort: most PLCs simply see the
    /// TCP close.
    pub fn disconnect(self: *Client) void {
        defer self.connected = false;
        var body: [16]u8 = undefined;
        const dr = cotp.encodeDisconnect(
            .{ .dst_ref = 0, .src_ref = self.config.src_ref, .reason = 0 },
            &body,
        ) catch return;
        const frame = tpkt.encode(dr, self.tx) catch return;
        self.tr.write(frame) catch {};
    }

    // ── framing ────────────────────────────────────────────────────────────

    /// Reassembles one whole TPKT in the receive half and returns its payload.
    /// Surplus octets from an over-eager transport are kept for the next call,
    /// which is what makes a transport that delivers several packets in one
    /// read safe.
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

    /// Builds `TPKT | COTP DT | S7`, writes it, reads the reply and decodes it.
    fn exchange(self: *Client, rosctr: s7.Rosctr, params: []const u8, data_parts: []const []const u8) Error!s7.Pdu {
        var data_len: usize = 0;
        for (data_parts) |p| data_len += p.len;
        const hl = rosctr.headerLen();
        const pdu_len = hl + params.len + data_len;
        if (self.negotiated_pdu_length != 0 and pdu_len > self.negotiated_pdu_length) {
            return error.PduTooSmall;
        }
        const total = frame_overhead + pdu_len;
        if (total > self.tx.len) return error.BufferTooSmall;

        self.pdu_ref +%= 1;
        const th = try tpkt.header(total - tpkt.header_len);
        const dh = cotp.dataHeader(0, true);
        @memcpy(self.tx[0..tpkt.header_len], &th);
        @memcpy(self.tx[tpkt.header_len..][0..3], &dh);
        const body = self.tx[frame_overhead..];
        body[0] = s7.protocol_id;
        body[1] = @intFromEnum(rosctr);
        body[2] = 0;
        body[3] = 0;
        body[4] = @intCast(self.pdu_ref >> 8);
        body[5] = @intCast(self.pdu_ref & 0xFF);
        body[6] = @intCast(params.len >> 8);
        body[7] = @intCast(params.len & 0xFF);
        body[8] = @intCast(data_len >> 8);
        body[9] = @intCast(data_len & 0xFF);
        if (rosctr.hasErrorField()) {
            body[10] = 0;
            body[11] = 0;
        }
        @memcpy(body[hl..][0..params.len], params);
        var pos = hl + params.len;
        for (data_parts) |p| {
            @memcpy(body[pos..][0..p.len], p);
            pos += p.len;
        }
        try self.tr.write(self.tx[0..total]);

        const payload = try self.readPacket();
        const dt = switch (try cotp.decode(payload)) {
            .dt => |d| d,
            .dr, .dc => return error.EndOfStream,
            else => return error.UnexpectedReply,
        };
        const pdu = try s7.decode(dt.payload);
        if (pdu.header.pdu_reference != self.pdu_ref) return error.PduReferenceMismatch;
        if (pdu.header.isError()) return error.PlcError;
        return pdu;
    }

    // ── Read Var ───────────────────────────────────────────────────────────

    /// Reads exactly one item into `out`, which must hold the item's transfer
    /// size.
    pub fn readItem(self: *Client, item: items.Item, out: []u8) Error![]u8 {
        if (!self.connected) return error.NotConnected;
        const want = item.payloadBytes() orelse return error.LengthTransportMismatch;
        if (out.len < want) return error.BufferTooSmall;
        if (want > self.maxReadBytes()) return error.PduTooSmall;

        var params: [2 + items.item_len]u8 = undefined;
        const p = try vars.encodeRequest(.read_var, &[_]items.Item{item}, &params);
        const pdu = try self.exchange(.job, p, &.{});
        if (pdu.header.rosctr != .ack_data) return error.UnexpectedReply;
        const reply = try vars.decodeReply(pdu.parameters);
        if (reply.function != .read_var) return error.UnexpectedReply;
        if (reply.count != 1) return error.ItemCountMismatch;

        var it = items.DataItemIterator.init(pdu.data, 1);
        const di = (try it.next()) orelse return error.ShortReply;
        if (!di.return_code.isSuccess()) return error.ItemError;
        if (di.payload.len < want) return error.ShortReply;
        @memcpy(out[0..want], di.payload[0..want]);
        return out[0..want];
    }

    /// Reads `out.len` octets from an area, splitting the transfer over as
    /// many PDUs as the negotiated size needs.
    pub fn readBytes(self: *Client, area: items.Area, db_number: u16, start: u32, out: []u8) Error![]u8 {
        if (!self.connected) return error.NotConnected;
        const chunk = self.maxReadBytes();
        if (chunk == 0) return error.PduTooSmall;
        var done: usize = 0;
        while (done < out.len) {
            const n = @min(chunk, out.len - done);
            const item = try items.Item.at(area, db_number, start + done, 0, .byte, @intCast(n));
            _ = try self.readItem(item, out[done..][0..n]);
            done += n;
        }
        return out;
    }

    /// Reads by STEP 7 notation: `readAddress("DB1.DBW20", 2, &buf)` reads two
    /// words starting at DB1.DBW20.
    pub fn readAddress(self: *Client, text: []const u8, count: u16, out: []u8) Error![]u8 {
        return self.readItem(try address.parseItem(text, count), out);
    }

    /// Reads several items in one PDU. `out` receives the concatenated
    /// payloads and `results` one entry per item, each pointing into `out`.
    ///
    /// A failed item is **not** an error here: partial success is exactly the
    /// answer a multi-item read exists to give, so the per-item return code is
    /// reported and the caller decides.
    pub fn readMulti(
        self: *Client,
        list: []const items.Item,
        out: []u8,
        results: []ItemResult,
    ) Error![]ItemResult {
        if (!self.connected) return error.NotConnected;
        if (list.len == 0 or list.len > results.len) return error.ItemCountMismatch;
        if (list.len > max_multi_items) return error.TooManyItems;
        if (list.len > vars.maxRequestItems(self.negotiated_pdu_length)) return error.PduTooSmall;

        var params: [2 + items.item_len * max_multi_items]u8 = undefined;
        const p = try vars.encodeRequest(.read_var, list, &params);
        const pdu = try self.exchange(.job, p, &.{});
        if (pdu.header.rosctr != .ack_data) return error.UnexpectedReply;
        const reply = try vars.decodeReply(pdu.parameters);
        if (reply.function != .read_var) return error.UnexpectedReply;
        if (reply.count != list.len) return error.ItemCountMismatch;

        var it = items.DataItemIterator.init(pdu.data, reply.count);
        var pos: usize = 0;
        var i: usize = 0;
        while (i < list.len) : (i += 1) {
            const di = (try it.next()) orelse return error.ShortReply;
            if (!di.return_code.isSuccess()) {
                results[i] = .{ .return_code = di.return_code, .payload = &.{} };
                continue;
            }
            if (pos + di.payload.len > out.len) return error.BufferTooSmall;
            @memcpy(out[pos..][0..di.payload.len], di.payload);
            results[i] = .{ .return_code = di.return_code, .payload = out[pos..][0..di.payload.len] };
            pos += di.payload.len;
        }
        return results[0..list.len];
    }

    // ── Write Var ──────────────────────────────────────────────────────────

    /// Writes exactly one item. `payload` is sent as-is; no endianness
    /// conversion happens anywhere in this module.
    pub fn writeItem(self: *Client, item: items.Item, payload: []const u8) Error!void {
        if (!self.connected) return error.NotConnected;
        if (payload.len > self.maxWriteBytes()) return error.PduTooSmall;

        var params: [2 + items.item_len]u8 = undefined;
        const p = try vars.encodeRequest(.write_var, &[_]items.Item{item}, &params);
        const ts = dataTransportFor(item.transport_size);
        // The data-item header is built here and the payload is passed through
        // untouched, so a large write never needs a second copy.
        var head: [4]u8 = undefined;
        // In a request this octet is reserved and zero; `0xFF` belongs only in
        // a reply.
        head[0] = @intFromEnum(items.ReturnCode.reserved);
        head[1] = @intFromEnum(ts);
        const raw: u16 = if (ts == .bit)
            // A bit transfer's length counts bits, and one bit is 1 — not 8.
            item.count
        else
            try items.encodeLength(ts, payload.len);
        head[2] = @intCast(raw >> 8);
        head[3] = @intCast(raw & 0xFF);

        const pdu = try self.exchange(.job, p, &.{ &head, payload });
        try expectWriteAck(pdu, 1);
    }

    /// Writes `payload` to an area, splitting over as many PDUs as needed.
    pub fn writeBytes(self: *Client, area: items.Area, db_number: u16, start: u32, payload: []const u8) Error!void {
        if (!self.connected) return error.NotConnected;
        const chunk = self.maxWriteBytes();
        if (chunk == 0) return error.PduTooSmall;
        var done: usize = 0;
        while (done < payload.len) {
            const n = @min(chunk, payload.len - done);
            const item = try items.Item.at(area, db_number, start + done, 0, .byte, @intCast(n));
            try self.writeItem(item, payload[done..][0..n]);
            done += n;
        }
    }

    /// Writes by STEP 7 notation.
    pub fn writeAddress(self: *Client, text: []const u8, count: u16, payload: []const u8) Error!void {
        return self.writeItem(try address.parseItem(text, count), payload);
    }

    /// Writes a single bit, e.g. `writeBit(.flags, 0, 10, 2, true)` for `M10.2`.
    pub fn writeBit(self: *Client, area: items.Area, db_number: u16, byte_offset: u32, bit: u3, value: bool) Error!void {
        const item = try items.Item.at(area, db_number, byte_offset, bit, .bit, 1);
        return self.writeItem(item, &[_]u8{@intFromBool(value)});
    }

    /// Writes several items in one PDU. `scratch` holds the assembled data
    /// block (payload octets plus four per item plus padding).
    pub fn writeMulti(
        self: *Client,
        list: []const items.Item,
        payloads: []const []const u8,
        scratch: []u8,
    ) Error!void {
        if (!self.connected) return error.NotConnected;
        if (list.len == 0 or list.len != payloads.len) return error.ItemCountMismatch;
        if (list.len > max_multi_items) return error.TooManyItems;
        if (list.len > vars.maxRequestItems(self.negotiated_pdu_length)) return error.PduTooSmall;

        var params: [2 + items.item_len * max_multi_items]u8 = undefined;
        const p = try vars.encodeRequest(.write_var, list, &params);
        var w = items.DataBlockWriter{ .out = scratch };
        for (list, payloads) |item, payload| {
            const ts = dataTransportFor(item.transport_size);
            try w.addRequest(ts, payload);
        }
        const pdu = try self.exchange(.job, p, &.{w.written()});
        try expectWriteAck(pdu, @intCast(list.len));
    }

    fn expectWriteAck(pdu: s7.Pdu, count: u8) Error!void {
        if (pdu.header.rosctr != .ack_data) return error.UnexpectedReply;
        const reply = try vars.decodeReply(pdu.parameters);
        if (reply.function != .write_var) return error.UnexpectedReply;
        if (reply.count != count) return error.ItemCountMismatch;
        // A Write Var reply's data block is one bare return code per item.
        if (pdu.data.len < count) return error.ShortReply;
        for (pdu.data[0..count]) |rc| {
            if (@as(items.ReturnCode, @enumFromInt(rc)) != .success) return error.ItemError;
        }
    }

    // ── Userdata ───────────────────────────────────────────────────────────

    /// Result of a `Read SZL`.
    pub const Szl = struct {
        response: userdata.SzlResponse,
        /// True when the CPU said more PDUs follow. Only the first is
        /// returned — see SPEC.md, "Deferred".
        partial: bool,
    };

    /// Reads one system status list. The response is decoded out of the
    /// client's receive buffer, so it is invalidated by the next call.
    pub fn readSzl(self: *Client, id: u16, index: u16) Error!Szl {
        if (!self.connected) return error.NotConnected;
        var params: [userdata.Param.request_len]u8 = undefined;
        _ = try (userdata.Param{
            .message_type = .request,
            .function_group = .cpu_functions,
            .subfunction = @intFromEnum(userdata.CpuSubfunction.read_szl),
            .sequence = 0,
        }).encodeRequest(&params);
        var req: [8]u8 = undefined;
        const payload = try (userdata.SzlRequest{ .id = id, .index = index }).encode(&req);
        var data: [16]u8 = undefined;
        const block = try userdata.DataBlock.encode(.success, .octet_string, payload, &data);

        const pdu = try self.exchange(.userdata, &params, &[_][]const u8{block});
        if (pdu.header.rosctr != .userdata) return error.UnexpectedReply;
        const rp = try userdata.Param.decode(pdu.parameters);
        if (!rp.isResponse()) return error.UnexpectedReply;
        if (rp.error_code != 0) return error.PlcError;
        const db = try userdata.DataBlock.decode(pdu.data);
        if (!db.return_code.isSuccess()) return error.ItemError;
        return .{
            .response = try userdata.SzlResponse.decode(db.payload),
            .partial = rp.last_data_unit == .more_follows,
        };
    }

    /// The CPU's run/stop state, from SZL `0x0424`.
    pub fn cpuStatus(self: *Client) Error!userdata.CpuStatus {
        const r = try self.readSzl(userdata.SzlId.cpu_status, 0);
        return userdata.cpuStatusFrom(r.response) orelse error.ShortReply;
    }

    // ── PLC control — DANGEROUS ────────────────────────────────────────────
    //
    // These stop or restart a running machine. S7comm has no authentication:
    // anyone who can reach TCP/102 can call them and the PLC complies. They
    // are here because a fleet simulator and a diagnostic tool both need them,
    // and because pretending they do not exist does not make a plant safer.
    // Nothing in this module calls them implicitly. See SPEC.md, "Threat
    // model".

    const p_program = "P_PROGRAM";

    /// **Stops the CPU.** Outputs go to their configured safe state and the
    /// process stops. Never point this at equipment you do not own.
    pub fn plcStop(self: *Client) Error!void {
        if (!self.connected) return error.NotConnected;
        var params: [16]u8 = undefined;
        params[0] = @intFromEnum(s7.Function.plc_stop);
        @memset(params[1..6], 0);
        params[6] = p_program.len;
        @memcpy(params[7..][0..p_program.len], p_program);
        const pdu = try self.exchange(.job, params[0 .. 7 + p_program.len], &.{});
        try expectControlAck(pdu, @intFromEnum(s7.Function.plc_stop));
    }

    /// **Warm restart.** The CPU resumes; retentive data is preserved.
    pub fn plcHotStart(self: *Client) Error!void {
        return self.piService(&.{});
    }

    /// **Cold restart.** Retentive data is cleared — destructive to process
    /// state, not just to availability.
    pub fn plcColdStart(self: *Client) Error!void {
        return self.piService("C ");
    }

    fn piService(self: *Client, argument: []const u8) Error!void {
        if (!self.connected) return error.NotConnected;
        var params: [32]u8 = undefined;
        params[0] = @intFromEnum(s7.Function.pi_service);
        @memset(params[1..7], 0);
        params[7] = 0xFD;
        params[8] = @intCast(argument.len >> 8);
        params[9] = @intCast(argument.len & 0xFF);
        @memcpy(params[10..][0..argument.len], argument);
        var pos: usize = 10 + argument.len;
        params[pos] = p_program.len;
        pos += 1;
        @memcpy(params[pos..][0..p_program.len], p_program);
        pos += p_program.len;
        const pdu = try self.exchange(.job, params[0..pos], &.{});
        try expectControlAck(pdu, @intFromEnum(s7.Function.pi_service));
    }

    fn expectControlAck(pdu: s7.Pdu, function: u8) Error!void {
        if (pdu.header.rosctr != .ack_data) return error.UnexpectedReply;
        if (pdu.parameters.len < 1 or pdu.parameters[0] != function) return error.UnexpectedReply;
    }
};

/// Maps a request-item transport size onto the data-block transport size its
/// values travel under. Everything that is not a bit, a real or a
/// counter/timer goes as `byte_word_dword` — which is what the reference stack
/// emits for bytes, words *and* double words alike.
pub fn dataTransportFor(ts: items.TransportSize) items.DataTransportSize {
    return switch (ts) {
        .bit => .bit,
        .real => .real,
        .counter, .timer => .octet_string,
        else => .byte_word_dword,
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A scripted peer: hands the client canned replies and records what it sent.
const Scripted = struct {
    lt: transport.LoopTransport = .{},

    fn deliverHex(self: *Scripted, hex: []const u8) !void {
        var buf: [2048]u8 = undefined;
        self.lt.deliver(try std.fmt.hexToBytes(&buf, hex));
    }

    fn expectSentHex(self: *Scripted, hex: []const u8) !void {
        var buf: [2048]u8 = undefined;
        const want = try std.fmt.hexToBytes(&buf, hex);
        try testing.expectEqualSlices(u8, want, self.lt.sent());
        self.lt.clearSent();
    }
};

// The CC and Setup-Ack a real CPU sent, with the PDU reference adjusted to the
// one this client emits (1 for the Setup).
const cc_frame = "0300001611d00001000100c0010ac1020100c2020101";
const setup_ack_480 = "0300001b02f080320300000001000800000000f0000001000101e0";

fn connectedClient(sc: *Scripted, buf: []u8) !Client {
    try sc.deliverHex(cc_frame);
    try sc.deliverHex(setup_ack_480);
    var c = try Client.init(sc.lt.transport(), buf, .{
        .remote_tsap = cotp.Tsap.rackSlot(.pg, 0, 1),
    });
    try c.connect();
    sc.lt.clearSent();
    return c;
}

test "connect emits the captured CR and Setup and adopts the negotiated PDU" {
    var sc: Scripted = .{};
    var buf: [1024]u8 = undefined;
    try sc.deliverHex(cc_frame);
    try sc.deliverHex(setup_ack_480);
    var c = try Client.init(sc.lt.transport(), &buf, .{
        .remote_tsap = cotp.Tsap.rackSlot(.pg, 0, 1),
    });
    try c.connect();
    try testing.expectEqual(@as(u16, 480), c.pduLength());
    try testing.expectEqual(@as(usize, 462), c.maxReadBytes());
    try testing.expectEqual(@as(usize, 452), c.maxWriteBytes());
    // Byte for byte what the reference client sent, save the PDU reference.
    try sc.expectSentHex(
        "0300001611e00000000100c0010ac1020100c2020101" ++
            "0300001902f08032010000000100080000f0000001000101e0",
    );
}

test "a PLC that lowers the PDU length is believed; one that raises it is clamped" {
    var sc: Scripted = .{};
    var buf: [1024]u8 = undefined;
    try sc.deliverHex(cc_frame);
    try sc.deliverHex("0300001b02f080320300000001000800000000f0000001000100f0");
    var c = try Client.init(sc.lt.transport(), &buf, .{});
    try c.connect();
    try testing.expectEqual(@as(u16, 240), c.pduLength());
    try testing.expectEqual(@as(usize, 222), c.maxReadBytes());

    var sc2: Scripted = .{};
    var buf2: [1024]u8 = undefined;
    try sc2.deliverHex(cc_frame);
    try sc2.deliverHex("0300001b02f080320300000001000800000000f0000001000107e0");
    var c2 = try Client.init(sc2.lt.transport(), &buf2, .{});
    try c2.connect();
    try testing.expectEqual(@as(u16, 480), c2.pduLength());
}

test "reading DB1.DBW20 reproduces the captured request and decodes the reply" {
    var sc: Scripted = .{};
    var buf: [1024]u8 = undefined;
    var c = try connectedClient(&sc, &buf);
    try sc.deliverHex("0300001d02f080320300000002000200080000" ++ "0401" ++ "ff04002012345678");
    var out: [4]u8 = undefined;
    const got = try c.readAddress("DB1.DBW20", 2, &out);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34, 0x56, 0x78 }, got);
    try sc.expectSentHex("0300001f" ++ "02f080" ++ "320100000002000e0000" ++
        "0401" ++ "120a100400020001840000a0");
}

test "a per-item error surfaces as ItemError, not as data" {
    var sc: Scripted = .{};
    var buf: [1024]u8 = undefined;
    var c = try connectedClient(&sc, &buf);
    // Captured shape: DB 77 does not exist -> return code 0x0a, no payload.
    try sc.deliverHex("03000019" ++ "02f080" ++ "320300000002000200040000" ++ "0401" ++ "0a000004");
    var out: [4]u8 = undefined;
    try testing.expectError(error.ItemError, c.readAddress("DB77.DBB0", 4, &out));
}

test "an error return code with data behind it is still an error" {
    var sc: Scripted = .{};
    var buf: [1024]u8 = undefined;
    var c = try connectedClient(&sc, &buf);
    // Hostile: return code 0x05 followed by four octets that look like a value.
    try sc.deliverHex("0300001d" ++ "02f080" ++ "320300000002000200080000" ++ "0401" ++
        "0504002012345678");
    var out: [4]u8 = undefined;
    try testing.expectError(error.ItemError, c.readAddress("DB1.DBW20", 2, &out));
}

test "a mismatched PDU reference is refused" {
    var sc: Scripted = .{};
    var buf: [1024]u8 = undefined;
    var c = try connectedClient(&sc, &buf);
    try sc.deliverHex("0300001d" ++ "02f080" ++ "320300009999000200080000" ++ "0401" ++
        "ff04002012345678");
    var out: [4]u8 = undefined;
    try testing.expectError(error.PduReferenceMismatch, c.readAddress("DB1.DBW20", 2, &out));
}

test "a PLC-level error class is surfaced" {
    var sc: Scripted = .{};
    var buf: [1024]u8 = undefined;
    var c = try connectedClient(&sc, &buf);
    // Ack-Data, no parameters, error class 0x85 (error on supplies).
    try sc.deliverHex("03000013" ++ "02f080" ++ "320300000002000000008500");
    var out: [4]u8 = undefined;
    try testing.expectError(error.PlcError, c.readAddress("DB1.DBW20", 2, &out));
}

test "writing DB1.DBB20 reproduces the captured request" {
    var sc: Scripted = .{};
    var buf: [1024]u8 = undefined;
    var c = try connectedClient(&sc, &buf);
    try sc.deliverHex("03000016" ++ "02f080" ++ "320300000002000200010000" ++ "0501" ++ "ff");
    try c.writeAddress("DB1.DBB20", 4, &[_]u8{ 0x12, 0x34, 0x56, 0x78 });
    try sc.expectSentHex("03000027" ++ "02f080" ++ "320100000002000e0008" ++
        "0501" ++ "120a100200040001840000a0" ++ "0004002012345678");
}

test "writing a single bit uses a bit-counted length of 1" {
    var sc: Scripted = .{};
    var buf: [1024]u8 = undefined;
    var c = try connectedClient(&sc, &buf);
    try sc.deliverHex("03000016" ++ "02f080" ++ "320300000002000200010000" ++ "0501" ++ "ff");
    try c.writeBit(.flags, 0, 10, 2, true);
    // Captured: M10.2 -> address 0x52, data block 00 03 0001 01.
    try sc.expectSentHex("03000024" ++ "02f080" ++ "320100000002000e0005" ++
        "0501" ++ "120a10010001000083000052" ++ "0003000101");
}

test "a write whose reply reports a failed item is an error" {
    var sc: Scripted = .{};
    var buf: [1024]u8 = undefined;
    var c = try connectedClient(&sc, &buf);
    try sc.deliverHex("03000016" ++ "02f080" ++ "320300000002000200010000" ++ "0501" ++ "0a");
    try testing.expectError(error.ItemError, c.writeAddress("DB1.DBB20", 4, &[_]u8{ 1, 2, 3, 4 }));
}

test "a transfer larger than the negotiated PDU is split" {
    var sc: Scripted = .{};
    var buf: [1024]u8 = undefined;
    var c = try connectedClient(&sc, &buf);
    var first: [25 + 462]u8 = undefined;
    var second: [25 + 138]u8 = undefined;
    buildReadReply(&first, 2, 462);
    buildReadReply(&second, 3, 138);
    sc.lt.deliver(&first);
    sc.lt.deliver(&second);
    var out: [600]u8 = undefined;
    _ = try c.readBytes(.db, 9, 0, &out);
    // Two requests of 31 octets each; the second asks for 138 octets at bit
    // address 462 * 8 = 3696, exactly as the reference client split it.
    const sent = sc.lt.sent();
    try testing.expectEqual(@as(usize, 62), sent.len);
    try testing.expectEqual(@as(u16, 462), (@as(u16, sent[23]) << 8) | sent[24]);
    try testing.expectEqual(@as(u16, 138), (@as(u16, sent[31 + 23]) << 8) | sent[31 + 24]);
    const addr2 = (@as(u32, sent[31 + 28]) << 16) | (@as(u32, sent[31 + 29]) << 8) | sent[31 + 30];
    try testing.expectEqual(@as(u32, 462 * 8), addr2);
    try testing.expectEqual(@as(u8, 0xAB), out[599]);
}

fn buildReadReply(out: []u8, pdu_ref: u16, payload_len: usize) void {
    const total = 25 + payload_len;
    out[0] = 0x03;
    out[1] = 0x00;
    out[2] = @intCast(total >> 8);
    out[3] = @intCast(total & 0xFF);
    out[4] = 0x02;
    out[5] = 0xF0;
    out[6] = 0x80;
    out[7] = s7.protocol_id;
    out[8] = 0x03;
    out[9] = 0;
    out[10] = 0;
    out[11] = @intCast(pdu_ref >> 8);
    out[12] = @intCast(pdu_ref & 0xFF);
    out[13] = 0;
    out[14] = 2;
    out[15] = @intCast((4 + payload_len) >> 8);
    out[16] = @intCast((4 + payload_len) & 0xFF);
    out[17] = 0;
    out[18] = 0;
    out[19] = 0x04;
    out[20] = 0x01;
    out[21] = 0xFF;
    out[22] = 0x04;
    const bits = payload_len * 8;
    out[23] = @intCast(bits >> 8);
    out[24] = @intCast(bits & 0xFF);
    @memset(out[25..][0..payload_len], 0xAB);
}

test "a multi-item read reports per-item outcomes without failing the call" {
    var sc: Scripted = .{};
    var buf: [1024]u8 = undefined;
    var c = try connectedClient(&sc, &buf);
    // Captured shape: item 1 fails (DB 77), item 2 succeeds with two octets.
    try sc.deliverHex("0300001f" ++ "02f080" ++ "3203000000020002000a0000" ++ "0402" ++
        "0a000004" ++ "ff040010" ++ "0001");
    const list = [_]items.Item{
        try items.Item.at(.db, 77, 0, 0, .byte, 2),
        try items.Item.at(.db, 1, 0, 0, .byte, 2),
    };
    var out: [16]u8 = undefined;
    var results: [2]ItemResult = undefined;
    const got = try c.readMulti(&list, &out, &results);
    try testing.expectEqual(items.ReturnCode.object_does_not_exist, got[0].return_code);
    try testing.expectEqual(@as(usize, 0), got[0].payload.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01 }, got[1].payload);
    // And the request is the captured two-item form.
    try sc.expectSentHex("0300002b" ++ "02f080" ++ "320100000002001a0000" ++ "0402" ++
        "120a10020002004d84000000" ++ "120a10020002000184000000");
}

/// The 28-octet record a real S7-300 CPU returned for SZL 0x0011, index 0
/// (order number "6ES7 315-2EH14-0AB0 ", hardware/firmware version fields).
const szl_0011_record = "0001" ++ "36455337203331352d32454831342d3041423020" ++
    "00c0" ++ "0004" ++ "0001";

test "read SZL round trip against the captured module-identification record" {
    var sc: Scripted = .{};
    var buf: [1024]u8 = undefined;
    var c = try connectedClient(&sc, &buf);
    try sc.deliverHex("03000045" ++ "02f080" ++ "320700000002000c0028" ++
        "000112081284010000000000" ++
        "ff090024" ++ "0011" ++ "0000" ++ "001c" ++ "0001" ++ szl_0011_record);
    const r = try c.readSzl(0x0011, 0);
    try testing.expectEqual(@as(u16, 0x0011), r.response.header.id);
    try testing.expectEqual(@as(u16, 1), r.response.header.record_count);
    try testing.expect(!r.partial);
    try testing.expectEqual(@as(usize, 28), r.response.record(0).?.len);
    try testing.expectEqualSlices(u8, "6ES7 315-2EH14-0AB0 ", r.response.record(0).?[2..22]);
    try sc.expectSentHex("03000021" ++ "02f080" ++ "32070000000200080008" ++
        "0001120411440100" ++ "ff09000400110000");
}

test "a fragmented SZL response is reported as partial" {
    var sc: Scripted = .{};
    var buf: [1024]u8 = undefined;
    var c = try connectedClient(&sc, &buf);
    // Same reply, but `last data unit` = 0x01 (more follows).
    try sc.deliverHex("03000045" ++ "02f080" ++ "320700000002000c0028" ++
        "000112081284010000" ++ "01" ++ "0000" ++
        "ff090024" ++ "0011" ++ "0000" ++ "001c" ++ "0001" ++ szl_0011_record);
    const r = try c.readSzl(0x0011, 0);
    try testing.expect(r.partial);
}

test "calls before connect are refused" {
    var sc: Scripted = .{};
    var buf: [1024]u8 = undefined;
    var c = try Client.init(sc.lt.transport(), &buf, .{});
    var out: [4]u8 = undefined;
    try testing.expectError(error.NotConnected, c.readAddress("DB1.DBW0", 2, &out));
    try testing.expectError(error.NotConnected, c.writeAddress("DB1.DBW0", 2, &out));
    try testing.expectError(error.NotConnected, c.plcStop());
    try testing.expectError(error.NotConnected, c.readSzl(0x0011, 0));
}

test "init refuses a buffer that cannot hold two PDUs" {
    var sc: Scripted = .{};
    var small: [512]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, Client.init(sc.lt.transport(), &small, .{}));
    try testing.expectEqual(@as(usize, 974), Client.bufferSize(480));
}

test "a COTP disconnect instead of a CC is a refused connection" {
    var sc: Scripted = .{};
    var buf: [1024]u8 = undefined;
    try sc.deliverHex("0300000b" ++ "06800000000100");
    var c = try Client.init(sc.lt.transport(), &buf, .{});
    try testing.expectError(error.ConnectionRefused, c.connect());
}

test "the PLC control services emit the captured parameter blocks" {
    var sc: Scripted = .{};
    var buf: [1024]u8 = undefined;
    var c = try connectedClient(&sc, &buf);

    try sc.deliverHex("03000014" ++ "02f080" ++ "320300000002000100000000" ++ "29");
    try c.plcStop();
    try sc.expectSentHex("03000021" ++ "02f080" ++ "32010000000200100000" ++
        "29" ++ "0000000000" ++ "09" ++ "505f50524f4752414d");

    try sc.deliverHex("03000014" ++ "02f080" ++ "320300000003000100000000" ++ "28");
    try c.plcHotStart();
    try sc.expectSentHex("03000025" ++ "02f080" ++ "32010000000300140000" ++
        "28" ++ "000000000000" ++ "fd" ++ "0000" ++ "09" ++ "505f50524f4752414d");

    try sc.deliverHex("03000014" ++ "02f080" ++ "320300000004000100000000" ++ "28");
    try c.plcColdStart();
    try sc.expectSentHex("03000027" ++ "02f080" ++ "32010000000400160000" ++
        "28" ++ "000000000000" ++ "fd" ++ "0002" ++ "4320" ++ "09" ++ "505f50524f4752414d");
}

test "the CPU status comes out of SZL 0x0424" {
    var sc: Scripted = .{};
    var buf: [1024]u8 = undefined;
    var c = try connectedClient(&sc, &buf);
    // The exact 0x0424 reply a real CPU sent while running.
    const record = "5144ff0800000000000000002607230650400004";
    try sc.deliverHex("0300003d" ++ "02f080" ++ "320700000002000c0020" ++
        "000112081284010000000000" ++ "ff09001c" ++ "0424" ++ "0000" ++ "0014" ++ "0001" ++
        record);
    try testing.expectEqual(userdata.CpuStatus.run, try c.cpuStatus());
}
