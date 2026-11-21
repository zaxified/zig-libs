// SPDX-License-Identifier: MIT

//! A minimal S7 **responder**: the PLC side of the conversation, as a pure
//! function from one request packet to one reply packet.
//!
//! Its reason to exist is fleet simulation. A responder that speaks the real
//! wire format lets a whole S7 client stack — including this module's own
//! client — be exercised against hundreds of simulated CPUs with no hardware,
//! and it is what makes the round-trip tests in `root.zig` possible.
//!
//! It is deliberately **not** a PLC emulator: there is no program execution,
//! no cycle, no retentive-memory semantics. Registered areas are plain byte
//! slices the caller owns, and reads and writes hit them directly.
//!
//! `handle` takes one whole TPKT and writes one whole TPKT, so a caller can
//! drive it from any transport — or from none, which is what the tests do.

const std = @import("std");
const tpkt = @import("tpkt.zig");
const cotp = @import("cotp.zig");
const s7 = @import("s7.zig");
const items = @import("items.zig");
const vars = @import("vars.zig");
const userdata = @import("userdata.zig");
const bt = @import("blocktransfer.zig");

pub const Error = error{
    /// The request is not something this responder implements.
    Unsupported,
    /// The caller's output buffer is too small for the reply.
    BufferTooSmall,
} || bt.Error || tpkt.Error || cotp.Error || s7.Error || items.Error || vars.Error || userdata.Error;

/// One addressable memory area backed by caller-owned storage.
pub const AreaBinding = struct {
    area: items.Area,
    /// Only meaningful for `.db` / `.instance_db`.
    db_number: u16 = 0,
    bytes: []u8,
};

pub const Config = struct {
    /// PDU length this responder will agree to. The lower of this and what the
    /// client asks for wins.
    max_pdu_length: u16 = 480,
    /// Records returned for `Read SZL 0x0011` (module identification). Empty
    /// means "list not available", answered with a return code rather than a
    /// dropped connection.
    szl_0011: []const u8 = &.{},
    /// Operating mode reported through SZL `0x0424`.
    cpu_status: userdata.CpuStatus = .run,
    /// When false, PLC stop/restart requests are answered with an error class
    /// instead of being obeyed. Off by default: a simulator that silently
    /// accepts a stop teaches its operator the wrong lesson.
    allow_plc_control: bool = false,
    /// Time-of-day services (group 7). Null: the services are answered with
    /// the same "not available" error as an unknown SZL. There is no system
    /// time anywhere in this module; the caller supplies the clock.
    clock: ?Clock = null,
    /// Security services (group 5): the CPU password a set-password request
    /// is checked against (its first eight characters, as the CPU keeps).
    /// Null: no password is configured and set/clear are both answered with
    /// success, as python-snap7 3.1.0's emulator does. A correct password
    /// sets `Responder.legitimated`; nothing in the responder is gated on
    /// it (it enforces no access level, see SPEC "Threat model").
    password: ?[]const u8 = null,
    /// SZL `0x0232` index `0x0004` (protection). Null: the list is answered
    /// "not available".
    protection: ?userdata.Protection = null,
    /// Blocks reported by the block services (group 3). Every bound DB area
    /// is listed as well (load and MC7 size = its length) unless an entry here
    /// names the same DB, which then wins. Empty and no DB bound: the lists are
    /// empty and `GetBlockInfo` answers "object does not exist".
    blocks: []const userdata.BlockInfo = &.{},
    /// Largest payload of one Userdata answer PDU; a longer answer (a long SZL
    /// list, many blocks) goes out in several PDUs the client collects with
    /// follow-up requests. Zero: whatever the negotiated PDU length leaves
    /// (480 octets: 454). A small value forces fragmentation in tests.
    max_userdata_payload: u16 = 0,
    /// Block images served to an upload (functions 0x1D-0x1F), as the CPU keeps
    /// them. A block not listed here is "object does not exist".
    block_images: []const BlockImage = &.{},
    /// A download (functions 0x1A-0x1C, then `_INSE`) WRITES a program into
    /// the simulated CPU; refused unless this is set, like the PLC control
    /// requests. Off by default.
    allow_block_download: bool = false,
    /// Where a download's image is assembled. A download longer than this is
    /// refused ("no resources"). After the `_INSE` the image stays here until
    /// the next download starts (`Responder.insertedImage`).
    download_buffer: []u8 = &.{},
};

/// One block image served by the upload services.
pub const BlockImage = struct {
    block_type: userdata.BlockType,
    number: u16,
    image: []const u8,
};

/// A caller-supplied clock for the time-of-day services.
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    /// Current time; must return a valid `userdata.DateTime`.
    now: *const fn (ctx: ?*anyopaque) userdata.DateTime,
    /// Called with a validated date-time when a client sets the clock. Null:
    /// the clock is read-only and a set request is refused with an error.
    set: ?*const fn (ctx: ?*anyopaque, value: userdata.DateTime) void = null,
};

/// The length field a failed data item carries. It is meaningless — there is
/// no payload behind it — but the captured snap7-server emits exactly
/// `0x0004` for every failed item regardless of what was asked for (F13: the
/// capture's peer was snap7's software server-emulator, not a physical
/// Siemens CPU), and the responder reproduces that so its replies are
/// byte-identical to the capture's.
pub const error_item_length: u16 = 4;

pub const Responder = struct {
    config: Config,
    areas: []const AreaBinding,
    /// Negotiated after `Setup communication`; zero until then.
    pdu_length: u16 = 0,
    connected: bool = false,
    /// Set by a PLC control request when `allow_plc_control` is on.
    stopped: bool = false,
    /// The session presented the configured password (group 5); cleared by
    /// a clear-password request, a failed set, and a COTP connect or
    /// disconnect (a legitimation belongs to one connection).
    legitimated: bool = false,
    /// A multi-PDU Userdata answer in progress: what the next follow-up
    /// request continues. Cleared by a COTP connect or disconnect and by any
    /// request that is not the follow-up.
    cont: ?Continuation = null,
    /// An upload in progress (start-upload answered, end-upload not yet seen).
    up: ?Upload = null,
    /// A download in progress.
    dl: ?Download = null,
    /// The block the last successful `_INSE` activated.
    inserted: ?userdata.BlockRef = null,
    inserted_len: usize = 0,

    const Upload = struct { image: []const u8, offset: usize = 0 };
    const Download = struct {
        const Stage = enum { pulling, received, ended };
        name: bt.FileName,
        expected: usize,
        received: usize = 0,
        job_ref: u16,
        stage: Stage = .pulling,
    };
    /// Upload and download id the responder hands out.
    const transfer_id: u32 = 1;

    const Continuation = struct {
        const Kind = enum { szl, list };
        kind: Kind,
        group: userdata.FunctionGroup,
        sub: u8,
        id: u16 = 0,
        index: u16 = 0,
        block_type: userdata.BlockType = .db,
        offset: usize = 0,
        sequence: u8 = 0,
    };

    pub fn init(config: Config, areas: []const AreaBinding) Responder {
        return .{ .config = config, .areas = areas };
    }

    fn find(self: *Responder, area: items.Area, db_number: u16) ?[]u8 {
        for (self.areas) |b| {
            if (b.area != area) continue;
            if ((area == .db or area == .instance_db) and b.db_number != db_number) continue;
            return b.bytes;
        }
        return null;
    }

    /// Handles one whole TPKT and writes one whole TPKT into `out`.
    /// Returns null when the request needs no reply (a disconnect).
    pub fn handle(self: *Responder, packet: []const u8, out: []u8) Error!?[]u8 {
        const pkt = try tpkt.decode(packet);
        switch (try cotp.decode(pkt.payload)) {
            .cr => |cr| {
                self.connected = true;
                // A legitimation belongs to one connection.
                self.legitimated = false;
                self.cont = null;
                self.up = null;
                self.dl = null;
                var body: [64]u8 = undefined;
                // Echo the client's parameters back, which is what a real CPU
                // does and what makes the rack/slot round trip visible.
                const cc = try cotp.encodeConnect(.{
                    .code = .cc,
                    .credit = cr.credit,
                    .dst_ref = cr.src_ref,
                    .src_ref = 1,
                    .src_tsap = cr.src_tsap,
                    .dst_tsap = cr.dst_tsap,
                    .tpdu_size = cr.tpdu_size,
                }, &body);
                return try tpkt.encode(cc, out);
            },
            .dr, .dc => {
                self.connected = false;
                self.legitimated = false;
                self.cont = null;
                self.up = null;
                self.dl = null;
                return null;
            },
            .dt => |dt| {
                // F12: `EOT = 0` marks a fragment -- the peer is still
                // sending more DTs of the same PDU. `cotp.zig`'s own doc
                // comment claims a peer that clears it "is fragmenting,
                // which this implementation refuses to reassemble" -- but
                // nothing here ever read `dt.eot`, so the first fragment
                // was processed as if it were the whole request. Since there
                // is no reassembly, the honest answer to an incomplete
                // request is the same as to a disconnect: no reply yet: a
                // real CPU also would not answer until it had seen the rest.
                if (!dt.eot) return null;
                return try self.handleS7(dt.payload, out);
            },
            else => return error.Unsupported,
        }
    }

    fn handleS7(self: *Responder, bytes: []const u8, out: []u8) Error!?[]u8 {
        const pdu = try s7.decode(bytes);
        return switch (pdu.header.rosctr) {
            .job => try self.handleJob(pdu, out),
            .userdata => try self.handleUserdata(pdu, out),
            .ack_data => try self.handleAck(pdu, out),
            else => error.Unsupported,
        };
    }

    fn handleJob(self: *Responder, pdu: s7.Pdu, out: []u8) Error!?[]u8 {
        if (pdu.parameters.len == 0) return error.Unsupported;
        const function: s7.Function = @fromBackingInt(@intCast(pdu.parameters[0]));
        return switch (function) {
            .setup_communication => try self.doSetup(pdu, out),
            .read_var => try self.doRead(pdu, out),
            .write_var => try self.doWrite(pdu, out),
            .plc_stop => try self.doControl(pdu, out, true),
            .pi_service => if (bt.piServiceName(pdu.parameters)) |svc|
                (if (std.mem.eql(u8, svc, bt.insert_service))
                    try self.doInsert(pdu, out)
                else
                    try self.doControl(pdu, out, false))
            else
                try self.doControl(pdu, out, false),
            .start_upload => try self.doStartUpload(pdu, out),
            .upload => try self.doUpload(pdu, out),
            .end_upload => try self.doEndUpload(pdu, out),
            .request_download => try self.doRequestDownload(pdu, out),
            .download_ended => try self.doDownloadEnded(pdu, out),
            else => try errorReply(pdu, .error_on_service_processing, 0x04, out),
        };
    }

    fn doSetup(self: *Responder, pdu: s7.Pdu, out: []u8) Error![]u8 {
        const asked = try s7.Setup.decode(pdu.parameters);
        self.pdu_length = @min(asked.pdu_length, self.config.max_pdu_length);
        var params: [s7.Setup.wire_len]u8 = undefined;
        const p = try (s7.Setup{
            .max_amq_calling = 1,
            .max_amq_called = 1,
            .pdu_length = self.pdu_length,
        }).encode(&params);
        return self.reply(pdu.header.pdu_reference, p, &.{}, out);
    }

    fn doRead(self: *Responder, pdu: s7.Pdu, out: []u8) Error![]u8 {
        // A parameter block this responder cannot even parse (F8: e.g. a
        // Read Var request whose function octet is right but whose item
        // count/spec is short) used to propagate the decode error straight
        // out of `handle`, leaving the caller with NO reply at all -- unlike
        // an unrecognised function code, which already gets a typed error
        // reply below in `handleJob`. A real peer that sent a malformed but
        // recognisable request sees a dead connection instead of a typed
        // refusal, and (per the audit) that killed every later call on it.
        const req = vars.decodeRequest(pdu.parameters) catch
            return errorReply(pdu, .error_on_service_processing, 0x04, out);
        var it = req.iterator();
        // Build the data block into the tail of `out` and the parameters in
        // front of it once the length is known.
        var data: [2048]u8 = undefined;
        var w = items.DataBlockWriter{ .out = &data };
        var count: u8 = 0;
        while (try it.next()) |item| {
            count += 1;
            const want = item.payloadBytes() orelse {
                try w.addError(.data_type_unsupported, error_item_length);
                continue;
            };
            // A zero element count makes the bounds guard below vacuous: `want`
            // is 0, so `start + want > store.len` is false even at
            // `start == store.len`, and the `.bit` arm then indexes
            // `store[item.byteOffset()]` one octet past the area. Refuse it up
            // front -- there is nothing to transfer either way, and with
            // `count >= 1` the guard implies `byteOffset() < store.len` for
            // every area kind (for a bit-addressed area `start == byteOffset()`;
            // for an element-addressed one `byteOffset() <= start`).
            if (item.count == 0) {
                try w.addError(.invalid_address, error_item_length);
                continue;
            }
            const store = self.find(item.area, item.db_number) orelse {
                try w.addError(.object_does_not_exist, error_item_length);
                continue;
            };
            const start: usize = if (item.area.addressesElements())
                @as(usize, item.address) * 2
            else
                item.byteOffset();
            if (start + want > store.len) {
                try w.addError(.invalid_address, error_item_length);
                continue;
            }
            const ts = if (item.transport_size == .bit)
                items.DataTransportSize.bit
            else if (item.transport_size == .real)
                items.DataTransportSize.real
            else if (item.area.addressesElements())
                items.DataTransportSize.octet_string
            else
                items.DataTransportSize.byte_word_dword;
            if (ts == .bit) {
                // One bit, reported the way a real CPU does: length 1.
                // `addBit` pads the *previous* item first -- writing this
                // shape straight into `data` (as this used to) skipped that
                // pad whenever the previous item left an odd offset (F3).
                const byte = store[item.byteOffset()];
                const v = (byte >> item.bitOffset()) & 1 != 0;
                try w.addBit(v);
            } else {
                try w.add(ts, store[start..][0..want]);
            }
        }
        var params: [2]u8 = undefined;
        const p = try vars.encodeReply(.read_var, count, &params);
        return self.reply(pdu.header.pdu_reference, p, w.written(), out);
    }

    fn doWrite(self: *Responder, pdu: s7.Pdu, out: []u8) Error![]u8 {
        // Same reasoning as `doRead` above (F8): answer with a typed error
        // rather than dropping the reply entirely.
        const req = vars.decodeRequest(pdu.parameters) catch
            return errorReply(pdu, .error_on_service_processing, 0x04, out);
        var it = req.iterator();
        var di = items.DataItemIterator.initRequest(pdu.data, req.count);
        var codes: [vars.max_items]u8 = undefined;
        var count: u8 = 0;
        while (try it.next()) |item| {
            const value = (try di.next()) orelse return error.ShortItem;
            const rc = self.applyWrite(item, value);
            codes[count] = @backingInt(rc);
            count += 1;
        }
        var params: [2]u8 = undefined;
        const p = try vars.encodeReply(.write_var, count, &params);
        return self.reply(pdu.header.pdu_reference, p, codes[0..count], out);
    }

    fn applyWrite(self: *Responder, item: items.Item, value: items.DataItem) items.ReturnCode {
        const store = self.find(item.area, item.db_number) orelse return .object_does_not_exist;
        if (item.transport_size == .bit) {
            const off = item.byteOffset();
            if (off >= store.len or value.payload.len < 1) return .invalid_address;
            const mask: u8 = @as(u8, 1) << item.bitOffset();
            if (value.payload[0] & 1 != 0) store[off] |= mask else store[off] &= ~mask;
            return .success;
        }
        const want = item.payloadBytes() orelse return .data_type_unsupported;
        const start: usize = if (item.area.addressesElements())
            @as(usize, item.address) * 2
        else
            item.byteOffset();
        if (start + want > store.len) return .invalid_address;
        if (value.payload.len < want) return .data_type_inconsistent;
        @memcpy(store[start..][0..want], value.payload[0..want]);
        return .success;
    }

    // ── block upload and download ──────────────────────────────────────────

    /// The image `Config.block_images` holds for a block, or null.
    fn imageOf(self: *const Responder, t: userdata.BlockType, number: u16) ?[]const u8 {
        for (self.config.block_images) |b| {
            if (b.block_type == t and b.number == number) return b.image;
        }
        return null;
    }

    /// The image the last successful `_INSE` activated, or null.
    pub fn insertedImage(self: *const Responder) ?[]const u8 {
        if (self.inserted == null) return null;
        return self.config.download_buffer[0..self.inserted_len];
    }

    fn refuse(pdu: s7.Pdu, out: []u8) Error![]u8 {
        return errorReply(pdu, .error_on_service_processing, 0x04, out);
    }

    fn doStartUpload(self: *Responder, pdu: s7.Pdu, out: []u8) Error![]u8 {
        self.up = null;
        const name = bt.decodeStartUpload(pdu.parameters) catch return refuse(pdu, out);
        const image = self.imageOf(name.block_type, name.number) orelse
            return errorReply(pdu, .object_definition, 0x00, out);
        var params: [bt.start_upload_reply_len]u8 = undefined;
        if (image.len > bt.max_upload_len) return refuse(pdu, out);
        const p = try bt.encodeStartUploadReply(transfer_id, @intCast(image.len), &params);
        self.up = .{ .image = image };
        return self.reply(pdu.header.pdu_reference, p, &.{}, out);
    }

    /// Chunk payload room of one Ack-Data under the negotiated PDU length.
    fn chunkRoom(self: *const Responder) usize {
        const pdu_len: usize = if (self.pdu_length == 0) 480 else self.pdu_length;
        const overhead = s7.Rosctr.ack_data.headerLen() + 2 + bt.chunk_header_len;
        return @min(if (pdu_len > overhead) pdu_len - overhead else 0, 1024);
    }

    fn doUpload(self: *Responder, pdu: s7.Pdu, out: []u8) Error![]u8 {
        const up = &(self.up orelse return refuse(pdu, out));
        const id = bt.decodeIdJob(pdu.parameters, bt.fn_upload) catch return refuse(pdu, out);
        if (id != transfer_id) return refuse(pdu, out);
        const room = self.chunkRoom();
        if (room == 0) return refuse(pdu, out);
        const n = @min(room, up.image.len - up.offset);
        const more = up.offset + n < up.image.len;
        var cp: [2]u8 = undefined;
        var data: [1024 + bt.chunk_header_len]u8 = undefined;
        const d = try bt.encodeChunk(up.image[up.offset..][0..n], &data);
        const p = try bt.encodeChunkParams(bt.fn_upload, more, &cp);
        up.offset += n;
        return self.reply(pdu.header.pdu_reference, p, d, out);
    }

    fn doEndUpload(self: *Responder, pdu: s7.Pdu, out: []u8) Error![]u8 {
        if (self.up == null) return refuse(pdu, out);
        _ = bt.decodeIdJob(pdu.parameters, bt.fn_end_upload) catch return refuse(pdu, out);
        self.up = null;
        return self.reply(pdu.header.pdu_reference, pdu.parameters[0..1], &.{}, out);
    }

    /// The CPU's pull: the next "download block" job.
    fn downloadJob(self: *Responder, out: []u8) Error![]u8 {
        const dl = &self.dl.?;
        var jp: [bt.block_job_len]u8 = undefined;
        const p = try bt.encodeBlockJob(bt.fn_download_block, transfer_id, dl.name, &jp);
        return self.frame(.job, dl.job_ref, p, &.{}, out, false);
    }

    fn doRequestDownload(self: *Responder, pdu: s7.Pdu, out: []u8) Error![]u8 {
        self.dl = null;
        if (!self.config.allow_block_download) return refuse(pdu, out);
        const rd = bt.decodeRequestDownload(pdu.parameters) catch return refuse(pdu, out);
        if (rd.load_len > self.config.download_buffer.len) {
            return errorReply(pdu, .no_resources_available, 0x00, out);
        }
        self.inserted = null;
        self.dl = .{
            .name = rd.name,
            .expected = rd.load_len,
            .job_ref = pdu.header.pdu_reference +% 1,
        };
        // Two packets in one answer: the ack, then the CPU's first pull.
        const ack = try self.reply(pdu.header.pdu_reference, pdu.parameters[0..1], &.{}, out);
        const job = try self.downloadJob(out[ack.len..]);
        return out[0 .. ack.len + job.len];
    }

    /// The client's Ack-Data to a download-block job: one chunk of the image.
    /// Anything that does not fit a running download is dropped.
    fn handleAck(self: *Responder, pdu: s7.Pdu, out: []u8) Error!?[]u8 {
        const dl = &(self.dl orelse return null);
        if (dl.stage != .pulling or pdu.header.pdu_reference != dl.job_ref) return null;
        if (pdu.header.isError()) {
            self.dl = null;
            return null;
        }
        const more = bt.decodeChunkParams(pdu.parameters, bt.fn_download_block) catch {
            self.dl = null;
            return null;
        };
        const chunk = bt.decodeChunk(pdu.data) catch {
            self.dl = null;
            return null;
        };
        if (chunk.len > dl.expected - dl.received) {
            self.dl = null;
            return null;
        }
        @memcpy(self.config.download_buffer[dl.received..][0..chunk.len], chunk);
        dl.received += chunk.len;
        if (!more) {
            dl.stage = .received;
            return null;
        }
        dl.job_ref +%= 1;
        return try self.downloadJob(out);
    }

    fn sameBlock(a: bt.FileName, b: bt.FileName) bool {
        return a.block_type == b.block_type and a.number == b.number;
    }

    fn doDownloadEnded(self: *Responder, pdu: s7.Pdu, out: []u8) Error![]u8 {
        const dl = &(self.dl orelse return refuse(pdu, out));
        const job = bt.decodeBlockJob(pdu.parameters, bt.fn_download_ended) catch {
            self.dl = null;
            return refuse(pdu, out);
        };
        if (dl.stage != .received or dl.received != dl.expected or !sameBlock(job.name, dl.name)) {
            self.dl = null;
            return refuse(pdu, out);
        }
        dl.stage = .ended;
        return self.reply(pdu.header.pdu_reference, pdu.parameters[0..1], &.{}, out);
    }

    fn doInsert(self: *Responder, pdu: s7.Pdu, out: []u8) Error![]u8 {
        const dl = &(self.dl orelse return refuse(pdu, out));
        const name = bt.decodeInsert(pdu.parameters) catch return refuse(pdu, out);
        if (dl.stage != .ended or !sameBlock(name, dl.name)) {
            self.dl = null;
            return refuse(pdu, out);
        }
        self.inserted = .{ .block_type = dl.name.block_type, .number = dl.name.number };
        self.inserted_len = dl.expected;
        self.dl = null;
        return self.reply(pdu.header.pdu_reference, pdu.parameters[0..1], &.{}, out);
    }

    fn doControl(self: *Responder, pdu: s7.Pdu, out: []u8, is_stop: bool) Error![]u8 {
        if (!self.config.allow_plc_control) {
            return errorReply(pdu, .error_on_service_processing, 0x04, out);
        }
        self.stopped = is_stop;
        return self.reply(pdu.header.pdu_reference, pdu.parameters[0..1], &.{}, out);
    }

    fn handleUserdata(self: *Responder, pdu: s7.Pdu, out: []u8) Error![]u8 {
        const p = try userdata.Param.decode(pdu.parameters);
        if (p.function_group == .time_functions) return self.handleTime(p, pdu, out);
        if (p.function_group == .security) return self.handleSecurity(p, pdu, out);
        if (p.function_group == .block_functions) return self.handleBlocks(p, pdu, out);
        if (p.function_group != .cpu_functions or
            p.subfunction != @backingInt(userdata.CpuSubfunction.read_szl))
        {
            return error.Unsupported;
        }
        const block = try userdata.DataBlock.decode(pdu.data);
        var offset: usize = 0;
        const req: userdata.SzlRequest = if (self.followUp(p, block, .szl)) |c| blk: {
            offset = c.offset;
            break :blk .{ .id = c.id, .index = c.index };
        } else blk: {
            self.cont = null;
            break :blk try userdata.SzlRequest.decode(block.payload);
        };

        var payload: [1024]u8 = undefined;
        const szl = switch (req.id) {
            userdata.SzlId.module_identification => blk: {
                if (self.config.szl_0011.len == 0) break :blk null;
                const rl: u16 = 28;
                const n: u16 = @intCast(self.config.szl_0011.len / rl);
                break :blk try userdata.SzlResponse.encode(
                    .{ .id = req.id, .index = req.index, .record_length = rl, .record_count = n },
                    self.config.szl_0011,
                    &payload,
                );
            },
            userdata.SzlId.cpu_status => blk: {
                var rec: [20]u8 = @splat(0);
                rec[0] = 0x51;
                rec[1] = 0x44;
                rec[2] = 0xFF;
                rec[userdata.cpu_status_offset] =
                    @backingInt(if (self.stopped) userdata.CpuStatus.stop else self.config.cpu_status);
                break :blk try userdata.SzlResponse.encode(
                    .{ .id = req.id, .index = req.index, .record_length = 20, .record_count = 1 },
                    &rec,
                    &payload,
                );
            },
            userdata.SzlId.protection_status => blk: {
                const prot = self.config.protection orelse break :blk null;
                if (req.index != userdata.Protection.szl_index) break :blk null;
                var rec: [userdata.Protection.min_record_len]u8 = undefined;
                const r = try prot.encodeRecord(&rec);
                break :blk try userdata.SzlResponse.encode(
                    .{ .id = req.id, .index = req.index, .record_length = @intCast(r.len), .record_count = 1 },
                    r,
                    &payload,
                );
            },
            else => null,
        };

        var more = false;
        var piece: ?[]const u8 = null;
        if (szl) |s| {
            const room = self.fragmentRoom();
            const from = @min(offset, s.len);
            const to = @min(from + room, s.len);
            piece = s[from..to];
            more = to < s.len;
            self.cont = if (more) .{
                .kind = .szl,
                .group = .cpu_functions,
                .sub = p.subfunction,
                .id = req.id,
                .index = req.index,
                .offset = to,
                .sequence = p.sequence +% 1,
            } else null;
        } else self.cont = null;

        var params: [userdata.Param.response_len]u8 = undefined;
        const rp = try (userdata.Param{
            .message_type = .response,
            .function_group = .cpu_functions,
            .subfunction = p.subfunction,
            .sequence = if (more) p.sequence +% 1 else p.sequence,
            .last_data_unit = if (more) .more_follows else .no_more,
            .error_code = if (szl == null) 0xD401 else 0,
        }).encodeResponse(&params);

        var data: [1040]u8 = undefined;
        const db = if (piece) |s|
            try userdata.DataBlock.encode(.success, .octet_string, s, &data)
        else
            try userdata.DataBlock.encode(.object_does_not_exist, .null_size, &.{}, &data);

        return self.frame(.userdata, pdu.header.pdu_reference, rp, db, out, false);
    }

    /// Payload octets one Userdata answer PDU may carry: the negotiated PDU
    /// length less the 10-octet header, the 12-octet parameter block and the
    /// 4-octet data header, capped by `Config.max_userdata_payload`.
    fn fragmentRoom(self: *const Responder) usize {
        const pdu: usize = if (self.pdu_length != 0) self.pdu_length else 480;
        var room: usize = if (pdu > 26) pdu - 26 else 1;
        if (self.config.max_userdata_payload != 0) room = @min(room, self.config.max_userdata_payload);
        return @min(room, 1024);
    }

    /// The pending continuation when `block` is the follow-up request of it:
    /// an empty request block, the same group and subfunction, the sequence
    /// octet the previous answer carried.
    fn followUp(self: *Responder, p: userdata.Param, block: userdata.DataBlock, kind: Continuation.Kind) ?Continuation {
        const c = self.cont orelse return null;
        if (c.kind != kind or c.group != p.function_group or c.sub != p.subfunction) return null;
        if (p.message_type != .request or block.payload.len != 0 or p.sequence != c.sequence) return null;
        return c;
    }

    /// Group 3: `ListBlocks`, `ListBlocksOfType`, `GetBlockInfo`. The lists
    /// come from `Config.blocks` and the bound DB areas.
    fn handleBlocks(self: *Responder, p: userdata.Param, pdu: s7.Pdu, out: []u8) Error![]u8 {
        const sub: userdata.BlockSubfunction = @fromBackingInt(p.subfunction);
        var payload: [1024]u8 = undefined;
        var result: ?[]const u8 = null;
        var more = false;
        var rc: items.ReturnCode = .object_does_not_exist;
        const db_in = userdata.DataBlock.decode(pdu.data) catch null;
        if (p.message_type == .request) switch (sub) {
            .list_all => {
                var c: userdata.BlockCounts = .{};
                c.ob = self.countOf(.ob);
                c.fb = self.countOf(.fb);
                c.fc = self.countOf(.fc);
                c.db = self.countOf(.db);
                c.sdb = self.countOf(.sdb);
                c.sfc = self.countOf(.sfc);
                c.sfb = self.countOf(.sfb);
                result = try c.encode(&payload);
                self.cont = null;
            },
            .list_of_type => if (db_in) |db| {
                var offset: usize = 0;
                var t: userdata.BlockType = undefined;
                if (self.followUp(p, db, .list)) |c| {
                    offset = c.offset;
                    t = c.block_type;
                } else if (userdata.decodeListOfTypeRequest(db.payload)) |lt| {
                    t = lt;
                } else |_| {
                    rc = .data_type_inconsistent;
                    t = .db;
                    self.cont = null;
                    return self.blockAnswer(p, pdu, null, false, rc, out);
                }
                const per_pdu = self.fragmentRoom() / userdata.BlockEntry.wire_len;
                const total: usize = self.countOf(t);
                var n: usize = 0;
                var i = offset;
                while (i < total and n < per_pdu) : (i += 1) {
                    const b = self.nthBlock(t, i).?;
                    _ = try (userdata.BlockEntry{ .number = b.number, .flags = b.flags, .language = b.language })
                        .encode(payload[n * userdata.BlockEntry.wire_len ..]);
                    n += 1;
                }
                result = payload[0 .. n * userdata.BlockEntry.wire_len];
                more = i < total;
                self.cont = if (more) .{
                    .kind = .list,
                    .group = .block_functions,
                    .sub = p.subfunction,
                    .block_type = t,
                    .offset = i,
                    .sequence = p.sequence +% 1,
                } else null;
            },
            .block_info => if (db_in) |db| {
                self.cont = null;
                if (userdata.decodeBlockInfoRequest(db.payload)) |ref| {
                    if (self.findBlock(ref.block_type, ref.number)) |info| {
                        result = try info.encode(&payload);
                    }
                } else |_| {
                    rc = .data_type_inconsistent;
                }
            },
            _ => {},
        };
        return self.blockAnswer(p, pdu, result, more, rc, out);
    }

    fn blockAnswer(self: *Responder, p: userdata.Param, pdu: s7.Pdu, result: ?[]const u8, more: bool, rc: items.ReturnCode, out: []u8) Error![]u8 {
        var params: [userdata.Param.response_len]u8 = undefined;
        const rp = try (userdata.Param{
            .message_type = .response,
            .function_group = .block_functions,
            .subfunction = p.subfunction,
            .sequence = if (more) p.sequence +% 1 else p.sequence,
            .last_data_unit = if (more) .more_follows else .no_more,
            .error_code = if (result == null) userdata.ErrorCode.not_available else 0,
        }).encodeResponse(&params);
        var data: [1040]u8 = undefined;
        const db = if (result) |r|
            try userdata.DataBlock.encode(.success, .octet_string, r, &data)
        else
            try userdata.DataBlock.encode(rc, .null_size, &.{}, &data);
        return self.frame(.userdata, pdu.header.pdu_reference, rp, db, out, false);
    }

    /// Block `n` (0-based) of type `t`: the configured blocks first, then
    /// the bound DB areas no configured entry names.
    fn nthBlock(self: *const Responder, t: userdata.BlockType, n: usize) ?userdata.BlockInfo {
        var seen: usize = 0;
        for (self.config.blocks) |b| {
            if (b.block_type != t) continue;
            if (seen == n) return b;
            seen += 1;
        }
        if (t == .db) for (self.areas) |a| {
            if (a.area != .db) continue;
            if (self.configured(.db, a.db_number)) continue;
            if (seen == n) return areaBlock(a);
            seen += 1;
        };
        return null;
    }

    fn configured(self: *const Responder, t: userdata.BlockType, number: u16) bool {
        for (self.config.blocks) |b| if (b.block_type == t and b.number == number) return true;
        return false;
    }

    fn areaBlock(a: AreaBinding) userdata.BlockInfo {
        const size: u32 = @intCast(@min(a.bytes.len, 0xFFFF));
        return .{
            .block_type = .db,
            .number = a.db_number,
            .load_size = size,
            .mc7_size = @intCast(size),
        };
    }

    fn countOf(self: *const Responder, t: userdata.BlockType) u16 {
        var n: usize = 0;
        while (self.nthBlock(t, n) != null) n += 1;
        return @intCast(@min(n, 0xFFFF));
    }

    fn findBlock(self: *const Responder, t: userdata.BlockType, number: u16) ?userdata.BlockInfo {
        var n: usize = 0;
        while (self.nthBlock(t, n)) |b| : (n += 1) if (b.number == number) return b;
        return null;
    }

    /// Group 7. Read clock answers with the 10-octet date-time; set clock
    /// validates the request's date-time (BCD digits and ranges) and hands it to
    /// the configured setter. Anything unavailable or invalid is a response with
    /// an error code and a failing data return code, never a dropped reply.
    fn handleTime(self: *Responder, p: userdata.Param, pdu: s7.Pdu, out: []u8) Error![]u8 {
        const sub: userdata.TimeSubfunction = @fromBackingInt(p.subfunction);
        var ts: [userdata.DateTime.wire_len]u8 = undefined;
        var result: ?[]const u8 = null; // payload for a successful answer
        var rc: items.ReturnCode = .object_does_not_exist;
        var ok = false;
        if (self.config.clock) |clk| switch (sub) {
            .read_clock, .read_clock_following => {
                if (clk.now(clk.ctx).encode(&ts)) |enc| {
                    result = enc;
                    ok = true;
                } else |_| {
                    rc = .hardware_fault;
                }
            },
            .set_clock, .set_clock_alt => {
                const set = clk.set;
                if (set == null) {
                    rc = .access_denied;
                } else if (userdata.DataBlock.decode(pdu.data)) |db| {
                    if (!db.return_code.isSuccess()) {
                        rc = .data_type_inconsistent;
                    } else if (userdata.DateTime.decode(db.payload)) |dt| {
                        set.?(clk.ctx, dt);
                        result = &.{};
                        ok = true;
                    } else |_| {
                        rc = .data_type_inconsistent;
                    }
                } else |_| {
                    rc = .data_type_inconsistent;
                }
            },
            else => {},
        };

        var params: [userdata.Param.response_len]u8 = undefined;
        const rp = try (userdata.Param{
            .message_type = .response,
            .function_group = .time_functions,
            .subfunction = p.subfunction,
            .sequence = p.sequence,
            .last_data_unit = .no_more,
            .error_code = if (ok) 0 else 0xD401,
        }).encodeResponse(&params);
        var data: [4 + userdata.DateTime.wire_len]u8 = undefined;
        const db = if (result) |r|
            try userdata.DataBlock.encode(.success, .octet_string, r, &data)
        else
            try userdata.DataBlock.encode(rc, .null_size, &.{}, &data);
        return self.frame(.userdata, pdu.header.pdu_reference, rp, db, out, false);
    }

    /// Group 5. Set password: the data block must be an octet string of
    /// exactly eight encoded octets; they are compared, in constant time,
    /// with the configured password encoded the same way. A wrong password
    /// is error code `0xD602`, a malformed request `0xD401`, an unknown
    /// subfunction `0xD401`; each is a response, never a dropped reply.
    /// Clear password always succeeds and drops the legitimation.
    fn handleSecurity(self: *Responder, p: userdata.Param, pdu: s7.Pdu, out: []u8) Error![]u8 {
        // Only a request is served; anything else is answered like an
        // unknown subfunction and changes no state.
        const sub: userdata.SecuritySubfunction = if (p.message_type == .request) @fromBackingInt(p.subfunction) else @fromBackingInt(0);
        var code: u16 = userdata.ErrorCode.not_available;
        var rc: items.ReturnCode = .object_does_not_exist;
        switch (sub) {
            .set_password => blk: {
                // Any set that does not succeed leaves the session without
                // a legitimation, whatever it had before.
                self.legitimated = false;
                const db = userdata.DataBlock.decode(pdu.data) catch {
                    rc = .data_type_inconsistent;
                    break :blk;
                };
                if (!db.return_code.isSuccess() or db.transport_size != .octet_string or
                    db.payload.len != userdata.password_len)
                {
                    rc = .data_type_inconsistent;
                    break :blk;
                }
                const want = self.config.password orelse {
                    self.legitimated = true;
                    code = 0;
                    break :blk;
                };
                const enc = userdata.encodePassword(want);
                if (std.crypto.timing_safe.eql([userdata.password_len]u8, enc, db.payload[0..userdata.password_len].*)) {
                    self.legitimated = true;
                    code = 0;
                } else {
                    code = userdata.ErrorCode.incorrect_password;
                }
            },
            .clear_password => {
                self.legitimated = false;
                code = 0;
            },
            _ => {},
        }

        var params: [userdata.Param.response_len]u8 = undefined;
        const rp = try (userdata.Param{
            .message_type = .response,
            .function_group = .security,
            .subfunction = p.subfunction,
            .sequence = p.sequence,
            .last_data_unit = .no_more,
            .error_code = code,
        }).encodeResponse(&params);
        var data: [4]u8 = undefined;
        const db = if (code == 0)
            try userdata.DataBlock.encode(.success, .octet_string, &.{}, &data)
        else
            try userdata.DataBlock.encode(rc, .null_size, &.{}, &data);
        return self.frame(.userdata, pdu.header.pdu_reference, rp, db, out, false);
    }

    fn reply(self: *Responder, pdu_ref: u16, params: []const u8, data: []const u8, out: []u8) Error![]u8 {
        return self.frame(.ack_data, pdu_ref, params, data, out, true);
    }

    fn errorReply(pdu: s7.Pdu, class: s7.ErrorClass, code: u8, out: []u8) Error![]u8 {
        var body: [512]u8 = undefined;
        const enc = try s7.encode(.{
            .rosctr = .ack_data,
            .pdu_reference = pdu.header.pdu_reference,
            .error_class = class,
            .error_code = code,
        }, &.{}, &.{}, &body);
        return try wrap(enc, out);
    }

    fn frame(
        self: *Responder,
        rosctr: s7.Rosctr,
        pdu_ref: u16,
        params: []const u8,
        data: []const u8,
        out: []u8,
        check_pdu: bool,
    ) Error![]u8 {
        var body: [2048]u8 = undefined;
        const enc = try s7.encode(
            .{ .rosctr = rosctr, .pdu_reference = pdu_ref },
            params,
            data,
            &body,
        );
        if (check_pdu and self.pdu_length != 0 and enc.len > self.pdu_length) {
            return error.BufferTooSmall;
        }
        return try wrap(enc, out);
    }

    fn wrap(pdu: []const u8, out: []u8) Error![]u8 {
        if (out.len < tpkt.header_len + 3 + pdu.len) return error.BufferTooSmall;
        const dh = cotp.dataHeader(0, true);
        @memcpy(out[tpkt.header_len..][0..3], &dh);
        @memcpy(out[tpkt.header_len + 3 ..][0..pdu.len], pdu);
        const total = tpkt.header_len + 3 + pdu.len;
        const th = try tpkt.header(total - tpkt.header_len);
        @memcpy(out[0..tpkt.header_len], &th);
        return out[0..total];
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn hex(comptime s: []const u8, out: []u8) []const u8 {
    return std.fmt.hexToBytes(out, s) catch unreachable;
}

test "the responder answers the reference client's CR with a CC echoing the TSAPs" {
    var db: [64]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{}, &areas);
    var in: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    const cr = hex("0300001611e00000000100c0010ac1020100c2020122", &in);
    const cc = (try r.handle(cr, &out)).?;
    // Rack 1 slot 2 comes back untouched: 0x0122.
    try testing.expectEqualSlices(u8, &[_]u8{ 0xC2, 0x02, 0x01, 0x22 }, cc[18..22]);
    try testing.expectEqual(@as(u8, 0xD0), cc[5]);
}

test "setup negotiates down to the responder's ceiling" {
    var db: [64]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{ .max_pdu_length = 240 }, &areas);
    var in: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    const req = hex("0300001902f08032010000000100080000f0000001000101e0", &in);
    const rep = (try r.handle(req, &out)).?;
    try testing.expectEqual(@as(u16, 240), r.pdu_length);
    // f0 00 0001 0001 00f0
    try testing.expectEqualSlices(u8, &[_]u8{ 0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xF0 }, rep[19..27]);
}

test "read and write hit the registered area" {
    var db: [64]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{}, &areas);
    var in: [128]u8 = undefined;
    var out: [128]u8 = undefined;
    _ = try r.handle(hex("0300001902f08032010000000100080000f0000001000101e0", &in), &out);

    // Write 12345678 to DB1.DBB20 — the reference client's exact request.
    const wreq = hex("0300002702f080320100000200000e00080501120a100200040001840000a0" ++
        "0004002012345678", &in);
    const wrep = (try r.handle(wreq, &out)).?;
    try testing.expectEqual(@as(u8, 0xFF), wrep[wrep.len - 1]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34, 0x56, 0x78 }, db[20..24]);

    // Read it back.
    const rreq = hex("0300001f02f080320100000300000e00000401120a100200040001840000a0", &in);
    const rrep = (try r.handle(rreq, &out)).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0x04, 0x00, 0x20, 0x12, 0x34, 0x56, 0x78 }, rrep[21..]);
}

test "a read of a DB that is not registered gets the object-does-not-exist code" {
    var db: [64]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{}, &areas);
    var in: [128]u8 = undefined;
    var out: [128]u8 = undefined;
    _ = try r.handle(hex("0300001902f08032010000000100080000f0000001000101e0", &in), &out);
    // DB 77.
    const req = hex("0300001f02f080320100000200000e00000401120a10020004004d84000000", &in);
    const rep = (try r.handle(req, &out)).?;
    try testing.expectEqual(@as(u8, 0x0A), rep[21]);
    // An address past the end of a registered DB.
    const oob = hex("0300001f02f080320100000300000e00000401120a100200200001840007d0", &in);
    const rep2 = (try r.handle(oob, &out)).?;
    try testing.expectEqual(@as(u8, 0x05), rep2[21]);
}

test "bit read and write" {
    var flags: [16]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .flags, .bytes = &flags }};
    var r = Responder.init(.{}, &areas);
    var in: [128]u8 = undefined;
    var out: [128]u8 = undefined;
    _ = try r.handle(hex("0300001902f08032010000000100080000f0000001000101e0", &in), &out);
    // Set M10.2.
    const w = hex("0300002402f080320100000200000e00050501120a100100010000830000520003000101", &in);
    _ = try r.handle(w, &out);
    try testing.expectEqual(@as(u8, 0x04), flags[10]);
    // Read it back: the reply must be `ff 03 0001 01`.
    const rd = hex("0300001f02f080320100000300000e00000401120a10010001000083000052", &in);
    const rep = (try r.handle(rd, &out)).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0x03, 0x00, 0x01, 0x01 }, rep[21..]);
}

test "a write past the end of the area, or shorter than its item, is refused and writes nothing" {
    var db: [64]u8 = @splat(0);
    var flags: [16]u8 = @splat(0);
    var areas = [_]AreaBinding{
        .{ .area = .db, .db_number = 1, .bytes = &db },
        .{ .area = .flags, .bytes = &flags },
    };
    var r = Responder.init(.{}, &areas);
    var in: [128]u8 = undefined;
    var out: [128]u8 = undefined;
    _ = try r.handle(hex("0300001902f08032010000000100080000f0000001000101e0", &in), &out);

    // Four octets at DB1.DBB61 of a 64-octet DB: one past the end.
    const past = hex("0300002702f080320100000200000e00080501120a100200040001840001e8" ++
        "0004002012345678", &in);
    var rep = (try r.handle(past, &out)).?;
    try testing.expectEqual(@backingInt(items.ReturnCode.invalid_address), rep[rep.len - 1]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0 }, db[61..64]);

    // A four-octet item carrying two octets of data.
    const short = hex("0300002502f080320100000300000e00060501120a100200040001840000a0" ++
        "000400101234", &in);
    rep = (try r.handle(short, &out)).?;
    try testing.expectEqual(@backingInt(items.ReturnCode.data_type_inconsistent), rep[rep.len - 1]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0 }, db[20..22]);

    // M16.0 in a 16-octet flag area.
    const bit = hex("0300002402f080320100000400000e00050501120a100100010000830000800003000101", &in);
    rep = (try r.handle(bit, &out)).?;
    try testing.expectEqual(@backingInt(items.ReturnCode.invalid_address), rep[rep.len - 1]);
}

test "PLC control is refused unless explicitly enabled" {
    var db: [16]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{}, &areas);
    var setup_buf: [64]u8 = undefined;
    var stop_buf: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    const setup_req = hex("0300001902f08032010000000100080000f0000001000101e0", &setup_buf);
    const stop = hex("0300002102f0803201000002000010000029000000000009505f50524f4752414d", &stop_buf);
    _ = try r.handle(setup_req, &out);
    const rep = (try r.handle(stop, &out)).?;
    // Ack-Data with an error class, and the CPU is still running.
    try testing.expectEqual(@as(u8, 0x84), rep[17]);
    try testing.expect(!r.stopped);

    var r2 = Responder.init(.{ .allow_plc_control = true }, &areas);
    _ = try r2.handle(setup_req, &out);
    const rep2 = (try r2.handle(stop, &out)).?;
    try testing.expectEqual(@as(u8, 0x29), rep2[19]);
    try testing.expect(r2.stopped);
}

test "an unrecognized job function code gets a typed error reply, not silence" {
    // handleJob's `else` arm (unrecognized/unimplemented function code) had
    // no test at all -- only the *specific* function codes' own error paths
    // (e.g. PLC control refused) were covered. Built from the "PLC stop"
    // frame above with its function-code octet (0x29) replaced by 0xAA,
    // which is not one of `s7.Function`'s named values.
    var db: [16]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{}, &areas);
    var setup_buf: [64]u8 = undefined;
    var bad_buf: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    const setup_req = hex("0300001902f08032010000000100080000f0000001000101e0", &setup_buf);
    const bad = hex("0300002102f08032010000020000100000aa000000000009505f50524f4752414d", &bad_buf);
    _ = try r.handle(setup_req, &out);
    const rep = (try r.handle(bad, &out)).?;
    // Ack-Data (rosctr) with error_class = error_on_service_processing (0x84)
    // and error_code = 0x04, same shape as the refused-PLC-control reply.
    try testing.expectEqual(@as(u8, 0x84), rep[17]);
    try testing.expectEqual(@as(u8, 0x04), rep[18]);
}

test "read SZL 0x0424 reflects the configured and the stopped state" {
    var db: [16]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{ .allow_plc_control = true }, &areas);
    var setup_buf: [64]u8 = undefined;
    var szl_buf: [64]u8 = undefined;
    var out: [256]u8 = undefined;
    _ = try r.handle(hex("0300001902f08032010000000100080000f0000001000101e0", &setup_buf), &out);
    const szl = hex("0300002102f080320700000200000800080001120411440100ff09000404240000", &szl_buf);
    const rep = (try r.handle(szl, &out)).?;
    const pdu = try s7.decode((try cotp.decode((try tpkt.decode(rep)).payload)).dt.payload);
    const block = try userdata.DataBlock.decode(pdu.data);
    const resp = try userdata.SzlResponse.decode(block.payload);
    try testing.expectEqual(userdata.CpuStatus.run, userdata.cpuStatusFrom(resp).?);

    r.stopped = true;
    const rep2 = (try r.handle(szl, &out)).?;
    const pdu2 = try s7.decode((try cotp.decode((try tpkt.decode(rep2)).payload)).dt.payload);
    const resp2 = try userdata.SzlResponse.decode((try userdata.DataBlock.decode(pdu2.data)).payload);
    try testing.expectEqual(userdata.CpuStatus.stop, userdata.cpuStatusFrom(resp2).?);
}

const TestClock = struct {
    now_value: userdata.DateTime = .{ .year = 2026, .month = 11, .day = 19, .hour = 13, .minute = 45, .second = 59, .millisecond = 987, .weekday = 5 },
    sets: usize = 0,

    fn now(ctx: ?*anyopaque) userdata.DateTime {
        const self: *TestClock = @ptrCast(@alignCast(ctx.?));
        return self.now_value;
    }
    fn set(ctx: ?*anyopaque, value: userdata.DateTime) void {
        const self: *TestClock = @ptrCast(@alignCast(ctx.?));
        self.now_value = value;
        self.sets += 1;
    }
};

const read_clock_req = "0300001d02f080320700000300000800040001120411470100" ++ "0a000000";
const set_clock_req = "0300002702f0803207000004000008000e0001120411470200" ++ "ff09000a00202611191345599875";

test "read clock answers the injected clock, byte for byte" {
    var tc: TestClock = .{};
    var r = Responder.init(.{ .clock = .{ .ctx = &tc, .now = TestClock.now } }, &.{});
    var req: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    const rep = (try r.handle(hex(read_clock_req, &req), &out)).?;
    // Parameters: response head, type|group 0x87, subfunction 1, seq 0, last unit 0, no error.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01, 0x12, 0x08, 0x12, 0x87, 0x01, 0x00, 0, 0, 0, 0 }, rep[17..29]);
    // Data: success, octet string, 10 octets, then the BCD date-time.
    try testing.expectEqualSlices(u8, &[_]u8{
        0xFF, 0x09, 0x00, 0x0A, 0x00, 0x20, 0x26, 0x11, 0x19, 0x13, 0x45, 0x59, 0x98, 0x75,
    }, rep[29..]);
    // The following-variant (0x03) is answered the same way.
    var req2: [64]u8 = undefined;
    const rep2 = (try r.handle(hex("0300001d02f080320700000300000800040001120411470300" ++ "0a000000", &req2), &out)).?;
    try testing.expectEqual(@as(u8, 0x03), rep2[23]);
    try testing.expectEqual(@as(u8, 0xFF), rep2[29]);
}

test "set clock validates, stores through the setter, and answers empty success" {
    var tc: TestClock = .{};
    var r = Responder.init(.{ .clock = .{ .ctx = &tc, .now = TestClock.now, .set = TestClock.set } }, &.{});
    var req: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    const rep = (try r.handle(hex(set_clock_req, &req), &out)).?;
    try testing.expectEqual(@as(usize, 1), tc.sets);
    try testing.expectEqual(@as(u16, 2026), tc.now_value.year);
    try testing.expectEqual(@as(u16, 987), tc.now_value.millisecond);
    try testing.expectEqual(@as(u8, 5), tc.now_value.weekday);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01, 0x12, 0x08, 0x12, 0x87, 0x02, 0x00, 0, 0, 0, 0 }, rep[17..29]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0x09, 0x00, 0x00 }, rep[29..]);
}

test "clock services refuse politely: no clock, read-only clock, malformed date-time" {
    var req: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    // No clock configured: read and set both get an error response.
    var r0 = Responder.init(.{}, &.{});
    const a = (try r0.handle(hex(read_clock_req, &req), &out)).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xD4, 0x01 }, a[27..29]);
    try testing.expectEqual(@as(u8, 0x0A), a[29]);
    const b = (try r0.handle(hex(set_clock_req, &req), &out)).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xD4, 0x01 }, b[27..29]);

    // Read-only clock: set is refused, the clock is untouched.
    var tc: TestClock = .{};
    var r1 = Responder.init(.{ .clock = .{ .ctx = &tc, .now = TestClock.now } }, &.{});
    const c = (try r1.handle(hex(set_clock_req, &req), &out)).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xD4, 0x01 }, c[27..29]);
    try testing.expectEqual(@as(u8, 0x03), c[29]);
    try testing.expectEqual(@as(usize, 0), tc.sets);

    // A malformed date-time (month 13, BCD digit 0xA, short payload, wrong
    // return code) is refused and never reaches the setter.
    var r2 = Responder.init(.{ .clock = .{ .ctx = &tc, .now = TestClock.now, .set = TestClock.set } }, &.{});
    const bad = [_][]const u8{
        "0300002702f0803207000004000008000e0001120411470200" ++ "ff09000a00202613191345599875",
        "0300002702f0803207000004000008000e0001120411470200" ++ "ff09000a0020261119134a599875",
        "0300002702f0803207000004000008000e0001120411470200" ++ "ff09000a002026111913455998a5",
        "0300002502f0803207000004000008000c0001120411470200" ++ "ff0900080020261119134559",
        "0300002702f0803207000004000008000e0001120411470200" ++ "0a09000a00202611191345599875",
    };
    inline for (bad) |frame| {
        var fb: [64]u8 = undefined;
        const rep = (try r2.handle(hex(frame, &fb), &out)).?;
        try testing.expectEqualSlices(u8, &[_]u8{ 0xD4, 0x01 }, rep[27..29]);
        try testing.expectEqual(@as(u8, 0x07), rep[29]);
    }
    try testing.expectEqual(@as(usize, 0), tc.sets);

    // An unknown time subfunction is answered with the error too.
    var fb: [64]u8 = undefined;
    const u = (try r2.handle(hex("0300001d02f080320700000300000800040001120411470900" ++ "0a000000", &fb), &out)).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xD4, 0x01 }, u[27..29]);
}

// gos7 (BSD-3, commit 153d631d8881) on the wire against the live responder
// (tools/gos7_client_drive), password "s7live", and the replies gos7 accepted.
const gos7_set_right = "0300002502f0803207000027000008000c0001120411450100" ++ "ff09000826621f5e3c6e491b";
const gos7_set_wrong = "0300002502f0803207000027000008000c0001120411450100" ++ "ff0900083b3a1e0a6b7f1e0a";
const gos7_clear = "0300001d02f0803207000029000008000400011204114502000a000000";

test "security group 5: gos7's requests get the replies gos7 accepted" {
    var r = Responder.init(.{ .password = "s7live" }, &.{});
    var req: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    var want: [64]u8 = undefined;
    var rep = (try r.handle(hex(gos7_set_wrong, &req), &out)).?;
    try testing.expectEqualSlices(u8, hex("0300002102f080320700002700000c000400011208128501000000d6020a000000", &want), rep);
    try testing.expect(!r.legitimated);
    rep = (try r.handle(hex(gos7_set_right, &req), &out)).?;
    try testing.expectEqualSlices(u8, hex("0300002102f080320700002700000c0004000112081285010000000000ff090000", &want), rep);
    try testing.expect(r.legitimated);
    // A wrong password after a right one withdraws the legitimation.
    _ = (try r.handle(hex(gos7_set_wrong, &req), &out)).?;
    try testing.expect(!r.legitimated);
    _ = (try r.handle(hex(gos7_set_right, &req), &out)).?;
    rep = (try r.handle(hex(gos7_clear, &req), &out)).?;
    try testing.expectEqualSlices(u8, hex("0300002102f080320700002900000c0004000112081285020000000000ff090000", &want), rep);
    try testing.expect(!r.legitimated);
}

test "security group 5: malformed and unknown requests are refused with a reply" {
    var r = Responder.init(.{ .password = "s7live" }, &.{});
    var out: [128]u8 = undefined;
    // Seven octets, eight with a failing return code, a data block cut inside
    // its header: 0xD401 + data_type_inconsistent, never a legitimation.
    const bad = [_][]const u8{
        "0300002402f0803207000027000008000b0001120411450100" ++ "ff09000726621f5e3c6e49",
        "0300002502f0803207000027000008000c0001120411450100" ++ "0a09000826621f5e3c6e491b",
        "0300001b02f080320700002700000800020001120411450100" ++ "ff09",
        // nine octets: the right password plus one
        "0300002602f0803207000027000008000d0001120411450100" ++ "ff09000926621f5e3c6e491b00",
    };
    inline for (bad) |frame| {
        // Each refusal follows a successful login and withdraws it.
        var fr: [64]u8 = undefined;
        _ = (try r.handle(hex(gos7_set_right, &fr), &out)).?;
        try testing.expect(r.legitimated);
        var fb: [64]u8 = undefined;
        const rep = (try r.handle(hex(frame, &fb), &out)).?;
        try testing.expectEqualSlices(u8, &[_]u8{ 0xD4, 0x01 }, rep[27..29]);
        try testing.expectEqual(@as(u8, 0x07), rep[29]);
        try testing.expect(!r.legitimated);
    }
    // The right password as a bit string (transport size 3, 64 bits = 8
    // octets) is a failed set: refused, and the legitimation is dropped.
    // In a frame typed as a response it is refused and changes nothing.
    const Odd = struct { frame: []const u8, keeps: bool };
    inline for ([_]Odd{
        .{ .frame = "0300002502f0803207000027000008000c0001120411450100" ++ "ff03004026621f5e3c6e491b", .keeps = false },
        .{ .frame = "0300002502f0803207000027000008000c0001120411850100" ++ "ff09000826621f5e3c6e491b", .keeps = true },
    }) |o| {
        var fr: [64]u8 = undefined;
        _ = (try r.handle(hex(gos7_set_right, &fr), &out)).?;
        var fb2: [64]u8 = undefined;
        const rep = (try r.handle(hex(o.frame, &fb2), &out)).?;
        try testing.expectEqualSlices(u8, &[_]u8{ 0xD4, 0x01 }, rep[27..29]);
        try testing.expectEqual(o.keeps, r.legitimated);
    }
    {
        // ... and never legitimates on its own.
        var fr: [64]u8 = undefined;
        _ = (try r.handle(hex(gos7_set_wrong, &fr), &out)).?;
        var fb2: [64]u8 = undefined;
        _ = (try r.handle(hex("0300002502f0803207000027000008000c0001120411850100" ++ "ff09000826621f5e3c6e491b", &fb2), &out)).?;
        try testing.expect(!r.legitimated);
    }
    // A legitimation belongs to one connection: a COTP disconnect or a new
    // connect drops it.
    {
        var fr: [64]u8 = undefined;
        _ = (try r.handle(hex(gos7_set_right, &fr), &out)).?;
        try testing.expect(r.legitimated);
        var dr: [16]u8 = undefined;
        try testing.expect((try r.handle(hex("0300000b06800000000100", &dr), &out)) == null);
        try testing.expect(!r.legitimated);
        _ = (try r.handle(hex(gos7_set_right, &fr), &out)).?;
        var cr: [32]u8 = undefined;
        _ = (try r.handle(hex("0300001611e00000000100c0010ac1020100c2020122", &cr), &out)).?;
        try testing.expect(!r.legitimated);
    }
    // An unknown security subfunction.
    var fb: [64]u8 = undefined;
    const u = (try r.handle(hex("0300001d02f0803207000029000008000400011204114503000a000000", &fb), &out)).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 0x85, 0x03 }, u[22..24]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xD4, 0x01 }, u[27..29]);
    try testing.expectEqual(@as(u8, 0x0A), u[29]);
}

test "SZL 0x0232: index 4 only, and only when configured" {
    const szl_0232 = "0300002102f080320700000001000800080001120411440100" ++ "ff09000402320004";
    const szl_0232_idx0 = "0300002102f080320700000001000800080001120411440100" ++ "ff09000402320000";
    var req: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    var want: [64]u8 = undefined;
    var r = Responder.init(.{ .protection = .{ .sch_schal = 2, .sch_par = 3, .sch_rel = 1, .bart_sch = 3, .anl_sch = 2 } }, &.{});
    // The reply gos7's GetProtection accepted (tools/gos7_client_drive).
    const rep = (try r.handle(hex(szl_0232, &req), &out)).?;
    try testing.expectEqualSlices(u8, hex("0300003502f080320700000001000c0018000112081284010000000000ff09001402320004000c0001000400020003000100030002", &want), rep);
    // python-snap7 3.1.0 asks for index 0: not this record.
    const r0 = (try r.handle(hex(szl_0232_idx0, &req), &out)).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xD4, 0x01 }, r0[27..29]);
    var none = Responder.init(.{}, &.{});
    const n = (try none.handle(hex(szl_0232, &req), &out)).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xD4, 0x01 }, n[27..29]);
}

test "clock responder: alternate set subfunction, sequence echo, a clock that returns garbage" {
    var tc: TestClock = .{};
    var r = Responder.init(.{ .clock = .{ .ctx = &tc, .now = TestClock.now, .set = TestClock.set } }, &.{});
    var req: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    // Subfunction 0x04 (set clock, alternate) with sequence number 7.
    const rep = (try r.handle(hex("0300002702f0803207000004000008000e0001120411470407" ++ "ff09000a00202611191345599875", &req), &out)).?;
    try testing.expectEqual(@as(usize, 1), tc.sets);
    try testing.expectEqual(@as(u8, 0x04), rep[23]);
    try testing.expectEqual(@as(u8, 0x07), rep[24]);
    try testing.expectEqual(@as(u8, 0xFF), rep[29]);
    // A clock callback that hands back an invalid date-time: error response,
    // hardware fault return code, no panic.
    tc.now_value.month = 13;
    const bad = (try r.handle(hex(read_clock_req, &req), &out)).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 0xD4, 0x01 }, bad[27..29]);
    try testing.expectEqual(@as(u8, 0x01), bad[29]);
}

test "a Read Var item with count 0 on the bit path does not index past the area" {
    // Regression, wave-2 W2-02. `payloadBytes()` returns `(count + 7) / 8`, so a
    // `.bit` item with `count == 0` wants ZERO octets and the guard
    // `start + want > store.len` is satisfied at `start == store.len` -- after
    // which the `.bit` arm unconditionally read `store[item.byteOffset()]`, one
    // past the end. Wire-controlled and unauthenticated: S7 has no
    // authentication at all, and `doRead` does not require `Setup
    // communication` to have run first, so this frame is the whole attack.
    //
    // The item is `12 0a 10 01 0000 0001 84 000200`: S7ANY, transport size
    // `bit` (0x01), count 0, DB 1, area DB, bit address 0x200 = byte 64 -- one
    // past a 64-octet DB.
    //
    // (The audit's evidence line quotes this frame with a TPKT length octet of
    // `0x2b` and calls it "43 octets". That is wrong on both counts and the
    // frame as printed would have been refused by `tpkt.decode`, whose
    // `total > buf.len` check bites: the frame is 31 octets and its length
    // field is `0x1f`. The item bytes -- the part that carries the defect --
    // are exactly as the audit recorded them.)
    var db: [64]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{}, &areas);
    var in: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    const req = hex("0300001f" ++ "02f080" ++ "320100000001000e0000" ++ "0401" ++
        "120a1001" ++ "0000" ++ "0001" ++ "84" ++ "000200", &in);
    const rep = (try r.handle(req, &out)).?;
    // A refusal, not a payload: the item must come back as a four-octet error
    // entry (`rc, null_size, 00 04`) rather than a success item carrying a byte
    // that was never inside the area.
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ @backingInt(items.ReturnCode.invalid_address), 0x00, 0x00, 0x04 },
        rep[21..],
    );
}

test "F7(a): a read that lands exactly on the end of the area succeeds (positive control)" {
    // A byte-transport read of all 64 octets of a 64-octet DB: start=0,
    // want=64, so `start + want == store.len` exactly.
    var db: [64]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{}, &areas);
    var in: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    // ts=byte(0x02), count=0x0040 (64), db=1, area=DB(0x84), bit address 0.
    const req = hex("0300001f" ++ "02f080" ++ "320100000001000e0000" ++ "0401" ++
        "120a1002" ++ "0040" ++ "0001" ++ "84" ++ "000000", &in);
    const rep = (try r.handle(req, &out)).?;
    try testing.expectEqual(@backingInt(items.ReturnCode.success), rep[21]);
}

test "F7(a): a read that lands one octet past the end of the area is refused, not a stray byte" {
    // Regression: the audit's mutation `start + want > store.len` ->
    // `start + want > store.len + 1` survived the whole suite, because
    // nothing exercised the exact boundary it changes -- `start + want ==
    // store.len + 1`, i.e. reading one octet past a real, non-empty area
    // (the earlier `count == 0` regression only covers `start == store.len`
    // with `want == 0`). Same shape as that test, but a byte-transport read
    // of 65 octets from a 64-octet DB: start=0, want=65.
    var db: [64]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{}, &areas);
    var in: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    // ts=byte(0x02), count=0x0041 (65), db=1, area=DB(0x84), bit address 0.
    const req = hex("0300001f" ++ "02f080" ++ "320100000001000e0000" ++ "0401" ++
        "120a1002" ++ "0041" ++ "0001" ++ "84" ++ "000000", &in);
    const rep = (try r.handle(req, &out)).?;
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ @backingInt(items.ReturnCode.invalid_address), 0x00, 0x00, 0x04 },
        rep[21..],
    );
}

test "F8: a Read Var request too short to parse still gets a typed reply, not silence" {
    // The audit's own capture against a real independent client: a Job with
    // `parameter_length = 1` -- just the function octet (Read Var, 0x04),
    // no item count. `vars.decodeRequest` correctly refuses it
    // (`error.ShortParameters`), but that used to propagate straight out of
    // `handle`, leaving `null` -- no reply at all. The peer that sent this
    // frame timed out waiting for one, and (being a real stack, not this
    // test) treated the whole connection as dead afterwards. An unknown
    // FUNCTION code already got a typed reply (`handleJob`'s `else` arm);
    // a malformed body for a known one now does too.
    var db: [8]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{}, &areas);
    var in: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    const req = hex("03000012" ++ "02f080" ++ "32010000" ++ "0007" ++ "0001" ++ "0000" ++ "04", &in);
    const rep = (try r.handle(req, &out)).?;
    const pdu = try s7.decode((try cotp.decode((try tpkt.decode(rep)).payload)).dt.payload);
    try testing.expectEqual(@as(u16, 7), pdu.header.pdu_reference);
    try testing.expectEqual(s7.ErrorClass.error_on_service_processing, pdu.header.error_class);
    try testing.expectEqual(@as(u8, 0x04), pdu.header.error_code);
}

test "F12: a COTP DT with EOT=0 is a fragment and gets no reply, not processed whole" {
    // Same well-formed Read Var request as the `count == 0` regression
    // above, except the COTP DT header's EOT bit is cleared (TPDU number 3,
    // `02 f0 03` instead of `02 f0 80`) -- the audit's own repro. `cotp.zig`
    // documents this bit as "a peer that clears it is fragmenting, which
    // this implementation refuses to reassemble", but nothing read it:
    // before the fix this single (necessarily incomplete) DT was answered
    // as a complete 29-octet reply.
    var db: [64]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db }};
    var r = Responder.init(.{}, &areas);
    var in: [64]u8 = undefined;
    var out: [128]u8 = undefined;
    const req = hex("0300001f" ++ "02f003" ++ "320100000001000e0000" ++ "0401" ++
        "120a1001" ++ "0000" ++ "0001" ++ "84" ++ "000200", &in);
    try testing.expectEqual(@as(?[]const u8, null), try r.handle(req, &out));
}

test "fuzz: the responder never panics on hostile requests inside a well-formed envelope" {
    // The corpus is generated here from a FIXED PRNG seed rather than written
    // out as literals. This harness's seed format IS its draw schedule — one
    // 64-bit word per knob, four requests deep — so a hand-written seed would
    // be two kilobytes of hex that tells a reader nothing, and a corpus of
    // real S7 frames would be the wrong shape entirely: the frames are BUILT
    // here, not drawn. A fixed PRNG seed keeps the corpus identical on every
    // run, so a failure is reproducible from the source alone.
    var prng = std.Random.DefaultPrng.init(0x5337c0ffee001234);
    var bufs: [8][2048]u8 = undefined;
    var seeds: [8][]const u8 = undefined;
    for (&bufs, &seeds) |*b, *s| {
        prng.random().bytes(b);
        s.* = b;
    }
    try std.testing.fuzz({}, fuzzHandleSmith, .{ .corpus = &seeds });
}

// ── the structure-aware responder harness ───────────────────────────────────
//
// The previous version of this harness fed `smith.bytes()` straight into
// `handle`. That looked like coverage of the responder and was coverage of the
// framing layer only: before control can reach `doRead`, an input has to
// satisfy TPKT (`03 00`, a self-consistent length), COTP (LI, code, class 0),
// the S7 header (`0x32`, a known ROSCTR, and `parameter_length + data_length`
// matching the frame **exactly**), a Read/Write Var function octet and a
// `12 0a 10` S7ANY descriptor whose item count matches the octets present.
// Uniform random bytes clear that with probability ~0 — a 400 s
// coverage-guided run never got past `cotp` — so `doRead`, `doWrite`,
// `applyWrite` and `handleUserdata` had no fuzz coverage at all, and the
// out-of-bounds read in `doRead` (regression test above) sat one well-formed
// packet away from a harness that could never build one.
//
// So the envelope is **built** here rather than guessed, and the fuzzer's
// entropy is spent where the responder makes decisions: the item descriptors
// (transport size, element count, DB number, area, address) and the write
// data block (declared length vs. payload actually present). The framing
// layer keeps its own raw-byte harnesses in `tpkt.zig`, `cotp.zig`, `s7.zig`,
// `vars.zig` and `items.zig`, so nothing is given up by specialising this one.

/// Areas the responder can be asked about: two of them are registered below,
/// the rest must come back as a return code rather than a crash. `counter` and
/// `timer` are in the list because they are the two areas whose address counts
/// elements rather than bits, which is a second address-arithmetic path.
const fuzz_areas = [_]u8{ 0x1C, 0x1D, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87 };

/// The two areas the harness actually registers. Drawn from more often than
/// the full list: an item naming an unregistered area is answered from
/// `find`'s `orelse` arm and never reaches the address arithmetic at all, so
/// spreading the draw uniformly over ten areas spends 80% of the budget on one
/// early return.
const fuzz_bound_areas = [_]u8{ 0x83, 0x84 };

/// Every named request transport size, `bit` (0x01) included — it is the one
/// whose payload length is counted in bits and therefore rounds, which is what
/// made a zero element count degenerate.
const fuzz_sizes = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0F, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 };

/// The sizes a real client actually asks for, weighted up for the same reason.
const fuzz_common_sizes = [_]u8{ 0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08 };

/// Data-block transport sizes, including `null_size` and unknown-to-us values.
const fuzz_data_sizes = [_]u8{ 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09 };

/// A knob draw this harness's SEED can actually steer.
///
/// `Smith`'s ranged draws — `valueRangeAtMost`, `index`, `boolWeighted`, and
/// `value` of any type narrower than 64 bits — read EIGHT input octets as a
/// little-endian u64 and return the range MINIMUM unless that word already lies
/// inside the range. Every knob below used to be one of those, and the effect
/// was not a bias: it was total. Outside `zig build --fuzz` the test runner
/// replays seeds through a `Smith` reading real bytes, and there the request
/// builder produced ONE request — transport size `0x01`, element count 0, DB 0,
/// area `0x1C`, address 0, Setup Communication — for every seed it was ever
/// given, four times over. The comment above about spending the fuzzer's
/// entropy where the responder makes decisions was true of the *design* and
/// false of the *behaviour*.
///
/// `value(u64)` has full-range weights, so `weightsContain` is always true and
/// every input word survives. The reduction is ours.
///
/// Measured, over eight 2 KB seeds and four requests each, by
/// re-running the builder with each of these three helpers switched back to the
/// collapsing draw it replaced: **32 requests built, 1 DISTINCT, and 0 of them
/// accepted by `Responder.handle` — before. 32 built, 32 distinct, 25 accepted
/// with a reply — after.** The harness was not merely narrow: the single
/// request it could build is one `handle` refuses, so `doRead`, `doWrite`,
/// `applyWrite` and `handleUserdata` had no fuzz coverage at all — exactly the
/// hole the comment above was written to close.
///
/// ⛔ This target is NOT a candidate for a `STRUCTURED` fuzz-reach exemption,
/// though it looks like one. It does draw a shape rather than a byte string —
/// but the gate's own remedy for that case is the second in its list, "draw the
/// knob with `value(u64)` and reduce it yourself", and that is a three-function
/// change here. An exemption would have recorded the collapse as acceptable and
/// left the responder untested.
fn drawBelow(smith: anytype, bound: u64) u64 {
    return smith.value(u64) % bound;
}

/// `boolWeighted(num, den - num)` with a draw the seed can steer.
fn drawOdds(smith: anytype, num: u64, den: u64) bool {
    return drawBelow(smith, den) < num;
}

/// `smith.value(T)` for a `T` narrower than 64 bits collapses exactly like a
/// ranged draw: its weights are `0..maxInt(T)`, and `weightsContain` is false
/// for all but a vanishing fraction of the 64-bit words it reads, so it too
/// returned 0. Truncating a full-width `value(u64)` keeps every input word.
fn drawWide(smith: anytype, comptime T: type) T {
    return @truncate(smith.value(u64));
}

/// Writes one 12-octet S7ANY item descriptor. The three-octet prefix is fixed
/// because a wrong one is rejected by `items.Item.decode` before the responder
/// ever sees the item — that refusal is `items.zig`'s harness's job, not this
/// one's.
fn fuzzItemBytes(smith: anytype, out: *[12]u8) void {
    out[0] = 0x12;
    out[1] = 0x0A;
    out[2] = 0x10;
    out[3] = switch (drawBelow(smith, 10)) {
        0...5 => fuzz_common_sizes[@intCast(drawBelow(smith, fuzz_common_sizes.len))],
        6...8 => fuzz_sizes[@intCast(drawBelow(smith, fuzz_sizes.len))],
        else => drawWide(smith, u8),
    };
    // Biased small: that is the region where an item is *accepted* and the
    // bounds arithmetic is what decides the outcome. Zero is deliberately in
    // range — a zero count makes `payloadBytes()` zero for every size.
    const count: u16 = switch (drawBelow(smith, 10)) {
        0...5 => @intCast(drawBelow(smith, 9)),
        6...8 => @intCast(drawBelow(smith, 65)),
        else => drawWide(smith, u16),
    };
    out[4] = @intCast(count >> 8);
    out[5] = @truncate(count);
    // DB 1 is registered; 0 and 2 are not.
    const db: u16 = @intCast(drawBelow(smith, 3));
    out[6] = @intCast(db >> 8);
    out[7] = @truncate(db);
    out[8] = if (drawOdds(smith, 2, 5))
        fuzz_bound_areas[@intCast(drawBelow(smith, fuzz_bound_areas.len))]
    else
        fuzz_areas[@intCast(drawBelow(smith, fuzz_areas.len))];
    // The address is generated the way a client writes one -- a byte offset
    // plus a bit index -- rather than as a raw 24-bit number, and the byte
    // offset is drawn from a range that straddles the end of both 64-octet
    // areas. Uniform over 2^24 the boundary is never hit; uniform over the
    // wire encoding it is hit only by accident.
    const addr: u24 = switch (drawBelow(smith, 10)) {
        0...6 => @as(u24, @intCast(drawBelow(smith, 81))) * 8 + @as(u24, @intCast(drawBelow(smith, 8))),
        7...8 => @intCast(drawBelow(smith, 4097)),
        else => drawWide(smith, u24),
    };
    out[9] = @intCast((addr >> 16) & 0xFF);
    out[10] = @intCast((addr >> 8) & 0xFF);
    out[11] = @truncate(addr);
}

/// Appends one Write Var request data item at `pos`, returning the new
/// position. The declared length is usually the honest one — otherwise the
/// data-block iterator rejects the frame before `applyWrite` runs and the
/// whole request is wasted — but sometimes a lie, which is the case
/// `applyWrite`'s own `value.payload.len < want` guard exists for.
fn fuzzWriteValue(smith: anytype, data: []u8, pos: usize, last: bool) ?usize {
    const ts: items.DataTransportSize = @fromBackingInt(@intCast(fuzz_data_sizes[@intCast(drawBelow(smith, fuzz_data_sizes.len))]));
    const n: usize = @intCast(drawBelow(smith, 33));
    const honest = items.encodeLength(ts, n) catch return null;
    const raw: u16 = if (drawOdds(smith, 7, 8)) honest else drawWide(smith, u16);
    if (pos + 4 + n > data.len) return null;
    data[pos] = 0x00; // a request item's return-code octet is `reserved`
    data[pos + 1] = @backingInt(ts);
    data[pos + 2] = @intCast(raw >> 8);
    data[pos + 3] = @truncate(raw);
    smith.bytes(data[pos + 4 ..][0..n]);
    var p = pos + 4 + n;
    if (n % 2 == 1 and !last) {
        if (p >= data.len) return null;
        data[p] = 0x00;
        p += 1;
    }
    return p;
}

/// Wraps `params` / `data` in a correct COTP-DT + TPKT envelope and an S7
/// header whose two length fields agree with what follows, which is what
/// `s7.decode` insists on.
fn fuzzEnvelope(rosctr: u8, params: []const u8, data: []const u8, out: []u8) ?[]const u8 {
    const total = tpkt.header_len + 3 + 10 + params.len + data.len;
    if (total > out.len or total > 0xFFFF) return null;
    out[0] = 0x03;
    out[1] = 0x00;
    out[2] = @intCast(total >> 8);
    out[3] = @truncate(total);
    out[4] = 0x02; // COTP LI
    out[5] = 0xF0; // DT
    out[6] = 0x80; // TPDU number 0, EOT
    out[7] = 0x32; // S7 protocol id
    out[8] = rosctr;
    out[9] = 0x00; // redundancy identification
    out[10] = 0x00;
    out[11] = 0x00; // PDU reference
    out[12] = 0x01;
    out[13] = @intCast(params.len >> 8);
    out[14] = @truncate(params.len);
    out[15] = @intCast(data.len >> 8);
    out[16] = @truncate(data.len);
    @memcpy(out[17..][0..params.len], params);
    @memcpy(out[17 + params.len ..][0..data.len], data);
    return out[0..total];
}

/// A time-of-day request (group 7): subfunction 1-4 (sometimes anything), a
/// date-time that is valid three times in four and otherwise raw octets, and a
/// payload that is sometimes cut short or carries a failing return code.
fn fuzzClockRequest(smith: anytype, out: []u8) ?[]const u8 {
    var params: [userdata.Param.request_len]u8 = undefined;
    const sub: u8 = if (drawOdds(smith, 7, 8)) @intCast(1 + drawBelow(smith, 4)) else drawWide(smith, u8);
    const p = (userdata.Param{
        .message_type = .request,
        .function_group = .time_functions,
        .subfunction = sub,
        .sequence = drawWide(smith, u8),
    }).encodeRequest(&params) catch return null;
    var payload: [12]u8 = undefined;
    var n: usize = userdata.DateTime.wire_len;
    const dt: userdata.DateTime = .{
        .year = @intCast(1990 + drawBelow(smith, 100)),
        .month = @intCast(1 + drawBelow(smith, 12)),
        .day = @intCast(1 + drawBelow(smith, 28)),
        .hour = @intCast(drawBelow(smith, 24)),
        .minute = @intCast(drawBelow(smith, 60)),
        .second = @intCast(drawBelow(smith, 60)),
        .millisecond = @intCast(drawBelow(smith, 1000)),
        .weekday = @intCast(drawBelow(smith, 8)),
    };
    if (drawOdds(smith, 3, 4)) {
        _ = dt.encode(&payload) catch return null;
        // Maybe damage one octet: a BCD nibble above 9 is the interesting case.
        if (drawOdds(smith, 1, 3)) payload[drawBelow(smith, 10)] = drawWide(smith, u8);
    } else {
        for (payload[0..10]) |*b| b.* = drawWide(smith, u8);
    }
    if (drawOdds(smith, 1, 5)) n = @intCast(drawBelow(smith, 13));
    const rc: u8 = if (drawOdds(smith, 9, 10)) 0xFF else drawWide(smith, u8);
    var data: [20]u8 = undefined;
    const db = userdata.DataBlock.encode(
        @fromBackingInt(@intCast(rc)),
        @fromBackingInt(@intCast(0x09)),
        payload[0..n],
        &data,
    ) catch return null;
    return fuzzEnvelope(0x07, p, db, out);
}

/// A group-5 request: mostly a set-password with the harness's password
/// (`fuzz_password`), maybe damaged or resized, sometimes a clear or an
/// unknown subfunction.
fn fuzzSecurityRequest(smith: anytype, out: []u8) ?[]const u8 {
    var params: [userdata.Param.request_len]u8 = undefined;
    const sub: u8 = if (drawOdds(smith, 7, 8)) @intCast(1 + drawBelow(smith, 2)) else drawWide(smith, u8);
    const p = (userdata.Param{
        .message_type = .request,
        .function_group = .security,
        .subfunction = sub,
        .sequence = drawWide(smith, u8),
    }).encodeRequest(&params) catch return null;
    var payload: [12]u8 = undefined;
    var n: usize = userdata.password_len;
    if (drawOdds(smith, 1, 2)) {
        payload[0..8].* = userdata.encodePassword(fuzz_password);
        if (drawOdds(smith, 1, 3)) payload[drawBelow(smith, 8)] = drawWide(smith, u8);
    } else {
        for (payload[0..8]) |*b| b.* = drawWide(smith, u8);
    }
    if (drawOdds(smith, 1, 5)) {
        n = @intCast(drawBelow(smith, 13));
        for (payload[8..]) |*b| b.* = drawWide(smith, u8);
    }
    const rc: u8 = if (drawOdds(smith, 9, 10)) 0xFF else drawWide(smith, u8);
    var data: [20]u8 = undefined;
    const db = userdata.DataBlock.encode(
        @fromBackingInt(@intCast(rc)),
        @fromBackingInt(@intCast(0x09)),
        payload[0..n],
        &data,
    ) catch return null;
    return fuzzEnvelope(0x07, p, db, out);
}

const fuzz_password = "fz-pw";

/// Builds one request. Returns null when this draw could not be assembled, in
/// which case the caller simply moves on.
fn fuzzRequest(smith: anytype, out: []u8) ?[]const u8 {
    var params: [320]u8 = undefined;
    var data: [640]u8 = undefined;
    var plen: usize = 0;
    var dlen: usize = 0;
    var rosctr: u8 = 0x01; // job

    // Read Var is drawn most often: it is the request with the most
    // wire-controlled arithmetic behind it, and the only one that can be sent
    // with no prior exchange at all.
    switch (drawBelow(smith, 10)) {
        // Setup communication: the negotiated PDU length gates every reply.
        0 => {
            const asked: u16 = if (drawOdds(smith, 3, 4))
                @intCast(drawBelow(smith, 961))
            else
                drawWide(smith, u16);
            params[0] = 0xF0;
            params[1] = 0x00;
            params[2] = 0x00;
            params[3] = 0x01;
            params[4] = 0x00;
            params[5] = 0x01;
            params[6] = @intCast(asked >> 8);
            params[7] = @truncate(asked);
            plen = 8;
        },
        // Read Var / Write Var.
        1...6 => |k| {
            const func: u8 = if (k >= 5) 0x05 else 0x04;
            const n: u8 = @intCast(1 + drawBelow(smith, 12));
            params[0] = func;
            params[1] = n;
            plen = 2;
            var i: u8 = 0;
            while (i < n) : (i += 1) {
                fuzzItemBytes(smith, params[plen..][0..12]);
                plen += 12;
            }
            if (func == 0x05) {
                i = 0;
                while (i < n) : (i += 1) {
                    dlen = fuzzWriteValue(smith, &data, dlen, i + 1 == n) orelse break;
                }
            }
        },
        // PLC control, and — via an arbitrary function octet — `handleJob`'s
        // unrecognised-function arm.
        7 => {
            params[0] = if (drawOdds(smith, 2, 3))
                (if (drawOdds(smith, 1, 2)) @as(u8, 0x29) else 0x28)
            else
                drawWide(smith, u8);
            const tail: usize = @intCast(drawBelow(smith, 25));
            smith.bytes(params[1..][0..tail]);
            plen = 1 + tail;
        },
        // Userdata: half of it is the time-of-day group (7), a sixth the
        // security group (5), the rest Read SZL.
        else => {
            if (drawOdds(smith, 1, 2)) return fuzzClockRequest(smith, out);
            if (drawOdds(smith, 1, 3)) return fuzzSecurityRequest(smith, out);
            rosctr = 0x07;
            const p = (userdata.Param{
                .message_type = @fromBackingInt(@intCast(@as(u4, @truncate(if (drawOdds(smith, 7, 8)) @as(u8, 0) else drawWide(smith, u8))))),
                .function_group = @fromBackingInt(@intCast(@as(u4, @truncate(if (drawOdds(smith, 7, 8)) @as(u8, 4) else drawWide(smith, u8))))),
                .subfunction = if (drawOdds(smith, 7, 8)) 0x01 else drawWide(smith, u8),
            }).encodeRequest(&params) catch return null;
            plen = p.len;
            var payload: [32]u8 = undefined;
            const n: usize = @intCast(drawBelow(smith, 9));
            smith.bytes(payload[0..n]);
            if (n >= 2 and drawOdds(smith, 3, 4)) {
                // Steer the list id onto one the responder implements.
                const known = [_]u16{ 0x0011, 0x0424, 0x0232 };
                const id = known[@intCast(drawBelow(smith, known.len))];
                payload[0] = @intCast(id >> 8);
                payload[1] = @truncate(id);
            }
            const db = userdata.DataBlock.encode(
                @fromBackingInt(@intCast(0xFF)),
                @fromBackingInt(@intCast(0x09)),
                payload[0..n],
                &data,
            ) catch return null;
            dlen = db.len;
        },
    }
    return fuzzEnvelope(rosctr, params[0..plen], data[0..dlen], out);
}

const fz = @import("fuzz_test.zig");
const fuzzHandleMark = fz.Marker(enum { ran, request_built, replied, clock_request, clock_read_ok, clock_set_applied, clock_refused, password_accepted, password_refused });

/// Clock callbacks for the harness: `set` counts the date-times that got
/// through validation, and every such value must satisfy `validate`.
const FuzzClock = struct {
    var sets: usize = 0;
    var bad_set: bool = false;
    fn now(_: ?*anyopaque) userdata.DateTime {
        return .{ .year = 2026, .month = 11, .day = 19, .hour = 13, .minute = 45, .second = 59, .millisecond = 987, .weekday = 5 };
    }
    fn set(_: ?*anyopaque, v: userdata.DateTime) void {
        sets += 1;
        v.validate() catch {
            bad_set = true;
        };
    }
};

fn fuzzHandleSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzHandle(std.testing.Smith, smith, std.testing.allocator);
}

test "fuzz driver: S7COMM_FUZZ (fuzzHandle)" {
    try fz.fuzz_driver.run(fuzzHandle, .{ .prefix = "S7COMM_FUZZ", .name = "s7comm-server-handle" });
}

test "fuzz harness: fuzzHandle, 400 seeds, reaches every outcome" {
    try fuzzHandleMark.reach(fuzzHandle, "s7comm-server-handle", 400);
}

fn fuzzHandle(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    fuzzHandleMark.mark(.ran);
    var storage: [128]u8 = @splat(0);
    var areas = [_]AreaBinding{
        .{ .area = .db, .db_number = 1, .bytes = storage[0..64] },
        .{ .area = .flags, .bytes = storage[64..] },
    };
    var szl: [56]u8 = @splat(0x5A);
    var r = Responder.init(
        .{
            .allow_plc_control = true,
            .szl_0011 = &szl,
            .clock = .{ .now = FuzzClock.now, .set = FuzzClock.set },
            .password = fuzz_password,
            .protection = .{ .sch_schal = 2, .sch_par = 1, .sch_rel = 1, .bart_sch = 1, .anl_sch = 0 },
        },
        &areas,
    );
    var frame_buf: [1024]u8 = undefined;
    var out: [2048]u8 = undefined;
    // Several requests down one connection: `pdu_length` and `stopped` carry
    // across, so a state a single packet cannot reach is still reachable.
    var n: usize = 0;
    while (n < 4) : (n += 1) {
        const frame = fuzzRequest(smith, &frame_buf) orelse continue;
        fuzzHandleMark.mark(.request_built);
        const is_clock = frame.len >= 25 and frame[8] == 0x07 and frame[22] == 0x47;
        const is_set_pw = frame.len >= 25 and frame[8] == 0x07 and frame[22] == 0x45 and frame[23] == 0x01;
        if (is_clock) fuzzHandleMark.mark(.clock_request);
        const sets_before = FuzzClock.sets;
        const reply = r.handle(frame, &out) catch continue;
        if (reply != null) fuzzHandleMark.mark(.replied);
        if (is_set_pw) {
            // Legitimated exactly when the data block carried the encoded
            // password: success, octet string, eight octets.
            const want = userdata.encodePassword(fuzz_password);
            const right = frame.len == 37 and frame[25] == 0xFF and frame[26] == 0x09 and
                frame[27] == 0x00 and frame[28] == 0x08 and std.mem.eql(u8, frame[29..37], &want);
            try testing.expectEqual(right, r.legitimated);
            if (right) fuzzHandleMark.mark(.password_accepted) else fuzzHandleMark.mark(.password_refused);
        }
        if (is_clock) {
            const rep = reply orelse continue;
            // Never a value past validation, whatever the wire said.
            try testing.expect(!FuzzClock.bad_set);
            if (rep.len >= 29 and rep[27] == 0 and rep[28] == 0) {
                if (FuzzClock.sets != sets_before) fuzzHandleMark.mark(.clock_set_applied) else fuzzHandleMark.mark(.clock_read_ok);
            } else if (rep.len >= 29) {
                fuzzHandleMark.mark(.clock_refused);
                // A refusal must not have applied a set.
                try testing.expectEqual(sets_before, FuzzClock.sets);
            }
        }
    }
}
