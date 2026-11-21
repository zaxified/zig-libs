// SPDX-License-Identifier: MIT

//! File transfer (type ids 120-127, IEC 60870-5-101 §7.3.4 as carried by
//! IEC 60870-5-104): two sans-I/O state machines, `Sender` (the side that has
//! the file) and `Receiver` (the side that collects it). Both work in either
//! direction of the link: a controlling station reads a file from an
//! outstation, or sends one to it; which station plays which part is the
//! caller's choice (`client.zig` and `outstation.zig` wire them in).
//!
//! The engines read and build whole ASDUs and touch no clock, socket or heap:
//!
//! ```text
//! try engine.onAsdu(decoded_asdu);            // a received file ASDU
//! while (try engine.next(&buf)) |asdu| send(asdu);   // what it wants to say
//! ```
//!
//! The monitor-direction exchange (the same in the other direction with the
//! roles of master and outstation swapped):
//!
//! ```text
//! receiver                         sender
//!   F_SC select file  ----------->
//!                     <-----------  F_FR file ready (length)
//!   F_SC call file    ----------->
//!                     <-----------  F_SR section ready (n, length)
//!   F_SC call section ----------->
//!                     <-----------  F_SG segment ... (1..240 octets, 236 under 104 widths)
//!                     <-----------  F_LS last segment (section checksum)
//!   F_AF ack section  ----------->  (next section: F_SR again)
//!                     <-----------  F_LS last section (file checksum)
//!   F_AF ack file     ----------->
//! ```
//!
//! The checksum of a section is the sum of its data octets modulo 256, the
//! file's the sum of all of them. A directory is one `F_DR_TA_1` per file,
//! the last flagged LFD, answered to an `F_SC_NA_1` with NOF 0 (or to a query
//! log, `F_SC_NB_1`, restricted to a time range). All file ASDUs carry cause
//! 13 (file transfer) except the directory call and its answer (cause 5).
//!
//! What is not here: timeouts (the caller's: an idle transfer is dropped with
//! `abort`), delete file, subdirectories, concurrent transfers (one at a time
//! per engine), and a memory model: files are what the `Source` and the
//! `Sink` say they are.

const std = @import("std");
const asdu = @import("asdu.zig");
const info = @import("info.zig");

/// One directory entry (`F_DR_TA_1`).
pub const DirEntry = struct {
    nof: u16,
    length: u32,
    sof: info.Sof = .{},
    time: info.CP56Time2a = .{},
};

/// Where a `Sender` gets its files.
pub const Source = struct {
    ctx: ?*anyopaque = null,
    /// Directory entry `index` (0-based), or null past the end. File 0 is
    /// reserved for "the directory" and must not be listed.
    entryFn: *const fn (ctx: ?*anyopaque, index: usize) ?DirEntry,
    /// Copies up to `out.len` octets of file `nof` from `offset` and returns
    /// how many it copied; fewer than asked inside the file's length aborts
    /// the transfer.
    readFn: *const fn (ctx: ?*anyopaque, nof: u16, offset: u32, out: []u8) usize,

    fn find(self: Source, nof: u16) ?DirEntry {
        var i: usize = 0;
        while (self.entryFn(self.ctx, i)) |e| : (i += 1) {
            if (e.nof == nof) return e;
        }
        return null;
    }
};

/// Where a `Receiver` puts what arrives.
pub const Sink = struct {
    ctx: ?*anyopaque = null,
    /// A file of `length` octets is announced; false refuses it (memory).
    beginFn: *const fn (ctx: ?*anyopaque, nof: u16, length: u32) bool,
    /// The next octets of the file, in order, at `offset`; false aborts.
    writeFn: *const fn (ctx: ?*anyopaque, nof: u16, offset: u32, data: []const u8) bool,
    /// The transfer ended; `ok` is true only when length and checksum agreed.
    endFn: *const fn (ctx: ?*anyopaque, nof: u16, ok: bool) void,
};

/// How a transfer ended.
pub const Result = struct {
    kind: Kind,
    /// The error code that came with an abort (`default` when none did).
    err: info.FileError = .default,

    pub const Kind = enum {
        /// Both checksums agreed and the file was acknowledged.
        completed,
        /// The peer refused it: negative file ready, section not ready.
        refused,
        /// The peer ended it: negative acknowledgement, deactivation.
        peer_aborted,
        /// This side ended it: a checksum, a length, a sink or a source failed.
        local_abort,
    };
};

pub const Config = struct {
    params: asdu.Params = asdu.default_params,
    /// The common address stamped into every ASDU.
    common_address: u16,
    /// The information object address of the file service (0 by convention).
    ioa: u32 = 0,
    originator: u8 = 0,
};

fn build(cfg: Config, t: asdu.TypeId, cot: asdu.Cot, element: asdu.Element, time: asdu.TimeTag, out: []u8) asdu.Error![]u8 {
    return asdu.buildSingle(out, cfg.params, t, .{ .cot = cot, .originator = cfg.originator }, cfg.common_address, cfg.ioa, element, time);
}

/// The directory call: `F_SC_NA_1`, cause 5, NOF 0.
pub fn buildDirectoryRequest(cfg: Config, out: []u8) asdu.Error![]u8 {
    return build(cfg, .f_sc_na_1, .request, .{ .file_call = .{ .nof = 0, .nos = 0, .scq = .{} } }, .none, out);
}

/// The log query: `F_SC_NB_1`, cause 5, for the files of one time range.
pub fn buildQueryLog(cfg: Config, nof: u16, start: info.CP56Time2a, stop: info.CP56Time2a, out: []u8) asdu.Error![]u8 {
    return build(cfg, .f_sc_nb_1, .request, .{ .query_log = .{ .nof = nof, .range_start = start, .range_stop = stop } }, .none, out);
}

fn firstObject(a: asdu.Asdu) asdu.Error!asdu.Object {
    var it = a.objects();
    return (try it.next()) orelse error.ZeroObjectCount;
}

fn sumOf(data: []const u8) u8 {
    var s: u8 = 0;
    for (data) |b| s +%= b;
    return s;
}

// ── sender ──────────────────────────────────────────────────────────────────

pub const Sender = struct {
    cfg: Config,
    source: Source,
    /// Target length of a section; raised when the file would need more than
    /// the 255 sections a section number can count.
    section_len: u32 = 1920,
    /// Octets per segment, at most `asdu.maxSegmentLen(cfg.params)` (`init` sets it).
    segment_len: u8 = 0,
    phase: Phase = .idle,
    result: ?Result = null,

    nof: u16 = 0,
    nos: u8 = 0,
    file_len: u32 = 0,
    sec_size: u32 = 0,
    sec_start: u32 = 0,
    sec_len: u32 = 0,
    sent: u32 = 0,
    sec_sum: u8 = 0,
    file_sum: u8 = 0,
    pending: Pending = .none,

    pub const Phase = enum { idle, selected, called, sending, await_section_ack, await_file_ack };

    const Refusal = struct { nof: u16, nos: u8, err: info.FileError, section: bool };
    const Pending = union(enum) {
        none,
        file_ready: bool,
        section_ready,
        segments,
        last_section,
        last_file,
        refuse: Refusal,
        directory: Dir,
    };
    const Dir = struct { index: usize, range: ?struct { start: info.CP56Time2a, stop: info.CP56Time2a } };

    pub fn init(cfg: Config, source: Source) Sender {
        return .{ .cfg = cfg, .source = source, .segment_len = @intCast(asdu.maxSegmentLen(cfg.params)) };
    }

    /// True while a transfer is in progress or something is still to be sent.
    pub fn busy(self: *const Sender) bool {
        return self.phase != .idle or self.pending != .none;
    }

    /// Drops the transfer in progress (a timeout, a closed link).
    pub fn abort(self: *Sender) void {
        self.phase = .idle;
        self.pending = .none;
    }

    /// The sender announces a file on its own (`F_FR_NA_1`); the receiver then
    /// calls it. False when there is no such file or a transfer is running.
    pub fn offer(self: *Sender, nof: u16) bool {
        if (self.busy()) return false;
        const e = self.source.find(nof) orelse return false;
        self.begin(e);
        self.pending = .{ .file_ready = true };
        return true;
    }

    fn begin(self: *Sender, e: DirEntry) void {
        self.nof = e.nof;
        self.file_len = e.length;
        self.file_sum = 0;
        self.result = null;
        // Sections are as large as `section_len`, larger when 255 would not do.
        const need = (e.length + 254) / 255;
        self.sec_size = @min(@max(self.section_len, need, 1), 0xFF_FFFF);
        self.phase = .selected;
    }

    fn sections(self: *const Sender) u32 {
        return @max(1, (self.file_len + self.sec_size - 1) / self.sec_size);
    }

    fn setSection(self: *Sender, n: u8) void {
        self.nos = n;
        self.sec_start = (@as(u32, n) - 1) * self.sec_size;
        self.sec_len = if (self.sec_start >= self.file_len) 0 else @min(self.sec_size, self.file_len - self.sec_start);
        self.sent = 0;
        self.sec_sum = 0;
    }

    fn refuse(self: *Sender, nof: u16, nos: u8, err: info.FileError, section: bool) void {
        self.phase = .idle;
        self.pending = .{ .refuse = .{ .nof = nof, .nos = nos, .err = err, .section = section } };
    }

    /// Feeds one received ASDU: `F_SC_NA_1`, `F_AF_NA_1` or `F_SC_NB_1`.
    /// Anything else is `error.UnsupportedTypeId`.
    pub fn onAsdu(self: *Sender, a: asdu.Asdu) asdu.Error!void {
        const o = try firstObject(a);
        switch (a.header.type_id) {
            .f_sc_na_1 => try self.onCall(o.element.file_call),
            .f_af_na_1 => self.onAck(o.element.file_ack),
            .f_sc_nb_1 => {
                if (self.busy()) return self.refuse(o.element.query_log.nof, 0, .unexpected_service, false);
                const q = o.element.query_log;
                self.pending = .{ .directory = .{ .index = 0, .range = .{ .start = q.range_start, .stop = q.range_stop } } };
            },
            else => return error.UnsupportedTypeId,
        }
    }

    fn onCall(self: *Sender, c: anytype) asdu.Error!void {
        const scq = c.scq;
        if (c.nof == 0 and scq.action == .default) {
            if (self.busy()) return self.refuse(0, 0, .unexpected_service, false);
            self.pending = .{ .directory = .{ .index = 0, .range = null } };
            return;
        }
        switch (scq.action) {
            .select_file => {
                if (self.phase != .idle and self.phase != .selected) return self.refuse(c.nof, 0, .unexpected_service, false);
                const e = self.source.find(c.nof) orelse {
                    self.phase = .idle;
                    self.pending = .{ .file_ready = false };
                    self.nof = c.nof;
                    self.file_len = 0;
                    return;
                };
                self.begin(e);
                self.pending = .{ .file_ready = true };
            },
            .request_file => {
                switch (self.phase) {
                    .idle => {
                        const e = self.source.find(c.nof) orelse return self.refuse(c.nof, 0, .unexpected_file_name, false);
                        self.begin(e);
                    },
                    .selected => if (c.nof != self.nof) return self.refuse(c.nof, 0, .unexpected_file_name, false),
                    else => return self.refuse(c.nof, 0, .unexpected_service, false),
                }
                self.phase = .called;
                self.setSection(1);
                self.pending = .section_ready;
            },
            .request_section => {
                if (self.phase != .called) return self.refuse(c.nof, c.nos, .unexpected_service, true);
                if (c.nof != self.nof) return self.refuse(c.nof, c.nos, .unexpected_file_name, true);
                if (c.nos != self.nos) return self.refuse(c.nof, c.nos, .unexpected_section_name, true);
                self.phase = .sending;
                self.pending = .segments;
            },
            .deactivate_file, .deactivate_section => {
                self.abort();
                self.result = .{ .kind = .peer_aborted };
            },
            else => self.refuse(c.nof, c.nos, .unexpected_service, false),
        }
    }

    fn onAck(self: *Sender, f: anytype) void {
        switch (f.afq.action) {
            .positive_section => {
                if (self.phase != .await_section_ack or f.nof != self.nof or f.nos != self.nos)
                    return self.refuse(f.nof, f.nos, .unexpected_service, true);
                if (self.nos < self.sections()) {
                    self.phase = .called;
                    self.setSection(self.nos + 1);
                    self.pending = .section_ready;
                } else {
                    self.phase = .await_file_ack;
                    self.pending = .last_file;
                }
            },
            .positive_file => {
                if (self.phase != .await_file_ack or f.nof != self.nof)
                    return self.refuse(f.nof, f.nos, .unexpected_service, false);
                self.phase = .idle;
                self.result = .{ .kind = .completed };
            },
            .negative_file, .negative_section => {
                self.abort();
                self.result = .{ .kind = .peer_aborted, .err = f.afq.err };
            },
            else => self.refuse(f.nof, f.nos, .unexpected_service, false),
        }
    }

    /// The next ASDU to send, built into `out`, or null when there is nothing
    /// to say until the peer answers.
    pub fn next(self: *Sender, out: []u8) asdu.Error!?[]u8 {
        const cfg = self.cfg;
        switch (self.pending) {
            .none => return null,
            .file_ready => |positive| {
                self.pending = .none;
                return try build(cfg, .f_fr_na_1, .file_transfer, .{ .file_ready = .{
                    .nof = self.nof,
                    .length = if (positive) self.file_len else 0,
                    .frq = .{ .negative = !positive },
                } }, .none, out);
            },
            .section_ready => {
                self.pending = .none;
                return try build(cfg, .f_sr_na_1, .file_transfer, .{ .section_ready = .{
                    .nof = self.nof,
                    .nos = self.nos,
                    .length = self.sec_len,
                    .srq = .{},
                } }, .none, out);
            },
            .segments => {
                const left = self.sec_len - self.sent;
                if (left == 0) {
                    self.pending = .last_section;
                    return try self.next(out);
                }
                var buf: [asdu.max_segment_len]u8 = undefined;
                const n: usize = @min(left, @min(@max(self.segment_len, 1), asdu.maxSegmentLen(cfg.params)));
                const got = self.source.readFn(self.source.ctx, self.nof, self.sec_start + self.sent, buf[0..n]);
                if (got != n) {
                    self.refuse(self.nof, self.nos, .unexpected_service, true);
                    return try self.next(out);
                }
                self.sec_sum +%= sumOf(buf[0..n]);
                self.sent += @intCast(n);
                if (self.sent == self.sec_len) self.pending = .last_section;
                return try build(cfg, .f_sg_na_1, .file_transfer, .{ .file_segment = .{
                    .nof = self.nof,
                    .nos = self.nos,
                    .data = buf[0..n],
                } }, .none, out);
            },
            .last_section => {
                self.pending = .none;
                self.phase = .await_section_ack;
                self.file_sum +%= self.sec_sum;
                return try build(cfg, .f_ls_na_1, .file_transfer, .{ .file_last = .{
                    .nof = self.nof,
                    .nos = self.nos,
                    .lsq = .section_transfer_without_deactivation,
                    .checksum = self.sec_sum,
                } }, .none, out);
            },
            .last_file => {
                self.pending = .none;
                return try build(cfg, .f_ls_na_1, .file_transfer, .{ .file_last = .{
                    .nof = self.nof,
                    .nos = self.nos,
                    .lsq = .file_transfer_without_deactivation,
                    .checksum = self.file_sum,
                } }, .none, out);
            },
            .refuse => |r| {
                self.pending = .none;
                self.phase = .idle;
                self.result = .{ .kind = .local_abort, .err = r.err };
                return try build(cfg, .f_af_na_1, .file_transfer, .{ .file_ack = .{
                    .nof = r.nof,
                    .nos = r.nos,
                    .afq = .{ .action = if (r.section) .negative_section else .negative_file, .err = r.err },
                } }, .none, out);
            },
            .directory => |d| return try self.nextDirectory(d, out),
        }
    }

    fn inRange(d: Dir, e: DirEntry) bool {
        const r = d.range orelse return true;
        return timeKey(e.time) >= timeKey(r.start) and timeKey(e.time) <= timeKey(r.stop);
    }

    /// Next entry at or after `from` that the query selects.
    fn nextMatch(self: *const Sender, d: Dir, from: usize) ?struct { index: usize, entry: DirEntry } {
        var i = from;
        while (self.source.entryFn(self.source.ctx, i)) |e| : (i += 1) {
            if (e.nof != 0 and inRange(d, e)) return .{ .index = i, .entry = e };
        }
        return null;
    }

    fn nextDirectory(self: *Sender, d: Dir, out: []u8) asdu.Error!?[]u8 {
        const cfg = self.cfg;
        const m = self.nextMatch(d, d.index) orelse {
            // Nothing (more) to list: an empty directory is one empty entry
            // flagged as the last, a listed one was already closed with LFD.
            self.pending = .none;
            if (d.index != 0) return null;
            return try build(cfg, .f_dr_ta_1, .request, .{ .file_directory = .{
                .nof = 0,
                .length = 0,
                .sof = .{ .last_file = true },
            } }, .{ .cp56 = .{} }, out);
        };
        const last = self.nextMatch(d, m.index + 1) == null;
        var sof = m.entry.sof;
        sof.last_file = last;
        if (last) self.pending = .none else self.pending = .{ .directory = .{ .index = m.index + 1, .range = d.range } };
        return try build(cfg, .f_dr_ta_1, .request, .{ .file_directory = .{
            .nof = m.entry.nof,
            .length = m.entry.length,
            .sof = sof,
        } }, .{ .cp56 = m.entry.time }, out);
    }
};

/// Orders CP56Time2a values (the day of week and the flags do not count).
fn timeKey(t: info.CP56Time2a) u64 {
    return ((((@as(u64, t.year) * 13 + t.month) * 32 + t.day) * 24 + t.hour) * 60 + t.minute) * 60_000 +
        @as(u64, t.second) * 1000 + t.millisecond;
}

// ── receiver ────────────────────────────────────────────────────────────────

pub const Receiver = struct {
    cfg: Config,
    sink: Sink,
    phase: Phase = .idle,
    result: ?Result = null,

    nof: u16 = 0,
    file_len: u32 = 0,
    exp_nos: u8 = 1,
    sec_len: u32 = 0,
    got: u32 = 0,
    total: u32 = 0,
    sec_sum: u8 = 0,
    file_sum: u8 = 0,
    began: bool = false,
    pending: Pending = .none,

    pub const Phase = enum { idle, wait_ready, wait_section, receiving };

    const Pending = union(enum) {
        none,
        call: struct { action: info.ScqAction, nos: u8 },
        ack: struct { action: info.AfqAction, nos: u8, err: info.FileError },
    };

    pub fn init(cfg: Config, sink: Sink) Receiver {
        return .{ .cfg = cfg, .sink = sink };
    }

    pub fn busy(self: *const Receiver) bool {
        return self.phase != .idle or self.pending != .none;
    }

    /// Starts reading file `nof` from the peer: sends the select. False when a
    /// transfer is running.
    pub fn fetch(self: *Receiver, nof: u16) bool {
        if (self.busy()) return false;
        self.nof = nof;
        self.result = null;
        self.began = false;
        self.phase = .wait_ready;
        self.pending = .{ .call = .{ .action = .select_file, .nos = 0 } };
        return true;
    }

    /// Drops the transfer in progress (a timeout, a closed link); the sink
    /// hears `end(false)`.
    pub fn abort(self: *Receiver) void {
        if (self.phase != .idle) self.finish(.local_abort, .default);
        self.pending = .none;
    }

    fn finish(self: *Receiver, kind: Result.Kind, err: info.FileError) void {
        self.result = .{ .kind = kind, .err = err };
        if (self.began) self.sink.endFn(self.sink.ctx, self.nof, kind == .completed);
        self.began = false;
        self.phase = .idle;
    }

    fn refuse(self: *Receiver, nos: u8, section: bool, err: info.FileError) void {
        self.pending = .{ .ack = .{ .action = if (section) .negative_section else .negative_file, .nos = nos, .err = err } };
        self.finish(.local_abort, err);
    }

    /// Feeds one received ASDU: `F_FR_NA_1`, `F_SR_NA_1`, `F_SG_NA_1` or
    /// `F_LS_NA_1`. Other file types are ignored (a directory entry is for the
    /// application), anything else is `error.UnsupportedTypeId`.
    pub fn onAsdu(self: *Receiver, a: asdu.Asdu) asdu.Error!void {
        const o = try firstObject(a);
        switch (a.header.type_id) {
            .f_fr_na_1 => self.onReady(o.element.file_ready),
            .f_sr_na_1 => self.onSection(o.element.section_ready),
            .f_sg_na_1 => self.onSegment(o.element.file_segment),
            .f_ls_na_1 => self.onLast(o.element.file_last),
            .f_af_na_1 => {
                // The sender gave up (a failed source, a refused call): the
                // positive acknowledgements are ours to send, not to receive.
                const f = o.element.file_ack;
                if (self.phase != .idle and (f.afq.action == .negative_file or f.afq.action == .negative_section)) {
                    self.pending = .none;
                    self.finish(.peer_aborted, f.afq.err);
                }
            },
            .f_dr_ta_1, .f_sc_na_1, .f_sc_nb_1 => {},
            else => return error.UnsupportedTypeId,
        }
    }

    fn onReady(self: *Receiver, f: anytype) void {
        // Either the answer to our select, or the peer offering a file.
        if (self.phase == .wait_ready and f.nof != self.nof) return self.refuse(0, false, .unexpected_file_name);
        if (self.phase != .wait_ready and self.phase != .idle) return self.refuse(0, false, .unexpected_service);
        if (f.frq.negative) {
            self.phase = .idle;
            self.result = .{ .kind = .refused };
            return;
        }
        self.nof = f.nof;
        self.file_len = f.length;
        if (!self.sink.beginFn(self.sink.ctx, f.nof, f.length)) {
            self.refuse(0, false, .memory_not_available);
            return;
        }
        self.began = true;
        self.result = null;
        self.total = 0;
        self.file_sum = 0;
        self.exp_nos = 1;
        self.phase = .wait_section;
        self.pending = .{ .call = .{ .action = .request_file, .nos = 0 } };
    }

    fn onSection(self: *Receiver, s: anytype) void {
        if (self.phase != .wait_section) return self.refuse(s.nos, true, .unexpected_service);
        if (s.nof != self.nof) return self.refuse(s.nos, true, .unexpected_file_name);
        if (s.nos != self.exp_nos) return self.refuse(s.nos, true, .unexpected_section_name);
        if (s.srq.not_ready) {
            self.finish(.refused, .default);
            return;
        }
        self.sec_len = s.length;
        self.got = 0;
        self.sec_sum = 0;
        self.phase = .receiving;
        self.pending = .{ .call = .{ .action = .request_section, .nos = s.nos } };
    }

    fn onSegment(self: *Receiver, g: anytype) void {
        if (self.phase != .receiving) return self.refuse(g.nos, true, .unexpected_service);
        if (g.nof != self.nof) return self.refuse(g.nos, true, .unexpected_file_name);
        if (g.nos != self.exp_nos) return self.refuse(g.nos, true, .unexpected_section_name);
        if (g.data.len > self.sec_len - self.got) return self.refuse(g.nos, true, .unexpected_service);
        if (!self.sink.writeFn(self.sink.ctx, self.nof, self.total, g.data)) {
            return self.refuse(g.nos, true, .memory_not_available);
        }
        self.sec_sum +%= sumOf(g.data);
        self.got += @intCast(g.data.len);
        self.total += @intCast(g.data.len);
    }

    fn onLast(self: *Receiver, l: anytype) void {
        switch (l.lsq) {
            .section_transfer_without_deactivation, .section_transfer_with_deactivation => {
                if (self.phase != .receiving) return self.refuse(l.nos, true, .unexpected_service);
                if (l.nof != self.nof) return self.refuse(l.nos, true, .unexpected_file_name);
                if (l.nos != self.exp_nos) return self.refuse(l.nos, true, .unexpected_section_name);
                if (self.got != self.sec_len or l.checksum != self.sec_sum) return self.refuse(l.nos, true, .checksum_failed);
                self.file_sum +%= self.sec_sum;
                self.pending = .{ .ack = .{ .action = .positive_section, .nos = l.nos, .err = .default } };
                self.exp_nos +|= 1;
                self.phase = .wait_section;
            },
            .file_transfer_without_deactivation, .file_transfer_with_deactivation => {
                if (self.phase != .wait_section) return self.refuse(l.nos, false, .unexpected_service);
                if (l.nof != self.nof) return self.refuse(l.nos, false, .unexpected_file_name);
                if (self.total != self.file_len or l.checksum != self.file_sum) return self.refuse(l.nos, false, .checksum_failed);
                self.pending = .{ .ack = .{ .action = .positive_file, .nos = l.nos, .err = .default } };
                self.finish(.completed, .default);
            },
            else => self.refuse(l.nos, false, .unexpected_service),
        }
    }

    /// The next ASDU to send, built into `out`, or null.
    pub fn next(self: *Receiver, out: []u8) asdu.Error!?[]u8 {
        const cfg = self.cfg;
        switch (self.pending) {
            .none => return null,
            .call => |c| {
                self.pending = .none;
                return try build(cfg, .f_sc_na_1, .file_transfer, .{ .file_call = .{
                    .nof = self.nof,
                    .nos = c.nos,
                    .scq = .{ .action = c.action },
                } }, .none, out);
            },
            .ack => |k| {
                self.pending = .none;
                return try build(cfg, .f_af_na_1, .file_transfer, .{ .file_ack = .{
                    .nof = self.nof,
                    .nos = k.nos,
                    .afq = .{ .action = k.action, .err = k.err },
                } }, .none, out);
            },
        }
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const TestFiles = struct {
    names: [3]u16 = .{ 7, 8, 9 },
    data: [3][]const u8,
    times: [3]info.CP56Time2a = .{
        .{ .year = 26, .month = 11, .day = 1 },
        .{ .year = 26, .month = 11, .day = 15, .hour = 10 },
        .{ .year = 26, .month = 12, .day = 2 },
    },
    fail_read_after: ?u32 = null,

    fn source(self: *TestFiles) Source {
        return .{ .ctx = self, .entryFn = entry, .readFn = read };
    }

    fn entry(ctx: ?*anyopaque, i: usize) ?DirEntry {
        const self: *TestFiles = @ptrCast(@alignCast(ctx));
        if (i >= self.names.len) return null;
        return .{ .nof = self.names[i], .length = @intCast(self.data[i].len), .time = self.times[i] };
    }

    fn read(ctx: ?*anyopaque, nof: u16, offset: u32, out: []u8) usize {
        const self: *TestFiles = @ptrCast(@alignCast(ctx));
        for (self.names, 0..) |n, i| {
            if (n != nof) continue;
            if (self.fail_read_after) |lim| if (offset >= lim) return 0;
            const d = self.data[i];
            if (offset >= d.len) return 0;
            const k = @min(out.len, d.len - offset);
            @memcpy(out[0..k], d[offset..][0..k]);
            return k;
        }
        return 0;
    }
};

const TestSink = struct {
    buf: [8192]u8 = undefined,
    len: usize = 0,
    accept: bool = true,
    refuse_write_at: ?u32 = null,
    ended: ?bool = null,
    announced: ?u32 = null,
    writes: usize = 0,

    fn sink(self: *TestSink) Sink {
        return .{ .ctx = self, .beginFn = begin, .writeFn = write, .endFn = end };
    }

    fn begin(ctx: ?*anyopaque, _: u16, length: u32) bool {
        const self: *TestSink = @ptrCast(@alignCast(ctx));
        self.announced = length;
        self.len = 0;
        self.ended = null;
        return self.accept and length <= self.buf.len;
    }

    fn write(ctx: ?*anyopaque, _: u16, offset: u32, data: []const u8) bool {
        const self: *TestSink = @ptrCast(@alignCast(ctx));
        if (offset != self.len) return false;
        if (self.refuse_write_at) |at| if (offset >= at) return false;
        @memcpy(self.buf[self.len..][0..data.len], data);
        self.len += data.len;
        self.writes += 1;
        return true;
    }

    fn end(ctx: ?*anyopaque, _: u16, ok: bool) void {
        const self: *TestSink = @ptrCast(@alignCast(ctx));
        self.ended = ok;
    }
};

const test_cfg = Config{ .common_address = 5 };

fn pattern(buf: []u8, seed: u8) []u8 {
    for (buf, 0..) |*b, i| b.* = @truncate(i *% 31 +% seed);
    return buf;
}

/// Runs the two engines against each other, recording every ASDU's type id.
fn pump(s: *Sender, r: *Receiver, trace: ?*std.ArrayList(u8)) !void {
    var buf: [asdu.max_segment_len + 32]u8 = undefined;
    var rounds: usize = 0;
    while (rounds < 10_000) : (rounds += 1) {
        var moved = false;
        while (try r.next(&buf)) |b| {
            moved = true;
            if (trace) |t| try t.append(testing.allocator, b[0]);
            try s.onAsdu(try asdu.decode(b, test_cfg.params));
        }
        while (try s.next(&buf)) |b| {
            moved = true;
            if (trace) |t| try t.append(testing.allocator, b[0]);
            try r.onAsdu(try asdu.decode(b, test_cfg.params));
        }
        if (!moved) return;
    }
    return error.TestUnexpectedResult;
}

test "a file of three sections arrives whole: select, call, sections, segments, acknowledgements" {
    var d0: [100]u8 = undefined;
    var d1: [5000]u8 = undefined;
    var d2: [0]u8 = undefined;
    var files = TestFiles{ .data = .{ pattern(&d0, 1), pattern(&d1, 2), &d2 } };
    var sink = TestSink{};
    var s = Sender.init(test_cfg, files.source());
    s.section_len = 2000;
    var r = Receiver.init(test_cfg, sink.sink());
    try testing.expect(r.fetch(8));
    var trace: std.ArrayList(u8) = .empty;
    defer trace.deinit(testing.allocator);
    try pump(&s, &r, &trace);
    try testing.expectEqual(Result.Kind.completed, r.result.?.kind);
    try testing.expectEqual(Result.Kind.completed, s.result.?.kind);
    try testing.expectEqual(@as(?bool, true), sink.ended);
    try testing.expectEqualSlices(u8, files.data[1], sink.buf[0..sink.len]);
    try testing.expect(!s.busy() and !r.busy());
    // The conversation: select, ready, call, then per section (section ready,
    // call section, segments, last segment, ack), last section, ack file.
    try testing.expectEqual(@as(u8, 122), trace.items[0]);
    try testing.expectEqual(@as(u8, 120), trace.items[1]);
    try testing.expectEqual(@as(u8, 122), trace.items[2]);
    try testing.expectEqual(@as(u8, 121), trace.items[3]);
    var segs: usize = 0;
    var lasts: usize = 0;
    var acks: usize = 0;
    for (trace.items) |t| {
        if (t == 125) segs += 1;
        if (t == 123) lasts += 1;
        if (t == 124) acks += 1;
    }
    // 5000 octets in sections of 2000/2000/1000, segments of 236.
    try testing.expectEqual(@as(usize, 9 + 9 + 5), segs);
    try testing.expectEqual(@as(usize, 4), lasts); // three sections and the file
    try testing.expectEqual(@as(usize, 4), acks);
}

test "empty file and a file that fills its sections exactly" {
    var d0: [480]u8 = undefined;
    var files = TestFiles{ .data = .{ pattern(&d0, 9), &.{}, &.{} } };
    var sink = TestSink{};
    var s = Sender.init(test_cfg, files.source());
    s.section_len = 240;
    var r = Receiver.init(test_cfg, sink.sink());
    try testing.expect(r.fetch(7));
    try pump(&s, &r, null);
    try testing.expectEqual(Result.Kind.completed, r.result.?.kind);
    try testing.expectEqualSlices(u8, files.data[0], sink.buf[0..sink.len]);
    try testing.expect(r.fetch(8));
    try pump(&s, &r, null);
    try testing.expectEqual(Result.Kind.completed, r.result.?.kind);
    try testing.expectEqual(@as(usize, 0), sink.len);
}

test "the sender can announce a file, and the receiver calls it" {
    var d0: [300]u8 = undefined;
    var files = TestFiles{ .data = .{ pattern(&d0, 4), &.{}, &.{} } };
    var sink = TestSink{};
    var s = Sender.init(test_cfg, files.source());
    var r = Receiver.init(test_cfg, sink.sink());
    try testing.expect(s.offer(7));
    try testing.expect(!s.offer(7));
    var other = Sender.init(test_cfg, files.source());
    try testing.expect(!other.offer(99));
    try pump(&s, &r, null);
    try testing.expectEqual(Result.Kind.completed, r.result.?.kind);
    try testing.expectEqualSlices(u8, files.data[0], sink.buf[0..sink.len]);
}

test "refusals: unknown file, a sink without room, a negative ready" {
    var d0: [300]u8 = undefined;
    var files = TestFiles{ .data = .{ pattern(&d0, 4), &.{}, &.{} } };
    var sink = TestSink{};
    var s = Sender.init(test_cfg, files.source());
    var r = Receiver.init(test_cfg, sink.sink());
    try testing.expect(r.fetch(42));
    try pump(&s, &r, null);
    try testing.expectEqual(Result.Kind.refused, r.result.?.kind);
    try testing.expect(!r.busy() and !s.busy());

    sink.accept = false;
    try testing.expect(r.fetch(7));
    try pump(&s, &r, null);
    try testing.expectEqual(Result.Kind.local_abort, r.result.?.kind);
    try testing.expectEqual(info.FileError.memory_not_available, r.result.?.err);
    try testing.expectEqual(Result.Kind.peer_aborted, s.result.?.kind);
    try testing.expectEqual(info.FileError.memory_not_available, s.result.?.err);
    try testing.expect(!s.busy() and !r.busy());
}

test "a failing sink or source aborts the transfer on both sides" {
    var d0: [1000]u8 = undefined;
    var files = TestFiles{ .data = .{ pattern(&d0, 4), &.{}, &.{} } };
    var sink = TestSink{ .refuse_write_at = 480 };
    var s = Sender.init(test_cfg, files.source());
    var r = Receiver.init(test_cfg, sink.sink());
    try testing.expect(r.fetch(7));
    try pump(&s, &r, null);
    try testing.expectEqual(Result.Kind.local_abort, r.result.?.kind);
    try testing.expectEqual(@as(?bool, false), sink.ended);
    try testing.expectEqual(Result.Kind.peer_aborted, s.result.?.kind);

    sink.refuse_write_at = null;
    files.fail_read_after = 480;
    try testing.expect(r.fetch(7));
    try pump(&s, &r, null);
    try testing.expectEqual(Result.Kind.local_abort, s.result.?.kind);
    try testing.expectEqual(Result.Kind.peer_aborted, r.result.?.kind);
}

fn feedType(s: anytype, t: asdu.TypeId, cot: asdu.Cot, e: asdu.Element, time: asdu.TimeTag) !void {
    var buf: [64]u8 = undefined;
    const b = try asdu.buildSingle(&buf, test_cfg.params, t, .{ .cot = cot }, 5, 0, e, time);
    try s.onAsdu(try asdu.decode(b, test_cfg.params));
}

test "a damaged checksum is refused with the checksum error and nothing is kept as complete" {
    var sink = TestSink{};
    var r = Receiver.init(test_cfg, sink.sink());
    try testing.expect(r.fetch(7));
    var out: [64]u8 = undefined;
    _ = try r.next(&out);
    try feedType(&r, .f_fr_na_1, .file_transfer, .{ .file_ready = .{ .nof = 7, .length = 3, .frq = .{} } }, .none);
    _ = try r.next(&out);
    try feedType(&r, .f_sr_na_1, .file_transfer, .{ .section_ready = .{ .nof = 7, .nos = 1, .length = 3, .srq = .{} } }, .none);
    _ = try r.next(&out);
    try feedType(&r, .f_sg_na_1, .file_transfer, .{ .file_segment = .{ .nof = 7, .nos = 1, .data = "abc" } }, .none);
    try feedType(&r, .f_ls_na_1, .file_transfer, .{ .file_last = .{ .nof = 7, .nos = 1, .lsq = .section_transfer_without_deactivation, .checksum = 0 } }, .none);
    const nak = (try r.next(&out)).?;
    const a = try asdu.decode(nak, test_cfg.params);
    const o = try firstObject(a);
    try testing.expectEqual(info.AfqAction.negative_section, o.element.file_ack.afq.action);
    try testing.expectEqual(info.FileError.checksum_failed, o.element.file_ack.afq.err);
    try testing.expectEqual(@as(?bool, false), sink.ended);
    try testing.expectEqual(Result.Kind.local_abort, r.result.?.kind);
}

test "out-of-order and wrong-name messages never move a transfer forward" {
    var d0: [10]u8 = undefined;
    var files = TestFiles{ .data = .{ pattern(&d0, 4), &.{}, &.{} } };
    var s = Sender.init(test_cfg, files.source());
    var out: [64]u8 = undefined;
    // Call a section with nothing selected.
    try feedType(&s, .f_sc_na_1, .file_transfer, .{ .file_call = .{ .nof = 7, .nos = 1, .scq = .{ .action = .request_section } } }, .none);
    var o = try asdu.decode((try s.next(&out)).?, test_cfg.params);
    try testing.expectEqual(info.AfqAction.negative_section, (try firstObject(o)).element.file_ack.afq.action);
    try testing.expect(!s.busy());
    // Call a file that is not there, a section that is not current, an acknowledgement out of the blue.
    try feedType(&s, .f_sc_na_1, .file_transfer, .{ .file_call = .{ .nof = 99, .nos = 0, .scq = .{ .action = .request_file } } }, .none);
    o = try asdu.decode((try s.next(&out)).?, test_cfg.params);
    try testing.expectEqual(info.FileError.unexpected_file_name, (try firstObject(o)).element.file_ack.afq.err);
    try feedType(&s, .f_sc_na_1, .file_transfer, .{ .file_call = .{ .nof = 7, .nos = 0, .scq = .{ .action = .request_file } } }, .none);
    _ = try s.next(&out);
    try feedType(&s, .f_sc_na_1, .file_transfer, .{ .file_call = .{ .nof = 7, .nos = 2, .scq = .{ .action = .request_section } } }, .none);
    o = try asdu.decode((try s.next(&out)).?, test_cfg.params);
    try testing.expectEqual(info.FileError.unexpected_section_name, (try firstObject(o)).element.file_ack.afq.err);
    try feedType(&s, .f_af_na_1, .file_transfer, .{ .file_ack = .{ .nof = 7, .nos = 1, .afq = .{ .action = .positive_file } } }, .none);
    _ = try s.next(&out);
    try testing.expect(!s.busy());
    try testing.expectError(error.UnsupportedTypeId, s.onAsdu(try asdu.decode(try asdu.buildSingle(&out, test_cfg.params, .c_ic_na_1, .{ .cot = .activation }, 5, 0, .{ .qoi = .station }, .none), test_cfg.params)));
}

test "deactivation ends a transfer in progress without an answer" {
    var d0: [10]u8 = undefined;
    var files = TestFiles{ .data = .{ pattern(&d0, 4), &.{}, &.{} } };
    var s = Sender.init(test_cfg, files.source());
    var out: [64]u8 = undefined;
    try feedType(&s, .f_sc_na_1, .file_transfer, .{ .file_call = .{ .nof = 7, .nos = 0, .scq = .{ .action = .select_file } } }, .none);
    _ = try s.next(&out);
    try testing.expectEqual(Sender.Phase.selected, s.phase);
    try feedType(&s, .f_sc_na_1, .file_transfer, .{ .file_call = .{ .nof = 7, .nos = 0, .scq = .{ .action = .deactivate_file } } }, .none);
    try testing.expect((try s.next(&out)) == null);
    try testing.expectEqual(Sender.Phase.idle, s.phase);
    try testing.expectEqual(Result.Kind.peer_aborted, s.result.?.kind);
}

test "directory: one entry per ASDU, the last flagged; a time range narrows it; an empty one is one empty entry" {
    var d0: [10]u8 = undefined;
    var files = TestFiles{ .data = .{ pattern(&d0, 4), &.{}, &.{} } };
    var s = Sender.init(test_cfg, files.source());
    var out: [64]u8 = undefined;
    try s.onAsdu(try asdu.decode(try buildDirectoryRequest(test_cfg, &out), test_cfg.params));
    var seen: [4]u16 = undefined;
    var last: [4]bool = undefined;
    var n: usize = 0;
    while (try s.next(&out)) |b| : (n += 1) {
        const a = try asdu.decode(b, test_cfg.params);
        try testing.expectEqual(asdu.Cot.request, a.header.cause.cot);
        const o = try firstObject(a);
        seen[n] = o.element.file_directory.nof;
        last[n] = o.element.file_directory.sof.last_file;
        if (n == 0) try testing.expectEqual(@as(u32, 10), o.element.file_directory.length);
        try testing.expectEqual(@as(u8, 26), o.time.cp56.year);
    }
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqualSlices(u16, &[_]u16{ 7, 8, 9 }, seen[0..3]);
    try testing.expectEqualSlices(bool, &[_]bool{ false, false, true }, last[0..3]);

    // Query log: only the files of 10 to 20 November.
    const from: info.CP56Time2a = .{ .year = 26, .month = 11, .day = 10 };
    const to: info.CP56Time2a = .{ .year = 26, .month = 11, .day = 20 };
    try s.onAsdu(try asdu.decode(try buildQueryLog(test_cfg, 0, from, to, &out), test_cfg.params));
    var b = (try s.next(&out)).?;
    var o = try firstObject(try asdu.decode(b, test_cfg.params));
    try testing.expectEqual(@as(u16, 8), o.element.file_directory.nof);
    try testing.expect(o.element.file_directory.sof.last_file);
    try testing.expect((try s.next(&out)) == null);

    // A range with no file in it.
    const none_to: info.CP56Time2a = .{ .year = 26, .month = 11, .day = 11 };
    try s.onAsdu(try asdu.decode(try buildQueryLog(test_cfg, 0, from, none_to, &out), test_cfg.params));
    b = (try s.next(&out)).?;
    o = try firstObject(try asdu.decode(b, test_cfg.params));
    try testing.expectEqual(@as(u16, 0), o.element.file_directory.nof);
    try testing.expect(o.element.file_directory.sof.last_file);
    try testing.expect((try s.next(&out)) == null);
}

test "wire bytes of the file ASDUs (IEC 60870-5-101 §7.3.4 layouts, little-endian lengths)" {
    var out: [300]u8 = undefined;
    // F_FR_NA_1: NOF 0x0102, LOF 0x030405, FRQ 0.
    var b = try asdu.buildSingle(&out, asdu.default_params, .f_fr_na_1, .{ .cot = .file_transfer }, 1, 0, .{ .file_ready = .{ .nof = 0x0102, .length = 0x030405, .frq = .{} } }, .none);
    try testing.expectEqualSlices(u8, &[_]u8{ 120, 1, 13, 0, 1, 0, 0, 0, 0, 0x02, 0x01, 0x05, 0x04, 0x03, 0 }, b);
    // F_SR_NA_1: NOF, NOS 2, LOS 0x000010, SRQ not ready.
    b = try asdu.buildSingle(&out, asdu.default_params, .f_sr_na_1, .{ .cot = .file_transfer }, 1, 0, .{ .section_ready = .{ .nof = 1, .nos = 2, .length = 16, .srq = .{ .not_ready = true } } }, .none);
    try testing.expectEqualSlices(u8, &[_]u8{ 121, 1, 13, 0, 1, 0, 0, 0, 0, 1, 0, 2, 16, 0, 0, 0x80 }, b);
    // F_SC_NA_1: request section.
    b = try asdu.buildSingle(&out, asdu.default_params, .f_sc_na_1, .{ .cot = .file_transfer }, 1, 0, .{ .file_call = .{ .nof = 1, .nos = 2, .scq = .{ .action = .request_section } } }, .none);
    try testing.expectEqualSlices(u8, &[_]u8{ 122, 1, 13, 0, 1, 0, 0, 0, 0, 1, 0, 2, 6 }, b);
    // F_LS_NA_1 and F_AF_NA_1.
    b = try asdu.buildSingle(&out, asdu.default_params, .f_ls_na_1, .{ .cot = .file_transfer }, 1, 0, .{ .file_last = .{ .nof = 1, .nos = 2, .lsq = .section_transfer_without_deactivation, .checksum = 0xAB } }, .none);
    try testing.expectEqualSlices(u8, &[_]u8{ 123, 1, 13, 0, 1, 0, 0, 0, 0, 1, 0, 2, 3, 0xAB }, b);
    b = try asdu.buildSingle(&out, asdu.default_params, .f_af_na_1, .{ .cot = .file_transfer }, 1, 0, .{ .file_ack = .{ .nof = 1, .nos = 2, .afq = .{ .action = .negative_section, .err = .checksum_failed } } }, .none);
    try testing.expectEqualSlices(u8, &[_]u8{ 124, 1, 13, 0, 1, 0, 0, 0, 0, 1, 0, 2, 0x24 }, b);
    // F_SG_NA_1 carries its length.
    b = try asdu.buildSingle(&out, asdu.default_params, .f_sg_na_1, .{ .cot = .file_transfer }, 1, 0, .{ .file_segment = .{ .nof = 1, .nos = 2, .data = "xyz" } }, .none);
    try testing.expectEqualSlices(u8, &[_]u8{ 125, 1, 13, 0, 1, 0, 0, 0, 0, 1, 0, 2, 3, 'x', 'y', 'z' }, b);
    // F_DR_TA_1: NOF, LOF, SOF, CP56Time2a.
    b = try asdu.buildSingle(&out, asdu.default_params, .f_dr_ta_1, .{ .cot = .request }, 1, 0, .{ .file_directory = .{ .nof = 1, .length = 2, .sof = .{ .last_file = true } } }, .{ .cp56 = .{ .year = 26, .month = 11, .day = 21 } });
    try testing.expectEqualSlices(u8, &[_]u8{ 126, 1, 5, 0, 1, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0x20, 0, 0, 0, 0, 21, 11, 26 }, b);
    // F_SC_NB_1: NOF and the two range limits.
    b = try asdu.buildSingle(&out, asdu.default_params, .f_sc_nb_1, .{ .cot = .request }, 1, 0, .{ .query_log = .{ .nof = 1, .range_start = .{ .year = 26, .month = 1, .day = 1 }, .range_stop = .{ .year = 26, .month = 12, .day = 31 } } }, .none);
    try testing.expectEqual(@as(usize, 9 + 16), b.len);
    try testing.expectEqual(@as(u8, 127), b[0]);
}

test "segment codec: length rules, the 240-octet ceiling and truncation" {
    var out: [300]u8 = undefined;
    var data: [241]u8 = @splat(0xEE);
    try testing.expectError(error.SegmentTooLong, asdu.buildSingle(&out, asdu.default_params, .f_sg_na_1, .{ .cot = .file_transfer }, 1, 0, .{ .file_segment = .{ .nof = 1, .nos = 1, .data = &data } }, .none));
    const ok = try asdu.buildSingle(&out, asdu.default_params, .f_sg_na_1, .{ .cot = .file_transfer }, 1, 0, .{ .file_segment = .{ .nof = 1, .nos = 1, .data = data[0..240] } }, .none);
    try testing.expectEqual(@as(usize, 6 + 3 + 4 + 240), ok.len);
    const a = try asdu.decode(ok, asdu.default_params);
    try testing.expectEqual(@as(usize, 240), (try firstObject(a)).element.file_segment.data.len);
    // The length octet must agree with what follows, either way.
    try testing.expectError(error.ObjectCountMismatch, asdu.decode(ok[0 .. ok.len - 1], asdu.default_params));
    var longer: [260]u8 = undefined;
    @memcpy(longer[0..ok.len], ok);
    longer[ok.len] = 0;
    try testing.expectError(error.ObjectCountMismatch, asdu.decode(longer[0 .. ok.len + 1], asdu.default_params));
    // Two segments in one ASDU, or the sequence layout, are not a thing.
    var b = try asdu.Builder.init(&out, asdu.default_params, .f_sg_na_1, .{ .cot = .file_transfer }, 1, false);
    try b.add(0, .{ .file_segment = .{ .nof = 1, .nos = 1, .data = "a" } }, .none);
    try testing.expectError(error.TooManyObjects, b.add(0, .{ .file_segment = .{ .nof = 1, .nos = 1, .data = "b" } }, .none));
    var q = try asdu.Builder.init(&out, asdu.default_params, .f_sg_na_1, .{ .cot = .file_transfer }, 1, true);
    try testing.expectError(error.TooManyObjects, q.add(0, .{ .file_segment = .{ .nof = 1, .nos = 1, .data = "a" } }, .none));
    // Lengths beyond three octets.
    try testing.expectError(error.FileLengthOutOfRange, asdu.buildSingle(&out, asdu.default_params, .f_fr_na_1, .{ .cot = .file_transfer }, 1, 0, .{ .file_ready = .{ .nof = 1, .length = 0x1000000, .frq = .{} } }, .none));
}

test "fuzz: damaged file ASDUs fed to both engines never panic or hang" {
    var d0: [700]u8 = undefined;
    var files = TestFiles{ .data = .{ pattern(&d0, 4), &.{}, &.{} } };
    var prng = std.Random.DefaultPrng.init(0xF11E);
    const rnd = prng.random();
    const types = [_]u8{ 120, 121, 122, 123, 124, 125, 126, 127 };
    var round: usize = 0;
    while (round < 3000) : (round += 1) {
        var sink = TestSink{};
        var s = Sender.init(test_cfg, files.source());
        var r = Receiver.init(test_cfg, sink.sink());
        if (rnd.boolean()) _ = r.fetch(7);
        var out: [300]u8 = undefined;
        var k: usize = 0;
        while (k < 12) : (k += 1) {
            var raw: [40]u8 = undefined;
            rnd.bytes(&raw);
            raw[0] = types[rnd.uintLessThan(usize, types.len)];
            raw[1] = if (rnd.uintLessThan(u8, 8) == 0) rnd.int(u8) else 1;
            raw[2] = 13;
            raw[3] = 0;
            raw[4] = 5;
            raw[5] = 0;
            const len = 6 + rnd.uintLessThan(usize, 30);
            const a = asdu.decode(raw[0..len], test_cfg.params) catch continue;
            s.onAsdu(a) catch {};
            r.onAsdu(a) catch {};
            while (s.next(&out) catch null) |_| {}
            while (r.next(&out) catch null) |_| {}
        }
    }
}
