// SPDX-License-Identifier: MIT

//! tlsserver.connection — the blocking wrapper: a `Server` driven over a
//! `std.Io.Reader` / `std.Io.Writer` pair (a socket's, or a fiber's).
//!
//! Zero-copy both ways, with no buffer of its own beyond the joiner:
//!
//! - **Receive.** Records are opened in place inside the reader's own
//!   buffer, so `read` returns a slice of it, valid until the next call
//!   that reads. The reader's buffer must hold one whole record
//!   (`record.max_record_len`).
//! - **Send.** Records are framed and sealed in the WRITER's buffer, where
//!   the transport sends them from: the server's output buffer IS
//!   `output.buffer` (size it with `Server.minOutputLen`). The writer must
//!   be stream-shaped — `flush` sends everything and leaves its buffer
//!   empty, in place (a socket's or a file's writer; not `Writer.fixed` or
//!   `Writer.Allocating`, which keep their bytes: `error.WriteFailed`).
//!   Nothing else may write to it while the connection lives.
//!
//! `reader()` and `writer()` are a `std.Io.Reader` / `std.Io.Writer` over
//! the application data with no buffer of their own either: the reader's
//! buffer is the record just opened (where it lies in the input), the
//! writer's is the content of the record it will be sealed in (where it
//! lies in the output). Their one limit is the record: the reader cannot
//! give more contiguous octets than one record holds, the writer cannot
//! keep octets across one (`rebase` with something to preserve) — both
//! fail with `error.RecordBoundary` (in `err`) instead of copying.
//!
//! What the server queues is sent before every read that has to wait, and
//! after the handshake, every `writeAll`, `flush` and `close`. Octets
//! written through `writer()` and not yet flushed are sealed before
//! anything else is queued (a read, a KeyUpdate, `close`), so they keep
//! their place in the stream.
//!
//! An error is final. A refusal's alert is sent (best effort) before the
//! error is returned.
//!
//! **A reader and writers on fibers.** Reading sends too (what the server
//! queued, before a read waits), so a reader and a writer that may park
//! while sending — fibers of one thread, an HTTP/2 stream per fiber — would
//! both send the same queued octets. Give the connection a `Guard` (a
//! mutex that parks): it is held wherever the connection changes or sends
//! its output and released while a read waits for input. Writers must still
//! be serialised among themselves (`writer()` buffers without calling in),
//! and the guard does not make the connection safe across threads: the
//! octets a writer buffers are sealed by whichever side calls in next.

const std = @import("std");
const record = @import("record.zig");
const server_mod = @import("server.zig");

const Server = server_mod.Server;

pub const Error = server_mod.Error || error{
    /// The reader failed (`input`'s own error is the detail).
    ReadFailed,
    /// The writer failed, or kept octets `flush` should have sent (it is
    /// not stream-shaped).
    WriteFailed,
    /// The transport ended before the handshake did, or in the middle of a
    /// record (a truncation: without close_notify).
    EndOfStream,
    /// `reader()` was asked for more contiguous octets than one record
    /// holds, or `writer()` to keep octets across a record.
    RecordBoundary,
};

pub const Connection = struct {
    server: Server,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    /// `reader()`: the application data of the record last opened.
    app_in: std.Io.Reader = .{ .vtable = &reader_vtable, .buffer = &.{}, .seek = 0, .end = 0 },
    /// `writer()`: the content of the record being written (unsealed).
    app_out: std.Io.Writer = .{ .vtable = &writer_vtable, .buffer = &.{}, .end = 0 },
    /// The error behind `reader()`'s `ReadFailed` or `writer()`'s
    /// `WriteFailed`.
    err: ?Error = null,
    /// A reader and writers on fibers (see the file comment); null: one
    /// caller at a time.
    guard: ?Guard = null,

    /// A mutex the caller's scheduler can park on. Not reentrant: the
    /// connection never takes it twice.
    pub const Guard = struct {
        ctx: *anyopaque,
        lock: *const fn (ctx: *anyopaque) void,
        unlock: *const fn (ctx: *anyopaque) void,
    };

    fn enter(self: *Connection) void {
        if (self.guard) |g| g.lock(g.ctx);
    }

    fn leave(self: *Connection) void {
        if (self.guard) |g| g.unlock(g.ctx);
    }

    /// `output`'s buffer becomes the server's output buffer (see the file
    /// comment); it must be empty. `joiner_buf`: as for `Server.init`. With
    /// client authentication, give the server its peer buffer before the
    /// handshake (`server.setPeerBuffer`).
    /// secret-api-ok: returns the initial state; every secret in `server` is zero until the handshake runs (under `Server`'s burns).
    pub fn init(
        config: *const server_mod.Config,
        input: *std.Io.Reader,
        output: *std.Io.Writer,
        joiner_buf: []u8,
    ) Connection {
        std.debug.assert(input.buffer.len >= record.max_record_len);
        std.debug.assert(output.end == 0);
        return .{ .server = .init(config, joiner_buf, output.buffer), .input = input, .output = output };
    }

    /// Wipe the server's secrets and buffers — the writer's buffer
    /// included, which holds the records — but not the reader's buffer: the
    /// caller owns it, and it holds decrypted application data.
    pub fn deinit(self: *Connection) void {
        // A record left half-written: the server wipes just what was written.
        if (self.app_out.buffer.len != 0) self.server.abandonWrite(self.app_out.end);
        self.server.deinit();
        self.output.end = 0;
        // No alias outlives the connection: a late write must not land in
        // the wiped buffer and report success.
        self.app_out.buffer = &.{};
        self.app_out.end = 0;
        self.app_in.buffer = &.{};
        self.app_in.seek = 0;
        self.app_in.end = 0;
    }

    /// Send what the server queued.
    fn flushOut(self: *Connection) Error!void {
        const n = self.server.pendingOutput().len;
        if (n == 0) return;
        self.output.end = n;
        self.output.flush() catch {
            // Whatever the transport did not take, it kept at the front.
            self.server.out.len = @min(self.output.end, self.server.out.buf.len);
            return error.WriteFailed;
        };
        if (self.output.end != 0 or self.output.buffer.ptr != self.server.out.buf.ptr) return error.WriteFailed;
        self.server.discardOutput(n);
    }

    /// Feed what the reader holds; read more when the server needs it.
    fn step(self: *Connection) Error!server_mod.Event {
        try self.emit();
        while (true) {
            const r = self.server.feed(self.input.buffered()) catch |err| {
                self.flushOut() catch {};
                return err;
            };
            // The consumed octets stay in the buffer until the next fill, so
            // an `app_data` slice is still valid when it is returned.
            self.input.toss(r.consumed);
            if (r.event != .need_more) return r.event;
            try self.flushOut();
            // A reader buffer under `record.max_record_len` (the `init`
            // assert, gone in ReleaseFast) cannot hold a record the client
            // may send: refuse instead of asking a full buffer for more.
            if (self.input.bufferedLen() == self.input.buffer.len) return error.ReadFailed;
            // Waiting for input: writers may send meanwhile.
            self.leave();
            const filled = self.input.fillMore();
            self.enter();
            filled catch |err| return switch (err) {
                error.EndOfStream => error.EndOfStream,
                error.ReadFailed => error.ReadFailed,
            };
        }
    }

    /// Run the handshake until the client's Finished verified — or, with
    /// `Config.early_data`, only until the client's early data is taken
    /// (BoringSSL `SSL_do_handshake`; the client is not authenticated yet:
    /// check `server.isConnected()`): then `server.inEarlyData()`, and
    /// `read` returns the early data and completes the handshake; writes go
    /// out as half-RTT data. Called again in that state it returns at once.
    /// secret-api-ok: chains `Server` calls only; their secret work (record seal/open, HKDF, the handshake steps) runs under burns of its own, and no secret is held in this frame.
    pub fn handshake(self: *Connection) Error!void {
        self.enter();
        defer self.leave();
        return self.handshakeGuarded();
    }

    fn handshakeGuarded(self: *Connection) Error!void {
        while (!self.server.isConnected() and !self.server.inEarlyData()) {
            switch (try self.step()) {
                .handshake_done, .early_data_accepted => {},
                // None can come before the client's Finished (or before the
                // early data is taken): inbound refuses application data and
                // treats close_notify as an abort until then.
                .app_data, .early_data, .peer_closed => unreachable,
                .need_more => unreachable,
            }
        }
        try self.flushOut();
    }

    /// The next application data, a slice of the reader's buffer valid until
    /// the next `read`/`handshake`; null once the client sent close_notify.
    /// Runs the handshake first if it has not completed. Never empty. Data
    /// returned while `server.inEarlyData()` is 0-RTT data, which a
    /// recorded ClientHello can replay (RFC 8446 §8).
    /// secret-api-ok: chains `Server` calls only; their secret work (record seal/open, HKDF, the handshake steps) runs under burns of its own, and no secret is held in this frame.
    pub fn read(self: *Connection) Error!?[]u8 {
        self.enter();
        defer self.leave();
        if (!self.server.isConnected()) try self.handshakeGuarded();
        if (self.server.peer_closed) return null;
        while (true) {
            switch (try self.step()) {
                .app_data, .early_data => |d| if (d.len != 0) return d,
                .peer_closed => return null,
                // The client's Finished after its early data: what the
                // server queued (its tickets) goes out with the next flush.
                .handshake_done => {},
                // A KeyUpdate is handled inside `feed`; other post-handshake
                // messages fail there.
                .early_data_accepted, .need_more => unreachable,
            }
        }
    }

    /// Seal and send all of `data`.
    /// secret-api-ok: chains `Server` calls only; their secret work (record seal/open, HKDF, the handshake steps) runs under burns of its own, and no secret is held in this frame.
    pub fn writeAll(self: *Connection, data: []const u8) Error!void {
        self.enter();
        defer self.leave();
        try self.emit();
        var done: usize = 0;
        while (done < data.len) {
            const n = self.server.write(data[done..]) catch |err| switch (err) {
                error.OutputFull => {
                    // Nothing pending to send: the buffer is below
                    // `minOutputLen` and never takes a record.
                    if (self.server.pendingOutput().len == 0) return error.OutputFull;
                    try self.flushOut();
                    continue;
                },
                else => return err,
            };
            done += n;
        }
        try self.flushOut();
    }

    /// Seal what `writer()` holds and send everything queued.
    /// secret-api-ok: chains `Server` calls only; their secret work (record seal/open, HKDF, the handshake steps) runs under burns of its own, and no secret is held in this frame.
    pub fn flush(self: *Connection) Error!void {
        self.enter();
        defer self.leave();
        try self.emit();
        try self.flushOut();
    }

    /// Turn the send key over and send the KeyUpdate (`Server.keyUpdate`).
    /// secret-api-ok: chains `Server` calls only; their secret work (record seal/open, HKDF, the handshake steps) runs under burns of its own, and no secret is held in this frame.
    pub fn keyUpdate(self: *Connection, request: server_mod.KeyUpdateRequest) Error!void {
        self.enter();
        defer self.leave();
        try self.emit();
        try self.server.keyUpdate(request);
        // No room for it behind what is queued: drain, then it fits.
        if (self.server.tx_update != null) {
            try self.flushOut();
            try self.server.keyUpdate(request);
            // An output buffer below `minOutputLen` cannot take it even empty.
            if (self.server.tx_update != null) return error.OutputFull;
        }
        try self.flushOut();
    }

    /// Send close_notify (after what `writer()` holds). The connection takes
    /// no more writes.
    /// secret-api-ok: chains `Server` calls only; their secret work (record seal/open, HKDF, the handshake steps) runs under burns of its own, and no secret is held in this frame.
    pub fn close(self: *Connection) Error!void {
        self.enter();
        defer self.leave();
        try self.emit();
        try self.server.close();
        try self.flushOut();
    }

    // ── reader(): the application data where it was opened ──────────────

    /// A `std.Io.Reader` over the application data, its buffer the record
    /// last opened (in the input). `EndOfStream` after the client's
    /// close_notify; `ReadFailed` with `err` set otherwise — a transport that
    /// ends without close_notify is `error.EndOfStream` there (a truncation,
    /// not an end), and `error.RecordBoundary` is a request for more contiguous octets than
    /// one record holds (`peek`, `take…` beyond it; `peekGreedy(1)` /
    /// `buffered` / `toss` never ask that). Runs the handshake first if
    /// needed. `self` must not move while it is in use.
    pub fn reader(self: *Connection) *std.Io.Reader {
        return &self.app_in;
    }

    const reader_vtable: std.Io.Reader.VTable = .{
        .stream = readerStream,
        .discard = readerDiscard,
        .readVec = readerReadVec,
        .rebase = readerRebase,
    };

    fn readFailed(self: *Connection, err: Error) std.Io.Reader.Error {
        self.err = err;
        return error.ReadFailed;
    }

    /// Alias the reader onto the next record's application data.
    /// `buffer.len` is exactly that data: `Reader.fill` calls `rebase` only
    /// when `buffer.len - seek` is short of what it wants, so spare capacity
    /// that cannot be filled would send a cross-record request to `readVec`
    /// instead of to `rebase`, where it is refused.
    fn pull(self: *Connection) std.Io.Reader.Error!void {
        const data = (self.read() catch |err| return self.readFailed(err)) orelse return error.EndOfStream;
        self.app_in.buffer = data;
        self.app_in.seek = 0;
        self.app_in.end = data.len;
    }

    fn readerReadVec(r: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
        const self: *Connection = @alignCast(@fieldParentPtr("app_in", r));
        // `Reader.readVec` drains the buffer into `data` before it gets
        // here: anything still buffered means this record and the next one
        // are wanted contiguously.
        if (r.seek != r.end) return self.readFailed(error.RecordBoundary);
        _ = data; // answered out of `buffer`: that is what returning 0 says
        try self.pull();
        return 0;
    }

    fn readerRebase(r: *std.Io.Reader, capacity: usize) std.Io.Reader.RebaseError!void {
        const self: *Connection = @alignCast(@fieldParentPtr("app_in", r));
        _ = capacity;
        if (r.seek != r.end) return self.readFailed(error.RecordBoundary);
        // The record is spent: drop the alias, the next `readVec` takes a
        // fresh one.
        r.buffer = r.buffer[0..0];
        r.seek = 0;
        r.end = 0;
    }

    fn readerStream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *Connection = @alignCast(@fieldParentPtr("app_in", r));
        if (r.seek == r.end) try self.pull();
        const n = limit.minInt(r.end - r.seek);
        if (n == 0) return 0;
        try w.writeAll(r.buffer[r.seek..][0..n]);
        r.seek += n;
        return n;
    }

    fn readerDiscard(r: *std.Io.Reader, limit: std.Io.Limit) std.Io.Reader.Error!usize {
        const self: *Connection = @alignCast(@fieldParentPtr("app_in", r));
        if (r.seek == r.end) try self.pull();
        const n = limit.minInt(r.end - r.seek);
        r.seek += n;
        return n;
    }

    // ── writer(): the application data where it will be sealed ─────────

    /// A `std.Io.Writer` over the application data, its buffer the content
    /// of the next record, in the output: what is written is sealed where it
    /// lies, when the record is full or on `flush` (which also sends).
    /// `WriteFailed` with `err` set on an error — `error.RecordBoundary` for
    /// a `rebase` that would keep octets across a record. `self` must not
    /// move while it is in use.
    pub fn writer(self: *Connection) *std.Io.Writer {
        return &self.app_out;
    }

    const writer_vtable: std.Io.Writer.VTable = .{
        .drain = writerDrain,
        .flush = writerFlush,
        .rebase = writerRebase,
    };

    fn writeFailed(self: *Connection, err: Error) std.Io.Writer.Error {
        self.err = err;
        return error.WriteFailed;
    }

    /// Seal what `writer()` holds as one record and release its slot.
    fn emit(self: *Connection) Error!void {
        const n = self.app_out.end;
        self.app_out.buffer = &.{};
        self.app_out.end = 0;
        try self.server.commitWrite(n);
    }

    /// Give `writer()` the content slot of a fresh record. A record that
    /// would be cut short by output still waiting is not: that output is
    /// sent first, so records follow the data rather than the buffer.
    fn reserve(self: *Connection) Error!void {
        var s = try self.server.writeSlot();
        if (s.len < self.server.out.max_fragment and self.server.pendingOutput().len != 0) {
            try self.flushOut();
            s = try self.server.writeSlot();
        }
        if (s.len == 0) return error.OutputFull;
        self.app_out.buffer = s;
        self.app_out.end = 0;
    }

    /// Copy `data` (its last slice `splat` times) into the slot, in order,
    /// as far as it has room; how much was taken.
    fn fill(w: *std.Io.Writer, data: []const []const u8, splat: usize) usize {
        var n: usize = 0;
        for (data, 0..) |bytes, i| {
            const times = if (i == data.len - 1) splat else 1;
            if (bytes.len == 1 and times > 1) {
                const k = @min(times, w.buffer.len - w.end);
                @memset(w.buffer[w.end..][0..k], bytes[0]);
                w.end += k;
                n += k;
                if (k < times) return n;
                continue;
            }
            if (bytes.len == 0) continue;
            for (0..times) |_| {
                const k = @min(bytes.len, w.buffer.len - w.end);
                @memcpy(w.buffer[w.end..][0..k], bytes[0..k]);
                w.end += k;
                n += k;
                if (k < bytes.len) return n;
            }
        }
        return n;
    }

    fn writerDrain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *Connection = @alignCast(@fieldParentPtr("app_out", w));
        // Top the record up first: `drain` is reached because a write did
        // not fit what was left of it, and sealing it now would put a short
        // record on the wire for every write that straddles the end (an h2
        // frame header, then its payload). Sealed once full, on the next
        // call.
        const topped = fill(w, data, splat);
        if (topped != 0) return topped;
        try self.renew();
        return fill(w, data, splat);
    }

    /// Seal the record `writer()` holds and give it a fresh one.
    fn renew(self: *Connection) std.Io.Writer.Error!void {
        self.enter();
        defer self.leave();
        self.emit() catch |err| return self.writeFailed(err);
        self.reserve() catch |err| return self.writeFailed(err);
    }

    fn writerFlush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        const self: *Connection = @alignCast(@fieldParentPtr("app_out", w));
        self.flush() catch |err| return self.writeFailed(err);
    }

    /// `preserve == 0` is "a fresh record"; anything to keep across one is
    /// refused (it lies where the tag goes when the record is sealed).
    fn writerRebase(w: *std.Io.Writer, preserve: usize, capacity: usize) std.Io.Writer.Error!void {
        const self: *Connection = @alignCast(@fieldParentPtr("app_out", w));
        if (preserve != 0) return self.writeFailed(error.RecordBoundary);
        try self.renew();
        if (w.buffer.len - w.end < capacity) return self.writeFailed(error.RecordBoundary);
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const inbound = @import("inbound.zig");
const Sink = @import("test_sink.zig").Sink;

test "a refusal's alert reaches the writer before the error is returned" {
    var prng = std.Random.DefaultPrng.init(3);
    const ck: server_mod.CertifiedKey = undefined;
    const cfg: server_mod.Config = .{ .certificate = .{ .fixed = &ck }, .random = prng.random() };
    // A record that is not a ClientHello.
    var in_buf: [record.max_record_len]u8 = undefined;
    const bad = [_]u8{ 22, 3, 3, 0, 8, 20, 0, 0, 4, 1, 2, 3, 4 };
    @memcpy(in_buf[0..bad.len], &bad);
    var reader: std.Io.Reader = .fixed(in_buf[0..bad.len]);
    reader.buffer = &in_buf; // capacity for the assertion; `end` limits it
    var out_buf: [4096]u8 = undefined;
    var sink: Sink = .init(testing.allocator, &out_buf);
    defer sink.deinit();
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var c: Connection = .init(&cfg, &reader, &sink.writer, &joiner);
    defer c.deinit();
    try testing.expectError(error.UnexpectedMessage, c.handshake());
    try testing.expectEqualSlices(u8, &.{ 21, 3, 3, 0, 2, 2, 10 }, sink.written());
}

test "a transport that ends mid-handshake is EndOfStream" {
    var prng = std.Random.DefaultPrng.init(3);
    const ck: server_mod.CertifiedKey = undefined;
    const cfg: server_mod.Config = .{ .certificate = .{ .fixed = &ck }, .random = prng.random() };
    var in_buf: [record.max_record_len]u8 = undefined;
    const part = [_]u8{ 22, 3, 1, 0, 200, 1, 0 };
    @memcpy(in_buf[0..part.len], &part);
    var reader: std.Io.Reader = .fixed(in_buf[0..part.len]);
    reader.buffer = &in_buf;
    var out_buf: [4096]u8 = undefined;
    var sink: Sink = .init(testing.allocator, &out_buf);
    defer sink.deinit();
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var c: Connection = .init(&cfg, &reader, &sink.writer, &joiner);
    defer c.deinit();
    try testing.expectError(error.EndOfStream, c.handshake());
}

test "a writer that keeps its bytes (Writer.fixed) is refused, not corrupted" {
    var prng = std.Random.DefaultPrng.init(3);
    const ck: server_mod.CertifiedKey = undefined;
    const cfg: server_mod.Config = .{ .certificate = .{ .fixed = &ck }, .random = prng.random() };
    var in_buf: [record.max_record_len]u8 = undefined;
    const bad = [_]u8{ 22, 3, 3, 0, 8, 20, 0, 0, 4, 1, 2, 3, 4 };
    @memcpy(in_buf[0..bad.len], &bad);
    var reader: std.Io.Reader = .fixed(in_buf[0..bad.len]);
    reader.buffer = &in_buf;
    var out_buf: [4096]u8 = undefined;
    var fixed: std.Io.Writer = .fixed(&out_buf);
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var c: Connection = .init(&cfg, &reader, &fixed, &joiner);
    defer c.deinit();
    // The refusal's alert cannot be sent through it: the handshake error
    // still comes back (the alert is best effort).
    try testing.expectError(error.UnexpectedMessage, c.handshake());
    try testing.expectError(error.WriteFailed, c.flushOut());
}

/// The client end of the guard test: waits until the server's writer has
/// filled the socket, sends one record, then reads the writer's payload.
const GuardPeer = struct {
    io: std.Io,
    fd: std.posix.fd_t,
    payload: []const u8,
    got: []u8,
    err: ?anyerror = null,

    fn run(p: *GuardPeer) void {
        p.go() catch |err| {
            p.err = err;
            // A corrupt stream: unblock the server's writer and reader so
            // the test fails instead of hanging.
            _ = std.os.linux.shutdown(p.fd, std.os.linux.SHUT.RDWR);
        };
    }

    fn go(p: *GuardPeer) !void {
        const Client = @import("tlsclient").Client;
        const stream: std.Io.net.Stream = .{ .socket = .{ .handle = p.fd, .address = undefined } };
        var net_in: [Client.min_buffer_len]u8 = undefined;
        var net_out: [Client.min_buffer_len]u8 = undefined;
        var app_in: [Client.min_buffer_len]u8 = undefined;
        var app_out: [Client.min_buffer_len]u8 = undefined;
        var sr = stream.reader(p.io, &net_in);
        var sw = stream.writer(p.io, &net_out);
        const entropy: [Client.Options.entropy_len]u8 = @splat(7);
        var c = try Client.init(&sr.interface, &sw.interface, .{
            .host = .no_verification,
            .ca = .no_verification,
            .read_buffer = &app_in,
            .write_buffer = &app_out,
            .entropy = &entropy,
            .realtime_now = .fromNanoseconds(@as(i96, 1_900_000_000) * std.time.ns_per_s),
            .min_version = .tls_1_3,
        });
        // The server's writer blocks on the full socket meanwhile; its reader
        // then waits for this record.
        try p.io.sleep(.fromMilliseconds(200), .awake);
        try c.writer.writeAll("a");
        try c.writer.flush();
        try sw.interface.flush();
        try c.reader.readSliceAll(p.got);
        try c.end();
        try sw.interface.flush();
    }
};

test "a guard keeps a reader from resending what a parked writer is still sending" {
    // A writer blocked in sending (a fiber parked on a full socket, here a
    // thread) and a reader that needs input: without the guard the reader
    // sends the same queued records again, and the client sees a corrupt
    // stream (qap's HTTP/2 streams on fibers, 2026-10-22).
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    const gpa = testing.allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fds: [2]linux.fd_t = undefined;
    if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds)) != .SUCCESS) return error.SkipZigTest;
    defer for (fds) |fd| {
        _ = linux.close(fd);
    };
    const small: c_int = 4096;
    _ = linux.setsockopt(fds[0], linux.SOL.SOCKET, linux.SO.SNDBUF, std.mem.asBytes(&small), @sizeOf(c_int));
    _ = linux.setsockopt(fds[1], linux.SOL.SOCKET, linux.SO.RCVBUF, std.mem.asBytes(&small), @sizeOf(c_int));

    const certs = @import("test_certs.zig");
    const p256: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey = try .fromBytes(certs.p256_scalar);
    const chain = [_][]const u8{&certs.p256_cert};
    const ck: server_mod.CertifiedKey = .{ .chain = &chain, .key = .{ .ecdsa_p256 = &p256 } };
    var prng = std.Random.DefaultPrng.init(11);
    const cfg: server_mod.Config = .{ .certificate = .{ .fixed = &ck }, .random = prng.random() };

    const payload = try gpa.alloc(u8, 256 * 1024);
    defer gpa.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    const got = try gpa.alloc(u8, payload.len);
    defer gpa.free(got);
    var peer: GuardPeer = .{ .io = io, .fd = fds[1], .payload = payload, .got = got };
    const peer_thread = try std.Thread.spawn(.{}, GuardPeer.run, .{&peer});

    const stream: std.Io.net.Stream = .{ .socket = .{ .handle = fds[0], .address = undefined } };
    const in_buf = try gpa.alloc(u8, record.max_record_len);
    defer gpa.free(in_buf);
    const out_buf = try gpa.alloc(u8, server_mod.minOutputLen(&cfg, &ck) + server_mod.full_record_output_len);
    defer gpa.free(out_buf);
    const joiner = try gpa.alloc(u8, inbound.Joiner.bufferLen(inbound.default_max_message));
    defer gpa.free(joiner);
    var sr = stream.reader(io, in_buf);
    var sw = stream.writer(io, out_buf);
    var conn: Connection = .init(&cfg, &sr.interface, &sw.interface, joiner);
    defer conn.deinit();

    const Mutex = struct {
        m: std.Io.Mutex = .init,
        io: std.Io,
        fn lock(ctx: *anyopaque) void {
            const s: *@This() = @ptrCast(@alignCast(ctx));
            s.m.lockUncancelable(s.io);
        }
        fn unlock(ctx: *anyopaque) void {
            const s: *@This() = @ptrCast(@alignCast(ctx));
            s.m.unlock(s.io);
        }
    };
    var mutex: Mutex = .{ .io = io };
    conn.guard = .{ .ctx = &mutex, .lock = Mutex.lock, .unlock = Mutex.unlock };

    try conn.handshake();
    const Writer = struct {
        fn run(c: *Connection, data: []const u8, err: *?Error) void {
            c.writeAll(data) catch |e| {
                err.* = e;
            };
        }
    };
    var write_err: ?Error = null;
    const writer_thread = try std.Thread.spawn(.{}, Writer.run, .{ &conn, payload, &write_err });
    // Let the writer fill the socket and block.
    try io.sleep(.fromMilliseconds(50), .awake);
    const first = try conn.read();
    try testing.expectEqualStrings("a", first.?);
    writer_thread.join();
    try testing.expectEqual(null, write_err);
    try testing.expectEqual(null, try conn.read()); // close_notify
    peer_thread.join();
    try testing.expectEqual(null, peer.err);
    try testing.expectEqualSlices(u8, payload, got);
}
