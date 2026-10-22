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
//! there is one reader, `deinit` comes after every fiber is done with the
//! connection, and `err` holds whichever side's error came last. The guard
//! does not make the connection safe across threads: the octets a writer
//! buffers are sealed by whichever side calls in next, and that is only
//! safe where nothing runs between a writer's octets and its next park.

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
        while (true) {
            // Every pass: a writer may have opened a record while this one
            // waited for input, and what `feed` queues (a KeyUpdate, an
            // alert) would land where that record's octets lie.
            try self.emit();
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

/// The guard tests' rig: a `Connection` over one end of a socketpair (small
/// buffers, so a writer blocks soon), a `tlsclient` on the other end in a
/// thread of its own. Heap-allocated: the threads hold pointers into it.
const GuardRig = struct {
    const linux = std.os.linux;
    const Client = @import("tlsclient").Client;
    const certs = @import("test_certs.zig");

    gpa: std.mem.Allocator,
    threaded: std.Io.Threaded,
    fds: [2]linux.fd_t,
    p256: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey,
    chain: [1][]const u8,
    ck: server_mod.CertifiedKey,
    prng: std.Random.DefaultPrng,
    cfg: server_mod.Config,
    in_buf: []u8,
    out_buf: []u8,
    joiner: []u8,
    sr: std.Io.net.Stream.Reader,
    sw: std.Io.net.Stream.Writer,
    conn: Connection,
    mutex: std.Io.Mutex = .init,
    /// Set by the server side's writer thread once its octets are buffered.
    slot_open: std.atomic.Value(bool) = .init(false),
    /// Whether the guard is held, and sends made without it (`checked`).
    held: bool = false,
    unguarded_sends: usize = 0,
    /// With `checked`: the connection's output, which forwards to `sw` and
    /// counts every send made without the guard held.
    checked: std.Io.Writer = undefined,
    fwd_buf: [512]u8 = undefined,

    fn create(gpa: std.mem.Allocator) !*GuardRig {
        return createWith(gpa, false);
    }

    fn createWith(gpa: std.mem.Allocator, checked: bool) !*GuardRig {
        const g = try gpa.create(GuardRig);
        errdefer gpa.destroy(g);
        g.gpa = gpa;
        g.threaded = .init(gpa, .{});
        errdefer g.threaded.deinit();
        if (linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &g.fds)) != .SUCCESS) return error.SkipZigTest;
        const small: c_int = 4096;
        _ = linux.setsockopt(g.fds[0], linux.SOL.SOCKET, linux.SO.SNDBUF, std.mem.asBytes(&small), @sizeOf(c_int));
        _ = linux.setsockopt(g.fds[1], linux.SOL.SOCKET, linux.SO.RCVBUF, std.mem.asBytes(&small), @sizeOf(c_int));
        g.p256 = try .fromBytes(certs.p256_scalar);
        g.chain = .{&certs.p256_cert};
        g.ck = .{ .chain = &g.chain, .key = .{ .ecdsa_p256 = &g.p256 } };
        g.prng = .init(11);
        g.cfg = .{ .certificate = .{ .fixed = &g.ck }, .random = g.prng.random() };
        g.in_buf = try gpa.alloc(u8, record.max_record_len);
        g.out_buf = try gpa.alloc(u8, server_mod.minOutputLen(&g.cfg, &g.ck) + server_mod.full_record_output_len);
        g.joiner = try gpa.alloc(u8, inbound.Joiner.bufferLen(inbound.default_max_message));
        const io = g.threaded.io();
        const stream: std.Io.net.Stream = .{ .socket = .{ .handle = g.fds[0], .address = undefined } };
        g.sr = stream.reader(io, g.in_buf);
        g.held = false;
        g.unguarded_sends = 0;
        if (checked) {
            g.sw = stream.writer(io, &g.fwd_buf);
            g.checked = .{ .vtable = &.{ .drain = checkedDrain }, .buffer = g.out_buf, .end = 0 };
            g.conn = .init(&g.cfg, &g.sr.interface, &g.checked, g.joiner);
        } else {
            g.sw = stream.writer(io, g.out_buf);
            g.conn = .init(&g.cfg, &g.sr.interface, &g.sw.interface, g.joiner);
        }
        g.conn.guard = .{ .ctx = g, .lock = lock, .unlock = unlock };
        g.slot_open = .init(false);
        g.mutex = .init;
        return g;
    }

    fn destroy(g: *GuardRig) void {
        g.conn.deinit();
        for (g.fds) |fd| _ = linux.close(fd);
        g.gpa.free(g.in_buf);
        g.gpa.free(g.out_buf);
        g.gpa.free(g.joiner);
        g.threaded.deinit();
        g.gpa.destroy(g);
    }

    /// Unblock every thread on the socket: a failing test ends, not hangs.
    fn shutdown(g: *GuardRig) void {
        for (g.fds) |fd| _ = linux.shutdown(fd, linux.SHUT.RDWR);
    }

    fn lock(ctx: *anyopaque) void {
        const g: *GuardRig = @ptrCast(@alignCast(ctx));
        g.mutex.lockUncancelable(g.threaded.io());
        g.held = true;
    }

    fn unlock(ctx: *anyopaque) void {
        const g: *GuardRig = @ptrCast(@alignCast(ctx));
        g.held = false;
        g.mutex.unlock(g.threaded.io());
    }

    /// The `checked` output: a send is where a parked writer and the reader
    /// could meet, so each must happen with the guard held.
    fn checkedDrain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const g: *GuardRig = @alignCast(@fieldParentPtr("checked", w));
        if (!g.held) g.unguarded_sends += 1;
        const out = &g.sw.interface;
        try out.writeAll(w.buffered());
        w.end = 0;
        var n: usize = 0;
        for (data, 0..) |d, i| {
            const times = if (i == data.len - 1) splat else 1;
            for (0..times) |_| try out.writeAll(d);
            n += d.len * times;
        }
        try out.flush();
        return n;
    }

    /// Wait (up to 5 s) until the server's writer has put octets on the
    /// socket the client does not read, then a little longer: it has filled
    /// the small socket buffers and blocks. (How much stays queued depends
    /// on what the client's reader took in with the handshake's last
    /// flight, so the test waits for any, not for a count.) If the writer
    /// has not blocked by then, the reader merely waits for input first,
    /// and the race this rig is for goes unexercised: the test fails open.
    fn awaitWriterBlocked(g: *GuardRig) !void {
        for (0..500) |_| {
            var avail: c_int = 0;
            _ = linux.ioctl(g.fds[1], linux.T.FIONREAD, @intFromPtr(&avail));
            if (avail > 0) return g.threaded.io().sleep(.fromMilliseconds(50), .awake);
            try g.threaded.io().sleep(.fromMilliseconds(10), .awake);
        }
        return error.WriterNeverBlocked;
    }

    /// A thread joined once, by whichever comes first: the test, or the
    /// `defer` of a test that failed.
    const Joined = struct {
        t: std.Thread,
        done: bool = false,

        fn join(j: *Joined) void {
            if (j.done) return;
            j.t.join();
            j.done = true;
        }
    };

    /// The client side, in its own thread.
    const Peer = struct {
        rig: *GuardRig,
        /// What it does once the handshake is done.
        mode: enum { send_then_read, junk_after_slot, read_then_send },
        got: []u8,
        err: ?anyerror = null,

        fn run(p: *Peer) void {
            p.go() catch |err| {
                p.err = err;
                p.rig.shutdown();
            };
        }

        fn go(p: *Peer) !void {
            const g = p.rig;
            const io = g.threaded.io();
            const stream: std.Io.net.Stream = .{ .socket = .{ .handle = g.fds[1], .address = undefined } };
            var net_in: [Client.min_buffer_len]u8 = undefined;
            var net_out: [Client.min_buffer_len]u8 = undefined;
            var app_in: [Client.min_buffer_len]u8 = undefined;
            var app_out: [Client.min_buffer_len]u8 = undefined;
            var sr = stream.reader(io, &net_in);
            var sw = stream.writer(io, &net_out);
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
            switch (p.mode) {
                .send_then_read => {
                    // Once the server's writer blocks on the full socket.
                    try g.awaitWriterBlocked();
                    try c.writer.writeAll("a");
                    try c.writer.flush();
                    try sw.interface.flush();
                    try c.reader.readSliceAll(p.got);
                    try c.end();
                    try sw.interface.flush();
                },
                .read_then_send => {
                    // Everything the server sends, then one record, then
                    // the server's close_notify.
                    try c.reader.readSliceAll(p.got);
                    try c.writer.writeAll("a");
                    try c.writer.flush();
                    try sw.interface.flush();
                    var rest: [1]u8 = undefined;
                    if (try c.reader.readSliceShort(&rest) != 0) return error.DataAfterClose;
                    try c.end();
                    try sw.interface.flush();
                },
                .junk_after_slot => {
                    // Once the server's writer has its octets in an open
                    // record (and its reader waits for input): a record that
                    // does not open, so the server queues an alert.
                    for (0..500) |_| {
                        if (g.slot_open.load(.acquire)) break;
                        try io.sleep(.fromMilliseconds(10), .awake);
                    } else return error.SlotNeverOpened;
                    const junk = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x14 } ++ @as([20]u8, @splat(0));
                    if (linux.errno(linux.write(g.fds[1], &junk, junk.len)) != .SUCCESS) return error.WriteFailed;
                    // The writer's octets come first, sealed, then the alert.
                    try c.reader.readSliceAll(p.got);
                },
            }
        }
    };
};

/// The call a guard test's writer thread blocks in, sending.
const ParkedSend = enum { write_all, flush, key_update, close };

/// A writer blocked in sending (a fiber parked on a full socket, here a
/// thread) and a reader that needs input: without the guard the reader
/// sends the same queued records again, and the client sees a corrupt stream
/// (qap's HTTP/2 streams on fibers, 2026-10-22). `write_all` sends a payload
/// through `writeAll`; the others queue one with `Server.write` first and
/// block in `flush`, `keyUpdate` or `close`. Not through `writer()`: it
/// buffers outside the guard, which only fibers of one thread make safe (the
/// file comment), so threads cannot stand in for them on that path.
fn guardParkedSender(kind: ParkedSend) !void {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const g = try GuardRig.create(gpa);
    defer g.destroy();
    const payload = try gpa.alloc(u8, 256 * 1024);
    defer gpa.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    const got = try gpa.alloc(u8, payload.len);
    defer gpa.free(got);

    var peer: GuardRig.Peer = .{ .rig = g, .mode = .send_then_read, .got = got };
    var peer_thread: GuardRig.Joined = .{ .t = try std.Thread.spawn(.{}, GuardRig.Peer.run, .{&peer}) };
    defer peer_thread.join();
    errdefer g.shutdown();
    try g.conn.handshake();

    // Queued, not sent: more than the socket buffers take.
    var data: []const u8 = payload;
    if (kind != .write_all) {
        data = payload[0..try g.conn.server.write(payload)];
        try testing.expect(data.len >= 16 * 1024);
    }
    // The client reads what it will be sent (before the writer starts).
    peer.got = got[0..data.len];

    const Writer = struct {
        fn run(c: *Connection, k: ParkedSend, d: []const u8, err: *?anyerror) void {
            (switch (k) {
                .write_all => c.writeAll(d),
                .flush => c.flush(),
                .key_update => c.keyUpdate(.update_not_requested),
                .close => c.close(),
            }) catch |e| {
                err.* = e;
            };
        }
    };
    var write_err: ?anyerror = null;
    var writer_thread: GuardRig.Joined = .{ .t = try std.Thread.spawn(.{}, Writer.run, .{ &g.conn, kind, data, &write_err }) };
    defer writer_thread.join();
    errdefer g.shutdown();
    g.awaitWriterBlocked() catch |err| {
        std.debug.print("peer: {?}\n", .{peer.err});
        return err;
    };
    const first = try g.conn.read();
    try testing.expectEqualStrings("a", first.?);
    try testing.expectEqual(null, try g.conn.read()); // close_notify
    writer_thread.join();
    try testing.expectEqual(null, write_err);
    peer_thread.join();
    try testing.expectEqual(null, peer.err);
    try testing.expectEqualSlices(u8, data, got[0..data.len]);
}

test "a guard keeps a reader from resending what a parked writer is still sending" {
    try guardParkedSender(.write_all);
}

test "a guard keeps a reader from resending what a parked flush, keyUpdate or close is sending" {
    try guardParkedSender(.flush);
    try guardParkedSender(.key_update);
    try guardParkedSender(.close);
}

test "every send happens with the guard held, from every entry point" {
    // Where a parked writer and the reader could meet is a send: each one
    // goes through an output that counts the sends made without the guard.
    // One thread, no timing: the handshake, `writeAll`, `writer()` turning
    // records over (`renew`) and its `flush`, `keyUpdate`, a `read` that
    // queues nothing and `close`.
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const g = try GuardRig.createWith(gpa, true);
    defer g.destroy();
    const a = try gpa.alloc(u8, 40 * 1024);
    defer gpa.free(a);
    for (a, 0..) |*b, i| b.* = @truncate(i *% 13 +% 5);
    const got = try gpa.alloc(u8, 2 * a.len);
    defer gpa.free(got);

    var peer: GuardRig.Peer = .{ .rig = g, .mode = .read_then_send, .got = got };
    var peer_thread: GuardRig.Joined = .{ .t = try std.Thread.spawn(.{}, GuardRig.Peer.run, .{&peer}) };
    defer peer_thread.join();
    errdefer g.shutdown();

    try g.conn.handshake();
    try g.conn.writeAll(a);
    const w = g.conn.writer();
    try w.writeAll(a);
    try w.flush();
    try g.conn.keyUpdate(.update_not_requested);
    try testing.expectEqualStrings("a", (try g.conn.read()).?);
    try g.conn.close();
    try testing.expectEqual(null, try g.conn.read());
    peer_thread.join();
    try testing.expectEqual(null, peer.err);
    try testing.expectEqualSlices(u8, a, got[0..a.len]);
    try testing.expectEqualSlices(u8, a, got[a.len..]);
    try testing.expectEqual(@as(usize, 0), g.unguarded_sends);
}

test "what a writer left in an open record is sealed before the reader queues anything" {
    // The reader waits for input with the guard released; a writer opens a
    // record and leaves octets in it (no flush). The client's next record
    // makes the server queue an alert — which must come after those octets,
    // not over them (review of the guard, 2026-10-22).
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const g = try GuardRig.create(gpa);
    defer g.destroy();
    var got: [5]u8 = undefined;
    var peer: GuardRig.Peer = .{ .rig = g, .mode = .junk_after_slot, .got = &got };
    var peer_thread: GuardRig.Joined = .{ .t = try std.Thread.spawn(.{}, GuardRig.Peer.run, .{&peer}) };
    defer peer_thread.join();
    errdefer g.shutdown();
    try g.conn.handshake();

    const Writer = struct {
        fn run(rig: *GuardRig, err: *?anyerror) void {
            // After the reader has parked in its read.
            rig.threaded.io().sleep(.fromMilliseconds(100), .awake) catch {};
            rig.conn.writer().writeAll("hello") catch |e| {
                err.* = e;
            };
            rig.slot_open.store(true, .release);
        }
    };
    var write_err: ?anyerror = null;
    var writer_thread: GuardRig.Joined = .{ .t = try std.Thread.spawn(.{}, Writer.run, .{ g, &write_err }) };
    defer writer_thread.join();
    errdefer g.shutdown();
    try testing.expectError(error.BadRecordMac, g.conn.read());
    writer_thread.join();
    try testing.expectEqual(null, write_err);
    peer_thread.join();
    try testing.expectEqual(null, peer.err);
    try testing.expectEqualStrings("hello", &got);
}
