// SPDX-License-Identifier: MIT

//! tlsserver.connection — the blocking wrapper: a `Server` driven over a
//! `std.Io.Reader` / `std.Io.Writer` pair (a socket's, or a fiber's).
//!
//! Zero-copy on the receive side: records are decrypted in place inside the
//! reader's own buffer, so `read` returns a slice of it, valid until the
//! next call that reads. The reader's buffer must hold one whole record
//! (`record.max_record_len`). What the server queues is written to the
//! writer and flushed before every read that has to wait, and after the
//! handshake, every write and `close`.
//!
//! An error is final. A refusal's alert is flushed (best effort) before the
//! error is returned.

const std = @import("std");
const record = @import("record.zig");
const server_mod = @import("server.zig");

const Server = server_mod.Server;

pub const Error = server_mod.Error || error{
    /// The reader failed (`input`'s own error is the detail).
    ReadFailed,
    /// The writer failed.
    WriteFailed,
    /// The transport ended before the handshake did, or in the middle of a
    /// record (a truncation: without close_notify).
    EndOfStream,
};

pub const Connection = struct {
    server: Server,
    input: *std.Io.Reader,
    output: *std.Io.Writer,

    /// `joiner_buf`, `output_buf`: as for `Server.init`.
    pub fn init(
        config: *const server_mod.Config,
        input: *std.Io.Reader,
        output: *std.Io.Writer,
        joiner_buf: []u8,
        output_buf: []u8,
    ) Connection {
        std.debug.assert(input.buffer.len >= record.max_record_len);
        return .{ .server = .init(config, joiner_buf, output_buf), .input = input, .output = output };
    }

    /// Wipe the server's secrets and buffers (not the reader's buffer: the
    /// caller owns it, and it holds decrypted application data).
    pub fn deinit(self: *Connection) void {
        self.server.deinit();
    }

    fn flush(self: *Connection) Error!void {
        const p = self.server.pendingOutput();
        if (p.len != 0) {
            self.output.writeAll(p) catch return error.WriteFailed;
            self.server.discardOutput(p.len);
        }
        self.output.flush() catch return error.WriteFailed;
    }

    /// Feed what the reader holds; read more when the server needs it.
    fn step(self: *Connection) Error!server_mod.Event {
        while (true) {
            const r = self.server.feed(self.input.buffered()) catch |err| {
                self.flush() catch {};
                return err;
            };
            // The consumed octets stay in the buffer until the next fill, so
            // an `app_data` slice is still valid when it is returned.
            self.input.toss(r.consumed);
            if (r.event != .need_more) return r.event;
            try self.flush();
            self.input.fillMore() catch |err| return switch (err) {
                error.EndOfStream => error.EndOfStream,
                error.ReadFailed => error.ReadFailed,
            };
        }
    }

    /// Run the handshake to completion (the client's Finished verified).
    pub fn handshake(self: *Connection) Error!void {
        while (!self.server.isConnected()) {
            switch (try self.step()) {
                .handshake_done => {},
                // Neither can come before the client's Finished: inbound
                // refuses application data and treats close_notify as an
                // abort until then.
                .app_data, .peer_closed => unreachable,
                .need_more => unreachable,
            }
        }
        try self.flush();
    }

    /// The next application data, a slice of the reader's buffer valid until
    /// the next `read`/`handshake`; null once the client sent close_notify.
    /// Runs the handshake first if it has not completed. Never empty.
    pub fn read(self: *Connection) Error!?[]u8 {
        if (!self.server.isConnected()) try self.handshake();
        if (self.server.peer_closed) return null;
        while (true) {
            switch (try self.step()) {
                .app_data => |d| if (d.len != 0) return d,
                .peer_closed => return null,
                // Post-handshake handshake messages fail inside `feed`.
                .handshake_done, .need_more => unreachable,
            }
        }
    }

    /// Seal and send all of `data`.
    pub fn writeAll(self: *Connection, data: []const u8) Error!void {
        var done: usize = 0;
        while (done < data.len) {
            const n = self.server.write(data[done..]) catch |err| switch (err) {
                error.OutputFull => {
                    try self.flush();
                    continue;
                },
                else => return err,
            };
            done += n;
        }
        try self.flush();
    }

    /// Send close_notify. The connection takes no more writes.
    pub fn close(self: *Connection) Error!void {
        try self.server.close();
        try self.flush();
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const inbound = @import("inbound.zig");

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
    var out_buf: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out_buf);
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var obuf: [4096]u8 = undefined;
    var c: Connection = .init(&cfg, &reader, &writer, &joiner, &obuf);
    defer c.deinit();
    try testing.expectError(error.UnexpectedMessage, c.handshake());
    try testing.expectEqualSlices(u8, &.{ 21, 3, 3, 0, 2, 2, 10 }, writer.buffered());
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
    var out_buf: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out_buf);
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var obuf: [4096]u8 = undefined;
    var c: Connection = .init(&cfg, &reader, &writer, &joiner, &obuf);
    defer c.deinit();
    try testing.expectError(error.EndOfStream, c.handshake());
}
