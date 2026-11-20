// SPDX-License-Identifier: MIT

//! The TLS side of `Server`'s native HTTPS listener (`Options.tls`): one
//! `tlsserver.Connection` per accepted socket, with the buffers it needs, and
//! two small adapters that give the serving loops a reader and a writer that
//! have no record boundary to trip over.
//!
//! `tlsserver`'s own `reader()` / `writer()` are zero-copy: they cannot hand
//! out more contiguous octets than one record holds, which is a limit a
//! request head spread over two records, or a chunk line cut by a record
//! boundary, would hit. The adapters here have a buffer of their own and pull
//! (or push) record by record through `stream` / `drain`, which cross records.

const std = @import("std");
const tlsserver = @import("tlsserver");

const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// `Server.Options.tls`.
pub const Options = struct {
    /// The TLS configuration every connection starts from (certificate or
    /// selector, suites, ALPN, tickets, client authentication, ...). Its
    /// `random` is replaced by a per-connection CSPRNG seeded from the OS,
    /// whatever it holds. `alpn_protocols` decides the HTTP version: `h2`
    /// negotiated means HTTP/2 over TLS with the server's handler, anything
    /// else (or no ALPN) HTTP/1.1; leave `h2` out to serve only HTTP/1.1.
    config: *const tlsserver.Config,
    /// The size of the per-connection TLS output buffer (it holds the first
    /// handshake flight: `tlsserver.server.minOutputLen`). 0 = derived from a
    /// fixed certificate, and 48 KiB for a certificate selector (set it from
    /// `minOutputLen` of the largest key the selector can pick).
    output_buffer_len: usize = 0,
};

/// A reader over the application data of a `tlsserver.Connection`, with a
/// buffer of its own.
pub const AppReader = struct {
    conn: *tlsserver.Connection,
    reader: Reader,

    fn streamFn(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
        const a: *AppReader = @alignCast(@fieldParentPtr("reader", r));
        return a.conn.reader().stream(w, limit);
    }
};

/// A writer that seals what it is given into `tlsserver.Connection`'s records.
pub const AppWriter = struct {
    conn: *tlsserver.Connection,
    writer: Writer,

    fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const a: *AppWriter = @alignCast(@fieldParentPtr("writer", w));
        const cw = a.conn.writer();
        try cw.writeAll(w.buffer[0..w.end]);
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try cw.writeAll(d);
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| try cw.writeAll(last);
        return n + last.len * splat;
    }

    fn flush(w: *Writer) Writer.Error!void {
        const a: *AppWriter = @alignCast(@fieldParentPtr("writer", w));
        try Writer.defaultFlush(w);
        try a.conn.writer().flush();
    }
};

/// One connection's TLS state, heap-allocated (the connection must not move).
pub const Session = struct {
    gpa: std.mem.Allocator,
    cfg: tlsserver.Config,
    csprng: std.Random.DefaultCsprng,
    /// What the raw transport reads into / writes from (the server's TLS
    /// record buffers): the `TimeoutReader`'s and `TimeoutWriter`'s buffers.
    in_buf: []u8,
    out_buf: []u8,
    joiner: []u8,
    conn: tlsserver.Connection = undefined,
    app_in: AppReader = undefined,
    app_out: AppWriter = undefined,
    started: bool = false,

    pub fn create(gpa: std.mem.Allocator, io: std.Io, o: Options) !*Session {
        const s = try gpa.create(Session);
        errdefer gpa.destroy(s);
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        try io.randomSecure(&seed);
        const out_len = if (o.output_buffer_len != 0) o.output_buffer_len else switch (o.config.certificate) {
            .fixed => |ck| @max(tlsserver.server.full_record_output_len, tlsserver.server.minOutputLen(o.config, ck)),
            .select => 48 * 1024,
        };
        const in_buf = try gpa.alloc(u8, tlsserver.record.max_record_len);
        errdefer gpa.free(in_buf);
        const out_buf = try gpa.alloc(u8, out_len);
        errdefer gpa.free(out_buf);
        const joiner = try gpa.alloc(u8, tlsserver.inbound.Joiner.bufferLen(tlsserver.inbound.default_max_message));
        errdefer gpa.free(joiner);
        s.* = .{
            .gpa = gpa,
            .cfg = o.config.*,
            .csprng = std.Random.DefaultCsprng.init(seed),
            .in_buf = in_buf,
            .out_buf = out_buf,
            .joiner = joiner,
        };
        std.crypto.secureZero(u8, seed[0..]);
        s.cfg.random = s.csprng.random();
        return s;
    }

    pub fn destroy(s: *Session) void {
        if (s.started) s.conn.deinit();
        std.crypto.secureZero(u8, s.joiner);
        s.gpa.free(s.joiner);
        s.gpa.free(s.in_buf);
        s.gpa.free(s.out_buf);
        const gpa = s.gpa;
        s.* = undefined;
        gpa.destroy(s);
    }

    /// Run the handshake over `raw_in` / `raw_out` (buffers `in_buf` /
    /// `out_buf`), and set the adapters up over `read_buf` / `write_buf`.
    /// Returns the negotiated ALPN protocol, borrowed from the connection.
    pub fn handshake(s: *Session, raw_in: *Reader, raw_out: *Writer, read_buf: []u8, write_buf: []u8) !?[]const u8 {
        s.conn = tlsserver.Connection.init(&s.cfg, raw_in, raw_out, s.joiner);
        s.started = true;
        try s.conn.handshake();
        s.app_in = .{
            .conn = &s.conn,
            .reader = .{ .vtable = &.{ .stream = AppReader.streamFn }, .buffer = read_buf, .seek = 0, .end = 0 },
        };
        s.app_out = .{
            .conn = &s.conn,
            .writer = .{ .vtable = &.{ .drain = AppWriter.drain, .flush = AppWriter.flush }, .buffer = write_buf },
        };
        return s.conn.server.alpnProtocol();
    }

    /// close_notify, best effort.
    pub fn close(s: *Session) void {
        if (!s.started) return;
        s.app_out.writer.flush() catch {};
        s.conn.close() catch {};
    }
};
