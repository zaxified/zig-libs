// SPDX-License-Identifier: MIT

//! What a caller does with `tlsclient` to talk HTTPS to one host: load the
//! system CA bundle, open a TCP stream, run the handshake in place
//! (`initInto` — no by-value copy of the traffic keys), ask for the
//! negotiated parameters through `ConnectionInfo`, keep a TLS 1.3 session
//! cache for a later resumption, send one request, read the status line,
//! derive exporter keying material, and close with `close_notify`.
//!
//!   zig build example-tlsclient -- example.com [port]
//!
//! With no host it prints the usage and exits 0 (the collection's example
//! build runs no network).

const std = @import("std");
const tls = @import("tlsclient");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    var out_buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const out = &stdout.interface;
    defer out.flush() catch {};

    if (args.len < 2) {
        try out.writeAll("usage: example-tlsclient <host> [port]\n");
        return;
    }
    const host = args[1];
    const port: u16 = if (args.len > 2) try std.fmt.parseInt(u16, args[2], 10) else 443;

    // The trust anchors: the system bundle, guarded by a lock the client
    // takes while it verifies (several clients may share one bundle).
    var bundle: std.crypto.Certificate.Bundle = .empty;
    try bundle.rescan(arena, io, std.Io.Clock.real.now(io));
    var lock: std.Io.RwLock = .init;

    const name = try std.Io.net.HostName.init(host);
    var stream = try name.connect(io, port, .{ .mode = .stream });
    defer stream.close(io);

    // Socket-facing buffers hold a whole ciphertext record; the client's own
    // read buffer holds a record plus the plaintext the caller reads.
    var sock_r_buf: [tls.Client.min_buffer_len]u8 = undefined;
    var sock_w_buf: [tls.Client.min_buffer_len]u8 = undefined;
    var sr = stream.reader(io, &sock_r_buf);
    var sw = stream.writer(io, &sock_w_buf);
    var tls_r: [tls.Client.min_buffer_len + 4096]u8 = undefined;
    var tls_w: [4096]u8 = undefined;

    var storage: [16 * 1024]u8 = undefined;
    var info: tls.Client.ConnectionInfo = .init(&storage);
    var entries: [4]tls.Client.ClientSession = undefined;
    var cache: tls.Client.SessionCache = .init(&entries, null); // one thread: no lock

    var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
    try io.randomSecure(&entropy);
    defer std.crypto.secureZero(u8, &entropy);

    var client: tls.Client = undefined;
    try tls.Client.initInto(&client, &sr.interface, &sw.interface, .{
        .host = .{ .explicit = host },
        .ca = .{ .bundle = .{ .gpa = arena, .io = io, .lock = &lock, .bundle = &bundle } },
        .read_buffer = &tls_r,
        .write_buffer = &tls_w,
        .entropy = &entropy,
        .realtime_now = std.Io.Clock.real.now(io),
        .alpn_protocols = &.{"http/1.1"},
        .connection_info = &info,
        .session_cache = &cache,
    });

    try out.print("{s}:{d}: {t}, {t}, group {?t}, ALPN {?s}, HRR {}, EMS {}, {d} certificates, {d} SCTs\n", .{
        host,
        port,
        info.version,
        info.cipher_suite,
        info.negotiated_group,
        info.alpn_protocol,
        info.hello_retry_request,
        info.extended_master_secret,
        info.peerCertificates().len,
        info.signedCertificateTimestamps().len,
    });

    try client.writer.print("HEAD / HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{host});
    try client.writer.flush();
    try sw.interface.flush();
    const status = try client.reader.takeDelimiterExclusive('\n');
    try out.print("status: {s}\n", .{std.mem.trimEnd(u8, status, "\r")});

    var km: [32]u8 = undefined;
    try client.exportKeyingMaterial("EXPERIMENTAL-tlsclient-example", null, &km);
    try out.print("exporter: {x}\n", .{&km});

    try client.end();
    try sw.interface.flush();
}
