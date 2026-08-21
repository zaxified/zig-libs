// SPDX-License-Identifier: MIT

//! What a report-mailer consumer does with `smtp`: compose a multipart message
//! with an attachment, open an authenticated session over STARTTLS, send it to
//! two recipients, and find out that one of them bounced.
//!
//! The peer is a scripted server in memory, because that is exactly what the
//! module's `Transport` seam is for: one blocking `read`, one `write`, no
//! socket and no TLS inside the module. A downstream project plugs a real
//! stream in at the same place, and its tests plug in this.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`deps` only, no `test_deps`, no access to anything the module does
//! not export). If a type needed to call the API is not public, or an error
//! cannot be named from outside, this file stops compiling. The module's own
//! tests cannot notice either, because they live inside it.

const std = @import("std");
const smtp = @import("smtp");

/// One reply per read, in the order the client asks for them. The pre-TLS
/// EHLO deliberately advertises no AUTH and the post-TLS one does: a
/// capability list learned in the clear is attacker-controlled, so RFC 3207
/// §4.2 makes the client throw it away and ask again. Only the second list
/// may unlock a password.
const script = [_][]const u8{
    "220 mail.example.com ESMTP ready\r\n",
    "250-mail.example.com Hello\r\n" ++
        "250-PIPELINING\r\n" ++
        "250-SIZE 10240000\r\n" ++
        "250-8BITMIME\r\n" ++
        "250 STARTTLS\r\n",
    "220 2.0.0 Ready to start TLS\r\n",
    "250-mail.example.com Hello\r\n" ++
        "250-PIPELINING\r\n" ++
        "250-SIZE 10240000\r\n" ++
        "250-8BITMIME\r\n" ++
        "250 AUTH PLAIN LOGIN\r\n",
    "235 2.7.0 Authentication successful\r\n",
    "250 2.1.0 Ok\r\n", // MAIL FROM
    "250 2.1.5 Ok\r\n", // RCPT TO: ops@example.net
    "550 5.1.1 <archive@example.net>: unknown user\r\n", // RCPT TO: rejected
    "354 End data with <CR><LF>.<CR><LF>\r\n",
    "250 2.0.0 Ok: queued as 3F2A9\r\n",
    "221 2.0.0 Bye\r\n",
};

/// A `Transport` a consumer writes: the two functions in the vtable and the
/// three errors they may report are all the module asks for.
const ScriptedServer = struct {
    next_reply: usize = 0,
    sent: usize = 0,
    tls_upgrades: usize = 0,

    fn transport(s: *ScriptedServer) smtp.Transport {
        return .{ .ctx = s, .vtable = &.{ .read = read, .write = write } };
    }

    fn read(ctx: *anyopaque, buf: []u8) smtp.TransportError!usize {
        const s: *ScriptedServer = @ptrCast(@alignCast(ctx));
        if (s.next_reply == script.len) return error.EndOfStream;
        const reply = script[s.next_reply];
        if (reply.len > buf.len) return error.ReadFailed;
        s.next_reply += 1;
        @memcpy(buf[0..reply.len], reply);
        return reply.len;
    }

    fn write(ctx: *anyopaque, bytes: []const u8) smtp.TransportError!void {
        const s: *ScriptedServer = @ptrCast(@alignCast(ctx));
        s.sent += bytes.len;
    }

    /// The STARTTLS hook. A real consumer hands back a transport that wraps
    /// the same socket in a TLS client; the module implements no TLS and does
    /// not want to. Returning the same transport is this example's stand-in.
    fn upgrade(ctx: *anyopaque) smtp.TransportError!smtp.Transport {
        const s: *ScriptedServer = @ptrCast(@alignCast(ctx));
        s.tls_upgrades += 1;
        return s.transport();
    }
};

const report_csv =
    "date,host,latency_ms\n" ++
    "2026-08-21,edge-1,12\n" ++
    "2026-08-21,edge-2,41\n";

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var server: ScriptedServer = .{};

    var client = try smtp.Client.init(gpa, server.transport(), .{
        .session = .{
            .ehlo_domain = "reports.example.org",
            // Not `opportunistic`: a report with an attachment is worth
            // failing the send over rather than mailing it in the clear.
            .tls = .required,
            .credentials = .{ .username = "reports@example.org", .password = "s3cret" },
        },
        // Absent here would mean "this caller cannot do TLS", and a session
        // that reaches STARTTLS would fail rather than continue unencrypted.
        .tls = .{ .ctx = &server, .upgrade = ScriptedServer.upgrade },
    });
    defer client.deinit();

    client.connect() catch |err| switch (err) {
        // The server does not offer STARTTLS and the policy is `.required`.
        error.TlsNotOffered => {
            std.debug.print("server offers no STARTTLS, refusing to send\n", .{});
            return;
        },
        // Reached STARTTLS but no upgrade hook was configured.
        error.TlsUnavailable => {
            std.debug.print("cannot perform the TLS handshake, refusing to send\n", .{});
            return;
        },
        error.AuthenticationFailed => {
            std.debug.print("credentials rejected\n", .{});
            return;
        },
        // The server sent bytes after its 220 but before the handshake — an
        // injected command that would otherwise be read as if it had come
        // from inside the tunnel.
        error.PlaintextInjection => {
            std.debug.print("plaintext injected across the TLS boundary, aborting\n", .{});
            return;
        },
        else => return err,
    };

    const caps = client.serverCapabilities();
    std.debug.print(
        "connected: pipelining={} max_size={?d} auth_plain={}\n",
        .{ caps.pipelining, caps.max_size, caps.auth.plain },
    );

    // The module reads no clock — a timestamp is data the caller supplies,
    // which is also what makes a rendered message reproducible in a test.
    const msg: smtp.Message = .{
        .from = .{ .name = "Nightly Reports", .addr = "reports@example.org" },
        .to = &.{
            .{ .name = "Ops", .addr = "ops@example.net" },
            .{ .addr = "archive@example.net" },
        },
        .subject = "Latency report, 2026-08-21",
        .date = .{ .unix = 1_755_734_400, .offset_minutes = 120 },
        .body = .{ .multipart = .{
            .subtype = .mixed,
            .parts = &.{
                .{ .text = .{ .body = "Two edges over the 30 ms budget. Details attached.\r\n" } },
                .{ .attachment = .{
                    .filename = "latency-2026-08-21.csv",
                    .content_type = "text/csv",
                    .data = report_csv,
                } },
            },
        } },
    };

    // MIME boundaries must not be guessable by anyone who can influence the
    // body; a real sender seeds this from the OS CSPRNG. A fixed seed keeps
    // an example reproducible, and is the wrong choice in production.
    var prng: std.Random.DefaultPrng = .init(0x5EED_1234);

    const doc = client.sendMessage(msg, prng.random(), .{}, .{
        .to = &.{ "ops@example.net", "archive@example.net" },
    }) catch |err| switch (err) {
        // Not a bug in the message: every address the server was offered was
        // refused, so there is no transaction left to run.
        error.AllRecipientsRejected => {
            std.debug.print("nobody accepted the message\n", .{});
            return;
        },
        // The composer refuses to emit a boundary that occurs inside a part,
        // rather than producing a document that silently truncates.
        error.BoundaryCollision => {
            std.debug.print("could not find a MIME boundary unused by the body\n", .{});
            return;
        },
        // The body needs 8BITMIME (RFC 6152) and the server has none.
        error.EightBitNotSupported => {
            std.debug.print("server cannot take an 8-bit body\n", .{});
            return;
        },
        else => return err,
    };
    // The caller gets the exact octets that went out — what a Sent folder or
    // a golden test needs.
    defer gpa.free(doc);
    std.debug.print("sent {d} bytes of RFC 5322 document\n", .{doc.len});

    // A partly-accepted transaction still succeeds. Which addresses bounced is
    // per-recipient state, not an error code, and a mailer has to record it.
    for (client.recipients()) |r| {
        if (r.accepted) continue;
        std.debug.print("rejected {s}: {d}\n", .{ r.addr, r.code });
    }

    try client.quit();
    std.debug.print("session closed in state {s}\n", .{@tagName(client.state())});
}
