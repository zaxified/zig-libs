// SPDX-License-Identifier: MIT

//! Byte-exact goldens **captured from a live session** against a third-party
//! SMTP server (Python `aiosmtpd` 1.4.6 on CPython 3.14), recorded by a TCP
//! proxy that logged both directions verbatim. Nothing here is hand-written:
//! `live_server` is what the server sent, `live_client` is what this module
//! put on the wire, and the test below replays the former into the pure
//! `Session` and asserts it reproduces the latter octet for octet.
//!
//! That makes this the strongest test in the module: the reply parser is fed
//! foreign bytes (including a 7-line EHLO whose last line is the only one with
//! a space separator), the capability set, the AUTH exchange, the PIPELINING
//! grouping, the `SIZE=` parameter, the MIME composition and the dot-stuffing
//! are all re-derived from scratch, and any drift in any of them changes the
//! output. See SPEC.md for how the capture was made and how to redo it.
//!
//! The only edit made to the captured bytes: the server was started with
//! `server_hostname="oracle.example.com"` so the transcript carries no local
//! machine name. Everything else is verbatim.

const std = @import("std");
const testing = std.testing;

const reply = @import("reply.zig");
const session = @import("session.zig");
const message = @import("message.zig");
const data = @import("data.zig");
const capabilities = @import("capabilities.zig");

/// Server → client, verbatim.
pub const live_server =
    "220 oracle.example.com aiosmtpd interop oracle\r\n" ++
    "250-oracle.example.com\r\n" ++
    "250-SIZE 33554432\r\n" ++
    "250-8BITMIME\r\n" ++
    "250-SMTPUTF8\r\n" ++
    "250-AUTH LOGIN PLAIN\r\n" ++
    "250-PIPELINING\r\n" ++
    "250 HELP\r\n" ++
    "235 2.7.0 Authentication successful\r\n" ++
    "250 OK\r\n" ++
    "250 OK\r\n" ++
    "354 End data with <CR><LF>.<CR><LF>\r\n" ++
    "250 2.0.0 Message accepted for delivery\r\n" ++
    "221 Bye\r\n";

/// Client → server, verbatim (what this module produced).
pub const live_client =
    "EHLO client.example.org\r\n" ++
    "AUTH PLAIN AHRlc3RlcgBzM2NyZXQ=\r\n" ++
    "MAIL FROM:<sender@example.com> SIZE=1058\r\n" ++
    "RCPT TO:<rcpt@example.net>\r\n" ++
    "DATA\r\n" ++
    "Date: Wed, 22 Jul 2026 12:00:00 +0200\r\n" ++
    "From: Zig Tester <sender@example.com>\r\n" ++
    "To: =?utf-8?Q?Recipient_=C5=98?= <rcpt@example.net>\r\n" ++
    "Message-ID: <live-test@example.com>\r\n" ++
    "Subject: =?utf-8?B?xb1pdsOhIHprb3XFoWthIOKAlCBsaXZlIGludGVyb3A=?=\r\n" ++
    "MIME-Version: 1.0\r\n" ++
    "Content-Type: multipart/mixed; boundary=\"=_zigsmtp_8sqhIJwVXygCzGxw\"\r\n" ++
    "\r\n" ++
    "--=_zigsmtp_8sqhIJwVXygCzGxw\r\n" ++
    "Content-Type: multipart/alternative; boundary=\"=_zigsmtp_PRCGuDMWV-inq4cE\"\r\n" ++
    "\r\n" ++
    "--=_zigsmtp_PRCGuDMWV-inq4cE\r\n" ++
    "Content-Type: text/plain; charset=\"utf-8\"\r\n" ++
    "Content-Transfer-Encoding: quoted-printable\r\n" ++
    "\r\n" ++
    "prvn=C3=AD\r\n" ++
    "..\r\n" ++
    "t=C5=99et=C3=AD\r\n" ++
    "\r\n" ++
    "--=_zigsmtp_PRCGuDMWV-inq4cE\r\n" ++
    "Content-Type: text/html; charset=\"utf-8\"\r\n" ++
    "Content-Transfer-Encoding: quoted-printable\r\n" ++
    "\r\n" ++
    "<p>prvn=C3=AD</p>\r\n" ++
    "<p>.</p>\r\n" ++
    "\r\n" ++
    "--=_zigsmtp_PRCGuDMWV-inq4cE--\r\n" ++
    "--=_zigsmtp_8sqhIJwVXygCzGxw\r\n" ++
    "Content-Type: text/plain; name*=UTF-8''%C3%BA%C4%8Dtenka.txt\r\n" ++
    "Content-Transfer-Encoding: base64\r\n" ++
    "Content-Disposition: attachment; filename*=UTF-8''%C3%BA%C4%8Dtenka.txt\r\n" ++
    "\r\n" ++
    "YXR0YWNobWVudCBsaW5lIDEKLgphdHRhY2htZW50IGxpbmUgMwo=\r\n" ++
    "--=_zigsmtp_8sqhIJwVXygCzGxw--\r\n" ++
    ".\r\n" ++
    "QUIT\r\n";

/// The message the live test composed, reproduced exactly. The seed is the one
/// the live test used, so the MIME boundaries come out identical.
const live_seed: u64 = 0x5A17;

fn liveMessage() message.Message {
    return .{
        .from = .{ .name = "Zig Tester", .addr = "sender@example.com" },
        .to = &.{.{ .name = "Recipient \u{158}", .addr = "rcpt@example.net" }},
        .subject = "\u{17d}iv\u{e1} zkou\u{161}ka \u{2014} live interop",
        .date = .{ .unix = 1784714400, .offset_minutes = 120 },
        .message_id = "live-test@example.com",
        .body = .{ .multipart = .{ .subtype = .mixed, .parts = &.{
            .{ .multipart = .{ .subtype = .alternative, .parts = &.{
                .{ .text = .{ .body = "prvn\u{ed}\r\n.\r\nt\u{159}et\u{ed}\r\n" } },
                .{ .text = .{ .subtype = "html", .body = "<p>prvn\u{ed}</p>\r\n<p>.</p>\r\n" } },
            } } },
            .{ .attachment = .{
                .filename = "\u{fa}\u{10d}tenka.txt",
                .content_type = "text/plain",
                .data = "attachment line 1\n.\nattachment line 3\n",
            } },
        } } },
    };
}

test "golden: the captured EHLO reply parses to the capability set we acted on" {
    const gpa = testing.allocator;
    var p: reply.Parser = .init(gpa, .{}, .{});
    defer p.deinit();
    try p.feed(live_server);

    const greeting = (try p.next()).?;
    try testing.expectEqual(@as(u16, 220), greeting.code);
    try testing.expectEqualStrings("oracle.example.com aiosmtpd interop oracle", greeting.text);

    const ehlo = (try p.next()).?;
    try testing.expectEqual(@as(u16, 250), ehlo.code);
    // Seven physical lines, six of them continuations — the `-` vs SP test,
    // against bytes we did not write.
    try testing.expectEqual(@as(usize, 7), ehlo.lines);

    var caps = try capabilities.parse(gpa, ehlo.text, .{});
    defer caps.deinit();
    try testing.expectEqualStrings("oracle.example.com", caps.domain);
    try testing.expectEqual(@as(?u64, 33554432), caps.max_size);
    try testing.expect(caps.eightbitmime and caps.smtputf8 and caps.pipelining);
    try testing.expect(caps.auth.plain and caps.auth.login);
    try testing.expect(!caps.starttls);
    try testing.expect(!caps.enhanced_status_codes);
    try testing.expect(caps.has("HELP"));
}

test "golden: replaying the live server's bytes reproduces our exact wire output" {
    const gpa = testing.allocator;

    var prng = std.Random.DefaultPrng.init(live_seed);
    const doc = try message.render(gpa, liveMessage(), prng.random(), .{});
    defer gpa.free(doc);

    var s: session.Session = .init(gpa, .{
        .ehlo_domain = "client.example.org",
        .tls = .disabled,
        .allow_plaintext_auth = true,
        .credentials = .{ .username = "tester", .password = "s3cret" },
    });
    defer s.deinit();

    var p: reply.Parser = .init(gpa, .{}, .{});
    defer p.deinit();
    // The whole server stream at once: the parser has to find every reply
    // boundary itself.
    try p.feed(live_server);

    var sent: std.ArrayList(u8) = .empty;
    defer sent.deinit(gpa);

    var queued = false;
    var guard: usize = 0;
    while (guard < 100) : (guard += 1) {
        switch (try s.next()) {
            .send => |b| try sent.appendSlice(gpa, b),
            .send_body => |b| {
                const wire = try data.stuffAlloc(gpa, b, .{});
                defer gpa.free(wire);
                try sent.appendSlice(gpa, wire);
            },
            .recv => try s.feedReply((try p.next()).?),
            .start_tls => return error.TestUnexpectedResult,
            .done => {
                if (!queued) {
                    queued = true;
                    try s.beginTransaction(.{
                        .from = "sender@example.com",
                        .to = &.{"rcpt@example.net"},
                        .body = doc,
                    });
                    continue;
                }
                if (s.state == .ready) {
                    s.requestQuit();
                    continue;
                }
                break;
            },
        }
    }

    try testing.expectEqual(session.State.closed, s.state);
    try testing.expectEqualStrings(live_client, sent.items);
    // Every reply in the capture was consumed; nothing was left unread.
    try testing.expect((try p.next()) == null);
}

test "golden: a third-party CLIENT produces the same AUTH PLAIN octets" {
    // `swaks` (DEVRELEASE), an unrelated SMTP client, was pointed at the same
    // server with the same credentials and emitted, verbatim:
    //
    //      -> AUTH PLAIN AHRlc3RlcgBzM2NyZXQ=
    //
    // The same string appears in our own capture above. Two independent
    // implementations agreeing on the RFC 4616 encoding of the same
    // credentials is a stronger statement than either one's self-consistency.
    const auth = @import("auth.zig");
    var buf: [64]u8 = undefined;
    const ours = try auth.plainResponse(&buf, "", "tester", "s3cret");
    try testing.expectEqualStrings("AHRlc3RlcgBzM2NyZXQ=", ours);
    try testing.expect(std.mem.indexOf(u8, live_client, "AUTH PLAIN AHRlc3RlcgBzM2NyZXQ=\r\n") != null);
}

test "golden: the message inside the capture is what we compose today" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(live_seed);
    const doc = try message.render(gpa, liveMessage(), prng.random(), .{});
    defer gpa.free(doc);

    // Pull the DATA payload back out of the client capture and un-stuff it: it
    // must be exactly the document we render.
    const marker = "DATA\r\n";
    const start = std.mem.indexOf(u8, live_client, marker).? + marker.len;
    var u: data.Unstuffer = .init(gpa, .{});
    defer u.deinit();
    // Byte at a time, so the un-stuffer decides where the stream ends — the
    // QUIT that follows it in the capture must not be swallowed as body.
    var consumed: usize = 0;
    while (start + consumed < live_client.len) : (consumed += 1) {
        if (try u.feed(live_client[start + consumed ..][0..1])) break;
    }
    try testing.expectEqualStrings(doc, u.bytes());
    try testing.expectEqualStrings("QUIT\r\n", live_client[start + consumed + 1 ..]);

    // ...and the wire really carried the doubled period that the un-stuffed
    // document contains as a single one.
    try testing.expect(std.mem.indexOf(u8, live_client, "\r\n..\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, doc, "\r\n.\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, live_client, "\r\n.\r\nQUIT\r\n"));
}
