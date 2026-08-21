// SPDX-License-Identifier: MIT

//! What a mail-archiving consumer does with `imap`: open a session on streams
//! it owns, upgrade it with STARTTLS, log in, then ask INBOX which messages
//! are unread and pull their envelopes.
//!
//! The peer here is a scripted transcript in memory. That is not a shortcut —
//! it is the module's actual seam: `Client.init` takes a `*std.Io.Reader` and
//! a `*std.Io.Writer` and owns no socket and no TLS, so plain TCP, an
//! encrypted stream and a fixture buffer are all the same thing to it. A
//! downstream test harness gets to drive the real client with no network.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`deps` only, no `test_deps`, no access to anything the module does
//! not export). If a type needed to call the API is not public, or an error
//! cannot be named from outside, this file stops compiling. The module's own
//! tests cannot notice either, because they live inside it.

const std = @import("std");
const imap = @import("imap");

/// What the server says before the TLS handshake. It advertises
/// LOGINDISABLED, which is a server telling clients not to send a password on
/// this link at all — the module refuses `login` outright rather than trusting
/// the caller to check.
const cleartext_script =
    "* OK [CAPABILITY IMAP4rev2 STARTTLS LOGINDISABLED] Service Ready\r\n" ++
    "T1 OK Begin TLS negotiation now\r\n";

/// What the same server says once the link is encrypted. Note LOGINDISABLED
/// is gone: the capability list from before the handshake came from an
/// unauthenticated peer and RFC 9051 §6.2.1 makes the client discard it.
const encrypted_script =
    "* CAPABILITY IMAP4rev2 AUTH=PLAIN\r\n" ++
    "T2 OK CAPABILITY completed\r\n" ++
    "T3 OK LOGIN completed\r\n" ++
    "* 3 EXISTS\r\n" ++
    "* OK [UIDVALIDITY 3857529045] UIDs valid\r\n" ++
    "* OK [UIDNEXT 4392] Predicted next UID\r\n" ++
    "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n" ++
    "* OK [PERMANENTFLAGS (\\Deleted \\Seen \\*)] Limited\r\n" ++
    "T4 OK [READ-WRITE] SELECT completed\r\n" ++
    "* SEARCH 2 3\r\n" ++
    "T5 OK SEARCH completed\r\n" ++
    "* 2 FETCH (UID 4827313 ENVELOPE (" ++
    "\"Wed, 17 Jul 1996 02:23:25 -0700 (PDT)\" " ++
    "\"IMAP4rev2 WG mtg summary and minutes\" " ++
    "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) " ++
    "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) " ++
    "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) " ++
    "((NIL NIL \"imap\" \"cac.washington.edu\")) NIL NIL NIL " ++
    "\"<B27397-0100000@cac.washington.edu>\") RFC822.SIZE 4286)\r\n" ++
    "* 3 FETCH (UID 4827314 ENVELOPE (" ++
    "\"Thu, 18 Jul 1996 09:02:11 -0700\" " ++
    "\"Re: minutes\" " ++
    "((NIL NIL \"klensin\" \"mit.edu\")) NIL NIL " ++
    "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) NIL NIL " ++
    "\"<B27397-0100000@cac.washington.edu>\" " ++
    "\"<B27401-0100000@mit.edu>\") RFC822.SIZE 998)\r\n" ++
    "T6 OK FETCH completed\r\n" ++
    "* BYE Logging out\r\n" ++
    "T7 OK LOGOUT completed\r\n";

/// Unsolicited untagged data can land between any two responses, because it
/// reports something the server just learned. A consumer that cares about
/// live mailbox state registers an observer instead of losing it.
fn onUnilateral(ctx: ?*anyopaque, data: imap.response.Data) anyerror!void {
    _ = ctx;
    switch (data) {
        .exists => |n| std.debug.print("(mailbox now holds {d} messages)\n", .{n}),
        .expunge => |n| std.debug.print("(message {d} was expunged)\n", .{n}),
        else => {},
    }
}

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    // Before the handshake: whatever transport the caller opened.
    var clear_r: std.Io.Reader = .fixed(cleartext_script);
    var clear_wbuf: [4096]u8 = undefined;
    var clear_w: std.Io.Writer = .fixed(&clear_wbuf);

    var c = imap.Client.init(gpa, &clear_r, &clear_w, .{
        .on_unilateral = onUnilateral,
    });
    defer c.deinit();

    _ = try c.greet();

    // A password over cleartext is a password given away. The module makes
    // that a local error rather than a wire event, so it never leaves the
    // process.
    if (c.login("gray", "hunter2")) |_| {
        std.debug.print("unexpected: plaintext LOGIN was accepted\n", .{});
    } else |err| switch (err) {
        error.LoginDisabled => std.debug.print("server forbids LOGIN before TLS\n", .{}),
        error.PlaintextAuth => std.debug.print("refusing to send a password in the clear\n", .{}),
        else => return err,
    }

    if (!c.hasCap("STARTTLS")) {
        std.debug.print("no STARTTLS offered, giving up\n", .{});
        return;
    }

    _ = c.startTls() catch |err| switch (err) {
        // The server sent bytes after its OK, before any peer was
        // authenticated. Replaying those as if they came from inside the
        // tunnel is the classic STARTTLS injection; the module refuses.
        error.PlaintextInjection => {
            std.debug.print("plaintext buffered across the TLS boundary, aborting\n", .{});
            return;
        },
        else => return err,
    };

    // The handshake itself is the caller's job — this module owns no TLS. In
    // a real program these two are `std.crypto.tls.Client`'s streams; here
    // they are the rest of the transcript.
    var tls_r: std.Io.Reader = .fixed(encrypted_script);
    var tls_wbuf: [4096]u8 = undefined;
    var tls_w: std.Io.Writer = .fixed(&tls_wbuf);
    _ = try c.tlsEstablished(&tls_r, &tls_w);

    _ = try c.login("gray", "hunter2");
    // The password bytes are in the writer's buffer, which the caller owns —
    // the module keeps no copy and cannot know when they reached the wire.
    defer std.crypto.secureZero(u8, &tls_wbuf);

    _ = try c.select("INBOX", false);
    std.debug.print(
        "INBOX: {d} messages, uidvalidity {d}, {s}\n",
        .{
            c.mailbox.exists,
            c.mailbox.uid_validity,
            if (c.mailbox.read_only) "read-only" else "read-write",
        },
    );

    // Results outlive the response line they arrived on only if they are
    // allocated somewhere that is not the session's per-line arena.
    var results = std.heap.ArenaAllocator.init(gpa);
    defer results.deinit();

    const unseen = try c.searchMessages(
        results.allocator(),
        false,
        .{},
        &.{ .not_flag = &.{"\\Seen"} },
    );
    std.debug.print("{d} unread message(s)\n", .{unseen.numbers.len});
    if (unseen.numbers.len == 0) return;

    const msgs = c.fetchMessages(results.allocator(), "2:3", false, .{
        .uid = true,
        .envelope = true,
        .rfc822_size = true,
    }) catch |err| switch (err) {
        // The server answered NO or BAD. A mailbox that vanished under us is
        // an ordinary outcome for a background sync, not a crash.
        error.CommandFailed => {
            std.debug.print("server rejected the FETCH\n", .{});
            return;
        },
        else => return err,
    };

    for (msgs) |m| {
        const env = switch (m.find(.envelope) orelse continue) {
            .envelope => |e| e,
            else => continue,
        };
        std.debug.print("#{d} uid={?d} \"{s}\"", .{
            m.seq,
            m.uid(),
            env.subject orelse "(no subject)",
        });
        if (env.from.len > 0) {
            const a = env.from[0];
            std.debug.print(" from {s}@{s}", .{ a.mailbox orelse "?", a.host orelse "?" });
        }
        std.debug.print("\n", .{});
    }

    // LOGOUT gets an untagged BYE first; the module treats that as the
    // expected path rather than a connection error.
    try c.logout();
}
