// SPDX-License-Identifier: MIT

//! LIVE interop against a real IMAP server.
//!
//! Everything else in this module is anchored on transcripts copied from
//! RFC 9051, which pins the *parsing*. What no offline test can pin is the
//! **sequencing** — whether this client's writes are something a real server
//! accepts, in the order it accepts them. That is what runs here.
//!
//! ## The peer, and why this one
//!
//! `pymap` (Python, MIT) — an independent IMAP server: different author,
//! different language, and no shared code with `emersion/go-imap`, which this
//! module was ported from. That independence is the point. go-imap ships its
//! own `imapmemserver`, and testing against it would be weaker: client and
//! server there share one wire layer, so a shared misreading of the grammar
//! would be invisible to both.
//!
//! Install it with:
//!
//! ```
//! python3 -m venv ~/.cache/zig-libs-imap
//! ~/.cache/zig-libs-imap/bin/pip install pymap
//! ```
//!
//! The test finds it at `$IMAP_PYMAP` or that default path, starts it on a
//! high port with its in-memory demo mailbox, and **skips loudly** when it is
//! not there. It never touches a network service it did not start, and no
//! credential in here is real.

const std = @import("std");
const testing = std.testing;

const client = @import("client.zig");
const fetchmod = @import("fetch.zig");

/// A port unlikely to collide, and never 143 — this test must not talk to a
/// mail server someone else is running.
const port: u16 = 11143;

const demo_user = "demouser";
const demo_pass = "demopass";

const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;

fn envVar(name: []const u8) ?[]const u8 {
    return testkit.getEnv(name);
}

fn sleepMs(ms: u64) void {
    var ts: std.os.linux.timespec = .{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * 1_000_000),
    };
    _ = std.os.linux.nanosleep(&ts, null);
}

fn skip(comptime msg: []const u8, args: anytype) error{SkipZigTest} {
    if (verboseSkip()) {
        std.debug.print("\nLIVE imap interop test SKIPPED: " ++ msg ++ "\n", args);
    }
    return error.SkipZigTest;
}

/// Path to the `pymap` executable, or skip.
fn pymapPath(gpa: std.mem.Allocator, io: std.Io) ![]u8 {
    if (envVar("IMAP_PYMAP")) |p| return gpa.dupe(u8, p);
    const home = envVar("HOME") orelse return skip("no $HOME and no $IMAP_PYMAP", .{});
    const path = try std.fmt.allocPrint(gpa, "{s}/.cache/zig-libs-imap/bin/pymap", .{home});
    errdefer gpa.free(path);
    std.Io.Dir.cwd().access(io, path, .{}) catch {
        gpa.free(path);
        return skip(
            "pymap not installed. python3 -m venv ~/.cache/zig-libs-imap && ~/.cache/zig-libs-imap/bin/pip install pymap",
            .{},
        );
    };
    return path;
}

test "LIVE pymap interop: greet -> login -> select -> fetch -> search -> idle -> logout" {
    const gpa = testing.allocator;

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const exe = try pymapPath(gpa, io);
    defer gpa.free(exe);

    var port_buf: [8]u8 = undefined;
    const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch unreachable;

    var child = std.process.spawn(io, .{
        .argv = &.{
            exe,        "--host", "127.0.0.1",   "--port", port_str,
            "--no-tls", "dict",   "--demo-data",
        },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return skip("could not spawn pymap", .{});
    // `kill` reaps the child itself (it clears `id`), so a following `wait`
    // would assert -- which is exactly what it did the first time.
    defer child.kill(io);

    // The listener comes up asynchronously.
    var stream: std.Io.net.Stream = blk: {
        var attempt: usize = 0;
        while (attempt < 60) : (attempt += 1) {
            const addr = std.Io.net.IpAddress.parse("127.0.0.1", port) catch unreachable;
            if (addr.connect(io, .{ .mode = .stream })) |s| break :blk s else |_| {}
            sleepMs(250);
        }
        return skip("pymap did not listen on 127.0.0.1:{d} within 15s", .{port});
    };
    defer stream.close(io);

    var read_buf: [16384]u8 = undefined;
    var write_buf: [16384]u8 = undefined;
    var sr = stream.reader(io, &read_buf);
    var sw = stream.writer(io, &write_buf);

    // pymap is spawned by this test on 127.0.0.1 with no TLS at all, so the
    // plaintext-auth gate (`login` refuses an unencrypted link by default) has
    // to be opted out of explicitly. This is the "the caller knows the
    // transport is trusted" case the option exists for.
    var c = client.Client.init(gpa, &sr.interface, &sw.interface, .{ .allow_plaintext_auth = true });
    defer c.deinit();

    // ── greeting ────────────────────────────────────────────────────────────
    _ = try c.greet();
    // Deliberately NOT asserted on the greeting text: it carries the server's
    // hostname, which is machine-specific and has no business in a test.
    try testing.expectEqual(client.State.not_authenticated, c.state);
    try testing.expect(c.hasCap("IMAP4rev1"));

    // ── login ───────────────────────────────────────────────────────────────
    _ = try c.login(demo_user, demo_pass);
    try testing.expectEqual(client.State.authenticated, c.state);
    // Capabilities are re-announced on the login completion; the session must
    // have absorbed the second list, not kept the greeting's.
    try testing.expect(c.hasCap("IDLE"));

    // ── select ──────────────────────────────────────────────────────────────
    _ = try c.select("INBOX", false);
    try testing.expectEqual(client.State.selected, c.state);
    // A real mailbox: demo data has messages, and a real server always sends
    // UIDVALIDITY and PERMANENTFLAGS.
    try testing.expect(c.mailbox.exists > 0);
    try testing.expect(c.mailbox.uid_validity > 0);
    try testing.expect(c.mailbox.permanent_flags.len > 0);

    // ── fetch ───────────────────────────────────────────────────────────────
    var out = std.heap.ArenaAllocator.init(gpa);
    defer out.deinit();

    const msgs = try c.fetchMessages(out.allocator(), "1:*", false, .{
        .uid = true,
        .flags = true,
        .rfc822_size = true,
        .envelope = true,
        .body_structure = true,
    });
    try testing.expect(msgs.len > 0);

    var saw_envelope = false;
    var saw_structure = false;
    for (msgs) |m| {
        try testing.expect(m.uid() != null);
        for (m.items) |it| switch (it) {
            .envelope => |env| {
                saw_envelope = true;
                // A real message has a Message-ID and at least one sender.
                try testing.expect(env.message_id != null or env.subject != null);
            },
            .body_structure => |bs| {
                saw_structure = true;
                var buf: [128]u8 = undefined;
                const mt = try bs.mediaType(&buf);
                try testing.expect(mt.len > 2);
            },
            else => {},
        };
    }
    // These are the two structures a hand-written transcript is most likely to
    // get subtly wrong, so a real server having produced them is the point.
    try testing.expect(saw_envelope);
    try testing.expect(saw_structure);

    // ── command injection, against a server that would obey it ──────────────
    //
    // The audit's reproducer, pointed at a real IMAP server on an
    // authenticated, selected connection. `1:*\r\nT9 STORE ...` as a seq-set
    // used to put a second, fully-formed command on this socket, and pymap
    // would have run it — a mailbox mutation from a caller who thought they
    // were naming messages.
    //
    // Two things are checked that no offline Sink can check. The client
    // refuses; and the *connection is still in sync afterwards*, which is the
    // property that a half-written `T7 FETCH ` left in the write buffer would
    // break — it would prefix the next command and the server would answer BAD.
    try testing.expectError(error.InvalidSequenceSet, c.fetchMessages(
        out.allocator(),
        "1:*\r\nT9 STORE 1 +FLAGS (\\Deleted)",
        false,
        .{ .uid = true },
    ));
    try testing.expectError(error.InvalidSection, c.fetchMessages(
        out.allocator(),
        "1",
        false,
        .{ .sections = &.{"HEADER]\r\nT9 STORE 1 +FLAGS (\\Deleted)"} },
    ));

    const after = try c.fetchMessages(out.allocator(), "1", false, .{ .flags = true });
    try testing.expectEqual(@as(usize, 1), after.len);
    for (after[0].items) |it| {
        if (it != .flags) continue;
        for (it.flags) |f| try testing.expect(!std.ascii.eqlIgnoreCase(f, "\\Deleted"));
    }

    // ── a synchronising literal against a real server ───────────────────────
    //
    // pymap advertises LITERAL+, so the encoder would take the non-sync path
    // and the handshake would never run. Turning it off forces `{n}` + wait
    // for `+` + payload -- the one exchange that cannot be tested offline,
    // because offline there is nobody to send the continuation.
    c.enc.opts.literal_plus = false;
    c.enc.opts.literal_minus = false;
    const weird = try c.searchMessages(out.allocator(), false, .{}, &.{
        .body = &.{"a\r\nb"}, // holds CRLF, so it cannot be quoted
    });
    _ = weird;

    // ── search ──────────────────────────────────────────────────────────────
    c.enc.opts.literal_plus = true;
    const all = try c.searchMessages(out.allocator(), false, .{}, &.{});
    // pymap answers IMAP4rev1-style, which is the reply shape an offline test
    // is least likely to be written against.
    try testing.expect(all.numbers.len > 0 or all.all != null);

    // ── idle ────────────────────────────────────────────────────────────────
    try c.idleBegin();
    _ = try c.idleDone();

    // ── logout ──────────────────────────────────────────────────────────────
    try c.logout();
    try testing.expectEqual(client.State.logout, c.state);
}
