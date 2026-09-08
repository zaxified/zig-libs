// SPDX-License-Identifier: MIT

//! LIVE loopback exchange for `dns`: this module's `Resolver` against a hostile
//! UDP server, over a real socket, with a real second thread — and the recorder
//! that turns each of those exchanges into a committed frame `test-dns` replays
//! with no socket, no thread and no clock anywhere near it.
//!
//! ## Why this is a PROGRAM and not a test (and why `tools/`, when the "peer"
//! ## is our own stub rather than a foreign toolchain)
//!
//! CONVENTIONS.md §9 puts an instrument that needs a FOREIGN TOOLCHAIN here. A
//! loopback UDP stub written in Zig is plainly not that, so the placement is
//! argued rather than inherited:
//!
//! - What §9 actually separates is an instrument that needs an ENVIRONMENT the
//!   module's own test lane must not depend on, from one that is pure Zig over
//!   bytes. A C compiler is the commonest such environment. A second runnable
//!   thread that must be scheduled inside a timeout, while 215 other test
//!   binaries saturate every core, is another one — and it is the environment
//!   `zig build test-dns` is least able to guarantee, because the gate itself
//!   is what takes it away.
//! - It is mechanically honest: `zig build check-interop` COMPILES every
//!   `tools/interop.zig` with no peer present, and `zig build interop-dns` runs
//!   this one. A program that needs no peer at all is therefore fine on both
//!   lanes — it is never a skip, never a "peer missing" excuse, and
//!   `scripts/test.sh interop` reaches it like the other six.
//! - The one place the shape stretches is the step's own description, "against
//!   a real foreign peer (needs that peer)". For `dns` the peer is the local
//!   kernel's UDP stack plus a thread of our own; nothing is installed and
//!   nothing can be missing. Stated here so the next reader is not misled by
//!   the generic wording.
//!
//! ## What the split is for (audit F20, measured twice)
//!
//! `Resolver.zig` used to carry `test "query: a reply whose question is not
//! ours is not the answer, over loopback"`. It bound a UDP socket, spawned this
//! stub on `io.concurrent`, ran a real `query()` against it and then asserted
//! `stub.served == 1`. It failed on 2026-09-07 with three agents building, and
//! again on 2026-09-08 inside `scripts/test.sh all`, always as `expected 1,
//! found 0`.
//!
//! ⭐ THAT FAILURE WAS NOT A STARVED STUB. `expected 1, found 0` on `served`
//! means the resolver HAD received the datagram and HAD rejected it — the
//! module's own logic was right every time. What was wrong was the measurement:
//! the counter is written by the stub thread and was read by the test thread
//! BEFORE the joining `await` (a `defer`, so it ran after the assertions). The
//! stub was preempted in the one instruction between `send` returning and
//! `served += 1`. Measured on this 8-core machine with 32 busy loops:
//! **10 failures in 20 runs**. So no timeout constant would have fixed it, and
//! neither would putting `dns` in the serial `live` set: an unsynchronised
//! cross-thread read is not a scheduling accident, it is a race that a quiet
//! machine merely hides — and on a weakly-ordered CPU it need not even be
//! preempted to lose.
//!
//! The join is done correctly below (`await` BEFORE any field of the stub is
//! read) precisely because that is the bug this program exists to keep out of
//! `src/`. Everything the old test asserted about PARSING now lives in
//! `Resolver.zig` as a replay of the frames committed under `src/testdata/`,
//! where there is no thread to lose a race with. What only THIS can add — and
//! the reason the frames are not simply hand-written — is that the bytes really
//! do travel over a socket and really are what `query()` feeds to
//! `decodeResponse`: a hand-written fixture proves the parser's verdict, never
//! that the wire path hands the parser that question.
//!
//! ## Usage
//!
//!     zig build interop-dns                  # run every case live, verify the frames
//!     zig build interop-dns -- --capture     # ...and rewrite the committed frames
//!     zig build interop-dns -- --list        # list the case names
//!     zig build interop-dns -- --case wrong-question
//!     zig build interop-dns -- --repo-root P # read/write the frames under P
//!
//! It reads and writes `modules/dns/src/testdata/reply_*.bin` from their own
//! paths at run time, relative to the repository root (which is `zig build`'s
//! working directory). Nothing is embedded here; the module embeds the frames,
//! this program produces them.
//!
//! ⚠ VERIFY, DO NOT REWRITE, is the default — a lane that re-blesses its own
//! anchor is a lane that cannot fail. `--capture` is for a human who has read
//! the mismatch.
//!
//! Nothing here touches the network: the socket is bound to 127.0.0.1 on an
//! ephemeral port and the resolver is pointed straight at it.

const std = @import("std");
const dns = @import("dns");
const netaddr = @import("netaddr");
const net = std.Io.net;

/// The transaction id every committed frame carries.
///
/// The id on the wire is freshly random per datagram (`Resolver.query` re-rolls
/// it for every attempt — audit F9), so the recorded bytes differ on every run
/// and a byte-exact fixture would be impossible. Both the capture and the
/// comparison therefore normalise the first two bytes to this value. That is
/// sound because the id check has its own offline test in `Resolver.zig`
/// ("decodeResponse rejects id mismatch and non-response packets"); what these
/// frames are the anchor for is the QUESTION check, and the replaying test
/// reads the expected id out of the frame rather than assuming this constant.
const frame_id: u16 = 0x1234;

/// Everything after the header is fixed text, so a case is just its two
/// sections plus the verdict `query()` must reach.
const Case = struct {
    /// `--case` name and, as `reply_<name with _>.bin`, the fixture filename.
    name: []const u8,
    why: []const u8,
    /// Question section of the REPLY (empty = qdcount 0).
    question: []const u8,
    answers: []const u8,
    ancount: u16,
    /// True when `Resolver.query` must refuse this reply.
    hostile: bool,

    fn fileName(c: Case, buf: []u8) []const u8 {
        var w: std.Io.Writer = .fixed(buf);
        w.writeAll("reply_") catch unreachable;
        for (c.name) |ch| w.writeByte(if (ch == '-') '_' else ch) catch unreachable;
        w.writeAll(".bin") catch unreachable;
        return w.buffered();
    }
};

const question_echo = "\x07example\x03com\x00\x00\x01\x00\x01";
/// `example.com. 60 IN A 192.0.2.1`, owner written out in full (the compressed
/// `\xc0\x0c` spelling the goldens use would point into a question section that
/// two of these three replies do not have).
const a_example = "\x07example\x03com\x00" ++ "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" ++ "\xc0\x00\x02\x01";
/// `victim.test. 60 IN A 203.0.113.66` — out of bailiwick for `example.com`.
const a_victim = "\x06victim\x04test\x00" ++ "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" ++ "\xcb\x00\x71\x42";

const cases = [_]Case{
    .{
        .name = "wrong-question",
        .why = "question section says attacker.example TXT; must not answer example.com A",
        .question = "\x08attacker\x07example\x00\x00\x10\x00\x01",
        .answers = a_example,
        .ancount = 1,
        .hostile = true,
    },
    .{
        .name = "no-question",
        .why = "no question section at all (qdcount 0); must not answer example.com A",
        .question = "",
        .answers = a_example,
        .ancount = 1,
        .hostile = true,
    },
    .{
        // ⭐ THE POSITIVE CONTROL, and it is not optional. Without a reply that
        // must be ACCEPTED, both this program and the replay in `Resolver.zig`
        // stay green against a `decodeResponse` that refuses everything, and
        // against a fixture that has decayed into garbage.
        .name = "honest",
        .why = "our question echoed verbatim; accepted, and the off-bailiwick record it also carries is dropped later",
        .question = question_echo,
        .answers = a_victim ++ a_example,
        .ancount = 2,
        .hostile = false,
    },
};

/// One-shot hostile UDP server: takes one query, answers per `case`, keeps the
/// bytes it sent.
const Stub = struct {
    io: std.Io,
    sock: net.Socket,
    case: Case,
    sent: [512]u8 = undefined,
    sent_len: usize = 0,
    err: ?anyerror = null,

    fn run(st: *Stub) void {
        st.serveOne() catch |e| {
            st.err = e;
        };
    }

    fn serveOne(st: *Stub) !void {
        var rbuf: [dns.max_query_len]u8 = undefined;
        const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(10_000), .clock = .awake } };
        const incoming = try st.sock.receiveTimeout(st.io, &rbuf, t.toDeadline(st.io));
        const q = incoming.data;

        var w: std.Io.Writer = .fixed(&st.sent);
        try w.writeAll(q[0..2]); // echo the id the resolver rolled for this attempt
        try w.writeInt(u16, 0x8180, .big); // QR + RD + RA, rcode 0
        try w.writeInt(u16, if (st.case.question.len == 0) 0 else 1, .big);
        try w.writeInt(u16, st.case.ancount, .big);
        try w.writeInt(u16, 0, .big);
        try w.writeInt(u16, 0, .big);
        try w.writeAll(st.case.question);
        try w.writeAll(st.case.answers);
        const resp = w.buffered();

        try st.sock.send(st.io, &incoming.from, resp);
        st.sent_len = resp.len;
    }
};

/// Static: `Options.servers` keeps the slice, so an `&.{…}` literal written
/// inside the `init` call would dangle (audit note, 2026-09-06).
const loopback_servers = [_]netaddr.Ip{.{ .v4 = .{ 127, 0, 0, 1 } }};

const Outcome = struct {
    /// The reply as sent, with the id normalised to `frame_id`.
    frame: []const u8,
    /// null when `query` returned a message.
    err: ?anyerror,
    answers: usize,
};

/// Run one case end to end over a real loopback socket.
fn runCase(gpa: std.mem.Allocator, io: std.Io, case: Case) !Outcome {
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = try addr.bind(io, .{ .mode = .dgram });
    var stub: Stub = .{ .io = io, .sock = sock, .case = case };
    defer stub.sock.close(io);

    var fut = try io.concurrent(Stub.run, .{&stub});

    var r = dns.Resolver.init(io, gpa, .{
        .servers = &loopback_servers,
        .port = stub.sock.address.getPort(),
        .timeout_ms = 5000,
        .attempts = 1,
        .use_hosts = false,
        .use_search = false,
    });
    defer r.deinit();

    const result = r.query("example.com", .a);

    // ⛔ JOIN FIRST, READ THE STUB'S FIELDS AFTER. This one line is the whole
    // reason audit F20 exists: the old test in `src/` read `stub.served` while
    // the STUB thread was still runnable and lost the race 10 times in 20 under
    // load. `await` is bounded here — the stub's own receive has a 10 s
    // deadline, so a stub that was never reached still returns.
    fut.await(io);
    if (stub.err) |e| return e;

    var answers: usize = 0;
    var err: ?anyerror = null;
    if (result) |msg| {
        var m = msg;
        defer m.deinit();
        answers = m.answers.len;
    } else |e| {
        err = e;
    }

    const frame = try gpa.dupe(u8, stub.sent[0..stub.sent_len]);
    if (frame.len >= 2) std.mem.writeInt(u16, frame[0..2], frame_id, .big);
    return .{ .frame = frame, .err = err, .answers = answers };
}

const testdata_dir = "modules/dns/src/testdata";

const usage =
    \\dns live loopback interop: a hostile UDP server, a real socket, a real thread.
    \\
    \\  zig build interop-dns                   run every case live, verify the frames
    \\  zig build interop-dns -- --capture      ...and rewrite the committed frames
    \\  zig build interop-dns -- --case NAME    run one case (repeatable)
    \\  zig build interop-dns -- --list         list the case names
    \\  zig build interop-dns -- --repo-root P  read/write the frames under P
    \\
    \\Needs no peer and no network: the server is this program, on 127.0.0.1.
    \\The hermetic half — replaying the frames it commits — is `zig build test-dns`.
    \\
;

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    // An arena over it: a fixed number of short exchanges and then exit. The
    // alternative is threading `free` through every diagnosis path, where a
    // forgotten one turns a real interop failure into a leak report printed on
    // top of it.
    var arena: std.heap.ArenaAllocator = .init(da.allocator());
    defer arena.deinit();
    const gpa = arena.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var capture = false;
    var repo_root: []const u8 = ".";
    var selected: [cases.len][]const u8 = undefined;
    var selected_len: usize = 0;

    var args = init.args.iterate();
    _ = args.next(); // argv[0]
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--capture")) {
            capture = true;
        } else if (std.mem.eql(u8, arg, "--list")) {
            for (cases) |c| std.debug.print("{s}\t{s}\n", .{ c.name, c.why });
            return 0;
        } else if (std.mem.eql(u8, arg, "--case")) {
            const name = args.next() orelse {
                std.debug.print("--case needs a name\n{s}", .{usage});
                return 2;
            };
            if (selected_len == selected.len) return 2;
            selected[selected_len] = name;
            selected_len += 1;
        } else if (std.mem.eql(u8, arg, "--repo-root")) {
            repo_root = args.next() orelse {
                std.debug.print("--repo-root needs a path\n{s}", .{usage});
                return 2;
            };
        } else {
            std.debug.print("unknown argument \"{s}\"\n{s}", .{ arg, usage });
            return 2;
        }
    }

    var root = std.Io.Dir.cwd().openDir(io, repo_root, .{}) catch {
        std.debug.print("cannot open repository root \"{s}\" — run this as `zig build interop-dns` or pass --repo-root\n", .{repo_root});
        return 2;
    };
    defer root.close(io);

    if (capture) {
        var dir = root.createDirPathOpen(io, testdata_dir, .{}) catch |e| {
            std.debug.print("cannot create {s}: {t}\n", .{ testdata_dir, e });
            return 2;
        };
        dir.close(io);
    }

    var ran: usize = 0;
    var bad: usize = 0;
    for (cases) |case| {
        if (selected_len != 0) {
            var wanted = false;
            for (selected[0..selected_len]) |s| {
                if (std.mem.eql(u8, s, case.name)) wanted = true;
            }
            if (!wanted) continue;
        }
        ran += 1;

        const out = runCase(gpa, io, case) catch |e| {
            std.debug.print("{s}: the exchange itself failed: {t}\n", .{ case.name, e });
            bad += 1;
            continue;
        };

        // 1. The resolver's verdict on a real wire round trip.
        if (case.hostile) {
            if (out.err) |e| {
                if (e != error.MalformedResponse) {
                    std.debug.print("{s}: expected error.MalformedResponse over the wire, got {t}\n", .{ case.name, e });
                    bad += 1;
                    continue;
                }
            } else {
                std.debug.print("{s}: the resolver ACCEPTED a reply that does not echo our question\n", .{case.name});
                bad += 1;
                continue;
            }
        } else {
            if (out.err) |e| {
                std.debug.print("{s}: the resolver refused an honest reply: {t}\n", .{ case.name, e });
                bad += 1;
                continue;
            }
            if (out.answers != case.ancount) {
                std.debug.print("{s}: expected {d} answer records, decoded {d}\n", .{ case.name, case.ancount, out.answers });
                bad += 1;
                continue;
            }
        }

        // 2. The frame the module replays must be the frame that travelled.
        var name_buf: [64]u8 = undefined;
        const path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ testdata_dir, case.fileName(&name_buf) });
        if (capture) {
            root.writeFile(io, .{ .sub_path = path, .data = out.frame }) catch |e| {
                std.debug.print("{s}: cannot write {s}: {t}\n", .{ case.name, path, e });
                bad += 1;
                continue;
            };
            std.debug.print("{s}: captured {d} bytes -> {s}\n", .{ case.name, out.frame.len, path });
            continue;
        }
        const committed = root.readFileAlloc(io, path, gpa, .limited(64 * 1024)) catch |e| {
            std.debug.print("{s}: cannot read {s}: {t} — re-take with `zig build interop-dns -- --capture`\n", .{ case.name, path, e });
            bad += 1;
            continue;
        };
        if (!std.mem.eql(u8, committed, out.frame)) {
            std.debug.print(
                "{s}: MISMATCH — {s} holds {d} bytes, the wire carried {d}; `test-dns` is replaying something the socket no longer produces\n",
                .{ case.name, path, committed.len, out.frame.len },
            );
            bad += 1;
            continue;
        }
        std.debug.print("{s}: ok ({d} bytes, verdict {s})\n", .{
            case.name,
            out.frame.len,
            if (case.hostile) "refused" else "accepted",
        });
    }

    if (ran == 0) {
        std.debug.print("no case matched\n{s}", .{usage});
        return 2;
    }
    std.debug.print("dns interop: {d} case(s), {d} failure(s)\n", .{ ran, bad });
    return if (bad == 0) 0 else 1;
}
