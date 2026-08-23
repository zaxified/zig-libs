// SPDX-License-Identifier: MIT

//! What a WebSocket server built on `websocket` actually does with the
//! module: validate an opening handshake, answer 101, then parse and write
//! real frames off a real socket — against a genuinely independent RFC 6455
//! peer, not bytes this repository invented.
//!
//! **External judge, ACTUALLY RUN**: Python's `websockets` 15.0.1
//! (BSD-3-Clause), driven as a real client over loopback via
//! `websockets.sync.client.connect`. It is the peer for the live section
//! below: it generates its own `Sec-WebSocket-Key`, masks its own frames
//! (§5.1), and will refuse the handshake outright if this module's
//! `Sec-WebSocket-Accept` doesn't match what it computed independently — so
//! a live, successful `connect()` is itself an external confirmation of
//! `computeAcceptKey`, on top of the byte-exact worked-example check below.
//! It also exercises `send()` with an iterable, which the library fragments
//! into one frame per item (RFC 6455 §5.4) — a real independent
//! implementation's fragmentation, not bytes typed in by hand — and a real
//! `close()`, whose sync client blocks for the peer's own close frame
//! (§7.1.1), so this module's `writeFrame`d reply has to be correct or the
//! Python process hangs and the watchdog below fires.
//!
//! **Used only as a documented fixture** (no peer needed — RFC 6455's own
//! normative text is the judge): the accept-key worked example (§1.3) is
//! also checked directly, byte-exact, with no network involved; and the
//! rejection of an unmasked client-role frame (§5.1: "a client MUST mask
//! all frames... a server MUST NOT mask") is a hand-built wire buffer fed
//! straight to `frame.parseFrame`, since no conformant peer would ever send
//! that frame for us to catch — the whole point is that OUR parser refuses
//! it.
//!
//! `handshake`/`frame`/`connection` do no I/O and no allocation at all — see
//! root.zig — so there is nothing to leak in the live section below. The
//! standalone oversized-message check allocates the reassembly buffer
//! itself (a real caller's job per the `message_buf` contract) to give the
//! `DebugAllocator` leak check something on a failure path to actually
//! prove.
//!
//! Built against the PUBLISHED module (`@import("websocket")`, plus its one
//! declared dep `@import("http")` for `h1.RequestHead`/`readHead`) — no
//! `test_deps`, no reaching into `src/`. `zig build check-examples` builds
//! this against exactly that surface.

const std = @import("std");
const http = @import("http");
const websocket = @import("websocket");

/// RFC 6455 §1.3's own worked example, checked byte-exact with no socket
/// involved at all.
fn checkAcceptKeyWorkedExample() !void {
    const accept = websocket.handshake.computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==");
    if (!std.mem.eql(u8, &accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")) return error.AcceptKeyMismatch;
    std.debug.print("RFC 6455 S1.3 worked example: computeAcceptKey byte-exact\n", .{});
}

/// RFC 6455 §5.1: "a client MUST mask all frames... a server MUST NOT mask
/// any frames". A server-role parser fed an unmasked frame must reject it
/// by NAMED error — this is this module's own input validation, so it needs
/// no external peer to judge it (a conformant peer would never send it).
fn checkMalformedFrameRejected() !void {
    // FIN=1, opcode=text, MASK bit unset, len=5, "Hello" — a well-formed
    // frame in every respect except the masking direction a server requires.
    var wire = [_]u8{ 0x81, 0x05, 'H', 'e', 'l', 'l', 'o' };
    if (websocket.frame.parseFrame(&wire, .server, 1 << 16)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.UnmaskedClientFrame => std.debug.print(
            "unmasked client frame (S5.1): UnmaskedClientFrame (expected)\n",
            .{},
        ),
        else => return err,
    }
}

/// `message_buf`'s doc comment (connection.zig) says its length *is* the
/// caller's aggregate memory budget: a message that doesn't fit is
/// MessageTooLarge, not a bigger allocation. Allocate that buffer for real,
/// hit the cap on purpose, and let `defer` prove the failure path doesn't
/// leak — the module itself never allocates (root.zig), so this is the only
/// place in this example an allocation happens at all.
fn checkOversizedMessageRejected(gpa: std.mem.Allocator) !void {
    const msg_buf = try gpa.alloc(u8, 4); // deliberately smaller than the message below
    defer gpa.free(msg_buf);

    var conn = websocket.connection.Connection.init(.client, msg_buf, 1 << 20);
    // FIN=1, opcode=text, unmasked (client-role parser: masked frames are
    // rejected, so this must stay unmasked to reach the size check), 10-byte
    // payload against a 4-byte message_buf.
    var wire = [_]u8{ 0x81, 0x0a } ++ "abcdefghij".*;
    if (conn.receive(&wire)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.MessageTooLarge => std.debug.print(
            "10-byte message over a 4-byte message_buf: MessageTooLarge (expected)\n",
            .{},
        ),
        else => return err, // still reached through the `defer gpa.free` above
    }
}

// ── live section: a real socket, a real independent RFC 6455 peer ─────────

/// Watchdog ceiling for the whole live exchange (handshake + 3 frames +
/// closing handshake), all on loopback. Generous for a slow CI host; nowhere
/// near what a hang would take to be noticed otherwise.
const watchdog_ms: u64 = 15_000;

const ServerResult = struct {
    failed: bool = false,
    err_name: []const u8 = "",
    masked_ok: bool = false,
    frag_buf: [64]u8 = undefined,
    frag_len: usize = 0,
    close_code: ?u16 = null,
    close_reason_buf: [32]u8 = undefined,
    close_reason_len: usize = 0,
    both_closed: bool = false,
};

const ServerCtx = struct {
    io: std.Io,
    listener: *std.Io.net.Server,
    result: ServerResult = .{},
};

/// `frame.parseFrame`/`connection.Connection.receive` are pure codecs over a
/// caller-supplied buffer (root.zig: "does not open sockets"); reading
/// exactly one frame's worth of bytes off a stream and retrying on
/// `.need_more` is explicitly the caller's job per the module's own docs.
/// This decodes just enough of the length prefix (RFC 6455 §5.2) to know how
/// many bytes to peek, copies them out, and advances the reader — no
/// protocol validation happens here, that is still entirely `frame`'s job.
fn readOneFrameInto(r: *std.Io.Reader, scratch: []u8) ![]u8 {
    const head2 = try r.peek(2);
    const len7 = head2[1] & 0x7f;
    const masked = (head2[1] & 0x80) != 0;
    var header_len: usize = 2;
    if (len7 == 126) header_len += 2 else if (len7 == 127) header_len += 8;
    const pre = try r.peek(header_len);
    var payload_len: u64 = len7;
    if (len7 == 126) payload_len = std.mem.readInt(u16, pre[2..4], .big);
    if (len7 == 127) payload_len = std.mem.readInt(u64, pre[2..10], .big);
    if (masked) header_len += 4;
    const total: usize = header_len + std.math.cast(usize, payload_len).?;
    if (total > scratch.len) return error.FrameTooLargeForScratch;
    const wire = try r.peek(total);
    @memcpy(scratch[0..total], wire);
    r.toss(total);
    return scratch[0..total];
}

fn runServer(ctx: *ServerCtx) !void {
    var stream = try ctx.listener.accept(ctx.io);
    defer stream.close(ctx.io);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [1024]u8 = undefined;
    var sr = stream.reader(ctx.io, &rbuf);
    var sw = stream.writer(ctx.io, &wbuf);

    // ── opening handshake (S1.3/S4): validate the client's real Upgrade
    // request and answer 101 ────────────────────────────────────────────
    var head_buf: [2048]u8 = undefined;
    const head_bytes = try http.h1.readHead(&sr.interface, &head_buf);
    const head = try http.h1.RequestHead.parse(head_bytes);
    const accept = try websocket.handshake.acceptHandshake(head, .{});
    try websocket.handshake.writeResponse(&sw.interface, accept);
    try sw.interface.flush();

    // ── frame 1: a real masked single-frame text message from a real
    // client (S5.1's masking direction) ─────────────────────────────────
    var scratch: [512]u8 = undefined;
    const bytes1 = try readOneFrameInto(&sr.interface, &scratch);
    const parsed1 = switch (try websocket.frame.parseFrame(bytes1, .server, 1 << 16)) {
        .frame => |f| f,
        .need_more => return error.UnexpectedNeedMore,
    };
    if (!parsed1.masked) return error.ExpectedMaskedClientFrame;
    if (parsed1.opcode != .text) return error.WrongOpcode;
    if (!std.mem.eql(u8, parsed1.payload, "hello from python")) return error.PayloadMismatch;
    ctx.result.masked_ok = true;

    // ── a real fragmented message (S5.4), reassembled through
    // `connection.Connection`. The library's own `send(iterable)` decides
    // how many wire frames a 2-item iterable becomes (measured: 3, not the
    // naive "N items = N frames") -- looping to `.message` instead of
    // assuming a fixed count is what makes this a real reassembly test
    // rather than a rehearsed one. ───────────────────────────────────────
    var msg_buf: [64]u8 = undefined;
    var conn = websocket.connection.Connection.init(.server, &msg_buf, 1 << 16);

    var got_msg = false;
    var frames_seen: usize = 0;
    while (!got_msg and frames_seen < 8) : (frames_seen += 1) {
        const bytes = try readOneFrameInto(&sr.interface, &scratch);
        const r = try conn.receive(bytes);
        switch (r.event) {
            .message => |m| {
                @memcpy(ctx.result.frag_buf[0..m.payload.len], m.payload);
                ctx.result.frag_len = m.payload.len;
                got_msg = true;
            },
            .frame_consumed => {},
            else => return error.UnexpectedEvent,
        }
    }
    if (!got_msg) return error.NoMessage;

    // ── a real close frame (S5.5.1/S7.4.1), then answer it to complete the
    // closing handshake (S7.1.1) the Python peer is blocked on ───────────
    const bytes4 = try readOneFrameInto(&sr.interface, &scratch);
    const r4 = try conn.receive(bytes4);
    const close_info = switch (r4.event) {
        .close => |c| c,
        else => return error.UnexpectedEvent,
    };
    ctx.result.close_code = close_info.code;
    @memcpy(ctx.result.close_reason_buf[0..close_info.reason.len], close_info.reason);
    ctx.result.close_reason_len = close_info.reason.len;

    var body_buf: [16]u8 = undefined;
    const body = try websocket.frame.encodeCloseBody(&body_buf, 1000, "bye");
    try websocket.frame.writeFrame(&sw.interface, .{ .opcode = .close, .payload = body, .mask_key = null });
    try sw.interface.flush();
    conn.close_sent = true;
    ctx.result.both_closed = conn.bothClosed();
}

fn serverThreadMain(ctx: *ServerCtx) void {
    runServer(ctx) catch |err| {
        ctx.result.failed = true;
        ctx.result.err_name = @errorName(err);
    };
}

fn watchdogFn(stop: *std.atomic.Value(bool)) void {
    // `std.Thread.sleep` is gone in this Zig version -- raw `nanosleep`,
    // same as `modules/grpc/src/reference_interop.zig`'s own F1 watchdog.
    const poll_ms: u64 = 50;
    var waited_ms: u64 = 0;
    while (waited_ms < watchdog_ms) : (waited_ms += poll_ms) {
        if (stop.load(.acquire)) return;
        var ts: std.posix.timespec = .{
            .sec = @intCast(poll_ms / 1000),
            .nsec = @intCast((poll_ms % 1000) * 1_000_000),
        };
        _ = std.os.linux.nanosleep(&ts, null);
    }
    if (stop.load(.acquire)) return;
    std.debug.print(
        "\nwebsocket example WATCHDOG FIRED: the live exchange ran past {d} ms " ++
            "-- exiting instead of hanging.\n",
        .{watchdog_ms},
    );
    std.process.exit(1);
}

/// The Python peer script. Takes the loopback port as argv[1] so no string
/// formatting is needed on the Zig side beyond the port itself.
const python_script =
    \\import sys
    \\from websockets.sync.client import connect
    \\
    \\port = int(sys.argv[1])
    \\with connect(f"ws://127.0.0.1:{port}/", compression=None, open_timeout=5, close_timeout=5) as ws:
    \\    ws.send("hello from python")
    \\    print("PY: sent masked single-frame text message", flush=True)
    \\    ws.send(iter(["frag-A-", "frag-B"]))
    \\    print("PY: sent fragmented text message (2 frames)", flush=True)
    \\    ws.close(code=1000, reason="bye")
    \\    print("PY: closing handshake completed", flush=True)
    \\print("PYTHON_OK", flush=True)
;

fn runLiveExchange(gpa: std.mem.Allocator) !void {
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try addr.listen(io, .{});
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var ctx: ServerCtx = .{ .io = io, .listener = &listener };
    const server_thread = try std.Thread.spawn(.{}, serverThreadMain, .{&ctx});

    var watchdog_stop: std.atomic.Value(bool) = .init(false);
    const watchdog_thread = try std.Thread.spawn(.{}, watchdogFn, .{&watchdog_stop});
    defer {
        watchdog_stop.store(true, .release);
        watchdog_thread.join();
    }

    var port_buf: [8]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{port});

    var child = std.process.spawn(io, .{
        .argv = &.{ "python3", "-c", python_script, port_str },
        .stdin = .close,
        .stdout = .pipe,
        .stderr = .inherit,
    }) catch |err| {
        std.debug.print(
            "websocket example: could not spawn python3 (external judge unavailable): {t}\n",
            .{err},
        );
        return err;
    };

    var out_buf: [1024]u8 = undefined;
    var stdout_reader = child.stdout.?.reader(io, &out_buf);
    var saw_ok = false;
    while (true) {
        const line = stdout_reader.interface.takeDelimiterInclusive('\n') catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        std.debug.print("{s}", .{line});
        if (std.mem.indexOf(u8, line, "PYTHON_OK") != null) saw_ok = true;
    }

    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) {
            std.debug.print("websocket example: python3 websockets peer exited {d}\n", .{code});
            return error.PythonPeerFailed;
        },
        else => return error.PythonPeerFailed,
    }
    if (!saw_ok) return error.PythonPeerFailed;

    server_thread.join();

    const r = ctx.result;
    if (r.failed) {
        std.debug.print("websocket example: server side failed: {s}\n", .{r.err_name});
        return error.ServerSideFailed;
    }
    if (!r.masked_ok) return error.ExpectedMaskedClientFrame;
    if (!std.mem.eql(u8, r.frag_buf[0..r.frag_len], "frag-A-frag-B")) return error.FragmentMismatch;
    if (r.close_code != 1000) return error.WrongCloseCode;
    if (!std.mem.eql(u8, r.close_reason_buf[0..r.close_reason_len], "bye")) return error.WrongCloseReason;
    if (!r.both_closed) return error.ClosingHandshakeIncomplete;

    std.debug.print(
        "live exchange OK: masked frame + fragmented message ({s}) + close(1000,\"{s}\") -- all against a real Python websockets peer\n",
        .{ r.frag_buf[0..r.frag_len], r.close_reason_buf[0..r.close_reason_len] },
    );
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    try checkAcceptKeyWorkedExample();
    try checkMalformedFrameRejected();
    try checkOversizedMessageRejected(gpa);
    try runLiveExchange(gpa);

    std.debug.print("OK: all websocket example checks passed\n", .{});
}
