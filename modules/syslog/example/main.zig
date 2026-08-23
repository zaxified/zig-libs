// SPDX-License-Identifier: MIT

//! What a service built on `syslog` actually does with it: format an RFC
//! 5424 line with structured data, an RFC 3164 (BSD) legacy line, hand both
//! to independent outside judges, then send real datagrams/frames over real
//! loopback sockets with `UdpEmitter`/`TcpEmitter` -- the module's own test
//! suite admits those two paths are "compile-checked only... gated behind
//! runtime construction" (transport.zig), so this is the first time they run
//! for real.
//!
//! **External judges, ACTUALLY RUN:**
//!
//! 1. `python3`, twice: once as a grammar checker -- a regex built straight
//!    from RFC 5424 S6's ABNF (HEADER/STRUCTURED-DATA/SD-ELEMENT) and RFC
//!    3164 S4.1's line shape, run against the *exact bytes* `bufPrint`
//!    produced, not a paraphrase of them; and once as the plain syscall
//!    conduit that hands those same exact bytes to a real AF_UNIX socket (see
//!    judge 2) -- `std.posix` has no socket calls left in this Zig version
//!    (moved under `std.Io.net`, which only opens *IP* sockets), so python is
//!    the simplest real path to an AF_UNIX datagram.
//! 2. `systemd-journald`, via its always-on `/dev/log` socket and queried
//!    back with `journalctl` -- a real independent syslog receiver, with NO
//!    system configuration touched. This is deliberately NOT the rsyslogd
//!    UDP/TCP anchor root.zig's own external-anchor test uses (that one
//!    needed an AppArmor workaround to run rsyslogd unprivileged -- see
//!    SPEC.md -- which is exactly the kind of system change this example must
//!    not make); `/dev/log` needs no setup at all on any systemd host.
//!    Measured empirically before writing this: journald extracts PRIORITY
//!    (severity) and SYSLOG_FACILITY correctly from both formats over
//!    `/dev/log`, which is what gets cross-checked below, but it does NOT
//!    special-case the RFC 5424 "1 " version token the way a real RFC 5424
//!    collector (rsyslogd) does -- the whole HEADER after PRI lands verbatim
//!    in MESSAGE. That is `/dev/log`'s real, measured behavior, not a
//!    limitation of this module.
//!
//! **Used only as a documented fixture** (RFC 5424 S6.1's own truncation rule
//! and S6's field-length limits are the judge, not a peer): the oversized-
//! message truncation-with-marker behavior, and the two named-error paths
//! (`NoSpaceLeft`, `TimestampOutOfRange`).
//!
//! The module allocates nothing itself (README: "Allocation: none -- fixed
//! buffers throughout"), so the `NoSpaceLeft` check allocates its own
//! deliberately-undersized buffer to give the `DebugAllocator` leak check a
//! real failure path to prove.
//!
//! Built against the PUBLISHED module (`@import("syslog")` only -- it
//! declares no deps) plus plain `std` for the sockets/process-spawn plumbing
//! that reaches the external judges. `zig build check-examples` builds this
//! against exactly that surface.

const std = @import("std");
const syslog = @import("syslog");

// ── judge 1a: RFC 5424 / RFC 3164 grammar, checked with python3 ────────────

/// A regex built from RFC 5424 S6's ABNF (HEADER, STRUCTURED-DATA,
/// SD-ELEMENT, SD-PARAM) for `kind == "5424"`, and from RFC 3164 S4.1's line
/// shape for `kind == "3164"`. Reads the candidate line as raw bytes on
/// stdin so arbitrary MSG content (quotes, backslashes, brackets) survives
/// untouched; prints `PASS pri=<n>` and exits 0, or `FAIL ...` and exits 1.
const grammar_script =
    \\import sys, re
    \\
    \\kind = sys.argv[1]
    \\data = sys.stdin.buffer.read()
    \\text = data.decode("utf-8")
    \\
    \\printusascii = r'[\x21-\x7e]'
    \\if kind == "5424":
    \\    timestamp = r'(?:-|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2}))'
    \\    hostname = rf'(?:-|{printusascii}{{1,255}})'
    \\    appname = rf'(?:-|{printusascii}{{1,48}})'
    \\    procid = rf'(?:-|{printusascii}{{1,128}})'
    \\    msgid = rf'(?:-|{printusascii}{{1,32}})'
    \\    sd_name = r'[^ =\]"\x00-\x20\x7f]+'
    \\    sd_param = rf'{sd_name}="(?:[^"\\\]]|\\[\\"\]])*"'
    \\    sd_element = rf'\[{sd_name}(?: {sd_param})*\]'
    \\    structured_data = rf'(?:-|(?:{sd_element})+)'
    \\    header = rf'<(\d{{1,3}})>1 {timestamp} {hostname} {appname} {procid} {msgid}'
    \\    pattern = rf'^{header} {structured_data}(?: .*)?$'
    \\elif kind == "3164":
    \\    month = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    \\    pattern = rf'^<(\d{{1,3}})>{month} [ 0-9]\d \d{{2}}:\d{{2}}:\d{{2}} \S+ [^:\[]{{1,32}}(?:\[\d+\])?: .*$'
    \\else:
    \\    print(f"FAIL unknown kind {kind}")
    \\    sys.exit(1)
    \\
    \\m = re.match(pattern, text, re.DOTALL)
    \\if not m:
    \\    print(f"FAIL grammar mismatch for {kind}: {text!r}")
    \\    sys.exit(1)
    \\pri = int(m.group(1))
    \\if not (0 <= pri <= 191):
    \\    print(f"FAIL PRI out of range: {pri}")
    \\    sys.exit(1)
    \\print(f"PASS pri={pri}")
;

fn runPythonGrammarCheck(io: std.Io, kind: []const u8, bytes: []const u8) !void {
    var child = try std.process.spawn(io, .{
        .argv = &.{ "python3", "-c", grammar_script, kind },
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .inherit,
    });
    {
        var wbuf: [256]u8 = undefined;
        var sw = child.stdin.?.writer(io, &wbuf);
        try sw.interface.writeAll(bytes);
        try sw.interface.flush();
    }
    child.stdin.?.close(io);
    child.stdin = null; // matches the harness's own cleanup convention: null out what's already closed

    var out_buf: [512]u8 = undefined;
    var sr = child.stdout.?.reader(io, &out_buf);
    const line = sr.interface.takeDelimiterInclusive('\n') catch |err| switch (err) {
        error.EndOfStream => "",
        else => return err,
    };
    std.debug.print("python grammar check ({s}): {s}", .{ kind, line });
    if (line.len == 0) std.debug.print("\n", .{});

    const term = try child.wait(io);
    const exited_zero = switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!exited_zero or !std.mem.startsWith(u8, line, "PASS")) return error.GrammarCheckFailed;
}

fn checkGrammar5424(io: std.Io) !void {
    // Same content as root.zig's own live-rsyslogd external-anchor test
    // (byte-identical fixture), but judged here by an independent tool
    // instead of trusting the pinned literal.
    const msg = syslog.Message{
        .facility = .local3,
        .severity = .warning,
        .timestamp = .{ .unix_ms = 1783600496123, .offset_minutes = 60 },
        .hostname = "probe-host",
        .app_name = "live-probe",
        .procid = "4242",
        .msgid = "ORACLE",
        .structured_data = &.{.{ .id = "exampleSDID@32473", .params = &.{
            .{ .name = "iut", .value = "3" },
            .{ .name = "eventSource", .value = "Application" },
            .{ .name = "eventID", .value = "1011" },
        } }},
        .msg = "quotes \" backslash \\ bracket ] end",
    };
    var buf: [512]u8 = undefined;
    const wire = try syslog.bufPrint(&msg, &buf);
    try runPythonGrammarCheck(io, "5424", wire);
}

fn checkGrammar3164(io: std.Io) !void {
    const msg = syslog.bsd.Message{
        .facility = .local0,
        .severity = .warning,
        .timestamp = .{ .unix_ms = 1783600496000 },
        .hostname = "host",
        .tag = "app",
        .pid = "123",
        .msg = "hello",
    };
    var buf: [128]u8 = undefined;
    const wire = try syslog.bsd.bufPrint(&msg, &buf);
    try runPythonGrammarCheck(io, "3164", wire);
}

// ── documented fixtures: the module's own defined error/truncation surface ─

/// RFC 5424 S6.1: a UDP transport with a small budget truncates rather than
/// fragmenting; `buildDatagram` is the module's own rule for that, checked
/// directly (no peer needed -- the rule is internal policy, not a wire
/// format an outside party parses).
fn checkOversizedMessageTruncated() !void {
    const msg = syslog.Message{ .facility = .user, .severity = .notice, .msg = "A" ** 400 };
    var scratch: [1024]u8 = undefined;
    const opts = syslog.Options{ .udp_limit = 64, .trunc_marker = "...[TRUNCATED]" };
    const dg = syslog.buildDatagram(&msg, &scratch, opts);
    if (dg.len != 64) return error.WrongTruncatedLength;
    if (!std.mem.endsWith(u8, dg, "...[TRUNCATED]")) return error.MissingTruncationMarker;
    std.debug.print(
        "oversized message (400-byte MSG, 64-byte UDP budget): truncated to {d} bytes with marker\n",
        .{dg.len},
    );
}

/// `bufPrint`'s only error is `NoSpaceLeft` (message.zig) -- the module
/// itself never allocates, so this allocates the target buffer for real to
/// give the leak check an actual failure path: allocate, fail, and prove
/// `defer` still frees it.
fn checkNoSpaceLeft(gpa: std.mem.Allocator) !void {
    const buf = try gpa.alloc(u8, 8); // far too small for any real line
    defer gpa.free(buf);
    const msg = syslog.Message{ .facility = .user, .severity = .notice, .msg = "this will not fit" };
    // `bufPrint`'s error set is exactly `{NoSpaceLeft}` (message.zig), so
    // there is no `else` branch to fall through -- the exhaustive switch
    // below is itself the proof this is the module's only failure mode
    // here.
    if (syslog.bufPrint(&msg, buf)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.NoSpaceLeft => std.debug.print(
            "message into an 8-byte buffer: NoSpaceLeft (expected)\n",
            .{},
        ),
    }
}

/// `decompose`'s only error: an instant `format`/`bufPrint` would otherwise
/// have to reject or panic on. A pre-epoch timestamp exercises it directly
/// (S3.3 of message.zig: `format` itself catches this and renders NILVALUE,
/// so `decompose` is the only place the named error surfaces at all).
fn checkTimestampOutOfRange() !void {
    if (syslog.decompose(.{ .unix_ms = -1 })) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.TimestampOutOfRange => std.debug.print(
            "pre-epoch timestamp: TimestampOutOfRange (expected)\n",
            .{},
        ),
    }
}

// ── judge 1b + judge 2: deliver real bytes to /dev/log, confirm with journald

const devlog_script =
    \\import sys, socket
    \\data = sys.stdin.buffer.read()
    \\s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    \\s.connect("/dev/log")
    \\s.send(data)
    \\s.close()
;

fn deliverToDevLog(io: std.Io, bytes: []const u8) !void {
    var child = try std.process.spawn(io, .{
        .argv = &.{ "python3", "-c", devlog_script },
        .stdin = .pipe,
        .stdout = .ignore,
        .stderr = .inherit,
    });
    {
        var wbuf: [256]u8 = undefined;
        var sw = child.stdin.?.writer(io, &wbuf);
        try sw.interface.writeAll(bytes);
        try sw.interface.flush();
    }
    child.stdin.?.close(io);
    child.stdin = null;
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) return error.DevLogDeliveryFailed,
        else => return error.DevLogDeliveryFailed,
    }
}

/// Find `"key":"value"` in one `journalctl -o json` line and return `value`.
fn jsonField(line: []const u8, comptime key: []const u8) ?[]const u8 {
    const needle = "\"" ++ key ++ "\":\"";
    const idx = std.mem.indexOf(u8, line, needle) orelse return null;
    const start = idx + needle.len;
    const end = std.mem.indexOfScalarPos(u8, line, start, '"') orelse return null;
    return line[start..end];
}

/// Poll `journalctl` for a line containing `marker`, then check journald's
/// own independently-derived PRIORITY (severity) and SYSLOG_FACILITY against
/// what this module encoded into the PRI byte -- the real cross-check, not
/// just "did a line show up".
fn queryJournaldForMarker(io: std.Io, marker: []const u8, expected_severity: u8, expected_facility: u8) !void {
    var attempt: usize = 0;
    while (attempt < 20) : (attempt += 1) {
        // `-n 50` (not thousands): our marker is the newest entry, so a
        // short recent window both finds it and keeps the pipe well under
        // its kernel buffer -- draining it fully below (even on an early
        // match) is what actually prevents `journalctl` blocking on a full
        // pipe with `wait` never returning, but staying small keeps every
        // attempt cheap regardless.
        var child = try std.process.spawn(io, .{
            .argv = &.{ "journalctl", "--no-pager", "-o", "json", "-n", "50" },
            .stdin = .close,
            .stdout = .pipe,
            .stderr = .ignore,
        });
        var out_buf: [32768]u8 = undefined;
        var sr = child.stdout.?.reader(io, &out_buf);
        var match_line_buf: [32768]u8 = undefined;
        var match_len: usize = 0;
        while (true) {
            const line = sr.interface.takeDelimiterInclusive('\n') catch |err| switch (err) {
                error.EndOfStream => break,
                // An occasional journal line (a big audit/coredump blob)
                // can exceed even a generous buffer; treat that one line as
                // a miss rather than aborting the whole check.
                error.StreamTooLong => break,
                else => return err,
            };
            if (std.mem.indexOf(u8, line, marker) != null) {
                match_len = @min(line.len, match_line_buf.len);
                @memcpy(match_line_buf[0..match_len], line[0..match_len]);
                break;
            }
        }
        // Drain whatever `journalctl` still has queued -- without this, an
        // early match (or an early StreamTooLong) can leave it blocked
        // writing into a full pipe, and `wait` below would then hang.
        _ = sr.interface.discardRemaining() catch {};
        _ = try child.wait(io);

        if (match_len > 0) {
            const line = match_line_buf[0..match_len];
            const pri_str = jsonField(line, "PRIORITY") orelse return error.JournaldFieldMissing;
            const fac_str = jsonField(line, "SYSLOG_FACILITY") orelse return error.JournaldFieldMissing;
            const got_severity = std.fmt.parseInt(u8, pri_str, 10) catch return error.JournaldFieldUnparseable;
            const got_facility = std.fmt.parseInt(u8, fac_str, 10) catch return error.JournaldFieldUnparseable;
            if (got_severity != expected_severity or got_facility != expected_facility) return error.JournaldFieldMismatch;
            std.debug.print(
                "journald confirmed {s}: PRIORITY(severity)={d}, SYSLOG_FACILITY={d} (both independently decoded, match)\n",
                .{ marker, got_severity, got_facility },
            );
            return;
        }

        var ts: std.posix.timespec = .{ .sec = 0, .nsec = 150_000_000 };
        _ = std.os.linux.nanosleep(&ts, null);
    }
    return error.JournaldEntryNotFound;
}

fn checkJournald(io: std.Io) !void {
    std.Io.Dir.accessAbsolute(io, "/dev/log", .{}) catch {
        std.debug.print("journald section: /dev/log not present -- skipped, no system config changed to add it\n", .{});
        return;
    };

    const now = syslog.nowTimestamp();
    var marker_buf: [40]u8 = undefined;
    const marker = try std.fmt.bufPrint(&marker_buf, "ZLW{d}-{d}", .{ std.os.linux.getpid(), now.unix_ms });
    var marker_a_buf: [42]u8 = undefined;
    const marker_a = try std.fmt.bufPrint(&marker_a_buf, "{s}A", .{marker});
    var marker_b_buf: [42]u8 = undefined;
    const marker_b = try std.fmt.bufPrint(&marker_b_buf, "{s}B", .{marker});

    // RFC 5424, with structured data.
    var text5424_buf: [96]u8 = undefined;
    const text5424 = try std.fmt.bufPrint(&text5424_buf, "probe {s} quotes \" backslash \\ end", .{marker_a});
    const msg5424 = syslog.Message{
        .facility = .local3,
        .severity = .warning,
        .timestamp = now,
        .hostname = "example-host",
        .app_name = "syslog-example",
        .msgid = "PROBE",
        .structured_data = &.{.{ .id = "exampleSDID@32473", .params = &.{
            .{ .name = "iut", .value = "3" },
            .{ .name = "eventSource", .value = "Application" },
        } }},
        .msg = text5424,
    };
    var wire5424_buf: [256]u8 = undefined;
    const wire5424 = try syslog.bufPrint(&msg5424, &wire5424_buf);
    try deliverToDevLog(io, wire5424);
    try queryJournaldForMarker(io, marker_a, @intFromEnum(syslog.Severity.warning), @intFromEnum(syslog.Facility.local3));

    // RFC 3164 (BSD) legacy line.
    var text3164_buf: [64]u8 = undefined;
    const text3164 = try std.fmt.bufPrint(&text3164_buf, "probe {s}", .{marker_b});
    const msgbsd = syslog.bsd.Message{
        .facility = .local5,
        .severity = .err,
        .timestamp = now,
        .hostname = "example-host",
        .tag = "syslog-example",
        .msg = text3164,
    };
    var wire3164_buf: [256]u8 = undefined;
    const wire3164 = try syslog.bsd.bufPrint(&msgbsd, &wire3164_buf);
    try deliverToDevLog(io, wire3164);
    try queryJournaldForMarker(io, marker_b, @intFromEnum(syslog.Severity.err), @intFromEnum(syslog.Facility.local5));
}

// ── real network paths: UdpEmitter / TcpEmitter over real loopback sockets -

fn checkLiveUdpEmitter(io: std.Io) !void {
    const bind_addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var recv_socket = try bind_addr.bind(io, .{ .mode = .dgram });
    defer recv_socket.close(io);
    const port = recv_socket.address.getPort();
    const peer = try std.Io.net.IpAddress.parse("127.0.0.1", port);

    var emitter = try syslog.UdpEmitter.open(io, peer, .{});
    defer emitter.close();

    const msg = syslog.Message{ .facility = .local0, .severity = .info, .app_name = "udp-live", .msg = "udp emitter live probe" };
    var expected_buf: [256]u8 = undefined;
    const expected = try syslog.bufPrint(&msg, &expected_buf);

    try emitter.send(&msg);

    var recv_buf: [1024]u8 = undefined;
    const incoming = try recv_socket.receive(io, &recv_buf);
    if (!std.mem.eql(u8, incoming.data, expected)) return error.UdpPayloadMismatch;
    std.debug.print("UdpEmitter live loopback round trip: {d} bytes byte-exact\n", .{incoming.data.len});
}

fn checkLiveTcpEmitter(io: std.Io) !void {
    const bind_addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try bind_addr.listen(io, .{});
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();
    const peer = try std.Io.net.IpAddress.parse("127.0.0.1", port);

    // `TcpEmitter.connect` completing does not require `accept` to have run
    // yet -- the kernel completes the loopback handshake into the listen
    // backlog on its own, so connecting first and accepting second (both on
    // this one thread) is safe, not a race.
    var emitter = try syslog.TcpEmitter.connect(io, peer);
    defer emitter.close();

    var stream = try listener.accept(io);
    defer stream.close(io);

    const msg = syslog.Message{ .facility = .local0, .severity = .info, .app_name = "tcp-live", .msg = "tcp emitter live probe" };
    var expected_buf: [256]u8 = undefined;
    const expected = try syslog.bufPrint(&msg, &expected_buf);

    try emitter.send(&msg);

    var rbuf: [512]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    // RFC 6587 S3.4.1: "MSG-LEN SP SYSLOG-MSG". `takeDelimiterExclusive`
    // stops before the delimiter but does NOT consume it (see its own doc
    // comment: only `result.len` is tossed) -- the single SP separator has
    // to be taken explicitly, or the payload read below starts one byte
    // early (on the SP itself) and ends one byte short.
    const len_str = try sr.interface.takeDelimiterExclusive(' ');
    _ = try sr.interface.takeByte(); // the SP separator itself
    const len = try std.fmt.parseInt(usize, len_str, 10);
    if (len > rbuf.len) return error.OctetCountTooBig;
    const payload = try sr.interface.take(len);
    if (len != expected.len or !std.mem.eql(u8, payload, expected)) return error.TcpPayloadMismatch;
    std.debug.print("TcpEmitter live loopback round trip: RFC 6587 octet-count {d}, byte-exact\n", .{len});
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    try checkGrammar5424(io);
    try checkGrammar3164(io);
    try checkOversizedMessageTruncated();
    try checkNoSpaceLeft(gpa);
    try checkTimestampOutOfRange();
    try checkJournald(io);
    try checkLiveUdpEmitter(io);
    try checkLiveTcpEmitter(io);

    std.debug.print("OK: all syslog example checks passed\n", .{});
}
