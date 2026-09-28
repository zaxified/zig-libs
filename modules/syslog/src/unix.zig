// SPDX-License-Identifier: MIT
//! Local delivery (Linux only, raw AF_UNIX syscalls — no libc, no
//! `std.Io.net`, which has no unix-*datagram*-socket API; see its
//! `UnixAddress.connect`/`.listen`, both `SOCK_STREAM`-only). Two emitters:
//!
//!  * `UnixEmitter` — sends this module's own RFC 5424 / RFC 3164 encoders'
//!    output as one datagram to a unix *datagram* socket, default
//!    `"/dev/log"` — the same target glibc's `syslog()`/`openlog()` dial by
//!    default, and what Python's `logging.handlers.SysLogHandler("/dev/log")`
//!    and Go's `log/syslog` also connect to. Model: glibc's `syslog()` local
//!    delivery path (design only — no source read or copied; this repo
//!    already targets `std.Io`/raw syscalls throughout, never libc).
//!  * `journal` — the systemd **Journal Native Protocol**
//!    (https://systemd.io/JOURNAL_NATIVE_PROTOCOL/), default socket
//!    `"/run/systemd/journal/socket"`: one datagram of `KEY=value\n` fields
//!    (or the binary form for a value containing a newline), so a caller's
//!    structured fields stay independently queryable
//!    (`journalctl MYAPP_FIELD=value`) instead of being flattened into a free
//!    -text `MSG`. Model: the protocol document above, plus the field-name
//!    rule `sd_journal_send` enforces (uppercase `A`-`Z`, `0`-`9`, `_`; must
//!    not start with `_` or a digit — a leading `_` is reserved for fields
//!    journald itself attaches, e.g. `_PID`; max 64 bytes) — precedent named
//!    in the backlog request: Go `log/syslog` dialing the local socket by
//!    default, Python `SysLogHandler("/dev/log")`, `systemd.journal.send`,
//!    go-systemd's `journal` package.
//!
//! Neither emitter binds or listens — both are pure senders, matching the
//! precedent above (a client dials the well-known path, it never owns it).
//! Both use an UNCONNECTED datagram socket + `sendto`/`sendmsg` rather than
//! `connect`-then-`write`: a unix-domain `connect()` resolves to the specific
//! socket object bound at that path *at connect time*; if journald (or
//! `rsyslogd`) is restarted and re-binds the same path, an already-connected
//! sender keeps talking to the now-orphaned old socket and gets
//! `ECONNREFUSED` forever until it reconnects. Addressing the path fresh on
//! every send sidesteps that failure mode entirely, at the cost of one extra
//! syscall argument.
//!
//! `journal.Emitter.send` is genuinely zero-copy for field VALUES: it builds
//! a `sendmsg` scatter-gather list (`iovec`) pointing straight into the
//! caller's own field-value slices, so there is no internal buffer whose size
//! could silently cap or truncate a value — only the datagram's own kernel
//! size limit applies, surfaced as `error.MessageTooLarge` (`EMSGSIZE`) if
//! crossed. journald's own fallback past that limit is to pass the payload
//! through a `memfd` via `SCM_RIGHTS` instead of the datagram body — that
//! fallback is NOT implemented here (optional per the backlog request); a
//! caller who needs it must chunk or otherwise reduce the payload itself.
//! `UnixEmitter` has a fixed internal formatting buffer (`scratch_len`, like
//! `transport.zig`'s UDP/TCP emitters) for its convenience `send`/`sendBsd`
//! (`error.NoSpaceLeft` if a caller's `Message` doesn't fit it) but exposes
//! `sendRaw` for a caller that has already formatted (or otherwise built)
//! a larger buffer of its own — so nothing in this file ever truncates a
//! message that was handed to it in full.

const std = @import("std");
const message = @import("message.zig");
const bsd_mod = @import("bsd.zig");
const linux = std.os.linux;

// ── shared raw-socket plumbing (unconnected AF_UNIX SOCK_DGRAM) ────────────

/// Errors opening a sending socket or resolving its target path.
pub const OpenError = error{
    SocketFailed,
    /// `path` (plus the NUL terminator the kernel requires) does not fit in
    /// `sockaddr_un.sun_path` (108 bytes on Linux). Returned rather than
    /// silently truncating the path, which would silently address a
    /// DIFFERENT (or nonexistent) socket instead of failing loudly.
    PathTooLong,
};

/// A `sockaddr_un` for `path` (must fit with room for the kernel's implicit
/// NUL terminator — `addr.path` is zero-initialized and only ever holds
/// exactly `path.len` bytes of it, so the rest is already the terminator).
fn sockaddrUnix(path: []const u8) OpenError!linux.sockaddr.un {
    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    if (path.len >= addr.path.len) return error.PathTooLong;
    @memcpy(addr.path[0..path.len], path);
    return addr;
}

/// An unconnected `SOCK_DGRAM` unix socket, ready to `sendto`/`sendmsg`.
/// `CLOEXEC` so the fd is never leaked across a `fork`+`exec` in the caller.
fn openDgramSocket() OpenError!linux.fd_t {
    const s = linux.socket(linux.AF.UNIX, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(s) != .SUCCESS) return error.SocketFailed;
    return @intCast(s);
}

fn closeFd(fd: linux.fd_t) void {
    _ = linux.close(fd);
}

/// Failures a single-datagram send can report. `MessageTooLarge` is the
/// kernel's `EMSGSIZE` — the datagram (plus, for `journal`, its own framing
/// overhead) is bigger than the destination can ever accept in one message.
pub const WriteError = error{ WriteFailed, MessageTooLarge };

fn sendToAddr(fd: linux.fd_t, addr: *const linux.sockaddr.un, bytes: []const u8) WriteError!void {
    while (true) {
        const rc = linux.sendto(fd, bytes.ptr, bytes.len, 0, @ptrCast(addr), @sizeOf(linux.sockaddr.un));
        switch (linux.errno(rc)) {
            .SUCCESS => {
                if (rc != bytes.len) return error.WriteFailed; // never observed for SOCK_DGRAM; defensive
                return;
            },
            .INTR => continue,
            .MSGSIZE => return error.MessageTooLarge,
            else => return error.WriteFailed,
        }
    }
}

// ── UnixEmitter: this module's own RFC 5424 / RFC 3164 encoders ────────────

/// Internal formatting scratch for the convenience `send`/`sendBsd`. Larger
/// than `transport.zig`'s UDP `scratch_len` (2048): unix-domain delivery has
/// no IP-fragmentation reason to keep messages tiny, and callers with a
/// still-larger message can go through `sendRaw` instead of being truncated.
const scratch_len = 8192;

/// Sends this module's RFC 5424 (`send`) or RFC 3164 (`sendBsd`) wire format
/// as one datagram to a local unix socket (default `"/dev/log"`).
pub const UnixEmitter = struct {
    fd: linux.fd_t,
    addr: linux.sockaddr.un,
    scratch: [scratch_len]u8 = undefined,

    /// The traditional local-syslog socket (glibc, Python, Go, … all
    /// default to it) — a unix `SOCK_DGRAM` socket, NOT a file to `open()`.
    pub const default_path = "/dev/log";

    pub fn open(path: []const u8) OpenError!UnixEmitter {
        const addr = try sockaddrUnix(path);
        const fd = try openDgramSocket();
        return .{ .fd = fd, .addr = addr };
    }

    /// `open(default_path)`.
    pub fn openDefault() OpenError!UnixEmitter {
        return open(default_path);
    }

    pub fn close(e: *UnixEmitter) void {
        closeFd(e.fd);
    }

    pub const SendError = error{NoSpaceLeft} || WriteError;

    /// Format `msg` (RFC 5424) into the internal scratch buffer and send it
    /// as one datagram. `error.NoSpaceLeft` if `msg` doesn't fit
    /// `scratch_len` — never truncated; use `sendRaw` with your own buffer
    /// for a message that genuinely needs to be larger.
    pub fn send(e: *UnixEmitter, msg: *const message.Message) SendError!void {
        const bytes = message.bufPrint(msg, &e.scratch) catch return error.NoSpaceLeft;
        try e.sendRaw(bytes);
    }

    /// `send`'s RFC 3164 (BSD) twin.
    pub fn sendBsd(e: *UnixEmitter, msg: *const bsd_mod.Message) SendError!void {
        const bytes = bsd_mod.bufPrint(msg, &e.scratch) catch return error.NoSpaceLeft;
        try e.sendRaw(bytes);
    }

    /// Send `bytes` verbatim as one datagram — for a caller that has already
    /// formatted a message (elsewhere, or into its own larger buffer) and
    /// wants no formatting or internal size cap applied at all.
    pub fn sendRaw(e: *UnixEmitter, bytes: []const u8) WriteError!void {
        try sendToAddr(e.fd, &e.addr, bytes);
    }
};

// ── journal: systemd's native protocol ──────────────────────────────────────

pub const journal = struct {
    /// The socket every `sd_journal_send` / `systemd.journal.send` /
    /// go-systemd `journal` client dials.
    pub const default_path = "/run/systemd/journal/socket";

    /// One field: `name`/`value`, both borrowed (never copied) — `send`
    /// references them directly via `sendmsg`'s scatter-gather list, so
    /// they must outlive the `send` call (an ordinary stack-local slice
    /// does).
    pub const Field = struct { name: []const u8, value: []const u8 };

    /// `sd_journal_send`'s field-name rule (Journal Native Protocol doc +
    /// `journal_field_valid`): uppercase `A`-`Z`, digits `0`-`9`, `_`; must
    /// not start with a digit; must not start with `_` (leading `_` is
    /// reserved for the "trusted" fields journald itself attaches, e.g.
    /// `_PID`/`_UID` — a client is not journald); at most 64 bytes.
    pub const FieldError = error{
        FieldNameEmpty,
        FieldNameTooLong,
        FieldNameInvalidStart,
        FieldNameInvalidChar,
    };

    pub const max_field_name_len = 64;

    pub fn validFieldName(name: []const u8) FieldError!void {
        if (name.len == 0) return error.FieldNameEmpty;
        if (name.len > max_field_name_len) return error.FieldNameTooLong;
        const c0 = name[0];
        if (c0 == '_' or (c0 >= '0' and c0 <= '9')) return error.FieldNameInvalidStart;
        for (name) |c| {
            const ok = (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9') or c == '_';
            if (!ok) return error.FieldNameInvalidChar;
        }
    }

    /// One `send` call's field-count ceiling — keeps the `iovec`/glue arrays
    /// fixed-size (this module allocates nowhere). Each field costs 3
    /// `iovec` entries (header, value, trailing newline); `max_fields * 3`
    /// stays far under Linux's `IOV_MAX` (1024). Comfortably above any
    /// realistic single record (ttydesk's own audit trail sends ~12).
    pub const max_fields = 64;

    /// Per-field header glue: the name, then either `=` (text form) or a
    /// `\n` + 8-byte little-endian length (binary form) — everything a
    /// field needs on the wire EXCEPT the value bytes themselves and the
    /// trailing `\n`, both handled separately in `buildIovecs` so a value of
    /// any size can be referenced without being copied here.
    const max_header_glue = max_field_name_len + 1 + 8;

    const newline: [1]u8 = .{'\n'};

    pub const SendError = error{TooManyFields} || FieldError || WriteError;

    /// Builds the `sendmsg` scatter-gather list for `fields` into `header`
    /// (one `max_header_glue`-byte scratch slot per field) and `iov` (3
    /// slots per field); returns the number of `iov` entries filled.
    /// Validates every field name BEFORE writing any glue bytes, so a
    /// later invalid field never leaves an earlier one half-built pointing
    /// at a header buffer that's about to be reused for something else --
    /// not that it would matter, since a validation failure here means
    /// `sendmsg` is never reached at all.
    fn buildIovecs(
        fields: []const Field,
        header: [][max_header_glue]u8,
        iov: []std.posix.iovec_const,
    ) FieldError!usize {
        for (fields) |f| try validFieldName(f.name);

        var n: usize = 0;
        for (fields, 0..) |f, i| {
            const h = &header[i];
            const has_newline = std.mem.indexOfScalar(u8, f.value, '\n') != null;
            var header_len: usize = undefined;
            if (has_newline) {
                @memcpy(h[0..f.name.len], f.name);
                h[f.name.len] = '\n';
                std.mem.writeInt(u64, h[f.name.len + 1 ..][0..8], f.value.len, .little);
                header_len = f.name.len + 1 + 8;
            } else {
                @memcpy(h[0..f.name.len], f.name);
                h[f.name.len] = '=';
                header_len = f.name.len + 1;
            }
            iov[n] = .{ .base = h, .len = header_len };
            n += 1;
            iov[n] = .{ .base = f.value.ptr, .len = f.value.len };
            n += 1;
            iov[n] = .{ .base = &newline, .len = 1 };
            n += 1;
        }
        return n;
    }

    /// One datagram to the journal, native protocol. Field order is
    /// preserved on the wire (journald keeps the last value if a name
    /// repeats, first-to-last, so order can matter to a caller).
    pub const Emitter = struct {
        fd: linux.fd_t,
        addr: linux.sockaddr.un,

        pub fn open(path: []const u8) OpenError!Emitter {
            const addr = try sockaddrUnix(path);
            const fd = try openDgramSocket();
            return .{ .fd = fd, .addr = addr };
        }

        /// `open(default_path)`.
        pub fn openDefault() OpenError!Emitter {
            return open(default_path);
        }

        pub fn close(e: *Emitter) void {
            closeFd(e.fd);
        }

        pub fn send(e: *Emitter, fields: []const Field) SendError!void {
            if (fields.len > max_fields) return error.TooManyFields;
            var header: [max_fields][max_header_glue]u8 = undefined;
            var iov: [max_fields * 3]std.posix.iovec_const = undefined;
            const n = try buildIovecs(fields, header[0..fields.len], iov[0 .. fields.len * 3]);

            const msg: linux.msghdr_const = .{
                .name = @ptrCast(&e.addr),
                .namelen = @sizeOf(linux.sockaddr.un),
                .iov = iov[0..n].ptr,
                .iovlen = n,
                .control = null,
                .controllen = 0,
                .flags = 0,
            };
            while (true) {
                const rc = linux.sendmsg(e.fd, &msg, 0);
                switch (linux.errno(rc)) {
                    .SUCCESS => return,
                    .INTR => continue,
                    .MSGSIZE => return error.MessageTooLarge,
                    else => return error.WriteFailed,
                }
            }
        }

        /// `MESSAGE` (+ optional `PRIORITY`/`SYSLOG_IDENTIFIER`) plus any
        /// caller fields, in that order — the fields most tools expect
        /// first, matching `sd_journal_send(3)`'s own convention of naming
        /// `MESSAGE=` as the first argument.
        pub const SendMessageOptions = struct {
            message: []const u8,
            /// Journal `PRIORITY` (0-7, same numeric scale as syslog
            /// severity) -- reuses `message.Severity` rather than a bare
            /// int so a caller building both an RFC 5424 message and a
            /// journal record for the same event has one enum, not two.
            priority: ?message.Severity = null,
            identifier: ?[]const u8 = null,
            fields: []const Field = &.{},
        };

        pub fn sendMessage(e: *Emitter, opts: SendMessageOptions) SendError!void {
            var buf: [max_fields]Field = undefined;
            var n: usize = 0;
            buf[n] = .{ .name = "MESSAGE", .value = opts.message };
            n += 1;
            var prio_buf: [1]u8 = undefined;
            if (opts.priority) |p| {
                prio_buf[0] = '0' + @as(u8, @intFromEnum(p));
                buf[n] = .{ .name = "PRIORITY", .value = prio_buf[0..1] };
                n += 1;
            }
            if (opts.identifier) |id| {
                buf[n] = .{ .name = "SYSLOG_IDENTIFIER", .value = id };
                n += 1;
            }
            for (opts.fields) |f| {
                if (n >= buf.len) return error.TooManyFields;
                buf[n] = f;
                n += 1;
            }
            try e.send(buf[0..n]);
        }
    };
};

// ── tests ────────────────────────────────────────────────────────────────
//
// No running syslogd/journald needed: every test binds its OWN throwaway
// AF_UNIX SOCK_DGRAM socket under `.zig-cache/tmp/` (never `/tmp` -- repo
// convention) and receives what the emitter actually put on the wire,
// asserting the exact bytes. That is a real kernel round trip through a real
// unix socket, just not through a real log daemon.

const t = std.testing;

/// A throwaway receiver: bind an AF_UNIX SOCK_DGRAM socket at `path` (which
/// must not already exist -- `tmpDir` gives each test a fresh directory) and
/// read back one datagram into `buf`. Test-only; not part of the module's
/// public surface (this module has no receiver -- see the fuzz exemption in
/// SPEC.md).
const TestReceiver = struct {
    fd: linux.fd_t,

    fn bind(path: []const u8) !TestReceiver {
        const addr = try sockaddrUnix(path);
        const fd = try openDgramSocket();
        errdefer closeFd(fd);
        if (linux.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.un))) != .SUCCESS)
            return error.BindFailed;
        return .{ .fd = fd };
    }

    fn close(r: *TestReceiver) void {
        closeFd(r.fd);
    }

    /// Read exactly one datagram (whatever its size) into `buf`.
    fn recv(r: *TestReceiver, buf: []u8) ![]u8 {
        while (true) {
            const rc = linux.read(r.fd, buf.ptr, buf.len);
            switch (linux.errno(rc)) {
                .SUCCESS => return buf[0..rc],
                .INTR => continue,
                else => return error.ReadFailed,
            }
        }
    }
};

fn testSocketPath(tmp: *std.testing.TmpDir, buf: []u8, name: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, ".zig-cache/tmp/{s}/{s}", .{ &tmp.sub_path, name });
}

test "UnixEmitter: RFC 5424 message arrives byte-exact over a real unix socket" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const path = try testSocketPath(&tmp, &path_buf, "syslog.sock");

    var recv = try TestReceiver.bind(path);
    defer recv.close();

    var emitter = try UnixEmitter.open(path);
    defer emitter.close();

    const msg = message.Message{
        .facility = .local0,
        .severity = .info,
        .timestamp = .{ .unix_ms = 1783600496000 },
        .hostname = "web-1",
        .app_name = "api",
        .msgid = "REQ",
        .msg = "served /health 200",
    };
    try emitter.send(&msg);

    var recv_buf: [256]u8 = undefined;
    const got = try recv.recv(&recv_buf);
    try t.expectEqualStrings(
        "<134>1 2026-07-09T12:34:56.000Z web-1 api - REQ - served /health 200",
        got,
    );
}

test "UnixEmitter: RFC 3164 (BSD) message arrives byte-exact" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const path = try testSocketPath(&tmp, &path_buf, "syslog.sock");

    var recv = try TestReceiver.bind(path);
    defer recv.close();
    var emitter = try UnixEmitter.open(path);
    defer emitter.close();

    const msg = bsd_mod.Message{
        .facility = .local0,
        .severity = .warning,
        .timestamp = .{ .unix_ms = 1783600496000 },
        .hostname = "host",
        .tag = "app",
        .pid = "123",
        .msg = "hello",
    };
    try emitter.sendBsd(&msg);

    var recv_buf: [256]u8 = undefined;
    const got = try recv.recv(&recv_buf);
    try t.expectEqualStrings("<132>Jul  9 12:34:56 host app[123]: hello", got);
}

test "UnixEmitter: sendRaw over budget is MessageTooLarge, not a truncated send" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const path = try testSocketPath(&tmp, &path_buf, "syslog.sock");

    var recv = try TestReceiver.bind(path);
    defer recv.close();
    var emitter = try UnixEmitter.open(path);
    defer emitter.close();

    // Force a tiny send buffer on OUR OWN sending socket so the datagram
    // below is guaranteed to exceed it regardless of this host's real
    // defaults (which are normally large enough that a small test payload
    // would never hit EMSGSIZE at all).
    try std.posix.setsockopt(emitter.fd, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&@as(c_int, 1024)));

    var big: [65536]u8 = undefined;
    @memset(&big, 'x');
    try t.expectError(error.MessageTooLarge, emitter.sendRaw(&big));

    // Nothing arrived -- a rejected send must not have partially delivered.
    var poll_fd = [_]std.posix.pollfd{.{ .fd = recv.fd, .events = std.posix.POLL.IN, .revents = 0 }};
    const n = try std.posix.poll(&poll_fd, 0);
    try t.expectEqual(@as(usize, 0), n);
}

test "UnixEmitter: PathTooLong instead of a silently truncated (wrong) path" {
    const too_long = "x" ** 200;
    try t.expectError(error.PathTooLong, UnixEmitter.open(too_long));
}

test "journal.validFieldName: sd_journal's rules" {
    try journal.validFieldName("MESSAGE");
    try journal.validFieldName("TTYDESK_ACTION");
    try journal.validFieldName("A");
    try journal.validFieldName("A0");
    try t.expectError(error.FieldNameEmpty, journal.validFieldName(""));
    try t.expectError(error.FieldNameTooLong, journal.validFieldName("A" ** 65));
    try journal.validFieldName("A" ** 64); // exactly at the limit: fine
    try t.expectError(error.FieldNameInvalidStart, journal.validFieldName("1FOO"));
    try t.expectError(error.FieldNameInvalidStart, journal.validFieldName("_FOO")); // reserved for trusted fields
    try t.expectError(error.FieldNameInvalidChar, journal.validFieldName("foo")); // lowercase
    try t.expectError(error.FieldNameInvalidChar, journal.validFieldName("FOO-BAR"));
    try t.expectError(error.FieldNameInvalidChar, journal.validFieldName("FOO BAR"));
    try t.expectError(error.FieldNameInvalidChar, journal.validFieldName("FOO=BAR"));
}

test "journal.Emitter: text-form fields arrive byte-exact (no newline in any value)" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const path = try testSocketPath(&tmp, &path_buf, "journal.sock");

    var recv = try TestReceiver.bind(path);
    defer recv.close();
    var emitter = try journal.Emitter.open(path);
    defer emitter.close();

    try emitter.send(&.{
        .{ .name = "MESSAGE", .value = "hello world" },
        .{ .name = "PRIORITY", .value = "6" },
        .{ .name = "SYSLOG_IDENTIFIER", .value = "probe" },
    });

    var recv_buf: [256]u8 = undefined;
    const got = try recv.recv(&recv_buf);
    try t.expectEqualStrings("MESSAGE=hello world\nPRIORITY=6\nSYSLOG_IDENTIFIER=probe\n", got);
}

test "journal.Emitter: a value with a newline switches that field to binary form" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const path = try testSocketPath(&tmp, &path_buf, "journal.sock");

    var recv = try TestReceiver.bind(path);
    defer recv.close();
    var emitter = try journal.Emitter.open(path);
    defer emitter.close();

    try emitter.send(&.{
        .{ .name = "MESSAGE", .value = "line one\nline two" },
        .{ .name = "SYSLOG_IDENTIFIER", .value = "probe" }, // stays text form
    });

    var recv_buf: [256]u8 = undefined;
    const got = try recv.recv(&recv_buf);

    // Hand-built expected bytes: "MESSAGE\n" + 8-byte LE length (17) +
    // "line one\nline two" + "\n", then the ordinary text-form field.
    var want_buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&want_buf);
    try w.writeAll("MESSAGE\n");
    try w.writeInt(u64, "line one\nline two".len, .little);
    try w.writeAll("line one\nline two");
    try w.writeAll("\n");
    try w.writeAll("SYSLOG_IDENTIFIER=probe\n");
    try t.expectEqualSlices(u8, w.buffered(), got);
}

test "journal.Emitter.sendMessage: MESSAGE/PRIORITY/SYSLOG_IDENTIFIER convenience" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const path = try testSocketPath(&tmp, &path_buf, "journal.sock");

    var recv = try TestReceiver.bind(path);
    defer recv.close();
    var emitter = try journal.Emitter.open(path);
    defer emitter.close();

    try emitter.sendMessage(.{
        .message = "unit restarted",
        .priority = .notice,
        .identifier = "ttydesk",
        .fields = &.{.{ .name = "TTYDESK_ACTION", .value = "unit.restart" }},
    });

    var recv_buf: [256]u8 = undefined;
    const got = try recv.recv(&recv_buf);
    try t.expectEqualStrings(
        "MESSAGE=unit restarted\nPRIORITY=5\nSYSLOG_IDENTIFIER=ttydesk\nTTYDESK_ACTION=unit.restart\n",
        got,
    );
}

test "journal.Emitter.send: rejects an invalid field name before sending anything" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const path = try testSocketPath(&tmp, &path_buf, "journal.sock");

    var recv = try TestReceiver.bind(path);
    defer recv.close();
    var emitter = try journal.Emitter.open(path);
    defer emitter.close();

    try t.expectError(error.FieldNameInvalidStart, emitter.send(&.{
        .{ .name = "MESSAGE", .value = "ok" },
        .{ .name = "_HIDDEN", .value = "nope" }, // reserved leading underscore
    }));

    // The whole send was refused -- not even the (validly-named) first field
    // went out on its own.
    var poll_fd = [_]std.posix.pollfd{.{ .fd = recv.fd, .events = std.posix.POLL.IN, .revents = 0 }};
    const n = try std.posix.poll(&poll_fd, 0);
    try t.expectEqual(@as(usize, 0), n);
}

test "journal.Emitter.send: too many fields is TooManyFields, not a silent drop" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const path = try testSocketPath(&tmp, &path_buf, "journal.sock");

    var recv = try TestReceiver.bind(path);
    defer recv.close();
    var emitter = try journal.Emitter.open(path);
    defer emitter.close();

    var fields: [journal.max_fields + 1]journal.Field = undefined;
    for (&fields) |*f| f.* = .{ .name = "A", .value = "x" };
    try t.expectError(error.TooManyFields, emitter.send(&fields));
}

test "journal.Emitter.send: a datagram too large for the socket is MessageTooLarge" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const path = try testSocketPath(&tmp, &path_buf, "journal.sock");

    var recv = try TestReceiver.bind(path);
    defer recv.close();
    var emitter = try journal.Emitter.open(path);
    defer emitter.close();

    try std.posix.setsockopt(emitter.fd, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&@as(c_int, 1024)));

    var big: [65536]u8 = undefined;
    @memset(&big, 'x');
    try t.expectError(error.MessageTooLarge, emitter.send(&.{.{ .name = "MESSAGE", .value = &big }}));
}
