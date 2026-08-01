// SPDX-License-Identifier: MIT

//! RFC 6241 §8.1 — the `<hello>` capability exchange, and the capability-set
//! model the rest of the client reasons about.
//!
//! Two jobs live here:
//!
//! 1. Parse a peer's `<hello>` into a `Capabilities` set plus the `<session-id>`
//!    (which a *server* MUST send and a *client* MUST NOT — both directions are
//!    enforced, since a client that accepts a hello without a session id has no
//!    way to name itself in a later `<kill-session>`).
//! 2. Decide the framing dialect. RFC 6242 §4.1: chunked framing is used if and
//!    only if `:base:1.1` is advertised by BOTH peers; otherwise the old
//!    end-of-message framing. That intersection is `negotiate` below, and it is
//!    the only place the decision is made.
//!
//! Capability URIs may carry parameters (`…?module=foo&revision=…`), and RFC
//! 6241 §8.1 says only the part before the parameters is compared. `has`
//! implements that rule; the full URIs stay available verbatim in `list` so a
//! caller can read YANG module capabilities it understands and this module
//! does not.

const std = @import("std");
const xml = @import("xml");
const testing = std.testing;

/// The NETCONF base namespace — the XML namespace of `<hello>`, `<rpc>`,
/// `<rpc-reply>` and the standard operations. Note it stays `:base:1.0` even
/// for a `:base:1.1` session (RFC 6241 §3.1); only the *capability* URI moves.
pub const base_ns = "urn:ietf:params:xml:ns:netconf:base:1.0";

/// RFC 5277 §4 notification namespace.
pub const notification_ns = "urn:ietf:params:xml:ns:netconf:notification:1.0";

pub const cap_base_1_0 = "urn:ietf:params:netconf:base:1.0";
pub const cap_base_1_1 = "urn:ietf:params:netconf:base:1.1";
pub const cap_writable_running = "urn:ietf:params:netconf:capability:writable-running:1.0";
pub const cap_candidate = "urn:ietf:params:netconf:capability:candidate:1.0";
pub const cap_confirmed_commit_1_0 = "urn:ietf:params:netconf:capability:confirmed-commit:1.0";
pub const cap_confirmed_commit = "urn:ietf:params:netconf:capability:confirmed-commit:1.1";
pub const cap_rollback_on_error = "urn:ietf:params:netconf:capability:rollback-on-error:1.0";
pub const cap_validate_1_0 = "urn:ietf:params:netconf:capability:validate:1.0";
pub const cap_validate = "urn:ietf:params:netconf:capability:validate:1.1";
pub const cap_startup = "urn:ietf:params:netconf:capability:startup:1.0";
pub const cap_url = "urn:ietf:params:netconf:capability:url:1.0";
pub const cap_xpath = "urn:ietf:params:netconf:capability:xpath:1.0";
pub const cap_notification = "urn:ietf:params:netconf:capability:notification:1.0";
pub const cap_interleave = "urn:ietf:params:netconf:capability:interleave:1.0";

/// What this client advertises by default: both base versions (so a
/// `:base:1.0`-only peer still interoperates) plus the notification capability,
/// which is what makes `create-subscription` legal.
pub const default_client_capabilities = [_][]const u8{
    cap_base_1_0,
    cap_base_1_1,
};

pub const HelloError = error{
    /// Not a `<hello>` in the NETCONF base namespace, or `<capabilities>` is
    /// missing/ill-formed.
    MalformedHello,
    /// A server hello without `<session-id>` (RFC 6241 §8.1 MUST).
    MissingSessionId,
    /// `<session-id>` present where it must not be, or not a positive integer.
    InvalidSessionId,
    /// The peer advertised no `:base:` version we implement.
    NoCommonBaseVersion,
} || xml.ParseError || std.mem.Allocator.Error;

/// A peer's advertised capability set. `list` holds every URI verbatim and in
/// order (YANG module capabilities included, opaque to us); the booleans are
/// the standard ones, pre-resolved.
pub const Capabilities = struct {
    gpa: std.mem.Allocator,
    list: [][]u8,

    base_1_0: bool = false,
    base_1_1: bool = false,
    writable_running: bool = false,
    candidate: bool = false,
    confirmed_commit: bool = false,
    rollback_on_error: bool = false,
    validate: bool = false,
    startup: bool = false,
    url: bool = false,
    xpath: bool = false,
    notification: bool = false,
    interleave: bool = false,

    pub fn deinit(self: *Capabilities) void {
        for (self.list) |c| self.gpa.free(c);
        self.gpa.free(self.list);
        self.* = undefined;
    }

    /// Build a set from URIs, taking a private copy of each.
    pub fn fromSlice(gpa: std.mem.Allocator, uris: []const []const u8) std.mem.Allocator.Error!Capabilities {
        var list = try gpa.alloc([]u8, uris.len);
        var filled: usize = 0;
        errdefer {
            for (list[0..filled]) |c| gpa.free(c);
            gpa.free(list);
        }
        for (uris, 0..) |u, i| {
            list[i] = try gpa.dupe(u8, u);
            filled = i + 1;
        }
        var self: Capabilities = .{ .gpa = gpa, .list = list };
        self.resolve();
        return self;
    }

    /// RFC 6241 §8.1 comparison: equal ignoring any `?parameters` suffix.
    pub fn has(self: *const Capabilities, uri: []const u8) bool {
        for (self.list) |c| if (sameCapability(c, uri)) return true;
        return false;
    }

    /// Exact string match, for a caller that cares about the parameters too.
    pub fn hasExact(self: *const Capabilities, uri: []const u8) bool {
        for (self.list) |c| if (std.mem.eql(u8, c, uri)) return true;
        return false;
    }

    fn resolve(self: *Capabilities) void {
        self.base_1_0 = self.has(cap_base_1_0);
        self.base_1_1 = self.has(cap_base_1_1);
        self.writable_running = self.has(cap_writable_running);
        self.candidate = self.has(cap_candidate);
        self.confirmed_commit = self.has(cap_confirmed_commit) or self.has(cap_confirmed_commit_1_0);
        self.rollback_on_error = self.has(cap_rollback_on_error);
        self.validate = self.has(cap_validate) or self.has(cap_validate_1_0);
        self.startup = self.has(cap_startup);
        self.url = self.has(cap_url);
        self.xpath = self.has(cap_xpath);
        self.notification = self.has(cap_notification);
        self.interleave = self.has(cap_interleave);
    }
};

/// "only the base part is used, in the event any parameters are encoded at the
/// end of the URI string" (RFC 6241 §8.1).
pub fn sameCapability(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, baseOf(a), baseOf(b));
}

fn baseOf(uri: []const u8) []const u8 {
    const q = std.mem.indexOfScalar(u8, uri, '?') orelse return uri;
    return uri[0..q];
}

/// A parsed `<hello>`.
pub const Hello = struct {
    capabilities: Capabilities,
    /// Present exactly when the peer is a server.
    session_id: ?u32,

    pub fn deinit(self: *Hello) void {
        self.capabilities.deinit();
        self.* = undefined;
    }
};

pub const Role = enum { client, server };

/// Parse a `<hello>` document. `expect` says which side sent it, which decides
/// whether `<session-id>` is required (server) or forbidden (client).
pub fn parseHello(gpa: std.mem.Allocator, source: []const u8, expect: Role) HelloError!Hello {
    var doc = try xml.parse(gpa, source, .{ .doctype = .reject });
    defer doc.deinit();

    const root = doc.root;
    if (!std.mem.eql(u8, root.local, "hello")) return error.MalformedHello;
    if (!std.mem.eql(u8, root.uri, base_ns)) return error.MalformedHello;

    var uris: std.ArrayList([]u8) = .empty;
    errdefer {
        for (uris.items) |u| gpa.free(u);
        uris.deinit(gpa);
    }
    var session_id: ?u32 = null;
    var saw_capabilities = false;

    var it = root.elementIterator();
    while (it.next()) |child| {
        if (std.mem.eql(u8, child.local, "capabilities") and std.mem.eql(u8, child.uri, base_ns)) {
            if (saw_capabilities) return error.MalformedHello;
            saw_capabilities = true;
            var cit = child.elementIterator();
            while (cit.next()) |cap| {
                if (!std.mem.eql(u8, cap.local, "capability")) return error.MalformedHello;
                const text = try cap.textContent(gpa);
                defer gpa.free(text);
                // The RFC's own examples put the URI on its own indented line,
                // so surrounding whitespace is not significant.
                const trimmed = std.mem.trim(u8, text, " \t\r\n");
                if (trimmed.len == 0) return error.MalformedHello;
                try uris.append(gpa, try gpa.dupe(u8, trimmed));
            }
        } else if (std.mem.eql(u8, child.local, "session-id") and std.mem.eql(u8, child.uri, base_ns)) {
            if (session_id != null) return error.InvalidSessionId;
            const text = try child.textContent(gpa);
            defer gpa.free(text);
            const trimmed = std.mem.trim(u8, text, " \t\r\n");
            const v = std.fmt.parseInt(u32, trimmed, 10) catch return error.InvalidSessionId;
            if (v == 0) return error.InvalidSessionId; // session ids are 1..4294967295
            session_id = v;
        }
        // Unknown children are ignored: hello is an extension point.
    }
    if (!saw_capabilities) return error.MalformedHello;
    switch (expect) {
        .server => if (session_id == null) return error.MissingSessionId,
        .client => if (session_id != null) return error.InvalidSessionId,
    }

    var caps: Capabilities = .{ .gpa = gpa, .list = try uris.toOwnedSlice(gpa) };
    caps.resolve();
    return .{ .capabilities = caps, .session_id = session_id };
}

/// Serialise a `<hello>`. `session_id` is non-null only for a server.
pub fn writeHello(
    w: *std.Io.Writer,
    uris: []const []const u8,
    session_id: ?u32,
) std.Io.Writer.Error!void {
    try w.writeAll("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    try w.print("<hello xmlns=\"{s}\">\n", .{base_ns});
    try w.writeAll("  <capabilities>\n");
    for (uris) |u| try w.print("    <capability>{s}</capability>\n", .{u});
    try w.writeAll("  </capabilities>\n");
    if (session_id) |sid| try w.print("  <session-id>{d}</session-id>\n", .{sid});
    try w.writeAll("</hello>\n");
}

const framing = @import("framing.zig");

/// RFC 6242 §4.1: chunked framing iff BOTH peers advertise `:base:1.1`.
/// Also enforces RFC 6241 §8.1's "MUST verify that the other peer has
/// advertised a common protocol version".
pub fn negotiate(ours: *const Capabilities, theirs: *const Capabilities) error{NoCommonBaseVersion}!framing.Dialect {
    if (ours.base_1_1 and theirs.base_1_1) return .chunked;
    if (ours.base_1_0 and theirs.base_1_0) return .end_of_message;
    return error.NoCommonBaseVersion;
}

// ── tests ──────────────────────────────────────────────────────────────────

/// RFC 6241 §8.1, verbatim — a server hello with the base capability, one
/// standard capability and one implementation-specific one.
const rfc6241_8_1_server_hello =
    \\<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    \\  <capabilities>
    \\    <capability>
    \\      urn:ietf:params:netconf:base:1.1
    \\    </capability>
    \\    <capability>
    \\      urn:ietf:params:netconf:capability:startup:1.0
    \\    </capability>
    \\    <capability>
    \\      http://example.net/router/2.3/myfeature
    \\    </capability>
    \\  </capabilities>
    \\  <session-id>4</session-id>
    \\</hello>
;

/// RFC 6242 §3, verbatim — the client half of the capability exchange.
const rfc6242_3_client_hello =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    \\  <capabilities>
    \\    <capability>
    \\      urn:ietf:params:netconf:base:1.1
    \\    </capability>
    \\  </capabilities>
    \\</hello>
;

test "parseHello: RFC 6241 §8.1 server hello (verbatim)" {
    const gpa = testing.allocator;
    var h = try parseHello(gpa, rfc6241_8_1_server_hello, .server);
    defer h.deinit();

    try testing.expectEqual(@as(?u32, 4), h.session_id);
    try testing.expectEqual(@as(usize, 3), h.capabilities.list.len);
    try testing.expect(h.capabilities.base_1_1);
    try testing.expect(!h.capabilities.base_1_0);
    try testing.expect(h.capabilities.startup);
    try testing.expect(!h.capabilities.candidate);
    // The vendor capability survives verbatim.
    try testing.expectEqualStrings("http://example.net/router/2.3/myfeature", h.capabilities.list[2]);
}

test "parseHello: RFC 6242 §3 client hello (verbatim) has no session-id" {
    const gpa = testing.allocator;
    var h = try parseHello(gpa, rfc6242_3_client_hello, .client);
    defer h.deinit();
    try testing.expectEqual(@as(?u32, null), h.session_id);
    try testing.expect(h.capabilities.base_1_1);
}

test "parseHello: a server hello without session-id is rejected" {
    const gpa = testing.allocator;
    try testing.expectError(error.MissingSessionId, parseHello(gpa, rfc6242_3_client_hello, .server));
}

test "parseHello: a client hello WITH a session-id is rejected" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidSessionId, parseHello(gpa, rfc6241_8_1_server_hello, .client));
}

test "parseHello: hostile / malformed inputs" {
    const gpa = testing.allocator;
    const cases = [_]struct { src: []const u8, want: anyerror }{
        .{ .src = "<hello/>", .want = error.MalformedHello }, // no namespace
        .{ .src = "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"/>", .want = error.MalformedHello }, // no capabilities
        .{ .src = "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><capabilities/></rpc>", .want = error.MalformedHello },
        .{ .src = "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><capabilities><capability></capability></capabilities><session-id>1</session-id></hello>", .want = error.MalformedHello },
        .{ .src = "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><capabilities/><session-id>0</session-id></hello>", .want = error.InvalidSessionId },
        .{ .src = "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><capabilities/><session-id>x</session-id></hello>", .want = error.InvalidSessionId },
        .{ .src = "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><capabilities/><session-id>4294967296</session-id></hello>", .want = error.InvalidSessionId },
        .{ .src = "<!DOCTYPE hello [<!ENTITY x \"y\">]><hello/>", .want = error.DoctypeForbidden }, // XXE surface stays shut
        .{ .src = "<hello", .want = error.UnexpectedEof },
    };
    for (cases) |c| try testing.expectError(c.want, parseHello(gpa, c.src, .server));
}

test "capability comparison ignores ?parameters (RFC 6241 §8.1)" {
    const gpa = testing.allocator;
    var caps = try Capabilities.fromSlice(gpa, &.{
        "urn:ietf:params:netconf:base:1.1",
        "urn:ietf:params:netconf:capability:validate:1.1",
        "http://example.com/mod?module=example-system&revision=2026-01-01",
    });
    defer caps.deinit();
    try testing.expect(caps.has("http://example.com/mod"));
    try testing.expect(caps.has("http://example.com/mod?module=other"));
    try testing.expect(!caps.hasExact("http://example.com/mod"));
    try testing.expect(caps.validate);
    try testing.expect(caps.base_1_1);
}

test "negotiate: the dialect is the capability intersection, nothing else" {
    const gpa = testing.allocator;
    var both: Capabilities = try .fromSlice(gpa, &.{ cap_base_1_0, cap_base_1_1 });
    defer both.deinit();
    var only10: Capabilities = try .fromSlice(gpa, &.{cap_base_1_0});
    defer only10.deinit();
    var only11: Capabilities = try .fromSlice(gpa, &.{cap_base_1_1});
    defer only11.deinit();
    var none: Capabilities = try .fromSlice(gpa, &.{"http://example.com/x"});
    defer none.deinit();

    try testing.expectEqual(framing.Dialect.chunked, try negotiate(&both, &both));
    try testing.expectEqual(framing.Dialect.chunked, try negotiate(&both, &only11));
    try testing.expectEqual(framing.Dialect.end_of_message, try negotiate(&both, &only10));
    try testing.expectEqual(framing.Dialect.end_of_message, try negotiate(&only10, &only10));
    try testing.expectError(error.NoCommonBaseVersion, negotiate(&only10, &only11));
    try testing.expectError(error.NoCommonBaseVersion, negotiate(&both, &none));
}

test "writeHello round-trips through parseHello" {
    const gpa = testing.allocator;
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try writeHello(&aw.writer, &default_client_capabilities, null);
    var h = try parseHello(gpa, aw.written(), .client);
    defer h.deinit();
    try testing.expect(h.capabilities.base_1_0);
    try testing.expect(h.capabilities.base_1_1);
    try testing.expectEqual(@as(?u32, null), h.session_id);

    var aw2: std.Io.Writer.Allocating = .init(gpa);
    defer aw2.deinit();
    try writeHello(&aw2.writer, &.{ cap_base_1_1, cap_candidate }, 7);
    var h2 = try parseHello(gpa, aw2.written(), .server);
    defer h2.deinit();
    try testing.expectEqual(@as(?u32, 7), h2.session_id);
    try testing.expect(h2.capabilities.candidate);
}

// External anchor (2026-08-01): a real, independent NETCONF server — the
// Python `netconf` 2.1.0 package (Christian Hopps' implementation), the same
// one the live interop tests in `client.zig` dial. Unlike the RFC-literal
// goldens above (hand-copied from the spec text), this `<hello>` is byte-for-
// byte what that server actually put on the wire, captured once by
// temporarily instrumenting `Client.receive`/`sendRaw` during a real session
// against it (session-id 3, `:base:1.0`+`:base:1.1` negotiated `.chunked`),
// then frozen here — this test does not open a socket. See SPEC.md
// "External-anchor investigation" for the full setup (throwaway RSA host
// key, static `rpc_get_config` responder, the `paramiko.dsskey` shim needed
// because paramiko 5.0.0 dropped the module `sshutil` 1.5.0 still imports).
const live_netconf_2_1_0_server_hello =
    \\<?xml version="1.0" encoding="UTF-8"?><hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability><capability>urn:ietf:params:netconf:base:1.1</capability></capabilities><session-id>3</session-id></hello>
;

test "external anchor: parseHello on a real server hello from the `netconf` 2.1.0 package (frozen 2026-08-01)" {
    const gpa = testing.allocator;
    var h = try parseHello(gpa, live_netconf_2_1_0_server_hello, .server);
    defer h.deinit();
    try testing.expectEqual(@as(?u32, 3), h.session_id);
    try testing.expectEqual(@as(usize, 2), h.capabilities.list.len);
    try testing.expect(h.capabilities.base_1_0);
    try testing.expect(h.capabilities.base_1_1);

    // The dialect this hello actually negotiated, live, against our own
    // default client capabilities: `.chunked`, matching what the client
    // printed during the real session (`live NETCONF: session-id=3
    // dialect=chunked`).
    var ours: Capabilities = try .fromSlice(gpa, &default_client_capabilities);
    defer ours.deinit();
    try testing.expectEqual(framing.Dialect.chunked, try negotiate(&ours, &h.capabilities));
}

test "fuzz: parseHello never crashes on arbitrary XML-ish input" {
    try testing.fuzz({}, fuzzHello, .{});
}

fn fuzzHello(_: void, smith: *std.testing.Smith) !void {
    var raw: [512]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    if (parseHello(testing.allocator, raw[0..len], .server)) |*h| {
        var m = h.*;
        m.deinit();
    } else |_| {}
}
