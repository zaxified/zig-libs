// SPDX-License-Identifier: MIT

//! RFC 6241 §4.2–§4.3 — `<rpc-reply>`, `<ok>`, `<data>` and `<rpc-error>`,
//! plus the RFC 5277 §2.2.1 `<notification>` message.
//!
//! Design rule: **a reply is never silently dropped**. `Reply` retains the
//! whole message (and every structured `<rpc-error>` field) whether or not the
//! operation succeeded; the typed error `error.RpcError` is what `expectOk` /
//! `expectData` raise, and the caller still holds the `Reply` with the reason.
//! `error-info` — whose contents are extension-defined — is kept as the
//! verbatim XML span rather than being flattened.
//!
//! Correlation is a first-class concern: `Reply.messageId` is the `message-id`
//! attribute exactly as it arrived, and `Reply.expectMessageId` treats a
//! missing or mismatched id as an error. A NETCONF peer may interleave
//! notifications with replies, so "the next message" and "my reply" are not
//! the same thing.

const std = @import("std");
const testing = std.testing;
const xml = @import("xml");
const caps = @import("capabilities.zig");

pub const base_ns = caps.base_ns;
pub const notification_ns = caps.notification_ns;

/// RFC 6241 Appendix A `error-type`: the protocol layer that failed.
pub const ErrorType = enum {
    transport,
    rpc,
    protocol,
    application,

    pub fn parse(s: []const u8) ?ErrorType {
        return std.meta.stringToEnum(ErrorType, s);
    }
};

/// RFC 6241 §4.3 `error-severity`.
pub const ErrorSeverity = enum {
    err,
    warning,

    pub fn parse(s: []const u8) ?ErrorSeverity {
        if (std.mem.eql(u8, s, "error")) return .err;
        if (std.mem.eql(u8, s, "warning")) return .warning;
        return null;
    }
};

/// RFC 6241 Appendix A `error-tag`. `unknown` covers a tag we do not model —
/// the verbatim text is always available in `RpcError.tag_text`, so an
/// unmodelled tag is never lost.
pub const ErrorTag = enum {
    in_use,
    invalid_value,
    too_big,
    missing_attribute,
    bad_attribute,
    unknown_attribute,
    missing_element,
    bad_element,
    unknown_element,
    unknown_namespace,
    access_denied,
    lock_denied,
    resource_denied,
    rollback_failed,
    data_exists,
    data_missing,
    operation_not_supported,
    operation_failed,
    partial_operation,
    malformed_message,
    unknown,

    pub fn parse(s: []const u8) ErrorTag {
        const table = [_]struct { text: []const u8, tag: ErrorTag }{
            .{ .text = "in-use", .tag = .in_use },
            .{ .text = "invalid-value", .tag = .invalid_value },
            .{ .text = "too-big", .tag = .too_big },
            .{ .text = "missing-attribute", .tag = .missing_attribute },
            .{ .text = "bad-attribute", .tag = .bad_attribute },
            .{ .text = "unknown-attribute", .tag = .unknown_attribute },
            .{ .text = "missing-element", .tag = .missing_element },
            .{ .text = "bad-element", .tag = .bad_element },
            .{ .text = "unknown-element", .tag = .unknown_element },
            .{ .text = "unknown-namespace", .tag = .unknown_namespace },
            .{ .text = "access-denied", .tag = .access_denied },
            .{ .text = "lock-denied", .tag = .lock_denied },
            .{ .text = "resource-denied", .tag = .resource_denied },
            .{ .text = "rollback-failed", .tag = .rollback_failed },
            .{ .text = "data-exists", .tag = .data_exists },
            .{ .text = "data-missing", .tag = .data_missing },
            .{ .text = "operation-not-supported", .tag = .operation_not_supported },
            .{ .text = "operation-failed", .tag = .operation_failed },
            .{ .text = "partial-operation", .tag = .partial_operation },
            .{ .text = "malformed-message", .tag = .malformed_message },
        };
        for (table) |e| if (std.mem.eql(u8, e.text, s)) return e.tag;
        return .unknown;
    }
};

/// One `<rpc-error>`. Every field is a slice into the `Reply`'s retained copy
/// of the message, so the whole structure dies with `Reply.deinit`.
pub const RpcError = struct {
    error_type: ?ErrorType = null,
    type_text: []const u8 = "",
    tag: ErrorTag = .unknown,
    tag_text: []const u8 = "",
    severity: ?ErrorSeverity = null,
    severity_text: []const u8 = "",
    app_tag: ?[]const u8 = null,
    path: ?[]const u8 = null,
    message: ?[]const u8 = null,
    /// `xml:lang` of `<error-message>`, if the server sent one.
    message_lang: ?[]const u8 = null,
    /// Verbatim XML of the `<error-info>` element (extension-defined content).
    info: ?[]const u8 = null,
    /// `<session-id>` inside `<error-info>` — the one standard piece of
    /// error-info, carried by `lock-denied` (RFC 6241 §7.5).
    info_session_id: ?u32 = null,
};

pub const ParseError = error{
    /// Not an `<rpc-reply>` in the NETCONF base namespace.
    NotAReply,
    /// `<rpc-reply>` with no recognisable body.
    MalformedReply,
} || xml.ParseError || std.mem.Allocator.Error;

pub const CheckError = error{
    /// The peer answered with one or more `<rpc-error>`. Details stay in the
    /// `Reply`.
    RpcError,
    /// A well-formed reply that is not the shape this call expected (e.g.
    /// `<ok/>` where `<data>` was required).
    UnexpectedReply,
    /// The reply's `message-id` is missing or does not match the request.
    MessageIdMismatch,
};

/// A parsed `<rpc-reply>`. Owns the message bytes and the parse tree.
pub const Reply = struct {
    gpa: std.mem.Allocator,
    /// The message exactly as received (framing already stripped).
    raw: []u8,
    doc: xml.Document,
    errors: []RpcError,

    /// `message-id` attribute, verbatim. Null when the peer omitted it — which
    /// is a protocol violation for a reply to an `<rpc>` and is treated as one
    /// by `expectMessageId`.
    message_id: ?[]const u8,
    /// The `<data>` element, verbatim XML including its own tags. Null unless
    /// the reply carried one.
    ///
    /// **Caveat:** this is a raw slice of the message, so namespace
    /// declarations inherited from `<rpc-reply>` are *not* repeated on it —
    /// re-parsing the slice standalone loses them. Use `data_element` to walk
    /// the content with full namespace context; use this slice for logging,
    /// hashing or handing the bytes to something that re-establishes context.
    data: ?[]const u8,
    /// The `<data>` element in the already-parsed tree (full namespace scope).
    data_element: ?*xml.Element,
    /// Verbatim XML of the first child element, whatever it was. Lets a caller
    /// handle a body this module does not model (e.g. RFC 6242 §4.3's older
    /// `<config>` reply, or an RPC-specific output element). Same namespace
    /// caveat as `data`.
    body: ?[]const u8,
    /// The first child element in the parsed tree.
    body_element: ?*xml.Element,
    ok: bool,

    pub fn deinit(self: *Reply) void {
        self.gpa.free(self.errors);
        self.doc.deinit();
        self.gpa.free(self.raw);
        self.* = undefined;
    }

    pub fn hasErrors(self: *const Reply) bool {
        return self.errors.len != 0;
    }

    pub fn firstError(self: *const Reply) ?*const RpcError {
        return if (self.errors.len == 0) null else &self.errors[0];
    }

    /// Correlate. RFC 6241 §4.1: the reply carries the request's `message-id`.
    pub fn expectMessageId(self: *const Reply, expected: u64) CheckError!void {
        const got = self.message_id orelse return error.MessageIdMismatch;
        var buf: [24]u8 = undefined;
        const want = std.fmt.bufPrint(&buf, "{d}", .{expected}) catch unreachable;
        if (!std.mem.eql(u8, got, want)) return error.MessageIdMismatch;
    }

    /// `<ok/>` or bust. Errors keep their detail in `self.errors`.
    pub fn expectOk(self: *const Reply) CheckError!void {
        if (self.hasErrors()) return error.RpcError;
        if (!self.ok) return error.UnexpectedReply;
    }

    /// The `<data>` element, or a typed error.
    pub fn expectData(self: *const Reply) CheckError![]const u8 {
        if (self.hasErrors()) return error.RpcError;
        return self.data orelse error.UnexpectedReply;
    }
};

/// Parse a `<rpc-reply>` message. `source` is copied, so the caller may reuse
/// its buffer immediately.
pub fn parseReply(gpa: std.mem.Allocator, source: []const u8) ParseError!Reply {
    const raw = try gpa.dupe(u8, source);
    errdefer gpa.free(raw);

    var doc = try xml.parse(gpa, raw, .{ .doctype = .reject });
    errdefer doc.deinit();

    const root = doc.root;
    if (!std.mem.eql(u8, root.local, "rpc-reply")) return error.NotAReply;
    if (!std.mem.eql(u8, root.uri, base_ns)) return error.NotAReply;

    var errors: std.ArrayList(RpcError) = .empty;
    errdefer errors.deinit(gpa);

    var data: ?[]const u8 = null;
    var data_element: ?*xml.Element = null;
    var body: ?[]const u8 = null;
    var body_element: ?*xml.Element = null;
    var ok = false;

    var it = root.elementIterator();
    while (it.next()) |child| {
        if (body == null) {
            body = child.span.slice(raw);
            body_element = child;
        }
        if (std.mem.eql(u8, child.uri, base_ns)) {
            if (std.mem.eql(u8, child.local, "ok")) {
                ok = true;
                continue;
            }
            if (std.mem.eql(u8, child.local, "data")) {
                data = child.span.slice(raw);
                data_element = child;
                continue;
            }
            if (std.mem.eql(u8, child.local, "rpc-error")) {
                try errors.append(gpa, parseRpcError(child, raw));
                continue;
            }
        }
        // Anything else is an RPC-specific output element; `body` holds it.
    }

    return .{
        .gpa = gpa,
        .raw = raw,
        .doc = doc,
        .errors = try errors.toOwnedSlice(gpa),
        .message_id = root.attr("", "message-id"),
        .data = data,
        .data_element = data_element,
        .body = body,
        .body_element = body_element,
        .ok = ok,
    };
}

fn parseRpcError(el: *const xml.Element, source: []const u8) RpcError {
    var e: RpcError = .{};
    var it = el.elementIterator();
    while (it.next()) |f| {
        if (!std.mem.eql(u8, f.uri, base_ns)) continue;
        const text = elementText(f, source);
        if (std.mem.eql(u8, f.local, "error-type")) {
            e.type_text = text;
            e.error_type = ErrorType.parse(text);
        } else if (std.mem.eql(u8, f.local, "error-tag")) {
            e.tag_text = text;
            e.tag = ErrorTag.parse(text);
        } else if (std.mem.eql(u8, f.local, "error-severity")) {
            e.severity_text = text;
            e.severity = ErrorSeverity.parse(text);
        } else if (std.mem.eql(u8, f.local, "error-app-tag")) {
            e.app_tag = text;
        } else if (std.mem.eql(u8, f.local, "error-path")) {
            e.path = text;
        } else if (std.mem.eql(u8, f.local, "error-message")) {
            e.message = text;
            e.message_lang = f.attr(xml.xml_ns, "lang");
        } else if (std.mem.eql(u8, f.local, "error-info")) {
            e.info = f.span.slice(source);
            var ii = f.elementIterator();
            while (ii.next()) |info_child| {
                if (std.mem.eql(u8, info_child.local, "session-id")) {
                    e.info_session_id = std.fmt.parseInt(u32, elementText(info_child, source), 10) catch null;
                }
            }
        }
    }
    return e;
}

/// Text content of a leaf element, whitespace-trimmed, as a slice of `source`.
/// NETCONF error fields are always single-token or single-line values, and the
/// RFC's own examples indent them, so trimming is what a caller wants. Falls
/// back to a span slice when the element has exactly one text child (the
/// common case) and to "" otherwise, so nothing is allocated.
fn elementText(el: *const xml.Element, source: []const u8) []const u8 {
    _ = source;
    var out: []const u8 = "";
    var count: usize = 0;
    for (el.children) |c| switch (c.content) {
        .text, .cdata => |t| {
            out = t;
            count += 1;
        },
        else => {},
    };
    if (count != 1) return std.mem.trim(u8, out, " \t\r\n");
    return std.mem.trim(u8, out, " \t\r\n");
}

// ── notifications (RFC 5277 §2.2.1) ────────────────────────────────────────

pub const Notification = struct {
    gpa: std.mem.Allocator,
    raw: []u8,
    doc: xml.Document,
    /// `<eventTime>` as the `xsd:dateTime` string the server sent.
    event_time: []const u8,
    /// Verbatim XML of the event element itself (the child after eventTime).
    event: ?[]const u8,

    pub fn deinit(self: *Notification) void {
        self.doc.deinit();
        self.gpa.free(self.raw);
        self.* = undefined;
    }
};

pub const NotificationError = error{NotANotification} || xml.ParseError || std.mem.Allocator.Error;

pub fn parseNotification(gpa: std.mem.Allocator, source: []const u8) NotificationError!Notification {
    const raw = try gpa.dupe(u8, source);
    errdefer gpa.free(raw);
    var doc = try xml.parse(gpa, raw, .{ .doctype = .reject });
    errdefer doc.deinit();

    const root = doc.root;
    if (!std.mem.eql(u8, root.local, "notification")) return error.NotANotification;
    if (!std.mem.eql(u8, root.uri, notification_ns)) return error.NotANotification;

    var event_time: []const u8 = "";
    var event: ?[]const u8 = null;
    var it = root.elementIterator();
    while (it.next()) |child| {
        if (std.mem.eql(u8, child.local, "eventTime") and std.mem.eql(u8, child.uri, notification_ns)) {
            event_time = elementText(child, raw);
        } else if (event == null) {
            event = child.span.slice(raw);
        }
    }
    if (event_time.len == 0) return error.NotANotification;
    return .{ .gpa = gpa, .raw = raw, .doc = doc, .event_time = event_time, .event = event };
}

// ── message classification ─────────────────────────────────────────────────

pub const MessageKind = enum { hello, rpc_reply, rpc, notification, unknown };

/// Cheap root-element sniff, so the session layer can route a message without
/// parsing it twice. Skips the XML declaration, comments and PIs; does not
/// validate — the real parser does that.
pub fn classify(source: []const u8) MessageKind {
    var i: usize = 0;
    while (i < source.len) {
        // Skip whitespace.
        while (i < source.len and (source[i] == ' ' or source[i] == '\t' or source[i] == '\r' or source[i] == '\n')) i += 1;
        if (i >= source.len or source[i] != '<') return .unknown;
        if (std.mem.startsWith(u8, source[i..], "<?")) {
            const end = std.mem.indexOfPos(u8, source, i, "?>") orelse return .unknown;
            i = end + 2;
            continue;
        }
        if (std.mem.startsWith(u8, source[i..], "<!--")) {
            const end = std.mem.indexOfPos(u8, source, i, "-->") orelse return .unknown;
            i = end + 3;
            continue;
        }
        if (std.mem.startsWith(u8, source[i..], "<!")) {
            const end = std.mem.indexOfScalarPos(u8, source, i, '>') orelse return .unknown;
            i = end + 1;
            continue;
        }
        // Element name: strip an optional prefix, stop at whitespace or '>'.
        var j = i + 1;
        while (j < source.len and source[j] != ' ' and source[j] != '\t' and source[j] != '\r' and
            source[j] != '\n' and source[j] != '>' and source[j] != '/') j += 1;
        var name = source[i + 1 .. j];
        if (std.mem.indexOfScalar(u8, name, ':')) |c| name = name[c + 1 ..];
        if (std.mem.eql(u8, name, "hello")) return .hello;
        if (std.mem.eql(u8, name, "rpc-reply")) return .rpc_reply;
        if (std.mem.eql(u8, name, "rpc")) return .rpc;
        if (std.mem.eql(u8, name, "notification")) return .notification;
        return .unknown;
    }
    return .unknown;
}

// ── tests ──────────────────────────────────────────────────────────────────

/// RFC 6241 §7.1, verbatim — the reply to the `<users>` `get-config`.
const rfc_7_1_reply =
    \\<rpc-reply message-id="101"
    \\     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    \\  <data>
    \\    <top xmlns="http://example.com/schema/1.2/config">
    \\      <users>
    \\        <user>
    \\          <name>root</name>
    \\          <type>superuser</type>
    \\          <full-name>Charlie Root</full-name>
    \\          <company-info>
    \\            <dept>1</dept>
    \\            <id>1</id>
    \\          </company-info>
    \\        </user>
    \\        <!-- additional <user> elements appear here... -->
    \\      </users>
    \\    </top>
    \\  </data>
    \\</rpc-reply>
;

/// RFC 6241 §7.5, verbatim — a failed `<lock>`, the canonical `<rpc-error>`.
const rfc_7_5_lock_denied =
    \\<rpc-reply message-id="101"
    \\     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    \\  <rpc-error>
    \\    <error-type>protocol</error-type>
    \\    <error-tag>lock-denied</error-tag>
    \\    <error-severity>error</error-severity>
    \\    <error-message>
    \\      Lock failed, lock is already held
    \\    </error-message>
    \\    <error-info>
    \\      <session-id>454</session-id>
    \\      <!-- lock is held by NETCONF session 454 -->
    \\    </error-info>
    \\  </rpc-error>
    \\</rpc-reply>
;

/// RFC 6241 §7.5, verbatim — the successful lock reply (with the RFC's own
/// trailing comment, which must not confuse the `<ok/>` detection).
const rfc_7_5_lock_ok =
    \\<rpc-reply message-id="101"
    \\     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    \\  <ok/> <!-- lock succeeded -->
    \\</rpc-reply>
;

test "parseReply: RFC 6241 §7.1 data reply (verbatim)" {
    const gpa = testing.allocator;
    var r = try parseReply(gpa, rfc_7_1_reply);
    defer r.deinit();

    try testing.expectEqualStrings("101", r.message_id.?);
    try r.expectMessageId(101);
    try testing.expectError(error.MessageIdMismatch, r.expectMessageId(102));
    try testing.expect(!r.hasErrors());
    try testing.expect(!r.ok);

    const data = try r.expectData();
    try testing.expect(std.mem.startsWith(u8, data, "<data>"));
    try testing.expect(std.mem.endsWith(u8, data, "</data>"));
    try testing.expect(std.mem.indexOf(u8, data, "<full-name>Charlie Root</full-name>") != null);

    // The parsed element keeps full namespace context...
    const de = r.data_element.?;
    try testing.expectEqualStrings("data", de.local);
    try testing.expectEqualStrings(base_ns, de.uri);
    const top = de.firstElementChild().?;
    try testing.expectEqualStrings("top", top.local);
    try testing.expectEqualStrings("http://example.com/schema/1.2/config", top.uri);

    // ...while the raw span is well-formed XML but has lost the inherited
    // default namespace, exactly as documented on `Reply.data`.
    var sub = try xml.parse(gpa, data, .{ .doctype = .reject });
    defer sub.deinit();
    try testing.expectEqualStrings("data", sub.root.local);
    try testing.expectEqualStrings("", sub.root.uri);
}

test "parseReply: RFC 6241 §7.5 lock-denied error (verbatim), every field retained" {
    const gpa = testing.allocator;
    var r = try parseReply(gpa, rfc_7_5_lock_denied);
    defer r.deinit();

    try testing.expect(r.hasErrors());
    try testing.expectEqual(@as(usize, 1), r.errors.len);
    const e = r.firstError().?;
    try testing.expectEqual(ErrorType.protocol, e.error_type.?);
    try testing.expectEqualStrings("protocol", e.type_text);
    try testing.expectEqual(ErrorTag.lock_denied, e.tag);
    try testing.expectEqualStrings("lock-denied", e.tag_text);
    try testing.expectEqual(ErrorSeverity.err, e.severity.?);
    try testing.expectEqualStrings("Lock failed, lock is already held", e.message.?);
    try testing.expectEqual(@as(?u32, 454), e.info_session_id);
    try testing.expect(std.mem.startsWith(u8, e.info.?, "<error-info>"));
    try testing.expect(std.mem.indexOf(u8, e.info.?, "<session-id>454</session-id>") != null);

    // The typed error is raised, the detail is still there.
    try testing.expectError(error.RpcError, r.expectOk());
    try testing.expectError(error.RpcError, r.expectData());
    try testing.expectEqual(ErrorTag.lock_denied, r.firstError().?.tag);
}

test "parseReply: RFC 6241 §7.5 ok reply (verbatim, with the RFC's comment)" {
    const gpa = testing.allocator;
    var r = try parseReply(gpa, rfc_7_5_lock_ok);
    defer r.deinit();
    try testing.expect(r.ok);
    try r.expectOk();
    try testing.expectError(error.UnexpectedReply, r.expectData());
}

test "parseReply: multiple rpc-errors are all kept, in order" {
    const gpa = testing.allocator;
    const src =
        \\<rpc-reply message-id="5" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        \\  <rpc-error>
        \\    <error-type>application</error-type>
        \\    <error-tag>data-missing</error-tag>
        \\    <error-severity>error</error-severity>
        \\    <error-app-tag>vendor-1</error-app-tag>
        \\    <error-path>/t:top/t:users</error-path>
        \\    <error-message xml:lang="en">no such user</error-message>
        \\  </rpc-error>
        \\  <rpc-error>
        \\    <error-type>application</error-type>
        \\    <error-tag>operation-failed</error-tag>
        \\    <error-severity>warning</error-severity>
        \\  </rpc-error>
        \\</rpc-reply>
    ;
    var r = try parseReply(gpa, src);
    defer r.deinit();
    try testing.expectEqual(@as(usize, 2), r.errors.len);
    try testing.expectEqual(ErrorTag.data_missing, r.errors[0].tag);
    try testing.expectEqualStrings("vendor-1", r.errors[0].app_tag.?);
    try testing.expectEqualStrings("/t:top/t:users", r.errors[0].path.?);
    try testing.expectEqualStrings("no such user", r.errors[0].message.?);
    try testing.expectEqualStrings("en", r.errors[0].message_lang.?);
    try testing.expectEqual(ErrorTag.operation_failed, r.errors[1].tag);
    try testing.expectEqual(ErrorSeverity.warning, r.errors[1].severity.?);
    try testing.expectEqual(@as(?[]const u8, null), r.errors[1].app_tag);
}

test "ErrorTag.parse: every RFC 6241 Appendix A tag maps to its own enum value" {
    // Each published error-tag string must round-trip to the enum value of
    // the SAME name — a copy/paste in the lookup table (e.g. two entries
    // mapping to the same tag, leaving a third value dead) parses without
    // error and is otherwise invisible: only `lock-denied`, `data-missing`
    // and `operation-failed` had dedicated coverage elsewhere in this file,
    // so a swap among any of the other 17 tags went undetected.
    const cases = [_]struct { text: []const u8, tag: ErrorTag }{
        .{ .text = "in-use", .tag = .in_use },
        .{ .text = "invalid-value", .tag = .invalid_value },
        .{ .text = "too-big", .tag = .too_big },
        .{ .text = "missing-attribute", .tag = .missing_attribute },
        .{ .text = "bad-attribute", .tag = .bad_attribute },
        .{ .text = "unknown-attribute", .tag = .unknown_attribute },
        .{ .text = "missing-element", .tag = .missing_element },
        .{ .text = "bad-element", .tag = .bad_element },
        .{ .text = "unknown-element", .tag = .unknown_element },
        .{ .text = "unknown-namespace", .tag = .unknown_namespace },
        .{ .text = "access-denied", .tag = .access_denied },
        .{ .text = "lock-denied", .tag = .lock_denied },
        .{ .text = "resource-denied", .tag = .resource_denied },
        .{ .text = "rollback-failed", .tag = .rollback_failed },
        .{ .text = "data-exists", .tag = .data_exists },
        .{ .text = "data-missing", .tag = .data_missing },
        .{ .text = "operation-not-supported", .tag = .operation_not_supported },
        .{ .text = "operation-failed", .tag = .operation_failed },
        .{ .text = "partial-operation", .tag = .partial_operation },
        .{ .text = "malformed-message", .tag = .malformed_message },
    };
    for (cases) |c| {
        try testing.expectEqual(c.tag, ErrorTag.parse(c.text));
        // And every other case's text must NOT parse to this case's tag —
        // catches a table entry accidentally mapped to a neighbour's value.
        for (cases) |other| {
            if (std.mem.eql(u8, other.text, c.text)) continue;
            try testing.expect(ErrorTag.parse(other.text) != c.tag);
        }
    }
    try testing.expectEqual(ErrorTag.unknown, ErrorTag.parse("not-a-real-tag"));
}

test "parseReply: an unmodelled error-tag keeps its text" {
    const gpa = testing.allocator;
    const src =
        \\<rpc-reply message-id="1" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        \\  <rpc-error><error-tag>vendor-specific-boom</error-tag></rpc-error>
        \\</rpc-reply>
    ;
    var r = try parseReply(gpa, src);
    defer r.deinit();
    try testing.expectEqual(ErrorTag.unknown, r.errors[0].tag);
    try testing.expectEqualStrings("vendor-specific-boom", r.errors[0].tag_text);
}

test "parseReply: an RPC-specific body is exposed verbatim, not dropped" {
    const gpa = testing.allocator;
    // RFC 6242 §4.3's example reply uses <config>, not <data> — an older
    // shape, and exactly the case that must not be silently discarded.
    const src =
        \\<rpc-reply message-id="105" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        \\  <config xmlns="http://example.com/schema/1.2/config">
        \\    <users/>
        \\  </config>
        \\</rpc-reply>
    ;
    var r = try parseReply(gpa, src);
    defer r.deinit();
    try testing.expect(!r.ok);
    try testing.expect(!r.hasErrors());
    try testing.expectEqual(@as(?[]const u8, null), r.data);
    try testing.expect(std.mem.startsWith(u8, r.body.?, "<config"));
    try testing.expectError(error.UnexpectedReply, r.expectOk());
}

test "parseReply: hostile / wrong-document inputs" {
    const gpa = testing.allocator;
    const cases = [_]struct { src: []const u8, want: anyerror }{
        .{ .src = "<rpc-reply/>", .want = error.NotAReply }, // wrong namespace
        .{ .src = "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"/>", .want = error.NotAReply },
        .{ .src = "<rpc-reply xmlns=\"urn:x\"/>", .want = error.NotAReply },
        .{ .src = "<!DOCTYPE r><rpc-reply/>", .want = error.DoctypeForbidden },
        .{ .src = "<rpc-reply", .want = error.UnexpectedEof },
        .{ .src = "", .want = error.NoRootElement },
    };
    for (cases) |c| try testing.expectError(c.want, parseReply(gpa, c.src));
}

test "parseReply: a reply with no message-id fails correlation" {
    const gpa = testing.allocator;
    var r = try parseReply(gpa, "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><ok/></rpc-reply>");
    defer r.deinit();
    try testing.expectEqual(@as(?[]const u8, null), r.message_id);
    try testing.expectError(error.MessageIdMismatch, r.expectMessageId(1));
}

test "parseNotification: RFC 5277 §2.2.1 shape" {
    const gpa = testing.allocator;
    const src =
        \\<notification xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
        \\  <eventTime>2007-07-08T00:01:00Z</eventTime>
        \\  <event xmlns="http://example.com/event/1.0">
        \\    <eventClass>fault</eventClass>
        \\    <severity>major</severity>
        \\  </event>
        \\</notification>
    ;
    var n = try parseNotification(gpa, src);
    defer n.deinit();
    try testing.expectEqualStrings("2007-07-08T00:01:00Z", n.event_time);
    try testing.expect(std.mem.startsWith(u8, n.event.?, "<event xmlns="));
    try testing.expect(std.mem.indexOf(u8, n.event.?, "<severity>major</severity>") != null);

    try testing.expectError(error.NotANotification, parseNotification(gpa, "<notification/>"));
    try testing.expectError(error.NotANotification, parseNotification(
        gpa,
        "<notification xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\"/>",
    ));
}

test "classify: routes the four message kinds without a full parse" {
    try testing.expectEqual(MessageKind.hello, classify("<?xml version=\"1.0\"?>\n<hello xmlns=\"x\"/>"));
    try testing.expectEqual(MessageKind.rpc_reply, classify("  <rpc-reply message-id=\"1\"/>"));
    try testing.expectEqual(MessageKind.rpc, classify("<rpc message-id=\"1\">"));
    try testing.expectEqual(MessageKind.notification, classify("<notification>"));
    try testing.expectEqual(MessageKind.rpc, classify("<netconf:rpc message-id=\"101\">"));
    try testing.expectEqual(MessageKind.hello, classify("<!-- hi --><hello/>"));
    try testing.expectEqual(MessageKind.unknown, classify(""));
    try testing.expectEqual(MessageKind.unknown, classify("garbage"));
    try testing.expectEqual(MessageKind.unknown, classify("<?xml"));
    try testing.expectEqual(MessageKind.unknown, classify("<!--"));
}

// External anchor (2026-08-01): the same real, independent NETCONF server as
// `capabilities.zig`'s live-hello anchor — the Python `netconf` 2.1.0 package.
// These two replies are byte-for-byte what it put on the wire in the same
// session (session-id 3, `.chunked` framing) that produced the hello frozen
// there: message-id 1 is the reply to our own `get-config` request (built by
// `buildRpc` — see the matching anchor in `rpc.zig`), message-id 3 is the
// reply to a deliberately unsupported operation, a REAL `<rpc-error>` from a
// server that never saw our code, not a hand-typed one. Captured once by
// instrumenting `Client.receive` during the live interop test; this test
// itself opens no socket. See SPEC.md "External-anchor investigation".
const live_netconf_2_1_0_get_config_reply =
    \\<?xml version="1.0" encoding="UTF-8"?><rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
    \\  <data>
    \\    <probe:top xmlns:probe="urn:example:probe">
    \\      <probe:name>oracle-probe</probe:name>
    \\      <probe:value>42</probe:value>
    \\    </probe:top>
    \\  </data>
    \\</rpc-reply>
;

const live_netconf_2_1_0_rpc_error_reply =
    \\<?xml version="1.0" encoding="UTF-8"?><rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="3"><rpc-error><error-type>protocol</error-type><error-tag>operation-not-supported</error-tag><error-severity>error</error-severity></rpc-error></rpc-reply>
;

test "external anchor: parseReply on a real get-config reply from the `netconf` 2.1.0 package (frozen 2026-08-01)" {
    const gpa = testing.allocator;
    var r = try parseReply(gpa, live_netconf_2_1_0_get_config_reply);
    defer r.deinit();
    try r.expectMessageId(1);
    try testing.expect(!r.hasErrors());

    const data = try r.expectData();
    try testing.expect(std.mem.indexOf(u8, data, "<probe:name>oracle-probe</probe:name>") != null);
    try testing.expect(std.mem.indexOf(u8, data, "<probe:value>42</probe:value>") != null);

    // The parsed tree keeps the `probe:` namespace binding the raw span
    // cannot see standalone (the same caveat `rfc_7_1_reply`'s test proves).
    const de = r.data_element.?;
    const top = de.firstElementChild().?;
    try testing.expectEqualStrings("top", top.local);
    try testing.expectEqualStrings("urn:example:probe", top.uri);
}

test "external anchor: parseReply on a real rpc-error from the `netconf` 2.1.0 package (frozen 2026-08-01)" {
    const gpa = testing.allocator;
    var r = try parseReply(gpa, live_netconf_2_1_0_rpc_error_reply);
    defer r.deinit();
    try r.expectMessageId(3);
    try testing.expect(r.hasErrors());
    const e = r.firstError().?;
    try testing.expectEqual(ErrorType.protocol, e.error_type.?);
    try testing.expectEqualStrings("protocol", e.type_text);
    try testing.expectEqual(ErrorTag.operation_not_supported, e.tag);
    try testing.expectEqualStrings("operation-not-supported", e.tag_text);
    try testing.expectEqual(ErrorSeverity.err, e.severity.?);
    try testing.expectError(error.RpcError, r.expectOk());
    try testing.expectError(error.RpcError, r.expectData());
}

test "fuzz: parseReply / classify never crash" {
    try testing.fuzz({}, fuzzReply, .{});
}

fn fuzzReply(_: void, smith: *std.testing.Smith) !void {
    var raw: [512]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    const input = raw[0..len];
    _ = classify(input);
    if (parseReply(testing.allocator, input)) |*r| {
        var m = r.*;
        _ = m.hasErrors();
        m.deinit();
    } else |_| {}
    if (parseNotification(testing.allocator, input)) |*n| {
        var m = n.*;
        m.deinit();
    } else |_| {}
}
