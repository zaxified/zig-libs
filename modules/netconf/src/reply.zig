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
    /// RFC 6241 §4.2: `<rpc-reply>` content is exactly one of `<ok/>`, a
    /// single `<data>`, or one-or-more `<rpc-error>`. The server sent more
    /// than one of those three, or more than one `<ok/>`/`<data>` (2026-09-10
    /// audit, `A1/netconf.md` N6/N17 -- before this, `<ok/>`+`<rpc-error>`
    /// set both `Reply.ok = true` AND `Reply.hasErrors() = true`, and two
    /// `<data>` elements made `Reply.body` and `Reply.expectData()` silently
    /// point at DIFFERENT elements).
    AmbiguousReply,
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
        const want = std.mem.print(&buf, "{d}", .{expected}) catch unreachable;
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

    var doc = try xml.parse(gpa, raw, .{ .doctype = .reject, .max_elements = caps.default_max_elements });
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
    var ok_count: usize = 0;
    var data_count: usize = 0;
    // RFC 6022 §4.2 spells the get-schema `<data>` in `ietf-netconf-monitoring`;
    // it is not `Reply.data`, but two `<data>` in either namespace are one too many.
    var monitoring_data_count: usize = 0;

    var it = root.elementIterator();
    while (it.next()) |child| {
        if (body == null) {
            body = child.span.slice(raw);
            body_element = child;
        }
        if (std.mem.eql(u8, child.uri, base_ns)) {
            if (std.mem.eql(u8, child.local, "ok")) {
                ok = true;
                ok_count += 1;
                continue;
            }
            if (std.mem.eql(u8, child.local, "data")) {
                data = child.span.slice(raw);
                data_element = child;
                data_count += 1;
                continue;
            }
            if (std.mem.eql(u8, child.local, "rpc-error")) {
                try errors.append(gpa, parseRpcError(child, raw));
                continue;
            }
        }
        if (std.mem.eql(u8, child.uri, monitoring_ns) and std.mem.eql(u8, child.local, "data")) {
            monitoring_data_count += 1;
        }
        // Anything else is an RPC-specific output element; `body` holds it.
    }

    // RFC 6241 §4.2: content is exactly one of `<ok/>`, `<data>`, or
    // one-or-more `<rpc-error>`. More than one `<data>`/`<ok/>`, or more than
    // one of the three categories present at once, is a protocol violation --
    // see the `AmbiguousReply` doc comment for what silently diverged before
    // this was enforced (N6/N17).
    const categories_present: u2 =
        @as(u2, @intFromBool(ok_count > 0)) +
        @as(u2, @intFromBool(data_count > 0)) +
        @as(u2, @intFromBool(errors.items.len > 0));
    if (categories_present > 1 or ok_count > 1 or data_count + monitoring_data_count > 1) return error.AmbiguousReply;

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
                    // N4 (second site): same strict decimal rule as
                    // `capabilities.parseSessionIdDigits` -- `parseInt`'s `_`
                    // separator let `<session-id>4_5_4</session-id>` inside
                    // `<error-info>` parse as 454, a value the digits do not
                    // show, feeding `RpcError.info_session_id` (what a caller
                    // reads to decide whose lock-holding session to kill).
                    e.info_session_id = caps.parseSessionIdDigits(elementText(info_child, source));
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
    if (count != 1) return ""; // split across multiple text/CDATA nodes (or none) — see doc comment
    return std.mem.trim(u8, out, " \t\r\n");
}

// ── RFC 6022 schema discovery ──────────────────────────────────────────────

/// RFC 6022 §2.1 / §3.1: the `ietf-netconf-monitoring` namespace.
pub const monitoring_ns = "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring";

/// Upper bound on `<schema>` entries `parseSchemaList` accepts. Real devices
/// list hundreds to a few thousand modules; `parseReply` already caps the whole
/// document at `caps.default_max_elements` (65536) elements, so this only makes
/// the list bound explicit and independent of how many leaves an entry has.
pub const max_schemas: usize = 8192;
/// Upper bound on `<location>` entries of one schema (RFC 6022 §2.1.3 lists
/// "NETCONF" plus a handful of URIs).
pub const max_locations: usize = 64;

pub const SchemaError = CheckError || error{
    /// The list holds more than `max_schemas` entries, or one entry more than
    /// `max_locations` locations.
    TooManyEntries,
} || std.mem.Allocator.Error;

/// One `/netconf-state/schemas/schema` entry (RFC 6022 §2.1.3). The strings are
/// owned by the enclosing `SchemaList`.
pub const Schema = struct {
    /// Key leaf `identifier`: what `<get-schema>` takes.
    identifier: []const u8,
    /// Key leaf `version`; may legitimately be empty for unversioned schemas.
    version: []const u8 = "",
    /// Key leaf `format` (`yang`, `xsd`, …); "" if the server omitted it.
    format: []const u8 = "",
    /// `namespace` leaf (the XML namespace the schema defines); "" if absent.
    namespace: []const u8 = "",
    /// `location` leaf-list, in order: a URI, or the literal "NETCONF" meaning
    /// "retrievable with `<get-schema>`".
    locations: []const []const u8 = &.{},

    /// True when `<get-schema>` can fetch this entry (RFC 6022 §2.1.3: a
    /// `location` of `NETCONF`). Servers that omit `location` entirely are not
    /// excluded: an entry with no locations is reported as retrievable too,
    /// because the RFC makes `location` optional and `<get-schema>` is keyed by
    /// the three key leaves, not by it.
    pub fn viaGetSchema(self: Schema) bool {
        if (self.locations.len == 0) return true;
        for (self.locations) |l| if (std.mem.eql(u8, l, "NETCONF")) return true;
        return false;
    }
};

/// The parsed schema list. Owns its strings; independent of the `Reply` it was
/// parsed from.
pub const SchemaList = struct {
    arena: std.heap.ArenaAllocator,
    items: []const Schema,

    pub fn deinit(self: *SchemaList) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Whitespace-trimmed text of a leaf: its direct text and CDATA children
/// concatenated, comments and nested elements ignored.
fn leafText(a: std.mem.Allocator, el: *const xml.Element) std.mem.Allocator.Error![]const u8 {
    var single: ?[]const u8 = null;
    var n: usize = 0;
    for (el.children) |c| switch (c.content) {
        .text, .cdata => |t| {
            single = t;
            n += 1;
        },
        else => {},
    };
    if (n == 0) return "";
    if (n == 1) return a.dupe(u8, std.mem.trim(u8, single.?, " \t\r\n"));
    var out: std.ArrayList(u8) = .empty;
    for (el.children) |c| switch (c.content) {
        .text, .cdata => |t| try out.appendSlice(a, t),
        else => {},
    };
    return std.mem.trim(u8, out.items, " \t\r\n");
}

/// RFC 6022 §2.1.3 / §4.1: read `/netconf-state/schemas` out of the reply to a
/// `<get>` (see `rpc.schemas_filter`). Rules, in the module's usual lenient
/// style for unknown content: elements outside the monitoring namespace and
/// unknown children are skipped; a `<schema>` with no `<identifier>` is skipped
/// (it cannot be asked for); an absent `<netconf-state>`/`<schemas>` (a filter
/// that matched nothing, `<data/>`) is an empty list. An `<rpc-error>` is
/// `error.RpcError`, a reply with no `<data>` is `error.UnexpectedReply`, and
/// more than `max_schemas` entries / `max_locations` locations per entry is
/// `error.TooManyEntries`.
pub fn parseSchemaList(gpa: std.mem.Allocator, r: *const Reply) SchemaError!SchemaList {
    _ = try r.expectData();
    const data_el = r.data_element orelse return error.UnexpectedReply;

    var arena: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    var list: std.ArrayList(Schema) = .empty;
    var nit = data_el.elementIterator();
    while (nit.next()) |state| {
        if (!std.mem.eql(u8, state.uri, monitoring_ns) or !std.mem.eql(u8, state.local, "netconf-state")) continue;
        var sit = state.elementIterator();
        while (sit.next()) |schemas| {
            if (!std.mem.eql(u8, schemas.uri, monitoring_ns) or !std.mem.eql(u8, schemas.local, "schemas")) continue;
            var eit = schemas.elementIterator();
            while (eit.next()) |entry| {
                if (!std.mem.eql(u8, entry.uri, monitoring_ns) or !std.mem.eql(u8, entry.local, "schema")) continue;
                var s: Schema = .{ .identifier = "" };
                var have_id = false;
                var locs: std.ArrayList([]const u8) = .empty;
                var fit = entry.elementIterator();
                while (fit.next()) |f| {
                    if (!std.mem.eql(u8, f.uri, monitoring_ns)) continue;
                    if (std.mem.eql(u8, f.local, "identifier")) {
                        s.identifier = try leafText(a, f);
                        have_id = s.identifier.len != 0;
                    } else if (std.mem.eql(u8, f.local, "version")) {
                        s.version = try leafText(a, f);
                    } else if (std.mem.eql(u8, f.local, "format")) {
                        s.format = try leafText(a, f);
                    } else if (std.mem.eql(u8, f.local, "namespace")) {
                        s.namespace = try leafText(a, f);
                    } else if (std.mem.eql(u8, f.local, "location")) {
                        if (locs.items.len >= max_locations) return error.TooManyEntries;
                        try locs.append(a, try leafText(a, f));
                    }
                }
                if (!have_id) continue;
                if (list.items.len >= max_schemas) return error.TooManyEntries;
                s.locations = locs.items;
                try list.append(a, s);
            }
        }
    }
    return .{ .arena = arena, .items = list.items };
}

/// RFC 6022 §3.1 / §4.2: the schema text of a `<get-schema>` reply, owned by the
/// caller. The `<data>` element may be in the base namespace or — as the RFC's
/// own examples have it — in `ietf-netconf-monitoring`; both are accepted. Its
/// content is returned as the schema: text and CDATA are XML-unescaped and
/// concatenated (a YANG module), and when the content is itself XML (an `xsd`
/// schema) its markup is returned verbatim. Not trimmed. `<rpc-error>` is
/// `error.RpcError` (RFC 6022 §3.1: unknown schema is `invalid-value`, an
/// ambiguous one `operation-failed`/`data-not-unique`), no `<data>` is
/// `error.UnexpectedReply`.
pub fn parseSchemaText(gpa: std.mem.Allocator, r: *const Reply) (CheckError || std.mem.Allocator.Error)![]u8 {
    if (r.hasErrors()) return error.RpcError;
    var data_el: ?*xml.Element = null;
    var it = r.doc.root.elementIterator();
    while (it.next()) |c| {
        if (!std.mem.eql(u8, c.local, "data")) continue;
        if (std.mem.eql(u8, c.uri, base_ns) or std.mem.eql(u8, c.uri, monitoring_ns)) {
            data_el = c;
            break;
        }
    }
    const el = data_el orelse return error.UnexpectedReply;

    var has_element = false;
    for (el.children) |c| switch (c.content) {
        .element => has_element = true,
        else => {},
    };
    if (has_element) {
        // Verbatim inner XML: from the first child node to the end of the last.
        const first = el.children[0].span.start;
        const last = el.children[el.children.len - 1].span.end;
        return gpa.dupe(u8, r.raw[first..last]);
    }
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    for (el.children) |c| switch (c.content) {
        .text, .cdata => |t| try out.appendSlice(gpa, t),
        else => {},
    };
    return out.toOwnedSlice(gpa);
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
    var doc = try xml.parse(gpa, raw, .{ .doctype = .reject, .max_elements = caps.default_max_elements });
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
    // A leading UTF-8 BOM is legal XML (XML 1.0 §4.3.3) and `xml.parse`
    // accepts it at byte 0 -- but `classify` used to stop at the very first
    // byte check (`source[i] != '<'`) and return `.unknown`. A server that
    // prefixed its `<rpc-reply>` with a BOM (RFC 6242 §3 requires UTF-8 but
    // does not forbid one) was therefore routed as `.unknown` by this
    // function while `parseReply` parsed it without complaint --
    // `Client.receiveReply` trusts `classify` exclusively, so the session
    // died on `error.UnexpectedMessage` over a reply the module could
    // actually read (2026-09-10 audit, `A1/netconf.md` N5).
    if (std.mem.startsWith(u8, source, "\xEF\xBB\xBF")) i = 3;
    while (i < source.len) {
        // Skip whitespace.
        while (i < source.len and (source[i] == ' ' or source[i] == '\t' or source[i] == '\r' or source[i] == '\n')) i += 1;
        if (i >= source.len or source[i] != '<') return .unknown;
        if (std.mem.startsWith(u8, source[i..], "<?")) {
            const end = std.mem.findPos(u8, source, i, "?>") orelse return .unknown;
            i = end + 2;
            continue;
        }
        if (std.mem.startsWith(u8, source[i..], "<!--")) {
            const end = std.mem.findPos(u8, source, i, "-->") orelse return .unknown;
            i = end + 3;
            continue;
        }
        if (std.mem.startsWith(u8, source[i..], "<!")) {
            const end = std.mem.findScalarPos(u8, source, i, '>') orelse return .unknown;
            i = end + 1;
            continue;
        }
        // Element name: strip an optional prefix, stop at whitespace or '>'.
        var j = i + 1;
        while (j < source.len and source[j] != ' ' and source[j] != '\t' and source[j] != '\r' and
            source[j] != '\n' and source[j] != '>' and source[j] != '/') j += 1;
        var name = source[i + 1 .. j];
        if (std.mem.findScalar(u8, name, ':')) |c| name = name[c + 1 ..];
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
    try testing.expect(std.mem.find(u8, data, "<full-name>Charlie Root</full-name>") != null);

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
    try testing.expect(std.mem.find(u8, e.info.?, "<session-id>454</session-id>") != null);

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

test "F2: elementText falls back to \"\" when the text is split across multiple nodes, per its own doc comment" {
    // The `count != 1` branch and its fallthrough used to be byte-identical
    // (`return trim(out)` both times), so an element whose text was split by
    // a comment/CDATA silently returned only the LAST text node instead of
    // the documented "" fallback. `error-tag` isn't a realistic place for a
    // comment to appear, but `elementText` has no notion of which caller it
    // serves — it must behave per its own contract for any leaf element.
    const gpa = testing.allocator;
    const src =
        \\<rpc-reply message-id="1" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        \\  <rpc-error><error-tag>a<!--x-->b</error-tag></rpc-error>
        \\</rpc-reply>
    ;
    var r = try parseReply(gpa, src);
    defer r.deinit();
    // Two text nodes ("a" and "b") either side of the comment: count != 1,
    // so this must be "", never "b" (the last node) or "a" (the first).
    try testing.expectEqualStrings("", r.errors[0].tag_text);
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

test "parseReply: N6/N17 -- more than one of ok/data/rpc-error is AmbiguousReply, not silently picked" {
    const gpa = testing.allocator;
    const cases = [_][]const u8{
        // N17 r11: <ok/> AND <rpc-error> -- before the fix, Reply.ok = true
        // AND Reply.hasErrors() = true simultaneously.
        "<rpc-reply message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><ok/><rpc-error><error-tag>in-use</error-tag></rpc-error></rpc-reply>",
        // N17 r12: <data> AND <rpc-error>.
        "<rpc-reply message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><data>x</data><rpc-error><error-tag>in-use</error-tag></rpc-error></rpc-reply>",
        // N6 r13 / N17: two <data> elements -- before the fix, Reply.body was
        // the FIRST ("<data>FIRST</data>") and Reply.expectData() was the
        // LAST ("<data>SECOND</data>"): two different elements, silently.
        "<rpc-reply message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><data>FIRST</data><data>SECOND</data></rpc-reply>",
        // Two <ok/>.
        "<rpc-reply message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><ok/><ok/></rpc-reply>",
    };
    for (cases) |src| try testing.expectError(error.AmbiguousReply, parseReply(gpa, src));

    // Positive control: each category ALONE, and an RPC-specific body with
    // none of the three, must keep parsing -- the guard must not become
    // over-eager.
    var ok_only = try parseReply(gpa, rfc_7_5_lock_ok);
    defer ok_only.deinit();
    try testing.expect(ok_only.ok);

    var data_only = try parseReply(gpa, rfc_7_1_reply);
    defer data_only.deinit();
    _ = try data_only.expectData();

    var errors_only = try parseReply(gpa,
        \\<rpc-reply message-id="1" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        \\  <rpc-error><error-tag>in-use</error-tag></rpc-error>
        \\  <rpc-error><error-tag>too-big</error-tag></rpc-error>
        \\</rpc-reply>
    );
    defer errors_only.deinit();
    try testing.expectEqual(@as(usize, 2), errors_only.errors.len);

    var body_only = try parseReply(gpa,
        \\<rpc-reply message-id="105" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        \\  <config xmlns="http://example.com/schema/1.2/config"><users/></config>
        \\</rpc-reply>
    );
    defer body_only.deinit();
    try testing.expect(!body_only.hasErrors());
}

test "classify: a UTF-8 BOM before the root element does not defeat routing" {
    const bom = "\xEF\xBB\xBF";
    try testing.expectEqual(MessageKind.rpc_reply, classify(bom ++ "<rpc-reply message-id=\"1\"/>"));
    try testing.expectEqual(MessageKind.hello, classify(bom ++ "<?xml version=\"1.0\"?>\n<hello xmlns=\"x\"/>"));
    try testing.expectEqual(MessageKind.notification, classify(bom ++ "<notification>"));
}

test "parseReply: a BOM-prefixed reply classifies AND parses consistently" {
    // N5 regression, exercised end to end: `classify` used to say `.unknown`
    // for exactly the documents `parseReply` accepts here.
    const gpa = testing.allocator;
    const bom = "\xEF\xBB\xBF";
    const src = bom ++ "<rpc-reply message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><ok/></rpc-reply>";
    try testing.expectEqual(MessageKind.rpc_reply, classify(src));
    var r = try parseReply(gpa, src);
    defer r.deinit();
    try r.expectOk();
}

test "parseReply: N4 (error-info site) -- session-id with a digit separator is rejected, not silently reinterpreted" {
    const gpa = testing.allocator;
    var r = try parseReply(gpa,
        \\<rpc-reply message-id="1" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        \\  <rpc-error>
        \\    <error-tag>lock-denied</error-tag>
        \\    <error-info><session-id>4_5_4</session-id></error-info>
        \\  </rpc-error>
        \\</rpc-reply>
    );
    defer r.deinit();
    // Before the fix this was 454 (the digits with the `_` dropped), not null.
    try testing.expectEqual(@as(?u32, null), r.errors[0].info_session_id);
}

test "parseReply: N1 -- element count is bounded independent of Limits.max_message" {
    // `xml.parse`'s own default (`Options.max_elements = 1 << 20`) let a
    // small, well-under-`max_message` document balloon to hundreds of MiB of
    // live bytes (2026-09-10 audit, `A1/netconf.md` N1: a 4.00 MiB
    // `<a/>`-repeated reply cost 529.2 MiB, a 132x amplification, with
    // `Limits.max_message` never engaging at all -- it bounds wire bytes, not
    // element count, and the two are unrelated in this module).
    // `caps.default_max_elements` (65536) is what `parseReply` now passes to
    // `xml.parse` instead of inheriting that default.
    const gpa = testing.allocator;
    var over: std.ArrayList(u8) = .empty;
    defer over.deinit(gpa);
    try over.appendSlice(gpa, "<rpc-reply message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><data>");
    var i: usize = 0;
    // + the <rpc-reply> and <data> elements themselves push this over the cap.
    while (i <= caps.default_max_elements) : (i += 1) try over.appendSlice(gpa, "<a/>");
    try over.appendSlice(gpa, "</data></rpc-reply>");
    try testing.expectError(error.TooManyElements, parseReply(gpa, over.items));

    // Positive control: comfortably under the cap still parses in full.
    var under: std.ArrayList(u8) = .empty;
    defer under.deinit(gpa);
    try under.appendSlice(gpa, "<rpc-reply message-id=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><data>");
    i = 0;
    while (i < caps.default_max_elements - 4) : (i += 1) try under.appendSlice(gpa, "<a/>");
    try under.appendSlice(gpa, "</data></rpc-reply>");
    var r = try parseReply(gpa, under.items);
    defer r.deinit();
    _ = try r.expectData();
}

test "parseReply: N18 -- expectMessageId is strict decimal-string comparison, by design" {
    // N18 (LOW, audit's own verdict: "the strictness is security-correct;
    // noting it as an interop risk, not a defect" -- confirmed here, not
    // changed). A server that reflects `message-id` with a leading zero, a
    // sign or surrounding whitespace fails correlation instead of being
    // fuzzy-matched; RFC 6241 §4.1 says the id is returned, not that it is
    // returned byte-identical, but treating anything other than an exact
    // decimal echo as a mismatch is the safer of the two readings and this
    // locks it in.
    const gpa = testing.allocator;
    const cases = [_][]const u8{ "01", " 1", "+1", "1\n" };
    for (cases) |id| {
        var buf: [256]u8 = undefined;
        const src = try std.mem.print(&buf, "<rpc-reply message-id=\"{s}\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><ok/></rpc-reply>", .{id});
        var r = try parseReply(gpa, src);
        defer r.deinit();
        try testing.expectError(error.MessageIdMismatch, r.expectMessageId(1));
    }
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
    try testing.expect(std.mem.find(u8, n.event.?, "<severity>major</severity>") != null);

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
    try testing.expect(std.mem.find(u8, data, "<probe:name>oracle-probe</probe:name>") != null);
    try testing.expect(std.mem.find(u8, data, "<probe:value>42</probe:value>") != null);

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

/// `testkit.fuzz.seed`: a corpus entry is NOT the document. `Smith.slice`
/// reads a little-endian `u32` length first, so a raw reply handed to the
/// corpus would reach `classify` and `parseReply` four octets short.
const seed = @import("testkit").fuzz.seed;

/// Replies and notifications in the format `Smith.slice` reads.
///
/// ⚠ The buffer above is 512 octets and this module's largest fixture,
/// `rfc_7_1_reply`, is 506 — checked, because a seed over the buffer reads
/// back EMPTY rather than truncated, silently. Anything added here that is
/// longer than 512 must raise the buffer, not be shortened.
///
/// Lifted from the value tests: the three RFC 6241 §7 documents, the two
/// frozen live replies, the RFC 5277 notification, every hostile case
/// `parseReply: hostile / wrong-document inputs` names, and the four shapes
/// `classify` routes.
const reply_seeds = [_][]const u8{
    seed(rfc_7_1_reply), // §7.1 data reply: message-id 101, a full <data>
    seed(rfc_7_5_lock_denied), // §7.5: one rpc-error with error-info
    seed(rfc_7_5_lock_ok), // §7.5: <ok/> with the RFC's own comment
    seed(live_netconf_2_1_0_get_config_reply), // frozen live get-config reply
    seed(live_netconf_2_1_0_rpc_error_reply), // frozen live rpc-error
    seed("<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><ok/></rpc-reply>"), // no message-id
    seed("<notification xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>2007-07-08T00:01:00Z</eventTime><event xmlns=\"http://example.com/event/1.0\"><severity>major</severity></event></notification>"),
    seed("<notification/>"), // NotANotification: no namespace
    seed("<rpc-reply/>"), // NotAReply: wrong namespace
    seed("<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"/>"), // NotAReply, classify → .hello
    seed("<rpc-reply xmlns=\"urn:x\"/>"), // NotAReply: a foreign namespace
    seed("<!DOCTYPE r><rpc-reply/>"), // DoctypeForbidden: the XXE surface stays shut
    seed("<rpc-reply"), // UnexpectedEof
    seed("<rpc message-id=\"101\">"), // classify → .rpc
    seed("<netconf:rpc message-id=\"101\">"), // classify → .rpc through a prefix
    seed("garbage"), // classify → .unknown
};

test "fuzz: parseReply / classify never crash" {
    try testing.fuzz({}, fuzzReply, .{ .corpus = &reply_seeds });
}

fn fuzzReply(_: void, smith: *std.testing.Smith) !void {
    var raw: [512]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(raw.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM —
    // so `len` was 0 for every input, `classify` was handed "" (→ .unknown)
    // and both parsers refused with `error.NoRootElement` before reading a
    // byte, with the document sitting unread in `raw`. Measured 2026-09-07
    // over the corpus above: **0 of 16 seeds non-empty, 0 replies parsed and 0
    // classified as anything but .unknown before; 16 of 16 non-empty, 6 replies
    // parsed, 1 notification parsed and 15 classified after.**
    const len: usize = smith.slice(&raw);
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

test "corpus: every reply seed reaches the parsers, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment. A seed
    // longer than the harness's buffer reads back EMPTY (`Smith.slice` falls
    // back to the range minimum) — the reason `rfc_7_1_reply`'s 506 octets
    // against a 512 buffer is documented at the corpus rather than left to be
    // rediscovered.
    //
    // `classified` is the number the empty input cannot produce: `classify("")`
    // is `.unknown` by design, so it is reach that this counts, not legality.
    var nonempty: usize = 0;
    var replies: usize = 0;
    var notifications: usize = 0;
    var classified: usize = 0;
    var rpc_errors: usize = 0;
    for (reply_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [512]u8 = undefined;
        const len: usize = smith.slice(&raw);
        if (len != 0) nonempty += 1;
        const input = raw[0..len];
        if (classify(input) != .unknown) classified += 1;
        if (parseReply(testing.allocator, input)) |*r| {
            var m = r.*;
            defer m.deinit();
            replies += 1;
            rpc_errors += m.errors.len;
        } else |_| {}
        if (parseNotification(testing.allocator, input)) |*n| {
            var m = n.*;
            m.deinit();
            notifications += 1;
        } else |_| {}
    }
    try testing.expectEqual(reply_seeds.len, nonempty);
    // Measured 2026-09-07: with the collapsing draw, 0 of 16 seeds non-empty,
    // 0 replies, 0 notifications, 0 classified and 0 rpc-errors — one empty
    // string sixteen times. After:
    try testing.expectEqual(@as(usize, 6), replies);
    try testing.expectEqual(@as(usize, 1), notifications);
    try testing.expectEqual(@as(usize, 15), classified);
    try testing.expectEqual(@as(usize, 2), rpc_errors);
}

// ── RFC 6022 tests ─────────────────────────────────────────────────────────

/// RFC 6022 §4.1, verbatim — the schema list reply.
const rfc_6022_4_1_reply =
    \\<rpc-reply message-id="101"
    \\           xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    \\  <data>
    \\    <netconf-state
    \\    xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">
    \\      <schemas>
    \\        <schema>
    \\          <identifier>foo</identifier>
    \\          <version>1.0</version>
    \\          <format>xsd</format>
    \\          <namespace>http://example.com/foo</namespace>
    \\          <location>ftp://ftp.example.com/schemas/foo_1.0.xsd</location>
    \\          <location>http://www.example.com/schema/foo_1.0.xsd</location>
    \\          <location>NETCONF</location>
    \\        </schema>
    \\        <schema>
    \\          <identifier>foo</identifier>
    \\          <version>1.1</version>
    \\          <format>xsd</format>
    \\          <namespace>http://example.com/foo</namespace>
    \\          <location>ftp://ftp.example.com/schemas/foo_1.1.xsd</location>
    \\          <location>http://www.example.com/schema/foo_1.1.xsd</location>
    \\          <location>NETCONF</location>
    \\        </schema>
    \\        <schema>
    \\          <identifier>bar</identifier>
    \\          <version>2008-06-01</version>
    \\          <format>yang</format>
    \\          <namespace>http://example.com/bar</namespace>
    \\          <location>
    \\            http://example.com/schema/bar@2008-06-01.yang
    \\          </location>
    \\          <location>NETCONF</location>
    \\        </schema>
    \\        <schema>
    \\          <identifier>bar-types</identifier>
    \\          <version>2008-06-01</version>
    \\          <format>yang</format>
    \\          <namespace>http://example.com/bar</namespace>
    \\          <location>
    \\            http://example.com/schema/bar-types@2008-06-01.yang
    \\          </location>
    \\          <location>NETCONF</location>
    \\        </schema>
    \\      </schemas>
    \\    </netconf-state>
    \\  </data>
    \\</rpc-reply>
;

test "parseSchemaList: RFC 6022 §4.1 reply (verbatim): four entries, locations kept, whitespace trimmed" {
    const gpa = testing.allocator;
    var r = try parseReply(gpa, rfc_6022_4_1_reply);
    defer r.deinit();
    var l = try parseSchemaList(gpa, &r);
    defer l.deinit();
    try testing.expectEqual(@as(usize, 4), l.items.len);
    const foo10 = l.items[0];
    try testing.expectEqualStrings("foo", foo10.identifier);
    try testing.expectEqualStrings("1.0", foo10.version);
    try testing.expectEqualStrings("xsd", foo10.format);
    try testing.expectEqualStrings("http://example.com/foo", foo10.namespace);
    try testing.expectEqual(@as(usize, 3), foo10.locations.len);
    try testing.expectEqualStrings("ftp://ftp.example.com/schemas/foo_1.0.xsd", foo10.locations[0]);
    try testing.expectEqualStrings("http://www.example.com/schema/foo_1.0.xsd", foo10.locations[1]);
    try testing.expectEqualStrings("NETCONF", foo10.locations[2]);
    try testing.expect(foo10.viaGetSchema());
    try testing.expectEqualStrings("1.1", l.items[1].version);
    const bar = l.items[2];
    try testing.expectEqualStrings("bar", bar.identifier);
    try testing.expectEqualStrings("2008-06-01", bar.version);
    try testing.expectEqualStrings("yang", bar.format);
    // The RFC indents this location on its own lines; the value is trimmed.
    try testing.expectEqualStrings("http://example.com/schema/bar@2008-06-01.yang", bar.locations[0]);
    try testing.expectEqualStrings("bar-types", l.items[3].identifier);
}

test "parseSchemaList: the list outlives the Reply it came from" {
    const gpa = testing.allocator;
    var r = try parseReply(gpa, rfc_6022_4_1_reply);
    var l = try parseSchemaList(gpa, &r);
    defer l.deinit();
    r.deinit();
    try testing.expectEqualStrings("bar-types", l.items[3].identifier);
}

test "parseSchemaList: hostile and odd replies are errors or skips, never a panic" {
    const gpa = testing.allocator;
    const head = "<rpc-reply message-id=\"1\" xmlns=\"" ++ base_ns ++ "\">";
    const state = "<netconf-state xmlns=\"" ++ monitoring_ns ++ "\"><schemas>";
    const state_end = "</schemas></netconf-state>";

    // <ok/>, no <data>: UnexpectedReply.
    {
        var r = try parseReply(gpa, head ++ "<ok/></rpc-reply>");
        defer r.deinit();
        try testing.expectError(error.UnexpectedReply, parseSchemaList(gpa, &r));
    }
    // <rpc-error>: RpcError.
    {
        var r = try parseReply(gpa, rfc_7_5_lock_denied);
        defer r.deinit();
        try testing.expectError(error.RpcError, parseSchemaList(gpa, &r));
    }
    // Empty <data/> (filter matched nothing), and no <schemas>: empty list.
    inline for (.{ "<data/>", "<data><netconf-state xmlns=\"" ++ monitoring_ns ++ "\"/></data>" }) |body| {
        var r = try parseReply(gpa, head ++ body ++ "</rpc-reply>");
        defer r.deinit();
        var l = try parseSchemaList(gpa, &r);
        defer l.deinit();
        try testing.expectEqual(@as(usize, 0), l.items.len);
    }
    // Unknown children, a foreign-namespace <schema>, a schema with no/empty
    // identifier: skipped; the good entry survives; missing leaves are "".
    {
        const body = "<data>" ++ state ++
            "<junk>x<schema/></junk>" ++
            "<schema xmlns=\"urn:other\"><identifier>alien</identifier></schema>" ++
            "<schema><version>1</version></schema>" ++
            "<schema><identifier>  </identifier></schema>" ++
            "<schema><identifier>ok</identifier><weird><identifier>nested</identifier></weird></schema>" ++
            state_end ++ "</data>";
        var r = try parseReply(gpa, head ++ body ++ "</rpc-reply>");
        defer r.deinit();
        var l = try parseSchemaList(gpa, &r);
        defer l.deinit();
        try testing.expectEqual(@as(usize, 1), l.items.len);
        try testing.expectEqualStrings("ok", l.items[0].identifier);
        try testing.expectEqualStrings("", l.items[0].version);
        try testing.expectEqual(@as(usize, 0), l.items[0].locations.len);
        try testing.expect(l.items[0].viaGetSchema());
    }
    // Entities are expanded; CDATA and split text are one value.
    {
        const body = "<data>" ++ state ++
            "<schema><identifier>a&amp;b<![CDATA[<c>]]>d</identifier>" ++
            "<location>http://x/?a=1&amp;b=2</location></schema>" ++ state_end ++ "</data>";
        var r = try parseReply(gpa, head ++ body ++ "</rpc-reply>");
        defer r.deinit();
        var l = try parseSchemaList(gpa, &r);
        defer l.deinit();
        try testing.expectEqualStrings("a&b<c>d", l.items[0].identifier);
        try testing.expectEqualStrings("http://x/?a=1&b=2", l.items[0].locations[0]);
        try testing.expect(!l.items[0].viaGetSchema());
    }
    // Entity tricks: a DOCTYPE (billion laughs, external entity) never gets as
    // far as the schema reader -- parseReply refuses it.
    try testing.expectError(error.DoctypeForbidden, parseReply(gpa, "<!DOCTYPE r [<!ENTITY a \"aaaa\"><!ENTITY b \"&a;&a;&a;&a;\">]>" ++ head ++
        "<data>" ++ state ++ "<schema><identifier>&b;</identifier></schema>" ++ state_end ++ "</data></rpc-reply>"));
}

test "parseSchemaList: more than max_schemas entries, or max_locations locations, is TooManyEntries" {
    const gpa = testing.allocator;
    const head = "<rpc-reply message-id=\"1\" xmlns=\"" ++ base_ns ++ "\"><data><netconf-state xmlns=\"" ++ monitoring_ns ++ "\"><schemas>";
    const tail = "</schemas></netconf-state></data></rpc-reply>";
    var doc: std.ArrayList(u8) = .empty;
    defer doc.deinit(gpa);

    // Exactly max_schemas: fine. One more: error.
    try doc.appendSlice(gpa, head);
    for (0..max_schemas) |_| try doc.appendSlice(gpa, "<schema><identifier>m</identifier></schema>");
    try doc.appendSlice(gpa, tail);
    {
        var r = try parseReply(gpa, doc.items);
        defer r.deinit();
        var l = try parseSchemaList(gpa, &r);
        defer l.deinit();
        try testing.expectEqual(max_schemas, l.items.len);
    }
    doc.clearRetainingCapacity();
    try doc.appendSlice(gpa, head);
    for (0..max_schemas + 1) |_| try doc.appendSlice(gpa, "<schema><identifier>m</identifier></schema>");
    try doc.appendSlice(gpa, tail);
    {
        var r = try parseReply(gpa, doc.items);
        defer r.deinit();
        try testing.expectError(error.TooManyEntries, parseSchemaList(gpa, &r));
    }

    // Locations.
    for ([_]usize{ max_locations, max_locations + 1 }) |n| {
        doc.clearRetainingCapacity();
        try doc.appendSlice(gpa, head);
        try doc.appendSlice(gpa, "<schema><identifier>m</identifier>");
        for (0..n) |_| try doc.appendSlice(gpa, "<location>NETCONF</location>");
        try doc.appendSlice(gpa, "</schema>");
        try doc.appendSlice(gpa, tail);
        var r = try parseReply(gpa, doc.items);
        defer r.deinit();
        if (n > max_locations) {
            try testing.expectError(error.TooManyEntries, parseSchemaList(gpa, &r));
        } else {
            var l = try parseSchemaList(gpa, &r);
            defer l.deinit();
            try testing.expectEqual(n, l.items[0].locations.len);
        }
    }
}

test "parseSchemaText: RFC 6022 §4.2 YANG reply (data in the monitoring namespace)" {
    const gpa = testing.allocator;
    // RFC 6022 §4.2 example 2's reply (message-id 102): the <data> element is
    // in ietf-netconf-monitoring, not the base namespace, and holds plain text.
    var r = try parseReply(gpa,
        \\<rpc-reply message-id="102"
        \\  xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        \\  <data
        \\  xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">
        \\    module bar {
        \\      //default format (yang) returned
        \\      leaf a { type string; }  // &lt;&amp;&gt; in a comment
        \\    }
        \\  </data>
        \\</rpc-reply>
    );
    defer r.deinit();
    const text = try parseSchemaText(gpa, &r);
    defer gpa.free(text);
    try testing.expect(std.mem.startsWith(u8, std.mem.trim(u8, text, " \n"), "module bar {"));
    try testing.expect(std.mem.find(u8, text, "// <&> in a comment") != null);
    try testing.expect(std.mem.endsWith(u8, std.mem.trimEnd(u8, text, " \n"), "}"));
}

test "parseSchemaText: base-namespace <data>, CDATA, and an xsd body kept as XML" {
    const gpa = testing.allocator;
    {
        var r = try parseReply(gpa, "<rpc-reply message-id=\"1\" xmlns=\"" ++ base_ns ++ "\"><data>module m { description \"a&amp;b\"; }" ++
            "<![CDATA[ // <raw> & ]]></data></rpc-reply>");
        defer r.deinit();
        const text = try parseSchemaText(gpa, &r);
        defer gpa.free(text);
        try testing.expectEqualStrings("module m { description \"a&b\"; } // <raw> & ", text);
    }
    {
        // RFC 6022 §4.2 example 1's reply: the schema is XML.
        var r = try parseReply(gpa,
            \\<rpc-reply message-id="101"
            \\  xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            \\  <data
            \\  xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">
            \\    <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
            \\      <!-- foo 1.0 xsd schema contents here -->
            \\    </xs:schema>
            \\  </data>
            \\</rpc-reply>
        );
        defer r.deinit();
        const text = try parseSchemaText(gpa, &r);
        defer gpa.free(text);
        const t = std.mem.trim(u8, text, " \n");
        try testing.expect(std.mem.startsWith(u8, t, "<xs:schema xmlns:xs="));
        try testing.expect(std.mem.endsWith(u8, t, "</xs:schema>"));
        try testing.expect(std.mem.find(u8, t, "<!-- foo 1.0 xsd schema contents here -->") != null);
    }
}

test "parseSchemaText: hostile replies are errors, never a panic" {
    const gpa = testing.allocator;
    const head = "<rpc-reply message-id=\"1\" xmlns=\"" ++ base_ns ++ "\">";
    // No <data>.
    {
        var r = try parseReply(gpa, head ++ "<ok/></rpc-reply>");
        defer r.deinit();
        try testing.expectError(error.UnexpectedReply, parseSchemaText(gpa, &r));
    }
    // A <data> in a foreign namespace is not ours.
    {
        var r = try parseReply(gpa, head ++ "<data xmlns=\"urn:other\">x</data></rpc-reply>");
        defer r.deinit();
        try testing.expectError(error.UnexpectedReply, parseSchemaText(gpa, &r));
    }
    // rpc-error (RFC 6022 §3.1 invalid-value).
    {
        var r = try parseReply(gpa, head ++
            "<rpc-error><error-type>application</error-type><error-tag>invalid-value</error-tag>" ++
            "<error-severity>error</error-severity></rpc-error></rpc-reply>");
        defer r.deinit();
        try testing.expectError(error.RpcError, parseSchemaText(gpa, &r));
        try testing.expectEqual(ErrorTag.invalid_value, r.firstError().?.tag);
    }
    // Empty <data/>: an empty text, not a crash (indexing children[0] is guarded).
    {
        var r = try parseReply(gpa, head ++ "<data/></rpc-reply>");
        defer r.deinit();
        const text = try parseSchemaText(gpa, &r);
        defer gpa.free(text);
        try testing.expectEqual(@as(usize, 0), text.len);
    }
    // Two <data>: AmbiguousReply already at parseReply for base-ns ones.
    try testing.expectError(error.AmbiguousReply, parseReply(gpa, head ++ "<data>a</data><data>b</data></rpc-reply>"));
    // DOCTYPE entity bomb never reaches the reader.
    try testing.expectError(error.DoctypeForbidden, parseReply(gpa, "<!DOCTYPE r [<!ENTITY a \"aaaa\">]>" ++ head ++ "<data>&a;</data></rpc-reply>"));
}

test "parseSchemaList: every level must be an ietf-netconf-monitoring element of the right name" {
    const gpa = testing.allocator;
    const mon = "xmlns=\"" ++ monitoring_ns ++ "\"";
    const other = "xmlns=\"urn:other\"";
    // Each decoy carries an otherwise valid <identifier>, so a reader that stops
    // checking its level's namespace or local name would list it.
    const body = "<data>" ++
        "<netconf-state " ++ other ++ "><schemas " ++ mon ++ "><schema><identifier>a1</identifier></schema></schemas></netconf-state>" ++
        "<other-state " ++ mon ++ "><schemas><schema><identifier>b1</identifier></schema></schemas></other-state>" ++
        "<netconf-state " ++ mon ++ ">" ++
        "<schemas " ++ other ++ "><schema " ++ mon ++ "><identifier>c1</identifier></schema></schemas>" ++
        "<schemas-x><schema><identifier>d1</identifier></schema></schemas-x>" ++
        "<schemas>" ++
        "<schema " ++ other ++ "><identifier " ++ mon ++ ">e1</identifier></schema>" ++
        "<junk><identifier>f1</identifier></junk>" ++
        "<schema><identifier " ++ other ++ ">g1</identifier></schema>" ++
        "<schema><identifier>good</identifier><version " ++ other ++ ">bad</version></schema>" ++
        "</schemas></netconf-state></data>";
    var r = try parseReply(gpa, "<rpc-reply message-id=\"1\" xmlns=\"" ++ base_ns ++ "\">" ++ body ++ "</rpc-reply>");
    defer r.deinit();
    var l = try parseSchemaList(gpa, &r);
    defer l.deinit();
    try testing.expectEqual(@as(usize, 1), l.items.len);
    try testing.expectEqualStrings("good", l.items[0].identifier);
    try testing.expectEqualStrings("", l.items[0].version);
}

test "parseSchemaList: a leaf is trimmed and joined across text and CDATA nodes" {
    const gpa = testing.allocator;
    const head = "<rpc-reply message-id=\"1\" xmlns=\"" ++ base_ns ++ "\"><data><netconf-state xmlns=\"" ++ monitoring_ns ++ "\"><schemas>";
    const tail = "</schemas></netconf-state></data></rpc-reply>";
    var r = try parseReply(gpa, head ++
        "<schema><identifier>  a&amp;b<![CDATA[<c>]]>d  </identifier><version>ab<![CDATA[cd]]></version></schema>" ++
        "<schema><identifier><![CDATA[ solo ]]></identifier><format><![CDATA[x]]> y </format></schema>" ++ tail);
    defer r.deinit();
    var l = try parseSchemaList(gpa, &r);
    defer l.deinit();
    try testing.expectEqual(@as(usize, 2), l.items.len);
    // Several nodes: concatenated, then trimmed as a whole.
    try testing.expectEqualStrings("a&b<c>d", l.items[0].identifier);
    // Text then CDATA: both kept.
    try testing.expectEqualStrings("abcd", l.items[0].version);
    // A CDATA section alone is the value (trimmed).
    try testing.expectEqualStrings("solo", l.items[1].identifier);
    try testing.expectEqualStrings("x y", l.items[1].format);
}

test "parseSchemaText: two <data> are ambiguous in either namespace; an XML body is returned byte for byte, untrimmed" {
    const gpa = testing.allocator;
    const mon = "xmlns=\"" ++ monitoring_ns ++ "\"";
    const head = "<rpc-reply message-id=\"1\" xmlns=\"" ++ base_ns ++ "\">";
    // ncclient reads the first one and libnetconf2 (libyang: one instance of the
    // output leaf) refuses; RFC 6241 §4.2 allows a single <data>. Refused.
    try testing.expectError(error.AmbiguousReply, parseReply(gpa, head ++ "<data " ++ mon ++ ">first</data><data " ++ mon ++ ">second</data></rpc-reply>"));
    try testing.expectError(error.AmbiguousReply, parseReply(gpa, head ++ "<data>first</data><data>second</data></rpc-reply>"));
    try testing.expectError(error.AmbiguousReply, parseReply(gpa, head ++ "<data>first</data><data " ++ mon ++ ">second</data></rpc-reply>"));
    {
        var r = try parseReply(gpa, head ++ "<data " ++ mon ++ ">only</data></rpc-reply>");
        defer r.deinit();
        const text = try parseSchemaText(gpa, &r);
        defer gpa.free(text);
        try testing.expectEqualStrings("only", text);
    }
    {
        const inner = "\n  <xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"><!-- c --></xs:schema>\n ";
        var r = try parseReply(gpa, head ++ "<data " ++ mon ++ ">" ++ inner ++ "</data></rpc-reply>");
        defer r.deinit();
        const text = try parseSchemaText(gpa, &r);
        defer gpa.free(text);
        try testing.expectEqualStrings(inner, text);
    }
}
