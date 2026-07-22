// SPDX-License-Identifier: MIT

//! RFC 6241 §7 + §8 — the `<rpc>` request builders.
//!
//! Pure serialisation: a `Rpc` value in, NETCONF XML out. No allocation on the
//! `write*` path (the caller supplies the writer), no I/O, no state. The
//! `message-id` is a parameter rather than something this file invents,
//! because allocating it is the session's job (`client.zig`) and correlating a
//! reply to it is the whole point of the attribute.
//!
//! Payloads that are themselves XML — a subtree filter, an `<edit-config>`
//! `<config>` body — are taken as **verbatim XML fragments**. That is a
//! deliberate seam: NETCONF content is YANG-modelled data this module has no
//! model of, and re-encoding it would be lossy. Everything that is *not* a
//! fragment (URLs, stream names, timestamps) goes through XML escaping.

const std = @import("std");
const testing = std.testing;
const caps = @import("capabilities.zig");
const xml = @import("xml");

pub const base_ns = caps.base_ns;
pub const notification_ns = caps.notification_ns;

/// A configuration datastore, as it appears inside `<source>`/`<target>`.
/// `.url` requires the peer's `:url` capability (RFC 6241 §8.8).
pub const Datastore = union(enum) {
    running,
    candidate,
    startup,
    url: []const u8,
};

/// Everything a `<source>` may be for `copy-config`/`validate`: a datastore, a
/// URL, or an inline `<config>` body (verbatim XML fragment).
pub const ConfigSource = union(enum) {
    running,
    candidate,
    startup,
    url: []const u8,
    /// Verbatim XML children of `<config>`.
    config: []const u8,
};

/// RFC 6241 §7.2 `<default-operation>`.
pub const DefaultOperation = enum {
    merge,
    replace,
    none,

    pub fn wire(self: DefaultOperation) []const u8 {
        return @tagName(self);
    }
};

/// RFC 6241 §7.2 `<test-option>` (`test-then-set` needs `:validate:1.1`).
pub const TestOption = enum {
    test_then_set,
    set,
    test_only,

    pub fn wire(self: TestOption) []const u8 {
        return switch (self) {
            .test_then_set => "test-then-set",
            .set => "set",
            .test_only => "test-only",
        };
    }
};

/// RFC 6241 §7.2 `<error-option>` (`rollback-on-error` needs the capability of
/// the same name, §8.5).
pub const ErrorOption = enum {
    stop_on_error,
    continue_on_error,
    rollback_on_error,

    pub fn wire(self: ErrorOption) []const u8 {
        return switch (self) {
            .stop_on_error => "stop-on-error",
            .continue_on_error => "continue-on-error",
            .rollback_on_error => "rollback-on-error",
        };
    }
};

/// The RFC 6241 §7.2 `operation` attribute placed on elements inside a
/// `<config>` body. It lives in the NETCONF base namespace, so it needs a
/// prefix bound to that namespace — `<config xmlns:nc="…base:1.0">` and then
/// `nc:operation="delete"`. `attribute()` gives the ready-made attribute text
/// for the `nc` prefix `editConfigConfigOpen` declares.
pub const Operation = enum {
    merge,
    replace,
    create,
    delete,
    remove,

    pub fn wire(self: Operation) []const u8 {
        return @tagName(self);
    }

    /// ` nc:operation="delete"` — including the leading space, ready to splice
    /// into a start tag whose document declares `xmlns:nc` = the base
    /// namespace (which `Rpc.edit_config` does on `<config>`).
    pub fn attribute(self: Operation) []const u8 {
        return switch (self) {
            .merge => " nc:operation=\"merge\"",
            .replace => " nc:operation=\"replace\"",
            .create => " nc:operation=\"create\"",
            .delete => " nc:operation=\"delete\"",
            .remove => " nc:operation=\"remove\"",
        };
    }
};

/// RFC 6241 §6 subtree filtering, or §8.9 XPath filtering.
pub const Filter = union(enum) {
    none,
    /// Verbatim XML fragment placed inside `<filter type="subtree">`.
    subtree: []const u8,
    /// `:xpath` capability. `ns` is an optional verbatim attribute string of
    /// namespace declarations to place on `<filter>`, e.g.
    /// `xmlns:t="http://example.com/schema/1.2/config"`.
    xpath: struct {
        select: []const u8,
        ns: []const u8 = "",
    },
};

/// The body of an `<edit-config>`: an inline config, or a URL (`:url`).
pub const EditPayload = union(enum) {
    /// Verbatim XML children of `<config>`.
    config: []const u8,
    url: []const u8,
};

pub const EditConfig = struct {
    target: Datastore,
    payload: EditPayload,
    default_operation: ?DefaultOperation = null,
    test_option: ?TestOption = null,
    error_option: ?ErrorOption = null,
};

pub const GetConfig = struct {
    source: Datastore = .running,
    filter: Filter = .none,
};

pub const Get = struct {
    filter: Filter = .none,
};

pub const CopyConfig = struct {
    target: Datastore,
    source: ConfigSource,
};

/// RFC 6241 §8.3.4.1 / §8.4.5.1 `<commit>`.
pub const Commit = struct {
    /// `<confirmed/>` — the commit reverts unless confirmed (`:confirmed-commit`).
    confirmed: bool = false,
    /// `<confirm-timeout>` in seconds; only meaningful with `confirmed`.
    confirm_timeout: ?u32 = null,
    /// `<persist>` — makes the confirmed commit survive session loss (:1.1).
    persist: ?[]const u8 = null,
    /// `<persist-id>` — confirms a persistent confirmed commit from another
    /// session (:1.1).
    persist_id: ?[]const u8 = null,
};

/// RFC 5277 §2.1.1 `<create-subscription>`.
pub const CreateSubscription = struct {
    /// Event stream name; null means the default `NETCONF` stream.
    stream: ?[]const u8 = null,
    filter: Filter = .none,
    /// `<startTime>` / `<stopTime>` as `xsd:dateTime` strings (replay,
    /// RFC 5277 §3.3) — passed through verbatim after escaping.
    start_time: ?[]const u8 = null,
    stop_time: ?[]const u8 = null,
};

/// Every request this module can build. `raw` is the escape hatch: its bytes
/// are placed inside the `<rpc>` envelope verbatim, so an operation from a
/// YANG module we know nothing about still gets a correlated message-id.
pub const Rpc = union(enum) {
    get: Get,
    get_config: GetConfig,
    edit_config: EditConfig,
    copy_config: CopyConfig,
    delete_config: Datastore,
    lock: Datastore,
    unlock: Datastore,
    commit: Commit,
    discard_changes,
    validate: ConfigSource,
    close_session,
    kill_session: u32,
    create_subscription: CreateSubscription,
    /// Verbatim XML child element(s) of `<rpc>`.
    raw: []const u8,
};

pub const BuildError = std.Io.Writer.Error;

/// Serialise `rpc` as a complete `<rpc>` document (no XML declaration — RFC
/// 6241 §7's own examples omit it, and it is optional in XML 1.0).
pub fn writeRpc(w: *std.Io.Writer, message_id: u64, rpc: Rpc) BuildError!void {
    try w.print("<rpc message-id=\"{d}\" xmlns=\"{s}\">\n", .{ message_id, base_ns });
    switch (rpc) {
        .get => |g| {
            if (g.filter == .none) {
                try w.writeAll("  <get/>\n");
            } else {
                try w.writeAll("  <get>\n");
                try writeFilter(w, g.filter, 4);
                try w.writeAll("  </get>\n");
            }
        },
        .get_config => |g| {
            try w.writeAll("  <get-config>\n");
            try writeDatastore(w, "source", g.source, 4);
            try writeFilter(w, g.filter, 4);
            try w.writeAll("  </get-config>\n");
        },
        .edit_config => |e| {
            try w.writeAll("  <edit-config>\n");
            try writeDatastore(w, "target", e.target, 4);
            if (e.default_operation) |d|
                try w.print("    <default-operation>{s}</default-operation>\n", .{d.wire()});
            if (e.test_option) |t|
                try w.print("    <test-option>{s}</test-option>\n", .{t.wire()});
            if (e.error_option) |eo|
                try w.print("    <error-option>{s}</error-option>\n", .{eo.wire()});
            switch (e.payload) {
                .config => |body| {
                    // The `nc` prefix is bound here so callers can splice
                    // `Operation.attribute()` into their own elements.
                    try w.print("    <config xmlns:nc=\"{s}\">\n", .{base_ns});
                    try writeFragment(w, body, 6);
                    try w.writeAll("    </config>\n");
                },
                .url => |u| {
                    try w.writeAll("    <url>");
                    try writeEscaped(w, u);
                    try w.writeAll("</url>\n");
                },
            }
            try w.writeAll("  </edit-config>\n");
        },
        .copy_config => |c| {
            try w.writeAll("  <copy-config>\n");
            try writeDatastore(w, "target", c.target, 4);
            try writeSource(w, c.source, 4);
            try w.writeAll("  </copy-config>\n");
        },
        .delete_config => |t| {
            try w.writeAll("  <delete-config>\n");
            try writeDatastore(w, "target", t, 4);
            try w.writeAll("  </delete-config>\n");
        },
        .lock => |t| {
            try w.writeAll("  <lock>\n");
            try writeDatastore(w, "target", t, 4);
            try w.writeAll("  </lock>\n");
        },
        .unlock => |t| {
            try w.writeAll("  <unlock>\n");
            try writeDatastore(w, "target", t, 4);
            try w.writeAll("  </unlock>\n");
        },
        .commit => |c| {
            if (!c.confirmed and c.confirm_timeout == null and c.persist == null and c.persist_id == null) {
                try w.writeAll("  <commit/>\n");
            } else {
                try w.writeAll("  <commit>\n");
                if (c.confirmed) try w.writeAll("    <confirmed/>\n");
                if (c.confirm_timeout) |t| try w.print("    <confirm-timeout>{d}</confirm-timeout>\n", .{t});
                if (c.persist) |p| {
                    try w.writeAll("    <persist>");
                    try writeEscaped(w, p);
                    try w.writeAll("</persist>\n");
                }
                if (c.persist_id) |p| {
                    try w.writeAll("    <persist-id>");
                    try writeEscaped(w, p);
                    try w.writeAll("</persist-id>\n");
                }
                try w.writeAll("  </commit>\n");
            }
        },
        .discard_changes => try w.writeAll("  <discard-changes/>\n"),
        .validate => |s| {
            try w.writeAll("  <validate>\n");
            try writeSource(w, s, 4);
            try w.writeAll("  </validate>\n");
        },
        .close_session => try w.writeAll("  <close-session/>\n"),
        .kill_session => |sid| {
            try w.writeAll("  <kill-session>\n");
            try w.print("    <session-id>{d}</session-id>\n", .{sid});
            try w.writeAll("  </kill-session>\n");
        },
        .create_subscription => |s| {
            try w.print("  <create-subscription xmlns=\"{s}\">\n", .{notification_ns});
            if (s.stream) |st| {
                try w.writeAll("    <stream>");
                try writeEscaped(w, st);
                try w.writeAll("</stream>\n");
            }
            try writeFilter(w, s.filter, 4);
            if (s.start_time) |t| {
                try w.writeAll("    <startTime>");
                try writeEscaped(w, t);
                try w.writeAll("</startTime>\n");
            }
            if (s.stop_time) |t| {
                try w.writeAll("    <stopTime>");
                try writeEscaped(w, t);
                try w.writeAll("</stopTime>\n");
            }
            try w.writeAll("  </create-subscription>\n");
        },
        .raw => |body| try writeFragment(w, body, 2),
    }
    try w.writeAll("</rpc>\n");
}

/// `writeRpc` into a freshly allocated buffer.
pub fn buildRpc(gpa: std.mem.Allocator, message_id: u64, rpc: Rpc) std.mem.Allocator.Error![]u8 {
    var aw: std.Io.Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    writeRpc(&aw.writer, message_id, rpc) catch return error.OutOfMemory;
    return aw.toOwnedSlice();
}

// ── pieces ─────────────────────────────────────────────────────────────────

fn indent(w: *std.Io.Writer, n: usize) BuildError!void {
    try w.splatByteAll(' ', n);
}

fn writeDatastore(w: *std.Io.Writer, wrapper: []const u8, d: Datastore, ind: usize) BuildError!void {
    try indent(w, ind);
    try w.print("<{s}>\n", .{wrapper});
    switch (d) {
        .running, .candidate, .startup => {
            try indent(w, ind + 2);
            try w.print("<{s}/>\n", .{@tagName(d)});
        },
        .url => |u| {
            try indent(w, ind + 2);
            try w.writeAll("<url>");
            try writeEscaped(w, u);
            try w.writeAll("</url>\n");
        },
    }
    try indent(w, ind);
    try w.print("</{s}>\n", .{wrapper});
}

fn writeSource(w: *std.Io.Writer, s: ConfigSource, ind: usize) BuildError!void {
    try indent(w, ind);
    try w.writeAll("<source>\n");
    switch (s) {
        .running, .candidate, .startup => {
            try indent(w, ind + 2);
            try w.print("<{s}/>\n", .{@tagName(s)});
        },
        .url => |u| {
            try indent(w, ind + 2);
            try w.writeAll("<url>");
            try writeEscaped(w, u);
            try w.writeAll("</url>\n");
        },
        .config => |body| {
            try indent(w, ind + 2);
            try w.writeAll("<config>\n");
            try writeFragment(w, body, ind + 4);
            try indent(w, ind + 2);
            try w.writeAll("</config>\n");
        },
    }
    try indent(w, ind);
    try w.writeAll("</source>\n");
}

fn writeFilter(w: *std.Io.Writer, f: Filter, ind: usize) BuildError!void {
    switch (f) {
        .none => {},
        .subtree => |body| {
            try indent(w, ind);
            try w.writeAll("<filter type=\"subtree\">\n");
            try writeFragment(w, body, ind + 2);
            try indent(w, ind);
            try w.writeAll("</filter>\n");
        },
        .xpath => |x| {
            try indent(w, ind);
            try w.writeAll("<filter type=\"xpath\"");
            if (x.ns.len != 0) {
                try w.writeByte(' ');
                try w.writeAll(x.ns);
            }
            try w.writeAll(" select=\"");
            try writeEscapedAttr(w, x.select);
            try w.writeAll("\"/>\n");
        },
    }
}

/// Emit a caller-supplied XML fragment at `ind`, re-indenting each line so the
/// result stays readable. Blank lines stay blank; the fragment's own relative
/// indentation is preserved.
fn writeFragment(w: *std.Io.Writer, fragment: []const u8, ind: usize) BuildError!void {
    const trimmed = std.mem.trim(u8, fragment, "\r\n");
    if (trimmed.len == 0) return;
    var it = std.mem.splitScalar(u8, trimmed, '\n');
    while (it.next()) |line_raw| {
        const line = std.mem.trimEnd(u8, line_raw, "\r");
        if (std.mem.trim(u8, line, " \t").len == 0) {
            try w.writeByte('\n');
            continue;
        }
        try indent(w, ind);
        try w.writeAll(line);
        try w.writeByte('\n');
    }
}

/// XML character-data escaping. `>` is escaped too: it is only *required*
/// inside `]]>`, but escaping it unconditionally means a value can never
/// contribute to the `]]>]]>` framing delimiter.
pub fn writeEscaped(w: *std.Io.Writer, text: []const u8) BuildError!void {
    for (text) |c| switch (c) {
        '&' => try w.writeAll("&amp;"),
        '<' => try w.writeAll("&lt;"),
        '>' => try w.writeAll("&gt;"),
        else => try w.writeByte(c),
    };
}

/// Attribute-value escaping: character data plus the quote characters.
pub fn writeEscapedAttr(w: *std.Io.Writer, text: []const u8) BuildError!void {
    for (text) |c| switch (c) {
        '&' => try w.writeAll("&amp;"),
        '<' => try w.writeAll("&lt;"),
        '>' => try w.writeAll("&gt;"),
        '"' => try w.writeAll("&quot;"),
        '\'' => try w.writeAll("&apos;"),
        else => try w.writeByte(c),
    };
}

// ── tests ──────────────────────────────────────────────────────────────────
//
// Two kinds of check run over every builder:
//
//  * a byte-exact golden of OUR canonical output (a regression fence), and
//  * a structural comparison against the RFC's own literal example text
//    (`expectSameStructure`), which is the correctness claim: our request must
//    be the same XML infoset as the RFC's, modulo insignificant whitespace and
//    line layout.

fn build(gpa: std.mem.Allocator, id: u64, r: Rpc) ![]u8 {
    return buildRpc(gpa, id, r);
}

/// Compare two XML documents for infoset equality of the parts NETCONF cares
/// about: element name + namespace + attributes + child element order +
/// non-whitespace text.
fn expectSameStructure(a_src: []const u8, b_src: []const u8) !void {
    const gpa = testing.allocator;
    var a = try xml.parse(gpa, a_src, .{ .doctype = .reject });
    defer a.deinit();
    var b = try xml.parse(gpa, b_src, .{ .doctype = .reject });
    defer b.deinit();
    elementsEqual(a.root, b.root) catch |e| {
        std.debug.print("\n--- built ---\n{s}\n--- expected (RFC) ---\n{s}\n", .{ a_src, b_src });
        return e;
    };
}

fn elementsEqual(a: *const xml.Element, b: *const xml.Element) !void {
    try testing.expectEqualStrings(b.local, a.local);
    try testing.expectEqualStrings(b.uri, a.uri);

    // Attributes as a set (order is insignificant in XML).
    var a_attrs: usize = 0;
    for (a.attributes) |at| {
        a_attrs += 1;
        const other = b.attr(at.uri, at.local) orelse {
            std.debug.print("missing attribute {s}:{s} on <{s}>\n", .{ at.uri, at.local, a.local });
            return error.TestExpectedEqual;
        };
        try testing.expectEqualStrings(other, at.value);
    }
    try testing.expectEqual(b.attributes.len, a_attrs);

    // Non-whitespace text content, collapsed.
    const gpa = testing.allocator;
    const at = try a.textContent(gpa);
    defer gpa.free(at);
    const bt = try b.textContent(gpa);
    defer gpa.free(bt);
    try testing.expectEqualStrings(collapse(bt), collapse(at));

    var ai = a.elementIterator();
    var bi = b.elementIterator();
    while (true) {
        const ac = ai.next();
        const bc = bi.next();
        if (ac == null and bc == null) return;
        if (ac == null or bc == null) return error.TestExpectedEqual;
        try elementsEqual(ac.?, bc.?);
    }
}

/// Collapse runs of whitespace and trim — the comparison used for text nodes,
/// which in NETCONF are always tokens (names, numbers, URIs), never
/// whitespace-significant prose.
fn collapse(s: []const u8) []const u8 {
    // Operates in place on a static scratch buffer; only used by tests.
    const S = struct {
        var buf: [64 * 1024]u8 = undefined;
    };
    var n: usize = 0;
    var last_space = true;
    for (s) |c| {
        const is_space = c == ' ' or c == '\t' or c == '\r' or c == '\n';
        if (is_space) {
            if (!last_space and n < S.buf.len) {
                S.buf[n] = ' ';
                n += 1;
            }
            last_space = true;
        } else {
            if (n < S.buf.len) {
                S.buf[n] = c;
                n += 1;
            }
            last_space = false;
        }
    }
    return std.mem.trimEnd(u8, S.buf[0..n], " ");
}

// ── RFC 6241 literal examples, used as the correctness oracle ──────────────

/// RFC 6241 §7.1 — "To retrieve the entire <users> subtree".
const rfc_7_1_get_config =
    \\<rpc message-id="101"
    \\     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    \\  <get-config>
    \\    <source>
    \\      <running/>
    \\    </source>
    \\    <filter type="subtree">
    \\      <top xmlns="http://example.com/schema/1.2/config">
    \\        <users/>
    \\      </top>
    \\    </filter>
    \\  </get-config>
    \\</rpc>
;

/// RFC 6241 §7.2 — set the MTU to 1500 on interface Ethernet0/0.
const rfc_7_2_edit_config =
    \\<rpc message-id="101"
    \\     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    \\  <edit-config>
    \\    <target>
    \\      <running/>
    \\    </target>
    \\    <config>
    \\      <top xmlns="http://example.com/schema/1.2/config">
    \\        <interface>
    \\          <name>Ethernet0/0</name>
    \\          <mtu>1500</mtu>
    \\        </interface>
    \\      </top>
    \\    </config>
    \\  </edit-config>
    \\</rpc>
;

/// RFC 6241 §7.3 — copy a configuration from a URL into <running>.
const rfc_7_3_copy_config =
    \\<rpc message-id="101"
    \\     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    \\  <copy-config>
    \\    <target>
    \\      <running/>
    \\    </target>
    \\    <source>
    \\      <url>https://user:password@example.com/cfg/new.txt</url>
    \\    </source>
    \\  </copy-config>
    \\</rpc>
;

/// RFC 6241 §7.4 — delete the <startup> datastore.
const rfc_7_4_delete_config =
    \\<rpc message-id="101"
    \\     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    \\  <delete-config>
    \\    <target>
    \\      <startup/>
    \\    </target>
    \\  </delete-config>
    \\</rpc>
;

/// RFC 6241 §7.5 — lock <running>.
const rfc_7_5_lock =
    \\<rpc message-id="101"
    \\     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    \\  <lock>
    \\    <target>
    \\      <running/>
    \\    </target>
    \\  </lock>
    \\</rpc>
;

/// RFC 6241 §7.7 — get with a subtree filter over operational state.
const rfc_7_7_get =
    \\<rpc message-id="101"
    \\     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    \\  <get>
    \\    <filter type="subtree">
    \\      <top xmlns="http://example.com/schema/1.2/stats">
    \\        <interfaces>
    \\          <interface>
    \\            <ifName>eth0</ifName>
    \\          </interface>
    \\        </interfaces>
    \\      </top>
    \\    </filter>
    \\  </get>
    \\</rpc>
;

/// RFC 6241 §7.8 — close-session.
const rfc_7_8_close_session =
    \\<rpc message-id="101"
    \\     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    \\  <close-session/>
    \\</rpc>
;

/// RFC 6241 §7.9 — kill session 4.
const rfc_7_9_kill_session =
    \\<rpc message-id="101"
    \\     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    \\  <kill-session>
    \\    <session-id>4</session-id>
    \\  </kill-session>
    \\</rpc>
;

/// RFC 6241 §8.3.4.1 — plain commit.
const rfc_8_3_4_1_commit =
    \\<rpc message-id="101"
    \\     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    \\  <commit/>
    \\</rpc>
;

/// RFC 6241 §8.3.4.2 — discard-changes.
const rfc_8_3_4_2_discard =
    \\<rpc message-id="101"
    \\     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    \\  <discard-changes/>
    \\</rpc>
;

/// RFC 6241 §8.4.5.1 — confirmed commit with a 120 s timeout.
const rfc_8_4_5_1_confirmed_commit =
    \\<rpc message-id="101"
    \\     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    \\  <commit>
    \\    <confirmed/>
    \\    <confirm-timeout>120</confirm-timeout>
    \\  </commit>
    \\</rpc>
;

/// RFC 6241 §8.6.4.1 — validate the <candidate> datastore.
const rfc_8_6_4_1_validate =
    \\<rpc message-id="101"
    \\     xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    \\  <validate>
    \\    <source>
    \\      <candidate/>
    \\    </source>
    \\  </validate>
    \\</rpc>
;

/// RFC 5277 §2.1.1.1 — the simplest subscription. (The RFC writes the envelope
/// with a `netconf:` prefix; the infoset is identical to ours.)
const rfc5277_create_subscription =
    \\<netconf:rpc message-id="101"
    \\      xmlns:netconf="urn:ietf:params:xml:ns:netconf:base:1.0">
    \\    <create-subscription
    \\        xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
    \\    </create-subscription>
    \\</netconf:rpc>
;

test "get-config matches RFC 6241 §7.1 (structure) and its own golden (bytes)" {
    const gpa = testing.allocator;
    const got = try build(gpa, 101, .{ .get_config = .{
        .source = .running,
        .filter = .{ .subtree =
        \\<top xmlns="http://example.com/schema/1.2/config">
        \\  <users/>
        \\</top>
        },
    } });
    defer gpa.free(got);

    try expectSameStructure(got, rfc_7_1_get_config);
    try testing.expectEqualStrings(
        \\<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        \\  <get-config>
        \\    <source>
        \\      <running/>
        \\    </source>
        \\    <filter type="subtree">
        \\      <top xmlns="http://example.com/schema/1.2/config">
        \\        <users/>
        \\      </top>
        \\    </filter>
        \\  </get-config>
        \\</rpc>
        \\
    , got);
}

test "edit-config matches RFC 6241 §7.2" {
    const gpa = testing.allocator;
    const got = try build(gpa, 101, .{ .edit_config = .{
        .target = .running,
        .payload = .{ .config =
        \\<top xmlns="http://example.com/schema/1.2/config">
        \\  <interface>
        \\    <name>Ethernet0/0</name>
        \\    <mtu>1500</mtu>
        \\  </interface>
        \\</top>
        },
    } });
    defer gpa.free(got);
    // Our <config> additionally binds the `nc` prefix so callers can use
    // Operation.attribute(); a namespace declaration is not part of the
    // infoset comparison below, and adds no element or attribute.
    try expectSameStructure(got, rfc_7_2_edit_config);
}

test "edit-config carries default-operation / test-option / error-option and the operation attribute" {
    const gpa = testing.allocator;
    const body = try std.fmt.allocPrint(gpa,
        \\<top xmlns="http://example.com/schema/1.2/config">
        \\  <interface{s}>
        \\    <name>Ethernet0/0</name>
        \\  </interface>
        \\</top>
    , .{Operation.delete.attribute()});
    defer gpa.free(body);

    const got = try build(gpa, 42, .{ .edit_config = .{
        .target = .candidate,
        .payload = .{ .config = body },
        .default_operation = .none,
        .test_option = .test_then_set,
        .error_option = .rollback_on_error,
    } });
    defer gpa.free(got);

    try testing.expectEqualStrings(
        \\<rpc message-id="42" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        \\  <edit-config>
        \\    <target>
        \\      <candidate/>
        \\    </target>
        \\    <default-operation>none</default-operation>
        \\    <test-option>test-then-set</test-option>
        \\    <error-option>rollback-on-error</error-option>
        \\    <config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
        \\      <top xmlns="http://example.com/schema/1.2/config">
        \\        <interface nc:operation="delete">
        \\          <name>Ethernet0/0</name>
        \\        </interface>
        \\      </top>
        \\    </config>
        \\  </edit-config>
        \\</rpc>
        \\
    , got);

    // And the operation attribute really resolves to the base namespace.
    var doc = try xml.parse(gpa, got, .{ .doctype = .reject });
    defer doc.deinit();
    const iface = doc.findByAttr(base_ns, "operation", "delete") orelse return error.TestExpectedEqual;
    try testing.expectEqualStrings("interface", iface.local);
}

test "copy-config matches RFC 6241 §7.3 (url source)" {
    const gpa = testing.allocator;
    const got = try build(gpa, 101, .{ .copy_config = .{
        .target = .running,
        .source = .{ .url = "https://user:password@example.com/cfg/new.txt" },
    } });
    defer gpa.free(got);
    try expectSameStructure(got, rfc_7_3_copy_config);
}

test "delete-config / lock / unlock match RFC 6241 §7.4–§7.6" {
    const gpa = testing.allocator;
    {
        const got = try build(gpa, 101, .{ .delete_config = .startup });
        defer gpa.free(got);
        try expectSameStructure(got, rfc_7_4_delete_config);
    }
    {
        const got = try build(gpa, 101, .{ .lock = .running });
        defer gpa.free(got);
        try expectSameStructure(got, rfc_7_5_lock);
    }
    {
        // §7.6 <unlock> is §7.5 with the element renamed.
        const got = try build(gpa, 101, .{ .unlock = .running });
        defer gpa.free(got);
        const unlock_rfc = try std.mem.replaceOwned(u8, gpa, rfc_7_5_lock, "lock>", "unlock>");
        defer gpa.free(unlock_rfc);
        try expectSameStructure(got, unlock_rfc);
    }
}

test "get matches RFC 6241 §7.7" {
    const gpa = testing.allocator;
    const got = try build(gpa, 101, .{ .get = .{ .filter = .{ .subtree =
        \\<top xmlns="http://example.com/schema/1.2/stats">
        \\  <interfaces>
        \\    <interface>
        \\      <ifName>eth0</ifName>
        \\    </interface>
        \\  </interfaces>
        \\</top>
    } } });
    defer gpa.free(got);
    try expectSameStructure(got, rfc_7_7_get);
}

test "close-session / kill-session match RFC 6241 §7.8–§7.9" {
    const gpa = testing.allocator;
    {
        const got = try build(gpa, 101, .close_session);
        defer gpa.free(got);
        try expectSameStructure(got, rfc_7_8_close_session);
    }
    {
        const got = try build(gpa, 101, .{ .kill_session = 4 });
        defer gpa.free(got);
        try expectSameStructure(got, rfc_7_9_kill_session);
    }
}

test "commit / discard-changes / confirmed-commit / validate match RFC 6241 §8" {
    const gpa = testing.allocator;
    {
        const got = try build(gpa, 101, .{ .commit = .{} });
        defer gpa.free(got);
        try expectSameStructure(got, rfc_8_3_4_1_commit);
    }
    {
        const got = try build(gpa, 101, .discard_changes);
        defer gpa.free(got);
        try expectSameStructure(got, rfc_8_3_4_2_discard);
    }
    {
        const got = try build(gpa, 101, .{ .commit = .{ .confirmed = true, .confirm_timeout = 120 } });
        defer gpa.free(got);
        try expectSameStructure(got, rfc_8_4_5_1_confirmed_commit);
    }
    {
        const got = try build(gpa, 101, .{ .validate = .candidate });
        defer gpa.free(got);
        try expectSameStructure(got, rfc_8_6_4_1_validate);
    }
}

test "create-subscription matches RFC 5277 §2.1.1.1" {
    const gpa = testing.allocator;
    const got = try build(gpa, 101, .{ .create_subscription = .{} });
    defer gpa.free(got);
    try expectSameStructure(got, rfc5277_create_subscription);
}

test "create-subscription with stream, filter and replay window" {
    const gpa = testing.allocator;
    const got = try build(gpa, 7, .{ .create_subscription = .{
        .stream = "NETCONF",
        .filter = .{ .subtree = "<event xmlns=\"http://example.com/events\"/>" },
        .start_time = "2026-07-22T10:00:00Z",
        .stop_time = "2026-07-22T11:00:00Z",
    } });
    defer gpa.free(got);
    try testing.expectEqualStrings(
        \\<rpc message-id="7" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        \\  <create-subscription xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
        \\    <stream>NETCONF</stream>
        \\    <filter type="subtree">
        \\      <event xmlns="http://example.com/events"/>
        \\    </filter>
        \\    <startTime>2026-07-22T10:00:00Z</startTime>
        \\    <stopTime>2026-07-22T11:00:00Z</stopTime>
        \\  </create-subscription>
        \\</rpc>
        \\
    , got);
}

test "xpath filter and url datastores serialise with escaping" {
    const gpa = testing.allocator;
    const got = try build(gpa, 3, .{ .get_config = .{
        .source = .{ .url = "file:///cfg/a&b.xml" },
        .filter = .{ .xpath = .{
            .ns = "xmlns:t=\"http://example.com/schema/1.2/config\"",
            .select = "/t:top/t:users[t:name='fred' and 1 < 2]",
        } },
    } });
    defer gpa.free(got);
    try testing.expectEqualStrings(
        \\<rpc message-id="3" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        \\  <get-config>
        \\    <source>
        \\      <url>file:///cfg/a&amp;b.xml</url>
        \\    </source>
        \\    <filter type="xpath" xmlns:t="http://example.com/schema/1.2/config" select="/t:top/t:users[t:name=&apos;fred&apos; and 1 &lt; 2]"/>
        \\  </get-config>
        \\</rpc>
        \\
    , got);
    // And it is still well-formed XML with the select attribute intact.
    var doc = try xml.parse(gpa, got, .{ .doctype = .reject });
    defer doc.deinit();
    const filter = doc.root.firstElementChild().?.elementIterator();
    var it = filter;
    _ = it.next(); // <source>
    const f = it.next().?;
    try testing.expectEqualStrings("/t:top/t:users[t:name='fred' and 1 < 2]", f.attr("", "select").?);
}

test "raw escape hatch keeps the correlated envelope" {
    const gpa = testing.allocator;
    const got = try build(gpa, 99, .{ .raw =
        \\<get-schema xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">
        \\  <identifier>ietf-interfaces</identifier>
        \\</get-schema>
    });
    defer gpa.free(got);
    try testing.expectEqualStrings(
        \\<rpc message-id="99" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        \\  <get-schema xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">
        \\    <identifier>ietf-interfaces</identifier>
        \\  </get-schema>
        \\</rpc>
        \\
    , got);
}

test "every builder emits well-formed XML with the right envelope" {
    const gpa = testing.allocator;
    const all = [_]Rpc{
        .{ .get = .{} },
        .{ .get = .{ .filter = .{ .subtree = "<a/>" } } },
        .{ .get_config = .{} },
        .{ .get_config = .{ .source = .candidate } },
        .{ .get_config = .{ .source = .startup } },
        .{ .edit_config = .{ .target = .running, .payload = .{ .config = "<a/>" } } },
        .{ .edit_config = .{ .target = .candidate, .payload = .{ .url = "file:///x" } } },
        .{ .copy_config = .{ .target = .startup, .source = .running } },
        .{ .copy_config = .{ .target = .{ .url = "file:///y" }, .source = .{ .config = "<a/>" } } },
        .{ .delete_config = .startup },
        .{ .lock = .candidate },
        .{ .unlock = .candidate },
        .{ .commit = .{} },
        .{ .commit = .{ .confirmed = true, .confirm_timeout = 60, .persist = "id-1" } },
        .{ .commit = .{ .persist_id = "id-1" } },
        .discard_changes,
        .{ .validate = .{ .config = "<a/>" } },
        .close_session,
        .{ .kill_session = 4 },
        .{ .create_subscription = .{} },
        .{ .raw = "<my-op xmlns=\"urn:x\"/>" },
    };
    for (all, 0..) |r, i| {
        const got = try build(gpa, i + 1, r);
        defer gpa.free(got);
        var doc = try xml.parse(gpa, got, .{ .doctype = .reject });
        defer doc.deinit();
        try testing.expectEqualStrings("rpc", doc.root.local);
        try testing.expectEqualStrings(base_ns, doc.root.uri);
        const id = doc.root.attr("", "message-id").?;
        var buf: [24]u8 = undefined;
        try testing.expectEqualStrings(try std.fmt.bufPrint(&buf, "{d}", .{i + 1}), id);
    }
}

test "escaping: a value can never forge the end-of-message delimiter" {
    const gpa = testing.allocator;
    const got = try build(gpa, 1, .{ .copy_config = .{
        .target = .running,
        .source = .{ .url = "file:///x]]>]]>y" },
    } });
    defer gpa.free(got);
    try testing.expect(std.mem.indexOf(u8, got, "]]>]]>") == null);
    try testing.expect(std.mem.indexOf(u8, got, "]]&gt;]]&gt;") != null);
}
