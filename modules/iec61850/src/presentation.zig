// SPDX-License-Identifier: MIT

//! The ISO 8823 **presentation layer** — the CP / CPA PPDUs and, above all,
//! the **presentation context definition list**.
//!
//! This is the layer implementations get wrong. The context list is a
//! negotiation: the initiator proposes `{context id, abstract syntax OID,
//! transfer syntaxes}` triples (IEC 61850 proposes exactly two — ACSE as
//! context 1 and MMS as context 3), and the responder answers with a
//! *positionally matched* result list. Everything afterwards refers to a
//! context **by id only**, so:
//!
//! * a data PPDU naming an id that was never defined must be a typed error, not
//!   a silently mis-dispatched PDU — that is `error.UndefinedContext`, and it
//!   is why `ContextTable` exists as connection state rather than the ids being
//!   hard-coded to 1 and 3;
//! * the result list is matched **by position**, so a responder that returns a
//!   different number of results than there were proposals is refused rather
//!   than zipped short;
//! * a context the responder rejected must not then be used, which
//!   `ContextTable.lookup` enforces by returning the acceptance flag.
//!
//! `User-data` is `fully-encoded-data` `[APPLICATION 1]`: a sequence of
//! PDV-lists, each naming its context id and carrying one `single-ASN1-type`
//! value. After the association is up, a presentation PDU is *only* that — no
//! CP wrapper — which is why `decodeUserData` is a separate entry point.

const std = @import("std");
const ber = @import("ber.zig");

pub const Error = ber.Error || error{
    /// A PDV names a presentation context that was never defined.
    UndefinedContext,
    /// A PDV names a context the responder rejected.
    RejectedContext,
    /// The result list has a different number of entries than the proposal.
    ContextResultMismatch,
    /// More contexts than the fixed table holds.
    TooManyContexts,
    /// A required field is absent.
    MissingField,
    /// The mode-selector is not normal mode.
    UnsupportedMode,
};

/// The context ids IEC 61850-8-1 uses. They are conventional, not mandatory —
/// nothing here assumes them.
pub const context_acse: u16 = 1;
pub const context_mms: u16 = 3;

/// Presentation-context-definition-result values (ISO 8823 `Result`).
pub const Result = enum(u8) {
    acceptance = 0,
    user_rejection = 1,
    provider_rejection = 2,
    _,
};

pub const max_contexts: usize = 8;
const max_syntax_len: usize = 16;

pub const ContextDefinition = struct {
    id: u16,
    /// Abstract syntax OID, wire form.
    abstract_syntax: []const u8,
    /// The first proposed transfer syntax OID, wire form.
    transfer_syntax: []const u8,
};

/// The connection's negotiated context state. Fixed size, no allocation: a peer
/// proposing a thousand contexts gets `error.TooManyContexts`, not a heap.
pub const ContextTable = struct {
    ids: [max_contexts]u16 = @splat(0),
    syntax: [max_contexts][max_syntax_len]u8 = @splat(@splat(0)),
    syntax_len: [max_contexts]u8 = @splat(0),
    accepted: [max_contexts]bool = @splat(false),
    len: u8 = 0,

    pub fn define(self: *ContextTable, id: u16, abstract_syntax: []const u8) Error!void {
        if (self.len >= max_contexts) return error.TooManyContexts;
        if (abstract_syntax.len > max_syntax_len) return error.TooManyContexts;
        const i = self.len;
        self.ids[i] = id;
        @memcpy(self.syntax[i][0..abstract_syntax.len], abstract_syntax);
        self.syntax_len[i] = @intCast(abstract_syntax.len);
        // A context is provisional until a result list accepts it; the
        // initiator marks its own proposals accepted so it can send on them
        // once the CPA arrives.
        self.accepted[i] = false;
        self.len += 1;
    }

    pub fn index(self: *const ContextTable, id: u16) ?usize {
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            if (self.ids[i] == id) return i;
        }
        return null;
    }

    pub fn abstractSyntax(self: *const ContextTable, id: u16) ?[]const u8 {
        const i = self.index(id) orelse return null;
        return self.syntax[i][0..self.syntax_len[i]];
    }

    /// The id whose abstract syntax matches, if it was accepted.
    pub fn idFor(self: *const ContextTable, abstract_syntax: []const u8) ?u16 {
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            if (!self.accepted[i]) continue;
            if (std.mem.eql(u8, self.syntax[i][0..self.syntax_len[i]], abstract_syntax)) return self.ids[i];
        }
        return null;
    }

    /// Checks a context id arriving on a PDV. Refuses an undefined id and a
    /// rejected one separately, because they are different bugs.
    pub fn check(self: *const ContextTable, id: u16) Error!usize {
        const i = self.index(id) orelse return error.UndefinedContext;
        if (!self.accepted[i]) return error.RejectedContext;
        return i;
    }

    pub fn acceptAll(self: *ContextTable) void {
        var i: usize = 0;
        while (i < self.len) : (i += 1) self.accepted[i] = true;
    }

    /// Applies a CPA's result list, matched **by position** against what was
    /// proposed.
    pub fn applyResults(self: *ContextTable, results: []const Result) Error!void {
        if (results.len != self.len) return error.ContextResultMismatch;
        for (results, 0..) |r, i| self.accepted[i] = (r == .acceptance);
    }
};

// ── CP / CPA ────────────────────────────────────────────────────────────────

pub const Cp = struct {
    calling_selector: ?[]const u8 = null,
    called_selector: ?[]const u8 = null,
    responding_selector: ?[]const u8 = null,
    contexts: [max_contexts]ContextDefinition = undefined,
    context_count: u8 = 0,
    /// Result list from a CPA, positionally matched to the proposal.
    results: [max_contexts]Result = @splat(.acceptance),
    result_count: u8 = 0,
    /// The `fully-encoded-data` body — feed to `PdvIterator`.
    user_data: []const u8 = &.{},

    pub fn definitions(self: *const Cp) []const ContextDefinition {
        return self.contexts[0..self.context_count];
    }
    pub fn resultList(self: *const Cp) []const Result {
        return self.results[0..self.result_count];
    }
};

const tag_mode_selector = ber.Tag.ctxc(0);
const tag_normal_mode = ber.Tag.ctxc(2);
const tag_calling_selector = ber.Tag.ctx(1);
const tag_called_selector = ber.Tag.ctx(2);
const tag_responding_selector = ber.Tag.ctx(3);
const tag_context_list = ber.Tag.ctxc(4);
const tag_context_result_list = ber.Tag.ctxc(5);
/// `fully-encoded-data`.
pub const tag_user_data = ber.Tag.appc(1);

/// Decodes a CP-type or CPA-type PPDU (they share a shape; the fields present
/// differ).
pub fn decodeCp(bytes: []const u8) Error!Cp {
    const outer = try ber.expect(bytes, ber.Tag.set);
    var cp = Cp{};
    var it = ber.Iterator.init(outer.content);
    var saw_normal = false;
    while (try it.next()) |e| {
        if (e.tag.eql(tag_mode_selector)) {
            var m = ber.Iterator.init(e.content);
            const v = try m.expect(ber.Tag.ctx(0));
            if (try ber.decodeUint(u8, v.content) != 1) return error.UnsupportedMode;
        } else if (e.tag.eql(tag_normal_mode)) {
            saw_normal = true;
            try decodeNormalMode(e.content, &cp);
        }
    }
    if (!saw_normal) return error.MissingField;
    return cp;
}

fn decodeNormalMode(bytes: []const u8, cp: *Cp) Error!void {
    var it = ber.Iterator.init(bytes);
    while (try it.next()) |e| {
        if (e.tag.eql(tag_calling_selector)) {
            cp.calling_selector = e.content;
        } else if (e.tag.eql(tag_called_selector)) {
            cp.called_selector = e.content;
        } else if (e.tag.eql(tag_responding_selector)) {
            cp.responding_selector = e.content;
        } else if (e.tag.eql(tag_context_list)) {
            var list = ber.Iterator.init(e.content);
            while (try list.next()) |entry| {
                if (!entry.tag.eql(ber.Tag.sequence)) return error.UnexpectedTag;
                if (cp.context_count >= max_contexts) return error.TooManyContexts;
                var f = ber.Iterator.init(entry.content);
                const id = try f.expect(ber.Tag.uni(ber.Universal.integer));
                const as = try f.expect(ber.Tag.uni(ber.Universal.object_identifier));
                const ts_list = try f.expect(ber.Tag.sequence);
                const first_ts = try ber.expect(ts_list.content, ber.Tag.uni(ber.Universal.object_identifier));
                cp.contexts[cp.context_count] = .{
                    .id = try ber.decodeUint(u16, id.content),
                    .abstract_syntax = as.content,
                    .transfer_syntax = first_ts.content,
                };
                cp.context_count += 1;
            }
        } else if (e.tag.eql(tag_context_result_list)) {
            var list = ber.Iterator.init(e.content);
            while (try list.next()) |entry| {
                if (!entry.tag.eql(ber.Tag.sequence)) return error.UnexpectedTag;
                if (cp.result_count >= max_contexts) return error.TooManyContexts;
                var f = ber.Iterator.init(entry.content);
                const r = try f.expect(ber.Tag.ctx(0));
                cp.results[cp.result_count] = @enumFromInt(try ber.decodeUint(u8, r.content));
                cp.result_count += 1;
            }
        } else if (e.tag.eql(tag_user_data)) {
            cp.user_data = e.content;
        }
    }
}

pub const CpOptions = struct {
    calling_selector: []const u8 = &[_]u8{ 0x00, 0x00, 0x00, 0x01 },
    called_selector: []const u8 = &[_]u8{ 0x00, 0x00, 0x00, 0x01 },
    contexts: []const ContextDefinition = &default_contexts,
};

/// The two contexts every IEC 61850 association proposes.
pub const default_contexts = [_]ContextDefinition{
    .{ .id = context_acse, .abstract_syntax = &ber.oids.acse_abstract_syntax, .transfer_syntax = &ber.oids.ber_transfer_syntax },
    .{ .id = context_mms, .abstract_syntax = &ber.oids.mms_abstract_syntax, .transfer_syntax = &ber.oids.ber_transfer_syntax },
};

/// Builds a CP-type PPDU around a `fully-encoded-data` body.
pub fn encodeCp(user_data: []const u8, opts: CpOptions, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const outer = w.mark();
    try w.bytes(user_data);
    // Context list, written back to front so the list order comes out right.
    const list_mark = w.mark();
    var i: usize = opts.contexts.len;
    while (i > 0) {
        i -= 1;
        const c = opts.contexts[i];
        const entry = w.mark();
        const ts = w.mark();
        try w.oid(ber.Tag.uni(ber.Universal.object_identifier), .{ .bytes = c.transfer_syntax });
        try w.header(ber.Tag.sequence, ts);
        try w.oid(ber.Tag.uni(ber.Universal.object_identifier), .{ .bytes = c.abstract_syntax });
        try w.integer(ber.Tag.uni(ber.Universal.integer), c.id);
        try w.header(ber.Tag.sequence, entry);
    }
    try w.header(tag_context_list, list_mark);
    try w.primitive(tag_called_selector, opts.called_selector);
    try w.primitive(tag_calling_selector, opts.calling_selector);
    try w.header(tag_normal_mode, outer);
    const mode = w.mark();
    try w.integer(ber.Tag.ctx(0), 1);
    try w.header(tag_mode_selector, mode);
    try w.header(ber.Tag.set, outer);
    return w.done();
}

pub const CpaOptions = struct {
    responding_selector: []const u8 = &[_]u8{ 0x00, 0x00, 0x00, 0x01 },
    results: []const Result = &[_]Result{ .acceptance, .acceptance },
    transfer_syntax: []const u8 = &ber.oids.ber_transfer_syntax,
};

pub fn encodeCpa(user_data: []const u8, opts: CpaOptions, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const outer = w.mark();
    try w.bytes(user_data);
    const list_mark = w.mark();
    var i: usize = opts.results.len;
    while (i > 0) {
        i -= 1;
        const entry = w.mark();
        if (opts.results[i] == .acceptance) {
            try w.primitive(ber.Tag.ctx(1), opts.transfer_syntax);
        }
        try w.integer(ber.Tag.ctx(0), @intFromEnum(opts.results[i]));
        try w.header(ber.Tag.sequence, entry);
    }
    try w.header(tag_context_result_list, list_mark);
    try w.primitive(tag_responding_selector, opts.responding_selector);
    try w.header(tag_normal_mode, outer);
    const mode = w.mark();
    try w.integer(ber.Tag.ctx(0), 1);
    try w.header(tag_mode_selector, mode);
    try w.header(ber.Tag.set, outer);
    return w.done();
}

// ── user data (PDV lists) ───────────────────────────────────────────────────

pub const Pdv = struct {
    context_id: u16,
    /// The `single-ASN1-type` value: one complete BER element.
    value: []const u8,
};

/// Walks the PDV-lists inside a `fully-encoded-data` body.
pub const PdvIterator = struct {
    inner: ber.Iterator,

    pub fn init(user_data: []const u8) PdvIterator {
        return .{ .inner = ber.Iterator.init(user_data) };
    }

    pub fn next(self: *PdvIterator) Error!?Pdv {
        const e = (try self.inner.next()) orelse return null;
        if (!e.tag.eql(ber.Tag.sequence)) return error.UnexpectedTag;
        var f = ber.Iterator.init(e.content);
        var id: ?u16 = null;
        while (try f.next()) |m| {
            if (m.tag.eql(ber.Tag.uni(ber.Universal.integer))) {
                id = try ber.decodeUint(u16, m.content);
            } else if (m.tag.eql(ber.Tag.ctxc(0))) {
                // single-ASN1-type
                return .{ .context_id = id orelse return error.MissingField, .value = m.content };
            } else if (m.tag.eql(ber.Tag.ctx(1))) {
                // octet-aligned
                return .{ .context_id = id orelse return error.MissingField, .value = m.content };
            }
            // A transfer-syntax-name OID may precede the id; ignore it.
        }
        return error.MissingField;
    }
};

/// Reads a data-transfer PPDU: `fully-encoded-data` holding one PDV, whose
/// context id must be one the table accepted.
pub fn decodeUserData(bytes: []const u8, table: *const ContextTable) Error!Pdv {
    const ud = try ber.expect(bytes, tag_user_data);
    var it = PdvIterator.init(ud.content);
    const pdv = (try it.next()) orelse return error.MissingField;
    _ = try table.check(pdv.context_id);
    return pdv;
}

/// Wraps one BER value as a `fully-encoded-data` PPDU on `context_id`.
pub fn encodeUserData(context_id: u16, value: []const u8, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const outer = w.mark();
    const seq = w.mark();
    const sa = w.mark();
    try w.bytes(value);
    try w.header(ber.Tag.ctxc(0), sa);
    try w.integer(ber.Tag.uni(ber.Universal.integer), context_id);
    try w.header(ber.Tag.sequence, seq);
    try w.header(tag_user_data, outer);
    return w.done();
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// The presentation CP a real IEC 61850 client sent, with the ACSE payload
/// replaced by a two-octet stand-in so the test is about this layer only.
fn buildCaptureLikeCp(out: []u8) ![]const u8 {
    var ud: [64]u8 = undefined;
    const body = try encodeUserData(context_acse, &[_]u8{ 0x05, 0x00 }, &ud);
    return encodeCp(body, .{}, out);
}

test "the captured presentation context list round trips" {
    var out: [512]u8 = undefined;
    const built = try buildCaptureLikeCp(&out);
    const cp = try decodeCp(built);
    try testing.expectEqual(@as(u8, 2), cp.context_count);
    try testing.expectEqual(@as(u16, 1), cp.definitions()[0].id);
    try testing.expectEqualSlices(u8, &ber.oids.acse_abstract_syntax, cp.definitions()[0].abstract_syntax);
    try testing.expectEqual(@as(u16, 3), cp.definitions()[1].id);
    try testing.expectEqualSlices(u8, &ber.oids.mms_abstract_syntax, cp.definitions()[1].abstract_syntax);
    try testing.expectEqualSlices(u8, &ber.oids.ber_transfer_syntax, cp.definitions()[1].transfer_syntax);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x01 }, cp.calling_selector.?);
}

test "the exact context-list octets a real client emits" {
    // Taken verbatim out of captured traffic: two contexts, ACSE then MMS.
    const captured = [_]u8{
        0xA4, 0x23,
        0x30, 0x0F,
        0x02, 0x01,
        0x01, 0x06,
        0x04, 0x52,
        0x01, 0x00,
        0x01, 0x30,
        0x04, 0x06,
        0x02, 0x51,
        0x01, 0x30,
        0x10, 0x02,
        0x01, 0x03,
        0x06, 0x05,
        0x28, 0xCA,
        0x22, 0x02,
        0x01, 0x30,
        0x04, 0x06,
        0x02, 0x51,
        0x01,
    };
    var cp = Cp{};
    try decodeNormalMode(&captured, &cp);
    try testing.expectEqual(@as(u8, 2), cp.context_count);
    try testing.expectEqual(@as(u16, 1), cp.definitions()[0].id);
    try testing.expectEqual(@as(u16, 3), cp.definitions()[1].id);

    // And this module builds the identical octets.
    var out: [256]u8 = undefined;
    var w = ber.Writer.init(&out);
    const m = w.mark();
    var i: usize = default_contexts.len;
    while (i > 0) {
        i -= 1;
        const c = default_contexts[i];
        const entry = w.mark();
        const ts = w.mark();
        try w.oid(ber.Tag.uni(ber.Universal.object_identifier), .{ .bytes = c.transfer_syntax });
        try w.header(ber.Tag.sequence, ts);
        try w.oid(ber.Tag.uni(ber.Universal.object_identifier), .{ .bytes = c.abstract_syntax });
        try w.integer(ber.Tag.uni(ber.Universal.integer), c.id);
        try w.header(ber.Tag.sequence, entry);
    }
    try w.header(tag_context_list, m);
    try testing.expectEqualSlices(u8, &captured, w.done());
}

test "a CPA result list is matched by position" {
    var out: [256]u8 = undefined;
    var ud: [64]u8 = undefined;
    const body = try encodeUserData(context_acse, &[_]u8{ 0x05, 0x00 }, &ud);
    const cpa = try encodeCpa(body, .{}, &out);
    const decoded = try decodeCp(cpa);
    try testing.expectEqual(@as(u8, 2), decoded.result_count);
    try testing.expectEqual(Result.acceptance, decoded.resultList()[0]);

    var table = ContextTable{};
    try table.define(context_acse, &ber.oids.acse_abstract_syntax);
    try table.define(context_mms, &ber.oids.mms_abstract_syntax);
    try table.applyResults(decoded.resultList());
    try testing.expectEqual(@as(u16, context_mms), table.idFor(&ber.oids.mms_abstract_syntax).?);
}

test "the exact CPA result octets a real server emits" {
    const captured = [_]u8{
        0xA5, 0x12,
        0x30, 0x07,
        0x80, 0x01,
        0x00, 0x81,
        0x02, 0x51,
        0x01, 0x30,
        0x07, 0x80,
        0x01, 0x00,
        0x81, 0x02,
        0x51, 0x01,
    };
    var cp = Cp{};
    try decodeNormalMode(&captured, &cp);
    try testing.expectEqual(@as(u8, 2), cp.result_count);
    try testing.expectEqual(Result.acceptance, cp.resultList()[0]);
    try testing.expectEqual(Result.acceptance, cp.resultList()[1]);
}

test "a result list of the wrong length is refused rather than zipped short" {
    var table = ContextTable{};
    try table.define(context_acse, &ber.oids.acse_abstract_syntax);
    try table.define(context_mms, &ber.oids.mms_abstract_syntax);
    try testing.expectError(error.ContextResultMismatch, table.applyResults(&[_]Result{.acceptance}));
    try testing.expectError(
        error.ContextResultMismatch,
        table.applyResults(&[_]Result{ .acceptance, .acceptance, .acceptance }),
    );
}

test "a PDV naming an undefined context is a typed error" {
    var table = ContextTable{};
    try table.define(context_acse, &ber.oids.acse_abstract_syntax);
    try table.define(context_mms, &ber.oids.mms_abstract_syntax);
    table.acceptAll();

    var out: [64]u8 = undefined;
    const good = try encodeUserData(context_mms, &[_]u8{ 0xA0, 0x00 }, &out);
    const pdv = try decodeUserData(good, &table);
    try testing.expectEqual(@as(u16, 3), pdv.context_id);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xA0, 0x00 }, pdv.value);

    var out2: [64]u8 = undefined;
    const bad = try encodeUserData(99, &[_]u8{ 0xA0, 0x00 }, &out2);
    try testing.expectError(error.UndefinedContext, decodeUserData(bad, &table));
}

test "a PDV on a rejected context is refused separately from an undefined one" {
    var table = ContextTable{};
    try table.define(context_acse, &ber.oids.acse_abstract_syntax);
    try table.define(context_mms, &ber.oids.mms_abstract_syntax);
    try table.applyResults(&[_]Result{ .acceptance, .user_rejection });
    var out: [64]u8 = undefined;
    const pdu = try encodeUserData(context_mms, &[_]u8{ 0xA0, 0x00 }, &out);
    try testing.expectError(error.RejectedContext, decodeUserData(pdu, &table));
    // And a rejected context is not offered up by `idFor`.
    try testing.expect(table.idFor(&ber.oids.mms_abstract_syntax) == null);
    try testing.expectEqual(@as(u16, 1), table.idFor(&ber.oids.acse_abstract_syntax).?);
}

test "the context table refuses to grow without bound" {
    var table = ContextTable{};
    var i: usize = 0;
    while (i < max_contexts) : (i += 1) try table.define(@intCast(i + 1), &ber.oids.mms_abstract_syntax);
    try testing.expectError(error.TooManyContexts, table.define(99, &ber.oids.mms_abstract_syntax));
    // And an absurdly long abstract syntax OID.
    var t2 = ContextTable{};
    try testing.expectError(error.TooManyContexts, t2.define(1, &[_]u8{0} ** 32));
}

test "malformed CP PPDUs are typed errors" {
    try testing.expectError(error.UnexpectedTag, decodeCp(&[_]u8{ 0x30, 0x00 }));
    try testing.expectError(error.MissingField, decodeCp(&[_]u8{ 0x31, 0x00 }));
    // A mode-selector that is not normal mode.
    try testing.expectError(
        error.UnsupportedMode,
        decodeCp(&[_]u8{ 0x31, 0x05, 0xA0, 0x03, 0x80, 0x01, 0x02 }),
    );
    // A context-list entry that is not a SEQUENCE.
    try testing.expectError(
        error.UnexpectedTag,
        decodeCp(&[_]u8{ 0x31, 0x06, 0xA2, 0x04, 0xA4, 0x02, 0x05, 0x00 }),
    );
}

test "fuzz: presentation decode never panics" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = decodeCp(buf[0..len]) catch {};
    var table = ContextTable{};
    table.define(context_mms, &ber.oids.mms_abstract_syntax) catch return;
    table.acceptAll();
    _ = decodeUserData(buf[0..len], &table) catch {};
    var it = PdvIterator.init(buf[0..len]);
    var guard: usize = 0;
    while (true) {
        guard += 1;
        try testing.expect(guard <= buf.len + 1);
        const p = it.next() catch return;
        if (p == null) break;
    }
}
