// SPDX-License-Identifier: MIT

//! Tests added by the 2026-11-15 strict mutation re-audit: each one pins an arm,
//! boundary or omitted-field behaviour that the 2026-10-04 run (and the tests
//! then in the module) did not observe. See SPEC.md § Mutation (2026-11-15).

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const types = @import("types.zig");
const nl = @import("nl.zig");
const wire = @import("wire.zig");
const expr = @import("expr.zig");

const Expr = expr.Expr;
const JExpr = root.Expr;
const gpa = testing.allocator;

fn contains(hay: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, hay, needle) != null;
}

fn stringify(v: anytype) ![]u8 {
    return std.json.Stringify.valueAlloc(gpa, v, .{});
}

// ── JSON builder ────────────────────────────────────────────────────────────

test "JSON depth bound: the last allowed level serialises, the next is TooDeep" {
    var chain: [40]JExpr = undefined;
    chain[0] = root.num(1);
    for (1..chain.len) |i| chain[i] = .{ .jhash = .{ .mod = 1, .expr = &chain[i - 1] } };
    const mark: JExpr = .{ .meta = .mark };
    var first_bad: ?usize = null;
    for (0..chain.len) |k| {
        var rs = root.Ruleset.init(gpa);
        defer rs.deinit();
        try rs.addRule(.inet, "t", "c", &.{.{ .mangle = .{ .key = mark, .value = chain[k] } }});
        if (rs.toJson(gpa)) |j| gpa.free(j) else |e| {
            try testing.expectEqual(error.TooDeep, e);
            first_bad = k;
            break;
        }
    }
    // The `mangle` statement's own level counts: chain[k] (k+1 nested
    // expressions) is the first to exceed `max_json_depth` at k = 31.
    try testing.expectEqual(@as(?usize, root.max_json_depth - 1), first_bad);
}

test "a TooDeep failure does not leak into the next write's error" {
    var chain: [40]JExpr = undefined;
    chain[0] = root.num(1);
    for (1..chain.len) |i| chain[i] = .{ .jhash = .{ .mod = 1, .expr = &chain[i - 1] } };
    const mark: JExpr = .{ .meta = .mark };
    var deep = root.Ruleset.init(gpa);
    defer deep.deinit();
    try deep.addRule(.inet, "t", "c", &.{.{ .mangle = .{ .key = mark, .value = chain[39] } }});
    try testing.expectError(error.TooDeep, deep.toJson(gpa));

    var ok = root.Ruleset.init(gpa);
    defer ok.deinit();
    try ok.addTable(.inet, "filter");
    var tiny: [8]u8 = undefined;
    var w = std.Io.Writer.fixed(&tiny);
    try testing.expectError(error.WriteFailed, ok.writeJson(&w));
}

test "optional JSON fields appear when set and are omitted when empty" {
    // Chain.dev
    var rs = root.Ruleset.init(gpa);
    defer rs.deinit();
    try rs.addChain(.{ .family = .netdev, .table = "t", .name = "c", .dev = "eth0" });
    const j = try rs.toJson(gpa);
    defer gpa.free(j);
    try testing.expect(contains(j, "\"dev\":\"eth0\""));

    // Selector.chain / Selector.name
    const s = try stringify(root.Selector{ .kind = .rules, .family = .inet, .table = "t", .chain = "ch", .name = "nm" });
    defer gpa.free(s);
    try testing.expectEqualStrings("{\"rules\":{\"family\":\"inet\",\"table\":\"t\",\"chain\":\"ch\",\"name\":\"nm\"}}", s);

    // SetStmt with no per-element statements has no "stmt" key at all.
    const e: JExpr = .{ .meta = .mark };
    const ss = try stringify(root.Stmt{ .set_stmt = .{ .op = .add, .elem = e, .set = "s" } });
    defer gpa.free(ss);
    try testing.expect(!contains(ss, "\"stmt\""));

    // A reject carrying only the ICMP code expression is not `null`.
    const r = try stringify(root.Stmt{ .reject = .{ .expr = root.str("x") } });
    defer gpa.free(r);
    try testing.expectEqualStrings("{\"reject\":{\"expr\":\"x\"}}", r);
}

test "RuleBuilder reports an allocation failure at apply()" {
    var fa = testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
    var rs = root.Ruleset.init(fa.allocator());
    defer rs.deinit();
    var b = rs.rule(.inet, "t", "c");
    _ = b.accept();
    fa.fail_index = std.math.maxInt(usize); // a FailingAllocator fails every allocation from its index on
    try testing.expectError(error.OutOfMemory, b.apply());

    var fa2 = testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
    var rs2 = root.Ruleset.init(fa2.allocator());
    defer rs2.deinit();
    var b2 = rs2.rule(.inet, "t", "c");
    _ = b2.ctState(&.{"established"});
    fa2.fail_index = std.math.maxInt(usize);
    try testing.expectError(error.OutOfMemory, b2.apply());
}

// ── wire builders and decoders ──────────────────────────────────────────────

test "concatKeyType: two to five components, nothing else" {
    const T = types.SetDataType;
    try testing.expectError(error.InvalidExpression, wire.concatKeyType(&[_]T{.ipv4_addr}));
    _ = try wire.concatKeyType(&[_]T{ .ipv4_addr, .inet_service });
    _ = try wire.concatKeyType(&[_]T{ .ipv4_addr, .inet_service, .ipv4_addr, .inet_service, .mark });
    try testing.expectError(error.InvalidExpression, wire.concatKeyType(&[_]T{ .ipv4_addr, .inet_service, .ipv4_addr, .inet_service, .mark, .mark }));
}

fn firstMessage(bytes: []const u8) !nl.Message {
    var it: nl.MessageIterator = .{ .buf = bytes };
    return (try it.next()).?;
}

test "buildGenIdRequest is the 20-byte GETGEN header and nothing else" {
    const r = wire.buildGenIdRequest(0x01020304);
    const m = try firstMessage(&r);
    try testing.expectEqual(@as(usize, 20), r.len);
    try testing.expectEqual(@as(u32, 20), std.mem.readInt(u32, r[0..4], @import("builtin").cpu.arch.endian()));
    try testing.expectEqual(wire.nftMsg(wire.NFT_MSG.GETGEN), m.type);
    try testing.expectEqual(nl.NLM_F_REQUEST, m.flags);
    try testing.expectEqual(@as(u32, 0x01020304), m.seq);
    try testing.expectEqual(@as(u32, 0), m.pid);
}

test "buildRuleGetRequest carries table, chain and handle; the reset variant only changes the type" {
    const req = try wire.buildRuleGetRequest(gpa, 9, .inet, "tbl", "chn", 0x1122334455667788);
    defer gpa.free(req);
    const m = try firstMessage(req);
    try testing.expectEqual(wire.nftMsg(wire.NFT_MSG.GETRULE), m.type);
    const hdr = try wire.parseNfgenmsg(m.payload);
    var it = hdr.attrIterator();
    var seen_t = false;
    var seen_c = false;
    var seen_h = false;
    while (try it.next()) |a| switch (a.type) {
        wire.NFTA_RULE.TABLE => {
            try testing.expectEqualStrings("tbl", a.asString());
            seen_t = true;
        },
        wire.NFTA_RULE.CHAIN => {
            try testing.expectEqualStrings("chn", a.asString());
            seen_c = true;
        },
        wire.NFTA_RULE.HANDLE => {
            try testing.expectEqual(@as(u64, 0x1122334455667788), try a.asBe64());
            seen_h = true;
        },
        else => return error.TestUnexpectedResult,
    };
    try testing.expect(seen_t and seen_c and seen_h);

    const rst = try wire.buildRuleResetRequest(gpa, 9, .inet, "tbl", "chn");
    defer gpa.free(rst);
    try testing.expectEqual(wire.nftMsg(wire.NFT_MSG.GETRULE_RESET), (try firstMessage(rst)).type);
    const dump = try wire.buildRuleDumpRequest(gpa, 9, .inet, "tbl", "chn");
    defer gpa.free(dump);
    try testing.expectEqual(wire.nftMsg(wire.NFT_MSG.GETRULE), (try firstMessage(dump)).type);
}

test "set-element requests: the key count limit is 65535 (and 65535 keys no longer fit one nest)" {
    const keys = try gpa.alloc([]const u8, 65536);
    defer gpa.free(keys);
    @memset(keys, "k");
    try testing.expectError(error.AttrTooLong, wire.buildSetElemGetRequest(gpa, 1, .inet, "t", "s", keys, false));
    const few = try wire.buildSetElemGetRequest(gpa, 1, .inet, "t", "s", keys[0..3], false);
    gpa.free(few);
}

test "a catch-all element carries no key; an empty-keyed plain element still does" {
    var b = try wire.Batch.init(gpa, 1, .{});
    defer b.deinit();
    const ca = [_]wire.SetElem{.{ .key = "", .flags = wire.NFT_SET_ELEM_CATCHALL }};
    try b.addSetElems(.inet, "t", "s", null, &ca);
    const plain = [_]wire.SetElem{.{ .key = "" }};
    try b.addSetElems(.inet, "t", "s", null, &plain);
    // flags != 0 but not catch-all, empty key: still a keyed element
    const flagged = [_]wire.SetElem{.{ .key = "", .flags = 1 }};
    try b.addSetElems(.inet, "t", "s", null, &flagged);
    const keyed_catchall = [_]wire.SetElem{.{ .key = "k", .flags = wire.NFT_SET_ELEM_CATCHALL }};
    try b.addSetElems(.inet, "t", "s", null, &keyed_catchall);
    const bytes = try b.finish();

    var it: nl.MessageIterator = .{ .buf = bytes };
    var n: usize = 0;
    var has_key = [_]bool{ true, true, true, false };
    while (try it.next()) |m| {
        if (m.type != wire.nftMsg(wire.NFT_MSG.NEWSETELEM)) continue;
        const rep = try wire.decodeSetElemReply(m.payload);
        // decodeSetElemReply drops key-less non-catch-all elements; look at raw attrs
        var ei = rep.iterator().attrs;
        const el = (try ei.next()).?;
        var inner = el.nested();
        var k = false;
        while (try inner.next()) |a| if (a.type == wire.NFTA_SET_ELEM.KEY) {
            k = true;
        };
        has_key[n] = k;
        n += 1;
    }
    try testing.expectEqual(@as(usize, 4), n);
    try testing.expect(!has_key[0]);
    try testing.expect(has_key[1]);
    try testing.expect(has_key[2]);
    try testing.expect(has_key[3]);
}

fn elemPayload(b: *wire.Batch) ![]const u8 {
    const bytes = try b.finish();
    var it: nl.MessageIterator = .{ .buf = bytes };
    while (try it.next()) |m| if (m.type == wire.nftMsg(wire.NFT_MSG.NEWSETELEM)) return m.payload;
    return error.TestUnexpectedResult;
}

test "decodeSetElemReply: an EXPR nest with no name yields no expression" {
    var b = try wire.Batch.init(gpa, 1, .{});
    defer b.deinit();
    const named = [_]wire.SetElem{.{ .key = "k", .expr = .{ .counter = .{} } }};
    try b.addSetElems(.inet, "t", "s", null, &named);
    const payload = try elemPayload(&b);
    var it = (try wire.decodeSetElemReply(payload)).iterator();
    const el = (try it.next()).?;
    try testing.expectEqualStrings("counter", el.expr.?.name);

    // The same element with only NFTA_EXPR_DATA inside the EXPR nest.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const e0 = try nl.nestBegin(gpa, &list, nl.NLA_F_NESTED | 1);
    const k = try nl.nestBegin(gpa, &list, nl.NLA_F_NESTED | wire.NFTA_SET_ELEM.KEY);
    try nl.appendAttr(gpa, &list, expr.NFTA_DATA.VALUE, "kk");
    try nl.nestEnd(&list, k);
    const x = try nl.nestBegin(gpa, &list, nl.NLA_F_NESTED | wire.NFTA_SET_ELEM.EXPR);
    try nl.appendAttr(gpa, &list, expr.NFTA_EXPR.DATA, "dd");
    try nl.nestEnd(&list, x);
    try nl.nestEnd(&list, e0);
    var all: std.ArrayList(u8) = .empty;
    defer all.deinit(gpa);
    try all.appendSlice(gpa, &[_]u8{ 0, 0, 0, 0 }); // nfgenmsg
    const o = try nl.nestBegin(gpa, &all, nl.NLA_F_NESTED | wire.NFTA_SET_ELEM_LIST.ELEMENTS);
    try all.appendSlice(gpa, list.items);
    try nl.nestEnd(&all, o);
    var it2 = (try wire.decodeSetElemReply(all.items)).iterator();
    const el2 = (try it2.next()).?;
    try testing.expect(el2.expr == null);
}

test "decodeObjectData and expression attribute tables ignore an attribute type past their size" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try nl.appendAttrBe64(gpa, &list, expr.NFTA_COUNTER.PACKETS, 5);
    try nl.appendAttrBe32(gpa, &list, 16, 1); // one past the 16-slot table
    const od = (try wire.decodeObjectData(@backingInt(expr.ObjectType.counter), list.items)).?;
    try testing.expectEqual(@as(u64, 5), od.counter.packets);

    const v: expr.ExprView = .{ .name = "counter", .data = list.items };
    const back = try expr.decodeExpr(v);
    try testing.expectEqual(@as(u64, 5), back.counter.packets);
    const v2: expr.ExprView = .{ .name = "cmp", .data = list.items };
    _ = try expr.decodeExpr(v2);
}

// ── expressions ─────────────────────────────────────────────────────────────

fn roundTrip(e: Expr) !void {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try expr.appendExpr(gpa, &list, e);
    var it: expr.ExprIterator = .{ .attrs = .{ .buf = list.items } };
    const view = (try it.next()).?;
    try testing.expectEqualDeep(e, try expr.decodeExpr(view));
}

test "encoder: optional registers, flags and seeded counters survive a round trip" {
    try roundTrip(.{ .nat = .{ .kind = 1, .family = 2, .reg_addr_min = .r1, .reg_addr_max = .r2, .reg_proto_min = .r3, .reg_proto_max = .r4 } });
    try roundTrip(.{ .redir = .{ .reg_proto_min = .r1, .reg_proto_max = .r2, .flags = 2 } });
    try roundTrip(.{ .payload_set = .{ .base = .nh, .offset = 8, .len = 2, .sreg = .r2, .csum_type = 1, .csum_offset = 10, .csum_flags = 1 } });
    try roundTrip(.{ .counter = .{ .packets = 7 } });
    try roundTrip(.{ .counter = .{ .bytes = 9 } });
    try roundTrip(.{ .queue = .{ .num = 65535, .total = 1 } });
    try roundTrip(.{ .queue = .{ .num = 0, .total = 65535 } });
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try testing.expectError(error.InvalidQueueRange, expr.appendExpr(gpa, &list, .{ .queue = .{ .num = 65535, .total = 2 } }));
    try testing.expectError(error.InvalidQueueRange, expr.appendExpr(gpa, &list, .{ .queue = .{ .num = 1, .total = 0 } }));
}

test "encoder: a dynset with no element expressions sends neither EXPR nor EXPRESSIONS" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try expr.appendExpr(gpa, &list, .{ .dynset = .{ .set = "s", .op = .add, .sreg_key = .r1 } });
    var it: expr.ExprIterator = .{ .attrs = .{ .buf = list.items } };
    const view = (try it.next()).?;
    var ai = view.attrs();
    while (try ai.next()) |a| {
        try testing.expect(a.type != expr.NFTA_DYNSET.EXPR);
        try testing.expect(a.type != expr.NFTA_DYNSET.EXPRESSIONS);
    }
}

test "encoder: bitwise mask and xor must each match len" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const ok4 = [_]u8{ 0, 0, 0, 0 };
    const bad3 = [_]u8{ 0, 0, 0 };
    try expr.appendExpr(gpa, &list, .{ .bitwise = .{ .sreg = .r1, .dreg = .r1, .len = 4, .mask = &ok4, .xor = &ok4 } });
    try testing.expectError(error.BitwiseLengthMismatch, expr.appendExpr(gpa, &list, .{ .bitwise = .{ .sreg = .r1, .dreg = .r1, .len = 4, .mask = &ok4, .xor = &bad3 } }));
    try testing.expectError(error.BitwiseLengthMismatch, expr.appendExpr(gpa, &list, .{ .bitwise = .{ .sreg = .r1, .dreg = .r1, .len = 4, .mask = &bad3, .xor = &ok4 } }));
}

fn decodeRaw(name: []const u8, build: *const fn (*std.ArrayList(u8)) anyerror!void) !Expr {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try build(&list);
    // The decoded value may borrow from `list`; compare only what the caller
    // needs through the returned tag/fields, which are copied by value here.
    const e = try expr.decodeExpr(.{ .name = name, .data = list.items });
    return switch (e) {
        .bitwise => .{ .raw = .{ .name = "bitwise", .data = &.{} } }, // typed: marker
        .raw => .{ .raw = .{ .name = "raw", .data = &.{} } },
        else => e,
    };
}

fn bwBadXor(list: *std.ArrayList(u8)) anyerror!void {
    try nl.appendAttrBe32(gpa, list, expr.NFTA_BITWISE.SREG, 1);
    try nl.appendAttrBe32(gpa, list, expr.NFTA_BITWISE.DREG, 1);
    try nl.appendAttrBe32(gpa, list, expr.NFTA_BITWISE.LEN, 4);
    const o1 = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | expr.NFTA_BITWISE.MASK);
    try nl.appendAttr(gpa, list, expr.NFTA_DATA.VALUE, &[_]u8{ 1, 2, 3, 4 });
    try nl.nestEnd(list, o1);
    const o2 = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | expr.NFTA_BITWISE.XOR);
    try nl.appendAttr(gpa, list, expr.NFTA_DATA.VALUE, &[_]u8{ 1, 2, 3 });
    try nl.nestEnd(list, o2);
}

fn bwBadMask(list: *std.ArrayList(u8)) anyerror!void {
    try nl.appendAttrBe32(gpa, list, expr.NFTA_BITWISE.SREG, 1);
    try nl.appendAttrBe32(gpa, list, expr.NFTA_BITWISE.DREG, 1);
    try nl.appendAttrBe32(gpa, list, expr.NFTA_BITWISE.LEN, 4);
    const o1 = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | expr.NFTA_BITWISE.MASK);
    try nl.appendAttr(gpa, list, expr.NFTA_DATA.VALUE, &[_]u8{ 1, 2, 3 });
    try nl.nestEnd(list, o1);
    const o2 = try nl.nestBegin(gpa, list, nl.NLA_F_NESTED | expr.NFTA_BITWISE.XOR);
    try nl.appendAttr(gpa, list, expr.NFTA_DATA.VALUE, &[_]u8{ 1, 2, 3, 4 });
    try nl.nestEnd(list, o2);
}

fn counterOnlyPackets(list: *std.ArrayList(u8)) anyerror!void {
    try nl.appendAttrBe64(gpa, list, expr.NFTA_COUNTER.PACKETS, 6);
}

fn objrefEmptyName(list: *std.ArrayList(u8)) anyerror!void {
    try nl.appendAttr(gpa, list, expr.NFTA_OBJREF.IMM_NAME, "");
    try nl.appendAttrBe32(gpa, list, expr.NFTA_OBJREF.IMM_TYPE, 1);
}

test "decoder: a bitwise whose mask or xor has the wrong width stays raw" {
    const a = try decodeRaw("bitwise", bwBadXor);
    try testing.expectEqualStrings("raw", a.raw.name);
    const b = try decodeRaw("bitwise", bwBadMask);
    try testing.expectEqualStrings("raw", b.raw.name);
}

test "decoder: a counter with only PACKETS is a counter; an empty objref name does not underflow" {
    const c = try decodeRaw("counter", counterOnlyPackets);
    try testing.expectEqual(@as(u64, 6), c.counter.packets);
    try testing.expectEqual(@as(u64, 0), c.counter.bytes);
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try objrefEmptyName(&list);
    const o = try expr.decodeExpr(.{ .name = "objref", .data = list.items });
    try testing.expectEqual(@as(usize, 0), o.objref.name.len);
}

test "Program: boundary widths, /32 prefixes, equal range ends, inverted range" {
    var p = expr.Program.init(gpa, .inet);
    defer p.deinit();
    const wide: [16]u8 = @splat(0);
    _ = p.payloadLookup(.nh, 0, 16, "s", null, false);
    _ = p.payloadVmap(.nh, 0, 16, "m", null);
    _ = p.ipSaddrPrefix(.{ 10, 0, 0, 1 }, 32);
    _ = p.tcpDportRange(80, 80, true);
    _ = p.payloadMaskedCmp(.nh, 0, 16, &wide, .eq, &wide);
    const es = try p.finish();
    var saw_neq = false;
    for (es) |e| if (e == .range) {
        try testing.expectEqual(expr.RangeOp.neq, e.range.op);
        saw_neq = true;
    };
    try testing.expect(saw_neq);

    var q = expr.Program.init(gpa, .inet);
    defer q.deinit();
    _ = q.tcpDportRange(80, 80, false);
    const eq_es = try q.finish();
    for (eq_es) |e| if (e == .range) try testing.expectEqual(expr.RangeOp.eq, e.range.op);

    var r = expr.Program.init(gpa, .inet);
    defer r.deinit();
    const over: [17]u8 = @splat(0);
    _ = r.payloadLookup(.nh, 0, 17, "s", null, false);
    try testing.expectError(error.ValueWidthMismatch, r.finish());
    var r2 = expr.Program.init(gpa, .inet);
    defer r2.deinit();
    _ = r2.payloadVmap(.nh, 0, 17, "m", null);
    try testing.expectError(error.ValueWidthMismatch, r2.finish());
    var r3 = expr.Program.init(gpa, .inet);
    defer r3.deinit();
    _ = r3.ipSaddrPrefix(.{ 10, 0, 0, 1 }, 33);
    try testing.expectError(error.ValueWidthMismatch, r3.finish());

    // mask and value are each checked against len
    var m1 = expr.Program.init(gpa, .inet);
    defer m1.deinit();
    _ = m1.payloadMaskedCmp(.nh, 0, 4, over[0..3], .eq, over[0..4]);
    try testing.expectError(error.ValueWidthMismatch, m1.finish());
    var m2 = expr.Program.init(gpa, .inet);
    defer m2.deinit();
    _ = m2.payloadMaskedCmp(.nh, 0, 4, over[0..4], .eq, over[0..3]);
    try testing.expectError(error.ValueWidthMismatch, m2.finish());
}

fn commandHasAttr(bytes: []const u8, cmd: u8, attr_type: u16) !bool {
    var it: nl.MessageIterator = .{ .buf = bytes };
    while (try it.next()) |m| {
        if (m.type != wire.nftMsg(cmd)) continue;
        var ai = (try wire.parseNfgenmsg(m.payload)).attrIterator();
        while (try ai.next()) |a| if (a.type == attr_type) return true;
    }
    return false;
}

test "optional userdata and position attributes are sent exactly when set" {
    var b = try wire.Batch.init(gpa, 1, .{});
    defer b.deinit();
    try b.addChain(.{ .family = .inet, .table = "t", .name = "c", .userdata = "u" });
    try b.addRule(.{ .family = .inet, .table = "t", .chain = "c", .position = 7, .userdata = "ru" });
    const bytes = try b.finish();
    try testing.expect(try commandHasAttr(bytes, wire.NFT_MSG.NEWCHAIN, wire.NFTA_CHAIN.USERDATA));
    try testing.expect(try commandHasAttr(bytes, wire.NFT_MSG.NEWRULE, wire.NFTA_RULE.USERDATA));
    try testing.expect(try commandHasAttr(bytes, wire.NFT_MSG.NEWRULE, wire.NFTA_RULE.POSITION));

    var c = try wire.Batch.init(gpa, 1, .{});
    defer c.deinit();
    try c.addChain(.{ .family = .inet, .table = "t", .name = "c" });
    try c.addRule(.{ .family = .inet, .table = "t", .chain = "c" });
    const cb = try c.finish();
    try testing.expect(!try commandHasAttr(cb, wire.NFT_MSG.NEWCHAIN, wire.NFTA_CHAIN.USERDATA));
    try testing.expect(!try commandHasAttr(cb, wire.NFT_MSG.NEWRULE, wire.NFTA_RULE.USERDATA));
    try testing.expect(!try commandHasAttr(cb, wire.NFT_MSG.NEWRULE, wire.NFTA_RULE.POSITION));
}

fn exprHasAttr(e: Expr, attr_type: u16) !bool {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try expr.appendExpr(gpa, &list, e);
    var it: expr.ExprIterator = .{ .attrs = .{ .buf = list.items } };
    var ai = (try it.next()).?.attrs();
    while (try ai.next()) |a| if (a.type == attr_type) return true;
    return false;
}

test "encoder: dynset data register and ct direction are sent exactly when set" {
    try testing.expect(try exprHasAttr(.{ .dynset = .{ .set = "s", .op = .update, .sreg_key = .r1, .sreg_data = .r2 } }, expr.NFTA_DYNSET.SREG_DATA));
    try testing.expect(!try exprHasAttr(.{ .dynset = .{ .set = "s", .op = .update, .sreg_key = .r1 } }, expr.NFTA_DYNSET.SREG_DATA));
    try testing.expect(try exprHasAttr(.{ .ct_set = .{ .key = expr.NFT_CT.MARK, .dir = .reply, .sreg = .r1 } }, expr.NFTA_CT.DIRECTION));
    try testing.expect(!try exprHasAttr(.{ .ct_set = .{ .key = expr.NFT_CT.MARK, .sreg = .r1 } }, expr.NFTA_CT.DIRECTION));
}
