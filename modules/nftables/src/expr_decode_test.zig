// SPDX-License-Identifier: MIT

//! `decodeExpr` is the inverse of `appendExpr`: every typed expression the
//! module can send must come back from the kernel's own reply bytes as the
//! same typed value. The round trip is the oracle (the encoder is anchored
//! to `nft`'s bytes by `goldens.zig`/`goldens2.zig`); the second half pins
//! what must NOT be typed (unknown names, unnameable values) to `.raw`.

const std = @import("std");
const testing = std.testing;
const expr = @import("expr.zig");
const nl = @import("nl.zig");

const Expr = expr.Expr;

fn roundTrip(e: Expr) !void {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try expr.appendExpr(testing.allocator, &list, e);
    var it: expr.ExprIterator = .{ .attrs = .{ .buf = list.items } };
    const view = (try it.next()).?;
    const back = try expr.decodeExpr(view);
    try testing.expectEqualDeep(e, back);
    try testing.expect(try it.next() == null);
}

test "decodeExpr: every typed expression round-trips through its own encoding" {
    const v4 = [_]u8{ 10, 0, 0, 1 };
    const exprs = [_]Expr{
        .{ .payload_load = .{ .base = .th, .offset = 2, .len = 2, .dreg = .r1 } },
        .{ .payload_set = .{ .base = .nh, .offset = 8, .len = 2, .sreg = .r2, .csum_type = 1, .csum_offset = 10 } },
        .{ .meta_load = .{ .key = .mark, .dreg = .r1 } },
        .{ .meta_set = .{ .key = .mark, .sreg = .r3 } },
        .{ .ct_load = .{ .key = expr.NFT_CT.STATE, .dreg = .r1 } },
        .{ .ct_load = .{ .key = expr.NFT_CT.SRC, .dir = .reply, .dreg = .r1 } },
        .{ .ct_set = .{ .key = expr.NFT_CT.MARK, .sreg = .r1 } },
        .{ .cmp = .{ .sreg = .r1, .op = 0, .data = .{ .value = &v4 } } },
        .{ .cmp = .{ .sreg = .r1, .op = 1, .data = .{ .value = &.{} } } },
        .{ .bitwise = .{ .sreg = .r1, .dreg = .r1, .len = 4, .mask = &.{ 255, 0, 0, 0 }, .xor = &.{ 0, 0, 0, 0 } } },
        .{ .bitshift = .{ .sreg = .r1, .dreg = .r1, .len = 4, .dir = .left, .amount = 8 } },
        .{ .bitshift = .{ .sreg = .r1, .dreg = .r1, .len = 4, .dir = .right, .amount = 3 } },
        .{ .lookup = .{ .set = "blocked", .sreg = .r1, .set_id = 7, .invert = true } },
        .{ .lookup = .{ .set = "vm", .sreg = .r1, .dreg = .verdict } },
        .{ .counter = .{} },
        .{ .counter = .{ .packets = 3, .bytes = 400 } },
        .{ .immediate = .{ .dreg = .verdict, .data = .{ .verdict = .{ .code = -1 } } } },
        .{ .immediate = .{ .dreg = .verdict, .data = .{ .verdict = expr.Verdict.jumpTo("helper") } } },
        .{ .immediate = .{ .dreg = .r1, .data = .{ .value = &v4 } } },
        .{ .limit = .{ .rate = 10, .burst = 5 } },
        .{ .limit = .{ .rate = 100, .per = .hour, .unit = .bytes, .inv = true } },
        .{ .log = .{} },
        .{ .log = .{ .prefix = "ssh: ", .level = .info, .group = 3, .snaplen = 64, .qthreshold = 9, .flags = 1 } },
        .{ .nat = .{ .kind = 1, .family = 2, .reg_addr_min = .r1, .reg_proto_min = .r2, .flags = 2 } },
        .{ .masq = .{} },
        .{ .masq = .{ .flags = 2, .reg_proto_min = .r1, .reg_proto_max = .r2 } },
        .{ .reject = .{ .type = 1, .icmp_code = 0 } },
        .{ .queue = .{ .num = 2, .total = 4, .flags = 3 } },
        .{ .redir = .{ .reg_proto_min = .r1, .flags = 2 } },
        .{ .quota = .{ .bytes = 1000, .consumed = 5, .over = true } },
        .{ .objref = .{ .obj_type = .counter, .name = "c1" } },
        .{ .byteorder = .{ .sreg = .r1, .dreg = .r1, .op = .hton, .len = 4, .size = 4 } },
        .{ .exthdr = .{ .op = .tcpopt, .hdr_type = 2, .offset = 2, .len = 2, .dreg = .r1 } },
        .{ .exthdr = .{ .op = .ipv6, .hdr_type = 0, .offset = 0, .len = 1, .present = true, .dreg = .r1 } },
        .{ .exthdr = .{ .op = .tcpopt, .hdr_type = 2, .offset = 2, .len = 2, .sreg = .r1 } },
        .{ .fib = .{ .dreg = .r1, .result = 1, .flags = 41 } },
        .{ .hash = .{ .kind = .jenkins, .dreg = .r1, .sreg = .r2, .len = 4, .modulus = 4, .seed = 0x1234, .offset = 2 } },
        .{ .hash = .{ .kind = .sym, .dreg = .r1, .modulus = 2 } },
        .{ .numgen = .{ .dreg = .r1, .kind = .random, .modulus = 10, .offset = 5 } },
        .{ .range = .{ .sreg = .r1, .op = .neq, .from = &.{ 3, 232 }, .to = &.{ 7, 208 } } },
        .{ .rt = .{ .key = expr.NFT_RT.NEXTHOP4, .dreg = .r1 } },
        .{ .socket = .{ .key = expr.NFT_SOCKET.MARK, .dreg = .r1, .level = 2 } },
        .notrack,
        .{ .dup = .{ .sreg_addr = .r1, .sreg_dev = .r2 } },
        .{ .dup = .{ .sreg_addr = .r1 } },
        .{ .fwd = .{ .sreg_dev = .r1 } },
        .{ .fwd = .{ .sreg_dev = .r1, .sreg_addr = .r2, .nfproto = 2 } },
        .{ .tproxy = .{ .family = 2, .reg_addr = .r1, .reg_port = .r2 } },
        .{ .synproxy = .{ .mss = 1460, .wscale = 7, .flags = 15 } },
        .{ .connlimit = .{ .count = 10, .over = true } },
        .{ .osf = .{ .dreg = .r1, .ttl = 2, .version = true } },
        .{ .flow_offload = .{ .table = "ft" } },
        .{ .last = .{} },
        .{ .last = .{ .msecs = 3600000, .set = true } },
    };
    for (exprs) |e| try roundTrip(e);
}

test "decodeExpr: names and values the model cannot name stay raw" {
    // An expression this module does not model.
    const unknown: Expr = .{ .raw = .{ .name = "xt_future", .data = &.{} } };
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try expr.appendExpr(testing.allocator, &list, unknown);
    var it: expr.ExprIterator = .{ .attrs = .{ .buf = list.items } };
    try testing.expectEqualDeep(unknown, try expr.decodeExpr((try it.next()).?));

    // A meta key outside the vocabulary (NFT_META_TIME_NS = 26, not named
    // in `MetaKey`): typed would be a wrong answer, raw keeps the bytes.
    list.clearRetainingCapacity();
    try expr.appendExpr(testing.allocator, &list, .{ .raw = .{ .name = "meta", .data = &.{ 8, 0, 2, 0, 0, 0, 0, 99, 8, 0, 1, 0, 0, 0, 0, 1 } } });
    var it2: expr.ExprIterator = .{ .attrs = .{ .buf = list.items } };
    const r = try expr.decodeExpr((try it2.next()).?);
    try testing.expect(r == .raw);

    // A bitwise boolean operator (NFT_BITWISE_AND = 3) is never typed.
    list.clearRetainingCapacity();
    const bw = [_]u8{ 8, 0, 1, 0, 0, 0, 0, 1, 8, 0, 2, 0, 0, 0, 0, 1, 8, 0, 3, 0, 0, 0, 0, 4, 8, 0, 6, 0, 0, 0, 0, 3 };
    try expr.appendExpr(testing.allocator, &list, .{ .raw = .{ .name = "bitwise", .data = &bw } });
    var it3: expr.ExprIterator = .{ .attrs = .{ .buf = list.items } };
    try testing.expect((try expr.decodeExpr((try it3.next()).?)) == .raw);
}

test "decodeExpr: a truncated attribute is an error, never a panic" {
    // A `counter` whose BYTES attribute is 4 bytes long.
    const view: expr.ExprView = .{ .name = "counter", .data = &.{ 8, 0, 1, 0, 0, 0, 0, 1 } };
    try testing.expect(std.meta.isError(expr.decodeExpr(view)));
    const cut: expr.ExprView = .{ .name = "cmp", .data = &.{ 4, 0 } };
    try testing.expect(std.meta.isError(expr.decodeExpr(cut)));
}

test "Program helpers build what they say" {
    var p = expr.Program.init(testing.allocator, .inet);
    defer p.deinit();
    _ = p.tcpDportRange(1000, 2000, false).accept();
    const e = try p.finish();
    // l4proto dep (meta + cmp), the payload load, the range, the verdict.
    try testing.expectEqual(@as(usize, 5), e.len);
    try testing.expect(e[3] == .range);
    var q = expr.Program.init(testing.allocator, .inet);
    defer q.deinit();
    _ = q.tcpDportRange(2000, 1000, false);
    try testing.expectError(error.InvalidRange, q.finish());
}

test "exthdr, hash and numgen refuse contradictory fields" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    const bad = [_]Expr{
        .{ .exthdr = .{ .op = .tcpopt, .hdr_type = 2, .offset = 0, .len = 1 } },
        .{ .exthdr = .{ .op = .tcpopt, .hdr_type = 2, .offset = 0, .len = 1, .dreg = .r1, .sreg = .r2 } },
        .{ .hash = .{ .kind = .jenkins, .dreg = .r1, .modulus = 4 } },
        .{ .hash = .{ .kind = .sym, .dreg = .r1, .modulus = 0 } },
        .{ .numgen = .{ .dreg = .r1, .kind = .random, .modulus = 0 } },
        .{ .fwd = .{ .sreg_dev = .r1, .sreg_addr = .r2 } },
    };
    for (bad) |e| try testing.expectError(error.InvalidExpression, expr.appendExpr(testing.allocator, &list, e));
}
