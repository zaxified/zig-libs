// SPDX-License-Identifier: MIT

//! **Byte-exact goldens captured from the real `nft` binary.**
//!
//! Every constant below is the complete `sendmsg` payload a stock `nft` put on
//! the wire — the whole transactional batch, `NFNL_MSG_BATCH_BEGIN` through
//! `NFNL_MSG_BATCH_END`. `strace`'s `-e write=all` prints the buffer verbatim,
//! so there is no re-encoding step between the kernel-bound bytes and the hex
//! strings here.
//!
//! Capture recipe — every command ran inside one unprivileged network
//! namespace, so nothing touched host state:
//!
//! ```sh
//! unshare -rn strace -f -e trace=sendmsg -e write=all -xx -s 8192 \
//!         -e abbrev=none nft <command…>
//! ```
//!
//! Capture host: `nftables v1.1.6`, Linux 7.0, x86-64 (little-endian).
//! The exact command each golden came from is in the comment above it.
//!
//! ## Two things that make byte-exactness possible
//!
//! * **`nlmsg_seq`.** `nft` seeds its batch at 0 and numbers upwards
//!   (`BATCH_BEGIN` = 0, commands 1…n, `BATCH_END` = n+1), so the goldens pass
//!   `first_seq = 0`.
//! * **`NFTA_*_USERDATA`.** `nft` stamps a private versioned TLV into tables
//!   and sets. It is opaque to the kernel, so `TableSpec.userdata` /
//!   `SetSpec.userdata` pass it straight through and the goldens hand this
//!   module the exact bytes `nft` sent. Nothing here interprets them.
//!
//! `nft` does **not** set `NLM_F_ACK` on batch commands, so every golden builds
//! its batch with `.{ .ack = false }`. The module's own default is the
//! opposite — see `wire.BatchOptions`.

const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

const nl = @import("nl.zig");
const types = @import("types.zig");
const expr = @import("expr.zig");
const wire = @import("wire.zig");

const testing = std.testing;
const gpa = testing.allocator;

/// `nft`'s private table userdata stamp (see the module comment).
const nft_table_userdata = [_]u8{
    0x01, 0x04, 0x01, 0x01, 0x06, 0x00, 0x02, 0x08,
    0x00, 0x00, 0x00, 0x00, 0x69, 0x35, 0x43, 0xd4,
};

/// `nft`'s private set userdata stamp for an `ipv4_addr` interval set.
const nft_set_userdata_interval = [_]u8{
    0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x03, 0x08,
    0x00, 0x04, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00,
};

/// Compare a built batch against a golden hex string, decoding the golden on
/// the fly so the constants stay greppable next to the command that produced
/// them.
fn expectGolden(hex: []const u8, actual: []const u8) !void {
    if (native_endian != .little) return error.SkipZigTest; // captures are LE
    var expected: [1024]u8 = undefined;
    const want = try std.fmt.hexToBytes(expected[0 .. hex.len / 2], hex);
    try testing.expectEqualSlices(u8, want, actual);
}

// ── captured batches ────────────────────────────────────────────────────────

// ### nft add table inet filter
const g_add_table =
    "140000001000010000000000000000000000000a3c000000000a01000100000000000000010000000b00010066696c74" ++
    "65720000080002000000000014000600010401010600020800000000693543d414000000110001000200000000000000" ++
    "0000000a";

// ### nft delete table inet filter
const g_del_table =
    "140000001000010000000000000000000000000a20000000020a01000100000000000000010000000b00010066696c74" ++
    "65720000140000001100010002000000000000000000000a";

// ### nft add chain inet filter input '{ type filter hook input priority 0; policy drop; }'
const g_add_chain =
    "140000001000010000000000000000000000000a54000000030a01040100000000000000010000000b00010066696c74" ++
    "657200000a000300696e70757400000008000500000000000b00070066696c7465720000140004800800010000000001" ++
    "0800020000000000140000001100010002000000000000000000000a";

// ### nft add chain ip nat post '{ type nat hook postrouting priority 100; }'
const g_add_chain_nat =
    "140000001000010000000000000000000000000a44000000030a0104010000000000000002000000080001006e617400" ++
    "09000300706f737400000000080007006e61740014000480080001000000000408000200000000641400000011000100" ++
    "02000000000000000000000a";

// ### nft delete chain inet filter input2
const g_del_chain =
    "140000001000010000000000000000000000000a2c000000050a01000100000000000000010000000b00010066696c7465" ++
    "7200000b000300696e707574320000140000001100010002000000000000000000000a";

// ### nft add rule inet filter input tcp dport 22 counter accept
const g_rule_tcp_dport =
    "140000001000010000000000000000000000000a24010000060a010c0100000000000000010000000b00010066696c74" ++
    "657200000a000200696e707574000000f800048024000180090001006d65746100000000140002800800020000000010" ++
    "08000100000000012c00018008000100636d700020000280080001000000000108000200000000000c00038005000100" ++
    "06000000340001800c0001007061796c6f61640024000280080001000000000108000200000000020800030000000002" ++
    "08000400000000022c00018008000100636d700020000280080001000000000108000200000000000c00038006000100" ++
    "00160000140001800c000100636f756e7465720004000280300001800e000100696d6d6564696174650000001c000280" ++
    "0800010000000000100002800c0002800800010000000001140000001100010002000000000000000000000a";

// ### nft add rule inet filter input tcp sport 22 counter accept
// Anchors `Program.tcpSport`'s native offset (`expr.zig` `.th, 0, 2`), which
// had no oracle in either lane before this golden — see audit finding
// `nftables` F1.
const g_rule_tcp_sport =
    "140000001000010000000000000000000000000a24010000060a010c0100000000000000010000000b00010066696c746572" ++
    "00000a000200696e707574000000f800048024000180090001006d6574610000000014000280080002000000001008000100" ++
    "000000012c00018008000100636d700020000280080001000000000108000200000000000c00038005000100060000003400" ++
    "01800c0001007061796c6f616400240002800800010000000001080002000000000208000300000000000800040000000002" ++
    "2c00018008000100636d700020000280080001000000000108000200000000000c0003800600010000160000140001800c00" ++
    "0100636f756e7465720004000280300001800e000100696d6d6564696174650000001c000280080001000000000010000280" ++
    "0c0002800800010000000001140000001100010002000000000000000000000a";

// ### nft add rule inet filter input ip daddr 10.0.0.1 drop
// Anchors `Program.ipDaddr`'s native offset (`expr.zig` `.nh, 16, 4`), which
// had no oracle in either lane before this golden — see audit finding
// `nftables` F1.
const g_rule_ip_daddr =
    "140000001000010000000000000000000000000a10010000060a010c0100000000000000010000000b00010066696c746572" ++
    "00000a000200696e707574000000e400048024000180090001006d6574610000000014000280080002000000000f08000100" ++
    "000000012c00018008000100636d700020000280080001000000000108000200000000000c00038005000100020000003400" ++
    "01800c0001007061796c6f616400240002800800010000000001080002000000000108000300000000100800040000000004" ++
    "2c00018008000100636d700020000280080001000000000108000200000000000c000380080001000a000001300001800e00" ++
    "0100696d6d6564696174650000001c0002800800010000000000100002800c00028008000100000000001400000011000100" ++
    "02000000000000000000000a";

// ### nft add rule inet filter input ip saddr 10.0.0.0/8 drop
// A byte-aligned prefix needs no `bitwise`: nft shortens the payload load to
// the one covered byte.
const g_rule_prefix8 =
    "140000001000010000000000000000000000000a10010000060a010c0100000000000000010000000b00010066696c74" ++
    "657200000a000200696e707574000000e400048024000180090001006d6574610000000014000280080002000000000f" ++
    "08000100000000012c00018008000100636d700020000280080001000000000108000200000000000c00038005000100" ++
    "02000000340001800c0001007061796c6f6164002400028008000100000000010800020000000001080003000000000c" ++
    "08000400000000012c00018008000100636d700020000280080001000000000108000200000000000c00038005000100" ++
    "0a000000300001800e000100696d6d6564696174650000001c0002800800010000000000100002800c00028008000100" ++
    "00000000140000001100010002000000000000000000000a";

// ### nft add rule inet filter input ip saddr 10.0.0.0/12 drop
// The non-byte-aligned prefix that forces the `bitwise` mask/xor expression.
const g_rule_prefix12_bitwise =
    "140000001000010000000000000000000000000a54010000060a010c0100000000000000010000000b00010066696c74" ++
    "657200000a000200696e7075740000002801048024000180090001006d6574610000000014000280080002000000000f" ++
    "08000100000000012c00018008000100636d700020000280080001000000000108000200000000000c00038005000100" ++
    "02000000340001800c0001007061796c6f6164002400028008000100000000010800020000000001080003000000000c" ++
    "0800040000000004440001800c0001006269747769736500340002800800010000000001080002000000000108000300" ++
    "000000040c00048008000100fff000000c00058008000100000000002c00018008000100636d70002000028008000100" ++
    "0000000108000200000000000c000380080001000a000000300001800e000100696d6d6564696174650000001c000280" ++
    "0800010000000000100002800c0002800800010000000000140000001100010002000000000000000000000a";

// ### nft add rule inet filter input ip saddr @blocked drop
const g_rule_lookup =
    "140000001000010000000000000000000000000a14010000060a010c0100000000000000010000000b00010066696c74" ++
    "657200000a000200696e707574000000e800048024000180090001006d6574610000000014000280080002000000000f" ++
    "08000100000000012c00018008000100636d700020000280080001000000000108000200000000000c00038005000100" ++
    "02000000340001800c0001007061796c6f6164002400028008000100000000010800020000000001080003000000000c" ++
    "0800040000000004300001800b0001006c6f6f6b757000002000028008000200000000010c000100626c6f636b656400" ++
    "0800040000000001300001800e000100696d6d6564696174650000001c0002800800010000000000100002800c000280" ++
    "0800010000000000140000001100010002000000000000000000000a";

// ### nft add rule inet filter input ct state established,related accept
const g_rule_ct_state =
    "140000001000010000000000000000000000000af0000000060a010c0100000000000000010000000b00010066696c74" ++
    "657200000a000200696e707574000000c400048020000180070001006374000014000280080002000000000008000100" ++
    "00000001440001800c000100626974776973650034000280080001000000000108000200000000010800030000000004" ++
    "0c00048008000100060000000c00058008000100000000002c00018008000100636d7000200002800800010000000001" ++
    "08000200000000010c0003800800010000000000300001800e000100696d6d6564696174650000001c00028008000100" ++
    "00000000100002800c0002800800010000000001140000001100010002000000000000000000000a";

// ### nft add rule inet filter input limit rate 10/second burst 5 packets accept
const g_rule_limit =
    "140000001000010000000000000000000000000aa4000000060a010c0100000000000000010000000b00010066696c74" ++
    "657200000a000200696e70757400000078000480440001800a0001006c696d6974000000340002800c00010000000000" ++
    "0000000a0c0002000000000000000001080003000000000508000400000000000800050000000000300001800e000100" ++
    "696d6d6564696174650000001c0002800800010000000000100002800c00028008000100000000011400000011000100" ++
    "02000000000000000000000a";

// ### nft add rule inet filter input log prefix '"ssh: "' level info
const g_rule_log =
    "140000001000010000000000000000000000000a54000000060a010c0100000000000000010000000b00010066696c74" ++
    "657200000a000200696e7075740000002800048024000180080001006c6f6700180002800a0002007373683a20000000" ++
    "0800050000000006140000001100010002000000000000000000000a";

// ### nft add rule inet filter input iifname "lo" accept
const g_rule_iifname =
    "140000001000010000000000000000000000000abc000000060a010c0100000000000000010000000b00010066696c74" ++
    "657200000a000200696e7075740000009000048024000180090001006d65746100000000140002800800020000000006" ++
    "08000100000000013800018008000100636d70002c000280080001000000000108000200000000001800038014000100" ++
    "6c6f0000000000000000000000000000300001800e000100696d6d6564696174650000001c0002800800010000000000" ++
    "100002800c0002800800010000000001140000001100010002000000000000000000000a";

// ### nft add rule ip nat post oifname "eth0" masquerade
const g_rule_masquerade =
    "140000001000010000000000000000000000000a9c000000060a010c010000000000000002000000080001006e617400" ++
    "09000200706f7374000000007400048024000180090001006d6574610000000014000280080002000000000708000100" ++
    "000000013800018008000100636d70002c00028008000100000000010800020000000000180003801400010065746830" ++
    "00000000000000000000000014000180090001006d617371000000000400028014000000110001000200000000000000" ++
    "0000000a";

// ### nft add rule ip nat post ip saddr 10.0.0.0/8 snat to 192.0.2.1
const g_rule_snat =
    "140000001000010000000000000000000000000ae0000000060a010c010000000000000002000000080001006e617400" ++
    "09000200706f737400000000b8000480340001800c0001007061796c6f61640024000280080001000000000108000200" ++
    "00000001080003000000000c08000400000000012c00018008000100636d700020000280080001000000000108000200" ++
    "000000000c000380050001000a0000002c0001800e000100696d6d656469617465000000180002800800010000000001" ++
    "0c00028008000100c000020128000180080001006e6174001c0002800800010000000000080002000000000208000300" ++
    "00000001140000001100010002000000000000000000000a";

// ### nft add rule ip nat post tcp dport 80 dnat to 10.0.0.5:8080
const g_rule_dnat =
    "140000001000010000000000000000000000000a6c010000060a010c010000000000000002000000080001006e617400" ++
    "09000200706f7374000000004401048024000180090001006d6574610000000014000280080002000000001008000100" ++
    "000000012c00018008000100636d700020000280080001000000000108000200000000000c0003800500010006000000" ++
    "340001800c0001007061796c6f6164002400028008000100000000010800020000000002080003000000000208000400" ++
    "000000022c00018008000100636d700020000280080001000000000108000200000000000c0003800600010000500000" ++
    "2c0001800e000100696d6d6564696174650000001800028008000100000000010c000280080001000a0000052c000180" ++
    "0e000100696d6d6564696174650000001800028008000100000000020c000280060001001f9000003800018008000100" ++
    "6e6174002c00028008000100000000010800020000000002080003000000000108000500000000020800070000000002" ++
    "140000001100010002000000000000000000000a";

// ### nft insert rule inet filter input counter accept — no NLM_F_APPEND,
// unlike `add rule` above, which is the whole distinction `insertRule` exists
// to carry (see wire.zig's `insertRule` doc comment).
const g_insert_rule =
    "140000001000010000000000000000000000000a74000000060a01040100000000000000010000000b00010066696c7465" ++
    "7200000a000200696e70757400000048000480140001800c000100636f756e7465720004000280300001800e000100696d" ++
    "6d6564696174650000001c0002800800010000000000100002800c00028008000100000000011400000011000100020000" ++
    "00000000000000000a";

// ### nft add set inet filter blocked '{ type ipv4_addr; flags interval; }'
const g_add_set =
    "140000001000010000000000000000000000000a60000000090a01040100000000000000010000000b00010066696c74" ++
    "657200000c000200626c6f636b65640008000300000000040800040000000007080005000000000408000a0000000001" ++
    "14000d0000040200000003080004040000000100140000001100010002000000000000000000000a";

// ### nft delete set inet filter tmpset
const g_del_set =
    "140000001000010000000000000000000000000a2c0000000b0a01000100000000000000010000000b00010066696c7465" ++
    "7200000b000200746d707365740000140000001100010002000000000000000000000a";

// ### nft add element inet filter blocked '{ 10.0.0.1 }'
// Three elements, not one: an interval set stores a singleton as
// [0.0.0.0 INTERVAL_END] [10.0.0.1] [10.0.0.2 INTERVAL_END] — the closing
// markers are the *exclusive* upper bounds of the gaps around it.
const g_add_element =
    "140000001000010000000000000000000000000a780000000c0a01040100000000000000010000000b00010066696c74" ++
    "657200000c000200626c6f636b6564000800040000000001440003801800018008000300000000010c00018008000100" ++
    "00000000100002800c000180080001000a0000011800038008000300000000010c000180080001000a00000214000000" ++
    "1100010002000000000000000000000a";

// ### nft delete element inet filter blocked '{ 10.0.0.1 }' — against a
// *non-interval* set, unlike the add-element golden above: a single wire
// element, no synthetic INTERVAL_END neighbours.
const g_del_element =
    "140000001000010000000000000000000000000a400000000e0a01000100000000000000010000000b00010066696c7465" ++
    "7200000c000200626c6f636b65640014000380100001800c000180080001000a0000011400000011000100020000000000" ++
    "00000000000a";

// ### nft delete rule inet filter input handle 4
const g_del_rule =
    "140000001000010000000000000000000000000a38000000080a01000100000000000000010000000b00010066696c74" ++
    "657200000a000200696e7075740000000c0003000000000000000004140000001100010002000000000000000000000a";

// ### nft flush chain inet filter input — a handle-less DELRULE, table+chain
// only, same shape as delete-rule above minus NFTA_RULE_HANDLE.
const g_flush_chain =
    "140000001000010000000000000000000000000a2c000000080a01000100000000000000010000000b00010066696c7465" ++
    "7200000a000200696e707574000000140000001100010002000000000000000000000a";

// ### one `nft -f` run with three commands = ONE batch (the batch-framing proof):
// ###   add table inet multi
// ###   add chain inet multi c { type filter hook input priority 0; policy accept; }
// ###   add rule inet multi c tcp dport 22 accept
const g_multi_batch =
    "140000001000010000000000000000000000000a3c000000000a01000100000000000000010000000a0001006d756c74" ++
    "69000000080002000000000014000600010401010600020800000000693543d450000000030a01040200000000000000" ++
    "010000000a0001006d756c7469000000060003006300000008000500000000010b00070066696c746572000014000480" ++
    "080001000000000108000200000000000c010000060a010c0300000000000000010000000a0001006d756c7469000000" ++
    "0600020063000000e400048024000180090001006d657461000000001400028008000200000000100800010000000001" ++
    "2c00018008000100636d700020000280080001000000000108000200000000000c000380050001000600000034000180" ++
    "0c0001007061796c6f616400240002800800010000000001080002000000000208000300000000020800040000000002" ++
    "2c00018008000100636d700020000280080001000000000108000200000000000c000380060001000016000030000180" ++
    "0e000100696d6d6564696174650000001c0002800800010000000000100002800c000280080001000000000114000000" ++
    "1100010004000000000000000000000a";

// ── helpers ─────────────────────────────────────────────────────────────────

/// A batch framed exactly like `nft`: sequence numbers from 0, no `NLM_F_ACK`.
fn nftBatch() !wire.Batch {
    return wire.Batch.init(gpa, 0, .{ .ack = false });
}

// ── tests ───────────────────────────────────────────────────────────────────

test "golden: add table" {
    var b = try nftBatch();
    defer b.deinit();
    try b.addTable(.{
        .family = .inet,
        .name = "filter",
        .userdata = &nft_table_userdata,
    });
    try expectGolden(g_add_table, try b.finish());
}

test "golden: delete table" {
    var b = try nftBatch();
    defer b.deinit();
    try b.deleteTable(.inet, "filter");
    try expectGolden(g_del_table, try b.finish());
}

test "golden: add base chain with policy drop" {
    var b = try nftBatch();
    defer b.deinit();
    try b.addChain(.{
        .family = .inet,
        .table = "filter",
        .name = "input",
        .chain_type = .filter,
        .hook = .input,
        .prio = 0,
        .policy = .drop,
    });
    try expectGolden(g_add_chain, try b.finish());
}

test "golden: add nat base chain without a policy" {
    var b = try nftBatch();
    defer b.deinit();
    try b.addChain(.{
        .family = .ip,
        .table = "nat",
        .name = "post",
        .chain_type = .nat,
        .hook = .postrouting,
        .prio = 100,
    });
    try expectGolden(g_add_chain_nat, try b.finish());
}

test "golden: delete chain" {
    var b = try nftBatch();
    defer b.deinit();
    try b.deleteChain(.inet, "filter", "input2");
    try expectGolden(g_del_chain, try b.finish());
}

test "golden: rule — tcp dport 22 counter accept" {
    var p = expr.Program.init(gpa, .inet);
    defer p.deinit();
    _ = p.tcpDport(22).counter().accept();

    var b = try nftBatch();
    defer b.deinit();
    try b.addRule(.{
        .family = .inet,
        .table = "filter",
        .chain = "input",
        .exprs = try p.finish(),
    });
    try expectGolden(g_rule_tcp_dport, try b.finish());
}

test "golden: rule — tcp sport 22 counter accept" {
    var p = expr.Program.init(gpa, .inet);
    defer p.deinit();
    _ = p.tcpSport(22).counter().accept();

    var b = try nftBatch();
    defer b.deinit();
    try b.addRule(.{
        .family = .inet,
        .table = "filter",
        .chain = "input",
        .exprs = try p.finish(),
    });
    try expectGolden(g_rule_tcp_sport, try b.finish());
}

test "golden: rule — ip daddr 10.0.0.1 drop" {
    var p = expr.Program.init(gpa, .inet);
    defer p.deinit();
    _ = p.ipDaddr(.{ 10, 0, 0, 1 }).drop();

    var b = try nftBatch();
    defer b.deinit();
    try b.addRule(.{
        .family = .inet,
        .table = "filter",
        .chain = "input",
        .exprs = try p.finish(),
    });
    try expectGolden(g_rule_ip_daddr, try b.finish());
}

test "golden: ipv4Bytes(10,0,0,1) is byte-identical to the .{10,0,0,1} literal" {
    // ipv4Bytes had no call site anywhere in the module before this test —
    // reusing the exact golden above, but building the address through the
    // helper instead of a bare array literal, proves it wires into a real
    // rule correctly rather than merely compiling.
    var p = expr.Program.init(gpa, .inet);
    defer p.deinit();
    _ = p.ipDaddr(expr.ipv4Bytes(10, 0, 0, 1)).drop();

    var b = try nftBatch();
    defer b.deinit();
    try b.addRule(.{
        .family = .inet,
        .table = "filter",
        .chain = "input",
        .exprs = try p.finish(),
    });
    try expectGolden(g_rule_ip_daddr, try b.finish());
}

test "golden: rule — ip saddr 10.0.0.0/8 drop (byte-aligned prefix, no bitwise)" {
    var p = expr.Program.init(gpa, .inet);
    defer p.deinit();
    _ = p.ipSaddrPrefix(.{ 10, 0, 0, 0 }, 8).drop();

    var b = try nftBatch();
    defer b.deinit();
    try b.addRule(.{
        .family = .inet,
        .table = "filter",
        .chain = "input",
        .exprs = try p.finish(),
    });
    try expectGolden(g_rule_prefix8, try b.finish());
}

test "golden: rule — ip saddr 10.0.0.0/12 drop (bitwise mask/xor)" {
    var p = expr.Program.init(gpa, .inet);
    defer p.deinit();
    _ = p.ipSaddrPrefix(.{ 10, 0, 0, 0 }, 12).drop();

    var b = try nftBatch();
    defer b.deinit();
    try b.addRule(.{
        .family = .inet,
        .table = "filter",
        .chain = "input",
        .exprs = try p.finish(),
    });
    try expectGolden(g_rule_prefix12_bitwise, try b.finish());
}

test "golden: rule — ip saddr @blocked drop (set lookup)" {
    var p = expr.Program.init(gpa, .inet);
    defer p.deinit();
    _ = p.ipSaddrSet("blocked", 1, false).drop();

    var b = try nftBatch();
    defer b.deinit();
    try b.addRule(.{
        .family = .inet,
        .table = "filter",
        .chain = "input",
        .exprs = try p.finish(),
    });
    try expectGolden(g_rule_lookup, try b.finish());
}

test "golden: rule — ct state established,related accept" {
    var p = expr.Program.init(gpa, .inet);
    defer p.deinit();
    _ = p.ctStateAny(expr.CT_STATE.ESTABLISHED | expr.CT_STATE.RELATED).accept();

    var b = try nftBatch();
    defer b.deinit();
    try b.addRule(.{
        .family = .inet,
        .table = "filter",
        .chain = "input",
        .exprs = try p.finish(),
    });
    try expectGolden(g_rule_ct_state, try b.finish());
}

test "golden: rule — limit rate 10/second burst 5 packets accept" {
    var p = expr.Program.init(gpa, .inet);
    defer p.deinit();
    _ = p.limit(.{ .rate = 10, .burst = 5 }).accept();

    var b = try nftBatch();
    defer b.deinit();
    try b.addRule(.{
        .family = .inet,
        .table = "filter",
        .chain = "input",
        .exprs = try p.finish(),
    });
    try expectGolden(g_rule_limit, try b.finish());
}

test "golden: rule — log prefix \"ssh: \" level info" {
    var p = expr.Program.init(gpa, .inet);
    defer p.deinit();
    _ = p.log(.{ .prefix = "ssh: ", .level = .info });

    var b = try nftBatch();
    defer b.deinit();
    try b.addRule(.{
        .family = .inet,
        .table = "filter",
        .chain = "input",
        .exprs = try p.finish(),
    });
    try expectGolden(g_rule_log, try b.finish());
}

test "golden: rule — iifname \"lo\" accept (IFNAMSIZ-padded cmp)" {
    var p = expr.Program.init(gpa, .inet);
    defer p.deinit();
    _ = p.ifnameCmp(.iifname, .eq, "lo").accept();

    var b = try nftBatch();
    defer b.deinit();
    try b.addRule(.{
        .family = .inet,
        .table = "filter",
        .chain = "input",
        .exprs = try p.finish(),
    });
    try expectGolden(g_rule_iifname, try b.finish());
}

test "golden: rule — oifname \"eth0\" masquerade" {
    var p = expr.Program.init(gpa, .ip);
    defer p.deinit();
    _ = p.ifnameCmp(.oifname, .eq, "eth0").masquerade();

    var b = try nftBatch();
    defer b.deinit();
    try b.addRule(.{
        .family = .ip,
        .table = "nat",
        .chain = "post",
        .exprs = try p.finish(),
    });
    try expectGolden(g_rule_masquerade, try b.finish());
}

test "golden: rule — ip saddr 10.0.0.0/8 snat to 192.0.2.1" {
    var p = expr.Program.init(gpa, .ip);
    defer p.deinit();
    _ = p.ipSaddrPrefix(.{ 10, 0, 0, 0 }, 8)
        .nat(.snat, .ip, &.{ 192, 0, 2, 1 }, null, 0);

    var b = try nftBatch();
    defer b.deinit();
    try b.addRule(.{
        .family = .ip,
        .table = "nat",
        .chain = "post",
        .exprs = try p.finish(),
    });
    try expectGolden(g_rule_snat, try b.finish());
}

test "golden: rule — tcp dport 80 dnat to 10.0.0.5:8080 (two live registers)" {
    var p = expr.Program.init(gpa, .ip);
    defer p.deinit();
    _ = p.tcpDport(80).nat(.dnat, .ip, &.{ 10, 0, 0, 5 }, 8080, 0);

    var b = try nftBatch();
    defer b.deinit();
    try b.addRule(.{
        .family = .ip,
        .table = "nat",
        .chain = "post",
        .exprs = try p.finish(),
    });
    try expectGolden(g_rule_dnat, try b.finish());
}

test "golden: insert rule — no NLM_F_APPEND, unlike add rule" {
    var p = expr.Program.init(gpa, .inet);
    defer p.deinit();
    _ = p.counter().accept();

    var b = try nftBatch();
    defer b.deinit();
    try b.insertRule(.{
        .family = .inet,
        .table = "filter",
        .chain = "input",
        .exprs = try p.finish(),
    });
    const bytes = try b.finish();
    try expectGolden(g_insert_rule, bytes);

    // The byte-exact match above already proves NLM_F_APPEND is absent, but
    // spell it out: this is the one flag bit that distinguishes `insertRule`
    // from `addRule` (see both doc comments in wire.zig), so assert it
    // directly against the decoded header rather than only via opaque bytes.
    var it: nl.MessageIterator = .{ .buf = bytes };
    _ = try it.next(); // BATCH_BEGIN
    const cmd = (try it.next()).?;
    try testing.expectEqual(wire.nftMsg(wire.NFT_MSG.NEWRULE), cmd.type);
    try testing.expect(cmd.flags & nl.NLM_F_CREATE != 0);
    try testing.expect(cmd.flags & nl.NLM_F_APPEND == 0);
}

test "golden: add set (ipv4_addr, interval)" {
    var b = try nftBatch();
    defer b.deinit();
    try b.addSet(.{
        .family = .inet,
        .table = "filter",
        .name = "blocked",
        .key_type = .ipv4_addr,
        .flags = &.{.interval},
        .id = 1,
        .userdata = &nft_set_userdata_interval,
    });
    try expectGolden(g_add_set, try b.finish());
}

test "golden: delete set" {
    var b = try nftBatch();
    defer b.deinit();
    try b.deleteSet(.inet, "filter", "tmpset");
    try expectGolden(g_del_set, try b.finish());
}

test "golden: add element to an interval set (three wire elements)" {
    var b = try nftBatch();
    defer b.deinit();
    try b.addSetElems(.inet, "filter", "blocked", 1, &.{
        .{ .key = &.{ 0, 0, 0, 0 }, .flags = wire.NFT_SET_ELEM_INTERVAL_END },
        .{ .key = &.{ 10, 0, 0, 1 } },
        .{ .key = &.{ 10, 0, 0, 2 }, .flags = wire.NFT_SET_ELEM_INTERVAL_END },
    });
    try expectGolden(g_add_element, try b.finish());
}

test "golden: delete element from a non-interval set (one wire element)" {
    var b = try nftBatch();
    defer b.deinit();
    try b.deleteSetElems(.inet, "filter", "blocked", &.{
        .{ .key = &.{ 10, 0, 0, 1 } },
    });
    try expectGolden(g_del_element, try b.finish());
}

test "golden: delete rule by handle" {
    var b = try nftBatch();
    defer b.deinit();
    try b.deleteRule(.inet, "filter", "input", 4);
    try expectGolden(g_del_rule, try b.finish());
}

test "golden: flush chain — handle-less DELRULE" {
    var b = try nftBatch();
    defer b.deinit();
    try b.flushChain(.inet, "filter", "input");
    try expectGolden(g_flush_chain, try b.finish());
}

test "golden: one multi-command batch (table + chain + rule in a single sendmsg)" {
    var p = expr.Program.init(gpa, .inet);
    defer p.deinit();
    _ = p.tcpDport(22).accept();

    var b = try nftBatch();
    defer b.deinit();
    try b.addTable(.{ .family = .inet, .name = "multi", .userdata = &nft_table_userdata });
    try b.addChain(.{
        .family = .inet,
        .table = "multi",
        .name = "c",
        .chain_type = .filter,
        .hook = .input,
        .prio = 0,
        .policy = .accept,
    });
    try b.addRule(.{
        .family = .inet,
        .table = "multi",
        .chain = "c",
        .exprs = try p.finish(),
    });
    const bytes = try b.finish();
    try expectGolden(g_multi_batch, bytes);

    // …and the framing invariants the golden encodes, stated explicitly.
    try testing.expectEqual(@as(usize, 3), b.commandCount());
    var it: nl.MessageIterator = .{ .buf = bytes };
    var seqs: [5]u32 = undefined;
    var kinds: [5]u16 = undefined;
    var n: usize = 0;
    while (try it.next()) |m| : (n += 1) {
        seqs[n] = m.seq;
        kinds[n] = m.type;
    }
    try testing.expectEqual(@as(usize, 5), n);
    try testing.expectEqualSlices(u32, &.{ 0, 1, 2, 3, 4 }, &seqs);
    try testing.expectEqual(wire.NFNL_MSG_BATCH_BEGIN, kinds[0]);
    try testing.expectEqual(wire.nftMsg(wire.NFT_MSG.NEWTABLE), kinds[1]);
    try testing.expectEqual(wire.nftMsg(wire.NFT_MSG.NEWCHAIN), kinds[2]);
    try testing.expectEqual(wire.nftMsg(wire.NFT_MSG.NEWRULE), kinds[3]);
    try testing.expectEqual(wire.NFNL_MSG_BATCH_END, kinds[4]);
    // Attribution: seq 2 is the chain command, seq 0 is the commit stage.
    try testing.expectEqualStrings("NEWCHAIN", b.entryForSeq(2).?.commandName());
    try testing.expectEqual(wire.Stage.commit, b.stageForSeq(0));
}

// ── set datatype ids ────────────────────────────────────────────────────────
//
// `NFTA_SET_KEY_TYPE` is a *userspace* number the kernel stores and returns
// untouched, so it cannot be read off a UAPI header. These were read off
// `unshare -rn strace … nft add set inet t s '{ type <t>; }'`, one run per
// type, and are what `types.SetDataType.id()` encodes.

test "golden: set datatype ids and key lengths match nft's captures" {
    const cases = .{
        .{ types.SetDataType.ipv4_addr, 7, 4 },
        .{ types.SetDataType.ipv6_addr, 8, 16 },
        .{ types.SetDataType.ether_addr, 9, 6 },
        .{ types.SetDataType.inet_proto, 12, 1 },
        .{ types.SetDataType.inet_service, 13, 2 },
        .{ types.SetDataType.mark, 19, 4 },
        .{ types.SetDataType.ifname, 41, 16 },
    };
    inline for (cases) |c| {
        try testing.expectEqual(@as(u32, c[1]), c[0].id());
        try testing.expectEqual(@as(u32, c[2]), c[0].keyLen());
    }
}

// ### nft add set inet t s_to '{ type ipv4_addr; flags timeout; timeout 10s; size 1024; }'
//
// Not a byte golden: the captured NEWSET carries nft's userdata stamp, and
// dropping it would change the enclosing `nlmsg_len`, i.e. re-encode the
// capture. What the capture *pins* is the attribute values, so those are
// asserted directly — `NFTA_SET_FLAGS = 0x10` (NFT_SET_TIMEOUT),
// `NFTA_SET_DESC{ SIZE = 0x400 }` and `NFTA_SET_TIMEOUT = 0x2710`
// (**milliseconds**, for a `10s` timeout).
test "golden values: set with size + timeout (NFTA_SET_DESC + NFTA_SET_TIMEOUT)" {
    var b = try nftBatch();
    defer b.deinit();
    try b.addSet(.{
        .family = .inet,
        .table = "t",
        .name = "s_to",
        .key_type = .ipv4_addr,
        .flags = &.{.timeout},
        .id = 1,
        .size = 1024,
        .timeout_ms = 10_000,
    });
    const bytes = try b.finish();

    var it: nl.MessageIterator = .{ .buf = bytes };
    _ = try it.next(); // BATCH_BEGIN
    const m = (try it.next()).?;
    try testing.expectEqual(wire.nftMsg(wire.NFT_MSG.NEWSET), m.type);
    const s = try wire.decodeSet(m.payload);
    try testing.expectEqualStrings("t", s.table);
    try testing.expectEqualStrings("s_to", s.name);
    try testing.expectEqual(@as(u32, 0x10), s.flags);
    try testing.expectEqual(@as(u32, 7), s.key_type);
    try testing.expectEqual(@as(u32, 4), s.key_len);
    try testing.expectEqual(@as(?u32, 0x400), s.size);
    try testing.expectEqual(@as(?u64, 0x2710), s.timeout_ms);

    // …and the attribute order the capture showed: TABLE, NAME, FLAGS,
    // KEY_TYPE, KEY_LEN, ID, DESC, TIMEOUT.
    const hdr = try wire.parseNfgenmsg(m.payload);
    var a = hdr.attrIterator();
    var order: [8]u16 = undefined;
    var n: usize = 0;
    while (try a.next()) |attr| : (n += 1) order[n] = attr.type;
    try testing.expectEqual(@as(usize, 8), n);
    try testing.expectEqualSlices(u16, &.{
        wire.NFTA_SET.TABLE,
        wire.NFTA_SET.NAME,
        wire.NFTA_SET.FLAGS,
        wire.NFTA_SET.KEY_TYPE,
        wire.NFTA_SET.KEY_LEN,
        wire.NFTA_SET.ID,
        wire.NFTA_SET.DESC,
        wire.NFTA_SET.TIMEOUT,
    }, &order);
}
