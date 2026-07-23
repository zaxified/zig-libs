// SPDX-License-Identifier: MIT

//! Byte-exact frames captured from **real traffic between two independent
//! third-party implementations**, recorded through a TPKT-aware proxy sitting
//! between an S7 client and an S7 server that are not this module.
//!
//! Two stacks appear here:
//!
//! * `.snap7_c` — the `snap7` C library (Davide Nardella), driven through its
//!   Python binding, client and server both. This is the reference S7
//!   implementation everything else in the field is checked against.
//! * `.snap7_py` — a second, independently written pure-Python S7 stack. Only
//!   its connection handshake is kept, because it orders the COTP parameters
//!   differently and that difference is worth pinning.
//!
//! Both were used **as black boxes only** — to generate wire traffic and to
//! act as a live peer. No third-party source was read as a design reference;
//! under CONVENTIONS §5 that is a test oracle, not a design reference. See
//! SPEC.md.
//!
//! Three assertions run over the whole table:
//!
//! 1. every frame decodes (TPKT, COTP, and for a DT also the S7 PDU, with the
//!    parameter and data lengths accounting exactly for the octets present);
//! 2. every frame **re-encodes to the identical octets** — and for a Read/Write
//!    Var request the parameter block is rebuilt from the *decoded items*
//!    through `vars.encodeRequest`, so the item encoder is what is being
//!    checked and not a memcpy;
//! 3. a representative subset is asserted field by field.

const std = @import("std");
const tpkt = @import("tpkt.zig");
const cotp = @import("cotp.zig");
const s7 = @import("s7.zig");
const items = @import("items.zig");
const vars = @import("vars.zig");
const userdata = @import("userdata.zig");

pub const Direction = enum { to_plc, from_plc };
pub const Source = enum { snap7_c, snap7_py };

pub const Golden = struct {
    name: []const u8,
    dir: Direction,
    source: Source,
    hex: []const u8,
};

/// Largest captured frame, and therefore the buffer every test here needs.
pub const max_frame_len: usize = 512;

pub const table = [_]Golden{
    .{ .name = "connect rack0 slot1 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001611e00000000100c0010ac1020100c2020101" },
    .{ .name = "connect rack0 slot1 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001611d00001000100c0010ac1020100c2020101" },
    .{ .name = "connect rack0 slot1 request 2", .dir = .to_plc, .source = .snap7_c, .hex = "0300001902f08032010000000000080000f0000001000101e0" },
    .{ .name = "connect rack0 slot1 reply 2", .dir = .from_plc, .source = .snap7_c, .hex = "0300001b02f080320300000000000800000000f0000001000101e0" },
    .{ .name = "db write db1 start20 4 bytes 12345678 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002702f080320100000100000e00080501120a100200040001840000a00004002012345678" },
    .{ .name = "db write db1 start20 4 bytes 12345678 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001602f0803203000001000002000100000501ff" },
    .{ .name = "db read db1 start20 len4 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000200000e00000401120a100200040001840000a0" },
    .{ .name = "db read db1 start20 len4 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001d02f0803203000002000002000800000401ff04002012345678" },
    .{ .name = "db write db1 start0 len1 a5 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002402f080320100000300000e00050501120a1002000100018400000000040008a5" },
    .{ .name = "db write db1 start0 len1 a5 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001602f0803203000003000002000100000501ff" },
    .{ .name = "db read db1 start0 len1 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000400000e00000401120a10020001000184000000" },
    .{ .name = "db read db1 start0 len1 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001a02f0803203000004000002000500000401ff040008a5" },
    .{ .name = "db read db2 start0 len32 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000500000e00000401120a10020020000284000000" },
    .{ .name = "db read db2 start0 len32 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300003902f0803203000005000002002400000401ff0401000000000000000000000000000000000000000000000000000000000000000000" },
    .{ .name = "read area mk start0 len8 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000600000e00000401120a10020008000083000000" },
    .{ .name = "read area mk start0 len8 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300002102f0803203000006000002000c00000401ff0400400000000000000000" },
    .{ .name = "write area mk start4 len2 dead request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002502f080320100000700000e00060501120a1002000200008300002000040010dead" },
    .{ .name = "write area mk start4 len2 dead reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001602f0803203000007000002000100000501ff" },
    .{ .name = "read area pe start0 len4 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000800000e00000401120a10020004000081000000" },
    .{ .name = "read area pe start0 len4 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001d02f0803203000008000002000800000401ff04002000000000" },
    .{ .name = "read area pa start0 len4 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000900000e00000401120a10020004000082000000" },
    .{ .name = "read area pa start0 len4 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001d02f0803203000009000002000800000401ff04002000000000" },
    .{ .name = "read area ct start0 count2 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000a00000e00000401120a101c000200001c000000" },
    .{ .name = "read area ct start0 count2 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001d02f080320300000a000002000800000401ff09000400000000" },
    .{ .name = "read area tm start0 count2 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000b00000e00000401120a101d000200001d000000" },
    .{ .name = "read area tm start0 count2 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001d02f080320300000b000002000800000401ff09000400000000" },
    .{ .name = "read multi vars 3 items request", .dir = .to_plc, .source = .snap7_c, .hex = "0300003702f080320100000c00002600000403120a100200040001840000a0120a10020002000083000000120a10020008000284000040" },
    .{ .name = "read multi vars 3 items reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300002f02f080320300000c000002001a00000403ff04002012345678ff0400100000ff0400400000000000000000" },
    .{ .name = "db read missing db77 item error request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000d00000e00000401120a10020004004d84000000" },
    .{ .name = "db read missing db77 item error reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001902f080320300000d0000020004000004010a000004" },
    .{ .name = "db read db1 start250 len32 out of range request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000e00000e00000401120a100200200001840007d0" },
    .{ .name = "db read db1 start250 len32 out of range reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001902f080320300000e00000200040000040105000004" },
    .{ .name = "read szl 0x0011 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002102f080320700000f00000800080001120411440100ff09000400110000" },
    .{ .name = "read szl 0x0011 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300009902f080320700000f00000c007c000112081284010000000000ff09007800110000001c0004000136455337203331352d32454831342d304142302000c000040001000636455337203331352d32454831342d304142302000c0000400010007202020202020202020202020202020202020202000c0560302060081426f6f74204c6f61646572202020202020202020000041200909" },
    .{ .name = "read szl 0x001c request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002102f080320700001000000800080001120411440100ff090004001c0000" },
    .{ .name = "read szl 0x001c reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300017d02f080320700001000000c0160000112081284010000000000ff09015c001c00000022000a0001534e4150372d53455256455200000000000000000000000000000000000000000002435055203331352d3220504e2f445000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000000044f726967696e616c205369656d656e732045717569706d656e7400000000000000055320432d433255523238393232303132000000000000000000000000000000000007435055203331352d3220504e2f4450000000000000000000000000000000000000084d4d4320323637464631314600000000000000000000000000000000000000000009002af60000010000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000000b0000000000000000000000000000000000000000000000000000000000000000" },
    .{ .name = "read szl 0x0132 index 4 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002102f080320700001100000800080001120411440100ff09000401320004" },
    .{ .name = "read szl 0x0132 index 4 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300005102f080320700001100000c0034000112081284010000000000ff0900300132000400280001000400010000000100020000000056561001337b020075f402000000000000000000000000000000" },
    .{ .name = "get cpu state request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002102f080320700001200000800080001120411440100ff09000404240000" },
    .{ .name = "get cpu state reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300003d02f080320700001200000c0020000112081284010000000000ff09001c04240000001400015144ff0800000000000000002607230627350004" },
    .{ .name = "get cpu info request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002102f080320700001300000800080001120411440100ff090004001c0000" },
    .{ .name = "get cpu info reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300017d02f080320700001300000c0160000112081284010000000000ff09015c001c00000022000a0001534e4150372d53455256455200000000000000000000000000000000000000000002435055203331352d3220504e2f445000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000000044f726967696e616c205369656d656e732045717569706d656e7400000000000000055320432d433255523238393232303132000000000000000000000000000000000007435055203331352d3220504e2f4450000000000000000000000000000000000000084d4d4320323637464631314600000000000000000000000000000000000000000009002af60000010000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000000b0000000000000000000000000000000000000000000000000000000000000000" },
    .{ .name = "plc stop request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002102f0803201000014000010000029000000000009505f50524f4752414d" },
    .{ .name = "plc stop reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001402f08032030000140000010000000029" },
    .{ .name = "plc hot start request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002502f0803201000015000014000028000000000000fd000009505f50524f4752414d" },
    .{ .name = "plc hot start reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001402f08032030000150000010000000028" },
    .{ .name = "plc cold start request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002702f0803201000016000016000028000000000000fd0002432009505f50524f4752414d" },
    .{ .name = "plc cold start reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001402f08032030000160000010000000028" },
    .{ .name = "connect rack1 slot2 tsap 0x0122 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001611e00000000100c0010ac1020100c2020122" },
    .{ .name = "connect rack1 slot2 tsap 0x0122 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001611d00001000100c0010ac1020100c2020122" },
    .{ .name = "connect rack1 slot2 tsap 0x0122 request 2", .dir = .to_plc, .source = .snap7_c, .hex = "0300001902f08032010000000000080000f0000001000101e0" },
    .{ .name = "connect rack1 slot2 tsap 0x0122 reply 2", .dir = .from_plc, .source = .snap7_c, .hex = "0300001b02f080320300000000000800000000f0000001000101e0" },
    .{ .name = "write byte db1 0 a5 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002402f080320100000100000e00050501120a1002000100018400000000040008a5" },
    .{ .name = "write byte db1 0 a5 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001602f0803203000001000002000100000501ff" },
    .{ .name = "read bit db1 dbx0 0 wordlen bit request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000200000e00000401120a10010001000184000000" },
    .{ .name = "read bit db1 dbx0 0 wordlen bit reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001a02f0803203000002000002000500000401ff03000101" },
    .{ .name = "read bit db1 dbx0 2 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000300000e00000401120a10010001000184000002" },
    .{ .name = "read bit db1 dbx0 2 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001a02f0803203000003000002000500000401ff03000101" },
    .{ .name = "write bit mk 10 2 1 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002402f080320100000400000e00050501120a100100010000830000520003000101" },
    .{ .name = "write bit mk 10 2 1 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001602f0803203000004000002000100000501ff" },
    .{ .name = "read bit mk 10 2 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000500000e00000401120a10010001000083000052" },
    .{ .name = "read bit mk 10 2 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001a02f0803203000005000002000500000401ff03000101" },
    .{ .name = "read word db1 index 10 count 2 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000600000e00000401120a10040002000184000050" },
    .{ .name = "read word db1 index 10 count 2 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001d02f0803203000006000002000800000401ff04002000000000" },
    .{ .name = "read dword db1 index 4 count 1 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000700000e00000401120a10060001000184000020" },
    .{ .name = "read dword db1 index 4 count 1 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001d02f0803203000007000002000800000401ff04002000000000" },
    .{ .name = "read real db1 index 4 count 2 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000800000e00000401120a10080002000184000020" },
    .{ .name = "read real db1 index 4 count 2 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300002102f0803203000008000002000c00000401ff0700080000000000000000" },
    .{ .name = "write real db1 index 0 count 1 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002702f080320100000900000e00080501120a100800010001840000000007000441200000" },
    .{ .name = "write real db1 index 0 count 1 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001602f0803203000009000002000100000501ff" },
    .{ .name = "read counter ct 0 count 2 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000a00000e00000401120a101c000200001c000000" },
    .{ .name = "read counter ct 0 count 2 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001d02f080320300000a000002000800000401ff09000400000000" },
    .{ .name = "write counter ct 0 count 1 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002502f080320100000b00000e00060501120a101c000100001c000000000900020123" },
    .{ .name = "write counter ct 0 count 1 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001602f080320300000b000002000100000501ff" },
    .{ .name = "read timer tm 0 count 2 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000c00000e00000401120a101d000200001d000000" },
    .{ .name = "read timer tm 0 count 2 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001d02f080320300000c000002000800000401ff09000400000000" },
    .{ .name = "db read db9 0 len 600 splits over 480 byte pdu request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000d00000e00000401120a100201ce000984000000" },
    .{ .name = "db read db9 0 len 600 splits over 480 byte pdu reply", .dir = .from_plc, .source = .snap7_c, .hex = "030001e702f080320300000d00000201d200000401ff040e70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" },
    .{ .name = "db read db9 0 len 600 splits over 480 byte pdu request 2", .dir = .to_plc, .source = .snap7_c, .hex = "0300001f02f080320100000e00000e00000401120a1002008a000984000e70" },
    .{ .name = "db read db9 0 len 600 splits over 480 byte pdu reply 2", .dir = .from_plc, .source = .snap7_c, .hex = "030000a302f080320300000e000002008e00000401ff040450000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" },
    .{ .name = "prologue request", .dir = .to_plc, .source = .snap7_c, .hex = "0300001611e00000000100c0010ac1020100c2020101" },
    .{ .name = "prologue reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001611d00001000100c0010ac1020100c2020101" },
    .{ .name = "prologue request 2", .dir = .to_plc, .source = .snap7_c, .hex = "0300001902f08032010000000000080000f0000001000101e0" },
    .{ .name = "prologue reply 2", .dir = .from_plc, .source = .snap7_c, .hex = "0300001b02f080320300000000000800000000f0000001000101e0" },
    .{ .name = "seed db1 0 15 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300003302f080320100000100000e00140501120a1002001000018400000000040080000102030405060708090a0b0c0d0e0f" },
    .{ .name = "seed db1 0 15 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001602f0803203000001000002000100000501ff" },
    .{ .name = "read multi vars odd lengths 1 3 2 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300003702f080320100000200002600000403120a10020001000184000000120a10020003000184000020120a10020002000083000000" },
    .{ .name = "read multi vars odd lengths 1 3 2 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300002902f0803203000002000002001400000403ff0400080000ff040018040506baff0400100000" },
    .{ .name = "write multi vars odd lengths 1 3 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300003802f080320100000300001a000d0502120a10020001000184000100120a1002000300018400014000040008aa0200040018b1b2b3" },
    .{ .name = "write multi vars odd lengths 1 3 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001702f0803203000003000002000200000502ffff" },
    .{ .name = "read multi vars with one bad item db77 one good request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002b02f080320100000400001a00000402120a10020002004d84000000120a10020002000184000000" },
    .{ .name = "read multi vars with one bad item db77 one good reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300001f02f0803203000004000002000a000004020a000004ff0400100001" },
    .{ .name = "prologue request 3", .dir = .to_plc, .source = .snap7_c, .hex = "0300001611e00000000100c0010ac1020100c2020101" },
    .{ .name = "prologue reply 3", .dir = .from_plc, .source = .snap7_c, .hex = "0300001611d00001000100c0010ac1020100c2020101" },
    .{ .name = "prologue request 4", .dir = .to_plc, .source = .snap7_c, .hex = "0300001902f08032010000000000080000f0000001000101e0" },
    .{ .name = "prologue reply 4", .dir = .from_plc, .source = .snap7_c, .hex = "0300001b02f080320300000000000800000000f0000001000101e0" },
    .{ .name = "szl 0424 while run request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002102f080320700000100000800080001120411440100ff09000404240000" },
    .{ .name = "szl 0424 while run reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300003d02f080320700000100000c0020000112081284010000000000ff09001c04240000001400015144ff0800000000000000002607230650400004" },
    .{ .name = "plc stop request 2", .dir = .to_plc, .source = .snap7_c, .hex = "0300002102f0803201000002000010000029000000000009505f50524f4752414d" },
    .{ .name = "plc stop reply 2", .dir = .from_plc, .source = .snap7_c, .hex = "0300001402f08032030000020000010000000029" },
    .{ .name = "szl 0424 while stop request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002102f080320700000300000800080001120411440100ff09000404240000" },
    .{ .name = "szl 0424 while stop reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300003d02f080320700000300000c0020000112081284010000000000ff09001c04240000001400015144ff0400000000000000002607230650400004" },
    .{ .name = "plc hot start request 2", .dir = .to_plc, .source = .snap7_c, .hex = "0300002502f0803201000004000014000028000000000000fd000009505f50524f4752414d" },
    .{ .name = "plc hot start reply 2", .dir = .from_plc, .source = .snap7_c, .hex = "0300001402f08032030000040000010000000028" },
    .{ .name = "szl 0424 after restart request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002102f080320700000500000800080001120411440100ff09000404240000" },
    .{ .name = "szl 0424 after restart reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300003d02f080320700000500000c0020000112081284010000000000ff09001c04240000001400015144ff0800000000000000002607230650410004" },
    .{ .name = "szl 0011 index 0 request", .dir = .to_plc, .source = .snap7_c, .hex = "0300002102f080320700000600000800080001120411440100ff09000400110000" },
    .{ .name = "szl 0011 index 0 reply", .dir = .from_plc, .source = .snap7_c, .hex = "0300009902f080320700000600000c007c000112081284010000000000ff09007800110000001c0004000136455337203331352d32454831342d304142302000c000040001000636455337203331352d32454831342d304142302000c0000400010007202020202020202020202020202020202020202000c0560302060081426f6f74204c6f61646572202020202020202020000041200909" },
    .{ .name = "connect rack0 slot1 request 3", .dir = .to_plc, .source = .snap7_py, .hex = "0300001611e00000000100c1020100c2020101c0010a" },
    .{ .name = "connect rack0 slot1 reply 3", .dir = .from_plc, .source = .snap7_py, .hex = "0300000b06d00001000100" },
    .{ .name = "connect rack0 slot1 request 4", .dir = .to_plc, .source = .snap7_py, .hex = "0300001902f08032010000000100080000f0000001000101e0" },
    .{ .name = "connect rack0 slot1 reply 4", .dir = .from_plc, .source = .snap7_py, .hex = "0300001b02f080320300000001000800000000f0000001000101e0" },
    // The second stack's COTP disconnect. Note the octet past the length
    // indicator: a DR carries no user data, so that is the sending stack's
    // stray padding — which is why the re-encode assertion below compares
    // `1 + LI` octets rather than the whole packet.
    .{ .name = "cotp disconnect request", .dir = .to_plc, .source = .snap7_py, .hex = "0300000c0680000100010000" },
};

/// Looks a golden up by name; the field-level tests use it so a renamed or
/// dropped capture fails loudly instead of silently reducing coverage.
pub fn get(name: []const u8) []const u8 {
    for (&table) |g| {
        if (std.mem.eql(u8, g.name, name)) return g.hex;
    }
    @panic("no such golden");
}

fn bytes(hex: []const u8, out: []u8) []const u8 {
    return std.fmt.hexToBytes(out, hex) catch unreachable;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "every captured frame decodes" {
    var buf: [max_frame_len]u8 = undefined;
    for (&table) |g| {
        const frame = bytes(g.hex, &buf);
        const pkt = tpkt.decode(frame) catch |e| {
            std.debug.print("tpkt decode failed for \"{s}\": {t}\n", .{ g.name, e });
            return e;
        };
        try testing.expectEqual(frame.len, pkt.total_len);
        const tpdu = cotp.decode(pkt.payload) catch |e| {
            std.debug.print("cotp decode failed for \"{s}\": {t}\n", .{ g.name, e });
            return e;
        };
        switch (tpdu) {
            .dt => |dt| {
                const pdu = s7.decode(dt.payload) catch |e| {
                    std.debug.print("s7 decode failed for \"{s}\": {t}\n", .{ g.name, e });
                    return e;
                };
                // The lengths must account for exactly the octets present.
                try testing.expectEqual(dt.payload.len, pdu.total_len);
            },
            else => {},
        }
    }
}

test "every captured frame re-encodes to the identical octets" {
    var buf: [max_frame_len]u8 = undefined;
    var body: [max_frame_len]u8 = undefined;
    var out: [max_frame_len]u8 = undefined;
    for (&table) |g| {
        const frame = bytes(g.hex, &buf);
        const pkt = try tpkt.decode(frame);
        const tpdu = try cotp.decode(pkt.payload);
        const rebuilt: []const u8 = switch (tpdu) {
            .cr, .cc => |c| try cotp.encodeConnectVerbatim(c, &body),
            .dr => |d| {
                // A DR carries no user data, so only `1 + LI` octets are the
                // TPDU; one captured peer appends a stray octet after them.
                const li: usize = pkt.payload[0];
                try testing.expectEqualSlices(
                    u8,
                    pkt.payload[0 .. 1 + li],
                    try cotp.encodeDisconnect(d, &body),
                );
                continue;
            },
            .dt => |dt| blk: {
                var pdu_buf: [max_frame_len]u8 = undefined;
                const pdu = try s7.decode(dt.payload);
                const again = try s7.encode(pdu.header, pdu.parameters, pdu.data, &pdu_buf);
                try testing.expectEqualSlices(u8, dt.payload, again);
                break :blk try cotp.encodeData(.{ .payload = again }, &body);
            },
            else => continue,
        };
        const whole = try tpkt.encode(rebuilt, &out);
        testing.expectEqualSlices(u8, frame, whole) catch |e| {
            std.debug.print("re-encode mismatch for \"{s}\"\n", .{g.name});
            return e;
        };
    }
}

test "every Read/Write Var request rebuilds from its decoded items" {
    var buf: [max_frame_len]u8 = undefined;
    var params: [max_frame_len]u8 = undefined;
    var seen: usize = 0;
    for (&table) |g| {
        if (g.dir != .to_plc) continue;
        const frame = bytes(g.hex, &buf);
        const tpdu = cotp.decode((try tpkt.decode(frame)).payload) catch continue;
        const dt = switch (tpdu) {
            .dt => |d| d,
            else => continue,
        };
        const pdu = try s7.decode(dt.payload);
        if (pdu.header.rosctr != .job or pdu.parameters.len < 2) continue;
        const req = vars.decodeRequest(pdu.parameters) catch continue;
        var list: [vars.max_items]items.Item = undefined;
        var it = req.iterator();
        var n: usize = 0;
        while (try it.next()) |item| : (n += 1) list[n] = item;
        const again = try vars.encodeRequest(req.function, list[0..n], &params);
        try testing.expectEqualSlices(u8, pdu.parameters, again);
        seen += 1;
    }
    // The capture really does contain variable accesses; a table that lost
    // them would otherwise pass this test vacuously.
    try testing.expect(seen >= 30);
}

test "the capture covers the frame kinds this module claims to handle" {
    var buf: [max_frame_len]u8 = undefined;
    var saw_cr = false;
    var saw_cc = false;
    var saw_dr = false;
    var saw_setup = false;
    var saw_read = false;
    var saw_write = false;
    var saw_userdata = false;
    var saw_item_error = false;
    var saw_multi_item = false;
    var saw_control = false;
    var areas = std.EnumSet(items.Area).initEmpty();
    var sizes = std.EnumSet(items.TransportSize).initEmpty();

    for (&table) |g| {
        const frame = bytes(g.hex, &buf);
        const pkt = try tpkt.decode(frame);
        switch (try cotp.decode(pkt.payload)) {
            .cr => saw_cr = true,
            .cc => saw_cc = true,
            .dr => saw_dr = true,
            .dt => |dt| {
                const pdu = try s7.decode(dt.payload);
                if (pdu.header.rosctr == .userdata) saw_userdata = true;
                if (pdu.parameters.len == 0) continue;
                switch (@as(s7.Function, @enumFromInt(pdu.parameters[0]))) {
                    .setup_communication => saw_setup = true,
                    .plc_stop, .pi_service => saw_control = true,
                    .read_var, .write_var => |f| {
                        if (f == .read_var) saw_read = true else saw_write = true;
                        if (pdu.header.rosctr == .job) {
                            const req = try vars.decodeRequest(pdu.parameters);
                            if (req.count > 1) saw_multi_item = true;
                            var it = req.iterator();
                            while (try it.next()) |item| {
                                areas.insert(item.area);
                                sizes.insert(item.transport_size);
                            }
                        } else if (f == .read_var) {
                            // Only a Read Var reply carries data items; a
                            // Write Var reply's data block is bare return codes.
                            const rep = try vars.decodeReply(pdu.parameters);
                            var di = items.DataItemIterator.init(pdu.data, rep.count);
                            while (try di.next()) |d| {
                                if (!d.return_code.isSuccess()) saw_item_error = true;
                            }
                        }
                    },
                    else => {},
                }
            },
            else => {},
        }
    }
    try testing.expect(saw_cr and saw_cc and saw_dr);
    try testing.expect(saw_setup and saw_read and saw_write and saw_userdata);
    try testing.expect(saw_item_error and saw_multi_item and saw_control);
    // Every area the reference stack was driven through.
    for ([_]items.Area{ .db, .flags, .inputs, .outputs, .counter, .timer }) |a| {
        try testing.expect(areas.contains(a));
    }
    // Every transport size that appeared on the wire.
    for ([_]items.TransportSize{ .bit, .byte, .word, .dword, .real, .counter, .timer }) |t| {
        try testing.expect(sizes.contains(t));
    }
}

test "the rack/slot TSAP survives a round trip in both captures" {
    var buf: [max_frame_len]u8 = undefined;
    // rack 0, slot 1 -> 0x0101.
    const a = (try cotp.decode((try tpkt.decode(
        bytes(get("connect rack0 slot1 request"), &buf),
    )).payload)).cr;
    try testing.expectEqual(@as(u16, 0x0101), a.dst_tsap.?.value);
    try testing.expectEqual(@as(u3, 0), a.dst_tsap.?.rack());
    try testing.expectEqual(@as(u5, 1), a.dst_tsap.?.slot());
    try testing.expectEqual(cotp.TpduSize.size_1024, a.tpdu_size.?);

    // rack 1, slot 2 -> 1 * 0x20 + 2 = 0x22.
    var buf2: [max_frame_len]u8 = undefined;
    const b = (try cotp.decode((try tpkt.decode(
        bytes(get("connect rack1 slot2 tsap 0x0122 request"), &buf2),
    )).payload)).cr;
    try testing.expectEqual(@as(u16, 0x0122), b.dst_tsap.?.value);
    try testing.expectEqual(@as(u3, 1), b.dst_tsap.?.rack());
    try testing.expectEqual(@as(u5, 2), b.dst_tsap.?.slot());
}

test "the second stack orders the COTP parameters differently and still decodes" {
    var buf: [max_frame_len]u8 = undefined;
    var found = false;
    for (&table) |g| {
        if (g.source != .snap7_py) continue;
        const tpdu = try cotp.decode((try tpkt.decode(bytes(g.hex, &buf))).payload);
        switch (tpdu) {
            .cr => |cr| {
                // src TSAP first, then dst, then the TPDU size — the opposite
                // of the C stack's order.
                try testing.expectEqual(@as(u8, 0xC1), cr.variable_part[0]);
                try testing.expectEqual(@as(u16, 0x0101), cr.dst_tsap.?.value);
                found = true;
            },
            else => {},
        }
    }
    try testing.expect(found);
}

test "the setup negotiation is 480 octets in both directions" {
    var buf: [max_frame_len]u8 = undefined;
    for ([_][]const u8{
        "connect rack0 slot1 request 2",
        "connect rack0 slot1 reply 2",
    }) |name| {
        const dt = (try cotp.decode((try tpkt.decode(bytes(get(name), &buf))).payload)).dt;
        const pdu = try s7.decode(dt.payload);
        const setup = try s7.Setup.decode(pdu.parameters);
        try testing.expectEqual(@as(u16, 480), setup.pdu_length);
        try testing.expectEqual(@as(u16, 1), setup.max_amq_calling);
    }
}

test "the DB1.DBW20 read is a bit address of 160 and returns 32 bits of payload" {
    var buf: [max_frame_len]u8 = undefined;
    const req = (try cotp.decode((try tpkt.decode(
        bytes(get("db read db1 start20 len4 request"), &buf),
    )).payload)).dt;
    const pdu = try s7.decode(req.payload);
    const parsed = try vars.decodeRequest(pdu.parameters);
    var it = parsed.iterator();
    const item = (try it.next()).?;
    try testing.expectEqual(items.Area.db, item.area);
    try testing.expectEqual(@as(u16, 1), item.db_number);
    try testing.expectEqual(@as(u24, 20 * 8), item.address);
    try testing.expectEqual(@as(u32, 20), item.byteOffset());
    try testing.expectEqual(@as(u16, 4), item.count);

    var buf2: [max_frame_len]u8 = undefined;
    const rep = (try cotp.decode((try tpkt.decode(
        bytes(get("db read db1 start20 len4 reply"), &buf2),
    )).payload)).dt;
    const rpdu = try s7.decode(rep.payload);
    const rparsed = try vars.decodeReply(rpdu.parameters);
    try testing.expectEqual(@as(u8, 1), rparsed.count);
    var di = items.DataItemIterator.init(rpdu.data, 1);
    const d = (try di.next()).?;
    try testing.expect(d.return_code.isSuccess());
    try testing.expectEqual(items.DataTransportSize.byte_word_dword, d.transport_size);
    try testing.expectEqual(@as(u16, 32), d.raw_length); // bits, not bytes
    try testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34, 0x56, 0x78 }, d.payload);
}

test "the bit read reply is bit-counted and the real read reply is byte-counted" {
    var buf: [max_frame_len]u8 = undefined;
    const bit = (try cotp.decode((try tpkt.decode(
        bytes(get("read bit db1 dbx0 0 wordlen bit reply"), &buf),
    )).payload)).dt;
    var di = items.DataItemIterator.init((try s7.decode(bit.payload)).data, 1);
    const b = (try di.next()).?;
    try testing.expectEqual(items.DataTransportSize.bit, b.transport_size);
    try testing.expectEqual(@as(u16, 1), b.raw_length);
    try testing.expectEqual(@as(usize, 1), b.payload.len);

    var buf2: [max_frame_len]u8 = undefined;
    const real = (try cotp.decode((try tpkt.decode(
        bytes(get("read real db1 index 4 count 2 reply"), &buf2),
    )).payload)).dt;
    var di2 = items.DataItemIterator.init((try s7.decode(real.payload)).data, 1);
    const r = (try di2.next()).?;
    try testing.expectEqual(items.DataTransportSize.real, r.transport_size);
    // Two 4-octet reals: the length field says 8, in octets.
    try testing.expectEqual(@as(u16, 8), r.raw_length);
    try testing.expectEqual(@as(usize, 8), r.payload.len);

    var buf3: [max_frame_len]u8 = undefined;
    const ctr = (try cotp.decode((try tpkt.decode(
        bytes(get("read counter ct 0 count 2 reply"), &buf3),
    )).payload)).dt;
    var di3 = items.DataItemIterator.init((try s7.decode(ctr.payload)).data, 1);
    const c = (try di3.next()).?;
    try testing.expectEqual(items.DataTransportSize.octet_string, c.transport_size);
    try testing.expectEqual(@as(u16, 4), c.raw_length);
    try testing.expectEqual(@as(usize, 4), c.payload.len);
}

test "the padding between multi-item payloads is skipped, not validated" {
    var buf: [max_frame_len]u8 = undefined;
    const rep = (try cotp.decode((try tpkt.decode(
        bytes(get("read multi vars odd lengths 1 3 2 reply"), &buf),
    )).payload)).dt;
    const pdu = try s7.decode(rep.payload);
    var di = items.DataItemIterator.init(pdu.data, 3);
    const a = (try di.next()).?;
    const b = (try di.next()).?;
    const c = (try di.next()).?;
    try testing.expectEqual(@as(usize, 1), a.payload.len);
    try testing.expectEqual(@as(usize, 3), b.payload.len);
    try testing.expectEqual(@as(usize, 2), c.payload.len);
    try testing.expectEqual(pdu.data.len, di.consumed());
    // The real stack put an uninitialised octet in the second pad slot, which
    // is exactly why a decoder must not check its value.
    try testing.expectEqual(@as(u8, 0xBA), pdu.data[13]);
}

test "a failed item is four octets with no payload and the next item follows it" {
    var buf: [max_frame_len]u8 = undefined;
    const rep = (try cotp.decode((try tpkt.decode(
        bytes(get("read multi vars with one bad item db77 one good reply"), &buf),
    )).payload)).dt;
    const pdu = try s7.decode(rep.payload);
    var di = items.DataItemIterator.init(pdu.data, 2);
    const bad = (try di.next()).?;
    try testing.expectEqual(items.ReturnCode.object_does_not_exist, bad.return_code);
    try testing.expectEqual(@as(usize, 0), bad.payload.len);
    const good = (try di.next()).?;
    try testing.expect(good.return_code.isSuccess());
    try testing.expectEqual(@as(usize, 2), good.payload.len);
    try testing.expectEqual(pdu.data.len, di.consumed());

    // The single-item out-of-range reply uses code 0x05.
    var buf2: [max_frame_len]u8 = undefined;
    const oob = (try cotp.decode((try tpkt.decode(
        bytes(get("db read db1 start250 len32 out of range reply"), &buf2),
    )).payload)).dt;
    var di2 = items.DataItemIterator.init((try s7.decode(oob.payload)).data, 1);
    try testing.expectEqual(items.ReturnCode.invalid_address, (try di2.next()).?.return_code);
}

test "the 600-octet read splits at the negotiated PDU boundary" {
    var buf: [max_frame_len]u8 = undefined;
    const first = (try cotp.decode((try tpkt.decode(
        bytes(get("db read db9 0 len 600 splits over 480 byte pdu request"), &buf),
    )).payload)).dt;
    var it = (try vars.decodeRequest((try s7.decode(first.payload)).parameters)).iterator();
    const a = (try it.next()).?;
    // 480 - 18 = 462 octets in the first request.
    try testing.expectEqual(@as(u16, 462), a.count);
    try testing.expectEqual(@as(usize, 462), vars.maxReadPayload(480));
    try testing.expectEqual(@as(u24, 0), a.address);

    var buf2: [max_frame_len]u8 = undefined;
    const second = (try cotp.decode((try tpkt.decode(
        bytes(get("db read db9 0 len 600 splits over 480 byte pdu request 2"), &buf2),
    )).payload)).dt;
    var it2 = (try vars.decodeRequest((try s7.decode(second.payload)).parameters)).iterator();
    const b = (try it2.next()).?;
    try testing.expectEqual(@as(u16, 600 - 462), b.count);
    try testing.expectEqual(@as(u24, 462 * 8), b.address);
}

test "the SZL replies decode into records" {
    var buf: [max_frame_len]u8 = undefined;
    const rep = (try cotp.decode((try tpkt.decode(
        bytes(get("read szl 0x0011 reply"), &buf),
    )).payload)).dt;
    const pdu = try s7.decode(rep.payload);
    const p = try userdata.Param.decode(pdu.parameters);
    try testing.expect(p.isResponse());
    try testing.expectEqual(userdata.FunctionGroup.cpu_functions, p.function_group);
    try testing.expectEqual(userdata.LastDataUnit.no_more, p.last_data_unit);
    const block = try userdata.DataBlock.decode(pdu.data);
    const szl = try userdata.SzlResponse.decode(block.payload);
    try testing.expectEqual(@as(u16, 0x0011), szl.header.id);
    try testing.expectEqual(@as(u16, 28), szl.header.record_length);
    try testing.expectEqual(@as(u16, 4), szl.header.record_count);
    // The order number the CPU reported, from the first record.
    try testing.expectEqualSlices(u8, "6ES7 315-2EH14-0AB0 ", szl.record(0).?[2..22]);
    try testing.expect(szl.record(4) == null);
}

test "the CPU status octet flips between the running and the stopped capture" {
    var buf: [max_frame_len]u8 = undefined;
    const run = (try cotp.decode((try tpkt.decode(
        bytes(get("szl 0424 while run reply"), &buf),
    )).payload)).dt;
    const running = try userdata.SzlResponse.decode(
        (try userdata.DataBlock.decode((try s7.decode(run.payload)).data)).payload,
    );
    try testing.expectEqual(userdata.CpuStatus.run, userdata.cpuStatusFrom(running).?);

    var buf2: [max_frame_len]u8 = undefined;
    const stop = (try cotp.decode((try tpkt.decode(
        bytes(get("szl 0424 while stop reply"), &buf2),
    )).payload)).dt;
    const stopped = try userdata.SzlResponse.decode(
        (try userdata.DataBlock.decode((try s7.decode(stop.payload)).data)).payload,
    );
    try testing.expectEqual(userdata.CpuStatus.stop, userdata.cpuStatusFrom(stopped).?);
}

test "the PLC control requests carry the P_PROGRAM parameter block" {
    var buf: [max_frame_len]u8 = undefined;
    const stop = (try cotp.decode((try tpkt.decode(
        bytes(get("plc stop request"), &buf),
    )).payload)).dt;
    const p = (try s7.decode(stop.payload)).parameters;
    try testing.expectEqual(@as(u8, 0x29), p[0]);
    try testing.expectEqualSlices(u8, "P_PROGRAM", p[7..16]);

    var buf2: [max_frame_len]u8 = undefined;
    const cold = (try cotp.decode((try tpkt.decode(
        bytes(get("plc cold start request"), &buf2),
    )).payload)).dt;
    const c = (try s7.decode(cold.payload)).parameters;
    try testing.expectEqual(@as(u8, 0x28), c[0]);
    try testing.expectEqual(@as(u8, 0xFD), c[7]);
    // The cold restart carries a two-octet "C " argument the warm one lacks.
    try testing.expectEqualSlices(u8, "C ", c[10..12]);
    try testing.expectEqualSlices(u8, "P_PROGRAM", c[13..22]);
}

test "the responder's replies are byte-compared against the recorded CPU's" {
    const server = @import("server.zig");
    var db1: [256]u8 = @splat(0);
    var db2: [64]u8 = @splat(0);
    var flags: [128]u8 = @splat(0);
    var areas = [_]server.AreaBinding{
        .{ .area = .db, .db_number = 1, .bytes = &db1 },
        .{ .area = .db, .db_number = 2, .bytes = &db2 },
        .{ .area = .flags, .bytes = &flags },
    };
    var r = server.Responder.init(.{}, &areas);

    var in: [max_frame_len]u8 = undefined;
    var out: [max_frame_len]u8 = undefined;
    var want: [max_frame_len]u8 = undefined;

    // Handshake, replayed from the capture.
    _ = try r.handle(bytes(get("connect rack0 slot1 request"), &in), &out);
    const setup_reply = (try r.handle(bytes(get("connect rack0 slot1 request 2"), &in), &out)).?;
    try testing.expectEqualSlices(
        u8,
        bytes(get("connect rack0 slot1 reply 2"), &want),
        setup_reply,
    );

    // The write, then the read: our replies must be the CPU's octets. The PDU
    // reference is echoed from the request, so the frames are fully comparable.
    const w = (try r.handle(bytes(get("db write db1 start20 4 bytes 12345678 request"), &in), &out)).?;
    try testing.expectEqualSlices(
        u8,
        bytes(get("db write db1 start20 4 bytes 12345678 reply"), &want),
        w,
    );
    try testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34, 0x56, 0x78 }, db1[20..24]);

    const rd = (try r.handle(bytes(get("db read db1 start20 len4 request"), &in), &out)).?;
    try testing.expectEqualSlices(u8, bytes(get("db read db1 start20 len4 reply"), &want), rd);

    // A DB the responder does not have, exactly as the CPU answered it.
    const missing = (try r.handle(
        bytes(get("db read missing db77 item error request"), &in),
        &out,
    )).?;
    try testing.expectEqualSlices(
        u8,
        bytes(get("db read missing db77 item error reply"), &want),
        missing,
    );

    // An address past the end of DB 1.
    const oob = (try r.handle(
        bytes(get("db read db1 start250 len32 out of range request"), &in),
        &out,
    )).?;
    try testing.expectEqualSlices(
        u8,
        bytes(get("db read db1 start250 len32 out of range reply"), &want),
        oob,
    );
}
