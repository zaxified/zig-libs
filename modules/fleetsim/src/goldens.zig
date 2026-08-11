// SPDX-License-Identifier: MIT

//! External anchor: Wireshark 4.6.4 (`sharkd`), applied to the bytes this
//! module's adapters actually emit.
//!
//! ## Why this file exists
//!
//! `fleetsim` ships eight `test "live: …"` cases that point a real third-party
//! master (opendnp3, lib60870, snap7, open62541, a Modbus master, an
//! EtherNet/IP master, a BACnet client) at a simulated node. Every one of them
//! is gated on a `FLEETSIM_*_LISTEN` environment variable and returns
//! `error.SkipZigTest` when it is unset, so the default run reports
//! "N pass, 8 skip", exit 0 — while certifying **zero** third-party interop.
//! The wave-2 audit recorded that as this module's one HIGH finding: the only
//! external anchor never runs.
//!
//! Those live tests cannot be made to run by default here — see "What this is
//! not" below. What *can* run offline, on every build, with no new dependency,
//! is a third-party **reading** of the same bytes: Wireshark's dissector
//! library is a mature, independent implementation of all seven of these
//! specifications, and it grades the frames our adapters produce without any
//! knowledge of how we produced them. That is an oracle which fails
//! independently of whoever wrote the encoder, which is the definition this
//! repo works to (`scripts/dissect.py`, and the `isis*` goldens files).
//!
//! ## What each vector is
//!
//! Every byte array below was produced by driving the **adapter** through
//! `Node.deliver` — the same entry point the TCP binding uses — not by calling
//! a sibling encoder directly. So what Wireshark grades is exactly the layer
//! `fleetsim` adds over its dependencies: the request→response mapping, the
//! framing, and the device state the adapter projects onto the wire.
//!
//! ## How the frozen readings were obtained (capture-and-freeze, run once)
//!
//! `scripts/dissect.py` only knows the `raw`/`eth`/`llc` framings, and these
//! are TCP/UDP payloads, so the runs went through the same two tools it drives
//! internally, with `text2pcap` supplying the transport header:
//!
//!     hexdump -> in.txt   # "%06x  aa bb cc ..." per 16 bytes
//!     text2pcap -q -T <srcport>,<dstport> in.txt in.pcap   # -u for UDP
//!     printf '{"jsonrpc":"2.0","id":1,"method":"load","params":{"file":"in.pcap"}}\n
//!             {"jsonrpc":"2.0","id":2,"method":"frame","params":{"frame":1,"proto":true}}\n' \
//!       | sharkd -
//!
//! Ports used (they are what selects the dissector): Modbus 502, DNP3 20000,
//! IEC 104 2404, S7comm/TPKT 102, EtherNet/IP 44818 (both ends — Wireshark's
//! `enip` dissector only registers when *both* ports match), OPC UA 4840,
//! BACnet/IP UDP 47808. The quoted output below is what makes the anchor
//! re-checkable without re-running the tool; **the test suite never invokes
//! `sharkd`/`text2pcap`** (no new build dependency, the gate stays offline).
//!
//! ## What this is NOT
//!
//! A dissector grades a frame that was produced; it can never grade *whether*
//! or *when* one should have been, nor how a real master's state machine
//! reacts over a 60-second session. So this file does **not** retire the eight
//! live tests and does not claim to. It closes the "a green `test-fleetsim`
//! proves nothing third-party" half of the finding; the "a real master drove
//! it" half stays with the live lane, which `expectLive()` in `root.zig` now
//! makes loud instead of silent.

const std = @import("std");
const testing = std.testing;

const modbus = @import("modbus");
const dnp3 = @import("dnp3");
const iec104 = @import("iec104");
const s7comm = @import("s7comm");
const bacnet = @import("bacnet");
const enip = @import("enip");

const adapters = @import("adapters.zig");
const node_mod = @import("node.zig");
const Framing = node_mod.Framing;

test "anchor: Wireshark reads the Modbus adapter's read reply, and its trouble exception" {
    // sharkd, tcp 502 -> 40000:
    //   Modbus/TCP
    //     Transaction Identifier: 4660      [mbtcp.trans_id == 4660]
    //     Protocol Identifier: 0            [mbtcp.prot_id == 0]
    //     Length: 7                         [mbtcp.len == 7]
    //     Unit Identifier: 5                [mbtcp.unit_id == 5]
    //   Modbus
    //     0... .... = Exception: No         [modbus.exception == False]
    //     .000 0011 = Function Code: Read Holding Registers (3)
    //     Byte Count: 4                     [modbus.byte_cnt == 4]
    //     Register 0 (UINT16): 258          [modbus.regnum16 == 0]
    //                                       [modbus.regval_uint16 == 258]
    //     Register 1 (UINT16): 772          [modbus.regnum16 == 1]
    //                                       [modbus.regval_uint16 == 772]
    //
    // Note what an independent reader confirms that our own round trip cannot:
    // that the MBAP `Length` field counts unit-id + PDU (7, not 6 or 8), and
    // that 0x0102/0x0304 land big-endian *within* each register — Wireshark
    // says 258 and 772, where a byte-swapped encoder would have made it read
    // 513 and 1027.
    //
    // The register values are deliberately **asymmetric**. The first version of
    // this vector used 0x1111/0x2222, which are byte-palindromes: flipping the
    // encoder's endianness emits the identical frame, so the reading above
    // could not have distinguished it and the claim in this comment was one the
    // vector did not support. Measured: with `modules/modbus/src/server.zig`'s
    // register writer at `.little`, this test stayed GREEN on the old fixture
    // (six other fleetsim tests went red) and goes RED on this one. A golden
    // that a real external tool produced is still only worth the distinctions
    // its inputs can express.
    var holdings = [_]u16{ 0x0102, 0x0304, 0x3333, 0x4444 };
    var slave = adapters.Modbus.init(
        .{ .unit_id = 5, .framing = .tcp },
        .{ .holding_registers = .{ .base = 0, .values = &holdings } },
    );
    const n = slave.node();

    var req_buf: [modbus.tcp.max_adu_len]u8 = undefined;
    var out: [modbus.tcp.max_adu_len]u8 = undefined;
    const req = try modbus.tcp.encodeAdu(&req_buf, 0x1234, 5, &.{ 0x03, 0x00, 0x00, 0x00, 0x02 });
    const reply = (try n.deliver(req, &out, 0)).?;
    try testing.expectEqualSlices(u8, &.{
        0x12, 0x34, 0x00, 0x00, 0x00, 0x07, 0x05, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
    }, reply);

    // sharkd, same stream, on the trouble reply:
    //   Modbus/TCP: Length: 3, Unit Identifier: 5
    //   Function 3:  Read Holding Registers.  Exception: Slave device failure
    //     1... .... = Exception: Yes         [modbus.exception == True]
    //     Exception Code: Slave device failure (4)  [modbus.exception_code == 4]
    //
    // This is the anchor for the adapter's *trouble semantics*, not just its
    // framing: a third party names the degraded device state the simulator was
    // asked to project — "Slave device failure" — from the bytes alone.
    try testing.expect(n.control(.trouble_on, 0));
    const bad = (try n.deliver(req, &out, 0)).?;
    try testing.expectEqualSlices(u8, &.{
        0x12, 0x34, 0x00, 0x00, 0x00, 0x03, 0x05, 0x83, 0x04,
    }, bad);
}

test "anchor: Wireshark reads the DNP3 adapter's link ACK, and verifies its CRC" {
    // sharkd, tcp 20000 -> 20000:
    //   Distributed Network Protocol 3.0
    //     Data Link Layer, Len: 5, From: 1024, To: 1, ACK
    //       Start Bytes: 0x0564              [dnp3.start == 0x0564]
    //       Length: 5                        [dnp3.len == 5]
    //       Control: 0x00 (ACK)
    //         0... .... = Direction: Not set [dnp3.ctl.dir == False]
    //         .0.. .... = Primary: Not set   [dnp3.ctl.prm == False]
    //         .... 0000 = Control Function Code: ACK (0)  [dnp3.ctl.secfunc == 0]
    //       Destination: 1                   [dnp3.dst == 1]
    //       Source: 1024                     [dnp3.src == 1024]
    //       Data Link Header checksum: 0x7027 [correct]
    //       Data Link Header Checksum Status: Good  [dnp.hdr.CRC.status == "Good"]
    //
    // The last two lines are the reason this vector is worth freezing: DNP3's
    // header CRC is a bespoke polynomial with a reflected/little-endian
    // placement that a round trip against our own encoder would agree with
    // however we got it wrong. Wireshark recomputes it and says "Good".
    var binaries = [_]dnp3.outstation.BinaryInput{.{ .value = true, .class = .class1 }} ** 4;
    var analogs = [_]dnp3.outstation.AnalogInput{.{ .value = 7, .class = .class2 }} ** 2;
    var event_storage: [16]dnp3.outstation.Event = undefined;
    var rx_buf: [512]u8 = undefined;
    var scratch: [512]u8 = undefined;
    var tx_fragment: [2048]u8 = undefined;
    var station: adapters.Dnp3 = undefined;
    station.init(
        .{ .address = 1024, .master_address = 1 },
        .{ .binary_inputs = &binaries, .analog_inputs = &analogs },
        dnp3.outstation.EventBuffer.init(&event_storage),
        &rx_buf,
        &scratch,
        &tx_fragment,
    );
    const n = station.node();

    var frame_buf: [64]u8 = undefined;
    const reset = try dnp3.link.encodeFrame(
        .{ .dir = true, .prm = true, .function = @intFromEnum(dnp3.link.PrimaryFunction.reset_link_states) },
        1024,
        1,
        &.{},
        &frame_buf,
    );
    var out: [512]u8 = undefined;
    const ack = (try n.deliver(reset, &out, 0)).?;
    try testing.expectEqualSlices(u8, &.{
        0x05, 0x64, 0x05, 0x00, 0x01, 0x00, 0x00, 0x04, 0x27, 0x70,
    }, ack);
}

test "anchor: Wireshark reads the IEC 104 adapter's STARTDT con" {
    // sharkd, tcp 2404 -> 40000:
    //   IEC 60870-5-104: -> U (STARTDT con)
    //     START                                       [iec60870_asdu.start == 0x68]
    //     ApduLen: 4                                  [iec60870_104.apdulen == 4]
    //     ... ..11 = Type: U (0x3)                    [iec60870_104.type == 3]
    //     ... 0000 10.. = UType: STARTDT con (0x02)   [iec60870_104.utype == 2]
    //
    // The U-format control field is a bitfield whose "con" vs "act" distinction
    // is two bits apart (0x0B vs 0x07); an independent decoder naming *con* is
    // exactly the check a self-round-trip cannot make.
    var points = [_]iec104.Point{
        .{ .ioa = 101, .type_id = .m_sp_na_1, .element = .{ .siq = .{ .on = true } } },
        .{ .ioa = 105, .type_id = .m_me_nc_1, .element = .{ .short_float = .{ .value = 1.5, .quality = .{} } } },
    };
    var frame_buf: [512]u8 = undefined;
    var queue_buf: [8192]u8 = undefined;
    var rtu: adapters.Iec104 = undefined;
    try rtu.init(.{ .common_address = 47 }, &points, &frame_buf, &queue_buf, .{});
    const n = rtu.node();

    var out: [512]u8 = undefined;
    // STARTDT act in, STARTDT con out.
    const reply = (try n.deliver(&.{ 0x68, 0x04, 0x07, 0x00, 0x00, 0x00 }, &out, 0)).?;
    try testing.expectEqualSlices(u8, &.{ 0x68, 0x04, 0x0B, 0x00, 0x00, 0x00 }, reply);
}

test "anchor: Wireshark reads the S7comm adapter's TPKT/COTP Connect Confirm" {
    // sharkd, tcp 102 -> 40000:
    //   TPKT, Version: 3, Length: 22        [tpkt.version == 3] [tpkt.length == 22]
    //   ISO 8073/X.224 COTP
    //     Length: 17                        [cotp.li == 17]
    //     PDU Type: CC Connect Confirm (0x0d)  [cotp.type == 0x0d]
    //     Destination reference: 0x0001     [cotp.destref == 0x0001]
    //     Source reference: 0x0001          [cotp.srcref == 0x0001]
    //     0000 .... = Class: 0              [cotp.class == 0]
    //     Parameter code: tpdu-size (0xc0), TPDU size: 1024   [cotp.tpdu_size == 1024]
    //     Parameter code: src-tsap (0xc1), Source TSAP: 0100
    //     Parameter code: dst-tsap (0xc2), Destination TSAP: 0102
    //
    // The TSAP swap on a Connect Confirm (the CR's dst becomes the CC's src in
    // some stacks and not others) and the TPKT length counting its own 4-byte
    // header are both places a same-author round trip agrees with itself.
    var db1 = [_]u8{0} ** 32;
    const areas = [_]s7comm.AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db1 }};
    var plc = adapters.S7comm.init(.{}, &areas);
    const n = plc.node();

    var out: [512]u8 = undefined;
    const cr = [_]u8{
        0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
        0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x01, 0x02, 0xC0, 0x01, 0x0A,
    };
    const cc = (try n.deliver(&cr, &out, 0)).?;
    try testing.expectEqualSlices(u8, &.{
        0x03, 0x00, 0x00, 0x16, 0x11, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00,
        0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x01, 0x02,
    }, cc);
}

test "anchor: Wireshark reads the EtherNet/IP adapter's RegisterSession reply" {
    // sharkd, tcp 44818 -> 44818 (the enip dissector needs both ends on 44818):
    //   EtherNet/IP (Industrial Protocol), Session: 0xA5A50001, Register Session
    //     Command: Register Session (0x0065)   [enip.command == 0x0065]
    //     Length: 4                            [enip.length == 4]
    //     Session Handle: 0xa5a50001           [enip.session == 0xa5a50001]
    //     Status: Success (0x00000000)         [enip.status == 0x00000000]
    //     Sender Context: 0000000000000000     [enip.context]
    //     Options: 0x00000000                  [enip.options == 0x00000000]
    //     Command Specific Data
    //       Protocol Version: 1                [enip.rs.version == 1]
    //       Option Flags: 0x0000               [enip.rs.flags == 0x0000]
    //
    // Every field of the 24-byte encapsulation header is little-endian while
    // the CIP payload above it is not; an independent reader placing the
    // session handle and length correctly is the check that matters.
    var tag_bytes = [_]u8{0} ** 8;
    const tags = [_]enip.TagBinding{.{ .name = "Speed", .type = .dint, .bytes = &tag_bytes }};
    var dev = adapters.Enip.init(.{}, &tags);
    const n = dev.node();

    var out: [512]u8 = undefined;
    var req: [28]u8 = @splat(0);
    std.mem.writeInt(u16, req[0..2], @intFromEnum(enip.Command.register_session), .little);
    std.mem.writeInt(u16, req[2..4], 4, .little);
    std.mem.writeInt(u16, req[24..26], 1, .little); // protocol version
    const reply = (try n.deliver(&req, &out, 0)).?;
    try testing.expectEqualSlices(u8, &.{
        0x65, 0x00, 0x04, 0x00, 0x01, 0x00, 0xA5, 0xA5, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
    }, reply);
}

test "anchor: Wireshark reads the BACnet adapter's I-Am, down to the device instance" {
    // sharkd, udp 47808 -> 47808:
    //   BACnet Virtual Link Control
    //     Type: BACnet/IP (Annex J) (0x81)   [bvlc.type == 0x81]
    //     Function: Original-Broadcast-NPDU (0x0b)  [bvlc.function == 0x0b]
    //   BACnet NPDU
    //     Version: 0x01 (ASHRAE 135-1995)    [bacnet.version == 1]
    //     Control: 0x20, Destination Specifier
    //     Destination Network Address: 65535 [bacnet.dnet == 65535]
    //     Destination MAC Layer Address Length: 0 indicates Broadcast
    //     Hop Count: 255                     [bacnet.hopc == 255]
    //   BACnet APDU
    //     0001 .... = APDU Type: Unconfirmed-REQ (1)   [bacapp.type == 1]
    //     Unconfirmed Service Choice: i-Am (0)         [bacapp.unconfirmed_service == 0]
    //     Object Identifier: DEV-260001      [bacapp.objectIdentifier == 33814433]
    //       Object Type: device (8)          [bacapp.objectType == 8]
    //       Instance Number: 260001          [bacapp.instance_number == 260001]
    //     Maximum ADPU Length Accepted: (Unsigned) 1476
    //     Segmentation Supported: no-segmentation (3)
    //     Vendor ID: Reserved for ASHRAE (999)  [bacapp.vendor_identifier == 999]
    //
    // BACnet's object identifier packs a 10-bit type and a 22-bit instance into
    // one 32-bit word; `objectIdentifier == 33814433` decomposing to
    // device/260001 is a genuine third-party confirmation of that packing, and
    // it is the identity a real BACnet client discovers the simulated device by.
    var props = [_]bacnet.Property{
        .{ .id = .object_name, .value = .{ .string = "AI-1" } },
        .{ .id = .present_value, .value = .{ .real = 21.5 } },
    };
    var objects = [_]bacnet.Object{.{
        .id = .{ .type = .analog_input, .instance = 1 },
        .properties = &props,
    }};
    var dev: adapters.DefaultBacnet = undefined;
    dev.init(
        .{ .instance = 260_001, .vendor_id = 999 },
        &objects,
        .{ .ip = .{ 10, 0, 0, 2 }, .port = 47808 },
        .{ .ip = .{ 10, 0, 0, 1 }, .port = 47808 },
    );
    const n = dev.node();

    const who_is = [_]u8{ 0x81, 0x0B, 0x00, 0x0C, 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08 };
    var out: [1024]u8 = undefined;
    const reply = (try n.deliver(&who_is, &out, 0)).?;
    try testing.expectEqualSlices(u8, &.{
        0x81, 0x0B, 0x00, 0x19, 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x00,
        0xC4, 0x02, 0x03, 0xF7, 0xA1, 0x22, 0x05, 0xC4, 0x91, 0x03, 0x22, 0x03,
        0xE7,
    }, reply);
    try testing.expectEqual(@as(?usize, reply.len), try Framing.bacnet_bvll.frameLen(reply));
}
