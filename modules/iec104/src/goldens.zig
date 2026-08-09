// SPDX-License-Identifier: MIT

//! Byte-exact goldens captured from **real traffic between two independent
//! third-party IEC 60870-5-104 implementations**.
//!
//! Provenance of this table (see SPEC.md "Verification" for the full story):
//! a Python `c104` 2.2.1 controlling station (Fraunhofer FIT, a binding over
//! the `lib60870-C` protocol stack) was pointed at a `c104` controlled station
//! through a recording TCP proxy, and every APDU that crossed the wire was
//! logged as hex together with `c104.explain_bytes`'s own interpretation of
//! it. Neither endpoint is this module, so these octets are an independent
//! oracle, not a self-consistency check. Frames covering `TESTFR`, the
//! negative confirmation and the three "unknown …" causes of transmission
//! were produced by driving the same third-party server from a raw socket.
//!
//! `note` is `c104`'s verbatim explanation of the frame (its `|` separators
//! rewritten as `/` so they survive being a Zig string), kept so a reader can
//! see what the third-party stack thought each frame meant.
//!
//! The tests below assert three things for every entry: it decodes; the
//! decode round-trips to the very same octets; and — for a representative
//! subset — the decoded fields match `c104`'s interpretation.

const std = @import("std");
const apci = @import("apci.zig");
const asdu = @import("asdu.zig");
const info = @import("info.zig");
const state = @import("state.zig");

pub const Direction = enum {
    /// Master -> RTU.
    controlling_to_controlled,
    /// RTU -> master.
    controlled_to_controlling,
};

pub const Golden = struct {
    hex: []const u8,
    dir: Direction,
    /// `c104.explain_bytes` output for this frame, verbatim.
    note: []const u8,
};

/// Every distinct APDU observed in the capture.
pub const captured = [_]Golden{
    .{ .hex = "680407000000", .dir = .controlling_to_controlled, .note = "U-Format / StartDT act" },
    .{ .hex = "68040b000000", .dir = .controlled_to_controlling, .note = "U-Format / StartDT con" },
    .{ .hex = "681400000000670106002f00000000cb9c120317071a", .dir = .controlling_to_controlled, .note = "I-Format / C_CS_NA_1 / ACTIVATION / POSITIVE / CA 47 / 1st IOA 0 / LIST[1] (00 00 00 cb 9c 12 03 17 07 1a )" },
    .{ .hex = "681400000200670107002f00000000cb9c120317071a", .dir = .controlled_to_controlling, .note = "I-Format / C_CS_NA_1 / ACTIVATION_CON / POSITIVE / CA 47 / 1st IOA 0 / LIST[1] (00 00 00 cb 9c 12 03 17 07 1a )" },
    .{ .hex = "680e02000200640106002f0000000014", .dir = .controlling_to_controlled, .note = "I-Format / C_IC_NA_1 / ACTIVATION / POSITIVE / CA 47 / 1st IOA 0 / LIST[1] (00 00 00 14 )" },
    .{ .hex = "680e02000400640107002f0000000014", .dir = .controlled_to_controlling, .note = "I-Format / C_IC_NA_1 / ACTIVATION_CON / POSITIVE / CA 47 / 1st IOA 0 / LIST[1] (00 00 00 14 )" },
    .{ .hex = "680e04000400018114002f0065000001", .dir = .controlled_to_controlling, .note = "I-Format / M_SP_NA_1 / INTERROGATED_BY_STATION / POSITIVE / CA 47 / 1st IOA 101 / SEQUENCE[1] (65 00 00 01 )" },
    .{ .hex = "680e06000400038114002f0066000002", .dir = .controlled_to_controlling, .note = "I-Format / M_DP_NA_1 / INTERROGATED_BY_STATION / POSITIVE / CA 47 / 1st IOA 102 / SEQUENCE[1] (66 00 00 02 )" },
    .{ .hex = "680f08000400058114002f006700000500", .dir = .controlled_to_controlling, .note = "I-Format / M_ST_NA_1 / INTERROGATED_BY_STATION / POSITIVE / CA 47 / 1st IOA 103 / SEQUENCE[1] (67 00 00 05 00 )" },
    .{ .hex = "68120a000400078114002f006800000000000000", .dir = .controlled_to_controlling, .note = "I-Format / M_BO_NA_1 / INTERROGATED_BY_STATION / POSITIVE / CA 47 / 1st IOA 104 / SEQUENCE[1] (68 00 00 00 00 00 00 00 )" },
    .{ .hex = "68100c000400098114002f00690000004000", .dir = .controlled_to_controlling, .note = "I-Format / M_ME_NA_1 / INTERROGATED_BY_STATION / POSITIVE / CA 47 / 1st IOA 105 / SEQUENCE[1] (69 00 00 00 40 00 )" },
    .{ .hex = "68100e0004000b8114002f006a00002efb00", .dir = .controlled_to_controlling, .note = "I-Format / M_ME_NB_1 / INTERROGATED_BY_STATION / POSITIVE / CA 47 / 1st IOA 106 / SEQUENCE[1] (6a 00 00 2e fb 00 )" },
    .{ .hex = "6812100004000d8114002f006b0000d00f494000", .dir = .controlled_to_controlling, .note = "I-Format / M_ME_NC_1 / INTERROGATED_BY_STATION / POSITIVE / CA 47 / 1st IOA 107 / SEQUENCE[1] (6b 00 00 d0 0f 49 40 00 )" },
    .{ .hex = "6815120004001e8114002f00c9000001f794120317071a", .dir = .controlled_to_controlling, .note = "I-Format / M_SP_TB_1 / INTERROGATED_BY_STATION / POSITIVE / CA 47 / 1st IOA 201 / SEQUENCE[1] (c9 00 00 01 f7 94 12 03 17 07 1a )" },
    .{ .hex = "6815140004001f8114002f00ca000001f794120317071a", .dir = .controlled_to_controlling, .note = "I-Format / M_DP_TB_1 / INTERROGATED_BY_STATION / POSITIVE / CA 47 / 1st IOA 202 / SEQUENCE[1] (ca 00 00 01 f7 94 12 03 17 07 1a )" },
    .{ .hex = "681716000400228114002f00cb000000e000f794120317071a", .dir = .controlled_to_controlling, .note = "I-Format / M_ME_TD_1 / INTERROGATED_BY_STATION / POSITIVE / CA 47 / 1st IOA 203 / SEQUENCE[1] (cb 00 00 00 e0 00 f7 94 12 03 17 07 1a )" },
    .{ .hex = "681718000400238114002f00cc0000e11000f794120317071a", .dir = .controlled_to_controlling, .note = "I-Format / M_ME_TE_1 / INTERROGATED_BY_STATION / POSITIVE / CA 47 / 1st IOA 204 / SEQUENCE[1] (cc 00 00 e1 10 00 f7 94 12 03 17 07 1a )" },
    .{ .hex = "680401001200", .dir = .controlling_to_controlled, .note = "S-Format" },
    .{ .hex = "68191a000400248114002f00cd0000000020c000f794120317071a", .dir = .controlled_to_controlling, .note = "I-Format / M_ME_TF_1 / INTERROGATED_BY_STATION / POSITIVE / CA 47 / 1st IOA 205 / SEQUENCE[1] (cd 00 00 00 00 20 c0 00 f7 94 12 03 17 07 1a )" },
    .{ .hex = "680e1c00040064010a002f0000000014", .dir = .controlled_to_controlling, .note = "I-Format / C_IC_NA_1 / ACTIVATION_TERMINATION / POSITIVE / CA 47 / 1st IOA 0 / LIST[1] (00 00 00 14 )" },
    .{ .hex = "680e04001e00650106002f0000000005", .dir = .controlling_to_controlled, .note = "I-Format / C_CI_NA_1 / ACTIVATION / POSITIVE / CA 47 / 1st IOA 0 / LIST[1] (00 00 00 05 )" },
    .{ .hex = "680e1e000600650107002f0000000005", .dir = .controlled_to_controlling, .note = "I-Format / C_CI_NA_1 / ACTIVATION_CON / POSITIVE / CA 47 / 1st IOA 0 / LIST[1] (00 00 00 05 )" },
    .{ .hex = "6812200006000f8125002f006c00000000000000", .dir = .controlled_to_controlling, .note = "I-Format / M_IT_NA_1 / REQUESTED_BY_GENERAL_COUNTER / POSITIVE / CA 47 / 1st IOA 108 / SEQUENCE[1] (6c 00 00 00 00 00 00 00 )" },
    .{ .hex = "681922000600258125002f00ce00000000000000f794120317071a", .dir = .controlled_to_controlling, .note = "I-Format / M_IT_TB_1 / REQUESTED_BY_GENERAL_COUNTER / POSITIVE / CA 47 / 1st IOA 206 / SEQUENCE[1] (ce 00 00 00 00 00 00 00 f7 94 12 03 17 07 1a )" },
    .{ .hex = "680e2400060065010a002f0000000005", .dir = .controlled_to_controlling, .note = "I-Format / C_CI_NA_1 / ACTIVATION_TERMINATION / POSITIVE / CA 47 / 1st IOA 0 / LIST[1] (00 00 00 05 )" },
    .{ .hex = "6816060026006b0106002f00000000000091a6120317071a", .dir = .controlling_to_controlled, .note = "I-Format / C_TS_TA_1 / ACTIVATION / POSITIVE / CA 47 / 1st IOA 0 / LIST[1] (00 00 00 00 00 91 a6 12 03 17 07 1a )" },
    .{ .hex = "6816260008006b0107002f00000000000091a6120317071a", .dir = .controlled_to_controlling, .note = "I-Format / C_TS_TA_1 / ACTIVATION_CON / POSITIVE / CA 47 / 1st IOA 0 / LIST[1] (00 00 00 00 00 91 a6 12 03 17 07 1a )" },
    .{ .hex = "680e080028002d0106002f002d010081", .dir = .controlling_to_controlled, .note = "I-Format / C_SC_NA_1 / ACTIVATION / POSITIVE / CA 47 / 1st IOA 301 / LIST[1] (2d 01 00 81 )" },
    .{ .hex = "680e28000a002d0107002f002d010081", .dir = .controlled_to_controlling, .note = "I-Format / C_SC_NA_1 / ACTIVATION_CON / POSITIVE / CA 47 / 1st IOA 301 / LIST[1] (2d 01 00 81 )" },
    .{ .hex = "680e0a002a002d0106002f002d010001", .dir = .controlling_to_controlled, .note = "I-Format / C_SC_NA_1 / ACTIVATION / POSITIVE / CA 47 / 1st IOA 301 / LIST[1] (2d 01 00 01 )" },
    .{ .hex = "680e2a000c002d0107002f002d010001", .dir = .controlled_to_controlling, .note = "I-Format / C_SC_NA_1 / ACTIVATION_CON / POSITIVE / CA 47 / 1st IOA 301 / LIST[1] (2d 01 00 01 )" },
    .{ .hex = "680e2c000c002d010a002f002d010081", .dir = .controlled_to_controlling, .note = "I-Format / C_SC_NA_1 / ACTIVATION_TERMINATION / POSITIVE / CA 47 / 1st IOA 301 / LIST[1] (2d 01 00 81 )" },
    .{ .hex = "680e0c002e002e0106002f002e010002", .dir = .controlling_to_controlled, .note = "I-Format / C_DC_NA_1 / ACTIVATION / POSITIVE / CA 47 / 1st IOA 302 / LIST[1] (2e 01 00 02 )" },
    .{ .hex = "680e2e000e002e0107002f002e010002", .dir = .controlled_to_controlling, .note = "I-Format / C_DC_NA_1 / ACTIVATION_CON / POSITIVE / CA 47 / 1st IOA 302 / LIST[1] (2e 01 00 02 )" },
    .{ .hex = "680e0e0030002f0106002f002f010002", .dir = .controlling_to_controlled, .note = "I-Format / C_RC_NA_1 / ACTIVATION / POSITIVE / CA 47 / 1st IOA 303 / LIST[1] (2f 01 00 02 )" },
    .{ .hex = "680e300010002f0107002f002f010002", .dir = .controlled_to_controlling, .note = "I-Format / C_RC_NA_1 / ACTIVATION_CON / POSITIVE / CA 47 / 1st IOA 303 / LIST[1] (2f 01 00 02 )" },
    .{ .hex = "681010003200300106002f00300100002080", .dir = .controlling_to_controlled, .note = "I-Format / C_SE_NA_1 / ACTIVATION / POSITIVE / CA 47 / 1st IOA 304 / LIST[1] (30 01 00 00 20 80 )" },
    .{ .hex = "681032001200300107002f00300100002080", .dir = .controlled_to_controlling, .note = "I-Format / C_SE_NA_1 / ACTIVATION_CON / POSITIVE / CA 47 / 1st IOA 304 / LIST[1] (30 01 00 00 20 80 )" },
    .{ .hex = "681012003400300106002f00300100002000", .dir = .controlling_to_controlled, .note = "I-Format / C_SE_NA_1 / ACTIVATION / POSITIVE / CA 47 / 1st IOA 304 / LIST[1] (30 01 00 00 20 00 )" },
    .{ .hex = "681034001400300107002f00300100002000", .dir = .controlled_to_controlling, .note = "I-Format / C_SE_NA_1 / ACTIVATION_CON / POSITIVE / CA 47 / 1st IOA 304 / LIST[1] (30 01 00 00 20 00 )" },
    .{ .hex = "68103600140030010a002f00300100002080", .dir = .controlled_to_controlling, .note = "I-Format / C_SE_NA_1 / ACTIVATION_TERMINATION / POSITIVE / CA 47 / 1st IOA 304 / LIST[1] (30 01 00 00 20 80 )" },
    .{ .hex = "681014003800310106002f00310100090300", .dir = .controlling_to_controlled, .note = "I-Format / C_SE_NB_1 / ACTIVATION / POSITIVE / CA 47 / 1st IOA 305 / LIST[1] (31 01 00 09 03 00 )" },
    .{ .hex = "681038001600310107002f00310100090300", .dir = .controlled_to_controlling, .note = "I-Format / C_SE_NB_1 / ACTIVATION_CON / POSITIVE / CA 47 / 1st IOA 305 / LIST[1] (31 01 00 09 03 00 )" },
    .{ .hex = "681216003a00320106002f003201000000c03f00", .dir = .controlling_to_controlled, .note = "I-Format / C_SE_NC_1 / ACTIVATION / POSITIVE / CA 47 / 1st IOA 306 / LIST[1] (32 01 00 00 00 c0 3f 00 )" },
    .{ .hex = "68123a001800320107002f003201000000c03f00", .dir = .controlled_to_controlling, .note = "I-Format / C_SE_NC_1 / ACTIVATION_CON / POSITIVE / CA 47 / 1st IOA 306 / LIST[1] (32 01 00 00 00 c0 3f 00 )" },
    .{ .hex = "681518003c003a0106002f00370100013ab2120317071a", .dir = .controlling_to_controlled, .note = "I-Format / C_SC_TA_1 / ACTIVATION / POSITIVE / CA 47 / 1st IOA 311 / LIST[1] (37 01 00 01 3a b2 12 03 17 07 1a )" },
    .{ .hex = "68153c001a003a0107002f00370100013ab2120317071a", .dir = .controlled_to_controlling, .note = "I-Format / C_SC_TA_1 / ACTIVATION_CON / POSITIVE / CA 47 / 1st IOA 311 / LIST[1] (37 01 00 01 3a b2 12 03 17 07 1a )" },
    .{ .hex = "68191a003e003f0106002f003c010000001c4100cab3120317071a", .dir = .controlling_to_controlled, .note = "I-Format / C_SE_TC_1 / ACTIVATION / POSITIVE / CA 47 / 1st IOA 316 / LIST[1] (3c 01 00 00 00 1c 41 00 ca b3 12 03 17 07 1a )" },
    .{ .hex = "68193e001c003f0107002f003c010000001c4100cab3120317071a", .dir = .controlled_to_controlling, .note = "I-Format / C_SE_TC_1 / ACTIVATION_CON / POSITIVE / CA 47 / 1st IOA 316 / LIST[1] (3c 01 00 00 00 1c 41 00 ca b3 12 03 17 07 1a )" },
    .{ .hex = "680d1c004000660105002f00650000", .dir = .controlling_to_controlled, .note = "I-Format / C_RD_NA_1 / REQUEST / POSITIVE / CA 47 / 1st IOA 101 / LIST[1] (65 00 00 )" },
    .{ .hex = "680d40001e00660107002f00650000", .dir = .controlled_to_controlling, .note = "I-Format / C_RD_NA_1 / ACTIVATION_CON / POSITIVE / CA 47 / 1st IOA 101 / LIST[1] (65 00 00 )" },
    .{ .hex = "680e42001e00010105002f0065000000", .dir = .controlled_to_controlling, .note = "I-Format / M_SP_NA_1 / REQUEST / POSITIVE / CA 47 / 1st IOA 101 / LIST[1] (65 00 00 00 )" },
    .{ .hex = "680401004400", .dir = .controlling_to_controlled, .note = "S-Format" },
    .{ .hex = "680e00000000640106002f0000000014", .dir = .controlling_to_controlled, .note = "I-Format / C_IC_NA_1 / ACTIVATION / POSITIVE / CA 47 / 1st IOA 0 / LIST[1] (00 00 00 14 )" },
    .{ .hex = "680e00000200640107002f0000000014", .dir = .controlled_to_controlling, .note = "I-Format / C_IC_NA_1 / ACTIVATION_CON / POSITIVE / CA 47 / 1st IOA 0 / LIST[1] (00 00 00 14 )" },
    .{ .hex = "681902000200018c14002f00e80300000100010001000100010001", .dir = .controlled_to_controlling, .note = "I-Format / M_SP_NA_1 / INTERROGATED_BY_STATION / POSITIVE / CA 47 / 1st IOA 1000 / SEQUENCE[12] (e8 03 00 00 01 00 01 00 01 00 01 00 01 00 01 )" },
    .{ .hex = "680e0400020064010a002f0000000014", .dir = .controlled_to_controlling, .note = "I-Format / C_IC_NA_1 / ACTIVATION_TERMINATION / POSITIVE / CA 47 / 1st IOA 0 / LIST[1] (00 00 00 14 )" },
    .{ .hex = "680401000400", .dir = .controlling_to_controlled, .note = "S-Format" },
    .{ .hex = "680401000600", .dir = .controlling_to_controlled, .note = "S-Format" },
    .{ .hex = "680413000000", .dir = .controlling_to_controlled, .note = "U-Format / StopDT act" },
    .{ .hex = "680423000000", .dir = .controlled_to_controlling, .note = "U-Format / StopDT con" },
    .{ .hex = "680443000000", .dir = .controlling_to_controlled, .note = "U-Format / TestFR act" },
    .{ .hex = "680483000000", .dir = .controlled_to_controlling, .note = "U-Format / TestFR con" },
    .{ .hex = "680e00000000c80106002f0000000000", .dir = .controlling_to_controlled, .note = "I-Format / unknown / ACTIVATION / POSITIVE / CA 47 / 1st IOA 0 / LIST[1] (00 00 00 00 )" },
    .{ .hex = "680e0000000064010600630000000014", .dir = .controlling_to_controlled, .note = "I-Format / C_IC_NA_1 / ACTIVATION / POSITIVE / CA 99 / 1st IOA 0 / LIST[1] (00 00 00 14 )" },
    .{ .hex = "680e0000020064014700630000000014", .dir = .controlled_to_controlling, .note = "I-Format / C_IC_NA_1 / ACTIVATION_CON / NEGATIVE / CA 99 / 1st IOA 0 / LIST[1] (00 00 00 14 )" },
    .{ .hex = "680e0200020064012e00630000000014", .dir = .controlled_to_controlling, .note = "I-Format / C_IC_NA_1 / UNKNOWN_COMMON_ADDRESS_OF_ASDU / POSITIVE / CA 99 / 1st IOA 0 / LIST[1] (00 00 00 14 )" },
    .{ .hex = "680e000000002d0106002f00e7030001", .dir = .controlling_to_controlled, .note = "I-Format / C_SC_NA_1 / ACTIVATION / POSITIVE / CA 47 / 1st IOA 999 / LIST[1] (e7 03 00 01 )" },
    .{ .hex = "680e000002002d0147002f00e7030001", .dir = .controlled_to_controlling, .note = "I-Format / C_SC_NA_1 / ACTIVATION_CON / NEGATIVE / CA 47 / 1st IOA 999 / LIST[1] (e7 03 00 01 )" },
    .{ .hex = "680e020002002d012f002f00e7030001", .dir = .controlled_to_controlling, .note = "I-Format / C_SC_NA_1 / UNKNOWN_INFORMATION_OBJECT_ADDRESS / POSITIVE / CA 47 / 1st IOA 999 / LIST[1] (e7 03 00 01 )" },
    .{ .hex = "680e00000000640163002f0000000014", .dir = .controlling_to_controlled, .note = "I-Format / C_IC_NA_1 / INTERROGATED_BY_GROUP_15 / NEGATIVE / CA 47 / 1st IOA 0 / LIST[1] (00 00 00 14 )" },
    .{ .hex = "680e0000020064016d002f0000000014", .dir = .controlled_to_controlling, .note = "I-Format / C_IC_NA_1 / UNKNOWN_CAUSE_OF_TRANSMISSION / NEGATIVE / CA 47 / 1st IOA 0 / LIST[1] (00 00 00 14 )" },
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn bytesOf(hex: []const u8, buf: []u8) []u8 {
    return std.fmt.hexToBytes(buf, hex) catch unreachable;
}

test "every captured APDU decodes" {
    var buf: [apci.max_apdu_len]u8 = undefined;
    for (captured) |g| {
        const raw = bytesOf(g.hex, &buf);
        const frame = apci.decode(raw) catch |e| {
            std.debug.print("failed to decode golden {s}: {s}\n{s}\n", .{ g.hex, @errorName(e), g.note });
            return e;
        };
        try testing.expectEqual(raw.len, frame.len);
        switch (frame.control) {
            .i => {
                // One capture entry is the deliberate unknown-type-id probe
                // (type 200) sent to provoke an error reply; it is expected to
                // have no modelled element layout.
                const h = try asdu.decodeHeader(frame.asdu, asdu.default_params);
                if (asdu.shapeOf(h.type_id) == null) continue;
                // Every other I-format golden must parse as an ASDU under the
                // 3/2/originator profile that IEC 60870-5-104 fixes.
                const a = asdu.decode(frame.asdu, asdu.default_params) catch |e| {
                    std.debug.print("failed to decode ASDU of {s}: {s}\n{s}\n", .{ g.hex, @errorName(e), g.note });
                    return e;
                };
                var it = a.objects();
                var n: usize = 0;
                while (try it.next()) |_| n += 1;
                try testing.expectEqual(@as(usize, a.header.vsq.count), n);
            },
            .s, .u => try testing.expectEqual(@as(usize, 0), frame.asdu.len),
        }
    }
}

test "every captured APDU re-encodes to the identical octets" {
    var buf: [apci.max_apdu_len]u8 = undefined;
    var out: [apci.max_apdu_len]u8 = undefined;
    var asdu_buf: [apci.max_asdu_len]u8 = undefined;
    for (captured) |g| {
        const raw = bytesOf(g.hex, &buf);
        const frame = try apci.decode(raw);

        // Rebuild the ASDU from the decoded objects, not from the raw bytes,
        // so the builder itself is what is being checked.
        var body: []const u8 = frame.asdu;
        if (frame.control == .i) {
            const h = try asdu.decodeHeader(frame.asdu, asdu.default_params);
            if (asdu.shapeOf(h.type_id) == null) continue; // the type-200 probe
            const a = try asdu.decode(frame.asdu, asdu.default_params);
            var b = try asdu.Builder.init(
                &asdu_buf,
                asdu.default_params,
                a.header.type_id,
                a.header.cause,
                a.header.common_address,
                a.header.vsq.sq,
            );
            var it = a.objects();
            while (try it.next()) |o| try b.add(o.ioa, o.element, o.time);
            body = try b.finish();
            try testing.expectEqualSlices(u8, frame.asdu, body);
        }
        const again = try apci.encode(frame.control, body, &out);
        testing.expectEqualSlices(u8, raw, again) catch |e| {
            std.debug.print("re-encode mismatch for {s}\n{s}\n", .{ g.hex, g.note });
            return e;
        };
    }
}

/// Finds the golden whose hex is exactly `hex`, so a semantic assertion below
/// cannot silently drift onto a different frame.
fn golden(hex: []const u8) []const u8 {
    for (captured) |g| {
        if (std.mem.eql(u8, g.hex, hex)) return g.hex;
    }
    unreachable;
}

fn decodeAsdu(hex: []const u8, buf: []u8) !asdu.Asdu {
    const raw = bytesOf(golden(hex), buf);
    const frame = try apci.decode(raw);
    return asdu.decode(frame.asdu, asdu.default_params);
}

test "goldens: the six U-format frames are exactly what the peer sent" {
    var buf: [8]u8 = undefined;
    const cases = [_]struct { hex: []const u8, f: apci.UFunction }{
        .{ .hex = "680407000000", .f = .startdt_act },
        .{ .hex = "68040b000000", .f = .startdt_con },
        .{ .hex = "680413000000", .f = .stopdt_act },
        .{ .hex = "680423000000", .f = .stopdt_con },
        .{ .hex = "680443000000", .f = .testfr_act },
        .{ .hex = "680483000000", .f = .testfr_con },
    };
    for (cases) |c| {
        const raw = bytesOf(golden(c.hex), &buf);
        try testing.expectEqual(c.f, (try apci.decode(raw)).control.u);
        try testing.expectEqualSlices(u8, raw, &apci.encodeU(c.f));
    }
}

test "goldens: S-format acknowledgements carry the N(R) the peer meant" {
    var buf: [8]u8 = undefined;
    // 0x0012 >> 1 = 9, 0x0044 >> 1 = 34, 0x0006 >> 1 = 3.
    const cases = [_]struct { hex: []const u8, nr: apci.Seq }{
        .{ .hex = "680401001200", .nr = 9 },
        .{ .hex = "680401004400", .nr = 34 },
        .{ .hex = "680401000600", .nr = 3 },
    };
    for (cases) |c| {
        const raw = bytesOf(golden(c.hex), &buf);
        try testing.expectEqual(c.nr, (try apci.decode(raw)).control.s.recv_seq);
    }
}

test "goldens: I-format sequence numbers advance as the capture shows" {
    var buf: [apci.max_apdu_len]u8 = undefined;
    // "68 14 00 00 02 00" -> N(S) 0, N(R) 1 (the clock-sync confirmation).
    const raw = bytesOf(golden("681400000200670107002f00000000cb9c120317071a"), &buf);
    const f = try apci.decode(raw);
    try testing.expectEqual(@as(apci.Seq, 0), f.control.i.send_seq);
    try testing.expectEqual(@as(apci.Seq, 1), f.control.i.recv_seq);

    // "68 19 1a 00 3e 00" -> N(S) 13, N(R) 31.
    const raw2 = bytesOf(golden("68191a003e003f0106002f003c010000001c4100cab3120317071a"), &buf);
    const f2 = try apci.decode(raw2);
    try testing.expectEqual(@as(apci.Seq, 13), f2.control.i.send_seq);
    try testing.expectEqual(@as(apci.Seq, 31), f2.control.i.recv_seq);
}

test "goldens: general interrogation activation, confirmation and termination" {
    var buf: [apci.max_apdu_len]u8 = undefined;
    const act = try decodeAsdu("680e02000200640106002f0000000014", &buf);
    try testing.expectEqual(asdu.TypeId.c_ic_na_1, act.header.type_id);
    try testing.expectEqual(asdu.Cot.activation, act.header.cause.cot);
    try testing.expect(!act.header.cause.negative);
    try testing.expectEqual(@as(u16, 47), act.header.common_address);
    var it = act.objects();
    const o = (try it.next()).?;
    try testing.expectEqual(@as(u32, 0), o.ioa);
    try testing.expectEqual(info.Qoi.station, o.element.qoi);

    var b2: [apci.max_apdu_len]u8 = undefined;
    const con = try decodeAsdu("680e02000400640107002f0000000014", &b2);
    try testing.expectEqual(asdu.Cot.activation_con, con.header.cause.cot);
    var b3: [apci.max_apdu_len]u8 = undefined;
    const term = try decodeAsdu("680e1c00040064010a002f0000000014", &b3);
    try testing.expectEqual(asdu.Cot.activation_termination, term.header.cause.cot);
}

test "goldens: monitoring values decode to the values the RTU was set to" {
    var buf: [apci.max_apdu_len]u8 = undefined;

    // M_SP_NA_1, IOA 101, single point ON, good quality.
    {
        const a = try decodeAsdu("680e04000400018114002f0065000001", &buf);
        try testing.expectEqual(asdu.TypeId.m_sp_na_1, a.header.type_id);
        try testing.expectEqual(asdu.Cot.interrogated_by_station, a.header.cause.cot);
        // lib60870 sets SQ even for a single object.
        try testing.expect(a.header.vsq.sq);
        var it = a.objects();
        const o = (try it.next()).?;
        try testing.expectEqual(@as(u32, 101), o.ioa);
        try testing.expect(o.element.siq.on);
        try testing.expect(o.element.siq.quality.isGood());
    }
    // M_DP_NA_1, IOA 102, double point ON.
    {
        const a = try decodeAsdu("680e06000400038114002f0066000002", &buf);
        var it = a.objects();
        const o = (try it.next()).?;
        try testing.expectEqual(@as(u32, 102), o.ioa);
        try testing.expectEqual(info.DoublePoint.on, o.element.diq.state);
    }
    // M_ST_NA_1, IOA 103, step position 5, not transient.
    {
        const a = try decodeAsdu("680f08000400058114002f006700000500", &buf);
        var it = a.objects();
        const o = (try it.next()).?;
        try testing.expectEqual(@as(i8, 5), o.element.step.position.value);
        try testing.expect(!o.element.step.position.transient);
    }
    // M_ME_NA_1, IOA 105, normalised 0.5 -> raw 0x4000.
    {
        const a = try decodeAsdu("68100c000400098114002f00690000004000", &buf);
        var it = a.objects();
        const o = (try it.next()).?;
        try testing.expectEqual(@as(i16, 16384), o.element.normalized.value.raw);
        try testing.expectApproxEqAbs(@as(f32, 0.5), o.element.normalized.value.toFloat(), 1e-6);
    }
    // M_ME_NB_1, IOA 106, scaled -1234.
    {
        const a = try decodeAsdu("68100e0004000b8114002f006a00002efb00", &buf);
        var it = a.objects();
        try testing.expectEqual(@as(i16, -1234), (try it.next()).?.element.scaled.value);
    }
    // M_ME_NC_1, IOA 107, short float 3.14159.
    {
        const a = try decodeAsdu("6812100004000d8114002f006b0000d00f494000", &buf);
        var it = a.objects();
        try testing.expectApproxEqAbs(@as(f32, 3.14159), (try it.next()).?.element.short_float.value, 1e-5);
    }
    // M_IT_NA_1, IOA 108, counter reading answering a counter interrogation.
    {
        const a = try decodeAsdu("6812200006000f8125002f006c00000000000000", &buf);
        try testing.expectEqual(asdu.Cot.requested_by_general_counter, a.header.cause.cot);
        var it = a.objects();
        const o = (try it.next()).?;
        try testing.expectEqual(@as(u32, 108), o.ioa);
        try testing.expectEqual(@as(i32, 0), o.element.counter.counter);
    }
}

test "goldens: the CP56Time2a-tagged monitoring types carry a decodable tag" {
    var buf: [apci.max_apdu_len]u8 = undefined;
    // Every time-tagged golden in the capture carries the same instant:
    // 2026-07-23 03:18:38.135 local time.
    const want = info.CP56Time2a{
        .millisecond = 135,
        .second = 38,
        .minute = 18,
        .hour = 3,
        .day = 23,
        .day_of_week = 0,
        .month = 7,
        .year = 26,
    };
    const hexes = [_][]const u8{
        "6815120004001e8114002f00c9000001f794120317071a", // M_SP_TB_1
        "6815140004001f8114002f00ca000001f794120317071a", // M_DP_TB_1
        "681716000400228114002f00cb000000e000f794120317071a", // M_ME_TD_1
        "681718000400238114002f00cc0000e11000f794120317071a", // M_ME_TE_1
        "68191a000400248114002f00cd0000000020c000f794120317071a", // M_ME_TF_1
        "681922000600258125002f00ce00000000000000f794120317071a", // M_IT_TB_1
    };
    for (hexes) |h| {
        const a = try decodeAsdu(h, &buf);
        var it = a.objects();
        const o = (try it.next()).?;
        try testing.expectEqual(want, o.time.cp56Time().?);
    }
    // ... and the values behind those tags.
    {
        const a = try decodeAsdu("681716000400228114002f00cb000000e000f794120317071a", &buf);
        var it = a.objects();
        const o = (try it.next()).?;
        try testing.expectEqual(@as(u32, 203), o.ioa);
        try testing.expectApproxEqAbs(@as(f32, -0.25), o.element.normalized.value.toFloat(), 1e-6);
    }
    {
        const a = try decodeAsdu("68191a000400248114002f00cd0000000020c000f794120317071a", &buf);
        var it = a.objects();
        try testing.expectEqual(@as(f32, -2.5), (try it.next()).?.element.short_float.value);
    }
}

test "goldens: SQ = 1 with twelve objects, one address, consecutive addresses" {
    var buf: [apci.max_apdu_len]u8 = undefined;
    const a = try decodeAsdu("681902000200018c14002f00e80300000100010001000100010001", &buf);
    try testing.expectEqual(asdu.TypeId.m_sp_na_1, a.header.type_id);
    try testing.expect(a.header.vsq.sq);
    try testing.expectEqual(@as(u7, 12), a.header.vsq.count);
    var it = a.objects();
    var i: u32 = 0;
    while (try it.next()) |o| : (i += 1) {
        try testing.expectEqual(@as(u32, 1000 + i), o.ioa);
        // The RTU alternated the points: even index off, odd index on.
        try testing.expectEqual(i % 2 == 1, o.element.siq.on);
    }
    try testing.expectEqual(@as(u32, 12), i);
}

test "goldens: select-before-operate really is two frames differing in one bit" {
    var sel_buf: [apci.max_apdu_len]u8 = undefined;
    var exe_buf: [apci.max_apdu_len]u8 = undefined;
    const sel = try decodeAsdu("680e080028002d0106002f002d010081", &sel_buf);
    const exe = try decodeAsdu("680e0a002a002d0106002f002d010001", &exe_buf);
    var si = sel.objects();
    var ei = exe.objects();
    const so = (try si.next()).?;
    const eo = (try ei.next()).?;
    try testing.expectEqual(@as(u32, 301), so.ioa);
    try testing.expectEqual(so.ioa, eo.ioa);
    try testing.expectEqual(info.SelectExecute.select, so.element.sco.select);
    try testing.expectEqual(info.SelectExecute.execute, eo.element.sco.select);
    try testing.expect(so.element.sco.on and eo.element.sco.on);
    // The set-point pair does the same through the QOS octet.
    const ssel = try decodeAsdu("681010003200300106002f00300100002080", &sel_buf);
    const sexe = try decodeAsdu("681012003400300106002f00300100002000", &exe_buf);
    var ssi = ssel.objects();
    var sei = sexe.objects();
    const sso = (try ssi.next()).?;
    const seo = (try sei.next()).?;
    try testing.expectEqual(info.SelectExecute.select, sso.element.setpoint_normalized.qos.select);
    try testing.expectEqual(info.SelectExecute.execute, seo.element.setpoint_normalized.qos.select);
    try testing.expectEqual(@as(i16, 8192), sso.element.setpoint_normalized.value.raw);
    try testing.expectEqual(sso.element.setpoint_normalized.value.raw, seo.element.setpoint_normalized.value.raw);
}

test "goldens: the command types carry the values the master sent" {
    var buf: [apci.max_apdu_len]u8 = undefined;
    {
        const a = try decodeAsdu("680e0c002e002e0106002f002e010002", &buf);
        var it = a.objects();
        const o = (try it.next()).?;
        try testing.expectEqual(@as(u32, 302), o.ioa);
        try testing.expectEqual(info.DoublePoint.on, o.element.dco.state);
    }
    {
        const a = try decodeAsdu("680e0e0030002f0106002f002f010002", &buf);
        var it = a.objects();
        try testing.expectEqual(info.StepCommand.higher, (try it.next()).?.element.rco.step);
    }
    {
        const a = try decodeAsdu("681014003800310106002f00310100090300", &buf);
        var it = a.objects();
        try testing.expectEqual(@as(i16, 777), (try it.next()).?.element.setpoint_scaled.value);
    }
    {
        const a = try decodeAsdu("681216003a00320106002f003201000000c03f00", &buf);
        var it = a.objects();
        try testing.expectEqual(@as(f32, 1.5), (try it.next()).?.element.setpoint_float.value);
    }
    // C_SC_TA_1 and C_SE_TC_1: the same commands with a CP56Time2a appended.
    {
        const a = try decodeAsdu("681518003c003a0106002f00370100013ab2120317071a", &buf);
        try testing.expectEqual(asdu.TypeId.c_sc_ta_1, a.header.type_id);
        var it = a.objects();
        const o = (try it.next()).?;
        try testing.expectEqual(@as(u32, 311), o.ioa);
        try testing.expect(o.element.sco.on);
        try testing.expect(o.time.cp56Time() != null);
    }
    {
        const a = try decodeAsdu("68191a003e003f0106002f003c010000001c4100cab3120317071a", &buf);
        try testing.expectEqual(asdu.TypeId.c_se_tc_1, a.header.type_id);
        var it = a.objects();
        const o = (try it.next()).?;
        try testing.expectEqual(@as(f32, 9.75), o.element.setpoint_float.value);
    }
}

test "goldens: clock sync, counter interrogation, read and test commands" {
    var buf: [apci.max_apdu_len]u8 = undefined;
    {
        const a = try decodeAsdu("681400000000670106002f00000000cb9c120317071a", &buf);
        try testing.expectEqual(asdu.TypeId.c_cs_na_1, a.header.type_id);
        var it = a.objects();
        const o = (try it.next()).?;
        try testing.expectEqual(@as(u32, 0), o.ioa);
        const t = o.time.cp56Time().?;
        // 0x9CCB = 40139 -> 40 s 139 ms.
        try testing.expectEqual(@as(u8, 40), t.second);
        try testing.expectEqual(@as(u16, 139), t.millisecond);
        try testing.expectEqual(@as(u8, 7), t.month);
    }
    {
        const a = try decodeAsdu("680e04001e00650106002f0000000005", &buf);
        try testing.expectEqual(asdu.TypeId.c_ci_na_1, a.header.type_id);
        var it = a.objects();
        const q = (try it.next()).?.element.qcc;
        try testing.expectEqual(info.CounterRequest.general, q.request);
        try testing.expectEqual(info.CounterFreeze.read, q.freeze);
    }
    {
        const a = try decodeAsdu("680d1c004000660105002f00650000", &buf);
        try testing.expectEqual(asdu.TypeId.c_rd_na_1, a.header.type_id);
        try testing.expectEqual(asdu.Cot.request, a.header.cause.cot);
        var it = a.objects();
        const o = (try it.next()).?;
        try testing.expectEqual(@as(u32, 101), o.ioa);
        try testing.expectEqual(asdu.Element{ .empty = {} }, o.element);
    }
    {
        const a = try decodeAsdu("6816060026006b0106002f00000000000091a6120317071a", &buf);
        try testing.expectEqual(asdu.TypeId.c_ts_ta_1, a.header.type_id);
        var it = a.objects();
        const o = (try it.next()).?;
        try testing.expectEqual(@as(u16, 0), o.element.fbp);
        try testing.expect(o.time.cp56Time() != null);
    }
}

test "goldens: the error causes of transmission the peer generated" {
    var buf: [apci.max_apdu_len]u8 = undefined;
    // Unknown common address: a negative activation confirmation, then a
    // separate ASDU with COT 46.
    {
        const a = try decodeAsdu("680e0000020064014700630000000014", &buf);
        try testing.expectEqual(asdu.Cot.activation_con, a.header.cause.cot);
        try testing.expect(a.header.cause.negative);
        try testing.expectEqual(@as(u16, 99), a.header.common_address);
    }
    {
        const a = try decodeAsdu("680e0200020064012e00630000000014", &buf);
        try testing.expectEqual(asdu.Cot.unknown_common_address, a.header.cause.cot);
        try testing.expect(!a.header.cause.negative);
    }
    // Unknown information-object address.
    {
        const a = try decodeAsdu("680e000002002d0147002f00e7030001", &buf);
        try testing.expectEqual(asdu.Cot.activation_con, a.header.cause.cot);
        try testing.expect(a.header.cause.negative);
        var it = a.objects();
        try testing.expectEqual(@as(u32, 999), (try it.next()).?.ioa);
    }
    {
        const a = try decodeAsdu("680e020002002d012f002f00e7030001", &buf);
        try testing.expectEqual(asdu.Cot.unknown_ioa, a.header.cause.cot);
    }
    // Unknown cause of transmission, flagged negative.
    {
        const a = try decodeAsdu("680e0000020064016d002f0000000014", &buf);
        try testing.expectEqual(asdu.Cot.unknown_cause, a.header.cause.cot);
        try testing.expect(a.header.cause.negative);
    }
    // The master's own frame with an unmodelled type id (200) still decodes
    // at the APCI layer; only the ASDU codec refuses it.
    {
        var b: [apci.max_apdu_len]u8 = undefined;
        const raw = bytesOf(golden("680e00000000c80106002f0000000000"), &b);
        const f = try apci.decode(raw);
        try testing.expectError(error.UnsupportedTypeId, asdu.decode(f.asdu, asdu.default_params));
        // The data unit identifier itself is still readable.
        const h = try asdu.decodeHeader(f.asdu, asdu.default_params);
        try testing.expectEqual(@as(u8, 200), @intFromEnum(h.type_id));
        try testing.expectEqual(asdu.Cot.activation, h.cause.cot);
    }
}

test "goldens: the capture covers the type ids this module claims to support" {
    var buf: [apci.max_apdu_len]u8 = undefined;
    var seen = std.AutoHashMap(u8, void).init(testing.allocator);
    defer seen.deinit();
    for (captured) |g| {
        const raw = bytesOf(g.hex, &buf);
        const f = try apci.decode(raw);
        if (f.control != .i) continue;
        const h = try asdu.decodeHeader(f.asdu, asdu.default_params);
        try seen.put(@intFromEnum(h.type_id), {});
    }
    // Monitoring, control and system types all appear in the capture.
    const must = [_]asdu.TypeId{
        .m_sp_na_1, .m_dp_na_1, .m_st_na_1, .m_bo_na_1, .m_me_na_1, .m_me_nb_1,
        .m_me_nc_1, .m_it_na_1, .m_sp_tb_1, .m_dp_tb_1, .m_me_td_1, .m_me_te_1,
        .m_me_tf_1, .m_it_tb_1, .c_sc_na_1, .c_dc_na_1, .c_rc_na_1, .c_se_na_1,
        .c_se_nb_1, .c_se_nc_1, .c_sc_ta_1, .c_se_tc_1, .c_ic_na_1, .c_ci_na_1,
        .c_rd_na_1, .c_cs_na_1, .c_ts_ta_1,
    };
    for (must) |t| {
        if (!seen.contains(@intFromEnum(t))) {
            std.debug.print("type id {d} missing from the capture\n", .{@intFromEnum(t)});
            return error.TestUnexpectedResult;
        }
    }
}

// ── the flow-control layer: a real peer through the 15-bit sequence wrap ──
//
// Everything above anchors the ASDU/APCI *codec*. It does not touch F6: the
// k/w window, t0..t3 and the 32768-frame sequence wrap were, before this,
// validated only between two instances of *this* module with a fake clock —
// SPEC.md itself calls the wrap "the part of the protocol that is actually
// hard", and no third-party stack had ever been driven through it.
//
// Captured 2026-08-08 with a real `c104` 2.2.1 (Fraunhofer FIT's Python
// binding over `lib60870-C`, the reference C stack) outstation, paced to
// avoid overrunning its internal send queue:
//
//   python3 -c '
//     import c104, time
//     srv = c104.Server(ip="127.0.0.1", port=P, tick_rate_ms=50)
//     srv.protocol_parameters.message_timeout = 60       # t1
//     srv.protocol_parameters.send_window_size = 100     # k
//     srv.protocol_parameters.receive_window_size = 50   # w
//     st = srv.add_station(common_address=1)
//     pt = st.add_point(io_address=100, type=c104.Type.M_ME_NC_1)
//     srv.start()
//     # ...wait for a client, then...
//     for i in range(33000):
//         pt.value = float(i % 1000)
//         pt.transmit(cause=c104.Cot.SPONTANEOUS)
//         if i % 40 == 39: time.sleep(0.01)   # let the link drain
//   '
//
// against this module's own `Client` (`client.zig`'s
// `"live: drive send_seq/recv_seq through the 15-bit wrap against a real
// outstation"`, gated on `IEC104_TEST_WRAP`, an in-process `RawTap` recording
// every APCI frame — no external proxy). The client's own `recv_seq` wrapped
// 32767 → 0 exactly where the peer's own N(S) did:
// `monitoring=32773 recv_seq=5 wrapped=true`.
//
// These are the last 64 frames of that run: real `M_ME_NC_1` spontaneous
// reports (`rx`, type id 13 = `0x0d`) from the outstation's own N(S) counter,
// the S-format acknowledgements this module's `Client` sent back (`tx`), the
// 32767→0 wrap itself (frame 60, `feff...`→frame 61, `0000...`), and a few
// frames past it. No third-party source was read as a design reference —
// `c104` was driven as a black box only, generating real traffic; under
// CONVENTIONS §5 that is a test oracle, not a design reference.
pub const WrapDirection = enum {
    /// Outstation -> master (this module's `Client`).
    rx,
    /// Master -> outstation.
    tx,
};

pub const WrapFrame = struct {
    dir: WrapDirection,
    hex: []const u8,
};

/// `recv_seq` (the master's own "next N(S) I expect") immediately before the
/// first frame in `wrap_table` — this module's own `recv_seq` at that point
/// in the real capture, read from `RawTap`'s companion debug output.
pub const wrap_start_recv_seq: apci.Seq = 32716;

pub const wrap_table = [_]WrapFrame{
    .{ .dir = .rx, .hex = "681298ff00000d01030001006400000000334400" },
    .{ .dir = .rx, .hex = "68129aff00000d01030001006400000040334400" },
    .{ .dir = .rx, .hex = "68129cff00000d01030001006400000080334400" },
    .{ .dir = .rx, .hex = "68129eff00000d010300010064000000c0334400" },
    .{ .dir = .tx, .hex = "68040100a0ff" },
    .{ .dir = .rx, .hex = "6812a0ff00000d01030001006400000000344400" },
    .{ .dir = .rx, .hex = "6812a2ff00000d01030001006400000040344400" },
    .{ .dir = .rx, .hex = "6812a4ff00000d01030001006400000080344400" },
    .{ .dir = .rx, .hex = "6812a6ff00000d010300010064000000c0344400" },
    .{ .dir = .rx, .hex = "6812a8ff00000d01030001006400000000354400" },
    .{ .dir = .rx, .hex = "6812aaff00000d01030001006400000040354400" },
    .{ .dir = .rx, .hex = "6812acff00000d01030001006400000080354400" },
    .{ .dir = .rx, .hex = "6812aeff00000d010300010064000000c0354400" },
    .{ .dir = .tx, .hex = "68040100b0ff" },
    .{ .dir = .rx, .hex = "6812b0ff00000d01030001006400000000364400" },
    .{ .dir = .rx, .hex = "6812b2ff00000d01030001006400000040364400" },
    .{ .dir = .rx, .hex = "6812b4ff00000d01030001006400000080364400" },
    .{ .dir = .rx, .hex = "6812b6ff00000d010300010064000000c0364400" },
    .{ .dir = .rx, .hex = "6812b8ff00000d01030001006400000000374400" },
    .{ .dir = .rx, .hex = "6812baff00000d01030001006400000040374400" },
    .{ .dir = .rx, .hex = "6812bcff00000d01030001006400000080374400" },
    .{ .dir = .rx, .hex = "6812beff00000d010300010064000000c0374400" },
    .{ .dir = .tx, .hex = "68040100c0ff" },
    .{ .dir = .rx, .hex = "6812c0ff00000d01030001006400000000384400" },
    .{ .dir = .rx, .hex = "6812c2ff00000d01030001006400000040384400" },
    .{ .dir = .rx, .hex = "6812c4ff00000d01030001006400000080384400" },
    .{ .dir = .rx, .hex = "6812c6ff00000d010300010064000000c0384400" },
    .{ .dir = .rx, .hex = "6812c8ff00000d01030001006400000000394400" },
    .{ .dir = .rx, .hex = "6812caff00000d01030001006400000040394400" },
    .{ .dir = .rx, .hex = "6812ccff00000d01030001006400000080394400" },
    .{ .dir = .rx, .hex = "6812ceff00000d010300010064000000c0394400" },
    .{ .dir = .tx, .hex = "68040100d0ff" },
    .{ .dir = .rx, .hex = "6812d0ff00000d010300010064000000003a4400" },
    .{ .dir = .rx, .hex = "6812d2ff00000d010300010064000000403a4400" },
    .{ .dir = .rx, .hex = "6812d4ff00000d010300010064000000803a4400" },
    .{ .dir = .rx, .hex = "6812d6ff00000d010300010064000000c03a4400" },
    .{ .dir = .rx, .hex = "6812d8ff00000d010300010064000000003b4400" },
    .{ .dir = .rx, .hex = "6812daff00000d010300010064000000403b4400" },
    .{ .dir = .rx, .hex = "6812dcff00000d010300010064000000803b4400" },
    .{ .dir = .rx, .hex = "6812deff00000d010300010064000000c03b4400" },
    .{ .dir = .tx, .hex = "68040100e0ff" },
    .{ .dir = .rx, .hex = "6812e0ff00000d010300010064000000003c4400" },
    .{ .dir = .rx, .hex = "6812e2ff00000d010300010064000000403c4400" },
    .{ .dir = .rx, .hex = "6812e4ff00000d010300010064000000803c4400" },
    .{ .dir = .rx, .hex = "6812e6ff00000d010300010064000000c03c4400" },
    .{ .dir = .rx, .hex = "6812e8ff00000d010300010064000000003d4400" },
    .{ .dir = .rx, .hex = "6812eaff00000d010300010064000000403d4400" },
    .{ .dir = .rx, .hex = "6812ecff00000d010300010064000000803d4400" },
    .{ .dir = .rx, .hex = "6812eeff00000d010300010064000000c03d4400" },
    .{ .dir = .tx, .hex = "68040100f0ff" },
    .{ .dir = .rx, .hex = "6812f0ff00000d010300010064000000003e4400" },
    .{ .dir = .rx, .hex = "6812f2ff00000d010300010064000000403e4400" },
    .{ .dir = .rx, .hex = "6812f4ff00000d010300010064000000803e4400" },
    .{ .dir = .rx, .hex = "6812f6ff00000d010300010064000000c03e4400" },
    .{ .dir = .rx, .hex = "6812f8ff00000d010300010064000000003f4400" },
    .{ .dir = .rx, .hex = "6812faff00000d010300010064000000403f4400" },
    .{ .dir = .rx, .hex = "6812fcff00000d010300010064000000803f4400" },
    .{ .dir = .rx, .hex = "6812feff00000d010300010064000000c03f4400" },
    .{ .dir = .tx, .hex = "680401000000" },
    .{ .dir = .rx, .hex = "6812000000000d01030001006400000000404400" },
    .{ .dir = .rx, .hex = "6812020000000d01030001006400000040404400" },
    .{ .dir = .rx, .hex = "6812040000000d01030001006400000080404400" },
    .{ .dir = .rx, .hex = "6812060000000d010300010064000000c0404400" },
    .{ .dir = .rx, .hex = "6812080000000d01030001006400000000414400" },
};

test "goldens: every wrap_table frame decodes and the rx sequence numbers are exactly what the peer sent" {
    var buf: [apci.max_apdu_len]u8 = undefined;
    var expected_ns: apci.Seq = wrap_start_recv_seq;
    var saw_wrap = false;
    for (wrap_table) |g| {
        const raw = bytesOf(g.hex, &buf);
        const f = try apci.decode(raw);
        switch (g.dir) {
            .rx => {
                const ns = f.control.i.send_seq;
                try testing.expectEqual(expected_ns, ns);
                if (expected_ns == 32767) saw_wrap = true;
                expected_ns +%= 1;
            },
            .tx => try testing.expect(f.control == .s),
        }
    }
    // The table must actually straddle the wrap, not just approach it.
    try testing.expect(saw_wrap);
    try testing.expectEqual(@as(apci.Seq, 5), expected_ns);
}

// The strong test: replays the captured session through a fresh
// `state.Connection`, fast-forwarded to the real capture's own starting
// point (the same technique `state.zig`'s pre-existing self-only wrap test
// already uses — `recv_seq`/`send_seq`/`ack_seq`/`last_sent_ack` are public
// fields for exactly this). Every `rx` frame is fed through `onFrame`; `tick`
// runs after each one, exactly as `Client.poll` does, so the w=8 ack cadence
// the capture shows is reproduced rather than assumed. This is not
// decode∘encode agreeing with itself — `onFrame`'s `UnexpectedSequence`
// check is what a consistent-but-wrong wrap implementation would trip, and
// nothing here generated the sequence numbers being checked against: a real
// `lib60870-C` outstation did, live.
test "a real outstation's session replays byte-exact through this module's own Connection, across the wrap" {
    var c = try state.Connection.init(.{}, .controlling);
    c.beginConnect(0);
    c.onTcpConnected(0);
    _ = try c.startDataTransfer(0);
    _ = try c.onFrame(.{ .control = .{ .u = .startdt_con }, .asdu = &.{}, .len = 6 }, 0);
    try testing.expectEqual(state.State.started, c.state);

    // Fast-forward to the real capture's own starting point. Only the
    // receive side moves: in the real session the master (this side) never
    // sent an I-frame of its own, so its send_seq/ack_seq genuinely stayed
    // at 0 the whole time (confirmed in the live run's own diagnostics,
    // "send_seq=0 outstanding=0") — every captured `rx` I-frame's own N(R)
    // is 0 for that reason, not because it was faked here.
    c.recv_seq = wrap_start_recv_seq;
    c.last_sent_ack = wrap_start_recv_seq;

    var buf: [apci.max_apdu_len]u8 = undefined;
    var now: u64 = 1;
    var rx_count: usize = 0;
    for (wrap_table) |g| {
        if (g.dir != .rx) continue;
        const raw = bytesOf(g.hex, &buf);
        const f = try apci.decode(raw);
        const event = c.onFrame(f, now) catch |e| {
            std.debug.print("wrap replay failed at recv_seq={d}: {t}\n", .{ c.recv_seq, e });
            return e;
        };
        try testing.expect(event == .asdu);
        rx_count += 1;
        now += 1;
        _ = c.tick(now); // let acks go out on the same cadence Client.poll uses
    }
    try testing.expectEqual(wrap_table.len - 7, rx_count); // 7 tx (S-format) entries in the table
    // The wrap actually happened, driven entirely by real captured N(S)
    // values, not by a hand-picked expected value.
    try testing.expectEqual(@as(apci.Seq, 5), c.recv_seq);
}

// ── the t1 half of F6: a real peer driven to an ACTUAL acknowledgement
//    timeout ─────────────────────────────────────────────────────────────────
//
// The wrap capture above closed one half of audit finding F6; this closes the
// other. Until now no test had driven a third-party stack to a real t1
// expiry — the t1/t2/t3 behaviour was validated only between two instances of
// this module with an injected clock, i.e. against our own reading of §5.5.
//
// Method (2026-08-09): the third-party stack is the ACTIVE side and WE are a
// deliberately silent APCI endpoint — a bare TCP socket that acknowledges
// nothing. A conforming controlling station must give up after t1. Two runs,
// with `c104` 2.2.1 (Fraunhofer FIT's binding over `lib60870-C`) as the
// client, both at that stack's stock timers (t1 = 15 s, t3 = 20 s):
//
//   python3 -c '
//     # ...accept() on 127.0.0.1:P in a thread, log every APDU, reply only
//     # with STARTDT con in scenario I, never with an S-format...
//     import c104
//     cl = c104.Client(tick_rate_ms=100, command_timeout_ms=1000)
//     cl.add_connection(ip="127.0.0.1", port=P, init=c104.Init.INTERROGATION)
//     cl.start()
//   '
//
// Scenario I — we confirm STARTDT, then never acknowledge its I-frame:
//
//   t+ 0.00s  U STARTDT act              680407000000
//   t+ 0.00s  (ours) STARTDT con         68040b000000
//   t+ 0.00s  I N(S)=0 N(R)=0            680e0000000064010600ffff00000014
//   t+15.03s  peer closed the connection (FIN)
//
// 15.03 s after an unacknowledged I-frame, on a stack whose t1 is 15 s: **t1
// on an I-frame is confirmed live against a third-party implementation.**
// That is the assertion F6 asked for and never had.
//
// ⚠ Scenario U — we never confirm the STARTDT act at all:
//
//   t+ 0.00s  U STARTDT act              680407000000
//   t+20.03s  U TESTFR act               680443000000
//   t+35.06s  peer closed the connection (FIN)
//
// lib60870-C did **not** arm t1 on its outstanding `STARTDT act`: had it, the
// link would have died at t+15. It instead sat idle until t3 (20 s), sent
// `TESTFR act`, and died 15.03 s after THAT — t1 on the test APDU. This
// module is deliberately STRICTER: `state.Connection` arms t1 on any U-format
// *act*, `STARTDT`/`STOPDT` included (see `state.zig`'s "t1 expiry on an
// unconfirmed U-format act closes the connection"). Both readings fit §5.5's
// "time-out of send or test APDUs" — lib60870 reads "send or test" as
// I-format and TESTFR only. The divergence is one-way and safe: we drop a
// link whose STARTDT went unanswered for t1 where lib60870 waits t3+t1, and
// a peer that cannot confirm STARTDT within 15 s is dead either way. It is
// NOT a wire-format difference — nothing about the frames changes. Recorded
// here because an interop surprise ("why did the Zig side hang up during
// startup?") is exactly what an external anchor is for.
//
// `c104` was driven as a black box generating real traffic; no third-party
// source was read as a design reference (CONVENTIONS §5).

/// The frames the real controlling station put on the wire in the two runs
/// above, in order. `startdt_con` is the only one WE sent.
pub const t1_startdt_act = "680407000000";
pub const t1_startdt_con = "68040b000000";
pub const t1_interrogation = "680e0000000064010600ffff00000014";
pub const t1_testfr_act = "680443000000";

/// Seconds from the unacknowledged frame to the peer's FIN, as measured.
pub const t1_measured_i_frame_s = 15.03;
pub const t1_measured_testfr_s = 15.03; // 35.06 - 20.03
/// Seconds the peer sat idle before sending `TESTFR act` — its t3.
pub const t1_measured_t3_s = 20.03;

test "live-derived: the frames a real controlling station sent before its t1 fired" {
    var buf: [apci.max_apdu_len]u8 = undefined;

    // The two U-format frames, decoded as this module sees them.
    try testing.expectEqual(
        apci.Control{ .u = .startdt_act },
        (try apci.decode(bytesOf(t1_startdt_act, &buf))).control,
    );
    try testing.expectEqual(
        apci.Control{ .u = .startdt_con },
        (try apci.decode(bytesOf(t1_startdt_con, &buf))).control,
    );
    try testing.expectEqual(
        apci.Control{ .u = .testfr_act },
        (try apci.decode(bytesOf(t1_testfr_act, &buf))).control,
    );
    // `TESTFR act` is the frame lib60870-C DID arm t1 on, and `STARTDT act`
    // the one it did not — both are `act`s by our classification, which is
    // exactly where the two implementations part company.
    try testing.expect(apci.UFunction.startdt_act.isAct());
    try testing.expect(apci.UFunction.testfr_act.isAct());

    // The I-frame it never got acknowledged: the very first one on the link,
    // N(S)=0 / N(R)=0, carrying a general interrogation to the BROADCAST
    // common address 65535 — a CA no other golden in this file exercises
    // (the captures above use 47 and 99).
    const frame = try apci.decode(bytesOf(t1_interrogation, &buf));
    try testing.expectEqual(apci.Control{ .i = .{ .send_seq = 0, .recv_seq = 0 } }, frame.control);
    const a = try asdu.decode(frame.asdu, .{});
    try testing.expectEqual(asdu.TypeId.c_ic_na_1, a.header.type_id);
    try testing.expectEqual(@as(u16, 65535), a.header.common_address);
    try testing.expectEqual(asdu.Cot.activation, a.header.cause.cot);
    try testing.expect(!a.header.cause.negative);
    try testing.expectEqual(@as(u8, 1), a.header.vsq.count);
    var it = a.objects();
    const obj = (try it.next()).?;
    try testing.expectEqual(@as(u32, 0), obj.ioa);
    // QOI 20 = station interrogation (global).
    try testing.expectEqual(@as(u8, 20), @intFromEnum(obj.element.qoi));
}
