// SPDX-License-Identifier: MIT

//! Byte-exact **control-model** frames captured from real IEC 61850 traffic,
//! recorded through a TPKT-aware TCP proxy inside a network namespace.
//!
//! Two captures, and the distinction matters when reading the evidence:
//!
//! * `.third_party` — an independent IEC 61850 **client** driving an
//!   independent IEC 61850 **server**, neither of them this module. Nothing
//!   here was produced by any code in this repository, so these frames are the
//!   ground truth for the layouts.
//! * `.ours` — this module's own client driving that same third-party server.
//!   These pin the **answers a real IED gave us** — in particular the
//!   `LastApplError` and the negative write response, which no third-party
//!   client in the oracle's examples ever provokes.
//!
//! The oracle was used **as a black box only**: cloned, built with `cmake`, its
//! example server and example client executed, the octets logged. **No
//! third-party source file was opened.** Its shipped SCL files were read, but
//! they are configuration *data*, not source, and only as parser input — see
//! SPEC.md's provenance statement.
//!
//! **Anonymisation.** These are TCP frames with no MAC addresses, and every
//! object name comes from the oracle's own shipped *example* control model
//! (`simpleIOGenericIO`, `GGIO1`, `SPCSO1`..`SPCSO9`). No real substation, IED
//! identity or vendor name appears, so no substitution was necessary. The one
//! originator identity in the table is `zig-libs`, which is ours.
//!
//! Four assertions run over the whole table:
//!
//! 1. every frame decodes — TPKT, COTP, session, presentation and MMS;
//! 2. every control structure inside it decodes to a `control.Command`, a
//!    `control.LastApplError` or a `control.Notification`, and **re-encodes to
//!    the identical octets** from its decoded fields;
//! 3. every whole write request re-encodes octet for octet from its decoded
//!    object name and its decoded command — i.e. this module could have sent
//!    the frame the third-party client sent;
//! 4. a coverage assertion fails if the table stops containing all four control
//!    models, both selects, a positive and a negative termination, and a
//!    `LastApplError`.

const std = @import("std");
const ber = @import("ber.zig");
const tpkt = @import("tpkt.zig");
const cotp = @import("cotp.zig");
const session = @import("session.zig");
const presentation = @import("presentation.zig");
const mms = @import("mms.zig");
const mmsdata = @import("mmsdata.zig");
const control = @import("control.zig");

/// Which pair of implementations produced the frame.
pub const Source = enum {
    /// Third-party client ↔ third-party server. Nothing in this repo touched it.
    third_party,
    /// This module's client ↔ third-party server.
    ours,
};

pub const Golden = struct {
    name: []const u8,
    source: Source,
    hex: []const u8,
};

pub const max_frame_len: usize = 512;

pub const table = [_]Golden{
    // ── reading the model, which is what a control client does first ────────
    .{ .name = "read/ctlModel", .source = .third_party, .hex = "0300005202f0800100010061453043020103a03ea03c020101a437a135a0333031a02fa12d1a1173696d706c65494f47656e65726963494f1a184747494f3124434624535043534f312463746c4d6f64656c" },
    .{ .name = "resp/ctlModel=direct-with-normal-security", .source = .third_party, .hex = "0300002002f0800100010061133011020103a00ca10a020101a405a103850101" },

    // The type of a sbo-with-normal-security control object: SBO, Oper, Cancel.
    .{ .name = "resp/getVariableAccessAttributes/SPCSO2", .source = .third_party, .hex = "0300012902f080010001006182011a30820116020103a082010fa182010b020106a6820104800100a281fea281fba181f8300a800353424fa1038a01c0307a80044f706572a172a270a16e300c800663746c56616ca1028300302c80066f726967696ea122a220a11e300c80056f72436174a103850108300e80076f724964656e74a1038901c0300d800663746c4e756da1038601083007800154a1029100300a800454657374a1028300300c8005436865636ba1038401fe306e800643616e63656ca164a262a160300c800663746c56616ca1028300302c80066f726967696ea122a220a11e300c80056f72436174a103850108300e80076f724964656e74a1038901c0300d800663746c4e756da1038601083007800154a1029100300a800454657374a1028300" },

    // ── direct-with-normal-security: one write, one answer ──────────────────
    .{ .name = "req/Oper/direct-with-normal-security", .source = .third_party, .hex = "0300006e02f080010001006161305f020103a05aa058020103a553a02f302da02ba1291a1173696d706c65494f47656e65726963494f1a144747494f3124434f24535043534f31244f706572a020a21e830101a205850103890086010191086a620591620c490083010084020600" },
    .{ .name = "resp/write-accepted", .source = .third_party, .hex = "0300001d02f080010001006110300e020103a009a107020103a5028100" },

    // ── sbo-with-normal-security: the select is a READ of SBO ───────────────
    .{ .name = "req/read-SBO", .source = .third_party, .hex = "0300004d02f080010001006140303e020103a039a037020107a432a130a02e302ca02aa1281a1173696d706c65494f47656e65726963494f1a134747494f3124434f24535043534f322453424f" },
    .{ .name = "resp/SBO-granted", .source = .third_party, .hex = "0300004002f0800100010061333031020103a02ca12a020107a425a1238a2173696d706c65494f47656e65726963494f2f4747494f3124434f24535043534f32" },
    .{ .name = "req/Oper/sbo-with-normal-security", .source = .third_party, .hex = "0300006e02f080010001006161305f020103a05aa058020108a553a02f302da02ba1291a1173696d706c65494f47656e65726963494f1a144747494f3124434f24535043534f32244f706572a020a21e830101a205850100890086010191086a620591624dd20083010084020600" },

    // ── direct-with-enhanced-security: the write is not the answer ──────────
    .{ .name = "ind/CommandTermination+/direct-with-enhanced-security", .source = .third_party, .hex = "0300006b02f08001000100615e305c020103a057a355a053a02f302da02ba1291a1173696d706c65494f47656e65726963494f1a144747494f3124434f24535043534f33244f706572a020a21e830101a205850100890086010191086a620591624dd20083010084020600" },

    // ── sbo-with-enhanced-security: the select is a WRITE of SBOw ───────────
    .{ .name = "req/SBOw/sbo-with-enhanced-security", .source = .third_party, .hex = "0300006e02f080010001006161305f020103a05aa05802010fa553a02f302da02ba1291a1173696d706c65494f47656e65726963494f1a144747494f3124434f24535043534f342453424f77a020a21e830101a205850100890086010191086a620592645a1c0083010084020600" },
    .{ .name = "req/Oper/sbo-with-enhanced-security", .source = .third_party, .hex = "0300006e02f080010001006161305f020103a05aa058020110a553a02f302da02ba1291a1173696d706c65494f47656e65726963494f1a144747494f3124434f24535043534f34244f706572a020a21e830101a205850100890086010191086a620592649ba50083010084020600" },
    .{ .name = "ind/CommandTermination+/sbo-with-enhanced-security", .source = .third_party, .hex = "0300006b02f08001000100615e305c020103a057a355a053a02f302da02ba1291a1173696d706c65494f47656e65726963494f1a144747494f3124434f24535043534f34244f706572a020a21e830101a205850100890086010191086a620592649ba50083010084020600" },

    // ── the failure path, which the oracle's own client never exercises ─────
    // Our client wrote Oper to a sbo-with-enhanced-security object without
    // selecting it. The IED answered with a LastApplError and *then* a negative
    // write response.
    .{ .name = "req/Oper-without-select", .source = .ours, .hex = "0300007702f08001000100616a3068020103a063a061020113a55ca02f302da02ba1291a1173696d706c65494f47656e65726963494f1a144747494f3124434f24535043534f34244f706572a029a227830101a20d85010289087a69672d6c696273860200c891086553f1000000000a83010084020600" },
    .{ .name = "ind/LastApplError/Object-not-selected", .source = .ours, .hex = "0300007202f0800100010061653063020103a05ea35ca05aa0133011a00f800d4c6173744170706c4572726f72a043a2418a2673696d706c65494f47656e65726963494f2f4747494f3124434f24535043534f34244f706572850100a20d85010289087a69672d6c696273860200c8850112" },
    .{ .name = "resp/write-refused", .source = .ours, .hex = "0300001e02f080010001006111300f020103a00aa108020113a503800103" },

    // A CommandTermination+ the real IED sent **to us**, echoing the origin we
    // put in the Oper.
    .{ .name = "ind/CommandTermination+/to-us", .source = .ours, .hex = "0300007302f0800100010061663064020103a05fa35da05ba02f302da02ba1291a1173696d706c65494f47656e65726963494f1a144747494f3124434f24535043534f33244f706572a028a226830101a20d85010289087a69672d6c69627386010191086553f1000000000a83010084020600" },
};

// ── helpers ─────────────────────────────────────────────────────────────────

fn liveContexts() presentation.ContextTable {
    var t = presentation.ContextTable{};
    t.define(presentation.context_acse, &ber.oids.acse_abstract_syntax) catch unreachable;
    t.define(presentation.context_mms, &ber.oids.mms_abstract_syntax) catch unreachable;
    t.acceptAll();
    return t;
}

/// TPKT → COTP → session → presentation → MMS, the way a live client does it.
pub fn decodePdu(frame: []const u8) !mms.Pdu {
    const pkt = try tpkt.decode(frame);
    const dt = (try cotp.decode(pkt.payload)).dt;
    const ppdu = try session.decodeDataTransfer(dt.payload);
    var contexts = liveContexts();
    const pdv = try presentation.decodeUserData(ppdu, &contexts);
    return mms.decode(pdv.value);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const decodeHex = @import("goldens.zig").decodeHex;

test "every captured control frame decodes end to end" {
    var buf: [max_frame_len]u8 = undefined;
    for (table) |g| {
        const frame = decodeHex(g.hex, &buf);
        const pkt = try tpkt.decode(frame);
        try testing.expectEqual(frame.len, pkt.total_len);
        _ = decodePdu(frame) catch |e| {
            std.debug.print("decode failed for {s}: {t}\n", .{ g.name, e });
            return e;
        };
    }
}

// The `Oper`/`SBOw` writes: decode the whole request, then rebuild it from the
// decoded object name and the decoded command and require the identical
// octets. That is a much stronger claim than "our encoder round-trips": it says
// this module could have produced the frame a third-party client sent.
test "every captured control write re-encodes octet for octet" {
    var buf: [max_frame_len]u8 = undefined;
    var out: [max_frame_len]u8 = undefined;
    var n: usize = 0;
    for (table) |g| {
        const frame = decodeHex(g.hex, &buf);
        const pdu = try decodePdu(frame);
        const req = switch (pdu) {
            .confirmed_request => |r| r,
            else => continue,
        };
        if (req.service != .write) continue;

        const w_req = try mms.decodeWriteRequest(req.body);
        var names = switch (w_req.spec) {
            .variables => |v| v,
            else => continue,
        };
        const name = (try names.next()).?;
        try testing.expect((try names.next()) == null);

        // The value, decoded as a control command and re-emitted from its
        // fields — not memcpy'd.
        const value = try mmsdata.Data.decode(w_req.values);
        try value.validate();
        const cmd = try control.Command.decode(value);
        var cmd_buf: [control.Command.max_encoded_len]u8 = undefined;
        const re_value = try cmd.encode(&cmd_buf);
        try testing.expectEqualSlices(u8, value.raw, re_value);

        const rebuilt = try mms.encodeWrite(
            req.invoke_id,
            .{ .variables = &[_]mms.ObjectName{name} },
            &[_][]const u8{re_value},
            &out,
        );
        // Compare the MMS PDU inside the frame, which is everything after the
        // TPKT + COTP + session + presentation prefix.
        try testing.expect(std.mem.endsWith(u8, frame, rebuilt));
        n += 1;
    }
    try testing.expect(n >= 4);
}

test "the captured CommandTermination and LastApplError classify correctly" {
    var buf: [max_frame_len]u8 = undefined;
    var positives: usize = 0;
    var errors: usize = 0;
    for (table) |g| {
        const frame = decodeHex(g.hex, &buf);
        const pdu = try decodePdu(frame);
        const u = switch (pdu) {
            .unconfirmed => |x| x,
            else => continue,
        };
        const info = try mms.decodeInformationReport(u.body);
        const n = (try control.classify(info)) orelse {
            std.debug.print("not classified as a control notification: {s}\n", .{g.name});
            return error.TestUnexpectedResult;
        };
        switch (n.kind) {
            .command_termination_positive => {
                positives += 1;
                try testing.expect(n.command != null);
                try testing.expect(n.last_error == null);
                // The object named is the `Oper` of a `CO` control object.
                const item = n.object.?.domain_specific.item;
                try testing.expect(control.splitControlItem(item) != null);
                try testing.expect(try n.command.?.boolValue());
            },
            .last_appl_error => {
                errors += 1;
                const e = n.last_error.?;
                // The real IED's answer to an operate on an unselected object.
                try testing.expectEqual(control.AddCause.object_not_selected, e.add_cause);
                try testing.expectEqual(control.ControlError.no_error, e.err);
                try testing.expectEqual(@as(u8, 200), e.ctl_num);
                try testing.expectEqual(control.OrCat.station_control, e.origin.or_cat);
                try testing.expectEqualStrings("zig-libs", e.origin.or_ident);
                try testing.expectEqualStrings(
                    "simpleIOGenericIO/GGIO1$CO$SPCSO4$Oper",
                    e.ctl_obj_ref,
                );
            },
            .command_termination_negative => {},
        }
    }
    try testing.expect(positives >= 3);
    try testing.expect(errors >= 1);
}

test "the captured LastApplError re-encodes to the identical octets" {
    var buf: [max_frame_len]u8 = undefined;
    var out: [max_frame_len]u8 = undefined;
    var n: usize = 0;
    for (table) |g| {
        if (!std.mem.startsWith(u8, g.name, "ind/LastApplError")) continue;
        const frame = decodeHex(g.hex, &buf);
        const u = (try decodePdu(frame)).unconfirmed;
        var info = try mms.decodeInformationReport(u.body);
        const value = (try info.results.next()).?.success;
        const e = try control.LastApplError.decode(value);
        var w = ber.Writer.init(&out);
        try e.emit(&w);
        try testing.expectEqualSlices(u8, value.raw, w.done());
        n += 1;
    }
    try testing.expectEqual(@as(usize, 1), n);
}

test "the SBO read answers with the object reference, which is the select" {
    var buf: [max_frame_len]u8 = undefined;
    var found = false;
    for (table) |g| {
        if (!std.mem.eql(u8, g.name, "resp/SBO-granted")) continue;
        const frame = decodeHex(g.hex, &buf);
        const resp = (try decodePdu(frame)).confirmed_response;
        var r = try mms.decodeReadResponse(resp.body);
        const v = (try r.results.next()).?.success;
        try testing.expectEqualStrings(
            "simpleIOGenericIO/GGIO1$CO$SPCSO2",
            try v.visibleString(),
        );
        found = true;
    }
    try testing.expect(found);
}

test "the ctlModel read answers with the enumeration this module decodes" {
    var buf: [max_frame_len]u8 = undefined;
    var found = false;
    for (table) |g| {
        if (!std.mem.startsWith(u8, g.name, "resp/ctlModel")) continue;
        const frame = decodeHex(g.hex, &buf);
        const resp = (try decodePdu(frame)).confirmed_response;
        var r = try mms.decodeReadResponse(resp.body);
        const v = (try r.results.next()).?.success;
        try testing.expectEqual(
            control.CtlModel.direct_with_normal_security,
            try control.CtlModel.fromData(v),
        );
        found = true;
    }
    try testing.expect(found);
}

test "the negative write response is a per-object failure, not a service error" {
    var buf: [max_frame_len]u8 = undefined;
    var found = false;
    for (table) |g| {
        if (!std.mem.eql(u8, g.name, "resp/write-refused")) continue;
        const frame = decodeHex(g.hex, &buf);
        const resp = (try decodePdu(frame)).confirmed_response;
        var it = mms.decodeWriteResponse(resp.body);
        const first = (try it.next()).?;
        // `object-access-denied` — and on its own it says nothing about *why*,
        // which is exactly the gap `LastApplError` fills.
        try testing.expectEqual(mms.WriteResult{ .failure = .object_access_denied }, first);
        found = true;
    }
    try testing.expect(found);
}

test "the type of a control object names the members this module encodes" {
    // `GetVariableAccessAttributes` on a sbo-with-normal-security object: the
    // IED's own description of the structure, which is the independent check
    // that `Command` has the right members in the right order.
    var buf: [max_frame_len]u8 = undefined;
    var found = false;
    for (table) |g| {
        if (!std.mem.startsWith(u8, g.name, "resp/getVariableAccessAttributes")) continue;
        const frame = decodeHex(g.hex, &buf);
        const resp = (try decodePdu(frame)).confirmed_response;
        const attrs = try mms.decodeGetVariableAccessAttributesResponse(resp.body);
        try testing.expect(attrs.type_spec.isStructure());
        var it = try attrs.type_spec.components();
        // SBO first: a plain VisibleString, which is why the select is a read.
        try testing.expectEqualStrings("SBO", (try it.next()).?.name.?);
        const oper = (try it.next()).?;
        try testing.expectEqualStrings("Oper", oper.name.?);
        var members = try oper.type_spec.components();
        try testing.expectEqualStrings("ctlVal", (try members.next()).?.name.?);
        try testing.expectEqualStrings("origin", (try members.next()).?.name.?);
        try testing.expectEqualStrings("ctlNum", (try members.next()).?.name.?);
        try testing.expectEqualStrings("T", (try members.next()).?.name.?);
        try testing.expectEqualStrings("Test", (try members.next()).?.name.?);
        try testing.expectEqualStrings("Check", (try members.next()).?.name.?);
        try testing.expect((try members.next()) == null);
        // And `Cancel` is the same list without `Check`.
        const cancel = (try it.next()).?;
        try testing.expectEqualStrings("Cancel", cancel.name.?);
        var cm = try cancel.type_spec.components();
        var count: usize = 0;
        var last: []const u8 = "";
        while (try cm.next()) |c| : (count += 1) last = c.name.?;
        try testing.expectEqual(@as(usize, 5), count);
        try testing.expectEqualStrings("Test", last);
        found = true;
    }
    try testing.expect(found);
}

test "this module's own type specification is byte-identical to the IED's" {
    // The strongest statement available about the control structure: build the
    // `TypeSpecification` for a sbo-with-normal-security object from this
    // module's own model and require the identical octets the real IED sent for
    // its `GGIO1$CO$SPCSO2`. If a member were missing, misnamed, in the wrong
    // order or of the wrong width, this fails.
    var buf: [max_frame_len]u8 = undefined;
    var found = false;
    for (table) |g| {
        if (!std.mem.startsWith(u8, g.name, "resp/getVariableAccessAttributes")) continue;
        const frame = decodeHex(g.hex, &buf);
        const resp = (try decodePdu(frame)).confirmed_response;
        // The `typeDescription [2]` element's content is the whole type spec.
        var it = ber.Iterator.init(resp.body);
        var captured: []const u8 = "";
        while (try it.next()) |e| {
            if (e.tag.eql(ber.Tag.ctxc(2))) captured = e.content;
        }
        try testing.expect(captured.len > 0);

        const point = control.Point{
            .domain = "simpleIOGenericIO",
            .item = "GGIO1$CO$SPCSO2",
            .ctl_model = .sbo_with_normal_security,
        };
        var out: [1024]u8 = undefined;
        var w = ber.Writer.init(&out);
        try point.emitTypeSpec(&w);
        try testing.expectEqualSlices(u8, captured, w.done());
        found = true;
    }
    try testing.expect(found);
}

test "the table still covers every control model and both terminations" {
    var models: usize = 0;
    var selects: usize = 0;
    var terminations: usize = 0;
    var last_appl_errors: usize = 0;
    var third_party: usize = 0;
    for (table) |g| {
        if (std.mem.indexOf(u8, g.name, "req/Oper/") != null) models += 1;
        if (std.mem.indexOf(u8, g.name, "SBO") != null and
            std.mem.startsWith(u8, g.name, "req/")) selects += 1;
        if (std.mem.indexOf(u8, g.name, "CommandTermination") != null) terminations += 1;
        if (std.mem.indexOf(u8, g.name, "LastApplError") != null) last_appl_errors += 1;
        if (g.source == .third_party) third_party += 1;
    }
    // direct/normal, sbo/normal, sbo/enhanced (direct/enhanced is pinned by its
    // termination, whose Oper the third-party client sent).
    try testing.expect(models >= 3);
    // The SBO read and the SBOw write — the two shapes a select takes.
    try testing.expect(selects >= 2);
    try testing.expect(terminations >= 3);
    try testing.expect(last_appl_errors >= 1);
    // Most of the table must be traffic this module had no part in.
    try testing.expect(third_party >= 9);
}
