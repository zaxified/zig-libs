// SPDX-License-Identifier: MIT

//! **ACSE** (ISO 8650 / X.227) — the association-control layer that rides on
//! presentation context 1 and carries the MMS `Initiate` PDU as its user
//! information.
//!
//! Four APDUs matter for IEC 61850:
//!
//! * `AARQ` `[APPLICATION 0]` — associate request. Names the **application
//!   context** (`1.0.9506.2.3` for MMS) and, optionally, AP/AE titles and
//!   qualifiers. A real IED both sends and checks these: a mismatched
//!   application context name is the standard way an association is refused
//!   before a single MMS byte is parsed.
//! * `AARE` `[APPLICATION 1]` — associate response, carrying `result` and a
//!   `result-source-diagnostic`. **`result != 0` means the association failed**
//!   even though the TCP connection is up and the presentation layer accepted
//!   its contexts, which is the failure mode a naive client reports as "connected".
//! * `RLRQ`/`RLRE` `[APPLICATION 2]`/`[APPLICATION 3]` — orderly release.
//! * `ABRT` `[APPLICATION 4]` — abort, which is what the captured client sends
//!   inside a session ABORT SPDU when it disconnects.
//!
//! `user-information` is a `SEQUENCE OF EXTERNAL`. The captured stack encodes
//! the EXTERNAL with an **indirect reference** (the presentation context id)
//! rather than a direct-reference OID; both forms decode here, and the encoder
//! emits the indirect form so its output matches the reference stack.

const std = @import("std");
const ber = @import("ber.zig");

pub const Error = ber.Error || error{
    MissingField,
    /// The APDU is not one this module models.
    UnknownApdu,
    /// The peer's `application-context-name` is not the MMS one.
    WrongApplicationContext,
    /// `AARE.result` was not `accepted`.
    AssociateRejected,
};

pub const tag_aarq = ber.Tag.appc(0);
pub const tag_aare = ber.Tag.appc(1);
pub const tag_rlrq = ber.Tag.appc(2);
pub const tag_rlre = ber.Tag.appc(3);
pub const tag_abrt = ber.Tag.appc(4);

const tag_application_context_name = ber.Tag.ctxc(1);
const tag_called_ap_title = ber.Tag.ctxc(2);
const tag_called_ae_qualifier = ber.Tag.ctxc(3);
const tag_result = ber.Tag.ctxc(2);
const tag_result_source_diagnostic = ber.Tag.ctxc(3);
const tag_responding_ap_title = ber.Tag.ctxc(4);
const tag_calling_ap_title = ber.Tag.ctxc(6);
const tag_calling_ae_qualifier = ber.Tag.ctxc(7);
const tag_user_information = ber.Tag.ctxc(30);

/// ACSE `Associate-result`.
pub const AssociateResult = enum(u8) {
    accepted = 0,
    rejected_permanent = 1,
    rejected_transient = 2,
    _,
};

/// Where an `AARE` rejection came from.
pub const DiagnosticSource = enum { user, provider, unspecified };

pub const Aarq = struct {
    application_context: ?ber.Oid = null,
    called_ap_title: ?ber.Oid = null,
    called_ae_qualifier: ?i32 = null,
    calling_ap_title: ?ber.Oid = null,
    calling_ae_qualifier: ?i32 = null,
    /// The `single-ASN1-type` payload of the EXTERNAL — the MMS Initiate PDU.
    user_information: []const u8 = &.{},
    /// Present when the EXTERNAL used the indirect (context-id) reference.
    indirect_reference: ?u16 = null,
};

pub const Aare = struct {
    application_context: ?ber.Oid = null,
    result: AssociateResult = .accepted,
    diagnostic_source: DiagnosticSource = .unspecified,
    diagnostic: i32 = 0,
    responding_ap_title: ?ber.Oid = null,
    user_information: []const u8 = &.{},
    indirect_reference: ?u16 = null,

    pub fn accepted(self: Aare) bool {
        return self.result == .accepted;
    }
};

/// The EXTERNAL wrapper `user-information` uses.
fn decodeUserInformation(content: []const u8, out_indirect: *?u16) Error![]const u8 {
    var it = ber.Iterator.init(content);
    const ext = (try it.next()) orelse return error.MissingField;
    // EXTERNAL is [UNIVERSAL 8] constructed; some stacks tag it [8] context.
    if (!ext.tag.eqlLoose(ber.Tag.unic(ber.Universal.external)) and
        !ext.tag.eqlLoose(ber.Tag.ctxc(ber.Universal.external))) return error.UnexpectedTag;
    var f = ber.Iterator.init(ext.content);
    while (try f.next()) |m| {
        if (m.tag.eql(ber.Tag.uni(ber.Universal.object_identifier))) {
            // direct-reference; the transfer syntax OID, not needed here.
        } else if (m.tag.eql(ber.Tag.uni(ber.Universal.integer))) {
            out_indirect.* = try ber.decodeUint(u16, m.content);
        } else if (m.tag.eql(ber.Tag.ctxc(0))) {
            return m.content; // single-ASN1-type
        } else if (m.tag.eql(ber.Tag.ctx(1))) {
            return m.content; // octet-aligned
        }
    }
    return error.MissingField;
}

pub fn decodeAarq(bytes: []const u8) Error!Aarq {
    const outer = try ber.expect(bytes, tag_aarq);
    var a = Aarq{};
    var it = ber.Iterator.init(outer.content);
    while (try it.next()) |e| {
        if (e.tag.eql(tag_application_context_name)) {
            a.application_context = .{ .bytes = (try ber.expect(e.content, ber.Tag.uni(ber.Universal.object_identifier))).content };
        } else if (e.tag.eql(tag_called_ap_title)) {
            a.called_ap_title = .{ .bytes = (try ber.expect(e.content, ber.Tag.uni(ber.Universal.object_identifier))).content };
        } else if (e.tag.eql(tag_called_ae_qualifier)) {
            a.called_ae_qualifier = try ber.decodeInt(i32, (try ber.expect(e.content, ber.Tag.uni(ber.Universal.integer))).content);
        } else if (e.tag.eql(tag_calling_ap_title)) {
            a.calling_ap_title = .{ .bytes = (try ber.expect(e.content, ber.Tag.uni(ber.Universal.object_identifier))).content };
        } else if (e.tag.eql(tag_calling_ae_qualifier)) {
            a.calling_ae_qualifier = try ber.decodeInt(i32, (try ber.expect(e.content, ber.Tag.uni(ber.Universal.integer))).content);
        } else if (e.tag.eql(tag_user_information)) {
            a.user_information = try decodeUserInformation(e.content, &a.indirect_reference);
        }
    }
    return a;
}

pub fn decodeAare(bytes: []const u8) Error!Aare {
    const outer = try ber.expect(bytes, tag_aare);
    var a = Aare{};
    var it = ber.Iterator.init(outer.content);
    while (try it.next()) |e| {
        if (e.tag.eql(tag_application_context_name)) {
            a.application_context = .{ .bytes = (try ber.expect(e.content, ber.Tag.uni(ber.Universal.object_identifier))).content };
        } else if (e.tag.eql(tag_result)) {
            a.result = @enumFromInt(try ber.decodeUint(u8, (try ber.expect(e.content, ber.Tag.uni(ber.Universal.integer))).content));
        } else if (e.tag.eql(tag_result_source_diagnostic)) {
            var d = ber.Iterator.init(e.content);
            if (try d.next()) |src| {
                a.diagnostic_source = if (src.tag.number == 1) .user else if (src.tag.number == 2) .provider else .unspecified;
                a.diagnostic = try ber.decodeInt(i32, (try ber.expect(src.content, ber.Tag.uni(ber.Universal.integer))).content);
            }
        } else if (e.tag.eql(tag_responding_ap_title)) {
            a.responding_ap_title = .{ .bytes = (try ber.expect(e.content, ber.Tag.uni(ber.Universal.object_identifier))).content };
        } else if (e.tag.eql(tag_user_information)) {
            a.user_information = try decodeUserInformation(e.content, &a.indirect_reference);
        }
    }
    return a;
}

/// AP/AE identity for an AARQ. The defaults are the ones the captured client
/// used; a real deployment often has to match what an IED's SCL configured.
pub const Identity = struct {
    /// Called (server) AP title OID, wire form. Null omits it.
    called_ap_title: ?[]const u8 = &[_]u8{ 0x29, 0x01, 0x87, 0x67, 0x01 },
    called_ae_qualifier: ?i32 = 12,
    calling_ap_title: ?[]const u8 = &[_]u8{ 0x29, 0x01, 0x87, 0x67 },
    calling_ae_qualifier: ?i32 = 12,
    /// Presentation context id used as the EXTERNAL's indirect reference.
    indirect_reference: u16 = 3,
};

pub fn encodeAarq(user_information: []const u8, id: Identity, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const outer = w.mark();
    // user-information [30] { EXTERNAL { indirect-reference, [0] payload } }
    const ui = w.mark();
    const ext = w.mark();
    const sa = w.mark();
    try w.bytes(user_information);
    try w.header(ber.Tag.ctxc(0), sa);
    try w.integer(ber.Tag.uni(ber.Universal.integer), id.indirect_reference);
    try w.header(ber.Tag.unic(ber.Universal.external), ext);
    try w.header(tag_user_information, ui);

    if (id.calling_ae_qualifier) |q| {
        const m = w.mark();
        try w.integer(ber.Tag.uni(ber.Universal.integer), q);
        try w.header(tag_calling_ae_qualifier, m);
    }
    if (id.calling_ap_title) |t| {
        const m = w.mark();
        try w.oid(ber.Tag.uni(ber.Universal.object_identifier), .{ .bytes = t });
        try w.header(tag_calling_ap_title, m);
    }
    if (id.called_ae_qualifier) |q| {
        const m = w.mark();
        try w.integer(ber.Tag.uni(ber.Universal.integer), q);
        try w.header(tag_called_ae_qualifier, m);
    }
    if (id.called_ap_title) |t| {
        const m = w.mark();
        try w.oid(ber.Tag.uni(ber.Universal.object_identifier), .{ .bytes = t });
        try w.header(tag_called_ap_title, m);
    }
    const acn = w.mark();
    try w.oid(ber.Tag.uni(ber.Universal.object_identifier), .{ .bytes = &ber.oids.mms_application_context });
    try w.header(tag_application_context_name, acn);
    try w.header(tag_aarq, outer);
    return w.done();
}

pub const AareOptions = struct {
    result: AssociateResult = .accepted,
    diagnostic: i32 = 0,
    indirect_reference: u16 = 3,
};

pub fn encodeAare(user_information: []const u8, opts: AareOptions, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const outer = w.mark();
    const ui = w.mark();
    const ext = w.mark();
    const sa = w.mark();
    try w.bytes(user_information);
    try w.header(ber.Tag.ctxc(0), sa);
    try w.integer(ber.Tag.uni(ber.Universal.integer), opts.indirect_reference);
    try w.header(ber.Tag.unic(ber.Universal.external), ext);
    try w.header(tag_user_information, ui);

    const diag = w.mark();
    const inner = w.mark();
    try w.integer(ber.Tag.uni(ber.Universal.integer), opts.diagnostic);
    try w.header(ber.Tag.ctxc(1), inner);
    try w.header(tag_result_source_diagnostic, diag);

    const res = w.mark();
    try w.integer(ber.Tag.uni(ber.Universal.integer), @intFromEnum(opts.result));
    try w.header(tag_result, res);

    const acn = w.mark();
    try w.oid(ber.Tag.uni(ber.Universal.object_identifier), .{ .bytes = &ber.oids.mms_application_context });
    try w.header(tag_application_context_name, acn);
    try w.header(tag_aare, outer);
    return w.done();
}

/// `ABRT-apdu { abort-source [0] }`. `0` = acse-service-user, which is what a
/// client sends when it walks away.
pub fn encodeAbrt(source: u8, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const outer = w.mark();
    try w.integer(ber.Tag.ctx(0), source);
    try w.header(tag_abrt, outer);
    return w.done();
}

/// `RLRQ-apdu { reason [0] }`. `0` = normal.
pub fn encodeRlrq(reason: ?u8, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const outer = w.mark();
    if (reason) |r| try w.integer(ber.Tag.ctx(0), r);
    try w.header(tag_rlrq, outer);
    return w.done();
}

pub fn encodeRlre(reason: ?u8, out: []u8) Error![]const u8 {
    var w = ber.Writer.init(out);
    const outer = w.mark();
    if (reason) |r| try w.integer(ber.Tag.ctx(0), r);
    try w.header(tag_rlre, outer);
    return w.done();
}

/// What kind of ACSE APDU this is, without parsing it.
pub fn classify(bytes: []const u8) Error!enum { aarq, aare, rlrq, rlre, abrt } {
    const e = try ber.decode(bytes);
    if (e.tag.eql(tag_aarq)) return .aarq;
    if (e.tag.eql(tag_aare)) return .aare;
    if (e.tag.eql(tag_rlrq)) return .rlrq;
    if (e.tag.eql(tag_rlre)) return .rlre;
    if (e.tag.eql(tag_abrt)) return .abrt;
    return error.UnknownApdu;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// The AARQ a real IEC 61850 client sent, with the MMS Initiate payload
/// replaced by a two-octet stand-in.
const captured_aarq_prefix = [_]u8{
    0xA1, 0x07, 0x06, 0x05, 0x28, 0xCA, 0x22, 0x02, 0x03, // application-context-name 1.0.9506.2.3
    0xA2, 0x07, 0x06, 0x05, 0x29, 0x01, 0x87, 0x67, 0x01, // called-AP-title
    0xA3, 0x03, 0x02, 0x01, 0x0C, // called-AE-qualifier 12
    0xA6, 0x06, 0x06, 0x04, 0x29, 0x01, 0x87, 0x67, // calling-AP-title
    0xA7, 0x03, 0x02, 0x01, 0x0C, // calling-AE-qualifier 12
};

test "encodeAarq reproduces the captured field order and octets" {
    var out: [256]u8 = undefined;
    const built = try encodeAarq(&[_]u8{ 0x05, 0x00 }, .{}, &out);
    // 60 <len> then the captured prefix.
    try testing.expectEqual(@as(u8, 0x60), built[0]);
    try testing.expectEqualSlices(u8, &captured_aarq_prefix, built[2..][0..captured_aarq_prefix.len]);
    // Then user-information: be <len> 28 <len> 02 01 03 a0 02 05 00
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0xBE, 0x09, 0x28, 0x07, 0x02, 0x01, 0x03, 0xA0, 0x02, 0x05, 0x00 },
        built[2 + captured_aarq_prefix.len ..],
    );
}

test "the captured AARQ decodes field by field" {
    var out: [256]u8 = undefined;
    const built = try encodeAarq(&[_]u8{ 0x05, 0x00 }, .{}, &out);
    const a = try decodeAarq(built);
    try testing.expect(a.application_context.?.eql(.{ .bytes = &ber.oids.mms_application_context }));
    try testing.expectEqual(@as(i32, 12), a.called_ae_qualifier.?);
    try testing.expectEqual(@as(i32, 12), a.calling_ae_qualifier.?);
    try testing.expectEqual(@as(u16, 3), a.indirect_reference.?);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x05, 0x00 }, a.user_information);
    try testing.expectEqual(@as(usize, 5), a.called_ap_title.?.bytes.len);
}

test "the exact AARE a real server emits decodes" {
    // Captured verbatim, with the MMS Initiate response replaced by 05 00.
    const captured = [_]u8{
        0x61, 0x1E,
        0xA1, 0x07,
        0x06, 0x05,
        0x28, 0xCA,
        0x22, 0x02,
        0x03,
        0xA2, 0x03, 0x02, 0x01, 0x00, // result = accepted
        0xA3, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x00, // diagnostic: acse-service-user, 0
        0xBE, 0x07, 0x28, 0x05, 0x02, 0x01, 0x03,
        0xA0, 0x00,
    };
    const a = try decodeAare(&captured);
    try testing.expect(a.accepted());
    try testing.expectEqual(AssociateResult.accepted, a.result);
    try testing.expectEqual(DiagnosticSource.user, a.diagnostic_source);
    try testing.expectEqual(@as(i32, 0), a.diagnostic);
    try testing.expectEqual(@as(u16, 3), a.indirect_reference.?);
}

test "a rejected AARE is visible rather than looking like success" {
    var out: [128]u8 = undefined;
    const built = try encodeAare(&[_]u8{}, .{ .result = .rejected_permanent, .diagnostic = 1 }, &out);
    const a = try decodeAare(built);
    try testing.expect(!a.accepted());
    try testing.expectEqual(AssociateResult.rejected_permanent, a.result);
    try testing.expectEqual(@as(i32, 1), a.diagnostic);
}

test "the ABRT a real client sends on disconnect" {
    var out: [16]u8 = undefined;
    const built = try encodeAbrt(0, &out);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x64, 0x03, 0x80, 0x01, 0x00 }, built);
    try testing.expectEqual(@as(@TypeOf(try classify(built)), .abrt), try classify(built));
}

test "release APDUs round trip" {
    var out: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, &[_]u8{ 0x62, 0x03, 0x80, 0x01, 0x00 }, try encodeRlrq(0, &out));
    try testing.expectEqualSlices(u8, &[_]u8{ 0x63, 0x03, 0x80, 0x01, 0x00 }, try encodeRlre(0, &out));
    try testing.expectEqualSlices(u8, &[_]u8{ 0x62, 0x00 }, try encodeRlrq(null, &out));
}

test "classify refuses an APDU this module does not model" {
    try testing.expectError(error.UnknownApdu, classify(&[_]u8{ 0x65, 0x00 }));
    try testing.expectError(error.Truncated, classify(&[_]u8{}));
}

test "malformed ACSE APDUs are typed errors" {
    try testing.expectError(error.UnexpectedTag, decodeAarq(&[_]u8{ 0x61, 0x00 }));
    // user-information whose EXTERNAL carries a reference but no payload.
    try testing.expectError(
        error.MissingField,
        decodeAarq(&[_]u8{ 0x60, 0x07, 0xBE, 0x05, 0x28, 0x03, 0x02, 0x01, 0x03 }),
    );
    // An EXTERNAL whose length runs past the octets present.
    try testing.expectError(
        error.Overrun,
        decodeAarq(&[_]u8{ 0x60, 0x06, 0xBE, 0x04, 0x28, 0x02, 0x02, 0x01 }),
    );
    // user-information that is not an EXTERNAL at all.
    try testing.expectError(
        error.UnexpectedTag,
        decodeAarq(&[_]u8{ 0x60, 0x04, 0xBE, 0x02, 0x05, 0x00 }),
    );
    // An application-context-name that is not an OID.
    try testing.expectError(
        error.UnexpectedTag,
        decodeAarq(&[_]u8{ 0x60, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x01 }),
    );
}

test "fuzz: acse decode never panics" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = decodeAarq(buf[0..len]) catch {};
    _ = decodeAare(buf[0..len]) catch {};
    _ = classify(buf[0..len]) catch {};
}
