// SPDX-License-Identifier: MIT

//! SNMPv3 Report-PDU classification — the engine-to-engine error channel.
//!
//! A v3 exchange can come back as a **Report-PDU** [8] instead of a Response,
//! and a client that treats a Report as a normal response is broken: it will
//! either surface a bogus varbind list or silently retry forever. RFC 3414 §5
//! defines the `usmStats*` counters an authoritative engine reports, and RFC
//! 3412 §5.2 / RFC 3418 add the message-processing ones; every Report carries
//! exactly one varbind whose **name** identifies the failure and whose value is
//! the agent's Counter32 for it.
//!
//! ```
//! usmStatsUnsupportedSecLevels  1.3.6.1.6.3.15.1.1.1.0
//! usmStatsNotInTimeWindows      1.3.6.1.6.3.15.1.1.2.0
//! usmStatsUnknownUserNames      1.3.6.1.6.3.15.1.1.3.0
//! usmStatsUnknownEngineIDs      1.3.6.1.6.3.15.1.1.4.0
//! usmStatsWrongDigests          1.3.6.1.6.3.15.1.1.5.0
//! usmStatsDecryptionErrors      1.3.6.1.6.3.15.1.1.6.0
//! snmpUnknownSecurityModels     1.3.6.1.6.3.11.2.1.1.0
//! snmpInvalidMsgs               1.3.6.1.6.3.11.2.1.2.0
//! snmpUnknownPDUHandlers        1.3.6.1.6.3.11.2.1.3.0
//! ```
//!
//! `classify` maps that OID to a `Reason`, and `toError` maps a `Reason` to a
//! typed error so a client can `try` on it. Two reasons are *recoverable* and a
//! well-behaved client retries once after acting on them:
//!   * `unknown_engine_ids` — the normal end of the discovery handshake: the
//!     engine has told us its `msgAuthoritativeEngineID`; adopt it and re-send.
//!   * `not_in_time_windows` — our cached boots/time were stale; the Report
//!     carries the engine's authentic values (RFC 3414 §3.2), so latch and
//!     re-send. This one arrives **authenticated**; a client must verify it
//!     before trusting the clock inside, or an off-path attacker could shove
//!     our time window wherever it likes.
//! Everything else is terminal (bad credentials, wrong security level, …).
//!
//! Provenance: clean-room from RFC 3414 §5 (usmStats objects), RFC 3412 §5.2
//! and RFC 3418 §5 (snmpUnknown* objects). No source consulted.

const std = @import("std");
const oid_mod = @import("oid.zig");
const message = @import("message.zig");
const v3 = @import("v3.zig");

const Oid = oid_mod.Oid;

/// The prefix shared by all six RFC 3414 §5 `usmStats*` scalars
/// (`snmpUsmMIB.usmMIBObjects.usmStats`).
pub const usm_stats_prefix = [_]u32{ 1, 3, 6, 1, 6, 3, 15, 1, 1 };

/// The prefix shared by the RFC 3412 §5.2 message-processing scalars
/// (`snmpMPDMIB.snmpMPDMIBObjects.snmpMPDStats`).
pub const mpd_stats_prefix = [_]u32{ 1, 3, 6, 1, 6, 3, 11, 2, 1 };

/// Why the remote engine sent a Report instead of a Response.
pub const Reason = enum {
    /// usmStatsUnsupportedSecLevels.0 — the user exists but not at the
    /// requested securityLevel (e.g. authPriv asked of an auth-only user).
    unsupported_sec_levels,
    /// usmStatsNotInTimeWindows.0 — our engineBoots/engineTime were outside the
    /// engine's ±150 s window. Recoverable: latch the Report's clock, re-send.
    not_in_time_windows,
    /// usmStatsUnknownUserNames.0 — no such `msgUserName` on the engine.
    unknown_user_names,
    /// usmStatsUnknownEngineIDs.0 — the engine did not recognise the
    /// `msgAuthoritativeEngineID` we sent. This is the expected reply to an
    /// empty-engineID discovery probe. Recoverable: adopt and re-send.
    unknown_engine_ids,
    /// usmStatsWrongDigests.0 — the authentication digest did not verify at the
    /// engine: wrong auth password, wrong auth protocol, or a mangled message.
    wrong_digests,
    /// usmStatsDecryptionErrors.0 — the engine could not decrypt our scopedPDU:
    /// wrong privacy password/protocol, or a corrupted salt.
    decryption_errors,
    /// snmpUnknownSecurityModels.0 — `msgSecurityModel` was not one the engine
    /// implements (we always send 3 = USM).
    unknown_security_models,
    /// snmpInvalidMsgs.0 — the engine rejected the message envelope itself
    /// (e.g. an impossible msgFlags combination).
    invalid_msgs,
    /// snmpUnknownPDUHandlers.0 — no dispatcher for the scopedPDU's PDU type.
    unknown_pdu_handlers,
    /// A Report whose varbind OID is none of the above. Hostile or simply from
    /// a MIB we do not model — surfaced, never guessed at.
    unknown,

    /// True for the two reasons a client can act on and retry once
    /// (see the module docs). Everything else is terminal.
    pub fn isRecoverable(self: Reason) bool {
        return switch (self) {
            .unknown_engine_ids, .not_in_time_windows => true,
            else => false,
        };
    }
};

/// Typed errors a Report maps to, so a v3 client can `try` on the exchange and
/// never mistake a Report for data.
pub const ReportError = error{
    /// usmStatsUnsupportedSecLevels.0
    UnsupportedSecLevel,
    /// usmStatsNotInTimeWindows.0
    NotInTimeWindow,
    /// usmStatsUnknownUserNames.0
    UnknownUserName,
    /// usmStatsUnknownEngineIDs.0
    UnknownEngineId,
    /// usmStatsWrongDigests.0
    WrongDigest,
    /// usmStatsDecryptionErrors.0
    DecryptionError,
    /// snmpUnknownSecurityModels.0
    UnknownSecurityModel,
    /// snmpInvalidMsgs.0
    InvalidMsg,
    /// snmpUnknownPDUHandlers.0
    UnknownPduHandler,
    /// A Report carrying an OID outside the modelled set.
    UnknownReport,
    /// A Report PDU with no varbind at all (nothing to classify).
    EmptyReport,
};

/// Map a `Reason` to its typed error.
pub fn toError(reason: Reason) ReportError {
    return switch (reason) {
        .unsupported_sec_levels => error.UnsupportedSecLevel,
        .not_in_time_windows => error.NotInTimeWindow,
        .unknown_user_names => error.UnknownUserName,
        .unknown_engine_ids => error.UnknownEngineId,
        .wrong_digests => error.WrongDigest,
        .decryption_errors => error.DecryptionError,
        .unknown_security_models => error.UnknownSecurityModel,
        .invalid_msgs => error.InvalidMsg,
        .unknown_pdu_handlers => error.UnknownPduHandler,
        .unknown => error.UnknownReport,
    };
}

/// Classify a single Report varbind OID. Matching is on the object arc under
/// the `usmStats` / `snmpMPDStats` prefixes; a trailing `.0` instance arc is
/// accepted but not required (agents are consistent about it, but a decoder
/// must not hinge on it).
pub fn classifyOid(name: *const Oid) Reason {
    const arcs = name.slice();
    if (matchPrefix(arcs, &usm_stats_prefix)) |arc| return switch (arc) {
        1 => .unsupported_sec_levels,
        2 => .not_in_time_windows,
        3 => .unknown_user_names,
        4 => .unknown_engine_ids,
        5 => .wrong_digests,
        6 => .decryption_errors,
        else => .unknown,
    };
    if (matchPrefix(arcs, &mpd_stats_prefix)) |arc| return switch (arc) {
        1 => .unknown_security_models,
        2 => .invalid_msgs,
        3 => .unknown_pdu_handlers,
        else => .unknown,
    };
    return .unknown;
}

/// If `arcs` starts with `prefix` and has exactly one or two more arcs (object
/// arc, plus an optional `.0` instance arc), return the object arc.
fn matchPrefix(arcs: []const u32, prefix: []const u32) ?u32 {
    if (arcs.len != prefix.len + 1 and arcs.len != prefix.len + 2) return null;
    if (!std.mem.eql(u32, arcs[0..prefix.len], prefix)) return null;
    if (arcs.len == prefix.len + 2 and arcs[prefix.len + 1] != 0) return null;
    return arcs[prefix.len];
}

/// What a Report told us, fully parsed.
pub const ReportInfo = struct {
    reason: Reason,
    /// The Report varbind's OID, verbatim.
    oid: Oid,
    /// The agent's counter for that condition, when the value was a Counter32
    /// (agents always send one, but a hostile peer need not).
    counter: ?u32,
    /// The Report PDU's request-id, for matching against our own.
    request_id: i32,
};

pub const ClassifyError = message.DecodeError || error{EmptyReport};

/// Classify a decoded ScopedPDU's Report. `error.UnexpectedTag` if the inner
/// PDU is not a Report; `error.EmptyReport` when it carries no varbind. Only
/// the FIRST varbind is classified — RFC 3412 §7.2 specifies exactly one, and
/// a peer stuffing extra varbinds must not change the verdict.
pub fn classify(scoped: v3.ScopedPdu) ClassifyError!ReportInfo {
    const pdu = switch (scoped.pdu) {
        .report => |p| p,
        else => return error.UnexpectedTag,
    };
    var it = pdu.varbinds.iterator();
    const vb = (try it.next()) orelse return error.EmptyReport;
    return .{
        .reason = classifyOid(&vb.name),
        .oid = vb.name,
        .counter = switch (vb.value) {
            .counter32 => |c| c,
            else => null,
        },
        .request_id = pdu.request_id,
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const ber = @import("ber.zig");

test "classifyOid: every RFC 3414 §5 usmStats scalar, with and without the .0" {
    const cases = [_]struct { []const u8, Reason }{
        .{ "1.3.6.1.6.3.15.1.1.1.0", .unsupported_sec_levels },
        .{ "1.3.6.1.6.3.15.1.1.2.0", .not_in_time_windows },
        .{ "1.3.6.1.6.3.15.1.1.3.0", .unknown_user_names },
        .{ "1.3.6.1.6.3.15.1.1.4.0", .unknown_engine_ids },
        .{ "1.3.6.1.6.3.15.1.1.5.0", .wrong_digests },
        .{ "1.3.6.1.6.3.15.1.1.6.0", .decryption_errors },
        .{ "1.3.6.1.6.3.15.1.1.1", .unsupported_sec_levels },
        .{ "1.3.6.1.6.3.15.1.1.6", .decryption_errors },
        .{ "1.3.6.1.6.3.11.2.1.1.0", .unknown_security_models },
        .{ "1.3.6.1.6.3.11.2.1.2.0", .invalid_msgs },
        .{ "1.3.6.1.6.3.11.2.1.3.0", .unknown_pdu_handlers },
    };
    for (cases) |c| {
        const o = try Oid.parse(c[0]);
        try testing.expectEqual(c[1], classifyOid(&o));
    }
}

test "classifyOid: near-misses and junk are .unknown, never a wrong verdict" {
    const misses = [_][]const u8{
        "1.3.6.1.6.3.15.1.1.7.0", // one past the last usmStats scalar
        "1.3.6.1.6.3.15.1.1.0.0", // arc 0 is not a scalar
        "1.3.6.1.6.3.15.1.1", // the prefix itself
        "1.3.6.1.6.3.15.1.1.4.1", // non-zero instance arc
        "1.3.6.1.6.3.15.1.1.4.0.1", // too deep
        "1.3.6.1.6.3.11.2.1.4.0", // one past the last MPD scalar
        "1.3.6.1.2.1.1.5.0", // sysName — an ordinary object
        "1.3", // degenerate
    };
    for (misses) |m| {
        const o = try Oid.parse(m);
        try testing.expectEqual(Reason.unknown, classifyOid(&o));
    }
}

test "isRecoverable: only unknownEngineIDs and notInTimeWindows" {
    try testing.expect(Reason.unknown_engine_ids.isRecoverable());
    try testing.expect(Reason.not_in_time_windows.isRecoverable());
    for ([_]Reason{
        .unsupported_sec_levels, .unknown_user_names,      .wrong_digests,
        .decryption_errors,      .unknown_security_models, .invalid_msgs,
        .unknown_pdu_handlers,   .unknown,
    }) |r| try testing.expect(!r.isRecoverable());
}

test "toError maps every Reason to a distinct typed error" {
    // `toError` is exhaustive over `Reason` at compile time; check here that no
    // two reasons collapse onto the same error code.
    const fields = @typeInfo(Reason).@"enum".fields;
    var codes: [fields.len]anyerror = undefined;
    inline for (fields, 0..) |f, i| codes[i] = toError(@field(Reason, f.name));
    for (codes, 0..) |a, i| {
        for (codes[i + 1 ..]) |b| try testing.expect(a != b);
    }
    try testing.expectEqual(ReportError.UnknownEngineId, toError(.unknown_engine_ids));
    try testing.expectEqual(ReportError.NotInTimeWindow, toError(.not_in_time_windows));
    try testing.expectEqual(ReportError.UnknownReport, toError(.unknown));
}

/// Build a v3 datagram whose scopedPDU is a Report carrying `oid`.
fn buildReport(buf: []u8, oid_text: []const u8, counter: u32, rid: i32) ![]const u8 {
    const vbs = [_]message.VarBind{
        .{ .name = try Oid.parse(oid_text), .value = .{ .counter32 = counter } },
    };
    return v3.encode(buf, .{
        .msg_id = rid,
        .context_engine_id = "eng",
        .pdu = .{ .type = .report, .request_id = rid, .varbinds = &vbs },
    });
}

test "classify: a real-shaped Report scopedPDU round-trips to a Reason" {
    var buf: [256]u8 = undefined;
    const dg = try buildReport(&buf, "1.3.6.1.6.3.15.1.1.4.0", 7, 4242);
    const m = try v3.decode(dg);
    const info = try classify(m.data.plaintext);
    try testing.expectEqual(Reason.unknown_engine_ids, info.reason);
    try testing.expectEqual(@as(?u32, 7), info.counter);
    try testing.expectEqual(@as(i32, 4242), info.request_id);
    try testing.expectEqual(ReportError.UnknownEngineId, toError(info.reason));
}

test "classify: a Report with an OID we do not model -> .unknown / UnknownReport" {
    var buf: [256]u8 = undefined;
    const dg = try buildReport(&buf, "1.3.6.1.4.1.99999.1.1", 1, 5);
    const m = try v3.decode(dg);
    const info = try classify(m.data.plaintext);
    try testing.expectEqual(Reason.unknown, info.reason);
    try testing.expectEqual(ReportError.UnknownReport, toError(info.reason));
}

test "classify: a non-Report PDU is UnexpectedTag, an empty Report is EmptyReport" {
    var buf: [256]u8 = undefined;
    // Response, not Report.
    const resp = try v3.encode(&buf, .{
        .msg_id = 1,
        .context_engine_id = "e",
        .pdu = .{ .type = .response, .request_id = 1 },
    });
    const rm = try v3.decode(resp);
    try testing.expectError(error.UnexpectedTag, classify(rm.data.plaintext));

    // Report with an empty varbind list.
    var buf2: [256]u8 = undefined;
    const empty = try v3.encode(&buf2, .{
        .msg_id = 2,
        .context_engine_id = "e",
        .pdu = .{ .type = .report, .request_id = 2 },
    });
    const em = try v3.decode(empty);
    try testing.expectError(error.EmptyReport, classify(em.data.plaintext));
}

test "classify: a non-Counter32 report value yields counter = null, not an error" {
    const vbs = [_]message.VarBind{
        .{ .name = try Oid.parse("1.3.6.1.6.3.15.1.1.5.0"), .value = .{ .octet_string = "nope" } },
    };
    var buf: [256]u8 = undefined;
    const dg = try v3.encode(&buf, .{
        .msg_id = 9,
        .context_engine_id = "e",
        .pdu = .{ .type = .report, .request_id = 9, .varbinds = &vbs },
    });
    const m = try v3.decode(dg);
    const info = try classify(m.data.plaintext);
    try testing.expectEqual(Reason.wrong_digests, info.reason);
    try testing.expectEqual(@as(?u32, null), info.counter);
}

test "classify: extra varbinds cannot change the verdict (only the first counts)" {
    const vbs = [_]message.VarBind{
        .{ .name = try Oid.parse("1.3.6.1.6.3.15.1.1.4.0"), .value = .{ .counter32 = 1 } },
        .{ .name = try Oid.parse("1.3.6.1.6.3.15.1.1.5.0"), .value = .{ .counter32 = 9 } },
    };
    var buf: [256]u8 = undefined;
    const dg = try v3.encode(&buf, .{
        .msg_id = 3,
        .context_engine_id = "e",
        .pdu = .{ .type = .report, .request_id = 3, .varbinds = &vbs },
    });
    const m = try v3.decode(dg);
    try testing.expectEqual(Reason.unknown_engine_ids, (try classify(m.data.plaintext)).reason);
}

test "classify: a malformed varbind list is a typed decode error, not a panic" {
    // A Report whose varbind SEQUENCE content is garbage.
    var buf: [128]u8 = undefined;
    var e = ber.Encoder.init(&buf);
    try e.prependTlv(ber.tag.sequence, &[_]u8{ 0x30, 0x7f, 0x06 }); // truncated vb
    try e.prependInteger(ber.tag.integer, 0);
    try e.prependInteger(ber.tag.integer, 0);
    try e.prependInteger(ber.tag.integer, 1);
    try e.wrap(@intFromEnum(message.PduType.report), 0);
    const pdu_bytes = e.encoded();

    var d = ber.Decoder.init(pdu_bytes);
    const tlv = try d.any();
    const scoped: v3.ScopedPdu = .{
        .context_engine_id = "",
        .context_name = "",
        .pdu = try message.decodePdu(tlv),
    };
    try testing.expectError(error.Truncated, classify(scoped));
}
