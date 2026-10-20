// SPDX-License-Identifier: MIT

//! tlsserver.alert — TLS 1.3 alerts (RFC 8446 §6): the two-octet message,
//! what a received alert means for the connection, and the alert this
//! module sends for each of its own errors.
//!
//! The receive rules follow rustls 0.23 (the module's scope reference),
//! which follows RFC 8446 §6 with two documented choices:
//!
//! - an unknown `AlertLevel` is answered with `illegal_parameter`;
//! - a `warning`-level alert other than `close_notify` and `user_canceled`
//!   is answered with `decode_error` (§6: "all alerts … MUST be treated as
//!   error alerts … regardless of the AlertLevel"); `user_canceled` is
//!   ignored, at most `max_warning_alerts` times per connection.
//!
//! `close_notify` ends the peer's direction only once the handshake is
//! complete; before that it is an unauthenticated request to abort, and the
//! connection fails without an alert of its own (as in rustls).

const std = @import("std");

pub const Level = enum(u8) {
    warning = 1,
    fatal = 2,
    _,
};

/// RFC 8446 §6 (and RFC 8701/8879/9846 additions that a TLS 1.3 server
/// can meet). Non-exhaustive: an unknown description is still a fatal
/// alert from the peer.
pub const Description = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    record_overflow = 22,
    handshake_failure = 40,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    inappropriate_fallback = 86,
    user_canceled = 90,
    missing_extension = 109,
    unsupported_extension = 110,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,
    _,
};

pub const Alert = struct {
    level: Level,
    description: Description,

    pub fn encode(a: Alert) [2]u8 {
        return .{ @backingInt(a.level), @backingInt(a.description) };
    }

    /// A fatal alert (RFC 8446 §6.2: every error alert is sent `fatal`).
    pub fn fatal(d: Description) Alert {
        return .{ .level = .fatal, .description = d };
    }

    pub const close_notify: Alert = .{ .level = .warning, .description = .close_notify };
};

/// The content of an alert record is exactly two octets (RFC 8446 §6;
/// anything else is `decode_error`, as in rustls `expect_empty`). Several
/// alerts in one record, or one split over two, are refused the same way.
pub fn parse(content: []const u8) error{DecodeError}!Alert {
    if (content.len != 2) return error.DecodeError;
    return .{ .level = @fromBackingInt(content[0]), .description = @fromBackingInt(content[1]) };
}

/// How many ignored `user_canceled` warnings one connection tolerates
/// (rustls `allowed_warning_alerts`: 4). One more is `unexpected_message`.
pub const max_warning_alerts = 4;

/// What a received alert does to the connection.
pub const Verdict = union(enum) {
    /// `close_notify` after the handshake: the peer will send no more data.
    peer_closed,
    /// `user_canceled` as a warning: ignored (rustls, for JDK clients that
    /// send it before `close_notify`).
    ignore,
    /// The peer aborted with this alert. Nothing is sent back.
    peer_aborted: Description,
    /// The alert itself is a protocol violation: answer with this alert.
    reply: Description,
};

/// Classify a received alert. `handshake_done`: the peer's Finished has
/// been verified (application data may flow). `warnings` counts the
/// ignored warnings so far and is advanced here.
pub fn classify(a: Alert, handshake_done: bool, warnings: *u8) Verdict {
    switch (a.level) {
        .warning, .fatal => {},
        _ => return .{ .reply = .illegal_parameter },
    }
    if (a.description == .close_notify) {
        return if (handshake_done) .peer_closed else .{ .peer_aborted = .close_notify };
    }
    if (a.level == .warning) {
        if (warnings.* >= max_warning_alerts) return .{ .reply = .unexpected_message };
        warnings.* += 1;
        if (a.description == .user_canceled) return .ignore;
        return .{ .reply = .decode_error };
    }
    return .{ .peer_aborted = a.description };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "encode / parse" {
    try testing.expectEqualSlices(u8, &.{ 2, 40 }, &Alert.fatal(.handshake_failure).encode());
    try testing.expectEqualSlices(u8, &.{ 1, 0 }, &Alert.close_notify.encode());
    const a = try parse(&.{ 2, 50 });
    try testing.expectEqual(Level.fatal, a.level);
    try testing.expectEqual(Description.decode_error, a.description);
    try testing.expectError(error.DecodeError, parse(&.{2}));
    try testing.expectError(error.DecodeError, parse(&.{ 2, 50, 2, 50 }));
    try testing.expectError(error.DecodeError, parse(&.{}));
}

test "classify: close_notify only closes after the handshake" {
    var w: u8 = 0;
    try testing.expectEqual(Verdict.peer_closed, classify(Alert.close_notify, true, &w));
    try testing.expectEqual(Verdict{ .peer_aborted = .close_notify }, classify(Alert.close_notify, false, &w));
    // The level of close_notify does not matter (RFC 8446 §6.1 sends it as a
    // warning, a fatal one closes just the same).
    try testing.expectEqual(Verdict.peer_closed, classify(.{ .level = .fatal, .description = .close_notify }, true, &w));
    try testing.expectEqual(@as(u8, 0), w);
}

test "classify: warnings, unknown levels, fatal alerts" {
    var w: u8 = 0;
    try testing.expectEqual(Verdict{ .reply = .illegal_parameter }, classify(.{ .level = @fromBackingInt(3), .description = .close_notify }, true, &w));
    try testing.expectEqual(Verdict{ .reply = .decode_error }, classify(.{ .level = .warning, .description = .bad_certificate }, true, &w));
    try testing.expectEqual(Verdict{ .peer_aborted = .bad_certificate }, classify(Alert.fatal(.bad_certificate), false, &w));
    try testing.expectEqual(Verdict{ .peer_aborted = @fromBackingInt(200) }, classify(.{ .level = .fatal, .description = @fromBackingInt(200) }, true, &w));
    // user_canceled is ignored, max_warning_alerts in total.
    w = 0;
    const uc: Alert = .{ .level = .warning, .description = .user_canceled };
    for (0..max_warning_alerts) |_| try testing.expectEqual(Verdict.ignore, classify(uc, true, &w));
    try testing.expectEqual(Verdict{ .reply = .unexpected_message }, classify(uc, true, &w));
}
