// SPDX-License-Identifier: MIT

//! dnp3.sa — SCAFFOLD ONLY for DNP3 Secure Authentication (IEEE 1815 Annex
//! / IEC 62351-5), object group 120. This file defines the *shapes* the
//! g120 objects take (challenge, reply, aggregate MAC, session-key
//! status/change, error) so a later Fable crypto pass has a stable, typed
//! place to slot in. It implements **no cryptography whatsoever**: no
//! HMAC/AES-GMAC, no session-key wrap/unwrap, no challenge-data generation
//! or verification.
//!
//! What's real here: the enums (`ObjectVariation`, `HmacAlgorithm`,
//! `KeyWrapAlgorithm`, `ErrorCode`) and the struct *shapes* for each
//! variation's fixed-format fields, matching the commonly published SAv5
//! object model. What's a stub: every `encode`/`decode` method on those
//! structs is `@panic("TODO(agent): ...")` -- calling them is a deliberate,
//! loud failure, not a silently-wrong crypto result. This is the one place
//! in the whole `dnp3` module that panics on purpose; nothing in
//! `link`/`transport`/`application`/`objects` ever does, and the test suite
//! never calls into this file (a panic here would abort the test binary).
//!
//! Honesty note on precision: the variation numbers below are transcribed
//! from secondary references (public DNP3 Secure Authentication primers and
//! the opendnp3 object model) rather than a direct read of the primary IEEE
//! 1815 SA Annex / IEC 62351-5 text. Treat them as "best-effort, needs a
//! spec cross-check" -- the Fable crypto pass MUST verify every variation
//! number, field width, and algorithm-id value against the primary
//! standard text before any wire-level interop is attempted. Nothing here
//! is wire-tested; there are no golden vectors, because there is no
//! implemented codec to test.

const std = @import("std");

/// Group 120 (Authentication) object variations this scaffold names. The
/// full SAv5 object model has more variations (e.g. user certificates,
/// update-key change) that are out of scope even as a stub -- only the set
/// explicitly called out for this scaffold pass is represented.
pub const ObjectVariation = enum(u8) {
    /// g120v1 -- Challenge: sent by the station requesting authentication
    /// of a critical request/response.
    challenge = 1,
    /// g120v2 -- Reply: the HMAC/AES-GMAC digest answering a Challenge.
    reply = 2,
    /// g120v4 -- Session Key Status Request.
    session_key_status_request = 4,
    /// g120v5 -- Session Key Status: current key-change method + status +
    /// a fresh challenge for the key-wrap handshake.
    session_key_status = 5,
    /// g120v6 -- Session Key Change: the wrapped new session key(s).
    session_key_change = 6,
    /// g120v7 -- Error: an SA-layer error report (see `ErrorCode`).
    sa_error = 7,
    /// g120v9 -- (Aggregate) MAC: the digest object appended to an
    /// aggressive-mode request/response instead of a separate
    /// challenge/reply round-trip.
    aggregate_mac = 9,
    _,
};

/// HMAC/MAC algorithm identifiers carried in `SessionKeyStatus`/`Reply`
/// objects. Values per the commonly published SAv5 algorithm table.
pub const HmacAlgorithm = enum(u8) {
    hmac_sha1_trunc_8 = 1,
    hmac_sha256_trunc_8 = 2,
    hmac_sha256_trunc_16 = 3,
    hmac_sha3_256_trunc_16 = 4,
    hmac_sha3_256_trunc_8 = 5,
    aes_gmac = 6,
    _,
};

/// Key-wrap algorithm identifiers for `SessionKeyChange`.
pub const KeyWrapAlgorithm = enum(u8) {
    aes_128_key_wrap = 1,
    aes_256_key_wrap = 2,
    _,
};

/// SA-layer error codes (`sa_error` / g120v7).
pub const ErrorCode = enum(u8) {
    authentication_failed = 1,
    unexpected_reply = 2,
    no_available_session_key = 3,
    unknown_user = 4,
    unknown_association = 5,
    unknown_sequence_number = 6,
    unknown_key_change_method = 7,
    unsupported_security_algorithm = 8,
    unsupported_mac_algorithm = 9,
    mac_algorithm_not_permitted = 10,
    key_wrap_algorithm_not_permitted = 11,
    authentication_method_not_permitted = 12,
    key_status_not_ok = 13,
    no_available_configuration_signature = 14,
    invalid_certification_data = 15,
    invalid_signature = 16,
    message_swap_detected = 17,
    excessive_delay = 18,
    unexpected_key_change_sequence_number = 19,
    _,
};

/// g120v1 Challenge. `challenge_data` is a caller-owned slice (not copied)
/// -- generating cryptographically-suitable challenge data is itself part
/// of the crypto pass, not this scaffold.
pub const Challenge = struct {
    challenge_seq_num: u32,
    hmac_algorithm: HmacAlgorithm,
    challenge_data: []const u8,

    /// TODO(agent): implement g120v1 wire encoding (challenge_seq_num u32 LE
    /// + method/reason byte + HMAC algorithm byte + challenge-data length
    /// u16 LE + challenge_data). No crypto is needed for *encoding* the
    /// frame shape -- this can move out of the stub set without touching
    /// any cryptographic primitive, once cross-checked against the primary
    /// spec text for the exact field layout.
    pub fn encode(self: Challenge, out: []u8) []u8 {
        _ = self;
        _ = out;
        @panic("TODO(agent): dnp3.sa.Challenge.encode is unimplemented (g120 scaffold only, see module doc comment)");
    }

    pub fn decode(bytes: []const u8) Challenge {
        _ = bytes;
        @panic("TODO(agent): dnp3.sa.Challenge.decode is unimplemented (g120 scaffold only, see module doc comment)");
    }
};

/// g120v2 Reply: the HMAC/AES-GMAC digest answering a `Challenge`.
/// `hmac_value` is caller-owned (not computed here -- computing it is the
/// entire point of the later crypto pass).
pub const Reply = struct {
    challenge_seq_num: u32,
    user_number: u16,
    hmac_value: []const u8,

    pub fn encode(self: Reply, out: []u8) []u8 {
        _ = self;
        _ = out;
        @panic("TODO(agent): dnp3.sa.Reply.encode is unimplemented (g120 scaffold only, see module doc comment)");
    }

    pub fn decode(bytes: []const u8) Reply {
        _ = bytes;
        @panic("TODO(agent): dnp3.sa.Reply.decode is unimplemented (g120 scaffold only, see module doc comment)");
    }
};

/// g120v9 Aggregate MAC: the digest appended to an aggressive-mode
/// request/response in place of a separate challenge/reply round-trip.
pub const AggregateMac = struct {
    mac_value: []const u8,

    pub fn encode(self: AggregateMac, out: []u8) []u8 {
        _ = self;
        _ = out;
        @panic("TODO(agent): dnp3.sa.AggregateMac.encode is unimplemented (g120 scaffold only, see module doc comment)");
    }

    pub fn decode(bytes: []const u8) AggregateMac {
        _ = bytes;
        @panic("TODO(agent): dnp3.sa.AggregateMac.decode is unimplemented (g120 scaffold only, see module doc comment)");
    }
};

/// g120v5 Session Key Status: the outstation's current key-change method,
/// status, and a fresh challenge for the next key-wrap handshake.
pub const SessionKeyStatus = struct {
    key_change_seq_num: u32,
    user_number: u16,
    key_wrap_algorithm: KeyWrapAlgorithm,
    key_status: enum(u8) { not_init = 1, ok = 2, comm_fail = 3, auth_fail = 4, _ },
    hmac_algorithm: HmacAlgorithm,
    challenge_data: []const u8,
    hmac_value: []const u8,

    pub fn encode(self: SessionKeyStatus, out: []u8) []u8 {
        _ = self;
        _ = out;
        @panic("TODO(agent): dnp3.sa.SessionKeyStatus.encode is unimplemented (g120 scaffold only, see module doc comment)");
    }

    pub fn decode(bytes: []const u8) SessionKeyStatus {
        _ = bytes;
        @panic("TODO(agent): dnp3.sa.SessionKeyStatus.decode is unimplemented (g120 scaffold only, see module doc comment)");
    }
};

/// g120v6 Session Key Change: the wrapped new session key material. The
/// wrap/unwrap operation (AES key-wrap) is exactly the crypto this scaffold
/// defers -- `wrapped_key_data` is opaque bytes here.
pub const SessionKeyChange = struct {
    key_change_seq_num: u32,
    user_number: u16,
    wrapped_key_data: []const u8,

    pub fn encode(self: SessionKeyChange, out: []u8) []u8 {
        _ = self;
        _ = out;
        @panic("TODO(agent): dnp3.sa.SessionKeyChange.encode is unimplemented (g120 scaffold only, see module doc comment)");
    }

    pub fn decode(bytes: []const u8) SessionKeyChange {
        _ = bytes;
        @panic("TODO(agent): dnp3.sa.SessionKeyChange.decode is unimplemented (g120 scaffold only, see module doc comment)");
    }
};

/// g120v7 Error: an SA-layer error report.
pub const SaError = struct {
    association_id: u16,
    sequence_number: u32,
    error_code: ErrorCode,
    time_of_error: u48,
    error_text: []const u8,

    pub fn encode(self: SaError, out: []u8) []u8 {
        _ = self;
        _ = out;
        @panic("TODO(agent): dnp3.sa.SaError.encode is unimplemented (g120 scaffold only, see module doc comment)");
    }

    pub fn decode(bytes: []const u8) SaError {
        _ = bytes;
        @panic("TODO(agent): dnp3.sa.SaError.decode is unimplemented (g120 scaffold only, see module doc comment)");
    }
};

// ── tests ────────────────────────────────────────────────────────────────────
//
// Deliberately shallow: this file's job is to compile and hold the right
// *shapes*, not to pass behavior tests -- there is no behavior yet. None of
// the encode/decode stubs above are called (they panic by design).

const testing = std.testing;

test "g120 scaffold: types exist with the expected variation numbers" {
    try testing.expectEqual(@as(u8, 1), @intFromEnum(ObjectVariation.challenge));
    try testing.expectEqual(@as(u8, 2), @intFromEnum(ObjectVariation.reply));
    try testing.expectEqual(@as(u8, 5), @intFromEnum(ObjectVariation.session_key_status));
    try testing.expectEqual(@as(u8, 6), @intFromEnum(ObjectVariation.session_key_change));
    try testing.expectEqual(@as(u8, 7), @intFromEnum(ObjectVariation.sa_error));
    try testing.expectEqual(@as(u8, 9), @intFromEnum(ObjectVariation.aggregate_mac));
}

test "g120 scaffold: struct shapes construct without invoking any stub" {
    const challenge = Challenge{ .challenge_seq_num = 1, .hmac_algorithm = .hmac_sha256_trunc_16, .challenge_data = "x" };
    try testing.expectEqual(@as(u32, 1), challenge.challenge_seq_num);

    const reply = Reply{ .challenge_seq_num = 1, .user_number = 1, .hmac_value = "y" };
    try testing.expectEqual(@as(u16, 1), reply.user_number);

    const mac = AggregateMac{ .mac_value = "z" };
    try testing.expectEqual(@as(usize, 1), mac.mac_value.len);
}
