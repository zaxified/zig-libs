// SPDX-License-Identifier: MIT

//! dnp3.sa — DNP3 Secure Authentication, SAv2 symmetric core (IEEE 1815-2012
//! §7 / IEC 62351-5), object group 120. Pure-Zig, zero-C.
//!
//! IMPLEMENTED (SAv2 symmetric authentication):
//! - **AES Key Wrap (RFC 3394)** via the shared `aeskw` module
//!   (`modules/aeskw`) — `aeskw.wrap`/`aeskw.unwrap`, byte-exact against the
//!   RFC 3394 §4 published vectors. std ships no key-wrap; this used to be a
//!   local copy here but has been collapsed onto the canonical extracted
//!   module (also used by `jwe` and `xmlenc`).
//! - **MAC algorithms** (`mac`): the SA algorithm registry — HMAC-SHA-1
//!   (truncated to 4/8/10 octets), HMAC-SHA-256 (truncated to 8/16 octets),
//!   and AES-GMAC (12-octet tag), all via `std.crypto`. Truncation lengths
//!   per the SA MAC-algorithm table. Constant-time verification.
//! - **g120 message codecs**: v1 Challenge, v2 Reply, v3 Aggressive-Mode
//!   Request, v4 Session-Key-Status Request, v5 Session-Key Status, v6
//!   Session-Key Change, v7 Error, v9 (aggressive-mode) MAC — build + parse,
//!   plus the group-120 free-format object header (qualifier 0x5B).
//! - **Challenge-response flow**: `computeReplyMac` MACs over the exact SA
//!   data (challenge message ‖ authenticated ASDU); session-key wrap/unwrap
//!   binding control + monitoring keys under the update key; sequence
//!   (CSQ/KSQ) and key-expiry counters as pure data (no wall-clock — the
//!   caller supplies the clock, like the rest of the repo).
//!
//! OUT OF SCOPE (later pass): the **SAv5/SAv6 asymmetric update-key change**
//! (g120 v8/v10–v15: RSA/DSA-signed remote update-key change, user
//! certificates, user-status change) — none of the certificate/public-key
//! objects are implemented here; only the symmetric update-key ↔ session-key
//! path is. Also out of scope: the DNP3-specific AES-GMAC IV derivation
//! (the GMAC primitive is provided and KAT-validated; the caller supplies the
//! 12-octet IV — the SA IV-from-sequence-number binding is not encoded here).
//!
//! PROVENANCE / what was validated against what (this matters for a crypto
//! file — no over-claiming):
//! - g120 variation numbers, field order/widths, and the MAC-algorithm /
//!   key-wrap / key-status enum values were cross-checked against the
//!   **Wireshark DNP3 dissector** (`epan/dissectors/packet-dnp.c`, GPL —
//!   consulted as a behavioral/wire reference only, no source copied). The
//!   scaffold's MAC-algorithm ids and key-status ordering were WRONG and are
//!   corrected here (see the enum doc comments).
//! - AES-KW (the shared `aeskw` module) is byte-exact against RFC 3394 §4
//!   test vectors; this file's own tests exercise it as an integration path
//!   (session-key wrap/unwrap through this module's call sites).
//! - HMAC truncation is validated against RFC 2202 / RFC 4231 KATs; AES-GMAC
//!   against the GCM spec (McGrew & Viega) test case 1.
//! - The **MAC-input byte construction** (challenge message ‖ authenticated
//!   ASDU for the reply; last-challenge ‖ aggressive request for aggressive
//!   mode) follows the IEEE 1815-2012 §7 description and is validated for
//!   full-flow self-consistency (build→verify accept; flip one byte of the
//!   MAC or of the authenticated ASDU → reject). It is NOT checked against a
//!   live opendnp3 golden MAC vector: modern opendnp3 dropped its SA
//!   implementation, so no interop MAC vector was available. Wire-level MAC
//!   interop therefore remains unproven; the primitives underneath it are
//!   KAT-exact.

const std = @import("std");

/// RFC 3394 AES Key Wrap — the shared, canonical implementation (see
/// `modules/aeskw/src/root.zig`; also used by `jwe` and `xmlenc`). Re-exported
/// under this name so the rest of this file (and its tests) reads the same as
/// before the extraction.
const aeskw = @import("aeskw");

// ── constant-time byte-slice compare ─────────────────────────────────────────

/// Constant-time equality for equal-length secrets. The length itself is
/// public (an early `false` on length mismatch leaks nothing about content).
fn ctEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

// ── MAC algorithms (the SA algorithm registry) ───────────────────────────────

/// HMAC/MAC algorithm identifiers carried in `Challenge`/`SessionKeyStatus`.
///
/// CORRECTED from the scaffold: the scaffold listed SHA-3 variants that are
/// not in IEEE 1815-2012 and had SHA-256/SHA-1 lengths wrong. These values +
/// truncation lengths are cross-checked against the Wireshark DNP3 dissector
/// (`dnp3_al_sa_mal_vals`).
pub const HmacAlgorithm = enum(u8) {
    none = 0,
    /// HMAC-SHA-1 truncated to 4 octets (serial).
    hmac_sha1_trunc_4 = 1,
    /// HMAC-SHA-1 truncated to 10 octets (networked).
    hmac_sha1_trunc_10 = 2,
    /// HMAC-SHA-256 truncated to 8 octets (serial).
    hmac_sha256_trunc_8 = 3,
    /// HMAC-SHA-256 truncated to 16 octets (networked).
    hmac_sha256_trunc_16 = 4,
    /// HMAC-SHA-1 truncated to 8 octets (serial).
    hmac_sha1_trunc_8 = 5,
    /// AES-GMAC, 12-octet tag.
    aes_gmac_trunc_12 = 6,
    _,
};

pub const mac = struct {
    const hmac = std.crypto.auth.hmac;
    const HmacSha1 = hmac.HmacSha1;
    const HmacSha256 = hmac.sha2.HmacSha256;
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

    /// Largest MAC any registry algorithm produces (16, HMAC-SHA-256/16).
    pub const max_len = 16;

    pub const Error = error{
        UnsupportedAlgorithm,
        BufferTooSmall,
        /// AES-GMAC selected but no 12-octet IV was supplied.
        GmacIvRequired,
        /// AES-GMAC key isn't 16 or 32 bytes.
        KeyLength,
    };

    /// Output length in octets for `alg` (0 for `none` / unknown).
    pub fn length(alg: HmacAlgorithm) usize {
        return switch (alg) {
            .none => 0,
            .hmac_sha1_trunc_4 => 4,
            .hmac_sha1_trunc_10 => 10,
            .hmac_sha256_trunc_8 => 8,
            .hmac_sha256_trunc_16 => 16,
            .hmac_sha1_trunc_8 => 8,
            .aes_gmac_trunc_12 => 12,
            _ => 0,
        };
    }

    /// Computes the truncated MAC of a single contiguous `msg` into `out`.
    /// `iv` is required only for AES-GMAC. Returns the truncated slice.
    pub fn compute(alg: HmacAlgorithm, key: []const u8, msg: []const u8, iv: ?[12]u8, out: []u8) Error![]u8 {
        const n = length(alg);
        if (n == 0) return error.UnsupportedAlgorithm;
        if (out.len < n) return error.BufferTooSmall;
        switch (alg) {
            .hmac_sha1_trunc_4, .hmac_sha1_trunc_8, .hmac_sha1_trunc_10 => {
                var full: [HmacSha1.mac_length]u8 = undefined;
                HmacSha1.create(&full, msg, key);
                @memcpy(out[0..n], full[0..n]);
            },
            .hmac_sha256_trunc_8, .hmac_sha256_trunc_16 => {
                var full: [HmacSha256.mac_length]u8 = undefined;
                HmacSha256.create(&full, msg, key);
                @memcpy(out[0..n], full[0..n]);
            },
            .aes_gmac_trunc_12 => {
                const nonce = iv orelse return error.GmacIvRequired;
                var tag: [16]u8 = undefined;
                switch (key.len) {
                    16 => Aes128Gcm.encrypt(&.{}, &tag, &.{}, msg, nonce, key[0..16].*),
                    32 => Aes256Gcm.encrypt(&.{}, &tag, &.{}, msg, nonce, key[0..32].*),
                    else => return error.KeyLength,
                }
                @memcpy(out[0..n], tag[0..n]);
            },
            else => return error.UnsupportedAlgorithm,
        }
        return out[0..n];
    }

    /// Constant-time verify of `received` against the freshly computed MAC.
    pub fn verify(alg: HmacAlgorithm, key: []const u8, msg: []const u8, iv: ?[12]u8, received: []const u8) bool {
        var buf: [max_len]u8 = undefined;
        const computed = compute(alg, key, msg, iv, &buf) catch return false;
        return ctEql(computed, received);
    }

    /// HMAC over two concatenated slices without materialising the
    /// concatenation (streamed) — used for the SA "challenge ‖ ASDU" MAC
    /// input. HMAC algorithms only; AES-GMAC returns `UnsupportedAlgorithm`
    /// (its AAD is single-slice — concatenate and use `compute`).
    pub fn computeTwo(alg: HmacAlgorithm, key: []const u8, a: []const u8, b: []const u8, out: []u8) Error![]u8 {
        const n = length(alg);
        if (out.len < n) return error.BufferTooSmall;
        switch (alg) {
            .hmac_sha1_trunc_4, .hmac_sha1_trunc_8, .hmac_sha1_trunc_10 => {
                var ctx = HmacSha1.init(key);
                ctx.update(a);
                ctx.update(b);
                var full: [HmacSha1.mac_length]u8 = undefined;
                ctx.final(&full);
                @memcpy(out[0..n], full[0..n]);
            },
            .hmac_sha256_trunc_8, .hmac_sha256_trunc_16 => {
                var ctx = HmacSha256.init(key);
                ctx.update(a);
                ctx.update(b);
                var full: [HmacSha256.mac_length]u8 = undefined;
                ctx.final(&full);
                @memcpy(out[0..n], full[0..n]);
            },
            else => return error.UnsupportedAlgorithm,
        }
        return out[0..n];
    }

    /// Constant-time verify of the two-slice (streamed) MAC.
    pub fn verifyTwo(alg: HmacAlgorithm, key: []const u8, a: []const u8, b: []const u8, received: []const u8) bool {
        var buf: [max_len]u8 = undefined;
        const computed = computeTwo(alg, key, a, b, &buf) catch return false;
        return ctEql(computed, received);
    }
};

// ── g120 object model: enums ─────────────────────────────────────────────────

/// Group 120 (Authentication) object variations implemented by this module.
/// Variation numbers cross-checked against the Wireshark DNP3 dissector
/// (`AL_OBJ_SA_AUTH_*`).
pub const ObjectVariation = enum(u8) {
    /// g120v1 — Challenge.
    challenge = 1,
    /// g120v2 — Reply (MAC answering a Challenge).
    reply = 2,
    /// g120v3 — Aggressive-Mode Request (CSQ + user, prepended to a critical ASDU).
    aggressive_mode_request = 3,
    /// g120v4 — Session-Key Status Request.
    session_key_status_request = 4,
    /// g120v5 — Session-Key Status.
    session_key_status = 5,
    /// g120v6 — Session-Key Change (wrapped session keys).
    session_key_change = 6,
    /// g120v7 — Error.
    sa_error = 7,
    /// g120v9 — MAC (aggressive-mode HMAC object appended to a critical ASDU).
    aggregate_mac = 9,
    _,
};

/// Key-wrap algorithm identifiers for `SessionKeyChange` (Wireshark
/// `dnp3_al_sa_kwa_vals`).
pub const KeyWrapAlgorithm = enum(u8) {
    unused = 0,
    aes_128 = 1,
    aes_256 = 2,
    _,
};

/// Key-status values (`SessionKeyStatus`). CORRECTED from the scaffold, which
/// had `ok`/`not_init` swapped: per the Wireshark dissector
/// (`dnp3_al_sa_ks_vals`) OK = 1, NOT_INIT = 2.
pub const KeyStatus = enum(u8) {
    not_used = 0,
    ok = 1,
    not_init = 2,
    comm_fail = 3,
    auth_fail = 4,
    _,
};

/// Reason-for-challenge byte in `Challenge` (g120v1).
pub const ChallengeReason = enum(u8) {
    /// The challenged ASDU is a Critical function that must be authenticated.
    critical = 1,
    _,
};

/// SA-layer error codes (`SaError` / g120v7).
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

// ── g120 free-format object header ───────────────────────────────────────────
//
// Group-120 objects are carried with the DNP3 free-format qualifier 0x5B:
// prefix 5 (2-octet object-size prefix) + range 0xB (1-octet object count).
// One object per header: [120][var][0x5B][count=1][size u16 LE][object data].

pub const ObjError = error{ BufferTooSmall, ShortObject, Truncated };

/// The DNP3 free-format qualifier used for every group-120 object.
pub const free_format_qualifier: u8 = 0x5B;

/// Bytes of header preceding a single g120 object's data (group, variation,
/// qualifier, count, 2-octet size).
pub const object_header_len: usize = 6;

/// Frames a single g120 object: writes the group-120 free-format header and
/// `data` into `out`, returning the whole `object_header_len + data.len` slice.
pub fn encodeObject(variation: ObjectVariation, data: []const u8, out: []u8) ObjError![]u8 {
    const total = object_header_len + data.len;
    if (out.len < total) return error.BufferTooSmall;
    if (data.len > 0xFFFF) return error.BufferTooSmall;
    out[0] = 120;
    out[1] = @intFromEnum(variation);
    out[2] = free_format_qualifier;
    out[3] = 1; // object count
    std.mem.writeInt(u16, out[4..6], @intCast(data.len), .little);
    @memcpy(out[object_header_len..total], data);
    return out[0..total];
}

pub const DecodedObject = struct {
    variation: ObjectVariation,
    data: []const u8,
    consumed: usize,
};

/// Parses one group-120 free-format object header + its data slice.
pub fn decodeObject(bytes: []const u8) ObjError!DecodedObject {
    if (bytes.len < object_header_len) return error.ShortObject;
    if (bytes[0] != 120 or bytes[2] != free_format_qualifier) return error.ShortObject;
    const size = std.mem.readInt(u16, bytes[4..6], .little);
    const end = object_header_len + @as(usize, size);
    if (bytes.len < end) return error.Truncated;
    return .{
        .variation = @enumFromInt(bytes[1]),
        .data = bytes[object_header_len..end],
        .consumed = end,
    };
}

// ── g120v1 Challenge ─────────────────────────────────────────────────────────

/// g120v1 Challenge. Layout: CSQ(4 LE) + user(2 LE) + MAC-alg(1) + reason(1)
/// + challenge data (rest). `challenge_data` is a borrowed slice (not copied);
/// generating cryptographically random challenge data is the caller's job.
pub const Challenge = struct {
    challenge_seq_num: u32,
    user_number: u16,
    mac_algorithm: HmacAlgorithm,
    reason: ChallengeReason,
    challenge_data: []const u8,

    pub const min_len: usize = 8;

    pub fn encode(self: Challenge, out: []u8) ObjError![]u8 {
        const total = min_len + self.challenge_data.len;
        if (out.len < total) return error.BufferTooSmall;
        std.mem.writeInt(u32, out[0..4], self.challenge_seq_num, .little);
        std.mem.writeInt(u16, out[4..6], self.user_number, .little);
        out[6] = @intFromEnum(self.mac_algorithm);
        out[7] = @intFromEnum(self.reason);
        @memcpy(out[8..total], self.challenge_data);
        return out[0..total];
    }

    pub fn decode(bytes: []const u8) ObjError!Challenge {
        if (bytes.len < min_len) return error.ShortObject;
        return .{
            .challenge_seq_num = std.mem.readInt(u32, bytes[0..4], .little),
            .user_number = std.mem.readInt(u16, bytes[4..6], .little),
            .mac_algorithm = @enumFromInt(bytes[6]),
            .reason = @enumFromInt(bytes[7]),
            .challenge_data = bytes[8..],
        };
    }
};

// ── g120v2 Reply ─────────────────────────────────────────────────────────────

/// g120v2 Reply. Layout: CSQ(4 LE) + user(2 LE) + MAC value (rest).
pub const Reply = struct {
    challenge_seq_num: u32,
    user_number: u16,
    mac_value: []const u8,

    pub const min_len: usize = 6;

    pub fn encode(self: Reply, out: []u8) ObjError![]u8 {
        const total = min_len + self.mac_value.len;
        if (out.len < total) return error.BufferTooSmall;
        std.mem.writeInt(u32, out[0..4], self.challenge_seq_num, .little);
        std.mem.writeInt(u16, out[4..6], self.user_number, .little);
        @memcpy(out[6..total], self.mac_value);
        return out[0..total];
    }

    pub fn decode(bytes: []const u8) ObjError!Reply {
        if (bytes.len < min_len) return error.ShortObject;
        return .{
            .challenge_seq_num = std.mem.readInt(u32, bytes[0..4], .little),
            .user_number = std.mem.readInt(u16, bytes[4..6], .little),
            .mac_value = bytes[6..],
        };
    }
};

// ── g120v3 Aggressive-Mode Request ───────────────────────────────────────────

/// g120v3 Aggressive-Mode Request. Layout: CSQ(4 LE) + user(2 LE). Prepended
/// to a critical ASDU whose MAC is then appended as a g120v9 object.
pub const AggressiveModeRequest = struct {
    challenge_seq_num: u32,
    user_number: u16,

    pub const wire_len: usize = 6;

    pub fn encode(self: AggressiveModeRequest, out: []u8) ObjError![]u8 {
        if (out.len < wire_len) return error.BufferTooSmall;
        std.mem.writeInt(u32, out[0..4], self.challenge_seq_num, .little);
        std.mem.writeInt(u16, out[4..6], self.user_number, .little);
        return out[0..wire_len];
    }

    pub fn decode(bytes: []const u8) ObjError!AggressiveModeRequest {
        if (bytes.len < wire_len) return error.ShortObject;
        return .{
            .challenge_seq_num = std.mem.readInt(u32, bytes[0..4], .little),
            .user_number = std.mem.readInt(u16, bytes[4..6], .little),
        };
    }
};

// ── g120v4 Session-Key Status Request ────────────────────────────────────────

/// g120v4 Session-Key Status Request. Layout: user(2 LE).
pub const SessionKeyStatusRequest = struct {
    user_number: u16,

    pub const wire_len: usize = 2;

    pub fn encode(self: SessionKeyStatusRequest, out: []u8) ObjError![]u8 {
        if (out.len < wire_len) return error.BufferTooSmall;
        std.mem.writeInt(u16, out[0..2], self.user_number, .little);
        return out[0..wire_len];
    }

    pub fn decode(bytes: []const u8) ObjError!SessionKeyStatusRequest {
        if (bytes.len < wire_len) return error.ShortObject;
        return .{ .user_number = std.mem.readInt(u16, bytes[0..2], .little) };
    }
};

// ── g120v5 Session-Key Status ────────────────────────────────────────────────

/// g120v5 Session-Key Status. Layout: KSQ(4 LE) + user(2 LE) + key-wrap-alg(1)
/// + key-status(1) + MAC-alg(1) + challenge-data-length(2 LE) + challenge data
/// + MAC value (rest). The MAC value length is implied by `mac_algorithm`, so
/// decode splits the tail deterministically.
pub const SessionKeyStatus = struct {
    key_change_seq_num: u32,
    user_number: u16,
    key_wrap_algorithm: KeyWrapAlgorithm,
    key_status: KeyStatus,
    mac_algorithm: HmacAlgorithm,
    challenge_data: []const u8,
    mac_value: []const u8,

    pub const fixed_len: usize = 11; // 4+2+1+1+1+2

    pub fn encode(self: SessionKeyStatus, out: []u8) ObjError![]u8 {
        const total = fixed_len + self.challenge_data.len + self.mac_value.len;
        if (out.len < total) return error.BufferTooSmall;
        if (self.challenge_data.len > 0xFFFF) return error.BufferTooSmall;
        std.mem.writeInt(u32, out[0..4], self.key_change_seq_num, .little);
        std.mem.writeInt(u16, out[4..6], self.user_number, .little);
        out[6] = @intFromEnum(self.key_wrap_algorithm);
        out[7] = @intFromEnum(self.key_status);
        out[8] = @intFromEnum(self.mac_algorithm);
        std.mem.writeInt(u16, out[9..11], @intCast(self.challenge_data.len), .little);
        var p: usize = fixed_len;
        @memcpy(out[p..][0..self.challenge_data.len], self.challenge_data);
        p += self.challenge_data.len;
        @memcpy(out[p..][0..self.mac_value.len], self.mac_value);
        return out[0..total];
    }

    pub fn decode(bytes: []const u8) ObjError!SessionKeyStatus {
        if (bytes.len < fixed_len) return error.ShortObject;
        const cdl = std.mem.readInt(u16, bytes[9..11], .little);
        const cd_end = fixed_len + @as(usize, cdl);
        if (bytes.len < cd_end) return error.Truncated;
        return .{
            .key_change_seq_num = std.mem.readInt(u32, bytes[0..4], .little),
            .user_number = std.mem.readInt(u16, bytes[4..6], .little),
            .key_wrap_algorithm = @enumFromInt(bytes[6]),
            .key_status = @enumFromInt(bytes[7]),
            .mac_algorithm = @enumFromInt(bytes[8]),
            .challenge_data = bytes[fixed_len..cd_end],
            .mac_value = bytes[cd_end..],
        };
    }

    /// The bytes the outstation MACs into `mac_value`: everything in the
    /// status object from the KSQ through the challenge data (i.e. the object
    /// body up to but excluding the MAC), which binds the status to the
    /// wrapped-key challenge. Returns the length of that prefix within `full`
    /// (the object's own encoded body, without the g120 object header).
    pub fn macCoveredLen(self: SessionKeyStatus) usize {
        return fixed_len + self.challenge_data.len;
    }
};

// ── g120v6 Session-Key Change ────────────────────────────────────────────────

/// g120v6 Session-Key Change. Layout: KSQ(4 LE) + user(2 LE) + wrapped key
/// data (rest). `wrapped_key_data` is the AES-KW output over the concatenated
/// control + monitoring session keys (see `wrapSessionKeys`).
pub const SessionKeyChange = struct {
    key_change_seq_num: u32,
    user_number: u16,
    wrapped_key_data: []const u8,

    pub const min_len: usize = 6;

    pub fn encode(self: SessionKeyChange, out: []u8) ObjError![]u8 {
        const total = min_len + self.wrapped_key_data.len;
        if (out.len < total) return error.BufferTooSmall;
        std.mem.writeInt(u32, out[0..4], self.key_change_seq_num, .little);
        std.mem.writeInt(u16, out[4..6], self.user_number, .little);
        @memcpy(out[6..total], self.wrapped_key_data);
        return out[0..total];
    }

    pub fn decode(bytes: []const u8) ObjError!SessionKeyChange {
        if (bytes.len < min_len) return error.ShortObject;
        return .{
            .key_change_seq_num = std.mem.readInt(u32, bytes[0..4], .little),
            .user_number = std.mem.readInt(u16, bytes[4..6], .little),
            .wrapped_key_data = bytes[6..],
        };
    }
};

// ── g120v7 Error ─────────────────────────────────────────────────────────────

/// g120v7 Error. CORRECTED from the scaffold, whose field order was wrong and
/// which omitted the user number. Layout (per Wireshark): sequence(4 LE) +
/// user(2 LE) + association-id(2 LE) + error-code(1) + time-of-error(6, u48
/// LE ms-since-epoch) + error text (rest).
pub const SaError = struct {
    sequence_number: u32,
    user_number: u16,
    association_id: u16,
    error_code: ErrorCode,
    time_of_error: u48,
    error_text: []const u8,

    pub const min_len: usize = 15; // 4+2+2+1+6

    pub fn encode(self: SaError, out: []u8) ObjError![]u8 {
        const total = min_len + self.error_text.len;
        if (out.len < total) return error.BufferTooSmall;
        std.mem.writeInt(u32, out[0..4], self.sequence_number, .little);
        std.mem.writeInt(u16, out[4..6], self.user_number, .little);
        std.mem.writeInt(u16, out[6..8], self.association_id, .little);
        out[8] = @intFromEnum(self.error_code);
        std.mem.writeInt(u48, out[9..15], self.time_of_error, .little);
        @memcpy(out[15..total], self.error_text);
        return out[0..total];
    }

    pub fn decode(bytes: []const u8) ObjError!SaError {
        if (bytes.len < min_len) return error.ShortObject;
        return .{
            .sequence_number = std.mem.readInt(u32, bytes[0..4], .little),
            .user_number = std.mem.readInt(u16, bytes[4..6], .little),
            .association_id = std.mem.readInt(u16, bytes[6..8], .little),
            .error_code = @enumFromInt(bytes[8]),
            .time_of_error = std.mem.readInt(u48, bytes[9..15], .little),
            .error_text = bytes[15..],
        };
    }
};

// ── g120v9 (aggressive-mode) MAC ─────────────────────────────────────────────

/// g120v9 MAC object: the aggressive-mode MAC value, appended to a critical
/// ASDU. Layout: MAC value (whole object).
pub const AggregateMac = struct {
    mac_value: []const u8,

    pub fn encode(self: AggregateMac, out: []u8) ObjError![]u8 {
        if (out.len < self.mac_value.len) return error.BufferTooSmall;
        @memcpy(out[0..self.mac_value.len], self.mac_value);
        return out[0..self.mac_value.len];
    }

    pub fn decode(bytes: []const u8) ObjError!AggregateMac {
        return .{ .mac_value = bytes };
    }
};

// ── challenge-response MAC input construction ────────────────────────────────
//
// SECURITY CRUX. IEEE 1815-2012 §7 defines the reply MAC as computed over the
// challenge message concatenated with the ASDU being authenticated. Callers
// pass the exact wire byte slices; both sides MUST agree on the same
// definition of those slices (documented below). Validated for full-flow
// self-consistency, not against a live opendnp3 MAC vector (see module header).
//
// ── TRANSCRIPT ADJUDICATION (adversarial-soundness review, 2026-07-19) ────────
// Verdict: SOUND — no attacker-malleable field and no reachable splicing gap,
// given the calling contract below. No code-logic change was required; this
// note exists so the transcript is not re-audited from scratch.
//
// What the MAC input `challenge_message ‖ authenticated_asdu` binds, mapped to
// what IEEE 1815-2012 §7 / IEC 62351-5 require for the challenge-response reply:
//   • CSQ (challenge sequence number) — BOUND: it is the first field of the
//     g120v1 Challenge body (`Challenge.encode`, sa.zig:458, offset 0..4), and
//     `challenge_message` is the whole Challenge fragment.
//   • USR (user number)              — BOUND: g120v1 body offset 4..6
//     (sa.zig:459). A reply for user A cannot be replayed as user B: the copy
//     of USR inside `challenge_message` differs, so the MAC differs.
//   • MAC algorithm + reason         — BOUND: g120v1 bytes 6 and 7
//     (sa.zig:460-461); an attacker cannot silently downgrade the algorithm id.
//   • Challenge nonce (freshness)    — BOUND: g120v1 tail (sa.zig:462). A stale
//     reply fails because the verifier's stored nonce differs.
//   • Direction / role               — BOUND out-of-band by KEY SEPARATION, not
//     by transcript bytes: the control-direction and monitoring-direction
//     session keys are distinct (see `wrapSessionKeys`, sa.zig:752), so a reply
//     MAC'd under one direction's key never verifies under the other's. This
//     matches the spec, which does not put a direction octet in the MAC input.
//   • KSQ (key-change sequence)      — NOT APPLICABLE to the reply MAC. KSQ
//     belongs to the session-key-change path (g120v5/v6) and is bound there by
//     `SessionKeyStatus.macCoveredLen` (sa.zig:608), which covers KSQ..nonce.
//   • Full critical ASDU             — BOUND: `authenticated_asdu` is the entire
//     application fragment. In AGGRESSIVE mode the g120v3 request object (its
//     own CSQ+USR, sa.zig:517) is the leading bytes of `authenticated_asdu`, so
//     the per-message aggressive CSQ is bound too — supply g120v3‖ASDU as the
//     second operand.
//
// (a) Attacker-varied-yet-verifies field: NONE. Every field above is either in
//     a MAC-covered operand or separated by key. Under a FIXED verifier
//     challenge C, `verify(C ‖ A') == verify(C ‖ A)` forces A' == A (HMAC
//     collision resistance); across challenges a fresh nonce in C breaks replay.
//
// (b) Concatenation / length-ambiguity splicing: the two operands are streamed
//     with NO length prefix (`mac.computeTwo`, sa.zig:281), so as a pure
//     function the boundary is ambiguous — HMAC(x‖y)=HMAC(x'‖y') whenever the
//     flat bytes coincide. This is NOT reachable by an attacker because the
//     VERIFIER supplies BOTH operands from its own authoritative state: the
//     g120v2 Reply on the wire carries only CSQ+USR+MAC (sa.zig:481), never the
//     challenge, so the outstation MUST reconstruct `challenge_message` from the
//     challenge IT sent (a fixed, known length) and take `authenticated_asdu`
//     from the received request framed by its own object headers. The boundary
//     is therefore pinned out-of-band on the trusting side and cannot be shifted
//     from the wire. CONTRACT (do not break): never derive the length of
//     `challenge_message` from bytes carried in the reply/request — always from
//     the verifier's stored challenge. If a future caller ever lets the wire
//     move that boundary, add explicit length-prefix framing here first.
//
// (c) Omitted critical ASDU field: NONE — the whole application fragment is one
//     opaque operand; nothing inside it is skipped.

/// Computes the g120v2 Reply MAC. `session_key` is the direction's session
/// key; `challenge_message` is the full application-layer bytes of the
/// received g120v1 Challenge ASDU (from the application control octet through
/// the last challenge-data octet); `authenticated_asdu` is the full
/// application-layer bytes of the critical ASDU being authenticated. Streams
/// `challenge_message ‖ authenticated_asdu` through the MAC (HMAC algorithms).
pub fn computeReplyMac(
    alg: HmacAlgorithm,
    session_key: []const u8,
    challenge_message: []const u8,
    authenticated_asdu: []const u8,
    out: []u8,
) mac.Error![]u8 {
    return mac.computeTwo(alg, session_key, challenge_message, authenticated_asdu, out);
}

/// Constant-time verify of a received g120v2 Reply MAC (mirror of
/// `computeReplyMac`).
pub fn verifyReplyMac(
    alg: HmacAlgorithm,
    session_key: []const u8,
    challenge_message: []const u8,
    authenticated_asdu: []const u8,
    received: []const u8,
) bool {
    return mac.verifyTwo(alg, session_key, challenge_message, authenticated_asdu, received);
}

// ── session-key wrap / unwrap ────────────────────────────────────────────────

pub const SessionKeyError = error{
    /// The two direction keys differ in length, or aren't 16/32 bytes.
    KeyLength,
    BufferTooSmall,
    /// AES-KW integrity failure on unwrap (wrong update key or corruption).
    Unauthentic,
};

/// Wraps the control- and monitoring-direction session keys under the update
/// key using AES-KW (RFC 3394), producing the g120v6 `wrapped_key_data`. Both
/// keys must be the same length (16 or 32). Output is `2*key_len + 8` bytes.
pub fn wrapSessionKeys(
    update_key: []const u8,
    control_key: []const u8,
    monitoring_key: []const u8,
    out: []u8,
) SessionKeyError![]u8 {
    if (control_key.len != monitoring_key.len) return error.KeyLength;
    if (control_key.len != 16 and control_key.len != 32) return error.KeyLength;
    var plain: [64]u8 = undefined;
    // `plain` holds both session keys in cleartext; wipe the stack scratch on
    // every exit so the secrets do not linger after wrapping.
    defer std.crypto.secureZero(u8, &plain);
    const klen = control_key.len;
    @memcpy(plain[0..klen], control_key);
    @memcpy(plain[klen .. 2 * klen], monitoring_key);
    // `else` folds both `aeskw.Error.InvalidLength` (misshapen KEK/plaintext)
    // and `aeskw.Error.UnsupportedKeyLength` (a KEK length with no std AES
    // core, e.g. 192-bit) into `KeyLength` — this module's public error set
    // has never distinguished those two failure modes for the update key, so
    // adopting the shared `aeskw` module (which splits them) doesn't change
    // what a `wrapSessionKeys` caller observes.
    return aeskw.wrap(update_key, plain[0 .. 2 * klen], out) catch |e| switch (e) {
        error.BufferTooSmall => error.BufferTooSmall,
        else => error.KeyLength,
    };
}

pub const UnwrappedSessionKeys = struct {
    control_key: []const u8,
    monitoring_key: []const u8,
};

/// Unwraps g120v6 `wrapped_key_data` back into the two direction keys, writing
/// them into `out` and returning slices into it. `key_len` is the per-direction
/// key length used at wrap time (16 or 32). The recovered keys live in the
/// caller-owned `out`; the caller MUST `secureZero` it once the session keys are
/// installed (this function cannot, as it hands those bytes back).
pub fn unwrapSessionKeys(
    update_key: []const u8,
    wrapped: []const u8,
    key_len: usize,
    out: []u8,
) SessionKeyError!UnwrappedSessionKeys {
    if (key_len != 16 and key_len != 32) return error.KeyLength;
    if (out.len < 2 * key_len) return error.BufferTooSmall;
    // Same `else` fold as `wrapSessionKeys`: `aeskw.Error.InvalidLength` and
    // `aeskw.Error.UnsupportedKeyLength` both become `KeyLength` here, so
    // adopting the shared module (which added the latter as a distinct
    // variant) does not change this function's observable error surface.
    const recovered = aeskw.unwrap(update_key, wrapped, out) catch |e| switch (e) {
        error.Unauthentic => return error.Unauthentic,
        error.BufferTooSmall => return error.BufferTooSmall,
        else => return error.KeyLength,
    };
    if (recovered.len != 2 * key_len) return error.KeyLength;
    return .{
        .control_key = recovered[0..key_len],
        .monitoring_key = recovered[key_len .. 2 * key_len],
    };
}

// ── session/state helpers (pure data, caller supplies the clock) ─────────────

/// A monotonic sequence counter for the Challenge (CSQ) or Key-Change (KSQ)
/// sequence numbers. Wraps at u32.
pub const SeqCounter = struct {
    value: u32 = 0,

    /// Returns the next sequence number to send and advances.
    pub fn next(self: *SeqCounter) u32 {
        self.value +%= 1;
        return self.value;
    }

    /// Whether `received` is the sequence number we expect next (strict
    /// increase-by-one; the caller decides its own replay policy on top).
    pub fn accepts(self: SeqCounter, received: u32) bool {
        return received == self.value +% 1;
    }
};

/// Session-key expiry as pure data: a key must be re-established after either
/// `max_messages` authenticated messages or `max_seconds` of wall time. No
/// wall-clock is read here — the caller passes the current time, matching the
/// rest of the repo. A limit of 0 disables that axis.
pub const KeyExpiry = struct {
    max_messages: u32,
    max_seconds: u32,
    message_count: u32 = 0,
    /// Caller-supplied timestamp (seconds) recorded when the key was set.
    established_at: u64 = 0,

    pub fn establish(self: *KeyExpiry, now_seconds: u64) void {
        self.message_count = 0;
        self.established_at = now_seconds;
    }

    /// Records one authenticated message against the counter.
    pub fn onMessage(self: *KeyExpiry) void {
        self.message_count +|= 1;
    }

    /// Whether the key has expired given the caller's clock.
    pub fn expired(self: KeyExpiry, now_seconds: u64) bool {
        if (self.max_messages != 0 and self.message_count >= self.max_messages) return true;
        if (self.max_seconds != 0 and now_seconds >= self.established_at + self.max_seconds) return true;
        return false;
    }
};

/// A user → update-key association. Update keys are long-lived pre-shared
/// secrets; this is just the lookup shape (the caller owns storage).
pub const UserAssociation = struct {
    user_number: u16,
    update_key: []const u8,
};

/// Linear lookup of a user's update key in a caller-owned association table.
pub fn lookupUpdateKey(table: []const UserAssociation, user_number: u16) ?[]const u8 {
    for (table) |a| {
        if (a.user_number == user_number) return a.update_key;
    }
    return null;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// The four tests below duplicate KATs also asserted in
// `modules/aeskw/src/root.zig` (§4.1/§4.3/§4.6, wrong-KEK/corruption reject,
// malformed lengths). Kept here deliberately as an INTEGRATION test through
// dnp3's own `aeskw` re-export (sa.zig:63) — they prove the module import is
// wired correctly and that `wrapSessionKeys`/`unwrapSessionKeys` sit on the
// same primitive dnp3's tests have always exercised, not just that the
// standalone `aeskw` module itself is correct (already covered there).

test "AES-KW: RFC 3394 §4.1 (128-bit KEK, 128-bit key)" {
    const kek = hexToBytes("000102030405060708090A0B0C0D0E0F");
    const key = hexToBytes("00112233445566778899AABBCCDDEEFF");
    const expect = hexToBytes("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
    var buf: [64]u8 = undefined;
    const ct = try aeskw.wrap(&kek, &key, &buf);
    try testing.expectEqualSlices(u8, &expect, ct);
    var ubuf: [64]u8 = undefined;
    const pt = try aeskw.unwrap(&kek, ct, &ubuf);
    try testing.expectEqualSlices(u8, &key, pt);
}

test "AES-KW: RFC 3394 §4.3 (256-bit KEK, 128-bit key)" {
    const kek = hexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    const key = hexToBytes("00112233445566778899AABBCCDDEEFF");
    const expect = hexToBytes("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7");
    var buf: [64]u8 = undefined;
    const ct = try aeskw.wrap(&kek, &key, &buf);
    try testing.expectEqualSlices(u8, &expect, ct);
    var ubuf: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, &key, try aeskw.unwrap(&kek, ct, &ubuf));
}

test "AES-KW: RFC 3394 §4.6 (256-bit KEK, 256-bit key)" {
    const kek = hexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    const key = hexToBytes("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
    const expect = hexToBytes("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21");
    var buf: [64]u8 = undefined;
    const ct = try aeskw.wrap(&kek, &key, &buf);
    try testing.expectEqualSlices(u8, &expect, ct);
    var ubuf: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, &key, try aeskw.unwrap(&kek, ct, &ubuf));
}

test "AES-KW: unwrap with wrong KEK or corrupted ciphertext is rejected" {
    const kek = hexToBytes("000102030405060708090A0B0C0D0E0F");
    const bad_kek = hexToBytes("100102030405060708090A0B0C0D0E0F");
    const key = hexToBytes("00112233445566778899AABBCCDDEEFF");
    var buf: [64]u8 = undefined;
    const ct = try aeskw.wrap(&kek, &key, &buf);
    var ubuf: [64]u8 = undefined;
    try testing.expectError(error.Unauthentic, aeskw.unwrap(&bad_kek, ct, &ubuf));
    var corrupt: [24]u8 = undefined;
    @memcpy(&corrupt, ct);
    corrupt[10] ^= 0x01;
    try testing.expectError(error.Unauthentic, aeskw.unwrap(&kek, &corrupt, &ubuf));
}

test "AES-KW: malformed lengths are typed errors, never panic" {
    const kek = hexToBytes("000102030405060708090A0B0C0D0E0F");
    var buf: [64]u8 = undefined;
    try testing.expectError(error.InvalidLength, aeskw.wrap(&kek, &.{ 1, 2, 3 }, &buf)); // not mult of 8
    try testing.expectError(error.InvalidLength, aeskw.wrap(&kek, &(hexToBytes("0011223344556677")), &buf)); // < 16
    try testing.expectError(error.InvalidLength, aeskw.unwrap(&kek, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, &buf)); // < 24
}

test "MAC: HMAC-SHA-256 KAT (RFC 4231 case 2) at 8- and 16-octet truncations" {
    const key = "Jefe";
    const msg = "what do ya want for nothing?";
    const full = hexToBytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    var out: [16]u8 = undefined;
    const t8 = try mac.compute(.hmac_sha256_trunc_8, key, msg, null, &out);
    try testing.expectEqualSlices(u8, full[0..8], t8);
    const t16 = try mac.compute(.hmac_sha256_trunc_16, key, msg, null, &out);
    try testing.expectEqualSlices(u8, full[0..16], t16);
}

test "MAC: HMAC-SHA-1 KAT (RFC 2202 case 2) at 4/8/10-octet truncations" {
    const key = "Jefe";
    const msg = "what do ya want for nothing?";
    const full = hexToBytes("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    var out: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, full[0..4], try mac.compute(.hmac_sha1_trunc_4, key, msg, null, &out));
    try testing.expectEqualSlices(u8, full[0..8], try mac.compute(.hmac_sha1_trunc_8, key, msg, null, &out));
    try testing.expectEqualSlices(u8, full[0..10], try mac.compute(.hmac_sha1_trunc_10, key, msg, null, &out));
}

test "MAC: AES-GMAC via GCM empty-plaintext path — McGrew GCM test case 1" {
    // AES-128, key=0, IV=0, empty plaintext, empty AAD -> tag 58e2...455a.
    const key = [_]u8{0} ** 16;
    const iv = [_]u8{0} ** 12;
    const expect_tag = hexToBytes("58e2fccefa7e3061367f1d57a4e7455a");
    var tag: [16]u8 = undefined;
    mac.Aes128Gcm.encrypt(&.{}, &tag, &.{}, &.{}, iv, key);
    try testing.expectEqualSlices(u8, &expect_tag, &tag);
    // And the 12-octet SA GMAC truncation over a non-empty authenticated msg
    // round-trips through compute/verify (self-consistent).
    var out: [16]u8 = undefined;
    const t = try mac.compute(.aes_gmac_trunc_12, &key, "authenticated data", iv, &out);
    try testing.expectEqual(@as(usize, 12), t.len);
    try testing.expect(mac.verify(.aes_gmac_trunc_12, &key, "authenticated data", iv, t));
    try testing.expect(!mac.verify(.aes_gmac_trunc_12, &key, "authenticated dat!", iv, t));
}

test "MAC: constant-time verify accepts good, rejects tampered / wrong length" {
    const key = "secret-session-key";
    const msg = "critical asdu bytes";
    var out: [16]u8 = undefined;
    const t = try mac.compute(.hmac_sha256_trunc_16, key, msg, null, &out);
    try testing.expect(mac.verify(.hmac_sha256_trunc_16, key, msg, null, t));
    var tampered: [16]u8 = undefined;
    @memcpy(&tampered, t);
    tampered[0] ^= 0x01;
    try testing.expect(!mac.verify(.hmac_sha256_trunc_16, key, msg, null, &tampered));
    try testing.expect(!mac.verify(.hmac_sha256_trunc_16, key, msg, null, t[0..15])); // wrong length
}

test "g120 free-format object header round-trip" {
    var data: [4]u8 = .{ 0xDE, 0xAD, 0xBE, 0xEF };
    var out: [16]u8 = undefined;
    const obj = try encodeObject(.reply, &data, &out);
    try testing.expectEqualSlices(u8, &.{ 120, 2, 0x5B, 1, 4, 0, 0xDE, 0xAD, 0xBE, 0xEF }, obj);
    const dec = try decodeObject(obj);
    try testing.expectEqual(ObjectVariation.reply, dec.variation);
    try testing.expectEqualSlices(u8, &data, dec.data);
    try testing.expectEqual(obj.len, dec.consumed);
}

test "g120v1 Challenge encode/decode round-trip" {
    const cd = "0123456789abcdef";
    const ch = Challenge{
        .challenge_seq_num = 0x11223344,
        .user_number = 7,
        .mac_algorithm = .hmac_sha256_trunc_16,
        .reason = .critical,
        .challenge_data = cd,
    };
    var out: [64]u8 = undefined;
    const bytes = try ch.encode(&out);
    try testing.expectEqual(@as(usize, 8 + cd.len), bytes.len);
    try testing.expectEqual(@as(u8, @intFromEnum(HmacAlgorithm.hmac_sha256_trunc_16)), bytes[6]);
    try testing.expectEqual(@as(u8, 1), bytes[7]); // reason = critical
    const back = try Challenge.decode(bytes);
    try testing.expectEqual(@as(u32, 0x11223344), back.challenge_seq_num);
    try testing.expectEqual(@as(u16, 7), back.user_number);
    try testing.expectEqual(HmacAlgorithm.hmac_sha256_trunc_16, back.mac_algorithm);
    try testing.expectEqualSlices(u8, cd, back.challenge_data);
}

test "g120v5 Session-Key Status encode/decode splits challenge data + MAC" {
    const cd = "challenge!";
    const mv = hexToBytes("00112233445566778899aabbccddeeff");
    const st = SessionKeyStatus{
        .key_change_seq_num = 42,
        .user_number = 3,
        .key_wrap_algorithm = .aes_256,
        .key_status = .ok,
        .mac_algorithm = .hmac_sha256_trunc_16,
        .challenge_data = cd,
        .mac_value = &mv,
    };
    var out: [128]u8 = undefined;
    const bytes = try st.encode(&out);
    try testing.expectEqual(@as(u8, @intFromEnum(KeyStatus.ok)), bytes[7]);
    const back = try SessionKeyStatus.decode(bytes);
    try testing.expectEqual(KeyStatus.ok, back.key_status);
    try testing.expectEqual(KeyWrapAlgorithm.aes_256, back.key_wrap_algorithm);
    try testing.expectEqualSlices(u8, cd, back.challenge_data);
    try testing.expectEqualSlices(u8, &mv, back.mac_value);
}

test "g120v7 Error corrected layout round-trip (seq, user, assoc, code, time)" {
    const err = SaError{
        .sequence_number = 0xAABBCCDD,
        .user_number = 5,
        .association_id = 0x1234,
        .error_code = .authentication_failed,
        .time_of_error = 0x0000_1122_3344_5566 & 0xFFFF_FFFF_FFFF,
        .error_text = "denied",
    };
    var out: [64]u8 = undefined;
    const bytes = try err.encode(&out);
    // Field order sanity: bytes[0..4]=seq, [4..6]=user, [6..8]=assoc, [8]=code.
    try testing.expectEqual(@as(u32, 0xAABBCCDD), std.mem.readInt(u32, bytes[0..4], .little));
    try testing.expectEqual(@as(u16, 5), std.mem.readInt(u16, bytes[4..6], .little));
    try testing.expectEqual(@as(u16, 0x1234), std.mem.readInt(u16, bytes[6..8], .little));
    try testing.expectEqual(@as(u8, 1), bytes[8]);
    const back = try SaError.decode(bytes);
    try testing.expectEqual(ErrorCode.authentication_failed, back.error_code);
    try testing.expectEqualSlices(u8, "denied", back.error_text);
}

test "g120 v3/v4/v6/v9 round-trips" {
    var out: [64]u8 = undefined;

    const agg = AggressiveModeRequest{ .challenge_seq_num = 9, .user_number = 2 };
    const b3 = try agg.encode(&out);
    try testing.expectEqual(agg.challenge_seq_num, (try AggressiveModeRequest.decode(b3)).challenge_seq_num);

    const req = SessionKeyStatusRequest{ .user_number = 77 };
    var o4: [8]u8 = undefined;
    try testing.expectEqual(@as(u16, 77), (try SessionKeyStatusRequest.decode(try req.encode(&o4))).user_number);

    const wrapped = hexToBytes("000102030405060708090a0b0c0d0e0f1011121314151617");
    const kc = SessionKeyChange{ .key_change_seq_num = 3, .user_number = 1, .wrapped_key_data = &wrapped };
    const b6 = try kc.encode(&out);
    try testing.expectEqualSlices(u8, &wrapped, (try SessionKeyChange.decode(b6)).wrapped_key_data);

    const m = AggregateMac{ .mac_value = wrapped[0..12] };
    const b9 = try m.encode(&out);
    try testing.expectEqualSlices(u8, wrapped[0..12], (try AggregateMac.decode(b9)).mac_value);
}

test "decode: short/garbage g120 objects are typed errors, never panic" {
    try testing.expectError(error.ShortObject, Challenge.decode(&.{ 1, 2, 3 }));
    try testing.expectError(error.ShortObject, Reply.decode(&.{ 1, 2 }));
    try testing.expectError(error.ShortObject, SaError.decode(&[_]u8{0} ** 10));
    try testing.expectError(error.ShortObject, decodeObject(&.{ 120, 2 }));
    // wrong group / qualifier
    try testing.expectError(error.ShortObject, decodeObject(&.{ 99, 2, 0x5B, 1, 0, 0 }));
    // size claims more than present
    try testing.expectError(error.Truncated, decodeObject(&.{ 120, 2, 0x5B, 1, 40, 0, 0xAA }));
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        const garbage: [16]u8 = .{0xFF} ** 16;
        _ = Challenge.decode(garbage[0..i]) catch {};
        _ = SessionKeyStatus.decode(garbage[0..i]) catch {};
        _ = decodeObject(garbage[0..i]) catch {};
    }
}

test "session-key wrap/unwrap: both sides recover identical keys; wrong update key fails" {
    const update_key = hexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    const wrong_key = hexToBytes("FF0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    const control_key = hexToBytes("00112233445566778899AABBCCDDEEFF");
    const monitoring_key = hexToBytes("FFEEDDCCBBAA99887766554433221100");

    var wrapped: [72]u8 = undefined;
    const wk = try wrapSessionKeys(&update_key, &control_key, &monitoring_key, &wrapped);
    try testing.expectEqual(@as(usize, 2 * 16 + 8), wk.len);

    var recovered: [72]u8 = undefined;
    const keys = try unwrapSessionKeys(&update_key, wk, 16, &recovered);
    try testing.expectEqualSlices(u8, &control_key, keys.control_key);
    try testing.expectEqualSlices(u8, &monitoring_key, keys.monitoring_key);

    var bad: [64]u8 = undefined;
    try testing.expectError(error.Unauthentic, unwrapSessionKeys(&wrong_key, wk, 16, &bad));

    // 256-bit session keys too.
    const ck32 = hexToBytes("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");
    const mk32 = hexToBytes("FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100");
    const wk2 = try wrapSessionKeys(&update_key, &ck32, &mk32, &wrapped);
    try testing.expectEqual(@as(usize, 2 * 32 + 8), wk2.len);
    const keys2 = try unwrapSessionKeys(&update_key, wk2, 32, &recovered);
    try testing.expectEqualSlices(u8, &ck32, keys2.control_key);
    try testing.expectEqualSlices(u8, &mk32, keys2.monitoring_key);
}

test "full challenge-response flow: build v1 -> compute v2 -> verify = accept; tamper = reject" {
    // Shared session key (control direction).
    const session_key = hexToBytes("0f0e0d0c0b0a09080706050403020100112233445566778899aabbccddeeff00");
    const alg: HmacAlgorithm = .hmac_sha256_trunc_16;
    const user: u16 = 4;
    var csq = SeqCounter{};

    // The master sent this critical ASDU (e.g. an operate) — full app fragment.
    const critical_asdu = [_]u8{ 0xC4, 0x05, 0x0C, 0x01, 0x17, 0x01, 0x00, 0x41, 0x03, 0x00 };

    // Outstation builds a g120v1 Challenge as a full application fragment:
    // app control + AUTH_RESPONSE function + the framed g120v1 object.
    const challenge_data = hexToBytes("cafebabedeadbeef00112233445566778899aabbccddeeff");
    const ch = Challenge{
        .challenge_seq_num = csq.next(),
        .user_number = user,
        .mac_algorithm = alg,
        .reason = .critical,
        .challenge_data = &challenge_data,
    };
    var ch_obj_buf: [64]u8 = undefined;
    const ch_obj = try ch.encode(&ch_obj_buf);
    var ch_msg_buf: [96]u8 = undefined;
    ch_msg_buf[0] = 0xC3; // app control (FIR|FIN, seq 3)
    ch_msg_buf[1] = 0x83; // AUTH_RESPONSE
    const framed = try encodeObject(.challenge, ch_obj, ch_msg_buf[2..]);
    const challenge_message = ch_msg_buf[0 .. 2 + framed.len];

    // Master receives the challenge, computes the reply MAC over
    // challenge_message ‖ critical_asdu, and builds a g120v2 Reply.
    var reply_mac_buf: [16]u8 = undefined;
    const reply_mac = try computeReplyMac(alg, &session_key, challenge_message, &critical_asdu, &reply_mac_buf);
    const reply = Reply{ .challenge_seq_num = ch.challenge_seq_num, .user_number = user, .mac_value = reply_mac };
    var reply_obj_buf: [64]u8 = undefined;
    const reply_obj = try reply.encode(&reply_obj_buf);

    // Outstation parses the reply and verifies against the same inputs.
    const parsed_reply = try Reply.decode(reply_obj);
    try testing.expectEqual(ch.challenge_seq_num, parsed_reply.challenge_seq_num);
    try testing.expect(verifyReplyMac(alg, &session_key, challenge_message, &critical_asdu, parsed_reply.mac_value));

    // Tamper the MAC -> reject.
    var bad_mac: [16]u8 = undefined;
    @memcpy(&bad_mac, reply_mac);
    bad_mac[7] ^= 0x01;
    try testing.expect(!verifyReplyMac(alg, &session_key, challenge_message, &critical_asdu, &bad_mac));

    // Tamper the authenticated ASDU -> reject (MAC binds the ASDU).
    var tampered_asdu: [critical_asdu.len]u8 = undefined;
    @memcpy(&tampered_asdu, &critical_asdu);
    tampered_asdu[8] ^= 0x01; // flip a control-code byte
    try testing.expect(!verifyReplyMac(alg, &session_key, challenge_message, &tampered_asdu, parsed_reply.mac_value));
}

test "transcript adjudication: verifier's authoritative boundary rejects a spliced ASDU" {
    // The reply MAC streams `challenge_message ‖ authenticated_asdu` with no
    // length prefix, so soundness rests on the verifier fixing the boundary
    // from its OWN stored challenge (see the TRANSCRIPT ADJUDICATION note). This
    // pins the security property: an attacker who tries to move the boundary —
    // shrinking the challenge and growing the ASDU by the freed byte — produces
    // a different concatenation against the verifier's fixed 6-byte challenge
    // and is rejected. (A future length-prefix hardening keeps this green.)
    const key = "session-key-control-direction!!!"; // 32 bytes
    const alg: HmacAlgorithm = .hmac_sha256_trunc_16;

    // The 6-byte challenge the outstation actually sent, and the 4-byte ASDU.
    const challenge = [_]u8{ 0xC3, 0x83, 0xAA, 0xBB, 0xCC, 0xDD };
    const asdu = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    var m: [16]u8 = undefined;
    const good = try computeReplyMac(alg, key, &challenge, &asdu, &m);
    // Honest split verifies against the authoritative challenge.
    try testing.expect(verifyReplyMac(alg, key, &challenge, &asdu, good));

    // Attacker's alternate 5+5 split (last challenge byte moved into the ASDU).
    const spliced_asdu = [_]u8{ challenge[5], asdu[0], asdu[1], asdu[2], asdu[3] };
    // Against the verifier's FIXED 6-byte challenge this is a different message
    // (6 ‖ 5 = 11 bytes, not the original 10) and must not verify.
    try testing.expect(!verifyReplyMac(alg, key, &challenge, &spliced_asdu, good));
}

test "SeqCounter and KeyExpiry behave as pure counters (no wall clock)" {
    var seq = SeqCounter{};
    try testing.expectEqual(@as(u32, 1), seq.next());
    try testing.expectEqual(@as(u32, 2), seq.next());
    try testing.expect(seq.accepts(3));
    try testing.expect(!seq.accepts(5));

    var exp = KeyExpiry{ .max_messages = 3, .max_seconds = 100 };
    exp.establish(1000);
    try testing.expect(!exp.expired(1050));
    exp.onMessage();
    exp.onMessage();
    exp.onMessage();
    try testing.expect(exp.expired(1050)); // message count hit
    exp.establish(1000);
    try testing.expect(exp.expired(1100)); // time axis hit (>= established + max_seconds)
}

test "lookupUpdateKey finds the user's update key" {
    const k1 = [_]u8{0x11} ** 16;
    const k2 = [_]u8{0x22} ** 32;
    const table = [_]UserAssociation{
        .{ .user_number = 1, .update_key = &k1 },
        .{ .user_number = 9, .update_key = &k2 },
    };
    try testing.expectEqualSlices(u8, &k2, lookupUpdateKey(&table, 9).?);
    try testing.expect(lookupUpdateKey(&table, 5) == null);
}
