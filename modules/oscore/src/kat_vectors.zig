// SPDX-License-Identifier: MIT
//! RFC 8613 (OSCORE) Appendix C's OFFICIAL test vectors, transcribed
//! byte-exact from the RFC text (not copied from any implementation —
//! see `../NOTICE`). All hex fields are lowercase, no `0x` prefix, no
//! byte-count comments (see each `Vector` field's doc comment for the
//! exact RFC field it corresponds to).
//!
//! - `key_derivation_vectors`: Appendix C.1 ("Key Derivation with Master
//!   Salt"), C.2 ("Key Derivation without Master Salt"), and C.3 ("Key
//!   Derivation with ID Context") — each split into its Client (§C.x.1)
//!   and Server (§C.x.2) direction, six entries total.
//! - `message_vectors`: Appendix C.4-C.6 (three OSCORE-protected
//!   requests, one per key-derivation vector above) and C.7-C.8 (two
//!   OSCORE-protected responses to the C.4 request) — five entries.

/// One direction (client or server) of one Appendix C.1-C.3 key-derivation
/// test case.
pub const KeyDerivationVector = struct {
    label: []const u8,
    master_secret: []const u8, // hex
    master_salt: []const u8, // hex, "" if not used (C.2)
    id_context: []const u8, // hex, "" if not used (C.1, C.2)
    sender_id: []const u8, // hex
    recipient_id: []const u8, // hex
    /// §3.2.1 `info` CBOR array, Sender Key direction (`id = sender_id`).
    info_sender_key: []const u8, // hex
    /// §3.2.1 `info`, Recipient Key direction (`id = recipient_id`).
    info_recipient_key: []const u8, // hex
    /// §3.2.1 `info`, Common IV direction (`id = ""`, always).
    info_common_iv: []const u8, // hex
    sender_key: []const u8, // hex, 16 bytes
    recipient_key: []const u8, // hex, 16 bytes
    common_iv: []const u8, // hex, 13 bytes
    /// `computeNonce(common_iv, sender_id, 0)`.
    sender_nonce_piv0: []const u8, // hex, 13 bytes
    /// `computeNonce(common_iv, recipient_id, 0)`.
    recipient_nonce_piv0: []const u8, // hex, 13 bytes
};

pub const key_derivation_vectors = [_]KeyDerivationVector{
    .{
        .label = "C.1.1 Client (Key Derivation with Master Salt)",
        .master_secret = "0102030405060708090a0b0c0d0e0f10",
        .master_salt = "9e7ca92223786340",
        .id_context = "",
        .sender_id = "",
        .recipient_id = "01",
        .info_sender_key = "8540f60a634b657910",
        .info_recipient_key = "854101f60a634b657910",
        .info_common_iv = "8540f60a6249560d",
        .sender_key = "f0910ed7295e6ad4b54fc793154302ff",
        .recipient_key = "ffb14e093c94c9cac9471648b4f98710",
        .common_iv = "4622d4dd6d944168eefb54987c",
        .sender_nonce_piv0 = "4622d4dd6d944168eefb54987c",
        .recipient_nonce_piv0 = "4722d4dd6d944169eefb54987c",
    },
    .{
        .label = "C.1.2 Server (Key Derivation with Master Salt)",
        .master_secret = "0102030405060708090a0b0c0d0e0f10",
        .master_salt = "9e7ca92223786340",
        .id_context = "",
        .sender_id = "01",
        .recipient_id = "",
        .info_sender_key = "854101f60a634b657910",
        .info_recipient_key = "8540f60a634b657910",
        .info_common_iv = "8540f60a6249560d",
        .sender_key = "ffb14e093c94c9cac9471648b4f98710",
        .recipient_key = "f0910ed7295e6ad4b54fc793154302ff",
        .common_iv = "4622d4dd6d944168eefb54987c",
        .sender_nonce_piv0 = "4722d4dd6d944169eefb54987c",
        .recipient_nonce_piv0 = "4622d4dd6d944168eefb54987c",
    },
    .{
        .label = "C.2.1 Client (Key Derivation without Master Salt)",
        .master_secret = "0102030405060708090a0b0c0d0e0f10",
        .master_salt = "",
        .id_context = "",
        .sender_id = "00",
        .recipient_id = "01",
        .info_sender_key = "854100f60a634b657910",
        .info_recipient_key = "854101f60a634b657910",
        .info_common_iv = "8540f60a6249560d",
        .sender_key = "321b26943253c7ffb6003b0b64d74041",
        .recipient_key = "e57b5635815177cd679ab4bcec9d7dda",
        .common_iv = "be35ae297d2dace910c52e99f9",
        .sender_nonce_piv0 = "bf35ae297d2dace910c52e99f9",
        .recipient_nonce_piv0 = "bf35ae297d2dace810c52e99f9",
    },
    .{
        .label = "C.2.2 Server (Key Derivation without Master Salt)",
        .master_secret = "0102030405060708090a0b0c0d0e0f10",
        .master_salt = "",
        .id_context = "",
        .sender_id = "01",
        .recipient_id = "00",
        .info_sender_key = "854101f60a634b657910",
        .info_recipient_key = "854100f60a634b657910",
        .info_common_iv = "8540f60a6249560d",
        .sender_key = "e57b5635815177cd679ab4bcec9d7dda",
        .recipient_key = "321b26943253c7ffb6003b0b64d74041",
        .common_iv = "be35ae297d2dace910c52e99f9",
        .sender_nonce_piv0 = "bf35ae297d2dace810c52e99f9",
        .recipient_nonce_piv0 = "bf35ae297d2dace910c52e99f9",
    },
    .{
        .label = "C.3.1 Client (Key Derivation with ID Context)",
        .master_secret = "0102030405060708090a0b0c0d0e0f10",
        .master_salt = "9e7ca92223786340",
        .id_context = "37cbf3210017a2d3",
        .sender_id = "",
        .recipient_id = "01",
        .info_sender_key = "85404837cbf3210017a2d30a634b657910",
        .info_recipient_key = "8541014837cbf3210017a2d30a634b657910",
        .info_common_iv = "85404837cbf3210017a2d30a6249560d",
        .sender_key = "af2a1300a5e95788b356336eeecd2b92",
        .recipient_key = "e39a0c7c77b43f03b4b39ab9a268699f",
        .common_iv = "2ca58fb85ff1b81c0b7181b85e",
        .sender_nonce_piv0 = "2ca58fb85ff1b81c0b7181b85e",
        .recipient_nonce_piv0 = "2da58fb85ff1b81d0b7181b85e",
    },
    .{
        .label = "C.3.2 Server (Key Derivation with ID Context)",
        .master_secret = "0102030405060708090a0b0c0d0e0f10",
        .master_salt = "9e7ca92223786340",
        .id_context = "37cbf3210017a2d3",
        .sender_id = "01",
        .recipient_id = "",
        .info_sender_key = "8541014837cbf3210017a2d30a634b657910",
        .info_recipient_key = "85404837cbf3210017a2d30a634b657910",
        .info_common_iv = "85404837cbf3210017a2d30a6249560d",
        .sender_key = "e39a0c7c77b43f03b4b39ab9a268699f",
        .recipient_key = "af2a1300a5e95788b356336eeecd2b92",
        .common_iv = "2ca58fb85ff1b81c0b7181b85e",
        .sender_nonce_piv0 = "2da58fb85ff1b81d0b7181b85e",
        .recipient_nonce_piv0 = "2ca58fb85ff1b81c0b7181b85e",
    },
};

/// One Appendix C.4-C.8 protected-message test case.
pub const MessageVector = struct {
    label: []const u8,
    /// True for C.4-C.6 (requests, always replay-checked, §8.4); false
    /// for C.7-C.8 (responses, never replay-checked — even C.8, which
    /// carries its OWN fresh Partial IV in the option).
    is_request: bool,
    /// The plain (unprotected) CoAP message, RFC 7252 wire format.
    unprotected_message: []const u8, // hex
    common_iv: []const u8, // hex, 13 bytes
    /// The PROTECTING endpoint's own Sender ID (whose Sender Key
    /// encrypts this message).
    sender_id: []const u8, // hex
    sender_key: []const u8, // hex, 16 bytes
    sender_sequence_number: u64,
    /// `id_piv`/`partial_iv` fed to `computeNonce`'s §5.2 XOR
    /// construction for THIS message — for a response that reuses the
    /// request's nonce (C.7), this is the REQUEST's own sender_id/piv,
    /// not this message's protecting endpoint's.
    nonce_id: []const u8, // hex
    nonce_piv: u64,
    /// This message's OWN OSCORE-option Partial IV (§6.1) — `null` when
    /// the option omits it entirely (C.7's response).
    option_partial_iv: ?u64,
    /// This message's own OSCORE-option kid (§6.1) — `null` when absent
    /// (the `k` flag is 0); `""` (hex, zero-length but non-null) when
    /// present but zero-length.
    option_kid: ?[]const u8, // hex, or null if absent
    /// This message's own OSCORE-option kid context (§5.1/§6.1) — only
    /// C.6 sets one; `null` otherwise.
    option_kid_context: ?[]const u8, // hex, or null if absent
    /// §5.4's `request_kid`/`request_piv` — the ORIGINAL REQUEST's own
    /// kid/Partial IV, even for a response vector (C.7, C.8).
    request_kid: []const u8, // hex
    request_piv: []const u8, // hex
    aad_array: []const u8, // hex — encodeAadArray's expected output
    aad: []const u8, // hex — buildAad's expected output (full Enc_structure)
    plaintext: []const u8, // hex — RFC 8613 §5.3 plaintext
    nonce: []const u8, // hex, 13 bytes — computeNonce's expected output
    option_value: []const u8, // hex — OscoreOption.encode's expected output
    ciphertext: []const u8, // hex — protect's expected AEAD output (ciphertext || tag)
    protected_message: []const u8, // hex — the full OSCORE-protected CoAP message
};

pub const message_vectors = [_]MessageVector{
    .{
        .label = "C.4 OSCORE Request, Client (security context: C.1 Client)",
        .is_request = true,
        .unprotected_message = "44015d1f00003974396c6f63616c686f737483747631",
        .common_iv = "4622d4dd6d944168eefb54987c",
        .sender_id = "",
        .sender_key = "f0910ed7295e6ad4b54fc793154302ff",
        .sender_sequence_number = 20,
        .nonce_id = "",
        .nonce_piv = 20,
        .option_partial_iv = 20,
        .option_kid = "",
        .option_kid_context = null,
        .request_kid = "",
        .request_piv = "14",
        .aad_array = "8501810a40411440",
        .aad = "8368456e63727970743040488501810a40411440",
        .plaintext = "01b3747631",
        .nonce = "4622d4dd6d944168eefb549868",
        .option_value = "0914",
        .ciphertext = "612f1092f1776f1c1668b3825e",
        .protected_message = "44025d1f00003974396c6f63616c686f7374620914ff612f1092f1776f1c1668b3825e",
    },
    .{
        .label = "C.5 OSCORE Request, Client (security context: C.2 Client)",
        .is_request = true,
        .unprotected_message = "440171c30000b932396c6f63616c686f737483747631",
        .common_iv = "be35ae297d2dace910c52e99f9",
        .sender_id = "00",
        .sender_key = "321b26943253c7ffb6003b0b64d74041",
        .sender_sequence_number = 20,
        .nonce_id = "00",
        .nonce_piv = 20,
        .option_partial_iv = 20,
        .option_kid = "00",
        .option_kid_context = null,
        .request_kid = "00",
        .request_piv = "14",
        .aad_array = "8501810a4100411440",
        .aad = "8368456e63727970743040498501810a4100411440",
        .plaintext = "01b3747631",
        .nonce = "bf35ae297d2dace910c52e99ed",
        .option_value = "091400",
        .ciphertext = "4ed339a5a379b0b8bc731fffb0",
        .protected_message = "440271c30000b932396c6f63616c686f737463091400ff4ed339a5a379b0b8bc731fffb0",
    },
    .{
        .label = "C.6 OSCORE Request, Client (security context: C.3 Client, kid context present)",
        .is_request = true,
        .unprotected_message = "44012f8eef9bbf7a396c6f63616c686f737483747631",
        .common_iv = "2ca58fb85ff1b81c0b7181b85e",
        .sender_id = "",
        .sender_key = "af2a1300a5e95788b356336eeecd2b92",
        .sender_sequence_number = 20,
        .nonce_id = "",
        .nonce_piv = 20,
        .option_partial_iv = 20,
        .option_kid = "",
        .option_kid_context = "37cbf3210017a2d3",
        .request_kid = "",
        .request_piv = "14",
        .aad_array = "8501810a40411440",
        .aad = "8368456e63727970743040488501810a40411440",
        .plaintext = "01b3747631",
        .nonce = "2ca58fb85ff1b81c0b7181b84a",
        .option_value = "19140837cbf3210017a2d3",
        .ciphertext = "72cd7273fd331ac45cffbe55c3",
        .protected_message = "44022f8eef9bbf7a396c6f63616c686f73746b19140837cbf3210017a2d3ff72cd7273fd331ac45cffbe55c3",
    },
    .{
        .label = "C.7 OSCORE Response, Server (security context: C.1 Server; replies to C.4; nonce REUSED from request)",
        .is_request = false,
        .unprotected_message = "64455d1f00003974ff48656c6c6f20576f726c6421",
        .common_iv = "4622d4dd6d944168eefb54987c",
        .sender_id = "01",
        .sender_key = "ffb14e093c94c9cac9471648b4f98710",
        .sender_sequence_number = 0,
        // Nonce reused verbatim from the C.4 request: id_piv = the
        // CLIENT's Sender ID (empty), piv = the request's Partial IV
        // (20) — NOT this server's own Sender ID/sequence number.
        .nonce_id = "",
        .nonce_piv = 20,
        .option_partial_iv = null,
        .option_kid = null,
        .option_kid_context = null,
        .request_kid = "",
        .request_piv = "14",
        .aad_array = "8501810a40411440",
        .aad = "8368456e63727970743040488501810a40411440",
        .plaintext = "45ff48656c6c6f20576f726c6421",
        .nonce = "4622d4dd6d944168eefb549868",
        .option_value = "",
        .ciphertext = "dbaad1e9a7e7b2a813d3c31524378303cdafae119106",
        .protected_message = "64445d1f0000397490ffdbaad1e9a7e7b2a813d3c31524378303cdafae119106",
    },
    .{
        .label = "C.8 OSCORE Response with Partial IV, Server (security context: C.1 Server; replies to C.4; server mints its OWN fresh Partial IV)",
        .is_request = false,
        .unprotected_message = "64455d1f00003974ff48656c6c6f20576f726c6421",
        .common_iv = "4622d4dd6d944168eefb54987c",
        .sender_id = "01",
        .sender_key = "ffb14e093c94c9cac9471648b4f98710",
        .sender_sequence_number = 0,
        // This response mints its OWN fresh Partial IV (0), using ITS
        // OWN Sender ID (01) for the nonce — distinct from C.7's
        // reused-request-nonce case.
        .nonce_id = "01",
        .nonce_piv = 0,
        .option_partial_iv = 0,
        .option_kid = null,
        .option_kid_context = null,
        // AAD still cites the ORIGINAL C.4 REQUEST's kid/piv, regardless
        // of this response's own new Partial IV.
        .request_kid = "",
        .request_piv = "14",
        .aad_array = "8501810a40411440",
        .aad = "8368456e63727970743040488501810a40411440",
        .plaintext = "45ff48656c6c6f20576f726c6421",
        .nonce = "4722d4dd6d944169eefb54987c",
        .option_value = "0100",
        .ciphertext = "4d4c13669384b67354b2b6175ff4b8658c666a6cf88e",
        .protected_message = "64445d1f00003974920100ff4d4c13669384b67354b2b6175ff4b8658c666a6cf88e",
    },
};
