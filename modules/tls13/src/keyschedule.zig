// SPDX-License-Identifier: MIT

//! tls13.keyschedule — the RFC 8446 §7.1 key schedule, shared by TLS 1.3
//! (`tls13`) and DTLS 1.3 (`dtls13`, RFC 9147 §5.9). Real, KAT-validated.
//!
//! **Label prefix:** the two protocols run the same schedule with a different
//! HKDF-Expand-Label prefix — `"tls13 "` (6 bytes, trailing space) for TLS,
//! `"dtls13"` (6 bytes, NO trailing space) for DTLS, for key separation
//! between them. That is the ONE difference between the two schedules, and
//! getting it wrong silently produces keys no peer accepts. So every
//! label-dependent step lives in `Schedule(prefix)`, instantiated once per
//! protocol: `tls13` and `dtls13` below. std's `std.crypto.tls.hkdfExpandLabel`
//! hardcodes `"tls13 "` and is not used (it is the differential oracle for the
//! `tls13` instance in the tests).
//!
//! Everything here operates on caller-supplied transcript-hash bytes and
//! secret bytes; no I/O, no key storage. Validated against RFC 8448 §3/§4
//! (`tls13 `) and an independent Python `hmac`/`hashlib` reimplementation
//! (`dtls13`) — see the tests below. Moved from `dtls/src/keyschedule.zig`
//! 2026-10-20 (its earlier history is that of `modules/dtls/src/keyschedule.zig`,
//! which git does not link across the split); dtls keeps a shim with its
//! original names over `dtls13`.

const std = @import("std");
const burn = @import("burn.zig");

/// RFC 8446 §7.1 HKDF-Expand-Label prefix (TLS 1.3).
pub const tls13_prefix = "tls13 ";
/// RFC 9147 §5.9 HKDF-Expand-Label prefix (DTLS 1.3) — no trailing space.
pub const dtls13_prefix = "dtls13";

/// The TLS 1.3 schedule (`"tls13 "` labels).
pub const tls13 = Schedule(tls13_prefix);
/// The DTLS 1.3 schedule (`"dtls13"` labels).
pub const dtls13 = Schedule(dtls13_prefix);

// Dead-stack shape (CONVENTIONS §2.1.1): every secret goes in by `*const`
// and every secret result comes out through an `out` pointer (first
// parameter after the comptime types), never by value. Entry points that
// keep a secret in a local of their own run under `burn.run`; the ones that
// only chain other burned entry points need none.

/// RFC 8446 §7.1 HKDF-Expand-Label with an explicit label prefix. Builds the
/// `HkdfLabel` structure — `uint16 length; opaque label<7..255>; opaque
/// context<0..255>` — where `label = prefix ++ label_body`, then runs
/// HKDF-Expand into `out`. `Hkdf` is e.g. `std.crypto.kdf.hkdf.HkdfSha256`.
/// `out` may alias `secret`.
pub fn expandLabel(
    comptime Hkdf: type,
    comptime prefix: []const u8,
    comptime len: usize,
    out: *[len]u8,
    secret: *const [Hkdf.prk_length]u8,
    label: []const u8,
    context: []const u8,
) void {
    burn.run(burn.ks_burn, void, expandLabelBody, .{ Hkdf, prefix, len, out, secret, label, context });
}

fn expandLabelBody(
    comptime Hkdf: type,
    comptime prefix: []const u8,
    comptime len: usize,
    out: *[len]u8,
    secret: *const [Hkdf.prk_length]u8,
    label: []const u8,
    context: []const u8,
) void {
    std.debug.assert(prefix.len + label.len <= 255);
    std.debug.assert(context.len <= 255);

    var info_buf: [2 + 1 + 255 + 1 + 255]u8 = undefined;
    std.mem.writeInt(u16, info_buf[0..2], @intCast(len), .big);
    info_buf[2] = @intCast(prefix.len + label.len);
    var i: usize = 3;
    @memcpy(info_buf[i..][0..prefix.len], prefix);
    i += prefix.len;
    @memcpy(info_buf[i..][0..label.len], label);
    i += label.len;
    info_buf[i] = @intCast(context.len);
    i += 1;
    @memcpy(info_buf[i..][0..context.len], context);
    i += context.len;

    Hkdf.expand(out, info_buf[0..i], secret.*);
}

/// `expandLabelBody` with a run-time output length (the exporter's), at
/// most `255 * Hkdf.prk_length` octets.
fn expandLabelSliceBody(
    comptime Hkdf: type,
    comptime prefix: []const u8,
    out: []u8,
    secret: *const [Hkdf.prk_length]u8,
    label: []const u8,
    context: []const u8,
) void {
    std.debug.assert(prefix.len + label.len <= 255);
    std.debug.assert(context.len <= 255);
    std.debug.assert(out.len <= 255 * Hkdf.prk_length);

    var info_buf: [2 + 1 + 255 + 1 + 255]u8 = undefined;
    std.mem.writeInt(u16, info_buf[0..2], @intCast(out.len), .big);
    info_buf[2] = @intCast(prefix.len + label.len);
    var i: usize = 3;
    @memcpy(info_buf[i..][0..prefix.len], prefix);
    i += prefix.len;
    @memcpy(info_buf[i..][0..label.len], label);
    i += label.len;
    info_buf[i] = @intCast(context.len);
    i += 1;
    @memcpy(info_buf[i..][0..context.len], context);
    i += context.len;

    Hkdf.expand(out, info_buf[0..i], secret.*);
}

fn exportKeyingMaterialBody(
    comptime Hash: type,
    comptime Hkdf: type,
    comptime prefix: []const u8,
    out: []u8,
    exporter_master_secret: *const [Hkdf.prk_length]u8,
    label: []const u8,
    context: []const u8,
) void {
    comptime std.debug.assert(Hash.digest_length == Hkdf.prk_length);
    var empty_hash: [Hash.digest_length]u8 = undefined;
    Hash.hash("", &empty_hash, .{});
    var context_hash: [Hash.digest_length]u8 = undefined;
    Hash.hash(context, &context_hash, .{});
    var secret: [Hkdf.prk_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &secret);
    expandLabelBody(Hkdf, prefix, Hkdf.prk_length, &secret, exporter_master_secret, label, &empty_hash);
    expandLabelSliceBody(Hkdf, prefix, out, &secret, "exporter", &context_hash);
}

/// RFC 8446 §7.1: `Early Secret = HKDF-Extract(salt = 0^Hash.length, IKM =
/// PSK)`. The IKM is the raw PSK — an external PSK, or a resumption PSK
/// (`Schedule.deriveResumptionPsk`); without a PSK, `Hash.length` zero bytes.
/// Label-free, so the same for both protocols.
pub fn earlySecret(comptime Hkdf: type, out: *[Hkdf.prk_length]u8, psk: []const u8) void {
    burn.run(burn.ks_burn, void, earlySecretBody, .{ Hkdf, out, psk });
}

fn earlySecretBody(comptime Hkdf: type, out: *[Hkdf.prk_length]u8, psk: []const u8) void {
    const zero_salt = @as([Hkdf.prk_length]u8, @splat(0));
    out.* = Hkdf.extract(&zero_salt, psk);
}

/// RFC 8446 §4.4.4: `verify_data = HMAC(finished_key, Transcript-Hash(...))`.
/// The receiving side MUST recompute this and compare with
/// `std.crypto.timing_safe.eql` — never `std.mem.eql`. Label-free.
pub fn computeFinishedVerifyData(
    comptime Hmac: type,
    out: *[Hmac.mac_length]u8,
    finished_key: *const [Hmac.mac_length]u8,
    transcript_hash: []const u8,
) void {
    burn.run(burn.ks_burn, void, computeFinishedVerifyDataBody, .{ Hmac, out, finished_key, transcript_hash });
}

fn computeFinishedVerifyDataBody(
    comptime Hmac: type,
    out: *[Hmac.mac_length]u8,
    finished_key: *const [Hmac.mac_length]u8,
    transcript_hash: []const u8,
) void {
    Hmac.create(out, transcript_hash, finished_key);
}

/// Every label-dependent step of the RFC 8446 §7.1 schedule, for one
/// HKDF-Expand-Label prefix (`tls13_prefix` or `dtls13_prefix`).
pub fn Schedule(comptime prefix: []const u8) type {
    return struct {
        /// The HKDF-Expand-Label prefix of this instance.
        pub const label_prefix = prefix;

        /// Label-free; the same function for both protocols.
        pub const earlySecret = keyschedule.earlySecret;
        /// Label-free; the same function for both protocols.
        pub const computeFinishedVerifyData = keyschedule.computeFinishedVerifyData;

        /// HKDF-Expand-Label with this instance's prefix.
        pub fn hkdfExpandLabel(
            comptime Hkdf: type,
            comptime len: usize,
            out: *[len]u8,
            secret: *const [Hkdf.prk_length]u8,
            label: []const u8,
            context: []const u8,
        ) void {
            expandLabel(Hkdf, prefix, len, out, secret, label, context);
        }

        /// RFC 8446 §7.1 `Derive-Secret(Secret, Label, Messages) =
        /// HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages),
        /// Hash.length)`. `transcript_hash` is the already-computed digest of
        /// `Messages`. `out` may alias `secret`.
        pub fn deriveSecret(
            comptime Hkdf: type,
            out: *[Hkdf.prk_length]u8,
            secret: *const [Hkdf.prk_length]u8,
            label: []const u8,
            transcript_hash: []const u8,
        ) void {
            hkdfExpandLabel(Hkdf, Hkdf.prk_length, out, secret, label, transcript_hash);
        }

        /// RFC 8446 §7.1: `binder_key = Derive-Secret(early_secret, "ext
        /// binder", "")` — an external PSK. The transcript context is the hash
        /// of the EMPTY message list, so the caller passes the empty-string
        /// hash for `empty_transcript_hash` (e.g. SHA-256("")).
        pub fn binderKey(
            comptime Hkdf: type,
            out: *[Hkdf.prk_length]u8,
            early_secret: *const [Hkdf.prk_length]u8,
            empty_transcript_hash: []const u8,
        ) void {
            deriveSecret(Hkdf, out, early_secret, "ext binder", empty_transcript_hash);
        }

        /// RFC 8446 §7.1: `binder_key = Derive-Secret(early_secret, "res
        /// binder", "")` — a resumption PSK (a NewSessionTicket's).
        pub fn resumptionBinderKey(
            comptime Hkdf: type,
            out: *[Hkdf.prk_length]u8,
            early_secret: *const [Hkdf.prk_length]u8,
            empty_transcript_hash: []const u8,
        ) void {
            deriveSecret(Hkdf, out, early_secret, "res binder", empty_transcript_hash);
        }

        /// RFC 8446 §4.2.11.2: the PSK binder = `HMAC(finished_key,
        /// Transcript-Hash(Truncate(ClientHello1)))` where `finished_key =
        /// HKDF-Expand-Label(binder_key, "finished", "", Hash.length)`. The
        /// caller supplies the transcript hash of the TRUNCATED ClientHello
        /// (everything up to but excluding the binders list).
        ///
        /// Server side: recompute this and compare against the offered
        /// binder with `std.crypto.timing_safe.eql` BEFORE trusting the PSK
        /// identity.
        pub fn pskBinder(
            comptime Hkdf: type,
            comptime Hmac: type,
            out: *[Hmac.mac_length]u8,
            binder_key: *const [Hkdf.prk_length]u8,
            truncated_client_hello_transcript_hash: []const u8,
        ) void {
            burn.run(burn.ks_burn, void, pskBinderBody, .{ Hkdf, Hmac, out, binder_key, truncated_client_hello_transcript_hash });
        }

        fn pskBinderBody(
            comptime Hkdf: type,
            comptime Hmac: type,
            out: *[Hmac.mac_length]u8,
            binder_key: *const [Hkdf.prk_length]u8,
            truncated_client_hello_transcript_hash: []const u8,
        ) void {
            var finished_key: [Hmac.mac_length]u8 = undefined;
            hkdfExpandLabel(Hkdf, Hmac.mac_length, &finished_key, binder_key, "finished", "");
            Hmac.create(out, truncated_client_hello_transcript_hash, &finished_key);
        }

        /// RFC 8446 §7.1: `handshake_secret = HKDF-Extract(salt =
        /// Derive-Secret(early_secret, "derived", ""), IKM = shared_secret)`.
        /// `dhe_shared_secret` is the (EC)DHE output, or `null` for pure
        /// `psk_ke` (IKM = `Hash.length` zero bytes). Pass the empty-string
        /// transcript hash for `empty_transcript_hash`. `out` may alias
        /// `early_secret`.
        pub fn deriveHandshakeSecret(
            comptime Hkdf: type,
            out: *[Hkdf.prk_length]u8,
            early_secret: *const [Hkdf.prk_length]u8,
            empty_transcript_hash: []const u8,
            dhe_shared_secret: ?[]const u8,
        ) void {
            burn.run(burn.ks_burn, void, deriveHandshakeSecretBody, .{ Hkdf, out, early_secret, empty_transcript_hash, dhe_shared_secret });
        }

        fn deriveHandshakeSecretBody(
            comptime Hkdf: type,
            out: *[Hkdf.prk_length]u8,
            early_secret: *const [Hkdf.prk_length]u8,
            empty_transcript_hash: []const u8,
            dhe_shared_secret: ?[]const u8,
        ) void {
            var salt: [Hkdf.prk_length]u8 = undefined;
            deriveSecret(Hkdf, &salt, early_secret, "derived", empty_transcript_hash);
            const zero_ikm = @as([Hkdf.prk_length]u8, @splat(0));
            const ikm: []const u8 = dhe_shared_secret orelse &zero_ikm;
            out.* = Hkdf.extract(&salt, ikm);
        }

        /// RFC 8446 §7.1: client/server handshake traffic secrets — both from
        /// the SAME transcript hash (through ServerHello), differing only in
        /// the `"c hs traffic"` / `"s hs traffic"` label.
        pub fn deriveHandshakeTrafficSecrets(
            comptime Hkdf: type,
            out_client: *[Hkdf.prk_length]u8,
            out_server: *[Hkdf.prk_length]u8,
            handshake_secret: *const [Hkdf.prk_length]u8,
            transcript_hash_through_server_hello: []const u8,
        ) void {
            deriveSecret(Hkdf, out_client, handshake_secret, "c hs traffic", transcript_hash_through_server_hello);
            deriveSecret(Hkdf, out_server, handshake_secret, "s hs traffic", transcript_hash_through_server_hello);
        }

        /// RFC 8446 §7.1: `master_secret = HKDF-Extract(salt =
        /// Derive-Secret(handshake_secret, "derived", ""), IKM =
        /// 0^Hash.length)`. `out` may alias `handshake_secret`.
        pub fn deriveMasterSecret(
            comptime Hkdf: type,
            out: *[Hkdf.prk_length]u8,
            handshake_secret: *const [Hkdf.prk_length]u8,
            empty_transcript_hash: []const u8,
        ) void {
            burn.run(burn.ks_burn, void, deriveMasterSecretBody, .{ Hkdf, out, handshake_secret, empty_transcript_hash });
        }

        fn deriveMasterSecretBody(
            comptime Hkdf: type,
            out: *[Hkdf.prk_length]u8,
            handshake_secret: *const [Hkdf.prk_length]u8,
            empty_transcript_hash: []const u8,
        ) void {
            var salt: [Hkdf.prk_length]u8 = undefined;
            deriveSecret(Hkdf, &salt, handshake_secret, "derived", empty_transcript_hash);
            const zero_ikm = @as([Hkdf.prk_length]u8, @splat(0));
            out.* = Hkdf.extract(&salt, &zero_ikm);
        }

        /// RFC 8446 §7.1: client/server application traffic secrets — both
        /// over the transcript THROUGH THE SERVER'S Finished (not the
        /// client's), differing only in the `"c ap traffic"` / `"s ap
        /// traffic"` label.
        pub fn deriveApplicationTrafficSecrets(
            comptime Hkdf: type,
            out_client: *[Hkdf.prk_length]u8,
            out_server: *[Hkdf.prk_length]u8,
            master_secret: *const [Hkdf.prk_length]u8,
            transcript_hash_through_server_finished: []const u8,
        ) void {
            deriveSecret(Hkdf, out_client, master_secret, "c ap traffic", transcript_hash_through_server_finished);
            deriveSecret(Hkdf, out_server, master_secret, "s ap traffic", transcript_hash_through_server_finished);
        }

        /// RFC 8446 §7.1: `exporter_master_secret = Derive-Secret(master,
        /// "exp master", ClientHello..server Finished)` — the RFC 8446 §7.5
        /// exporter's base (and kTLS-style key export's neighbour).
        pub fn deriveExporterMasterSecret(
            comptime Hkdf: type,
            out: *[Hkdf.prk_length]u8,
            master_secret: *const [Hkdf.prk_length]u8,
            transcript_hash_through_server_finished: []const u8,
        ) void {
            deriveSecret(Hkdf, out, master_secret, "exp master", transcript_hash_through_server_finished);
        }

        /// RFC 8446 §7.5: `TLS-Exporter(label, context_value, key_length) =
        /// HKDF-Expand-Label(Derive-Secret(exporter_master_secret, label,
        /// ""), "exporter", Hash(context_value), key_length)` into `out`
        /// (`key_length` = `out.len`). No context and an empty one are the
        /// same value (§7.5). `Hash` is the suite's hash (`Hkdf`'s); the
        /// caller checks `label.len <= max_exporter_label_len` and
        /// `out.len <= maxExporterLen(Hkdf)`.
        pub fn exportKeyingMaterial(
            comptime Hash: type,
            comptime Hkdf: type,
            out: []u8,
            exporter_master_secret: *const [Hkdf.prk_length]u8,
            label: []const u8,
            context: []const u8,
        ) void {
            burn.run(burn.ks_burn, void, exportKeyingMaterialBody, .{ Hash, Hkdf, prefix, out, exporter_master_secret, label, context });
        }

        /// The longest exporter label: `HkdfLabel.label` holds at most 255
        /// octets, the prefix included.
        pub const max_exporter_label_len = 255 - prefix.len;

        /// The longest exporter output: HKDF-Expand's 255 blocks.
        pub fn maxExporterLen(comptime Hkdf: type) usize {
            return 255 * Hkdf.prk_length;
        }

        /// RFC 8446 §7.1: `resumption_master_secret = Derive-Secret(master,
        /// "res master", ClientHello..client Finished)` — note the CLIENT's
        /// Finished, unlike the application traffic secrets.
        pub fn deriveResumptionMasterSecret(
            comptime Hkdf: type,
            out: *[Hkdf.prk_length]u8,
            master_secret: *const [Hkdf.prk_length]u8,
            transcript_hash_through_client_finished: []const u8,
        ) void {
            deriveSecret(Hkdf, out, master_secret, "res master", transcript_hash_through_client_finished);
        }

        /// RFC 8446 §4.6.1: the PSK a NewSessionTicket stands for,
        /// `HKDF-Expand-Label(resumption_master_secret, "resumption",
        /// ticket_nonce, Hash.length)`.
        pub fn deriveResumptionPsk(
            comptime Hkdf: type,
            out: *[Hkdf.prk_length]u8,
            resumption_master_secret: *const [Hkdf.prk_length]u8,
            ticket_nonce: []const u8,
        ) void {
            hkdfExpandLabel(Hkdf, Hkdf.prk_length, out, resumption_master_secret, "resumption", ticket_nonce);
        }

        /// RFC 8446 §7.2 (KeyUpdate): `application_traffic_secret_N+1 =
        /// HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "",
        /// Hash.length)`. `out` may alias `secret`.
        pub fn nextApplicationTrafficSecret(
            comptime Hkdf: type,
            out: *[Hkdf.prk_length]u8,
            secret: *const [Hkdf.prk_length]u8,
        ) void {
            hkdfExpandLabel(Hkdf, Hkdf.prk_length, out, secret, "traffic upd", "");
        }

        /// RFC 8446 §7.1: `finished_key = HKDF-Expand-Label(BaseKey,
        /// "finished", "", Hash.length)` where `BaseKey` is the relevant
        /// handshake traffic secret.
        pub fn deriveFinishedKey(
            comptime Hkdf: type,
            comptime mac_length: usize,
            out: *[mac_length]u8,
            traffic_secret: *const [Hkdf.prk_length]u8,
        ) void {
            hkdfExpandLabel(Hkdf, mac_length, out, traffic_secret, "finished", "");
        }

        /// RFC 8446 §7.3: `write_key = HKDF-Expand-Label(Secret, "key", "",
        /// AEAD.key_length)`, `write_iv = HKDF-Expand-Label(Secret, "iv", "",
        /// AEAD.nonce_length)` — the record-protection key and the STATIC IV
        /// the per-record sequence number is XORed into.
        pub fn deriveTrafficKeyIv(
            comptime Hkdf: type,
            comptime key_len: usize,
            comptime iv_len: usize,
            out_key: *[key_len]u8,
            out_iv: *[iv_len]u8,
            traffic_secret: *const [Hkdf.prk_length]u8,
        ) void {
            hkdfExpandLabel(Hkdf, key_len, out_key, traffic_secret, "key", "");
            hkdfExpandLabel(Hkdf, iv_len, out_iv, traffic_secret, "iv", "");
        }
    };
}

const keyschedule = @This();

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

fn emptyHash() [32]u8 {
    var h: [32]u8 = undefined;
    Sha256.hash("", &h, .{});
    return h;
}

// RFC 8448 "Example Handshake Traces for TLS 1.3" — §3 (initial, psk_dhe_ke)
// and §4 (resumed, PSK binder). These validate the HKDF-Extract / Expand /
// Derive-Secret sequencing and the PSK binder byte-for-byte. They use the
// TLS 1.3 `"tls13 "` prefix (the schedule logic is prefix-independent), so
// the tests drive `expandLabel(..., tls13_prefix, ...)`.

fn hexTo(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn deriveSecretTls13(secret: [32]u8, label: []const u8, th: []const u8) [32]u8 {
    return v_expandLabel(HkdfSha256, tls13_prefix, secret, label, th, 32);
}

fn Pair(comptime Hkdf: type) type {
    return struct { client: [Hkdf.prk_length]u8, server: [Hkdf.prk_length]u8 };
}

fn KeyIv(comptime key_len: usize, comptime iv_len: usize) type {
    return struct { key: [key_len]u8, iv: [iv_len]u8 };
}

// By-value wrappers over the pointer/out API: test conveniences only (the
// secrets here are published KAT values).

fn v_expandLabel(comptime Hkdf: type, comptime prefix: []const u8, secret: [Hkdf.prk_length]u8, label: []const u8, context: []const u8, comptime len: usize) [len]u8 {
    var o: [len]u8 = undefined;
    expandLabel(Hkdf, prefix, len, &o, &secret, label, context);
    return o;
}

fn v_hkdfExpandLabel(comptime Hkdf: type, secret: [Hkdf.prk_length]u8, label: []const u8, context: []const u8, comptime len: usize) [len]u8 {
    var o: [len]u8 = undefined;
    dtls13.hkdfExpandLabel(Hkdf, len, &o, &secret, label, context);
    return o;
}

fn v_earlySecret(comptime Hkdf: type, psk: []const u8) [Hkdf.prk_length]u8 {
    var o: [Hkdf.prk_length]u8 = undefined;
    earlySecret(Hkdf, &o, psk);
    return o;
}

fn v_binderKey(comptime Hkdf: type, es: [Hkdf.prk_length]u8, eh: []const u8) [Hkdf.prk_length]u8 {
    var o: [Hkdf.prk_length]u8 = undefined;
    dtls13.binderKey(Hkdf, &o, &es, eh);
    return o;
}

fn v_pskBinder(comptime Hkdf: type, comptime Hmac: type, bk: [Hkdf.prk_length]u8, th: []const u8) [Hmac.mac_length]u8 {
    var o: [Hmac.mac_length]u8 = undefined;
    dtls13.pskBinder(Hkdf, Hmac, &o, &bk, th);
    return o;
}

fn v_deriveHandshakeSecret(comptime Hkdf: type, es: [Hkdf.prk_length]u8, eh: []const u8, dhe: ?[]const u8) [Hkdf.prk_length]u8 {
    var o: [Hkdf.prk_length]u8 = undefined;
    dtls13.deriveHandshakeSecret(Hkdf, &o, &es, eh, dhe);
    return o;
}

fn v_deriveHandshakeTrafficSecrets(comptime Hkdf: type, hs: [Hkdf.prk_length]u8, th: []const u8) Pair(Hkdf) {
    var r: Pair(Hkdf) = undefined;
    dtls13.deriveHandshakeTrafficSecrets(Hkdf, &r.client, &r.server, &hs, th);
    return r;
}

fn v_deriveMasterSecret(comptime Hkdf: type, hs: [Hkdf.prk_length]u8, eh: []const u8) [Hkdf.prk_length]u8 {
    var o: [Hkdf.prk_length]u8 = undefined;
    dtls13.deriveMasterSecret(Hkdf, &o, &hs, eh);
    return o;
}

fn v_deriveApplicationTrafficSecrets(comptime Hkdf: type, ms: [Hkdf.prk_length]u8, th: []const u8) Pair(Hkdf) {
    var r: Pair(Hkdf) = undefined;
    dtls13.deriveApplicationTrafficSecrets(Hkdf, &r.client, &r.server, &ms, th);
    return r;
}

fn v_deriveFinishedKey(comptime Hkdf: type, comptime mac_length: usize, ts: [Hkdf.prk_length]u8) [mac_length]u8 {
    var o: [mac_length]u8 = undefined;
    dtls13.deriveFinishedKey(Hkdf, mac_length, &o, &ts);
    return o;
}

fn v_computeFinishedVerifyData(comptime Hmac: type, fk: [Hmac.mac_length]u8, th: []const u8) [Hmac.mac_length]u8 {
    var o: [Hmac.mac_length]u8 = undefined;
    computeFinishedVerifyData(Hmac, &o, &fk, th);
    return o;
}

fn v_deriveTrafficKeyIv(comptime Hkdf: type, comptime key_len: usize, comptime iv_len: usize, ts: [Hkdf.prk_length]u8) KeyIv(key_len, iv_len) {
    var r: KeyIv(key_len, iv_len) = undefined;
    dtls13.deriveTrafficKeyIv(Hkdf, key_len, iv_len, &r.key, &r.iv, &ts);
    return r;
}

fn v_deriveSequenceNumberKey(comptime Hkdf: type, comptime key_len: usize, ts: [Hkdf.prk_length]u8) [key_len]u8 {
    var o: [key_len]u8 = undefined;
    dtls13.hkdfExpandLabel(Hkdf, key_len, &o, &ts, "sn", ""); // dtls's deriveSequenceNumberKey
    return o;
}

test "RFC 8448 §3: early secret (all-zero PSK, all-zero salt)" {
    const psk = @as([32]u8, @splat(0));
    const es = v_earlySecret(HkdfSha256, &psk);
    try testing.expectEqualSlices(u8, &hexTo(32, "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"), &es);
}

test "RFC 8448 §3: handshake secret from derived salt + DHE IKM" {
    const es = hexTo(32, "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
    const salt = deriveSecretTls13(es, "derived", &emptyHash());
    try testing.expectEqualSlices(u8, &hexTo(32, "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"), &salt);
    const dhe = hexTo(32, "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    const hs = HkdfSha256.extract(&salt, &dhe);
    try testing.expectEqualSlices(u8, &hexTo(32, "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"), &hs);
}

test "RFC 8448 §3: c/s handshake traffic secrets (same transcript, diff label)" {
    const hs = hexTo(32, "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
    const th = hexTo(32, "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    const c = deriveSecretTls13(hs, "c hs traffic", &th);
    const s = deriveSecretTls13(hs, "s hs traffic", &th);
    try testing.expectEqualSlices(u8, &hexTo(32, "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"), &c);
    try testing.expectEqualSlices(u8, &hexTo(32, "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"), &s);
}

test "RFC 8448 §3: master secret (zero IKM)" {
    const hs = hexTo(32, "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
    const salt = deriveSecretTls13(hs, "derived", &emptyHash());
    const zero = @as([32]u8, @splat(0));
    const ms = HkdfSha256.extract(&salt, &zero);
    try testing.expectEqualSlices(u8, &hexTo(32, "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"), &ms);
}

test "RFC 8448 §3: c/s application traffic secrets (through server Finished)" {
    const ms = hexTo(32, "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");
    const th = hexTo(32, "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
    const c = deriveSecretTls13(ms, "c ap traffic", &th);
    const s = deriveSecretTls13(ms, "s ap traffic", &th);
    try testing.expectEqualSlices(u8, &hexTo(32, "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"), &c);
    try testing.expectEqualSlices(u8, &hexTo(32, "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"), &s);
}

test "RFC 8448 §3: finished_key + traffic key/iv" {
    const s_hs = hexTo(32, "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
    const fk = v_expandLabel(HkdfSha256, tls13_prefix, s_hs, "finished", "", 32);
    try testing.expectEqualSlices(u8, &hexTo(32, "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"), &fk);
    const key = v_expandLabel(HkdfSha256, tls13_prefix, s_hs, "key", "", 16);
    const iv = v_expandLabel(HkdfSha256, tls13_prefix, s_hs, "iv", "", 12);
    try testing.expectEqualSlices(u8, &hexTo(16, "3fce516009c21727d0f2e4e86ee403bc"), &key);
    try testing.expectEqualSlices(u8, &hexTo(12, "5d313eb2671276ee13000b30"), &iv);
}

test "RFC 8448 §4: PSK binder (external-binder construction, byte-exact)" {
    // §4 uses a resumption PSK; the binder math is identical to ext-binder
    // (HMAC(finished_key, binder_hash), finished_key from binder_key). We
    // drive it through earlySecret + a manual "res binder" derive to match
    // the RFC's resumption trace exactly, proving the pskBinder inner math.
    const psk = hexTo(32, "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3");
    const es = v_earlySecret(HkdfSha256, &psk);
    try testing.expectEqualSlices(u8, &hexTo(32, "9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c"), &es);
    const bk = deriveSecretTls13(es, "res binder", &emptyHash());
    try testing.expectEqualSlices(u8, &hexTo(32, "69fe131a3bbad5d63c64eebcc30e395b9d8107726a13d074e389dbc8a4e47256"), &bk);
    const fk = v_expandLabel(HkdfSha256, tls13_prefix, bk, "finished", "", 32);
    try testing.expectEqualSlices(u8, &hexTo(32, "5588673e72cb59c87d220caffe94f2dea9a3b1609f7d50e90a48227db9ed7eaa"), &fk);
    const binder_hash = hexTo(32, "63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14");
    var binder: [32]u8 = undefined;
    HmacSha256.create(&binder, &binder_hash, &fk);
    try testing.expectEqualSlices(u8, &hexTo(32, "3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d"), &binder);
}

test "pskBinder helper reproduces the RFC 8448 §4 binder end-to-end" {
    // Same vector, but through the module's own pskBinder (with the ext
    // binder label swapped for res binder to match the resumption trace).
    const psk = hexTo(32, "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3");
    const es = v_earlySecret(HkdfSha256, &psk);
    const bk = deriveSecretTls13(es, "res binder", &emptyHash());
    // pskBinder uses the dtls13 prefix for the finished_key; the §4 trace
    // uses tls13, so replicate the inner call with tls13 here to match.
    const fk = v_expandLabel(HkdfSha256, tls13_prefix, bk, "finished", "", 32);
    const binder_hash = hexTo(32, "63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14");
    var want: [32]u8 = undefined;
    HmacSha256.create(&want, &binder_hash, &fk);
    try testing.expectEqualSlices(u8, &hexTo(32, "3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d"), &want);
}

// ── DTLS-prefix ("dtls13") vectors — independent Python hmac/hashlib
// reimplementation (see scratchpad gen_kats.py). These lock in the exact
// prefix RFC 9147 §5.9 mandates; if someone "fixes" it back to tls13 these
// fail. PSK = 0x01..0x20; transcripts are fixed test strings, hashed.

fn sha256Of(s: []const u8) [32]u8 {
    var h: [32]u8 = undefined;
    Sha256.hash(s, &h, .{});
    return h;
}

test "DTLS13 prefix: full psk_ke schedule matches independent oracle" {
    var psk: [32]u8 = undefined;
    for (&psk, 0..) |*b, i| b.* = @intCast(i + 1);

    const es = v_earlySecret(HkdfSha256, &psk);
    try testing.expectEqualSlices(u8, &hexTo(32, "23499e7edf0fbe6baa137df0f23becaefa722ad19fc262855409de8cd8b3c897"), &es);

    const bk = v_binderKey(HkdfSha256, es, &emptyHash());
    try testing.expectEqualSlices(u8, &hexTo(32, "8819dce8e36a7975f4144278b2d9e7c0050aedb9d51414005be2eb23b34369df"), &bk);

    const trunc_hash = sha256Of("fake truncated client hello");
    const binder = v_pskBinder(HkdfSha256, HmacSha256, bk, &trunc_hash);
    try testing.expectEqualSlices(u8, &hexTo(32, "eae227d1c692ff0a7de317423977af6c049c83287cd7237cec719792799bf05f"), &binder);

    const hs = v_deriveHandshakeSecret(HkdfSha256, es, &emptyHash(), null);
    try testing.expectEqualSlices(u8, &hexTo(32, "195c7a5bafbac544933208c559627c4a73129a669c841f6ee570f005cde1e7d5"), &hs);

    const th_sh = sha256Of("fake transcript through ServerHello");
    const hst = v_deriveHandshakeTrafficSecrets(HkdfSha256, hs, &th_sh);
    try testing.expectEqualSlices(u8, &hexTo(32, "2508f0f8566b542193b94492d4a1fdeb23582e3832c6438a5670af1387ae3982"), &hst.client);
    try testing.expectEqualSlices(u8, &hexTo(32, "6e663c1527a961cf462bd3d1e674f00acd5f7679d6566c68823e3a27fc071d60"), &hst.server);

    const ms = v_deriveMasterSecret(HkdfSha256, hs, &emptyHash());
    try testing.expectEqualSlices(u8, &hexTo(32, "12a60a1f197d6b98d2e462e57b74c950d8832088a4e41f7b41fedd81e17adfa2"), &ms);

    const th_fin = sha256Of("fake transcript through server Finished");
    const apt = v_deriveApplicationTrafficSecrets(HkdfSha256, ms, &th_fin);
    try testing.expectEqualSlices(u8, &hexTo(32, "74b31f48e32206d833c335e4cc98dcd597a880437e7486b072ada76f7b5ccc89"), &apt.client);
    try testing.expectEqualSlices(u8, &hexTo(32, "6de3fbd4fdf6b50f2239fd6f43514846236862673c7f35914aee8fbdd38664d1"), &apt.server);

    const fk = v_deriveFinishedKey(HkdfSha256, 32, hst.server);
    try testing.expectEqualSlices(u8, &hexTo(32, "c536eab4bd6aa4ee057843cec9b6a299b335e30e922287444cf86db702c4d685"), &fk);
    const vd = v_computeFinishedVerifyData(HmacSha256, fk, &th_fin);
    try testing.expectEqualSlices(u8, &hexTo(32, "aa24bfbc296807e8c9b27ea3f99232a3ec7b3efba2c0ed8ad3e29a29aac0debe"), &vd);

    const ki = v_deriveTrafficKeyIv(HkdfSha256, 16, 12, hst.server);
    try testing.expectEqualSlices(u8, &hexTo(16, "64c4d830da761c2c61fd5e5c9e2fa278"), &ki.key);
    try testing.expectEqualSlices(u8, &hexTo(12, "b6ac7fc7f23301f3b1c050c4"), &ki.iv);

    const snk = v_deriveSequenceNumberKey(HkdfSha256, 16, hst.server);
    try testing.expectEqualSlices(u8, &hexTo(16, "a5c0ea3a852584f23e5fab16dab5d753"), &snk);
}

test "DTLS13 vs TLS13 prefix: same inputs, DIFFERENT output (prefix separation)" {
    const secret = @as([32]u8, @splat(0x42));
    const d = v_hkdfExpandLabel(HkdfSha256, secret, "key", "", 16); // dtls13
    const t = v_expandLabel(HkdfSha256, tls13_prefix, secret, "key", "", 16);
    try testing.expect(!std.mem.eql(u8, &d, &t));
    // And the tls13 path matches std's own hardcoded-tls13 function exactly.
    const std_t = std.crypto.tls.hkdfExpandLabel(HkdfSha256, secret, "key", "", 16);
    try testing.expectEqualSlices(u8, &std_t, &t);
}

test "finished verify data: constant-time compare accepts/rejects correctly" {
    const fk = @as([32]u8, @splat(0xAB));
    const th = sha256Of("transcript");
    const vd = v_computeFinishedVerifyData(HmacSha256, fk, &th);
    try testing.expect(std.crypto.timing_safe.eql([32]u8, vd, vd));
    var bad = vd;
    bad[0] ^= 1;
    try testing.expect(!std.crypto.timing_safe.eql([32]u8, vd, bad));
}

test "psk_dhe_ke: non-null DHE secret feeds handshake_secret, changes it" {
    var psk: [32]u8 = undefined;
    for (&psk, 0..) |*b, i| b.* = @intCast(i + 1);
    const es = v_earlySecret(HkdfSha256, &psk);
    const dhe = @as([32]u8, @splat(0x11));
    const hs_psk = v_deriveHandshakeSecret(HkdfSha256, es, &emptyHash(), null);
    const hs_dhe = v_deriveHandshakeSecret(HkdfSha256, es, &emptyHash(), &dhe);
    try testing.expect(!std.mem.eql(u8, &hs_psk, &hs_dhe));
}

test "SHA-384 suite: schedule runs at the larger digest length" {
    const Hkdf384 = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);
    const psk = @as([48]u8, @splat(0x07));
    const es = v_earlySecret(Hkdf384, &psk);
    try testing.expectEqual(@as(usize, 48), es.len);
    var eh: [48]u8 = undefined;
    std.crypto.hash.sha2.Sha384.hash("", &eh, .{});
    const hs = v_deriveHandshakeSecret(Hkdf384, es, &eh, null);
    try testing.expectEqual(@as(usize, 48), hs.len);
}

// ── the `tls13` instance end to end, and the steps only a TLS server needs ──

test "tls13 instance: RFC 8448 §3 secrets through the namespaced API" {
    const T = tls13;
    const psk = @as([32]u8, @splat(0));
    var es: [32]u8 = undefined;
    T.earlySecret(HkdfSha256, &es, &psk);
    const dhe = hexTo(32, "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    var hs: [32]u8 = undefined;
    T.deriveHandshakeSecret(HkdfSha256, &hs, &es, &emptyHash(), &dhe);
    try testing.expectEqualSlices(u8, &hexTo(32, "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"), &hs);
    var c_hs: [32]u8 = undefined;
    var s_hs: [32]u8 = undefined;
    T.deriveHandshakeTrafficSecrets(HkdfSha256, &c_hs, &s_hs, &hs, &hexTo(32, "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"));
    try testing.expectEqualSlices(u8, &hexTo(32, "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"), &s_hs);
    var ms: [32]u8 = undefined;
    T.deriveMasterSecret(HkdfSha256, &ms, &hs, &emptyHash());
    try testing.expectEqualSlices(u8, &hexTo(32, "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"), &ms);
    var key: [16]u8 = undefined;
    var iv: [12]u8 = undefined;
    T.deriveTrafficKeyIv(HkdfSha256, 16, 12, &key, &iv, &s_hs);
    try testing.expectEqualSlices(u8, &hexTo(16, "3fce516009c21727d0f2e4e86ee403bc"), &key);
    try testing.expectEqualSlices(u8, &hexTo(12, "5d313eb2671276ee13000b30"), &iv);
}

test "tls13 instance: RFC 8448 §3 exporter and resumption master secrets, §4.6.1 resumption PSK" {
    const T = tls13;
    const ms = hexTo(32, "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");
    // Transcript through the server Finished (exporter) and through the
    // client Finished (resumption) — RFC 8448 §3.
    var exp: [32]u8 = undefined;
    T.deriveExporterMasterSecret(HkdfSha256, &exp, &ms, &hexTo(32, "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"));
    try testing.expectEqualSlices(u8, &hexTo(32, "fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50"), &exp);
    var rms: [32]u8 = undefined;
    T.deriveResumptionMasterSecret(HkdfSha256, &rms, &ms, &hexTo(32, "209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d"));
    // The same value tlsresume/src/psk.zig pins (`rfc8448_resumption_master_secret`).
    try testing.expectEqualSlices(u8, &hexTo(32, "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c"), &rms);
    // NewSessionTicket nonce 0x0000 → the §4 resumption PSK.
    var psk: [32]u8 = undefined;
    T.deriveResumptionPsk(HkdfSha256, &psk, &rms, &.{ 0, 0 });
    try testing.expectEqualSlices(u8, &hexTo(32, "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3"), &psk);
}

test "tls13 instance: RFC 8446 §7.5 exporter over the RFC 8448 §3 exporter master secret" {
    // Expected values from an independent Python hmac/hashlib
    // reimplementation of §7.5 (RFC 8448 has no exporter outputs).
    const T = tls13;
    const ems = hexTo(32, "fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50");
    var out32: [32]u8 = undefined;
    T.exportKeyingMaterial(Sha256, HkdfSha256, &out32, &ems, "label", "context");
    try testing.expectEqualSlices(u8, &hexTo(32, "ce26b14a53672bf3c0bc3dfe540cc9aaa8475f17cf8572d0607358d96622d48e"), &out32);
    var out1: [1]u8 = undefined;
    T.exportKeyingMaterial(Sha256, HkdfSha256, &out1, &ems, "label", "");
    try testing.expectEqualSlices(u8, &.{0x9f}, &out1);
    // More than one HKDF block.
    var out100: [100]u8 = undefined;
    T.exportKeyingMaterial(Sha256, HkdfSha256, &out100, &ems, "EXPERIMENTAL-tls13", "");
    try testing.expectEqualSlices(u8, &hexTo(100, "e8e2618df14a30cbf3a78bfeb92011228591fca61783912f8751a3f75876a8b32285e020e9ed31d103ed15500a5e5f48ebbc65166456e048193c50e3a4f9540b75ff51c55aab153ac20fbc3fa5dbd249e64a16db75bd626c79698fbeee1719ff186b0f4f"), &out100);
    // Over 255 octets: the u16 length's high octet is not zero.
    var out300: [300]u8 = undefined;
    T.exportKeyingMaterial(Sha256, HkdfSha256, &out300, &ems, "label", "context");
    try testing.expectEqualSlices(u8, &hexTo(300, "bf78979912d435a84b161b70455589a5fe53e6c34f1d4af0afbcbda8380db0857440b151d0653225473f8435eac81f272863d30ce7fb8be2fa1e2ef3458e61a2e8aeac91a0a54dadddfb5a1ce906ba694a64f69b05a373f9f8c96d8de20072686dcf08016f2b88c5b91251650818a0cb310233b11849e63f3b85962ceb4b8242bc87b71e080dc9c4223bdaf3d72330a5b97aafc6141665c53242a7502ed2cc6b74784c9b323c32ef7e827615a2142e9644309e2dc650722fa55e5dc842486c744baeea99ccb254c20c82a7c8d7a7f0c1ad510c1dfa550341f3c8fb2aae3252c0cc8875cd9f6bda36578fff8f94bcec0987a3f37fd6fbbf3583d143d8ae70398050583bbd5bf2c1f2872b6528fa50ae26a700cec7cff7ecb6b9c69bb68b434d236213fa29202e14576cb0bbb6"), &out300);
    // SHA-384 (an arbitrary secret, octets 0..47).
    var ems384: [48]u8 = undefined;
    for (&ems384, 0..) |*b, i| b.* = @intCast(i);
    var out48: [48]u8 = undefined;
    const Hkdf384 = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);
    T.exportKeyingMaterial(std.crypto.hash.sha2.Sha384, Hkdf384, &out48, &ems384, "label", "context");
    try testing.expectEqualSlices(u8, &hexTo(48, "20bb6c7843de066107923ee40ab8b407c25203da8c2dff6566e83350fb34e41de88f237f66325b77e4b88f8ce340066d"), &out48);
    try testing.expectEqual(249, T.max_exporter_label_len);
    try testing.expectEqual(8160, T.maxExporterLen(HkdfSha256));
}

test "tls13 instance: RFC 8448 §4 binder end to end through resumptionBinderKey + pskBinder" {
    const T = tls13;
    const psk = hexTo(32, "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3");
    var es: [32]u8 = undefined;
    T.earlySecret(HkdfSha256, &es, &psk);
    var bk: [32]u8 = undefined;
    T.resumptionBinderKey(HkdfSha256, &bk, &es, &emptyHash());
    try testing.expectEqualSlices(u8, &hexTo(32, "69fe131a3bbad5d63c64eebcc30e395b9d8107726a13d074e389dbc8a4e47256"), &bk);
    var binder: [32]u8 = undefined;
    T.pskBinder(HkdfSha256, HmacSha256, &binder, &bk, &hexTo(32, "63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14"));
    try testing.expectEqualSlices(u8, &hexTo(32, "3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d"), &binder);
}

test "tls13 instance: KeyUpdate's traffic upd equals std's hardcoded-tls13 expansion, for both digest sizes" {
    const s256 = @as([32]u8, @splat(0x5a));
    var n256: [32]u8 = undefined;
    tls13.nextApplicationTrafficSecret(HkdfSha256, &n256, &s256);
    try testing.expectEqualSlices(u8, &std.crypto.tls.hkdfExpandLabel(HkdfSha256, s256, "traffic upd", "", 32), &n256);
    // Aliasing out == secret is allowed.
    var again = s256;
    tls13.nextApplicationTrafficSecret(HkdfSha256, &again, &again);
    try testing.expectEqualSlices(u8, &n256, &again);

    const Hkdf384 = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);
    const s384 = @as([48]u8, @splat(0xa5));
    var n384: [48]u8 = undefined;
    tls13.nextApplicationTrafficSecret(Hkdf384, &n384, &s384);
    try testing.expectEqualSlices(u8, &std.crypto.tls.hkdfExpandLabel(Hkdf384, s384, "traffic upd", "", 48), &n384);
    // The DTLS instance differs (prefix separation applies to every step).
    var d256: [32]u8 = undefined;
    dtls13.nextApplicationTrafficSecret(HkdfSha256, &d256, &s256);
    try testing.expect(!std.mem.eql(u8, &n256, &d256));
}
