// SPDX-License-Identifier: MIT
//! BOLT#11 payment requests (Lightning invoices) — bech32-encoded (no
//! length cap, see `bech32_raw.zig`), decode/verify + encode/sign. Parses
//! untrusted invoice strings; every decode path is fail-closed: a bad
//! bech32 checksum, a malformed/truncated tagged field, a fixed-length
//! field (`p`/`h`/`s`/`n`) with the wrong length, a missing required field,
//! or a signature that fails to verify/recover is a specific typed error,
//! never a best-effort partial parse.
//!
//! Decode's security core is the `signature` field: when no `n` field pins
//! the payee, the payee's node ID is *recovered* from the signature
//! (`ecdsa_recover.recoverPubkey`) — a tampered `payment_hash`/`amount`/
//! anything-covered-by-the-signature changes the signed hash and recovers a
//! wrong (or non-recoverable) key, not the payee's real one. When an `n`
//! field IS present, it is verified against the signature directly
//! (standard ECDSA verify) and low-S is required (BOLT#11 "MUST fail the
//! payment" on high-S with `n` present — recovery-only invoices accept
//! either, per spec).

const std = @import("std");
const Allocator = std.mem.Allocator;
const k256 = @import("k256");
const bech32raw = @import("bech32_raw.zig");
const bitpack = @import("bitpack.zig");
const ecdsa = @import("ecdsa_recover.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

// ── network / amount (human-readable part) ──────────────────────────────

pub const Network = enum { mainnet, testnet, signet, regtest };

fn networkPrefix(n: Network) []const u8 {
    return switch (n) {
        .mainnet => "bc",
        .testnet => "tb",
        .signet => "tbs",
        .regtest => "bcrt",
    };
}

const NetworkMatch = struct { prefix: []const u8, network: Network };
// Longest-prefix-first: "tbs" (signet) must be tried before "tb" (testnet),
// since "tb" is itself a prefix of "tbs".
const network_matches = [_]NetworkMatch{
    .{ .prefix = "bcrt", .network = .regtest },
    .{ .prefix = "tbs", .network = .signet },
    .{ .prefix = "bc", .network = .mainnet },
    .{ .prefix = "tb", .network = .testnet },
};

fn multiplierExp(c: u8) ?u8 {
    return switch (c) {
        'm' => 3,
        'u' => 6,
        'n' => 9,
        'p' => 12,
        else => null,
    };
}

fn pow10(e: u8) u128 {
    var r: u128 = 1;
    for (0..e) |_| r *= 10;
    return r;
}

pub const AmountError = error{
    InvalidAmountDigits,
    AmountLeadingZero,
    SubMilliSatoshiPrecision,
    AmountTooLarge,
};

/// Parses the optional `amount` + `multiplier` suffix of the HRP (BOLT#11
/// "Human-Readable Part"/"Requirements"). `null` means no amount specified.
fn parseAmountMsat(s: []const u8) AmountError!?u64 {
    if (s.len == 0) return null;

    var digits = s;
    var exp: u8 = 0;
    if (multiplierExp(s[s.len - 1])) |e| {
        exp = e;
        digits = s[0 .. s.len - 1];
    }
    if (digits.len == 0) return error.InvalidAmountDigits;
    if (digits.len > 1 and digits[0] == '0') return error.AmountLeadingZero;
    if (digits.len > 20) return error.AmountTooLarge; // guards the u128 accumulation below

    var v: u128 = 0;
    for (digits) |c| {
        if (c < '0' or c > '9') return error.InvalidAmountDigits;
        v = v * 10 + (c - '0');
    }

    var msat: u128 = undefined;
    if (exp <= 11) {
        msat = v * pow10(11 - exp);
    } else {
        // multiplier 'p' (10^-12 BTC): msat = v * 10^11 / 10^12 = v / 10,
        // exact iff v's last decimal is 0 (BOLT#11's own "p multiplier"
        // rationale: sub-millisatoshi amounts can't exist on the wire).
        if (v % 10 != 0) return error.SubMilliSatoshiPrecision;
        msat = v / 10;
    }
    if (msat > std.math.maxInt(u64)) return error.AmountTooLarge;
    return @intCast(msat);
}

/// Shortest-representation amount encoding (BOLT#11 "SHOULD use the
/// shortest representation possible, by using the largest multiplier or
/// omitting the multiplier"): tries no-multiplier, then `m`/`u`/`n` in
/// decreasing-precision order, falling back to `p` (always exact, since any
/// integer msat times 10 always ends in a 0 decimal).
fn formatAmount(msat: u64, buf: *[32]u8) []const u8 {
    const m: u128 = msat;
    const Case = struct { divisor_exp: u8, mult: ?u8 };
    const cases = [_]Case{
        .{ .divisor_exp = 11, .mult = null },
        .{ .divisor_exp = 8, .mult = 'm' },
        .{ .divisor_exp = 5, .mult = 'u' },
        .{ .divisor_exp = 2, .mult = 'n' },
    };
    for (cases) |c| {
        const d = pow10(c.divisor_exp);
        if (m % d == 0) return fmtDigits(buf, m / d, c.mult);
    }
    return fmtDigits(buf, m * 10, 'p');
}

fn fmtDigits(buf: *[32]u8, digits: u128, mult: ?u8) []const u8 {
    var tmp: [24]u8 = undefined;
    const s = std.fmt.bufPrint(&tmp, "{d}", .{digits}) catch unreachable;
    @memcpy(buf[0..s.len], s);
    var n = s.len;
    if (mult) |mm| {
        buf[n] = mm;
        n += 1;
    }
    return buf[0..n];
}

// ── tagged-field type codes (BOLT#11 "Tagged Fields") ────────────────────

const TAG_PAYMENT_HASH: u5 = 1;
const TAG_ROUTING_INFO: u5 = 3;
const TAG_FEATURES: u5 = 5;
const TAG_EXPIRY: u5 = 6;
const TAG_FALLBACK: u5 = 9;
const TAG_DESCRIPTION: u5 = 13;
const TAG_PAYMENT_SECRET: u5 = 16;
const TAG_NODE_ID: u5 = 19;
const TAG_DESCRIPTION_HASH: u5 = 23;
const TAG_MIN_FINAL_CLTV: u5 = 24;
const TAG_METADATA: u5 = 27;

/// The `r` tagged field's one routing-hint hop (BOLT#11 "Tagged Fields"):
/// `pubkey(264 bits) || short_channel_id(64) || fee_base_msat(32) ||
/// fee_proportional_millionths(32) || cltv_expiry_delta(16)` = 51 bytes.
pub const RouteHop = struct {
    pubkey: [33]u8,
    short_channel_id: u64,
    fee_base_msat: u32,
    fee_proportional_millionths: u32,
    cltv_expiry_delta: u16,
};

pub const RouteHint = struct { hops: []RouteHop };

/// The `f` tagged field: a 5-bit version (witness version 0-16, or 17 for a
/// P2PKH hash / 18 for a P2SH hash) plus the raw program/hash bytes.
/// Address-format interpretation is left to the caller (out of this
/// module's scope — see `SPEC.md`); a reader that doesn't understand
/// `version` is expected to skip the entry (BOLT#11 "MUST skip over `f`
/// fields that use an unknown `version`"), which this typed representation
/// lets the caller do trivially.
pub const Fallback = struct { version: u5, program: []u8 };

pub const VerificationSource = enum { declared_node_id, recovered };

pub const Invoice = struct {
    network: Network,
    amount_msat: ?u64,
    timestamp: u64,
    payment_hash: [32]u8,
    payment_secret: [32]u8,
    /// Exactly one of `description`/`description_hash` is set (BOLT#11:
    /// "MUST include either exactly one `d` or exactly one `h` field").
    description: ?[]u8,
    description_hash: ?[32]u8,
    metadata: ?[]u8,
    expiry_seconds: u64 = 3600,
    min_final_cltv_expiry: u64 = 18,
    /// The raw `n` field, if present (33-byte compressed SEC1 pubkey).
    node_id_field: ?[33]u8,
    fallbacks: []Fallback,
    route_hints: []RouteHint,
    features: ?[]u8,
    signature: ecdsa.Signature,
    /// Compressed SEC1 pubkey: the verified `n` field, or the pubkey
    /// recovered from the signature when `n` was absent — see `verification`.
    verified_pubkey: [33]u8,
    verification: VerificationSource,

    pub fn deinit(self: *Invoice, allocator: Allocator) void {
        if (self.description) |d| allocator.free(d);
        if (self.metadata) |m| allocator.free(m);
        if (self.features) |f| allocator.free(f);
        for (self.fallbacks) |fb| allocator.free(fb.program);
        allocator.free(self.fallbacks);
        for (self.route_hints) |rh| allocator.free(rh.hops);
        allocator.free(self.route_hints);
        self.* = undefined;
    }
};

pub const DecodeError = bech32raw.DecodeError || bitpack.PaddingError || bitpack.IntError ||
    AmountError || ecdsa.RecoverError || Allocator.Error || error{
    UnknownPrefix,
    UnknownNetwork,
    InvoiceTooShort,
    TruncatedTaggedField,
    WrongFixedFieldLength,
    NonMinimalTaggedField,
    BadRouteHintLength,
    MissingPaymentHash,
    MissingPaymentSecret,
    MissingDescription,
    AmbiguousDescription,
    InvalidRecoveryId,
    InvalidSignature,
    HighSNotAllowed,
};

/// Decode + fully verify a BOLT#11 payment request. Fail-closed throughout
/// — see the module doc comment for the signature-verification core.
/// The returned `Invoice` owns `description`/`metadata`/`features`/
/// `fallbacks[].program`/`route_hints[].hops` — call `.deinit(allocator)`.
pub fn decode(allocator: Allocator, invoice_str: []const u8) DecodeError!Invoice {
    var raw = try bech32raw.decode(allocator, invoice_str);
    defer raw.deinit(allocator);

    // ── HRP: "ln" + network + optional amount ──
    if (raw.hrp.len < 2 or !std.mem.eql(u8, raw.hrp[0..2], "ln")) return error.UnknownPrefix;
    const rest = raw.hrp[2..];
    var network: Network = undefined;
    var amount_part: []const u8 = undefined;
    var matched = false;
    for (network_matches) |m| {
        if (std.mem.startsWith(u8, rest, m.prefix)) {
            network = m.network;
            amount_part = rest[m.prefix.len..];
            matched = true;
            break;
        }
    }
    if (!matched) return error.UnknownNetwork;
    const amount_msat = try parseAmountMsat(amount_part);

    // ── data part: 35-bit timestamp + tagged fields + 520-bit signature ──
    const data = raw.data;
    if (data.len < 7 + 104) return error.InvoiceTooShort;
    const timestamp = try bitpack.quintetsToUint(data[0..7]);
    const sig_start = data.len - 104;

    var payment_hash: ?[32]u8 = null;
    var payment_secret: ?[32]u8 = null;
    var description: ?[]u8 = null;
    var description_hash: ?[32]u8 = null;
    var metadata: ?[]u8 = null;
    var expiry_seconds: u64 = 3600;
    var expiry_seen = false;
    var min_final_cltv_expiry: u64 = 18;
    var cltv_seen = false;
    var node_id_field: ?[33]u8 = null;
    var features: ?[]u8 = null;
    var fallbacks: std.ArrayList(Fallback) = .empty;
    var route_hints: std.ArrayList(RouteHint) = .empty;
    errdefer {
        if (description) |d| allocator.free(d);
        if (metadata) |m| allocator.free(m);
        if (features) |f| allocator.free(f);
        for (fallbacks.items) |fb| allocator.free(fb.program);
        fallbacks.deinit(allocator);
        for (route_hints.items) |rh| allocator.free(rh.hops);
        route_hints.deinit(allocator);
    }

    var idx: usize = 7;
    while (idx < sig_start) {
        if (sig_start - idx < 3) return error.TruncatedTaggedField;
        const tag: u5 = data[idx];
        const len: usize = @as(usize, data[idx + 1]) * 32 + @as(usize, data[idx + 2]);
        idx += 3;
        if (sig_start - idx < len) return error.TruncatedTaggedField;
        const value = data[idx .. idx + len];
        idx += len;

        switch (tag) {
            // Fixed-length fields (p/h/s/n): BOLT#11's own "including fields
            // which must be ignored" vector demonstrates that an occurrence
            // with the WRONG fixed length is simply skipped (never fatal,
            // regardless of whether it's the first occurrence of that tag)
            // -- only a correctly-sized occurrence ever claims the slot. A
            // reader still fails closed overall via the post-loop
            // "MissingPaymentHash"/etc checks if no valid occurrence of a
            // REQUIRED field ever appears.
            TAG_PAYMENT_HASH => if (payment_hash == null and len == 52) {
                const bytes = try bitpack.quintetsToBytesStrict(allocator, value);
                defer allocator.free(bytes);
                payment_hash = bytes[0..32].*;
            },
            TAG_PAYMENT_SECRET => if (payment_secret == null and len == 52) {
                const bytes = try bitpack.quintetsToBytesStrict(allocator, value);
                defer allocator.free(bytes);
                payment_secret = bytes[0..32].*;
            },
            TAG_DESCRIPTION => if (description == null) {
                description = try bitpack.quintetsToBytesStrict(allocator, value);
            },
            TAG_DESCRIPTION_HASH => if (description_hash == null and len == 52) {
                const bytes = try bitpack.quintetsToBytesStrict(allocator, value);
                defer allocator.free(bytes);
                description_hash = bytes[0..32].*;
            },
            TAG_METADATA => if (metadata == null) {
                metadata = try bitpack.quintetsToBytesStrict(allocator, value);
            },
            TAG_NODE_ID => if (node_id_field == null and len == 53) {
                const bytes = try bitpack.quintetsToBytesStrict(allocator, value);
                defer allocator.free(bytes);
                node_id_field = bytes[0..33].*;
            },
            TAG_EXPIRY => if (!expiry_seen) {
                if (value.len > 0 and value[0] == 0) return error.NonMinimalTaggedField;
                expiry_seconds = try bitpack.quintetsToUint(value);
                expiry_seen = true;
            },
            TAG_MIN_FINAL_CLTV => if (!cltv_seen) {
                if (value.len > 0 and value[0] == 0) return error.NonMinimalTaggedField;
                min_final_cltv_expiry = try bitpack.quintetsToUint(value);
                cltv_seen = true;
            },
            TAG_FALLBACK => {
                if (len == 0) return error.WrongFixedFieldLength;
                const version: u5 = value[0];
                const program = try bitpack.quintetsToBytesStrict(allocator, value[1..]);
                errdefer allocator.free(program);
                try fallbacks.append(allocator, .{ .version = version, .program = program });
            },
            TAG_ROUTING_INFO => {
                const bytes = try bitpack.quintetsToBytesStrict(allocator, value);
                defer allocator.free(bytes);
                if (bytes.len == 0 or bytes.len % 51 != 0) return error.BadRouteHintLength;
                const n_hops = bytes.len / 51;
                const hops = try allocator.alloc(RouteHop, n_hops);
                errdefer allocator.free(hops);
                for (0..n_hops) |i| {
                    const off = i * 51;
                    hops[i] = .{
                        .pubkey = bytes[off..][0..33].*,
                        .short_channel_id = std.mem.readInt(u64, bytes[off + 33 ..][0..8], .big),
                        .fee_base_msat = std.mem.readInt(u32, bytes[off + 41 ..][0..4], .big),
                        .fee_proportional_millionths = std.mem.readInt(u32, bytes[off + 45 ..][0..4], .big),
                        .cltv_expiry_delta = std.mem.readInt(u16, bytes[off + 49 ..][0..2], .big),
                    };
                }
                try route_hints.append(allocator, .{ .hops = hops });
            },
            TAG_FEATURES => if (features == null) {
                features = try bitpack.quintetsToBytesStrict(allocator, value);
            },
            else => {}, // unrecognized tag: already consumed above, discard
        }
    }

    if (payment_hash == null) return error.MissingPaymentHash;
    if (payment_secret == null) return error.MissingPaymentSecret;
    if (description == null and description_hash == null) return error.MissingDescription;
    if (description != null and description_hash != null) return error.AmbiguousDescription;

    // ── signature ──
    const sig_bytes = try bitpack.quintetsToBytesStrict(allocator, data[sig_start..]);
    defer allocator.free(sig_bytes);
    std.debug.assert(sig_bytes.len == 65); // structural: 104 quintets = 520 bits = 65 bytes exactly
    const sig_r = sig_bytes[0..32].*;
    const sig_s = sig_bytes[32..64].*;
    if (sig_bytes[64] > 3) return error.InvalidRecoveryId;
    const recid: u2 = @intCast(sig_bytes[64]);

    // ── preimage + hash (BOLT#11: HRP || data-without-signature, 0-padded
    // to a byte boundary) ──
    const data_bytes = try bitpack.quintetsToBytesPadded(allocator, data[0..sig_start]);
    defer allocator.free(data_bytes);
    const preimage = try std.mem.concat(allocator, u8, &.{ raw.hrp, data_bytes });
    defer allocator.free(preimage);
    var hash: [32]u8 = undefined;
    Sha256.hash(preimage, &hash, .{});

    var verified_pubkey: [33]u8 = undefined;
    var verification: VerificationSource = undefined;
    if (node_id_field) |n_bytes| {
        if (!ecdsa.isLowS(sig_s)) return error.HighSNotAllowed;
        var sig_rs: [64]u8 = undefined;
        sig_rs[0..32].* = sig_r;
        sig_rs[32..64].* = sig_s;
        if (!k256.sign.ecdsaVerify(&n_bytes, preimage, sig_rs)) return error.InvalidSignature;
        verified_pubkey = n_bytes;
        verification = .declared_node_id;
    } else {
        const Q = try ecdsa.recoverPubkey(hash, sig_r, sig_s, recid);
        verified_pubkey = Q.toCompressedSec1();
        verification = .recovered;
    }

    return .{
        .network = network,
        .amount_msat = amount_msat,
        .timestamp = timestamp,
        .payment_hash = payment_hash.?,
        .payment_secret = payment_secret.?,
        .description = description,
        .description_hash = description_hash,
        .metadata = metadata,
        .expiry_seconds = expiry_seconds,
        .min_final_cltv_expiry = min_final_cltv_expiry,
        .node_id_field = node_id_field,
        .fallbacks = try fallbacks.toOwnedSlice(allocator),
        .route_hints = try route_hints.toOwnedSlice(allocator),
        .features = features,
        .signature = .{ .r = sig_r, .s = sig_s, .recid = recid },
        .verified_pubkey = verified_pubkey,
        .verification = verification,
    };
}

// ── encode ────────────────────────────────────────────────────────────────

pub const TaggedFieldOut = union(enum) {
    payment_hash: [32]u8,
    payment_secret: [32]u8,
    description: []const u8,
    description_hash: [32]u8,
    metadata: []const u8,
    node_id: [33]u8,
    expiry_seconds: u64,
    min_final_cltv_expiry: u64,
    fallback: struct { version: u5, program: []const u8 },
    route_hint: []const RouteHop,
    features: []const u8,
};

pub const EncodeParams = struct {
    network: Network,
    amount_msat: ?u64 = null,
    timestamp: u64,
    /// Emitted in exactly this order (BOLT#11 gives the writer free choice
    /// of tagged-field order; there is no canonical order to reconstruct).
    fields: []const TaggedFieldOut,
};

pub const SignInput = union(enum) {
    signature: ecdsa.Signature,
    private_key: [32]u8,
};

fn appendBytesAsQuintets(allocator: Allocator, list: *std.ArrayList(u5), bytes: []const u8) !void {
    const q = try bitpack.bytesToQuintets(allocator, bytes);
    defer allocator.free(q);
    try list.appendSlice(allocator, q);
}

fn appendTaggedField(allocator: Allocator, data: *std.ArrayList(u5), f: TaggedFieldOut) !void {
    var value: std.ArrayList(u5) = .empty;
    defer value.deinit(allocator);
    var tag: u5 = undefined;

    switch (f) {
        .payment_hash => |h| {
            tag = TAG_PAYMENT_HASH;
            try appendBytesAsQuintets(allocator, &value, &h);
        },
        .payment_secret => |h| {
            tag = TAG_PAYMENT_SECRET;
            try appendBytesAsQuintets(allocator, &value, &h);
        },
        .description => |s| {
            tag = TAG_DESCRIPTION;
            try appendBytesAsQuintets(allocator, &value, s);
        },
        .description_hash => |h| {
            tag = TAG_DESCRIPTION_HASH;
            try appendBytesAsQuintets(allocator, &value, &h);
        },
        .metadata => |s| {
            tag = TAG_METADATA;
            try appendBytesAsQuintets(allocator, &value, s);
        },
        .node_id => |p| {
            tag = TAG_NODE_ID;
            try appendBytesAsQuintets(allocator, &value, &p);
        },
        .expiry_seconds => |v| {
            tag = TAG_EXPIRY;
            var buf: [13]u5 = undefined;
            try value.appendSlice(allocator, bitpack.uintToQuintets(v, &buf));
        },
        .min_final_cltv_expiry => |v| {
            tag = TAG_MIN_FINAL_CLTV;
            var buf: [13]u5 = undefined;
            try value.appendSlice(allocator, bitpack.uintToQuintets(v, &buf));
        },
        .fallback => |fb| {
            tag = TAG_FALLBACK;
            try value.append(allocator, fb.version);
            try appendBytesAsQuintets(allocator, &value, fb.program);
        },
        .route_hint => |hops| {
            tag = TAG_ROUTING_INFO;
            var bytes: std.ArrayList(u8) = .empty;
            defer bytes.deinit(allocator);
            for (hops) |h| {
                try bytes.appendSlice(allocator, &h.pubkey);
                var b8: [8]u8 = undefined;
                std.mem.writeInt(u64, &b8, h.short_channel_id, .big);
                try bytes.appendSlice(allocator, &b8);
                var b4a: [4]u8 = undefined;
                std.mem.writeInt(u32, &b4a, h.fee_base_msat, .big);
                try bytes.appendSlice(allocator, &b4a);
                var b4b: [4]u8 = undefined;
                std.mem.writeInt(u32, &b4b, h.fee_proportional_millionths, .big);
                try bytes.appendSlice(allocator, &b4b);
                var b2: [2]u8 = undefined;
                std.mem.writeInt(u16, &b2, h.cltv_expiry_delta, .big);
                try bytes.appendSlice(allocator, &b2);
            }
            try appendBytesAsQuintets(allocator, &value, bytes.items);
        },
        .features => |s| {
            tag = TAG_FEATURES;
            try appendBytesAsQuintets(allocator, &value, s);
        },
    }

    if (value.items.len > 1023) return error.TaggedFieldTooLong; // data_length is 10 bits
    try data.append(allocator, tag);
    try data.append(allocator, @intCast((value.items.len >> 5) & 0x1f));
    try data.append(allocator, @intCast(value.items.len & 0x1f));
    try data.appendSlice(allocator, value.items);
}

/// Encode + sign a BOLT#11 payment request. `sign_input` is either a
/// caller-supplied signature (the module never needs to hold a private
/// key) or a raw private key to sign with directly (RFC 6979 deterministic
/// nonce — see `ecdsa_recover.zig`). Returns an owned, freshly bech32
/// (no length cap) - encoded invoice string.
pub fn encode(allocator: Allocator, params: EncodeParams, sign_input: SignInput) ![]u8 {
    var amt_buf: [32]u8 = undefined;
    const amt_str: []const u8 = if (params.amount_msat) |m| formatAmount(m, &amt_buf) else "";
    const hrp = try std.fmt.allocPrint(allocator, "ln{s}{s}", .{ networkPrefix(params.network), amt_str });
    defer allocator.free(hrp);

    var data: std.ArrayList(u5) = .empty;
    defer data.deinit(allocator);

    // timestamp: fixed-width 7 quintets (35 bits), NOT minimally encoded --
    // unlike x/c it has no variable-length data_length header.
    {
        var v = params.timestamp;
        var tmp: [7]u5 = undefined;
        var i: usize = 7;
        while (i > 0) {
            i -= 1;
            tmp[i] = @intCast(v & 0x1f);
            v >>= 5;
        }
        try data.appendSlice(allocator, &tmp);
    }

    for (params.fields) |f| try appendTaggedField(allocator, &data, f);

    const data_bytes = try bitpack.quintetsToBytesPadded(allocator, data.items);
    defer allocator.free(data_bytes);
    const preimage = try std.mem.concat(allocator, u8, &.{ hrp, data_bytes });
    defer allocator.free(preimage);
    var hash: [32]u8 = undefined;
    Sha256.hash(preimage, &hash, .{});

    const sig: ecdsa.Signature = switch (sign_input) {
        .signature => |s| s,
        .private_key => |pk| try ecdsa.sign(pk, hash),
    };

    var sig_bytes: [65]u8 = undefined;
    sig_bytes[0..32].* = sig.r;
    sig_bytes[32..64].* = sig.s;
    sig_bytes[64] = sig.recid;
    const sig_quintets = try bitpack.bytesToQuintets(allocator, &sig_bytes);
    defer allocator.free(sig_quintets);
    std.debug.assert(sig_quintets.len == 104);
    try data.appendSlice(allocator, sig_quintets);

    return bech32raw.encode(allocator, hrp, data.items);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn hexToBytes(comptime n: usize, hex: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// BOLT#11's own worked examples are all signed with this private key, node
// ID `03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad`.
const spec_privkey = hexToBytes(32, "e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734");
const spec_node_id = hexToBytes(33, "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad");

test "BOLT#11 vector: donation invoice, no 'n' field -- recovers the spec's own node ID" {
    const allocator = testing.allocator;
    const invoice = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";

    var inv = try decode(allocator, invoice);
    defer inv.deinit(allocator);

    try testing.expectEqual(Network.mainnet, inv.network);
    try testing.expectEqual(@as(?u64, null), inv.amount_msat);
    try testing.expectEqual(@as(u64, 1496314658), inv.timestamp);
    try testing.expectEqualSlices(u8, &hexToBytes(32, "0001020304050607080900010203040506070809000102030405060708090102"), &inv.payment_hash);
    try testing.expectEqualSlices(u8, &hexToBytes(32, "1111111111111111111111111111111111111111111111111111111111111111"), &inv.payment_secret);
    try testing.expectEqualStrings("Please consider supporting this project", inv.description.?);
    try testing.expectEqual(@as(?[32]u8, null), inv.description_hash);
    try testing.expectEqual(VerificationSource.recovered, inv.verification);
    try testing.expectEqualSlices(u8, &spec_node_id, &inv.verified_pubkey);

    // The signature's own recovery id / r / s match the spec's documented
    // breakdown byte-exact.
    try testing.expectEqualSlices(u8, &hexToBytes(32, "8d3ce9e28357337f62da0162d9454df827f83cfe499aeb1c1db349d4d8112742"), &inv.signature.r);
    try testing.expectEqual(@as(u2, 1), inv.signature.recid);
}

test "BOLT#11 vector: high-S variant -- same r, s = n-s_donation, decodes without error" {
    // BOLT#11's own "Public-key recovery with high-S signature" example: same
    // `r` as the donation invoice, `s` negated mod the group order (verified
    // independently below), same transmitted recid (1). Cross-checked outside
    // this module with Python's `cryptography` library: BOTH (r, s_donation)
    // and (r, s_high) verify as genuine signatures by the spec's node key
    // under SHA256(preimage) -- s_high is a real "other" valid signature, not
    // a garbage/corrupted one. But `s_high = n - s_donation` implies the
    // *other* nonce `k' = n-k` was used, whose `R' = -R` has the OPPOSITE y
    // parity from the donation signature's `R` -- so recovering it correctly
    // needs recid 0, not the transmitted 1. The spec's own worked example
    // ships recid 1 for both, which is why decoding this exact invoice with
    // the module's (spec-compliant: trust the transmitted recid) recovery
    // does NOT reproduce the node ID -- documented, not silently "fixed" by
    // guessing recid, since guessing would mean *any* recid always "succeeds"
    // and defeats the module's actual security property (see the module doc
    // comment / the "tampered invoice" test below).
    const allocator = testing.allocator;
    const invoice = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap2r09nt4ndd0unm3z9u5t48y6ucv4r5sg7lk98c77ctvjczkspk5qprc90gx";

    var inv = try decode(allocator, invoice);
    defer inv.deinit(allocator);

    try testing.expectEqual(VerificationSource.recovered, inv.verification);
    try testing.expect(!ecdsa.isLowS(inv.signature.s)); // this is the documented high-S example
    try testing.expectEqualSlices(u8, &hexToBytes(32, "8d3ce9e28357337f62da0162d9454df827f83cfe499aeb1c1db349d4d8112742"), &inv.signature.r);
    try testing.expectEqual(@as(u2, 1), inv.signature.recid); // the vector's transmitted recid

    // Proves the recovery ALGORITHM (not the vector's own recid choice) is
    // correct: with the mathematically-consistent recid (0, per the parity
    // argument above), recovery over this exact (hash, r, s) reproduces the
    // spec's own node ID byte-exact.
    const hash = hexToBytes(32, "6daf4d488be41ce7cbb487cab1ef2975e5efcea879b20d421f0ef86b07cbb987");
    const Q = try ecdsa.recoverPubkey(hash, inv.signature.r, inv.signature.s, 0);
    try testing.expectEqualSlices(u8, &spec_node_id, &Q.toCompressedSec1());
}

test "BOLT#11 vector: $3 coffee -- amount(2500u)/expiry/description decode exactly" {
    const allocator = testing.allocator;
    const invoice = "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";

    var inv = try decode(allocator, invoice);
    defer inv.deinit(allocator);

    try testing.expectEqual(@as(?u64, 250_000_000), inv.amount_msat); // 2500 micro-BTC
    try testing.expectEqual(@as(u64, 60), inv.expiry_seconds);
    try testing.expectEqualStrings("1 cup coffee", inv.description.?);
    try testing.expectEqual(VerificationSource.recovered, inv.verification);
    try testing.expectEqualSlices(u8, &spec_node_id, &inv.verified_pubkey);
}

test "BOLT#11 vector: sub-millisatoshi pico amount (9678785340p -> 967878534 msat) + route hint" {
    const allocator = testing.allocator;
    const invoice = "lnbc9678785340p1pwmna7lpp5gc3xfm08u9qy06djf8dfflhugl6p7lgza6dsjxq454gxhj9t7a0sd8dgfkx7cmtwd68yetpd5s9xar0wfjn5gpc8qhrsdfq24f5ggrxdaezqsnvda3kkum5wfjkzmfqf3jkgem9wgsyuctwdus9xgrcyqcjcgpzgfskx6eqf9hzqnteypzxz7fzypfhg6trddjhygrcyqezcgpzfysywmm5ypxxjemgw3hxjmn8yptk7untd9hxwg3q2d6xjcmtv4ezq7pqxgsxzmnyyqcjqmt0wfjjq6t5v4khxsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsxqyjw5qcqp2rzjq0gxwkzc8w6323m55m4jyxcjwmy7stt9hwkwe2qxmy8zpsgg7jcuwz87fcqqeuqqqyqqqqlgqqqqn3qq9q9qrsgqrvgkpnmps664wgkp43l22qsgdw4ve24aca4nymnxddlnp8vh9v2sdxlu5ywdxefsfvm0fq3sesf08uf6q9a2ke0hc9j6z6wlxg5z5kqpu2v9wz";

    var inv = try decode(allocator, invoice);
    defer inv.deinit(allocator);

    try testing.expectEqual(@as(?u64, 967_878_534), inv.amount_msat);
    try testing.expectEqual(@as(u64, 604_800), inv.expiry_seconds);
    try testing.expectEqual(@as(u64, 10), inv.min_final_cltv_expiry);
    try testing.expectEqualSlices(u8, &hexToBytes(32, "462264ede7e14047e9b249da94fefc47f41f7d02ee9b091815a5506bc8abf75f"), &inv.payment_hash);

    try testing.expectEqual(@as(usize, 1), inv.route_hints.len);
    try testing.expectEqual(@as(usize, 1), inv.route_hints[0].hops.len);
    const hop = inv.route_hints[0].hops[0];
    try testing.expectEqualSlices(u8, &hexToBytes(33, "03d06758583bb5154774a6eb221b1276c9e82d65bbaceca806d90e20c108f4b1c7"), &hop.pubkey);
    try testing.expectEqual(@as(u32, 1000), hop.fee_base_msat);
    try testing.expectEqual(@as(u32, 2500), hop.fee_proportional_millionths);
    try testing.expectEqual(@as(u16, 40), hop.cltv_expiry_delta);
    // short_channel_id 589390x3312x1 packed as block<<40 | tx<<16 | output.
    try testing.expectEqual(@as(u64, (589390 << 40) | (3312 << 16) | 1), hop.short_channel_id);

    try testing.expectEqual(VerificationSource.recovered, inv.verification);
    try testing.expectEqualSlices(u8, &spec_node_id, &inv.verified_pubkey);
}

test "BOLT#11 vector: $24 with 'h' description-hash field decodes and matches the documented SHA256" {
    const allocator = testing.allocator;
    const invoice = "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrsgq7ea976txfraylvgzuxs8kgcw23ezlrszfnh8r6qtfpr6cxga50aj6txm9rxrydzd06dfeawfk6swupvz4erwnyutnjq7x39ymw6j38gp7ynn44";

    var inv = try decode(allocator, invoice);
    defer inv.deinit(allocator);

    try testing.expectEqual(@as(?u64, 2_000_000_000), inv.amount_msat); // 20 milli-BTC
    try testing.expectEqual(@as(?[]u8, null), inv.description);
    try testing.expectEqualSlices(u8, &hexToBytes(32, "3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1"), &inv.description_hash.?);
    try testing.expectEqualSlices(u8, &spec_node_id, &inv.verified_pubkey);
}

test "BOLT#11 vector: same-but-uppercase decodes identically (case-insensitive bech32)" {
    const allocator = testing.allocator;
    const invoice = "LNBC25M1PVJLUEZPP5QQQSYQCYQ5RQWZQFQQQSYQCYQ5RQWZQFQQQSYQCYQ5RQWZQFQYPQDQ5VDHKVEN9V5SXYETPDEESSP5ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYGS9Q5SQQQQQQQQQQQQQQQQSGQ2A25DXL5HRNTDTN6ZVYDT7D66HYZSYHQS4WDYNAVYS42XGL6SGX9C4G7ME86A27T07MDTFRY458RTJR0V92CNMSWPSJSCGT2VCSE3SGPZ3UAPA";
    var inv = try decode(allocator, invoice);
    defer inv.deinit(allocator);
    try testing.expectEqualStrings("coffee beans", inv.description.?);
    try testing.expectEqualSlices(u8, &spec_node_id, &inv.verified_pubkey);
}

test "BOLT#11 vector: duplicate/unknown fields after the first are ignored" {
    const allocator = testing.allocator;
    const invoice = "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqqsgq2qrqqqfppnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqppnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhpnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqspnqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsp4qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnp5qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnpkqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz599y53s3ujmcfjp5xrdap68qxymkqphwsexhmhr8wdz5usdzkzrse33chw6dlp3jhuhge9ley7j2ayx36kawe7kmgg8sv5ugdyusdcqzn8z9x";

    var inv = try decode(allocator, invoice);
    defer inv.deinit(allocator);

    // The FIRST 'd' field ("coffee beans") wins; the later duplicate 'p'/
    // 'h'/'s'/'n' fields (some with deliberately wrong fixed lengths) and
    // the unknown type-2 field are all silently discarded, not fatal.
    try testing.expectEqualStrings("coffee beans", inv.description.?);
    try testing.expectEqual(@as(usize, 1), inv.fallbacks.len); // the one real 'f' (type 19, unknown version)
    try testing.expectEqual(@as(u5, 19), inv.fallbacks[0].version);
    try testing.expectEqual(@as(?[33]u8, null), inv.node_id_field); // both 'n' occurrences had wrong length, both duplicates of "unset"
}

test "hostile: bad bech32 checksum is rejected" {
    const allocator = testing.allocator;
    const invoice = "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrnt";
    try testing.expectError(error.InvalidChecksum, decode(allocator, invoice));
}

test "hostile: malformed bech32 (no separator) is rejected" {
    const allocator = testing.allocator;
    const invoice = "pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny";
    try testing.expectError(error.NoSeparator, decode(allocator, invoice));
}

test "hostile: mixed-case bech32 is rejected" {
    const allocator = testing.allocator;
    const invoice = "LNBC2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpuyk0sg5g70me25alkluzd2x62aysf2pyy8edtjeevuv4p2d5p76r4zkmneet7uvyakky2zr4cusd45tftc9c5fh0nnqpnl2jfll544esqchsrny";
    try testing.expectError(error.MixedCase, decode(allocator, invoice));
}

test "hostile: unrecoverable signature (no 'n' field, corrupted r) is rejected -- the security core" {
    // BOLT#11's own "Signature is not recoverable" invalid-invoice vector:
    // `r` (with the recid's x-overflow bit set) resolves to an x-coordinate
    // >= the field prime, so it cannot even be lifted to a curve point --
    // `ecdsa_recover.recoverPubkey` rejects it as `error.InvalidScalar`
    // before ever reaching a curve operation. This is the security property
    // the module exists for: a bad/tampered signature does NOT silently
    // recover a plausible-looking pubkey, it fails closed.
    const allocator = testing.allocator;
    const invoice = "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgqwgt7mcn5yqw3yx0w94pswkpq6j9uh6xfqqqtsk4tnarugeektd4hg5975x9am52rz4qskukxdmjemg92vvqz8nvmsye63r5ykel43pgz7zq0g2";
    try testing.expectError(error.InvalidScalar, decode(allocator, invoice));
}

test "hostile: invalid multiplier char is rejected" {
    const allocator = testing.allocator;
    const invoice = "lnbc2500x1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgqrrzc4cvfue4zp3hggxp47ag7xnrlr8vgcmkjxk3j5jqethnumgkpqp23z9jclu3v0a7e0aruz366e9wqdykw6dxhdzcjjhldxq0w6wgqcnu43j";
    // 'x' isn't a recognized multiplier char, so it's parsed as (rejected)
    // part of the amount digit string itself -- "amount contains a
    // non-digit" (BOLT#11 reader requirement), same underlying spec clause.
    try testing.expectError(error.InvalidAmountDigits, decode(allocator, invoice));
}

test "hostile: sub-millisatoshi precision ('p' multiplier, non-zero last decimal) is rejected" {
    const allocator = testing.allocator;
    const invoice = "lnbc2500000001p1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgq0lzc236j96a95uv0m3umg28gclm5lqxtqqwk32uuk4k6673k6n5kfvx3d2h8s295fad45fdhmusm8sjudfhlf6dcsxmfvkeywmjdkxcp99202x";
    try testing.expectError(error.SubMilliSatoshiPrecision, decode(allocator, invoice));
}

test "hostile: missing required 's' (payment_secret) field is rejected" {
    const allocator = testing.allocator;
    const invoice = "lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrsgq7ea976txfraylvgzuxs8kgcw23ezlrszfnh8r6qtfpr6cxga50aj6txm9rxrydzd06dfeawfk6swupvz4erwnyutnjq7x39ymw6j38gp49qdkj";
    try testing.expectError(error.MissingPaymentSecret, decode(allocator, invoice));
}

test "hostile: too-short invoice (not enough quintets for timestamp+signature) is rejected" {
    const allocator = testing.allocator;
    const invoice = "lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6na6hlh";
    try testing.expectError(error.InvoiceTooShort, decode(allocator, invoice));
}

test "hostile: 'n' field present + high-S signature is rejected (low-S required when node ID is declared)" {
    const allocator = testing.allocator;
    const invoice = "lnbc25m1p70xwfzpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaqnp4q0n326hr8v9zprg8gsvezcch06gfaqqhde2aj730yg0durunfhv66sp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsp5cfzp9ugllvk03rltd6hvndxj26ux6gcxc5azyxk060rj9tzghct5zvjlps76gx8wpq5yuu79688k8gnm2c0al6v608s96l0xzrrlqqwnzxmu";
    try testing.expectError(error.HighSNotAllowed, decode(allocator, invoice));
}

test "encode -> decode round-trip: fields survive re-parsing, node ID recovered matches signer" {
    const allocator = testing.allocator;
    var privkey: [32]u8 = undefined;
    @memset(&privkey, 0x11);
    const pub_point = try k256.Secp256k1.combMulBase(privkey, .big);
    const pub_compressed = pub_point.toCompressedSec1();

    const payment_hash: [32]u8 = hexToBytes(32, "0001020304050607080900010203040506070809000102030405060708090102");
    const payment_secret: [32]u8 = hexToBytes(32, "1111111111111111111111111111111111111111111111111111111111111111");
    const fields = [_]TaggedFieldOut{
        .{ .payment_hash = payment_hash },
        .{ .payment_secret = payment_secret },
        .{ .description = "round-trip test invoice" },
        .{ .expiry_seconds = 900 },
        .{ .min_final_cltv_expiry = 40 },
    };
    const params = EncodeParams{
        .network = .testnet,
        .amount_msat = 1_234_000,
        .timestamp = 1_700_000_000,
        .fields = &fields,
    };
    const str = try encode(allocator, params, .{ .private_key = privkey });
    defer allocator.free(str);
    try testing.expect(std.mem.startsWith(u8, str, "lntb"));

    var inv = try decode(allocator, str);
    defer inv.deinit(allocator);
    try testing.expectEqual(Network.testnet, inv.network);
    try testing.expectEqual(@as(?u64, 1_234_000), inv.amount_msat);
    try testing.expectEqual(@as(u64, 1_700_000_000), inv.timestamp);
    try testing.expectEqualSlices(u8, &payment_hash, &inv.payment_hash);
    try testing.expectEqualSlices(u8, &payment_secret, &inv.payment_secret);
    try testing.expectEqualStrings("round-trip test invoice", inv.description.?);
    try testing.expectEqual(@as(u64, 900), inv.expiry_seconds);
    try testing.expectEqual(@as(u64, 40), inv.min_final_cltv_expiry);
    try testing.expectEqual(VerificationSource.recovered, inv.verification);
    try testing.expectEqualSlices(u8, &pub_compressed, &inv.verified_pubkey);
}

test "RFC6979 byte-exact re-derivation: signing the donation vector's own hash with its own privkey reproduces its exact r/s" {
    // The strongest possible encoder check: BOLT#11's own donation-invoice
    // hash (SHA256(hrp || data-without-signature), independently confirmed
    // to equal the spec's own documented "hex of SHA256 of the preimage")
    // signed with RFC6979 + the spec's own documented private key must
    // reproduce the EXACT (r, s) the spec's bech32 invoice carries -- not
    // merely "a valid signature", the literal same bytes, since RFC6979 is
    // deterministic. This sidesteps `encode()`'s tagged-field bit-packing
    // (the spec's own `9` features field uses non-minimal padding this
    // module's encoder doesn't reproduce bit-for-bit, so going through the
    // full encode pipeline can't be asserted byte-exact against this
    // particular vector -- signing the hash directly can be).
    const hash = hexToBytes(32, "6daf4d488be41ce7cbb487cab1ef2975e5efcea879b20d421f0ef86b07cbb987");
    const sig = try ecdsa.sign(spec_privkey, hash);
    try testing.expectEqualSlices(u8, &hexToBytes(32, "8d3ce9e28357337f62da0162d9454df827f83cfe499aeb1c1db349d4d8112742"), &sig.r);
    try testing.expectEqualSlices(u8, &hexToBytes(32, "5e434ca29929406c23bba1ae8ac6ca32880b38d4bf6ff874024cac34ba9625f1"), &sig.s);
    try testing.expectEqual(@as(u2, 1), sig.recid);

    // And recovering from that freshly-computed signature reproduces the
    // spec's own node ID -- signer and verifier agree end-to-end.
    const Q = try ecdsa.recoverPubkey(hash, sig.r, sig.s, sig.recid);
    try testing.expectEqualSlices(u8, &spec_node_id, &Q.toCompressedSec1());
}

// ── fuzz: decode never panics on a user-pasted invoice string ────────────
//
// `decode` is the module's whole reason to exist: a BOLT#11 invoice is
// text a user copy-pastes from an untrusted counterparty/webpage straight
// into a wallet. Plain random bytes would die almost immediately on
// `bech32_raw.decode`'s checksum check (a 1-in-2^30 chance of passing by
// luck), testing nothing past it -- so this harness builds a
// checksum-VALID bech32 string via `bech32_raw.encode` itself (real HRP
// grammar: "ln" + a real network prefix + an optional amount+multiplier;
// real data-part length, biased toward >= 7+104 quintets so the
// tagged-field loop at the heart of this file actually runs) and lets
// only the HRP shape, amount digits, and tagged-field quintets vary
// randomly. This is what actually drives the parser into
// `TruncatedTaggedField`/fixed-length-field/signature-recovery territory
// instead of bouncing off `InvalidChecksum` every time.
test "fuzz: decode never panics on arbitrary attacker-supplied invoice strings" {
    try testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;

    var hrp_buf: [16]u8 = undefined;
    var hrp_len: usize = 0;
    const net_prefixes = [_][]const u8{ "bc", "tb", "tbs", "bcrt" };
    const net = net_prefixes[smith.valueRangeAtMost(u8, 0, net_prefixes.len - 1)];
    @memcpy(hrp_buf[0..2], "ln");
    hrp_len = 2;
    @memcpy(hrp_buf[hrp_len..][0..net.len], net);
    hrp_len += net.len;
    if (smith.value(bool)) {
        const digits = "0123456789";
        const n_digits = smith.valueRangeAtMost(u8, 0, 5);
        var i: u8 = 0;
        while (i < n_digits) : (i += 1) {
            hrp_buf[hrp_len] = digits[smith.valueRangeAtMost(u8, 0, 9)];
            hrp_len += 1;
        }
        if (n_digits > 0 and smith.value(bool)) {
            const mults = "munp";
            hrp_buf[hrp_len] = mults[smith.valueRangeAtMost(u8, 0, 3)];
            hrp_len += 1;
        }
    }

    // Data part: random quintets, biased toward >= 7+104 (timestamp +
    // signature) so the tagged-field loop actually runs most of the time;
    // occasionally shorter, to exercise `InvoiceTooShort` too.
    var data_buf: [200]u5 = undefined;
    const data_len: usize = if (smith.value(bool))
        smith.valueRangeAtMost(u16, 111, data_buf.len)
    else
        smith.valueRangeAtMost(u16, 0, data_buf.len);
    for (data_buf[0..data_len]) |*q| q.* = @intCast(smith.valueRangeAtMost(u8, 0, 31));

    const invoice = bech32raw.encode(allocator, hrp_buf[0..hrp_len], data_buf[0..data_len]) catch return;
    defer allocator.free(invoice);

    var inv = decode(allocator, invoice) catch return;
    defer inv.deinit(allocator);
}
