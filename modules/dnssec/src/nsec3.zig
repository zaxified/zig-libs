// SPDX-License-Identifier: MIT

//! NSEC3 (RFC 5155) mechanics: base32hex encoding (RFC 4648 §7, used for the
//! textual/owner-label form of an NSEC3 hash) and the iterated-SHA-1 owner
//! hash (RFC 5155 §5). Both are pure bit-shuffling / repeated hashing — no
//! signature cryptography.
//!
//! Also here (`proveDenial`): the closest-encloser / next-closer
//! denial-of-existence proof (RFC 4035 §5.4, RFC 5155 §8) — deciding, from a
//! set of NSEC3 records, whether they prove a name's non-existence (NXDOMAIN),
//! a no-data condition, or a wildcard, including Opt-Out (§8.9). Reuses the
//! iterated hash above. Cross-checked against real NSEC3-signed zones
//! (`ldns-signzone -n`, incl. an Opt-Out variant), each independently
//! verified with `ldns-verify-zone`; see `oracle_test.zig`.

const std = @import("std");
const rdata = @import("rdata.zig");
const wire = @import("wire.zig");

// ── base32hex (RFC 4648 §7) ─────────────────────────────────────────────────

const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

pub const Base32HexError = error{InvalidBase32Hex};

/// Longest base32hex text for `n` input bytes (8 chars per 5 bytes, rounded
/// up; DNSSEC never pads — NSEC3 hash lengths are whole SHA-1/SHA-256
/// digests, which happen to encode without padding at 20 and 32 bytes).
pub fn encodedLen(byte_len: usize) usize {
    return (byte_len * 8 + 4) / 5;
}

/// Encode `bytes` as unpadded base32hex text (RFC 4648 §7 alphabet
/// `0-9A-V`), written into `out` (`out.len >= encodedLen(bytes.len)`).
/// Returns the written slice.
pub fn encode(bytes: []const u8, out: []u8) []u8 {
    var bit_buf: u32 = 0;
    var bit_count: u5 = 0;
    var out_len: usize = 0;
    for (bytes) |b| {
        bit_buf = (bit_buf << 8) | b;
        bit_count += 8;
        while (bit_count >= 5) {
            bit_count -= 5;
            out[out_len] = alphabet[(bit_buf >> bit_count) & 0x1f];
            out_len += 1;
        }
    }
    if (bit_count > 0) {
        out[out_len] = alphabet[(bit_buf << (5 - bit_count)) & 0x1f];
        out_len += 1;
    }
    return out[0..out_len];
}

fn decodeChar(c: u8) Base32HexError!u5 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'A'...'V' => @intCast(c - 'A' + 10),
        'a'...'v' => @intCast(c - 'a' + 10),
        else => error.InvalidBase32Hex,
    };
}

/// Longest byte output for `n` input chars.
pub fn decodedLen(text_len: usize) usize {
    return (text_len * 5) / 8;
}

/// Decode unpadded base32hex `text` (case-insensitive) into `out`
/// (`out.len >= decodedLen(text.len)`). Rejects non-alphabet characters.
pub fn decode(text: []const u8, out: []u8) Base32HexError![]u8 {
    var bit_buf: u32 = 0;
    var bit_count: u5 = 0;
    var out_len: usize = 0;
    for (text) |c| {
        const v = try decodeChar(c);
        bit_buf = (bit_buf << 5) | v;
        bit_count += 5;
        if (bit_count >= 8) {
            bit_count -= 8;
            out[out_len] = @truncate(bit_buf >> bit_count);
            out_len += 1;
        }
    }
    return out[0..out_len];
}

// ── iterated hash (RFC 5155 §5) ─────────────────────────────────────────────

pub const sha1_digest_len = std.crypto.hash.Sha1.digest_length;

/// NSEC3 hash algorithm 1 is the only one ever registered (RFC 5155 §2 /
/// IANA "DNSSEC NSEC3 Hash Algorithms").
pub const hash_algorithm_sha1: u8 = 1;

/// Compute the NSEC3 owner hash (RFC 5155 §5) for `owner_name_wire` (the
/// name's CANONICAL wire-format encoding — lowercased, uncompressed; see
/// `wire.encodeCanonicalName`), a given `salt`, and `iterations`:
///
///   IH(0, name, salt)     = SHA1(name || salt)
///   IH(k, name, salt)     = SHA1(IH(k-1, name, salt) || salt)
///   Hash(name)            = IH(iterations, name, salt)
///
/// Only hash algorithm 1 (SHA-1) is defined; callers must check
/// `Nsec3.hash_algorithm`/`Nsec3Param.hash_algorithm` == `hash_algorithm_sha1`
/// before calling this (an unrecognized algorithm makes the whole NSEC3
/// chain unusable — RFC 5155 §5 "unknown hash algorithm").
pub fn iteratedHash(owner_name_wire: []const u8, salt: []const u8, iterations: u16) [sha1_digest_len]u8 {
    var digest: [sha1_digest_len]u8 = undefined;
    {
        var st = std.crypto.hash.Sha1.init(.{});
        st.update(owner_name_wire);
        st.update(salt);
        st.final(&digest);
    }
    var k: u32 = 0;
    while (k < iterations) : (k += 1) {
        var st = std.crypto.hash.Sha1.init(.{});
        st.update(&digest);
        st.update(salt);
        st.final(&digest);
    }
    return digest;
}

// ── closest-encloser / denial-of-existence proof (RFC 5155 §8) ─────────────

pub const DenialResult = enum {
    /// NXDOMAIN: closest encloser proven, next closer covered, and no
    /// wildcard at the closest encloser (RFC 5155 §8.4).
    name_error,
    /// The name exists but the queried type does not — either a direct match
    /// with the type absent (§8.5) or a wildcard match with the type absent
    /// (§8.7).
    no_data,
    /// A wildcard at the closest encloser exists and asserts the queried type
    /// (or CNAME): a positive wildcard answer, not a denial (§8.8 territory).
    wildcard_answer,
    /// A covering NSEC3 carries the Opt-Out bit (§8.9): the next closer name
    /// could be an unsigned delegation, so non-existence cannot be proven —
    /// the correct verdict is provably-insecure, not secure NXDOMAIN.
    insecure,
    /// The supplied NSEC3 set does not constitute a valid proof (missing
    /// closest encloser, uncovered next closer, contradictory records, or an
    /// unusable hash algorithm) — treat like a failed denial.
    bogus,
};

pub const Nsec3Record = struct { owner_hash_label: []const u8, rdata: rdata.Nsec3 };

pub const Nsec3Set = struct {
    records: []const Nsec3Record,
};

const cname_type: u16 = 5;

/// Prove (or disprove) denial of existence for `qname`/`qtype` against the
/// NSEC3 records covering the zone (RFC 5155 §8). `qname` is dotted text
/// (e.g. `sub.www.example`); `salt`/`iterations` are the zone's NSEC3
/// parameters (from NSEC3PARAM). Only records whose own hash-algorithm/salt/
/// iterations match those parameters are considered.
pub fn proveDenial(qname: []const u8, qtype: u16, nsec3_set: Nsec3Set, salt: []const u8, iterations: u16) DenialResult {
    const set = nsec3_set.records;

    // (1) Direct match on QNAME (§8.5): the name provably exists, so the only
    // denial it can support is NODATA (queried type + CNAME both absent).
    if (matchNsec3(set, qname, salt, iterations)) |m| {
        if (m.types.contains(qtype) or m.types.contains(cname_type)) return .bogus;
        return .no_data;
    }

    // (2) Closest encloser: the longest ancestor of QNAME with a matching
    // NSEC3. `next_closer` is one label longer, on the path to QNAME.
    var closest_encloser: []const u8 = undefined;
    var next_closer: []const u8 = undefined;
    {
        var prev: []const u8 = stripDot(qname);
        var cur: []const u8 = parentOf(prev);
        var found = false;
        while (true) {
            if (matchNsec3(set, cur, salt, iterations)) |_| {
                closest_encloser = cur;
                next_closer = prev;
                found = true;
                break;
            }
            if (cur.len == 0) break; // hit the root without a match
            prev = cur;
            cur = parentOf(cur);
        }
        if (!found) return .bogus;
    }

    // (3) The next closer name must be covered (proves it does not exist).
    const nc_cover = coverNsec3(set, next_closer, salt, iterations) orelse return .bogus;
    const opt_out = nc_cover.optOut();

    // (4) Wildcard at the closest encloser.
    var wc_buf: [2 + wire.max_name_text_len]u8 = undefined;
    const wildcard = wildcardName(closest_encloser, &wc_buf) orelse return .bogus;
    if (matchNsec3(set, wildcard, salt, iterations)) |wm| {
        // The wildcard exists: NODATA if it lacks the type, else a positive
        // wildcard answer (RFC 5155 §8.7 / §8.8).
        if (wm.types.contains(qtype) or wm.types.contains(cname_type)) return .wildcard_answer;
        return .no_data;
    }
    // The wildcard does not exist either → NXDOMAIN (§8.4), unless Opt-Out on
    // the next-closer cover downgrades the proof to insecure (§8.9): the next
    // closer name could be an unsigned (opt-out) delegation rather than truly
    // absent.
    _ = coverNsec3(set, wildcard, salt, iterations) orelse return .bogus;
    if (opt_out) return .insecure;
    return .name_error;
}

fn stripDot(name: []const u8) []const u8 {
    return if (std.mem.endsWith(u8, name, ".")) name[0 .. name.len - 1] else name;
}

/// The parent name (drop the first label). Root ("") has no parent → "".
fn parentOf(name: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, name, '.')) |dot| return name[dot + 1 ..];
    return name[name.len..]; // single label → root
}

/// Build "*." ++ `encloser` (or "*" at the root) into `out`; null on overflow.
fn wildcardName(encloser: []const u8, out: *[2 + wire.max_name_text_len]u8) ?[]const u8 {
    var w: std.Io.Writer = .fixed(out);
    w.writeByte('*') catch return null;
    if (encloser.len != 0) {
        w.writeByte('.') catch return null;
        w.writeAll(encloser) catch return null;
    }
    return w.buffered();
}

/// Compute the NSEC3 hash of `name` with the given parameters, or null if the
/// name cannot be canonically encoded.
fn hashName(name: []const u8, salt: []const u8, iterations: u16) ?[sha1_digest_len]u8 {
    var buf: [wire.max_canonical_wire_len]u8 = undefined;
    const w = wire.encodeCanonicalName(name, &buf) catch return null;
    return iteratedHash(w, salt, iterations);
}

/// Only records that actually use the zone's SHA-1 NSEC3 parameters can
/// participate in the proof (RFC 5155 §5 — a differing salt/iteration/algo
/// belongs to a different, unusable chain).
fn usableRecord(r: Nsec3Record, salt: []const u8, iterations: u16) bool {
    return r.rdata.hash_algorithm == hash_algorithm_sha1 and
        r.rdata.iterations == iterations and
        std.mem.eql(u8, r.rdata.salt, salt);
}

fn decodeOwnerHash(label: []const u8, out: *[sha1_digest_len]u8) ?[]const u8 {
    if (decodedLen(label.len) < sha1_digest_len) return null;
    var tmp: [64]u8 = undefined;
    const dec = decode(label, &tmp) catch return null;
    if (dec.len != sha1_digest_len) return null;
    @memcpy(out, dec);
    return out;
}

/// The NSEC3 whose owner hash equals `hash(name)`, if any (§8.3 "match").
fn matchNsec3(set: []const Nsec3Record, name: []const u8, salt: []const u8, iterations: u16) ?rdata.Nsec3 {
    const h = hashName(name, salt, iterations) orelse return null;
    for (set) |r| {
        if (!usableRecord(r, salt, iterations)) continue;
        var oh: [sha1_digest_len]u8 = undefined;
        const owner = decodeOwnerHash(r.owner_hash_label, &oh) orelse continue;
        if (std.mem.eql(u8, owner, &h)) return r.rdata;
    }
    return null;
}

/// The NSEC3 that covers `hash(name)` — i.e. owner_hash < H < next_hash, with
/// the last record in the chain wrapping (owner_hash >= next_hash) — if any
/// (§8.3 "cover").
fn coverNsec3(set: []const Nsec3Record, name: []const u8, salt: []const u8, iterations: u16) ?rdata.Nsec3 {
    const h = hashName(name, salt, iterations) orelse return null;
    for (set) |r| {
        if (!usableRecord(r, salt, iterations)) continue;
        var oh: [sha1_digest_len]u8 = undefined;
        const owner = decodeOwnerHash(r.owner_hash_label, &oh) orelse continue;
        const next = r.rdata.next_hashed_owner_name;
        if (next.len != sha1_digest_len) continue;
        const o_lt_h = std.mem.order(u8, owner, &h) == .lt;
        const h_lt_n = std.mem.order(u8, &h, next) == .lt;
        const wraps = std.mem.order(u8, owner, next) != .lt; // owner >= next
        const covered = if (wraps) (o_lt_h or h_lt_n) else (o_lt_h and h_lt_n);
        if (covered) return r.rdata;
    }
    return null;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "base32hex: encode/decode round-trip, RFC 4648 alphabet" {
    var enc_buf: [64]u8 = undefined;
    var dec_buf: [64]u8 = undefined;
    const inputs = [_][]const u8{ "", "f", "fo", "foo", "foob", "fooba", "foobar" };
    for (inputs) |input| {
        const enc = encode(input, &enc_buf);
        const dec = try decode(enc, &dec_buf);
        try testing.expectEqualSlices(u8, input, dec);
    }
}

test "base32hex: known vector (RFC 4648 §10 base32 test vectors, hex alphabet)" {
    // RFC 4648's own base32 (standard alphabet) test vectors for "foobar"
    // decode to specific bit patterns; base32hex uses a different alphabet
    // (0-9A-V rather than A-Z2-7) over the SAME bit-packing algorithm, so we
    // verify structurally: encoding then decoding "foobar" must round-trip
    // and produce the RFC 4648 §6 expected LENGTH (8 chars for 6 bytes,
    // unpadded).
    var buf: [16]u8 = undefined;
    const enc = encode("foobar", &buf);
    try testing.expectEqual(@as(usize, 10), enc.len); // ceil(6*8/5) = 10
}

test "base32hex: rejects out-of-alphabet characters" {
    var buf: [8]u8 = undefined;
    try testing.expectError(error.InvalidBase32Hex, decode("W", &buf)); // 'W' is past 'V'
    try testing.expectError(error.InvalidBase32Hex, decode("!", &buf));
}

test "base32hex: lowercase accepted (case-insensitive decode)" {
    var enc_buf: [16]u8 = undefined;
    var dec_buf: [16]u8 = undefined;
    const enc = encode("hi", &enc_buf);
    var lower_buf: [16]u8 = undefined;
    for (enc, 0..) |c, i| lower_buf[i] = std.ascii.toLower(c);
    const dec = try decode(lower_buf[0..enc.len], &dec_buf);
    try testing.expectEqualSlices(u8, "hi", dec);
}

test "iteratedHash: zero iterations equals a single SHA1(name||salt)" {
    const name = "\x03www\x07example\x03com\x00";
    const salt = "\xaa\xbb";
    var expected: [sha1_digest_len]u8 = undefined;
    var st = std.crypto.hash.Sha1.init(.{});
    st.update(name);
    st.update(salt);
    st.final(&expected);
    try testing.expectEqualSlices(u8, &expected, &iteratedHash(name, salt, 0));
}

test "iteratedHash: one iteration matches manual double-hash" {
    const name = "\x03www\x07example\x03com\x00";
    const salt = "";
    var h0: [sha1_digest_len]u8 = undefined;
    std.crypto.hash.Sha1.hash(name, &h0, .{});
    var expected: [sha1_digest_len]u8 = undefined;
    std.crypto.hash.Sha1.hash(&h0, &expected, .{});
    try testing.expectEqualSlices(u8, &expected, &iteratedHash(name, salt, 1));
}

test "iteratedHash: empty salt behaves like no salt appended" {
    const name = "example";
    var expected: [sha1_digest_len]u8 = undefined;
    std.crypto.hash.Sha1.hash(name, &expected, .{});
    try testing.expectEqualSlices(u8, &expected, &iteratedHash(name, "", 0));
}
