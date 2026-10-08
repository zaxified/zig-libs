// SPDX-License-Identifier: MIT

//! stream — the version-2 wire format: the same two locks and the same AND
//! as `envelope.zig`'s version 1, with the content cut into an age-style
//! STREAM so a payload of any size is sealed and opened in bounded memory
//! over `std.Io.Reader` / `std.Io.Writer`.
//!
//! ```
//! magic "TLE1" | version 2 | suite_id | flags | round (u64 LE)   15 bytes
//! tlock_ct (128)                                                  the time lock
//! hqc_ct (Kem.ct_bytes)                                           the PQ lock
//! chunk_0 || chunk_1 || … || chunk_last                           STREAM payload
//! ```
//!
//! - **Key.** `K = HKDF-SHA256(salt = stream_kdf_salt, ikm = s_time ||
//!   s_pq, info = "TLE2-stream-key" || version || suite_id || u64be(round) ||
//!   SHA-256(header || tlock_ct || hqc_ct))`. Both lock secrets bind the
//!   key exactly as in version 1; the transcript hash in `info` stands in
//!   for version 1's AEAD AAD, so a change to any header or lock byte gives
//!   a different `K` and the first chunk fails its tag (`AuthFailed`).
//! - **Payload.** `tlock.age.PayloadStream` — the age STREAM `tlock`'s
//!   `.tle` decryptor uses and that is byte-exact against drand's Go `tle`:
//!   64 KiB chunks, ChaCha20-Poly1305, nonce `BE88(counter) || last_flag`.
//!   The last chunk may be full; it is empty only when the whole payload
//!   is. Truncation at a chunk boundary, reordering, a dropped or appended
//!   chunk all fail a tag.
//! - **No nonce on the wire**, as in version 1: `K` is unique per seal
//!   because `s_time` and the KEM coins are fresh per seal, and the chunk
//!   nonce is a counter under that key. The same `SealRandomness` reuse
//!   caveat applies (see `envelope.DerivedKeys`).
//!
//! ⚠ **Streaming release.** `openStream` writes each chunk as soon as its
//! own tag verifies, so every byte written is authentic and in order — but
//! the payload is COMPLETE only when `openStream` returns without error. On
//! an error the caller must discard what was written (a truncated or
//! tampered tail is detected only when it is reached). This is age's
//! property too.

const std = @import("std");
const tlock = @import("tlock");
const hqc = @import("hqc");
const envelope = @import("envelope.zig");
const burn = @import("burn.zig");

const bls12_381 = tlock.bls12_381;
const g1 = bls12_381.g1;
const g2 = bls12_381.g2;
const age = tlock.age;
const PayloadStream = age.PayloadStream;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Wire-format version of the streaming format (version 1 is `envelope`'s
/// one-shot format; each parser refuses the other's with
/// `error.UnsupportedVersion`).
pub const stream_version: u8 = 2;
/// Plaintext bytes per STREAM chunk (64 KiB, age's).
pub const chunk_bytes = age.chunk_bytes;
/// Wire bytes per full STREAM chunk (plaintext + Poly1305 tag).
pub const sealed_chunk_bytes = age.sealed_chunk_bytes;
pub const tag_bytes = age.tag_bytes;
/// HKDF salt for version 2 — distinct from version 1's, so the two formats
/// never derive the same key from the same lock secrets.
pub const stream_kdf_salt = "timelock_envelope:v2:hybrid-AND-stream:hkdf-sha256";
/// HKDF `info` prefix for version 2 (see `deriveStreamKey`).
pub const stream_kdf_info_label = "TLE2-stream-key";
/// `magic(4) || version(1) || suite_id(1) || flags(1) || round_le(8)`.
pub const stream_header_bytes: usize = 4 + 1 + 1 + 1 + 8;

const round_off = 7;

/// Errors `sealStream` can return.
pub const StreamSealError = std.mem.Allocator.Error || error{ ReadFailed, WriteFailed };

/// Errors `openStream` can return. Every malformed or under-authorized
/// input maps to one of these; nothing panics or reads past the input.
pub const StreamOpenError = std.mem.Allocator.Error || error{
    ReadFailed,
    WriteFailed,
    /// The stream ended inside the header or the two lock ciphertexts.
    Truncated,
    BadMagic,
    UnsupportedVersion,
    SuiteMismatch,
    MalformedTimeLock,
    TimeGateClosed,
    /// The payload is empty (not even the one chunk an empty plaintext
    /// seals to) or its last chunk is shorter than a tag, or empty after a
    /// non-empty chunk.
    MalformedPayload,
    /// A chunk failed its tag: wrong HQC key, a tampered header or lock
    /// (different key), a tampered/reordered/dropped chunk, or truncation
    /// at a chunk boundary.
    AuthFailed,
};

/// `HKDF-SHA256` over `ikm = s_time || s_pq`, `info = label || version ||
/// suite_id || u64be(round) || transcript_hash`, 32 octets: the STREAM key.
/// `transcript_hash` is `SHA-256` of the header and both lock ciphertexts.
///
/// The key is written to `out`; the secrets come in by pointer, and the body
/// runs one frame down and is burned after (`burn.zig`).
pub fn deriveStreamKey(
    out: *[32]u8,
    s_time: *const [envelope.time_secret_bytes]u8,
    s_pq: *const [hqc.params.shared_secret_bytes]u8,
    suite_id: u8,
    round: u64,
    transcript_hash: *const [Sha256.digest_length]u8,
) void {
    burn.run(burn.kdf_burn, void, deriveStreamKeyBody, .{ out, s_time, s_pq, suite_id, round, transcript_hash });
}

fn deriveStreamKeyBody(
    out: *[32]u8,
    s_time: *const [envelope.time_secret_bytes]u8,
    s_pq: *const [hqc.params.shared_secret_bytes]u8,
    suite_id: u8,
    round: u64,
    transcript_hash: *const [Sha256.digest_length]u8,
) void {
    var ikm: [envelope.time_secret_bytes + hqc.params.shared_secret_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &ikm);
    @memcpy(ikm[0..envelope.time_secret_bytes], s_time);
    @memcpy(ikm[envelope.time_secret_bytes..], s_pq);
    var prk = Hkdf.extract(stream_kdf_salt, &ikm);
    defer std.crypto.secureZero(u8, &prk);

    const l = stream_kdf_info_label.len;
    var info: [l + 1 + 1 + 8 + Sha256.digest_length]u8 = undefined;
    @memcpy(info[0..l], stream_kdf_info_label);
    info[l] = stream_version;
    info[l + 1] = suite_id;
    std.mem.writeInt(u64, info[l + 2 ..][0..8], round, .big);
    @memcpy(info[l + 10 ..], transcript_hash);

    Hkdf.expand(out, &info, prk);
}

/// The streaming seal/open pair for one HQC parameter set; reached as
/// `Envelope(Kem).sealStream` / `.openStream`.
pub fn Stream(comptime Kem: type) type {
    const Env = envelope.Envelope(Kem);
    return struct {
        /// Header plus both lock ciphertexts — everything before the payload.
        pub const prefix_bytes: usize = stream_header_bytes + Env.time_lock_bytes + Env.pq_lock_bytes;

        /// Total wire size of a `len`-byte plaintext.
        pub fn sealedLen(len: usize) usize {
            return prefix_bytes + age.sealedLen(len);
        }

        /// Read `reader` to its end and write the sealed stream to `writer`
        /// (not flushed — the caller owns the writer). Memory is bounded:
        /// one allocation of about two chunks (`gpa`), freed before return.
        pub fn seal(
            gpa: std.mem.Allocator,
            writer: *std.Io.Writer,
            reader: *std.Io.Reader,
            recipient_ek: *const Kem.EncapsKey,
            p_pub: g2.Affine,
            round: u64,
            rnd: *const Env.SealRandomness,
        ) StreamSealError!void {
            return burn.run(burn.envelope_burn, StreamSealError!void, sealBody, .{ gpa, writer, reader, recipient_ek, p_pub, round, rnd });
        }

        fn sealBody(
            gpa: std.mem.Allocator,
            writer: *std.Io.Writer,
            reader: *std.Io.Reader,
            recipient_ek: *const Kem.EncapsKey,
            p_pub: g2.Affine,
            round: u64,
            rnd: *const Env.SealRandomness,
        ) StreamSealError!void {
            const buf = try gpa.alloc(u8, chunk_bytes + 1 + sealed_chunk_bytes);
            defer {
                std.crypto.secureZero(u8, buf);
                gpa.free(buf);
            }

            const tl = tlock.encrypt(p_pub, round, &rnd.s_time, &rnd.tlock_sigma);
            var enc: struct { ct: Kem.Ciphertext, ss: Kem.SharedSecret } = undefined;
            defer std.crypto.secureZero(u8, &enc.ss);
            Kem.encaps(&enc.ct, &enc.ss, recipient_ek, &rnd.kem_coins);

            var prefix: [prefix_bytes]u8 = undefined;
            @memcpy(prefix[0..4], &envelope.magic);
            prefix[4] = stream_version;
            prefix[5] = Env.suite_id;
            prefix[6] = 0; // flags (reserved; bound into the key via the transcript)
            std.mem.writeInt(u64, prefix[round_off..][0..8], round, .little);
            @memcpy(prefix[stream_header_bytes..][0..Env.time_lock_bytes], &tl.toBytes());
            @memcpy(prefix[stream_header_bytes + Env.time_lock_bytes ..], &enc.ct);

            var th: [Sha256.digest_length]u8 = undefined;
            Sha256.hash(&prefix, &th, .{});
            var stream_key: [32]u8 = undefined;
            deriveStreamKeyBody(&stream_key, &rnd.s_time, &enc.ss, Env.suite_id, round, &th);
            defer std.crypto.secureZero(u8, &stream_key);
            var ps: PayloadStream = undefined;
            ps.init(&stream_key);
            defer ps.wipe();

            try writer.writeAll(&prefix);

            // One byte of lookahead decides whether a full chunk is the
            // last one: read `chunk_bytes + 1`; if that many arrived, seal
            // the first `chunk_bytes` as non-last and carry the extra byte.
            const in = buf[0 .. chunk_bytes + 1];
            const out = buf[chunk_bytes + 1 ..];
            var have: usize = 0;
            while (true) {
                have += try reader.readSliceShort(in[have..]);
                const last = have <= chunk_bytes;
                const n = if (last) have else chunk_bytes;
                ps.sealChunk(out[0 .. n + tag_bytes], in[0..n], last);
                try writer.writeAll(out[0 .. n + tag_bytes]);
                if (last) return;
                in[0] = in[chunk_bytes];
                have = 1;
            }
        }

        /// Read a sealed stream from `reader` and write the plaintext to
        /// `writer` (not flushed), chunk by chunk. Recovers the plaintext
        /// only when BOTH locks open. ⚠ See the module doc: on an error,
        /// discard whatever was already written.
        pub fn open(
            gpa: std.mem.Allocator,
            writer: *std.Io.Writer,
            reader: *std.Io.Reader,
            recipient_dk: *const Kem.DecapsKey,
            round_signature: g1.Affine,
        ) StreamOpenError!void {
            return burn.run(burn.envelope_burn, StreamOpenError!void, openBody, .{ gpa, writer, reader, recipient_dk, round_signature });
        }

        fn openBody(
            gpa: std.mem.Allocator,
            writer: *std.Io.Writer,
            reader: *std.Io.Reader,
            recipient_dk: *const Kem.DecapsKey,
            round_signature: g1.Affine,
        ) StreamOpenError!void {
            var prefix: [prefix_bytes]u8 = undefined;
            const got = try reader.readSliceShort(&prefix);
            if (got < stream_header_bytes) return error.Truncated;
            if (!std.mem.eql(u8, prefix[0..4], &envelope.magic)) return error.BadMagic;
            if (prefix[4] != stream_version) return error.UnsupportedVersion;
            if (prefix[5] != Env.suite_id) return error.SuiteMismatch;
            if (got != prefix_bytes) return error.Truncated;
            const round = std.mem.readInt(u64, prefix[round_off..][0..8], .little);

            const tl = tlock.Ciphertext.fromBytes(prefix[stream_header_bytes..][0..Env.time_lock_bytes].*) catch
                return error.MalformedTimeLock;
            var s_time: [tlock.block_bytes]u8 = undefined;
            tlock.decrypt(&s_time, round_signature, tl) catch return error.TimeGateClosed;
            defer std.crypto.secureZero(u8, &s_time);
            // Implicit rejection: a wrong key gives a pseudo-random s_pq,
            // which surfaces as AuthFailed on the first chunk.
            var s_pq: Kem.SharedSecret = undefined;
            Kem.decaps(&s_pq, recipient_dk, prefix[stream_header_bytes + Env.time_lock_bytes ..][0..Env.pq_lock_bytes]);
            defer std.crypto.secureZero(u8, &s_pq);

            var th: [Sha256.digest_length]u8 = undefined;
            Sha256.hash(&prefix, &th, .{});
            var stream_key: [32]u8 = undefined;
            deriveStreamKeyBody(&stream_key, &s_time, &s_pq, Env.suite_id, round, &th);
            defer std.crypto.secureZero(u8, &stream_key);
            var ps: PayloadStream = undefined;
            ps.init(&stream_key);
            defer ps.wipe();

            const buf = try gpa.alloc(u8, sealed_chunk_bytes + 1 + chunk_bytes);
            defer {
                std.crypto.secureZero(u8, buf);
                gpa.free(buf);
            }
            const in = buf[0 .. sealed_chunk_bytes + 1];
            const out = buf[sealed_chunk_bytes + 1 ..];
            var have: usize = 0;
            while (true) {
                have += try reader.readSliceShort(in[have..]);
                const last = have <= sealed_chunk_bytes;
                const c = if (last) in[0..have] else in[0..sealed_chunk_bytes];
                if (c.len < tag_bytes) return error.MalformedPayload;
                const n = c.len - tag_bytes;
                ps.openChunk(out[0..n], c, last) catch |err| return switch (err) {
                    error.MalformedPayload => error.MalformedPayload,
                    error.PayloadAuthenticationFailed => error.AuthFailed,
                };
                try writer.writeAll(out[0..n]);
                if (last) return;
                in[0] = in[sealed_chunk_bytes];
                have = 1;
            }
        }
    };
}

// ── tests ────────────────────────────────────────────────────────────

const testing = std.testing;

test "deriveStreamKey matches an independent Python HKDF recomputation" {
    // Python hmac/hashlib, 2026-10-06: HKDF-SHA256(salt = stream_kdf_salt,
    // ikm = 0xA1^16 || 0xB2^32, info = "TLE2-stream-key" || 0x02 || 0x10 ||
    // be64(42) || 0xC3^32), 32 octets.
    const k = deriveStreamKeyV([_]u8{0xA1} ** 16, [_]u8{0xB2} ** 32, 16, 42, [_]u8{0xC3} ** 32);
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "01c4b91de51f4744107c149831848382412854ed7747b20f9130711bbbeaa44d");
    try testing.expectEqualSlices(u8, &want, &k);
}

test "deriveStreamKey: each input separates the key, and it never equals version 1's" {
    const base = deriveStreamKeyV([_]u8{0xA1} ** 16, [_]u8{0xB2} ** 32, 16, 42, [_]u8{0xC3} ** 32);
    const variants = [_][32]u8{
        deriveStreamKeyV([_]u8{0} ** 16, [_]u8{0xB2} ** 32, 16, 42, [_]u8{0xC3} ** 32),
        deriveStreamKeyV([_]u8{0xA1} ** 16, [_]u8{0} ** 32, 16, 42, [_]u8{0xC3} ** 32),
        deriveStreamKeyV([_]u8{0xA1} ** 16, [_]u8{0xB2} ** 32, 32, 42, [_]u8{0xC3} ** 32),
        deriveStreamKeyV([_]u8{0xA1} ** 16, [_]u8{0xB2} ** 32, 16, 43, [_]u8{0xC3} ** 32),
        deriveStreamKeyV([_]u8{0xA1} ** 16, [_]u8{0xB2} ** 32, 16, 42, [_]u8{0xC4} ** 32),
        blk: {
            var k: envelope.DerivedKeys = undefined;
            envelope.deriveKeys(&k, &([_]u8{0xA1} ** 16), &([_]u8{0xB2} ** 32), 16, 42);
            break :blk k.key;
        },
    };
    for (variants) |v| try testing.expect(!std.mem.eql(u8, &base, &v));
}

/// Test helper: the stream key as a value.
fn deriveStreamKeyV(s_time: [envelope.time_secret_bytes]u8, s_pq: [hqc.params.shared_secret_bytes]u8, suite: u8, round: u64, th: [Sha256.digest_length]u8) [32]u8 {
    var k: [32]u8 = undefined;
    deriveStreamKey(&k, &s_time, &s_pq, suite, round, &th);
    return k;
}
