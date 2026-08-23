// SPDX-License-Identifier: MIT

//! What a Privacy-Pass-style anonymous-token client and issuer do with
//! `blindrsa`: the issuer signs a blinded message it never sees, the
//! client unblinds and verifies, and neither the issuer's own records nor
//! a network observer can link a given `blinded_msg` to the `sig` it
//! eventually became. Drives both roles (client: `blind`/`finalize`,
//! server: `blindSign`) across THREE independent token requests — two
//! under the RECOMMENDED `RSABSSA-SHA384-PSS-Randomized` variant (fresh
//! salt AND fresh `prepareRandomize` prefix each time) and one under
//! `RSABSSA-SHA384-PSSZERO-Deterministic` (`salt_len = 0`,
//! `prepareIdentity`) — the module's own table of four variants names
//! both as real configurations, not just the RFC 9474 Appendix A KAT's
//! fixed choice.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! no `test_deps`, no access to anything the module does not export).
//!
//! No `std.heap.DebugAllocator`: every `blindrsa` entry point (`blind`,
//! `blindSign`, `finalize`, `verify`) writes into a caller-supplied
//! fixed-size buffer (`[max_modulus_len]u8` throughout this file) and
//! returns a subslice of it — there is no allocator parameter anywhere in
//! this module's public API, so there is nothing for a leak detector to
//! watch.
//!
//! `modules/blindrsa/src/kat_test.zig` already drives RFC 9474 Appendix
//! A.1 (PSS-Randomized) and A.4 (PSSZERO-Deterministic) byte-exact,
//! including every published intermediate (`encoded_msg`, `r`, `inv`,
//! `blinded_msg`, `blind_sig`, `sig`) — this file does NOT restate that
//! table, and deliberately uses a FRESH `rsa.generate()` keypair (1024
//! bits — small purely for this example's runtime, `rsa` itself is
//! exercised at realistic sizes in its own test suite) rather than the
//! RFC's fixed 4096-bit modulus.
//!
//! External oracle: NONE was run. RFC 9474 is new enough (published 2023)
//! and its exact composite-modulus blinding construction specific enough
//! that no maintained, license-clear Python package implementing RSABSSA
//! specifically (as opposed to plain RSA-PSS, which every TLS library
//! has) was found in this sandbox without native compilation. RFC 9474
//! Appendix A's official vectors remain the real external judge for
//! byte-exact correctness, already exercised at the module level; this
//! file instead exercises the two-party sequencing, buffer-ownership, and
//! unlinkability properties a fixed-vector KAT test cannot — a fresh key
//! per run, fresh blinding per request, and the mandatory fail-closed
//! checks on both the signer's and the client's side.

const std = @import("std");
const blindrsa = @import("blindrsa");
const rsa = @import("rsa");
const Sha384 = std.crypto.hash.sha2.Sha384;

pub fn main() !void {
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x5a} ** 32);
    const random = csprng.random();

    // ── issuer setup (once) ─────────────────────────────────────────────
    // 1024 bits is the smallest modulus that fits a full SHA-384 PSS
    // encoding (em_len >= hLen + sLen + 2 = 48 + 48 + 2 = 98 bytes => >=
    // 784 bits), rounded up purely for this example's speed.
    const kp = try rsa.generate(random, 1024, 65537);

    // ── request 1: RSABSSA-SHA384-PSS-Randomized ────────────────────────
    const msg1 = "anonymous-token request #1";
    var prep_buf1: [blindrsa.randomizer_len + msg1.len]u8 = undefined;
    const prepared1 = blindrsa.prepareRandomize(msg1, random, &prep_buf1);
    var salt1: [Sha384.digest_length]u8 = undefined;
    random.bytes(&salt1);

    var ctx1: blindrsa.Context = undefined;
    var blinded_buf1: [blindrsa.max_modulus_len]u8 = undefined;
    const blinded1 = try blindrsa.blind(kp.public_key, Sha384, prepared1, &salt1, random, &ctx1, &blinded_buf1);

    // Server/issuer: signs the opaque blinded integer, never seeing
    // `prepared1` or `msg1` at all.
    var blind_sig_buf1: [blindrsa.max_modulus_len]u8 = undefined;
    const blind_sig1 = try blindrsa.blindSign(kp.secret_key, kp.public_key, random, blinded1, &blind_sig_buf1);

    // Client: unblind + the mandatory trailing verify, fused in `finalize`.
    var sig_buf1: [blindrsa.max_modulus_len]u8 = undefined;
    const sig1 = try blindrsa.finalize(kp.public_key, Sha384, blind_sig1, &ctx1, &sig_buf1);
    // A relying party who only has (pk, prepared_msg, sig) can check it
    // independently of the client/issuer exchange that produced it.
    try blindrsa.verify(kp.public_key, Sha384, prepared1, sig1, salt1.len);
    std.debug.print("request 1 (PSS-Randomized): token issued and verifies\n", .{});

    // ── request 2: same variant, SECOND independent session ─────────────
    // Fresh randomizer prefix, fresh salt, fresh blinding factor — nothing
    // from session 1 may leak into this one.
    const msg2 = "anonymous-token request #2";
    var prep_buf2: [blindrsa.randomizer_len + msg2.len]u8 = undefined;
    const prepared2 = blindrsa.prepareRandomize(msg2, random, &prep_buf2);
    var salt2: [Sha384.digest_length]u8 = undefined;
    random.bytes(&salt2);

    var ctx2: blindrsa.Context = undefined;
    var blinded_buf2: [blindrsa.max_modulus_len]u8 = undefined;
    const blinded2 = try blindrsa.blind(kp.public_key, Sha384, prepared2, &salt2, random, &ctx2, &blinded_buf2);
    std.debug.assert(!std.mem.eql(u8, blinded1, blinded2));

    var blind_sig_buf2: [blindrsa.max_modulus_len]u8 = undefined;
    const blind_sig2 = try blindrsa.blindSign(kp.secret_key, kp.public_key, random, blinded2, &blind_sig_buf2);

    var sig_buf2: [blindrsa.max_modulus_len]u8 = undefined;
    const sig2 = try blindrsa.finalize(kp.public_key, Sha384, blind_sig2, &ctx2, &sig_buf2);
    try blindrsa.verify(kp.public_key, Sha384, prepared2, sig2, salt2.len);
    std.debug.assert(!std.mem.eql(u8, sig1, sig2));
    std.debug.print("request 2 (PSS-Randomized): independent token, distinct from request 1\n", .{});

    // Unlinkability sanity: blinding the SAME message again (a THIRD call)
    // still yields a fresh, unrelated blinded_msg — the issuer genuinely
    // cannot tell "same underlying message, blinded twice" from "two
    // different messages" by comparing blinded_msg bytes.
    var prep_buf1b: [blindrsa.randomizer_len + msg1.len]u8 = undefined;
    const prepared1b = blindrsa.prepareRandomize(msg1, random, &prep_buf1b);
    var salt1b: [Sha384.digest_length]u8 = undefined;
    random.bytes(&salt1b);
    var ctx1b: blindrsa.Context = undefined;
    var blinded_buf1b: [blindrsa.max_modulus_len]u8 = undefined;
    const blinded1b = try blindrsa.blind(kp.public_key, Sha384, prepared1b, &salt1b, random, &ctx1b, &blinded_buf1b);
    std.debug.assert(!std.mem.eql(u8, blinded1, blinded1b));
    std.debug.print("re-blinding the same underlying message: unrelated blinded_msg (unlinkability)\n", .{});

    // ── request 3: RSABSSA-SHA384-PSSZERO-Deterministic ─────────────────
    // salt_len = 0, prepareIdentity (no randomizer prefix) — the module's
    // OTHER real variant, not just the PSS-Randomized one the first two
    // requests used.
    const msg3 = "anonymous-token request #3 (deterministic variant)";
    const prepared3 = blindrsa.prepareIdentity(msg3);
    var ctx3: blindrsa.Context = undefined;
    var blinded_buf3: [blindrsa.max_modulus_len]u8 = undefined;
    const blinded3 = try blindrsa.blind(kp.public_key, Sha384, prepared3, &.{}, random, &ctx3, &blinded_buf3);

    var blind_sig_buf3: [blindrsa.max_modulus_len]u8 = undefined;
    const blind_sig3 = try blindrsa.blindSign(kp.secret_key, kp.public_key, random, blinded3, &blind_sig_buf3);

    var sig_buf3: [blindrsa.max_modulus_len]u8 = undefined;
    const sig3 = try blindrsa.finalize(kp.public_key, Sha384, blind_sig3, &ctx3, &sig_buf3);
    try blindrsa.verify(kp.public_key, Sha384, prepared3, sig3, 0);
    std.debug.print("request 3 (PSSZERO-Deterministic): token issued and verifies\n", .{});

    // ── negative paths: named errors only ──────────────────────────────

    // (1) A tampered blind_sig: finalize's mandatory trailing verify must
    // fail closed rather than hand back a bad signature.
    var tampered_buf: [blindrsa.max_modulus_len]u8 = undefined;
    @memcpy(tampered_buf[0..blind_sig1.len], blind_sig1);
    tampered_buf[blind_sig1.len / 2] ^= 0x04;
    var out_tampered: [blindrsa.max_modulus_len]u8 = undefined;
    if (blindrsa.finalize(kp.public_key, Sha384, tampered_buf[0..blind_sig1.len], &ctx1, &out_tampered)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.SignatureVerificationFailed => std.debug.print("tampered blind_sig: SignatureVerificationFailed (expected)\n", .{}),
        else => return err,
    }

    // (2) A blind_sig of the wrong length — the real wire-level check
    // (RFC 9474 Finalize step 1), distinct from the MAC/signature failure
    // above.
    var out_wrong_len: [blindrsa.max_modulus_len]u8 = undefined;
    if (blindrsa.finalize(kp.public_key, Sha384, blind_sig1[0 .. blind_sig1.len - 1], &ctx1, &out_wrong_len)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidBlindSignatureLength => std.debug.print("truncated blind_sig: InvalidBlindSignatureLength (expected)\n", .{}),
        else => return err,
    }

    // (3) A blinded_msg of the wrong length reaching the SERVER's own
    // entry point — the real untrusted-input shape blindSign meets.
    var out_bad_blinded: [blindrsa.max_modulus_len]u8 = undefined;
    if (blindrsa.blindSign(kp.secret_key, kp.public_key, random, blinded1[0 .. blinded1.len - 1], &out_bad_blinded)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidBlindedMessage => std.debug.print("truncated blinded_msg at the server: InvalidBlindedMessage (expected)\n", .{}),
        else => return err,
    }

    // (4) `blind` gives up rather than proceed with a non-invertible
    // blinding factor: an RNG rigged to always draw `sk.p` (a real factor
    // of THIS key's own modulus `n`) makes every sampled `r` (and every
    // masking scalar `maskedInvert` draws internally) share that factor,
    // so no retry within the bounded attempt loop can ever succeed. This
    // is the only way to reach `error.InvalidBlindingFactor` through the
    // public API without inverting SHA-384 — same technique
    // `kat_test.zig` uses against the RFC's fixed key, replayed here
    // against THIS run's freshly generated one.
    const RiggedRandom = struct {
        factor: []const u8,
        fn fill(self: *const @This(), buf: []u8) void {
            @memset(buf, 0);
            if (buf.len >= self.factor.len) {
                @memcpy(buf[buf.len - self.factor.len ..], self.factor);
            } else {
                @memcpy(buf, self.factor[self.factor.len - buf.len ..]);
            }
        }
    };
    var p_bytes: [rsa.max_modulus_len]u8 = undefined;
    const p_len = (kp.secret_key.p.bits() + 7) / 8;
    try kp.secret_key.p.toBytes(p_bytes[0..p_len], .big);
    var rigged = RiggedRandom{ .factor = p_bytes[0..p_len] };
    const rigged_random = std.Random.init(&rigged, RiggedRandom.fill);

    var ctx_rigged: blindrsa.Context = undefined;
    var blinded_buf_rigged: [blindrsa.max_modulus_len]u8 = undefined;
    if (blindrsa.blind(kp.public_key, Sha384, prepared1, &salt1, rigged_random, &ctx_rigged, &blinded_buf_rigged)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidBlindingFactor => std.debug.print("RNG rigged to a factor of n: InvalidBlindingFactor (expected)\n", .{}),
        else => return err,
    }
}
