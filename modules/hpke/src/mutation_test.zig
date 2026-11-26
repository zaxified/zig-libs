// SPDX-License-Identifier: MIT
//! Tests added by the mutation audit of `hpke` (suite, kdf, dhkem,
//! schedule, pq): each one kills a mutant the pre-existing tests let survive.
//! The comment above a test names the line it pins.

const std = @import("std");
const testing = std.testing;
const aesgcm = @import("aesgcm");
const chachapoly = @import("chachapoly");
const suite = @import("suite.zig");
const kdf = @import("kdf.zig");
const dhkem = @import("dhkem.zig");
const schedule = @import("schedule.zig");
const pq = @import("pq.zig");
const agile = @import("agile.zig");

const Aead = aesgcm.Aes128Gcm;

fn expectZeroed(ptr: anytype) !void {
    for (std.mem.asBytes(ptr)) |b| try testing.expectEqual(@as(u8, 0), b);
}

// suite.labeledExpand: the labeled info is assembled in a 512-byte scratch, so
// 2 (L) + 7 ("HPKE-v1") + 10 (suite_id) + label + info = 512 bytes is the
// largest that fits; one more byte is LabelTooLong.
test "labeledExpand: the 512-byte label scratch takes exactly 512 bytes of labeled info" {
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const sid = suite.suiteId(0x0020, 0x0001, 0x0001);
    const prk: [32]u8 = @splat(5);
    var info: [493]u8 = @splat('i');
    var out: [32]u8 = undefined;
    try suite.labeledExpand(Hkdf, &sid, &prk, "x", info[0..492], &out);
    try testing.expectError(error.LabelTooLong, suite.labeledExpand(Hkdf, &sid, &prk, "x", info[0..493], &out));
}

// kdf.labeledDerive: the label is length-prefixed in two bytes, so 65,535 fits.
test "labeledDerive: a label of 65535 bytes works, 65536 is LabelTooLong" {
    const label = try testing.allocator.alloc(u8, kdf.max_one_stage_len + 1);
    defer testing.allocator.free(label);
    @memset(label, 'l');
    var out: [32]u8 = undefined;
    try kdf.Shake256.labeledDerive(&out, "sid", &.{"ikm"}, label[0..kdf.max_one_stage_len], &.{});
    try testing.expectError(error.LabelTooLong, kdf.Shake256.labeledDerive(&out, "sid", &.{"ikm"}, label, &.{}));
}

// schedule.oneStageSchedule: every length-prefixed field (shared_secret, psk,
// psk_id, info) takes 65,535 bytes; 65,536 is LabelTooLong.
test "one-stage key schedule: shared_secret, psk, psk_id and info each take 65535 bytes and refuse 65536" {
    const K = kdf.Shake256;
    const sid = suite.suiteId(0x647a, K.kdf_id, 0x0001);
    var ctx: schedule.Context(Aead, K) = undefined;
    const big = try testing.allocator.alloc(u8, kdf.max_one_stage_len + 1);
    defer testing.allocator.free(big);
    @memset(big, 'b');
    const ok = big[0..kdf.max_one_stage_len];
    const small: [32]u8 = @splat(1);
    // shared_secret
    try schedule.keySchedule(Aead, K, &ctx, .base, &sid, ok, "", "", "");
    try testing.expectError(error.LabelTooLong, schedule.keySchedule(Aead, K, &ctx, .base, &sid, big, "", "", ""));
    // info
    try schedule.keySchedule(Aead, K, &ctx, .base, &sid, &small, ok, "", "");
    try testing.expectError(error.LabelTooLong, schedule.keySchedule(Aead, K, &ctx, .base, &sid, &small, big, "", ""));
    // psk
    try schedule.keySchedule(Aead, K, &ctx, .psk, &sid, &small, "", ok, "id");
    try testing.expectError(error.LabelTooLong, schedule.keySchedule(Aead, K, &ctx, .psk, &sid, &small, "", big, "id"));
    // psk_id
    try schedule.keySchedule(Aead, K, &ctx, .psk, &sid, &small, "", &small, ok);
    try testing.expectError(error.LabelTooLong, schedule.keySchedule(Aead, K, &ctx, .psk, &sid, &small, "", &small, big));
}

// schedule.sealBody: a plaintext past the AEAD's message limit is InvalidLength
// BEFORE any byte of it is read (fabricated slices; they are never touched).
test "seal: a plaintext past max_message_len is InvalidLength without reading it" {
    inline for (.{ Aead, chachapoly.ChaCha20Poly1305 }) |A| {
        const C = schedule.Context(A, 32);
        var ctx: C = .{ .key = @splat(1), .base_nonce = @splat(2), .exporter_secret = @splat(3) };
        const n: usize = @intCast(C.max_message_len + 1);
        const pt_ptr: [*]const u8 = @ptrFromInt(0x10000);
        const out_ptr: [*]u8 = @ptrFromInt(0x20000);
        try testing.expectError(error.InvalidLength, ctx.seal("", pt_ptr[0..n], out_ptr[0 .. n + A.tag_length]));
        try testing.expectEqual(@as(u64, 0), ctx.seq);
    }
}

// pq.zig, pure ML-KEM: a non-canonical encapsulation key (coefficient >= q) is
// DeserializeError (not another error) and `out` is zeroed.
test "ML-KEM encap: a non-canonical encapsulation key is DeserializeError and zeroes out" {
    inline for (.{ pq.MlKem512Kem, pq.MlKem768Kem, pq.MlKem1024Kem }) |K| {
        var kp: K.KeyPair = undefined;
        K.fromSeed(&kp, &@as([K.Nsk]u8, @splat(3)));
        var pk = kp.public_key;
        pk[0] = 0xff;
        pk[1] = 0xff;
        pk[2] = 0xff; // two coefficients of 4095 >= q = 3329
        const eph: K.Ephemeral = @splat(5);
        var out: K.Encapped = undefined;
        @memset(std.mem.asBytes(&out), 0xaa);
        try testing.expectError(error.DeserializeError, K.encapDeterministic(&out, pk, &eph));
        try expectZeroed(&out);
        try K.encapDeterministic(&out, kp.public_key, &eph); // positive control
    }
}

// pq.zig, hybrid decap: a low-order X25519 half is DhFailed and zeroes `out`
// (nothing wrote to `out` before the failure, so only the errdefer clears it).
test "hybrid decap: DhFailed zeroes out" {
    const K = pq.MlKem768X25519Kem;
    var kp: K.KeyPair = undefined;
    K.fromSeed(&kp, &@as([32]u8, @splat(7)));
    const enc: K.EncappedKey = @splat(0);
    var out: [32]u8 = @splat(0xaa);
    try testing.expectError(error.DhFailed, K.decap(&out, enc, &kp));
    try expectZeroed(&out);
}

// pq.zig NistGroup: a zero scalar is not a candidate (the first valid
// candidate is the one used), and a point that does not decode is
// DeserializeError on both the encap and the decap side.
test "hybrid NIST: zero candidates are skipped; an undecodable curve point is DeserializeError" {
    inline for (.{ .{ pq.MlKem768P256Kem, 1184 }, .{ pq.MlKem1024P384Kem, 1568 } }) |spec| {
        const K = spec[0];
        const ek_pq_len = spec[1];
        var kp: K.KeyPair = undefined;
        K.fromSeed(&kp, &@as([32]u8, @splat(9)));
        var out: K.Encapped = undefined;

        // No valid candidate (all zero): DhFailed.
        var zero_eph: K.Ephemeral = @splat(0);
        try testing.expectError(error.DhFailed, K.encapDeterministic(&out, kp.public_key, &zero_eph));

        // A zero candidate before a valid one is skipped: same as 0xff.. (>= n).
        if (K == pq.MlKem768P256Kem) {
            var eph_a: K.Ephemeral = @splat(0x11);
            var eph_b = eph_a;
            @memset(eph_a[32..][0..32], 0);
            @memset(eph_b[32..][0..32], 0xff);
            var out_b: K.Encapped = undefined;
            try K.encapDeterministic(&out, kp.public_key, &eph_a);
            try K.encapDeterministic(&out_b, kp.public_key, &eph_b);
            try testing.expectEqualSlices(u8, &out.shared_secret, &out_b.shared_secret);
            try testing.expectEqualSlices(u8, &out.enc, &out_b.enc);
        }

        // ek_T that is not a curve point.
        var bad_pk = kp.public_key;
        @memset(bad_pk[ek_pq_len..], 0);
        const good_eph: K.Ephemeral = @splat(0x11);
        try testing.expectError(error.DeserializeError, K.encapDeterministic(&out, bad_pk, &good_eph));

        // ct_T that is not a curve point.
        var enc: K.EncappedKey = @splat(0);
        var ss: [32]u8 = @splat(0xaa);
        try testing.expectError(error.DeserializeError, K.decap(&ss, enc, &kp));
        try expectZeroed(&ss);
        enc = @splat(0xff);
        try testing.expectError(error.DeserializeError, K.decap(&ss, enc, &kp));
    }
}

// dhkem.zig: a zero ephemeral scalar gives the identity as the DH result, which
// is DhFailed (not a deserialization error), for every NIST KEM.
test "DHKEM NIST encap with a zero ephemeral scalar is DhFailed" {
    inline for (.{ dhkem.P256Kem, dhkem.P384Kem, dhkem.P521Kem }) |K| {
        var r: K.KeyPair = undefined;
        K.deriveKeyPair(&r, "recipient");
        var eph: K.KeyPair = undefined;
        K.deriveKeyPair(&eph, "ephemeral");
        eph.secret_key = @splat(0);
        var out: K.Encapped = undefined;
        try testing.expectError(error.DhFailed, K.encapDeterministic(&out, r.public_key, &eph));
    }
}

// delta audit (ct25519 X25519 in dhkem): AuthDecap's FIRST DH is
// x(skR, enc). A low-order `enc` with a valid pkS must be DhFailed, not another
// error -- the sweep only fed the low-order point as pkS (second DH).
test "DHKEM X25519 AuthDecap: a low-order enc with a valid pkS is DhFailed" {
    const K = dhkem.X25519Kem;
    var kp: K.KeyPair = undefined;
    K.deriveKeyPair(&kp, "recipient ikm");
    var sender: K.KeyPair = undefined;
    K.deriveKeyPair(&sender, "sender ikm");
    var ss: [K.Nsecret]u8 = undefined;
    const zero: [32]u8 = @splat(0);
    const one = [_]u8{1} ++ @as([31]u8, @splat(0));
    for ([_][32]u8{ zero, one }) |enc| {
        try testing.expectError(error.DhFailed, K.authDecap(&ss, enc, &kp, sender.public_key));
        try expectZeroed(&ss);
    }
}

// ── whole-module run 2026-11-25: agile.zig / agile_set.zig ───────────────────

// agile.Suite.encLength / tagLength: an id `init` refuses (built by hand, the
// fields are public) has length 0, as documented.
test "mutation 2026-11-25: Suite.encLength and tagLength are 0 for an unregistered KEM / AEAD id" {
    const s: agile.Suite = .{ .kem = @fromBackingInt(0x1234), .kdf = .hkdf_sha256, .aead = @fromBackingInt(0x1234) };
    try testing.expectEqual(@as(usize, 0), s.encLength());
    try testing.expectEqual(@as(usize, 0), s.tagLength());
}

// agile_set.keyPairFromSecret: `out` is zeroed when the DHKEM scalar is refused.
// The callee fails before it writes the payload, so what the zeroing makes
// observable is the union tag: a zeroed KeyPair is the first variant (P-256),
// not the P-384 variant `@unionInit` selected.
test "mutation 2026-11-25: agile keyPairFromSecret zeroes out when the scalar is refused" {
    var kp: agile.KeyPair = undefined;
    @memset(std.mem.asBytes(&kp), 0xaa);
    const zero_sk: [48]u8 = @splat(0);
    try testing.expectError(error.DeserializeError, agile.keyPairFromSecret(&kp, .dhkem_p384_hkdf_sha384, &zero_sk));
    try testing.expectEqual(agile.KemId.dhkem_p256_hkdf_sha256, kp.kemId());
}

// agile_set: the sender's / recipient's own keys must belong to the suite's KEM
// (KemMismatch, before the inactive union field is touched); the recipient's
// mode check (auth needs pkS, base takes none); `out` is zeroed on every error
// of setupS / setupR; the exporter secret's tail past Nh is zero; an
// export-only context has seq 0.
test "mutation 2026-11-25: agile setup checks sender key KEM, recipient mode, zeroing and padding" {
    var x: agile.KeyPair = undefined;
    try agile.deriveKeyPair(&x, .dhkem_x25519_hkdf_sha256, "x");
    var m: agile.KeyPair = undefined;
    try agile.deriveKeyPair(&m, .ml_kem_768, "m");
    const pkx = x.publicKey();
    const pkm = m.publicKey();
    const sx = try agile.Suite.init(0x0020, 1, 1);
    var st: agile.Setup = undefined;
    var c: agile.Context = undefined;

    // skS of another KEM, pkS of another KEM.
    try testing.expectError(error.KemMismatch, agile.setupSDeterministic(&st, sx, .auth, &pkx, &m, "e", "", "", ""));
    try testing.expectError(error.KemMismatch, agile.setupR(&c, sx, .auth, pkx.slice(), &x, &pkm, "", "", ""));
    // Recipient: auth without pkS, base with pkS.
    try testing.expectError(error.UnsupportedMode, agile.setupR(&c, sx, .auth, pkx.slice(), &x, null, "", "", ""));
    try testing.expectError(error.UnsupportedMode, agile.setupR(&c, sx, .base, pkx.slice(), &x, &pkx, "", "", ""));

    // `out` zeroed on error.
    @memset(std.mem.asBytes(&st), 0xaa);
    try testing.expectError(error.KemMismatch, agile.setupSDeterministic(&st, sx, .base, &pkm, null, "e", "", "", ""));
    try expectZeroed(&st);
    @memset(std.mem.asBytes(&c), 0xaa);
    try testing.expectError(error.InvalidLength, agile.setupR(&c, sx, .base, "short", &x, null, "", "", ""));
    try expectZeroed(&c);

    // The exporter secret past Nh (HKDF-SHA256: 32) is zero, sender and recipient.
    @memset(std.mem.asBytes(&st), 0xaa);
    try agile.setupSDeterministic(&st, sx, .base, &pkx, null, "e", "", "", "");
    for (st.context.exporter_secret[32..]) |b| try testing.expectEqual(@as(u8, 0), b);
    @memset(std.mem.asBytes(&c), 0xaa);
    try agile.setupR(&c, sx, .base, st.encSlice(), &x, null, "", "", "");
    for (c.exporter_secret[32..]) |b| try testing.expectEqual(@as(u8, 0), b);

    // Export-only: seq() is 0.
    const se = try agile.Suite.init(0x0020, 1, 0xffff);
    try agile.setupSDeterministic(&st, se, .base, &pkx, null, "e", "", "", "");
    try testing.expectEqual(@as(u64, 0), st.context.seq());
}

// agile_set.sealBase / openBase: an `out` shorter than `enc` (or a `sealed`
// shorter than `enc`) is InvalidLength; at exactly `enc` length the error is the
// context's (ExportOnly for an export-only suite, DecryptionFailed for an empty ciphertext).
test "mutation 2026-11-25: agile sealBase / openBase length guards at the enc boundary" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var x: agile.KeyPair = undefined;
    try agile.deriveKeyPair(&x, .dhkem_x25519_hkdf_sha256, "x");
    const pkx = x.publicKey();
    const s = try agile.Suite.init(0x0020, 1, 1);
    const n = s.encLength();
    var buf: [128]u8 = undefined;
    try testing.expectError(error.InvalidLength, agile.sealBase(s, &pkx, io, "", "", "", buf[0 .. n - 1]));
    const se = try agile.Suite.init(0x0020, 1, 0xffff);
    try testing.expectError(error.ExportOnly, agile.sealBase(se, &pkx, io, "", "", "", buf[0..n]));

    try agile.sealBase(s, &pkx, io, "", "", "x", buf[0 .. n + 1 + s.tagLength()]);
    var back: [1]u8 = undefined;
    try testing.expectError(error.InvalidLength, agile.openBase(s, &x, "", "", buf[0 .. n - 1], &back));
    try testing.expectError(error.DecryptionFailed, agile.openBase(s, &x, "", "", buf[0..n], back[0..0]));
}

// ── whole-module run 2026-11-25: schedule.zig / pq.zig ───────────────────────

// schedule.Context: `aead_key` records the key `aead_state` was expanded from.
// The key schedule must (re)expand and record it (`expandAead`, both the two-stage
// and the one-stage path), and `readyAead` must honour the record: a Context whose
// `aead_key` already equals the freshly derived key but whose state is garbage
// still seals correctly; a rewritten `key` that happens to equal a garbage
// `aead_key` is not mistaken for the expanded one.
test "mutation 2026-11-25: Context expandAead records aead_key and the key schedule re-expands over a poisoned state" {
    inline for (.{ kdf.HkdfSha256, kdf.Shake256 }) |K| {
        const C = schedule.Context(Aead, K);
        const sid = suite.suiteId(0x0020, K.kdf_id, 0x0001);
        const ss: [32]u8 = @splat(5);
        var ref: C = undefined;
        try schedule.keySchedule(Aead, K, &ref, .base, &sid, &ss, "i", "", "");
        var ctx: C = undefined;
        @memset(std.mem.asBytes(&ctx), 0xaa);
        ctx.aead_key = ref.key; // claims an expansion that never happened
        try schedule.keySchedule(Aead, K, &ctx, .base, &sid, &ss, "i", "", "");
        var c1: [6 + 16]u8 = undefined;
        var c2: [6 + 16]u8 = undefined;
        try ref.seal("aad", "hello!", &c1);
        try ctx.seal("aad", "hello!", &c2);
        try testing.expectEqualSlices(u8, &c1, &c2);

        // A rewritten key that equals the (garbage) pre-schedule aead_key.
        var a: C = undefined;
        var b: C = undefined;
        @memset(std.mem.asBytes(&b), 0x55);
        try schedule.keySchedule(Aead, K, &a, .base, &sid, &ss, "i", "", "");
        try schedule.keySchedule(Aead, K, &b, .base, &sid, &ss, "i", "", "");
        a.key = @splat(0x55);
        b.key = @splat(0x55);
        try a.seal("aad", "hello!", &c1);
        try b.seal("aad", "hello!", &c2);
        try testing.expectEqualSlices(u8, &c1, &c2);
    }
}

// pq.zig HybridKem.encapBody: the ML-KEM half of the key is checked first and is
// DeserializeError (not DhFailed), `out` zeroed.
test "mutation 2026-11-25: hybrid encap: a non-canonical ML-KEM key half is DeserializeError and zeroes out" {
    inline for (.{ pq.MlKem768P256Kem, pq.MlKem1024P384Kem, pq.MlKem768X25519Kem }) |K| {
        var kp: K.KeyPair = undefined;
        K.fromSeed(&kp, &@as([32]u8, @splat(3)));
        var pk = kp.public_key;
        pk[0] = 0xff;
        pk[1] = 0xff;
        pk[2] = 0xff; // two coefficients of 4095 >= q
        const eph: K.Ephemeral = @splat(0x11);
        var out: K.Encapped = undefined;
        @memset(std.mem.asBytes(&out), 0xaa);
        try testing.expectError(error.DeserializeError, K.encapDeterministic(&out, pk, &eph));
        try expectZeroed(&out);
        try K.encapDeterministic(&out, kp.public_key, &eph); // positive control
    }
}

// ── whole-module run 2026-11-25: dhkem.zig ───────────────────────────────────

// X448Kem: every failing entry point zeroes `out` (the sweep's out-zeroing test
// predates X448), and the all-zero DH check looks at the WHOLE output: a DH
// result that is non-zero but ends in a zero byte is a shared secret, not DhFailed.
test "mutation 2026-11-25: X448 zeroes out on every failing entry point; a DH output ending in 0x00 is accepted" {
    const K = dhkem.X448Kem;
    var r: K.KeyPair = undefined;
    K.deriveKeyPair(&r, "recipient");
    var s: K.KeyPair = undefined;
    K.deriveKeyPair(&s, "sender");
    var e: K.KeyPair = undefined;
    K.deriveKeyPair(&e, "ephemeral");
    const low: K.PublicKey = @splat(0); // u = 0: low order, DH output all zero
    var out: K.Encapped = undefined;
    var ss: [K.Nsecret]u8 = undefined;

    @memset(std.mem.asBytes(&out), 0xaa);
    try testing.expectError(error.DhFailed, K.encapDeterministic(&out, low, &e));
    try expectZeroed(&out);
    @memset(&ss, 0xaa);
    try testing.expectError(error.DhFailed, K.decap(&ss, low, &r));
    try expectZeroed(&ss);
    @memset(std.mem.asBytes(&out), 0xaa);
    try testing.expectError(error.DhFailed, K.authEncapDeterministic(&out, low, &s, &e));
    try expectZeroed(&out);
    @memset(&ss, 0xaa);
    try testing.expectError(error.DhFailed, K.authDecap(&ss, low, &r, s.public_key));
    try expectZeroed(&ss);
    @memset(&ss, 0xaa);
    try testing.expectError(error.DhFailed, K.authDecap(&ss, e.public_key, &r, low));
    try expectZeroed(&ss);

    // DH(k, 5) for k = 1496 (LE) is non-zero with a zero last byte (RFC 7748
    // ladder, checked independently): accepted.
    var base: K.PublicKey = @splat(0);
    base[0] = 5;
    var eph: K.KeyPair = .{ .public_key = @splat(1), .secret_key = @splat(0) };
    eph.secret_key[0] = 0xd8;
    eph.secret_key[1] = 0x05;
    try K.encapDeterministic(&out, base, &eph);
}

// P256Kem / P384Kem: the error class of each failing step in decap and the auth
// modes (an undecodable point is DeserializeError, a zero scalar, i.e. an identity
// DH result, is DhFailed).
test "mutation 2026-11-25: DHKEM P-256 / P-384 decap and auth modes: error class per failing step" {
    inline for (.{ dhkem.P256Kem, dhkem.P384Kem }) |K| {
        var r: K.KeyPair = undefined;
        K.deriveKeyPair(&r, "recipient");
        var s: K.KeyPair = undefined;
        K.deriveKeyPair(&s, "sender");
        var e: K.KeyPair = undefined;
        K.deriveKeyPair(&e, "ephemeral");
        var bad: K.PublicKey = @splat(0);
        bad[0] = 4;
        bad[(K.Npk - 1) / 2] = 1;
        bad[K.Npk - 1] = 1; // (1, 1): not on the curve ((0, 0) is p384's affine identity: DhFailed)
        var r0 = r;
        r0.secret_key = @splat(0);
        var s0 = s;
        s0.secret_key = @splat(0);
        var e0 = e;
        e0.secret_key = @splat(0);
        var out: K.Encapped = undefined;
        var ss: [K.Nsecret]u8 = undefined;

        try testing.expectError(error.DeserializeError, K.authEncapDeterministic(&out, bad, &s, &e));
        try testing.expectError(error.DhFailed, K.authEncapDeterministic(&out, r.public_key, &s, &e0));
        try testing.expectError(error.DhFailed, K.authEncapDeterministic(&out, r.public_key, &s0, &e));
        try testing.expectError(error.DhFailed, K.decap(&ss, e.public_key, &r0));
        try testing.expectError(error.DeserializeError, K.authDecap(&ss, bad, &r, s.public_key));
        try testing.expectError(error.DeserializeError, K.authDecap(&ss, e.public_key, &r, bad));
        try testing.expectError(error.DhFailed, K.authDecap(&ss, e.public_key, &r0, s.public_key));
        // (0, 0): p256 refuses it as a point, p384 decodes it as its affine identity (DH fails).
        var origin: K.PublicKey = @splat(0);
        origin[0] = 4;
        const want: anyerror = if (K == dhkem.P384Kem) error.DhFailed else error.DeserializeError;
        try testing.expectError(want, K.authDecap(&ss, e.public_key, &r, origin));
        // positive control
        try K.authEncapDeterministic(&out, r.public_key, &s, &e);
        try K.authDecap(&ss, out.enc, &r, s.public_key);
        try testing.expectEqualSlices(u8, &out.shared_secret, &ss);
    }
}

// pq.zig NistGroup.dh: p384 decodes (0, 0) as its affine identity, so a hybrid key
// or ciphertext carrying it fails the DH (DhFailed) where p256 refuses the
// encoding (DeserializeError): the multiplication's identity error is reachable.
test "mutation 2026-11-25: MLKEM1024-P384: an identity curve half is DhFailed on encap and decap" {
    const K = pq.MlKem1024P384Kem;
    const ek_pq_len = 1568;
    var kp: K.KeyPair = undefined;
    K.fromSeed(&kp, &@as([32]u8, @splat(9)));
    var out: K.Encapped = undefined;
    var bad_pk = kp.public_key;
    @memset(bad_pk[ek_pq_len..], 0);
    bad_pk[ek_pq_len] = 4;
    const eph: K.Ephemeral = @splat(0x11);
    try testing.expectError(error.DhFailed, K.encapDeterministic(&out, bad_pk, &eph));
    var enc: K.EncappedKey = @splat(0);
    enc[K.Nenc - 97] = 4;
    var ss: [32]u8 = undefined;
    try testing.expectError(error.DhFailed, K.decap(&ss, enc, &kp));
}
