// SPDX-License-Identifier: MIT

//! aes192 — the AES-192 block cipher (FIPS-197, Nk = 6, Nr = 12) that Zig
//! 0.16's `std.crypto.core.aes` does not ship (it has `Aes128` and `Aes256`
//! only), shaped exactly like std's two so a mode written generically over
//! them takes this one unchanged.
//!
//! Only the key expansion is new. The rounds are std's own block primitive,
//! `std.crypto.core.aes.Block` — AES-NI on amd64, the ARMv8 Crypto Extensions
//! on arm64, std's table-based software path everywhere else — so the
//! per-block code and its constant-time posture are std's, chosen at compile
//! time by the same switch that chooses them for `Aes128`/`Aes256`.
//!
//! The key expansion (FIPS-197 §5.2) needs SubWord on secret words. It owns
//! no S-box: `subWord` runs the word through std's `Block.encryptLast` with a
//! zero round key, on a state whose four columns are the same word. ShiftRows
//! is the identity on such a state (each row holds one repeated byte), so the
//! last round reduces to SubBytes, and SubWord inherits the backend's
//! constant-time property instead of adding a lookup of its own. Pinned
//! against the FIPS-197 S-box for all 256 inputs (`model_test.zig`).
//!
//! What it is not: a mode. CBC, CTR, GCM, KW live in the modules that already
//! implement them for AES-128/256; wiring this cipher into them is separate
//! work (see SPEC.md).

const std = @import("std");
const aes = std.crypto.core.aes;
const burn = @import("burn.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "AES-192 block cipher (FIPS-197 Nk=6/Nr=12) on std's AES-NI / ARMv8 / software round primitive, shaped like std's Aes128/Aes256 so modes can be generic over it",
    // Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any (AES-NI / ARMv8 Crypto via std, software fallback)",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "FIPS-197 §5.2 + std.crypto.core.aes (Aes128/Aes256 shape)",
    .deps = .{},
};

/// One AES block and its round operations: std's, for the backend this
/// target compiles (see the module comment).
pub const Block = aes.Block;

/// `true` when the rounds run on AES hardware (AES-NI on amd64, ARMv8 Crypto
/// on arm64). Without it std's software path is table-based with cache-line
/// masking (`std.options.side_channels_mitigations`), not bitsliced — this
/// module inherits exactly that posture (SPEC.md, *Constant-time contract*).
pub const has_hardware_support = aes.has_hardware_support;

/// The key length in bytes.
pub const key_length = 24;
/// The number of rounds (FIPS-197 Table 3, Nr for Nk = 6).
pub const rounds = 12;

/// The 13 round keys of one AES-192 key.
pub const KeySchedule = struct {
    round_keys: [rounds + 1]Block,

    /// The schedule for the equivalent inverse cipher (FIPS-197 §5.3.5):
    /// round keys in reverse order, InvMixColumns applied to all but the
    /// first and the last.
    fn invert(ks: *const KeySchedule) KeySchedule {
        const rk = &ks.round_keys;
        var inv: KeySchedule = undefined;
        inv.round_keys[0] = rk[rounds];
        inline for (1..rounds) |i| inv.round_keys[i] = invMixColumns(rk[rounds - i]);
        inv.round_keys[rounds] = rk[0];
        return inv;
    }
};

const zero_block: [16]u8 = @splat(0);

/// SubWord (FIPS-197 §5.2) through std's last-round primitive: the word in
/// all four columns, a zero round key, the first column back out.
inline fn subWord(w: [4]u8) [4]u8 {
    const state: [16]u8 = w ++ w ++ w ++ w;
    const out = Block.fromBytes(&state).encryptLast(Block.fromBytes(&zero_block)).toBytes();
    return out[0..4].*;
}

/// InvMixColumns of a round key, composed from the round primitives:
/// `decrypt(encryptLast(x, 0), 0)` = InvMixColumns(InvSubBytes(InvShiftRows(
/// ShiftRows(SubBytes(x))))) = InvMixColumns(x). Not `Block.invMixColumns`:
/// on std 0.16's software backend that one multiplies through `mul`, whose
/// `if (j & 0x100 != 0)` is a branch on the (secret) round-key byte
/// (`lib/std/crypto/aes/soft.zig:805`, 872 memcheck contexts in this
/// module's `dec` harness before the change). std's own software contexts
/// never call it; through the round primitives the inversion has exactly
/// the posture of every other round. On AES-NI / ARMv8 it costs one extra
/// instruction per round key, once per key.
inline fn invMixColumns(x: Block) Block {
    const z = Block.fromBytes(&zero_block);
    return x.encryptLast(z).decrypt(z);
}

/// Rcon[i/Nk] for i = 6, 12, ..., 48 (FIPS-197 §5.2): x^(j-1) in GF(2^8).
const rcon = [_]u8{ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };

/// KEYEXPANSION() for Nk = 6 (FIPS-197 §5.2, Algorithm 2). Every branch is
/// on the loop index; the key bytes reach only XOR and `subWord`.
fn expand(out: *KeySchedule, key: *const [key_length]u8) void {
    const nk = 6;
    var w: [4 * (rounds + 1)][4]u8 = undefined;
    inline for (0..nk) |i| w[i] = key[4 * i ..][0..4].*;
    inline for (nk..w.len) |i| {
        var t = w[i - 1];
        if (i % nk == 0) {
            t = subWord(.{ t[1], t[2], t[3], t[0] }); // SubWord(RotWord(t))
            t[0] ^= rcon[i / nk - 1];
        }
        inline for (0..4) |j| w[i][j] = w[i - nk][j] ^ t[j];
    }
    inline for (0..rounds + 1) |r| out.round_keys[r] = Block.fromBytes(std.mem.asBytes(w[4 * r ..][0..4]));
}

const RoundOp = enum { encrypt, encryptLast, decrypt, decryptLast };

/// One round over `count` independent blocks with the same round key — what
/// std's `Block.parallel.*Wide` does on AES-NI and ARMv8 (an unrolled loop
/// the CPU pipelines). Not called through std: in Zig 0.16.0 the software
/// backend's `parallel.*Wide` does not compile (`var i = 0;` is a
/// `comptime_int` variable, `lib/std/crypto/aes/soft.zig:315`); std's own
/// contexts never reach it there. Same code on every backend this way.
inline fn roundWide(comptime op: RoundOp, comptime count: usize, ts: [count]Block, rk: Block) [count]Block {
    var out: [count]Block = undefined;
    inline for (0..count) |j| out[j] = @field(Block, @tagName(op))(ts[j], rk);
    return out;
}

/// A context to encrypt with one AES-192 key. Same shape as std's
/// `AesEncryptCtx(Aes128)`: by-value `encrypt`/`xor`/`encryptWide`/`xorWide`
/// and a `block` with `parallel`, so `std.crypto.core.modes.ctr` and any
/// mode generic over std's contexts accept it.
///
/// It holds the round keys, i.e. the key. Call `wipe` when the key is
/// retired — nothing else clears it (`CONVENTIONS.md` §2.1, Z2).
///
/// Dead stack (`CONVENTIONS.md` §2.1.1): `init`/`initInto` burn (key
/// expansion); the per-block calls deliberately do not — a keyed transform's
/// working state is §2.1's Z3, and the burn belongs to the entry point of the
/// mode or protocol that owns the key and the message.
pub const Aes192EncryptCtx = struct {
    const Self = @This();
    pub const block = Block;
    pub const block_length = Block.block_length;
    key_schedule: KeySchedule,

    /// The context for `key`. `initInto` is the dead-stack-clean form: no
    /// key copy in the caller's frame, no context in its result slot.
    pub fn init(key: [key_length]u8) Self {
        return burn.run(burn.schedule_burn, Self, initBody, .{&key});
    }

    /// `out` ← the context for `*key` (the pointer twin of `init`).
    pub fn initInto(out: *Self, key: *const [key_length]u8) void {
        burn.run(burn.schedule_burn, void, expand, .{ &out.key_schedule, key });
    }

    fn initBody(key: *const [key_length]u8) Self {
        var ctx: Self = undefined;
        expand(&ctx.key_schedule, key);
        return ctx;
    }

    /// Encrypt one block.
    pub fn encrypt(ctx: Self, dst: *[16]u8, src: *const [16]u8) void {
        const rk = ctx.key_schedule.round_keys;
        var t = Block.fromBytes(src).xorBlocks(rk[0]);
        inline for (1..rounds) |i| t = t.encrypt(rk[i]);
        t = t.encryptLast(rk[rounds]);
        dst.* = t.toBytes();
    }

    /// `dst` ← `src` XOR the encryption of `counter` (one CTR step).
    pub fn xor(ctx: Self, dst: *[16]u8, src: *const [16]u8, counter: [16]u8) void {
        const rk = ctx.key_schedule.round_keys;
        var t = Block.fromBytes(&counter).xorBlocks(rk[0]);
        inline for (1..rounds) |i| t = t.encrypt(rk[i]);
        t = t.encryptLast(rk[rounds]);
        dst.* = t.xorBytes(src);
    }

    /// Encrypt `count` blocks, interleaved so the backend can pipeline them.
    pub fn encryptWide(ctx: Self, comptime count: usize, dst: *[16 * count]u8, src: *const [16 * count]u8) void {
        const rk = ctx.key_schedule.round_keys;
        var ts: [count]Block = undefined;
        inline for (0..count) |j| ts[j] = Block.fromBytes(src[j * 16 ..][0..16]).xorBlocks(rk[0]);
        inline for (1..rounds) |i| ts = roundWide(.encrypt, count, ts, rk[i]);
        ts = roundWide(.encryptLast, count, ts, rk[rounds]);
        inline for (0..count) |j| dst[j * 16 ..][0..16].* = ts[j].toBytes();
    }

    /// `count` CTR steps at once: `dst` ← `src` XOR E(`counters`).
    pub fn xorWide(ctx: Self, comptime count: usize, dst: *[16 * count]u8, src: *const [16 * count]u8, counters: [16 * count]u8) void {
        const rk = ctx.key_schedule.round_keys;
        var ts: [count]Block = undefined;
        inline for (0..count) |j| ts[j] = Block.fromBytes(counters[j * 16 ..][0..16]).xorBlocks(rk[0]);
        inline for (1..rounds) |i| ts = roundWide(.encrypt, count, ts, rk[i]);
        ts = roundWide(.encryptLast, count, ts, rk[rounds]);
        inline for (0..count) |j| dst[j * 16 ..][0..16].* = ts[j].xorBytes(src[j * 16 ..][0..16]);
    }

    /// Zero the round keys.
    pub fn wipe(ctx: *Self) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&ctx.key_schedule));
    }
};

/// A context to decrypt with one AES-192 key (the equivalent inverse cipher,
/// FIPS-197 §5.3.5, as std's `AesDecryptCtx`). Same lifetime and dead-stack
/// rules as `Aes192EncryptCtx`.
pub const Aes192DecryptCtx = struct {
    const Self = @This();
    pub const block = Block;
    pub const block_length = Block.block_length;
    key_schedule: KeySchedule,

    /// The decryption context for the key of an existing encryption context.
    pub fn initFromEnc(ctx: Aes192EncryptCtx) Self {
        return .{ .key_schedule = ctx.key_schedule.invert() };
    }

    /// The decryption context for `key`. `initInto` is the dead-stack-clean
    /// form.
    pub fn init(key: [key_length]u8) Self {
        return burn.run(burn.schedule_burn, Self, initBody, .{&key});
    }

    /// `out` ← the decryption context for `*key` (the pointer twin of `init`).
    pub fn initInto(out: *Self, key: *const [key_length]u8) void {
        burn.run(burn.schedule_burn, void, initIntoBody, .{ out, key });
    }

    fn initBody(key: *const [key_length]u8) Self {
        var enc: KeySchedule = undefined;
        expand(&enc, key);
        return .{ .key_schedule = enc.invert() };
    }

    fn initIntoBody(out: *Self, key: *const [key_length]u8) void {
        var enc: KeySchedule = undefined;
        expand(&enc, key);
        out.key_schedule = enc.invert();
    }

    /// Decrypt one block.
    pub fn decrypt(ctx: Self, dst: *[16]u8, src: *const [16]u8) void {
        const rk = ctx.key_schedule.round_keys;
        var t = Block.fromBytes(src).xorBlocks(rk[0]);
        inline for (1..rounds) |i| t = t.decrypt(rk[i]);
        t = t.decryptLast(rk[rounds]);
        dst.* = t.toBytes();
    }

    /// Decrypt `count` blocks, interleaved so the backend can pipeline them.
    pub fn decryptWide(ctx: Self, comptime count: usize, dst: *[16 * count]u8, src: *const [16 * count]u8) void {
        const rk = ctx.key_schedule.round_keys;
        var ts: [count]Block = undefined;
        inline for (0..count) |j| ts[j] = Block.fromBytes(src[j * 16 ..][0..16]).xorBlocks(rk[0]);
        inline for (1..rounds) |i| ts = roundWide(.decrypt, count, ts, rk[i]);
        ts = roundWide(.decryptLast, count, ts, rk[rounds]);
        inline for (0..count) |j| dst[j * 16 ..][0..16].* = ts[j].toBytes();
    }

    /// Zero the round keys.
    pub fn wipe(ctx: *Self) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&ctx.key_schedule));
    }
};

/// AES-192 with the standard key schedule: the third member of std's
/// `Aes128`/`Aes256` family, with the same declarations.
pub const Aes192 = struct {
    pub const key_bits: usize = 192;
    pub const rounds = 12;
    pub const block = Block;

    /// A new context for encryption. `initEncInto` is the dead-stack-clean
    /// form.
    pub fn initEnc(key: [key_bits / 8]u8) Aes192EncryptCtx {
        return Aes192EncryptCtx.init(key);
    }

    /// A new context for decryption. `initDecInto` is the dead-stack-clean
    /// form.
    pub fn initDec(key: [key_bits / 8]u8) Aes192DecryptCtx {
        return Aes192DecryptCtx.init(key);
    }

    /// `out` ← an encryption context for `*key`.
    pub fn initEncInto(out: *Aes192EncryptCtx, key: *const [key_bits / 8]u8) void {
        Aes192EncryptCtx.initInto(out, key);
    }

    /// `out` ← a decryption context for `*key`.
    pub fn initDecInto(out: *Aes192DecryptCtx, key: *const [key_bits / 8]u8) void {
        Aes192DecryptCtx.initInto(out, key);
    }
};

comptime {
    std.debug.assert(Aes192.rounds == rounds);
    std.debug.assert(Aes192.key_bits / 8 == key_length);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const hex = std.fmt.hexToBytes;

test {
    _ = @import("model_test.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("stackprobe_test.zig");
}

fn fromHex(comptime n: usize, comptime h: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = hex(&out, h) catch unreachable;
    return out;
}

test "FIPS-197 Appendix C.2: cipher and inverse cipher" {
    const key = fromHex(24, "000102030405060708090a0b0c0d0e0f1011121314151617");
    const pt = fromHex(16, "00112233445566778899aabbccddeeff");
    const ct = fromHex(16, "dda97ca4864cdfe06eaf70a0ec0d7191");
    var out: [16]u8 = undefined;
    Aes192.initEnc(key).encrypt(&out, &pt);
    try testing.expectEqualSlices(u8, &ct, &out);
    Aes192.initDec(key).decrypt(&out, &ct);
    try testing.expectEqualSlices(u8, &pt, &out);
}

test "FIPS-197 Appendix A.2: the 52 expanded words of a 192-bit key" {
    // w0..w51 from the A.2 table, four words per round key.
    const exp = [_]*const [32]u8{
        "8e73b0f7da0e6452c810f32b809079e5", "62f8ead2522c6b7bfe0c91f72402f5a5",
        "ec12068e6c827f6b0e7a95b95c56fec2", "4db7b4bd69b5411885a74796e92538fd",
        "e75fad44bb095386485af05721efb14f", "a448f6d94d6dce24aa326360113b30e6",
        "a25e7ed583b1cf9a27f939436a94f767", "c0a69407d19da4e1ec1786eb6fa64971",
        "485f703222cb8755e26d135233f0b7b3", "40beeb282f18a2596747d26b458c553e",
        "a7e1466c9411f1df821f750aad07d753", "ca4005388fcc5006282d166abc3ce7b5",
        "e98ba06f448c773c8ecc720401002202",
    };
    const key = fromHex(24, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    const enc = Aes192.initEnc(key);
    var want: [16]u8 = undefined;
    for (enc.key_schedule.round_keys, exp) |rk, e| {
        _ = try hex(&want, e);
        try testing.expectEqualSlices(u8, &want, &rk.toBytes());
    }
}

test "FIPS-197 Appendix C.2: round keys of the cipher and of the equivalent inverse cipher" {
    const key = fromHex(24, "000102030405060708090a0b0c0d0e0f1011121314151617");
    // `round[r].k_sch` of the CIPHER trace.
    const k_sch = [_]*const [32]u8{
        "000102030405060708090a0b0c0d0e0f", "10111213141516175846f2f95c43f4fe",
        "544afef55847f0fa4856e2e95c43f4fe", "40f949b31cbabd4d48f043b810b7b342",
        "58e151ab04a2a5557effb5416245080c", "2ab54bb43a02f8f662e3a95d66410c08",
        "f501857297448d7ebdf1c6ca87f33e3c", "e510976183519b6934157c9ea351f1e0",
        "1ea0372a995309167c439e77ff12051e", "dd7e0e887e2fff68608fc842f9dcc154",
        "859f5f237a8d5a3dc0c02952beefd63a", "de601e7827bcdf2ca223800fd8aeda32",
        "a4970a331a78dc09c418c271e3a41d5d",
    };
    // `round[r].ik_sch` of the EQUIVALENT INVERSE CIPHER trace.
    const ik_sch = [_]*const [32]u8{
        "a4970a331a78dc09c418c271e3a41d5d", "d6bebd0dc209ea494db073803e021bb9",
        "8fb999c973b26839c7f9d89d85c68c72", "f77d6ec1423f54ef5378317f14b75744",
        "1147659047cf663b9b0ece8dfc0bf1f0", "dcc1a8b667053f7dcc5c194ab5423a2e",
        "c6deb0ab791e2364a4055fbe568803ab", "dd1b7cdaf28d5c158a49ab1dbbc497cb",
        "78c4f708318d3cd69655b701bfc093cf", "60dcef10299524ce62dbef152f9620cf",
        "4b4ecbdb4d4dcfda5752d7c74949cbde", "1a1f181d1e1b1c194742c7d74949cbde",
        "000102030405060708090a0b0c0d0e0f",
    };
    const enc = Aes192.initEnc(key);
    const dec = Aes192.initDec(key);
    const dec_from_enc = Aes192DecryptCtx.initFromEnc(enc);
    var want: [16]u8 = undefined;
    for (k_sch, enc.key_schedule.round_keys) |e, rk| {
        _ = try hex(&want, e);
        try testing.expectEqualSlices(u8, &want, &rk.toBytes());
    }
    for (ik_sch, dec.key_schedule.round_keys, dec_from_enc.key_schedule.round_keys) |e, rk, rk2| {
        _ = try hex(&want, e);
        try testing.expectEqualSlices(u8, &want, &rk.toBytes());
        try testing.expectEqualSlices(u8, &want, &rk2.toBytes());
    }
}

test "NIST CAVP AESAVS: every AES-192 ECB KAT and MMT vector (GFSbox, KeySbox, VarKey, VarTxt, MMT)" {
    const cavp = @import("testdata/cavp_ecb192.zig");
    var buf_in: [160]u8 = undefined;
    var buf_out: [160]u8 = undefined;
    var buf_want: [160]u8 = undefined;
    var per_file = [_]usize{0} ** 5;
    const files = [_][]const u8{ "ECBGFSbox192.rsp", "ECBKeySbox192.rsp", "ECBVarKey192.rsp", "ECBVarTxt192.rsp", "ECBMMT192.rsp" };
    for (cavp.vectors) |v| {
        var key: [24]u8 = undefined;
        _ = try hex(&key, v.key);
        const n = v.pt.len / 2;
        try testing.expect(n % 16 == 0 and n > 0 and n <= buf_in.len);
        const src_hex, const want_hex = switch (v.op) {
            .encrypt => .{ v.pt, v.ct },
            .decrypt => .{ v.ct, v.pt },
        };
        _ = try hex(buf_in[0..n], src_hex);
        _ = try hex(buf_want[0..n], want_hex);
        var off: usize = 0;
        switch (v.op) {
            .encrypt => {
                const ctx = Aes192.initEnc(key);
                while (off < n) : (off += 16) ctx.encrypt(buf_out[off..][0..16], buf_in[off..][0..16]);
            },
            .decrypt => {
                const ctx = Aes192.initDec(key);
                while (off < n) : (off += 16) ctx.decrypt(buf_out[off..][0..16], buf_in[off..][0..16]);
            },
        }
        testing.expectEqualSlices(u8, buf_want[0..n], buf_out[0..n]) catch |err| {
            std.debug.print("CAVP {s} {t} COUNT={d}\n", .{ v.file, v.op, v.count });
            return err;
        };
        for (files, 0..) |f, i| {
            if (std.mem.eql(u8, f, v.file)) per_file[i] += 1;
        }
    }
    // The pinned per-file totals: a generator that dropped a section would
    // still leave every surviving vector green.
    try testing.expectEqual(@as(usize, 720), cavp.total);
    try testing.expectEqualSlices(usize, &.{ 12, 48, 384, 256, 20 }, &per_file);
}

test "SP 800-38A F.1.3/F.1.4 and F.5.5/F.5.6: ECB and CTR (std.crypto.core.modes.ctr) over Aes192EncryptCtx" {
    const key = fromHex(24, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    const pt = fromHex(64, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" ++
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    const ecb = fromHex(64, "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eef" ++
        "ef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e");
    const ctr = fromHex(64, "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e94" ++
        "1e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050");
    const iv = fromHex(16, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    const enc = Aes192.initEnc(key);
    const dec = Aes192.initDec(key);
    var out: [64]u8 = undefined;
    enc.encryptWide(4, &out, &pt);
    try testing.expectEqualSlices(u8, &ecb, &out);
    dec.decryptWide(4, &out, &ecb);
    try testing.expectEqualSlices(u8, &pt, &out);
    std.crypto.core.modes.ctr(Aes192EncryptCtx, enc, &out, &pt, iv, .big);
    try testing.expectEqualSlices(u8, &ctr, &out);
    std.crypto.core.modes.ctr(Aes192EncryptCtx, enc, &out, &ctr, iv, .big);
    try testing.expectEqualSlices(u8, &pt, &out);
}

test "wide and xor paths agree with the one-block path, every width 1..9" {
    const key = fromHex(24, "000102030405060708090a0b0c0d0e0f1011121314151617");
    const enc = Aes192.initEnc(key);
    const dec = Aes192.initDec(key);
    var src: [16 * 9]u8 = undefined;
    for (&src, 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);
    var ctrs: [16 * 9]u8 = undefined;
    for (&ctrs, 0..) |*b, i| b.* = @truncate(i *% 101 +% 3);
    inline for (1..10) |count| {
        const n = 16 * count;
        var one: [n]u8 = undefined;
        var wide: [n]u8 = undefined;
        for (0..count) |j| enc.encrypt(one[j * 16 ..][0..16], src[j * 16 ..][0..16]);
        enc.encryptWide(count, &wide, src[0..n]);
        try testing.expectEqualSlices(u8, &one, &wide);

        var back: [n]u8 = undefined;
        dec.decryptWide(count, &back, &wide);
        try testing.expectEqualSlices(u8, src[0..n], &back);

        // xor == E(counter) ^ src, one block and wide.
        var ks: [n]u8 = undefined;
        for (0..count) |j| enc.encrypt(ks[j * 16 ..][0..16], ctrs[j * 16 ..][0..16]);
        for (&ks, src[0..n]) |*k, s| k.* ^= s;
        var x1: [n]u8 = undefined;
        for (0..count) |j| enc.xor(x1[j * 16 ..][0..16], src[j * 16 ..][0..16], ctrs[j * 16 ..][0..16].*);
        try testing.expectEqualSlices(u8, &ks, &x1);
        var xw: [n]u8 = undefined;
        enc.xorWide(count, &xw, src[0..n], ctrs[0..n].*);
        try testing.expectEqualSlices(u8, &ks, &xw);
    }
}

test "the *Into twins build the same contexts as the by-value constructors" {
    const key = fromHex(24, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    var e: Aes192EncryptCtx = undefined;
    var d: Aes192DecryptCtx = undefined;
    Aes192.initEncInto(&e, &key);
    Aes192.initDecInto(&d, &key);
    const e2 = Aes192.initEnc(key);
    const d2 = Aes192.initDec(key);
    try testing.expectEqualSlices(u8, std.mem.asBytes(&e2.key_schedule), std.mem.asBytes(&e.key_schedule));
    try testing.expectEqualSlices(u8, std.mem.asBytes(&d2.key_schedule), std.mem.asBytes(&d.key_schedule));
    try testing.expect(!std.mem.eql(u8, std.mem.asBytes(&e.key_schedule), std.mem.asBytes(&d.key_schedule)));
}

test "wipe zeroes the round keys" {
    const key = fromHex(24, "000102030405060708090a0b0c0d0e0f1011121314151617");
    var e = Aes192.initEnc(key);
    var d = Aes192.initDec(key);
    try testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&e.key_schedule), 0));
    try testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&d.key_schedule), 0));
    e.wipe();
    d.wipe();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&e.key_schedule), 0));
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&d.key_schedule), 0));
}

test "subWord is FIPS-197 SubWord for all 256 bytes, in every byte position" {
    // S(0x53) = 0xed is the worked example of FIPS-197 §5.1.1.
    try testing.expectEqual([4]u8{ 0xed, 0x63, 0x7c, 0x16 }, subWord(.{ 0x53, 0x00, 0x01, 0xff }));
    // The full table, transcribed from FIPS-197 Table 4 (model_test.zig).
    const sbox = @import("model_test.zig").sbox;
    for (0..256) |x| {
        const w = [4]u8{ @truncate(x), @truncate(x +% 85), @truncate(x +% 170), @truncate(x +% 255) };
        const got = subWord(w);
        for (w, got) |in, out| try testing.expectEqual(sbox[in], out);
    }
}

test "invMixColumns through the round primitives equals std's Block.invMixColumns" {
    var prng = std.Random.DefaultPrng.init(0x1c);
    for (0..512) |_| {
        var b: [16]u8 = undefined;
        prng.random().bytes(&b);
        const x = Block.fromBytes(&b);
        try testing.expectEqual(x.invMixColumns().toBytes(), invMixColumns(x).toBytes());
    }
}
