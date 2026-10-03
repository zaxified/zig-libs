// SPDX-License-Identifier: MIT
//! Interop with real circom/snarkjs files — the module's foreign oracle for
//! the file formats and the zkey prover.
//!
//! `testdata/snarkjs/` was produced by `tools/snarkjs/gen.sh` (circom 2.2.3
//! and snarkjs@0.7.6, run as black boxes; only their OUTPUT is committed)
//! from `t.circom`:
//!
//! ```
//! t <== a*b;  out <== t*c + a;   public [a], output out;   a=3 b=5 c=7
//! ```
//!
//! | file | made by |
//! |---|---|
//! | `t.r1cs` | `circom t.circom --r1cs` |
//! | `t.wtns` | circom's witness generator on `input.json` |
//! | `pot.ptau` | `powersoftau new bn128 4` → `contribute` → `prepare phase2` |
//! | `t0.zkey` | `groth16 setup t.r1cs pot.ptau` (no contribution, δ = 1) |
//! | `t1.zkey` | `zkey contribute t0.zkey` (one contribution) |
//! | `vk.json` | `zkey export verificationkey t1.zkey` |
//! | `proof.json`, `public.json` | `groth16 prove t1.zkey t.wtns` |
//!
//! snarkjs itself confirmed `groth16 verify vk.json public.json proof.json`
//! → OK and `zkey verify t.r1cs pot.ptau t1.zkey` → OK when they were made.

const std = @import("std");
const bn254 = @import("bn254");
const bin = @import("snarkjs_bin.zig");
const zkey = @import("zkey.zig");
const circom = @import("circom.zig");
const ptau_mod = @import("ptau.zig");
const zkprove = @import("zkprove.zig");
const field = @import("field.zig");

const Fp = bn254.Fp;
const Fr = bn254.Fr;
const G1 = bn254.G1;
const G2 = bn254.G2;
const testing = std.testing;

const t_r1cs = @embedFile("testdata/snarkjs/t.r1cs");
const t_wtns = @embedFile("testdata/snarkjs/t.wtns");
const t0_zkey = @embedFile("testdata/snarkjs/t0.zkey");
const t1_zkey = @embedFile("testdata/snarkjs/t1.zkey");
const pot_ptau = @embedFile("testdata/snarkjs/pot.ptau");
const vk_json = @embedFile("testdata/snarkjs/vk.json");
const proof_json = @embedFile("testdata/snarkjs/proof.json");
const public_json = @embedFile("testdata/snarkjs/public.json");

// ── decimal JSON (snarkjs's own export format) → our types ────────────────

fn decBe(s: []const u8) ![32]u8 {
    const v = try std.fmt.parseInt(u256, s, 10);
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, v, .big);
    return out;
}

fn jFp(v: std.json.Value) !Fp {
    return Fp.fromBytes(try decBe(v.string));
}

fn jFr(v: std.json.Value) !Fr {
    return Fr.fromBytes(try decBe(v.string));
}

fn jG1(v: std.json.Value) !G1.Affine {
    const a = v.array.items;
    if (std.mem.eql(u8, a[2].string, "0")) return G1.Affine.identity;
    try testing.expectEqualStrings("1", a[2].string);
    return .{ .x = try jFp(a[0]), .y = try jFp(a[1]) };
}

fn jG2(v: std.json.Value) !G2.Affine {
    const a = v.array.items;
    try testing.expectEqualStrings("1", a[2].array.items[0].string);
    return .{
        .x = .{ .c0 = try jFp(a[0].array.items[0]), .c1 = try jFp(a[0].array.items[1]) },
        .y = .{ .c0 = try jFp(a[1].array.items[0]), .c1 = try jFp(a[1].array.items[1]) },
    };
}

fn g1Eq(a: G1.Affine, b: G1.Affine) bool {
    if (a.infinity or b.infinity) return a.infinity == b.infinity;
    return a.x.eql(b.x) and a.y.eql(b.y);
}

fn g2Eq(a: G2.Affine, b: G2.Affine) bool {
    if (a.infinity or b.infinity) return a.infinity == b.infinity;
    return a.x.eql(b.x) and a.y.eql(b.y);
}

fn parseJson(bytes: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, testing.allocator, bytes, .{});
}

// ── tests ────────────────────────────────────────────────────────────────

test "zkey: every verifying-key value equals what snarkjs exported" {
    var z = try zkey.parse(testing.allocator, t1_zkey);
    defer z.deinit(testing.allocator);
    const j = try parseJson(vk_json);
    defer j.deinit();
    const o = j.value.object;

    try testing.expectEqual(@as(u32, 6), z.n_vars);
    try testing.expectEqual(@as(u32, 2), z.n_public);
    try testing.expectEqual(@as(u32, 8), z.domain_size);
    try testing.expect(g1Eq(z.alpha_g1, try jG1(o.get("vk_alpha_1").?)));
    try testing.expect(g2Eq(z.beta_g2, try jG2(o.get("vk_beta_2").?)));
    try testing.expect(g2Eq(z.gamma_g2, try jG2(o.get("vk_gamma_2").?)));
    try testing.expect(g2Eq(z.delta_g2, try jG2(o.get("vk_delta_2").?)));
    const ic = o.get("IC").?.array.items;
    try testing.expectEqual(ic.len, z.ic.len);
    for (ic, z.ic) |want, got| try testing.expect(g1Eq(got, try jG1(want)));

    // One contribution, named as the recipe named it; its δ is the key's δ.
    try testing.expectEqual(@as(usize, 1), z.contributions.len);
    try testing.expectEqualStrings("c1", z.contributions[0].name().?);
    try testing.expect(g1Eq(z.contributions[0].delta_after, z.delta_g1));
}

test "zkey: the extra public-input rows and the coefficient encoding" {
    var z = try zkey.parse(testing.allocator, t0_zkey);
    defer z.deinit(testing.allocator);
    // 2 A + 2 B entries from the two constraints, then A[2+i][i] = 1 for
    // the constant and the two public signals.
    try testing.expectEqual(@as(usize, 7), z.coefs.len);
    try testing.expectEqual(zkey.Coef.Matrix.a, z.coefs[0].matrix);
    try testing.expectEqual(@as(u32, 2), z.coefs[0].signal);
    try testing.expect(z.coefs[0].value.eql(Fr.zero.sub(Fr.one))); // −1
    for (0..3) |i| {
        const co = z.coefs[4 + i];
        try testing.expectEqual(zkey.Coef.Matrix.a, co.matrix);
        try testing.expectEqual(@as(u32, @intCast(2 + i)), co.constraint);
        try testing.expectEqual(@as(u32, @intCast(i)), co.signal);
        try testing.expect(co.value.eql(Fr.one));
    }
    // Before any contribution δ is the generator, and there is no record.
    try testing.expect(g1Eq(z.delta_g1, G1.Affine.generator));
    try testing.expectEqual(@as(usize, 0), z.contributions.len);
}

test "zkey: write(parse(file)) reproduces both snarkjs files byte for byte" {
    for ([_][]const u8{ t0_zkey, t1_zkey }) |file| {
        var z = try zkey.parse(testing.allocator, file);
        defer z.deinit(testing.allocator);
        const out = try zkey.toBytes(testing.allocator, z);
        defer testing.allocator.free(out);
        try testing.expectEqualSlices(u8, file, out);
    }
}

test "wtns and r1cs: values, and the witness satisfies the circuit" {
    const w = try circom.parseWitness(testing.allocator, t_wtns);
    defer testing.allocator.free(w);
    const want = [_]u64{ 1, 108, 3, 5, 7, 15 }; // [1, out, a, b, c, t]
    try testing.expectEqual(want.len, w.len);
    for (want, w) |e, g| try testing.expect(g.eql(field.frFromU64(e)));

    var r = try circom.parseR1cs(testing.allocator, t_r1cs);
    defer r.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, 6), r.n_wires);
    try testing.expectEqual(@as(u32, 2), r.nPublic());
    try testing.expectEqual(@as(usize, 2), r.constraints.len);
    try testing.expect(r.system().isSatisfied(w));
    var bad = try testing.allocator.dupe(Fr, w);
    defer testing.allocator.free(bad);
    bad[5] = bad[5].add(Fr.one);
    try testing.expect(!r.system().isSatisfied(bad));

    // Our .wtns writer reproduces circom's file.
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try circom.writeWitness(&aw.writer, w);
    try testing.expectEqualSlices(u8, t_wtns, aw.written());
}

test "ptau: header, and the Lagrange basis is over this module's domain" {
    const p = try ptau_mod.Ptau.parse(pot_ptau);
    try testing.expectEqual(@as(u5, 4), p.power);
    try testing.expect(g1Eq(try p.tauG1(0), G1.Affine.generator));
    // x = Σ ωⁱ·Lᵢ(x) on a size-8 domain, so Σ ωⁱ·[Lᵢ(τ)]₁ = [τ]₁.
    const w = @import("domain.zig").rootOfUnity(3);
    var acc = G1.Jacobian.identity;
    var wi = Fr.one;
    for (0..8) |i| {
        acc = acc.add(G1.Jacobian.fromAffine(try p.lagrangeG1(.tau_g1, 3, i)).scalarMul(wi));
        wi = wi.mul(w);
    }
    try testing.expect(g1Eq(acc.toAffine(), try p.tauG1(1)));
}

test "snarkjs's own proof verifies under bn254.groth16Verify with our parsed key" {
    var z = try zkey.parse(testing.allocator, t1_zkey);
    defer z.deinit(testing.allocator);
    const pj = try parseJson(proof_json);
    defer pj.deinit();
    const o = pj.value.object;
    const proof: bn254.Groth16Proof = .{
        .a = try jG1(o.get("pi_a").?),
        .b = try jG2(o.get("pi_b").?),
        .c = try jG1(o.get("pi_c").?),
    };
    const pubj = try parseJson(public_json);
    defer pubj.deinit();
    var publics: [2]Fr = undefined;
    for (pubj.value.array.items, &publics) |v, *out| out.* = try jFr(v);
    try testing.expect(try bn254.groth16Verify(z.verifyingKey(), proof, &publics));
    publics[1] = publics[1].add(Fr.one);
    try testing.expect(!try bn254.groth16Verify(z.verifyingKey(), proof, &publics));
}

test "zkprove: our proof from snarkjs's key and circom's witness verifies" {
    var z = try zkey.parse(testing.allocator, t1_zkey);
    defer z.deinit(testing.allocator);
    const w = try circom.parseWitness(testing.allocator, t_wtns);
    defer testing.allocator.free(w);
    const proof = try zkprove.prove(testing.allocator, z, w, .{ .r = field.frFromU64(11), .s = field.frFromU64(13) });
    try testing.expect(try bn254.groth16Verify(z.verifyingKey(), proof, w[1..3]));

    // An unsatisfying witness gives a proof that does not verify.
    var bad = try testing.allocator.dupe(Fr, w);
    defer testing.allocator.free(bad);
    bad[5] = bad[5].add(Fr.one);
    const bad_proof = try zkprove.prove(testing.allocator, z, bad, .{ .r = field.frFromU64(11), .s = field.frFromU64(13) });
    try testing.expect(!try bn254.groth16Verify(z.verifyingKey(), bad_proof, bad[1..3]));

    try testing.expectError(error.WitnessMismatch, zkprove.prove(testing.allocator, z, w[0..5], .{ .r = Fr.one, .s = Fr.one }));
}

test "zkprove: our proof is the one snarkjs accepted" {
    // `ours_proof.json` is this test's output at r = 11, s = 13, written by
    // `snarkjs_export.proofJson`. `snarkjs groth16 verify vk.json public.json
    // ours_proof.json` printed `OK!`; the same file with pi_a.x + 1 printed
    // `Proof commitments are not valid.` (tools/snarkjs/gen.sh, step "ours").
    // Pinning the bytes keeps that foreign verdict about THIS code.
    var z = try zkey.parse(testing.allocator, t1_zkey);
    defer z.deinit(testing.allocator);
    const w = try circom.parseWitness(testing.allocator, t_wtns);
    defer testing.allocator.free(w);
    const proof = try zkprove.prove(testing.allocator, z, w, .{ .r = field.frFromU64(11), .s = field.frFromU64(13) });
    const js = try @import("snarkjs_export.zig").proofJson(testing.allocator, proof);
    defer testing.allocator.free(js);
    try testing.expectEqualStrings(std.mem.trimEnd(u8, @embedFile("testdata/snarkjs/ours_proof.json"), "\n"), js);
}

// ── phase 2 ─────────────────────────────────────────────────────────────────

const phase2 = @import("phase2.zig");

/// Offset of section 10's payload in `t0.zkey` (`dumpsec` of the file): the
/// 64-byte circuit hash this module does not reproduce (phase2.zig doc).
const t0_hash_off = 3540;

test "phase2.newZkey reproduces snarkjs groth16 setup, all but the circuit hash" {
    var r = try circom.parseR1cs(testing.allocator, t_r1cs);
    defer r.deinit(testing.allocator);
    const p = try ptau_mod.Ptau.parse(pot_ptau);
    var z = try phase2.newZkey(testing.allocator, r, p);
    defer z.deinit(testing.allocator);
    const out = try zkey.toBytes(testing.allocator, z);
    defer testing.allocator.free(out);
    try testing.expectEqual(t0_zkey.len, out.len);
    try testing.expectEqualSlices(u8, t0_zkey[0..t0_hash_off], out[0..t0_hash_off]);
    try testing.expectEqualSlices(u8, t0_zkey[t0_hash_off + 64 ..], out[t0_hash_off + 64 ..]);
}

fn loadAll() !struct { r: circom.R1cs, p: ptau_mod.Ptau } {
    return .{ .r = try circom.parseR1cs(testing.allocator, t_r1cs), .p = try ptau_mod.Ptau.parse(pot_ptau) };
}

test "phase2.verify accepts snarkjs's keys and names what a tampered one broke" {
    var f = try loadAll();
    defer f.r.deinit(testing.allocator);
    for ([_][]const u8{ t0_zkey, t1_zkey }) |file| {
        var z = try zkey.parse(testing.allocator, file);
        defer z.deinit(testing.allocator);
        try testing.expectEqual(phase2.Verdict.ok, try phase2.verify(testing.allocator, testing.io, f.r, f.p, z));
    }

    var z = try zkey.parse(testing.allocator, t1_zkey);
    defer z.deinit(testing.allocator);
    const V = phase2.Verdict;
    const io = testing.io;

    const c0 = z.c[0];
    z.c[0] = G1.Affine.generator;
    try testing.expectEqual(V.not_divided_by_delta, try phase2.verify(testing.allocator, io, f.r, f.p, z));
    z.c[0] = c0;

    const h3 = z.h[3];
    z.h[3] = z.h[4];
    try testing.expectEqual(V.not_divided_by_delta, try phase2.verify(testing.allocator, io, f.r, f.p, z));
    z.h[3] = h3;

    const d2 = z.delta_g2;
    z.delta_g2 = G2.Affine.generator;
    try testing.expectEqual(V.bad_delta, try phase2.verify(testing.allocator, io, f.r, f.p, z));
    z.delta_g2 = d2;

    const a1 = z.a[1];
    z.a[1] = z.a[2];
    try testing.expectEqual(V.circuit_mismatch, try phase2.verify(testing.allocator, io, f.r, f.p, z));
    z.a[1] = a1;

    const ic = z.ic[2];
    z.ic[2] = G1.Affine.generator;
    try testing.expectEqual(V.circuit_mismatch, try phase2.verify(testing.allocator, io, f.r, f.p, z));
    z.ic[2] = ic;

    // A consistent δ the chain does not end at (the record says otherwise).
    z.contributions[0].delta_after = G1.Affine.generator;
    try testing.expectEqual(V.chain_mismatch, try phase2.verify(testing.allocator, io, f.r, f.p, z));
}

test "phase2.contribute over a snarkjs key: still valid, provable, and its proof of knowledge checks" {
    var f = try loadAll();
    defer f.r.deinit(testing.allocator);
    var z = try zkey.parse(testing.allocator, t1_zkey);
    defer z.deinit(testing.allocator);
    const old_delta = z.delta_g2;

    try phase2.contribute(testing.allocator, &z, field.frFromU64(123456789), field.frFromU64(987654321), "zig");
    try testing.expectEqual(@as(usize, 2), z.contributions.len);
    try testing.expectEqualStrings("zig", z.contributions[1].name().?);
    try testing.expect(!g2Eq(z.delta_g2, old_delta));
    try testing.expectEqual(phase2.Verdict.ok, try phase2.verify(testing.allocator, testing.io, f.r, f.p, z));
    try testing.expect(phase2.verifyContribution(z, 1));
    // snarkjs's own record uses its hash-to-G2, which is not reproduced here.
    try testing.expect(!phase2.verifyContribution(z, 0));

    const w = try circom.parseWitness(testing.allocator, t_wtns);
    defer testing.allocator.free(w);
    const proof = try zkprove.prove(testing.allocator, z, w, .{ .r = field.frFromU64(5), .s = field.frFromU64(6) });
    try testing.expect(try bn254.groth16Verify(z.verifyingKey(), proof, w[1..3]));

    // The written file parses back to the same key.
    const out = try zkey.toBytes(testing.allocator, z);
    defer testing.allocator.free(out);
    var back = try zkey.parse(testing.allocator, out);
    defer back.deinit(testing.allocator);
    try testing.expect(phase2.verifyContribution(back, 1));

    // A forged record: δ moved by a different x than its proof claims.
    z.contributions[1].g1_sx = z.contributions[1].g1_s;
    try testing.expect(!phase2.verifyContribution(z, 1));
}

test "phase2.contribute refuses a trivial secret, verifyContribution an index past the end" {
    var z = try zkey.parse(testing.allocator, t0_zkey);
    defer z.deinit(testing.allocator);
    try testing.expectError(error.TrivialSecret, phase2.contribute(testing.allocator, &z, Fr.zero, Fr.one, "x"));
    try testing.expectError(error.TrivialSecret, phase2.contribute(testing.allocator, &z, Fr.one, Fr.one, "x"));
    try testing.expectError(error.TrivialSecret, phase2.contribute(testing.allocator, &z, field.frFromU64(2), Fr.zero, "x"));
    try testing.expectEqual(@as(usize, 0), z.contributions.len);
    try testing.expect(!phase2.verifyContribution(z, 0));
}

// ── forged counts (found by fuzz_test.zig) ─────────────────────────────────

test "zkey: a forged n_vars is refused before anything is allocated for it" {
    // Section 2's payload starts at byte 40 of t1.zkey; n_vars is its 73rd byte.
    var forged = t1_zkey.*;
    std.mem.writeInt(u32, forged[40 + 72 ..][0..4], 0x7fff_ffff, .little);
    // 64 KiB is plenty for the real key and nothing like 2³¹ points: a parser
    // that allocates from the header before checking the section answers
    // OutOfMemory here instead.
    var buf: [64 * 1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    try testing.expectError(error.BadSectionSize, zkey.parse(fba.allocator(), &forged));
}

test "r1cs: a wire count the file does not pay for is refused" {
    // Section 1's payload starts at byte 312 of t.r1cs; n_wires follows n8·prime.
    var forged = t_r1cs.*;
    std.mem.writeInt(u32, forged[312 + 36 ..][0..4], 0xffff_ffff, .little);
    try testing.expectError(error.BadSectionSize, circom.parseR1cs(testing.allocator, &forged));
}

// ── header and index checks (asked for by the mutation run) ───────────────

/// Offset of section `ty`'s size field and payload in a binfile.
fn sectionAt(file: []const u8, ty: u32) struct { head: usize, payload: usize, size: usize } {
    var off: usize = 12;
    while (true) {
        const t = std.mem.readInt(u32, file[off..][0..4], .little);
        const size: usize = @intCast(std.mem.readInt(u64, file[off + 4 ..][0..8], .little));
        if (t == ty) return .{ .head = off, .payload = off + 12, .size = size };
        off += 12 + size;
    }
}

/// `file` with one extra byte at the end of section `ty`'s payload.
fn growSection(file: []const u8, ty: u32) ![]u8 {
    const s = sectionAt(file, ty);
    const end = s.payload + s.size;
    const out = try testing.allocator.alloc(u8, file.len + 1);
    @memcpy(out[0..end], file[0..end]);
    out[end] = 0;
    @memcpy(out[end + 1 ..], file[end..]);
    std.mem.writeInt(u64, out[s.head + 4 ..][0..8], s.size + 1, .little);
    return out;
}

/// `file` with an empty section `ty` appended.
fn addSection(file: []const u8, ty: u32) ![]u8 {
    const out = try testing.allocator.alloc(u8, file.len + 12);
    @memcpy(out[0..file.len], file);
    std.mem.writeInt(u32, out[file.len..][0..4], ty, .little);
    std.mem.writeInt(u64, out[file.len + 4 ..][0..8], 0, .little);
    const n = std.mem.readInt(u32, out[8..12], .little);
    std.mem.writeInt(u32, out[8..12], n + 1, .little);
    return out;
}

fn expectZkeyError(want: anyerror, bytes: []const u8) !void {
    if (zkey.parse(testing.allocator, bytes)) |z| {
        var zz = z;
        zz.deinit(testing.allocator);
        return error.TestExpectedError;
    } else |e| try testing.expectEqual(want, e);
}

fn putU32(file: []u8, at: usize, v: u32) void {
    std.mem.writeInt(u32, file[at..][0..4], v, .little);
}

test "zkey header refusals: protocol, prime, counts, domain, section size" {
    const h2 = sectionAt(t1_zkey, 2).payload;
    {
        var f = t1_zkey.*;
        putU32(&f, sectionAt(t1_zkey, 1).payload, 2); // not Groth16
        try expectZkeyError(error.Unsupported, &f);
    }
    {
        var f = t1_zkey.*;
        f[h2 + 4 + 32 + 4] ^= 1; // r's low byte
        try expectZkeyError(error.WrongField, &f);
    }
    {
        var f = t1_zkey.*;
        putU32(&f, h2 + 76, 6); // n_public == n_vars
        try expectZkeyError(error.BadIndex, &f);
    }
    for ([_]u32{ 0, 1, 7 }) |d| {
        var f = t1_zkey.*;
        putU32(&f, h2 + 80, d); // domain 0, 1, not a power of two
        try expectZkeyError(error.BadIndex, &f);
    }
    {
        const f = try growSection(t1_zkey, 2);
        defer testing.allocator.free(f);
        try expectZkeyError(error.BadSectionSize, f);
    }
}

test "zkey coefficient and contribution refusals" {
    const c4 = sectionAt(t1_zkey, 4).payload + 4; // first entry
    {
        var f = t1_zkey.*;
        putU32(&f, c4, 2); // matrix C is not stored
        try expectZkeyError(error.BadIndex, &f);
    }
    {
        var f = t1_zkey.*;
        putU32(&f, c4 + 4, 8); // constraint == domain_size
        try expectZkeyError(error.BadIndex, &f);
    }
    {
        var f = t1_zkey.*;
        putU32(&f, c4 + 8, 6); // signal == n_vars
        try expectZkeyError(error.BadIndex, &f);
    }
    const s10 = sectionAt(t1_zkey, 10).payload;
    {
        var f = t1_zkey.*;
        putU32(&f, s10 + 64, 1000); // more records than the section holds
        try expectZkeyError(error.BadSectionSize, &f);
    }
    {
        const f = try growSection(t1_zkey, 10);
        defer testing.allocator.free(f);
        try expectZkeyError(error.BadSectionSize, f);
    }
}

test "wtns refusals: version, witness 0" {
    {
        var f = t_wtns.*;
        putU32(&f, 4, 3);
        try testing.expectError(error.UnsupportedVersion, circom.parseWitness(testing.allocator, &f));
    }
    {
        var f = t_wtns.*;
        f[sectionAt(t_wtns, 2).payload] = 2; // w[0] = 2
        try testing.expectError(error.BadIndex, circom.parseWitness(testing.allocator, &f));
    }
}

test "r1cs refusals: custom gates, wire index, signal counts" {
    {
        const f = try addSection(t_r1cs, 4);
        defer testing.allocator.free(f);
        try testing.expectError(error.Unsupported, circom.parseR1cs(testing.allocator, f));
    }
    {
        var f = t_r1cs.*;
        putU32(&f, sectionAt(t_r1cs, 2).payload + 4, 6); // first term's wire == n_wires
        try testing.expectError(error.BadIndex, circom.parseR1cs(testing.allocator, &f));
    }
    {
        var f = t_r1cs.*;
        putU32(&f, sectionAt(t_r1cs, 1).payload + 48, 100); // n_prv_in
        try testing.expectError(error.BadIndex, circom.parseR1cs(testing.allocator, &f));
    }
}

test "ptau refusals: section size, Lagrange level" {
    const f = try growSection(pot_ptau, 3);
    defer testing.allocator.free(f);
    try testing.expectError(error.BadSectionSize, ptau_mod.Ptau.parse(f));
    const p = try ptau_mod.Ptau.parse(pot_ptau);
    try testing.expectError(error.BadIndex, p.lagrangeBytes(.tau_g2, 5));
    try testing.expectError(error.BadIndex, p.lagrangeBytes(.tau_g1, 6));
    _ = try p.lagrangeBytes(.tau_g1, 5); // tau_g1 has one level more
}

test "phase2.verify: tampered coefficients, B₂, α, a zero δ, an off-subgroup δ₂" {
    var f = try loadAll();
    defer f.r.deinit(testing.allocator);
    var z = try zkey.parse(testing.allocator, t1_zkey);
    defer z.deinit(testing.allocator);
    const V = phase2.Verdict;
    const io = testing.io;

    const v0 = z.coefs[0].value;
    z.coefs[0].value = Fr.one;
    try testing.expectEqual(V.circuit_mismatch, try phase2.verify(testing.allocator, io, f.r, f.p, z));
    z.coefs[0].value = v0;

    const b = z.b_g2[3];
    z.b_g2[3] = G2.Affine.generator;
    try testing.expectEqual(V.circuit_mismatch, try phase2.verify(testing.allocator, io, f.r, f.p, z));
    z.b_g2[3] = b;

    const alpha = z.alpha_g1;
    z.alpha_g1 = G1.Affine.generator;
    try testing.expectEqual(V.circuit_mismatch, try phase2.verify(testing.allocator, io, f.r, f.p, z));
    z.alpha_g1 = alpha;

    // δ = 0 on both sides is "consistent" and every C, H check against it is
    // trivially satisfied on the left — it must be refused by name.
    const d1 = z.delta_g1;
    const d2 = z.delta_g2;
    z.delta_g1 = G1.Affine.identity;
    z.delta_g2 = G2.Affine.identity;
    try testing.expectEqual(V.bad_delta, try phase2.verify(testing.allocator, io, f.r, f.p, z));
    z.delta_g1 = d1;

    // On the twist, outside the order-r subgroup (bn254's own test point).
    var c1_bytes = [_]u8{0} ** 32;
    c1_bytes[31] = 1;
    var y0: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&y0, "0cf32d3c49a2cb8a092f24ec3201e68dc299b6216e6321ee60573e3a7f596ea8");
    var y1: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&y1, "07bca656753ef8cbee60335acbffe3def91636952d4ab9eb0b839c7f3566c0e2");
    z.delta_g2 = .{
        .x = .{ .c0 = Fp.zero, .c1 = try Fp.fromBytes(c1_bytes) },
        .y = .{ .c0 = try Fp.fromBytes(y0), .c1 = try Fp.fromBytes(y1) },
    };
    try testing.expectEqual(V.bad_delta, try phase2.verify(testing.allocator, io, f.r, f.p, z));
    z.delta_g2 = d2;
    try testing.expectEqual(V.ok, try phase2.verify(testing.allocator, io, f.r, f.p, z));
}

test "phase2.verify: a moved δ with no contribution record is a chain mismatch" {
    var f = try loadAll();
    defer f.r.deinit(testing.allocator);
    var z = try zkey.parse(testing.allocator, t0_zkey);
    defer z.deinit(testing.allocator);
    try phase2.contribute(testing.allocator, &z, field.frFromU64(3), field.frFromU64(4), "x");
    // Hide the record: a consistent, correctly divided key whose δ the
    // (empty) chain does not account for.
    const recs = z.contributions;
    z.contributions = recs[0..0];
    defer z.contributions = recs;
    try testing.expectEqual(phase2.Verdict.chain_mismatch, try phase2.verify(testing.allocator, testing.io, f.r, f.p, z));
}

test "phase2.verifyContribution: the record's name is bound by its transcript" {
    var z = try zkey.parse(testing.allocator, t0_zkey);
    defer z.deinit(testing.allocator);
    try phase2.contribute(testing.allocator, &z, field.frFromU64(3), field.frFromU64(4), "alice");
    try testing.expect(phase2.verifyContribution(z, 0));
    const params: []u8 = @constCast(z.contributions[0].params);
    params[2] = 'A';
    try testing.expect(!phase2.verifyContribution(z, 0));
}

test "zkey: a verifying-key G2 point outside the subgroup is refused at parse" {
    // On the twist, not in G2: x = u (bn254's g2.zig test point).
    var c1: [32]u8 = @splat(0);
    c1[31] = 1;
    var y0: [32]u8 = undefined;
    var y1: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&y0, "0cf32d3c49a2cb8a092f24ec3201e68dc299b6216e6321ee60573e3a7f596ea8");
    _ = try std.fmt.hexToBytes(&y1, "07bca656753ef8cbee60335acbffe3def91636952d4ab9eb0b839c7f3566c0e2");
    const bad: G2.Affine = .{
        .x = .{ .c0 = Fp.zero, .c1 = try Fp.fromBytes(c1) },
        .y = .{ .c0 = try Fp.fromBytes(y0), .c1 = try Fp.fromBytes(y1) },
    };
    const bad_enc = bin.g2ToBytes(bad);

    var z = try zkey.parse(testing.allocator, t1_zkey);
    const targets = [_][bin.g2_bytes]u8{
        bin.g2ToBytes(z.gamma_g2),
        bin.g2ToBytes(z.delta_g2),
        bin.g2ToBytes(z.contributions[z.contributions.len - 1].g2_spx),
    };
    z.deinit(testing.allocator);

    for (targets) |target| {
        const buf = try testing.allocator.dupe(u8, t1_zkey);
        defer testing.allocator.free(buf);
        const at = std.mem.indexOf(u8, buf, &target) orelse return error.TestPointNotFound;
        buf[at..][0..bin.g2_bytes].* = bad_enc;
        try testing.expectError(error.NotInSubgroup, zkey.parse(testing.allocator, buf));
    }
}
