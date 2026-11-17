// SPDX-License-Identifier: MIT
//! Tests that close the gaps the 2026-11-17 whole-module mutation audit found:
//! each one names the mutant (what a surviving change did) it exists to kill.
//! Nothing here is a general test of the module; the module's own tests sit
//! beside the code and in `harness_test.zig` / `snarkjs_files_test.zig`.

const std = @import("std");
const bn254 = @import("bn254");
const field = @import("field.zig");
const poly = @import("poly.zig");
const domain = @import("domain.zig");
const circom = @import("circom.zig");

const Fr = field.Fr;
const testing = std.testing;
const u = field.frFromU64;

fn frDec(comptime s: []const u8) Fr {
    var b: [32]u8 = undefined;
    std.mem.writeInt(u256, &b, std.fmt.parseInt(u256, s, 10) catch unreachable, .big);
    return Fr.fromBytes(b) catch unreachable;
}

// ── domain ────────────────────────────────────────────────────────────────

test "domain: the 2^28-th root of unity is the arkworks / snarkjs constant (generator 5)" {
    // Mutant: `generator` 5 -> 7. 5 and 7 give the SAME root for every domain up
    // to 2^5 (and every fixture here is that small), so only a pin at a larger
    // size tells them apart. 19103219067921713944291392827692070036145651957329286315305642004821462161904
    // is `TWO_ADIC_ROOT_OF_UNITY` of ark-bn254 (the same omega snarkjs and
    // ffjavascript use), i.e. 5^((r-1)/2^28).
    const w28 = frDec("19103219067921713944291392827692070036145651957329286315305642004821462161904");
    try testing.expect(domain.rootOfUnity(28).eql(w28));
    // ... and the smaller ones are its repeated squares (domain 2^6 is the first
    // size where 5 and 7 differ).
    var w = w28;
    for (0..22) |_| w = w.square();
    try testing.expect(domain.rootOfUnity(6).eql(w));
    try testing.expect(domain.Domain(64).root().eql(w));
}

// ── poly ──────────────────────────────────────────────────────────────────

test "poly.add / poly.sub: operands of different length, either one shorter" {
    // Mutants: `i < a.len` / `i < b.len` -> `<=` read one past the shorter operand.
    const a = [_]Fr{ u(1), u(2), u(3) };
    const b = [_]Fr{ u(10), u(20) };
    var out: [3]Fr = undefined;
    poly.add(&out, &a, &b);
    try testing.expect(out[0].eql(u(11)) and out[1].eql(u(22)) and out[2].eql(u(3)));
    poly.add(&out, &b, &a);
    try testing.expect(out[0].eql(u(11)) and out[1].eql(u(22)) and out[2].eql(u(3)));
    poly.sub(&out, &a, &b);
    try testing.expect(out[0].eql(u(1).sub(u(10))) and out[1].eql(u(2).sub(u(20))) and out[2].eql(u(3)));
    poly.sub(&out, &b, &a);
    try testing.expect(out[0].eql(u(10).sub(u(1))) and out[1].eql(u(20).sub(u(2))) and out[2].eql(Fr.zero.sub(u(3))));
}

test "poly.mulSchoolbook: an empty operand gives the empty product, whatever the other length" {
    // Mutant: the `a.len == 0 or b.len == 0` early return dropped, which asserts
    // `out.len == a.len + b.len - 1` (an underflow for two empty operands, a
    // length mismatch for one).
    var none: [0]Fr = .{};
    poly.mulSchoolbook(&none, &none, &none);
    const b = [_]Fr{ u(1), u(2) };
    poly.mulSchoolbook(&none, &none, &b);
    poly.mulSchoolbook(&none, &b, &none);
}

test "poly.divByVanishing: exactly max_degree coefficients are accepted, one more is refused" {
    // Mutant: `p.len > max_degree` -> `>=`.
    const a = testing.allocator;
    const p = try a.alloc(Fr, poly.max_degree + 1);
    defer a.free(p);
    @memset(p, Fr.zero);
    p[0] = Fr.one; // not divisible by x^2 - 1: remainder 1
    const q = try a.alloc(Fr, poly.max_degree - 2);
    defer a.free(q);
    try testing.expectEqual(false, try poly.divByVanishing(q, p[0..poly.max_degree], 2));
    p[0] = Fr.zero;
    try testing.expectEqual(true, try poly.divByVanishing(q, p[0..poly.max_degree], 2));
    const q1 = try a.alloc(Fr, poly.max_degree - 1);
    defer a.free(q1);
    try testing.expectError(error.PolynomialTooLarge, poly.divByVanishing(q1, p, 2));
}

// ── circom ────────────────────────────────────────────────────────────────

test "circom.parseWitness: a witness file with no entries is refused, not read past its end" {
    // Mutant: the `n == 0` refusal dropped, `out[0]` then reads an empty slice.
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try circom.writeWitness(&aw.writer, &.{});
    try testing.expectError(error.BadIndex, circom.parseWitness(testing.allocator, aw.written()));
}

// ── file-format refusals the mutation audit found untested ─────────────────

const bin = @import("snarkjs_bin.zig");
const ptau_mod = @import("ptau.zig");
const Sections = [bin.BinFile.max_sections]?[]const u8;

const t_r1cs = @embedFile("testdata/snarkjs/t.r1cs");
const pot_ptau = @embedFile("testdata/snarkjs/pot.ptau");

/// A file of `magic`/`version` holding exactly `secs` (by type id), any order
/// the parsers do not care about.
fn buildFile(a: std.mem.Allocator, magic: *const [4]u8, version: u32, secs: Sections) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(a);
    errdefer aw.deinit();
    var n: u32 = 0;
    for (secs) |s| n += @intFromBool(s != null);
    try bin.writeHeader(&aw.writer, magic, version, n);
    for (secs, 0..) |maybe, ty| {
        const s = maybe orelse continue;
        try bin.writeSectionHeader(&aw.writer, @intCast(ty), s.len);
        try aw.writer.writeAll(s);
    }
    return aw.toOwnedSlice();
}

fn sectionsOf(bytes: []const u8, magic: *const [4]u8) !struct { version: u32, secs: Sections } {
    const f = try bin.BinFile.parse(bytes, magic);
    return .{ .version = f.version, .secs = f.sections };
}

fn withSection(a: std.mem.Allocator, bytes: []const u8, magic: *const [4]u8, ty: usize, payload: ?[]const u8) ![]u8 {
    const f = try sectionsOf(bytes, magic);
    var secs = f.secs;
    secs[ty] = payload;
    return buildFile(a, magic, f.version, secs);
}

/// A one-constraint circuit `w2 * w2 = w1` with `n_wires` wires, header counts
/// as given (the wire map section is `8 * n_wires` zero bytes).
fn tinyR1cs(a: std.mem.Allocator, n_wires: u32, n_pub_out: u32, n_pub_in: u32, n_prv_in: u32) !struct { bytes: []u8, header: []u8, body: []u8 } {
    var hw: std.Io.Writer.Allocating = .init(a);
    errdefer hw.deinit();
    try bin.writePrime(&hw.writer, &bin.r_le);
    for ([_]u32{ n_wires, n_pub_out, n_pub_in, n_prv_in }) |v| try hw.writer.writeInt(u32, v, .little);
    try hw.writer.writeInt(u64, n_wires, .little);
    try hw.writer.writeInt(u32, 1, .little);
    const header = try hw.toOwnedSlice();
    errdefer a.free(header);

    var bw: std.Io.Writer.Allocating = .init(a);
    errdefer bw.deinit();
    for ([_]u32{ 2, 2, 1 }) |wire| { // A = w2, B = w2, C = w1, coefficient 1
        try bw.writer.writeInt(u32, 1, .little);
        try bw.writer.writeInt(u32, wire, .little);
        try bw.writer.writeAll(&bin.frToLe(Fr.one));
    }
    const body = try bw.toOwnedSlice();
    errdefer a.free(body);

    const wire_map = try a.alloc(u8, 8 * @as(usize, n_wires));
    defer a.free(wire_map);
    @memset(wire_map, 0);
    var secs: Sections = @splat(null);
    secs[1] = header;
    secs[2] = body;
    secs[3] = wire_map;
    return .{ .bytes = try buildFile(a, "r1cs", 1, secs), .header = header, .body = body };
}

test "r1cs: refusals the whole-module mutation found untested" {
    const a = testing.allocator;
    // The smallest valid circuit: every wire is the constant, an output or an
    // input (n_wires = 1 + 1 + 0 + 1). Mutant: `... + 1 > n_wires` -> `>=`.
    const ok = try tinyR1cs(a, 3, 1, 0, 1);
    defer a.free(ok.bytes);
    defer a.free(ok.header);
    defer a.free(ok.body);
    var r = try circom.parseR1cs(a, ok.bytes);
    r.deinit(a);
    const short = try tinyR1cs(a, 2, 1, 0, 1); // one wire fewer than the counts need
    defer a.free(short.bytes);
    defer a.free(short.header);
    defer a.free(short.body);
    try testing.expectError(error.BadIndex, circom.parseR1cs(a, short.bytes));

    // Mutant: the version check dropped.
    const v2 = try buildFile(a, "r1cs", 2, (try sectionsOf(ok.bytes, "r1cs")).secs);
    defer a.free(v2);
    try testing.expectError(error.UnsupportedVersion, circom.parseR1cs(a, v2));

    // Mutants: either custom-gate section (4 list, 5 application) dropped from the refusal.
    for ([_]usize{ 4, 5 }) |ty| {
        const g = try withSection(a, ok.bytes, "r1cs", ty, "");
        defer a.free(g);
        try testing.expectError(error.Unsupported, circom.parseR1cs(a, g));
    }

    // Mutant: `hc.rest() != 0` dropped (a header with trailing bytes).
    const long_header = try std.mem.concat(a, u8, &.{ ok.header, "x" });
    defer a.free(long_header);
    const lh = try withSection(a, ok.bytes, "r1cs", 1, long_header);
    defer a.free(lh);
    try testing.expectError(error.BadSectionSize, circom.parseR1cs(a, lh));

    // Mutant: the trailing-bytes check of the constraint section dropped.
    const long_body = try std.mem.concat(a, u8, &.{ ok.body, "x" });
    defer a.free(long_body);
    const lb = try withSection(a, ok.bytes, "r1cs", 2, long_body);
    defer a.free(lb);
    try testing.expectError(error.BadSectionSize, circom.parseR1cs(a, lb));
}

test "BinFile.parse: a file that is only a header (no sections) is a file" {
    // Mutant: `bytes.len < 12` -> `<=`.
    const empty = try buildFile(testing.allocator, "wtns", 2, @splat(null));
    defer testing.allocator.free(empty);
    try testing.expectEqual(@as(usize, 12), empty.len);
    const f = try bin.BinFile.parse(empty, "wtns");
    try testing.expectError(error.MissingSection, f.get(1));
}

test "ptau: header and section refusals, point accessors at their bounds" {
    const a = testing.allocator;
    const base = try sectionsOf(pot_ptau, "ptau");
    const p = try ptau_mod.Ptau.parse(pot_ptau);

    // Mutants: version check dropped; power < 1 and power > 28 refusals.
    const v2 = try buildFile(a, "ptau", 2, base.secs);
    defer a.free(v2);
    try testing.expectError(error.UnsupportedVersion, ptau_mod.Ptau.parse(v2));
    for ([_]u32{ 0, 29 }) |power| {
        const h = try a.dupe(u8, base.secs[1].?);
        defer a.free(h);
        std.mem.writeInt(u32, h[36..40], power, .little);
        const f = try withSection(a, pot_ptau, "ptau", 1, h);
        defer a.free(f);
        try testing.expectError(error.BadIndex, ptau_mod.Ptau.parse(f));
    }

    // Mutants: each required section (2..6) not required / the check dropped.
    for ([_]usize{ 2, 3, 4, 5, 6 }) |ty| {
        const f = try withSection(a, pot_ptau, "ptau", ty, null);
        defer a.free(f);
        try testing.expectError(error.MissingSection, ptau_mod.Ptau.parse(f));
    }

    // Mutant: the size check of the (optional) section 12 dropped.
    const s12 = base.secs[12].?;
    const f12 = try withSection(a, pot_ptau, "ptau", 12, s12[0 .. s12.len - 64]);
    defer a.free(f12);
    try testing.expectError(error.BadSectionSize, ptau_mod.Ptau.parse(f12));

    // Mutants: index `>` for `>=` in the three accessors (one past the last point).
    const n: usize = @as(usize, 1) << p.power;
    try testing.expectError(error.BadIndex, p.tauG1(2 * n - 1));
    try testing.expectError(error.BadIndex, p.tauG2(n));
    try testing.expectError(error.BadIndex, p.lagrangeG1(.tau_g1, 3, 8));
    try testing.expectError(error.BadIndex, p.lagrangeG2(3, 8));
    // Mutant: tauG2 reading section 6 (the single beta point): index 0 is the generator.
    const g2 = try p.tauG2(0);
    try testing.expect(g2.x.eql(bn254.G2.Affine.generator.x) and g2.y.eql(bn254.G2.Affine.generator.y));
}

test "snarkjs_bin: field-prime width, length overflow and slice sizes" {
    const a = testing.allocator;
    // Mutant: `n8 != 32` dropped (a header that names a 33-byte field but carries our prime).
    const h = try a.dupe(u8, (try sectionsOf(t_r1cs, "r1cs")).secs[1].?);
    defer a.free(h);
    std.mem.writeInt(u32, h[0..4], 33, .little);
    const f = try withSection(a, t_r1cs, "r1cs", 1, h);
    defer a.free(f);
    try testing.expectError(error.WrongField, circom.parseR1cs(a, f));

    // Mutant: the u64 overflow of `count * width` wraps instead of refusing
    // (2^62 * 64 = 2^68 wraps to 0).
    try testing.expectError(error.BadSectionSize, bin.byteLen(@as(u64, 1) << 62, 64));
    try testing.expectEqual(@as(usize, 128), try bin.byteLen(2, 64));

    // Mutants: `g1Slice` / `g2SliceUnchecked` accept a byte string longer than the output needs.
    var g1s: [2]bn254.G1.Affine = undefined;
    var g1b: [2 * bin.g1_bytes + 1]u8 = @splat(0);
    try testing.expectError(error.BadSectionSize, bin.g1Slice(&g1b, &g1s));
    try bin.g1Slice(g1b[0 .. 2 * bin.g1_bytes], &g1s);
    var g2s: [2]bn254.G2.Affine = undefined;
    var g2b: [2 * bin.g2_bytes + 1]u8 = @splat(0);
    try testing.expectError(error.BadSectionSize, bin.g2SliceUnchecked(&g2b, &g2s));
    try bin.g2SliceUnchecked(g2b[0 .. 2 * bin.g2_bytes], &g2s);
}

test "zkey.Contribution.name: an empty name, a name after another parameter, a truncated one" {
    // Mutants: `i + 2 <= params.len` -> `<` (loses a zero-length name), and the
    // skip `i += 2 + len` -> `i += 2` (a parameter before the name is read as tags).
    const zkey_mod = @import("zkey.zig");
    var c: zkey_mod.Contribution = undefined;
    c.params = &.{ 1, 0 };
    try testing.expectEqualStrings("", c.name().?);
    c.params = &.{ 2, 3, 1, 1, 1, 1, 2, 'h', 'i' };
    try testing.expectEqualStrings("hi", c.name().?);
    c.params = &.{ 1, 3, 'a', 'b' }; // declared length runs past the end
    try testing.expectEqual(@as(?[]const u8, null), c.name());
    c.params = &.{};
    try testing.expectEqual(@as(?[]const u8, null), c.name());
}

const zkey_file = @import("zkey.zig");
const import = @import("snarkjs_import.zig");
const t1_zkey = @embedFile("testdata/snarkjs/t1.zkey");

test "zkey.parse: version, domain size at its cap, a forged coefficient count, ignorable extra sections" {
    const a = testing.allocator;
    const base = try sectionsOf(t1_zkey, "zkey");

    // Mutant: the version check dropped.
    const v2 = try buildFile(a, "zkey", 2, base.secs);
    defer a.free(v2);
    try testing.expectError(error.UnsupportedVersion, zkey_file.parse(a, v2));

    // Mutant: `domain_size > 2^28` -> `>=`. A domain of exactly 2^28 passes the
    // header check; its H section is then (correctly) the wrong size.
    const h = try a.dupe(u8, base.secs[2].?);
    defer a.free(h);
    std.mem.writeInt(u32, h[80..84], @as(u32, 1) << 28, .little);
    const big = try withSection(a, t1_zkey, "zkey", 2, h);
    defer a.free(big);
    try testing.expectError(error.BadSectionSize, zkey_file.parse(a, big));

    // Mutant: the coefficient section's size check dropped, which would
    // allocate for the count the file claims.
    const co = try a.dupe(u8, base.secs[4].?);
    defer a.free(co);
    std.mem.writeInt(u32, co[0..4], 0x0fff_ffff, .little);
    const forged = try withSection(a, t1_zkey, "zkey", 4, co);
    defer a.free(forged);
    try testing.expectError(error.BadSectionSize, zkey_file.parse(a, forged));

    // Mutants: section ids 0 and 11 counted among the ten the format has. A
    // reader ignores sections it does not know.
    for ([_]usize{ 0, 11 }) |ty| {
        const extra = try withSection(a, t1_zkey, "zkey", ty, "");
        defer a.free(extra);
        var z = try zkey_file.parse(a, extra);
        z.deinit(a);
    }
}

test "snarkjs_import: decimal overflow, digit range, point-at-infinity encodings, negative nPublic" {
    const a = testing.allocator;
    // Mutants: the u256 multiply / add overflow checks dropped (2^256 wraps to 0
    // in the add; 2^256 + 5 wraps to 5 in the multiply), and `c > '9'` dropped
    // (':' would be the digit ten).
    for ([_][]const u8{
        "[\"115792089237316195423570985008687907853269984665640564039457584007913129639936\"]",
        "[\"115792089237316195423570985008687907853269984665640564039457584007913129639941\"]",
        "[\"1:\"]",
    }) |json| {
        try testing.expectError(error.NonCanonicalNumber, import.parsePublic(a, json));
    }

    const head = "{\"protocol\":\"groth16\",\"curve\":\"bn128\",";
    const inf1 = "[\"0\",\"1\",\"0\"]";
    const inf2 = "[[\"0\",\"0\"],[\"1\",\"0\"],[\"0\",\"0\"]]";
    // G1 infinity is (0, 1, 0): any other x or y is a malformed encoding
    // (mutants: the y == 1 check dropped).
    // G2 infinity is ((0,0), (1,0), (0,0)); finite points have z == (1, 0)
    // (mutants: x == 0, y == 1 and the z check dropped).
    const cases = [_]struct { a: []const u8, b: []const u8 }{
        .{ .a = "[\"0\",\"2\",\"0\"]", .b = inf2 },
        .{ .a = inf1, .b = "[[\"1\",\"0\"],[\"1\",\"0\"],[\"0\",\"0\"]]" },
        .{ .a = inf1, .b = "[[\"0\",\"0\"],[\"2\",\"0\"],[\"0\",\"0\"]]" },
        .{ .a = inf1, .b = "[[\"0\",\"0\"],[\"1\",\"0\"],[\"1\",\"1\"]]" },
        .{ .a = inf1, .b = "[[\"0\",\"0\"],[\"1\",\"0\"],[\"2\",\"0\"]]" },
    };
    for (cases) |c| {
        const json = try std.fmt.allocPrint(a, "{s}\"pi_a\":{s},\"pi_b\":{s},\"pi_c\":{s}}}", .{ head, c.a, c.b, inf1 });
        defer a.free(json);
        try testing.expectError(error.InvalidShape, import.parseProof(a, json));
    }

    // Mutant: `n < 0` dropped (the cast of a negative count to u64 panics).
    const neg = try std.fmt.allocPrint(a, "{s}\"nPublic\":-1,\"IC\":[{s}]}}", .{ head, inf1 });
    defer a.free(neg);
    try testing.expectError(error.PublicCountMismatch, import.parseVerifyingKey(a, neg));
}

// ── heap scratch: dirty on the way in ─────────────────────────────────────

const zkprove = @import("zkprove.zig");
const prover = @import("prover.zig");
const G1 = bn254.G1;
const G2 = bn254.G2;
const t_wtns = @embedFile("testdata/snarkjs/t.wtns");

/// Fills every new allocation with a varying byte pattern, so "uninitialised"
/// is never zero and never a constant (a constant offset of every evaluation
/// cancels out of the quotient, which would hide a missing zeroing). (It
/// cannot also check that scratch is wiped before it is freed: `Allocator.free`
/// poisons the block before the vtable sees it in the safe modes. That check
/// is the stack-probe test's heap scan, ReleaseFast only.)
const Dirty = struct {
    parent: std.mem.Allocator,

    const vtable: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };

    fn allocator(self: *Dirty) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *Dirty = @ptrCast(@alignCast(ctx));
        const p = self.parent.rawAlloc(len, alignment, ra) orelse return null;
        for (p[0..len], 0..) |*byte, i| byte.* = @truncate((i *% 2654435761) >> 7);
        return p;
    }

    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }

    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *Dirty = @ptrCast(@alignCast(ctx));
        self.parent.rawFree(memory, alignment, ra);
    }
};

fn g1Same(a: G1.Affine, b: G1.Affine) bool {
    if (a.infinity or b.infinity) return a.infinity == b.infinity;
    return a.x.eql(b.x) and a.y.eql(b.y);
}

fn g2Same(a: G2.Affine, b: G2.Affine) bool {
    if (a.infinity or b.infinity) return a.infinity == b.infinity;
    return a.x.eql(b.x) and a.y.eql(b.y);
}

test "zkprove.prove: scratch is zeroed before use, whatever the allocator hands out" {
    // Mutant: `@memset(evals, Fr.zero)` dropped (the coefficient loop accumulates
    // onto whatever the allocator hands out).
    const a = testing.allocator;
    var z = try zkey_file.parse(a, t1_zkey);
    defer z.deinit(a);
    const w = try circom.parseWitness(a, t_wtns);
    defer circom.freeWitness(a, w);
    const rand: prover.Randomizers = .{ .r = u(11), .s = u(13) };
    for ([_]zkprove.Msm{ .pippenger, .constant_time }) |kind| {
        const want = try zkprove.proveWith(a, z, w, &rand, .{ .msm = kind });
        var dirty: Dirty = .{ .parent = a };
        const got = try zkprove.proveWith(dirty.allocator(), z, w, &rand, .{ .msm = kind });
        try testing.expect(g1Same(got.a, want.a) and g2Same(got.b, want.b) and g1Same(got.c, want.c));
    }
}

test "zkprove.prove: a domain of 2^28 is refused before anything is allocated" {
    // Mutant: `log_n + 1 > max_log_size` -> `log_n > max_log_size`, which would
    // go on to ask for 3 * 2^28 field elements (and then for the 2^29-th root
    // of unity, which does not exist).
    var z: zkey_file.ZKey = undefined;
    z.n_vars = 1;
    z.domain_size = @as(u32, 1) << 28;
    const rand: prover.Randomizers = .{ .r = u(1), .s = u(1) };
    try testing.expectError(error.DomainTooLarge, zkprove.prove(testing.allocator, z, &.{Fr.one}, &rand));
    try testing.expectError(error.WitnessMismatch, zkprove.prove(testing.allocator, z, &.{ Fr.one, Fr.one }, &rand));
}

// ── phase 2: newZkey on circuits the fixtures do not cover; verify's verdicts ──

const phase2 = @import("phase2.zig");
const r1cs_mod = @import("r1cs.zig");
const Fp = bn254.Fp;
const ZKey = zkey_file.ZKey;

fn tm(index: usize, v: u64) r1cs_mod.Term {
    return .{ .index = index, .coeff = u(v) };
}

test "phase2.newZkey: a circuit with coefficients proves and verifies; the domain is the next power of two of the rows" {
    // 2a * 3b = 6t and (t + a) * b = out, witness [1, out=24, a=2, b=3, t=6]:
    // 4 rows (2 constraints + 1 public + 1), so a domain of exactly 4. Mutants:
    // `(1 << l) < rows` -> `<=` (a power-of-two row count doubled), a B
    // coefficient taken as 1, the C-column cursor of `fromR1csC` not advanced.
    const a = testing.allocator;
    var cons = [_]r1cs_mod.Constraint{
        .{ .a = &.{tm(2, 2)}, .b = &.{tm(3, 3)}, .c = &.{tm(4, 6)} },
        .{ .a = &.{ tm(4, 1), tm(2, 1) }, .b = &.{tm(3, 1)}, .c = &.{tm(1, 1)} },
    };
    const r: circom.R1cs = .{ .n_wires = 5, .n_pub_out = 1, .n_pub_in = 0, .n_prv_in = 2, .n_labels = 0, .constraints = &cons, .terms = &.{} };
    const p = try ptau_mod.Ptau.parse(pot_ptau);
    var z = try phase2.newZkey(a, r, p);
    defer z.deinit(a);
    try testing.expectEqual(@as(u32, 4), z.domain_size);

    const want = [_]struct { m: zkey_file.Coef.Matrix, row: u32, sig: u32, v: u64 }{
        .{ .m = .a, .row = 0, .sig = 2, .v = 2 }, .{ .m = .b, .row = 0, .sig = 3, .v = 3 },
        .{ .m = .a, .row = 1, .sig = 4, .v = 1 }, .{ .m = .a, .row = 1, .sig = 2, .v = 1 },
        .{ .m = .b, .row = 1, .sig = 3, .v = 1 }, .{ .m = .a, .row = 2, .sig = 0, .v = 1 },
        .{ .m = .a, .row = 3, .sig = 1, .v = 1 },
    };
    try testing.expectEqual(want.len, z.coefs.len);
    for (want, z.coefs) |w, c| {
        try testing.expectEqual(w.m, c.matrix);
        try testing.expectEqual(w.row, c.constraint);
        try testing.expectEqual(w.sig, c.signal);
        try testing.expect(c.value.eql(u(w.v)));
    }

    const wit = [_]Fr{ Fr.one, u(24), u(2), u(3), u(6) };
    try testing.expect(r1cs_mod.System.isSatisfied(.{ .num_vars = 5, .constraints = &cons }, &wit));
    const proof = try zkprove.prove(a, z, &wit, &.{ .r = u(5), .s = u(7) });
    try testing.expect(try bn254.groth16Verify(z.verifyingKey(), proof, wit[1..2]));
    // A wrong public output is rejected (the key is bound to the circuit, not to one witness).
    try testing.expect(!(try bn254.groth16Verify(z.verifyingKey(), proof, &.{u(25)})));
}

test "phase2.newZkey: smallest and largest circuits a power-of-tau of power 4 takes" {
    // Mutants: `log_n > p.power` -> `>=`; the minimum domain 2 taken as 1.
    const a = testing.allocator;
    const p = try ptau_mod.Ptau.parse(pot_ptau);
    try testing.expectEqual(@as(u5, 4), p.power);
    const term_w0 = [_]r1cs_mod.Term{tm(0, 1)};
    var rows15: [15]r1cs_mod.Constraint = undefined;
    for (&rows15) |*c| c.* = .{ .a = &term_w0, .b = &term_w0, .c = &term_w0 };
    const none: []r1cs_mod.Constraint = &.{};
    const base: circom.R1cs = .{ .n_wires = 1, .n_pub_out = 0, .n_pub_in = 0, .n_prv_in = 0, .n_labels = 0, .constraints = &rows15, .terms = &.{} };

    // 15 constraints + the constant row = 16 rows = 2^4: fits exactly.
    var z = try phase2.newZkey(a, base, p);
    try testing.expectEqual(@as(u32, 16), z.domain_size);
    z.deinit(a);
    // One more constraint needs 2^5.
    var rows16: [16]r1cs_mod.Constraint = undefined;
    for (&rows16) |*c| c.* = .{ .a = &term_w0, .b = &term_w0, .c = &term_w0 };
    var big = base;
    big.constraints = &rows16;
    try testing.expectError(error.PtauTooSmall, phase2.newZkey(a, big, p));

    // No constraint at all: one row, but a domain of 2 (the least a key can have;
    // zkey.parse refuses less), and the key survives a write/parse round trip.
    var empty = base;
    empty.constraints = none;
    var z0 = try phase2.newZkey(a, empty, p);
    defer z0.deinit(a);
    try testing.expectEqual(@as(u32, 2), z0.domain_size);
    const bytes = try zkey_file.toBytes(a, z0);
    defer a.free(bytes);
    var back = try zkey_file.parse(a, bytes);
    back.deinit(a);
}

test "phase2.circuitHash: pinned, and every section is part of it" {
    // The circuit hash is this module's own (blake2b-512 over the A / B / C /
    // IC / H sections' bytes in the order ic, a, b_g1, b_g2, c, h); the value
    // was derived outside the module from the bytes of `t0.zkey`. Mutants:
    // `newZkey` not setting it, any one section skipped.
    const a = testing.allocator;
    var want: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "d4e298861ec65c95fab388a68d9c328fc842913764c17d39af8056deab5810b4b23eec3b51543ab66e994ec29becb323896910e4418df8c481ea116d295a631b");
    var r = try circom.parseR1cs(a, t_r1cs);
    defer r.deinit(a);
    const p = try ptau_mod.Ptau.parse(pot_ptau);
    var fresh = try phase2.newZkey(a, r, p);
    defer fresh.deinit(a);
    try testing.expectEqualSlices(u8, &want, &fresh.circuit_hash);

    var z = try zkey_file.parse(a, @embedFile("testdata/snarkjs/t0.zkey"));
    defer z.deinit(a);
    try testing.expectEqualSlices(u8, &want, &phase2.circuitHash(z));
    // Moving one element of any section changes the hash (a point-wise tamper
    // of a different, valid element: the generator doubled).
    const g2 = bn254.G1.Jacobian.fromAffine(bn254.G1.Affine.generator).double().toAffine();
    inline for (.{ "ic", "a", "b_g1", "c", "h" }) |sec| {
        const slice = @field(z, sec);
        const keep = slice[0];
        slice[0] = g2;
        try testing.expect(!std.mem.eql(u8, &want, &phase2.circuitHash(z)));
        slice[0] = keep;
    }
    const keep2 = z.b_g2[0];
    z.b_g2[0] = bn254.G2.Jacobian.fromAffine(bn254.G2.Affine.generator).double().toAffine();
    try testing.expect(!std.mem.eql(u8, &want, &phase2.circuitHash(z)));
    z.b_g2[0] = keep2;
    try testing.expectEqualSlices(u8, &want, &phase2.circuitHash(z));
}

fn fpDec(comptime s: []const u8) Fp {
    var b: [32]u8 = undefined;
    std.mem.writeInt(u256, &b, std.fmt.parseInt(u256, s, 10) catch unreachable, .big);
    return Fp.fromBytes(b) catch unreachable;
}

test "phase2.verify: each comparison and count it makes names the field that broke" {
    const a = testing.allocator;
    const io = testing.io;
    const V = phase2.Verdict;
    var r = try circom.parseR1cs(a, t_r1cs);
    defer r.deinit(a);
    const p = try ptau_mod.Ptau.parse(pot_ptau);
    var z = try zkey_file.parse(a, t1_zkey);
    defer z.deinit(a);
    const orig = z;

    try testing.expectEqual(V.ok, try phase2.verify(a, io, r, p, z));

    // Counts and sizes: one scalar field at a time...
    inline for (.{ "n_vars", "n_public", "domain_size" }) |f| {
        @field(z, f) += 1;
        try testing.expectEqual(V.circuit_mismatch, try phase2.verify(a, io, r, p, z));
        @field(z, f) -= 1;
    }
    // ... and one slice length at a time (a section one element short).
    inline for (.{ "coefs", "c", "h", "ic", "a", "b_g1", "b_g2" }) |f| {
        const whole = @field(z, f);
        @field(z, f) = whole[0 .. whole.len - 1];
        try testing.expectEqual(V.circuit_mismatch, try phase2.verify(a, io, r, p, z));
        @field(z, f) = whole;
    }
    z = orig;

    // The coefficient records, one field at a time.
    const c0 = z.coefs[0];
    z.coefs[0].matrix = if (c0.matrix == .a) .b else .a;
    try testing.expectEqual(V.circuit_mismatch, try phase2.verify(a, io, r, p, z));
    z.coefs[0] = c0;
    z.coefs[0].constraint += 1;
    try testing.expectEqual(V.circuit_mismatch, try phase2.verify(a, io, r, p, z));
    z.coefs[0] = c0;
    z.coefs[0].signal += 1;
    try testing.expectEqual(V.circuit_mismatch, try phase2.verify(a, io, r, p, z));
    z.coefs[0] = c0;
    z.coefs[0].value = c0.value.add(Fr.one);
    try testing.expectEqual(V.circuit_mismatch, try phase2.verify(a, io, r, p, z));
    z.coefs[0] = c0;

    // Elements: another valid point, the negated point, the point with its x
    // multiplied by a cube root of unity (same y, still on the curve): each is
    // "a different point", and `eqG1`/`eqG2` must see it through either coordinate.
    const w3 = fpDec("21888242871839275220042445260109153167277707414472061641714758635765020556616");
    const d1 = bn254.G1.Jacobian.fromAffine(bn254.G1.Affine.generator).double().toAffine();
    const d2 = bn254.G2.Jacobian.fromAffine(bn254.G2.Affine.generator).double().toAffine();

    const beta1 = z.beta_g1;
    z.beta_g1 = d1;
    try testing.expectEqual(V.circuit_mismatch, try phase2.verify(a, io, r, p, z));
    z.beta_g1 = beta1;
    const beta2 = z.beta_g2;
    z.beta_g2 = d2;
    try testing.expectEqual(V.circuit_mismatch, try phase2.verify(a, io, r, p, z));
    z.beta_g2 = .{ .x = beta2.x, .y = beta2.y.neg() };
    try testing.expectEqual(V.circuit_mismatch, try phase2.verify(a, io, r, p, z));
    z.beta_g2 = .{ .x = .{ .c0 = beta2.x.c0.mul(w3), .c1 = beta2.x.c1.mul(w3) }, .y = beta2.y };
    try testing.expectEqual(V.circuit_mismatch, try phase2.verify(a, io, r, p, z));
    z.beta_g2 = beta2;
    const gamma = z.gamma_g2;
    z.gamma_g2 = d2;
    try testing.expectEqual(V.circuit_mismatch, try phase2.verify(a, io, r, p, z));
    z.gamma_g2 = gamma;
    const alpha = z.alpha_g1;
    z.alpha_g1 = .{ .x = alpha.x, .y = alpha.y.neg() };
    try testing.expectEqual(V.circuit_mismatch, try phase2.verify(a, io, r, p, z));
    z.alpha_g1 = .{ .x = alpha.x.mul(w3), .y = alpha.y };
    try testing.expectEqual(V.circuit_mismatch, try phase2.verify(a, io, r, p, z));
    z.alpha_g1 = alpha;
    const bg1 = z.b_g1[1];
    z.b_g1[1] = d1;
    try testing.expectEqual(V.circuit_mismatch, try phase2.verify(a, io, r, p, z));
    z.b_g1[1] = bg1;
    try testing.expectEqual(V.ok, try phase2.verify(a, io, r, p, z));
}

// ── heap wipes, optimised builds only ─────────────────────────────────────

const builtin = @import("builtin");
const msm = @import("msm.zig");

var heap_buf: [64 * 1024]u8 align(64) = undefined;

/// `Allocator.free` poisons the block before the allocator sees it in Debug and
/// ReleaseSafe, so "was it wiped before the free" can only be read where it
/// does not (the stack-probe test has the same rule).
fn skipUnlessOptimized() !void {
    if (builtin.mode == .debug or builtin.mode == .safe) return error.SkipZigTest;
}

test "heap wipes: a freed witness and the Pippenger buckets leave no secret-derived bytes behind" {
    // Mutants: `freeWitness` without its `secureZero`, `pippenger` without the
    // `secureZero` of its bucket array (a bucket is the sum of the bases whose
    // scalar digit it is: reading one tells which scalars had which digit).
    try skipUnlessOptimized();

    // The scan itself works: an unwiped freed block is found.
    @memset(&heap_buf, 0);
    var fba: std.heap.FixedBufferAllocator = .init(&heap_buf);
    var a = fba.allocator();
    const marker = [_]u8{ 0x5a, 0xc3, 0x11, 0x9e, 0x77, 0x04, 0xd2, 0x68, 0x3b, 0xf0, 0x8d, 0x26, 0xa1, 0x59, 0xee, 0x40 };
    const blk = try a.alloc(u8, marker.len);
    @memcpy(blk, &marker);
    a.free(blk);
    try testing.expect(std.mem.find(u8, &heap_buf, &marker) != null);

    // freeWitness: a witness element is in the heap before, gone after.
    @memset(&heap_buf, 0);
    fba = .init(&heap_buf);
    a = fba.allocator();
    const w = try circom.parseWitness(a, t_wtns);
    const needle = std.mem.asBytes(&w[1]).*;
    try testing.expect(std.mem.find(u8, &heap_buf, &needle) != null);
    circom.freeWitness(a, w);
    try testing.expect(std.mem.find(u8, &heap_buf, &needle) == null);

    // Pippenger: 9 terms (>= 8: the bucket path), scalars 1..9, so window 0's
    // bucket d holds exactly the base d, and the last window processed is window 0.
    @memset(&heap_buf, 0);
    fba = .init(&heap_buf);
    a = fba.allocator();
    var bases: [9]G1.Affine = undefined;
    var scalars: [9]Fr = undefined;
    var cur = G1.Jacobian.fromAffine(G1.Affine.generator);
    for (&bases, &scalars, 1..) |*b, *s, i| {
        b.* = cur.toAffine();
        s.* = u(i);
        cur = cur.add(G1.Jacobian.fromAffine(G1.Affine.generator));
    }
    const got = (try msm.pippengerG1(a, &bases, &scalars)).toAffine();
    try testing.expect(g1Same(got, msm.msmG1(&bases, &scalars).toAffine()));
    for (bases) |b| {
        const x = std.mem.asBytes(&b.x).*;
        try testing.expect(std.mem.find(u8, &heap_buf, &x) == null);
    }
}
