// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GT, findings MI-1 .. MI-6), see
//! ~/CML/20261029-panic-sweep/montint-sweep.report.md.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const root = @import("root.zig");
const limbs = root.limbs;
const asm_core = root.asm_core;
const safegcd = root.safegcd;
const Modint = root.Modint;
const DynModint = root.DynModint;
const Field = root.Field;

const Child = struct { died: bool, len: usize };

/// Run `body` in a forked child, stderr captured into `buf`; `died` = killed by
/// a signal (a panic aborts). Past five seconds the child counts as hung.
fn runChild(comptime body: fn () void, buf: []u8) !Child {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.SkipZigTest;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    if (rc == 0) {
        _ = linux.dup2(fds[1], 2);
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        body();
        linux.exit_group(0);
    }
    _ = linux.close(fds[1]);
    defer _ = linux.close(fds[0]);
    const pid: linux.pid_t = @intCast(rc);
    var status: u32 = 0;
    var waited_ms: usize = 0;
    while (true) {
        const r = linux.waitpid(pid, @ptrCast(&status), linux.W.NOHANG);
        if (linux.errno(r) != .SUCCESS) return error.WaitFailed;
        if (r == @as(usize, @intCast(pid))) break;
        if (waited_ms >= 5000) {
            _ = linux.kill(pid, .KILL);
            _ = linux.waitpid(pid, @ptrCast(&status), 0);
            return error.ChildHung;
        }
        const ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
        waited_ms += 10;
    }
    const n = linux.read(fds[0], buf.ptr, buf.len);
    return .{ .died = linux.W.IFSIGNALED(status), .len = if (linux.errno(n) == .SUCCESS) n else 0 };
}

// Needles live in consts, never inline at the call: the child's stack trace
// prints the caller's source line, so an inline needle matches ANY panic.
fn expectPanicMessage(comptime body: fn () void, needle: []const u8) !void {
    var buf: [8192]u8 = undefined;
    const c = try runChild(body, &buf);
    try testing.expect(c.died);
    try testing.expect(std.mem.find(u8, buf[0..c.len], needle) != null);
}

const needle_len = limbs.len_mismatch_msg;
const needle_product = limbs.product_len_msg;
const needle_wide = limbs.wide_len_msg;
const needle_scratch = limbs.scratch_len_msg;
const needle_bits = "montint: fromElemUncheckedBits nbits out of range";
const needle_sg = "montint.safegcd: nbits out of range";
const needle_asm = "montint.asm_core: z, a, b, m";
const needle_field = "montint.Field: exponent longer than 8*L bytes";

var runtime_len: usize = 3; // keeps the lengths out of the optimizer's sight

// ── MI-1: limbs length contracts ────────────────────────────────────────────

fn addIntoShort() void {
    var x: [4]u64 = @splat(1);
    const y: [4]u64 = @splat(1);
    _ = limbs.addInto(&x, y[0..runtime_len]);
}
fn subIntoShort() void {
    var x: [4]u64 = @splat(1);
    const y: [4]u64 = @splat(1);
    _ = limbs.subInto(x[0..runtime_len], &y);
}
fn cmpShort() void {
    const x: [4]u64 = @splat(1);
    _ = limbs.cmp(&x, x[0..runtime_len]);
}
fn schoolbookShortZ() void {
    var z: [4]u64 = undefined;
    const x: [4]u64 = @splat(1);
    limbs.mulSchoolbook(z[0..runtime_len], x[0..2], x[0..2]);
}
fn wideSmallLonger() void {
    var big: [2]u64 = @splat(1);
    const small: [4]u64 = @splat(1);
    _ = limbs.addWideInto(big[0..runtime_len -| 1], &small);
}
fn wideSubSmallLonger() void {
    var big: [2]u64 = @splat(1);
    const small: [4]u64 = @splat(1);
    _ = limbs.subWideInto(big[0..runtime_len -| 1], &small);
}

test "limbs.addInto: a length mismatch is a checked montint panic (sweep MI-1a)" {
    try expectPanicMessage(addIntoShort, needle_len);
}
test "limbs.subInto: a length mismatch is a checked montint panic (sweep MI-1b)" {
    try expectPanicMessage(subIntoShort, needle_len);
}
test "limbs.cmp: a length mismatch is a checked montint panic (sweep MI-1c)" {
    try expectPanicMessage(cmpShort, needle_len);
}
test "limbs.mulSchoolbook: a bad product length is a checked montint panic (sweep MI-1d)" {
    try expectPanicMessage(schoolbookShortZ, needle_product);
}
test "limbs.addWideInto: a longer small operand is a checked montint panic (sweep MI-1e)" {
    try expectPanicMessage(wideSmallLonger, needle_wide);
}
test "limbs.subWideInto: a longer small operand is a checked montint panic (sweep MI-1f)" {
    try expectPanicMessage(wideSubSmallLonger, needle_wide);
}

fn karatsubaDocScratch() void {
    // n = 17: the old doc said 4*(n/2 + 1) = 36 limbs; the code needs 4*(9 + 1) = 40.
    var x: [17]u64 = @splat(3);
    var z: [34]u64 = undefined;
    var scratch: [36]u64 = undefined;
    runtime_len = 36;
    limbs.mulKaratsuba(&z, &x, &x, scratch[0..runtime_len]);
    x[0] = z[0];
}

test "limbs.mulKaratsuba: scratch of 4*(ceil(n/2)+1) works, the old documented 4*(n/2+1) panics (sweep MI-1g)" {
    var prng = std.Random.DefaultPrng.init(0x6177);
    const rnd = prng.random();
    var x: [17]u64 = undefined;
    var y: [17]u64 = undefined;
    for (&x, &y) |*a, *b| {
        a.* = rnd.int(u64);
        b.* = rnd.int(u64);
    }
    var want: [34]u64 = undefined;
    var got: [34]u64 = undefined;
    var scratch: [40]u64 = undefined;
    limbs.mulSchoolbook(&want, &x, &y);
    limbs.mulKaratsuba(&got, &x, &y, &scratch);
    try testing.expectEqualSlices(u64, &want, &got);
    try expectPanicMessage(karatsubaDocScratch, needle_scratch);
}

// ── MI-2: Modint.fromElemUncheckedBits nbits ────────────────────────────────

fn bitsZero() void {
    const M = Modint(128);
    var v = std.mem.zeroes(M.Elem);
    v[0] = 3;
    runtime_len = 0;
    _ = M.fromElemUncheckedBits(v, runtime_len);
}
fn bitsOne() void {
    const M = Modint(128);
    var v = std.mem.zeroes(M.Elem);
    v[0] = 3;
    runtime_len = 1;
    _ = M.fromElemUncheckedBits(v, runtime_len);
}
fn bitsTooWide() void {
    const M = Modint(128);
    var v = std.mem.zeroes(M.Elem);
    v[0] = 3;
    runtime_len = 129;
    _ = M.fromElemUncheckedBits(v, runtime_len);
}

test "Modint.fromElemUncheckedBits: nbits outside 2..64*L is a checked panic; the edges work (sweep MI-2)" {
    const M = Modint(128);
    var v = std.mem.zeroes(M.Elem);
    v[0] = 3; // 2 bits
    const a = M.fromElemUncheckedBits(v, 2);
    const b = try M.fromElem(v);
    try testing.expectEqualSlices(u64, &b.r2, &a.r2);
    try testing.expectEqualSlices(u64, &b.one_mont, &a.one_mont);
    v[1] = 1 << 63; // full 128 bits, odd
    const c = M.fromElemUncheckedBits(v, 128);
    const d = try M.fromElem(v);
    try testing.expectEqualSlices(u64, &d.r2, &c.r2);
    try expectPanicMessage(bitsZero, needle_bits);
    try expectPanicMessage(bitsOne, needle_bits);
    try expectPanicMessage(bitsTooWide, needle_bits);
}

// ── MI-3: safegcd ───────────────────────────────────────────────────────────

test "safegcd: an even modulus answers false, never an internal assert (sweep MI-3)" {
    const I = safegcd.Inverter(256);
    var m: [4]u64 = .{ 6, 0, 0, 1 }; // even
    const x: [4]u64 = .{ 5, 0, 0, 0 };
    var out: [4]u64 = undefined;
    try testing.expect(!I.invert(&x, &m, 256, &out));
    var m2: [4]u64 = .{ 7, 0, 0, 1 }; // odd, for the pair
    var o2: [4]u64 = undefined;
    const v = I.invert2(&x, &m, &x, &m2, 256, &out, &o2);
    try testing.expect(!v[0]);
    // the odd side of the pair is unaffected by the even one
    var w: [4]u64 = undefined;
    try testing.expectEqual(I.invert(&x, &m2, 256, &w), v[1]);
    try testing.expectEqualSlices(u64, &w, &o2);
    m[0] = 0;
    try testing.expect(!I.invert(&x, &m, 256, &out));
}

fn sgTooSmall() void {
    const I = safegcd.Inverter(256);
    const m: [4]u64 = .{ 7, 0, 0, 0 };
    const x: [4]u64 = .{ 5, 0, 0, 0 };
    var out: [4]u64 = undefined;
    runtime_len = 2;
    _ = I.invert(&x, &m, runtime_len, &out);
}
fn sgTooWide() void {
    const I = safegcd.Inverter(256);
    const m: [4]u64 = .{ 7, 0, 0, 0 };
    const x: [4]u64 = .{ 5, 0, 0, 0 };
    var o1: [4]u64 = undefined;
    var o2: [4]u64 = undefined;
    runtime_len = 257;
    _ = I.invert2(&x, &m, &x, &m, runtime_len, &o1, &o2);
}

test "safegcd: nbits outside 3..max_bits is a checked panic (sweep MI-3)" {
    try expectPanicMessage(sgTooSmall, needle_sg);
    try expectPanicMessage(sgTooWide, needle_sg);
}

// ── MI-4: asm_core slice entry points ───────────────────────────────────────

fn asmShortZ() void {
    var z: [4]u64 = undefined;
    const a: [4]u64 = @splat(1);
    const m: [4]u64 = .{ 7, 0, 0, 0 };
    runtime_len = 3;
    asm_core.montMul(z[0..runtime_len], &a, &a, &m, 1);
}
fn asmSqrShortScratch() void {
    var z: [4]u64 = undefined;
    var scratch: [8]u64 = undefined;
    const a: [4]u64 = @splat(1);
    const m: [4]u64 = .{ 7, 0, 0, 0 };
    runtime_len = 7;
    asm_core.montSqr(&z, &a, &m, 1, scratch[0..runtime_len]);
}

test "asm_core.montMul / montSqr: mismatched lengths are a checked panic (sweep MI-4)" {
    if (!asm_core.supported) return error.SkipZigTest;
    try expectPanicMessage(asmShortZ, needle_asm);
    try expectPanicMessage(asmSqrShortScratch, needle_asm);
}

// ── MI-5: Field.pow exponent length ─────────────────────────────────────────

const F127 = Field((1 << 127) - 1);

fn fieldLongExponent() void {
    const e: [17]u8 = @splat(1);
    runtime_len = 17;
    _ = F127.one.pow(e[0..runtime_len]);
}

test "Field.pow: 8*L bytes work, one more is a checked panic (sweep MI-5)" {
    const e: [16]u8 = @splat(0);
    try testing.expect(F127.eql(F127.one.pow(&e), F127.one)); // x^0
    try expectPanicMessage(fieldLongExponent, needle_field);
}

// ── MI-6: DynModint.sqrt work limit ─────────────────────────────────────────

const D = DynModint(512);

/// `c·2^k + 1` (c < 2^16, k ≥ 1).
fn proth(c: u16, k: usize) D.Elem {
    var v = D.zero;
    for (0..16) |i| {
        if ((c >> @intCast(i)) & 1 == 1) {
            const pos = k + i;
            v[pos / 64] |= @as(u64, 1) << @intCast(pos % 64);
        }
    }
    v[0] |= 1;
    return v;
}

test "sqrt: s = v2(p-1) of 256 still works, 257 is error.SqrtWorkLimit with out zeroed (sweep MI-6)" {
    try testing.expectEqual(@as(usize, 256), D.sqrt_max_two_adicity);
    var four = D.zero;
    four[0] = 4;
    var r: D.Elem = undefined;

    const p256 = try D.fromLimbs(&proth(207, 256)); // prime, s = 256
    try testing.expect(try p256.sqrt(&four, &r));
    try testing.expect(D.eql(&p256.sq(&r), &four));

    const p257 = try D.fromLimbs(&proth(51, 257)); // prime, s = 257
    r = D.one();
    try testing.expectError(error.SqrtWorkLimit, p257.sqrt(&four, &r));
    try testing.expect(D.isZero(&r));
}

test "sqrt: a composite with no small non-residue is error.SqrtWorkLimit, not false (sweep MI-6)" {
    try testing.expectEqual(@as(usize, 256), D.sqrt_max_candidates);
    const q: u128 = (1 << 61) - 1; // prime, q = 7 mod 8, so q^2 = 1 mod 8
    const n2 = q * q;
    var v = D.zero;
    v[0] = @truncate(n2);
    v[1] = @truncate(n2 >> 64);
    const m = try D.fromLimbs(&v);
    var four = D.zero;
    four[0] = 4;
    var r: D.Elem = undefined;
    try testing.expectError(error.SqrtWorkLimit, m.sqrt(&four, &r));
    try testing.expect(D.isZero(&r));
}
