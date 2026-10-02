// SPDX-License-Identifier: MIT
//! Fuzz harness for the file readers — the decode surface that overturned
//! SPEC.md's old EMIT-ONLY exemption. `.zkey`, `.wtns`, `.r1cs` and `.ptau`
//! arrive from elsewhere (a ceremony download, a circuit build), so every
//! count, size and index in them is the attacker's.
//!
//! Each input is one of the real snarkjs/circom files in `testdata/snarkjs`,
//! damaged with aim at the structure: the section table (type and size
//! fields), the counts in the headers, plain byte flips, truncation, random
//! bytes. Oracles:
//!
//!   - no crash, no hang, no leak (the driver's DebugAllocator);
//!   - an intact file is accepted;
//!   - `zkey`: write(parse(x)) is a fixed point — parsing it back and writing
//!     again gives the same bytes; a parsed key can be proved against and
//!     handed to `phase2.verify` without tripping a bounds check;
//!   - `wtns`: writeWitness(parse(x)) parses back to the same values.
//!
//! Driver: `GROTH16_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; see
//! its doc for `_ONLY`, `_MS`, `_SEEDFILE`, `_INPUT`).

const std = @import("std");
const testing = std.testing;
const bn254 = @import("bn254");
const fuzz_driver = @import("testkit").fuzz.driver;
const bin = @import("snarkjs_bin.zig");
const zkey = @import("zkey.zig");
const circom = @import("circom.zig");
const ptau_mod = @import("ptau.zig");
const zkprove = @import("zkprove.zig");
const phase2 = @import("phase2.zig");
const field = @import("field.zig");

const Fr = bn254.Fr;

const Kind = enum { zkey0, zkey1, wtns, r1cs, ptau };
const files = [_][]const u8{
    @embedFile("testdata/snarkjs/t0.zkey"),
    @embedFile("testdata/snarkjs/t1.zkey"),
    @embedFile("testdata/snarkjs/t.wtns"),
    @embedFile("testdata/snarkjs/t.r1cs"),
    @embedFile("testdata/snarkjs/pot.ptau"),
};
const max_len = 20 * 1024 + 64;
var scratch: [max_len]u8 = undefined;

/// Offsets of every section-header `{type:u32, size:u64}` in `bytes`
/// (the undamaged file's table).
fn sectionHeaders(bytes: []const u8, out: *[32]usize) usize {
    var n: usize = 0;
    var off: usize = 12;
    while (off + 12 <= bytes.len and n < out.len) {
        out[n] = off;
        n += 1;
        const size = std.mem.readInt(u64, bytes[off + 4 ..][0..8], .little);
        off += 12 + @as(usize, @intCast(size));
    }
    return n;
}

fn damage(comptime S: type, src: *S, base: []const u8) []u8 {
    var len = base.len;
    @memcpy(scratch[0..len], base);
    var heads: [32]usize = undefined;
    const nh = sectionHeaders(base, &heads);
    switch (src.valueRangeAtMost(u8, 0, 6)) {
        0 => fuzz_driver.hit("intact"),
        1 => { // a section header's type or size
            const h = heads[src.index(nh)];
            if (src.value(bool)) {
                std.mem.writeInt(u32, scratch[h..][0..4], src.valueRangeAtMost(u32, 0, 40), .little);
            } else {
                const delta = src.valueRangeAtMost(u8, 0, 3);
                const old = std.mem.readInt(u64, scratch[h + 4 ..][0..8], .little);
                const new: u64 = switch (delta) {
                    0 => old +% 1,
                    1 => old -% 1,
                    2 => src.value(u64),
                    else => old +% 64,
                };
                std.mem.writeInt(u64, scratch[h + 4 ..][0..8], new, .little);
            }
            fuzz_driver.hit("table");
        },
        2 => { // a u32 count inside the first bytes of a section payload
            const h = heads[src.index(nh)];
            const payload = h + 12;
            if (payload + 4 <= len) {
                const at = payload + 4 * src.index(@min(48, (len - payload) / 4));
                const v: u32 = switch (src.valueRangeAtMost(u8, 0, 3)) {
                    0 => std.mem.readInt(u32, scratch[at..][0..4], .little) +% 1,
                    1 => std.mem.readInt(u32, scratch[at..][0..4], .little) -% 1,
                    2 => 0,
                    else => src.value(u32),
                };
                std.mem.writeInt(u32, scratch[at..][0..4], v, .little);
                fuzz_driver.hit("count");
            }
        },
        3 => { // a few byte flips anywhere
            for (0..src.valueRangeAtMost(u8, 1, 8)) |_| scratch[src.index(len)] ^= src.valueRangeAtMost(u8, 1, 255);
        },
        4 => len = src.index(len), // truncated
        5 => { // swap two section headers (order is not fixed in the format)
            const a = heads[src.index(nh)];
            const b = heads[src.index(nh)];
            const ta = std.mem.readInt(u32, scratch[a..][0..4], .little);
            const tb = std.mem.readInt(u32, scratch[b..][0..4], .little);
            std.mem.writeInt(u32, scratch[a..][0..4], tb, .little);
            std.mem.writeInt(u32, scratch[b..][0..4], ta, .little);
        },
        else => { // random bytes behind a kept magic
            len = 12 + src.index(@min(len, 2048));
            src.bytes(scratch[4..len]);
        },
    }
    return scratch[0..len];
}

fn note(e: anyerror) void {
    switch (e) {
        error.Truncated => fuzz_driver.hit("err_truncated"),
        error.BadSectionSize => fuzz_driver.hit("err_size"),
        error.MissingSection => fuzz_driver.hit("err_missing"),
        error.NotOnCurve => fuzz_driver.hit("err_curve"),
        error.NonCanonical => fuzz_driver.hit("err_noncanonical"),
        error.BadIndex => fuzz_driver.hit("err_index"),
        else => fuzz_driver.hit("err_other"),
    }
}

/// The fixed-witness inputs that go with the fixtures.
var witness: ?[]Fr = null;
var r1cs_fixture: ?circom.R1cs = null;

fn fixtures() !void {
    if (witness != null) return;
    const pa = std.heap.page_allocator; // global-alloc-ok: process-lifetime fixtures of a test-only harness
    witness = try circom.parseWitness(pa, files[@intFromEnum(Kind.wtns)]);
    r1cs_fixture = try circom.parseR1cs(pa, files[@intFromEnum(Kind.r1cs)]);
}

fn readersHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    try fixtures();
    const kind: Kind = @enumFromInt(src.index(files.len));
    const base = files[@intFromEnum(kind)];
    const in = damage(S, src, base);
    const intact = std.mem.eql(u8, in, base);

    switch (kind) {
        .zkey0, .zkey1 => {
            var z = zkey.parse(gpa, in) catch |e| {
                note(e);
                if (intact) return error.IntactRefused;
                return;
            };
            defer z.deinit(gpa);
            fuzz_driver.hit("zkey_accepted");
            const once = try zkey.toBytes(gpa, z);
            defer gpa.free(once);
            var back = try zkey.parse(gpa, once);
            defer back.deinit(gpa);
            const twice = try zkey.toBytes(gpa, back);
            defer gpa.free(twice);
            if (!std.mem.eql(u8, once, twice)) return error.WriteNotIdempotent;
            if (intact and !std.mem.eql(u8, once, in)) return error.IntactNotReproduced;
            if (z.n_vars == witness.?.len) {
                _ = zkprove.prove(gpa, z, witness.?, .{ .r = Fr.one, .s = Fr.one }) catch |e| switch (e) {
                    error.OutOfMemory => return e,
                    else => {},
                };
                fuzz_driver.hit("zkey_proved");
            }
            const p = try ptau_mod.Ptau.parse(files[@intFromEnum(Kind.ptau)]);
            const v = try phase2.verify(gpa, std.testing.io, r1cs_fixture.?, p, z);
            if (intact and v != .ok) return error.IntactNotVerified;
            if (v == .ok) fuzz_driver.hit("zkey_verified") else fuzz_driver.hit("zkey_rejected");
        },
        .wtns => {
            const w = circom.parseWitness(gpa, in) catch |e| {
                note(e);
                if (intact) return error.IntactRefused;
                return;
            };
            defer gpa.free(w);
            fuzz_driver.hit("wtns_accepted");
            var aw: std.Io.Writer.Allocating = .init(gpa);
            defer aw.deinit();
            try circom.writeWitness(&aw.writer, w);
            const back = try circom.parseWitness(gpa, aw.written());
            defer gpa.free(back);
            for (w, back) |a, b| if (!a.eql(b)) return error.WitnessRoundTrip;
        },
        .r1cs => {
            var r = circom.parseR1cs(gpa, in) catch |e| {
                note(e);
                if (intact) return error.IntactRefused;
                return;
            };
            defer r.deinit(gpa);
            fuzz_driver.hit("r1cs_accepted");
            // Every index the parser handed out must be usable as one.
            const zw = try gpa.alloc(Fr, r.n_wires);
            defer gpa.free(zw);
            @memset(zw, Fr.one);
            _ = r.system().isSatisfied(zw);
        },
        .ptau => {
            const p = ptau_mod.Ptau.parse(in) catch |e| {
                note(e);
                if (intact) return error.IntactRefused;
                return;
            };
            fuzz_driver.hit("ptau_accepted");
            var level: u5 = 0;
            while (level <= p.power + 1) : (level += 1) {
                for ([_]ptau_mod.Ptau.Basis{ .tau_g1, .alpha_tau_g1, .beta_tau_g1 }) |b| {
                    _ = p.lagrangeG1(b, level, 0) catch |e| note(e);
                }
                _ = p.lagrangeG2(level, 0) catch |e| note(e);
            }
            _ = p.tauG1(0) catch |e| note(e);
            _ = p.tauG2(0) catch |e| note(e);
            _ = p.betaG2() catch |e| note(e);
            // A circuit-specific setup over a damaged ceremony file must
            // refuse or succeed, never trip.
            var z = phase2.newZkey(gpa, r1cs_fixture.?, p) catch |e| {
                note(e);
                return;
            };
            z.deinit(gpa);
            fuzz_driver.hit("ptau_newzkey");
        },
    }
}

test "fuzz driver: file readers on damaged snarkjs/circom files (GROTH16_FUZZ)" {
    try fuzz_driver.run(readersHarness, .{ .prefix = "GROTH16_FUZZ", .name = "readers" });
}

test "fuzz: file readers (coverage-guided exploration)" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *std.testing.Smith) !void {
            try readersHarness(std.testing.Smith, smith, testing.allocator);
        }
    }.one, .{});
}
