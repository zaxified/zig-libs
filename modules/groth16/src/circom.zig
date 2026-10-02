// SPDX-License-Identifier: MIT
//! circom's two outputs a Groth16 prover consumes: the constraint system
//! (`.r1cs`) and a computed witness (`.wtns`). Layouts established black-box
//! from circom 2.2.3 / snarkjs@0.7.6 output (`tools/snarkjs/gen.sh`); the
//! container and encodings are in `snarkjs_bin.zig`.
//!
//! `.wtns` (version 2): section 1 `n8·r · n_witness:u32`, section 2
//! `n_witness × Fr` (canonical LE). Witness 0 is the constant 1.
//!
//! `.r1cs` (version 1): section 1 `n8·r · n_wires:u32 · n_pub_out:u32 ·
//! n_pub_in:u32 · n_prv_in:u32 · n_labels:u64 · n_constraints:u32`; section 2
//! `n_constraints × (A, B, C)`, each a linear combination `n:u32 × {wire:u32,
//! coeff:Fr}`; section 3 the wire→label map (`n_wires × u64`; its values are
//! not needed for proving, its SIZE bounds `n_wires`). Sections 4/5 hold PLONK custom gates, which a
//! Groth16 system cannot use: a file that has them is refused.
//!
//! Signal order is circom's: `[1, outputs…, public inputs…, private…]`, so
//! the public signals are wires `1..=n_pub_out + n_pub_in`.

const std = @import("std");
const bn254 = @import("bn254");
const bin = @import("snarkjs_bin.zig");
const r1cs = @import("r1cs.zig");

const Fr = bn254.Fr;
const Allocator = std.mem.Allocator;
pub const Error = bin.ParseError || Allocator.Error;

/// Parses a `.wtns` into a freshly allocated witness vector.
pub fn parseWitness(allocator: Allocator, bytes: []const u8) Error![]Fr {
    const f = try bin.BinFile.parse(bytes, "wtns");
    if (f.version != 2) return error.UnsupportedVersion;
    var hc: bin.Cursor = .{ .bytes = try f.get(1) };
    try bin.expectPrime(&hc, &bin.r_le);
    const n = try hc.int(u32);
    const body = try f.get(2);
    if (body.len != try bin.byteLen(n, 32)) return error.BadSectionSize;
    if (n == 0) return error.BadIndex;
    const out = try allocator.alloc(Fr, n);
    errdefer allocator.free(out);
    for (out, 0..) |*v, i| v.* = try bin.frFromLe(body[i * 32 ..][0..32]);
    if (!out[0].eql(Fr.one)) return error.BadIndex; // witness 0 is the constant 1
    return out;
}

/// Writes a witness vector as a `.wtns` (what circom's witness generator
/// writes), so a witness computed here can be handed to snarkjs.
pub fn writeWitness(w: *std.Io.Writer, witness: []const Fr) std.Io.Writer.Error!void {
    try bin.writeHeader(w, "wtns", 2, 2);
    try bin.writeSectionHeader(w, 1, 40);
    try bin.writePrime(w, &bin.r_le);
    try w.writeInt(u32, @intCast(witness.len), .little);
    try bin.writeSectionHeader(w, 2, witness.len * 32);
    for (witness) |v| try w.writeAll(&bin.frToLe(v));
}

/// A circom constraint system. `system` borrows `terms` and `constraints`;
/// everything is owned by this struct.
pub const R1cs = struct {
    n_wires: u32,
    n_pub_out: u32,
    n_pub_in: u32,
    n_prv_in: u32,
    n_labels: u64,
    constraints: []r1cs.Constraint,
    terms: []r1cs.Term,

    /// Public signals besides the constant: outputs, then public inputs.
    pub fn nPublic(self: R1cs) u32 {
        return self.n_pub_out + self.n_pub_in;
    }

    /// The constraint system in this module's own `r1cs.System` form.
    pub fn system(self: R1cs) r1cs.System {
        return .{ .num_vars = self.n_wires, .constraints = self.constraints };
    }

    pub fn deinit(self: *R1cs, allocator: Allocator) void {
        allocator.free(self.constraints);
        allocator.free(self.terms);
        self.* = undefined;
    }
};

/// Parses a circom `.r1cs`. Every wire index is checked against `n_wires`.
pub fn parseR1cs(allocator: Allocator, bytes: []const u8) Error!R1cs {
    const f = try bin.BinFile.parse(bytes, "r1cs");
    if (f.version != 1) return error.UnsupportedVersion;
    if (f.sections[4] != null or f.sections[5] != null) return error.Unsupported; // custom gates

    var hc: bin.Cursor = .{ .bytes = try f.get(1) };
    try bin.expectPrime(&hc, &bin.r_le);
    const n_wires = try hc.int(u32);
    const n_pub_out = try hc.int(u32);
    const n_pub_in = try hc.int(u32);
    const n_prv_in = try hc.int(u32);
    const n_labels = try hc.int(u64);
    const n_constraints = try hc.int(u32);
    if (hc.rest() != 0) return error.BadSectionSize;
    if (n_wires == 0) return error.BadIndex;
    // Section 3 (wire → label, one u64 per wire) is the one place the file
    // pays for its wire count. Requiring it bounds `n_wires` by the file's
    // size: a 400-byte file announcing 2³² wires made a witness allocation
    // of 128 GiB (fuzz, seed 6013) — or, at 10⁸ wires, ten seconds of
    // memset (seed 140696).
    if ((try f.get(3)).len != try bin.byteLen(n_wires, 8)) return error.BadSectionSize;
    // ⚠ That bound is 8 bytes per wire; `phase2.newZkey` then spends ~400
    // bytes per wire (points for A, B₁, B₂, C plus index arrays), so a key
    // costs ~50× the r1cs's section 3 in memory — sized by the file, but
    // a consumer taking circuits from strangers should cap the file size.
    // Promote before adding: three attacker-chosen u32s must not wrap.
    if (@as(u64, n_pub_out) + n_pub_in + n_prv_in + 1 > n_wires) return error.BadIndex;

    const body = try f.get(2);

    // Pass 1: validate the shape and count the terms, so the term array is
    // allocated once and every constraint slice can point into it.
    var total_terms: usize = 0;
    {
        var c: bin.Cursor = .{ .bytes = body };
        for (0..n_constraints) |_| {
            for (0..3) |_| {
                const n = try c.int(u32);
                if (c.rest() / 36 < n) return error.Truncated;
                _ = try c.take(@as(usize, n) * 36);
                total_terms += n;
            }
        }
        if (c.rest() != 0) return error.BadSectionSize;
    }

    const terms = try allocator.alloc(r1cs.Term, total_terms);
    errdefer allocator.free(terms);
    const constraints = try allocator.alloc(r1cs.Constraint, n_constraints);
    errdefer allocator.free(constraints);

    var c: bin.Cursor = .{ .bytes = body };
    var t: usize = 0;
    for (constraints) |*con| {
        var lcs: [3][]const r1cs.Term = undefined;
        for (&lcs) |*lc| {
            const n = try c.int(u32);
            const start = t;
            for (0..n) |_| {
                const wire = try c.int(u32);
                if (wire >= n_wires) return error.BadIndex;
                terms[t] = .{ .index = wire, .coeff = try bin.frFromLe((try c.take(32))[0..32]) };
                t += 1;
            }
            lc.* = terms[start..t];
        }
        con.* = .{ .a = lcs[0], .b = lcs[1], .c = lcs[2] };
    }

    return .{
        .n_wires = n_wires,
        .n_pub_out = n_pub_out,
        .n_pub_in = n_pub_in,
        .n_prv_in = n_prv_in,
        .n_labels = n_labels,
        .constraints = constraints,
        .terms = terms,
    };
}
