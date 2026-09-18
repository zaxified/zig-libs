// SPDX-License-Identifier: MIT

//! ctgrind_harness — measures the two places this module handles the one thing
//! it exists to hide: the client's query index. Run it through
//! `../../../scripts/checks/ctgrind.sh pir`.
//!
//! ## Why this module has a harness at all
//!
//! Audit finding M2 (A1 `pir.md`): *"`pir` and `fss` are not in the `ct` module
//! list for ctgrind — the module's central claim has therefore never been
//! machine-checked."* The `fss` half was closed on 2026-09-09 and it was NOT a
//! formality: the moment `fss` entered the gate it exposed a real defect —
//! `xorMasked` skipped the XOR exactly when the secret bit was zero, and the
//! 7.4% the barrier costs IS the signal that used to be readable. `pir` sits
//! directly on top of that DPF, so it is the sibling that just demonstrated
//! what an unmeasured claim can hide.
//!
//! `SPEC.md` makes the claim in its own words, twice:
//!
//!   "The client's check is a fixed-trip loop of ring multiply/add/xor
//!    accumulating one difference word — no data-dependent branch, no early
//!    exit — with a single final branch on the accept bit, which is the
//!    protocol's own public output"
//!
//!   "this layer adds no new branch on secret data"
//!
//! ## Targets, and what is tainted
//!
//! * `query` — `Pir.query(index, s0, s1)` with the **index** marked undefined.
//!   The index is the secret: two-server PIR exists to keep it from either
//!   server. This walks `fss`'s DPF `Gen` keyed by that index.
//! * `reconstruct` — `Verified.reconstruct(...)` with the client's secret and
//!   both servers' answers tainted. This is the fixed-trip check the SPEC
//!   sentence above is about.
//!
//! ⚠ The PRG is pinned to `fss.prg.Sha256Prg`, NOT the default `Aes128Mmo`.
//! That is not a convenience: `Aes128Mmo` declares
//! `constant_time = aes.has_hardware_support`, so on a machine WITH AES-NI the
//! measurement would be green for a reason that does not hold on a machine
//! without it — and `SPEC.md` §"Constant-time PRG selection" says outright that
//! the soft-AES fallback leaks the query index to a co-resident attacker. A row
//! whose colour depends on the CPU the gate happened to run on is a row that
//! says nothing, so this measures the PRG a caller on a soft-AES target is told
//! to choose. ⛔ Therefore a green `query` row is NOT a claim about the default
//! instantiation on a soft-AES host.
//!
//! ## What the honest expectation is
//!
//! ⚠ **Not zero for `query`, and a reader should not want zero.**
//! `Pir.query` opens with `if (index >= domain_size) return error.IndexOutOfDomain`
//! — a branch on the tainted index against a public bound. It is a contract
//! check whose outcome the caller already knows (it chose the index), so it
//! discloses nothing an attacker can use; it is real, it is pinned, and it is
//! named here rather than hidden by narrowing the taint.
//!
//! Likewise `reconstruct` ends in the accept/reject the SPEC calls "the
//! protocol's own public output". What the claim forbids is a branch that
//! reveals WHICH word mismatched, and that is what the counts have to stay
//! away from.
//!
//! ## The traps
//!
//! 1. Without `-fvalgrind` every row reads 0 regardless; the driver builds both
//!    ways and prints the no-`-fvalgrind` row as a trap beside the claim.
//! 2. `reloadVolatile` forces a real load from freshly-tainted memory, so the
//!    index cannot be consumed as a register copy that predates the taint.
//! 3. ReleaseFast only. `ReleaseSafe` adds overflow checks over secret-derived
//!    data that bury the signal — measured on `hqc`, whose `decaps` goes from
//!    14 contexts to 92 for exactly that reason.
//!
//! ## The propagation witness
//!
//! Each target prints a value derived from the tainted input as
//! `ctgrind_result`, so `Writer.zig` flags it. A non-zero witness beside the
//! in-file count is what separates "the module has no secret-dependent branch"
//! from "the harness never called the module" (`ct25519` C1).

const std = @import("std");
const builtin = @import("builtin");
const fss = @import("fss");
const pir = @import("root.zig");

/// 4-bit domain (16 records), 8-byte words: small enough that a memcheck run
/// is quick, wide enough that the DPF descent has real levels to walk.
const domain_bits = 4;
const word_bytes = 8;
const record_len = 24;
const record_count = 1 << domain_bits;

const P = pir.PirWith(fss.prg.Sha256Prg, domain_bits, word_bytes);
const V = pir.VerifiedWith(fss.prg.Sha256Prg, domain_bits, word_bytes, 1);

fn detSeed(tag: []const u8) P.Seed {
    var out: P.Seed = undefined;
    var st = std.crypto.hash.sha2.Sha256.init(.{});
    st.update("ctgrind-pir-harness-v1");
    st.update(tag);
    var wide: [32]u8 = undefined;
    st.final(&wide);
    @memcpy(&out, wide[0..out.len]);
    return out;
}

fn reloadVolatileUsize(src: *const usize) usize {
    const v: *const volatile usize = src;
    return v.*;
}

fn fillDb(bytes: []u8) void {
    for (bytes, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
}

const Target = enum { query, reconstruct };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "query")) return .query;
    if (std.mem.eql(u8, s, "reconstruct")) return .reconstruct;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const tainted = (try parseTaint(it.next() orelse return error.MissingTaint)) == .yes;

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    var db_bytes: [record_count * record_len]u8 = undefined;
    fillDb(&db_bytes);
    const database = try pir.Database.init(&db_bytes, record_len);

    switch (target) {
        .query => {
            var index: usize = 9;
            if (tainted) std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&index));
            const i = reloadVolatileUsize(&index);

            const shares = try P.query(i, detSeed("v0"), detSeed("v1"));

            // Witness: the share bytes are a deterministic function of the
            // tainted index, so the formatter walks secret-derived data.
            var buf: [P.share_len]u8 = undefined;
            P.shareToBytes(shares[0], &buf);
            std.debug.print("ctgrind_result={x}\n", .{buf});
        },
        .reconstruct => {
            // Build a real, honest transcript first, OUTSIDE the taint: the
            // subject is the client's check, and tainting the setup would fold
            // the query's own contexts into this row's count.
            var index: usize = 6;
            var mac_rand: [V.tag_word_len]u8 = undefined;
            const md = detSeed("mac");
            @memcpy(&mac_rand, md[0..mac_rand.len]);

            const q = try V.query(
                index,
                mac_rand,
                detSeed("v0"),
                detSeed("v1"),
                detSeed("t0"),
                detSeed("t1"),
            );

            const per = P.answerWords(record_len);
            var v0: [64]P.Word = undefined;
            var v1: [64]P.Word = undefined;
            var t0: [65]V.TagWord = undefined;
            var t1: [65]V.TagWord = undefined;
            try V.answer(0, q.shares[0], database, v0[0..per], t0[0 .. per + 1]);
            try V.answer(1, q.shares[1], database, v1[0..per], t1[0 .. per + 1]);

            var secret = q.secret;
            if (tainted) {
                std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&secret));
                std.valgrind.memcheck.makeMemUndefined(std.mem.sliceAsBytes(v0[0..per]));
                std.valgrind.memcheck.makeMemUndefined(std.mem.sliceAsBytes(v1[0..per]));
                std.valgrind.memcheck.makeMemUndefined(std.mem.sliceAsBytes(t0[0 .. per + 1]));
                std.valgrind.memcheck.makeMemUndefined(std.mem.sliceAsBytes(t1[0 .. per + 1]));
            }

            var out: [record_len]u8 = undefined;
            // ⚠ The `catch` is a branch on the accept bit and is DELIBERATELY
            // here: it is the abort the protocol publishes by definition, so a
            // real client writes exactly this. Hiding it would measure a caller
            // nobody writes.
            V.reconstruct(secret, v0[0..per], v1[0..per], t0[0 .. per + 1], t1[0 .. per + 1], &out) catch |err| {
                std.debug.print("rejected: {t}\n", .{err});
                return;
            };
            std.debug.print("ctgrind_result={x}\n", .{out});
            index = 0;
        },
    }
}
