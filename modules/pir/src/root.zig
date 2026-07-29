// SPDX-License-Identifier: MIT

//! pir — **two-server Private Information Retrieval**: fetch record `i` from a
//! database replicated on two servers without either server learning `i`.
//!
//! A thin, honest composition over this repo's `fss` Distributed Point
//! Function. The client secret-shares the selector "1 at index `i`, 0
//! everywhere else" into two compact DPF keys; each server evaluates its key
//! against every record and returns one record-sized answer; the client
//! combines the two answers into the record. Communication is
//! `O(λ·log N)` up and `O(record_len)` down, against the `O(N)` of just
//! downloading the database — which is the entire point.
//!
//! ## Read this before using it
//!
//! - **Two colluding servers recover `i` immediately.** The two shares carry
//!   byte-identical correction words; anyone holding both evaluates them over
//!   the domain and reads off the single index where the sum is non-zero.
//!   That is the model, not a flaw. `privacy_test.zig` runs that attack as an
//!   executable test so it cannot be read past. If you cannot justify
//!   non-collusion operationally, this protocol gives you nothing.
//! - **Reconstruction is `+` in `Z_{2^{8L}}`, not XOR.** The textbook
//!   description of DPF-based PIR assumes a bit-valued, XOR-group DPF.
//!   `fss`'s DPF is the additive `Z_{2^{8L}}` construction, so the server's
//!   answer is a ring inner product and the client *adds*. See `pir.zig`'s
//!   module doc for the derivation.
//! - **This library does no I/O.** No sockets, no server loop, no storage
//!   format. Query construction, answer computation, reconstruction, and the
//!   byte codecs between them — nothing else. See `SPEC.md`.
//!
//! ## Entry points
//!
//!   - `Pir(domain_bits, word_bytes)` — the protocol.
//!     `.query(i, s0, s1)` → two shares · `.answer(party, share, db, out)` ·
//!     `.reconstruct(a0, a1, record_out)`, plus the wire codecs
//!     `shareToBytes`/`shareFromBytes`/`answerToBytes`/`answerFromBytes`/
//!     `reconstructFromBytes`. The server side runs on `fss`'s tree-reuse
//!     `evalFull` — ~1 PRG call per record, never touching the domain's
//!     unused tail.
//!   - `Pir(...).queryKeyword(kw, s0, s1)` — **lookup by keyword**: exactly
//!     `query(keywordIndex(kw), …)`, where `keywordIndex` is a public, total,
//!     deterministic SHA-256→index map. A miss is the same call as a hit —
//!     PROVIDED the caller never skips a query and never retries; collisions
//!     are a provisioned false-negative cost, not a leak. Read the README
//!     callout / `SPEC.md` §"Keyword lookup" before using it.
//!   - `Pir(...).Multi(k)` — **`k` records per round trip**, over `fss`'s
//!     multi-point FSS. Same shape, plus `answerAggregate` for the query a
//!     single multi-point inner product actually computes (`Σ_j record[α_j]`,
//!     one record of download — an aggregate, *not* `k`-record retrieval).
//!     ⚠ `k` is public: the share length and the answer width both reveal it.
//!   - `Verified(domain_bits, word_bytes, tag_slack_bytes)` — **detection of
//!     a lying server**: the same protocol plus a MACed tag channel; the
//!     client aborts (`error.AnswerRejected`) instead of silently
//!     reconstructing a doctored record. Detection only — no recovery, no
//!     attribution, colluding servers still win. Also `Pir(b,L).Verified(S)`.
//!   - `Database` — a borrowed, fixed-record-length view over bytes you
//!     already have.
//!   - `domainBitsFor(count)` — pick `domain_bits` for a record count.
//!
//! ## Scoped out
//!
//! Multi-*record*-sized retrieval — a whole block rather than a bit — needed
//! nothing extra and is the default case: see `pir.zig`. Answer verification
//! against a malicious server is now `Verified` (`verify.zig`) — detection
//! and abort, never recovery. Keyword lookup is now `queryKeyword` (above).
//! Still out: robustness and attribution (inherent at two servers), binding
//! answers to a *published* database digest (authenticated PIR — a different
//! trust model, see `SPEC.md`), a verified `Multi(k)`, **sublinear** batch
//! PIR (`Multi(k)` amortizes the database pass but still costs `k` DPF
//! evaluations per record; the cuckoo/batch-code multi-point construction
//! that would fix that is scoped out in `fss`), and the `evalFull` wiring of
//! `Multi(k)`'s inner loop (see `SPEC.md` §"Scoped out").

const std = @import("std");

pub const meta = .{
    .platform = .any, // pure computation — no threads / OS / libc / entropy source
    .role = .codec, // query/answer/reconstruct + byte codecs; no I/O of any kind
    .concurrency = .reentrant, // no shared state; every input is caller-supplied
    .model_after = "Gilboa-Ishai / Boyle-Gilboa-Ishai DPF-based 2-server PIR (the standard composition; see SPEC.md for why no external test vector exists)",
    .deps = .{"fss"},
};

const db_mod = @import("db.zig");
const pir_mod = @import("pir.zig");
const verify_mod = @import("verify.zig");

/// `Pir(domain_bits, word_bytes)` — the two-server PIR protocol over a
/// `2^domain_bits` index domain. See `pir.zig`.
pub const Pir = pir_mod.Pir;

/// `Verified(domain_bits, word_bytes, tag_slack_bytes)` — the same protocol
/// with **detection of a lying server**: a MACed tag channel that makes the
/// client abort (`error.AnswerRejected`) instead of silently reconstructing a
/// doctored record. Also reachable as `Pir(b, L).Verified(S)`. Detection
/// only — no recovery, no attribution, and colluding servers still defeat it
/// (as they already defeat privacy). See `verify.zig`.
pub const Verified = verify_mod.Verified;

/// A borrowed, fixed-record-length view over a database. See `db.zig`.
pub const Database = db_mod.Database;

/// Smallest DPF domain (in bits) addressing `count` records. See `db.zig`.
pub const domainBitsFor = db_mod.domainBitsFor;

/// Words per record for a given record and word length. See `db.zig`.
pub const wordsPerRecord = db_mod.wordsPerRecord;

/// Every error this module returns — all of them size/geometry disagreements.
pub const Error = db_mod.Error;

// Pull every submodule's tests into the test binary (CONVENTIONS.md §6
// dark-tests rule: a bare re-export does NOT pull a file's tests in).
test {
    std.testing.refAllDecls(@This());
    _ = db_mod;
    _ = pir_mod;
    _ = verify_mod;
    _ = @import("privacy_test.zig");
}

test "SELF: the README's end-to-end example compiles and retrieves" {
    // Keep this in sync with README.md's usage block — it IS that block.
    const fss = @import("fss");

    const records = [_][]const u8{
        "record-zero  ", "record-one   ", "record-two   ",
        "record-three ", "record-four  ",
    };
    var flat: [5 * 13]u8 = undefined;
    for (records, 0..) |r, i| @memcpy(flat[i * 13 ..][0..13], r);

    const database = try Database.init(&flat, 13);
    const bits = try domainBitsFor(database.count()); // 3
    try std.testing.expectEqual(@as(usize, 3), bits);

    const P = Pir(3, 16);
    const want_index = 3;

    // Client: two fresh seeds (production: a CSPRNG, one pair per query).
    const s0: fss.prg.Seed = [_]u8{0x11} ** 16;
    const s1: fss.prg.Seed = [_]u8{0x22} ** 16;
    const shares = try P.query(want_index, s0, s1);

    // Servers (each holds one share and the same database).
    const n_words = P.answerWords(database.record_len);
    var a0: [1]P.Word = undefined;
    var a1: [1]P.Word = undefined;
    try P.answer(0, shares[0], database, a0[0..n_words]);
    try P.answer(1, shares[1], database, a1[0..n_words]);

    // Client.
    var got: [13]u8 = undefined;
    try P.reconstruct(a0[0..n_words], a1[0..n_words], &got);
    try std.testing.expectEqualSlices(u8, records[want_index], &got);
}

test "meta.deps names fss, the primitive this composes" {
    try std.testing.expectEqualStrings("fss", meta.deps[0]);
}
