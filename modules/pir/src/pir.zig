// SPDX-License-Identifier: MIT

//! pir — two-server Private Information Retrieval as a composition over the
//! `fss` Distributed Point Function.
//!
//! ## The protocol, in the shape this module actually implements it
//!
//! A client wants record `i` of an `N`-record database that **both** servers
//! hold identically, without either server learning `i`.
//!
//! 1. **Client:** `query(i, s0, s1)` runs the DPF's `Gen` for the point
//!    function `f_{i,1}` — value **1** at `i`, `0` everywhere else — producing
//!    two shares. Share 0 goes to server 0, share 1 to server 1, and
//!    **never both to the same server**.
//! 2. **Server `b`:** `answer(b, share, db, out)` evaluates its share at every
//!    index `x < N` and accumulates `share_b(x) · record[x]` into a
//!    record-sized answer.
//! 3. **Client:** `reconstruct(a0, a1, out)` combines the two answers into
//!    record `i`.
//!
//! ## Why the combination is `+` and not `xor`
//!
//! The textbook description of DPF-based PIR says "each server XORs the
//! records its share selects, and the client XORs the two answers". That
//! describes a DPF whose output group is `GF(2)^m` and whose shares are
//! **bits**. `fss`'s DPF is **not** that one: its output group is
//! `Z_{2^{8L}}` (`fss/SPEC.md` §"Output group choice"), so `Eval` returns a
//! full pseudorandom `L`-byte group element, not a selection bit. There is no
//! "the records this share selects" — off-target shares are random values that
//! cancel *in pairs across the two servers*, not zeros.
//!
//! So the composition here is the **inner product in the ring `Z_{2^{8L}}`**:
//! a record is cut into `L`-byte little-endian words, and
//!
//! ```
//! answer_b[j] = Σ_{x<N} Eval(b, k_b, x) ·  word_j(record[x])       (mod 2^{8L})
//! answer_0[j] + answer_1[j]
//!             = Σ_x (Eval(0,k0,x) + Eval(1,k1,x)) · word_j(record[x])
//!             = Σ_x f_{i,1}(x) · word_j(record[x])
//!             = word_j(record[i])
//! ```
//!
//! using nothing but distributivity of multiplication over addition in
//! `Z_{2^{8L}}`. Carries between packed record bytes are harmless because the
//! identity is exact ring arithmetic, not per-byte arithmetic — which is why
//! packing `L` record bytes into one word is a free `L`-fold reduction in
//! multiplications rather than a correctness hazard.
//!
//! **The block ("multi-bit") case is therefore the only case.** Retrieving a
//! whole `record_len`-byte block costs one DPF evaluation per database record
//! regardless of `record_len`; the classic single-*bit* PIR is just
//! `record_len == 1`. Nothing extra had to be built for it.
//!
//! ## ⚠ Two colluding servers learn `i` immediately
//!
//! This is the security model, not a defect, and it is not subtle: `k0` and
//! `k1` share **byte-identical correction words** and differ only in the root
//! seed (`fss/dpf.zig`). Anyone holding both shares evaluates them at every
//! index, adds, and reads off the single index where the sum is non-zero —
//! that index is `i`. Two-server PIR buys index privacy **only** from the
//! assumption that the two servers do not pool their shares. If you cannot
//! justify that assumption operationally (different operators, different
//! jurisdictions, different infrastructure), this protocol gives you nothing.

const std = @import("std");
const fss = @import("fss");
const db_mod = @import("db.zig");

const Database = db_mod.Database;
const Error = db_mod.Error;

/// Two-server PIR over a `2^domain_bits`-index domain, with the database's
/// records cut into `word_bytes`-byte words.
///
/// - `domain_bits ∈ 1..31` — pick it with `db.domainBitsFor(record_count)`.
///   A domain larger than the database is fine; smaller is `DomainTooSmall`.
/// - `word_bytes ∈ 1..32` — the arithmetic width. Larger is faster (fewer
///   multiplications per record) and does **not** change the answer's size in
///   bytes beyond rounding a record up to a whole number of words. `16` is a
///   good default; `1` gives exactly byte-granular answers.
///
/// Both are compile-time because `fss.Dpf` is: the key layout, the domain
/// index type and the group width are all fixed at compile time.
pub fn Pir(comptime domain_bits: usize, comptime word_bytes: usize) type {
    return struct {
        /// this single-index protocol, so the nested `Multi` layer can reach
        /// its geometry helpers without restating them
        const Single = @This();

        /// the underlying DPF instantiation — exposed so a caller can reach
        /// `fss`'s own verification oracles (`firstMismatch`, `evalAll`)
        /// without re-deriving the parameters
        pub const Dpf = fss.Dpf(domain_bits, word_bytes);

        /// a single ring element: one `word_bytes`-byte chunk of a record
        pub const Word = Dpf.Elem;
        /// the 16-byte root seed `query` needs two of
        pub const Seed = fss.prg.Seed;
        /// one server's query share (a DPF key)
        pub const Share = Dpf.Key;

        /// serialized length of one query share — a compile-time constant,
        /// identical for every index (see `SPEC.md` §"Privacy")
        pub const share_len = Dpf.Key.serialized_len;
        /// number of addressable indices, `2^domain_bits`
        pub const domain_size: usize = Dpf.domain_size;
        /// bytes per ring word
        pub const word_len: usize = word_bytes;

        // ── client: query construction ────────────────────────────────────

        /// Build the two query shares for `index`.
        ///
        /// `s0` and `s1` MUST be freshly drawn, mutually independent,
        /// cryptographically random 16-byte seeds, and MUST NOT be reused for
        /// another query: they are the protocol's only randomness, and the
        /// DPF is deterministic given them. `fss` deliberately keeps them
        /// caller-supplied so neither module needs an entropy source.
        ///
        /// `index` is checked against the *domain*, which is all this
        /// function knows about. It is the caller's job to also keep
        /// `index < db.count()`; querying a valid-but-unpopulated index is not
        /// an error and yields an all-zero reconstruction.
        ///
        /// Returns `.{ share_for_server_0, share_for_server_1 }`.
        pub fn query(index: usize, s0: Seed, s1: Seed) Error![2]Share {
            if (index >= domain_size) return error.IndexOutOfDomain;
            // β = 1: the point function is a pure selector. Any other β would
            // scale the retrieved record by β in the ring, which is not what
            // retrieval means.
            return Dpf.genWithSeeds(@intCast(index), 1, s0, s1);
        }

        /// Serialize a share for the wire. Fixed length, no header, no length
        /// field — see `SPEC.md` §"The codec has no length fields".
        pub fn shareToBytes(share: Share, buf: *[share_len]u8) void {
            share.toBytes(buf);
        }

        /// Parse a share received from a client. **This is the untrusted
        /// boundary**: a server calls it on bytes an arbitrary peer sent.
        /// The only accepted length is exactly `share_len`; every field of the
        /// result is a fixed-width read at a compile-time-known offset, so no
        /// count or length is ever taken from the input.
        ///
        /// A well-formed-length input that is not a real DPF key parses fine
        /// and produces a garbage-but-harmless answer. That is intended:
        /// nothing in two-server PIR lets a server *validate* a share (see
        /// `SPEC.md` §"What this does not do").
        pub fn shareFromBytes(buf: []const u8) Error!Share {
            if (buf.len != share_len) return error.ShareLengthMismatch;
            return Dpf.Key.fromBytes(buf[0..share_len]);
        }

        // ── server: answer computation ────────────────────────────────────

        /// Number of `Word`s in an answer over records of `record_len` bytes.
        pub fn answerWords(record_len: usize) usize {
            return db_mod.wordsPerRecord(record_len, word_bytes);
        }

        /// Number of bytes in a serialized answer over `record_len`-byte
        /// records. Note this is `record_len` rounded **up** to a whole word,
        /// so it depends only on the database's geometry — never on which
        /// index was queried.
        pub fn answerBytesLen(record_len: usize) usize {
            return answerWords(record_len) * word_bytes;
        }

        /// Server `party`'s answer to `share`, over `database`, into `out`
        /// (`out.len` must be `answerWords(database.record_len)`).
        ///
        /// Touches **every** record — the loop bound is `database.count()` and
        /// there is no early exit, no data-dependent skip and no branch on the
        /// evaluated share. An index-dependent access pattern here would leak
        /// exactly what the DPF is there to hide, so this is load-bearing, and
        /// there is a test asserting every record influences the result.
        pub fn answer(party: u1, share: Share, database: Database, out: []Word) Error!void {
            if (out.len != answerWords(database.record_len)) return error.AnswerLengthMismatch;
            const n = database.count();
            if (n > domain_size) return error.DomainTooSmall;

            @memset(out, 0);
            var x: usize = 0;
            while (x < n) : (x += 1) {
                const sel = Dpf.eval(party, share, @intCast(x));
                const rec = database.record(x);
                for (out, 0..) |*w, j| w.* +%= sel *% wordAt(rec, j);
            }
        }

        /// `answer` over a slice of records rather than one flat buffer, for
        /// callers whose database is not contiguous. Every record must have
        /// the same length (`RaggedRecords` otherwise) — see `db.zig` for why
        /// that is a hard requirement and not a convenience.
        pub fn answerSlices(party: u1, share: Share, records: []const []const u8, out: []Word) Error!void {
            if (records.len == 0) return error.EmptyDatabase;
            if (records.len > domain_size) return error.DomainTooSmall;
            const record_len = records[0].len;
            if (record_len == 0) return error.ZeroRecordLen;
            for (records) |r| if (r.len != record_len) return error.RaggedRecords;
            if (out.len != answerWords(record_len)) return error.AnswerLengthMismatch;

            @memset(out, 0);
            for (records, 0..) |rec, x| {
                const sel = Dpf.eval(party, share, @intCast(x));
                for (out, 0..) |*w, j| w.* +%= sel *% wordAt(rec, j);
            }
        }

        /// Serialize an answer, little-endian per word.
        pub fn answerToBytes(words: []const Word, buf: []u8) Error!void {
            const need = std.math.mul(usize, words.len, word_bytes) catch
                return error.AnswerLengthMismatch;
            if (buf.len != need) return error.AnswerLengthMismatch;
            for (words, 0..) |w, j| {
                std.mem.writeInt(Word, buf[j * word_bytes ..][0..word_bytes], w, .little);
            }
        }

        /// Parse an answer received from a server. **Untrusted boundary**:
        /// the required length is computed from the caller's own `out` slice
        /// and the input must match it exactly — the input never gets to say
        /// how long it is.
        pub fn answerFromBytes(buf: []const u8, out: []Word) Error!void {
            const need = std.math.mul(usize, out.len, word_bytes) catch
                return error.AnswerLengthMismatch;
            if (buf.len != need) return error.AnswerLengthMismatch;
            for (out, 0..) |*w, j| {
                w.* = std.mem.readInt(Word, buf[j * word_bytes ..][0..word_bytes], .little);
            }
        }

        // ── client: reconstruction ────────────────────────────────────────

        /// Combine the two servers' answers into the retrieved record.
        /// `record_out.len` is the database's record length; the answers must
        /// each be `answerWords(record_out.len)` long.
        pub fn reconstruct(a0: []const Word, a1: []const Word, record_out: []u8) Error!void {
            const n_words = answerWords(record_out.len);
            if (a0.len != n_words or a1.len != n_words) return error.AnswerLengthMismatch;
            var j: usize = 0;
            while (j < n_words) : (j += 1) {
                writeWord(record_out, j, a0[j] +% a1[j]);
            }
        }

        /// `reconstruct` straight from the two servers' serialized answers,
        /// without materializing the word arrays. **Untrusted boundary** for
        /// both inputs: the required length comes from `record_out`, and both
        /// buffers must match it exactly.
        pub fn reconstructFromBytes(a0: []const u8, a1: []const u8, record_out: []u8) Error!void {
            const n_words = answerWords(record_out.len);
            const need = std.math.mul(usize, n_words, word_bytes) catch
                return error.AnswerLengthMismatch;
            if (a0.len != need or a1.len != need) return error.AnswerLengthMismatch;
            var j: usize = 0;
            while (j < n_words) : (j += 1) {
                const w0 = std.mem.readInt(Word, a0[j * word_bytes ..][0..word_bytes], .little);
                const w1 = std.mem.readInt(Word, a1[j * word_bytes ..][0..word_bytes], .little);
                writeWord(record_out, j, w0 +% w1);
            }
        }

        // ── multi-index retrieval ─────────────────────────────────────────

        /// `k`-record retrieval in one round trip, over `fss`'s multi-point
        /// FSS (`fss.Mpf`). `k` is compile-time, like every other parameter
        /// here, which is what keeps the share encoding free of a count field.
        ///
        /// ## The correction: `k` records need `k` answer blocks
        ///
        /// The tempting shape is "one multi-point key, one inner product, one
        /// answer". It does not retrieve `k` records. Composing a `k`-point
        /// function with this module's inner product gives
        ///
        /// ```
        /// Σ_x f_{A,1}(x) · word_j(record[x])  =  Σ_l word_j(record[α_l])
        /// ```
        ///
        /// — the **sum** of the `k` records, from which the individual records
        /// are unrecoverable. That is a genuinely useful query (it is what
        /// `answerAggregate` computes, and its download is one record for `k`
        /// records' worth of selection), but it is an aggregate, not retrieval.
        ///
        /// Retrieval keeps the `k` instances apart: the server evaluates the
        /// components with `Mpf.evalEach` and accumulates `k` separate inner
        /// products, so an answer is `k` record-sized blocks laid end to end
        /// and reconstruction yields all `k` records. There is no way around
        /// the download cost — `k` records of information cannot arrive in one
        /// record of bytes — so "one answer per server" here means one
        /// *message*, `k` blocks wide.
        ///
        /// ## What carried over from the single-index case, and what did not
        ///
        /// - **The output group is still `Z_{2^{8L}}`, not XOR**, and the
        ///   components are still full pseudorandom group elements rather than
        ///   selection bits. Unchanged: each block is the same ring inner
        ///   product as before.
        /// - **β must still be 1**, now `k` times: `query` hard-codes `1` for
        ///   every point. A `β_j ≠ 1` scales block `j` by `β_j`.
        /// - **Record-length independence still comes free**, and for the same
        ///   reason: the DPF work is `k` evaluations per *record*, whatever the
        ///   record length. What is no longer free is the factor `k` itself —
        ///   see `fss/mpf.zig` on why this construction pays it.
        /// - **Repeated indices are fine here**, unlike in the aggregate. The
        ///   instances never meet, so `indices = .{7, 7}` returns record 7 in
        ///   both blocks. In the summed function those same points would add
        ///   to `2·record[7]`; the two semantics diverge exactly at repetition,
        ///   which is why retrieval uses the components and not the sum.
        /// - **One pass over the database, not `k`.** The loop is over records
        ///   on the outside and instances on the inside, so each record's bytes
        ///   are read and decomposed once. That is a memory-traffic win only —
        ///   the DPF evaluations are still `k·N`.
        ///
        /// `k = 0` is a degenerate no-op (a zero-byte share, an empty answer),
        /// accepted so the boundary is defined rather than undefined.
        pub fn Multi(comptime k: usize) type {
            return struct {
                /// this multi-index layer. Its `Share`/`Word`/`answerWords`
                /// etc. deliberately shadow the single-index ones, so every
                /// self-reference below is qualified through here — Zig
                /// rejects the ambiguous unqualified form, which is exactly the
                /// mix-up (a single-index answer buffer handed to the
                /// multi-index path) worth being unable to write by accident.
                const Mul = @This();

                /// the multi-point FSS instantiation behind this layer
                pub const Mpf = fss.Mpf(domain_bits, word_bytes, k);
                /// one server's multi-index query share (a multi-point key)
                pub const Share = Mpf.Key;
                pub const Word = Single.Word;
                pub const Seed = Single.Seed;
                /// number of records retrieved per query
                pub const points = k;
                /// serialized length of one share — a compile-time constant,
                /// identical for every index tuple. It is `k` times the
                /// single-index length, so it **does reveal `k`**; see
                /// `SPEC.md` §"Does `k` leak?".
                pub const share_len = Mpf.Key.serialized_len;
                pub const domain_size: usize = Single.domain_size;

                /// Build the two shares for `indices`, retrieving `k` records.
                ///
                /// **All `2k` seeds must be freshly drawn, mutually
                /// independent CSPRNG output** — across the `k` instances as
                /// well as within each pair. This is stricter than the
                /// single-index case in consequence, not just in wording:
                /// reusing one seed pair for two instances makes the two
                /// indices' shared prefix readable from the correction words.
                /// `fss.Mpf` rejects byte-identical seeds (`error.SeedReuse`)
                /// as a guard against that plumbing bug; it cannot check
                /// independence, which stays the caller's obligation.
                ///
                /// Duplicate *indices* are allowed and return the same record
                /// in each corresponding block. A client wanting fewer than
                /// `k` records pads with dummy indices — every share hides its
                /// own index, so any padding value works, and this is how a
                /// deployment hides how many records a client actually wanted.
                pub fn query(indices: [k]usize, s0: [k]Mul.Seed, s1: [k]Mul.Seed) Error![2]Mul.Share {
                    var alphas: [k]Mpf.Index = undefined;
                    for (indices, &alphas) |i, *a| {
                        if (i >= Mul.domain_size) return error.IndexOutOfDomain;
                        a.* = @intCast(i);
                    }
                    // β = 1 for every point, for the single-index reason: any
                    // other value scales that block's record in the ring.
                    const betas: [k]Mul.Word = @splat(1);
                    return Mpf.genWithSeeds(alphas, betas, s0, s1);
                }

                /// Serialize a share. Fixed length, no header, no count.
                pub fn shareToBytes(share: Mul.Share, buf: *[Mul.share_len]u8) void {
                    share.toBytes(buf);
                }

                /// Parse a share received from a client. **Untrusted
                /// boundary.** The only accepted length is exactly
                /// `share_len`; every sub-key is a fixed-width read at a
                /// compile-time-known offset, so — as in the single-index case
                /// — no count or length is ever taken from the input. In
                /// particular `k` is *not* read from the bytes: it is this
                /// server's own compile-time parameter.
                pub fn shareFromBytes(buf: []const u8) Error!Mul.Share {
                    if (buf.len != Mul.share_len) return error.ShareLengthMismatch;
                    return Mpf.Key.fromBytes(buf[0..Mul.share_len]);
                }

                /// `Word`s per retrieval answer: `k` blocks of
                /// `Single.answerWords(record_len)`.
                pub fn answerWords(record_len: usize) Error!usize {
                    return std.math.mul(usize, k, Single.answerWords(record_len)) catch
                        error.AnswerLengthMismatch;
                }

                /// Bytes in a serialized retrieval answer. Depends only on the
                /// database geometry and `k` — never on which indices were
                /// queried.
                pub fn answerBytesLen(record_len: usize) Error!usize {
                    return std.math.mul(usize, try Mul.answerWords(record_len), word_bytes) catch
                        error.AnswerLengthMismatch;
                }

                /// Server `party`'s retrieval answer: `k` blocks, block `j`
                /// being the inner product of instance `j`'s share vector with
                /// the database. `out.len` must be `answerWords(record_len)`.
                ///
                /// Touches every record exactly once, with no early exit and
                /// no branch on any evaluated share — the same access-pattern
                /// requirement as the single-index `answer`, and it matters
                /// more here because there are `k` indices to leak.
                pub fn answer(party: u1, share: Mul.Share, database: Database, out: []Mul.Word) Error!void {
                    const per = Single.answerWords(database.record_len);
                    if (out.len != try Mul.answerWords(database.record_len)) {
                        return error.AnswerLengthMismatch;
                    }
                    const n = database.count();
                    if (n > Mul.domain_size) return error.DomainTooSmall;

                    @memset(out, 0);
                    var sel: [k]Mul.Word = undefined;
                    var x: usize = 0;
                    while (x < n) : (x += 1) {
                        Mpf.evalEach(party, share, @intCast(x), &sel);
                        const rec = database.record(x);
                        // Records outside, instances inside: each record's
                        // bytes are decomposed once and reused across all k.
                        for (0..per) |w| {
                            const word = Single.wordAt(rec, w);
                            for (sel, 0..) |s, j| out[j * per + w] +%= s *% word;
                        }
                    }
                }

                /// Combine the two servers' retrieval answers into the `k`
                /// records, laid end to end in `records_out` (block `j` at
                /// `j * record_len`).
                pub fn reconstruct(
                    a0: []const Mul.Word,
                    a1: []const Mul.Word,
                    record_len: usize,
                    records_out: []u8,
                ) Error!void {
                    const per = Single.answerWords(record_len);
                    const need = try Mul.answerWords(record_len);
                    if (a0.len != need or a1.len != need) return error.AnswerLengthMismatch;
                    const want_out = std.math.mul(usize, k, record_len) catch
                        return error.RecordsLengthMismatch;
                    if (records_out.len != want_out) return error.RecordsLengthMismatch;
                    for (0..k) |j| {
                        try Single.reconstruct(
                            a0[j * per ..][0..per],
                            a1[j * per ..][0..per],
                            records_out[j * record_len ..][0..record_len],
                        );
                    }
                }

                /// `reconstruct` straight from the two servers' serialized
                /// answers. **Untrusted boundary** for both inputs: the
                /// required length comes from `record_len` and this server's
                /// own `k`, never from the buffers.
                pub fn reconstructFromBytes(
                    a0: []const u8,
                    a1: []const u8,
                    record_len: usize,
                    records_out: []u8,
                ) Error!void {
                    const need = try Mul.answerBytesLen(record_len);
                    if (a0.len != need or a1.len != need) return error.AnswerLengthMismatch;
                    const want_out = std.math.mul(usize, k, record_len) catch
                        return error.RecordsLengthMismatch;
                    if (records_out.len != want_out) return error.RecordsLengthMismatch;
                    const per_bytes = Single.answerBytesLen(record_len);
                    for (0..k) |j| {
                        try Single.reconstructFromBytes(
                            a0[j * per_bytes ..][0..per_bytes],
                            a1[j * per_bytes ..][0..per_bytes],
                            records_out[j * record_len ..][0..record_len],
                        );
                    }
                }

                // ── the aggregate query (the multi-point function itself) ──

                /// `Word`s in an aggregate answer: **one** record-sized block,
                /// whatever `k` is.
                pub fn aggregateWords(record_len: usize) usize {
                    return Single.answerWords(record_len);
                }

                /// Server `party`'s answer to the *multi-point function
                /// itself*: `Σ_j record[α_j]`, one record-sized block.
                ///
                /// This is what a single inner product against a `k`-point
                /// share computes, and it is included to make the distinction
                /// above concrete rather than only documented: the download is
                /// `k`-independent, and the individual records are gone. Use
                /// it when the sum is what you wanted (a private aggregate over
                /// `k` chosen rows); never as a way to fetch `k` records.
                ///
                /// Repeated indices count with multiplicity here — `.{7, 7}`
                /// aggregates to `2·record[7]`.
                pub fn answerAggregate(party: u1, share: Mul.Share, database: Database, out: []Mul.Word) Error!void {
                    if (out.len != Mul.aggregateWords(database.record_len)) {
                        return error.AnswerLengthMismatch;
                    }
                    const n = database.count();
                    if (n > Mul.domain_size) return error.DomainTooSmall;

                    @memset(out, 0);
                    var x: usize = 0;
                    while (x < n) : (x += 1) {
                        const sel = Mpf.eval(party, share, @intCast(x));
                        const rec = database.record(x);
                        for (out, 0..) |*w, j| w.* +%= sel *% Single.wordAt(rec, j);
                    }
                }

                /// Combine two aggregate answers into the summed record.
                pub fn reconstructAggregate(a0: []const Mul.Word, a1: []const Mul.Word, out: []u8) Error!void {
                    return Single.reconstruct(a0, a1, out);
                }
            };
        }

        // ── malicious-server detection ────────────────────────────────────

        /// Detection of a lying server: this value protocol unchanged, plus a
        /// MACed tag channel in a ring widened by `tag_slack_bytes` (soundness
        /// error `2^(1−8·tag_slack_bytes)`; `8` is the recommended default).
        /// Detection only — abort, no recovery, no attribution; see
        /// `verify.zig`'s module doc for the exact security statement.
        pub fn Verified(comptime tag_slack_bytes: usize) type {
            return @import("verify.zig").Verified(domain_bits, word_bytes, tag_slack_bytes);
        }

        // ── record ↔ word decomposition ───────────────────────────────────

        /// Word `j` of `record`, little-endian, zero-padded past the end.
        /// Reading past the record is defined rather than an error so the
        /// final partial word needs no special case in the hot loop.
        /// `pub` because the `Verified` layer's tag channel must decompose
        /// records into EXACTLY these words (zero-extended) — a re-derived
        /// decomposition that drifted from this one would break the honest
        /// `t_j == m·w_j` relation.
        pub fn wordAt(record: []const u8, j: usize) Word {
            var buf: [word_bytes]u8 = @splat(0);
            const start = j * word_bytes;
            if (start < record.len) {
                const n = @min(word_bytes, record.len - start);
                @memcpy(buf[0..n], record[start..][0..n]);
            }
            return std.mem.readInt(Word, &buf, .little);
        }

        /// Write word `j` back into `out`, dropping the zero padding of the
        /// final partial word.
        fn writeWord(out: []u8, j: usize, w: Word) void {
            var buf: [word_bytes]u8 = undefined;
            std.mem.writeInt(Word, &buf, w, .little);
            const start = j * word_bytes;
            const n = @min(word_bytes, out.len - start);
            @memcpy(out[start..][0..n], buf[0..n]);
        }
    };
}

// ── tests ─────────────────────────────────────────────────────────────────
//
// Anchoring (CONVENTIONS.md §7). Three labels are used, and they mean
// different things:
//
//   EXTERNAL — a vector produced by something other than this repo.
//              **There are none in this file, and none are obtainable**;
//              see SPEC.md §"External anchoring" for the argument.
//   DERIVED  — an in-house re-derivation: the result is computed a second,
//              structurally different way (from the *definition* of PIR, with
//              no DPF involved) and the two must agree.
//   SELF     — a round-trip or property of this module against itself.

const testing = std.testing;

/// Deterministic, reproducible seed pair for tests. NOT a production pattern —
/// `query` requires fresh CSPRNG seeds; this exists so a failure is a
/// permanent failure rather than a flake.
fn detSeeds(tag: u64) [2]fss.prg.Seed {
    var h: [32]u8 = undefined;
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, tag, .little);
    std.crypto.hash.sha2.Sha256.hash(&buf, &h, .{});
    return .{ h[0..16].*, h[16..32].* };
}

/// A deterministic database: record `x` is filled from a hash of `x`, so no
/// two records are equal and a wrong-index answer cannot accidentally match.
fn fillDb(bytes: []u8, record_len: usize) void {
    var x: usize = 0;
    while (x * record_len < bytes.len) : (x += 1) {
        const rec = bytes[x * record_len ..][0..record_len];
        var h: [32]u8 = undefined;
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, x, .little);
        std.crypto.hash.sha2.Sha256.hash(&buf, &h, .{});
        for (rec, 0..) |*b, k| b.* = h[k % h.len] ^ @as(u8, @truncate(k));
    }
}

test "SELF: retrieval returns the right record for EVERY index, across awkward sizes" {
    // Sizes chosen to straddle the DPF's internal tree boundaries: exact
    // powers of two, one below, one above, and the degenerate 1-record case.
    const cases = .{
        .{ .bits = 1, .count = 1 }, // smallest possible domain AND database
        .{ .bits = 1, .count = 2 }, // domain exactly full
        .{ .bits = 2, .count = 3 }, // one below a power of two
        .{ .bits = 3, .count = 5 }, // domain half-empty
        .{ .bits = 3, .count = 7 },
        .{ .bits = 3, .count = 8 },
        .{ .bits = 4, .count = 9 }, // one above a power of two
        .{ .bits = 5, .count = 17 },
        .{ .bits = 5, .count = 32 },
        .{ .bits = 6, .count = 33 },
    };
    // Record lengths straddling the word boundary too.
    const record_lens = [_]usize{ 1, 3, 4, 5, 7, 16, 33 };

    inline for (cases) |c| {
        const P = Pir(c.bits, 4);
        for (record_lens) |record_len| {
            var storage: [64 * 33]u8 = undefined;
            const bytes = storage[0 .. c.count * record_len];
            fillDb(bytes, record_len);
            const database = try Database.init(bytes, record_len);

            var a0: [9]P.Word = undefined; // 33 bytes / 4 = 9 words, the max here
            var a1: [9]P.Word = undefined;
            const n_words = P.answerWords(record_len);
            var got: [33]u8 = undefined;

            for (0..c.count) |i| {
                const seeds = detSeeds(@as(u64, c.bits) * 1_000_003 +
                    @as(u64, @intCast(i)) * 31 + @as(u64, @intCast(record_len)));
                const shares = try P.query(i, seeds[0], seeds[1]);
                try P.answer(0, shares[0], database, a0[0..n_words]);
                try P.answer(1, shares[1], database, a1[0..n_words]);
                try P.reconstruct(a0[0..n_words], a1[0..n_words], got[0..record_len]);
                try testing.expectEqualSlices(u8, database.record(i), got[0..record_len]);
            }
        }
    }
}

test "DERIVED: the answer equals the PIR definition computed without any DPF" {
    // Re-derivation, not a round-trip: compute Σ_x f_{i,1}(x)·word_j(rec[x])
    // straight from the plaintext point function, then check the DPF-shared
    // computation lands on the same words. This is the defining equation of
    // §"Why the combination is +", evaluated by a different route.
    const P = Pir(5, 4);
    const record_len = 10;
    const count = 20;
    var bytes: [count * record_len]u8 = undefined;
    fillDb(&bytes, record_len);
    const database = try Database.init(&bytes, record_len);
    const n_words = P.answerWords(record_len);

    for (0..count) |i| {
        // Route A — the plaintext definition, no secret sharing at all.
        var want: [3]P.Word = @splat(0);
        for (0..count) |x| {
            const f: P.Word = if (x == i) 1 else 0;
            const rec = database.record(x);
            for (want[0..n_words], 0..) |*w, j| {
                var chunk: [4]u8 = @splat(0);
                const start = j * 4;
                const n = @min(@as(usize, 4), rec.len - @min(start, rec.len));
                if (start < rec.len) @memcpy(chunk[0..n], rec[start..][0..n]);
                w.* +%= f *% std.mem.readInt(u32, &chunk, .little);
            }
        }

        // Route B — through the DPF.
        const seeds = detSeeds(4242 + i);
        const shares = try P.query(i, seeds[0], seeds[1]);
        var a0: [3]P.Word = undefined;
        var a1: [3]P.Word = undefined;
        try P.answer(0, shares[0], database, a0[0..n_words]);
        try P.answer(1, shares[1], database, a1[0..n_words]);

        for (0..n_words) |j| {
            try testing.expectEqual(want[j], a0[j] +% a1[j]);
        }
    }
}

test "SELF: word_bytes 1 and 16 retrieve the same record as word_bytes 4" {
    const record_len = 20;
    const count = 12;
    var bytes: [count * record_len]u8 = undefined;
    fillDb(&bytes, record_len);
    const database = try Database.init(&bytes, record_len);
    const seeds = detSeeds(7);

    inline for (.{ 1, 4, 16 }) |L| {
        const P = Pir(4, L);
        const n_words = P.answerWords(record_len);
        var a0: [record_len]P.Word = undefined;
        var a1: [record_len]P.Word = undefined;
        var got: [record_len]u8 = undefined;
        for (0..count) |i| {
            const shares = try P.query(i, seeds[0], seeds[1]);
            try P.answer(0, shares[0], database, a0[0..n_words]);
            try P.answer(1, shares[1], database, a1[0..n_words]);
            try P.reconstruct(a0[0..n_words], a1[0..n_words], &got);
            try testing.expectEqualSlices(u8, database.record(i), &got);
        }
    }
}

test "SELF: answerSlices agrees with answer over the flat database" {
    const P = Pir(4, 8);
    const record_len = 12;
    var bytes: [10 * record_len]u8 = undefined;
    fillDb(&bytes, record_len);
    const database = try Database.init(&bytes, record_len);
    var recs: [10][]const u8 = undefined;
    for (&recs, 0..) |*r, x| r.* = database.record(x);

    const n_words = P.answerWords(record_len);
    const seeds = detSeeds(99);
    const shares = try P.query(6, seeds[0], seeds[1]);
    var flat: [2]P.Word = undefined;
    var sliced: [2]P.Word = undefined;
    try P.answer(0, shares[0], database, flat[0..n_words]);
    try P.answerSlices(0, shares[0], &recs, sliced[0..n_words]);
    try testing.expectEqualSlices(P.Word, flat[0..n_words], sliced[0..n_words]);
}

test "SELF: wire round-trip — share and answer survive serialization" {
    const P = Pir(6, 16);
    const record_len = 40;
    const count = 50;
    var bytes: [count * record_len]u8 = undefined;
    fillDb(&bytes, record_len);
    const database = try Database.init(&bytes, record_len);
    const n_words = P.answerWords(record_len);
    const n_bytes = P.answerBytesLen(record_len);
    const seeds = detSeeds(1234);
    const i = 37;

    const shares = try P.query(i, seeds[0], seeds[1]);

    // client → servers
    var wire0: [P.share_len]u8 = undefined;
    var wire1: [P.share_len]u8 = undefined;
    P.shareToBytes(shares[0], &wire0);
    P.shareToBytes(shares[1], &wire1);

    // servers parse and answer
    var words: [3]P.Word = undefined;
    var ans0: [48]u8 = undefined;
    var ans1: [48]u8 = undefined;
    try P.answer(0, try P.shareFromBytes(&wire0), database, words[0..n_words]);
    try P.answerToBytes(words[0..n_words], ans0[0..n_bytes]);
    try P.answer(1, try P.shareFromBytes(&wire1), database, words[0..n_words]);
    try P.answerToBytes(words[0..n_words], ans1[0..n_bytes]);

    // servers → client
    var got: [record_len]u8 = undefined;
    try P.reconstructFromBytes(ans0[0..n_bytes], ans1[0..n_bytes], &got);
    try testing.expectEqualSlices(u8, database.record(i), &got);

    // the two-step path must agree with the streaming one
    var w0: [3]P.Word = undefined;
    var w1: [3]P.Word = undefined;
    try P.answerFromBytes(ans0[0..n_bytes], w0[0..n_words]);
    try P.answerFromBytes(ans1[0..n_bytes], w1[0..n_words]);
    var got2: [record_len]u8 = undefined;
    try P.reconstruct(w0[0..n_words], w1[0..n_words], &got2);
    try testing.expectEqualSlices(u8, &got, &got2);
}

test "SELF: every database record influences the answer (no index-dependent access pattern)" {
    // Teeth for the claim in `answer`'s doc comment. If the server skipped any
    // record — an early exit, a zero-share shortcut — perturbing that record
    // would leave the answer unchanged. Deterministic: fixed seeds, fixed db.
    const P = Pir(5, 4);
    const record_len = 8;
    const count = 20;
    var bytes: [count * record_len]u8 = undefined;
    fillDb(&bytes, record_len);
    const seeds = detSeeds(555);
    const shares = try P.query(3, seeds[0], seeds[1]);
    const n_words = P.answerWords(record_len);

    var base: [2]P.Word = undefined;
    try P.answer(0, shares[0], try Database.init(&bytes, record_len), base[0..n_words]);

    for (0..count) |x| {
        bytes[x * record_len] ^= 0x01;
        var perturbed: [2]P.Word = undefined;
        try P.answer(0, shares[0], try Database.init(&bytes, record_len), perturbed[0..n_words]);
        bytes[x * record_len] ^= 0x01;
        try testing.expect(!std.mem.eql(P.Word, base[0..n_words], perturbed[0..n_words]));
    }
}

test "SELF: an index inside the domain but past the database reconstructs to zero" {
    // Not an error — documented behaviour. The DPF's spike lands on an index
    // the server never evaluates, so every term cancels.
    const P = Pir(4, 4);
    const record_len = 8;
    var bytes: [5 * record_len]u8 = undefined;
    fillDb(&bytes, record_len);
    const database = try Database.init(&bytes, record_len);
    const seeds = detSeeds(31337);
    const shares = try P.query(11, seeds[0], seeds[1]); // 5 <= 11 < 16
    var a0: [2]P.Word = undefined;
    var a1: [2]P.Word = undefined;
    try P.answer(0, shares[0], database, &a0);
    try P.answer(1, shares[1], database, &a1);
    var got: [record_len]u8 = undefined;
    try P.reconstruct(&a0, &a1, &got);
    try testing.expectEqualSlices(u8, &[_]u8{0} ** record_len, &got);
}

test "SELF: geometry errors are returned, never asserted" {
    const P = Pir(3, 4);
    const seeds = detSeeds(1);
    try testing.expectError(error.IndexOutOfDomain, P.query(8, seeds[0], seeds[1]));
    const shares = try P.query(0, seeds[0], seeds[1]);

    var bytes: [4 * 6]u8 = undefined;
    fillDb(&bytes, 6);
    const database = try Database.init(&bytes, 6);
    var out: [2]P.Word = undefined;
    try testing.expectError(error.AnswerLengthMismatch, P.answer(0, shares[0], database, out[0..1]));

    // a database bigger than the domain
    var big: [9 * 6]u8 = undefined;
    fillDb(&big, 6);
    try testing.expectError(
        error.DomainTooSmall,
        P.answer(0, shares[0], try Database.init(&big, 6), &out),
    );

    try testing.expectError(error.ShareLengthMismatch, P.shareFromBytes(&[_]u8{0} ** 3));
    try testing.expectError(error.ShareLengthMismatch, P.shareFromBytes(&[_]u8{0} ** (P.share_len + 1)));

    var buf: [7]u8 = undefined;
    try testing.expectError(error.AnswerLengthMismatch, P.answerFromBytes(&buf, &out));
    try testing.expectError(error.AnswerLengthMismatch, P.answerToBytes(&out, &buf));
    var rec: [6]u8 = undefined;
    try testing.expectError(error.AnswerLengthMismatch, P.reconstruct(out[0..1], &out, &rec));
    try testing.expectError(error.AnswerLengthMismatch, P.reconstructFromBytes(&buf, &buf, &rec));

    const empty: [0][]const u8 = .{};
    try testing.expectError(error.EmptyDatabase, P.answerSlices(0, shares[0], &empty, &out));
    const ragged = [_][]const u8{ &[_]u8{ 1, 2, 3 }, &[_]u8{ 1, 2 } };
    try testing.expectError(error.RaggedRecords, P.answerSlices(0, shares[0], &ragged, out[0..1]));
    const zero_len = [_][]const u8{ &[_]u8{}, &[_]u8{} };
    try testing.expectError(error.ZeroRecordLen, P.answerSlices(0, shares[0], &zero_len, out[0..0]));
}

test "SELF: exhaustive length sweep over every untrusted boundary" {
    // `std.testing.fuzz`'s default corpus is small, and `zig build --fuzz`
    // does not build on Zig 0.16.0's shipped test runner (see SPEC.md
    // §"Fuzzing"), so the length boundaries get an EXHAUSTIVE deterministic
    // sweep as well. Every combination of buffer lengths in a small range:
    // exactly the right length must be accepted, and every other length must
    // be REJECTED rather than half-served. Deliberately checking both
    // directions — a parser that rejects everything would pass a
    // never-panics test while being useless.
    const P = Pir(4, 4);
    var b0: [24]u8 = undefined;
    var b1: [24]u8 = undefined;
    for (&b0, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
    for (&b1, 0..) |*b, i| b.* = @truncate(i * 11 + 3);
    var rec: [24]u8 = undefined;
    var words: [8]P.Word = undefined;

    for (0..b0.len + 1) |l0| for (0..b1.len + 1) |l1| for (0..rec.len + 1) |rl| {
        const need = P.answerBytesLen(rl);
        const r = P.reconstructFromBytes(b0[0..l0], b1[0..l1], rec[0..rl]);
        if (l0 == need and l1 == need) {
            try r;
        } else {
            try testing.expectError(error.AnswerLengthMismatch, r);
        }
    };

    for (0..b0.len + 1) |l0| for (0..words.len + 1) |ow| {
        const r = P.answerFromBytes(b0[0..l0], words[0..ow]);
        if (l0 == ow * 4) try r else try testing.expectError(error.AnswerLengthMismatch, r);
    };

    var big: [2 * P.share_len]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = @truncate(i);
    for (0..big.len + 1) |n| {
        const r = P.shareFromBytes(big[0..n]);
        if (n == P.share_len) {
            _ = try r;
        } else {
            try testing.expectError(error.ShareLengthMismatch, r);
        }
    }
}

// ── multi-index retrieval ─────────────────────────────────────────────────

/// `k` deterministic, mutually distinct seed pairs. NOT a production pattern;
/// `Multi.query` needs `2k` independent CSPRNG seeds.
fn detSeedsK(comptime k: usize, tag: u64) [2][k]fss.prg.Seed {
    var s0: [k]fss.prg.Seed = undefined;
    var s1: [k]fss.prg.Seed = undefined;
    for (0..k) |j| {
        const pair = detSeeds(tag *% 1_000_003 +% @as(u64, j));
        s0[j] = pair[0];
        s1[j] = pair[1];
    }
    return .{ s0, s1 };
}

test "SELF: multi-index retrieval returns all k records, across awkward geometries" {
    // The geometries the single-index sweep uses, crossed with k: k=1 (the
    // single-point path), k equal to the database size (retrieve everything),
    // and k in between. Databases that are not powers of two are the norm
    // here, not a special case.
    const cases = .{
        .{ .bits = 1, .count = 1, .k = 1 }, // smallest of everything
        .{ .bits = 1, .count = 2, .k = 2 }, // k == count == domain
        .{ .bits = 2, .count = 3, .k = 3 }, // k == count, non-power-of-two db
        .{ .bits = 3, .count = 5, .k = 2 },
        .{ .bits = 3, .count = 7, .k = 7 }, // k == count, one below a power
        .{ .bits = 3, .count = 8, .k = 3 },
        .{ .bits = 4, .count = 9, .k = 4 }, // one above a power of two
        .{ .bits = 5, .count = 17, .k = 1 },
        .{ .bits = 5, .count = 20, .k = 5 },
    };
    const record_lens = [_]usize{ 1, 3, 4, 7, 16 };

    inline for (cases) |c| {
        const M = Pir(c.bits, 4).Multi(c.k);
        for (record_lens) |record_len| {
            var storage: [32 * 16]u8 = undefined;
            const bytes = storage[0 .. c.count * record_len];
            fillDb(bytes, record_len);
            const database = try Database.init(bytes, record_len);
            const n_words = try M.answerWords(record_len);

            var a0: [c.k * 4]M.Word = undefined; // 16 bytes / 4 = 4 words max
            var a1: [c.k * 4]M.Word = undefined;
            var got: [c.k * 16]u8 = undefined;

            // Rotate the tuple so every index appears in every slot.
            for (0..c.count) |t| {
                var indices: [c.k]usize = undefined;
                for (&indices, 0..) |*idx, j| idx.* = (t + j * 3) % c.count;
                const seeds = detSeedsK(c.k, @as(u64, c.bits) * 7919 +
                    @as(u64, @intCast(t)) * 31 + @as(u64, @intCast(record_len)));
                const shares = try M.query(indices, seeds[0], seeds[1]);
                try M.answer(0, shares[0], database, a0[0..n_words]);
                try M.answer(1, shares[1], database, a1[0..n_words]);
                try M.reconstruct(
                    a0[0..n_words],
                    a1[0..n_words],
                    record_len,
                    got[0 .. c.k * record_len],
                );
                for (indices, 0..) |idx, j| {
                    try testing.expectEqualSlices(
                        u8,
                        database.record(idx),
                        got[j * record_len ..][0..record_len],
                    );
                }
            }
        }
    }
}

test "SELF: repeated indices retrieve the same record in each block" {
    // The multi-point *function* would add the two points together; retrieval
    // keeps the instances apart, so repetition is not a special case at all.
    // Asserted because it is the one place the two semantics visibly diverge.
    const M = Pir(4, 4).Multi(3);
    const record_len = 9;
    const count = 10;
    var bytes: [count * record_len]u8 = undefined;
    fillDb(&bytes, record_len);
    const database = try Database.init(&bytes, record_len);
    const n_words = try M.answerWords(record_len);

    for ([_][3]usize{ .{ 7, 7, 7 }, .{ 2, 9, 2 }, .{ 0, 0, 5 } }) |indices| {
        const seeds = detSeedsK(3, indices[0] * 101 + indices[1]);
        const shares = try M.query(indices, seeds[0], seeds[1]);
        var a0: [9]M.Word = undefined;
        var a1: [9]M.Word = undefined;
        try M.answer(0, shares[0], database, a0[0..n_words]);
        try M.answer(1, shares[1], database, a1[0..n_words]);
        var got: [3 * record_len]u8 = undefined;
        try M.reconstruct(a0[0..n_words], a1[0..n_words], record_len, &got);
        for (indices, 0..) |idx, j| {
            try testing.expectEqualSlices(
                u8,
                database.record(idx),
                got[j * record_len ..][0..record_len],
            );
        }
    }
}

test "SELF: k=0 is a defined no-op — zero-byte share, empty answer" {
    const M = Pir(4, 4).Multi(0);
    try testing.expectEqual(@as(usize, 0), M.share_len);
    var bytes: [5 * 8]u8 = undefined;
    fillDb(&bytes, 8);
    const database = try Database.init(&bytes, 8);

    const shares = try M.query(.{}, .{}, .{});
    try testing.expectEqual(@as(usize, 0), try M.answerWords(8));
    var out: [0]M.Word = undefined;
    try M.answer(0, shares[0], database, &out);
    var got: [0]u8 = undefined;
    try M.reconstruct(&out, &out, 8, &got);

    // The zero-length share still round-trips the wire boundary, and a
    // non-empty buffer is still rejected.
    var wire: [0]u8 = undefined;
    M.shareToBytes(shares[0], &wire);
    _ = try M.shareFromBytes(&wire);
    try testing.expectError(error.ShareLengthMismatch, M.shareFromBytes(&[_]u8{0}));
}

test "DERIVED: k=1 multi-index is byte-identical to the single-index path" {
    // Not "equivalent" — identical. Same seeds, same share bytes, same answer
    // words, same retrieved record.
    const P = Pir(5, 4);
    const M = P.Multi(1);
    const record_len = 13;
    const count = 25;
    var bytes: [count * record_len]u8 = undefined;
    fillDb(&bytes, record_len);
    const database = try Database.init(&bytes, record_len);
    const n_words = P.answerWords(record_len);
    try testing.expectEqual(n_words, try M.answerWords(record_len));
    try testing.expectEqual(P.share_len, M.share_len);

    for (0..count) |i| {
        const seeds = detSeeds(@as(u64, @intCast(i)) + 31337);
        const single = try P.query(i, seeds[0], seeds[1]);
        const multi = try M.query(.{i}, .{seeds[0]}, .{seeds[1]});

        var w_single: [P.share_len]u8 = undefined;
        var w_multi: [M.share_len]u8 = undefined;
        P.shareToBytes(single[0], &w_single);
        M.shareToBytes(multi[0], &w_multi);
        try testing.expectEqualSlices(u8, &w_single, &w_multi);

        var as0: [4]P.Word = undefined;
        var am0: [4]M.Word = undefined;
        try P.answer(0, single[0], database, as0[0..n_words]);
        try M.answer(0, multi[0], database, am0[0..n_words]);
        try testing.expectEqualSlices(P.Word, as0[0..n_words], am0[0..n_words]);
    }
}

test "DERIVED: block j equals an independent single-index query on instance j's seeds" {
    // The construction's defining claim, checked rather than assumed: a
    // k-index answer is k independent single-index answers side by side. If
    // the instances shared anything — state, seeds, an accumulator — this
    // would drift.
    const P = Pir(5, 8);
    const k = 4;
    const M = P.Multi(k);
    const record_len = 12;
    const count = 30;
    var bytes: [count * record_len]u8 = undefined;
    fillDb(&bytes, record_len);
    const database = try Database.init(&bytes, record_len);
    const per = P.answerWords(record_len);

    const indices = [k]usize{ 29, 0, 13, 13 };
    const seeds = detSeedsK(k, 4242);
    const shares = try M.query(indices, seeds[0], seeds[1]);

    var multi_answer: [k * 2]M.Word = undefined;
    try M.answer(0, shares[0], database, multi_answer[0 .. k * per]);

    for (indices, 0..) |idx, j| {
        const single = try P.query(idx, seeds[0][j], seeds[1][j]);
        var block: [2]P.Word = undefined;
        try P.answer(0, single[0], database, block[0..per]);
        try testing.expectEqualSlices(
            P.Word,
            block[0..per],
            multi_answer[j * per ..][0..per],
        );
    }
}

test "DERIVED: the aggregate answer is Σ record[α_j], computed without any DPF" {
    // The multi-point function itself, through the PIR inner product. Route A
    // sums the selected records in the ring directly; route B goes through the
    // shared k-point key. Also the evidence for the docs' claim that one
    // aggregate answer CANNOT be k-record retrieval.
    const P = Pir(5, 4);
    const k = 3;
    const M = P.Multi(k);
    const record_len = 10;
    const count = 20;
    var bytes: [count * record_len]u8 = undefined;
    fillDb(&bytes, record_len);
    const database = try Database.init(&bytes, record_len);
    const n_words = M.aggregateWords(record_len);

    const indices = [k]usize{ 3, 11, 19 };
    const seeds = detSeedsK(k, 909090);
    const shares = try M.query(indices, seeds[0], seeds[1]);

    var a0: [3]M.Word = undefined;
    var a1: [3]M.Word = undefined;
    try M.answerAggregate(0, shares[0], database, a0[0..n_words]);
    try M.answerAggregate(1, shares[1], database, a1[0..n_words]);

    // Route A: add the three records word-wise, no secret sharing involved.
    var want: [3]M.Word = @splat(0);
    for (indices) |idx| {
        const rec = database.record(idx);
        for (want[0..n_words], 0..) |*w, j| {
            var chunk: [4]u8 = @splat(0);
            const start = j * 4;
            if (start < rec.len) {
                const n = @min(@as(usize, 4), rec.len - start);
                @memcpy(chunk[0..n], rec[start..][0..n]);
            }
            w.* +%= std.mem.readInt(u32, &chunk, .little);
        }
    }
    for (0..n_words) |j| try testing.expectEqual(want[j], a0[j] +% a1[j]);

    // And the point of the distinction: a DIFFERENT index set with the same
    // sum yields the SAME aggregate answer, so the aggregate cannot be
    // inverted to the individual records.
    var sum_a: [3]M.Word = undefined;
    var sum_b: [3]M.Word = undefined;
    for (0..n_words) |j| sum_a[j] = a0[j] +% a1[j];
    const swapped = [k]usize{ 19, 3, 11 }; // same multiset, different order
    const seeds2 = detSeedsK(k, 121212);
    const shares2 = try M.query(swapped, seeds2[0], seeds2[1]);
    try M.answerAggregate(0, shares2[0], database, a0[0..n_words]);
    try M.answerAggregate(1, shares2[1], database, a1[0..n_words]);
    for (0..n_words) |j| sum_b[j] = a0[j] +% a1[j];
    try testing.expectEqualSlices(M.Word, sum_a[0..n_words], sum_b[0..n_words]);

    // The aggregate download is k-independent — one record-sized block.
    try testing.expectEqual(P.answerWords(record_len), M.aggregateWords(record_len));
}

test "SELF: multi-index wire round-trip through both untrusted boundaries" {
    const P = Pir(6, 16);
    const k = 3;
    const M = P.Multi(k);
    const record_len = 40;
    const count = 50;
    var bytes: [count * record_len]u8 = undefined;
    fillDb(&bytes, record_len);
    const database = try Database.init(&bytes, record_len);
    const n_words = try M.answerWords(record_len);
    const n_bytes = try M.answerBytesLen(record_len);
    const indices = [k]usize{ 49, 7, 0 };
    const seeds = detSeedsK(k, 5150);

    const shares = try M.query(indices, seeds[0], seeds[1]);

    var wire0: [M.share_len]u8 = undefined;
    var wire1: [M.share_len]u8 = undefined;
    M.shareToBytes(shares[0], &wire0);
    M.shareToBytes(shares[1], &wire1);

    var words: [k * 3]M.Word = undefined;
    var ans0: [k * 48]u8 = undefined;
    var ans1: [k * 48]u8 = undefined;
    try M.answer(0, try M.shareFromBytes(&wire0), database, words[0..n_words]);
    try P.answerToBytes(words[0..n_words], ans0[0..n_bytes]);
    try M.answer(1, try M.shareFromBytes(&wire1), database, words[0..n_words]);
    try P.answerToBytes(words[0..n_words], ans1[0..n_bytes]);

    var got: [k * record_len]u8 = undefined;
    try M.reconstructFromBytes(ans0[0..n_bytes], ans1[0..n_bytes], record_len, &got);
    for (indices, 0..) |idx, j| {
        try testing.expectEqualSlices(
            u8,
            database.record(idx),
            got[j * record_len ..][0..record_len],
        );
    }

    // the two-step path must agree with the streaming one
    var w0: [k * 3]M.Word = undefined;
    var w1: [k * 3]M.Word = undefined;
    try P.answerFromBytes(ans0[0..n_bytes], w0[0..n_words]);
    try P.answerFromBytes(ans1[0..n_bytes], w1[0..n_words]);
    var got2: [k * record_len]u8 = undefined;
    try M.reconstruct(w0[0..n_words], w1[0..n_words], record_len, &got2);
    try testing.expectEqualSlices(u8, &got, &got2);
}

test "SELF: every record influences every block of a multi-index answer" {
    // The access-pattern claim, per block. A server that skipped a record for
    // one instance — or reused one instance's evaluation for another — would
    // leave some block unchanged when that record is perturbed.
    const M = Pir(5, 4).Multi(3);
    const record_len = 8;
    const count = 20;
    var bytes: [count * record_len]u8 = undefined;
    fillDb(&bytes, record_len);
    const seeds = detSeedsK(3, 8888);
    const shares = try M.query(.{ 3, 14, 0 }, seeds[0], seeds[1]);
    const per = 2;
    const n_words = try M.answerWords(record_len);

    var base: [3 * per]M.Word = undefined;
    try M.answer(0, shares[0], try Database.init(&bytes, record_len), base[0..n_words]);

    for (0..count) |x| {
        bytes[x * record_len] ^= 0x01;
        var perturbed: [3 * per]M.Word = undefined;
        try M.answer(0, shares[0], try Database.init(&bytes, record_len), perturbed[0..n_words]);
        bytes[x * record_len] ^= 0x01;
        for (0..3) |j| {
            try testing.expect(!std.mem.eql(
                M.Word,
                base[j * per ..][0..per],
                perturbed[j * per ..][0..per],
            ));
        }
    }
}

test "SELF: multi-index geometry errors are returned, never asserted" {
    const M = Pir(3, 4).Multi(2);
    const seeds = detSeedsK(2, 1);

    // an index outside the domain, in either slot
    try testing.expectError(error.IndexOutOfDomain, M.query(.{ 8, 0 }, seeds[0], seeds[1]));
    try testing.expectError(error.IndexOutOfDomain, M.query(.{ 0, 8 }, seeds[0], seeds[1]));

    // seed reuse across the two instances — the leak guard, surfaced here
    var dup0 = seeds[0];
    dup0[1] = dup0[0];
    var dup1 = seeds[1];
    dup1[1] = dup1[0];
    try testing.expectError(error.SeedReuse, M.query(.{ 0, 1 }, dup0, dup1));

    const shares = try M.query(.{ 0, 1 }, seeds[0], seeds[1]);

    var bytes: [4 * 6]u8 = undefined;
    fillDb(&bytes, 6);
    const database = try Database.init(&bytes, 6);
    var out: [4]M.Word = undefined;
    try testing.expectError(error.AnswerLengthMismatch, M.answer(0, shares[0], database, out[0..3]));

    var big: [9 * 6]u8 = undefined;
    fillDb(&big, 6);
    try testing.expectError(
        error.DomainTooSmall,
        M.answer(0, shares[0], try Database.init(&big, 6), &out),
    );

    try testing.expectError(error.ShareLengthMismatch, M.shareFromBytes(&[_]u8{0} ** 3));
    try testing.expectError(
        error.ShareLengthMismatch,
        M.shareFromBytes(&[_]u8{0} ** (M.share_len + 1)),
    );
    // exactly one share's worth is NOT enough for a two-instance share
    try testing.expectError(
        error.ShareLengthMismatch,
        M.shareFromBytes(&[_]u8{0} ** (M.share_len / 2)),
    );

    var rec: [2 * 6]u8 = undefined;
    try testing.expectError(error.AnswerLengthMismatch, M.reconstruct(out[0..3], &out, 6, &rec));
    try testing.expectError(error.RecordsLengthMismatch, M.reconstruct(&out, &out, 6, rec[0..6]));
    var buf: [7]u8 = undefined;
    try testing.expectError(error.AnswerLengthMismatch, M.reconstructFromBytes(&buf, &buf, 6, &rec));
}

test "SELF: exhaustive length sweep over the multi-index untrusted boundaries" {
    // The same discipline as the single-index sweep: exactly the right length
    // must be accepted and EVERY other length rejected — both directions, so a
    // parser that rejects everything cannot pass. This is what caught the
    // count-from-input bug shape in the single-index codec.
    const k = 2;
    const M = Pir(4, 4).Multi(k);
    var b0: [32]u8 = undefined;
    var b1: [32]u8 = undefined;
    for (&b0, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
    for (&b1, 0..) |*b, i| b.* = @truncate(i * 11 + 3);
    var rec: [24]u8 = undefined;

    for (0..b0.len + 1) |l0| for (0..b1.len + 1) |l1| for (0..13) |record_len| {
        // records_out must be k*record_len; feed the right one and a wrong one.
        const need = try M.answerBytesLen(record_len);
        const r = M.reconstructFromBytes(b0[0..l0], b1[0..l1], record_len, rec[0 .. k * record_len]);
        if (l0 == need and l1 == need) try r else try testing.expectError(error.AnswerLengthMismatch, r);
        // With the answers the right length, a records_out that is one block
        // short must still be rejected — on its own error, never half-filled.
        // (The answer lengths are checked first, so this is only meaningful
        // once they are correct; asserting it unconditionally would only be
        // re-testing the answer-length check under a different name.)
        if (record_len > 0 and l0 == need and l1 == need) {
            try testing.expectError(
                error.RecordsLengthMismatch,
                M.reconstructFromBytes(b0[0..l0], b1[0..l1], record_len, rec[0..record_len]),
            );
        }
    };

    var big: [3 * M.share_len]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = @truncate(i);
    for (0..big.len + 1) |n| {
        const r = M.shareFromBytes(big[0..n]);
        if (n == M.share_len) _ = try r else try testing.expectError(error.ShareLengthMismatch, r);
    }
}

// ── fuzz: the untrusted boundaries ────────────────────────────────────────
//
// A server parses a client's share; a client parses two servers' answers.
// Both are "bytes from a peer" and are held to CONVENTIONS.md §7.1's
// never-panic-on-arbitrary-input bar.

const FuzzPir = Pir(8, 4);

fn fuzzShareFromBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [FuzzPir.share_len + 8]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = FuzzPir.shareFromBytes(buf[0..len]) catch return;
}
test "fuzz shareFromBytes never panics" {
    try std.testing.fuzz({}, fuzzShareFromBytes, .{});
}

fn fuzzAnswerHostileShare(_: void, smith: *std.testing.Smith) !void {
    // The full server-side path on a hostile share: parse, then compute an
    // answer with it. A share that parses is NOT a share that is valid — the
    // answer computation must survive arbitrary key material.
    var key_buf: [FuzzPir.share_len]u8 = undefined;
    smith.bytes(&key_buf);
    const share = FuzzPir.shareFromBytes(&key_buf) catch return;

    var db_bytes: [128]u8 = undefined;
    smith.bytes(&db_bytes);
    const record_len: usize = smith.valueRangeAtMost(u8, 1, 16);
    const record_count: usize = smith.valueRangeAtMost(u8, 1, 8);
    const used = record_len * record_count;
    const database = Database.init(db_bytes[0..used], record_len) catch return;

    var out: [16]FuzzPir.Word = undefined;
    const n_words = FuzzPir.answerWords(record_len);
    const party: u1 = @truncate(smith.valueRangeAtMost(u8, 0, 1));
    try FuzzPir.answer(party, share, database, out[0..n_words]);

    var wire: [64]u8 = undefined;
    try FuzzPir.answerToBytes(out[0..n_words], wire[0 .. n_words * 4]);
}
test "fuzz answer over a hostile share never panics" {
    try std.testing.fuzz({}, fuzzAnswerHostileShare, .{});
}

fn fuzzReconstruct(_: void, smith: *std.testing.Smith) !void {
    // The client's side: two independently attacker-chosen answer buffers of
    // attacker-chosen length, plus an independently chosen record length.
    var b0: [96]u8 = undefined;
    var b1: [96]u8 = undefined;
    smith.bytes(&b0);
    smith.bytes(&b1);
    const l0: usize = smith.valueRangeAtMost(u8, 0, b0.len);
    const l1: usize = smith.valueRangeAtMost(u8, 0, b1.len);
    const record_len: usize = smith.valueRangeAtMost(u8, 0, 64);
    var rec: [64]u8 = undefined;

    FuzzPir.reconstructFromBytes(b0[0..l0], b1[0..l1], rec[0..record_len]) catch return;

    var w0: [16]FuzzPir.Word = undefined;
    var w1: [16]FuzzPir.Word = undefined;
    const n_words = FuzzPir.answerWords(record_len);
    try FuzzPir.answerFromBytes(b0[0 .. n_words * 4], w0[0..n_words]);
    try FuzzPir.answerFromBytes(b1[0 .. n_words * 4], w1[0..n_words]);
    try FuzzPir.reconstruct(w0[0..n_words], w1[0..n_words], rec[0..record_len]);
}
test "fuzz reconstruct never panics" {
    try std.testing.fuzz({}, fuzzReconstruct, .{});
}

const FuzzMulti = FuzzPir.Multi(3);

fn fuzzMultiShareFromBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [FuzzMulti.share_len + 8]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = FuzzMulti.shareFromBytes(buf[0..len]) catch return;
}
test "fuzz multi-index shareFromBytes never panics" {
    try std.testing.fuzz({}, fuzzMultiShareFromBytes, .{});
}

fn fuzzMultiAnswerHostileShare(_: void, smith: *std.testing.Smith) !void {
    // The whole multi-index server path on a hostile share: parse k sub-keys
    // out of arbitrary bytes, then compute both the k-block retrieval answer
    // and the aggregate with them. A share that parses is not a share that is
    // valid, and there are now k times as many ways for the key material to be
    // nonsense.
    var key_buf: [FuzzMulti.share_len]u8 = undefined;
    smith.bytes(&key_buf);
    const share = FuzzMulti.shareFromBytes(&key_buf) catch return;

    var db_bytes: [128]u8 = undefined;
    smith.bytes(&db_bytes);
    const record_len: usize = smith.valueRangeAtMost(u8, 1, 16);
    const record_count: usize = smith.valueRangeAtMost(u8, 1, 8);
    const database = Database.init(db_bytes[0 .. record_len * record_count], record_len) catch return;
    const party: u1 = @truncate(smith.valueRangeAtMost(u8, 0, 1));

    var out: [3 * 16]FuzzMulti.Word = undefined;
    const n_words = try FuzzMulti.answerWords(record_len);
    try FuzzMulti.answer(party, share, database, out[0..n_words]);

    var agg: [16]FuzzMulti.Word = undefined;
    const agg_words = FuzzMulti.aggregateWords(record_len);
    try FuzzMulti.answerAggregate(party, share, database, agg[0..agg_words]);

    var wire: [3 * 64]u8 = undefined;
    try FuzzPir.answerToBytes(out[0..n_words], wire[0 .. n_words * 4]);
}
test "fuzz multi-index answer over a hostile share never panics" {
    try std.testing.fuzz({}, fuzzMultiAnswerHostileShare, .{});
}

fn fuzzMultiReconstruct(_: void, smith: *std.testing.Smith) !void {
    // Two attacker-chosen answer buffers of attacker-chosen length, an
    // attacker-chosen record length, and a records_out whose length is chosen
    // independently of all three — the shape where a k-block layout could walk
    // off the end of a buffer.
    var b0: [192]u8 = undefined;
    var b1: [192]u8 = undefined;
    smith.bytes(&b0);
    smith.bytes(&b1);
    const l0: usize = smith.valueRangeAtMost(u8, 0, b0.len);
    const l1: usize = smith.valueRangeAtMost(u8, 0, b1.len);
    const record_len: usize = smith.valueRangeAtMost(u8, 0, 32);
    const out_len: usize = smith.valueRangeAtMost(u8, 0, 96);
    var rec: [96]u8 = undefined;

    FuzzMulti.reconstructFromBytes(b0[0..l0], b1[0..l1], record_len, rec[0..out_len]) catch return;
    // If it succeeded, the geometry it accepted must be the only consistent
    // one — assert that rather than trusting it.
    try std.testing.expectEqual(try FuzzMulti.answerBytesLen(record_len), l0);
    try std.testing.expectEqual(l0, l1);
    try std.testing.expectEqual(3 * record_len, out_len);
}
test "fuzz multi-index reconstruct never panics" {
    try std.testing.fuzz({}, fuzzMultiReconstruct, .{});
}
