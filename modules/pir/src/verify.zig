// SPDX-License-Identifier: MIT

//! verify — detection of a lying PIR server.
//!
//! The base protocol (`pir.zig`) is honest-but-curious: a server that returns
//! a doctored answer makes the client silently reconstruct a wrong record.
//! This layer adds **detection**: the client learns the answer is wrong and
//! aborts (`error.AnswerRejected`). It does NOT add robustness — with two
//! servers and a liar among them, the client cannot recover the right record,
//! and cannot even tell which server lied. Both are inherent at two servers;
//! see `SPEC.md` §"Malicious-server detection" for the argument.
//!
//! ## The construction: a secret-scalar MAC carried through the linearity
//!
//! Everything in the base protocol is linear over the DPF's output ring: the
//! answer is `Σ_x Eval(b,k_b,x)·word_j(record[x])` and the DPF's value
//! parameter β scales the reconstruction. So the client can MAC its own query:
//!
//! - **Value channel** — the base protocol unchanged: a DPF for `f_{i,1}` in
//!   `Z_{2^{8L}}`; reconstructs `w_j = word_j(record[i])`.
//! - **Tag channel** — a second, independent DPF for `f_{i,m}` where `m` is a
//!   secret ring element only the client knows, evaluated in the **widened**
//!   ring `Z_{2^{8(L+S)}}` (`S = tag_slack_bytes`); the server's inner product
//!   runs over the same `L`-byte record words zero-extended, plus one extra
//!   **presence word** with constant coefficient 1. Reconstructs
//!   `t_j = m·w_j` and `t_presence = m`.
//! - **Check** — `t_j == m·w_j` for every word and `t_presence == m`, else
//!   abort.
//!
//! Any deviation by a server — a flipped bit, a replayed answer, an answer
//! over a privately modified database, all zeros — lands as an additive error
//! `(e_v, e_t)` on the reconstruction, and by the DPF's hiding property that
//! error is chosen (computationally) without knowledge of `m`: the tag key
//! hides β = m exactly as it hides the index. Passing the check requires
//! `e_t = m·e_v` (up to a carry term; see SPEC), which for `e_v ≠ 0` the
//! adversary hits with probability ≤ 2^(1−8S) over the secret `m`.
//!
//! ## Why the ring is widened, in one sentence
//!
//! In the un-widened ring the check is deterministically forgeable — for any
//! odd `m`, `m·2^(8L−1) = 2^(8L−1)`, so flipping the value's top bit and
//! adding `2^(8L−1)` to the tag passes without knowing `m` (`Z_{2^k}` has zero
//! divisors; this is the standard MAC-over-`Z_{2^k}` failure, and the widening
//! is the standard fix — cf. SPDZ2k). A test demonstrates the S=0 forgery
//! arithmetic and that the widened check stops it.
//!
//! ## Why the presence word exists, in one sentence
//!
//! `t == m·v` is satisfied by the all-zero transcript, so two malicious
//! servers that each independently zero out their answers would otherwise make
//! the client accept an all-zero record; the presence word pins `t_presence`
//! to the nonzero secret `m`, which a zeroed transcript cannot supply.
//! (Consequence: querying an index past the database — which the base layer
//! defines as an all-zero reconstruction — is REJECTED here, deliberately: an
//! honest all-zero is indistinguishable from the zeroing forgery.)
//!
//! ## What this does and does not give (the honest summary)
//!
//! - **Detection, not robustness.** Abort, no recovery, no attribution.
//! - **One malicious server:** detected except with probability
//!   ≤ 2^(1−8S) + Adv_PRG.
//! - **Both servers malicious but not colluding:** still detected — their
//!   errors add, and the sum is still independent of `m`.
//! - **Both servers colluding:** no detection (they pool the two tag keys,
//!   recover `m`, and forge) — and no privacy either, exactly as in the base
//!   protocol. Collusion was already total loss; this layer does not change
//!   that boundary.
//! - **Both servers honestly serving the same wrong database:** NOT detected.
//!   The MAC binds the answer to the database the two servers jointly used,
//!   not to any database the client expects. Binding to a published database
//!   is authenticated PIR (digest + openings) — a different protocol, scoped
//!   out; see SPEC for why it was not chosen here.
//! - **Privacy is not degraded.** The tag key is one more DPF key under the
//!   same hiding property, and the abort event shifts by at most the soundness
//!   error across indices — there is no selective-failure attack with
//!   meaningful advantage (unlike hash-in-the-record designs; see SPEC).

const std = @import("std");
const fss = @import("fss");
const db_mod = @import("db.zig");
const pir_mod = @import("pir.zig");

const Database = db_mod.Database;
const Error = db_mod.Error;

/// Verified two-server PIR: `Pir(domain_bits, word_bytes)`'s protocol plus a
/// MACed tag channel that detects a lying server.
///
/// `tag_slack_bytes` (`S ≥ 1`, `word_bytes + S ≤ 32`) sets the statistical
/// soundness error `2^(1−8S)`: an adversary forging without the secret `m`
/// passes the check with at most that probability. `8` is the recommended
/// default (error ≤ 2^-63); `1` is the floor (error ≤ 2^-7), permitted
/// because the bound is stated rather than hidden. `0` would be
/// deterministically forgeable and is a compile error.
pub fn Verified(
    comptime domain_bits: usize,
    comptime word_bytes: usize,
    comptime tag_slack_bytes: usize,
) type {
    if (tag_slack_bytes < 1) {
        // The un-widened check is not weak, it is BROKEN: m·2^(8L-1) == 2^(8L-1)
        // for every odd m, so the top-bit forgery passes with probability 1.
        @compileError("Verified: tag_slack_bytes must be >= 1 (S = 0 is deterministically forgeable; see SPEC.md)");
    }
    if (word_bytes + tag_slack_bytes > 32) {
        @compileError("Verified: word_bytes + tag_slack_bytes must be <= 32 (fss.Dpf's maximum output width)");
    }
    return struct {
        const Ver = @This();

        /// the unmodified base protocol — the value channel IS `Pir(b, L)`
        pub const Value = pir_mod.Pir(domain_bits, word_bytes);
        /// the tag channel's DPF, over the widened ring `Z_{2^{8(L+S)}}`
        pub const TagDpf = fss.Dpf(domain_bits, word_bytes + tag_slack_bytes);

        pub const Word = Value.Word;
        /// a tag-channel ring element (also the type of the secret `m`)
        pub const TagWord = TagDpf.Elem;
        pub const Seed = Value.Seed;

        /// bytes per tag word (`word_bytes + tag_slack_bytes`)
        pub const tag_word_len: usize = word_bytes + tag_slack_bytes;
        /// serialized length of one server's bundled share (value key ‖ tag
        /// key) — compile-time constant, identical for every index and every
        /// `m`, so neither leaks through the length
        pub const share_len = Value.share_len + TagDpf.Key.serialized_len;
        pub const domain_size: usize = Value.domain_size;

        /// one server's share: the value key and the tag key. The two are
        /// independent DPF instances (independent seeds enforced by `query`),
        /// so jointly they hide `(i, m)` exactly as each hides its own pair.
        pub const Share = struct {
            value: Value.Share,
            tag: TagDpf.Key,
        };

        /// the client's per-query secret. `m` never goes on the wire; it is
        /// hidden inside the tag keys as the DPF's β, under the same PRG
        /// assumption that hides the index.
        pub const Secret = struct {
            m: TagWord,

            /// Destroy `m` (CONVENTIONS §2.1 Z1 — a per-query client secret in
            /// storage this struct owns). Call it once `reconstruct` has
            /// returned: `m` is what the soundness bound rests on, and holding
            /// it past the query buys nothing. A wiped `Secret` rejects every
            /// answer, so it cannot be reused by accident.
            pub fn wipe(self: *Secret) void {
                std.crypto.secureZero(TagWord, @as(*[1]TagWord, &self.m));
            }
        };

        pub const Query = struct {
            shares: [2]Ver.Share,
            secret: Secret,

            /// Destroy the client secret carried by this query — see
            /// `Secret.wipe`. `shares` are the outbound wire values (they went
            /// to the servers) and are left alone.
            pub fn wipe(self: *Query) void {
                self.secret.wipe();
            }
        };

        // ── client: query construction ────────────────────────────────────

        /// Build the two bundled shares for `index`, plus the secret the
        /// client must retain for `reconstruct`.
        ///
        /// `mac_rand` and all four seeds MUST be freshly drawn, mutually
        /// independent CSPRNG output, never reused for another query (the
        /// seeds for the base-protocol reason; `mac_rand` because a reused
        /// `m` lets each rejected forgery attempt eliminate candidate values
        /// — soundness degrades linearly in the number of attempts against
        /// one `m`). Byte-identical seeds are rejected (`error.SeedReuse`),
        /// the same plumbing-bug guard `Multi` uses; independence remains the
        /// caller's obligation, as everywhere in this repo.
        ///
        /// `mac_rand` and the four seeds are **caller-owned** storage
        /// (CONVENTIONS §2.1 Z2): this module copies what it needs and cannot
        /// know when the caller is done, so the caller must
        /// `std.crypto.secureZero` its own buffers. The copy that ends up in
        /// the returned `Query` is ours — destroy it with `Query.wipe` once
        /// `reconstruct` has returned.
        ///
        /// `m` is `mac_rand` forced odd (low bit set). Odd means invertible,
        /// which removes the all-even weak class and makes the presence check
        /// exact; forcing one known bit costs one bit of `m`'s entropy, which
        /// the soundness bound already accounts for.
        ///
        /// Unlike the base `query`, the caller must keep `index < db.count()`:
        /// the presence word makes an unpopulated index REJECT rather than
        /// reconstruct to zero (see the module doc).
        pub fn query(
            index: usize,
            mac_rand: [tag_word_len]u8,
            sv0: Seed,
            sv1: Seed,
            st0: Seed,
            st1: Seed,
        ) Error!Query {
            const seeds = [4]Seed{ sv0, sv1, st0, st1 };
            for (0..seeds.len) |a| {
                for (a + 1..seeds.len) |b| {
                    if (std.mem.eql(u8, &seeds[a], &seeds[b])) return error.SeedReuse;
                }
            }
            // Value channel: the base protocol verbatim (β = 1, index check
            // included).
            const value_shares = try Value.query(index, sv0, sv1);
            // Tag channel: β = m. The DPF hides β exactly as it hides α, so
            // handing the server this key does not hand it the MAC key.
            var m: TagWord = std.mem.readInt(TagWord, &mac_rand, .little);
            m |= 1;
            const tag_keys = TagDpf.genWithSeeds(@intCast(index), m, st0, st1);
            return .{
                .shares = .{
                    .{ .value = value_shares[0], .tag = tag_keys[0] },
                    .{ .value = value_shares[1], .tag = tag_keys[1] },
                },
                .secret = .{ .m = m },
            };
        }

        /// Query by keyword: exactly `query(Value.keywordIndex(keyword), …)`
        /// and nothing else — the same total, deterministic, unconditional map
        /// as the base layer's `queryKeyword`, with the same caller
        /// discipline (one lookup, one query; never skip, never retry).
        ///
        /// ⚠ One interaction is specific to this layer: a keyword whose slot
        /// is past the database REJECTS (`error.AnswerRejected`) rather than
        /// reconstructing to zero — the presence word makes an honest
        /// all-zero indistinguishable from the zeroing forgery (module doc).
        /// So under `Verified`, "absent keyword whose slot is unpopulated" and
        /// "a server lied" are the SAME client-visible outcome, and the
        /// discipline above matters doubly: re-querying on that reject would
        /// leak exactly the retry pattern `queryKeyword` exists to avoid. A
        /// deployment wanting a verifiable "absent" must materialize every
        /// slot (filler records up to `2^domain_bits`, or a domain sized to
        /// the record count) so a miss is a present-but-filler record.
        pub fn queryKeyword(
            keyword: []const u8,
            mac_rand: [tag_word_len]u8,
            sv0: Seed,
            sv1: Seed,
            st0: Seed,
            st1: Seed,
        ) Error!Query {
            return query(Value.keywordIndex(keyword), mac_rand, sv0, sv1, st0, st1);
        }

        /// Serialize a bundled share: value key then tag key, fixed offsets,
        /// no header — the same no-length-field discipline as the base codec.
        pub fn shareToBytes(share: Ver.Share, buf: *[share_len]u8) void {
            share.value.toBytes(buf[0..Value.share_len]);
            share.tag.toBytes(buf[Value.share_len..][0..TagDpf.Key.serialized_len]);
        }

        /// Parse a bundled share. **Untrusted boundary** (a server parses a
        /// client's bytes): exactly one accepted length, every field a
        /// fixed-width read at a compile-time-known offset.
        pub fn shareFromBytes(buf: []const u8) Error!Ver.Share {
            if (buf.len != share_len) return error.ShareLengthMismatch;
            return .{
                .value = try Value.shareFromBytes(buf[0..Value.share_len]),
                .tag = TagDpf.Key.fromBytes(buf[Value.share_len..][0..TagDpf.Key.serialized_len]),
            };
        }

        // ── server: answer computation ────────────────────────────────────

        /// Tag words per answer: one per value word, plus the presence word.
        pub fn tagWords(record_len: usize) usize {
            return Value.answerWords(record_len) + 1;
        }

        /// Bytes in a serialized tag answer. Geometry-only, like every other
        /// length here.
        pub fn tagBytesLen(record_len: usize) usize {
            return tagWords(record_len) * tag_word_len;
        }

        /// Server `party`'s answer to a bundled share: the base-protocol value
        /// answer into `value_out` (`Value.answerWords(record_len)` words) and
        /// the tag answer into `tag_out` (`tagWords(record_len)` words).
        ///
        /// The tag inner product runs over the SAME `L`-byte record words as
        /// the value channel, zero-extended into the widened ring — not over a
        /// re-decomposition into wider words. That is what makes the honest
        /// relation `t_j = m·w_j` exact: `w_j < 2^{8L}` fits the widened ring
        /// with room to spare, so no reduction happens on the honest path and
        /// the check needs no tolerance. The final word accumulates
        /// coefficient 1 per record — the presence word.
        ///
        /// Two passes over the database (one per channel), each touching every
        /// record with no early exit and no branch on evaluated shares — the
        /// base layer's access-pattern requirement, unchanged. The second pass
        /// is the price of reusing the tested base `answer` verbatim rather
        /// than forking its loop.
        pub fn answer(
            party: u1,
            share: Ver.Share,
            database: Database,
            value_out: []Word,
            tag_out: []TagWord,
        ) Error!void {
            try Value.answer(party, share.value, database, value_out);

            if (tag_out.len != tagWords(database.record_len)) return error.AnswerLengthMismatch;
            const n = database.count();
            if (n > domain_size) return error.DomainTooSmall;
            const per = Value.answerWords(database.record_len);

            @memset(tag_out, 0);
            // The tag channel is just another instantiation of the same
            // generic `fss.Dpf`, so it gets the same tree-reuse streaming walk
            // the value channel's `Value.answer` uses (~1 PRG call per record
            // instead of `domain_bits`), for the same allocator-free reason.
            // The walk emits every `x < n` exactly once, in order — the
            // access-pattern requirement is unchanged.
            const Ctx = struct { database: Database, tag_out: []TagWord, per: usize };
            TagDpf.evalFullWith(
                party,
                share.tag,
                n,
                Ctx{ .database = database, .tag_out = tag_out, .per = per },
                struct {
                    fn emit(ctx: Ctx, x: usize, sel: TagWord) void {
                        const rec = ctx.database.record(x);
                        for (0..ctx.per) |j| {
                            ctx.tag_out[j] +%= sel *% @as(TagWord, Value.wordAt(rec, j));
                        }
                        // presence: coefficient 1 for every record
                        ctx.tag_out[ctx.per] +%= sel;
                    }
                }.emit,
            );
        }

        /// Serialize a tag answer, little-endian per tag word. The value
        /// answer uses the base `Value.answerToBytes` unchanged.
        pub fn tagAnswerToBytes(words: []const TagWord, buf: []u8) Error!void {
            const need = std.math.mul(usize, words.len, tag_word_len) catch
                return error.AnswerLengthMismatch;
            if (buf.len != need) return error.AnswerLengthMismatch;
            for (words, 0..) |w, j| {
                std.mem.writeInt(TagWord, buf[j * tag_word_len ..][0..tag_word_len], w, .little);
            }
        }

        /// Parse a tag answer. **Untrusted boundary**: the required length is
        /// computed from the caller's own `out` slice; the input never gets to
        /// say how long it is.
        pub fn tagAnswerFromBytes(buf: []const u8, out: []TagWord) Error!void {
            const need = std.math.mul(usize, out.len, tag_word_len) catch
                return error.AnswerLengthMismatch;
            if (buf.len != need) return error.AnswerLengthMismatch;
            for (out, 0..) |*w, j| {
                w.* = std.mem.readInt(TagWord, buf[j * tag_word_len ..][0..tag_word_len], .little);
            }
        }

        // ── client: verify + reconstruct ──────────────────────────────────

        /// Verify the two servers' answers against the retained secret and, on
        /// success, reconstruct the record into `record_out`. On any check
        /// failure returns `error.AnswerRejected` and writes nothing.
        ///
        /// Detection only: a rejection says SOMEONE deviated (or the replicas
        /// diverged), not who, and gives no way to recover the record.
        ///
        /// Constant-time position: the check is a fixed-trip loop of ring
        /// multiply/add/xor accumulating a single difference word — no
        /// data-dependent branch, no early exit, no per-word bail-out — and
        /// the one branch at the end is on the accept/reject bit, which is the
        /// protocol's own output (the client aborts visibly). What this buys:
        /// timing does not reveal WHICH word mismatched or by how much. What
        /// it cannot buy: hiding the reject itself, which is definitionally
        /// public. The DPF evaluation underneath keeps `fss`'s documented
        /// posture (control-bit-gated branches, scoped-out hardening there).
        pub fn reconstruct(
            secret: Secret,
            v0: []const Word,
            v1: []const Word,
            t0: []const TagWord,
            t1: []const TagWord,
            record_out: []u8,
        ) Error!void {
            const per = Value.answerWords(record_out.len);
            if (v0.len != per or v1.len != per) return error.AnswerLengthMismatch;
            if (t0.len != per + 1 or t1.len != per + 1) return error.AnswerLengthMismatch;

            var diff: TagWord = 0;
            var j: usize = 0;
            while (j < per) : (j += 1) {
                const v = v0[j] +% v1[j];
                const t = t0[j] +% t1[j];
                diff |= t ^ (secret.m *% @as(TagWord, v));
            }
            // The presence word must reconstruct to exactly m. This is what a
            // coordinated all-zero transcript cannot supply, and (deliberately)
            // what makes an unpopulated-index query reject.
            diff |= (t0[per] +% t1[per]) ^ secret.m;
            if (diff != 0) return error.AnswerRejected;

            return Value.reconstruct(v0, v1, record_out);
        }

        /// `reconstruct` straight from the four serialized answers.
        /// **Untrusted boundary** for all four: every required length is
        /// derived from `record_out`, and each input must match exactly.
        /// Verification reads words directly from the buffers, so no
        /// intermediate arrays (and no allocator) are needed.
        pub fn reconstructFromBytes(
            secret: Secret,
            v0: []const u8,
            v1: []const u8,
            t0: []const u8,
            t1: []const u8,
            record_out: []u8,
        ) Error!void {
            const per = Value.answerWords(record_out.len);
            const v_need = std.math.mul(usize, per, word_bytes) catch
                return error.AnswerLengthMismatch;
            const t_need = std.math.mul(usize, per + 1, tag_word_len) catch
                return error.AnswerLengthMismatch;
            if (v0.len != v_need or v1.len != v_need) return error.AnswerLengthMismatch;
            if (t0.len != t_need or t1.len != t_need) return error.AnswerLengthMismatch;

            var diff: TagWord = 0;
            var j: usize = 0;
            while (j < per) : (j += 1) {
                const w0 = std.mem.readInt(Word, v0[j * word_bytes ..][0..word_bytes], .little);
                const w1 = std.mem.readInt(Word, v1[j * word_bytes ..][0..word_bytes], .little);
                const g0 = std.mem.readInt(TagWord, t0[j * tag_word_len ..][0..tag_word_len], .little);
                const g1 = std.mem.readInt(TagWord, t1[j * tag_word_len ..][0..tag_word_len], .little);
                diff |= (g0 +% g1) ^ (secret.m *% @as(TagWord, w0 +% w1));
            }
            const p0 = std.mem.readInt(TagWord, t0[per * tag_word_len ..][0..tag_word_len], .little);
            const p1 = std.mem.readInt(TagWord, t1[per * tag_word_len ..][0..tag_word_len], .little);
            diff |= (p0 +% p1) ^ secret.m;
            if (diff != 0) return error.AnswerRejected;

            return Value.reconstructFromBytes(v0, v1, record_out);
        }
    };
}

// ── tests ─────────────────────────────────────────────────────────────────
//
// Anchoring (CONVENTIONS.md §7, SPEC.md §"Anchoring"): no external vector
// exists for this layer either — same argument as the base protocol, plus the
// MAC scalar is a client secret so a fixed vector would have to publish it.
// Labels used here:
//
//   DERIVED — the tag answer recomputed from the plaintext definition
//             (m·word, no DPF) and required to match.
//   SELF    — round-trips and properties against this module.
//   ATTACK  — a simulated malicious server (this module plays both attacker
//             and defender; that is a SELF-grade test of the DETECTION
//             property, honestly labelled as such — it proves the check fires
//             on these concrete deviations, not that no deviation exists).
//   EXACT   — deterministic structural assertions, privacy-battery style.

const testing = std.testing;

/// Deterministic seeds/mac for tests. NOT a production pattern — `query`
/// requires fresh CSPRNG input; this exists so a failure is permanent, never
/// a flake.
fn detSeed(tag: u64) fss.prg.Seed {
    var h: [32]u8 = undefined;
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, tag, .little);
    std.crypto.hash.sha2.Sha256.hash(&buf, &h, .{});
    return h[0..16].*;
}

fn detMac(comptime n: usize, tag: u64) [n]u8 {
    var out: [n]u8 = undefined;
    var i: usize = 0;
    while (i * 16 < n) : (i += 1) {
        const part = detSeed(tag *% 7919 +% i +% 0xace);
        const take = @min(16, n - i * 16);
        @memcpy(out[i * 16 ..][0..take], part[0..take]);
    }
    return out;
}

/// Same deterministic database the base tests use: record `x` from a hash of
/// `x`, so no two records are equal and a wrong answer cannot accidentally
/// match the right record.
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

/// The workhorse config for the attack battery: 12 records of 5 bytes in a
/// 16-index domain, 4-byte value words (so answers have a partial final word
/// — the awkward case), 8 bytes of tag slack (the recommended default).
const V = Verified(4, 4, 8);
const t_record_len = 5;
const t_count = 12;

/// One honest protocol run: both servers' value and tag answers plus the
/// client state, for the attack tests to tamper with.
const Run = struct {
    q: V.Query,
    va: [2][2]V.Word, // [party][word]
    ta: [2][3]V.TagWord, // [party][word] (2 value words + presence)
    db_bytes: [t_count * t_record_len]u8,

    fn database(self: *const Run) Database {
        return Database.init(&self.db_bytes, t_record_len) catch unreachable;
    }

    fn init(index: usize, tag: u64) !Run {
        var r: Run = undefined;
        fillDb(&r.db_bytes, t_record_len);
        r.q = try V.query(
            index,
            detMac(V.tag_word_len, tag),
            detSeed(tag *% 4 + 0),
            detSeed(tag *% 4 + 1),
            detSeed(tag *% 4 + 2),
            detSeed(tag *% 4 + 3),
        );
        for (0..2) |b| {
            try V.answer(@intCast(b), r.q.shares[b], r.database(), &r.va[b], &r.ta[b]);
        }
        return r;
    }

    fn reconstruct(self: *const Run, out: *[t_record_len]u8) Error!void {
        return V.reconstruct(self.q.secret, &self.va[0], &self.va[1], &self.ta[0], &self.ta[1], out);
    }
};

test "SOUNDNESS: the MAC scalar is forced ODD, whatever the caller supplies" {
    // `query` does `m |= 1`, and the doc comment above it gives a security
    // reason: odd means invertible in Z_(2^k), which removes the all-even
    // weak class and makes the presence check exact. The soundness bound
    // stated in SPEC.md is derived under that assumption.
    //
    // Nothing else in this file notices if the forcing is dropped. Changing
    // `m |= 1` to `m &= ~1` — every scalar even, the weak class the comment
    // warns about — leaves all other tests in this module green, because a
    // consistent even scalar still satisfies `t_j = m·w_j` and the honest
    // path never exercises the class. So the property is pinned here
    // directly rather than left to be inferred from the attack tests.
    const W = Verified(4, 4, 8);
    const seeds = [4]W.Seed{
        [_]u8{0xA1} ** 16, [_]u8{0xB2} ** 16,
        [_]u8{0xC3} ** 16, [_]u8{0xD4} ** 16,
    };

    // An all-even `mac_rand`, i.e. the worst thing a caller can hand in.
    var mac_rand = [_]u8{0} ** W.tag_word_len;
    for (&mac_rand, 0..) |*b, i| b.* = @truncate((i * 2) & 0xFE);
    const q = try W.query(0, mac_rand, seeds[0], seeds[1], seeds[2], seeds[3]);
    try std.testing.expect(q.secret.m & 1 == 1);

    // And an already-odd one must be left alone apart from that bit, so the
    // forcing costs exactly the one bit the bound accounts for.
    var odd_rand = [_]u8{0} ** W.tag_word_len;
    for (&odd_rand, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
    const raw = std.mem.readInt(W.TagWord, &odd_rand, .little);
    const q2 = try W.query(0, odd_rand, seeds[0], seeds[1], seeds[2], seeds[3]);
    try std.testing.expectEqual(raw | 1, q2.secret.m);
}

test "SELF: honest verified retrieval returns the right record for EVERY index, across geometries" {
    const cases = .{
        .{ .bits = 1, .count = 1 },
        .{ .bits = 1, .count = 2 },
        .{ .bits = 2, .count = 3 },
        .{ .bits = 3, .count = 8 },
        .{ .bits = 4, .count = 9 },
        .{ .bits = 5, .count = 20 },
    };
    const record_lens = [_]usize{ 1, 3, 4, 5, 16 };

    inline for (cases) |c| {
        const W = Verified(c.bits, 4, 8);
        for (record_lens) |record_len| {
            var storage: [32 * 16]u8 = undefined;
            const bytes = storage[0 .. c.count * record_len];
            fillDb(bytes, record_len);
            const database = try Database.init(bytes, record_len);
            const per = W.Value.answerWords(record_len);
            const tw = W.tagWords(record_len);

            var va: [2][4]W.Word = undefined;
            var ta: [2][5]W.TagWord = undefined;
            var got: [16]u8 = undefined;

            for (0..c.count) |i| {
                const t = @as(u64, c.bits) * 1_000_003 + i * 31 + record_len;
                const q = try W.query(
                    i,
                    detMac(W.tag_word_len, t),
                    detSeed(t * 4 + 0),
                    detSeed(t * 4 + 1),
                    detSeed(t * 4 + 2),
                    detSeed(t * 4 + 3),
                );
                for (0..2) |b| {
                    try W.answer(@intCast(b), q.shares[b], database, va[b][0..per], ta[b][0..tw]);
                }
                try W.reconstruct(
                    q.secret,
                    va[0][0..per],
                    va[1][0..per],
                    ta[0][0..tw],
                    ta[1][0..tw],
                    got[0..record_len],
                );
                try testing.expectEqualSlices(u8, database.record(i), got[0..record_len]);
            }
        }
    }
}

test "DERIVED: the tag answer equals m·word (+ presence m) computed without any DPF" {
    // Route A is the defining equation of the tag channel — m times the
    // record's zero-extended words, plus m once for presence — computed
    // straight from the plaintext, no secret sharing. Route B is through the
    // two shared tag answers. They must agree word for word.
    const run = try Run.init(7, 1001);
    const rec = run.database().record(7);

    for (0..2) |j| {
        const w: V.TagWord = V.Value.wordAt(rec, j);
        const want = run.q.secret.m *% w;
        try testing.expectEqual(want, run.ta[0][j] +% run.ta[1][j]);
    }
    try testing.expectEqual(run.q.secret.m, run.ta[0][2] +% run.ta[1][2]);
}

test "SELF: wire round-trip — bundled share and both answers survive serialization" {
    const run = try Run.init(3, 77);

    var wire: [V.share_len]u8 = undefined;
    V.shareToBytes(run.q.shares[0], &wire);
    const parsed = try V.shareFromBytes(&wire);
    var va: [2]V.Word = undefined;
    var ta: [3]V.TagWord = undefined;
    try V.answer(0, parsed, run.database(), &va, &ta);
    try testing.expectEqualSlices(V.Word, &run.va[0], &va);
    try testing.expectEqualSlices(V.TagWord, &run.ta[0], &ta);

    var vb: [2][8]u8 = undefined;
    var tb: [2][3 * V.tag_word_len]u8 = undefined;
    for (0..2) |b| {
        try V.Value.answerToBytes(&run.va[b], &vb[b]);
        try V.tagAnswerToBytes(&run.ta[b], &tb[b]);
    }
    // parse-back agrees with the originals
    var t_back: [3]V.TagWord = undefined;
    try V.tagAnswerFromBytes(&tb[1], &t_back);
    try testing.expectEqualSlices(V.TagWord, &run.ta[1], &t_back);

    var got: [t_record_len]u8 = undefined;
    try V.reconstructFromBytes(run.q.secret, &vb[0], &vb[1], &tb[0], &tb[1], &got);
    try testing.expectEqualSlices(u8, run.database().record(3), &got);
}

test "SELF: verified keyword lookup — a hit verifies; an UNPOPULATED slot rejects (documented interaction)" {
    const W = Verified(8, 4, 8);
    const record_len = 12; // key field (8) + payload
    var bytes: [W.domain_size * record_len]u8 = undefined;
    @memset(&bytes, 0xFF); // filler in every slot

    const kw = "alpha";
    const idx = W.Value.keywordIndex(kw);
    {
        const rec = bytes[idx * record_len ..][0..record_len];
        @memset(rec, 0);
        @memcpy(rec[0..kw.len], kw);
    }
    const per = W.Value.answerWords(record_len);
    const tw = W.tagWords(record_len);
    var va: [2][3]W.Word = undefined;
    var ta: [2][4]W.TagWord = undefined;
    var got: [record_len]u8 = undefined;

    // Hit over a fully-materialized domain: verifies and returns the record.
    // Also pin that the keyword wrapper is exactly query∘keywordIndex here
    // too — byte-identical bundled shares under the same inputs.
    {
        const database = try Database.init(&bytes, record_len);
        const q = try W.queryKeyword(
            kw,
            detMac(W.tag_word_len, 6001),
            detSeed(6002),
            detSeed(6003),
            detSeed(6004),
            detSeed(6005),
        );
        const q_idx = try W.query(
            idx,
            detMac(W.tag_word_len, 6001),
            detSeed(6002),
            detSeed(6003),
            detSeed(6004),
            detSeed(6005),
        );
        var w_kw: [W.share_len]u8 = undefined;
        var w_idx: [W.share_len]u8 = undefined;
        for (0..2) |b| {
            W.shareToBytes(q.shares[b], &w_kw);
            W.shareToBytes(q_idx.shares[b], &w_idx);
            try testing.expectEqualSlices(u8, &w_idx, &w_kw);
        }
        for (0..2) |b| {
            try W.answer(@intCast(b), q.shares[b], database, va[b][0..per], ta[b][0..tw]);
        }
        try W.reconstruct(q.secret, va[0][0..per], va[1][0..per], ta[0][0..tw], ta[1][0..tw], &got);
        try testing.expectEqualSlices(u8, kw, got[0..kw.len]);
    }

    // A keyword whose slot is PAST the record count: the query is still the
    // same single unconditional call (the servers see nothing new), but the
    // presence word makes the client REJECT rather than read all-zero —
    // "absent" and "a server lied" are the same client-visible outcome here.
    // That is why `Verified.queryKeyword`'s doc tells deployments wanting a
    // verifiable absent to materialize every slot, as the hit case above does.
    {
        const small = try Database.init(bytes[0 .. 100 * record_len], record_len);
        var buf: [16]u8 = undefined;
        var t: usize = 0;
        const far_kw = while (t < 1000) : (t += 1) {
            const cand = std.fmt.bufPrint(&buf, "far-{d}", .{t}) catch unreachable;
            if (W.Value.keywordIndex(cand) >= 100) break cand;
        } else unreachable;
        const q = try W.queryKeyword(
            far_kw,
            detMac(W.tag_word_len, 6101),
            detSeed(6102),
            detSeed(6103),
            detSeed(6104),
            detSeed(6105),
        );
        for (0..2) |b| {
            try W.answer(@intCast(b), q.shares[b], small, va[b][0..per], ta[b][0..tw]);
        }
        try testing.expectError(
            error.AnswerRejected,
            W.reconstruct(q.secret, va[0][0..per], va[1][0..per], ta[0][0..tw], ta[1][0..tw], &got),
        );
    }
}

// ── ATTACK: the malicious-server battery ──────────────────────────────────

test "ATTACK: every single-bit flip in either server's value answer is rejected" {
    const run = try Run.init(5, 2002);
    var got: [t_record_len]u8 = undefined;

    for (0..2) |b| {
        for (0..2) |j| {
            for (0..@bitSizeOf(V.Word)) |bit| {
                var tampered = run;
                tampered.va[b][j] ^= @as(V.Word, 1) << @intCast(bit);
                try testing.expectError(error.AnswerRejected, tampered.reconstruct(&got));
            }
        }
    }
}

test "ATTACK: every single-bit flip in either server's tag answer (incl. presence) is rejected" {
    const run = try Run.init(5, 2003);
    var got: [t_record_len]u8 = undefined;

    for (0..2) |b| {
        for (0..3) |j| {
            for (0..@bitSizeOf(V.TagWord)) |bit| {
                var tampered = run;
                tampered.ta[b][j] ^= @as(V.TagWord, 1) << @intCast(bit);
                try testing.expectError(error.AnswerRejected, tampered.reconstruct(&got));
            }
        }
    }
}

test "ATTACK: one server returning all zeros is rejected" {
    const run = try Run.init(9, 2004);
    var got: [t_record_len]u8 = undefined;

    var tampered = run;
    @memset(&tampered.va[1], 0);
    @memset(&tampered.ta[1], 0);
    try testing.expectError(error.AnswerRejected, tampered.reconstruct(&got));

    // Zeroing only one channel is rejected too.
    var half = run;
    @memset(&half.ta[1], 0);
    try testing.expectError(error.AnswerRejected, half.reconstruct(&got));
}

test "ATTACK: BOTH servers zeroing everything is rejected — the presence word is load-bearing" {
    // Without the presence word this transcript PASSES: v = 0, t = 0 satisfies
    // t == m·v, and the client would accept an all-zero record — reachable by
    // two malicious servers who each zero their own answers WITHOUT colluding.
    // The presence word demands t_presence == m ≠ 0, which zeros cannot supply.
    const run = try Run.init(4, 2005);
    var got: [t_record_len]u8 = undefined;

    var tampered = run;
    for (0..2) |b| {
        @memset(&tampered.va[b], 0);
        @memset(&tampered.ta[b], 0);
    }
    try testing.expectError(error.AnswerRejected, tampered.reconstruct(&got));
}

test "ATTACK: a replayed answer — from an older query for the SAME index — is rejected" {
    // Server 1 ignores the fresh share and replays the answers it computed for
    // a previous query (same index, so the "right" record — but under the old
    // keys). The stale answers are additive garbage relative to the fresh
    // instance and carry no relation to the fresh m.
    const fresh = try Run.init(6, 2006);
    const stale = try Run.init(6, 2007);
    var got: [t_record_len]u8 = undefined;

    var tampered = fresh;
    tampered.va[1] = stale.va[1];
    tampered.ta[1] = stale.ta[1];
    try testing.expectError(error.AnswerRejected, tampered.reconstruct(&got));
}

test "ATTACK: ONE server answering over a privately modified database is rejected" {
    // Server 1 follows the protocol honestly but over a database whose record
    // 2 differs by one bit — the replica-divergence failure the base layer
    // documents as silent corruption. Here the effective error is an inner
    // product of the tampered records with this server's pseudorandom share
    // vector, which cannot satisfy t == m·v.
    const run = try Run.init(2, 2008); // query the very record that differs
    var got: [t_record_len]u8 = undefined;

    var tampered = run;
    tampered.db_bytes[2 * t_record_len] ^= 0x01;
    try V.answer(1, tampered.q.shares[1], tampered.database(), &tampered.va[1], &tampered.ta[1]);
    tampered.db_bytes = run.db_bytes; // client-side state; servers already answered
    try testing.expectError(error.AnswerRejected, tampered.reconstruct(&got));

    // Same attack on a record OTHER than the queried one: still rejected —
    // divergence is detected regardless of whether the client's index is hit.
    var tampered2 = run;
    tampered2.db_bytes[9 * t_record_len] ^= 0x01;
    try V.answer(1, tampered2.q.shares[1], tampered2.database(), &tampered2.va[1], &tampered2.ta[1]);
    tampered2.db_bytes = run.db_bytes;
    try testing.expectError(error.AnswerRejected, tampered2.reconstruct(&got));
}

test "ATTACK NOT CAUGHT: both servers agreeing on the same wrong database is ACCEPTED" {
    // The documented limitation, asserted so it cannot be over-claimed away:
    // the MAC binds the answer to the database the two servers JOINTLY used.
    // If both replicas hold the same modified database and both answer
    // honestly over it, the transcript is self-consistent and the client
    // accepts the modified record. Detecting THIS requires a digest of the
    // authentic database (authenticated PIR) — a different protocol, scoped
    // out in SPEC.md.
    var run = try Run.init(2, 2009);
    var got: [t_record_len]u8 = undefined;

    run.db_bytes[2 * t_record_len] ^= 0x01; // both servers see the same DB'
    for (0..2) |b| {
        try V.answer(@intCast(b), run.q.shares[b], run.database(), &run.va[b], &run.ta[b]);
    }
    try run.reconstruct(&got); // accepted…
    try testing.expectEqualSlices(u8, run.database().record(2), &got); // …and it IS DB'[2]
    try testing.expect(got[0] != fillDbByte(2)); // which differs from the authentic record
}

/// first byte of the authentic record `x` under `fillDb` — recomputed
/// independently so the previous test's last assertion does not depend on the
/// mutated buffer.
fn fillDbByte(x: usize) u8 {
    var h: [32]u8 = undefined;
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, x, .little);
    std.crypto.hash.sha2.Sha256.hash(&buf, &h, .{});
    return h[0];
}

test "ATTACK NOT CAUGHT: colluding servers that recover m forge undetectably" {
    // The other documented limitation: m's secrecy is the DPF's β-hiding, so
    // two servers that pool their tag keys evaluate both and read off (i, m)
    // — the same full-domain scan that already recovers i in the base
    // protocol. With m in hand, e_t = m·e_v passes the check by construction.
    // Collusion was already total privacy loss; it is total integrity loss
    // too, and this test keeps that from being papered over.
    const run = try Run.init(8, 2010);
    var got: [t_record_len]u8 = undefined;

    // The colluding pair knows m AND i (simulated by reading the client's
    // secret — which is exactly what evaluating both keys over the domain
    // yields). Both are needed: the tag compensation is m·(e_v − δ·2^{8L})
    // where δ is the carry of the value word's mod-2^{8L} wrap, and computing
    // δ requires knowing record[i]'s word — one more thing only colluders
    // have. (A single malicious server would have to guess δ as well as m.)
    const m = run.q.secret.m;
    const e_v: V.Word = 0xdeadbeef;
    const w0: V.Word = V.Value.wordAt(run.database().record(8), 0);
    const carry = @addWithOverflow(w0, e_v)[1];
    const wrap: V.TagWord = @as(V.TagWord, carry) << @bitSizeOf(V.Word);
    var tampered = run;
    tampered.va[1][0] +%= e_v;
    tampered.ta[1][0] +%= m *% (@as(V.TagWord, e_v) -% wrap);
    try tampered.reconstruct(&got); // accepted
    var honest: [t_record_len]u8 = undefined;
    try run.reconstruct(&honest);
    try testing.expect(!std.mem.eql(u8, &got, &honest)); // and the record is wrong
}

test "ATTACK: the top-bit ring forgery — deterministic at S=0, stopped by the slack" {
    // Part 1, the arithmetic fact that makes S=0 a compile error rather than a
    // parameter: in the UN-widened ring, m·2^(8L−1) == 2^(8L−1) for EVERY odd
    // m. An attacker flips the value's top bit and adds 2^(8L−1) to the tag —
    // no knowledge of m required, success probability 1. Demonstrated over
    // many m rather than asserted in prose.
    var i: u64 = 0;
    while (i < 64) : (i += 1) {
        var mac = detMac(V.tag_word_len, 3000 + i);
        mac[0] |= 1;
        const m_narrow: V.Word = @truncate(std.mem.readInt(V.TagWord, &mac, .little));
        const top: V.Word = @as(V.Word, 1) << (@bitSizeOf(V.Word) - 1);
        try testing.expectEqual(top, m_narrow *% top); // the S=0 check would accept
    }

    // Part 2: the same attack against the widened check. The compensating tag
    // error would have to be m·2^(8L−1) mod 2^(8(L+S)) — whose value depends
    // on 8S+1 secret bits of m — and the attacker's best m-independent guess
    // (the S=0 winner, zero-extended) fails for every tested m.
    i = 0;
    while (i < 64) : (i += 1) {
        const run = try Run.init(5, 4000 + i);
        var got: [t_record_len]u8 = undefined;
        var tampered = run;
        tampered.va[1][0] +%= @as(V.Word, 1) << (@bitSizeOf(V.Word) - 1);
        tampered.ta[1][0] +%= @as(V.TagWord, 1) << (@bitSizeOf(V.Word) - 1);
        try testing.expectError(error.AnswerRejected, tampered.reconstruct(&got));
    }
}

test "ATTACK: querying past the database rejects — honest all-zero is indistinguishable from zeroing" {
    // The base layer defines index-in-domain-but-past-the-database as an
    // all-zero reconstruction. Here the presence word reconstructs to 0 ≠ m,
    // so the verified layer rejects — deliberately: accepting it would
    // re-open the coordinated-zeroing forgery as "maybe I queried a hole".
    const run = try Run.init(t_count + 2, 2011); // 12 <= 14 < 16: in-domain, unpopulated
    var got: [t_record_len]u8 = undefined;
    try testing.expectError(error.AnswerRejected, run.reconstruct(&got));
}

// ── EXACT: privacy is not degraded by the integrity layer ─────────────────

test "EXACT: bundled share length is a constant — independent of index AND of m" {
    // The first place the secret could leak is a length. share_len is
    // comptime, but assert the serialized bytes really are that long for
    // extreme indices and extreme m values.
    var wire: [V.share_len]u8 = undefined;
    for ([_]usize{ 0, 7, 15 }) |i| {
        for ([_]u64{ 1, 500, 999 }) |mt| {
            const q = try V.query(
                i,
                detMac(V.tag_word_len, mt),
                detSeed(mt * 4 + 0),
                detSeed(mt * 4 + 1),
                detSeed(mt * 4 + 2),
                detSeed(mt * 4 + 3),
            );
            V.shareToBytes(q.shares[0], &wire); // compile-time length check IS the assertion
            V.shareToBytes(q.shares[1], &wire);
        }
    }
}

test "EXACT: with seeds fixed, varying m changes ONLY the tag key's final output CW" {
    // Locates the m-dependence of a share, the way the base battery locates
    // the index-dependence of the level-1 seed CW: everything in the bundle
    // except the tag DPF's final output correction word is byte-identical
    // across m values. So m's entire footprint in a server's view is one
    // PRG-masked ring element — its secrecy is exactly the DPF's β-hiding,
    // resting on the PRG like the index's own privacy. Also asserts the final
    // CW is not m verbatim for these cases (it is β masked by the two leaves'
    // convert values — pseudorandom, not a plaintext copy).
    const s = [4]fss.prg.Seed{ detSeed(51), detSeed(52), detSeed(53), detSeed(54) };
    const index = 6;

    const qa = try V.query(index, detMac(V.tag_word_len, 61), s[0], s[1], s[2], s[3]);
    const qb = try V.query(index, detMac(V.tag_word_len, 62), s[0], s[1], s[2], s[3]);
    try testing.expect(qa.secret.m != qb.secret.m); // distinct m, or the test is vacuous

    for (0..2) |b| {
        var wa: [V.share_len]u8 = undefined;
        var wb: [V.share_len]u8 = undefined;
        V.shareToBytes(qa.shares[b], &wa);
        V.shareToBytes(qb.shares[b], &wb);
        // Everything up to the final tag CW is identical…
        const final_off = V.share_len - V.tag_word_len;
        try testing.expectEqualSlices(u8, wa[0..final_off], wb[0..final_off]);
        // …the final CW differs (it is where β lives)…
        try testing.expect(!std.mem.eql(u8, wa[final_off..], wb[final_off..]));
        // …and neither is the m value in the clear.
        var m_bytes_a: [V.tag_word_len]u8 = undefined;
        var m_bytes_b: [V.tag_word_len]u8 = undefined;
        std.mem.writeInt(V.TagWord, &m_bytes_a, qa.secret.m, .little);
        std.mem.writeInt(V.TagWord, &m_bytes_b, qb.secret.m, .little);
        try testing.expect(!std.mem.eql(u8, wa[final_off..], &m_bytes_a));
        try testing.expect(!std.mem.eql(u8, wb[final_off..], &m_bytes_b));
    }
}

test "EXACT: for a fixed tampering, the reject verdict is identical for EVERY queried index" {
    // The selective-failure question: does the abort event tell the adversary
    // anything about i? For any m-independent tampering the verdict is reject
    // for every index (up to the 2^(1−8S) soundness error — and these are
    // deterministic seeds, so here it is reject for ALL of them, asserted).
    // Contrast the hash-in-the-record design SPEC.md rejects, where the
    // adversary constructs a tampering that passes exactly when i == x* and
    // the abort bit is a 1-of-N index test.
    var got: [t_record_len]u8 = undefined;
    for (0..t_count) |i| {
        // Fresh seeds and m per query (as the protocol requires); only the
        // TAMPERING is held fixed across indices — that is the adversary's
        // fixed, m-independent strategy whose verdict must not vary with i.
        const run = try Run.init(i, 5000 + i);
        var tampered = run;
        tampered.va[0][0] +%= 1; // the fixed deviation
        try testing.expectError(error.AnswerRejected, tampered.reconstruct(&got));
    }
}

// ── SELF: geometry errors and boundary sweeps ─────────────────────────────

test "SELF: geometry errors are returned, never asserted" {
    const seeds = [4]fss.prg.Seed{ detSeed(0), detSeed(1), detSeed(2), detSeed(3) };
    const mac = detMac(V.tag_word_len, 9);

    try testing.expectError(
        error.IndexOutOfDomain,
        V.query(16, mac, seeds[0], seeds[1], seeds[2], seeds[3]),
    );
    // seed reuse anywhere in the four — including ACROSS the two channels,
    // where reuse would correlate the value and tag trees
    try testing.expectError(error.SeedReuse, V.query(0, mac, seeds[0], seeds[0], seeds[2], seeds[3]));
    try testing.expectError(error.SeedReuse, V.query(0, mac, seeds[0], seeds[1], seeds[0], seeds[3]));
    try testing.expectError(error.SeedReuse, V.query(0, mac, seeds[0], seeds[1], seeds[2], seeds[1]));

    const q = try V.query(0, mac, seeds[0], seeds[1], seeds[2], seeds[3]);
    var db_bytes: [t_count * t_record_len]u8 = undefined;
    fillDb(&db_bytes, t_record_len);
    const database = try Database.init(&db_bytes, t_record_len);

    var va: [2]V.Word = undefined;
    var ta: [3]V.TagWord = undefined;
    try testing.expectError(error.AnswerLengthMismatch, V.answer(0, q.shares[0], database, va[0..1], &ta));
    try testing.expectError(error.AnswerLengthMismatch, V.answer(0, q.shares[0], database, &va, ta[0..2]));

    try testing.expectError(error.ShareLengthMismatch, V.shareFromBytes(&[_]u8{0} ** 3));
    try testing.expectError(
        error.ShareLengthMismatch,
        V.shareFromBytes(&[_]u8{0} ** (V.share_len + 1)),
    );

    var rec: [t_record_len]u8 = undefined;
    try testing.expectError(
        error.AnswerLengthMismatch,
        V.reconstruct(q.secret, va[0..1], &va, &ta, &ta, &rec),
    );
    try testing.expectError(
        error.AnswerLengthMismatch,
        V.reconstruct(q.secret, &va, &va, ta[0..2], &ta, &rec),
    );
    var buf: [7]u8 = undefined;
    try testing.expectError(
        error.AnswerLengthMismatch,
        V.reconstructFromBytes(q.secret, &buf, &buf, &buf, &buf, &rec),
    );
}

test "SELF: exhaustive length sweep over the verified untrusted boundaries" {
    // The house discipline: exactly the right length accepted, every other
    // length rejected — both directions, so a reject-everything parser cannot
    // pass. Small ranges keep it fast; the stride logic has no size-dependent
    // branches beyond these.
    const W = Verified(3, 2, 2); // tag_word_len 4 keeps the sweep small
    const sec = W.Secret{ .m = 12345 | 1 };
    var v: [16]u8 = undefined;
    var t: [24]u8 = undefined;
    for (&v, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
    for (&t, 0..) |*b, i| b.* = @truncate(i * 11 + 3);
    var rec: [8]u8 = undefined;

    for (0..v.len + 1) |lv| for (0..t.len + 1) |lt| for (0..rec.len + 1) |rl| {
        const per = W.Value.answerWords(rl);
        const v_need = per * 2;
        const t_need = (per + 1) * 4;
        const r = W.reconstructFromBytes(sec, v[0..lv], v[0..lv], t[0..lt], t[0..lt], rec[0..rl]);
        if (lv == v_need and lt == t_need) {
            // geometry accepted; the MAC verdict on garbage bytes is
            // (almost always) a reject, but it must be THE reject error,
            // never a length error or a panic
            r catch |e| try testing.expectEqual(error.AnswerRejected, e);
        } else {
            try testing.expectError(error.AnswerLengthMismatch, r);
        }
    };

    var big: [W.share_len + 8]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = @truncate(i);
    for (0..big.len + 1) |n| {
        const r = W.shareFromBytes(big[0..n]);
        if (n == W.share_len) {
            _ = try r;
        } else {
            try testing.expectError(error.ShareLengthMismatch, r);
        }
    }

    var words: [4]W.TagWord = undefined;
    for (0..t.len + 1) |lt| for (0..words.len + 1) |ow| {
        const r = W.tagAnswerFromBytes(t[0..lt], words[0..ow]);
        if (lt == ow * 4) try r else try testing.expectError(error.AnswerLengthMismatch, r);
    };
}

// ── fuzz: the untrusted boundaries ────────────────────────────────────────

const FuzzVer = Verified(6, 4, 4);

fn fuzzVerShareFromBytes(_: void, smith: *std.testing.Smith) !void {
    var buf: [FuzzVer.share_len + 8]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = FuzzVer.shareFromBytes(buf[0..len]) catch return;
}
test "fuzz verified shareFromBytes never panics" {
    try std.testing.fuzz({}, fuzzVerShareFromBytes, .{});
}

fn fuzzVerAnswerHostileShare(_: void, smith: *std.testing.Smith) !void {
    // The whole verified server path on a hostile bundle: parse, then compute
    // BOTH channels' answers with arbitrary key material.
    var key_buf: [FuzzVer.share_len]u8 = undefined;
    smith.bytes(&key_buf);
    const share = FuzzVer.shareFromBytes(&key_buf) catch return;

    var db_bytes: [96]u8 = undefined;
    smith.bytes(&db_bytes);
    const record_len: usize = smith.valueRangeAtMost(u8, 1, 12);
    const record_count: usize = smith.valueRangeAtMost(u8, 1, 8);
    const database = Database.init(db_bytes[0 .. record_len * record_count], record_len) catch return;
    const party: u1 = @truncate(smith.valueRangeAtMost(u8, 0, 1));

    var va: [3]FuzzVer.Word = undefined;
    var ta: [4]FuzzVer.TagWord = undefined;
    const per = FuzzVer.Value.answerWords(record_len);
    try FuzzVer.answer(party, share, database, va[0..per], ta[0 .. per + 1]);

    var wire: [4 * FuzzVer.tag_word_len]u8 = undefined;
    try FuzzVer.tagAnswerToBytes(ta[0 .. per + 1], wire[0 .. (per + 1) * FuzzVer.tag_word_len]);
}
test "fuzz verified answer over a hostile share never panics" {
    try std.testing.fuzz({}, fuzzVerAnswerHostileShare, .{});
}

fn fuzzVerReconstruct(_: void, smith: *std.testing.Smith) !void {
    // Four independently attacker-chosen buffers with attacker-chosen lengths
    // plus an attacker-chosen record length and an attacker-chosen "secret" —
    // the client-side boundary. Must reject or verify, never panic.
    var v0: [64]u8 = undefined;
    var v1: [64]u8 = undefined;
    var t0: [96]u8 = undefined;
    var t1: [96]u8 = undefined;
    smith.bytes(&v0);
    smith.bytes(&v1);
    smith.bytes(&t0);
    smith.bytes(&t1);
    const lv0: usize = smith.valueRangeAtMost(u8, 0, v0.len);
    const lv1: usize = smith.valueRangeAtMost(u8, 0, v1.len);
    const lt0: usize = smith.valueRangeAtMost(u8, 0, t0.len);
    const lt1: usize = smith.valueRangeAtMost(u8, 0, t1.len);
    const record_len: usize = smith.valueRangeAtMost(u8, 0, 24);
    const m: FuzzVer.TagWord = smith.value(FuzzVer.TagWord) | 1;
    var rec: [24]u8 = undefined;

    FuzzVer.reconstructFromBytes(
        .{ .m = m },
        v0[0..lv0],
        v1[0..lv1],
        t0[0..lt0],
        t1[0..lt1],
        rec[0..record_len],
    ) catch return;
}
test "fuzz verified reconstruct never panics" {
    try std.testing.fuzz({}, fuzzVerReconstruct, .{});
}

test "Query.wipe destroys the client MAC secret, and a wiped Secret rejects" {
    var run = try Run.init(9, 4711);
    var got: [t_record_len]u8 = undefined;

    // Precondition: an honest run reconstructs, and `m` is really non-zero —
    // without this the assertion below could hold vacuously.
    try run.reconstruct(&got);
    try testing.expect(run.q.secret.m != 0);

    run.q.wipe();

    try testing.expectEqual(@as(V.TagWord, 0), run.q.secret.m);
    // A wiped secret cannot be reused by accident: m = 0 fails the presence
    // word, so every answer rejects.
    try testing.expectError(error.AnswerRejected, run.reconstruct(&got));
}
