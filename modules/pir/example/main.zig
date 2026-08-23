// SPDX-License-Identifier: MIT

//! What a client does with `pir`: fetch one record from a two-server
//! database without either server learning which index was requested.
//! This mirrors the module's own README/root.zig "SELF" end-to-end test —
//! the club membership records aren't fictional filler, they're exactly
//! the shape this protocol is FOR (a client that must not reveal which
//! member it looked up), just run here through the public API rather than
//! from inside the module's own test file.
//!
//! Everything stays in memory: no sockets, no two real servers — a real
//! deployment sends `shares[0]`/`shares[1]` to two servers that must not
//! collude (see the module doc comment's "Read this before using it"), and
//! this file plays both server roles itself to demonstrate the protocol
//! shape.
//!
//! Built against the PUBLISHED module (`@import("pir")`) plus its declared
//! dep `fss` (needed for `fss.prg.Seed`, the client's query-seed type).

const std = @import("std");
const pir = @import("pir");
const fss = @import("fss");

const records = [_][]const u8{
    "member-alice ", "member-bob   ", "member-carol ",
    "member-dave  ", "member-erin  ",
};
const record_len = 13;

pub fn main() !void {
    var flat: [records.len * record_len]u8 = undefined;
    for (records, 0..) |r, i| @memcpy(flat[i * record_len ..][0..record_len], r);

    const database = try pir.Database.init(&flat, record_len);
    const bits = try pir.domainBitsFor(database.count());
    std.debug.print("domain_bits for {d} records: {d}\n", .{ database.count(), bits });

    const P = pir.Pir(3, 16);
    const want_index = 2; // "member-carol " — the client's private choice

    // Client: two fresh seeds. Production: a CSPRNG, one pair per query —
    // reusing seeds across queries would let the two servers correlate
    // requests even without colluding on content.
    const s0: fss.prg.Seed = [_]u8{0x11} ** 16;
    const s1: fss.prg.Seed = [_]u8{0x22} ** 16;
    const shares = try P.query(want_index, s0, s1);
    std.debug.print("query built: two {d}-byte shares, one per server\n", .{P.share_len});

    // Servers: each holds ONE share and the full (replicated) database.
    // Neither share alone reveals `want_index` — that's the whole point.
    const n_words = P.answerWords(database.record_len);
    var a0: [1]P.Word = undefined;
    var a1: [1]P.Word = undefined;
    try P.answer(0, shares[0], database, a0[0..n_words]);
    try P.answer(1, shares[1], database, a1[0..n_words]);

    // Client: combine the two answers into the record. Neither answer
    // alone is readable; only their sum recovers anything.
    var got: [record_len]u8 = undefined;
    try P.reconstruct(a0[0..n_words], a1[0..n_words], &got);
    std.debug.print("recovered record: \"{s}\"\n", .{&got});
    if (!std.mem.eql(u8, &got, records[want_index])) return error.WrongRecord;

    // ── keyword lookup: the same protocol, addressed by name instead of
    // a raw index — a client looking up "bob" doesn't need to know his row
    // number. A miss is the SAME call as a hit (module doc: "PROVIDED the
    // caller never skips a query and never retries"), so this is safe to
    // call even when the caller isn't sure the keyword is present.
    //
    // `keywordIndex` is a public, total SHA-256-derived hash of the KEYWORD
    // ALONE — it has no knowledge of `records` above or their array
    // positions. A caller doing keyword lookup therefore must lay out ITS
    // OWN database as a hash table: each record lives at the slot
    // `keywordIndex(its own keyword)`, and carries that keyword as a key
    // field so a hit can be told apart, locally, from a colliding miss.
    // This is the exact convention pir.zig's own "SELF: keyword retrieval"
    // test pins — building a plain array indexed 0.. and hoping
    // `keywordIndex("carol")` happens to equal carol's array position would
    // only work by coincidence.
    const kw_key_len = 8;
    const kw_payload_len = 8;
    const kw_record_len = kw_key_len + kw_payload_len;
    const Member = struct { kw: []const u8, payload: []const u8 };
    const members = [_]Member{
        .{ .kw = "bob", .payload = "member-1" },
        .{ .kw = "carol", .payload = "member-2" },
    };
    var kw_bytes: [P.domain_size * kw_record_len]u8 = undefined;
    @memset(&kw_bytes, 0); // empty slots read back as an all-zero (clean) miss
    for (members) |m| {
        const ix = P.keywordIndex(m.kw);
        const rec = kw_bytes[ix * kw_record_len ..][0..kw_record_len];
        @memcpy(rec[0..m.kw.len], m.kw);
        @memcpy(rec[kw_key_len..][0..m.payload.len], m.payload);
    }
    std.debug.print("keywordIndex(\"bob\") = {d}\n", .{P.keywordIndex("bob")});

    const kw_database = try pir.Database.init(&kw_bytes, kw_record_len);
    const n_words_kw = P.answerWords(kw_record_len);
    // A second query needs its OWN fresh seed pair — reusing `s0`/`s1`
    // here would correlate this lookup with the one above.
    const s0b: fss.prg.Seed = [_]u8{0x33} ** 16;
    const s1b: fss.prg.Seed = [_]u8{0x44} ** 16;
    const kw_shares = try P.queryKeyword("carol", s0b, s1b);
    var kwa0: [1]P.Word = undefined;
    var kwa1: [1]P.Word = undefined;
    try P.answer(0, kw_shares[0], kw_database, kwa0[0..n_words_kw]);
    try P.answer(1, kw_shares[1], kw_database, kwa1[0..n_words_kw]);
    var kw_got: [kw_record_len]u8 = undefined;
    try P.reconstruct(kwa0[0..n_words_kw], kwa1[0..n_words_kw], &kw_got);
    std.debug.print("keyword lookup \"carol\" recovered: key=\"{s}\" payload=\"{s}\"\n", .{
        std.mem.sliceTo(kw_got[0..kw_key_len], 0), kw_got[kw_key_len..],
    });
    // The recovered key field must match the keyword asked for — this is
    // the local hit/collision check a real caller performs before trusting
    // the payload (a wrong key field here would mean a hash collision, not
    // a protocol bug).
    if (!std.mem.eql(u8, kw_got[0.."carol".len], "carol")) return error.WrongRecord;
    if (!std.mem.eql(u8, kw_got[kw_key_len..], "member-2")) return error.WrongRecord;
}
