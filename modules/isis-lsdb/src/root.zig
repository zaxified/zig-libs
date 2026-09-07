// SPDX-License-Identifier: MIT
//! isis-lsdb — the IS-IS link-state database for one level (ISO/IEC 10589 §7.3):
//! store LSPs keyed by LSP-ID, apply the §7.3.16.1 newer-LSP comparison
//! (sequence-number → zero-lifetime-purge-wins → checksum tie-break), age
//! Remaining Lifetime on a time-injected `tick` and purge at `MaxAge`/
//! `ZeroAgeLifetime`, and maintain the per-interface SRM (flood) / SSN
//! (acknowledge) flag sets a flooding layer consumes — plus the CSNP/PSNP
//! database-synchronisation reconcile. Pure and single-owner: no threads, no
//! owned timers, no sockets; the caller supplies `now` and drives all I/O.
//! Builds on the sibling `isis` codec (the `Lsp` PDU + the LSP-Entries #9 TLV);
//! the flooding transmit loop and SPF are later consumers.
//!
//! ## Layers
//! - `compare` — the ISO §7.3.16.1 newer-LSP comparison (the correctness core),
//!   pure and std-only, with a deliberately-broken variant for the positive
//!   control.
//! - `store` — the `Lsdb`: the LSP-ID-keyed store, the update process
//!   (`insert` → comparison → SRM/SSN flags), time-injected aging + purge, the
//!   flooding-flag query surface, and the CSNP/PSNP reconcile.
//!
//! ## Time-injection contract
//! Identical to the sibling `isis-adj` FSM: the store never reads a clock. Every
//! entry point that cares about time takes a caller-supplied monotonic `now:
//! Time` (abstract ticks in the caller's own unit); a stored LSP's Remaining
//! Lifetime is *derived* from the `now` it was set at, so aging is a comparison,
//! never an owned countdown. Given the same `(ops, now)` stream the database and
//! its flag state are fully deterministic.
//!
//! ## Capacity / DoS bound
//! The store is bounded by `Config.capacity`: a new distinct LSP-ID is admitted
//! only while `count() < capacity`, else `insert` returns `error.DatabaseFull`
//! (unchanged). A flood of distinct LSP-IDs — or of SNP entries requesting LSPs
//! we lack — cannot grow the database without limit. Request placeholders (born
//! from *unauthenticated* SNP bytes) additionally get their own sub-budget
//! (`Config.request_capacity`) and their own timeout (`Config.request_timeout`),
//! so a hostile SNP can neither wedge nor starve the database. See `SPEC.md`.
//!
//! ## Receive-side self-defence (ISO/IEC 10589 §7.3.16.1)
//! IS-IS here is unauthenticated (auth is deferred, `SPEC.md` §8), so the update
//! process must defend itself against an on-link peer: a copy of **our own** LSP
//! received from a circuit is never accepted (the owner is told to re-originate
//! at `InsertResult.self_challenge + 1`), a local origination at
//! `max_sequence_number` is `error.SequenceExhausted` rather than a permanent
//! self-lockout, and a **received** LSP whose ISO Fletcher checksum does not
//! check out is discarded with `error.CorruptedLsp` before any comparison
//! (§7.3.14.2 e), the precondition §7.3.16.1(d)'s checksum tie-break assumes —
//! see `compare.zig`). Purges and locally originated LSPs are exempt, for the
//! reasons spelled out at `Lsdb.insert`. What remains missing is
//! **authentication** (RFC 5304/5310, `SPEC.md` §8): the checksum is unkeyed, so
//! it stops corruption and accidents, not a determined on-link forger.
//!
//! Provenance: clean-room from ISO/IEC 10589 §7.3; the §7.3.16.1 comparison was
//! cross-checked against FRRouting `isis_lsp.c:lsp_compare` for the (oriented)
//! purge/checksum tie-break. No third-party source ported. See /NOTICE (no entry
//! required — public specs).

const std = @import("std");
const isis = @import("isis");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "IS-IS link-state database — stores LSPs by LSP-ID, ISO 10589 §7.3 newer-LSP comparison, time-injected aging + MaxAge purge, per-interface SRM/SSN flooding flags; pure",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "ISO/IEC 10589 §7.3 link-state database (update process, SRM/SSN)",
    .deps = .{"isis"},
};

pub const compare = @import("compare.zig");
pub const store = @import("store.zig");

// ── the most-used surface, re-exported ───────────────────────────────────────
pub const Lsdb = store.Lsdb;
pub const Config = store.Config;
pub const Time = store.Time;
pub const LspId = store.LspId;
pub const InterfaceSet = store.InterfaceSet;
pub const InsertResult = store.InsertResult;
pub const InsertError = store.InsertError;
pub const AgeReport = store.AgeReport;
pub const EntryView = store.EntryView;
pub const Ordering = compare.Ordering;
pub const LspVersion = compare.LspVersion;
pub const compareVersions = compare.compare;
pub const max_interfaces = store.max_interfaces;
pub const max_sequence_number = store.max_sequence_number;

// ── integration test: two databases synchronise via CSNP + flooding ──────────

const testing = std.testing;

const sys_a: [6]u8 = .{ 0, 0, 0, 0, 0, 0xA };
const sys_b: [6]u8 = .{ 0, 0, 0, 0, 0, 0xB };

/// Stamps the ISO 10589 §7.3.11 checksum: the LSP A floods is *received* by B in
/// this test, and `insert`'s §7.3.14.2 gate discards an LSP that does not carry
/// one (the fixture previously used a `0xAAAA` placeholder, which is not a valid
/// checksum for these bytes and would now be refused — correctly).
fn buildLsp(buf: []u8, sys: [6]u8, lsp_num: u8, seq: u32, life: u16) []const u8 {
    var b = isis.pdu.LspBuilder.init(buf, .{
        .remaining_lifetime = life,
        .lsp_id = .{ sys[0], sys[1], sys[2], sys[3], sys[4], sys[5], 0, lsp_num },
        .sequence_number = seq,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    }) catch unreachable;
    return b.finishStamped();
}

// The end-to-end proof: B holds an LSP that A lacks. A learns of it from B's
// CSNP (→ SSN request), and A floods its own LSP that B's CSNP omitted. Then the
// actual LSP bytes A holds for flooding are fed into B via `insert`, and B
// stores them — the two databases converge, all through the `isis` wire codec.
test "two databases reconcile a CSNP and flood the delta into each other" {
    var a = Lsdb.init(testing.allocator, .{ .local_system_id = sys_a, .interface_count = 2, .capacity = 16 });
    defer a.deinit();
    var b = Lsdb.init(testing.allocator, .{ .local_system_id = sys_b, .interface_count = 2, .capacity = 16 });
    defer b.deinit();

    var buf: [128]u8 = undefined;

    // A originates its own LSP (floods out every circuit).
    _ = try a.insert(buildLsp(&buf, sys_a, 0, 1, 1000), null, 0);
    // B originates its own LSP.
    _ = try b.insert(buildLsp(&buf, sys_b, 0, 1, 1000), null, 0);

    // B sends A a CSNP summarising B's whole DB (just B's own LSP). A holds A's
    // LSP but not B's.
    var cbuf: [256]u8 = undefined;
    var out: [8]isis.tlvs.LspEntry = undefined;
    const n = b.summarise(&out, @splat(0), @splat(0xFF), 0);
    var cb = isis.pdu.CsnpBuilder.init(&cbuf, .{
        .source_id = .{ sys_b[0], sys_b[1], sys_b[2], sys_b[3], sys_b[4], sys_b[5], 0 },
        .start_lsp_id = @splat(0),
        .end_lsp_id = @splat(0xFF),
    }) catch unreachable;
    try isis.tlvs.addLspEntries(&cb.tlvs, out[0..n]);
    const cwire = cb.finish();

    const csnp = try isis.Csnp.decode(cwire);
    a.reconcileCsnp(csnp, 1, 1);

    // A now wants B's LSP (SSN request placeholder) and will flood its own LSP
    // (SRM on the CSNP circuit, since B's CSNP omitted A's LSP).
    const b_id: LspId = .{ sys_b[0], sys_b[1], sys_b[2], sys_b[3], sys_b[4], sys_b[5], 0, 0 };
    const a_id: LspId = .{ sys_a[0], sys_a[1], sys_a[2], sys_a[3], sys_a[4], sys_a[5], 0, 0 };
    try testing.expect(a.get(b_id, 1).?.is_request);
    try testing.expect(a.ssnSet(b_id).?.isSet(1));
    try testing.expect(a.srmSet(a_id).?.isSet(1));

    // A floods its SRM-queued LSP(s) out circuit 1 → feed them into B.
    var it = a.srmIterator(1);
    while (it.next()) |item| {
        _ = try b.insert(item.bytes, 0, 2);
    }
    // B now holds A's LSP → the databases have converged on A's LSP.
    try testing.expect(b.get(a_id, 2) != null);
    try testing.expectEqual(@as(u32, 1), b.get(a_id, 2).?.sequence_number);
}

// ── fuzz: hostile LSP bytes must never panic and never corrupt the store ──────

/// `testkit.fuzz`: `seedHex` for the corpora and `Cursor` for the SNP harness's
/// script. A corpus entry is not the frame — `Smith.slice` reads a
/// little-endian u32 length first.
const testkit = @import("testkit");
const seed = testkit.fuzz.seedHex;

/// LSP frames, in the format `Smith.slice` reads: the module's own golden LSP,
/// the goldens from the `isis` codec beside it, and the refusals `insert` has
/// to make. The largest is 66 octets, well inside the 128-octet buffer.
const insert_seeds = [_][]const u8{
    seed("831B010614010003001B0384AABBCCDDEEFF070380000007AEE7D7"), // this module's golden L2 LSP, checksum stamped
    seed("831B010612010003003C04B00000000000010000000000010000010104034900018101CC89046E6F646590100000030C0000001122330010C0000064"), // L1 LSP with SPB sub-TLVs
    seed("831B010612010003004204B0000000000002000000000001000001010403490001020C000A8080800000000000030016110000000000030000000A06FA040A000001"), // LSP with extended IS reachability
    seed("831B010612010003003C04B0000000000003000000000001000001901F0000011B80000000000000010000000080000010ABCD01C000000001010020"), // LSP with an SPB instance
    seed("831401061101000303000000000001001E0025018101CC0104034900010606001B213C9DF8"), // a LAN IIH: a well-formed PDU that is not an LSP
    seed("831B010614010003001B0384AABBCCDDEEFF0703800000070000D7"), // the same golden with its checksum zeroed: the §7.3.14.2 discard path
    seed("DEADBEEF99"), // not an IS-IS PDU
    seed("831B01061401"), // an LSP header cut off mid-way
    seed(""), // the empty buffer
};

test "fuzz: insert on hostile bytes never panics; a rejected LSP leaves the store unchanged" {
    try std.testing.fuzz({}, fuzzInsert, .{ .corpus = &insert_seeds });
}

/// Stamps a modeled L1 LSP header over the front of `buf`, so a buffer of
/// arbitrary octets reaches the body decoder instead of dying on the
/// discriminator. Returns false if the buffer is too short to hold one.
fn biasToLsp(buf: []u8) bool {
    if (buf.len < 27) return false;
    buf[0] = 0x83; // discriminator
    buf[1] = 27; // length indicator (LSP fixed header)
    buf[2] = 1; // version
    buf[3] = 0; // id length 0 => 6
    buf[4] = 18; // l1_lsp
    buf[5] = 1; // version
    return true;
}

/// The six ways one buffer of octets can arrive: raw / header-stamped /
/// header-stamped-with-a-valid-checksum, each as a local origination and as a
/// receive off an interface.
///
/// ⚠ These used to be `smith.value(bool)` draws made AFTER `smith.bytes(&buf)`
/// had eaten the input. With the input exhausted every one of them is false, so
/// outside `--fuzz` the bias never ran, the checksum was never stamped, and
/// `arrival` was always `null` — the LOCAL side of a gate whose whole point is
/// what happens on the RECEIVE side. Enumerated rather than drawn, they are all
/// six reachable from every seed and none of them depends on input the seed has
/// already spent.
fn driveInsert(db: *Lsdb, input: []const u8) !InsertTally {
    var tally: InsertTally = .{};
    var work: [128]u8 = undefined;
    var arm: u8 = 0;
    while (arm < 3) : (arm += 1) {
        @memcpy(work[0..input.len], input);
        const bytes = work[0..input.len];
        if (arm >= 1 and !biasToLsp(bytes)) continue;
        // ISO 10589 §7.3.14.2: a received LSP with a wrong Fletcher checksum is
        // discarded before the store is touched, so unstamped bytes almost
        // never get past `insert`'s front door. Arm 2 stamps a correct one to
        // keep the deep store path (compare → fill → flags) reachable; arms 0
        // and 1 keep fuzzing the discard path itself.
        if (arm == 2) _ = isis.pdu.stampLspChecksum(bytes) catch {};

        for ([_]?u8{ null, 0 }) |arrival| {
            const before = db.count();
            if (db.insert(bytes, arrival, 1)) |_| {
                // Accepted, ignored, or refused — all leave a coherent store.
                if (arrival == null) tally.local += 1 else tally.received += 1;
            } else |_| {
                // A decode error (or DatabaseFull) must be inert w.r.t. membership.
                try testing.expectEqual(before, db.count());
            }
        }
    }
    return tally;
}

/// How many of the six arms `insert` got all the way through, split by which
/// side of the §7.3.14.2 checksum gate they were on.
const InsertTally = struct { local: usize = 0, received: usize = 0 };

fn fuzzInsert(_: void, smith: *std.testing.Smith) !void {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_a, .interface_count = 2, .capacity = 32 });
    defer db.deinit();

    var buf: [128]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM —
    // so `len` was 0 on every input a seed can carry and `insert` was handed an
    // empty slice, which `header.decode` refuses on its first line.
    const len: usize = smith.slice(&buf);
    _ = try driveInsert(&db, buf[0..len]);
}

test "corpus: every insert seed reaches the store, and the counts are pinned" {
    // Three numbers. `nonempty` is the reach claim. `accepted` says the corpus
    // is not refusals only. `received` is the one the local arm cannot produce:
    // `insert(bytes, null, …)` is a local origination and skips the §7.3.14.2
    // checksum gate entirely, so a guard that only counted acceptances would
    // score full marks while the receive path — the untrusted one — went
    // unwalked. It was structurally 0 before: `arrival` was drawn after the
    // input was spent, so it was always `null`.
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var received: usize = 0;
    for (insert_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [128]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;

        var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_a, .interface_count = 2, .capacity = 32 });
        defer db.deinit();
        const tally = try driveInsert(&db, buf[0..len]);
        accepted += tally.local;
        received += tally.received;
    }
    try testing.expectEqual(insert_seeds.len - 1, nonempty); // the empty seed is deliberate
    try testing.expectEqual(@as(usize, 15), accepted);
    try testing.expectEqual(@as(usize, 7), received);
}

// ── fuzz: the SNP surface — the half `fuzzInsert` structurally cannot reach ───
//
// W2 A3 (F8) recorded that `insert` was the only fuzzed entry point, and that
// `reconcileCsnp` / `reconcilePsnp` / `summarise` — the whole SNP attack
// surface, and where this module's own CRIT lived — had never been fuzzed.
// The obstacle is a type, not a budget: `reconcileCsnp` takes an `isis.Csnp`,
// i.e. a PDU that has already decoded, and arbitrary octets do not decode into
// one (an 0x83 discriminator, the right PDU type, a length field that agrees,
// and a TLV region that walks). So the harness builds real CSNP/PSNP PDUs with
// the fuzzer choosing the parts a hostile neighbour chooses — the summary
// range, the LSP-Entry records, and a tail of arbitrary octets in the TLV
// region — and puts them through the wire codec before the store sees them.
test "fuzz: hostile CSNP/PSNP bytes never panic, and never grow the store past capacity" {
    try std.testing.fuzz({}, fuzzSnp, .{ .corpus = &snp_seeds });
}

const fuzz_capacity: usize = 16;

/// Flips up to three octets inside the TLV region of an already-built SNP,
/// leaving the fixed header intact so the PDU still decodes and the damage
/// lands where the TLV walk has to cope with it.
fn damageTlvRegion(cur: *testkit.fuzz.Cursor, pdu_bytes: []u8, fixed_len: usize) void {
    if (pdu_bytes.len <= fixed_len) return;
    const n = cur.ranged(0, 3);
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        const at = fixed_len + cur.ranged(0, @intCast(pdu_bytes.len - fixed_len - 1));
        pdu_bytes[at] ^= @intCast(cur.ranged(1, 255));
    }
}

/// What one run of the SNP harness actually did, so a guard can pin it.
const SnpTally = struct {
    /// Real LSPs put in the store before the SNP arrives.
    seeded: usize = 0,
    /// LSP-Entry records the built SNP carried.
    entries: usize = 0,
    /// Request placeholders the reconcile created — the DoS quantity.
    placeholders: usize = 0,
    /// Entries `summarise` returned afterwards.
    summarised: usize = 0,
    /// 1 if the run built a CSNP, 0 if a PSNP.
    csnp: usize = 0,
};

/// ⚠ Every choice here comes out of a `testkit.fuzz.Cursor` over ONE
/// `smith.slice` draw, not out of separate `Smith` draws.
///
/// `check-fuzz-reach` called this target R1 because its first draw was
/// `smith.valueRangeAtMost(u8, 0, 4)`, and it was right about the shape but the
/// module had already worked around the consequence: the `snpSeed` helper below
/// used to hand-assemble little-endian u64 words so that each scalar draw would
/// land inside its range. That worked, and it was unreadable — a corpus nobody
/// could review, whose four entries differed only in a 64-bit constant. A
/// cursor over the drawn bytes satisfies the gate honestly and turns each seed
/// into a script you can read. Under `--fuzz` the fuzzer still drives every
/// choice, because it drives the slice.
fn driveSnp(db: *Lsdb, cur: *testkit.fuzz.Cursor) !SnpTally {
    var tally: SnpTally = .{};

    // A few real LSPs, so the reconcile has something to compare against and
    // the completeness sweep has in-range entries to mark. An empty database
    // makes every SNP path a no-op — which is how this surface stays "covered"
    // while testing nothing.
    var lbuf: [128]u8 = undefined;
    const n_lsps = cur.ranged(0, 4);
    var k: u32 = 0;
    while (k < n_lsps) : (k += 1) {
        const sys: [6]u8 = .{ 0x00, 0x00, 0x00, 0x00, 0x00, cur.byte() };
        const lsp_num = cur.byte();
        const seq: u32 = cur.ranged(1, 8);
        const life = cur.word();
        _ = db.insert(buildLsp(&lbuf, sys, lsp_num, seq, life), null, 0) catch {};
    }
    tally.seeded = db.count();

    // The SNP's own TLV region: LSP-Entry records the script chooses, then an
    // arbitrary tail, so both the well-formed and the malformed walk are
    // driven. `reconcileCsnp` skips its completeness sweep when the walk hits
    // malformed bytes, and that branch is only reachable with the tail.
    var entries: [8]isis.tlvs.LspEntry = undefined;
    const n_entries = cur.ranged(0, entries.len);
    for (entries[0..n_entries]) |*e| {
        const life = cur.word();
        const id_a = cur.byte();
        const id_b = cur.byte();
        const id_c = cur.byte();
        const seq: u32 = cur.ranged(0, 8);
        e.* = .{
            .remaining_lifetime = life,
            .lsp_id = .{ 0, 0, 0, 0, 0, id_a, id_b, id_c },
            .sequence_number = seq,
            .checksum = cur.word(),
        };
    }
    tally.entries = n_entries;

    // An extra, unmodelled TLV, then a few byte flips confined to the TLV
    // region: `reconcileCsnp` skips its completeness sweep when the walk hits
    // malformed bytes, and that branch is only reachable if the walk can
    // actually break. The fixed header is left alone so the PDU still decodes.
    var extra: [48]u8 = undefined;
    for (&extra) |*b| b.* = cur.byte();
    const extra_len = cur.ranged(0, extra.len);
    const extra_code = cur.byte();

    const start_lsp_id: LspId = .{ 0, 0, 0, 0, 0, cur.byte(), cur.byte(), cur.byte() };
    const end_lsp_id: LspId = .{ 0, 0, 0, 0, 0, cur.byte(), cur.byte(), cur.byte() };
    const iface: u8 = @intCast(cur.ranged(0, 1));
    const now: Time = cur.word();
    const want_csnp = cur.byte() & 1 == 1;
    const source_last = cur.byte();

    var wire: [512]u8 = undefined;
    if (want_csnp) {
        tally.csnp = 1;
        var cb = isis.pdu.CsnpBuilder.init(&wire, .{
            .source_id = .{ 0, 0, 0, 0, 0, source_last, 0 },
            .start_lsp_id = start_lsp_id,
            .end_lsp_id = end_lsp_id,
        }) catch return tally;
        isis.tlvs.addLspEntries(&cb.tlvs, entries[0..n_entries]) catch {};
        cb.tlvs.addTlv(extra_code, extra[0..extra_len]) catch {};
        const len = cb.finish().len;
        damageTlvRegion(cur, wire[0..len], isis.pdu.csnp_fixed_len);
        const csnp = isis.Csnp.decode(wire[0..len]) catch return tally;
        db.reconcileCsnp(csnp, iface, now);
    } else {
        var pb = isis.pdu.PsnpBuilder.init(&wire, .{
            .source_id = .{ 0, 0, 0, 0, 0, source_last, 0 },
        }) catch return tally;
        isis.tlvs.addLspEntries(&pb.tlvs, entries[0..n_entries]) catch {};
        pb.tlvs.addTlv(extra_code, extra[0..extra_len]) catch {};
        const len = pb.finish().len;
        damageTlvRegion(cur, wire[0..len], isis.pdu.psnp_fixed_len);
        const psnp = isis.Psnp.decode(wire[0..len]) catch return tally;
        db.reconcilePsnp(psnp, iface, now);
    }

    // The DoS bound is the property an unauthenticated SNP threatens: entries
    // requesting LSPs we lack become request placeholders, and those must stay
    // inside the configured capacity no matter what the neighbour sends.
    if (db.count() > fuzz_capacity) return error.CapacityExceeded;
    if (db.count() < tally.seeded) return error.ReconcileDroppedRealLsps;
    tally.placeholders = db.count() - tally.seeded;

    // `summarise` on the same store: the caller's buffer bounds it, every
    // entry it returns lies in the requested range, and the result is sorted.
    var out: [6]isis.tlvs.LspEntry = undefined;
    const want = cur.ranged(0, out.len);
    const n = db.summarise(out[0..want], start_lsp_id, end_lsp_id, now);
    if (n > want) return error.SummariseOverranBuffer;
    tally.summarised = n;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (std.mem.order(u8, &out[i].lsp_id, &start_lsp_id) == .lt) return error.SummariseBelowRange;
        if (std.mem.order(u8, &out[i].lsp_id, &end_lsp_id) == .gt) return error.SummariseAboveRange;
        if (i > 0 and std.mem.order(u8, &out[i - 1].lsp_id, &out[i].lsp_id) != .lt)
            return error.SummariseNotSorted;
    }
    return tally;
}

fn fuzzSnp(_: void, smith: *std.testing.Smith) !void {
    var db = Lsdb.init(testing.allocator, .{
        .local_system_id = sys_a,
        .interface_count = 2,
        .capacity = fuzz_capacity,
    });
    defer db.deinit();

    var script: [256]u8 = undefined;
    const n: usize = smith.slice(&script);
    var cur: testkit.fuzz.Cursor = .{ .bytes = script[0..n] };
    _ = try driveSnp(&db, &cur);
}

/// Scripts for `driveSnp`, read octet by octet (a short one cycles). The first
/// octet is the LSP count, so the leading digit of each seed says how much of a
/// database the SNP arrives at.
const snp_seeds = [_][]const u8{
    // Four real LSPs (5 octets each: system-id tail, LSP number, sequence,
    // lifetime), then a CSNP whose four entries name LSPs we do NOT hold — so
    // every one becomes a request placeholder, the DoS quantity this harness
    // bounds.
    seed("04" ++ "0101000064" ++ "0202000064" ++ "0303000064" ++ "0404000064" ++
        "04" ++ "0064AABBCC010001" ++ "0064DDEEFF020002" ++ "0064112233030003" ++ "0064445566040004" ++
        ("00" ** 48) ++ "00" ++ "EE" ++ "000000" ++ "FFFFFF" ++ "00" ++ "0032" ++ "01" ++ "0A" ++ "00" ++ "06"),
    // The same store and the same entries, but a PSNP — the other arm of a
    // branch that used to hang on a `smith.value(bool)` drawn after the input
    // was spent, i.e. that was always false.
    seed("04" ++ "0101000064" ++ "0202000064" ++ "0303000064" ++ "0404000064" ++
        "04" ++ "0064AABBCC010001" ++ "0064DDEEFF020002" ++ "0064112233030003" ++ "0064445566040004" ++
        ("00" ** 48) ++ "00" ++ "EE" ++ "000000" ++ "FFFFFF" ++ "01" ++ "0032" ++ "02" ++ "0B" ++ "00" ++ "06"),
    // A CSNP summarising exactly the two LSPs the store already holds (entry
    // ids are `sys, 0, lsp_num`), so the completeness sweep runs with every
    // entry in range and nothing to request.
    seed("02" ++ "0100010064" ++ "0200010064" ++
        "02" ++ "0064010001" ++ "0001FFFF" ++ "0064020001" ++ "0001FFFF" ++
        ("00" ** 48) ++ "00" ++ "00" ++ "000000" ++ "FFFFFF" ++ "00" ++ "0032" ++ "01" ++ "0A" ++ "00" ++ "06"),
    // An empty store meeting a CSNP with a 40-octet unmodelled trailing TLV and
    // three byte flips inside the TLV region: the malformed-walk branch, where
    // `reconcileCsnp` skips its completeness sweep.
    seed("00" ++ "03" ++ "0064010203010001" ++ "0064040506020002" ++ "0064070809030003" ++
        ("5A" ** 48) ++ "28" ++ "7F" ++ "000000" ++ "FFFFFF" ++ "00" ++ "0032" ++ "01" ++ "0C" ++ "03" ++ "06"),
    // The degenerate script: every choice is its cursor minimum, which is
    // exactly the collapsed harness — kept as the "before" measurement.
    seed(""),
};

test "corpus: every SNP seed builds a real PDU, and the counts are pinned" {
    // Five numbers, built from the SAME `driveSnp` the harness runs — a guard
    // measuring a different corpus is not a guard.
    //
    // `seeded`, `entries` and `placeholders` are the ones the degenerate script
    // cannot produce: with every choice at its cursor minimum the store is
    // EMPTY, the SNP carries ZERO LSP-Entry records, and no request placeholder
    // is ever created — which is precisely what the old `snpSeed` corpus was
    // written to work around, and what an `accepted > 0` guard would have
    // reported as health. `csnps` pins that both arms of the CSNP/PSNP branch
    // are taken; the branch octet used to be `smith.value(bool)`.
    var seeded: usize = 0;
    var entries: usize = 0;
    var placeholders: usize = 0;
    var summarised: usize = 0;
    var csnps: usize = 0;
    for (snp_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var script: [256]u8 = undefined;
        const n: usize = smith.slice(&script);
        var cur: testkit.fuzz.Cursor = .{ .bytes = script[0..n] };

        var db = Lsdb.init(testing.allocator, .{
            .local_system_id = sys_a,
            .interface_count = 2,
            .capacity = fuzz_capacity,
        });
        defer db.deinit();
        const t = try driveSnp(&db, &cur);
        seeded += t.seeded;
        entries += t.entries;
        placeholders += t.placeholders;
        summarised += t.summarised;
        csnps += t.csnp;
    }
    try testing.expectEqual(@as(usize, 10), seeded);
    try testing.expectEqual(@as(usize, 13), entries);
    try testing.expectEqual(@as(usize, 13), placeholders);
    try testing.expectEqual(@as(usize, 8), summarised);
    try testing.expectEqual(@as(usize, 2), csnps);
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("compare.zig");
    _ = @import("store.zig");
    _ = @import("goldens.zig");
    _ = @import("bench.zig");
}
