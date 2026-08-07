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

test "fuzz: insert on hostile bytes never panics; a rejected LSP leaves the store unchanged" {
    try std.testing.fuzz({}, fuzzInsert, .{});
}

fn fuzzInsert(_: void, smith: *std.testing.Smith) !void {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_a, .interface_count = 2, .capacity = 32 });
    defer db.deinit();

    var buf: [128]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, @intCast(buf.len));
    const input = buf[0..len];

    // Bias toward a valid-looking LSP header so deeper paths are exercised.
    if (len >= 27 and smith.value(bool)) {
        buf[0] = 0x83; // discriminator
        buf[1] = 27; // length indicator (LSP fixed header)
        buf[2] = 1; // version
        buf[3] = 0; // id length 0 => 6
        buf[4] = 18; // l1_lsp
        buf[5] = 1; // version
        // ISO 10589 §7.3.14.2: a received LSP with a wrong Fletcher checksum is
        // discarded before the store is touched, so random bytes would now
        // almost never get past `insert`'s front door. Stamp a correct checksum
        // on some of them to keep the deep store path (compare → fill → flags)
        // as reachable as it was before that gate existed, while the unstamped
        // half keeps fuzzing the discard path itself.
        if (smith.value(bool)) _ = isis.pdu.stampLspChecksum(input) catch {};
    }

    // Both sides of the gate: `null` is a local origination (checksum exempt),
    // an interface index is a receive (checksum enforced).
    const arrival: ?u8 = if (smith.value(bool)) null else smith.valueRangeAtMost(u8, 0, 1);

    const before = db.count();
    if (db.insert(input, arrival, 1)) |_| {
        // Accepted, ignored, or refused — all leave a coherent store.
    } else |_| {
        // A decode error (or DatabaseFull) must be inert w.r.t. membership.
        try testing.expectEqual(before, db.count());
    }
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
    try std.testing.fuzz({}, fuzzSnp, .{ .corpus = snp_seeds });
}

const fuzz_capacity: usize = 16;

/// Flips up to three octets inside the TLV region of an already-built SNP,
/// leaving the fixed header intact so the PDU still decodes and the damage
/// lands where the TLV walk has to cope with it.
fn damageTlvRegion(smith: *std.testing.Smith, pdu_bytes: []u8, fixed_len: usize) void {
    if (pdu_bytes.len <= fixed_len) return;
    const n = smith.valueRangeAtMost(u8, 0, 3);
    var i: u8 = 0;
    while (i < n) : (i += 1) {
        const at = fixed_len + smith.index(pdu_bytes.len - fixed_len);
        pdu_bytes[at] ^= smith.valueRangeAtMost(u8, 1, 255);
    }
}

fn fuzzSnp(_: void, smith: *std.testing.Smith) !void {
    var db = Lsdb.init(testing.allocator, .{
        .local_system_id = sys_a,
        .interface_count = 2,
        .capacity = fuzz_capacity,
    });
    defer db.deinit();

    // A few real LSPs, so the reconcile has something to compare against and
    // the completeness sweep has in-range entries to mark. An empty database
    // makes every SNP path a no-op — which is how this surface stays "covered"
    // while testing nothing.
    var lbuf: [128]u8 = undefined;
    const n_lsps = smith.valueRangeAtMost(u8, 0, 4);
    var k: u8 = 0;
    while (k < n_lsps) : (k += 1) {
        const sys: [6]u8 = .{ 0x00, 0x00, 0x00, 0x00, 0x00, smith.value(u8) };
        _ = db.insert(
            buildLsp(&lbuf, sys, smith.value(u8), smith.valueRangeAtMost(u32, 1, 8), smith.value(u16)),
            null,
            0,
        ) catch {};
    }
    const seeded = db.count();

    // The SNP's own TLV region: LSP-Entry records the fuzzer chooses, then an
    // arbitrary tail, so both the well-formed and the malformed walk are
    // driven. `reconcileCsnp` skips its completeness sweep when the walk hits
    // malformed bytes, and that branch is only reachable with the tail.
    var entries: [8]isis.tlvs.LspEntry = undefined;
    const n_entries = smith.valueRangeAtMost(u8, 0, entries.len);
    for (entries[0..n_entries]) |*e| {
        e.* = .{
            .remaining_lifetime = smith.value(u16),
            .lsp_id = .{
                0,               0,               0,               0, 0,
                smith.value(u8), smith.value(u8), smith.value(u8),
            },
            .sequence_number = smith.valueRangeAtMost(u32, 0, 8),
            .checksum = smith.value(u16),
        };
    }
    // An extra, unmodelled TLV, then a few byte flips confined to the TLV
    // region: `reconcileCsnp` skips its completeness sweep when the walk hits
    // malformed bytes, and that branch is only reachable if the walk can
    // actually break. The fixed header is left alone so the PDU still decodes.
    var extra: [48]u8 = undefined;
    smith.bytes(&extra);
    const extra_len = smith.valueRangeAtMost(u8, 0, extra.len);
    const extra_code = smith.value(u8);

    const start_lsp_id: LspId = .{
        0, 0, 0, 0, 0, smith.value(u8), smith.value(u8), smith.value(u8),
    };
    const end_lsp_id: LspId = .{
        0, 0, 0, 0, 0, smith.value(u8), smith.value(u8), smith.value(u8),
    };
    const iface = smith.valueRangeAtMost(u8, 0, 1);
    const now: Time = smith.value(u16);

    var wire: [512]u8 = undefined;
    if (smith.value(bool)) {
        var cb = isis.pdu.CsnpBuilder.init(&wire, .{
            .source_id = .{ 0, 0, 0, 0, 0, smith.value(u8), 0 },
            .start_lsp_id = start_lsp_id,
            .end_lsp_id = end_lsp_id,
        }) catch return;
        isis.tlvs.addLspEntries(&cb.tlvs, entries[0..n_entries]) catch {};
        cb.tlvs.addTlv(extra_code, extra[0..extra_len]) catch {};
        const len = cb.finish().len;
        damageTlvRegion(smith, wire[0..len], isis.pdu.csnp_fixed_len);
        const csnp = isis.Csnp.decode(wire[0..len]) catch return;
        db.reconcileCsnp(csnp, iface, now);
    } else {
        var pb = isis.pdu.PsnpBuilder.init(&wire, .{
            .source_id = .{ 0, 0, 0, 0, 0, smith.value(u8), 0 },
        }) catch return;
        isis.tlvs.addLspEntries(&pb.tlvs, entries[0..n_entries]) catch {};
        pb.tlvs.addTlv(extra_code, extra[0..extra_len]) catch {};
        const len = pb.finish().len;
        damageTlvRegion(smith, wire[0..len], isis.pdu.psnp_fixed_len);
        const psnp = isis.Psnp.decode(wire[0..len]) catch return;
        db.reconcilePsnp(psnp, iface, now);
    }

    // The DoS bound is the property an unauthenticated SNP threatens: entries
    // requesting LSPs we lack become request placeholders, and those must stay
    // inside the configured capacity no matter what the neighbour sends.
    if (db.count() > fuzz_capacity) return error.CapacityExceeded;
    if (db.count() < seeded) return error.ReconcileDroppedRealLsps;

    // `summarise` on the same store: the caller's buffer bounds it, every
    // entry it returns lies in the requested range, and the result is sorted.
    var out: [6]isis.tlvs.LspEntry = undefined;
    const want = smith.valueRangeAtMost(u8, 0, out.len);
    const n = db.summarise(out[0..want], start_lsp_id, end_lsp_id, now);
    if (n > want) return error.SummariseOverranBuffer;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (std.mem.order(u8, &out[i].lsp_id, &start_lsp_id) == .lt) return error.SummariseBelowRange;
        if (std.mem.order(u8, &out[i].lsp_id, &end_lsp_id) == .gt) return error.SummariseAboveRange;
        if (i > 0 and std.mem.order(u8, &out[i - 1].lsp_id, &out[i].lsp_id) != .lt)
            return error.SummariseNotSorted;
    }
}

/// See `iec61850/src/goose.zig`: without `--fuzz` the runner feeds only
/// `options.corpus` plus one empty input, and an empty input makes every draw
/// return its range minimum — an empty database and an empty SNP. `Smith`
/// reads one little-endian `u64` per scalar draw and discards a word outside
/// that draw's range, so the words are kept small.
fn snpSeed(comptime bits: u64, comptime n: usize) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    var i: usize = 0;
    var w: u6 = 0;
    while (i + 8 <= n) : (i += 8) {
        std.mem.writeInt(u64, out[i..][0..8], (bits >> w) & 0x03, .little);
        w +%= 1;
    }
    @memset(out[i..], 0);
    return out;
}

const snp_seeds: []const []const u8 = &.{
    &snpSeed(0x9E37_79B9_7F4A_7C15, 512),
    &snpSeed(0x0123_4567_89AB_CDEF, 512),
    &snpSeed(0xF0E1_D2C3_B4A5_9687, 512),
    &snpSeed(0xFFFF_FFFF_FFFF_FFFF, 512),
};

test {
    std.testing.refAllDecls(@This());
    _ = @import("compare.zig");
    _ = @import("store.zig");
    _ = @import("goldens.zig");
}
