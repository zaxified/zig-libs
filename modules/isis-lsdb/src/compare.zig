// SPDX-License-Identifier: MIT

//! The IS-IS newer-LSP comparison (ISO/IEC 10589 §7.3.16.1) — the correctness
//! core of the update process. Given an incoming LSP and the stored copy with
//! the **same LSP-ID**, decide whether the incoming one is newer, the same, or
//! older. This file is pure and std-only (no `isis` dep): it reasons over the
//! three header fields the comparison needs.
//!
//! ## The rule (ISO/IEC 10589 §7.3.16.1), oriented incoming-vs-stored
//!
//! The comparison is asymmetric — it is *not* a symmetric "larger checksum
//! wins" total order (a common misreading). The standard, and every production
//! implementation (verified against FRRouting `isis_lsp.c:lsp_compare`), orients
//! it against the **stored** copy:
//!
//! 1. **Sequence number** — a strictly greater sequence number is more recent.
//!    The comparison is **plain unsigned** 32-bit `>`/`<`, *not* serial-number
//!    (RFC 1982) arithmetic: ISO 10589 uses a linear sequence space
//!    `[1, 2^32-1]`; on exhaustion the origin purges the LSP and waits `MaxAge`
//!    before reusing sequence number 1, so wrap-around ordering never applies.
//! 2. **Equal sequence + a purge** — if the stored copy is active (non-zero
//!    Remaining Lifetime) and the incoming copy has a **zero** Remaining Lifetime
//!    (a purge), the incoming purge is more recent. A purge authoritatively
//!    overrides the active copy of the same sequence number.
//! 3. **Equal sequence + differing checksum against an active stored copy** —
//!    if the checksums differ and the stored copy is active, the incoming copy is
//!    treated as more recent. This is the ISO tie-break that forces a purge of a
//!    possibly-corrupt copy; it is deliberately conditioned on the *stored*
//!    copy's lifetime, matching the standard and FRR (a differing checksum is not
//!    an ordering by magnitude).
//! 4. Otherwise the two are **identical** (equal sequence, equal checksum, and
//!    matching zero-ness of Remaining Lifetime) or the incoming copy is **older**.

const std = @import("std");

/// The result of comparing an incoming LSP against the stored copy of the same
/// LSP-ID.
pub const Ordering = enum {
    /// The incoming LSP is more recent — accept and store it.
    newer,
    /// The two are identical (per §7.3.16.1) — acknowledge, do not re-flood.
    same,
    /// The incoming LSP is stale — the stored copy should be re-sent to the
    /// sender.
    older,
};

/// The three LSP header fields the newer-comparison reasons over. Deliberately
/// decoupled from `isis.Lsp` so the correctness core carries no dependency; the
/// store converts its entries (and decoded PDUs) into this.
pub const LspVersion = struct {
    sequence_number: u32,
    /// Remaining Lifetime **as it applies at the moment of comparison**. For a
    /// stored entry this is the value *aged down to `now`* (an entry aged to zero
    /// is a purge for tie-break purposes), not the value first received.
    remaining_lifetime: u16,
    checksum: u16,
};

/// ISO/IEC 10589 §7.3.16.1 newer-LSP comparison. Returns whether `incoming` is
/// newer / same / older than `stored` (both the same LSP-ID). See the file doc
/// comment for the exact rule and its provenance.
pub fn compare(incoming: LspVersion, stored: LspVersion) Ordering {
    // §7.3.16.1(a): identical iff equal sequence number, equal checksum, and
    // both Remaining Lifetimes zero or both non-zero. (Matches FRR LSP_EQUAL.)
    if (incoming.sequence_number == stored.sequence_number and
        incoming.checksum == stored.checksum and
        (incoming.remaining_lifetime == 0) == (stored.remaining_lifetime == 0))
    {
        return .same;
    }

    // §7.3.16.1(b): a strictly greater sequence number is more recent — plain
    // UNSIGNED comparison (linear space; not serial-number arithmetic).
    if (incoming.sequence_number > stored.sequence_number) return .newer;
    if (incoming.sequence_number < stored.sequence_number) return .older;

    // Equal sequence number from here on.

    // §7.3.16.1(c): an incoming purge (zero lifetime) overrides an active
    // (non-zero) stored copy.
    if (stored.remaining_lifetime != 0 and incoming.remaining_lifetime == 0) return .newer;

    // §7.3.16.1(d): a differing checksum against an active stored copy is
    // treated as more recent (forces a purge of the corrupt copy).
    //
    // PRECONDITION (now enforced): in ISO/IEC 10589 this clause is safe only
    // because §7.3.14.2 e) has *already* discarded any received LSP whose ISO
    // Fletcher checksum is invalid, so by the time (d) runs a differing checksum
    // can only mean "two well-formed copies of the same sequence number
    // disagree" — §7.3.16.2's LSP-confusion case, corruption to be purged.
    // `Lsdb.insert` performs that discard before calling here (`store.zig`,
    // "§7.3.14.2 receive validation"), using `isis.pdu.checkLspChecksum`. This
    // rule is a faithful transcription of the standard and must NOT be weakened;
    // if the discard is ever removed, (d) degrades back into a primitive that
    // replaces an LSP's content at an *equal* sequence number using arbitrary
    // checksum bytes (audit W2-28).
    //
    // What the discard does NOT buy: Fletcher is unkeyed, so an on-link forger
    // can compute a valid checksum for forged content. Against a deliberate
    // attacker the defence is authentication (RFC 5304/5310, `SPEC.md` §8), not
    // this clause.
    if (incoming.checksum != stored.checksum and stored.remaining_lifetime != 0) return .newer;

    // None of the "more recent" conditions hold and it is not identical → older.
    return .older;
}

/// A DELIBERATELY BROKEN comparison used solely by the module's permanent
/// positive control (CONVENTIONS/brief): it (a) compares sequence numbers as
/// **signed** integers and (b) treats an equal-sequence purge as **older**
/// rather than newer. If `compare` above ever regressed into either mistake, the
/// positive-control test would stop seeing a divergence and go RED. Never call
/// this outside that test.
pub fn compareBroken(incoming: LspVersion, stored: LspVersion) Ordering {
    const a: i32 = @bitCast(incoming.sequence_number);
    const b: i32 = @bitCast(stored.sequence_number);
    if (a > b) return .newer;
    if (a < b) return .older;
    // BROKEN: no purge-wins rule — equal sequence is just "same".
    if (incoming.checksum == stored.checksum) return .same;
    return if (incoming.checksum > stored.checksum) .newer else .older;
}

// ── tests: the comparison KAT table ──────────────────────────────────────────

const testing = std.testing;

fn v(seq: u32, life: u16, csum: u16) LspVersion {
    return .{ .sequence_number = seq, .remaining_lifetime = life, .checksum = csum };
}

test "KAT: higher sequence number wins (plain unsigned)" {
    try testing.expectEqual(Ordering.newer, compare(v(5, 1000, 0xAAAA), v(4, 1000, 0xAAAA)));
    try testing.expectEqual(Ordering.older, compare(v(4, 1000, 0xAAAA), v(5, 1000, 0xAAAA)));
    // The high-bit case that a SIGNED compare would get wrong: 0x8000_0000 is a
    // LARGER unsigned value than 0x7FFF_FFFF, so it is newer.
    try testing.expectEqual(Ordering.newer, compare(v(0x8000_0000, 1000, 1), v(0x7FFF_FFFF, 1000, 1)));
    try testing.expectEqual(Ordering.older, compare(v(0x7FFF_FFFF, 1000, 1), v(0x8000_0000, 1000, 1)));
    // Top of the sequence space is the newest of all.
    try testing.expectEqual(Ordering.newer, compare(v(0xFFFF_FFFF, 1000, 1), v(0xFFFF_FFFE, 1000, 1)));
}

test "KAT: equal sequence, incoming purge (lifetime 0) beats active stored" {
    try testing.expectEqual(Ordering.newer, compare(v(7, 0, 0x1234), v(7, 1000, 0x1234)));
    // The reverse: an active copy received while we hold a purge of the same
    // sequence is OLDER (we keep the purge).
    try testing.expectEqual(Ordering.older, compare(v(7, 1000, 0x1234), v(7, 0, 0x1234)));
}

test "KAT: equal sequence + equal purge-state → same (identical)" {
    // Both active, equal checksum → identical.
    try testing.expectEqual(Ordering.same, compare(v(7, 900, 0x1234), v(7, 1000, 0x1234)));
    // Both zero-lifetime purges, equal checksum → identical.
    try testing.expectEqual(Ordering.same, compare(v(7, 0, 0x1234), v(7, 0, 0x1234)));
}

test "KAT: equal sequence, differing checksum vs an active stored → newer (purge tie-break)" {
    try testing.expectEqual(Ordering.newer, compare(v(7, 1000, 0x2222), v(7, 1000, 0x1111)));
    // But when the STORED copy is a purge (zero lifetime), a differing checksum
    // does NOT make the incoming active copy newer — the purge still governs.
    try testing.expectEqual(Ordering.older, compare(v(7, 1000, 0x2222), v(7, 0, 0x1111)));
}

test "KAT: fully identical is same both directions" {
    const x = v(42, 500, 0xBEEF);
    try testing.expectEqual(Ordering.same, compare(x, x));
}

test "positive control: the broken comparison disagrees with the correct one" {
    // The purge case: correct says newer, broken (no purge rule) says same.
    const purge_in = v(7, 0, 0x1234);
    const active_stored = v(7, 1000, 0x1234);
    try testing.expectEqual(Ordering.newer, compare(purge_in, active_stored));
    try testing.expectEqual(Ordering.same, compareBroken(purge_in, active_stored));

    // The signed-sequence case: correct says newer (0x8000_0000 > 0x7FFF_FFFF
    // unsigned), broken (signed) says older.
    const hi = v(0x8000_0000, 1000, 1);
    const lo = v(0x7FFF_FFFF, 1000, 1);
    try testing.expectEqual(Ordering.newer, compare(hi, lo));
    try testing.expectEqual(Ordering.older, compareBroken(hi, lo));
}
