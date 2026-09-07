// SPDX-License-Identifier: MIT
//! CompactSize (Bitcoin's varint) and Bitcoin transaction (de)serialization
//! — legacy and BIP144 segwit wire forms — over untrusted bytes.
//!
//! ## Ownership model
//!
//! `deserialize`/`deserializePartial` allocate exactly the dynamic-length
//! *arrays* this format needs (`vin`, `vout`, `witness`, and each witness's
//! `items`) — every `scriptSig`/`scriptPubKey`/witness-stack-item byte
//! slice is a **borrowed** view directly into the caller's `bytes` buffer,
//! never copied. This means: (1) `bytes` must outlive the returned
//! `Transaction`; (2) `Transaction.deinit` frees only the arrays it
//! allocated, never the borrowed byte content; (3) there is exactly one
//! copy of the wire bytes in memory at any time, which is also why hostile
//! `vin`/`vout`/witness counts can't be used to force a large upfront
//! allocation (see "Hostile-input handling" below) — the arrays grow only
//! as items are actually, successfully parsed out of `bytes`.
//!
//! ## Hostile-input handling
//!
//! Every decode path returns a typed error, never panics, on malformed,
//! truncated, or adversarial bytes. In particular: a `vin`/`vout`/witness
//! count is bounds-checked against the bytes actually remaining *before*
//! the parse loop runs (`error.TooManyItems`), and — even before that
//! check — the parse loop itself only ever grows its `ArrayList` one
//! successfully-parsed item at a time, so a hostile huge count can never by
//! itself force a large allocation: the very first out-of-bounds item read
//! fails closed with `error.Truncated`.
//!
//! ## Scope
//!
//! No Bitcoin Script interpretation: `scriptSig`/`scriptPubKey`/witness
//! items are opaque byte slices. Legacy (pre-BIP144) and BIP144 segwit
//! (marker `0x00` + flag `0x01` + witness stacks) wire forms only — no
//! other flag value is defined by any deployed spec, so `flag != 0x01`
//! after a `0x00` marker byte is `error.InvalidWitnessFlag`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const hash256 = @import("hash256.zig");
/// Test-only (`build.zig`'s `test_deps`, never `deps`): fuzz corpus framing.
const testkit = @import("testkit");
/// Test-only: the two reference transactions the fuzz corpus is cut from.
const kat_vectors = @import("tx_kat_vectors.zig");

// ── CompactSize (Bitcoin's varint) ──────────────────────────────────────────

pub const CompactSizeError = error{
    /// Fewer bytes remain than the encoding requires.
    Truncated,
    /// A value was encoded wider than necessary (e.g. `0xfd 0x0a 0x00` for
    /// the value 10, which fits the 1-byte form) — Bitcoin Core's
    /// `ReadCompactSize` rejects these; so does this decoder.
    NonMinimal,
};

pub const CompactSizeDecoded = struct { value: u64, consumed: usize };

/// The minimal CompactSize encoding length for `value`.
pub fn compactSizeLen(value: u64) usize {
    if (value < 0xfd) return 1;
    if (value <= 0xffff) return 3;
    if (value <= 0xffffffff) return 5;
    return 9;
}

/// Writes the minimal CompactSize encoding of `value` into `out`, returning
/// the written prefix. `out` must be at least `compactSizeLen(value)` bytes
/// (9 is always enough for any `u64`).
pub fn encodeCompactSize(value: u64, out: []u8) error{BufferTooSmall}![]u8 {
    const n = compactSizeLen(value);
    if (out.len < n) return error.BufferTooSmall;
    if (value < 0xfd) {
        out[0] = @intCast(value);
    } else if (value <= 0xffff) {
        out[0] = 0xfd;
        std.mem.writeInt(u16, out[1..3], @intCast(value), .little);
    } else if (value <= 0xffffffff) {
        out[0] = 0xfe;
        std.mem.writeInt(u32, out[1..5], @intCast(value), .little);
    } else {
        out[0] = 0xff;
        std.mem.writeInt(u64, out[1..9], value, .little);
    }
    return out[0..n];
}

/// Decodes one CompactSize from the front of `bytes`. Fail-closed on
/// truncation and on non-minimal encodings.
pub fn decodeCompactSize(bytes: []const u8) CompactSizeError!CompactSizeDecoded {
    if (bytes.len == 0) return error.Truncated;
    const first = bytes[0];
    if (first < 0xfd) return .{ .value = first, .consumed = 1 };
    if (first == 0xfd) {
        if (bytes.len < 3) return error.Truncated;
        const v = std.mem.readInt(u16, bytes[1..3], .little);
        if (v < 0xfd) return error.NonMinimal;
        return .{ .value = v, .consumed = 3 };
    }
    if (first == 0xfe) {
        if (bytes.len < 5) return error.Truncated;
        const v = std.mem.readInt(u32, bytes[1..5], .little);
        if (v <= 0xffff) return error.NonMinimal;
        return .{ .value = v, .consumed = 5 };
    }
    // first == 0xff
    if (bytes.len < 9) return error.Truncated;
    const v = std.mem.readInt(u64, bytes[1..9], .little);
    if (v <= 0xffffffff) return error.NonMinimal;
    return .{ .value = v, .consumed = 9 };
}

// ── transaction model ────────────────────────────────────────────────────────

pub const OutPoint = struct {
    /// Wire byte order (== internal digest order of the referenced tx's
    /// `txid()`, NOT the reversed order conventionally displayed).
    txid: [32]u8,
    vout: u32,
};

pub const TxIn = struct {
    prevout: OutPoint,
    /// Borrowed slice into the buffer `deserialize` was called with (see
    /// module doc comment). Opaque bytes — no Script parsing.
    script_sig: []const u8,
    sequence: u32,
};

pub const TxOut = struct {
    /// Satoshis. Signed to match Bitcoin Core's `CAmount` (`i64`) and to
    /// represent the SIGHASH_SINGLE legacy-sighash "null" marker (`-1`).
    value: i64,
    /// Borrowed slice (see module doc comment).
    script_pubkey: []const u8,
};

/// One input's witness stack. `items[i]` is a borrowed slice (see module
/// doc comment).
pub const Witness = struct {
    items: [][]const u8,
};

/// A parsed (or hand-built) Bitcoin transaction.
///
/// Invariant when `has_witness == true`: `witness.len == vin.len` (one
/// stack per input, wire-mandated by BIP144 — `deserialize` always
/// maintains this; `serializeSegwit` asserts it). When `has_witness ==
/// false`, `witness.len == 0`.
pub const Transaction = struct {
    version: i32,
    vin: []TxIn,
    vout: []TxOut,
    witness: []Witness,
    locktime: u32,
    /// Whether this transaction was parsed from (or should serialize as)
    /// the BIP144 segwit wire form (marker `0x00` + flag `0x01` + witness
    /// stacks) rather than the legacy form. `serialize` dispatches on this;
    /// `txid()` always uses the non-witness form regardless.
    has_witness: bool,

    /// Frees the arrays this `Transaction` owns (`vin`, `vout`, `witness`,
    /// and each witness's `items`). Does NOT free any `scriptSig`/
    /// `scriptPubKey`/witness-item bytes — those are borrowed from the
    /// buffer `deserialize` was called with (see module doc comment).
    pub fn deinit(self: *Transaction, allocator: Allocator) void {
        for (self.witness) |w| allocator.free(w.items);
        allocator.free(self.witness);
        allocator.free(self.vin);
        allocator.free(self.vout);
        self.* = undefined;
    }

    /// `sha256d` of the non-witness serialization (BIP141: "txid").
    pub fn txid(self: Transaction, allocator: Allocator) Allocator.Error![32]u8 {
        const ser = try serializeLegacy(allocator, self);
        defer allocator.free(ser);
        return hash256.sha256d(ser);
    }

    /// True if any vin actually carries witness data. Deliberately checked
    /// against content, not merely `has_witness`: the latter reflects
    /// whether a BIP144 marker/flag was present on the wire (or was set by
    /// hand), which `deserializePartial` now refuses to decouple from
    /// content (`error.SuperfluousWitnessRecord`) -- but `wtxid()` must
    /// hold its own invariant regardless of how a `Transaction` value was
    /// built, not only for ones that went through the decoder.
    pub fn hasWitnessData(self: Transaction) bool {
        if (!self.has_witness) return false;
        for (self.witness) |w| {
            if (w.items.len > 0) return true;
        }
        return false;
    }

    /// `sha256d` of the full segwit serialization (BIP141: "wtxid"). For a
    /// transaction with no witness data, `wtxid == txid` per BIP141.
    pub fn wtxid(self: Transaction, allocator: Allocator) Allocator.Error![32]u8 {
        if (!self.hasWitnessData()) return self.txid(allocator);
        const ser = try serializeSegwit(allocator, self);
        defer allocator.free(ser);
        return hash256.sha256d(ser);
    }
};

// ── deserialize ──────────────────────────────────────────────────────────────

pub const DecodeError = CompactSizeError || error{
    /// A `vin`/`vout`/witness count that cannot possibly fit in the bytes
    /// remaining, rejected before any per-item allocation is attempted.
    TooManyItems,
    /// A marker byte (`0x00`) was seen but the following flag byte was not
    /// `0x01` (the only flag any deployed spec defines).
    InvalidWitnessFlag,
    /// The BIP144 marker/flag says witness data follows, but every vin's
    /// witness stack decoded empty -- Core's "Superfluous witness record".
    SuperfluousWitnessRecord,
    /// `deserialize` (whole-buffer convenience) had bytes left over after a
    /// complete, valid transaction. `deserializePartial` never returns this.
    TrailingBytes,
};

pub const DeserializeError = DecodeError || Allocator.Error;

fn readBytes(bytes: []const u8, offset: *usize, n: u64) DecodeError![]const u8 {
    const remaining: u64 = bytes.len - offset.*;
    if (n > remaining) return error.Truncated;
    const nu: usize = @intCast(n);
    const s = bytes[offset.* .. offset.* + nu];
    offset.* += nu;
    return s;
}

fn readU32(bytes: []const u8, offset: *usize) DecodeError!u32 {
    const s = try readBytes(bytes, offset, 4);
    return std.mem.readInt(u32, s[0..4], .little);
}

fn readI32(bytes: []const u8, offset: *usize) DecodeError!i32 {
    const s = try readBytes(bytes, offset, 4);
    return std.mem.readInt(i32, s[0..4], .little);
}

fn readI64(bytes: []const u8, offset: *usize) DecodeError!i64 {
    const s = try readBytes(bytes, offset, 8);
    return std.mem.readInt(i64, s[0..8], .little);
}

fn readCompactSizeAdvance(bytes: []const u8, offset: *usize) DecodeError!u64 {
    const r = try decodeCompactSize(bytes[offset.*..]);
    offset.* += r.consumed;
    return r.value;
}

/// Decodes a CompactSize count, then rejects it outright
/// (`error.TooManyItems`) if it can't possibly fit in the bytes remaining
/// given every item takes at least `min_per_item` bytes — a cheap
/// fail-fast bound, defense-in-depth alongside the incremental per-item
/// append loop that is the real safety net (see module doc comment).
fn readCount(bytes: []const u8, offset: *usize, min_per_item: usize) DecodeError!u64 {
    const count = try readCompactSizeAdvance(bytes, offset);
    const remaining: u64 = bytes.len - offset.*;
    if (min_per_item > 0 and count > remaining / min_per_item) return error.TooManyItems;
    return count;
}

fn decodeTxIn(bytes: []const u8, offset: *usize) DecodeError!TxIn {
    const txid_bytes = try readBytes(bytes, offset, 32);
    var txid_arr: [32]u8 = undefined;
    @memcpy(&txid_arr, txid_bytes);
    const vout = try readU32(bytes, offset);
    const script_len = try readCompactSizeAdvance(bytes, offset);
    const script_sig = try readBytes(bytes, offset, script_len);
    const sequence = try readU32(bytes, offset);
    return .{
        .prevout = .{ .txid = txid_arr, .vout = vout },
        .script_sig = script_sig,
        .sequence = sequence,
    };
}

fn decodeTxOut(bytes: []const u8, offset: *usize) DecodeError!TxOut {
    const value = try readI64(bytes, offset);
    const script_len = try readCompactSizeAdvance(bytes, offset);
    const script_pubkey = try readBytes(bytes, offset, script_len);
    return .{ .value = value, .script_pubkey = script_pubkey };
}

fn decodeWitness(allocator: Allocator, bytes: []const u8, offset: *usize) DeserializeError!Witness {
    // Every witness item is at least 1 byte (its own CompactSize length
    // prefix, possibly encoding a zero-length item) -- min_per_item = 1.
    const count = try readCount(bytes, offset, 1);
    var items: std.ArrayList([]const u8) = .empty;
    errdefer items.deinit(allocator);
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const len = try readCompactSizeAdvance(bytes, offset);
        const item = try readBytes(bytes, offset, len);
        try items.append(allocator, item);
    }
    return .{ .items = try items.toOwnedSlice(allocator) };
}

pub const PartialResult = struct { tx: Transaction, consumed: usize };

/// Decodes one transaction from the front of `bytes`, returning how many
/// bytes it consumed (so a caller can decode several transactions packed
/// back-to-back, e.g. from a `getdata`/block payload). See `deserialize`
/// for a whole-buffer convenience that rejects trailing bytes.
pub fn deserializePartial(allocator: Allocator, bytes: []const u8) DeserializeError!PartialResult {
    var offset: usize = 0;
    const version = try readI32(bytes, &offset);

    // BIP144 marker/flag disambiguation: a legacy vin-count CompactSize of
    // 0x00 is indistinguishable, byte-for-byte, from the segwit marker --
    // Bitcoin Core (and every other implementation) resolves this by
    // requiring a following flag byte whenever the very next byte is 0x00.
    var has_witness = false;
    if (offset >= bytes.len) return error.Truncated;
    if (bytes[offset] == 0x00) {
        if (offset + 1 >= bytes.len) return error.Truncated;
        const flag = bytes[offset + 1];
        if (flag != 0x01) return error.InvalidWitnessFlag;
        has_witness = true;
        offset += 2;
    }

    // Real vin/vout are at least 41/9 bytes each (32+4+1+4 / 8+1) -- a
    // tighter fail-fast bound than min_per_item=1 would give.
    const vin_count = try readCount(bytes, &offset, 41);
    var vin: std.ArrayList(TxIn) = .empty;
    errdefer vin.deinit(allocator);
    {
        var i: u64 = 0;
        while (i < vin_count) : (i += 1) try vin.append(allocator, try decodeTxIn(bytes, &offset));
    }

    const vout_count = try readCount(bytes, &offset, 9);
    var vout: std.ArrayList(TxOut) = .empty;
    errdefer vout.deinit(allocator);
    {
        var i: u64 = 0;
        while (i < vout_count) : (i += 1) try vout.append(allocator, try decodeTxOut(bytes, &offset));
    }

    var witness: std.ArrayList(Witness) = .empty;
    errdefer {
        for (witness.items) |w| allocator.free(w.items);
        witness.deinit(allocator);
    }
    if (has_witness) {
        var i: u64 = 0;
        while (i < vin.items.len) : (i += 1) try witness.append(allocator, try decodeWitness(allocator, bytes, &offset));

        // BIP144: the marker/flag says "witness data follows", so there
        // must actually BE some -- Core's `UnserializeTransaction` throws
        // "Superfluous witness record" for a segwit-marked tx whose every
        // vin's witness stack is empty (`if (flags & 1) { ... if
        // (!tx.HasWitness()) throw; }`). Without this, a decoder accepts a
        // wire form Core rejects, and `wtxid()` would key off the flag
        // rather than actual content and diverge from `txid()` for a
        // transaction that carries no witness data at all -- contradicting
        // BIP141 (wave-2 audit finding `bitcointx` F3).
        var any_witness_data = false;
        for (witness.items) |w| {
            if (w.items.len > 0) {
                any_witness_data = true;
                break;
            }
        }
        if (!any_witness_data) return error.SuperfluousWitnessRecord;
    }

    const locktime = try readU32(bytes, &offset);

    return .{
        .tx = .{
            .version = version,
            .vin = try vin.toOwnedSlice(allocator),
            .vout = try vout.toOwnedSlice(allocator),
            .witness = try witness.toOwnedSlice(allocator),
            .locktime = locktime,
            .has_witness = has_witness,
        },
        .consumed = offset,
    };
}

/// `deserializePartial`, requiring the whole of `bytes` to be exactly one
/// transaction (`error.TrailingBytes` if not).
pub fn deserialize(allocator: Allocator, bytes: []const u8) DeserializeError!Transaction {
    var r = try deserializePartial(allocator, bytes);
    if (r.consumed != bytes.len) {
        r.tx.deinit(allocator);
        return error.TrailingBytes;
    }
    return r.tx;
}

// ── serialize ────────────────────────────────────────────────────────────────

fn appendCompactSize(buf: *std.ArrayList(u8), allocator: Allocator, value: u64) Allocator.Error!void {
    var tmp: [9]u8 = undefined;
    const w = encodeCompactSize(value, &tmp) catch unreachable; // tmp is always big enough
    try buf.appendSlice(allocator, w);
}

fn appendU32LE(buf: *std.ArrayList(u8), allocator: Allocator, v: u32) Allocator.Error!void {
    var tmp: [4]u8 = undefined;
    std.mem.writeInt(u32, &tmp, v, .little);
    try buf.appendSlice(allocator, &tmp);
}

fn appendI32LE(buf: *std.ArrayList(u8), allocator: Allocator, v: i32) Allocator.Error!void {
    var tmp: [4]u8 = undefined;
    std.mem.writeInt(i32, &tmp, v, .little);
    try buf.appendSlice(allocator, &tmp);
}

fn appendI64LE(buf: *std.ArrayList(u8), allocator: Allocator, v: i64) Allocator.Error!void {
    var tmp: [8]u8 = undefined;
    std.mem.writeInt(i64, &tmp, v, .little);
    try buf.appendSlice(allocator, &tmp);
}

fn appendTxIn(buf: *std.ArrayList(u8), allocator: Allocator, vin: TxIn) Allocator.Error!void {
    try buf.appendSlice(allocator, &vin.prevout.txid);
    try appendU32LE(buf, allocator, vin.prevout.vout);
    try appendCompactSize(buf, allocator, vin.script_sig.len);
    try buf.appendSlice(allocator, vin.script_sig);
    try appendU32LE(buf, allocator, vin.sequence);
}

fn appendTxOut(buf: *std.ArrayList(u8), allocator: Allocator, vout: TxOut) Allocator.Error!void {
    try appendI64LE(buf, allocator, vout.value);
    try appendCompactSize(buf, allocator, vout.script_pubkey.len);
    try buf.appendSlice(allocator, vout.script_pubkey);
}

/// The non-witness serialization (no marker/flag/witness stacks) -- the
/// form `Transaction.txid` hashes, and the wire form of any pre-segwit
/// transaction.
pub fn serializeLegacy(allocator: Allocator, tx: Transaction) Allocator.Error![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try appendI32LE(&buf, allocator, tx.version);
    try appendCompactSize(&buf, allocator, tx.vin.len);
    for (tx.vin) |vin| try appendTxIn(&buf, allocator, vin);
    try appendCompactSize(&buf, allocator, tx.vout.len);
    for (tx.vout) |vout| try appendTxOut(&buf, allocator, vout);
    try appendU32LE(&buf, allocator, tx.locktime);
    return buf.toOwnedSlice(allocator);
}

/// The BIP144 segwit serialization (marker `0x00` + flag `0x01` + a
/// witness stack per input) -- the form `Transaction.wtxid` hashes.
/// Asserts `tx.witness.len == tx.vin.len` (see `Transaction`'s doc
/// comment); that invariant is a caller-construction contract, not
/// untrusted-input territory (this function serializes an already-typed
/// `Transaction`, not raw bytes).
pub fn serializeSegwit(allocator: Allocator, tx: Transaction) Allocator.Error![]u8 {
    std.debug.assert(tx.witness.len == tx.vin.len);
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try appendI32LE(&buf, allocator, tx.version);
    try buf.append(allocator, 0x00);
    try buf.append(allocator, 0x01);
    try appendCompactSize(&buf, allocator, tx.vin.len);
    for (tx.vin) |vin| try appendTxIn(&buf, allocator, vin);
    try appendCompactSize(&buf, allocator, tx.vout.len);
    for (tx.vout) |vout| try appendTxOut(&buf, allocator, vout);
    for (tx.witness) |w| {
        try appendCompactSize(&buf, allocator, w.items.len);
        for (w.items) |item| {
            try appendCompactSize(&buf, allocator, item.len);
            try buf.appendSlice(allocator, item);
        }
    }
    try appendU32LE(&buf, allocator, tx.locktime);
    return buf.toOwnedSlice(allocator);
}

/// Dispatches to `serializeSegwit` or `serializeLegacy` per
/// `tx.has_witness` -- the "round-trip" form matching whatever wire shape
/// `tx` was parsed from (or is declared to represent).
pub fn serialize(allocator: Allocator, tx: Transaction) Allocator.Error![]u8 {
    return if (tx.has_witness) serializeSegwit(allocator, tx) else serializeLegacy(allocator, tx);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "CompactSize round-trip across every width boundary" {
    const cases = [_]u64{ 0, 1, 0xfc, 0xfd, 0xfe, 0xffff, 0x10000, 0xffffffff, 0x100000000, std.math.maxInt(u64) };
    for (cases) |v| {
        var buf: [9]u8 = undefined;
        const enc = try encodeCompactSize(v, &buf);
        try testing.expectEqual(compactSizeLen(v), enc.len);
        const dec = try decodeCompactSize(enc);
        try testing.expectEqual(v, dec.value);
        try testing.expectEqual(enc.len, dec.consumed);
    }
}

test "CompactSize rejects non-minimal encodings" {
    // 0xfd-prefixed value 0x00fc (252) fits the 1-byte form.
    try testing.expectError(error.NonMinimal, decodeCompactSize(&.{ 0xfd, 0xfc, 0x00 }));
    // 0xfd-prefixed value exactly 0xfd is the minimal boundary -- accepted.
    try testing.expectEqual(@as(u64, 0xfd), (try decodeCompactSize(&.{ 0xfd, 0xfd, 0x00 })).value);
    // 0xfe-prefixed value 0xffff fits the 3-byte (0xfd) form.
    try testing.expectError(error.NonMinimal, decodeCompactSize(&.{ 0xfe, 0xff, 0xff, 0x00, 0x00 }));
    // 0xff-prefixed value 0xffffffff fits the 5-byte (0xfe) form.
    try testing.expectError(error.NonMinimal, decodeCompactSize(&.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }));
}

test "CompactSize rejects truncation at every prefix width" {
    try testing.expectError(error.Truncated, decodeCompactSize(&.{}));
    try testing.expectError(error.Truncated, decodeCompactSize(&.{ 0xfd, 0x00 }));
    try testing.expectError(error.Truncated, decodeCompactSize(&.{ 0xfe, 0x00, 0x00, 0x00 }));
    try testing.expectError(error.Truncated, decodeCompactSize(&.{ 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }));
}

fn buildMinimalLegacyTx(allocator: Allocator) Allocator.Error![]u8 {
    // 1-in-1-out legacy tx: version=1, 1 vin (32-byte zero prevtxid, vout=0,
    // empty scriptSig, sequence=0xffffffff), 1 vout (value=5000, empty
    // scriptPubKey), locktime=0. Self-authored (not an official vector) --
    // used only to exercise round-trip/allocation plumbing.
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try appendI32LE(&buf, allocator, 1);
    try appendCompactSize(&buf, allocator, 1);
    try buf.appendSlice(allocator, &([_]u8{0} ** 32));
    try appendU32LE(&buf, allocator, 0);
    try appendCompactSize(&buf, allocator, 0);
    try appendU32LE(&buf, allocator, 0xffffffff);
    try appendCompactSize(&buf, allocator, 1);
    try appendI64LE(&buf, allocator, 5000);
    try appendCompactSize(&buf, allocator, 0);
    try appendU32LE(&buf, allocator, 0);
    return buf.toOwnedSlice(allocator);
}

test "legacy tx: deserialize -> serialize is byte-exact (self-consistency round-trip)" {
    const allocator = testing.allocator;
    const raw = try buildMinimalLegacyTx(allocator);
    defer allocator.free(raw);

    var tx = try deserialize(allocator, raw);
    defer tx.deinit(allocator);
    try testing.expectEqual(false, tx.has_witness);
    try testing.expectEqual(@as(usize, 1), tx.vin.len);
    try testing.expectEqual(@as(usize, 1), tx.vout.len);
    try testing.expectEqual(@as(usize, 0), tx.witness.len);

    const reser = try serialize(allocator, tx);
    defer allocator.free(reser);
    try testing.expectEqualSlices(u8, raw, reser);
}

fn buildMinimalSegwitTx(allocator: Allocator) Allocator.Error![]u8 {
    // 1-in-1-out segwit tx: marker/flag, 1 vin, 1 vout, one 2-item witness
    // stack on the sole input, locktime=0. Self-authored, round-trip only.
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try appendI32LE(&buf, allocator, 2);
    try buf.append(allocator, 0x00);
    try buf.append(allocator, 0x01);
    try appendCompactSize(&buf, allocator, 1);
    try buf.appendSlice(allocator, &([_]u8{0xaa} ** 32));
    try appendU32LE(&buf, allocator, 1);
    try appendCompactSize(&buf, allocator, 0);
    try appendU32LE(&buf, allocator, 0xffffffff);
    try appendCompactSize(&buf, allocator, 1);
    try appendI64LE(&buf, allocator, 1234567);
    try appendCompactSize(&buf, allocator, 0);
    // witness: 1 input, 2 items
    try appendCompactSize(&buf, allocator, 2);
    try appendCompactSize(&buf, allocator, 3);
    try buf.appendSlice(allocator, &[_]u8{ 1, 2, 3 });
    try appendCompactSize(&buf, allocator, 0);
    try appendU32LE(&buf, allocator, 0);
    return buf.toOwnedSlice(allocator);
}

fn buildSuperfluousWitnessTx(allocator: Allocator) Allocator.Error![]u8 {
    // Same shape as `buildMinimalSegwitTx` (1-in-1-out, BIP144 marker/flag)
    // but the sole input's witness stack has ZERO items instead of two --
    // the marker says "witness data follows" and none actually does.
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    try appendI32LE(&buf, allocator, 2);
    try buf.append(allocator, 0x00);
    try buf.append(allocator, 0x01);
    try appendCompactSize(&buf, allocator, 1);
    try buf.appendSlice(allocator, &([_]u8{0xaa} ** 32));
    try appendU32LE(&buf, allocator, 1);
    try appendCompactSize(&buf, allocator, 0);
    try appendU32LE(&buf, allocator, 0xffffffff);
    try appendCompactSize(&buf, allocator, 1);
    try appendI64LE(&buf, allocator, 1234567);
    try appendCompactSize(&buf, allocator, 0);
    // witness: 1 input, 0 items -- the superfluous-record shape.
    try appendCompactSize(&buf, allocator, 0);
    try appendU32LE(&buf, allocator, 0);
    return buf.toOwnedSlice(allocator);
}

test "F3 regression: a BIP144-marked tx whose witness stacks are all empty is rejected, not accepted as a wtxid != txid transaction" {
    // Before the fix, `deserializePartial` accepted this wire form and
    // `wtxid()` keyed off `has_witness` (set purely from the marker/flag),
    // so it would diverge from `txid()` despite the transaction carrying no
    // actual witness data -- contradicting this file's own documented
    // BIP141 invariant "wtxid == txid" for a witness-free transaction.
    // Bitcoin Core's `UnserializeTransaction` throws "Superfluous witness
    // record" for exactly this shape (wave-2 audit finding `bitcointx` F3).
    const allocator = testing.allocator;
    const raw = try buildSuperfluousWitnessTx(allocator);
    defer allocator.free(raw);
    try testing.expectError(error.SuperfluousWitnessRecord, deserialize(allocator, raw));
}

test "F3 regression: wtxid() honors actual witness content, not just the has_witness flag" {
    // Defense in depth beyond the decoder-level reject above: a
    // hand-constructed `Transaction` with `has_witness = true` but an empty
    // witness stack must still satisfy `wtxid() == txid()`.
    const allocator = testing.allocator;
    var vin = [_]TxIn{.{
        .prevout = .{ .txid = [_]u8{0xaa} ** 32, .vout = 1 },
        .script_sig = &.{},
        .sequence = 0xffffffff,
    }};
    var vout = [_]TxOut{.{ .value = 1234567, .script_pubkey = &.{} }};
    var empty_items = [_][]const u8{};
    var witness = [_]Witness{.{ .items = &empty_items }}; // present but empty
    const tx: Transaction = .{
        .version = 2,
        .vin = &vin,
        .vout = &vout,
        .witness = &witness,
        .locktime = 0,
        .has_witness = true, // flag says "segwit", content says otherwise
    };
    try testing.expectEqual(false, tx.hasWitnessData());
    const the_txid = try tx.txid(allocator);
    const the_wtxid = try tx.wtxid(allocator);
    try testing.expectEqualSlices(u8, &the_txid, &the_wtxid);
}

test "segwit tx: deserialize -> serialize is byte-exact, and txid != wtxid" {
    const allocator = testing.allocator;
    const raw = try buildMinimalSegwitTx(allocator);
    defer allocator.free(raw);

    var tx = try deserialize(allocator, raw);
    defer tx.deinit(allocator);
    try testing.expectEqual(true, tx.has_witness);
    try testing.expectEqual(@as(usize, 1), tx.witness.len);
    try testing.expectEqual(@as(usize, 2), tx.witness[0].items.len);

    const reser = try serialize(allocator, tx);
    defer allocator.free(reser);
    try testing.expectEqualSlices(u8, raw, reser);

    const the_txid = try tx.txid(allocator);
    const the_wtxid = try tx.wtxid(allocator);
    try testing.expect(!std.mem.eql(u8, &the_txid, &the_wtxid));
}

test "hostile: truncated tx (fewer bytes than the fixed 4-byte version field) fails closed" {
    try testing.expectError(error.Truncated, deserialize(testing.allocator, &.{ 0x01, 0x00 }));
}

test "hostile: truncated tx cut mid-scriptSig fails closed with Truncated (not TooManyItems -- enough bytes remain for the TooManyItems bound check to pass, so this exercises the deeper per-field truncation path)" {
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try appendI32LE(&buf, allocator, 1);
    try appendCompactSize(&buf, allocator, 1); // vin count = 1
    try buf.appendSlice(allocator, &([_]u8{0} ** 32));
    try appendU32LE(&buf, allocator, 0);
    try appendCompactSize(&buf, allocator, 20); // scriptSig declared as 20 bytes...
    try buf.appendSlice(allocator, &([_]u8{0xab} ** 10)); // ...but only 10 are actually present
    try testing.expectError(error.Truncated, deserialize(allocator, buf.items));
}

test "hostile: vin count claiming far more inputs than remain fails closed with TooManyItems, no OOM/panic" {
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try appendI32LE(&buf, allocator, 1);
    // Claim 2^32-ish inputs immediately followed by nothing.
    try appendCompactSize(&buf, allocator, 0xffffffff);
    try testing.expectError(error.TooManyItems, deserialize(allocator, buf.items));
}

test "hostile: vout count claiming more outputs than remain fails closed with TooManyItems" {
    // vin count is deliberately 1 (not 0): a leading 0x00 count byte is
    // indistinguishable from the segwit marker (module doc comment), so a
    // "legacy, 0 inputs" buffer isn't expressible here -- a real,
    // complete single input keeps this test about the VOUT bound only.
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try appendI32LE(&buf, allocator, 1);
    try appendCompactSize(&buf, allocator, 1); // vin count = 1
    try buf.appendSlice(allocator, &([_]u8{0} ** 32));
    try appendU32LE(&buf, allocator, 0);
    try appendCompactSize(&buf, allocator, 0); // empty scriptSig
    try appendU32LE(&buf, allocator, 0xffffffff);
    try appendCompactSize(&buf, allocator, 0xffffffff); // hostile vout count
    try testing.expectError(error.TooManyItems, deserialize(allocator, buf.items));
}

test "hostile: non-minimal CompactSize as the vin count is rejected" {
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try appendI32LE(&buf, allocator, 1);
    // 0xfd 0x00 0x00 encodes 0 the non-minimal way.
    try buf.appendSlice(allocator, &[_]u8{ 0xfd, 0x00, 0x00 });
    try testing.expectError(error.NonMinimal, deserialize(allocator, buf.items));
}

test "hostile: marker 0x00 with an unrecognized flag byte is rejected" {
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try appendI32LE(&buf, allocator, 1);
    try buf.appendSlice(allocator, &[_]u8{ 0x00, 0x02 }); // marker ok, flag != 0x01
    try testing.expectError(error.InvalidWitnessFlag, deserialize(allocator, buf.items));
}

test "hostile: trailing bytes after a complete, valid transaction are rejected" {
    const allocator = testing.allocator;
    const raw = try buildMinimalLegacyTx(allocator);
    defer allocator.free(raw);
    var padded: std.ArrayList(u8) = .empty;
    defer padded.deinit(allocator);
    try padded.appendSlice(allocator, raw);
    try padded.append(allocator, 0xff);
    try testing.expectError(error.TrailingBytes, deserialize(allocator, padded.items));
}

test "deserializePartial reports the exact byte count consumed (no forced whole-buffer match)" {
    const allocator = testing.allocator;
    const raw = try buildMinimalLegacyTx(allocator);
    defer allocator.free(raw);
    var padded: std.ArrayList(u8) = .empty;
    defer padded.deinit(allocator);
    try padded.appendSlice(allocator, raw);
    try padded.append(allocator, 0xff);

    var r = try deserializePartial(allocator, padded.items);
    defer r.tx.deinit(allocator);
    try testing.expectEqual(raw.len, r.consumed);
}

// ── fuzz: deserializePartial never panics on arbitrary attacker bytes ────
//
// A Bitcoin transaction is consensus data straight off the p2p wire (or a
// PSBT's `UNSIGNED_TX`/`(NON_)WITNESS_UTXO` value -- see `psbt`, which
// calls this same function on a caller-supplied slice). Plain uniform
// bytes would die almost immediately on the leading CompactSize
// vin-count's own truncation check; this harness biases every
// CompactSize-shaped field (vin/vout/script-length/witness-item counts)
// toward small single-byte forms most of the time -- explores the
// TooManyItems/per-field-Truncated boundary the module doc comment claims
// ("a hostile huge count can never by itself force a large allocation")
// -- with fully random bytes the rest, so the multi-byte 0xfd/0xfe/0xff
// CompactSize forms and the marker/flag/witness disambiguation also get
// hit.
/// ⚠ 256 was too small for the module's OWN reference transactions: the
/// smaller of the two `tx_kat_vectors` fixtures is 275 octets and the largest
/// row of `tx_wire_vectors` (Bitcoin Core's `tx_valid.json`/`tx_invalid.json`)
/// is 1911. A seed longer than the buffer does not arrive truncated, it reads
/// back EMPTY -- `Smith.slice` checks the declared length against
/// `rangeAtMost(0, buf.len)` and falls back to the range minimum -- so at 256
/// not one real Bitcoin transaction this module owns could ever have passed
/// through its own decoder harness.
pub const fuzz_tx_buf_len = 2048;

/// A corpus entry for a `smith.slice` harness whose later draws are knobs:
/// `testkit.fuzz.seedInto` frames the transaction, and `tail` supplies the
/// little-endian `u64` words the ranged draws after it read. ⛔ Without the
/// tail every knob is dead on a corpus replay -- `Smith` returns the range
/// MINIMUM once the input is short, so `which` would be 0 on every seed and
/// the branch that leaves a real frame alone would never run.
fn TxCorpus(comptime cap: usize, comptime store_len: usize) type {
    return struct {
        store: [store_len]u8 = undefined,
        used: usize = 0,
        entries: [cap][]const u8 = undefined,
        n: usize = 0,

        fn push(self: *@This(), frame: []const u8, tail: []const u64) void {
            const start = self.used;
            var at = start + testkit.fuzz.seedInto(self.store[start..], frame).len;
            for (tail) |w| {
                std.mem.writeInt(u64, self.store[at..][0..8], w, .little);
                at += 8;
            }
            self.entries[self.n] = self.store[start..at];
            self.used = at;
            self.n += 1;
        }
    };
}

/// Comptime hex, so the wire fixtures can be spelled the way the vectors file
/// spells them.
fn hexBytes(comptime h: []const u8) [h.len / 2]u8 {
    @setEvalBranchQuota(@max(1000, 60 * h.len));
    var out: [h.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, h) catch unreachable;
    return out;
}

const kat_legacy = hexBytes(kat_vectors.legacy_raw_tx_hex);
const kat_segwit = hexBytes(kat_vectors.segwit_raw_tx_hex);

/// Test-only: `root.zig`'s decode->sighash harness is cut from the same two
/// reference transactions, and cannot import `tx_kat_vectors` through a path
/// that would make it a production dependency of `tx.zig`'s consumers.
pub const fuzz_kat_legacy = kat_legacy;
pub const fuzz_kat_segwit = kat_segwit;

/// `which == 3` leaves the frame untouched; the other three are the original
/// bias, which only matters for arbitrary bytes.
const DeserCorpus = TxCorpus(10, 10 * (4 + fuzz_tx_buf_len + 16));

fn buildDeserCorpus(self: *DeserCorpus) []const []const u8 {
    self.push(&kat_legacy, &.{3}); // the 275-octet legacy KAT, untouched
    self.push(&kat_segwit, &.{3}); // the 343-octet BIP144 KAT, marker + witness
    self.push(kat_legacy[0..100], &.{3}); // truncated mid-scriptSig
    self.push(&kat_legacy, &.{ 0, 2 }); // vin count rewritten to 2: one input short
    self.push(&kat_legacy, &.{1}); // vin count rewritten to the segwit marker
    // ⛔ Arm 2 — the one that writes an ARBITRARY octet — had never been
    // selected: measured 2026-09-08, the `which` histogram over the eight
    // seeds above was 1 / 1 / **0** / 4, and the guard below only asserted
    // that arms 0, 1 and 3 had been seen. `0xfd` is the CompactSize prefix
    // that claims a two-octet count, so the vin count is then read from the
    // two octets of a real transaction that follow it.
    self.push(&kat_legacy, &.{ 2, 0xfd });
    self.push(&kat_segwit, &.{ 2, 0xff }); // and the eight-octet CompactSize prefix
    self.push(kat_segwit[0..5], &.{3}); // version + marker and nothing after
    self.push(&[_]u8{ 0x01, 0x00, 0x00 }, &.{3}); // shorter than the version field
    self.push("", &.{3}); // and the input this target used to run for ever
    return self.entries[0..self.n];
}

test "fuzz: deserializePartial never panics on arbitrary bytes" {
    var corpus: DeserCorpus = .{};
    try testing.fuzz({}, fuzzDeserializePartial, .{ .corpus = buildDeserCorpus(&corpus) });
}

fn fuzzDeserializePartial(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;
    var buf: [fuzz_tx_buf_len]u8 = undefined;
    // ⚠ One `smith.slice` call, never `bytes` followed by a ranged length. The
    // latter drew `len == 0` on every input this target ever ran outside
    // `--fuzz`: a ranged draw reads eight octets as a little-endian u64 and
    // returns the range MINIMUM when fewer than eight remain, and `bytes` had
    // already eaten them. With no corpus either, the one input was `""` -- so
    // `deserializePartial` had never decoded a transaction here.
    const len: usize = smith.slice(&buf);

    // Bias the byte right after the 4-byte version field (where a
    // CompactSize vin-count, or the 0x00 segwit marker, is read) toward
    // small counts / the marker byte / random -- so that ARBITRARY bytes
    // reach the three code paths instead of dying on the vin-count
    // truncation check. `else` leaves the frame alone, which is what a seed
    // carrying a real transaction needs; the knob is readable because every
    // seed carries a `u64` tail word for it.
    if (len > 4) {
        buf[4] = switch (smith.valueRangeAtMost(u8, 0, 3)) {
            0 => smith.valueRangeAtMost(u8, 0, 4), // small vin count
            1 => 0x00, // segwit marker
            2 => smith.value(u8),
            else => buf[4],
        };
    }

    var r = deserializePartial(allocator, buf[0..len]) catch return;
    defer r.tx.deinit(allocator);
}

test "corpus: deserializePartial seeds reach the decoder, and the counts are pinned" {
    const allocator = testing.allocator;
    var corpus: DeserCorpus = .{};
    var nonempty: usize = 0;
    var accepted: usize = 0;
    // ⛔ The number an empty input cannot produce, and that `accepted > 0`
    // would not have held up: total inputs walked out of the decoded
    // transactions. It only moves when a seed's own octets reach the vin loop.
    var vin_total: usize = 0;
    var witness_seen: usize = 0;
    var which_hist = [_]usize{0} ** 4;
    for (buildDeserCorpus(&corpus)) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [fuzz_tx_buf_len]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        // Mirrors the harness exactly, `if (len > 4)` included: a guard that
        // draws where the harness does not is measuring a different corpus.
        if (len > 4) {
            const which = smith.valueRangeAtMost(u8, 0, 3);
            which_hist[which] += 1;
            buf[4] = switch (which) {
                0 => smith.valueRangeAtMost(u8, 0, 4),
                1 => 0x00,
                2 => smith.value(u8),
                else => buf[4],
            };
        }
        var r = deserializePartial(allocator, buf[0..len]) catch continue;
        defer r.tx.deinit(allocator);
        accepted += 1;
        vin_total += r.tx.vin.len;
        if (r.tx.has_witness) witness_seen += 1;
    }
    try testing.expectEqual(corpus.n - 1, nonempty); // all but the empty seed
    try testing.expectEqual(@as(usize, 2), accepted);
    try testing.expectEqual(@as(usize, 3), vin_total);
    try testing.expectEqual(@as(usize, 1), witness_seen);
    // The knob is alive on a corpus replay, which is the half a seed alone
    // cannot fix. ⛔ But "alive" is not "varying": measured 2026-09-08 the
    // histogram was 1 / 1 / **0** / 4, and the three booleans that used to
    // stand here could not say so — a boolean cannot distinguish "arm 2 never
    // ran" from "arm 2 was not asserted". Pinned as counts, all four arms.
    try testing.expectEqualSlices(usize, &[_]usize{ 1, 1, 2, 4 }, &which_hist);
}
