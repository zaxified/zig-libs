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

    /// `sha256d` of the full segwit serialization (BIP141: "wtxid"). For a
    /// transaction with no witness data, `wtxid == txid` per BIP141.
    pub fn wtxid(self: Transaction, allocator: Allocator) Allocator.Error![32]u8 {
        if (!self.has_witness) return self.txid(allocator);
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
test "fuzz: deserializePartial never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDeserializePartial, .{});
}

fn fuzzDeserializePartial(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);

    // Bias the byte right after the 4-byte version field (where a
    // CompactSize vin-count, or the 0x00 segwit marker, is read) toward
    // small counts / the marker byte / random -- three-way split so all
    // three code paths (legacy-small-count, segwit-marker, arbitrary
    // multi-byte-form) get real traffic.
    if (buf.len > 4) {
        buf[4] = switch (smith.valueRangeAtMost(u8, 0, 2)) {
            0 => smith.valueRangeAtMost(u8, 0, 4), // small vin count
            1 => 0x00, // segwit marker
            else => smith.value(u8),
        };
    }
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);

    var r = deserializePartial(allocator, buf[0..len]) catch return;
    defer r.tx.deinit(allocator);
}
