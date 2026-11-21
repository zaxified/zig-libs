// SPDX-License-Identifier: MIT
//! BOLT#3 commitment and HTLC transaction construction: the funding, `to_local`,
//! `to_remote`, anchor and HTLC scripts, fee and trimming arithmetic, the
//! commitment transaction with its BIP69+CLTV output order, the second-stage
//! HTLC-timeout / HTLC-success transactions, the BIP143 signature hashes and the
//! witness layouts.
//!
//! Everything here is public data (public keys, amounts, hashes): the caller derives
//! the keys (`derivePublicKey`, `deriveRevocationPublicKey`), signs the digests this
//! module hands out with its own funding / HTLC keys, and passes the signatures back
//! to be placed in the witness. Nothing is secret, so nothing is constant-time.
//!
//! ## Channel types
//!
//! `Format` selects what BOLT#3 varies by channel type: `anchors` (option_anchors:
//! 1124-weight commitments, 330 sat anchors, one-block CSV on `to_remote` and the
//! HTLC scripts, HTLC transactions with sequence 1) and `zero_fee_commitments`
//! (version 3 transactions, no fees, the P2A shared anchor). They are independent
//! because the standard keeps them so: the HTLC scripts and the `to_remote` output
//! follow `anchors` alone; the fee-free HTLC transactions and
//! SIGHASH_SINGLE|ANYONECANPAY follow either.
//!
//! ## Ownership
//!
//! `buildCommitment` and `buildHtlcTx` allocate everything (the arrays and the
//! scripts the transaction borrows) from one arena that the result owns: call
//! `deinit` on the result, never `Transaction.deinit` on its `tx`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const bitcointx = @import("bitcointx");
const ripemd160 = @import("ripemd160");

/// Fixed size of an anchor output (option_anchors).
pub const anchor_amount_sat: i64 = 330;
/// The standard dust limit of the P2A `shared_anchor`: the most its amount takes from the fee.
pub const shared_anchor_max_sat: i64 = 240;

/// `SIGHASH_ALL`.
pub const sighash_all: u32 = 0x01;
/// `SIGHASH_SINGLE | SIGHASH_ANYONECANPAY`, the HTLC transactions' type under anchors / zero-fee commitments.
pub const sighash_single_anyonecanpay: u32 = 0x83;

pub const Format = struct {
    anchors: bool = false,
    zero_fee_commitments: bool = false,

    fn version(self: Format) i32 {
        return if (self.zero_fee_commitments) 3 else 2;
    }

    fn htlcFeesZero(self: Format) bool {
        return self.anchors or self.zero_fee_commitments;
    }
};

pub const Error = Allocator.Error || error{
    /// An amount does not fit a signed 64-bit satoshi value.
    AmountOutOfRange,
    /// `buildHtlcTx`: the output index is not an HTLC output of the commitment.
    NotAnHtlcOutput,
};

// ── fees ────────────────────────────────────────────────────────────────

/// Expected weight of an HTLC-timeout transaction (BOLT#3 §Fee Calculation); the fee is 0 under anchors / zero-fee.
pub const htlc_timeout_weight: u64 = 663;
/// Expected weight of an HTLC-success transaction.
pub const htlc_success_weight: u64 = 703;

/// The fee of an HTLC-timeout (offered) or HTLC-success (received) transaction in satoshis.
pub fn htlcTxFee(feerate_per_kw: u32, offered: bool, format: Format) u64 {
    if (format.htlcFeesZero()) return 0;
    return @as(u64, feerate_per_kw) * (if (offered) htlc_timeout_weight else htlc_success_weight) / 1000;
}

/// The base fee of a commitment transaction with `untrimmed_htlcs` HTLC outputs, in satoshis:
/// `feerate_per_kw * (724 | 1124 + 172 * n) / 1000`, 0 under zero-fee commitments.
pub fn commitmentFee(feerate_per_kw: u32, untrimmed_htlcs: usize, format: Format) u64 {
    if (format.zero_fee_commitments) return 0;
    const weight: u64 = (if (format.anchors) @as(u64, 1124) else 724) + 172 * @as(u64, untrimmed_htlcs);
    return @as(u64, feerate_per_kw) * weight / 1000;
}

// ── commitment number obscuring ─────────────────────────────────────────

/// The 48-bit factor the commitment number is XORed with: the lower 48 bits of
/// `SHA256(opener payment_basepoint || accepter payment_basepoint)`.
pub fn obscuringFactor(opener_payment_basepoint: [33]u8, accepter_payment_basepoint: [33]u8) u48 {
    var h = Sha256.init(.{});
    h.update(&opener_payment_basepoint);
    h.update(&accepter_payment_basepoint);
    const d = h.finalResult();
    return std.mem.readInt(u48, d[26..32], .big);
}

pub const LocktimeSequence = struct { locktime: u32, sequence: u32 };

/// The commitment transaction's locktime (upper byte 0x20, lower 24 bits of the obscured number)
/// and input sequence (upper byte 0x80, upper 24 bits).
pub fn obscuredLocktimeSequence(commitment_number: u48, factor: u48) LocktimeSequence {
    const o: u48 = commitment_number ^ factor;
    return .{
        .locktime = (@as(u32, 0x20) << 24) | @as(u32, @truncate(o & 0xffffff)),
        .sequence = (@as(u32, 0x80) << 24) | @as(u32, @truncate(o >> 24)),
    };
}

// ── scripts ─────────────────────────────────────────────────────────────

const op_0: u8 = 0x00;
const op_1: u8 = 0x51;
const op_2: u8 = 0x52;
const op_16: u8 = 0x60;
const op_if: u8 = 0x63;
const op_notif: u8 = 0x64;
const op_else: u8 = 0x67;
const op_endif: u8 = 0x68;
const op_drop: u8 = 0x75;
const op_dup: u8 = 0x76;
const op_ifdup: u8 = 0x73;
const op_swap: u8 = 0x7c;
const op_size: u8 = 0x82;
const op_equal: u8 = 0x87;
const op_equalverify: u8 = 0x88;
const op_hash160: u8 = 0xa9;
const op_checksig: u8 = 0xac;
const op_checksigverify: u8 = 0xad;
const op_checkmultisig: u8 = 0xae;
const op_cltv: u8 = 0xb1;
const op_csv: u8 = 0xb2;

const ScriptWriter = struct {
    allocator: Allocator,
    list: std.ArrayList(u8) = .empty,

    fn deinit(self: *ScriptWriter) void {
        self.list.deinit(self.allocator);
    }

    fn op(self: *ScriptWriter, b: u8) Allocator.Error!void {
        try self.list.append(self.allocator, b);
    }

    /// A direct push of up to 75 bytes (every datum here is 20, 32 or 33 bytes).
    fn push(self: *ScriptWriter, data: []const u8) Allocator.Error!void {
        std.debug.assert(data.len >= 1 and data.len <= 75);
        try self.list.append(self.allocator, @intCast(data.len));
        try self.list.appendSlice(self.allocator, data);
    }

    /// A minimally encoded script number: `OP_0`, `OP_1`..`OP_16`, otherwise the little-endian
    /// bytes with a sign byte when the top bit is set (what LDK and lnd push for delays and expiries).
    fn number(self: *ScriptWriter, n: u32) Allocator.Error!void {
        if (n == 0) return self.op(op_0);
        if (n <= 16) return self.op(op_1 - 1 + @as(u8, @intCast(n)));
        var buf: [5]u8 = undefined;
        var len: usize = 0;
        var v = n;
        while (v != 0) : (v >>= 8) {
            buf[len] = @truncate(v);
            len += 1;
        }
        if (buf[len - 1] & 0x80 != 0) {
            buf[len] = 0;
            len += 1;
        }
        try self.push(buf[0..len]);
    }

    fn finish(self: *ScriptWriter) Allocator.Error![]u8 {
        return self.list.toOwnedSlice(self.allocator);
    }
};

fn ripemd(data: []const u8) [20]u8 {
    var out: [20]u8 = undefined;
    ripemd160.Ripemd160.hash(data, &out, .{});
    return out;
}

fn hash160(data: []const u8) [20]u8 {
    var out: [20]u8 = undefined;
    ripemd160.hash160(data, &out);
    return out;
}

/// The funding output's witness script: `2 <pubkey1> <pubkey2> 2 OP_CHECKMULTISIG`, the
/// lexicographically lesser key first.
pub fn fundingScript(allocator: Allocator, key_a: [33]u8, key_b: [33]u8) Allocator.Error![]u8 {
    const swap = std.mem.lessThan(u8, &key_b, &key_a);
    var w: ScriptWriter = .{ .allocator = allocator };
    errdefer w.deinit();
    try w.op(op_2);
    try w.push(if (swap) &key_b else &key_a);
    try w.push(if (swap) &key_a else &key_b);
    try w.op(op_2);
    try w.op(op_checkmultisig);
    return w.finish();
}

/// `to_local` and HTLC-transaction output witness script:
/// `OP_IF <revocationpubkey> OP_ELSE <to_self_delay> OP_CSV OP_DROP <local_delayedpubkey> OP_ENDIF OP_CHECKSIG`.
pub fn toLocalScript(allocator: Allocator, revocation_pubkey: [33]u8, to_self_delay: u32, local_delayed_pubkey: [33]u8) Allocator.Error![]u8 {
    var w: ScriptWriter = .{ .allocator = allocator };
    errdefer w.deinit();
    try w.op(op_if);
    try w.push(&revocation_pubkey);
    try w.op(op_else);
    try w.number(to_self_delay);
    try w.op(op_csv);
    try w.op(op_drop);
    try w.push(&local_delayed_pubkey);
    try w.op(op_endif);
    try w.op(op_checksig);
    return w.finish();
}

/// The `to_remote` witness script under option_anchors: `<remotepubkey> OP_CHECKSIGVERIFY 1 OP_CSV`.
pub fn toRemoteAnchorScript(allocator: Allocator, remote_pubkey: [33]u8) Allocator.Error![]u8 {
    var w: ScriptWriter = .{ .allocator = allocator };
    errdefer w.deinit();
    try w.push(&remote_pubkey);
    try w.op(op_checksigverify);
    try w.op(op_1);
    try w.op(op_csv);
    return w.finish();
}

/// The anchor witness script: `<funding_pubkey> OP_CHECKSIG OP_IFDUP OP_NOTIF OP_16 OP_CSV OP_ENDIF`.
pub fn anchorScript(allocator: Allocator, funding_pubkey: [33]u8) Allocator.Error![]u8 {
    var w: ScriptWriter = .{ .allocator = allocator };
    errdefer w.deinit();
    try w.push(&funding_pubkey);
    try w.op(op_checksig);
    try w.op(op_ifdup);
    try w.op(op_notif);
    try w.op(op_16);
    try w.op(op_csv);
    try w.op(op_endif);
    return w.finish();
}

/// The P2A script of the `shared_anchor` output: `OP_1 <0x4e73>`.
pub const shared_anchor_script = [_]u8{ op_1, 0x02, 0x4e, 0x73 };

/// An offered HTLC's witness script (the commitment owner offered it): the revocation key, the
/// remote key with the preimage, or the 2-of-2 of an HTLC-timeout transaction. `anchors` adds
/// the one-block CSV.
pub fn offeredHtlcScript(allocator: Allocator, revocation_pubkey: [33]u8, remote_htlc_pubkey: [33]u8, local_htlc_pubkey: [33]u8, payment_hash: [32]u8, anchors: bool) Allocator.Error![]u8 {
    var w: ScriptWriter = .{ .allocator = allocator };
    errdefer w.deinit();
    try htlcScriptHead(&w, revocation_pubkey, remote_htlc_pubkey);
    try w.op(op_equal);
    try w.op(op_notif);
    try w.op(op_drop);
    try w.op(op_2);
    try w.op(op_swap);
    try w.push(&local_htlc_pubkey);
    try w.op(op_2);
    try w.op(op_checkmultisig);
    try w.op(op_else);
    try w.op(op_hash160);
    try w.push(&ripemd(&payment_hash));
    try w.op(op_equalverify);
    try w.op(op_checksig);
    try w.op(op_endif);
    try htlcScriptTail(&w, anchors);
    return w.finish();
}

/// A received HTLC's witness script: the revocation key, an HTLC-success 2-of-2 with the preimage,
/// or the remote key after `cltv_expiry`.
pub fn receivedHtlcScript(allocator: Allocator, revocation_pubkey: [33]u8, remote_htlc_pubkey: [33]u8, local_htlc_pubkey: [33]u8, payment_hash: [32]u8, cltv_expiry: u32, anchors: bool) Allocator.Error![]u8 {
    var w: ScriptWriter = .{ .allocator = allocator };
    errdefer w.deinit();
    try htlcScriptHead(&w, revocation_pubkey, remote_htlc_pubkey);
    try w.op(op_equal);
    try w.op(op_if);
    try w.op(op_hash160);
    try w.push(&ripemd(&payment_hash));
    try w.op(op_equalverify);
    try w.op(op_2);
    try w.op(op_swap);
    try w.push(&local_htlc_pubkey);
    try w.op(op_2);
    try w.op(op_checkmultisig);
    try w.op(op_else);
    try w.op(op_drop);
    try w.number(cltv_expiry);
    try w.op(op_cltv);
    try w.op(op_drop);
    try w.op(op_checksig);
    try w.op(op_endif);
    try htlcScriptTail(&w, anchors);
    return w.finish();
}

/// The prefix both HTLC scripts share: `OP_DUP OP_HASH160 <RIPEMD160(SHA256(revocationpubkey))> OP_EQUAL
/// OP_IF OP_CHECKSIG OP_ELSE <remote_htlcpubkey> OP_SWAP OP_SIZE 32`; each caller continues with `OP_EQUAL`.
fn htlcScriptHead(w: *ScriptWriter, revocation_pubkey: [33]u8, remote_htlc_pubkey: [33]u8) Allocator.Error!void {
    try w.op(op_dup);
    try w.op(op_hash160);
    try w.push(&hash160(&revocation_pubkey));
    try w.op(op_equal);
    try w.op(op_if);
    try w.op(op_checksig);
    try w.op(op_else);
    try w.push(&remote_htlc_pubkey);
    try w.op(op_swap);
    try w.op(op_size);
    try w.push(&.{32});
}

fn htlcScriptTail(w: *ScriptWriter, anchors: bool) Allocator.Error!void {
    if (anchors) {
        try w.op(op_1);
        try w.op(op_csv);
        try w.op(op_drop);
    }
    try w.op(op_endif);
}

/// A version 0 P2WSH script_pubkey for `witness_script`.
pub fn p2wsh(witness_script: []const u8) [34]u8 {
    var out: [34]u8 = undefined;
    out[0] = 0x00;
    out[1] = 0x20;
    Sha256.hash(witness_script, out[2..34], .{});
    return out;
}

/// A version 0 P2WPKH script_pubkey for the 33-byte `pubkey`.
pub fn p2wpkh(pubkey: [33]u8) [22]u8 {
    var out: [22]u8 = undefined;
    out[0] = 0x00;
    out[1] = 0x14;
    out[2..22].* = hash160(&pubkey);
    return out;
}

// ── commitment transaction ──────────────────────────────────────────────

/// A committed HTLC, from the point of view of the commitment's owner.
pub const Htlc = struct {
    /// True when the owner offered it (the owner -> remote direction), false when it received it.
    offered: bool,
    amount_msat: u64,
    cltv_expiry: u32,
    payment_hash: [32]u8,
};

/// The derived keys a commitment uses (BOLT#3 §Key Derivation).
pub const Keys = struct {
    revocation_pubkey: [33]u8,
    local_delayed_pubkey: [33]u8,
    local_htlc_pubkey: [33]u8,
    remote_htlc_pubkey: [33]u8,
    /// The `to_remote` key (`remotepubkey`).
    remote_pubkey: [33]u8,
    local_funding_pubkey: [33]u8,
    remote_funding_pubkey: [33]u8,
};

pub const CommitmentParams = struct {
    funding_txid: [32]u8,
    funding_output_index: u32,
    funding_amount_sat: u64,
    commitment_number: u48,
    /// `payment_basepoint` of `open_channel` and of `accept_channel`, in that order (for `obscuringFactor`).
    opener_payment_basepoint: [33]u8,
    accepter_payment_basepoint: [33]u8,
    /// Balances before the fee, the anchors and the in-flight HTLCs are taken off.
    to_local_msat: u64,
    to_remote_msat: u64,
    /// The commitment's owner opened the channel (pays the fee and the anchors).
    local_is_funder: bool,
    /// The owner's `dust_limit_satoshis`.
    dust_limit_satoshis: u64,
    feerate_per_kw: u32,
    to_self_delay: u16,
    keys: Keys,
    format: Format = .{},
    htlcs: []const Htlc = &.{},
};

pub const OutputKind = union(enum) {
    to_local,
    to_remote,
    local_anchor,
    remote_anchor,
    shared_anchor,
    /// The HTLC at this index of `CommitmentParams.htlcs`.
    htlc: usize,
};

pub const Commitment = struct {
    arena: std.heap.ArenaAllocator,
    /// Unsigned: one input with an empty scriptSig and no witness yet (`finalizeCommitment` adds it).
    tx: bitcointx.Transaction,
    /// What each output of `tx.vout` is.
    kinds: []OutputKind,
    funding_script: []const u8,
    funding_amount_sat: i64,

    pub fn deinit(self: *Commitment) void {
        self.arena.deinit();
        self.* = undefined;
    }

    /// The BIP143 digest of the funding input, `SIGHASH_ALL`, for either party's funding key to sign.
    pub fn sighash(self: Commitment, allocator: Allocator) bitcointx.bip143.Bip143Error![32]u8 {
        return bitcointx.bip143.sighash(allocator, self.tx, 0, self.funding_script, self.funding_amount_sat, sighash_all);
    }

    /// Places the witness `0 <sig1> <sig2> <funding script>` on the funding input. The signatures are
    /// DER with the sighash byte (`derSignature`), `*_for_*` being the signature by the funding key it names.
    pub fn finalize(self: *Commitment, sig_local_funding: []const u8, sig_remote_funding: []const u8, local_funding_pubkey: [33]u8, remote_funding_pubkey: [33]u8) Allocator.Error!void {
        const a = self.arena.allocator();
        const local_first = std.mem.lessThan(u8, &local_funding_pubkey, &remote_funding_pubkey);
        const items = try a.alloc([]const u8, 4);
        items[0] = &.{};
        items[1] = if (local_first) sig_local_funding else sig_remote_funding;
        items[2] = if (local_first) sig_remote_funding else sig_local_funding;
        items[3] = self.funding_script;
        const witness = try a.alloc(bitcointx.Witness, 1);
        witness[0] = .{ .items = items };
        self.tx.witness = witness;
        self.tx.has_witness = true;
    }
};

const Pending = struct {
    value: i64,
    script: []const u8,
    kind: OutputKind,
    cltv: u32,

    fn lessThan(_: void, a: Pending, b: Pending) bool {
        if (a.value != b.value) return a.value < b.value;
        if (!std.mem.eql(u8, a.script, b.script)) return std.mem.lessThan(u8, a.script, b.script);
        return a.cltv < b.cltv;
    }
};

fn toI64(v: u64) error{AmountOutOfRange}!i64 {
    return std.math.cast(i64, v) orelse error.AmountOutOfRange;
}

/// The HTLC witness script of `h` under `p`'s keys and format.
pub fn htlcWitnessScript(allocator: Allocator, p: CommitmentParams, h: Htlc) Allocator.Error![]u8 {
    return if (h.offered)
        offeredHtlcScript(allocator, p.keys.revocation_pubkey, p.keys.remote_htlc_pubkey, p.keys.local_htlc_pubkey, h.payment_hash, p.format.anchors)
    else
        receivedHtlcScript(allocator, p.keys.revocation_pubkey, p.keys.remote_htlc_pubkey, p.keys.local_htlc_pubkey, h.payment_hash, h.cltv_expiry, p.format.anchors);
}

/// Whether `h` gets an output on `p`'s commitment (BOLT#3 §Trimmed Outputs): its whole satoshis minus
/// the fee of the HTLC transaction that would spend it reach the owner's dust limit.
pub fn htlcUntrimmed(p: CommitmentParams, h: Htlc) bool {
    const sat: u64 = h.amount_msat / 1000;
    const fee = htlcTxFee(p.feerate_per_kw, h.offered, p.format);
    return sat >= p.dust_limit_satoshis + fee;
}

/// BOLT#3 §Commitment Transaction Construction: the owner's commitment transaction with its
/// outputs in BIP69+CLTV order. Balances and HTLC amounts round down to whole satoshis; the base
/// fee and the anchors come off the funder's side before the dust check; a side whose amount ends
/// below the dust limit (or negative) gets no output, and under zero-fee commitments whatever is
/// short of the P2A anchor's 240 sat goes to it.
pub fn buildCommitment(allocator: Allocator, p: CommitmentParams) Error!Commitment {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    const f = p.format;
    const dust = try toI64(p.dust_limit_satoshis);
    const funding = try toI64(p.funding_amount_sat);

    var untrimmed: usize = 0;
    for (p.htlcs) |h| {
        if (htlcUntrimmed(p, h)) untrimmed += 1;
    }
    const base_fee = try toI64(commitmentFee(p.feerate_per_kw, untrimmed, f));
    var to_local = try toI64(p.to_local_msat / 1000);
    var to_remote = try toI64(p.to_remote_msat / 1000);
    const funder_cut = base_fee + (if (f.anchors) 2 * anchor_amount_sat else 0);
    if (p.local_is_funder) to_local -= funder_cut else to_remote -= funder_cut;

    var pending: std.ArrayList(Pending) = .empty;
    for (p.htlcs, 0..) |h, i| {
        if (!htlcUntrimmed(p, h)) continue;
        const script = try htlcWitnessScript(a, p, h);
        try pending.append(a, .{
            .value = try toI64(h.amount_msat / 1000),
            .script = try a.dupe(u8, &p2wsh(script)),
            .kind = .{ .htlc = i },
            .cltv = h.cltv_expiry,
        });
    }
    const to_local_exists = to_local >= dust;
    const to_remote_exists = to_remote >= dust;
    if (to_local_exists) {
        const s = try toLocalScript(a, p.keys.revocation_pubkey, p.to_self_delay, p.keys.local_delayed_pubkey);
        try pending.append(a, .{ .value = to_local, .script = try a.dupe(u8, &p2wsh(s)), .kind = .to_local, .cltv = 0 });
    }
    if (to_remote_exists) {
        const spk: []const u8 = if (f.anchors)
            try a.dupe(u8, &p2wsh(try toRemoteAnchorScript(a, p.keys.remote_pubkey)))
        else
            try a.dupe(u8, &p2wpkh(p.keys.remote_pubkey));
        try pending.append(a, .{ .value = to_remote, .script = spk, .kind = .to_remote, .cltv = 0 });
    }
    if (f.anchors) {
        if (to_local_exists or untrimmed > 0) {
            const s = try anchorScript(a, p.keys.local_funding_pubkey);
            try pending.append(a, .{ .value = anchor_amount_sat, .script = try a.dupe(u8, &p2wsh(s)), .kind = .local_anchor, .cltv = 0 });
        }
        if (to_remote_exists or untrimmed > 0) {
            const s = try anchorScript(a, p.keys.remote_funding_pubkey);
            try pending.append(a, .{ .value = anchor_amount_sat, .script = try a.dupe(u8, &p2wsh(s)), .kind = .remote_anchor, .cltv = 0 });
        }
    }
    if (f.zero_fee_commitments) {
        var others: i64 = 0;
        for (pending.items) |o| others += o.value;
        const diff = @max(funding - others, 0);
        try pending.append(a, .{
            .value = @min(diff, shared_anchor_max_sat),
            .script = try a.dupe(u8, &shared_anchor_script),
            .kind = .shared_anchor,
            .cltv = 0,
        });
    }
    std.mem.sort(Pending, pending.items, {}, Pending.lessThan);

    const vout = try a.alloc(bitcointx.TxOut, pending.items.len);
    const kinds = try a.alloc(OutputKind, pending.items.len);
    for (pending.items, vout, kinds) |o, *v, *k| {
        v.* = .{ .value = o.value, .script_pubkey = o.script };
        k.* = o.kind;
    }
    const factor = obscuringFactor(p.opener_payment_basepoint, p.accepter_payment_basepoint);
    const ls = obscuredLocktimeSequence(p.commitment_number, factor);
    const vin = try a.alloc(bitcointx.TxIn, 1);
    vin[0] = .{ .prevout = .{ .txid = p.funding_txid, .vout = p.funding_output_index }, .script_sig = &.{}, .sequence = ls.sequence };
    return .{
        .arena = arena,
        .tx = .{ .version = f.version(), .vin = vin, .vout = vout, .witness = &.{}, .locktime = ls.locktime, .has_witness = false },
        .kinds = kinds,
        .funding_script = try fundingScript(a, p.keys.local_funding_pubkey, p.keys.remote_funding_pubkey),
        .funding_amount_sat = funding,
    };
}

// ── HTLC transactions ───────────────────────────────────────────────────

pub const HtlcTx = struct {
    arena: std.heap.ArenaAllocator,
    /// Unsigned until `finalize`.
    tx: bitcointx.Transaction,
    /// The witness script of the HTLC output this transaction spends.
    spent_script: []const u8,
    /// The value of that output.
    spent_amount_sat: i64,
    /// Whether this is an HTLC-timeout transaction (the HTLC was offered), else HTLC-success.
    offered: bool,
    /// The sighash type of the REMOTE node's signature: `sighash_all`, or `sighash_single_anyonecanpay` under
    /// anchors / zero-fee commitments (so fee inputs can be added to the HTLC transaction). The local node's own
    /// signature is its choice (the published vectors use `sighash_all`); `sighash` takes the type.
    remote_hash_type: u32,

    pub fn deinit(self: *HtlcTx) void {
        self.arena.deinit();
        self.* = undefined;
    }

    /// The BIP143 digest of the HTLC input for a signature of `hash_type` (use `remote_hash_type` to check or
    /// make the remote node's signature).
    pub fn sighash(self: HtlcTx, allocator: Allocator, hash_type: u32) bitcointx.bip143.Bip143Error![32]u8 {
        return bitcointx.bip143.sighash(allocator, self.tx, 0, self.spent_script, self.spent_amount_sat, hash_type);
    }

    /// Places the witness `0 <remotehtlcsig> <localhtlcsig> <preimage | empty> <script>`; `preimage` is the
    /// payment preimage for HTLC-success and `null` (an empty item) for HTLC-timeout. Signatures are DER
    /// with the sighash byte.
    pub fn finalize(self: *HtlcTx, remote_htlc_sig: []const u8, local_htlc_sig: []const u8, preimage: ?[32]u8) Allocator.Error!void {
        const a = self.arena.allocator();
        const items = try a.alloc([]const u8, 5);
        items[0] = &.{};
        items[1] = remote_htlc_sig;
        items[2] = local_htlc_sig;
        items[3] = if (preimage) |pre| try a.dupe(u8, &pre) else &.{};
        items[4] = self.spent_script;
        const witness = try a.alloc(bitcointx.Witness, 1);
        witness[0] = .{ .items = items };
        self.tx.witness = witness;
        self.tx.has_witness = true;
    }
};

/// The HTLC-timeout / HTLC-success transaction spending output `output_index` of `c` (an HTLC output
/// of the commitment built from `p`): version as the commitment, locktime `cltv_expiry` for a timeout
/// and 0 for a success, sequence 1 under anchors and 0 otherwise, one output of the HTLC amount minus
/// the fee into the `to_local`-style script.
pub fn buildHtlcTx(allocator: Allocator, p: CommitmentParams, c: Commitment, output_index: usize) Error!HtlcTx {
    if (output_index >= c.kinds.len) return error.NotAnHtlcOutput;
    const hi = switch (c.kinds[output_index]) {
        .htlc => |i| i,
        else => return error.NotAnHtlcOutput,
    };
    const h = p.htlcs[hi];
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    const txid = try c.tx.txid(a);
    const spent = c.tx.vout[output_index].value;
    const fee = try toI64(htlcTxFee(p.feerate_per_kw, h.offered, p.format));
    const out_script = try toLocalScript(a, p.keys.revocation_pubkey, p.to_self_delay, p.keys.local_delayed_pubkey);
    const vin = try a.alloc(bitcointx.TxIn, 1);
    vin[0] = .{ .prevout = .{ .txid = txid, .vout = @intCast(output_index) }, .script_sig = &.{}, .sequence = if (p.format.anchors) 1 else 0 };
    const vout = try a.alloc(bitcointx.TxOut, 1);
    vout[0] = .{ .value = spent - fee, .script_pubkey = try a.dupe(u8, &p2wsh(out_script)) };
    return .{
        .arena = arena,
        .tx = .{
            .version = p.format.version(),
            .vin = vin,
            .vout = vout,
            .witness = &.{},
            .locktime = if (h.offered) h.cltv_expiry else 0,
            .has_witness = false,
        },
        .spent_script = try htlcWitnessScript(a, p, h),
        .spent_amount_sat = spent,
        .offered = h.offered,
        .remote_hash_type = if (p.format.htlcFeesZero()) sighash_single_anyonecanpay else sighash_all,
    };
}

// ── signatures ──────────────────────────────────────────────────────────

/// A DER signature plus its sighash byte, at most 73 bytes.
pub const DerSignature = struct {
    buf: [73]u8,
    len: u8,

    pub fn slice(self: *const DerSignature) []const u8 {
        return self.buf[0..self.len];
    }
};

fn derInteger(out: []u8, v: *const [32]u8) usize {
    var start: usize = 0;
    while (start < 31 and v[start] == 0) start += 1;
    const pad: usize = if (v[start] & 0x80 != 0) 1 else 0;
    const len = 32 - start + pad;
    out[0] = 0x02;
    out[1] = @intCast(len);
    if (pad == 1) out[2] = 0;
    @memcpy(out[2 + pad ..][0 .. 32 - start], v[start..]);
    return 2 + len;
}

/// The compact (r || s) signature BOLT#2 messages carry as the DER signature with `hash_type`
/// appended that goes into a witness.
pub fn derSignature(sig_rs: [64]u8, hash_type: u8) DerSignature {
    var out: DerSignature = .{ .buf = undefined, .len = 0 };
    var n: usize = 2;
    n += derInteger(out.buf[n..], sig_rs[0..32]);
    n += derInteger(out.buf[n..], sig_rs[32..64]);
    out.buf[0] = 0x30;
    out.buf[1] = @intCast(n - 2);
    out.buf[n] = hash_type;
    out.len = @intCast(n + 1);
    return out;
}
