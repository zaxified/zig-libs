// SPDX-License-Identifier: MIT

//! What a release-signing appliance does with `xmss`: sign build artifacts
//! with a hash-based signature whose security rests on SHA-256 alone — no
//! elliptic curve, nothing a quantum computer shortens by more than a square
//! root. The price is that the key is STATEFUL: every signature burns one of
//! the tree's 2^h one-time keys, and signing twice from the same leaf is not
//! a reuse warning, it is key recovery. Driving that state correctly is the
//! entire job of a consumer, and it is what this program shows.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`@import("xmss")` and nothing else). If a type needed to call the
//! API is not public, or an error cannot be named from outside, this file
//! stops compiling. The module's own tests cannot notice either, because they
//! live inside it.
//!
//! The durable index below lives in a variable rather than on disk, so this
//! program touches no files; the shape of the hook is the point, and a real
//! appliance's `write` fsyncs before returning.

const std = @import("std");
const xmss = @import("xmss");

/// XMSS-SHA2_10_256: 2^10 = 1024 signatures per key, the smallest set RFC
/// 8391 assigns an OID. An appliance signing a release a day retires this key
/// in under three years and plans for that.
const Xmss = xmss.XmssSha2_10_256;

/// Stands in for the file the appliance fsyncs the next-unused index into.
/// `fail` simulates a full or unwritable volume.
const IndexStore = struct {
    next_idx: u32 = 0,
    writes: usize = 0,
    fail: bool = false,

    /// The hook `SigningKey` calls BEFORE it produces any signature bytes.
    /// Returning an error here must leave the leaf unconsumed — which is the
    /// direction that matters: a durable index AHEAD of the signatures
    /// actually released only wastes leaves, while one BEHIND them permits
    /// reuse after a crash.
    fn write(ctx: *anyopaque, next_idx: u32) anyerror!void {
        const self: *IndexStore = @ptrCast(@alignCast(ctx));
        if (self.fail) return error.StorageFull;
        self.next_idx = next_idx;
        self.writes += 1;
    }
};

pub fn main() !void {
    // ── key generation ───────────────────────────────────────────────────
    // Three independent 32-byte seeds, caller-supplied: `xmss` reads no
    // entropy of its own. Fixed literals here for reproducibility; an
    // appliance draws all three from a CSPRNG inside an HSM and the first two
    // never leave it.
    const keys = Xmss.keyGen(
        @splat(0xa1), // sk_seed  — derives every WOTS+ chain
        @splat(0xb2), // sk_prf   — randomizes the message hash
        @splat(0xc3), // pub_seed — public, travels in the public key
    );

    // The public key is 68 bytes: OID, tree root, public seed. This is what
    // ships with the product.
    const published = keys.pk.toBytes();
    std.debug.print("public key: {d} bytes, {d} signatures available\n", .{
        published.len,
        Xmss.max_signatures,
    });

    // ── the signing handle ───────────────────────────────────────────────
    // `SigningKey` is written through a pointer rather than returned by
    // value, on purpose: it records its own address so a later copy can be
    // detected. Bare `SecretKey` + `Xmss.sign` also work, but then the
    // consumer owns the crash-safety and the no-copy discipline alone.
    var store: IndexStore = .{};
    var signer: Xmss.SigningKey = undefined;
    Xmss.SigningKey.init(&signer, keys.sk, .{ .ctx = &store, .write = IndexStore.write });
    defer signer.zeroize();

    var sig: [Xmss.signature_length]u8 = undefined;

    // ── sign two artifacts ───────────────────────────────────────────────
    const artifacts = [_][]const u8{
        "release-4.2.1.tar.zst sha256=1a2b…",
        "release-4.2.2.tar.zst sha256=3c4d…",
    };
    for (artifacts) |artifact| {
        try signer.sign(&sig, artifact);
        if (!Xmss.verify(keys.pk, artifact, &sig)) return error.OwnSignatureRejected;
        std.debug.print("signed at leaf {d}, durable index now {d}\n", .{
            signer.index() - 1,
            store.next_idx,
        });
    }

    // ── the rejection a caller must handle ───────────────────────────────
    // Storage failed, so the signature is NOT produced and the leaf is NOT
    // spent. An appliance that treated this as a transient error and retried
    // later is correct; one that ignored it and signed anyway would be one
    // crash away from reusing a leaf.
    const leaf_before = signer.index();
    store.fail = true;
    if (signer.sign(&sig, "release-4.2.3.tar.zst sha256=5e6f…")) |_| {
        return error.SignedWithoutDurableIndex;
    } else |err| switch (err) {
        error.PersistFailed => std.debug.print("durable write failed — no signature, no leaf spent\n", .{}),
        error.KeyExhausted, error.KeyHandleCopied => return error.WrongRejectionReason,
    }
    if (signer.index() != leaf_before) return error.LeafSpentOnFailedPersist;
    store.fail = false;

    // A copied handle refuses to sign. Without this, a `var copy = signer`
    // — an innocent-looking move into a struct field or an array — would
    // fork the counter into two keys that both believe they are at leaf k.
    var forked = signer;
    if (forked.sign(&sig, "anything")) |_| {
        return error.CopiedHandleSigned;
    } else |err| switch (err) {
        error.KeyHandleCopied => std.debug.print("copied handle refused to sign\n", .{}),
        error.KeyExhausted, error.PersistFailed => return error.WrongRejectionReason,
    }

    // ── verification, on someone else's machine ──────────────────────────
    // The verifier holds 68 bytes and nothing else. A key for a different
    // parameter set is rejected by OID rather than silently mis-parsed.
    const verifier_key = Xmss.PublicKey.fromBytes(&published) catch |err| switch (err) {
        error.UnsupportedOid => {
            std.debug.print("public key is for a different XMSS parameter set\n", .{});
            return;
        },
    };

    try signer.sign(&sig, artifacts[0]);
    if (!Xmss.verify(verifier_key, artifacts[0], &sig)) return error.HonestSignatureRejected;

    // Tampering is caught by a plain `false` — `verify` never errors, so a
    // caller that wrote `try` here would have written nothing at all.
    if (Xmss.verify(verifier_key, "release-4.2.1.tar.zst sha256=dead…", &sig)) {
        return error.TamperedArtifactAccepted;
    }
    std.debug.print("tampered artifact rejected\n", .{});

    // So is a public key from the wrong product line: same signature, other
    // root, no match.
    var other_seed: [32]u8 = @splat(0xa1);
    other_seed[0] = 0xa2;
    const other = Xmss.keyGen(other_seed, @splat(0xb2), @splat(0xc3));
    if (Xmss.verify(other.pk, artifacts[0], &sig)) return error.WrongKeyAccepted;
    std.debug.print("signature does not verify under an unrelated key\n", .{});

    var wrong_oid = published;
    wrong_oid[3] = 0x02; // the OID of XMSS-SHA2_16_256
    if (Xmss.PublicKey.fromBytes(&wrong_oid)) |_| {
        return error.WrongOidAccepted;
    } else |err| switch (err) {
        error.UnsupportedOid => std.debug.print("public key with a foreign OID rejected\n", .{}),
    }
}
