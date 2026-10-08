// SPDX-License-Identifier: MIT

//! What a firmware-signing appliance does with `lms`: sign release images with
//! HSS (RFC 8554), the stateful hash-based scheme NIST SP 800-208 and CNSA 2.0
//! approve for code signing, and let a device verify them from a 60-byte public
//! key. The key is STATEFUL: every signature spends one one-time leaf, and
//! signing two images with the same leaf is key recovery. Driving that state
//! correctly is the consumer's job, and it is what this program shows.
//!
//! Built against the PUBLISHED module (`@import("lms")` and nothing else): a type
//! the API needs but does not export, or an error that cannot be named from
//! outside, stops this file compiling.
//!
//! The durable position lives in a variable here so the program touches no
//! files; a real appliance's `write` fsyncs before returning.

const std = @import("std");
const lms = @import("lms");

/// Two levels of H5 / W8: 32 x 32 = 1024 signatures, and only the top tree (32
/// one-time keys) is generated up front; each 32-signature lower tree is built
/// when the first signature needs it. Real deployments pick H10/H15 at the top.
const levels = [_]lms.Level{
    .{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w8 },
    .{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w8 },
};

/// Stands in for the file the appliance fsyncs the next position into.
const PositionStore = struct {
    next: lms.Position = .{},
    writes: usize = 0,
    fail: bool = false,

    /// Called BEFORE the signature bytes exist. An error here must leave the
    /// leaf unspent: a durable position AHEAD of the signatures released only
    /// wastes leaves, one BEHIND them permits reuse after a crash.
    fn write(ctx: *anyopaque, next: lms.Position) anyerror!void {
        const self: *PositionStore = @ptrCast(@alignCast(ctx));
        if (self.fail) return error.StorageFull;
        self.next = next;
        self.writes += 1;
    }
};

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak in lms example");
    const gpa = da.allocator();

    // ── key generation ───────────────────────────────────────────────────
    // A 32-byte secret SEED and a 16-byte identifier I, both caller-supplied:
    // `lms` reads no entropy of its own. Fixed literals here for
    // reproducibility; an appliance draws them from a CSPRNG inside an HSM.
    const seed: [32]u8 = @splat(0x5e);
    const id: [16]u8 = @splat(0x1d);
    var key: lms.SecretKey = undefined;
    try lms.SecretKey.init(&key, gpa, &levels, &seed, id, null);

    // The public key is 60 bytes (L, LMS type, LM-OTS type, I, root): this is
    // what ships with the product.
    const published = key.publicKey().toBytes();
    std.debug.print("public key: {d} bytes, signature: {d} bytes\n", .{
        published.len,
        key.signatureLength(),
    });

    // ── the signing handle ───────────────────────────────────────────────
    // Written in place: it records its own address so a copy can be detected.
    var store: PositionStore = .{};
    var signer: lms.SigningKey = undefined;
    lms.SigningKey.init(&signer, &key, .{ .ctx = &store, .write = PositionStore.write });
    defer signer.deinit(); // wipes the seeds, frees the node caches

    const sig_buf = try gpa.alloc(u8, signer.sk.signatureLength());
    defer gpa.free(sig_buf);

    // ── sign two release images ──────────────────────────────────────────
    const images = [_][]const u8{
        "firmware-4.2.1.bin sha256=1a2b...",
        "firmware-4.2.2.bin sha256=3c4d...",
    };
    for (images) |image| {
        const sig = try signer.sign(image, sig_buf);
        if (!lms.hssVerify(&published, image, sig)) return error.OwnSignatureRejected;
        std.debug.print("signed: next leaf of the message tree is {d}, durable position written {d}x\n", .{
            store.next.q[1],
            store.writes,
        });
    }

    // ── the rejections a caller must handle ──────────────────────────────
    // Storage failed, so NO signature is produced and NO leaf is spent.
    // Treating it as transient and retrying is correct; signing anyway would be
    // one crash away from reusing a leaf.
    const before = signer.position();
    store.fail = true;
    if (signer.sign("firmware-4.2.3.bin", sig_buf)) |_| {
        return error.SignedWithoutDurablePosition;
    } else |err| switch (err) {
        error.PersistFailed => std.debug.print("durable write failed: no signature, no leaf spent\n", .{}),
        error.KeyExhausted, error.OutputTooSmall, error.OutOfMemory, error.KeyHandleCopied => return error.WrongRejectionReason,
    }
    if (!std.meta.eql(before.q, signer.position().q)) return error.LeafSpentOnFailedPersist;
    store.fail = false;

    // A copied handle refuses to sign; without this a `var copy = signer`
    // would fork the counter into two keys that both believe they are at leaf k.
    var forked = signer;
    if (forked.sign("anything", sig_buf)) |_| {
        return error.CopiedHandleSigned;
    } else |err| switch (err) {
        error.KeyHandleCopied => std.debug.print("copied handle refused to sign\n", .{}),
        error.KeyExhausted, error.OutputTooSmall, error.OutOfMemory, error.PersistFailed => return error.WrongRejectionReason,
    }

    // ── verification, on the device ──────────────────────────────────────
    // The device holds 60 bytes and nothing else. `verify` allocates nothing and
    // answers false for every malformed input; it never errors.
    const verifier_key = try lms.HssPublicKey.parse(&published);
    const sig = try signer.sign(images[0], sig_buf);
    if (!verifier_key.verify(images[0], sig)) return error.HonestSignatureRejected;
    if (verifier_key.verify(images[1], sig)) return error.TamperedImageAccepted;
    if (lms.hssVerify(&published, images[0], sig[0 .. sig.len - 1])) return error.TruncatedSignatureAccepted;
    std.debug.print("tampered image and truncated signature rejected\n", .{});

    // A public key for a parameter set this module does not implement (here:
    // SHA-256/192, SP 800-208) is a typed error, never a silent mis-parse.
    var foreign = published;
    foreign[7] = 0x11; // LMS typecode 0x11: not in RFC 8554
    if (lms.HssPublicKey.parse(&foreign)) |_| {
        return error.ForeignTypecodeAccepted;
    } else |err| switch (err) {
        error.UnsupportedLmsType => std.debug.print("public key with an unsupported LMS typecode rejected\n", .{}),
        error.InvalidLength, error.UnsupportedOtsType, error.InvalidLevels => return error.WrongRejectionReason,
    }
}
