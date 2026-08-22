// SPDX-License-Identifier: MIT

//! What a trusted dealer does with `threshold_ecdsa`'s keygen layer
//! (Phase 2a): Shamir-split a group ECDSA secret key into `n` shares
//! reconstructible by any `t` of them, publish a Feldman VSS commitment so
//! every share is publicly checkable, derive one participant's public key
//! share without ever seeing its secret share, and reconstruct the secret
//! from a quorum to confirm the dealing round-trips.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const threshold_ecdsa = @import("threshold_ecdsa");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const Scalar = threshold_ecdsa.Scalar;

    // The dealer's group ECDSA secret key, and the degree-1 polynomial's
    // one non-constant coefficient (2-of-3: t=2 needs t-1=1 coefficient).
    const secret_key = Scalar.random(io);
    const coefficients = [_]Scalar{Scalar.random(io)};

    const split = try threshold_ecdsa.splitSecretKey(gpa, secret_key, 2, 3, &coefficients);
    defer gpa.free(split.shares);
    defer gpa.free(split.commitments.commitments);

    const group_pub = threshold_ecdsa.groupPublicKey(split.commitments);
    std.debug.print("group public key: {x}\n", .{std.fmt.bytesToHex(group_pub.toBytes(), .lower)});

    // Derive participant 1's PUBLIC key share from the Feldman commitment
    // alone — no access to its secret share.
    const pub_share_1 = try threshold_ecdsa.derivePublicKeyShare(split.commitments, 1);
    std.debug.print("participant 1 public share: {x}\n", .{std.fmt.bytesToHex(pub_share_1.toBytes(), .lower)});

    // A quorum of 2 (of 3) shares reconstructs the original secret.
    const quorum = [_]threshold_ecdsa.ShamirShare{ split.shares[0], split.shares[2] };
    const reconstructed = try threshold_ecdsa.reconstructSecret(&quorum);
    std.debug.assert(reconstructed.toBytes(.big).len == secret_key.toBytes(.big).len);
    std.debug.assert(std.mem.eql(u8, &reconstructed.toBytes(.big), &secret_key.toBytes(.big)));
    std.debug.print("reconstructed secret matches the dealt one\n", .{});

    // A caller-supplied duplicate share index must be a nameable error, not
    // silently-wrong arithmetic — the reconstruction has no way to detect a
    // logic bug that hands it the same party twice, so it must refuse.
    const duplicate = [_]threshold_ecdsa.ShamirShare{ split.shares[0], split.shares[0] };
    if (threshold_ecdsa.reconstructSecret(&duplicate)) |_| {
        unreachable;
    } else |err| switch (err) {
        error.DuplicateIndex => std.debug.print("duplicate share index correctly rejected\n", .{}),
        error.InsufficientShares, error.ZeroIndex => return err,
    }

    // A malformed (t, n) pair must fail the same way, before any Shamir
    // arithmetic runs.
    if (threshold_ecdsa.splitSecretKey(gpa, secret_key, 5, 3, &coefficients)) |bad| {
        gpa.free(bad.shares);
        gpa.free(bad.commitments.commitments);
        unreachable;
    } else |err| switch (err) {
        error.InvalidParameters => std.debug.print("t > n correctly rejected\n", .{}),
        error.InvalidElement, error.OutOfMemory => return err,
    }
}
