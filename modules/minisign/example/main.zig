// SPDX-License-Identifier: MIT

//! What a package manager does with `minisign`: check a downloaded release
//! tarball against the `.pub` key it pinned at install time and the `.minisig`
//! the mirror served alongside the artifact. Both files are text, both arrive
//! from somewhere untrusted, and the only thing the verifier trusts is the 42
//! bytes of pinned public key.
//!
//! The example plays the vendor too, because a signature has to exist before
//! it can be checked: it imports a release key, seals it under a passphrase
//! the way `minisign -G` would, re-opens it, and signs. That import is not a
//! shortcut — `KeyPair.generate` takes an `std.Io`, and a release pipeline
//! whose signing key lives in an HSM hands the module key bytes rather than
//! asking it to mint one.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`@import("minisign")` and nothing else; `entropy` is the module's
//! own dependency, not this file's). If a type needed to call the API is not
//! public, or an error cannot be named from outside, this file stops
//! compiling. The module's own tests cannot notice either, because they live
//! inside it.

const std = @import("std");
const minisign = @import("minisign");

/// The vendor's Ed25519 release seed, as exported from an HSM. Fixed here so
/// the run is reproducible.
const release_seed: [32]u8 = .{
    0x3b, 0xd1, 0x07, 0x64, 0x9a, 0x2e, 0xf3, 0x50, 0x18, 0xc7, 0x46, 0x8b, 0x22, 0x0d, 0xe5, 0x71,
    0xa4, 0x69, 0x1c, 0xb0, 0x57, 0x3e, 0x82, 0xff, 0x0a, 0x95, 0x6d, 0x24, 0xc1, 0x38, 0x7a, 0x40,
};

/// A second, unrelated key — the "some other vendor signed this" case below.
const impostor_seed: [32]u8 = @splat(0xa7);

/// The key id published in the `.pub` file. Not a secret; it exists so a
/// verifier holding several pinned keys can tell immediately which one a
/// signature claims, before doing any curve arithmetic.
const release_key_number: [8]u8 = .{ 0x9e, 0x4c, 0x11, 0x03, 0xd7, 0x60, 0x2a, 0xb8 };
const impostor_key_number: [8]u8 = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

/// A fixed scrypt salt; a real `-G` draws it from a CSPRNG.
const salt: [minisign.salt_length]u8 = @splat(0x5c);

const passphrase = "correct horse battery staple";

/// The artifact and the human-readable claim the vendor binds to it. The
/// trusted comment is signed by a SECOND signature, which is exactly what
/// makes it trustworthy enough to print — an unsigned comment on an untrusted
/// mirror is just attacker-supplied text.
const tarball = "\x1f\x8b\x08...(pretend this is the release tarball)";
const trusted_comment = "timestamp:1750000000\tfile:app-2.4.1.tar.gz";

fn importKey(seed: [32]u8, key_number: [8]u8) !minisign.KeyPair {
    return .{
        .key_number = key_number,
        .ed25519 = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed),
    };
}

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── the vendor: seal the key the way `minisign -G` writes it ─────────
    var release_key = try importKey(release_seed, release_key_number);
    defer release_key.wipe();

    const sealed = try minisign.sealSecretKey(
        gpa,
        release_key,
        passphrase,
        salt,
        minisign.ops_limit_interactive,
        minisign.mem_limit_interactive,
    );

    var sk_buf: [512]u8 = undefined;
    var sk_writer: std.Io.Writer = .fixed(&sk_buf);
    try minisign.writeSecretKeyFile(&sk_writer, minisign.default_secret_key_comment, sealed);
    const sk_file = sk_writer.buffered();

    // ── the vendor's build agent: reload the key and sign ────────────────
    // Round-tripping through the text form is the point: the agent reads the
    // same bytes off disk that `minisign -G` wrote.
    const parsed_sk = try minisign.parseSecretKeyFile(sk_file);
    var opened = minisign.openSecretKey(gpa, parsed_sk.key, passphrase) catch |err| switch (err) {
        // A mistyped passphrase is a typed error, never a silently-wrong key
        // that would go on to produce garbage signatures.
        error.WrongPassword => {
            std.debug.print("wrong passphrase for the release key\n", .{});
            return;
        },
        else => return err,
    };
    defer opened.wipe();

    const signed = try minisign.signFile(gpa, opened, tarball, .prehashed, trusted_comment);

    var sig_buf: [512]u8 = undefined;
    var sig_writer: std.Io.Writer = .fixed(&sig_buf);
    try minisign.writeSignatureFile(
        &sig_writer,
        minisign.default_signature_comment,
        signed.signature,
        trusted_comment,
        signed.global_signature,
    );
    const minisig_file = sig_writer.buffered();

    var pk_buf: [256]u8 = undefined;
    var pk_writer: std.Io.Writer = .fixed(&pk_buf);
    const key_id = minisign.formatKeyId(opened.key_number);
    var comment_buf: [128]u8 = undefined;
    const pk_comment = try std.fmt.bufPrint(&comment_buf, "{s}{s}", .{
        minisign.public_key_comment_prefix,
        key_id,
    });
    try minisign.writePublicKeyFile(&pk_writer, pk_comment, opened.publicKey());
    const pub_file = pk_writer.buffered();
    std.debug.print("published key {s}, {d}-byte .pub, {d}-byte .minisig\n", .{
        key_id,
        pub_file.len,
        minisig_file.len,
    });

    // ── the package manager ──────────────────────────────────────────────
    // It pinned the `.pub` at install time; the `.minisig` came with the
    // download. Both are parsed from text that a mirror could have rewritten.
    const pinned = minisign.parsePublicKeyFile(pub_file) catch |err| switch (err) {
        // Every malformed-text case is one named variant, so a package
        // manager can distinguish "this file is not a minisign key" from
        // "this key does not match" in what it tells the user.
        error.MissingUntrustedCommentPrefix, error.MissingLine, error.WrongLength, error.InvalidBase64 => {
            std.debug.print("pinned key file is not a minisign public key\n", .{});
            return;
        },
        else => return err,
    };

    const sig = try minisign.parseSignatureFile(minisig_file);
    std.debug.print("signature claims key {s}, algorithm {s}\n", .{
        minisign.formatKeyId(sig.signature.key_number),
        @tagName(sig.algorithm),
    });

    try minisign.verifyFile(gpa, pinned.key, tarball, sig);
    // Only NOW is the trusted comment safe to show a user: it is covered by
    // the second signature `verifyFile` just checked, and `parseSignatureFile`
    // already refused any control characters in it.
    std.debug.print("verified: {s}\n", .{sig.trusted_comment});

    // ── the rejections a package manager must handle ─────────────────────
    // 1. The mirror served a modified tarball with the genuine signature.
    var corrupted = tarball.*;
    corrupted[3] ^= 0x01;
    if (minisign.verifyFile(gpa, pinned.key, &corrupted, sig)) |_| {
        return error.TamperedArtifactAccepted;
    } else |err| switch (err) {
        error.SignatureVerificationFailed => std.debug.print("modified tarball rejected\n", .{}),
        else => return err,
    }

    // 2. A perfectly valid signature — by the wrong key. The key id check
    //    fires before any curve arithmetic, so the caller can say "signed by
    //    an unpinned key" rather than the useless "bad signature".
    var impostor = try importKey(impostor_seed, impostor_key_number);
    defer impostor.wipe();
    const impostor_sig = try minisign.signMessage(impostor, tarball, .prehashed);
    if (minisign.verifyMessage(pinned.key, tarball, impostor_sig)) |_| {
        return error.UnpinnedKeyAccepted;
    } else |err| switch (err) {
        error.KeyIdMismatch => std.debug.print("signature from an unpinned key rejected\n", .{}),
        else => return err,
    }

    // 3. The trusted comment rewritten on the mirror, artifact untouched.
    //    The first layer still passes; only the global signature catches it,
    //    which is the entire reason the second layer exists.
    var rewritten = sig;
    rewritten.trusted_comment = "timestamp:1750000000\tfile:totally-fine.tar.gz";
    if (minisign.verifyFile(gpa, pinned.key, tarball, rewritten)) |_| {
        return error.RewrittenTrustedCommentAccepted;
    } else |err| switch (err) {
        error.SignatureVerificationFailed => std.debug.print("rewritten trusted comment rejected\n", .{}),
        else => return err,
    }
}
