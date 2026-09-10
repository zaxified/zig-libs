// SPDX-License-Identifier: MIT

//! What an anonymous-report / "send us a tip" style consumer does with
//! `sealedbox`: rebuild a long-term recipient keypair from a stored secret
//! key, seal a fresh message to it both via the no-alloc buffer API and the
//! allocating convenience API, open it back, and reject a tampered box and a
//! wrong keypair by NAME. Then the key-text round trip a config file would
//! actually use (base64/hex encode -> parse -> rebuild -> still opens).
//!
//! External oracle actually run (see the report, not restated here): the
//! recipient PUBLIC key this example derives from `sk` via
//! `keyPairFromSecretKey` (std's X25519 base-point multiply) is checked
//! against `nacl.public.PrivateKey(sk).public_key` from PyNaCl (a real
//! libsodium binding, not std.crypto) — an independent X25519 implementation
//! computing the SAME clamped scalar multiplication on the SAME fresh,
//! non-RFC-vector secret. `crypto_box_seal` itself uses a fresh ephemeral
//! keypair every call (that is the point of the construction — the recipient
//! can never learn who sent a message), so its ciphertext is not
//! byte-reproducible run to run; the printed ciphertext/plaintext hex below
//! is what the report's cross-check decrypts with
//! `nacl.public.SealedBox(PrivateKey(sk)).decrypt(...)` against this same
//! `sk` to confirm a real libsodium can open what this module sealed.
//!
//! This module allocates in exactly two functions (`sealAlloc`/`openAlloc`);
//! the buffer-API `seal`/`open` never do. Both allocating paths run under
//! `std.heap.DebugAllocator` with `defer if (da.deinit() == .leak) @panic`
//! below, including the FAILURE path (`openAlloc` on a tampered box), which
//! allocates its output buffer before discovering the tag doesn't verify and
//! must free it via `errdefer` rather than leak it.

const std = @import("std");
const sealedbox = @import("sealedbox");

/// A check that survives EVERY optimize mode, unlike a debug-only assert:
/// `-Doptimize=ReleaseFast` compiles those out, and `scripts/test.sh` does not
/// merely BUILD the examples, it RUNS them in the lane's own optimize mode --
/// so in a release lane the check vanished and the example went on printing
/// that it had passed. See `scripts/check-example-assert.py`.
fn must(ok: bool, src: std.builtin.SourceLocation) void {
    if (!ok) std.debug.panic("example check failed at {s}:{d}", .{ src.file, src.line });
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Fresh throwaway X25519 secret scalar -- invented for this example, NOT
    // one of the module's RFC 7748 §6.1 (Alice) KAT bytes. The recipient's
    // long-term keypair is rebuilt from just this stored secret, the way a
    // service loading its key from a config file would.
    const sk = hex32("3a7c910e3a7c910e3a7c910e3a7c910e3a7c910e3a7c910e3a7c910e3a7c910e");
    const kp = try sealedbox.keyPairFromSecretKey(sk);

    // PyNaCl's `PrivateKey(sk).public_key` for the exact same `sk` — an
    // independent (libsodium-backed) X25519 base-point multiplication. If
    // std's clamping/scalar-mult ever diverged from libsodium's, this would
    // catch it; a self-consistency check inside this module never could.
    const expected_pk = hex32("27e10fb4dba861e1a07264255ffd06c692f752e4d42e687f4faa404f5a1dc41b");
    must(std.mem.eql(u8, &expected_pk, &kp.public_key), @src());
    std.debug.print("keyPairFromSecretKey: public key byte-exact vs. PyNaCl's independent X25519\n", .{});

    // ── no-alloc buffer API ─────────────────────────────────────────────
    //
    // Buffer sizing is the caller's job: `out` must be exactly
    // `msg.len + overhead` (48 bytes: 32-byte ephemeral pubkey + 16-byte
    // Poly1305 tag) -- get this wrong and `seal` returns `error.InvalidBufferSize`
    // in EVERY build mode (see root.zig: the check is a real `if`, not
    // `std.debug.assert`, precisely because ReleaseFast would otherwise compile
    // the check out and turn a caller's sizing mistake into memory corruption
    // in exactly the build where nothing would have caught it). This comment
    // used to describe the old assert-based behavior after the code had
    // already moved past it -- audit finding L3, 2026-09-05.
    const msg1 = "meet at the usual place, bring the fresh evidence";
    var boxed1: [msg1.len + sealedbox.overhead]u8 = undefined;
    must(boxed1.len == sealedbox.sealedLen(msg1.len), @src());
    try sealedbox.seal(io, &boxed1, msg1, kp.public_key);

    var opened1: [msg1.len]u8 = undefined;
    try sealedbox.open(&opened1, &boxed1, kp);
    try std.testing.expectEqualStrings(msg1, &opened1);
    std.debug.print("buffer API: round-tripped a {d}-byte message, no allocation\n", .{msg1.len});

    // Print for the external cross-check: decrypt THIS exact box with
    // PyNaCl's `SealedBox(PrivateKey(sk)).decrypt(...)` against the same
    // `sk` above (done separately -- see the report).
    std.debug.print("boxed1 hex (for external PyNaCl decrypt): {x}\n", .{boxed1});

    // ── allocating convenience API -- the leak-detection duty ───────────
    const msg2 = "a longer tip that a caller would rather not size a stack buffer for";
    const boxed2 = try sealedbox.sealAlloc(gpa, io, msg2, kp.public_key);
    defer gpa.free(boxed2);
    must(boxed2.len == sealedbox.sealedLen(msg2.len), @src());

    const opened2 = try sealedbox.openAlloc(gpa, boxed2, kp);
    defer gpa.free(opened2);
    try std.testing.expectEqualStrings(msg2, opened2);
    std.debug.print("allocating API: round-tripped a {d}-byte message, freed cleanly\n", .{msg2.len});

    // ── negative path #1: tampered box -> AuthenticationFailed, freed ───
    //
    // `openAlloc` allocates its output buffer BEFORE the AEAD tag is known
    // to be valid, then must free that allocation on the failure path
    // (`errdefer`) rather than leak it -- exactly the failure-path-that-
    // allocates-and-returns-early case the DebugAllocator above exists to
    // catch. Flip a byte past the ephemeral-pubkey prefix, deep in the
    // Poly1305-tagged body.
    var tampered: [msg2.len + sealedbox.overhead]u8 = boxed2[0 .. msg2.len + sealedbox.overhead].*;
    tampered[tampered.len - 1] ^= 0x01;
    if (sealedbox.openAlloc(gpa, &tampered, kp)) |_| {
        unreachable; // a flipped tag-covered byte cannot survive verification
    } else |err| switch (err) {
        error.AuthenticationFailed => std.debug.print("tampered box: openAlloc -> AuthenticationFailed (expected), no leak\n", .{}),
        else => return err,
    }

    // ── negative path #2: wrong recipient keypair -> AuthenticationFailed ─
    const wrong_sk = [_]u8{0x5b} ** sealedbox.secret_length;
    const wrong_kp = try sealedbox.keyPairFromSecretKey(wrong_sk);
    var opened_wrong: [msg1.len]u8 = undefined;
    if (sealedbox.open(&opened_wrong, &boxed1, wrong_kp)) |_| {
        unreachable;
    } else |err| switch (err) {
        error.AuthenticationFailed => std.debug.print("wrong keypair: open -> AuthenticationFailed (expected)\n", .{}),
        else => return err,
    }

    // ── key-text round trip: what a config file actually stores ─────────
    const pk_text = sealedbox.encodePublicKeyBase64(kp.public_key);
    const pk_back = try sealedbox.parsePublicKeyBase64(&pk_text);
    must(std.mem.eql(u8, &kp.public_key, &pk_back), @src());

    var sk_text = sealedbox.encodeSecretKeyHex(kp.secret_key);
    const sk_back = try sealedbox.parseSecretKeyHex(&sk_text);
    must(std.mem.eql(u8, &kp.secret_key, &sk_back), @src());
    sealedbox.wipe(&sk_text); // hygiene: this is throwaway key material, but the API is the point
    for (sk_text) |c| must(c == 0, @src());
    std.debug.print("key-text round trip: base64 pubkey + hex secret, secret wiped after use\n", .{});

    // Malformed key text is a typed error, not a panic -- a config-file
    // parser branches on which one.
    if (sealedbox.parsePublicKeyBase64(pk_text[0 .. pk_text.len - 1])) |_| {
        unreachable;
    } else |err| switch (err) {
        error.InvalidLength => std.debug.print("truncated base64 key: InvalidLength (expected)\n", .{}),
        error.InvalidKeyEncoding => unreachable,
    }
}

fn hex32(comptime s: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
