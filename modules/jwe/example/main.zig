// SPDX-License-Identifier: MIT

//! What a consumer does with `jwe`: encrypt an application secret into a
//! compact JWE, decrypt it back, and get a named, fail-closed error — not
//! a partially-decrypted buffer — when the ciphertext was tampered with or
//! opened under the wrong kind of key. `jwt` proves a token wasn't
//! tampered with; `jwe` is for the payload that must not be *readable*
//! without the key at all (an encrypted refresh token, a sealed webhook
//! secret).
//!
//! Entropy is a caller obligation the module's `Entropy` type makes
//! explicit (see `src/entropy.zig`) — `std.crypto.random` was removed in
//! Zig 0.16, so this example seeds its own `std.Random.DefaultCsprng` from
//! a fixed array instead of reading OS entropy, keeping the whole example
//! in memory with no syscalls.
//!
//! Built against the PUBLISHED module (`@import("jwe")`) only — no
//! `test_deps`.

const std = @import("std");
const jwe = @import("jwe");

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i * 7 + 1); // fixed, not OS entropy
    var csprng = std.Random.DefaultCsprng.init(seed);

    // A long-lived shared key a service uses to seal data for itself (e.g.
    // an opaque refresh token it will decrypt on the next request).
    const shared_key = [_]u8{0x2b} ** 32;

    // ── encrypt ──────────────────────────────────────────────────────────
    const token = try jwe.encryptCompact(
        gpa,
        .dir,
        .A256GCM,
        .{ .symmetric = &shared_key },
        "refresh-token-for-user-42",
        "",
        .{ .csprng = csprng.random() },
        .{},
    );
    defer gpa.free(token);
    std.debug.print("sealed {d} byte(s) into a {d}-byte compact JWE\n", .{
        "refresh-token-for-user-42".len,
        token.len,
    });

    // ── decrypt ──────────────────────────────────────────────────────────
    const plaintext = try jwe.decryptCompact(gpa, .{ .symmetric = &shared_key }, token, .{});
    defer gpa.free(plaintext);
    std.debug.print("opened: \"{s}\"\n", .{plaintext});
    if (!std.mem.eql(u8, plaintext, "refresh-token-for-user-42")) return error.DecryptedPlaintextMismatch;

    // ── reject: tampered ciphertext ────────────────────────────────────
    // Flip one byte inside the ciphertext segment. GCM's tag must catch
    // this before any plaintext is returned — a named error, not a
    // garbled string.
    const tampered = try gpa.dupe(u8, token);
    defer gpa.free(tampered);
    const last_dot = std.mem.lastIndexOfScalar(u8, tampered, '.').?;
    const third_dot = std.mem.lastIndexOfScalar(u8, tampered[0..last_dot], '.').?;
    tampered[third_dot + 5] = if (tampered[third_dot + 5] == 'A') 'B' else 'A';
    if (jwe.decryptCompact(gpa, .{ .symmetric = &shared_key }, tampered, .{})) |leaked| {
        gpa.free(leaked);
        return error.TamperedCiphertextUnexpectedlyDecrypted;
    } else |err| switch (err) {
        error.AuthenticationFailed => {
            std.debug.print("rejected: AuthenticationFailed (tampered ciphertext)\n", .{});
        },
        else => return err,
    }

    // ── reject: right key bytes, wrong key kind ─────────────────────────
    // `dir` needs a `.symmetric` key; handing it an RSA key structurally
    // cannot decrypt this token — refused before any crypto runs, the JWE
    // analogue of `jwt`'s AlgKeyMismatch algorithm-confusion defense.
    var dummy_priv: [1]u8 = .{0};
    if (jwe.decryptCompact(gpa, .{ .password = &dummy_priv }, token, .{})) |leaked| {
        gpa.free(leaked);
        return error.WrongKeyKindUnexpectedlyAccepted;
    } else |err| switch (err) {
        error.KeyMaterialMismatch => {
            std.debug.print("rejected: KeyMaterialMismatch (dir token needs a symmetric key)\n", .{});
        },
        else => return err,
    }
}
