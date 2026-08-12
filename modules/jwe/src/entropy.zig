// SPDX-License-Identifier: MIT

//! The randomness seam between this module and its consumer.
//!
//! std 0.16 removed `std.crypto.random`, so `jwe` has no generator of its own
//! and every fresh value it needs — the CEK, the content IV, the AxxxGCMKW
//! wrap IV, the PBES2 salt, the ECDH-ES ephemeral private key — arrives from
//! the caller. A bare `std.Random` parameter cannot carry that requirement:
//! it is a vtable, `DefaultPrng.init(0).random()` and a `getrandom(2)`-seeded
//! `DefaultCsprng` are the same type at the call site, and the weak one is not
//! a variant the caller has to choose — it is simply what fits.
//!
//! `Entropy` makes the choice a thing the caller writes out. It is a VALUE,
//! not a capability handle: this module is a pure codec (`meta.role = .codec`,
//! no I/O of its own), so the `io: std.Io` arm that lets a module draw its own
//! entropy — `bfv`, `tfhe`, `coconut` — is deliberately absent. It would hand
//! a JOSE encoder the authority to open sockets and files, and it would delete
//! this module's strongest external anchor: `kat_rfc7516.zig` reproduces RFC
//! 7516 §A.3's published token **byte-exact in the encrypt direction** by
//! feeding `encryptCompact` the RFC's own CEK ‖ IV through a fixed byte
//! stream. That test exists only because the randomness is injectable.
//!
//! ## What this does NOT do
//!
//! `std.Random` is still a vtable, so nothing checks what is inside
//! `.csprng`. A caller who writes `.{ .csprng = DefaultPrng.init(0).random() }`
//! still gets a predictable CEK and IV. This is a **fail-visible** seam, not a
//! fail-closed one: it removes the accident, not the possibility. Structural
//! prevention is out of reach here for a reason worth stating plainly — see
//! `Entropy.fixed_for_test`.

const std = @import("std");

pub const Entropy = union(enum) {
    /// PRODUCTION. A generator the caller asserts is cryptographically secure
    /// — `std.Random.DefaultCsprng` seeded from real OS entropy
    /// (`getrandom(2)`), or an equivalent. This module cannot verify the
    /// assertion; naming this arm IS the assertion.
    csprng: std.Random,

    /// **TEST / KAT ONLY.** A caller-controlled generator, so a token can be
    /// reproduced byte-for-byte — RFC 7516 §A.3's encrypt direction needs
    /// exactly that, and there is no other way to pin a published vector
    /// through a randomized encoder.
    ///
    /// What choosing this in production costs, concretely, and why the `dir`
    /// key-management mode is the sharp end:
    ///
    /// - Under `dir` the CEK **is** the caller's long-lived shared key. It
    ///   does not change between messages, so the content IV is the only
    ///   thing separating two encryptions. A repeated IV under `A128GCM` /
    ///   `A256GCM` is the classic GCM catastrophe: the keystream repeats, so
    ///   `C1 XOR C2 = P1 XOR P2` recovers plaintext outright, **and** the two
    ///   authentication tags expose the GHASH subkey `H = E_K(0^128)`, which
    ///   yields existential forgery of *any* message under that key — not
    ///   just the two that collided. Because the key is long-lived, that
    ///   forgery capability outlives the two messages and covers every other
    ///   token the same key protects. Under `A128CBC-HS256` /
    ///   `A256CBC-HS512` a repeated IV is bad but bounded: CBC with a
    ///   repeated IV leaks equality of plaintext block prefixes, and the
    ///   encrypt-then-MAC key is not recoverable from it.
    /// - Under every *other* `alg` (`RSA-OAEP`, `AxxxKW`, `AxxxGCMKW`,
    ///   `PBES2-*`, `ECDH-ES+AxxxKW`) the CEK is drawn fresh per call, so a
    ///   repeated draw damages only the messages that share it, and the
    ///   recipient's long-term key is untouched.
    ///
    /// Why the module cannot simply prevent this: `encryptCompact` is a pure
    /// function over caller-owned key material (`meta.concurrency =
    /// .reentrant`, no shared state). Guaranteeing IV uniqueness needs
    /// per-key state that survives process restarts, which nothing in a
    /// stateless encoder can hold; and the deterministic alternative — an
    /// SIV/nonce-derived-from-plaintext construction (RFC 5297) — is not
    /// expressible as an RFC 7518 §5 `enc` value, so it would not be JWE. The
    /// reachable ceiling is that picking the weak path has to be written
    /// down, which is this union.
    fixed_for_test: std.Random,
};

// Deliberately NO `pub fn source()`: the generator is unwrapped by a two-arm
// switch inside each file that actually draws bytes (`root.zig`, `alg.zig`,
// `ecdhes.zig`). An accessor would hand callers back the flat `std.Random`
// this type replaced, which is the whole thing it exists to stop being the
// path of least resistance.
