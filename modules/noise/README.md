# noise

The generic **Noise Protocol Framework** (https://noiseprotocol.org, spec
revision 34): handshake patterns as data plus a comptime-parameterized
DH/cipher/hash `Suite`, reusable for any Noise-based protocol — unlike the
`wireguard` module's `noise.zig`/`handshake.zig`, which hard-wire
WireGuard's fixed `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` instantiation and
already implement its KDF. This module has **zero dependency** on
`wireguard` (or any other sibling module).

**Status: compiling scaffold, no crypto implemented.** Every method on
`CipherState` / `SymmetricState` / `HandshakeState` (spec §5) is a
`@panic("TODO(agent): ...")` stub reserving the API surface; the
handshake-*pattern* data (§7/§9 token sequences for `NN`/`NK`/`XX`/`IK`) is
real, since patterns are pure specification text, not crypto. See
`SPEC.md` for the fill-in plan.

- **Model after:** Noise Protocol Framework rev 34 (noiseprotocol.org);
  design ref cacophony (Haskell) / noise-c / snow (Rust) — shape only, no
  source copied.
- **Platform:** any. **Role:** util. **Concurrency:** reentrant — a
  `HandshakeState` is entirely caller-owned, no shared/global state.

## API

```zig
const noise = @import("noise");
const std = @import("std");

// Handshake-pattern data (real, spec §7/§9):
noise.patterns.NN; // -> e ; <- e, ee
noise.patterns.NK; // pre: <- s ; -> e, es ; <- e, ee
noise.patterns.XX; // -> e ; <- e, ee, s, es ; -> s, se
noise.patterns.IK; // pre: <- s ; -> e, es, s, ss ; <- e, ee, se

// Cipher suite binding (spec §4) — comptime-parameterized on DH/AEAD/Hash:
const S = noise.Suite(
    std.crypto.dh.X25519,
    std.crypto.aead.chacha_poly.ChaCha20Poly1305,
    std.crypto.hash.sha2.Sha256,
);
// ...or the convenience alias for the same combination:
const S2 = noise.DefaultSuite;

var hs: S.HandshakeState = .{};
// hs.initialize(...) / hs.writeMessage(...) / hs.readMessage(...) all
// @panic("TODO(agent): ...") for now — the crypto is not implemented yet.
```

## Verify

```
zig build test-noise
```

## Provenance

Clean-room from the Noise Protocol Framework specification rev 34
(https://noiseprotocol.org/noise.html) — a public spec, not copyrightable
expression (merger doctrine), so the spec citation alone needs no NOTICE
entry. This module additionally names design references consulted for
API/behavior SHAPE only (no source copied): cacophony (Haskell,
BSD-2-Clause), noise-c (https://github.com/rweather/noise-c,
BSD-2-Clause), snow (Rust, Apache-2.0 OR MIT) — see `../../NOTICE` for the
repo-wide provenance ledger entry.

Official test vectors for the eventual crypto implementation:
- rweather/noise-c's `vectors/` directory on GitHub — the canonical
  `cacophony`-format vector JSON, covering the standard patterns/suites.
- snow's and cacophony's own vector JSON files (same `cacophony` vector
  format), useful as an independent cross-check.

Neither is consulted yet — this pass only reserves the API surface.
