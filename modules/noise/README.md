# noise

The generic **Noise Protocol Framework** (https://noiseprotocol.org, spec
revision 34): handshake patterns as data plus a comptime-parameterized
DH/cipher/hash `Suite`, reusable for any Noise-based protocol — unlike the
`wireguard` module's `noise.zig`/`handshake.zig`, which hard-wire
WireGuard's fixed `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` instantiation and
already implement its KDF. This module has **zero dependency** on
`wireguard` (or any other sibling module).

**Status: implemented.** The `CipherState` / `SymmetricState` /
`HandshakeState` methods (spec §5) run for real over the
comptime-parameterized `Suite` — DH exchange, AEAD seal/open, and the
HKDF/HMAC ratchet — and the handshake-pattern data (§7/§9 token sequences
for `NN`/`NK`/`XX`/`IK`) is real as well. Exercised end-to-end by the
sibling `bolt8` module, whose BOLT#8 appendix vectors are byte-exact over
this framework. See `SPEC.md` for the verification detail.

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
// hs.initialize(...) then hs.writeMessage(...) / hs.readMessage(...)
// drive the handshake; SymmetricState.split() then yields the two
// transport CipherStates.
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

Test vectors actually consulted: six official `cacophony`-format vectors
from rweather/noise-c's `vectors/` directory on GitHub, transcribed into
`state.zig` and checked byte-exact end-to-end (ciphertexts + handshake
hash) across `NN`/`NK`/`XX`/`IK`, both hash choices (SHA-256/SHA-512), and
a second hash function (BLAKE2s) — see `SPEC.md`'s "Verification" for the
full list. snow's and cacophony's own vector files (same format) were not
additionally consulted — the noise-c set already covers every pattern/
suite this module implements.
