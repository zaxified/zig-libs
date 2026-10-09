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
for `NN`/`NK`/`XX`/`IK`) is real as well. The sibling `bolt8` does NOT run on
`HandshakeState`: the suite accepts only X25519 (`dhName` in `src/state.zig`),
so `bolt8` drives its secp256k1 handshake with its own state
(`bolt8/src/handshake.zig`). See `SPEC.md` for the verification detail.

- **Model after:** Noise Protocol Framework rev 34 (noiseprotocol.org);
  design ref cacophony (Haskell) / noise-c / snow (Rust) — shape only, no
  source copied.
- **Platform:** any. **Role:** util. **Concurrency:** reentrant — a
  `HandshakeState` is entirely caller-owned, no shared/global state.

## API

```zig
const noise = @import("noise");
const std = @import("std");

// Handshake-pattern data, the whole rev-34 catalog (spec §7.4–§7.6):
// one-way N/K/X, fundamental NN NK NX KN KK KX XN XK XX IN IK IX, and the
// 23 deferred ones (NK1, X1K1, IX1, …) — `noise.patterns.catalog`.
noise.patterns.XX; // -> e ; <- e, ee, s, es ; -> s, se
const xx3 = noise.withPsk(noise.patterns.XX, &.{3}); // XXpsk3 (spec §9.2), comptime

// A protocol name, resolved at run time (spec §8):
var storage: noise.PatternStorage = .{};
const proto = try noise.parseProtocolName(&storage, "Noise_XXpsk3_25519_ChaChaPoly_SHA256");
// proto.pattern, proto.dh / .cipher / .hash; S.matches(proto) checks the suite.

// Cipher suite binding (spec §4) — comptime-parameterized on DH/AEAD/Hash:
const S = noise.Suite(
    std.crypto.dh.X25519,
    std.crypto.aead.chacha_poly.ChaCha20Poly1305,
    std.crypto.hash.sha2.Sha256,
);
// ...or the convenience alias for the same combination:
const S2 = noise.DefaultSuite;

// The checked constructor: validates the pattern against the keys this
// party holds (spec §7.3) — MissingKey, PskCountMismatch, InvalidPattern —
// so writeMessage/readMessage can never reach a missing key or PSK.
// In place, keys by pointer (no copy of a private key in a dead frame).
var hs: S.HandshakeState = .{};
try hs.init(proto.pattern, true, prologue, &.{ .s = &my_static, .psks = &.{psk} });
// hs.writeMessage(random, payload, out, &transport) / hs.readMessage(msg, out,
// &transport) drive the handshake; the call that returns `Step.complete` has
// written the two transport CipherStates to `transport`.
// (`initialize` remains, unchecked.)

// Any other primitive joins a suite by declaring its spec §8 name, e.g. an
// X448 adapter over the `ed448` module: `pub const noise_name = "448";`
// plus the std DH shape (public_length, seed_length, KeyPair, scalarmult).
```

## Verify

```
zig build test-noise
```

87 cacophony vectors (snow's `tests/vectors/cacophony.txt`, a verbatim subset
in `src/testdata/`, extracted by `tools/extract-vectors.py`) run byte-exact:
every catalog pattern, every PSK variant in the file, all eight 25519 suites.

## Provenance

Clean-room from the Noise Protocol Framework specification rev 34
(https://noiseprotocol.org/noise.html) — a public spec, not copyrightable
expression (merger doctrine), so the spec citation alone needs no attribution.
This module additionally names design references consulted for API/behavior
SHAPE only (no source copied): cacophony (Haskell, BSD-2-Clause), noise-c
(https://github.com/rweather/noise-c, BSD-2-Clause), snow (Rust, Apache-2.0 OR
MIT). It is distinct from — and has zero dependency on — the `wireguard`
module's `noise.zig`/`handshake.zig`, which hard-wire WireGuard's fixed
`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` instantiation; this module is the
generic framework (patterns as data, comptime DH/cipher/hash suite selection).

Test vectors actually consulted: six official `cacophony`-format vectors
from rweather/noise-c's `vectors/` directory on GitHub, transcribed into
`state.zig` and checked byte-exact end-to-end (ciphertexts + handshake
hash) across `NN`/`NK`/`XX`/`IK`, both hash choices (SHA-256/SHA-512), and
a second hash function (BLAKE2s) — see `SPEC.md`'s "Verification" for the
full list. snow's and cacophony's own vector files (same format) were not
additionally consulted — the noise-c set already covers every pattern/
suite this module implements.