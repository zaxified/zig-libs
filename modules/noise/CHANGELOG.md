# noise — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — tests: deterministic fuzz driver `NOISE_FUZZ` (`src/fuzz_test.zig`). `noise-handshake`: a whole in-memory handshake of a random catalog pattern (plus XXpsk3, IKpsk2) with random payloads; undamaged it completes with equal handshake hashes and working transport states, with one message damaged / truncated / replaced by random bytes / given a low-order ephemeral it is refused with a typed error or never completes on both sides. `noise-transport`: genuine messages open; a flipped ciphertext or ad bit, a truncation, a replay and out-of-order delivery are refused without advancing the nonce; rekey in step stays in sync, one-sided rekey does not. Verdicts clean (handshake at `.scale` 3). No code change.
- **2026-10-10** — Constant time: new `src/ctgrind_harness.zig` (targets `hs`, `transport`, ReleaseFast). `hs` runs a full `Noise_XXpsk3` handshake with both static private keys, every ephemeral seed and the PSK tainted; `transport` taints the split keys through encrypt/decrypt and `rekey`. No context is a branch of noise's own on a secret: the 8 / 6 in-file contexts are std's X25519 identity-point check and the AEAD tag-verify outcome, reached through noise frames (itemised in `scripts/checks/ctgrind-expected.tsv`). No code change.
- **2026-10-09** — **FIX (secrets on the dead stack, per suite):** the burns were sized for the default suite (X25519, ChaChaPoly, SHA-256); a deeper DH (P-384 dirties 11.3 KiB) outgrew the fixed 8 KiB handshake burn, and std's AEADs leave their own frames under the 1 KiB cipher burn. Now each `Suite` computes its burns (`Suite.burns`, `burn.Sizes.of`) from the stack its three primitives dirty (`state.stack_bytes`): measured upper bounds for the std types, a declared `pub const noise_stack_bytes` for any other type, else a conservative fallback (DH 40 KiB, AEAD/hash 4 KiB). The default suite's burns are unchanged. New probe tests: every std primitive within its claimed size, and every burned entry point within its burn on all twelve std suites plus a P-384 adapter (declared and undeclared). No API change; a pluggable primitive may add `noise_stack_bytes`.

- **2026-10-09** — **BREAKING + FIX (secrets on the dead stack):** a new ReleaseFast stack probe (`src/stackprobe_test.zig`, `XXpsk3`, 41 needles) found the static key left by `HandshakeState.init`/`initialize`, the ephemeral key and the transport keys left by `writeMessage`/`readMessage`, and `ck`/`k`/the split keys left by `SymmetricState.mixKey`/`mixKeyAndHash`/`split`. After: 0 everywhere. **API (BREAKING):** `CipherState.initializeKey(key: *const [32]u8)`; `SymmetricState.split(out: *[2]CipherState)` (was a return value); `HandshakeState.init(self, pattern, initiator, prologue, keys: *const Keys)` initializes in place (was `init(...) InitError!HandshakeState`); `HandshakeState.initialize(self, pattern, initiator, prologue, keys: *const Keys)` (the `s, e, rs, re, psks` parameters are now the `Keys` fields); `Keys.s`/`Keys.e` are `?*const KeyPair`; `writeMessage(random, payload, out, transport: *[2]CipherState)` and `readMessage(message, out, transport)` fill `transport` on the call that completes the pattern, and `Step` is `{ len, complete: bool }` (was `{ len, transport: ?[2]CipherState }`). Migration: `var hs: S.HandshakeState = .{}; try hs.init(pattern, true, prologue, &.{ .s = &my_static });` and `var tp: [2]S.CipherState = undefined; const step = try hs.writeMessage(rng, payload, &out, &tp); if (step.complete) { use tp }`. Every secret-touching entry point runs its body one frame down and burns (`src/burn.zig`). `bolt8` (`split`, `initializeKey`) migrated in the same change; `tenantkex` rebuilt on the new API.

- **2026-10-08** — **FIX (secrets on the dead stack):** the dead-stack burn's buffer is now
  16-aligned instead of the vector type's natural 32. At 32 the burn's frame was realigned, and
  the up to 56 bytes between its saved frame pointer and the buffer — the top of the frame the
  burned body had used — stayed unzeroed (found by `threshold_ecdsa`'s stack probe: half of a
  secret survived there). No API change.
- **2026-10-08** — **FIX (key on the dead stack; NO API CHANGE):** `CipherState.encryptWithAd`/
  `decryptWithAd`/`rekey` copied the key into a dead frame on every call (the AEAD takes it by
  value). Each now runs one frame down and zeroes 1 KiB below it (~10 ns).
- **2026-10-04** — **mvp → core.** The whole rev-34 pattern catalog: one-way
  `N`/`K`/`X`, the twelve fundamental and the twenty-three deferred patterns
  (`patterns.catalog`, `patterns.byName`). PSK modifiers (`withPsk` at
  comptime, `PatternStorage.parse`/`applyPsk` at run time, `psk0`..`psk4`,
  combinable with `+`); `parseProtocolName` (`Noise_XXpsk3_25519_…`);
  `Suite.matches`, `Suite.name_suffix`. `HandshakeState.init` — the checked
  constructor: validates the pattern against the keys held (spec §7.3:
  `MissingKey`, `PskCountMismatch`, `InvalidPattern`) so a missing key or PSK can
  no longer reach a null unwrap or an out-of-bounds index. Pluggable primitives:
  a DH/AEAD/hash type declaring `pub const noise_name` joins a suite (the AESGCM
  big-endian nonce now follows the name). 87 cacophony vectors (snow's file) run
  byte-exact, every pattern of the catalog anchored; seeded sweeps over random
  patterns (whatever `init` accepts completes and agrees), damaged handshake
  messages and hostile names; mutation 25 mutants, 0 surviving (4 equivalent
  branches removed). Additive: `initialize` and every existing name unchanged.
- **2026-09-09** — Docs: the `NOTICE` pointer in ``src/root.zig`` resolved to `modules/NOTICE`,
  a path that has never existed in this repository. Now ``../../../NOTICE``. No code or data
  changed. `zig build check-catalog` gained a check that resolves every relative NOTICE
  link under `modules/**`, so this cannot come back silently.
- **2026-09-07** — Fuzz reach: `fuzzReadMessage` never read a handshake message. It
  opened `smith.bytes(&msg)` and then drew the length with `smith.valueRangeAtMost`;
  `bytes` consumes `@min(msg.len, in.len)` octets and a ranged draw reads EIGHT more as a
  little-endian `u64`, returning the range MINIMUM when fewer remain, so the length was 0
  — and with no corpus the one input it ever ran was empty. `readMessage("")` fails on
  the `e` token's length check before a single octet of transcript is mixed. Measured
  2026-09-07: 1 round, 0 messages accepted, 0 payload octets recovered. The draw is now
  one `smith.slice` and the corpus is built at run time from this module's own
  `writeMessage` — a genuine NN message 1 (`e || payload`, no AEAD yet, which is why the
  responder accepts it without knowing the initiator), the same ephemeral with an empty
  payload (`DHLEN` octets, the shortest accepted message), one octet short of `DHLEN`,
  the all-zero ephemeral, the all-ones ephemeral, and a 256-octet message that fills the
  buffer and `out` exactly. ⚠ The corpus guard pins payload octets, not acceptances: a
  `DHLEN`-octet message is accepted with a ZERO-length payload, so "accepted > 0" would
  say nothing about whether any payload crossed the boundary. Pinned: 6 non-empty,
  5 accepted, 257 payload octets.

- **2026-08-21** — **Breaking:** `CipherState.encryptWithAd`/`decryptWithAd` and
  `SymmetricState.encryptAndHash`/`decryptAndHash` gained `error.BufferTooSmall`. The
  output-buffer preconditions were `std.debug.assert`, which compiles out in `ReleaseFast`
  and `ReleaseSmall` — the modes this ships in — leaving a caller-supplied `out` slice to
  be written past in exactly the builds where it matters. The module already published
  `BufferTooSmall` and used a runtime check for the same class elsewhere; these four sites
  were the inconsistency. Callers that only `try` are unaffected; an exhaustive `switch`
  over the error set needs the new tag.

- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Byte-exact against RFC 5869's
  published test vectors.
- **2026-07-10** — New module: The generic Noise Protocol Framework (noiseprotocol.org,
  spec rev 34).
