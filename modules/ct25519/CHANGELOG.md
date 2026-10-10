# ct25519 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — tools: comparative benchmark `tools/bench.zig` + `tools/c_bench/foreign_bench.c` (`zig build bench-ct25519`) against libsodium 1.0.18 (stand-in reference; dalek not installed) and OpenSSL 3.5.5 for X25519; card Performance filled (0.58–1.09×, fastest 1.21× OpenSSL), SPEC "Performance — bench-ct25519" section.
- **2026-10-09** — **Additive API + burn:** `X25519.recoverPublicKey` now runs under a burn (new `recoverPublicKeyInto(out, secret_key *const)`); new pointer twins `KeyPair.generateDeterministicInto` and `KeyPair.generateInto`. The std-shaped by-value `recoverPublicKey` / `generateDeterministic` / `generate` stay (qap's TLS shim swaps the type in for std's) and call the twins. Probe: `src/stackprobe2_test.zig`.
- **2026-10-08** — **FIX (secrets on the dead stack, MEDIUM) + additive API:** the new ReleaseFast
  stack probe (`src/stackprobe_test.zig`, all secret-scalar entry points) found every scalar in dead
  frames after `mulMultiRistretto` and the shared secret after `X25519.scalarmult`; `mul`, `mulBase`,
  `mulRistretto`, `mulRistrettoBase` and `recoverPublicKey` measured clean. Both now burn their stack
  (`burn.zig`). `X25519` keeps std's shape (qap's TLS shim swaps it in for std's), which leaves the
  key and the result in the caller's frame; the new `X25519.scalarmultInto(out, sk: *const, pk)`
  leaves neither.
- **2026-09-29** — **`X25519.scalarmult` on a 4×64-bit field core in x86-64
  MULX/ADX assembly (P6).** No API change: same signature, same bytes,
  `error.IdentityElement` on an all-zero result as std. Dispatch at compile
  time: BMI2+ADX → `mulx` with `adcx`/`adox` carry chains; BMI2 only (qap's
  `x86_64_v3` target) → `mulx` with `adc` chains; anything else, or the
  self-hosted backend → std's ladder. Constant-time: straight-line asm, fixed
  offsets from one state pointer, masked swap and folds, fixed inversion
  chain; the one zero-output branch depends on the public point only and is
  declassified for memcheck. Evidence (SPEC.md § P6): RFC 7748 §5.2 (incl.
  1 000 iterations) and §6.1 on every backend, std differential over 5 000
  random + edge inputs per backend, field ops vs `u512` mod p; ctgrind
  `x25519` target extended to the shared secret — 4 witness / 0 in-module on
  both asm paths, positive controls 1 in-module each. ReleaseFast bench, same
  process: MULX+ADX 1.23× std (43.9–45.7 vs 53.9–56.1 µs), MULX only
  1.16–1.23×. First consumer: qap's TLS fork, where the shared secret was
  18.65 % of the churn lane.
- **2026-09-28** — **New `X25519`: std's `X25519` shape with key generation
  on the C3 comb.** Additive API. `recoverPublicKey` = `clamp(sk)·B` on the
  fixed-base comb, then `u = (Z + Y)/(Z − Y)` (one inversion); `scalarmult`
  is std's ladder re-exported. No identity branch (unreachable for a clamped
  scalar, proof in `SPEC.md`). Bit-exact with std over RFC 7748 §6.1 and 512
  raw seeds; ctgrind target `x25519` 2 contexts / 0 in-module, as `comb`.
  ReleaseFast bench: public key 51.6 → 21.8 µs (2.36×). First consumer: qap's
  TLS fork (`-Dfast-x25519`), where the ephemeral key pair was half of X25519's
  ~28 % of a handshake.
- **2026-09-15** — **New `mulMultiRistretto`: constant-time `Σ s_i·P_i` by
  Straus's interleaving (audit `bulletproofs` B9).** Additive API. All terms
  share one chain of doublings; every term pays one `pcSelect` and one add per
  window whatever its scalar, so it stays constant-time where the bucket
  method does not. Chunks of 8 terms keep the tables on the stack (no
  allocator). A `DECISIONS.md` P5 addition, evidence in `SPEC.md` § B9:
  bit-exact against the per-term `mulRistretto` sum at every chunk boundary
  (n up to 64, raw/reduced/edge scalars, base, decoded, identity and random
  points), 7/7 mutants red and two chunk-size rewrites green; ctgrind `msm`
  target 0 contexts in `root.zig`, positive control 2 at the mutated line.
  ReleaseFast A/B: MSM n = 64 3 429 → 1 397 µs (2.45×); `bulletproofs.prove`
  n = 64 47.3 → 34.6 ms (1.37×), n = 32 1.50×; untouched `verify` 1.00×/0.99×.
  Its only caller is `bulletproofs`' prover.

- **2026-09-15** — **`mulBase`/`mulRistrettoBase` use a fixed-base comb:
  2.62× / 2.56× faster, same results (audit C3, C4, C9).** The base point ran
  the same 16-entry window ladder as any point, 252 doublings per multiply.
  It now runs the signed-radix-16 comb of Bernstein et al. 2012 §4 (ref10's
  `ge_scalarmult_base`) over a comptime 32×8 table: 64 additions, 4
  doublings, plus one always-performed add of `2^256·B` so all 256 scalar bits
  still count (ref10 instead requires `s < 2^255`). A deliberate exception to
  "never a new algorithm", admitted under `DECISIONS.md` P5; the four pieces of
  evidence are in `SPEC.md` § C3: bit-exact against the pre-C3 ladder on every
  nibble at every position, 33 boundary scalars and 20 000 random ones (10/10
  mutants red, 2 correct rewrites green); ctgrind `comb` target 0 contexts in
  `root.zig` with two positive controls firing (1 and 6 contexts at the
  mutated line); ReleaseFast A/B `mulBase` 56.3 → 21.5 µs, `ecvrf`
  `KeyPair.prove` 193.8 → 160.3 µs, control pair 1.01×.
  `mul(Edwards25519.basePoint, s)` stays on the ladder as the reference.
  New ctgrind targets `ladderbase` and `ladder` (the runtime-table path
  `voprf`/`opaque`/`bulletproofs` take, which had no target — C4), and an
  opt-in `src/bench.zig` (`CT25519_BENCH=1`, C9).
  NO CONSUMER-VISIBLE CHANGE in values or signatures; ~41 KiB more rodata.

- **2026-09-08** — **The scalar's by-value copy is now wiped here, because the
  caller cannot reach it.** `SPEC.md` said zeroization was "the caller's, on the
  scalar it supplied". A caller can wipe its own variable and nothing else: the
  copy the ABI leaves on `mul`'s frame is invisible to it. Measured with a
  painted-stack probe whose controls live inside the measurement — the 32-byte
  secret was readable in the dead frame after the call (SECRET 1, POS 1). Every
  entry point taking the scalar by value (`mul`, `mulBase`, `mulRistretto`,
  `mulRistrettoBase`) now copies it into a local and `defer`s `secureZero` on
  that copy; the three wrappers get their own wipe rather than relying on being
  inlined into `mul`, which would make the property a compiler's rather than
  the module's. Re-measured: SECRET 0 with POS still 1.
  `ecvrf` recorded the same defect from the other side — three surviving copies
  of its nonce, key algebraically recoverable — and concluded the fix belonged
  here. It does.
  Constant time unchanged: ctgrind still reports 2 contexts for `ct25519` and 3
  for `std`, so the wipe added no branch and was not elided.
  NO CONSUMER-VISIBLE CHANGE (same values, same signatures).

- **2026-08-10** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against RFC
  8032 §7.1's published test vectors.
- **2026-08-09** — New module: Constant-time-on-secrets scalar multiplication for
  Edwards25519 / Ristretto255.
