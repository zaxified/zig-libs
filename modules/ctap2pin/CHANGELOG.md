# ctap2pin — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — **BEHAVIOURAL, not breaking:** `PublicKey.toPoint` now rejects the
  point at infinity, `(0, 1)` — P-256's affine encoding of the identity element, which
  `fromAffineCoordinates` used to accept by name (`on_curve | is_identity`), so a caller
  validating a peer's `*KeyAgreementKey` with `toPoint` (its documented use) could store a
  public key with no discrete log (audit finding M1). Maps onto the existing
  `error.InvalidPublicKey`, no new error value. Zero in-repo consumers (`DECISIONS.md` P1).
  Also additive: `Protocol.fromWire(u8) error{InvalidProtocol}!Protocol` (audit finding
  L3) — the enum was documented as a wire value with no validating decoder. And
  **NO CONSUMER-VISIBLE CHANGE:** `One`/`Two` `encrypt`/`decrypt` re-bind their by-value
  `key` parameter to a local `var` and `defer std.crypto.secureZero` it, and `Two.kdf`
  does the same for its internal HKDF `prk` (audit finding M3) — a defensive hardening
  pass; measured with a dead-stack probe (`src/stackprobe_test.zig`) and the result was
  inconclusive (hit count unchanged, 2 → 2, just redistributed between needles), so M3
  stays open in `A1/ctap2pin.md` despite the source change.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `ecdhZ`'s all-zero scalar check uses `std.crypto.timing_safe.eql` instead of `std.mem.allEqual` (audit finding L1). `std.mem.allEqual` is a naive byte loop with an early return — for a real scalar it stops after roughly one byte, for the all-zero one it walks all 32 — and it was reading the SECRET scalar. ⚠ **Measured, it did not compile that way:** LLVM vectorised it into a single data-independent `vptest`, observed twice over (here and in `sphinx`), so this was never a live leak. It was **safe by accident**: `std.mem.allEqual` promises nothing about timing, nothing pins that vectorisation, and another LLVM, `ReleaseSafe` or another target turns it back into the byte loop with no test able to notice. `timing_safe.eql` promises it, which is what the MAC comparison 35 lines above already did deliberately. ⭐ The ctgrind counts do **not** move (`ecdh` stays at 4 in-file) — exactly as expected, since the binary was already branch-free; what changed is the guarantee, and `scripts/check-ct-compare.py` now pins the call so it cannot be swapped back unnoticed (it went red on this very edit, in the good direction, and was re-pinned deliberately).

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **ecdh 4 / one 7 / two 7 / token 0**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. First evidence for `SPEC.md`'s two claims ("`mul(scalar, .big)` is the constant-time scalar-mult", "both `verify`s compare MACs in constant time and fail closed") — the `token` target's clean **0** backs the second. ⭐ Confirms an audit lead and REFINES it: `root.zig:162`'s `if (std.mem.allEqual(u8, &private_scalar, 0))` does branch on raw secret-key bytes, but the implied mechanism — a byte-count-dependent early-exit scan — is refuted at the compiled level: LLVM emits one `vmovdqu`+`vptest` over all 32 bytes and a single `je`, so only the branch direction depends on the secret, the same shape as the other negligible-probability checks. The second independent sighting of `allEqual` being vectorised (see `sphinx`). ⚠ The secret here is a PIN, whose entropy is tiny, so this module's checks deserve more caution than the same shapes on a 256-bit key.

- **2026-09-07** — Test-only, no production change: `fuzzTwoDecrypt` had never decrypted
  anything. `cipher_len` came from `smith.valueRangeAtMost(u16, 0, 256)` drawn after
  `smith.bytes` had eaten the input; a ranged `Smith` draw returns the range MINIMUM when
  fewer than eight octets remain, so it was **0** on every input the ordinary lane ever ran,
  and `Two.decryptedLength(0)` returned `InvalidLength` before a single AES round. Now one
  `smith.slice(&cipher_buf)`, with a corpus that walks the length gate `Two.decrypt`
  actually has: `16 + 16k` accepted, 15 (short of the IV) and 33 (not a whole number of
  blocks) refused. Measured by the new `corpus:` guard: 6 non-empty seeds, 4 accepted
  lengths, **288 plaintext octets out of AES** (0 before). Octets rather than accepted
  lengths alone, because `decryptedLength(16)` is a legal 0 - an accepted length does not
  mean anything was decrypted.

- **2026-07-18** — Security audit: no findings. Modeled on `libfido2` (design reference,
  not a test anchor).
- **2026-07-12** — New module: CTAP2 `pinUvAuthProtocol` (FIDO2 / WebAuthn CTAP 2.1).
