# timelock_envelope — SPEC

Hybrid two-lock sealed envelope — see [README.md](README.md) for purpose
and API. This document is the auditor-facing design + threat model: the
construction, the field-by-field wire format, what each lock guarantees,
what an attacker recording the ciphertext today can and cannot do,
malformed-input handling, and the deliberately deferred list.

**Status: REAL — composition only.** No cryptographic primitive is
implemented here. The three locks are `tlock`, `hqc`, and `chachapoly`
used exactly as they ship; key derivation is `std.crypto.kdf.hkdf`
(HKDF-SHA256). The design is the standard hybrid AND envelope
(`age`-style two-recipient KDF), specialised to one temporal lock and one
PQ-KEM lock.

## The construction

```
seal(plaintext, ek_pq, p_pub, R, rnd):
  s_time  = rnd.s_time                       # 16 random bytes (the temporal secret)
  TL      = tlock.encrypt(p_pub, R, s_time, rnd.tlock_sigma)   # 128-byte time lock
  (PQ, s_pq) = hqc.encaps(ek_pq, rnd.kem_coins)                # KEM ct + 32-byte secret
  (K, N)  = HKDF(s_time, s_pq, R)            # content key + nonce (see below)
  AAD     = header || TL || PQ
  (ct,tag)= chachapoly.seal(K, N, plaintext, AAD)
  return  header || TL || PQ || tag || ct

open(wire, dk_pq, sig_R):
  parse wire  → (R, TL, PQ, tag, ct, AAD)    # bounds-checked, typed errors
  s_time = tlock.decrypt(sig_R, TL)          # FO check ⇒ error.TimeGateClosed if closed
  s_pq   = hqc.decaps(dk_pq, PQ)             # implicit rejection: never errors
  (K, N) = HKDF(s_time, s_pq, R)
  return chachapoly.open(K, N, ct, tag, AAD) # tag fail ⇒ error.AuthFailed
```

### Key derivation (where the AND is bound)

`HKDF-SHA256` (`std.crypto.kdf.hkdf.HkdfSha256`), two-step:

- **extract**: `PRK = HKDF-Extract(salt, ikm)` with
  - `salt = "timelock_envelope:v1:hybrid-AND:hkdf-sha256"` (fixed
    domain-separation label, so the extracted PRK can never collide with
    another protocol reusing the same `(s_time, s_pq)`);
  - `ikm = s_time (16) || s_pq (32)` — **both** lock secrets. This is the
    load-bearing bind: dropping either yields a different, non-opening
    key (proven by the positive-control tests).
- **expand**: `OKM = HKDF-Expand(PRK, info, 44)` with
  - `info = "TLE1-content-key" || version(1) || suite_id(1) || R(u64 BE)`
    — binds the key to the logical context (round, HQC parameter set,
    format version) independently of the AEAD's own AAD;
  - `OKM[0..32]` = the ChaCha20-Poly1305 key `K`;
  - `OKM[32..44]` = the 12-byte AEAD nonce `N`.

**Nonce derivation (judgement call).** The nonce is derived from the same
HKDF output rather than stored on the wire. Since `s_time` and the HQC
encapsulation randomness are drawn fresh per `seal`, `(K, N)` is
effectively unique per envelope, so there is no nonce-reuse risk and 12
wire bytes are saved. A nonce collision would require the exact same
`s_time`, `s_pq`, *and* context to recur — cryptographically negligible.

### Why this is an AND and not an OR (enforcement)

Two independent mechanisms, one per lock:

- **Time lock — enforced by `tlock`'s own FO check.** `tlock.decrypt`
  runs a Fujisaki-Okamoto consistency check and returns a typed error
  for any wrong / premature / other-round / other-beacon signature.
  Before round `R` no valid signature exists, so `s_time` is
  unrecoverable → `error.TimeGateClosed`. `open` never proceeds to the
  content on a closed time gate.
- **PQ lock — enforced by the AEAD tag.** HQC's KEM uses *implicit
  rejection*: `decaps` with the wrong secret key does **not** error, it
  returns a pseudo-random `s_pq`. That wrong `s_pq` produces a wrong `K`,
  and Poly1305 then rejects → `error.AuthFailed`. This is exactly why `K`
  must be bound to `s_pq`: the AEAD tag is the PQ lock's gate.

Because `K` depends on both secrets and the AEAD AAD covers the whole
header + both lock ciphertexts, recovering the plaintext requires opening
both locks and leaves no field swappable or tamperable undetected.

## Wire format (field by field)

All header integers are little-endian. Sizes for `Envelope128` shown in
parentheses; `hqc_ct` and total scale with the HQC parameter set.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | `magic` | ASCII `"TLE1"` |
| 4 | 1 | `version` | `1`; a parser rejects any other value |
| 5 | 1 | `suite_id` | HQC set id = its security-byte width (16/24/32); rejected on mismatch with the `Envelope`'s `Kem` |
| 6 | 1 | `flags` | reserved, currently `0`; unconstrained by the parser but authenticated as AAD |
| 7 | 8 | `round` | the drand round `R` |
| 15 | 4 | `pt_len` | plaintext length (== AEAD ciphertext length); the buffer's total size is fully determined by this |
| 19 | 128 | `tlock_ct` | the time lock — `tlock.Ciphertext.toBytes` (`U‖V‖W`) |
| 147 | `Kem.ct_bytes` (4433) | `hqc_ct` | the PQ lock — HQC KEM ciphertext |
| — | 16 | `tag` | Poly1305 tag |
| — | `pt_len` | `aead_ct` | ChaCha20 keystream ⊕ plaintext |

- **AAD** = bytes `[0 .. 19 + 128 + Kem.ct_bytes)` — header plus both
  lock ciphertexts. Everything semantically meaningful except the AEAD
  output itself is authenticated.
- **Overhead** (`Envelope128`) = 19 + 128 + 4433 + 16 = 4596 bytes.

## Security model / threat model

- **Guarantee.** The plaintext is recoverable iff (round `R` reached ⇒
  the beacon's `sig_R` is known) **AND** (the recipient's HQC secret key
  is held). Missing either → a typed error, never plaintext.
- **What an attacker recording the ciphertext today can do.** Nothing
  useful: before `R` the time lock is closed even for the intended
  recipient; the PQ lock protects confidentiality indefinitely.
- **After `R`, without the HQC key.** The attacker can recover `s_time`
  (the round signature is now public) but not `s_pq` (HQC hardness), so
  `K` is unrecoverable. This is the case the positive-control test
  weaponises: a *broken* KDF that dropped `s_pq` would be openable here,
  and the test demonstrates exactly that, proving the real construction's
  `s_pq` bind is what closes it.
- **Quantum adversary (the honest caveat).** `tlock` is pairing-based and
  **not** post-quantum. A future quantum adversary could forge the timing
  lock — but the PQ lock (`hqc`, code-based) still holds, so long-term
  confidentiality survives. The timelock half enforces *timing* only;
  this module never claims a "post-quantum timelock." Conversely, the
  timing guarantee itself rests on the drand beacon's threshold model
  (no coalition below threshold can produce `sig_R` early) — a temporal
  assumption, not a computational-hardness one.
- **Beacon trust.** `p_pub` and `sig_R` are caller-supplied; this module
  runs no beacon and no DKG, and does not verify `sig_R` against `p_pub`
  (a separate `bls12_381.bls_sig`-style pairing check the caller performs
  when crossing a trust boundary — the same contract `tlock` itself has).
  `tlock`'s FO check nonetheless rejects any `sig_R` that is not the
  correct round key, so a wrong signature cannot open the envelope even
  if it is unverified.
- **Malleability / tamper.** ChaCha20-Poly1305 over the full AAD makes
  every header field and both lock ciphertexts tamper-evident; the round
  number is additionally bound into `K` via the HKDF `info`.

## Malformed-input handling

`parse` is a pure, bounds-checked function: it validates length ≥ header,
magic, version, suite id, and that the buffer size exactly matches the
declared `pt_len` before returning any field view. It never panics, reads
out of bounds, allocates, or loops. Because total size is derived from
`pt_len` and checked against the actual buffer, a small malformed buffer
can never induce a large allocation in `open` (no OOM vector). `open`
then maps a malformed `tlock` region to `MalformedTimeLock` and any
authenticity failure to `AuthFailed`. A `std.testing.fuzz` harness drives
`open` with both random and mutated-valid inputs and asserts it never
panics and never returns a wrong plaintext (see `security_test.zig`).

## Verification

- Round-trip against **real** drand quicknet data: seal to round 1000
  with quicknet's master public key, open with the published round-1000
  signature (the same pairing-verified vector `tlock`'s KAT pins). This
  obtains the round secret deterministically with no live drand.
- Round-trip across all three HQC parameter sets (`Envelope128/192/256`).
- The three AND negatives: wrong/absent round signature →
  `TimeGateClosed`; wrong HQC secret key → `AuthFailed`; different-round
  signature → `TimeGateClosed`.
- Per-region tamper: flipping a byte in the round field, `tlock_ct`,
  `hqc_ct`, tag, or content each fails with a typed error; corrupting
  magic/version/suite fails at parse; truncation is rejected.
- Positive controls: an s_pq-dropping KDF is shown to make the
  wrong-PQ-key attack succeed (so the negative is a real detector), while
  the real key demonstrably depends on both `s_time` and `s_pq` (and on
  round/suite/version).

## Deliberately deferred (out of scope)

- **Streaming / very large payloads.** `seal`/`open` are one-shot and
  buffer the whole plaintext; `pt_len` is a `u32`. A chunked AEAD framing
  for multi-gigabyte payloads is a separable follow-up.
- **`age`-file / armored interchange format.** This module ships its own
  compact binary envelope, not `filippo.io/age` stanza framing. Interop
  with drand's `tle` file format is not a goal.
- **Beacon operation and signature verification.** No drand node, no DKG,
  and no `sig_R`-vs-`p_pub` pairing check (caller's responsibility, as in
  `tlock`).
- **Multiple recipients / threshold PQ locks.** A single HQC recipient
  per envelope; N-of-M or multi-recipient KEM wrapping is not modelled.
- **Key/parameter agility beyond the three HQC sets and the single
  ChaCha20-Poly1305 / HKDF-SHA256 suite.** `version`/`suite_id` leave
  room to add suites later; only the shipped one is implemented.
- **Metadata privacy.** `round`, `suite_id`, and `pt_len` are in the
  clear (authenticated, not encrypted) — the envelope hides content, not
  the fact that it targets round `R`.
