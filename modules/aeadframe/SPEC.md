# aeadframe — design & threat model

Purpose and API: see [README.md](README.md). This document is the auditor
altitude — the wire format, the nonce-uniqueness and rekey safety arguments,
the replay-window semantics, the untrusted-decode threat model, and what is
deferred. Meta tags live in `src/root.zig`; this file does not restate them.

## 1. Model

The IPsec ESP (RFC 4303) / DTLS 1.3 (RFC 9147 §5) record layer, distilled: a
per-key channel that turns a plaintext into a self-describing record and back,
with (a) a monotonic sequence number that both drives a never-repeating nonce
and feeds an anti-replay window, and (b) an epoch that partitions the nonce
space across rekeys. Unlike ESP/DTLS this layer is transport-agnostic and does
**no key agreement** — the key is an input (§6).

It is a *composition* module: it calls existing, already-KAT'd AEADs
(`chachapoly.ChaCha20Poly1305`, `std.crypto.aead.aes_gcm.Aes256Gcm`) and
implements no cipher or MAC. `Channel(Aead)` is comptime-generic over any AEAD
presenting the 32/12/16 shape and the `encrypt(c,tag,m,ad,npub,k)` /
`decrypt(m,c,tag,ad,npub,k)` signature (a comptime assertion enforces the
lengths).

## 2. Wire format

A record is `header ‖ ciphertext ‖ tag`, all integers big-endian:

```
  offset  size  field
  0       1     version    = 1
  1       4     epoch      (u32)
  5       8     seq        (u64)
  13      N     ciphertext (N = plaintext length, N ≥ 0)
  13+N    16    tag        (AEAD authentication tag)
```

`overhead = 29` bytes (13 header + 16 tag). There is **no explicit
ciphertext-length field**: `N = record.len − overhead`, recovered by `parse`.
Omitting the length field removes a whole class of parser bug (length-field vs
actual-length disagreement) — the slice length *is* the length.

The header is **not** concatenated into the AEAD associated data. It does not
need to be: every header field is already integrity-protected.

- `epoch` and `seq` are the nonce (§3). Flipping either changes the nonce the
  receiver derives, so the tag fails — a tampered `epoch`/`seq` is caught as
  `EpochMismatch` (epoch is also checked explicitly) or `AuthenticationFailed`.
- `version` is validated explicitly (`UnsupportedVersion`).

So the caller's `aad` is passed to the AEAD verbatim, keeping `seal`/`open`
zero-allocation (no need to build a `header ‖ aad` buffer for an arbitrary-length
`aad`), while header tampering remains a guaranteed failure. This is the one
non-obvious design choice; it is deliberately documented here so an auditor does
not read the missing header-in-AAD as an oversight.

## 3. Nonce construction and its uniqueness argument

```
nonce = epoch (4 bytes, big-endian)  ‖  seq (8 bytes, big-endian)   // 12 bytes
```

`deriveNonce : (u32, u64) → [12]u8` writes the two fields into disjoint, fixed
byte ranges, so it is **injective**: `deriveNonce(e₁,s₁) = deriveNonce(e₂,s₂)`
iff `(e₁,s₁) = (e₂,s₂)`. Nonce uniqueness under one key therefore reduces to
`(epoch, seq)`-pair uniqueness under one key, which the `Sealer` guarantees:

1. Within one epoch, `seq` starts at 0 and increments by exactly 1 per `seal`.
   `seal` refuses (`error.SequenceExhausted`) when `seq == maxInt(u64)` rather
   than wrapping — a wrapped `seq` would repeat a nonce, catastrophically
   breaking a counter-mode AEAD (keystream reuse / forgery). The usable space is
   `2⁶⁴−1` messages per epoch.
2. Across epochs under the same key, `epoch` occupies the high 4 bytes and is
   strictly increasing (see §4), so records from different epochs cannot collide
   even when they reuse a `seq` value.

Hence within a `Sealer`'s lifetime no nonce is ever reused. (Constructing a
*fresh* `Sealer` with a `(key, epoch)` pair already used elsewhere is the
caller's responsibility — the guarantee is per live Sealer; see §6 deferred.)

The `chachapoly` and std AEADs both build their internal counter from a 96-bit
nonce; a distinct 12-byte nonce is exactly what each needs to stay in its safe
domain.

## 4. Epoch / rekey nonce-safety

Two rekey paths, both nonce-safe, chosen by policy:

- **`rekey(new_key, new_epoch)` — new key.** A fresh key gives an independent
  keystream, so nonce reuse across the boundary is impossible regardless of
  epoch numbering, and (if the old key is destroyed) it provides forward
  secrecy. This is the recommended production path. Because `rekey` also resets
  `seq` to 0, it is safe **only** when the `(key, epoch)` pair it installs is
  unspent; the sealer enforces the part of that it can see (below).
- **`bumpEpoch()` — same key, epoch += 1, `seq` reset to 0.** Nonce-safe
  because the epoch is embedded in the nonce and strictly increases: epoch 0
  uses nonces `00000000·{0,1,…}`, epoch 1 uses `00000001·{0,1,…}`, and the two
  sets are disjoint in the epoch field. `bumpEpoch` refuses at
  `epoch == maxInt(u32)` (`error.EpochExhausted`) so the epoch never wraps and
  never repeats for a key. It gives **no forward secrecy** (a key compromise
  exposes every epoch) — that is a policy tradeoff, not a nonce hazard.

The coordinator's brief flagged "reset the sequence counter to 0 on rekey" as a
potential nonce-reuse trap. It is **safe here specifically because the epoch is
part of the nonce and is monotone** — resetting `seq` to 0 under a *new* epoch
(or a new key) lands in a fresh nonce subspace. Resetting `seq` while keeping
both key *and* epoch unchanged is the unsafe version, and `Sealer.rekey` — the
one entry point that could express it — **refuses it**: if `new_key` equals the
current key and `new_epoch` does not strictly advance past the current epoch,
it returns `error.NonceSpaceReuse` with the sealer's state untouched. `seal`
and `bumpEpoch` cannot express it at all (both are strictly increasing and
refuse at their ceilings), so no sequence of calls on a live `Sealer` emits a
nonce twice, with the single exception recorded in §8 (re-installing a key this
sealer used *earlier*).

Note the asymmetry with a *different* key: `rekey` imposes no epoch ordering
there, because an independent key gives an independent keystream and the epoch
field is then irrelevant to collision. `Opener.rekey` stays infallible — a
receiver emits no nonce, so it has no nonce space to spend.

> History: until this guard existed, `SPEC.md` asserted at this point that "the
> API offers no such operation", while `Sealer.rekey` accepted exactly it and
> silently reset `seq`. The sentence is corrected rather than deleted so the
> claim and the check are visibly the same statement.

On the receive side, an epoch change (`bumpEpoch`/`rekey`) **resets the replay
window** — the old sequence numbers describe a spent nonce space and carry no
replay meaning under the new one. An old-epoch record presented to an advanced
opener is rejected with `error.EpochMismatch` before any crypto.

This module implements **explicit, caller-driven** epoch transitions on both
ends (no automatic negotiation). Out-of-order delivery *across* an epoch
boundary is not handled — a record from the previous epoch arriving after the
opener has advanced is dropped (see §6).

## 5. Anti-replay window

`ReplayWindow` is the standard IPsec/DTLS bitmap window (RFC 6479): a
high-water mark `highest` plus a `u64` `bitmap` where bit *i* records that
`highest − (i+1)` has been committed. Width `size` (default 64) is clamped to
64 by the bitmap capacity — a conscious ceiling.

**On the 64-counter ceiling, and why it is not inherited debt.** WireGuard
reserves a far larger window (2^13 counters) for the same job, so a reader
coming from `wireguard` may read this `u64` as an under-built version of that.
It is not. This module is a generic AEAD record framer, not a WireGuard
implementation, and it makes no claim to WireGuard's window size; 64 is the
IPsec/DTLS (RFC 6479) default and is sized for the reordering a record stream
of this kind actually sees. Widening the bitmap is a **design decision for
this module's owner**, driven by a consumer that measurably needs a deeper
window — not a defect to be fixed and not a debt inherited from `wireguard`.
Do not file it as one.

- `accepts(seq)` (read-only): `true` if `seq > highest` (fresh), or within the
  window (`0 < highest − seq ≤ size`) and its bit is clear. A duplicate of
  `highest` (`diff 0`) or a too-old `seq` (`diff > size`) returns `false`.
- `commit(seq)`: slides the window on a new high (shifting the bitmap and
  setting the old mark's bit), or sets the in-window bit for a late arrival.

**Verify-then-commit ordering.** `Opener.open` calls `accepts` as a cheap
pre-filter, runs the AEAD, and calls `commit` **only after** the tag verifies.
Committing an unverified `seq` would let an on-path attacker replay/forge a
record with a future `seq` to "burn" that window slot and get the genuine
record later rejected as a replay it never was. The pre-check only ever
*rejects*; it never advances state, so an attacker who cannot forge a tag
cannot move the window.

The window is validated in `replay.zig` against a brute-force reference oracle
(a plain `HashMap` set with the same age cutoff) over a 4000-step randomised
trace at widths 8/32/64, plus explicit edge sweeps (exactly-at-edge, jump past
the window, oversized `size` with hostile diffs → no panic).

Clamping guards a real latent panic: without it, a hostile `seq` producing a
`diff`/`shift` in 64..127 would `@intCast` to `u6` and panic — a config-gated
crash on attacker-influenced input. `eff()` caps at 64 so every shift fits a
`u6`.

## 6. Untrusted-decode threat model

`Opener.open` treats the record as fully attacker-controlled. Guarantees on
arbitrary bytes:

- **Bounded, total parse.** `record.parse` checks `len ≥ overhead` and the
  version before any indexing; a short or wrong-version record returns
  `error.Truncated` / `error.UnsupportedVersion`. No out-of-bounds read, no
  loop, no panic.
- **No allocation.** `seal` and `open` write into caller buffers; there is no
  allocator and nothing sized by attacker-controlled length beyond the caller's
  own `out` (checked with `BufferTooSmall`). Memory use is `O(input)` and fixed.
- **Fail-closed, no garbage.** On any failure (`Replayed`, `EpochMismatch`,
  `AuthenticationFailed`) the plaintext region of `out` is zeroed — including
  the AES-GCM path, where std leaves `m` undefined on auth failure, so both
  instantiations honour "never garbage plaintext".
- A `std.testing.fuzz` harness (`fuzzOpen`) drives `open` over Smith-generated
  bytes and asserts only a typed error or a plaintext length `≤` input — never a
  panic, OOB, or hang.
- **No stream-termination signal — a per-record guarantee, not a stream one.**
  Every guarantee above is about ONE record: tamper detection, replay
  rejection, fail-closed on failure. Nothing in `header_len`/the record
  format carries a terminator, a total-message-count, or any other marker of
  "this is the last record." An attacker who truncates the underlying
  transport after any complete, validly-authenticated record removes every
  record after that point with no evidence left for `Opener` to detect —
  each delivered record still authenticates individually. This is not a
  defect specific to this module (ESP and DTLS 1.3 leave the identical gap
  to a higher layer, e.g. a length-prefixed application message or an
  explicit close-notify), but this module's own docs previously did not say
  so despite framing itself as a complete record layer. **The caller's
  transport/application layer is responsible for detecting stream
  truncation** — e.g. a length-prefixed outer message, a sequence-number
  gap check against an expected total, or an explicit terminator record the
  caller defines above this layer. `aeadframe` does not provide one.

## 7. Verification

- **KAT (framing anchor).** One record with fixed key/epoch/seq/aad/plaintext
  is pinned byte-exact: header bytes (hand-verifiable) plus ciphertext+tag
  produced independently by `std.crypto.aead.chacha_poly` (byte-identical to
  the `chachapoly` sibling) for `nonce = deriveNonce(0x11223344, 42)`. This
  anchors the header layout, endianness, nonce construction, and record framing
  — it does not re-KAT the cipher, which `chachapoly`/std already do. A pure
  12-byte nonce-layout KAT anchors the endianness independently.
- **Both AEADs.** The behavioural suite (round-trip, empty plaintext, AAD
  mismatch, ciphertext/tag/header tamper, monotonic nonce, sequence ceiling,
  replay, epoch/rekey) runs `inline for` over `{ChaChaChannel, AesGcmChannel}`.
- **Positive controls (permanent).** Two sentinels prove the safety tests have
  teeth: a broken nonce derivation that drops the epoch is shown to *collide*
  (so the real injectivity test would go red on that regression), and an
  always-accept replay stub is shown to *admit* a duplicate the real window
  rejects.

## 8. Deferred / out of scope

- **Key agreement / handshake.** No Noise/HPKE/X25519 here — the key is an
  input. A future module (or the fabric orchestrator) performs the handshake and
  hands `aeadframe` the per-tenant key.
- **Key-rotation policy.** *When* to `bumpEpoch` vs install a fresh key (time,
  byte count, message count, forward-secrecy target) is a caller policy; this
  module only makes each transition nonce-safe.
- **Cross-`Sealer` nonce uniqueness.** Guaranteed within one live `Sealer`. A
  caller that reconstructs a `Sealer` on the same `(key, epoch)` — e.g. after a
  crash without persisting `seq` — must supply a fresh key or a never-before-used
  epoch. Durable sequence-number/epoch persistence is a caller concern. The same
  limit applies *within* a sealer to re-installing an earlier key: `rekey` holds
  only the current key, so `rekey(A,0) → rekey(B,9) → rekey(A,0)` is accepted
  even though key A's epoch 0 is spent. Detecting it would require the sealer to
  retain every key it has held, which is the opposite of the forward secrecy
  `rekey` exists to provide — so it is a caller obligation, stated rather than
  enforced.
- **Out-of-order delivery across an epoch boundary.** Records straddling a
  rekey are dropped as `EpochMismatch`; a multi-epoch opener (keeping the
  previous epoch's key+window alive during a transition window) is not built.
- **Multi-channel / tenant map.** One `Channel` is one `(key, epoch)` context.
  The I-SID → channel map is orchestration glue above this module.
- **Concurrency.** `single_owner`: a `Sealer`/`Opener` is owned by one
  thread/loop and holds no lock. Sharing one across threads is the caller's to
  synchronise.

## Anchoring

**Anchor grade:** class D · oracle n/a

- **Class D** — our own design — no third party exists to agree with, by construction.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** own composed record framing inspired by RFC4303/9147, wire format defined in SPEC.md
