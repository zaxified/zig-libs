# aeskw — spec

RFC 3394 AES Key Wrap. Usage: see ./README.md.

## Scope

- **RFC 3394 only** (the unpadded "AES Key Wrap" construction, §2.2.1 wrap / §2.2.2 unwrap /
  §2.2.3.1 default IV). `plaintext`/recovered key data is always a multiple of 8 bytes, >= 16
  (>= 2 semiblocks) — the RFC's own domain.
- **RFC 5649 (AES Key Wrap with Padding, for key data that isn't an 8-byte multiple) is
  deferred, not implemented.** No in-repo consumer (`jwe`, `dnp3`, `xmlenc`) needs it today —
  all three only ever wrap fixed-size, already-8-byte-aligned symmetric keys (AES-128/192/256,
  HMAC keys). Adding it later is additive (a new `wrapPad`/`unwrapPad` pair layering RFC 5649
  §4.1's alternative IV + padding scheme on top of this module's block-recurrence core) and
  would not change this module's existing `wrap`/`unwrap` signatures or KATs.
- **KEK width: AES-128 (16-byte) and AES-256 (32-byte) only.** A 192-bit (24-byte) KEK returns
  `error.UnsupportedKeyLength` — Zig 0.16's `std.crypto.core.aes` ships `Aes128`/`Aes256` but no
  AES-192 block cipher, a real std gap rather than a design choice. If std ever adds AES-192,
  `encBlock`/`decBlock`'s two-arm `switch (kek.len)` is the only place that needs a third arm.

## Design & invariants

- **Registers laid out in the caller's `out` buffer, not a fresh allocation.** `wrap` writes
  `A(8) || R1 || R2 || ... || Rn` directly into `out` and the 6-round/`n`-block double loop
  (RFC 3394 §2.2.1) shifts `A` through a local `[8]u8` while `R[i]` is updated in place inside
  `out`; `unwrap` mirrors this over `ciphertext`'s trailing `R` blocks. No allocation anywhere in
  the core — every buffer is either caller-supplied (`out`) or a fixed-size stack `[8]u8`/`[16]u8`
  block. This matches the "never panic, no hidden allocation" requirement all three future
  callers (`jwe`, `dnp3`, `xmlenc`) already rely on.

- **Exact recurrence, both directions.** `wrap`'s inner loop computes
  `B = AES-encrypt(KEK, A || R[i])`, then `A = MSB(64, B) XOR t` (`t = n*j + i`, 1-indexed per the
  RFC, XORed big-endian into the top 8 bytes only) and `R[i] = LSB(64, B)`, for `j` in `0..6` and
  `i` in `0..n`. `unwrap` runs the same recurrence backwards (`j` from 5 down to 0, `i` from
  `n-1` down to 0) with AES-decrypt in place of AES-encrypt and `A = MSB(64, B) XOR t` computed
  *before* decrypting (since `t` was XORed in after encryption on the way in). Byte-exact against
  RFC 3394 §4.1 (128-bit KEK / 128-bit key, n=2), §4.3 (256-bit KEK / 128-bit key, n=2), §4.5
  (256-bit KEK / 192-bit key, n=3 — the odd-n case), and §4.6 (256-bit KEK / 256-bit key, n=4),
  each direction independently checked against the RFC's published ciphertext.

- **Constant-time integrity check, fail-closed and clean.** `unwrap`'s only accept/reject
  decision is the final comparison of the recovered register `A` against `default_iv`
  (`A6A6A6A6A6A6A6A6`, RFC 3394 §2.2.3.1) — done via `std.crypto.timing_safe.eql` rather than
  `std.mem.eql`/`==`, so a wrong KEK or a corrupted ciphertext byte can't be distinguished by
  comparison-time (an early-exit compare here would leak how many of the 8 IV bytes happened to
  match before the mismatch, a real oracle in a network-facing key-unwrap path like DNP3 SAv2's
  session-key change or an XML-Enc `kw-aes*` EncryptedKey). On any decrypt-block failure
  (`UnsupportedKeyLength`, propagated from mid-loop) or on integrity-check failure, the entire
  scratch `R` region inside `out` is wiped with `std.crypto.secureZero` before the function
  returns — a failed unwrap never lets the caller observe partially-recovered, KEK-derived
  plaintext bytes. Verified by a dedicated test with **both** a wrong-KEK and a
  single-bit-corrupted-ciphertext case, each checked for `error.Unauthentic` *and* an
  all-zero `out`, plus a same-shape correct-KEK positive control proving the zeroing path isn't
  masking a wrap/unwrap bug.

- **Length discipline, typed, with positive controls at the boundary.** `wrap`: `plaintext.len`
  must be `>= 16` and a multiple of 8, else `error.InvalidLength`; `out.len < plaintext.len + 8`
  is `error.BufferTooSmall` (checked after the length-multiple check, so a too-small buffer for a
  malformed-length input still reports `InvalidLength` first — the input shape is invalid
  independent of what buffer was handed in). `unwrap`: `ciphertext.len` must be `>= 24` and a
  multiple of 8, else `error.InvalidLength`; `out.len < ciphertext.len - 8` is
  `error.BufferTooSmall`. The exact boundary values (16-byte wrap input, 24-byte unwrap input)
  are exercised as positive controls in the same test that checks the `< 16`/`< 24` rejections,
  so the boundary itself is proven inclusive, not just "some large input works."

## Provenance

Original work of the zig-libs authors (MIT), implemented directly from the RFC 3394 text — an
open IETF Standards-Track specification, not a copyrightable work (merger doctrine; see
CONVENTIONS.md §5). This module **extracts and re-validates** a construction that had
independently accreted three times in this repo before existing as its own module:
`modules/jwe/src/aeskw.zig` (A128KW/A256KW, RFC 7518 §4.4), `modules/dnp3/src/sa.zig`'s `aeskw`
namespace (SAv2 session-key wrap, IEEE 1815-2012 §7), and `modules/xmlenc/src/root.zig`'s
unwrap-only local core (`kw-aes128`/`kw-aes256`, XML Encryption 1.1). All three were already
byte-exact against RFC 3394 §4.1; this module additionally proves §4.3/§4.5/§4.6 (covering both
KEK widths and the n=2/3/4 block-count cases) and is the version those three modules are expected
to adopt in a follow-up (no code from them is imported here — this module has zero deps, per the
pre-registered `build.zig` entry).

No GPL/LGPL/AGPL source was consulted or copied. `std.crypto.core.aes` (`Aes128`/`Aes256`),
`std.crypto.timing_safe.eql`, and `std.crypto.secureZero` are used via their public std APIs
(MIT, part of Zig itself).

## Threat model / out of scope

Designed for a symmetric-key-management path where the KEK is a trusted local secret and the
wrapped blob may arrive over an untrusted channel (SAv2 session-key change on the wire, an
XML-Enc `EncryptedKey`, a JOSE `A128KW`/`A256KW` Encrypted Key) — `unwrap` never trusts the
ciphertext's length or content, rejects malformed shapes before touching AES, and fails closed
without a plaintext-derived timing or content leak. Not covered: key derivation/agreement (how
the KEK itself was established — out of this module's scope, same posture as RFC 3394 itself),
and RFC 5649 padding (see "Scope" above).
