# aescbc — SPEC

Raw AES-CBC (NIST SP800-38A §6.2) over `std.crypto.core.aes`'s
`Aes128`/`Aes256`, plus the two padding schemes this repo's consumers need.
`std.crypto.core.aes` (Zig 0.16) ships the AES block cipher but no CBC mode;
CBC had been hand-rolled independently in `xmlenc` (XML-Encryption content
decryption) and `jwe` (`AxxxCBC-HSxxx`, RFC 7518 §5.2). This module is the
single extracted core both are expected to collapse onto.

## API

```zig
pub const block_len = 16;

pub const Error = error{ NotBlockAligned, BufferTooSmall };
pub const PaddingError = error{InvalidPadding};

pub fn encrypt(comptime Aes: type, key: [Aes.key_bits / 8]u8, iv: [block_len]u8, plaintext: []const u8, out: []u8) Error!usize;
pub fn decrypt(comptime Aes: type, key: [Aes.key_bits / 8]u8, iv: [block_len]u8, ciphertext: []const u8, out: []u8) Error!usize;

pub fn paddedLenPkcs7(msg_len: usize) usize;
pub fn padPkcs7(msg: []const u8, out: []u8) error{BufferTooSmall}!usize;
pub fn unpadPkcs7(buf: []const u8) PaddingError!usize;

pub fn unpadXmlEnc(buf: []const u8) PaddingError!usize;
```

`encrypt`/`decrypt` are the classic chain: `C[0] = E(P[0] XOR IV)`,
`C[i] = E(P[i] XOR C[i-1])` for `i > 0`; `P[i] = D(C[i]) XOR C[i-1]`,
`C[-1] = IV`. Both operate on block-aligned buffers only
(`plaintext.len`/`ciphertext.len % 16 == 0`, including zero) — pad first if
your input isn't already block-aligned. No allocation; caller supplies `out`,
which must be at least as long as the input. Both are `comptime`-generic over
`Aes` (`std.crypto.core.aes.Aes128` or `Aes256`); the key array size is
derived from `Aes.key_bits`, so the compiler enforces the right key length
per cipher — there is no runtime key-length check to get wrong.

## Two padding schemes — pick per protocol

CBC needs the plaintext to be a block multiple; padding schemes differ in how
they encode "how much was padding" and in what they let an attacker probe.
This module offers both schemes used by consumers in this repo, as **explicit
helpers**, not baked into `encrypt`/`decrypt` — the caller picks per protocol.

### PKCS#7 (`padPkcs7` / `unpadPkcs7`) — used by `jwe`

RFC 5652 §6.3 / RFC 7518 §5.2.2.1 step 2. Every pad byte equals the pad
length `N` (`1 <= N <= 16`). Always pads — even a plaintext that is already
block-aligned gains one full block of padding (`0x10` × 16) — which is what
makes unpadding unambiguous: the pad is always present and always
self-describing, not just "the last byte if it happens to look like one."

`unpadPkcs7` validates `1 <= N <= 16` **and** that all `N` trailing bytes
equal `N`, matching what `jwe/src/enc.zig`'s `cbc_hmac.decryptImpl` already
does by hand (same accumulate-into-one-flag shape, see below).

### XML-Encryption padding (`unpadXmlEnc`) — used by `xmlenc`

W3C XML-Encryption Syntax and Processing 1.1 §5.2. The **final** byte `N`
(`1 <= N <= 16`) is the pad length; the preceding `N-1` pad bytes are
**arbitrary** — the scheme does not define their content, so `unpadXmlEnc`
only validates the length byte's range. There is deliberately no `padXmlEnc`:
the `xmlenc` module is decryption-only (it is the relying party recovering a
SAML assertion, never the party encrypting one), so there is nothing in this
repo that needs to *produce* this padding. An encoder that does need to
produce it can use `padPkcs7` — a PKCS#7-padded buffer is a valid instance of
the (looser) XML-Enc scheme, since PKCS#7's pad bytes happen to be
self-consistent too.

**Do not use `unpadXmlEnc` where `unpadPkcs7` is called for, or vice versa.**
They accept different attacker inputs as valid; picking the wrong one either
rejects legitimate ciphertext (XML-Enc bytes fed to `unpadPkcs7`, which will
usually — but not always — reject on the mismatched trailing bytes) or
under-validates PKCS#7 ciphertext (feeding it to `unpadXmlEnc`, which ignores
the very bytes PKCS#7 defines as meaningful).

## Padding-oracle caveat (read before wiring this into anything network-facing)

**CBC padding oracles are a real, practical attack class** (Vaudenay 2002,
POODLE, Lucky13's padding-adjacent timing, the "How to Break XML Encryption"
attack against xmlenc's own CBC content encryption). The shape of the attack:
an adversary who can submit chosen ciphertext and observe *whether padding
validation succeeded* (via a distinct error, a timing difference, or any
other side channel) can decrypt arbitrary ciphertext one byte at a time
without the key, by exploiting exactly the check `unpadPkcs7`/`unpadXmlEnc`
perform.

This module's unpad helpers are written defensively but **cannot fully close
the oracle on their own**:

- Both accumulate every validity check into a single flag with no
  secret-dependent early `return`/`break`, so there is no *control-flow*
  signal distinguishing "bad length byte" from "bad pad byte" from "pad byte
  N mismatch at position k" — all collapse to the same `error.InvalidPadding`
  at the same point in the function.
- Neither helper performs a MAC/tag check — CBC alone is **unauthenticated**.
  The actual, load-bearing defense is at the *protocol* layer, not here:
  - `jwe`'s `cbc_hmac` verifies the HMAC tag **before** calling any CBC
    decryption at all (encrypt-then-MAC, verify-before-decrypt), and maps a
    subsequent PKCS#7 padding failure to the exact same
    `error.AuthenticationFailed` as a tag mismatch — a caller can never tell
    the two apart. This module's `unpadPkcs7` is the piece `jwe` calls
    *after* that verification already succeeded.
  - `xmlenc` has no HMAC (raw CBC per xmlenc-core-1), so it relies on the
    caller's next step — XML-DSig signature verification of the decrypted
    assertion — to catch a padding-oracle probe's well-formed-but-wrong
    plaintext. `xmlenc`'s own SPEC.md documents this: "the robust composition
    remains decrypt → signature-verify."
- **This module cannot enforce either composition** — it has no visibility
  into whether a caller checks a MAC or a signature afterward. A caller that
  calls `decrypt` + `unpadPkcs7`/`unpadXmlEnc` directly against
  attacker-chosen ciphertext, surfaces `InvalidPadding` distinguishably from
  other failures (e.g. a different HTTP status code), and does *not*
  authenticate the plaintext some other way, **has built a padding oracle**,
  regardless of how carefully this module's internals avoid branching. Never
  wire raw CBC + one of these unpad helpers directly to attacker input
  without an authentication step ahead of or after it (prefer ahead of, per
  `jwe`'s verify-before-decrypt shape).

## AES-192 exclusion

`std.crypto.core.aes` in Zig 0.16 exports only `Aes128`/`Aes256` — no AES-192
key schedule exists in any backend (aesni/armcrypto/soft). Because this
module is `comptime`-generic over the block-cipher type rather than
dispatching on a runtime key-length enum (unlike `jwe`'s `Enc`/`xmlenc`'s
`classifyContent`, which pick a cipher from a wire algorithm identifier),
there is no third type to pass for AES-192 — an attempted call is a
**compile error** (no matching `Aes` type), not a runtime
`error.UnsupportedKeyLength`. Callers that dispatch on a runtime algorithm
identifier (as `jwe` and `xmlenc` both do) are expected to reject AES-192
themselves, before ever reaching this module — exactly as
`jwe/src/enc.zig`'s `A192CBC-HS384` arm and `xmlenc/src/root.zig`'s
`classifyContent` already do today.

## Validation

- **Byte-exact vs. NIST SP800-38A**, both directions:
  - Appendix F.2.1 (AES-128-CBC) — encrypt and decrypt, byte-exact.
  - Appendix F.2.5 (AES-256-CBC) — encrypt and decrypt, byte-exact (same
    vector transcribed in `ctap2pin/src/kat_vectors.zig` and
    `xmlenc/src/root.zig`; this module carries its own copy so it stays
    zero-dep).
- Raw-CBC edge cases: rejects non-block-aligned input/output on both
  directions, rejects an undersized `out` buffer, round-trips an empty
  message and a multi-block message.
- PKCS#7: pad/unpad round-trip (including the always-pads-a-full-block case
  for an already-aligned message) through both the helpers directly and
  through real `encrypt`/`decrypt`; rejects every malformed shape mentioned
  above (`N == 0`, `N > block_len`, an inconsistent trailing byte, empty/
  non-aligned input) with positive controls (a validly-padded buffer of the
  same shape is accepted).
- XML-Enc: accepts a valid pad with arbitrary non-final bytes (the defining
  property that distinguishes it from PKCS#7); rejects the same length-byte
  malformations; round-trips through real `encrypt`/`decrypt`.
- A std-only sanity oracle test reproduces `jwe`'s/`xmlenc`'s original
  hand-rolled CBC loop shape independently and checks it agrees with this
  module's `encrypt` byte-for-byte, so a future edit here that silently
  diverges from that shape gets caught.

## Status

`extract` — implemented and tested, both Debug and `-Doptimize=ReleaseFast`.
Zero dependencies (std-only). Not yet wired into `xmlenc`/`jwe` — both are
still using their own hand-rolled CBC loops; rewiring them onto this module
is tracked as a follow-up so their existing byte-exact RFC KATs (RFC 7518
Appendix B for `jwe`, NIST SP800-38A + the SAML round-trip suite for
`xmlenc`) stay green through the swap.

## Anchoring

**Anchor grade:** class B · oracle EXTERNAL

- **Class B** — published cryptographic or algorithmic construction with published vectors.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** NIST SP800-38A Appendix F.2.5 byte-exact vector in kat_vectors.zig
