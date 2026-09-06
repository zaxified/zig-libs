# bech32 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-06** — **`base58` wipes its scratch buffers, and the guards the 2026-09-06 audit
  found untested now have teeth.** Findings A1 H1/H2/M2/M3/M4/L3.
  - **H2 (zeroization):** `encode`'s base-58 digit buffer, `decode`'s byte buffer and both
    Base58Check staging buffers are wiped on every exit (`std.crypto.secureZero`, `defer`
    registered before the fill). WIF and `xprv` go through here; `bip32` wiped its own copy and
    this module left one more after `checkEncode` and two after `checkDecode` on the dead stack
    in ReleaseFast. No behaviour change. The module doc and SPEC now also say plainly that
    `base58` is **not constant-time** (M1: `alphabet[d]` indexed by the payload's digits) — a
    documented limit, not a fix.
  - **H1 (test):** `decode`'s `BufferTooSmall` guard — the only thing between a 180-`1` paste
    and a write past `checkDecode`'s 132-byte buffer (48 bytes over, silently, in ReleaseFast
    with the guard removed) — is pinned in both directions and on the envelope.
  - **`checkEncode`'s bound is now on the envelope:** a payload longer than `max_payload_len - 4`
    is `PayloadTooLarge` at the entry rather than after the checksum was computed and the payload
    copied, where `encode` rejected `payload ++ checksum` with the same error. A payload of
    125–128 bytes never succeeded before either; no real Bitcoin payload exceeds 78.
  - **Tests for guards no test held:** every checksum byte is compared, not only the last (M4);
    the HRP is compared whole — `bcrt` is not `bc` (M2); an incomplete tail group of 5 zero bits
    is `InvalidPadding` (M3, the second half of BIP173's rule, which the official invalid
    vectors do not exercise). Each was measured to survive a weakening with a green suite.
  - **Fuzz (L3):** the three harnesses use `smith.slice` and carry seeds (real addresses and the
    180-`1` boundary); each saw a single empty input before.

- **2026-08-06** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against the
  complete official BIP-173 and BIP-350 vector sets, including every invalid vector.
- **2026-07-21** — New module: Bitcoin address encodings — bech32 (BIP173) + bech32m
  (BIP350) generic codec (BCH checksum, HRP expansion, charset), segwit address
  encode/decode with the consensus rules (witness version 0–16, program 2–40 bytes,
  exactly 20 or 32 for v0, and the variant required to match the witness version), and
  base58 + base58check (double-SHA256 checksum) with P2PKH / P2WPKH-program helpers over
  `ripemd160`'s `hash160`.
