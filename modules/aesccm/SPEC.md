# `aesccm` — specification

## Maturity

**Grade:** *(written by `zig build gen-catalog` — never by hand)*

**Scope:** core — NIST SP 800-38C / RFC 3610 AES-CCM as OpenSSL and Python `cryptography` (`AESCCM`) offer it (surveyed 2026-11-21)

**Audit:** review none · mutation none · src ?

**Hardening:** fuzz none — harness `aesccm-open` exists, not yet budget-run · ct 2026-11-21 (ctgrind `aead`: key and plaintext tainted through seal / open / tampered open, AES-128 and AES-256, tags 8 and 16)

**Performance:** not measured

**Known defects:** none recorded

**Downstream consumer:** no

## Compared with

Surveyed 2026-11-21 per `SURVEY-PLAYBOOK.md`.

| Project | Language | Licence | Stars | Last release / push | What a user notices against this module |
|---|---|---|--:|---|---|
| [pyca/cryptography](https://github.com/pyca/cryptography) `AESCCM` — **reference** | Python (OpenSSL) | Apache-2.0 OR BSD-3-Clause | 7.4k | 46.0 (2026) | Any nonce 7..13 bytes, tag 4..16 (even), AES-128/192/256, one-shot `encrypt`/`decrypt`. This module: the same nonce and tag ranges, AES-128/256, one-shot and a keyed context; no AES-192. |
| [openssl/openssl](https://github.com/openssl/openssl) `EVP_aes_*_ccm` | C | Apache-2.0 | 30.9k | openssl-4.0.3 | The same construction through the EVP interface (nonce length and tag set by ctrl calls); streaming input is not allowed for CCM there either. |
| [RustCrypto/AEADs](https://github.com/RustCrypto/AEADs) `ccm` | Rust | MIT OR Apache-2.0 | 800 | ccm 0.5 | Generic over cipher, nonce size (7..13) and tag size (4..16) as type parameters, like this module's comptime ones *(inferred from its README)*. |
| Zig `std.crypto.aead.aes_ccm` (0.17.1) | Zig | MIT | — | Zig 0.17.1 | Exports only 13-byte-nonce presets; the generic `AesCcm` is private, so the 12-byte TLS/DTLS 1.3 profile is unreachable. The reason this module exists. |

**Where we are ahead:** the 12-byte-nonce profile in Zig at all; errors instead of asserts at the API boundary.
**Where we are behind:** AES-192 keys (std has no AES-192 key schedule here; `aes192` could supply one — Backlog).

## What this module is, and what it is not

AES in CCM mode: CBC-MAC over `B_0 ‖ encoded(ad) ‖ m` (RFC 3610 §2.2) encrypted with `S_0`, and CTR encryption from
counter 1 (§2.3). The nonce length `n` (7..13) and tag length `M` (4, 6, …, 16) are comptime parameters; `L = 15 - n`
bounds the message at `2^(8L) - 1` bytes (`max_message_len`). Built for DTLS 1.3 / TLS 1.3 CCM and CCM_8 (RFC 8446
§B.4, 12-byte nonce, tags 16 / 8) and COSE / OSCORE AES-CCM-16-64-128 (RFC 8152 §10.2, 13-byte nonce, tag 8).

Not here: CCM* encryption-only (tag 0, IEEE 802.15.4; std's `Aes128Ccm0` has it), streaming (CCM needs the message
length up front), AES-192.

## Wire format / algorithm

RFC 3610 §2 exactly: `B_0` flags `64·Adata + 8·(M-2)/2 + (L-1)`, then the nonce and `l(m)` in `L` bytes; the
additional data is prefixed by its length in 2 bytes below `2^16 - 2^8`, `0xfffe` + 4 bytes below `2^32`, `0xffff` +
8 bytes beyond, and zero-padded to a block; the message is zero-padded. `A_i` = flags `L-1`, nonce, counter `i` in
`L` bytes; `S_0` encrypts the MAC, `S_1…` the message.

## Constant-time contract

Secret: the key and the plaintext. The block cipher is std's AES (AES-NI / ARMv8 Crypto Extensions where present,
otherwise its table-free software path). The tag comparison is `std.crypto.timing_safe.eql`; the only data-dependent
branch is that one verdict (accept / reject), after which a rejected plaintext buffer is zeroed. Lengths (message,
additional data) are public. Machine-checked by `scripts/checks/ctgrind.sh aesccm` (row in
`scripts/checks/ctgrind-expected.tsv`).

## Limits and refusals

- `c.len != m.len` → `error.BufferSizeMismatch` (std asserts).
- `m.len > max_message_len` (65535 for a 13-byte nonce, 2^24 - 1 for 12) → `error.MessageTooLong`.
- Tag mismatch → `error.AuthenticationFailed`, plaintext buffer zeroed.
- Invalid nonce or tag length is a compile error.

## Anchoring

- **External:** NIST SP 800-38C Appendix C Example 3 (12-byte nonce, 8-byte tag) and RFC 3610 Packet Vector #1
  (13-byte nonce, 8-byte tag), byte for byte; a KAT table from OpenSSL through Python `cryptography`'s `AESCCM`
  (`tools/ccm_kats.py` is the recipe): AES-128/256, tags 8/16, nonces 12/13, empty and multi-block messages, additional
  data of 0..70000 bytes including both sides of the `0xff00` length-encoding switch.
- **Re-derived:** std's `Aes128Ccm16` (13-byte nonce) over the same inputs.

**Anchor grade:** class A · oracle EXTERNAL

## Verification

`scripts/modtest aesccm`: the vectors above, the fuzz harness `aesccm-open` (`src/fuzz_test.zig`, `AESCCM_FUZZ=<runs>`;
four profiles, genuine opened, damaged ciphertext / tag / AD / nonce / truncation refused with the buffer zeroed), every single-bit flip of ciphertext and tag rejected with the plaintext
zeroed, additional data / nonce changes rejected, the boundary errors. `scripts/checks/ctgrind.sh aesccm`: target
`aead`. The card's `**Audit:**` line is the current review/mutation score.

## What is deliberately not done

- **CCM\* (tag length 0).** Unauthenticated encryption; std's `Aes128Ccm0` covers IEEE 802.15.4, nothing in this
  collection needs it.

## Backlog / deferred

- **AES-192 keys** via the `aes192` module (Python `cryptography` and OpenSSL accept them; no protocol this collection
  speaks uses AES-192-CCM). Effort: small.
- **OSCORE on this module.** `oscore` uses std's `Aes128Ccm8` (13-byte nonce) today; switching it to
  `Aes128Ccm8Nonce13` is a one-line change once a consumer wants a single CCM core.
