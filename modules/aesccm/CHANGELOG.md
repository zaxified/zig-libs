# `aesccm` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-26** — **NO CONSUMER-VISIBLE CHANGE:** first dead-stack probe (`src/stackprobe_test.zig`, SPEC Backlog item): `init`, `seal`, `open`, `encrypt`, `decrypt` for AES-128/192/256, with the expanded key schedule and the plaintext as needles (CCM carries no burn). Clean. Test only.
- **2026-11-25** — AES-192 keys: `Aes192Ccm` / `Aes192Ccm8` presets and `Ccm(aes192.Aes192, ...)` over the new `aes192` dependency (same RFC 3610 core; the key-schedule context type is now derived from `Aes.initEnc`, so any block cipher shaped like std's works). Verified against an OpenSSL (Python `cryptography` AESCCM) AES-192 KAT table, all four tag/nonce profiles. No change for the AES-128/256 types.
- **2026-11-21** — New module: AES-CCM (NIST SP 800-38C, RFC 3610) generic over nonce length 7..13 and tag length 4..16, with the 12-byte-nonce TLS/DTLS 1.3 CCM / CCM_8 presets std lacks and COSE/OSCORE's 13-byte one; verified against SP 800-38C Appendix C, RFC 3610 Packet Vector #1 and an OpenSSL KAT table.
