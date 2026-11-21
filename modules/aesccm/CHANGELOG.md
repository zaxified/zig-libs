# `aesccm` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-21** — New module: AES-CCM (NIST SP 800-38C, RFC 3610) generic over nonce length 7..13 and tag length 4..16, with the 12-byte-nonce TLS/DTLS 1.3 CCM / CCM_8 presets std lacks and COSE/OSCORE's 13-byte one; verified against SP 800-38C Appendix C, RFC 3610 Packet Vector #1 and an OpenSSL KAT table.
