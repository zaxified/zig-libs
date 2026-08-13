# isis — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: — and
  re-verified first-hand, not trusted.
- **2026-07-24** — New module: IS-IS (ISO/IEC 10589) PDU codec — common header + TLV
  framework + IIH/LSP PDUs + SPB (802.1aq) TLVs + raw-TLV escape hatch; pure
  bounds-checked encode/decode of untrusted link bytes, the wire.
