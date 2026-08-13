# blobmsg — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: Wire format
  is clean-room from named OpenWRT sources and byte-parity-verified against `ubus -S`
  per README.
- **2026-07-05** — New module: OpenWRT ubus client + blob/blobmsg wire codec.
