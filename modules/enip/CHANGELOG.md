# enip — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-11** — Security audit: seven findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on `OpENer` /
  `EIPScanner` (design reference, not a test anchor).
- **2026-07-23** — New module: EtherNet/IP + CIP — encapsulation layer
  (register/unregister session, SendRRData/SendUnitData), CIP messaging (Get/Set
  Attribute, Multiple Service Packet), connection manager, and a tag/symbolic path.
