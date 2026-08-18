# enip — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — Portability fix (`check-portable`): the "huge index" overflow test
  built `wrapping_index` from a hardcoded `1 << 63`, which doesn't fit `usize` on a
  32-bit target. The literal's job was "half of `usize`'s range, rounded up, so `* 2`
  wraps" — a target-relative property, not a 64-bit-specific one — so replaced it with
  `(std.math.maxInt(usize) / 2) + 1`, which equals the original `1 << 63` exactly on
  64-bit and generalizes correctly to any width. Compile-only, identical behaviour on
  every target that already built. Verified: `zig build portable-enip` and
  `zig build test-enip --summary all` (164/167, 3 pre-existing skips) both green.
- **2026-08-14** — Provenance corrected: README stated that no third-party source
  had been consulted as a design reference, while `src/connmgr.zig:250` cites
  `epan/dissectors/packet-cip.c` and the internal `hf_cip_cm_fwo_*` field
  identifiers — names visible only in Wireshark's source, not in anything
  `rawshark` prints. The module was genuinely oracle-only when it was written;
  `5f9685e` later derived the `ConnectionParameters` reserved-bit masks from
  Wireshark's field map (the ODVA spec being paywalled) and said so in its own
  message, but the Provenance paragraph was never updated. Now recorded, with
  the upstream licence (GPL-2.0). Documentation only; no code change, and
  nothing owed — a design reference carries no condition even from GPL source.

- **2026-08-11** — Security audit: seven findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on `OpENer` /
  `EIPScanner` (design reference, not a test anchor).
- **2026-07-23** — New module: EtherNet/IP + CIP — encapsulation layer
  (register/unregister session, SendRRData/SendUnitData), CIP messaging (Get/Set
  Attribute, Multiple Service Packet), connection manager, and a tag/symbolic path.
