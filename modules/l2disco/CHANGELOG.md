# l2disco — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — **BREAKING:** `lldp.Lldpdu.parse` now takes a second parameter,
  `opts: lldp.ParseOptions` (existing call sites become `Lldpdu.parse(bytes, .{})`), matching the
  `cdp.Frame.parse(bytes, opts)` shape already in this module. Adds `ParseOptions.tolerant_optionals`
  (default `false`, so the parse stays strict unless a caller opts in): when `true`, a malformed
  *optional* TLV (System Capabilities of the wrong length, an internally-inconsistent Management
  Address) is skipped instead of discarding the whole LLDPDU, and `Lldpdu.skipped_optionals` counts
  how many were dropped. A malformed *mandatory* TLV (Chassis ID / Port ID / TTL) or its ordering
  still always fails the parse, in both modes — relaxing mandatory-TLV ordering was considered and
  deliberately left out of scope (see SPEC.md's Backlog section). Prompted by a consumer running a
  second tolerant pass over the same `TlvIterator` after the typed parse, purely to recover a
  neighbour whose Chassis ID / Port ID were fine but whose optional TLVs were not.
- **2026-08-18** — `cdp.Frame.parse` gains `ParseOptions.tolerant_trailing_tlv` (default `false`):
  when `true`, a truncated or malformed *trailing* TLV — the shape real 802.3 zero-padding to the
  60-byte Ethernet minimum produces once the TLV walk reaches it — stops the walk and returns what
  parsed instead of failing the whole frame; the new `Frame.trailing_tlv_truncated` field reports
  whether this happened. Not BREAKING: `cdp.ParseOptions` already carried a defaulted field
  (`verify_checksum`), so every existing `Frame.parse(bytes, .{})` call site is source-compatible
  with the new one added alongside it.
- **2026-08-18** — README: added a prominent callout that `cdp.Frame.parse` verifies the RFC 1071
  checksum by default (correct, and staying that way) — real gear and most hand-rolled test frames
  emit a zero checksum, which needs `ParseOptions.verify_checksum = false` to parse. Previously this
  was only documented in a doc comment inside `cdp.zig`, not in the consumer-facing README.
- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on Wireshark
  dissectors / lldpd / isc-dhcp (design reference, not a test anchor).
- **2026-07-07** — New module: Layer-2 / neighbor discovery codec — LLDP (802.1AB) + CDP
  + ARP (RFC 826) + DHCP options (RFC 2131/2132) + MAC helper.
