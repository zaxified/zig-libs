# l2disco — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — All four fuzz targets parsed an EMPTY frame. Each opened with
  `smith.bytes(&buf)` and then drew its length with `valueRangeAtMost`, which reads eight input
  octets as a little-endian u64 and returns the range minimum when fewer remain — so the length
  was 0 on every seed and every parser was handed `""` with the frame sitting unread in `buf`.
  For `lldp` that meant the `catch return` one line down took every round and the three
  iterators the target exists for had never executed at all. The `dhcp` harness stamped the magic
  cookie "in about half the cases … so the option walker past the cookie gate is actually
  reached"; it never was, twice over — the `boolWeighted` draw came after the input was spent and
  the `len >= header_len + 4` guard was false anyway, so the stamp never happened once. Each
  target now draws with one `smith.slice(&buf)`, carries a corpus of real frames plus the
  refusals a well-formed frame cannot reach, and is pinned by a guard counting work done —
  address octets sliced, TLVs walked, options decoded, management addresses read — because a
  four-octet CDP header, a 240-octet DHCP header with no options, and an LLDPDU carrying only its
  three mandatory TLVs are all legal, so an acceptance count reads as health while nothing walks.
  Two knobs that could only ever be their default now travel in the seed's tail: `cdp`'s
  `verify_checksum` (one seed makes the two settings disagree) and `lldp`'s `tolerant_optionals`
  (four do). Buffers were raised where the module's own largest frame did not fit. Verified by
  mutation: nine loosened bounds across the four parsers are now caught, five of them only after
  seeds were added that miss the limit by one or two octets rather than by thousands.

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
