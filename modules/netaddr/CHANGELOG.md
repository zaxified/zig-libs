# netaddr — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-23** — **Breaking:** `sortDestinations` returns
  `error{TooManyCandidates}!void` instead of `void`, and rejects
  `dsts.len > max_sort_candidates` with an error where it previously used
  `std.debug.assert`. The scratch array it fills is a fixed 64-slot stack
  array, and ReleaseFast compiles both the assert and the bounds check out —
  so an over-long slice wrote past a stack buffer in release builds. The
  argument is typically a resolver's answer set, which is data off the wire.
  Found by an audit sweep for this shape after two others were fixed the same
  day.

- **2026-08-22** — **Breaking:** `formatIp` and `formatPrefix` take `*[max_ip_text_len]u8` /
  `*[max_prefix_text_len]u8` instead of `[]u8`. They guarded the size with
  `std.debug.assert`, which is `if (!ok) unreachable` and so compiles out of ReleaseFast
  and ReleaseSmall — the modes an integrator ships. A caller passing a short buffer got a
  clean crash while testing and a silent write past the end of it in production. The
  requirement is now in the type, where the compiler enforces it in every mode. Callers
  holding a larger buffer pass `buf[0..max_ip_text_len]`.
- **2026-07-19** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified against RFC
  6724.
- **2026-07-02** — New module: IP parse/format (RFC 5952) + RFC 6724 source/dest
  selection + CIDR/Prefix ops (contains/overlaps/supernet, range↔prefix summarize).
