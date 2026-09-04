# netaddr — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-04** — **First audit.** No defect in the parsing itself, which is
  anchored far better than its own SPEC admitted; the findings are in what the
  tests and the docs claim.

  **The module's central invariant had no test.** Making `Ip.eql` report
  `1.2.3.4` equal to `::ffff:1.2.3.4` left the suite at **47/47 green** — and
  that identity is what every module storing an `Ip` compares on. An allow-list
  keyed on it would have accepted `::ffff:127.0.0.1` wherever it meant
  `127.0.0.1`, and a deny-list the reverse. Now pinned in both directions,
  including the v4-compatible `::1.2.3.4` third form.

  **All three fuzz harnesses ran one input, and it was `""`.** Each called
  `smith.bytes(&buf)` and then drew a length: `bytes` consumes the whole input,
  and a ranged draw returns the range's minimum unless the eight bytes it reads
  as a little-endian `u64` already lie in range. Instrumented: **1 round, 0
  non-empty, 0 that parsed**; even given a hand-written corpus of 12 real
  address literals, 13 rounds and still 0 non-empty. Replaced with
  `smith.slice`, which draws length and bytes in one call — 9 non-empty and 2
  parsing on the same budget.

  **Two doc claims corrected.** README said "**Allocation:** none, anywhere"
  while `summarize` and `mergePrefixes` allocate; the bound is `2·width − 2`
  prefixes per range and is now stated. SPEC declared "class C · oracle n/a"
  for a module whose core now agrees with **three independent outside
  implementations** — glibc `inet_pton` and Python `ipaddress` over 2,100,000
  generated literals with 0 disagreements, RFC 5952 canonical form
  byte-identical over 480,000 addresses, `summarize`/`mergePrefixes` against
  `summarize_address_range`/`collapse_addresses` over 260,000 cases with 0, and
  an 8,000,000-address format round-trip with 0 failures. It is class B ·
  oracle MIXED: EXTERNAL for the core, SELF for the RFC 6724 half, which
  genuinely is oracle-poor. `check-fuzz` reads that line, so understating it was
  not only a documentation matter.

  Recorded, not fixed: `max_ip_text_len` is anchored by nothing and its
  `catch unreachable` is mode-divergent (one byte short: Debug and ReleaseSafe
  panic, **ReleaseFast hangs**, **ReleaseSmall silently returns a truncated
  address**); the overflow caps in all three numeric parsers are untested;
  `formatPrefix` output does not re-parse when `bits > width`; `parsePort`
  accepts leading zeros while every other numeric field rejects them.

- **2026-08-23** — **Breaking:** `sortDestinationsWithSources` returns
  `error{MismatchedLengths}!void` instead of `void`, and rejects
  `dsts.len != srcs.len` with an error where it previously used
  `std.debug.assert`. Both slices are independent caller-supplied arguments,
  and ReleaseFast compiles the assert (and the bounds check on every
  `srcs[i]` read/write in the sort loop) out — so a shorter `srcs` slice was
  an out-of-bounds read/write in release builds. Same shape as
  `sortDestinations` above, in the same file, noted as left over when that
  one was fixed.

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
