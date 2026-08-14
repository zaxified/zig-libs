# procnet — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-14** — `zig build check-fuzz` coverage: a `testing.fuzz` harness on each of
  the five `/proc` table decode entry points — `parseProcStat`, `parseRoutes`,
  `parseTcp`/`parseUdp`, `parseArp`, `parseConntrack`. Kernel-emitted is not
  trusted-input: a container's `/proc` can be bind-mounted/faked, a process names
  itself (`comm`) with adversarial parens, and every parser also reads from a
  caller-supplied snapshot file. Each harness mutates a real fixture (byte flips over
  a copy of the real `/proc/net/*`/`/proc/<pid>/stat` sample) plus a fifth-of-the-time
  pure arbitrary bytes, since arbitrary bytes essentially never spell the exact
  column/hex-length shapes these formats require; the four allocating parsers run
  under `std.testing.allocator` with the result freed on every path. No panic, hang,
  OOB read or leak found.
- **2026-07-19** — Security audit: three findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified against a live capture from
  gopsutil (Go) / procps-ng.
- **2026-07-09** — New module: Linux `/proc`+`/sys` parsers — ARP/routes/TCP+UDP
  sockets/conntrack/process stats/device health, typed.
