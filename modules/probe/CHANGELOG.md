# probe — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-22** — **BREAKING:** `Status` gained a fifth value, `canceled`. Before this,
  `LiveConnector.classifyErr`'s `else => .@"error"` arm silently folded `std.Io.net`'s
  `Io.Cancelable` (`error.Canceled`) into `.@"error"` — a caller that canceled its own
  `std.Io` task (`Future.cancel`) mid-connect saw the targets it never finished probing
  reported as dead hosts, not as canceled. `PosixConnector` cannot produce this value (its
  raw-syscall path sits outside `std.Io`'s cancellation registry) and its exhaustive switch
  in `connectImpl` marks that arm `unreachable`. **BREAKING** because any consumer switching
  exhaustively over `Status` now fails to compile until it adds a `.canceled` arm — the same
  shape as every other enum addition here. See SPEC.md "Cancelation is not a transport
  failure" for the two shapes considered and why the smaller one (a new `Status` value) was
  taken over redesigning the fan-out to stop early.
- **2026-08-18** — `ConnectOutcome`/`Result` gained two new optional fields, `errno: ?i32`
  and `err_name: ?[]const u8`, carrying the underlying OS errno (`PosixConnector`) or Zig
  error name (`LiveConnector`) behind a non-`.up` outcome — previously discarded once
  classified into `Status`. The `Status` classification itself is unchanged. **Not BREAKING**:
  both fields are additive with a `null` default, so every existing `ConnectOutcome`/`Result`
  struct literal and every existing field read compiles unchanged; only code that *counts*
  the fields of either struct (e.g. `@typeInfo`-based reflection) would notice. See SPEC.md
  "Underlying error alongside Status".
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on `nmap -sT`,
  `fping` (technique only; behavioral, not code) (design reference, not a test anchor).
- **2026-07-07** — New module: TCP-connect reachability prober — up/refused/timeout +
  RTT, fan-out with bounded concurrency, latency aggregation.
