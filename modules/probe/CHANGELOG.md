# probe — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-02** — Drift re-audit (W2, window `becadd6..HEAD`). Eight findings, all fixed:

  - **HIGH, false negative in the default path:** `PosixConnector` connected to the **first**
    resolved address only, while `LiveConnector` (via `net.HostName.connect`) races **every** one.
    Same target, opposite verdicts: on a dual-stack host whose service listens only on the second
    address, `PosixConnector` reported `.refused` — documented as "a definitive, fast negative" —
    where `LiveConnector` reported `.up`; with the first address black-holed it burned the whole
    budget and reported `.timeout`. `.system` is the default and `PosixConnector` is the
    recommended connector, so this was a false "service down" on the health checker the module
    exists for. Every resolved address (up to 8) now gets a turn against the remaining budget.
    ⚠ No test ever called `connectImpl` with `resolve = .system` **and** a non-null `io`, which is
    why the suite could not see it.
  - **A cancellation is no longer counted as packet loss.** `Status.canceled` was added so a
    caller that cancelled its own `std.Io` task stopped seeing "dead hosts" — but only the
    *sample* was relabelled. The aggregate, which is what a consumer reads, still said
    `received = 0`, `reachable() = false`, `lossPct() = 100`. Cancelled repetitions are now
    excluded from `stats` entirely, and `TargetResult.canceledCount()` reports them.
  - **An `.up` with no round-trip is a broken connector, not a 0 ns connect.** `rtt_ns orelse 0`
    folded the two together into a fabricated latency floor. `Connector` is a public seam.
  - `lowestFreeFd`'s error guard was dead code: `dup` returns `usize`, so on failure the
    `@intCast` to `i32` panicked *before* the `fd < 0` check could be true — in the
    descriptor-leak oracle, i.e. exactly the test that runs when descriptors are scarce.
  - **Docs.** `Options.timeout_ms = 0` means **no budget** (block until the OS gives up, ~2 min),
    a convention that lived only in two private comments while the public knob said nothing.
    SPEC's "**exactly** one of `errno`/`err_name` is ever set" is false — six live `.error` exits
    carry neither, and the absolute invites `r.errno.?`, a panic in Debug and illegal behaviour in
    ReleaseFast. `probeMany`'s "at most `max_concurrent` in flight" is `max(1, …)`: 0 means one at
    a time, not none.

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
