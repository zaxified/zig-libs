# procrun — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-18** — **NO CONSUMER-VISIBLE CHANGE:** `killerLoop` gains a
  test-only wakeup counter (`void` outside a test build, so the increment
  compiles to nothing there). F4's regression test now counts how many times
  the killer thread wakes over a 300ms child (1 with the futex wait, ~60 with
  the old fixed 5ms poll) instead of asserting a mean wall time under 50ms,
  which the old poll (mean ~6.4ms) had passed anyway. The wall-time check
  stays as a coarse sanity bound on the minimum of 20 runs.
- **2026-09-15** — **NO CONSUMER-VISIBLE CHANGE:** `zig build check-portable`
  caught `.windows` compiling for the first time in this Zig version:
  `drainLoop`'s deadline wait referenced `std.posix.POLL.IN`, which lowers to
  `ws2_32.POLL` on Windows and does not exist there (a std gap), and
  `monoNowNs` called `std.posix.system.clock_gettime`, which on Windows is
  `extern "c"` and fails to compile without linking libc (this repo's policy
  is libc only for `sqlite`). `pollReady` now has a real Windows branch
  (`PeekNamedPipe`-based, since a pipe HANDLE has no `poll`-equivalent
  readiness wait) and `monoNowNs` a `QueryPerformanceCounter`-based one, same
  raw-kernel32-extern idiom `sleepNs` already used on this platform. No
  behavior change on POSIX; the deadline-bounded read path was previously
  unreachable on Windows only because it could not compile there at all.
- **2026-09-10** — **BEHAVIOURAL, not breaking:** A1 fix campaign, six findings
  from the 2026-09-04 audit. `runTimeout` is now actually bounded by roughly
  its own `timeout_ns` (plus a small fixed grace): before, it waited on the
  stdout/stderr pipes reaching EOF, which a descendant the direct child forked
  (e.g. `sh -c 'sleep 100 & exit 0'`) could hold open indefinitely even after
  the direct child was killed — `sh -c 'sleep 2 & exit 0'` at a 200ms deadline
  used to return after the full `sleep`; now it returns within ~450ms. New
  `Output.stdout_deadline_stopped`/`.stderr_deadline_stopped` fields say when
  capture was cut short by the deadline rather than EOF. Under `Spec.rlimit`,
  `argv[0]` PATH resolution now genuinely always uses the parent's real `PATH`
  (as `Spec`'s doc comment already promised) instead of the wrapper shell's
  own `exec "$@"` resolving it against the child's `PATH` per `env_mode`. A
  rejected `ulimit` inside the `rlimit` wrapper now surfaces as
  `Term{.signal = SIGUSR1}` instead of `Term{.exited = 121}`, which used to be
  indistinguishable from a child that legitimately exits 121 on its own.
  `runTimeout`'s internal killer thread no longer polls in fixed 5ms steps
  (measured 4.7x overhead on a child that exits immediately) — it now blocks
  on `std.Io.Event.waitTimeout` and is woken directly. `Spec.max_output_bytes`
  and `Spec.rlimit`'s `/bin/sh` dependency are now documented accurately (were
  previously silent or, in one case, actively wrong about what the code did).
  See `A1/procrun.md`'s 2026-09-10 disposition for the measured before/after
  on each.
- **2026-09-03** — Drift re-audit. **A signal is no longer sent to a pid we may
  no longer own.** This module exists because a sibling thread's `wait4(-1)`
  can reap our child; the edge nobody had covered is what happens NEXT. Once
  somebody else reaps it the pid is free for the host's next `fork`, while
  `child.id` is still set (nothing nulls it until `waitTolerant` runs) and the
  `runTimeout` killer thread is still armed up to the deadline. Both `deliver`
  and `deliverGroup` signalled it anyway — and `deliverGroup`'s form is
  `kill(-pid, SIGKILL)`, an entire recycled process **group**. Reproduced:
  after an out-of-band reap, `child.id` is still set and both paths proceeded.
  Every signal now passes `stillOurChild(pid)` — `waitid` with
  `WNOHANG | WNOWAIT`, non-destructive (it never consumes the status
  `waitTolerant` still needs) and answering `ECHILD` exactly when the pid stops
  being ours. ⚠ This NARROWS the window rather than closing it: the pid can be
  reaped between the answer and the `kill`. The real fix is a `pidfd` opened at
  spawn, deferred and recorded in SPEC. Linux-only; elsewhere the gate answers
  "ours" and the old behaviour stands. Pid RECYCLING itself was not reproduced
  (it needs the pid counter forced to wrap) — what a test pins is the gate, in
  both directions.


- **2026-08-17** — The documented "compiles for Windows" claim was false, and had been
  since the module existed: `spawnChild` passed the POSIX literal `0` to `Child.pgid`
  ("lead your own group"), which on Windows is a `?*anyopaque` HANDLE and does not
  typecheck, and the `statusToTerm` test decodes a POSIX wait(2) status word through
  `std.posix.W`, which is `void` there. Both are now branched at `comptime`
  (`new_process_group` was already documented as a Windows no-op, so the branch keeps
  that promise rather than failing the build). No behavior change on POSIX. Nothing in
  this repo compiled for Windows, which is why a false claim survived — and `check-portable`
  would not have caught it even with a Windows target, because `build-obj` on a library root
  analyses no function bodies at all (measured: reverting qr's 32-bit fix leaves
  `zig build portable-qr` green).
- **2026-07-19** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on Python
  `subprocess.run`/`Popen`, Go `os/exec` (design reference, not a test anchor).
- **2026-07-09** — New module: Subprocess runner: reap-race-tolerant wait, deadlock-free
  capped stdio capture, timeout, streaming + cancel.
