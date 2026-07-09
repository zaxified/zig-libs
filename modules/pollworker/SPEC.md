# pollworker — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: original work of
the zig-libs authors (MIT).

## Design & invariants
Two independent building blocks sharing only the "single owner drives the loop" discipline.
`Loop` — a thin, allocation-free wrapper over `poll(2)` (`Loop.poll`, raw `std.os.linux.poll`, no
libc) plus a per-tick maintenance-callback list (`addTask`/`tick`, run in registration order); the
owner composes them manually (poll the fds, service readiness, `tick()` the callbacks). `JobTable
(N, Job)` — a fixed-size, lock-free `FREE→RUNNING→DONE` slot table: the loop `claim()`s a slot
(loop-thread only), a worker fills the `Job` payload and `finish()`s it (worker-thread only, one
writer per transition), the loop `drain()`s DONE slots on its next tick, recycling them to FREE.
Handoff is a single per-slot atomic with acquire/release ordering — no mutex; each slot has exactly
one writer at a time by construction (loop owns claim/drain/release, the assigned worker owns
finish for its slot only), so there is no data race to reason about beyond that atomic.
`spawnDetached(argv, report)` runs the RUNNING→DONE half on a detached thread: `argv` is copied
into a heap-owned `OwnedArgv` (freed after the child is reaped, so the caller's slice need not
outlive the call); the between-fork-and-exec window in the child is deliberately async-signal-safe
— only `execve`/`exit_group`, no allocation, matching the POSIX fork-safety contract; the worker's
own heap (ctx + owned argv) is freed *before* publishing DONE, since once the loop observes DONE it
may tear down or leak-check the allocator and the detached thread must not touch it again after
that signal. Children exec with an empty environment (`empty_envp`) — callers needing `PATH` etc.
should exec absolute paths, which need none. `decodeStatus` decodes the raw `wait(2)` status word
without libc `W*` macros. Back-pressure is purely the fixed slot count `N`: `claim` returns `null`
and `spawnDetached` returns `error.TableFull` when every slot is busy — no queueing. Original work
of the zig-libs authors (MIT) — a single-owner event loop (`runController`) plus an HttpJob table;
the curl-specific fetch body is deliberately not included —
`spawnDetached` generalizes it to an arbitrary argv. Modeled after a single-owner event loop +
detached-fork worker pool pattern.

## Threat model / out of scope
Linux-only by design (raw `std.os.linux` errno-encoded syscalls: `poll`/`fork`/`execve`/`waitpid`/
`access`) — a conscious no-libc, no-portability ceiling, grouped with the repo's other Linux-only
members (icmp/rawsock/netlink/wireguard/l2disco/procnet); accepted scope, not a gap. Not a security
boundary in itself — `spawnDetached` execs whatever `argv` the caller supplies with no validation
or sandboxing; the caller is responsible for trusting/sanitizing `argv[0]` and its arguments (this
module's job is only the fork/exec/wait plumbing and slot handoff, not argument-injection
defense). Resource bounds: fixed `N` slots (compile-time), so unbounded job submission is a caller
bug surfaced as `error.TableFull`, never an unbounded allocation or thread explosion. Failure
modes: a `fork`/`thread-spawn` failure returns a typed error (`spawn_failed` in `ProcResult`, or
`error.ThreadSpawnFailed`) rather than panicking; the child's fate is explicitly "unknown" in that
case, never assumed successful.

## Verification
4 tests. `Loop.poll`: a pipe becomes readable within timeout (real syscall, Linux-gated). `Loop.
tick`: maintenance callbacks run in registration order. `JobTable`: claim/finish/drain handoff plus
slot reuse under N-jobs-through-2-slots (multi-round, real threads, asserts exact sum/count and
zero-busy after drain — proves the acquire/release handoff is actually visible, not just
sequentially consistent by luck). `JobTable.spawnDetached`: real fork/exec against `/bin/true` and
`/bin/false` (skipped if either binary is absent), asserting exact ok/fail counts and busy-count
convergence via a bounded spin-wait. Run: `zig build test-pollworker`.

## Backlog / deferred
Per the module README's "Not in scope (DEFER)": the curl-specific fetch body (buffer read,
negative-cache, stderr capture) stays in the app, not this module; eventfd/real completion
notification (results are currently observed by the loop polling `drain` each tick, not by waking
`poll` on completion — a registered eventfd would remove the drain latency); environment
inheritance for detached children (currently always empty — a caller-supplied envp is a future
option); back-pressure beyond the fixed slot count (queueing/retry is the caller's job); Windows/
non-Linux support (out of scope by design).

## Status
`extract · linux · util · single_owner` + deps: none (std only) — canonical source is `pub const
meta` in src/root.zig.
