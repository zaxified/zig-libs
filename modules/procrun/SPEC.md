# procrun — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Reap-race-tolerant wait is the hard core.** In a host process where a sibling thread calls
  `wait4(-1)` (reaps *any* child — a language VM's exit handler, or a shell that left `SIGCHLD` as
  `SIG_IGN` so the kernel auto-reaps), a child can be reaped out from under a runner. Zig 0.16's
  `std.process.Child.wait` treats the resulting `ECHILD` as an `errnoBug` and panics (a racy
  `SIGABRT`); `procrun.waitTolerant` maps `ECHILD` to `Term.unknown` and closes the child's stdio
  handles itself instead. Extracted and rewritten from the authors' bxp `bxp-gui-bridge/src/main.zig`
  (`waitTolerant`/`reapTolerantPosix`/`statusToTerm`, the `SIGCHLD` fixup, and the capped 3-thread
  drain/streaming-with-cancel machinery — Apache-2.0 → MIT relicense); the reap syscalls differ from
  the seed (`std.posix.system.wait4`/`waitpid`, raw `std.os.linux` on Linux, not libc) to keep the
  module libc-free. Model after Python `subprocess.run`/`Popen`, Go `os/exec` — see NOTICE.
- **Deadlock-free capped stdio capture:** separate stdin-writer / stdout-drainer / stderr-drainer
  threads, so a stdin body larger than the pipe buffer can't deadlock a child withholding stdout. A
  per-stream cap **keeps the prefix and keeps draining** past the cap (unlike `std.process.run`'s
  `error.StreamTooLong`, which discards everything).
- **Three env policies** (`.inherit`/`.clear`/`.merge`): `.merge` reads the parent snapshot
  libc-free from `/proc/self/environ` (Linux) or the PEB (Windows); other POSIX targets without
  `/proc` may see an empty snapshot there — `.clear` is the documented fallback.
- **Typed errors, lossless term:** spawn failures are typed `std.process.SpawnError` variants, never
  `@errorName` strings; `Output.term` exposes `std.process.Child.Term` directly (`.exited` code,
  `.signal`/`.stopped` raw `std.posix.SIG`, `.unknown`) with no lossy re-encoding to `i32`.
- **Concurrency:** reentrant — no shared module state beyond an idempotent, threadsafe
  `SIGCHLD`-fixup guard (`ensureChildReaping`/`restoreChildReaping`).

## Threat model / out of scope

Not a sandbox: it does not itself constrain what the child can do (no seccomp/namespace/rlimit) —
that is the caller's responsibility or a deferred feature (see backlog). `argsafe` integration
(argv-injection-safe argument construction) is not yet wired in — callers building argv from
untrusted input must sanitize it themselves until that lands. Full behavior (the reap-race
tolerance) is POSIX-only; Windows falls back to `std.process.Child.wait` and has not been
regression-tested for the reap-race the POSIX path was built to fix. Signal delivery
(`cancel`/`kill`/`signal`) targets the direct child only — orphaned grandchildren of a killed child
are not reaped or terminated (no process-group/`setsid` in v1).

## Verification

Deterministic tests over real spawned processes (`git`, `sleep`, `cat`, and synthetic scripts) plus
the reap-race regression itself (a sibling-thread `wait4(-1)` racing the runner's own wait): blocking
run + capture, capped-output truncate-not-discard, stdin-larger-than-pipe-buffer non-deadlock, all
three env modes, hard-timeout SIGKILL+reap, streaming spawn with ack/cancel/kill/signal and
`on_exit` firing exactly once. Run: `zig build test-procrun`.

## Backlog / deferred

- **Process-group / `setsid` + whole-tree kill** — v1 signals only the direct child; a killed
  child's orphaned grandchildren survive.
- **rlimit control** (max CPU time / address space) for sandboxed exec — needs `setrlimit` in the
  post-fork child.
- **Streaming stdin after spawn** — v1 writes a fixed `stdin_body` then closes; interactive
  request/response protocols (e.g. an MCP stdio transport) need a handle that stays open.
- **Line-delimited / NDJSON stdout mode** — v1 delivers raw pipe chunks only.
- **Windows reap-race coverage** — the `TerminateProcess`/`create_no_window` branch compiles but is
  untested for the POSIX-specific regression this module exists to fix.
- **Type-level "consumed" marker** — a move-only handle preventing a double-`wait`/double-reap at
  compile time.
- **PATH-resolution policy + `argsafe` integration** — explicit control over `argv[0]` resolution
  and argument-quoting safety, pending once `argsafe` is wired in.

## Status

`extract · any (full behavior on POSIX; reap-race handling is POSIX-only) · util · reentrant` +
deps: none (std only) — canonical source is `pub const meta` in src/root.zig.
