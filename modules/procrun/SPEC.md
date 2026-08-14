# procrun — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: original work of
the zig-libs authors (MIT).

## Design & invariants

- **Reap-race-tolerant wait is the hard core.** In a host process where a sibling thread calls
  `wait4(-1)` (reaps *any* child — a language VM's exit handler, or a shell that left `SIGCHLD` as
  `SIG_IGN` so the kernel auto-reaps), a child can be reaped out from under a runner. Zig 0.16's
  `std.process.Child.wait` treats the resulting `ECHILD` as an `errnoBug` and panics (a racy
  `SIGABRT`); `procrun.waitTolerant` maps `ECHILD` to `Term.unknown` and closes the child's stdio
  handles itself instead. Original work of the zig-libs authors (MIT) —
  (`waitTolerant`/`reapTolerantPosix`/`statusToTerm`, the `SIGCHLD` fixup, and the capped 3-thread
  drain/streaming-with-cancel machinery); the reap syscalls use
  `std.posix.system.wait4`/`waitpid` (raw `std.os.linux` on Linux, not libc) to keep the
  module libc-free. Model after Python `subprocess.run`/`Popen`, Go `os/exec`.
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

Not a full sandbox: no seccomp/namespace isolation (that remains the caller's responsibility); an
opt-in `RlimitSpec` (`Spec.rlimit`) covers the resource-exhaustion axis only (CPU/address-space/
open-files/file-size), applied via a `/bin/sh -c 'ulimit ...; exec "$@"'` wrapper — see SPEC below
for why (`std.process.spawn` has no post-fork/pre-exec hook). `argsafe` integration
(`runValidated`/`buildValidatedArgv`) is opt-in — the ordinary `run`/`runTimeout`/`spawnStreaming`
entry points still treat `Spec.argv` as trusted-by-construction; callers building argv from
untrusted input either use `runValidated` or sanitize it themselves. Full reap-race-tolerance
behavior is POSIX-only; Windows falls back to `std.process.Child.wait` and has not been
regression-tested for the reap-race the POSIX path was built to fix. `Spec.new_process_group`
(POSIX-only) makes the direct child the leader of its own process group and enables
`Handle.cancelGroup`/`killGroup`/`signalGroup` plus a grouped `runTimeout` deadline-kill, so a
killed child's own descendants (e.g. a shell's `&`-backgrounded jobs) are reachable too — but this
only covers descendants that stayed in the group the kernel assigns at fork; a descendant that
calls `setsid`/`setpgid` itself escapes it, same as any POSIX process-group signal.

## Verification

Deterministic tests over real spawned processes (`git`, `sleep`, `cat`, `dd`, `/bin/sh`, and
synthetic scripts) plus the reap-race regression itself (a sibling-thread `wait4(-1)` racing the
runner's own wait): blocking run + capture, capped-output truncate-not-discard,
stdin-larger-than-pipe-buffer non-deadlock, all three env modes, hard-timeout SIGKILL+reap,
streaming spawn with ack/cancel/kill/signal and `on_exit` firing exactly once,
**`Spec.new_process_group` + `Handle.killGroup` actually reaping a `sh -c 'sleep 100 &'`
grandchild** (polled against `/proc/<pid>/stat`'s state byte, not just `kill(pid,0)`, so a
not-yet-reaped zombie can't pass for "still running"), **`RlimitSpec.file_size_bytes` biting real
`dd` output** (asserted via both `Term.signal == SIGXFSZ` and the file's on-disk size staying at
the cap) and **`RlimitSpec.cpu_seconds` terminating a busy loop** well inside a generous
`runTimeout` safety net (proving the *rlimit*, not the safety net, fired), **`Handle.writeStdin`/
`closeStdin` round-tripping incremental chunks through `cat`** plus their unavailable/double-close
error paths, and **`runValidated` rejecting a flag-injection-shaped arg via `argsafe` before
spawning anything** alongside an accept-and-actually-run case. Run: `zig build test-procrun`.

## Backlog / deferred

- **Line-delimited / NDJSON stdout mode** — v1 delivers raw pipe chunks only; a framed/line mode
  would spare consumers reassembly. Still open.
- **Windows reap-race coverage** — the `TerminateProcess`/`create_no_window` branch compiles but is
  untested for the POSIX-specific regression this module exists to fix. Still open.
  `new_process_group`/`RlimitSpec` are also POSIX-only (`new_process_group` is a documented no-op,
  `rlimit` is `error.OperationUnsupported`) on Windows.
- **Type-level "consumed" marker** — a move-only handle preventing a double-`wait`/double-reap at
  compile time. Still open.
- **PATH-resolution policy** — explicit control over `argv[0]` PATH resolution independent of
  `argsafe` (now wired in for argv *sanitization* via `runValidated`/`buildValidatedArgv`; PATH
  *resolution* policy itself is unchanged from v1 — see `Spec`'s doc comment). Still open.
- ~~**Process-group / `setsid` + whole-tree kill**~~ — done: `Spec.new_process_group` (`setpgid(0,
  0)`) + `Handle.cancelGroup`/`killGroup`/`signalGroup` + a grouped `runTimeout` deadline-kill.
- ~~**rlimit control**~~ — done: `Spec.rlimit` (`RlimitSpec`: CPU/address-space/open-files/
  file-size), applied via a `ulimit`-then-`exec` shell wrapper (`std.process.spawn` has no
  post-fork/pre-exec hook to call `setrlimit` directly in the child).
- ~~**Streaming stdin after spawn**~~ — done: `Handle.writeStdin`/`closeStdin` on a
  `spawnStreaming` handle (`Spec.stdin = .pipe`), independent of the one-shot `stdin_body` on
  `run`/`runTimeout`.
- ~~**`argsafe` integration**~~ — done: `runValidated`/`buildValidatedArgv` (opt-in; ordinary
  `run`/`runTimeout`/`spawnStreaming` still treat `Spec.argv` as trusted).

## Status

`extract · any (full behavior on POSIX; reap-race handling, new_process_group, and rlimit are
POSIX-only) · util · reentrant` + deps: `argsafe` (opt-in argv sanitization via `runValidated`/
`buildValidatedArgv`; every other entry point is std-only) — canonical source is `pub const meta`
in src/root.zig.

## Anchoring

**Anchor grade:** class C · oracle n/a

- **Class C** — internal algorithm or data structure — no outside exists, so correctness is defined by invariants or a brute-force reference. Not anchor debt.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** process reap/spawn robustness util, no wire format
