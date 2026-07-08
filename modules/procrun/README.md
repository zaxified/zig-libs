# procrun

A subprocess runner whose hard core is a **reap-race-tolerant wait**. In a host
process where a sibling thread calls `wait4(-1)` (reaps *any* child — a language
VM's exit-code handler, or a shell that left `SIGCHLD` as `SIG_IGN` so the
kernel auto-reaps), the child can be reaped out from under you. Zig 0.16's
`std.process.Child.wait` treats the resulting `ECHILD` as an `errnoBug`
(double-free) and **panics** (a racy `SIGABRT`). `procrun.waitTolerant` reaps
through a path that maps `ECHILD` to `Term.unknown` (child gone, status
unreadable) and closes the child's stdio handles itself, so it never panics.

Beyond that it adds what a runner needs: deadlock-free capped stdio capture
(separate stdin-writer / stdout-drainer / stderr-drainer threads, so a stdin
body larger than the pipe buffer can't deadlock a child that withholds stdout),
a per-stream cap that **keeps the prefix and keeps draining** past the cap
(rather than `std.process.run`'s `error.StreamTooLong`, which discards
everything), env/cwd control, a hard timeout, and a streaming variant with
signal-based cancel/kill and backpressure.

Provenance: extracted and rewritten as a native Zig API from the authors' bxp
project (`bxp-gui-bridge/src/main.zig` — the `waitTolerant` /
`reapTolerantPosix` / `statusToTerm` reap-race core, the
`ensureChildReaping` / `restoreChildReaping` `SIGCHLD` fixup, and the capped
3-thread drain / streaming-with-cancel machinery; the authors' own code,
Apache-2.0 → MIT relicense). The bridge's Dart-FFI/JSON shim is discarded; only
the process-handling substance is kept. The reap decision differs from the seed:
where the bridge used `std.c.waitpid` (libc), procrun uses
`std.posix.system.wait4`/`waitpid` — on Linux that is `std.os.linux`, i.e. raw
syscalls, keeping the module **libc-free**.

- **Status:** `extract`.
- **Model after:** Python `subprocess.run`/`Popen`, Go `os/exec`.
- **Platform:** any (full behavior on POSIX; the reap-race handling is
  POSIX-only, Windows falls back to `std.process.Child.wait`). **Role:** util.
  **Concurrency:** reentrant (no shared module state beyond the idempotent,
  threadsafe `SIGCHLD`-fixup guard).
- **Deps:** none (std only).

## API

```zig
const procrun = @import("procrun");

var threaded = std.Io.Threaded.init(gpa, .{});
defer threaded.deinit();
const io = threaded.io();

// Blocking run: capture stdout/stderr, wait reap-race-tolerantly.
var out = try procrun.run(gpa, io, .{
    .argv = &.{ "git", "status", "--short" },
    .cwd = "/path/to/repo",
    .max_output_bytes = 1 << 20,
}, ""); // stdin body (only used when .stdin == .pipe)
defer out.deinit(gpa);
switch (out.term) {
    .exited => |code| { _ = code; },
    else => {},
}
// out.stdout / out.stderr owned by caller; out.truncated_stdout / _stderr.

// Feed a large stdin body without deadlock:
var piped = try procrun.run(gpa, io, .{ .argv = &.{"cat"}, .stdin = .pipe }, big_body);
defer piped.deinit(gpa);

// Hard timeout: SIGKILL + reap if it outlives the deadline.
var t = try procrun.runTimeout(gpa, io, .{ .argv = &.{ "sleep", "60" } }, "", 500 * std.time.ns_per_ms);
defer t.deinit(gpa);
// t.term == .signal on timeout.

// Streaming with cancel/kill + backpressure:
const h = try procrun.spawnStreaming(gpa, io, .{ .argv = &.{"long-running"} }, .{
    .ctx = &my_sink,
    .on_stdout = onStdout, // fn (ctx: ?*anyopaque, chunk: []const u8) void
    .on_stderr = onStderr,
    .on_exit = onExit,     // fn (ctx: ?*anyopaque, term: procrun.Term) void
});
// h.ack() per consumed stdout chunk; h.cancel() = SIGTERM, h.kill() = SIGKILL,
// h.signal(n) = arbitrary signal.
const term = h.wait(); // joins readers, reaps, fires on_exit, frees state.
```

### Environment control (`env_mode`)

- `.inherit` (default) — child inherits the parent environment; `Spec.env`
  ignored.
- `.clear` — child gets **only** `Spec.env` (empty if null).
- `.merge` — parent environment with `Spec.env` overlaid. The parent snapshot is
  read libc-free from `/proc/self/environ` on Linux and the PEB on Windows; on
  other POSIX targets (no `/proc`) that snapshot may be empty — prefer `.clear`
  there.

Errors are typed (`error.FileNotFound`, `error.AccessDenied`, … from
`std.process.SpawnError`), never `@errorName` strings.

`Output.term` exposes `std.process.Child.Term` directly (`.exited` code,
`.signal`/`.stopped` `std.posix.SIG`, `.unknown` raw status) — no lossy
re-encoding to `i32`.

## Backlog (deferred from v1)

- **Process-group / `setsid` + whole-tree kill.** v1 signals only the direct
  child; a killed child's orphaned grandchildren survive. Add `pgid`/`setsid`
  and group-kill for reliable subtree teardown.
- **rlimit control (max CPU time / address space).** For sandboxed exec; needs
  `setrlimit` in the post-fork child.
- **Streaming stdin after spawn.** v1 writes a fixed `stdin_body` then closes;
  interactive request/response protocols (e.g. an MCP stdio transport) need a
  writable handle that stays open.
- **Line-delimited / NDJSON stdout mode.** v1 delivers raw pipe chunks only; a
  framed/line mode would spare consumers reassembly.
- **Windows depth.** The `TerminateProcess` / `create_no_window` branch is
  present and the module compiles for Windows, but the reap-race regression is a
  POSIX phenomenon — Windows reap-race coverage is deferred.
- **Type-level "consumed" marker.** A move-only handle preventing a
  double-`wait`/double-reap at compile time.
- **PATH-resolution policy + `argsafe` integration.** Explicit control over
  `argv[0]` resolution and argument-quoting safety.
