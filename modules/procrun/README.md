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

Provenance: original work of the zig-libs authors (MIT) — the `waitTolerant` /
`reapTolerantPosix` / `statusToTerm` reap-race core, the
`ensureChildReaping` / `restoreChildReaping` `SIGCHLD` fixup, and the capped
3-thread drain / streaming-with-cancel machinery. procrun uses
`std.posix.system.wait4`/`waitpid` — on Linux that is `std.os.linux`, i.e. raw
syscalls, keeping the module **libc-free**.

- **Model after:** Python `subprocess.run`/`Popen`, Go `os/exec`.
- **Platform:** any (full behavior on POSIX; the reap-race handling,
  `new_process_group`, and `rlimit` are POSIX-only — `new_process_group` is a
  documented no-op and `rlimit` is `error.OperationUnsupported` on Windows;
  Windows falls back to `std.process.Child.wait`). **Role:** util.
  **Concurrency:** reentrant (no shared module state beyond the idempotent,
  threadsafe `SIGCHLD`-fixup guard).
- **Deps:** `argsafe` (opt-in argv sanitization via `runValidated`/
  `buildValidatedArgv` only — every other entry point is std-only).

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

// Redirection (StdioMode: .close .inherit .pipe .ignore .file .stdout):
var merged = try procrun.run(gpa, io, .{ .argv = &.{ "sh", "-c", "echo a; echo b >&2" }, .stderr = .stdout }, ""); // one pipe: order kept, merged.stderr empty
var quiet = try procrun.run(gpa, io, .{ .argv = &.{"make"}, .stdout = .ignore, .stderr = .ignore }, ""); // /dev/null
var to_log = try procrun.run(gpa, io, .{ .argv = &.{"make"}, .stdout = .{ .file = log_file }, .stderr = .stdout }, ""); // caller-owned File, never closed by procrun

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

// Streaming stdin: write incrementally after spawn (Spec.stdin = .pipe),
// not just a one-shot pre-filled buffer.
const h2 = try procrun.spawnStreaming(gpa, io, .{ .argv = &.{"cat"}, .stdin = .pipe }, .{});
try h2.writeStdin("first chunk, ");
try h2.writeStdin("second chunk");
try h2.closeStdin(); // signal EOF; `wait` also closes it if still open
_ = h2.wait();

// Whole-tree kill: put the child in its own process group and signal the
// group, not just the direct child — reaches descendants it forked itself
// (e.g. `sh -c 'long-runner &'`).
const h3 = try procrun.spawnStreaming(gpa, io, .{
    .argv = &.{ "sh", "-c", "sleep 100 &" },
    .new_process_group = true,
}, .{});
h3.killGroup(); // SIGKILL to -pgid; cancelGroup()/signalGroup(n) also exist
_ = h3.wait();
// runTimeout also grouped-kills on deadline when new_process_group is set.

// Graceful stop (opt-in, POSIX): SIGTERM first, SIGKILL only after the grace.
// Applies to Spec.cancel and runTimeout's deadline (to the group with
// new_process_group). null (default) = SIGKILL at once, as before.
var g = try procrun.runTimeout(gpa, io, .{
    .argv = &.{ "some-server" },
    .cancel_grace_ns = 5 * std.time.ns_per_s,
}, "", 30 * std.time.ns_per_s);
defer g.deinit(gpa);
// g.timed_out / g.canceled say why it was stopped; g.grace_expired == true means
// it ignored SIGTERM and was SIGKILLed. Streaming twin, blocking, from the owner:
//   const exited_in_grace = h.terminate(5 * std.time.ns_per_s); // terminateGroup(ns)

// Line-framed stdout (NDJSON etc.): one callback per line, no reassembly.
const hl = try procrun.spawnStreaming(gpa, io, .{ .argv = &.{"tail-events"} }, .{
    .ctx = &my_sink,
    // fn (ctx, line: []const u8, truncated: bool) void -- `\n` (and one
    // trailing `\r`) stripped; a final line without `\n` is delivered at EOF.
    .on_stdout_line = onLine, // replaces on_stdout
    .max_line_bytes = 64 * 1024, // longer line: first 64 KiB, truncated = true
});
// h.ack() once per LINE (one stdout permit per line). Parse each line yourself.
_ = hl.wait();

// rlimit sandbox: applied to the child before it execs the real program.
var limited = try procrun.run(gpa, io, .{
    .argv = &.{ "some-untrusted-tool", "arg" },
    .rlimit = .{ .cpu_seconds = 5, .address_space_bytes = 256 << 20, .open_files = 64 },
}, "");
defer limited.deinit(gpa);

// argsafe integration (opt-in): validate argv before it can be spawned.
const argsafe = @import("argsafe");
var validated = try procrun.runValidated(
    gpa, io,
    "/usr/bin/some-tool", argsafe.isSafePath,
    &.{ user_supplied_arg }, argsafe.isSafeIdentifier,
    .{}, "",
); // error.Rejected before anything spawns if either predicate fails
defer validated.deinit(gpa);
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

- **Windows depth.** The `TerminateProcess` / `create_no_window` branch is
  present and the module compiles for Windows, but the reap-race regression is a
  POSIX phenomenon — Windows reap-race coverage is deferred. `new_process_group`
  and `rlimit` are POSIX-only for the same reason (see below).
- **PATH-resolution policy.** Explicit control over `argv[0]` PATH resolution
  (see `Spec`'s doc comment for current behavior) — independent of the
  `argsafe` *sanitization* integration below, which has landed. Open, and not
  a one-line knob: see `SPEC.md`.

Rejected: a type-level "consumed" marker for `Handle` (Zig has no move-only
types; see `SPEC.md`).

Done since v1:

- **Stdio redirection.** `StdioMode` gains `.ignore` (`/dev/null`), `.file`
  (caller-owned `std.Io.File`) and, for `Spec.stderr`, `.stdout` (Python's
  `stderr=STDOUT`: one shared pipe, write order preserved). `pass_fds` is not
  possible race-free over `std.process.spawn` (see `SPEC.md` Backlog).
- **Graceful cancellation.** `Spec.cancel_grace_ns` (blocking runs: `Cancel`
  and the `runTimeout` deadline) and `Handle.terminate`/`terminateGroup`
  (streaming): SIGTERM, wait up to the grace, then SIGKILL. `Output.timed_out`
  and `Output.grace_expired` report what happened. POSIX-only.
- **Line-delimited / NDJSON stdout mode.** `Callbacks.on_stdout_line` +
  `max_line_bytes`: bounded reassembly across chunks, one callback and one
  backpressure permit per line, final unterminated line flushed at EOF.

- **Process-group / whole-tree kill.** `Spec.new_process_group` (`setpgid(0,
  0)` between fork and exec) plus `Handle.cancelGroup`/`killGroup`/
  `signalGroup` (`kill(-pgid, sig)`) and a grouped `runTimeout` deadline-kill,
  so a killed child's own `&`-backgrounded jobs are reachable too. POSIX-only;
  a documented no-op on Windows.
- **rlimit control.** `Spec.rlimit` (`RlimitSpec`: `cpu_seconds`,
  `address_space_bytes`, `open_files`, `file_size_bytes`), applied via a
  `/bin/sh -c 'ulimit ...; exec "$@"'` wrapper inserted in front of `argv` —
  `std.process.spawn` has no post-fork/pre-exec hook to call `setrlimit`
  directly, so the *immediate* child (the shell) sets its own limits, which
  POSIX guarantees survive `exec`. POSIX-only; `error.OperationUnsupported` on
  Windows.
- **Streaming stdin after spawn.** `Handle.writeStdin`/`closeStdin` on a
  `spawnStreaming` handle (`Spec.stdin = .pipe`) — interactive request/
  response protocols (e.g. an MCP stdio transport) can now keep stdin open
  and drive it incrementally, independent of `run`'s one-shot `stdin_body`.
- **`argsafe` integration.** `runValidated`/`buildValidatedArgv` — opt-in;
  ordinary `run`/`runTimeout`/`spawnStreaming` still treat `Spec.argv` as
  trusted-by-construction, per module convention.
