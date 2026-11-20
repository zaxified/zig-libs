# stopsignal

The process's own stop signals (SIGTERM, SIGINT, SIGHUP, ...) as a readable event
source, for a daemon that must flush state and exit cleanly. It blocks the chosen
signals in the calling thread and reads them from a Linux `signalfd`: no signal
handler runs, no global state is kept, and the arrival is a value (`Signo`) the
caller waits for, polls for, or puts into its own epoll/io_uring loop.

**Status:** `gap · linux · util · single_owner` — written against a consumer request
(2026-11-15): three daemons had each hand-written the same `sigprocmask` + `signalfd`
code.

**Model after:** Go `os/signal` (`signal.NotifyContext`) and tokio `signal::unix`.

## Use

```zig
const stopsignal = @import("stopsignal");

var stop = try stopsignal.StopSignals.init(.{});   // SIGTERM + SIGINT; .hup/.quit/.usr1/.usr2 opt-in
defer stop.deinit();
// start worker threads only now: they inherit the blocked mask
while (true) {
    if (try stop.poll()) |s| { _ = s; break; }     // flag form, for a polling loop
    // ... one unit of work ...
}
// or block: const which = try stop.wait(io);     // cancelable through io
```

- `init(set)` — blocks the set in the calling thread, opens the signalfd.
  **Call it before any other thread exists**; a thread started earlier keeps the
  signal unblocked and the kernel may deliver it there, bypassing this module.
- `wait(io)` — blocks until one arrives; `error.Canceled` when the task is cancelled.
- `poll()` — non-blocking, `null` when nothing is queued.
- `fd()` — the signalfd for the caller's own event loop.
- `deinit()` — closes the fd and unblocks what `init` blocked (not what the caller
  had blocked before). Same thread as `init`.
- `childMask()` — the signals this instance blocked; a child inherits the blocked
  mask across `fork`/`exec`. procrun's Linux spawner resets it by default
  (`Spec.reset_signal_mask`); a program with its own spawn or pre-exec step unblocks
  this set in the child before `exec`.

Not Linux: `init`, `poll` and `wait` return `error.Unsupported`. Details and refusals: [SPEC.md](SPEC.md).

## Not provided

A signal handler, real-time or non-stop signals, several subscribers per signal, disposition control and escalation policy are refused on purpose; sender pid/uid, a non-blocking descriptor option and Windows/macOS support are open. See SPEC *What is deliberately not done* and *Backlog / deferred*.

Provenance: clean-room from the Linux `signalfd(2)` and `sigprocmask(2)` man pages; the
API shape follows Go's `os/signal` and tokio's `signal::unix` (public documentation only,
no third-party source ported or studied), so there is no `NOTICE` file.
