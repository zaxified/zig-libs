# stopsignal — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-15** — Independent review, no-panic sweep and scope survey (card: Scope `core`, review and panic recorded; `Compared with`, Backlog). Fixes: `poll`/`wait` return `error.Unsupported` off Linux instead of failing to compile on Windows; a second `deinit`, or `poll`/`wait` after one, no longer touches a stale descriptor number (the struct holds `fd_ = -1` and empty masks instead of `undefined`). Docs: LIFO `deinit` of overlapping instances, ignored-at-start signals are delivered, `wait` returns only set members. Tests: set already blocked, pending outside signal, ignored-at-start SIGHUP, deinit twice.
- **2026-11-15** — New module: the process's own stop signals (SIGTERM/SIGINT/SIGHUP/SIGQUIT/SIGUSR1/SIGUSR2) via blocked mask + `signalfd` — `StopSignals.init/wait/poll/fd/deinit`, no global handler (consumer request 2026-11-15; Go `signal.NotifyContext`, tokio `signal::unix`). Kernel-anchored tests only (signals sent to the test's own thread).
