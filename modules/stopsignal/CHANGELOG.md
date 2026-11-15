# stopsignal — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-15** — **NO CONSUMER-VISIBLE CHANGE:** docs: procrun now starts children with an empty signal mask (`procrun.Spec.reset_signal_mask`), so the fork/exec finding names only std's spawn as passing the blocked set on.
- **2026-11-15** — New module: the process's own stop signals (SIGTERM/SIGINT/SIGHUP/SIGQUIT/SIGUSR1/SIGUSR2) via blocked mask + `signalfd` — `StopSignals.init/wait/poll/fd/deinit`, no global handler (consumer request 2026-11-15; Go `signal.NotifyContext`, tokio `signal::unix`). Kernel-anchored tests only (signals sent to the test's own thread).
