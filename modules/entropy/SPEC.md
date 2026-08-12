# entropy — design & threat model

What it is and how to call it: [README.md](README.md).

## The defect this exists to prevent

`std.Io.random`'s contract permits a silent downgrade, and the default
implementation takes it. On `error.EntropyUnavailable`, `std.Io.Threaded` seeds
its CSPRNG from `fallbackSeed`: a zeroed buffer, an ASLR pointer, `getpid()`
and a clock reading. Measured on this host, that produces 17 non-zero bytes out
of 32, with the pid recoverable in plaintext and only two bytes differing
between consecutive calls.

The failure mode is not that this is weak. It is that it is **invisible**. A
key drawn this way has the right length and the right entropy *shape*; every
round-trip test, every KAT, every fuzz harness downstream stays green, and
nothing in the process ever learns that the OS refused. There is no test a
consumer of the key could write that would catch it, because the key is only
wrong relative to a fact — "the OS said no" — that was discarded at the point
of the draw.

That is the asymmetry the whole module rests on: an entropy failure is
detectable *only* at the moment it happens.

## Why `@panic`, and what it costs

`fill` returns `void`. At that signature the choices are exhaustive:

1. return weak bytes (what `io.random` does) — the invisible failure above;
2. return zeros or leave the buffer untouched — worse, and equally invisible;
3. abort.

There is no fourth option, and (1) and (2) are the same defect. So the panic is
not a strong opinion about aborts in libraries; it is the only remaining arm
once the signature has no error channel.

The cost is real and is not minimised here: a library aborting its host is
severe, it is unrecoverable in-process, and it converts a subsystem's problem
into a whole-process outage. Two things bound it:

- **It is the floor, not the recommendation.** Any caller whose signature can
  return an error is told, in the module doc, the README table and
  `CONVENTIONS.md` §2.2, to call `try io.randomSecure(buf)` and not this. `fill`
  is for the call sites that structurally cannot.
- **The abort is operationally recoverable; the alternative is not.** An
  operator reads the message, fixes the sandbox policy, restarts. A key minted
  from a pid and a clock outlives the incident, and nothing downstream will ever
  flag it.

The two abort messages are separate public constants because they describe
different faults. `EntropyUnavailable` is a machine/policy problem
(seccomp, Landlock, a container profile, an unreachable `arc4random_buf`);
`Canceled` is the caller's own `std.Io` cancelling an operation that had no
error channel to report on — nothing is wrong with the machine's entropy at
all. Collapsing them into one string would send an operator to the wrong place.
The `catch |err| switch (err)` is exhaustive, so a future std error member is a
compile error rather than a silent fold into one of these two.

## What the tests can and cannot establish

**Cannot:** that `fill` actually aborts. Zig has no catchable panic, so
observing it requires re-exec'ing the test binary in a child process, which
costs a fork per run to assert a two-line `catch`. That trade was declined.

**Can, and this is the load-bearing part:** *which std entry point the call goes
to.* `CountingIo` copies the whole `std.Io.VTable` from a real `Io`, replaces
only the `random` and `randomSecure` slots with counting delegates, and hands
back a fully working `std.Io`. `fill` must show `secure_calls == 1,
random_calls == 0`.

This distinction is the only thing worth testing here, and it is worth
labouring why. Every *output-shaped* assertion one might reach for — "the bytes
differ between calls", "the buffer is not all zero", "the whole buffer was
written" — passes identically under `fill = io.random(buf)`, because bytes out
of `io.random` on a healthy host **are** random. A suite made of those tests
would be fully green against a module that had lost its entire reason to exist.
Only an assertion about the *route* separates the two implementations, so that
is the assertion the suite is built around.

Verified by mutation, and the split is worth recording exactly. With `fill`'s
body replaced by `io.random(buf)`, `zig build test-entropy` reports **4 passed,
4 failed**. The four reds are the four tests that assert on the route
(`fill draws from randomSecure and never from random`, `SecureSource routes
every draw through randomSecure`, and the `secure_calls == 1` assertions inside
the zero-length and large-buffer tests). The four greens are precisely the
output-shaped and premise tests — bytes differ across calls, the whole buffer
is covered, `std.Io.failing`'s contract, the message constants — none of which
can tell the two implementations apart. That 4/4 split is the evidence for the
paragraph above: half this file would certify a module that had lost its
purpose.

`std.Io.failing` is pinned separately as the premise: a std-provided `Io` whose
`random` returns zeros and whose `randomSecure` refuses. It is std's own most
extreme statement of the degrade, and if either half of that contract changes,
the test says so.

## Scope

- **No generator.** No pool, no reseed, no DRBG, no state of any kind. Adding
  one would give this module something to be wrong about, and the module's
  whole value is that it has nothing to be wrong about.
- **No retry or chunking.** `randomSecure` is called exactly once per `fill`,
  asserted by a test. Short reads and retries are `std.Io`'s contract; a retry
  loop here would be a second, undocumented entropy policy.
- **No detector.** Nothing here can tell whether the `std.Io` it was handed has
  a real entropy source behind it — a consumer that passes a doctored `Io` gets
  what it asked for. This module removes the *accident* (reaching for the
  degrading call because it is the one that fits), not the possibility. That is
  the same ceiling `jwe`'s `Entropy` and `dtls`'s `Entropy` unions hit, from the
  other direction.
- **`ssh` and `bulletproofs` are not migrated.** Both hand-roll a
  `getrandom(2)` loop with the same abort posture, and both are deliberately
  `platform = .linux` for it. Rewriting them onto `std.Io` is a behaviour change
  to working, audited code for no gain; see `CONVENTIONS.md` §2.2.
