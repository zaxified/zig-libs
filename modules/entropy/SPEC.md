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

There is exactly **one** abort message, and it covers exactly one fault:
`error.EntropyUnavailable`, a machine or policy problem (seccomp, Landlock, a
container profile, an unreachable `arc4random_buf`). The `catch |err| switch
(err)` is exhaustive over `std.Io.RandomSecureError`, so a future std error
member is a compile error rather than a silent fold into this one.

## Cancellation is not an entropy fault

Until 2026-08-13 there was a second abort message and a second `@panic`, for
`error.Canceled`. That was wrong, and the argument for it — that a `void`
signature has nowhere to report a cancellation — skipped the option std itself
takes at the same site.

`std.Io.RandomSecureError` is `error{EntropyUnavailable} || std.Io.Cancelable`,
and neither producer of `error.Canceled` means anything is wrong with the
machine: `Syscall.start()` returns it *before touching the entropy source*
whenever a cancel is already outstanding on the task, and an EINTR mid-draw
routes through `checkCancel()` to the same error. A consumer timing out a
peer-driven request while it draws an ephemeral key was enough to abort the
host process — `wireguard`'s handshake, `hpke`'s DHKEM, `sessions`, `acme`'s
JWS are all on that shape of path. That is a library killing its host over a
routine timeout, which is a far worse trade than the one the section above
argues for.

The fix is std's own, at the analogous site: `std.Io.Threaded.randomMainThread`
wraps its `randomSecure` call in `swapCancelProtection(.blocked)` with a
`defer` restore, and only then writes `error.Canceled => unreachable`. The doc
comment on `std.Io.swapCancelProtection` carries that idiom as its worked
example. `fill` does the same, so its `error.Canceled` arm is `unreachable`
*because of the two lines above it*, not because the error cannot occur.

Two costs, neither hidden:

- **A cancel aimed at a task inside `fill` is not observed until the draw
  returns.** On a healthy host that is one non-blocking `getrandom(2)`. It is
  not bounded on a machine whose entropy pool is not yet initialised (early
  boot, a fresh VM), where `getrandom(2)` with `flags = 0` blocks until it is.
  The alternative on that same path is not "cancel promptly", it is "abort the
  process".
- **`fill` now requires an `std.Io` that implements `swapCancelProtection`.**
  `std.Io.failing` does not — every cancellation slot on it is `unreachable` —
  so `fill(std.Io.failing, buf)` panics with "reached unreachable code" from
  inside std instead of with `unavailable_message`. Verified by running it.
  That `Io` simulates a machine with no `Io` operations at all, a draw on it was
  already fatal, and no production consumer passes it; what is lost is the
  diagnostic text on a path nothing takes. `Threaded`, `Evented`, `Uring` and
  `Dispatch` all implement the slot.

The removal of the second `@panic` arm also closed a real test gap. With two
arms and two message constants, no test could tell *which* message was on which
arm — exchanging them left the suite green, so a seccomp-blocked host could
have been told its draw was cancelled. With one arm the binding is structural
rather than asserted.

## What the tests can and cannot establish

**Cannot:** that `fill` actually aborts. Zig has no catchable panic, so
observing it requires re-exec'ing the test binary in a child process, which
costs a fork per run to assert a one-line `catch`. That trade was declined. With
two abort arms this left a real gap — nothing pinned which message went with
which error. With one arm it does not: `unavailable_message` is the only
`@panic` argument in the module, so the binding is a property of the source
rather than of a test.

**Can, and this is the load-bearing part:** *which std entry point the call goes
to.* `CountingIo` copies the whole `std.Io.VTable` from a real `Io` and replaces
the slots `fill` uses with observing delegates. `fill` must show
`secure_calls == 1, random_calls == 0`.

**What `CountingIo` is not.** It is not a fully working `std.Io`, and the doc
comment that claimed it was ("keeps working if std grows more vtable entries")
was wrong until 2026-08-13. It sets `userdata = self` so the overrides can find
the probe, which means every slot that is *not* overridden holds the inner
implementation's function pointer and receives the **probe's** userdata —
a `*CountingIo` where a `*std.Io.Threaded` is expected. `std.Io.VTable` has 109
slots at Zig 0.16; three are overridden and the other 106 are mis-bound, so
calling one is undefined behaviour. Copying the vtable buys compilation against
a moving std and nothing else. The rule that replaces the false guarantee:
**every `std.Io` function reachable from `fill` or `SecureSource` needs an
override in `CountingIo`.** Today that set is `random`, `randomSecure` and
`swapCancelProtection`.

That is not a theoretical hazard, and it did not announce itself. When
`swapCancelProtection` was added to `fill` it had no override, and the suite
stayed green: `std.Io.Threaded.swapCancelProtection` discards its `userdata`
(`_ = t;`) and reads a thread-local instead, and `@alignOf` is 8 for both
structs so even the `@alignCast` safety check stayed quiet. Measured: with the
override deleted, the run is `11 pass, 1 fail` — the one red being the new
cancel-protection test, which sees *nothing happen*, not a crash.

**A second measured limit, which shapes what the cancel tests can assert.**
Under the Zig test runner the main thread is not a `std.Io.Threaded` task, so
`Thread.current` is `null` and `Threaded.swapCancelProtection` stores nothing
and always answers `.unblocked`. A test that delegated and read the state back
would therefore report `.unblocked` whether or not `fill` blocks anything.
`CountingIo` models the protection state itself for that reason (while still
driving the inner `Io`), so the assertion has teeth; the mutation evidence
below is what makes that claim checkable rather than a promise.

The route distinction is worth labouring. Every *output-shaped* assertion one
might reach for — "the bytes differ between calls", "the buffer is not all
zero", "the whole buffer was written" — passes identically under
`fill = io.random(buf)`, because bytes out of `io.random` on a healthy host
**are** random. A suite made only of those tests would be fully green against a
module that had lost its entire reason to exist. Only an assertion about the
*route* separates the two implementations, which is why the suite is built
around one. It is not, however, sufficient on its own: a route assertion counts
syscalls and inspects no bytes, so it is blind in the opposite direction — see
the `SecureSource` measurement below.

Verified by mutation, and the split is worth recording exactly. With the
`randomSecure` call in `fill` replaced by `io.random(buf)`,
`zig build test-entropy` reports **5 passed, 5 failed, 2 crashed** of 12
(exit 1). The seven that notice are the route assertions (`fill draws from
randomSecure and never from random`, `SecureSource routes every draw through
randomSecure`, the `secure_calls == 1` checks inside the zero-length,
large-buffer and large-`SecureSource` tests) plus the two cancel-protection
tests, which crash rather than fail because the draw they inspect never
happened. The five greens are precisely the output-shaped and premise tests —
bytes differ across calls, both whole-buffer coverage checks, `std.Io.failing`'s
contract, the message constant — none of which can tell the two implementations
apart. That split is the evidence for the paragraph above: nearly half this file
would certify a module that had lost its purpose.

*(Recorded for comparison: before 2026-08-13 the same mutation gave a 4/4 split
of 8 tests. The suite grew by the four tests added for the cancel-protection fix
and the `SecureSource` output gap.)*

**What the output-shaped tests do buy, on the other entry point.** `fill` had a
sliding-window coverage assertion from the start; `SecureSource` — the adapter
all twelve `bfv`/`tfhe` secret-key draws go through — had none, so a `fillFn`
that wrote *nothing*, leaving every key as uninitialised stack memory, left the
suite fully green. Measured, and it is the `wireguard`-nonce class exactly:
`fillFn` → `fill(self.io, buffer[0..0])` was **8/8 green** before the two
`SecureSource` coverage tests existed, and is **10 pass, 2 fail** (exit 1) with
them; the subtler `buffer[0 .. buffer.len / 2]` gives the same 10/2. Route
assertions and output assertions catch disjoint defects, and this module needed
both on both entry points.

`std.Io.failing` is pinned separately as the premise: a std-provided `Io` whose
`random` returns zeros and whose `randomSecure` refuses. It is std's own most
extreme statement of the degrade, and if either half of that contract changes,
the test says so.

## What a draw costs, and why the adapter is not where to fix it

`SecureSource` makes one `getrandom(2)` syscall per `std.Random` draw, including
the four bytes `std.Random.int(u32)` takes. That is the design — every byte came
out of the OS on this call — and it is expensive. The number belongs here rather
than in a review comment, and so does where it goes.

Measured 2026-08-13 on this host (Zig 0.16, `-Doptimize=ReleaseFast`, a
temporary bench added to `src/root.zig` and removed afterwards), 100 000
iterations per row:

| path | ns per draw |
|---|---|
| `SecureSource` → `std.Random.int(u32)` | **816** |
| `fill(io, buf[0..4])` | 796 |
| `io.randomSecure(buf[0..4])` | 773 |
| bare `getrandom(2)` on 4 bytes, no `std.Io` | **771** |
| the `swapCancelProtection` pair alone | ~0 (27 µs / 100 000) |
| `std.Random.IoSource` → `int(u32)` (i.e. `io.random`) | 23 |

**94% of a `SecureSource` draw is the syscall itself.** `std.Random`'s own
machinery costs 20 ns, the `std.Io` vtable hop 2 ns, and the cancel-protection
pair the 2026-08-13 fix added is not measurable at this resolution. So there is
nothing in the adapter, in `fill`, or in the vtable to tune: the only lever is
*fewer, larger* draws. For comparison, one bulk `fill` of 400 000 bytes takes
1.26 ms, so the per-draw route is **65×** more expensive for the same bytes.
(An earlier note recorded 872 ns and 85×; both are superseded by the row above,
which was re-measured rather than carried forward.)

**Buffering inside `SecureSource` is still refused, and the measurement does not
change that.** A pool of pre-drawn bytes living across calls is a userspace
CSPRNG wearing this module's name: bytes get *stretched*, one OS draw serves
several logically independent secrets, and compromising the pool at time T
compromises secrets drawn after T. That is the exact property `randomSecure`
exists to deny.

**A per-operation buffer is a different object, and the difference is not
cosmetic.** One `fill` at the top of an operation, consumed byte-for-byte, then
`secureZero`d: the map from OS bytes to consumed bytes is the identity (no
expansion function, so nothing is stretched), no byte serves two operations, and
no state survives the call. The exposure it adds is raw entropy sitting in a
frame for the length of one operation — and whoever can read that frame can
already read the secret being built from it in the same frame, so it puts
nothing new within reach. A cross-call pool does: it exposes secrets that do not
exist yet, belonging to callers that have not run. That asymmetry is the whole
argument, and it is why "buffer per operation" is allowed here and "buffer
inside the adapter" is not.

**If it is ever done, do it with a small refilling window, not one big buffer.**
Measured over 393 216 bytes (`bfv.keyGen`'s exact byte budget at N = 8192,
L = 4), varying the size of each `fill`:

| window | syscalls | total |
|---|---|---|
| 8 B (today's per-draw route) | 49 152 | 39.7 ms |
| 64 B | 6 144 | 5.77 ms |
| 256 B | 1 536 | 2.36 ms |
| 1 KiB | 384 | 2.17 ms |
| **4 KiB** | **96** | **1.84 ms** |
| 16 KiB | 24 | 1.60 ms |
| 64 KiB | 6 | 1.62 ms |

A 4 KiB window recovers 95% of the entire available saving. Going to a
whole-operation buffer buys another 0.24 ms and holds 384 KiB of *unconsumed*
raw entropy instead of 4 KiB — worse on exposure, negligibly better on time. So
the shape to reach for is a small window refilled by `fill` as it drains, inside
one operation, zeroized on the way out.

**No such helper is exported, because there is no caller for it.** All twelve
`SecureSource` sites in the collection are `pub fn X(io: std.Io)` wrappers whose
body calls the `XForTest(random: std.Random)` twin — and every one of those
twins carries `comptime if (!builtin.is_test) @compileError(…)`. Zig analyses the
twin's body because the wrapper references it, so **the wrappers do not compile
outside a test build either**. Verified rather than reasoned: a non-test
`zig build-obj` over a root that calls `Bfv(params.test_tiny).keyGen(io)` fails
with that `@compileError`, reported through `keyGen` (`bfv.zig:683`), exit 1;
the same probe against `Tfhe(params.toy).lweKeyGen(16, io)` fails identically
(`tfhe.zig:292`). Every millisecond in the tables above is therefore paid only
by test builds. A helper here would be new API surface — on a module whose value
is having almost none — serving a path production cannot reach. The measurement
and the idiom are written down; the code is not.

That reachability fact is a defect in `bfv`/`tfhe`, not in this module, and it is
recorded in their audit files rather than fixed here.

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

## Anchoring

**Anchor grade:** class D · oracle n/a

- **Class D** — our own design — no third party exists to agree with, by construction.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** own policy binding over std.Io.randomSecure; no algorithm and no wire, so no third party to agree with — tests pin WHICH std entry point is called, not any output value
