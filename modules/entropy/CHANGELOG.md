# entropy — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-14** — **BEHAVIOURAL (aborts earlier, with its own message):** audit F1, round-2
  decision Q8. `fill` called `swapCancelProtection` unconditionally; on `std.Io.failing`, whose
  slot is std's `unreachableSwapCancelProtection`, that is undefined behaviour. Measured on the
  new test before the fix: Debug panicked with std's "reached unreachable code", ReleaseFast
  died with SIGSEGV. `fill` now compares the slot with `std.Io.unreachableSwapCancelProtection`
  first and panics with the new `unsupported_io_message`, in every build mode. It recognises
  that one std-defined slot, not a list of good backends, so no real `Io` changes behaviour and
  there is no switch. No consumer in the repo hands `fill` `std.Io.failing`.

- **2026-09-10** — **BEHAVIOURAL, not breaking:** `fill`'s `error.Canceled`
  arm is a real `@panic` with its own message now, not `unreachable` (audit
  finding F3). `unreachable` was correct against a conforming `Io`, but
  against one that violates the "honors `swapCancelProtection(.blocked)`"
  contract it was undefined — and undefined does not mean inert: measured
  under ReleaseFast, an exhaustive two-arm switch with one `unreachable` arm
  collapsed into the *other* arm unconditionally, so `fill` still aborted,
  but with a message blaming `EntropyUnavailable` for what was actually a
  contract violation. `fill` still panics unconditionally on both causes; a
  caller who was already relying on any abort at all sees no change. A
  caller inspecting the panic message against a violating `Io` now gets the
  true cause instead of a false one.

- **2026-09-04** — **Second audit pass** (the first was 2026-08-13, which
  closed `SecureSource`'s missing output coverage and the swapped-message
  arms). The module's central guarantee — abort
  rather than silently degrade — **had no test**. Three mutations were green at
  12/12: deleting the `@panic` arm, swapping it for `unreachable`, and
  replacing the whole `catch` with `catch { io.random(buf); }`, which is
  precisely the fall-back-to-the-degrading-source defect SPEC's opening section
  says this module exists to prevent. A caller drawing a key would have
  received plausible PRNG bytes with no way to tell.

  The property is an *effect*, not a value, so no value test can see it. `fill`
  now has one that forks, fails `getrandom(2)` inside the child with a
  seccomp-BPF filter, and asserts the child is killed by **SIGABRT with
  `unavailable_message` in its output**. All three mutations are red, in Debug
  **and** ReleaseFast. Reading the message matters: `unreachable` also aborts
  in Debug and ReleaseSafe and stops aborting only in ReleaseFast, so a test
  accepting any SIGABRT would have caught that mutation in exactly the mode the
  default gate does not run.

  Three doc claims corrected, each measured rather than reasoned about:

  * SPEC said an `Io` without `swapCancelProtection` "panics with 'reached
    unreachable code' … what is lost is the diagnostic text on a path nothing
    takes". Debug exits 13 and ReleaseSafe 134, but **ReleaseFast and
    ReleaseSmall do not panic at all** — one binary took SIGSEGV, another fell
    through into an unrelated branch and ran to completion. What is lost in the
    build that ships is the abort, not the text.
  * `fill`'s doc said a zero-length `buf` "still makes the call, so a caller
    cannot accidentally treat 'no entropy needed' as 'entropy is fine here'".
    Measured under the same seccomp filter: `fill(io, &.{})` **returns cleanly
    on a machine with no entropy at all**. The test that appeared to prove
    otherwise counted vtable invocations, which is a different quantity from
    entropy accesses.
  * `SecureSource`'s doc named twelve `std.Random.IoSource` call sites in `bfv`
    and `tfhe` by line, and framed migrating them as an open decision. They
    migrated: `std.Random.IoSource` now appears **nowhere in the collection as
    code**, and both modules added the comptime guard this doc says the swap
    requires. The line citations are removed rather than corrected — a claim
    about what exists anywhere can be re-measured with one `rg`.

- **2026-08-13** — **BEHAVIOURAL, and source-breaking on one symbol.** `fill` no
  longer aborts the host process on `error.Canceled`. The draw now runs with
  cancellation blocked — `io.swapCancelProtection(.blocked)` with a `defer`
  restore to whatever was in force — so the `error.Canceled` arm is
  `unreachable` and the only remaining `@panic` is
  `error.EntropyUnavailable`. This is std's own shape at the analogous site
  (`std.Io.Threaded.randomMainThread`), and the worked example in
  `std.Io.swapCancelProtection`'s doc comment.

  Why it is a defect fix rather than a preference: `error.Canceled` is routine
  control flow, not an entropy fault. `Syscall.start()` returns it *before
  touching the entropy source* whenever a cancel is already outstanding, and an
  EINTR mid-draw routes to the same error. `fill` sits on remote-triggered
  paths (`wireguard` handshake, `hpke` DHKEM, `sessions`, `acme` JWS), so a
  consumer timing out a peer-driven request while it drew an ephemeral key
  aborted the whole process.

  **Observable changes, in both directions:**
  - A cancelled task inside `fill` no longer dies; the cancel is observed after
    `fill` returns. Not free — the cancel is unobservable for the length of the
    draw, which is one non-blocking `getrandom(2)` on a healthy host but is
    unbounded before the kernel entropy pool is initialised. The alternative on
    that path was aborting, so this is strictly better, but it is a change.
  - `fill` now requires an `std.Io` implementing `swapCancelProtection`.
    `std.Io.failing` does **not** (every cancellation slot on it is
    `unreachable`), so `fill(std.Io.failing, buf)` now panics with "reached
    unreachable code" from inside std instead of with `unavailable_message`.
    `Threaded`, `Evented`, `Uring` and `Dispatch` all implement the slot; no
    production consumer passes `failing`.
  - **`canceled_message` is removed** — its arm no longer exists. Source-breaking
    for anyone who referenced it; contained, because the module has not shipped
    in a tagged release (this whole section is still `Unreleased`) and there are
    no references to it anywhere in the repo. `unavailable_message` is unchanged
    and is now the only message `fill` can abort with. `fill`'s signature is
    unchanged.

  Two test gaps closed at the same time, both mutation-proven:
  - `SecureSource` had **no output coverage**. A `fillFn` writing nothing — every
    `bfv`/`tfhe` secret key left as uninitialised stack memory — kept the suite
    green; so did a half-fill. Two sentinel-and-sliding-window tests now cover
    the adapter the way `fill` was already covered, and both mutations go red.
  - With two `@panic` arms, nothing pinned *which* message went with which
    error; exchanging them stayed green, so a seccomp-blocked host could have
    been told its draw was cancelled. One arm remains, so that binding is now
    structural rather than untested.

  `CountingIo`, the test double, copied the inner `std.Io`'s whole vtable and
  rebound `userdata` to itself, which mis-binds every slot it does not override
  (109 slots at Zig 0.16, three overridden). It gained a `swapCancelProtection`
  override, and its doc comment no longer claims it "keeps working if std grows
  more vtable entries" — it does not, and the mis-binding was silent.

- **2026-08-12** — New module. `fill(io, buf)` takes bytes from `std.Io.randomSecure` or aborts
  the process — the fail-closed entropy source for secret-bearing draws that
  std 0.16 leaves you to write yourself. `std.Io.random` is a CSPRNG with a
  documented silent-degrade clause and `std.Io.Threaded` honours it literally
  (a zeroed buffer plus an ASLR pointer, the pid and a clock); `randomSecure`
  is the fail-closed twin, but the two are one letter apart at a call site and
  the only std bridge from `std.Io` to `std.Random` — `std.Random.IoSource` —
  binds the degrading one. `SecureSource` is the missing counterpart, bound to
  `randomSecure`, for the twelve existing call sites in `bfv` and `tfhe` that
  adapt `std.Io` to `std.Random` around a secret-key draw.

  There is deliberately **no** error-returning twin: `std.Io.RandomSecureError`
  carries `error.Canceled` as well as `error.EntropyUnavailable`, so a
  narrowed `fillOrError` would report a cancellation as an entropy failure, and
  an honest one is `io.randomSecure` renamed. Callers that can return an error
  are told to call `try io.randomSecure(buf)` directly. The two abort messages
  are separate public constants for the same reason — they describe different
  faults, one a sandbox/machine problem and one the caller's own cancellation.

  Repo policy is now written down in `CONVENTIONS.md` §2.2, including the
  deliberate exceptions (`ssh` and `bulletproofs` keep their hand-rolled
  `getrandom(2)` loops; `sealedbox` and `signal`'s KAT seams keep `io.random`
  so their vectors stay reproducible).
