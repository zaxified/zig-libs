# entropy

One blessed **fail-closed** entropy source for secret-bearing draws: `fill`
takes bytes from `std.Io.randomSecure` or aborts the process. It implements no
generator and holds no state — every byte it returns came out of
`randomSecure` on that call.

- **Why:** std 0.16's `std.Io.random` is a CSPRNG with a documented
  silent-degrade clause ("seeded by `randomSecure`, or a less secure mechanism
  upon failure"), and `std.Io.Threaded` honours it literally — on
  `error.EntropyUnavailable` it seeds from a zeroed buffer plus an ASLR
  pointer, the pid and a clock. `std.Io.randomSecure` is the fail-closed twin,
  but the two are one letter apart at the call site, and the only std bridge
  from `std.Io` to `std.Random` (`std.Random.IoSource`) binds the degrading
  one. std ships no bridge from `randomSecure` to anything. This is that
  bridge.
- **Platform:** any (`std.Io` carries the OS-specific half — `getrandom(2)` on
  Linux, `arc4random_buf` under libc). **Role:** util.
  **Concurrency:** reentrant (no state at all; `randomSecure` is documented
  threadsafe). **Allocation:** none, anywhere.
- **It aborts the host process.** That is a deliberate trade and it is the
  floor, not the recommendation — see [Which one to call](#which-one-to-call).

Provenance: original work, written against the `std.Io` documentation in Zig
0.16. Nothing is ported and no third-party implementation was studied, so no
`NOTICE` entry is required (root [`NOTICE`](../../NOTICE) §0). The
abort-rather-than-return-weak-entropy posture is the one
`ssh/src/transport.zig` and `bulletproofs/src/rangeproof.zig` already take
against raw `getrandom(2)` in this repo.

## API

```zig
const entropy = @import("entropy");

// Fail-closed fill. Aborts the process if the OS has no entropy.
var key: [32]u8 = undefined;
entropy.fill(io, &key);

// A std.Random bound to randomSecure — the fail-closed counterpart of
// std.Random.IoSource, for internals written against std.Random.
var src: entropy.SecureSource = .{ .io = io };
const random = src.interface();   // every draw is a randomSecure syscall

// The abort messages are public, so a consumer can pin them in its own tests.
_ = entropy.unavailable_message;
_ = entropy.canceled_message;
```

## Which one to call

| Your signature | Call |
|---|---|
| returns an error | **`try io.randomSecure(buf)`** — direct, no import, and the caller decides what a failure means |
| returns `void` / a value, and the bytes are a secret | `entropy.fill(io, buf)` |
| internals are written against `std.Random`, entry point takes `std.Io` | `entropy.SecureSource` |
| the bytes are **not** a secret (jitter, backoff, tiebreaks, fixtures, hash seeds) | `io.random(buf)` — do not pay a syscall, let alone an abort, for these |

Repo-wide this is a rule, not a suggestion: see `CONVENTIONS.md` §2.2, which
also names the deliberate exceptions.

There is **no** error-returning twin here, on purpose.
`std.Io.RandomSecureError` is `error{EntropyUnavailable} || std.Io.Cancelable`,
so a `fillOrError` narrowed to `error{EntropyUnavailable}` would report a
*cancellation* as an entropy failure, and one carrying the full error set is
`io.randomSecure` with a different name and an extra import.

## Notes

- Zero-length buffers are legal and still make the call, so "no bytes needed"
  cannot be mistaken for "entropy works here".
- `SecureSource` makes **every** draw a syscall, including the single bytes
  `std.Random.int`/`uintLessThan` take. Correct for key and nonce material;
  wasteful for anything else.
- The abort paths have no unit test and cannot have one — Zig has no catchable
  panic. What is tested is everything that decides whether they are reachable
  and correct; [SPEC.md](SPEC.md) says what that buys and what it does not.

## Verify

```
zig build test-entropy
```
