# entropy — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- New module. `fill(io, buf)` takes bytes from `std.Io.randomSecure` or aborts
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
