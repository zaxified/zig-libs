# coconut — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **authority_sign 69 / user_issue 3 / user_show 51**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. No constant-time claim exists in `SPEC.md` or `README.md`; nothing was added. Three targets split by which party holds the secret (authority key share, user attributes at local commitment, user attributes plus blinding at proof showing). ⭐ Independently reproduced `bls12_381`'s `ctSelect` finding with the identical disassembled sequence `bt %esi,%edx; jae` — the second witness that turned it from one measurement's surprise into a settled result. ⭐ This agent also added the campaign's third context class: **over-taint artifact** — `ff.zig`'s `conditionalAdd`/`conditionalSub`/`limbsCmpLt` are real `je`/`jne` but branch on a limb COUNT or a Montgomery-form FLAG, not on the secret's value, and light up only because the harness taints the whole opaque `Fe` struct including its metadata (as `bls12_381`'s own harness also does). ⚠ Not adjusted for single-process over-taint either.

- **2026-09-07** — `fuzzShowProofDecode` had only ever decoded the empty slice. It drew its
  bytes with `smith.bytes(&buf)` and then took a length from
  `smith.valueRangeAtMost(u16, 0, 1024)`; a ranged `Smith` draw reads eight octets as a
  little-endian `u64` and returns the range MINIMUM when fewer remain, and `bytes` had already
  consumed them — so `len` was 0 on every input and `ShowProof.fromBytes` refused on its
  `bytes.len < 2` line. The "attacker-controlled count vs. actual buffer length" surface the
  harness's own comment describes was never entered once. Now one `smith.slice(&buf)` call,
  plus an eight-seed corpus built through the module's own `toBytes` (a valid `ShowProof`
  carries four compressed group elements and three `Fr` scalars, so nothing hand-written gets
  past `g1.fromBytesCompressed`) covering the round-trip encoding, a short encoding, an
  out-of-range `disclosed` octet, a `q` of `0xFFFF` against the real length, `q = 0`, an extra
  scalar, an all-zero body and a two-octet stub. Measured: **0 of 8 seeds non-empty, 0 proofs
  decoded and 0 disclosure octets walked before; 8 of 8 non-empty, 1 decoded, 3 disclosure
  octets walked and 7 typed errors after.**

- **2026-08-12** — **BREAKING:** `keygen` and `proveCredential` take `io: std.Io` instead of
  `random: std.Random`, and draw from `std.Io.random` — contractually a
  CSPRNG. The old shape did not merely permit the mistake, it *taught* it:
  `keygen`'s doc comment said "seed it for deterministic tests" with nothing
  saying "and never in production". A consumer who followed that advice
  shipped an authority master secret `(x, y₁…y_q)` that is a pure function of
  the seed — anyone who recovers the seed issues arbitrary valid credentials
  for the whole system, and the `t`-of-`n` threshold split becomes decoration
  because the dealer's secret never had to be reassembled from shares. On the
  show side, witness nonces that repeat across two proofs let a verifier who
  sees both extract the HIDDEN attributes and the blinding `r` by the standard
  two-transcript Sigma-protocol argument, i.e. exactly the privacy selective
  disclosure exists to provide.

  The guarantee is now at the type: a `std.Random.DefaultPrng` is not
  expressible at a `std.Io` parameter. This is the `bbs`/`ibe`/`tlock` shape.

  **Migration:** obtain an `Io` (`std.Io.Threaded.init(gpa, .{})` then
  `.io()`) and pass it where the `std.Random` used to go. Coconut has no
  published byte-exact test vector (`SPEC.md` §3), so no consumer needs a
  deterministic issuance; test suites that do can call the new
  `keygenSeededForTest` / `proveCredentialSeededForTest`, whose names are the
  signal. New public `Entropy` union backs both paths.
- **2026-07-18** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on `asonnino/coconut` (Python) /
  `nymtech/coconut` (Rust/Go) — no byte-exact vector exists for Coconut; anchored
  internally on the deterministic PS pairing-verify identity (design reference, not a
  test anchor).
