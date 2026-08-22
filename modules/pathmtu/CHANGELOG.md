# pathmtu — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-22** — `LiveProber.attempt` panics on a probe smaller than the ICMP header,
  matching the panic it already had for the opposite bound, now that
  `icmp.echo.writeEchoRequest` reports a short buffer instead of asserting.
- **2026-08-18** — Audit fixes (three confirmed defects, found before this
  module was ever tagged):
  - **Critical — stack-memory disclosure.** `Options.ceiling_mtu` flowed
    into `LiveProber`'s fixed 9000-byte (`max_probe_mtu`) stack buffer
    unclamped. Debug/ReleaseSafe panicked (`index out of bounds`);
    **ReleaseFast** — where Zig's own slice-bounds check compiles out along
    with every other runtime safety check — read past the buffer end and
    handed the over-length slice to `sendto(2)`, putting adjacent stack
    memory on the wire as ICMP payload and returning a fabricated `Result`
    instead of an error. Fixed: `probe()` now refuses an explicit
    `ceiling_mtu` above `max_probe_mtu` (`error.CeilingTooHigh`) rather than
    clamping it — a caller who names a ceiling this module can never probe
    is stating an expectation the module cannot meet, refused the same way
    `error.CeilingTooLow` already is, not silently answered with a smaller,
    unrequested ceiling. `LiveProber.attempt` also gained a defense-in-depth
    `@panic`-based bounds check on the same invariant (deliberately not a
    `std.debug.assert` — that class of check is exactly what let the bug
    through ReleaseFast). `LiveProber.buf` is now zero-filled at
    construction instead of `undefined`, closing a smaller, in-bounds
    version of the same disclosure (uninitialized stack bytes past the
    8-byte echo header, sent on every probe, not only an oversized one).
  - **`searchWith`'s `ceiling > floor` precondition, fail-open in
    ReleaseFast.** Was a bare `std.debug.assert`, which compiles out
    entirely in ReleaseFast/ReleaseSmall; `searchWith` is `pub` and its own
    doc comment recommends it directly to a consumer substituting a
    transport, so it was not protected by `probe()`'s own `CeilingTooLow`
    guard. A violated precondition underflowed `hi - lo` on unsigned `u16`
    arithmetic and hung (confirmed: 15+ seconds) rather than panicking.
    Fixed: `searchWith` now returns `error.CeilingTooLow` itself before
    entering the search loop. SPEC.md's "termination is therefore
    structural, not merely typical" claim, which was false in exactly this
    lane, is corrected to state the precondition it depends on and how that
    precondition is now enforced.
  - **Threat model — an undocumented, opposite-direction spoofing case.**
    SPEC.md documented that a spoofed Frag-Needed/Packet-Too-Big hint
    "cannot claim a size larger than what has already failed," but did not
    say that `applyOutcome`'s unconditional `lo.* = size` on `.ok`, combined
    with `classify` authenticating only on ident+seq, lets a single forged
    echo reply for the first (ceiling) probe converge the whole search
    instantly to a **falsely large** `mtu` with `blackhole = false` — the
    "everything's fine" signal this module exists to independently confirm.
    SPEC.md's "Threat model" section now documents this directly, states
    plainly that no code change alters the module's stance toward an
    on-path attacker (unauthenticated, matching `traceroute`), and adds one
    honestly-scoped mitigation against a *blind off-path* attacker only:
    `probe`'s live path now seeds its starting `seq` from `getrandom(2)`
    (`randomStartSeq`) instead of the fixed value 1, so a blind spoofer must
    now guess a full 16-bit unknown instead of spraying ~15–20 sequential
    values. Two further candidates (randomizing `ident`; a per-probe
    payload nonce) were considered and deliberately not implemented — see
    SPEC.md for why.
- **2026-08-18** — New module: Path MTU discovery for IPv4/IPv6 on Linux —
  `query` (kernel PMTU cache) and `probe` (authoritative DF-bit binary
  search that detects ICMP black holes the cache structurally cannot see).
  `probe`'s wire classification is anchored against ICMP Fragmentation
  Needed / Packet Too Big bytes captured from a real forwarding router with
  a genuinely lowered-MTU link (`veth` pair in an unprivileged netns); the
  search algorithm and the black-hole/well-behaved distinction are verified
  offline against a fake `Prober` (class A · oracle MIXED — see SPEC.md).
