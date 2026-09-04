# pathmtu — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-04** — **First audit.** Three HIGH-class defects, all fixed with
  tests that go red when the fix is reverted.

  **The 2026-08-18 CRITICAL was regression-tested on one of its two routes.**
  `LiveProber`'s fixed 9000-byte stack buffer is reached both by
  `Options.ceiling_mtu` (refused above `max_probe_mtu`, two tests named for the
  finding) and by `Options.iface` → `SIOCGIFMTU` (clamped, no test). Changing
  that clamp to 65535 left the suite green in Debug, ReleaseSafe **and**
  ReleaseFast, while `ifaceMtu("lo")` on an ordinary host is 65536 — so a
  perfectly legitimate `probe(dest, .{ .iface = "lo" })` reproduced the
  original defect, a bounds panic in the safe modes and a SIGSEGV in
  ReleaseFast. A live test could not have held it either: `probe` needs
  CAP_NET_RAW, so on an ordinary host it skips, and a skip is a pass. The
  ceiling and the buffer-capacity check are now `ceilingFor`/`probeFits`,
  testable with no socket and no privilege; the zero-filled buffer (the
  stack-disclosure half of the same fix) has a test too.

  **A forged MTU hint named the answer outright.** `applyOutcome` set `lo` to
  the router's hint and returned, so the reported size was never probed.
  Against a prober whose true path MTU is 300, one forged Fragmentation-Needed
  answering the first probe gave **`mtu = 1499, blackhole = false`, in 2
  probes** — any value in `(floor, ceiling)`, for the cost of guessing
  `ident`, since ICMP is unauthenticated. SPEC said a hostile hint "can only
  make the search slower, never wrong" and that this shape was structurally
  impossible; both sentences are corrected. An accepted hint now narrows `hi`
  only, so `Result.mtu` is always a size this module probed — one extra probe,
  and it is what RFC 1191 §3 and RFC 8201 §4 require (a PMTU estimate may only
  decrease).

  **`timeout_ms` bounded idle waiting, not the attempt.** The deadline was
  checked only on the EAGAIN branch, so an arriving packet `continue`d past it
  without consulting the clock: with a 1 ms budget the loop absorbed **8739
  unrelated packets in 18 ms** with one deadline check. Free to anyone who can
  put ICMP on the host, and automatic on the RAW lane. Hoisted to the top of
  the receive loop.

  Also: both live tests took their skip condition from the code under test —
  forcing `query` to return `SocketFailed`, or `probe` to return
  `PermissionDenied`, turned each into a SKIP with the suite green, deleting
  every line of live-path coverage. They ask the socket layer directly now.
  The fuzz harness ran exactly one input (`Smith` ranged draws return the
  range's minimum, and `Smith.bytes` had already consumed the input):
  instrumented at **1,000,000 rounds, 3,000,000 `classify` calls, every one
  with a zero-length packet, ident 0, seq 0**; it derives length, ident and
  seq from the bytes now, measured at 99% non-empty packets. Four guards on
  the hint and the RFC 8201 §4 IPv6 floor gained teeth.

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
