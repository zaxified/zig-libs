# testkit

The harness pieces every module's tests were re-deriving. **Test-only**: it is
wired into each consumer's test binary through `build.zig`'s `test_deps`, never
into the module a downstream user imports — `@import("frost")` does not drag a
test harness along with it.

- **Status:** complete. **Platform:** any.
- **Deps:** none (std only).
- **Model after:** `std.testing`, extended with the helpers this repo's own
  tests kept re-deriving.

## What is here, and why only this

Everything in this module was **measurably** duplicated first. It is not a
place to put things a test might one day want.

| Piece | Was duplicated |
|---|---|
| `verboseSkip` / `skip` | 42 byte-identical copies across 26 modules |
| `hex.bytes` | 18 byte-identical copies across 8 modules |
| `expectHex` / `expectBytes` | every `goldens.zig` spelled it differently |

The golden comparison is the one piece that is *better* than what it replaced,
not merely shared — see below.

Deliberately **not** here: netns setup and privileged-capability probing. Those
read genuinely differently per module (`tc` wants a fresh netns with `lo` at
ifindex 1; `ebpf` wants `CAP_BPF` in the *initial* user namespace, where
`unshare -r` actively lies to you), and a shared abstraction would hide exactly
the distinctions that make those skips correct. The VOPR side is already a
module: [`netsim`](../netsim).

## Use

```zig
const testkit = @import("testkit");

// Skips. Returns the error, so `return` cannot fall through to the
// assertions it was meant to skip.
if (!haveCapability()) return testkit.skip("needs CAP_BPF (uid {d})", .{uid});

// Hex, in the three shapes the repo uses.
const key = comptime testkit.hex.bytes(32, "000102...");   // KAT vectors
const got = try testkit.hex.into(&buf, wire_hex);           // caller buffer
const owned = try testkit.hex.alloc(gpa, wire_hex);         // allocated

// Goldens.
try testkit.expectHex("45000054...", frame);
try testkit.expectBytes(expected, actual);
```

## The golden diff

`std.testing.expectEqualSlices` prints both slices in full. For the goldens
this repo actually has — a 200-byte netlink datagram from `iproute2`, a GOOSE
frame, a DER certificate — that is two walls of hex and you still have to find
the difference by eye. `expectBytes` names the first differing **offset** and
shows a window around it with the offending byte bracketed:

```
golden differs at offset 44 (0x2c): expected 0x08, got 0x0c
  offset 36..
  expected:  00  00  01  00  00  00  00  00 [08] 00  01  00 ...
  actual:    00  00  01  00  00  00  00  00 [0c] 00  01  00 ...
```

A golden failure is nearly always "one field moved", and the offset names the
field. A **length** mismatch is reported separately and first: a truncated
encode is a different bug from a wrong byte, and conflating them costs a
debugging cycle.

The comparison (`diff`) and the formatting (`render`) are pure functions and
are what the tests exercise. That is not tidiness — a test asserting "this
comparison fails" would otherwise print its own diagnostic on every green run,
and this repo treats any stderr from the suite as a real problem.

## ⚠ The one thing not verified here

`verbose_skip_env`'s **value** — the string `"ZIG_LIBS_VERBOSE_SKIP"` — is not
pinned by any test, and cannot be: a test reading the same literal it checks is
circular, and a test binary cannot set a variable for itself. A typo would
silently mean "never verbose" forever. The decision *logic* is tested
(`verboseEnabled`); the name is held only by `scripts/test.sh` and the docs
using the same spelling. Grep before renaming.

## Verify

```
zig build test-testkit                          # Debug       — 21 pass
zig build test-testkit -Doptimize=ReleaseFast   # ReleaseFast — 21 pass
zig build check-testonly                        # the isolation claim
```

`check-testonly` is the one worth knowing about. `test_deps` claims the
published module never needs the harness, and **nothing checked that**: Zig
analyses container-level decls lazily, so an unused `@import("testkit")` in a
module's non-test code is simply never looked at. Verified by planting
`pub const leaked_probe = testkit.verbose_skip_env;` in `netlink` — every
dependent still built green. The step forces the analysis with a
consumer-shaped probe, and the planted leak then fails it while
`zig build test-netlink` stays green.

Forcing that analysis also compiles public code nothing had ever referenced,
which immediately found two dead-but-broken declarations: `enip`'s
`UdpDiscovery.send` constructed an `Ip6Address` with fields Zig 0.16 does not
have, and `ethtool`'s `max_error_message` took `.len` of a *type*.

Provenance: original work of the zig-libs authors (MIT); a thin layer over
`std.testing`. No third-party source consulted or copied, so no `NOTICE` entry
is required (root [`NOTICE`](../../NOTICE) §0).

## Anchoring

**Anchor grade:** class C · oracle n/a

- **Class C** — internal algorithm or data structure — no outside exists, so correctness is defined by invariants or a brute-force reference. Not anchor debt.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** in-process test-utility layer over std.testing, no wire/crypto
