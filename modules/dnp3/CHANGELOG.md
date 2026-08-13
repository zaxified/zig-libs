# dnp3 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-12** — **BEHAVIOURAL, not breaking** — the outstation's select-before-operate
  interlock is now bound to the peer that issued the SELECT, and `Session.feedFrame`
  filters the data-link **source** by default. Previously the arming bound sequence number,
  byte-identical objects and a timeout but carried no peer identity, so on a link where
  more than one station can transmit, station A could SELECT and station B could OPERATE
  and the physical output actuated. New `Outstation.handleFrom(request, peer, now_ms, out)`
  carries the peer; `Outstation.handle` remains as a wrapper passing `null`, and `null`
  matches only `null`, so a point-to-point caller keeps its previous behaviour exactly.
  `Config.require_master_source` (default `true`) can turn the source filter off — the same
  escape hatch both reference stacks ship — while the peer-bound SELECT has no opt-out,
  since one would be an opt-in to "A arms, B fires". (Re-audit F6(b).)
- **2026-08-11** — Security re-audit of the outstation: three HIGH and one MED fixed. Two
  reproduced **remote panics** on the control path, both reachable from a single
  unauthenticated ~15-byte fragment: `doCommand` computed the object-instance count in
  `u32`, and the prefix-less point index was `@intCast` into a `u16`. Both now compute in
  `u64` and answer with the protocol's own `PARAMETER_ERROR` — widening the types alone was
  rejected deliberately, as it would have traded a panic for a 2³²-iteration loop, and
  truncating the index would have actuated the wrong output point. `Session.feedFrame` never
  filtered the data-link **destination**, so a frame addressed to a different outstation was
  executed here, output actuation included; frames for another station are now dropped
  before reassembly, while a broadcast (`0xFFFD`–`0xFFFF`) is executed and never answered,
  its reply state cleared so `nextFrames` cannot leak it. And the fuzz harness could not
  reach the shapes the two panics lived in — 20 000 uniform-random draws never found either
  — so it was replaced with a structured generator over each field's boundary values, whose
  loops assert they actually produced those shapes.
- **2026-08-03** — New `Range.objectSpanBytes(bytes_per_object)`. Both factors of an object
  block's size come off the wire, and `start = 0, stop = 0xFFFFFFFF` is a legal encoding for
  2³² objects, so the natural consumer loop `rest = rest[count * each ..]` overflows `u32`
  and slices past the end — no allocator involved. `objectSpanBytes` computes the span in
  `u64` so a caller can reject such a header with one comparison against the bytes it
  actually has. This is the remaining half of the audit finding about decoded counts; the
  count itself is deliberately **not** capped, because a decoder's job is to return what
  arrived on the wire and large ranges are legal.
- **2026-07-20** — Security audit, two lower-severity items. `wrapSessionKeys` built both
  DNP3-SA session keys in cleartext in a stack scratch buffer and never wiped it; the
  scratch is now `secureZero`'d on every exit, and `unwrapSessionKeys` — which returns
  slices into the caller's own buffer and so cannot wipe what it hands back — documents that
  the caller must `secureZero` that buffer once the keys are installed. Separately, the
  link-layer frame decoder, the module's primary untrusted-wire surface, gained a
  `std.testing.fuzz` harness.
- **2026-07-19** — Security audit. `Range.objectCount()` computed `stop - start + 1` in
  `u32` on values read straight off the wire, so an object header with `start = 0,
  stop = 0xFFFFFFFF` panicked in Debug/ReleaseSafe and wrapped silently to zero in
  ReleaseFast — reachable through a public helper a consumer naturally calls to size the
  loop after a header. The arithmetic is widened, and with it the signature: `objectCount`
  returns **`?u64`** where it used to return `?u32`. A second finding — whether the
  DNP3-SA reply-MAC transcript binds everything an attacker could vary — was adjudicated
  **SOUND** with no logic change, since modern opendnp3 dropped Secure Authentication and no
  external vector exists to diff against; the field-by-field verdict and the load-bearing
  contract (the verifier must never derive the challenge message's length from wire bytes)
  are recorded as a doc-anchor with a regression test pinning the boundary property.
