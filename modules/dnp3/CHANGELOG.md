# dnp3 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-02** — **Audit (drift campaign): 1 CRITICAL, 2 HIGH, 2 MEDIUM, 1 LOW fixed.** All in
  the read/command path, and none of them needed a malformed request.
  **CRITICAL — a legal request drove a response series that never ended.** `emitRun` returned a
  bare count, and a zero meant either "no room in this fragment" (retry; the cursor must not move)
  or "this point cannot be encoded in the requested variation" (step over it; the cursor must
  move). `emitStatics` assumed the first, so a `READ g20v2` against a counter above `0xFFFF` --
  or `g30v2`/`g30v4` against an analog outside `i16`, or a class-0 poll of any point whose
  declared variation is narrower than its value -- left `item_pos` unchanged and emitted identical
  empty non-FIN fragments for ever (measured: 50 000 frames, 1.1 MB, still going, from one 20-byte
  link frame). `emitRun` now reports WHY it stopped; the caller steps over an unencodable point and
  sets `parameter_error` so the master learns the response is not everything it asked for.
  **HIGH — the value's shape came from the point's configured variation, the layout from the
  master's requested one.** Nothing bound the two together, so a float-configured analog read as
  `g30v1` reached `records.encode`'s `.i32` arm holding `.analog_float`: a panic in Debug, and in
  ReleaseFast the f64's low four bytes reinterpreted -- a reading of `12.3` arriving at the master
  as `-1717986918`. The encoder now converts between the analog shapes (`Value.analogAsInt`,
  refusing NaN/inf/out-of-range) and `analogValue` no longer guesses a shape at all.
  **HIGH — a NaN setpoint defeated the analog-output limits.** `value < min or value > max` is
  false for a NaN, so a `g41v3` carrying `00 00 C0 7F` returned `.success`, was stored, and was
  handed to the caller's hook and its actuator past a declared `[-100, 100]`. Phrased as the
  positive property now.
  **MEDIUM — the shape picker hard-coded group 30's float variation numbers** (5, 6) and was
  applied to g40 (3, 4) and g32/g42 (5..8) as well, so a g40v3 point was rounded to an integer
  before the encoder saw it: `3.25` arrived as `3`. Gone with the guess.
  **MEDIUM — the fuzz harness could not report any of this.** `checkDrawnFragment` drained with an
  unbounded `while (station.cursor != null)`: fed the wedging fragment it HUNG rather than failed
  (`timeout 60` → exit 124). It is bounded now, and exceeding the bound is an error rather than a
  `break`. Two further blind spots closed with it: the hostile-object pool named only variations
  wide enough to carry any value (`{20,2}`, `{30,2}`, `{30,4}`, `{30,5}` added), and the fixture
  held no value that a narrow variation refuses -- an input that asks for the class is not enough
  if no STATE makes it happen.
  **LOW — `parseReadHeader`'s empty-database guard had no test behind it.** Disabling
  `if (n == 0) return error.UnknownObject` left the whole suite green, while a `READ g21` against
  a database with no frozen counters computes `stop = n - 1` on an unsigned zero: `integer
  overflow` in Debug, a ~2^32-point walk in ReleaseFast. Pinned.
  Every fix carries a regression test that goes red when the fix is reverted; `Value.asInt`'s
  unguarded `@intFromFloat` (a public entry point reachable from decoded wire bytes) saturates
  instead of being undefined. Ledger: `~/CML/20260931-zig-libs-audit/dnp3.md`.

- **2026-08-18** — Portability fix (`check-portable`), and a latent 32-bit correctness
  bug it uncovered: `Cursor.item_pos` and the class-0 static-scan's `scan_stride`
  constant (`1 << 32`) were typed `usize`. The `1 << 32` literal doesn't fit `usize` on a
  32-bit target, so this was first a compile error there — but retyping only the literal
  would have left a real defect: the class-0 scan packs `kind_index * scan_stride +
  point_index` into `item_pos`, and DNP3 object headers carry a full 32-bit range
  qualifier, so a point index can itself approach `2^32`. On a 32-bit host a `usize`
  `item_pos` would silently overflow as soon as the resumable scan crossed from the
  first `PointKind` into the second, not merely fail to compile. Retyped `item_pos`
  (the `Cursor` field and `emitStatics`'s parameter) and `scan_stride` to fixed-width
  `u64`, narrowing back to `usize` only at the one point that indexes the (seven-entry)
  `kinds` array. Compile-only on every target that already built (64-bit); on a 32-bit
  target this also fixes a real overflow, though no 32-bit CI lane exercises it yet, so
  no new behavioural test was added — the fix is verified by inspection plus the
  existing native suite. Verified: `zig build portable-dnp3` and
  `zig build test-dnp3 --summary all` (142/142) both green. `fleetsim` shares this exact
  defect (it reaches this same `outstation.zig:1160`) and its portable gate is fixed
  transitively by this change — no `fleetsim` source changed, so no entry there.
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
