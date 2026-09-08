# bolt8 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-08** — The module is measured under ctgrind now, instead of inheriting a
  verdict. `src/ctgrind_harness.zig` is committed and `scripts/ctgrind.sh` drives it; until
  today `bolt8` was outside that table and its ledger read "PASS (inherited)" — derived from
  reading, never instrumented — while the module holds the node's long-term static private
  key, the ephemeral keys, `temp_k*` and both transport keys (audit F10). Four targets, all
  `ReleaseFast`: `dh` 1 in-file context, `keygen` 3, `act3` 6, `transport` 3, with the
  untainted control and the no-`-fvalgrind` trap at 0 for every one. No secret-dependent
  branch was found: every non-zero is an invalid-key rejection, std's tag-check branch on a
  public answer, or the taint model reaching a value that is legitimately public — itemised
  one by one in `SPEC.md`. Teeth: a secret-dependent early return in `dh()` moves `dh` to 2
  and `act3` to 7 and fails the gate. `act1` deliberately has no row, because Act One never
  touches the static key and its zero would say nothing.

- **2026-09-07** — **NO CONSUMER-VISIBLE CHANGE:** this module is out of
  `zig build check-testonly` again, and its fuzz corpus uses a nine-line local
  copy of `testkit.fuzz`'s seed helper rather than the shared one. Enrolling it
  via `test_deps` puts it in that gate, whose probe imports the *published*
  module and references every declaration three levels deep — and this module
  deliberately guards a test-only function with a `@compileError` that fires
  outside a test build, so the probe touches a decl that exists to refuse being
  touched. The two gates contradict each other for any module shaped this way.
  ⛔ A local copy is the thing `testkit.fuzz` was created to abolish (33 of them
  across 12 modules). What stops this one drifting is its anchor test, which
  drives the real `std.testing.Smith` over what the helper produces — the same
  shape as testkit's own tests, so a future Zig that changes `slice`'s framing
  fails here loudly instead of leaving the corpus quietly seeding nothing.

- **2026-09-07** — The three `act.zig` fuzz targets had never parsed an act. Each drew
  `smith.bytes(&buf)` and then a ranged length, which returns the range minimum when
  fewer than eight input octets remain — so the length was 0 on every input, and with no
  corpus the lane ran exactly one round each: `Act1/2/3.fromBytes("")`, `error.ShortRead`
  before a field is read. The draw is now one `smith.slice(&buf)`, each target carries a
  corpus built from the Appendix A vectors in `kat_vectors.zig` (the published act, the
  bad-MAC/bad-ciphertext/bad-rs vectors, the bad-version and short-read vectors, a full
  act with trailing octets, an all-zero act, and the empty seed), and the harness now
  asserts the fixed-layout round-trip `fromBytes(x).toBytes() == x[0..act_len]` that it
  previously discarded. Measured: 7/7, 7/7 and 8/8 non-empty seeds reach the parser
  where 0 did; 5, 5 and 6 accepted, carrying 3, 3 and 4 **distinct** `e_pub`/`c` values —
  the second number is pinned because an accepted count cannot tell a corpus that
  collapsed to one frame from one that did not.

- **2026-08-21** — `noise`'s cipher calls gained `error.BufferTooSmall`; this module maps
  it to the `BufferWrongSize` it already publishes, so its own error sets are unchanged. It
  validates every buffer length itself before calling, so the mapped error is not reachable
  through this API — the mapping exists so that stays true by construction rather than by
  an `unreachable`.

- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Verified: `kat_test.zig`
  verifies BOLT#8 Appendix A byte-exact (act1→act2→ act3, five crypto-level negative
  vectors, transport round-trip).
- **2026-07-12** — New module: Lightning BOLT#8 encrypted transport
  (`Noise_XK_secp256k1_ChaChaPoly_SHA256`).
