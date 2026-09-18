# bolt8 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-11** — **API CHANGE:** `Initiator.State`/`Responder.State` gain
  a new member, `.failed` (audit finding F5). Every act function
  (`act1`/`readAct2`/`genAct3` on `Initiator`, `readAct1`/`act2`/`readAct3`
  on `Responder`) now `errdefer`s `self.state = .failed` after its own
  state-guard check, so a failed act kills the object instead of leaving
  `state` wherever it was mid-act: before this, a rejected message left
  the object looking untouched (still `.awaiting_act2`/`.awaiting_act3`),
  re-enterable over a `SymmetricState` that had already partially
  advanced (the transcript hash had moved, the cipher key may have been
  re-seeded), and a retry of the SAME bad message, or the genuine one
  that would have worked, ran against that half-mutated state instead of
  being rejected outright. Every act already checks its own expected
  state first, and `.failed` matches none of them, so this needs no new
  error variant — the existing `error.WrongState` now covers it. Also:
  `Responder.readAct3` sets `rs_pub` (the peer's static key, recovered
  from a validated point) BEFORE its own final integrity check (the tag
  over the whole transcript) can still fail — an `errdefer self.rs_pub =
  null` added right after the assignment clears it back out on that
  failure, since until the final check passes the peer has not actually
  authenticated as that key. `QUESTIONS-ROUND-2.md` Q3: this module has
  zero consumers in this repository, and this specific instance of the
  question (a plain enum, not an error set) is the one the coordinator's
  own worked example in the fixer brief cites. Measured: two new tests
  (RFC vectors, existing `act2_bad_mac`/`act3_bad_tag`) drive a real
  handshake failure on each side and check both `state == .failed` and
  (on the responder) `rs_pub == null` afterward, plus that neither a
  retry of the failed message nor the genuine one that would have
  succeeded is accepted; removing either new `errdefer` turns the
  matching test `RED` (confirmed for both).

- **2026-09-10** — **BEHAVIOURAL, not breaking, plus one BREAKING and one additive
  field:** A1 fix campaign, 11 of 12 open findings (F1-F4, F6-F9, F11-F13; F5 needs a
  user decision, left open). **BREAKING:** `Act1`/`Act2`/`Act3.fromBytes` now reject a
  buffer whose length is not EXACTLY the act length (was `<`, now `!=`) — F9, zero
  in-repo consumers, `DECISIONS.md` P1. **Additive:** `HandshakeResult` gained
  `remote_static: [33]u8` (the peer's static public key — F7) and
  `Initiator`/`Responder`/`Transport`/`dh.KeyPair` gained `deinit()` (zeroes the key
  material each object directly owns, not dead-stack copies inside the act functions —
  F2). `handshake_hash` is now anchored against an independently-computed value instead
  of only comparing the two sides of one handshake against each other (F1). Two fuzz
  harnesses added for `Transport.recvLength`/`recvMessage` (F3, the act-framing half of
  this finding was already fixed pre-campaign in `4063b8db`). Doc-only: `Transport`
  desync warning (F6), unauthenticated-work deadline note (F8), backfilled the missing
  2026-08-12 changelog entry (F11), fixed a README snippet that failed to compile
  (F12), documented why `NonceExhausted` cannot occur today (F13), added the one
  missing BOLT#8 named test vector (F4). See `~/CML/20260901-zig-libs-audit/A1/bolt8.md`
  for the full disposition and RED/GREEN measurements.

- **2026-09-09** — Licensing: `NOTICE` kind changed from `provenance note` (record only) to
  `third-party attribution` (carries a CONDITION). `src/kat_vectors.zig` embeds BOLT#8's Appendix A transport test vectors verbatim from `lightning/bolts`,
  which is CC-BY 4.0, so attribution is owed and was not being given. ⛔⛔ The repository was
  distributing two opposite answers about one upstream: `lnwire`, `lninvoice` and `k256`
  record `lightning/bolts` as CC-BY 4.0 and attribute it, while this file said BOLT text is
  "not a copyrightable work (merger doctrine)" and needs no entry. Re-verified 2026-09-09
  against commit `152897261850d93c4f4597f39cf22d7d22d6ede6`: all 40 hex literals of 32+ characters that this module vendors appear verbatim in today's `08-transport.md`. The pin is now that
  commit rather than "`master` branch", which is not a pin. CC-BY's
  indicate-modifications condition is discharged (none — the values are the published ones,
  hex-decoded). No code or data changed.

  ⭐ Changing the kind pulled this file under `zig build check-copyleft` for the first time,
  so the existing "No GPL/LGPL/AGPL source was consulted" sentence had to become a declared
  `**Copyleft:**` line.
- **2026-09-08** — The module is measured under ctgrind now, instead of inheriting a
  verdict. `src/ctgrind_harness.zig` is committed and `scripts/checks/ctgrind.sh` drives it; until
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

- **2026-08-12** — **BREAKING (backfilled 2026-09-10, audit finding F11):** B6 RNG-seam
  fix, commit `c36f2cac` — never recorded here even though the changelog file itself was
  created three commits later the same evening (`da6c475c`) and simply omitted it.
  `Initiator`/`Responder`'s public `e` field is GONE; `genAct1(std.Random)` /
  `genAct2(std.Random)` became `genAct1(Ephemeral)` / `genAct2(Ephemeral)` (a tagged union
  naming `.csprng` vs. `.seeded_for_test` at the call site — see `Ephemeral`'s own doc
  comment). Before this, `self.e orelse dh.KeyPair.generate(random)` meant a consumer who
  assigned `.e` got a CONSTANT ephemeral public key on every Act One (cross-session
  linkability, and a constant `es`), with the `random` argument silently going dead — nobody
  had to select the weak path, it was reachable by assignment. Also added: a linear
  `state: State` machine (`error.WrongState` on any act run out of order or twice), closing
  the sibling bug where a retry could reuse the previous ephemeral share.
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
