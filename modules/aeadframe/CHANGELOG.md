# aeadframe — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-26** — **NO CONSUMER-VISIBLE CHANGE:** dead-stack coverage sweep, wave 3: a `testkit.stackprobe` probe of the public secret entry points no probe called — `Opener.rekeyOverlap` / `rekeyOverlapInto`, both channels (appended to `src/stackprobe_test.zig`). Clean. Test only.
- **2026-11-23** — **NO API CHANGE:** `Channel.Opener.bumpEpochOverlap` runs under `frame_burn` like `rekeyOverlap`: both copy the current key into the retained-epoch literal, which the compiler may build on the stack.
- **2026-11-17** — opt-in multi-epoch opener: `Opener.rekeyOverlap`/`rekeyOverlapInto`, `bumpEpochOverlap`, `dropPrevious`, `previousEpoch`, `OverlapError` (`EpochNotDistinct`) and an `Opener.prev` field retain the epoch being left (key and replay window) so in-flight records still open, per RFC 9147 §4.2.1/§4.5.1 (a window per epoch, retention bounded by the caller). Plain `rekey`/`bumpEpoch` are unchanged except that they also drop (and wipe) a retained epoch; `Opener.wipe` wipes it too. Default behaviour unchanged: without an overlap call an old-epoch record is `EpochMismatch`. `Opener` grows by the retained key, epoch and window.
- **2026-11-17** — opt-in length padding: `Sealer.sealPadded` (version-2 record, body `plaintext ‖ zeros ‖ pad(u16)` inside the AEAD), `Sealer.sealedLenPadded`, `record.padForBlock`, `record.parseWith`, `Header.encodePadded`, `Parsed.padded`, `Opener.allow_padding` (default false) and `error.InvalidPadding` in `OpenError` (an exhaustive `switch` over `OpenError` in caller code needs a new arm). `seal`, version-1 records and the default opener are unchanged: a version-2 record is `UnsupportedVersion` unless `allow_padding` is set. Tests: round trip for both AEADs, bytes pinned against an independent AEAD call, version tamper both ways, replay, bad trailers consumed and wiped, maximum pad, block rounding.
- **2026-10-18** — Ported to Zig 0.17.0. No source change beyond the repo-wide codemod (all `@bitCast` sites audited; aesgcm's are x86-64-only, so LE memory order is unchanged).
- **2026-10-10** — tests: deterministic fuzz driver `AEADFRAME_FUZZ` (`src/fuzz_test.zig`): `aeadframe-channel` (both AEADs, Sealer to Opener with records delivered in a drawn order with duplicates against an independent replay-window model; before each delivery a flipped bit, a truncation, other AAD, an undersized buffer and a damaged copy are refused and change nothing; an epoch bump refuses the old epoch; the top of the sequence space is exhausted, never wrapped) and `aeadframe-record` (`record.parse`). ReleaseSafe, clean.
- **2026-10-10** — Constant time: new `src/ctgrind_harness.zig` (targets `chacha`, `aes`, ReleaseFast): channel keys and plaintext are tainted through `Sealer.seal`, `rekeyInto` and `Opener.open`, including a tampered record. 5 in-file contexts per target: the AEAD tag-verify outcome and `rekey`'s verdict on its constant-time same-key compare. No code change.
- **2026-10-09** — Dead-stack sweep (`CONVENTIONS.md` §2.1.1). `Sealer.seal`, `Opener.open` and
  both `rekey`s now run under an 8 KiB per-message burn (`src/burn.zig`): the AEAD call copied the
  key by value into a frame nothing cleared. The by-value `init`/`initWindow`/`rekey` stay; new
  pointer twins build the half in place and take the key by pointer: `Sealer.initInto`,
  `Opener.initInto`, `Opener.initWindowInto`, `Sealer.rekeyInto`, `Opener.rekeyInto`. Additive, no
  existing signature changed. `stackprobe_test.zig` probes them for both instantiations.
- **2026-10-05** — **Fix (anti-replay):** `ReplayWindow.commit` cleared the bitmap when the
  high-water mark advanced by exactly the window size, so the previous high-water mark (then at
  the window's trailing edge, still in range) was accepted a second time — a replay. Fixed;
  `Opener.open` now refuses it. Tests: first dated mutation run (35/35 after the fix and 2 new
  tests; `SPEC.md` § "Mutation run 2026-10-05").

- **2026-09-07** — Fuzz: `Opener.open`'s harness never ran a record. It drew
  `smith.bytes(&buf)` and then a ranged length, which reads eight octets as a
  little-endian u64 and returns the range minimum when fewer remain — so the
  length was always 0 and, with no corpus, the target ran `open(&out, "", "aad")`
  and nothing else, for ever. `record.parse` refuses that as `Truncated`, so the
  harness's own assertion (`m + record.overhead <= len`) had never executed.
  Now a single `smith.slice(&buf)` draw plus an 8-seed corpus built from this
  module's own sealer (a genuine record, the empty-plaintext minimum, one that
  fills the buffer, and four one-octet perturbations reaching `UnsupportedVersion`,
  `EpochMismatch`, `Truncated` and the Poly1305 refusal). Pinned by a corpus
  guard: 7 of 8 seeds non-empty, 3 accepted, 104 plaintext octets recovered.

- **2026-08-06** — Security audit: four findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on IPsec ESP
  (RFC 4303) / DTLS 1.3 record layer (design reference, not a test anchor).
- **2026-07-24** — New module: Per-key AEAD record layer — seal/open with a monotonic
  counter nonce (never reused), epoch rekey, sliding-window anti-replay + AAD binding;
  generic over the AEAD.
