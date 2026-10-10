# megolm — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — tests: deterministic fuzz driver `MEGOLM_FUZZ` (`src/fuzz_test.zig`): `megolm-message` (a genuine message is decrypted exactly; one flipped bit anywhere, a damaged copy and damaged base64 are refused, accepted only if byte-identical), `megolm-session-key` (share/export formats; one flipped bit of a signed share is refused) and `megolm-pickle` (plain and sealed pickles; every flipped bit, truncation and wrong key of a sealed pickle is refused). 200,000-run verdicts, ReleaseSafe, clean.
- **2026-10-10** — Constant time: `SessionKey`/`ExportedSessionKey` `toBase64`/`fromBase64` ran the secret ratchet through `std.base64`, which indexes a table by every secret sextet (encode) and character (decode) and branches on validity. A new private `src/b64ct.zig` does branch- and table-free unpadded standard base64 with std's exact accept set and errors (cross-checked against std over every byte value and every character in every tail position); validity is branched on once, at the end. Message encoding (public ciphertext) still uses std. New `src/ctgrind_harness.zig` (targets `msg`, `skey`, `pickle`, ReleaseFast): `skey` went from 40 to 26 in-file; what remains in all three is std Ed25519 internals, verdicts and processing of decrypted or public-length data, itemised in `scripts/checks/ctgrind-expected.tsv`. No API change.
- **2026-10-09** — **BREAKING:** dead-stack pass (`check-secret-api`). `pickle.decodeOutbound` and `pickle.openOutbound` no longer return the `OutboundSession` (it sat in the caller's result slot); they write it through a new trailing `out: *OutboundSession` parameter, only on success. `cipher.fullMac`, `verifyTruncatedMac` and `pickle.encodeOutbound`/`decodeOutbound`/`openOutbound` now run under a burn (`burn.mac_burn` 4 KiB, `session_burn`, `decrypt_burn`). `OutboundSession.fromPickle`/`fromSealedPickle` follow. `sessionId` carries a `secret-api-ok` marker (public key only). New `src/stackprobe2_test.zig` on `testkit.stackprobe` probes those five entry points (ReleaseFast).

- **2026-10-09** — **BREAKING + FIX (secrets on the dead stack, second wave):** the remaining by-value secrets (before: `deriveKeys` left AES key, HMAC key, IV and round-key
  residue, `Ratchet.generate` R0 and `SessionKey.decode` / `fromBase64` R left residue, 0
  after): `cipher.deriveKeys(&ratchet, &out)` (was `deriveKeys(&ratchet) Keys`),
  `Ratchet.init(&data, counter, &out)` (was `init(data, counter) Ratchet`),
  `Ratchet.generate(io, &out)` (was `generate(io) Ratchet`),
  `SessionKey.encode(&out_229)` / `ExportedSessionKey.encode(&out_165)` (were `[N]u8`
  returns), `SessionKey.decode(bytes, &out)` / `ExportedSessionKey.decode(bytes, &out)` and
  `fromBase64(allocator, s, &out)` on both (were struct returns; error set unchanged, new
  `session_key.FromBase64Error`). `toBase64` keeps its signature but wipes its raw buffer;
  `fromBase64` wipes its heap scratch. `decodeSignedPartUnchecked` is private and now fills
  `out`. Migrated: tests (by-value adapters in `src/test_shim.zig`), example, README.

- **2026-10-09** — **Breaking:** dead-stack burn for the session entry points
  (`stackprobe_test.zig`: 11 of 16 probed calls left ratchet / signing-key / AES key /
  round-key residue before; 0 after). Secret results go through `out` instead of a return
  value: `OutboundSession.init(io, &out)`, `sessionKey(&out)`,
  `InboundGroupSession.fromSessionKey(&key, &out)`, `fromExportedKey(&key, &out)`,
  `exportAt(index, &out) bool` (was `?ExportedSessionKey`), `fromPickle(bytes, &out)` and
  `fromSealedPickle(bytes, &key, &out)` on both session types. `encrypt`, `decrypt`,
  `forgetBefore`, `Ratchet.advanceStep` / `advanceTo` keep their signatures and burn. Migrated:
  tests (via `src/test_shim.zig`), example, README. No other consumer in the tree.

- **2026-10-06** — **NO CONSUMER-VISIBLE CHANGE:** `pickle.zig` documents that restoring an
  old outbound pickle rewinds the ratchet and reuses message indices (review of PR #4).

- **2026-10-06** — ADDED: session pickling (`pickle.zig`). `OutboundSession.pickle` /
  `pickleSealed` / `fromPickle` / `fromSealedPickle` and the same four on `InboundGroupSession`
  save and restore every field of a session (ratchet and index, the outbound Ed25519 key pair,
  the inbound first-known ratchet, fast-forward cache, signing key and `signing_key_verified`
  flag) in a versioned fixed-width layout, optionally sealed with ChaCha20-Poly1305 under a
  caller-supplied 32-byte `PickleKey`. Before this an outbound session could not be saved, and
  restoring an inbound one via `exportAt`/`fromExportedKey` lost the verified flag. Decoding is
  strict and fail-closed (`PickleError`: length, magic, version, kind, tag, flags, key validity,
  cache consistency). New sibling dependency: `chachapoly`. Fuzzed (`fuzzPickleDecode`).
  Scope mvp -> core.
- **2026-10-06** — **NO CONSUMER-VISIBLE CHANGE:** SPEC consistency: the mutation note no longer calls the module "untracked" in the present tense.
- **2026-09-08** — Test-only, no production change: `fuzzMessageDecode`'s payload generator
  emitted exactly **one** field on every seed, and the field it emitted was always the same one.
  Measured 2026-09-08 over the whole corpus: `fields = 1`, `tag_kinds = {1, 0, 0, 0}`,
  `wide_length = 0` — the `0x12` **ciphertext** branch, both arbitrary-tag branches and the
  wide-claimed-length knob had never executed. The cause is that the loop condition is an `eos`
  draw, which consumes ONE octet where a scalar draw consumes eight, so every `u64` word in a
  word-only tail is read out of phase from the first field onward. A new `TailWriter` writes the
  tail at the widths each draw actually reads (word / octet / `u32`-prefixed slice) and two
  seeds now drive the generator: one that builds a **complete, decodable** message (version,
  index, an 8-octet ciphertext field, the 72-octet suffix — it round-trips byte-identically
  through the harness's own oracle), one that walks the refusal shapes. After:
  `fields = 7`, `tag_kinds = {3, 2, 1, 1}`, `wide_length = 1`, decoded 3 → 4.
  The harness body moved into `messageRound`, which the guard now drives directly, so the guard
  measures the knobs inside the harness instead of a hand-copied replay of its draw order.
  `session_key`'s five knobs measured ALIVE and varying (length modes 3/4/2/1, version modes
  5/4/1, base64 corruption 1 of 10); its guard's `expect(seen)` booleans are replaced by the
  measured histograms, and it now replays the three base64 knobs it used to stop short of.

- **2026-09-07** — Test-only, no production change: both fuzz targets carried a
  "reachability was verified rather than assumed" note, and both notes were measured under
  `scripts/fuzz-sweep.sh` - i.e. under `--fuzz`. The ORDINARY lane replays
  `options.corpus` plus one empty input, and neither target had a corpus, so with the input
  exhausted every draw returned its range minimum. In `message.fuzzMessageDecode` the first
  draw was `smith.boolWeighted(1, 7)`, so the unstructured arm - which is where
  `smith.slice(&buf)` lived - had **never run outside `--fuzz`**: no octet of any input ever
  reached `decode`, and the structured arm built one deterministic frame. In
  `session_key.fuzzSessionKeyDecode` the first draw was
  `smith.value(enum { exact_export, exact_share, near, any })`, so `len` was always
  `export_len` and the `smith.slice` after it read an already-exhausted input; the whole
  length sweep its comment describes - `share_len`, the off-by-ones, the arbitrary lengths -
  had never happened. Both now draw bytes FIRST and unconditionally, and both branch knobs
  are `smith.value(u64)` reduced here rather than bounded draws (`check-fuzz-reach`'s own
  option 2), so a corpus replay drives them. Corpora built from `dummyMessage`,
  `nonMinimalIndexEncoding` and a real signed `SessionKey`. Measured by the two new
  `corpus:` guards - messages: **6 unstructured-arm runs** (0 before), 3 frames decoded, 48
  ciphertext octets, each re-encoding byte-identically (the W2-33 oracle, now over a
  deliberately non-canonical frame); session keys: **all four length modes exercised**,
  1953 -> 2041 octets of length swept, 2 exports and 1 share accepted (0 before - the
  all-zero `signing_key` the collapsed harness always produced is not a canonical Ed25519
  point).

- **2026-09-06** — **`NOTICE` corrected: this module carries an Apache-2.0 condition.**
  It was headed `provenance note` and called the implementation "clean-room ...
  no libolm C or vodozemac Rust source was copied, ported, or transliterated",
  while `src/ratchet.zig:17-18` said "this module is a direct, byte-for-byte port
  of theirs" about the same code. The source comment is the accurate one. The
  file is now a `third-party attribution`, reproduces the Apache License 2.0 in
  full (§4(a)), retains OpenMarket Ltd's and The Matrix.org Foundation's
  copyright notices (§4(c)), and states what was changed in the port (§4(b));
  `src/ratchet.zig` carries the same modification notice in its header. Neither
  upstream ships a NOTICE file, checked the same day, so §4(d) adds nothing.
  Root `NOTICE` §1 lists this module, 24 entries to 25. **No code changed** —
  the condition was always there, it was written down wrongly.

- **2026-08-13** — Test-only, neither BREAKING nor BEHAVIOURAL: `session.zig` gained a
  seam test proving `OutboundSession.init`'s two `entropy.fill` draws (the
  ratchet R₀ and the Ed25519 signing key) are both actually read (two
  sessions from the same `io` must differ in both secrets) and that the
  production encrypt/decrypt path still round-trips end to end. Before
  this, either draw could be replaced by a constant and the suite stayed
  green — confirmed by mutating both draws simultaneously (`@memset(...,
  0x42)`) and watching the new test fail (46 pass, 1 fail on the ratchet
  assertion), then isolating the signing-key draw alone to confirm the
  second assertion independently catches it too, then reverting to green
  (47/47). Does not distinguish real entropy from a varying-but-weak PRNG;
  see the test's own comment.
- **2026-08-13** — `OutboundSession.init`'s Ed25519 signing keypair now draws its seed from
  `entropy.fill` (`std.Io.randomSecure`) instead of `io.random`, matching
  what `Ratchet.generate` already did for R₀. **Not breaking:** no
  signature changed and no new dep (`entropy` was already one).

  The ratchet half of a session was fail-closed and the signing half was
  not, which is the wrong place to draw that line: this key signs every
  session-sharing blob and every message frame, so a weak draw lets an
  attacker forge into the group no matter how good R₀ was. The generator
  is std's `Ed25519.KeyPair.generate` verbatim — retry loop included —
  with one substitution in where its 32 seed bytes come from.

- **2026-08-12** — `Ratchet.generate` draws R₀ through the new `entropy` module
  (`entropy.fill`, i.e. `std.Io.randomSecure`) instead of `io.random`. Not
  breaking: `fill` returns `void`, so no signature changed and `generate`
  still returns a plain `Ratchet`. `std.Io.random` is a CSPRNG whose
  contract permits a silent fallback to a weaker seed (`std/Io.zig:2462`)
  and the default `Io.Threaded` takes it, seeding from pid + wall clock +
  an ASLR pointer. Those 128 bytes *are* the session key — every message
  key the group will ever use is a hash of them and they are shared out
  verbatim in the session-sharing format — so the draw now aborts rather
  than mint a group history from a degraded seed. The old doc comment
  justified `io.random` by pointing at `signal` and `std`'s Ed25519
  keygen; that comparison is gone with it.
- **2026-08-06** — Security audit: four findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on
  `matrix-org/olm` (libolm) + `vodozemac` (design reference, not a test anchor).
- **2026-07-29** — New module: Matrix's Megolm group ratchet, the third real-world
  group-messaging construction here alongside `signal` (pairwise Double
  Ratchet) and `mls` (RFC 9420). A one-way four-part HMAC-SHA-256 hash
  ratchet that fast-forwards to any future index but never rewinds, plus
  Ed25519 signatures over the message frame; `OutboundSession` /
  `InboundGroupSession` and the exact session-sharing, session-export and
  message wire formats. The cipher is not a choice: the spec mandates
  AES-256-CBC/PKCS#7 + HMAC-SHA-256 truncated to 8 bytes, taken from the
  sibling `aescbc`. `decrypt` separates four failure causes into distinct
  typed errors (`InvalidSignature`, `MessageIndexTooOld`, `InvalidMac`,
  `InvalidPadding`) and verifies signature → MAC → padding in that order,
  so the padding check is unreachable without a valid MAC. Byte-exact
  against libolm's own `test_megolm.cpp` ratchet vectors — including the
  2^24/2^16/2^8 boundary crossings and the 32-bit counter wraparound —
  and a real libolm-produced session-key + message pair from
  `test_group_session.cpp`, independently re-derived end to end with a
  separate Python toolchain (PyNaCl + `cryptography` + stdlib `hmac`) as
  a non-libolm cross-check. The ratchet advance is a cascade, not a
  per-part rehash: crossing a boundary rehashes the crossed part and
  everything to its right **from the same pre-update value** —
  implementing it as an independent per-part rehash still round-trips,
  and is caught only by a boundary-crossing vector. Olm, the Matrix
  event-JSON layer and key backup are out of scope.
