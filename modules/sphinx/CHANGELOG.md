# sphinx — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-21** — New `sphinx.blinded`: BOLT#4 route blinding — `createPath` (first `path_key`, blinded node ids, `encrypted_recipient_data`) and `unblind` (plaintext, blinded private key for `process`, next `path_key`), byte-exact against BOLT#4 `route-blinding-test.json`. Additive.
- **2026-11-17** — **NEW (BOLT#4 "Returning Errors"):** `failure.zig`, exported as `sphinx.failure`: `create` / `createPadded` (the erring node's packet, `failure_len + pad_len` padded to 256 or the caller's pad, authenticated with `um` and obfuscated with `ammag`), `forward` (a relay's obfuscation, truncating over 32768 bytes), `unwrap` (the origin peels layers until a hop's HMAC verifies and names that hop; at least 27 rounds like lnd; `PacketTooShort` under 292 bytes, `SourceUnidentified` when no hop verifies) and `parseFailure`. New `sphinx.sharedSecret(out, node_privkey, ephemeral_pubkey)`, the receiving hop's ECDH step, because a relay needs its secret for `create`/`forward` and `process` does not return it. `KeyType` gains `.ammag` (a new enum member: an exhaustive `switch` over `KeyType` must add a branch). Byte-exact against `bolt04/onion-error-test.json` and the spec's trace vector (`src/failure_vectors.zig`). Delta mutation 35/37 killed, 2 equivalent (card 68/73, 5 eq). Not implemented: `attribution_data`.

- **2026-11-16** — **NEW (replay-protection hook):** `ProcessResult` gains `replay_tag` (BOLT#4's `SHA256(ss)`, 32 bytes; a new field, so code that builds a `ProcessResult` by literal must set it). New `processWithHook(priv, pkt, ad, ReplayHook)` calls the caller's `check(ctx, &tag)` after the HMAC verified and before unwrapping; `false` returns the new `error.Replayed` (`ProcessHookError`). `process` is unchanged; the module stores no log.


- **2026-10-10** — **FIX (panic on an authenticated hostile hop frame):** `hopframe.readHopFrame` added `hmac_len` to the peer-declared bigsize length before comparing it with the bytes that remain, so a length within 32 of 2^64 overflowed (a panic in safe builds, a wild slice in ReleaseFast) and on a 32-bit target the `@intCast` to `usize` failed first. It is reachable by anyone who can build an onion for the node (the sender picks the ephemeral key, so the HMAC verifies over any frame). The length is now compared as a u64 against the remaining bytes first; regression test in `hopframe.zig`. Found by the new fuzz driver `SPHINX_FUZZ` (`src/fuzz_test.zig`): `sphinx-packet` (an accepted packet re-encodes to its input), `sphinx-route` (a route built by `construct`, peeled hop by hop; flipped bit, other associated data, other node key, damaged packet refused) and `sphinx-forged` (a packet with a VALID HMAC over an arbitrary deobfuscated frame: a result or a typed error, never a panic). ReleaseSafe, clean after the fix.
- **2026-10-09** — **BREAKING:** dead-stack rule (CONVENTIONS §2.1.1). `generateKey(out: *[32]u8, key_type, shared_secret: *const [32]u8) void` (was `generateKey(key_type, shared_secret: [32]u8) [32]u8`) and `generateCipherStream(key: *const [32]u8, out: []u8)` (was `key: [32]u8`); both run under a 2 KiB stack burn (new `src/burn.zig`) and are probed by the new `src/stackprobe2_test.zig`. `construct`/`process` keep their own burn; the derived `rho`/`mu`/pad keys now live in zeroed locals instead of by-value temporaries.

- **2026-10-08** — **FIX (secrets on the dead stack):** the dead-stack burn's buffer is now
  16-aligned instead of the vector type's natural 32. At 32 the burn's frame was realigned, and
  the up to 56 bytes between its saved frame pointer and the buffer — the top of the frame the
  burned body had used — stayed unzeroed (found by `threshold_ecdsa`'s stack probe: half of a
  secret survived there). No API change.
- **2026-10-08** — **NO CONSUMER-VISIBLE CHANGE (speed):** the dead-stack burn added earlier
  today zeroes with volatile 32-byte vector stores instead of `u64` stores (~4× faster per KiB).
- **2026-10-08** — **BREAKING + FIX (secrets on the dead stack, HIGH):** measured with the new
  ReleaseFast stack probe, `deriveHopSecrets`, `construct` and `process` left the session key or
  node key, blinded ephemeral scalars, blinding factors and `rho`/`mu`/`pad` keys in dead stack
  frames. Each now runs one frame down and zeroes 40 KiB at that depth; the secret key comes in
  by pointer: `deriveHopSecrets(&session_key, …)`, `construct(&session_key, …)`,
  `process(&node_privkey, …)`. (`loopix`'s routing test updated.)
- **2026-10-06** — **NO BEHAVIOURAL CHANGE (constant time by construction):** `process`'s
  final-hop test compares the deobfuscated `next_hmac` with zero through
  `std.crypto.timing_safe.eql` instead of `std.mem.allEqual`, whose constant time was an accident
  of LLVM's vectorisation. Same verdicts; ctgrind `process` unchanged at 40 contexts (digest
  re-pinned); `check-ct-compare` now pins two constant-time compares in `core.zig`.
- **2026-10-05** — Mutation run: 33 of 36 killed, 3 equivalent; 5 tests added or extended
  (`process` frame refusals on genuinely-MACed onions, a route filling exactly 1300 octets,
  `process` on an off-curve key, hop-frame edges, BigSize `fd00fc`). No code change.


- **2026-09-09** — Licensing: `NOTICE` kind changed from `provenance note` (record only) to
  `third-party attribution` (carries a CONDITION). `src/kat_vectors.zig` embeds BOLT#4's onion test vector verbatim from `lightning/bolts`,
  which is CC-BY 4.0, so attribution is owed and was not being given. ⛔⛔ The repository was
  distributing two opposite answers about one upstream: `lnwire`, `lninvoice` and `k256`
  record `lightning/bolts` as CC-BY 4.0 and attribute it, while this file said BOLT text is
  "not a copyrightable work (merger doctrine)" and needs no entry. Re-verified 2026-09-09
  against commit `152897261850d93c4f4597f39cf22d7d22d6ede6`: all 12 values vendored from `bolt04/onion-test.json` are byte-identical upstream today. The pin is now that
  commit rather than "`master` branch", which is not a pin. CC-BY's
  indicate-modifications condition is discharged (none — the values are the published ones,
  hex-decoded). No code or data changed.

  ⭐ Changing the kind pulled this file under `zig build check-copyleft` for the first time
  — that gate only holds ATTRIBUTION files to the formal `**Copyleft:**` shape — so the
  existing "No GPL/LGPL/AGPL source was consulted" sentence had to become a declared line.
  Declaring a condition honestly is what turned on a check the file had never faced.
- **2026-09-07** — **Test-only: `fuzzOnionPacketDecode` handed `fromSlice` the
  empty slice on every run, so `fromBytes` — the version check, the SEC1
  public-key decode, and `toBytes` behind them — had never executed from this
  target.** The harness drew `smith.bytes(&buf)` and then
  `smith.valueRangeAtMost(u16, 0, buf.len)`; `bytes` consumes
  `@min(buf.len, in.len)` octets, so the ranged draw found fewer than the
  eight it reads as a little-endian `u64` and returned the range MINIMUM.
  `len` was 0 for every input the ordinary test lane can carry, and
  `fromSlice` refused it at the `bytes.len != packet_len` line. ⭐ This is the
  exact-length shape that makes a short corpus useless: **no seed under 1366
  octets can get past the first line at all**, so the seeds are assembled at
  comptime by a `wire()` helper. 14 of them now cover an accepted packet, both
  SEC1 sign bytes, `UnsupportedVersion`, three distinct `InvalidPublicKey`
  causes (a non-encoding-type prefix, x = 0, x above the field prime), and
  `packet_len` minus one / plus one / plus eight. Measured 2026-09-07: **0 of
  14 seeds arrived non-empty, 0 got past the length gate and 0 parsed before;
  13, 9 and 3 after.**

- **2026-07-18** — Security audit: no findings. Verified:
  `kat_test.zig`/`kat_vectors.zig` carry the official BOLT#4 test vector.
- **2026-07-12** — New module: Lightning BOLT#4 Sphinx onion routing (the mix-net that
  gives Lightning payment privacy).
