# webhooksig — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-09** — tests: deterministic fuzz driver `WEBHOOKSIG_FUZZ` over the existing harnesses (`verify`, plus a genuine signature (every digest, encoding and prefix) accepted and a flipped digit, prefix, body, secret or truncation refused).
- **2026-10-09** — **SECURITY FIX (verifier DoS / stack overflow write):** a `v1a` signature
  of exactly 88 base64 characters without `==` padding decodes to 66 octets and was decoded
  into the 64-octet signature buffer — a panic in safe builds, 2 octets past the buffer in
  ReleaseFast, from an attacker-supplied header. Such a value is now skipped like any other
  undecodable entry. The same defect in `decodeMac` (every `v1`/base64 HMAC signature:
  44 characters without `=` decode to 33 octets for SHA-256's 32) is fixed the same way.
  Same shape as the websocket key defect found by fuzzing that day; regression tests.
- **2026-10-09** — Dead-stack burn: `standard.encodeSecret` (the raw HMAC key) now runs under `burn.run` (2 KiB); probed in the new `stackprobe2_test.zig`. No signature change.

- **2026-10-09** — **BREAKING:** dead-stack burns on every secret-touching entry point, and the
  Ed25519 signing key by pointer / into `out`. `standard.decodeSigningKey(out: *Ed25519.KeyPair,
  text)` (was: returned the pair — secret half — in an error union), `standard.signEd25519(…,
  key_pair: *const Ed25519.KeyPair, …)` (was: by value). Every HMAC sign/verify (`computeHex`,
  `sign*`, `verify*`, `signFormat`/`verifyFormat`, `standard`/`stripe`/`slack`, `Verifier`) now
  zeroes its stack after the call (`burn.zig`: 8 KiB HMAC, 16 KiB Ed25519). Before: every one of
  the 13 entry points left its frames — the HMAC `key ⊕ ipad/opad` states, the expected MACs a
  verify computed, the Ed25519 seed (18–69 windows) — on the dead stack (`stackprobe_test.zig`,
  `testkit.stackprobe`; the HMAC residue holds no verbatim key bytes, so only the probe's
  needle-free residue rule sees it).
- **2026-10-06** — ⛔ **Fixed: a 64-byte `whsk_` key whose public half is not its seed's was accepted in ReleaseFast.** `decodeSigningKey` relied on `std`'s `Ed25519.KeyPair.fromSecretKey`, which checks the embedded public key only under `std.debug.runtime_safety`; signing one message under two public keys gives away the secret scalar. It now derives the pair from the seed and compares in every mode. Found by the tag `2026-10-06` ReleaseFast lane (the existing test asserted the refusal and failed there).
- **2026-10-04** — **mvp → core.** Standard Webhooks (`standard`: `v1`
  HMAC-SHA256 and `v1a` Ed25519, `whsec_`/`whpk_`/`whsk_` keys, multi-signature
  headers), Stripe (`stripe`) and Slack (`slack`), each with a replay tolerance
  checked both ways against a caller-supplied `now` (`checkTimestamp`,
  `default_tolerance_s` = 300, `VerifyError`); the prefixed scheme generalised
  to SHA-1/SHA-512 and base64 (`Format`, `Digest`, `Encoding`, `signFormat`,
  `verifyFormat`); the middleware handles every scheme (`Options.scheme`,
  `digest`, `encoding`, `public_keys`, `clock`, `tolerance_s`;
  `Verifier.verifyRequest`, `checkFreshness`, `Clock.fromIo`) and refuses a stale
  delivery before reading its body. Vectors: the Standard Webhooks reference
  sign test, Slack's documented example, Python `hmac` / `openssl` black-box
  values. Seeded hostile-header sweep + sign/verify/flip oracle; mutation 37
  mutants, 0 surviving. Additive: every existing name and signature unchanged.
  **Behaviour change:** none for the default `.prefixed` scheme. `presentedMac`
  (private) now goes through the general decoder; the CT-compare pin for this
  file moves from 2 call sites to 1 (`macEql`, used by every compare) and the
  plain `std.mem.eql` count from 2 to 4 (version tags `v1`/`v1a`, public).
- **2026-09-07** — `fuzzVerify` ran exactly one input for its whole existence, and one of its
  two calls was a duplicate of the other. It opened with `smith.bytes(&secret_buf)` plus a
  ranged length, then the same for the body, then `smith.value(bool)` to choose between a raw
  and a structured presented value; a ranged `Smith` draw returns the range MINIMUM when fewer
  than eight octets remain, `bool` is a 1-bit range, and `Smith` discards the rest of its
  input after the first short read — so every run used secret `"\x00"`, an empty body, and a
  presented value of seven NUL octets followed by sixty-four `'0'`s (`smith.index` was 0 for
  every character). Separately, `_ = verifyWithPrefix("sha256=", …)` beside `_ = verify(…)` is
  literally the same call twice, since `verify` expands to exactly that. Now one
  `smith.slice(&presented_buf)` call as the first draw, an eleven-value corpus built around
  the module's own demo HMAC vector (so a genuinely CORRECT signature is in it), the secret
  and body derived from the drawn bytes with `testkit.fuzz.Cursor` instead of drawn after
  them, and the second call made with the EMPTY prefix, which is the case that actually
  differs. Measured: **0 of 11 seeds non-empty, 0 MACs decoded, 0 signatures accepted and
  exactly 1 distinct secret before; 10 of 11 non-empty, 5 decoded, 4 accepted and 8 distinct
  secrets after.**
- **2026-08-23** — **Breaking:** `sign` and `signWithPrefix` return
  `SignError![]const u8` (`error{OutputTooSmall}`) instead of `[]const u8`.
  `signWithPrefix` used to guard `out_buf.len` with `std.debug.assert` before
  two `@memcpy` calls; ReleaseFast compiles the assert (and the bounds check
  on those memcpys) out together, so an `out_buf` undersized relative to
  `signatureBufLen(prefix)` was a silent out-of-bounds write in the build
  that ships. Found by an audit sweep for this shape.
- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Verified: Byte-exact
  HMAC-SHA256 KAT (key="key", "The quick brown fox…" → `f7bc83f4…a3cd8`),
  `src/root.zig:360-368`.
- **2026-07-08** — New module: HMAC webhook signatures (GitHub style: `sha256=<hex>`).
