# opaque — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — A1 audit fix campaign, `A1/opaque.md` H1/H2/M1/M2/L1/L3/L5 (0 consumers
  in this repo, P1 applies). None of these change the wire protocol or existing test
  vectors.
  - **H1**: the MAC/tag comparison tests (`kat_test.zig`) only ever tampered byte 0 or
    the last byte of `server_mac`/`client_mac` — a comparison narrowed to a range that
    happened to include those positions would still pass 17/17 green (measured in the
    audit: a `server_mac[0..1]`-only comparison accepted 25 of 4096 fully forged MACs).
    Added three full-width tests that flip every one of the 64 bytes of the envelope
    `auth_tag`, `server_mac`, and `client_mac` individually and require every position
    to be caught. Confirmed the tests have teeth: a scratch mutant weakening `server_mac`
    to `[1]u8` still passes the *old* byte-0 tamper test but fails the new full-width one
    at the first byte beyond 0.
  - **H2**: added `defer std.crypto.secureZero` on secrets that never leave their
    function (`store`'s AKE private key, `createRegistrationResponse`/`generateKE2`'s
    per-client OPRF key, `generateKE2`'s ephemeral server keyshare private key,
    `generateKE3`'s recovered client private key and local copy of the ephemeral client
    secret). Measured with a stack-scan probe (paint + victim call + dead-stack search,
    same method as the audit): `generateKE2`'s OPRF key went from 1 hit to 0;
    `createRegistrationResponse`'s went from 2 hits to 1. The ephemeral keyshare private
    key stayed at 4 hits before and after — the residual copies are made by argument
    passing into `diffieHellman`/`ct25519`, the same class of issue tracked separately
    as `zig_std_crypto_leaves_key_schedules_on_stack`, and a single-module `defer` cannot
    reach them.
  - **M1**: the "Fake" credential-response doc comment said "random `client_public_key`"
    (implying 32 uniform random bytes); RFC 9807 §6.3.2.2 says "randomly generated public
    key" (a canonically-encoded group element). 93.754% of the former are rejected by
    `generateKE2`'s peer-element check, defeating the user-enumeration defense the fake
    record exists for. Doc corrected to point at `deriveAkeKeyPair` instead.
  - **M2**: `i2osp2`'s 2-byte length prefix (binding `identities`/`context` into the
    envelope MAC and AKE transcript) asserted `len <= 0xffff` — a panic in Debug/
    ReleaseSafe, a silent wraparound in ReleaseFast, on an application-controlled
    identity or context string. Added `checkIdentities`, called at every public entry
    point that accepts these values (`finalizeRegistrationRequest`, `generateKE2`,
    `generateKE3`), returning the new `error.IdentityTooLong` instead. Verified in both
    Debug and ReleaseFast (23/23).
  - **L1**: added `RegistrationRecord.validate()` (canonical `client_public_key` check,
    the same one `diffieHellman` would perform anyway) so a server can reject a malformed
    upload at registration time instead of discovering it as `error.InvalidPublicKey` on
    the client's first login — indistinguishable from a wrong password.
  - **L3**: added RFC 9807 Appendix C.2.1 (the ristretto255 FAKE/unregistered-user
    vector) as a KAT test — the only vector in this suite that exercises the
    user-enumeration defense end-to-end; SPEC.md previously said it had "nothing new to
    pin", which this closes as incorrect.
  - **L5**: NOTICE claimed "11/11 tests"; the suite has had more than that since
    `cc73521` and now has 23 (17 original + 6 from this fix).
  - **M3 (audit finding, no code change here)**: already fixed by `d5bdf8d7` before this
    session — the example's five `std.debug.assert` calls (which compile out in
    ReleaseFast, so the example kept printing "session_key independent" while comparing
    a mutated constant to itself) are now `must()`, which panics unconditionally.
    Verified: `d5bdf8d7^:modules/opaque/example/main.zig` has the asserts,
    `d5bdf8d7` is an ancestor of the tip this session started from.
  - Open: M4 (fuzz harnesses only exercise `@memcpy`-shaped decoders), M5 (no ctgrind
    harness — needs the shared valgrind lane, a full-repo gate, deferred), M6 (KSF is
    hardwired to Identity — a policy/API decision, not a mechanical P1–P6 fit), L2 (two
    unreachable `error` variants — removing them is a signature change, not covered by
    P1's "additive only"), L4 (preamble mutation coverage — test-writing debt). See
    `A1/opaque.md` dispozice for the numbers and reasoning on every item.
- **2026-07-18** — Security audit: no findings. Byte-exact against RFC 9807 Appendix
  C.1's published test vectors.
- **2026-07-12** — New module: OPAQUE — an asymmetric PAKE (RFC 9807),
  ristretto255-SHA-512 + 3DH + internal envelope (Identity KSF).
