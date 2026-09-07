# jwe — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **Test-only: both fuzz harnesses had already been "fixed"
  once, and both fixes bought nothing, for the same reason.**
  (a) `header.fuzzParse` carried a comment recording the earlier repair —
  "build a syntactically valid header and let the fuzzer choose its member
  VALUES instead" — but every knob that repair added was a
  `smith.value(bool)` drawn AFTER `smith.bytes(&raw)`. `bytes` consumes
  `@min(buf.len, in.len)` octets, so on the one input the ordinary test lane
  runs, `n` was 0 and every `bool` was false: the header actually parsed was
  `{"alg":"PBES2-HS256+A128KW","enc":"A128GCM"}` with **no optional members at
  all**, so `optionalBase64`, `optionalUint` and `optionalEpk` — named in that
  same comment as the paths where the parse errors live — were still never
  entered. Measured 2026-09-07: 0 of 1 inputs carried a `p2c`, `p2s`, `kid` or
  `epk`. Now one `smith.slice` draw whose first octet is a bitmask over the
  optional members, with a 15-seed corpus. After: **14 of 15 seeds non-empty,
  15 headers parsed, 4 with `p2c`, 4 with `p2s`, 2 with `kid`, 2 with `epk`,
  and 1 blob parsed as a header in its own right.**
  (b) `root.fuzzDecryptCompact` carried the same shape of record — the
  measured "0 of 200,000 uniform-random inputs got past
  `MalformedToken`/`InvalidBase64`" that motivated corrupting a genuine token
  instead — and then made `n_flips` its FIRST ranged draw. So on the one input
  the lane runs, `n_flips` was 1, `smith.index(token.len)` was 0 and
  `smith.value(u8)` was 0: **one input for ever, the genuine token with its
  first octet zeroed, refused by `InvalidBase64` before `header.parse`.** The
  flips now come from one `smith.slice` read as a script, with a **16-bit**
  offset — a one-octet offset could not reach the authentication tag of a
  ~180-octet token at all. After: **10 of 11 seeds non-empty, 11 distinct
  damaged tokens, 8 refused at the framing and 3 reaching the header parse and
  key unwrap, where that count had always been 0.** The guard also pins
  `accepted == 0`: a damaged token that authenticated would be the defect.

- **2026-09-03** — Drift re-audit (706 lines since the last one). ⚠ **BREAKING**
  in three ways: `DecryptError` gained `WorkFactorTooHigh`; `header.ParseError`
  gained `UnsupportedCrit`; and several decrypt failures that previously
  surfaced as `InvalidKey`/`UnwrapFailed`/`BufferTooSmall` now surface as
  `AuthenticationFailed` or `MalformedToken`.
  - **RFC 7516 §11.5, verbatim: "the recipient MUST NOT distinguish between
    format, padding, and length errors of encrypted keys."** One RSA-OAEP
    decryption returned three distinguishable values — an unwrap error for
    junk, `InvalidKey` for a *valid* OAEP wrap of a wrong-length message (the
    "length error" the sentence names), and `AuthenticationFailed` once both
    passed. That is Manger's oracle read straight off the return value, with no
    statistics required; `AxxxKW` and `AxxxGCMKW` had the same shape. Collapsing
    the VALUE alone would not have sufficed — the early returns also skipped the
    content decryption, so the arms did different amounts of WORK. Fixed the way
    §11.5 recommends: substitute a decoy CEK the peer cannot compute and proceed,
    so every path runs the AEAD and fails there. Structural checks that happen
    before any secret is touched (a missing `epk`, a curve that is not the
    recipient's, a non-empty Encrypted Key under a direct-agreement `alg`) stay
    distinguishable as `MalformedToken`/`CurveMismatch` — collapsing those would
    leak nothing and would hide the confusion and malleability defenses.
  - **`p2c` was an attacker-chosen work factor with no ceiling**, obeyed before
    anything was authenticated. Measured at ~1 µs/iteration: a 192-byte token
    declaring `p2c=100,000,000` costs 99.75 s of CPU and then returns
    `AuthenticationFailed`; at `u32` max, ~71 CPU-minutes. SPEC.md's
    "header-size-bounded decode" bullet was read as covering this; it bounds the
    header's BYTES, and what grows is the WORK its contents command. New
    `default_max_p2c` (1,000,000) and `DecryptOptions.max_p2c`.
  - **`crit` was parsed past and ignored** (RFC 7516 §5.2 step 5: a recipient
    MUST understand and process every parameter listed, and MUST reject the JWE
    otherwise). Six shapes were accepted on genuine tokens, including the
    spec-forbidden `crit:["alg"]` and a malformed `crit:"notanarray"`. This
    module implements no extensions, so any `crit` is now `UnsupportedCrit`.
  - The `dir` arm accepted a **non-empty Encrypted Key segment**, which is
    outside the AAD — unbounded token malleability with no key at all. RFC 7516
    §5.2 step 10 names Direct Encryption alongside Direct Key Agreement; only
    the ECDH-ES arm implemented it. Its comment cited "§5.2 step 5" — the `crit`
    step, i.e. the one step the module skipped, quoted as authority for the one
    it kept.
  - RFC 7518 §4.8.1.1's "A minimum salt length of 8 octets MUST be used" is now
    enforced on `p2s`; the encrypt-side doc had called that MUST a
    recommendation.
  - **Both fuzz harnesses reached nothing.** `decryptCompact`'s fed uniform
    random bytes, of which **0 of 200,000** got past `MalformedToken`/
    `InvalidBase64` into the header parser — so the entire surface the findings
    above live on was unfuzzed while `check-fuzz` reported the module covered.
    And outside `--fuzz` an empty corpus is exactly one input, with
    `valueRangeAtMost` falling back to its LOWER bound, making that one input
    `len = 0`. Both now start from a well-formed artifact and corrupt it, with a
    test asserting the corruption reaches the parser.
  - Docs: `KeyMaterial` was described as four arms in both README and SPEC — in
    the sentence stating the algorithm-confusion defense — when it has six.
  - ⚠ This changelog also had **no entry for the breaking `std.Random`→`Entropy`
    signature change** (`c36f2cac`). `snmp`, changed by the same commit for the
    same reason, carries a dated `**BREAKING:**` entry; `jwe` carried nothing,
    and `check-changelog` structurally cannot see the difference.

- **2026-07-18** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Byte-exact against RFC 7518's published
  test vectors.
- **2026-07-11** — New module: JSON Web Encryption (RFC 7516/7518) compact
  serialization.
