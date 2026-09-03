# xmlenc — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-03** — Drift re-audit (last audited `d163578`, ~737 lines since). Five fixes,
  seven mutations, seven red.
  - **The constant-time v1.5 unpadding was defeated by its own caller.**
    `rsaPkcs1v15Unwrap` goes to real lengths to hide whether a block is PKCS#1-conforming —
    mask arithmetic, a fixed-shape extraction, a masked publish — and then `decryptData`
    leaked exactly that bit at millisecond scale, because a conforming block with a
    correctly-sized payload went on to decrypt the whole attacker-sized content while a
    non-conforming one returned having done none of it. All three outcomes collapsed to the
    same `error.DecryptionError`, so the **value** was collapsed and the **work** was not.
    Measured, interleaved, in ReleaseFast over a 3 MiB CBC content ciphertext: min-of-8
    queries with a fixed threshold classified conforming vs non-conforming **194/200 =
    97.0%**, and the distinguisher's strength is chosen by the attacker, because it comes
    from the content size, which is their input. This is the Bleichenbacher /
    Jager-Somorovsky oracle the module's own doc comment names as the reason `rsa-1_5` is
    gated at all.
    Fixed with the RFC 8017 §7.2.2 / TLS countermeasure: a failed unwrap now yields a
    **decoy CEK** of exactly the content algorithm's key length, the content is decrypted
    either way, and the answer is decided by the validity mask afterwards. The decoy is
    derived from secret material the peer cannot compute — the raw RSA block for v1.5, the
    KEK for AES-KW — because a *predictable* decoy would let them craft content that
    authenticates under it and read the bit back out of the success/failure answer. The
    content key-length check moved from `decryptData` into the unwrap's mask for the same
    reason: checked one frame up it was the third arm of the same oracle. ⛔ OAEP still
    returns early; the decoy needs secret material and the only secret on that path is
    inside `rsa.decryptOaepH`, so closing it means either a second modular exponentiation
    (a louder difference than the one being closed) or a change to `rsa`'s surface.
    Recorded in SPEC.md.
  - **The EncryptedKey's 1024-byte cap bounded nothing.** `readCipherValue` ran
    `textContent(alloc)` — one full copy of the attacker's base64 — then grew an ArrayList
    byte by byte — a second — and only then checked the decoded size. So the cap bounded
    the OUTPUT while the work was unbounded. Measured: one 64 MB unauthenticated document
    reached **191,005,769 bytes of peak live allocation and 474 ms**, 186,000x the stated
    bound, all of it spent before the private key is touched — and `saml`'s
    `EncryptedAssertion` path reaches here pre-authentication. The source is now bounded
    before anything is copied (base64 spends 4 characters per 3 bytes, so a character count
    past that ceiling cannot decode within the cap whatever it contains), and the
    compaction allocates once at the exact size. Same document, after: **7 bytes**.
  - **Duplicate `CipherData`/`CipherValue` were decrypted first-match.** The xenc schema
    allows exactly one of each and `xmlsec1 --decrypt` refuses such a document outright —
    measured against the C reference on 14 crafted variants of this module's own fixture:
    two documents that xmlsec1 will not process at all yielded plaintext here, chosen by
    whichever copy came first. That is signature wrapping's shape one layer down. Now
    `error.MalformedStructure`, which is agreement with the reference.
  - **`decryptDataToDocument` freed the recovered assertion unwiped** — a CONVENTIONS §2.1
    **Z1** site (this function allocates and frees the plaintext itself and never hands it
    out). The repo-wide zeroization pass that added the wipes inside `decryptData`, and
    wrote the paragraph on its doc comment saying "every buffer *this* module frees on the
    way there ... is wiped here", walked past the sibling three lines below it. Measured
    with a free-scanning allocator in ReleaseFast: 1 of 12 released blocks still held the
    whole SAML subject identity and every attribute asserted about it. The existing `Z1:`
    regression test covered only the CBC scratch; it now covers this path too.
  - **Six refusals gained the tests they never had.** A corpus of VALID documents cannot
    exercise a refusal — the lesson this module's own previous audit recorded — and nine
    guards could each be deleted with the whole suite green, four of them memory-safety
    bounds on lengths the peer chooses. ⚠ One of the reported nine did not survive
    verification: removing the AES-KW `wrapped.len < 24` floor does NOT slice a 64-byte
    array to ~2^64, because the `plain_len > out.len` check on the next line catches it;
    what it does is turn a typed error into an integer-overflow panic, which is still a
    broken promise (SPEC: "typed errors, never panics") and is now red under mutation.
- **2026-09-03** — Docs. README's "no padding/oracle signal" was false as written and had
  already propagated into `saml`; both now say what is true — the error value carries no
  signal and, since this release, neither does the work. README's and SPEC's allow-list
  rows claimed OAEP's "MGF matches digest"; the code resolves DigestMethod and MGF
  **independently** and defaults MGF to MGF1-SHA1 whatever the digest is (the module has a
  test asserting exactly that, and its own second external fixture is such a pair), so both
  rows understated the accepted algorithm surface — the wrong direction for an allow-list to
  be wrong in. `example/main.zig`, the pattern an integrator copies, freed the recovered
  plaintext bare while `decryptData`'s doc comment tells callers to wipe it; it now does.
  SPEC's constant-time section is rescoped from one callee to `decryptData`.
- **2026-09-03** — ⛔ **Recorded, NOT fixed.** The OAEP arm of the work-collapse above.
  And `test "fuzz: decryptData never panics on a hostile EncryptedData"` passes an empty
  `FuzzInputOptions.corpus`, so under `zig build test-xmlenc` — the command SPEC.md names
  as this module's verification — Zig's test runner executes the harness on exactly **one**
  input, the empty-string smoke case. It is a compile check in the lane that runs, not
  coverage, and it is the direct reason the length bounds above could be deleted green. A
  committed corpus would fix it; the shapes are in the new refusal table meanwhile.

- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against RFC
  3394 §4.1's published test vectors.
- **2026-07-22** — New module: XML-Encryption (xmlenc-core-1) decryption.
