# ripemd160 — spec

Design + threat notes for auditors. Usage: see ./README.md.

## Design & invariants

RIPEMD-160 processes 512-bit blocks through **two independent, parallel
80-round lines** (five 16-round groups each with distinct nonlinear
functions `f1..f5`, message-word-selection permutations `r`/`r'`, and
rotate-amount tables `s`/`s'`), whose final states are combined additively
into the next chaining value — unlike a single-line hash (SHA-1/SHA-2). The
round tables and constants (`R`/`RP`/`S`/`SP`/`K_GROUP`/`KP_GROUP` in
`root.zig`) are transcribed directly from the published spec; the right
line's nonlinear-function group order is the mirror of the left line's
(`f1,f2,f3,f4,f5` vs `f5,f4,f3,f2,f1` across the same five 16-round ranges),
while its additive constants (`K'`) are indexed by the same round-range
group as the left line's `K` — these are two independently-indexed
properties of the spec and easy to conflate; `compress()` keeps them as two
separate group computations (`group = j/16` for constants and left-line
functions, `groupp = 4 - group` for the right-line function only) to make
that distinction explicit in the code rather than folding them into one
"mirrored index" expression.

**Length padding is little-endian** — the classic implementation bug this
family (MD5, RIPEMD) inverts relative to SHA-1/SHA-2's big-endian: append
`0x80`, zero-pad to a 56-mod-64 boundary (rolling to a fresh block if the
message tail leaves no room), then the 64-bit bit-length as **LE** bytes.
Streaming cache (`buf`/`buf_len`/`total_len`) mirrors
`std.crypto.hash.md5.Md5`'s shape.

**`final()` is single-use, deliberately, matching `std.crypto.hash`.** It
does not clear `Self`: a second `final()`, an `update()` after `final()`, or
reuse without a fresh `init()` all return a digest, just not the one over the
bytes a caller probably meant. None of `sha2`/`sha3`/`blake2`/`blake3` in
`std` offer a `reset()` either — the fix is `init()` again, not recycling.

## Threat model / out of scope

Not secret-input-sensitive in this repo's usage (content hashing / Bitcoin
address derivation — the input is a public key or message, not a key or
password), so no constant-time claim is made or needed; RIPEMD-160 itself
has no secret-dependent branch/index in this implementation (round tables
are compile-time constants, indexed by the public round counter `j`, not by
data). RIPEMD-160's 160-bit output has a lower collision-resistance margin
than SHA-256 — that is a property of the algorithm the spec accepts, not a
defect of this implementation; consumers pair it with SHA-256 (`hash160`)
specifically because 160 bits alone is not their preimage/collision anchor
for anything security-critical beyond address-collision resistance (as
Bitcoin does).

## Verification

Official RIPEMD-160 test vectors (spec Appendix, widely republished, e.g.
the Bosselaers reference page): `""`, `"a"`, `"abc"`, `"message digest"`,
`"abcdefghijklmnopqrstuvwxyz"`, the 62-char alphanumeric vector, the 8×
`"1234567890"` vector, and the 1,000,000-`'a'` stress vector (fed in 1000
chunks of 1000 bytes, so it also exercises the multi-block `compress` loop
and both one-shot vs. chunked-streaming agreement). All cross-checked
locally against `openssl dgst -rmd160` and Python's
`hashlib.new('ripemd160')` while authoring this module (both back RIPEMD-160
via OpenSSL's legacy provider) — independent oracles beyond eyeballing the
published hex. Streaming teeth: byte-at-a-time feed and uneven chunking
across a >64-byte message (straddling the block boundary, including a chunk
that lands exactly on a 64-byte boundary) both agree with the one-shot
digest. `hash160`: cross-checked against a real secp256k1 compressed pubkey
generated locally (`openssl ecparam -genkey -name secp256k1`) piped through
`openssl dgst -sha256 | openssl dgst -rmd160` — the same
SHA256∘RIPEMD160 composition Bitcoin uses — plus an in-module differential
against a manual `Sha256` → `Ripemd160` composition. Also `Hmac(Ripemd160)`
against the RFC 2286 HMAC-RIPEMD160 vectors — the one test that actually
reads `block_length`, rather than comparing it to its own hardcoded copy.
Run: `zig build test-ripemd160`.

**Fuzz:** one `testing.fuzz` target, `fuzzStreamingMatchesOneShot` —
differential oracle, streaming `update`/`final` against one-shot `hash`, at
however many block-boundary-straddling splits the input's own bytes pick.
Corpus seeds sit at the lengths the KATs don't reach (55/56, 63/64/65, and
others around `block_length`). It does not re-check byte-exactness against
an external reference — the KATs above already pin that — it checks the
buffer arithmetic (`update`'s partial-fill / full-block / remainder logic)
the KATs' one-shot calls can't exercise.

## Backlog / deferred

None open.

## Status

`extract · any · util · reentrant` · deps: none (std only) — canonical
source is `pub const meta` in `src/root.zig`.

## Anchoring

**Anchor grade:** class B · oracle EXTERNAL

- **Class B** — published cryptographic or algorithmic construction with published vectors.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** official RIPEMD-160 spec Appendix vectors, incl. million-'a' KAT
