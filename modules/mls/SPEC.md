# mls — SPEC

See `README.md` for the consumer-facing API summary and Provenance note.

## What this is, in one paragraph

RFC 9420 Messaging Layer Security: a scalable-group-messaging protocol
built around TreeKEM (a ratchet tree of HPKE keypairs, one per group
member, that lets the whole group agree on a shared epoch secret in
O(log n) messages per membership change instead of Signal-style pairwise
sessions). This module (`mls`) is a multi-part arc; **Part 1** builds only
the FOUNDATION every later part needs: the mandatory cipher suite
(`suite.zig`), the seven labeled-crypto primitives RFC 9420 §5/§8/§9.1
define (`crypto.zig`), the ratchet tree's pure integer math
(`treemath.zig`), and the TLS-presentation-language wire codec
(`codec.zig`). Part 1 deliberately builds NO group state, NO TreeKEM
key-derivation-along-a-path, NO KeyPackage/Proposal/Commit message types,
and NO key schedule — those are later parts (see "Arc breakdown" below).

## Design & invariants

**`codec.zig`'s ONE deviation from plain RFC 8446 is load-bearing for the
whole arc.** RFC 9420 §2.1 states it uses the TLS presentation language
verbatim except for vector length headers: instead of a fixed `uint8`/
`uint16`/`uint32` length prefix sized by declared min/max
(`opaque foo<0..255>`), MLS uses a QUIC-style variable-length integer
(§2.1.2, borrowed from RFC 9000 §16, with RFC 9420 additionally requiring
— matching RFC 9000's own requirement — the encoder to always use the
SMALLEST prefix that fits). Every later part's KeyPackage/LeafNode/
Proposal/Commit/framing wire formats are `opaque foo<V>`-shaped, so
`codec.Writer`/`Reader` getting this byte-exact here is a correctness
precondition for everything downstream, not just this part's own use of
it (`crypto.zig`'s `KDFLabel`/`SignContent`/`EncryptContext` framing).
Verified against RFC 9420 §2.1.2's own three worked examples
(`0x9d7f3e7d` → 494878333, `0x7bbd` → 15293, `0x25` → 37) plus explicit
non-minimal-encoding and truncated-input rejection tests.

**Two label-framing systems that look similar but are NOT the same
construction.** `hpke.suite.labeledExtract`/`labeledExpand` (RFC 9180 §4)
prepend `"HPKE-v1" || suite_id` to every derivation; MLS's `KDFLabel`/
`SignContent`/`EncryptContext` (RFC 9420 §8/§5.1.2/§5.1.3) prepend
nothing of the sort — they're MLS's own wire structs (`length ||
opaque label<V> || opaque context<V>`, etc.), assembled via
`codec.Writer` and fed DIRECTLY into `KDF.Expand`/the signature scheme.
`crypto.zig`'s `ExpandWithLabel`/`DeriveSecret`/`SignWithLabel`/
`VerifyWithLabel` never call into `hpke.suite`'s labeling at all — only
`EncryptWithLabel`/`DecryptWithLabel` hand off to `hpke` wholesale (RFC
9420 §5.1.3 literally says "SealBase and OpenBase are defined in Section
6.1 of [RFC9180]"), and even then MLS's `EncryptContext` framing becomes
HPKE's `info` parameter — HPKE then applies ITS OWN "HPKE-v1"+suite_id
labeling around that on top. The two layers compose; verifying this
required tracing RFC 9420 §5.1.3's definition against RFC 9180 §6.1's
`SealBase`/`OpenBase` signatures by hand (both take `info` as an opaque
byte string, so MLS's pre-encoded `EncryptContext` slots in exactly
where HPKE expects a caller-supplied `info`).

**`RefHash` streams; `ExpandWithLabel`/`SignWithLabel`/`EncryptWithLabel`
assemble a bounded scratch buffer (implementation detail, not a spec
requirement) — same asymmetry `hpke.suite.labeledExtract`/
`labeledExpand` already has, for the identical reason.** `RefHash`'s
`value` argument is an entire encoded `KeyPackage`/`AuthenticatedContent`
in real use with no realistic upper bound, so it hashes incrementally
(`Hash.update` per varint-prefixed field) and needs no buffer at all. The
other five functions each need ONE CONTIGUOUS byte slice to hand to
`Hkdf.expand`/`Ed25519.sign`/HPKE's `info` (all three re-process their
input as a whole, not incrementally), so they assemble their
`KDFLabel`/`SignContent`/`EncryptContext` into a fixed 512-byte
`label_scratch_len` stack buffer (matching `hpke.suite.labeledExpand`'s
own 512-byte constant) and return `error.LabelTooLong` rather than
silently truncating or panicking on overflow. Every label/context/content
this Part or the KAT vectors use is a handful to a few dozen bytes, so
512 is comfortable headroom; a LATER part deriving a secret from a
multi-kilobyte `GroupContext` (with extensions) may need a larger bound
or a caller-supplied scratch slice instead — tracked below in Backlog,
not a gap for anything this Part actually exercises.

**`treemath.zig` returns `null`, never panics, where the RFC's own Python
raises an exception.** RFC 9420 Appendix C's reference `left`/`right`
raise on a leaf node, `parent`/`sibling` raise on the root — this port
returns `?usize` at exactly those points instead, because a later part
calls these with node indices that arrive over the wire (an
attacker-controlled tree size or index is untrusted input, and a panic on
untrusted input is a denial-of-service bug this repo's fuzz-safety
convention forbids). `direct_path`/`copath` take a caller-supplied `out:
[]usize` buffer and return `error.BufferTooShort` rather than allocating
or assuming a bound — `max_path_len = 64` is published as the safe size
for any tree this module can index (`usize` node indices already cap
`n_leaves` well below any tree Appendix C's algorithm would need a
deeper-than-64 path for).

**Ed25519 signing is deterministic (RFC 8032) — `SignWithLabel` calls
`std.crypto.sign.Ed25519.KeyPair.sign(msg, null)` with `noise = null`,
never hedged/randomized signing.** This is a stronger-than-required KAT
property the vector format doesn't ask for explicitly (the task brief
expected only a verify-round-trip, appropriate for a RANDOMIZED scheme
like ECDSA) — because Ed25519 is deterministic, `kat_test.zig` re-signs
the vector's own `(priv, label, content)` and checks the produced
signature is byte-IDENTICAL to the vector's published `signature` field,
which is a strictly stronger check than "verifies successfully" (a buggy
sign that happened to produce a different-but-still-valid signature would
pass a verify-only check but fail this one).

## Arc breakdown (Part 1 done; later parts, tier-tagged)

Honest tiering per the task brief: this Part is **100% Sonnet** —
mechanical composition (wire encoding, HKDF/Ed25519/HPKE calls exactly as
specified, integer-arithmetic tree math ported from the RFC's own
pseudocode) with an authoritative byte-exact conformance oracle (the
official interop vectors) for every function. Nothing here required a
novel security-property judgment call the way, say, TreeKEM's
parent-hash validation logic does (see Part 2 below).

| Part | Scope | Tier | RFC-vector components |
|---|---|---|---|
| **1 (this part)** | Cipher suite, labeled crypto, tree math, codec | **Sonnet** | `tree-math.json`, `crypto-basics.json` |
| **2 — TreeKEM core** | `UpdatePath`/`UpdatePathNode`, parent-node content, tree-hash (§7.1/§7.8), resolution (§4.1's "resolved node set" computation), the actual path-secret-derivation-and-encryption-to-a-copath walk (§7.6) | **Fable** — the genuinely hard piece the task brief flags. Parent-hash chaining (§7.9) and resolution are subtle recursive tree-validation logic with real security consequences if wrong (a forged parent-hash or a wrong resolution set can let a malicious member inject an unauthorized key into another member's derived path) — the "hardest TIER, not crypto-only" bar this repo's Fable pool applies | `tree-operations.json`, `tree-validation.json`, `treekem.json` (mlswg vector names — not yet fetched/audited by this Part) |
| **3 — LeafNode / KeyPackage / Credential** | §5.3 credentials, §7.2/§7.3 `LeafNode` content + validation (`leaf_node_validation.json`), `KeyPackage` (§10) wire format + validation | **Sonnet** — mostly `codec.zig`-shaped serialization plus signature verification (`SignWithLabel`/`VerifyWithLabel` from THIS part) over well-specified structs; the validation RULES (§7.3's numbered list) are mechanical checks, not novel crypto | `key-package-validation.json`, `leaf-node-validation.json` |
| **4 — Key Schedule** | §8's full `init_secret_[n-1] → ... → init_secret_[n]` chain, §8.1 `GroupContext`, §9 Secret Tree (`DeriveTreeSecret` from THIS part slots in directly) | **Sonnet** — pure composition of `ExpandWithLabel`/`DeriveSecret` (already built) over a well-specified derivation graph; the only subtlety is getting the derivation ORDER exactly right, which the RFC's own diagram (Figure 22) pins unambiguously | `key-schedule.json`, `secret-tree.json`, `message-protection.json` |
| **5 — Proposal / Commit / framing** | §11-§12 Proposal types, Commit processing, `PublicMessage`/`PrivateMessage` framing + the membership/confirmation MACs | **Sonnet** — mechanical message-type composition over Parts 1-4's primitives, EXCEPT the Commit-processing state machine's interaction with TreeKEM (applying a Commit's proposals correctly against the ratchet tree) which leans on Part 2's resolution logic being right | `messages.json`, `commit-processing` vectors |
| **6 — External Commit / PSK / Reinit / Sub-group ops** | §12.4.3 external Commit, §8's `psk_secret` injection (§13), §16's reinit/branch | **Sonnet**, lowest priority — genuinely-used-but-optional MLS features; defer until a real consumer needs them (this repo's std/dedup consumer-check convention) | — |

**Where TreeKEM/Fable lands, restated plainly:** it's Part 2, specifically
the path-secret-derivation-along-the-copath + parent-hash-chain
validation logic — NOT the crypto primitives (HPKE seal/open is already
done, here, via `EncryptWithLabel`/`DecryptWithLabel`; HKDF derivation is
already done, via `ExpandWithLabel`/`DeriveTreeSecret`) but the TREE
ALGORITHM binding them together correctly under adversarial tree state
(a malicious member's LeafNode, a stale/forked view of the tree, a
resolution set computed over unmerged leaves). This matches the task
brief's own expectation exactly.

## Threat model

- **`codec.Reader` on hostile input.** Every `read*` function is bounds-
  checked against the buffer's actual length regardless of what a length
  prefix inside the buffer claims — a `readVector` whose varint claims
  more bytes than remain fails `error.BufferTooShort`, never an
  out-of-bounds read. `readEnum`/`readPresence` never call
  `@enumFromInt`/switch in a way that's reachable-UB on an unrecognized
  tag — see `codec.zig`'s `readEnum` doc comment on requiring a
  non-exhaustive (`_,`) enum, the convention this repo's other
  wire-format enums (`dtls.messages.HandshakeType`, `hpke.suite.KemId`)
  already follow.
- **Scratch-buffer overflow on an oversized label/context.** `LabelTooLong`
  is a typed error, never a panic/truncation — see Design's scratch-buffer
  paragraph above. An application binding attacker-controlled data
  directly into a `context`/`content` argument (unusual, but not
  impossible — e.g. an application-defined MLS extension) gets a clean
  error rather than a buffer overrun.
- **`treemath.zig` on an attacker-controlled tree size / node index.**
  Every function is pure arithmetic with no allocation and no panic path
  reachable from an out-of-range `x`/`n_leaves` input on its own —
  `left`/`right`/`parent`/`sibling` return `null` rather than indexing
  into anything; `direct_path`/`copath` are the only functions that can
  fail (`error.BufferTooShort` on an undersized `out`), and that failure
  is a caller-buffer-sizing issue, not a function of the (attacker-
  supplied) tree shape itself misbehaving. Note: this module does NOT
  itself validate that a given `x` is actually `< node_width(n_leaves)`
  for the caller's tree — passing an out-of-range `x` produces
  arithmetically well-defined but MEANINGLESS results (no panic, no OOB
  memory access, just a wrong-but-bounded answer); range-checking `x`
  against the caller's actual tree is the CALLER's responsibility (a
  later part's ratchet-tree state owns that invariant), matching this
  file's "pure integer math, no I/O, no validation policy" scope.
- **Ed25519/HPKE key material.** This module generates no keys of its own
  beyond what a caller passes in (`SignWithLabel`/`EncryptWithLabel` take
  an already-constructed `KeyPair`/`PublicKey`) — key generation, storage,
  and rotation are entirely the caller's (a later part's KeyPackage
  lifecycle) responsibility, mirroring `hpke`'s own scoping.
- **`EncryptWithLabel`'s randomness source.** Takes `io: std.Io` and draws
  a fresh ephemeral KEM keypair per call via `hpke.sealBase` (never an
  injected/fixed ephemeral in the real entry point) — the KAT's
  `DecryptWithLabel`-only check against the vector's fixed `kem_output`
  doesn't exercise this randomness at all, so `kat_test.zig` separately
  round-trips `EncryptWithLabel`→`DecryptWithLabel` through the real
  `io`-backed path to confirm the non-deterministic entry point itself
  works, not just the deterministic-input decrypt half.

## Backlog

- **Scratch-buffer size (512 bytes) may need revisiting once `GroupContext`
  (Part 4) exists** — a `GroupContext` with several MLS extensions could
  plausibly exceed 512 bytes as an `ExpandWithLabel` `context` argument.
  Options when that part lands: widen `label_scratch_len`, or add a
  caller-supplied-scratch-slice overload alongside the current
  fixed-buffer convenience functions.
- **Part 2 (TreeKEM) vector fetch/audit not yet done** — `tree-
  operations.json`/`tree-validation.json`/`treekem.json` from
  `mlswg/mls-implementations` need the same fetch-and-embed treatment
  `kat_test.zig` gives `tree-math.json`/`crypto-basics.json` here, plus a
  read of RFC 9420 §7 end-to-end before implementation starts (this Part
  deliberately did not do that reading — out of scope per the task
  brief).
- **`treemath.zig`'s `common_ancestor_semantic`/`common_ancestor_direct`**
  (RFC 9420 Appendix C also publishes these) are NOT implemented here —
  not required by `tree-math.json`'s published fields (`root`/`left`/
  `right`/`parent`/`sibling` only) and not needed until a later part's
  actual TreeKEM resolution logic wants them; add then, following the
  same direct-port approach.
