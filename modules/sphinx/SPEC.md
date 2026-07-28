# sphinx — SPEC

Lightning BOLT#4 Sphinx onion routing; see [README.md](README.md) for
purpose and API. Provenance: see [NOTICE](NOTICE).

## Design

- **Source of truth**: BOLT#4 ("Onion Routing Protocol", `lightning/bolts`).
  BOLT#1 is cited for the `bigsize` variable-length integer encoding, which
  BOLT#4's `hop_payload` framing reuses for its `length` field.
- **Layering**: the module splits cleanly along "does this touch
  elliptic-curve math or drive the full per-hop crypto loop":
  - Keyless infrastructure — `packet.zig` (the fixed 1366-byte wire shape +
    the two packet-level checks BOLT#4 assigns before any crypto:
    `version == 0`, `public_key` parses as a valid on-curve compressed
    secp256k1 point via `Secp256k1.fromSec1`), `keyderive.zig`
    (`generateKey`/`generateCipherStream` — both plain `std.crypto`, no EC
    math), `bigsize.zig` (BOLT#1's codec, pure integer arithmetic),
    `hopframe.zig` (the per-hop `bigsize(length) ‖ payload ‖ hmac` frame
    shape and the `shiftSize`/right-shift/left-shift buffer mechanics —
    pure byte-shape logic, no keys involved).
  - Crypto cores (`core.zig`) — `deriveHopSecrets` (the forward
    shared-secret + blinding chain, BOLT#4 "Shared Secret" + "Blinding
    Ephemeral Onion Keys"), `construct` (BOLT#4 "Packet Construction",
    incl. "Filler Generation"), `process` (BOLT#4 "Onion Decryption", one
    hop). Each carries the exact per-step algorithm in its own doc comment —
    see `core.zig` directly rather than duplicating that text here.
- **std recon** (confirmed against `lib/std/crypto/pcurves/secp256k1.zig`
  and `lib/std/crypto/chacha20.zig`, Zig 0.16.0):
  - ECDH point: `Secp256k1.fromSec1(&pubkey_33_bytes)` parses a compressed
    (or uncompressed/identity) SEC1-encoded point, rejecting anything
    off-curve or malformed (`error.InvalidEncoding`/`.NotSquare`/
    `.NonCanonicalEncoding` — all folded into `packet.ParseError.
    InvalidPublicKey` at the packet-parse layer, and into `core.
    SharedSecretError.InvalidPublicKey` where the crypto core parses a raw
    hop pubkey). `.mul(scalar_bytes, .big)` performs the scalar multiply
    (`IdentityElementError!Secp256k1` — the identity case is a real,
    checked failure mode). `.toCompressedSec1()` serializes the result back
    to the same 33-byte shape `packet.OnionPacket.public_key` uses, ready
    for `Sha256.hash` — this exact `fromSec1 -> mul -> toCompressedSec1 ->
    Sha256.hash` chain is verified BYTE-EXACT in `kat_test.zig`'s hop-0
    shared-secret test (see "Verification" below).
  - Cipher stream: `std.crypto.stream.chacha.ChaCha20IETF.stream(out,
    counter=0, key, nonce=0^12)` — the IETF variant (`nonce_length == 12`,
    i.e. 96 bits, matching BOLT#4's "96-bit zero-nonce" verbatim;
    `key_length == 32`). `.stream` OVERWRITES `out` with the raw keystream
    (there is no real plaintext to XOR against — BOLT#4's own wording,
    "encrypting a 0x00-byte stream", is exactly this), which is why
    `keyderive.generateCipherStream` calls `.stream`, not `.xor`.
  - `std.crypto.auth.hmac.sha2.HmacSha256.create(out, msg, key)` — note the
    ARGUMENT ORDER: BOLT#4 "Key Generation" uses the key-TYPE label
    (`"rho"`/`"mu"`/`"um"`/`"pad"`, no NUL terminator) as the HMAC KEY and
    the 32-byte shared secret as the MESSAGE — the opposite of the more
    common "HMAC keyed by secret material" idiom. Getting this backwards
    silently produces a non-interoperable key derivation that would still
    "work" (compile, run, produce SOME 32-byte key) but never match another
    implementation. `keyderive.zig`'s doc comment flags this explicitly,
    and its own test recomputes one label via the raw std call to prove the
    order.
- **Payload framing, the JSON's fixture layout**: the official
  `bolt04/onion-test.json` vector's per-hop `payload` field already
  includes that hop's OWN `bigsize` length prefix (verified in
  `kat_vectors.zig`'s doc comment and independently re-derived while
  building `kat_vectors.zig`) — i.e. `payloads[i]` is exactly
  `bigsize(len) ++ tlv_payload`, matching `hopframe.writeHopFrame`'s input
  shape (minus the trailing 32-byte `hmac`, which the sender only knows
  once the reverse-order per-hop loop reaches that hop). This is why
  `kat_test.zig` can real-test `bigsize.read`/`hopframe.shiftSize` against
  the vector directly, with no crypto involved at all.
- **Why `deriveHopSecrets` is its own function, not inlined into
  `construct`**: BOLT#4's "Packet Construction" walks the route TWICE —
  once FORWARD (to derive `ss_i`/`epk_i` for every hop, since each
  iteration's ephemeral scalar depends on the previous one via blinding)
  and once in REVERSE (to actually assemble `hop_payloads`, since "the
  packet construction is performed in the reverse order of the route").
  Splitting the forward pass into its own function makes that two-pass
  structure explicit at the API level rather than requiring `construct` to
  either recompute the chain twice or thread a hidden intermediate array
  through untyped. It doubles as `process`'s conceptual sibling: a
  receiving hop effectively runs ONE step of this same chain (its own
  `ss`, plus the point-multiply for the pubkey it forwards onward) without
  ever materializing the full array — see `core.process`'s doc comment,
  step 9.a.

## Threat model / limits

- **Per-hop unlinkability is the module's entire reason to exist.** Two
  distinct properties, both required, neither sufficient alone:
  - **Ephemeral-key blinding** (`deriveHopSecrets`'s blinding-factor chain,
    `process`'s per-hop re-blinding): without it, every hop would see the
    SAME ephemeral public key, letting any two colluding hops (or a single
    observer with visibility into multiple hops) trivially link packets
    from the same payment as it traverses the network — defeating the
    entire point of onion routing. The blinding factor is derived from
    BOTH the current ephemeral pubkey AND the shared secret specifically
    so that no party other than the two ECDH participants at that hop can
    predict or verify it.
  - **Filler generation** (BOLT#4 "Filler Generation", inside `construct`):
    without deterministic filler, each hop's freshly-revealed tail (after
    the fixed-size `hop_payloads` buffer is left-shifted during unwrap)
    would be all-zero, and successive hops would see a SHRINKING run of
    trailing zeros — directly leaking each intermediate hop's distance
    from the final recipient (its "position in the route") to any single
    observer, even one who never colludes with another hop. The filler
    must be bit-for-bit what an honest forwarding hop's own
    deobfuscation-then-XOR would produce, or the sender's precomputed
    per-hop HMACs will not verify anywhere down the route.
- **HMAC integrity is the packet's only anti-tamper/anti-misrouting
  guarantee** (`process`'s step 4). It MUST be a constant-time comparison
  (`std.crypto.timing_safe.eql`, per `core.ProcessError.
  IntegrityCheckFailed`'s doc comment) — a timing-variable compare lets an
  attacker who can repeatedly resubmit a forwarded/mutated onion to a
  target hop (an HTLC probe, not even a full payment) recover the correct
  HMAC one byte at a time. This is the single highest-severity property
  `process` must get right (it does — `std.crypto.timing_safe.eql`, and
  the tamper path is KAT-tested); unlike a
  signature-forgery bug, a broken constant-time compare here doesn't just
  weaken the scheme, it turns every hop into a byte-at-a-time decryption
  oracle for an adversary with repeated-probe access (widely available
  in practice via failed/retried HTLCs).
- **`version != 0` / invalid `public_key` MUST hard-fail before any crypto
  runs** (BOLT#4 "Onion Decryption" §Requirements, enforced today in
  `packet.OnionPacket.fromBytes` — this is the one piece of the "Onion
  Decryption" Requirements list this module implements for real already,
  since it needs no shared secret). Skipping either check risks feeding a
  malformed or attacker-chosen point into `process`'s later EC arithmetic.
- **Reserved payload lengths (0, 1)**: BOLT#4 reserves these because no
  real `payload` TLV stream is ever shorter than 2 bytes; `hopframe.
  writeHopFrame`/`.readHopFrame` reject them today (`error.
  ReservedPayloadLength`) as a real, checked parse-level guard — not
  merely documented.
- **Constant-time scope**: `deriveHopSecrets`
  and the sender-side half of `construct` handle SECRET scalar material
  (`session_key` and its blinded derivatives) — `Secp256k1.scalar.mul`/
  `.mul` on the curve are std's constant-time paths and should be used
  as-is, with no additional secret-dependent branching introduced around
  them. `process` similarly handles a secret `node_privkey`. The HMAC
  VERIFY step (not the HMAC-key derivation, which handles only PUBLIC
  shared-secret-derived data at that point) is the one comparison in the
  whole pipeline that must be constant-time with respect to
  attacker-controlled input (see above); every other computation in
  `process` operates on values that are either fully public (the packet
  bytes) or, once past the HMAC gate, this node's own already-established
  secrets.
- **Out of scope for this module** (left to whatever protocol layer wires
  it in): the `payload` TLV field's own value semantics (`amt_to_forward`,
  `short_channel_id`, `payment_data`, etc. — BOLT#4's own payload-format
  section defines these; this module treats `payload` as an opaque byte
  string throughout), route blinding's `path_key`/`blinding_ss` tweak
  (BOLT#4 "Route Blinding" — a distinct mechanism layered on top of plain
  Sphinx, not part of the base onion construction/decryption this module
  implements), and the return-path error-message obfuscation (BOLT#4
  "Returning Errors" — reuses this module's shared secrets but is its own
  wire format and its own `um`-keyed HMAC chain, not built here).

## TODO(fable) — done record (fill-in pass completed 2026-07-12)

All three `core.zig` stubs were implemented in the checklist's dependency
order and every formerly-`SkipZigTest` KAT assertion was re-enabled (plus
new ones); `kat_test.zig` now carries zero skips:

1. **`deriveHopSecrets`** — implemented exactly per its doc-comment recipe
   (ECDH via `Secp256k1.fromSec1(pubkey).mul(scalar, .big)` →
   `.toCompressedSec1()` → `Sha256.hash`; blinding factor
   `SHA256(epk ‖ ss)`; scalar chain via `Secp256k1.scalar.mul(_, _, .big)`,
   point chain via one point-multiply per hop instead of a fresh base-point
   multiply). Reproduces all 5 `kat_vectors.shared_secrets` byte-exact, and
   `epk_0 == pubkeys[0]` (the fixture's documented session_key ==
   node_privkeys[0] coincidence). `scalar.mul`'s `error.NonCanonical` (a
   blinding factor ≥ the group order, probability ~2^-128) folds into
   `error.IdentityElement` — same "degenerate scalar" class, fail closed.
2. **`construct`** — validation (hop-count match, `max_hops` = 37 cap,
   reserved-length payloads, total `shiftSize` ≤ 1300) before any EC math,
   then `deriveHopSecrets`, filler generation, `pad`-stream seeding, and
   the reverse-order right-shift/write-frame/XOR/HMAC wrap loop. The
   filler recurrence used (derived from the `process`-side identity, see
   the inline comment): with `L` = filler length so far and `s` = hop i's
   `shiftSize`, `filler' = (filler ‖ 0^s) XOR rho_i-stream[1300-L ..
   1300+s]` — the stream slice starts mid-stream because hop i's unwrap
   XORs a 2600-byte stream against `(view ‖ 0^1300)` and the freshly
   revealed tail lands at exactly those offsets. **Reproduces
   `kat_vectors.onion` (the official published 1366-byte packet)
   byte-exact** — the module's make-or-break oracle.
3. **`process`** — receiver-direction ECDH, `mu`-HMAC verify via
   `std.crypto.timing_safe.eql` (fail closed, `error.
   IntegrityCheckFailed`), 2600-byte deobfuscation, `hopframe.
   readHopFrame` (bigsize/short-buffer failures mapped to `error.
   MalformedPayload`, plus a `frame.consumed <= 1300` bound so a hostile
   length can never index the zero-padding half or overflow
   `payload_buf`), all-zero `next_hmac` ⇒ final hop, else the
   blinding-factor point-multiply for the outgoing `public_key` and the
   `[consumed .. consumed+1300]` slice as the outgoing `hop_payloads`.
   Verified against hop 0 of the published packet AND a full 5-hop
   `construct` → `process` round-trip (every hop's TLV recovered, each
   intermediate `next_packet` re-parses as a valid wire packet, final hop
   flagged `next_packet == null`); 1-bit hmac tamper and wrong-node-key
   probes both fail closed.

## Verification

- KAT oracle: the official BOLT#4 test vector, fetched directly from
  `lightning/bolts` (raw GitHub, `master` branch) for this pass:
  `bolt04/onion-test.json` (the `generate` input, the assembled 1366-byte
  `onion`, and the `decode` array of 5 node private keys) plus
  `04-onion-routing.md`'s "# Test Vector" section (the 5 per-hop
  `shared_secret` values, published there rather than in the JSON).
  Embedded verbatim in `src/kat_vectors.zig` — see its doc comment for the
  exact provenance split between the two source files.
- **Independent re-derivation log** (not just "copied the spec's numbers"):
  while building `kat_vectors.zig`, the 5 `shared_secrets` were recomputed
  from scratch in Python (the `ecdsa` PyPI package for secp256k1 point
  arithmetic only — no Lightning/Sphinx-specific code, no code shared with
  this Zig module or any Lightning implementation) by directly implementing
  BOLT#4's "Shared Secret" + "Blinding Ephemeral Onion Keys" formulas:
  `ss_i = SHA256(compress(pubkey_i * ek_i))`,
  `bf_i = SHA256(compress(G*ek_i) ++ ss_i)`, `ek_{i+1} = ek_i * bf_i mod n`,
  starting from `ek_0 = session_key`. All 5 outputs matched the spec's
  published `shared_secret` values byte-for-byte before being transcribed
  into `kat_vectors.zig`. This both confirms the doc's shared-secret →
  hop-index mapping (the source document walks hops in REVERSE, node 4
  down to node 0) and gives this module a from-scratch, non-Lightning
  cross-check of the BOLT#4 formula itself, independent of the spec text's
  own prose description.
- Exercised (`src/kat_test.zig`, zero skips): `OnionPacket.fromBytes`/
  `.toBytes()` round-trip on the official 1366-byte packet;
  `Secp256k1.basePoint.mul` re-derives all 5 published pubkeys from their
  published private keys (plain std, confirms the KAT data's internal
  consistency independent of this module's own code); the hop-0 shared
  secret recomputed directly against raw `std.crypto.ecc.Secp256k1` calls
  matches `kat_vectors.shared_secrets[0]` byte-exact (an std-only
  cross-check of `deriveHopSecrets`'s ECDH step); `bigsize.read` and
  `hopframe.shiftSize` match the vector's 5 real payload lengths (18, 82,
  18, 18, 272 bytes) exactly; `deriveHopSecrets` reproduces ALL 5
  published `shared_secrets`; `construct` reproduces the published
  1366-byte `onion` packet BYTE-EXACT; `process(node_privkeys[0], onion)`
  extracts `payloads[0]`'s TLV content with a non-null `next_packet`; a
  full `construct` → 5x `process` round-trip recovers every hop's TLV
  (each intermediate packet re-parsing as a valid wire packet, final hop
  flagged); and a 1-bit hmac tamper / wrong-node-key probe both fail
  closed with `error.IntegrityCheckFailed`. `core.zig` additionally tests
  its own error paths (`HopCountMismatch`, `ReservedPayloadLength`, both
  `RouteTooLong` forms, `InvalidPublicKey`).
- Both `zig build test-sphinx` (Debug) and `-Doptimize=ReleaseFast` pass
  in full, with no skips; the full repo `zig build test` is green;
  `zig fmt --check modules/sphinx/` is clean.
