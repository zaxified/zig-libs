# Changelog

Per-release changes, grouped by module. One semver for the whole collection
(policy: `CONVENTIONS.md` §8 — pre-1.0, a minor bump may break any module's
API; breaking changes are flagged **BREAKING**). Routine internal refactors
are not listed.

## Unreleased

The collection grew 77 → 148 modules since v0.1.0. Highlights, by area:

- **Pairing / elliptic-curve crypto:** the complete BLS12-381 arc (field tower,
  pairing, RFC 9380 hash-to-curve, BLS signatures, KZG/EIP-4844, threshold) +
  `bn254`, `bbs`, `coconut`, `tlock`, `ibe`; native `k256`/`p256` cores;
  `ed448`/`decaf448`; `montint` big-integer Montgomery arithmetic.
- **Bitcoin / Lightning:** `bip340` Schnorr, `taproot`, `musig2`, `frost`,
  `adaptor`, `sphinx` (BOLT#4), `bolt3`, `bolt8` (Noise_XK) — byte-exact
  against the BIP/BOLT vectors.
- **Post-quantum:** `slhdsa` (FIPS 205), `falcon` (FN-DSA), `hqc`, `xmss`.
- **FHE / ZK / MPC:** `bfv`, `tfhe`, `groth16`, `bulletproofs`, `paillier`,
  `threshold_ecdsa`, `dkg`, `fss`, `vdf`, `ecvrf`.
- **Protocol security:** `rsa`, `x509` path validation, `dnssec`, `ssh`
  (client + server transport), `opcua` (full client incl. SecureChannel),
  `dtls` 1.3 PSK, `quic-crypto` (RFC 9001), `tlsresume`, the `noise`
  framework, `hpke`, `mls`, `signal`, `opaque`/`voprf`, `spake2plus`,
  `ctap2pin`, `oscore`, `jwe`, `sealedbox`, `blindrsa`, `otp`.
- **Fabric / distributed:** `netsim` (deterministic DES + VOPR harness),
  `raft` (model-checked against the five safety properties), `spf-ect`,
  `loopfree-reconv`, `df-elect`, `liveness-hyst`, `loopix`, `lockfree`
  (MPMC queue + epoch reclamation), `ethfrag`, `kvtree` (COW B-tree).
- **Kernel / networking:** `ebpf` + `xdp-classifier`, `tc` (netem),
  `genetlink`, `wireguard`, `rawsock`, `stun`, `pping`, `sntp`, `dnp3`,
  `snmp` (v3/USM auth), `coap`, `mqtt`, `modbus`.
- **Performance campaign:** SIMD `chachapoly` (beats OpenSSL AVX2 keystream on
  the reference host), asm/Montgomery cores under `k256`/`p256`/`montint`;
  audited hot paths within ~≤3× of C peers; several constant-time leaks fixed.
- **Security audit (collection-wide):** all CRIT/HIGH findings fixed — memory
  safety in `dnssec`/`opcua`/`x509`/`stun`/`dnp3`, HTTP request-smuggling and
  `validate` O(n²)-DoS hardening, `dtls` anti-replay window, `zipstream`/
  `json5`/`mcp`/`csvsafe` fixes.
- **Tooling/docs:** `zig build check-catalog` consistency gate (found + fixed
  6 modules missing README catalog rows); versioning + spin-off policy
  (`CONVENTIONS.md` §8); this changelog.

Per-module API changes since v0.1.0 worth calling out:

- **`dtls`:** handshake-message reassembly across `handleFlight` calls (RFC
  9147 §5.2). A message split across datagrams — a certificate chain past
  the path MTU, in practice — is now buffered and reassembled by
  `fragment_offset` (never arrival order), tolerating out-of-order and
  duplicate fragments; `error.FragmentedMessageUnsupported` is gone.
  `HandshakeResult` gains `need_more_data` (defaulted, so existing
  construction sites are unaffected): while a flight is incomplete the
  connection is rolled back to its exact pre-call state, so a half-processed
  flight never leaves the state machine, transcript, key schedule or
  anti-replay windows half-advanced. The buffered bytes are unauthenticated
  at handshake time, so the surface is capped: 4 KiB per flight
  (`error.FlightTooLarge`), exactly one in-progress message
  (`error.InterleavedFragments`), and a fragment contradicting bytes already
  received is `error.OverlappingFragment` rather than overwriting them
  (byte-identical re-delivery stays legal). `handshake.Reassembler` also
  rejects a mid-message `msg_type` change (`error.InconsistentMessageType`).
  Certificate mode is no longer self-interop only: the live wolfSSL suite
  gains a PSK-less `.cert_dhe` handshake against a wolfSSL certificate
  server, plus the same handshake at a 256-byte peer MTU so the peer's
  Certificate really is fragmented. That found one more defect of the class
  only a third party can find — the `.cert_dhe` ClientHello carried no
  `supported_versions`, so a real DTLS 1.3 server negotiated 1.2.
  Sending is still single-fragment.
- **`x509`:** new `x509.spkiOf(certificate_der)` → `x509.Spki` — a
  certificate's `SubjectPublicKeyInfo` (full TLV + algorithm OID + parameters
  + key bits) extracted over the defensive `safe.zig` walk, never through
  `std.crypto.Certificate.parse`. Every returned slice borrows the caller's
  buffer. Works on RSASSA-PSS-signed certificates, which std cannot parse at
  all. Adds `safe.oid_*` OID constants.
- **`saml`:** Holder-of-Key subject confirmation now performs **cross-form**
  matching (an `<ds:X509Certificate>` confirmation against a configured bare
  `presented_holder_key`, and a `<ds:KeyValue>` confirmation against a
  configured `presented_holder_cert_der`) over `x509.spkiOf`, comparing key
  parameters — RSA modulus/exponent, P-256 affine point — never encodings.
  **BREAKING (behavioral, not signature):** pairings that previously always
  returned `error.HolderOfKeyCrossFormUnsupported` can now confirm a subject,
  and that error's meaning narrows to "key material was named but none of it
  could be reduced to a comparable key". Same-form matching, and every
  non-HoK path, are unchanged. New sibling dependency: `x509`.
- **`fss`:** `Dpf.evalFull` / `evalFullWith` — one tree traversal that emits
  every leaf, instead of re-walking the tree from the root per point. Cost
  drops from `O(N log N)` PRG calls to `O(N)`: measured **570 ms → 52 ms**
  (~10.9×) for a full 2^16 domain, matching the `(2n+1)/3` prediction. It
  fills a **prefix**, not only a whole domain — `pir`'s server evaluates
  `x < database.count()` and domains are routinely provisioned far larger
  than the current record count, so a full-domain-only evaluator would have
  been a regression for the common case. Subtrees past the requested prefix
  are pruned **before** the PRG call, so an oversized domain costs nothing:
  a 500-point prefix of a 2^20 domain is **5.1 ms → 0.36 ms**. The streaming
  form exists because `pir` has no allocator and no runtime-sized scratch —
  it lets the server fold each value into its accumulator as the walk
  produces it, leaving `answer`/`answerSlices` signatures untouched.
  `evalAll` is deliberately left naive, as a structurally independent
  differential oracle. Both `pir`'s value channel and `Verified`'s tag
  channel are wired to it.
- **`fss`:** `Mpf.evalEachFullWith` / `evalFullWith` / `evalFull` — the
  multi-point counterpart, and the interleaved walk the `Dpf.evalFull` entry
  above recorded as the right answer for `Multi(k)`. ONE descent of the
  domain prefix carries all `k` tree states side by side and emits every
  instance's share at each index, instead of `k` per-point evaluations
  (`k·N·n` PRG calls) or `k` separate prefix walks (which would have turned
  one pass over the consumer's data into `k`). Cost per index drops from
  `k·n` PRG calls to `~k`: measured **495 ms → 52 ms** (~9.5×) for a full
  2^14 domain at `k=4`, and **43.1 ms → 3.0 ms** (~14×) for a 500-point
  prefix of a 2^20 domain at `k=8`. Same construction, same keys, same
  outputs — a traversal-order change only, with the sum-of-`k`-DPFs
  construction and its `k·N` evaluation count untouched (the cuckoo/batch-code
  alternative stays scoped out). `evalEach` stays naive as the differential
  oracle, and the walk's index-range-only pruning keeps the emission sequence
  a function of the prefix length alone.
- **`pir`:** keyword lookup — `keywordIndex` / `queryKeyword`, also under
  `Verified`. `queryKeyword` is literally `query(keywordIndex(kw), …)`, and
  that is the point: the map is total, deterministic and unconditional
  (`LE64(SHA-256(kw)[0..8])` masked to the domain — a mask, not a modulo, so
  no reduction bias, since domains are powers of two), so **a query for a
  missing keyword is byte- and shape-identical to one for a present
  keyword**. Presence never enters the computation, so it cannot leave it.
  That guarantee carries a caller obligation stated in the README and at the
  call site, not buried in SPEC: **one lookup, one query, whatever comes
  back**. A client that consults a local set and skips the query, or retries
  on a mismatch, puts the presence bit back on the wire — a test demonstrates
  exactly that wrapper's leak. Collisions are a **correctness** cost, never a
  privacy one: two keywords may share a slot and the loser becomes a false
  negative discovered locally, with the provisioning rule
  `domain_bits >= 2·log2(N) + log2(1/eps) − 1` given for sizing. Under
  `Verified`, a keyword whose slot lies past the database **rejects**, so
  "absent" and "the server lied" are indistinguishable there — a deployment
  wanting verifiable absence must materialise every slot. A published
  key→index map was rejected because it needs the same always-query
  discipline *plus* a distribution and freshness pipeline this
  no-I/O module cannot provide; cuckoo/batch codes stay rejected, and would
  compose above this layer rather than replace it.
- **`pir`:** malicious-server detection (`Verified(...)`). The module's model
  was honest-but-curious: a server learned nothing about the index but was
  assumed to answer honestly, so a doctored share made the client silently
  reconstruct a wrong record. It now runs a second DPF for the same index
  whose payload is a **client-secret odd scalar `m`**, so the tag answer is
  `m·word` by the protocol's own linearity, checked in a widened ring
  (SPDZ2k-style) together with a presence word. No new dependency: the tag
  key is one more DPF key under the same hiding.
  The security statement, stated exactly because over-claiming here would be
  worse than not building it: **detection, not robustness** — the client
  aborts with `error.AnswerRejected`, does not recover the record and cannot
  say which server lied. Any record-changing deviation by ONE server (or by
  both, if they do not pool keys) is caught except with probability
  `≤ 2^(1−8S) + Adv_PRG`, a function of `tag_slack_bytes` alone (2^−63 at the
  default). **Colluding servers forge undetectably** — the same full-domain
  scan that recovers the index recovers `m` — and **two servers holding the
  same wrong database are accepted**, since the MAC binds to the servers'
  common data rather than to a published digest. Both are asserted as
  `ATTACK NOT CAUGHT` tests, not left implicit. Privacy is unchanged, and the
  abort verdict is index-independent, so the check adds no selective-failure
  oracle. `S = 0` is a `@compileError`: in the un-widened ring
  `m·2^(8L−1) = 2^(8L−1)` for every odd `m`, so a top-bit forgery would pass
  with probability 1. Querying past the database now **rejects** rather than
  reconstructing to zero, because an honest all-zero answer is
  indistinguishable from the coordinated-zeroing forgery the presence word
  exists to stop. Authenticated PIR against a published digest (Colombo et
  al.) is the composable upgrade and is named as such; cross-checking by
  repetition was rejected outright, since a server adding the same constant
  every time produces identical wrong reconstructions.
- **`rescue`:** new module — Rescue-Prime Optimized (RPO) over Goldilocks
  `p = 2^64 − 2^32 + 1`, at both published instances (`m = 12`, `m = 16`),
  both sponge framings that exist upstream, and the paper's round order as a
  separate permutation. The sibling to `poseidon`: same motivation (cheap
  inside a circuit), opposite trade — Rescue alternates `x^α` with `x^(1/α)`,
  which is far more expensive in software and cheaper to prove. Measured
  here: the inverse S-box layer is **15× the forward one and 76% of the whole
  permutation**; hashing 512 bytes costs 61× SHA-256. The field lives inside
  the module (~240 lines, canonical, branch-free) rather than becoming a new
  general-purpose module.
  **The variant was chosen on anchoring, not deployment**: plain Rescue-Prime's
  reference implementation publishes **no** test vectors, while RPO publishes
  38. Constants are derived (SHAKE256) and pinned element-by-element against
  miden-crypto's embedded values; `1/α` is computed and checked three ways,
  including replaying its 72-multiply addition chain symbolically over
  exponents. Three upstream divergences are documented rather than smoothed
  over: miden-crypto changed its state layout in a `[BREAKING]` PR so every
  digest changed (a single-value test tells the corpora apart); the two RPO
  sponges disagree on padding, capacity placement and the empty input, so
  both ship with a test asserting they never collide; and **Winterfell's
  Rescue-XLIX round constants could not be re-derived** from the generator
  its own comment cites, so that one table is an honestly-labelled embedded
  blob pinned by file digest plus the published KAT — while the same
  generator reproduces miden's RPO tables exactly. Constant-time throughout
  (the inverse S-box is a fixed addition chain, not a ladder), not
  disassembly-verified. Byte-level hashing is grade-2 anchored: no upstream
  byte KAT exists anywhere in miden-crypto.
- **`megolm`:** new module — Matrix's Megolm group ratchet, the third
  real-world group-messaging construction here alongside `signal` (pairwise
  Double Ratchet) and `mls` (RFC 9420). A one-way four-part HMAC-SHA-256 hash
  ratchet that fast-forwards to any future index but never rewinds, plus
  Ed25519 signatures over the message frame; `OutboundSession` /
  `InboundGroupSession` and the exact session-sharing, session-export and
  message wire formats. The cipher is not a choice: the spec mandates
  AES-256-CBC/PKCS#7 + HMAC-SHA-256 truncated to 8 bytes, taken from the
  sibling `aescbc`. `decrypt` separates four failure causes into distinct
  typed errors (`InvalidSignature`, `MessageIndexTooOld`, `InvalidMac`,
  `InvalidPadding`) and verifies signature → MAC → padding in that order, so
  the padding check is unreachable without a valid MAC. Byte-exact against
  libolm's own `test_megolm.cpp` ratchet vectors — including the 2^24/2^16/2^8
  boundary crossings and the 32-bit counter wraparound — and a real
  libolm-produced session-key + message pair from `test_group_session.cpp`,
  independently re-derived end to end with a separate Python toolchain
  (PyNaCl + `cryptography` + stdlib `hmac`) as a non-libolm cross-check. The
  ratchet advance is a cascade, not a per-part rehash: crossing a boundary
  rehashes the crossed part and everything to its right **from the same
  pre-update value** — implementing it as an independent per-part rehash
  still round-trips, and is caught only by a boundary-crossing vector. Olm,
  the Matrix event-JSON layer and key backup are out of scope.
- **`poseidon`:** new module — the Poseidon ZK-friendly hash over `bn254`
  (circomlib's parameters, `t = 2..17`) and `bls12_381` (the authors'
  `poseidonperm_x5_255_{3,5}`). `groth16` and `bulletproofs` had no hash that
  is cheap *inside* a circuit, which left the ZK domain half-covered: SHA-256
  costs tens of thousands of constraints where Poseidon costs a few hundred.
  Field arithmetic is reused unchanged from the sibling curve modules.
  Round constants and MDS matrices are **derived** by a port of the authors'
  Grain-LFSR generator rather than embedded (~700 KB of hex avoided), and
  pinned by SHA-256 digests over the upstream constant files so a generator
  drift is distinguishable from a permutation bug. Anchored byte-exactly
  against the authors' own `hadeshash` `test_vectors.txt` (all four GF(p)
  instances, every output word), circomlibjs's published known answers, and a
  full `t = 2..17` sweep produced by *executing* circomlibjs's reference and
  optimized implementations and requiring them to agree.
  Two deployment realities are followed over the paper and documented:
  circomlib rounds `R_P` up to a multiple of `t`, and it ships Poseidon twice
  (a folded/optimized form storing the MDS transposed, and the reference
  form) — this implements the reference form, byte-compatible with both.
  **Boundaries stated rather than glossed:** the generator's MDS
  security checks (`algorithm_1/2/3`) are not re-implemented, which is sound
  only because every shipped parameter set accepts its first candidate — a
  fact proven by matching all 18 upstream tables, not assumed — so this code
  **cannot be pointed at a new `(n, t, R_F, R_P)` and trusted** without
  running the sage script alongside. The permutation is constant-time
  (fixed bounds, no data-dependent branch or index) but not
  disassembly-verified, unlike `k256`/`montint`; parameter derivation is not
  constant-time and consumes only public inputs. On BLS12-381 only the
  permutation is anchored — the `hash`/`compress` framing has no deployed
  counterpart on that field and differs from `neptune`/dusk/arkworks, which
  is flagged at the call site. Variable-length sponge, Poseidon2 and
  Rescue/Rescue-Prime are out of scope; Rescue is named as the follow-up.
- **`mls`:** external Commits (RFC 9420 §12.4.3.2) — joining a group **without
  an invitation**. Until now the only way in was a Welcome, which requires an
  existing member to have added you; an external Commit lets a newcomer join
  from a published `GroupInfo` alone. New `Group.joinByExternalCommit`
  (sender) and a `new_member_commit` branch through `processCommit`
  (receiver), plus `tree.RatchetTree.assignBlankLeaf` — the leftmost blank
  leaf, expanding right per §7.7 when there is none, which is the one step
  sender and receiver must compute identically and independently.
  `createCommit` is now a wrapper over a shared `commitInner`, so the regular
  and external paths cannot drift apart. §12.2's second validation procedure
  is a genuine whitelist (exactly one ExternalInit, at most one Remove, PSKs,
  nothing else) rather than the regular Commit's blacklist, and §8.3's
  external `init_secret` replaces the previous epoch's on both sides.
  Two receiver-enforced rules live in §12.4.3.2 rather than §12.2 and are
  easy to miss when building the whitelist from §12.2 alone: "the Commit MUST
  NOT include any proposals by reference" (`error.ProposalByReference
  InExternalCommit`) and "External Commits MUST contain a path field"
  (`error.ExternalCommitRequiresPath`). The second coincides with §12.4's
  `needs_path` today but is independent of it, and only the path rule is
  unconditional — so the distinct error is pinned by its own test, or the
  unconditional rule would quietly become an accident of proposal typing.
  **There is no upstream external-Commit test vector**, so this lands
  round-trip-anchored: a stranger joins from a published `GroupInfo`, every
  existing member processes the Commit, all three reach the same
  `epoch_authenticator` by opposite halves of §8.3, and the newcomer then
  commits again. Reject tests **re-sign** a real external Commit with the
  joiner's own key after spoiling it, which is what an attacker can actually
  do — §6.1 verifies a `new_member_commit` with the key carried inside the
  message — so they reach §12.4.2's validation rather than failing earlier on
  the signature. Not covered: resumption PSKs in an external join
  (`error.PskNotAvailable` — there is no history to resolve against), and
  resync where the receiver is the member being removed.
- **`dtls`:** **serving** a HelloRetryRequest — RFC 9147 §5.1's stateless
  return-routability check, the other half of the exchange. Until now this
  module's server answered a first ClientHello with a full flight, which
  §5.1 names as an amplification vector: forge a victim's source address,
  send a small ClientHello, and the server sprays a much larger flight at the
  victim. New `Config.hello_retry` (`HelloRetryConfig`) turns the check on;
  `null` (the default) keeps every existing caller byte-for-byte unchanged,
  though it is **not** the posture §5.1 recommends for anything
  internet-facing.
  A cookie-less ClientHello now gets a HelloRetryRequest and the server keeps
  **nothing** — no transcript, no state transition, no cached flight, and no
  PSK-binder verification, so an unverified address costs one HMAC rather
  than a flight or a key schedule. ClientHello2 is finished by a *brand-new*
  `Connection` reconstructing everything from the cookie: RFC 8446 §4.4.1's
  `message_hash` rewrite plus a byte-exact re-encoding of the server's own
  HelloRetryRequest. The cookie is
  `HMAC-SHA256(cookie_secret, label || peer_binding || version ||
  cipher_suite || Hash(ClientHello1))`, checked with
  `std.crypto.timing_safe.eql`; the new `error.CookieVerifyFailed` covers
  every rejection cause without distinguishing them.
  `HelloRetryConfig.peer_binding` is **caller-supplied** because the module
  never touches a socket — the peer's address is an input, like
  `Config.now_sec` and the `std.Random` arguments — and an empty one is
  `error.EmptyPeerBinding` rather than a documented footgun, since a cookie
  bound to nothing verifies from anywhere while still looking like a cookie.
  Proven against a stock wolfSSL client, with the test structured so that
  statelessness is what makes it pass. **Behavioral fix on the way through:**
  the ServerHello no longer echoes the client's `legacy_session_id` — RFC
  9147 §5 forbids it ("DTLS servers MUST NOT echo the 'legacy_session_id'
  value from the client"; DTLS has no TLS 1.3 compatibility mode). No DTLS
  1.3 peer is affected, since such a client sends a zero-length one.
- **`dtls`:** HelloRetryRequest (RFC 8446 §4.1.4 / RFC 9147 §5.3), client
  side. A stock DTLS 1.3 server answers the first ClientHello with a cookie
  and refuses to proceed until it comes back — return-routability without
  server state — so until now this module could not complete a handshake
  against a default-configured peer at all. `handleFlight` on a client now
  answers an HRR with ClientHello2: the cookie echoed, ClientHello1's
  `random` reused (RFC 8446 §4.1.2 does not list it among the permitted
  changes), a fresh binder, and a new `message_seq` (it is a new message,
  not a retransmission). A second HRR is refused (§4.1.4) so a server cannot
  hold a client in a retry loop. New `Transcript.resetToMessageHash`
  implements §4.4.1's rewrite — ClientHello1 is replaced by a synthetic
  `message_hash` message carrying its hash, which is what lets a stateless
  server rebuild the transcript from its own cookie. Proven against a
  default-configured wolfSSL server (`server-hrr` peer mode), and the test
  asserts the retry actually happened rather than trusting the peer to send
  one. The rewrite is exactly the kind of thing only a live peer can check:
  replacing it with the naive "CH1 || HRR || CH2" leaves every self-interop
  test green and fails only the live test. (Serving an HRR was still missing
  at this point; the entry above closes that half.)
  `error.HelloRetryRequestUnsupported` narrows to the two cases that remain
  (an HRR in `.cert_dhe` mode, or one carrying nothing to change). New
  `Connection.sawHelloRetryRequest`.
- **`dtls`:** live third-party interop, and the four wire defects it exposed.
  `src/wolfssl_interop.zig` runs a real DTLS 1.3 PSK handshake over loopback
  UDP against **wolfSSL 5.9.1** in both roles (our client vs its server, our
  server vs its client), each with an application-data round trip; the peer
  is a small C program embedded in the test and compiled by `cc` at test
  time, skipping loudly when `cc` or wolfSSL is absent. Everything before
  this was self-interop, which by construction cannot catch a misreading
  both sides share — and four such defects were live:
  **(1)** the ClientHello omitted DTLS's `legacy_cookie` field entirely (RFC
  9147 §5.3 keeps it, present and empty); **(2)** the PSK binder was computed
  over a transcript two bytes too long — RFC 8446 §4.2.11.2 truncates before
  the binders *list*, whose own 2-byte length prefix was being left in;
  **(3)** neither Hello carried `supported_versions`, so nothing on the wire
  ever said DTLS 1.3; **(4)** the server sent no RFC 9147 §7 ACK for the
  client's final flight — the one flight §7.1 excludes from implicit
  acknowledgement — leaving a conforming client blocked forever.
  **BREAKING (wire):** (1)–(4) all change the bytes this module sends and the
  transcript it hashes, so a peer built from an older revision no longer
  interoperates with this one; the binder change in particular makes the
  mismatch surface as a handshake failure, not silent corruption. **BREAKING
  (API):** `SendError` gains `ReceivedAck` and `ReceivedPostHandshakeMessage`
  — `recv` used to call an ACK or a NewSessionTicket `error.Malformed`, and
  a real peer sends both on the application epoch. `HandshakeError` gains
  `VersionNotNegotiated`/`UnsupportedVersion`: the client now *requires*
  `supported_versions` in the ServerHello and rejects any selection other
  than DTLS 1.3, which is a downgrade guard, not only a compatibility fix.
  Separately, a peer's `signature_algorithms` list is now filtered against
  the schemes this module can select (new `messages.filterU16ListExtension`)
  instead of being decoded whole into a `[8]u16` — wolfSSL advertises 18 and
  OpenSSL a similar number, so every real client was being rejected with
  `error.Malformed`. Documented in `SPEC.md`, including the correction that
  its own oracle ranking was wrong: OpenSSL 3.5.5 and GnuTLS 3.8.12 have no
  DTLS 1.3 at all, which is why "no peer exists" sat in the backlog until
  someone checked what was installable.
- **`dtls`:** `signature_algorithms` is now genuinely negotiated instead of
  advertised-and-ignored. New `Config.signature_algorithms` drives both what
  this side offers and what it will accept; the scheme used to sign
  CertificateVerify is chosen from peer-advertised ∩ self-permitted ∩
  key-producible. A peer signing with a scheme we never advertised is
  rejected (`error.SignatureSchemeNotAdvertised`); an empty intersection
  fails the handshake (`error.NoSignatureSchemeOverlap`). The PSK-mode
  ClientHello now advertises the extension at all (RFC 8446 §9.2 makes it
  mandatory; it was omitted), and the server's `CertificateRequest` carries
  it. **BREAKING:** `CertConfig.signature_scheme` is removed — the scheme is
  negotiated, no longer configured. New `certverify.candidateSchemes`.
- **`snmp`:** the USM privacy salt (`msgPrivacyParameters`) is now generated by
  the library instead of being a caller obligation. **BREAKING:**
  `priv.encrypt` no longer takes a salt — it takes a `priv.SaltSource` and
  returns `priv.Encrypted { ciphertext, salt }`, the salt being an *output* for
  the USM header. The default `SaltSource.counter(seed)` is a never-repeating
  counter shaped per RFC 3826 §3.3.1 (AES) / RFC 3414 §8.1.1.1 (DES), so no
  call shape can repeat a salt on live traffic; pinning one for a published KAT
  or a captured datagram is the explicit opt-in `SaltSource.fixedForInterop`.
  New errors `error.SaltReuse` (an IV identical to the immediately preceding
  one — an adjacent-repeat tripwire, not full history) and
  `error.SaltExhausted` (DES has only 2^32 salts per `snmpEngineBoots` epoch;
  it refuses rather than wrapping). **BREAKING:** `V3Client.Options.initial_salt`
  is now `?u64`, defaulting to `null` = seed the counter from the engine's
  discovered `engineBoots‖engineTime`, so a client restart does not resume the
  counter from a fixed constant. `priv.decrypt` is unchanged (its salt comes off
  the wire). Scope and limits documented in `modules/snmp/SPEC.md`.
- **`hpke`:** `mode_psk`, `mode_auth` and `mode_auth_psk` are now anchored to
  RFC 9180's own Appendix A vectors (A.1.2/3/4 for X25519, A.3.2/3/4 for
  P-256) instead of only to this module's round-trip; the implementations
  needed no correction. New single-shot wrappers `sealPsk`/`openPsk`,
  `sealAuth`/`openAuth`, `sealAuthPsk`/`openAuthPsk` alongside the existing
  `sealBase`/`openBase`. **BREAKING (behavioral):** a psk-bearing mode now
  rejects a PSK shorter than `Nh` with `error.PskTooShort` — deliberately
  stricter than the RFC's `VerifyPSKInputs` pseudocode, on the grounds that
  §5.1.2's "MUST have at least 32 bytes of entropy" cannot hold for a PSK
  shorter than 32 bytes, and length is the only checkable projection of that
  requirement. Appendix A's own PSK vectors satisfy the floor.
- **`k256`:** new `k256.ecdsa_recover` — RFC 6979 deterministic-nonce ECDSA
  signing and public-key recovery (`Q = r⁻¹(sR − eG)`), moved here from
  `lninvoice`, which had implemented them locally because `k256` shipped only
  Schnorr and ECDSA *verify*. `lninvoice` re-exports them, so its callers are
  unaffected; the algorithm is unchanged.
- **`bip340`:** new `taggedHashRuntime`/`taggedHasherRuntime` — the BIP-340
  tagged hash with a **runtime** tag assembled from parts, for callers whose
  tag is not comptime-known (BOLT#12's nonce leaf, BIP-341 leaf hashes). The
  comptime `taggedHash`/`taggedHasher` remain the fast path. New
  `xonlyBytesOf` (33-byte compressed → 32-byte x-only), also moved out of
  `lninvoice`.
- **`minisign`:** new module — sign/verify in the minisign file format over
  Ed25519, both legacy (`Ed`) and prehashed-BLAKE2b (`ED`), including
  scrypt-encrypted secret keys and the trusted-comment global signature.
  Byte-exact against artifacts produced by the reference `minisign` binary.
- **`threshold_ecdsa`:** the GG18 Appendix-A Fiat-Shamir transcripts now bind
  the Paillier **generator** `Γ`, not only the modulus `N` (audit F3 — an
  unbound public value in the verification equation is a value a prover can
  still vary after the challenge is fixed). A companion fail-closed check,
  `root.paillierGeneratorIsStandard`, rejects any received Paillier key whose
  `Γ != N+1` at every prove and verify entry point, alongside the existing
  F1/F2 gates. **BREAKING (wire):** absorbing a new value changes every
  challenge, so proofs minted before this change do not verify after it; the
  three Fiat-Shamir domain tags were bumped `…/v1` → `…/v2` so the break
  surfaces as a plain verification failure. No interop is affected — these
  proofs were never byte-compatible with any other implementation.

## v0.1.0 — 2026-07-10

Initial public release: 77 modules, 1844 tests, CI green in Debug +
ReleaseFast, MIT (fping-lineage attribution preserved in `NOTICE` §1).
