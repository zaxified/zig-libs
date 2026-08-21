# dtls — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-21** — **Breaking (in the direction of working):** `Config.cipher_suites` now
  defaults to `.aes_128_gcm_sha256`, and `Config.validate` rejects any suite this module
  cannot install keys for with the new `ConfigError.UnsupportedSuite`. The old default was
  `.aes_128_ccm_8_sha256` — the CoAP profile's choice, and so the one a consumer was most
  likely to inherit by omission — but `suiteParams` returns null for both CCM suites because
  Zig 0.16's std ships only a 13-byte-nonce CCM. That config passed `validate`, completed a
  handshake, and only then failed at `installApplicationKeys`. Nothing can have depended on
  the old default: it could never complete a connection. Found by writing `example/main.zig`.

- **2026-08-12** — **BREAKING:** `startHandshake` and `handleFlight` take a `dtls.Entropy`
  instead of a `std.Random`. `Entropy` is a two-armed tagged union —
  `.csprng` (production) and `.seeded_for_test` — so the entropy choice is
  written out at every call site instead of being whatever generator the caller
  had in scope. Migration is mechanical: `conn.startHandshake(rnd, …)` becomes
  `conn.startHandshake(.{ .csprng = rnd }, …)`.

  The documentation-only pass below said what a seeded generator costs (the
  x25519 / secp256r1 ephemeral PRIVATE key is a function of the seed, so anyone
  who learns it decrypts every recorded session retroactively) but left the weak
  path as the ONLY path. It is now a variant a caller has to name. This is not a
  detector — `std.Random` is still a vtable and this module still cannot judge
  what is inside either arm; naming `.csprng` is an assertion, and the union
  makes it a deliberate one rather than an accident. `std.Io` remains refused:
  `Connection` is a sans-I/O state machine and a capability handle threaded
  through a per-datagram entry point would contradict that, while a union is a
  value and costs the invariant nothing. `Entropy` is threaded to
  `ecdheGenerate` and to every internal step that draws bytes; the arm is erased
  only at the leaves. A new test pins that the type has exactly two arms, that
  they are distinct, and that both carry `std.Random`.

- **2026-08-12** — The `std.Random` requirement is now stated, not implied *(superseded by the
  entry above, which turned the statement into a type — the "no signature
  changed" note below was true of this pass only)*. `startHandshake`,
  `handleFlight` and `ecdheGenerate` said only *why* the parameter exists
  ("std 0.16 removed `std.crypto.random`") — a migration note a consumer reads
  as "any `std.Random` will do", and `DefaultPrng` is what std's own examples
  show. Those calls draw the x25519 / secp256r1 ephemeral PRIVATE key: under a
  seeded generator a passive eavesdropper who learns the seed recomputes the
  (EC)DHE shared secret and decrypts every recorded session from that peer,
  retroactively. Each entry point now carries the `jwt`/`jwe` sentence
  ("`random` MUST be a cryptographically secure source") together with what
  breaks, and `README.md` / `root.zig` gained a Randomness section.

  **No signature changed and no behaviour changed** — this is documentation.
  The mistake is still expressible and this module still cannot detect it
  (`std.Random` is a vtable). Converting to `std.Io` was considered and
  rejected: `Connection` is a sans-I/O state machine (no socket, no clock, no
  allocator — every external fact is an input value) and `handleFlight` is the
  only way to drive it, so an I/O capability handle per datagram contradicts
  the design. Two tests pin the outcome: one demonstrates the seeded-RNG
  hazard is real (same seed ⇒ byte-identical ephemeral private key), one
  asserts the sentence is present at each of the three declarations.

- **2026-07-28** — `signature_algorithms` is now genuinely negotiated instead of
  advertised-and-ignored. New `Config.signature_algorithms` drives both
  what this side offers and what it will accept; the scheme used to sign
  CertificateVerify is chosen from peer-advertised ∩ self-permitted ∩
  key-producible. A peer signing with a scheme we never advertised is
  rejected (`error.SignatureSchemeNotAdvertised`); an empty intersection
  fails the handshake (`error.NoSignatureSchemeOverlap`). The PSK-mode
  ClientHello now advertises the extension at all (RFC 8446 §9.2 makes it
  mandatory; it was omitted), and the server's `CertificateRequest`
  carries it. **BREAKING:** `CertConfig.signature_scheme` is removed — the
  scheme is negotiated, no longer configured. New
  `certverify.candidateSchemes`.

- **2026-07-29** — Live third-party interop, and the four wire defects it exposed.
  `src/wolfssl_interop.zig` runs a real DTLS 1.3 PSK handshake over
  loopback UDP against **wolfSSL 5.9.1** in both roles (our client vs its
  server, our server vs its client), each with an application-data round
  trip; the peer is a small C program embedded in the test and compiled
  by `cc` at test time, skipping loudly when `cc` or wolfSSL is absent.
  Everything before this was self-interop, which by construction cannot
  catch a misreading both sides share — and four such defects were live:
  **(1)** the ClientHello omitted DTLS's `legacy_cookie` field entirely
  (RFC 9147 §5.3 keeps it, present and empty); **(2)** the PSK binder was
  computed over a transcript two bytes too long — RFC 8446 §4.2.11.2
  truncates before the binders *list*, whose own 2-byte length prefix was
  being left in; **(3)** neither Hello carried `supported_versions`, so
  nothing on the wire ever said DTLS 1.3; **(4)** the server sent no RFC
  9147 §7 ACK for the client's final flight — the one flight §7.1
  excludes from implicit acknowledgement — leaving a conforming client
  blocked forever. **BREAKING (wire):** (1)-(4) all change the bytes this
  module sends and the transcript it hashes, so a peer built from an
  older revision no longer interoperates with this one; the binder change
  in particular makes the mismatch surface as a handshake failure, not
  silent corruption. **BREAKING (API):** `SendError` gains `ReceivedAck`
  and `ReceivedPostHandshakeMessage` — `recv` used to call an ACK or a
  NewSessionTicket `error.Malformed`, and a real peer sends both on the
  application epoch. `HandshakeError` gains
  `VersionNotNegotiated`/`UnsupportedVersion`: the client now *requires*
  `supported_versions` in the ServerHello and rejects any selection other
  than DTLS 1.3, which is a downgrade guard, not only a compatibility
  fix. Separately, a peer's `signature_algorithms` list is now filtered
  against the schemes this module can select (new
  `messages.filterU16ListExtension`) instead of being decoded whole into
  a `[8]u16` — wolfSSL advertises 18 and OpenSSL a similar number, so
  every real client was being rejected with `error.Malformed`.
  Documented in `SPEC.md`, including the correction that its own oracle
  ranking was wrong: OpenSSL 3.5.5 and GnuTLS 3.8.12 have no DTLS 1.3 at
  all, which is why "no peer exists" sat in the backlog until someone
  checked what was installable.

- **2026-07-29** — HelloRetryRequest (RFC 8446 §4.1.4 / RFC 9147 §5.3), client side. A
  stock DTLS 1.3 server answers the first ClientHello with a cookie and
  refuses to proceed until it comes back — return-routability without
  server state — so until now this module could not complete a handshake
  against a default-configured peer at all. `handleFlight` on a client
  now answers an HRR with ClientHello2: the cookie echoed, ClientHello1's
  `random` reused (RFC 8446 §4.1.2 does not list it among the permitted
  changes), a fresh binder, and a new `message_seq` (it is a new message,
  not a retransmission). A second HRR is refused (§4.1.4) so a server
  cannot hold a client in a retry loop. New
  `Transcript.resetToMessageHash` implements §4.4.1's rewrite —
  ClientHello1 is replaced by a synthetic `message_hash` message carrying
  its hash, which is what lets a stateless server rebuild the transcript
  from its own cookie. Proven against a default-configured wolfSSL server
  (`server-hrr` peer mode), and the test asserts the retry actually
  happened rather than trusting the peer to send one. The rewrite is
  exactly the kind of thing only a live peer can check: replacing it with
  the naive "CH1 || HRR || CH2" leaves every self-interop test green and
  fails only the live test. (Serving an HRR was still missing at this
  point; the entry below closes that half.) **BEHAVIOURAL, not
  breaking:** `error.HelloRetryRequestUnsupported` narrows to the two
  cases that remain (an HRR in `.cert_dhe` mode, or one carrying nothing
  to change). **What changes for a consumer:** a PSK handshake against a
  default-configured server used to end in that error — it could not
  complete at all — and now completes after a second ClientHello, so a
  caller branching on the error takes a different path and two flights go
  out where one did. The error stays a member of `HandshakeError`
  (nothing stops compiling), no previously-successful handshake changes,
  and the retry is authenticated exactly as before — a second HRR is
  refused, so no trust boundary moves. New
  `Connection.sawHelloRetryRequest`.

- **2026-07-29** — **Serving** a HelloRetryRequest — RFC 9147 §5.1's stateless
  return-routability check, the other half of the exchange. Until now
  this module's server answered a first ClientHello with a full flight,
  which §5.1 names as an amplification vector: forge a victim's source
  address, send a small ClientHello, and the server sprays a much larger
  flight at the victim. New `Config.hello_retry` (`HelloRetryConfig`)
  turns the check on; `null` (the default) keeps every existing caller
  byte-for-byte unchanged, though it is **not** the posture §5.1
  recommends for anything internet-facing. A cookie-less ClientHello now
  gets a HelloRetryRequest and the server keeps **nothing** — no
  transcript, no state transition, no cached flight, and no PSK-binder
  verification, so an unverified address costs one HMAC rather than a
  flight or a key schedule. ClientHello2 is finished by a *brand-new*
  `Connection` reconstructing everything from the cookie: RFC 8446
  §4.4.1's `message_hash` rewrite plus a byte-exact re-encoding of the
  server's own HelloRetryRequest. The cookie is `HMAC-SHA256
  (cookie_secret, label || peer_binding || version || cipher_suite ||
  Hash(ClientHello1))`, checked with `std.crypto.timing_safe.eql`; the
  new `error.CookieVerifyFailed` covers every rejection cause without
  distinguishing them. **BREAKING (API):** that error joins the declared
  `HandshakeError`, and `ConfigError` gains `EmptyCookieSecret` and
  `EmptyPeerBinding` — **what a consumer must change:** an exhaustive
  `switch` over either set has to handle the new members before it
  compiles again; a `catch |e| switch (e) { … else => }` and every
  `hello_retry = null` caller are otherwise untouched, since the feature
  itself is opt-in. `HelloRetryConfig.peer_binding` is
  **caller-supplied** because the module never touches a socket — the
  peer's address is an input, like `Config.now_sec` and the
  `std.Random` arguments — and an empty one is `error.EmptyPeerBinding`
  rather than a documented footgun, since a cookie bound to nothing
  verifies from anywhere while still looking like a cookie. Proven
  against a stock wolfSSL client, with the test structured so that
  statelessness is what makes it pass. **Behavioral fix on the way
  through:** the ServerHello no longer echoes the client's
  `legacy_session_id` — RFC 9147 §5 forbids it ("DTLS servers MUST NOT
  echo the 'legacy_session_id' value from the client"; DTLS has no TLS
  1.3 compatibility mode). No DTLS 1.3 peer is affected, since such a
  client sends a zero-length one.

- **2026-07-29** — Handshake-message reassembly across `handleFlight` calls (RFC 9147
  §5.2). A message split across datagrams — a certificate chain past the
  path MTU, in practice — is now buffered and reassembled by
  `fragment_offset` (never arrival order), tolerating out-of-order and
  duplicate fragments. **BREAKING (API):** `HandshakeError` **loses**
  `FragmentedMessageUnsupported` and gains `FlightIncomplete`,
  `FlightTooLarge` and `InterleavedFragments`; `handshake.ReassembleError`
  — which `HandshakeError` includes — gains `InconsistentMessageType` and
  `OverlappingFragment`. Both sets are declared, so **what a consumer must
  change:** any `switch` prong naming `error.FragmentedMessageUnsupported`
  has to go, and it stops compiling even with an `else` (a prong naming a
  non-member is a type error, not dead code); an exhaustive `switch` must
  also handle the five new members. A `catch |e| switch (e) { … else => }`
  that never named the removed error is unaffected.
  `HandshakeResult` gains `need_more_data` (defaulted, so
  existing construction sites are unaffected): while a flight is
  incomplete the connection is rolled back to its exact pre-call state,
  so a half-processed flight never leaves the state machine, transcript,
  key schedule or anti-replay windows half-advanced. The buffered bytes
  are unauthenticated at handshake time, so the surface is capped: 4 KiB
  per flight (`error.FlightTooLarge`), exactly one in-progress message
  (`error.InterleavedFragments`), and a fragment contradicting bytes
  already received is `error.OverlappingFragment` rather than
  overwriting them (byte-identical re-delivery stays legal).
  `handshake.Reassembler` also rejects a mid-message `msg_type` change
  (`error.InconsistentMessageType`). Certificate mode is no longer
  self-interop only: the live wolfSSL suite gains a PSK-less `.cert_dhe`
  handshake against a wolfSSL certificate server, plus the same handshake
  at a 256-byte peer MTU so the peer's Certificate really is fragmented.
  That found one more defect of the class only a third party can find —
  the `.cert_dhe` ClientHello carried no `supported_versions`, so a real
  DTLS 1.3 server negotiated 1.2. Sending is still single-fragment.

  HelloRetryRequest now works in `.cert_dhe` mode as well, including RFC
  8446 §4.1.4's (EC)DHE half: a retry naming a different
  `supported_groups` group is answered with a fresh `key_share` in THAT
  group, so `secp256r1` is now a real key-exchange group (65-byte
  uncompressed SEC1 share, shared secret = the X coordinate per RFC 8446
  §7.4.2) rather than something advertised and not implemented.
  **BEHAVIOURAL, not breaking:** `error.HelloRetryRequestUnsupported` no
  longer covers cert-mode retries. **What changes for a consumer:** a
  `.cert_dhe` handshake against a server that answers with an HRR used to
  end in that error and now completes, so a caller that treated it as
  "this peer is unusable, fall back" takes a different path. Nothing that
  previously succeeded changes: the error remains a member of
  `HandshakeError`, the retry is still fully authenticated, and a peer
  that never sends an HRR is byte-for-byte unaffected.
  **BREAKING (API):** `HandshakeError` gains `error.UnsupportedGroup`
  (retry named a group we never advertised) and
  `error.IllegalHelloRetryRequest` (retry named a group we already
  offered a share in — the peer-driven retry loop; or a ServerHello that
  switched cipher suite after the retry committed to one) — an exhaustive
  `switch` over the set stops compiling until it handles both; a `catch
  |e| switch (e) { … else => }` is unaffected.
  A cookie-only retry deliberately leaves the `key_share`
  byte-identical: §4.1.2 permits no gratuitous change. Live-anchored
  against wolfSSL in three shapes (cookie only, group change only, both),
  and the P-256 ECDH is additionally KAT'd byte-exact against Python
  `cryptography`/OpenSSL.

  Certificate mode's last two self-interop-only gaps are closed, both
  live: a wolfSSL server configured with `VERIFY_PEER |
  FAIL_IF_NO_PEER_CERT` now verifies OUR client certificate (mutual
  auth), and a real wolfSSL certificate client verifies the chain OUR
  server presents. The first of those found a sixth wire defect of the
  same family as the five before it: the client decoded a
  CertificateRequest's `signature_algorithms` with
  `decodeU16ListExtension` into a fixed `[8]u16`, so a real peer's list
  (wolfSSL sends 16) came back `error.TooManyExtensions` → `Malformed`.
  It now filters to this side's own scheme table, exactly as the
  ClientHello path already did.

- **2026-07-19** — Security audit: fixed the anti-replay window (part of the
  collection-wide CRIT/HIGH audit; the root changelog records no further
  detail than this).
