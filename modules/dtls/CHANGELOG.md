# dtls — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **NO CONSUMER-VISIBLE CHANGE:** the module's last two fuzz
  targets stop drawing their whole scenario from collapsing draws, and `dtls`
  reaches zero on `scripts/check-fuzz-reach.py` (17 → 0).

  `handshake.fuzzReassemble` and `Connection.fuzzHandleFlight` both draw a
  SHAPE rather than a frame, and both took every choice from
  `smith.valueRangeAtMost` — starting with the first. A ranged draw reads eight
  octets as a little-endian `u64` and returns the range MINIMUM unless the whole
  word lands inside the range, and after one short read `Smith` discards the
  rest of the input. Neither was exempted: a state machine driven by a byte
  script has a byte-first form, so both now take one `smith.slice` and read
  their choices out of it with `testkit.fuzz.Cursor`. `fuzzReassemble`'s
  hand-written corpus of 8-octet little-endian words, and the
  `CorpusItem`/`corpusBytes`/`stormFragment` apparatus that built it, are gone;
  the seeds are now hex scripts that read as the scenario they are.

  ⭐ What the collapse was hiding in `fuzzHandleFlight`: its second-fragment
  branch is commented *"Half the time, feed the TRUE remaining bytes at the TRUE
  offset, so the completing path is reached too and not only the rejecting
  one"*. That `smith.boolWeighted(1, 1)` was drawn after the input was
  exhausted, so it was `false` every time — **the completing path, which is the
  half of the accumulate/snapshot transaction the target was written to cover,
  had never run**. The target had executed exactly one scenario for its whole
  life: split = 1, an empty continuation of a zero-length message.

  Measured before → after: `fuzzReassemble` **1 script, 3 octets stitched → 9
  scripts, 405 octets stitched, 30 declared-vs-present mismatches refused**;
  `fuzzHandleFlight` **1 script, 0 truthful continuations → 8 scripts, 4
  truthful, 360 octets of real ClientHello body delivered**. Both keep the
  collapsed run as an executable "before" line in their corpus guards.

- **2026-09-07** — **NO CONSUMER-VISIBLE CHANGE:** the twelve handshake-message
  fuzz targets and the certificate-bridge one stop throwing their input away,
  and two new certificate fixtures reach two dispatch arms that had never run.

  Nine `messages.zig` targets opened with `smith.bytes(&buf)` followed by
  `smith.valueRangeAtMost(u16, 0, buf.len)`, which is the range MINIMUM once
  `bytes` has consumed the input — so `len` was 0 and every decoder was called
  with an empty slice. The other three built a message with this file's own
  encoders from parts that were *all* ranged draws, so the message was the same
  one every time: an empty session id, **zero cipher suites and zero
  extensions**. `certauth.fuzzParseLeafPublicKey` was the first shape again.
  None of the thirteen declared a corpus, so outside `--fuzz` the runner
  replayed exactly one input each.

  Measured 2026-09-07, before → after (non-empty seeds / accepted / fields
  walked): ClientHello **0/0/0 → 18/14/91**, ServerHello **0/0/0 → 25/23/45**,
  Certificate **0/0/0 → 8/3/1161 DER octets**, extension blocks **0/0/0 →
  35/32/115 extensions**, `key_share` ClientHello **0/0/0 → 10/9/3809 octets**,
  `parseLeafPublicKey` **0/0 → 13/5 keys in 4 of the 4 supported kinds**.

  Two things the collapse had been hiding:

  * **The buffers were too small for this module's own traffic.** The largest
    recorded ClientHello body is 1554 octets and the largest `key_share` 1222 —
    the hybrid X25519MLKEM768 offer this module exists to make — against 1024-
    and 256-octet harness buffers. A seed longer than the buffer reads back as
    the EMPTY one, so the flagship handshake could never have passed through its
    own harnesses even with the draw fixed. Raised to 2048.
  * **`parseLeafPublicKey`'s P-384 and Ed25519 arms had no fixture.** Its own
    comment says those two arms are the reason the harness exists (the RSA and
    P-256 paths are re-fuzzed in `x509` and `rsa`), but the module owned no
    P-384 and no Ed25519 certificate, so neither arm had ever executed.
    `src/testdata/certs/p384-cert.der` and `ed25519-cert.der` were generated
    with the same OpenSSL 3.5.5 and the same validity window as the existing
    fixtures, and are exported as `p384_cert_der` / `ed25519_cert_der`.

  Also fixed, and recorded because both were false when written: "then
  SOMETIMES flip one byte" (the flip hung on a `boolWeighted` drawn after the
  input was gone — it had never fired), and "plain random bytes at a plausible
  length already reach their interior loops" (the length was 0). The mutation is
  now a full-width `smith.value(u64)` carried in the seed's tail, and the corpus
  guard pins how many seeds carry one.

- **2026-09-07** — **NO CONSUMER-VISIBLE CHANGE:** the record-layer fuzz targets
  stop throwing their input away, and the module gains a corpus source built
  from the recorded wolfSSL transcript (`src/fuzz_corpus.zig`).

  `fuzzDecodeUnified` and `fuzzDecodePlaintext` both opened with
  `smith.bytes(&buf)` followed by `smith.valueRangeAtMost(u8, 0, buf.len)`.
  `Smith.bytes` consumes `@min(buf.len, in.len)` octets, so the ranged draw
  found fewer than the eight it reads as a little-endian `u64` and returned the
  range MINIMUM: `len` was **0 for every input**, and both decoders were handed
  an empty slice. Neither target declared a corpus either, so outside `--fuzz`
  the runner replayed exactly one input each — the empty one. Measured
  2026-09-07: **1 input each, 0 non-empty and 0 headers decoded before; 92 and
  22 seeds, all non-empty, 85 and 21 headers decoded after.**

  Two knobs went the same way, both drawn after the byte draw and therefore
  after the input was exhausted: the `boolWeighted(1, 6)` that was supposed to
  bias byte 0 into the valid fixed-bit pattern had **never executed once**, and
  the negotiated CID length was 0 on every call — so `decodeUnified`'s entire
  `has_cid` arm, `error.UnsupportedCidLength` included, was unreachable from its
  own harness. Both now come out of one full-width `smith.value(u64)` carried in
  the seed's tail, and the corpus guard pins 4 headers decoded WITH a CID.

  `src/fuzz_corpus.zig` reads the 120 recorded datagrams out of
  `src/testdata/wolfssl_transcript.txt` and hands them over in the framing
  `Smith.slice` reads. Nothing under `src/` is changed for a consumer; the file
  is test-only, and it re-introduces the `testkit` test dependency dropped on
  2026-09-06 (nothing under `src/` imported it *then*; `testkit.fuzz`'s seed
  helpers are what this needs, rather than a 34th private copy of them).

- **2026-09-06** — **NO CONSUMER-VISIBLE CHANGE:** `dtls` stops declaring itself
  `live` and stops declaring a `testkit` test dependency. Both went stale earlier
  the same day, when the wolfSSL peer moved to `tools/interop.zig`: `live` means
  "this module's tests talk to a real external peer, so run them serially", and
  `test-dtls` now opens nothing — it replays `src/testdata/wolfssl_transcript.txt`
  and passes 268/268 with no compiler and no wolfSSL on the box. Nothing under
  `src/` had imported `testkit` since the move either. The cost of leaving them
  was a needlessly serialised test run; no behaviour, API or output changes.

- **2026-09-06** — **The module stops shipping foreign source.** The live
  wolfSSL interop moved out of `src/` and became a standalone program; what it
  proves moved *in*, as a committed recording.

  **Consumer-visible:** `modules/dtls/src/wolfssl_interop.zig` and
  `modules/dtls/src/testdata/wolfssl_peer.c` are gone. A consumer of this
  module no longer receives 555 lines of C, and `zig build test-dtls` no longer
  wants a C compiler or `libwolfssl-dev` for anything: it went from *266 pass /
  14 skip* to *268 pass / 0 skip* on a host with no `cc`, `gcc`, `clang` or
  `ld` on `PATH`. The fourteen skips were not a small loss — CI installs the
  peer with `continue-on-error`, so a failed install degraded the entire
  third-party anchor to a silent skip.

  The pieces now:

  - `tools/interop.zig` — the live handshakes, a program, run by
    `zig build interop-dtls` and compiled (never run) by
    `zig build check-interop`. It reads `tools/wolfssl_peer.c` from its own
    path at run time instead of `@embedFile`ing it, which is what had forced
    the C to live under `src/` in the first place. All fourteen cases pass
    against wolfSSL 5.9.1.
  - `src/testdata/wolfssl_transcript.txt` — what `--capture` writes: every
    datagram in both directions, the seed, the configuration and the
    post-handshake assertions for each case, with a header naming the wolfSSL
    version, the date and the exact command.
  - `src/wolfssl_replay.zig` — replays it in pure Zig, no child process, no
    socket. A seven-mutation sweep over the fixture (a peer byte, one of our
    bytes, the seed, a dropped case, a changed `expect group=`, an
    application-record byte, a changed skip-error) is caught 7/7.

  **The replay is deterministic because the module already had the seam.**
  Randomness comes from the caller-supplied `Entropy`, and the live runs have
  used its `.seeded_for_test` arm from a fixed seed since they were written.
  Nothing was added, weakened, or asserted-on-a-stable-subset to make the
  recording replay.

  **What the replay cannot do**, recorded so a green run is not overread: it
  cannot discover a NEW divergence (the peer's bytes are frozen at wolfSSL
  5.9.1); a failure is a summons to re-run the live program, not a verdict of
  non-interoperability, because a change that emits different-but-still-valid
  bytes fails it too; and it cannot re-check anything that was not on the wire
  — the peer's exit status, its `wolfSSL_get_verify_result` and the `PEERCERT`
  subject it printed are kept in the transcript as comments precisely because
  only the live run can check them.

  **Also:** `src/certauth_kat_vectors.zig`'s hex literals became
  `@embedFile`s of `src/testdata/certs/*` (identical bytes, identical types).
  The interop program cannot import across the module's package root, and both
  sides must hand wolfSSL the same anchor and leaf — a second hex literal in
  `tools/` would have been a second thing to keep in step. `SPEC.md` called the
  peer "~170-line"; it is 555.

- **2026-08-31** — Post-quantum hybrid key exchange: `.cert_dhe` now speaks
  **X25519MLKEM768** (`0x11ec`, draft-ietf-tls-ecdhe-mlkem) alongside
  X25519 and secp256r1 — the last TLS-family path in this collection with
  no PQ option. The server side is unconditional (a client's 1216-byte
  hybrid share gets the 1120-byte ciphertext-form answer and the 64-byte
  `ss_MLKEM ‖ ss_X25519` concatenation feeds the unmodified key schedule);
  the client offers it via the new `Config.key_share_group` field (default
  `.x25519` — unchanged wire behavior — because a hybrid offer costs one
  HelloRetryRequest round trip against every classical-only DTLS server;
  the group is always ADVERTISED, so a preference-honoring server can also
  retry a classical offer up to it). Deliberately NOT built on
  `std.crypto.kem.hybrid.MlKem768X25519`: that type has the same share
  sizes but is X-Wing (SHA3 combiner), a third same-sized,
  non-interoperable construction next to TLS's concatenation and `ssh`'s
  `SHA256(ss_M ‖ ss_X)`. Live-anchored against wolfSSL 5.9.1 in three
  shapes (offered directly; upgraded to via HRR; a wolfSSL client's share
  answered by our server), which surfaced two wolfSSL field behaviors now
  encoded in the harness: PQ shares appear only after
  `wolfSSL_UseKeyShare`, and `WOLFSSL_DTLS_CH_FRAG` silently EMPTIES the
  key share when ClientHello1 would exceed the MTU.
  **BREAKING (API):** `ConfigError` gains `error.UnsupportedKeyShareGroup`
  (a `key_share_group` outside `advertised_groups`) — an exhaustive
  `switch` over the set stops compiling until it handles it. Sizing
  changes that follow from 1.2-KB shares: `max_flight_bytes` 4096 → 5632,
  the retransmission cache (`last_flight`) 1500 → `max_flight_bytes`
  (a cert-mode server flight could already exceed 1500 and then failed
  the handshake AFTER the flight went out), and the ClientHello accept
  bound is 2048 (a foreign hybrid hello — wolfSSL's — exceeded 1536 live).

- **2026-08-23** — `Connection.suite`'s field initialiser is no longer
  `.aes_128_ccm_8_sha256`. It now shares `Config.cipher_suites`' default
  through a single `default_cipher_suites` constant, so the pre-negotiation
  value of a public field can no longer be a suite this module has no
  `suiteParams` entry for. The 2026-08-21 entry below fixed `Config`'s copy of
  that default and left this one behind; sharing the constant is what makes
  them impossible to separate again. No behaviour change on any path — every
  read of `suite` for record protection is preceded by a write — and the
  field's doc comment now records exactly that, rather than implying a test
  covers it. Also closes the 2026-08-21 fix's own verification gap: every
  handshake test named `.cipher_suites` explicitly, so the DEFAULT never
  travelled end to end and `ConfigError.UnsupportedSuite` had no test at all.
  Both now do.

- **2026-08-22** — Documented the absence of a post-quantum key exchange in
  `SPEC.md`, `README.md` and the module doc comment. It is written down
  because the failure mode is an assumption, not an oversight: the other
  TLS-family paths a consumer reaches for (`std.crypto.tls.Client`, and `ssh`)
  do offer an ML-KEM hybrid, so picking `dtls` silently drops to a classical
  exchange. Includes what closing it would take and why the primitive is not
  the obstacle.
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
