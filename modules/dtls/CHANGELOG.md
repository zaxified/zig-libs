# dtls — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-21** — **NEW API + Behaviour change (DTLS 1.2):** RFC 9146 connection ID in the 1.2 engine. `Config.connection_id` (until now 1.3 only) is offered in a 1.2 ClientHello and answered by a 1.2 server that set one; once negotiated, epoch-1 records are `tls12_cid` (25) records with the RFC 9146 §5.3 additional data, and a received epoch-1 record without this side's CID (or with another) is `error.Malformed`. Default (null) unchanged. New: `Connection12.peerConnectionId`, `Endpoint.peerConnectionId`, `record12.content_tls12_cid`, `record12.CidHeader`, `record12.decodeCidHeader`, `record12.sealCid`, `record12.openCid`, `record12.OpenedCid`, `record12.max_cid_len`; `record.nextDatagramCid` also cuts `tls12_cid` records.
- **2026-11-21** — **NO CONSUMER-VISIBLE CHANGE:** the recorded DTLS 1.2 interop transcript (`src/testdata/wolfssl12_transcript.txt`) was re-captured with two new plain-PSK cases against OpenSSL 3.5, both roles; the engine is unchanged.
- **2026-11-21** — **NEW API:** `CertConfig.rsa_blinding` (`?*rsa.BlindingCache`, default null = unchanged): every RSA signature of both engines (1.3 CertificateVerify through `certverify.signWith`, 1.2 CertificateVerify and ServerKeyExchange, PSS and PKCS#1 v1.5) reuses the per-key blinding pair. **Source-breaking:** `sig12.sign` takes the cache as a new third parameter.
- **2026-11-21** — **NEW API:** DTLS 1.3 connection ID (RFC 9146 §3, RFC 9147 §9): `Config.connection_id`, `Connection.peerConnectionId`, `max_cid_len` (32), `ext_connection_id`, `ConfigError.InvalidConnectionId`, `record.nextDatagramCid`. Negotiated in ClientHello / ServerHello; protected records from epoch 2 on carry the peer's CID; a received record with another CID, or without the expected one, is `error.Malformed`. Default (null) unchanged. **Source-breaking** for an exhaustive `switch` over `ConfigError`.
- **2026-11-21** — **Behaviour change (1.3 server):** a client key share in secp384r1, secp521r1, ML-KEM-512/768/1024, SecP256r1MLKEM768 or SecP384r1MLKEM1024 is now answered (was `MissingKeyShare`), after the advertised groups in preference order; the client's offer is unchanged. `max_server_hello_body` 1216 → 1792.
- **2026-11-21** — **NEW API:** `PeerVerify.chain` (`ChainVerify`: `trust_anchors`, `required_eku`, `revocation`): RFC 5280 §6 certification-path validation of the peer's whole Certificate message through `x509.verifyChain` (multi-hop, name constraints, `basicConstraints` / `keyUsage`, path length, EKU, CRLs, `expected_peer_name` against the SAN), allocation-free (stack buffer), in both engines; `certauth.verifyPeerChain`, `certauth.max_chain_certs`, `messages12.decodeCertificateList`; `dtls.PeerVerify` / `dtls.ChainVerify` re-exported. A received Certificate may now carry 9 entries (was 4). **Source-breaking** for an exhaustive `switch` over `PeerVerify`.
- **2026-11-21** — **NEW API:** RFC 5764 `use_srtp` in both engines: `Config.srtp_profiles`, `negotiatedSrtpProfile()` on `Connection` / `Connection12` / `Endpoint`, `ConfigError.InvalidSrtpProfiles`, `max_srtp_profiles`, and `messages.ext_use_srtp` / `UseSrtp` / `encodeUseSrtp` / `decodeUseSrtp` / `selectSrtpProfile`. The server answers its first preference the client listed, with an empty MKI; no overlap = no answer. Default (empty list) unchanged. **Source-breaking** for an exhaustive `switch` over `ConfigError`.
- **2026-11-21** — **NEW API:** `HelloRetryConfig.refuse_fragmented_client_hello` (default `false` = unchanged): a server with the cookie exchange on refuses a ClientHello that does not arrive as one whole fragment, before keeping any reassembly state — OpenSSL's `DTLSv1_listen`, mbedTLS and wolfSSL (cookies on) do not reassemble one either. New error `FragmentedClientHello` in `HandshakeError` (**source-breaking** for an exhaustive `switch` over it).
- **2026-11-21** — **NEW API:** the AES-CCM suites, on the new `aesccm` module (12-byte nonce; std has only 13): DTLS 1.3 `aes_128_ccm_sha256` (0x1304) and `aes_128_ccm_8_sha256` (0x1305) are now wired (`Config.validate` no longer refuses them; RFC 9147 §4.2.3 AES sequence-number mask; under CCM_8 a record shorter than 16 ciphertext bytes is zero-padded as §4.2.3 requires), and DTLS 1.2 gains `CipherSuite12.psk_with_aes_128_ccm` / `psk_with_aes_128_ccm_8` / `ecdhe_ecdsa_with_aes_128_ccm` / `ecdhe_ecdsa_with_aes_128_ccm_8` (RFC 6655 / 7251, RFC 7925's mandatory CCM_8 pair) and `record12.Bulk.aes_128_ccm` / `.aes_128_ccm_8`, `Bulk.tagLen`, `Bulk.hasExplicitNonce`. **Source-breaking** for an exhaustive `switch` over `record12.Bulk` or `CipherSuite12`. Defaults unchanged (CCM is opt-in). New dependency `aesccm`.
- **2026-11-21** — **Behaviour change (1.3 engine):** (1) **send-side fragmentation:** `Config.max_datagram_len` now applies to the DTLS 1.3 engine too — a handshake message whose record would exceed it (or, with no limit, one 1500-byte record) is sent as RFC 9147 §5.5 fragments, one record each; cut the returned bytes with `record.nextDatagram`. Default 0 leaves the bytes unchanged. (2) **Retransmission in new records (RFC 9147 §5.2):** `poll` re-seals the cached flight with fresh epoch-0 / epoch-2 sequence numbers instead of resending the same bytes, and leaves out the records an epoch-2 ACK named (§7.2); an ACK naming only part of the flight makes `handleFlight` return the rest at once (`need_more_data` with a non-empty `out`). (3) **Partial-flight ACK (§7.1):** a server left with part of the client's final flight returns an epoch-2 ACK of what it read. `HandshakeResult.need_more_data` no longer implies an empty `out`. NEW API `Connection.cachedClientHello` (used by `Endpoint`). The cached flight holds up to 64 records.
- **2026-11-19** — **Behaviour change / Security fix (1.2 engine, review follow-up):** the epoch-0 window records a record only when it completed a message or was an accepted ChangeCipherSpec, and never more than one window width (64) ahead of its high mark; a forged 1-byte hello fragment with record number 2^48-1 no longer shadows the genuine records. `handleFlight`'s retry from live bytes now also drops a partial message latched by an earlier call (kept only if the datagram alone completes the message), and a server at `.start` lets a whole ClientHello under another `message_seq` replace a partial one, so the same forged fragment no longer wedges the reassembly either. 1.3: `handleFlight` asserts the cached flight's record table is unchanged before ACK marks are carried across a rollback.
- **2026-11-19** — **Behaviour change (1.3 engine):** RFC 9147 §7.2 MUST — once an authenticated (epoch-2) ACK has named every record of the flight this side last sent, that flight is no longer retransmitted by `poll`. The cached flight's record numbers are kept (`flight_rns`); ACKs naming records not sent are ignored; epoch-0 ACKs are still only length-checked (unauthenticated). The ACK marks survive the incomplete-flight rollback.
- **2026-11-19** — **Behaviour change / Security fix (1.2 engine):** the epoch-0 replay window is no longer advanced by unauthenticated records. A record is checked against the window and recorded only once it advanced the handshake (next message, bytes of the message in progress, or a ChangeCipherSpec), so an off-path sender can no longer make the genuine hellos look stale with a huge record number (RFC 6347 §4.1.2.6, RFC 9147 §4.5.1; pion/dtls does the same). The 1.3 engine keeps no epoch-0 window and is unchanged; a test pins it. Supersedes the 2026-11-18 "kept" decision.
- **2026-11-17** — **Behaviour change / Fix:** an RFC 9147 §7 ACK record arriving in the middle of a handshake flight (epoch 0 plaintext, or epoch 2) no longer fails the handshake with `error.UnexpectedMessage`: a well-formed one is authenticated, replay-checked, length-checked and skipped; a malformed one (short, truncated, odd-sized, trailing byte) is `error.Malformed`, as before an error. It is not matched against the cached flight (the whole flight is still resent on the timer; SPEC Backlog "partial retransmission"). Tests: an ACK between the records of the server's flight (both epochs) and ahead of the client's Finished, four malformed bodies in both epochs, a replayed ACK, another inner content type.
- **2026-11-17** — **NO CONSUMER-VISIBLE CHANGE:** the DTLS 1.3 engine's dead flight-tracker bookkeeping is deleted (`pending_flight_buf`, `pending_flight_count`, `markFlightSent`, `clearFlightTracker` and the `extra_records` / `all_records` lists that fed them): written on every flight and never read, found by the whole-module mutation (14 equivalent mutants). `flight.FlightTracker` stays (public, tested). A lost flight is still resent whole from the cached copy (RFC 9147 §7.2 makes partial retransmission a SHOULD); SPEC Backlog lists what partial retransmission would need.
- **2026-11-17** — **Fix:** the DTLS 1.2 plain-PSK premaster (RFC 4279 §2: `other_secret` is `psk.len` zero bytes) overflowed its 596-byte stack buffer for PSKs of 297..512 bytes (`max_psk_len`): a panic in ReleaseSafe, a stack overflow in ReleaseFast. Reached only through the local `Config.psk`, never by a peer. Both buffers (client and server) are now `2 + max(80, max_psk_len) + 2 + max_psk_len`; the 512-byte cap (OpenSSL's `PSK_MAX_PSK_LEN`) and the wipe of the buffer are unchanged. Found by the whole-module mutation audit; test "dtls12 PSK of 512 bytes works, 513 is KeyExchangeFailed" (296/297/512 both PSK suites).




- **2026-11-17** — **NO CONSUMER-VISIBLE CHANGE (hardening of the same-day 1.2 receive queue):** the retry-without-queue also runs when the message in progress holds queued bytes latched by an EARLIER call (a forged partial fragment queued, then drained when the genuine previous message completed), and then forgets that message too. New tests: that case; a record of exactly `max_datagram_len` is not fragmented and one byte over is; a short output buffer while fragmenting is `BufferTooShort`; no stale queued copies left after a reversed, duplicated flight; `nextDatagram` on a truncated unified header.

- **2026-11-17** — **NEW API + Behaviour change (DTLS 1.2):** (1) **Live wolfSSL 1.2 interop:** `tools/wolfssl_peer.c` gains `12-server-*` / `12-client-*` modes (`wolfDTLSv1_2_*_method`), `tools/interop.zig` fifteen 1.2 cases (ECDHE_PSK, ECDHE_ECDSA with AES-128-GCM / AES-256-GCM-SHA384 / ChaCha20-Poly1305 and on secp256r1, ECDHE_RSA, both roles, mutual auth both ways, wolfSSL's HelloVerifyRequest and our stateless one, wolfSSL fragmenting at MTU 256, us fragmenting at 200) and `--version 12|13`; recorded into the new `testdata/wolfssl12_transcript.txt` and replayed by the new `wolfssl12_replay.zig` (the 1.3 transcript is untouched). Plain PSK stays self-interop only: Debian's wolfSSL has no static PSK. **Behaviour change (finding, fixed):** a 1.2 server no longer refuses a client that signals neither RFC 5746 `renegotiation_info` nor the SCSV (`SecureRenegotiationRequired`) — RFC 5746 §4.3 lets a server that never renegotiates continue, OpenSSL / wolfSSL / mbedTLS servers do, and wolfSSL's own 1.2 client is such a client; the ServerHello then carries no `renegotiation_info`. A client still requires it. (2) **NEW API `Config.max_datagram_len`** (default 0 = unchanged; 1.2 only, the 1.3 engine ignores it — Backlog) and **`record.nextDatagram`**: a 1.2 handshake message whose record would exceed the limit is sent as RFC 6347 §4.2.3 fragments, and the caller cuts the returned bytes into datagrams; `ConfigError.MaxDatagramLenTooSmall` below `min_max_datagram_len` (128). **Behaviour change:** incoming 1.2 messages are reassembled by `handshake.Reassembler` (fragments in any order; a contradicting overlap is now `OverlappingFragment` / `InconsistentLength` / `InconsistentMessageType` instead of `Malformed`), and fragments of up to 8 later messages (6144 bytes) are queued instead of dropped; a call that fed a queued fragment and failed is retried once without the queue, so forged queued fragments cannot wedge a flight. `Connection12` grows by about 10 KiB.



- **2026-11-13** — **NEW API:** DTLS 1.2 (RFC 6347), client and server: `Connection12` (same method shape as `Connection`, same `Config`) and `Endpoint` (negotiates 1.3 vs 1.2 from the new `Config.versions`, default `{.dtls13}` = unchanged). Suites (`CipherSuite12`, `Config.cipher_suites12`): ECDHE_ECDSA and ECDHE_RSA with AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, PSK with AES-128-GCM, ECDHE_PSK with ChaCha20-Poly1305; X25519 / secp256r1 / secp384r1; RSA-PSS preferred, PKCS#1 v1.5 accepted and produced for 1.2 only. HelloVerifyRequest cookie exchange (stateless, `Config.hello_retry`), retransmission with fresh record numbers, mutual authentication, RFC 7627 extended master secret required by default (`Config.require_extended_master_secret`), RFC 5746 `renegotiation_info` sent and required, renegotiation never performed, RFC 5705 exporter, ALPN, RFC 8446 §4.1.3 downgrade sentinel in both roles. A dual-version ClientHello adds 1.2 to `supported_versions`, the 1.2 suites and the EMS / RI / point-format extensions. New errors `ExtendedMasterSecretRequired`, `SecureRenegotiationRequired`, `DowngradeDetected`, `NegotiatedDtls12` (internal to `Endpoint`), `ReceivedAlert`, `ConfigError.InvalidVersions` / `NoCipherSuites12`; `Config.psk_identity_hint`. New files `prf12`, `record12`, `messages12`, `sig12`, `suite12`; fuzz harnesses `dtls12-handshake`, `dtls12-wire`; an RSA-2048 test fixture.
- **2026-11-13** — **NEW API:** `TLS_AES_256_GCM_SHA384` (0x1302): `CipherSuite.aes_256_gcm_sha384` with the SHA-384 key schedule end to end (48-byte secrets, transcript, PSK binder, Finished MACs, HelloRetryRequest `message_hash` and an 83-byte cookie, KeyUpdate, the RFC 8446 §7.5 exporter under SHA-384). New `HashAlg`, `CipherSuite.hash()`, `Config.psk_hash` (default `.sha256`, RFC 8446 §4.2.11: in `.psk` mode a client offers and a server selects only suites of the PSK's hash; a ServerHello or HelloRetryRequest naming another is refused), `ConfigError.PskHashMismatch` (no configured suite of `psk_hash`), `Connection.installApplicationSecrets` (slices, any suite; `installApplicationKeys` keeps its `*const [32]u8` signature and refuses a SHA-384 suite). **Default `Config.cipher_suites` is now `{ aes_128_gcm_sha256, aes_256_gcm_sha384 }`** (pion/wolfSSL order): a `.cert_dhe` ClientHello offers both; a default `.psk` ClientHello is byte-identical (SHA-256 PSK). The client's transcript runs SHA-256 and SHA-384 side by side until the ServerHello / HelloRetryRequest names the suite (`suitehash.Transcript`); `Connection.client_hello1_hash` is gone (read from that transcript). A client now refuses a HelloRetryRequest naming a suite it did not offer (`error.IllegalHelloRetryRequest`, RFC 8446 §4.1.4) at the retry rather than at the ServerHello.
- **2026-11-13** — **NEW API:** KeyUpdate in both directions (RFC 9147 §8): `Connection.requestKeyUpdate`, `keyUpdatePending`, `Config.key_update_after_records` (default 2^24, automatic rekey; `null` = off); `recv` processes a peer KeyUpdate (new `error.ReceivedKeyUpdate`) instead of leaving the connection on an un-updatable key, keeps the previous read epoch for late records, and ACKs NewSessionTicket; `poll` now returns the ACK / KeyUpdate records once connected (it returned `null` before). New `error.KeyUpdatePending`. RFC 8446 §7.5 exporter `Connection.exportKeyingMaterial` (`"dtls13"` labels). RFC 7301 ALPN: `Config.alpn_protocols`, `Connection.negotiatedAlpn`, `error.NoApplicationProtocol`, `error.InvalidAlpnProtocols`; `messages.encodeAlpn`/`AlpnIter`/`decodeAlpnSelected`. The client's EncryptedExtensions buffer grew 64 → 512 bytes.
- **2026-11-01** — **NO CONSUMER-VISIBLE CHANGE:** the ML-KEM half of the PQ hybrid comes from `tls13.kex`, which now runs on the `mlkem` module; `mlkem` is a direct dep for the tests that decapsulate with it.
- **2026-10-31** — **NO CONSUMER-VISIBLE CHANGE:** the client keeps the expanded ML-KEM decapsulation key from key generation (`tls13.kex.generateExpanded` / `sharedSecretExpanded`, new `Connection.ecdhe_expanded`, wiped wherever `ecdhe_secret` is), so the hybrid / ML-KEM-1024 shared secret no longer re-expands the key. `Connection` grows by ~12 KiB.
- **2026-10-20** — **NO CONSUMER-VISIBLE CHANGE:** `engine.Transcript` is now
  `tls13.transcript.Transcript(Sha256)` (same methods, same bytes); its tests moved to `tls13`,
  where the HelloRetryRequest rewrite is now anchored on RFC 8448 §5. ctgrind counts unchanged.

- **2026-10-20** — **NO CONSUMER-VISIBLE CHANGE:** the (EC)DHE key exchange (x25519,
  secp256r1, X25519MLKEM768) moved to `tls13.kex`; `Connection.zig` keeps the group policy
  (`advertised_groups`, the offered share, preference order) and thin wrappers under the old
  names. Each exchange now runs under its own burn inside the entry points' burns. Its four kex
  unit tests moved with the code; the wolfSSL replay, stack probes and ctgrind counts (hs 119,
  app 14) are unchanged.

- **2026-10-20** — **NO CONSUMER-VISIBLE CHANGE:** `certverify` (CertificateVerify sign/verify)
  and its KAT vectors moved to the `tls13` module; `dtls.certverify` re-exports it, so the API
  and the types are the same. Its 29 tests now run in `test-tls13`; the stack probe of
  `certverify.sign` stays here. ctgrind counts unchanged (hs 119, app 14).

- **2026-10-20** — **NO CONSUMER-VISIBLE CHANGE:** the key schedule moved to the new `tls13`
  module (shared with the planned `tlsserver`); `src/keyschedule.zig` is now a shim that binds
  `tls13.keyschedule.dtls13` to the same names, so `dtls.keyschedule` and `Connection` are
  unchanged byte for byte in what they compute. The KATs moved with the code; the shim keeps a
  test for `deriveSequenceNumberKey`, the one DTLS-only derivation. New dependency: `tls13`.

- **2026-10-19** — **NO CONSUMER-VISIBLE CHANGE:** the AES-128-GCM record protection now runs on the zig-libs `aesgcm` module instead of `std.crypto.aead.aes_gcm` (std AES-GCM is 2.6x slower on Zig 0.17, #36256). Same bytes on the wire; new dependency `aesgcm` in `meta.deps`. Bulk path not re-measured yet.

- **2026-10-18** — Ported to Zig 0.17.0. `X25519.KeyPair.generateDeterministic`/`recoverPublicKey` no longer return errors: the `catch return error.KeyExchangeFailed` arms (and their secret wipe, now unreachable) are gone; `EnumSet.initEmpty()` -> `.empty`; the `Entropy` union test reads `field_names`/`field_types`.
- **2026-10-10** — tests: deterministic fuzz driver `DTLS_FUZZ` (`src/fuzz_test.zig`) over the in-memory client <-> server flow. `dtls-handshake`: PSK (AES-GCM, ChaCha20), PSK with the HelloRetryRequest cookie exchange and certificate-less (EC)DHE, one flight damaged / replaced by random bytes / dropped / duplicated; an undamaged handshake connects, a connected pair agrees on its directional keys and carries a record each way, a damaged flight that still connects differs only in a plaintext record header's legacy_version / epoch / sequence octets (the receiver does not check a plaintext record's epoch field). `dtls-record`: damaged, replayed and reordered application records (a damaged record is never accepted, a replay is refused). `dtls-wire`: record, handshake-header, reassembler, ClientHello / ServerHello / extension / ACK parsers on damaged genuine hellos and random bytes. 200,000-run verdicts clean. No code change.
- **2026-10-10** — Constant time: new `src/ctgrind_harness.zig` (targets `hs`, `app`, ReleaseFast). `hs` runs an in-memory PSK handshake with the PSK tainted on both sides; `app` taints both directions' record keys (AEAD key, IV, sequence-number mask key) through `send`/`recv` under AES-128-GCM and ChaCha20-Poly1305. No context is a branch on a key: the in-file ones are verdicts of checks that already run in constant time (PSK binder, both Finished MACs, the AEAD tag) and the receiver processing what it just decrypted (sequence-number reconstruction, padding scan and content-type dispatch, handshake-message parsing, transcript hashing), itemised in `scripts/checks/ctgrind-expected.tsv`. No code change.
- **2026-10-09** — **BREAKING (dead-stack rule, CONVENTIONS §2.1.1, public building blocks):** `keyschedule.*`
  now takes every secret by `*const [N]u8` and returns it through `out` pointers (first parameter after the
  comptime types), no secret by value or return: `expandLabel(Hkdf, prefix, len, out, secret, label, ctx)`,
  `hkdfExpandLabel(Hkdf, len, out, secret, label, ctx)`, `deriveSecret`/`earlySecret`/`binderKey`/`pskBinder`/
  `deriveHandshakeSecret`/`deriveMasterSecret`/`deriveFinishedKey`/`computeFinishedVerifyData`/
  `deriveSequenceNumberKey` (out first), `deriveHandshakeTrafficSecrets` / `deriveApplicationTrafficSecrets`
  (`out_client, out_server` instead of a struct), `deriveTrafficKeyIv` (`out_key, out_iv`). Burned entry points
  (8 KiB, one-shot): `expandLabel`, `earlySecret`, `pskBinder`, `deriveHandshakeSecret`, `deriveMasterSecret`,
  `computeFinishedVerifyData` (the rest only chain these). `aead.Protection(A).protect/unprotect` take the key
  as `*const [key_length]u8` and run under a 4 KiB per-record burn; `encryptSequenceNumberAes/ChaCha20`
  (and the `decrypt*` aliases) are burned the same way. `certverify.sign` / `candidateSchemes`,
  `Config.validate` and `Connection.clientInit/serverInit` carry `secret-api-ok` markers (their by-value
  arguments hold only slices/pointers; `Connection` is returned before any key exists). No user outside the
  module (rg modules/ example-apps, 2026-10-09). New probe `src/stackprobe2_test.zig` (testkit engine) over
  all of the above; `check-secret-api` is at 0 for dtls.

- **2026-10-09** — **BREAKING + FIX (secrets on the dead stack, HIGH):** the key exchange, key schedule and
  record keys of `Connection` left copies on the dead stack. Measured BEFORE with the new full-handshake probe
  in `src/stackprobe_test.zig` (a client<->server handshake in static memory; one probe per public step:
  `startHandshake`, `handleFlight` ×3, `send`, `recv` ×2 directions, `installApplicationKeys`; ReleaseFast,
  per 5 calls; needles derived from the live connections and a recording entropy source): every one of the
  40 probes measured before the fix (5 sets × 8 steps) found residue, 5 015 hits per 5 calls over the four classical sets
  (PSK AES-128-GCM 1 620, PSK ChaCha20 860, cert X25519 1 750, cert P-256 + client auth 785) and 26 305 for the
  X25519MLKEM768 set (24 540 of it the re-expanded ML-KEM decapsulation key). By kind, summed over the
  sets: the ephemeral entropy draws 65× and the clamped X25519 scalar 10×, the client's `ecdhe_secret` 50×,
  the shared secret 80×, the early / handshake / master secrets 120× / 100× / 100×, the PSK binder key 60×,
  the handshake traffic secrets 100× + 100×, the application traffic secrets 200× + 200×, the finished keys
  200×, the record keys 1 070×, the sequence-number keys 625× and AES-128 round keys / GHASH key 3 700×; the
  ML-KEM decapsulation key (expanded from the seed) 24 540×. Dirty depth of the unburned bodies:
  `startHandshake` 7.2 KiB (PSK) … 70.2 KiB (hybrid), `handleFlight` 34.6 … 107.0 KiB, `send`/`recv`
  1.9 … 4.3 KiB, `installApplicationKeys` 2.1 KiB. After: 0 residues in all 45 probes (the 40 plus `installApplicationKeys`), negative control 0,
  positive control found.
  - **API:** `Connection.installApplicationKeys` takes the two application traffic secrets by pointer
    (`client_ap_secret: *const [32]u8`, `server_ap_secret: *const [32]u8`, were `[32]u8` by value): a by-value
    secret argument is copied into the caller's frame, where no burn inside the callee can reach it.
    Callers write `&client_ap_secret, &server_ap_secret`. Nothing else in the public API changed.
  - Each of `startHandshake`, `handleFlight`, `installApplicationKeys`, `send` and `recv` now runs its body one
    frame down and zeroes the stack it dirtied (`src/burn.zig`: 128 KiB, 224 KiB, 8 KiB, 8 KiB, 8 KiB; each
    ~2× the measured depth). Because the burn sits at the public entry, it also covers std's X25519 / P-256 /
    ML-KEM / HKDF / AES frames, the entropy source's own frames and the snapshot `handleFlight` takes for its
    rollback. 224 KiB of vector stores is about 2 µs next to a handshake's scalar multiplications.
  - `ecdheGenerate`/`ecdheSharedSecret`/`ecdheServerExchange` (file-private) are unchanged: the secrets never
    cross the public API, so burning around the call replaces moving them to out-parameters.
  - Not covered (SPEC "Backlog / deferred"): the standalone helpers in `keyschedule`/`aead`/`record` when a
    consumer calls them directly, secrets that stay in the live `Connection` by design, HelloRetryRequest and
    `poll` paths.

- **2026-10-08** — **BREAKING + FIX (secrets on the dead stack, HIGH):** CertificateVerify signing
  (`certverify.sign`, all four key families) left the private key and the signing nonce on the dead stack,
  and `certverify.SecretKey` carried the keys BY VALUE (an `rsa.SecretKey` alone is 11.8 KiB), copied with
  every `CertConfig` pass. Measured BEFORE with the new `src/stackprobe_test.zig` (ReleaseFast, per 5 calls,
  key held in a `var`, one key case shown): ECDSA P-256 left `d` 75×, `k` 35×, `k⁻¹` 20×, `r·d` 10×,
  `e+r·d` 10× (down to 34.5 KiB below the call; the same with noise); ECDSA P-384 `d` 110×, `k` 40×, `k⁻¹` 25×,
  `r·d` 15×, `e+r·d` 15× (32.2 KiB); Ed25519 the seed 30×, `SHA-512(seed)` 10×, the clamped scalar 10×, the
  prefix 5×, the nonce `r` 30× (+20× its 64-byte form; 30.7 KiB); RSA-PSS `p` 30×, `q` 40×, and the key
  struct's `p`/`q`/`d`/`dP`/`dQ`/`qInv` images 80–200× each plus 340×/310× `p`/`q` Montgomery constants
  (26.9 KiB, from 0.5 KiB below the call: the by-value key copies in the caller's and `sign`'s frames). `k`
  next to a published signature is the private key. After: 0 residues in all six cases, negative control 0,
  positive control found.
  - **API:** every `certverify.SecretKey` variant is now a pointer (`rsa: *const rsa.SecretKey`,
    `ecdsa_p256: *const Ecdsa.EcdsaP256Sha256.SecretKey`, `ecdsa_p384: *const …P384Sha384.SecretKey`,
    `ed25519: *const Ed25519.SecretKey`). The key is BORROWED and must outlive every use of the union —
    for `Connection`, the connection (`CertConfig.private_key` doc says so). `certverify.sign` keeps its
    signature; callers write `.{ .ecdsa_p256 = &sk }` with `sk` in a `var`/`const` that has an address.
  - `sign` runs each family's signing body one frame down and zeroes the stack it dirtied (`src/burn.zig`:
    48 KiB ECDSA, 40 KiB Ed25519, 8 KiB RSA-PSS above rsa's own burn). Zeroing is a handful of vector
    stores per KiB, small next to a scalar multiplication.
  - Tests: `kat.rsa_pss_sha256_server.secretKey(out)` is an out-param now. The "CSPRNG requirement is
    load-bearing" test compared the whole 96-byte `EcdheKeyPair.secret`, whose tail is undefined for
    X25519/P-256 — it passed only while the stack under it happened to be equal; it now compares the 32
    written bytes (found because the burn changed that stack).
  - Not covered (SPEC "Backlog / deferred"): the `Connection` path itself (not driven by the probe) and
    the ECDHE scalars, key schedule and record keys.
- **2026-10-08** — **NO CONSUMER-VISIBLE CHANGE:** CertificateVerify signing passes the RSA key to
  `rsa.signPss` by pointer, and the KAT key fixture builds through rsa's out-param `fromPrimes`
  (rsa 2026-10-08).
- **2026-10-06** — ⛔ **Fixed: Ed25519 `sign` with a secret key whose embedded public half is not its own went ahead in ReleaseFast.** It relied on `std`'s `Ed25519.KeyPair.fromSecretKey`, which checks the embedded public key only under `std.debug.runtime_safety` (signing one message under two public keys gives away the secret scalar). It now derives the pair from the seed and compares in every mode (`error.KeyMismatch`). Same defect as webhooksig's, found by grepping siblings; new test, teeth checked in ReleaseFast.
- **2026-09-10** — **BEHAVIOURAL, not breaking:** the application-epoch
  `send`/ack path now refuses (`error.SequenceNumberExhausted`, new
  `SendError` member) the record that would need `send_seq` to wrap past its
  48-bit ceiling, instead of silently reusing an AEAD nonce under the
  unchanged traffic key (RFC 9147 §4.5.4, audit A1 F4/LOW4). The PQ-hybrid
  key exchange now zeroizes the ML-KEM decapsulation key and both derived
  shared secrets after use, not just the seeds that fed them (audit A1
  F5/LOW5). No consumer exists yet (0 in-repo, `build.zig` is the only line
  naming the module), so nothing downstream to update. Also: two stale doc
  claims corrected (the anti-replay window comment's off-by-one, and the
  `ecdhe_public` field doc's over-claim that the client checks the peer
  share against both group AND value — only group is checked, matching RFC
  8446 §4.2.8, audit A1 F7/LOW7) and the stateless-cookie-vs-fragmented-
  ClientHello memory amplification documented as a known limitation (audit
  A1 F6/LOW6) — both doc-only, see `SPEC.md`.
- **2026-09-09** — Docs: `tools/wolfssl_peer.c` had no `SPDX-License-Identifier`; added (MIT —
  the file is this repository's own `main`/`run_server`/`run_client` over wolfSSL's public
  API, not wolfSSL source). `zig build check-catalog` now enforces the header on every
  shipped source file.
- **2026-09-07** — **BEHAVIOURAL, not breaking — remote crash fixed:**
  `messages.decodeCertificate` panicked with `integer overflow` on a peer's
  `Certificate` message whose `certificate_request_context` is 255 octets long.

  `certificate_request_context` is a `<0..2^8-1>` field (RFC 8446 §4.4.2), so
  255 is a value a conforming peer may send. The decoder wrote
  `var i: usize = 1 + ctx_len` — and `ctx_len` is a `u8` while the `usize` is
  only the RESULT type, so peer-type resolution did the addition in `u8`.
  A 259-octet body with `ctx_len == 255` therefore **panicked in Debug and
  ReleaseSafe**, and in ReleaseFast wrapped to `i = 0`, after which the
  context-length octet was re-read as the top of the 24-bit `certificate_list`
  length. The bounds check on the line above it is written correctly
  (`@as(usize, ctx_len)`); only this one was not.

  Reachable from `Connection.zig`'s handshake path on a peer's `Certificate`
  message — i.e. a malicious server can crash a client, and in mutual-auth mode
  a malicious client can crash a server, **before either has authenticated the
  other**, which is the point of that message. Consumers running ReleaseSafe
  see a process abort turn into an ordinary decode; nothing that used to succeed
  behaves differently.

  Found by `zig build --fuzz` in **328 runs**, on the day
  `fuzzDecodeCertificate` was first given a corpus and a byte-first draw. The
  target had been in the tree since the module was written and had never decoded
  a `Certificate` body at all: its length draw collapsed to 0, so it called
  `decodeCertificate("")` once and stopped. The crashing shape is now both a
  named regression test and a corpus seed.





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
