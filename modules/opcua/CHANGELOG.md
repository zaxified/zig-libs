# opcua — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-19** — **NO CONSUMER-VISIBLE CHANGE:** delta mutation audit of the review fixes (15 mutants: 14 killed, 1 unobservable heap-wipe), one more scripted-peer test (short and absent `CreateMonitoredItems` results); the card counts are now 900/977 (cumulative), `src` re-pinned.
- **2026-11-19** — **NO CONSUMER-VISIBLE CHANGE:** the result-count check of `createMonitoredItems`/`modifyMonitoredItems` reads the count with an explicit `if` instead of `orelse &.{}` (same value; the `orelse` form does not survive a mutation switch around it).
- **2026-11-19** — **NO CONSUMER-VISIBLE CHANGE:** the decoded server nonce of an OpenSecureChannel answer is now zeroed by a `defer` on every way out of the exchange (before, only on the success path; the wrong-channel-id and other early refusals freed it unwiped). The code change landed in the preceding LOW-1 documentation commit; this entry records it (review LOW-2).
- **2026-11-19** — **NO CONSUMER-VISIBLE CHANGE:** documentation: `MonitoredItemModifySpec.client_handle` uniqueness stays the caller's duty and is not enforced (open62541's client assigns handles itself and does not enforce caller-chosen ones either). Review LOW-6.
- **2026-11-19** — **Behaviour change:** `Subscription.createMonitoredItems` and `modifyMonitoredItems` return `error.ResultCountMismatch` (new member of `services.ServiceError`) when the answer has a different number of results than the request had items (shorter, longer or absent; OPC 10000-4 one result per item, in order) and leave the handle table untouched; before, a surplus was ignored and a shortage silently left items uncorrelated. Review LOW-5.
- **2026-11-19** — **Behaviour change:** an OpenSecureChannel answer whose server nonce is not exactly 32 bytes (the symmetric key length, OPC 10000-6 §6.7.5) is refused with `error.InvalidSecureMessage` at a secured policy, for `open` and `renew`; before, only an empty nonce was refused. Review LOW-3.
- **2026-11-19** — **NO CONSUMER-VISIBLE CHANGE:** documentation: `SecureChannel.renew` now says that after a client-side refusal of a renewal answer the server has already rotated to the new token, so the old one lives only for the overlap window (review LOW-1).
- **2026-11-19** — **Behaviour change:** an OpenSecureChannel answer with `RevisedLifetime == 0` is refused (`error.InvalidTokenLifetime`, new member of `services.ServiceError`) before any channel state changes, for `open` and `renew`; and `renewalDue` is never true sooner than `SecureChannel.min_renewal_delay_ms` (default 50 ms) after the token arrived, so a server revising the lifetime to a few milliseconds cannot turn `renewIfDue` into one RSA operation per request. The floor follows node-opcua's client (`max(75 %, 50 ms)`); open62541 has none. Review finding MEDIUM-1.
- **2026-11-19** — **NO CONSUMER-VISIBLE CHANGE:** delta mutation audit of the client-side renewal, ModifyMonitoredItems, SetMonitoringMode and TranslateBrowsePaths code (50 mutants: 48 killed, 2 unobservable stack-copy wipes); one more scripted-peer test; the card counts are now 886/962 (cumulative), `src` re-pinned.
- **2026-11-19** — **New API (no behaviour change):** client-side SecureChannel renewal — `SecureChannel.renew`, `renewalDue` (75 % of the revised lifetime on the caller's clock) and `renewIfDue`, plus `OpenOptions.now_ms`, `SecureChannel.token_installed_ms` and `RenewOptions`. The OpenSecureChannel exchange of `open` and `renew` is one shared function; `open`'s wire behaviour is unchanged.
- **2026-11-19** — **New API (no behaviour change):** `Subscription.setMonitoringMode` — client-side SetMonitoringMode (OPC 10000-4 §5.12.4), one status per item id.
- **2026-11-19** — **New API (no behaviour change):** `Subscription.modifyMonitoredItems` — client-side ModifyMonitoredItems (OPC 10000-4 §5.12.3); the handle table follows a changed `ClientHandle`. `services.result_fns` gained `modify_monitored_items` and `set_monitoring_mode`.
- **2026-11-19** — **New API (no behaviour change):** `Session.translateBrowsePaths` — client-side TranslateBrowsePathsToNodeIds (OPC 10000-4 §5.8.4), the raw service like open62541's `UA_Client_Service_translateBrowsePathsToNodeIds`; tested against this module's own server over the in-memory pipe and, LIVE, against open62541.
- **2026-11-19** — **NO CONSUMER-VISIBLE CHANGE:** delta mutation audit of the key-length band (29 mutants, 29 killed); the card counts are now 838/912 (cumulative), `src` re-pinned.
- **2026-11-19** — **Behaviour change:** the OPC UA Part 7 RSA key-length band (2048..4096 bits for `Basic256Sha256`) is now enforced. The server answers a client certificate outside it with `BadCertificateUseNotAllowed` (open62541's status) and refuses an OPN with `BadSecurityPolicyRejected` when its own key is outside it; `SecureChannel.open` returns the new `error.KeyLengthOutOfPolicy` for an own key or pinned server certificate outside it (new variant in `ServiceError`); `ClientCredentials.generateSelfSigned` returns it for a `modulus_bits` outside the band (before: 1024 and above were accepted; new option `policy`). New: `SecurityPolicy.minAsymmetricKeyBits`/`maxAsymmetricKeyBits`/`allowsKeyBits`, `certificatePublicKeyForPolicy`, `checkContextKeyLengths`, `KeyLengthError`. Testing escape `insecure_allow_key_length_outside_policy` on `GenerateSelfSignedOptions`, `SecurityContext` and `SecurityConfig` (consumers with 1024-bit test keys set it).
- **2026-11-19** — **NO CONSUMER-VISIBLE CHANGE:** Backlog: per-policy RSA key-length minimum.
- **2026-11-19** — **Behaviour change:** `ClientCredentials.generateSelfSigned` with `modulus_bits` under 1024 returns `error.InvalidBits` (`rsa.generate` now refuses it, Go 1.24 floor); documented on the option. Tests moved to 1024/1280-bit keys (`k` 128/160); the self-derived golden OpenSecureChannel handshake was regenerated at 1024 bits (certificates and ciphertext).
- **2026-11-18** — **BUG FIX (no API change):** `Session.create` freed the SessionId and AuthenticationToken only on success; when it refused a CreateSession answer after receiving it (the ServerSignature did not verify) both NodeIds leaked. Found by the second whole-module mutation pass, which also adds tests only: SecureChannel gate, token window, channel teardown, OPN handler states, Read/Write/Browse/Translate/Call rules, subscription and monitored-item services, the publish engine, and the `root.zig` client against the server over an in-memory pipe; 809 of 883 mutants killed, 74 equivalent or unobservable, none open (SPEC, "Audit 2026-11-18").
- **2026-11-18** — **NO CONSUMER-VISIBLE CHANGE:** tests only. Whole-module mutation audit (885 mutants over every non-test source file, offline tests): 40 killing tests (transport and codec boundaries, forged-but-signed OPN and symmetric-chunk padding rules, Hello field validation, reassembly limits, token overlap window, renewal and certificate checks, operation-count and resource caps, session table, identity rules, Browse filters, subscription Modify/SetPublishingMode, node-store hierarchy and access rules); 605 killed, 58 equivalent/unobservable, 220 open (listed in `SPEC.md`, "Audit 2026-11-18"). The card is not changed. `scripts/checks/ctgrind-expected.tsv`: source pins of the `kdf` and `chunk` rows re-pinned (counts unchanged: 0 and 14).
- **2026-11-08** — **NO CONSUMER-VISIBLE CHANGE:** the credential comparison in `server.zig` calls `security.constantTimeEql` (std `timing_safe.compare`) instead of its own xor loop; same length-first short-circuit, same result.
- **2026-10-19** — **NO CONSUMER-VISIBLE CHANGE:** Deprecated std names replaced by their Zig 0.17 spellings (`mem.indexOf*` -> `mem.find*`, `fmt.bufPrint` -> `mem.print`, `fmt.allocPrint(a, …)` -> `a.print(…)`, `bufPrintSentinel` -> `mem.printSentinel`, `@intFromEnum` -> `@backingInt`); the old names are aliases, so behaviour is identical.

- **2026-10-18** — Ported to Zig 0.17.0 (no source change needed).
- **2026-10-17** — **NO CONSUMER-VISIBLE CHANGE:** `rsa_burn` 64 → 256 KiB (probe window 512 KiB): at CI's `-Dcpu` the ReleaseFast stack probe found `encryptUserTokenSecret` reaching 186 KB, residue past the old burn (rsa's 8192-bit capacity).

- **2026-10-10** — tests: deterministic fuzz driver `OPCUA_FUZZ` (`server.zig`, plumbing in `src/fuzz_test.zig`). A genuine client conversation (HEL, OPN, CreateSession, ActivateSession, Read, Write, CreateSubscription, CreateMonitoredItems, Publish, CloseSession; and a Basic256Sha256 SignAndEncrypt one) is recorded from the test rig once and replayed against fresh rigs with one chunk damaged, dropped, duplicated, swapped with its neighbour or replaced by random bytes (the rig's PRNG is seeded, so recorded requests stay valid). Undamaged replays reproduce the recorded reply byte count and the Write; over SignAndEncrypt a tampered or dropped Write chunk never reaches the address space and no mutation leaves a value other than 42/43. 12,500-run verdicts clean per harness (`.scale` 16: each run builds a rig). No code change.
- **2026-10-10** — Constant time: new `src/ctgrind_harness.zig` (targets `kdf`, `chunk`, ReleaseFast, Basic256Sha256). `kdf` taints both channel nonces through `deriveKeys` and has 0 in-file contexts. `chunk` taints the channel keys and body through `symmetricSignAndEncrypt`/`symmetricDecryptAndVerify`: 14 contexts, made up of the HMAC verdict and, after it, the padding checks and copy of the authenticated plaintext (its length). Padding is checked only after the MAC, so it is no padding oracle. No code change.
- **2026-10-09** — **BREAKING:** dead-stack burns (`CONVENTIONS.md` §2.1.1).
  `SecureChannel.open(conn, allocator, options, out: *SecureChannel)` and
  `ClientCredentials.generateSelfSigned(allocator, random, options, out:
  *ClientCredentials)` write their result through `out` instead of returning it
  (both hold key material by value). `security.sealAsymmetricMessage` takes
  `credentials: *const ClientCredentials`, `openAsymmetricMessage` and
  `decryptUserTokenSecret` take `private_key: *const rsa.SecretKey`, and
  `symmetricSignAndEncrypt` / `symmetricSealChunk` / `symmetricDecryptAndVerify`
  take `keys: *const ChannelKeys` (no by-value key copies in the callers'
  frames). Burned entry points: the P-SHA256 / AES-256-CBC primitives, the
  symmetric and asymmetric chunk seal/open, `encryptUserTokenSecret` /
  `decryptUserTokenSecret`, `generateSelfSigned`, `SecureChannel.open`/`close`,
  every `Session.*` / `Subscription.*` request method and `Connection.tick`.
  New `src/burn.zig` and `stackprobe_test.zig` (`testkit.stackprobe`; the
  request methods, `open` and `tick` need a live peer and are not probed).

- **2026-10-08** — **BREAKING:** `security.asymmetricDecrypt` and `security.asymmetricSign` take
  `private_key: *const rsa.SecretKey`, following rsa's 2026-10-08 API: by value, the 11.8 KiB key
  was copied into the caller's frame on every call, where nothing wipes it. `generateCredentials`
  builds the pair through rsa's out-param `generate`.
- **2026-10-06** — **BEHAVIOURAL, not breaking:** client hardening against a
  hostile server (review 2026-10-06, open item (b)). `Channel.recvService` now
  frees everything it decoded when it refuses a response — a string-typed
  response NodeId, a `ServiceFault`, a response with a Bad ServiceResult, the
  fields of a struct a truncated body cut short, and a decode that ran out of
  memory part-way all leaked per response before; it decodes through a private
  tracking allocator, and an accepted response is still plain caller-allocator
  memory freed with the same `free*Response`. On a signed or encrypted channel
  every response chunk's SequenceNumber must now follow the previous one
  (`security.sequenceFollows`, moved there from `server.zig` and now `pub`;
  the `issue` OPN response starts the count, tracked in the new defaulted field
  `Channel.recv_sequence_number`), else the new
  `ServiceError.SequenceNumberInvalid` — a replayed signed response used to be
  accepted. (An exhaustive `switch` over `ServiceError` without an `else` needs
  an arm for the new member; nothing in this repository has one.) The asyncua transcript and the Basic256Sha256 goldens are unchanged
  and still pass byte for byte.

- **2026-10-06** — **BEHAVIOURAL, not breaking:** the pre-authentication RSA cost
  of an OpenSecureChannel is bounded (review 2026-10-06, open item (a)). Every OPN
  chunk used to be RSA-OAEP-decrypted block by block before its signature could
  be checked — ≈250 private-key operations per 64 KiB chunk under a 2048-bit key,
  up to `max_chunk_count` chunks, for any stranger. Now an OPN must be a single
  final chunk (`C` or `A` → `ERR BadTcpMessageTypeInvalid`, as open62541 answers;
  asyncua sends OPN as one chunk citing OPC 10000-6 §6.7.2), and its encrypted
  region may not exceed the new `SecurityConfig.max_opn_encrypted_len` (default
  4096 bytes — at most 16 private-key operations at 2048 bits, 8 at 4096; a real
  asyncua OPN is 512) → `ERR BadTcpMessageTooLarge`. Both are decided on the
  header before any RSA operation. The asyncua transcript and the
  Basic256Sha256 goldens are unchanged and still pass byte for byte.

- **2026-10-06** — **BEHAVIOURAL, not breaking:** Review: adversarial re-review
  of the code since the 2026-09-02 review (C4–C8) and the server receive path.
  Five findings, all fixed, each with a test that failed before the fix (see
  SPEC.md, *Review 2026-10-06*). The two that change what the server accepts:
  - **H1:** a `renew` OpenSecureChannel must keep the channel's
    SecurityPolicy; a `#None` channel renewed under Basic256Sha256 is now
    refused with `ERR BadSecurityPolicyRejected`. Before this, the None token
    became the overlap token with no keys, and a MSG naming it reached
    `c.prev_keys.?`: a remote panic (Debug/ReleaseSafe) from any peer with any
    self-signed certificate, wherever `#None` was offered beside a secured
    endpoint. The `.?` is now an `ERR` too.
  - **M1:** on a secured channel every chunk's `SequenceNumber` must be the
    previous one + 1 (OPC 10000-6 §6.7.2.4, with the wrap below 1024 that
    open62541 and asyncua accept), else `ERR BadSecurityChecksFailed`. It was
    read and discarded, so a captured signed or encrypted Write/Call could be
    replayed for the token's whole life. The asyncua transcript and the
    Basic256Sha256 goldens are unchanged and still pass byte for byte.
  - Memory-safety on OutOfMemory only, no change to any output: **L1**
    `sampleDue` no longer frees `last_value` before its replacement exists (a
    failure there left a dangling pointer, later freed twice); **L2** C4's
    `decodeArray`/`decodeVariantArraySlice` grow the list before decoding an
    element, so a failed growth no longer leaks it; **L3**
    `NodeStore.dupAttributes` gets C7's errdefers.
  - Reported and not fixed (owner's decision): the pre-authentication RSA cost
    of a large or multi-chunk OPN; client-side leaks and the missing
    `SequenceNumber` check in `Channel.recvService` against a hostile server;
    `Config.max_lifetime_count` below 3× keep-alive overriding §5.13.2's floor.

- **2026-10-06** — **NO CONSUMER-VISIBLE CHANGE:** test fixtures re-taken after montint's
  review fix L2 (Miller-Rabin witnesses now near-uniform over `[2, m − 2]`), which changes
  which prime a seeded `rsa.generate` lands on. The self-derived Basic256Sha256 golden
  (`server_interop.zig`: both 512-bit certificates and the sealed OPN message) is regenerated
  from the same seeds, and `src/testdata/asyncua_transcript.txt` is re-captured against a real
  Python asyncua 2.0.1 peer (`zig build interop-opcua -- --capture`: 7 connections, 1739 steps,
  0 rejected). No opcua code changed.

- **2026-10-03** — **NO CONSUMER-VISIBLE CHANGE:** the asyncua replay
  transcript was re-taken (`zig build interop-opcua -- --capture`, asyncua
  2.0.1, driver exit 0). `rsa.generate`'s new constant-time Miller-Rabin
  (rsa, same day) draws a different number of bytes from the fixture's
  CSPRNG on its way to the SAME key (the `fixture cert_sha256=` line is
  unchanged), which shifted every later draw — the OAEP seeds of the
  asymmetric responses — and broke the byte-for-byte replay in CI.

- **2026-09-10** — **NO CONSUMER-VISIBLE CHANGE:** `decodeArray`/
  `decodeVariantArraySlice` (private, services.zig/encoding.zig) now take a
  `freeItem` so a truncated wire array frees what it already decoded instead
  of leaking it (C4); five `nodestore.zig` `dup*` helpers now free an
  earlier allocating step if a later one fails with OutOfMemory (C7); new
  `pub fn freeRelativePath`/`freeBrowsePath`/`freeBrowsePathResult` fill a
  pre-existing gap (those three types had no free function at all) needed
  to wire C4's fix through `RelativePath`/`BrowsePath`/`BrowsePathResult`
  arrays — additive, nothing existing calls them yet. `Config.max_lifetime_count`
  (new field, default 10 000) caps `CreateSubscription`'s `LifetimeCount`,
  which previously had a floor and no ceiling (C5) — additive default,
  existing callers unaffected. Catalog `.doc` line and `SPEC.md` corrected
  to match the code (C6, C8).
- **2026-09-07** — Both fuzz targets had been running one fixed input for their whole
  existence. `security`'s certificate target was written as an inline
  `struct { fn run … }.run` — the one shape `check-fuzz-reach` reports as UNJUDGED rather
  than judging, and it carried exactly the defect the gate names elsewhere: `smith.bytes(&buf)`
  followed by `smith.valueRangeAtMost(u16, 0, 1024)`, whose ranged draw returns the range
  MINIMUM because `bytes` has already eaten the octets it needs, so `certificatePublicKey`,
  `certificateValidity` and `viewAsymmetricHeader` were each called with the empty slice and
  nothing else. `server`'s `fuzzConnection` was worse: its first draw was `smith.value(bool)`,
  which is a 1-bit range, so `rig.connect()` had **never run once** outside `--fuzz` and the
  service layer the target names was unreachable, while all four of its per-round lengths were
  0 — it fed the connection state machine nothing, four times, from a cold rig. Both are now
  byte-first `smith.slice` draws with a real corpus and a corpus guard; the connection knob
  moved INTO the drawn script (first octet), because a knob drawn after the byte draw is dead
  on a replay. Measured: **certificates 0 of 12 seeds non-empty, 0 parsed, 0 OPN headers
  scanned → 11 of 12 non-empty, 1 parsed, 1 scanned; connection 0 of 8 scripts fed a byte and
  0 replies → 8 of 8 fed, 6 replies, 4 from a live session.** No behavior change.
- **2026-09-07** — The Python `asyncua` interop left the module. It had been a
  ~190-line driver script held as an inline `\\` string literal in
  `src/server_interop.zig` and run with `python3 -c`, so `zig build test-opcua`
  reached for an interpreter and a third-party package the module has no
  business needing, and the anchor skipped — loudly, but skipped — wherever
  either was absent. That is the seventh instance of the shape six modules were
  separated from on 2026-09-06 (`f3dbf38d`, `f42cc67a`); it was missed because
  the other six kept their driver in a FILE, which could be `git mv`'d and was
  therefore visible in the diff, while a string constant moves nowhere.
  `zig build check-module-purity` (`33f26907`) is what named it.
  - The script is now `tools/asyncua_driver.py`, run **from its own path** —
    never embedded, never inlined — by `tools/interop.zig`
    (`zig build interop-opcua`, compiled on every lane by
    `zig build check-interop`).
  - `zig build interop-opcua -- --capture` records the whole exchange into
    `src/testdata/asyncua_transcript.txt`, and the new `src/asyncua_replay.zig`
    replays it **byte for byte with no interpreter, no asyncua, no child process
    and no socket**: seven connections at #None / Basic256Sha256 Sign (encrypted
    username token) / SignAndEncrypt, covering Hello, OpenSecureChannel,
    GetEndpoints, CreateSession, ActivateSession, Browse, Read, Write, Call,
    CreateSubscription, Publish and two mid-stream SecurityToken renewals.
  - Nothing was weakened to make that replayable. The seams were already there:
    `Server.init` takes the `std.Random` it draws from, and `feed`/`tick` take
    time as a parameter, so a recorded seed plus `start_time` plus each `t=`
    fixes the RSA key pair, the certificate, every nonce, token id and
    timestamp. The transcript header carries all of it, plus the asyncua and
    Python versions, the date and the exact command.
  - Coverage went UP, not down. The live test compared ten stdout markers, the
    driver's exit status and a connection count — twelve facts. The replay
    requires every one of the server's 1 734 recorded answers to match exactly
    (which pins Browse, Read, Write, Call and the DataChangeNotification through
    their ciphertext), re-derives each connection's SecurityPolicy/SecurityMode,
    walks the opc.tcp framing of both directions, decodes the endpoint list off
    the unsecured leg and requires our own certificate on the secured
    endpoints, and checks the value asyncua wrote is still in the address space.
    Proved not blind by mutation: a single flipped transcript byte, a dropped
    renewal leg, a falsified SecurityMode and a one-value change to
    `Config.max_chunk_count` each turn it red.
  - What the replay CANNOT do is stated in its own header and in SPEC.md: it
    cannot find a NEW divergence, it cannot tell "we broke interop" from "we
    changed valid bytes", and it cannot re-check anything that was not bytes on
    the wire (asyncua's own assertions and its exit status are kept in the file
    as `#` notes for that reason).
  - Unchanged and deliberately not folded in: the `podman`/open62541 tests still
    run a container. A third-party *server* is a live PEER, not a foreign
    toolchain, and `live` in `build.zig`'s `module_list` is where that question
    is answered.
- **2026-09-02** — Security audit: a plaintext `UserNameIdentityToken` is now
  refused unless the client named a `UserTokenPolicy` this server advertises
  **and** that policy is `#None`. The refusal used to be nested inside
  `if (parsed.policy_id) |pid|` and `if (userTokenPolicy(cfg, pid)) |policy|`,
  both of which fall through when absent — so a token carrying no PolicyId, or
  naming an unadvertised one, had its cleartext password accepted against an
  endpoint whose only username policy demands encryption. The module's own test
  for this passed the one PolicyId that reaches the guard, so it proved the
  branch works without proving the branch is reached.
- **2026-09-02** — Security audit: `SamplingInterval` is clamped at both ends
  (new `Config.max_sampling_interval_ms`). It had a floor and no ceiling, unlike
  `reviseInterval` and `reviseKeepAlive` beside it, so a client-supplied
  `Double` of 1e300 came back verbatim and was then added to a millisecond clock
  as an `i64`: a remote panic in Debug and ReleaseSafe, and in ReleaseFast an
  `i64` poison value that made `now_ms < next_sample_ms` never true — the item
  sampled on EVERY tick while the server reported
  `RevisedSamplingInterval = 1e300`. Asking for the slowest interval got you the
  fastest, the exact inverse of what `min_sampling_interval_ms` enforces. Both
  `CreateMonitoredItems` and `ModifyMonitoredItems` route through the clamp.

- **2026-09-02** — Security audit: **a `SecurityPolicy#None` channel was accepted by
  a server that advertises no `#None` endpoint.** `endpointOffers` — documented as
  "The gate every `OpenSecureChannel` passes through", with `Config.endpoints`
  documented as "**This list is the authority**" and SPEC promising "only
  advertised modes are usable" — was only reached on the secured branch of
  `handleOpenSecureChannel`; the `#None` branch returned before it. A deployment
  built the documented way for security, offering Basic256Sha256 at Sign and
  SignAndEncrypt and nothing else, therefore still accepted a cleartext channel;
  and since `CreateSession` and `ActivateSession` both gate their certificate and
  `ClientSignature` checks on `sec_mode != .none`, both were then skipped, giving
  an anonymous peer Read/Write/Call in the clear. The gate now applies to both
  branches.

- **2026-08-15** — Test-only (no change to the module): the driver rejected a reconnect it
  should have accepted, under load. In one iteration of `Driver.serve` the order was *read
  data → accept → tear down a finished connection*, so when a client's last bytes
  (`CloseSecureChannel`) and its FIN landed in DIFFERENT poll iterations — which contention
  makes likely — the accept branch still saw a non-null `stream` and closed the incoming
  connection. open62541's `client` and `client_encryption` both connect, call GetEndpoints,
  disconnect and reconnect, so both reported `Receiving ACK message failed with
  BadConnectionClosed`. The teardown now runs before the accept branch, so accept decides on
  the current state rather than on state that changes later in the same iteration.

  ⚠ This is the SECOND time closing one hole in this loop opened another: the 2026-08-14
  reorder fixed the case where the close arrives as a 0-byte read in the same poll as the
  next connection, and its comment claimed the failure mode was solved. It was solved for
  one of the two ways to reach it.

  Reproduced deliberately rather than waited for: running the four live modules
  CONCURRENTLY under 7-of-8 cores of load failed 3 of 3 rounds (2, 3 and 2 failures of 176);
  after the fix, 4 of 4 rounds pass 176/176. That condition is what the serial `LIVE_MODULES`
  step had been hiding — and in the same experiment `ssh`, `dtls` and `imap` passed every
  round, so of the four modules quarantined there, only this one had evidence against it.
- **2026-08-15** — Test-only (no change to the module): one live test spent two minutes
  waiting out a backstop. `Driver.serve` could only end early through a CLOSED connection —
  `peer_alive` is consulted in the branch guarded by `stream == null` — and open62541's
  `client_subscription_loop` opens one connection, subscribes and stays, so the question was
  never asked and the loop ran to `deadline_ms = 120_000`. Measured by watching the
  container: alive from t=12 s to t≈120 s of a 177 s module, on every lane and every local
  gate run since the test was written. New `Driver.StopWhen` is asked on a timer regardless
  of connection state, and the subscription test hands it the line its own assertion counts
  (`currentTime has changed`, ×2) — the client's own output rather than a server-side
  publish counter, because the point of driving a third-party client is that it UNDERSTOOD
  what we sent. `deadline_ms` is deliberately unchanged: it is a backstop, and lowering it
  would have hidden this instead of fixing it. **Module: 177 s → 57 s**, 176/176 passing,
  three consecutive runs at 57/57/57 s with no leftover containers.
- **2026-08-13** — Test-only: deleted `test "smoke"` in `src/root.zig`, whose
  whole body was `try std.testing.expect(true);`. **Neither BREAKING nor
  BEHAVIOURAL** — no production code changed. It could not fail, and it
  anchored nothing: `root.zig` is this module's test root, and the aggregation
  `test` at the top of that file is what pulls the submodules' tests in. Its
  only effect was to report a test count one larger than the coverage behind
  it. Deleted rather than given an assertion because the spot has no subject
  of its own — the offline-flow test that follows it is the real smoke test.
  Measured: `zig build test-opcua` went 176/176 to 175/175, the difference
  being exactly this test, with every other test still running and passing.
- **2026-07-19** — Security audit: fixed a memory-safety finding rated CRIT/HIGH (part of
  the collection-wide audit; the root changelog records no further detail
  than this).
