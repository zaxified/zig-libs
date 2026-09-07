# snmp — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — Fuzz reach: all three harnesses (`message.fuzzDecode`, `usm.fuzzParse`,
  `v3.fuzzDecode`) ran on the empty datagram, for ever. Each opened with `smith.bytes(&buf)`
  followed by `smith.valueRangeAtMost(u16, 0, buf.len)`; a ranged draw reads eight octets as a
  little-endian u64 and returns the range MINIMUM when fewer than eight remain, and `bytes` had
  already consumed the seed — so `len` was **0 on every input** and each decoder failed on its
  first `expect(sequence)`. Nothing behind that line was reachable: in `message` the varbind
  walk (which is LAZY, so a message decoding says nothing about it); in `usm` the two INTEGER
  range checks the 2026-09-02 audit added, whose absence turned one spoofed datagram into a
  permanent denial; in `v3` the flag octet, the security model and the msgData CHOICE that
  decides whether attacker bytes reach the decryptor. All three now draw with one
  `smith.slice(&buf)` and carry a corpus built by this module's own `encode` (the accepted
  half) plus hand-written BER for the refusals, with a guard pinning two measured numbers.
  Before → after: `message.fuzzDecode` 0/12 seeds non-empty, 0 decoded, 0 varbinds walked →
  11/12 (one is the empty datagram on purpose), 8 decoded, 9 varbinds and 1 iterator refusal;
  `usm.fuzzParse` 0/11 and 0 parsed → 10/11 and 4 parsed, 36 HMAC octets seen;
  `v3.fuzzDecode` 0/11 and 0 decoded → 10/11 and 4 decoded, 3 plaintext and 1 encryptedPDU.

- **2026-09-02** — **Audit (drift campaign): 1 HIGH, 4 LOW fixed.**
  **HIGH — `msgFlags.privFlag` did not select the ScopedPduData branch; the msgData TLV *tag*
  did.** RFC 3412 §7.2 step 5 makes the flag the selector, and the previous audit's fix checked
  only the flag PAIR (`priv and !auth`), so both mismatch directions were open. privFlag set with
  a plaintext `SEQUENCE` was taken as authPriv **data** — an adversary holding only the auth key
  could read and inject at authPriv, a privacy downgrade that looked like a normal reply. privFlag
  clear with an OCTET STRING was taken as `.encrypted`, so **unauthenticated** bytes reached
  `priv.decryptScopedPdu` under the real localized key with an attacker-chosen IV (boots, time and
  salt all come from the unauthenticated USM params). The second one was measured as a live
  oracle: 20 000 random ciphertexts produced 8 distinct typed-error classes, identical in Debug
  and ReleaseFast. SPEC.md already said in as many words that an unauthenticated "encrypted"
  message must not be decrypted even as an oracle; nothing implemented it. Both directions are
  `error.SecurityLevelMismatch` now.
  **LOW — `msgAuthoritativeEngineBoots`/`Time` were not range-checked** against RFC 3414 §2.2's
  `INTEGER (0..2147483647)`, and the anti-replay escape hatch ("boots at the ceiling ⇒ always out
  of window") was written `== max_boots`, so a spoofed `0xFFFFFFFF` stepped over it: one
  unauthenticated discovery Report seeded the client's clock and every genuine reply after it was
  `NotInTimeWindow`, permanently. Range enforced at `parse`, and the ceiling comparison widened to
  `>=` as a second lock. ⚠ A round-trip test asserted the out-of-range value survives `parse` —
  it was pinning the defect, and is corrected.
  **LOW — `usm.verify`/`usm.sign` accepted a zero-length localized key**, so a digest signed with
  `""` verified against `""`: the pair failed open together, while the privacy layer beside them
  has always returned `KeyTooShort`. `sign` is fallible now.
  **LOW — `computeDigestInto`'s out-buffer guard was `std.debug.assert`.** Measured in ReleaseFast
  with a 4-byte buffer for a 12-byte digest: it returned 12 bytes and wrote 8 of them past the
  slice, no error. It is a `pub` entry point; the check is real now (`BufferTooSmall`).
  **LOW — the catalog cell outlived the code**: `meta.doc` (the rendered source of truth) still
  said "privacy crypto in progress" while RFC 7860 SHA-224/256/384/512 and DES-CBC + AES-128-CFB
  ship, KAT- and net-snmp-anchored.
  Every fix carries a regression test that goes red when the fix is reverted. Ledger:
  `~/CML/20260931-zig-libs-audit/snmp.md`.

- **2026-08-23** — **Behavioural:** `TransportError` gains `Canceled`, and
  `UdpTransport.exchangeFn` recovers it from `Socket.send`/`.receiveTimeout`
  instead of folding every failure into `TransportFailed`. A canceled
  request was indistinguishable from a dead agent, so a consumer retried a
  request its own caller had already abandoned. `snmp` was the last sibling
  of the module-wide cancelation campaign that fixed nine modules and missed
  `whois` (fixed this morning); this closes the same gap here. Unlike
  `whois`'s buffered TCP reader/writer, `std.Io.net.Socket.send`/
  `.receiveTimeout` report `Canceled` directly (`Io.Cancelable` is part of
  their own error sets), so no concrete-reader recovery dance was needed.
  Covered by a loopback test that parks a real receive against a bound UDP
  peer that never replies; mutation-confirmed by folding the two `catch`es
  back and watching the test report `TransportFailed`.
- **2026-08-12** — **BREAKING:** `V3Client.Options.initial_salt: ?u64` is replaced by
  `V3Client.Options.salt_seed: ?SaltSeed`, a tagged union with a `.csprng`
  arm and a `.fixed_for_test` arm. The privacy-salt counter is no longer
  seeded from the engine's discovered `engineBoots‖engineTime` — those are
  public clock/boot registers, identical for every manager polling that
  engine, and RFC 3414 §2.6 key localization puts nothing per-client into
  the localized privacy key, so two managers that reached their first
  authPriv message in the same engine second emitted the same IV sequence
  under the same key. New `error.SaltSeedRequired`: a client whose
  `salt_seed` is `null` refuses to send authPriv rather than starting the
  counter from a number an attacker can read off the wire. `null` stays
  legal for noAuthNoPriv/authNoPriv clients, which never encrypt.
  Rationale and the per-mode consequence (AES-CFB leaks `P1 XOR P2`;
  DES-CBC leaks only block-prefix equality) are in `modules/snmp/SPEC.md`.
  The entry below is superseded on its `initial_salt` sentence.

- **2026-08-11** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against RFC
  3414's published test vectors.
- **2026-07-28** — The USM privacy salt (`msgPrivacyParameters`) is now generated by the
  library instead of being a caller obligation. **BREAKING:**
  `priv.encrypt` no longer takes a salt — it takes a `priv.SaltSource`
  and returns `priv.Encrypted { ciphertext, salt }`, the salt being an
  *output* for the USM header. The default `SaltSource.counter(seed)` is
  a never-repeating counter shaped per RFC 3826 §3.3.1 (AES) / RFC 3414
  §8.1.1.1 (DES), so no call shape can repeat a salt on live traffic;
  pinning one for a published KAT or a captured datagram is the explicit
  opt-in `SaltSource.fixedForInterop`. New errors `error.SaltReuse` (an
  IV identical to the immediately preceding one — an adjacent-repeat
  tripwire, not full history) and `error.SaltExhausted` (DES has only
  2^32 salts per `snmpEngineBoots` epoch; it refuses rather than
  wrapping). **BREAKING:** `V3Client.Options.initial_salt` is now `?u64`,
  defaulting to `null` = seed the counter from the engine's discovered
  `engineBoots‖engineTime`, so a client restart does not resume the
  counter from a fixed constant. `priv.decrypt` is unchanged (its salt
  comes off the wire). Scope and limits documented in
  `modules/snmp/SPEC.md`.
