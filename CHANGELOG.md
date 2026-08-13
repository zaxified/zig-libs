# Changelog

**Index only.** This file lists which modules each dated tag touched; the
detail lives in `modules/<name>/CHANGELOG.md`, so a consumer of three modules
reads three files instead of scanning every release section here.

Tags are dates (`YYYY-MM-DD`), not semantic versions, and assert one thing:
every module passed every lane at that commit. Policy and the reasoning —
why semver would be both unenforceable and uninformative here — are in
`CONVENTIONS.md` §8. `v0.1.0` remains as history; nothing after it is a
semantic version.

## Unreleased

The collection grew 77 → 225 modules since v0.1.0, spanning pairing/EC
crypto, Bitcoin/Lightning, post-quantum, FHE/ZK/MPC, protocol security,
distributed fabric and kernel/networking. Every module now carries a
`CHANGELOG.md`, not only the ones with a code change to record: each
one's audit — PASS, findings fixed, or (for the small number rated CRIT)
the fixed defect stated plainly — is itself a maturity fact worth dating,
and a module with no post-creation history still gets its `New module:`
entry so per-module maturity is trackable without the internal audit
directory.

### Modules with a changelog

Each entry below is a one-line pointer; the detail lives in the linked
file. A `BREAKING` tag means the module's own changelog flags at least
one breaking change in its `Unreleased` section. Note that `BEHAVIOURAL,
not breaking` — which four of the middleware entries below carry — is a
different thing and is never tagged `BREAKING` here.

`zig build check-changelog` enforces both halves of this list: a module
changelog with no entry here, an entry here pointing at no file, and a
`BREAKING` tag that disagrees with the module's own `Unreleased` section
all fail the gate. See `CONVENTIONS.md` §8.

- [`aaa-gate`](modules/aaa-gate/CHANGELOG.md) — security audit: two findings
  fixed.
- [`abuseguard`](modules/abuseguard/CHANGELOG.md) — security audit: one
  finding fixed, two accepted as documented trade-offs.
- [`accesslog`](modules/accesslog/CHANGELOG.md) — security audit: one
  finding fixed, one accepted as documented trade-offs.
- [`acme`](modules/acme/CHANGELOG.md) — new `jws.generateKeyPair(io)`;
  both certificate-key draws now fail closed.
- [`adaptor`](modules/adaptor/CHANGELOG.md) — security audit: two findings
  fixed.
- [`aeadframe`](modules/aeadframe/CHANGELOG.md) — security audit: four
  findings fixed.
- [`aescbc`](modules/aescbc/CHANGELOG.md) — security audit: two findings
  fixed, one accepted as documented trade-offs.
- [`aeskw`](modules/aeskw/CHANGELOG.md) — security audit: two findings
  fixed, two accepted as documented trade-offs.
- [`argsafe`](modules/argsafe/CHANGELOG.md) — security audit: one finding
  fixed.
- [`bacnet`](modules/bacnet/CHANGELOG.md) — security audit: unguarded
  wire-integer narrowing (~15 sites) fixed, plus a COV-subscription lifetime
  gap.
- [`bbs`](modules/bbs/CHANGELOG.md) — `proofGen`'s blinding scalars draw
  fail-closed entropy.
- [`bech32`](modules/bech32/CHANGELOG.md) — security audit: two findings
  fixed.
- [`bfv`](modules/bfv/CHANGELOG.md) — **BREAKING** — `keyGen`/`encrypt`/
  `genRelinKey` take `std.Io` instead of `std.Random`; the secret draws
  fail closed.
- [`bip32`](modules/bip32/CHANGELOG.md) — security audit: six findings
  fixed.
- [`bip340`](modules/bip340/CHANGELOG.md) — runtime-tag tagged hash,
  `xonlyBytesOf`.
- [`bitcoinscript`](modules/bitcoinscript/CHANGELOG.md) — security audit:
  matched Core's legacy sighash step exactly; 9 further findings fixed.
- [`bitcointx`](modules/bitcointx/CHANGELOG.md) — security audit: ten
  findings fixed, one accepted as documented trade-offs.
- [`blindrsa`](modules/blindrsa/CHANGELOG.md) — security audit: a reachable
  panic on any non-4096-bit RSA modulus, fixed.
- [`blobmsg`](modules/blobmsg/CHANGELOG.md) — security audit: two findings
  fixed.
- [`blobstore`](modules/blobstore/CHANGELOG.md) — security audit: one
  finding fixed.
- [`bls12_381`](modules/bls12_381/CHANGELOG.md) — `scalar.Fr.random`
  draws fail-closed entropy.
- [`bn254`](modules/bn254/CHANGELOG.md) — security audit: five findings
  fixed, four accepted as documented trade-offs.
- [`bolt3`](modules/bolt3/CHANGELOG.md) — security audit: no findings.
- [`bolt8`](modules/bolt8/CHANGELOG.md) — security audit: one finding fixed.
- [`brotli`](modules/brotli/CHANGELOG.md) — encoder now actually
  compresses (LZ77 + Huffman).
- [`btcp2p`](modules/btcp2p/CHANGELOG.md) — security audit: four findings
  fixed.
- [`bulletproofs`](modules/bulletproofs/CHANGELOG.md) — security audit:
  three findings fixed.
- [`bumtree`](modules/bumtree/CHANGELOG.md) — security audit: three findings
  fixed, two accepted as documented trade-offs.
- [`cbor`](modules/cbor/CHANGELOG.md) — security audit: five findings fixed.
- [`chachapoly`](modules/chachapoly/CHANGELOG.md) — SIMD implementation
  (performance campaign).
- [`coap`](modules/coap/CHANGELOG.md) — security audit: one finding fixed,
  one accepted as documented trade-offs.
- [`coconut`](modules/coconut/CHANGELOG.md) — **BREAKING** — `keygen`/
  `proveCredential` take `std.Io` instead of `std.Random`; the secret
  draws fail closed.
- [`conntrack`](modules/conntrack/CHANGELOG.md) — security audit: six
  findings fixed.
- [`cookies`](modules/cookies/CHANGELOG.md) — **BREAKING** — `set` no
  longer takes a caller-supplied buffer; new `max_set_cookie_bytes`.
- [`cors`](modules/cors/CHANGELOG.md) — BEHAVIOURAL, not breaking: the
  204 preflight no longer forces an early `ResponseWriter.end()`.
- [`csvsafe`](modules/csvsafe/CHANGELOG.md) — security-audit fix.
- [`csvstream`](modules/csvstream/CHANGELOG.md) — security audit: three
  findings fixed.
- [`ct25519`](modules/ct25519/CHANGELOG.md) — security audit: six findings
  fixed.
- [`ctap2pin`](modules/ctap2pin/CHANGELOG.md) — security audit: no findings.
- [`dataset`](modules/dataset/CHANGELOG.md) — security audit: two findings
  fixed.
- [`datefmt`](modules/datefmt/CHANGELOG.md) — security audit: no findings.
- [`decaf448`](modules/decaf448/CHANGELOG.md) — security audit: no findings.
- [`decimal`](modules/decimal/CHANGELOG.md) — `Decimal`/`BigDecimal`
  interop, new `BigDecimal` ops.
- [`devlink`](modules/devlink/CHANGELOG.md) — security audit: six findings
  fixed.
- [`df-elect`](modules/df-elect/CHANGELOG.md) — security audit: two findings
  fixed.
- [`diagnostics`](modules/diagnostics/CHANGELOG.md) — security audit: no
  findings.
- [`dkg`](modules/dkg/CHANGELOG.md) — security audit: two findings fixed.
- [`dnp3`](modules/dnp3/CHANGELOG.md) — security-audit memory-safety fix.
- [`dns`](modules/dns/CHANGELOG.md) — security audit: one finding fixed.
- [`dnssec`](modules/dnssec/CHANGELOG.md) — security-audit memory-safety
  fix.
- [`drand`](modules/drand/CHANGELOG.md) — security audit: a missing subgroup
  check let a beacon signature be malleated; fixed.
- [`dtls`](modules/dtls/CHANGELOG.md) — **BREAKING** — HRR (both sides),
  fragment reassembly, live wolfSSL interop, negotiated
  `signature_algorithms`, anti-replay-window fix.
- [`ebpf`](modules/ebpf/CHANGELOG.md) — security audit: six findings fixed.
- [`ecvrf`](modules/ecvrf/CHANGELOG.md) — security audit: no findings.
- [`ed448`](modules/ed448/CHANGELOG.md) — both `KeyPair.generate` entry
  points draw a fail-closed seed.
- [`encoding`](modules/encoding/CHANGELOG.md) — security audit: one finding
  fixed.
- [`enip`](modules/enip/CHANGELOG.md) — security audit: seven findings
  fixed.
- [`entropy`](modules/entropy/CHANGELOG.md) — new: the fail-closed
  `fill`/`SecureSource` source for secret-bearing draws
  (`CONVENTIONS.md` §2.2).
- [`ethfrag`](modules/ethfrag/CHANGELOG.md) — security audit: one finding
  fixed.
- [`ethtool`](modules/ethtool/CHANGELOG.md) — security audit: five findings
  fixed, one accepted as documented trade-offs.
- [`falcon`](modules/falcon/CHANGELOG.md) — security audit: two findings
  fixed, one accepted as documented trade-offs.
- [`filestore`](modules/filestore/CHANGELOG.md) — security audit: no
  findings.
- [`finstats`](modules/finstats/CHANGELOG.md) — security audit: one finding
  fixed.
- [`fleetsim`](modules/fleetsim/CHANGELOG.md) — security audit: seven
  findings fixed, one accepted as documented trade-offs.
- [`framing`](modules/framing/CHANGELOG.md) — security audit: one finding
  fixed.
- [`frost`](modules/frost/CHANGELOG.md) — security audit: no findings.
- [`fss`](modules/fss/CHANGELOG.md) — **BREAKING** — default PRG swapped
  to fixed-key AES-128; `evalFull` for `Dpf`/`Mpf`.
- [`fuzzysearch`](modules/fuzzysearch/CHANGELOG.md) — security audit: no
  findings.
- [`genetlink`](modules/genetlink/CHANGELOG.md) — security audit: no
  findings.
- [`geoindex`](modules/geoindex/CHANGELOG.md) — security audit: no findings.
- [`groth16`](modules/groth16/CHANGELOG.md) — security audit: two findings
  fixed.
- [`grpc`](modules/grpc/CHANGELOG.md) — new: gRPC client over HTTP/2.
- [`hashdigest`](modules/hashdigest/CHANGELOG.md) — security audit: no
  findings.
- [`health`](modules/health/CHANGELOG.md) — security audit: two findings
  fixed.
- [`hpke`](modules/hpke/CHANGELOG.md) — **BREAKING** — RFC 9180 Appendix A
  vectors; PSK length floor.
- [`hqc`](modules/hqc/CHANGELOG.md) — security audit: two findings fixed.
- [`http`](modules/http/CHANGELOG.md) — **BREAKING** header/trailer
  bytes are copied (use-after-scope fix); new
  `error.HeaderBytesExhausted`.
- [`ibe`](modules/ibe/CHANGELOG.md) — `ciphersuite.randomSigma` draws
  fail-closed entropy; the master secret key follows `bls12_381`.
- [`icmp`](modules/icmp/CHANGELOG.md) — security audit: two findings fixed.
- [`idempotency`](modules/idempotency/CHANGELOG.md) — security audit: two
  findings fixed.
- [`iec104`](modules/iec104/CHANGELOG.md) — security audit: six findings
  fixed.
- [`iec61850`](modules/iec61850/CHANGELOG.md) — security audit: six findings
  fixed, one accepted as documented trade-offs.
- [`iec62351`](modules/iec62351/CHANGELOG.md) — security audit: four
  findings fixed, two accepted as documented trade-offs.
- [`imap`](modules/imap/CHANGELOG.md) — security audit: a CRLF
  command-injection gap in the write path, and missing STARTTLS, fixed.
- [`ipcbus`](modules/ipcbus/CHANGELOG.md) — security audit: one finding
  fixed, one accepted as documented trade-offs.
- [`isis`](modules/isis/CHANGELOG.md) — security audit: five findings fixed.
- [`isis-adj`](modules/isis-adj/CHANGELOG.md) — security audit: five
  findings fixed.
- [`isis-dis`](modules/isis-dis/CHANGELOG.md) — security audit: three
  findings fixed, one accepted as documented trade-offs.
- [`isis-flood`](modules/isis-flood/CHANGELOG.md) — security audit: the
  flooding scheduler understated LSP-database coverage above 256 entries;
  fixed.
- [`isis-lsdb`](modules/isis-lsdb/CHANGELOG.md) — security audit: missing
  ISO 10589 receive-side defences against an unauthenticated peer, fixed (8
  findings).
- [`isis-sim`](modules/isis-sim/CHANGELOG.md) — security audit: five
  findings fixed, one accepted as documented trade-offs.
- [`isis-spf`](modules/isis-spf/CHANGELOG.md) — security audit: six findings
  fixed.
- [`jinja`](modules/jinja/CHANGELOG.md) — security audit: an autoescape
  bypass and an allocation-overflow guard fixed, among 12 findings.
- [`jobqueue`](modules/jobqueue/CHANGELOG.md) — security audit: one finding
  fixed.
- [`json5`](modules/json5/CHANGELOG.md) — security-audit fix.
- [`jsonshape`](modules/jsonshape/CHANGELOG.md) — security audit: one
  finding fixed.
- [`jwe`](modules/jwe/CHANGELOG.md) — security audit: two findings fixed,
  one accepted as documented trade-offs.
- [`jwt`](modules/jwt/CHANGELOG.md) — security audit: the `crit` header and
  OIDC `azp` gaps, fixed.
- [`k256`](modules/k256/CHANGELOG.md) — new `ecdsa_recover`; asm/Montgomery
  core (performance campaign).
- [`kv`](modules/kv/CHANGELOG.md) — security audit: four findings fixed.
- [`kvtree`](modules/kvtree/CHANGELOG.md) — security audit: three findings
  fixed.
- [`l2disco`](modules/l2disco/CHANGELOG.md) — security audit: two findings
  fixed.
- [`l2encap`](modules/l2encap/CHANGELOG.md) — security audit: four findings
  fixed, one accepted as documented trade-offs.
- [`l2forward`](modules/l2forward/CHANGELOG.md) — security audit: seven
  findings fixed, one accepted as documented trade-offs.
- [`latency-stats`](modules/latency-stats/CHANGELOG.md) — security audit: no
  findings.
- [`linkheader`](modules/linkheader/CHANGELOG.md) — security audit: no
  findings.
- [`liveness-hyst`](modules/liveness-hyst/CHANGELOG.md) — security audit:
  two findings fixed.
- [`llmclient`](modules/llmclient/CHANGELOG.md) — security audit: one
  finding fixed.
- [`lninvoice`](modules/lninvoice/CHANGELOG.md) — ECDSA
  sign/recover moved to `k256`, re-exported.
- [`lnwire`](modules/lnwire/CHANGELOG.md) — security audit: five findings
  fixed, one accepted as documented trade-offs.
- [`lockfree`](modules/lockfree/CHANGELOG.md) — security audit: three
  findings fixed, one accepted as documented trade-offs.
- [`loopfree-reconv`](modules/loopfree-reconv/CHANGELOG.md) — security
  audit: two findings fixed.
- [`loopix`](modules/loopix/CHANGELOG.md) — security audit: two findings
  fixed, one accepted as documented trade-offs.
- [`mcp`](modules/mcp/CHANGELOG.md) — server→client requests (sampling,
  elicitation); JSON-RPC fixes; security-audit fix.
- [`mcp-http`](modules/mcp-http/CHANGELOG.md) — transport half of `mcp`'s
  server→client requests; `application/json` body fix.
- [`megolm`](modules/megolm/CHANGELOG.md) — new: Matrix's Megolm group
  ratchet.
- [`metrics`](modules/metrics/CHANGELOG.md) — security audit: two findings
  fixed, one accepted as documented trade-offs.
- [`minisign`](modules/minisign/CHANGELOG.md) — new: minisign file-format
  sign/verify.
- [`mls`](modules/mls/CHANGELOG.md) — external Commits (RFC 9420
  §12.4.3.2).
- [`modbus`](modules/modbus/CHANGELOG.md) — security audit: two findings
  fixed.
- [`montint`](modules/montint/CHANGELOG.md) — timing fix (Montgomery
  final-subtraction leak on the portable path); asm/Montgomery core
  (performance campaign).
- [`mqtt`](modules/mqtt/CHANGELOG.md) — security audit: two findings fixed,
  one accepted as documented trade-offs.
- [`musig2`](modules/musig2/CHANGELOG.md) — security audit: no findings.
- [`netaddr`](modules/netaddr/CHANGELOG.md) — security audit: three findings
  fixed.
- [`netconf`](modules/netconf/CHANGELOG.md) — security audit: a quadratic
  chunked-framer DoS (159s to 0.015s) fixed, among 6 findings.
- [`netlink`](modules/netlink/CHANGELOG.md) — security audit: three findings
  fixed.
- [`netsim`](modules/netsim/CHANGELOG.md) — security audit: three findings
  fixed.
- [`nftables`](modules/nftables/CHANGELOG.md) — security audit: three
  findings fixed.
- [`nl80211`](modules/nl80211/CHANGELOG.md) — security audit: six findings
  fixed, one accepted as documented trade-offs.
- [`noise`](modules/noise/CHANGELOG.md) — security audit: one finding fixed.
- [`numparse`](modules/numparse/CHANGELOG.md) — security audit: one finding
  fixed, one accepted as documented trade-offs.
- [`ocsp`](modules/ocsp/CHANGELOG.md) — security audit: seven findings
  fixed.
- [`ocspcache`](modules/ocspcache/CHANGELOG.md) — security audit: six
  findings fixed, one accepted as documented trade-offs.
- [`opaque`](modules/opaque/CHANGELOG.md) — security audit: no findings.
- [`opcua`](modules/opcua/CHANGELOG.md) — security-audit memory-safety
  fix.
- [`openapi`](modules/openapi/CHANGELOG.md) — security audit: one finding
  fixed.
- [`oscore`](modules/oscore/CHANGELOG.md) — security audit: one finding
  fixed.
- [`otp`](modules/otp/CHANGELOG.md) — security audit: one finding fixed.
- [`p256`](modules/p256/CHANGELOG.md) — asm/Montgomery core (performance
  campaign).
- [`pagecache`](modules/pagecache/CHANGELOG.md) — security audit: six
  findings fixed.
- [`paillier`](modules/paillier/CHANGELOG.md) — security audit: two findings
  fixed, one accepted as documented trade-offs.
- [`pbb`](modules/pbb/CHANGELOG.md) — security audit: four findings fixed.
- [`pir`](modules/pir/CHANGELOG.md) — malicious-server detection
  (`Verified`); keyword lookup.
- [`pollworker`](modules/pollworker/CHANGELOG.md) — security audit: one
  finding fixed.
- [`poseidon`](modules/poseidon/CHANGELOG.md) — new: Poseidon ZK-friendly
  hash over `bn254`/`bls12_381`.
- [`pping`](modules/pping/CHANGELOG.md) — security audit: one finding fixed.
- [`probe`](modules/probe/CHANGELOG.md) — security audit: one finding fixed.
- [`procnet`](modules/procnet/CHANGELOG.md) — security audit: three findings
  fixed, one accepted as documented trade-offs.
- [`procrun`](modules/procrun/CHANGELOG.md) — security audit: two findings
  fixed.
- [`protobuf`](modules/protobuf/CHANGELOG.md) — security audit: four
  findings fixed, one accepted as documented trade-offs.
- [`psbt`](modules/psbt/CHANGELOG.md) — security audit: six findings fixed.
- [`quic-crypto`](modules/quic-crypto/CHANGELOG.md) — security audit: no
  findings.
- [`raft`](modules/raft/CHANGELOG.md) — security audit: three findings
  fixed, one accepted as documented trade-offs.
- [`ramcache`](modules/ramcache/CHANGELOG.md) — new thread-safe `Sharded`
  option.
- [`ratelimit`](modules/ratelimit/CHANGELOG.md) — BEHAVIOURAL, not
  breaking: the 429 deny path no longer forces an early
  `ResponseWriter.end()`.
- [`rawsock`](modules/rawsock/CHANGELOG.md) — security audit: no findings.
- [`rbac`](modules/rbac/CHANGELOG.md) — security audit: no findings.
- [`rdap`](modules/rdap/CHANGELOG.md) — security audit: one finding fixed.
- [`readthrough`](modules/readthrough/CHANGELOG.md) — security audit: five
  findings fixed.
- [`reconcilable`](modules/reconcilable/CHANGELOG.md) — security audit: five
  findings fixed.
- [`requestid`](modules/requestid/CHANGELOG.md) — security audit: one
  finding fixed.
- [`rescue`](modules/rescue/CHANGELOG.md) — new: Rescue-Prime Optimized
  over Goldilocks.
- [`resilience`](modules/resilience/CHANGELOG.md) — security audit: two
  findings fixed, one accepted as documented trade-offs.
- [`ripemd160`](modules/ripemd160/CHANGELOG.md) — security audit: one
  finding fixed, two accepted as documented trade-offs.
- [`router`](modules/router/CHANGELOG.md) — BEHAVIOURAL, not breaking:
  the trailing-slash redirect no longer forces an early
  `ResponseWriter.end()`.
- [`rsa`](modules/rsa/CHANGELOG.md) — security audit: four findings fixed,
  one accepted as documented trade-offs.
- [`s7comm`](modules/s7comm/CHANGELOG.md) — security audit: an
  unauthenticated out-of-bounds read in Read Var handling, fixed.
- [`saml`](modules/saml/CHANGELOG.md) — **BREAKING** — cross-form
  Holder-of-Key confirmation.
- [`sandbox`](modules/sandbox/CHANGELOG.md) — security audit: no findings.
- [`sealedbox`](modules/sealedbox/CHANGELOG.md) — security audit: no
  findings.
- [`security-headers`](modules/security-headers/CHANGELOG.md) —
  **BREAKING** — `init` now fallible, rejects a CSP that would exceed
  `http`'s header-byte budget at config time instead of 500ing at
  request time.
- [`seqmap`](modules/seqmap/CHANGELOG.md) — security audit: one finding
  fixed.
- [`sessions`](modules/sessions/CHANGELOG.md) — `Manager.newId` mints
  every session id from fail-closed entropy.
- [`shardstore`](modules/shardstore/CHANGELOG.md) — security audit: five
  findings fixed.
- [`signal`](modules/signal/CHANGELOG.md) — new
  `x3dh.generateKeyPair(io)`; all four production key draws fail closed.
- [`slhdsa`](modules/slhdsa/CHANGELOG.md) — security audit: one finding
  fixed.
- [`smtp`](modules/smtp/CHANGELOG.md) — security audit: five findings fixed.
- [`snmp`](modules/snmp/CHANGELOG.md) — **BREAKING** — library-generated
  USM privacy salt.
- [`sntp`](modules/sntp/CHANGELOG.md) — security audit: two findings fixed,
  one accepted as documented trade-offs.
- [`spake2plus`](modules/spake2plus/CHANGELOG.md) — security audit: one
  finding fixed.
- [`spbfib`](modules/spbfib/CHANGELOG.md) — security audit: no findings.
- [`spf-ect`](modules/spf-ect/CHANGELOG.md) — security audit: four findings
  fixed.
- [`sphinx`](modules/sphinx/CHANGELOG.md) — security audit: no findings.
- [`ssh`](modules/ssh/CHANGELOG.md) — security audit: six findings fixed.
- [`staticfiles`](modules/staticfiles/CHANGELOG.md) — security audit: one
  finding fixed.
- [`stun`](modules/stun/CHANGELOG.md) — security-audit memory-safety fix.
- [`syslog`](modules/syslog/CHANGELOG.md) — security audit: two findings
  fixed.
- [`tabular`](modules/tabular/CHANGELOG.md) — security audit: zero findings
  fixed, two accepted as documented trade-offs.
- [`taproot`](modules/taproot/CHANGELOG.md) — security audit: no findings.
- [`tar`](modules/tar/CHANGELOG.md) — security audit: a base-256 size-field
  integer overflow (DoS), fixed the same day.
- [`tc`](modules/tc/CHANGELOG.md) — security audit: three findings fixed.
- [`tcplan`](modules/tcplan/CHANGELOG.md) — security audit: no findings.
- [`tenantkex`](modules/tenantkex/CHANGELOG.md) — security audit: four
  findings fixed.
- [`testkit`](modules/testkit/CHANGELOG.md) — security audit: no findings.
- [`tfhe`](modules/tfhe/CHANGELOG.md) — **BREAKING** — keygen/encrypt entry
  points take `std.Io` instead of `std.Random`; the secret draws fail
  closed.
- [`threshold_ecdsa`](modules/threshold_ecdsa/CHANGELOG.md) —
  **BREAKING** — Paillier generator bound into Fiat-Shamir transcript.
- [`throttle`](modules/throttle/CHANGELOG.md) — BEHAVIOURAL, not
  breaking: the 503 shed path no longer forces an early
  `ResponseWriter.end()`.
- [`timelock_envelope`](modules/timelock_envelope/CHANGELOG.md) —
  `SealRandomness.generate` draws all three values fail-closed.
- [`tlock`](modules/tlock/CHANGELOG.md) — `ciphersuite.randomSigma`
  draws fail-closed entropy.
- [`tlsresume`](modules/tlsresume/CHANGELOG.md) — security audit: zero
  findings fixed, one accepted as documented trade-offs.
- [`tracecontext`](modules/tracecontext/CHANGELOG.md) — security audit: two
  findings fixed.
- [`traceroute`](modules/traceroute/CHANGELOG.md) — security audit: no
  findings.
- [`trie`](modules/trie/CHANGELOG.md) — security audit: no findings.
- [`tsdb`](modules/tsdb/CHANGELOG.md) — new: time-series persistence over
  `kvtree`.
- [`tz`](modules/tz/CHANGELOG.md) — security audit: no findings.
- [`uci`](modules/uci/CHANGELOG.md) — security audit: two findings fixed.
- [`upstream`](modules/upstream/CHANGELOG.md) — security audit: one finding
  fixed.
- [`validate`](modules/validate/CHANGELOG.md) — security-audit O(n²)-DoS
  hardening.
- [`vdf`](modules/vdf/CHANGELOG.md) — security audit: two findings fixed,
  one accepted as documented trade-offs.
- [`voprf`](modules/voprf/CHANGELOG.md) — security audit: no findings.
- [`webauthn`](modules/webauthn/CHANGELOG.md) — security audit: an
  attacker-supplied certificate could abort the process; fixed via this
  repo's defensive x509 parser.
- [`webhooksig`](modules/webhooksig/CHANGELOG.md) — security audit: one
  finding fixed.
- [`websocket`](modules/websocket/CHANGELOG.md) — security audit: six
  findings fixed.
- [`whois`](modules/whois/CHANGELOG.md) — security audit: one finding fixed.
- [`wireguard`](modules/wireguard/CHANGELOG.md) — `Keypair.generate` and
  `CookieChecker`'s three draws fail closed.
- [`workerpool`](modules/workerpool/CHANGELOG.md) — security audit: six
  findings fixed.
- [`writebehind`](modules/writebehind/CHANGELOG.md) — security audit: five
  findings fixed.
- [`x509`](modules/x509/CHANGELOG.md) — new `spkiOf`; security-audit
  memory-safety fix.
- [`xdp-classifier`](modules/xdp-classifier/CHANGELOG.md) — security audit:
  one finding fixed.
- [`xml`](modules/xml/CHANGELOG.md) — security audit: three findings fixed.
- [`xmldsig`](modules/xmldsig/CHANGELOG.md) — security audit: five findings
  fixed.
- [`xmlenc`](modules/xmlenc/CHANGELOG.md) — security audit: five findings
  fixed.
- [`xmss`](modules/xmss/CHANGELOG.md) — security audit: two findings fixed,
  one accepted as documented trade-offs.
- [`yaml`](modules/yaml/CHANGELOG.md) — security audit: five findings fixed.
- [`zipstream`](modules/zipstream/CHANGELOG.md) — security-audit fix.

### Collection-wide notes (belong to no single module)

- **Security audit:** all CRIT/HIGH findings from a collection-wide audit
  were fixed. Findings named for a specific module are indexed above and
  detailed in that module's own changelog; this line is the pointer for
  the audit as a whole.
- **Performance campaign:** in addition to the per-module wins indexed
  above, audited hot paths across the collection landed within ~≤3× of C
  peers, and several constant-time leaks were fixed, in modules not
  individually named for either.
- **Tooling:** `zig build check-catalog` consistency gate added (found
  and fixed 6 modules missing README catalog rows), and
  `zig build check-changelog` for this index (found 16 module changelogs
  it had never listed — nothing had ever checked it).
- **Policy:** dated-tag versioning + spin-off policy adopted
  (`CONVENTIONS.md` §8); this changelog split is one product of it.

## v0.1.0 — 2026-07-10

Initial public release: 77 modules, 1844 tests, CI green in Debug +
ReleaseFast, MIT (fping-lineage attribution preserved in `NOTICE` §1).
