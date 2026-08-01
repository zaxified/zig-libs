# iec62351 — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see this module's README "Provenance" note — clean-room, so there is deliberately no root `/NOTICE` entry to point at (root `NOTICE` §0).

## Design & invariants

### The layering decision: no dependency on `iec61850`

IEC 62351-6 is a *wrapper* around an IEC 61850-8-1/9-2 frame; 62351-4 is three
*additional fields* in an ACSE association PDU; 62351-3 is a *constraint* on a
TLS session negotiated elsewhere. In all three cases the secured protocol is
someone else's, so this module takes the encoded bytes as input and never
decodes them. The seam is a `[]const u8`.

That is not only cleaner, it is what makes the module useful: the same
`goose.verify` runs over a frame from `iec61850`, a frame from a vendor IED and
a frame lifted out of a `.pcap`. It also keeps two modules that are edited
independently from sharing a compile-time surface.

### The covered range, and why it is one function

`goose.Frame.macDomain()` is the only expression of the authenticated range in
the module: the EtherType field through the end of the APDU. Everything else —
`build`, `verify`, `computeMac`, the KAT vectors, the raw seam — calls it.

Three properties are enforced rather than commented:

1. **The header is inside the range.** `Length`, `Reserved 1` and `Reserved 2`
   describe where the APDU stops and the Extension starts. `build` writes them
   with their *final* values (Length already counting the extension, the flag
   already set, the extension length already stored) and only then computes the
   tag. If they were outside the range, or filled in afterwards, an attacker
   who can rewrite two octets could move the APDU/Extension boundary and keep a
   valid tag. Test: `header: Length counts the extension, ...` plus
   `negative: a tampered header octet inside the domain fails`.
2. **The range is derived from `Length`, never from the buffer.** A GOOSE frame
   is padded to the Ethernet minimum; `parse` slices the frame at
   `2 + Length` and ignores the rest. Test: `negative: Ethernet padding is
   excluded from the covered range`.
3. **The classic two-octet shift is a test, not a comment.** Starting at APPID
   instead of at the EtherType produces a tag that must not verify. Test:
   `negative: a tag computed over a shifted range does not verify`. The same
   test also checks a range extended one octet *into* the extension.

### Constant-time comparison

Every tag comparison goes through `goose.constantTimeEql`, which dispatches to
`std.crypto.timing_safe.eql` for the fixed sizes this module emits (8, 10, 16,
32, 64) and falls back to an accumulate-XOR loop for other lengths (an RSA
signature). `std.mem.eql` is never used on a tag. The length check that
precedes it is not secret — the tag length is visible in the frame header.
`acse.passwordMatches` hashes both sides with SHA-256 before comparing, which
removes the length dependence as well as the content one.

`RawVerifier` implementations are the caller's; the doc comment requires them
to compare in constant time and exports `constantTimeEql` for the purpose.

### The replay guards are pure and time-injected

No thread, no timer, no clock read anywhere in `replay.zig`; `now_ns` is a
parameter. `check` is a pure function of (state, input, now) and mutates
nothing, `accept` is `check` plus a commit on success. A rejection therefore
provably cannot disturb the stored state — asserted directly in
`GOOSE: a replayed frame is rejected` and in the fuzz property.

Two design decisions inside are worth an auditor's attention, because getting
either wrong produces a guard that looks correct and fails in production:

- **`t` is checked for age only when `stNum` advances.** GOOSE `t` is the time
  of the last state change, not of the current frame. A publisher retransmits
  an unchanged state with an increasing `sqNum` and an unchanged `t`, so on a
  slow-moving signal `t` is legitimately hours old. A naive freshness window on
  every frame rejects healthy traffic. The compensating check is
  `require_stable_timestamp`: `t` must *not* move while `stNum` stands still.
- **Ordering is RFC 1982 serial arithmetic by default.** IEC 61850-8-1 wraps
  both counters from the maximum back to 1. Plain `>` turns that wrap into a
  permanent rejection and wedges the subscriber. The documented cost is that an
  attacker able to jump the counter by more than 2^31 gets a fresh start;
  `allow_stnum_wrap` / `allow_sqnum_wrap` = `false` buys strict ordering back.

Sampled Values get much less: SV PDUs carry no timestamp, so `SvGuard` can only
enforce a forward-moving `smpCnt` inside a bounded window, a stable `confRev`,
optional `smpSynch`, and an idle-gap ceiling the caller must set. This is
stated in the type's doc comment rather than implied by its existence.

### The BER reader is small and strict on purpose

`ber.zig` accepts definite lengths only, single-octet tags only, and minimal
length encodings only, and bounds-checks every content slice before producing
it. Both the GOOSE extension and the ACSE fields need exactly that much ASN.1.
Being stricter than a general decoder is a feature here: one encoding maps to
one length, so a re-encode is byte-exact and a length that overruns is a typed
error.

### Guarding `std.crypto.Certificate.parse` (via the shared `x509.safe` helper)

`std.crypto.Certificate.der.Element.parse` reads its identifier octet without
checking the index against the buffer length, and derives a content slice from
the encoded length without validating it. **The fuzz test found this the first
time it ran**: `inspectCertificate(&.{})` aborted the process inside std rather
than returning an error. The guard that used to live here
(`tlsprofile.structurallySafe`) has moved to the shared **`x509.safe`** helper,
which three modules independently needed; `inspectCertificate` now parses the
certificate through `x509.safe.safeCertificate`, which validates DER
well-formedness and hands std a validated, zero-padded copy so a hostile
certificate is a typed `MalformedCertificate`, never a crash. See
`modules/x509/src/safe.zig` and `modules/x509/SPEC.md`.

### The escape seams

Three, because three different things are modelled and each could be wrong in a
specific deployment:

- `goose.RawSealer` / `goose.RawVerifier` — an unmodelled algorithm, over the
  same covered range. Exercised by a test that plugs in HMAC-SHA-512/160, an
  algorithm that appears in no IEC table.
- `goose.HeaderProfile` — the reserved-field layout, as data.
- `acse.MechanismName.custom` and `AuthValue.external`/`.other` — an arbitrary
  mechanism OID and arbitrary authentication-value bytes, so a vendor's real
  encoding can be carried without touching this module.

## Provenance of the wire model

IEC 62351-3/-4/-6 are paywalled. What follows is the honest split between what
is grounded in publicly available material and what is this module's model.
Nothing below is claimed as normative.

**Grounded** (the published table of contents of IEC 62351-6:2020 — clause 6.2
"Replay Protection" with a state machine per profile, clause 8.2 "Extended PDU"
/ "Format of extension octets", figures "Definition of Reserved 1" and
"Calculated MAC Domain", and its normative references to RFC 2104, NIST
SP 800-38D and RFC 8052; plus peer-reviewed survey literature describing both
editions):

- The frame geometry: EtherType, APPID, Length, Reserved 1, Reserved 2, APDU,
  with an `Extension` appended after the APDU when security is in use.
- The covered range for the 2007 signature: "starting with the EtherType field
  through the end of the APDU field".
- The MAC algorithm registry and tag lengths — HMAC-SHA256-80/128/256 (10/16/32
  octets) and AES-GMAC-64/128 (8/16 octets) — and their numbering 1..5, which
  IEC 61850-90-5 uses for the routed profiles and 62351-6:2020 adopts.
- The `0x85` tag for the authentication value, from the 61850-90-5 session PDU
  signature field.
- The authentication value's field order: version, TimeOfCurrentKey (4 octets),
  TimeToNextKey (2 octets), initialisation vector, Key ID (4 octets), MAC value
  (8–32 octets).
- IEC TS 62351-6:2007 used SHA-256 + RSASSA-PSS (RFC 3447), and the 2020 IS
  replaced it with symmetric MACs because signatures cannot meet IEC 61850-5's
  3 ms transfer-time class.
- The 2020 document is cover-labelled "Edition 1.0" despite superseding the
  2007 Technical Specification. (Recorded because it is confusing, not because
  it matters technically.)
- ACSE `[10]`/`[11]`/`[12]` tags, the `Authentication-value` CHOICE and its four
  alternatives, and the `password-1` mechanism OID 2.2.3.1 — these come from
  ISO 8650-1 / ITU-T X.227, which are not the paywalled part.
- TLS cipher-suite code points (IANA registry) and the IEC 62351-4:2018 cipher
  suite tables including `TLS_RSA_WITH_AES_128_CBC_SHA256` as
  mandatory-to-implement for the native mode.

**Modelled by this module** (parameterised or escapable in every case):

- The exact BER framing of the `Extension`: a universal `SEQUENCE` wrapping the
  `0x85` authentication value. The *contents* are grounded; the outer wrapper's
  encoding is this module's.
- Which reserved field carries the presence flag and which carries the length.
  Secondary sources disagree — one describes the 2007 layout as "length in the
  second octet of Reserved 1, CRC in Reserved 2", the 2020 figure list implies a
  redefined `Reserved 1`. Both readings ship as `HeaderProfile.ts2007` and
  `HeaderProfile.ed2020`, with the flag bit and length field as fields.
  **A finding worth recording:** a single length octet caps the extension at 255
  octets, but the 2007 profile's own RSASSA-PSS signature is 256 octets for a
  2048-bit key. A 2048-bit 2007 deployment therefore cannot be using a one-octet
  length field, whatever the secondary literature says. This is asserted as a
  test (`ts2007: a 2048-bit signature extension does not fit the single length
  octet`) rather than papered over.
- The 2007 `Reserved 2` CRC is **not** computed or checked. It is an integrity
  check, not a security one, and inventing a polynomial would be worse than
  omitting it. Deferred, listed below.
- HMAC-SHA-3 variants are **not** implemented. They are discussed around the
  IEC 62351 series but do not appear in the -6 algorithm table this module was
  built from, and inventing registry numbers for them would be worse than not
  shipping them. `RawSealer`/`RawVerifier` covers a deployment that needs one.
- ECDSA P-256 as a GOOSE signature profile. The 2007 profile is RSA-only; ECDSA
  is offered because 62351-4's end-to-end table lists `ecdsa-with-SHA256` and
  the covered range is identical either way.
- `acse.SignedToken`'s entire encoding. Flagged in the type's doc comment, in
  the README and here.
- The IEC 62351-4 mechanism OID **leaves**. Only the arc `1.0.62351.4` is
  provided, explicitly labelled as an arc; `MechanismName.custom` carries the
  real one.
- The numeric bounds in `tlsprofile.Profile` (session lifetime, resumption age,
  maximum certificate validity). Defaults are stated in the type; the standard's
  exact figures vary by edition and claimed profile.

## Relationship to `modules/dnp3`

IEC 62351-**5** is DNP3 Secure Authentication (= IEEE 1815-2012 §7), and it is
already implemented as `dnp3.sa`. **It stays there.** SA is not a wrapper over
DNP3 the way -6 is a wrapper over GOOSE: it is object group 120 living inside
DNP3's own application layer, with a challenge/reply flow, session-key change
messages and aggressive mode all bound to DNP3 ASDU boundaries. Extracting it
would leave a DNP3 module that cannot speak DNP3-with-SA and a security module
that must reimplement DNP3 framing to be useful. Nothing is moved or
duplicated.

Two things were taken *from* `dnp3.sa` as house style, and both are visible
here: the MAC registry as an explicit `enum(u8)` with a `tagLen` function
rather than implicit truncation, and constant-time verification with the
comparison isolated in one function.

## Threat model

### What IEC 62351-6 as implemented here does protect against

- **Forgery and modification of a GOOSE/SV frame by an attacker without the
  key.** Any change inside the covered range — APDU content, APPID, the
  reserved fields, the frame length — invalidates the tag. Four separate
  negative tests, one per class.
- **Replay of a captured frame.** The tag alone does not stop this: a captured
  frame stays valid forever. `replay.GooseGuard` rejects a rewound
  `stNum`/`sqNum`, a `t` that moved without a state change, a stale state
  change, a timestamp from the future, and (optionally) resumption after an
  unexplained silence.
- **Truncation of the tag, and tag/length confusion.** A shortened extension
  fails; a tag longer than the verifier's algorithm produces is refused at
  parse time by `Verifier.maxTagLen()` rather than being compared.
- **Downgrade by clearing the security flag.** The presence flag and the
  extension length are both inside the covered range and must agree
  (`ExtensionFlagMismatch`) — but see the limitation below.

### What it does not protect against

- **Confidentiality. None.** GOOSE authentication is authentication. Breaker
  positions, trip commands and measurements travel in the clear and anyone with
  a port mirror reads them. IEC 62351-1 explicitly rules out encryption for
  GOOSE because of the 3 ms budget; the 2020 edition's AES-GCM option for the
  routed profiles is not implemented here.
- **Publisher identity, when a symmetric MAC is used.** A group key
  authenticates *the group*. Every subscriber holds the key, so every
  subscriber can forge every publisher's frames. This is inherent to the
  symmetric profile, not a limitation of this implementation, and it is the
  reason the signature profiles exist at all. A deployment that needs publisher
  authentication and can afford the latency uses `.rsa_pss_sha256` or
  `.ecdsa_p256_sha256`.
- **The latency budget.** IEC 61850-5's transfer-time class for a trip message
  is 3 ms end to end. Measured RSA signature generation on IED-class hardware
  is milliseconds to tens of milliseconds per frame, against a publisher rate
  of 100–150 GOOSE/s and up to 4000 SV/s. **The signature profiles are
  therefore not usable for real trip traffic** and are shipped for
  slow/engineering traffic, offline verification of captures, and deployments
  that have measured their own hardware. The MAC profiles are what production
  uses; that is exactly why the 2020 edition made the switch.
- **Downgrade to no security at all.** If a subscriber is willing to accept
  unauthenticated frames, an attacker simply sends one: nothing in the frame
  can prevent that, because an unauthenticated frame is a valid 61850-8-1
  frame. `verify` returns `error.NoExtension` rather than silently accepting,
  so the *policy* ("we only accept authenticated frames") is the caller's to
  enforce and is easy to enforce correctly — but it is a policy, not a
  cryptographic guarantee.
- **Key management.** No key derivation, distribution, rollover or revocation.
  `time_of_current_key`/`time_to_next_key`/`key_id` are carried and returned to
  the caller; acting on them is IEC 62351-9 / RFC 8052 GDOI territory and is not
  implemented.
- **Denial of service.** An attacker flooding the segment with frames that fail
  verification still costs the subscriber a MAC computation per frame. GMAC and
  HMAC are cheap, but the bound is the caller's rate limiting, not this
  module's.
- **The `stNum` flooding attack, on its first move.** An attacker who *has* the
  key can jump `stNum` far ahead, after which the genuine publisher's frames are
  rejected as replays. The guard cannot distinguish that from a legitimate burst
  of events; what it does guarantee is that the attacker cannot then rewind, and
  that the operator sees a stream of `reject_replay_state` verdicts rather than
  a silent switchover. Test:
  `GOOSE: the status-number flooding attack is rejected once it rewinds`.
- **Side channels other than the tag comparison.** The MAC computation itself
  is `std.crypto`'s; no claim is made about the whole path being constant-time
  with respect to the key beyond what those primitives provide.

### IEC 62351-4 specifics

- The `charstring` (password) mechanism sends a shared secret **in the clear**
  inside the AARQ. It is only meaningful underneath the T-profile's TLS, and
  `passwordMatches` being constant-time does not change that. Said plainly
  because the mechanism is widely deployed.
- `SignedToken` binds a time and an identity, and `verifyToken` refuses to
  return a token outside the freshness window even when the signature is valid
  — a signature alone would make a captured AARQ replayable forever. The window
  is the caller's to size against its clock synchronisation.
- The token binds *nothing about the transport*. It is not channel-bound to the
  TLS session, so a token captured on one connection is usable on another
  within the freshness window by an attacker who can intercept it. Channel
  binding would need an exporter value from the TLS layer this module does not
  own. Deferred, listed below.

### IEC 62351-3 specifics

The policy judges *assertions*. `chain_validated` and `revocation_checked` are
booleans the caller sets; the module has no way to confirm them and does not
pretend to. A caller that hard-codes `true` gets a report that says nothing
useful — which is why both have a named `Violation` rather than being silently
assumed. Path validation is `x509.verifyChain`; revocation is `ocsp`/`ocspcache`.

## Verification

### What was run

- `zig build test-iec62351` in **Debug** and **`--release=fast`**: all pass,
  no failures, no skips, in both.
- `zig build test-x509` and `zig build test-rsa` (the two sibling dependencies):
  green.
- `zig fmt --check modules/iec62351`: clean.

### Test vectors, and where each one comes from

`vectors_test.zig` labels every vector. The distinction is not cosmetic: IEC
62351 publishes none, so a module that only tested itself against itself would
prove nothing about the primitives.

**Standard-derived (byte-exact from a published specification):**

- RFC 4231 §4 test cases 1, 2, 3, 4, 6 and 7, HMAC-SHA-256 column, reproduced
  exactly.
- The same six vectors run through `computeMac` for all three HMAC profiles,
  asserting that the 80/128/256-bit tags are exact **prefixes** of the RFC
  answer — this pins the truncation *direction*, which RFC 2104 §5 / NIST
  SP 800-107 fix as leftmost and which is a silent interoperability failure if
  taken from the wrong end. The test additionally asserts the rightmost bits do
  *not* verify.
- AES-GCM test cases 1 (AES-128) and 13 (AES-256) — all-zero key, IV, plaintext
  and AAD — reproduced exactly, then truncated to the GMAC-64/128 tag lengths.

**Self-derived (frozen output of this module, labelled as such):**

- One complete authenticated frame for HMAC-SHA256-128, byte-for-byte. This
  pins the header encoding, the extension encoding and the covered range in one
  artefact.
- The tag alone for each of the five MAC algorithms over the same fixed input.
- An RSASSA-PSS signature over the same covered range (PSS is randomised, so it
  is frozen as a *verification* vector) and a deterministic ECDSA P-256
  signature (fixed key seed + fixed noise, so it is reproduced exactly).

The two are bridged deliberately: `self: every frozen tag is exactly the MAC of
the frame's own covered range` recomputes the frozen tag straight from
`macDomain()` with the RFC-4231-validated primitive, so the self-derived
vectors rest on the standard-derived ones instead of on themselves.

### Third-party oracle — what actually ran

`libiec61850` is not installed on this machine and its 62351 support was not
obtainable, so **no IEC 61850 stack was used as an oracle and no GOOSE
interoperability is claimed.** What was available was used, as a black box:

- **OpenSSL 3.5.5, `openssl dgst -sha256 -mac HMAC -macopt hexkey:0b0b…`** over
  the exact 39 octets of the frozen frame's `macDomain()`, giving
  `5a78a13bb948ea4aa1a53a57bddfb82dae45…` — whose first 16 octets are the
  frozen `hmac_sha256_128` tag. This independently confirms both the primitive
  and the covered range: OpenSSL never saw this module's code.
- **`openssl asn1parse -inform DER`** on the GOOSE security `Extension`
  (`SEQUENCE` containing a primitive `cont [5]` of 27 octets), on an AARQ with
  the authentication fields spliced in (`appl [0]` containing `cont [0]`,
  `cont [1]` with OID **1.0.9506.2.3** — the MMS application context —,
  `cont [10]`, `cont [11]`, a **constructed** `cont [12]` containing
  `cont [0]`, and `cont [30]`), and on a `SignedToken`
  (`SEQUENCE { cont[0], cont[1], cont[2], cont[3] }`). An independent ASN.1
  decoder agrees with the structure this module emits, including that `[12]` is
  constructed (explicit) rather than primitive.
- **`openssl x509 -noout -text`** on a certificate generated by the sibling
  `rsa` module and inspected by `tlsprofile.inspectCertificate`: OpenSSL reports
  Version 3, RSA 2048-bit, `sha256WithRSAEncryption`, `Basic Constraints:
  critical CA:FALSE`, `Key Usage: critical Digital Signature` — matching every
  field `CertificateFacts` reported for the same bytes.
- **`asn1crypto`** decoded the two OID constants to `2.2.3.1` and `1.0.62351.4`,
  confirming the hand-encoded content octets.

### Real GOOSE captures — header/APDU boundary anchor, not an interop claim

`libiec61850` remaining unavailable (previous section), three real IEC
61850-8-1 GOOSE frames — a GE F650 relay and two IEDs from a mock four-bus
substation, all captured from genuine devices, none of them this module's own
output — were vendored instead (`cutaway-security/goosestalker`, MIT; see
`../NOTICE`) and driven through `parse`/`verify` in
`src/goose_capture_test.zig`. Since `goose.zig` never parses the `goosePdu`
(the layering decision above), what a real frame can anchor is exactly the
header: EtherType, APPID, `Length`, `Reserved 1`/`Reserved 2`, and the
APDU/extension boundary `Length` derives — all confirmed byte-exact against
genuine wire data, including the VLAN-tagged case (stripped before `parse`,
per this module's documented contract).

**All 493 GOOSE frames surveyed across the five source `.pcap` files carry
`Reserved 1` = `Reserved 2` = `0x0000` — no IEC 62351-6 security extension in
any of them.** That is the anchored finding: real-world GOOSE traffic
essentially never turns the layer-2 security profile on, so a real capture
cannot substitute for the `libiec61850` 62351-6 interop test this section
already says is unavailable. The security extension's wire shape (the `0x85`
tag, the field order, the covered range) remains this module's own model, as
documented above — but it composes correctly over a genuine captured APDU:
`goose_capture_test.zig` wraps one of the real APDUs with this module's own
HMAC extension, round-trips it, and confirms tampering inside the real
`gocbRef` text is still caught. As a bonus check of the shared `ber.zig`
reader (not a claim about `goose.zig`'s own scope), the same file also walks
each real `goosePdu`'s `gocbRef`/`stNum`/`sqNum`/`allData` fields with
`ber.iterate`, cross-checked against a hand-decode of the same bytes.

### Negative tests

Not a sample — the full list, because for a security module they are the point:
tampered APDU octet; tampered header octet inside the covered range; tampered
tag octet; truncated tag (with every length field consistently shortened, so it
fails on the tag rather than on the parse); a tag computed over a two-octet
shifted range; a tag computed over a range extended into the extension; wrong
key; wrong algorithm at the same tag length; Ethernet padding excluded; reserved
flag/length disagreement in both directions; extension longer than the frame;
`Length` below the header minimum; a frame with no extension refused by
`verify`; an over-long tag refused at parse; trailing bytes after the extension;
a zero-length tag; IV present/absent mismatched with the algorithm in both
directions; the 2007 profile misread as 2020; replayed `stNum`; replayed
`sqNum`; duplicate frame; `sqNum` not restarted on a state change; `t` moved
without a state change; stale state change; future timestamp (including on the
first frame); idle gap; counter rewind past the wrap window; an implicit `[12]`
tag not being recognised as the authentication value; a `[12]` with two child
elements; an unknown CHOICE alternative; a `[3] other` without an OID; a
tampered token identity; a tampered token time; an expired token; a token from
the future; a token with an unknown version; a wrong public key; an expired
certificate; a not-yet-valid certificate; a certificate valid for too long; a
1024-bit key against a 2048-bit minimum; a CA certificate used as an end
entity; a real certificate patched to drop `digitalSignature` from its
`keyUsage`; a forbidden cipher suite; an unknown cipher-suite code point; TLS
below the floor; compression enabled; missing secure renegotiation; missing
mutual authentication; session and resumption lifetimes exceeded;
`chain_validated`/`revocation_checked` false; a malformed certificate.

### Fuzzing

Six `std.testing.fuzz` targets, chosen for the specific failure modes the task
of writing a parser for attacker-controlled bytes invites:

- `ber.zig` — the reader over arbitrary bytes, asserting every accepted element
  lies wholly inside the input, including its children.
- `goose.zig` — frame parse over arbitrary bytes under both header profiles,
  asserting `apdu + extension + header == Length` and that the covered range
  stays inside the frame; then `verify` on the same bytes, which must fail
  cleanly.
- `goose.zig` — extension parse over arbitrary octets with a randomised
  `expect_iv`, asserting the tag never exceeds the bound and the IV presence
  matches what was asked for. This is the "`reserved2` disagreeing with the
  actual tag length" case.
- `acse.zig` — authentication-field discovery over arbitrary bytes as both AARQ
  and AARE, asserting everything reported points inside the input. This is the
  "authentication-value whose declared type does not match its content" case.
- `acse.zig` — token parsing, additionally asserting arbitrary bytes never
  verify against a real key.
- `tlsprofile.zig` — certificate inspection over arbitrary DER, **and** over a
  real certificate with one fuzzer-chosen octet corrupted. The first of these
  found the `std.crypto.Certificate.parse` out-of-bounds abort described above.

## Deferred

Stated, not hidden:

- **AES-GCM confidentiality for the routed profiles.** IEC 62351-6:2020 covers
  AES-GCM over L2 GOOSE/SV and IEC 61850-90-5 defines AES-128/256-GCM for
  R-GOOSE/R-SV. Only authentication is implemented here; encryption is not.
- **R-GOOSE / R-SV (IEC 61850-90-5) session PDUs.** The UDP-routed profile has
  its own session header (SPDU number, TimeOfCurrentKey, security algorithms
  octet, Key ID) which is a different, larger wire format than the L2 extension.
  Not implemented; the MAC registry here is deliberately numbered compatibly
  with it, which is the groundwork.
- **Key management (IEC 62351-9 / RFC 8052 GDOI).** No key derivation,
  distribution, rollover or revocation. The key-schedule fields are carried and
  surfaced, nothing more.
- **The 2007 `Reserved 2` CRC.** Not computed, not checked, polynomial not
  guessed.
- **HMAC-SHA-3 profiles.** See the provenance section — no grounded registry
  numbers; use the raw seam.
- **Channel binding for `acse.SignedToken`.** The token is not bound to the TLS
  session it travels over.
- **CRL/OCSP inside the 62351-3 policy.** By design — `revocation_checked` is
  the caller's assertion and `ocsp`/`ocspcache` do the work.
- **SNTP security (IEC 62351-6 clause 7) and the SCL extensions (clause 9).**
  Out of scope: the first is a different protocol, the second is configuration
  schema rather than a security mechanism.
- **Real GOOSE interoperability.** No IEC 61850 stack with 62351 support was
  obtainable, so the wire format is verified for self-consistency, structural
  agreement with an independent ASN.1 decoder, and primitive-level agreement
  with OpenSSL — but **not** against another 62351 implementation. Anyone with
  access to one should run the frozen frame in `vectors_test.zig` through it
  before deploying.

## Coordinator notes

- `NOTICE` needs **no entry**: this module is clean-room from public
  specifications and public descriptions; no third-party source was ported and
  no third-party implementation was studied for algorithm or API shape. OpenSSL
  and `asn1crypto` were run purely as black-box test oracles, which
  `CONVENTIONS.md` §5 explicitly exempts.
- The root `README.md` catalog row and the `build.zig` entry were pre-wired by
  the coordinator and are correct as written; no change needed.
- `CHANGELOG.md` wants an "added module" line for the next release.
