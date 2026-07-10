# Pre-public security / similarity review

**Status: COMPLETE (2026-07-10).** All review phases done and all findings actioned —
provenance/license audit + loose-ends, dark-tests check, the 10-target adversarial security
pass (findings fixed), the jwt safe-by-default decision, the kv VOPR fault-sweep, AND the four
previously-deferred production-readiness items (mqtt broker hardening, sessions cross-request
CAS, coap admission-hook/DTLS-seam, kv out-of-order-durability) are now RESOLVED (see the
per-item ✅ entries below). Suite: 1833/1843, Debug + ReleaseFast green. Remaining before a
release tag: (1) honor the **fping Stanford attribution obligation** (NOTICE §1 — MIT for own
code but not obligation-free); (2) a multi-threaded stress/race pass on the mqtt broker (its
in-module tests are socket-free/single-threaded + a deterministic lock-probe). This file can be
deleted once those two are handled — the review itself is done.

## Progress (2026-07-09)

**✅ DONE — provenance / similarity audit + NOTICE completeness (the license-contamination
pass).** Traced every module's seed back through the sibling projects (axp/bxp/wgs/
poc-wf-analytic/zig-fping), not just their Apache-2/MIT surface. Fixes landed in commit
`667b29d`. Key outcomes:
- **fping lineage** (icmp/seqmap/netaddr/dns): fping = non-standard Stanford
  BSD-with-advertising license → zig-libs carries a Stanford attribution obligation
  (NOT obligation-free MIT). Restored the truncated NOTICE §1 clause; added README
  licensing note.
- **blobmsg**: LGPL-2.1 fear did NOT materialize — `libubus-io.c` contributed no code;
  only uncopyrightable ubus protocol constants + msghdr struct present. Safe under MIT;
  NOTICE/README rewordted to scope it accurately.
- **tar** cleared (spec-based ustar, GNU tar only a black-box test oracle — SPEC was
  overstating). **procnet/rawsock** SPECs corrected (gopsutil/libpcap never consulted).
- **WealthFolio (AGPL-3.0)** in the finstats chain: data-only interop (SQL schema read,
  no code linked/ported) — CLEAN, now documented in NOTICE.
- bxp family (decimal/tz/zipstream/…): verified CLEAN.

**✅ DONE — provenance/NOTICE loose-ends (2026-07-10):**
- C3 doc/UAPI references deep-checked (nftables/uci/upstream/abuseguard/modbus cite
  GPL/LGPL project *docs*; netlink/wireguard cite Linux-syscall-note UAPI headers): all
  **CLEAN-ORIGINAL or FACTS-ONLY-OK** — no source translation; netlink/wireguard only use
  the uncopyrightable ABI constants/struct layouts. No contamination.
- `Provenance:` line format NORMALIZED across all 77 module READMEs (20 bold-list variants
  → the plain single-`Provenance:`-line form; 57 already canonical; no facts lost).
- NOTICE-entry POLICY decided + documented (NOTICE §0 + CONVENTIONS §5): a pure
  clean-room-from-public-spec/RFC module needs NO NOTICE entry (RFC isn't copyrightable;
  citation lives in its SPEC); NOTICE is for ported code + named design references only.
  `whois`/`rdap`/`tar` confirmed compliant (correctly have no entry). Stale "audit pending"
  note in NOTICE §2 + syslog README owner-note cleared.
- blobmsg `ubus -S` byte-parity is pinned by committed OFFLINE golden-byte tests in the
  module (green); a live re-run against the axp qemu image is out of scope for this repo's
  CI (needs the axp environment) — the offline goldens cover the wire-compat regression.

**✅ DONE — dark-tests files-vs-running test-count check** (§ below). Swept all 19
multi-file modules: disk `test`-block count == running total (pass+skip) for every one;
all 10 skips accounted for (env/netns/live-gated). No dark tests. http/coap fixes hold;
no regressions. icmp uses `refAllDecls` (verified pulls everything), tz's only sibling
has zero tests — both safe.

**✅ DONE — adversarial SECURITY pass** (§ "Per-target adversarial review" below). All 10
targets reviewed under active attack; findings fixed in commits `cdc273c` (wave 1) +
`44f7420` (wave 2). Suite after fixes: 1814/1824 pass (10 skip), Debug+ReleaseFast green.
Highlights:
- **CLEAN** (well-hardened, no exploitable defect): `sealedbox`/`hashdigest` (faithful
  std.crypto wrappers), `acme` (JWS/ES256/nonce/CSR all correct), `jwt` crypto core
  (alg-confusion / `none` / jku-x5u-smuggling / const-time / sig-correctness all closed),
  `snmp` DES/key-IV-derivation/time-window/const-time-auth, `http` H2 DoS
  (rapid-reset/CONTINUATION/HPACK-bomb) + smuggling + multipart/range/HPACK, `mqtt`
  varint/topic-matcher/state-machine, `coap` option decoder, `argsafe` CharClass predicates.
- **FIXED**: http redirect Authorization host-only strip (CVE-2018-18074 class) + Cookie
  cross-origin leak (both HIGH); sessions same-request fixation/logout resurrection (HIGH)
  + id-entropy floor; coap block-Assembler never-written-bytes disclosure (HIGH) + Uri-Host
  encoding + dedup zero-guard; mqtt accept-loop inline-wedge DoS (CRIT) + resource caps +
  pre-CONNECT timeout; snmp.usm empty-password panic; aaa-gate throttle-key amplification
  (HIGH); argsafe CIDR leading-dash; jwt dead error-arm.

**☐ OPEN — decisions / deferred (surfaced by the security pass, NOT yet actioned):**
- **✅ RESOLVED 2026-07-09 — jwt insecure-defaults (was DECISION):** chose option (A),
  safe-by-default with explicit conscious opt-out. `Options.issuer`/`Options.audience` (and
  `Provider.ClaimOptions.audience`) are now mandatory typed unions with NO default —
  `.{ .required = "…" }` or the greppable `.any` opt-out; a jwks_uri-only provider with no
  configured issuer fails closed (`IssuerNotConfigured`). A same-IdP token for another service is
  now rejected by default (RFC 8725 §3.9). Also: `oct` keys from a **network-fetched** JWKS are now
  refused (`JwkSkipReason.oct_from_network`); locally-configured HMAC keys still work. See
  modules/jwt/{src/root.zig,README.md,SPEC.md}; new `SECURITY: mandatory audience …` test + reworked
  P5 tests (asymmetric keys over the fetcher). `test-jwt` green Debug + ReleaseFast.
- **✅ RESOLVED 2026-07-10 — mqtt broker production-hardening (`254ad6d`):** (A) O(C×S) fan-out
  replaced with a topic-filter TRIE index + the global lock released before socket writes
  (snapshot-under-lock, per-conn tx_lock, atomic refs for mid-fan-out safety; a LockProbe test
  proves the lock is dropped before writes); (B) per-subscriber delivery failure contained to that
  subscriber (publisher survives); (C) takeover shuts the superseded socket (zombie reaped); (D)
  optional auth + ACL hooks. Residual (documented): QoS2/persistent-sessions/Will/TLS unimplemented;
  a multi-threaded stress/race pass recommended before release. 58 tests, green Debug + RF.
- **✅ RESOLVED 2026-07-10 — sessions cross-request race (`c1bc3d7`):** store-level optimistic
  concurrency — each record carries a monotonic generation; save() is a CAS (write only if the
  generation matches load-time), delete/regenerate bump it so a stale save from another in-flight
  request fails closed (never resurrects); absent==0 makes the stale CAS fail even if the tombstone
  was LRU-evicted. Policy: delete/regenerate wins; concurrent data writes first-writer-wins. 22 tests.
- **✅ RESOLVED 2026-07-10 — coap unauth-UDP (`ef9044a`):** observe Registry admission hook
  (`tryRegister` + optional per-source cap; a rejected request evicts nothing) + DTLS-seam docs
  (transport-agnostic → runs over caller-terminated DTLS; production MUST use DTLS); dedup documented
  as reliability-not-security (a boundary only with source auth). 65 tests.
- **✅ RESOLVED 2026-07-10 — kv out-of-order durability (`978c779`):** VOPR SimStorage now models
  non-contiguous unsynced-region drop (holes) targeting compact()'s multi-write window; recovery
  PROVEN correct (CRC32 fail-stop truncates at the hole; compact()'s only multi-write window is the
  temp file, adopted only via atomic rename after a full sync — recovery never depends on write
  ordering). No product defect. 36 tests.

## Purpose

This is the **highest-value step before any public release** of zig-libs. The module set
is functionally complete (77 modules / 1809 tests, Debug + ReleaseFast green); what has
**not** yet had a dedicated adversarial pass is (a) the security-sensitive modules'
constant-time/confusion/replay properties under active attack, not just correctness
under normal input, and (b) a line-level check that "model after X" / "clean-room from
spec" claims recorded in `NOTICE` and each module's `README.md`/`SPEC.md` actually hold —
i.e. that provenance is accurate, not just asserted. Do not tag or announce a public
release before this checklist is worked through.

## Per-target adversarial review checklist

Each target below gets a dedicated adversarial pass — not just "does it pass its own
tests" but "what would a hostile input/attacker do here":

- ✅ **`acme`** — JWS signing correctness (ES256 over the right protected header/payload
  encoding) and CSR (PKCS#10) construction; nonce handling; replay/downgrade paths in the
  ACME v2 (RFC 8555) client flow. — done (see Progress: adversarial SECURITY pass, listed
  CLEAN — JWS/ES256/nonce/CSR all correct).
- ✅ **`aaa-gate` / `jwt`** — constant-time comparison on every secret-bearing compare
  (bearer tokens, HMAC signatures); **alg-confusion** resistance (HS vs RS/ES/EdDSA
  cannot be swapped by an attacker-controlled `alg` header); JWKS handling — `kid`
  lookup can't be tricked into fetching or trusting an attacker-supplied key
  ("JWKS smuggling"); key-rotation correctness under a JWKS refresh. — done (see Progress:
  adversarial SECURITY pass — jwt crypto core CLEAN incl. alg-confusion/jku-x5u-smuggling;
  aaa-gate throttle-key amplification FIXED; jwt insecure-defaults RESOLVED separately).
- ✅ **`snmp.usm`** — constant-time HMAC-MD5/SHA-1-96 verification; MD5/SHA-1
  algorithm-confusion (can't downgrade auth to a weaker alg unexpectedly); privacy
  (DES-CBC / AES-128-CFB) key derivation and IV handling; engineBoots/engineTime
  anti-replay window (RFC 3414 §3.2) actually rejects stale/replayed frames. — done (see
  Progress: adversarial SECURITY pass — DES/key-IV-derivation/time-window/const-time-auth
  CLEAN; empty-password panic FIXED).
- ✅ **`kv`** — fault-sweep / VOPR DONE (2026-07-10). Two harnesses (exhaustive scripted +
  2000-seed randomized VOPR) model crash-anywhere, partial-fsync/record-truncation, and
  byte-arbitrary torn writes; recovery is CRC32-per-record fail-stop (torn/corrupt tail
  truncated, never replayed — the VOPR checker actively flags any "corrupt served as valid").
  Re-ran at 10× (20k seeds): 0 failures. GAP logged as backlog (kv/SPEC.md): out-of-order /
  non-contiguous durability within an un-synced multi-write window isn't expressible in the
  current always-contiguous-prefix SimStorage, though compact()'s write-loop-then-single-sync
  is that pattern — not a correctness defect (CRC gates it), but over-truncation-under-reordering
  is unverified. Not a release blocker.
- ✅ **`http` parser cluster** — the whole family that parses attacker-controlled bytes:
  redirect handling + auth-header-stripping on cross-origin redirects, HTTP/2 DoS
  resistance (the CVE-2023-44487/CVE-2024-27316-derived mitigations actually hold under
  adversarial framing), and the body/multipart/mcp-http/webhooksig/cookies/range/conneg
  parser cluster (malformed multipart boundaries, cookie injection, oversized/negative
  Range requests, conneg header abuse). — done (see Progress: adversarial SECURITY pass —
  H2 DoS + smuggling + multipart/range/HPACK CLEAN; redirect Authorization host-only strip
  + cross-origin Cookie leak FIXED, both HIGH).
- ✅ **`sealedbox` / `hashdigest`** — thin-wrapper correctness over `std.crypto` (no
  accidental weakening of the underlying primitive — e.g. key/nonce reuse, truncation,
  or a fallback path that silently drops to something weaker). — done (see Progress:
  adversarial SECURITY pass — listed CLEAN, faithful std.crypto wrappers).
- ✅ **`sessions` / CSRF** (`sessions` module) — session-fixation resistance
  (`regenerate` actually kills the old id), constant-time CSRF token compare, double-submit
  binding to the right session, cookie hardening defaults (`Secure`/`HttpOnly`/`SameSite`)
  can't be silently bypassed. — done (see Progress: adversarial SECURITY pass — fixation/
  logout-resurrection + id-entropy floor FIXED; cross-request race separately RESOLVED via
  CAS, commit `c1bc3d7`).
- ✅ **`argsafe`** — the allowlist/CharClass predicates and the `Argv` builder: confirm no
  predicate can be tricked into accepting a flag-injection, NUL-smuggling, or `..`
  path-traversal payload; confirm a rejected `pushChecked`/`pushIf` always poisons the
  builder (no code path can ship a short argv after a swallowed error). — done (see
  Progress: adversarial SECURITY pass — CharClass predicates CLEAN; CIDR leading-dash
  FIXED).
- ✅ **`mqtt` broker** — the first-cut broker (per-conn state machine, subscription
  registry, PUBLISH fan-out, QoS0/1): resource-exhaustion and malformed-packet handling
  from an untrusted client connection. — done (see Progress: adversarial SECURITY pass —
  varint/topic-matcher/state-machine CLEAN; accept-loop inline-wedge DoS FIXED (CRIT);
  broader production-hardening separately RESOLVED, commit `254ad6d`).
- ✅ **`coap`** — the reliability layer (CON retransmission, message-ID dedup) and the new
  C6/C7 block-wise + observe additions: replay/duplicate handling under adversarial
  timing, and the `options` decoder's handling of malformed delta-encoded option lengths.
  — done (see Progress: adversarial SECURITY pass — options decoder CLEAN; block-Assembler
  disclosure FIXED (HIGH); unauth-UDP separately RESOLVED, commit `ef9044a`).

## Line-level provenance / similarity audit

**✅ Done — see Progress** (the provenance/similarity audit, commit `667b29d`, plus the
2026-07-10 loose-ends pass). No checkboxes below; this section is the methodology
description that audit followed.

Independent of the security pass: for every module recorded as "clean-room from
spec/RFC" or "model after X" in `NOTICE` / the module `README.md`, do a line-level
similarity check against the named reference implementation(s) — confirm the claim holds
(design/behavior only, no source-level copying) and that no third-party GPL/AGPL/LGPL or
unknown-license code has been consulted at the source level. Pay particular attention to
modules whose `NOTICE` entry cites a reference under a copyleft or unclear license
(e.g. anything noted "documented behavior only, no code consulted or copied" — verify
that boundary was actually respected, not just asserted).

## Files-vs-running test-count check (the dark-tests check)

**✅ Done — see Progress** (dark-tests files-vs-running test-count check: all 19
multi-file modules swept, disk-count == running total, no dark tests). No checkboxes
below; this section is the methodology description that sweep followed.

Repo-wide sweep for the **dark-tests bug** (found 2026-07-08): a bare
`pub const x = @import("x.zig")` re-export does **not** pull `x`'s tests into the module's
test binary — only a `test { _ = x; }` aggregator (or `refAllDecls`) does. Concretely:
for every multi-file module, compare the test count `zig build test-<name>` reports
against a manual count of `test "..."` blocks across all of that module's source files
(`rg -c '^test "' modules/<name>/src/**/*.zig`) and confirm they match. This already
caught 92 never-run tests (in `http` and `coap`) and 3 latent bugs those hidden tests
would have caught — treat a mismatch as a release blocker, not a nice-to-have.

## NOTICE-completeness sweep

- ✅ Every third-party design-reference actually used anywhere in the repo has a
  corresponding `NOTICE` entry (cross-check against every module's `README.md`
  `Provenance:` line — nothing referenced in a README should be absent from `NOTICE`).
  — done (see Progress: provenance/NOTICE loose-ends — C3 doc/UAPI references
  deep-checked all CLEAN-ORIGINAL/FACTS-ONLY-OK; NOTICE-entry policy decided +
  documented).
- ✅ The `Provenance:` line format is consistent across all module READMEs (as of the
  last audit, roughly 13 modules use a bold-list variant instead of the plain-line
  form — pick one and normalize). — done (see Progress: `Provenance:` line format
  NORMALIZED across all 77 module READMEs — 20 bold-list variants converted; 57
  already canonical).
- ✅ Resolved the `latency-stats` and `dns` citation nits (2026-07-10). Explicit pass:
  `latency-stats` NOTICE entry was rewritten during the provenance reframe and is now
  complete + correct (moment stats = authors' own original work; HdrHistogram design refs
  all carry licenses; RFC 3550 + Welford cited). `dns` had one real nit — `c-ares` was
  cited without its license alongside `miekg/dns (BSD-3-Clause)`; annotated `c-ares (MIT)`.
  Both NOTICE entries now license every design reference.
- ✅ Confirm the NOTICE policy for pure-clean-room-from-RFC modules with no third-party
  code reference at all (`whois`, `rdap`, `tar`) — decide and document whether these need
  a NOTICE entry (spec-only, no design reference) or are correctly NOTICE-absent. — done
  (see Progress: NOTICE-entry POLICY decided + documented, NOTICE §0 + CONVENTIONS §5;
  `whois`/`rdap`/`tar` confirmed compliant, correctly have no entry).
- ✅ Re-run the axp qemu `ubus -S` parity check against the extracted `blobmsg` module,
  to confirm byte-for-byte wire compatibility still holds. — done differently (see
  Progress: byte-parity pinned by committed OFFLINE golden-byte tests in the module,
  green; a live re-run against the axp qemu image is explicitly out of scope for this
  repo's CI since it needs the axp environment — the offline goldens cover the
  wire-compat regression instead).
