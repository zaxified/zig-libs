# Pre-public security / similarity review

**Status: in progress.** This is a living TODO — check items off in place as they're
done. **Delete this file once the review is complete and its findings have been acted
on**; it is not meant to be a permanent doc, only a working checklist for the one-time
gate below.

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

**☐ STILL OPEN under provenance/NOTICE:**
- C3 doc/UAPI references not deep-traced (lower risk, all assert no-code-copied):
  `nftables`/`uci`/`upstream`/`abuseguard`/`modbus` (cite GPL/LGPL project *docs*),
  `netlink`/`wireguard` (cite GPL-2.0-WITH-Linux-syscall-note UAPI headers — rest on the
  standard "OS-ABI, not copyrightable" position). Confirm each is behavior/spec-only.
- `Provenance:` line FORMAT consistency across all module READMEs (some use a bold-list
  variant) — normalize.
- NOTICE policy for pure-clean-room-from-RFC modules (`whois`/`rdap`/`tar`): decide
  whether a spec-only module needs a NOTICE entry.
- Re-run the axp qemu `ubus -S` parity check against `blobmsg` (byte-compat confirmation).

**✅ DONE — dark-tests files-vs-running test-count check** (§ below). Swept all 19
multi-file modules: disk `test`-block count == running total (pass+skip) for every one;
all 10 skips accounted for (env/netns/live-gated). No dark tests. http/coap fixes hold;
no regressions. icmp uses `refAllDecls` (verified pulls everything), tz's only sibling
has zero tests — both safe.

**☐ NOT STARTED — the adversarial SECURITY pass** (§ "Per-target adversarial review"
below): the 10 crypto/parser targets under active attack, not just correctness.

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

- ☐ **`acme`** — JWS signing correctness (ES256 over the right protected header/payload
  encoding) and CSR (PKCS#10) construction; nonce handling; replay/downgrade paths in the
  ACME v2 (RFC 8555) client flow.
- ☐ **`aaa-gate` / `jwt`** — constant-time comparison on every secret-bearing compare
  (bearer tokens, HMAC signatures); **alg-confusion** resistance (HS vs RS/ES/EdDSA
  cannot be swapped by an attacker-controlled `alg` header); JWKS handling — `kid`
  lookup can't be tricked into fetching or trusting an attacker-supplied key
  ("JWKS smuggling"); key-rotation correctness under a JWKS refresh.
- ☐ **`snmp.usm`** — constant-time HMAC-MD5/SHA-1-96 verification; MD5/SHA-1
  algorithm-confusion (can't downgrade auth to a weaker alg unexpectedly); privacy
  (DES-CBC / AES-128-CFB) key derivation and IV handling; engineBoots/engineTime
  anti-replay window (RFC 3414 §3.2) actually rejects stale/replayed frames.
- ☐ **`kv`** — the fault-sweep / VOPR: re-run and extend the randomized crash-recovery
  simulation looking specifically for a scenario the current seed set doesn't cover
  (partial fsync, torn writes at odd boundaries, out-of-order flush).
- ☐ **`http` parser cluster** — the whole family that parses attacker-controlled bytes:
  redirect handling + auth-header-stripping on cross-origin redirects, HTTP/2 DoS
  resistance (the CVE-2023-44487/CVE-2024-27316-derived mitigations actually hold under
  adversarial framing), and the body/multipart/mcp-http/webhooksig/cookies/range/conneg
  parser cluster (malformed multipart boundaries, cookie injection, oversized/negative
  Range requests, conneg header abuse).
- ☐ **`sealedbox` / `hashdigest`** — thin-wrapper correctness over `std.crypto` (no
  accidental weakening of the underlying primitive — e.g. key/nonce reuse, truncation,
  or a fallback path that silently drops to something weaker).
- ☐ **`sessions` / CSRF** (`sessions` module) — session-fixation resistance
  (`regenerate` actually kills the old id), constant-time CSRF token compare, double-submit
  binding to the right session, cookie hardening defaults (`Secure`/`HttpOnly`/`SameSite`)
  can't be silently bypassed.
- ☐ **`argsafe`** — the allowlist/CharClass predicates and the `Argv` builder: confirm no
  predicate can be tricked into accepting a flag-injection, NUL-smuggling, or `..`
  path-traversal payload; confirm a rejected `pushChecked`/`pushIf` always poisons the
  builder (no code path can ship a short argv after a swallowed error).
- ☐ **`mqtt` broker** — the first-cut broker (per-conn state machine, subscription
  registry, PUBLISH fan-out, QoS0/1): resource-exhaustion and malformed-packet handling
  from an untrusted client connection.
- ☐ **`coap`** — the reliability layer (CON retransmission, message-ID dedup) and the new
  C6/C7 block-wise + observe additions: replay/duplicate handling under adversarial
  timing, and the `options` decoder's handling of malformed delta-encoded option lengths.

## Line-level provenance / similarity audit

Independent of the security pass: for every module recorded as "clean-room from
spec/RFC" or "model after X" in `NOTICE` / the module `README.md`, do a line-level
similarity check against the named reference implementation(s) — confirm the claim holds
(design/behavior only, no source-level copying) and that no third-party GPL/AGPL/LGPL or
unknown-license code has been consulted at the source level. Pay particular attention to
modules whose `NOTICE` entry cites a reference under a copyleft or unclear license
(e.g. anything noted "documented behavior only, no code consulted or copied" — verify
that boundary was actually respected, not just asserted).

## Files-vs-running test-count check (the dark-tests check)

Repo-wide sweep for the **dark-tests bug** (found 2026-07-08): a bare
`pub const x = @import("x.zig")` re-export does **not** pull `x`'s tests into the module's
test binary — only a `test { _ = x; }` aggregator (or `refAllDecls`) does. Concretely:
for every multi-file module, compare the test count `zig build test-<name>` reports
against a manual count of `test "..."` blocks across all of that module's source files
(`rg -c '^test "' modules/<name>/src/**/*.zig`) and confirm they match. This already
caught 92 never-run tests (in `http` and `coap`) and 3 latent bugs those hidden tests
would have caught — treat a mismatch as a release blocker, not a nice-to-have.

## NOTICE-completeness sweep

- ☐ Every third-party design-reference actually used anywhere in the repo has a
  corresponding `NOTICE` entry (cross-check against every module's `README.md`
  `Provenance:` line — nothing referenced in a README should be absent from `NOTICE`).
- ☐ The `Provenance:` line format is consistent across all module READMEs (as of the
  last audit, roughly 13 modules use a bold-list variant instead of the plain-line
  form — pick one and normalize).
- ☐ Resolve the `latency-stats` and `dns` citation nits (flagged but not yet fixed as of
  the last doc audit).
- ☐ Confirm the NOTICE policy for pure-clean-room-from-RFC modules with no third-party
  code reference at all (`whois`, `rdap`, `tar`) — decide and document whether these need
  a NOTICE entry (spec-only, no design reference) or are correctly NOTICE-absent.
- ☐ Re-run the axp qemu `ubus -S` parity check against the extracted `blobmsg` module,
  to confirm byte-for-byte wire compatibility still holds.
