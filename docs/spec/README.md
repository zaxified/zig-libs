# Design specs

One `SPEC-<module>.md` per module — the **design / audit-facing** companion to each module's
user-facing `README.md`. Where the README says *what it is and how to call it*, the spec records
*why it is built this way, what it guarantees, and what it deliberately does not do*. The
`Threat model / out of scope` section doubles as input to the pre-public security review.

**Format** (keep specs short — design rationale, not a re-hash of the README or the code):

```
# SPEC — <module>

**Purpose** — one paragraph: what problem it solves and why it exists here.
**Model after / Seed** — the reference implementation(s) it mirrors + the source it was
  extracted from (provenance / code lineage). Cross-refs NOTICE + docs/CANDIDATES.md.
**Design & invariants** — the load-bearing design decisions and the properties the module
  guarantees: allocation discipline (zero-alloc? one alloc at init?), concurrency model,
  transport/clock seams, error policy (never-panic / typed errors), API shape.
**Threat model / out of scope** — for security-sensitive modules: the attacks it defends
  against and how; for all modules: what it explicitly does NOT do (so callers don't assume it).
**Verification** — how correctness is established: RFC/known-answer vectors, golden bytes,
  live round-trip, fuzz/VOPR, cross-check tools.
**Status** — `status·platform·role·concurrency` tags · deps.
```

Coverage is being brought to **all 49 modules** (older specs predate later features and are being
refreshed). The living contract remains tests + README + doc-comments + NOTICE; the spec is the
design record on top. Provenance (`Model after` / `Seed`) is also catalogued in
[`../CANDIDATES.md`](../CANDIDATES.md); third-party attributions + licenses live in
[`../../NOTICE`](../../NOTICE).
