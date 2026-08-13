# rbac — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: no findings. Modeled on NIST RBAC core (INCITS
  359-2012) + XACML 3.0 (design refs, no external byte-level KAT applies to decision
  logic) (design reference, not a test anchor).
- **2026-07-21** — New module: authorization decision engine — NIST RBAC (hierarchical +
  static SoD, cycle-checked) and a depth-bounded ABAC condition-tree evaluator (typed
  builder, 10 operators) with XACML-style.
