# rbac — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-04** — Tests: first mutation run (55 mutants, 54 killed, 1 equivalent); 4 tests added
  (`eq`/`ne` kind mismatch, `in` with mixed-type list and non-list RHS, inclusive depth bound,
  `deny_overrides` with an Indeterminate rule next to a Permit). No source change.
- **2026-09-30** — `rbac.Engine` revoke/remove operations: `unassignRole`, `removePermission`,
  `removeHierarchy`, `removeStaticSoD` (return `error{UnknownRole}!bool`, `false` = nothing to
  remove) and `removeRole` (NIST `DeleteRole`: cascades over the role's permissions,
  assignments, hierarchy edges and SoD pairs). Storage moved from one arena to individually
  owned allocations that are freed on removal (no tombstones; churn-tested). `addPermission`,
  `addHierarchy` and `addStaticSoD` are now idempotent (a repeat used to append a duplicate);
  `Engine.arena` is replaced by `Engine.gpa`. Scope raised from mvp to core.
- **2026-08-06** — Security audit: no findings. Modeled on NIST RBAC core (INCITS
  359-2012) + XACML 3.0 (design refs, no external byte-level KAT applies to decision
  logic) (design reference, not a test anchor).
- **2026-07-21** — New module: authorization decision engine — NIST RBAC (hierarchical +
  static SoD, cycle-checked) and a depth-bounded ABAC condition-tree evaluator (typed
  builder, 10 operators) with XACML-style.
