# rbac — spec

Authorization decision engine: RBAC (role-based) + ABAC (attribute-based). Usage: see
./README.md. No third-party source ported and no third-party implementation studied as a
design reference — pure clean-room-from-spec (NIST RBAC / XACML), so no NOTICE entry
(see CONVENTIONS.md §5).

## Design & invariants

- **Two independent models, one `Decision` shape.** `rbac.Engine.check` and `abac.evaluate`
  both return the root `Decision{ result: Result, reason: []const u8 }` where
  `Result = enum { permit, deny }`. `Decision.isPermit()` is the safe binary read a caller
  should gate on. Neither model allocates for the returned `Decision` itself — `reason` is
  always a borrowed string literal or a caller-owned id (an `abac.Rule.id`, or an `rbac`
  role/permission string already owned by the `Engine`'s arena).
- **RBAC (`rbac.Engine`) — NIST RBAC core + hierarchical RBAC (INCITS 359-2012).** Roles carry
  permissions (`action` + `resource`, opaque caller-defined strings — this module does not
  interpret them); users hold a set of directly assigned roles; a role hierarchy
  (`addHierarchy(senior, junior)`) lets a senior role inherit everything a junior role (and
  its own juniors, transitively) can do. `check` resolves direct grants first, then walks the
  hierarchy — the `Decision.reason` string tells a caller/auditor which path fired
  ("granted directly by an assigned role" vs "granted via role hierarchy inheritance").
- **Cycle-free by construction.** `addHierarchy` runs a DFS reachability check (`reachable`)
  BEFORE linking the edge and rejects anything that would close a cycle, including a direct
  self-edge, with `error.CyclicHierarchy`. This means the juniors graph is a DAG at every
  point in its lifetime, so `check`'s permission-resolution DFS (`roleGrantsTransitive`) never
  needs a visited-set guard of its own — the invariant is enforced once, at the single
  insertion point, not re-checked on every read.
- **Static separation-of-duty only.** `addStaticSoD(a, b)` declares two roles mutually
  exclusive; `assignRole` checks the user's currently-held roles against every declared pair
  (order-independent) and rejects with `error.ConflictingRole` before the conflicting
  assignment lands. **Dynamic (session-based) SoD — where a user may hold both roles but not
  *activate* both in the same session — is explicitly deferred**: this module has no session
  concept at all (RBAC "sessions" per NIST RBAC are out of scope; `check` takes a bare user
  id). A caller wanting dynamic SoD needs a session layer above this engine that tracks
  per-session active-role subsets and applies the same exclusivity pairs to that subset
  instead of to the full assignment set.
- **Engine memory model.** `Engine` owns one internal `ArenaAllocator`; every string handed to
  a mutating method (`addRole`/`addPermission`/`addHierarchy`/`addStaticSoD`/`assignRole`) is
  duped into it, so the caller's arguments never need to outlive the call, and `deinit` frees
  everything the engine owns in one pass. This trades a small amount of duplicate storage
  (repeated role names across permissions/hierarchy edges/assignments each get their own
  dupe) for a dead-simple ownership story — acceptable for a config-time, admin-scale
  structure (roles/permissions/users in the thousands, not millions).
- **ABAC (`abac`) — a typed condition-tree evaluator, not a DSL.** Policies are built
  programmatically with a typed builder API (`abac.eq`/`abac.andAll`/`abac.attr`/…) rather
  than parsed from a string. This is a deliberate scope cut, not a shortcut: a string
  expression language needs its own grammar, parser, and parser-level DoS/injection
  hardening (the classic "policy strings are attacker-adjacent" problem when policies come
  from a multi-tenant admin UI) — none of which this module's stated scope asks for. The
  typed `Condition` union is exactly as expressive and is impossible to "parse" incorrectly
  because there is no parser.
- **Attribute categories.** `Attributes` holds four flat `name -> Value` maps —
  `subject`/`resource`/`action`/`environment`, the standard XACML/NIST-SP-800-162 attribute
  categories. `Value` is `string | int | bool | list(Value)`. Equality (`eq`/`ne`) is
  type-checked (comparing a `string` to an `int` is `error.TypeMismatch`, never a silent
  `false`); ordering (`lt`/`le`/`gt`/`ge`) is defined **only** for `int` — string/bool/list
  ordering is not supported (no locale-dependent or ambiguous lexical-order semantics to get
  wrong). `in` requires its RHS to resolve to a `.list`.
- **Depth-bounded evaluation — the DoS bound.** `evalCondition`/`evaluate` recurse into
  `and_`/`or_`/`not` up to `Policy.max_depth` (default `abac.default_max_depth = 32`) and
  return `error.MaxDepthExceeded` past it. This is the one bounded-evaluation guarantee the
  task requires: an adversarially deep (or accidentally cyclic-by-construction, e.g. a
  recursive builder bug) condition tree cannot exhaust the call stack — evaluation fails
  closed with a typed error rather than crashing.
- **Combining algorithms — `deny_overrides` (default) and `permit_overrides`, XACML-style.**
  Per rule, a condition evaluates to Permit-fires / Deny-fires (condition true) /
  NotApplicable (condition false, rule abstains) / Indeterminate (evaluation error). Across a
  rule set: `deny_overrides` returns Deny the instant any rule Denies, regardless of other
  Permits; `permit_overrides` is the mirror (Permit wins the instant one fires). Both then
  prefer Indeterminate over the "no rule fired" NotApplicable fallback if no immediate winner
  showed up, since an error mid-evaluation means the true answer is unknown, not "no
  opinion". **`deny_overrides` is the recommended and structural default** on `Policy` — for
  an authorization gate, "when in doubt, forbid" is the safer failure mode than "when in
  doubt, allow", and it matches XACML's own conventional default for security-sensitive
  policy sets.
- **`evaluate` vs `evaluateDetailed` — where the four-valued XACML model lives.** The task's
  "optionally NotApplicable/Indeterminate, your call" is resolved as: the four-valued
  `RuleOutcome` (`permit`/`deny`/`not_applicable`/`indeterminate`) exists and is exposed via
  `evaluateDetailed` for callers/auditors who want to distinguish "nothing matched" from "a
  rule errored" from an explicit deny in their logs. The everyday entry point, `evaluate`,
  collapses NotApplicable and Indeterminate into `.deny` and returns the shared two-valued
  `Decision` — so the **default-deny contract is structural in the type callers actually
  branch on**, not just a documented convention. `Decision.reason` still carries the
  original detail (e.g. "indeterminate: condition tree exceeded max evaluation depth") even
  after the collapse, so nothing is lost for logging.

## Threat model / out of scope

- **Not a persistence layer.** Both models are built/loaded into memory by the caller — no
  policy-file format (JSON/YAML/XACML-XML), no serialization, no storage backend. A caller
  wanting a wire format defines and parses it themselves, then constructs `rbac.Engine`
  calls / `abac.Policy` values from the result.
- **No crypto, no I/O.** This module never touches the network, disk, or `std.crypto` — it is
  pure decision logic over caller-supplied structures. Identity/authentication (who is this
  subject, is this token valid) is a different module's job (see `jwt`, `aaa-gate`); this
  module only decides "given this already-authenticated subject/attributes, is the action
  authorized."
- **RBAC deferred:** dynamic/session-based SoD (see above); NIST RBAC "sessions" and
  session-scoped role activation; permission-level or object-instance-level constraints
  beyond the flat `(action, resource)` pair (e.g. row-level/ownership checks) — those are
  naturally expressed as ABAC conditions instead (`resource.owner == subject.id`), not as an
  RBAC extension.
- **ABAC deferred:** a string policy DSL/parser (see design rationale above); the full XACML
  request/response protocol (obligations, advice, multiple-decision profile, policy
  administration point, PDP/PEP network protocol) — this module is the policy-decision
  *core* (condition evaluation + combining algorithm) an application wires into its own
  request path, not a XACML server; regex/wildcard/glob matching on string attributes (only
  exact equality is provided — a caller wanting pattern matching composes it before calling
  `put`, e.g. by pre-computing a `matches_pattern: bool` attribute).
- **Not a validator against malicious *policy authors*.** The depth bound defends the
  *evaluator* against a pathologically deep tree (accidental or adversarial), but the
  `Condition`/`Rule`/`Policy` values themselves come from trusted, in-process Zig code (the
  caller building the tree with the typed builder API), not from untrusted network input —
  there is no deserialization step here to attack. A caller that DOES build policies from
  untrusted input (e.g. reading a tenant-supplied policy file) is responsible for bounding
  *that* input (tree size/branching factor) before constructing a `Condition`; this module
  only bounds the recursion depth during *evaluation*.
- **RBAC hierarchy is admin-configured, not attacker-facing.** `addHierarchy`'s cycle check
  runs at edge-insertion time (an administrative operation), not per-request — this is
  appropriate because the caller wiring roles/hierarchy is a trusted administrator, unlike
  ABAC's `evaluate`, which runs per authorization *request* against attributes that may
  originate from less-trusted sources (hence that path is the one with the runtime depth
  bound).

## Verification

`zig build test-rbac` (Debug) and `zig build test-rbac -Doptimize=ReleaseFast`; 36/36 tests,
both green. This is policy logic with no external interop target — there is no third-party
"RBAC KAT" or "ABAC KAT" corpus to validate against (unlike e.g. a crypto primitive or wire
codec), so **self-constructed test cases are the correct verification approach here**, per
the task brief. Coverage:

- **RBAC:** direct grant permits (+ sibling: wrong action denies); inherited grant through
  hierarchy permits (+ sibling: same setup without the hierarchy edge denies); denial when
  unassigned (+ sibling: assigning the role flips it to permit); cycle detection rejects a
  cyclic edge and a self-edge (+ sibling: a non-cyclic edge on the same chain succeeds);
  static SoD rejects a conflicting assignment in both pair orderings (+ sibling: an unrelated
  third role assigns fine); unknown-role errors from every mutating method that references a
  role.
- **ABAC:** every operator (`eq`/`ne`/`lt`/`le`/`gt`/`ge`/`in`) each with its minimal-flip
  deny sibling; ordering-on-non-int is `error.TypeMismatch`; `And`/`Or`/`Not` composition
  each with a sibling that flips the minimal clause; default-deny when no rule matches (+
  sibling: matching the rule flips it to permit); `deny_overrides` vs `permit_overrides` on
  the *identical* rule set and attributes (proving the algorithm, not rule order, decides);
  the default algorithm is `deny_overrides`; depth-bound rejection of a 40-deep `not` chain
  against `default_max_depth = 32` (+ sibling: the same shape at depth 10 evaluates
  correctly, including odd/even negation parity) and its collapse to `Decision.deny` through
  `evaluate`; a missing attribute is `Indeterminate` at the `evalCondition` level and collapses
  to `Decision.deny` through `evaluate`.

Every "should-permit"/"should-match" test above has an adjacent "should-deny"/"should-fail"
sibling built by the minimal change that flips the outcome (a wrong field, a missing edge, an
unmet boundary, a swapped algorithm) — proving each check actually has discriminating power
rather than passing by default-deny alone.

## Backlog / deferred

- Dynamic (session-based) SoD — needs a session/role-activation concept this module
  deliberately doesn't have (see Design & invariants).
- Policy-file format / (de)serialization for either model.
- String policy DSL for ABAC (typed builder API only, by design).
- Full XACML protocol surface (obligations/advice/PAP/PDP-PEP wire protocol, multiple-decision
  profile) — only the condition-evaluation + combining-algorithm core is in scope.
- Pattern/regex/glob matching on string attributes.
