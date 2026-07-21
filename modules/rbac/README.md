# rbac

Authorization **decision engine**: RBAC (role-based, NIST core + hierarchical) and ABAC
(attribute-based, a depth-bounded typed condition-tree evaluator with XACML-style combining
algorithms), sharing one `Decision{ result: permit|deny, reason }` result shape. Pure policy
logic — no crypto, no I/O, no persistence: both models are built/loaded in memory by the
caller. Identity/authentication (is this token valid, who is this subject) is a different
module's job (see `jwt`, `aaa-gate`); `rbac` only answers "is this already-identified subject
authorized to do this."

- **Model after:** NIST RBAC core + hierarchical RBAC (INCITS 359-2012); XACML 3.0 combining
  algorithms for the ABAC half.
- **Platform:** any (pure in-memory logic, no OS calls). **Role:** util. **Concurrency:**
  reentrant — no shared global state; each `Engine`/`Policy`/`Attributes` is owned by its
  caller.
- **Default-deny, structurally:** `rbac.Engine.check` denies an unknown user, an unassigned
  user, or a user whose roles don't cover the permission; `abac.evaluate` collapses
  "no rule matched" and "a rule errored" (missing attribute, type mismatch, depth-bound
  exceeded) into `Decision.deny` — the everyday entry point's *type* is the two-valued
  `Decision`, so default-deny isn't just documented, it's what callers actually branch on.

Provenance: clean-room implementation from the public NIST RBAC / XACML specs — no
third-party source ported or implementation consulted; see SPEC.md and NOTICE (§5:
public-spec implementations need no NOTICE entry).

## RBAC API

```zig
const rbac = @import("rbac").rbac;

const Permission = struct { action: []const u8, resource: []const u8 };
const Error = error{ OutOfMemory, UnknownRole, CyclicHierarchy, ConflictingRole };

var engine = rbac.Engine.init(allocator);
defer engine.deinit(); // frees everything the engine owns (one internal arena)

try engine.addRole("viewer");
try engine.addRole("editor");
try engine.addPermission("viewer", .{ .action = "read", .resource = "doc" });
try engine.addPermission("editor", .{ .action = "write", .resource = "doc" });

// senior inherits junior's permissions, transitively; rejects a cycle/self-edge.
try engine.addHierarchy("editor", "viewer");

// static separation-of-duty: these two roles can never both be on one user.
try engine.addStaticSoD("payer", "approver");

try engine.assignRole("alice", "viewer");   // error.ConflictingRole on an SoD violation
                                              // error.UnknownRole if the role doesn't exist

const decision = engine.check("alice", "read", "doc"); // -> Decision
if (decision.isPermit()) { ... }
```

All strings passed to a mutating `Engine` method are duped into the engine's internal arena
— callers never need to keep arguments alive past the call.

## ABAC API

```zig
const abac = @import("rbac").abac;

// attributes for one evaluation request
var attrs: abac.Attributes = .{};
defer attrs.deinit(allocator);
try attrs.put(allocator, .subject, "department", abac.str("eng"));
try attrs.put(allocator, .resource, "owner_dept", abac.str("eng"));
try attrs.put(allocator, .environment, "hour", abac.int(10));

// typed condition tree (no string DSL) — mirrors:
//   subject.department == resource.owner_dept AND environment.hour IN [9..17)
const cond = abac.andAll(&.{
    abac.eq(abac.attr(.subject, "department"), abac.of(abac.attr(.resource, "owner_dept"))),
    abac.ge(abac.attr(.environment, "hour"), abac.lit(abac.int(9))),
    abac.lt(abac.attr(.environment, "hour"), abac.lit(abac.int(17))),
});

const rules = [_]abac.Rule{
    .{ .id = "business-hours-same-dept", .effect = .permit, .condition = cond },
};
const policy: abac.Policy = .{
    .rules = &rules,
    .algorithm = .deny_overrides, // default; .permit_overrides also available
    .max_depth = abac.default_max_depth, // 32; bounds And/Or/Not recursion
};

const decision = abac.evaluate(policy, &attrs); // -> Decision (permit/deny, default-deny)
const detailed = abac.evaluateDetailed(policy, &attrs); // -> full XACML 4-valued RuleOutcome
```

Operators: `eq`/`ne` (type-checked, any `Value` kind), `lt`/`le`/`gt`/`ge` (int only),
`in` (RHS must resolve to a `.list`), `andAll`/`orAny`/`not` for composition. `Value` =
`string | int | bool | list(Value)`. Evaluation is depth-bounded (`error.MaxDepthExceeded`
past `Policy.max_depth`) so an adversarially/accidentally deep tree cannot exhaust the stack.

## Verify

```sh
zig build test-rbac
zig build test-rbac -Doptimize=ReleaseFast
```

Self-constructed unit tests (36) — see SPEC.md for why no external KAT applies to policy
logic, and for the design rationale behind the `deny_overrides` default and the
`evaluate`/`evaluateDetailed` split.
