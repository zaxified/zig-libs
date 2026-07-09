# argsafe — spec

Allowlist validators + a typed argv builder neutralizing argument/flag injection into an exec argv.
Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
- **`CharClass`** — the one composable predicate every convenience function collapses to: byte-class
  + length + structural checks (`allow_alnum`, `extra`, `min_len`/`max_len`, `first_char`,
  `reject_substrings`, `reject_leading_dash`, `reject_control`). `check()` never allocates or
  panics; `predicate()` adapts a comptime-known class to `fn([]const u8) bool`.
- **Convenience predicates** (`isSafeIdentifier`, `isSafePath`, `isSafeUrl`, `isSafeBase64`,
  `isSafeCidrList`, `isSafeKvValue`, `isInAllowlist`) cover the common validator shapes on top of
  `CharClass`, with the safe behavior (leading-dash reject, `..` reject) as the **default** for all
  of them.
- **`Argv`** builder makes an unvalidated element unrepresentable: the only append methods are
  `push` (comptime-literal only — cannot carry runtime input) and `pushChecked`/`pushIf`
  (validated). A rejected push **poisons** the builder so `slice()` returns `error.Rejected` even if
  the caller swallowed the earlier error — a validation failure can never silently ship a short
  argv.
  - **Limitation:** "impossible to construct an invalid `Argv`" is an *API contract*, not a
    compiler-enforced one — Zig has no field-level privacy (no `private`/module-boundary field
    access control within the same file), so `Argv.items`/`Argv.ok` are technically reachable and a
    caller could mutate them directly, bypassing every validator. Callers MUST treat the fields as
    implementation detail and only ever go through `push`/`pushChecked`/`pushIf`/`slice`/`deinit`. A
    future refactor should consider a stronger encapsulation (e.g. an opaque handle plus an
    accessor in a separate file) to make the invariant harder to violate by accident.
- Pure, reentrant, no shared state; every function is pure over its arguments. Std-only.

## Threat model / out of scope
Values validated here only ever become **array elements** of an argv passed to
`std.process.run`/`std.process.Child` — never a byte of a shell command string; there is no shell to
quote against. Neutralizes: flag injection (reject leading `-`), NUL smuggling (always rejected, not
overridable), control-byte/newline injection, path traversal (`..`), and length abuse. Out of scope:
Windows `CommandLineToArgvW` quoting (POSIX argv only — Windows backslash-before-quote rules are a
different hazard, not covered); environment-variable injection (`std.process.Child.env_map` is out
of scope, argv only); no first-principles justification for the per-encoding length bounds — they
are the proven-in-production ceilings carried from the pre-consolidation validators (path ≤4096, url ≤1024, cidr ≤256, base64
44/≤512).

## Verification
`zig build test-argsafe`. Golden allow/reject tables covering every validator (incl.
base64 exactly-44 with 43/45 rejected, `isSafePath` rejecting `..`,
`isSafeCidrList` rejecting a leading dash even when the caller's `sep` is `'-'` itself), a
property-style adversarial sweep feeding every predicate a raw NUL/`\n`/leading-`-`/`..`/DEL/ESC and
asserting none are accepted, and `Argv` tests (validated build; a rejected `pushChecked`/`pushIf`
poisons `slice()`). 18 tests. Green in Debug and ReleaseFast; `zig fmt --check` clean.

## Backlog / deferred
Windows argv quoting and environment-variable-injection allowlisting are explicitly out of scope for
v1 (see Threat model). No other deferred items in README beyond the general pre-public
review pass.

## Status
`gap · any · util · reentrant` + deps: none (std only) — canonical source is `pub const meta` in
src/root.zig.
