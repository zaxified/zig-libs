# diagnostics — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
LSP-style structured validation-finding collector: an ordered `Diagnostics` list of `error`/
`warning`/`info` findings, each with a dot-separated tree path, optional 1-based source line/col
(+ end position), an optional in-expression byte offset/length for token highlighting, a
machine-readable `code`, a `message`, and an optional did-you-mean `suggest`. `append` grows the
caller-owned list; `count`/`countBySeverity` are the read side (e.g. gate saving on zero errors).
Platform: any. Role: util. Concurrency: reentrant (no shared state — safe if not shared).
Allocation: owned by the caller-supplied allocator; the collector holds no ownership beyond its own
`items` list — all strings referenced by an appended `Diagnostic` (path/message/suggest) are
expected to outlive the collector, typically because both live in the same arena freed in one shot
at the validation boundary; callers must dupe strings that need to outlive that arena. Modeled after
LSP's `Diagnostic` type / rustc diagnostics; extracted from bxp-core's config/json5/expr validation
pass (`bxp-core/src/diagnostics.zig`, user's own code) — no third-party source. See NOTICE.

## Threat model / out of scope
Not security-sensitive; it is a passive data collector with no I/O, no parsing, and no trust
boundary of its own — whatever a caller `append`s is stored verbatim. Out of scope, deferred: it
does not itself validate anything (callers build `Diagnostic` values from their own checks), and it
never dereferences the referenced strings beyond storing the slice, so a caller that frees path/
message/suggest memory before reading the collector back gets a dangling-slice bug that is the
caller's responsibility, not this module's.

## Verification
4 tests: append + count/countBySeverity accounting across severities, the doc-comment usage
pattern (arena-lifetime append then read), and structural field coverage (path/line/col/end/
byte-offset/code/message/suggest all round-trip through `items`). Run: `zig build test-diagnostics`.

## Backlog / deferred
Deferred from v1, per the module README: rendering to a human-readable string
(rustc-style caret/source-snippet output); JSON serialization of diagnostics; sorting diagnostics by
source position. The sibling `json5` module additionally intends to formalize its
`AnnotatedResult` against this module (a `json5`-side integration task, not a `diagnostics` gap).

## Status
`extract · any · util · reentrant` · deps: none — canonical source is `pub const meta` in
src/root.zig.
