# argsafe

Allowlist validators + a typed argv builder that neutralize **argument / flag
injection** when an exec `argv` is assembled from untrusted input.

Provenance: consolidates the 14 ad-hoc `*Safe` predicates in
`axp-core/src/task.zig` (user's own code, MIT) — `ubusNameSafe`, `readPathSafe`,
`logLevelSafe`, `sysctlKeySafe`, `sysctlValueSafe`, `timeSpecSafe`, `uciNameSafe`,
`fwKeySafe`, `fwValueSafe`, `wgKeySafe`, `wgAllowedIpsSafe`, `ledNameSafe`,
`uciGetKeySafe`, `pkgNameSafe`, `urlSafe`, `svcNameSafe`. Each one hand-rolled a
character-class + length check guarding a `std.process.run(.{ .argv = ... })`
call site, with no shared abstraction. This is a **design consolidation**
(pattern distillation, not a copy): one composable `CharClass` primitive, a set
of convenience predicates on top, and an `Argv` builder that makes an
unvalidated argv element unrepresentable. No third-party code.

- **Status:** `gap`. **Model after:** allowlist validators (shlex.quote-adjacent)
  + a typed argv builder.
- **Platform:** any (pure byte checks; the *semantics* are POSIX argv — see
  Boundaries). **Role:** util. **Concurrency:** reentrant — every function is
  pure over its arguments; no shared state.
- **Deps:** `std` only.

## Security model

The values validated here only ever become **array elements** of an argv passed
to `std.process.run` / `std.process.Child` — never a byte of a shell command
string. There is no shell to quote against. What we neutralize:

| Threat | Guard | Default |
|---|---|---|
| **Flag injection** (`-rf`, `--foo` read as an option, not a positional) | reject a leading `-` | on |
| **NUL smuggling** (truncates the C string `execve` sees) | reject any `0x00` | always on (not overridable) |
| **Control-byte / newline** injection | reject `< 0x20` and `0x7f` | on |
| **Path traversal** (`..`) | reject configured substrings | on (`..`) |
| Length abuse | `min_len` / `max_len` | on |

The seed only guarded a leading `-` and `..` in *some* of its 14 copies; here the
safe path is the **default** for all of them.

## API

### `CharClass` — the one primitive the 14 validators collapse to

```zig
const argsafe = @import("argsafe");

// ubusNameSafe: alnum + `_-.*`, first alnum, ≤128:
const ubus: argsafe.CharClass = .{ .extra = "_-.*", .first_char = .alnum };
if (!ubus.check(object)) return error.BadName;
```

Fields: `allow_alnum` (default true), `extra: []const u8`, `min_len`/`max_len`
(default 1 / 128), `first_char: enum { any, alnum, not_digit, not_dash }`,
`reject_substrings` (default `&.{".."}`), `reject_leading_dash` (default true),
`reject_control` (default true). `check(s) bool` never allocates or panics.
`predicate()` adapts a comptime-known class to a plain `fn([]const u8) bool`.

### Convenience predicates

| Function | Shape | Seed origin |
|---|---|---|
| `isSafeIdentifier(s)` | `[A-Za-z0-9_-]`, first alnum, 1..128 | `svcNameSafe` / `ubusNameSafe` |
| `isSafePath(s)` | absolute, no `..`, no control, ≤4096 | `readPathSafe` (**+`..` fix**) |
| `isSafeUrl(s)` | `http(s)://`, no control/space, no `" ' \` `` ` `` | `urlSafe` |
| `isSafeBase64(s, exact_len)` | `[A-Za-z0-9+/=]`, optional exact length | `wgKeySafe` (44) |
| `isSafeCidrList(s, sep)` | hex + `. : /` + `sep`, 1..256 | `wgAllowedIpsSafe` |
| `isSafeKvValue(s, printable_ascii)` | printable ASCII, or `[A-Za-z0-9._:/-]` | `sysctlValueSafe` / `fwValueSafe` |
| `isInAllowlist(s, comptime allowed)` | exact membership | `logLevelSafe` / `fwKeySafe` |

### `Argv` — a builder that can't hold an unvalidated element

```zig
var argv: argsafe.Argv = .empty;
defer argv.deinit(gpa);
try argv.push(gpa, "wg");                                   // trusted comptime literal
try argv.push(gpa, "set");
try argv.pushChecked(gpa, iface, .{ .extra = "_-.*", .first_char = .alnum });
try argv.push(gpa, "peer");
try argv.pushIf(gpa, pubkey, struct {                       // any fn([]const u8) bool
    fn f(s: []const u8) bool { return argsafe.isSafeBase64(s, 44); }
}.f);
const res = try std.process.run(gpa, io, .{ .argv = try argv.slice() });
```

The security property: the only append methods are `push` (a **comptime** literal
— cannot be untrusted run-time input) and `pushChecked` / `pushIf` (validated).
There is no public raw-append. A rejected push **poisons** the builder, so
`slice()` returns `error.Rejected` even if the caller swallowed the earlier
error — a validation failure can never silently ship a short argv.

## Boundaries (deferred — out of scope for v1)

- **Windows `CommandLineToArgvW` quoting.** This module is POSIX-argv only. On
  Windows the CRT re-parses one command line via `CommandLineToArgvW`, whose
  backslash-before-quote rules are a sharper, different hazard. A Windows argv
  quoter is a separate concern and is **not** covered here.
- **Environment-variable injection.** Scope is argv only; a validated allowlist
  for the child environment (`std.process.Child.env_map`) is out of scope.
- **Per-encoding length rationale.** The convenience predicates keep the seed's
  byte bounds (path ≤4096, url ≤1024, cidr ≤256, base64 44/≤512); a
  first-principles justification per encoding is not attempted — they are the
  proven-in-production ceilings from axp.

## Verification

`zig build test-argsafe` — golden allow/reject tables reconstructing the seed
validators (incl. base64 exactly-44 with 43/45 rejected, `isSafePath` now
rejecting the `..` the seed accepted), a property-style adversarial sweep
feeding every predicate a raw NUL / `\n` / leading `-` / `..` / DEL / ESC and
asserting none are accepted, and `Argv` tests (validated build; a rejected
`pushChecked`/`pushIf` poisons `slice()`). Green in Debug and
`-Doptimize=ReleaseFast`; `zig fmt --check modules/argsafe` clean.
