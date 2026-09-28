# argsafe

Allowlist validators + a typed argv builder that neutralize **argument / flag
injection** when an exec `argv` is assembled from untrusted input.

Provenance: original work of the zig-libs authors (MIT) — a design
consolidation of 14 ad-hoc `*Safe` predicates (`ubusNameSafe`, `readPathSafe`,
`logLevelSafe`, `sysctlKeySafe`, `sysctlValueSafe`, `timeSpecSafe`, `uciNameSafe`,
`fwKeySafe`, `fwValueSafe`, `wgKeySafe`, `wgAllowedIpsSafe`, `ledNameSafe`,
`uciGetKeySafe`, `pkgNameSafe`, `urlSafe`, `svcNameSafe`), each of which hand-rolled a
character-class + length check guarding a `std.process.run(.{ .argv = ... })`
call site, with no shared abstraction. This is a **design consolidation**
(pattern distillation, not a copy): one composable `CharClass` primitive, a set
of convenience predicates on top, and an `Argv` builder that makes an
unvalidated argv element unrepresentable. No third-party code.

- **Model after:** allowlist validators (shlex.quote-adjacent)
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

The safe path is the **default** for every predicate — a leading `-` and `..` are
guarded everywhere, not just in selected call sites.

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

| Function | Shape | Covers |
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

### `Template` — an argv shape from a trusted config, holes filled from untrusted values

```zig
const holes = [_]argsafe.Hole{
    .{ .name = "unit", .class = .{ .extra = "_-.@", .first_char = .alnum } },
};
const t = try argsafe.Template.parse(&.{ "systemctl", "restart", "{unit}" }, &holes);

var out = try t.fill(gpa, &.{unit_value}); // one value per hole, same order as `holes`
switch (out) {
    .ok => |*filled| {
        defer filled.deinit();
        const res = try std.process.run(gpa, io, .{ .argv = filled.argv });
    },
    .refused => |r| std.log.warn("{s}: refused ({})", .{ r.hole, r.why }),
}
```

For a runner whose command lines come from an admin-written config
(`["systemctl", "restart", "{unit}"]`, one `CharClass` per named hole) rather
than being built in Zig source. `Template.parse` validates up front and
allocates nothing — `tokens`/`holes` are borrowed, so the config must outlive
every `fill` call. It fails closed on a config error, never a per-value
refusal: `error.UnknownHole` (a `{name}` not in `holes`), `error.HoleInArgv0`
(any hole in the program name, valid or not), `error.UnbalancedBrace`, or
`error.DuplicateHoleName`. A hole may be the whole token or sit inside one
(`"--unit={unit}"`), and the same hole may be **reused** — every occurrence
substitutes the identical value. Write a literal `{`/`}` doubled — `{{`/`}}`
— the same convention as `std.fmt`/Python `str.format`.

`fill` checks every value with `hole.class.explain(value)` — the exact same
rule `pushChecked` runs — **before** building anything, so a templated value
is held to identical rules as a hand-built `Argv`. A leading `-` is refused
regardless of where the hole sits in its token (not just when the hole is the
whole token) — deliberately position-independent, so the same hole can't be
"safe" in one token and "dangerous" in another depending on where the braces
land; opt out per-hole with `.{ .reject_leading_dash = false }` when a hole is
known to sit somewhere a leading `-` can't reach argv-token start (the same
escape hatch `CharClass` already documents for a value passed after `--`).
The result is a tagged `FillOutcome`: `.ok` (a `Filled` owning its argv in one
arena — `Filled.deinit` frees it) or `.refused = .{ hole, why: CharClass.Reason }`.

`CharClass.explain(s) ?CharClass.Reason` backs the refusal: `check(s)` is now
just `explain(s) == null`, so the two can never disagree. `Reason` names which
rule failed (`too_short`, `too_long`, `nul_byte`, `leading_dash`,
`forbidden_substring`, `bad_first_char`, `control_byte`, `bad_byte`) for a UI
that wants to say why without re-implementing `check`.

## Boundaries (deferred — out of scope for v1)

- **Windows `CommandLineToArgvW` quoting.** This module is POSIX-argv only. On
  Windows the CRT re-parses one command line via `CommandLineToArgvW`, whose
  backslash-before-quote rules are a sharper, different hazard. A Windows argv
  quoter is a separate concern and is **not** covered here.
- **Environment-variable injection.** Scope is argv only; a validated allowlist
  for the child environment (`std.process.Child.env_map`) is out of scope.
- **Per-encoding length rationale.** The convenience predicates use fixed
  byte bounds (path ≤4096, url ≤1024, cidr ≤256, base64 44/≤512); a
  first-principles justification per encoding is not attempted — they are
  proven-in-production ceilings.

## Verification

`zig build test-argsafe` — golden allow/reject tables covering every
validator (incl. base64 exactly-44 with 43/45 rejected, `isSafePath`
rejecting `..`), a property-style adversarial sweep
feeding every predicate a raw NUL / `\n` / leading `-` / `..` / DEL / ESC and
asserting none are accepted, and `Argv` tests (validated build; a rejected
`pushChecked`/`pushIf` poisons `slice()`). Green in Debug and
`-Doptimize=ReleaseFast`; `zig fmt --check modules/argsafe` clean.
