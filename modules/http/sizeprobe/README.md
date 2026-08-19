# http Client size probe

Verification tool for the plaintext-only `http.Client` split
(`Client.requestPlain` / `requestStreamingPlain` / `putFilePlain`, alongside
`dialPlain`/`dialTls` — see their doc comments in `../src/Client.zig`). Not
wired into the repo's `zig build`: this is a one-off, documented probe, not a
unit test — see "Why not a Zig test" below for why the actual property it
proves cannot be a `zig build test-http` assertion.

## What this proves, and how

A consumer — a device agent on an 8 MB router overlay — measured
`http.Client` at +351 000 B on x86-64 musl/ReleaseSmall and +607 200 B on
big-endian MIPS32 for two plaintext one-shot operations — a `putFile` upload
and a `request` + `streamRemaining` fetch, both to an IP literal, no TLS. A
follow-up measurement attributed ~90% of that (325 760 B) to one thing: the
TLS reference. `dialConn` computed `tls_needed` from a **runtime** URL value,
so `Client.zig`'s single `if (tls_needed)` branch forced Sema to analyse the
whole TLS client (handshake state machine, X.509 parse/verify, every
hash/curve/AEAD it pulls in) for EVERY caller, plaintext-only or not.

The fix is a decl-level split: `dialPlain` (whose body names nothing from
`tls`/`ensureCaBundle`/`Certificate`) alongside `dialTls`, reached only by
`requestPlain`/`requestStreamingPlain`/`putFilePlain` — which never call
`dialConn`/`dialTls` at all, so nothing forces Sema to analyse the TLS
client for a binary that only calls the plaintext entry points. `request`/
`requestStreaming`/`putFile` are unchanged and still go through `dialConn`
(now a two-line dispatcher onto `dialPlain`/`dialTls`), so they keep costing
what they always cost — TLS included.

`run.sh` builds, for two targets (x86_64-linux-musl and mips-linux-musleabi
— big-endian MIPS32, the second target that consumer measured), two pairs of static
`ReleaseSmall` executables via `build.zig`:

- `probe_before.zig` — the consumer's two call sites through `request`/`putFile`
  (the original, TLS-capable entry points every existing caller still uses).
- `probe_after.zig` — the same two call sites through `requestPlain`/
  `putFilePlain` (the new split).

Each pair is built twice: once as ships (stripped — the size-comparison
numbers below), once with symbols kept (`_syms` — for `nm`). A stripped
binary has no symbol table at all, so `nm` on one is vacuous either way, not
evidence of anything; the size comparison and the symbol check therefore
necessarily come from different builds of the same source.

## Last measured numbers (2026-08-18, zig 0.16.0)

| target | probe_before | probe_after | delta | the real agent's delta |
|---|---:|---:|---:|---:|
| x86_64-linux-musl | 490 408 B | 165 520 B | **324 888 B** | 351 000 B (+49%, fuller agent) |
| mips-linux-musleabi (BE MIPS32) | 923 904 B | 238 576 B | **685 328 B** | 607 200 B (fuller agent) |

The x86_64 delta (324 888 B) lands within 1 KB of the 325 760 B the earlier
attribution measurement predicted for "the TLS reference" alone — strong
confirmation this split removes exactly that cost and nothing else. The MIPS
delta is larger in this isolated two-call-site probe than in the real
agent, because that agent carries substantial non-HTTP code that dilutes the
same absolute TLS cost into a smaller percentage; the mechanism is identical.

`nm -C zig-out/<target>/bin/probe_after_syms` reports **zero** matches for
`tls\.Client|Certificate|X25519|P256|P384|Sha1|Sha256|Sha3|Sha512|Rsa|MlKem|
Aegis|Aes(128|256)?Gcm|ChaCha20Poly1305` on both targets. The same grep
against `probe_before_syms` matches 196 times on both — proof the grep
pattern itself is not vacuous (it would catch a real reference if one were
there).

## Usage

```
modules/http/sizeprobe/run.sh
```

Run from anywhere; it `cd`s to its own directory. Builds and cleans up its
own `zig-out/`/`.zig-cache/` subdirectories (both already covered by the
repo's top-level `.gitignore` patterns). Exits non-zero if either target's
`probe_after_syms` references a TLS/crypto symbol.

## Why not a Zig test

A Zig test can only observe the runtime *behavior* of one already-linked
binary — the whole `test-http` suite, TLS included — so "this symbol is
absent from a differently-scoped binary" is not a thing any Zig test can
assert; see `Client.zig`'s test
`"requestPlain/requestStreamingPlain/putFilePlain: https:// is rejected
before any dial"` for what IS covered by a unit test (the scheme guard's
behavior and `dialCount() == 0`), and what that test's own doc comment says
it does NOT guarantee.
