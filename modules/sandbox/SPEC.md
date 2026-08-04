# sandbox — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: original work of
the zig-libs authors (MIT) — see the UAPI citation below.

## UAPI citation (why no NOTICE entry)

Every constant, struct layout and the seccomp BPF program are **clean-room from the Linux kernel
UAPI** — an OS ABI, not a copyrightable work (merger doctrine: there is exactly one way to spell
`PR_SET_NO_NEW_PRIVS = 38` or `struct sock_filter`). No third-party implementation
(libseccomp, libcap, systemd, OpenSSH's `sandbox-seccomp-filter.c`, Cloudflare's sandbox) was
ported or studied for algorithm/API shape; those are named only as prior art that hardens the same
way. Per CONVENTIONS.md §5 a pure clean-room-from-UAPI module needs **no NOTICE entry** — the
citation lives here:

- `prctl.h` — `PR_SET_NO_NEW_PRIVS` (38), `PR_SET_SECCOMP` (22), `PR_CAPBSET_DROP` (24).
- `seccomp.h` — `SECCOMP_MODE_FILTER` (2), `SECCOMP_RET_*` action words, `struct seccomp_data`.
- `filter.h` / `bpf_common.h` — classic-BPF `struct sock_filter` (8 bytes) + `sock_fprog`, opcode
  classes (BPF_LD/JMP/RET, BPF_W/ABS, BPF_JEQ/K).
- `landlock.h` — `landlock_create_ruleset`/`add_rule`/`restrict_self` (syscalls 444/445/446),
  `struct landlock_ruleset_attr`, packed `struct landlock_path_beneath_attr`, `LANDLOCK_ACCESS_FS_*`,
  the ABI-version negotiation via `LANDLOCK_CREATE_RULESET_VERSION`.
- `capability.h` — `_LINUX_CAPABILITY_VERSION_3` (0x20080522), the v3 two-word data layout.
- `audit.h` + `elf.h` — `AUDIT_ARCH_*` = `EM_<arch>` OR'd with the 64-bit/little-endian flags,
  computed directly (std's `linux.AUDIT.ARCH` enum is unbuildable in Zig 0.16 — a bad `elf.EM.FRV`
  member — so the arch token is derived clean-room from `builtin.cpu.arch`).

## Design & invariants

- **Five independent, opt-in steps; the caller picks and orders them.** A server applies these last,
  after `bind`/`listen` and opening every privileged fd. Nothing here is a global — each function is
  a thin, verified wrapper over one syscall family.
- **Order-safety is enforced, not documented.** `dropPrivileges` does `setgroups([]) → setgid →
  setuid` (the only safe order — setuid first strips the privilege setgid/setgroups themselves need)
  and then **reads back** `getuid`/`geteuid`/`getgid`/`getegid`, returning `error.DropNotEffective`
  if any of the real *or* effective ids did not become the target. A partial/spoofed drop is fatal,
  never silently tolerated.
- **seccomp is an allow-list with a mandatory arch guard.** The generated classic-BPF program loads
  `seccomp_data.arch`, KILLs on a mismatch (always KILL, independent of the configured deny action —
  a foreign ABI like x86-64's x32 reuses syscall numbers and must not be able to alias an allowed
  `nr`), loads `nr`, then a linear `JEQ nr_i → ALLOW` chain with a single deny leaf. Jump offsets
  (`jt`) are a `u8`, so the flat encoding caps at 255 allowed calls (`error.TooManySyscalls` past
  that). The default allow-list is comptime-filtered by `@hasField(linux.SYS, name)` so it stays
  valid on any arch. `sock_filter` is asserted 8 bytes; `landlock_path_beneath_attr` asserted 12
  (packed u64+s32) so the byte layout matches the kernel's `copy_from_user`.
- **The W^X preset (`seccomp.buildWx`/`buildDefaultWx`) adds argument-checked blocks, not a
  different filter shape.** For each of `{mmap, mprotect, pkey_mprotect}` present in the allow-list,
  a self-contained 9-instruction block sits ahead of the plain nr dispatch: reload `nr`, compare to
  this syscall (local jump, skip the block on mismatch), load the high 32 bits of `arg2` (`prot`) and
  deny if non-zero, load the low 32 bits, `AND` with `PROT_WRITE|PROT_EXEC`, and deny if the result
  equals the mask (both bits set) — otherwise `ALLOW` directly. Every jump inside a block is a small
  local offset (0/1/3/7), so blocks don't need to know the program's total length or each other's
  position, unlike the plain dispatch chain (which needs the overall count for its descending `jt`).
  Two things a naive version gets wrong: comparing `prot == (WRITE|EXEC)` instead of a masked AND
  (misses `READ|WRITE|EXEC`), and inspecting only the low 32-bit half of the 64-bit `arg2` register
  (a raw syscall bypassing libc's int zero-extension can put anything in the high half, so a
  low-word-only filter is checking a different value than what actually reaches the kernel — a
  non-zero high word is treated as a violation here, not ignored). `PROT_WRITE`/`PROT_EXEC` are
  hardcoded (`0x2`/`0x4`, `mman-common.h`, identical on every Linux arch) rather than taken from
  std's `linux.PROT`, whose packed-struct field layout isn't a byte-order-independent value to
  compare inside a BPF program.
- **`seccomp.installTsync` uses the `seccomp(2)` syscall (not `prctl`) with `SECCOMP_FILTER_FLAG_TSYNC`**
  to apply a filter to every thread of the process atomically, for the case where hardening happens
  after workers already exist (`install()`'s prctl form only ever touches the calling thread).
  `TSYNC`'s failure convention is the trap: on a thread-sync failure the raw return value is the
  *positive tid* of the first thread that failed to sync — not a negated errno — so reusing
  `install()`'s `linux.errno(rc) != .SUCCESS` check here would silently read that as success (a
  positive value decodes to `.SUCCESS` under `linux.errno`'s `(-4096, 0)` window). `installTsync`
  checks for this explicitly and reports `error.ThreadSyncFailed` rather than `error.SeccompFailed`.
- **Landlock degrades, never faults, on old kernels.** The ABI version is queried first
  (`landlock_create_ruleset(NULL,0,VERSION)`); the handled-access mask and each rule's allowed-access
  are intersected with the bits that ABI understands, so passing a newer access bit to an older
  kernel can't trigger EINVAL. Pre-5.13 / disabled surfaces as `error.NotSupported` / `error.Disabled`.
- **Raw errno syscalls, no libc.** Every call goes through `std.os.linux` directly (`prctl`,
  `setgroups`/`setgid`/`setuid`, `setrlimit`, `capset`, and `syscall2/3/4` for the three landlock
  numbers). Failures are typed errors; there is no path that panics on a malformed or
  unsupported-kernel result — a server must be able to log and choose policy.
- **Concurrency:** single_owner — applied once at startup by the owning thread. The prctl-form
  seccomp install and Landlock `restrict_self` affect the calling thread (and its future children);
  install before spawning workers, or use the deferred `seccomp(2)` TSYNC form.

## Threat model / out of scope

**Linux-only by design** — no OpenBSD `pledge`/`unveil`, no FreeBSD Capsicum, no cross-platform
abstraction attempted. This module **reduces** a process's own privilege; it is not an access-control
policy engine and does not decide *what* a service may do — that is the deployment's choice, encoded
in the allow-lists/paths/ids the caller passes. **Irreversibility is the point:** no-new-privs,
seccomp, Landlock `restrict_self` and a real uid drop cannot be undone, so a bug that hardens too
aggressively bricks the process (fail-closed) rather than silently leaving it open — the audit
concern is a filter that is too *loose* (defeats the purpose) far more than one too tight. The
default seccomp allow-list is explicitly a **starting point** to be profiled and tuned per binary,
not a vetted policy for any given program; shipping it unmodified can either break a program that
uses a syscall it omits or leave reachable a syscall it includes. The plain `build`/`install` path
filters on the syscall *number* only — argument filtering beyond the W^X preset (e.g. restricting
`socket` address families or `ioctl` requests) is deferred, so a number-level allow of
`ioctl`/`socket` still admits every variant; `mmap`/`mprotect`/`pkey_mprotect` get the one argument
check this module ships (`buildWx`/`buildDefaultWx`, PROT_WRITE|PROT_EXEC). Landlock covers the
filesystem (and, when built out, network ports); it does not restrict already-open fds, IPC, or
ptrace — pair it with seccomp + a namespace for those. Out of scope: general seccomp arg matching
(non-PROT), Landlock net/scoped rules, BSD sandboxing.

## Verification

The enforcement tests **fork a child**, apply one restriction, attempt the forbidden action and
assert the child terminates exactly as configured, with a control child (no restriction) succeeding —
the only honest way to test a security boundary; a pure unit test would prove nothing about the
kernel actually enforcing it. Unprivileged and always-run: seccomp (KILL child dies of `SIGSYS`,
ERRNO child sees `-EPERM`, control survives), the same KILL/ERRNO shape re-verified through
`installTsync`'s `seccomp(2)` path, a cross-thread test that spawns a worker *before* installing
(via `installTsync`) and confirms the worker's own denied syscall brings the whole process down
(proof `TSYNC` actually reached a thread that never called into seccomp itself — `install()`'s
prctl form cannot do this), the W^X preset (RW `mprotect`/`mmap` still succeed; RWX denied; a raw
syscall with a crafted non-zero high word on the `prot` argument is denied too, proving the 64-bit
argument check and not just its low half is active), Landlock (child confined to a temp dir is
denied `/etc/passwd`, allowed its own file — skips pre-5.13), rlimit (`RLIMIT_NOFILE` bites at the
cap with EMFILE and cannot be raised back; `RLIMIT_CORE=0`). Root-gated + `SkipZigTest` otherwise:
privilege drop (drops to `nobody`, asserts `setuid(0)` fails) and capability bounding-set drop.
Pure/logic tests cover the BPF program shape (arch guard + per-syscall compare + allow/deny leaves +
descending `jt`), struct ABI sizes, and the monotone Landlock access mask. Run:
`zig build test-sandbox` (add `-Doptimize=ReleaseFast` for the release check; `sudo` prefix to also
exercise the two root-gated tests).

## Backlog / deferred

- **General seccomp argument filtering** — match on `seccomp_data.arg*` for arbitrary
  syscalls/argument indices (e.g. gate `socket` families, `ioctl` requests). The one instance built
  so far is the W^X preset (`buildWx`/`buildDefaultWx`, PROT_WRITE|PROT_EXEC on
  mmap/mprotect/pkey_mprotect) — a general-purpose arg-rule builder for other syscalls is not.
- **Landlock network + scoped rules** — `LANDLOCK_RULE_NET_PORT` (ABI 4), scoped-abstraction (ABI 6).
- **Remains Linux-only** — the documented ceiling (no `pledge`/Capsicum) is permanent, not a gap.

## Status

`new · linux · util · single_owner` + deps: none — canonical source is `pub const meta` in
src/root.zig.
