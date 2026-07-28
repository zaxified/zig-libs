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
uses a syscall it omits or leave reachable a syscall it includes. seccomp here filters on the
syscall *number* only — argument filtering (e.g. restricting `socket` address families,
`ioctl` requests, `mmap` PROT_EXEC) is deferred, so a number-level allow of `ioctl`/`mmap`/`socket`
still admits every variant. Landlock covers the filesystem (and, when built out, network ports); it
does not restrict already-open fds, IPC, or ptrace — pair it with seccomp + a namespace for those.
Out of scope: seccomp arg matching, the `seccomp(2)` TSYNC form, Landlock net/scoped rules, BSD
sandboxing.

## Verification

The enforcement tests **fork a child**, apply one restriction, attempt the forbidden action and
assert the child terminates exactly as configured, with a control child (no restriction) succeeding —
the only honest way to test a security boundary; a pure unit test would prove nothing about the
kernel actually enforcing it. Unprivileged and always-run: seccomp (KILL child dies of `SIGSYS`,
ERRNO child sees `-EPERM`, control survives), Landlock (child confined to a temp dir is denied
`/etc/passwd`, allowed its own file — skips pre-5.13), rlimit (`RLIMIT_NOFILE` bites at the cap with
EMFILE and cannot be raised back; `RLIMIT_CORE=0`). Root-gated + `SkipZigTest` otherwise: privilege
drop (drops to `nobody`, asserts `setuid(0)` fails) and capability bounding-set drop. Pure/logic
tests cover the BPF program shape (arch guard + per-syscall compare + allow/deny leaves + descending
`jt`), struct ABI sizes, and the monotone Landlock access mask. Run: `zig build test-sandbox`
(add `-Doptimize=ReleaseFast` for the release check; `sudo` prefix to also exercise the two
root-gated tests).

## Backlog / deferred

- **seccomp argument filtering** — match on `seccomp_data.arg*`, two loads per 64-bit arg; lets an
  allow-list gate `socket` families, `ioctl` requests, `mmap` PROT_EXEC. Not built.
- **`seccomp(2)` SET_MODE_FILTER + `TSYNC`** — apply across all threads of an already-multi-threaded
  process; the prctl form filters the calling thread only. Not built.
- **Landlock network + scoped rules** — `LANDLOCK_RULE_NET_PORT` (ABI 4), scoped-abstraction (ABI 6).
- **Remains Linux-only** — the documented ceiling (no `pledge`/Capsicum) is permanent, not a gap.

## Status

`new · linux · util · single_owner` + deps: none — canonical source is `pub const meta` in
src/root.zig.
