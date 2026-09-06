# sandbox — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — A1 security audit, the five HIGH findings fixed. **BREAKING:**
  `Landlock.init()` takes no argument and handles EVERY filesystem right the kernel's ABI
  knows (`access.all`, deny by default); the old `init(handled)` is `initHandling(mask)`.
  Reason: Landlock only restricts handled rights, and every piece of this module's
  documentation passed `access.read_only` to `init` — a ruleset that handled
  `read_file|read_dir` and left the other 14 rights unrestricted, so a process "confined to
  a read-only tree" could create, truncate, unlink and symlink anywhere its DAC permissions
  reached (measured). `allowPath` opens with `O_NOFOLLOW` and refuses a final-component
  symlink with the new `error.PathIsSymlink` (one `link -> /` had granted the whole
  filesystem); intermediate symlink components still resolve. `seccomp.build`/`buildWx`
  refuse `Action.errno` outside `1..4095` with the new `error.InvalidErrno` (`.errno = 0`
  made a DENIED syscall return 0, i.e. success). `dropPrivileges`' read-back now covers saved
  uid/gid (`getresuid`/`getresgid`) and an empty supplementary group list, so a partial drop
  is `DropNotEffective` in more cases. New `seccomp.available()` (probes
  `SECCOMP_GET_ACTION_AVAIL`), `Landlock.access.all`, `seccomp.max_errno`,
  `seccomp.wx_block_len`. `fstatat64` (std's x86-64 spelling of syscall 262) joins the
  default allow-list next to `newfstatat`, which `@hasField` had been dropping silently.
  Tests: the arch guard is pinned by its jump targets in BOTH `build` and `buildWx` (a
  `jf: 0 → 1` mutation kept opcode and `k` and survived) and, on x86-64, by the escape it
  prevents — a child under a getpid-only filter issues `int $0x80` nr 39 (i386 `mkdir`) and
  must die of SIGSYS; Landlock write-denial outside and inside a `read_only` tree with a
  `read_write` positive control; a symlink refused by name; a worker spawned before
  `restrictSelf` measured unconfined (no TSYNC for Landlock — documented as such, the SPEC
  used to say "or use the TSYNC form" for both); `disableCoreDumps` read back via
  `getrlimit`; the default allow-list's named content and the exact count `@hasField` keeps
  on x86-64. Skips are now decided up front from kernel probes, never from the child's own
  failure exit (a mutation that disabled Landlock entirely had produced "15 pass / 3 skip",
  exit 0), and `runInChild` checks `waitpid`. Docs: the arch guard's real job is the i386
  `int $0x80` alias, not x32 (which reports `AUDIT_ARCH_X86_64` and is stopped by
  default-deny); the W^X preset forbids W|X in one call and not the two-step RW→RX sequence;
  README's recipe drops the capability bounding set BEFORE the uid drop (after it,
  `PR_CAPBSET_DROP` always hit EPERM and `catch {}` swallowed it). `build`/`buildWx`
  preallocate their exact program length (3–6× faster, no behaviour change).
- **2026-07-19** — Security audit: no findings. Modeled on OpenSSH/systemd sandboxing,
  libseccomp, Landlock UAPI (design reference, not a test anchor).
- **2026-07-11** — New module: Process self-hardening for an internet-facing server.
