# diskusage

The `du(1)` question — how much space does a directory tree occupy — without
spawning `du`: walk the tree, `lstat` every entry, accumulate real allocation
(`st_blocks * 512`) and apparent size (`st_size`) in one pass, with the
hard-link de-duplication, filesystem boundary and skip-and-carry-on failure
behaviour `du` itself has. Underneath it is the per-file metadata layer `std`
does not expose: `statx(2)` where the kernel has it, a raw
`fstatat`/`fstatat64` with a per-architecture kernel-ABI struct where it does
not.

**Pairs with [`diskfree`](../diskfree), and does not overlap it.** That module
answers `df` — whole-filesystem space from `statfs(2)` plus the mount table —
and walks no directories. This one walks and stats and never calls `statfs`.
The two share no symbol and neither imports the other; the pair is named after
the two tools it mirrors.

Provenance: clean-room from `du(1)`'s observable behaviour, `statx(2)`, and
the kernel UAPI headers (`include/uapi/asm-generic/stat.h` plus the
per-architecture overrides in `arch/{x86,arm,mips,powerpc,s390}/include/uapi/
asm/stat.h`) — no third-party source ported, so no `NOTICE` entry is required
(root [`NOTICE`](../../NOTICE) §0). GNU coreutils' `du` and uutils' `du` are
used purely as black-box compatibility oracles, which needs no entry either
(CONVENTIONS.md §5). The one committed non-source file, `tools/stat-layout-probe.sh`,
is our own tooling: it holds no data, and the layout numbers it reports are generated
on demand from whatever kernel UAPI headers the machine running it has installed, so
the assertions in `src/stat.zig` can be re-derived rather than trusted. Nothing here is
captured from a third party.

- **Model after:** GNU coreutils `du` (traversal rules) + `statx(2)`/kernel
  UAPI `struct stat` (wire format).
- **Platform:** linux (raw `statx`/`fstatat` syscalls, no libc).
  **Role:** util. **Concurrency:** reentrant — the stat backend is chosen per
  scan and passed down, never latched in a global.
- **Deps:** none.

## Why this exists, and why it is not part of `diskfree`

`diskfree` was renamed out of the way to make room for this module, and the
reason is the reason the two stay separate: they answer different questions
with disjoint mechanisms. `diskfree` is one `statfs(2)` call plus two `/proc`
text parsers; it never opens a directory. `diskusage` opens every directory in
a tree and stats every entry; it never asks the kernel about a filesystem as a
whole. A consumer that wants "is the disk full" imports `diskfree` and pays
for no traversal code; a consumer that wants "what is filling it" imports this
and pays for no mount-table parser.

The blocker that kept this from existing earlier was concrete:
`std.Io.File.Stat` carries neither `st_blocks` (real allocation — the number
`du` reports) nor `st_dev` (the filesystem boundary, and half of the
`(dev, ino)` identity hard links need). `std.os.linux` declares no `Stat`
struct either. `SPEC.md` has the full account, including why nine
per-architecture kernel structs are needed for the fallback and why a wrong
one here fails *silently* where `diskfree`'s equivalent fails loudly.

## API

```zig
const diskusage = @import("diskusage");

var threaded: std.Io.Threaded = .init(gpa, .{});
defer threaded.deinit();
const io = threaded.io();

// The whole tree, both measures, one pass.
const r = try diskusage.scanPath(gpa, io, "/var/log", .{});
std.log.info("{d} allocated / {d} apparent over {d} entries", .{
    r.total.allocated_bytes, r.total.apparent_bytes, r.total.entries,
});
if (r.errors > 0) std.log.warn("{d} entries could not be read", .{r.errors});
```

`scanAt(gpa, io, base_dir, sub_path, options)` is the same thing resolved
against an already-open `std.Io.Dir`.

### Per-directory subtotals and failures

Both are callbacks with a caller-supplied context pointer:

```zig
fn onDir(ctx: ?*anyopaque, rel: []const u8, depth: u32, t: diskusage.Totals) diskusage.SinkError!void {
    const self: *MyState = @ptrCast(@alignCast(ctx.?));
    // `rel` is relative to the scan root; "" IS the root. Borrowed: copy to keep.
    try self.print(rel, t.allocated_bytes);
}

fn onErr(ctx: ?*anyopaque, path: []const u8, err: anyerror) void {
    // Called once per unreadable entry. The scan continues.
}

const r = try diskusage.scanPath(gpa, io, path, .{
    .on_directory = .{ .context = &state, .func = onDir },
    .on_error     = .{ .context = &state, .func = onErr },
});
```

Directories arrive **post-order** — every child before its parent, the scan
root last, at depth 0, with a subtotal equal to `Report.total`. That is `du`'s
own output order and falls out of the traversal rather than being sorted
afterwards.

### The options, and what each corresponds to in `du`

| Option | `du` equivalent | Default |
|---|---|---|
| `count_hard_links` | `--count-links` | `false` — count once per `(dev, ino)`, like `du` |
| `one_file_system` | `-x` | `false` |
| `backend` | — | `null`, probe `statx` once per scan |

There is deliberately **no** apparent-versus-allocated switch: `Totals` always
carries both, from the same `lstat`.

⚠ Two `du` compatibility details worth knowing before comparing numbers, both
established by measurement against GNU and uutils rather than from
documentation (see SPEC.md):

* **A directory contributes 0 to `apparent_bytes`** and its real blocks to
  `allocated_bytes`. Summing `st_size` for directories too — the obvious
  implementation — disagrees with `du --apparent-size` by the sum of every
  directory's `st_size`.
* **`one_file_system` excludes cross-device entries entirely**, rather than
  merely declining to descend. GNU applies this to files as well as
  directories; uutils applies it to directories only. This module follows GNU.

## Verify

```sh
zig build test-diskusage
zig build example-diskusage      # builds the du-shaped demo
```

The demo's default output is byte-for-byte `du -B1`'s shape, so it can be
diffed against the real thing:

```sh
diff <(du -B1 /some/tree | sort -k2) \
     <(./zig-out/bin/diskusage-demo /some/tree | sort -k2)
```

⚠ Always compare at `-B1`. `du`'s default columns are 1024-byte blocks rounded
up per entry, and different `du` implementations round differently — a harness
that called that a failure would be worse than no harness.

`diskusage-demo --explain` prints what `du` has no column for: the sparse gap
(apparent minus allocated, from one traversal instead of two runs), the
hard-link saving, and which stat backend this host actually supports.

The per-architecture `struct stat` layouts are re-derivable, not just asserted:

```sh
bash modules/diskusage/tools/stat-layout-probe.sh
```

It compiles the real kernel UAPI header for each architecture with a compiler
that knows that ABI and prints the `sizeof`/`offsetof` numbers that must match
`src/stat.zig`'s `assertLayout` calls. SPEC.md says why that oracle is
load-bearing here in a way it is not for `diskfree`.

## DEFER (beyond this module's current scope)

- Following symlinks (`du -L`/`-D`) — not `du`'s default, and an invitation to
  a non-terminating traversal.
- `--exclude`, `--threshold`, `--separate-dirs`, `--inodes`, `--time` —
  reporting and filtering policy a caller can express over `DirSink` and
  `Report`.
- Human-readable / block-size formatting: exact bytes only, for the same
  reason `diskfree` computes no use-percentage.
- A per-entry sink (`du -a`) — a small symmetric extension, deferred until a
  consumer needs it.
- An `fstatat` layout for sparc/sparc64, m68k, xtensa, x32 and mips64 n32.
  Those are `statx`-only and return `error.Unsupported` on a pre-4.11 kernel,
  rather than guessing at a struct with no loud-failure mode.
