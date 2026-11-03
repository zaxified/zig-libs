# diskfree

Filesystem space + mount table, without spawning `df`/`mount`: a raw
`statfs(2)`/`statfs64(2)` syscall wrapper (total/free/available bytes, inode
counts, block size, filesystem type) plus parsers for `/proc/self/mounts`
(the simple `mtab`(5)-shaped four-column table) and `/proc/self/mountinfo`
(the richer source — mount ID/parent ID, the mount's root within its
filesystem, `major:minor` — that `findmnt`/`libmount` actually read).

Provenance: clean-room from `statfs(2)`, `proc(5)` and the kernel UAPI
headers (`include/uapi/asm-generic/statfs.h` and the per-architecture
overrides in `arch/{x86,arm,mips}/include/uapi/asm/statfs.h`) — no
third-party source ported, so no `NOTICE` entry is required (root
[`NOTICE`](../../NOTICE) §0). One design reference was studied, not ported:
musl libc's `src/stat/statvfs.c` (MIT) for its syscall-selection strategy —
`statfs64` with an explicit `sizeof(*buf)` where the target has it,
otherwise plain `statfs` — mirrored here because a native 64-bit `statfs`
struct already has 64-bit counters and gains nothing from the wider syscall.
No musl source was copied. The `src/testdata/*_sample.txt` fixtures are raw
captures of this host's own live `/proc/self/mounts`/`mountinfo` output (no
third-party data); `src/testdata/*_escaped.txt` are hand-authored by our own
tooling to exercise the octal-escape path deterministically. The 2026-11-03
additions (`table`, `lookup`, `classify`, `Usage.flags`, the `mips64` and `s390x`
`statfs` structs from `arch/{mips,s390}/include/uapi/asm/statfs.h`) are
clean-room from `statfs(2)`/`proc(5)` and observed GNU `df` 9.7 / Python
`os.statvfs` output. `tools/go_bench/go.mod` and `go.sum` pin
`github.com/moby/sys/mountinfo` v0.7.3 (Apache-2.0), `github.com/prometheus/procfs`
v0.21.1 (Apache-2.0) and `golang.org/x/sys` v0.49.0 (BSD-3-Clause), written by
`go get`/`go mod tidy` from the local Go module cache; they are bench references
only and no source of theirs is ported or committed.

- **Model after:** musl libc (syscall selection) + `statfs(2)`/`proc(5)` (wire
  formats).
- **Platform:** linux (raw `statfs`/`statfs64` syscalls, no libc; `/proc`
  reads). **Role:** util. **Concurrency:** reentrant (no shared state).
- **Deps:** none.

## Why this exists, and why it is not part of `procnet`

`procnet` already parses `/proc` text files, and it was the obvious first
place to look. Its own `SPEC.md` backlog names this gap explicitly and
declines it: *"`statvfs`/`/proc/mounts` disk usage — filesystem space, not a
`/proc/net` or per-process concern; a different module axis entirely."*
`procnet`'s design is ARP/routes/sockets/conntrack/process — everything it
covers is either `/proc/net/*` or per-process, and its typed results
(`netaddr.Ip`/`Prefix`) exist because that's what those tables carry. Disk
usage shares none of that shape: no socket, no process, no network address —
just "how full is this filesystem, and what's mounted". Folding it into
`procnet` would mean a consumer that only wants `df`-style numbers pulling in
socket-table and conntrack-flow parsing to get them, for a coincidence of
directory (`/proc`) rather than a shared concern. A sibling module keeps the
dependency honest: `diskfree` imports nothing, and nothing that wants disk
space has to import ARP/routing/socket parsing to get it.

What would have made the other call correct: if disk usage were *itself*
`/proc/net`-shaped or process-shaped — it is not. `statfs(2)` is a syscall,
not a `/proc` read at all; the `/proc/self/mounts`/`mountinfo` half is
`/proc`-adjacent only in the sense that most things on Linux eventually are.

## API

```zig
const diskfree = @import("diskfree");

// statfs(2): total/free/available bytes, inodes, block size, fs type magic.
const u = try diskfree.query("/var/log");
// or: diskfree.statfs.query(...) — same function, submodule path.
std.log.info("{d} MB available of {d} MB", .{
    u.availableBytes() / (1024 * 1024),
    u.totalBytes() / (1024 * 1024),
});

var threaded = std.Io.Threaded.init(gpa, .{});
defer threaded.deinit();
const io = threaded.io();

// /proc/self/mounts — device, mount point, fs type, options.
if (try diskfree.mounts.readMounts(gpa, io)) |mnts| {
    defer diskfree.mounts.freeAll(gpa, mnts);
    for (mnts) |m| std.log.info("{s} on {s} ({s})", .{ m.device, m.mount_point, m.fs_type });
}

// /proc/self/mountinfo — mount ID/parent ID/root/major:minor, for anything
// that needs the mount tree or must tell a bind mount from a full one.
if (try diskfree.mountinfo.readMountinfo(gpa, io)) |mnts| {
    defer diskfree.mountinfo.freeAll(gpa, mnts);
    for (mnts) |m| std.log.info("id={d} parent={d} {s} -> {s}", .{ m.mount_id, m.parent_id, m.mount_source, m.mount_point });
}
```

`Usage.blocks_free` (`f_bfree`) and `Usage.blocks_available`
(`f_bavail`)/`availableBytes()` are **not the same number** — they differ by
the margin a filesystem reserves for its superuser (ext-family: `tune2fs
-m`). `df`(1) reports its "Available" column, and computes its use
percentage, from `f_bavail`; a consumer replacing `df` output should read
`availableBytes()`, not `freeBytes()`.

`df`'s columns come straight off a `Usage`: `totalBytes()` (Size),
`usedBytes()` (Used = total − free), `availableBytes()` (Avail),
`usePercent()` (Use%: rounded up; null where `df` prints `-`) and the inode
counts. The byte unit is `f_frsize` (`unitBytes()`; `f_bsize` only when the
kernel reports 0), as POSIX `statvfs` and `df` use it. **Checked against GNU
`df` itself:** a golden of captured `df` output for twelve real filesystems
is in the test suite (`tools/capture-df-golden.sh`), and `tools/df-diff.sh`
compares the module with `df` live on every mount of the machine it runs on
(2026-10-04: 61 SAME, 2 live-drift, 0 DIFF over 63 mounts).

**The `df` listing as data** (2026-11-03). `df`, `df -a`, `df -l`, `df FILE`:

```zig
// Every mount with its statfs: pseudo filesystems hidden, one row per mount
// point, at most 512 mount points looked at (`truncated` says when it cut).
if (try diskfree.table.readTable(gpa, io, .{ .local_only = true })) |t| {
    defer t.deinit(gpa);
    for (t.table.rows) |r| std.log.info("{s} {s} {d}% ro={}", .{
        r.mount_point, r.fs_type, r.usage.usePercent() orelse 0, r.usage.isReadOnly(),
    });
}
// The mount that holds a path (lexical: canonicalise symlinks first). Read with the
// `Limited` reader to learn whether the 1 MiB read cut the table, and use mountinfo
// entries: they carry the mount tree, so stacked and covered mounts are right.
const r = (try diskfree.mountinfo.readMountinfoLimited(gpa, io, 1 << 20)).?;
defer r.deinit(gpa);
const ans = try diskfree.lookup.locate(r.entries, r.truncated, "/var/log/syslog");
if (ans.index) |i| std.log.info("on {s} (table cut: {})", .{ r.entries[i].mount_point, ans.table_truncated });
```

`classify.isPseudo(fs_type)` / `isRemote(fs_type, device)` decide by type NAME
(no magic-number table); `Usage.flags`/`St.*` are the kernel's mount flags
(read-only is `isReadOnly()`), `usePercentNearest()` is busybox's rounding.

`mounts.parseMounts`/`mountinfo.parseMountinfo` are pure (`(gpa, text) →
[]Entry`, golden-text tested against real kernel captures in `src/testdata/`,
including octal-escaped paths — see `mounts.unescapeOctal`'s doc comment);
`readMounts`/`readMountinfo` are the thin live-file wrappers. A missing or
unreadable `/proc` file returns `null`, not an error.

## DEFER (beyond this module's current scope)

- Filesystem-type-magic → name resolution (`0xEF53` → `"ext4"`) — the
  kernel's magic-number table is long and grows; `Usage.fs_type_magic` is
  exposed raw and a caller compares against the specific constant it needs.
- `/proc/<pid>/mounts` for another process — `mountinfo.readMountinfoOf(pid)`
  covers `/proc/<pid>/mountinfo`, the better source for a namespace question.
- `fstatfs` (by file descriptor), human/SI size formatting, a mount tree,
  hiding bind mounts of one device (`df`'s policy): see SPEC "Parity verdicts".
- `x32` ABI `statfs64` layout — refused at compile time
  (`statfs.zig`'s `family` dispatch) rather than guessed at; not a target of
  this collection.
