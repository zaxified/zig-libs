# zstd-cli

The `zstd` command, on zig-libs' [`zstd`](../../modules/zstd/) module: a Zig
port of libzstd 1.5.7's `programs/` (`zstdcli.c`, `fileio.c`). Same options,
same defaults, same file handling, same messages — and **the same frames, byte
for byte**, as the C command for the same options. The binary is called `zstd`.

That last claim is checked, not assumed: `smoke.sh` compresses with this
binary and with a real `zstd` 1.5.7 (when one is on `PATH`) and compares the
bytes, the messages and the exit codes.

## Get it

Take this directory and nothing else — it is a self-contained project, and the
rest of the collection arrives as a pinned dependency, not as a checkout:

```sh
curl -L https://github.com/zaxified/zig-libs/archive/refs/tags/2026-09-19.tar.gz \
  | tar -xz --strip-components=2 'zig-libs-2026-09-19/example-apps/zstd-cli'
cd zstd-cli
```

## Build and run

```sh
./init.sh                      # fetch the pinned zig-libs, build zig-out/bin/zstd (ReleaseFast)
./zig-out/bin/zstd -19 big.log # -> big.log.zst
./zig-out/bin/zstd -d big.log.zst -o back.log
./zig-out/bin/zstd -l big.log.zst
./smoke.sh                     # round trips, verdicts, and parity with a real zstd 1.5.7
```

## Why the frames match

The frames a compressor writes depend on how its input is handed over, not
only on the level. The C command reads its input in 128 KiB chunks and passes
each whole to `ZSTD_compressStream2(continue)`, the last with `end` (or an
empty `end` after the last read when the size is unknown), pledging the file
size when it knows it; by default it compresses with `max(1, min(4, cores/4))`
worker threads, so its frames are multithreaded ones. This port does exactly
that with `zstd.Stream`, whose frames equal libzstd's for the same call plan
and — with workers — for any worker count. `-T1`, `-T4`, `-T0` and the
default therefore all give the C command's bytes; `--single-thread` gives its
single-threaded bytes.

Checked on 2026-09-27 against `/usr/bin/zstd` 1.5.7: 226 combinations of
input (0 B to 3 MB, text and random, exactly 128 KiB, stdin), level (−5…22),
threads, `--long`, `--rsyncable`, `-B`, `--no-check`, `--no-content-size`,
`-D` dictionaries (with `--no-dictID`), `--target-compressed-block-size`,
`--[no-]compress-literals`, `--[no-]row-match-finder`, `--stream-size` and
`--size-hint` — all byte-identical; and 71 message scenarios (summaries,
several files, overwrite refusals, `--rm`, links, directories, unknown
suffixes, trailing garbage, truncation, `-t`, `-l`, `-lv`, window limits with
their `--long=`/`--memory=` advice, `zstdcat`/`unzstd`, bad options, the
`ZSTD_CLEVEL` variable, permissions and times carried over)
with the same stderr, stdout, exit code and resulting files, but for the
differences below.

## Benchmark mode (`-b`)

`zstd -b#` with the C command's options (`-e#` last level, `-i#` seconds,
`-B#` blocks, `-S` per file, `-d` decode only, `-D`, `-T#`, `--long`) and
its output, line for line: the input cut into blocks, each compressed by a
reused context and decompressed by a stream, timed in runs of about a
second, the fastest run kept. The compressed sizes and ratios equal the C
command's (`smoke.sh` checks them); the speeds are the comparison:

```sh
zstd -q -b1 -e19 -i5 big.tar            # libzstd 1.5.7
./zig-out/bin/zstd -q -b1 -e19 -i5 big.tar   # this port, same columns
```

Build with `-Dcpu=native` (or `x86_64_v3`) for a fair comparison: libzstd
picks its BMI2 code at run time, the port at compile time. Not ported:
`-b` without an input file (the C command's synthetic lorem-ipsum and
`-P#` data).

## Deliberately different

- **The banner** (`-V`, `-v`) says `zig-libs port` where the C command names
  its author.
- **No gzip, xz, lzma or lz4.** As a libzstd built without zlib, liblzma and
  liblz4: `--format=gzip` and friends are unknown options, such input is
  refused with the C command's "compiled without" message, and the suffix
  list in messages is `.zst/.tzst`.
- **`--sparse`, `--asyncio`, `--mmap-dict`** are accepted and change nothing:
  output is written plainly, I/O is synchronous, the dictionary is read
  whole. None of them changes a byte of output.

## Not ported yet

Refused by name (`zstd: X is not supported by this port yet`), never parsed
and ignored: `-b` without an input file, `-p` (pause), dictionary training (`--train*`, `--maxdict`,
`--dictID`, `-s`), `--adapt`, `--patch-from`, `--zstd=`, `--max`, `-r` and
`--filelist`, `--output-dir-*`, `--show-default-cparams`, `--trace`, the
progress counter (stderr on a terminal) and the `--fake-*-is-console`
test hooks. `-M` / `--memory=` below 1 KiB counts as 1 KiB, where libzstd
refuses it.

## Licence

The port of `programs/` is BSD-licensed code translated into Zig: see
[`NOTICE`](NOTICE), which carries libzstd's licence text as that licence
requires. The zstd module the command links has its own `NOTICE`.
