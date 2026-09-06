# SPDX-License-Identifier: MIT
#
# Reference driver for the brotli module's interop program.
#
# FOREIGN CODE LIVES HERE, NOT IN THE MODULE. This file is driven only by
# `tools/interop.zig`, a standalone program run by `zig build interop-brotli`.
# Nothing under `../src/` embeds, spawns or otherwise needs it: the module's own
# tests replay what a capture run froze into `../src/testdata/`.
#
# The peer is the Python `brotli` package -- a C-extension binding to the
# actual google/brotli library, i.e. the reference implementation of RFC 7932,
# not a second reading of the spec.
#
# DETERMINISM. `quality` and `lgwin` are always passed explicitly and `mode` is
# always MODE_GENERIC, because all three change the output and all three have
# defaults that a package upgrade is free to move. `lgblock=0` (the default)
# lets the library choose the block size from quality+lgwin, which is
# deterministic for a given version; the version itself is recorded in the
# header of every captured fixture.
#
# Every op takes explicit file paths, so the caller chooses the scratch
# directory and this script never depends on its own cwd:
#   python3 reference.py version <out.txt>
#   python3 reference.py compress <quality> <lgwin> <in.bin> <out.br>
#   python3 reference.py decompress <in.br> <out.bin>
#
# `decompress` exits non-zero when the reference REFUSES the stream, which is
# the failure the interop program exists to catch.

import datetime
import sys

import brotli


def main(argv):
    op = argv[1]
    if op == "version":
        # One line, copied verbatim into the header of every captured fixture:
        # it is the whole provenance of the bytes below it.
        with open(argv[2], "w") as fh:
            fh.write("python brotli %s (google/brotli), Python %d.%d.%d, %s" % (
                getattr(brotli, "__version__", "unknown"),
                sys.version_info[0], sys.version_info[1], sys.version_info[2],
                datetime.date.today().isoformat(),
            ))
        return 0

    if op == "compress":
        quality, lgwin = int(argv[2]), int(argv[3])
        data = open(argv[4], "rb").read()
        out = brotli.compress(data, mode=brotli.MODE_GENERIC,
                              quality=quality, lgwin=lgwin)
        with open(argv[5], "wb") as fh:
            fh.write(out)
        return 0

    if op == "decompress":
        data = open(argv[2], "rb").read()
        # Raises brotli.error on a stream the reference refuses -> non-zero
        # exit -> error.ReferenceRejected on the Zig side.
        out = brotli.decompress(data)
        with open(argv[3], "wb") as fh:
            fh.write(out)
        return 0

    raise SystemExit("unknown op " + op)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
