# btcaddr tools

`gen_core_vectors.py` regenerates `src/core_vectors.zig` from Bitcoin Core's
`key_io_valid.json` / `key_io_invalid.json` (MIT; see `../NOTICE`). Usage is in
the script's docstring. It is the recipe that produced a committed vector file,
kept per CONVENTIONS §9; python3 standard library only.
