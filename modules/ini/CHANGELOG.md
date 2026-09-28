# `ini` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-28** — New module: an INI reader (sections, `key = value`, comments, line numbers,
  strict and lenient modes) with a Python `configparser` and a Desktop Entry preset, requested by
  ttydesk for Midnight Commander skins. Verified against CPython 3.14 `configparser` and GLib
  2.88 `GKeyFile` on 905 texts (`tools/gen_goldens.py`), all in agreement.
