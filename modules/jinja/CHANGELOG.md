# jinja — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: an autoescape bypass via the `replace` filter could
  inject unescaped markup into rendered output; fixed, along with an integer-overflow
  allocation guard, an unbounded expression-nesting DoS, and 9 further findings (2
  accepted as measured non-issues, not defects).
- **2026-07-30** — New module: Jinja2-compatible template engine — `{{ … }}`, `{# … #}`,
  `{% if/elif/else %}`, `{% for %}` with the full `loop` object.
