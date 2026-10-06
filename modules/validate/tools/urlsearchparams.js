// SPDX-License-Identifier: MIT
// WHATWG URLSearchParams (bun) for tools/query_oracle.py: the first value of a
// field, UTF-8 encoded as hex (the spec decodes percent-escapes as UTF-8 with
// replacement). Reads a JSON array of {query, field} on stdin.
const reqs = JSON.parse(await Bun.stdin.text());
const out = reqs.map(({ query, field }) => {
  const v = new URLSearchParams(query).get(field);
  return v === null ? null : Buffer.from(v, "utf8").toString("hex");
});
console.log(JSON.stringify(out));
