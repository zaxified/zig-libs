# xml

**Namespace-aware, security-hardened XML 1.0 parser** producing a DOM-like,
canonicalization-ready infoset tree. Built as the foundation of a SAML /
XML-DSig cluster (`xmldsig` → `saml`): the tree preserves exactly what Canonical
XML and XML-Signature reference resolution need — original prefixes, resolved
namespace URIs, raw attribute order, comments, PIs, document order, and per-node
byte spans. Input is treated as **untrusted** (external IdP), so hardening is a
primary feature, not an option.

```zig
const xml = @import("xml");

var doc = try xml.parse(gpa, source, .{}); // DOCTYPE rejected by default
defer doc.deinit();                        // frees the whole tree (arena)

const root = doc.root;                      // *xml.Element
const uri  = root.uri;                      // resolved namespace URI
const pfx  = root.prefix;                   // ORIGINAL prefix (kept for C14N)

// attribute by (namespace, local); "" = no-namespace attribute
const id = root.attr("", "ID");

// child elements in document order
var it = root.elementIterator();
while (it.next()) |child| { /* ... */ }

// namespace resolution & the inherited axis (for C14N)
const bound = root.resolveNs("saml");          // ?[]const u8
const axis  = try root.inScopeNamespaces(gpa); // []NsDecl (caller frees)
defer gpa.free(axis);

// reference resolution (XML-DSig URI="#id")
const target = doc.getElementById("assertion-1")       // xml:id / ID heuristic
            orelse doc.findByAttr("", "ID", "assertion-1"); // exact control

// raw bytes / subtree location
const bytes = target.?.span.slice(source);
```

## What the tree preserves (C14N fidelity)

- Elements with `prefix` + `local` + resolved `uri`.
- `ns_decls` per element (raw `xmlns` / `xmlns:p` bindings) + `parent` pointers
  ⇒ both the inherited namespace axis and per-node in-scope resolution.
- Attributes in original order, each with `prefix`/`local`/`uri`/`value`;
  namespace declarations are lifted out of `attributes` into `ns_decls`.
- Text (entity-expanded, line-ending-normalized), CDATA (verbatim, distinct
  child), comments, PIs — all in document order; prolog/epilog comments & PIs
  kept on the `Document`.
- `span: {start, end}` byte range into the original source for every node.

## Hardening (untrusted input)

- **XXE-proof**: `<!DOCTYPE>` **rejected by default** (`error.DoctypeForbidden`);
  with `.doctype = .ignore` the DTD is skipped without parsing — no external
  entity or external subset is ever dereferenced (the parser has no filesystem
  or network code path).
- **Billion-laughs-proof**: no user-defined general entities; only the 5
  predefined entities + numeric character references expand.
- **Bounded**: `max_depth` (256), `max_attributes` (4096), `max_name_len`
  (1 MiB), numeric refs bounded to valid Unicode; UTF-8 validated up front.
- **Signature-wrapping guard**: duplicate ID values ⇒ `error.DuplicateId`.
- Malformed input ⇒ typed `ParseError`, **never a panic**.

Options: `max_depth`, `max_attributes`, `max_name_len`, `doctype`
(`.reject` | `.ignore`), `id_attr_names`.

- **Role:** codec. **Platform:** any. **Concurrency:** reentrant (allocator +
  borrowed input slice; no shared state). **Deps:** std-only.
- **Model after:** W3C XML 1.0 (5th ed.) + Namespaces in XML 1.0; OWASP XXE
  prevention guidance.

Provenance: original work of the zig-libs authors (MIT).

## Out of scope

Not a validating parser (no DTD content-model validation / DTD-declared
defaults or ID typing); no XML 1.1; no XPath; UTF-8 only (other encodings
rejected). Canonicalization and signature verification themselves live in the
`xmldsig` layer — this module only guarantees the infoset that layer needs. See
`SPEC.md` for the full parse model, C14N-fidelity guarantees, and threat model.

## Verification

`zig build test-xml` — green in Debug and `-Doptimize=ReleaseFast`.
Composition: W3C-pattern well-formed docs (namespaces / mixed content / entities
/ spans), W3C-pattern not-well-formed rejections (modeled on xmlconf `not-wf/sa`
+ Namespaces error cases), and security tests (XXE, billion-laughs, depth,
attribute count, duplicate ID, invalid UTF-8) each with a positive control.
`zig fmt --check modules/xml` clean.
