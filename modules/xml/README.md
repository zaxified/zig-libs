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
            orelse try doc.findByAttr(gpa, "", "ID", "assertion-1"); // exact control

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
- **Billion-laughs-proof**: by default no user-defined general entities; only
  the 5 predefined entities + numeric character references expand (the opt-in
  `.internal_entities` below is bounded by a depth cap and one expansion budget).
- **Bounded**: `max_depth` (256), `max_elements` (1 Mi — generous; set it far
  lower for untrusted input), `max_attributes` (4096), `max_name_len` (1 MiB),
  numeric refs bounded to valid Unicode; input checked as valid UTF-8 up front
  (after transcoding, for the other encodings).
- **Signature-wrapping guard**: duplicate ID values ⇒ `error.DuplicateId`.
- Malformed input ⇒ typed `ParseError`, **never a panic**.

Options: `max_depth`, `max_elements`, `max_attributes`, `max_name_len`,
`doctype` (`.reject` | `.ignore` | `.internal_entities`), `max_entity_depth`,
`max_entity_expansion`, `utf8_only`, `id_attr_names`.

- **Role:** codec. **Platform:** any. **Concurrency:** reentrant (allocator +
  borrowed input slice; no shared state). **Deps:** std-only.
- **Model after:** W3C XML 1.0 (5th ed.) + Namespaces in XML 1.0; OWASP XXE
  prevention guidance.

Provenance: original work of the zig-libs authors (MIT). The test inputs are
the authors' own too; the expected verdicts come from libxml2 (through lxml)
used as a black-box oracle. The W3C XML Conformance Test Suite is not shipped:
it is downloaded on demand (`tools/xmlconf_fetch.sh`). See [`NOTICE`](NOTICE).

## Input encodings, internal entities, writing

- **Encodings.** UTF-8 (BOM optional), UTF-16 LE/BE (BOM, or detected from
  `<?xml` per XML 1.0 Appendix F), ISO-8859-1 (`latin1`) and US-ASCII by their
  declaration — transcoded to UTF-8 before parsing; `doc.source` is then the
  UTF-8 copy the spans index and `doc.source_encoding` says what came in. A
  declaration that contradicts the bytes (a UTF-16 BOM labelled "UTF-8") and
  any other encoding are `UnsupportedEncoding`. `Options.utf8_only = true`
  refuses everything but UTF-8.
- **Internal DTD entities**, opt-in: `.doctype = .internal_entities` reads
  `<!ENTITY name "text">` from the internal subset and expands references in
  content and attribute values. Text-only (a replacement holding `<` is
  `UnsupportedEntity`), never external or parameter entities, bounded:
  `max_entity_depth` (8) nesting, `max_entity_expansion` (1 MiB) total bytes
  plus one per reference — billion laughs, and its empty-string variant,
  stop at the cap (`EntityLimit`); a self-reference is `EntityLoop`.
  `.reject` stays the default.
- **Writer.** `xml.Writer` (push: `startElement`, `attribute`, `namespace`,
  `text`, `cdata`, `comment`, `pi`, `endElement`, `end`) onto any
  `*std.Io.Writer`, with escaping that survives a re-parse (attribute TAB/LF/CR
  as character references, CR in text as `&#xD;`) and refusals instead of
  silent damage (bad names, characters XML cannot carry, `--` in a comment);
  `xml.writeDocument` / `xml.writeElement` serialize a parsed tree
  (iteratively — no recursion). After a write error the output is not usable.

## Not provided

Not a validating parser (no DTD content-model validation / DTD-declared
defaults or ID typing), no XPath, no external resource access, no
canonicalization or signature verification (the `xmldsig` layer builds on the
infoset this module guarantees); and, for now, no XML 1.1, no streaming/pull
reader, no entities whose replacement text holds markup, and no encodings
beyond UTF-8/16, ISO-8859-1 and US-ASCII. See `SPEC.md` (*What is deliberately
not done*, *Backlog / deferred*) for the reasons, the parse model, the
C14N-fidelity guarantees and the threat model.

## Verification

`scripts/modtest xml` (`zig build test-xml`). Composition: W3C-pattern
well-formed docs (namespaces / mixed content / entities / spans), W3C-pattern
not-well-formed rejections (the same defect classes as the W3C `not-wf` suite,
plus Namespaces error cases), and security tests (XXE, billion-laughs, depth,
breadth, attribute count, duplicate ID, invalid UTF-8) each with a positive
control. `core_test.zig` replays libxml2's (lxml's) reading of the encoding and
entity cases (`core_vectors.zig`, recipe `tools/gen_core_vectors.py`) and
round-trips every accepted own well-formedness vector (`wf_vectors.zig`, with
libxml2's verdicts) through the writer; `fuzz_test.zig` is a deterministic fuzz
driver (`XML_FUZZ=<runs>[,<seed>]`); `tools/writer_oracle.*` hands the writer's
output to libxml2 and compares canonical forms. `zig fmt --check modules/xml`
clean.
