# xml — design, C14N-fidelity guarantees & threat model

Auditor-facing. The consumer-facing surface is in `README.md`; the canonical
metadata is `pub const meta` in `src/root.zig`.

## Purpose

`xml` is a **namespace-aware, security-hardened XML 1.0 parser** that produces a
DOM-like infoset tree. It is the foundation of a SAML / XML-DSig cluster: the
next module `xmldsig` (exclusive C14N + XML-Signature verification) and then
`saml` (SAML 2.0 SP side) consume this tree. Because an XML-DSig implementation
is only as correct as the infoset it canonicalizes, the tree's fidelity — and,
because the input is untrusted IdP data, its security posture — are the whole
point of this module.

Modeled after the W3C specs, not invented:
- *Extensible Markup Language (XML) 1.0 (Fifth Edition)*
- *Namespaces in XML 1.0 (Third Edition)*
- Hardening follows the OWASP "XML External Entity Prevention" guidance
  (disable DTDs / external entities entirely).

## Parse model

The tree is built to be **Canonical-XML-ready**. In document order it preserves:

- **Elements** — original `prefix` + `local` name AND the resolved namespace
  `uri`. Original prefixes are never discarded (C14N reproduces them).
- **Namespace declarations** — each element carries `ns_decls`: the raw
  prefix→URI bindings declared literally *on that element* (default decl has
  `prefix == ""`). Combined with `parent` pointers this yields both the
  inherited namespace axis (inclusive C14N) and per-node in-scope resolution
  (exclusive C14N "visibly utilized" + resolution).
- **Attributes** — `prefix` + `local` + resolved `uri` + normalized `value`, in
  original document order. C14N re-sorts attributes itself; we keep the raw set
  and their namespaces. Namespace-declaration attributes are lifted out into
  `ns_decls` and are NOT present in `attributes` (C14N treats namespace nodes
  separately anyway).
- **Text** — entity-expanded, line-ending-normalized character content.
- **CDATA** — kept as a distinct `cdata` child (verbatim content, no entity
  expansion) but semantically a text node; C14N replaces it with its content.
- **Comments** — preserved (`comment` child + document `prolog`/`epilog`), so
  both with-comments and without-comments C14N are expressible.
- **Processing instructions** — preserved (`pi` child + prolog/epilog).
- **Whitespace** — preserved faithfully inside element content (C14N is
  whitespace-sensitive there). Inter-element whitespace *outside* the root
  element is not retained (it is not part of any canonicalized subtree).
- **Byte spans** — every node carries `span: {start, end}` into the ORIGINAL
  source. An element's span runs from its opening `<` to just past the `>` that
  closes it. Lets `xmldsig` locate / raw-slice a specific subtree and aids
  reference resolution.

### Normalization performed (and why)

- **Line endings**: literal `\r\n` and `\r` → `\n` in text and attribute values
  (XML §2.11). C14N operates on an infoset that has already been through this.
- **Attribute-value normalization** (CDATA-type, since we do not process DTDs):
  literal whitespace (`\t`, `\n`, normalized `\r`) → space; whitespace
  introduced by a character reference (e.g. `&#9;`) is kept verbatim (XML §3.3.3).
- **Entities**: the 5 predefined (`&lt; &gt; &amp; &apos; &quot;`) and numeric
  character references (`&#d;` / `&#xh;`) are expanded to their characters.
  Numeric refs are bounded to valid XML Unicode scalar values.

## Read API (what the next layer builds on)

Types: `Document`, `Element`, `Attribute`, `NsDecl`, `Child` (tagged union
`element|text|cdata|comment|pi`), `Pi`, `Span`.

Entry point: `parse(gpa, source, Options) ParseError!Document`. The `Document`
owns all memory via an internal arena (child allocator = `gpa`); `deinit` frees
the whole tree at once. Arena-per-document means any subtree stays valid for the
Document's lifetime — exactly what a C14N pass over a subtree requires.

- `Document.root: *Element`, `Document.prolog/epilog: []const Child`
- `Document.getElementById(id) ?*Element` — ID heuristic: `xml:id` always, plus
  unqualified attrs whose local name ∈ `Options.id_attr_names` (default
  `ID`/`Id`/`id`). Duplicate ID values across the document are a parse error
  (`DuplicateId`) — a deliberate guard against XML-Signature-wrapping tricks.
- `Document.findByAttr(uri, local, value) ?*Element` — exact-attribute search,
  giving the dsig layer full control over which attribute is the ID.
- `Element.resolveNs(prefix) ?[]const u8` — in-scope prefix→URI resolution
  (`""` = default namespace; result `""` for `""` means "no namespace";
  reserved `xml`/`xmlns` handled). Cost is O(declaring ancestors), not
  O(declarations × depth): the parser links each element to a `NsScope` that
  skips every ancestor declaring nothing and indexes any element carrying more
  than `dup_scan_threshold` declarations. That matters because this is a
  per-attribute call for `c14n`/`xmldsig` — a linear walk here reintroduces, in
  every consumer, the exact quadratic the parser's own paths were hardened
  against. A hand-assembled tree (no `ns_scope`) falls back to the plain
  parent-axis walk and answers identically.
- `Element.inScopeNamespaces(alloc) ![]NsDecl` — full inherited namespace axis,
  nearest-wins, undeclared default omitted (for inclusive C14N).
- `Element.attr(uri, local) ?[]const u8`, `Element.elementIterator()`,
  `Element.firstElementChild()`, `Element.textContent(alloc)`.
- `Span.slice(source)` — raw bytes of a node.

### How the C14N layer should drive this

- **"Canonical subtree rooted at X"**: walk `X.children` in document order;
  each `Child` is already tagged and ordered. For X's namespace context, use
  `X.inScopeNamespaces` (inclusive) or, for exclusive C14N, compute the visibly-
  utilized prefixes from `X.prefix` + each attribute's `prefix`, then
  `X.resolveNs(prefix)` each one. Attributes come pre-split from namespace
  declarations, so the C14N attribute axis and namespace axis are cleanly
  separable. Sort per the C14N rules at that layer.
- **"Resolve in-scope namespaces at X"**: `X.resolveNs` / `X.inScopeNamespaces`.
- **Reference `URI="#id"`**: `getElementById` or `findByAttr`.

No known gap blocks exclusive C14N. One thing the C14N layer must add itself
(by design, not a defect): the `xml`-namespace attribute inheritance / the
implicit `xml` namespace handling, and the final attribute/namespace sorting —
these are canonicalization policy, not infoset data.

## Hardening posture (primary requirement — untrusted IdP input)

| Vector | Policy | Test |
|--------|--------|------|
| **XXE / external entities / external DTD** | `<!DOCTYPE>` is **rejected by default** (`error.DoctypeForbidden`) — an external subset is never even inspected. With `doctype = .ignore` the DTD is *skipped without parsing any entity declaration*; the parser has **no filesystem/network code path at all**, so `SYSTEM "file:///…"` can never be dereferenced, and the later `&xxe;` fails as `UndefinedEntity`. | `security XXE: *` (incl. a positive control) |
| **Entity-expansion DoS** (billion laughs / quadratic blowup) | User-defined general entities are **never supported**. Only the 5 predefined + numeric refs expand. A custom `&lol3;` is simply undefined ⇒ `UndefinedEntity` (or `DoctypeForbidden` under the default policy) — no recursive expansion, no memory growth. | `security billion-laughs: *` |
| **Adversarial nesting / stack exhaustion** | Element depth capped at `Options.max_depth` (default 256); the parser uses an explicit heap stack (no native recursion on nesting). | `security depth: *` (reject + positive control) |
| **Pathological attribute counts** | Two separate bounds, because a count cap alone is **not** a CPU bound. (a) `Options.max_attributes` (default 4096) ⇒ `TooManyAttributes`. (b) Per-element duplicate detection — duplicate attributes, duplicate namespace declarations, and prefix resolution — is O(k), not O(k²): above `dup_scan_threshold` entries each runs through a hash set instead of rescanning the list. Before (b), one element at the default cap cost 8.4 M name comparisons ≈ 50 ms of CPU for 127 KB of input, pre-authentication. (c) `Element.resolveNs` — the same resolution reached as a *public* call rather than through the parser — is bounded by the same index plus a scope chain that skips non-declaring ancestors, so a consumer resolving one prefix per attribute does not reintroduce the quadratic. Measured: a 4000-deep document costs 51.4 ms of consumer-side resolution before that change, 0.13 ms after; exclusive C14N over it, 31.6 ms → 1.1 ms. | `security bounds: too many attributes`, `security bounds: per-element duplicate detection is linear in k`, `complexity: Element.resolveNs is O(1) in depth and in declaration count` |
| **Oversized names** | `Options.max_name_len` (default 1 MiB) ⇒ `NameTooLong`. | (bound enforced in `parseNameRaw`) |
| **Signature-wrapping via duplicate IDs** | Duplicate ID values ⇒ `DuplicateId`. | `security: duplicate ID rejected` |
| **Invalid input** | Whole input must be valid UTF-8; numeric char refs bounded to valid XML scalar values; malformed markup ⇒ typed errors, **never a panic**. | `security: invalid UTF-8`, `char ref out of range`, the not-wf suite |

Everything returns a typed `ParseError`; there are no `unreachable`/panic paths
on malformed input.

## Well-formedness enforced

Mismatched / overlapping tags (`MismatchedTag`), unclosed elements
(`UnclosedElement`), duplicate attributes by expanded name
(`DuplicateAttribute`), undeclared namespace prefixes
(`UndeclaredNamespacePrefix`), illegal namespace operations — using/redeclaring
`xml`/`xmlns`, undeclaring a prefix in Namespaces 1.0, binding reserved URIs
(`NamespaceError`), illegal characters (`InvalidCharacter`/`InvalidCharRef`),
malformed comments/PIs/CDATA, multiple or missing root elements, and content
outside the root.

## Out of scope (deliberate)

- **Not a validating parser** — no DTD content-model validation; no
  attribute-default or ID/IDREF typing from a DTD (the ID heuristic above stands
  in for the SAML/dsig use case).
- **No XML 1.1** (`version` must be `1.0`).
- **No XPath** — the `xmldsig`/`saml` layers navigate the tree directly.
- **UTF-8 only** — a non-UTF-8 `encoding=` declaration is rejected
  (`UnsupportedEncoding`); no transcoding.
- **No external resource access of any kind** — by construction, not by config.
- **Canonicalization / signing themselves** — that is the `xmldsig` layer; this
  module only guarantees the infoset it needs.

## BEHAVIOURAL (2026-09-11, A1 fix campaign round 2, `QUESTIONS-ROUND-2.md` Q5)

Five divergences from XML 1.0 / libxml2 / expat, previously listed above as
deliberate scope limits, are now closed by matching the norm exactly (Q5: "the
newer/more precise norm wins" — XML 1.0 §2.11/§7 and libxml2/expat agree with
each other here, only this module diverged, so per Q5 rule 1 there is no
compatibility switch: the norm and the reference implementations already
agree, only the module needed to change).

- **Line-ending normalization (§2.11) now applies inside comment and PI
  content too**, not just text/attribute values (former F3). A document with
  a raw CR inside a `<!--comment-->` or `<?pi?>` now canonicalizes
  byte-for-byte identically to libxml2/expat instead of one byte off. Verified black-box
  against `xmllint --c14n` (audit `A1/xml.md` F3, closed).
- **Name characters are validated against the real Unicode
  `NameStartChar`/`NameChar` grammar**, decoded from UTF-8, instead of
  accepting any byte `>= 0x80` (former F4) or trusting the whole-document
  `utf8ValidateSlice` check as the only thing standing between a name and
  malformed UTF-8 (former F9 sub-finding "M16" — both close via the same
  rewrite of `parseNameRaw`). U+00B7 alone at the start of a name, a bare
  combining character starting a name, and non-Name characters mid-name are
  now rejected, matching libxml2/expat exactly (verified black-box). This is
  BEHAVIOURAL: a small number of previously-accepted non-ASCII-but-out-of-
  grammar names are now `error.InvalidName`.
- **A PI target starting with `xml` (e.g. `xml-stylesheet`, `xmlfoo`) is now
  treated identically at byte 0 of the document and everywhere else** (former
  F7). Only the EXACT target `xml` (any ASCII case) is reserved, per XML 1.0
  §7 — not every name that merely starts with those three letters. Verified
  black-box: `<?xml-stylesheet href="a.xsl"?><a/>` now parses, matching
  xmllint and Python's expat.
- **`DoctypePolicy.ignore`'s DOCTYPE skip now tracks quote state for the
  WHOLE declaration**, not just inside an internal subset's `[ ... ]`
  (former F10), so a literal `>` inside a `SYSTEM`/`PUBLIC` external
  identifier literal no longer ends the skip early. Verified black-box
  against xmllint/expat.
- **`Document.findByAttr` no longer recurses on the machine stack**
  (former "F5-zbytek"). Same fix and same shape as `Element.textContent`
  (F5, closed 2026-09-10): an explicit heap stack, bounded by the allocator
  instead of `ulimit -s`. **API change**: `findByAttr` now takes an
  `std.mem.Allocator` and returns `std.mem.Allocator.Error!?*Element`
  instead of `?*Element`. All three in-repo callers (`xmldsig`,
  `saml`, `netconf`) were updated in the same commit.

## Validation

Green in Debug and ReleaseFast (UB-checked). Composition:
- **W3C-pattern well-formed**: nested elements/attributes/document-order,
  namespace default/prefixed/scoping/shadowing/resolution, mixed content with
  comments + PIs + CDATA + byte-span round-trip, entity + numeric-ref decoding,
  attribute-value normalization, ID lookup, inherited namespace axis.
- **W3C-pattern not-well-formed** (modeled on the xmlconf `not-wf/sa` +
  Namespaces error cases): mismatched/overlapping/unclosed tags, duplicate
  attribute, undeclared entity, undeclared prefix, prefix-undeclaration,
  invalid name, out-of-range char ref, bad comment, multiple/absent roots,
  top-level text.
- **Security** (each with a positive control proving the guard has teeth): XXE,
  billion-laughs, depth cap, attribute-count cap, duplicate ID, invalid UTF-8,
  encoding/version rejection.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** src/xmlconf_test.zig runs 130 cases of the W3C XML Conformance Test Suite (src/testdata/xmlconf) through parse; the slice is LICENCE-FILTERED (xmltest excluded on licence grounds, so the suite's largest section is absent) and src/xmlconf_test.zig carries a known_disagreements list -- paths outside the vendored slice remain self-graded

**How it got there.** The anchoring work landed. DONE 6cc02e8: 130 xmlconf cases, FIVE real bugs; xmltest excluded on licence grounds
