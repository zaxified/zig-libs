#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for `src/wf_vectors.zig`: OUR OWN well-formedness inputs, with the
expected verdict taken from libxml2 (through lxml, BSD-3; libxml2 itself MIT)
driven as a BLACK-BOX oracle -- public API only (`etree.fromstring` with an
`XMLParser`), no source read, no libxml2/lxml test data copied.

Why this exists (2026-10-24): the module used to vendor a slice of the W3C
XML Conformance Test Suite. Those files carry notices that grant no
permission to redistribute them, so they left the repository. This recipe
replaces them with fresh inputs written for the same XML 1.0 productions and
defect classes (section numbers below name the class, not the suite's text).
The real suite is fetched at test time, never committed: `xmlconf_fetch.sh`
and `xmlconf_run.zig`.

Run:  python3 gen_wf_vectors.py > ../src/wf_vectors.zig && zig fmt ../src/wf_vectors.zig
      python3 gen_wf_vectors.py --files DIR   # also write DIR/<id>.xml + DIR/index.tsv
                                              # (for tools/probe.zig `file` runs; no stdout)

Per case:
  id, sections  XML 1.0 (5th ed.) section / production the case exercises
  mode          .none      no DOCTYPE; default Options
                .ignore    DOCTYPE whose internal subset is a no-op; Options{.doctype=.ignore}
                .entities  declares general entities; Options{.doctype=.internal_entities}
  lxml          null = libxml2 refused the document; otherwise its view of the
                document as the DUMP defined in gen_core_vectors.py (re-implemented
                by core_test.zig's `dump`)
  ours          null = this module agrees with libxml2 (rejects, or accepts with the
                same DUMP). Otherwise a DELIBERATE deviation, recorded here by hand
                after looking at the cause -- never flipped silently to match our
                output: "accept" = we accept what libxml2 refuses; an error name =
                we refuse (with exactly that error) what libxml2 accepts;
                "infoset:" + DUMP = we accept but build a different infoset.
"""
import sys
from lxml import etree


def hx(s):
    return s.encode("utf-8").hex()


def dump_el(el):
    out = []
    tag = etree.QName(el)
    out.append("<{%s}%s" % (tag.namespace or "", tag.localname))
    attrs = []
    for k, v in el.attrib.items():
        q = etree.QName(k)
        attrs.append((q.namespace or "", q.localname, v))
    for u, l, v in sorted(attrs):
        out.append(" {%s}%s=%s" % (u, l, hx(v)))
    out.append(">")
    if el.text:
        out.append("T[%s]" % hx(el.text))
    for c in el:
        if isinstance(c, etree._Comment):
            out.append("C[%s]" % hx(c.text or ""))
        elif isinstance(c, etree._ProcessingInstruction):
            out.append("P[%s %s]" % (c.target, hx(c.text or "")))
        elif isinstance(c, etree._Entity):
            raise ValueError("unresolved entity")
        else:
            out.append(dump_el(c))
        if c.tail:
            out.append("T[%s]" % hx(c.tail))
    out.append("</>")
    return "".join(out)


def merge_text(d):
    import re
    while True:
        m = re.search(r"T\[([0-9a-f]*)\]T\[([0-9a-f]*)\]", d)
        if not m:
            return d
        d = d[:m.start()] + "T[%s%s]" % (m.group(1), m.group(2)) + d[m.end():]


def oracle(data, entities):
    p = etree.XMLParser(resolve_entities=entities, no_network=True, load_dtd=False,
                        huge_tree=False, remove_blank_text=False)
    try:
        return merge_text(dump_el(etree.fromstring(data, p)))
    except (etree.XMLSyntaxError, ValueError):
        return None


# Deliberate deviations from libxml2, id -> "accept" | ErrorName. Filled by hand
# after reading the cause (see the comment on each).
OURS = {
    # Measured 2026-10-24 with tools/probe.zig. Each is a place where this module is MORE
    # LENIENT than libxml2 (the direction that matters for a signature verifier); they are
    # recorded, not fixed, by the commit that introduced this file -- see CHANGELOG.
    # NSC "Reserved Prefixes and Namespace Names": the XML namespace as the DEFAULT namespace.
    "r-ns-xml-uri-default": "accept",
    # Under doctype=.ignore the DOCTYPE is skipped without checking its position or shape.
    "r-dt-two": "accept",            # second DOCTYPE
    "r-dt-after-root": "accept",     # DOCTYPE after the root element
    "r-dt-in-content": "accept",     # DOCTYPE inside the root element
    "r-dt-no-name": "accept",        # <!DOCTYPE> with no name
    "r-dt-bad-subset-open": "accept",  # <!DOCTYPE a ]> (] without [)
}

cases = []  # (id, sections, desc, bytes, mode)


def add(cid, sec, desc, data, mode=None):
    if isinstance(data, str):
        data = data.encode("utf-8")
    if mode is None:
        mode = "ignore" if b"<!DOCTYPE" in data else "none"
    cases.append((cid, sec, desc, data, mode))


def ent(cid, sec, desc, data):
    add(cid, sec, desc, data, "entities")


# ---------------------------------------------------------------- REJECT ----
# Prolog and XML declaration (2.8, productions 22-27, 32, 77-81)
add("r-decl-no-version", "2.8 [23]", "XMLDecl without a version", '<?xml encoding="UTF-8"?><a/>')
add("r-decl-version-unquoted", "2.8 [24]", "version value without quotes", '<?xml version=1.0?><a/>')
add("r-decl-version-mixed-quotes", "2.8 [24]", "version quoted with ' and \"", "<?xml version='1.0\"?><a/>")
add("r-decl-version-empty", "2.8 [26]", "empty VersionNum", '<?xml version=""?><a/>')
add("r-decl-version-letters", "2.8 [26]", "VersionNum with letters", '<?xml version="1.x"?><a/>')
add("r-decl-version-3", "2.8 [26]", "unsupported major version", '<?xml version="3.0"?><a/>')
add("r-decl-order", "2.8 [23]", "standalone before encoding", '<?xml version="1.0" standalone="yes" encoding="UTF-8"?><a/>')
add("r-decl-standalone-value", "2.9 [32]", "standalone other than yes/no", '<?xml version="1.0" standalone="maybe"?><a/>')
add("r-decl-standalone-case", "2.9 [32]", "standalone value is case sensitive", '<?xml version="1.0" standalone="YES"?><a/>')
add("r-decl-empty", "2.8 [23]", "empty XMLDecl", '<?xml?><a/>')
add("r-decl-unterminated", "2.8 [23]", "XMLDecl never closed", '<?xml version="1.0"')
add("r-decl-no-space", "2.8 [23]", "no space before encoding", '<?xml version="1.0"encoding="UTF-8"?><a/>')
add("r-decl-after-space", "2.8 [23]", "XMLDecl after leading whitespace", ' <?xml version="1.0"?><a/>')
add("r-decl-after-newline", "2.8 [23]", "XMLDecl after a newline", '\n<?xml version="1.0"?><a/>')
add("r-decl-after-comment", "2.8 [23]", "XMLDecl after a comment", '<!-- c --><?xml version="1.0"?><a/>')
add("r-decl-twice", "2.8 [23]", "two XMLDecls", '<?xml version="1.0"?><?xml version="1.0"?><a/>')
add("r-decl-in-content", "2.6 [17]", "xml PI target inside the root", '<a><?xml version="1.0"?></a>')
add("r-pi-target-XML", "2.6 [17]", "PI target XML in capitals", '<?XML version="1.0"?><a/>')
add("r-pi-target-Xml", "2.6 [17]", "PI target Xml mixed case", '<a><?Xml x?></a>')
add("r-enc-empty", "4.3.3 [81]", "empty encoding name", '<?xml version="1.0" encoding=""?><a/>')
add("r-enc-digit-start", "4.3.3 [81]", "encoding name starting with a digit", '<?xml version="1.0" encoding="8859-1"?><a/>')
add("r-enc-space", "4.3.3 [81]", "space inside the encoding name", '<?xml version="1.0" encoding="UTF 8"?><a/>')
add("r-enc-non-ascii", "4.3.3 [81]", "non-ASCII letter in the encoding name", '<?xml version="1.0" encoding="UTF-\u00e9"?><a/>')
add("r-enc-charref", "4.3.3 [81]", "character reference in the encoding name", '<?xml version="1.0" encoding="UTF&#45;8"?><a/>')
add("r-enc-slash", "4.3.3 [81]", "slash in the encoding name", '<?xml version="1.0" encoding="UTF/8"?><a/>')
add("r-enc-unquoted", "4.3.3 [80]", "encoding value without quotes", '<?xml version="1.0" encoding=UTF-8?><a/>')

# Document structure (2.1, production 1)
add("r-doc-empty", "2.1 [1]", "empty input", '')
add("r-doc-blank", "2.1 [1]", "only whitespace", ' \n\t ')
add("r-doc-only-comment", "2.1 [1]", "a comment and no root", '<!-- c -->')
add("r-doc-only-decl", "2.1 [1]", "only an XMLDecl", '<?xml version="1.0"?>')
add("r-doc-only-pi", "2.1 [1]", "only a PI", '<?p d?>')
add("r-doc-text", "2.1 [1]", "text and no element", 'hello')
add("r-doc-text-before", "2.1 [1]", "text before the root", 'x<a/>')
add("r-doc-text-after", "2.1 [27]", "text after the root", '<a/>x')
add("r-doc-two-roots", "2.1 [1]", "two root elements", '<a/><b/>')
add("r-doc-two-roots-same", "2.1 [1]", "the same root element twice", '<a></a><a></a>')
add("r-doc-stray-end", "2.1 [1]", "end tag after the root", '<a/></a>')
add("r-doc-cdata-after", "2.1 [27]", "CDATA section after the root", '<a/><![CDATA[x]]>')
add("r-doc-cdata-before", "2.1 [22]", "CDATA section before the root", '<![CDATA[x]]><a/>')
add("r-doc-charref-after", "2.1 [27]", "character reference after the root", '<a/>&#65;')
add("r-doc-lt-only", "3.1 [40]", "a lone <", '<')
add("r-doc-lt-space", "3.1 [40]", "< followed by a space", '< a/>')
add("r-doc-gt-only", "2.4 [14]", "a lone >", '>')
add("r-doc-nul-trailing", "2.2 [2]", "a NUL byte after the root", b'<a/>\x00')
add("r-doc-bom-garbage", "2.1 [1]", "a partial BOM before the root", b'\xef\xbb<a/>')

# Elements and tags (3.1, 3.3 productions 39-44)
add("r-el-eof-start", "3.1 [40]", "EOF inside a start tag", '<a')
add("r-el-eof-attr", "3.1 [41]", "EOF inside an attribute value", '<a b="1')
add("r-el-eof-content", "3.1 [39]", "root never closed", '<a>')
add("r-el-eof-nested", "3.1 [39]", "inner element never closed", '<a><b></a>')
add("r-el-eof-end", "3.1 [42]", "EOF inside an end tag", '<a></a')
add("r-el-eof-end2", "3.1 [42]", "EOF right after </", '<a></')
add("r-el-mismatch", "3.1 [39]", "end tag names another element", '<a></b>')
add("r-el-mismatch-case", "3.1 [39]", "end tag differs in case", '<a></A>')
add("r-el-mismatch-prefix", "3.1 [39]", "end tag lacks the prefix", '<p:a xmlns:p="urn:x"></a>')
add("r-el-crossed", "3.1 [39]", "crossed nesting", '<a><b></a></b>')
add("r-el-extra-end", "3.1 [39]", "one end tag too many", '<a><b/></b></a>')
add("r-el-space-after-lt-end", "3.1 [42]", "space between </ and the name", '<a></ a>')
add("r-el-end-with-attr", "3.1 [42]", "attribute on an end tag", '<a></a b="1">')
add("r-el-end-selfclose", "3.1 [42]", "end tag with a slash", '<a></a/>')
add("r-el-empty-space", "3.1 [44]", "space between / and > in an empty tag", '<a/ >')
add("r-el-empty-space2", "3.1 [44]", "space inside the empty-element close", '<a / >')
add("r-el-slash-no-gt", "3.1 [44]", "/ without >", '<a/')
add("r-el-name-digit", "2.3 [5]", "element name starting with a digit", '<1a/>')
add("r-el-name-hyphen", "2.3 [5]", "element name starting with a hyphen", '<-a/>')
add("r-el-name-dot", "2.3 [5]", "element name starting with a dot", '<.a/>')
add("r-el-name-dollar", "2.3 [4]", "$ inside an element name", '<a$b/>')
add("r-el-name-at", "2.3 [4]", "@ inside an element name", '<a@b/>')
add("r-el-name-hash", "2.3 [5]", "element name starting with #", '<#a/>')
add("r-el-name-multiply", "2.3 [4]", "U+00D7 in an element name", '<a\u00d7b/>')
add("r-el-name-divide", "2.3 [4]", "U+00F7 in an element name", '<a\u00f7b/>')
add("r-el-name-middot-start", "2.3 [5]", "U+00B7 starting an element name", '<\u00b7a/>')
add("r-el-name-combining-start", "2.3 [5]", "combining mark starting an element name", '<\u0301a/>')
add("r-el-name-nbsp", "2.3 [4]", "no-break space inside an element name", '<a\u00a0b/>')
add("r-el-name-empty", "2.3 [5]", "< followed directly by >", '<>')
add("r-el-name-bang", "3.1 [40]", "<! that opens nothing known", '<a><!x></a>')
add("r-el-lt-in-text", "2.4 [14]", "bare < in character data", '<a>1 < 2</a>')
add("r-el-lt-in-text-eof", "2.4 [14]", "bare < at the end of the content", '<a><</a>')
add("r-el-amp-bare", "2.4 [14]", "bare & in character data", '<a>x & y</a>')
add("r-el-cdend-text", "2.4 [14]", "]]> in character data", '<a>]]></a>')
add("r-el-cdend-text2", "2.4 [14]", "]]> after other text", '<a>x]]>y</a>')

# Attributes (3.1 productions 40-41, 3.3.3, WFC no duplicates / no < in values)
add("r-at-no-value", "3.1 [41]", "attribute without = and value", '<a b/>')
add("r-at-no-value2", "3.1 [41]", "attribute without value before >", '<a b>x</a>')
add("r-at-unquoted", "3.1 [41]", "attribute value without quotes", '<a b=c/>')
add("r-at-unquoted-num", "3.1 [41]", "numeric attribute value without quotes", '<a b=1/>')
add("r-at-mixed-quotes", "3.1 [10]", "value opened with ' closed with \"", '<a b=\'c"/>')
add("r-at-mixed-quotes2", "3.1 [10]", "value opened with \" closed with '", "<a b=\"c'/>")
add("r-at-open-quote", "3.1 [10]", "value quote never closed", '<a b="/>')
add("r-at-lt-value", "3.1 WFC", "< inside an attribute value", '<a b="<"/>')
add("r-at-lt-value2", "3.1 WFC", "markup inside an attribute value", '<a b="<c/>"/>')
add("r-at-amp-bare", "3.1 [10]", "bare & in an attribute value", '<a b="&"/>')
add("r-at-amp-noterm", "4.1 [68]", "reference without ; in an attribute", '<a b="&amp"/>')
add("r-at-undefined-entity", "4.1 WFC", "undeclared entity in an attribute value", '<a b="&nope;"/>')
add("r-at-duplicate", "3.1 WFC", "same attribute twice", '<a b="1" b="2"/>')
add("r-at-duplicate-same", "3.1 WFC", "same attribute twice, same value", '<a b="1" b="1"/>')
add("r-at-duplicate-quotes", "3.1 WFC", "same attribute twice, different quote style", "<a b='1' b=\"2\"/>")
add("r-at-no-space", "3.1 [40]", "no whitespace between attributes", '<a b="1"c="2"/>')
add("r-at-no-name", "3.1 [41]", "= without an attribute name", '<a ="1"/>')
add("r-at-no-name2", "3.1 [41]", "value without name or =", '<a "1"/>')
add("r-at-name-digit", "2.3 [5]", "attribute name starting with a digit", '<a 1b="x"/>')
add("r-at-name-bang", "2.3 [4]", "! in an attribute name", '<a b!="x"/>')
add("r-at-name-multiply", "2.3 [4]", "U+00D7 in an attribute name", '<a b\u00d7="x"/>')
add("r-at-double-eq", "3.1 [25]", "two = signs", '<a b=="1"/>')
add("r-at-eq-eq-space", "3.1 [41]", "stray text between value and >", '<a b="1" x></a>')
add("r-at-comma", "3.1 [40]", "comma between attributes", '<a b="1", c="2"/>')
add("r-at-after-slash", "3.1 [44]", "attribute after the /", '<a/ b="1">')
add("r-at-ctrl-in-value", "2.2 [2]", "control character in an attribute value", b'<a b="\x01"/>')
add("r-at-gt-then-eof", "3.1 [41]", "attribute, then EOF before >", '<a b="1" ')

# Character and entity references (4.1, 4.4 WFC Legal Character)
add("r-ref-empty-name", "4.1 [68]", "&; with no name", '<a>&;</a>')
add("r-ref-undefined", "4.1 WFC", "undeclared entity in content", '<a>&nope;</a>')
add("r-ref-undefined-underscore", "4.1 WFC", "undeclared entity with underscore name", '<a>&_x;</a>')
add("r-ref-case", "4.6", "predefined entities are case sensitive", '<a>&Lt;</a>')
add("r-ref-case2", "4.6", "&AMP; is not predefined", '<a>&AMP;</a>')
add("r-ref-noterm", "4.1 [68]", "entity reference without ;", '<a>&amp</a>')
add("r-ref-noterm-eof", "4.1 [68]", "entity reference cut by EOF", '<a>&amp')
add("r-ref-space-before-semi", "4.1 [68]", "space before the ;", '<a>&amp ;</a>')
add("r-ref-space-after-amp", "4.1 [68]", "space after the &", '<a>& amp;</a>')
add("r-ref-digit-name", "4.1 [68]", "entity name starting with a digit", '<a>&1x;</a>')
add("r-ref-colon-name", "4.1 [68]", "entity name that is not a legal NCName start", '<a>&-x;</a>')
add("r-ref-char-empty", "4.1 [66]", "&#; with no digits", '<a>&#;</a>')
add("r-ref-char-hex-empty", "4.1 [66]", "&#x; with no digits", '<a>&#x;</a>')
add("r-ref-char-noterm", "4.1 [66]", "&#65 without ;", '<a>&#65</a>')
add("r-ref-char-noterm-gt", "4.1 [66]", "&#x41 then text", '<a>&#x41 b;</a>')
add("r-ref-char-upper-x", "4.1 [66]", "&#X41; with a capital X", '<a>&#X41;</a>')
add("r-ref-char-non-hex", "4.1 [66]", "non-hex digit in &#x...;", '<a>&#xg;</a>')
add("r-ref-char-non-dec", "4.1 [66]", "letter in a decimal reference", '<a>&#6a;</a>')
add("r-ref-char-neg", "4.1 [66]", "negative decimal reference", '<a>&#-1;</a>')
add("r-ref-char-plus", "4.1 [66]", "signed decimal reference", '<a>&#+65;</a>')
add("r-ref-char-nul", "4.1 WFC", "&#0; is not a Char", '<a>&#0;</a>')
add("r-ref-char-x0", "4.1 WFC", "&#x0; is not a Char", '<a>&#x0;</a>')
add("r-ref-char-1", "4.1 WFC", "&#1; is not a Char", '<a>&#1;</a>')
add("r-ref-char-8", "4.1 WFC", "&#8; is not a Char", '<a>&#8;</a>')
add("r-ref-char-b", "4.1 WFC", "&#xB; is not a Char", '<a>&#xB;</a>')
add("r-ref-char-c", "4.1 WFC", "&#xC; is not a Char", '<a>&#xC;</a>')
add("r-ref-char-1f", "4.1 WFC", "&#x1F; is not a Char", '<a>&#x1F;</a>')
add("r-ref-char-surrogate", "4.1 WFC", "&#xD800; is a surrogate", '<a>&#xD800;</a>')
add("r-ref-char-surrogate2", "4.1 WFC", "&#xDFFF; is a surrogate", '<a>&#xDFFF;</a>')
add("r-ref-char-surrogate-dec", "4.1 WFC", "decimal surrogate 55296", '<a>&#55296;</a>')
add("r-ref-char-fffe", "4.1 WFC", "&#xFFFE; is not a Char", '<a>&#xFFFE;</a>')
add("r-ref-char-ffff", "4.1 WFC", "&#xFFFF; is not a Char", '<a>&#xFFFF;</a>')
add("r-ref-char-110000", "4.1 WFC", "&#x110000; is beyond Unicode", '<a>&#x110000;</a>')
add("r-ref-char-huge", "4.1 WFC", "a reference far beyond 32 bits", '<a>&#99999999999999999999;</a>')
add("r-ref-char-attr-nul", "4.1 WFC", "&#0; in an attribute value", '<a b="&#0;"/>')
add("r-ref-char-attr-fffe", "4.1 WFC", "&#xFFFE; in an attribute value", '<a b="&#xFFFE;"/>')

# Characters (2.2 production 2)
add("r-chr-nul", "2.2 [2]", "NUL in character data", b'<a>\x00</a>')
add("r-chr-01", "2.2 [2]", "U+0001 in character data", b'<a>\x01</a>')
add("r-chr-08", "2.2 [2]", "U+0008 in character data", b'<a>\x08</a>')
add("r-chr-0b", "2.2 [2]", "U+000B in character data", b'<a>\x0b</a>')
add("r-chr-0c", "2.2 [2]", "U+000C in character data", b'<a>\x0c</a>')
add("r-chr-1f", "2.2 [2]", "U+001F in character data", b'<a>\x1f</a>')
add("r-chr-fffe", "2.2 [2]", "U+FFFE in character data", b'<a>\xef\xbf\xbe</a>')
add("r-chr-ffff", "2.2 [2]", "U+FFFF in character data", b'<a>\xef\xbf\xbf</a>')
add("r-chr-surrogate-utf8", "2.2 [2]", "an encoded surrogate (invalid UTF-8)", b'<a>\xed\xa0\x80</a>')
add("r-chr-overlong", "2.2 [2]", "an overlong NUL (invalid UTF-8)", b'<a>\xc0\x80</a>')
add("r-chr-overlong3", "2.2 [2]", "an overlong 3-byte slash (invalid UTF-8)", b'<a>\xe0\x80\xaf</a>')
add("r-chr-ff", "2.2 [2]", "byte 0xFF (invalid UTF-8)", b'<a>\xff</a>')
add("r-chr-truncated", "2.2 [2]", "a truncated multi-byte sequence", b'<a>\xe6\xb0</a>')
add("r-chr-lone-cont", "2.2 [2]", "a lone continuation byte", b'<a>\x80</a>')
add("r-chr-beyond", "2.2 [2]", "a 4-byte sequence above U+10FFFF", b'<a>\xf4\x90\x80\x80</a>')
add("r-chr-comment", "2.2 [2]", "control character in a comment", b'<a><!--\x01--></a>')
add("r-chr-cdata", "2.2 [2]", "control character in a CDATA section", b'<a><![CDATA[\x01]]></a>')
add("r-chr-pi", "2.2 [2]", "control character in a PI", b'<a><?p \x01?></a>')
add("r-chr-name", "2.3 [4]", "control character inside a name", b'<a\x01b/>')
add("r-chr-prolog", "2.2 [2]", "control character in the prolog", b'\x01<a/>')
add("r-chr-ff-attr", "2.2 [2]", "invalid UTF-8 in an attribute value", b'<a b="\xff"/>')

# Comments (2.5), PIs (2.6), CDATA (2.7)
add("r-cm-double-dash", "2.5 [15]", "-- inside a comment", '<a><!-- a -- b --></a>')
add("r-cm-triple-end", "2.5 [15]", "comment ending in --->", '<a><!-- a ---></a>')
add("r-cm-short-open", "2.5 [15]", "<!---> is not a complete comment", '<a><!---></a>')
add("r-cm-unterminated", "2.5 [15]", "comment never closed", '<a><!-- x</a>')
add("r-cm-unterminated-eof", "2.5 [15]", "comment cut by EOF", '<a/><!-- x')
add("r-cm-one-dash-open", "2.5 [15]", "<!- instead of <!--", '<a><!- x --></a>')
add("r-cm-one-dash-close", "2.5 [15]", "comment closed with -> only", '<a><!-- x -></a>')
add("r-cm-prolog-dd", "2.5 [15]", "-- inside a prolog comment", '<!-- a -- b --><a/>')
add("r-cm-epilog-dd", "2.5 [15]", "-- inside an epilog comment", '<a/><!-- a -- b -->')
add("r-cm-in-tag", "3.1 [40]", "comment inside a start tag", '<a <!-- c --> b="1"/>')
add("r-pi-no-target", "2.6 [16]", "PI without a target", '<a><? d?></a>')
add("r-pi-no-target2", "2.6 [16]", "PI that is only ?>", '<a><??></a>')
add("r-pi-digit-target", "2.6 [17]", "PI target starting with a digit", '<a><?1p d?></a>')
add("r-pi-unterminated", "2.6 [16]", "PI never closed", '<a><?p d</a>')
add("r-pi-unterminated-eof", "2.6 [16]", "PI cut by EOF", '<a/><?p')
add("r-pi-question-no-gt", "2.6 [16]", "? inside PI data never followed by >", '<a><?pd?x</a>')
add("r-pi-gt-only", "2.6 [16]", "PI closed with > only", '<a><?p d></a>')
add("r-pi-colon-target", "Namespaces 1.0 [4]", "PI target containing a colon", '<a><?x:y d?></a>')
add("r-cd-unterminated", "2.7 [18]", "CDATA section never closed", '<a><![CDATA[x</a>')
add("r-cd-unterminated2", "2.7 [18]", "CDATA closed with ]> only", '<a><![CDATA[x]></a>')
add("r-cd-lowercase", "2.7 [19]", "CDATA keyword in lowercase", '<a><![cdata[x]]></a>')
add("r-cd-space", "2.7 [19]", "space inside <![CDATA [", '<a><![CDATA [x]]></a>')
add("r-cd-nested", "2.7 [20]", "CDATA section nested in CDATA (the inner ]]> ends the outer one)", '<a><![CDATA[<![CDATA[x]]>]]></a>')
add("r-cd-section-bang", "2.7 [18]", "<![ with another keyword", '<a><![INCLUDE[x]]></a>')
add("r-cd-in-attr", "2.7 [18]", "CDATA section inside an attribute", '<a b="<![CDATA[x]]>"/>')

# Namespaces in XML 1.0 (production 7-10, NSC)
add("r-ns-unbound-el", "NS 1.0 NSC", "unbound element prefix", '<p:a/>')
add("r-ns-unbound-child", "NS 1.0 NSC", "unbound prefix on a child", '<a><p:b/></a>')
add("r-ns-unbound-attr", "NS 1.0 NSC", "unbound attribute prefix", '<a p:b="1"/>')
add("r-ns-unbound-scope", "NS 1.0 NSC", "prefix declared on a sibling only", '<a><b xmlns:p="urn:x"/><p:c/></a>')
add("r-ns-unbound-after-close", "NS 1.0 NSC", "prefix used after its element closed", '<a><b xmlns:p="urn:x"></b><c p:d="1"/></a>')
add("r-ns-colon-end", "NS 1.0 [7]", "element name ending in a colon", '<a xmlns:a="urn:x"><a:/></a>')
add("r-ns-colon-start", "NS 1.0 [7]", "element name starting with a colon", '<:a/>')
add("r-ns-two-colons", "NS 1.0 [7]", "two colons in an element name", '<a xmlns:a="urn:x"><a:b:c/></a>')
add("r-ns-attr-two-colons", "NS 1.0 [7]", "two colons in an attribute name", '<a xmlns:a="urn:x" a:b:c="1"/>')
add("r-ns-attr-colon-end", "NS 1.0 [7]", "attribute name ending in a colon", '<a xmlns:a="urn:x" a:="1"/>')
add("r-ns-empty-decl-name", "NS 1.0 [1]", "xmlns: with no prefix", '<a xmlns:="urn:x"/>')
add("r-ns-unbind-prefix", "NS 1.0 NSC", "xmlns:p=\"\" (1.1 syntax) in a 1.0 document", '<a xmlns:p=""/>')
add("r-ns-unbind-prefix-used", "NS 1.0 NSC", "prefix undeclared with an empty value, then used", '<a xmlns:p="urn:x"><b xmlns:p=""><p:c/></b></a>')
add("r-ns-xml-wrong-uri", "NS 1.0 NSC", "xml prefix bound to another namespace", '<a xmlns:xml="urn:other"/>')
add("r-ns-xml-uri-other-prefix", "NS 1.0 NSC", "xml namespace bound to another prefix", '<a xmlns:p="http://www.w3.org/XML/1998/namespace"/>')
add("r-ns-xml-uri-default", "NS 1.0 NSC", "xml namespace bound as the default", '<a xmlns="http://www.w3.org/XML/1998/namespace"/>')
add("r-ns-xmlns-declared", "NS 1.0 NSC", "xmlns prefix declared", '<a xmlns:xmlns="urn:x"/>')
add("r-ns-xmlns-declared-own", "NS 1.0 NSC", "xmlns prefix bound to its own namespace", '<a xmlns:xmlns="http://www.w3.org/2000/xmlns/"/>')
add("r-ns-xmlns-uri-prefix", "NS 1.0 NSC", "xmlns namespace bound to a prefix", '<a xmlns:p="http://www.w3.org/2000/xmlns/"/>')
add("r-ns-xmlns-uri-default", "NS 1.0 NSC", "xmlns namespace bound as the default", '<a xmlns="http://www.w3.org/2000/xmlns/"/>')
add("r-ns-dup-expanded", "NS 1.0 NSC", "two prefixes for one namespace, same local attribute", '<a xmlns:p="urn:x" xmlns:q="urn:x" p:b="1" q:b="2"/>')
add("r-ns-dup-prefix-decl", "NS 1.0 WFC", "the same xmlns:p declared twice", '<a xmlns:p="urn:x" xmlns:p="urn:y"/>')
add("r-ns-dup-default-decl", "NS 1.0 WFC", "the default namespace declared twice", '<a xmlns="urn:x" xmlns="urn:y"/>')
add("r-ns-dup-attr-prefix", "NS 1.0 WFC", "same prefixed attribute twice", '<a xmlns:p="urn:x" p:b="1" p:b="2"/>')

# DOCTYPE present with a no-op internal subset, then something bad (mode .ignore)
add("r-dt-trailing-text", "2.8 [28]", "text after a DOCTYPE and before the root", '<!DOCTYPE a>x<a/>')
add("r-dt-two", "2.8 [22]", "two DOCTYPEs", '<!DOCTYPE a><!DOCTYPE a><a/>')
add("r-dt-after-root", "2.8 [22]", "DOCTYPE after the root", '<a/><!DOCTYPE a>')
add("r-dt-in-content", "2.8 [22]", "DOCTYPE inside the root", '<!DOCTYPE a><a><!DOCTYPE a></a>')
add("r-dt-root-unclosed", "3.1 [39]", "root never closed after a DOCTYPE", '<!DOCTYPE a [<!ELEMENT a ANY>]><a>')
add("r-dt-bad-attr", "3.1 [41]", "unquoted attribute after a DOCTYPE", '<!DOCTYPE a [<!ELEMENT a ANY>]><a b=c/>')
add("r-dt-undefined-entity", "4.1 WFC", "entity not declared by the (no-op) subset", '<!DOCTYPE a [<!ELEMENT a ANY>]><a>&e;</a>')
add("r-dt-mismatch", "3.1 [39]", "mismatched tags after a DOCTYPE", '<!DOCTYPE a [<!ATTLIST a b CDATA #IMPLIED>]><a></b>')
add("r-dt-lowercase", "2.8 [28]", "doctype keyword in lowercase", '<!doctype a><a/>', "ignore")
add("r-dt-no-name", "2.8 [28]", "DOCTYPE without a name", '<!DOCTYPE><a/>')
add("r-dt-unterminated", "2.8 [28]", "DOCTYPE never closed", '<!DOCTYPE a [<!ELEMENT a ANY>')
add("r-dt-bad-subset-open", "2.8 [28]", "DOCTYPE with ] but no [", '<!DOCTYPE a ]><a/>')
add("r-dt-chr", "2.2 [2]", "control character after a DOCTYPE", b'<!DOCTYPE a><a>\x01</a>')

# ---------------------------------------------------------------- ACCEPT ----
# Document shapes
add("a-min-empty", "3.1 [44]", "empty-element root", '<a/>')
add("a-min-pair", "3.1 [39]", "start and end tag, no content", '<a></a>')
add("a-min-space-selfclose", "3.1 [44]", "space before the /> ", '<a />')
add("a-min-space-end", "3.1 [42]", "space inside the end tag", '<a></a  >')
add("a-min-newline-end", "3.1 [42]", "newline inside the end tag", '<a></a\n>')
add("a-min-one-char-name", "2.3 [5]", "one-letter name", '<x>y</x>')
add("a-prolog-decl", "2.8 [23]", "XMLDecl with a version only", '<?xml version="1.0"?><a/>')
add("a-prolog-decl-single", "2.8 [24]", "version in single quotes", "<?xml version='1.0'?><a/>")
add("a-prolog-decl-eq-space", "2.8 [25]", "spaces around =", '<?xml version = "1.0" ?><a/>')
add("a-prolog-decl-eq-left", "2.8 [25]", "space before =", '<?xml version ="1.0"?><a/>')
add("a-prolog-decl-eq-right", "2.8 [25]", "space after =", '<?xml version= "1.0"?><a/>')
add("a-prolog-decl-trailing-nl", "2.8 [23]", "newline before ?>", '<?xml version="1.0"\n?><a/>')
add("a-prolog-decl-tab", "2.8 [23]", "tab between pseudo-attributes", '<?xml version="1.0"\tencoding="UTF-8"?><a/>')
add("a-prolog-decl-newline", "2.8 [23]", "newline between pseudo-attributes", '<?xml\nversion="1.0"\nencoding="UTF-8"\n?><a/>')
add("a-prolog-enc-upper", "4.3.3 [80]", "encoding UTF-8", '<?xml version="1.0" encoding="UTF-8"?><a>x</a>')
add("a-prolog-enc-lower", "4.3.3 [80]", "encoding utf-8", '<?xml version="1.0" encoding="utf-8"?><a>x</a>')
add("a-prolog-enc-single", "4.3.3 [80]", "encoding in single quotes", "<?xml version=\"1.0\" encoding='UTF-8'?><a/>")
add("a-prolog-enc-ascii", "4.3.3 [80]", "encoding US-ASCII, ASCII content", '<?xml version="1.0" encoding="US-ASCII"?><a>x</a>')
add("a-prolog-sd-yes", "2.9 [32]", "standalone yes", '<?xml version="1.0" standalone="yes"?><a/>')
add("a-prolog-sd-no", "2.9 [32]", "standalone no", '<?xml version="1.0" standalone="no"?><a/>')
add("a-prolog-sd-single", "2.9 [32]", "standalone in single quotes", "<?xml version=\"1.0\" standalone='yes'?><a/>")
add("a-prolog-all", "2.8 [23]", "version, encoding and standalone", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><a/>')
add("a-prolog-all-trailing", "2.8 [23]", "all three and a trailing space", '<?xml version="1.0" encoding="UTF-8" standalone="no" ?><a/>')
add("a-prolog-version-1x", "2.8 [26]", "version 1.0 only (1.1 is out of scope)", '<?xml version="1.0"?>\n<a/>')
add("a-prolog-bom", "2.8 [3]", "UTF-8 byte order mark", b'\xef\xbb\xbf<a/>')
add("a-prolog-bom-decl", "2.8 [3]", "UTF-8 BOM and an XMLDecl", b'\xef\xbb\xbf<?xml version="1.0" encoding="UTF-8"?><a/>')
add("a-misc-comment-before", "2.8 [27]", "comment before the root", '<!-- c --><a/>')
add("a-misc-comment-after", "2.8 [27]", "comment after the root", '<a/><!-- c -->')
add("a-misc-pi-before", "2.8 [27]", "PI before the root", '<?p d?><a/>')
add("a-misc-pi-after", "2.8 [27]", "PI after the root", '<a/><?p d?>')
add("a-misc-space-before", "2.8 [27]", "whitespace before the root", ' \t\r\n<a/>')
add("a-misc-space-after", "2.8 [27]", "whitespace after the root", '<a/> \t\r\n')
add("a-misc-all", "2.8 [22]", "XMLDecl, comment, PI, spaces, root, comment, PI", '<?xml version="1.0"?>\n<!-- a -->\n<?p q?>\n<a/>\n<!-- b -->\n<?r s?>\n')
add("a-misc-many", "2.8 [27]", "many comments and PIs around the root", '<!--1--><?a 1?><!--2--><?b 2?><r/><!--3--><?c 3?><!--4-->')
add("a-misc-nl-eof", "2.1 [1]", "newline at EOF", '<a/>\n')

# Characters and white space (2.2, 2.3, 2.11)
add("a-chr-ws", "2.3 [3]", "all four white space characters in content", '<a> \t\r\n</a>')
add("a-chr-tab-nl-cr", "2.2 [2]", "tab, newline, carriage return as text", '<a>x\ty\nz\rw</a>')
add("a-chr-crlf", "2.11", "CRLF in content becomes LF", '<a>x\r\ny</a>')
add("a-chr-cr-lone", "2.11", "lone CR in content becomes LF", '<a>x\ry</a>')
add("a-chr-crcr", "2.11", "two CRs and a CRLF", '<a>\r\r\n\r</a>')
add("a-chr-crlf-comment", "2.11", "CRLF in a comment", '<a><!--x\r\ny--></a>')
add("a-chr-crlf-pi", "2.11", "CRLF in PI data", '<a><?p x\r\ny?></a>')
add("a-chr-crlf-cdata", "2.11", "CRLF in a CDATA section", '<a><![CDATA[x\r\ny]]></a>')
add("a-chr-crlf-attr", "2.11 3.3.3", "CRLF in an attribute value is one space", '<a b="x\r\ny"/>')
add("a-chr-cr-attr", "3.3.3", "lone CR in an attribute value", '<a b="x\ry"/>')
add("a-chr-tab-attr", "3.3.3", "tab in an attribute value becomes a space", '<a b="x\ty"/>')
add("a-chr-nl-attr", "3.3.3", "newline in an attribute value becomes a space", '<a b="x\ny"/>')
add("a-chr-ws-attr", "3.3.3", "runs of white space in a CDATA attribute are kept", '<a b="  x \t\n y  "/>')
add("a-chr-latin", "2.2 [2]", "Latin-1 supplement letters", '<a>\u00e9\u00fc\u00f1</a>')
add("a-chr-cjk", "2.2 [2]", "CJK text", '<a>\u6c34\u706b\u6728</a>')
add("a-chr-astral", "2.2 [2]", "characters above U+FFFF", '<a>\U00010151\U0001f600\U0010fffd</a>')
add("a-chr-edges", "2.2 [2]", "last char before a gap and first after", '<a>\ud7ff\ue000\ufffd</a>')
add("a-chr-del-c1", "2.2 [2]", "DEL and C1 controls are legal", '<a>\x7f\u0085\u009f</a>')
add("a-chr-nbsp", "2.2 [2]", "no-break space and BOM-like U+FEFF in content", '<a>\u00a0\ufeff</a>')
add("a-chr-lsep", "2.2 [2]", "U+2028 and U+2029 are plain characters", '<a>\u2028\u2029</a>')
add("a-chr-quote-in-text", "2.4 [14]", "quotes and > in text", '<a>"\'>></a>')
add("a-chr-gt-alone", "2.4 [14]", "a bare > in text", '<a>1 > 0</a>')
add("a-chr-rb", "2.4 [14]", "single and double ] in text", '<a>]x]]y]</a>')
add("a-chr-rb-gt", "2.4 [14]", "] and > not adjacent", '<a>] ></a>')
add("a-text-mixed", "3.1", "mixed content with children", '<a>one<b>two</b>three<c/>four</a>')
add("a-text-empty-pair", "3.1", "empty content, nested empties", '<a><b></b><c/></a>')
add("a-text-deep", "3.1", "50 levels of nesting", "<a>" * 50 + "x" + "</a>" * 50)
add("a-text-wide", "3.1", "200 siblings", "<r>" + "<c/>" * 200 + "</r>")
add("a-text-long", "2.4 [14]", "20000 bytes of text", "<a>" + "abcdefghij" * 2000 + "</a>")
add("a-text-ws-between", "3.1", "white space between elements is kept", '<a> <b/> \n <c/> </a>')

# Names (2.3 productions 4-5)
add("a-name-underscore", "2.3 [5]", "name starting with _", '<_a/>')
add("a-name-colon-less", "2.3 [4]", "digits, hyphen, dot and underscore inside", '<a1-b.c_d/>')
add("a-name-latin", "2.3 [4]", "Latin-1 letters in a name", '<\u00e9l\u00e9ment/>')
add("a-name-cjk", "2.3 [4]", "CJK letters in a name", '<\u6c34\u706b/>')
add("a-name-greek-cyr", "2.3 [4]", "Greek and Cyrillic letters in a name", '<\u03b1\u0431/>')
add("a-name-middot", "2.3 [4]", "U+00B7 inside a name", '<a\u00b7b/>')
add("a-name-combining", "2.3 [4]", "combining mark inside a name", '<a\u0301/>')
add("a-name-digit-ar", "2.3 [4]", "non-ASCII digit inside a name", '<a\u0661/>')
add("a-name-astral", "2.3 [4]", "astral letter in a name", '<a\U00010400/>')
add("a-name-astral-start", "2.3 [5]", "astral letter starting a name", '<\U00010400a/>')
add("a-name-long", "2.3 [5]", "a 1000-byte name", '<' + 'n' * 1000 + '/>')
add("a-name-attr-unicode", "2.3 [5]", "non-ASCII attribute names", '<a \u00e9="1" \u6c34="2"/>')
add("a-name-case", "2.3 [5]", "names differing only in case are different", '<a><A/><a/></a>')
add("a-name-fffd", "2.3 [4]", "U+FFFD is a legal name character (5th edition)", '<a\ufffdb/>')
add("a-name-xml-prefix", "2.3", "a name beginning with xml but not a PI target", '<xmlish xmlfoo="1"/>')

# Attributes (3.1, 3.3.3)
add("a-at-one", "3.1 [41]", "one attribute", '<a b="1"/>')
add("a-at-single", "3.1 [41]", "single-quoted value", "<a b='1'/>")
add("a-at-empty", "3.1 [10]", "empty value", '<a b=""/>')
add("a-at-empty-single", "3.1 [10]", "empty single-quoted value", "<a b=''/>")
add("a-at-eq-space", "3.1 [25]", "spaces around =", '<a b = "1" c\t=\n"2"/>')
add("a-at-two-quotes", "3.1 [10]", "one of each quote style", "<a b=\"1\" c='2'/>")
add("a-at-q-in-q", "3.1 [10]", "other quote inside a value", "<a b=\"it's\" c='say \"x\"'/>")
add("a-at-gt", "3.1 [10]", "> inside a value", '<a b="1 > 0"/>')
add("a-at-rb", "3.1 [10]", "]]> inside a value", '<a b="x]]>y"/>')
add("a-at-ref-predef", "4.6", "all five predefined entities in a value", '<a b="&lt;&gt;&amp;&quot;&apos;"/>')
add("a-at-ref-char", "4.1 [66]", "character references in a value", '<a b="&#65;&#x42;&#x63;"/>')
add("a-at-ref-ws", "3.3.3", "white space references are kept as written", '<a b="x&#9;&#10;&#13;y"/>')
add("a-at-ref-space", "3.3.3", "&#32; is a space", '<a b="&#32;"/>')
add("a-at-many", "3.1 [40]", "30 attributes", '<a ' + ' '.join('a%d="%d"' % (i, i) for i in range(30)) + '/>')
add("a-at-space-end", "3.1 [40]", "white space before > and />", '<a b="1" ></a>')
add("a-at-space-selfclose", "3.1 [44]", "white space before />", '<a b="1" />')
add("a-at-newline-between", "3.1 [40]", "attributes on separate lines", '<a\n  b="1"\n  c="2"\n/>')
add("a-at-order", "3.1", "attribute order does not matter for the infoset", '<a z="1" y="2" x="3"/>')
add("a-at-same-name-other-el", "3.1", "same attribute name on different elements", '<a b="1"><c b="2"/></a>')
add("a-at-long", "3.1 [10]", "a 10000-byte value", '<a b="' + 'x' * 10000 + '"/>')
add("a-at-unicode", "3.1 [10]", "non-ASCII value", '<a b="\u00e9\u6c34\U00010151"/>')
add("a-at-xml-lang", "2.12", "xml:lang on the root", '<a xml:lang="en-GB"/>')
add("a-at-xml-lang-empty", "2.12", "xml:lang with an empty value", '<a xml:lang=""/>')
add("a-at-xml-space", "2.10", "xml:space values", '<a xml:space="preserve"><b xml:space="default"/></a>')
add("a-at-xml-base", "NS 1.0", "xml:base is just another xml: attribute", '<a xml:base="http://example.org/"/>')
add("a-at-xml-bound", "NS 1.0", "xml prefix declared with its own namespace", '<a xmlns:xml="http://www.w3.org/XML/1998/namespace" xml:lang="x"/>')

# Comments, PIs, CDATA (2.5-2.7)
add("a-cm-empty", "2.5 [15]", "empty comment", '<a><!----></a>')
add("a-cm-text", "2.5 [15]", "comment with text", '<a><!-- hello --></a>')
add("a-cm-one-dash", "2.5 [15]", "single dashes inside a comment", '<a><!-- a-b - c --></a>')
add("a-cm-dash-end", "2.5 [15]", "dash before the closing --> needs a space", '<a><!-- x - --></a>')
add("a-cm-markup", "2.5 [15]", "markup characters inside a comment", '<a><!-- <b>&amp; ]]> <![CDATA[ --></a>')
add("a-cm-multiline", "2.5 [15]", "multi-line comment", '<a><!--\nline1\n  line2\n--></a>')
add("a-cm-adjacent", "2.5 [15]", "adjacent comments", '<a><!--1--><!--2--><!--3--></a>')
add("a-cm-unicode", "2.5 [15]", "non-ASCII comment", '<a><!--\u00e9\u6c34\U00010151--></a>')
add("a-cm-between", "2.5 [15]", "comments between text runs", '<a>x<!--c-->y</a>')
add("a-cm-long", "2.5 [15]", "a 10000-byte comment", '<a><!--' + 'z' * 10000 + '--></a>')
add("a-pi-target-only", "2.6 [16]", "PI with a target and nothing else", '<a><?p?></a>')
add("a-pi-target-space", "2.6 [16]", "PI with a target and one space", '<a><?p ?></a>')
add("a-pi-data", "2.6 [16]", "PI with data", '<a><?p some data?></a>')
add("a-pi-data-q", "2.6 [16]", "? and > separately inside PI data", '<a><?p a?b>c?></a>')
add("a-pi-data-lt", "2.6 [16]", "markup characters in PI data", '<a><?p <b>&amp;]]> ?></a>')
add("a-pi-leading-ws", "2.6 [16]", "leading white space after the target is dropped", '<a><?p \t\n data?></a>')
add("a-pi-trailing-ws", "2.6 [16]", "trailing white space in PI data is kept", '<a><?p data   ?></a>')
add("a-pi-stylesheet", "2.6 [17]", "xml-stylesheet style target", '<?xml-stylesheet type="text/xsl" href="s.xsl"?><a/>')
add("a-pi-xmlfoo", "2.6 [17]", "target that merely starts with xml", '<a><?xmlfoo bar?><?xm x?><?x-ml y?></a>')
add("a-pi-unicode-target", "2.6 [17]", "non-ASCII PI target", '<a><?\u00e9\u6c34 d?></a>')
add("a-pi-between", "2.6 [16]", "PIs between text runs", '<a>x<?p d?>y<?q?>z</a>')
add("a-cd-empty", "2.7 [20]", "empty CDATA section", '<a><![CDATA[]]></a>')
add("a-cd-text", "2.7 [20]", "CDATA section with text", '<a><![CDATA[hello]]></a>')
add("a-cd-markup", "2.7 [20]", "markup characters in CDATA", '<a><![CDATA[<b>&amp;"\']]></a>')
add("a-cd-brackets", "2.7 [21]", "] and ]] and ]> inside CDATA", '<a><![CDATA[a]b]]c]>d]]></a>')
add("a-cd-end-split", "2.7 [21]", "]]> split across two sections", '<a><![CDATA[]]]]><![CDATA[>]]></a>')
add("a-cd-bracket-end", "2.7 [21]", "a section ending in ]", '<a><![CDATA[x]]]></a>')
add("a-cd-adjacent", "2.7 [18]", "adjacent sections", '<a><![CDATA[1]]><![CDATA[2]]></a>')
add("a-cd-mixed", "2.7 [18]", "CDATA between text and a child", '<a>x<![CDATA[y]]>z<b/><![CDATA[w]]></a>')
add("a-cd-ws", "2.7 [18]", "white space only", '<a><![CDATA[ \t\n ]]></a>')
add("a-cd-unicode", "2.7 [18]", "non-ASCII text", '<a><![CDATA[\u00e9\u6c34\U00010151]]></a>')
add("a-cd-long", "2.7 [18]", "a 10000-byte section", '<a><![CDATA[' + 'q' * 10000 + ']]></a>')
add("a-cd-cr", "2.11", "CR line ends in CDATA", '<a><![CDATA[a\rb\r\nc]]></a>')

# References (4.1, 4.6)
add("a-ref-predef", "4.6", "the five predefined entities in content", '<a>&lt;&gt;&amp;&quot;&apos;</a>')
add("a-ref-predef-adjacent", "4.6", "predefined entities with no text between", '<a>&amp;&amp;&amp;</a>')
add("a-ref-predef-text", "4.6", "predefined entities amid text", '<a>1 &lt; 2 &amp;&amp; 3 &gt; 2</a>')
add("a-ref-dec", "4.1 [66]", "decimal character reference", '<a>&#65;&#97;&#48;</a>')
add("a-ref-hex", "4.1 [66]", "hexadecimal character references", '<a>&#x41;&#x61;&#x7A;</a>')
add("a-ref-hex-case", "4.1 [66]", "upper and lower case hex digits", '<a>&#xAb;&#xaB;&#xFF;&#xff;</a>')
add("a-ref-leading-zeros", "4.1 [66]", "leading zeros in references", '<a>&#0065;&#x0041;&#x000000000000041;</a>')
add("a-ref-ws", "4.1 [66]", "references to the white space characters", '<a>&#9;&#10;&#13;&#32;</a>')
add("a-ref-hex-ws", "4.1 [66]", "hex references to white space", '<a>&#x9;&#xA;&#xD;&#x20;</a>')
add("a-ref-lt-char", "4.1 [66]", "&#60; is a literal < in the infoset, not markup", '<a>&#60;b&#62;&#38;</a>')
add("a-ref-amp-char", "4.1 [66]", "&#38; yields a plain &, not a reference", '<a>&#38;lt;</a>')
add("a-ref-bmp-edges", "4.1 [66]", "references at BMP range edges", '<a>&#xD7FF;&#xE000;&#xFFFD;</a>')
add("a-ref-astral", "4.1 [66]", "references above U+FFFF", '<a>&#x10000;&#x1F600;&#x10FFFF;</a>')
add("a-ref-astral-dec", "4.1 [66]", "decimal reference above U+FFFF", '<a>&#65536;&#1114111;</a>')
add("a-ref-del-c1", "4.1 [66]", "DEL and C1 by reference", '<a>&#127;&#133;&#x9F;</a>')
add("a-ref-name-chars", "4.1 [68]", "references between elements", '<a><b/>&#65;<c/>&amp;</a>')
add("a-ref-cdata-no-ref", "2.7", "references are literal inside CDATA", '<a><![CDATA[&amp;&#65;&nope;]]></a>')
add("a-ref-comment-no-ref", "2.5", "references are literal inside a comment", '<a><!-- &nope; &#0; --></a>')
add("a-ref-pi-no-ref", "2.6", "references are literal inside PI data", '<a><?p &nope; &#0;?></a>')
add("a-ref-attr-mixed", "3.3.3", "text and references mixed in a value", '<a b="x&amp;y&#65;z&lt;"/>')

# Namespaces in XML 1.0
add("a-ns-default", "NS 1.0 [5]", "default namespace", '<a xmlns="urn:x"/>')
add("a-ns-default-child", "NS 1.0 [5]", "default namespace is inherited", '<a xmlns="urn:x"><b><c/></b></a>')
add("a-ns-prefix", "NS 1.0 [4]", "prefixed namespace", '<p:a xmlns:p="urn:x"/>')
add("a-ns-prefix-child", "NS 1.0 [4]", "prefix inherited by children", '<p:a xmlns:p="urn:x"><p:b><p:c/></p:b></p:a>')
add("a-ns-prefix-attr", "NS 1.0 [4]", "prefixed attribute", '<a xmlns:p="urn:x" p:b="1"/>')
add("a-ns-attr-no-default", "NS 1.0 6.2", "the default namespace does not apply to attributes", '<a xmlns="urn:x" b="1"/>')
add("a-ns-override", "NS 1.0 6.1", "prefix rebound in a child", '<p:a xmlns:p="urn:x"><p:b xmlns:p="urn:y"><p:c/></p:b><p:d/></p:a>')
add("a-ns-default-override", "NS 1.0 6.1", "default namespace rebound in a child", '<a xmlns="urn:x"><b xmlns="urn:y"><c/></b><d/></a>')
add("a-ns-default-undeclare", "NS 1.0 6.2", "xmlns=\"\" undeclares the default", '<a xmlns="urn:x"><b xmlns=""><c/></b></a>')
add("a-ns-two-prefixes", "NS 1.0 [4]", "two prefixes", '<p:a xmlns:p="urn:x" xmlns:q="urn:y"><q:b/><p:c/></p:a>')
add("a-ns-same-uri-two-prefixes", "NS 1.0 6.3", "two prefixes for one namespace, different locals", '<a xmlns:p="urn:x" xmlns:q="urn:x" p:b="1" q:c="2"/>')
add("a-ns-same-local-two-ns", "NS 1.0 6.3", "same local name in two namespaces", '<a xmlns:p="urn:x" xmlns:q="urn:y" p:b="1" q:b="2"/>')
add("a-ns-attr-same-local-no-ns", "NS 1.0 6.3", "unprefixed and prefixed attribute with one local name", '<a xmlns:p="urn:x" b="1" p:b="2"/>')
add("a-ns-decl-order", "NS 1.0", "declaration after its use on the same tag", '<p:a p:b="1" xmlns:p="urn:x"/>')
add("a-ns-prefix-shadow-default", "NS 1.0", "a prefix and the default bound to one URI", '<a xmlns="urn:x" xmlns:p="urn:x"><p:b/><c/></a>')
add("a-ns-uri-relative", "NS 1.0 [1]", "relative reference as a namespace name", '<a xmlns="relative/path"/>')
add("a-ns-uri-fragment", "NS 1.0 [1]", "namespace name with a fragment", '<a xmlns="http://example.org/x#frag"/>')
add("a-ns-uri-case", "NS 1.0 [1]", "namespace names differing in case are different", '<a xmlns:p="urn:X" xmlns:q="urn:x"><p:b/><q:b/></a>')
add("a-ns-uri-escaped", "NS 1.0 [1]", "namespace names differing in escaping are different", '<a xmlns:p="urn:%41" xmlns:q="urn:A"><p:b/><q:b/></a>')
add("a-ns-uri-entity", "NS 1.0 [1]", "predefined entity in a namespace name", '<a xmlns="urn:x&amp;y"/>')
add("a-ns-uri-weird", "NS 1.0 [1]", "an odd scheme as a namespace name", '<a xmlns="foo:bar:baz?q#r"/>')
add("a-ns-uri-empty-prefix-ok", "NS 1.0", "empty default undeclared twice", '<a xmlns=""><b xmlns=""/></a>')
add("a-ns-prefix-xmlns-like", "NS 1.0", "prefixes that merely resemble xml/xmlns", '<a xmlns:xmlx="urn:x" xmlns:xmln="urn:y" xmlns:xm="urn:z"><xmlx:b/><xmln:c/><xm:d/></a>')
add("a-ns-prefix-long", "NS 1.0 [7]", "a long prefix and local name", '<%s:%s xmlns:%s="urn:x"/>' % ('p' * 200, 'l' * 200, 'p' * 200))
add("a-ns-prefix-unicode", "NS 1.0 [7]", "non-ASCII prefix", '<\u00e9:a xmlns:\u00e9="urn:x"/>')
add("a-ns-pi-no-colon", "NS 1.0", "PI target without a colon", '<a xmlns:p="urn:x"><?p d?></a>')
add("a-ns-comment-prefix", "NS 1.0", "xmlns text inside a comment is not a declaration", '<a><!-- xmlns:p="urn:x" --></a>')
add("a-ns-many-decls", "NS 1.0", "20 declarations on one element", '<a ' + ' '.join('xmlns:p%d="urn:%d"' % (i, i) for i in range(20)) + '><p19:b/></a>')
add("a-ns-deep-chain", "NS 1.0 6.1", "prefix declared at the root, used 30 levels down", '<p:a xmlns:p="urn:x">' + '<p:b>' * 30 + '</p:b>' * 30 + '</p:a>')

# DOCTYPE with a no-op subset (Options.doctype = .ignore), 2.8 productions 28-30
add("a-dt-bare", "2.8 [28]", "DOCTYPE with only a name", '<!DOCTYPE a><a/>')
add("a-dt-space", "2.8 [28]", "white space inside the DOCTYPE", '<!DOCTYPE   a  ><a/>')
add("a-dt-newline", "2.8 [28]", "newlines inside the DOCTYPE", '<!DOCTYPE\na\n><a/>')
add("a-dt-system", "2.8 [75]", "external subset by SYSTEM id (never read)", '<!DOCTYPE a SYSTEM "a.dtd"><a/>')
add("a-dt-system-single", "2.8 [75]", "SYSTEM id in single quotes", "<!DOCTYPE a SYSTEM 'a.dtd'><a/>")
add("a-dt-public", "2.8 [75]", "external subset by PUBLIC id (never read)", '<!DOCTYPE a PUBLIC "-//X//DTD A//EN" "a.dtd"><a/>')
add("a-dt-empty-subset", "2.8 [28]", "empty internal subset", '<!DOCTYPE a []><a/>')
add("a-dt-subset-space", "2.8 [28]", "white space in the internal subset", '<!DOCTYPE a [ \n\t ]><a/>')
add("a-dt-element", "3.2 [45]", "ELEMENT declarations", '<!DOCTYPE a [<!ELEMENT a (b|c)*><!ELEMENT b EMPTY><!ELEMENT c (#PCDATA)>]><a><b/><c>x</c></a>')
add("a-dt-element-any", "3.2 [46]", "ELEMENT with ANY", '<!DOCTYPE a [<!ELEMENT a ANY>]><a>x<b/></a>')
add("a-dt-element-mixed", "3.2.2 [51]", "mixed content model", '<!DOCTYPE a [<!ELEMENT a (#PCDATA|b|c)*><!ELEMENT b EMPTY><!ELEMENT c EMPTY>]><a>x<b/>y<c/></a>')
add("a-dt-element-seq", "3.2.1 [49]", "sequence and choice particles", '<!DOCTYPE a [<!ELEMENT a (b,(c|d)+,e?)><!ELEMENT b EMPTY><!ELEMENT c EMPTY><!ELEMENT d EMPTY><!ELEMENT e EMPTY>]><a><b/><c/><d/></a>')
add("a-dt-attlist", "3.3 [52]", "ATTLIST with CDATA and #IMPLIED", '<!DOCTYPE a [<!ELEMENT a ANY><!ATTLIST a b CDATA #IMPLIED>]><a b="1"/>')
add("a-dt-attlist-types", "3.3.1 [54]", "tokenized and enumerated attribute types", '<!DOCTYPE a [<!ELEMENT a ANY><!ATTLIST a i ID #IMPLIED r IDREF #IMPLIED n NMTOKEN #IMPLIED e (x|y|z) #IMPLIED>]><a n="t"/>')
add("a-dt-attlist-required", "3.3.2 [60]", "#REQUIRED attribute that is present", '<!DOCTYPE a [<!ELEMENT a ANY><!ATTLIST a b CDATA #REQUIRED>]><a b="1"/>')
add("a-dt-notation", "4.7 [82]", "NOTATION declaration", '<!DOCTYPE a [<!NOTATION n SYSTEM "n.exe">]><a/>')
add("a-dt-notation-public", "4.7 [83]", "NOTATION with a PUBLIC id", '<!DOCTYPE a [<!NOTATION n PUBLIC "-//X//N//EN">]><a/>')
add("a-dt-comment", "2.5 [15]", "comment in the internal subset", '<!DOCTYPE a [<!-- note -->]><a/>')
add("a-dt-comment-brackets", "2.5 [15]", "] and > inside a subset comment", '<!DOCTYPE a [<!-- ] > ]> -->]><a/>')
add("a-dt-pi", "2.6 [16]", "PI in the internal subset", '<!DOCTYPE a [<?p d?>]><a/>')
add("a-dt-quote-bracket", "2.3 [11]", "] and > inside a quoted literal in the subset", '<!DOCTYPE a [<!ENTITY % e "x]>y"><!ELEMENT a ANY>]><a/>'.replace('<!ENTITY % e "x]>y">', '<!NOTATION n SYSTEM "a]b>c">'))
add("a-dt-before-comment", "2.8 [22]", "comment before and after the DOCTYPE", '<!-- 1 --><!DOCTYPE a><!-- 2 --><a/>')
add("a-dt-decl-before", "2.8 [22]", "XMLDecl, DOCTYPE, comment, PI, root", '<?xml version="1.0"?>\n<!DOCTYPE a [<!ELEMENT a EMPTY>]>\n<!-- c -->\n<?p q?>\n<a/>')
add("a-dt-name-colon", "2.8 [28]", "DOCTYPE name with a prefix", '<!DOCTYPE p:a><p:a xmlns:p="urn:x"/>')
add("a-dt-ns-root", "2.8 [28]", "DOCTYPE with a namespaced root", '<!DOCTYPE a [<!ATTLIST a xmlns CDATA #IMPLIED>]><a xmlns="urn:x"/>')
add("a-dt-content", "2.8", "document content after a DOCTYPE", '<!DOCTYPE a><a b="1">text<c/><!-- x --><?p q?><![CDATA[<>]]>&amp;&#65;</a>')

# General entities, Options.doctype = .internal_entities (4.1-4.5)
ent("e-text", "4.2 [71]", "internal entity in content", '<!DOCTYPE a [<!ENTITY e "hello">]><a>&e;</a>')
ent("e-attr", "4.4.5 [71]", "internal entity in an attribute value", '<!DOCTYPE a [<!ENTITY e "hello">]><a b="&e;"/>')
ent("e-both", "4.4", "internal entity in text and attribute", '<!DOCTYPE a [<!ENTITY e "v">]><a b="[&e;]">[&e;]</a>')
ent("e-repeat", "4.4", "the same entity three times", '<!DOCTYPE a [<!ENTITY e "ab">]><a>&e;&e;&e;</a>')
ent("e-empty", "4.2", "entity with an empty replacement", '<!DOCTYPE a [<!ENTITY e "">]><a>x&e;y</a>')
ent("e-single-quote", "4.2 [9]", "entity value in single quotes", "<!DOCTYPE a [<!ENTITY e 'it\"s'>]><a>&e;</a>")
ent("e-quote-inside", "4.2 [9]", "other quote inside the value", '<!DOCTYPE a [<!ENTITY e "it\'s">]><a>&e;</a>')
ent("e-nested", "4.4", "entity referring to another entity", '<!DOCTYPE a [<!ENTITY x "X"><!ENTITY y "[&x;&x;]">]><a>&y;</a>')
ent("e-nested-order", "4.4", "reference to an entity declared later", '<!DOCTYPE a [<!ENTITY y "[&x;]"><!ENTITY x "X">]><a>&y;</a>')
ent("e-chain", "4.4", "a chain of five", '<!DOCTYPE a [<!ENTITY e1 "v"><!ENTITY e2 "&e1;&e1;"><!ENTITY e3 "&e2;&e2;"><!ENTITY e4 "&e3;&e3;"><!ENTITY e5 "&e4;&e4;">]><a>&e5;</a>')
ent("e-charref-in-value", "4.5", "character reference in the replacement text", '<!DOCTYPE a [<!ENTITY e "A&#66;C">]><a>&e;</a>')
ent("e-charref-hex", "4.5", "hex character reference in the replacement", '<!DOCTYPE a [<!ENTITY e "&#x48;&#x49;">]><a>&e;</a>')
ent("e-charref-amp", "4.5", "&#38;#60; is double-escaped", '<!DOCTYPE a [<!ENTITY e "&#38;#60;">]><a>&e;</a>')
ent("e-charref-ws-attr", "3.3.3", "white space character references through an entity in an attribute", '<!DOCTYPE a [<!ENTITY e "x&#9;&#10;y">]><a b="&e;"/>')
ent("e-predef-in-value", "4.6", "predefined entities in the replacement text", '<!DOCTYPE a [<!ENTITY e "&lt;&amp;&gt;">]><a>&e;</a>')
ent("e-predef-in-attr", "4.6", "predefined entities through an entity in an attribute", '<!DOCTYPE a [<!ENTITY e "&lt;b&gt;">]><a b="&e;"/>')
ent("e-ws-value", "4.2", "white space in the replacement text", '<!DOCTYPE a [<!ENTITY e "  a\tb  ">]><a>&e;</a>')
ent("e-nl-attr", "3.3.3", "newline in the replacement of an attribute use", '<!DOCTYPE a [<!ENTITY e "x\ny">]><a b="&e;"/>')
ent("e-unicode", "4.2", "non-ASCII replacement text", '<!DOCTYPE a [<!ENTITY e "\u00e9\u6c34\U00010151">]><a>&e;</a>')
ent("e-first-wins", "4.2", "the first declaration binds", '<!DOCTYPE a [<!ENTITY e "1"><!ENTITY e "2">]><a>&e;</a>')
ent("e-predef-redeclared", "4.6", "predefined entity redeclared as itself", '<!DOCTYPE a [<!ENTITY lt "&#38;#60;">]><a>&lt;</a>')
ent("e-unused", "4.2", "declared and never used", '<!DOCTYPE a [<!ENTITY e "v">]><a>x</a>')
ent("e-many", "4.2", "ten entities in one subset", '<!DOCTYPE a [' + ''.join('<!ENTITY e%d "v%d">' % (i, i) for i in range(10)) + ']><a>&e0;&e5;&e9;</a>')
ent("e-with-decls", "4.2", "entity among other declarations", '<!DOCTYPE a [<!ELEMENT a ANY><!ATTLIST a b CDATA #IMPLIED><!-- c --><?p q?><!ENTITY e "v">]><a>&e;</a>')
ent("e-between-elements", "4.4", "entity between child elements", '<!DOCTYPE a [<!ENTITY e "t">]><a><b/>&e;<c/>&e;</a>')
ent("e-in-nested-attr", "4.4.5", "entity in an attribute of a deep child", '<!DOCTYPE a [<!ENTITY e "v">]><a><b><c d="&e;"/></b></a>')
ent("e-ns-value", "NS 1.0", "entity as a namespace name", '<!DOCTYPE a [<!ENTITY u "urn:x">]><a xmlns="&u;"/>')
ent("e-ws-around-decl", "4.2 [70]", "white space around the declaration pieces", '<!DOCTYPE a [<!ENTITY   e   "v"   >]><a>&e;</a>')
ent("e-newline-decl", "4.2 [70]", "newlines inside the declaration", '<!DOCTYPE a [<!ENTITY\ne\n"v"\n>]><a>&e;</a>')
ent("e-cr-in-value", "2.11", "CRLF inside the entity value literal", '<!DOCTYPE a [<!ENTITY e "x\r\ny">]><a>&e;</a>')
ent("e-long", "4.2", "a 5000-byte replacement text", '<!DOCTYPE a [<!ENTITY e "' + 'w' * 5000 + '">]><a>&e;</a>')
ent("e-amp-in-text", "4.1", "text, predefined and declared entities together", '<!DOCTYPE a [<!ENTITY e "E">]><a>a&amp;b&e;c&lt;d</a>')
# Entity-related rejects
ent("er-charref-lt", "4.5", "&#60; in the value becomes markup when the entity is used", '<!DOCTYPE a [<!ENTITY e "1&#60;2">]><a>&e;</a>')
ent("er-undefined", "4.1 WFC", "undeclared entity with a DOCTYPE present", '<!DOCTYPE a [<!ENTITY e "v">]><a>&f;</a>')
ent("er-loop", "4.1 WFC", "entities referring to each other", '<!DOCTYPE a [<!ENTITY x "&y;"><!ENTITY y "&x;">]><a>&x;</a>')
ent("er-self", "4.1 WFC", "entity referring to itself", '<!DOCTYPE a [<!ENTITY x "a&x;b">]><a>&x;</a>')
ent("er-lt-attr", "3.1 WFC", "entity whose text is < used in an attribute", '<!DOCTYPE a [<!ENTITY m "&#60;">]><a b="&m;"/>')
ent("er-bad-charref-value", "4.1 WFC", "illegal character reference in the replacement text", '<!DOCTYPE a [<!ENTITY e "&#0;">]><a>&e;</a>')
ent("er-bad-charref-value2", "4.1 WFC", "&#xFFFE; in the replacement text", '<!DOCTYPE a [<!ENTITY e "&#xFFFE;">]><a>&e;</a>')
ent("er-undefined-in-value", "4.1 WFC", "replacement text references an undeclared entity", '<!DOCTYPE a [<!ENTITY e "&nope;">]><a>&e;</a>')
ent("er-bad-text-in-value", "4.3.2", "replacement text with an unbalanced tag", '<!DOCTYPE a [<!ENTITY e "<b>">]><a>&e;</a>')
ent("er-value-unterminated", "4.2 [9]", "entity value literal never closed", '<!DOCTYPE a [<!ENTITY e "v>]><a/>')
ent("er-value-mixed-quotes", "4.2 [9]", "entity value opened with \" closed with '", "<!DOCTYPE a [<!ENTITY e \"v'>]><a/>")
ent("er-no-name", "4.2 [71]", "ENTITY declaration without a name", '<!DOCTYPE a [<!ENTITY "v">]><a/>')
ent("er-no-value", "4.2 [71]", "ENTITY declaration without a value", '<!DOCTYPE a [<!ENTITY e>]><a/>')
ent("er-amp-in-value", "4.1", "bare & in the entity value", '<!DOCTYPE a [<!ENTITY e "a & b">]><a>&e;</a>')
ent("er-subset-unterminated", "2.8 [28]", "internal subset never closed", '<!DOCTYPE a [<!ENTITY e "v"><a/>')
ent("er-decl-lowercase", "4.2 [71]", "lowercase entity keyword", '<!DOCTYPE a [<!entity e "v">]><a>&e;</a>')
ent("er-bad-char-after", "2.2 [2]", "control character in content after the DOCTYPE", b'<!DOCTYPE a [<!ENTITY e "v">]><a>\x01</a>')
ent("er-bad-char-in-value", "2.2 [2]", "control character in an entity value", b'<!DOCTYPE a [<!ENTITY e "\x01">]><a>&e;</a>')
ent("er-decl-after-root", "2.8", "entity used before the DOCTYPE declares it", '<a>&e;</a>')

# --------------------------------------------------------------------------

ids = [c[0] for c in cases]
assert len(ids) == len(set(ids)), [i for i in ids if ids.count(i) > 1]


def zstr(b):
    out = []
    for c in b:
        if c == 0x22:
            out.append('\\"')
        elif c == 0x5c:
            out.append('\\\\')
        elif c == 0x0a:
            out.append('\\n')
        elif 0x20 <= c < 0x7f:
            out.append(chr(c))
        else:
            out.append('\\x%02x' % c)
    return '"' + ''.join(out) + '"'


def qs(s):
    return zstr(s.encode("utf-8"))


results = []
for cid, sec, desc, data, mode in cases:
    o = oracle(data, mode == "entities")
    results.append((cid, sec, desc, data, mode, o, OURS.get(cid)))

if len(sys.argv) > 2 and sys.argv[1] == "--files":
    import os
    d = sys.argv[2]
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "index.tsv"), "w") as ix:
        for cid, sec, desc, data, mode, o, ours in results:
            with open(os.path.join(d, cid + ".xml"), "wb") as f:
                f.write(data)
            ix.write("%s\t%s\t%s\t%s\n" % (cid, mode, "ERR" if o is None else "OK", ours or "-"))
    sys.exit(0)

print("// SPDX-License-Identifier: MIT")
print("//! GENERATED by tools/gen_wf_vectors.py (libxml2 via lxml as a black-box oracle) -- do not edit.")
print("//! Every input is this module's own; only the verdicts come from libxml2.")
print("pub const Mode = enum { none, ignore, entities };")
print("pub const Case = struct {")
print("    id: []const u8,")
print("    sections: []const u8,")
print("    desc: []const u8,")
print("    input: []const u8,")
print("    mode: Mode,")
print("    /// null = libxml2 refused the document; else its DUMP (see gen_core_vectors.py).")
print("    lxml: ?[]const u8,")
print("    /// null = this module agrees; \"accept\" or an error name = a recorded deviation.")
print("    ours: ?[]const u8,")
print("};")
print("pub const cases = [_]Case{")
for cid, sec, desc, data, mode, o, ours in results:
    lx = "null" if o is None else '"%s"' % o
    ou = "null" if ours is None else '"%s"' % ours
    print("    .{ .id = %s, .sections = %s, .desc = %s, .input = %s, .mode = .%s, .lxml = %s, .ours = %s }," % (
        qs(cid), qs(sec), qs(desc), zstr(data), mode, lx, ou))
print("};")
