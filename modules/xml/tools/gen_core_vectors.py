#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for `src/core_vectors.zig`: libxml2, through lxml (BSD-3; libxml2
itself MIT), driven as a BLACK-BOX oracle on the 2026-10-04 additions --
non-UTF-8 input and internal DTD entities. Public API only
(`etree.fromstring` with an `XMLParser`); no source read.

Run:  python3 gen_core_vectors.py > ../src/core_vectors.zig && zig fmt ../src/core_vectors.zig

For each case the oracle's view of the document is written as a DUMP, a
format defined here and re-implemented by `core_test.zig`'s `dump`:
  element  <{uri}local + per attribute, sorted by (uri, local), ' {uri}local=HEX'
           + '>' + children + '</>'
  text     T[HEX]   (adjacent text and CDATA merged, as lxml merges them)
  comment  C[HEX]
  pi       P[target HEX]
HEX is the lowercase hex of the UTF-8 bytes, so nothing needs escaping.
`lxml = null` means libxml2 refused the document. `ours` names the error
this module returns where it is deliberately stricter than libxml2 (or where
no oracle run was made, e.g. an external entity libxml2 would try to load).
"""
from lxml import etree

def hx(s):
    return s.encode("utf-8").hex()

def dump_el(el):
    out = []
    tag = etree.QName(el)
    uri = tag.namespace or ""
    out.append("<{%s}%s" % (uri, tag.localname))
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
            # merge with a following text run
            if out[-1].startswith("T[") and False:
                pass
            out.append("T[%s]" % hx(c.tail))
    out.append("</>")
    return "".join(out)

def merge_text(d):
    # T[a]T[b] -> T[ab] (adjacent runs), the form core_test.zig produces
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
        root = etree.fromstring(data, p)
        return merge_text(dump_el(root))
    except (etree.XMLSyntaxError, ValueError):
        return None

bom16le = b"\xff\xfe"
bom16be = b"\xfe\xff"
def u16le(s): return s.encode("utf-16-le")
def u16be(s): return s.encode("utf-16-be")
doc_u = '<?xml version="1.0" encoding="UTF-16"?><r a="ü"><x>水 \U00010151</x><!--c--><?p d?></r>'
laughs = '<!DOCTYPE r [<!ENTITY a "aaaaaaaaaa">' + "".join(
    '<!ENTITY %s "%s">' % (chr(98 + i), ("&%s;" % chr(97 + i)) * 10) for i in range(9)) + ']><r>&j;</r>'

cases = [
    # (name, bytes, entities?, ours-error-or-None, run-oracle?)
    ("utf-16le with BOM and declaration", bom16le + u16le(doc_u), False, None, True),
    ("utf-16be with BOM, no declaration", bom16be + u16be('<r a="é">\U00010151</r>'), False, None, True),
    ("utf-16le without BOM (Appendix F)", u16le('<?xml version="1.0" encoding="UTF-16"?><r>x</r>'), False, None, True),
    ("utf-16be without BOM (Appendix F)", u16be('<?xml version="1.0" encoding="utf-16"?><r>y</r>'), False, None, True),
    ("iso-8859-1 declared", b'<?xml version="1.0" encoding="ISO-8859-1"?><r a="\xe9">\xfc\xff</r>', False, None, True),
    ("latin1 alias", b'<?xml version="1.0" encoding="latin1"?><r>\xe9</r>', False, None, True),
    ("us-ascii declared", b'<?xml version="1.0" encoding="US-ASCII"?><r>plain</r>', False, None, True),
    ("us-ascii declared, a byte >= 0x80", b'<?xml version="1.0" encoding="US-ASCII"?><r>\xe9</r>', False, "InvalidCharacter", True),
    ("utf-16 BOM, declaration says UTF-8", bom16le + u16le('<?xml version="1.0" encoding="UTF-8"?><r/>'), False, "UnsupportedEncoding", True),
    ("utf-16, odd byte count", bom16le + u16le("<r/>") + b"\x00", False, "InvalidCharacter", True),
    ("utf-16, unpaired surrogate", bom16le + u16le("<r>") + b"\x00\xd8" + u16le("</r>"), False, "InvalidCharacter", True),
    ("an encoding not supported here", b'<?xml version="1.0" encoding="Shift_JIS"?><r/>', False, "UnsupportedEncoding", True),
    ("entity in text and attribute", b'<!DOCTYPE r [<!ENTITY co "ACME &amp; Co">]><r a="&co;">&co; x</r>', True, None, True),
    ("nested entities", b'<!DOCTYPE r [<!ENTITY a "A"><!ENTITY b "&a;-&a;">]><r>&b;</r>', True, None, True),
    ("char ref in an entity value: tab kept in text, space in attribute", b'<!DOCTYPE r [<!ENTITY t "x&#9;y">]><r a="&t;">&t;</r>', True, None, True),
    ("double-escaped reference", b'<!DOCTYPE r [<!ENTITY l2 "&#38;#60;">]><r>&l2;</r>', True, None, True),
    ("first declaration binds", b'<!DOCTYPE r [<!ENTITY e "1"><!ENTITY e "2">]><r>&e;</r>', True, None, True),
    ("predefined entity redeclared", b'<!DOCTYPE r [<!ENTITY lt "&#38;#60;">]><r>&lt;</r>', True, None, True),
    ("other declarations skipped", b'<!DOCTYPE r [<!ELEMENT r (#PCDATA)><!ATTLIST r a CDATA "d"><!-- c --><?p q?><!ENTITY e "v">]><r>&e;</r>', True, None, True),
    ("undefined entity", b'<!DOCTYPE r [<!ENTITY e "v">]><r>&f;</r>', True, "UndefinedEntity", True),
    ("entity loop", b'<!DOCTYPE r [<!ENTITY a "&b;"><!ENTITY b "&a;">]><r>&a;</r>', True, "EntityLoop", True),
    ("billion laughs (10^10 bytes)", laughs.encode(), True, "EntityLimit", True),
    ("< in an entity used in an attribute", b'<!DOCTYPE r [<!ENTITY m "&#60;">]><r a="&m;"/>', True, "UnexpectedChar", True),
    ("markup in an entity (text-only here)", b'<!DOCTYPE r [<!ENTITY m "<b>x</b>">]><r>&m;</r>', True, "UnsupportedEntity", True),
    ("parameter entity reference", b'<!DOCTYPE r [<!ENTITY % p "x"> %p;]><r/>', True, "UnsupportedEntity", True),
    ("external entity: never read", b'<!DOCTYPE r [<!ENTITY x SYSTEM "file:///nonexistent/x">]><r>&x;</r>', True, "UnsupportedEntity", False),
    ("entity without DOCTYPE support (ignore policy)", b'<!DOCTYPE r [<!ENTITY e "v">]><r>&e;</r>', False, "UndefinedEntity", False),
]

print("// SPDX-License-Identifier: MIT")
print("//! GENERATED by tools/gen_core_vectors.py (libxml2 via lxml as a black-box oracle) -- do not edit.")
print("pub const Case = struct { name: []const u8, input: []const u8, entities: bool, lxml: ?[]const u8, ours: ?[]const u8 };")
print("pub const cases = [_]Case{")
for name, data, ent, ours, run in cases:
    o = oracle(data, ent) if run else None
    lx = "null" if o is None else '"%s"' % o
    ou = "null" if ours is None else '"%s"' % ours
    print('    .{ .name = "%s", .input = "%s", .entities = %s, .lxml = %s, .ours = %s },' % (
        name.replace('"', '\\"'), data.hex(), "true" if ent else "false", lx, ou))
print("};")
