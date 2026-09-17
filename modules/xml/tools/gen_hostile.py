#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate the hostile/differential XML corpus (60 documents).

WHY THIS EXISTS: `differ.sh` runs this module, libxml2 and expat over the same
documents and compares their verdicts. The documents have to come from
somewhere, and a corpus that exists only as files in a droppable cache is a
corpus that disappears. This is the corpus, as code.

⚠ EVERY DOCUMENT HERE IS DELIBERATE. The names encode what each one probes:
`xsw*` signature-wrapping shapes, `ent*`/`xxe*` entity and external-entity
attacks, `chr*` character and encoding edges, `crlf*` line-ending normalisation
per content kind (audit F3), `nam*` the Name grammar (audit F4), `pi*` the
processing-instruction / XML-declaration boundary (audit F7), `str*` structural
truncation. Several are now pinned by named tests in `src/root.zig`; they stay
here because the differential asks a question the tests cannot -- not "does the
module do X" but "do three independent implementations agree".

WHAT IT PRODUCES: `<out>/hostile/`, 60 files, ~12 KB.

    modules/xml/tools/gen_hostile.py [outdir]     # default: .zig-cache/xml-corpus
"""
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
repo = os.path.abspath(os.path.join(here, "..", "..", ".."))
out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(repo, ".zig-cache", "xml-corpus")
d = os.path.join(out, "hostile")
os.makedirs(d, exist_ok=True)


def w(n, b):
    with open(os.path.join(d, n), "wb") as f:
        f.write(b if isinstance(b, bytes) else b.encode("utf-8"))


# XSW / "two views of one document"
w('xsw01_dup_id.xml', '<r><a ID="x"/><b ID="x"/></r>')
w('xsw02_dup_id_case.xml', '<r><a ID="x"/><b Id="x"/></r>')
w('xsw03_prefixed_id.xml', '<r xmlns:s="urn:s"><a s:ID="x"/><b s:ID="x"/></r>')
w('xsw04_xmlid_dup.xml', '<r><a xml:id="x"/><b xml:id="x"/></r>')
w('xsw05_same_expanded_two_prefixes.xml', '<r xmlns:a="urn:x" xmlns:b="urn:x"><a:e ID="p"/><b:e ID="q"/></r>')
w('xsw06_dup_attr_two_prefixes.xml', '<r xmlns:a="urn:x" xmlns:b="urn:x"><e a:v="1" b:v="2"/></r>')
w('xsw07_default_ns_redefined.xml', '<r xmlns="urn:a"><c xmlns="urn:b"><d/></c></r>')
w('xsw08_prefix_rebound.xml', '<r xmlns:p="urn:a"><p:e/><m xmlns:p="urn:b"><p:e/></m></r>')
w('xsw09_undeclared_prefix.xml', '<r><p:e/></r>')
w('xsw10_xmlns_empty.xml', '<r xmlns="urn:a"><c xmlns=""><d/></c></r>')
w('xsw11_xmlns_prefix_empty.xml', '<r xmlns:p="urn:a"><c xmlns:p=""><p:d/></c></r>')
w('xsw12_id_in_comment_ns.xml', '<r xmlns:xsi="urn:s"><a ID="x"/><!--<b ID="x"/>--></r>')

# entities / XXE
w('ent01_billion.xml', '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>')
w('ent02_quadratic.xml', '<!DOCTYPE b [<!ENTITY a "' + ('A' * 5000) + '">]><b>' + ('&a;' * 5000) + '</b>')
w('ent03_undefined.xml', '<r>&foo;</r>')
w('ent04_predef_only.xml', '<r>&lt;&gt;&amp;&apos;&quot;</r>')
w('xxe01_file.xml', '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>')
w('xxe02_http.xml', '<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://127.0.0.1:48231/x">]><r>&xxe;</r>')
w('xxe03_ext_subset.xml', '<!DOCTYPE r SYSTEM "http://127.0.0.1:48231/dtd"><r/>')
w('xxe04_param_entity.xml', '<!DOCTYPE r [<!ENTITY % pe SYSTEM "http://127.0.0.1:48231/pe">%pe;]><r/>')
w('xxe05_public.xml', '<!DOCTYPE r PUBLIC "-//X//DTD//EN" "file:///etc/passwd"><r/>')
w('xxe06_gt_in_extid.xml', '<!DOCTYPE r SYSTEM "a>b"><r/>')

# characters
w('chr01_nul_ref.xml', '<a>&#x0;</a>')
w('chr02_surrogate.xml', '<a>&#xD800;</a>')
w('chr03_above_max.xml', '<a>&#x110000;</a>')
w('chr04_huge.xml', '<a>&#x' + ('F' * 40) + ';</a>')
w('chr05_upper_X.xml', '<a>&#X41;</a>')
w('chr06_overlong.xml', b'<a>\xc0\x80</a>')
w('chr07_bom.xml', b'\xef\xbb\xbf<a/>')
w('chr08_bom_mid.xml', b'<a>\xef\xbb\xbf</a>')
w('chr09_crlf.xml', b'<a>x\r\ny\rz</a>')
w('chr10_attr_norm.xml', b'<a v="x\ty\r\nz"/>')
w('chr11_attr_charref_tab.xml', '<a v="x&#9;y"/>')
w('chr12_fffe.xml', '<a>￾</a>')
w('chr13_cdata_end.xml', '<a>]]></a>')
w('chr14_cdata_ok.xml', '<a><![CDATA[]]]]><![CDATA[>]]></a>')
w('chr15_lone_cr.xml', b'<a>x\rz</a>')

# line-ending normalisation, per content kind (audit F3)
w('crlf01_cdata.xml', b'<a><![CDATA[x\r\ny\rz]]></a>')
w('crlf02_text.xml', b'<a>x\r\ny\rz</a>')
w('crlf03_comment.xml', b'<a><!--x\r\ny--></a>')
w('crlf04_pi.xml', b'<a><?t x\r\ny?></a>')
w('crlf05_attr.xml', b'<a v="x\r\ny&#13;z&#9;w"/>')

# Name grammar (audit F4)
w('nam01_middledot_start.xml', '<·a/>')
w('nam02_combining_start.xml', '<̀a/>')
w('nam03_multiply_sign.xml', '<a×b/>')
w('nam04_digit_start.xml', '<1a/>')
w('nam05_colon_name.xml', '<a:b:c/>')
w('nam06_attr_multiply.xml', '<a b×c="1"/>')

# PI / XML declaration (audit F7)
w('pi01_stylesheet_first.xml', '<?xml-stylesheet href="a.xsl"?><a/>')
w('pi02_stylesheet_after_ws.xml', '\n<?xml-stylesheet href="a.xsl"?><a/>')
w('pi03_stylesheet_mid.xml', '<a><?xml-stylesheet href="a.xsl"?></a>')
w('pi04_xmlfoo.xml', '<?xmlfoo bar?><a/>')
w('pi05_decl_ok.xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><a/>')
w('pi06_decl_no_ws.xml', '<?xml version="1.0"encoding="UTF-8"?><a/>')

# structure
w('str01_unterminated_comment.xml', '<a><!-- x</a>')
w('str02_unterminated_cdata.xml', '<a><![CDATA[x</a>')
w('str03_no_ws_attrs.xml', '<a b="1"c="2"/>')
w('str04_trailing.xml', '<a/>junk')
w('str05_two_roots.xml', '<a/><b/>')
w('str06_empty.xml', '')

n = len(os.listdir(d))
print(f"wrote {n} documents to {d}")
if n != 60:
    raise SystemExit(f"expected 60 documents, wrote {n} -- the corpus is not what the differential expects")
