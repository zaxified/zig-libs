#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""gen_kat_vectors — regenerate `src/kat_vectors.zig` from the text of
draft-irtf-cfrg-bbs-signatures-12 (both suites: §8.2, §8.3/§8.4,
Appendix D.1/D.2).

The recipe that produced the committed KATs (CONVENTIONS §9). Usage:

    curl -fsSL -o draft-12.txt \
        https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-12.txt
    python3 -I modules/bbs/tools/gen_kat_vectors.py draft-12.txt > modules/bbs/src/kat_vectors.zig
    zig fmt modules/bbs/src/kat_vectors.zig

Values are copied verbatim (hex, lowercased); nothing is computed here.
"""
import re
import sys


def sections(path):
    lines = open(path, encoding="utf-8").read().split("\n")
    keep = [l for l in lines
            if not re.match(r"^(Looker, et al\.|Internet-Draft  )", l) and not l.startswith("\x0c")]
    txt = "\n".join(keep)
    parts = re.split(r"\n((?:8|D)\.[0-9.]+)  ([^\n]+)\n", txt)
    out = {}
    for k in range(1, len(parts), 3):
        num, title, body = parts[k].rstrip("."), parts[k + 1], parts[k + 2]
        vals = {}
        order = []
        # The closing quote is optional: draft-12 Appendix D.1.3 omits it
        # after `scalar` (the section header that follows ends the value).
        for m in re.finditer(r"([A-Za-z_~^0-9]+)\s*=\s*(?:h|0x)'([0-9a-fA-F\s]*)'?", body):
            vals[m.group(1)] = re.sub(r"\s+", "", m.group(2)).lower()
            order.append(m.group(1))
        idx = re.search(r"revealed_indexes = \[([0-9 ,]*)\]", body)
        valid = re.search(r"(?m)^valid: (true|false)", body)
        out[num] = {
            "title": title.strip(),
            "vals": vals,
            "order": order,
            "revealed": [int(x) for x in idx.group(1).split(",") if x.strip()] if idx else None,
            "valid": (valid.group(1) == "true") if valid else True,
        }
    return out


def zstr(s):
    return '"' + s + '"'


def msgs_of(sec):
    return [sec["vals"][k] for k in sec["order"] if re.fullmatch(r"m_\d+", k)]


SUITES = {
    # name: (key pair, map, generators, sig valid x2, mocked, proofs x3, appendix)
    "sha256": ("8.4", "D.2"),
    "shake256": ("8.3", "D.1"),
}


def emit_suite(w, s, name, main, app):
    w(f"pub const {name} = struct {{\n")
    kp = s[f"{main}.1"]["vals"]
    w("    pub const keypair = struct {\n")
    for k in ("key_material", "key_info"):
        w(f"        pub const {k} = {zstr(kp[k])};\n")
    w("        /// Published for one suite only; null = the suite's default.\n")
    w(f"        pub const key_dst: ?[]const u8 = {zstr(kp['key_dst']) if 'key_dst' in kp else 'null'};\n")
    w(f"        pub const sk = {zstr(kp['SK'])};\n")
    w(f"        pub const pk = {zstr(kp['PK'])};\n")
    w("    };\n\n")

    ms = s[f"{main}.2"]
    w("    pub const map_messages_to_scalar = struct {\n")
    w("        /// Published for one suite only; null = the suite's `map_msg_dst`.\n")
    w(f"        pub const dst: ?[]const u8 = {zstr(ms['vals']['dst']) if 'dst' in ms['vals'] else 'null'};\n")
    w("        pub const scalars = [_][]const u8{\n")
    for k in ms["order"]:
        if k.startswith("msg_scalar_"):
            w(f"            {zstr(ms['vals'][k])},\n")
    w("        };\n    };\n\n")

    g = s[f"{main}.3"]
    w("    pub const generators = struct {\n")
    w(f"        pub const q1 = {zstr(g['vals']['Q_1'])};\n")
    w("        pub const msg_generators = [_][]const u8{\n")
    for k in g["order"]:
        if k.startswith("H_"):
            w(f"            {zstr(g['vals'][k])},\n")
    w("        };\n    };\n\n")

    r = s[f"{main}.5"]
    w("    /// `seeded_random_scalars(SEED, api_id || \"MOCK_RANDOM_SCALARS_DST_\", 10)`.\n")
    w("    pub const mocked_rng = struct {\n")
    w(f"        pub const seed = {zstr(r['vals']['SEED'])};\n")
    w("        pub const scalars = [_][]const u8{\n")
    for k in r["order"]:
        if k.startswith("random_scalar_"):
            w(f"            {zstr(r['vals'][k])},\n")
    w("        };\n    };\n\n")

    h = s[f"{app}.3"]["vals"]
    w("    pub const h2s = struct {\n")
    for k in ("msg", "dst", "scalar"):
        w(f"        pub const {k} = {zstr(h[k])};\n")
    w("    };\n\n")

    w("    pub const signature_cases = [_]SignatureCase{\n")
    for num in [f"{main}.4.1", f"{main}.4.2"] + [f"{app}.1.{i}" for i in range(1, 8)]:
        c = s[num]
        v = c["vals"]
        w("        .{\n")
        w(f"            .name = {zstr(num + ' ' + c['title'])},\n")
        w("            .messages = &.{" + ", ".join(zstr(m) for m in msgs_of(c)) + "},\n")
        sk = zstr(v["SK"]) if "SK" in v else "null"
        w(f"            .sk = {sk},\n            .pk = {zstr(v['PK'])},\n")
        w(f"            .header = {zstr(v['header'])},\n            .signature = {zstr(v['signature'])},\n")
        w(f"            .valid = {'true' if c['valid'] else 'false'},\n")
        w("        },\n")
    w("    };\n\n")

    w("    /// Proofs under `mocked_rng.seed` (5 + U scalars each).\n")
    w("    pub const proof_cases = [_]ProofCase{\n")
    for num in [f"{main}.5.{i}" for i in (1, 2, 3)] + [f"{app}.2.1", f"{app}.2.2"]:
        c = s[num]
        v = c["vals"]
        msgs = [v[k] for k in c["order"] if re.fullmatch(r"m_\d+", k)]
        w("        .{\n")
        w(f"            .name = {zstr(num + ' ' + c['title'])},\n")
        w("            .messages = &.{" + ", ".join(zstr(m) for m in msgs) + "},\n")
        w(f"            .pk = {zstr(v['public_key'])},\n            .signature = {zstr(v['signature'])},\n")
        w(f"            .header = {zstr(v['header'])},\n            .presentation_header = {zstr(v['presentation_header'])},\n")
        w("            .disclosed_indexes = &.{" + ", ".join(str(i) for i in c["revealed"]) + "},\n")
        w(f"            .proof = {zstr(v['proof'])},\n")
        w("        },\n")
    w("    };\n};\n\n")


def main():
    s = sections(sys.argv[1])
    w = sys.stdout.write
    w("// SPDX-License-Identifier: MIT\n")
    w("//! GENERATED by `tools/gen_kat_vectors.py` from the text of\n")
    w("//! draft-irtf-cfrg-bbs-signatures-12 (§8.2; BLS12-381-SHA-256: §8.4 and\n")
    w("//! Appendix D.2; BLS12-381-SHAKE-256: §8.3 and Appendix D.1) — do not\n")
    w("//! edit by hand. Hex as published, lowercased. The draft's code\n")
    w("//! components are under the Revised BSD License (IETF Trust Legal\n")
    w("//! Provisions); see `../NOTICE`.\n\n")
    w('pub const draft = "draft-irtf-cfrg-bbs-signatures-12";\n\n')
    w("/// §8.2 — the ten messages every multi-message fixture signs.\n")
    w("pub const messages = [_][]const u8{\n")
    for m in msgs_of(s["8.2"]):
        w(f"    {zstr(m)},\n")
    w("};\n\n")
    w("pub const SignatureCase = struct {\n")
    w("    name: []const u8,\n    messages: []const []const u8,\n    /// Published with the valid cases only.\n    sk: ?[]const u8,\n    pk: []const u8,\n")
    w("    header: []const u8,\n    signature: []const u8,\n    valid: bool,\n};\n\n")
    w("pub const ProofCase = struct {\n")
    w("    name: []const u8,\n    /// Every signed message, in signing order.\n    messages: []const []const u8,\n")
    w("    pk: []const u8,\n    signature: []const u8,\n    header: []const u8,\n    presentation_header: []const u8,\n")
    w("    disclosed_indexes: []const usize,\n    proof: []const u8,\n};\n\n")
    for name, (main_sec, app) in SUITES.items():
        emit_suite(w, s, name, main_sec, app)


if __name__ == "__main__":
    main()
