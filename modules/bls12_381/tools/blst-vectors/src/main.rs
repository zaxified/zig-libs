// SPDX-License-Identifier: MIT
// Reference-vector generator for zig-libs `modules/bls12_381` (scheme.zig,
// bls_sig.zig, eip2333.zig).
//
// Runs supranational/blst (Rust bindings, Apache-2.0) as a black box and
// prints a Zig source file with what it computed. No blst source is copied;
// only its public API is called. Every printed signature is first verified
// by blst itself, and one tampered message per suite is asserted rejected
// (the oracle's own negative control).

use blst::BLST_ERROR;

// splitmix64: a fixed, dependency-free byte source (the vectors only need to
// be reproducible, not secret).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() & 0xff) as u8).collect()
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

const MSG_LENS: [usize; 6] = [0, 1, 32, 33, 64, 200];

macro_rules! suite {
    ($out:expr, $rng:expr, $m:ident, $name:expr, $g:expr, $tag:expr) => {{
        use blst::$m::{AggregateSignature, PublicKey, SecretKey, Signature};
        let dst = format!("BLS_SIG_BLS12381G{}_XMD:SHA-256_SSWU_RO_{}_", $g, $tag);
        let dst_pop = format!("BLS_POP_BLS12381G{}_XMD:SHA-256_SSWU_RO_POP_", $g);
        let aug_scheme = $tag == "AUG";
        let pop_scheme = $tag == "POP";
        $out.push_str(&format!("pub const {} = Suite{{ .dst = \"{}\", .sign = &.{{\n", $name, dst));
        let mut sigs: Vec<Signature> = Vec::new();
        let mut pks: Vec<PublicKey> = Vec::new();
        let mut msgs: Vec<Vec<u8>> = Vec::new();
        for (i, &len) in MSG_LENS.iter().enumerate() {
            let ikm = $rng.bytes(32 + i);
            let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
            // draft -05 KeyGen (raw salt on the first round); `key_gen`
            // above is the -04-compatible one (pre-hashed salt).
            let sk_v5 = SecretKey::key_gen_v5(&ikm, b"BLS-SIG-KEYGEN-SALT-", &[]).unwrap();
            let pk = sk.sk_to_pk();
            let pk_bytes = pk.compress();
            let msg = $rng.bytes(len);
            let aug: Vec<u8> = if aug_scheme { pk_bytes.to_vec() } else { Vec::new() };
            let sig = sk.sign(&msg, dst.as_bytes(), &aug);
            assert_eq!(sig.verify(true, &msg, dst.as_bytes(), &aug, &pk, true), BLST_ERROR::BLST_SUCCESS);
            let pop = if pop_scheme {
                let p = sk.sign(&pk_bytes, dst_pop.as_bytes(), &[]);
                assert_eq!(p.verify(true, &pk_bytes, dst_pop.as_bytes(), &[], &pk, true), BLST_ERROR::BLST_SUCCESS);
                hex(&p.compress())
            } else {
                String::new()
            };
            $out.push_str(&format!(
                "    .{{ .ikm = \"{}\", .sk = \"{}\", .sk_v5 = \"{}\", .pk = \"{}\", .msg = \"{}\", .sig = \"{}\", .pop = \"{}\" }},\n",
                hex(&ikm), hex(&sk.to_bytes()), hex(&sk_v5.to_bytes()), hex(&pk_bytes), hex(&msg), hex(&sig.compress()), pop
            ));
            sigs.push(sig);
            pks.push(pk);
            msgs.push(msg);
        }
        // Oracle negative control: one flipped message byte is refused.
        {
            let mut bad = msgs[2].clone();
            bad[0] ^= 1;
            let aug: Vec<u8> = if aug_scheme { pks[2].compress().to_vec() } else { Vec::new() };
            assert_ne!(sigs[2].verify(true, &bad, dst.as_bytes(), &aug, &pks[2], true), BLST_ERROR::BLST_SUCCESS);
        }
        // Aggregate of every case's signature (distinct random messages, so
        // every scheme accepts it), verified by blst before printing.
        let refs: Vec<&Signature> = sigs.iter().collect();
        let agg = AggregateSignature::aggregate(&refs, true).unwrap().to_signature();
        let pk_refs: Vec<&PublicKey> = pks.iter().collect();
        let full_msgs: Vec<Vec<u8>> = msgs
            .iter()
            .zip(pks.iter())
            .map(|(m, pk)| if aug_scheme { [pk.compress().as_slice(), m.as_slice()].concat() } else { m.clone() })
            .collect();
        let msg_refs: Vec<&[u8]> = full_msgs.iter().map(|m| m.as_slice()).collect();
        assert_eq!(agg.aggregate_verify(true, &msg_refs, dst.as_bytes(), &pk_refs, true), BLST_ERROR::BLST_SUCCESS);
        $out.push_str(&format!("}}, .aggregate = \"{}\"", hex(&agg.compress())));
        // POP: one shared message signed by every key, fast-aggregate-verified.
        if pop_scheme {
            let shared = $rng.bytes(48);
            // Four further keys, printed as secret keys.
            let mut f: Vec<Signature> = Vec::new();
            let mut fpks: Vec<PublicKey> = Vec::new();
            let mut fsks_hex: Vec<String> = Vec::new();
            for _ in 0..4 {
                let ikm = $rng.bytes(32);
                let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
                fsks_hex.push(hex(&sk.to_bytes()));
                fpks.push(sk.sk_to_pk());
                f.push(sk.sign(&shared, dst.as_bytes(), &[]));
            }
            let frefs: Vec<&Signature> = f.iter().collect();
            let fagg = AggregateSignature::aggregate(&frefs, true).unwrap().to_signature();
            let fpk_refs: Vec<&PublicKey> = fpks.iter().collect();
            assert_eq!(fagg.fast_aggregate_verify(true, &shared, dst.as_bytes(), &fpk_refs), BLST_ERROR::BLST_SUCCESS);
            let ikm_list: Vec<String> = fsks_hex.iter().map(|s| format!("\"{}\"", s)).collect();
            $out.push_str(&format!(
                ", .fast = .{{ .sks = &.{{ {} }}, .msg = \"{}\", .aggregate = \"{}\" }}",
                ikm_list.join(", "), hex(&shared), hex(&fagg.compress())
            ));
        }
        $out.push_str(" };\n\n");
    }};
}

fn main() {
    let mut rng = Rng(0x0B15_0001);
    let mut out = String::new();
    out.push_str(
        "// SPDX-License-Identifier: MIT\n\
//\n\
// GENERATED by tools/blst-vectors (Cargo project) -- do not edit. Regenerate:\n\
//   hw run -- cargo run -q --release --manifest-path modules/bls12_381/tools/blst-vectors/Cargo.toml \\\n\
//     --target-dir ~/.cache/zig-libs-cargo/blst-vectors > modules/bls12_381/src/blst_vectors.zig\n\
//\n\
// Source: supranational/blst 0.3.16 Rust bindings (Apache-2.0), run as a black box over a\n\
// fixed splitmix64 stream (seed 0x0B150001). Per suite: SecretKey::key_gen(ikm, \"\") (the\n\
// draft -04-compatible KeyGen: salt pre-hashed) as `sk`, and key_gen_v5(ikm,\n\
// \"BLS-SIG-KEYGEN-SALT-\", \"\") (draft -05) as `sk_v5`; sk_to_pk of `sk`,\n\
// sign(msg, dst, aug) with aug = compressed PK for the AUG suites, every signature verified by\n\
// blst before printing; PoP proofs = sign(PK bytes, BLS_POP_ DST); the aggregate of all of a\n\
// suite's signatures (aggregate_verify'd by blst); for POP a fast_aggregate_verify'd shared-\n\
// message aggregate under four further keys. EIP-2333: derive_master_eip2333 /\n\
// derive_child_eip2333. Points ZCash-compressed; all values lowercase hex.\n\
\n\
// zig fmt: off\n\
\n\
pub const SignCase = struct { ikm: []const u8, sk: []const u8, sk_v5: []const u8, pk: []const u8, msg: []const u8, sig: []const u8, pop: []const u8 };\n\
pub const Fast = struct { sks: []const []const u8, msg: []const u8, aggregate: []const u8 };\n\
pub const Suite = struct { dst: []const u8, sign: []const SignCase, aggregate: []const u8, fast: ?Fast = null };\n\
pub const Eip2333 = struct { seed: []const u8, master: []const u8, index: u32, child: []const u8 };\n\n",
    );
    suite!(out, rng, min_pk, "min_pk_basic", 2, "NUL");
    suite!(out, rng, min_pk, "min_pk_aug", 2, "AUG");
    suite!(out, rng, min_pk, "min_pk_pop", 2, "POP");
    suite!(out, rng, min_sig, "min_sig_basic", 1, "NUL");
    suite!(out, rng, min_sig, "min_sig_aug", 1, "AUG");
    suite!(out, rng, min_sig, "min_sig_pop", 1, "POP");

    out.push_str("pub const eip2333 = [_]Eip2333{\n");
    for (i, idx) in [0u32, 1, 42, 0x7fff_ffff, 0xffff_ffff].iter().enumerate() {
        let seed = rng.bytes(32 + 8 * i);
        let master = blst::min_pk::SecretKey::derive_master_eip2333(&seed).unwrap();
        let child = master.derive_child_eip2333(*idx);
        out.push_str(&format!(
            "    .{{ .seed = \"{}\", .master = \"{}\", .index = {}, .child = \"{}\" }},\n",
            hex(&seed), hex(&master.to_bytes()), idx, hex(&child.to_bytes())
        ));
    }
    out.push_str("};\n");
    print!("{}", out);
}
