// SPDX-License-Identifier: MIT
//
// tfhe-rs 1.8.1 as a black-box oracle for modules/tfhe (see ../README.md).
//
//   tfhe_tfhers_vectors vectors OUT.bin   tfhe-rs -> this module: keys, keys
//                                         in standard layout, ciphertexts,
//                                         PBS / key-switch / gate outputs
//   tfhe_tfhers_vectors check IN.bin      this module -> tfhe-rs: decrypts the
//                                         module's ciphertexts and evaluates
//                                         tfhe-rs's gates with the module's
//                                         bootstrap and key-switch keys;
//                                         panics on the first disagreement
//
// File format (both directions): records of `tag[4] | len u32 LE | len u32
// words LE`. Every key and ciphertext is tfhe-rs's standard-domain container,
// verbatim.

use std::io::Write;
use tfhe::boolean::prelude::*;
use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::commons::math::random::Seed;
use tfhe::core_crypto::prelude::*;

const TRUE: u32 = 1 << 29;
const FALSE: u32 = TRUE.wrapping_neg();
const GATES: [&str; 7] = ["and", "nand", "or", "nor", "xor", "xnor", "mux"];

fn put(out: &mut Vec<u8>, tag: &str, words: &[u32]) {
    assert_eq!(tag.len(), 4);
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(&(words.len() as u32).to_le_bytes());
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
}

fn records(bytes: &[u8]) -> Vec<(String, Vec<u32>)> {
    let mut v = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let tag = String::from_utf8(bytes[i..i + 4].to_vec()).unwrap();
        let len = u32::from_le_bytes(bytes[i + 4..i + 8].try_into().unwrap()) as usize;
        let words = bytes[i + 8..i + 8 + 4 * len]
            .chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        v.push((tag, words));
        i += 8 + 4 * len;
    }
    v
}

fn get<'a>(recs: &'a [(String, Vec<u32>)], tag: &str) -> &'a [u32] {
    &recs.iter().find(|(t, _)| t == tag).unwrap_or_else(|| panic!("missing record {tag}")).1
}

fn std_dev(d: DynamicDistribution<u32>) -> f64 {
    match d {
        DynamicDistribution::Gaussian(g) => g.std,
        other => panic!("not Gaussian: {other:?}"),
    }
}

fn param_words(p: &BooleanParameters) -> Vec<u32> {
    let mut w = vec![
        p.lwe_dimension.0 as u32,
        p.glwe_dimension.0 as u32,
        p.polynomial_size.0 as u32,
        p.pbs_base_log.0 as u32,
        p.pbs_level.0 as u32,
        p.ks_base_log.0 as u32,
        p.ks_level.0 as u32,
    ];
    for s in [std_dev(p.lwe_noise_distribution), std_dev(p.glwe_noise_distribution)] {
        let b = s.to_bits();
        w.push(b as u32);
        w.push((b >> 32) as u32);
    }
    w
}

fn bool_of(phase: u32) -> bool {
    phase >> 31 == 0
}

fn gate(sk: &ServerKey, g: &str, a: &Ciphertext, b: &Ciphertext, c: &Ciphertext) -> Ciphertext {
    match g {
        "and" => sk.and(a, b),
        "nand" => sk.nand(a, b),
        "or" => sk.or(a, b),
        "nor" => sk.nor(a, b),
        "xor" => sk.xor(a, b),
        "xnor" => sk.xnor(a, b),
        "mux" => sk.mux(c, a, b),
        _ => unreachable!(),
    }
}

fn expect(g: &str, a: bool, b: bool, c: bool) -> bool {
    match g {
        "and" => a & b,
        "nand" => !(a & b),
        "or" => a | b,
        "nor" => !(a | b),
        "xor" => a ^ b,
        "xnor" => !(a ^ b),
        "mux" => if c { a } else { b },
        _ => unreachable!(),
    }
}

fn lwe_words(ct: &Ciphertext) -> Vec<u32> {
    match ct {
        Ciphertext::Encrypted(l) => l.as_ref().to_vec(),
        Ciphertext::Trivial(_) => panic!("trivial gate output"),
    }
}

fn small_params() -> BooleanParameters {
    BooleanParameters {
        lwe_dimension: LweDimension(16),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(64),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2f64.powi(-22))),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(2f64.powi(-28))),
        pbs_base_log: DecompositionBaseLog(6),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        encryption_key_choice: EncryptionKeyChoice::Small,
    }
}

struct Keys {
    lwe: LweSecretKeyOwned<u32>,
    glwe: GlweSecretKeyOwned<u32>,
    bsk: LweBootstrapKeyOwned<u32>,
    ksk: LweKeyswitchKeyOwned<u32>,
}

fn keygen(p: &BooleanParameters, seed: u128) -> Keys {
    let cm = CiphertextModulus::<u32>::new_native();
    let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(seed));
    let mut sgen = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let mut egen = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), &mut seeder);
    let lwe = allocate_and_generate_new_binary_lwe_secret_key(p.lwe_dimension, &mut sgen);
    let glwe = allocate_and_generate_new_binary_glwe_secret_key(p.glwe_dimension, p.polynomial_size, &mut sgen);
    let big = glwe.clone().into_lwe_secret_key();
    let bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
        &lwe, &glwe, p.pbs_base_log, p.pbs_level, p.glwe_noise_distribution, cm, &mut egen,
    );
    let ksk = allocate_and_generate_new_lwe_keyswitch_key(
        &big, &lwe, p.ks_base_log, p.ks_level, p.lwe_noise_distribution, cm, &mut egen,
    );
    Keys { lwe, glwe, bsk, ksk }
}

fn fourier(bsk: &LweBootstrapKeyOwned<u32>) -> FourierLweBootstrapKeyOwned {
    let mut f = FourierLweBootstrapKey::new(
        bsk.input_lwe_dimension(),
        bsk.glwe_size(),
        bsk.polynomial_size(),
        bsk.decomposition_base_log(),
        bsk.decomposition_level_count(),
    );
    convert_standard_lwe_bootstrap_key_to_fourier(bsk, &mut f);
    f
}

fn server_key(bsk: &LweBootstrapKeyOwned<u32>, ksk: &LweKeyswitchKeyOwned<u32>) -> ServerKey {
    ServerKey::from_raw_parts(fourier(bsk), ksk.clone(), PBSOrder::BootstrapKeyswitch)
}

fn encrypt_bits(k: &Keys, p: &BooleanParameters, bits: &[bool], seed: u128) -> Vec<LweCiphertextOwned<u32>> {
    let cm = CiphertextModulus::<u32>::new_native();
    let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(seed));
    let mut egen = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), &mut seeder);
    bits.iter()
        .map(|&b| {
            allocate_and_encrypt_new_lwe_ciphertext(
                &k.lwe, Plaintext(if b { TRUE } else { FALSE }), p.lwe_noise_distribution, cm, &mut egen,
            )
        })
        .collect()
}

/// The gate convention shared with interop_test.zig: gate `g` on pair `i`
/// reads inputs `a = 2i`, `b = 2i+1`, control `c = (2i+2) mod count`.
fn gate_records(out: &mut Vec<u8>, prefix: &str, sk: &ServerKey, cts: &[Ciphertext], pairs: usize) {
    for (gi, g) in GATES.iter().enumerate() {
        let mut words = Vec::new();
        for i in 0..pairs {
            let (a, b, c) = (&cts[2 * i], &cts[2 * i + 1], &cts[(2 * i + 2) % cts.len()]);
            words.extend(lwe_words(&gate(sk, g, a, b, c)));
        }
        put(out, &format!("{prefix}GT{gi}"), &words);
    }
}

fn bits_from(seed: u64, count: usize) -> Vec<bool> {
    let mut x = seed;
    (0..count)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x >> 63 == 1
        })
        .collect()
}

fn vectors(path: &str) {
    let mut out = Vec::new();

    // 1. The boolean parameter sets.
    put(&mut out, "PARD", &param_words(&DEFAULT_PARAMETERS));
    put(&mut out, "PARL", &param_words(&TFHE_LIB_PARAMETERS));
    put(&mut out, "PARE", &param_words(&PARAMETERS_ERROR_PROB_2_POW_MINUS_165));

    // 2. Signed decomposition: inputs with ties planted at every level.
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for (si, &(bl, lc)) in [(3usize, 5usize), (10, 2), (2, 8), (7, 3), (6, 3)].iter().enumerate() {
        let dec = SignedDecomposer::<u32>::new(DecompositionBaseLog(bl), DecompositionLevelCount(lc));
        let mut words = vec![bl as u32, lc as u32];
        for t in 0..400 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let mut v = (x >> 20) as u32;
            if t % 2 == 1 {
                let lvl = (x as usize) % lc;
                let sh = 32 - bl * (lvl + 1);
                v = (v & !(((1u32 << bl) - 1) << sh)) | ((1u32 << (bl - 1)) << sh);
            }
            let mut digits: Vec<u32> = dec.decompose(v).map(|t| t.value()).collect();
            digits.reverse(); // most significant first
            words.push(v);
            words.extend(digits);
        }
        put(&mut out, &format!("DEC{si}"), &words);
    }

    // 3. Small k = 2 set: everything in standard layout, plus PBS, key-switch
    //    and gate outputs computed by tfhe-rs.
    let p = small_params();
    let k = keygen(&p, 0x5eed_0001);
    put(&mut out, "SLSK", k.lwe.as_ref());
    put(&mut out, "SGSK", k.glwe.as_ref());
    put(&mut out, "SBSK", k.bsk.as_ref());
    put(&mut out, "SKSK", k.ksk.as_ref());
    let count = 32;
    let bits = bits_from(0x0bad_cafe, count);
    let inputs = encrypt_bits(&k, &p, &bits, 0x5eed_0002);
    put(&mut out, "SBIT", &bits.iter().map(|&b| b as u32).collect::<Vec<_>>());
    put(&mut out, "SINP", &inputs.iter().flat_map(|c| c.as_ref().to_vec()).collect::<Vec<_>>());
    let fbsk = fourier(&k.bsk);
    let n_big = p.glwe_dimension.0 * p.polynomial_size.0;
    let cm = CiphertextModulus::<u32>::new_native();
    let acc = allocate_and_trivially_encrypt_new_glwe_ciphertext(
        p.glwe_dimension.to_glwe_size(),
        &PlaintextList::new(TRUE, PlaintextCount(p.polynomial_size.0)),
        cm,
    );
    let (mut pbs_words, mut ks_words) = (Vec::new(), Vec::new());
    for ct in &inputs {
        let mut big = LweCiphertext::new(0u32, LweSize(n_big + 1), cm);
        programmable_bootstrap_lwe_ciphertext(ct, &mut big, &acc, &fbsk);
        let mut small = LweCiphertext::new(0u32, p.lwe_dimension.to_lwe_size(), cm);
        keyswitch_lwe_ciphertext(&k.ksk, &big, &mut small);
        pbs_words.extend_from_slice(big.as_ref());
        ks_words.extend_from_slice(small.as_ref());
    }
    put(&mut out, "SPBS", &pbs_words);
    put(&mut out, "SKS_", &ks_words);
    let sk = server_key(&k.bsk, &k.ksk);
    let cts: Vec<Ciphertext> = inputs.into_iter().map(Ciphertext::Encrypted).collect();
    gate_records(&mut out, "S", &sk, &cts, count / 2);
    for (gi, g) in GATES.iter().enumerate() {
        let w = get(&records(&out), &format!("SGT{gi}")).to_vec();
        for (i, ct) in w.chunks(p.lwe_dimension.0 + 1).enumerate() {
            let ph = decrypt_lwe_ciphertext(&k.lwe, &LweCiphertext::from_container(ct.to_vec(), cm)).0;
            let (a, b, c) = (bits[2 * i], bits[2 * i + 1], bits[(2 * i + 2) % count]);
            assert_eq!(bool_of(ph), expect(g, a, b, c), "tfhe-rs gate {g} pair {i}");
        }
    }

    // 4. DEFAULT_PARAMETERS: secret keys, tfhe-rs ciphertexts and gate outputs
    //    (the 53 MB bootstrap key stays out; the test regenerates its own).
    let pd = DEFAULT_PARAMETERS;
    let kd = keygen(&pd, 0x5eed_0003);
    put(&mut out, "DLSK", kd.lwe.as_ref());
    put(&mut out, "DGSK", kd.glwe.as_ref());
    let count = 8;
    let bits = bits_from(0x0dec_af00, count);
    let inputs = encrypt_bits(&kd, &pd, &bits, 0x5eed_0004);
    put(&mut out, "DBIT", &bits.iter().map(|&b| b as u32).collect::<Vec<_>>());
    put(&mut out, "DINP", &inputs.iter().flat_map(|c| c.as_ref().to_vec()).collect::<Vec<_>>());
    let sk = server_key(&kd.bsk, &kd.ksk);
    let cts: Vec<Ciphertext> = inputs.into_iter().map(Ciphertext::Encrypted).collect();
    gate_records(&mut out, "D", &sk, &cts, 2);

    std::fs::File::create(path).unwrap().write_all(&out).unwrap();
    eprintln!("wrote {} bytes to {path}", out.len());
}

/// The module's keys and ciphertexts through tfhe-rs. Record prefix `S`
/// (small set) or `D` (DEFAULT_PARAMETERS), as written by emit_zig.zig.
fn check(path: &str) {
    let recs = records(&std::fs::read(path).unwrap());
    let cm = CiphertextModulus::<u32>::new_native();
    for (prefix, p) in [("S", small_params()), ("D", DEFAULT_PARAMETERS)] {
        if !recs.iter().any(|(t, _)| t == &format!("{prefix}LSK")) {
            continue;
        }
        let lwe = LweSecretKey::from_container(get(&recs, &format!("{prefix}LSK")).to_vec());
        let glwe = GlweSecretKey::from_container(get(&recs, &format!("{prefix}GSK")).to_vec(), p.polynomial_size);
        let bsk = LweBootstrapKey::from_container(
            get(&recs, &format!("{prefix}BSK")).to_vec(),
            p.glwe_dimension.to_glwe_size(),
            p.polynomial_size,
            p.pbs_base_log,
            p.pbs_level,
            cm,
        );
        let ksk = LweKeyswitchKey::from_container(
            get(&recs, &format!("{prefix}KSK")).to_vec(),
            p.ks_base_log,
            p.ks_level,
            p.lwe_dimension.to_lwe_size(),
            cm,
        );
        assert_eq!(bsk.input_lwe_dimension(), p.lwe_dimension);
        let bits: Vec<bool> = get(&recs, &format!("{prefix}BIT")).iter().map(|&b| b == 1).collect();
        let n1 = p.lwe_dimension.0 + 1;
        let inputs: Vec<LweCiphertextOwned<u32>> = get(&recs, &format!("{prefix}INP"))
            .chunks(n1)
            .map(|c| LweCiphertext::from_container(c.to_vec(), cm))
            .collect();
        assert_eq!(inputs.len(), bits.len());
        // a) tfhe-rs decrypts the module's ciphertexts.
        for (ct, &b) in inputs.iter().zip(&bits) {
            assert_eq!(bool_of(decrypt_lwe_ciphertext(&lwe, ct).0), b, "{prefix} input decrypt");
        }
        // b) ...and the module's gate outputs.
        let count = bits.len();
        for (gi, g) in GATES.iter().enumerate() {
            for (i, c) in get(&recs, &format!("{prefix}GT{gi}")).chunks(n1).enumerate() {
                let ph = decrypt_lwe_ciphertext(&lwe, &LweCiphertext::from_container(c.to_vec(), cm)).0;
                let e = expect(g, bits[2 * i], bits[2 * i + 1], bits[(2 * i + 2) % count]);
                assert_eq!(bool_of(ph), e, "{prefix} module gate {g} pair {i}");
            }
        }
        // c) tfhe-rs's gates, run with the module's bootstrap and key-switch keys.
        let ck = ClientKey::new_from_raw_parts(lwe.clone(), glwe, p);
        let sk = server_key(&bsk, &ksk);
        let cts: Vec<Ciphertext> = inputs.into_iter().map(Ciphertext::Encrypted).collect();
        let mut evaluated = 0;
        for g in GATES {
            for i in 0..count / 2 {
                let (a, b, c) = (&cts[2 * i], &cts[2 * i + 1], &cts[(2 * i + 2) % count]);
                let r = gate(&sk, g, a, b, c);
                let e = expect(g, bits[2 * i], bits[2 * i + 1], bits[(2 * i + 2) % count]);
                assert_eq!(ck.decrypt(&r), e, "{prefix} tfhe-rs gate {g} on module keys, pair {i}");
                evaluated += 1;
            }
        }
        println!(
            "{prefix}: n={} k={} N={}: tfhe-rs decrypted {} module ciphertexts and {} module gate outputs, \
             and evaluated {} gates with the module's bootstrap/key-switch keys: all as expected",
            p.lwe_dimension.0,
            p.glwe_dimension.0,
            p.polynomial_size.0,
            count,
            GATES.len() * (count / 2),
            evaluated
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("vectors") => vectors(&args[2]),
        Some("check") => check(&args[2]),
        _ => panic!("usage: tfhe_tfhers_vectors (vectors OUT.bin | check IN.bin)"),
    }
}
