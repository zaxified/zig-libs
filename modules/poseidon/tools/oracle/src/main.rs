// SPDX-License-Identifier: MIT
//! Foreign side of `zig build bench-poseidon` and the live-vector generator for
//! zig-libs `modules/poseidon`. Drives, through their public APIs only:
//!  - neptune 14.0.0 at one git commit (Filecoin / Lurk Poseidon over BLS12-381,
//!    MIT OR Apache-2.0), the reference for `poseidon.neptune`;
//!  - light-poseidon 0.4.0 (Apache-2.0), circom-compatible Poseidon over BN254,
//!    the reference for `poseidon.bn254` (the bench's `bn254_*` rows).
//!
//! `poseidon-oracle vectors`   prints the neptune known-answer file
//!                             (`src/testdata/neptune_vectors.txt`) on stdout.
//! `poseidon-oracle <dir> <name>`  one bench workload (`bn254_t3`, `bn254_t5`,
//!                             `neptune_a2`, `neptune_a4`, `neptune_a8`): a chain
//!                             of 16 hashes per op, `acc = H(acc, c_i)` (or the
//!                             arity's worth of constants), count = low 64 bits
//!                             of the final digest. Prints `name\tns/op\tcount`.
use ark_bn254::Fr as ArkFr;
use ark_ff::{BigInteger, PrimeField as ArkPrimeField};
use blstrs::Scalar as Fr;
use ff::PrimeField;
use light_poseidon::{Poseidon as LightPoseidon, PoseidonHasher};
use neptune::generic_array::typenum::{U1, U11, U16, U2, U24, U3, U36, U4, U8};
use neptune::hash_type::{CType, HashType};
use neptune::poseidon::{Arity, Poseidon, PoseidonConstants};
use neptune::Strength;
use std::time::Instant;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn be(f: &Fr) -> [u8; 32] {
    let mut b = f.to_bytes_le();
    b.reverse();
    b
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    /// A uniformly distributed element (rejection on the canonical encoding).
    fn fr(&mut self) -> Fr {
        loop {
            let mut b = [0u8; 32];
            for c in b.chunks_mut(8) {
                c.copy_from_slice(&self.next().to_le_bytes());
            }
            b[31] &= 0x7f;
            let mut repr = <Fr as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(&b);
            if let Some(f) = Fr::from_repr_vartime(repr) {
                return f;
            }
        }
    }
}

fn line<A: Arity<Fr>>(out: &mut Vec<String>, strength: Strength, ht_name: &str, ht: HashType<Fr, A>, len: usize, rng: &mut Rng) {
    let constants = PoseidonConstants::<Fr, A>::new_with_strength_and_type(strength, ht);
    for case in 0..3 {
        // case 0: small integers 0..len, 1: full-size, 2: all zero
        let pre: Vec<Fr> = (0..len)
            .map(|i| match case {
                0 => Fr::from(i as u64),
                1 => rng.fr(),
                _ => Fr::from(0u64),
            })
            .collect();
        let mut p = Poseidon::<Fr, A>::new_with_preimage(&pre, &constants);
        let d = p.hash();
        let st = match strength {
            Strength::Standard => "standard",
            Strength::Strengthened => "strengthened",
        };
        let ins: Vec<String> = pre.iter().map(|f| hex(&be(f))).collect();
        out.push(format!("{} {} {} {} {} {}", A::to_usize(), st, ht_name, len, ins.join(","), hex(&be(&d))));
    }
}

fn arity_lines<A: Arity<Fr>>(out: &mut Vec<String>, rng: &mut Rng) {
    let n = A::to_usize();
    for strength in [Strength::Standard, Strength::Strengthened] {
        line::<A>(out, strength, "merkle", HashType::MerkleTree, n, rng);
        line::<A>(out, strength, "encryption", HashType::Encryption, n, rng);
        line::<A>(out, strength, "custom1", HashType::Custom(CType::Arbitrary(1)), n, rng);
        line::<A>(out, strength, "custom256", HashType::Custom(CType::Arbitrary(256)), n, rng);
        line::<A>(out, strength, "custom7", HashType::Custom(CType::Arbitrary(7)), n, rng);
        for len in [1usize, n / 2, n] {
            if len >= 1 {
                line::<A>(out, strength, &format!("const{}", len), HashType::ConstantLength(len), len, rng);
            }
        }
    }
}

fn vectors() {
    let mut rng = Rng(0x706f736569646f6e);
    let mut out = Vec::new();
    arity_lines::<U1>(&mut out, &mut rng);
    arity_lines::<U2>(&mut out, &mut rng);
    arity_lines::<U3>(&mut out, &mut rng);
    arity_lines::<U4>(&mut out, &mut rng);
    arity_lines::<U8>(&mut out, &mut rng);
    arity_lines::<U11>(&mut out, &mut rng);
    arity_lines::<U16>(&mut out, &mut rng);
    arity_lines::<U24>(&mut out, &mut rng);
    arity_lines::<U36>(&mut out, &mut rng);
    println!("# poseidon.neptune known answers, produced by running neptune 14.0.0 (git b06f03c5) via tools/oracle `vectors`.");
    println!("# arity strength hashtype len inputs(64-hex BE, comma separated) digest(64-hex BE)");
    println!("# Inputs: case 0 = 0..len, case 1 = full-size elements (splitmix64 seed 706f736569646f6e), case 2 = zeros.");
    for l in out {
        println!("{}", l);
    }
}

const CHAIN: usize = 16;

fn best_ns(mut once: impl FnMut() -> u64) -> (f64, u64) {
    let mut n = 1usize;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            std::hint::black_box(once());
        }
        if t.elapsed().as_nanos() > 100_000_000 {
            break;
        }
        n *= 2;
    }
    let mut best = f64::MAX;
    let mut count = 0;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            count = std::hint::black_box(once());
        }
        best = best.min(t.elapsed().as_nanos() as f64 / n as f64);
    }
    (best, count)
}

fn neptune_chain<A: Arity<Fr>>() -> (f64, u64) {
    let arity = A::to_usize();
    let constants = PoseidonConstants::<Fr, A>::new();
    let mut p = Poseidon::<Fr, A>::new(&constants);
    let cs: Vec<Fr> = (0..CHAIN * arity).map(|i| Fr::from(i as u64 + 1)).collect();
    best_ns(|| {
        let mut acc = Fr::from(0u64);
        for i in 0..CHAIN {
            let mut pre = Vec::with_capacity(arity);
            pre.push(acc);
            pre.extend_from_slice(&cs[i * arity + 1..(i + 1) * arity]);
            p.set_preimage(&pre);
            acc = p.hash();
        }
        u64::from_le_bytes(acc.to_bytes_le()[0..8].try_into().unwrap())
    })
}

fn bn254_chain(inputs: usize) -> (f64, u64) {
    let mut h = LightPoseidon::<ArkFr>::new_circom(inputs).unwrap();
    let cs: Vec<ArkFr> = (0..CHAIN * inputs).map(|i| ArkFr::from(i as u64 + 1)).collect();
    best_ns(|| {
        let mut acc = ArkFr::from(0u64);
        for i in 0..CHAIN {
            let mut pre = Vec::with_capacity(inputs);
            pre.push(acc);
            pre.extend_from_slice(&cs[i * inputs + 1..(i + 1) * inputs]);
            acc = h.hash(&pre).unwrap();
        }
        let b = acc.into_bigint().to_bytes_le();
        u64::from_le_bytes(b[0..8].try_into().unwrap())
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && args[1] == "vectors" {
        vectors();
        return;
    }
    if args.len() != 3 {
        eprintln!("usage: poseidon-oracle vectors | poseidon-oracle <work dir> <name>");
        std::process::exit(2);
    }
    let name = args[2].as_str();
    let (ns, count) = match name {
        "bn254_t3" => bn254_chain(2),
        "bn254_t5" => bn254_chain(4),
        "neptune_a2" => neptune_chain::<U2>(),
        "neptune_a4" => neptune_chain::<U4>(),
        "neptune_a8" => neptune_chain::<U8>(),
        _ => {
            eprintln!("unknown workload {}", name);
            std::process::exit(2);
        }
    };
    println!("{}\t{:.2}\t{}", name, ns, count);
    eprintln!("{} (Rust, release, lto)", if name.starts_with("bn254") { "light-poseidon 0.4.0 (new_circom)" } else { "neptune 14.0.0 (OptimizedStatic)" });
}
