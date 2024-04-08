use super::*;
use crate::circuit::BccCircuit;
use ark_ff::UniformRand;
use ark_std::{
    rand::{CryptoRng, RngCore, SeedableRng},
    test_rng,
};
use bccgroth16::{crypto::commitment::CM, BccGroth16};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref PATH: String = "./".to_string();
    pub static ref PK_FILE: String = "cbdc.pk.dat".to_string();
    pub static ref VK_FILE: String = "cbdc.vk.dat".to_string();
    pub static ref PRF_FILE: String = "cbdc.proof.dat".to_string();
    pub static ref N: usize = 1 << 4;
}

type E = ark_bn254::Bn254;
type F = ark_bn254::Fr;

fn random_cm<R: RngCore + CryptoRng>(n: usize, rng: &mut R) -> Vec<CM<F>> {
    let cm: Vec<CM<F>> = (0..n)
        .map(|_| CM {
            msg: F::from(100u32),
            rand: F::rand(rng),
        })
        .collect();
    cm
}

#[test]
fn test_cc_groth16_without_key() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    println!("The number of users : {}", *N);
    println!("Generate parameters...");

    let mock = BccCircuit::<F>::default(*N);

    println!("Generate CRS...");
    let (pk, vk) = BccGroth16::<E>::setup(mock, &mut rng).unwrap();
    // assert_eq!(vk.gamma_abc_g1.len(), 4 + 4 * (*N), "vk length invalid");

    // make random cm (prev, curr)
    let list_cm = random_cm(*N, &mut rng);
    let committed_witness = list_cm
        .iter()
        .flat_map(|cm| [cm.msg, cm.rand])
        .collect::<Vec<F>>();

    // make random list cm (g1)
    let mut list_cm_g1 = vec![];
    for CM { msg, rand } in list_cm.iter() {
        let cm_g1 = pk.ck.batched[0].mul(msg) + pk.ck.batched[1].mul(rand);
        list_cm_g1.push(cm_g1.into_affine());
    }

    let (proof_dependent_cm, tau) =
        BccGroth16::<E>::commit(&pk.ck, &committed_witness, &mut rng).unwrap();

    // make circuit
    let circuit = BccCircuit::<F>::new(list_cm, tau);

    println!("Generate proof...");
    let proof =
        BccGroth16::<E>::prove(&pk, circuit.clone(), &proof_dependent_cm, &mut rng).unwrap();

    let public_inputs = [&list_cm_g1[..], &[proof_dependent_cm.cm]].concat();
    assert_eq!(public_inputs.len(), *N + 1, "public inputs length invalid");
    println!("Verify proof...");
    assert!(BccGroth16::<E>::verify(&vk, &proof, public_inputs.as_slice()).unwrap());
}

#[test]
fn test_setup_bn254() {
    let c_path = CString::new(PATH.as_str()).unwrap();
    let c_path = c_path.as_ptr();
    let is_success = setup_bn254(c_path, *N);
    let is_pk_file_exist = fs::metadata(format!("{}{}", *PATH, PK_FILE.as_str())).is_ok();
    let is_vk_file_exist = fs::metadata(format!("{}{}", *PATH, VK_FILE.as_str())).is_ok();
    assert!(is_success && is_pk_file_exist && is_vk_file_exist);
}

#[test]
fn test_prove_bn254() {
    test_setup_bn254();
    println!("prove_bn254_test: start");
    let vec = vec!["1"; *N];
    let vec_string = vec.join(",");
    let c_path = CString::new(PATH.as_str()).unwrap();
    let c_path = c_path.as_ptr();
    let vec_ptr = CString::new(vec_string).unwrap();
    let vec_ptr = vec_ptr.as_ptr();
    let proof = prove_bn254(c_path, vec_ptr, vec_ptr);
    assert!(!proof.is_null());
}
