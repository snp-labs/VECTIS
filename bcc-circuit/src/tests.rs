use super::*;
use crate::{circuit::BccCircuit, utils::compute_hash};

use ark_ff::{QuadExtField, UniformRand};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use ark_std::{
    rand::{CryptoRng, RngCore, SeedableRng},
    test_rng,
};
use bccgroth16::{
    crypto::{commitment::CM, tree::AggregationTree},
    BccGroth16,
};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref PATH: String = "./".to_string();
    pub static ref PK_FILE: String = "cbdc.pk.dat".to_string();
    pub static ref VK_FILE: String = "cbdc.vk.dat".to_string();
    pub static ref PRF_FILE: String = "cbdc.proof.dat".to_string();
    pub static ref LOG_N: usize = 7;
}

type E = ark_bn254::Bn254;
type F = ark_bn254::Fr;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

fn random_cm<R: RngCore + CryptoRng>(n: usize, rng: &mut R) -> Vec<CM<F>> {
    let cm: Vec<CM<F>> = (0..n)
        .map(|_| CM {
            msg: F::from(100u32),
            rand: F::rand(rng),
        })
        .collect();
    cm
}

fn print_mock<E: Pairing>(
    vk: &VerifyingKey<E>,
    list_cm: &Vec<E::G1Affine>,
    proof: &Proof<E>,
    proof_cm: &E::G1Affine,
    tau: E::ScalarField,
) {
    println!("vk: {:?}", vk.to_string());
    println!("list_cm: {:?}", list_cm);
    println!("proof: {:?}", proof.to_string());
    println!("proof_cm: {:?}", proof_cm);
    println!("tau: {:?}", tau.to_string());
}

#[test]
fn test_bcc_groth16_num_constraints() {
    let mut result: Vec<usize> = vec![];
    for n in 0..=*LOG_N {
        let cs_timer = start_timer!(|| format!("Batch Size: 2^{}", n));
        let mock = BccCircuit::<F>::default(1 << n);

        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);

        let _ = mock.generate_constraints(cs.clone());

        cs.finalize();
        result.push(cs.num_constraints());
        end_timer!(cs_timer);
    }

    println!("{:?}", result);
    assert_eq!(result.len(), *LOG_N + 1, "invalid number of test");
}

#[test]
fn test_cc_groth16_without_key() {
    for n in 0..=*LOG_N {
        let batch_size = 1 << n;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        println!("Generate parameters...");

        let mock = BccCircuit::<F>::default(batch_size);

        println!("Generate CRS...");
        let (pk, vk) = BccGroth16::<E>::setup(mock, &mut rng).unwrap();

        // make random cm (prev, curr)
        let list_cm = random_cm(batch_size, &mut rng);
        let committed_witness = list_cm
            .iter()
            .flat_map(|cm| [cm.msg, cm.rand])
            .collect::<Vec<F>>();

        let (list_cm_g1, proof_dependent_cm, _) =
            BccGroth16::<E>::commit(&pk.ck, &committed_witness, &mut rng).unwrap();

        let public_inputs = [&list_cm_g1[..], &[proof_dependent_cm.cm]].concat();
        let tau = compute_hash::<E>(&[proof_dependent_cm.cm]);

        // make circuit
        let circuit = BccCircuit::<F>::new(list_cm, tau);

        println!("Generate proof...");
        let proof =
            BccGroth16::<E>::prove(&pk, circuit.clone(), &proof_dependent_cm, &mut rng).unwrap();

        assert_eq!(
            public_inputs.len(),
            batch_size + 1,
            "Invalid Public Statement Size"
        );

        // println!("Verify proof...");
        // assert!(BccGroth16::<E>::verify(&vk, &proof, public_inputs.as_slice()).unwrap());

        print_mock(&vk, &list_cm_g1, &proof, &proof_dependent_cm.cm, tau);
    }
}

#[test]
fn test_setup_bn254() {
    let c_path = CString::new(PATH.as_str()).unwrap();
    let c_path = c_path.as_ptr();
    let is_success = setup_bn254(c_path, 1 << *LOG_N);
    let is_pk_file_exist = fs::metadata(format!("{}{}", *PATH, PK_FILE.as_str())).is_ok();
    let is_vk_file_exist = fs::metadata(format!("{}{}", *PATH, VK_FILE.as_str())).is_ok();
    assert!(is_success && is_pk_file_exist && is_vk_file_exist);
}

#[test]
fn test_prove_bn254() {
    test_setup_bn254();
    println!("prove_bn254_test: start");
    let vec = vec!["1"; 1 << *LOG_N];
    let vec_string = vec.join(",");
    let c_path = CString::new(PATH.as_str()).unwrap();
    let c_path = c_path.as_ptr();
    let vec_ptr = CString::new(vec_string).unwrap();
    let vec_ptr = vec_ptr.as_ptr();
    let proof = prove_bn254(c_path, vec_ptr, vec_ptr);
    assert!(!proof.is_null());
}
