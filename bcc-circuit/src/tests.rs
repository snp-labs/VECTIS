use super::*;
use crate::{circuit::BccCircuit, utils::compute_hash};

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisError,
    SynthesisMode,
};
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
    pub static ref LOG_N: usize = 20;
    pub static ref USE_HASH: bool = true;
}

type E = ark_bn254::Bn254;
type F = ark_bn254::Fr;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

fn random_cm<R: RngCore + CryptoRng>(n: usize, rng: &mut R) -> Vec<CM<F>> {
    let cm: Vec<CM<F>> = (0..n)
        .map(|_| CM {
            msg: F::from(100u32),
            rand: F::from(100u32),
            // rand: F::rand(rng),
        })
        .collect();
    cm
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
fn test_bcc_groth16_key_size() {
    let mut result_pk = vec![];
    let mut result_vk = vec![];
    let mut result_batched = vec![];
    let mut result_proof_dependent = vec![];

    for n in 0..=*LOG_N {
        let batch_size = 1 << n;
        let num_committed_witness = 2 * (batch_size + 1) + 1;
        println!("Batch Size: {}", batch_size);

        let mock = BccCircuit::<F>::default(batch_size);
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let (pk, vk) = BccGroth16::<E>::setup(mock, num_committed_witness, &mut rng).unwrap();

        let mut pk_bytes = Vec::new();
        pk.serialize_compressed(&mut pk_bytes).unwrap();
        result_pk.push(pk_bytes.len());

        let mut vk_bytes = Vec::new();
        vk.serialize_compressed(&mut vk_bytes).unwrap();
        result_vk.push(vk_bytes.len());

        let mut batched_bytes = Vec::new();
        pk.ck
            .batched
            .serialize_compressed(&mut batched_bytes)
            .unwrap();
        result_batched.push(batched_bytes.len());

        let mut proof_dependent_bytes = Vec::new();
        pk.ck
            .proof_dependent
            .serialize_compressed(&mut proof_dependent_bytes)
            .unwrap();
        result_proof_dependent.push(proof_dependent_bytes.len());
    }
    println!("{:?}", result_pk);
    println!("{:?}", result_vk);
    println!("{:?}", result_batched);
    println!("{:?}", result_proof_dependent);

    assert_eq!(result_pk.len(), *LOG_N + 1, "invalid number of tests 1");
    assert_eq!(result_vk.len(), *LOG_N + 1, "invalid number of tests 2");
    assert_eq!(
        result_batched.len(),
        *LOG_N + 1,
        "invalid number of tests 3"
    );
    assert_eq!(
        result_proof_dependent.len(),
        *LOG_N + 1,
        "invalid number of tests 4"
    );
}

#[test]
fn test_bcc_groth16_without_key() {
    for n in 1..=*LOG_N {
        let batch_size = 1 << n;
        let num_committed_witness = 2 * (batch_size + 1) + 1;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        println!("Generate parameters...");

        let mock = BccCircuit::<F>::default(batch_size);

        println!("Generate CRS...");
        let (pk, vk) = BccGroth16::<E>::setup(mock, num_committed_witness, &mut rng).unwrap();
        // assert_eq!(vk.gamma_abc_g1.len(), 4 + 4 * (*N), "vk length invalid");

        // make random cm (prev, curr)
        let list_cm = random_cm(batch_size, &mut rng);
        let committed_witness = list_cm
            .iter()
            .flat_map(|cm| [cm.msg, cm.rand])
            .collect::<Vec<F>>();

        let (list_cm_g1, proof_dependent_cm, tau) =
            BccGroth16::<E>::commit(&pk.ck, &committed_witness, &mut rng).unwrap();

        let tau = if *USE_HASH {
            compute_hash::<E>(&[proof_dependent_cm.cm])
        } else {
            tau
        };

        // make circuit
        let circuit = BccCircuit::<F>::new(list_cm, tau);

        println!("Generate proof...");
        let proof =
            BccGroth16::<E>::prove(&pk, circuit.clone(), &proof_dependent_cm, &mut rng).unwrap();

        let public_inputs = [&list_cm_g1[..], &[proof_dependent_cm.cm]].concat();
        assert_eq!(
            public_inputs.len(),
            batch_size + 1,
            "Invalid Public Statement Size"
        );

        if !*USE_HASH {
            println!("Verify proof...");
            assert!(BccGroth16::<E>::verify(&vk, &proof, public_inputs.as_slice()).unwrap());
        }

        println!("batch size: {}", batch_size);
        println!("const cm = {:?}", list_cm_g1[0].to_vec());
        println!(
            "const proof = {:?}",
            [proof.to_vec(), proof_dependent_cm.cm.to_vec()].concat()
        );
        println!("const vk = {:?}", vk.to_vec());
        println!("\nexport const batch{} = {{ cm, proof, vk }}", batch_size);
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
