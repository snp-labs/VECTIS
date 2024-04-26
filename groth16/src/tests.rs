use ark_bn254::Bn254;
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsProjective, Fr};
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use ark_std::{
    end_timer,
    rand::{RngCore, SeedableRng},
    start_timer, test_rng,
};

use crate::{circuit::BatchCommitmentCircuit, commitments::Message, LOG_N};

type E = Bn254;
type C = EdwardsProjective;
type GG = EdwardsVar;

#[test]
fn test_batch_commit_groth16_num_constraints() {
    let mut result: Vec<usize> = vec![];
    for n in 0..=*LOG_N {
        let cs_timer = start_timer!(|| format!("Batch Size: 2^{}", n));
        let mock = BatchCommitmentCircuit::<C, GG>::default(1 << n);

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

        let mock = BatchCommitmentCircuit::<C, GG>::default(batch_size);

        println!("Generate CRS...");
        let (pk, vk) = Groth16::<Bn254>::setup(mock, &mut rng).unwrap();
        let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

        // make random cm (prev, curr)
        let ck = vec![C::rand(&mut rng).into_affine(); 2];
        let msgs = vec![Fr::rand(&mut rng); batch_size];
        let opens = vec![Fr::rand(&mut rng); batch_size];

        // make circuit
        let circuit = BatchCommitmentCircuit::<C, GG>::new(ck, msgs, opens);

        println!("Generate proof...");
        let proof = Groth16::<E>::prove(&pk, circuit.clone(), &mut rng).unwrap();

        let ck = circuit
            .ck
            .unwrap()
            .iter()
            .flat_map(|p| [p.generator.x, p.generator.y])
            .collect::<Vec<_>>();

        let cms = circuit
            .cms
            .unwrap()
            .iter()
            .flat_map(|cm| [cm.x, cm.y])
            .collect::<Vec<_>>();

        let public_inputs = [&ck[..], &cms[..]].concat();
        println!("Verify proof...");
        assert!(
            Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap(),
            "Verification failed"
        )
    }
}
