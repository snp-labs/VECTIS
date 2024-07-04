use std::time::Instant;

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{
    rand::{CryptoRng, RngCore},
    vec::Vec,
    Zero,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::utils::*;

use crate::{
    crypto::commitment::{
        pedersen::{Pedersen, PedersenGadget},
        BatchCommitmentGadget, BatchCommitmentScheme,
    },
    gro::CCGroth16,
    snark::{CircuitSpecificSetupCCSNARK, CCSNARK},
    solidity::Solidity,
};

#[derive(Clone)]
struct BatchCommitmentCircuit<C: CurveGroup> {
    // public input
    pub tau: Option<C::ScalarField>,

    // committed witness
    pub aggregation: Option<Vec<C::ScalarField>>,
    pub commitments: Option<Vec<Vec<C::ScalarField>>>,
}

impl<C: CurveGroup> BatchCommitmentCircuit<C> {
    pub fn new(commitments: Vec<Vec<C::ScalarField>>, tau: C::ScalarField) -> Self {
        let slices: Vec<&[C::ScalarField]> = commitments.iter().map(|cm| &cm[..]).collect();
        let aggregation = Pedersen::<C>::scalar_aggregate(&slices[..], tau, None);

        Self {
            tau: Some(tau),
            aggregation: Some(aggregation),
            commitments: Some(commitments),
        }
    }

    pub fn mock(batch_size: usize) -> Self {
        Self {
            tau: Some(C::ScalarField::zero()),
            aggregation: Some(vec![C::ScalarField::zero(); 2]),
            commitments: Some(vec![vec![C::ScalarField::zero(); 2]; batch_size]),
        }
    }
}

impl<C: CurveGroup> ConstraintSynthesizer<C::ScalarField> for BatchCommitmentCircuit<C> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::ScalarField>,
    ) -> ark_relations::r1cs::Result<()> {
        let tau = FpVar::new_input(cs.clone(), || {
            self.tau.ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        let aggregation = Vec::<FpVar<C::ScalarField>>::new_witness(cs.clone(), || {
            self.aggregation
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        let commitments = self
            .commitments
            .ok_or_else(|| SynthesisError::AssignmentMissing)?
            .into_iter()
            .map(|cm| Vec::<FpVar<C::ScalarField>>::new_witness(cs.clone(), || Ok(cm)))
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        PedersenGadget::<C, FpVar<C::ScalarField>>::enforce_equal(
            aggregation,
            commitments,
            tau,
            None,
        )?;

        Ok(())
    }
}

#[derive(Clone)]
struct ZKSTCircuit<C: CurveGroup> {
    // public input
    pub permuted: Option<Vec<C::ScalarField>>,
    pub tau: Option<C::ScalarField>,

    // committed witness
    pub aggregation: Option<Vec<C::ScalarField>>,
    pub current_commitments: Option<Vec<Vec<C::ScalarField>>>,
    pub delta_commitments: Option<Vec<Vec<C::ScalarField>>>,
}

impl<C: CurveGroup> ZKSTCircuit<C> {
    pub fn new(
        permuted: Vec<C::ScalarField>,
        current_commitments: Vec<Vec<C::ScalarField>>,
        delta_commitments: Vec<Vec<C::ScalarField>>,
        tau: C::ScalarField,
    ) -> Self {
        let commitments = [&current_commitments[..], &delta_commitments[..]].concat();
        let slices: Vec<&[C::ScalarField]> = commitments.iter().map(|cm| &cm[..]).collect();
        let aggregation = Pedersen::<C>::scalar_aggregate(&slices, tau, None);

        Self {
            permuted: Some(permuted),
            tau: Some(tau),
            aggregation: Some(aggregation),
            current_commitments: Some(current_commitments),
            delta_commitments: Some(delta_commitments),
        }
    }

    pub fn mock(batch_size: usize) -> Self {
        Self {
            permuted: Some(vec![C::ScalarField::zero(); batch_size]),
            tau: Some(C::ScalarField::zero()),
            aggregation: Some(vec![C::ScalarField::zero(); 2]),
            current_commitments: Some(vec![vec![C::ScalarField::zero(); 2]; batch_size]),
            delta_commitments: Some(vec![vec![C::ScalarField::zero(); 2]; batch_size]),
        }
    }
}

impl<C: CurveGroup> ConstraintSynthesizer<C::ScalarField> for ZKSTCircuit<C> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::ScalarField>,
    ) -> ark_relations::r1cs::Result<()> {
        let permuted = Vec::<FpVar<C::ScalarField>>::new_input(cs.clone(), || {
            self.permuted
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        let tau = FpVar::new_input(cs.clone(), || {
            self.tau.ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        let aggregation = Vec::<FpVar<C::ScalarField>>::new_witness(cs.clone(), || {
            self.aggregation
                .ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        let current_commitments = self
            .current_commitments
            .ok_or_else(|| SynthesisError::AssignmentMissing)?
            .into_iter()
            .map(|cm| Vec::<FpVar<C::ScalarField>>::new_witness(cs.clone(), || Ok(cm)))
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let delta_commitments = self
            .delta_commitments
            .ok_or_else(|| SynthesisError::AssignmentMissing)?
            .into_iter()
            .map(|cm| Vec::<FpVar<C::ScalarField>>::new_witness(cs.clone(), || Ok(cm)))
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        // permtation check
        let permutation = permuted
            .iter()
            .fold(FpVar::Constant(C::ScalarField::zero()), |acc, msg| {
                acc * (msg + &tau)
            });

        let _permutation = delta_commitments
            .iter()
            .fold(FpVar::Constant(C::ScalarField::zero()), |acc, msg| {
                acc * (&msg[0] + &tau)
            });

        _permutation
            .enforce_equal(&permutation)
            .expect("Permutation Check");

        // aggregation check
        let commitments =
            [current_commitments, delta_commitments].concat::<Vec<FpVar<C::ScalarField>>>();
        PedersenGadget::<C, FpVar<C::ScalarField>>::enforce_equal(
            aggregation,
            commitments,
            tau,
            None,
        )
        .expect("Aggregation Check");

        Ok(())
    }
}

fn test_commitments<F: PrimeField>(num_commitments: usize, length: usize) -> Vec<Vec<F>> {
    let mut commitments = vec![];
    for i in 0..num_commitments {
        commitments.push(vec![F::from(((i & 1) + 1) as u64); length]);
    }
    commitments
}

// Calculate the time taken to generator, prover and verifier
fn process_batch_commitment_circuit<E: Pairing, R: RngCore + CryptoRng>(
    repeat: usize,
    batch_size: usize,
    rng: &mut R,
) -> (u128, u128, u128)
where
    E::G1Affine: Solidity,
    E::G2Affine: Solidity,
{
    let mut generator = vec![];
    let mut prover = vec![];
    let mut aggregation = vec![];
    for _ in 0..repeat {
        let num_aggregation_variables = 2;
        let num_committed_witness_variables =
            num_aggregation_variables + batch_size * num_aggregation_variables;

        let mock = BatchCommitmentCircuit::<E::G1>::mock(batch_size);

        let gen_instant = Instant::now();
        let (pk, vk, ck) = CCGroth16::<E>::setup(
            mock,
            num_aggregation_variables,
            num_committed_witness_variables,
            rng,
        )
        .unwrap();
        generator.push(gen_instant.elapsed().as_micros());

        // make random cm (prev, curr)
        let commitments = test_commitments::<E::ScalarField>(batch_size, 2);

        // Generage Proof Dependent Commitment
        let committed_witness = cfg_iter!(commitments)
            .flat_map(|cm| cfg_iter!(cm).cloned())
            .collect::<Vec<_>>();
        let proof_dependent_commitment =
            CCGroth16::<E>::commit(&ck, &committed_witness[..], rng).unwrap();

        // Batch Commitment Module
        let slices = cfg_iter!(commitments).map(|cm| &cm[..]).collect::<Vec<_>>();
        let commitments_g1 = Pedersen::<E::G1>::batch_commit(&pk.vk.ck.batch_g1, &slices[..]);
        let tau = Pedersen::<E::G1>::challenge(
            &commitments_g1[batch_size / 2..],
            &proof_dependent_commitment.cm,
        );

        // Make circuit
        let circuit = BatchCommitmentCircuit::<E::G1>::new(commitments, tau);

        let prv_instant = Instant::now();
        let mut proof =
            CCGroth16::<E>::prove(&pk, circuit.clone(), &proof_dependent_commitment, rng).unwrap();
        prover.push(prv_instant.elapsed().as_micros());

        if repeat == 1 {
            println!(
                "const cm = {:?}",
                vec![commitments_g1[0], commitments_g1[1]].to_solidity()
            );
            println!("const proof = {:?}", proof.to_solidity());
            println!("const vk = {:?}", vk.to_solidity());
            println!("\nconst batch{} = {{ cm, proof, vk }}", batch_size / 2);
            println!("\nexport default batch{}", batch_size / 2);
        }

        let public_inputs = [tau];

        let agg_instant = Instant::now();
        // Aggregate commitments
        let aggregation_g1 = Pedersen::<E::G1>::aggregate(&commitments_g1, tau);
        // Update proof dependent commitment
        proof.d = (proof.d.into_group() + aggregation_g1.into_group()).into_affine();
        aggregation.push(agg_instant.elapsed().as_micros());

        // In Batch Commitment Circuit, there is no different public inputs
        assert!(
            CCGroth16::<E>::verify(&vk, public_inputs.as_slice(), &proof).unwrap(),
            "Invalid Proof"
        );
    }

    (generator.average(), prover.average(), aggregation.average())
}

fn process_zkst_circuit<E: Pairing, R: RngCore + CryptoRng>(
    repeat: usize,
    batch_size: usize,
    rng: &mut R,
) -> (u128, u128, u128)
where
    E::G1Affine: Solidity,
    E::G2Affine: Solidity,
    E::ScalarField: Solidity,
{
    let mut generator = vec![];
    let mut prover = vec![];
    let mut aggregation = vec![];
    for _ in 0..repeat {
        let num_aggregation_variables = 2;
        let num_committed_witness_variables = num_aggregation_variables + batch_size * 2;

        let mock = ZKSTCircuit::<E::G1>::mock(batch_size);

        let gen_instant = Instant::now();
        let (pk, vk, ck) = CCGroth16::<E>::setup(
            mock,
            num_aggregation_variables,
            num_committed_witness_variables,
            rng,
        )
        .unwrap();
        generator.push(gen_instant.elapsed().as_micros());

        // make random cm (prev, curr)
        let current_commitments = test_commitments::<E::ScalarField>(batch_size, 2);
        let delta_commitments = current_commitments.clone();
        let commitments = [&current_commitments[..], &delta_commitments[..]].concat();
        let mut permuted = delta_commitments
            .iter()
            .map(|cm| cm[0])
            .collect::<Vec<E::ScalarField>>();
        permuted.sort();

        // Generage Proof Dependent Commitment
        let committed_witness = cfg_iter!(commitments)
            .flat_map(|cm| cfg_iter!(cm).cloned())
            .collect::<Vec<_>>();
        let proof_dependent_commitment =
            CCGroth16::<E>::commit(&ck, &committed_witness[..], rng).unwrap();

        // Batch Commitment Module
        let slices = cfg_iter!(commitments).map(|cm| &cm[..]).collect::<Vec<_>>();
        let commitments_g1 = Pedersen::<E::G1>::batch_commit(&pk.vk.ck.batch_g1, &slices[..]);
        let tau = Pedersen::<E::G1>::challenge(
            &commitments_g1[batch_size / 2..],
            &proof_dependent_commitment.cm,
        );

        // Make circuit
        let circuit = ZKSTCircuit::<E::G1>::new(
            permuted.clone(),
            current_commitments,
            delta_commitments,
            tau,
        );

        let prv_instant = Instant::now();
        let mut proof =
            CCGroth16::<E>::prove(&pk, circuit.clone(), &proof_dependent_commitment, rng).unwrap();
        prover.push(prv_instant.elapsed().as_micros());

        if repeat == 1 {
            println!(
                "const plain = {:?}",
                vec![permuted[0], permuted[permuted.len() >> 1]].to_solidity()
            );
            println!(
                "const cm = {:?}",
                vec![commitments_g1[0], commitments_g1[1]].to_solidity()
            );
            println!("const proof = {:?}", proof.to_solidity());
            println!("const vk = {:?}", vk.to_solidity());
            println!("\nconst batch{} = {{ plain, cm, proof, vk }}", batch_size);
            println!("\nexport default batch{}", batch_size);
        }

        let public_inputs = [permuted.clone(), vec![tau]].concat();

        let agg_instant = Instant::now();
        // Aggregate commitments
        let aggregation_g1 = Pedersen::<E::G1>::aggregate(&commitments_g1, tau);
        // Update proof dependent commitment
        proof.d = (proof.d.into_group() + aggregation_g1.into_group()).into_affine();
        aggregation.push(agg_instant.elapsed().as_micros());

        assert!(
            CCGroth16::<E>::verify(&vk, public_inputs.as_slice(), &proof).unwrap(),
            "Invalid Proof"
        );
    }

    (generator.average(), prover.average(), aggregation.average())
}

pub mod bn254 {
    use ark_relations::r1cs::{ConstraintSystem, OptimizationGoal, SynthesisMode};
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        test_rng,
    };

    use super::*;

    type C = ark_bn254::G1Projective;
    type E = ark_bn254::Bn254;
    type R = StdRng;
    const STATISTICS: bool = true;
    const NUM_REPEAT: usize = if STATISTICS { 1 } else { 10 };
    const LOG_MIN: usize = 1;
    const LOG_MAX: usize = 9;

    #[test]
    fn batch_commitment_circuit_num_constraints() {
        let mut result: Vec<usize> = vec![];
        for n in LOG_MIN..=LOG_MAX {
            let batch_size = 1 << (n + 1);

            let cs_timer = start_timer!(|| format!("Batch Size: 2^{}", n));
            let mock = BatchCommitmentCircuit::<C>::mock(batch_size);

            let cs = ConstraintSystem::new_ref();
            cs.set_optimization_goal(OptimizationGoal::Weight);
            cs.set_mode(SynthesisMode::Setup);

            let _ = mock.generate_constraints(cs.clone());

            cs.finalize();
            result.push(cs.num_constraints());
            end_timer!(cs_timer);
        }

        println!("{:?}", result);
    }

    #[test]
    fn batch_commitment_circuit_without_key() {
        let mut rng = R::seed_from_u64(test_rng().next_u64());
        for n in LOG_MIN..=LOG_MAX {
            let batch_size = 1 << n;

            let (gen, prv, vrf) =
                process_batch_commitment_circuit::<E, R>(NUM_REPEAT, batch_size, &mut rng);
            println!(
                "Batch Size: 2^{} Generator: {} Prover: {} Aggregation: {}",
                n - 1,
                format_time(gen),
                format_time(prv),
                format_time(vrf)
            );
        }
    }

    #[test]
    fn zkst_circuit_without_key() {
        let mut rng = R::seed_from_u64(test_rng().next_u64());
        for n in LOG_MIN..=LOG_MAX {
            let batch_size = 1 << n;

            let (gen, prv, vrf) = process_zkst_circuit::<E, R>(NUM_REPEAT, batch_size, &mut rng);
            println!(
                "Batch Size: 2^{} Generator: {} Prover: {} Aggregation: {}",
                n,
                format_time(gen),
                format_time(prv),
                format_time(vrf)
            );
        }
    }
}
