use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng,
    vec::Vec,
    Zero,
};

use crate::{
    crypto::commitment::{
        pedersen::{Pedersen, PedersenGadget},
        BatchCommitmentGadget, BatchCommitmentScheme,
    },
    gro::CCGroth16,
    snark::{CircuitSpecificSetupCCSNARK, CCSNARK},
};

#[derive(Clone)]
struct BatchCommitmentCircuit<C: CurveGroup> {
    // public input
    pub tau: Option<C::ScalarField>,

    // committed witness
    pub aggregation: Option<Vec<C::ScalarField>>,
    pub commitments: Option<Vec<Vec<C::ScalarField>>>,
}

impl<C: CurveGroup> BatchCommitmentCircuit<C>
where
    C::BaseField: PrimeField,
{
    pub fn new(commitments: Vec<Vec<C::ScalarField>>, tau: C::ScalarField) -> Self {
        let aggregation = Pedersen::<C>::cc_aggregate(&commitments, tau, None);

        Self {
            aggregation: Some(aggregation),
            commitments: Some(commitments),
            tau: Some(tau),
        }
    }

    pub fn mock(batch_size: usize) -> Self {
        Self {
            aggregation: Some(vec![C::ScalarField::zero(); 2]),
            commitments: Some(vec![vec![C::ScalarField::zero(); 2]; batch_size]),
            tau: Some(C::ScalarField::zero()),
        }
    }
}

impl<C: CurveGroup> ConstraintSynthesizer<C::ScalarField> for BatchCommitmentCircuit<C>
where
    C::BaseField: PrimeField,
{
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

fn test_commitments<F: PrimeField>(num_commitments: usize, length: usize) -> Vec<Vec<F>> {
    let mut commitments = vec![];
    for i in 0..num_commitments {
        commitments.push(vec![F::from((i + 1) as u64); length]);
    }
    commitments
}

pub mod bn254 {

    use super::*;

    type C = ark_bn254::G1Projective;
    type E = ark_bn254::Bn254;
    type F = ark_bn254::Fr;

    #[test]
    fn bn254_batch_commitment_circuit() {
        let log_n = 3;
        for n in 1..=log_n {
            let batch_size = 1 << n;
            let num_aggregation_variables = 2;
            let num_committed_witness_variables = num_aggregation_variables + batch_size * 2;
            let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

            println!("Generate parameters...");

            let mock = BatchCommitmentCircuit::<C>::mock(batch_size);

            println!("Generate CRS...");
            let (pk, vk) = CCGroth16::<E>::setup(
                mock,
                num_aggregation_variables,
                num_committed_witness_variables,
                &mut rng,
            )
            .unwrap();

            // make random cm (prev, curr)
            let commitments = test_commitments::<F>(batch_size, 2);

            // Batch Commitment Module
            let (commitments_g1, proof_dependent_commitment_g1) = Pedersen::<C>::batch_commit(
                &commitments,
                &pk.ck.batch_g1,
                &pk.ck.proof_dependent_g1,
            );
            let tau = Pedersen::<C>::challenge(&commitments_g1, &proof_dependent_commitment_g1);

            // Make circuit
            let circuit = BatchCommitmentCircuit::<C>::new(commitments, tau);

            println!("Generate proof...");
            let mut proof = CCGroth16::<E>::prove(&pk, circuit.clone(), &mut rng).unwrap();

            let public_inputs = vec![tau];

            println!("Verify proof...");
            // Aggregate commitments
            let aggregation_g1 = Pedersen::<C>::aggregate(&commitments_g1, tau);
            // Update proof dependent commitment
            proof.d = (proof.d.into_group() + aggregation_g1.into_group()).into_affine();
            assert!(
                CCGroth16::<E>::verify(&vk, public_inputs.as_slice(), &proof).unwrap(),
                "Invalid Proof"
            );
        }
    }
}
