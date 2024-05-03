//! An implementation of the [`Groth16`] zkSNARK.
//!
//! [`Groth16`]: https://eprint.iacr.org/2016/260.pdf
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    missing_docs
)]
#![allow(clippy::many_single_char_names, clippy::op_ref)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate ark_std;

#[cfg(feature = "r1cs")]

/// Reduce an R1CS instance to a *Quadratic Arithmetic Program* instance.
pub use ark_groth16::r1cs_to_qap;

/// Data structures used by the prover, verifier, and generator.
pub mod data_structures;

/// Generate public parameters for the Groth16 zkSNARK construction.
pub mod generator;

/// Create proofs for the Groth16 zkSNARK construction.
pub mod prover;

/// Verify proofs for the Groth16 zkSNARK construction.
pub mod verifier;

pub use self::data_structures::*;
pub use self::verifier::*;

// #[cfg(feature = "r1cs")]
pub mod crypto;
pub mod transcript;
pub mod utils;

pub mod bcc_snark;
use bcc_snark::{BccSNARK, CircuitSpecificSetupBccSNARK};

use ark_ec::pairing::Pairing;
use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::rand::RngCore;
use ark_std::{marker::PhantomData, vec::Vec};

/// The SNARK of [[Groth16]](https://eprint.iacr.org/2016/260.pdf).
/// M: message vector size
pub struct BccGroth16<E: Pairing, QAP: R1CSToQAP = LibsnarkReduction, const M: usize = 1> {
    _p: PhantomData<(E, QAP)>,
}

impl<E: Pairing, QAP: R1CSToQAP> BccSNARK<E, E::ScalarField> for BccGroth16<E, QAP> {
    type ProvingKey = ProvingKey<E>;
    type VerifyingKey = VerifyingKey<E>;
    type CommittingKey = CommittingKey<E>;
    type Proof = Proof<E>;
    type Commitment = Commitment<E>;
    type ProcessedVerifyingKey = PreparedVerifyingKey<E>;
    type Error = SynthesisError;

    fn circuit_specific_setup<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore>(
        circuit: C,
        num_committed_witness: usize,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error> {
        let pk =
            Self::generate_random_parameters_with_reduction(circuit, num_committed_witness, rng)?;
        let vk = pk.vk.clone();

        Ok((pk, vk))
    }

    fn commit<R: RngCore>(
        circuit_ck: &Self::CommittingKey,
        committed_witness: &[E::ScalarField],
        rng: &mut R,
    ) -> Result<(Vec<E::G1Affine>, Self::Commitment, E::ScalarField), Self::Error> {
        Self::commit_proof_dependent_cm(circuit_ck, committed_witness, rng)
    }

    fn prove<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore>(
        pk: &Self::ProvingKey,
        circuit: C,
        proof_dependent_cm: &Self::Commitment,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error> {
        Self::create_random_proof_with_reduction(circuit, proof_dependent_cm, pk, rng)
    }

    fn process_vk(
        circuit_vk: &Self::VerifyingKey,
    ) -> Result<Self::ProcessedVerifyingKey, Self::Error> {
        Ok(prepare_verifying_key(circuit_vk))
    }

    fn verify_with_processed_vk(
        circuit_pvk: &Self::ProcessedVerifyingKey,
        proof: &Self::Proof,
        public_inputs: &[E::G1Affine],
    ) -> Result<bool, Self::Error> {
        Ok(Self::verify_proof(circuit_pvk, proof, public_inputs)?)
    }
}

impl<E: Pairing, QAP: R1CSToQAP> CircuitSpecificSetupBccSNARK<E, E::ScalarField>
    for BccGroth16<E, QAP>
{
}

#[cfg(test)]
mod tests {
    use crate::{bcc_snark::BccSNARK, crypto::tree::AggregationTree, BccGroth16};
    use ark_ff::PrimeField;
    use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
    use ark_relations::r1cs::{
        ConstraintSynthesizer, ConstraintSystemRef, Result as R1CSResult, SynthesisError,
    };
    use ark_std::{
        ops::Add,
        rand::{RngCore, SeedableRng},
        test_rng,
        vec::Vec,
    };
    use serde_json::map;

    type E = ark_bn254::Bn254;
    type F = ark_bn254::Fr;

    #[derive(Clone)]
    struct Circuit<F: PrimeField> {
        aggr_msg: Option<F>,
        aggr_rand: Option<F>,
        list_msg: Option<Vec<F>>,
        list_rand: Option<Vec<F>>,
        rand: Option<F>,
    }

    impl<F: PrimeField> ConstraintSynthesizer<F> for Circuit<F> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> R1CSResult<()> {
            let aggr_msg = FpVar::new_input(cs.clone(), || {
                self.aggr_msg.ok_or(SynthesisError::AssignmentMissing)
            })?;

            let aggr_rand = FpVar::new_input(cs.clone(), || {
                self.aggr_rand.ok_or(SynthesisError::AssignmentMissing)
            })?;

            let mut list_msg = Vec::<FpVar<F>>::new_input(cs.clone(), || {
                self.list_msg
                    .clone()
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

            let mut list_rand = Vec::<FpVar<F>>::new_input(cs.clone(), || {
                self.list_rand.ok_or(SynthesisError::AssignmentMissing)
            })?;

            let rand = FpVar::new_input(cs.clone(), || {
                self.rand.ok_or(SynthesisError::AssignmentMissing)
            })?;

            let mut _aggr_msg = list_msg[0].clone();

            let mut nodes = list_msg.len();
            println!("Nodes: {}", nodes);
            let mut coeff = rand.clone();

            while nodes > 1 {
                let even: FpVar<F> = list_msg.iter().skip(1).step_by(2).sum();
                _aggr_msg += even * &coeff;

                coeff = coeff.clone() * &coeff;
                nodes >>= 1;
                for i in 0..nodes {
                    list_msg[i] = list_msg[i << 1].clone().add(list_msg[(i << 1) + 1].clone());
                }
                list_msg.truncate(nodes);
            }

            let _aggr_rand = list_rand.compute_root(rand.clone());

            aggr_msg.enforce_equal(&_aggr_msg)?;
            aggr_rand.enforce_equal(&_aggr_rand)?;

            Ok(())
        }
    }

    #[test]
    fn test_circuit() {
        const BATCH_SIZE: usize = 1024;
        const M: usize = 1;
        let num_committed_witness: usize = (M + 1) * (BATCH_SIZE + 1) + 1; // agg(M + 1), list[BATCH_SIZE](M + 1), tau
        let aggr_msg = F::from(0u64);
        let aggr_rand = F::from(0u64);
        let list_msg = vec![F::from(0u64); M];
        let list_rand = vec![F::from(0u64); M];
        let rand = F::from(0u64);

        let circuit = Circuit {
            aggr_msg: Some(aggr_msg),
            aggr_rand: Some(aggr_rand),
            list_msg: Some(list_msg.clone()),
            list_rand: Some(list_rand.clone()),
            rand: Some(rand),
        };

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let (pk, vk) =
            BccGroth16::<E>::circuit_specific_setup(circuit, num_committed_witness, &mut rng)
                .unwrap();

        let committed_witness = [&list_msg[..], &list_rand[..]].concat();

        println!("Commit proof dependent");
        let (_list_cm, proof_dependent_cm, tau) =
            BccGroth16::<E>::commit(&pk.ck, committed_witness.as_slice(), &mut rng).unwrap();

        let circuit = Circuit {
            aggr_msg: Some(aggr_msg),
            aggr_rand: Some(aggr_rand),
            list_msg: Some(list_msg.clone()),
            list_rand: Some(list_rand.clone()),
            rand: Some(tau),
        };

        println!("Commitment generation done...");

        println!("Generate proof...");
        let _proof = BccGroth16::<E>::prove(&pk, circuit, &proof_dependent_cm, &mut rng).unwrap();
    }
}
