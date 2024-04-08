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

pub mod bcc_snark;
use bcc_snark::{BccSNARK, CircuitSpecificSetupBccSNARK};

use ark_ec::pairing::Pairing;
use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::rand::RngCore;
use ark_std::{marker::PhantomData, vec::Vec};

/// The SNARK of [[Groth16]](https://eprint.iacr.org/2016/260.pdf).
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
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error> {
        let pk = Self::generate_random_parameters_with_reduction(circuit, rng)?;
        let vk = pk.vk.clone();

        Ok((pk, vk))
    }

    fn commit<R: RngCore>(
        circuit_ck: &Self::CommittingKey,
        committed_witness: &[E::ScalarField],
        rng: &mut R,
    ) -> Result<(Self::Commitment, E::ScalarField), Self::Error> {
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
