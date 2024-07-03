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
    use crate::{
        bcc_snark::{BccSNARK, CircuitSpecificSetupBccSNARK},
        crypto::commitment::{constraints::CMVar, CM},
        BccGroth16,
    };
    use ark_ff::{PrimeField, Zero};
    use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::{
        rand::{CryptoRng, RngCore, SeedableRng},
        test_rng,
        vec::Vec,
    };

    type E = ark_bn254::Bn254;
    type F = ark_bn254::Fr;

    fn random_cm<R: RngCore + CryptoRng>(n: usize, rng: &mut R) -> Vec<CM<F>> {
        let cm: Vec<CM<F>> = (0..n)
            .map(|_| CM {
                msg: F::from(100u32),
                rand: F::from(100u32),
            })
            .collect();
        cm
    }

    #[derive(Clone)]
    pub struct BccCircuit<F: PrimeField> {
        pub aggr: Option<CM<F>>,
        pub list_cm: Option<Vec<CM<F>>>,
        pub rand: Option<F>,
    }

    impl<F: PrimeField> BccCircuit<F> {
        /// Create a new circuit
        pub fn new(list_cm: Vec<CM<F>>, rand: F) -> Self {
            let mut aggr = CM::zero();
            let mut evaluate = rand;
            for &cm in list_cm.iter() {
                aggr += cm * evaluate;
                evaluate *= rand;
            }
            Self {
                aggr: Some(aggr),
                list_cm: Some(list_cm),
                rand: Some(rand),
            }
        }

        /// Create a default circuit with all Zero
        pub fn default(n: usize) -> Self {
            Self {
                aggr: Some(CM::zero()),
                list_cm: Some(vec![CM::zero(); n]),
                rand: Some(F::zero()),
            }
        }
    }

    impl<F: PrimeField> ConstraintSynthesizer<F> for BccCircuit<F> {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<F>,
        ) -> ark_relations::r1cs::Result<()> {
            let aggr = CMVar::new_witness(cs.clone(), || {
                self.aggr.ok_or(SynthesisError::AssignmentMissing)
            })?;

            let list_cm = Vec::<CMVar<F>>::new_witness(cs.clone(), || {
                self.list_cm.ok_or(SynthesisError::AssignmentMissing)
            })?;

            let rand = FpVar::new_witness(cs.clone(), || {
                self.rand.ok_or(SynthesisError::AssignmentMissing)
            })?;

            let mut _aggr = CMVar::new_constant(cs.clone(), CM::zero())?;
            let mut evaluate = rand.clone();
            for cm in list_cm.iter() {
                _aggr += cm.clone() * &evaluate;
                evaluate *= &rand;
            }

            aggr.enforce_equal(&_aggr)?;
            Ok(())
        }
    }

    #[test]
    fn test_circuit() {
        let batch_size: usize = 1 << 10;
        let num_committed_witness = 2 * (batch_size + 1) + 1;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        println!("Generate parameters...");
        let mock = BccCircuit::<F>::default(batch_size);

        println!("Generate CRS...");
        let (pk, vk) = BccGroth16::<E>::setup(mock, num_committed_witness, &mut rng).unwrap();

        // make random cm (prev, curr)
        let list_cm = random_cm(batch_size, &mut rng);
        let committed_witness = list_cm
            .iter()
            .flat_map(|cm| [cm.msg, cm.rand])
            .collect::<Vec<F>>();

        let (list_cm_g1, proof_dependent_cm, tau) =
            BccGroth16::<E>::commit(&pk.ck, &committed_witness, &mut rng).unwrap();

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

        assert!(BccGroth16::<E>::verify(&vk, &proof, public_inputs.as_slice()).unwrap());
    }
}
