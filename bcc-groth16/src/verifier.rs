use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_relations::r1cs::{Result as R1CSResult, SynthesisError};
use core::ops::{AddAssign, Neg};

use crate::{
    crypto::tree::AggregationTree,
    r1cs_to_qap::R1CSToQAP,
    transcript::{Transcript, TranscriptProtocol},
    BccGroth16, PreparedVerifyingKey, Proof, VerifyingKey,
};

/// Prepare the verifying key `vk` for use in proof verification.
pub fn prepare_verifying_key<E: Pairing>(vk: &VerifyingKey<E>) -> PreparedVerifyingKey<E> {
    PreparedVerifyingKey {
        vk: vk.clone(),
        alpha_g1_beta_g2: E::pairing(vk.alpha_g1, vk.beta_g2).0,
        gamma_g2_neg_pc: vk.gamma_g2.into_group().neg().into_affine().into(),
        delta_g2_neg_pc: vk.delta_g2.into_group().neg().into_affine().into(),
    }
}

impl<E: Pairing, QAP: R1CSToQAP, const M: usize> BccGroth16<E, QAP, M> {
    /// Prepare proof inputs for use with [`verify_proof_with_prepared_inputs`], wrt the prepared
    /// verification key `pvk` and instance public inputs.
    pub fn prepare_inputs(
        pvk: &PreparedVerifyingKey<E>,
        public_inputs: &[E::G1Affine],
    ) -> R1CSResult<E::G1> {
        let mut transcript = Transcript::new(b"bcc_groth16");

        if pvk.vk.gamma_abc_g1.len() != 2 {
            println!("vk len differ {}", pvk.vk.gamma_abc_g1.len());
        }

        let (proof_dependent_cm, list_cm) = public_inputs.split_last().unwrap();
        let list_cm = list_cm
            .iter()
            .map(|cm| cm.into_group())
            .collect::<Vec<E::G1>>();

        // Transcript proof-dependent commitment and the list commitments
        for i in 0..list_cm.len() {
            transcript.append_message(b"list commitment", &list_cm[i].to_string().as_bytes());
        }
        transcript.append_message(
            b"proof dependent commitment",
            proof_dependent_cm.to_string().as_bytes(),
        );

        // Challenge tau
        let tau: E::ScalarField = transcript.challenge_scalar(b"challenge");

        let mut g_ic = pvk.vk.gamma_abc_g1[0].into_group();
        let cm_aggr = list_cm.compute_root(tau);
        let tau_g1 = pvk.vk.gamma_abc_g1[1].mul_bigint(tau.into_bigint());
        g_ic.add_assign(cm_aggr);
        g_ic.add_assign(proof_dependent_cm);
        g_ic.add_assign(tau_g1);

        Ok(g_ic)
    }

    /// Verify a Groth16 proof `proof` against the prepared verification key `pvk` and prepared public
    /// inputs. This should be preferred over [`verify_proof`] if the instance's public inputs are
    /// known in advance.
    pub fn verify_proof_with_prepared_inputs(
        pvk: &PreparedVerifyingKey<E>,
        proof: &Proof<E>,
        prepared_inputs: &E::G1,
    ) -> R1CSResult<bool> {
        let qap = E::multi_miller_loop(
            [
                <E::G1Affine as Into<E::G1Prepared>>::into(proof.a),
                prepared_inputs.into_affine().into(),
                proof.c.into(),
            ],
            [
                proof.b.into(),
                pvk.gamma_g2_neg_pc.clone(),
                pvk.delta_g2_neg_pc.clone(),
            ],
        );

        let test = E::final_exponentiation(qap).ok_or(SynthesisError::UnexpectedIdentity)?;

        Ok(test.0 == pvk.alpha_g1_beta_g2)
    }

    /// Verify a Batched cc-Grtoh16 proof `proof` against the prepared verification key `pvk`,
    /// with respect to the instance `public_inputs`.
    /// public_inputs = list_cm
    pub fn verify_proof(
        pvk: &PreparedVerifyingKey<E>,
        proof: &Proof<E>,
        public_inputs: &[E::G1Affine],
    ) -> R1CSResult<bool> {
        let prepared_inputs = Self::prepare_inputs(pvk, public_inputs)?;
        Self::verify_proof_with_prepared_inputs(pvk, proof, &prepared_inputs)
    }
}
