use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalSerialize;

use crate::crypto::protocol::transcript::TranscriptProtocol;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::{Commitment, CompDLEq, Instance, Proof, PublicParameters};

impl<C: CurveGroup> CompDLEq<C> {
    pub fn verify_proof(
        pp: &PublicParameters<C>,
        instance: &Instance<C>,
        proof: &Proof<C>,
        transcript: &mut impl TranscriptProtocol,
    ) -> Result<bool, ()> {
        let threshold = 2;
        if proof.z.len() != threshold || pp.g.len() != pp.g_hat.len() {
            return Err(());
        }

        let verifier_timer = start_timer!(|| "CompDLEq::Verifier");
        let mut pp = pp.clone();
        let mut instance = instance.clone();
        proof.commitments.iter().for_each(|commitment| {
            let challenge = Self::compute_challenge(commitment, transcript);

            (pp, instance) =
                Self::update_public_parameters_and_instance(&pp, &instance, commitment, challenge)
                    .unwrap();
        });

        if proof.z.len() != pp.g.len() {
            return Err(());
        }
        let y_real = (pp.g[0] * proof.z[0] + pp.g[1] * proof.z[1]).into_affine();
        let y_hat_real = (pp.g_hat[0] * proof.z[0] + pp.g_hat[1] * proof.z[1]).into_affine();
        end_timer!(verifier_timer);

        Ok(instance.y == y_real && instance.y_hat == y_hat_real)
    }

    pub fn compute_challenge(
        commitment: &Commitment<C>,
        transcript: &mut impl TranscriptProtocol,
    ) -> C::ScalarField {
        let commitment = vec![
            commitment.left,
            commitment.right,
            commitment.left_hat,
            commitment.right_hat,
        ];

        let bytes = cfg_iter!(commitment)
            .map(|p| {
                let mut _bytes = vec![];
                let (x, y) = p.xy().unwrap();
                y.serialize_uncompressed(&mut _bytes).unwrap();
                x.serialize_uncompressed(&mut _bytes).unwrap();
                _bytes.reverse();
                _bytes
            })
            .flatten()
            .collect::<Vec<_>>();

        transcript.append(b"commitments", &bytes[..]);
        transcript.challenge_scalar(b"challenge")
    }
}
