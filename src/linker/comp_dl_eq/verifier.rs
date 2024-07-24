use ark_ec::CurveGroup;

use crate::crypto::protocol::transcript::TranscriptProtocol;

use super::{CompDLEq, Instance, Proof, PublicParameters};

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
}
