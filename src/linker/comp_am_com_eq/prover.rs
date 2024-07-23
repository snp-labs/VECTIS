use ark_ec::CurveGroup;
use ark_ff::PrimeField;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::{data_structure::*, CompAmComEq};

impl<C: CurveGroup> CompAmComEq<C> {
    pub fn compute_depth_commitment_from_updated_parameters(
        pp: &PublicParameters<C>,
        proof: &PartialProof<C>,
    ) -> Result<DepthCommitment<C>, ()> {
        if proof.z.len() != pp.g.len() || proof.z.len() != pp.g_hat.len() {
            return Err(());
        }
        let commit_timer = start_timer!(|| "CompAmComEq::Depth Commit");
        let mid = proof.z.len() / 2;

        let z_bigint = cfg_iter!(proof.z)
            .map(|z| z.into_bigint())
            .collect::<Vec<_>>();

        let lr_timer = start_timer!(|| "Compute LR");
        let left = C::msm_bigint(&pp.g[mid..], &z_bigint[..mid]);
        let right = C::msm_bigint(&pp.g[..mid], &z_bigint[mid..]);

        end_timer!(lr_timer);

        let lr_hat_timer = start_timer!(|| "Compute LR Hat");
        let left_hat = C::msm_bigint(&pp.g_hat[mid..], &z_bigint[..mid]);
        let right_hat = C::msm_bigint(&pp.g_hat[..mid], &z_bigint[mid..]);

        end_timer!(lr_hat_timer);
        end_timer!(commit_timer);

        Ok(DepthCommitment {
            left: left.into_affine(),
            right: right.into_affine(),
            left_hat: left_hat.into_affine(),
            right_hat: right_hat.into_affine(),
        })
    }

    /// Update the public parameters and the proof with the challenge.
    /// Prover also needs to update the proof with the challenge.
    pub fn update_pp_and_prf_with_challenge(
        pp: &PublicParameters<C>,
        proof: &PartialProof<C>,
        commitment: &DepthCommitment<C>,
        challenge: C::ScalarField,
    ) -> Result<(PublicParameters<C>, PartialProof<C>), ()> {
        let pp = Self::update_with_challenge(pp, commitment, challenge)?;

        let proof_timer = start_timer!(|| "Update proof");
        let mid = proof.z.len() / 2;
        let z = cfg_iter!(proof.z[..mid])
            .zip(&proof.z[mid..])
            .map(|(l, r)| *l + challenge * r)
            .collect::<Vec<_>>();
        end_timer!(proof_timer);

        Ok((pp, PartialProof { z }))
    }
}
