use std::marker::PhantomData;

use ark_ec::CurveGroup;

mod data_structure;
pub use data_structure::*;

mod generator;
mod prover;
mod verifier;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub struct CompAmComEq<C: CurveGroup> {
    _group: PhantomData<C>,
}

impl<C: CurveGroup> CompAmComEq<C> {
    /// Both the prover and verifier need to update the public parameters
    pub fn update_with_challenge(
        pp: &PublicParameters<C>,
        commitment: &DepthCommitment<C>,
        challenge: C::ScalarField,
    ) -> Result<PublicParameters<C>, ()> {
        let update_timer = start_timer!(|| "CompAmComEq::Update (Fold)");

        let mid = pp.g.len() / 2;
        let sqr_challenge = challenge * challenge;

        let expected_timer = start_timer!(|| "Update expected");
        let y = commitment.left + pp.y * challenge + commitment.right * sqr_challenge;
        let y_hat =
            commitment.left_hat + pp.y_hat * challenge + commitment.right_hat * sqr_challenge;
        end_timer!(expected_timer);

        let g_timer = start_timer!(|| "Update G");
        let g = cfg_iter!(pp.g[..mid])
            .zip(&pp.g[mid..])
            .map(|(l, r)| *l * challenge + r)
            .collect::<Vec<_>>();
        end_timer!(g_timer);

        let g_hat_timer = start_timer!(|| "Update G Hat");
        let g_hat = cfg_iter!(pp.g_hat[..mid])
            .zip(&pp.g_hat[mid..])
            .map(|(l, r)| *l * challenge + r)
            .collect::<Vec<_>>();
        end_timer!(g_hat_timer);
        end_timer!(update_timer);

        Ok(PublicParameters {
            g: C::normalize_batch(&g),
            g_hat: C::normalize_batch(&g_hat),
            y: y.into_affine(),
            y_hat: y_hat.into_affine(),
        })
    }
}
