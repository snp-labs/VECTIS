use ark_ec::CurveGroup;
use ark_ff::{PrimeField, UniformRand};
use ark_std::rand::Rng;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::{
    errors::AmComEqError, AmComEq, Commitment, Proof, PublicParameters, Randomness, Witness,
};

impl<C: CurveGroup> AmComEq<C> {
    /// Generate a random and compute the commitment
    /// Returns the randomness and the commitment
    pub fn create_random_commitment(
        pp: &PublicParameters<C>,
        rng: &mut impl Rng,
    ) -> Result<(Randomness<C>, Commitment<C>), AmComEqError> {
        let commit_timer = start_timer!(|| "AmComEq::Commit");
        let ld = pp.poly_ck.g.len();
        let d1 = pp.poly_ck.h.len();
        let d2 = pp.coeff_ck.h.len();

        let random_timer = start_timer!(|| "Generate Random");
        let r = (0..ld).map(|_| C::ScalarField::rand(rng)).collect();
        let delta = (0..d1).map(|_| C::ScalarField::rand(rng)).collect();
        let gamma = (0..d2).map(|_| C::ScalarField::rand(rng)).collect();

        let random = Randomness { r, delta, gamma };

        end_timer!(random_timer);

        let commitment = Self::create_commitment_from_random(pp, &random)?;
        end_timer!(commit_timer);

        Ok((random, commitment))
    }

    pub fn create_commitment_from_random(
        pp: &PublicParameters<C>,
        random: &Randomness<C>,
    ) -> Result<Commitment<C>, AmComEqError> {
        let a_timer = start_timer!(|| "Compute A");
        let r = cfg_iter!(random.r)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let delta = cfg_iter!(random.delta)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let a = C::msm_bigint(&pp.poly_ck.g, &r[..]) + C::msm_bigint(&pp.poly_ck.h, &delta[..]);
        drop(r);
        drop(delta);

        end_timer!(a_timer);

        let a_hat_timer = start_timer!(|| "Compute A hat");
        let d0 = pp.coeff_ck.g.len();
        let l = pp.poly_ck.g.len() / d0;

        let d0_indicies = (0..d0).collect::<Vec<_>>();
        let l_indicies = (0..l).collect::<Vec<_>>();

        let aggregated_r = cfg_iter!(d0_indicies)
            .map(|&j| {
                cfg_iter!(l_indicies)
                    .map(|&i| random.r[d0 * i + j] * pp.powers_of_x[i])
                    .sum::<C::ScalarField>()
                    .into_bigint()
            })
            .collect::<Vec<_>>();
        let gamma = cfg_iter!(random.gamma)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let a_hat = C::msm_bigint(&pp.coeff_ck.g, &aggregated_r)
            + C::msm_bigint(&pp.coeff_ck.h, &gamma[..]);

        end_timer!(a_hat_timer);

        Ok(Commitment {
            a: a.into(),
            a_hat: a_hat.into(),
        })
    }

    pub fn create_proof_with_challenge(
        pp: &PublicParameters<C>,
        witness: &Witness<C>,
        randomness: &Randomness<C>,
        challenge: C::ScalarField,
    ) -> Result<Proof<C>, AmComEqError> {
        let proof_timer = start_timer!(|| "AmComEq::Prover");

        let z_timer = start_timer!(|| "Compute Z");
        let z = cfg_iter!(randomness.r)
            .zip(witness.w.concat())
            .map(|(&r, w)| r + challenge * w)
            .collect();
        end_timer!(z_timer);

        let omega_timer = start_timer!(|| "Compute ω");
        let omega = cfg_iter!(randomness.delta)
            .zip(&witness.alpha)
            .map(|(&delta, alpha)| delta + challenge * alpha)
            .collect();
        end_timer!(omega_timer);

        let omega_hat_timer = start_timer!(|| "Compute Ω");
        let d2_indicies = (0..pp.coeff_ck.h.len()).collect::<Vec<_>>();

        let aggregated_beta = cfg_iter!(d2_indicies)
            .map(|&j| {
                cfg_iter!(witness.beta)
                    .zip(&pp.powers_of_x)
                    .map(|(beta, x)| beta[j] * x)
                    .sum::<C::ScalarField>()
            })
            .collect::<Vec<_>>();

        let omega_hat = cfg_iter!(randomness.gamma)
            .zip(aggregated_beta)
            .map(|(&gamma, beta)| gamma + challenge * beta)
            .collect();

        end_timer!(omega_hat_timer);

        end_timer!(proof_timer);

        Ok(Proof {
            z,
            omega,
            omega_hat,
        })
    }
}
