use ark_ec::CurveGroup;
use ark_ff::PrimeField;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::{AmComEq, Commitment, Instance, Proof, PublicParameters};

impl<C: CurveGroup> AmComEq<C> {
    pub fn verify_proof_with_challenge(
        pp: &PublicParameters<C>,
        instance: &Instance<C>,
        commitment: &Commitment<C>,
        proof: &Proof<C>,
        challenge: C::ScalarField,
    ) -> Result<bool, ()> {
        let verifier_timer = start_timer!(|| "AmComEq::Verifier");

        let single_timer = start_timer!(|| "Single Commitment");
        let z = cfg_iter!(proof.z)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let omega = cfg_iter!(proof.omega)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let s_real =
            C::msm_bigint(&pp.poly_ck.g, &z[..]) + C::msm_bigint(&pp.poly_ck.h, &omega[..]);
        drop(omega);

        let s_expected = commitment.a + instance.c * challenge;
        end_timer!(single_timer);

        let multiple_timer = start_timer!(|| "Multiple Commitment");

        let d0 = pp.coeff_ck.g.len();
        let l = pp.powers_of_x.len();

        let d0_indicies = (0..d0).collect::<Vec<_>>();
        let l_indicies = (0..l).collect::<Vec<_>>();

        let aggregated_z = cfg_iter!(d0_indicies)
            .map(|&j| {
                cfg_iter!(l_indicies)
                    .map(|&i| proof.z[d0 * i + j] * pp.powers_of_x[i])
                    .sum::<C::ScalarField>()
                    .into_bigint()
            })
            .collect::<Vec<_>>();
        drop(z);

        let omega_hat = cfg_iter!(proof.omega_hat)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let m_real = C::msm_bigint(&pp.coeff_ck.g, &aggregated_z)
            + C::msm_bigint(&pp.coeff_ck.h, &omega_hat[..]);

        drop(aggregated_z);
        drop(omega_hat);

        let powers_of_x = cfg_iter!(pp.powers_of_x)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let m_expected =
            commitment.a_hat + C::msm_bigint(&instance.c_hat, &powers_of_x[..]) * challenge;

        end_timer!(multiple_timer);

        end_timer!(verifier_timer);

        assert_eq!(
            s_real.into_affine(),
            s_expected.into_affine(),
            "single commit different"
        );
        assert_eq!(
            m_real.into_affine(),
            m_expected.into_affine(),
            "multiple commit different"
        );

        Ok(s_real.into_affine() == s_expected.into() && m_real.into_affine() == m_expected.into())
    }
}
