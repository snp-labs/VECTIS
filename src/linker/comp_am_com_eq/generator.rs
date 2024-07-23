use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_std::Zero;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::{data_structure::*, CompAmComEq};

impl<C: CurveGroup> CompAmComEq<C> {
    pub fn prepare_from_am_com_eq(
        pp: &AmComEqPP<C>,
        instance: &Instance<C>,
        commitment: &Commitment<C>,
        proof: &AmComEqPrf<C>,
        challenge: C::ScalarField,
    ) -> Result<(PublicParameters<C>, PartialProof<C>), ()> {
        if pp.powers_of_x.len() * pp.coeff_ck.g.len() != pp.poly_ck.g.len() {
            return Err(());
        }

        let prepare_timer = start_timer!(|| "CompAmComEq::Prepare");

        let mut g = pp.poly_ck.g.clone();
        let mut g_hat = cfg_iter!(pp.powers_of_x)
            .map(|x| {
                cfg_iter!(pp.coeff_ck.g)
                    .map(|g| (*g * x).into_affine())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
            .concat();

        let extend_size = Self::rescale_size(g.len()) - g.len();
        g.extend(vec![C::Affine::generator(); extend_size]);
        g_hat.extend(vec![C::Affine::zero(); extend_size]);

        let mut z = proof.z.clone();
        z.extend(vec![C::ScalarField::zero(); extend_size]);

        let expected_timer = start_timer!(|| "Compute Expected");

        let y_timer = start_timer!(|| "Compute Y");
        let omega = cfg_iter!(proof.omega)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let y = commitment.a + instance.c * challenge - C::msm_bigint(&pp.poly_ck.h, &omega[..]);
        drop(omega);
        end_timer!(y_timer);

        let y_hat_timer = start_timer!(|| "Compute Y Hat");
        let powers_of_x = cfg_iter!(pp.powers_of_x)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let omega_hat = cfg_iter!(proof.omega_hat)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let y_hat = commitment.a_hat + C::msm_bigint(&instance.c_hat, &powers_of_x[..]) * challenge
            - C::msm_bigint(&pp.coeff_ck.h, &omega_hat[..]);
        drop(powers_of_x);
        drop(omega_hat);
        end_timer!(y_hat_timer);
        end_timer!(expected_timer);
        end_timer!(prepare_timer);

        // unimplemented!()

        Ok((
            PublicParameters {
                g,
                g_hat,
                y: y.into_affine(),
                y_hat: y_hat.into_affine(),
            },
            PartialProof { z },
        ))
    }

    fn rescale_size(l: usize) -> usize {
        if l.is_power_of_two() {
            l
        } else {
            l.next_power_of_two()
        }
    }
}
