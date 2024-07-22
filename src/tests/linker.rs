use ark_ec::CurveGroup;
use ark_std::{
    rand::{CryptoRng, RngCore},
    One, UniformRand,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{
    crypto::commitment::{pedersen::Pedersen, CommitmentScheme},
    linker::am_com_eq::*,
};

fn am_com_eq_setup<C: CurveGroup, R: RngCore + CryptoRng>(
    l: usize,
    d0: usize,
    d1: usize,
    d2: usize,
    rng: &mut R,
) -> (PublicParameters<C>, Instance<C>, Witness<C>) {
    let ld = l * d0;
    // let g = random_affine_points(ld, rng);
    let g = vec![C::Affine::rand(rng); ld];
    let h = vec![C::Affine::rand(rng); d1];

    let g_hat = vec![C::Affine::rand(rng); d0];
    let h_hat = vec![C::Affine::rand(rng); d2];

    let w = vec![vec![C::ScalarField::rand(rng); d0]; l];
    let alpha = vec![C::ScalarField::rand(rng); d1];
    let beta = vec![vec![C::ScalarField::rand(rng); d2]; l];

    let w_flat = cfg_iter!(w).flat_map(|w_i| w_i.clone()).collect::<Vec<_>>();
    let c = Pedersen::<C>::commit(&g, &w_flat) + Pedersen::<C>::commit(&h, &alpha);
    let c_hat = cfg_iter!(w)
        .zip(&beta)
        .map(|(w_i, beta_i)| {
            Pedersen::<C>::commit(&g_hat, w_i) + Pedersen::<C>::commit(&h_hat, beta_i)
        })
        .collect::<Vec<_>>();

    let x = C::ScalarField::rand(rng);
    let mut powers_of_x = vec![];
    let mut curr = C::ScalarField::one();
    for _ in 0..l {
        powers_of_x.push(curr);
        curr *= x;
    }

    (
        PublicParameters {
            poly_ck: CommittingKey { g, h },
            coeff_ck: CommittingKey { g: g_hat, h: h_hat },
            powers_of_x,
        },
        Instance {
            c: c.into_affine(),
            c_hat: C::normalize_batch(&c_hat),
        },
        Witness { w, alpha, beta },
    )
}

pub mod bn254 {
    use crate::tests::utils::parse_env;

    use super::*;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        test_rng,
    };
    use lazy_static::lazy_static;

    // type E = ark_bn254::Bn254;
    type F = ark_bn254::Fr;
    type C = ark_bn254::G1Projective;
    type R = StdRng;

    lazy_static! {
        pub static ref L: usize = parse_env("L").expect("Failed to parse L");
        pub static ref D0: usize = parse_env("D0").expect("Failed to parse D0");
        pub static ref D1: usize = parse_env("D1").expect("Failed to parse D1");
        pub static ref D2: usize = parse_env("D2").expect("Failed to parse D2");
    }

    #[test]
    fn am_com_eq_scenario() {
        let mut rng = R::seed_from_u64(test_rng().next_u64());

        let (pp, instance, witness) = am_com_eq_setup::<C, _>(*L, *D0, *D1, *D2, &mut rng);

        // commit
        let (random, commitment) =
            AmComEq::<C>::create_random_commitment(&pp, &mut rng).expect("commitment failed");

        // challenge
        let challenge = F::rand(&mut rng);

        // prove
        let proof = AmComEq::<C>::create_proof_with_challenge(&pp, &witness, &random, challenge)
            .expect("proof failed");

        // verify
        assert!(AmComEq::<C>::verify_proof_with_challenge(
            &pp,
            &instance,
            &commitment,
            &proof,
            challenge
        )
        .unwrap());
    }
}
