use std::time::Instant;

use ark_ec::CurveGroup;
use ark_std::{
    rand::{CryptoRng, RngCore},
    UniformRand,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{
    crypto::{
        commitment::{pedersen::Pedersen, CommitmentScheme},
        protocol::{
            sigma::SigmaProtocol,
            transcript::{sha3::SHA3Base, TranscriptProtocol},
        },
    },
    linker::{
        am_com_eq::{
            data_structure::{CommittingKey, Instance, PublicParameters, Witness},
            AmComEq,
        },
        comp_am_com_eq::CompAmComEq,
    },
};

use super::utils::Average;

fn linker_setup<C: CurveGroup, R: RngCore + CryptoRng>(
    l: usize,
    d0: usize,
    d1: usize,
    d2: usize,
    rng: &mut R,
) -> (PublicParameters<C>, Instance<C>, Witness<C>) {
    let ld = l * d0;

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

    (
        PublicParameters {
            poly_ck: CommittingKey { g, h },
            coeff_ck: CommittingKey { g: g_hat, h: h_hat },
        },
        Instance {
            c: c.into_affine(),
            c_hat: C::normalize_batch(&c_hat),
        },
        Witness { w, alpha, beta },
    )
}

fn process_linker<C: CurveGroup, R: RngCore + CryptoRng>(
    repeat: usize,
    l: usize,
    d0: usize,
    d1: usize,
    d2: usize,
    rng: &mut R,
) -> (u128, u128) {
    let mut prover = vec![];
    let mut verifier = vec![];
    for _ in 0..repeat {
        let prv_instant = Instant::now();
        let (pp, instance, witness) = linker_setup::<C, _>(l, d0, d1, d2, rng);
        let mut transcript = SHA3Base::new(true);

        // prove
        let proof = CompAmComEq::<C>::prove(&pp, &instance, &witness, &mut transcript, rng)
            .expect("proof failed");
        prover.push(prv_instant.elapsed().as_micros());
        drop(witness);

        // verify
        let vry_instant = Instant::now();
        let mut transcript = SHA3Base::new(true);
        assert!(CompAmComEq::<C>::verify(&pp, &instance, &proof, &mut transcript).unwrap());
        verifier.push(vry_instant.elapsed().as_micros());
    }
    (prover.average(), verifier.average())
}

pub mod bn254 {
    use crate::tests::{
        utils::{format_time, parse_env},
        LOG_MAX, LOG_MIN, NUM_REPEAT,
    };

    use super::*;
    use ark_std::{
        rand::{rngs::StdRng, SeedableRng},
        test_rng,
    };
    use lazy_static::lazy_static;

    type C = ark_bn254::G1Projective;
    type R = StdRng;

    lazy_static! {
        pub static ref D0: usize = parse_env("D0").expect("Failed to parse D0");
        pub static ref D1: usize = parse_env("D1").expect("Failed to parse D1");
        pub static ref D2: usize = parse_env("D2").expect("Failed to parse D2");
    }

    #[test]
    fn simple_am_com_eq_scenario() {
        let mut rng = R::seed_from_u64(test_rng().next_u64());

        let l = 1 << *LOG_MIN;
        let (pp, instance, witness) = linker_setup::<C, _>(l, *D0, *D1, *D2, &mut rng);

        // prove
        let mut transcript = SHA3Base::new(false);
        let proof = AmComEq::<C>::prove(&pp, &instance, &witness, &mut transcript, &mut rng)
            .expect("proof failed");

        // verify
        let mut transcript = SHA3Base::new(false);
        assert!(AmComEq::<C>::verify(&pp, &instance, &proof, &mut transcript).unwrap());
    }

    #[test]
    fn comp_am_com_eq_scenario() {
        let mut rng = R::seed_from_u64(test_rng().next_u64());
        for n in *LOG_MIN..=*LOG_MAX {
            let l = 1 << n;

            let (prv, vrf) = process_linker::<C, R>(*NUM_REPEAT, l, *D0, *D1, *D2, &mut rng);
            println!(
                "Batch Size: 2^{} Prover: {} Verifier: {}",
                n,
                format_time(prv),
                format_time(vrf)
            );
        }
    }
}
