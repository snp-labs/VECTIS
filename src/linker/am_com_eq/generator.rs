use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalSerialize;
use ark_std::One;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::crypto::protocol::transcript::TranscriptProtocol;

pub use super::{data_structure::*, AmComEq};

impl<C: CurveGroup> AmComEq<C> {
    pub fn compute_powers_of_x<T: TranscriptProtocol>(
        instance: &Instance<C>,
        transcript: &mut T,
    ) -> Vec<C::ScalarField> {
        let l = instance.c_hat.len();
        let instance = vec![&[instance.c][..], &instance.c_hat].concat();
        let bytes = cfg_iter!(instance)
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
        transcript.append(b"instance", &bytes);
        let x = transcript.challenge_scalar::<C::ScalarField>(b"challenge");

        let mut powers_of_x = vec![];
        let mut curr = C::ScalarField::one();
        for _ in 0..l {
            powers_of_x.push(x);
            curr *= x;
        }
        powers_of_x
    }

    pub fn compute_e<T: TranscriptProtocol>(
        commitment: &Commitment<C>,
        transcript: &mut T,
    ) -> C::ScalarField {
        let mut bytes = vec![];
        let (x, y) = commitment.a.xy().unwrap();
        let (x_hat, y_hat) = commitment.a_hat.xy().unwrap();
        y_hat.serialize_uncompressed(&mut bytes).unwrap();
        x_hat.serialize_uncompressed(&mut bytes).unwrap();
        y.serialize_uncompressed(&mut bytes).unwrap();
        x.serialize_uncompressed(&mut bytes).unwrap();
        bytes.reverse();
        transcript.append(b"commitment", &bytes);
        transcript.challenge_scalar::<C::ScalarField>(b"challenge")
    }
}
