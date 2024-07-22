use std::marker::PhantomData;

use ark_ec::CurveGroup;

pub mod data_structure;
pub use self::data_structure::*;

mod errors;
mod prover;
mod verifier;

pub struct AmComEq<C: CurveGroup> {
    _group: PhantomData<C>,
}
