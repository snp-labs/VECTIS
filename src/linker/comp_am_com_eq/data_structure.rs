use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub use crate::linker::am_com_eq::data_structure::{
    Commitment, CommittingKey, Instance, Proof as AmComEqPrf, PublicParameters as AmComEqPP,
};

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicParameters<C: CurveGroup> {
    pub g: Vec<C::Affine>,
    pub g_hat: Vec<C::Affine>,

    /// `Y` in the first step, or `Y'` of recursive steps in CompDLEq
    pub y: C::Affine,

    /// `Yˆ` in the first step, or ` Yˆ'` of recursive steps in CompDLEq
    pub y_hat: C::Affine,
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct DepthCommitment<C: CurveGroup> {
    pub left: C::Affine,
    pub right: C::Affine,
    pub left_hat: C::Affine,
    pub right_hat: C::Affine,
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct InitialProof<C: CurveGroup> {
    pub omega: Vec<C::ScalarField>,
    pub omega_hat: Vec<C::ScalarField>,
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PartialProof<C: CurveGroup> {
    pub z: Vec<C::ScalarField>,
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<C: CurveGroup> {
    pub compressed: AmComEqPrf<C>,
    pub commitments: Vec<DepthCommitment<C>>,
}
