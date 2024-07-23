use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CommittingKey<C: CurveGroup> {
    pub g: Vec<C::Affine>,
    pub h: Vec<C::Affine>,
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicParameters<C: CurveGroup> {
    pub poly_ck: CommittingKey<C>,
    pub coeff_ck: CommittingKey<C>,

    /// powers of x = [1, x, ..., x^(l-1)]
    pub powers_of_x: Vec<C::ScalarField>,
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Instance<C: CurveGroup> {
    pub c: C::Affine,
    pub c_hat: Vec<C::Affine>,
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Witness<C: CurveGroup> {
    pub w: Vec<Vec<C::ScalarField>>,
    pub alpha: Vec<C::ScalarField>,
    pub beta: Vec<Vec<C::ScalarField>>,
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Randomness<C: CurveGroup> {
    pub r: Vec<C::ScalarField>,
    pub delta: Vec<C::ScalarField>,
    pub gamma: Vec<C::ScalarField>,
}

/// Eclipse: AmComEq commitment
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Commitment<C: CurveGroup> {
    pub a: C::Affine,
    pub a_hat: C::Affine,
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<C: CurveGroup> {
    pub z: Vec<C::ScalarField>,
    pub omega: Vec<C::ScalarField>,
    pub omega_hat: Vec<C::ScalarField>,
}
