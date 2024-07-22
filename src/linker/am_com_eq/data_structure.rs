use ark_ec::CurveGroup;

pub struct CommittingKey<C: CurveGroup> {
    pub g: Vec<C::Affine>,
    pub h: Vec<C::Affine>,
}

pub struct PublicParameters<C: CurveGroup> {
    pub poly_ck: CommittingKey<C>,
    pub coeff_ck: CommittingKey<C>,

    /// powers of x = [1, x, ..., x^(l-1)]
    pub powers_of_x: Vec<C::ScalarField>,
    // /// g hat = [g^(x^0), g^(x^1), ..., g^(x^(l-1))]
    // pub g_hat: Vec<C::ScalarField>,
}

pub struct Instance<C: CurveGroup> {
    pub c: C::Affine,
    pub c_hat: Vec<C::Affine>,
}

pub struct Witness<C: CurveGroup> {
    pub w: Vec<Vec<C::ScalarField>>,
    pub alpha: Vec<C::ScalarField>,
    pub beta: Vec<Vec<C::ScalarField>>,
}

pub struct Randomness<C: CurveGroup> {
    pub r: Vec<C::ScalarField>,
    pub delta: Vec<C::ScalarField>,
    pub gamma: Vec<C::ScalarField>,
}

/// Eclipse: AmComEq commitment
pub struct Commitment<C: CurveGroup> {
    pub a: C::Affine,
    pub a_hat: C::Affine,
}

pub struct Proof<C: CurveGroup> {
    pub z: Vec<C::ScalarField>,
    pub omega: Vec<C::ScalarField>,
    pub omega_hat: Vec<C::ScalarField>,
}
