// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The opening
use crate::commitment::HomomorphicCommitment;
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;


/// Proof-dependent commitment
#[derive(Debug, Clone)]
pub struct PDCommitment<F: PrimeField, PC: HomomorphicCommitment<F>> {
    /// The commitment
    pub(crate) pd_cm: PC::Commitment,

    /// The opening of the commitment
    pub(crate) opening: Vec<F>,
}

impl<F, PC> PDCommitment<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    /// Creates a new struct for [`PublicInputs`].
    pub fn new(pd_cm: PC::Commitment, opening: Vec<F>) -> Self {
        Self { pd_cm, opening }
    }
}

/// Batch proof
pub struct BatchedProof<F: PrimeField, PC: HomomorphicCommitment<F>> {
    /// Committed witness polynomial
    pub(crate) cw_poly: DensePolynomial<F>,

    /// Committed Witness Commitment
    pub(crate) cw_comm: PC::Commitment,

    /// Committed witness randomness
    pub(crate) cw_rand: PC::Randomness,
}
