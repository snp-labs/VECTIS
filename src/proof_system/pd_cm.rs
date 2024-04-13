// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The opening
use ark_ff::PrimeField;
use crate::commitment::HomomorphicCommitment;

/// Proof-dependent commitment에 대한 [`Opening`]
// pub struct Opening<F: PrimeField> {
//     pub(crate) opening: Vec<F>,
// }

/// Proof-dependent commitment
pub struct PDCommitment<F : PrimeField, PC: HomomorphicCommitment<F>> 
{
    /// The commitment
    pub(crate) pd_cm: PC::Commitment,

    /// The opening of the commitment
    pub(crate) opening: Vec<F>
}

impl<F : PrimeField, PC: HomomorphicCommitment<F>> Default for PDCommitment<F, PC> {
    fn default() -> Self {
        Self {
            pd_cm: PC::Commitment::default(),
            opening: Vec::default(),
        }
    }
}