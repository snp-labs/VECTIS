// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The opening

use crate::poly_commit::LabeledCommitment;
use ark_ff::PrimeField;

use crate::commitment::HomomorphicCommitment;

/// Proof-dependent commitment에 대한 [`Opening`]
pub struct Opening<F: PrimeField> {
    pub(crate) opening: Vec<F>,
}

/// Batched Commitment에 대한 [`BatchCommitKey`]
pub struct BatchCommitKey<F, PC>
where
    F: PrimeField,
    PC: HomomorphicCommitment<F>,
{
    pub(crate) ck: Vec<LabeledCommitment<PC::Commitment>>,
}
