// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) ZK-Garage. All rights reserved.

//! committed witnesss of the circuit. This values are available for the
//! [`super::Prover`] and [`super::Verifier`].
//!
//! This module contains the implementation of the [`PublicInputs`] struct and
//! all the basic manipulations such as inserting new values and getting the
//! committed witnesss in evaluation or coefficient form.

use alloc::collections::BTreeMap;
use ark_ff::{FftField, ToConstraintField};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, UVPolynomial,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use itertools::Itertools;

use crate::prelude::Error;

///  committed witnesss
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct CommittedWitness<F>
where
    F: FftField,
{
    // non-zero values of the committed witness
    values: BTreeMap<usize, F>,
}

impl<F> CommittedWitness<F>
where
    F: FftField,
{
    /// Creates a new struct for [`PublicInputs`].
    pub fn new() -> Self {
        Self {
            values: BTreeMap::new(),
        }
    }

    /// Inserts a new committed witness value at a given position.
    ///
    /// If the value provided is zero no insertion will be made as zeros are the
    /// implicit value of empty positions.
    /// The function will panic if an insertion is atempted in an already
    /// occupied position.
    fn insert(&mut self, pos: usize, val: F) {
        if self.values.contains_key(&pos) {
            panic!(
                "Insertion in commited witness conflicts with previous value at position {}",
                pos
            );
        }
        if val != F::zero() {
            self.values.insert(pos, val);
        }
    }

    /// Inserts committed witness data that can be converted to one or more field
    /// elements starting at a given position.
    /// Returns the number of field elements occupied by the input or
    /// [`Error::InvalidPublicInputValue`] if the input could not be converted.
    pub fn add_input<T>(&mut self, pos: usize, item: &T) -> Result<usize, Error>
    where
        T: ToConstraintField<F>,
    {
        self.extend(pos, [item])
    }

    /// Inserts all the elements of `iter` converted into constraint field
    /// elements in consecutive positions.
    /// Returns the number of field elements occupied by `iter`
    /// [`Error::InvalidPublicInputValue`] if the input could not be converted.
    fn extend<'t, T, I>(&mut self, init_pos: usize, iter: I) -> Result<usize, Error>
    where
        T: 't + ToConstraintField<F>,
        I: IntoIterator<Item = &'t T>,
    {
        let mut count = 0;
        for item in iter {
            for elem in item
                .to_field_elements()
                .ok_or(Error::InvalidPublicInputValue)?
            {
                self.insert(init_pos + count, elem);
                count += 1;
            }
        }
        Ok(count)
    }

    /// Returns the committed witnesss as a vector of `n` evaluations.
    /// The provided `n` must be a power of 2.
    pub fn as_evals(&self, n: usize) -> Vec<F> {
        assert!(n.is_power_of_two());
        let mut cw = vec![F::zero(); n];
        self.values.iter().for_each(|(pos, eval)| cw[*pos] = *eval);
        cw
    }

    /// Returns the committed witnesss as a vector of `n` evaluations.
    /// The provided `n` must be a power of 2.
    pub fn into_dense_poly(&self, n: usize) -> DensePolynomial<F> {
        let domain = GeneralEvaluationDomain::<F>::new(n).unwrap();
        let evals = self.as_evals(n);
        DensePolynomial::from_coefficients_vec(domain.ifft(&evals))
    }

    /// Constructs [`PublicInputs`] from a positions and a values.
    ///
    /// Panics if the positions and values have different lenghts or if
    /// several values try to be inserted in the same position.
    pub fn from_val_pos<T>(pos: &[usize], vals: &[T]) -> Result<Self, Error>
    where
        T: ToConstraintField<F>,
    {
        let mut cw = Self::new();
        pos.iter()
            .zip_eq(vals)
            .try_for_each(|(p, v)| -> Result<(), Error> {
                cw.add_input(*p, v)?;
                Ok(())
            })?;
        Ok(cw)
    }

    /// Returns the position of non-zero PI values.
    pub fn get_pos(&self) -> impl Iterator<Item = &usize> {
        self.values.keys()
    }

    /// Returns the non-zero PI values.
    pub fn get_vals(&self) -> impl Iterator<Item = &F> {
        self.values.values()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::batch_field_test;
    use ark_bls12_377::Fr as Bls12_377_scalar_field;
    use ark_bls12_381::Fr as Bls12_381_scalar_field;

    // Checks Committed Witness representation is not affected by insertion order
    // or extra zeros.
    fn test_cw_unique_repr<F>()
    where
        F: FftField,
    {
        let mut cw_1: CommittedWitness<F> = CommittedWitness::new();

        cw_1.insert(2, F::from(2u64));
        cw_1.insert(5, F::from(5u64));
        cw_1.insert(6, F::from(6u64));

        let mut cw_2 = CommittedWitness::new();

        cw_2.insert(6, F::from(6u64));
        cw_2.insert(5, F::from(5u64));
        cw_2.insert(2, F::from(2u64));

        cw_2.insert(0, F::zero());
        cw_2.insert(1, F::zero());
        assert_eq!(cw_1, cw_2);
    }

    // Checks PublicInputs does not allow to override already inserted values.
    fn test_cw_dup_insertion<F>()
    where
        F: FftField,
    {
        let mut cw_1 = CommittedWitness::new();

        cw_1.insert(2, F::from(2u64));
        cw_1.insert(5, F::from(5u64));
        cw_1.insert(5, F::from(2u64));
    }

    // Bls12-381 tests
    batch_field_test!(
        [
            test_cw_unique_repr
        ],
        [
            test_cw_dup_insertion
        ] => Bls12_381_scalar_field
    );

    // Bls12-377 tests
    batch_field_test!(
        [
            test_cw_unique_repr
        ],
        [
            test_cw_dup_insertion
        ] => Bls12_377_scalar_field
    );
}
