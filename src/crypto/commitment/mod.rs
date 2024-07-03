pub mod constraints;
pub use constraints::BatchCommitmentGadget;

pub mod pedersen;

use ark_ff::PrimeField;
use ark_std::vec::Vec;

pub trait CommitmentScheme {
    type Scalar;
    type Base;
    type Commitment;

    fn commit(
        committing_key: &Vec<Self::Base>,
        commitments: &Vec<Self::Scalar>,
    ) -> Self::Commitment;
}

/// The basic functionality for a Batch Commitment Scheme.
pub trait BatchCommitmentScheme {
    type Scalar: PrimeField;
    type Base;
    type Challenge;

    // [cm_0, cm_1, ... cm_k, proof dependent cm]
    fn batch_commit(
        commitments: &Vec<Vec<Self::Scalar>>,
        batch_key: &Vec<Self::Base>,
        proof_key: &Vec<Self::Base>,
    ) -> (Vec<Self::Base>, Self::Base);

    fn challenge(
        commitments: &Vec<Self::Base>,
        proof_dependent_commitment: &Self::Base,
    ) -> Self::Challenge;

    fn aggregate(commitments: &Vec<Self::Base>, tau: Self::Challenge) -> Self::Base;

    fn cc_aggregate(
        commitments: &Vec<Vec<Self::Scalar>>,
        tau: Self::Challenge,
        initial: Option<Self::Challenge>,
    ) -> Vec<Self::Scalar>;
}
