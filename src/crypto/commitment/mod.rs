pub mod constraints;
pub use constraints::BatchCommitmentGadget;

pub mod pedersen;

use ark_std::vec::Vec;

pub trait CommitmentScheme {
    type Scalar;
    type Base;
    type Commitment;

    fn commit(committing_key: &[Self::Base], commitments: &[Self::Scalar]) -> Self::Commitment;
}

/// The basic functionality for a Batch Commitment Scheme.
pub trait BatchCommitmentScheme: CommitmentScheme {
    type Challenge;

    // [cm_0, cm_1, ... cm_k, proof dependent cm]
    fn batch_commit(
        batch_key: &[Self::Base],
        commitments: &[&[Self::Scalar]],
    ) -> Vec<Self::Commitment>;

    fn challenge(
        commitments: &[Self::Base],
        proof_dependent_commitment: &Self::Base,
    ) -> Self::Challenge;

    fn aggregate(commitments: &[Self::Commitment], tau: Self::Challenge) -> Self::Commitment;

    fn scalar_aggregate(
        commitments: &[&[Self::Scalar]],
        tau: Self::Challenge,
        initial: Option<Self::Challenge>,
    ) -> Vec<Self::Scalar>;
}
