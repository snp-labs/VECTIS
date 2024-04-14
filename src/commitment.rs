//! Useful commitment stuff
use crate::ark_std::Zero;
use crate::poly_commit::{kzg10, sonic_pc::SonicKZG10, PolynomialCommitment};
use crate::transcript::TranscriptProtocol;
use ark_ec::ProjectiveCurve;
use ark_ec::{msm::VariableBaseMSM, AffineCurve, PairingEngine};
use ark_ff::{Field, PrimeField};
use ark_poly::univariate::DensePolynomial;
use core::{
    iter::Sum,
    ops::{Add, AddAssign},
};
use merlin::Transcript;
use std::ops::MulAssign;

/// A homomorphic polynomial commitment
pub trait HomomorphicCommitment<F>: PolynomialCommitment<F, DensePolynomial<F>>
where
    F: PrimeField,
    Self::VerifierKey: core::fmt::Debug,
{
    /// Combine a linear combination of homomorphic commitments
    fn multi_scalar_mul(commitments: &[Self::Commitment], scalars: &[F]) -> Self::Commitment;

    /// Aggregate multiple commitments
    fn agg(commitments: &[Self::Commitment]) -> Self::Commitment;

    /// Compute a batched commitment
    fn binary_encoding(commitments: &[Self::Commitment], tau: F) -> Self::Commitment;

    /// Aggregate multiple commitments
    fn compute_challenge(
        trans: &mut Transcript,
        commitments: &[Self::Commitment],
        pd_cm: &Self::Commitment,
    ) -> F;

    /// Generate commitment list
    fn generate_commitment_list(
        ck: Self::BatchCommitterKey,
        m_list: Vec<F>,
        o_list: Vec<F>,
    ) -> Vec<Self::Commitment>;

    /// Generate a proof dependent commitment
    fn generate_proof_dependent_commitment(
        bck: &Self::BatchCommitterKey,
        m_list: &Vec<F>,
        o_list: &Vec<F>,
        opening: &Vec<F>,
    ) -> Self::Commitment;
}

/// The Default KZG-style commitment scheme
pub type KZG10<E> = SonicKZG10<E, DensePolynomial<<E as PairingEngine>::Fr>>;
/// A single KZG10 commitment
pub type KZG10Commitment<E> = <KZG10<E> as PolynomialCommitment<
    <E as PairingEngine>::Fr,
    DensePolynomial<<E as PairingEngine>::Fr>,
>>::Commitment;

impl<E> HomomorphicCommitment<E::Fr> for KZG10<E>
where
    E: PairingEngine,
{
    fn multi_scalar_mul(
        commitments: &[KZG10Commitment<E>],
        scalars: &[E::Fr],
    ) -> KZG10Commitment<E> {
        let scalars_repr = scalars
            .iter()
            .map(<E::Fr as PrimeField>::into_repr)
            .collect::<Vec<_>>();

        let points_repr = commitments.iter().map(|c| c.0).collect::<Vec<_>>();

        kzg10::Commitment::<E>(
            VariableBaseMSM::multi_scalar_mul(&points_repr, &scalars_repr).into(),
        )
    }

    fn agg(commitments: &[Self::Commitment]) -> KZG10Commitment<E> {
        let points_repr = commitments.iter().map(|c| c.0).collect::<Vec<_>>();
        let mut ret = E::G1Affine::zero();

        for i in 0..points_repr.len() {
            ret = ret + points_repr[i];
        }

        kzg10::Commitment(ret.into())
    }

    fn binary_encoding(commitments: &[Self::Commitment], tau: E::Fr) -> KZG10Commitment<E> {
        let points_repr = commitments
            .iter()
            .map(|c| c.0.into_projective())
            .collect::<Vec<_>>();
        let ret = points_repr.compute_root(tau);

        kzg10::Commitment(ret.into())
    }

    fn compute_challenge(
        trans: &mut Transcript,
        commitments: &[Self::Commitment],
        pd_cm: &Self::Commitment,
    ) -> E::Fr {
        // Transcript proof-dependent commitment and the list commitments
        let points_repr = commitments
            .iter()
            .map(|c| c.0.into_projective())
            .collect::<Vec<_>>();
        for i in 0..points_repr.len() {
            trans.append_message(b"list commitment", &points_repr[i].to_string().as_bytes());
        }
        trans.append_message(
            b"proof dependent commitment",
            pd_cm.0.into_projective().to_string().as_bytes(),
        );
        let tau: E::Fr = trans.challenge_scalar(b"challenge");

        tau
    }

    fn generate_commitment_list(
        ck: Self::BatchCommitterKey,
        m_list: Vec<E::Fr>,
        o_list: Vec<E::Fr>,
    ) -> Vec<Self::Commitment> {
        let cm: Vec<kzg10::Commitment<E>> = m_list
            .iter()
            .zip(o_list.iter())
            .map(|(m, o)| {
                kzg10::Commitment(
                    (AffineCurve::mul(&ck.bck_1[0], m.into_repr())
                        + AffineCurve::mul(&ck.bck_1[1], o.into_repr()))
                    .into_affine()
                    .into(),
                )
            })
            .collect();

        cm
    }

    fn generate_proof_dependent_commitment(
        bck: &Self::BatchCommitterKey,
        m_list: &Vec<E::Fr>,
        o_list: &Vec<E::Fr>,
        opening: &Vec<E::Fr>,
    ) -> Self::Commitment {
        let cw: Vec<E::Fr> = m_list
            .into_iter()
            .zip(o_list.into_iter())
            .flat_map(|(m, o)| vec![*m, *o].into_iter())
            .collect();

        let pd_cm = Self::compute_proof_dependent_cm(&bck, cw, opening.clone()).unwrap();

        pd_cm.commitment().clone()
    }
}

/// Computes a linear combination of the polynomial evaluations and polynomial
/// commitments provided a challenge.
// TODO: complete doc & use util::lc for eval combination
pub fn linear_combination<F, H>(
    evals: &[F],
    commitments: &[H::Commitment],
    challenge: F,
) -> (H::Commitment, F)
where
    F: PrimeField,
    H: HomomorphicCommitment<F>,
{
    assert_eq!(evals.len(), commitments.len());
    let powers = crate::util::powers_of(challenge)
        .take(evals.len())
        .collect::<Vec<_>>();
    let combined_eval = evals
        .iter()
        .zip(powers.iter())
        .map(|(&eval, power)| eval * power)
        .sum();
    let combined_commitment = H::multi_scalar_mul(commitments, &powers);
    (combined_commitment, combined_eval)
}

/// Aggregate polynomials
pub fn aggregate_polynomials<F: Field>(
    polynomials: &[DensePolynomial<F>],
    challenge: F,
) -> DensePolynomial<F> {
    crate::util::powers_of(challenge)
        .zip(polynomials)
        .map(|(challenge, poly)| poly * challenge)
        .fold(Zero::zero(), Add::add)
}

/// Aggregation tree trait
pub trait AggregationTree<U> {
    /// Node type
    type Node;
    /// Compute root with some challenge tau
    fn compute_root(&self, tau: U) -> Self::Node;
}

impl<T, U> AggregationTree<U> for Vec<T>
where
    T: Clone + AddAssign<T> + for<'a> Add<&'a T, Output = T> + MulAssign<U> + for<'a> Sum<&'a T>,
    U: Clone + core::ops::Mul<U> + for<'a> core::ops::Mul<&'a U, Output = U>,
{
    type Node = T;
    fn compute_root(&self, tau: U) -> Self::Node {
        let mut cm_list = self.clone();
        let mut ret = cm_list[0].clone();

        let mut nodes = cm_list.len();
        let mut coeff = tau;

        while nodes > 1 {
            let mut even: T = cm_list.iter().skip(1).step_by(2).sum();
            even.mul_assign(coeff.clone());
            ret += even;

            coeff = coeff.clone() * &coeff;
            nodes >>= 1;
            for i in 0..nodes {
                cm_list[i] = cm_list[i << 1].clone() + &cm_list[(i << 1) + 1];
            }
            cm_list.truncate(nodes);
        }

        ret
    }
}
