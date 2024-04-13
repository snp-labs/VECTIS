use std::iter;

use ark_ff::{Field, PrimeField};
use ark_ec::{msm::VariableBaseMSM, AffineCurve, ProjectiveCurve};
use ark_poly::{univariate::{DensePolynomial, SparsePolynomial}, EvaluationDomain, GeneralEvaluationDomain, UVPolynomial};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use ark_std::One;


/// Compute lagrange basis polynomial
// pub fn compute_lagrange_basis<C: AffineCurve>(tau_powers: &[C]) -> Vec<C> {
pub fn compute_lagrange_basis<C: AffineCurve>(powers_of_g: &Vec<C>) -> Vec<C> {
    let n = powers_of_g.len();
    assert!((n & (n - 1)) == 0);

    let domain = GeneralEvaluationDomain::<C::ScalarField>::new(n).unwrap();
    let n_inv = domain.size_as_field_element().inverse().unwrap();

    let tau_projective: Vec<C::Projective> = powers_of_g
        .iter()
        .map(|tau_pow_i| tau_pow_i.into_projective())
        .collect();
    
    let p_evals: Vec<C::Projective> = domain.fft(&tau_projective);
    let p_evals_reversed = iter::once(p_evals[0]).chain(p_evals.into_iter().skip(1).rev());

    let mut ls: Vec<C::Projective> = p_evals_reversed
        .into_iter()
        .map(|pi| {
           let p_affine = pi.into_affine();
           p_affine.mul(n_inv)
        })
        .collect();
    C::Projective::batch_normalization_into_affine(&mut ls)
}

/// Compute commitment key for blinding factors
pub fn compute_blind_basis<C: AffineCurve>(n: usize, powers_of_g: &Vec<C>) -> Vec<C> {
    let domain = GeneralEvaluationDomain::<C::ScalarField>::new(n)
    .ok_or(crate::error::Error::InvalidEvalDomainSize { 
        log_size_of_group: n.trailing_zeros(),
        adicity: <<C::ScalarField as ark_ff::FftField>::FftParams as ark_ff::FftParameters>::TWO_ADICITY 
    }).unwrap();

    let mut blind_of_g = Vec::new();
    let zero_poly: DensePolynomial<C::ScalarField> = domain.vanishing_polynomial().into();
    let zero_coeffs = zero_poly.coeffs();
    let zero_of_g = VariableBaseMSM::multi_scalar_mul(
        &powers_of_g, convert_to_bigints(zero_coeffs).as_slice()).into_affine();
    
    // println!("zero_coeffs : {:?} \n", zero_coeffs);

    blind_of_g.push(zero_of_g);
    
    let _x_zero_coeffs = vec![(1, -C::ScalarField::one()), (domain.size() + 1, C::ScalarField::one())];
    let x_zero_poly : DensePolynomial<C::ScalarField> =  SparsePolynomial::<C::ScalarField>::from_coefficients_vec(_x_zero_coeffs.clone()).into();
    let x_zero_coeffs = x_zero_poly.coeffs();
    let x_zero_of_g = VariableBaseMSM::multi_scalar_mul(
        &powers_of_g, convert_to_bigints(x_zero_coeffs).as_slice()).into_affine();
    
    // println!("x_zero_coeffs : {:?} \n", x_zero_coeffs);

    blind_of_g.push(x_zero_of_g);
    
    // let test_coeffs = vec![(0, -C::ScalarField::one()), (1, -C::ScalarField::one()), (domain.size(), C::ScalarField::one()), (domain.size() + 1, C::ScalarField::one())];
    // let test_poly: DensePolynomial<C::ScalarField> =  SparsePolynomial::<C::ScalarField>::from_coefficients_vec(test_coeffs).into();
    // let test_co = test_poly.coeffs();
    // let test = VariableBaseMSM::multi_scalar_mul(
    //     &powers_of_g, convert_to_bigints(test_co).as_slice()).into_affine();


    // fn vanishing_polynomial(&self) -> crate::univariate::SparsePolynomial<F> {
    //     let coeffs = vec![(0, -F::one()), (self.size(), F::one())];
    //     crate::univariate::SparsePolynomial::from_coefficients_vec(coeffs)
    // }

    // println!("zero poly : {:?} \n", zero_poly);
    // let (num_leading_zeros, zero_coeffs) = 
    //     skip_leading_zeros_and_convert_to_bigints(&zero_poly);
    // println!("num : {:?}\n", num_leading_zeros);
    // println!("zero coeffs : {:?}\n", zero_coeffs);
    // // g^{z_H(X)}
    // let zero = VariableBaseMSM::multi_scalar_mul(
    //     &powers_of_g[num_leading_zeros..], 
    //     &zero_coeffs).into_affine();

    // blind_of_g.push(zero);

    // let mut zero_coeffs = zero_poly.coeffs.to_vec();
    // zero_coeffs.insert(0, C::ScalarField::zero());
    // zero_coeffs[1] = -domain.generator_inv(); // coset_offset
    // let x_zero_poly = 
    //     DensePolynomial::<C::ScalarField>::from_coefficients_vec(zero_coeffs);
    
    // println!("x zero poly : {:?}\n", zero_poly);

    // let x_zero: C = VariableBaseMSM::multi_scalar_mul(
    //     powers_of_g.as_slice(),
    //     convert_to_bigints(x_zero_poly.coeffs.as_slice()).as_slice()
    // ).into_affine();

    // blind_of_g.push(x_zero);

    return blind_of_g;
}

/// Skip leading zeros
pub fn skip_leading_zeros_and_convert_to_bigints<F, P>(
    p: &P,
) -> (usize, Vec<F::BigInt>) where F: PrimeField, P: UVPolynomial<F> {
    let mut num_leading_zeros = 0;
    while num_leading_zeros < p.coeffs().len() && p.coeffs()[num_leading_zeros].is_zero() {
        num_leading_zeros += 1;
    }
    let coeffs = convert_to_bigints(&p.coeffs()[num_leading_zeros..]);
    (num_leading_zeros, coeffs)
}

/// Convert F to bigint
pub fn convert_to_bigints<F: PrimeField>(p: &[F]) -> Vec<F::BigInt> {
    let to_bigint_time = start_timer!(|| "Converting polynomial coeffs to bigints");
    let coeffs = ark_std::cfg_iter!(p)
        .map(|s| s.into_repr())
        .collect::<Vec<_>>();
    end_timer!(to_bigint_time);
    coeffs
}