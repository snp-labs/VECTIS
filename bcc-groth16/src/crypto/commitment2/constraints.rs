use super::Commitment;
use ark_ff::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::SynthesisError;
use ark_std::{
    iter::Sum,
    ops::{Mul, MulAssign},
    Zero,
};
use std::borrow::Borrow;

/// Represents a variable for the commitment `Commitment` with separate variables for the message and opening.
#[derive(Clone, Debug)]
pub struct CommitmentVar<F: PrimeField, const M: usize = 1> {
    /// Message part of the commitment variable.
    pub msg: [FpVar<F>; M],
    /// Randomness part of the commitment vairalbe.
    pub open: FpVar<F>,
}

// impl<F: PrimeField, const M: usize> CommitmentVar<F, M> {
//     fn addmany<'a, I: Iterator<Item = ([&'a AllocatedFp<F>; M], &'a AllocatedFp<F>)>>(
//         iter: I,
//     ) -> Self {
//         let mut cs = ConstraintSystemRef::None;
//         let mut has_value = true;
//         let mut value = Commitment::<F>::zero();
//         let mut msg_lc = lc!();
//         let mut open_lc = lc!();

//         for (msg, open) in iter {
//             if !msg.cs.is_none() {
//                 cs = cs.or(msg.cs.clone());
//             }
//             match (msg.value(), open.value()) {
//                 (Ok(m), Ok(r)) => {
//                     value.msg += m;
//                     value.open += r;
//                 }
//                 _ => has_value = false,
//             }
//             msg_lc = msg_lc + msg.variable;
//             open_lc = open_lc + open.variable;
//         }

//         let msg = cs.new_lc(msg_lc).unwrap();
//         let open = cs.new_lc(open_lc).unwrap();

//         if has_value {
//             CommitmentVar::<F> {
//                 msg: FpVar::Var(AllocatedFp::new(Some(value.msg), msg, cs.clone())),
//                 open: FpVar::Var(AllocatedFp::new(Some(value.open), open, cs.clone())),
//             }
//         } else {
//             CommitmentVar::<F> {
//                 msg: FpVar::Var(AllocatedFp::new(None, msg, cs.clone())),
//                 open: FpVar::Var(AllocatedFp::new(None, open, cs.clone())),
//             }
//         }
//     }
// }

impl<F: PrimeField, const M: usize> AllocVar<Commitment<F, M>, F> for CommitmentVar<F, M> {
    fn new_variable<T: Borrow<Commitment<F, M>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let cm = f().map(|g| *g.borrow());
        let msg = cm.map(|c| {
            c.msg
                .iter()
                .map(|m| FpVar::<F>::new_variable(cs.clone(), || Ok(m), mode).unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        })?;
        let open = FpVar::<F>::new_variable(cs.clone(), || cm.map(|c| c.open), mode)?;

        Ok(Self { msg, open })
    }
}

impl<F: PrimeField, const M: usize> EqGadget<F> for CommitmentVar<F, M> {
    #[tracing::instrument(target = "r1cs", skip(self, other))]
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        let mut equal = self.open.is_eq(&other.open)?;

        for i in 0..M {
            equal = equal.and(&self.msg[i].is_eq(&other.msg[i])?)?;
        }
        Ok(equal)
    }
}

// impl_ops!(
//     CommitmentVar<F, M>,
//     Commitment<F, M>,
//     Add,
//     add,
//     AddAssign,
//     add_assign,
//     |this: &'a CommitmentVar<F, M>, other: &'a CommitmentVar<F, M> | {
//         CommitmentVar::<F, M> {
//             msg,
//             open: &this.open + &other.open
//         }
//     },
//     |this: &'a CommitmentVar<F, M>, other: Commitment<F, M>| {
//         CommitmentVar::<F, M> {
//             msg,
//             open: &this.open + other.open,
//         }
//     },
//     F: PrimeField,
//     const M: usize
// );

// impl_ops!(
//     CommitmentVar<F, M>,
//     Commitment<F, M>,
//     Sub,
//     sub,
//     SubAssign,
//     sub_assign,
//     |this: &'a CommitmentVar<F, M>, other: &'a CommitmentVar<F, M> | {
//         CommitmentVar::<F, M> {
//             msg: &this.msg - &other.msg,
//             open: &this.open - &other.open
//         }
//     },
//     |this: &'a CommitmentVar<F, M>, other: Commitment<F, M>| {
//         CommitmentVar::<F, M> {
//             msg: &this.msg - other.msg,
//             open: &this.open - other.open,
//         }
//     },
//     F: PrimeField,
//     const M: usize,
// );

// // Mul
// /// need to fix
// impl<'a, F: PrimeField, const M: usize> Mul<&'a FpVar<F>> for &'a CommitmentVar<F, M> {
//     type Output = CommitmentVar<F, M>;

//     #[tracing::instrument(target = "r1cs", skip(self))]
//     #[allow(unused_braces)]
//     fn mul(self, other: &'a FpVar<F>) -> Self::Output {
//         CommitmentVar::<F, M> {
//             msg: &self.msg * other,
//             open: &self.open * other,
//         }
//     }
// }

// impl<'a, F: PrimeField, const M: usize> core::ops::Mul<FpVar<F>> for &'a CommitmentVar<F, M> {
//     type Output = CommitmentVar<F, M>;

//     #[tracing::instrument(target = "r1cs", skip(self))]
//     #[allow(unused_braces)]
//     fn mul(self, other: FpVar<F>) -> Self::Output {
//         core::ops::Mul::mul(self, &other)
//     }
// }

// impl<'a, F: PrimeField, const M: usize> core::ops::Mul<&'a FpVar<F>> for CommitmentVar<F, M> {
//     type Output = CommitmentVar<F, M>;

//     #[tracing::instrument(target = "r1cs", skip(self))]
//     #[allow(unused_braces)]
//     fn mul(self, other: &'a FpVar<F>) -> Self::Output {
//         core::ops::Mul::mul(&self, other)
//     }
// }

// impl<F: PrimeField, const M: usize> core::ops::Mul<FpVar<F>> for CommitmentVar<F, M> {
//     type Output = CommitmentVar<F, M>;

//     #[tracing::instrument(target = "r1cs", skip(self))]
//     #[allow(unused_braces)]
//     fn mul(self, other: FpVar<F>) -> Self::Output {
//         core::ops::Mul::mul(&self, &other)
//     }
// }

// impl<F: PrimeField, const M: usize> core::ops::MulAssign<FpVar<F>> for CommitmentVar<F, M> {
//     #[tracing::instrument(target = "r1cs", skip(self))]
//     #[allow(unused_braces)]
//     fn mul_assign(&mut self, other: FpVar<F>) {
//         let result = core::ops::Mul::mul(&*self, &other);
//         *self = result
//     }
// }

// impl<'a, F: PrimeField, const M: usize> core::ops::MulAssign<&'a FpVar<F>> for CommitmentVar<F, M> {
//     #[tracing::instrument(target = "r1cs", skip(self))]
//     #[allow(unused_braces)]
//     fn mul_assign(&mut self, other: &'a FpVar<F>) {
//         let result = core::ops::Mul::mul(&*self, other);
//         *self = result
//     }
// }

// // Mul Constant Commitment<F, M> * F
// /// need to fix
// impl<'a, F: PrimeField, const M: usize> Mul<F> for &'a CommitmentVar<F, M> {
//     type Output = CommitmentVar<F, M>;

//     #[tracing::instrument(target = "r1cs", skip(self))]
//     #[allow(unused_braces)]
//     fn mul(self, other: F) -> Self::Output {
//         CommitmentVar::<F, M> {
//             msg: &self.msg * other,
//             open: &self.open * other,
//         }
//     }
// }

// impl<F: PrimeField, const M: usize> Mul<F> for CommitmentVar<F, M> {
//     type Output = CommitmentVar<F, M>;

//     #[tracing::instrument(target = "r1cs", skip(self))]
//     #[allow(unused_braces)]
//     fn mul(self, other: F) -> Self::Output {
//         core::ops::Mul::mul(&self, other)
//     }
// }

// impl<F: PrimeField, const M: usize> MulAssign<F> for CommitmentVar<F, M> {
//     #[tracing::instrument(target = "r1cs", skip(self))]
//     #[allow(unused_braces)]
//     fn mul_assign(&mut self, other: F) {
//         let result = core::ops::Mul::mul(&*self, other);
//         *self = result
//     }
// }

// // Mul Constant Commitment<F, M> * FpVar<F>
// /// need to fix
// impl<'a, F: PrimeField, const M: usize> Mul<FpVar<F>> for &'a Commitment<F, M> {
//     type Output = CommitmentVar<F, M>;

//     #[tracing::instrument(target = "r1cs", skip(self))]
//     #[allow(unused_braces)]
//     fn mul(self, other: FpVar<F>) -> Self::Output {
//         CommitmentVar::<F, M> {
//             msg: &other * self.msg,
//             open: &other * self.open,
//         }
//     }
// }

// impl<F: PrimeField, const M: usize> Mul<FpVar<F>> for Commitment<F, M> {
//     type Output = CommitmentVar<F, M>;

//     #[tracing::instrument(target = "r1cs", skip(self))]
//     #[allow(unused_braces)]
//     fn mul(self, other: FpVar<F>) -> Self::Output {
//         core::ops::Mul::mul(&self, other)
//     }
// }

// impl<'a, F: PrimeField, const M: usize> Sum<&'a CommitmentVar<F, M>> for CommitmentVar<F, M> {
//     fn sum<I: Iterator<Item = &'a CommitmentVar<F, M>>>(iter: I) -> CommitmentVar<F, M> {
//         let mut sum_constants = Commitment::<F>::zero();
//         let sum_variables =
//             CommitmentVar::<F>::addmany(iter.filter_map(|x| match (&x.msg, &x.open) {
//                 (FpVar::Constant(m), FpVar::Constant(r)) => {
//                     sum_constants.msg += m;
//                     sum_constants.open += r;
//                     None
//                 }
//                 (FpVar::Var(m), FpVar::Var(r)) => Some((m, r)),
//                 _ => unreachable!(),
//             }));

//         let sum = sum_variables + sum_constants;
//         sum
//     }
// }

#[cfg(test)]
mod tests {
    use ark_r1cs_std::alloc::AllocVar;

    use super::{Commitment, CommitmentVar};
    use ark_ff::{PrimeField, Zero};

    type E = ark_bn254::Bn254;
    type F = ark_bn254::Fq;

    #[test]
    fn test_cmvar() {
        let cs = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();

        let msg = [F::zero(), F::zero()];
        let open = F::zero();
        let cm = Commitment::<F, 2> { msg, open };

        let cm_var = CommitmentVar::<F, 2>::new_input(cs.clone(), || Ok(cm));
    }
}
