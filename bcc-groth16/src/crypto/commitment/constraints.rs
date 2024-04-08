use super::CM;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    eq::EqGadget,
    fields::fp::{AllocatedFp, FpVar},
    impl_bounded_ops, impl_ops,
    prelude::*,
};
use ark_relations::{
    lc,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use ark_std::{
    iter::Sum,
    ops::{Mul, MulAssign},
    Zero,
};
use std::borrow::Borrow;

/// Represents a variable for the commitment `CM` with separate variables for the message and randomness.
#[derive(Clone, Debug)]
pub struct CMVar<F: PrimeField> {
    /// Message part of the commitment variable.
    pub msg: FpVar<F>,
    /// Randomness part of the commitment vairalbe.
    pub rand: FpVar<F>,
}

impl<F: PrimeField> CMVar<F> {
    fn addmany<'a, I: Iterator<Item = (&'a AllocatedFp<F>, &'a AllocatedFp<F>)>>(iter: I) -> Self {
        let mut cs = ConstraintSystemRef::None;
        let mut has_value = true;
        let mut value = CM::<F>::zero();
        let mut msg_lc = lc!();
        let mut rand_lc = lc!();

        for (msg, rand) in iter {
            if !msg.cs.is_none() {
                cs = cs.or(msg.cs.clone());
            }
            match (msg.value(), rand.value()) {
                (Ok(m), Ok(r)) => {
                    value.msg += m;
                    value.rand += r;
                }
                _ => has_value = false,
            }
            msg_lc = msg_lc + msg.variable;
            rand_lc = rand_lc + rand.variable;
        }

        let msg = cs.new_lc(msg_lc).unwrap();
        let rand = cs.new_lc(rand_lc).unwrap();

        if has_value {
            CMVar::<F> {
                msg: FpVar::Var(AllocatedFp::new(Some(value.msg), msg, cs.clone())),
                rand: FpVar::Var(AllocatedFp::new(Some(value.rand), rand, cs.clone())),
            }
        } else {
            CMVar::<F> {
                msg: FpVar::Var(AllocatedFp::new(None, msg, cs.clone())),
                rand: FpVar::Var(AllocatedFp::new(None, rand, cs.clone())),
            }
        }
    }
}

impl<F> AllocVar<CM<F>, F> for CMVar<F>
where
    F: PrimeField,
{
    fn new_variable<T: Borrow<CM<F>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let cm = f().map(|g| *g.borrow());
        let msg = FpVar::<F>::new_variable(cs.clone(), || cm.map(|c| c.msg), mode)?;
        let rand = FpVar::<F>::new_variable(cs.clone(), || cm.map(|c| c.rand), mode)?;

        Ok(Self { msg, rand })
    }
}

impl<F: PrimeField> EqGadget<F> for CMVar<F> {
    #[tracing::instrument(target = "r1cs", skip(self, other))]
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        let msg = self.msg.is_eq(&other.msg)?;
        let rand = self.rand.is_eq(&other.rand)?;
        msg.and(&rand)
    }
}

impl_ops!(
    CMVar<F>,
    CM<F>,
    Add,
    add,
    AddAssign,
    add_assign,
    |this: &'a CMVar<F>, other: &'a CMVar<F> | {
        CMVar::<F> {
            msg: &this.msg + &other.msg,
            rand: &this.rand + &other.rand
        }
    },
    |this: &'a CMVar<F>, other: CM<F>| {
        CMVar::<F> {
            msg: &this.msg + other.msg,
            rand: &this.rand + other.rand,
        }
    },
    F: PrimeField,
);

impl_ops!(
    CMVar<F>,
    CM<F>,
    Sub,
    sub,
    SubAssign,
    sub_assign,
    |this: &'a CMVar<F>, other: &'a CMVar<F> | {
        CMVar::<F> {
            msg: &this.msg - &other.msg,
            rand: &this.rand - &other.rand
        }
    },
    |this: &'a CMVar<F>, other: CM<F>| {
        CMVar::<F> {
            msg: &this.msg - other.msg,
            rand: &this.rand - other.rand,
        }
    },
    F: PrimeField,
);

// Mul

impl<'a, F: PrimeField> Mul<&'a FpVar<F>> for &'a CMVar<F> {
    type Output = CMVar<F>;

    #[tracing::instrument(target = "r1cs", skip(self))]
    #[allow(unused_braces)]
    fn mul(self, other: &'a FpVar<F>) -> Self::Output {
        CMVar::<F> {
            msg: &self.msg * other,
            rand: &self.rand * other,
        }
    }
}

impl<'a, F: PrimeField> core::ops::Mul<FpVar<F>> for &'a CMVar<F> {
    type Output = CMVar<F>;

    #[tracing::instrument(target = "r1cs", skip(self))]
    #[allow(unused_braces)]
    fn mul(self, other: FpVar<F>) -> Self::Output {
        core::ops::Mul::mul(self, &other)
    }
}

impl<'a, F: PrimeField> core::ops::Mul<&'a FpVar<F>> for CMVar<F> {
    type Output = CMVar<F>;

    #[tracing::instrument(target = "r1cs", skip(self))]
    #[allow(unused_braces)]
    fn mul(self, other: &'a FpVar<F>) -> Self::Output {
        core::ops::Mul::mul(&self, other)
    }
}

impl<F: PrimeField> core::ops::Mul<FpVar<F>> for CMVar<F> {
    type Output = CMVar<F>;

    #[tracing::instrument(target = "r1cs", skip(self))]
    #[allow(unused_braces)]
    fn mul(self, other: FpVar<F>) -> Self::Output {
        core::ops::Mul::mul(&self, &other)
    }
}

impl<F: PrimeField> core::ops::MulAssign<FpVar<F>> for CMVar<F> {
    #[tracing::instrument(target = "r1cs", skip(self))]
    #[allow(unused_braces)]
    fn mul_assign(&mut self, other: FpVar<F>) {
        let result = core::ops::Mul::mul(&*self, &other);
        *self = result
    }
}

impl<'a, F: PrimeField> core::ops::MulAssign<&'a FpVar<F>> for CMVar<F> {
    #[tracing::instrument(target = "r1cs", skip(self))]
    #[allow(unused_braces)]
    fn mul_assign(&mut self, other: &'a FpVar<F>) {
        let result = core::ops::Mul::mul(&*self, other);
        *self = result
    }
}

// Mul Constant CMVar<F> * F

impl<'a, F: PrimeField> Mul<F> for &'a CMVar<F> {
    type Output = CMVar<F>;

    #[tracing::instrument(target = "r1cs", skip(self))]
    #[allow(unused_braces)]
    fn mul(self, other: F) -> Self::Output {
        CMVar::<F> {
            msg: &self.msg * other,
            rand: &self.rand * other,
        }
    }
}

impl<F: PrimeField> Mul<F> for CMVar<F> {
    type Output = CMVar<F>;

    #[tracing::instrument(target = "r1cs", skip(self))]
    #[allow(unused_braces)]
    fn mul(self, other: F) -> Self::Output {
        core::ops::Mul::mul(&self, other)
    }
}

impl<F: PrimeField> MulAssign<F> for CMVar<F> {
    #[tracing::instrument(target = "r1cs", skip(self))]
    #[allow(unused_braces)]
    fn mul_assign(&mut self, other: F) {
        let result = core::ops::Mul::mul(&*self, other);
        *self = result
    }
}

// Mul Constant CM<F> * FpVar<F>

impl<'a, F: PrimeField> Mul<FpVar<F>> for &'a CM<F> {
    type Output = CMVar<F>;

    #[tracing::instrument(target = "r1cs", skip(self))]
    #[allow(unused_braces)]
    fn mul(self, other: FpVar<F>) -> Self::Output {
        CMVar::<F> {
            msg: &other * self.msg,
            rand: &other * self.rand,
        }
    }
}

impl<F: PrimeField> Mul<FpVar<F>> for CM<F> {
    type Output = CMVar<F>;

    #[tracing::instrument(target = "r1cs", skip(self))]
    #[allow(unused_braces)]
    fn mul(self, other: FpVar<F>) -> Self::Output {
        core::ops::Mul::mul(&self, other)
    }
}

impl<'a, F: PrimeField> Sum<&'a CMVar<F>> for CMVar<F> {
    fn sum<I: Iterator<Item = &'a CMVar<F>>>(iter: I) -> CMVar<F> {
        let mut sum_constants = CM::<F>::zero();
        let sum_variables = CMVar::<F>::addmany(iter.filter_map(|x| match (&x.msg, &x.rand) {
            (FpVar::Constant(m), FpVar::Constant(r)) => {
                sum_constants.msg += m;
                sum_constants.rand += r;
                None
            }
            (FpVar::Var(m), FpVar::Var(r)) => Some((m, r)),
            _ => unreachable!(),
        }));

        let sum = sum_variables + sum_constants;
        sum
    }
}
