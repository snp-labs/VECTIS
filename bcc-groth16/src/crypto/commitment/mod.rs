/// Implementation of Pedersen Commitment
pub mod constraints;

use ark_ff::PrimeField;
use ark_std::{
    ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign},
    Zero,
};

/// A Pedersen commitment structure over a prime field `F`.
///
/// The `CM` struct represents a commitment to a message with some randomness for blinding.
///
/// # Fields
///
/// * `msg` - The message part of the commitment.
/// * `rand` - The randomness part of the commitment, used for blinding.
///
/// # Example
///
/// ```ignore
/// use ccgroth16::crypto::cm::CM;
/// use ark_bn254::Fq; // Example field
/// let msg = Fq::from(12345678u64);
/// let rand = Fq::from(87654321u64);
/// let cm = CM { msg: msg, rand: rand };
/// ```
#[derive(Clone, Debug, Copy, PartialEq)]
pub struct CM<F>
where
    F: PrimeField + Zero,
{
    /// Message part of the commitment.
    pub msg: F,
    /// Randomness part of the commitment.
    pub rand: F,
}

impl<'a, F: PrimeField> From<(&'a str, &'a str)> for CM<F> {
    fn from((msg, rand): (&'a str, &'a str)) -> Self {
        let msg = F::from_str(msg).unwrap_or_default();
        let rand = F::from_str(rand).unwrap_or_default();
        CM { msg, rand }
    }
}

impl<F: PrimeField> Zero for CM<F> {
    #[inline]
    fn zero() -> Self {
        CM {
            msg: F::zero(),
            rand: F::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        self.msg == F::ZERO && self.rand == F::ZERO
    }
}

// Add

impl<'a, F: PrimeField> Add<&'a CM<F>> for CM<F> {
    type Output = CM<F>;

    #[inline]
    fn add(mut self, rhs: &Self) -> Self {
        self.add_assign(rhs);
        self
    }
}

impl<'a, 'b, F: PrimeField> Add<&'b CM<F>> for &'a CM<F> {
    type Output = CM<F>;

    #[inline]
    fn add(self, rhs: &'b CM<F>) -> CM<F> {
        let mut result = *self;
        result.add_assign(rhs);
        result
    }
}

impl<F: PrimeField> core::ops::Add<Self> for CM<F> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self {
        self.add_assign(&rhs);
        self
    }
}

impl<'a, F: PrimeField> core::ops::Add<&'a mut Self> for CM<F> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &'a mut Self) -> Self {
        self.add_assign(&*rhs);
        self
    }
}

impl<'a, F: PrimeField> AddAssign<&'a Self> for CM<F> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        self.msg += rhs.msg;
        self.rand += rhs.rand;
    }
}

impl<F: PrimeField> core::ops::AddAssign<Self> for CM<F> {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        self.add_assign(&rhs)
    }
}

impl<'a, F: PrimeField> core::ops::AddAssign<&'a mut Self> for CM<F> {
    #[inline(always)]
    fn add_assign(&mut self, rhs: &'a mut Self) {
        self.add_assign(&*rhs)
    }
}

// Sub

impl<'a, F: PrimeField> Sub<&'a CM<F>> for CM<F> {
    type Output = CM<F>;

    #[inline]
    fn sub(mut self, rhs: &Self) -> Self {
        self.sub_assign(rhs);
        self
    }
}

impl<'a, 'b, F: PrimeField> Sub<&'b CM<F>> for &'a CM<F> {
    type Output = CM<F>;

    #[inline]
    fn sub(self, rhs: &'b CM<F>) -> CM<F> {
        let mut result = *self;
        result.sub_assign(rhs);
        result
    }
}

impl<F: PrimeField> core::ops::Sub<Self> for CM<F> {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self {
        self.sub_assign(&rhs);
        self
    }
}

impl<'a, F: PrimeField> core::ops::Sub<&'a mut Self> for CM<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: &'a mut Self) -> Self {
        self.sub_assign(&*rhs);
        self
    }
}

impl<'a, F: PrimeField> SubAssign<&'a Self> for CM<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        self.msg -= rhs.msg;
        self.rand -= rhs.rand;
    }
}

impl<F: PrimeField> core::ops::SubAssign<Self> for CM<F> {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        self.sub_assign(&rhs)
    }
}

impl<'a, F: PrimeField> core::ops::SubAssign<&'a mut Self> for CM<F> {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: &'a mut Self) {
        self.sub_assign(&*rhs)
    }
}

// Mul

impl<'a, F: PrimeField> Mul<&'a F> for CM<F> {
    type Output = CM<F>;

    #[inline]
    fn mul(mut self, rhs: &F) -> Self {
        self.mul_assign(rhs);
        self
    }
}

impl<'a, 'b, F: PrimeField> Mul<&'b F> for &'a CM<F> {
    type Output = CM<F>;

    #[inline]
    fn mul(self, rhs: &'b F) -> CM<F> {
        let mut result = *self;
        result.mul_assign(rhs);
        result
    }
}

impl<F: PrimeField> core::ops::Mul<F> for CM<F> {
    type Output = Self;

    fn mul(mut self, rhs: F) -> Self {
        self.mul_assign(&rhs);
        self
    }
}

impl<'a, F: PrimeField> core::ops::Mul<&'a mut F> for CM<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: &'a mut F) -> Self {
        self.mul_assign(&*rhs);
        self
    }
}

impl<'a, F: PrimeField> MulAssign<&'a F> for CM<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &F) {
        self.msg *= rhs;
        self.rand *= rhs;
    }
}

impl<F: PrimeField> core::ops::MulAssign<F> for CM<F> {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: F) {
        self.mul_assign(&rhs)
    }
}

impl<F: PrimeField> core::iter::Sum<Self> for CM<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), core::ops::Add::add)
    }
}

impl<'a, F: PrimeField> core::iter::Sum<&'a Self> for CM<F> {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), core::ops::Add::add)
    }
}

#[test]
fn test_commitment_ops() {
    use ark_bn254;
    use std::str::FromStr;

    type F = ark_bn254::Fq;

    let coeff = F::from_str("3").unwrap();

    let cm1 = CM::<F> {
        msg: F::from_str("1").unwrap(),
        rand: F::from_str("1").unwrap(),
    };

    let cm2 = CM::<F> {
        msg: F::from_str("2").unwrap(),
        rand: F::from_str("2").unwrap(),
    };

    let cm_list = vec![cm1, cm2, cm1, cm2];

    let add = cm1 + cm2;
    println!("{:?} + {:?} = {:?}", cm1, cm2, add);

    let sub = cm1 - cm2;
    println!("{:?} - {:?} = {:?}", cm1, cm2, sub);

    let mul = cm1 * coeff;
    println!("{:?} * {:?} = {:?}", cm1, coeff, mul);

    let sum: CM<F> = cm_list.iter().sum();
    println!("sum = {:?}", sum);
}
