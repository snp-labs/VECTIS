pub mod constraints;
use ark_ff::{PrimeField, Zero};
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

/// A commitment structure over a prime field `F`.
///
/// The `CM` struct represents a commitment to a message with some opening for blinding.
///
/// # Fields
///
/// * `msg` - The message part of the commitment.
/// * `open` - The openomness part of the commitment, used for blinding.
#[derive(Clone, Debug, Copy, PartialEq)]
pub struct Commitment<F, const M: usize>
where
    F: PrimeField + Zero,
{
    /// Message part of the commitment.
    pub msg: [F; M],
    /// Opening part of the commitment.
    pub open: F,
}

impl<F: PrimeField, const M: usize> Zero for Commitment<F, M> {
    #[inline]
    fn zero() -> Self {
        Commitment {
            msg: [F::zero(); M],
            open: F::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        self.msg.iter().all(|m| m.is_zero()) && self.open == F::ZERO
    }
}

// Add

impl<'a, F: PrimeField, const M: usize> Add<&'a Commitment<F, M>> for Commitment<F, M> {
    type Output = Commitment<F, M>;

    #[inline]
    fn add(mut self, rhs: &Self) -> Self {
        self.add_assign(rhs);
        self
    }
}

impl<'a, 'b, F: PrimeField, const M: usize> Add<&'b Commitment<F, M>> for &'a Commitment<F, M> {
    type Output = Commitment<F, M>;

    #[inline]
    fn add(self, rhs: &'b Commitment<F, M>) -> Commitment<F, M> {
        let mut result = *self;
        result.add_assign(rhs);
        result
    }
}

impl<F: PrimeField, const M: usize> core::ops::Add<Self> for Commitment<F, M> {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self {
        self.add_assign(&rhs);
        self
    }
}

impl<'a, F: PrimeField, const M: usize> core::ops::Add<&'a mut Self> for Commitment<F, M> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: &'a mut Self) -> Self {
        self.add_assign(&*rhs);
        self
    }
}

impl<'a, F: PrimeField, const M: usize> AddAssign<&'a Self> for Commitment<F, M> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        self.msg
            .iter_mut()
            .zip(rhs.msg.iter())
            .for_each(|(m1, m2)| *m1 += m2);
        self.open += rhs.open;
    }
}

impl<F: PrimeField, const M: usize> core::ops::AddAssign<Self> for Commitment<F, M> {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        self.add_assign(&rhs)
    }
}

impl<'a, F: PrimeField, const M: usize> core::ops::AddAssign<&'a mut Self> for Commitment<F, M> {
    #[inline(always)]
    fn add_assign(&mut self, rhs: &'a mut Self) {
        self.add_assign(&*rhs)
    }
}

// Sub

impl<'a, F: PrimeField, const M: usize> Sub<&'a Commitment<F, M>> for Commitment<F, M> {
    type Output = Commitment<F, M>;

    #[inline]
    fn sub(mut self, rhs: &Self) -> Self {
        self.sub_assign(rhs);
        self
    }
}

impl<'a, 'b, F: PrimeField, const M: usize> Sub<&'b Commitment<F, M>> for &'a Commitment<F, M> {
    type Output = Commitment<F, M>;

    #[inline]
    fn sub(self, rhs: &'b Commitment<F, M>) -> Commitment<F, M> {
        let mut result = *self;
        result.sub_assign(rhs);
        result
    }
}

impl<F: PrimeField, const M: usize> core::ops::Sub<Self> for Commitment<F, M> {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self {
        self.sub_assign(&rhs);
        self
    }
}

impl<'a, F: PrimeField, const M: usize> core::ops::Sub<&'a mut Self> for Commitment<F, M> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: &'a mut Self) -> Self {
        self.sub_assign(&*rhs);
        self
    }
}

impl<'a, F: PrimeField, const M: usize> SubAssign<&'a Self> for Commitment<F, M> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        self.msg
            .iter_mut()
            .zip(rhs.msg.iter())
            .for_each(|(m1, m2)| *m1 += m2);
        self.open += rhs.open;
    }
}

impl<F: PrimeField, const M: usize> core::ops::SubAssign<Self> for Commitment<F, M> {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        self.sub_assign(&rhs)
    }
}

impl<'a, F: PrimeField, const M: usize> core::ops::SubAssign<&'a mut Self> for Commitment<F, M> {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: &'a mut Self) {
        self.sub_assign(&*rhs)
    }
}

// Mul

impl<'a, F: PrimeField, const M: usize> Mul<&'a F> for Commitment<F, M> {
    type Output = Commitment<F, M>;

    #[inline]
    fn mul(mut self, rhs: &F) -> Self {
        self.mul_assign(rhs);
        self
    }
}

impl<'a, 'b, F: PrimeField, const M: usize> Mul<&'b F> for &'a Commitment<F, M> {
    type Output = Commitment<F, M>;

    #[inline]
    fn mul(self, rhs: &'b F) -> Commitment<F, M> {
        let mut result = *self;
        result.mul_assign(rhs);
        result
    }
}

impl<F: PrimeField, const M: usize> core::ops::Mul<F> for Commitment<F, M> {
    type Output = Self;

    fn mul(mut self, rhs: F) -> Self {
        self.mul_assign(&rhs);
        self
    }
}

impl<'a, F: PrimeField, const M: usize> core::ops::Mul<&'a mut F> for Commitment<F, M> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: &'a mut F) -> Self {
        self.mul_assign(&*rhs);
        self
    }
}

impl<'a, F: PrimeField, const M: usize> MulAssign<&'a F> for Commitment<F, M> {
    #[inline]
    fn mul_assign(&mut self, rhs: &F) {
        self.msg.iter_mut().for_each(|m| *m *= rhs);
        self.open *= rhs;
    }
}

impl<F: PrimeField, const M: usize> core::ops::MulAssign<F> for Commitment<F, M> {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: F) {
        self.mul_assign(&rhs)
    }
}

impl<F: PrimeField, const M: usize> core::iter::Sum<Self> for Commitment<F, M> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), core::ops::Add::add)
    }
}

impl<'a, F: PrimeField, const M: usize> core::iter::Sum<&'a Self> for Commitment<F, M> {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), core::ops::Add::add)
    }
}
