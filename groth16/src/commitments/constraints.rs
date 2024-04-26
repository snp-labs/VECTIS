use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField, Zero};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    uint8::UInt8,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_std::{borrow::Borrow, marker::PhantomData, vec::Vec};
use derivative::Derivative;

use super::{BatchCommitment, Commitment, CommitmentScheme, Message, Parameters};

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

pub trait CommitmentGadget<CS: CommitmentScheme, ConstraintF: Field> {
    type ParametersVar: AllocVar<CS::Parameters, ConstraintF> + Clone;
    type MessageVar: AllocVar<CS::Message, ConstraintF> + Clone;
    type CommitmentVar: AllocVar<CS::Commitment, ConstraintF> + EqGadget<ConstraintF> + Clone;
    type Output;

    fn commit(
        commitment_key: &Vec<Self::ParametersVar>,
        messages: &Vec<Self::MessageVar>,
        opens: &Vec<Self::MessageVar>,
    ) -> Result<Self::Output, SynthesisError>;
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>"))]
pub struct ParametersVar<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    generator: GG,
    #[doc(hidden)]
    _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<Parameters<C>, ConstraintF<C>> for ParametersVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn new_variable<T: Borrow<Parameters<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let generator = GG::new_variable(cs, || f().map(|g| g.borrow().generator), mode)?;
        Ok(Self {
            generator,
            _curve: PhantomData,
        })
    }
}

#[derive(Clone, Debug)]
pub struct MessageVar<F: Field>(Vec<UInt8<F>>);

impl<C, F> AllocVar<Message<C>, F> for MessageVar<F>
where
    C: CurveGroup,
    F: PrimeField,
{
    fn new_variable<T: Borrow<Message<C>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let mut m = Vec::new();
        let _ = &f()
            .map(|b| b.borrow().0)
            .unwrap_or(C::ScalarField::zero())
            .serialize_compressed(&mut m)
            .unwrap();
        match mode {
            AllocationMode::Constant => Ok(Self(UInt8::constant_vec(&m))),
            AllocationMode::Input => UInt8::new_input_vec(cs, &m).map(Self),
            AllocationMode::Witness => UInt8::new_witness_vec(cs, &m).map(Self),
        }
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>"))]
pub struct CommitmentVar<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub commitment: GG,
    #[doc(hidden)]
    _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<Commitment<C>, ConstraintF<C>> for CommitmentVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn new_variable<T: Borrow<Commitment<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let commitment = GG::new_variable(cs, f, mode)?;
        Ok(Self {
            commitment,
            _curve: PhantomData,
        })
    }
}

impl<C, GC> EqGadget<ConstraintF<C>> for CommitmentVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        Ok(self.commitment.is_eq(&other.commitment)?)
    }
}

pub struct BatchCommitmentGadget<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    #[doc(hidden)]
    _curve: PhantomData<*const C>,
    _group_var: PhantomData<*const GG>,
}

impl<C, GG> CommitmentGadget<BatchCommitment<C>, ConstraintF<C>> for BatchCommitmentGadget<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    ConstraintF<C>: PrimeField,
{
    type ParametersVar = ParametersVar<C, GG>;
    type MessageVar = MessageVar<ConstraintF<C>>;
    type CommitmentVar = CommitmentVar<C, GG>;
    type Output = Vec<Self::CommitmentVar>;

    fn commit(
        commitment_key: &Vec<Self::ParametersVar>,
        messages: &Vec<Self::MessageVar>,
        opens: &Vec<Self::MessageVar>,
    ) -> Result<Self::Output, SynthesisError> {
        let mut commitments = Vec::new();
        for (msg, open) in messages.iter().zip(opens.iter()) {
            let m = msg
                .0
                .iter()
                .flat_map(|b| b.to_bits_le().unwrap())
                .collect::<Vec<_>>();
            let o = open
                .0
                .iter()
                .flat_map(|b| b.to_bits_le().unwrap())
                .collect::<Vec<_>>();
            let cm = commitment_key[0]
                .generator
                .clone()
                .scalar_mul_le(m.iter())?
                + commitment_key[1]
                    .generator
                    .clone()
                    .scalar_mul_le(o.iter())?;
            commitments.push(self::CommitmentVar {
                commitment: cm,
                _curve: PhantomData,
            });
        }
        Ok(commitments)
    }
}
