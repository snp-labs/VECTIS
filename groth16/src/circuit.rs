use std::marker::PhantomData;

use ark_ec::CurveGroup;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    groups::{CurveVar, GroupOpsBounds},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::Zero;

use crate::commitments::{
    self,
    constraints::{
        BatchCommitmentGadget, CommitmentGadget, CommitmentVar, ConstraintF, MessageVar,
        ParametersVar,
    },
    BatchCommitment, CommitmentScheme,
};

#[derive(Clone)]
pub struct BatchCommitmentCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
{
    pub ck: Option<Vec<commitments::Parameters<C>>>,
    pub cms: Option<Vec<commitments::Commitment<C>>>,
    pub msgs: Option<Vec<commitments::Message<C>>>,
    pub opens: Option<Vec<commitments::Message<C>>>,
    pub _curve_var: PhantomData<GG>,
}

impl<C, GG> BatchCommitmentCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
{
    pub fn new(ck: Vec<C::Affine>, msgs: Vec<C::ScalarField>, opens: Vec<C::ScalarField>) -> Self {
        let ck = ck
            .iter()
            .map(|g| commitments::Parameters { generator: *g })
            .collect::<Vec<commitments::Parameters<C>>>();

        let msgs = msgs
            .iter()
            .map(|m| commitments::Message(*m))
            .collect::<Vec<commitments::Message<C>>>();

        let opens = opens
            .iter()
            .map(|o| commitments::Message(*o))
            .collect::<Vec<commitments::Message<C>>>();

        let cms = BatchCommitment::<C>::commit(&ck, &msgs, &opens);

        Self {
            ck: Some(ck),
            cms: Some(cms),
            msgs: Some(msgs),
            opens: Some(opens),
            _curve_var: PhantomData,
        }
    }

    pub fn default(n: usize) -> Self {
        let ck = vec![C::zero().into_affine(), C::zero().into_affine()];
        let msgs = vec![C::ScalarField::zero(); n];
        let opens = vec![C::ScalarField::zero(); n];

        Self::new(ck, msgs, opens)
    }
}

impl<C, GG> ConstraintSynthesizer<ConstraintF<C>> for BatchCommitmentCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        let ck = Vec::<ParametersVar<C, GG>>::new_input(cs.clone(), || {
            self.ck.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let cms = Vec::<CommitmentVar<C, GG>>::new_input(cs.clone(), || {
            self.cms.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let msgs = Vec::<MessageVar<ConstraintF<C>>>::new_witness(cs.clone(), || {
            self.msgs.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let opens = Vec::<MessageVar<ConstraintF<C>>>::new_witness(cs.clone(), || {
            self.opens.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let _cms = BatchCommitmentGadget::<C, GG>::commit(&ck, &msgs, &opens)?;

        _cms.iter()
            .zip(cms.iter())
            .for_each(|(_cm, cm)| _cm.enforce_equal(&cm).unwrap());

        Ok(())
    }
}
