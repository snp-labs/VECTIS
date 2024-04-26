use std::marker::PhantomData;

use ark_ec::CurveGroup;

pub mod constraints;

#[derive(Clone)]
pub struct Parameters<C: CurveGroup> {
    pub generator: C::Affine,
}

#[derive(Clone)]
pub struct Message<C: CurveGroup>(pub C::ScalarField);

pub type Commitment<C> = <C as CurveGroup>::Affine;

pub trait CommitmentScheme {
    type Parameters;
    type Message;
    type Commitment;
    type Output;

    fn commit(
        ck: &Vec<Self::Parameters>,
        messages: &Vec<Self::Message>,
        opens: &Vec<Self::Message>,
    ) -> Self::Output;
}

pub struct BatchCommitment<C: CurveGroup> {
    _group: PhantomData<C>,
}

impl<C: CurveGroup> CommitmentScheme for BatchCommitment<C> {
    type Parameters = Parameters<C>;
    type Message = Message<C>;
    type Commitment = Commitment<C>;
    type Output = Vec<Self::Commitment>;

    fn commit(
        ck: &Vec<Self::Parameters>,
        messages: &Vec<Self::Message>,
        opens: &Vec<Self::Message>,
    ) -> Self::Output {
        let mut commitments = Vec::new();
        for (message, open) in messages.iter().zip(opens.iter()) {
            let cm = ck[0].generator * (message.0) + ck[1].generator * open.0;
            commitments.push(cm.into());
        }
        commitments
    }
}
