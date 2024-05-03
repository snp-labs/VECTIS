use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::Zero;
use bccgroth16::crypto::{
    commitment::{constraints::CMVar, CM},
    tree::AggregationTree,
};

#[derive(Clone)]
pub struct BccCircuit<F: PrimeField> {
    pub aggr: Option<CM<F>>,
    pub list_cm: Option<Vec<CM<F>>>,
    pub rand: Option<F>,
}

impl<F: PrimeField> BccCircuit<F> {
    /// Create a new circuit
    pub fn new(list_cm: Vec<CM<F>>, rand: F) -> Self {
        let aggr = list_cm.compute_root(rand);
        Self {
            aggr: Some(aggr),
            list_cm: Some(list_cm),
            rand: Some(rand),
        }
    }

    /// Create a default circuit with all Zero
    pub fn default(n: usize) -> Self {
        Self {
            aggr: Some(CM::zero()),
            list_cm: Some(vec![CM::zero(); n]),
            rand: Some(F::zero()),
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for BccCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> ark_relations::r1cs::Result<()> {
        let aggr = CMVar::new_witness(cs.clone(), || {
            self.aggr.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let list_cm = Vec::<CMVar<F>>::new_witness(cs.clone(), || {
            self.list_cm.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let rand = FpVar::new_witness(cs.clone(), || {
            self.rand.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let _aggr: CMVar<F> = list_cm.compute_root(rand);
        aggr.enforce_equal(&_aggr)?;
        Ok(())
    }
}
